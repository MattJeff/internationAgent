//! Who is calling, established from the credential and from nothing else.
//!
//! # The hole this closes
//!
//! The previous API took `tenant_id` from wherever it appeared — a path
//! segment, a JSON field, a header a client set. Any of those means a caller
//! can name a tenant that is not theirs, and the only thing standing between
//! them and its data is every handler remembering to check. One did not.
//!
//! So [`Principal`] is produced in exactly one place: [`require_api_key`],
//! from the `Authorization` header. It is not `Deserialize`, so it cannot
//! arrive in a body. Handlers get it as an extractor, and the tenant id they
//! read is the one the key proved. A path parameter named `tenant_id` should
//! not exist; if one ever does, it is decoration, and this module is still the
//! authority.
//!
//! [`Keyring::principal_of`] is the resolution [`require_api_key`] performs,
//! reachable by name, and it does not weaken that sentence. It hands a
//! [`Principal`] back to its caller; it does not put one in a request. The claim
//! is not "one function builds a Principal" but "one function attaches one to a
//! request", and the `extensions_mut().insert` below is still the only place
//! that happens. `routes::mcp_server`, the one caller, reads the answer as a
//! yes-or-no and drops the value — it has no handler to hand it to.
//!
//! # Where the keys live: two keyrings, and the split is the design
//!
//! **`api_keys`, a table** — every credential a *customer* holds. Issued and
//! destroyed over HTTP with no restart, hashed with HMAC-SHA256
//! (`agentos_app::api_keys` argues that at length), looked up on every request
//! with no cache, so a `DELETE` is felt by the next call and not by the next
//! deploy. This is what the module's old `ponytail:` note promised and this
//! wave built.
//!
//! **`AGENTOS_API_KEYS`, the environment** — unchanged, still `label:tenant-uuid:secret`
//! comma separated, still consulted **first**. It is not a deprecated path: the
//! whole test suite and the runbook stand a server up with it, and resolving one
//! of its entries costs no round trip because [`Keyring::resolve`] returns
//! before it queries anything. Its ceiling is real and now bounded — issuing and
//! revoking still mean a redeploy — so it is a keyring for the deployment's own
//! operators, not for customers.
//!
//! ## Which wins when both name the same secret
//!
//! The environment. Two reasons, and the second is the one that matters:
//!
//! * It is the cheaper path — a linear scan of a handful of entries in memory,
//!   no round trip — and putting it first means the ordinary case pays nothing.
//! * **It cannot be changed by anything running at runtime.** A row is written
//!   by a process; a variable is written by whoever deploys. If the table won,
//!   an INSERT would be able to shadow the operator's own console key and point
//!   it at another tenant, which is a privilege escalation with a
//!   `INSERT ... ON CONFLICT`. The precedence is a `find`-then-`else`, and
//!   `an_env_key_wins_over_a_table_row_naming_the_same_secret` is the test.
//!
//! # And a third keyring, which is not a tenant at all
//!
//! [`PlatformKeys`], from `AGENTOS_PLATFORM_KEYS`, as `label:secret` — no
//! tenant uuid, because it does not speak for one. It authorises exactly two
//! verbs: create a tenant, and issue or revoke that tenant's keys. See
//! `crate::routes::platform` for why the authority to mint had to be a separate
//! principal and not a permission on a tenant's own key.
//!
//! The obvious objection is that this puts a credential back in an environment
//! variable, which is the ceiling this wave exists to break. It does, on
//! purpose, and the split is the answer: **the N credentials customers hold move
//! into the database; the 1 credential the vendor holds stays in the
//! environment.** Rotating the customer's key must not require a deploy, because
//! a deploy interrupts every *other* customer. Rotating the vendor's own key is
//! a deploy the vendor was going to do anyway. And the recursion has to stop
//! somewhere: whatever mints the first credential cannot itself have been
//! minted.

use std::num::NonZeroU32;
use std::sync::Arc;

use agentos_domain::ids::TenantId;
use agentos_store::audit::AuditActor;
use agentos_store::db::Db;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ring::pbkdf2;

use crate::error::ApiError;

/// The authenticated caller.
///
/// Deliberately not `Deserialize` and deliberately without a public
/// constructor from strings: the only way to get one is to present a key.
///
/// Not to be confused with `agentos_app::gate::Principal`, which additionally
/// names the *employee* an action is attributed to. A route builds that one by
/// pairing this tenant and actor with an employee id from its path — and the
/// tenant still comes from here, so a path naming another tenant's employee
/// simply finds nothing.
#[derive(Debug, Clone)]
pub struct Principal {
    /// The tenant every query this request makes will be confined to.
    pub tenant_id: TenantId,
    /// Who to attribute the request to in the audit trail.
    pub actor: AuditActor,
}

/// One configured credential.
#[derive(Clone)]
struct ApiKey {
    /// Human name for the key, e.g. `ops-console`. Becomes the audit actor —
    /// so the trail says which key acted, never what the secret was.
    label: String,
    tenant_id: TenantId,
    secret: String,
}

// Hand-written, like every other type in this workspace that holds one: a
// derived `Debug` prints `secret` verbatim, and a keyring is exactly the sort of
// thing somebody renders while working out why a request 401'd. The label and
// the tenant are the half that answers that question; the secret never was.
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("label", &self.label)
            .field("tenant_id", &self.tenant_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The keyring, parsed once at boot and shared by every request.
#[derive(Debug, Clone, Default)]
pub struct ApiKeys(Arc<Vec<ApiKey>>);

/// Why `AGENTOS_API_KEYS` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeysError {
    /// An entry was not `label:tenant-uuid:secret`.
    #[error("entry {index} is not `label:tenant-uuid:secret`")]
    Shape {
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// The middle field is not a UUID.
    #[error("entry {index} has an unparseable tenant id")]
    TenantId {
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// A short secret is a guessable secret.
    #[error("entry {index} has a secret shorter than {min} characters", min = ApiKeys::MIN_SECRET_LEN)]
    WeakSecret {
        /// Zero-based position of the offending entry.
        index: usize,
    },
}

impl ApiKeys {
    /// Shortest secret we will boot with. 32 characters of anything is beyond
    /// online guessing; anything shorter is a typo or a placeholder, and both
    /// are better caught at boot than at 3am.
    pub const MIN_SECRET_LEN: usize = 32;

    /// Parse `label:tenant-uuid:secret,label:tenant-uuid:secret,…`.
    ///
    /// An empty string is a valid, empty keyring — the server boots and
    /// authenticates nobody, which is the correct failure mode for a
    /// misconfigured deployment.
    pub fn parse(raw: &str) -> Result<Self, ApiKeysError> {
        let keys = raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
            .map(|(index, entry)| {
                // `splitn(3)` so a secret may itself contain colons.
                let mut fields = entry.splitn(3, ':');
                let (Some(label), Some(tenant), Some(secret)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Err(ApiKeysError::Shape { index });
                };
                if label.is_empty() {
                    return Err(ApiKeysError::Shape { index });
                }
                if secret.len() < Self::MIN_SECRET_LEN {
                    return Err(ApiKeysError::WeakSecret { index });
                }
                Ok(ApiKey {
                    label: label.to_owned(),
                    tenant_id: tenant
                        .parse()
                        .map_err(|_| ApiKeysError::TenantId { index })?,
                    secret: secret.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(Arc::new(keys)))
    }

    /// No keys configured: nothing can authenticate.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many keys are configured. For the boot log — never the secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Resolve a presented secret.
    ///
    /// A linear scan with a constant-time comparison, not a `HashMap`: the map
    /// would hash the attacker's input and then compare it with `==`, which
    /// returns as soon as two bytes differ. Ten keys is not a scan worth
    /// optimising.
    pub fn lookup(&self, presented: &str) -> Option<Principal> {
        self.0
            .iter()
            .find(|key| ct_eq(key.secret.as_bytes(), presented.as_bytes()))
            .map(|key| Principal {
                tenant_id: key.tenant_id,
                actor: AuditActor::Operator(key.label.clone()),
            })
    }
}

/// Compare without an early exit. The length is allowed to leak — the secret's
/// length is not the secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// The two keyrings a tenant credential can come from
// ---------------------------------------------------------------------------

/// Everything `require_api_key` needs to answer "whose is this".
///
/// Holds the environment keyring, the pool, and the deployment's key-hashing
/// key. Cheap to clone: an `Arc<Vec<_>>`, a pooled handle and 32 bytes.
///
/// No `Debug`. Not because a rendering would leak — [`ApiKeys`] redacts, and so
/// does [`agentos_app::api_keys::Hasher`] by having none. Because this is the
/// type an axum layer holds, so it is the type that appears in a `Service` type
/// name in a panic, and the fewer ways there are to render a keyring the better.
#[derive(Clone)]
pub struct Keyring {
    /// `AGENTOS_API_KEYS`. Consulted first — see the module docs.
    env: ApiKeys,
    /// Where the `api_keys` table lives.
    db: Db,
    /// Turns a presented token into the digest the table is indexed on.
    hasher: agentos_app::api_keys::Hasher,
}

impl Keyring {
    /// Build the composite keyring. `master_key` is `AGENTOS_MASTER_KEY`; the
    /// hashing key is derived from it, never equal to it.
    pub fn new(env: ApiKeys, db: Db, master_key: &str) -> Self {
        Self {
            env,
            db,
            hasher: agentos_app::api_keys::Hasher::from_master_key(master_key),
        }
    }

    /// The hasher, for the routes that issue and revoke.
    pub fn hasher(&self) -> &agentos_app::api_keys::Hasher {
        &self.hasher
    }

    /// Environment first, then the table.
    ///
    /// `Ok(None)` is "nobody". `Err` is the database, and the caller must not
    /// render it as a 401: a Postgres that is down would otherwise be
    /// indistinguishable from a wrong key, and every customer would be told to
    /// rotate a credential that is fine.
    async fn resolve(
        &self,
        presented: &str,
    ) -> Result<Option<Principal>, agentos_store::db::StoreError> {
        if let Some(principal) = self.env.lookup(presented) {
            return Ok(Some(principal));
        }
        Ok(
            agentos_app::api_keys::authenticate(&self.db, &self.hasher, presented)
                .await?
                .map(|found| Principal {
                    tenant_id: found.tenant_id,
                    // The same actor shape an env key produces, deliberately:
                    // the trail says which key acted, and where the key was
                    // kept is not a fact about the action.
                    actor: AuditActor::Operator(found.label),
                }),
        )
    }

    /// Who this `Authorization` header speaks for, **without refusing anybody**.
    ///
    /// The half of [`require_api_key`] that establishes an identity, split out
    /// so that the one route which cannot be behind that middleware can still
    /// reach exactly this answer: `routes::mcp_server`, whose `initialize` has
    /// to succeed unauthenticated while `tools/list` and `tools/call` must not.
    /// A second parser of `Bearer …` in that module would be a second opinion
    /// about what a credential is, and the two would drift on the day one of
    /// them learns a new scheme.
    ///
    /// `Ok(None)` is "nobody" — no header, wrong scheme, or a secret in neither
    /// keyring. `Err` is the database, and a caller that renders it as a 401 is
    /// telling every customer to rotate a key that is fine.
    pub(crate) async fn principal_of(
        &self,
        header: Option<&HeaderValue>,
    ) -> Result<Option<Principal>, agentos_store::db::StoreError> {
        let Some(presented) = header
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
        else {
            return Ok(None);
        };
        self.resolve(presented).await
    }
}

/// The master key this crate's own tests derive a hashing key from.
///
/// One constant rather than a literal per test module. Most of those tests
/// exercise the *environment* half of the keyring, where the value only has to
/// exist; the ones that mean to exercise the table half issue a key against this
/// same value, and sharing it is what makes the two halves line up.
#[cfg(test)]
pub(crate) const TEST_MASTER_KEY: &str = "agentos-tests-master-key";

/// Reject the request, or attach a [`Principal`] to it.
///
/// Sits above every route that touches tenant data and below `/livez` and
/// `/readyz`, which must answer while the keyring is empty or the database is
/// down.
///
/// ponytail: the table is read on every authenticated request, with no cache in
/// front of it. That is one indexed equality on a unique `bytea` — and it is
/// what makes revocation instantaneous rather than eventually-consistent, which
/// is the entire point of moving keys out of the environment. The known ceiling
/// is that an unauthenticated flood costs one round trip per request, because
/// the rate limiter is *below* this layer and cannot be above it (it is keyed on
/// the tenant this layer establishes). The upgrade path is a connection-limited
/// ingress, not a TTL: see `agentos_store::api_keys::lookup` on why a cache here
/// would have to be measured in "how long a stolen key still works".
pub async fn require_api_key(
    State(keys): State<Keyring>,
    mut req: Request,
    next: Next,
) -> Response {
    let principal = match keys
        .principal_of(req.headers().get(header::AUTHORIZATION))
        .await
    {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            // One response for "no header", "wrong scheme" and "wrong secret":
            // the distinction is only ever useful to someone probing.
            return unauthorized();
        }
        // Never a 401. `ApiError::from` logs the driver error and answers 500 —
        // or 503 for a retryable abort — so an outage reads as an outage.
        Err(err) => return ApiError::from(err).into_response(),
    };

    // The one place a Principal enters the request.
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// 401 plus the challenge header, in one place so the two middlewares here —
/// and `routes::mcp_server`, which authenticates outside both of them — cannot
/// answer a missing credential three different ways.
pub(crate) fn unauthorized() -> Response {
    let mut response = ApiError::unauthorized().into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"agentos\""),
    );
    response
}

// ---------------------------------------------------------------------------
// Le rôle de l'humain qui appelle
// ---------------------------------------------------------------------------

/// **Les gestes qu'une personne sans le rôle propriétaire peut faire.**
///
/// # Pourquoi la liste est dans ce sens
///
/// L'autre sens est le réflexe : lister les routes qui engagent la société et
/// refuser celles-là. Il a un défaut qui ne se voit qu'une fois — **l'oubli
/// laisse la porte ouverte**. Une route ajoutée la vague prochaine, qui déplace
/// un plafond ou signe un contrat, n'est dans aucune liste et n'est donc
/// refusée à personne ; rien ne rougit, et le trou se découvre chez un client.
/// Soixante-et-une routes de ce déploiement engagent l'argent ou l'existence de
/// la société aujourd'hui, contre vingt-et-une qui écrivent sans engager : la
/// liste courte est aussi celle qui se tient à jour.
///
/// Ici l'oubli ferme une porte. Une route d'écriture anodine ajoutée demain et
/// non listée est refusée à un membre, qui lit une phrase qui dit exactement
/// quoi demander et à qui — et un propriétaire, lui, continue de passer. C'est
/// la règle que `agentos_app::gate` applique un étage plus bas et pour la même
/// raison : *un déploiement sans couche plateforme n'a pas de plafond à faire
/// respecter, donc la gate refuse tout jusqu'à ce qu'un opérateur en installe
/// une — l'autre choix est un déploiement mal configuré qui est silencieusement
/// permissif.*
///
/// # Ce qui est dedans, et la seule ligne qui s'est discutée
///
/// Ce qui s'écrit et se corrige en le refaisant : un carnet de tâches, un
/// rendez-vous, un brouillon, une question de contenu, une équipe et sa
/// mission, un document, un fichier, une liste de prospects, les pas d'une
/// séquence (qui n'envoie rien elle-même), une cible de croissance. Plus trois
/// `POST` qui sont des lectures que HTTP ne sait pas dire autrement : la
/// prévisualisation d'un post, la découverte des outils d'un serveur MCP, et la
/// sonde d'un proxy.
///
/// `POST /v1/employees/{id}/desk` est la ligne qui s'est discutée : écrire à un
/// siège le réveille, et un tour coûte de l'argent. Elle reste ouverte parce
/// que c'est *le* geste du deuxième humain — répondre sur le fil — et parce que
/// la dépense qu'elle déclenche est déjà bornée deux fois sans elle : le budget
/// de tours du siège (409 quand il est épuisé) et la gate, qui refuse tout
/// paiement au-delà des plafonds. Un membre ne peut pas déplacer ces deux
/// bornes-là ; c'est ce que la liste protège.
///
/// Les lectures ne sont pas ici : **toutes** sont ouvertes à un membre, et
/// c'est un choix. Le rôle existe pour empêcher quelqu'un d'engager la société,
/// pas pour cloisonner ce qu'un collègue à qui on a déjà donné un mot de passe
/// a le droit de voir. `GET /v1/files/content` rend les octets d'un contrat
/// signé : le jour où un client veut cloisonner ça, c'est un troisième rôle et
/// c'est une autre conversation.
const MEMBER_WRITES: &[(&str, &str)] = &[
    ("POST", "/v1/work"),
    ("PUT", "/v1/work/{id}"),
    ("POST", "/v1/calendar"),
    ("POST", "/v1/employees/{id}/desk"),
    ("POST", "/v1/content/questions"),
    ("DELETE", "/v1/content/questions/{id}"),
    ("POST", "/v1/content/drafts"),
    ("PUT", "/v1/content/drafts/{id}"),
    ("POST", "/v1/prospects/import"),
    ("POST", "/v1/sequences"),
    ("DELETE", "/v1/sequences/{id}"),
    ("POST", "/v1/knowledge/documents"),
    ("POST", "/v1/files"),
    ("POST", "/v1/teams"),
    ("POST", "/v1/teams/{team_id}/sections"),
    ("PUT", "/v1/teams/{team_id}/mission"),
    ("PUT", "/v1/growth/target"),
    // Les trois `POST` qui ne changent rien chez nous.
    ("POST", "/v1/social/preview"),
    ("POST", "/v1/mcp/servers/{server}/discover"),
    ("POST", "/v1/browser/proxy/check"),
];

/// Est-ce qu'un membre a le droit de jouer ce couple ?
///
/// Une fonction pure, testée sur la liste complète des routes qui engagent —
/// écrite en toutes lettres dans le test, jamais dérivée de [`MEMBER_WRITES`],
/// sans quoi le test dirait seulement que la table est égale à elle-même.
fn member_may(method: &axum::http::Method, matched_path: &str) -> bool {
    // `HEAD` est un `GET` sans corps et `OPTIONS` est du CORS. Aucune des trois
    // ne change quoi que ce soit.
    if matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return true;
    }
    MEMBER_WRITES
        .iter()
        .any(|(verb, path)| method == verb && *path == matched_path)
}

/// Le compte de console que ce credential est, s'il en est un.
///
/// L'étiquette porte déjà l'identité : `agentos_store::api_keys::session_label`
/// écrit `session-<uuid>` et documente que c'est *la* propriété du format. On
/// la relit ici plutôt que d'ajouter un champ à [`Principal`] — et ce n'est pas
/// de la paresse, c'est ce qui fait que **la lecture ne paie rien** : le rôle
/// n'est lu que sur les appels qui engagent, donc jamais sur un `GET`, qui est
/// tout ce que la console fait en boucle.
///
/// `None` pour tout le reste : une clé de l'environnement, une clé
/// d'intégration d'un client, un employé, le système. Voir
/// [`require_console_role`] pour pourquoi ceux-là sont propriétaires.
fn console_account_of(actor: &AuditActor) -> Option<uuid::Uuid> {
    let AuditActor::Operator(label) = actor else {
        return None;
    };
    label
        .strip_prefix(agentos_store::api_keys::SESSION_LABEL_PREFIX)
        .and_then(|rest| rest.parse().ok())
}

/// Le rôle de ce credential, pour qui veut l'afficher plutôt que le faire
/// respecter.
///
/// `Ok(None)` couvre les deux « pas de rôle » que [`require_console_role`]
/// sépare — ce n'est pas une session de console, ou c'est une session dont la
/// ligne ne se lit pas — parce que l'appelant qui affiche n'a rien à décider
/// entre les deux : les deux se rendent `null`. Le seul appelant est
/// `GET /v1/whoami`.
pub(crate) async fn console_role_of(
    db: &Db,
    principal: &Principal,
) -> Result<Option<agentos_store::accounts::ConsoleRole>, agentos_store::db::StoreError> {
    match console_account_of(&principal.actor) {
        Some(account_id) => agentos_store::accounts::role_of(db, account_id).await,
        None => Ok(None),
    }
}

/// Le refus, et il nomme le droit qui manque et qui peut le donner.
///
/// Un 403 nu envoie la personne demander au support ce que cette phrase lui
/// dit. `code` reste un littéral à faible cardinalité (`error.rs`, règle 2), le
/// `detail` dit quoi faire, et les deux membres d'extension sont là pour la
/// console : elle peut griser le bouton *avant* le clic et écrire la même
/// phrase que nous, comme `approbations/Queue.tsx` le fait déjà pour
/// `role_required`.
fn not_the_owner() -> Response {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "owner_role_required",
        "this console account does not hold the owner role",
    )
    .with_detail(
        "Ce geste engage l'argent ou l'existence de la société : seul un compte `owner` de ce \
         locataire peut l'appeler. La lecture vous reste entière, ainsi que les écritures qui \
         n'engagent rien. Pour l'obtenir, demandez à un `owner` d'appeler `PUT \
         /v1/console/accounts/role` (outil MCP `console_accounts_role_set`) avec votre adresse et \
         `\"role\": \"owner\"`.",
    )
    .with_extension("required_role", serde_json::json!("owner"))
    .into_response()
}

/// **Le seul endroit qui décide de ce qu'un humain a le droit de faire.**
///
/// Posé dans `with_api_stack`, juste sous [`require_api_key`], donc au-dessus
/// de tout ce qui lit ou écrit les données d'un locataire — y compris des
/// outils MCP, que `routes::mcp_server` rejoue **dans ce routeur-ci** avec
/// l'en-tête `Authorization` du client. Un outil n'est donc pas une deuxième
/// porte : c'est la même.
///
/// Une couche plutôt qu'un extracteur `Owner` que les gestionnaires
/// concernés extrairaient : les deux sont un seul endroit où la règle est
/// écrite, mais l'extracteur se *nomme* soixante-et-une fois, et une route
/// ajoutée sans lui est une route ouverte. Ici, une route ajoutée sans rien est
/// une route fermée aux membres. C'est la même différence qu'entre les deux
/// sens de [`MEMBER_WRITES`], au niveau du dessus.
///
/// # Ce que la couche lit, et quand
///
/// Rien, tant que le geste n'engage pas. `member_may` répond sur la méthode et
/// le chemin **routé** (`MatchedPath`, donc `/v1/employees/{id}/desk` et pas
/// l'uuid), et la base n'est touchée que sur les appels qui restent. Sur
/// ceux-là, une égalité sur la clé primaire de `console_accounts`, sans cache,
/// pour que retirer un rôle soit senti par la requête suivante.
///
/// # Qui est propriétaire sans avoir de ligne
///
/// Les credentials qui ne sont pas des sessions de console : les clés de
/// `AGENTOS_API_KEYS`, qui sont celles de l'opérateur du déploiement, et les
/// clés d'intégration qu'un locataire s'émet pour son propre Claude Code. Elles
/// n'ont pas de compte humain derrière, donc pas de rôle à lire, et les
/// rétrograder couperait l'intégration de chaque client le jour du déploiement.
/// C'est le même argument que le `DEFAULT 'owner'` de la migration, une couche
/// plus haut : une politique se resserre depuis un état qui marche.
pub async fn require_console_role(
    State(db): State<Db>,
    req: Request,
    next: Next,
) -> Response {
    let matched = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str().to_owned());
    // Pas de `MatchedPath` : la requête n'a été routée nulle part, elle finira
    // en 404. On la laisse passer vers ce 404 plutôt que d'inventer un 403 sur
    // un chemin qui n'existe pas — dire « il vous manque un droit » sur une
    // URL fautive envoie chercher un rôle au lieu d'une faute de frappe.
    let Some(matched) = matched else {
        return next.run(req).await;
    };

    if member_may(req.method(), &matched) {
        return next.run(req).await;
    }

    let Some(principal) = req.extensions().get::<Principal>() else {
        // Cette couche est sous `require_api_key`, qui en pose un ou refuse.
        // Y arriver sans principal veut dire qu'on l'a montée ailleurs, et le
        // silence ici serait une route qui n'a jamais eu de rôle à vérifier.
        tracing::error!("require_console_role runs without require_api_key above it");
        return unauthorized();
    };

    let Some(account_id) = console_account_of(&principal.actor) else {
        return next.run(req).await;
    };

    match agentos_store::accounts::role_of(&db, account_id).await {
        Ok(Some(agentos_store::accounts::ConsoleRole::Owner)) => next.run(req).await,
        Ok(Some(agentos_store::accounts::ConsoleRole::Member)) => not_the_owner(),
        // Pas de ligne, ou un mot que ce binaire ne connaît pas. La première
        // est un état que rien ne produit — désactiver un compte supprime sa
        // session dans la même transaction (`0089`) — et la seconde est un
        // binaire en retard sur sa base. Les deux se refusent : deviner
        // « propriétaire » ici, c'est ouvrir la société sur une ligne qu'on n'a
        // pas su lire.
        Ok(None) => {
            tracing::warn!(%account_id, "a console session resolves to no readable role");
            not_the_owner()
        }
        // Jamais un 403 : une base en panne qui se lit comme un droit manquant
        // envoie tout le monde réclamer un rôle qu'il a déjà.
        Err(err) => ApiError::from(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// The platform principal
// ---------------------------------------------------------------------------

/// A credential that belongs to **no tenant**.
///
/// Its whole reason for existing is what it is *not*: it is not a [`Principal`],
/// so it cannot be extracted by any route in this server that reads tenant data,
/// because every one of those extracts `Principal` and only [`require_api_key`]
/// inserts one. A platform key presented to `/v1/employees` is simply a secret
/// that is not in the tenant keyring, and gets the same 401 as a typo.
///
/// The converse holds by the same construction: a tenant's key is not in
/// [`PlatformKeys`], so it cannot mint or revoke anything. That is the sentence
/// revocation depends on — a stolen key that could issue keys would make
/// revoking it pointless.
#[derive(Debug, Clone)]
pub struct PlatformPrincipal {
    /// The key's human name. Becomes the audit actor on every row the platform
    /// writes into a tenant's trail, so `operator:signup-service` is who a
    /// customer sees issued their credential.
    pub label: String,
}

/// One configured platform credential.
#[derive(Clone)]
struct PlatformKey {
    label: String,
    secret: String,
}

// Hand-written, for the reason [`ApiKey`]'s is — and this one guards the single
// credential that can mint another tenant's keys.
impl std::fmt::Debug for PlatformKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformKey")
            .field("label", &self.label)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The platform keyring, parsed once at boot.
///
/// Empty is the default and the correct default: a deployment that has not been
/// given a platform key has no signup surface at all, and `/v1/platform/*`
/// answers 401 to everybody including us.
#[derive(Debug, Clone, Default)]
pub struct PlatformKeys(Arc<Vec<PlatformKey>>);

/// Why `AGENTOS_PLATFORM_KEYS` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PlatformKeysError {
    /// An entry was not `label:secret`.
    #[error("entry {index} is not `label:secret`")]
    Shape {
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// A short secret is a guessable secret.
    #[error("entry {index} has a secret shorter than {min} characters", min = ApiKeys::MIN_SECRET_LEN)]
    WeakSecret {
        /// Zero-based position of the offending entry.
        index: usize,
    },
}

impl PlatformKeys {
    /// Parse `label:secret,label:secret,…`.
    ///
    /// **Two fields, not three, and the missing one is the point.** An entry
    /// here names no tenant because this credential speaks for none; a form that
    /// accepted a tenant uuid would be a form somebody eventually pastes a
    /// tenant key into, and it would then hold both authorities at once.
    pub fn parse(raw: &str) -> Result<Self, PlatformKeysError> {
        let keys = raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .enumerate()
            .map(|(index, entry)| {
                // `splitn(2)` so a secret may itself contain colons, same as the
                // tenant keyring.
                let (label, secret) = entry
                    .split_once(':')
                    .ok_or(PlatformKeysError::Shape { index })?;
                if label.is_empty() {
                    return Err(PlatformKeysError::Shape { index });
                }
                if secret.len() < ApiKeys::MIN_SECRET_LEN {
                    return Err(PlatformKeysError::WeakSecret { index });
                }
                Ok(PlatformKey {
                    label: label.to_owned(),
                    secret: secret.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self(Arc::new(keys)))
    }

    /// No platform keys configured: nothing can sign anybody up.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many are configured. For the boot log — never the secrets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Resolve a presented secret. Constant-time, linear, for the same reason
    /// [`ApiKeys::lookup`] is.
    fn lookup(&self, presented: &str) -> Option<PlatformPrincipal> {
        self.0
            .iter()
            .find(|key| ct_eq(key.secret.as_bytes(), presented.as_bytes()))
            .map(|key| PlatformPrincipal {
                label: key.label.clone(),
            })
    }
}

/// Reject the request, or attach a [`PlatformPrincipal`] to it.
///
/// Sits above `/v1/platform/*` and nothing else.
pub async fn require_platform_key(
    State(keys): State<PlatformKeys>,
    mut req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    let Some(principal) = presented.and_then(|secret| keys.lookup(secret)) else {
        return unauthorized();
    };

    req.extensions_mut().insert(principal);
    next.run(req).await
}

impl<S: Send + Sync> FromRequestParts<S> for PlatformPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            tracing::error!(
                path = %parts.uri.path(),
                "route extracts a PlatformPrincipal but is not behind require_platform_key"
            );
            ApiError::internal()
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            // Not a client error: a route that extracts a Principal was mounted
            // outside `require_api_key`. Fail closed and page someone.
            tracing::error!(
                path = %parts.uri.path(),
                "route extracts a Principal but is not behind require_api_key"
            );
            ApiError::internal()
        })
    }
}

// ---------------------------------------------------------------------------
// Le mot de passe d'une personne
// ---------------------------------------------------------------------------
//
// **Pourquoi ceci est dans `auth.rs` et pas dans `routes::accounts`.** Deux
// routes en ont besoin et elles sont sur deux étages différents :
// `routes::platform::create_account` dérive une empreinte avec la clé du
// fournisseur, `routes::accounts::open_session` en vérifie une sans credential
// du tout. Ce module est déjà l'autorité sur « qui appelle, établi depuis le
// credential et depuis rien d'autre » ; un troisième trousseau — celui d'une
// personne — s'y range, et l'argument sur POURQUOI il est haché autrement que
// les deux autres se lit à côté des deux autres.
//
// L'argument de bout en bout est dans
// `migrations/0089_une_personne_ouvre_la_console.sql` ; la route qui s'en sert
// est `apps/server/src/routes/accounts.rs`, qui porte l'argument de sécurité de
// la session elle-même.
//
// L'argument « pourquoi pas le HMAC d'`api_keys` » est dans
// `migrations/0089_une_personne_ouvre_la_console.sql`, en entier : là-bas
// l'entrée fait 256 bits de CSPRNG et il n'y a rien à étirer ; ici elle est
// choisie par un humain et le dictionnaire existe.
//
// **Pourquoi `ring` et pas un crate de plus.** Le workspace n'a ni `argon2` ni
// `pbkdf2` ; il a `hmac`, `sha2` et — déjà dans le graphe de compilation, tiré
// par rustls via `sqlx/tls-rustls-ring` — `ring`. Les trois options réelles
// étaient donc : ajouter `argon2`, écrire PBKDF2 à la main sur `hmac`, ou
// déclarer une dépendance sur une bibliothèque déjà compilée.
//
// Écrire PBKDF2 à la main est exclu : c'est de la cryptographie faite maison
// pour économiser une ligne de `Cargo.toml`. Entre les deux autres, `argon2`
// résiste mieux au GPU et c'est vrai ; il coûte un crate de plus, un choix de
// paramètres mémoire à défendre, et il n'est pas ce qui décide de l'issue ici —
// ce qui décide, c'est qu'un dump seul ne suffise pas à casser des mots de
// passe en masse, et 600 000 itérations de PBKDF2-HMAC-SHA256 sont la
// recommandation courante de l'OWASP pour exactement cette raison. `ring` est
// donc pris : rien de neuf dans la lock file, une implémentation auditée, et
// une vérification à temps constant fournie par la bibliothèque.

/// Version d'empreinte que ce build écrit.
///
/// Le premier octet de la colonne. Il existe pour que le facteur de travail
/// puisse MONTER : les itérations d'un PBKDF2 doivent suivre le matériel, et
/// sans préfixe de version, les augmenter invaliderait toutes les lignes d'un
/// coup. Avec, une ligne se re-dérive à la prochaine connexion réussie — quand
/// le mot de passe en clair est là, et il n'est là qu'à ce moment.
///
/// ponytail : la re-dérivation n'est pas écrite. Une seule version existe, donc
/// il n'y a rien à migrer, et un chemin de migration sans deuxième version est
/// du code que personne n'exécute. Le jour où `KDF_VERSION` passe à 2, ce sont
/// trois lignes dans [`open_session`] : si la ligne lue est en version 1 et que
/// le mot de passe est bon, réécrire l'empreinte.
const KDF_VERSION: u8 = 1;

/// Itérations pour [`KDF_VERSION`] = 1. La recommandation OWASP 2023 pour
/// PBKDF2-HMAC-SHA256.
const KDF_V1_ITERATIONS: u32 = 600_000;

/// Octets de sel, par ligne. 128 bits : de quoi rendre toute table
/// pré-calculée inutile, et de quoi que deux personnes qui choisissent le même
/// mot de passe n'aient pas la même empreinte.
const SALT_LEN: usize = 16;

/// Octets dérivés. La sortie native de SHA-256 ; en demander plus ferait tourner
/// tout le PBKDF2 une deuxième fois pour rien.
const DERIVED_LEN: usize = 32;

/// `[version][sel][dérivé]` — 49 octets, ce que la CHECK d'`0089` exige.
const HASH_LEN: usize = 1 + SALT_LEN + DERIVED_LEN;

/// Le sel utilisé quand il n'y a pas de ligne à vérifier.
///
/// Sa valeur n'a aucune importance et son existence en a une : c'est ce qui
/// fait qu'une adresse inconnue coûte le même temps qu'un mot de passe faux.
const NO_ROW_SALT: &[u8; SALT_LEN] = b"agentos.no-row..";

fn v1_iterations() -> NonZeroU32 {
    NonZeroU32::new(KDF_V1_ITERATIONS).expect("600000 is not zero")
}

/// Dériver une empreinte neuve, sel compris.
///
/// Appelée par `routes::platform` à la création d'un compte, et par personne
/// d'autre — un mot de passe n'entre dans ce système qu'à ce moment-là et à la
/// connexion.
pub(crate) fn hash_password(password: &str) -> Vec<u8> {
    use ring::rand::SecureRandom as _;

    let mut salt = [0u8; SALT_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut salt)
        // Le CSPRNG du système. S'il ne répond pas, il n'y a pas de repli
        // acceptable : un sel prévisible est un sel absent, et rendre un compte
        // sans sel serait pire que refuser de le créer.
        .expect("the OS CSPRNG");

    let mut out = Vec::with_capacity(HASH_LEN);
    out.push(KDF_VERSION);
    out.extend_from_slice(&salt);

    let mut derived = [0u8; DERIVED_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        v1_iterations(),
        &salt,
        password.as_bytes(),
        &mut derived,
    );
    out.extend_from_slice(&derived);
    out
}

/// Vérifier un mot de passe contre une empreinte stockée.
///
/// **Une empreinte illisible — une tranche vide parce qu'il n'y avait pas de
/// ligne, une version qu'on ne connaît pas, une longueur fausse — dépense quand
/// même la dérivation** avant de refuser. C'est tout l'intérêt de la fonction :
/// sans ça, `credentials()` rendant `None` reviendrait en une microseconde là où
/// un mot de passe faux prend trois cents millisecondes, et la différence est
/// lisible depuis n'importe où. Elle dirait « cette adresse est cliente chez
/// nous », une adresse à la fois, à qui veut.
///
/// La comparaison finale est celle de `ring`, qui est à temps constant — même
/// raison qu'`auth::ct_eq`, sauf qu'ici il n'y a pas à l'écrire.
pub(crate) fn verify_password(stored: &[u8], password: &str) -> bool {
    let Some((&KDF_VERSION, rest)) = stored.split_first() else {
        return spend_and_refuse(password);
    };
    if rest.len() != SALT_LEN + DERIVED_LEN {
        return spend_and_refuse(password);
    }
    let (salt, expected) = rest.split_at(SALT_LEN);
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        v1_iterations(),
        salt,
        password.as_bytes(),
        expected,
    )
    .is_ok()
}

/// Les deux mêmes, hors du fil de l'exécuteur.
///
/// **Ceci n'est pas de la prudence, c'est la condition pour que le KDF soit
/// utilisable.** 600 000 itérations, ce sont quelques centaines de millisecondes
/// de CPU *sans point d'attente* : lancées directement dans un handler, elles
/// bloquent un worker tokio, et tokio en a autant que de cœurs. Quatre
/// connexions simultanées sur une machine à quatre cœurs, et le serveur ne
/// répond plus à personne — y compris aux sondes. `spawn_blocking` les envoie
/// sur le pool prévu pour ça.
///
/// Une `JoinError` veut dire que la tâche a paniqué (le CSPRNG du système) : un
/// 500, jamais un refus, parce qu'un refus dirait à la personne que son mot de
/// passe est faux alors que c'est nous qui sommes cassés.
pub(crate) async fn hash_password_off_thread(password: String) -> Result<Vec<u8>, ApiError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|err| {
            tracing::error!(%err, "the password KDF did not finish");
            ApiError::internal()
        })
}

pub(crate) async fn verify_password_off_thread(
    stored: Vec<u8>,
    password: String,
) -> Result<bool, ApiError> {
    tokio::task::spawn_blocking(move || verify_password(&stored, &password))
        .await
        .map_err(|err| {
            tracing::error!(%err, "the password KDF did not finish");
            ApiError::internal()
        })
}

/// Payer le prix d'une vérification, puis refuser.
fn spend_and_refuse(password: &str) -> bool {
    let mut sink = [0u8; DERIVED_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        v1_iterations(),
        NO_ROW_SALT,
        password.as_bytes(),
        &mut sink,
    );
    // `black_box`, parce que `sink` est mort ensuite et qu'un optimiseur a le
    // droit de supprimer un calcul dont personne ne lit le résultat. Il
    // supprimerait avec lui la seule chose que cette fonction fait.
    std::hint::black_box(sink);
    false
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

/// Longueur minimale d'un mot de passe, à la création.
///
/// Douze, pas huit. Ce n'est pas un avis sur l'entropie : c'est que le KDF
/// défend contre un dump volé, et que douze caractères choisis sont la
/// frontière en dessous de laquelle 600 000 itérations ne rattrapent plus rien.
/// Aucune règle de composition — majuscule, chiffre, symbole — parce qu'elles
/// produisent `Password1!` et rien d'autre.
pub(crate) const MIN_PASSWORD_LEN: usize = 12;

/// Ce que la colonne accepte. La normalisation est ici et la CHECK
/// `accounts_email_is_normalised` est ce qui garantit qu'elle a eu lieu.
///
/// Pas de validation RFC 5322 : elle n'attrape rien qu'un envoi de courriel
/// n'attrape mieux, et une regex d'adresse est une façon connue de refuser les
/// adresses de vrais gens. Ce qui est vérifié, c'est ce que la base exige.
pub(crate) fn normalise_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let plausible = (3..=254).contains(&email.len())
        && email.match_indices('@').count() == 1
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.chars().any(char::is_whitespace);
    plausible.then_some(email)
}
#[cfg(test)]
mod tests {

    /// A passphrase for the KDF tests. Not a credential of anything.
    const TEST_PASSWORD: &str = "un-mot-de-passe-honnete";

    /// The same round trip, on the blocking pool — which is where both of these
    /// actually run, because 600 000 iterations with no await point in them
    /// would otherwise hold a tokio worker for the whole derivation.
    #[tokio::test]
    async fn a_password_survives_the_trip_through_the_blocking_pool() {
        let stored = hash_password_off_thread(TEST_PASSWORD.to_owned())
            .await
            .expect("derive");
        assert_eq!(stored.len(), HASH_LEN);
        assert!(
            verify_password_off_thread(stored.clone(), TEST_PASSWORD.to_owned())
                .await
                .expect("verify")
        );
        assert!(
            !verify_password_off_thread(stored, "autre-chose-entierement".to_owned())
                .await
                .expect("verify")
        );
    }

    /// Le KDF, sans base : sel par ligne, vérification qui accepte le bon mot
    /// de passe et refuse tout le reste, et une empreinte illisible qui refuse
    /// au lieu de paniquer.
    #[test]
    fn a_digest_is_salted_per_row_and_verifies_only_its_own_password() {
        let one = hash_password(TEST_PASSWORD);
        let two = hash_password(TEST_PASSWORD);

        assert_eq!(one.len(), HASH_LEN);
        assert_eq!(one[0], KDF_VERSION);
        assert_ne!(one, two, "two people with one password, two digests");
        assert!(
            !String::from_utf8_lossy(&one).contains(TEST_PASSWORD),
            "the password is not in its own digest"
        );

        assert!(verify_password(&one, TEST_PASSWORD));
        assert!(verify_password(&two, TEST_PASSWORD));
        assert!(!verify_password(&one, "presque-le-bon-mot!"));
        assert!(!verify_password(&one, ""));

        // Illisible: vide, version inconnue, longueur fausse. Aucune ne panique
        // et aucune n'accepte.
        assert!(!verify_password(&[], TEST_PASSWORD));
        assert!(!verify_password(&[0u8; HASH_LEN], TEST_PASSWORD));
        assert!(!verify_password(&one[..HASH_LEN - 1], TEST_PASSWORD));
    }

    #[test]
    fn an_address_is_normalised_or_it_is_not_an_address() {
        assert_eq!(
            normalise_email("  Anna@Example.TEST "),
            Some("anna@example.test".to_owned())
        );
        for bad in [
            "",
            "@example.test",
            "anna@",
            "anna",
            "a@b@c",
            "an na@x.test",
        ] {
            assert_eq!(normalise_email(bad), None, "{bad:?}");
        }
    }

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210";

    /// Shared with every other test module in this crate — see
    /// [`TEST_MASTER_KEY`].
    const MASTER: &str = TEST_MASTER_KEY;

    fn env_keyring() -> (TenantId, ApiKeys) {
        let tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let raw = format!("ops-console:{}:{SECRET}", tenant.as_uuid());
        (tenant, ApiKeys::parse(&raw).expect("valid keyring"))
    }

    /// A secret no `api_keys` row can hold, because nothing has ever seen it.
    ///
    /// **`lookup` is cross-tenant by definition** — it scans the table with no
    /// tenant predicate, which is the whole reason it needs an admin
    /// transaction — so a row another test in this binary left behind is a row
    /// these assertions can see. `an_env_key_wins_over_a_table_row_naming_the_same_secret`
    /// really does leave one holding `SECRET`, deliberately, and a test that
    /// then asserted `SECRET` authenticates nobody would be asserting about the
    /// wrong keyring. A fresh uuid costs nothing and cannot collide.
    fn unheld_secret() -> String {
        format!("{SECRET}-{}", Uuid::now_v7())
    }

    /// A pool, or `None` when there is nothing to talk to.
    ///
    /// [`Keyring`] holds one because the second half of every lookup is a table.
    /// The tests below that are only about the *environment* half still need it
    /// — the type cannot be built without one — and they are still meaningful
    /// without a row in that table, which is the state they run in.
    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the auth keyring needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A router whose only handler flips `reached`, behind the auth layer.
    fn app(keys: Keyring, reached: Arc<AtomicBool>) -> Router {
        Router::new()
            .route(
                "/employees/{id}",
                get(move |principal: Principal| {
                    let reached = reached.clone();
                    async move {
                        reached.store(true, Ordering::SeqCst);
                        principal.tenant_id.to_string()
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(keys, require_api_key))
    }

    async fn call(app: Router, header: Option<&str>) -> (StatusCode, String) {
        let mut req = HttpRequest::builder().uri("/employees/anything");
        if let Some(value) = header {
            req = req.header(header::AUTHORIZATION, value);
        }
        let response = app
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("service");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn an_unauthenticated_request_is_refused_before_the_handler_runs() {
        let Some(db) = db().await else { return };
        let (_, env) = env_keyring();
        let keys = Keyring::new(env, db, MASTER);

        for header in [
            None,
            Some("Bearer wrong"),
            // Right secret, wrong scheme.
            Some(SECRET),
            Some(&format!("Basic {SECRET}")),
            // A secret neither keyring holds.
            Some(&format!("Bearer {}", unheld_secret())),
        ] {
            let reached = Arc::new(AtomicBool::new(false));
            let (status, _) = call(app(keys.clone(), reached.clone()), header).await;

            assert_eq!(status, StatusCode::UNAUTHORIZED, "for header {header:?}");
            assert!(
                !reached.load(Ordering::SeqCst),
                "the handler ran for header {header:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_valid_key_names_its_own_tenant() {
        let Some(db) = db().await else { return };
        let (tenant, env) = env_keyring();
        let reached = Arc::new(AtomicBool::new(false));

        let (status, body) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
            Some(&format!("Bearer {SECRET}")),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(reached.load(Ordering::SeqCst));
        assert_eq!(
            body,
            tenant.to_string(),
            "the tenant came from the key, not from the path"
        );
    }

    #[tokio::test]
    async fn an_empty_keyring_authenticates_nobody() {
        let Some(db) = db().await else { return };
        let env = ApiKeys::parse("   ").expect("empty is valid");
        assert!(env.is_empty());

        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
            Some(&format!("Bearer {}", unheld_secret())),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!reached.load(Ordering::SeqCst));
    }

    /// **Which keyring wins.** One secret, two homes, two different tenants —
    /// and the answer has to be the one nothing at runtime can rewrite.
    ///
    /// Break it by swapping the two branches of [`Keyring::resolve`] and this
    /// says:
    ///
    /// ```text
    /// assertion `left == right` failed: a row must not be able to shadow the
    /// deployment's own keyring
    /// ```
    #[tokio::test]
    async fn an_env_key_wins_over_a_table_row_naming_the_same_secret() {
        let Some(db) = db().await else { return };

        // A secret of this run's own, in *both* keyrings. Fresh rather than the
        // module's `SECRET`, because `api_keys.secret_hash` is unique: a fixed
        // one would make the row survive the run and the second run collide on
        // it, and a test that only passes against a clean database is a test
        // nobody can re-run while debugging the thing it caught.
        let shared = unheld_secret();
        let env_tenant = TenantId::from_uuid(Uuid::from_u128(1));
        let env = ApiKeys::parse(&format!("ops-console:{}:{shared}", env_tenant.as_uuid()))
            .expect("valid keyring");

        // A real tenant with a real key whose secret is byte-for-byte the one
        // the environment already claims.
        let row_tenant = TenantId::new_v7(chrono::Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'shadow')")
            .bind(row_tenant.as_uuid())
            .bind(format!("shadow-{}", row_tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let hasher = agentos_app::api_keys::Hasher::from_master_key(MASTER);
        agentos_store::api_keys::issue(
            &db,
            uuid::Uuid::now_v7(),
            row_tenant,
            "shadow",
            &hasher.digest(&shared),
            &AuditActor::Operator("test".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("issue");

        let reached = Arc::new(AtomicBool::new(false));
        let (status, body) = call(
            app(Keyring::new(env, db, MASTER), reached.clone()),
            Some(&format!("Bearer {shared}")),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            env_tenant.to_string(),
            "a row must not be able to shadow the deployment's own keyring"
        );
    }

    /// **The revocation proof, through the whole HTTP stack.** Issue a key, use
    /// it, delete it, use it again — no restart, no waiting.
    #[tokio::test]
    async fn a_revoked_table_key_is_refused_by_the_very_next_request() {
        let Some(db) = db().await else { return };
        let tenant = TenantId::new_v7(chrono::Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'revoked')")
            .bind(tenant.as_uuid())
            .bind(format!("revoked-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let keys = Keyring::new(ApiKeys::parse("").expect("empty"), db.clone(), MASTER);
        let issued = agentos_app::api_keys::issue(
            &db,
            keys.hasher(),
            tenant,
            "ops",
            &AuditActor::Operator("platform".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("issue");
        let header = format!("Bearer {}", issued.secret.expose_for_transport());

        let reached = Arc::new(AtomicBool::new(false));
        let (status, body) = call(app(keys.clone(), reached.clone()), Some(&header)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, tenant.to_string(), "the row named the tenant");

        agentos_app::api_keys::revoke(
            &db,
            issued.id,
            &AuditActor::Operator("platform".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("revoke");

        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(app(keys, reached.clone()), Some(&header)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the request after the DELETE must fail; there is no cache to expire"
        );
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[test]
    fn a_malformed_keyring_is_a_boot_failure_not_a_silent_skip() {
        let tenant = Uuid::from_u128(1);
        assert!(matches!(
            ApiKeys::parse("no-colons-here"),
            Err(ApiKeysError::Shape { index: 0 })
        ));
        assert!(matches!(
            ApiKeys::parse(&format!("label:not-a-uuid:{SECRET}")),
            Err(ApiKeysError::TenantId { index: 0 })
        ));
        assert!(matches!(
            ApiKeys::parse(&format!("label:{tenant}:short")),
            Err(ApiKeysError::WeakSecret { index: 0 })
        ));
        // The index points at the offending entry, not at the first one.
        assert!(matches!(
            ApiKeys::parse(&format!("a:{tenant}:{SECRET}, b:{tenant}:short")),
            Err(ApiKeysError::WeakSecret { index: 1 })
        ));
    }

    #[test]
    fn a_secret_may_contain_colons() {
        let tenant = Uuid::from_u128(7);
        let secret = format!("{SECRET}:with:colons");
        let keys = ApiKeys::parse(&format!("label:{tenant}:{secret}")).expect("valid");
        assert_eq!(keys.len(), 1);
        assert!(keys.lookup(&secret).is_some());
        assert!(keys.lookup(SECRET).is_none());
    }

    #[test]
    fn the_actor_is_the_key_label_never_the_secret() {
        let (_, keys) = env_keyring();
        let principal = keys.lookup(SECRET).expect("known key");
        match principal.actor {
            AuditActor::Operator(who) => assert_eq!(who, "ops-console"),
            other => panic!("expected an operator, got {other:?}"),
        }
    }

    /// **A keyring must not print what it holds.**
    ///
    /// [`Keyring`] has no `Debug` at all, which is what keeps these off the one
    /// surface that renders types by accident — but these two are `pub`, they
    /// are what `Config` holds, and one `tracing::debug!(?keys)` anywhere is a
    /// log line carrying every operator credential in the deployment. The
    /// labels are the half worth printing and the half that is already the
    /// audit actor; the secrets are the half that is never worth printing.
    #[test]
    fn a_keyring_renders_its_labels_and_never_its_secrets() {
        let tenant = Uuid::from_u128(1);
        let env = ApiKeys::parse(&format!("ops-console:{tenant}:{SECRET}")).expect("valid");
        let rendered = format!("{env:?}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(
            rendered.contains("ops-console") && rendered.contains(&tenant.to_string()),
            "the half worth printing is missing: {rendered}"
        );

        let platform = PlatformKeys::parse(&format!("signup:{OTHER}")).expect("valid");
        let rendered = format!("{platform:?}");
        assert!(!rendered.contains(OTHER), "{rendered}");
        assert!(rendered.contains("signup"), "{rendered}");
    }

    #[test]
    fn comparison_does_not_short_circuit() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    // -- the platform keyring ---------------------------------------------

    #[test]
    fn a_platform_entry_names_no_tenant_and_a_malformed_one_is_a_boot_failure() {
        let keys = PlatformKeys::parse(&format!("signup:{SECRET}, ops:{OTHER}")).expect("valid");
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys.lookup(SECRET).expect("known").label,
            "signup",
            "the label is the audit actor"
        );
        assert!(keys.lookup("nope").is_none());

        assert!(PlatformKeys::parse("").expect("empty is valid").is_empty());
        assert!(matches!(
            PlatformKeys::parse("no-colon-here"),
            Err(PlatformKeysError::Shape { index: 0 })
        ));
        assert!(matches!(
            PlatformKeys::parse("label:short"),
            Err(PlatformKeysError::WeakSecret { index: 0 })
        ));
        assert!(matches!(
            PlatformKeys::parse(&format!("a:{SECRET}, b:short")),
            Err(PlatformKeysError::WeakSecret { index: 1 })
        ));
        // A three-field entry is a tenant keyring line pasted into the wrong
        // variable. It parses — the uuid becomes part of the secret — and it
        // therefore authenticates nobody, which is the failure direction that
        // does not hand a tenant's key platform authority.
        let pasted = PlatformKeys::parse(&format!("ops:{}:{SECRET}", Uuid::from_u128(1)))
            .expect("parses as label + a secret containing colons");
        assert!(
            pasted.lookup(SECRET).is_none(),
            "the tenant uuid is part of the secret, so the tenant's key does not open this"
        );
    }

    /// **The two keyrings do not overlap, and that is what makes revocation
    /// mean anything.** A tenant's key cannot mint; the minting key cannot read.
    #[tokio::test]
    async fn a_tenant_key_is_not_a_platform_key_and_the_reverse() {
        let Some(db) = db().await else { return };
        let (_, env) = env_keyring();
        let tenant_keys = Keyring::new(env, db, MASTER);
        let platform_keys = PlatformKeys::parse(&format!("signup:{OTHER}")).expect("valid");

        // The tenant's secret, offered to the platform keyring.
        assert!(platform_keys.lookup(SECRET).is_none());

        // The platform's secret, offered to a tenant route.
        let reached = Arc::new(AtomicBool::new(false));
        let (status, _) = call(
            app(tenant_keys, reached.clone()),
            Some(&format!("Bearer {OTHER}")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a platform key must not read tenant data"
        );
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_platform_layer_refuses_before_the_handler_runs() {
        let keys = PlatformKeys::parse(&format!("signup:{SECRET}")).expect("valid");
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        let router = Router::new()
            .route(
                "/v1/platform/keys",
                get(move |principal: PlatformPrincipal| {
                    let flag = flag.clone();
                    async move {
                        flag.store(true, Ordering::SeqCst);
                        principal.label
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                keys,
                require_platform_key,
            ));

        for (header, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(format!("Bearer {OTHER}")), StatusCode::UNAUTHORIZED),
            (Some(SECRET.to_owned()), StatusCode::UNAUTHORIZED),
            (Some(format!("Bearer {SECRET}")), StatusCode::OK),
        ] {
            reached.store(false, Ordering::SeqCst);
            let mut req = HttpRequest::builder().uri("/v1/platform/keys");
            if let Some(value) = &header {
                req = req.header(header::AUTHORIZATION, value);
            }
            let response = router
                .clone()
                .oneshot(req.body(Body::empty()).expect("request"))
                .await
                .expect("service");
            assert_eq!(response.status(), expected, "for header {header:?}");
            assert_eq!(
                reached.load(Ordering::SeqCst),
                expected == StatusCode::OK,
                "for header {header:?}"
            );
        }
    }

    /// An empty platform keyring is the default, and it closes the door rather
    /// than opening it.
    #[tokio::test]
    async fn no_platform_key_configured_means_nobody_can_sign_anybody_up() {
        let keys = PlatformKeys::parse("").expect("empty is valid");
        assert!(keys.is_empty());
        assert!(keys.lookup(SECRET).is_none());
        assert!(keys.lookup("").is_none());
    }

    // -----------------------------------------------------------------------
    // Le rôle de console
    // -----------------------------------------------------------------------

    /// **Les soixante-et-une routes qui engagent l'argent ou l'existence de la
    /// société, écrites en toutes lettres.**
    ///
    /// Écrites, et pas dérivées de [`MEMBER_WRITES`] : une liste construite à
    /// partir de la table que la table est censée décider serait l'assertion
    /// « la table est égale à elle-même », qui ne peut pas rougir. Celle-ci
    /// rougit dans les deux sens qui comptent — si quelqu'un ouvre une de ces
    /// routes aux membres, et si quelqu'un renomme un chemin sans le dire.
    const ENGAGES_THE_COMPANY: &[(&str, &str)] = &[
        // Les credentials
        ("POST", "/v1/keys"),
        ("DELETE", "/v1/keys/{id}"),
        // Les sièges : en créer un achète onze ressources, en résilier un les rend
        ("POST", "/v1/employees"),
        ("POST", "/v1/employees/{id}/suspend"),
        ("POST", "/v1/employees/{id}/resume"),
        ("POST", "/v1/employees/{id}/terminate"),
        ("POST", "/v1/companies"),
        ("POST", "/v1/org"),
        // Le domaine d'envoi : la réputation d'expéditeur du client
        ("POST", "/v1/domain"),
        ("POST", "/v1/domain/verify"),
        ("POST", "/v1/domain/dns"),
        ("PUT", "/v1/domains/{domain}/cap"),
        ("DELETE", "/v1/domains/{domain}"),
        // L'existence même
        ("POST", "/v1/halt"),
        ("DELETE", "/v1/halt"),
        ("PUT", "/v1/window"),
        ("PUT", "/v1/employees/{id}/initiative"),
        // L'argent qu'on approuve, et les plafonds qui le bornent
        ("POST", "/v1/approvals/{id}/approve"),
        ("POST", "/v1/approvals/{id}/deny"),
        ("POST", "/v1/capability-requests/decide"),
        ("PUT", "/v1/employees/{id}/spend-caps"),
        ("PUT", "/v1/policy/roles/{role}"),
        ("PUT", "/v1/teams/{team_id}/budget"),
        ("PUT", "/v1/teams/{team_id}/policy-role"),
        ("POST", "/v1/teams/{team_id}/members"),
        ("PUT", "/v1/teams/{team_id}/members/{employee_id}"),
        ("DELETE", "/v1/teams/{team_id}/members/{employee_id}"),
        // De qui est la facture du modèle, et par où sort le navigateur
        ("POST", "/v1/model"),
        ("PUT", "/v1/browser/proxy"),
        ("DELETE", "/v1/browser/proxy"),
        // Les outils que les sièges ont le droit d'appeler
        ("POST", "/v1/mcp/connect"),
        ("POST", "/v1/mcp/servers"),
        ("DELETE", "/v1/mcp/servers/{server}"),
        ("PUT", "/v1/mcp/servers/{server}/tools/{tool}"),
        ("POST", "/v1/mcp/oauth/start"),
        // Ce qui sort devant des tiers
        ("POST", "/v1/social/accounts/connect"),
        ("POST", "/v1/social/posts"),
        ("POST", "/v1/public-register/consent"),
        ("PUT", "/v1/employees/{id}/booking"),
        ("POST", "/v1/sequences/{id}/enroll"),
        ("POST", "/v1/employees/{id}/queue/export"),
        ("POST", "/v1/content/questions/{id}/measure"),
        ("POST", "/v1/employees/{id}/interview"),
        ("POST", "/a2a/jsonrpc"),
        // Les livres
        ("POST", "/v1/invoices/{id}/paid"),
        ("POST", "/v1/invoices/{id}/credit"),
        ("PUT", "/v1/invoices/issuer"),
        ("POST", "/v1/quotes/{id}/accepted"),
        ("POST", "/v1/quotes/{id}/declined"),
        // Les numéros
        ("POST", "/v1/pool/numbers"),
        ("POST", "/v1/pool/numbers/{id}/reassign"),
        // Et le rôle lui-même : sans cette ligne, un membre se promeut
        ("PUT", "/v1/console/accounts/role"),
    ];

    /// **Aucune de ces routes n'est jouable sans le rôle, et les autres le
    /// sont.**
    ///
    /// La deuxième moitié est la garde : sans elle, un `member_may` qui
    /// rendrait `false` partout passerait la première et aurait tout fermé, y
    /// compris la lecture.
    #[test]
    fn a_member_may_not_touch_what_engages_the_company_and_may_touch_the_rest() {
        for (verb, path) in ENGAGES_THE_COMPANY {
            let method = axum::http::Method::from_bytes(verb.as_bytes()).expect("une méthode");
            assert!(
                !member_may(&method, path),
                "{verb} {path} engage la société et un membre peut l'appeler"
            );
        }

        // La garde. Les lectures d'abord — toutes ouvertes, y compris celles
        // des chemins ci-dessus.
        for (verb, path) in [
            ("GET", "/v1/halt"),
            ("GET", "/v1/keys"),
            ("GET", "/v1/employees/{id}/spend-caps"),
            ("HEAD", "/v1/pnl"),
        ] {
            let method = axum::http::Method::from_bytes(verb.as_bytes()).expect("une méthode");
            assert!(member_may(&method, path), "{verb} {path}");
        }
        // Puis les écritures qui n'engagent rien, telles que la table les
        // nomme : celle-ci peut se lire depuis `MEMBER_WRITES` sans rien
        // affaiblir, puisque l'assertion qui compte est celle du dessus.
        for (verb, path) in MEMBER_WRITES {
            let method = axum::http::Method::from_bytes(verb.as_bytes()).expect("une méthode");
            assert!(member_may(&method, path), "{verb} {path}");
        }

        // Une route d'écriture que personne n'a classée est fermée aux
        // membres, pas ouverte. C'est le sens de la liste, et c'est ce qui
        // rend une vague future sûre par défaut.
        assert!(!member_may(
            &axum::http::Method::POST,
            "/v1/quelque-chose-que-personne-na-encore-ecrit"
        ));
    }

    /// L'étiquette d'une session porte l'id du compte, et rien d'autre ne la
    /// porte.
    #[test]
    fn only_a_console_session_label_names_a_person() {
        let account = Uuid::now_v7();
        let label = agentos_store::api_keys::session_label(account);
        assert_eq!(
            console_account_of(&AuditActor::Operator(label)),
            Some(account)
        );
        for other in ["ops-console", "claude-code", "session-pas-un-uuid", ""] {
            assert_eq!(
                console_account_of(&AuditActor::Operator(other.to_owned())),
                None,
                "{other:?}"
            );
        }
        assert_eq!(console_account_of(&AuditActor::System), None);
    }

    /// **Le refus et son contraire, par la vraie pile HTTP.**
    ///
    /// Quatre appels sur deux routes, dont l'une engage : le membre est refusé
    /// avec la phrase qui dit quoi demander, le propriétaire passe, le membre
    /// passe sur l'écriture qui n'engage rien, et la clé d'intégration —
    /// celle qui n'a aucun humain derrière — n'a rien perdu.
    #[tokio::test]
    async fn a_member_is_refused_where_an_owner_and_an_integration_key_pass() {
        let Some(db) = db().await else { return };

        let tenant = TenantId::new_v7(chrono::Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'roles')")
            .bind(tenant.as_uuid())
            .bind(format!("roles-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");

        let keys = Keyring::new(ApiKeys::parse("").expect("empty"), db.clone(), MASTER);

        // Deux personnes : la première est propriétaire par construction, la
        // seconde ne l'est pas. C'est `accounts::create` qui décide, et c'est
        // le fait sur lequel tout ce fichier repose.
        let token_of = |who: &str| {
            let db = db.clone();
            let hasher = keys.hasher().clone();
            let email = format!("{who}-{}@example.test", Uuid::now_v7().simple());
            async move {
                let account = agentos_store::accounts::create(
                    &db,
                    Uuid::now_v7(),
                    tenant,
                    &email,
                    &hash_password("un-mot-de-passe-honnete"),
                    chrono::Utc::now(),
                )
                .await
                .expect("créer la personne");
                let issued = agentos_app::api_keys::issue(
                    &db,
                    &hasher,
                    tenant,
                    &agentos_store::api_keys::session_label(account.id),
                    &AuditActor::Operator("test".to_owned()),
                    chrono::Utc::now(),
                )
                .await
                .expect("ouvrir la session");
                (
                    account.role,
                    format!("Bearer {}", issued.secret.expose_for_transport()),
                )
            }
        };
        let (owner_role, owner) = token_of("fondatrice").await;
        let (member_role, member) = token_of("stagiaire").await;
        assert_eq!(owner_role, agentos_store::accounts::ConsoleRole::Owner);
        assert_eq!(member_role, agentos_store::accounts::ConsoleRole::Member);

        // La clé d'intégration du locataire : aucune ligne dans
        // `console_accounts`, donc aucun rôle à lire.
        let integration = agentos_app::api_keys::issue(
            &db,
            keys.hasher(),
            tenant,
            "claude-code",
            &AuditActor::Operator("test".to_owned()),
            chrono::Utc::now(),
        )
        .await
        .expect("émettre");
        let integration = format!("Bearer {}", integration.secret.expose_for_transport());

        // Deux routes, l'une engage et l'autre non, derrière les deux couches
        // dans l'ordre où `with_api_stack` les monte.
        let app = Router::new()
            .route("/v1/halt", axum::routing::post(|| async { "arrêtée" }))
            .route("/v1/work", axum::routing::post(|| async { "notée" }))
            .layer(axum::middleware::from_fn_with_state(
                db.clone(),
                require_console_role,
            ))
            .layer(axum::middleware::from_fn_with_state(
                keys.clone(),
                require_api_key,
            ));

        let call = |token: String, path: &'static str| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        HttpRequest::post(path)
                            .header(header::AUTHORIZATION, token)
                            .body(Body::empty())
                            .expect("request"),
                    )
                    .await
                    .expect("service");
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                    .await
                    .expect("body");
                (status, String::from_utf8_lossy(&body).into_owned())
            }
        };

        let (status, body) = call(member.clone(), "/v1/halt").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("owner_role_required"), "{body}");
        assert!(
            body.contains("/v1/console/accounts/role"),
            "le refus doit dire qui peut donner le droit : {body}"
        );

        // Et avec le droit, ça passe — sans quoi on aurait tout fermé.
        let (status, body) = call(owner.clone(), "/v1/halt").await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(member.clone(), "/v1/work").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "un membre écrit ce qui n'engage rien : {body}"
        );

        let (status, body) = call(integration, "/v1/halt").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "une clé d'intégration n'a pas d'humain derrière et ne perd rien : {body}"
        );
    }
}
