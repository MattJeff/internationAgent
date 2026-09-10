//! `/v1/accounts/session` : une **personne** se connecte, et la console reçoit
//! de quoi appeler `/v1/*` pour son locataire — celui-là et aucun autre.
//!
//! # Ce qui manquait, et pourquoi c'est ça qui empêchait de vendre deux fois
//!
//! Le produit est multi-locataire de bout en bout côté données : `force` sur
//! chaque table, `TenantTx` qui épingle le locataire, une faille refermée en
//! `0062`. Il était mono-client côté ACCÈS : un `ADMIN_EMAIL` et un
//! `ADMIN_PASSWORD` dans l'environnement de la console, une `AGENTS_API_KEY`
//! pour l'appeler. Un deuxième client, c'était donc un deuxième déploiement.
//! `0044_api_keys.sql` avait sorti de l'environnement les credentials des
//! clients ; ceci en sort l'accès des personnes.
//!
//! # La question de `routes::platform`, posée à cette route
//!
//! `routes::platform` argumente en tête de fichier qu'**aucune route de ce
//! serveur ne doit émettre une clé pour le locataire de l'appelant**, et
//! l'argument est exact : une clé volée en émettrait d'autres, la révocation
//! deviendrait une course, et perdre cette course est silencieux — la deuxième
//! clé du voleur a un autre id, une autre empreinte, et ressemble à toutes
//! celles que le client a demandées.
//!
//! Cette route émet une clé. Il faut donc dire précisément pourquoi elle ne
//! rouvre pas ce trou-là, et la réponse tient en une phrase : **ce qui est
//! présenté ici n'est pas une clé.**
//!
//! Le danger que `platform.rs` nomme est un CYCLE : un credential que l'API
//! accepte peut fabriquer un credential que l'API accepte. C'est le cycle qui
//! rend la révocation inefficace, parce qu'il rend l'attaquant capable de
//! survivre à la destruction de ce qu'il détient. Le graphe ici n'a pas de
//! cycle :
//!
//! ```text
//!   mot de passe ──▶ jeton de session ──▶ (rien)
//! ```
//!
//! * Le mot de passe **n'authentifie rien d'autre**. Il n'ouvre aucun `/v1/*`,
//!   il n'est dans aucun trousseau, et `auth::Keyring` ne le verra jamais : il
//!   n'existe que dans le corps de cette requête-ci et sous forme de PBKDF2
//!   dans une colonne de `console_accounts` qu'`app_role` n'a pas le droit de
//!   lire.
//! * Le jeton de session **ne peut pas en fabriquer un deuxième**. Il n'est
//!   accepté par aucune route de ce module — `POST` exige un mot de passe,
//!   `DELETE` ne fait que détruire — ni par `/v1/platform/*`, qui est un autre
//!   trousseau et un autre type Rust.
//!
//! Donc voler le jeton ne donne pas le pouvoir d'en émettre un autre, et le
//! détruire termine l'incident. C'est exactement la propriété que `platform.rs`
//! protège, obtenue par la même méthode : le pouvoir d'émettre n'est pas dans
//! ce que l'attaquant a pris.
//!
//! Reste le cas où l'attaquant a pris le mot de passe. Là il peut se
//! reconnecter après chaque destruction de jeton — et c'est précisément pour ça
//! que la révocation véritable n'est pas « supprimer le jeton » mais
//! **désactiver le compte**, `DELETE /v1/platform/accounts/{id}`, qui est un
//! acte de la clé plateforme et pas du locataire, et qui fait les deux dans une
//! seule transaction (`store::accounts::deactivate`). La hiérarchie de
//! `platform.rs` est intacte : le client ne se révoque pas lui-même, le
//! fournisseur le fait.
//!
//! # Ce que la console détient, exactement
//!
//! Une ligne d'`api_keys`, étiquetée `session-<id du compte>`, appartenant au
//! locataire de la personne. **Pas un trousseau, pas la clé plateforme, pas la
//! clé d'un autre client** : le locataire vient de la LIGNE `accounts`, jamais
//! du corps de la requête, ce qui est la première phrase d'`auth.rs`. La console
//! ne peut donc pas détenir la clé de quelqu'un d'autre — il n'existe aucun
//! chemin qui lui en remette une.
//!
//! Et c'est une clé ordinaire, ce qui n'est pas un raccourci mais le choix :
//!
//! * `auth::require_api_key` la résout déjà, sans cache, en une égalité indexée
//!   — donc **la révocation est sentie par la requête suivante**, pas par le
//!   prochain déploiement ni à la fin d'un TTL. Un jeton de session maison
//!   aurait fallu un deuxième chemin d'authentification, c'est-à-dire un
//!   deuxième endroit d'où sort un `tenant_id`, c'est-à-dire l'inverse de ce
//!   qu'`auth.rs` a construit.
//! * `api_keys_tenant_label_key` donne gratuitement **une session vivante par
//!   personne** : se reconnecter détruit la précédente.
//! * L'étiquette ne nomme aucun rôle, et `routes::approvals::held_role` lit le
//!   rôle d'approbation à même l'étiquette — donc une session de console **ne
//!   peut pas approuver un paiement**. C'est le bon défaut pour un credential
//!   qui vit dans un navigateur ; ce n'est pas une limitation qu'on lèvera en
//!   renommant l'étiquette, ce serait donner un rôle d'approbation à un cookie.
//!
//! ## ponytail : pas d'`expires_at`, et ce que ça coûte
//!
//! Un jeton de session qui n'expire pas de lui-même est le vrai défaut de ce
//! design, et il est écrit ici plutôt que passé sous silence. Ce qui le rend
//! acceptable aujourd'hui : la déconnexion le détruit, une reconnexion le
//! remplace, et la désactivation du compte l'emporte dans la même transaction —
//! donc il existe trois façons de le tuer et elles agissent toutes à la requête
//! suivante. Ce qui reste ouvert : un jeton oublié dans un navigateur reste
//! valable tant que personne ne fait rien.
//!
//! La montée est petite et connue : une colonne `expires_at timestamptz` sur
//! `api_keys`, `AND (expires_at IS NULL OR expires_at > now())` dans l'unique
//! `SELECT` d'`api_keys::lookup`, et un paramètre de plus sur
//! `store::api_keys::issue`. Elle n'a pas été faite dans cette vague parce que
//! ce paramètre traverse `agentos_app::api_keys::issue`, qui appartient à une
//! autre livraison en cours.
//!
//! # Le bourrage
//!
//! Il n'y a **pas** de compteur de tentatives ici, et c'est un choix, pas un
//! oubli. Ce qui limite le bourrage sur cette route, c'est le KDF lui-même :
//! 600 000 itérations de PBKDF2-HMAC-SHA256, dépensées **aussi quand l'adresse
//! n'existe pas** (voir [`verify_password`]), ce qui met un essai à quelques
//! centaines de millisecondes de CPU et rend l'énumération d'adresses aussi
//! chère que la devinette d'un mot de passe.
//!
//! Un verrouillage par compte serait, lui, une arme : quiconque connaît
//! l'adresse de quelqu'un peut le verrouiller en se trompant exprès. Et un
//! compteur par IP dans ce processus serait faux dès le deuxième réplica.
//! Ce qui manque vraiment et qui n'est pas ici, dit franchement :
//!
//! * une limite de connexions concurrentes **à l'ingress**, parce que le KDF
//!   qui protège du bourrage est aussi ce qui rend cette route coûteuse à
//!   inonder ; c'est la même conclusion qu'`auth::require_api_key` tire pour
//!   son propre étage, et c'est un réglage d'infrastructure, pas une couche
//!   axum ;
//! * un délai croissant par compte, le jour où la console voudra le montrer à
//!   l'utilisateur. Il se poserait sur une colonne `failed_since` de
//!   `console_accounts`,
//!   pas sur un état en mémoire.
//!
//! # Une seule réponse pour deux échecs
//!
//! « Adresse inconnue », « mot de passe faux » et « compte désactivé » rendent
//! le même corps, le même code et le même statut. Et le même temps : la
//! dérivation est faite sur une empreinte factice quand il n'y a pas de ligne,
//! et l'état désactivé est lu **après** la vérification. Sans ça, cette route
//! serait un annuaire des clients du déploiement, interrogeable par n'importe
//! qui, une adresse à la fois.

use agentos_store::accounts;
use agentos_store::api_keys::{SESSION_LABEL_PREFIX, session_label};
use agentos_store::audit::AuditActor;
use agentos_store::db::Db;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, response::Result as AxumResult};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{normalise_email, verify_password_off_thread};
use crate::error::ApiError;

// ---------------------------------------------------------------------------
// La route
// ---------------------------------------------------------------------------

/// Ce que la connexion a besoin de tenir : la base, et la clé de hachage du
/// déploiement — la même que celle d'`auth::Keyring`, parce que deux
/// dérivations feraient un déploiement qui émet des clés qu'il ne sait pas
/// vérifier.
#[derive(Clone)]
pub struct AccountState {
    db: Db,
    hasher: agentos_app::api_keys::Hasher,
}

/// Les deux verbes d'une session, montés **sans credential**, à côté des
/// webhooks et de la page de réservation.
///
/// Pas derrière `with_api_stack` pour la raison qui saute aux yeux dès qu'on
/// l'écrit : cet étage-là EST `require_api_key`, et une personne qui se connecte
/// n'a par définition pas encore de clé. Pas derrière `require_platform_key`
/// non plus — ce serait demander à un navigateur de détenir le credential qui
/// crée des locataires.
///
/// `DELETE` est sur le même étage et s'authentifie tout seul, avec le jeton
/// qu'il est en train de détruire ; voir [`close_session`].
pub fn public_router(db: Db, hasher: agentos_app::api_keys::Hasher) -> Router {
    Router::new()
        .route(
            "/v1/accounts/session",
            post(open_session).delete(close_session),
        )
        .with_state(AccountState { db, hasher })
}

/// Le seul refus que cette route sait prononcer sur un credential.
///
/// Une fonction, pas trois littéraux, parce que trois littéraux finissent par
/// diverger d'un mot — et ce mot-là serait la différence entre « ce compte
/// n'existe pas » et « ce mot de passe est faux ».
fn refused() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "the address or the password is wrong",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSessionRequest {
    email: String,
    password: String,
}

/// `POST /v1/accounts/session` — une adresse, un mot de passe, et de quoi
/// appeler `/v1/*`.
///
/// La réponse porte le jeton **une seule fois**, comme
/// `platform::IssuedKeyBody` : rien ne le stocke, rien ne le recalcule, et le
/// perdre veut dire se reconnecter — ce qui, ici, est gratuit.
///
/// L'ordre des quatre lignes qui décident est le sujet du fichier :
/// on lit la ligne, on dépense le KDF **quoi qu'il arrive**, on regarde
/// seulement ensuite si le compte est ouvert. Inverser deux d'entre elles
/// suffit à rendre l'annuaire des clients interrogeable.
async fn open_session(
    State(state): State<AccountState>,
    body: Result<Json<OpenSessionRequest>, JsonRejection>,
) -> AxumResult<Response, ApiError> {
    let Json(request) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    // Une adresse mal formée n'est pas un 400 : elle est traitée comme une
    // adresse qui n'existe pas, dépense le KDF, et rend le même 401. Un 400 ici
    // n'apprendrait rien à l'appelant sur SON adresse, mais il ferait deux
    // chemins de sortie de longueurs différentes sur la route dont l'unique
    // règle est de n'en avoir qu'un.
    let email = normalise_email(&request.email);

    let found = match &email {
        Some(email) => accounts::credentials(&state.db, email).await?,
        None => None,
    };

    // La tranche vide passe par `spend_and_refuse`, donc « pas de ligne » coûte
    // ce que coûte « mauvais mot de passe ». C'est la ligne que le test
    // `an_unknown_address_and_a_wrong_password_answer_the_same_way_in_the_same_time`
    // surveille.
    let stored = found
        .as_ref()
        .map_or_else(Vec::new, |found| found.password_hash.clone());
    let correct = verify_password_off_thread(stored, request.password).await?;

    // Désactivé est lu APRÈS la vérification, et rendu comme le reste.
    let Some(account) = found.filter(|found| correct && found.deactivated_at.is_none()) else {
        return Err(refused());
    };

    let now = Utc::now();
    // L'acteur de la trace, et l'id du compte plutôt que l'adresse : le journal
    // part chez qui le lit, et une adresse est une donnée personnelle là où un
    // uuid est une clé de jointure.
    let actor = AuditActor::Operator(format!("account-{}", account.id.simple()));

    // Se reconnecter détruit la session précédente. Sans cette ligne, la
    // deuxième connexion se heurte à `api_keys_tenant_label_key` et rend 409 —
    // et avec une étiquette rendue unique à la place, on aurait des jetons
    // vivants que personne ne compte.
    accounts::clear_session(&state.db, account.tenant_id, account.id, &actor, now).await?;

    let issued = agentos_app::api_keys::issue(
        &state.db,
        &state.hasher,
        account.tenant_id,
        &session_label(account.id),
        &actor,
        now,
    )
    .await?;

    // L'id de la clé et le compte. Jamais le jeton, jamais l'adresse.
    tracing::info!(
        account_id = %account.id,
        tenant_id = %account.tenant_id.as_uuid(),
        key_id = %issued.id,
        "console session opened"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "account_id": account.id,
            "tenant_id": account.tenant_id.as_uuid(),
            // L'id de la LIGNE, pas un credential : c'est ce que
            // `DELETE /v1/platform/keys/{id}` nomme si le fournisseur doit
            // couper cette session-là depuis l'extérieur.
            "key_id": issued.id,
            // Montré une fois. Se présente en `Authorization: Bearer <token>`
            // sur `/v1/*`, exactement comme une clé de client, parce que c'en
            // est une.
            "token": issued.secret.expose_for_transport(),
            "token_type": "Bearer",
        })),
    )
        .into_response())
}

/// `DELETE /v1/accounts/session` — la personne se déconnecte, et le jeton cesse
/// de lire.
///
/// # Pourquoi cette route s'authentifie elle-même
///
/// Elle est sur l'étage public, avec `POST`, et résout le jeton présenté par le
/// même chemin qu'`auth::require_api_key` — `agentos_app::api_keys::authenticate`
/// — au lieu d'extraire un `auth::Principal`. Deux raisons :
///
/// * un `Principal` ne porte pas l'id de la ligne, seulement le locataire et
///   l'étiquette. Révoquer voudrait dire relister les clés du locataire pour
///   retrouver la sienne ;
/// * et les deux verbes d'une session sont alors montés d'une seule ligne, au
///   même endroit, ce qui est une chose de moins à monter de travers.
///
/// # Elle ne détruit qu'une session
///
/// Un jeton dont l'étiquette ne commence pas par `session-` est la clé
/// d'intégration d'un client, et un `DELETE` qui l'accepterait ferait
/// exactement ce que `routes::platform` interdit : un credential qui se
/// gouverne lui-même. Les clés de client se révoquent par la clé plateforme et
/// par elle seule. D'où `403` et pas `401` : le credential est bon, l'acte ne
/// lui appartient pas.
async fn close_session(
    State(state): State<AccountState>,
    headers: HeaderMap,
) -> AxumResult<Response, ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();

    // `Err` est la base, jamais un 401 : une panne de Postgres qui se lit comme
    // un mauvais jeton envoie tout le monde changer un credential qui va bien.
    // C'est la note d'`auth::Keyring::resolve`, et elle vaut ici.
    let Some(principal) =
        agentos_app::api_keys::authenticate(&state.db, &state.hasher, presented).await?
    else {
        return Err(refused());
    };

    if !principal.label.starts_with(SESSION_LABEL_PREFIX) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "not_a_session",
            "this credential is an integration key, not a console session",
        )
        .with_detail(
            "Only a session opened by `POST /v1/accounts/session` can be closed here. An \
             integration key is revoked by the platform, with `DELETE /v1/platform/keys/{id}`.",
        ));
    }

    agentos_app::api_keys::revoke(
        &state.db,
        principal.key_id,
        &AuditActor::Operator(principal.label.clone()),
        Utc::now(),
    )
    .await?;

    tracing::info!(
        tenant_id = %principal.tenant_id.as_uuid(),
        key_id = %principal.key_id,
        "console session closed"
    );

    Ok((
        StatusCode::OK,
        Json(json!({ "key_id": principal.key_id, "closed": true })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;
    use crate::auth::{ApiKeys, Keyring, TEST_MASTER_KEY, hash_password};

    const PASSWORD: &str = "un-mot-de-passe-honnete";

    struct Harness {
        db: Db,
        public: Router,
        api: Router,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; a console session needs a real Postgres");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let hasher = agentos_app::api_keys::Hasher::from_master_key(TEST_MASTER_KEY);
            Some(Self {
                public: public_router(db.clone(), hasher),
                // Le trousseau d'environnement est vide exprès : la seule chose
                // qui puisse authentifier dans ces tests est une ligne de la
                // table, c'est-à-dire un jeton de session.
                api: crate::with_api_stack(
                    crate::routes::employees::router(crate::routes::domain::Hiring::for_tests(
                        db.clone(),
                    )),
                    db.clone(),
                    Keyring::new(ApiKeys::default(), db.clone(), TEST_MASTER_KEY),
                ),
                a: new_tenant(&db).await,
                b: new_tenant(&db).await,
                db,
            })
        }

        /// Créer un compte comme le fait `POST /v1/platform/accounts`.
        async fn account(&self, tenant: TenantId, password: &str) -> (Uuid, String) {
            let id = Uuid::now_v7();
            let email = format!("p-{}@example.test", id.simple());
            accounts::create(
                &self.db,
                id,
                tenant,
                &email,
                &hash_password(password),
                Utc::now(),
            )
            .await
            .expect("create the account");
            (id, email)
        }

        async fn login(&self, email: &str, password: &str) -> (StatusCode, serde_json::Value) {
            let req = HttpRequest::builder()
                .method("POST")
                .uri("/v1/accounts/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": email, "password": password }).to_string(),
                ))
                .expect("request");
            read(self.public.clone().oneshot(req).await.expect("service")).await
        }

        async fn logout(&self, token: &str) -> StatusCode {
            let req = HttpRequest::builder()
                .method("DELETE")
                .uri("/v1/accounts/session")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request");
            self.public
                .clone()
                .oneshot(req)
                .await
                .expect("service")
                .status()
        }

        /// Ce que la console lit vraiment avec son jeton : les sièges de son
        /// locataire.
        async fn employees(&self, token: &str) -> (StatusCode, serde_json::Value) {
            let req = HttpRequest::builder()
                .uri("/v1/employees")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request");
            read(self.api.clone().oneshot(req).await.expect("service")).await
        }

        async fn seat(&self, tenant: TenantId, slug: &str) {
            let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle, spec) \
                 VALUES ($1, $2, $3, $3, 'active', $4)",
            )
            .bind(Uuid::now_v7())
            .bind(tenant.as_uuid())
            .bind(slug)
            .bind(json!({ "domain": "agents.example.com" }))
            .execute(&mut *tx)
            .await
            .expect("insert employee");
            tx.commit().await.expect("commit");
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    async fn read(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
        (status, body)
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'accounts-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn token(body: &serde_json::Value) -> String {
        body["token"].as_str().expect("a token").to_owned()
    }

    /// **Le test qui compte.** Le jeton de A ne lit rien de B.
    ///
    /// Pas « ne voit pas le siège de B dans une liste » : la requête part avec
    /// le credential de A sur l'API réelle, derrière `with_api_stack`,
    /// c'est-à-dire derrière `require_api_key`, et le `tenant_id` qui en sort
    /// vient de la ligne `api_keys` et de nulle part ailleurs. B a un siège, A
    /// n'en a pas, et A voit une liste vide.
    ///
    /// L'autre moitié compte autant : les deux jetons existent en même temps,
    /// chacun ouvre le sien, et aucune requête n'a jamais nommé un locataire.
    #[tokio::test]
    async fn the_token_person_a_holds_reads_nothing_of_tenant_b() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.seat(h.b, "bruno").await;

        let (_, anna) = h.account(h.a, PASSWORD).await;
        let (_, bruno) = h.account(h.b, PASSWORD).await;

        let (status, body) = h.login(&anna, PASSWORD).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["tenant_id"], json!(h.a.as_uuid()));
        let anna_token = token(&body);

        let (status, body) = h.login(&bruno, PASSWORD).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let bruno_token = token(&body);
        assert_ne!(anna_token, bruno_token);

        let (status, seen) = h.employees(&anna_token).await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        let rendered = seen.to_string();
        assert!(
            !rendered.contains("bruno"),
            "A's session read a seat of B's: {rendered}"
        );

        // Et l'inverse tient : le jeton de B voit bien le siège de B, donc le
        // vide ci-dessus est une frontière et pas une route cassée.
        let (status, seen) = h.employees(&bruno_token).await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        assert!(
            seen.to_string().contains("bruno"),
            "B's own session must read B's seat: {seen}"
        );

        h.teardown().await;
    }

    /// **Un compte inconnu et un mot de passe faux rendent la même chose, dans
    /// le même temps.**
    ///
    /// Le corps et le statut sont comparés à l'octet. Le temps est comparé
    /// large — une assertion de timing serrée est une assertion qui rougit un
    /// jour sur une machine chargée sans que rien n'ait cassé. Ce qu'elle
    /// attrape est massif : sans [`spend_and_refuse`], la branche « pas de
    /// ligne » est un accès à l'index et rend en microsecondes, là où l'autre
    /// dépense 600 000 itérations. Le rapport serait de plusieurs milliers, pas
    /// de quatre.
    #[tokio::test]
    async fn an_unknown_address_and_a_wrong_password_answer_the_same_way_in_the_same_time() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (_, anna) = h.account(h.a, PASSWORD).await;

        let started = Instant::now();
        let (wrong_status, wrong_body) = h.login(&anna, "ce-n-est-pas-le-bon").await;
        let wrong = started.elapsed();

        let started = Instant::now();
        let (unknown_status, unknown_body) = h.login("personne@example.test", PASSWORD).await;
        let unknown = started.elapsed();

        assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
        assert_eq!(unknown_status, wrong_status);
        assert_eq!(unknown_body, wrong_body, "two refusals, one sentence");

        // Et une adresse qui n'est même pas une adresse ne se distingue pas non
        // plus — pas de 400 qui répondrait avant le KDF.
        let (shape_status, shape_body) = h.login("pas-une-adresse", PASSWORD).await;
        assert_eq!(shape_status, wrong_status);
        assert_eq!(shape_body, wrong_body);

        let ratio = wrong.as_secs_f64().max(unknown.as_secs_f64())
            / wrong.as_secs_f64().min(unknown.as_secs_f64());
        assert!(
            ratio < 4.0,
            "an unknown address must not be cheaper than a wrong password: \
             wrong={wrong:?} unknown={unknown:?}"
        );

        h.teardown().await;
    }

    /// **Un compte désactivé ne s'authentifie plus**, et le jeton qu'il tenait
    /// non plus — la désactivation les emporte tous les deux dans un commit.
    #[tokio::test]
    async fn a_deactivated_person_cannot_log_in_and_her_token_stops_reading() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (id, anna) = h.account(h.a, PASSWORD).await;

        let (status, body) = h.login(&anna, PASSWORD).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let held = token(&body);
        assert_eq!(h.employees(&held).await.0, StatusCode::OK);

        let closed = accounts::deactivate(
            &h.db,
            id,
            &AuditActor::Operator("platform".to_owned()),
            Utc::now(),
        )
        .await
        .expect("deactivate");
        assert!(closed.session_revoked);

        let (status, body) = h.login(&anna, PASSWORD).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(
            body["code"],
            json!("invalid_credentials"),
            "a closed account is not a different refusal from a wrong password"
        );
        assert_eq!(
            h.employees(&held).await.0,
            StatusCode::UNAUTHORIZED,
            "no cache, so the very next request is the one that fails"
        );

        h.teardown().await;
    }

    /// Se reconnecter remplace la session, se déconnecter la détruit, et un
    /// jeton détruit ne lit rien.
    #[tokio::test]
    async fn a_second_login_replaces_the_first_and_a_logout_ends_both() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (_, anna) = h.account(h.a, PASSWORD).await;

        let (_, first) = h.login(&anna, PASSWORD).await;
        let first = token(&first);
        let (status, second) = h.login(&anna, PASSWORD).await;
        assert_eq!(status, StatusCode::CREATED, "{second}");
        let second = token(&second);

        assert_ne!(first, second);
        assert_eq!(
            h.employees(&first).await.0,
            StatusCode::UNAUTHORIZED,
            "the first token was replaced, not left running"
        );
        assert_eq!(h.employees(&second).await.0, StatusCode::OK);

        assert_eq!(h.logout(&second).await, StatusCode::OK);
        assert_eq!(h.employees(&second).await.0, StatusCode::UNAUTHORIZED);
        // Fermer deux fois: le jeton ne résout plus rien, donc 401 — la même
        // réponse qu'un jeton inventé, ce qui est la bonne.
        assert_eq!(h.logout(&second).await, StatusCode::UNAUTHORIZED);

        h.teardown().await;
    }

    /// Une clé d'intégration ne se révoque pas par la porte de la console.
    #[tokio::test]
    async fn an_integration_key_cannot_be_closed_as_if_it_were_a_session() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let issued = agentos_app::api_keys::issue(
            &h.db,
            &agentos_app::api_keys::Hasher::from_master_key(TEST_MASTER_KEY),
            h.a,
            "ops-console",
            &AuditActor::Operator("platform".to_owned()),
            Utc::now(),
        )
        .await
        .expect("issue");

        assert_eq!(
            h.logout(issued.secret.expose_for_transport()).await,
            StatusCode::FORBIDDEN
        );
        // Et elle marche toujours, ce qui est la moitié qui compte.
        assert_eq!(
            h.employees(issued.secret.expose_for_transport()).await.0,
            StatusCode::OK
        );

        h.teardown().await;
    }
}
