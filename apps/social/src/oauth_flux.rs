//! Le flux authorization-code des deux plateformes, et le scellement de ce
//! qu'il rapporte.
//!
//! `crates/app/src/oauth.rs` a déjà résolu les questions dures, et ce module
//! reprend ses décisions au lieu de les renégocier :
//!
//! * **PKCE en `S256`, jamais `plain`** : `plain` met le vérifieur dans l'URL
//!   d'autorisation, précisément la surface qu'on suppose fuyante — il défend
//!   rien en ayant l'air de défendre. Aucune branche ici ne peut le choisir.
//! * **Le `state` est une capacité** : 32 octets d'entropie OS, stocké en
//!   SHA-256 seulement (la table ne permet pas de finir un flux), réclamé une
//!   fois — la réclamation atomique vit dans store.rs (lot cœur), le hachage
//!   vit ici pour que l'écrivain et le lecteur arrivent aux mêmes 32 octets.
//! * **Aucun point d'échange en `http://`** : les points sont des littéraux
//!   `&'static str` en `https` dans ce binaire — l'argument de `post_token` :
//!   rien sur le chemin ne les produit dynamiquement, et le test d'à côté les
//!   tient à `https`. Les redirections sont coupées : un point de jeton qui
//!   302 est un point auquel on ne renvoie pas le secret client.
//! * **Un 200 qui porte `error` est un refus** : GitHub et Slack l'ont appris
//!   à `oauth.rs` le 2026-08-31 ; on garde la leçon sans attendre de la
//!   réapprendre.
//!
//! Les faits de plateforme, relevés le 2026-09-02 :
//!
//! * X — <https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code> :
//!   autorisation `https://x.com/i/oauth2/authorize`, jeton
//!   `POST https://api.x.com/2/oauth2/token` ; PKCE exigé par le flux ;
//!   `offline.access` fait émettre un refresh token (« If this scope is not
//!   passed, we will not generate a refresh token ») ; l'auth_code expire en
//!   30 secondes ; « You don't need client id for confidential clients with a
//!   valid Authorization Header » — le client confidentiel s'authentifie en
//!   Basic, le schéma obligatoire de RFC 6749 §2.3.1.
//! * LinkedIn — <https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow> :
//!   autorisation `GET https://www.linkedin.com/oauth/v2/authorization`, jeton
//!   `POST https://www.linkedin.com/oauth/v2/accessToken` avec `client_id` et
//!   `client_secret` dans le corps (paramètres requis, table de l'étape 3) ;
//!   pas de PKCE dans cette doc ; jetons d'accès à 60 jours ; « Programmatic
//!   refresh tokens are available for a limited set of partners » — pour nous,
//!   pas de rafraîchissement : on refait consentir, et l'outil le dit.

use agentos_domain::ids::TenantId;
use agentos_providers::secrets::{Envelope, LocalEnvelopeSecretStore};
use agentos_providers::{ProviderError, Secret};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngCore;
use sha2::{Digest, Sha256};
use url::Url;

use crate::adapters::{ErreurPlateforme, http};

/// Relevés le 2026-09-02 — URLs en tête de module.
pub const X_AUTORISATION: &str = "https://x.com/i/oauth2/authorize";
pub const X_JETON: &str = "https://api.x.com/2/oauth2/token";
pub const LINKEDIN_AUTORISATION: &str = "https://www.linkedin.com/oauth/v2/authorization";
pub const LINKEDIN_JETON: &str = "https://www.linkedin.com/oauth/v2/accessToken";

/// Qui est ce jeton ? Un point de jeton ne rend que des jetons ; le compte à
/// nommer en base vient d'un second appel :
///
/// * X : `GET /2/users/me` → `data.username` (le handle), scopes
///   `users.read` + `tweet.read` —
///   <https://docs.x.com/x-api/users/user-lookup-me>, relevé le 2026-09-02.
/// * LinkedIn : `GET https://api.linkedin.com/v2/userinfo` → `sub` (« User
///   identifier », le member id), scope `openid` —
///   <https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2>,
///   relevé le 2026-09-02. L'URN d'auteur du Posts API se compose de ce même
///   id : `urn:li:person:{id}` (post-api-schema).
pub const X_ME: &str = "https://api.x.com/2/users/me";
pub const LINKEDIN_USERINFO: &str = "https://api.linkedin.com/v2/userinfo";

/// `tweet.write` publie (creation-of-a-post), `tweet.read`/`users.read` lisent
/// les métriques (get-post-by-id) ET servent `GET /2/users/me`,
/// `offline.access` fait émettre le refresh token — tous relevés le 2026-09-02.
pub const X_SCOPES: &str = "tweet.read tweet.write users.read offline.access";
/// `w_member_social` : « Post, comment, and like posts on behalf of an
/// authenticated member » (posts-api, table Permissions). `openid` + `profile` :
/// requis pour `GET /v2/userinfo`, qui est le SEUL moyen self-serve de savoir
/// quel membre le jeton représente — sans lui, pas d'URN d'auteur, pas de post
/// (sign-in-with-linkedin-v2, produit « Sign In with LinkedIn using OpenID
/// Connect », sans revue d'app). Relevés le 2026-09-02.
pub const LINKEDIN_SCOPES: &str = "openid profile w_member_social";

/// Mêmes largeurs que `oauth.rs` : 32 octets d'OS pour le `state` (256 bits
/// contre qui regarde les flux passer), 32 pour le vérifieur (le minimum de
/// RFC 7636 est 43 caractères base64url parce que c'est 256 bits).
const STATE_OCTETS: usize = 32;
const VERIFIEUR_OCTETS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlateformeOauth {
    X,
    Linkedin,
}

/// Ce qu'un flux démarré laisse derrière lui.
///
/// Pas de `Debug`, pas de `Serialize` : `authorize_url` porte le `state`, qui
/// est la capacité de finir ce flux — la même phrase que `oauth::Started`,
/// pour la même raison (un `tracing::info!(?flux)` finit dans un ticket).
pub struct FluxDemarre {
    /// Où envoyer le navigateur. Porte le `state` : une réponse HTTP, au
    /// tenant qui l'a demandée, et aucune autre surface.
    pub authorize_url: String,
    /// La clé de la table des flux (lot cœur). Le `state` en clair n'est
    /// jamais stocké.
    pub empreinte_state: [u8; 32],
    /// Le vérifieur PKCE, scellé sous l'AAD de ce flux. `None` pour LinkedIn :
    /// sa doc ne définit pas de PKCE, et sceller un vérifieur que personne ne
    /// vérifiera serait le théâtre de la sécurité.
    pub verifieur_scelle: Option<Vec<u8>>,
}

/// Ce qu'un point de jeton a émis. Pas de `Debug`, pas de `Clone` : deux
/// credentials vivants, qui existent entre la réponse HTTP et le chiffre.
pub struct JetonEmis {
    pub acces: Secret,
    pub rafraichissement: Option<Secret>,
    /// Secondes avant expiration ; 3600 si la plateforme se tait — `expires_in`
    /// est un SHOULD de RFC 6749, et prendre le silence pour « éternel » est
    /// le bug que `oauth.rs` documente. LinkedIn annonce 60 jours, X 2 heures.
    pub duree_s: u64,
}

/// Le hachage que l'écrivain et le lecteur du `state` partagent.
pub fn empreinte_state(state: &str) -> [u8; 32] {
    Sha256::digest(state.as_bytes()).into()
}

/// L'AAD d'un jeton de plateforme au repos : un chiffre déplacé entre tenants,
/// plateformes ou comptes ne déchiffre rien. Une fonction, pas deux
/// épellations — la règle de `credential_context` dans mcp.rs.
pub fn contexte_social(tenant: TenantId, plateforme: &str, compte: &str) -> String {
    format!("social://{tenant}/{plateforme}/{compte}")
}

/// L'AAD d'un vérifieur PKCE : lié au flux par l'empreinte du `state`, comme
/// `flow_context` dans oauth.rs — voler la table ne permet pas d'apparier un
/// vérifieur connu avec un state choisi.
fn contexte_flux(tenant: TenantId, empreinte: &[u8; 32]) -> String {
    format!("social-flux://{tenant}/{}", hex(empreinte))
}

/// L'AAD d'un refresh token : un espace de clés À PART du jeton d'accès. Les
/// deux enveloppes vivent sur la même ligne de compte ; sous une AAD commune,
/// un blob échangé entre les deux colonnes déchiffrerait quand même.
fn contexte_rafraichissement(tenant: TenantId, plateforme: &str, compte: &str) -> String {
    format!("social-refresh://{tenant}/{plateforme}/{compte}")
}

/// Hex minuscule — la clé texte de `social_oauth_pending.state` (le state en
/// clair n'est JAMAIS stocké : la table ne permet pas de finir un flux) et le
/// suffixe de l'AAD de flux passent par ici, une seule épellation.
pub fn hex(octets: &[u8]) -> String {
    octets.iter().fold(String::new(), |mut s, o| {
        use std::fmt::Write;
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// Scelle un jeton de plateforme pour la colonne du lot cœur.
pub fn sceller_jeton(
    chiffre: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    plateforme: &str,
    compte: &str,
    jeton: &Secret,
) -> Result<Vec<u8>, ProviderError> {
    chiffre
        .seal_in(tenant, &contexte_social(tenant, plateforme, compte), jeton)
        .map(|env| env.to_bytes())
}

/// Scelle le refresh token de X sous son AAD propre. Pas d'ouvreur encore :
/// il naîtra avec le câblage de [`rafraichir`] dans le chemin de publication
/// — on garde le jeton (le perdre coûterait un re-consentement humain), on ne
/// prétend pas déjà s'en servir.
pub fn sceller_rafraichissement(
    chiffre: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    plateforme: &str,
    compte: &str,
    jeton: &Secret,
) -> Result<Vec<u8>, ProviderError> {
    chiffre
        .seal_in(
            tenant,
            &contexte_rafraichissement(tenant, plateforme, compte),
            jeton,
        )
        .map(|env| env.to_bytes())
}

/// L'autre moitié de [`sceller_jeton`].
pub fn ouvrir_jeton(
    chiffre: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    plateforme: &str,
    compte: &str,
    scelle: &[u8],
) -> Result<Secret, ProviderError> {
    let envelope = Envelope::from_bytes(scelle)?;
    chiffre.open_in(
        tenant,
        &contexte_social(tenant, plateforme, compte),
        &envelope,
    )
}

/// Démarre un flux : l'URL de consentement et ce que le retour exigera.
///
/// N'écrit rien — le lot cœur range la ligne dans sa transaction, comme
/// `oauth::start`. `redirect_uri` est construit une fois par l'appelant : il
/// doit être identique à l'octet près entre le consentement, l'échange et
/// l'enregistrement chez le fournisseur.
pub fn demarrer(
    plateforme: PlateformeOauth,
    client_id: &str,
    redirect_uri: &str,
    tenant: TenantId,
    chiffre: &LocalEnvelopeSecretStore,
) -> Result<FluxDemarre, ProviderError> {
    let state = aleatoire_b64url(STATE_OCTETS);
    let empreinte = empreinte_state(&state);

    let (point, scopes) = match plateforme {
        PlateformeOauth::X => (X_AUTORISATION, X_SCOPES),
        PlateformeOauth::Linkedin => (LINKEDIN_AUTORISATION, LINKEDIN_SCOPES),
    };
    // `Url` et pas `format!` : les scopes ont des espaces, un client_id est
    // une valeur opaque du fournisseur — la raison exacte de `oauth::start`.
    let mut url = Url::parse(point).expect("littéral https statique");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scopes)
        .append_pair("state", &state);

    let verifieur_scelle = match plateforme {
        PlateformeOauth::X => {
            let verifieur = aleatoire_b64url(VERIFIEUR_OCTETS);
            // Le défi hache le TEXTE base64url du vérifieur, pas les octets
            // derrière — RFC 7636 est explicite, et se tromper produit chez
            // chaque fournisseur une erreur PKCE qui ne nomme rien.
            let defi = B64URL.encode(Sha256::digest(verifieur.as_bytes()));
            url.query_pairs_mut()
                .append_pair("code_challenge", &defi)
                .append_pair("code_challenge_method", "S256");
            Some(
                chiffre
                    .seal_in(
                        tenant,
                        &contexte_flux(tenant, &empreinte),
                        &Secret::new(verifieur),
                    )?
                    .to_bytes(),
            )
        }
        PlateformeOauth::Linkedin => None,
    };

    Ok(FluxDemarre {
        authorize_url: url.into(),
        empreinte_state: empreinte,
        verifieur_scelle,
    })
}

/// Ouvre le vérifieur scellé par [`demarrer`], au retour du callback.
pub fn ouvrir_verifieur(
    chiffre: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    empreinte: &[u8; 32],
    scelle: &[u8],
) -> Result<Secret, ProviderError> {
    let envelope = Envelope::from_bytes(scelle)?;
    chiffre.open_in(tenant, &contexte_flux(tenant, empreinte), &envelope)
}

/// Le corps de l'échange, sorti en fonction pour être comparé aux tables de
/// paramètres des deux docs sans réseau.
///
/// X : `code_verifier` requis (PKCE), le client confidentiel s'authentifie par
/// l'en-tête Basic — donc ni `client_id` ni `client_secret` dans le corps.
/// LinkedIn : `client_id` et `client_secret` dans le corps, requis par la
/// table de l'étape 3 de sa doc.
pub fn corps_d_echange<'a>(
    plateforme: PlateformeOauth,
    code: &'a str,
    redirect_uri: &'a str,
    verifieur: Option<&'a str>,
    client_id: &'a str,
    client_secret: Option<&'a str>,
) -> Vec<(&'static str, &'a str)> {
    match plateforme {
        PlateformeOauth::X => vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifieur.unwrap_or_default()),
        ],
        PlateformeOauth::Linkedin => vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret.unwrap_or_default()),
            ("redirect_uri", redirect_uri),
        ],
    }
}

/// Échange le `code` du callback contre un jeton, et rien d'autre : le
/// scellement et la ligne de compte sont à l'appelant, dans sa transaction.
pub async fn echanger(
    plateforme: PlateformeOauth,
    client_id: &str,
    client_secret: &Secret,
    redirect_uri: &str,
    code: &str,
    verifieur: Option<&Secret>,
) -> Result<JetonEmis, ErreurPlateforme> {
    let verifieur_texte = verifieur.map(Secret::expose_for_transport);
    let secret_texte = client_secret.expose_for_transport();
    let corps = corps_d_echange(
        plateforme,
        code,
        redirect_uri,
        verifieur_texte,
        client_id,
        Some(secret_texte),
    );
    poster_jeton(plateforme, client_id, client_secret, &corps).await
}

/// Rafraîchit un jeton X. Pour LinkedIn c'est un refus immédiat et nommé,
/// AVANT tout réseau : « Programmatic refresh tokens are available for a
/// limited set of partners » (authorization-code-flow, étape 5, relevé le
/// 2026-09-02) — le chemin honnête est de refaire consentir l'humain, et un
/// appel réseau qui échouerait en 401 ne l'aurait dit à personne.
pub async fn rafraichir(
    plateforme: PlateformeOauth,
    client_id: &str,
    client_secret: &Secret,
    rafraichissement: &Secret,
) -> Result<JetonEmis, ErreurPlateforme> {
    if plateforme == PlateformeOauth::Linkedin {
        return Err(ErreurPlateforme::RafraichissementIndisponible);
    }
    // Forme documentée : `grant_type=refresh_token` + `refresh_token` sur le
    // même point de jeton ; le client confidentiel passe par Basic.
    let corps = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", rafraichissement.expose_for_transport()),
    ];
    poster_jeton(plateforme, client_id, client_secret, &corps).await
}

/// Le POST vers un point de jeton — l'authentification client est ajoutée ici
/// pour qu'aucun appelant ne puisse l'oublier ni la choisir (la discipline de
/// `post_token`).
async fn poster_jeton(
    plateforme: PlateformeOauth,
    client_id: &str,
    client_secret: &Secret,
    corps: &[(&str, &str)],
) -> Result<JetonEmis, ErreurPlateforme> {
    let point = match plateforme {
        PlateformeOauth::X => X_JETON,
        PlateformeOauth::Linkedin => LINKEDIN_JETON,
    };
    // `Accept: application/json` : inoffensif partout (c'est le type que RFC
    // 6749 §5.1 impose déjà), et la leçon GitHub de `post_token` dit qu'un
    // fournisseur peut répondre autre chose si on ne le demande pas tout haut.
    let mut requete = http().post(point).header("Accept", "application/json");
    if plateforme == PlateformeOauth::X {
        // Basic pour le client confidentiel — voir la citation en tête de
        // module. LinkedIn veut le secret dans le corps, il y est déjà.
        requete = requete.basic_auth(client_id, Some(client_secret.expose_for_transport()));
    }
    let reponse = requete
        .form(corps)
        .send()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    let statut = reponse.status().as_u16();
    let octets = reponse
        .bytes()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    jeton_depuis(statut, &octets)
}

/// Lit la réponse d'un point de jeton. Le corps ne traverse jamais vers
/// l'erreur : il peut écho la requête, et l'erreur finit dans des logs.
pub fn jeton_depuis(statut: u16, corps: &[u8]) -> Result<JetonEmis, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    // Un 200 qui porte `error` est un refus, pas une réponse illisible — la
    // leçon GitHub/Slack de `post_token`, mesurée le 2026-08-31.
    if document.get("error").is_some_and(|v| !v.is_null()) {
        return Err(ErreurPlateforme::Refus { statut });
    }
    let acces = document
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    Ok(JetonEmis {
        acces: Secret::new(acces),
        rafraichissement: document
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(Secret::new),
        duree_s: document
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600),
    })
}

/// Demande à la plateforme QUI est ce jeton — l'étape entre l'échange et la
/// ligne de compte : c'est elle qui donne le `handle` de `social_accounts`
/// (nom d'écran chez X, URN d'auteur chez LinkedIn).
pub async fn identite(
    plateforme: PlateformeOauth,
    acces: &Secret,
) -> Result<String, ErreurPlateforme> {
    let point = match plateforme {
        PlateformeOauth::X => X_ME,
        PlateformeOauth::Linkedin => LINKEDIN_USERINFO,
    };
    let reponse = http()
        .get(point)
        .bearer_auth(acces.expose_for_transport())
        .send()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    let statut = reponse.status().as_u16();
    let octets = reponse
        .bytes()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    identite_depuis(plateforme, statut, &octets)
}

/// Lit la réponse d'identité — pur, comparé aux fixtures des deux docs.
///
/// X : `{"data": {"id", "name", "username"}}` → le `username` (user-lookup-me).
/// LinkedIn : `{"sub": "782bbtaQ", ...}` → `urn:li:person:{sub}` — `sub` est
/// « User identifier » (sign-in-with-linkedin-v2) et l'URN d'auteur du Posts
/// API est `urn:li:person:{id}` (post-api-schema) ; les deux relevés le
/// 2026-09-02.
pub fn identite_depuis(
    plateforme: PlateformeOauth,
    statut: u16,
    corps: &[u8],
) -> Result<String, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    match plateforme {
        PlateformeOauth::X => document
            .pointer("/data/username")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible),
        PlateformeOauth::Linkedin => document
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|sub| format!("urn:li:person:{sub}"))
            .ok_or(ErreurPlateforme::Illisible),
    }
}

/// 32 octets d'entropie OS en base64url — `rand::rng()` est semé par l'OS, et
/// un `state` n'est pas de la gigue (le commentaire de `random_b64url`).
fn aleatoire_b64url(octets: usize) -> String {
    let mut tampon = vec![0u8; octets];
    rand::rng().fill_bytes(&mut tampon);
    B64URL.encode(&tampon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn chiffre() -> LocalEnvelopeSecretStore {
        LocalEnvelopeSecretStore::new([7u8; 32])
    }

    fn tenant() -> TenantId {
        "0192aaaa-0000-7000-8000-000000000001"
            .parse()
            .expect("uuid")
    }

    fn parametres(url: &str) -> HashMap<String, String> {
        Url::parse(url)
            .expect("url d'autorisation")
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn x_demarre_en_s256_et_le_defi_hache_le_texte_du_verifieur() {
        let chiffre = chiffre();
        let flux = demarrer(
            PlateformeOauth::X,
            "client-x",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre,
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert!(flux.authorize_url.starts_with(X_AUTORISATION));
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["scope"], X_SCOPES);
        // Le state de l'URL et l'empreinte rendue désignent le même flux.
        assert_eq!(empreinte_state(&params["state"]), flux.empreinte_state);
        // Le vérifieur scellé rouvre, et son TEXTE base64url hache vers le
        // défi de l'URL — si un refactor hachait les octets, ce test tombe.
        let verifieur = ouvrir_verifieur(
            &chiffre,
            tenant(),
            &flux.empreinte_state,
            flux.verifieur_scelle.as_deref().expect("PKCE chez X"),
        )
        .expect("le vérifieur rouvre sous l'AAD du flux");
        let defi = B64URL.encode(Sha256::digest(verifieur.expose_for_transport().as_bytes()));
        assert_eq!(params["code_challenge"], defi);
        // 32 octets → 43 caractères, le minimum exigé par RFC 7636.
        assert_eq!(verifieur.expose_for_transport().len(), 43);
    }

    #[test]
    fn linkedin_demarre_sans_pkce_et_avec_le_seul_scope_du_jour_un() {
        let flux = demarrer(
            PlateformeOauth::Linkedin,
            "client-li",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert!(flux.authorize_url.starts_with(LINKEDIN_AUTORISATION));
        // openid+profile : le prix de savoir QUI poste (userinfo) — voir la
        // citation sur LINKEDIN_SCOPES.
        assert_eq!(params["scope"], "openid profile w_member_social");
        assert!(!params.contains_key("code_challenge"));
        assert!(flux.verifieur_scelle.is_none());
        assert!(params.contains_key("state"));
    }

    /// Les tables de paramètres des deux docs, sans réseau.
    #[test]
    fn les_corps_d_echange_suivent_les_deux_docs() {
        assert_eq!(
            corps_d_echange(
                PlateformeOauth::X,
                "auth-code",
                "https://cb.example",
                Some("verif"),
                "id",
                Some("secret"),
            ),
            vec![
                ("grant_type", "authorization_code"),
                ("code", "auth-code"),
                ("redirect_uri", "https://cb.example"),
                ("code_verifier", "verif"),
            ],
            "X : PKCE dans le corps, client en Basic — jamais le secret ici"
        );
        assert_eq!(
            corps_d_echange(
                PlateformeOauth::Linkedin,
                "auth-code",
                "https://cb.example",
                None,
                "id",
                Some("secret"),
            ),
            vec![
                ("grant_type", "authorization_code"),
                ("code", "auth-code"),
                ("client_id", "id"),
                ("client_secret", "secret"),
                ("redirect_uri", "https://cb.example"),
            ],
            "LinkedIn : les cinq paramètres requis de l'étape 3"
        );
    }

    #[test]
    fn un_refus_de_jeton_est_nomme_et_ne_porte_pas_le_secret() {
        // Un 200 qui dit error est un refus (leçon GitHub/Slack). `match` et
        // pas `expect_err` : `JetonEmis` n'a pas de Debug, par construction.
        let refus = match jeton_depuis(
            200,
            br#"{"error":"invalid_grant","hint":"code SECRET-ECHO"}"#,
        ) {
            Err(erreur) => erreur,
            Ok(_) => panic!("un error est un refus"),
        };
        assert_eq!(refus, ErreurPlateforme::Refus { statut: 200 });
        let rendu = format!("{refus} / {refus:?}");
        assert!(!rendu.contains("SECRET-ECHO"), "le corps a fui: {rendu}");
        // Un 4xx est un refus, un 5xx une mauvaise minute.
        assert!(matches!(
            jeton_depuis(400, b"{}"),
            Err(ErreurPlateforme::Refus { statut: 400 })
        ));
        assert!(matches!(
            jeton_depuis(503, b""),
            Err(ErreurPlateforme::Injoignable)
        ));
    }

    #[test]
    fn un_jeton_emis_se_lit_et_le_silence_sur_l_expiration_vaut_une_heure() {
        let jeton = jeton_depuis(
            200,
            br#"{"access_token":"AQUvlL","expires_in":5184000,"refresh_token":"r1","scope":"w_member_social"}"#,
        )
        .expect("forme documentée LinkedIn");
        assert_eq!(jeton.acces.expose_for_transport(), "AQUvlL");
        assert_eq!(jeton.duree_s, 5_184_000);
        assert!(jeton.rafraichissement.is_some());
        // Sans expires_in : une heure, jamais « éternel ».
        let muet = jeton_depuis(200, br#"{"access_token":"a"}"#).expect("access seul");
        assert_eq!(muet.duree_s, 3600);
    }

    #[tokio::test]
    async fn linkedin_ne_se_rafraichit_pas_et_le_dit_sans_toucher_le_reseau() {
        // Aucun serveur ne tourne : si la fonction tentait le réseau, elle
        // rendrait Injoignable et ce test le verrait.
        let resultat = rafraichir(
            PlateformeOauth::Linkedin,
            "id",
            &Secret::new("secret"),
            &Secret::new("refresh"),
        )
        .await;
        match resultat {
            Err(erreur) => assert_eq!(erreur, ErreurPlateforme::RafraichissementIndisponible),
            Ok(_) => panic!("pas de rafraîchissement programmatique chez LinkedIn"),
        }
    }

    #[test]
    fn un_jeton_scelle_ne_se_deplace_ni_de_plateforme_ni_de_compte() {
        let chiffre = chiffre();
        let scelle = sceller_jeton(&chiffre, tenant(), "x", "orizn", &Secret::new("jeton"))
            .expect("scellement");
        assert_eq!(
            ouvrir_jeton(&chiffre, tenant(), "x", "orizn", &scelle)
                .expect("même AAD")
                .expose_for_transport(),
            "jeton"
        );
        // Déplacé vers une autre plateforme ou un autre compte : rien.
        assert!(ouvrir_jeton(&chiffre, tenant(), "linkedin", "orizn", &scelle).is_err());
        assert!(ouvrir_jeton(&chiffre, tenant(), "x", "autre", &scelle).is_err());
    }

    #[test]
    fn tous_les_points_du_flux_sont_en_https() {
        for point in [
            X_AUTORISATION,
            X_JETON,
            LINKEDIN_AUTORISATION,
            LINKEDIN_JETON,
            X_ME,
            LINKEDIN_USERINFO,
        ] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }

    /// Les fixtures d'identité des deux docs, sans réseau.
    #[test]
    fn l_identite_se_lit_comme_les_docs_le_montrent() {
        // user-lookup-me : data.id/name/username.
        let x = identite_depuis(
            PlateformeOauth::X,
            200,
            br#"{"data":{"id":"2244994945","name":"X Dev","username":"XDevelopers"}}"#,
        )
        .expect("forme documentée X");
        assert_eq!(x, "XDevelopers");
        // sign-in-with-linkedin-v2 : le sub de l'exemple devient l'URN d'auteur.
        let li = identite_depuis(
            PlateformeOauth::Linkedin,
            200,
            br#"{"sub":"782bbtaQ","name":"John Doe","locale":"en-US"}"#,
        )
        .expect("forme documentée LinkedIn");
        assert_eq!(li, "urn:li:person:782bbtaQ");
        // Un refus reste un refus, un 2xx difforme est illisible.
        assert_eq!(
            identite_depuis(PlateformeOauth::X, 401, b"{}"),
            Err(ErreurPlateforme::Refus { statut: 401 })
        );
        assert_eq!(
            identite_depuis(PlateformeOauth::Linkedin, 200, b"{}"),
            Err(ErreurPlateforme::Illisible)
        );
    }

    /// Le refresh scellé ne s'ouvre PAS comme un jeton d'accès du même
    /// compte : les deux colonnes vivent côte à côte, l'AAD les sépare.
    #[test]
    fn un_refresh_scelle_n_est_pas_un_jeton_d_acces() {
        let chiffre = chiffre();
        let scelle =
            sceller_rafraichissement(&chiffre, tenant(), "x", "orizn", &Secret::new("refresh"))
                .expect("scellement");
        assert!(ouvrir_jeton(&chiffre, tenant(), "x", "orizn", &scelle).is_err());
    }
}
