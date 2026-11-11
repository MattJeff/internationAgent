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
//! * Instagram (« Instagram API with Instagram Login ») —
//!   <https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/business-login>,
//!   relevé 2026-09-02 : autorisation `https://www.instagram.com/oauth/authorize`
//!   (scopes séparés par des VIRGULES), échange
//!   `POST https://api.instagram.com/oauth/access_token` — « must be made in
//!   server-side code », client_id + client_secret dans le corps ; le code est
//!   « valid for 1 hour and can only be used once ». Le jeton court est
//!   CHAÎNÉ vers le long :
//!   `GET https://graph.instagram.com/access_token?grant_type=ig_exchange_token`
//!   → « valid for 60 days ». Pas de refresh_token séparé : le jeton long se
//!   rafraîchit LUI-MÊME (`grant_type=ig_refresh_token`) tant qu'il est
//!   « at least 24 hours old » ET encore valide — d'où le rafraîchissement
//!   PROACTIF de `mcp::jeton_frais`, un 401 arrive trop tard. Pas de PKCE
//!   documenté.
//! * TikTok — <https://developers.tiktok.com/doc/oauth-user-access-token-management>,
//!   relevé 2026-09-02 : autorisation `https://www.tiktok.com/v2/auth/authorize/`
//!   avec le paramètre **`client_key`** (pas client_id), scopes séparés par des
//!   VIRGULES ; jeton `POST https://open.tiktokapis.com/v2/oauth/token/`
//!   (client_key + secret dans le corps). access 86400 s, refresh 31536000 s ;
//!   ROTATION : « The returned refresh_token may be different... You must use
//!   the newly-returned token » — couvert par `resceller_jetons` (remplace
//!   quand `Some`, COALESCE sinon).
//! * YouTube/Google — <https://developers.google.com/identity/protocols/oauth2/web-server>,
//!   relevé 2026-09-02 : autorisation `https://accounts.google.com/o/oauth2/v2/auth`
//!   avec `access_type=offline` ET `prompt=consent` — le refresh token n'est
//!   rendu qu'au PREMIER échange sans `prompt=consent` ; jeton
//!   `POST https://oauth2.googleapis.com/token` (client_id + secret dans le
//!   corps). Limite : 100 refresh tokens par compte Google et par client_id —
//!   le plus ancien meurt en silence au 101e.

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
pub const INSTAGRAM_AUTORISATION: &str = "https://www.instagram.com/oauth/authorize";
pub const INSTAGRAM_JETON: &str = "https://api.instagram.com/oauth/access_token";
/// L'échange court → long (`grant_type=ig_exchange_token`) — le second maillon
/// du chaînage d'`echanger`.
pub const INSTAGRAM_JETON_LONG: &str = "https://graph.instagram.com/access_token";
/// Le rafraîchissement du jeton long PAR LUI-MÊME (`grant_type=ig_refresh_token`).
pub const INSTAGRAM_RAFRAICHIR: &str = "https://graph.instagram.com/refresh_access_token";
pub const TIKTOK_AUTORISATION: &str = "https://www.tiktok.com/v2/auth/authorize/";
pub const TIKTOK_JETON: &str = "https://open.tiktokapis.com/v2/oauth/token/";
pub const YOUTUBE_AUTORISATION: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const YOUTUBE_JETON: &str = "https://oauth2.googleapis.com/token";

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
/// Instagram : `GET /me?fields=user_id,username` → le username comme handle,
/// `user_id` comme id plateforme (référence ig-user, relevé 2026-09-02).
pub const INSTAGRAM_ME: &str = "https://graph.instagram.com/me";
/// TikTok : `GET /v2/user/info/?fields=open_id,display_name` (scope
/// user.info.basic, relevé 2026-09-02) — `open_id` est l'identifiant que tous
/// les endpoints Content Posting/Display exigent.
pub const TIKTOK_USERINFO: &str = "https://open.tiktokapis.com/v2/user/info/";
/// YouTube : `GET /youtube/v3/channels?part=snippet&mine=true` → le titre du
/// channel comme handle, `items[0].id` (UC…) comme id plateforme. Coûte
/// 1 unité de quota (channels.list, relevé 2026-09-02) — dit ici parce que
/// c'est le seul appel d'identité du service qui a un prix.
pub const YOUTUBE_CHANNELS: &str = "https://www.googleapis.com/youtube/v3/channels";

/// `tweet.write` publie (creation-of-a-post), `tweet.read`/`users.read` lisent
/// les métriques (get-post-by-id) ET servent `GET /2/users/me`,
/// `offline.access` fait émettre le refresh token — tous relevés le 2026-09-02.
///
/// La surface messagerie (relevés docs.x.com/x-api/direct-messages/manage/integrate,
/// 2026-09-02) : `dm.read` + `dm.write` pour les DM (« dm.write exige dm.read »,
/// et tous les scopes dm exigent `tweet.read` + `users.read`, déjà là),
/// `like.write` pour `POST /2/users/{id}/likes`, `bookmark.write` pour les
/// bookmarks (« OAuth2 PKCE uniquement » — notre flux X est déjà PKCE).
///
/// Un compte connecté AVANT cet élargissement n'a PAS ces scopes : son jeton
/// prendra un 403 de plateforme sur les outils messagerie, et
/// `account_connect_url` reste le chemin de re-consentement — pas de
/// migration de jetons, l'humain re-consent et la ligne de compte se
/// re-scelle par l'upsert de `connecter_compte`.
pub const X_SCOPES: &str = "tweet.read tweet.write users.read offline.access media.write dm.read dm.write like.write bookmark.write";
/// `w_member_social` : « Post, comment, and like posts on behalf of an
/// authenticated member » (posts-api, table Permissions). `openid` + `profile` :
/// requis pour `GET /v2/userinfo`, qui est le SEUL moyen self-serve de savoir
/// quel membre le jeton représente — sans lui, pas d'URN d'auteur, pas de post
/// (sign-in-with-linkedin-v2, produit « Sign In with LinkedIn using OpenID
/// Connect », sans revue d'app). Relevés le 2026-09-02.
pub const LINKEDIN_SCOPES: &str = "openid profile w_member_social";
/// Page organisation, derrière `SOCIAL_LINKEDIN_ORG_POSTING`. Le membre
/// (`w_member_social`) reste toujours demandé. `w_organization_social` poste
/// au nom d'une page dont le membre a le rôle.
pub const LINKEDIN_SCOPES_ORG: &str = "openid profile w_member_social w_organization_social";
/// Les quatre scopes du chemin « Instagram API with Instagram Login » (tableau
/// de permissions, developers.facebook.com/docs/instagram-platform, relevé
/// 2026-09-02) : publier (content_publish), modérer les commentaires
/// (manage_comments), répondre aux DM (manage_messages), et le socle (basic).
/// Séparés par des VIRGULES — la forme de l'URL d'exemple de business-login.
pub const INSTAGRAM_SCOPES: &str = "instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments,instagram_business_manage_messages";
/// `video.publish` (Direct Post), `video.list` (read_timeline/metriques),
/// `user.info.basic` (identité) — tiktok-api-scopes, relevé 2026-09-02.
/// Séparés par des VIRGULES (« comma-separated », oauth-user-access-token).
pub const TIKTOK_SCOPES: &str = "user.info.basic,video.list,video.publish,video.upload";
/// Les seuls scopes que `SOCIAL_TIKTOK_EXTRA_SCOPES` peut ajouter :
/// `user.info.profile` (bio_description, profile_deep_link, is_verified,
/// username) et `user.info.stats` (follower_count, following_count,
/// likes_count, video_count) — user/info, relevé 2026-11-11. Demander à
/// l'OAuth un scope que l'app n'a pas fait échouer la connexion : la variable
/// est vide par défaut.
pub const TIKTOK_SCOPES_OPTIONNELS: [&str; 2] = ["user.info.profile", "user.info.stats"];

/// Lit `SOCIAL_TIKTOK_EXTRA_SCOPES` (virgules ou espaces) : les scopes
/// acceptés, dans l'ordre de [`TIKTOK_SCOPES_OPTIONNELS`] et sans doublon,
/// puis les entrées refusées — que l'appelant signale et ignore.
pub fn scopes_tiktok_optionnels(brut: &str) -> (Vec<&'static str>, Vec<String>) {
    let demandes: Vec<&str> = brut
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    let acceptes = TIKTOK_SCOPES_OPTIONNELS
        .into_iter()
        .filter(|s| demandes.contains(s))
        .collect();
    let refuses = demandes
        .iter()
        .filter(|d| !TIKTOK_SCOPES_OPTIONNELS.contains(d))
        .map(|d| (*d).to_owned())
        .collect();
    (acceptes, refuses)
}
/// `youtube.upload` publie ; `youtube.force-ssl` couvre commentaires, likes,
/// recherche et lectures (commentThreads/insert, videos/rate — relevés
/// 2026-09-02). Google sépare les scopes par des ESPACES, comme X/LinkedIn.
pub const YOUTUBE_SCOPES: &str = "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.force-ssl";
/// Permissions à cocher dans la configuration Facebook Login for Business
/// (`META2_FB_CONFIG_ID`). Elles ne partent pas dans `scope` : le `config_id`
/// les remplace. `instagram_business_*` est le produit « Instagram Login »,
/// indisponible sur une app neuve (« Invalid platform app »).
/// `instagram_manage_comments` et `instagram_manage_messages` ne sont pas
/// dans cette liste : le code ne les appelle pas.
/// Relevées le 2026-11-10.
pub const META2_PERMISSIONS_CONFIG: &[&str] = &[
    "pages_show_list",
    "pages_manage_posts",
    "pages_read_engagement",
    "instagram_basic",
    "instagram_content_publish",
];
/// Threads API. Relevées le 2026-11-10.
pub const THREADS_SCOPES: &str = "threads_basic,threads_content_publish";

/// Même hôte que le connecteur historique : une autre app, le même dialogue.
pub const FACEBOOK_AUTORISATION: &str = "https://www.facebook.com/v27.0/dialog/oauth";
pub const FACEBOOK_JETON: &str = "https://graph.facebook.com/v27.0/oauth/access_token";
pub const FACEBOOK_ME: &str = "https://graph.facebook.com/v27.0/me";
pub const FACEBOOK_PAGES: &str = "https://graph.facebook.com/v27.0/me/accounts";
pub const THREADS_AUTORISATION: &str = "https://threads.net/oauth/authorize";
pub const THREADS_JETON: &str = "https://graph.threads.net/oauth/access_token";
pub const THREADS_JETON_LONG: &str = "https://graph.threads.net/access_token";
pub const THREADS_RAFRAICHIR: &str = "https://graph.threads.net/refresh_access_token";
pub const THREADS_ME: &str = "https://graph.threads.net/v1.0/me";

/// Mêmes largeurs que `oauth.rs` : 32 octets d'OS pour le `state` (256 bits
/// contre qui regarde les flux passer), 32 pour le vérifieur (le minimum de
/// RFC 7636 est 43 caractères base64url parce que c'est 256 bits).
const STATE_OCTETS: usize = 32;
const VERIFIEUR_OCTETS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlateformeOauth {
    X,
    Linkedin,
    Instagram,
    Tiktok,
    Youtube,
    /// Reel via Facebook Login for Business (même dialogue que `FacebookPage`).
    /// Publication sur `graph.facebook.com/{ig-user-id}/media`, pas sur
    /// `instagram.com`.
    InstagramReels,
    /// Facebook Login for Business, puis un jeton de Page par Page.
    FacebookPage,
    /// Threads API, app `META2_THREADS_*`.
    Threads,
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

/// Scelle le refresh token de X sous son AAD propre. L'ouvreur est
/// [`ouvrir_rafraichissement`], et le seul appelant des deux est le chemin de
/// publication : perdre ce jeton coûterait un re-consentement humain.
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

/// L'autre moitié de [`sceller_rafraichissement`]. AAD séparée exprès : un
/// refresh token déplacé dans la case d'un jeton d'accès ne s'ouvre pas.
pub fn ouvrir_rafraichissement(
    chiffre: &LocalEnvelopeSecretStore,
    tenant: TenantId,
    plateforme: &str,
    compte: &str,
    scelle: &[u8],
) -> Result<Secret, ProviderError> {
    let envelope = Envelope::from_bytes(scelle)?;
    chiffre.open_in(
        tenant,
        &contexte_rafraichissement(tenant, plateforme, compte),
        &envelope,
    )
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
    demarrer_interne(
        plateforme,
        client_id,
        redirect_uri,
        tenant,
        chiffre,
        false,
        None,
        &[],
    )
}

/// Comme [`demarrer`], avec `w_organization_social` en plus des scopes membre.
/// Réservé au drapeau `SOCIAL_LINKEDIN_ORG_POSTING`.
pub fn demarrer_page(
    plateforme: PlateformeOauth,
    client_id: &str,
    redirect_uri: &str,
    tenant: TenantId,
    chiffre: &LocalEnvelopeSecretStore,
) -> Result<FluxDemarre, ProviderError> {
    demarrer_interne(
        plateforme,
        client_id,
        redirect_uri,
        tenant,
        chiffre,
        true,
        None,
        &[],
    )
}

/// Facebook Login for Business, pour `facebook_page` et `instagram_reels`.
///
/// `config_id` remplace `scope` (`override_default_response_type=true` pour
/// obtenir un code, pas un jeton implicite). Même URL pour les deux
/// plateformes : un consentement relie la Page et le compte Instagram
/// professionnel qui y est lié.
/// <https://developers.facebook.com/docs/facebook-login/facebook-login-for-business>,
/// relevé le 2026-11-10.
pub fn demarrer_facebook_business(
    plateforme: PlateformeOauth,
    client_id: &str,
    config_id: &str,
    redirect_uri: &str,
    tenant: TenantId,
    chiffre: &LocalEnvelopeSecretStore,
) -> Result<FluxDemarre, ProviderError> {
    demarrer_interne(
        plateforme,
        client_id,
        redirect_uri,
        tenant,
        chiffre,
        false,
        Some(config_id),
        &[],
    )
}

/// TikTok avec les scopes optionnels de `SOCIAL_TIKTOK_EXTRA_SCOPES`, ajoutés
/// après [`TIKTOK_SCOPES`]. `scopes_extra` vide rend l'URL de [`demarrer`].
pub fn demarrer_tiktok(
    client_id: &str,
    scopes_extra: &[&str],
    redirect_uri: &str,
    tenant: TenantId,
    chiffre: &LocalEnvelopeSecretStore,
) -> Result<FluxDemarre, ProviderError> {
    demarrer_interne(
        PlateformeOauth::Tiktok,
        client_id,
        redirect_uri,
        tenant,
        chiffre,
        false,
        None,
        scopes_extra,
    )
}

/// Un id de configuration Meta est une suite de chiffres.
pub fn config_id_meta2_valide(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_digit())
}

#[allow(clippy::too_many_arguments)]
fn demarrer_interne(
    plateforme: PlateformeOauth,
    client_id: &str,
    redirect_uri: &str,
    tenant: TenantId,
    chiffre: &LocalEnvelopeSecretStore,
    page_linkedin: bool,
    config_id: Option<&str>,
    scopes_tiktok_extra: &[&str],
) -> Result<FluxDemarre, ProviderError> {
    let state = aleatoire_b64url(STATE_OCTETS);
    let empreinte = empreinte_state(&state);

    let (point, scopes) = match plateforme {
        PlateformeOauth::X => (X_AUTORISATION, X_SCOPES),
        PlateformeOauth::Linkedin => (
            LINKEDIN_AUTORISATION,
            if page_linkedin {
                LINKEDIN_SCOPES_ORG
            } else {
                LINKEDIN_SCOPES
            },
        ),
        PlateformeOauth::Instagram => (INSTAGRAM_AUTORISATION, INSTAGRAM_SCOPES),
        PlateformeOauth::Tiktok => (TIKTOK_AUTORISATION, TIKTOK_SCOPES),
        PlateformeOauth::Youtube => (YOUTUBE_AUTORISATION, YOUTUBE_SCOPES),
        // Les deux plateformes du second connecteur Meta : le même dialogue
        // Facebook. Pas de `scope` ici — il vit dans la configuration.
        PlateformeOauth::InstagramReels | PlateformeOauth::FacebookPage => {
            (FACEBOOK_AUTORISATION, "")
        }
        PlateformeOauth::Threads => (THREADS_AUTORISATION, THREADS_SCOPES),
    };
    let scopes_tiktok;
    let scopes = if plateforme == PlateformeOauth::Tiktok && !scopes_tiktok_extra.is_empty() {
        scopes_tiktok = format!("{TIKTOK_SCOPES},{}", scopes_tiktok_extra.join(","));
        scopes_tiktok.as_str()
    } else {
        scopes
    };
    // TikTok nomme son identifiant client `client_key` — le seul des cinq
    // (oauth-user-access-token-management, relevé 2026-09-02). Les scopes,
    // eux, sont DANS la constante : virgules ou espaces selon la plateforme,
    // la valeur est déjà de la bonne forme.
    let nom_client = match plateforme {
        PlateformeOauth::Tiktok => "client_key",
        _ => "client_id",
    };
    // `Url` et pas `format!` : les scopes ont des espaces, un client_id est
    // une valeur opaque du fournisseur — la raison exacte de `oauth::start`.
    let mut url = Url::parse(point).expect("littéral https statique");
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair(nom_client, client_id)
            .append_pair("redirect_uri", redirect_uri);
        if matches!(
            plateforme,
            PlateformeOauth::FacebookPage | PlateformeOauth::InstagramReels
        ) {
            if let Some(config) = config_id {
                query
                    .append_pair("config_id", config)
                    .append_pair("override_default_response_type", "true");
            }
        } else {
            query.append_pair("scope", scopes);
        }
        query.append_pair("state", &state);
    }
    if plateforme == PlateformeOauth::Youtube {
        // Sans `access_type=offline` Google n'émet pas de refresh token, et
        // sans `prompt=consent` il ne le ré-émet qu'au PREMIER consentement de
        // la vie du couple (compte, client_id) — un utilisateur qui reconnecte
        // repartirait sans refresh et devrait re-consentir chaque heure
        // (web-server flow, relevé 2026-09-02).
        url.query_pairs_mut()
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
    }

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
        // Aucune des quatre autres docs ne définit de PKCE pour son flux web
        // confidentiel (LinkedIn étape 3 ; business-login IG ; oauth TikTok ;
        // web-server Google — relevés 2026-09-02) : sceller un vérifieur que
        // personne ne vérifiera serait le théâtre de la sécurité.
        _ => None,
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
/// table de l'étape 3 de sa doc. Instagram et YouTube : pareil (docs citées en
/// tête de module). TikTok : pareil, mais l'identifiant s'appelle
/// **`client_key`** — copier la forme LinkedIn ici produirait un
/// `invalid_client` qui ne nomme rien.
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
        PlateformeOauth::Linkedin
        | PlateformeOauth::Instagram
        | PlateformeOauth::InstagramReels
        | PlateformeOauth::FacebookPage
        | PlateformeOauth::Threads
        | PlateformeOauth::Youtube => vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret.unwrap_or_default()),
            ("redirect_uri", redirect_uri),
        ],
        PlateformeOauth::Tiktok => vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_key", client_id),
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
    let jeton = poster_jeton(plateforme, client_id, client_secret, &corps).await?;
    match plateforme {
        PlateformeOauth::Instagram => {
            // Le jeton de api.instagram.com/oauth/access_token est court ;
            // `ig_exchange_token` le troque contre le jeton long « valid for
            // 60 days » (long-lived-tokens, relevé 2026-09-02). C'est le long
            // qu'on scelle. Le second connecteur n'emprunte PAS ce chemin.
            let long = obtenir_jeton_en_get(
                INSTAGRAM_JETON_LONG,
                &[
                    ("grant_type", "ig_exchange_token"),
                    ("client_secret", secret_texte),
                    ("access_token", jeton.acces.expose_for_transport()),
                ],
            )
            .await?;
            Ok(copie_en_rafraichissement(long))
        }
        PlateformeOauth::Threads => {
            // Même chaîne, grant `th_exchange_token`, 60 jours
            // (Threads long-lived tokens, relevé le 2026-11-10).
            let long = obtenir_jeton_en_get(
                THREADS_JETON_LONG,
                &[
                    ("grant_type", "th_exchange_token"),
                    ("client_secret", secret_texte),
                    ("access_token", jeton.acces.expose_for_transport()),
                ],
            )
            .await?;
            Ok(copie_en_rafraichissement(long))
        }
        PlateformeOauth::FacebookPage | PlateformeOauth::InstagramReels => {
            // Court → long (`fb_exchange_token`, ~60 jours). Le jeton de Page
            // qu'on scelle ensuite est dérivé de CELUI-CI et n'expire pas
            // (get-long-lived, relevé le 2026-11-10). On ne copie pas ce jeton
            // utilisateur dans `sealed_refresh` : il ne quitte pas le callback.
            obtenir_jeton_en_get(
                FACEBOOK_JETON,
                &[
                    ("grant_type", "fb_exchange_token"),
                    ("client_id", client_id),
                    ("client_secret", secret_texte),
                    ("fb_exchange_token", jeton.acces.expose_for_transport()),
                ],
            )
            .await
        }
        _ => Ok(jeton),
    }
}

/// Instagram n'a PAS de refresh_token séparé : le jeton long se rafraîchit
/// lui-même. La colonne `sealed_refresh` reçoit donc une COPIE du jeton long —
/// toute la machinerie existante (sceller, resceller, `jeton_rafraichi`)
/// marche alors sans une ligne de spécial-casing hors d'ici.
fn copie_en_rafraichissement(jeton: JetonEmis) -> JetonEmis {
    let copie = Secret::new(jeton.acces.expose_for_transport());
    JetonEmis {
        rafraichissement: Some(copie),
        ..jeton
    }
}

/// Les deux points GET d'Instagram (échange long, rafraîchissement) rendent la
/// même forme `{access_token, token_type, expires_in}` que les points POST —
/// même lecteur `jeton_depuis`, même discipline anti-fuite.
async fn obtenir_jeton_en_get(
    point: &'static str,
    parametres: &[(&str, &str)],
) -> Result<JetonEmis, ErreurPlateforme> {
    let reponse = http()
        .get(point)
        .query(parametres)
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
    match plateforme {
        PlateformeOauth::Linkedin
        | PlateformeOauth::FacebookPage
        | PlateformeOauth::InstagramReels => {
            // Le jeton de Page (et celui scellé pour le Reel lié) ne se
            // rafraîchit pas : il est dérivé du jeton utilisateur long.
            // Un 401 se répare par un nouveau consentement.
            Err(ErreurPlateforme::RafraichissementIndisponible)
        }
        PlateformeOauth::Instagram => {
            // Le jeton long se rafraîchit LUI-MÊME (`sealed_refresh` en porte
            // la copie) — exige un jeton « at least 24 hours old » ET encore
            // valide (refresh_access_token, relevé 2026-09-02). C'est pour ce
            // « encore valide » que `mcp::jeton_frais` appelle PROACTIVEMENT :
            // au premier 401 le rafraîchissement serait déjà impossible.
            let frais = obtenir_jeton_en_get(
                INSTAGRAM_RAFRAICHIR,
                &[
                    ("grant_type", "ig_refresh_token"),
                    ("access_token", rafraichissement.expose_for_transport()),
                ],
            )
            .await?;
            Ok(copie_en_rafraichissement(frais))
        }
        PlateformeOauth::Threads => {
            // `th_refresh_token`, jeton « at least 24 hours old » et encore
            // valide — même fenêtre proactive que Instagram.
            let frais = obtenir_jeton_en_get(
                THREADS_RAFRAICHIR,
                &[
                    ("grant_type", "th_refresh_token"),
                    ("access_token", rafraichissement.expose_for_transport()),
                ],
            )
            .await?;
            Ok(copie_en_rafraichissement(frais))
        }
        _ => {
            // X, TikTok, YouTube : `grant_type=refresh_token` sur le même
            // point de jeton — le chemin partagé sert tel quel, seule la
            // place des credentials client change (corps_de_rafraichissement).
            let corps = corps_de_rafraichissement(
                plateforme,
                rafraichissement.expose_for_transport(),
                client_id,
                client_secret.expose_for_transport(),
            );
            poster_jeton(plateforme, client_id, client_secret, &corps).await
        }
    }
}

/// Le corps d'un rafraîchissement POST, sorti en fonction pour être comparé
/// aux tables des docs sans réseau. X : client en Basic, rien dans le corps.
/// TikTok : `client_key` + secret dans le corps (oauth-user-access-token).
/// YouTube : `client_id` + secret dans le corps (web-server, « Refreshing an
/// access token »). LinkedIn et Instagram ne passent jamais ici (refus nommé
/// et GET dédié, plus haut).
pub fn corps_de_rafraichissement<'a>(
    plateforme: PlateformeOauth,
    rafraichissement: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
) -> Vec<(&'static str, &'a str)> {
    match plateforme {
        PlateformeOauth::Tiktok => vec![
            ("grant_type", "refresh_token"),
            ("client_key", client_id),
            ("client_secret", client_secret),
            ("refresh_token", rafraichissement),
        ],
        PlateformeOauth::Youtube => vec![
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", rafraichissement),
        ],
        _ => vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", rafraichissement),
        ],
    }
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
        PlateformeOauth::Instagram => INSTAGRAM_JETON,
        PlateformeOauth::FacebookPage | PlateformeOauth::InstagramReels => FACEBOOK_JETON,
        PlateformeOauth::Threads => THREADS_JETON,
        PlateformeOauth::Tiktok => TIKTOK_JETON,
        PlateformeOauth::Youtube => YOUTUBE_JETON,
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
/// ligne de compte : elle donne le `handle` de `social_accounts` (nom d'écran
/// chez X, URN d'auteur chez LinkedIn) ET `platform_user_id`, l'identifiant
/// que les chemins d'API `/2/users/{id}/…` exigent (l'id numérique chez X ;
/// chez LinkedIn l'URN sert aux deux rôles).
pub async fn identite(
    plateforme: PlateformeOauth,
    acces: &Secret,
) -> Result<(String, String), ErreurPlateforme> {
    // Le couple (point, query) de chaque plateforme — le jeton passe en
    // Bearer partout, jamais dans la query : une URL finit dans des logs.
    let (point, query): (&str, &[(&str, &str)]) = match plateforme {
        PlateformeOauth::X => (X_ME, &[]),
        PlateformeOauth::Linkedin => (LINKEDIN_USERINFO, &[]),
        PlateformeOauth::Instagram => (INSTAGRAM_ME, &[("fields", "user_id,username")]),
        PlateformeOauth::FacebookPage | PlateformeOauth::InstagramReels => {
            (FACEBOOK_ME, &[("fields", "id,name")])
        }
        PlateformeOauth::Threads => (THREADS_ME, &[("fields", "id,username")]),
        PlateformeOauth::Tiktok => (TIKTOK_USERINFO, &[("fields", "open_id,display_name")]),
        PlateformeOauth::Youtube => (YOUTUBE_CHANNELS, &[("part", "snippet"), ("mine", "true")]),
    };
    let reponse = http()
        .get(point)
        .query(query)
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
/// Rend `(handle, platform_user_id)`.
///
/// X : `{"data": {"id", "name", "username"}}` (user-lookup-me) → le `username`
/// comme handle, et `data.id` — l'id NUMÉRIQUE que `/2/users/{id}/likes`,
/// `/bookmarks`, `/retweets` et `/mentions` exigent : le username n'y passe
/// pas.
/// Organisations que le membre peut publier. `organizationAcls?q=roleAssignee`
/// (Community Management). On ne garde que les rôles qui postent.
pub fn organisations_depuis(statut: u16, corps: &[u8]) -> Result<Vec<String>, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let elements = document
        .get("elements")
        .and_then(|v| v.as_array())
        .ok_or(ErreurPlateforme::Illisible)?;
    let mut orgs = Vec::new();
    for element in elements {
        let role = element.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if role != "ADMINISTRATOR" && role != "CONTENT_ADMIN" {
            continue;
        }
        let Some(urn) = element.get("organization").and_then(|v| v.as_str()) else {
            continue;
        };
        if urn.starts_with("urn:li:organization:") {
            orgs.push(urn.to_owned());
        }
    }
    Ok(orgs)
}

pub const POINT_ORGANISATIONS: &str =
    "https://api.linkedin.com/rest/organizationAcls?q=roleAssignee&state=APPROVED";

/// Liste les pages que le membre peut publier. Un échec réseau est une erreur :
/// l'appelant décide de ne pas faire échouer la connexion du membre pour autant.
pub async fn lister_organisations(acces: &Secret) -> Result<Vec<String>, ErreurPlateforme> {
    let reponse = http()
        .get(POINT_ORGANISATIONS)
        .bearer_auth(acces.expose_for_transport())
        .header(
            "LinkedIn-Version",
            crate::adapters::linkedin::VERSION_LINKEDIN,
        )
        .header(
            "X-Restli-Protocol-Version",
            crate::adapters::linkedin::PROTOCOLE_RESTLI,
        )
        .send()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    let statut = reponse.status().as_u16();
    let corps = reponse
        .bytes()
        .await
        .map_err(|_| ErreurPlateforme::Injoignable)?;
    organisations_depuis(statut, &corps)
}

fn id_page(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_digit())
}

/// Compte Instagram professionnel lié à une Page
/// (`instagram_business_account`). Pas le produit Instagram Login.
pub struct InstagramLie {
    pub id: String,
    /// Nom d'utilisateur, pour l'écran de retour. Le handle en base est `id`.
    pub username: String,
}

/// Une Page que le membre peut publier. Pas de `Debug` : `jeton` est le
/// jeton de Page, il ne doit pas finir dans un log.
pub struct PageFacebook {
    pub id: String,
    pub nom: String,
    pub jeton: Secret,
    pub instagram: Option<InstagramLie>,
}

/// `GET /me/accounts?fields=id,name,access_token,tasks,instagram_business_account{id,username}`.
/// On ne garde que les Pages dont la tâche est CREATE_CONTENT ou MANAGE.
/// Sans tableau `tasks`, on garde la Page : le champ est parfois omis.
/// `instagram_business_account` est le compte professionnel lié à la Page.
/// Absent = pas de ligne `instagram_reels` pour cette Page.
pub fn pages_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<(Vec<PageFacebook>, Option<String>), ErreurPlateforme> {
    let document = crate::adapters::lire_json(statut, corps)?;
    let elements = document
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or(ErreurPlateforme::Illisible)?;
    let mut pages = Vec::new();
    for element in elements {
        let Some(id) = element.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !id_page(id) {
            continue;
        }
        let Some(jeton) = element.get("access_token").and_then(|v| v.as_str()) else {
            continue;
        };
        if jeton.is_empty() {
            continue;
        }
        if let Some(tasks) = element.get("tasks").and_then(|v| v.as_array()) {
            let peut = tasks
                .iter()
                .any(|t| matches!(t.as_str(), Some("CREATE_CONTENT") | Some("MANAGE")));
            if !peut {
                continue;
            }
        }
        let nom = element.get("name").and_then(|v| v.as_str()).unwrap_or(id);
        let instagram = element.get("instagram_business_account").and_then(|ig| {
            let id_ig = ig.get("id").and_then(|v| v.as_str())?;
            let username = ig.get("username").and_then(|v| v.as_str()).unwrap_or("");
            if !id_page(id_ig) {
                return None;
            }
            Some(InstagramLie {
                id: id_ig.to_owned(),
                username: username.to_owned(),
            })
        });
        pages.push(PageFacebook {
            id: id.to_owned(),
            nom: nom.to_owned(),
            jeton: Secret::new(jeton),
            instagram,
        });
    }
    let suivant = document
        .pointer("/paging/cursors/after")
        .and_then(|v| v.as_str())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 2048
                && s.bytes()
                    .all(|b| b.is_ascii() && !b.is_ascii_whitespace() && b != b'&' && b != b'#')
        })
        .map(str::to_owned);
    Ok((pages, suivant))
}

/// Liste les Pages. Le curseur `after` repart en query encodée, jamais collé
/// dans une URL copiée de `paging.next` (cette URL porte souvent le jeton).
pub async fn lister_pages(acces: &Secret) -> Result<Vec<PageFacebook>, ErreurPlateforme> {
    let mut curseur: Option<String> = None;
    let mut toutes = Vec::new();
    for _ in 0..4 {
        let mut requete = http()
            .get(FACEBOOK_PAGES)
            .bearer_auth(acces.expose_for_transport())
            .query(&[
                (
                    "fields",
                    "id,name,access_token,tasks,instagram_business_account{id,username}",
                ),
                ("limit", "50"),
            ]);
        if let Some(apres) = &curseur {
            requete = requete.query(&[("after", apres.as_str())]);
        }
        let reponse = requete
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let (pages, suivant) = pages_depuis(statut, &corps)?;
        toutes.extend(pages);
        match suivant {
            Some(c) if curseur.as_deref() != Some(c.as_str()) => curseur = Some(c),
            _ => break,
        }
    }
    Ok(toutes)
}

/// LinkedIn : `{"sub": "782bbtaQ", ...}` → `urn:li:person:{sub}` — `sub` est
/// « User identifier » (sign-in-with-linkedin-v2) et l'URN d'auteur du Posts
/// API est `urn:li:person:{id}` (post-api-schema) ; l'URN sert aux deux
/// rôles. Les deux relevés le 2026-09-02.
pub fn identite_depuis(
    plateforme: PlateformeOauth,
    statut: u16,
    corps: &[u8],
) -> Result<(String, String), ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let champ = |pointeur: &str| {
        document
            .pointer(pointeur)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    };
    match plateforme {
        PlateformeOauth::X => Ok((champ("/data/username")?, champ("/data/id")?)),
        PlateformeOauth::Linkedin => {
            let urn = format!("urn:li:person:{}", champ("/sub")?);
            Ok((urn.clone(), urn))
        }
        // `GET graph.instagram.com/me?fields=user_id,username` →
        // `{"user_id": "...", "username": "..."}` (ig-user, relevé 2026-09-02).
        // Le username est le handle humain ; `user_id` est l'id que les
        // chemins `/{ig-user-id}/media` exigent.
        PlateformeOauth::Instagram => Ok((champ("/username")?, champ("/user_id")?)),
        // `GET graph.facebook.com/me?fields=id,name`. L'id est le sujet de
        // la suppression. Les lignes scellées sont les Pages et les comptes
        // Instagram liés, pas cet utilisateur.
        PlateformeOauth::FacebookPage | PlateformeOauth::InstagramReels => {
            Ok((champ("/name")?, champ("/id")?))
        }
        // `GET graph.threads.net/v1.0/me?fields=id,username`.
        PlateformeOauth::Threads => Ok((champ("/username")?, champ("/id")?)),
        // `GET /v2/user/info/` enveloppe sous `data.user` (get-user-info,
        // relevé 2026-09-02) ; `open_id` est l'identifiant de TOUS les
        // endpoints Content Posting/Display.
        PlateformeOauth::Tiktok => Ok((
            champ("/data/user/display_name")?,
            champ("/data/user/open_id")?,
        )),
        // `channels.list?mine=true` → `items[0]` est LE channel du jeton ;
        // son `id` (UC…) est l'id plateforme, `snippet.title` le nom montrable
        // (channels/list, relevé 2026-09-02). Un compte Google sans channel
        // YouTube rend `items` vide — Illisible, et l'humain crée son channel
        // avant de reconnecter.
        PlateformeOauth::Youtube => Ok((champ("/items/0/snippet/title")?, champ("/items/0/id")?)),
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
        let page = demarrer_page(
            PlateformeOauth::Linkedin,
            "client-li",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("page");
        let params_page = parametres(&page.authorize_url);
        assert_eq!(params_page["scope"], LINKEDIN_SCOPES_ORG);
        assert!(params_page["scope"].contains("w_organization_social"));
        assert!(params_page["scope"].contains("w_member_social"));
        let orgs = organisations_depuis(
            200,
            br#"{"elements":[
                {"organization":"urn:li:organization:42","role":"ADMINISTRATOR","state":"APPROVED"},
                {"organization":"urn:li:organization:7","role":"CONTENT_ADMIN","state":"APPROVED"},
                {"organization":"urn:li:organization:9","role":"CURATOR","state":"APPROVED"},
                {"organization":"urn:li:person:nope","role":"ADMINISTRATOR"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            orgs,
            vec![
                "urn:li:organization:42".to_owned(),
                "urn:li:organization:7".to_owned()
            ]
        );
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
            INSTAGRAM_AUTORISATION,
            INSTAGRAM_JETON,
            INSTAGRAM_JETON_LONG,
            INSTAGRAM_RAFRAICHIR,
            INSTAGRAM_ME,
            TIKTOK_AUTORISATION,
            TIKTOK_JETON,
            TIKTOK_USERINFO,
            YOUTUBE_AUTORISATION,
            YOUTUBE_JETON,
            YOUTUBE_CHANNELS,
            FACEBOOK_AUTORISATION,
            FACEBOOK_JETON,
            FACEBOOK_ME,
            FACEBOOK_PAGES,
            THREADS_AUTORISATION,
            THREADS_JETON,
            THREADS_JETON_LONG,
            THREADS_RAFRAICHIR,
            THREADS_ME,
        ] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }

    // -- Les trois flux du chantier IG/TikTok/YouTube, contre leurs docs. ----

    #[test]
    fn instagram_demarre_sans_pkce_avec_les_scopes_a_virgules() {
        let flux = demarrer(
            PlateformeOauth::Instagram,
            "client-ig",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert!(flux.authorize_url.starts_with(INSTAGRAM_AUTORISATION));
        assert_eq!(params["client_id"], "client-ig");
        // Les quatre scopes instagram_business_*, séparés par des virgules —
        // la forme de l'URL d'exemple de business-login (2026-09-02).
        assert_eq!(params["scope"], INSTAGRAM_SCOPES);
        assert!(params["scope"].contains(','));
        assert!(
            !params.contains_key("code_challenge"),
            "pas de PKCE documenté"
        );
        assert!(flux.verifieur_scelle.is_none());
    }

    #[test]
    fn tiktok_demarre_avec_client_key_jamais_client_id() {
        let flux = demarrer(
            PlateformeOauth::Tiktok,
            "clef-tiktok",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert!(flux.authorize_url.starts_with(TIKTOK_AUTORISATION));
        // LE piège de TikTok : `client_key`, pas `client_id`
        // (oauth-user-access-token-management, 2026-09-02).
        assert_eq!(params["client_key"], "clef-tiktok");
        assert!(!params.contains_key("client_id"));
        assert_eq!(params["scope"], TIKTOK_SCOPES);
        assert!(params["scope"].contains("video.upload"));
        assert!(params["scope"].contains("video.publish"));
        assert!(flux.verifieur_scelle.is_none());
    }

    /// Sans `SOCIAL_TIKTOK_EXTRA_SCOPES`, l'URL est celle d'avant la
    /// variable, à l'octet près (le state, aléatoire, est lu puis recollé).
    #[test]
    fn tiktok_sans_scopes_extra_garde_son_url_a_l_octet() {
        const ATTENDUE: &str = "https://www.tiktok.com/v2/auth/authorize/?response_type=code&client_key=clef-tiktok&redirect_uri=https%3A%2F%2Fsocial.example%2Foauth%2Fcallback&scope=user.info.basic%2Cvideo.list%2Cvideo.publish%2Cvideo.upload&state=";
        let historique = demarrer(
            PlateformeOauth::Tiktok,
            "clef-tiktok",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let sans_extra = demarrer_tiktok(
            "clef-tiktok",
            &[],
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        for flux in [historique, sans_extra] {
            let state = &parametres(&flux.authorize_url)["state"];
            assert_eq!(flux.authorize_url, format!("{ATTENDUE}{state}"));
        }
    }

    #[test]
    fn tiktok_avec_scopes_extra_les_ajoute_apres_les_quatre() {
        let (extra, refuses) = scopes_tiktok_optionnels("user.info.profile,user.info.stats");
        assert!(refuses.is_empty());
        let flux = demarrer_tiktok(
            "clef-tiktok",
            &extra,
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert_eq!(
            params["scope"],
            "user.info.basic,video.list,video.publish,video.upload,user.info.profile,user.info.stats"
        );
        assert_eq!(params["client_key"], "clef-tiktok");
    }

    #[test]
    fn les_scopes_extra_tiktok_ne_laissent_passer_que_les_deux_connus() {
        assert_eq!(scopes_tiktok_optionnels(""), (vec![], vec![]));
        assert_eq!(scopes_tiktok_optionnels("  "), (vec![], vec![]));
        // Ordre canonique, doublon retiré, espaces ou virgules.
        assert_eq!(
            scopes_tiktok_optionnels("user.info.stats, user.info.profile user.info.stats"),
            (vec!["user.info.profile", "user.info.stats"], vec![])
        );
        // video.manage n'a pas d'endpoint public : refusé comme tout le reste,
        // sans emporter le scope valide posé à côté.
        assert_eq!(
            scopes_tiktok_optionnels("video.manage,user.info.stats,USER.INFO.PROFILE"),
            (
                vec!["user.info.stats"],
                vec!["video.manage".to_owned(), "USER.INFO.PROFILE".to_owned()]
            )
        );
        // Un scope déjà dans TIKTOK_SCOPES n'est pas « en plus ».
        assert_eq!(
            scopes_tiktok_optionnels("video.list"),
            (vec![], vec!["video.list".to_owned()])
        );
    }

    #[test]
    fn youtube_demarre_en_offline_et_reforce_le_consentement() {
        let flux = demarrer(
            PlateformeOauth::Youtube,
            "client-g",
            "https://social.example/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("démarrage");
        let params = parametres(&flux.authorize_url);
        assert!(flux.authorize_url.starts_with(YOUTUBE_AUTORISATION));
        // Sans ces deux paramètres, pas de refresh token à la reconnexion —
        // la citation vit sur le code qui les pose.
        assert_eq!(params["access_type"], "offline");
        assert_eq!(params["prompt"], "consent");
        assert_eq!(params["scope"], YOUTUBE_SCOPES);
        assert!(flux.verifieur_scelle.is_none());
    }

    #[test]
    fn le_second_connecteur_meta_a_ses_propres_portees() {
        // La version Facebook est celle du connecteur historique : un bump
        // de VERSION_GRAPH qui oublie ces URL casse le test.
        assert!(FACEBOOK_AUTORISATION.contains(crate::adapters::instagram::VERSION_GRAPH));
        assert!(FACEBOOK_JETON.contains(crate::adapters::instagram::VERSION_GRAPH));
        for pf in [
            PlateformeOauth::InstagramReels,
            PlateformeOauth::FacebookPage,
        ] {
            let flux = demarrer_facebook_business(
                pf,
                "app-2",
                "1234567890",
                "https://social-local.orizn.app/oauth/callback",
                tenant(),
                &chiffre(),
            )
            .expect("démarrage");
            let params = parametres(&flux.authorize_url);
            assert!(
                flux.authorize_url.starts_with(FACEBOOK_AUTORISATION),
                "{}",
                flux.authorize_url
            );
            assert!(!flux.authorize_url.contains("instagram.com"));
            assert!(!flux.authorize_url.contains("instagram_business"));
            assert!(!params.contains_key("scope"), "config_id remplace scope");
            assert_eq!(params["config_id"], "1234567890");
            assert_eq!(params["override_default_response_type"], "true");
            assert_eq!(params["response_type"], "code");
            assert_eq!(
                params["redirect_uri"],
                "https://social-local.orizn.app/oauth/callback"
            );
            assert!(flux.verifieur_scelle.is_none(), "pas de PKCE documenté");
        }
        let threads = demarrer(
            PlateformeOauth::Threads,
            "app-threads",
            "https://social-local.orizn.app/oauth/callback",
            tenant(),
            &chiffre(),
        )
        .expect("threads");
        assert!(threads.authorize_url.starts_with(THREADS_AUTORISATION));
        assert_eq!(parametres(&threads.authorize_url)["scope"], THREADS_SCOPES);
        // La configuration ne demande pas commentaires ni messages : le code
        // ne les appelle pas. Le connecteur historique, lui, les garde.
        assert!(!META2_PERMISSIONS_CONFIG.contains(&"instagram_manage_comments"));
        assert!(!META2_PERMISSIONS_CONFIG.contains(&"instagram_manage_messages"));
        assert!(!META2_PERMISSIONS_CONFIG.contains(&"ads_management"));
        assert!(!META2_PERMISSIONS_CONFIG.contains(&"ads_read"));
        assert!(META2_PERMISSIONS_CONFIG.contains(&"instagram_basic"));
        assert!(META2_PERMISSIONS_CONFIG.contains(&"instagram_content_publish"));
        assert!(META2_PERMISSIONS_CONFIG.contains(&"pages_manage_posts"));
        assert!(
            INSTAGRAM_SCOPES.contains("instagram_business_manage_messages"),
            "le connecteur historique garde ses portées"
        );
        assert!(config_id_meta2_valide("1234567890"));
        assert!(!config_id_meta2_valide(""));
        assert!(!config_id_meta2_valide("cfg-1"));
    }

    #[test]
    fn les_pages_se_lisent_sans_garder_un_jeton_dans_l_erreur() {
        let corps = br#"{"data":[
            {"id":"111","name":"Clip","access_token":"JETON-PAGE","tasks":["CREATE_CONTENT"],"instagram_business_account":{"id":"17841405822304914","username":"cliponit"}},
            {"id":"222","name":"Lecture","access_token":"AUTRE","tasks":["ANALYZE"]},
            {"id":"333","name":"Sans tache","access_token":"JETON-3"}
        ],"paging":{"cursors":{"after":"CURSEUR_1"}}}"#;
        let (pages, suivant) = pages_depuis(200, corps).expect("forme documentée");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].id, "111");
        assert_eq!(pages[0].nom, "Clip");
        assert_eq!(pages[0].jeton.expose_for_transport(), "JETON-PAGE");
        let ig = pages[0].instagram.as_ref().expect("compte lié");
        assert_eq!(ig.id, "17841405822304914");
        assert_eq!(ig.username, "cliponit");
        assert!(pages[1].instagram.is_none());
        assert_eq!(pages[1].id, "333");
        assert_eq!(suivant.as_deref(), Some("CURSEUR_1"));
        let limite = br#"{"error":{"message":"access_token=NE-DOIT-PAS-FUITER","code":32}}"#;
        match pages_depuis(400, limite) {
            Err(err) => {
                assert_eq!(err, ErreurPlateforme::LimitePublication);
                assert!(!err.to_string().contains("NE-DOIT-PAS-FUITER"));
            }
            Ok(_) => panic!("une limite doit être une erreur"),
        }
    }

    #[test]
    fn l_identite_du_second_connecteur_se_lit_comme_ses_docs() {
        let ig = identite_depuis(
            PlateformeOauth::InstagramReels,
            200,
            br#"{"id":"99","name":"Ada"}"#,
        )
        .unwrap();
        assert_eq!(ig, ("Ada".into(), "99".into()));
        let fb = identite_depuis(
            PlateformeOauth::FacebookPage,
            200,
            br#"{"id":"99","name":"Ada"}"#,
        )
        .unwrap();
        assert_eq!(fb, ("Ada".into(), "99".into()));
        let th = identite_depuis(
            PlateformeOauth::Threads,
            200,
            br#"{"id":"77","username":"ada"}"#,
        )
        .unwrap();
        assert_eq!(th, ("ada".into(), "77".into()));
    }

    #[test]
    fn les_corps_d_echange_des_trois_nouvelles_plateformes_suivent_leurs_docs() {
        // Instagram et YouTube : la forme LinkedIn (credentials dans le corps).
        for plateforme in [PlateformeOauth::Instagram, PlateformeOauth::Youtube] {
            assert_eq!(
                corps_d_echange(
                    plateforme,
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
            );
        }
        // TikTok : la même table, mais `client_key` (fetch-user-token, 2026-09-02).
        assert_eq!(
            corps_d_echange(
                PlateformeOauth::Tiktok,
                "auth-code",
                "https://cb.example",
                None,
                "clef",
                Some("secret"),
            ),
            vec![
                ("grant_type", "authorization_code"),
                ("code", "auth-code"),
                ("client_key", "clef"),
                ("client_secret", "secret"),
                ("redirect_uri", "https://cb.example"),
            ],
        );
    }

    #[test]
    fn les_corps_de_rafraichissement_portent_les_credentials_au_bon_endroit() {
        // X : client en Basic, le corps ne porte QUE le grant et le jeton.
        assert_eq!(
            corps_de_rafraichissement(PlateformeOauth::X, "r1", "id", "secret"),
            vec![("grant_type", "refresh_token"), ("refresh_token", "r1")],
        );
        assert_eq!(
            corps_de_rafraichissement(PlateformeOauth::Tiktok, "r1", "clef", "secret"),
            vec![
                ("grant_type", "refresh_token"),
                ("client_key", "clef"),
                ("client_secret", "secret"),
                ("refresh_token", "r1"),
            ],
        );
        assert_eq!(
            corps_de_rafraichissement(PlateformeOauth::Youtube, "r1", "id", "secret"),
            vec![
                ("grant_type", "refresh_token"),
                ("client_id", "id"),
                ("client_secret", "secret"),
                ("refresh_token", "r1"),
            ],
        );
    }

    /// Le rafraîchissement Instagram recopie le jeton frais dans la case
    /// refresh : c'est TOUTE l'astuce qui fait marcher la machinerie existante
    /// (resceller_jetons remplace quand `Some`) sans spécial-casing ailleurs.
    #[test]
    fn le_jeton_long_instagram_repart_en_acces_et_en_copie_refresh() {
        let jeton = jeton_depuis(
            200,
            br#"{"access_token":"IGQVJ-long","expires_in":5184000}"#,
        )
        .expect("forme documentée ig_exchange_token");
        let chaine = copie_en_rafraichissement(jeton);
        assert_eq!(chaine.acces.expose_for_transport(), "IGQVJ-long");
        assert_eq!(
            chaine
                .rafraichissement
                .as_ref()
                .expect("la copie existe")
                .expose_for_transport(),
            "IGQVJ-long"
        );
        assert_eq!(chaine.duree_s, 5_184_000);
    }

    /// Les fixtures d'identité des trois nouvelles docs, sans réseau.
    #[test]
    fn l_identite_des_trois_nouvelles_plateformes_se_lit_comme_leurs_docs() {
        // ig-user : GET /me?fields=user_id,username (2026-09-02).
        let ig = identite_depuis(
            PlateformeOauth::Instagram,
            200,
            br#"{"user_id":"17841405822304914","username":"orizn_app"}"#,
        )
        .expect("forme documentée Instagram");
        assert_eq!(ig, ("orizn_app".into(), "17841405822304914".into()));
        // get-user-info : l'enveloppe data.user (2026-09-02).
        let tt = identite_depuis(
            PlateformeOauth::Tiktok,
            200,
            br#"{"data":{"user":{"open_id":"723f24d7-e717-40f8","display_name":"Orizn"}},"error":null}"#,
        )
        .expect("forme documentée TikTok");
        assert_eq!(tt, ("Orizn".into(), "723f24d7-e717-40f8".into()));
        // channels/list : items[0].id + snippet.title (2026-09-02).
        let yt = identite_depuis(
            PlateformeOauth::Youtube,
            200,
            br#"{"items":[{"id":"UC_x5XG1OV2P6uZZ5FSM9Ttw","snippet":{"title":"Google Developers"}}]}"#,
        )
        .expect("forme documentée YouTube");
        assert_eq!(
            yt,
            (
                "Google Developers".into(),
                "UC_x5XG1OV2P6uZZ5FSM9Ttw".into()
            )
        );
        // Un compte Google SANS channel : items vide — illisible, pas un panic.
        assert_eq!(
            identite_depuis(PlateformeOauth::Youtube, 200, br#"{"items":[]}"#),
            Err(ErreurPlateforme::Illisible)
        );
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
        // Le handle est le username ; l'id NUMÉRIQUE part à part — c'est lui
        // que les chemins /2/users/{id}/… exigent.
        assert_eq!(x, ("XDevelopers".into(), "2244994945".into()));
        // sign-in-with-linkedin-v2 : le sub de l'exemple devient l'URN d'auteur,
        // qui sert aux deux rôles.
        let li = identite_depuis(
            PlateformeOauth::Linkedin,
            200,
            br#"{"sub":"782bbtaQ","name":"John Doe","locale":"en-US"}"#,
        )
        .expect("forme documentée LinkedIn");
        assert_eq!(li.0, "urn:li:person:782bbtaQ");
        assert_eq!(li.0, li.1);
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

    /// Les deux AAD sont des cases étanches : un refresh token scellé ne
    /// s'ouvre pas comme un jeton d'accès, et réciproquement. C'est la
    /// propriété qui rend `sceller_rafraichissement`/`ouvrir_rafraichissement`
    /// sûrs à câbler dans le chemin de publication — un octet rangé dans la
    /// mauvaise colonne échoue bruyamment au lieu de servir.
    #[test]
    fn le_refresh_scelle_ne_s_ouvre_que_dans_sa_case() {
        let chiffre = LocalEnvelopeSecretStore::new(Sha256::digest("clef-de-test").into());
        let tenant = TenantId::from_uuid(uuid::Uuid::now_v7());
        let secret = Secret::new("refresh-vivant");

        let scelle =
            sceller_rafraichissement(&chiffre, tenant, "x", "agent_test", &secret).unwrap();

        let ouvert = ouvrir_rafraichissement(&chiffre, tenant, "x", "agent_test", &scelle).unwrap();
        assert_eq!(ouvert.expose_for_transport(), "refresh-vivant");

        // La case d'a cote refuse.
        assert!(ouvrir_jeton(&chiffre, tenant, "x", "agent_test", &scelle).is_err());
        // Et un autre compte du meme tenant refuse aussi : le handle est dans l'AAD.
        assert!(ouvrir_rafraichissement(&chiffre, tenant, "x", "autre", &scelle).is_err());
    }
}
