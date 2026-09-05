//! agentos-social — l'agregateur de publication sociale concu pour des agents.
//!
//! Le seul du catalogue ou `OptOuts::NoStrangers` est vrai PAR CONSTRUCTION :
//! aucune surface DM (le test anti-DM de mcp.rs le prouve en lisant la table
//! d'outils), idempotence en base, previsualisation avec empreinte, table
//! d'outils versionnee.
//!
//! Deux modes :
//!   agentos-social                      — sert POST /mcp, POST /mcp/messagerie,
//!                                         GET /livez, GET /oauth/callback,
//!                                         GET /medias/{digest} (octets vettes,
//!                                         pour les plateformes a modele pull)
//!   agentos-social mint-tenant <label>  — frappe un jeton de tenant (affiche UNE fois)
//!
//! Environnement : SOCIAL_DATABASE_URL (base SEPAREE du runtime),
//! SOCIAL_MASTER_KEY (racine du scellement AES-256-GCM), SOCIAL_BIND
//! (defaut 127.0.0.1:8791), SOCIAL_PUBLIC_URL (base des redirect_uri OAuth).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub mod adapters;
pub mod mcp;
pub mod medias;
pub mod messagerie;
pub mod oauth_flux;
pub mod store;
pub mod tenants;

/// Les migrations embarquees : la base se pose toute seule au demarrage, comme
/// pour le runtime — un binaire qui exige un `psql -f` manuel est un binaire
/// qu'on deploie mal un jour.
pub static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let url = std::env::var("SOCIAL_DATABASE_URL")
        .context("SOCIAL_DATABASE_URL est obligatoire — base separee du runtime, a dessein")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .context("connexion a SOCIAL_DATABASE_URL")?;
    MIGRATIONS.run(&pool).await.context("migrations")?;

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("mint-tenant") {
        let label = args
            .get(2)
            .context("usage: agentos-social mint-tenant <label>")?;
        let jeton = tenants::frapper(&pool, label).await?;
        // Sur stdout et une seule fois : seul le SHA-256 survit en base.
        println!("{jeton}");
        return Ok(());
    }

    let clef = std::env::var("SOCIAL_MASTER_KEY").context(
        "SOCIAL_MASTER_KEY est obligatoire — sans elle aucun jeton de plateforme ne se scelle",
    )?;
    let bind = std::env::var("SOCIAL_BIND").unwrap_or_else(|_| "127.0.0.1:8791".into());
    let url_publique =
        std::env::var("SOCIAL_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind}"));
    // Le depot des octets vettes : le MEME Arc va aux adaptateurs (qui
    // deposent au debut de `publier`) et a l'Etat (dont la route publique
    // GET /medias/{digest} sert) — c'est la couture des modeles « pull »
    // (images Instagram, photos TikTok : la plateforme tire NOS octets
    // vettes, jamais l'URL du client).
    let depot = Arc::new(medias::DepotMedias::new());
    let ctx = adapters::ContexteAdaptateurs {
        base_publique: url_publique.clone(),
        depot: depot.clone(),
    };
    let etat = Arc::new(mcp::Etat {
        pool,
        // Meme derivation que crates/app/src/identity.rs::envelope : SHA-256
        // de la clef d'environnement vers les 32 octets d'AES-256. Generer la
        // clef (`openssl rand -base64 32`), ne pas la taper.
        chiffreur: Arc::new(agentos_providers::secrets::LocalEnvelopeSecretStore::new(
            Sha256::digest(clef.as_bytes()).into(),
        )),
        adaptateurs: adapters::adaptateurs(&ctx),
        // Le vrai téléchargeur : https seul, IP publiques seules, plafond
        // 512 MiB — la boucle locale n'est ouvrable QUE par le constructeur
        // de test, jamais d'ici ni d'une variable d'environnement.
        telechargeur: medias::Telechargeur::new(),
        url_publique,
        // Les credentials client OAuth, enregistres par le fondateur sur
        // chaque portail dev. Optionnels : sans eux le service sert (preview,
        // idempotence, historique) et account_connect_url explique ce qui
        // manque au lieu d'envoyer un humain consentir pour rien.
        oauth_x: credentiels_env("SOCIAL_X_CLIENT_ID", "SOCIAL_X_CLIENT_SECRET"),
        oauth_linkedin: credentiels_env(
            "SOCIAL_LINKEDIN_CLIENT_ID",
            "SOCIAL_LINKEDIN_CLIENT_SECRET",
        ),
        // META et pas INSTAGRAM, GOOGLE et pas YOUTUBE : les apps clientes
        // vivent sur developers.facebook.com et console.cloud.google.com —
        // nommer la variable d'apres la plateforme servie enverrait le
        // fondateur chercher un portail qui n'existe pas. La valeur TikTok
        // est le `client_key` du portail developers.tiktok.com.
        oauth_meta: credentiels_env("SOCIAL_META_CLIENT_ID", "SOCIAL_META_CLIENT_SECRET"),
        oauth_tiktok: credentiels_env("SOCIAL_TIKTOK_CLIENT_ID", "SOCIAL_TIKTOK_CLIENT_SECRET"),
        oauth_google: credentiels_env("SOCIAL_GOOGLE_CLIENT_ID", "SOCIAL_GOOGLE_CLIENT_SECRET"),
        depot,
        // La seconde surface — l'absence d'un adaptateur EST le refus, cite
        // (LinkedIn : linkedin::refus_messagerie).
        adaptateurs_messagerie: adapters::adaptateurs_messagerie(&ctx),
    });

    let ecoute = tokio::net::TcpListener::bind(&bind).await.context(bind)?;
    tracing::info!(adresse = %ecoute.local_addr()?, "agentos-social ecoute");
    axum::serve(ecoute, routeur(etat)).await?;
    Ok(())
}

/// Un couple client_id/client_secret d'environnement, ou rien — les deux ou
/// aucun : un seul des deux est une demi-configuration qu'on refuse de deviner.
fn credentiels_env(id: &str, secret: &str) -> Option<mcp::CredentielsClient> {
    match (std::env::var(id), std::env::var(secret)) {
        (Ok(client_id), Ok(client_secret)) => Some(mcp::CredentielsClient {
            client_id,
            client_secret: agentos_providers::Secret::new(client_secret),
        }),
        (Err(_), Err(_)) => None,
        _ => {
            tracing::warn!("{id}/{secret} : un seul des deux est pose — OAuth desactive");
            None
        }
    }
}

fn routeur(etat: Arc<mcp::Etat>) -> Router {
    Router::new()
        .route("/mcp", post(poste_mcp))
        .route("/mcp/messagerie", post(poste_mcp_messagerie))
        .route("/livez", get(|| async { "ok" }))
        .route("/oauth/callback", get(retour_oauth))
        .route("/medias/{digest}", get(servir_media))
        .with_state(etat)
}

/// GET /medias/{digest} — la route publique des modeles « pull ».
///
/// Publique SANS auth, et inoffensive par construction : elle ne sert que des
/// octets deja vettes et EN COURS de publication publique, adresses par leur
/// SHA-256 (2^256 n'est pas un espace qui s'enumere), entre le depot fait par
/// l'adaptateur et le `retirer` post-confirmation (ou le TTL d'une heure).
/// Un digest difforme est un 404 sans meme prendre le verrou du depot.
async fn servir_media(
    State(etat): State<Arc<mcp::Etat>>,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> Response {
    let bien_forme = digest.len() == 64
        && digest
            .bytes()
            .all(|o| o.is_ascii_hexdigit() && !o.is_ascii_uppercase());
    if !bien_forme {
        return StatusCode::NOT_FOUND.into_response();
    }
    match etat.depot.servir(&digest) {
        // Content-Type = le type detecte AUX OCTETS par le telechargeur ;
        // no-store : la fenetre de vie est le TTL du depot, pas celle d'un
        // cache intermediaire qui servirait un media apres son retrait.
        Some((octets, mime)) => (
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, "no-store"),
            ],
            axum::body::Bytes::from_owner(ArcOctets(octets)),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `Bytes::from_owner` veut un proprietaire `AsRef<[u8]>` : ce chapeau donne
/// cette vue a l'`Arc<Vec<u8>>` du depot — zero copie, meme pour une photo
/// TikTok de 20 MB que la plateforme tire plusieurs fois.
struct ArcOctets(Arc<Vec<u8>>);

impl AsRef<[u8]> for ArcOctets {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Les deux surfaces MCP du binaire — le transport et l'authentification sont
/// identiques, seule la table servie change.
enum Surface {
    Editeur,
    Messagerie,
}

/// POST /mcp — Streamable HTTP, forme JSON simple : un message JSON-RPC entre,
/// un message sort (ou 202 pour une notification). Pas de flux SSE : aucun de
/// nos outils ne progresse par etapes.
async fn poste_mcp(
    State(etat): State<Arc<mcp::Etat>>,
    en_tetes: HeaderMap,
    corps: String,
) -> Response {
    servir(etat, en_tetes, corps, Surface::Editeur).await
}

/// POST /mcp/messagerie — meme transport, meme auth Bearer tenant, SA table.
async fn poste_mcp_messagerie(
    State(etat): State<Arc<mcp::Etat>>,
    en_tetes: HeaderMap,
    corps: String,
) -> Response {
    servir(etat, en_tetes, corps, Surface::Messagerie).await
}

async fn servir(
    etat: Arc<mcp::Etat>,
    en_tetes: HeaderMap,
    corps: String,
    surface: Surface,
) -> Response {
    let autorisation = en_tetes
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(tenant) = tenants::authentifier(&etat.pool, autorisation).await else {
        // Meme corps pour « pas d'en-tete », « pas Bearer » et « jeton faux » :
        // la reponse ne dit pas ce qui a echoue, et la comparaison en dessous
        // est en temps constant.
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    };
    let Ok(req) = serde_json::from_str::<Value>(&corps) else {
        return Json(json!({
            "jsonrpc": "2.0", "id": null,
            "error": { "code": -32700, "message": "JSON illisible" }
        }))
        .into_response();
    };
    let rep = match surface {
        Surface::Editeur => mcp::traiter(&etat, tenant, &req).await,
        Surface::Messagerie => messagerie::traiter(&etat, tenant, &req).await,
    };
    match rep {
        Some(rep) => Json(rep).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// GET /oauth/callback — le retour du navigateur apres autorisation.
///
/// Le state (indevinable, a usage unique, quinze minutes, stocke en SHA-256
/// seulement) relie ce retour au tenant qui a appele account_connect_url. La
/// suite est oauth_flux de bout en bout : echange code -> jeton, puis
/// « qui est ce jeton ? » (GET /2/users/me chez X, GET /v2/userinfo chez
/// LinkedIn) — parce qu'un point de jeton ne rend que des jetons, et que la
/// ligne de compte a besoin d'un nom. Le jeton repart scelle sans jamais
/// toucher le disque en clair.
async fn retour_oauth(
    State(etat): State<Arc<mcp::Etat>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let refus = |pourquoi: &str| {
        (
            StatusCode::BAD_REQUEST,
            format!("Connexion refusee : {pourquoi}"),
        )
            .into_response()
    };
    if let Some(e) = params.get("error") {
        // La plateforme a dit non (acces refuse par l'humain, etc.).
        return refus(e);
    }
    let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
        return refus("code ou state absent");
    };
    // La table ne connait que le SHA-256 du state : on hache ce que le
    // navigateur presente, la comparaison est l'egalite de la cle primaire.
    let empreinte = oauth_flux::empreinte_state(state);
    let Ok(Some((tenant, plateforme, scelle))) =
        store::consommer_attente_oauth(&etat.pool, &oauth_flux::hex(&empreinte)).await
    else {
        return refus("state inconnu ou expire — relancer account_connect_url");
    };
    let tenant_id = agentos_domain::ids::TenantId::from_uuid(tenant);
    let Some((pf, credentiels)) = etat.oauth(&plateforme) else {
        return refus("plateforme sans credentials client");
    };

    let verificateur = match &scelle {
        None => None,
        Some(octets) => {
            match oauth_flux::ouvrir_verifieur(&etat.chiffreur, tenant_id, &empreinte, octets) {
                Ok(s) => Some(s),
                Err(_) => return refus("le verificateur PKCE ne s'ouvre pas"),
            }
        }
    };

    let jeton = match oauth_flux::echanger(
        pf,
        &credentiels.client_id,
        &credentiels.client_secret,
        &etat.redirect_uri(),
        code,
        verificateur.as_ref(),
    )
    .await
    {
        Ok(j) => j,
        Err(e) => return refus(&e.to_string()),
    };
    let (handle, id_plateforme) = match oauth_flux::identite(pf, &jeton.acces).await {
        Ok(h) => h,
        Err(e) => return refus(&format!("identite du compte introuvable : {e}")),
    };
    let Ok(scelle) = oauth_flux::sceller_jeton(
        &etat.chiffreur,
        tenant_id,
        &plateforme,
        &handle,
        &jeton.acces,
    ) else {
        return refus("le jeton n'a pas pu etre scelle");
    };
    // Le refresh de X (offline.access) se garde des maintenant : le perdre
    // couterait un re-consentement humain quand le rafraichissement sera cable.
    let refresh_scelle = jeton.rafraichissement.as_ref().and_then(|r| {
        oauth_flux::sceller_rafraichissement(&etat.chiffreur, tenant_id, &plateforme, &handle, r)
            .ok()
    });
    if store::connecter_compte(
        &etat.pool,
        tenant,
        &plateforme,
        &handle,
        Some(&id_plateforme),
        &scelle,
        refresh_scelle.as_deref(),
        // L'heure de mort annoncee du jeton : c'est elle que le
        // rafraichissement PROACTIF d'Instagram (mcp::jeton_frais) lit.
        Some(jeton.duree_s as i64),
    )
    .await
    .is_err()
    {
        return refus("le compte n'a pas pu etre enregistre");
    }
    Html(format!(
        "<p>Compte <b>{handle}</b> connecte sur {plateforme}. Vous pouvez fermer cet onglet.</p>"
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn etat_nu() -> Option<Arc<mcp::Etat>> {
        let pool = store::pool_de_test("main").await?;
        Some(Arc::new(mcp::Etat {
            pool,
            chiffreur: Arc::new(agentos_providers::secrets::LocalEnvelopeSecretStore::new(
                Sha256::digest("clef-de-test").into(),
            )),
            adaptateurs: Vec::new(),
            telechargeur: medias::Telechargeur::new(),
            url_publique: "http://127.0.0.1:0".into(),
            oauth_x: None,
            oauth_linkedin: None,
            oauth_meta: None,
            oauth_tiktok: None,
            oauth_google: None,
            depot: Arc::new(medias::DepotMedias::new()),
            adaptateurs_messagerie: Vec::new(),
        }))
    }

    fn requete_sur(chemin: &str, autorisation: Option<&str>) -> Request<Body> {
        let mut r = Request::post(chemin).header("content-type", "application/json");
        if let Some(a) = autorisation {
            r = r.header("authorization", a);
        }
        r.body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn un_jeton_faux_rend_401_et_un_vrai_rend_la_table() {
        let Some(etat) = etat_nu().await else { return };
        let jeton = tenants::frapper(&etat.pool, &format!("http-{}", uuid::Uuid::now_v7()))
            .await
            .unwrap();

        // Sans en-tete, avec un jeton invente, avec un schema non-Bearer :
        // 401, sans distinction.
        for mauvais in [
            None,
            Some("Bearer soc_0000000000000000000000000000000000000000000000000000000000000000"),
            Some("Basic abc"),
        ] {
            // La MEME porte sur les DEUX surfaces : un jeton qui ne passe pas
            // /mcp ne passe pas /mcp/messagerie non plus.
            for chemin in ["/mcp", "/mcp/messagerie"] {
                let rep = routeur(etat.clone())
                    .oneshot(requete_sur(chemin, mauvais))
                    .await
                    .unwrap();
                assert_eq!(
                    rep.status(),
                    StatusCode::UNAUTHORIZED,
                    "{chemin} {mauvais:?}"
                );
            }
        }

        let rep = routeur(etat.clone())
            .oneshot(requete_sur("/mcp", Some(&format!("Bearer {jeton}"))))
            .await
            .unwrap();
        assert_eq!(rep.status(), StatusCode::OK);
        let corps = axum::body::to_bytes(rep.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&corps).unwrap();
        assert_eq!(
            v["result"]["tools"].as_array().unwrap().len(),
            6,
            "les six outils, pas un de plus"
        );

        // Et la seconde surface sert SA table : les quatorze outils.
        let rep = routeur(etat.clone())
            .oneshot(requete_sur(
                "/mcp/messagerie",
                Some(&format!("Bearer {jeton}")),
            ))
            .await
            .unwrap();
        assert_eq!(rep.status(), StatusCode::OK);
        let corps = axum::body::to_bytes(rep.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&corps).unwrap();
        assert_eq!(
            v["result"]["tools"].as_array().unwrap().len(),
            14,
            "les quatorze outils messagerie, pas un de plus"
        );

        // /livez ne demande rien : c'est une sonde, pas une surface.
        let rep = routeur(etat)
            .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rep.status(), StatusCode::OK);
    }

    /// La route publique des octets vettes : les octets EXACTS du digest tant
    /// que l'entree vit, 404 pour tout le reste — digest inconnu, digest
    /// difforme (pas 64 hex minuscules), et apres `retirer`.
    #[tokio::test]
    async fn la_route_medias_sert_le_digest_vivant_et_404_tout_le_reste() {
        let Some(etat) = etat_nu().await else { return };
        let octets = medias::octets_png(b"octets pour instagram");
        let digest = medias::hex_sha256(&octets);
        etat.depot.deposer(
            &digest,
            Arc::new(octets.clone()),
            crate::adapters::TypeMedia::Png,
        );

        let get = |chemin: String| {
            let routeur = routeur(etat.clone());
            async move {
                routeur
                    .oneshot(Request::get(&chemin).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            }
        };

        // L'entree vivante : les octets exacts, le type detecte AUX octets,
        // no-store — et sans aucune authentification, c'est le contrat.
        let rep = get(format!("/medias/{digest}")).await;
        assert_eq!(rep.status(), StatusCode::OK);
        assert_eq!(rep.headers()["content-type"], "image/png");
        assert_eq!(rep.headers()["cache-control"], "no-store");
        let corps = axum::body::to_bytes(rep.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(corps.as_ref(), octets.as_slice());

        // Digest inconnu et digest difformes : 404, sans distinction.
        for mauvais in [
            "0".repeat(64),                 // inconnu
            "0".repeat(63),                 // trop court
            digest.to_uppercase(),          // hex majuscule
            format!("{}zz", &digest[..62]), // pas hex
        ] {
            let rep = get(format!("/medias/{mauvais}")).await;
            assert_eq!(rep.status(), StatusCode::NOT_FOUND, "{mauvais}");
        }

        // Apres retirer (la confirmation du conteneur plateforme) : plus rien.
        etat.depot.retirer(&digest);
        let rep = get(format!("/medias/{digest}")).await;
        assert_eq!(rep.status(), StatusCode::NOT_FOUND);
    }
}
