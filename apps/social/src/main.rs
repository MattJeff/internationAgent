//! agentos-social — l'agregateur de publication sociale concu pour des agents.
//!
//! Le seul du catalogue ou `OptOuts::NoStrangers` est vrai PAR CONSTRUCTION :
//! aucune surface DM (le test anti-DM de mcp.rs le prouve en lisant la table
//! d'outils), idempotence en base, previsualisation avec empreinte, table
//! d'outils versionnee.
//!
//! Deux modes :
//!   agentos-social                      — sert POST /mcp, GET /livez, GET /oauth/callback
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
    let etat = Arc::new(mcp::Etat {
        pool,
        // Meme derivation que crates/app/src/identity.rs::envelope : SHA-256
        // de la clef d'environnement vers les 32 octets d'AES-256. Generer la
        // clef (`openssl rand -base64 32`), ne pas la taper.
        chiffreur: Arc::new(agentos_providers::secrets::LocalEnvelopeSecretStore::new(
            Sha256::digest(clef.as_bytes()).into(),
        )),
        adaptateurs: adapters::adaptateurs(),
        // Le vrai téléchargeur : https seul, IP publiques seules, plafond
        // 512 MiB — la boucle locale n'est ouvrable QUE par le constructeur
        // de test, jamais d'ici ni d'une variable d'environnement.
        telechargeur: medias::Telechargeur::new(),
        url_publique: std::env::var("SOCIAL_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://{bind}")),
        // Les credentials client OAuth, enregistres par le fondateur sur
        // chaque portail dev. Optionnels : sans eux le service sert (preview,
        // idempotence, historique) et account_connect_url explique ce qui
        // manque au lieu d'envoyer un humain consentir pour rien.
        oauth_x: credentiels_env("SOCIAL_X_CLIENT_ID", "SOCIAL_X_CLIENT_SECRET"),
        oauth_linkedin: credentiels_env(
            "SOCIAL_LINKEDIN_CLIENT_ID",
            "SOCIAL_LINKEDIN_CLIENT_SECRET",
        ),
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
        .route("/livez", get(|| async { "ok" }))
        .route("/oauth/callback", get(retour_oauth))
        .with_state(etat)
}

/// POST /mcp — Streamable HTTP, forme JSON simple : un message JSON-RPC entre,
/// un message sort (ou 202 pour une notification). Pas de flux SSE : aucun de
/// nos six outils ne progresse par etapes.
async fn poste_mcp(
    State(etat): State<Arc<mcp::Etat>>,
    en_tetes: HeaderMap,
    corps: String,
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
    match mcp::traiter(&etat, tenant, &req).await {
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
    let handle = match oauth_flux::identite(pf, &jeton.acces).await {
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
        &scelle,
        refresh_scelle.as_deref(),
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
        }))
    }

    fn requete_mcp(autorisation: Option<&str>) -> Request<Body> {
        let mut r = Request::post("/mcp").header("content-type", "application/json");
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
            let rep = routeur(etat.clone())
                .oneshot(requete_mcp(mauvais))
                .await
                .unwrap();
            assert_eq!(rep.status(), StatusCode::UNAUTHORIZED, "{mauvais:?}");
        }

        let rep = routeur(etat.clone())
            .oneshot(requete_mcp(Some(&format!("Bearer {jeton}"))))
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

        // /livez ne demande rien : c'est une sonde, pas une surface.
        let rep = routeur(etat)
            .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rep.status(), StatusCode::OK);
    }
}
