//! `/v1/domain` : le domaine d'envoi du locataire, posé depuis la console,
//! vérifié chez le fournisseur, et ses enregistrements DNS recopiés chez
//! Cloudflare en un appel.
//!
//! # Pourquoi une route, et pas une variable
//!
//! `AGENT_EMAIL_DOMAIN` était le domaine d'envoi de *tout* le déploiement,
//! et rien ne vérifiait qu'il existe chez le fournisseur : Orizn a tourné
//! cinq jours sur `agent-orizn.com`, un domaine que personne ne possède
//! (mesuré le 2026-09-10). Un deuxième client doit poser **son** domaine
//! lui-même, voir ce que le fournisseur lui demande, et savoir quand ses
//! sièges peuvent écrire. La variable reste, comme **défaut** du locataire
//! qui n'en nomme aucun — `config.rs` le dit — et
//! `agentos_app::sending_domain` porte la logique ; ce fichier n'est que la
//! porte.
//!
//! # Quatre gestes
//!
//! | Route | Réponse |
//! |---|---|
//! | `GET /v1/domain` | 404 `no_domain`, ou la ligne |
//! | `POST /v1/domain {domain}` | 201 la ligne ; 200 si c'était déjà celle-là ; 409 `another_domain` ; 409 `domain_taken` (un autre locataire) ; 400 `bad_domain` |
//! | `POST /v1/domain/verify` | 200 la ligne, relue chez le fournisseur ; réveille les sièges qui attendaient |
//! | `POST /v1/domain/dns {cloudflare_api_token}` | 200 `{posed, skipped, zone}` |
//!
//! La ligne : `{domain, provider, status, records: [{record, type, name,
//! value, priority?, ttl, status}], checked_at, verified_at}`. `records` est
//! ce que le fournisseur a répondu, tel quel — la console l'affiche, `dns`
//! le pose. Le MX de réception n'y est pas tant que la réception n'est pas
//! activée chez le fournisseur ; `dns` le dérive de la région
//! (`docs/PROVIDERS.md` §Resend).
//!
//! # Le jeton Cloudflare
//!
//! Lu dans le corps, enveloppé dans un [`Secret`] à la ligne suivante,
//! passé au client HTTP, et mort avec la réponse. Aucune colonne ne l'attend,
//! aucune ligne de log ne le porte — le test `the_token_is_used_once_and_never_logged`
//! capture tout ce que `tracing` émet pendant l'appel et cherche les octets.
//! Un rejet de corps est rendu avec un texte fixe plutôt que le message de
//! serde, qui cite parfois la valeur qu'il n'a pas comprise.
//!
//! # `Hiring`
//!
//! Les trois routes qui embauchent (`POST /v1/org`, `POST /v1/companies`,
//! `POST /v1/employees`) ont besoin de la même chose que celles-ci : le
//! fournisseur email pour enregistrer un domaine au passage, et le domaine
//! par défaut. [`Hiring`] est cet état, un pour les quatre routeurs ;
//! `FromRef<Hiring> for Db` fait que chaque handler existant qui ne veut que
//! la base continue de demander `State<Db>`.

use std::sync::Arc;

use agentos_app::effects::Ports;
use agentos_app::inbound::Secret;
use agentos_app::mocks::ProviderError;
use agentos_app::sending_domain::{self, Refusal, Row};
use agentos_store::db::Db;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::error::ApiError;

/// Ce qu'une route qui mint une adresse tient en plus de la base.
#[derive(Clone)]
pub struct Hiring {
    pub db: Db,
    /// Le fournisseur email est `ports.email` ; le reste voyage avec parce
    /// que le binaire ne peut pas nommer `Arc<dyn EmailProvider>` seul.
    pub ports: Arc<Ports>,
    /// `AGENT_EMAIL_DOMAIN` : le domaine d'un locataire qui n'en nomme aucun.
    pub default_domain: String,
    /// L'origine de l'API Cloudflare ; un faux serveur dans les tests.
    pub cloudflare_api: String,
}

impl FromRef<Hiring> for Db {
    fn from_ref(hiring: &Hiring) -> Db {
        hiring.db.clone()
    }
}

impl Hiring {
    /// Tous les faux, le domaine des tests, la vraie API Cloudflare que rien
    /// n'appelle.
    #[cfg(test)]
    pub(crate) fn for_tests(db: Db) -> Self {
        Self {
            db,
            ports: Arc::new(agentos_app::mocks::ports()),
            default_domain: "agents.example.com".to_owned(),
            cloudflare_api: sending_domain::CLOUDFLARE_API.to_owned(),
        }
    }

    /// Le domaine qu'un locataire de test possède : dérivé de son id, parce
    /// que `tenant_domains.domain` est unique dans toute la base et que les
    /// tests d'un binaire la partagent — deux harnais qui embaucheraient sur
    /// `agents.example.com` se refuseraient l'un l'autre, à raison.
    #[cfg(test)]
    pub(crate) fn domain_of(tenant: agentos_domain::ids::TenantId) -> String {
        format!("{}.example.com", tenant.as_uuid().simple())
    }

    /// Donne à `tenant` son domaine ([`Hiring::domain_of`]), vérifié sur
    /// le champ par le faux fournisseur, pour qu'un corps sans `domain`
    /// embauche dessus.
    #[cfg(test)]
    pub(crate) async fn adopt(&self, tenant: agentos_domain::ids::TenantId) -> String {
        let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
        let row = sending_domain::register(&mut tx, &*self.ports.email, &Self::domain_of(tenant))
            .await
            .expect("register the tenant's domain");
        tx.commit().await.expect("commit");
        row.domain
    }
}

pub fn router(hiring: Hiring) -> Router {
    Router::new()
        .route("/v1/domain", get_route(get).post(register))
        .route("/v1/domain/verify", post(verify))
        .route("/v1/domain/dns", post(dns))
        .with_state(hiring)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    domain: String,
}

/// Pas de `Debug`, exprès : le seul champ est un jeton.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsBody {
    cloudflare_api_token: String,
}

async fn get(State(hiring): State<Hiring>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = hiring.db.tenant_tx(principal.tenant_id).await?;
    let row = sending_domain::current(&mut tx).await?;
    tx.rollback().await?;
    match row {
        Some(row) => Ok((StatusCode::OK, Json(view(&row))).into_response()),
        None => Err(no_domain()),
    }
}

async fn register(
    State(hiring): State<Hiring>,
    principal: Principal,
    body: Result<Json<RegisterBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let mut tx = hiring.db.tenant_tx(principal.tenant_id).await?;
    let had = sending_domain::current(&mut tx).await?;
    let row = sending_domain::register(&mut tx, &*hiring.ports.email, &body.domain)
        .await
        .map_err(refused)?;
    tx.commit().await?;
    let status = if had.is_some() {
        StatusCode::OK
    } else {
        tracing::info!(
            tenant_id = %principal.tenant_id,
            domain = %row.domain,
            provider = %row.provider,
            status = row.status.as_str(),
            "sending domain registered"
        );
        StatusCode::CREATED
    };
    Ok((status, Json(view(&row))).into_response())
}

async fn verify(State(hiring): State<Hiring>, principal: Principal) -> Result<Response, ApiError> {
    let mut tx = hiring.db.tenant_tx(principal.tenant_id).await?;
    let row = sending_domain::verify(&mut tx, &*hiring.ports.email)
        .await
        .map_err(refused)?;
    tx.commit().await?;
    tracing::info!(
        tenant_id = %principal.tenant_id,
        domain = %row.domain,
        status = row.status.as_str(),
        "sending domain checked"
    );
    Ok((StatusCode::OK, Json(view(&row))).into_response())
}

async fn dns(
    State(hiring): State<Hiring>,
    principal: Principal,
    body: Result<Json<DnsBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    // Un texte fixe : le message de serde cite parfois la valeur refusée.
    let Json(body) = body.map_err(|_| {
        ApiError::bad_request("body must be {\"cloudflare_api_token\": \"<token>\"}")
    })?;
    let token = Secret::new(body.cloudflare_api_token);
    let mut tx = hiring.db.tenant_tx(principal.tenant_id).await?;
    let posed = sending_domain::pose_dns(&mut tx, token, &hiring.cloudflare_api)
        .await
        .map_err(refused)?;
    tx.rollback().await?;
    tracing::info!(
        tenant_id = %principal.tenant_id,
        posed = posed.posed,
        skipped = posed.skipped,
        zone = %posed.zone,
        "dns records posed"
    );
    Ok((StatusCode::OK, Json(json!(posed))).into_response())
}

/// La ligne, sur le fil. `records` passe par la sérialisation de
/// `DnsRecord`, où `kind` s'écrit `type`.
fn view(row: &Row) -> Value {
    json!({
        "domain": row.domain,
        "provider": row.provider,
        "status": row.status.as_str(),
        "records": row.records,
        "checked_at": row.checked_at,
        "verified_at": row.verified_at,
    })
}

fn no_domain() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "no_domain",
        "this tenant has no sending domain yet",
    )
}

/// Un refus de `sending_domain`, en statut et en code — partagé avec les
/// routes qui embauchent, pour qu'un domaine refusé ait le même nom partout.
pub(crate) fn refused(err: Refusal) -> ApiError {
    match err {
        Refusal::BadDomain(detail) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_domain",
            "not a sending domain",
        )
        .with_detail(detail),
        Refusal::AnotherDomain { current } => ApiError::conflict(
            "another_domain",
            "this tenant already sends from another domain",
        )
        .with_extension("current", json!(current)),
        Refusal::DomainTaken => ApiError::conflict(
            "domain_taken",
            "another tenant already sends from this domain",
        ),
        Refusal::NoDomain => no_domain(),
        // Le fournisseur a dit non à quelque chose que le client contrôle
        // (jeton refusé, zone introuvable, domaine rejeté) : son mot, en 422.
        Refusal::Provider(ProviderError::Terminal { code }) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "the provider refused",
        ),
        Refusal::Provider(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
            "the provider did not answer; try again",
        ),
        Refusal::Store(err) => err.into(),
    }
}

// ---------------------------------------------------------------------------
// Tests — with a database, and a loopback Cloudflare.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::sync::Mutex;

    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::extract::Path;
    use axum::http::{HeaderMap, Request as HttpRequest, header};
    use chrono::Utc;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TOKEN: &str = "cf_route_token_MUST_NOT_APPEAR_IN_LOGS";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
        cloudflare: Arc<Mutex<Vec<Value>>>,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; a sending domain is a row");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let a = tenant(&db).await;
            let b = tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            let (cloudflare_api, cloudflare) = fake_cloudflare().await;
            let hiring = Hiring {
                cloudflare_api,
                ..Hiring::for_tests(db.clone())
            };
            Some(Self {
                app: crate::with_api_stack(
                    router(hiring),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
                cloudflare,
            })
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"));
            let req = match body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            }
            .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
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

    async fn tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'domain-route')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Un nom par test : `tenant_domains.domain` est unique dans toute la
    /// base, et les tests d'un binaire la partagent.
    fn unique() -> String {
        format!("agents-{}.getorizn.com", Uuid::now_v7().simple())
    }

    /// Un Cloudflare de poche : une zone, `getorizn.com`, vide ; chaque
    /// `POST` est gardé, et le jeton est exigé.
    async fn fake_cloudflare() -> (String, Arc<Mutex<Vec<Value>>>) {
        let posted: Arc<Mutex<Vec<Value>>> = Arc::default();
        let app = Router::new()
            .route("/zones", get_route(zones))
            .route("/zones/{id}/dns_records", get_route(records).post(create))
            .with_state(posted.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (base, posted)
    }

    fn bearer_ok(headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {TOKEN}"))
    }

    async fn zones(
        headers: HeaderMap,
        axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    ) -> (StatusCode, Json<Value>) {
        if !bearer_ok(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        let hits: Vec<Value> = (q.get("name").map(String::as_str) == Some("getorizn.com"))
            .then(|| json!({"id": "zone_1", "name": "getorizn.com"}))
            .into_iter()
            .collect();
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": hits})),
        )
    }

    async fn records(
        State(posted): State<Arc<Mutex<Vec<Value>>>>,
        headers: HeaderMap,
        Path(_id): Path<String>,
    ) -> (StatusCode, Json<Value>) {
        if !bearer_ok(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        let rows = posted.lock().expect("not poisoned").clone();
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": rows})),
        )
    }

    async fn create(
        State(posted): State<Arc<Mutex<Vec<Value>>>>,
        headers: HeaderMap,
        Path(_id): Path<String>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if !bearer_ok(&headers) {
            return (StatusCode::FORBIDDEN, Json(json!({"success": false})));
        }
        posted.lock().expect("not poisoned").push(body.clone());
        (
            StatusCode::OK,
            Json(json!({"success": true, "result": body})),
        )
    }

    /// Tout ce que `tracing` émet pendant un appel, champs compris, rendu en
    /// texte — pour chercher des octets qui ne doivent pas y être.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<String>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Render<'a>(&'a mut String);
            impl tracing::field::Visit for Render<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    let _ = write!(self.0, "{}={:?} ", field.name(), value);
                }
            }
            let mut out = self.0.lock().expect("not poisoned");
            let _ = write!(out, "[{}] ", event.metadata().target());
            event.record(&mut Render(&mut out));
            out.push('\n');
        }
    }

    #[tokio::test]
    async fn no_domain_then_register_then_read_back_and_the_other_tenant_sees_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let name = unique();

        let (status, body) = h.send("GET", "/v1/domain", SECRET_A, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], "no_domain");

        let (status, body) = h
            .send(
                "POST",
                "/v1/domain",
                SECRET_A,
                Some(json!({"domain": name})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["domain"], name);
        assert_eq!(body["provider"], "mock-email");
        assert_eq!(body["status"], "verified", "the mock verifies on sight");
        assert_eq!(
            body["records"][0]["type"], "TXT",
            "the wire says `type`, not `kind`"
        );
        assert_eq!(body["records"][0]["record"], "DKIM");
        assert!(
            body["records"][0].get("priority").is_none(),
            "no priority on a TXT"
        );
        assert!(body["checked_at"].is_string() && body["verified_at"].is_string());

        let (status, read) = h.send("GET", "/v1/domain", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read, body);

        // The same domain again: nothing created, the same row, a 200.
        let (status, again) = h
            .send(
                "POST",
                "/v1/domain",
                SECRET_A,
                Some(json!({"domain": name})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again, body);

        // Another domain: another story. A bad one: a 400 with its name.
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain",
                SECRET_A,
                Some(json!({"domain": unique()})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "another_domain");
        assert_eq!(body["current"], name);
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain",
                SECRET_A,
                Some(json!({"domain": "localhost"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "bad_domain");

        // Tenant B: RLS — no domain, and A's name is taken.
        let (status, body) = h.send("GET", "/v1/domain", SECRET_B, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain",
                SECRET_B,
                Some(json!({"domain": name})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "domain_taken");

        // Verify reads the provider again and answers the same shape.
        let (status, body) = h.send("POST", "/v1/domain/verify", SECRET_A, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "verified");
        let (status, body) = h.send("POST", "/v1/domain/verify", SECRET_B, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        h.teardown().await;
    }

    /// Les enregistrements — ceux du fournisseur, plus le MX de réception
    /// dérivé de la région — sont posés dans la zone `getorizn.com`, et le
    /// jeton n'apparaît dans aucune ligne de log.
    #[tokio::test]
    async fn dns_poses_the_records_on_cloudflare_and_the_token_is_used_once_and_never_logged() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let name = unique();
        h.send(
            "POST",
            "/v1/domain",
            SECRET_A,
            Some(json!({"domain": name})),
        )
        .await;

        // Without a domain: 404, and nothing reached Cloudflare.
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain/dns",
                SECRET_B,
                Some(json!({"cloudflare_api_token": TOKEN})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(h.cloudflare.lock().expect("not poisoned").is_empty());

        let captured = Captured::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain/dns",
                SECRET_A,
                Some(json!({"cloudflare_api_token": TOKEN})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({"posed": 2, "skipped": 0, "zone": "getorizn.com"})
        );
        let posted = h.cloudflare.lock().expect("not poisoned").clone();
        assert_eq!(posted[0]["type"], "TXT");
        assert_eq!(posted[0]["name"], format!("mock._domainkey.{name}"));
        assert_eq!(
            posted[0]["content"], "\"p=MOCK\"",
            "TXT quoted as Cloudflare wants it"
        );
        assert_eq!(posted[0]["proxied"], false);
        assert_eq!(posted[0]["ttl"], 1);
        assert_eq!(
            posted[1]["type"], "MX",
            "the inbound MX, derived from the region"
        );
        assert_eq!(posted[1]["name"], name);
        assert_eq!(posted[1]["content"], "inbound-smtp.eu-west-1.amazonaws.com");
        assert_eq!(posted[1]["priority"], 10);

        // A second click: everything is there.
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain/dns",
                SECRET_A,
                Some(json!({"cloudflare_api_token": TOKEN})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["posed"], 0);
        assert_eq!(body["skipped"], 2);

        // A wrong token is the provider's word, in a 422 — and not ours.
        let (status, body) = h
            .send(
                "POST",
                "/v1/domain/dns",
                SECRET_A,
                Some(json!({"cloudflare_api_token": "cf_wrong"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["code"], "cloudflare_token_refused");

        let log = captured.0.lock().expect("not poisoned").clone();
        assert!(
            log.contains("dns records posed"),
            "the capture saw nothing, so it proves nothing:\n{log}"
        );
        assert!(!log.contains(TOKEN), "the token reached a log line:\n{log}");
        assert!(
            !log.contains("cf_wrong"),
            "the refused token reached a log line:\n{log}"
        );

        h.teardown().await;
    }
}
