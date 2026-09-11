//! `POST /v1/prospects/import` : le fichier Smartlead du fondateur, déposé
//! depuis la console plutôt que copié dans le conteneur.
//!
//! [`crate::prospects`] (la sous-commande) explique pourquoi l'import a d'abord
//! été une commande et non une route, et nomme ce qui changerait la réponse :
//! « une console hébergée où le fondateur n'est pas l'opérateur et glisse un
//! CSV dans un navigateur ». C'est le cas depuis que la console porte une
//! session par locataire. Le corps de la route est le corps du fichier, en
//! `text/csv`, et tout le reste est [`agentos_app::prospects::import`] — la
//! même fonction que la sous-commande, avec les mêmes refus.
//!
//! Le locataire vient de [`Principal`] ; `accounts` et `contacts` sont sous RLS
//! forcée, donc un import n'écrit que des lignes que l'appelant possède déjà.
//!
//! `?dry_run=true` fait tout et annule la transaction : le rapport se lit avant
//! d'être vrai, ce que la console exige avant d'activer le bouton qui écrit.

use agentos_app::prospects::{self, ImportError, List, Report, SEGMENTS, UNKNOWN_COUNTRY};
use agentos_store::db::Db;
use agentos_store::revenue::RevenueError;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get as get_route, post as post_route};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiError;

/// Le plus gros fichier accepté.
///
/// ponytail: c'est [`crate::MAX_BODY_BYTES`], pas 10 Mo. La pile extérieure
/// borne déjà tout corps à ce chiffre et la couche d'idempotence le met en
/// mémoire entier ; la plus grosse liste du fondateur fait 141 Ko et les cinq
/// réunies 660 Ko. Lever ce plafond, c'est lever celui de toutes les routes.
const MAX_CSV_BYTES: usize = crate::MAX_BODY_BYTES;

/// This unit's routes.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/prospects/import", post_route(import))
        .route("/v1/prospects/segments", get_route(segments))
        .route("/v1/contacts", get_route(contacts))
        .layer(DefaultBodyLimit::max(MAX_CSV_BYTES))
        .with_state(db)
}

/// Combien de contacts une page rend quand l'appelant ne le dit pas, et au plus.
///
/// Les mêmes chiffres que `GET /v1/employees`, parce que c'est la même forme de
/// pagination et qu'un deuxième couple de bornes serait un deuxième à retenir.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
struct ImportQuery {
    segment: String,
    country: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

/// Une ligne refusée, telle que [`Report::refused`] la formule : `line N: …`.
#[derive(Debug, Serialize)]
struct ErrorView {
    line: Option<usize>,
    reason: String,
}

#[derive(Debug, Serialize)]
struct Counts {
    created: usize,
    existing: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<usize>,
}

/// Le [`Report`] de l'import, et rien qu'il ne compte vraiment.
#[derive(Debug, Serialize)]
struct ImportView {
    dry_run: bool,
    segment: String,
    country: String,
    rows: usize,
    accounts: Counts,
    contacts: Counts,
    /// Contacts sans prénom ni nom ; aucun n'a été inventé.
    nameless: usize,
    /// Téléphones hors E.164, non stockés.
    phones_dropped: usize,
    /// Lignes avec un `linkedin_profile`, qui n'a de colonne nulle part.
    linkedin_dropped: usize,
    /// Comptes créés avec le pays `ZZ`.
    unknown_country: usize,
    errors: Vec<ErrorView>,
}

impl ImportView {
    fn new(query: &ImportQuery, country: String, report: Report) -> Self {
        let errors = report
            .refused
            .into_iter()
            .map(|refused| {
                let parsed = refused
                    .strip_prefix("line ")
                    .and_then(|rest| rest.split_once(": "))
                    .and_then(|(n, reason)| Some((n.parse::<usize>().ok()?, reason.to_owned())));
                match parsed {
                    Some((line, reason)) => ErrorView {
                        line: Some(line),
                        reason,
                    },
                    None => ErrorView {
                        line: None,
                        reason: refused,
                    },
                }
            })
            .collect();
        Self {
            dry_run: query.dry_run,
            segment: query.segment.clone(),
            country,
            rows: report.rows,
            accounts: Counts {
                created: report.accounts_created,
                existing: report.accounts_existing,
                skipped: None,
            },
            contacts: Counts {
                created: report.contacts_created,
                existing: report.contacts_existing,
                skipped: Some(report.suppressed),
            },
            nameless: report.nameless,
            phones_dropped: report.phones_dropped,
            linkedin_dropped: report.linkedin_dropped,
            unknown_country: report.unknown_country,
            errors,
        }
    }
}

async fn import(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<ImportQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ImportView>, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let is_csv = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("text/csv"));
    if !is_csv {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "the body must be text/csv",
        ));
    }

    let body = body.map_err(|err| {
        if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "the file is too large",
            )
            .with_detail(format!("at most {MAX_CSV_BYTES} bytes"))
        } else {
            ApiError::bad_request(err.body_text())
        }
    })?;
    let text = String::from_utf8(body.to_vec()).map_err(|_| bad_csv("the file is not UTF-8"))?;

    let country = query
        .country
        .as_deref()
        .map_or(UNKNOWN_COUNTRY, str::trim)
        .to_ascii_uppercase();
    let list = List {
        segment: &query.segment,
        country: &country,
        employee_id: None,
    };

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let report = match prospects::import(&mut tx, &list, &text, Utc::now()).await {
        Ok(report) => report,
        Err(ImportError::Segment(_)) => {
            return Err(
                ApiError::new(StatusCode::BAD_REQUEST, "bad_segment", "unknown segment")
                    .with_detail(format!("one of {}", SEGMENTS.join(", "))),
            );
        }
        Err(ImportError::Country(_)) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_country",
                "country is not ISO 3166-1 alpha-2",
            )
            .with_detail(format!("two upper-case letters, or {UNKNOWN_COUNTRY}")));
        }
        Err(ImportError::Header(had)) => {
            return Err(bad_csv(format!(
                "expected header {}, got {had:?}",
                agentos_app::queue::COLUMNS[..8].join(",")
            )));
        }
        Err(ImportError::Store(RevenueError::Store(err))) => return Err(err.into()),
        Err(ImportError::Store(err)) => return Err(ApiError::bad_request(err.to_string())),
    };
    if query.dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    Ok(Json(ImportView::new(&query, country, report)))
}

fn bad_csv(detail: impl Into<String>) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "bad_csv",
        "this is not a Smartlead list",
    )
    .with_detail(detail)
}

/// `GET /v1/prospects/segments` : ce que la CHECK `accounts_segment` admet.
async fn segments(_principal: Principal) -> Json<serde_json::Value> {
    Json(json!({ "segments": SEGMENTS }))
}

// ---------------------------------------------------------------------------
// La liste — l'identifiant que l'import ne rendait pas
// ---------------------------------------------------------------------------

/// Pagination par clé, la même que `GET /v1/employees` : les identifiants sont
/// des UUIDv7, donc `id > after` veut dire « créé après ».
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    after: Option<uuid::Uuid>,
    #[serde(default)]
    limit: Option<i64>,
}

/// Une ligne de la liste.
///
/// **Pas de `phone`, et c'est délibéré** : cette lecture existe pour donner à un
/// terminal l'identifiant qu'il lui manque, pas pour exporter un carnet
/// d'adresses. L'adresse électronique y est parce qu'elle est la seule façon de
/// reconnaître une personne dans une liste que l'appelant vient d'importer
/// lui-même, et c'est déjà la clé d'unicité d'un contact.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct ContactRow {
    id: uuid::Uuid,
    account_id: uuid::Uuid,
    full_name: String,
    email: Option<String>,
    active: bool,
    last_contacted_at: Option<chrono::DateTime<Utc>>,
    next_follow_up_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

/// `GET /v1/contacts` — les contacts de cette entreprise, du plus ancien au
/// plus récent.
///
/// # Pourquoi cette route existe
///
/// Marché le 2026-09-11 depuis un terminal, par le serveur MCP et rien d'autre :
/// `POST /v1/sequences/{id}/enroll` réclame un `contact_id`, et **aucune route
/// de ce déploiement n'en rendait un**. `POST /v1/prospects/import` rend des
/// compteurs ; `POST /v1/employees/{id}/queue/export` rend un CSV dont les dix
/// colonnes sont celles de Smartlead et ne contiennent aucun identifiant ; il
/// n'y avait pas de `/v1/contacts`. Le deuxième des quatre gestes du plugin —
/// « de l'import d'une liste au premier envoi » — était donc impossible à
/// terminer, et un modèle qui essayait inventait un UUID et lisait un 404 qu'il
/// prenait pour sa propre faute.
///
/// L'import ne pouvait pas rendre ces identifiants lui-même : son premier appel
/// est un `dry_run` qui annule sa transaction, donc les lignes qu'il décrit
/// n'existent pas encore, et une liste de cent mille identifiants dans la
/// réponse d'un import serait une deuxième pagination à inventer.
///
/// Pas de `WHERE tenant_id` : la RLS l'ajoute, et l'écrire à la main serait un
/// deuxième endroit où l'oublier.
async fn contacts(
    State(db): State<Db>,
    principal: Principal,
    page: Result<Query<Page>, QueryRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Query(page) = page.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let limit = page.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<ContactRow> = sqlx::query_as(
        "SELECT id, account_id, full_name, email, active, last_contacted_at, \
                next_follow_up_at, created_at \
           FROM contacts \
          WHERE ($1::uuid IS NULL OR id > $1) \
          ORDER BY id \
          LIMIT $2",
    )
    .bind(page.after)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(agentos_store::db::StoreError::from)?;
    tx.rollback().await?;

    // Seule une page pleine peut avoir une suite. Une page courte termine la
    // marche sans coûter un aller-retour de plus.
    let next_after = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|last| last.id))
        .flatten();
    Ok(Json(json!({ "contacts": rows, "next_after": next_after })))
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REAL: &str =
        include_str!("../../../../crates/app/tests/fixtures/smartlead_getorizn_prospection.csv");

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; an import is a SQL question");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");
            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            secret: &str,
            content_type: &str,
            body: impl Into<Body>,
        ) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header(header::CONTENT_TYPE, content_type)
                .body(body.into())
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

        async fn import(&self, query: &str, secret: &str, csv: &str) -> (StatusCode, Value) {
            self.send(
                "POST",
                &format!("/v1/prospects/import?{query}"),
                secret,
                "text/csv; charset=utf-8",
                csv.to_owned(),
            )
            .await
        }

        async fn contacts(&self, tenant: TenantId) -> i64 {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query_scalar("SELECT count(*) FROM contacts")
                .fetch_one(&mut **tx)
                .await
                .expect("count")
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

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'import-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Le fichier du fondateur, importé pour de vrai, puis une seconde fois :
    /// la première crée, la seconde ne trouve que de l'existant. Et le voisin
    /// qui importe le même fichier crée tout : l'unicité est par locataire,
    /// donc la RLS tient.
    #[tokio::test]
    async fn the_real_file_is_imported_once_and_the_neighbour_sees_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.import("segment=other", SECRET_A, REAL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["dry_run"], Value::Bool(false));
        assert_eq!(body["country"], Value::String(UNKNOWN_COUNTRY.to_owned()));
        assert_eq!(body["rows"], Value::from(3));
        assert_eq!(body["accounts"]["created"], Value::from(3), "{body}");
        assert_eq!(body["contacts"]["created"], Value::from(3), "{body}");
        assert_eq!(body["contacts"]["skipped"], Value::from(0));
        assert_eq!(body["errors"], json!([]));
        assert_eq!(h.contacts(h.a).await, 3);

        let (status, again) = h.import("segment=other", SECRET_A, REAL).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["accounts"]["created"], Value::from(0));
        assert_eq!(again["accounts"]["existing"], Value::from(3));
        assert_eq!(again["contacts"]["existing"], Value::from(3));
        assert_eq!(h.contacts(h.a).await, 3);

        assert_eq!(h.contacts(h.b).await, 0, "B lit les contacts de A");
        let (status, theirs) = h.import("segment=other&country=ph", SECRET_B, REAL).await;
        assert_eq!(status, StatusCode::OK, "{theirs}");
        assert_eq!(theirs["country"], Value::String("PH".to_owned()));
        assert_eq!(theirs["accounts"]["created"], Value::from(3), "{theirs}");
        assert_eq!(h.contacts(h.b).await, 3);
        assert_eq!(h.contacts(h.a).await, 3);

        h.teardown().await;
    }

    /// **Le défaut mesuré le 2026-09-11.** `sequences_enroll` réclame un
    /// `contact_id` et rien de ce déploiement n'en rendait un : l'import rend
    /// des compteurs, le tirage de file rend les dix colonnes de Smartlead, et
    /// il n'y avait pas de liste. Un import suivi d'une lecture doit donner
    /// l'identifiant qu'un enrôlement recopie, et la pagination doit finir.
    #[tokio::test]
    async fn un_import_rend_ses_contacts_avec_leur_identifiant() {
        let Some(h) = Harness::new().await else {
            return;
        };
        h.import("segment=other", SECRET_A, REAL).await;

        let (status, body) = h
            .send("GET", "/v1/contacts", SECRET_A, "text/plain", "")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows = body["contacts"].as_array().expect("une liste");
        assert_eq!(rows.len(), 3, "{body}");
        assert!(
            rows.iter().all(|row| row["id"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())),
            "chaque ligne porte l'UUID que `sequences_enroll` recopie : {body}"
        );
        assert!(rows[0]["email"].is_string(), "{body}");
        assert!(
            body["next_after"].is_null(),
            "une page courte finit : {body}"
        );

        // La pagination, aux deux bornes : une page pleine porte sa suite.
        let (status, page) = h
            .send("GET", "/v1/contacts?limit=2", SECRET_A, "text/plain", "")
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["contacts"].as_array().expect("liste").len(), 2);
        let cursor = page["next_after"].as_str().expect("un curseur").to_owned();
        let (_, suite) = h
            .send(
                "GET",
                &format!("/v1/contacts?limit=2&after={cursor}"),
                SECRET_A,
                "text/plain",
                "",
            )
            .await;
        assert_eq!(suite["contacts"].as_array().expect("liste").len(), 1);
        assert!(suite["next_after"].is_null(), "{suite}");

        // Et les contacts d'une autre société ne sont pas filtrés, ils sont
        // invisibles.
        let (_, voisin) = h
            .send("GET", "/v1/contacts", SECRET_B, "text/plain", "")
            .await;
        assert_eq!(voisin["contacts"], json!([]), "{voisin}");

        h.teardown().await;
    }

    /// `dry_run` rend le rapport entier et n'écrit rien, y compris une ligne
    /// refusée avec son numéro.
    #[tokio::test]
    async fn a_dry_run_reports_everything_and_writes_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let csv = format!("{REAL}nobody@example.com,,,,,,,\r\n");
        let (status, body) = h
            .import("segment=relocation&dry_run=true", SECRET_A, &csv)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["dry_run"], Value::Bool(true));
        assert_eq!(body["rows"], Value::from(4));
        assert_eq!(body["accounts"]["created"], Value::from(3), "{body}");
        assert_eq!(body["errors"][0]["line"], Value::from(5), "{body}");
        assert!(
            body["errors"][0]["reason"]
                .as_str()
                .expect("reason")
                .contains("company_name"),
            "{body}"
        );
        assert_eq!(h.contacts(h.a).await, 0, "un essai a écrit");
        h.teardown().await;
    }

    /// Chaque refus a un nom, et aucun n'écrit.
    #[tokio::test]
    async fn every_refusal_is_named_and_writes_nothing() {
        let Some(h) = Harness::new().await else {
            return;
        };

        let (status, body) = h.import("segment=other", SECRET_A, "a,b\r\n1,2\r\n").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], Value::String("bad_csv".to_owned()));
        assert!(
            body["detail"]
                .as_str()
                .expect("detail")
                .contains("email,first_name,last_name,company_name"),
            "{body}"
        );

        let (status, body) = h.import("segment=airlines", SECRET_A, REAL).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], Value::String("bad_segment".to_owned()));

        let (status, body) = h
            .import("segment=other&country=France", SECRET_A, REAL)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], Value::String("bad_country".to_owned()));

        let (status, body) = h.import("dry_run=true", SECRET_A, REAL).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        let (status, body) = h
            .send(
                "POST",
                "/v1/prospects/import?segment=other",
                SECRET_A,
                "application/json",
                "{}",
            )
            .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");

        let big = vec![b'a'; MAX_CSV_BYTES + 1];
        let (status, body) = h
            .send(
                "POST",
                "/v1/prospects/import?segment=other",
                SECRET_A,
                "text/csv",
                big,
            )
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert_eq!(body["code"], Value::String("body_too_large".to_owned()));

        let (status, body) = h
            .send(
                "POST",
                "/v1/prospects/import?segment=other",
                "nope",
                "text/csv",
                REAL,
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

        assert_eq!(h.contacts(h.a).await, 0);
        h.teardown().await;
    }

    #[tokio::test]
    async fn the_segments_are_the_checks() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (status, body) = h
            .send("GET", "/v1/prospects/segments", SECRET_A, "text/plain", "")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["segments"], json!(SEGMENTS));
        h.teardown().await;
    }
}
