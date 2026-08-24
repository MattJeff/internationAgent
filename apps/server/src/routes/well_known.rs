//! `GET /.well-known/http-message-signatures-directory`: the public keys a
//! counterparty verifies our signatures with.
//!
//! # Public and unauthenticated, which is the entire point
//!
//! A verifier is by definition somebody we have no relationship with. They
//! received a signed A2A request or a signed message, they have a `kid`, and
//! they need the key. A key directory behind an API key is a key directory
//! nobody can use, in exactly the way an agent card behind an API key is — see
//! [`crate::routes::a2a`], which mounts for the same reason on the same tier.
//!
//! So this router goes **outside** `with_api_stack`, and every line below is
//! written on the assumption that the caller is hostile.
//!
//! # What it can leak, which is nothing but public keys
//!
//! Three layers, in order, and none of them is "the handler is careful":
//!
//! 1. **The query cannot fetch the private half.**
//!    [`agentos_store::signing::published_keys`] selects `public_key` and
//!    nothing else. `sealed_private_key` is not in the projection, not in the
//!    row type, and not in any value reachable from here.
//! 2. **The document type cannot hold anything else.**
//!    [`agentos_domain::identity::jwks`] takes `PublicKey` values — 32 bytes,
//!    no other fields — so the response is structurally incapable of carrying
//!    a slug, an address, a lifecycle or a tenant id. A JWKS with a seventh
//!    member is a compile error, not a review catch.
//! 3. **Row-level security bounds the read to one tenant.** See below.
//!
//! It deliberately does *not* echo the employee's name, address or
//! capabilities. That is the agent card's job, the agent card is a separate
//! document a peer asks for on purpose, and merging them would mean every
//! verifier fetch also hands out a profile.
//!
//! # How a verifier knows which tenant a key belongs to
//!
//! **It does not, and it must not need to.** `PUBLIC_HOST` is one origin
//! serving many tenants, so the host answers nothing on its own. The binding a
//! verifier actually relies on is the one it already has: it fetched *this
//! URL* because our signature told it to, and the document at this URL lists
//! the keys that URL vouches for. That is the same trust model as Web Bot
//! Auth's directory and as `did:web` — the URL is the identifier, and the key
//! set is what the identifier attests to. Adding a `tenant` field to the
//! document would not strengthen it by one bit: a document that names its own
//! tenant is a document that could name any tenant.
//!
//! What has to be true, then, is that the URL is unambiguous and that the
//! document behind it can only ever contain the right tenant's keys. Both are:
//!
//! * **The URL is scoped by `?employee=<uuid>`**, exactly the selector
//!   [`crate::routes::a2a`] already puts in the agent card's interface URL, and
//!   resolved by the same [`crate::routes::a2a::discover`] — one rule for
//!   "which employee is this endpoint about", not two that can drift. As there,
//!   the parameter is optional and a single-employee deployment may omit it;
//!   a deployment with more than one employee answers 400 rather than guessing.
//! * **The tenant is derived from the employee, never from the request.** The
//!   handler resolves employee → tenant, then opens `tenant_tx` for *that*
//!   tenant, and the RLS policy in `0013_identity.sql` makes every other
//!   tenant's rows invisible for the life of the transaction. A caller cannot
//!   name a tenant, so a caller cannot widen the document.
//!
//! Scoped to an employee rather than to a whole tenant on purpose. A
//! tenant-wide directory would let anyone holding one employee's URL enumerate
//! every colleague — headcount, ids and hiring rate, from an unauthenticated
//! endpoint. A verifier only ever needs the key that signed the thing in front
//! of it.
//!
//! # Leaving the did:web door open
//!
//! `/.well-known/did.json` over these same rows is a second rendering of
//! [`agentos_domain::identity::PublicKey`] and would be another handler in this
//! file — the storage, the scoping and the tenant resolution are already
//! whatever it would need. It is not built, because nothing has asked for it
//! and the DID crates are not worth depending on; see
//! `agentos_domain::identity`.
//!
//! ponytail: no `Cache-Control`. The correct max-age depends on how fast an
//! operator expects a suspension to take effect — publication is
//! lifecycle-gated, so suspending an employee withdraws its key — and that is a
//! deployment decision for the ingress proxy, which is also the thing that
//! should be absorbing this traffic.

// `DIRECTORY_PATH` is the path Cloudflare's Web Bot Auth directory uses, and
// the reason this module exists rather than a `did:web` one. It is a literal in
// the domain crate, never assembled from a prefix — a well-known path built out
// of parts is a well-known path somebody eventually re-prefixes — and it lives
// there rather than here because it is now read from both ends:
// `agentos_app::peer_keys` fetches a *peer's* directory at the same path, and
// two spellings of it would be two protocols.
use agentos_domain::identity::{DIRECTORY_PATH, PublicKey, jwks};
use agentos_store::db::Db;
use agentos_store::signing;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::error::ApiError;
use crate::routes::a2a::Which;

/// The media type the directory draft specifies. It is a JWKS, so
/// `application/json` would parse everywhere, but a verifier that content-type
/// checks is a verifier we would otherwise fail for no reason.
const MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";

/// The directory, at the root. Merge this **outside** the API stack — see the
/// module docs.
pub fn router(db: Db) -> Router {
    Router::new()
        .route(DIRECTORY_PATH, get(directory))
        .with_state(db)
}

/// The selector is [`Which`] itself, not a copy of it: the agent card and this
/// directory must not disagree about how an employee is named in a URL.
async fn directory(State(db): State<Db>, Query(which): Query<Which>) -> Result<Response, ApiError> {
    let (tenant_id, employee_id) = crate::routes::a2a::discover(&db, which.employee()).await?;

    // From here on the transaction is pinned to the tenant that owns the
    // employee, and RLS is what keeps the answer inside it.
    let mut tx = db.tenant_tx(tenant_id).await?;
    let published = signing::published_keys(&mut tx, employee_id).await?;
    tx.commit().await?;

    // An employee with no published key has no verifiable identity, and
    // handing a verifier an empty key set would have it conclude "signed by a
    // key I cannot find" — which is what it should conclude, but a 404 says it
    // in one round trip. Same call the agent card makes for an unprovisioned
    // A2A step, and the same status as "no such employee", deliberately: a
    // stranger learns nothing about which of the two it is.
    if published.is_empty() {
        return Err(ApiError::not_found());
    }

    let keys = published
        .iter()
        .map(|bytes| PublicKey::from_slice(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            // The column has a length check, so this is a corrupt row rather
            // than a caller's problem. Nothing about it goes on the wire.
            tracing::error!(error = %err, %employee_id, "stored public key is not an Ed25519 key");
            ApiError::internal()
        })?;

    Ok(([(header::CONTENT_TYPE, MEDIA_TYPE)], axum::Json(jwks(keys))).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_store::signing::StoredKey;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use chrono::Utc;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// Recognisable, and not a valid key by accident: 32 bytes of one value.
    const PUBLIC: [u8; 32] = [0x2b; 32];
    /// What must never appear in a response. Long and distinctive on purpose.
    const SEALED: &[u8] = b"SEALED-PRIVATE-KEY-MATERIAL-THAT-MUST-NEVER-BE-SERVED-0123456789";

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the key directory needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant with one employee that already has a key.
    async fn seed(db: &Db, lifecycle: &str, public_key: [u8; 32]) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let (tenant, employee) = (TenantId::new_v7(now), EmployeeId::new_v7(now));

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().simple().to_string())
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid().simple().to_string())
        .bind(lifecycle)
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        signing::ensure(
            &mut tx,
            tenant,
            employee,
            &StoredKey {
                public_key: public_key.to_vec(),
                sealed_private_key: SEALED.to_vec(),
            },
        )
        .await
        .expect("key");
        tx.commit().await.expect("commit");

        (tenant, employee)
    }

    async fn fetch(db: &Db, employee: EmployeeId) -> (StatusCode, String, String) {
        let response = router(db.clone())
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("{DIRECTORY_PATH}?employee={}", employee.as_uuid()))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (
            status,
            content_type,
            String::from_utf8(body.to_vec()).expect("utf8"),
        )
    }

    // -- the tests ---------------------------------------------------------

    #[tokio::test]
    async fn the_directory_serves_one_jwk_and_nothing_else_about_the_employee() {
        let Some(db) = db().await else { return };
        let (_, employee) = seed(&db, "active", PUBLIC).await;

        let (status, content_type, body) = fetch(&db, employee).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, MEDIA_TYPE);

        let document: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(document.as_object().expect("object").len(), 1, "{body}");
        let keys = document["keys"].as_array().expect("key set");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["use"], "sig");
        assert_eq!(keys[0]["x"], B64URL.encode(PUBLIC));
        assert_eq!(keys[0]["kid"], PublicKey::new(PUBLIC).key_id().as_str());
        assert_eq!(keys[0].as_object().expect("object").len(), 6);

        // Nothing identifying rides along. Each of these is a real leak if it
        // ever appears: an unauthenticated endpoint is not the place to publish
        // the org chart.
        for forbidden in [
            "tenant",
            "employee",
            "slug",
            "lifecycle",
            "address",
            "sealed",
        ] {
            assert!(
                !body.to_lowercase().contains(forbidden),
                "{forbidden:?} appeared in the public directory: {body}"
            );
        }
    }

    /// The one that matters: the private half is not in the response in any
    /// encoding.
    #[tokio::test]
    async fn the_sealed_private_key_is_in_the_row_and_not_in_the_response() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active", PUBLIC).await;

        let (_, _, body) = fetch(&db, employee).await;
        let raw = String::from_utf8(SEALED.to_vec()).expect("ascii");
        for needle in [
            raw.clone(),
            B64URL.encode(SEALED),
            base64::engine::general_purpose::STANDARD.encode(SEALED),
            SEALED
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            format!("{SEALED:?}"),
        ] {
            assert!(
                !body.contains(&needle),
                "the sealed key leaked as {needle:?}"
            );
        }

        // ...and it really is in the row, so the assertions above are not
        // passing because there was nothing to leak.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            signing::load(&mut tx, employee)
                .await
                .expect("load")
                .sealed_private_key,
            SEALED
        );
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn one_tenants_url_never_serves_anothers_key() {
        let Some(db) = db().await else { return };
        let (_, mine) = seed(&db, "active", PUBLIC).await;
        let (_, theirs) = seed(&db, "active", [0x7f; 32]).await;

        let (_, _, my_body) = fetch(&db, mine).await;
        let (_, _, their_body) = fetch(&db, theirs).await;

        // Two employees in two tenants, two documents, one key each, and
        // neither contains the other's.
        assert!(my_body.contains(&B64URL.encode(PUBLIC)));
        assert!(!my_body.contains(&B64URL.encode([0x7fu8; 32])));
        assert!(their_body.contains(&B64URL.encode([0x7fu8; 32])));
        assert!(!their_body.contains(&B64URL.encode(PUBLIC)));
    }

    #[tokio::test]
    async fn suspending_an_employee_withdraws_its_published_key() {
        let Some(db) = db().await else { return };

        for lifecycle in ["draft", "suspended", "terminated"] {
            let (_, employee) = seed(&db, lifecycle, PUBLIC).await;
            let (status, ..) = fetch(&db, employee).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "a {lifecycle} employee must not publish a key"
            );
        }
    }

    #[tokio::test]
    async fn an_employee_with_no_key_and_an_unknown_employee_are_indistinguishable() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "active", PUBLIC).await;

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        signing::delete(&mut tx, employee).await.expect("delete");
        tx.commit().await.expect("commit");

        let (no_key, ..) = fetch(&db, employee).await;
        let (unknown, ..) = fetch(&db, EmployeeId::new_v7(Utc::now())).await;
        assert_eq!(no_key, StatusCode::NOT_FOUND);
        assert_eq!(unknown, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_malformed_employee_selector_is_refused_before_any_lookup() {
        let Some(db) = db().await else { return };

        let response = router(db)
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("{DIRECTORY_PATH}?employee=not-a-uuid"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
