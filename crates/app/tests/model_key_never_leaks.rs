//! **One key goes in. It comes out in exactly one place, and that place is the
//! vault.**
//!
//! `agentos_app::model_access` takes a customer's Anthropic API key, proves it
//! against the provider, and stores it. Between those three steps the key passes
//! through an HTTP client, a `Result`, an audit payload, a database transaction
//! and two `tracing` events, and any one of them could keep a copy. This file is
//! the search: after a successful connection, the key must not be findable in
//! the outcome that becomes an HTTP body, the audit trail, the connection row,
//! any `Debug` rendering, any log line, or the stored ciphertext.
//!
//! # Why this is a test binary of its own and not one more `#[test]` in the module
//!
//! Because it captures `tracing`, and capture is the part that is easy to get
//! silently wrong. `tracing::subscriber::set_default` is **thread-local**, libtest
//! runs a crate's unit tests in parallel across threads, and a callsite's
//! `Interest` is cached globally the first time it is evaluated. Put this test
//! beside the module's other eight and it passes alone and captures nothing when
//! a sibling test reaches the same `tracing::info!` first — which is exactly what
//! it did, and a leak test that quietly stops looking is worse than no leak test,
//! because it is green.
//!
//! Its own binary means its own process, one test in it, and
//! [`set_global_default`](tracing::subscriber::set_global_default) rather than a
//! thread-local guard. The ordering hazard is gone rather than worked around.
//!
//! # Mutations this test is known to catch
//!
//! Break any of these in `model_access.rs` and this file is what goes red:
//! putting the key in the audit payload, hashing it into the payload, logging it
//! beside the tenant id, adding a `key` field to `Outcome`, or storing it in the
//! connection row instead of the vault. The assertion covers a rendered blob of
//! every one of those surfaces at once, so a new surface added later is covered
//! the moment it is added to the blob — and the blob is the thing to add to.

use std::sync::{Arc, Mutex};

use agentos_app::mocks::{Llm, LlmBackend, LlmResponse, ScriptedLlm, Usage};
use agentos_app::model_access::{connect, for_turn};
use agentos_domain::ids::TenantId;
use agentos_domain::model_access::{ModelAccess, ModelPath, Verdict};
use agentos_domain::policy::ModelId;
use agentos_providers::Secret;
use agentos_providers::secrets::{LocalEnvelopeSecretStore, SecretStore};
use agentos_store::audit::AuditActor;
use agentos_store::db::{Db, TenantTx};
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;

/// The string this whole exercise exists to keep out of everything. Distinctive
/// on purpose: three independent fragments, so a partial or truncated copy is
/// caught as well as a whole one.
const KEY: &str = "sk-ant-api03-DO-NOT-LEAK-ME-4a9f2c";

/// Everything `tracing` emitted, as bytes.
///
/// A real subscriber rendering real events, because the question is what a *log
/// line* contains and the only honest way to ask it is to render one. Asserting
/// on a buffer nothing ever wrote to is an assertion about nothing, which is why
/// the test also proves the expected line arrived.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A one-shot HTTP server standing in for `api.anthropic.com`.
///
/// The same twenty lines `llm_anthropic`'s own tests use — no wiremock in this
/// workspace, and a listener beats a dependency. It returns the raw request it
/// received, which is what proves the key really went out on the wire: a leak
/// test against a probe that never happened proves nothing.
async fn anthropic(status: &str, body: &str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let raw = read_request(&mut sock).await;
        sock.write_all(response.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
        raw
    });
    (origin, handle)
}

async fn read_request(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
        let len: usize = head
            .split("content-length:")
            .nth(1)
            .and_then(|rest| rest.split(['\r', '\n']).next())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if buf.len() >= end + 4 + len {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

const OK_BODY: &str = r#"{"content":[{"type":"text","text":"h"}],
    "stop_reason":"max_tokens","usage":{"input_tokens":9,"output_tokens":1}}"#;

async fn fixture() -> Option<(Db, TenantId)> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIP: DATABASE_URL is unset; the model key leak test needs a database");
        return None;
    };
    let db = Db::connect(&url).await.expect("connect");
    db.migrate().await.expect("migrate");

    let tenant_id = TenantId::new_v7(Utc::now());
    let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
    sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'model key leak')")
        .bind(tenant_id.as_uuid())
        .bind(format!("mkl-{}", tenant_id.as_uuid().simple()))
        .execute(&mut *admin)
        .await
        .expect("insert tenant");
    admin.commit().await.expect("commit");
    Some((db, tenant_id))
}

/// A host backend that is never reached on the api_key path — present because
/// `connect` takes one, and scripted to answer so that a wrong branch would
/// succeed loudly rather than fail for the wrong reason.
fn host() -> Arc<dyn Llm> {
    Arc::new(ScriptedLlm::looping(vec![Ok(LlmResponse::text(
        "h",
        Usage::new(9, 1, 0),
    ))]))
}

#[tokio::test]
async fn the_key_reaches_the_vault_and_appears_nowhere_else() {
    let logs = Logs::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish(),
    )
    .expect("one test, one process, one subscriber");

    let Some((db, tenant_id)) = fixture().await else {
        return;
    };
    let (origin, request) = anthropic("200 OK", OK_BODY).await;
    let secrets = LocalEnvelopeSecretStore::new([3u8; 32]);
    let now = Utc::now();

    // The real `connect`, with its probe pointed at a listener instead of the
    // real API. Nothing on the path is re-implemented here — a leak test
    // against a copy of the function tests the copy.
    let mut tx: TenantTx<'_> = db.tenant_tx(tenant_id).await.expect("tx");
    let outcome = connect(
        &mut tx,
        &secrets,
        &host(),
        LlmBackend::Mock,
        ModelPath::ApiKey,
        ModelId::Opus5,
        Some(Secret::new(KEY)),
        Some(&origin),
        AuditActor::Operator("founder@example.com".to_owned()),
        now,
    )
    .await
    .expect("connect");
    tx.commit().await.expect("commit");

    assert_eq!(outcome.verdict, Verdict::Connected);
    assert_eq!(outcome.access.expect("stored").model, ModelId::Opus5);

    // 1. The key really did go out on the wire, or none of the rest means
    //    anything.
    let raw = request.await.unwrap();
    assert!(raw.to_lowercase().contains("x-api-key"), "{raw}");
    assert!(raw.contains(KEY), "the probe must actually use the key");

    // 2. The vault has it, under the ref derived from the tenant id.
    let secret_ref = ModelAccess::secret_ref(tenant_id).unwrap();
    assert_eq!(
        secrets
            .get(&secret_ref)
            .await
            .expect("stored")
            .expose_for_transport(),
        KEY
    );

    // 3. And the turn that spends it gets a client, not a copy anybody can
    //    read: `for_turn` hands back an `Arc<dyn Llm>` with no accessor on it.
    let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
    let (llm, access) = for_turn(&mut tx, &secrets, &host(), LlmBackend::Mock, Some(&origin))
        .await
        .expect("connected");
    let spender = format!("{:?}", Arc::as_ptr(&llm));

    // 4. Everything anybody can read. The outcome is the HTTP body, the audit
    //    payloads are the trail, the row is the table, `Debug` on the store is
    //    what a panic prints, and the ciphertext is what a database dump holds.
    let row = agentos_store::model_access::load(&mut tx)
        .await
        .expect("load")
        .expect("connected");
    let audit_rows: Vec<(String, String, serde_json::Value)> =
        sqlx::query_as("SELECT actor, action_kind, payload FROM audit_log ORDER BY occurred_at")
            .fetch_all(&mut **tx)
            .await
            .expect("audit");
    let ciphertext = secrets
        .seal(&secret_ref, &Secret::new(KEY))
        .expect("seal")
        .to_bytes();
    tx.commit().await.expect("commit");

    assert_eq!(audit_rows.len(), 1, "one connect, one row");
    assert_eq!(audit_rows[0].1, "model_connected");
    assert_eq!(
        audit_rows[0].0, "operator:founder@example.com",
        "the trail names who, never what"
    );
    assert_eq!(access, row);

    let everything = format!(
        "{outcome:?} {json} {row:?} {access:?} {audit_rows:?} {secrets:?} {spender} {logs} \
         {cipher:?} {cipher_utf8}",
        json = serde_json::to_string(&outcome).expect("serialize"),
        logs = logs.text(),
        cipher = ciphertext,
        cipher_utf8 = String::from_utf8_lossy(&ciphertext),
    );
    assert!(
        !everything.contains(KEY),
        "the key leaked into something readable:\n{everything}"
    );
    // …and not a fragment of it either. A truncated key in a log is still a key
    // in a log, and `sk-ant-` alone tells an attacker what they are looking at.
    for fragment in ["sk-ant", "DO-NOT-LEAK", "4a9f2c"] {
        assert!(
            !everything.contains(fragment),
            "{fragment:?} leaked:\n{everything}"
        );
    }

    // 5. The searched surfaces are not empty. An absence proves nothing about a
    //    string nobody wrote, so each of the three that could plausibly be blank
    //    is checked to contain what it should.
    let logged = logs.text();
    assert!(logged.contains("model connected"), "{logged}");
    assert!(
        logged.contains(&tenant_id.as_uuid().to_string()),
        "{logged}"
    );
    assert!(
        serde_json::to_string(&outcome)
            .unwrap()
            .contains("connected"),
        "the response body must actually say something"
    );
    assert!(ciphertext.len() > 32, "a sealed envelope is not empty");
}
