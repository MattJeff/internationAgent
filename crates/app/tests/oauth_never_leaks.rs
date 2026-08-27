//! **Five secrets pass through one OAuth flow. None of them is findable
//! afterwards.**
//!
//! `agentos_app::oauth` handles, in one exchange: the deployment's
//! `client_secret`, the PKCE `code_verifier`, the `state` that lets whoever
//! holds it finish somebody's connection, the authorization `code`, and the two
//! tokens that come back. Between them they pass through an HTTP client, a URL,
//! a `Result`, two database tables and several `tracing` events, and any one of
//! those could keep a copy.
//!
//! This file is the search. After a flow completes, none of the five may be
//! findable in: the authorize URL beyond the one field that must carry it, any
//! row of `mcp_oauth_flows` or `mcp_servers`, any `Debug` rendering of the
//! registry or the error types, any log line, or the sealed ciphertext.
//!
//! # Why this is a test binary of its own
//!
//! Because it captures `tracing`, and capture is the part that is easy to get
//! silently wrong. `tracing::subscriber::set_default` is **thread-local**,
//! libtest runs a crate's unit tests in parallel across threads, and a
//! callsite's `Interest` is cached globally the first time it is evaluated. Put
//! this beside `oauth.rs`'s other thirteen tests and it passes alone and
//! captures nothing the moment a sibling reaches the same `tracing::warn!`
//! first. `model_key_never_leaks.rs` is the same file for the same reason and
//! its header carries the whole argument.
//!
//! Its own binary means its own process, one test in it, and
//! [`set_global_default`](tracing::subscriber::set_global_default) rather than a
//! thread-local guard.
//!
//! # Mutations this file is known to catch
//!
//! Break any of these and it goes red: putting the token endpoint's response
//! body into `OauthError::Endpoint`, logging `authorize_url` instead of the
//! state hash, storing the raw `state` in `mcp_oauth_flows` instead of its
//! SHA-256, storing the verifier unsealed, deriving `Debug` on `OauthClients`,
//! `Started` or `Sealed`, or echoing the `code` into any of them.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use agentos_app::catalog::{ClientAuth, Connector, Credential, OAuth};
use agentos_app::mcp::{Credentials, Reach, RiskClass};
use agentos_app::oauth::{Claimed, OauthClients, complete, refresh_due, start, state_hash};
use agentos_domain::ids::{Slug, TenantId};
use agentos_providers::secrets::LocalEnvelopeSecretStore;
use agentos_store::db::Db;
use chrono::{DateTime, TimeDelta, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::fmt::MakeWriter;

/// The five strings this exercise exists to keep out of everything.
///
/// Distinctive on purpose, and each in three independent fragments, so a
/// truncated or partial copy is caught as well as a whole one — a token with its
/// last eight characters trimmed is still a token in a log.
const CLIENT_SECRET: &str = "csec-DO-NOT-LEAK-8b21";
const CODE: &str = "authcode-DO-NOT-LEAK-3f70";
const ACCESS: &str = "at-DO-NOT-LEAK-9c4e";
const REFRESH: &str = "rt-DO-NOT-LEAK-2a15";

/// Everything `tracing` emitted, as bytes.
///
/// A real subscriber rendering real events: the question is what a *log line*
/// contains, and the only honest way to ask it is to render one. Asserting on a
/// buffer nothing wrote to is an assertion about nothing, which is why the test
/// also proves the expected lines arrived.
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

// ---------------------------------------------------------------------------
// An authorization server, on a loopback port
// ---------------------------------------------------------------------------

/// A token endpoint that records what it was sent and answers with two tokens.
///
/// Its own copy rather than a shared helper, deliberately: this file is a
/// different crate to `oauth.rs`'s unit tests and a leak test that imported its
/// subject's own fixtures would be one refactor away from testing a fake.
struct Provider {
    origin: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Provider {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    while let Some(body) = read_body(&mut stream, &mut buffer).await {
                        recorded
                            .lock()
                            .expect("not poisoned")
                            .push(String::from_utf8_lossy(&body).into_owned());
                        let payload = format!(
                            r#"{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}",
                                "token_type":"Bearer","expires_in":3600}}"#
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\n\r\n{payload}",
                            payload.len()
                        );
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            origin: format!("http://{addr}"),
            seen,
        }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

async fn read_body(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                let body = buffer[end + 4..end + 4 + length].to_vec();
                buffer.drain(..end + 4 + length);
                return Some(body);
            }
        }
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A catalogue entry pointed at the loopback provider.
///
/// `Box::leak` because `Connector` is `&'static` on purpose — production entries
/// are literals in a `const` array and the signature says so.
fn connector_for(origin: &str) -> &'static Connector {
    let endpoints: &'static OAuth = Box::leak(Box::new(OAuth {
        authorize: Box::leak(format!("{origin}/authorize").into_boxed_str()),
        token: Box::leak(format!("{origin}/token").into_boxed_str()),
        scopes: "read:things",
        auth: ClientAuth::Post,
    }));
    Box::leak(Box::new(Connector {
        key: "leaky",
        label: "A provider that would love to be logged",
        url: Some("https://mcp.example.test/mcp"),
        reach: Reach::Public,
        credential: Credential::OAuth(endpoints),
        floor: RiskClass::Write,
    }))
}

async fn fixture() -> Option<(Db, TenantId)> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIP: DATABASE_URL is unset; the oauth leak test needs a database");
        return None;
    };
    let db = Db::connect(&url).await.expect("connect");
    db.migrate().await.expect("migrate");

    let tenant_id = TenantId::new_v7(Utc::now());
    let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
    sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'oauth leak')")
        .bind(tenant_id.as_uuid())
        .bind(format!("oal-{}", tenant_id.as_uuid().simple()))
        .execute(&mut *admin)
        .await
        .expect("insert tenant");
    admin.commit().await.expect("commit");
    Some((db, tenant_id))
}

#[tokio::test]
async fn no_part_of_a_flow_is_findable_after_it_completes() {
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
    let provider = Provider::start().await;
    let connector = connector_for(&provider.origin);
    let credentials = Credentials::new(Arc::new(LocalEnvelopeSecretStore::new([11_u8; 32])));
    let clients =
        OauthClients::parse(&format!("leaky:our-client-id:{CLIENT_SECRET}")).expect("registration");
    let server = Slug::parse("leaky-erp").expect("slug");
    let redirect = "https://agentos.test/v1/mcp/oauth/callback";
    let now = Utc::now();

    // --- 1. start, and store the flow exactly as the route does -------------
    let started =
        start(&clients, &credentials, tenant_id, connector, redirect, now).expect("start");

    let mut tx = db.tenant_tx(tenant_id).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO mcp_oauth_flows \
           (state_hash, tenant_id, connector, server, sealed_verifier, redirect_uri, expires_at) \
         VALUES ($1, $2, 'leaky', $3, $4, $5, $6)",
    )
    .bind(started.state_hash.as_slice())
    .bind(tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(started.sealed_verifier.as_slice())
    .bind(redirect)
    .bind(started.expires_at)
    .execute(&mut **tx)
    .await
    .expect("insert flow");
    tx.commit().await.expect("commit");

    // The `state` is only ever in the URL. Pull it back out, because everything
    // below has to prove it is nowhere else.
    let state = url::Url::parse(&started.authorize_url)
        .expect("a url")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("the authorize url carries the state");
    assert_eq!(state_hash(&state), started.state_hash);

    // --- 2. complete ---------------------------------------------------------
    let flow = Claimed {
        tenant_id,
        connector,
        server: server.clone(),
        state_hash: started.state_hash,
        sealed_verifier: started.sealed_verifier.clone(),
    };
    let sealed = complete(
        &clients,
        &credentials,
        &flow,
        CODE.to_owned(),
        redirect,
        now,
    )
    .await
    .expect("complete");

    // The secrets really did go out on the wire, or none of the rest means
    // anything: a leak test against an exchange that never happened proves
    // nothing.
    let seen = provider.seen();
    assert_eq!(seen.len(), 1, "one exchange");
    assert!(
        seen[0].contains(CODE),
        "the code must actually be presented"
    );
    assert!(
        seen[0].contains(CLIENT_SECRET),
        "the client secret must actually authenticate"
    );

    // --- 3. store the binding the way the callback does ---------------------
    let mut tx = db.tenant_tx(tenant_id).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO mcp_servers \
           (tenant_id, server, url, reach, connector, sealed_token, \
            sealed_refresh_token, token_expires_at) \
         VALUES ($1, $2, 'https://mcp.example.test/mcp', 'public', 'github', $3, $4, $5)",
    )
    .bind(tenant_id.as_uuid())
    .bind(server.as_str())
    .bind(sealed.access.as_slice())
    .bind(sealed.refresh.as_deref())
    // Already due, so the refresh step below actually selects it.
    .bind(now + TimeDelta::minutes(1))
    .execute(&mut **tx)
    .await
    .expect("insert binding");
    tx.commit().await.expect("commit");

    // --- 4. and drive the refresh step's FAILURE path ------------------------
    //
    // `connector` is stored as `github` above, which is a real catalogue entry
    // that takes a pasted bearer — so `refresh_due` selects the row and then
    // refuses it. That is the branch worth searching: an error path is where a
    // token gets logged "just this once, for debugging".
    let mut tx = db.tenant_tx(tenant_id).await.expect("tenant tx");
    let refreshed = refresh_due(&mut tx, &credentials, &clients, now).await;
    tx.rollback().await.expect("rollback");
    assert_eq!(
        refreshed, 0,
        "github takes a pasted token, so nothing renews"
    );

    // --- 5. everything anybody can read -------------------------------------
    let mut tx = db.tenant_tx(tenant_id).await.expect("tenant tx");
    let flow_row: (Vec<u8>, String, String, Vec<u8>, String, DateTime<Utc>) = sqlx::query_as(
        "SELECT state_hash, connector, server, sealed_verifier, redirect_uri, expires_at \
           FROM mcp_oauth_flows",
    )
    .fetch_one(&mut **tx)
    .await
    .expect("flow row");
    let binding_row: (String, String, Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT url, connector, sealed_token, sealed_refresh_token FROM mcp_servers",
    )
    .fetch_one(&mut **tx)
    .await
    .expect("binding row");
    tx.rollback().await.expect("rollback");

    let blobs: Vec<Vec<u8>> = vec![
        flow_row.0.clone(),
        flow_row.3.clone(),
        binding_row.2.clone(),
        binding_row.3.clone().unwrap_or_default(),
        sealed.access.clone(),
        sealed.refresh.clone().unwrap_or_default(),
    ];
    let raw: String = blobs
        .iter()
        .map(|blob| String::from_utf8_lossy(blob).into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    // A failure that could carry a body, rendered both ways. `OauthError` has
    // one shape for "the authorization server said no" and it holds a
    // `&'static str`; if somebody ever widens it to carry the response, this is
    // the line that notices.
    let refused = start(
        &OauthClients::default(),
        &credentials,
        tenant_id,
        connector,
        redirect,
        now,
    );
    let rendered_error = match refused {
        Ok(_) => panic!("an unregistered connector must not start a flow"),
        Err(err) => format!("{err} {err:?} {}", err.code()),
    };

    let everything = format!(
        "{url} {clients:?} {flow:?} {binding:?} {raw} {raw_bytes:?} {rendered_error} {logs}",
        url = started.authorize_url,
        flow = flow_row,
        binding = binding_row,
        raw_bytes = blobs,
        logs = logs.text(),
    );

    for (what, secret) in [
        ("the client secret", CLIENT_SECRET),
        ("the authorization code", CODE),
        ("the access token", ACCESS),
        ("the refresh token", REFRESH),
    ] {
        assert!(
            !everything.contains(secret),
            "{what} leaked into something readable:\n{everything}"
        );
    }
    // …and not a fragment either. `DO-NOT-LEAK` alone is enough to tell an
    // attacker what they are looking at, and a truncated token is still a token.
    for fragment in [
        "DO-NOT-LEAK",
        "csec-",
        "authcode-",
        "8b21",
        "3f70",
        "9c4e",
        "2a15",
    ] {
        assert!(
            !everything.contains(fragment),
            "{fragment:?} leaked:\n{everything}"
        );
    }

    // The `state` is a capability. It is in the URL, because that is the URL's
    // whole job, and it must be in nothing else — not the row it keys, not a log
    // line, not an error.
    assert!(
        started.authorize_url.contains(&state),
        "the consent URL has to carry it"
    );
    let without_url = everything.replacen(&started.authorize_url, "<the-consent-url>", 1);
    assert!(
        !without_url.contains(&state),
        "the state leaked outside the consent url:\n{without_url}"
    );
    // **A prefix, not the whole value**, and this line is the one that earns its
    // place. `state_hash` is 32 bytes and a `state` is 43 characters, so a
    // version of it that stored the state *truncated* would never be equal to
    // the state and an `assert_ne!` on the two would pass while the row held a
    // key an attacker could read and replay. Sixteen characters of a 256-bit
    // value is not a coincidence anywhere.
    let stub = &state[..16];
    assert!(
        !without_url.contains(stub),
        "part of the state leaked outside the consent url — the row must key on \
         sha256(state) and never on the state itself:\n{without_url}"
    );

    // And the PKCE verifier is in the database only as ciphertext. The value is
    // recovered from what the provider was sent, which is the one place it is
    // supposed to appear.
    let opened = url::form_urlencoded::parse(seen[0].as_bytes())
        .find(|(key, _)| key == "code_verifier")
        .map(|(_, value)| value.into_owned())
        .expect("the exchange presented a verifier");
    assert!(
        !everything.contains(&opened),
        "the code verifier leaked out of its envelope:\n{everything}"
    );

    // --- 6. the searched surfaces are not empty ------------------------------
    //
    // An absence proves nothing about a string nobody wrote.
    let logged = logs.text();
    assert!(
        logged.contains("could not refresh an mcp oauth token"),
        "the refresh failure must actually have been logged:\n{logged}"
    );
    assert!(
        logged.contains("connector_is_not_oauth"),
        "and with its stable code:\n{logged}"
    );
    assert!(
        started.authorize_url.contains("code_challenge"),
        "{}",
        started.authorize_url
    );
    assert!(sealed.access.len() > 32, "a sealed envelope is not empty");
    assert!(flow_row.3.len() > 32, "nor is a sealed verifier");
    assert!(rendered_error.contains("leaky"), "{rendered_error}");
}
