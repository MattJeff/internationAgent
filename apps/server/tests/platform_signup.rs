//! **Step zero, against the real binary: a customer who has never been
//! deployed.**
//!
//! Every other credential in this workspace's tests is written into
//! `AGENTOS_API_KEYS` before the process starts. This harness starts the server
//! with that variable **empty** — so nothing here can authenticate at all unless
//! the signup route works — and then does what a customer does: one call to
//! `POST /v1/platform/tenants`, one credential back, and `GET /v1/whoami`
//! answering with a tenant that did not exist a second ago.
//!
//! It then does the other half, which is the half that costs money when it is
//! missing: `DELETE /v1/platform/keys/{id}`, and the very next request with that
//! secret answering 401 — with no restart, no cache to expire, and every other
//! key on the deployment still working.
//!
//! # Why the whole binary, and why the log file is the leak surface
//!
//! `crates/app/tests/model_key_never_leaks.rs` had to install a global
//! `tracing` subscriber in a test binary of its own, because
//! `set_default` is thread-local, libtest runs unit tests in parallel, and a
//! callsite's `Interest` is cached the first time it is evaluated — so a leak
//! test that captures in-process can silently capture nothing and stay green.
//!
//! This test sidesteps that hazard rather than working around it. The secret is
//! generated **inside a separate process**, and that process's stdout is a file
//! this test reads after SIGTERM. There is no subscriber to install, no
//! ordering to get wrong, and what is searched is the bytes a log shipper would
//! actually have shipped. Nothing about the assertion depends on the test
//! process's own tracing state.
//!
//! Four surfaces are searched, and the fourth is the one a unit test cannot
//! reach: the server's log, the `api_keys` row, the `audit_log` rows, and the
//! *second* response — `GET /v1/platform/keys`, which is the endpoint somebody
//! will eventually be tempted to add a `secret` field to.
//!
//! # And the third test, which follows a secret the other way
//!
//! [`a_providers_signing_secret_is_usable_and_findable_nowhere`] registers two
//! customers' webhook endpoints on one deployment with the **same** `whsec_…` —
//! the shape two tenants behind one provider account actually have — delivers to
//! each, and asserts that neither queue holds the other's message and that the
//! secret is in none of seven surfaces. It shares this harness deliberately: the
//! process boundary that makes the log honest is the same one, and a second
//! binary would be a second copy of it.

mod common;

use std::collections::HashMap;
use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentos_store::db::Db;
use serde_json::Value;
use sqlx::Row as _;

/// The platform credential this deployment is handed. Long enough for
/// `ApiKeys::MIN_SECRET_LEN`, which the platform keyring reuses.
const PLATFORM_SECRET: &str = "0123456789abcdef0123456789abcdef";

/// What an issued secret starts with — `agentos_app::api_keys::SECRET_PREFIX`,
/// restated here because a test that imported the constant would agree with a
/// change to it rather than notice one.
const ISSUED_PREFIX: &str = "aos_";

/// The provider's signing secret, in the one test where a secret travels
/// *inwards*. Distinctive on purpose, and in three independent fragments, so a
/// partial or truncated copy is caught as well as a whole one.
const WEBHOOK_SECRET: &str = "whsec_DO-NOT-LEAK-ME-4a9f2c-webhook";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running server and its private database. No tenant and no API key: making
/// those is what is under test.
struct Server {
    child: Child,
    base: String,
    admin_url: String,
    database: String,
    database_url: String,
    log: PathBuf,
    reaped: bool,
}

/// A failing test must not leave a server running — `end_to_end.rs`'s `Drop`
/// impl carries the full argument for why this is SIGKILL and why it does not
/// drop the database.
impl Drop for Server {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    async fn start() -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the signup journey needs a real Postgres");
            return None;
        };

        let (base_url, _) = url.rsplit_once('/').expect("DATABASE_URL has a path");
        let admin_url = format!("{base_url}/postgres");
        let database = common::private_name(&url, "signup");
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect to postgres");
        // The audit `AssertSqlSafe` asks for: the name is this run's own
        // database name plus two integers, from `common::private_name`.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .expect("create the test database");
        admin.close().await;

        let database_url = format!("{base_url}/{database}");
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("a free port")
            .local_addr()
            .expect("addr")
            .port();

        let env: HashMap<&str, String> = HashMap::from([
            ("APP_BIND", format!("127.0.0.1:{port}")),
            ("PUBLIC_HOST", format!("http://127.0.0.1:{port}")),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com".to_owned()),
            ("DATABASE_URL", database_url.clone()),
            ("AGENTOS_MASTER_KEY", "not-a-real-key".to_owned()),
            ("AGENTOS_ALLOW_MOCKS", "1".to_owned()),
            // **Deliberately absent.** `AGENTOS_API_KEYS` is unset, so this
            // deployment can authenticate nobody until the signup route issues
            // a credential. Every 200 below is therefore a key that no
            // deployment produced.
            ("AGENTOS_PLATFORM_KEYS", format!("signup:{PLATFORM_SECRET}")),
            ("RUST_LOG", "info,agentos_server=debug".to_owned()),
        ]);

        let log = std::env::temp_dir().join(format!("{database}.log"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentos-server"));
        command
            .env_clear()
            .stdout(Stdio::from(File::create(&log).expect("log file")))
            .stderr(Stdio::inherit());
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        for (var, value) in &env {
            command.env(var, value);
        }

        let server = Self {
            child: command.spawn().expect("start the server"),
            base: format!("http://127.0.0.1:{port}"),
            admin_url,
            database,
            database_url,
            log,
            reaped: false,
        };
        server.wait_until_live();
        Some(server)
    }

    fn wait_until_live(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.curl("GET", "/livez", None, None).0 == 200 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the server never became live");
    }

    /// One request. `bearer` is the whole credential, whichever keyring it
    /// belongs to — which is the point of several assertions below.
    fn curl(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> (u16, Value) {
        let mut args = vec![
            "-sS".to_owned(),
            "-X".to_owned(),
            method.to_owned(),
            "-w".to_owned(),
            "\n%{http_code}".to_owned(),
            format!("{}{path}", self.base),
        ];
        if let Some(secret) = bearer {
            args.push("-H".to_owned());
            args.push(format!("Authorization: Bearer {secret}"));
        }
        if let Some(body) = body {
            args.push("-H".to_owned());
            args.push("Content-Type: application/json".to_owned());
            args.push("-d".to_owned());
            args.push(body.to_owned());
        }

        let output = Command::new("curl")
            .args(&args)
            .output()
            .expect("curl must be on PATH");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let (body, status) = text
            .rsplit_once('\n')
            .expect("curl -w writes the status on its own line");

        // Redacted before it is printed, and the redaction is the same regex a
        // secret scanner would use — which is what `SECRET_PREFIX` exists for.
        // The test's own output is not a log a shipper reads, but a harness that
        // prints credentials teaches the habit anyway.
        eprintln!("--- {method} {path} -> {status}\n{}", redact(body));
        (
            status.trim().parse().expect("an HTTP status"),
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    }

    fn get(&self, path: &str, bearer: Option<&str>) -> (u16, Value) {
        self.curl("GET", path, bearer, None)
    }

    fn post(&self, path: &str, bearer: Option<&str>, body: &str) -> (u16, Value) {
        self.curl("POST", path, bearer, Some(body))
    }

    /// SIGTERM, then everything the process wrote.
    fn shutdown(mut self) -> String {
        Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("send SIGTERM");

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait().expect("wait") {
                Some(status) => {
                    assert!(status.success(), "the server exited {status}");
                    break;
                }
                None if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    panic!("the server ignored SIGTERM");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }

        let logs = std::fs::read_to_string(&self.log).unwrap_or_default();
        let _ = std::fs::remove_file(&self.log);

        let (admin_url, database) = (self.admin_url.clone(), self.database.clone());
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async move {
                    let Ok(admin) = sqlx::PgPool::connect(&admin_url).await else {
                        return;
                    };
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE IF EXISTS {database} WITH (FORCE)"
                    )))
                    .execute(&admin)
                    .await;
                    admin.close().await;
                });
        })
        .join()
        .expect("drop the database");

        self.reaped = true;
        logs
    }
}

/// Replace anything shaped like an issued secret with its prefix.
fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(ISSUED_PREFIX) {
        out.push_str(&rest[..at]);
        out.push_str(ISSUED_PREFIX);
        out.push_str("<redacted>");
        rest = &rest[at + ISSUED_PREFIX.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// The journey
// ---------------------------------------------------------------------------

/// **A customer arrives, is given a key, and the key is taken away — all over
/// HTTP, on a deployment whose `AGENTOS_API_KEYS` is empty.**
///
/// Mutations this catches, with the message each produces:
///
/// * mount the platform router inside `with_api_stack` → step 2 answers 401
///   (`the signup call must not need a tenant key it cannot have`);
/// * let `require_api_key` accept the platform keyring → step 4 answers 200
///   (`a platform key must not read tenant data`);
/// * let a tenant key reach the platform router → step 5 answers 201
///   (`a stolen key must not be able to mint another`);
/// * cache the lookup → step 10 answers 200 (`the request after the DELETE`).
#[tokio::test]
async fn a_customer_signs_up_and_their_key_is_revoked_without_a_restart() {
    let Some(server) = Server::start().await else {
        return;
    };

    // 1. Nothing authenticates yet. Not even the platform key, on a tenant
    //    route: it is a credential of a different kind.
    assert_eq!(server.get("/v1/whoami", None).0, 401);
    assert_eq!(server.get("/v1/whoami", Some(PLATFORM_SECRET)).0, 401);

    // 2. Step zero. One call, no shell, no deploy.
    let (status, body) = server.post(
        "/v1/platform/tenants",
        Some(PLATFORM_SECRET),
        r#"{"slug":"acme","name":"Acme Corp"}"#,
    );
    assert_eq!(
        status, 201,
        "the signup call must not need a tenant key it cannot have: {body}"
    );
    let tenant_id = body["tenant_id"].as_str().expect("tenant_id").to_owned();
    let owner_id = body["key"]["id"].as_str().expect("key id").to_owned();
    let owner_secret = body["key"]["secret"]
        .as_str()
        .expect("the one response that carries a secret")
        .to_owned();
    assert!(
        owner_secret.starts_with(ISSUED_PREFIX),
        "prefixed for scanners"
    );
    assert!(owner_secret.len() >= 40, "{} chars", owner_secret.len());
    assert_eq!(body["key"]["label"], "owner");

    // 3. And it works, immediately, naming its own tenant and its own label.
    let (status, who) = server.get("/v1/whoami", Some(&owner_secret));
    assert_eq!(status, 200, "{who}");
    assert_eq!(who["tenant_id"], tenant_id, "the tenant came from the row");
    assert_eq!(who["actor"], "operator:owner");

    // 4. The platform key still cannot read that tenant's data.
    assert_eq!(
        server.get("/v1/whoami", Some(PLATFORM_SECRET)).0,
        401,
        "a platform key must not read tenant data"
    );

    // 5. **The tenant's own key cannot mint another.** This is the sentence
    //    revocation depends on.
    let (status, refused) = server.post(
        "/v1/platform/keys",
        Some(&owner_secret),
        &format!(r#"{{"tenant_id":"{tenant_id}","label":"backdoor"}}"#),
    );
    assert_eq!(
        status, 401,
        "a stolen key must not be able to mint another: {refused}"
    );

    // 6. Signing up twice under one slug is a conflict, not a second secret for
    //    the same company.
    let (status, conflict) = server.post(
        "/v1/platform/tenants",
        Some(PLATFORM_SECRET),
        r#"{"slug":"acme","name":"Acme Again"}"#,
    );
    assert_eq!(status, 409, "{conflict}");
    assert_eq!(conflict["code"], "tenant_exists");

    // 7. The rotation path: a second key, issued before the first is destroyed,
    //    so revoking costs no downtime.
    let (status, second) = server.post(
        "/v1/platform/keys",
        Some(PLATFORM_SECRET),
        &format!(r#"{{"tenant_id":"{tenant_id}","label":"ops-console"}}"#),
    );
    assert_eq!(status, 201, "{second}");
    let ops_secret = second["secret"].as_str().expect("secret").to_owned();
    assert_ne!(ops_secret, owner_secret, "two mints, two secrets");
    assert_eq!(server.get("/v1/whoami", Some(&ops_secret)).0, 200);

    // ...and the label is unique within the tenant, so a revocation names one
    // row.
    let (status, dup) = server.post(
        "/v1/platform/keys",
        Some(PLATFORM_SECRET),
        &format!(r#"{{"tenant_id":"{tenant_id}","label":"ops-console"}}"#),
    );
    assert_eq!(status, 409, "{dup}");
    assert_eq!(dup["code"], "key_label_exists");

    // 8. Both are listed, with no secret in sight.
    let (status, listed) = server.get(
        &format!("/v1/platform/keys?tenant_id={tenant_id}"),
        Some(PLATFORM_SECRET),
    );
    assert_eq!(status, 200, "{listed}");
    let labels: Vec<&str> = listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key["label"].as_str().expect("label"))
        .collect();
    assert_eq!(labels, vec!["owner", "ops-console"]);

    // 9. Revoke the first.
    let (status, revoked) = server.curl(
        "DELETE",
        &format!("/v1/platform/keys/{owner_id}"),
        Some(PLATFORM_SECRET),
        None,
    );
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["tenant_id"], tenant_id, "whose key was destroyed");

    // 10. **The very next request.** No restart, no waiting.
    assert_eq!(
        server.get("/v1/whoami", Some(&owner_secret)).0,
        401,
        "the request after the DELETE must fail: there is no cache to expire"
    );
    // ...and only that one. Revoking one customer's key must not interrupt any
    // other credential on the deployment.
    assert_eq!(
        server.get("/v1/whoami", Some(&ops_secret)).0,
        200,
        "revocation must be one key, not a redeploy"
    );

    // 11. Revoking twice is the state the caller wanted, reported as absence.
    let (status, _) = server.curl(
        "DELETE",
        &format!("/v1/platform/keys/{owner_id}"),
        Some(PLATFORM_SECRET),
        None,
    );
    assert_eq!(status, 404);

    let logs = server.shutdown();
    for line in ["api key issued", "api key revoked"] {
        assert!(
            logs.contains(line),
            "the operator's trail is missing {line:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The search
// ---------------------------------------------------------------------------

/// **One secret goes out. It is findable in exactly one place, and that place is
/// the response that issued it.**
///
/// Break any of these in `routes::platform` or `store::api_keys` and this goes
/// red: logging the secret beside the key id, putting it in the audit payload,
/// adding a `secret` field to the listing, storing it in `api_keys.secret_hash`
/// instead of its HMAC, or echoing it in the 409 a duplicate label produces.
///
/// The searched surfaces are checked to be non-empty first. An assertion that a
/// string is absent from a buffer nothing ever wrote to is an assertion about
/// nothing — which is the failure mode `crates/app/tests/model_key_never_leaks.rs`
/// was built to avoid, and the reason its argument is quoted in this file's
/// header.
#[tokio::test]
async fn the_issued_secret_appears_in_exactly_one_response_and_nowhere_else() {
    let Some(server) = Server::start().await else {
        return;
    };

    let (status, body) = server.post(
        "/v1/platform/tenants",
        Some(PLATFORM_SECRET),
        r#"{"slug":"leak-check","name":"Leak Check"}"#,
    );
    assert_eq!(status, 201, "{body}");
    let tenant_id = body["tenant_id"].as_str().expect("tenant_id").to_owned();
    let secret = body["key"]["secret"].as_str().expect("secret").to_owned();
    let key_id = body["key"]["id"].as_str().expect("id").to_owned();

    // The response that carries it says, in the payload, that it will not carry
    // it again.
    assert!(
        body["key"]["warning"]
            .as_str()
            .is_some_and(|w| w.contains("shown exactly once")),
        "{body}"
    );

    // Use it, so the authentication path has run with it and had a chance to
    // log it.
    assert_eq!(server.get("/v1/whoami", Some(&secret)).0, 200);
    // And fail with it, so the refusal path has too.
    assert_eq!(
        server
            .post(
                "/v1/platform/keys",
                Some(&secret),
                &format!(r#"{{"tenant_id":"{tenant_id}"}}"#)
            )
            .0,
        401
    );

    // The second response: the listing. This is where a `secret` field would go
    // if somebody ever added one "for convenience".
    let (_, listed) = server.get(
        &format!("/v1/platform/keys?tenant_id={tenant_id}"),
        Some(PLATFORM_SECRET),
    );

    // The rows: what a database dump holds.
    let db = Db::connect(&server.database_url).await.expect("connect");
    let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
    let key_row = sqlx::query("SELECT id, tenant_id, label, secret_hash FROM api_keys")
        .fetch_all(&mut *tx)
        .await
        .expect("api_keys");
    let digests: Vec<Vec<u8>> = key_row
        .iter()
        .map(|row| row.get::<Vec<u8>, _>("secret_hash"))
        .collect();
    let audit: Vec<(String, String, Value)> =
        sqlx::query_as("SELECT actor, action_kind, payload FROM audit_log ORDER BY occurred_at")
            .fetch_all(&mut *tx)
            .await
            .expect("audit_log");
    tx.rollback().await.expect("rollback");
    drop(db);

    // The surfaces are not empty — otherwise every assertion below is vacuous.
    assert_eq!(key_row.len(), 1, "one signup, one key");
    assert_eq!(digests[0].len(), 32, "an HMAC-SHA256 digest is 32 bytes");
    assert_eq!(audit.len(), 1, "one issuance, one row");
    assert_eq!(audit[0].1, "api_key_issued");
    assert_eq!(audit[0].0, "operator:signup", "the platform key's label");
    assert_eq!(audit[0].2["key_id"], key_id);
    assert!(listed["keys"].as_array().is_some_and(|k| k.len() == 1));

    let logs = server.shutdown();
    assert!(
        logs.contains("api key issued") && logs.contains(&key_id),
        "the log must actually record the issuance, or searching it proves nothing"
    );

    let everything = format!(
        "{logs}\n{listed}\n{audit:?}\n{digests:?}\n{}",
        digests
            .iter()
            .map(|d| String::from_utf8_lossy(d).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert!(
        !everything.contains(&secret),
        "the secret leaked into something readable:\n{}",
        redact(&everything)
    );
    // ...and not a fragment either. A truncated secret in a log is still a
    // secret in a log, and the prefix alone tells a scanner what it found.
    for fragment in [&secret[..16], &secret[secret.len() - 16..]] {
        assert!(
            !everything.contains(fragment),
            "a fragment of the secret leaked:\n{}",
            redact(&everything)
        );
    }
    // The prefix on its own is expected to appear nowhere at all here: no
    // surface searched has any business carrying even the shape of a key.
    assert!(
        !everything.contains(ISSUED_PREFIX),
        "something is carrying a value shaped like a key:\n{}",
        redact(&everything)
    );
}

// ---------------------------------------------------------------------------
// The other direction: a secret that arrives
// ---------------------------------------------------------------------------

/// **Two customers behind one provider account, over HTTP, against the real
/// binary — and the signing secret they share is findable nowhere.**
///
/// The other tests in this file follow a secret *out*: minted here, shown once,
/// never again. This one follows one *in*. The `whsec_…` belongs to the
/// provider, arrives in a request body, and must appear in no response, no log
/// line, no audit payload and no column a `pg_dump` would carry — while still
/// being usable, which is the half a test that simply dropped it would also
/// pass.
///
/// Mutations this catches, with the message each produces:
///
/// * echo the secret back in the registration response → `the response that
///   registered it`;
/// * log it beside the path → `the server log`;
/// * put it in the audit payload → `the audit trail`;
/// * store it unsealed in `webhook_endpoints.sealed_secret` → `the stored row`;
/// * key the endpoint on the provider rather than the path, or resolve the
///   tenant from anywhere but the row → the two `202`s land in one tenant and
///   the queue-depth assertions fail;
/// * skip verification on a stored endpoint → the forged delivery is `202`.
#[tokio::test]
async fn a_providers_signing_secret_is_usable_and_findable_nowhere() {
    use agentos_app::inbound::{Secret, sign_webhook};

    let Some(server) = Server::start().await else {
        return;
    };

    // Two customers of one deployment, both behind the same provider account —
    // which is what makes them share a secret, and what made this whole surface
    // necessary.
    let mut tenants = Vec::new();
    for slug in ["alpha", "beta"] {
        let (status, body) = server.post(
            "/v1/platform/tenants",
            Some(PLATFORM_SECRET),
            &format!(r#"{{"slug":"{slug}","name":"{slug}"}}"#),
        );
        assert_eq!(status, 201, "{body}");
        let tenant_id = body["tenant_id"].as_str().expect("tenant_id").to_owned();

        let (status, registered) = server.post(
            "/v1/platform/webhooks",
            Some(PLATFORM_SECRET),
            &format!(r#"{{"tenant_id":"{tenant_id}","secret":"{WEBHOOK_SECRET}"}}"#),
        );
        assert_eq!(status, 201, "{registered}");
        assert_eq!(registered["rotated"], false);
        let path = registered["path"].as_str().expect("path").to_owned();
        assert!(path.starts_with("whe_"), "{path}");
        tenants.push((tenant_id, path, registered));
    }
    assert_ne!(
        tenants[0].1, tenants[1].1,
        "two customers were given one address"
    );

    // **The other half of the arm that answers a `provider` nothing reads.** It
    // is `webhook_endpoints_provider_is_wired` doing the refusing, and the route
    // now names the SQLSTATE rather than treating every driver error as this
    // case — so this assertion is what stops the narrowing from having taken the
    // real refusal away with the wrong one. A 500 here means the CHECK stopped
    // being reported as the caller's mistake; a 201 means the CHECK is gone.
    //
    // `slack` and not `twilio`: `0069` widened that constraint to two providers,
    // so the obvious second name is now *accepted*, and an assertion written
    // against it would have pinned nothing.
    let (status, refused) = server.post(
        "/v1/platform/webhooks",
        Some(PLATFORM_SECRET),
        &format!(
            r#"{{"tenant_id":"{}","provider":"slack","secret":"{WEBHOOK_SECRET}"}}"#,
            tenants[0].0
        ),
    );
    assert_eq!(
        status, 400,
        "a provider with no ingest is the caller's mistake: {refused}"
    );
    // **And the status on its own was the whole assertion, which is not enough
    // for either reader.** This route answers 400 for three different things —
    // a body that is not JSON, a blank `secret`, and this — and until now all
    // three carried `ApiError::bad_request`'s generic `bad_request`. A signup
    // script cannot act on that: two of the three are fixed by correcting the
    // request and the third only by deploying a build that reads the provider,
    // so a client retrying on 400 retries forever. The refusal now has a code of
    // its own, and this is what stops it quietly collapsing back into the
    // generic one — which is a change no status assertion can see.
    assert_eq!(
        refused["code"], "provider_not_wired",
        "the 400 has to say *which* 400 it is: {refused:#}"
    );
    // The other direction, and the reason a second code was worth adding: an
    // ordinary bad request on the same route keeps the generic code. Without
    // this, `provider_not_wired` could be what every refusal here says, which
    // would leave the caller exactly where it started.
    let (status, blank) = server.post(
        "/v1/platform/webhooks",
        Some(PLATFORM_SECRET),
        &format!(r#"{{"tenant_id":"{}","secret":"  "}}"#, tenants[0].0),
    );
    assert_eq!(status, 400, "a blank secret is refused: {blank}");
    assert_eq!(
        blank["code"], "bad_request",
        "a malformed request is not a provider this build cannot read: {blank:#}"
    );

    // A delivery each, with the same provider event id — the shape a shared
    // provider account produces. Signed with the shared secret, so the signature
    // cannot be what separates them.
    for (index, (_, path, _)) in tenants.iter().enumerate() {
        let body = format!(
            "{{\"type\":\"email.received\",\"created_at\":\"2026-08-24T10:00:00Z\",\
              \"data\":{{\"email_id\":\"email_{index}\",\"from\":\"ap@supplier.example\",\
              \"to\":[\"lena@agents.example.com\"]}}}}"
        );
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = sign_webhook(
            &Secret::new(WEBHOOK_SECRET),
            "msg_shared",
            &timestamp,
            body.as_bytes(),
        );
        let status = Command::new("curl")
            .args([
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-X",
                "POST",
                "-H",
                "webhook-id: msg_shared",
                "-H",
                &format!("webhook-timestamp: {timestamp}"),
                "-H",
                &format!("webhook-signature: {signature}"),
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
                &format!("{}/v1/webhooks/{path}", server.base),
            ])
            .output()
            .expect("curl");
        assert_eq!(
            String::from_utf8_lossy(&status.stdout),
            "202",
            "a genuine delivery to a registered endpoint was refused; the sealed \
             secret does not round-trip through the database"
        );
    }

    // **A signature that is well formed and wrong.** The refusal above this one
    // carries no `webhook-signature` header at all, so `verify_signature`
    // answers `MissingHeader` on its first line and the MAC is never reached —
    // which means every assertion in this file used to pass with the comparison
    // deleted. Measured: `matched |= true` in `providers::email`, all three
    // tests here green, and the `202` above green too, because a genuine
    // delivery is accepted either way. This is the arm that only a forged
    // delivery triggers: same endpoint, same headers, same bytes, signed with a
    // secret this deployment never registered.
    let forged_body = r#"{"type":"email.received","created_at":"2026-08-24T10:00:00Z","data":{"email_id":"email_forged","from":"ap@supplier.example","to":["lena@agents.example.com"]}}"#;
    let forged_timestamp = chrono::Utc::now().timestamp().to_string();
    let forged = sign_webhook(
        &Secret::new("whsec_a-secret-this-deployment-never-registered"),
        "msg_forged",
        &forged_timestamp,
        forged_body.as_bytes(),
    );
    // The raw `curl`, as above: the harness's `post` cannot carry the three
    // headers this scheme needs.
    let output = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-X",
            "POST",
            "-H",
            "webhook-id: msg_forged",
            "-H",
            &format!("webhook-timestamp: {forged_timestamp}"),
            "-H",
            &format!("webhook-signature: {forged}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            forged_body,
            &format!("{}/v1/webhooks/{}", server.base, tenants[0].1),
        ])
        .output()
        .expect("curl");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "401",
        "a delivery signed with the wrong secret was accepted: the MAC is not \
         being compared, only the headers counted"
    );

    // The refusal paths, so they have run with the secret in hand and had their
    // chance to render it.
    let (status, unverified) = server.post(
        &format!("/v1/webhooks/{}", tenants[0].1),
        None,
        r#"{"type":"email.received"}"#,
    );
    assert_eq!(status, 401, "{unverified}");
    let (status, missing) = server.post("/v1/webhooks/whe_no_such_endpoint_at_all", None, "{}");
    assert_eq!(status, 404, "{missing}");

    // The rows: what a database dump holds.
    let db = Db::connect(&server.database_url).await.expect("connect");
    let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
    let endpoints =
        sqlx::query("SELECT path, tenant_id, provider, sealed_secret FROM webhook_endpoints")
            .fetch_all(&mut *tx)
            .await
            .expect("webhook_endpoints");
    let sealed: Vec<Vec<u8>> = endpoints
        .iter()
        .map(|row| row.get::<Vec<u8>, _>("sealed_secret"))
        .collect();
    let audit: Vec<(String, String, Value)> = sqlx::query_as(
        "SELECT actor, action_kind, payload FROM audit_log \
          WHERE action_kind = 'webhook_endpoint_registered' ORDER BY occurred_at",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("audit_log");
    // Each tenant's own queue, read with RLS on — the isolation claim, asked of
    // the database rather than of a WHERE clause this test wrote.
    let mut depths = Vec::new();
    for (tenant_id, _, _) in &tenants {
        let mut tenant_tx = db
            .tenant_tx(agentos_domain::ids::TenantId::from_uuid(
                tenant_id.parse().expect("uuid"),
            ))
            .await
            .expect("tenant tx");
        let depth: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox_events WHERE aggregate_type = 'webhook'",
        )
        .fetch_one(&mut **tenant_tx)
        .await
        .expect("count");
        tenant_tx.commit().await.expect("commit");
        depths.push(depth);
    }
    tx.rollback().await.expect("rollback");
    drop(db);

    // The surfaces are not empty — otherwise every assertion below is vacuous.
    assert_eq!(endpoints.len(), 2, "two registrations, two rows");
    assert!(sealed.iter().all(|blob| blob.len() > 32), "{sealed:?}");
    assert_eq!(audit.len(), 2, "two registrations, two audit rows");
    assert_eq!(audit[0].0, "operator:signup", "the platform key's label");
    assert_eq!(
        depths,
        vec![1, 1],
        "one delivery each: {depths:?} — a customer is holding the other's mail, \
         or has lost their own to a dedupe key that forgot the tenant"
    );

    let logs = server.shutdown();
    assert!(
        logs.contains("webhook endpoint registered") && logs.contains(&tenants[0].1),
        "the log must actually record the registration, or searching it proves nothing"
    );

    // Whole, and in fragments: a truncated secret in a log is still a secret in
    // a log.
    let fragments = [
        WEBHOOK_SECRET,
        "DO-NOT-LEAK-ME",
        "4a9f2c",
        &WEBHOOK_SECRET[WEBHOOK_SECRET.len() - 12..],
    ];
    for (name, surface) in [
        ("the server log", logs.clone()),
        (
            "the response that registered it",
            format!("{}", tenants[0].2),
        ),
        (
            "the second registration's response",
            format!("{}", tenants[1].2),
        ),
        ("the 401 a bad signature produces", format!("{unverified}")),
        ("the 404 an unknown path produces", format!("{missing}")),
        ("the audit trail", format!("{audit:?}")),
        (
            "the stored row",
            format!(
                "{sealed:?} {}",
                sealed
                    .iter()
                    .map(|blob| String::from_utf8_lossy(blob).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
    ] {
        for fragment in fragments {
            assert!(
                !surface.contains(fragment),
                "the provider's signing secret leaked into {name} (fragment {fragment:?})"
            );
        }
    }
}
