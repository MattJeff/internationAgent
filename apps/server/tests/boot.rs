//! The boot guard, checked the way an orchestrator checks it: by the exit code.
//!
//! `config.rs` already proves [`Config::parse`] returns the right error. This
//! file proves the thing that actually matters to a deployment — that the
//! error reaches `main`, that the process **exits non-zero**, and that the
//! reason is on stderr where a crash-loop log will show it. A server that
//! detects a misconfiguration and then starts anyway has detected nothing, and
//! that failure mode is invisible to a unit test.
//!
//! Runs the real binary. It never reaches the database: both cases fail while
//! reading the environment.

use std::collections::HashMap;
use std::process::{Command, Output};

/// Every variable a good boot needs. Cases below remove from it.
///
/// The provider credentials are in the shape their variable demands — two of
/// the three are `left:right` pairs, because the adapters behind them take two
/// values and an adapter built from half a credential is the failure this file
/// is about.
fn complete_env() -> HashMap<&'static str, String> {
    let mut env: HashMap<&'static str, String> = HashMap::from([
        ("APP_BIND", "127.0.0.1:0".to_owned()),
        ("PUBLIC_HOST", "https://agents.example.com".to_owned()),
        ("AGENT_EMAIL_DOMAIN", "agents.example.com".to_owned()),
        (
            "DATABASE_URL",
            "postgres://nobody@127.0.0.1:1/nothing".to_owned(),
        ),
        ("AGENTOS_MASTER_KEY", "not-a-real-key".to_owned()),
        ("AGENTOS_LLM", "anthropic".to_owned()),
        ("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key".to_owned()),
    ]);
    for (var, value) in [
        ("EMAIL_API_KEY", "re_not_a_real_key"),
        ("TELEPHONY_API_KEY", "ACtest:not-a-real-token"),
        ("BROWSER_API_KEY", "proj_test:bb_not_a_real_key"),
    ] {
        env.insert(var, value.to_owned());
    }
    env
}

/// Boot the real binary with exactly `env` and nothing inherited — an
/// inherited `DATABASE_URL` from the test runner would quietly repair the very
/// environment the case is trying to break.
fn boot(env: &HashMap<&'static str, String>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentos-server"));
    command.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }
    for (var, value) in env {
        command.env(var, value);
    }
    command.output().expect("run the server binary")
}

#[test]
fn a_mock_adapter_without_permission_exits_non_zero() {
    let mut env = complete_env();
    env.remove("EMAIL_API_KEY");

    let output = boot(&env);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "the server started with a mock email adapter: {stderr}"
    );
    assert!(stderr.contains("email"), "which adapter? {stderr}");
    assert!(
        stderr.contains("AGENTOS_ALLOW_MOCKS"),
        "and how to proceed on purpose? {stderr}"
    );
}

/// Which one, by name. A guard that says "something is a mock" sends an
/// operator to read four variables; this one sends them to the right one.
#[test]
fn the_guard_names_the_adapter_that_would_be_a_mock_and_not_the_others() {
    for (var, adapter, other) in [
        ("EMAIL_API_KEY", "email", "telephony"),
        ("TELEPHONY_API_KEY", "telephony", "browser"),
        ("BROWSER_API_KEY", "browser", "email"),
    ] {
        let mut env = complete_env();
        env.remove(var);

        let output = boot(&env);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "the server started with a mock {adapter} adapter: {stderr}"
        );
        assert!(stderr.contains(var), "which variable? {stderr}");
        assert!(
            stderr.contains(&format!("{adapter}=MOCK")),
            "the inventory has to name it: {stderr}"
        );
        assert!(
            !stderr.contains(&format!("{other}=MOCK")),
            "{other} was configured and must not be blamed: {stderr}"
        );
    }
}

/// Half a credential is the deployment that believes it is real and is not, so
/// it is a boot failure and not a mock and not a client that 401s at 3am.
#[test]
fn half_a_compound_credential_exits_non_zero_and_names_the_variable() {
    for var in ["TELEPHONY_API_KEY", "BROWSER_API_KEY"] {
        let mut env = complete_env();
        env.insert(var, "one-value-with-no-colon".to_owned());

        let output = boot(&env);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "the server built an adapter from half a credential: {stderr}"
        );
        assert!(stderr.contains(var), "{stderr}");
        // And it says what the value has to look like.
        assert!(stderr.contains("both halves are required"), "{stderr}");
    }
}

/// The line an operator reads on a box that is half integrated.
///
/// The process still exits non-zero — the database in `complete_env` does not
/// exist — but the subscriber is installed and the inventory is logged before
/// anything touches it, which is the point: the inventory must not depend on
/// the rest of the boot succeeding.
#[test]
fn a_partly_real_deployment_says_so_in_one_line_at_boot() {
    let mut env = complete_env();
    env.remove("TELEPHONY_API_KEY");
    env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());

    let output = boot(&env);
    let logged = String::from_utf8_lossy(&output.stdout);

    assert!(
        logged.contains("email=resend"),
        "the real adapters have to be named: {logged}"
    );
    assert!(
        logged.contains("telephony=MOCK"),
        "and so does the one that is not: {logged}"
    );
    assert!(logged.contains("browser=browserbase"), "{logged}");
    // The ports no credential can make real are on the same line, so a line
    // with no MOCK in it cannot be produced by leaving something out.
    assert!(logged.contains("embedder=MOCK"), "{logged}");
}

#[test]
fn a_missing_required_variable_exits_non_zero_and_names_itself() {
    let mut env = complete_env();
    env.remove("DATABASE_URL");

    let output = boot(&env);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "started without a database URL");
    assert!(
        stderr.contains("DATABASE_URL"),
        "the message has to be actionable on its own: {stderr}"
    );
}
