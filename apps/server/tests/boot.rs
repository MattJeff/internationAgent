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
    ]);
    for var in [
        "EMAIL_API_KEY",
        "TELEPHONY_API_KEY",
        "BROWSER_API_KEY",
        "LLM_API_KEY",
        "EMBEDDER_API_KEY",
    ] {
        env.insert(var, "live-credential".to_owned());
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
