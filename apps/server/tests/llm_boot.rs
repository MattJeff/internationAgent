//! `AGENTOS_LLM`, checked the way an orchestrator checks it: by the exit code.
//!
//! `config.rs` proves `Config::parse` returns the right error. This proves the
//! thing a deployment feels — that a server asked for the real model with no
//! key **exits non-zero at boot**, rather than coming up, answering `/livez`,
//! accepting a week of mail and replying to none of it. That failure mode is
//! invisible to a unit test and expensive to discover in production.
//!
//! Runs the real binary. Neither case reaches the database: both fail while
//! reading the environment.

use std::collections::HashMap;
use std::process::{Command, Output};

/// Everything a good boot needs, on the real model. Cases below change one
/// thing.
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
    for var in [
        "EMAIL_API_KEY",
        "TELEPHONY_API_KEY",
        "BROWSER_API_KEY",
        "EMBEDDER_API_KEY",
    ] {
        env.insert(var, "live-credential".to_owned());
    }
    env
}

/// Boot the real binary with exactly `env` and nothing inherited — an inherited
/// `ANTHROPIC_API_KEY` from the developer's shell would quietly repair the very
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
fn asking_for_the_real_model_without_a_key_exits_non_zero() {
    let mut env = complete_env();
    env.remove("ANTHROPIC_API_KEY");

    let output = boot(&env);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "the server started on a model it cannot reach: {stderr}"
    );
    assert!(
        stderr.contains("ANTHROPIC_API_KEY"),
        "the message has to name the variable to set: {stderr}"
    );
}

#[test]
fn an_unknown_backend_exits_non_zero_rather_than_falling_back_to_the_mock() {
    let mut env = complete_env();
    env.insert("AGENTOS_LLM", "gpt-5".to_owned());

    let output = boot(&env);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "a typo'd backend silently became something: {stderr}"
    );
    assert!(stderr.contains("AGENTOS_LLM"), "{stderr}");
    // And it says what is on the menu.
    assert!(stderr.contains("anthropic"), "{stderr}");
}
