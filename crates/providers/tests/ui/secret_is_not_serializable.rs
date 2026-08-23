//! A struct holding a `Secret` must not be serializable — that is how an API
//! key ends up in a JSON log line, an audit row or an LLM context window.

use agentos_providers::Secret;

#[derive(serde::Serialize)]
struct ProviderConfig {
    api_key: Secret,
}

fn main() {}
