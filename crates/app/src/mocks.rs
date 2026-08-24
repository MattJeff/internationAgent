//! The development fakes, in one file, so `AGENTOS_ALLOW_MOCKS=1` has exactly
//! one thing to point at.
//!
//! The binary may not depend on `agentos-providers` — that is the rule that
//! makes [`Authorized`](crate::gate::Authorized) unforgeable outside this
//! crate — so it cannot name `MockEmailProvider`, cannot name `Arc<dyn
//! EmailProvider>`, and therefore cannot assemble an [`Adapters`] or a
//! [`Ports`] of its own. Rather than widen the manifest and lose the guarantee,
//! the constructors live here.
//!
//! [`adapters`] and [`ports`] are in memory and forget on restart. Nothing they
//! hand out should be reachable in a deployment that has its provider
//! credentials set: `config.rs` refuses to boot with mock adapters unless an
//! operator says out loud that this is a development box.
//!
//! ponytail: the ports with nothing behind them here — payments always, MCP
//! until a tenant is in hand — *refuse* rather than pretend. A fake that
//! returns a plausible payment id is a fake that will one day be believed;
//! `Terminal { code: "not_configured" }` is the honest answer and shows up in
//! the audit trail as one.
//!
//! MCP is the "until" case: [`crate::mcp::Fleet`] is the real adapter, and it
//! is built per turn from the acting tenant's `mcp_servers` rows, because a
//! binding is per-tenant configuration and [`ports`] is built once at boot for
//! every tenant. What is handed out here is what a turn that overrode nothing
//! would get, and refusing is the right answer for that.
//!
//! # The model is here too, and two of the three are real
//!
//! [`llm`] is the same idea one level up: the binary cannot name
//! [`Llm`], `AnthropicLlm` or `CliLlm` either, so the selection lives here and
//! the binary passes it a [`LlmBackend`] it read out of `AGENTOS_LLM`. Only
//! [`LlmBackend::Mock`] is a fake; the other two reason for real, which is why
//! `config.rs` treats anything but `anthropic` as a mock adapter and refuses to
//! boot without `AGENTOS_ALLOW_MOCKS`.

use std::sync::Arc;

use agentos_domain::action::McpTool;
use agentos_domain::ids::IdempotencyKey;
use agentos_domain::money::Money;
use agentos_domain::untrusted::Untrusted;
use agentos_providers::browser::MockBrowser;
use agentos_providers::email::{MockEmailProvider, ProviderMessageId};
use agentos_providers::llm_anthropic::{AnthropicLlm, DEFAULT_MODEL};
use agentos_providers::llm_cli::CliLlm;
use agentos_providers::secrets::MemorySecretStore;
use agentos_providers::telephony::MockTelephony;
use agentos_providers::{ProviderError, Secret};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use crate::effects::{McpCaller, PaymentInstruction, PaymentProvider, Ports};
use crate::provisioning::Adapters;

// The binary holds the value [`llm`] returns and hands it to
// [`Turn::new`](crate::turn::Turn::new), so it has to be able to *name* the
// trait — and it may not depend on `agentos-providers` to do it. Same trade as
// `inbound.rs` makes for `Secret`: one re-export beats widening the manifest.
// `ScriptedLlm` and friends come along so a test in the binary can script a
// model without one either.
pub use agentos_providers::llm::{Llm, LlmResponse, ScriptedLlm, Usage};

/// The signing secret the mock telephony adapter verifies callbacks against.
/// Fixed and public, because a fake secret that has to be configured is a fake
/// secret that stops a development box from booting.
const MOCK_TELEPHONY_TOKEN: &str = "mock-telephony-auth-token";

/// The four adapters [`ProvisioningEngine`](crate::provisioning::ProvisioningEngine)
/// needs, all fake.
///
/// The vault is a plaintext map: `LocalEnvelopeSecretStore` would be the
/// honest development store, and it needs the deployment's master key threaded
/// through — worth doing the day anything reads a secret back out for real.
pub fn adapters() -> Adapters {
    Adapters {
        email: Arc::new(MockEmailProvider::new()),
        telephony: Arc::new(MockTelephony::new(Utc::now(), MOCK_TELEPHONY_TOKEN)),
        browser: Arc::new(MockBrowser::new()),
        secrets: Arc::new(MemorySecretStore::new()),
    }
}

/// The five ports [`Effects`](crate::effects::Effects) and the inbound loop
/// need, all fake.
///
/// The email port is shared with nothing: a mock provider's inbox lives in its
/// own process memory, so an inbound notice recorded by the webhook route can
/// only be fetched back by *this* process's mock. That is a property of running
/// on fakes, not a bug to design around.
pub fn ports() -> Ports {
    Ports {
        email: Arc::new(MockEmailProvider::new()),
        telephony: Arc::new(MockTelephony::new(Utc::now(), MOCK_TELEPHONY_TOKEN)),
        browser: Arc::new(MockBrowser::new()),
        mcp: Arc::new(NotConfigured),
        payments: Arc::new(NotConfigured),
    }
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// Which model an employee reasons with. `AGENTOS_LLM`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LlmBackend {
    /// A scripted fake that answers every turn with [`MOCK_REPLY`] and never
    /// asks for a tool. The default, because it is the only backend that needs
    /// nothing configured and costs nothing to run.
    #[default]
    Mock,
    /// The local `claude` binary, via [`CliLlm`]. Real inference with no API
    /// key — the whole point of it — and testing-only: see that module's docs
    /// for what it is lossy about.
    Cli,
    /// `POST /v1/messages`. Needs [`LlmBackend::API_KEY_VAR`].
    Anthropic,
}

impl LlmBackend {
    /// The variable [`LlmBackend::Anthropic`] cannot run without.
    pub const API_KEY_VAR: &'static str = "ANTHROPIC_API_KEY";

    /// Every accepted spelling, for an error message that tells an operator
    /// what to write instead.
    pub const VALUES: &'static str = "mock, cli, anthropic";

    /// Parse `AGENTOS_LLM`. `None` is a value we do not have a backend for,
    /// which is a boot failure and never a silent fallback to the mock.
    pub fn parse(spec: &str) -> Option<Self> {
        match spec.trim().to_ascii_lowercase().as_str() {
            "mock" => Some(Self::Mock),
            "cli" => Some(Self::Cli),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }

    /// The spelling [`LlmBackend::parse`] accepts back.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Cli => "cli",
            Self::Anthropic => "anthropic",
        }
    }

    /// The variable this backend refuses to start without, if any.
    pub const fn required_var(self) -> Option<&'static str> {
        match self {
            Self::Anthropic => Some(Self::API_KEY_VAR),
            Self::Mock | Self::Cli => None,
        }
    }

    /// How this backend shows up in the "these adapters are not real" warning,
    /// or `None` when it is the real thing.
    ///
    /// The CLI backend is *not* a fake — it does real inference — but it is
    /// documented as testing-only, so a deployment still has to say
    /// `AGENTOS_ALLOW_MOCKS=1` out loud before it runs an employee on somebody's
    /// laptop login.
    pub const fn mock_label(self) -> Option<&'static str> {
        match self {
            Self::Mock => Some("llm (scripted mock)"),
            Self::Cli => Some("llm (local claude CLI)"),
            Self::Anthropic => None,
        }
    }

    /// The model id passed to the provider untouched. One model, deliberately:
    /// picking a cheaper one is an operator's decision and there is nowhere yet
    /// for them to record it.
    pub const fn model(self) -> &'static str {
        DEFAULT_MODEL
    }
}

/// What the scripted backend answers, every turn.
///
/// Says what it is. A mock model that writes a plausible customer reply is a
/// mock that ends up in a demo and then in a thread with a real supplier.
pub const MOCK_REPLY: &str = "(scripted mock model) I have read this message. \
                              This deployment has no real model configured, so there is no \
                              judgement behind this reply — set AGENTOS_LLM=anthropic.";

/// The model this process reasons with.
///
/// `Err` names the variable that is missing. `config.rs` checks the same thing
/// while parsing the environment, so this arm is the belt to its braces: a
/// second caller must not be able to build an `AnthropicLlm` with no key and
/// discover it at the first inbound email.
pub fn llm(backend: LlmBackend, api_key: Option<String>) -> Result<Arc<dyn Llm>, &'static str> {
    Ok(match (backend, api_key) {
        (LlmBackend::Mock, _) => Arc::new(scripted_mock()),
        (LlmBackend::Cli, _) => Arc::new(CliLlm::new()),
        (LlmBackend::Anthropic, Some(key)) => Arc::new(AnthropicLlm::new(Secret::new(key))),
        (LlmBackend::Anthropic, None) => return Err(LlmBackend::API_KEY_VAR),
    })
}

/// A model that answers [`MOCK_REPLY`] forever and never asks for a tool.
///
/// `looping`, not `new`: one employee handles many messages in a process, and a
/// script that runs out turns the eleventh inbound email into `script_exhausted`
/// rather than a reply.
pub fn scripted_mock() -> ScriptedLlm {
    ScriptedLlm::looping(vec![Ok(LlmResponse::text(MOCK_REPLY, Usage::default()))])
}

/// A port with no adapter. Refuses, terminally, every time.
#[derive(Debug)]
struct NotConfigured;

/// What both refusals report. Terminal, not retryable: no amount of waiting
/// configures an adapter that does not exist.
fn refuse() -> ProviderError {
    ProviderError::Terminal {
        code: "not_configured",
    }
}

#[async_trait]
impl McpCaller for NotConfigured {
    async fn call(
        &self,
        tool: &McpTool,
        _arguments: &Value,
    ) -> Result<Untrusted<Value>, ProviderError> {
        tracing::warn!(%tool, "MCP call refused: this build has no MCP adapter");
        Err(refuse())
    }
}

#[async_trait]
impl PaymentProvider for NotConfigured {
    async fn pay(
        &self,
        _key: &IdempotencyKey,
        amount: Money,
        _instruction: &PaymentInstruction,
    ) -> Result<ProviderMessageId, ProviderError> {
        tracing::error!(%amount, "payment refused: this build has no payment adapter");
        Err(refuse())
    }
}

#[cfg(test)]
mod tests {
    use agentos_providers::llm::{Content, LlmRequest};

    use super::*;

    /// The claim that matters: a port with no adapter refuses rather than
    /// inventing a receipt. A mock that "pays" is how a development build ends
    /// up in a demo that everyone believes.
    #[tokio::test]
    async fn the_unimplemented_ports_refuse_terminally() {
        let ports = ports();
        let err = ports
            .payments
            .pay(
                &IdempotencyKey::for_step(
                    agentos_domain::ids::EmployeeId::new_v7(Utc::now()),
                    "test",
                ),
                Money::new(100, agentos_domain::money::Currency::Eur).expect("nonzero"),
                &PaymentInstruction {
                    payee: "someone".to_owned(),
                    memo: "something".to_owned(),
                },
            )
            .await
            .expect_err("a build with no payment adapter must not report a payment");
        assert!(
            !err.is_retryable(),
            "retrying a missing adapter never helps"
        );
        assert_eq!(err.code(), "not_configured");
    }

    #[test]
    fn the_adapters_are_all_present() {
        // A field left out is a `ProvisioningEngine` that panics on the step
        // that needed it; the constructor exists so that is a compile error.
        let _ = adapters();
    }

    // -- the model ---------------------------------------------------------

    #[test]
    fn an_unknown_backend_is_none_rather_than_the_default() {
        for (spec, backend) in [
            ("mock", LlmBackend::Mock),
            ("  CLI ", LlmBackend::Cli),
            ("Anthropic", LlmBackend::Anthropic),
        ] {
            assert_eq!(LlmBackend::parse(spec), Some(backend), "{spec:?}");
            assert_eq!(LlmBackend::parse(backend.name()), Some(backend));
        }
        // The failure that matters: a typo must not quietly become the mock and
        // leave a production deployment answering with MOCK_REPLY.
        for typo in ["", "claude", "openai", "anthropik"] {
            assert_eq!(LlmBackend::parse(typo), None, "{typo:?}");
        }
        assert_eq!(LlmBackend::default(), LlmBackend::Mock);
    }

    #[test]
    fn anthropic_without_a_key_is_refused_by_name() {
        assert_eq!(
            llm(LlmBackend::Anthropic, None).err(),
            Some("ANTHROPIC_API_KEY"),
            "the message has to name the variable an operator has to set"
        );
        assert_eq!(
            LlmBackend::Anthropic.required_var(),
            Some(LlmBackend::API_KEY_VAR)
        );
        assert!(LlmBackend::Mock.required_var().is_none());
        assert!(LlmBackend::Cli.required_var().is_none());

        // And the two that need nothing are buildable with nothing.
        assert!(llm(LlmBackend::Mock, None).is_ok());
        assert!(llm(LlmBackend::Cli, None).is_ok());
        assert!(llm(LlmBackend::Anthropic, Some("sk-ant-x".to_owned())).is_ok());
    }

    #[test]
    fn only_the_real_backend_is_exempt_from_the_mock_warning() {
        assert!(LlmBackend::Anthropic.mock_label().is_none());
        assert!(LlmBackend::Mock.mock_label().is_some());
        // The CLI does real inference and is still not a thing to deploy on.
        assert!(LlmBackend::Cli.mock_label().is_some());
    }

    /// The scripted model never runs out, and says what it is.
    #[tokio::test]
    async fn the_scripted_mock_answers_every_turn_and_admits_it_is_one() {
        let llm = scripted_mock();
        let request = LlmRequest::new("m", "s", 16);

        for turn in 1..=12 {
            let response = llm
                .complete(request.clone())
                .await
                .unwrap_or_else(|e| panic!("turn {turn}: {e}"));
            assert!(!response.stop_reason.wants_tools(), "it asks for no tools");
            assert_eq!(response.content, vec![Content::text(MOCK_REPLY)]);
        }
        assert!(MOCK_REPLY.contains("mock"), "a fake has to say so");
    }

    /// Costs a real CLI turn and needs a logged-in `claude`.
    /// `cargo test -p agentos-app -- --ignored`.
    #[tokio::test]
    #[ignore = "shells out to the real claude binary"]
    async fn the_cli_backend_is_wired_to_something_that_answers() {
        let llm = llm(LlmBackend::Cli, None).expect("the CLI needs no key");
        let response = llm
            .complete(
                LlmRequest::new(LlmBackend::Cli.model(), "Reply with exactly: OK", 16_000)
                    .with_message(agentos_providers::llm::Message::user("say OK")),
            )
            .await
            .expect("the local claude CLI answered");
        assert!(response.usage.total() > 0);
    }
}
