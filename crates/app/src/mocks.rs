//! The development fakes, in one file, so `AGENTOS_ALLOW_MOCKS=1` has exactly
//! one thing to point at.
//!
//! The binary may not depend on `agentos-providers` — that is the rule that
//! makes [`Authorized`](crate::gate::Authorized) unforgeable outside this
//! crate — so it cannot name `MockEmailProvider`, cannot name `Arc<dyn
//! EmailProvider>`, and therefore cannot assemble an [`Adapters`] or a
//! [`Ports`] of its own. Rather than widen the manifest and lose the guarantee,
//! the two constructors live here.
//!
//! Everything below is in memory and forgets on restart. Nothing here should be
//! reachable in a deployment that has its provider credentials set: `config.rs`
//! refuses to boot with mock adapters unless an operator says out loud that
//! this is a development box.
//!
//! ponytail: the two ports with no adapter anywhere — MCP and payments —
//! *refuse* rather than pretend. A fake that returns a plausible payment id is
//! a fake that will one day be believed; `Terminal { code: "not_configured" }`
//! is the honest answer and shows up in the audit trail as one.

use std::sync::Arc;

use agentos_domain::action::McpTool;
use agentos_domain::ids::IdempotencyKey;
use agentos_domain::money::Money;
use agentos_domain::untrusted::Untrusted;
use agentos_providers::ProviderError;
use agentos_providers::browser::MockBrowser;
use agentos_providers::email::{MockEmailProvider, ProviderMessageId};
use agentos_providers::secrets::MemorySecretStore;
use agentos_providers::telephony::MockTelephony;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use crate::effects::{McpCaller, PaymentInstruction, PaymentProvider, Ports};
use crate::provisioning::Adapters;

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
}
