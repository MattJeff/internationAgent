//! The only crate allowed to hold reqwest / aws-sdk / rmcp clients.
//!
//! Every adapter ships with a mock beside it and a shared contract suite. The
//! contract every adapter must satisfy: `ensure` reconciles before it creates,
//! keyed on an idempotency key stamped into the provider's own tag field, so a
//! crashed-and-retried provisioning run never buys a second phone number.
//!
//! # The reconcile-before-create contract
//!
//! Every `ensure` implementation in this crate MUST, in this order:
//!
//! 1. **Look the resource up by tag.** The tag is [`EnsureCtx::tag`] — the
//!    string form of [`EnsureCtx::idempotency_key`] — stamped into whatever
//!    field the provider gives us for free-form labels: Twilio
//!    `friendly_name`, Resend domain name, Browserbase context name, a Stripe
//!    `metadata` entry. If the provider has a native idempotency header, send
//!    that too; it is a second belt, not a replacement for the lookup.
//! 2. **Return the hit.** If exactly one resource carries the tag, return it as
//!    [`Provisioned`] without creating anything. Two hits is a bug in a past
//!    version of the adapter, not something to paper over: return
//!    [`ProviderError::Terminal`] so a human looks at it.
//! 3. **Only then create**, stamping the tag into the same field the lookup
//!    reads. A create that cannot carry the tag is not idempotent and must not
//!    ship.
//!
//! The observable guarantee: calling `ensure` twice with the same
//! [`EnsureCtx`] yields ONE external resource with the SAME `external_id`.
//! [`IdempotencyKey::for_step`] is pure, so a process that crashes between the
//! provider's `201 Created` and our own commit rebuilds the identical key on
//! restart and finds the resource it already paid for. [`EnsureCtx::retry`]
//! bumps `attempt` and deliberately leaves the key alone — that is the whole
//! mechanism.
//!
//! [`FaultMode::FailAfterExternalSuccess`] exists to make chaos tests reproduce
//! exactly that crash window.
//!
//! # The release contract, which is the same discipline pointing the other way
//!
//! Every `release` implementation MUST be **idempotent and tolerant of an
//! already-gone resource**. Releasing twice, or releasing something the
//! provider no longer has, is `Ok(())`: the caller is asserting a desired state
//! ("this must not exist"), and if the state is already true there is nothing
//! to report. A 404 from a delete is success, not a failure.
//!
//! `ensure` reconciles before it creates because a *duplicate* is the expensive
//! mistake; `release` tolerates the missing resource because a *stranded
//! binding nobody may clear* is. The asymmetry in the write order follows:
//! `ensure` records its intent before it calls, `release` clears the binding
//! only after the provider has confirmed. A crash in either gap is repaired by
//! running the same operation again.
//!
//! A provider that genuinely **cannot** release something must say so —
//! `Terminal { code: `[`RELEASE_NOT_SUPPORTED`]` }` — and must not return
//! `Ok(())`. Pretending success clears the binding on a resource that still
//! exists, which is precisely how a thing gets billed forever with nothing left
//! pointing at it.

pub mod browser; // U18
pub mod browser_browserbase;
pub mod cdp;
pub mod email; // U16
pub mod email_resend; // real Resend client
pub mod embedder; // U19
pub mod leads; // the outbound sending platform's list
pub mod llm; // U19
pub mod llm_anthropic; // real /v1/messages client
pub mod llm_cli; // local `claude` CLI backend, for testing without an API key
pub mod secrets;
pub mod signing; // U18
pub mod telephony;
pub mod telephony_twilio; // real Twilio client // U17 // real CDP driver over a websocket

use std::fmt;
use std::time::Duration;

use agentos_domain::ids::{EmployeeId, IdempotencyKey, Slug, TenantId};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// A provider resource we already own: which provider, and its id over there.
///
/// A plain data mirror of the domain binding so adapters never need to depend
/// on the employee state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBinding {
    /// Adapter identity, e.g. `"twilio"`.
    pub provider: String,
    /// The id the provider uses, e.g. a Twilio SID.
    pub external_id: String,
}

/// The result of a successful [`EnsureCtx`]-driven `ensure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    /// Adapter identity, e.g. `"resend"`.
    pub provider: &'static str,
    /// The id the provider uses.
    pub external_id: String,
}

impl Provisioned {
    /// Build a result for `provider` from an id the provider handed back.
    pub fn new(provider: &'static str, external_id: impl Into<String>) -> Self {
        Self {
            provider,
            external_id: external_id.into(),
        }
    }

    /// The owned mirror to persist and to feed back as [`EnsureCtx::existing`].
    pub fn binding(&self) -> ProviderBinding {
        ProviderBinding {
            provider: self.provider.to_owned(),
            external_id: self.external_id.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnsureCtx
// ---------------------------------------------------------------------------

/// Everything an adapter needs to make one provisioning step true.
///
/// `idempotency_key` is CONSTANT across retries of the same step; see the
/// crate-level reconcile-before-create contract.
#[derive(Debug, Clone)]
pub struct EnsureCtx {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Employee being provisioned.
    pub employee_id: EmployeeId,
    /// Human-facing handle, used where a provider wants a readable name.
    pub slug: Slug,
    /// Provisioning step name; also the key material.
    pub step: String,
    /// Stable de-duplication token. Same for every attempt at this step.
    pub idempotency_key: IdempotencyKey,
    /// 0 on the first try, incremented by [`EnsureCtx::retry`].
    pub attempt: u32,
    /// What a previous run recorded, if the engine has it.
    pub existing: Option<ProviderBinding>,
}

impl EnsureCtx {
    /// Build the context for one step, deriving the idempotency key from it.
    ///
    /// The key is derived here and nowhere else so no caller can accidentally
    /// vary it between attempts.
    pub fn new(tenant_id: TenantId, employee_id: EmployeeId, slug: Slug, step: &str) -> Self {
        Self {
            tenant_id,
            employee_id,
            slug,
            step: step.to_owned(),
            idempotency_key: IdempotencyKey::for_step(employee_id, step),
            attempt: 0,
            existing: None,
        }
    }

    /// Attach the binding a previous run persisted.
    #[must_use]
    pub fn with_existing(mut self, existing: ProviderBinding) -> Self {
        self.existing = Some(existing);
        self
    }

    /// The next attempt at the same step. Bumps `attempt`, never the key.
    #[must_use]
    pub fn retry(mut self) -> Self {
        self.attempt += 1;
        self
    }

    /// The value to stamp into the provider's tag field and to search on.
    pub fn tag(&self) -> &str {
        self.idempotency_key.as_str()
    }
}

// ---------------------------------------------------------------------------
// ProviderError
// ---------------------------------------------------------------------------

/// Why an adapter call did not produce a [`Provisioned`].
///
/// The variants are load-bearing: the provisioning engine branches on them, so
/// mapping a transport timeout to `Terminal` would abandon a healthy provider
/// mid-run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// A timeout or a 5xx. The provider is fine, we were unlucky.
    #[error("provider unavailable, retry after {after:?}")]
    Retryable {
        /// Suggested backoff before the next attempt.
        after: Duration,
    },
    /// We are being throttled; `retry_after` is the provider's own advice.
    #[error("provider rate limited, retry after {retry_after:?}")]
    RateLimited {
        /// Delay the provider asked for.
        retry_after: Duration,
    },
    /// Not an error, a wait: a Twilio bundle in human review, a Meta display
    /// name approval. The resource exists; someone external must bless it.
    #[error("provider is waiting on an external process ({poll_ref}), expected by {expected_by}")]
    PendingExternal {
        /// Handle to poll or to match an inbound webhook against.
        poll_ref: String,
        /// When to escalate if it is still pending.
        expected_by: DateTime<Utc>,
    },
    /// A 4xx we caused. Retrying makes it worse.
    #[error("provider rejected the request: {code}")]
    Terminal {
        /// Stable, low-cardinality reason, safe as a metric label.
        code: &'static str,
    },
}

/// The `code` a provider returns from `release` when it has no way to give the
/// resource back.
///
/// Not a transport failure and not something a retry fixes: the resource is
/// still there, still billed, and the binding must stay put so somebody can
/// still find it. The engine records it as a failed release rather than
/// clearing the binding.
pub const RELEASE_NOT_SUPPORTED: &str = "release_not_supported";

/// Every [`ProviderError::code`] whose error [`ProviderError::is_retryable`]
/// calls retryable — the same rule, in the one form SQL can read.
///
/// Two entries and not forty, and that asymmetry is the whole reason this
/// exists. The terminal codes are open — any adapter may invent one — so a
/// `NOT IN (…)` list would be wrong the day somebody adds a `Terminal` arm,
/// and wrong in the expensive direction: an unknown code would read as
/// retryable and buy five provider calls. The retryable ones are closed by
/// `is_retryable`'s own `matches!`, so listing *those* is wrong only in the
/// direction of one attempt instead of five, and
/// `the_retryable_code_list_is_the_same_rule_as_is_retryable` fails the build
/// if the two ever disagree.
///
/// The reader is `CLAIM_SQL` in `apps/server/src/loops/provisioning.rs`, which
/// binds it rather than spelling it: a rule in two languages is a rule that
/// diverges in silence, which is exactly what `RELEASE_NOT_SUPPORTED` above is
/// bound for on the release side.
pub const RETRYABLE_CODES: [&str; 2] = ["retryable", "rate_limited"];

impl ProviderError {
    /// Default backoff when the provider gives no advice.
    const DEFAULT_BACKOFF: Duration = Duration::from_secs(1);
    /// Default cool-off when a 429 carries no `Retry-After`.
    const DEFAULT_COOLOFF: Duration = Duration::from_secs(5);

    /// A transport timeout. Always retryable — the request may even have landed,
    /// which is exactly what reconcile-before-create protects against.
    pub fn timeout() -> Self {
        Self::Retryable {
            after: Self::DEFAULT_BACKOFF,
        }
    }

    /// Classify an HTTP response. `retry_after` is the parsed `Retry-After`
    /// header, if the provider sent one.
    pub fn from_status(status: u16, retry_after: Option<Duration>) -> Self {
        match status {
            429 => Self::RateLimited {
                retry_after: retry_after.unwrap_or(Self::DEFAULT_COOLOFF),
            },
            408 | 425 | 500..=599 => Self::Retryable {
                after: retry_after.unwrap_or(Self::DEFAULT_BACKOFF),
            },
            400 => Self::Terminal {
                code: "bad_request",
            },
            401 => Self::Terminal {
                code: "unauthorized",
            },
            403 => Self::Terminal { code: "forbidden" },
            404 => Self::Terminal { code: "not_found" },
            409 => Self::Terminal { code: "conflict" },
            422 => Self::Terminal {
                code: "unprocessable",
            },
            _ => Self::Terminal {
                code: "client_error",
            },
        }
    }

    /// Whether the engine should try this step again on a backoff.
    ///
    /// `PendingExternal` is not retryable: nothing is retried, the step waits.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable { .. } | Self::RateLimited { .. })
    }

    /// Low-cardinality label for metrics. Never interpolate provider text here.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Retryable { .. } => "retryable",
            Self::RateLimited { .. } => "rate_limited",
            Self::PendingExternal { .. } => "pending_external",
            Self::Terminal { code } => code,
        }
    }
}

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

/// An API key, password or token that must never reach a log line, a database
/// row, an error message or an LLM context window.
///
/// Deliberately missing: `Serialize`, `Display`, `Deref`, `Clone`, and any
/// `Debug` that reveals anything. The only way out is
/// [`Secret::expose_for_transport`], named to be uncomfortable at a review.
/// The inner [`SecretString`] zeroizes its buffer on drop.
pub struct Secret(SecretString);

impl Secret {
    /// What a secret renders as anywhere it is printed.
    pub const REDACTED: &'static str = "[redacted]";

    /// Wrap a value that came from a secret store or an operator.
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// Hand the plaintext to an outbound request, and to nothing else.
    ///
    /// Every call site is a place a key can leak: put the result straight into
    /// the header or body being sent and never bind it to a named variable
    /// that outlives that expression.
    pub fn expose_for_transport(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Secret::REDACTED)
    }
}

// ---------------------------------------------------------------------------
// FaultMode
// ---------------------------------------------------------------------------

/// Fault injection every mock adapter embeds, so chaos tests can aim at a
/// specific window instead of a specific provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FaultMode {
    /// Behave.
    #[default]
    Healthy,
    /// Fail before the provider is touched: nothing was created out there.
    FailBefore(ProviderError),
    /// Fail AFTER the simulated external success: the resource exists and we
    /// never learned its id. This is the crash window that duplicates a paid
    /// resource unless `ensure` reconciles before it creates — point it at a
    /// step, run the step twice, and assert one `external_id`.
    FailAfterExternalSuccess(ProviderError),
}

impl FaultMode {
    /// Call at the top of a mock `ensure`, before any simulated work.
    pub fn check_before(&self) -> Result<(), ProviderError> {
        match self {
            Self::FailBefore(e) => Err(e.clone()),
            _ => Ok(()),
        }
    }

    /// Call after the mock has recorded its resource but before returning it.
    pub fn check_after(&self) -> Result<(), ProviderError> {
        match self {
            Self::FailAfterExternalSuccess(e) => Err(e.clone()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EnsureCtx {
        EnsureCtx::new(
            TenantId::new_v7(Utc::now()),
            EmployeeId::new_v7(Utc::now()),
            Slug::parse("ada").unwrap(),
            "provision_email",
        )
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let rendered = format!("{:?}", Secret::new("hunter2"));
        assert_eq!(rendered, Secret::REDACTED);
        assert!(!rendered.contains("hunter2"));

        // Also inside a struct, which is how it will actually get logged.
        #[derive(Debug)]
        struct Config {
            #[allow(dead_code)]
            api_key: Secret,
        }
        let nested = format!(
            "{:?}",
            Config {
                api_key: Secret::new("hunter2")
            }
        );
        assert!(!nested.contains("hunter2"), "{nested}");
        assert!(nested.contains(Secret::REDACTED), "{nested}");
    }

    #[test]
    fn expose_is_the_only_way_out() {
        assert_eq!(Secret::new("hunter2").expose_for_transport(), "hunter2");
    }

    #[test]
    fn timeout_is_retryable_and_400_is_terminal() {
        let timeout = ProviderError::timeout();
        assert!(timeout.is_retryable());
        assert!(matches!(timeout, ProviderError::Retryable { .. }));

        let bad_request = ProviderError::from_status(400, None);
        assert!(!bad_request.is_retryable());
        assert_eq!(bad_request.code(), "bad_request");

        assert!(ProviderError::from_status(503, None).is_retryable());
        assert!(ProviderError::from_status(429, None).is_retryable());
        assert_eq!(
            ProviderError::from_status(429, Some(Duration::from_secs(30))),
            ProviderError::RateLimited {
                retry_after: Duration::from_secs(30)
            }
        );
        assert_eq!(ProviderError::from_status(404, None).code(), "not_found");
    }

    /// [`RETRYABLE_CODES`] is a copy of [`ProviderError::is_retryable`] that a
    /// `WHERE` clause can read, and a copy is a thing that drifts. This is the
    /// test that makes drifting fail the build rather than quietly re-buying a
    /// phone number four times.
    ///
    /// Every variant, both directions: a code in the list whose error is not
    /// retryable would spend the budget it was added to save, and a retryable
    /// error whose code is missing would be parked after one attempt — which is
    /// the failure this whole change is about not causing.
    #[test]
    fn the_retryable_code_list_is_the_same_rule_as_is_retryable() {
        let every_variant = [
            ProviderError::timeout(),
            ProviderError::from_status(429, None),
            ProviderError::from_status(503, None),
            ProviderError::from_status(400, None),
            ProviderError::from_status(401, None),
            ProviderError::from_status(404, None),
            ProviderError::PendingExternal {
                poll_ref: "BU123".into(),
                expected_by: Utc::now(),
            },
            ProviderError::Terminal {
                code: RELEASE_NOT_SUPPORTED,
            },
            // A code no adapter has invented yet. It must not be retryable,
            // which is the direction an open `Terminal` set has to be wrong in.
            ProviderError::Terminal {
                code: "something_a_future_adapter_returns",
            },
        ];
        for err in every_variant {
            assert_eq!(
                RETRYABLE_CODES.contains(&err.code()),
                err.is_retryable(),
                "{} is on the wrong side of RETRYABLE_CODES",
                err.code()
            );
        }

        // Both spellings are reachable, so neither is a typo nobody would
        // notice: a list that matched nothing would pass the loop above.
        assert_eq!(ProviderError::timeout().code(), RETRYABLE_CODES[0]);
        assert_eq!(
            ProviderError::from_status(429, None).code(),
            RETRYABLE_CODES[1]
        );
    }

    #[test]
    fn pending_external_is_a_wait_not_a_retry() {
        let pending = ProviderError::PendingExternal {
            poll_ref: "BU123".into(),
            expected_by: Utc::now(),
        };
        assert!(!pending.is_retryable());
        assert_eq!(pending.code(), "pending_external");
    }

    #[test]
    fn idempotency_key_is_constant_across_attempts() {
        let first = ctx();
        let second = first.clone().retry().retry();
        assert_eq!(second.attempt, 2);
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_eq!(first.tag(), second.tag());
    }

    #[test]
    fn fault_mode_targets_one_window_at_a_time() {
        let after = FaultMode::FailAfterExternalSuccess(ProviderError::timeout());
        assert!(after.check_before().is_ok());
        assert!(after.check_after().is_err());

        let before = FaultMode::FailBefore(ProviderError::timeout());
        assert!(before.check_before().is_err());
        assert!(before.check_after().is_ok());

        assert!(FaultMode::default().check_before().is_ok());
        assert!(FaultMode::default().check_after().is_ok());
    }
}
