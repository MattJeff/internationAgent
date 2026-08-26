//! The outbound sending platform: hand it a prospect, and ask it who told it to
//! stop.
//!
//! Until 2026-09-01 the founder loads Smartlead by hand and
//! [`agentos_app::queue::csv`] is the whole delivery. From 2026-09-01 there is
//! an API. This is the port for it, and the reason it is a port rather than a
//! second `csv`-shaped function is that a file has no failure modes worth
//! modelling and an HTTP call is nothing but failure modes — a 429, a partial
//! batch, a replay.
//!
//! # The row shape, which is the whole seam
//!
//! [`LeadSink::stage`] takes **`&[(&str, &str)]`: column name, value, in the
//! producer's own order.** Not a struct with eight named fields. That is not
//! laziness about types, it is the one shape that keeps the producer from having
//! to know which sink it is feeding:
//!
//! * `agentos_app::queue::COLUMNS` and `Lead::fields()` pair index for index,
//!   and `queue::csv` is already a fold over exactly that pair. An adapter here
//!   reads the same pair. **Both sinks name the same ten things and neither can
//!   name an eleventh**, because there is only one array of names in the
//!   workspace and it is not in this crate.
//! * This crate cannot depend on `agentos-app` — the dependency runs the other
//!   way — so a struct here would be a *second* spelling of those ten names,
//!   sitting one crate away from the first, with nothing but a code review
//!   holding them level. The day somebody adds `linkedin_profile` for real, the
//!   struct version compiles and silently drops it.
//! * A column the adapter does not recognise is not an error and not a
//!   guess: it goes to the platform's own custom-variable bag, which is where
//!   `objet_email` and `angle_email` already live in the founder's uploads.
//!
//! What this costs: the adapter cannot be told at compile time that `email` is
//! present. It has to look, and refuse with
//! [`ProviderError::Terminal`]`{ code: `[`NO_ADDRESS`]` }` when it is not. That
//! is one check in one place, against ten strings that came out of a
//! `Lead` whose address is an `EmailAddress` — so it is a belt on a brace, and
//! the alternative was the wrong shape.
//!
//! # `stage`, and deliberately not `send`
//!
//! Adding a lead to a **paused** campaign stages it; adding to an **active** one
//! starts mailing on the next schedule tick. Which of those happens is a
//! property of the campaign an operator configured over there, and no argument
//! to this method can discover it. So the method is named for the weaker claim
//! and every caller must assume the stronger one — `agentos_app` asks the Policy
//! Gate for an `Action::EmailSend` before every call, because the honest reading
//! of "we handed a stranger's address to a mailer" is that the mail is sent.
//!
//! # Idempotence is the caller's key, and it is not the only lock
//!
//! `stage` is idempotent on `key`, the same contract
//! [`crate::email::EmailProvider::send`] carries: the same key must yield the
//! same handle and must not create a second lead. `agentos_app::effects` derives
//! that key from the gate's `decision_id`, so a retried token cannot buy a
//! second copy of the same email to the same stranger.
//!
//! That lock is the *weakest* of the three on this path and it is stated here so
//! nobody mistakes it for the strong one. The strong one is
//! `contacts.next_follow_up_at`, written by `queue::record_queued` and committed
//! before anything reaches this trait; the third is the platform's own duplicate
//! detection. See `agentos_app::queue`.
//!
//! # The return trip
//!
//! [`LeadSink::opted_out`] is the half that makes the whole thing lawful. A
//! person who clicks unsubscribe in a mail that left through this port has told
//! *the platform*, and the platform is not our suppression list. Nothing about
//! that click reaches `suppressions` unless something goes and asks — so this
//! method exists, `agentos_app::queue::reconcile_opt_outs` is its only caller,
//! and it runs **before** the queue is planned rather than on a cadence, because
//! the moment the answer matters is the moment a file is about to be built.

use agentos_domain::ids::IdempotencyKey;
use agentos_domain::message::ProviderRef;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::{FaultMode, ProviderError};

/// The column every row must carry, because it is the only one that names a
/// person. Spelled here and in `agentos_app::queue::COLUMNS`, and a test in
/// that module asserts the two agree.
pub const EMAIL_COLUMN: &str = "email";

/// [`ProviderError::Terminal`] code for a row with no [`EMAIL_COLUMN`] in it, or
/// an empty one.
///
/// Unreachable through `agentos_app::queue`, whose `Lead` holds a parsed
/// `EmailAddress` — which is exactly why it is a named code rather than a panic:
/// if it ever fires, the producer changed and the audit trail should say so in a
/// word an operator can grep for.
pub const NO_ADDRESS: &str = "lead_without_address";

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// A platform that holds a list of people and mails them.
///
/// One method to put somebody on the list, one to ask who has asked to come off
/// it. There is deliberately no method to *remove* anybody: an unsubscribe is
/// recorded on our side as a `suppressions` row, which is append-only and
/// deactivates the contact by trigger, and asking the platform to forget them
/// would destroy the evidence that they asked.
#[async_trait]
pub trait LeadSink: Send + Sync {
    /// Put one prospect on the list.
    ///
    /// `row` is `(column name, value)` in the producer's order — see the module
    /// docs for why this is a slice of pairs and not a struct. It must contain
    /// [`EMAIL_COLUMN`]; an adapter that cannot find it answers
    /// [`ProviderError::Terminal`]`{ code: `[`NO_ADDRESS`]` }` rather than
    /// staging a row nobody can be identified by.
    ///
    /// Idempotent on `key`: the same key returns the same [`ProviderRef`] and
    /// must not create a second lead.
    async fn stage(
        &self,
        key: &IdempotencyKey,
        row: &[(&str, &str)],
    ) -> Result<ProviderRef, ProviderError>;

    /// Every address the platform has been told to stop mailing.
    ///
    /// The whole list, not a delta. `agentos_store::revenue::suppress` is
    /// `ON CONFLICT DO NOTHING`, so re-recording an opt-out we already hold
    /// costs one index probe and cannot go wrong — whereas a delta needs a
    /// cursor, and a cursor that is ever wrong by one loses somebody's
    /// unsubscribe permanently. The wrong direction to be lazy about.
    ///
    /// ponytail: O(everyone who ever unsubscribed) per call, on a list of ~1,615
    /// prospects. Ask for a delta the day the whole list stops fitting in one
    /// response — and give it a cursor stored in the database, not in a process.
    async fn opted_out(&self) -> Result<Vec<String>, ProviderError>;
}

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

/// In-memory [`LeadSink`], keyed the way a real one must be.
///
/// It is not a convenience for tests that did not want to think about the
/// network: `staged` is a map from idempotency key to handle, so the mock
/// *enforces* the idempotence contract rather than merely tolerating it, and a
/// caller that varies the key when it should not gets two rows here exactly as
/// it would get two emails out there.
pub struct MockLeadSink {
    fault: FaultMode,
    state: Mutex<MockState>,
}

#[derive(Default)]
struct MockState {
    /// idempotency key -> handle. The contract, as a data structure.
    staged: BTreeMap<String, ProviderRef>,
    /// The address each staged row named, in the order they arrived.
    addresses: Vec<String>,
    /// What [`LeadSink::opted_out`] answers.
    opted_out: Vec<String>,
    next: u64,
}

impl Default for MockLeadSink {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLeadSink {
    /// Adapter identity, as recorded in a handle.
    pub const PROVIDER: &'static str = "mock-leads";

    /// A healthy mock.
    pub fn new() -> Self {
        Self::with_fault(FaultMode::Healthy)
    }

    /// A mock that fails in a chosen window. [`FaultMode::FailAfterExternalSuccess`]
    /// is the interesting one here: the lead exists over there and the caller
    /// never learned its handle, which is the crash the idempotency key repairs.
    pub fn with_fault(fault: FaultMode) -> Self {
        Self {
            fault,
            state: Mutex::new(MockState::default()),
        }
    }

    /// Tell the mock somebody has unsubscribed, the way a person clicking a
    /// link in a real campaign would.
    pub fn seed_opt_out(&self, address: impl Into<String>) {
        self.state
            .lock()
            .expect("mock state poisoned")
            .opted_out
            .push(address.into());
    }

    /// How many distinct leads actually exist. The duplicate-resource
    /// assertion: this must not grow when the same key is replayed.
    pub fn staged_count(&self) -> usize {
        self.state.lock().expect("mock state poisoned").staged.len()
    }

    /// Every address staged, in arrival order.
    pub fn staged_addresses(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .addresses
            .clone()
    }
}

#[async_trait]
impl LeadSink for MockLeadSink {
    async fn stage(
        &self,
        key: &IdempotencyKey,
        row: &[(&str, &str)],
    ) -> Result<ProviderRef, ProviderError> {
        self.fault.check_before()?;

        // The check a real adapter owes, in the place a real adapter owes it:
        // before anything is created, and named rather than panicked.
        let address = row
            .iter()
            .find(|(name, _)| *name == EMAIL_COLUMN)
            .map(|(_, value)| *value)
            .filter(|value| !value.is_empty())
            .ok_or(ProviderError::Terminal { code: NO_ADDRESS })?;

        let mut state = self.state.lock().expect("mock state poisoned");
        if let Some(existing) = state.staged.get(key.as_str()) {
            return Ok(existing.clone());
        }

        state.next += 1;
        let handle = ProviderRef::new(format!("lead_{:04}", state.next));
        state.staged.insert(key.as_str().to_owned(), handle.clone());
        state.addresses.push(address.to_owned());
        drop(state);

        // The lead now exists out there. Crashing here is the window that buys a
        // second one — unless the lookup above runs first next time.
        self.fault.check_after()?;
        Ok(handle)
    }

    async fn opted_out(&self) -> Result<Vec<String>, ProviderError> {
        self.fault.check_before()?;
        Ok(self
            .state
            .lock()
            .expect("mock state poisoned")
            .opted_out
            .clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::EmployeeId;
    use chrono::Utc;

    use super::*;

    fn key(step: &str) -> IdempotencyKey {
        IdempotencyKey::for_step(EmployeeId::new_v7(Utc::now()), step)
    }

    fn row<'a>(email: &'a str, subject: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("email", email),
            ("first_name", ""),
            ("company_name", "SafetyWing"),
            ("objet_email", subject),
        ]
    }

    /// The contract the whole port exists for: one key, one lead, however many
    /// times the caller asks.
    #[tokio::test]
    async fn one_key_stages_one_lead() {
        let sink = MockLeadSink::new();
        let key = key("stage:1");

        let first = sink
            .stage(&key, &row("a@example.com", "s"))
            .await
            .expect("stage");
        let second = sink
            .stage(&key, &row("a@example.com", "s"))
            .await
            .expect("replay");

        assert_eq!(first, second, "a replayed key must return the same handle");
        assert_eq!(sink.staged_count(), 1, "and must not create a second lead");
    }

    /// The crash window. The lead exists, we never learned its handle, and the
    /// retry finds it rather than buying another.
    #[tokio::test]
    async fn a_crash_after_the_platform_said_yes_does_not_buy_a_second_lead() {
        let sink =
            MockLeadSink::with_fault(FaultMode::FailAfterExternalSuccess(ProviderError::timeout()));
        let key = key("stage:1");

        let err = sink
            .stage(&key, &row("a@example.com", "s"))
            .await
            .expect_err("the fault fires after the lead exists");
        assert!(err.is_retryable());
        assert_eq!(sink.staged_count(), 1, "it exists over there");

        // Same key, healthy adapter: the lookup finds what the crashed run made.
        let healthy = MockLeadSink::new();
        healthy
            .stage(&key, &row("a@example.com", "s"))
            .await
            .expect("stage");
        healthy
            .stage(&key, &row("a@example.com", "s"))
            .await
            .expect("stage again");
        assert_eq!(healthy.staged_count(), 1);
    }

    /// A different key is a different person's mail, so it is a different lead.
    #[tokio::test]
    async fn different_keys_are_different_leads() {
        let sink = MockLeadSink::new();
        sink.stage(&key("stage:1"), &row("a@example.com", "s"))
            .await
            .expect("stage");
        sink.stage(&key("stage:2"), &row("b@example.com", "s"))
            .await
            .expect("stage");
        assert_eq!(sink.staged_count(), 2);
        assert_eq!(sink.staged_addresses(), ["a@example.com", "b@example.com"]);
    }

    /// The one refusal the row shape makes possible, refused by name.
    #[tokio::test]
    async fn a_row_with_no_address_is_refused_by_name() {
        let sink = MockLeadSink::new();

        for bad in [vec![("first_name", "Ada")], vec![("email", "")]] {
            let err = sink
                .stage(&key("stage:1"), &bad)
                .await
                .expect_err("a row nobody can be identified by");
            assert_eq!(err.code(), NO_ADDRESS);
        }
        assert_eq!(sink.staged_count(), 0, "and nothing was created");
    }

    #[tokio::test]
    async fn the_opt_out_list_comes_back_whole() {
        let sink = MockLeadSink::new();
        assert!(sink.opted_out().await.expect("empty").is_empty());

        sink.seed_opt_out("stop@example.com");
        assert_eq!(
            sink.opted_out().await.expect("list"),
            ["stop@example.com"],
            "an unsubscribe on the platform has to be readable from here, or it \
             never reaches our own suppression list"
        );
    }
}
