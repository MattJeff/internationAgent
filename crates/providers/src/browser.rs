//! Browser adapter: a persistent, isolated browser per employee.
//!
//! # Why a session is a provisioned resource and not a cheap handle
//!
//! Chrome keeps cookies, localStorage, IndexedDB and saved logins in the
//! profile directory named by `--user-data-dir`. That flag is a **process**
//! argument: one running Chrome, one profile. CDP's
//! `Target.createBrowserContext` does give a clean, isolated context inside an
//! already-running process, but it is incognito-shaped — it is destroyed with
//! the browser and writes nothing to the profile. So it buys **isolation
//! WITHOUT persistence**.
//!
//! An employee that must stay logged into a supplier portal between tasks needs
//! persistence *and* isolation from every other employee. With Chrome's actual
//! constraints that leaves exactly one self-hosted answer: **one browser
//! process per employee**, each started with its own `--user-data-dir`. A
//! session is therefore a unit of infrastructure with a memory footprint and a
//! lifetime, not a free object.
//!
//! The trait is shaped to say so:
//!
//! * There is no `new_session()`. The only way to get a context is
//!   [`BrowserProvider::ensure_context`], which takes an [`EnsureCtx`] and is
//!   subject to the crate's reconcile-before-create contract — the same
//!   treatment as buying a phone number, because it costs about as much.
//! * [`BrowserSession`] carries the `user_data_dir` that the process was
//!   started with. `None` means an ephemeral context: legitimate for a hosted
//!   provider that persists elsewhere (Browserbase contexts) or for a one-shot
//!   scrape, and a bug for anything that has to stay logged in.
//! * [`BrowserProvider::act`] takes a `&BrowserSession` rather than creating
//!   one, so no call site can quietly conjure a browser.
//!
//! # Why [`BrowserStep::Fill`] takes a `&Secret`
//!
//! A plan is data: it gets logged, persisted, replayed and — for an
//! LLM-authored plan — round-tripped through a model. A password inside a plan
//! that is a `String` is a password in all of those places. `Fill` therefore
//! holds a [`&Secret`](Secret), which has no `Display`, no `Serialize` and a
//! `Debug` that prints `[redacted]`. The plaintext leaves the vault only inside
//! the adapter, on the way into the DOM field, and the model that decided
//! "type the password here" never sees the password.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use agentos_domain::ids::EmployeeId;
use async_trait::async_trait;
use url::Url;

use crate::{EnsureCtx, FaultMode, ProviderBinding, ProviderError, Provisioned, Secret};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A browser context we already own, ready to be driven.
///
/// Obtained by pairing an employee with the binding
/// [`BrowserProvider::ensure_context`] returned. See the module docs for why
/// this is an expensive, per-employee thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSession {
    /// The employee whose browser this is. One employee, one process.
    pub employee_id: EmployeeId,
    /// Provider and context id from [`BrowserProvider::ensure_context`].
    pub binding: ProviderBinding,
    /// The `--user-data-dir` the process was started with, when self-hosted.
    ///
    /// `None` = the context does not survive the process. Fine for a one-shot
    /// scrape or a provider that persists state its own way; wrong for anything
    /// that must stay signed in.
    pub user_data_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Steps and outcomes
// ---------------------------------------------------------------------------

/// One thing to do in a browser. Closed on purpose: an open-ended
/// "run this script" variant is a hole through every policy check upstream.
///
/// Borrowed rather than owned so a step can point at a [`Secret`] the caller
/// holds, without the secret ever being copied into the plan.
#[derive(Debug)]
pub enum BrowserStep<'a> {
    /// Navigate to an absolute URL.
    Goto(&'a Url),
    /// Click the first match of a CSS selector.
    Click(&'a str),
    /// Type visible text into a field. Anything here may be logged.
    Type {
        /// CSS selector of the field.
        sel: &'a str,
        /// The literal text. Not for credentials — use [`BrowserStep::Fill`].
        text: &'a str,
    },
    /// Type a credential into a field.
    ///
    /// The whole point of this variant: the value is a [`Secret`], so it cannot
    /// be printed, serialised or handed to a model, and the plaintext exists
    /// only between the vault and the keystroke.
    Fill {
        /// CSS selector of the field.
        sel: &'a str,
        /// The credential.
        secret: &'a Secret,
    },
    /// Capture the viewport as a PNG.
    Screenshot,
}

/// What a [`BrowserStep`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserOutcome {
    /// Navigation finished; the URL after any redirects.
    Navigated(Url),
    /// The step ran and produced nothing worth returning.
    Done,
    /// PNG bytes.
    Screenshot(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Provision and drive a browser for one employee.
#[async_trait]
pub trait BrowserProvider: Send + Sync {
    /// Make the employee's browser context exist, exactly once.
    ///
    /// Reconcile-before-create, as in the crate docs: look the context up by
    /// [`EnsureCtx::tag`] (Browserbase context name, or the profile directory
    /// name for self-hosted Chrome), return the hit, and only then create.
    async fn ensure_context(&self, ctx: &EnsureCtx) -> Result<Provisioned, ProviderError>;

    /// Run one step in an existing session.
    async fn act(
        &self,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError>;

    /// Destroy the context: stop the process, drop the profile directory, stop
    /// paying for the seat.
    ///
    /// Idempotent and tolerant of a context that is already gone — see the
    /// crate-level release contract. `Ok(())` means "no such context exists any
    /// more", which is equally true whether this call destroyed it or a
    /// previous one did.
    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError>;
}

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

/// Provider name the mock reports.
pub const MOCK_PROVIDER: &str = "mock-browser";

#[derive(Debug, Default)]
struct MockState {
    fault: FaultMode,
    /// tag -> context id. A map is the honest model of "at most one resource
    /// carries the tag": the duplicate the real adapter must reject with
    /// `Terminal` is unrepresentable here.
    contexts: BTreeMap<String, String>,
    created: u32,
    log: Vec<String>,
}

/// In-memory [`BrowserProvider`]. Records every step so a test can assert on
/// what would have been sent — and on what was not.
#[derive(Debug, Default)]
pub struct MockBrowser {
    state: Mutex<MockState>,
}

impl MockBrowser {
    /// A healthy mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Point a fault at a specific window; see [`FaultMode`].
    pub fn set_fault(&self, fault: FaultMode) {
        self.lock().fault = fault;
    }

    /// Every step this mock was asked to run, oldest first.
    ///
    /// Secrets are rendered as [`Secret::REDACTED`] — the log is what a real
    /// adapter's tracing spans would carry.
    pub fn log(&self) -> Vec<String> {
        self.lock().log.clone()
    }

    /// How many contexts were actually created. The number that must stay at 1
    /// across a crash-and-retry.
    pub fn created(&self) -> u32 {
        self.lock().created
    }

    /// How many contexts still exist. Unlike [`Self::created`] this goes down
    /// again: it is the assertion that a release actually released something.
    pub fn context_count(&self) -> usize {
        self.lock().contexts.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl BrowserProvider for MockBrowser {
    async fn ensure_context(&self, ctx: &EnsureCtx) -> Result<Provisioned, ProviderError> {
        let mut state = self.lock();
        state.fault.check_before()?;

        // What a previous run persisted needs no round trip at all.
        if let Some(existing) = &ctx.existing {
            return Ok(Provisioned::new(
                MOCK_PROVIDER,
                existing.external_id.clone(),
            ));
        }
        // Reconcile: the tag is the context name, so the lookup is a name
        // lookup. Return the hit without creating and without tripping
        // `check_after` — a fault aimed at the create window must not make an
        // already-created context unreachable forever.
        if let Some(id) = state.contexts.get(ctx.tag()) {
            return Ok(Provisioned::new(MOCK_PROVIDER, id.clone()));
        }

        state.created += 1;
        let id = format!("ctx-{}", state.created);
        state.contexts.insert(ctx.tag().to_owned(), id.clone());
        // The crash window: the context exists over there, and we are about to
        // lose the id. The lookup above is what makes the retry free.
        state.fault.check_after()?;
        Ok(Provisioned::new(MOCK_PROVIDER, id))
    }

    async fn act(
        &self,
        session: &BrowserSession,
        step: BrowserStep<'_>,
    ) -> Result<BrowserOutcome, ProviderError> {
        let mut state = self.lock();
        state.fault.check_before()?;

        let ctx = &session.binding.external_id;
        let (line, outcome) = match step {
            BrowserStep::Goto(url) => (
                format!("{ctx} goto {url}"),
                BrowserOutcome::Navigated(url.clone()),
            ),
            BrowserStep::Click(sel) => (format!("{ctx} click {sel}"), BrowserOutcome::Done),
            BrowserStep::Type { sel, text } => {
                (format!("{ctx} type {sel} {text}"), BrowserOutcome::Done)
            }
            // The keystrokes happen; the plaintext does not reach the log.
            BrowserStep::Fill { sel, secret } => {
                let _typed = secret.expose_for_transport();
                (
                    format!("{ctx} fill {sel} {}", Secret::REDACTED),
                    BrowserOutcome::Done,
                )
            }
            BrowserStep::Screenshot => (
                format!("{ctx} screenshot"),
                BrowserOutcome::Screenshot(b"\x89PNG".to_vec()),
            ),
        };
        state.log.push(line);
        state.fault.check_after()?;
        Ok(outcome)
    }

    async fn release(&self, binding: &ProviderBinding) -> Result<(), ProviderError> {
        let mut state = self.lock();
        state.fault.check_before()?;
        // Indexed by tag, released by id: whoever holds a binding holds the id
        // and not the tag it was created under. A context that is not there is
        // the desired state already, so this is a `retain`, not a lookup that
        // can fail.
        state.contexts.retain(|_, id| *id != binding.external_id);
        state.log.push(format!("{} release", binding.external_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{Slug, TenantId};
    use chrono::Utc;

    use super::*;

    fn ctx(employee_id: EmployeeId) -> EnsureCtx {
        EnsureCtx::new(
            TenantId::new_v7(Utc::now()),
            employee_id,
            Slug::parse("ada").unwrap(),
            "browser",
        )
    }

    fn session(p: &Provisioned) -> BrowserSession {
        BrowserSession {
            employee_id: EmployeeId::new_v7(Utc::now()),
            binding: p.binding(),
            user_data_dir: Some(PathBuf::from("/var/lib/agentos").join(&p.external_id)),
        }
    }

    /// The contract every `BrowserProvider` must satisfy. Call it from the real
    /// adapter's tests too — that is the whole point of writing it once.
    async fn verify_contract<P: BrowserProvider>(p: &P) {
        let c = ctx(EmployeeId::new_v7(Utc::now()));

        let first = p.ensure_context(&c).await.unwrap();
        // Same ctx, next attempt: one context, same id.
        let second = p.ensure_context(&c.clone().retry()).await.unwrap();
        assert_eq!(first, second);

        // And the binding a previous run persisted is honoured as-is.
        let third = p
            .ensure_context(&c.clone().with_existing(first.binding()))
            .await
            .unwrap();
        assert_eq!(third.external_id, first.external_id);

        // A session can be driven.
        let url = Url::parse("https://portal.example.com/login").unwrap();
        assert_eq!(
            p.act(&session(&first), BrowserStep::Goto(&url))
                .await
                .unwrap(),
            BrowserOutcome::Navigated(url)
        );

        // And it can be given back — twice, and for a context that was never
        // there. Both are the same desired state, so both succeed.
        p.release(&first.binding()).await.unwrap();
        p.release(&first.binding()).await.unwrap();
        p.release(&ProviderBinding {
            provider: first.provider.to_owned(),
            external_id: "ctx-never-existed".to_owned(),
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn mock_satisfies_the_contract() {
        let p = MockBrowser::new();
        verify_contract(&p).await;
        assert_eq!(p.created(), 1);
        assert_eq!(p.context_count(), 0, "the contract releases what it made");
    }

    /// Releasing is what a termination does, and it has to actually free the
    /// process — and then be safe to do again, because the caller retries.
    #[tokio::test]
    async fn releasing_a_context_frees_it_and_is_safe_to_repeat() {
        let p = MockBrowser::new();
        let provisioned = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();
        assert_eq!(p.context_count(), 1);

        p.release(&provisioned.binding()).await.expect("release");
        assert_eq!(p.context_count(), 0, "the browser is still running");
        p.release(&provisioned.binding())
            .await
            .expect("releasing twice is the same desired state");
        assert_eq!(p.context_count(), 0);
    }

    #[tokio::test]
    async fn ensure_twice_yields_the_same_context_across_a_crash() {
        let p = MockBrowser::new();
        let c = ctx(EmployeeId::new_v7(Utc::now()));

        // We crashed after the context was created and never learned its id.
        p.set_fault(FaultMode::FailAfterExternalSuccess(ProviderError::timeout()));
        let err = p.ensure_context(&c).await.unwrap_err();
        assert!(err.is_retryable());
        assert_eq!(p.created(), 1);

        // The retry rebuilds the same idempotency key, finds the context by
        // tag, and does not create a second browser.
        p.set_fault(FaultMode::Healthy);
        let recovered = p.ensure_context(&c.retry()).await.unwrap();
        assert_eq!(recovered.external_id, "ctx-1");
        assert_eq!(p.created(), 1);
    }

    #[tokio::test]
    async fn each_employee_gets_its_own_context() {
        let p = MockBrowser::new();
        let a = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();
        let b = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();

        assert_ne!(a.external_id, b.external_id);
        assert_eq!(p.created(), 2);
    }

    #[tokio::test]
    async fn a_failure_before_the_call_creates_nothing() {
        let p = MockBrowser::new();
        p.set_fault(FaultMode::FailBefore(ProviderError::from_status(401, None)));

        let err = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "unauthorized");
        assert!(!err.is_retryable());
        assert_eq!(p.created(), 0);
    }

    #[tokio::test]
    async fn a_filled_password_is_typed_but_never_logged() {
        let p = MockBrowser::new();
        let provisioned = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();
        let s = session(&provisioned);
        let password = Secret::new("hunter2");

        let step = BrowserStep::Fill {
            sel: "#password",
            secret: &password,
        };
        // Even the plan itself cannot print it.
        let rendered = format!("{step:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains(Secret::REDACTED), "{rendered}");

        p.act(&s, step).await.unwrap();
        p.act(
            &s,
            BrowserStep::Type {
                sel: "#user",
                text: "ada@example.com",
            },
        )
        .await
        .unwrap();

        let log = p.log().join("\n");
        assert!(!log.contains("hunter2"), "{log}");
        assert!(log.contains("#password"), "{log}");
        // Visible text is not a secret and stays greppable.
        assert!(log.contains("ada@example.com"), "{log}");
    }

    #[tokio::test]
    async fn a_screenshot_comes_back_as_bytes() {
        let p = MockBrowser::new();
        let provisioned = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();

        let out = p
            .act(&session(&provisioned), BrowserStep::Screenshot)
            .await
            .unwrap();
        assert!(matches!(out, BrowserOutcome::Screenshot(png) if png.starts_with(b"\x89PNG")));
    }
}
