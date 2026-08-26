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
//!
//! # Why [`BrowserOutcome::Text`] is already [`Untrusted`]
//!
//! It is the only outcome that carries somebody else's *words*, and the caller
//! that wants them — `app::proof_of_need` — wants them precisely because it is
//! hunting for something quotable in them. Wrapping at the adapter, next to
//! `email::parse_inbound` and `telephony::inbound_sms`, means there is no
//! moment anywhere in the process when a page's text is a bare `String` that
//! somebody could concatenate. A screenshot is bytes and a navigation is a URL
//! we asked for; this one is a stranger talking.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_domain::untrusted::Untrusted;
use async_trait::async_trait;
use chrono::Utc;
use url::Url;

use crate::{EnsureCtx, FaultMode, ProviderBinding, ProviderError, Provisioned, Secret};

/// The selector matched nothing in the live document.
///
/// Trait vocabulary rather than a detail of one adapter: [`BrowserStep::Click`],
/// [`BrowserStep::Type`] and [`BrowserStep::Text`] all name an element that may
/// not be there, and every adapter has to answer that the same way. It is a
/// [`ProviderError::Terminal`] code because a retry cannot conjure the element
/// — the selector is ours and it is wrong.
pub const NO_SUCH_ELEMENT: &str = "no_such_element";

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
    /// Read the visible text of the first match of a CSS selector.
    ///
    /// The one step that brings the page's own words back, so it is the one
    /// step whose outcome is [`Untrusted`].
    ///
    /// **A selector that matches nothing is
    /// `Err(Terminal { code: NO_SUCH_ELEMENT })`, never `Ok(Text(""))`.** The
    /// two are different facts — "their page says nothing here" versus "we
    /// pointed at the wrong element" — and only the first of them is anything
    /// to tell a prospect about. Collapsing them into an empty string is how a
    /// broken selector becomes a sentence claiming somebody's checkout is
    /// silent about visas; an `Err` cannot be mistaken for an answer because a
    /// caller cannot get past it without saying so.
    Text(&'a str),
    /// Read the **markup** of the first match of a CSS selector: `outerHTML`.
    ///
    /// [`BrowserStep::Text`] answers "what does their page tell a traveller".
    /// This answers "what is their page made of", and there is exactly one
    /// caller that needs the difference: `agentos_app::flow_proposal`, which
    /// derives the `#id` of a booking form's fields so a human can review five
    /// selectors instead of authoring them. `innerText` cannot answer it —
    /// attributes are not rendered text, and an `id` is an attribute.
    ///
    /// **It is a read, and it is the most dangerous thing to render that this
    /// enum produces.** The text a `Text` brings back is a stranger's prose;
    /// the markup a `Markup` brings back is a stranger's prose *plus* their
    /// script bodies, their inline event handlers and their comments. So it is
    /// [`Untrusted`] like `Text` and, unlike `Text`, nothing in this workspace
    /// hands the result to a model or to a screen: the one caller scans it in
    /// Rust and returns counts and identifiers of a shape a CHECK constraint
    /// re-states. Point a tool at this and the fence is gone.
    ///
    /// `NO_SUCH_ELEMENT` on no match, for [`BrowserStep::Text`]'s reason.
    Markup(&'a str),
    /// Capture the viewport as a PNG.
    Screenshot,
}

impl BrowserStep<'_> {
    /// Does this step only *look*, or does it change somebody else's page?
    ///
    /// **The classification lives here, beside the variants, and the match has
    /// no `_` arm** — so adding a step to the enum above stops the build until
    /// somebody says which side it is on. That is the same discipline
    /// `agentos_domain::policy::evaluate_rules` keeps for `Action`, and it is
    /// here for a sharper reason than tidiness: the default a `_` arm would
    /// pick is the one that decides whether an unclassified step can be driven
    /// by a token that was only ruled a read.
    ///
    /// `Goto` is a read. Navigating is how you get to a page to look at it, and
    /// the URL is scope-checked against the token's own domain before it runs.
    /// `Screenshot`, `Text` and `Markup` observe. `Click`, `Type` and `Fill`
    /// put something of ours into a stranger's system, which is a write whatever
    /// the element happens to be — a search box today and a "delete account"
    /// button on the next redesign, and the selector cannot tell them apart.
    #[must_use]
    pub const fn is_a_read(&self) -> bool {
        match self {
            Self::Goto(_) | Self::Text(_) | Self::Markup(_) | Self::Screenshot => true,
            Self::Click(_) | Self::Type { .. } | Self::Fill { .. } => false,
        }
    }
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
    /// The visible text of the element a [`BrowserStep::Text`] named, exactly
    /// as it read — and wrapped, because it is a stranger's writing on a
    /// stranger's page. An empty string here means the element is there and
    /// says nothing; a selector that found no element does not come back at
    /// all. See the module docs.
    Text(Untrusted<String>),
    /// The `outerHTML` of the element a [`BrowserStep::Markup`] named.
    ///
    /// **A separate variant from [`BrowserOutcome::Text`] on purpose.** The two
    /// are both `Untrusted<String>` and a shared variant would compile
    /// everywhere — which is the problem: `Effects::read_page` matches on `Text`
    /// and hands what it finds to a model, so a day when a `Markup` step could
    /// answer with a `Text` outcome is a day a stranger's script bodies reach a
    /// prompt because two call sites drifted. They cannot drift; they do not
    /// share a name.
    Markup(Untrusted<String>),
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
    /// selector -> what successive reads of it find. A selector that is not a
    /// key is an element that is not on the page, which is the whole point:
    /// "unscripted" and "scripted as empty" have to be two different pages
    /// here, or a test cannot tell the two facts apart either.
    page: BTreeMap<String, (Vec<String>, usize)>,
    /// selector -> `outerHTML`. A second map rather than a second use of
    /// `page`, for the reason [`BrowserOutcome::Markup`] is a second variant: a
    /// test that scripts the *text* of `body` has said nothing about its
    /// markup, and a mock that answered a `Markup` with the scripted text would
    /// make `flow_proposal` look like it worked on pages that have no `id` on
    /// anything.
    markup: BTreeMap<String, String>,
}

impl MockState {
    /// The next text `sel` reads as, or `None` when nothing matches it.
    fn read(&mut self, sel: &str) -> Option<String> {
        let (texts, reads) = self.page.get_mut(sel)?;
        let text = texts[(*reads).min(texts.len() - 1)].clone();
        *reads += 1;
        Some(text)
    }
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

    /// Put an element on the page: what successive [`BrowserStep::Text`] reads
    /// of `sel` find, in order, with the last entry repeating forever.
    ///
    /// A sequence rather than one string because the interesting question about
    /// a page is whether it says the same thing twice — `app::proof_of_need`
    /// loads every flow two times and throws away anything that does not
    /// reproduce, so `["a", "b"]` is how a flaky widget is spelled.
    ///
    /// Anything never passed here has no element, and reads as
    /// [`NO_SUCH_ELEMENT`].
    pub fn set_text(&self, sel: &str, texts: &[&str]) {
        let texts: Vec<String> = texts.iter().map(|text| (*text).to_owned()).collect();
        assert!(
            !texts.is_empty(),
            "an element with no text still reads as \"\""
        );
        self.lock().page.insert(sel.to_owned(), (texts, 0));
    }

    /// Put markup on the page: what a [`BrowserStep::Markup`] of `sel` reads.
    ///
    /// One string and not a sequence, unlike [`MockBrowser::set_text`]: nothing
    /// reads markup twice to compare the two, because the question markup
    /// answers is what the page is built out of and the reproducibility bar is
    /// about what it says.
    pub fn set_markup(&self, sel: &str, html: &str) {
        self.lock().markup.insert(sel.to_owned(), html.to_owned());
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
            BrowserStep::Text(sel) => {
                let found = state.read(sel);
                // Logged whichever it was: an attempted read is a read, and a
                // test asserting "the panel was never touched" wants to see the
                // one that found nothing too.
                state.log.push(format!("{ctx} text {sel}"));
                state.fault.check_after()?;
                return found
                    .map(|text| BrowserOutcome::Text(Untrusted::new(text)))
                    .ok_or(ProviderError::Terminal {
                        code: NO_SUCH_ELEMENT,
                    });
            }
            BrowserStep::Markup(sel) => {
                let found = state.markup.get(sel).cloned();
                state.log.push(format!("{ctx} markup {sel}"));
                state.fault.check_after()?;
                return found
                    .map(|html| BrowserOutcome::Markup(Untrusted::new(html)))
                    .ok_or(ProviderError::Terminal {
                        code: NO_SUCH_ELEMENT,
                    });
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

// ---------------------------------------------------------------------------
// Contract suite
// ---------------------------------------------------------------------------

/// Every [`BrowserProvider`] must satisfy this. Panics on the first violation.
///
/// `pub`, and that is the point of it — the comment above it used to say "call
/// it from the real adapter's tests too", and nothing could, because it was
/// private to this module's `mod tests`. [`crate::browser_browserbase`] now
/// runs it against a hermetic HTTP server and a recording CDP driver.
///
/// Pure and idempotent paths only: ensure, ensure again, honour a persisted
/// binding, drive one step, and give the context back three times over. The
/// crash-window case needs fault injection and stays in this module's tests.
pub async fn contract_suite<P: BrowserProvider + ?Sized>(p: &P) {
    let c = EnsureCtx::new(
        TenantId::new_v7(Utc::now()),
        EmployeeId::new_v7(Utc::now()),
        Slug::parse("ada").expect("valid slug"),
        "browser",
    );
    let session = |provisioned: &Provisioned| BrowserSession {
        employee_id: EmployeeId::new_v7(Utc::now()),
        binding: provisioned.binding(),
        // `None`: a hosted provider persists login state its own way, and a
        // self-hosted one is told where by the caller. Neither is this suite's
        // business — see the trait's docs on why the field exists at all.
        user_data_dir: None,
    };

    let first = p.ensure_context(&c).await.expect("first ensure");
    // Same ctx, next attempt: one context, same id.
    let second = p
        .ensure_context(&c.clone().retry())
        .await
        .expect("second ensure");
    assert_eq!(
        first, second,
        "ensure must reconcile on the tag, not create a second context"
    );

    // And the binding a previous run persisted is honoured as-is.
    let third = p
        .ensure_context(&c.clone().with_existing(first.binding()))
        .await
        .expect("persisted ensure");
    assert_eq!(third.external_id, first.external_id);

    // A session can be driven.
    let url = Url::parse("https://portal.example.com/login").expect("valid url");
    assert_eq!(
        p.act(&session(&first), BrowserStep::Goto(&url))
            .await
            .expect("navigate"),
        BrowserOutcome::Navigated(url)
    );

    // And it can be given back — twice, and for a context that was never
    // there. All three are the same desired state, so all three succeed.
    p.release(&first.binding()).await.expect("release");
    p.release(&first.binding())
        .await
        .expect("releasing twice is the same desired state");
    p.release(&ProviderBinding {
        provider: first.provider.to_owned(),
        external_id: "ctx-never-existed".to_owned(),
    })
    .await
    .expect("releasing what the provider no longer has is success");
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn mock_satisfies_the_contract() {
        let p = MockBrowser::new();
        contract_suite(&p).await;
        assert_eq!(p.created(), 1);
        assert_eq!(p.context_count(), 0, "the contract releases what it made");
    }

    #[tokio::test]
    async fn the_mock_satisfies_the_contract_behind_a_dyn_reference() {
        // The trait has to stay object-safe: `Ports` holds a `dyn`.
        let p: &dyn BrowserProvider = &MockBrowser::new();
        contract_suite(p).await;
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

    /// The distinction the whole proof-of-need vertical rests on: an element
    /// that is there and empty is an answer, an element that is not there is
    /// not. They must not be the same value, and they are not even the same
    /// `Result`.
    #[tokio::test]
    async fn an_empty_panel_reads_as_text_and_a_missing_one_does_not_read_at_all() {
        let p = MockBrowser::new();
        let provisioned = p
            .ensure_context(&ctx(EmployeeId::new_v7(Utc::now())))
            .await
            .unwrap();
        let s = session(&provisioned);
        p.set_text("#visa-info", &["No visa required.", ""]);

        // Scripted in order, last entry forever — the two runs a check makes.
        let read = async || match p.act(&s, BrowserStep::Text("#visa-info")).await {
            Ok(BrowserOutcome::Text(text)) => Ok(text.into_inner_for_rendering()),
            Ok(other) => panic!("a text read answered {other:?}"),
            Err(err) => Err(err),
        };
        assert_eq!(read().await.unwrap(), "No visa required.");
        assert_eq!(read().await.unwrap(), "", "the panel is there and silent");
        assert_eq!(read().await.unwrap(), "");

        // And the element nobody put on the page: a fact about our selector,
        // not a page that said nothing.
        let err = p
            .act(&s, BrowserStep::Text("#not-there"))
            .await
            .expect_err("nothing matches it");
        assert_eq!(err.code(), NO_SUCH_ELEMENT);
        assert!(!err.is_retryable(), "the selector will still be wrong");

        // Both attempts are on the log, so "never read" stays assertable.
        assert_eq!(
            p.log(),
            [
                "ctx-1 text #visa-info",
                "ctx-1 text #visa-info",
                "ctx-1 text #visa-info",
                "ctx-1 text #not-there",
            ]
        );
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
