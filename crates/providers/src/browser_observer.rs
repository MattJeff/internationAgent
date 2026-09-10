//! What a browser adapter *tells* about a task, and to whom.
//!
//! Decided 2026-09-10 for the second phase of `docs/BROWSER.md`: the journal
//! of browser tasks, and the live view of a running one, are both **readers of
//! the same narration** — a task started, a step ran, a frame was captured, the
//! task ended. The adapter narrates; it never knows who listens. That keeps
//! `browser_chrome.rs` free of any table and any channel, and lets the journal
//! and the live view be built by two hands at once against one port.
//!
//! # Why a port and not events on the outbox
//!
//! Frames are not durable state: a live view that arrives ten seconds late is
//! not a live view, and a journal row is written once per task, not once per
//! frame. So this is a synchronous, in-process port — a method call, `&self`,
//! no `Result` — and the implementation decides what is kept (a row), what is
//! fanned out (a frame to whoever watches), and what is dropped (a frame nobody
//! watches). Nothing here may block the adapter: an implementation that needs
//! I/O spawns it.
//!
//! # What is deliberately absent
//!
//! No tenant: the adapter does not know it (see `browser_chrome.rs` on the
//! cookie jar, keyed by context for the same reason). The observer resolves
//! the tenant from the employee under an admin transaction, as the jar does.
//! No page content, no cookies, no typed text: a step is *named*, its URL is
//! given for `Goto` only, and a frame is a JPEG of what was on screen. The
//! password typed by a `Fill` never crosses this port.

use std::time::Duration;

use agentos_domain::ids::EmployeeId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One task: a context opened for one employee, driven by one or more steps,
/// closed once. Created by the adapter, echoed on every call so a listener
/// keyed by `task_id` needs no state between calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRef {
    pub task_id: Uuid,
    pub employee_id: EmployeeId,
    /// The adapter's own context id — `ctx-<tag>` for `chrome`.
    pub context: String,
    /// Which adapter narrates: `"chrome"`, `"browserbase"`, `"http-browser"`.
    pub provider: &'static str,
}

/// How a step ended, without its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Ok,
    /// The adapter refused before touching the page — a vetoed URL, a wall
    /// (`blocked_by_site`), a step this adapter does not serve.
    Refused {
        code: &'static str,
    },
    /// The page or the browser failed — navigation error, missing element,
    /// timeout.
    Failed {
        code: &'static str,
    },
}

/// A step, as the journal sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// `goto`, `click`, `type`, `fill`, `text`, `markup`, `screenshot`,
    /// `location` — the variant's name, lower-case, nothing from its payload.
    pub kind: &'static str,
    /// For `goto` only: the URL as navigated (after the vet, before redirects).
    pub url: Option<String>,
    pub outcome: StepOutcome,
    pub took: Duration,
}

/// The port. Every method has a default that does nothing, so an adapter can
/// be given [`NoopObserver`] in tests and a listener can implement only what
/// it reads.
pub trait BrowserObserver: Send + Sync {
    fn task_started(&self, _task: &TaskRef, _at: DateTime<Utc>) {}
    fn step_done(&self, _task: &TaskRef, _step: &StepReport, _at: DateTime<Utc>) {}
    /// A JPEG of the viewport. Sent only while somebody watches
    /// ([`Self::wants_frames`]), at most a few per second; never persisted by
    /// the adapter.
    fn frame(&self, _task: &TaskRef, _jpeg: &[u8], _at: DateTime<Utc>) {}
    /// Whether frames are worth capturing right now. The adapter asks before
    /// starting a screencast and again on every frame; `false` stops it.
    fn wants_frames(&self, _task: &TaskRef) -> bool {
        false
    }
    fn task_finished(&self, _task: &TaskRef, _outcome: &StepOutcome, _at: DateTime<Utc>) {}
}

/// Listens to nothing. The adapter's default, and the tests'.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl BrowserObserver for NoopObserver {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port must be object-safe: `Arc<dyn BrowserObserver>` is how the
    /// adapter holds it and how `mocks.rs` hands it over.
    #[test]
    fn the_observer_is_held_behind_a_dyn() {
        let observer: std::sync::Arc<dyn BrowserObserver> = std::sync::Arc::new(NoopObserver);
        let task = TaskRef {
            task_id: Uuid::nil(),
            employee_id: EmployeeId::new_v7(Utc::now()),
            context: "ctx-test".to_owned(),
            provider: "chrome",
        };
        assert!(!observer.wants_frames(&task));
        observer.task_started(&task, Utc::now());
        observer.task_finished(&task, &StepOutcome::Ok, Utc::now());
    }
}
