//! Evaluation: does the employee do good work?
//!
//! 861 tests in this workspace prove the code is correct. None of them ask
//! whether `rank` orders quotes the way a buyer would, whether the psyche
//! predicts better than the brochure, or how many true findings the
//! proof-of-need bar throws away. This crate asks those four questions and
//! nothing else.
//!
//! # A crate, not an `evals/` directory of JSON
//!
//! The things being measured are Rust values with no wire format, deliberately:
//! [`Evidence`](agentos_app::proof_of_need::Evidence) is not `Deserialize`
//! because an evidence that can be parsed from JSON will one day be parsed from
//! model output; `Landed` has one constructor; `Quote` has one constructor and
//! it checks a validity window. A directory of fixture JSON would need a
//! parallel deserializer for every one of them — a second, unchecked model of
//! the system, which is precisely the thing that rots. Fixtures here are Rust
//! consts that call the real functions.
//!
//! # The method, chosen per surface
//!
//! The system is a mixture and pretending otherwise produces a harness that is
//! either flaky or fake. So:
//!
//! | surface | method | why |
//! |---|---|---|
//! | [`ranking`] | fixtures, exact expected answer | `rank` is a pure function of quotes, a lane and an FX table. A reference ordering is arithmetic anyone can redo by hand. Runs in CI forever. |
//! | [`expectation`] | fixtures, measured against the eventual truth | `Expectation::observe` is pure and takes its clock as a parameter. The comparison that matters — prediction error against *believing the claim* — is computable exactly. |
//! | [`suppression`] | fixtures, exact for the classification, systematic perturbation for the rate | [`verdict`](agentos_app::proof_of_need::verdict) is a pure function of two strings. What each case *should* classify as is definitional; what the field *rate* is cannot be got from fixtures at all, so it isn't claimed — see below. |
//! | [`toolchoice`] | deterministic snapshot in CI, small held-out set run by hand | The model is the one part that cannot be evaluated deterministically. |
//! | [`scoping`] | fixtures, swept over company size, weighed in tokens | What a turn assembles is a pure function of one employee's configuration, so a company of fifty can be built and one employee's turn billed exactly. The token count is an estimate — there is no tokenizer here and no network — and every assertion is a *comparison* under that one estimator, so its error cancels rather than reaching the pass/fail. |
//!
//! ## Why no judge, and no record-and-replay
//!
//! **No judge.** A judge is for grading open-ended output. "Which of three
//! tools should this turn have called" has a known right answer by construction
//! of the case — a judge would add a second model's noise and a bill to a
//! question we already hold the key to.
//!
//! **No record-and-replay of model responses.** Replaying a recorded response
//! measures our parsing, not the model, and the moment the prompt changes the
//! recording is answering a question that was never asked. Since the whole
//! point of the tool-choice suite is "does a prompt change make this worse", a
//! replay harness would be at its most confident exactly when it is most wrong.
//!
//! What replaces it is smaller and honest: CI pins a **digest of the rendered
//! system prompt**. Editing the prompt turns the suite red with "the recorded
//! live scores are stale", which is the true statement. Re-running the live set
//! is a human's decision, and it costs one local `claude` subscription and
//! about a minute.
//!
//! # Two labels, never mixed
//!
//! Every result carries a [`Truth`]. A fixture whose expected answer somebody
//! made up is worse than no fixture, because everyone then optimises against
//! one person's guess. So:
//!
//! * [`Truth::Correct`] — the expected answer is derivable from a definition,
//!   from arithmetic, or from the eventual observation. A failure is a bug.
//! * [`Truth::Characterises`] — the expected answer is *today's behaviour*,
//!   recorded so a change is visible. A failure is a question, not a bug.
//!
//! They print differently and they are counted separately. Nothing here
//! promotes the second into the first.

pub mod expectation;
pub mod ranking;
pub mod scoping;
pub mod suppression;
pub mod toolchoice;

use std::fmt::Write as _;

/// Where a fixture's expected answer comes from. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// Derivable from a definition, from arithmetic, or from the eventual
    /// observation. A failure here is a bug.
    Correct,
    /// Today's behaviour, recorded so a change is visible. A failure here is a
    /// question for a human, not a regression.
    Characterises,
}

impl Truth {
    const fn tag(self) -> &'static str {
        match self {
            Truth::Correct => "CORRECT",
            Truth::Characterises => "CHARACTER",
        }
    }
}

/// One measured claim about one surface.
#[derive(Debug, Clone)]
pub struct Row {
    /// What was measured, in a few words.
    pub what: String,
    /// The number, already formatted. A metric nobody can read is a metric
    /// nobody reads.
    pub value: String,
    /// Where the expected answer came from.
    pub truth: Truth,
    /// `false` puts a `FAIL` on the row and fails the run when
    /// [`Truth::Correct`].
    pub ok: bool,
    /// One line of context, printed under the row when there is something a
    /// reader would otherwise get wrong.
    pub note: Option<String>,
}

impl Row {
    /// A passing row.
    pub fn ok(what: impl Into<String>, value: impl Into<String>, truth: Truth) -> Self {
        Self {
            what: what.into(),
            value: value.into(),
            truth,
            ok: true,
            note: None,
        }
    }

    /// A row that passes only if `ok`.
    #[must_use]
    pub fn gated(mut self, ok: bool) -> Self {
        self.ok = ok;
        self
    }

    /// Attach the one line of context.
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Everything measured about one surface, plus what about it is not.
#[derive(Debug, Clone)]
pub struct Surface {
    /// Module path of the thing under evaluation.
    pub name: &'static str,
    /// How it is evaluated and why, in one line.
    pub method: &'static str,
    /// The measurements.
    pub rows: Vec<Row>,
    /// What this suite does **not** cover. As valuable as the rows: a surface
    /// with an empty list here is a surface whose author has not looked.
    pub unmeasured: Vec<&'static str>,
}

impl Surface {
    /// Did every [`Truth::Correct`] row pass?
    pub fn passed(&self) -> bool {
        self.rows
            .iter()
            .all(|row| row.ok || row.truth == Truth::Characterises)
    }
}

/// Every deterministic suite. Free of I/O, a database and a model — this is the
/// part that runs in CI on every push.
pub fn deterministic() -> Vec<Surface> {
    vec![
        ranking::evaluate(),
        expectation::evaluate(),
        suppression::evaluate(),
        toolchoice::evaluate(),
        scoping::evaluate(),
    ]
}

/// The thirty-second read.
///
/// Aligned columns, one line per measurement, failures marked, and the
/// unmeasured list at the bottom where a reader ends up anyway.
pub fn render(surfaces: &[Surface]) -> String {
    let mut out = String::new();
    out.push_str("AgentOS evaluation\n\n");

    let width = surfaces
        .iter()
        .flat_map(|s| s.rows.iter().map(|r| r.what.len()))
        .max()
        .unwrap_or(20)
        .max(20);

    for surface in surfaces {
        let _ = writeln!(out, "{}", surface.name);
        let _ = writeln!(out, "  {}", surface.method);
        for row in &surface.rows {
            let verdict = if row.ok { "  " } else { "! " };
            let _ = writeln!(
                out,
                "  {verdict}{:<9}  {:<width$}  {}",
                row.truth.tag(),
                row.what,
                row.value,
            );
            if let Some(note) = &row.note {
                // Indented under the value column, aligned with the row above:
                // two for the margin, two for the verdict slot, nine for the tag.
                let _ = writeln!(out, "  {:<11}  {:<width$}  {note}", "", "");
            }
        }
        out.push('\n');
    }

    let label = surfaces
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(18)
        .max(18);
    out.push_str("UNMEASURED — nothing below is covered by any number above\n\n");
    for surface in surfaces {
        for gap in &surface.unmeasured {
            let _ = writeln!(out, "  {:<label$}  {gap}", surface.name);
        }
    }

    let failures: Vec<&Row> = surfaces
        .iter()
        .flat_map(|s| s.rows.iter())
        .filter(|r| !r.ok && r.truth == Truth::Correct)
        .collect();
    let changed: Vec<&Row> = surfaces
        .iter()
        .flat_map(|s| s.rows.iter())
        .filter(|r| !r.ok && r.truth == Truth::Characterises)
        .collect();

    out.push('\n');
    match (failures.len(), changed.len()) {
        (0, 0) => out.push_str("All correctness checks pass; no characterised behaviour moved.\n"),
        (0, n) => {
            let _ = writeln!(
                out,
                "All correctness checks pass. {n} characterised behaviour(s) moved — \
                 not a regression, but somebody decided something:"
            );
            for row in changed {
                let _ = writeln!(out, "  - {}", row.what);
            }
        }
        (n, _) => {
            let _ = writeln!(out, "{n} correctness check(s) FAILED:");
            for row in failures {
                let _ = writeln!(out, "  - {}: {}", row.what, row.value);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The harness's own gate. Every `Truth::Correct` row in every suite has to
    /// pass, or CI is red — which is the whole point of putting the
    /// deterministic half in CI.
    #[test]
    fn every_correctness_check_passes() {
        let surfaces = deterministic();
        let report = render(&surfaces);
        assert!(
            surfaces.iter().all(Surface::passed),
            "an evaluation regressed:\n\n{report}"
        );
    }

    /// A suite that measures nothing is a suite that passes vacuously.
    #[test]
    fn no_suite_is_empty_and_none_claims_full_coverage() {
        for surface in deterministic() {
            assert!(
                !surface.rows.is_empty(),
                "{} measured nothing",
                surface.name
            );
            assert!(
                !surface.unmeasured.is_empty(),
                "{} claims to measure everything about itself, which is never true",
                surface.name
            );
        }
    }

    /// The report is the deliverable; a reader has thirty seconds. The gate is
    /// on the *measurements* — the UNMEASURED list is a reference and is
    /// allowed to be as long as the truth requires.
    ///
    /// The budget is **per surface**, not one number for the whole page, and it
    /// was one number until a fifth suite arrived one line under a flat fifty.
    /// A global cap prices a new suite at whatever the existing ones left over,
    /// so the cheapest way to add a measurement becomes deleting somebody
    /// else's note — which is the opposite of what the cap is for. Fourteen
    /// lines is where a suite has stopped measuring and started narrating, and
    /// that is a property of the suite rather than of how many it has for
    /// company.
    #[test]
    fn the_measurements_fit_on_a_screen() {
        let surfaces = deterministic();
        let report = render(&surfaces);
        let measurements = report
            .split("UNMEASURED")
            .next()
            .expect("split always yields one")
            .lines()
            .count();
        let budget = 14 * surfaces.len();
        assert!(
            measurements < budget,
            "{measurements} lines of measurement across {} suites; nobody will read it",
            surfaces.len()
        );
        for surface in &surfaces {
            let lines =
                surface.rows.len() + surface.rows.iter().filter(|r| r.note.is_some()).count();
            assert!(
                lines <= 14,
                "{} alone prints {lines} lines; that is a document, not a measurement",
                surface.name
            );
        }
        assert!(report.contains("UNMEASURED"));
    }

    #[test]
    fn a_failing_correctness_row_is_reported_and_a_moved_characterisation_is_not() {
        let surfaces = vec![Surface {
            name: "made-up",
            method: "n/a",
            rows: vec![
                Row::ok("a definitional thing", "3/4", Truth::Correct).gated(false),
                Row::ok("a recorded thing", "17%", Truth::Characterises).gated(false),
            ],
            unmeasured: vec!["everything"],
        }];
        assert!(!surfaces[0].passed());

        let report = render(&surfaces);
        assert!(report.contains("1 correctness check(s) FAILED"), "{report}");
        assert!(report.contains("a definitional thing"), "{report}");
    }
}
