//! Does `proof_of_need` find real defects, and what does the two-run
//! byte-comparison throw away?
//!
//! # Why this suite exists at all, and the one change that let it
//!
//! The module docs ask an operator to read the suppression rate and to read it
//! *broken down by reason*, because "the bar is working" and "the panel
//! selector is wrong" produce the same headline number and opposite actions.
//! Until now that classification was reachable only through a Postgres
//! connection, a `PolicyGate` and a live `BrowserSession`, which is why nobody
//! had ever put a number on it. [`verdict`] is that decision lifted out of
//! `Prober::run` verbatim — same three branches, same order, no behaviour
//! change — as a pure function of two strings and a [`Claim`].
//!
//! **Nothing here weakens the bar and nothing here is allowed to.** The
//! suppression is deliberate. This measures its cost; it does not shop for a
//! way to avoid paying it.
//!
//! # Method, split in two because the ground truth is
//!
//! ## 1. Classification — fixtures, exact expected answers, [`Truth::Correct`]
//!
//! What each case *should* classify as is definitional, not a guess. A page
//! saying "no visa required" against an authority saying a visa is required
//! **is** a contradiction; a captcha **is** friction served to us and not a
//! statement about their checkout; "no e-visa needed" **is** something we
//! cannot turn into a requirement. Each fixture's expected value is written as
//! the `(outcome, detail)` pair that would land in `proof_of_need_attempts`, so
//! the fixture and the database column cannot drift.
//!
//! ## 2. The rate — systematic perturbation, [`Truth::Characterises`]
//!
//! **The field suppression rate cannot be obtained from fixtures and is not
//! claimed here.** A corpus of hand-written prospect pages produces a
//! hand-written rate; publishing that number would be the exact failure the
//! brief warns about, so the suite does not. The real one is a query and
//! [`REAL_RATE_SQL`] is printed in the report for whoever has the data.
//!
//! What *can* be measured honestly is the mechanism: take a panel that would
//! have produced a finding, apply one **named, benign** thing a real
//! e-commerce page does between two loads — a clock, a session id, a cart
//! counter, a rotating banner — and see what the bar does with it. The
//! population is not "prospects", it is "kinds of benign churn", and every
//! member of it is enumerated in [`Churn::ALL`]. That is a defensible sample
//! frame; "we imagined forty airlines" is not.
//!
//! # The result worth reading twice
//!
//! Benign churn suppresses *both* kinds of finding, and since `both_silent` it
//! does so **visibly for both**. A [`Finding::Contradicts`] page states a
//! requirement in both runs, so the pair lands as [`Divergence::SameAnswer`]. A
//! [`Finding::SaysNothing`] page has no requirement to compare, and the
//! identical churn lands as [`Divergence::BothSilent`]. Two reason codes, one
//! fix: a narrower [`Flow::panel`]. An operator adds them up.
//!
//! **It did not use to.** `BothSilent` did not exist, the says-nothing half fell
//! into [`Divergence::Undetermined`] pooled with pages we never got, and this
//! suite measured it at **0/8 diagnosable against 8/8** for the contradicts
//! half — half the loss invisible, on the very number the commercial argument
//! rests on. Both halves now read 8/8.
//!
//! What did **not** move: suppression is still 8/8 and 8/8. Every one of these
//! findings is still thrown away, and no churned pair produces [`Evidence`]. The
//! bar is untouched; only the label on the loss changed.
//!
//! The one thing `both_silent` refuses to claim is a page that came back
//! **empty**. That is not a checkout being silent about visas, it is a widget
//! that never rendered, and it stays [`Divergence::Undetermined`] — the
//! `one run silent, one run blank` fixture below is what holds that line.

use agentos_app::proof_of_need::{Checked, Claim, Divergence, Verdict, verdict};
use agentos_domain::untrusted::Untrusted;

use crate::{Row, Surface, Truth};

/// The real suppression rate is a query, not a fixture. Printed in the report
/// so the number nobody can compute here has an address.
/// `bar_misset` is `same_answer + both_silent`, from `proof_of_need_bar_misset`
/// (migration 0021) — the same mistake measured on the two kinds of finding.
/// Reading either alone is the bug this suite measured at 0/8.
pub const REAL_RATE_SQL: &str = "select s.prospect_domain, s.attempts, s.suppression_rate_pct, \
     s.blocked, m.bar_misset, s.flow_disagreed, s.undetermined \
     from proof_of_need_suppression s \
     join proof_of_need_bar_misset m using (tenant_id, prospect_domain) \
     order by s.attempts desc;";

// ---------------------------------------------------------------------------
// Part 1: classification
// ---------------------------------------------------------------------------

/// One pair of panel reads, and what it must come to.
struct Case {
    name: &'static str,
    first: &'static str,
    second: &'static str,
    authority: Claim,
    /// The `(outcome, detail)` pair as `proof_of_need_attempts` stores it.
    expect: (&'static str, Option<&'static str>),
}

/// A panel that states a requirement, of the shape a real widget renders.
const AGREES_TEXT: &str = "Entry requirements: a visa is required for this destination. \
                           Apply before you travel.";
/// The same widget, wrong.
const WRONG_TEXT: &str = "Entry requirements: no visa is required for this destination. \
                          Travel with a valid passport.";
/// A checkout that has no opinion about entry requirements at all.
const SILENT_TEXT: &str = "Review your booking. 2 passengers, 1 bag. Total EUR 412.00.";
/// What a bot-defence page looks like.
const CHALLENGE_TEXT: &str = "Checking your browser before you access this site. \
                              Please verify you are human.";

const CASES: &[Case] = &[
    // --- the three outcomes that must never be conflated --------------------
    Case {
        name: "flow agrees with the authority",
        first: AGREES_TEXT,
        second: AGREES_TEXT,
        authority: Claim::VisaRequired,
        expect: ("agrees", None),
    },
    Case {
        name: "flow contradicts the authority",
        first: WRONG_TEXT,
        second: WRONG_TEXT,
        authority: Claim::VisaRequired,
        expect: ("evidence", Some("contradicts")),
    },
    Case {
        name: "flow says nothing about entry",
        first: SILENT_TEXT,
        second: SILENT_TEXT,
        authority: Claim::VisaRequired,
        expect: ("evidence", Some("says_nothing")),
    },
    // --- the challenge check, and why it runs on both runs ------------------
    Case {
        name: "challenged on the second run",
        first: WRONG_TEXT,
        second: CHALLENGE_TEXT,
        authority: Claim::VisaRequired,
        expect: ("blocked", None),
    },
    Case {
        // The case the whole `looks_challenged` check exists for: two
        // identical captchas agree with each other perfectly, mention no
        // visa, and would otherwise become a `says_nothing` finding about a
        // checkout we never reached.
        name: "challenged on both runs, identically",
        first: CHALLENGE_TEXT,
        second: CHALLENGE_TEXT,
        authority: Claim::VisaRequired,
        expect: ("blocked", None),
    },
    Case {
        name: "rate-limited rather than captcha'd",
        first: "429 Too Many Requests. Please slow down.",
        second: "429 Too Many Requests. Please slow down.",
        authority: Claim::NoVisa,
        expect: ("blocked", None),
    },
    // --- the three divergence reasons --------------------------------------
    Case {
        name: "same requirement, different bytes",
        first: "A visa is required. Checked 14:02:11.",
        second: "A visa is required. Checked 14:02:19.",
        authority: Claim::NoVisa,
        expect: ("not_reproducible", Some("same_answer")),
    },
    Case {
        name: "flow answered two different ways",
        first: "A visa is required for this trip.",
        second: "No visa is required for this trip.",
        authority: Claim::VisaRequired,
        expect: ("not_reproducible", Some("answers")),
    },
    Case {
        // The twin of "same requirement, different bytes", for the other
        // finding: both runs read fine, neither said a word about entry
        // requirements, and a byte-identical repeat of either would have been a
        // `says_nothing` finding. Same mis-set bar, same narrower `Flow::panel`.
        name: "same silence, different bytes",
        first: SILENT_TEXT,
        second: "Review your booking. 2 passengers, 1 bag. Total EUR 412.00. ref=S-8813f2",
        authority: Claim::VisaRequired,
        expect: ("not_reproducible", Some("both_silent")),
    },
    Case {
        name: "one run loaded, one did not",
        first: WRONG_TEXT,
        second: "",
        authority: Claim::VisaRequired,
        expect: ("not_reproducible", Some("undetermined")),
    },
    Case {
        // The line `both_silent` must not cross. An empty panel reads as "no
        // mention of entry requirements" exactly like a real checkout does, and
        // it is not one — it is a widget that never rendered. Telling an
        // operator to narrow a selector at it would be the confidently wrong
        // reason code, which costs more than an unknown one.
        name: "one run silent, one run blank",
        first: SILENT_TEXT,
        second: "   ",
        authority: Claim::VisaRequired,
        expect: ("not_reproducible", Some("undetermined")),
    },
    Case {
        // And a run that mentioned entry requirements without stating one we
        // could parse is not silence either.
        name: "one run silent, one run unparseable",
        first: SILENT_TEXT,
        second: "Visa information may vary. Total EUR 412.00.",
        authority: Claim::VisaRequired,
        expect: ("not_reproducible", Some("undetermined")),
    },
    // --- refusing to claim, which is this module's actual job --------------
    Case {
        // "no e-visa needed" is not a page saying an e-visa is needed. A
        // negation we cannot resolve is silence, not a finding.
        name: "negated requirement is not a finding",
        first: "Good news: no e-visa needed for this route.",
        second: "Good news: no e-visa needed for this route.",
        authority: Claim::EVisa,
        expect: ("unreadable", None),
    },
    Case {
        // The parser is English-only. A French page must fail towards "no
        // evidence" and never towards a wrong claim about somebody's product.
        name: "a language we cannot read",
        first: "Formalités : un visa est exigé pour cette destination.",
        second: "Formalités : un visa est exigé pour cette destination.",
        authority: Claim::VisaRequired,
        // "visa" is present, no English phrase matches: unreadable, not a
        // contradiction. This is the safe direction and it is asserted.
        expect: ("unreadable", None),
    },
    Case {
        name: "visa on arrival, against an e-visa authority",
        first: "You may obtain a visa on arrival at the airport.",
        second: "You may obtain a visa on arrival at the airport.",
        authority: Claim::EVisa,
        expect: ("evidence", Some("contradicts")),
    },
];

/// The `(outcome, detail)` pair a verdict would file.
fn filed(verdict: &Verdict) -> (&'static str, Option<&'static str>) {
    match verdict {
        // `Prober::run` turns a `Finding` into `Checked::Evidence`, whose code
        // is "evidence"; the finding kind is what an operator reads next.
        Verdict::Finding(finding) => ("evidence", Some(finding.code())),
        Verdict::Nothing(checked) => (checked.code(), checked.detail()),
    }
}

fn run(first: &str, second: &str, authority: Claim) -> Verdict {
    verdict(
        &Untrusted::new(first.to_owned()),
        &Untrusted::new(second.to_owned()),
        authority,
    )
}

// ---------------------------------------------------------------------------
// Part 2: what benign churn costs
// ---------------------------------------------------------------------------

/// One thing a real page does between two loads that has nothing to do with
/// visas.
///
/// Each entry is a rewrite of the *second* run's panel text. The list is short
/// and every item is a documented behaviour of live e-commerce pages, not an
/// invention: this is the sample frame, and its honesty is the only thing
/// holding up the number below.
struct Churn {
    name: &'static str,
    /// Appended to, or wrapped around, the panel a widget rendered.
    suffix: &'static str,
}

impl Churn {
    const ALL: &'static [Churn] = &[
        Churn {
            name: "a clock",
            suffix: " Last updated 14:02:19.",
        },
        Churn {
            name: "a session id",
            suffix: " ref=S-8813f2",
        },
        Churn {
            name: "a basket counter",
            suffix: " 3 items in your basket.",
        },
        Churn {
            name: "a rotating banner",
            suffix: " Summer sale: 15% off checked bags.",
        },
        Churn {
            name: "a seats-left nudge",
            suffix: " Only 2 seats left at this price!",
        },
        Churn {
            name: "an A/B variant marker",
            suffix: " variant=b",
        },
        Churn {
            name: "a currency switcher's echo",
            suffix: " Prices shown in EUR.",
        },
        Churn {
            name: "trailing whitespace",
            suffix: "   ",
        },
    ];
}

/// What one churn kind did to one kind of finding.
struct Churned {
    /// Did the finding survive the byte comparison?
    suppressed: bool,
    /// If it was suppressed, did the reason code tell an operator what to fix?
    diagnosable: bool,
}

fn churn(base: &str, suffix: &str, authority: Claim) -> Churned {
    let outcome = run(base, &format!("{base}{suffix}"), authority);
    match outcome {
        Verdict::Finding(_) => Churned {
            suppressed: false,
            diagnosable: false,
        },
        Verdict::Nothing(Checked::NotReproducible(why)) => Churned {
            suppressed: true,
            // Both of these name the same fix — narrow `Flow::panel` — one per
            // kind of finding. `answers` and `undetermined` leave an operator
            // with nothing to act on.
            diagnosable: matches!(why, Divergence::SameAnswer(_) | Divergence::BothSilent),
        },
        Verdict::Nothing(_) => Churned {
            suppressed: true,
            diagnosable: false,
        },
    }
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// Run the classification cases and the churn sweep, and report.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    // --- part 1 -------------------------------------------------------------
    let wrong: Vec<&str> = CASES
        .iter()
        .filter(|case| filed(&run(case.first, case.second, case.authority)) != case.expect)
        .map(|case| case.name)
        .collect();
    let total = CASES.len();
    rows.push(
        Row::ok(
            "classification matches the spec",
            if wrong.is_empty() {
                format!("{total}/{total} cases")
            } else {
                format!(
                    "{}/{total} — wrong: {}",
                    total - wrong.len(),
                    wrong.join(", ")
                )
            },
            Truth::Correct,
        )
        .gated(wrong.is_empty()),
    );

    // The single most dangerous confusion in the module: a captcha becoming a
    // sentence telling an airline its checkout says nothing about visas.
    let captcha_is_not_a_finding = matches!(
        run(CHALLENGE_TEXT, CHALLENGE_TEXT, Claim::VisaRequired),
        Verdict::Nothing(Checked::Blocked)
    );
    rows.push(
        Row::ok(
            "two identical captchas are not a finding",
            if captcha_is_not_a_finding {
                "blocked, as required"
            } else {
                "A CAPTCHA BECAME EVIDENCE"
            },
            Truth::Correct,
        )
        .gated(captcha_is_not_a_finding),
    );

    // --- part 2: the cost of the bar ---------------------------------------
    let sweep = |base: &str| -> Vec<(&'static Churn, Churned)> {
        Churn::ALL
            .iter()
            .map(|kind| (kind, churn(base, kind.suffix, Claim::VisaRequired)))
            .collect()
    };
    let contradicts = sweep(WRONG_TEXT);
    let says_nothing = sweep(SILENT_TEXT);

    let kinds = Churn::ALL.len();
    let survived: Vec<&str> = contradicts
        .iter()
        .chain(&says_nothing)
        .filter(|(_, c)| !c.suppressed)
        .map(|(kind, _)| kind.name)
        .collect();
    let lost_contradicts = contradicts.iter().filter(|(_, c)| c.suppressed).count();
    let lost_nothing = says_nothing.iter().filter(|(_, c)| c.suppressed).count();
    let seen_contradicts = contradicts.iter().filter(|(_, c)| c.diagnosable).count();
    let seen_nothing = says_nothing.iter().filter(|(_, c)| c.diagnosable).count();

    rows.push(
        Row::ok(
            "benign churn suppresses a finding",
            if survived.is_empty() {
                format!("{lost_contradicts}/{kinds} kinds, both finding types")
            } else {
                format!(
                    "{lost_contradicts}/{kinds} — survived: {}",
                    survived.join(", ")
                )
            },
            Truth::Characterises,
        )
        .gated(lost_contradicts == kinds && lost_nothing == kinds)
        .note("one byte of unrelated page churn costs the finding — that is the bar, working"),
    );

    rows.push(
        Row::ok(
            "…and an operator can see why",
            format!(
                "contradicts {seen_contradicts}/{kinds} diagnosable, \
                 says-nothing {seen_nothing}/{kinds}"
            ),
            Truth::Characterises,
        )
        .gated(seen_contradicts == kinds && seen_nothing == kinds)
        .note("same_answer + both_silent is the whole loss; says-nothing used to read 0/8"),
    );

    // The line the fourth reason is not allowed to cross. Churn around a silent
    // panel is a suppressed finding; a panel that never rendered is a page we
    // did not get, and pooling the two would trade one invisible number for one
    // wrong one.
    let blank = run(SILENT_TEXT, "   ", Claim::VisaRequired);
    let unrendered_is_apart = matches!(
        blank,
        Verdict::Nothing(Checked::NotReproducible(Divergence::Undetermined))
    );
    rows.push(
        Row::ok(
            "a blank panel is not a silent one",
            if unrendered_is_apart {
                "undetermined, apart from both_silent"
            } else {
                "AN UNRENDERED WIDGET IS BEING READ AS A SILENT CHECKOUT"
            },
            Truth::Correct,
        )
        .gated(unrendered_is_apart),
    );

    rows.push(
        Row::ok(
            "field suppression rate",
            "NOT MEASURABLE HERE — run REAL_RATE_SQL",
            Truth::Characterises,
        )
        .note("a rate over invented prospect pages would be an invented rate; none is published"),
    );

    Surface {
        name: "app::proof_of_need",
        method: "pure `verdict()` over fixture panel pairs; systematic benign-churn sweep for cost",
        rows,
        unmeasured: vec![
            "the FIELD suppression rate and its reason mix — needs proof_of_need_attempts rows \
             from real probes; the view exists, the data does not",
            "the FALSE-NEGATIVE rate: how many real defects the parser reads as SaysNothing or \
             Unreadable. Needs labelled real panel text, which we cannot collect without \
             probing prospects",
            "whether `both_silent` is ever wrong about a page we did not get: an empty read is \
             caught, but a skeleton loader rendering placeholder text is silence to us and a \
             prospect's checkout is not what we measured",
            "non-English panels beyond one French case — read_claim is an English phrase table \
             and 14 of Orizn's locales are untested",
            "looks_challenged against real bot-defence pages: the table is 10 English phrases \
             and its recall is unknown",
            "the browser half — Plan execution, gating, screenshots, the DB write — none of \
             which verdict() touches",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::proof_of_need::Finding;

    use super::*;

    /// The fixtures assert against `(outcome, detail)` strings because those are
    /// the `proof_of_need_attempts` columns. If `filed` ever stopped agreeing
    /// with the real codes, every case would be checking a typo against a typo.
    #[test]
    fn filed_uses_the_same_codes_the_database_stores() {
        assert_eq!(
            filed(&Verdict::Nothing(Checked::Blocked)),
            (Checked::Blocked.code(), Checked::Blocked.detail())
        );
        assert_eq!(
            filed(&Verdict::Finding(Finding::SaysNothing)),
            ("evidence", Some(Finding::SaysNothing.code()))
        );
        // Every expected code in the corpus is one the module can actually
        // produce — a fixture expecting "not_reproducable" would pass forever.
        // Both halves of the pair: a fixture expecting `Some("both_silant")`
        // would pass forever too, and that is the newest way to get it wrong.
        let real = [
            "evidence",
            "agrees",
            "unreadable",
            "not_reproducible",
            "blocked",
        ];
        let details = [
            Finding::SaysNothing.code(),
            Finding::Contradicts {
                shown: Claim::NoVisa,
                correct: Claim::VisaRequired,
            }
            .code(),
            Divergence::SameAnswer(Claim::NoVisa).code(),
            Divergence::BothSilent.code(),
            Divergence::Answers {
                first: Claim::NoVisa,
                second: Claim::VisaRequired,
            }
            .code(),
            Divergence::Undetermined.code(),
        ];
        for case in CASES {
            assert!(
                real.contains(&case.expect.0),
                "{} expects {:?}",
                case.name,
                case.expect
            );
            assert!(
                case.expect.1.is_none_or(|detail| details.contains(&detail)),
                "{} expects {:?}",
                case.name,
                case.expect
            );
        }
    }

    /// The churn sweep is only meaningful if the un-churned panel produces a
    /// finding in the first place. A base text that was never a finding would
    /// report a 100% suppression rate on nothing.
    #[test]
    fn both_churn_baselines_are_findings_before_the_churn() {
        assert!(matches!(
            run(WRONG_TEXT, WRONG_TEXT, Claim::VisaRequired),
            Verdict::Finding(Finding::Contradicts { .. })
        ));
        assert!(matches!(
            run(SILENT_TEXT, SILENT_TEXT, Claim::VisaRequired),
            Verdict::Finding(Finding::SaysNothing)
        ));
    }

    /// Every churn suffix has to actually change the bytes, or the sweep is
    /// measuring an empty string eight times.
    #[test]
    fn every_churn_kind_changes_the_page() {
        for kind in Churn::ALL {
            assert!(!kind.suffix.is_empty(), "{} is a no-op", kind.name);
        }
    }
}
