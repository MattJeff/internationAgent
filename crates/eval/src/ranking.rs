//! Does [`rank`] order quotes the way a competent buyer would?
//!
//! # Method: fixtures with an expected answer anyone can redo by hand
//!
//! [`rank`], [`disagreement`] and [`shortlist`] are pure functions of their
//! arguments. No clock, no model, no database. So the honest evaluation is the
//! cheap one: rounds of quotes whose reference ordering is *arithmetic*, worked
//! out in the comment above each fixture, and re-derivable by anyone who
//! disagrees with it. This runs in CI on every push and a regression in ranking
//! breaks the build.
//!
//! # Where the ground truth comes from, and where it stops
//!
//! **High confidence, because the reference is not an opinion.** Landed cost is
//! defined — convert the goods once, add the duty when the buyer is the
//! importer, add the legs the incoterm left behind — and the expected ordering
//! is that definition evaluated by hand. A fixture here cannot encode one
//! person's guess about which supplier is nicer, because there is no room in it
//! for a guess.
//!
//! **But the definition is itself a judgement, and that judgement is the thing
//! the question was really about.** "The way a competent buyer would" is not
//! "cheapest landed" in every round: a buyer looking at a 2% saving against 35
//! extra days of lead time frequently takes the dearer quote, and `rank` cannot
//! express that because lead time is a tie-break and nothing else. That is
//! deliberate — a weighting between euros and days is a business decision and
//! putting one inside a sort key hides it — so the suite does not fail on it.
//! It **measures** it: [`Round::CURRENCY_AGAINST_TIME`] is a round where the
//! landed-cost winner is not the lead-time winner, and the report says how many
//! rounds are like that. A reader who thinks the number is too high is being
//! told something true about the system.
//!
//! The other named limit is the duty base. `landed_cost` charges duty on the
//! converted invoice value, which is where a broker starts; on an EXW lane a
//! customs authority would add the freight to it first. That is a documented
//! ponytail ceiling in `app::sourcing`, and [`Round::DUTY_BASE`] is the round
//! where the simplification changes who wins — recorded as a characterisation,
//! with the numbers a broker would have used, so the day somebody's bill
//! disagrees the fixture is already there.

use agentos_app::sourcing::{
    Fx, Incoterm, Landed, Lane, Quote, Reputation, disagreement, rank, shortlist,
};
use agentos_domain::action::EmailAddress;
use agentos_domain::money::{Currency, Money};
use agentos_domain::sourcing::{self as buying, RfqId, SampleAvailability, SupplierId};
use chrono::{DateTime, TimeZone, Utc};

use crate::{Row, Surface, Truth};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One supplier's answer to the round's RFQ.
struct Bid {
    supplier: &'static str,
    unit_minor: u64,
    currency: Currency,
    incoterm: Incoterm,
    lead_days: u32,
}

/// One RFQ fan-out, with the ordering a buyer should get back.
struct Round {
    name: &'static str,
    quantity: u64,
    bids: &'static [Bid],
    lane: Lane,
    /// `(from, numerator, denominator)` — minor units of the comparison
    /// currency per minor unit of `from`.
    rates: &'static [(Currency, u64, u64)],
    /// Cheapest landed first. Derived by hand; see each round's comment.
    reference: &'static [&'static str],
}

/// A lane with nothing on it, as a base for the rounds that isolate one term.
const FREE: Lane = Lane::new(Currency::Eur);

impl Round {
    /// **The whole reason `landed_cost` exists.** Four quotes whose unit-price
    /// order is very nearly the reverse of their landed order.
    ///
    /// Lane: handling €200, freight €1200, insurance €150, clearance €90,
    /// last mile €250 (€1890 of fixed legs), duty 5%. Quantity 1000.
    ///
    /// ```text
    ///   a  EXW  €6.00  goods €6000  legs €1890  duty €300.00  = €8190.00
    ///   b  DDP  €7.90  goods €7900  legs    €0  duty    €0    = €7900.00
    ///   c  FOB  €6.40  goods €6400  legs €1690  duty €320.00  = €8410.00
    ///   d  CIF  €7.10  goods €7100  legs  €340  duty €355.00  = €7795.00
    /// ```
    ///
    /// Unit price says `a, c, d, b`. Landed says `d, b, a, c`. The cheapest
    /// quote in the round is the third most expensive thing to receive.
    const INCOTERMS: Round = Round {
        name: "incoterms",
        quantity: 1_000,
        bids: &[
            Bid {
                supplier: "a@exw.example",
                unit_minor: 600,
                currency: Currency::Eur,
                incoterm: Incoterm::Exw,
                lead_days: 45,
            },
            Bid {
                supplier: "b@ddp.example",
                unit_minor: 790,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
            Bid {
                supplier: "c@fob.example",
                unit_minor: 640,
                currency: Currency::Eur,
                incoterm: Incoterm::Fob,
                lead_days: 40,
            },
            Bid {
                supplier: "d@cif.example",
                unit_minor: 710,
                currency: Currency::Eur,
                incoterm: Incoterm::Cif,
                lead_days: 35,
            },
        ],
        lane: Lane {
            export_handling_minor: 20_000,
            freight_minor: 120_000,
            insurance_minor: 15_000,
            clearance_minor: 9_000,
            last_mile_minor: 25_000,
            duty_bps: 500,
            ..FREE
        },
        rates: &[],
        reference: &[
            "d@cif.example",
            "b@ddp.example",
            "a@exw.example",
            "c@fob.example",
        ],
    };

    /// A CNY quote against a EUR one, and **the round where cheapest-landed is
    /// arguably not what a buyer wants.**
    ///
    /// Rate: 13 cents per 100 fen. Lane: freight €800, no duty. Quantity 500.
    ///
    /// ```text
    ///   cn  FOB  ¥45.00  goods ¥22 500 -> €2925  legs €800  = €3725.00  55 days
    ///   eu  DDP   €7.60  goods         €3800     legs   €0  = €3800.00  20 days
    /// ```
    ///
    /// `rank` returns `cn, eu`: it is €75 cheaper on €3800, a saving of 2.0%,
    /// for 35 extra days. Plenty of competent buyers take `eu`. `rank` has no
    /// way to say so and that is a design decision, not a defect — but it is
    /// the honest limit of what this suite can certify.
    const CURRENCY_AGAINST_TIME: Round = Round {
        name: "currency-against-time",
        quantity: 500,
        bids: &[
            Bid {
                supplier: "cn@cny.example",
                unit_minor: 4_500,
                currency: Currency::Cny,
                incoterm: Incoterm::Fob,
                lead_days: 55,
            },
            Bid {
                supplier: "eu@eur.example",
                unit_minor: 760,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 20,
            },
        ],
        lane: Lane {
            freight_minor: 80_000,
            ..FREE
        },
        rates: &[(Currency::Cny, 13, 100)],
        reference: &["cn@cny.example", "eu@eur.example"],
    };

    /// Three identical totals. The ordering must still be total and the same
    /// every time, which is the property `rank`'s third sort key exists for.
    ///
    /// All €10.00 DDP on a free lane, quantity 100, so every total is €1000.00.
    /// Lead time breaks first (`m` at 20 days), then the address — `a@` before
    /// `z@`, whatever order they arrived in.
    const TIES: Round = Round {
        name: "ties",
        quantity: 100,
        bids: &[
            Bid {
                supplier: "z@t.example",
                unit_minor: 1_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
            Bid {
                supplier: "m@t.example",
                unit_minor: 1_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 20,
            },
            Bid {
                supplier: "a@t.example",
                unit_minor: 1_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
        ],
        lane: FREE,
        rates: &[],
        reference: &["m@t.example", "a@t.example", "z@t.example"],
    };

    /// The duty-base simplification, at the point where it changes the winner.
    ///
    /// Lane: freight €2000, duty 10%. Quantity 100.
    ///
    /// ```text
    ///   exw  EXW  €50.00  goods €5000  legs €2000  duty €500  = €7500.00   <- wins
    ///   dap  DAP  €69.00  goods €6900  legs    €0  duty €690  = €7590.00
    /// ```
    ///
    /// A customs authority computing the EXW duty on a rebuilt CIF value
    /// (€5000 + €2000 freight) charges €700, not €500, and `exw` lands at
    /// €7700 — behind `dap`. So this pair is inside the error bar of the
    /// documented simplification. Characterised, not asserted as correct.
    const DUTY_BASE: Round = Round {
        name: "duty-base",
        quantity: 100,
        bids: &[
            Bid {
                supplier: "exw@d.example",
                unit_minor: 5_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Exw,
                lead_days: 30,
            },
            Bid {
                supplier: "dap@d.example",
                unit_minor: 6_900,
                currency: Currency::Eur,
                incoterm: Incoterm::Dap,
                lead_days: 30,
            },
        ],
        lane: Lane {
            freight_minor: 200_000,
            duty_bps: 1_000,
            ..FREE
        },
        rates: &[],
        reference: &["exw@d.example", "dap@d.example"],
    };

    /// One supplier priced at three times the others: the round
    /// [`disagreement`] is supposed to notice.
    ///
    /// Free lane, quantity 10, all DDP at 30 days, so the totals are the unit
    /// prices ×10: €100, €110, €300. The spread is 20 000 bps against a 2 000
    /// bps threshold.
    const OUTLIER: Round = Round {
        name: "outlier",
        quantity: 10,
        bids: &[
            Bid {
                supplier: "low@s.example",
                unit_minor: 1_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
            Bid {
                supplier: "mid@s.example",
                unit_minor: 1_100,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
            Bid {
                supplier: "high@s.example",
                unit_minor: 3_000,
                currency: Currency::Eur,
                incoterm: Incoterm::Ddp,
                lead_days: 30,
            },
        ],
        lane: FREE,
        rates: &[],
        reference: &["low@s.example", "mid@s.example", "high@s.example"],
    };

    const ALL: [Round; 5] = [
        Round::INCOTERMS,
        Round::CURRENCY_AGAINST_TIME,
        Round::TIES,
        Round::DUTY_BASE,
        Round::OUTLIER,
    ];

    fn fx(&self) -> Fx {
        self.rates
            .iter()
            .fold(Fx::new(self.lane.currency), |fx, &(from, num, den)| {
                fx.with(from, num, den)
            })
    }

    /// The round, ranked. Panics on a malformed fixture, which is what a
    /// malformed fixture deserves.
    fn ranked(&self) -> Vec<Landed> {
        let now = at(1_800_000_000);
        let domain: Vec<buying::Quote> = self.bids.iter().map(|bid| bid.quote(now)).collect();
        let quotes: Vec<Quote<'_>> = domain
            .iter()
            .zip(self.bids)
            .map(|(quote, bid)| {
                Quote::live_at(quote, address(bid.supplier), self.quantity, now)
                    .expect("fixture quote is live")
            })
            .collect();
        rank(&quotes, &self.lane, &self.fx()).expect("fixture round normalises")
    }
}

impl Bid {
    fn quote(&self, now: DateTime<Utc>) -> buying::Quote {
        buying::Quote {
            rfq_id: RfqId::new_v7(now),
            supplier_id: SupplierId::new_v7(now),
            unit_price: Money::new(self.unit_minor, self.currency).expect("non-zero price"),
            moq: std::num::NonZeroU32::new(1).expect("1 is non-zero"),
            lead_time_days: self.lead_days,
            valid_from: at(1_700_000_000),
            valid_until: at(1_900_000_000),
            incoterm: self.incoterm,
            sample: SampleAvailability::None,
        }
    }
}

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().expect("valid instant")
}

fn address(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("fixture address parses")
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Kendall's tau between an ordering and the reference: `+1.0` identical,
/// `-1.0` reversed, `0.0` no better than a coin.
///
/// The ordering metric rather than "is the list equal", because *how wrong* a
/// ranking is matters: swapping the two cheapest quotes is a different failure
/// from putting the dearest first, and an equality assertion scores both zero.
/// The equality assertion is kept too — it is the one that has to hold.
fn kendall_tau(got: &[String], want: &[&str]) -> f64 {
    let position = |item: &str| want.iter().position(|w| *w == item);
    let mut concordant = 0i64;
    let mut discordant = 0i64;

    for (i, left) in got.iter().enumerate() {
        for right in &got[i + 1..] {
            match (position(left), position(right)) {
                (Some(a), Some(b)) if a < b => concordant += 1,
                (Some(_), Some(_)) => discordant += 1,
                // A ranking that dropped or invented a supplier is not a
                // ranking with a tau; it is a bug the equality row catches.
                _ => return f64::NAN,
            }
        }
    }
    let pairs = concordant + discordant;
    if pairs == 0 {
        return 1.0;
    }
    (concordant - discordant) as f64 / pairs as f64
}

fn reputation(returned: i64, missed: i64) -> Reputation {
    Reputation {
        supplier_id: SupplierId::new_v7(at(1_800_000_000)).as_uuid(),
        observation_count: returned + missed,
        quotes_returned: returned,
        quotes_missed: missed,
        delivered_on_time: 0,
        delivered_late: 0,
        quality_accepted: 0,
        quality_rejected: 0,
        disputes: 0,
        on_time_rate_pct: None,
        response_rate_pct: None,
        quality_rate_pct: None,
        last_observed_at: at(1_800_000_000),
    }
}

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

/// Run every ranking fixture and report.
pub fn evaluate() -> Surface {
    let mut rows = Vec::new();

    // --- rank: the ordering itself -----------------------------------------
    let ranked: Vec<(&Round, Vec<Landed>)> = Round::ALL.iter().map(|r| (r, r.ranked())).collect();

    let mut exact = 0usize;
    let mut tau_sum = 0.0;
    for (round, landed) in &ranked {
        let got: Vec<String> = landed.iter().map(|l| l.supplier.to_string()).collect();
        let want: Vec<&str> = round.reference.to_vec();
        if got.iter().map(String::as_str).eq(want.iter().copied()) {
            exact += 1;
        }
        tau_sum += kendall_tau(&got, &want);
    }
    let n = ranked.len();
    let tau = tau_sum / n as f64;

    rows.push(
        Row::ok(
            "ordering matches reference",
            format!("{exact}/{n} rounds exact"),
            Truth::Correct,
        )
        .gated(exact == n),
    );
    rows.push(
        Row::ok(
            "Kendall tau vs reference",
            format!("{tau:.3}"),
            Truth::Correct,
        )
        .gated((tau - 1.0).abs() < 1e-9),
    );

    // --- what ranking on the sticker price would have done ------------------
    // The argument for `landed_cost`, as a number rather than a paragraph.
    let sticker_winner_differs = ranked
        .iter()
        .filter(|(round, landed)| {
            let by_sticker = round
                .bids
                .iter()
                .min_by_key(|bid| (bid.unit_minor, bid.supplier))
                .expect("round has bids");
            landed[0].supplier.to_string() != by_sticker.supplier
        })
        .count();
    rows.push(
        Row::ok(
            "unit price picks a different winner",
            format!("{sticker_winner_differs}/{n} rounds"),
            Truth::Characterises,
        )
        .note("this is what landed_cost buys; it is a property of the corpus, not of the code"),
    );

    // --- and the limit of ranking on cost alone -----------------------------
    let cost_beats_time = ranked
        .iter()
        .filter(|(_, landed)| {
            landed
                .iter()
                .any(|other| other.lead_time_days < landed[0].lead_time_days)
        })
        .count();
    rows.push(
        Row::ok(
            "winner is not the fastest",
            format!("{cost_beats_time}/{n} rounds"),
            Truth::Characterises,
        )
        .note("rank has no euros-per-day term by design; a buyer may disagree with these"),
    );

    // --- the duty base, at the point where it flips the answer --------------
    // €5000 goods + €2000 freight at 10% is €700 of duty, not €500; that puts
    // exw@ at €7700 and behind dap@ at €7590.
    let duty_base_flips = {
        let landed = Round::DUTY_BASE.ranked();
        let winner = landed[0].supplier.to_string();
        let rebuilt = landed[0].goods_minor + Round::DUTY_BASE.lane.freight_minor;
        let corrected = landed[0].total.minor() + (rebuilt - landed[0].goods_minor) / 10;
        winner == "exw@d.example" && corrected > landed[1].total.minor()
    };
    rows.push(
        Row::ok(
            "duty-base simplification flips a winner",
            if duty_base_flips {
                "yes, 1 round"
            } else {
                "no"
            },
            Truth::Characterises,
        )
        .note("duty is charged on the invoice value, not a rebuilt CIF value — a known ceiling"),
    );

    // --- disagreement -------------------------------------------------------
    // Quiet by design: over five rounds exactly two gaps clear their
    // thresholds, and they are the two the fixtures were built to contain.
    let found: Vec<(&str, String, String)> = ranked
        .iter()
        .flat_map(|(round, landed)| {
            disagreement(landed)
                .into_iter()
                .map(move |d| (round.name, d.field.code().to_owned(), d.high.to_string()))
        })
        .collect();
    let expected: [(&str, &str, &str); 2] = [
        ("currency-against-time", "lead_time_days", "cn@cny.example"),
        ("outlier", "landed_total", "high@s.example"),
    ];
    let disagreement_ok = found.len() == expected.len()
        && found
            .iter()
            .zip(expected)
            .all(|((n, f, h), (en, ef, eh))| *n == en && f == ef && h == eh);
    rows.push(
        Row::ok(
            "disagreement fires where specified",
            format!("{}/{} gaps, no others", found.len(), expected.len()),
            Truth::Correct,
        )
        .gated(disagreement_ok),
    );

    // --- shortlist ----------------------------------------------------------
    let silent = reputation(0, 4);
    let answered_once = reputation(1, 9);
    let four = vec![
        (address("keep1@s.example"), None),
        (address("keep2@s.example"), Some(answered_once.clone())),
        (address("keep3@s.example"), Some(reputation(3, 1))),
        (address("drop@s.example"), Some(silent.clone())),
    ];
    let drops_the_silent = shortlist(&four)
        .iter()
        .all(|a| a.to_string() != "drop@s.example")
        && shortlist(&four).len() == 3;

    let three = vec![
        (address("keep1@s.example"), None),
        (address("keep2@s.example"), Some(reputation(2, 0))),
        (address("drop@s.example"), Some(silent)),
    ];
    // Dropping would leave two, which is below MIN_SHORTLIST, so the evidence
    // has stopped buying anything and everyone is asked.
    let floor_holds = shortlist(&three).len() == 3;

    rows.push(
        Row::ok(
            "shortlist drops only the never-answered",
            if drops_the_silent && floor_holds {
                "drop rule + floor both hold"
            } else {
                "BROKEN"
            },
            Truth::Correct,
        )
        .gated(drops_the_silent && floor_holds),
    );

    Surface {
        name: "app::sourcing",
        method: "fixtures with hand-derived reference orderings; pure functions, runs in CI",
        rows,
        unmeasured: vec![
            "whether the landed-cost definition is the right objective — no euros-per-day \
             term exists, so no fixture can test one",
            "Buyer::issue_rfq / place_order / negotiation: gated I/O, covered by tests not evals",
            "Candidate::parse_all against real supplier directory output (we have none)",
            "whether real RFQ rounds look anything like these five",
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tau_is_one_for_identical_and_minus_one_for_reversed() {
        let want = ["a", "b", "c"];
        let same: Vec<String> = want.iter().map(|s| (*s).to_owned()).collect();
        let reversed: Vec<String> = want.iter().rev().map(|s| (*s).to_owned()).collect();

        assert!((kendall_tau(&same, &want) - 1.0).abs() < 1e-9);
        assert!((kendall_tau(&reversed, &want) + 1.0).abs() < 1e-9);
        // One adjacent swap out of three pairs: two concordant, one discordant.
        let swapped = vec!["b".to_owned(), "a".to_owned(), "c".to_owned()];
        assert!((kendall_tau(&swapped, &want) - 1.0 / 3.0).abs() < 1e-9);
    }

    /// A ranking that lost a supplier has no tau, and must not silently score
    /// well.
    #[test]
    fn a_dropped_supplier_is_not_a_tau_of_one() {
        let got = vec!["a".to_owned(), "ghost".to_owned()];
        assert!(kendall_tau(&got, &["a", "b"]).is_nan());
    }

    /// The fixture comments claim specific euro totals. If the arithmetic in
    /// the doc comment and the arithmetic in the code ever disagree, the
    /// comment is the thing everyone reads and the fixture is worthless.
    #[test]
    fn the_arithmetic_in_the_comments_is_the_arithmetic_in_the_code() {
        let landed = Round::INCOTERMS.ranked();
        let totals: Vec<u64> = landed.iter().map(|l| l.total.minor()).collect();
        assert_eq!(totals, vec![779_500, 790_000, 819_000, 841_000]);

        let landed = Round::CURRENCY_AGAINST_TIME.ranked();
        assert_eq!(landed[0].total.minor(), 372_500, "CNY leg converted wrong");
        assert_eq!(landed[1].total.minor(), 380_000);
    }
}
