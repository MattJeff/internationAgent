//! `/metrics` — a hand-rolled Prometheus text exposition.
//!
//! Six series and no exporter crate. Six because those are the ones an
//! operator is woken up by: the gate refusing work, provisioning failing to
//! finish an employee, the model bill, humans not clearing the approval queue,
//! and the outbox — lag and dead letters — which is the difference between
//! "accepted" and "actually happened". Everything else a dashboard might like
//! is already in the traces, and thirteen more series here would only make the
//! six that matter harder to find.
//!
//! # Cardinality is the whole design
//!
//! A single unbounded label — one tenant id, one employee id, one provider's
//! error string — multiplies the series count by the number of distinct values
//! forever, and kills the scrape long before anyone notices the dashboard got
//! slow. So the recording functions here take **typed values, never strings**:
//! [`Denied`], [`Step`], [`StepReport`], [`Usage`]. Their `code()`/`as_str()`
//! accessors return `&'static str` from a closed `match`, which is a compile-
//! time bound on the label set. There is deliberately no `record(name, label)`
//! taking a `&str`: if it existed, someone would eventually pass an id to it.
//!
//! # No credential, and therefore no tenant
//!
//! Scrapers do not hold API keys, so this endpoint is mounted outside the API
//! stack next to `/livez` and `/readyz`. That makes every number here readable
//! by anything that can reach the port, which is exactly why nothing here is
//! per-tenant. [`record_llm_usage`] takes the tenant and drops it on the floor
//! (into a debug span, which is authenticated by being a log) — per-tenant
//! spend is the ledger's job, behind a key. The aggregate is what an operator
//! pages on anyway: "the token spend rate doubled", not "which tenant".
//!
//! The corollary is a deployment requirement, not a code one: **the listener
//! must not be publicly routable.** The deny-reason mix and the approval-queue
//! depth are operational intelligence, and `/readyz` beside it already
//! publishes the outbox lag. `app()` in `main.rs` carries the argument for why
//! authentication is the wrong tool here and the ingress is the right one.
//!
//! # Where the numbers come from
//!
//! The three counters are process-local and reset when the pod restarts, which
//! is what `_total` means and what `rate()` expects. The three gauges are read
//! from Postgres at scrape time — the outbox lag through
//! [`crate::loops::outbox::lag_secs`], the poller's own definition, so this
//! endpoint and `/readyz` can never disagree about whether the queue is behind.
//!
//! Every counter's production call sites are one per *surface*, and each is the
//! place the event funnels through rather than a place it happens to pass. That
//! is the property worth holding — not a count, which has already been wrong
//! here twice:
//!
//! * [`record_denial`] — `impl From<Denied> for ApiError` in
//!   [`crate::error`], and `routes::a2a::denied` for the JSON-RPC surface,
//!   which does not build an `ApiError`.
//! * [`record_provisioning`] — `loops::provisioning`'s `drive`, which is where
//!   the engine's reports come back.
//! * [`record_llm_usage`] — the turn handler in `main.rs`, on both of its exits:
//!   the failed turn and the finished one. Both are needed and neither is a
//!   funnel for the other — a turn that dies mid-model-call has still spent the
//!   tokens, and billing it on only one exit is the same undercount as not
//!   billing it at all. `agentos_llm_tokens_total` therefore does **not** read
//!   zero any more; this bullet said "still test-only" long after both calls
//!   landed, which was the last of the three counters to stop being a lie.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};

use agentos_app::gate::Denied;
use agentos_app::mocks::Usage;
use agentos_app::provisioning::StepReport;
use agentos_domain::employee::Step;
use agentos_domain::ids::TenantId;
use agentos_store::db::{Db, StoreError};
use agentos_store::outbox;
use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// The exposition format Prometheus negotiates by default.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Most dead letters we will count.
///
/// ponytail: the gauge saturates here. One dead letter is already a page and
/// a hundred is already an incident, so the exact number past that changes
/// nobody's next move. Upgrade path if it ever does: a `count` accessor beside
/// `outbox::dead_letters`, so the predicate still lives in one place.
const DEAD_LETTER_CAP: i64 = 100;

static COUNTERS: Mutex<Counters> = Mutex::new(Counters::new());

/// Process-local counters. Every key is a `&'static str` from a closed match —
/// see the module docs on why that is not an implementation detail.
#[derive(Debug)]
struct Counters {
    /// Deny reason code → count.
    denials: BTreeMap<&'static str, u64>,
    /// (step, outcome code) → count.
    provisioning: BTreeMap<(&'static str, &'static str), u64>,
    /// Tokens, summed across every tenant. Saturating, via [`Usage::add`].
    llm: Usage,
}

impl Counters {
    const fn new() -> Self {
        Self {
            denials: BTreeMap::new(),
            provisioning: BTreeMap::new(),
            llm: Usage::new(0, 0, 0),
        }
    }
}

/// ponytail: one global mutex, held for the length of a `+= 1` or a render of
/// a few dozen lines. Sharded atomics if a profile ever says so; it will not.
/// A poisoned lock is recovered rather than propagated — the numbers behind it
/// are still perfectly good numbers, and a scrape that panics because some
/// unrelated handler did is an outage with no telemetry.
fn counters() -> MutexGuard<'static, Counters> {
    COUNTERS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One policy-gate refusal, by [`Denied::code`].
///
/// Takes the refusal itself rather than its code so that the call site cannot
/// pass anything else — `Denied::PendingApproval(id)` carries an id, and this
/// is the function that guarantees it never becomes a label.
pub fn record_denial(denied: &Denied) {
    *counters().denials.entry(denied.code()).or_default() += 1;
}

/// One provisioning step outcome, by step and [`StepReport::code`].
pub fn record_provisioning(step: Step, report: &StepReport) {
    *counters()
        .provisioning
        .entry((step.as_str(), report.code()))
        .or_default() += 1;
}

/// One model call's tokens.
///
/// `tenant_id` is taken and deliberately not exported: it goes to a log line,
/// which is behind the same wall as the rest of the logs, while the metric
/// stays aggregate. See the module docs.
///
/// **Its call site exists now**, in `Agent::on_turn`, beside both
/// `model_usage::record` calls — the successful turn and the failed one that
/// still paid for what it spent. The `allow(dead_code)` that sat here said
/// "delete it in the commit that adds the call"; that commit was a long time
/// coming, and until it did, token counts were persisted to `model_usage_daily`
/// and never observable anywhere a human watches.
pub fn record_llm_usage(tenant_id: TenantId, usage: Usage) {
    tracing::debug!(tenant_id = %tenant_id, tokens = usage.total(), "llm usage");
    counters().llm.add(usage);
}

/// The numbers that live in Postgres rather than in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gauges {
    approvals_pending: i64,
    outbox_lag_secs: i64,
    outbox_dead_letters: i64,
}

/// The scrape endpoint. No auth layer, by design — see the module docs.
pub fn router(db: Db) -> Router {
    Router::new().route("/metrics", get(scrape)).with_state(db)
}

async fn scrape(State(db): State<Db>) -> Response {
    // A database that is down is exactly when someone is reading this page, so
    // the process counters are served regardless and only the gauges go
    // missing. Prometheus already knows what to do with a series that stops
    // reporting; it does not know what to do with a 500.
    let gauges = match gauges(&db).await {
        Ok(gauges) => Some(gauges),
        Err(err) => {
            tracing::warn!(error = %err, "metrics: database gauges unavailable");
            None
        }
    };

    (
        [(header::CONTENT_TYPE, CONTENT_TYPE)],
        render(gauges.as_ref()),
    )
        .into_response()
}

async fn gauges(db: &Db) -> Result<Gauges, StoreError> {
    // The poller's own lag, not a second copy of the query that could drift
    // from it and leave two dashboards disagreeing.
    let outbox_lag_secs = crate::loops::outbox::lag_secs(db).await?;

    // Cross-tenant, like the backlog itself. Both counts are of things nobody
    // owns: work the platform has failed to finish.
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let dead = outbox::dead_letters(&mut tx, DEAD_LETTER_CAP).await?;
    // An expired approval is not queue depth: nobody can act on it, so
    // counting it would give a graph that climbs and never comes back.
    let approvals_pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approvals \
          WHERE state = 'pending' \
            AND (expires_at IS NULL OR expires_at > now())",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;

    Ok(Gauges {
        approvals_pending,
        outbox_lag_secs,
        outbox_dead_letters: i64::try_from(dead.len()).unwrap_or(DEAD_LETTER_CAP),
    })
}

/// The exposition itself.
///
/// A family always prints its `HELP`/`TYPE` even with no samples, so an
/// operator can tell "no denials" from "that metric does not exist here".
fn render(gauges: Option<&Gauges>) -> String {
    let counters = counters();
    let mut out = String::new();

    family(
        &mut out,
        "agentos_policy_denials_total",
        "counter",
        "Policy gate refusals, by deny reason code.",
    );
    for (code, count) in &counters.denials {
        let _ = writeln!(
            out,
            "agentos_policy_denials_total{{code=\"{code}\"}} {count}"
        );
    }

    family(
        &mut out,
        "agentos_provisioning_steps_total",
        "counter",
        "Provisioning step outcomes, by step and result code.",
    );
    for ((step, result), count) in &counters.provisioning {
        let _ = writeln!(
            out,
            "agentos_provisioning_steps_total{{step=\"{step}\",result=\"{result}\"}} {count}"
        );
    }

    family(
        &mut out,
        "agentos_llm_tokens_total",
        "counter",
        "Model tokens across all tenants, by kind. Per-tenant spend is in the ledger, not here.",
    );
    let llm = counters.llm;
    for (kind, tokens) in [
        ("input", llm.input_tokens),
        ("output", llm.output_tokens),
        ("cache_read", llm.cache_read_tokens),
    ] {
        let _ = writeln!(out, "agentos_llm_tokens_total{{kind=\"{kind}\"}} {tokens}");
    }

    family(
        &mut out,
        "agentos_approvals_pending",
        "gauge",
        "Approvals waiting on a human, across all tenants.",
    );
    if let Some(g) = gauges {
        let _ = writeln!(out, "agentos_approvals_pending {}", g.approvals_pending);
    }

    family(
        &mut out,
        "agentos_outbox_lag_seconds",
        "gauge",
        "Age of the oldest due, unpublished outbox event. The same number /readyz fails on.",
    );
    if let Some(g) = gauges {
        let _ = writeln!(out, "agentos_outbox_lag_seconds {}", g.outbox_lag_secs);
    }

    family(
        &mut out,
        "agentos_outbox_dead_letters",
        "gauge",
        "Outbox events that exhausted their attempts and will never be published. Capped at 100.",
    );
    if let Some(g) = gauges {
        let _ = writeln!(out, "agentos_outbox_dead_letters {}", g.outbox_dead_letters);
    }

    out
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

#[cfg(test)]
mod tests {
    use agentos_app::gate::RedemptionFailure;
    use agentos_domain::ids::{ApprovalId, EmployeeId};
    use agentos_domain::policy::DenyReason;
    use chrono::Utc;

    use super::*;

    // The counters are global and the tests run in one process, so each test
    // picks codes no other test touches and asserts on a delta rather than an
    // absolute count. That is the price of a process-wide registry, and it is
    // cheaper than threading a registry through every call site for the sake
    // of the tests.

    /// The value of the first series whose line starts with `prefix`.
    fn sample(out: &str, prefix: &str) -> Option<u64> {
        out.lines()
            .find(|line| line.starts_with(prefix))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
    }

    /// Every non-comment line: `name{labels} value`, split into name+labels
    /// and value.
    fn samples(out: &str) -> Vec<(&str, &str)> {
        out.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.rsplit_once(' ').expect("a sample has a value"))
            .collect()
    }

    fn label_values(out: &str) -> Vec<&str> {
        samples(out)
            .into_iter()
            .filter_map(|(series, _)| series.split_once('{'))
            .flat_map(|(_, labels)| {
                labels
                    .trim_end_matches('}')
                    .split(',')
                    .filter_map(|pair| pair.split_once('='))
                    .map(|(_, value)| value.trim_matches('"'))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn the_output_parses_as_prometheus_text() {
        record_denial(&Denied::Policy(DenyReason::CurrencyMismatch));
        record_provisioning(Step::Wallet, &StepReport::Ready);
        record_llm_usage(TenantId::new_v7(Utc::now()), Usage::new(1, 2, 3));

        let out = render(Some(&Gauges {
            approvals_pending: 4,
            outbox_lag_secs: 7,
            outbox_dead_letters: 0,
        }));

        // Every family declares itself before it is sampled, exactly once.
        let mut declared: Vec<&str> = Vec::new();
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').expect("TYPE names a kind");
                assert!(
                    matches!(kind, "counter" | "gauge"),
                    "unknown metric type {kind}"
                );
                assert!(!declared.contains(&name), "{name} declared twice");
                declared.push(name);
                continue;
            }
            if let Some(rest) = line.strip_prefix("# HELP ") {
                assert!(rest.contains(' '), "HELP without help text: {line}");
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect("a sample has a value");
            let name = series.split_once('{').map_or(series, |(name, _)| name);
            assert!(declared.contains(&name), "{name} sampled before its TYPE");
            assert!(
                name.starts_with("agentos_"),
                "{name} is missing the namespace"
            );
            value.parse::<f64>().expect("a sample value is a number");
        }

        // And the gauges are rendered from the argument, not from the process.
        assert!(declared.contains(&"agentos_policy_denials_total"));
        assert!(declared.contains(&"agentos_approvals_pending"));
        assert_eq!(sample(&out, "agentos_approvals_pending "), Some(4));
        assert_eq!(sample(&out, "agentos_outbox_lag_seconds "), Some(7));
    }

    #[test]
    fn a_denial_increments_the_counter_for_its_code() {
        let series = "agentos_policy_denials_total{code=\"cross_tenant_secret\"}";
        let before = sample(&render(None), series).unwrap_or(0);

        record_denial(&Denied::Policy(DenyReason::CrossTenantSecret));

        assert_eq!(sample(&render(None), series), Some(before + 1));
    }

    /// The wiring, not the counter: rendering a refusal as an HTTP problem
    /// document is what every REST route does with a `Denied`, and it is the
    /// one place that has to count. A counter nobody increments reads as "no
    /// denials", which is the worst possible way to be wrong.
    #[test]
    fn turning_a_refusal_into_a_response_is_what_counts_it() {
        let series = "agentos_policy_denials_total{code=\"domain_denied\"}";
        let before = sample(&render(None), series).unwrap_or(0);

        // Exactly what a handler's `?` does.
        let _: crate::error::ApiError = Denied::Policy(DenyReason::DomainDenied).into();

        assert_eq!(sample(&render(None), series), Some(before + 1));
    }

    /// The two `Denied` variants that carry an id must still land on a code.
    #[test]
    fn a_denial_that_carries_an_id_still_labels_by_code() {
        let now = Utc::now();
        record_denial(&Denied::PendingApproval(ApprovalId::new_v7(now)));
        record_denial(&Denied::Redemption(RedemptionFailure::ActionMismatch));
        record_denial(&Denied::NotActive(
            agentos_domain::employee::Lifecycle::Suspended,
        ));

        let out = render(None);
        assert!(
            sample(
                &out,
                "agentos_policy_denials_total{code=\"pending_approval\"}"
            )
            .is_some()
        );
        assert!(
            sample(
                &out,
                "agentos_policy_denials_total{code=\"approval_action_mismatch\"}"
            )
            .is_some()
        );
        assert!(
            sample(
                &out,
                "agentos_policy_denials_total{code=\"employee_not_active\"}"
            )
            .is_some()
        );
    }

    #[test]
    fn a_provisioning_failure_is_labelled_by_step_and_result() {
        let series = "agentos_provisioning_steps_total{step=\"phone\",result=\"blocked\"}";
        let before = sample(&render(None), series).unwrap_or(0);

        record_provisioning(Step::Phone, &StepReport::Blocked { on: Step::Identity });

        assert_eq!(sample(&render(None), series), Some(before + 1));
    }

    /// The dependency in `Blocked`, the poll ref in `PendingExternal`, the
    /// tenant in `record_llm_usage`: none of them may reach a label.
    #[test]
    fn no_label_value_is_ever_an_id() {
        let tenant = TenantId::new_v7(Utc::now());
        let employee = EmployeeId::new_v7(Utc::now());

        record_llm_usage(tenant, Usage::new(10, 5, 0));
        record_provisioning(
            Step::Whatsapp,
            &StepReport::PendingExternal {
                poll_ref: format!("sender-review/{}", employee.as_uuid()),
            },
        );

        let out = render(Some(&Gauges {
            approvals_pending: 1,
            outbox_lag_secs: 0,
            outbox_dead_letters: 0,
        }));

        assert!(!out.contains(&tenant.as_uuid().to_string()));
        assert!(!out.contains(&employee.as_uuid().to_string()));
        for value in label_values(&out) {
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "label value {value:?} is not a low-cardinality code"
            );
            assert!(value.len() <= 40, "label value {value:?} looks like an id");
        }
    }

    /// The property that keeps the scrape alive: touching the same counter
    /// with a thousand tenants adds a thousand rows to nothing.
    #[test]
    fn many_tenants_do_not_grow_the_series_count() {
        let llm_series = |out: &str| {
            out.lines()
                .filter(|line| line.starts_with("agentos_llm_tokens_total{"))
                .count()
        };
        assert_eq!(llm_series(&render(None)), 3);

        for _ in 0..1_000 {
            record_llm_usage(TenantId::new_v7(Utc::now()), Usage::new(1, 1, 1));
        }

        assert_eq!(llm_series(&render(None)), 3);
    }

    /// Scrapers do not have an API key. Needs a real Postgres because the
    /// gauges are real queries — but note the endpoint answers even when they
    /// fail, which is the other half of the point.
    #[tokio::test]
    async fn the_endpoint_answers_without_a_credential() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the metrics gauges need a real Postgres");
            return;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        let response = router(db)
            .oneshot(
                Request::get("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("service");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(CONTENT_TYPE)
        );

        let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        let out = String::from_utf8(body.to_vec()).expect("utf-8");
        assert!(sample(&out, "agentos_approvals_pending ").is_some());
        assert!(sample(&out, "agentos_outbox_lag_seconds ").is_some());
        assert!(sample(&out, "agentos_outbox_dead_letters ").is_some());

        // And the same cardinality bound holds on what actually goes over the
        // wire, not only on `render`. This is the body a stranger who can
        // reach the port would read, so it is the one that has to be free of
        // ids — `no_label_value_is_ever_an_id` above asserts the property, this
        // asserts it survived the handler.
        for value in label_values(&out) {
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "the scrape exposed {value:?}, which is not a low-cardinality code"
            );
        }
    }
}
