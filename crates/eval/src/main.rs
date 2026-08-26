//! `cargo run -p agentos-eval` — the report a human reads in thirty seconds.
//!
//! ```text
//! cargo run -p agentos-eval                     the deterministic suites (also `cargo test`)
//! cargo run -p agentos-eval -- --live           …plus the model held-out set, ~1 minute
//! cargo run -p agentos-eval -- --live --model X  a different model
//!
//! DATABASE_URL=… cargo run -p agentos-eval --features live-orizn -- --dry-run [passes=3]
//!                                               Orizn stood up for real and worked, ~10 min
//! ```
//!
//! `--dry-run` exits non-zero when a **structural** row fails — the loop did not
//! run, no tool was called, a tool call got no ruling, the provider errored. It
//! never exits non-zero for a number: how many calls a turn took and what they
//! cost are samples, and a threshold on a sample is a flaky build.
//!
//! The deterministic half is the same code CI runs as a test, so this binary
//! and the build agree by construction rather than by somebody remembering to
//! keep two lists in step. `--live` shells out to the local `claude` binary via
//! [`CliLlm`](agentos_providers::llm_cli::CliLlm): no API key, no spend.
//!
//! Exit code is 0 unless a [`Truth::Correct`](agentos_eval::Truth) row failed.

use agentos_domain::untrusted::TrustLabel;
use agentos_eval::toolchoice::{CASES, Chose, DEFAULT_MODEL, digest, run_live};
use agentos_eval::{Surface, deterministic, render, suppression::REAL_RATE_SQL};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let live = args.iter().any(|a| a == "--live");
    let model = args
        .iter()
        .position(|a| a == "--model")
        .and_then(|i| args.get(i + 1))
        .map_or(DEFAULT_MODEL, String::as_str);

    // The dry run is not a suite and does not print one: it stands a company up
    // and works it, which is its own report. Nothing below it applies.
    #[cfg(feature = "live-orizn")]
    if args.iter().any(|a| a == "--dry-run") {
        // Three, not one: every sampled row it prints is a spread across passes,
        // and a spread over one pass is a figure wearing a range's clothes.
        let passes = args
            .iter()
            .position(|a| a == "--dry-run")
            .and_then(|i| args.get(i + 1))
            .and_then(|n| n.parse().ok())
            .unwrap_or(3);
        if !agentos_eval::dryrun::run(model, passes).await {
            std::process::exit(1);
        }
        return;
    }

    let surfaces = deterministic();
    print!("{}", render(&surfaces));

    println!("\nThe real proof-of-need suppression rate is a query, not a fixture:");
    println!("  {REAL_RATE_SQL}");

    if live {
        live_report(model).await;
    } else {
        println!(
            "\nModel tool choice is not measured above. To measure it (~1 min, no API key):\n  \
             cargo run -p agentos-eval -- --live"
        );
    }

    if !surfaces.iter().all(Surface::passed) {
        std::process::exit(1);
    }
}

/// The held-out set, run against the local CLI.
///
/// Prints the prompt digest beside the scores, because a tool-choice score
/// without the prompt it was measured against is a number with no subject —
/// and CI will refuse the pin the moment that prompt is edited.
async fn live_report(model: &str) {
    println!("\n─────────────────────────────────────────────────────────────");
    println!("LIVE — {model} via the local `claude` CLI");
    println!(
        "prompt {} / {}\n",
        digest(TrustLabel::Trusted),
        digest(TrustLabel::Untrusted)
    );

    let results = run_live(model).await;
    let mut correct = 0usize;
    let mut violations = 0usize;
    let mut malformed = 0usize;

    for (case, chose) in &results {
        let ok = chose.matches(case);
        correct += usize::from(ok);
        if let Chose::Tool(name, _) = chose
            && case.must_not == Some(name.as_str())
        {
            violations += 1;
        }
        if matches!(chose, Chose::Malformed(_)) {
            malformed += 1;
        }

        let wanted = case.want.unwrap_or("(prose)");
        let got = match chose {
            Chose::Tool(name, args) => format!("{name} {args}"),
            Chose::Prose => "(prose)".to_owned(),
            Chose::Malformed(code) => format!("shim failed: {code}"),
        };
        println!(
            "  {} {:<24}  want {:<15} got {got}",
            if ok { " " } else { "!" },
            case.name,
            wanted
        );
        if !ok {
            println!("    {:<24}  {}", "", case.why);
        }
    }

    let n = CASES.len();
    println!("\n  tool choice        {correct}/{n} correct");
    println!("  safety violations  {violations} (a forbidden tool was called)");
    println!("  shim failures      {malformed}/{n} (llm_cli could not parse the reply)");
    println!(
        "\n  Compare against a previous run at the SAME prompt digest. A different digest \
         means\n  the prompt moved and the two numbers are not comparable."
    );
}
