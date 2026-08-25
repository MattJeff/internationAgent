//! The real Orizn MCP server, and the employee that reads it.
//!
//! Two things live here, and only the second one needs a network.
//!
//! [`ORIZN_TOOLS`] is the server's tool surface as it was actually captured, and
//! it is the reason this file is not in `src/`: nothing in the product reads it.
//! It exists so that drift is *visible* — the six names, what each one requires,
//! and the class an operator should declare each at. Everything downstream of an
//! MCP server in this workspace is keyed on tool names an operator wrote down
//! (`mcp_tool_declarations`, `PolicyLimits::allowed_mcp_tools`), so "what is
//! this server actually called and what does it actually take" is a fact the
//! repository should hold in one place rather than in six configuration files.
//!
//! The offline tests below check the parts of that fixture that do not need the
//! server: that every name survives the fold into a policy handle, that no two
//! collapse onto the same one, and that an employee granted this surface is
//! granted a *read* of it — the allowlist refuses a write tool on the visa
//! database, which is the property `RolePack::entry_requirements` exists for.
//! The one live test checks the part that does — that the fixture still
//! describes the server, and that a real question gets a real answer.

use std::collections::{BTreeMap, BTreeSet};

use agentos_app::mcp::RiskClass;
use agentos_app::rolepack_service::RolePack;
use agentos_domain::action::McpTool;
use agentos_domain::ids::Slug;
use agentos_domain::policy::{
    Decision, DenyReason, EffectivePolicy, PolicyLimits, evaluate_mcp_call,
};

/// One tool on the real server, as captured.
struct OriznTool {
    /// The name on the wire, verbatim. Underscores, not hyphens — the server's
    /// spelling, which is what `mcp_tool_declarations.tool` holds.
    wire: &'static str,
    /// The class an operator should declare it at, which for this server is
    /// `Read` for all six. It is what goes in `mcp_tool_declarations.risk`, and
    /// `a_write_tool_on_the_visa_database_is_not_in_this_employees_allowlist`
    /// is what notices if a seventh tool arrives classed anything else.
    risk: RiskClass,
    /// `inputSchema.required`, in the schema's own order.
    required: &'static [&'static str],
}

/// **The real tool surface of `orizn-visa-mcp`.**
///
/// Captured 2026-08-25 from `npx -y orizn-visa-mcp`, which reported
/// `serverInfo` `{"name": "orizn-visa", "version": "1.3.0"}` and negotiated
/// `protocolVersion` `2025-06-18`, by writing `initialize` then `tools/list`
/// to its stdin and reading the replies. Six tools, and the list is *closed* —
/// `tools/list` returned no `nextCursor`.
///
/// # Read this before trusting the shape of it
///
/// Three of the six do not work without an API key, and the server says so in
/// the tool description rather than by hiding the tool: `check_visa_requirement`,
/// `compare_destinations` and `check_transit_visa` are advertised, discoverable,
/// declarable — and fail at call time with no key. `compare_destinations` and
/// `check_transit_visa` need a *paid* key on top of that. So the tool inventory
/// is not the entitlement, and an employee that reads the inventory as a list of
/// things that will work has been misled by the server. That is not a bug to
/// route around here; it is why `crate::mcp` wraps every result in
/// `Untrusted<T>` and why the pack's briefing says an error or an empty answer
/// means Orizn has no data rather than that there is nothing to find.
///
/// Two of the six work keyless: `quick_visa_check` (rate-limited to ten a day)
/// and `get_coverage_stats`. `get_recent_changes` answers keyless but the feed
/// is switched off at the source and returns `{status: "unavailable",
/// changes: []}` — the server's own description explains that it was publishing
/// internal inconsistencies as if they were policy changes, which is the exact
/// failure the entry-requirements pack exists to prevent a repeat of.
///
/// # Why every one of them is `Read`
///
/// Not a default and not a shrug: all six only look things up. Five answer
/// questions about a passport/destination pair or a country, and the sixth
/// reports the size of the database. There is no tool on this server that
/// writes a rule, and that is the fact that lets this employee be granted the
/// whole server without being granted a way to change it. The packs used to
/// state that as a `RiskClass::Read` ceiling of their own; nothing read it, and
/// the allowlist that the gate does read says the same thing.
const ORIZN_TOOLS: [OriznTool; 6] = [
    OriznTool {
        wire: "check_visa_requirement",
        risk: RiskClass::Read,
        required: &["passport", "destination"],
    },
    OriznTool {
        wire: "quick_visa_check",
        risk: RiskClass::Read,
        required: &["passport", "destination"],
    },
    OriznTool {
        wire: "compare_destinations",
        risk: RiskClass::Read,
        required: &["passport", "destinations"],
    },
    OriznTool {
        wire: "check_transit_visa",
        risk: RiskClass::Read,
        required: &["passport", "transit_country"],
    },
    OriznTool {
        wire: "get_coverage_stats",
        risk: RiskClass::Read,
        required: &[],
    },
    OriznTool {
        wire: "get_recent_changes",
        risk: RiskClass::Read,
        required: &[],
    },
];

/// The fold `crate::mcp::handle` applies, restated here because it is private
/// there and this file has to predict its answer without a server.
///
/// One line, and deliberately not exported from the crate to be shared: a test
/// that computes the handle with the same function the code under test uses
/// proves the two agree with themselves and nothing else. This is the
/// independent statement of what the handles are supposed to be.
fn handle(wire: &str) -> String {
    wire.replace('_', "-")
}

/// Every wire name folds to a distinct policy handle.
///
/// This is the check that would have caught the collision `McpError::AmbiguousTool`
/// refuses at bind time — `_` folds to `-`, which is not injective, so a server
/// offering both `get_recent_changes` and `get-recent-changes` would fail to
/// bind at all and take the whole binding down with it. Six in, six out.
#[test]
fn every_orizn_tool_has_its_own_policy_handle() {
    let mut handles: BTreeMap<String, &str> = BTreeMap::new();
    for tool in &ORIZN_TOOLS {
        // `Slug` is kebab-case ASCII; a name that does not fold to one is
        // dropped by `mcp::inventory` and is therefore unreachable by any
        // allowlist, which for this server would mean a tool nobody can call.
        assert!(
            tool.wire
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{} does not fold to a slug",
            tool.wire
        );
        if let Some(clash) = handles.insert(handle(tool.wire), tool.wire) {
            panic!("{} and {} collapse onto one handle", clash, tool.wire);
        }
    }
    assert_eq!(handles.len(), ORIZN_TOOLS.len());
}

/// **"You propose, you do not change", as the gate actually enforces it.**
///
/// This assertion used to be `pack.may_call_tool(RiskClass::Write) == false`,
/// against a `max_tool_risk` ceiling on the pack. The ceiling was declared by
/// every pack, documented at length, and consulted by nothing outside this
/// test — so the sentence it used to carry ("refused by the pack rather than by
/// anybody remembering to leave it out of `allowed_mcp_tools`") had it exactly
/// backwards: leaving it out of `allowed_mcp_tools` was the only thing refusing
/// anything. The field is gone and this is the same claim, made against the
/// four-layer allowlist that always was the enforcement.
///
/// A provisioner grants this employee the six read tools by the struct update
/// `rolepack`'s module docs describe. `update_visa_requirement` is the
/// hypothetical write tool — the correction this briefing exists to route to a
/// person — and it is denied by name, with the reason the gate would give.
/// Add it to the allowlist below and this test goes red, which is what the
/// ceiling was supposed to do and never did.
#[test]
fn a_write_tool_on_the_visa_database_is_not_in_this_employees_allowlist() {
    let orizn = Slug::parse("orizn").expect("slug");
    let read_tools: BTreeSet<McpTool> = ORIZN_TOOLS
        .iter()
        .map(|tool| {
            // The fixture's own classes are the operator's declaration, and the
            // surface is `Read` end to end — so "the read tools" and "the whole
            // server" are the same set today. That is a fact about this server,
            // not a licence: the filter is what keeps it true if one grows.
            assert_eq!(
                tool.risk,
                RiskClass::Read,
                "{} is not a read tool",
                tool.wire
            );
            McpTool::new(
                orizn.clone(),
                Slug::parse(&handle(tool.wire)).expect("handle"),
            )
        })
        .collect();

    let role = PolicyLimits {
        allowed_mcp_tools: read_tools.clone(),
        ..RolePack::entry_requirements().limits().clone()
    };
    let policy = EffectivePolicy::try_new(&role, &role, &role, &role)
        .expect("the entry-requirements defaults are coherent");

    for tool in &read_tools {
        assert!(
            evaluate_mcp_call(&policy, tool).is_allow(),
            "{tool} is on the server and in the allowlist; it must be callable"
        );
    }

    let write = McpTool::new(orizn, Slug::parse("update-visa-requirement").expect("slug"));
    assert_eq!(
        evaluate_mcp_call(&policy, &write),
        Decision::Deny {
            reason: DenyReason::ToolNotAllowed
        },
        "a write tool on the visa database is the correction this role must propose, not make"
    );
}

/// Every tool that takes a passport takes it under that name.
///
/// Small, and it is the one thing about the schemas a caller can get wrong
/// silently: `check_transit_visa` takes `transit_country`, not `destination`,
/// and `compare_destinations` takes `destinations` (plural, an array), not
/// `destination`. An argument the server does not recognise is not an error on
/// this server — it is a required-field failure that reads like a data gap.
#[test]
fn the_captured_schemas_do_not_share_one_spelling() {
    let by_name: BTreeMap<&str, &[&str]> = ORIZN_TOOLS
        .iter()
        .map(|tool| (tool.wire, tool.required))
        .collect();
    assert_eq!(
        by_name["check_transit_visa"],
        &["passport", "transit_country"]
    );
    assert_eq!(
        by_name["compare_destinations"],
        &["passport", "destinations"]
    );
    assert_eq!(by_name["quick_visa_check"], &["passport", "destination"]);
    // The two that need nothing at all, which is why they are the two an
    // operator can use to prove a binding works.
    assert!(by_name["get_coverage_stats"].is_empty());
    assert!(by_name["get_recent_changes"].is_empty());
}

// ---------------------------------------------------------------------------
// The live test
// ---------------------------------------------------------------------------

/// Everything below dials the real server. See `Cargo.toml`'s `live-orizn`
/// feature for why this is a `cfg` and not a runtime skip: `scripts/test.sh`
/// fails the build on a printed `SKIP:`, and a test needing `npx` and the open
/// internet cannot satisfy that guard by being satisfiable, so it removes itself
/// from the default build instead of passing quietly inside it.
#[cfg(feature = "live-orizn")]
mod live {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use agentos_app::mcp::{McpServer, Reach, RiskClass};
    use agentos_domain::action::McpTool;
    use agentos_domain::ids::Slug;
    use rmcp::model::JsonObject;
    use tokio_util::sync::CancellationToken;

    use super::{ORIZN_TOOLS, handle};

    /// The bridge, as a child process.
    ///
    /// `supergateway` off the shelf rather than a proxy written here. It is what
    /// `crate::mcp`'s module docs tell an operator to run, so the test runs the
    /// operator's deployment rather than a test-shaped imitation of it — the
    /// only way this test can prove the documented arrangement works is by being
    /// that arrangement.
    ///
    /// `kill_on_drop` so a panicking assertion does not leave a node process
    /// holding the port. It kills the bridge and not the grandchild `npx -y
    /// orizn-visa-mcp`, which is fine and is how the server is designed to
    /// stop: the bridge dying closes its stdin, and the server exits on EOF —
    /// its own log line for that is "Shutting down".
    struct Bridge {
        child: tokio::process::Child,
        port: u16,
    }

    impl Bridge {
        /// Start it on a free port and wait until it answers.
        async fn start() -> Bridge {
            // Ask the OS for a port and immediately give it back. Racy in
            // principle; the alternative is a hard-coded port, which is racy
            // against every other developer on the machine instead.
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("a free port")
                .local_addr()
                .expect("a bound address")
                .port();

            let child = tokio::process::Command::new("npx")
                .args([
                    "-y",
                    "supergateway",
                    "--stdio",
                    "npx -y orizn-visa-mcp",
                    "--outputTransport",
                    "streamableHttp",
                    "--port",
                    &port.to_string(),
                    "--streamableHttpPath",
                    "/mcp",
                    "--logLevel",
                    "none",
                ])
                // Stateless is the default and is the one that matters: a
                // session-ful bridge would hand back an `Mcp-Session-Id` that
                // `crate::mcp` never echoes, because the client it builds is
                // sessionless-first. Named here so that a future default flip
                // is a visible break rather than a mysterious 400.
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect(
                    "npx is not on PATH; the live-orizn feature needs node, and the bridge \
                     command is in `crate::mcp`'s module docs",
                );

            let bridge = Bridge { child, port };
            bridge.wait_until_listening().await;
            bridge
        }

        /// Poll the port until something accepts. `npx -y` may be downloading
        /// two packages on a cold machine, so the budget is generous and the
        /// failure names what did not happen.
        async fn wait_until_listening(&self) {
            for _ in 0..120 {
                if tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                    .await
                    .is_ok()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            panic!(
                "the stdio->http bridge never listened on 127.0.0.1:{} within 60s",
                self.port
            );
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/mcp", self.port)
        }
    }

    impl Drop for Bridge {
        fn drop(&mut self) {
            // `kill_on_drop` already arms this; `start_kill` makes it happen
            // now rather than when the tokio runtime next reaps, which matters
            // because the runtime is about to be dropped too.
            let _ = self.child.start_kill();
        }
    }

    fn slug(raw: &str) -> Slug {
        Slug::parse(raw).expect("a valid slug")
    }

    /// **The whole integration, end to end, against the real thing.**
    ///
    /// It binds through `McpServer::bind` — the same function `Fleet::bind`
    /// calls for a tenant's row — at `Reach::Private`, because the bridge is a
    /// loopback sidecar and loopback is exactly what `Reach::Public` refuses.
    /// That is not a concession made for the test: it is the documented
    /// deployment, and a binding that had to be `Public` to work would mean the
    /// operator had to expose the bridge.
    ///
    /// # Why France to Japan
    ///
    /// The assertion needs a pair whose answer will not move under the test.
    /// FRA→JPN is visa-free for 90 days under a bilateral arrangement that has
    /// stood since the 1950s, on both a G7 and a Schengen passport; Japan
    /// suspended it once, for COVID, and restored it. It is the kind of rule
    /// that changes with years of notice and treaty ratification, not by
    /// ministerial notice on a Tuesday.
    ///
    /// The deliberate non-choices are the argument: anything involving a
    /// jurisdiction in dispute, a scheme mid-rollout (ETIAS, the UK ETA, any
    /// e-visa launch), a country with an active advisory, or a passport whose
    /// reciprocity is a live political question would be a test that fails one
    /// morning because the *world* changed and the code did not — which is a
    /// test that teaches people to ignore it.
    ///
    /// `quick_visa_check` and not `check_visa_requirement`: the detailed tool
    /// needs an API key, and a test that needs a secret is a test that runs on
    /// one machine. This one runs keyless, ten a day, on anybody's.
    #[tokio::test]
    async fn the_real_orizn_server_answers_a_pair_that_does_not_move() {
        let bridge = Bridge::start().await;

        // What an operator would have written into `mcp_tool_declarations`:
        // every tool by name, every one at `Read`. `digest: None` is the
        // migrating spelling — the class travels with the name — and it is used
        // here on purpose, because pinning a digest would make this test fail on
        // the day Orizn edits a tool description, which is drift the fixture
        // should report and not something that should stop the build.
        let declared: BTreeMap<Slug, agentos_app::mcp::Declaration> = ORIZN_TOOLS
            .iter()
            .map(|tool| {
                (
                    slug(&handle(tool.wire)),
                    agentos_app::mcp::Declaration {
                        risk: tool.risk,
                        digest: None,
                    },
                )
            })
            .collect();

        let server = McpServer::bind(
            slug("orizn"),
            &bridge.url(),
            &declared,
            Reach::Private,
            CancellationToken::new(),
        )
        .await
        .expect("the bridged orizn server binds");

        // Drift check number one: the fixture still describes the server. A
        // tool added, removed or renamed upstream lands here, in a diff, with
        // the capture date on `ORIZN_TOOLS` saying how old the claim was.
        let discovered: Vec<String> = server
            .tools()
            .values()
            .map(|tool| tool.wire_name().to_owned())
            .collect();
        let mut expected: Vec<String> = ORIZN_TOOLS
            .iter()
            .map(|tool| tool.wire.to_owned())
            .collect();
        expected.sort_by_key(|wire| handle(wire));
        assert_eq!(
            discovered, expected,
            "orizn-visa-mcp's tool surface has moved since ORIZN_TOOLS was captured"
        );

        // Drift check number two, and the one that is a security property
        // rather than an inventory: `classify` takes the stricter of what the
        // operator declared and what the server's own annotations admit to. All
        // six coming back `Read` says the server is claiming nothing worse. A
        // server that started advertising a destructive hint would raise these
        // and the pack's ceiling would then refuse the call — which is the
        // machinery working, and this is where it becomes visible.
        for bound in server.tools().values() {
            assert_eq!(
                bound.risk(),
                RiskClass::Read,
                "{} did not bind as a read",
                bound.wire_name()
            );
            assert!(
                bound.is_declared(),
                "{} was not declared",
                bound.wire_name()
            );
        }

        // The real question, to the real server.
        let mut arguments = JsonObject::new();
        arguments.insert("passport".to_owned(), "FRA".into());
        arguments.insert("destination".to_owned(), "JPN".into());
        let result = server
            .call(
                &McpTool::new(slug("orizn"), slug("quick-visa-check")),
                Some(arguments),
            )
            .await
            .expect("quick_visa_check answers");

        // `expose_for_parsing`, which is the only way to read one of these and
        // is named to be greppable: this is a third party's text being parsed,
        // not being put in front of a model.
        let result = result.expose_for_parsing();
        assert_ne!(
            result.is_error,
            Some(true),
            "the server reported a tool error: {:?}",
            result.content
        );

        // The tool returns its JSON as a text block, so the payload is parsed
        // out of the rendered string rather than read off `structured_content`.
        let rendered = serde_json::to_string(&result.content).expect("content is serialisable");
        let answer: serde_json::Value = result
            .content
            .iter()
            .find_map(|block| block.as_text())
            .and_then(|text| serde_json::from_str(&text.text).ok())
            .unwrap_or_else(|| panic!("no json text block in the answer: {rendered}"));

        assert_eq!(answer["passport"], "FRA");
        assert_eq!(answer["destination"], "JPN");
        assert_eq!(
            answer["requirement"], "visa_free",
            "France to Japan stopped being visa-free, or we asked the wrong question: {answer}"
        );
        assert_eq!(answer["visa_free_days"], 90);
        assert_eq!(answer["visa_required"], false);

        // Not an assertion about a value, because it moves every time Orizn
        // re-verifies the pair — but an assertion that it is *there*. The whole
        // discipline in this pack's briefing is that a rule without a
        // verification date is a lead, and a server that stopped sending one
        // would silently turn every answer into a lead.
        assert!(
            answer
                .get("last_verified")
                .is_some_and(|date| date.is_string()),
            "the answer carries no verification date: {answer}"
        );

        server.close().await.expect("the binding closes");
    }
}
