//! La surface d'outils du serveur MCP `orizn-visa`, telle qu'elle a été
//! capturée, et ce qu'une politique en fait.
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
//! Les tests ci-dessous ne touchent à rien : ils vérifient que chaque nom
//! survit au repliage en poignée de politique, que deux d'entre eux ne s'y
//! écrasent pas, et qu'un employé à qui l'on accorde cette surface se voit
//! accorder une *lecture* — la liste d'autorisations refuse un outil d'écriture
//! sur la base visa, propriété pour laquelle `RolePack::entry_requirements`
//! existe.
//!
//! Il y avait ici un test en ligne, qui montait un pont stdio→HTTP devant le
//! vrai serveur et lui posait une vraie question. Il est parti avec
//! `crates/app/src/orizn.rs` : c'était la vérification de bout en bout du
//! produit contre un SaaS réel, pas un morceau du produit. Le connecteur
//! `orizn-visa` du catalogue MCP, lui, reste — et ce fichier en est la
//! contrepartie testée.

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
