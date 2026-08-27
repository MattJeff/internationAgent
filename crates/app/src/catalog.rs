//! The connector catalogue: what we know about a third-party MCP server before
//! anybody has connected one.
//!
//! # The thesis this file is the answer to
//!
//! "GitHub, Discord, Trello, Smartlead and the customer's own server are all the
//! same thing — MCP servers, so there is no new subsystem to build, only a list
//! and a way to carry a token."
//!
//! That is true for every one of them **that answers Streamable HTTP**, and this
//! file is the list. It is not true for SSH, and the refusal is argued in
//! [`Credential`] rather than papered over with an entry that cannot work.
//!
//! # Why this is a `const`, and not a table
//!
//! A catalogue entry says *what a connector is allowed to be*: which URL a
//! handle resolves to, whether a credential is required, and the floor under the
//! risk class a customer may grant its tools. Those are our claims about a third
//! party, not a customer's configuration, and the difference decides the storage.
//!
//! The brief said this has to be something `app_role` cannot write. A table plus
//! a withheld `GRANT` would satisfy that sentence. A `const` satisfies it
//! *structurally*: there is no statement that writes an array in a binary, so
//! there is no privilege to withhold, no `REVOKE` to get wrong in migration
//! forty-one, and no row that can arrive malformed and need a fail-closed branch
//! to skip. `mcp::ALLOWED_SCHEMES` is the same call for the same reason, and
//! `0013_mcp` decision 3 is a whole paragraph about how nearly this went the
//! other way.
//!
//! What the `const` costs is real and is the honest half: adding a connector is
//! a deploy. That is the correct price for changing a security default, and it
//! is the same price `ALLOWED_SCHEMES` charges for a third URL scheme. What it
//! does *not* cost is a customer's ability to connect something we have never
//! heard of — [`CUSTOM`] is the entry for that, it takes a URL from the
//! customer, and everything after it is identical.
//!
//! # The floor is a claim, not a grant
//!
//! [`Connector::floor`] is the **lowest** [`RiskClass`] a customer may declare a
//! tool on this connector at. It only ever tightens: nothing here can lower a
//! class, mark a tool as read-only, or pre-declare anything. A tool nobody
//! declared is still [`RiskClass::Destructive`], exactly as `mcp::classify`
//! says, and a declaration still needs a digest of the tool as the server is
//! serving it.
//!
//! It is deliberately coarse — one class per connector, not per tool. The reason
//! is that the per-tool judgement already exists and is better: an operator
//! reads the name, the description and the input schema, and the SHA-256 pin
//! binds their grant to that exact reading. A per-tool table here would be a
//! second opinion about tools somebody else may rename tomorrow, maintained by
//! us, going stale silently. The floor answers a different and much smaller
//! question — "is there any tool on this connector that could be classed
//! `read`?" — and for a connector whose whole surface mutates a repository, the
//! answer is no and one constant says so.
//!
//! For [`CUSTOM`] the floor is [`RiskClass::Read`], which is no constraint at
//! all, and that is the truthful entry: we have never seen the server, so we
//! have no claim to make about it. Setting it to `Destructive` would not be
//! caution, it would be a false claim that we know the server is dangerous, and
//! it would make the entry useless — every call would need a human, forever.
//! What defends a custom binding is what defended every binding before this file
//! existed: the address check at bind time, the digest pin, and
//! undeclared-means-destructive.

use crate::mcp::{Reach, RiskClass};

/// What a connector needs from the person connecting it.
///
/// # There is no SSH variant, and that is the load-bearing part
///
/// The onboarding step this catalogue serves is described as "the API key, the
/// SSH — right, your company is connected". Two of those three are the same
/// thing and one is not.
///
/// A token is a credential *for a server somebody else already runs*. We dial an
/// endpoint, we send a header, `mcp::resolve_and_vet` has already refused every
/// address it does not like, and the blast radius of a hostile answer is bounded
/// by `Untrusted` and by the risk class of the tool that was called.
///
/// An SSH key is a credential *for running programs*. There is no MCP server at
/// the end of it. Making one appear means this process spawns something — either
/// an `ssh` child or a bridge — and `crates/app/src/mcp.rs` spends ninety lines
/// on why it will not: a spawned command runs in this process's tree with this
/// process's environment, which holds `DATABASE_URL` and the master key that
/// opens every tenant's sealed credentials, and *every* control in that module
/// rules on calls rather than on process creation. The address check that stops
/// an agent reading the cloud metadata endpoint is no defence against a child
/// process, because a child process already has `/proc/self/environ`.
///
/// So the honest answer is that SSH is not a connector, it is a *deployment*: the
/// customer runs an MCP server on their own box — theirs, or one of the many
/// off-the-shelf ones behind `supergateway` — and gives us its URL. That is
/// [`CUSTOM`], and it is a different sentence to the customer than "paste your
/// key". Writing an `Ssh` variant here would make the two look alike in the UI
/// while only one of them could ever work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// Nothing to send. The endpoint is open, or whatever grant it needs is
    /// already in the URL the customer pasted.
    None,
    /// One opaque string, sent as `Authorization: Bearer <it>`.
    ///
    /// The whole of what this catalogue supports today. Every remote MCP server
    /// worth connecting either takes one of these or takes OAuth, and OAuth is
    /// not here — see this module's tests and the report for what that costs.
    Bearer,
}

impl Credential {
    /// Stable, low-cardinality label, and the spelling the connect route reads
    /// back to a caller so a UI can decide which field to render.
    pub const fn code(self) -> &'static str {
        match self {
            Credential::None => "none",
            Credential::Bearer => "bearer",
        }
    }
}

/// One connector: everything needed to turn a name a customer clicked into a
/// binding `mcp::McpServer::bind` will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connector {
    /// The name the customer clicks. Lowercase, stable, and part of the API.
    pub key: &'static str,
    /// What to put on the button.
    pub label: &'static str,
    /// The endpoint, or `None` when the customer supplies it ([`CUSTOM`]).
    ///
    /// A fixed URL is most of the value of this file: a customer who cannot
    /// mistype the host cannot be phished into binding one, and the entry is
    /// the only thing in the system that can make that promise — the address
    /// check refuses a *class* of destinations, never a wrong-but-routable one.
    pub url: Option<&'static str>,
    /// The tightest [`Reach`] this connector can be bound at.
    ///
    /// `Public` for everything we name, because a connector whose URL we wrote
    /// down is on the internet. `CUSTOM` is the one that may be `Private`, for
    /// the sidecar case `Reach::Private` exists for, and it is the customer's
    /// deliberate choice recorded in a row.
    pub reach: Reach,
    /// What to ask the customer for.
    pub credential: Credential,
    /// The lowest class a tool on this connector may be declared at.
    ///
    /// Only ever tightens. See the module docs for why it is one class per
    /// connector and not a table of tools.
    pub floor: RiskClass,
}

/// The entry for a server the customer runs or already knows the URL of.
///
/// Named separately because two routes reach for it by identity: it is the only
/// entry that takes a URL from the request, and the only one whose [`Reach`] the
/// customer may choose.
pub const CUSTOM: Connector = Connector {
    key: "custom",
    label: "Your own MCP server",
    url: None,
    // The permissive one, and the only entry that gets it: this is the sidecar
    // and the on-premises case. `Reach::Private` still refuses link-local, so
    // the cloud metadata endpoint is out of reach here as it is everywhere else.
    reach: Reach::Private,
    credential: Credential::Bearer,
    // No claim. We have not seen this server. See the module docs.
    floor: RiskClass::Read,
};

/// Every connector we have written down.
///
/// Short on purpose. An entry is a claim about somebody else's product — their
/// URL, their auth scheme, the floor under their tools — and a claim we have not
/// checked is worse than an absent entry, because an absent entry sends the
/// customer to [`CUSTOM`] where they paste a URL they looked up themselves.
///
/// Each entry below carries the reason it is a static bearer token rather than
/// OAuth, because that is the question every one of them raises.
pub const CATALOG: &[Connector] = &[
    Connector {
        key: "github",
        label: "GitHub",
        // GitHub's own remote MCP server, Streamable HTTP, and it takes a
        // personal access token as a bearer — which is why it is the first
        // entry: it is the one major connector that works today with a string
        // the customer can paste, with no OAuth dance to build first.
        url: Some("https://api.githubcopilot.com/mcp/"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Nothing GitHub's server exposes is observation-only in the sense that
        // matters here: the same token that reads an issue opens one, and the
        // read tools return repository content that becomes `Untrusted` text an
        // employee then acts on. `Write` is the floor, so no customer can class
        // any of it `read` without an operator writing the row by hand.
        floor: RiskClass::Write,
    },
    CUSTOM,
];

/// Look one up by the name a customer clicked.
///
/// `None` is a 404 at the route, never a fallback to [`CUSTOM`]: falling back
/// would mean a typo in the connector name silently becomes "bind whatever URL
/// was in the body", which is the one substitution this file exists to prevent.
pub fn find(key: &str) -> Option<&'static Connector> {
    CATALOG.iter().find(|c| c.key == key)
}

impl Connector {
    /// Refuse a class below this connector's floor.
    ///
    /// `Ok(())` when `asked` is at least as strict as the floor. The comparison
    /// is [`RiskClass`]'s own ordering — `Read < Write < Destructive` — so
    /// "stricter" is `>=` and there is nothing to remember.
    ///
    /// This is a *tightening* and it can only ever be one: a connector with
    /// `floor: Read` accepts everything, exactly as the surface behaved before
    /// this file existed, and no value of `floor` can make a class more
    /// permissive than what the caller asked for.
    /// ponytail: not `const`. A `const fn` would have to compare the classes as
    /// `u8`, which is a second ordering that agrees with `RiskClass`'s derived
    /// one only for as long as nobody reorders the variants. One ordering.
    pub fn admits(&self, asked: RiskClass) -> Result<(), RiskClass> {
        if asked >= self.floor {
            Ok(())
        } else {
            Err(self.floor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor tightens and cannot widen, at every combination there is.
    #[test]
    fn a_floor_only_ever_refuses_and_never_grants() {
        let all = [RiskClass::Read, RiskClass::Write, RiskClass::Destructive];
        for floor in all {
            let connector = Connector { floor, ..CUSTOM };
            for asked in all {
                match connector.admits(asked) {
                    // Whatever it lets through is what the caller asked for.
                    // There is no branch that returns a *different*, lower class,
                    // which is the property that makes this unable to widen.
                    Ok(()) => assert!(asked >= floor, "{asked:?} slipped under {floor:?}"),
                    Err(reported) => {
                        assert!(asked < floor);
                        assert_eq!(reported, floor);
                    }
                }
            }
        }
    }

    /// `Read` is no constraint, which is what `CUSTOM` claims and has to mean.
    #[test]
    fn the_custom_entry_constrains_nothing_and_says_so() {
        assert_eq!(CUSTOM.floor, RiskClass::Read);
        for asked in [RiskClass::Read, RiskClass::Write, RiskClass::Destructive] {
            assert_eq!(CUSTOM.admits(asked), Ok(()));
        }
        assert!(CUSTOM.url.is_none(), "the customer supplies it");
    }

    /// Every named entry is bindable by the client that will bind it.
    ///
    /// Not a style check: a URL in this array is one a customer cannot correct,
    /// so a typo here is a connector nobody can use and an error message that
    /// blames their network. `vet_url` is the same function `declare_server`
    /// runs on a customer's own string.
    #[test]
    fn every_catalogued_url_is_one_the_mcp_client_accepts() {
        for connector in CATALOG {
            let Some(url) = connector.url else { continue };
            crate::mcp::vet_url(url).unwrap_or_else(|err| panic!("{}: {err}", connector.key));
            assert!(
                url.starts_with("https://"),
                "{}: a catalogued endpoint is on the internet and must be TLS",
                connector.key
            );
            assert_eq!(
                connector.reach,
                Reach::Public,
                "{}: a public endpoint has no business reaching private space",
                connector.key
            );
        }
    }

    /// Keys are the API. Two entries under one key is a lookup that silently
    /// picks the first, and `find` is what routes a customer's click.
    #[test]
    fn keys_are_unique_and_lowercase() {
        let mut keys: Vec<&str> = CATALOG.iter().map(|c| c.key).collect();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), count, "duplicate connector key");
        for connector in CATALOG {
            assert_eq!(connector.key, connector.key.to_lowercase());
            assert_eq!(find(connector.key), Some(connector));
        }
        assert_eq!(find("gıthub"), None, "a lookup is exact, never fuzzy");
    }
}
