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
//! It is also not true for the ones that ship only as a **stdio package**, which
//! is most of them — and that gap is what [`Provision::Host`] closes. Such an
//! entry names a [`crate::hosted::Package`]: a program we agree to run, on a
//! tenant's behalf, in a container this process does not own. The whole of the
//! isolation argument is in [`crate::hosted`]; what belongs here is only that
//! the program is written down in the same array, under the same rule, as
//! everything else we make a claim about. A tenant never names a package, for
//! exactly the reason `crate::mcp` gives for refusing a tenant-supplied command:
//! the allowlist of permitted programs *is* the configuration.
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

use crate::hosted::Package;
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
/// An SSH key is a credential *for running programs on somebody else's box*.
/// There is no MCP server at the end of it, and the program it would run is
/// whatever the person holding the key decides — which is the property
/// `crates/app/src/mcp.rs` spends ninety lines refusing, because a command
/// nobody wrote down has no checkable property at all.
///
/// **[`Provision::Host`] is not the counter-example, and the difference is the
/// whole of why it is safe.** Hosting runs a package *this binary names*, in a
/// container *we* describe, on a network we allocated — see [`crate::hosted`].
/// An SSH connector would run a command *the customer names*, in a shell on a
/// machine we know nothing about, and the only thing the two share is the word
/// "process". One is an allowlist; the other is an interpreter.
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
    /// One opaque string the customer pastes.
    ///
    /// Sent as `Authorization: Bearer <it>` for a connector we dial. For a
    /// [`Provision::Host`] entry the string is the same shape and the customer's
    /// experience is identical, but it goes into [`Package::env`] inside the
    /// bridge instead of onto a header — which is not a second kind of
    /// credential, it is the same one delivered where the package looks for it.
    /// The destination is [`Connector::provision`]'s to say, and keeping it
    /// there is what stops two fields disagreeing about whether a binding is
    /// hosted.
    ///
    /// A customer pastes it. It is the cheapest credential to support and the
    /// only one GitHub's remote server needs, which is why it was the first.
    Bearer,
    /// The authorization code flow: a consent page, a redirect back, and a token
    /// this deployment exchanged for.
    ///
    /// What comes out is still sent as `Authorization: Bearer <it>` — the access
    /// token goes in the same column and down the same header as a pasted one,
    /// and `mcp::McpServer::bind` cannot tell the two apart. That is the whole
    /// reason this variant is cheap: OAuth is a way of *obtaining* the string in
    /// [`Credential::Bearer`], not a second way of using one.
    ///
    /// What it costs, and it is the honest half: an access token expires, so a
    /// binding that carries one has to be refreshed by something before it does
    /// — `crate::oauth::refresh_due`, driven by the binder loop that was already
    /// rebinding every five minutes. See that module for why it is that loop and
    /// not a clock of its own.
    OAuth(&'static OAuth),
}

/// Where one connector's authorization server lives, and what we ask it for.
///
/// # These three strings are ours and the customer never sees a field for them
///
/// Same argument as [`Connector::url`], one level up: a customer who cannot
/// mistype an authorization endpoint cannot be walked into consenting at one
/// that looks like it. An OAuth consent page is the single most valuable phishing
/// target this product has — it is the screen where a person is *expected* to
/// approve access to their company's data — so the URL the browser is sent to
/// must come from this binary and from nowhere else.
///
/// `scopes` is here for the same reason, pointed the other way: it is the
/// **only** thing that bounds what the token we end up holding can do at the
/// provider, and letting a request name it would let a caller ask for more than
/// the connector needs. A tenant cannot widen it because there is no field to
/// widen it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuth {
    /// Where the browser is sent to ask a human. `https`, always.
    pub authorize: &'static str,
    /// Where a code is exchanged for a token, server to server. `https`, always.
    ///
    /// This one is never in a browser: it carries the deployment's client secret
    /// and the PKCE verifier, and both are ours.
    pub token: &'static str,
    /// What we ask for, space separated, exactly as the provider spells it.
    ///
    /// Narrow is the job. This is a claim about the least a connector can work
    /// with, and it is the one place in the system where "we asked for less" is
    /// a defence that holds even after every other control has failed.
    pub scopes: &'static str,
    /// How this provider wants the client secret presented at the token
    /// endpoint.
    ///
    /// A field and not a constant, and it is the one piece of flexibility in
    /// this struct that had to be argued rather than assumed. RFC 6749 §2.3.1
    /// makes HTTP Basic mandatory for a server to *support* and the form body
    /// optional — and then several of the largest providers document the form
    /// body as their only example, while others (Notion is the one everybody
    /// meets first) accept nothing but Basic. There is no choice here that is
    /// right for both, the wrong one is an `invalid_client` with no diagnosis,
    /// and this is not something the code can discover: it is a fact about a
    /// provider, written down beside the other three facts about that provider,
    /// by the same person reading the same page.
    pub auth: ClientAuth,
}

/// Which of RFC 6749 §2.3.1's two schemes a token endpoint wants.
///
/// Never both in one request — the RFC forbids it, and a server that sees two
/// answers `invalid_client`. [`crate::oauth::post_token`] is where that is one
/// `match` and cannot be forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// `Authorization: Basic base64(client_id:client_secret)`. The one the RFC
    /// says every authorization server must support, and the default to reach
    /// for when a provider's documentation does not say.
    Basic,
    /// `client_id` and `client_secret` as form fields in the token request.
    Post,
}

impl Credential {
    /// Stable, low-cardinality label, and the spelling the connect route reads
    /// back to a caller so a UI can decide which field to render.
    pub const fn code(self) -> &'static str {
        match self {
            Credential::None => "none",
            Credential::Bearer => "bearer",
            Credential::OAuth(_) => "oauth",
        }
    }

    /// The endpoints, for the connectors that have them.
    ///
    /// A method rather than a `matches!` at four call sites: the OAuth routes
    /// all begin by asking this question, and a `let else` on one `Option` is
    /// the shape that makes "this connector does not do OAuth" a single refusal
    /// instead of four.
    pub const fn oauth(self) -> Option<&'static OAuth> {
        match self {
            Credential::OAuth(endpoints) => Some(endpoints),
            Credential::None | Credential::Bearer => None,
        }
    }
}

/// Where the server on the other end of a binding comes from.
///
/// The three answers are genuinely different subsystems, and the enum exists so
/// that a caller cannot confuse them by looking at a `None`. Before it, "this
/// connector has no URL" meant "the customer supplies one"; a hosted entry has
/// no URL either, and a route that branched on `Option` would have asked a
/// customer to type the address of a container we had not started yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    /// A published endpoint we wrote down. We dial it and send a header.
    ///
    /// A fixed URL is most of the value of this file: a customer who cannot
    /// mistype the host cannot be phished into binding one, and the entry is
    /// the only thing in the system that can make that promise — the address
    /// check refuses a *class* of destinations, never a wrong-but-routable one.
    Dial(&'static str),
    /// The customer's own server, at a URL only they know. [`CUSTOM`], and the
    /// only variant that reads a URL out of a request body.
    Customer,
    /// A stdio package **we** run for the tenant, behind a bridge that speaks
    /// Streamable HTTP, in a container this process does not own.
    ///
    /// The endpoint is minted per start by a [`crate::hosted::BridgeRuntime`]
    /// and is never written to or read from a row — see [`crate::hosted`] for
    /// the isolation boundary and for what a deployment has to add before an
    /// entry like this can bind at all.
    Host(Package),
}

/// Where this connector's unsubscribes are read from.
///
/// # The gap this closes, which is an entrance and not a mechanism
///
/// The machinery that makes an opt-out final is built and is good: one row in
/// `suppressions` deactivates the **contact**, which is the join every channel
/// goes through, so the phone falls with the mail; the table is append-only for
/// everybody including superusers; and `crate::queue::reconcile_opt_outs` runs
/// before a queue is planned rather than on a cadence. Read
/// `migrations/0011_revenue.sql` around `suppressions_deactivate_contacts`.
///
/// What that machinery has no opinion about is **where the opt-outs come in**,
/// and that is per sender: Smartlead keeps its own unsubscribe list and
/// somebody has to go and read it; a mail provider we drive directly pushes
/// bounces, complaints and `List-Unsubscribe` clicks at a path that is ours; an
/// SMS gateway posts a `STOP` keyword. So the number of readers to write grows
/// with the number of connectors that can send, and today that growth is held
/// by somebody remembering to ask a vendor for an endpoint. `crate::queue`'s
/// module docs record that nobody has asked Smartlead yet, which is the first
/// connector and already the first miss.
///
/// This field is the memory. It is not `Option`, it has no default, and there
/// is **no `Unwired` variant**: a variant that compiles is a variant that ships,
/// and the one thing this file must not let somebody ship is a connector that
/// mails strangers with nowhere for their refusal to land.
///
/// # Where the line "this connector sends" falls, and who draws it
///
/// **The catalogue draws it, per entry, in this field.** One sentence, narrow
/// enough to be read off a vendor's own tool list rather than argued: *can any
/// tool this server serves put a message in front of a person who did not ask
/// for it?* GitHub cannot — its whole audience already has an account on a
/// repository they already have. `orizn-visa` cannot — six lookups against a
/// dataset. Smartlead can, and that is the entire difference between them.
///
/// Two other places could have held it and both are wrong:
///
/// * **[`RiskClass`] cannot.** `floor` answers a different question and answers
///   it coarsely: `Write` covers "opens an issue" and "adds two thousand
///   strangers to a campaign" with one value. Deriving "sends" from it would
///   exempt every `Read` connector — a lookup server with one notify tool is
///   not a contradiction — and catch GitHub, which reaches nobody. Two
///   judgements that move independently do not share a field.
/// * **Policy cannot.** A policy document is a tenant's, an operator writes it,
///   and `max_new_contacts_per_day` is already the tenant-side lever for how
///   many strangers a seat may approach. This is the deployment-side claim
///   *underneath* that lever — the same thing `url` and `floor` are, unwritable
///   by anyone but a deploy, for the reason the module docs give.
///
/// And there is deliberately no taxonomy of channels here. "Email, SMS,
/// WhatsApp, voice" is a second list to maintain that answers a question nobody
/// asked: `reconcile_opt_outs` does not need to know which channel an
/// unsubscribe arrived on, because the trigger deactivates the contact and
/// takes every channel down at once.
///
/// # The other two doors this obligation had to be put on
///
/// A catalogue entry is not the only way a message reaches a stranger, and this
/// field only closes the one. The other two are traits, one crate down, and
/// they carry the same obligation in the shape a trait can carry it:
///
/// * [`agentos_providers::leads::LeadSink::opted_out`] — a required method,
///   because the campaign platform holds the list and something of ours has to
///   go and read it. `crate::queue::reconcile_opt_outs` is that reader.
/// * [`agentos_providers::email::OptOuts`] — a required
///   [`opt_outs`](agentos_providers::email::EmailProvider::opt_outs) on
///   `EmailProvider`, with the catalogue's own two variants and **neither of
///   its two cheap ones**: an adapter that sends mail has already answered
///   "can this reach somebody who did not ask?", so there is no `NoStrangers`
///   to reach for and no `Unseen` to hide behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptOuts {
    /// Nothing this server serves can put a message in front of a person who
    /// did not ask for it, so there is no list anywhere to bring home.
    ///
    /// A claim, like `floor` is a claim, and checked the same way: by reading
    /// the vendor's tool list. It is the cheap answer and therefore the one the
    /// const block below charges for — see [`NO_OUTREACH`].
    NoStrangers,
    /// The platform sends on the tenant's behalf and keeps the unsubscribes.
    /// Something of ours has to go and ask.
    ///
    /// `from` names the read, concretely enough to be *wrong*: the MCP tool or
    /// the REST path that lists the people who came off the list. It is what
    /// [`crate::queue::reconcile_opt_outs`] would be pointed at, and there is no
    /// way to write it without having read the vendor's documentation — which
    /// is the point.
    Pulled { from: &'static str },
    /// They arrive here instead, at a path this deployment owns.
    ///
    /// `at` is the `provider` handle in `webhook_endpoints`;
    /// `0053_webhook_endpoints.sql`'s `webhook_endpoints_provider_is_wired`
    /// CHECK already refuses a handle no ingest reads, so a name invented here
    /// fails at registration rather than silently accepting callbacks nobody
    /// consumes.
    ///
    /// **"We own this channel, so there is nothing to read" is not a fourth
    /// variant, it is the reason this one applies.** A direct mail provider's
    /// `List-Unsubscribe` link resolves to a route of ours and its complaints
    /// arrive on its webhook; owning the channel is *why* the opt-out is pushed
    /// rather than pulled, and the path it is pushed to is still a string
    /// somebody has to name. An entry that named none would be a click with
    /// nowhere to go.
    Pushed { at: &'static str },
    /// This connector can put a message in front of a person who did not ask
    /// for it, and the vendor keeps no list of the ones who refused. So the
    /// only register of that refusal is `suppressions`, here, and there is
    /// nothing upstream for [`crate::queue::reconcile_opt_outs`] to fetch.
    ///
    /// # It is an admission, not a permission
    ///
    /// The three variants above all end in somewhere to look: a vendor's list,
    /// a path of ours, or a claim that nobody can be reached. This one ends in
    /// a fact about the vendor — *they do not keep one* — and that fact is not
    /// ours to fix by refusing the entry.
    ///
    /// That is the reasoning that was wrong before this variant existed, and it
    /// is worth writing down because it is the reasoning somebody will reach for
    /// again. [`NO_OUTREACH`] is a **register**, not an execution lock: nothing
    /// reads it at call time, no gate consults it, and no message is stopped by
    /// it. It is the document somebody has to be able to read to answer for an
    /// obligation. Refusing to write an entry therefore protected nobody — the
    /// customer connected the same vendor through [`CUSTOM`] and the register
    /// went quiet exactly where it should have spoken. What stops a call is the
    /// policy gate and a human approval, and both of them are downstream of
    /// every value in this enum.
    ///
    /// So this variant **widens** what the document says rather than what the
    /// product may do. [`OUTREACH_HELD_HERE`] is the second register it makes
    /// possible, and it is the honest half of [`NO_OUTREACH`]: one array names
    /// the connectors that reach nobody, the other names the connectors that
    /// reach strangers with no vendor list behind them. A connector that is in
    /// neither has named its read.
    ///
    /// # What it still costs
    ///
    /// The same discipline as [`OptOuts::NoStrangers`], for the same reason:
    /// both are claims about a tool list that only a person can check, and the
    /// cheap one is the one that gets typed by somebody in a hurry. Writing it
    /// fails the build until [`OUTREACH_HELD_HERE`]'s length is bumped, and that
    /// failure message asks for the reading that was owed — every tool this
    /// server serves, and which of them takes an address.
    ///
    /// It is also not the escape hatch for a vendor that *does* keep a list and
    /// nobody looked. [`OptOuts::Pulled`] is one string away and is strictly
    /// more useful, so the only entries here are the ones where somebody went
    /// looking for a suppression endpoint and found the vendor has none —
    /// `posthog` is the connector that proves the difference, because it can
    /// send and it publishes `opt-outs-list`, so it is `Pulled` and not this.
    HeldHere,
    /// Nobody here has ever seen this server.
    ///
    /// [`Provision::Customer`] and nothing else — asserted at compile time by
    /// [`NO_OUTREACH`]'s const block, so this cannot become the lazy answer for
    /// a vendor somebody could not be bothered to look up. It is the same
    /// refusal-to-claim that makes [`CUSTOM`]'s floor [`RiskClass::Read`]: we
    /// have not read this server's tool list, so `NoStrangers` would be a
    /// fabrication, and we cannot name a read endpoint for a server whose
    /// address the customer supplies at connect time.
    ///
    /// What it does not do is excuse anybody: a customer who stands up their own
    /// sender is the sender of record, and the suppression machinery is
    /// unchanged for them — `suppressions` still deactivates the contact, and
    /// `crate::queue` still refuses to queue one.
    Unseen,
}

/// One connector: everything needed to turn a name a customer clicked into a
/// binding `mcp::McpServer::bind` will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connector {
    /// The name the customer clicks. Lowercase, stable, and part of the API.
    pub key: &'static str,
    /// What to put on the button.
    pub label: &'static str,
    /// Where the server comes from, and therefore which of three paths a
    /// connect takes.
    pub provision: Provision,
    /// The tightest [`Reach`] a **dialled** binding on this connector may be
    /// made at.
    ///
    /// `Public` for everything we name, because a connector whose URL we wrote
    /// down is on the internet. `CUSTOM` is the one that may be `Private`, for
    /// the sidecar case `Reach::Private` exists for, and it is the customer's
    /// deliberate choice recorded in a row.
    ///
    /// A [`Provision::Host`] entry keeps the tight value and never uses it: a
    /// hosted binding's address comes from [`crate::hosted::accept`], which is
    /// narrower than either `Reach` — private space *and* inside the operator's
    /// bridge network *and* an IP literal. `Public` is what its row stores, so
    /// that a future reader who consults the column at all reads the refusing
    /// answer rather than the permissive one.
    pub reach: Reach,
    /// What to ask the customer for.
    pub credential: Credential,
    /// The lowest class a tool on this connector may be declared at.
    ///
    /// Only ever tightens. See the module docs for why it is one class per
    /// connector and not a table of tools.
    pub floor: RiskClass,
    /// Where this connector's unsubscribes come in, or the claim that it can
    /// reach nobody who would need to send one.
    ///
    /// No default and no `Option`: a struct literal cannot omit it, so "we
    /// forgot to ask the vendor for their opt-out endpoint" is not a state this
    /// array can be in. [`OptOuts`] is the whole argument.
    pub opt_outs: OptOuts,
}

/// The entry for a server the customer runs or already knows the URL of.
///
/// Named separately because two routes reach for it by identity: it is the only
/// entry that takes a URL from the request, and the only one whose [`Reach`] the
/// customer may choose.
pub const CUSTOM: Connector = Connector {
    key: "custom",
    label: "Your own MCP server",
    provision: Provision::Customer,
    // The permissive one, and the only entry that gets it: this is the sidecar
    // and the on-premises case. `Reach::Private` still refuses link-local, so
    // the cloud metadata endpoint is out of reach here as it is everywhere else.
    reach: Reach::Private,
    credential: Credential::Bearer,
    // No claim. We have not seen this server. See the module docs.
    floor: RiskClass::Read,
    // The same refusal to claim, one field down, and the only entry that may
    // make it — `NO_OUTREACH`'s const block fails the build for any other.
    opt_outs: OptOuts::Unseen,
};

/// Google's consent page, **with two query parameters that are not decoration**.
///
/// [`crate::oauth::start`] builds its query with `Url::query_pairs_mut`, which
/// *appends*: a query already on this literal survives everything `start` adds
/// after it. `a_providers_own_authorize_query_survives_what_start_appends` in
/// `crate::oauth` is the test that says so, rather than a reader hoping.
///
/// * `access_type=offline` — without it Google issues **no refresh token at
///   all**. Every other provider in this file returns one by default; Google's
///   default is a one-hour access token and nothing to renew it with. The
///   binding would survive onboarding, survive the demo, and be dead by lunch,
///   with `crate::oauth::refresh_due` looking at an empty column and no way back
///   except sending the customer through consent again.
/// * `prompt=consent` — Google returns the refresh token **only on a consent it
///   actually showed a human**. A user who has already approved this application
///   is re-authorized silently and the exchange comes back without one: the same
///   dead binding, except it happens only on rebinds, only to customers who
///   already connected once, and never in a first-run test.
///
/// So both are load-bearing, and the failure they prevent is the same one twice:
/// a stored access token with a `NULL` beside it that nobody can explain sixty
/// minutes later.
const GOOGLE_AUTHORIZE: &str =
    "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent";

/// Google's token endpoint, shared by all three entries below.
///
/// [`ClientAuth::Post`] with it: Google's documentation shows `client_id` and
/// `client_secret` as form fields and shows nothing else, which is the fact
/// [`OAuth::auth`] exists to record per provider.
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";

/// Every connector we have written down.
///
/// Short on purpose. An entry is a claim about somebody else's product — their
/// URL, their auth scheme, the floor under their tools — and a claim we have not
/// checked is worse than an absent entry, because an absent entry sends the
/// customer to [`CUSTOM`] where they paste a URL they looked up themselves.
///
/// # The OAuth entries, and what each of their four strings had to survive
///
/// An entry is a claim, and an OAuth entry is **four** claims: the MCP endpoint,
/// the authorization URL, the token URL, and the scope spelling. Every one of
/// them fails silently-ish if wrong — a bad scope is a consent screen that
/// grants too much, a bad authorize host is a phishing page we shipped
/// ourselves — so none of them may be typed from a blog post. The three Google
/// entries below were added after their MCP endpoints were dialled directly:
/// `initialize` at protocol `2025-06-18`, then `tools/list`, whose answers are
/// what the floors and the opt-out claims are read off. That probe is dated in
/// each entry, because a tool list is a thing a vendor changes without telling
/// anybody.
///
/// The second half is sharper and has not changed. **An OAuth connector needs a
/// client registration that only the deployment can obtain**, and
/// `apps/server/src/routes/mcp.rs`'s catalogue handler only advertises an entry
/// whose client credentials this deployment actually holds. So the entries below
/// are inert until somebody registers the application with Google and puts the
/// pair in `OauthClients` — a button that is invisible rather than broken, which
/// is the failure mode worth having.
///
/// # What is deliberately *not* here
///
/// * **Slack.** Technically ready — remote, Streamable HTTP, a bearer token.
///   What it is missing is not code: serving more than one workspace requires a
///   Slack Marketplace listing, and until that exists an entry here is a button
///   that works for exactly the workspace whose app we registered. That is a
///   demo, not a connector.
/// * **Sentry.** Its `client_id`/`client_secret` come from a hand-made
///   `POST /register` rather than a console, and the secret **expires at ninety
///   days**. Nothing in this repository would remind anybody, so the entry's
///   real cost is a quarterly chore that fails silently as an `invalid_client`
///   on a Tuesday. Out of scope until something owns that clock. Notion, Canva,
///   Granola and Magnific were in this paragraph for the same reason and are
///   not any more: all four answer `POST /register` with
///   `client_secret_expires_at: 0`, measured 2026-08-31, so the secret is
///   permanent and there is no clock to own. Three of them are entries below.
/// * **Figma.** Its authorization server answers 403 to clients outside its own
///   catalogue, so the consent page cannot be reached from here at all.
/// * **Canva.** The fourth of that group, and the one that did not survive its
///   own measurement. `POST https://mcp.canva.com/register` accepts
///   `https://siglair.com/v1/mcp/oauth/callback` and echoes it back — and then
///   `GET /authorize` answers **400 `Invalid redirect URI`** for that URI, for
///   `https://example.com/cb`, and for every `https` URI tried. The same client
///   registered with `http://localhost:33418/oauth/callback` gets a 302 to
///   Canva's consent page. Canva's MCP authorization server accepts loopback
///   redirects only, which is a desktop-client flow and is mutually exclusive
///   with this deployment having exactly one public callback. A second finding
///   from the same probe, moot but worth keeping: Canva ignores the `scope` we
///   send and substitutes its own full sixteen, so `OAuth::scopes` would have
///   been decorative here even if the redirect had worked. Not a registration
///   away — the provider has to change.
///
/// Each token entry below carries the reason it is a static bearer token, because
/// that is the question every one of them raises.
pub const CATALOG: &[Connector] = &[
    Connector {
        key: "github",
        label: "GitHub",
        // Le serveur MCP distant de GitHub, en Streamable HTTP.
        provision: Provision::Dial("https://api.githubcopilot.com/mcp/"),
        reach: Reach::Public,
        // OAuth, et non plus un jeton personnel collé. Les quatre littéraux
        // ci-dessous ne sont pas devinés : ils sortent du document RFC 8414 que
        // GitHub sert lui-même, relevé le 2026-08-31.
        //
        //   POST https://api.githubcopilot.com/mcp/  → 401, www-authenticate:
        //     resource_metadata=".../.well-known/oauth-protected-resource/mcp/"
        //   → authorization_servers: ["https://github.com/login/oauth"]
        //   GET https://github.com/.well-known/oauth-authorization-server/login/oauth
        //   → authorization_endpoint, token_endpoint,
        //     code_challenge_methods_supported: ["S256"]
        //
        // `Post` parce que c'est ce que GitHub documente : `client_id` et
        // `client_secret` en champs de formulaire.
        //
        // Les trois portées sont un SOUS-ENSEMBLE de `scopes_supported`, choisi
        // et non recopié : `repo` pour lire et écrire le code, `read:org` pour
        // voir l'organisation, `read:user` pour savoir au nom de qui on parle.
        // Ni `delete_repo`, ni `workflow`, ni `write:packages` — un employé qui
        // ne peut pas supprimer un dépôt est un employé dont le refus n'a pas à
        // être décidé ailleurs.
        //
        // **Une OAuth App GitHub émet un jeton sans expiration et sans jeton de
        // rafraîchissement**, donc `sealed_refresh_token` reste nul et
        // `refresh_due` ne le sélectionne jamais : rien à renouveler, rien qui
        // casse. Une GitHub App donnerait huit heures et un rafraîchissement,
        // mais ignore `scope` au profit de ses propres permissions — ce qui
        // rendrait le champ ci-dessous décoratif, et un champ décoratif sur une
        // limite est pire qu'un champ absent.
        credential: Credential::OAuth(&OAuth {
            authorize: "https://github.com/login/oauth/authorize",
            token: "https://github.com/login/oauth/access_token",
            scopes: "repo read:org read:user",
            auth: ClientAuth::Post,
        }),
        // Nothing GitHub's server exposes is observation-only in the sense that
        // matters here: the same token that reads an issue opens one, and the
        // read tools return repository content that becomes `Untrusted` text an
        // employee then acts on. `Write` is the floor, so no customer can class
        // any of it `read` without an operator writing the row by hand.
        floor: RiskClass::Write,
        // Read off the server's tool list rather than assumed. Every tool on
        // GitHub's remote server acts inside repositories, issues, pull requests
        // and Actions — surfaces whose entire audience already holds an account
        // and already watches the repository. An issue comment notifies a
        // subscriber; it does not reach a stranger, and there is no tool there
        // that takes an address of somebody who has not asked for anything. So
        // there is no unsubscribe list at GitHub for us to bring home, which is
        // a different sentence from "we did not look".
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "orizn-visa",
        label: "Orizn — visa rules and consular fees",
        // **The first hosted entry, and the one this workspace has measured.**
        //
        // Mesuré le 2026-08-25 en parlant MCP à `npx -y orizn-visa-mcp`, et la
        // mesure pointe des deux côtés :
        // `https://visa.orizn.app/mcp` answers Streamable HTTP but serves one
        // tool of six and ignores an API key in every header form, while the
        // stdio package serves all six and reads `ORIZN_API_KEY` out of its
        // environment. So a `Dial` entry for this vendor would be a connector
        // that connects and cannot answer the question anybody is paying for —
        // `check_visa_requirement`, the tool that prices a visa — and the
        // credential field on it would do nothing at all.
        //
        // Épinglé à 1.3.0 : la version depuis laquelle la surface a été
        // capturée, de sorte que les outils contre lesquels les déclarations de
        // cette entrée seront écrites sont les outils qui ont été lus. La
        // capture vit dans `crates/app/tests/orizn.rs`, qui en est la
        // contrepartie testée.
        provision: Provision::Host(Package {
            spec: "orizn-visa-mcp@1.3.0",
            env: Some("ORIZN_API_KEY"),
        }),
        // Unused on the hosted path and deliberately the tight one. See
        // `Connector::reach`.
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Six tools, every one of them a lookup against a curated dataset:
        // nothing on this server writes anything anywhere. `Read` is a claim we
        // have actually checked rather than an absence of one, which is the
        // difference between this and `CUSTOM`'s identical value.
        floor: RiskClass::Read,
        // The same six tools, read the same way: `check_visa_requirement` and
        // its five siblings take a nationality, a destination and a purpose, and
        // answer out of a curated dataset. None of them takes an address, a
        // number or a recipient of any kind, so there is nobody it could reach
        // and nothing anybody could unsubscribe from.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "google-gmail",
        label: "Gmail",
        // Google's own remote MCP server, and the reason these three entries
        // could be written at all: dialled **2026-08-31**, `initialize` answers
        // protocol `2025-06-18` over Streamable HTTP as `StatelessServer`/`ESF`,
        // and — unusually — `tools/list` answers **without a credential**. So
        // the floor and the opt-out claim below are read off the server itself
        // rather than off documentation about it.
        provision: Provision::Dial("https://gmailmcp.googleapis.com/mcp/v1"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            authorize: GOOGLE_AUTHORIZE,
            token: GOOGLE_TOKEN,
            // The narrowest pair that lets an employee read a thread and leave a
            // draft a human sends. `gmail.compose` is **not** `gmail.send`: it
            // writes drafts and labels and cannot put mail on the wire. That
            // distinction is doing as much work as the tool list is, two claims
            // further down.
            scopes: "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose",
            auth: ClientAuth::Post,
        }),
        // Nothing here is observation-only in the sense that matters. The same
        // token that reads a thread creates a draft, creates and applies labels,
        // trashes a message and marks one spam — and the read tools return mail
        // bodies, which become `Untrusted` text an employee then acts on. GitHub
        // is `Write` for the identical reason and this is the identical shape.
        floor: RiskClass::Write,
        // Read off the live tool list on **2026-08-31**: 23 tools —
        // `create_draft`, `list_drafts`, `get_draft`, `get_thread`,
        // `get_message`, `search_threads`, `list_labels`, `create_label`, the
        // six label/unlabel/sensitive-label tools, `update_message_labels`,
        // trash/untrash and spam/unspam for both threads and messages. **Not one
        // of them sends.** `create_draft` is the only tool that takes a
        // recipient address, and all it does is leave a draft in the customer's
        // own mailbox for a human to send or throw away.
        //
        // **This claim is dated, and it is the kind that breaks quietly.** What
        // breaks it is a `send_message`, `reply` or `forward` tool appearing on
        // this endpoint — Google already ships all three on its other Gmail
        // surfaces, so it is a product decision away rather than a rewrite. The
        // `const` below will not notice: it counts entries, not tools. Re-run
        // `tools/list` against the URL above before leaning on this line, and if
        // a send tool is there then this connector's opt-outs arrive somewhere
        // and `OptOuts::Pulled` or `OptOuts::Pushed` is where you name it.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "google-drive",
        label: "Google Drive",
        // Same probe, same date, same answer: Streamable HTTP, `2025-06-18`,
        // `tools/list` unauthenticated.
        provision: Provision::Dial("https://drivemcp.googleapis.com/mcp/v1"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            authorize: GOOGLE_AUTHORIZE,
            token: GOOGLE_TOKEN,
            // `drive.file` is the narrow write scope — it reaches only files
            // this application created or the user explicitly opened for it, not
            // the whole Drive. `drive.readonly` is the read half and is the
            // wider of the two; asking for `drive` instead would have been one
            // word and the entire corpus.
            scopes: "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.file",
            auth: ClientAuth::Post,
        }),
        // `create_file` and `copy_file` write, and the scope above grants it. The
        // read tools hand back document *content*, which is the largest single
        // source of `Untrusted` text in this product. Neither half can be classed
        // `read`.
        floor: RiskClass::Write,
        // Eight tools on **2026-08-31**: `search_files`, `list_recent_files`,
        // `get_file_metadata`, `get_file_permissions`, `read_file_content`,
        // `download_file_content`, `create_file`, `copy_file`. None takes an
        // address, and — the one that mattered to check — **none grants a
        // permission**. There is no `share_file` on this server, which is the
        // tool that would have mailed a share notification to somebody who never
        // asked for one. `get_file_permissions` reads them; nothing writes them.
        // A permission-granting tool appearing here is what breaks this claim.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "google-calendar",
        label: "Google Calendar",
        // Same server family as the two above and the same probe on
        // **2026-08-31**: Streamable HTTP, protocol `2025-06-18`,
        // `StatelessServer`/`ESF`, and `tools/list` answering without a
        // credential. Re-measured on the same day this entry was written, and
        // the nine tools below were read off that answer.
        provision: Provision::Dial("https://calendarmcp.googleapis.com/mcp/v1"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            authorize: GOOGLE_AUTHORIZE,
            token: GOOGLE_TOKEN,
            // Three scopes chosen against the nine tools rather than copied off
            // a page. `calendar.events` is read and write on events and is the
            // only wide one; the alternative spelling `calendar` would have
            // added settings, ACLs and calendar creation for one fewer word.
            // `calendar.calendarlist.readonly` is what `list_calendars` needs
            // and grants nothing else; `calendar.freebusy` is what
            // `suggest_time` reads across other people's calendars, and it
            // returns busy intervals rather than event contents.
            scopes: "https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.freebusy",
            auth: ClientAuth::Post,
        }),
        // **`Destructive`, and this is the one floor in the array that is not
        // `Write` for a connector of this shape.** `delete_event` is in the tool
        // list and Google Calendar has no trash for it: the event is gone from
        // every attendee's calendar, and the cancellation mail has already been
        // sent. `RiskClass::Destructive` is defined as "irreversible, or
        // expensive to undo", so this is the class the worst tool served here
        // actually is — and one class per connector means it is the floor.
        //
        // The price is real and is the honest half: `list_events` must be
        // declared `Destructive` too, so a human approves a calendar read. That
        // is what one coarse class per connector costs when a connector has one
        // irreversible tool, and `atlassian` above is the mirror of it —
        // `Write` there, recorded explicitly, *because* nothing on that server
        // deletes. A read-only Calendar entry on narrowed scopes is the entry
        // that would carry `Read`, and it is a product decision nobody has made.
        floor: RiskClass::Destructive,
        // Nine tools on **2026-08-31**: `list_events`, `get_event`,
        // `list_calendars`, `suggest_time`, `create_event`, `update_event`,
        // `delete_event`, `respond_to_event`, `search_events`.
        // `create_event`'s input schema has an `attendees` array whose member
        // type requires an `email`, and **Google mails an invitation to every
        // address on it** — so this connector can put a message in front of
        // somebody who did not ask, and `NoStrangers` would be a lie.
        //
        // `HeldHere` is the honest value and the reading behind it is the second
        // half of that variant's price: Google publishes **no** unsubscribe or
        // suppression list for calendar invitations. There is nothing at Google
        // for `reconcile_opt_outs` to fetch, so `Pulled` would have to name a
        // read that does not exist, and `Pushed` could not register a handle
        // anyway (`0069`'s `webhook_endpoints_provider_is_wired`). What answers
        // for a refusal is `suppressions`, here, and `OUTREACH_HELD_HERE` is
        // where this connector is written down as one of the four it answers
        // for.
        opt_outs: OptOuts::HeldHere,
    },
    Connector {
        key: "linear",
        label: "Linear",
        // Linear's own remote server. Dialled **2026-08-31**: 401 with
        // `WWW-Authenticate: Bearer realm="OAuth"`, so it is live and a bearer
        // is what it reads. `Credential::Bearer` rather than the OAuth dance its
        // interactive setup uses, because Linear's documentation says a Linear
        // API key goes straight into that header — a string the customer pastes,
        // with no client registration for this deployment to obtain first.
        provision: Provision::Dial("https://mcp.linear.app/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Linear's own words for this endpoint: read-write, with tools for
        // "finding, creating, and updating objects in Linear like issues,
        // projects, and comments". Creating an issue is a write and reading one
        // hands back text an employee acts on, so `Write` is the floor for the
        // reason it is GitHub's.
        floor: RiskClass::Write,
        // **Weaker evidence than the three Google entries, and the difference is
        // named here rather than hidden.** `tools/list` needs a token, so this
        // is read off Linear's description of the server's whole surface rather
        // than off an enumeration: every object it names — issues, projects,
        // comments — lives inside a workspace, and everybody in a workspace
        // holds an account in it. That is the same sentence that makes GitHub's
        // entry true, for the same reason: a comment notifies a subscriber, and
        // no tool takes the address of somebody who has not asked for anything.
        //
        // What breaks it: Linear says "more functionality on the way", and the
        // tool that would falsify this is an invite — Linear's own API can mail
        // an organization invitation to any address, and an MCP tool wrapping it
        // would reach a stranger with no list at Linear to bring home. Enumerate
        // with a real key before extending this claim to anything new here.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "linear-readonly",
        label: "Linear (read-only)",
        // The same server behind the endpoint Linear documents as one that
        // "only ever exposes read tools", dialled the same day with the same
        // bearer challenge. It is worth a second entry precisely because that
        // sentence is a guarantee about the tools this endpoint will *ever*
        // serve — which is the thing an enumeration cannot give.
        provision: Provision::Dial("https://mcp.linear.app/mcp/readonly"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // `Read` in the same sense as `google-calendar` and the opposite sense
        // to `CUSTOM`: not an absence of a claim, but the vendor's guarantee
        // that there is no tool on this endpoint to declare any other way.
        floor: RiskClass::Read,
        // Falls out of the same guarantee. A surface with no write tool has
        // nothing that could put anything in front of anybody, and the customer
        // who wants the writes has `linear` above, where the claim is argued
        // separately and on weaker evidence.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "atlassian",
        label: "Atlassian — Jira, Confluence, Bitbucket",
        // **The entry this file refused until somebody checked the header, and
        // the check is the whole reason it is here.** Atlassian's *personal* API
        // token goes out as `Basic base64(email:token)`, which is not
        // [`Credential::Bearer`] and would have been a broken button — that is
        // why an earlier pass left Atlassian out.
        //
        // A **service account** API key is a different credential and Atlassian
        // documents it as a bare `Authorization: Bearer <api_key>` against this
        // exact path. Two paths, and the difference matters: `/v1/mcp` is the
        // token path, `/v1/mcp/authv2` is the OAuth 2.1 one, and only the first
        // is what a pasted string reaches. Dialled 2026-08-31: 401 with
        // `WWW-Authenticate: Bearer` from `AtlassianEdge`, so the endpoint is
        // live and a bearer is what it reads.
        //
        // The honest caveat is not ours: an organization admin has to turn API
        // token authentication on for the site before any key works, so a
        // customer's first failure here may be a switch in their own console.
        provision: Provision::Dial("https://mcp.atlassian.com/v1/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Forty-seven published tools across Jira, Confluence, JSM, Bitbucket and
        // Compass. `createJiraIssue`, `editJiraIssue`, `addCommentToJiraIssue`,
        // `createConfluencePage`, `updateConfluencePage` and the two comment
        // creators all write, and the read tools hand back issue and page bodies
        // — the largest `Untrusted` surface after Drive. Nothing here is
        // observation-only. Worth recording that **no published tool deletes**:
        // the floor is `Write` because that is the truth about this list, not
        // because `Destructive` felt safer.
        floor: RiskClass::Write,
        // Read off Atlassian's own published tool list, 2026-08-31. Every write
        // lands inside a site — an issue, a page, a comment, a Compass component
        // — and everyone who is notified holds a licensed account on that site
        // and is already watching the thing they are notified about. There is no
        // tool that takes an email address, no invite, and no way to reach
        // somebody outside the site at all.
        //
        // What breaks it is a user-provisioning tool: Atlassian's own admin API
        // can mail an invitation to any address, and an MCP tool wrapping it
        // would reach a stranger with no list at Atlassian to bring home.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "zoom",
        label: "Zoom",
        // Zoom's own remote server. Dialled 2026-08-31: 401 with
        // `WWW-Authenticate: Bearer resource_metadata=...`, and that metadata
        // document is where the scopes below were read from rather than from
        // prose — `bearer_methods_supported: ["header"]`, `resource` matching
        // this URL exactly.
        provision: Provision::Dial("https://mcp.zoom.us/mcp/zoom/streamable"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            authorize: "https://zoom.us/oauth/authorize",
            token: "https://zoom.us/oauth/token",
            // Eight scopes, every one of them `:read:`. Zoom's protected-resource
            // metadata also advertises `hub:write:content` and
            // `docs:write:import`; both are deliberately absent, and their
            // absence is what the floor below is a claim about.
            //
            // No `access_type` equivalent is needed: Zoom's authorization-server
            // metadata lists `refresh_token` in `grant_types_supported`, so the
            // exchange returns one without being asked. Google is the odd one,
            // not the rule.
            scopes: "meeting:read:search meeting:read:assets cloud_recording:read:list_user_recordings cloud_recording:read:content agentic_search:read:search agentic_search:read:ask docs:read:export my_notes:read:content",
            // **Measured, not defaulted.** Zoom's
            // `/.well-known/oauth-authorization-server` says
            // `token_endpoint_auth_methods_supported: ["client_secret_basic"]`
            // and lists nothing else, so `ClientAuth::Post` here would be an
            // `invalid_client` with no diagnosis — which is the exact failure
            // that field exists to prevent. The same document confirms
            // `code_challenge_methods_supported: ["S256"]`, and carries **no**
            // `registration_endpoint`: there is no dynamic client registration
            // at Zoom, so this entry is inert until somebody registers an app by
            // hand, exactly as the Google three are.
            auth: ClientAuth::Basic,
        }),
        // `Read` in the same sense as `linear-readonly` and the opposite sense to
        // `CUSTOM`: not an absence of a claim but two independent supports for
        // one. Zoom publishes no tool that creates, updates or deletes a meeting
        // — the nine tools search and read — and every scope this entry asks for
        // is a `:read:` scope, so a token minted from it is refused at the
        // provider on anything else. Either alone would carry the floor.
        floor: RiskClass::Read,
        // Falls out of the same two facts, and Zoom is the connector where it
        // most needed checking: a meeting *invitation* is exactly the shape of
        // outreach this field exists to catch, and it is only absent because
        // there is no meeting-creation tool here. That is the thing to re-read
        // before extending this entry — a `create_meeting` tool takes an invitee
        // list, Zoom mails it, and there is no unsubscribe list at Zoom to bring
        // home. Widening `scopes` past the eight `:read:` ones falsifies this
        // claim and the floor together, the same way it would have on Calendar.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "malwarebytes",
        label: "Malwarebytes ScamGuard",
        // **The cheapest entry in the array, and the only one that needs
        // nothing at all.** Dialled 2026-08-31: `initialize` answers 200 over
        // Streamable HTTP with no credential, `serverInfo` names
        // `Malwarebytes ScamGuard 3.4.4`, and `tools/list` answers the same way.
        // No account, no key, no registration — so unlike every OAuth entry
        // above, this one is live the moment it is deployed.
        provision: Provision::Dial("https://scamguard.malwarebytes.com/claude/mcp"),
        reach: Reach::Public,
        // Nothing to send, and `mcp.rs`'s connect route refuses a token for this
        // connector rather than storing one nobody reads.
        credential: Credential::None,
        // **`Write`, not the `Read` this entry was drafted with, and the
        // difference is one tool that only a live enumeration shows.** The
        // server's own `instructions` block advertises five tools, all
        // reputation lookups; `tools/list` on 2026-08-31 answered with **six**,
        // and the sixth changes the floor: `reputation-report` "submits the
        // indicator to the threat intelligence system", which is a write into
        // somebody else's dataset with an effect on whoever owns the domain or
        // number reported. `RiskClass::Read` is "observes without changing
        // anything" and that is not this.
        //
        // The cost of being right here is nil: `Read` and `Write` both map to
        // `Risk::Low` in `mcp.rs`, so no approval changes. It is written down
        // because the floor is a claim, and a claim read off five tools when the
        // server serves six is the kind that is wrong for years.
        floor: RiskClass::Write,
        // Six tools, read off the live list: `reputation-check_link`,
        // `-check_phone`, `-check_email`, `-whois`, `-scan_all` and `-report`.
        // Three of them *take* an address or a phone number and none of them
        // sends anything to it — they hash it against a threat database and hand
        // back a verdict. `reputation-report` submits an indicator to
        // Malwarebytes' own analysts, who are the vendor and not a stranger.
        // There is nobody here who could ask to be left alone, and therefore no
        // list at Malwarebytes to bring home.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "context7",
        label: "Context7 — library documentation",
        // Dialled 2026-08-31: 200 with no credential, `exa`-style Streamable
        // HTTP, two tools on `tools/list`.
        provision: Provision::Dial("https://mcp.context7.com/mcp"),
        reach: Reach::Public,
        // **`None` and not `Bearer`, and it is a choice rather than a
        // measurement.** Context7 works with no credential and accepts an
        // optional API key as `Authorization: Bearer <key>` that buys a higher
        // rate limit and nothing else. There is no "optional credential" variant
        // and there should not be one: `Credential::Bearer` makes the key
        // *required* and turns the one entry that needs no signup into one that
        // does, while `Credential::None` makes the connect route refuse a key
        // somebody wanted to paste. The free tier is the entry worth having; the
        // day a tenant hits the limit, this becomes `Bearer` in one word.
        credential: Credential::None,
        // Two tools, both lookups against Context7's documentation index:
        // `resolve-library-id` maps a package name to an id, `query-docs`
        // returns documentation for one. Nothing writes. `Read` is a claim that
        // was checked, which is the difference between this and `CUSTOM`.
        //
        // What it *does* do, and what the floor cannot express, is return third
        // party prose straight into a turn — this is an `Untrusted` firehose by
        // design, and `crate::turn`'s trust filter is what handles that.
        floor: RiskClass::Read,
        // Neither tool takes an address, a number or a recipient. A
        // documentation index has nobody to reach.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "exa",
        label: "Exa — web search",
        // **The one entry in this batch whose credential shape had to be
        // measured rather than read, because Exa's REST API documents
        // `x-api-key` and the catalogue can only send `Authorization: Bearer`.**
        //
        // Measured 2026-08-31, three calls to the same session:
        //   * no header at all → `web_search_exa` returns results (free tier)
        //   * `Authorization: Bearer 0000…` → `error (401): Invalid API key`
        //   * `x-api-key: 0000…`            → `error (401): Invalid API key`
        // Identical upstream rejection from both headers, and neither is ignored
        // — so the bearer header *is* read as the API key, and this entry is not
        // the broken button `atlassian` nearly was. That is the evidence; the
        // documentation alone would not have settled it.
        provision: Provision::Dial("https://mcp.exa.ai/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Two tools on 2026-08-31: `web_search_exa` and `web_fetch_exa`. Both
        // read the public web and neither writes anywhere. Same caveat as
        // `context7` and larger: everything this returns is `Untrusted`.
        floor: RiskClass::Read,
        // Neither tool takes a recipient. Searching the web reaches nobody.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "supabase",
        label: "Supabase",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer
        // error="invalid_request", …resource_metadata=…`. OAuth is Supabase's
        // default door and is not the only one — a personal access token goes in
        // the same header ("create a personal access token (PAT) with the
        // necessary scopes and pass it as a header", `Authorization: Bearer
        // ${SUPABASE_ACCESS_TOKEN}`), which is what makes this a pasted string.
        //
        // The caveat is the customer's and is worth saying out loud in the UI: a
        // PAT is **account-wide** unless they scope it, so the narrow thing to
        // paste is a scoped token, and `?read_only=true` on the URL would be a
        // second, better entry the day somebody wants it.
        provision: Provision::Dial("https://mcp.supabase.com/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // `execute_sql` takes arbitrary SQL, so `DROP TABLE` and `DELETE FROM`
        // are one string away and no tool name says so. `delete_branch` and
        // `reset_branch` ("discards writes since the branch diverged") are
        // separately irreversible, and `pause_project` stops a production
        // database. `RiskClass::Destructive` is "irreversible, or expensive to
        // undo", and three tools here are exactly that.
        //
        // Worth naming the trap this floor is really for: `execute_sql` and a
        // hypothetical `execute_sql_readonly` would be **indistinguishable to
        // the floor**, because the floor is one class for the whole connector.
        // A tenant who wants reads without a human approves them at
        // `?read_only=true` on a second entry, not by declaring this tool lower.
        floor: RiskClass::Destructive,
        // Thirty-two published tools across projects, branches, migrations,
        // edge functions and storage. **Not one of them takes an address**:
        // there is no auth-admin invite tool, no email tool and no SMS tool on
        // this server. `deploy_edge_function` takes *code*, and the line this
        // file draws — the same one that makes GitHub `NoStrangers` while GitHub
        // Actions can run anything — is a tool whose **parameter is a
        // recipient**, not a tool that could be written into one.
        //
        // What breaks it is an `auth_admin` tool arriving: Supabase's Auth admin
        // API can invite a user by email, and an MCP tool wrapping it would
        // reach a stranger with no list at Supabase to bring home.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "neon",
        label: "Neon",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer
        // error="invalid_token", error_description="No authorization provided"`.
        // Neon documents the header directly — `Authorization: Bearer
        // <YOUR_NEON_API_KEY>`, "for API key or remote agent setups" — so OAuth
        // is the alternative here rather than the requirement.
        //
        // The caveat that belongs in the UI: **a Neon API key carries the whole
        // account**, not one project.
        provision: Provision::Dial("https://mcp.neon.tech/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // `run_sql` is documented as supporting "both read and write
        // operations", so it is the same arbitrary-SQL tool `supabase` has under
        // another name. `delete_project` ("deletes an existing Neon project"),
        // `delete_branch` and `reset_from_parent` ("discards writes since the
        // branch diverged") are three irreversible tools on top of it.
        floor: RiskClass::Destructive,
        // **The one entry in this batch whose opt-out claim could not be
        // enumerated, and the value says so rather than guessing kindly.**
        //
        // Neon's MCP tools are served per category and `https://mcp.neon.tech/mcp`
        // needs a token before `tools/list`, so nobody here has read the list
        // this URL actually serves. What is documented is that the surface
        // includes `create_auth_user` — a tool whose parameter is a person's
        // email address — and Neon Auth ships email verification and
        // customizable emails. Whether *that* call sends one is not stated on
        // Neon's own page, checked 2026-08-31.
        //
        // So `NoStrangers` is unavailable: it asserts that not one tool here can
        // reach somebody who did not ask, and that is exactly the sentence the
        // missing enumeration cannot support. The half that *is* certain is the
        // other one — Neon publishes no suppression, unsubscribe or opt-out
        // listing anywhere, so there is nothing for `reconcile_opt_outs` to
        // fetch and `Pulled` would name a read that does not exist. `HeldHere`
        // is what both halves add up to, and it errs into the register rather
        // than out of it: an entry wrongly listed here is a line somebody reads
        // and removes, an entry wrongly absent is a line nobody knows to look
        // for.
        //
        // Enumerate this endpoint with a real key and the claim tightens in
        // whichever direction the list says.
        opt_outs: OptOuts::HeldHere,
    },
    Connector {
        key: "posthog",
        label: "PostHog",
        // Dialled 2026-08-31: 401 whose body is "No token provided, please
        // provide a valid API token", which is the vendor saying the quiet part.
        // PostHog documents a personal API key created under its **MCP Server**
        // preset — "add the `Authorization: Bearer YOUR_API_KEY` header" — and
        // that preset scopes the key to one project, which is the narrow thing
        // to tell a customer to paste.
        provision: Provision::Dial("https://mcp.posthog.com/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Several hundred generated tools, and the floor is decided by two
        // families. `execute-sql` runs arbitrary HogQL — other tools' own
        // descriptions instruct the agent to route through it — and the deletes
        // are named and plural: `action-delete`, `alert-delete`,
        // `annotation-delete`, `insights-bulk-delete-create`,
        // `data-catalog-metrics-bulk-delete-create`, `messaging-templates-destroy`,
        // `data-warehouse-delete-org-destroy`. Irreversible, so `Destructive`.
        floor: RiskClass::Destructive,
        // **The connector that proves [`OptOuts::HeldHere`] is not the lazy
        // answer, and the only one of its kind in this array.**
        //
        // PostHog can send: `subscriptions-create` schedules recurring delivery
        // whose "`target_type` — `email` or `slack`" goes to caller-supplied
        // addresses, and a published workflow sends real messages
        // (`workflows-publish`; a workflow created over MCP is a draft until
        // then, and `workflows-test-run` deliberately does not reach real
        // recipients). So `NoStrangers` is false here in the plainest way.
        //
        // And **PostHog publishes the list**. `opt-outs-list` is a real tool,
        // spelled exactly that way — lowercase, hyphenated, plural — defined in
        // PostHog's own `products/messaging/mcp/tools.yaml` as
        // `messaging_preferences_opt_outs_retrieve`, annotated `readOnly: true`,
        // with `opt-outs-add` and `opt-outs-remove` beside it. That is a read
        // `crate::queue::reconcile_opt_outs` can be pointed at, which is the
        // entire bar `OptOuts::Pulled` sets.
        //
        // Writing `HeldHere` here would have been one word cheaper and would
        // have thrown away the only vendor in this whole qualification whose
        // unsubscribes can be named. That is why `OUTREACH_HELD_HERE`'s failure
        // message asks for the second reading and not just the first.
        opt_outs: OptOuts::Pulled {
            from: "opt-outs-list",
        },
    },
    Connector {
        key: "mixpanel",
        label: "Mixpanel",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer
        // error="invalid_token"…`. Live, and a bearer is what it reads.
        //
        // **The string a customer pastes here is not an API key, and getting
        // that wrong is a 401 nobody can debug.** Mixpanel's service-account
        // path wants the *literal* header value
        // `Authorization: Bearer Basic <base64(username:secret)>` — a Basic
        // credential carried inside the Bearer scheme token. `mcp.rs` writes the
        // `Bearer ` prefix itself and sends the stored string after it, so what
        // goes in the field is `Basic <base64>` and the wire ends up correct.
        // A customer who pastes the service-account secret alone gets a 401.
        //
        // This is `atlassian`'s trap wearing the opposite disguise: there a
        // Basic credential looked like a bearer and was not; here a Basic
        // credential really does ride inside one, and only because Mixpanel
        // built it that way. Their own docs mark it **beta** — "the interface
        // may change" — which is the sentence that will break this entry.
        provision: Provision::Dial("https://mcp.mixpanel.com/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // Sixty-odd tools in Capital-Hyphen-Case, unlike every other server
        // here. `Delete-Dashboard`, `Delete-Cohort` and `Delete-Tag` are
        // irreversible; `Merge-Group` collapses duplicate Lexicon entities into
        // one and there is no unmerge; `Update-Feature-Flag` changes targeting
        // on **production traffic**, which is a write whose blast radius is a
        // live product rather than a report.
        //
        // Worth recording what this floor is *not* about: `Run-Query` is a
        // structured insights/funnel/retention call, **not** arbitrary SQL. The
        // three other warehouses here are `Destructive` for the SQL; Mixpanel is
        // `Destructive` for the deletes and the flag.
        floor: RiskClass::Destructive,
        // Read off Mixpanel's published tool list, 2026-08-31. Dashboards,
        // cohorts, metrics, experiments, feature flags and lexicon entities —
        // every object lives inside a Mixpanel project and every person who
        // sees one holds a seat on it. No tool takes an email address, a phone
        // number or any recipient, and there is no invite, share or report-email
        // tool on this server.
        //
        // What breaks it is a scheduled-report tool: Mixpanel's product mails
        // digests, and an MCP tool wrapping that would take a recipient list
        // with no suppression endpoint at Mixpanel to bring home.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "motherduck",
        label: "MotherDuck",
        // Dialled 2026-08-31: 401 whose body is a JSON-RPC error saying it
        // plainly — "Authentication required. Please authenticate using OAuth or
        // provide a Bearer token." The `WWW-Authenticate` header also carries a
        // `resource` matching this URL exactly, which is the RFC 8707 indicator
        // this deployment never sends; see the module docs for that residual.
        provision: Provision::Dial("https://api.motherduck.com/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // `query_rw` is "SQL that can change data or schema" — create tables,
        // insert, update, save views, and therefore `DROP TABLE`. Its read-only
        // twin `query` sits right beside it in the same list, and **the floor
        // cannot tell them apart**: one class per connector means the class of
        // the worst tool, so `query` costs a human approval it does not deserve
        // in order that `query_rw` cannot avoid one. That is the price of coarse,
        // paid deliberately, and the alternative — a per-tool table maintained
        // here — is argued against in the module docs.
        floor: RiskClass::Destructive,
        // Seven core tools: `query`, `query_rw`, `list_databases`,
        // `list_tables`, `list_columns`, `search_catalog`, `ask_docs_question`.
        // None takes a recipient. Three further families exist — Dive, Flight
        // and Guide — whose individual names MotherDuck does not publish, and
        // Flight runs **scheduled Python jobs**, which is code and not an
        // address: the same line this file draws at GitHub Actions and at
        // Supabase's `deploy_edge_function`. A tool whose parameter is a
        // program is not a tool whose parameter is a person.
        //
        // What breaks it is a Flight tool that takes a destination — a job that
        // mails a report is a plausible product, and MotherDuck publishes no
        // suppression list to bring home if one ships. Enumerate with a real
        // token before extending this claim.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "stripe",
        label: "Stripe",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer
        // resource_metadata=…`, so it is live and a bearer is what it reads.
        // `Credential::Bearer` and not the OAuth realm it also advertises: a
        // Stripe API key — and specifically a **restricted** key — goes straight
        // into that header, which is a string the customer pastes with no client
        // registration for this deployment to obtain first.
        provision: Provision::Dial("https://mcp.stripe.com"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // **This is the caisse, and the floor is the only thing in this binary
        // that knows it.** `stripe_api_write` is documented as "write data with
        // any Stripe API `POST`, `PATCH`, `PUT` and `DELETE` method" — one tool
        // whose parameter is the verb. Refunds, invoice finalization and
        // subscription cancellation are all inside it, and none of them is
        // undone by another call.
        //
        // Same shape as `cloudflare` below and the same conclusion: the tool
        // list is a lid, not an inventory, so `Destructive` is read off what the
        // one tool can reach rather than off how many tools there are. The
        // cheaper and better entry is a **read-only restricted key**, which is
        // the customer's own choice to make at their end and which this field
        // cannot see — so the floor is written for the worst key they might
        // paste, not the best.
        floor: RiskClass::Destructive,
        // Finalizing an invoice **mails it** to whatever address a
        // `create_customer` call put on the record, and then keeps mailing it:
        // dunning is a sequence. That mail carries no unsubscribe link, and
        // **Stripe publishes no suppression endpoint at all** — there is nothing
        // to reconcile against, so `Pulled` would have to name a read that does
        // not exist and `Pushed` could not register a handle (`0069`'s
        // `webhook_endpoints_provider_is_wired`). `NoStrangers` is a claim with
        // no referent on a tool whose list is Stripe's whole REST surface.
        //
        // `HeldHere` is what is true: this connector can reach somebody who did
        // not ask, the only register of their refusal is `suppressions`, and
        // `OUTREACH_HELD_HERE` names it. The way out is a real one and is
        // written above [`NO_OUTREACH`] — turn Stripe's own invoice mail off,
        // send it through the provider whose `List-Unsubscribe` already lands on
        // a route of ours, and this becomes `OptOuts::Pushed`.
        opt_outs: OptOuts::HeldHere,
    },
    Connector {
        key: "cloudflare",
        label: "Cloudflare",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer realm="OAuth"`.
        // The realm says OAuth and the server does not mean it exclusively —
        // Cloudflare documents a plain API token in the same header
        // ("create a Cloudflare API token with the permissions you need and pass
        // it as a bearer token in the Authorization header"), which is what
        // makes this a pasted string rather than a consent flow this deployment
        // would have to register for. One caveat that is the customer's and not
        // ours: a token with Client IP Address Filtering enabled is refused.
        provision: Provision::Dial("https://mcp.cloudflare.com/mcp"),
        reach: Reach::Public,
        credential: Credential::Bearer,
        // ## Read this before touching the floor on this entry
        //
        // **Cloudflare's server serves three tools — `docs`, `search` and
        // `execute` — and the tool list tells you nothing about what it can
        // do.** `search` writes JavaScript that queries an OpenAPI `spec.paths`;
        // `execute` writes JavaScript that calls `cloudflare.request()` against
        // **any of the ~2,500 endpoints of the Cloudflare API**. Cloudflare's
        // own headline for it is "2500 endpoints in 1k tokens".
        //
        // So the usual method — enumerate the tools, take the worst one, write
        // its class down — reads three innocuous names and returns `Read`.
        // **Declaring `execute` as `read` would be a grave fault**: destroying a
        // DNS zone, dropping a D1 database, emptying an R2 bucket and deleting a
        // Worker are all reachable through it, and not one of them makes a
        // destructive-sounding tool name appear anywhere. The only permission
        // boundary on this connector is the scope of the API token the customer
        // pasted, and nothing in this binary can see that.
        //
        // `Destructive` is therefore the floor, and on this entry the floor is
        // the only thing standing between "the agent called a tool" and "the
        // account is gone". It forces every call on this connector — including
        // `docs`, which is a documentation search — through a human. That is the
        // correct price, and the same argument in reverse to `atlassian`'s
        // `Write`: there the tool list is the truth, here the tool list is a lid.
        floor: RiskClass::Destructive,
        // The same lid, pointed at the other claim. Account-member invitations
        // and Email Routing destination verification are both Cloudflare API
        // endpoints, so `execute` can put mail in front of an address somebody
        // typed — and no tool name here would ever say so. `NoStrangers` is a
        // claim with no referent on a connector whose tool list *is* a vendor's
        // whole REST surface, which is precisely the argument that kept this
        // entry out of the array until `OptOuts::HeldHere` existed.
        //
        // Cloudflare publishes no suppression or unsubscribe list — there is
        // nothing there to reconcile against, because Cloudflare is not an
        // outbound-messaging product; mail is a side effect of administration.
        // So the register is `suppressions`, here, and `OUTREACH_HELD_HERE` is
        // where this connector is named.
        opt_outs: OptOuts::HeldHere,
    },
    Connector {
        key: "notion",
        label: "Notion",
        // Dialled 2026-08-31: 401, `WWW-Authenticate: Bearer realm="OAuth"`,
        // `resource_metadata` at `/.well-known/oauth-protected-resource/mcp`.
        //
        // **OAuth and not a pasted key, and that is measured twice.** Notion
        // documents it — "Notion MCP currently requires you to complete the
        // OAuth authorization flow" — and the protected-resource document says
        // the same by having no other answer. An `ntn_` internal integration
        // token belongs to the older open-source server, not this one.
        provision: Provision::Dial("https://mcp.notion.com/mcp"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            // Read off `https://mcp.notion.com/.well-known/oauth-authorization-server`
            // on 2026-08-31, not off a blog post: `issuer` is
            // `https://mcp.notion.com`, and these are its two endpoints.
            authorize: "https://mcp.notion.com/authorize",
            token: "https://mcp.notion.com/token",
            // **`default` is the whole vocabulary**: `scopes_supported` is
            // `["default"]` on both the protected-resource and the
            // authorization-server document. Worth writing down what that costs,
            // because this file treats `scopes` as the one bound on a token that
            // survives every other control failing: Notion's `/authorize` hands
            // our request straight to `api.notion.com/v1/oauth/authorize` with
            // `owner=user` and **does not validate scope at all** — a probe with
            // `bogus_scope_xyz` was accepted exactly as `default` was. So the
            // token's real bound is the page tree the human ticks on Notion's
            // own consent screen, and this field is honest rather than
            // load-bearing. It is the only entry here of which that is true.
            scopes: "default",
            // `client_secret_basic` first in
            // `token_endpoint_auth_methods_supported`, and the variant this
            // file's `ClientAuth` docs already name Notion for.
            auth: ClientAuth::Basic,
        }),
        // Thirty-three published tools. `notion-create-pages`,
        // `notion-update-page`, `notion-create-database`, `notion-create-view`,
        // `notion-move-pages` and the comment and upload tools all write, and
        // `notion-fetch` hands back page bodies — an `Untrusted` surface the
        // size of Drive's. Nothing is observation-only, so not `Read`.
        //
        // And not `Destructive` either, which is the half worth recording: **no
        // published tool deletes.** Notion's REST API cannot permanently delete
        // a page at all — trashing is a reversible `in_trash` flag — so even a
        // pass-through would be undoable. `Write` is the truth about this list,
        // the same sentence `atlassian` carries.
        floor: RiskClass::Write,
        // Read off Notion's published tool list, 2026-08-31. There is no invite
        // tool, no email tool, and no way to address anybody outside the
        // workspace: `notion-create-comment` notifies the people already
        // following a page, all of whom hold an account on it. The tool that
        // needed checking is `notion-get-users`, which lists members and guests
        // **with their email addresses** — it reads an address book it has no
        // way to mail, which is an exfiltration question for the trust filter
        // and not an outreach question for this field.
        //
        // What breaks it is a user-provisioning tool, the same falsifier written
        // beside `atlassian`.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "granola",
        label: "Granola — meeting notes",
        // Dialled 2026-08-31: 401 with `WWW-Authenticate: Bearer`, pointing at
        // `/.well-known/oauth-protected-resource`, whose `authorization_servers`
        // is a **different host** — `https://mcp-auth.granola.ai`. The two
        // literals below come from that host's own metadata document and not
        // from the resource's, which is the mistake this note exists to prevent.
        //
        // OAuth is the only door: "there is no API key or service account access
        // method for MCP".
        provision: Provision::Dial("https://mcp.granola.ai/mcp"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            authorize: "https://mcp-auth.granola.ai/oauth2/authorize",
            token: "https://mcp-auth.granola.ai/oauth2/token",
            // **The one scope string in this file that the metadata document
            // would have got wrong.** The authorization server's
            // `scopes_supported` is `["email", "offline_access", "openid",
            // "profile"]` and **does not list `mcp`** — but the protected
            // resource's own document says `scopes_supported: ["mcp"]`, and the
            // resource is the thing being asked for.
            //
            // Settled by probing rather than by choosing, 2026-08-31, against a
            // client registered by hand at `/oauth2/register`:
            //   * `scope=mcp`                  → 302 to the consent page
            //   * `scope=mcp offline_access`   → 302 to the consent page
            //   * `scope=bogus_scope_xyz`      → 302 back with `error=invalid_scope`
            // So the endpoint does validate, `mcp` is real, and the metadata is
            // simply incomplete. `offline_access` is here because Granola lists
            // `refresh_token` in `grant_types_supported` and `crate::oauth::
            // refresh_due` needs something in the column to renew with.
            scopes: "mcp offline_access",
            auth: ClientAuth::Basic,
        }),
        // Six tools: `query_granola_meetings`, `list_meetings`, `get_meetings`,
        // `list_meeting_folders`, `get_meeting_transcript`, `get_account_info`.
        // Every one of them reads the customer's own notes; there is no create,
        // update, share or send tool on this server at all. `Read` is a checked
        // claim, like `orizn-visa`'s and unlike `CUSTOM`'s.
        //
        // The sensitivity is real and is not what the floor measures:
        // `get_meeting_transcript` returns verbatim minutes of meetings other
        // people were in. That is an `Untrusted`-text and a data-egress question,
        // and both are answered elsewhere.
        floor: RiskClass::Read,
        // Falls out of the same list. A surface with no write tool has nothing
        // that could put anything in front of anybody, and Granola is a notepad
        // rather than a sender. The falsifier is a share-by-email tool.
        opt_outs: OptOuts::NoStrangers,
    },
    Connector {
        key: "magnific",
        label: "Magnific — image and video generation",
        // **The address had to be found, and the old one is a trap.**
        // `mcp.magnific.ai` does not resolve, and `https://api.freepik.com/mcp`
        // — the endpoint most pages still name — answers 200 with a JSON-RPC
        // error saying it is deprecated and naming its successor. So this
        // literal comes from the deprecated server itself, dialled 2026-08-31,
        // and it is `magnific.com` rather than `magnific.ai`.
        //
        // 401 with `WWW-Authenticate: Bearer …, scope="openid profile email
        // mcp:custom-audience"`, and the protected-resource document's
        // `resource` is this bare URL with **no `/mcp` path** — which is why the
        // string below has none. OAuth only: "You don't need to manage an API
        // key."
        provision: Provision::Dial("https://mcp.magnific.com"),
        reach: Reach::Public,
        credential: Credential::OAuth(&OAuth {
            // A Keycloak realm, read off
            // `https://auth.magnific.com/realms/mcp/.well-known/oauth-authorization-server`
            // on 2026-08-31. The authorization server is a third host again —
            // neither the MCP endpoint nor `magnific.com`.
            authorize: "https://auth.magnific.com/realms/mcp/protocol/openid-connect/auth",
            token: "https://auth.magnific.com/realms/mcp/protocol/openid-connect/token",
            // The vendor's own answer, copied from the `scope=` parameter its
            // 401 challenge sends, and then probed against a hand-registered
            // client on 2026-08-31:
            //   * this string        → 302 to Magnific's login page
            //   * `bogus_scope_xyz`  → 302 back with
            //     `error=invalid_scope&error_description=Invalid+scopes%3A+…`
            // So the endpoint validates and this string passes. `offline_access`
            // is in the realm's `scopes_supported` and is deliberately **not**
            // asked for: Keycloak returns a session-bound refresh token for the
            // authorization-code grant without it, and `offline_access` is the
            // wider one that survives logout. If bindings here start dying at
            // the session boundary, that is the word to add.
            scopes: "openid profile email mcp:custom-audience",
            auth: ClientAuth::Basic,
        }),
        // Twenty-three published tools. Most generate: `images_generate`,
        // `images_upscale`, `video_generate`, `audio_tts`, `models3d_generate`
        // and their siblings, plus `creations_search`/`_get`/`_move` and
        // `account_balance`. Generating writes an asset into the customer's
        // Magnific account and **spends credits from a real balance**, so
        // nothing here is observation-only.
        //
        // Not `Destructive`: no tool deletes — `creations_move` relocates
        // between folders. The cost is money rather than data, and money spent
        // is the tenant's own ceiling to set, which `crate::policy` already has
        // a lever for.
        floor: RiskClass::Write,
        // Nothing on this server publishes, shares or sends. A generation tool
        // returns an asset to the caller; it does not put it in front of a third
        // party. One thing left unmeasured and worth naming rather than
        // assuming: whether the returned asset URLs are public CDN links. That
        // is an egress question, not an outreach one — nobody receives a message
        // either way.
        opt_outs: OptOuts::NoStrangers,
    },
    CUSTOM,
];

/// Every connector we have claimed can reach nobody who would need to
/// unsubscribe — and the length that makes claiming it cost a deliberate edit.
///
/// # Why the pinned list is this side of the partition
///
/// `DenyReason::GRANTABLE` in `agentos_domain::policy` is the mechanism being
/// copied: a `const` derived from a judgement, whose length is asserted *while
/// the constant is evaluated*, so changing the judgement without touching the
/// count fails the build rather than producing a quietly wrong list. Both of its
/// assertions are here, pointed at the claim that cannot be checked by machine.
///
/// Which side to pin is the whole design. [`OptOuts::Pulled`] and
/// [`OptOuts::Pushed`] already cost the person adding an entry something real —
/// a string they can only get by reading a vendor's documentation, and one this
/// block refuses to accept empty. [`OptOuts::NoStrangers`] costs nothing, is
/// true of most entries here, and is the answer somebody in a hurry reaches
/// for. So it is the one that has to be paid for twice, and the second payment
/// is this length, whose failure message says what reading is owed.
/// [`OUTREACH_HELD_HERE`] charges the identical price for the identical reason,
/// on the one other variant that is a claim rather than a string.
///
/// The other assertion is the trapdoor: [`OptOuts::Unseen`] is pinned to
/// [`Provision::Customer`], so the "we have not looked yet" answer is
/// **inexpressible** for any connector this file names. There is no `Unwired`
/// variant to leave in place, and no way to borrow the one variant that sounds
/// like it.
///
/// # The two connectors this block cost us, and what getting them back changed
///
/// `stripe` and `cloudflare` were both refused an entry once, for one reason
/// rather than two: **each serves a tool whose parameter is "any method of the
/// vendor's API"** — `stripe_api_write` ("write data with any Stripe API
/// `POST`, `PATCH`, `PUT` and `DELETE` method"), and Cloudflare's `execute`. A
/// tool like that has no tool list to read. Its list is the vendor's entire REST
/// surface, it grows whenever they ship anything, and nobody can assert over it
/// — so [`OptOuts::NoStrangers`] on such an entry is not a claim that turned out
/// wrong, it is a claim with no referent.
///
/// That much was right and still is. What was wrong was the conclusion.
/// [`OptOuts::Pulled`] cannot name a read that does not exist — Stripe's
/// invoice mail carries no unsubscribe link and Stripe publishes no suppression
/// endpoint; Cloudflare's `execute` reaches account-member invitations and Email
/// Routing destination verification and Cloudflare publishes none either. And
/// [`OptOuts::Pushed`] is no escape: `0069`'s
/// `webhook_endpoints_provider_is_wired` allows `provider in ('email',
/// 'twilio')`, so a `stripe` handle invented here would fail at registration
/// rather than quietly accept callbacks nobody consumes. Three variants, none of
/// them true — and the inference drawn from that was "then the entry must not be
/// written", which **protected nobody**.
///
/// This array is a register. Nothing reads it at call time; no message was ever
/// stopped by an entry's absence. A customer who wanted Stripe connected Stripe
/// through [`CUSTOM`], with a URL they pasted themselves, and the register said
/// nothing about it at all. The refusal bought silence where the document should
/// have spoken, and it bought it at the price of the two connectors most worth
/// writing down. [`OptOuts::HeldHere`] is the fourth answer, [`OUTREACH_HELD_HERE`]
/// is where it is recorded, and both entries are in the array above.
///
/// The upgrade path is unchanged and is still worth taking: the day something
/// owns Stripe's outbound mail — disable Stripe's own invoice emails, send them
/// through the provider whose `List-Unsubscribe` already lands on a route of
/// ours — that entry becomes [`OptOuts::Pushed`] and moves off the other array.
///
/// It is `pub` because it is the artifact the obligation actually needs: the
/// list of connectors this deployment asserts have no unsubscribe list
/// anywhere, in one place, readable by whoever has to answer for it.
pub const NO_OUTREACH: [&str; 17] = {
    let mut out = [""; 17];
    let (mut i, mut n) = (0, 0);
    while i < CATALOG.len() {
        vet(&CATALOG[i]);
        if matches!(CATALOG[i].opt_outs, OptOuts::NoStrangers) {
            assert!(
                n < 17,
                "a connector claiming `OptOuts::NoStrangers` was added to CATALOG and \
                 NO_OUTREACH's length was not updated. That claim is read off the vendor's \
                 own tool list — every tool this server serves, and not one of them can put \
                 a message in front of a person who did not ask for it. If you have read it \
                 and it holds, bump the length. If you have not, this connector's opt-outs \
                 arrive somewhere, and `OptOuts::Pulled` or `OptOuts::Pushed` is where you \
                 name where."
            );
            out[n] = CATALOG[i].key;
            n += 1;
        }
        i += 1;
    }
    assert!(
        n == 17,
        "a connector stopped claiming `OptOuts::NoStrangers` and NO_OUTREACH's length was \
         not updated"
    );
    out
};

/// Every connector we have written down that **can** put a message in front of
/// somebody who did not ask for it, and whose vendor keeps no list of the ones
/// who refused — so the only register of that refusal is `suppressions`, here.
///
/// # This is the register [`NO_OUTREACH`] could not hold
///
/// The two arrays are one document read from both ends. `NO_OUTREACH` names the
/// connectors that reach nobody; this one names the connectors that reach
/// strangers with nothing upstream to reconcile against. Everything else in
/// [`CATALOG`] has named its read in [`OptOuts::Pulled`] or [`OptOuts::Pushed`],
/// and `every_entry_is_on_exactly_one_of_the_two_registers` is the assertion
/// that no entry falls between them.
///
/// Before [`OptOuts::HeldHere`] existed there was no third answer, so a
/// connector in this position could not be written at all — and `stripe` and
/// `cloudflare` were both refused on exactly that. That refusal read as caution
/// and was not: `NO_OUTREACH` is a register, nothing consults it at call time,
/// and a customer who wanted Stripe connected Stripe through [`CUSTOM`] with
/// **no** entry in any array here. The refusal cost the document its two most
/// important lines and cost the customer nothing. Naming them is the safer half.
///
/// # Why it is pinned the same way
///
/// [`OptOuts::HeldHere`] is as cheap to type as [`OptOuts::NoStrangers`] and is
/// wrong in a worse direction: `NoStrangers` typed by mistake understates a
/// connector that sends, and `HeldHere` typed by mistake hides a vendor list
/// that exists and could have been reconciled. Both are claims about a tool list
/// no machine can check, so both cost a length. `posthog` is the entry that
/// shows the difference is real — it sends *and* publishes `opt-outs-list`, so
/// it is [`OptOuts::Pulled`] and appears in neither array.
///
/// `pub` for the same reason [`NO_OUTREACH`] is: it is the artifact the
/// obligation needs. Somebody answering for what this deployment can reach
/// reads these two arrays and nothing else.
pub const OUTREACH_HELD_HERE: [&str; 4] = {
    let mut out = [""; 4];
    let (mut i, mut n) = (0, 0);
    while i < CATALOG.len() {
        if matches!(CATALOG[i].opt_outs, OptOuts::HeldHere) {
            assert!(
                n < 4,
                "a connector claiming `OptOuts::HeldHere` was added to CATALOG and \
                 OUTREACH_HELD_HERE's length was not updated. That claim is two readings, \
                 not one: the vendor's own tool list, to see which tool takes the address of \
                 a person who did not ask — and the vendor's API, to see that no suppression \
                 or unsubscribe endpoint exists to reconcile against. If you have done both \
                 and the second came back empty, bump the length and this deployment answers \
                 for that connector's outreach itself. If the vendor does publish such a \
                 list, `OptOuts::Pulled` names it and is strictly better. If no tool there \
                 reaches anybody, `OptOuts::NoStrangers` and NO_OUTREACH is where you say so."
            );
            out[n] = CATALOG[i].key;
            n += 1;
        }
        i += 1;
    }
    assert!(
        n == 4,
        "a connector stopped claiming `OptOuts::HeldHere` and OUTREACH_HELD_HERE's length \
         was not updated"
    );
    out
};

/// The per-entry half of [`NO_OUTREACH`]'s judgement, in a `const fn` so the
/// same code runs at compile time over [`CATALOG`] and at run time over a
/// synthetic entry.
///
/// The pattern is `catalog`'s own: `oauth_endpoints_are_vetted_the_same_way`
/// proves a check bites without waiting for a real entry to be wrong. A `const
/// fn` that panics is a compile error in the const block and an ordinary panic
/// in a test, so one body carries both — and the `#[should_panic]` tests below
/// are the evidence that the compile error a newcomer meets is the one written
/// here.
const fn vet(connector: &Connector) {
    // `Provision::Customer` is the one entry whose server nobody here has seen.
    // The two directions of this are different mistakes and get different
    // sentences, because the person making each is looking at a different thing.
    let unseen_server = matches!(connector.provision, Provision::Customer);
    match connector.opt_outs {
        OptOuts::Unseen => assert!(
            unseen_server,
            "`OptOuts::Unseen` says nobody here has ever seen this server, which is true of \
             `Provision::Customer` and of nothing else. A connector we wrote down is one \
             somebody read the documentation of: if it can put a message in front of a \
             person who did not ask for it, name where its opt-outs come in with \
             `OptOuts::Pulled` or `OptOuts::Pushed`; if it cannot, say `NoStrangers` and \
             bump NO_OUTREACH. There is no third answer, and there is deliberately no \
             `Unwired` — an entry whose opt-outs nobody can name is one that must not be \
             added at all."
        ),
        OptOuts::NoStrangers => assert!(
            !unseen_server,
            "`Provision::Customer` is a server nobody here has seen, so `NoStrangers` is a \
             claim about a tool list nobody has read. `OptOuts::Unseen`, for the same reason \
             this entry's floor is `RiskClass::Read`."
        ),
        // Same trapdoor, same sentence, other direction: `HeldHere` says
        // somebody read a tool list, found a tool that reaches a stranger, and
        // went looking for the vendor's suppression endpoint. None of that has
        // happened for a URL that arrives in a request body.
        OptOuts::HeldHere => assert!(
            !unseen_server,
            "`Provision::Customer` is a server nobody here has seen, so `HeldHere` is a claim \
             about a tool list nobody has read — and about a vendor nobody has asked for a \
             suppression endpoint. `OptOuts::Unseen`, for the same reason this entry's floor \
             is `RiskClass::Read`."
        ),
        OptOuts::Pulled { from: source } | OptOuts::Pushed { at: source } => {
            assert!(
                !unseen_server,
                "`Provision::Customer` takes its address from the connect request, so no \
                 string in this binary can say where its opt-outs come in. `OptOuts::Unseen`."
            );
            assert!(
                !source.is_empty(),
                "an empty opt-out source is the `Unwired` variant this enum refuses to have. \
                 Name the read, or do not add the entry: a connector that can reach a \
                 stranger with nowhere for their refusal to land is the one thing this array \
                 must never hold."
            );
        }
    }
}

/// Look one up by the name a customer clicked.
///
/// `None` is a 404 at the route, never a fallback to [`CUSTOM`]: falling back
/// would mean a typo in the connector name silently becomes "bind whatever URL
/// was in the body", which is the one substitution this file exists to prevent.
pub fn find(key: &str) -> Option<&'static Connector> {
    find_in(CATALOG, key)
}

/// The same lookup, over a catalogue somebody named.
///
/// # Why this exists, when there is only one catalogue
///
/// Because `apps/server` has to be able to prove what its routes do with an
/// OAuth connector, and an OAuth connector is by definition one whose
/// authorization server is somebody else's — a `&'static str` this file will
/// never point at a loopback port. Handing the array in makes the route
/// testable against a provider a test can stand up, with **the same code path**:
/// there is no branch here that behaves differently for one catalogue than for
/// another, and the production wiring passes [`CATALOG`] in one place.
///
/// It is the same shape `model_access::connect` uses for its probe origin, and
/// the same argument: a value threaded through beats a `#[cfg(test)]` branch,
/// because a branch that only exists in a test build is a branch the shipped
/// binary has never run.
pub fn find_in<'a>(catalog: &'a [Connector], key: &str) -> Option<&'a Connector> {
    catalog.iter().find(|c| c.key == key)
}

impl Connector {
    /// The endpoint we publish for this connector, if there is one.
    ///
    /// `None` for both [`Provision::Customer`] and [`Provision::Host`], which is
    /// the *display* answer and deliberately not the *routing* one: a caller
    /// deciding what to do must match on [`Connector::provision`], because those
    /// two `None`s mean opposite things — one asks the customer for an address,
    /// the other refuses to let anyone name one.
    pub const fn url(&self) -> Option<&'static str> {
        match self.provision {
            Provision::Dial(url) => Some(url),
            Provision::Customer | Provision::Host(_) => None,
        }
    }

    /// The package this connector runs, if we run it.
    pub const fn package(&self) -> Option<&Package> {
        match &self.provision {
            Provision::Host(package) => Some(package),
            Provision::Dial(_) | Provision::Customer => None,
        }
    }

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
        assert_eq!(CUSTOM.provision, Provision::Customer);
        assert!(CUSTOM.url().is_none(), "the customer supplies it");
    }

    /// Every entry is bindable by the client that will bind it, whichever way
    /// it is provisioned.
    ///
    /// Not a style check: a URL in this array is one a customer cannot correct,
    /// so a typo here is a connector nobody can use and an error message that
    /// blames their network. `vet_url` is the same function `declare_server`
    /// runs on a customer's own string.
    ///
    /// The hosted arm is the one that matters most, because a hosted entry has
    /// *no* URL for a customer to correct and no address anybody may name: what
    /// it must not do is claim a `Reach` it does not use. See `Connector::reach`
    /// for why the unused value is the refusing one.
    #[test]
    fn every_catalogued_entry_is_one_the_mcp_client_accepts() {
        for connector in CATALOG {
            match connector.provision {
                Provision::Dial(url) => {
                    crate::mcp::vet_url(url)
                        .unwrap_or_else(|err| panic!("{}: {err}", connector.key));
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
                Provision::Host(_) => {
                    assert!(connector.url().is_none());
                    assert_eq!(
                        connector.reach,
                        Reach::Public,
                        "{}: a hosted binding never reads `reach`, so it stores the tight one",
                        connector.key
                    );
                }
                Provision::Customer => {}
            }
        }
    }

    /// An OAuth entry's three URLs are held to the same bar as the MCP one.
    ///
    /// **This test is written for an array it does not yet cover**, which is the
    /// unusual half and the deliberate half: [`CATALOG`]'s docs argue why no
    /// OAuth entry is here yet, and the entry that arrives will be four string
    /// literals typed by somebody reading a provider's documentation at the time.
    /// A typo in `authorize` is a consent page we sent a customer to, so the
    /// check has to already exist when the literal lands rather than be
    /// remembered alongside it. The loop below is empty today and costs nothing;
    /// the day it is not, it is the only thing standing between a slipped
    /// character and a browser.
    ///
    /// `oauth_endpoints_are_vetted_the_same_way` proves it bites on a bad entry
    /// without waiting for a real one.
    #[test]
    fn every_catalogued_oauth_endpoint_is_https_and_parseable() {
        for connector in CATALOG {
            let Some(endpoints) = connector.credential.oauth() else {
                continue;
            };
            assert_oauth_is_usable(connector.key, endpoints);
        }
    }

    /// The body of the check above, so a synthetic entry can run it.
    fn assert_oauth_is_usable(key: &str, endpoints: &OAuth) {
        for url in [endpoints.authorize, endpoints.token] {
            crate::mcp::vet_url(url).unwrap_or_else(|err| panic!("{key}: {url:?}: {err}"));
            assert!(
                url.starts_with("https://"),
                "{key}: {url:?} — an authorization server is on the internet and \
                 a consent page over http is a credential handed to whoever is \
                 on the wire"
            );
        }
        assert!(
            !endpoints.scopes.trim().is_empty(),
            "{key}: an empty scope string asks a provider for its default grant, \
             which is the widest one it has"
        );
    }

    /// A scope string is one hand-typed line of space-separated tokens.
    ///
    /// The provider reads it as a set; a stray double space or a newline makes
    /// one empty member, and a missing space glues two scopes into one token
    /// that no provider knows. Either way the failure is a consent screen that
    /// does not load, with an error naming nothing — so the scope strings above
    /// are deliberately *not* wrapped with a `\` continuation, and this is the
    /// assertion that says so out loud.
    #[test]
    fn every_scope_in_a_scope_string_is_a_whole_scope() {
        for connector in CATALOG {
            let Some(endpoints) = connector.credential.oauth() else {
                continue;
            };
            for scope in endpoints.scopes.split(' ') {
                assert!(
                    !scope.is_empty() && !scope.contains(char::is_whitespace),
                    "{}: an empty scope — the string has a double space or a newline in it",
                    connector.key
                );
                // Two absolute scopes glued together still parse as one URL, so
                // counting separators is what catches it and `vet_url` is not.
                assert!(
                    scope.matches("://").count() <= 1,
                    "{}: {scope:?} is two scopes with the space missing between them",
                    connector.key
                );
                if scope.contains("://") {
                    crate::mcp::vet_url(scope)
                        .unwrap_or_else(|err| panic!("{}: {scope:?}: {err}", connector.key));
                }
            }
        }
    }

    /// The loop above is empty; this is the proof it would refuse a bad entry.
    #[test]
    #[should_panic(expected = "an authorization server is on the internet")]
    fn oauth_endpoints_are_vetted_the_same_way() {
        assert_oauth_is_usable(
            "pretend",
            &OAuth {
                authorize: "http://accounts.example.com/authorize",
                token: "https://accounts.example.com/token",
                scopes: "read",
                auth: ClientAuth::Basic,
            },
        );
    }

    /// A connector that can reach a stranger, added the way somebody in a hurry
    /// would add it.
    ///
    /// This is the entry `crate::queue`'s module docs say is blocked: Smartlead
    /// mails on the tenant's behalf, its unsubscribe list lives over there, and
    /// **nobody here has asked which endpoint lists it** — deliberately, because
    /// nobody has looked at the live API. So there is no value of [`OptOuts`]
    /// this entry can carry, and the four tests below are the four ways somebody
    /// would try to write one anyway.
    ///
    /// Synthetic, not in [`CATALOG`], and it must stay that way: the package
    /// name and the environment variable below are the shape such an entry
    /// takes, not values anybody has verified.
    fn a_sender_nobody_has_looked_up(opt_outs: OptOuts) -> Connector {
        Connector {
            key: "a-sender",
            label: "A platform that mails strangers",
            provision: Provision::Host(Package {
                spec: "unverified@0.0.0",
                env: Some("UNVERIFIED_API_KEY"),
            }),
            reach: Reach::Public,
            credential: Credential::Bearer,
            floor: RiskClass::Write,
            opt_outs,
        }
    }

    /// The lazy answer, refused: `Unseen` is pinned to the one provision whose
    /// server nobody here has read.
    #[test]
    #[should_panic(expected = "there is deliberately no `Unwired`")]
    fn a_sender_cannot_borrow_the_variant_that_means_we_never_looked() {
        vet(&a_sender_nobody_has_looked_up(OptOuts::Unseen));
    }

    /// The other lazy answer: a string that is present and says nothing.
    #[test]
    #[should_panic(expected = "an empty opt-out source")]
    fn a_named_source_that_names_nothing_is_the_unwired_variant_again() {
        vet(&a_sender_nobody_has_looked_up(OptOuts::Pulled { from: "" }));
        vet(&a_sender_nobody_has_looked_up(OptOuts::Pushed { at: "" }));
    }

    /// And the one the const block charges for rather than forbids: claiming a
    /// server reaches nobody compiles, and costs an edit to [`NO_OUTREACH`]
    /// whose failure message says what reading is owed. That half is a compile
    /// error and cannot be asserted from here; what *can* be is that the claim
    /// is at least well-formed for a connector we wrote down.
    #[test]
    fn the_claim_that_costs_an_edit_is_the_only_one_that_compiles_unchallenged() {
        vet(&a_sender_nobody_has_looked_up(OptOuts::NoStrangers));
        vet(&a_sender_nobody_has_looked_up(OptOuts::Pulled {
            from: "list_unsubscribed",
        }));
        vet(&a_sender_nobody_has_looked_up(OptOuts::HeldHere));
    }

    /// The two registers are one document, and nothing falls between them.
    ///
    /// This replaces an assertion that used to read `NO_OUTREACH.len() ==
    /// CATALOG.len() - 1` — true only while every entry but [`CUSTOM`] claimed
    /// [`OptOuts::NoStrangers`], and quietly meaningless the moment one did not.
    /// The property actually worth holding is that **every catalogued connector
    /// is accounted for exactly once**: it is on the roster that says it reaches
    /// nobody, on the roster that says this deployment answers for its outreach,
    /// or it named the read where its unsubscribes come in. There is no fourth
    /// place for one to be, and a connector in none of the three would be the
    /// `Unwired` state [`OptOuts`] refuses to have.
    ///
    /// The two `const` blocks each hold their own length; what neither can see
    /// is the other, and this is the line that adds them up.
    #[test]
    fn every_entry_is_on_exactly_one_of_the_two_registers() {
        let named = CATALOG
            .iter()
            .filter(|c| matches!(c.opt_outs, OptOuts::Pulled { .. } | OptOuts::Pushed { .. }))
            .count();
        assert_eq!(
            NO_OUTREACH.len() + OUTREACH_HELD_HERE.len() + named,
            CATALOG.len() - 1,
            "every entry but `CUSTOM` reaches nobody, is answered for here, or named its \
             read — and one of them is now in none of the three"
        );
        for key in NO_OUTREACH {
            assert!(
                !OUTREACH_HELD_HERE.contains(&key),
                "{key} claims both that it reaches nobody and that it reaches strangers"
            );
            assert!(
                find(key).is_some(),
                "{key} is on a register and not in CATALOG"
            );
        }
        for key in OUTREACH_HELD_HERE {
            assert!(
                find(key).is_some(),
                "{key} is on a register and not in CATALOG"
            );
        }
    }

    /// [`CUSTOM`] cannot make the claim either, from the other direction: a
    /// server whose address arrives in a request body is one nobody here has
    /// read a tool list for.
    #[test]
    #[should_panic(expected = "a claim about a tool list nobody has read")]
    fn the_custom_entry_cannot_claim_it_reaches_nobody() {
        vet(&Connector {
            opt_outs: OptOuts::NoStrangers,
            ..CUSTOM
        });
    }

    /// And it cannot make the *opposite* claim either, which is the arm
    /// [`OptOuts::HeldHere`] added to [`vet`].
    ///
    /// `HeldHere` is two readings — a tool list, then a vendor's API — and
    /// neither has happened for a URL that arrives in a request body. Without
    /// this arm it would have been the one variant a customer entry could carry
    /// freely, which is exactly the `Unwired` hole [`OptOuts`] refuses to have.
    #[test]
    #[should_panic(expected = "about a vendor nobody has asked for a suppression endpoint")]
    fn the_custom_entry_cannot_claim_this_deployment_answers_for_it() {
        vet(&Connector {
            opt_outs: OptOuts::HeldHere,
            ..CUSTOM
        });
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
