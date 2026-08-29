//! Every environment variable the server reads, in one struct, parsed once.
//!
//! # Why this file is the whole configuration story
//!
//! `.env.example` drifts from the code because they are two lists maintained
//! by two people at two times. There is only one list here: [`Config::parse`]
//! names every variable, and a required one that is missing is a boot failure
//! with the variable's name in the message. A deployment that is missing
//! something learns it in the first second, from the process that needs it,
//! rather than three hours later from a handler that dereferenced a `None`.
//!
//! Nothing else in the binary calls `std::env::var`. If it did, this file
//! would stop being the list, and we would be back to two lists.
//!
//! # Mocks
//!
//! A provider is *real* when its credential is configured and *mock* when it
//! is not, and a mock in production is an outage that reports success. So the
//! server refuses to start with any mock adapter unless `AGENTOS_ALLOW_MOCKS=1`
//! says out loud that this is a development box — and when it does start, it
//! says which adapters are fake, at `warn`, every time.
//!
//! The credential does not merely *permit* the real adapter, it **selects**
//! it: [`Config::credentials`] is what `main.rs` hands to
//! [`agentos_app::mocks::adapters_for`], so the same read that satisfies the
//! guard is the read that builds the client. Per adapter, never all-or-nothing
//! — a deployment with a Resend key and no Twilio account runs real email and
//! a fake phone, and [`Config::adapter_summary`] says so in one line at boot.
//!
//! An adapter that needs two values takes them in one variable, colon
//! separated, the same shape as the keyring and the webhook registry:
//! `TELEPHONY_API_KEY=ACxxxx:auth_token`, `BROWSER_API_KEY=project-id:bb_key`.
//! Half of one is a named boot failure, because an adapter holding half its
//! credential is the deployment that believes it is real and is not.
//!
//! The model is the one adapter chosen by name rather than by credential:
//! `AGENTOS_LLM` is `mock` (the default), `cli` or `anthropic`, and only the
//! last of those counts as real. Picking `anthropic` without `ANTHROPIC_API_KEY`
//! is a boot failure, because the alternative is an employee that accepts mail
//! for a week and answers none of it.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use agentos_app::hosted::{BRIDGES_PER_TENANT, BridgeNetwork};
use agentos_app::mocks::{
    BrowserCredentials, Credentials, EmailCredentials, EmbedderCredentials, LlmBackend,
    TelephonyCredentials,
};
use agentos_app::oauth::OauthClients;
use agentos_domain::ids::TenantId;

use crate::auth::{ApiKeys, ApiKeysError, PlatformKeys, PlatformKeysError};

/// Where the listener binds when `APP_BIND` is unset.
const DEFAULT_BIND: &str = "0.0.0.0:8080";

/// Tracing filter when `RUST_LOG` is unset.
const DEFAULT_RUST_LOG: &str = "info,agentos_server=debug";

/// The adapters that can run as mocks: the name the guard uses, the variable
/// that makes each one real, and the vendor behind it when it is.
///
/// **This array is the definition of "is anything mocked?".** Adding a
/// provider means adding a row here *and* a `bool` to the array beside it in
/// [`Config::parse`], which is a fixed-length array precisely so forgetting is
/// a compile error rather than a provider that ships to production as a mock.
///
/// Two things are deliberately **not** in it:
///
/// * The **LLM**, which is chosen by name (`AGENTOS_LLM=mock|cli|anthropic`)
///   rather than by whether a credential happens to be exported;
///   [`LlmBackend::mock_label`] answers "is this one real?". A second variable
///   meaning the same thing would be the two lists this module exists to avoid.
/// * The **secret vault**, which has no real implementation in this workspace
///   at all. It is named as a permanent mock by [`Config::adapter_summary`]
///   instead, which is honest and does not make `AGENTOS_ALLOW_MOCKS` mandatory
///   for every deployment forever — a flag everybody must set is a flag that
///   means nothing.
///
/// # `EMBEDDER_API_KEY` is a row again, and the argument that removed it is
/// answered rather than forgotten
///
/// It used to sit here, and it was deleted for a good reason: exporting any
/// string silenced a refusal and **selected nothing**, because `Embedder` had
/// one variant and it was a SHA-256 hash. A credential that cannot change what
/// runs must not be able to quiet an alarm.
///
/// That test is met now, and it is worth being exact about how rather than
/// asserting it. `agentos_providers::embedder::Embedder` has a second variant;
/// [`Credentials::embedder`] being `Some` is what builds
/// `OpenAiEmbedder` against the customer's key, and three observable things
/// change with it: `Embedder::is_semantic()` becomes `true`, which is the branch
/// `agentos_app::knowledge::retrieve` reads to run the vector leg it refuses to
/// run on a hash; every chunk is stamped `text-embedding-3-small` instead of
/// `mock-sha256-1536`, which is what keeps the two vector spaces apart in one
/// table; and `migrations/0076` gives that model an index of its own. The alarm
/// this credential quiets is an alarm about something that became real, which
/// is the only condition under which quieting it was ever wrong.
///
/// What it still does **not** buy is a model of the operator's choosing — the
/// key is the customer's, the model name is a constant, and
/// `agentos_providers::embedder_openai` argues why a partial index predicate
/// cannot name an environment variable.
const PROVIDER_CREDENTIALS: [(&str, &str, &str); 4] = [
    ("email", "EMAIL_API_KEY", "resend"),
    ("telephony", "TELEPHONY_API_KEY", "twilio"),
    ("browser", "BROWSER_API_KEY", "browserbase"),
    ("embedder", "EMBEDDER_API_KEY", "openai"),
];

/// The adapters no credential can make real, named in every boot summary so a
/// green line is not read as "all of this is live".
///
/// One left. The embedder was the other, and it moved into
/// [`PROVIDER_CREDENTIALS`] when it stopped being unfixable — see that
/// constant's docs, which carry the argument for both directions.
const PERMANENT_MOCKS: &str = "secrets=MOCK(in-memory)";

/// Why the process cannot start.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A variable with no sensible default was not set.
    #[error("{var} is not set, and there is no safe default for it")]
    Missing {
        /// The variable's name, so the message is actionable without reading
        /// this file.
        var: &'static str,
    },

    /// A variable was set to something unusable.
    #[error("{var} is not usable: {detail}")]
    Invalid {
        /// The variable's name.
        var: &'static str,
        /// What was wrong with the value. Never the value itself — these are
        /// secrets as often as not.
        detail: String,
    },

    /// A webhook registration was not `provider:tenant-uuid:secret`.
    #[error("AGENTOS_WEBHOOK_SECRETS entry {index} is not `provider:tenant-uuid:secret`")]
    WebhookEntry {
        /// Zero-based position of the offending entry.
        index: usize,
    },

    /// Two tenants were registered on one provider path.
    ///
    /// A boot failure rather than a warning, and the difference is where the
    /// customer's mail ends up. `routes::webhooks` keys its registry on the
    /// `{provider}` path segment alone and `main::webhooks` collects into a
    /// `HashMap`, so the second registration silently replaces the first —
    /// after which one tenant's deliveries are checked against the other
    /// tenant's signing secret and refused as forgeries, or, when both tenants
    /// sit behind one provider account and therefore one secret, accepted and
    /// **filed against the wrong company**. `inbound::resolve_recipient` then
    /// matches the address's local part inside that company, and two customers
    /// who both hired a `sales` is the first two customers.
    ///
    /// # Why this survived `migrations/0053_webhook_endpoints`
    ///
    /// Because the table did not touch this map. `webhook_endpoints` gives a
    /// second tenant an endpoint of its own, on a path of its own, read at
    /// request time; `main::webhooks` is still a `.collect()` into a `HashMap`
    /// and still drops the first of two entries on one path without a trace.
    /// The refusal therefore still guards exactly what it always guarded — one
    /// silent replacement in one data structure — and what changed is only the
    /// remedy it can offer, which is now "register the second tenant in the
    /// table" instead of "serve one tenant per provider".
    ///
    /// Names the provider and never the value: the variable holds signing
    /// secrets.
    #[error(
        "AGENTOS_WEBHOOK_SECRETS registers two tenants on the provider path {provider:?}, and \
         that map can only hold one — the second silently replaces the first and one of those \
         customers' inbound deliveries is then refused as a forgery or filed against the \
         other's company. Keep one tenant per provider in this variable and register the \
         others with POST /v1/platform/webhooks, which gives each one an endpoint of its own"
    )]
    WebhookProviderTwice {
        /// The path segment registered twice.
        provider: String,
    },
    /// An OAuth client registration was not `connector:client_id:client_secret`.
    ///
    /// Its own variant rather than an [`ConfigError::Invalid`] with a rendered
    /// message, so the position is a field a log can index on — and, like every
    /// other error in this enum, it never names the value: entry three being
    /// malformed is a fact about a `client_secret`, and half of one is still a
    /// credential.
    #[error("AGENTOS_OAUTH_CLIENTS entry {index} is not `connector:client_id:client_secret`")]
    OauthClientEntry {
        /// Zero-based position of the offending entry.
        index: usize,
    },

    /// Mock adapters were configured without an explicit blessing.
    ///
    /// The message names *which* adapters, which variables would fix them, and
    /// what the whole deployment would have looked like — so an operator who
    /// meant to run real email and forgot one variable can see, in the refusal
    /// itself, that the rest was fine.
    #[error(
        "refusing to start: {adapters} would run as mocks and do nothing real, and nobody said \
         that was acceptable (set {vars} for the real thing, or AGENTOS_ALLOW_MOCKS=1 to accept \
         exactly these). Adapters would be: {summary}"
    )]
    MocksNotAllowed {
        /// Comma-separated adapter names.
        adapters: String,
        /// Comma-separated credential variable names.
        vars: String,
        /// The same one-line inventory [`Config::adapter_summary`] logs at boot.
        summary: String,
    },
}

/// The server's entire configuration.
pub struct Config {
    /// `APP_BIND` — the listener address. Defaults to [`DEFAULT_BIND`].
    pub bind: SocketAddr,
    /// `PUBLIC_HOST` — the origin this deployment is reachable at, for webhook
    /// URLs and A2A agent cards. There is no defensible default: guessing it
    /// wrong means providers deliver callbacks nowhere.
    pub public_host: String,
    /// `AGENT_EMAIL_DOMAIN` — the domain employee addresses are minted under.
    pub agent_email_domain: String,
    /// `DATABASE_URL` — Postgres.
    pub database_url: String,
    /// `AGENTOS_MASTER_KEY` — the envelope-encryption root key.
    ///
    /// Handed to `agentos_app::identity::envelope`, which is what turns it into
    /// the 32 bytes the cipher takes and documents why that is a hash and not a
    /// KDF. Every employee's private signing key is sealed under it, so
    /// changing it in place orphans every identity this deployment has issued.
    ///
    /// **And every tenant's MCP credential**, since `0040_mcp_credentials`. The
    /// failure mode there is gentler and much more visible: a binding whose
    /// `sealed_token` no longer opens is left out of the fleet with
    /// `secret_decrypt_failed` on `GET /v1/mcp/servers`, rather than binding
    /// without the header and collecting a 401 that blames the customer's token.
    /// Re-connecting the server through `POST /v1/mcp/connect` repairs it, which
    /// is the same request that proves the replacement works before it is stored.
    pub master_key: String,
    /// `AGENTOS_ALLOW_MOCKS` — `1`/`true` permits mock adapters.
    pub allow_mocks: bool,
    /// `AGENTOS_LLM` — which model the employees reason with. Defaults to
    /// [`LlmBackend::Mock`], which is a mock adapter and therefore needs
    /// `AGENTOS_ALLOW_MOCKS`.
    pub llm: LlmBackend,
    /// `ANTHROPIC_API_KEY`, when [`Config::llm`] needs one. Required at boot
    /// for [`LlmBackend::Anthropic`], so the first inbound email is never where
    /// a missing key is discovered.
    pub anthropic_api_key: Option<String>,
    /// `RUST_LOG` — the tracing filter.
    pub rust_log: String,
    /// `AGENTOS_API_KEYS` — the keyring. See [`crate::auth`].
    pub api_keys: ApiKeys,
    /// `AGENTOS_PLATFORM_KEYS` — the credential that may create a tenant and
    /// issue or revoke that tenant's keys, as `label:secret`. It names no
    /// tenant, because it speaks for none.
    ///
    /// Empty is the default and means `/v1/platform/*` answers 401 to
    /// everybody: a deployment that has not been handed this key has no signup
    /// surface at all, which is the right state for one that is not a control
    /// plane. See [`crate::auth`] for why this one credential stays in the
    /// environment while every customer's moved into the database.
    pub platform_keys: PlatformKeys,
    /// Adapters that will run as mocks in this process, derived from
    /// [`PROVIDER_CREDENTIALS`].
    pub mock_adapters: Vec<&'static str>,
    /// What the real adapters are built from. A `None` field here and a name in
    /// [`Config::mock_adapters`] are the same fact read twice: `main.rs` hands
    /// this to [`agentos_app::mocks::adapters_for`], so the credential that
    /// satisfies the guard is the credential that builds the client.
    pub credentials: Credentials,
    /// `AGENTOS_WEBHOOK_SECRETS` — which provider callbacks this deployment
    /// accepts, and whose. Empty means every `/v1/webhooks/{provider}` is a
    /// 404, which is the right answer for a deployment that has integrated
    /// nobody.
    pub webhooks: Vec<WebhookRegistration>,
    /// `AGENTOS_OAUTH_CLIENTS` — the OAuth applications *we* registered, one per
    /// connector, as `connector:client_id:client_secret[,…]`.
    ///
    /// **Deployment scope, never tenant scope.** A `client_secret` identifies
    /// this product to a provider; it is the same value for every customer and
    /// no customer has any business reading or writing one. `agentos_app::oauth`
    /// argues the whole split, and the visible consequence is in
    /// `routes::mcp::catalog`: a connector with no registration here is not
    /// advertised, so nobody clicks a button that cannot work.
    ///
    /// Empty is a deployment that offers no OAuth connectors, which is exactly
    /// what this one is until somebody registers an application — see
    /// `agentos_app::catalog::CATALOG` for why there is no entry to register for
    /// yet.
    pub oauth_clients: Arc<OauthClients>,
    /// `MCP_BRIDGE_BIND` — whether this deployment runs hosted MCP servers at
    /// all, and where their ports are published.
    ///
    /// `None` is the default and it is the whole safety switch: no address, no
    /// [`Bridges`](agentos_app::hosted::Bridges), and every hosted binding
    /// refuses with `hosting_unavailable`. `agentos_app::hosted` spends a page
    /// on why an unset value here has to start nothing rather than default to
    /// something, and the short version is that the wrong default is not a
    /// smaller version of the right one — it is one container per slug a tenant
    /// can invent, on our machine.
    pub hosting: Option<Hosting>,
}

/// What it takes to run somebody else's MCP server on this deployment.
///
/// One struct rather than three optional fields, because "an address but no
/// cap" and "a cap but no address" are states that would have to be checked for
/// at the call site, forever, by everyone. Here they cannot be spelled.
#[derive(Debug, Clone)]
pub struct Hosting {
    /// `MCP_BRIDGE_BIND` — the address a bridge's port is published on, and the
    /// **only** address [`accept`](agentos_app::hosted::accept) will take: see
    /// [`Hosting::network`]. `127.0.0.1` for a development box, the host's
    /// address on the operator's bridge subnet for a real one.
    pub bind: IpAddr,
    /// `MCP_BRIDGES_PER_TENANT` — how many bridges one tenant may have started
    /// on one bind pass. Defaults to
    /// [`BRIDGES_PER_TENANT`](agentos_app::hosted::BRIDGES_PER_TENANT), which is
    /// **zero**.
    ///
    /// A variable rather than the constant it defaults to, because that
    /// constant's own documentation says the number is "answered with an
    /// operator's arithmetic and not a programmer's" — box memory over runner
    /// size over tenants per box — and an operator cannot do arithmetic in a
    /// binary somebody else compiled. Defaulting to the constant keeps the
    /// fail-closed direction it was chosen for: a deployment that sets an
    /// address and nothing else starts nothing and says `hosted_cap_reached`,
    /// which names the remaining decision.
    pub per_tenant: usize,
    /// `MCP_BRIDGE_IMAGE` — the runner image. Defaults to
    /// [`DEFAULT_IMAGE`](crate::bridge::DEFAULT_IMAGE).
    pub image: String,
}

impl Hosting {
    /// The addresses [`accept`](agentos_app::hosted::accept) admits: exactly
    /// [`Hosting::bind`], as its own single-address prefix.
    ///
    /// Derived rather than configured, and that is the point. The network and
    /// the publish address used to be two variables, and two settings that must
    /// agree are one setting somebody eventually gets wrong — in the direction
    /// where the network is wider than what the runtime can produce, which is
    /// the direction that admits an address we did not mint.
    pub fn network(&self) -> BridgeNetwork {
        let bits = if self.bind.is_ipv4() { 32 } else { 128 };
        BridgeNetwork::parse(&format!("{}/{bits}", self.bind))
            .expect("a single address is the network address of its own longest prefix")
    }
}

/// One provider callback endpoint.
///
/// The tenant is part of the registration and never comes off the wire: a
/// delivery that could name its own tenant is a delivery that can write into
/// somebody else's queue. See `routes::webhooks`.
pub struct WebhookRegistration {
    /// The `{provider}` path segment, e.g. `email`.
    pub provider: String,
    /// Whose queue deliveries here land in.
    pub tenant_id: TenantId,
    /// The secret their signatures are MACed with.
    pub secret: String,
}

// Hand-written: a derived Debug would print the master key and the API keys
// into whatever log line someone dumps the config to. That is how secrets end
// up in log aggregators, and it is always an accident.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("public_host", &self.public_host)
            .field("agent_email_domain", &self.agent_email_domain)
            .field("database_url", &"<redacted>")
            .field("master_key", &"<redacted>")
            .field("allow_mocks", &self.allow_mocks)
            .field("llm", &self.llm.name())
            .field("anthropic_api_key", &self.anthropic_api_key.is_some())
            .field("rust_log", &self.rust_log)
            .field(
                "api_keys",
                &format_args!("{} configured", self.api_keys.len()),
            )
            .field(
                "platform_keys",
                &format_args!("{} configured", self.platform_keys.len()),
            )
            .field("mock_adapters", &self.mock_adapters)
            // Its own Debug prints which adapters are configured, never with
            // what.
            .field("credentials", &self.credentials)
            .field(
                "webhooks",
                &self
                    .webhooks
                    .iter()
                    .map(|hook| hook.provider.as_str())
                    .collect::<Vec<_>>(),
            )
            // Its own Debug prints the connector keys and nothing else — not
            // the client id, which is not a secret, and certainly not the one
            // beside it.
            .field("oauth_clients", &self.oauth_clients)
            // Nothing secret in it, and the whole of it is worth printing: this
            // is the field that decides whether this deployment runs anybody
            // else's code at all.
            .field("hosting", &self.hosting)
            .finish()
    }
}

impl Config {
    /// Read the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::parse(|var| std::env::var(var).ok())
    }

    /// Read from any source. Tests pass a closure over a fixed map, because
    /// `std::env::set_var` is `unsafe` in edition 2024 and process-global in
    /// every edition — two tests mutating it race each other.
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // An exported-but-empty variable is a variable someone meant to set.
        let get = |var: &'static str| {
            get(var)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let required = |var: &'static str| get(var).ok_or(ConfigError::Missing { var });

        // Required first: "you forgot DATABASE_URL" is a more useful first
        // message than anything downstream of it.
        let public_host = required("PUBLIC_HOST")?;
        let agent_email_domain = required("AGENT_EMAIL_DOMAIN")?;
        let database_url = required("DATABASE_URL")?;
        let master_key = required("AGENTOS_MASTER_KEY")?;

        let bind = get("APP_BIND").unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let bind = bind
            .parse::<SocketAddr>()
            .map_err(|err| ConfigError::Invalid {
                var: "APP_BIND",
                detail: format!("{bind:?} is not a host:port address ({err})"),
            })?;

        let api_keys = ApiKeys::parse(&get("AGENTOS_API_KEYS").unwrap_or_default()).map_err(
            |err: ApiKeysError| ConfigError::Invalid {
                var: "AGENTOS_API_KEYS",
                detail: err.to_string(),
            },
        )?;

        let platform_keys = PlatformKeys::parse(&get("AGENTOS_PLATFORM_KEYS").unwrap_or_default())
            .map_err(|err: PlatformKeysError| ConfigError::Invalid {
                var: "AGENTOS_PLATFORM_KEYS",
                detail: err.to_string(),
            })?;

        // The model, before the mock guard: a typo'd backend name is a more
        // useful message than "the llm would run as a mock".
        let llm = match get("AGENTOS_LLM") {
            None => LlmBackend::default(),
            Some(spec) => LlmBackend::parse(&spec).ok_or_else(|| ConfigError::Invalid {
                var: "AGENTOS_LLM",
                detail: format!("{spec:?} is not one of: {}", LlmBackend::VALUES),
            })?,
        };
        // Here rather than at the first inbound email: a deployment that meant
        // to run on the real model and forgot the key must crash-loop, not
        // quietly accept mail it cannot answer.
        let anthropic_api_key = get(LlmBackend::API_KEY_VAR);
        if let Some(var) = llm.required_var()
            && get(var).is_none()
        {
            return Err(ConfigError::Missing { var });
        }

        let allow_mocks = matches!(
            get("AGENTOS_ALLOW_MOCKS").unwrap_or_default().as_str(),
            "1" | "true" | "yes"
        );

        // Before the credentials: the email adapter is built with the `whsec_…`
        // an operator has already pasted in here, rather than with a fourth
        // variable holding the same string.
        let webhooks = parse_webhooks(&get("AGENTOS_WEBHOOK_SECRETS").unwrap_or_default())?;

        // Parsed here rather than in `routes::mcp`, because this file is the one
        // place that reads the environment and a second `std::env::var` is how a
        // deployment ends up with two answers about what it is registered for.
        let oauth_clients = Arc::new(
            OauthClients::parse(&get("AGENTOS_OAUTH_CLIENTS").unwrap_or_default())
                .map_err(|err| ConfigError::OauthClientEntry { index: err.index })?,
        );

        // The one read per adapter. What it produces decides *both* what gets
        // built and what the guard names, so the two cannot disagree about
        // which adapter is running.
        let credentials = Credentials {
            email: get("EMAIL_API_KEY").map(|api_key| EmailCredentials {
                api_key,
                // The adapter's own `verify_webhook` is not on any path today —
                // `routes::webhooks` verifies against this same registry before
                // anything reaches an adapter — so an unregistered `email`
                // provider leaves this empty rather than failing the boot. The
                // deployment is still told, loudly, that no callback can arrive
                // at all: see `warn_about_mocks`.
                webhook_secret: webhooks
                    .iter()
                    .find(|hook| hook.provider == "email")
                    .map_or_else(String::new, |hook| hook.secret.clone()),
                // One adapter owns one sending domain, and this is it.
                domain: agent_email_domain.clone(),
            }),
            telephony: split_pair(
                "TELEPHONY_API_KEY",
                get("TELEPHONY_API_KEY"),
                "ACxxxxxxxx:auth_token — console.twilio.com shows both",
            )?
            .map(|(account_sid, auth_token)| TelephonyCredentials {
                account_sid,
                auth_token,
            }),
            browser: split_pair(
                "BROWSER_API_KEY",
                get("BROWSER_API_KEY"),
                "project-id:api-key — the Browserbase settings page shows both",
            )?
            .map(|(project_id, api_key)| BrowserCredentials {
                project_id,
                api_key,
            }),
            // One value and not a pair, unlike the two above: the customer
            // brings the key and the model is a constant of the adapter,
            // because the HNSW index is partial on a model name and a partial
            // index predicate is a SQL literal. See
            // `agentos_providers::embedder_openai`.
            embedder: get("EMBEDDER_API_KEY").map(|api_key| EmbedderCredentials { api_key }),
        };

        // Fixed length, matching [`PROVIDER_CREDENTIALS`] row for row: adding a
        // provider without deciding whether it is real is a compile error, not
        // an adapter that slips past the guard.
        let is_real: [bool; PROVIDER_CREDENTIALS.len()] = [
            credentials.email.is_some(),
            credentials.telephony.is_some(),
            credentials.browser.is_some(),
            credentials.embedder.is_some(),
        ];
        let mut mock_adapters = Vec::new();
        let mut mock_vars = Vec::new();
        for ((adapter, var, _), real) in PROVIDER_CREDENTIALS.iter().zip(is_real) {
            if !real {
                mock_adapters.push(*adapter);
                mock_vars.push((*var).to_owned());
            }
        }
        if let Some(label) = llm.mock_label() {
            mock_adapters.push(label);
            mock_vars.push(format!(
                "AGENTOS_LLM=anthropic and {}",
                LlmBackend::API_KEY_VAR
            ));
        }

        if !mock_adapters.is_empty() && !allow_mocks {
            return Err(ConfigError::MocksNotAllowed {
                adapters: mock_adapters.join(", "),
                vars: mock_vars.join(", "),
                summary: summarize(&mock_adapters, llm),
            });
        }

        // Hosting is off unless an address says otherwise, and the other two
        // variables are read only inside that branch: a deployment that sets a
        // cap and no address has configured nothing, and reading its number
        // would give it something to look at that changes no behaviour.
        let hosting = match get("MCP_BRIDGE_BIND") {
            None => None,
            Some(raw) => {
                let bind = raw.parse::<IpAddr>().map_err(|err| ConfigError::Invalid {
                    var: "MCP_BRIDGE_BIND",
                    detail: format!("{raw:?} is not an IP address ({err})"),
                })?;
                let per_tenant = match get("MCP_BRIDGES_PER_TENANT") {
                    None => BRIDGES_PER_TENANT,
                    Some(raw) => raw.parse::<usize>().map_err(|err| ConfigError::Invalid {
                        var: "MCP_BRIDGES_PER_TENANT",
                        detail: format!("{raw:?} is not a count ({err})"),
                    })?,
                };
                Some(Hosting {
                    bind,
                    per_tenant,
                    image: get("MCP_BRIDGE_IMAGE")
                        .unwrap_or_else(|| crate::bridge::DEFAULT_IMAGE.to_owned()),
                })
            }
        };

        Ok(Self {
            bind,
            public_host,
            agent_email_domain,
            database_url,
            master_key,
            allow_mocks,
            llm,
            anthropic_api_key,
            rust_log: get("RUST_LOG").unwrap_or_else(|| DEFAULT_RUST_LOG.to_owned()),
            api_keys,
            platform_keys,
            mock_adapters,
            credentials,
            webhooks,
            oauth_clients,
            hosting,
        })
    }

    /// Every adapter and what is actually behind it, in one line.
    ///
    /// The line a partial deployment is legible from: `email=resend
    /// telephony=MOCK …` is the difference between "we integrated Twilio last
    /// week" and "we integrated Twilio last week and the variable has a typo in
    /// it". Names the adapters no credential can fix as well, so that a line
    /// with no `MOCK` in it cannot be manufactured by omission.
    pub fn adapter_summary(&self) -> String {
        summarize(&self.mock_adapters, self.llm)
    }

    /// Say, loudly and every time, what is real and what is not.
    ///
    /// Called after the subscriber is installed, which is why it is not part
    /// of [`Config::parse`] — a warning emitted before tracing is up goes
    /// nowhere, and this one is the whole point.
    pub fn warn_about_mocks(&self) {
        // Unconditional, even on a fully real deployment: the one line that
        // answers "is this thing actually sending email?" has to be in every
        // boot log, or the answer is "read the environment of a pod that has
        // since been replaced".
        tracing::info!(adapters = %self.adapter_summary(), "provider adapters");

        if !self.mock_adapters.is_empty() {
            tracing::warn!(
                adapters = %self.mock_adapters.join(", "),
                "RUNNING WITH MOCK ADAPTERS — these providers do nothing real. \
                 AGENTOS_ALLOW_MOCKS is set; unset it in any environment that matters."
            );
        }
        if self.api_keys.is_empty() && self.platform_keys.is_empty() {
            // Both, together, because either one on its own is now a legitimate
            // deployment: a control plane holds only a platform key and issues
            // the rest, and the runbook's single-tenant box holds only the
            // environment keyring. Warning about an empty `AGENTOS_API_KEYS` on
            // a box that is issuing keys over HTTP would be an alarm that is
            // always on, and an alarm that is always on is off.
            tracing::warn!(
                "AGENTOS_API_KEYS and AGENTOS_PLATFORM_KEYS are both empty: every request will \
                 be answered 401 and no key can be issued to change that. Set \
                 AGENTOS_API_KEYS to `label:tenant-uuid:secret[,…]`, or AGENTOS_PLATFORM_KEYS \
                 to `label:secret` and sign a tenant up through POST /v1/platform/tenants."
            );
        }
        if self.webhooks.is_empty() {
            tracing::warn!(
                "AGENTOS_WEBHOOK_SECRETS is empty: no provider callback is registered in the \
                 environment. Set it to `provider:tenant-uuid:signing-secret[,…]` — or, for a \
                 deployment whose customers each hold their own provider account, register them \
                 with POST /v1/platform/webhooks, which is the other half of this and is not \
                 visible from here."
            );
        }
    }
}

/// Every adapter and what is behind it, as `name=vendor` or `name=MOCK`.
///
/// Free-standing so [`Config::parse`] can put it in the refusal it returns
/// *instead of* a `Config` — the boot that does not happen is the one an
/// operator most needs the inventory for.
fn summarize(mock_adapters: &[&'static str], llm: LlmBackend) -> String {
    let mut parts = PROVIDER_CREDENTIALS
        .iter()
        .map(|(adapter, _, vendor)| {
            if mock_adapters.contains(adapter) {
                format!("{adapter}=MOCK")
            } else {
                format!("{adapter}={vendor}")
            }
        })
        .collect::<Vec<_>>();
    parts.push(match llm.mock_label() {
        // `cli` does real inference and is still not a thing to deploy on, so
        // it is named rather than blessed.
        Some(_) => format!("llm=MOCK({})", llm.name()),
        None => format!("llm={}", llm.name()),
    });
    parts.push(PERMANENT_MOCKS.to_owned());
    parts.join(" ")
}

/// Split a `left:right` credential, or refuse by name.
///
/// `None` in, `None` out: an adapter with no variable set is the mock, which is
/// the guard's business and not an error here. A variable that *is* set and is
/// not a pair is always an error, because the alternative is an adapter built
/// from half a credential — which authenticates against nothing and fails on
/// its first real call, hours later, in somebody else's log.
fn split_pair(
    var: &'static str,
    raw: Option<String>,
    shape: &str,
) -> Result<Option<(String, String)>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw.split_once(':') {
        Some((left, right)) if !left.trim().is_empty() && !right.trim().is_empty() => {
            Ok(Some((left.trim().to_owned(), right.trim().to_owned())))
        }
        // Never echoes the value: half of it is still a live credential.
        _ => Err(ConfigError::Invalid {
            var,
            detail: format!("must be `{shape}`, and both halves are required"),
        }),
    }
}

/// `provider:tenant-uuid:secret,…`, the same shape as the keyring next door so
/// there is one format to learn rather than two.
///
/// An empty string is a valid, empty registry.
/// Parse `AGENTOS_WEBHOOK_SECRETS`, refusing a provider registered twice.
///
/// The duplicate check is here rather than in `main::webhooks` because that is
/// where the value is *known* and this is where it is read — and because the
/// collapse it prevents is invisible at every later point: `Webhooks` is a
/// `HashMap` keyed on the provider path, so the second registration wins and
/// nothing has a record that there was a first. See
/// [`ConfigError::WebhookProviderTwice`] for what that costs a customer.
fn parse_webhooks(raw: &str) -> Result<Vec<WebhookRegistration>, ConfigError> {
    let parsed = parse_webhook_entries(raw)?;
    let mut seen = std::collections::BTreeSet::new();
    for hook in &parsed {
        if !seen.insert(hook.provider.as_str()) {
            return Err(ConfigError::WebhookProviderTwice {
                provider: hook.provider.clone(),
            });
        }
    }
    Ok(parsed)
}

fn parse_webhook_entries(raw: &str) -> Result<Vec<WebhookRegistration>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .enumerate()
        .map(|(index, entry)| {
            // `splitn(3)` so a secret may contain colons — `whsec_…` ones do.
            let mut fields = entry.splitn(3, ':');
            let (Some(provider), Some(tenant), Some(secret)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(ConfigError::WebhookEntry { index });
            };
            if provider.is_empty() || secret.is_empty() {
                return Err(ConfigError::WebhookEntry { index });
            }
            Ok(WebhookRegistration {
                provider: provider.to_owned(),
                tenant_id: tenant
                    .parse()
                    .map_err(|_| ConfigError::WebhookEntry { index })?,
                secret: secret.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TENANT: &str = "00000000-0000-0000-0000-000000000001";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /// A well-formed value for each provider credential, in the shape that
    /// variable demands. Two of the three are compound, and a test that pasted
    /// `live-credential` into them would be testing the refusal, not the boot.
    const CREDENTIALS: [(&str, &str); PROVIDER_CREDENTIALS.len()] = [
        ("EMAIL_API_KEY", "re_live_key"),
        ("TELEPHONY_API_KEY", "ACtest:live-auth-token"),
        ("BROWSER_API_KEY", "proj_test:bb_live_key"),
        ("EMBEDDER_API_KEY", "sk-live-key"),
    ];

    /// Everything a real deployment sets. Tests remove from this, never add to
    /// it, so "what does the server need?" has one answer.
    fn complete() -> HashMap<&'static str, String> {
        let mut env: HashMap<&'static str, String> = HashMap::from([
            ("APP_BIND", "127.0.0.1:9000".to_owned()),
            ("PUBLIC_HOST", "https://agents.example.com".to_owned()),
            ("AGENT_EMAIL_DOMAIN", "agents.example.com".to_owned()),
            ("DATABASE_URL", "postgres://localhost/agentos".to_owned()),
            ("AGENTOS_MASTER_KEY", "not-a-real-key".to_owned()),
            ("RUST_LOG", "debug".to_owned()),
            ("AGENTOS_API_KEYS", format!("ops:{TENANT}:{SECRET}")),
            // The only backend that is not a mock adapter, so that the cases
            // below are about the adapter they remove and nothing else.
            ("AGENTOS_LLM", "anthropic".to_owned()),
            ("ANTHROPIC_API_KEY", "sk-ant-live".to_owned()),
        ]);
        for (var, value) in CREDENTIALS {
            env.insert(var, value.to_owned());
        }
        env
    }

    fn parse(env: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::parse(|var| env.get(var).cloned())
    }

    /// Hosting is off unless an address turns it on, and on with a cap of zero
    /// unless a second variable answers the question written on
    /// `BRIDGES_PER_TENANT`. Both halves of the safety switch, in one test,
    /// because the dangerous edit is the one that keeps half of it.
    #[test]
    fn hosting_is_off_until_an_address_and_a_cap_say_otherwise() {
        let mut env = complete();
        assert!(parse(&env).expect("parse").hosting.is_none());

        env.insert("MCP_BRIDGE_BIND", "127.0.0.1".to_owned());
        let hosting = parse(&env).expect("parse").hosting.expect("hosting");
        assert_eq!(hosting.per_tenant, BRIDGES_PER_TENANT);
        assert_eq!(hosting.per_tenant, 0, "the default still starts nothing");
        assert_eq!(hosting.image, crate::bridge::DEFAULT_IMAGE);

        env.insert("MCP_BRIDGES_PER_TENANT", "2".to_owned());
        assert_eq!(
            parse(&env)
                .expect("parse")
                .hosting
                .expect("hosting")
                .per_tenant,
            2
        );

        env.insert("MCP_BRIDGE_BIND", "not-an-address".to_owned());
        assert!(matches!(
            parse(&env),
            Err(ConfigError::Invalid {
                var: "MCP_BRIDGE_BIND",
                ..
            })
        ));
    }

    /// The network `accept` is given admits the address the runtime publishes
    /// on, and **nothing else** — the whole reason it is derived rather than
    /// configured. A `/32` that came out one bit short would admit a
    /// neighbour's container.
    #[test]
    fn the_admitted_network_is_exactly_the_bind_address() {
        for (bind, neighbour) in [
            ("127.0.0.1", "127.0.0.2"),
            ("10.42.0.1", "10.42.0.2"),
            ("fd00::1", "fd00::2"),
        ] {
            let bind: IpAddr = bind.parse().expect("addr");
            let neighbour: IpAddr = neighbour.parse().expect("addr");
            let hosting = Hosting {
                bind,
                per_tenant: 1,
                image: String::new(),
            };
            let network = hosting.network();
            // Built the way `crate::bridge` builds it, through `SocketAddr`, so
            // an IPv6 literal is bracketed here exactly as it is there.
            let url = |ip| format!("http://{}/mcp", std::net::SocketAddr::new(ip, 8000));
            assert!(
                agentos_app::hosted::accept(&url(bind), &network).is_ok(),
                "{bind} is the address we publish on and must be admitted"
            );
            assert!(
                agentos_app::hosted::accept(&url(neighbour), &network).is_err(),
                "{neighbour} is not ours and must not be admitted"
            );
        }
    }

    #[test]
    fn a_complete_environment_boots() {
        let config = parse(&complete()).expect("a complete environment is enough");

        assert_eq!(config.bind.port(), 9000);
        assert_eq!(config.agent_email_domain, "agents.example.com");
        assert_eq!(config.rust_log, "debug");
        assert!(config.mock_adapters.is_empty());
        assert_eq!(config.api_keys.len(), 1);
        assert_eq!(config.llm, LlmBackend::Anthropic);
        // And every credential turned into something to build a client from,
        // which is the difference between satisfying the guard and being wired.
        assert!(config.credentials.email.is_some());
        assert!(config.credentials.telephony.is_some());
        assert!(config.credentials.browser.is_some());
        assert!(config.credentials.embedder.is_some());
    }

    // -- credentials select adapters ---------------------------------------

    /// The claim the whole file exists for: setting the variable does not
    /// merely permit the real adapter, it *is* how the real adapter gets built.
    #[test]
    fn a_credential_selects_the_real_adapter_and_its_absence_selects_the_mock() {
        let mut env = complete();
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());

        for (var, _) in CREDENTIALS {
            let mut without = env.clone();
            without.remove(var);
            let config = parse(&without).expect("mocks are allowed here");

            let present = |c: &Config| {
                [
                    ("EMAIL_API_KEY", c.credentials.email.is_some()),
                    ("TELEPHONY_API_KEY", c.credentials.telephony.is_some()),
                    ("BROWSER_API_KEY", c.credentials.browser.is_some()),
                    ("EMBEDDER_API_KEY", c.credentials.embedder.is_some()),
                ]
            };
            for (other, configured) in present(&config) {
                assert_eq!(
                    configured,
                    other != var,
                    "removing {var} changed whether {other} was configured"
                );
            }
        }
    }

    /// The compound halves. An adapter built from half a credential
    /// authenticates against nothing and finds out hours later, so the boot
    /// stops and names the variable.
    #[test]
    fn half_a_compound_credential_fails_the_boot_by_name() {
        for var in ["TELEPHONY_API_KEY", "BROWSER_API_KEY"] {
            for half in ["just-one-value", "ACtest:", ":token", ":"] {
                let mut env = complete();
                env.insert(var, half.to_owned());

                let err = parse(&env).expect_err("{var} = {half} must not build an adapter");
                assert!(
                    matches!(&err, ConfigError::Invalid { var: named, .. } if *named == var),
                    "{var} = {half:?} produced {err:?}"
                );
                // Actionable on its own, and never echoing the live half.
                assert!(err.to_string().contains(var), "{err}");
                assert!(!err.to_string().contains("ACtest"), "{err}");
            }
        }
    }

    /// The email adapter needs a `whsec_…` as well as an API key, and an
    /// operator has already pasted one into the webhook registry. Reading it
    /// from there beats a fourth variable holding the same string in a
    /// different place.
    #[test]
    fn the_email_adapter_signs_with_the_secret_already_in_the_webhook_registry() {
        let mut env = complete();
        env.insert(
            "AGENTOS_WEBHOOK_SECRETS",
            format!("email:{TENANT}:whsec_from_the_registry"),
        );

        let config = parse(&env).expect("valid");
        let email = config.credentials.email.expect("configured");
        assert_eq!(email.webhook_secret, "whsec_from_the_registry");
        assert_eq!(email.api_key, "re_live_key");
        // One adapter, one sending domain.
        assert_eq!(email.domain, "agents.example.com");

        // No registration is not a boot failure — nothing calls the adapter's
        // own verifier yet — but it does leave the secret empty rather than
        // inventing one.
        env.remove("AGENTOS_WEBHOOK_SECRETS");
        assert_eq!(
            parse(&env)
                .expect("valid")
                .credentials
                .email
                .expect("configured")
                .webhook_secret,
            ""
        );
    }

    /// The line an operator reads to answer "is this deployment actually
    /// sending email?" — and it has to stay answerable when only half the
    /// integration has landed.
    #[test]
    fn a_partly_real_deployment_is_legible_in_one_line() {
        let mut env = complete();
        assert_eq!(
            parse(&env).expect("valid").adapter_summary(),
            format!(
                "email=resend telephony=twilio browser=browserbase embedder=openai \
                 llm=anthropic {PERMANENT_MOCKS}"
            ),
        );

        env.remove("TELEPHONY_API_KEY");
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());
        let config = parse(&env).expect("allowed");
        assert_eq!(
            config.adapter_summary(),
            format!(
                "email=resend telephony=MOCK browser=browserbase embedder=openai \
                 llm=anthropic {PERMANENT_MOCKS}"
            ),
            "one real adapter missing must not read the same as all of them present"
        );
        config.warn_about_mocks();
    }

    /// The refusal carries the same inventory, because the boot that does not
    /// happen is the one the operator most needs it for.
    #[test]
    fn the_refusal_says_which_adapters_would_still_have_been_real() {
        let mut env = complete();
        env.remove("BROWSER_API_KEY");

        let err = parse(&env).expect_err("a mock browser must not start silently");
        let ConfigError::MocksNotAllowed { summary, .. } = &err else {
            panic!("expected MocksNotAllowed, got {err:?}");
        };
        assert!(summary.contains("browser=MOCK"), "{summary}");
        assert!(summary.contains("email=resend"), "{summary}");
        assert!(err.to_string().contains("email=resend"), "{err}");
    }

    /// The adapters no credential can fix are named every time, so a summary
    /// with no `MOCK` in it cannot be produced by leaving something out.
    ///
    /// One left. The embedder was the other and it is a credential now, which
    /// is what [`the_embedder_credential_is_a_selection_and_not_a_silencer`]
    /// below is about.
    #[test]
    fn the_permanent_mocks_are_named_even_on_a_fully_credentialed_deployment() {
        let config = parse(&complete()).expect("valid");
        assert!(
            config.mock_adapters.is_empty(),
            "nothing selectable is fake"
        );
        assert!(
            config.adapter_summary().contains("secrets=MOCK"),
            "{}",
            config.adapter_summary()
        );
    }

    /// **`EMBEDDER_API_KEY` is back, and it has to earn the alarm it quiets.**
    ///
    /// It was deleted because exporting any string turned a refusal green while
    /// selecting nothing. The test for its return is not "does it parse" — it is
    /// that removing it makes the boot *refuse* by name, the way every other
    /// credential does, and that the summary tells an operator which of the two
    /// embedders is behind the port. A variable that could be absent without the
    /// guard noticing would be the old bug pointing the other way.
    #[test]
    fn the_embedder_credential_is_a_selection_and_not_a_silencer() {
        let mut env = complete();
        assert!(
            parse(&env)
                .expect("valid")
                .adapter_summary()
                .contains("embedder=openai"),
            "a deployment that has bought an embedder must be able to see it"
        );

        env.remove("EMBEDDER_API_KEY");
        let err = parse(&env).expect_err("a hash embedder must not start silently");
        let ConfigError::MocksNotAllowed {
            adapters,
            vars,
            summary,
        } = &err
        else {
            panic!("expected MocksNotAllowed, got {err:?}");
        };
        assert_eq!(adapters, "embedder");
        assert_eq!(vars, "EMBEDDER_API_KEY");
        assert!(summary.contains("embedder=MOCK"), "{summary}");

        // And an operator who says so out loud gets the hash, named as one.
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());
        let config = parse(&env).expect("allowed");
        assert!(config.credentials.embedder.is_none());
        assert_eq!(config.mock_adapters, vec!["embedder"]);
    }

    // -- the model ---------------------------------------------------------

    /// The point of the whole variable: a deployment that asked for the real
    /// model and forgot the key stops at boot, naming the key.
    #[test]
    fn selecting_anthropic_without_a_key_fails_the_boot_by_name() {
        let mut env = complete();
        env.remove("ANTHROPIC_API_KEY");

        let err = parse(&env).expect_err("the real model needs a key");
        assert!(
            matches!(
                err,
                ConfigError::Missing {
                    var: "ANTHROPIC_API_KEY"
                }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("ANTHROPIC_API_KEY"), "{err}");

        // An exported-but-empty key is the same failure, not a client that
        // authenticates with the empty string.
        env.insert("ANTHROPIC_API_KEY", "  ".to_owned());
        assert!(parse(&env).is_err());
    }

    #[test]
    fn the_backends_that_need_nothing_boot_with_nothing() {
        let mut env = complete();
        env.remove("ANTHROPIC_API_KEY");
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());

        for (spec, backend) in [("mock", LlmBackend::Mock), ("cli", LlmBackend::Cli)] {
            env.insert("AGENTOS_LLM", spec.to_owned());
            let config = parse(&env).unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert_eq!(config.llm, backend);
            assert!(config.anthropic_api_key.is_none());
            // Neither is the real thing, so both are named in the warning.
            assert_eq!(config.mock_adapters.len(), 1, "{:?}", config.mock_adapters);
            assert!(config.mock_adapters[0].starts_with("llm ("));
        }
    }

    /// Unset is the mock, and the mock is a mock adapter — so a deployment
    /// cannot end up answering customers with `MOCK_REPLY` by omission.
    #[test]
    fn an_unset_backend_is_the_mock_and_the_mock_needs_permission() {
        let mut env = complete();
        env.remove("AGENTOS_LLM");
        env.remove("ANTHROPIC_API_KEY");

        let err = parse(&env).expect_err("the default backend is a mock");
        let ConfigError::MocksNotAllowed { adapters, vars, .. } = &err else {
            panic!("expected MocksNotAllowed, got {err:?}");
        };
        assert!(adapters.contains("llm"), "{adapters}");
        assert!(vars.contains("AGENTOS_LLM=anthropic"), "{vars}");

        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());
        assert_eq!(parse(&env).expect("allowed").llm, LlmBackend::Mock);
    }

    #[test]
    fn an_unknown_backend_fails_the_boot_rather_than_falling_back() {
        let mut env = complete();
        env.insert("AGENTOS_LLM", "gpt".to_owned());

        let err = parse(&env).expect_err("there is no such backend");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    var: "AGENTOS_LLM",
                    ..
                }
            ),
            "{err:?}"
        );
        // And it says what to write instead.
        assert!(err.to_string().contains("anthropic"), "{err}");
    }

    #[test]
    fn the_api_key_is_not_in_the_debug_rendering() {
        let mut env = complete();
        env.insert("ANTHROPIC_API_KEY", "sk-ant-hunter2".to_owned());
        let rendered = format!("{:?}", parse(&env).expect("valid"));

        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("anthropic"), "{rendered}");
    }

    #[test]
    fn every_required_variable_fails_the_boot_by_name() {
        for var in [
            "PUBLIC_HOST",
            "AGENT_EMAIL_DOMAIN",
            "DATABASE_URL",
            "AGENTOS_MASTER_KEY",
        ] {
            let mut env = complete();
            env.remove(var);

            let err = parse(&env).expect_err("{var} must be required");
            assert!(
                matches!(err, ConfigError::Missing { var: missing } if missing == var),
                "removing {var} produced {err:?}"
            );
            // The operator has to be able to act on the message alone.
            assert!(err.to_string().contains(var), "{err}");
        }
    }

    #[test]
    fn an_exported_but_empty_variable_counts_as_missing() {
        // `export DATABASE_URL=` is the most common way to "set" a variable to
        // nothing, and it must not read as configured.
        let mut env = complete();
        env.insert("DATABASE_URL", "   ".to_owned());

        assert!(matches!(
            parse(&env),
            Err(ConfigError::Missing {
                var: "DATABASE_URL"
            })
        ));
    }

    #[test]
    fn optional_variables_have_defaults() {
        let mut env = complete();
        env.remove("APP_BIND");
        env.remove("RUST_LOG");
        env.remove("AGENTOS_API_KEYS");

        let config = parse(&env).expect("the optional ones are optional");
        assert_eq!(config.bind.to_string(), DEFAULT_BIND);
        assert_eq!(config.rust_log, DEFAULT_RUST_LOG);
        assert!(config.api_keys.is_empty(), "and it authenticates nobody");
    }

    #[test]
    fn a_mock_adapter_refuses_to_boot_without_permission() {
        let mut env = complete();
        env.remove("EMAIL_API_KEY");

        let err = parse(&env).expect_err("a mock email adapter must not start silently");
        let ConfigError::MocksNotAllowed { adapters, vars, .. } = &err else {
            panic!("expected MocksNotAllowed, got {err:?}");
        };
        assert_eq!(adapters, "email");
        assert_eq!(vars, "EMAIL_API_KEY");
        assert!(err.to_string().contains("AGENTOS_ALLOW_MOCKS"), "{err}");
    }

    #[test]
    fn every_adapter_is_guarded_not_just_the_first() {
        // The guard is only worth anything if it covers the whole list; a
        // deployment that forgets the browser key is the same outage as one
        // that forgets email. (The model is guarded separately, above.)
        for (adapter, var, _) in PROVIDER_CREDENTIALS {
            let mut env = complete();
            env.remove(var);

            let err = parse(&env).expect_err("{adapter} must be guarded");
            assert!(
                matches!(&err, ConfigError::MocksNotAllowed { adapters, .. } if adapters == adapter),
                "{adapter} is not guarded: {err:?}"
            );
        }
    }

    #[test]
    fn allowing_mocks_is_explicit_and_recorded() {
        let mut env = complete();
        env.remove("EMAIL_API_KEY");
        env.insert("AGENTOS_LLM", "mock".to_owned());
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());

        let config = parse(&env).expect("explicitly allowed");
        assert!(config.allow_mocks);
        assert_eq!(
            config.mock_adapters,
            vec!["email", "llm (scripted mock)"],
            "the warning has to name every fake, the model included"
        );
        // Which is what `warn_about_mocks` shouts about on every boot.
        config.warn_about_mocks();
    }

    #[test]
    fn a_bad_bind_address_fails_the_boot() {
        let mut env = complete();
        env.insert("APP_BIND", "not-an-address".to_owned());

        assert!(matches!(
            parse(&env),
            Err(ConfigError::Invalid {
                var: "APP_BIND",
                ..
            })
        ));
    }

    #[test]
    fn webhook_registrations_are_optional_and_validated() {
        let mut env = complete();
        assert!(
            parse(&env).expect("valid").webhooks.is_empty(),
            "an unset registry registers nobody"
        );

        env.insert(
            "AGENTOS_WEBHOOK_SECRETS",
            format!("email:{TENANT}:whsec_has:colons:in:it"),
        );
        let config = parse(&env).expect("valid");
        assert_eq!(config.webhooks.len(), 1);
        assert_eq!(config.webhooks[0].provider, "email");
        assert_eq!(config.webhooks[0].tenant_id.as_uuid().to_string(), TENANT);
        assert_eq!(config.webhooks[0].secret, "whsec_has:colons:in:it");
        // And the secret is not in the Debug rendering.
        assert!(!format!("{config:?}").contains("whsec_"));

        for bad in ["email", &format!("email:not-a-uuid:{SECRET}")] {
            env.insert("AGENTOS_WEBHOOK_SECRETS", bad.to_owned());
            assert!(matches!(
                parse(&env),
                Err(ConfigError::WebhookEntry { index: 0 })
            ));
        }
    }

    /// **Two tenants cannot share one provider path, and the boot has to say so
    /// rather than pick one.**
    ///
    /// `routes::webhooks` keys its registry on the `{provider}` path segment and
    /// nothing else, and `main::webhooks` builds it by collecting into a
    /// `HashMap` — so a second `email:` registration silently replaces the
    /// first. Nothing anywhere reports it. What an operator gets is a
    /// deployment where one customer's inbound mail is verified against the
    /// other customer's signing secret and refused as a forgery, or — when the
    /// two tenants are behind one provider account and therefore one secret —
    /// **accepted and filed against the wrong tenant**, where
    /// `inbound::resolve_recipient` matches the address's local part inside
    /// that tenant. Two customers who both hired a `sales` is not a corner
    /// case; it is the first two customers.
    ///
    /// The registry cannot hold two, so the honest thing at boot is to refuse.
    /// The real fix is the `webhook_endpoints` table `routes::webhooks`'
    /// ponytail note already sketches, with the tenant in the *path* so the two
    /// deliveries never arrive at the same endpoint. Until that exists, a
    /// deployment that would have silently mis-delivered does not start.
    #[test]
    fn two_registrations_for_one_provider_refuse_the_boot() {
        const OTHER: &str = "00000000-0000-0000-0000-000000000002";
        let mut env = complete();
        env.insert(
            "AGENTOS_WEBHOOK_SECRETS",
            format!("email:{TENANT}:{SECRET},email:{OTHER}:{SECRET}"),
        );

        let err = parse(&env).expect_err(
            "two tenants registered on one provider path: the registry keeps one of them and \
             the other tenant's mail is either refused as a forgery or filed against the wrong \
             company",
        );
        assert!(matches!(
            err,
            ConfigError::WebhookProviderTwice { ref provider } if provider == "email"
        ));
        // The message names the provider and the remedy, because the value it
        // is about holds two signing secrets and cannot be printed.
        let said = err.to_string();
        assert!(said.contains("email"), "{said}");
        assert!(!said.contains(SECRET), "{said}");

        // Two *different* providers are the ordinary deployment and still boot.
        env.insert(
            "AGENTOS_WEBHOOK_SECRETS",
            format!("email:{TENANT}:{SECRET},telephony:{TENANT}:{SECRET}"),
        );
        assert_eq!(parse(&env).expect("valid").webhooks.len(), 2);
    }

    #[test]
    fn a_malformed_keyring_fails_the_boot() {
        let mut env = complete();
        env.insert("AGENTOS_API_KEYS", "ops:not-a-uuid:short".to_owned());

        assert!(matches!(
            parse(&env),
            Err(ConfigError::Invalid {
                var: "AGENTOS_API_KEYS",
                ..
            })
        ));
    }

    #[test]
    fn debug_does_not_print_secrets() {
        let mut env = complete();
        env.insert("AGENTOS_MASTER_KEY", "hunter2-the-real-key".to_owned());
        let config = parse(&env).expect("valid");

        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("agents.example.com"), "{rendered}");
    }
}
