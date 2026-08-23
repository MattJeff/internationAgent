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

use std::fmt;
use std::net::SocketAddr;

use agentos_domain::ids::TenantId;

use crate::auth::{ApiKeys, ApiKeysError};

/// Where the listener binds when `APP_BIND` is unset.
const DEFAULT_BIND: &str = "0.0.0.0:8080";

/// Tracing filter when `RUST_LOG` is unset.
const DEFAULT_RUST_LOG: &str = "info,agentos_server=debug";

/// The adapters that can run as mocks, and the variable that makes each one
/// real.
///
/// **This array is the definition of "is anything mocked?".** Adding a
/// provider means adding a row here; forgetting to means the new provider can
/// ship to production as a mock, which is the exact failure this guard exists
/// for.
const PROVIDER_CREDENTIALS: [(&str, &str); 5] = [
    ("email", "EMAIL_API_KEY"),
    ("telephony", "TELEPHONY_API_KEY"),
    ("browser", "BROWSER_API_KEY"),
    ("llm", "LLM_API_KEY"),
    ("embedder", "EMBEDDER_API_KEY"),
];

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

    /// Mock adapters were configured without an explicit blessing.
    #[error(
        "refusing to start: {adapters} would run as mocks (set {vars} to use the real thing, \
         or AGENTOS_ALLOW_MOCKS=1 if this is a development box)"
    )]
    MocksNotAllowed {
        /// Comma-separated adapter names.
        adapters: String,
        /// Comma-separated credential variable names.
        vars: String,
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
    // Read by the secrets unit, not by this one; without the allow, the boot
    // guard that makes it *required* would be deleted as dead code.
    #[allow(dead_code)]
    pub master_key: String,
    /// `AGENTOS_ALLOW_MOCKS` — `1`/`true` permits mock adapters.
    pub allow_mocks: bool,
    /// `RUST_LOG` — the tracing filter.
    pub rust_log: String,
    /// `AGENTOS_API_KEYS` — the keyring. See [`crate::auth`].
    pub api_keys: ApiKeys,
    /// Adapters that will run as mocks in this process, derived from
    /// [`PROVIDER_CREDENTIALS`].
    pub mock_adapters: Vec<&'static str>,
    /// `AGENTOS_WEBHOOK_SECRETS` — which provider callbacks this deployment
    /// accepts, and whose. Empty means every `/v1/webhooks/{provider}` is a
    /// 404, which is the right answer for a deployment that has integrated
    /// nobody.
    pub webhooks: Vec<WebhookRegistration>,
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
            .field("rust_log", &self.rust_log)
            .field(
                "api_keys",
                &format_args!("{} configured", self.api_keys.len()),
            )
            .field("mock_adapters", &self.mock_adapters)
            .field(
                "webhooks",
                &self
                    .webhooks
                    .iter()
                    .map(|hook| hook.provider.as_str())
                    .collect::<Vec<_>>(),
            )
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

        let allow_mocks = matches!(
            get("AGENTOS_ALLOW_MOCKS").unwrap_or_default().as_str(),
            "1" | "true" | "yes"
        );
        let mock_adapters = PROVIDER_CREDENTIALS
            .iter()
            .filter(|(_, var)| get(var).is_none())
            .map(|(adapter, _)| *adapter)
            .collect::<Vec<_>>();

        if !mock_adapters.is_empty() && !allow_mocks {
            return Err(ConfigError::MocksNotAllowed {
                adapters: mock_adapters.join(", "),
                vars: PROVIDER_CREDENTIALS
                    .iter()
                    .filter(|(adapter, _)| mock_adapters.contains(adapter))
                    .map(|(_, var)| *var)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }

        let webhooks = parse_webhooks(&get("AGENTOS_WEBHOOK_SECRETS").unwrap_or_default())?;

        Ok(Self {
            bind,
            public_host,
            agent_email_domain,
            database_url,
            master_key,
            allow_mocks,
            rust_log: get("RUST_LOG").unwrap_or_else(|| DEFAULT_RUST_LOG.to_owned()),
            api_keys,
            mock_adapters,
            webhooks,
        })
    }

    /// Say, loudly and every time, what is not real.
    ///
    /// Called after the subscriber is installed, which is why it is not part
    /// of [`Config::parse`] — a warning emitted before tracing is up goes
    /// nowhere, and this one is the whole point.
    pub fn warn_about_mocks(&self) {
        if !self.mock_adapters.is_empty() {
            tracing::warn!(
                adapters = %self.mock_adapters.join(", "),
                "RUNNING WITH MOCK ADAPTERS — these providers do nothing real. \
                 AGENTOS_ALLOW_MOCKS is set; unset it in any environment that matters."
            );
        }
        if self.api_keys.is_empty() {
            tracing::warn!(
                "AGENTOS_API_KEYS is empty: every request will be answered 401. \
                 Set it to `label:tenant-uuid:secret[,…]`."
            );
        }
        if self.webhooks.is_empty() {
            tracing::warn!(
                "AGENTOS_WEBHOOK_SECRETS is empty: every provider callback will be answered \
                 404 and no inbound message can arrive. Set it to \
                 `provider:tenant-uuid:signing-secret[,…]`."
            );
        }
    }
}

/// `provider:tenant-uuid:secret,…`, the same shape as the keyring next door so
/// there is one format to learn rather than two.
///
/// An empty string is a valid, empty registry.
fn parse_webhooks(raw: &str) -> Result<Vec<WebhookRegistration>, ConfigError> {
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
        ]);
        for (_, var) in PROVIDER_CREDENTIALS {
            env.insert(var, "live-credential".to_owned());
        }
        env
    }

    fn parse(env: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::parse(|var| env.get(var).cloned())
    }

    #[test]
    fn a_complete_environment_boots() {
        let config = parse(&complete()).expect("a complete environment is enough");

        assert_eq!(config.bind.port(), 9000);
        assert_eq!(config.agent_email_domain, "agents.example.com");
        assert_eq!(config.rust_log, "debug");
        assert!(config.mock_adapters.is_empty());
        assert_eq!(config.api_keys.len(), 1);
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
        let ConfigError::MocksNotAllowed { adapters, vars } = &err else {
            panic!("expected MocksNotAllowed, got {err:?}");
        };
        assert_eq!(adapters, "email");
        assert_eq!(vars, "EMAIL_API_KEY");
        assert!(err.to_string().contains("AGENTOS_ALLOW_MOCKS"), "{err}");
    }

    #[test]
    fn every_adapter_is_guarded_not_just_the_first() {
        // The guard is only worth anything if it covers the whole list; a
        // deployment that forgets the LLM key is the same outage.
        for (adapter, var) in PROVIDER_CREDENTIALS {
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
        env.remove("LLM_API_KEY");
        env.insert("AGENTOS_ALLOW_MOCKS", "1".to_owned());

        let config = parse(&env).expect("explicitly allowed");
        assert!(config.allow_mocks);
        assert_eq!(config.mock_adapters, vec!["email", "llm"]);
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
