//! **Whose model the tenant thinks with, and by what path** — a resource the
//! tenant owns, deliberately not a policy field.
//!
//! # Why this is not in [`PolicyLimits`]
//!
//! [`PolicyLimits::allowed_models`] already exists and already answers a
//! question about models, so the cheap move would have been one more field
//! beside it. It is the wrong move, and the reason is what a policy field *is*:
//! something that intersects across platform ∧ tenant ∧ role ∧ employee, where
//! empty denies and a lower layer can only narrow. Run this shape over "by what
//! path does this tenant reach a model" and every part of it reads wrong:
//!
//! * **There is nothing to intersect.** `{ApiKey} ∧ {Cli}` is the empty set, and
//!   the empty set means *deny* everywhere else in [`PolicyLimits`]. So a
//!   platform layer saying "API key" and a tenant saying "CLI" would produce a
//!   tenant that cannot think at all — not because anybody withheld anything but
//!   because two layers described the same tenant's plumbing differently.
//! * **A narrowing has no meaning here.** A role layer cannot sensibly say "this
//!   seat reaches the model by a *narrower* path than the tenant does". There is
//!   one path per tenant, because there is one credential per tenant.
//! * **Policy is written by an operator; this is stamped by the system.**
//!   [`ModelAccess::verified_at`] is a fact we observed by making a call. An
//!   operator cannot type it, and a layer document that could would be a
//!   document that asserts a key works.
//!
//! So it is a row the tenant owns, and since
//! `migrations/0050_tenant_model_key.sql` the credential is a sealed column on
//! that same row rather than an entry in a store somewhere else. There is no
//! pointer at all — not a stored one and not a derived one — which is the
//! strongest form of "no column anybody can edit to make one tenant's row reach
//! another tenant's key". The AES-GCM additional data is the tenant's own id, so
//! a blob moved between rows decrypts to nothing.
//!
//! # What this deliberately cannot do
//!
//! **It cannot widen [`PolicyLimits::allowed_models`].** Not "it is checked not
//! to" — it has no path to. [`ModelAccess`] holds a [`ModelId`] and that field
//! is the model whose reachability *was proven with this credential*, which is a
//! fact about the key and not a permission. Which model a turn actually runs is
//! still [`model_for`] over the four intersected layers, and it is the only
//! answer to that question in the workspace. A tenant that connects a key for
//! Opus under a policy that permits only Haiku runs Haiku — see
//! `agentos_app::model_access` for what that costs.
//!
//! [`PolicyLimits`]: crate::policy::PolicyLimits
//! [`PolicyLimits::allowed_models`]: crate::policy::PolicyLimits::allowed_models
//! [`model_for`]: crate::policy::model_for

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::ModelId;

// ---------------------------------------------------------------------------
// The path
// ---------------------------------------------------------------------------

/// How this tenant's employees reach a model.
///
/// Two variants and no third, because there are exactly two things a customer
/// can hand us: a credential, or a machine that already holds one. A `Mock`
/// variant is deliberately absent — a deployment's fake model is a property of
/// the deployment (`AGENTOS_LLM`), and putting it here would let a *tenant* row
/// assert that a tenant connected something when nobody did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPath {
    /// The tenant pasted an Anthropic API key. **Their key pays**, which is the
    /// whole commercial promise, so this is the path production is about.
    ApiKey,
    /// The tenant runs the model from the host this deployment sits on — the
    /// local `claude` CLI, logged in as them.
    ///
    /// See [`ModelPath::is_host`]: this path spends *whatever the host has*, so
    /// a deployment whose own backend is an API key we pay for must refuse it.
    Cli,
}

impl ModelPath {
    /// Both paths, for a caller that has to enumerate them.
    pub const ALL: [ModelPath; 2] = [ModelPath::ApiKey, ModelPath::Cli];

    /// The `path` column, verbatim.
    pub const fn as_str(self) -> &'static str {
        match self {
            ModelPath::ApiKey => "api_key",
            ModelPath::Cli => "cli",
        }
    }

    /// The inverse. `None` for anything else — a column naming a path this
    /// build does not know is a load failure, never a silently dropped row.
    pub fn parse(raw: &str) -> Option<Self> {
        ModelPath::ALL.into_iter().find(|p| p.as_str() == raw)
    }

    /// Does this path spend the *host's* model rather than the tenant's own
    /// credential?
    ///
    /// The one branch that keeps the founder's rule — we never provide the
    /// model — enforceable in code rather than in a paragraph: a host whose own
    /// backend is a key we hold must refuse this path, because a turn on it
    /// would be billed to us.
    pub const fn is_host(self) -> bool {
        matches!(self, ModelPath::Cli)
    }

    /// Whether a credential has to be supplied to connect this path.
    pub const fn needs_secret(self) -> bool {
        matches!(self, ModelPath::ApiKey)
    }
}

impl std::fmt::Display for ModelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------

/// A tenant's model connection, as it was proven.
///
/// There is **no key in here and no way to put one in**, and no pointer to one
/// either. `Serialize` is therefore safe on the whole struct, which is what lets
/// it be an HTTP response body without a second "public view" type that somebody
/// has to remember to keep in sync.
///
/// The sealed credential travels beside it in
/// `agentos_store::model_access::Connection`, which is deliberately *not*
/// `Serialize` — the split is what makes "the credential cannot reach a response
/// body" a fact about the types rather than a rule four handlers follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAccess {
    /// API key or host CLI.
    pub path: ModelPath,
    /// **The model this credential was proven to reach**, and nothing more.
    ///
    /// Not a permission and not an override: what a turn runs is still
    /// [`model_for`](crate::policy::model_for) over the four policy layers. It
    /// is here so an operator can see which model the one verification call
    /// actually asked for, because proving one model proves nothing about the
    /// other three.
    pub model: ModelId,
    /// When the verification call returned success. A fact we observed, which
    /// is why no operator document can contain it.
    pub verified_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// What one verification call proved.
///
/// A closed enum and not a message, for the reason
/// [`DenyReason`](crate::policy::DenyReason) is one: these become the thing a
/// person sees in a five-minute setup flow and the label on a metric, and a
/// free-form string is both a cardinality bomb and — here — a place a provider's
/// own text could be pasted into a response beside a credential we just handled.
///
/// Every variant except [`Verdict::Connected`] means **nothing was stored**.
/// The key is dropped, the row is not written, and the tenant is still
/// unconnected. That is the direction that cannot go wrong: a stored credential
/// nobody proved is a credential that fails at go-live, which is the exact
/// failure moving verification to connect-time exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The call returned a completion. The credential works, on this model,
    /// right now.
    Connected,
    /// 401 or 403. The key is wrong, revoked, or from another vendor.
    KeyRefused,
    /// A 404: the key is real and this model is not on it — a workspace without
    /// access, or a model name this account cannot address.
    ModelNotAccessible,
    /// A 4xx that is neither of the above. The commonest by a distance is an
    /// exhausted credit balance, which the provider returns as a 400.
    Unusable,
    /// A timeout, a 429 or a 5xx. **Says nothing about the credential** — it is
    /// the one verdict that means "ask again", and the reason nothing is stored
    /// on it is that we did not learn anything to store.
    Unreachable,
}

impl Verdict {
    /// Classify one attempt from the provider error's own code.
    ///
    /// Takes the code rather than the error because this crate has no
    /// `agentos-providers` dependency and will not be growing one — the
    /// classification is a rule, the transport is not. `agentos_app` supplies
    /// `ProviderError::code()`, which is already the stable low-cardinality
    /// label this needs.
    ///
    /// The catch-all is [`Verdict::Unusable`] rather than
    /// [`Verdict::Unreachable`]: a code this build does not recognise came from
    /// a terminal branch of `ProviderError::from_status`, and telling somebody
    /// to retry a 402 forever is worse than telling them their key did not work.
    pub fn from_provider_code(code: &str) -> Self {
        match code {
            "unauthorized" | "forbidden" => Verdict::KeyRefused,
            "not_found" => Verdict::ModelNotAccessible,
            "retryable" | "rate_limited" | "timeout" => Verdict::Unreachable,
            _ => Verdict::Unusable,
        }
    }

    /// Did this connect the tenant?
    pub const fn is_connected(self) -> bool {
        matches!(self, Verdict::Connected)
    }

    /// Stable, low-cardinality metric label.
    pub const fn code(self) -> &'static str {
        match self {
            Verdict::Connected => "connected",
            Verdict::KeyRefused => "key_refused",
            Verdict::ModelNotAccessible => "model_not_accessible",
            Verdict::Unusable => "unusable",
            Verdict::Unreachable => "unreachable",
        }
    }

    /// The sentence a person setting this up in five minutes reads.
    ///
    /// Ours, fixed, and containing nothing the provider sent back — a
    /// verification response is the one place in this system where a credential
    /// has just been in the same function as an error body.
    pub const fn explain(self) -> &'static str {
        match self {
            Verdict::Connected => {
                "connected: the key answered on this model, and nothing else was needed"
            }
            Verdict::KeyRefused => {
                "the provider refused this key. Check it at console.anthropic.com -> API keys; \
                 keys begin `sk-ant-`. Nothing was stored"
            }
            Verdict::ModelNotAccessible => {
                "the key is valid and this model is not available on it. Pick another model, or \
                 ask whoever owns the Anthropic workspace to grant it. Nothing was stored"
            }
            Verdict::Unusable => {
                "the key reached the provider and the call was refused. The usual cause is an \
                 empty credit balance on the account the key belongs to. Nothing was stored"
            }
            Verdict::Unreachable => {
                "the provider did not answer in time, or asked us to slow down. This says nothing \
                 about the key — try again. Nothing was stored"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::policy::{EffectivePolicy, PolicyLimits, model_for};

    #[test]
    fn a_path_round_trips_through_its_column_and_an_unknown_one_is_refused() {
        for path in ModelPath::ALL {
            assert_eq!(ModelPath::parse(path.as_str()), Some(path));
            assert_eq!(path.to_string(), path.as_str());
        }
        assert_eq!(ModelPath::parse("bedrock"), None);
        assert_eq!(ModelPath::parse(""), None);

        // The two properties the rest of the system branches on.
        assert!(ModelPath::Cli.is_host());
        assert!(!ModelPath::ApiKey.is_host());
        assert!(ModelPath::ApiKey.needs_secret());
        assert!(!ModelPath::Cli.needs_secret());
    }

    #[test]
    fn every_provider_code_lands_somewhere_and_only_a_success_connects() {
        for (code, expected) in [
            ("unauthorized", Verdict::KeyRefused),
            ("forbidden", Verdict::KeyRefused),
            ("not_found", Verdict::ModelNotAccessible),
            ("retryable", Verdict::Unreachable),
            ("rate_limited", Verdict::Unreachable),
            ("bad_request", Verdict::Unusable),
            ("invalid_response", Verdict::Unusable),
            ("something_new", Verdict::Unusable),
        ] {
            assert_eq!(Verdict::from_provider_code(code), expected, "{code}");
            assert!(!Verdict::from_provider_code(code).is_connected());
        }

        // Distinct codes, and no explanation leaks a provider's own words.
        let codes: BTreeSet<&str> = [
            Verdict::Connected,
            Verdict::KeyRefused,
            Verdict::ModelNotAccessible,
            Verdict::Unusable,
            Verdict::Unreachable,
        ]
        .into_iter()
        .map(Verdict::code)
        .collect();
        assert_eq!(codes.len(), 5);
        for verdict in [
            Verdict::KeyRefused,
            Verdict::ModelNotAccessible,
            Verdict::Unusable,
            Verdict::Unreachable,
        ] {
            assert!(
                verdict.explain().contains("Nothing was stored"),
                "{}",
                verdict.code()
            );
        }
    }

    /// **The structural claim this whole module rests on.**
    ///
    /// A connection names a model. If that name could reach the policy layers,
    /// a tenant would be able to grant themselves a model an operator withheld
    /// simply by pasting a key for it. It cannot, and this is what says so: the
    /// intersected allowlist is built from four `PolicyLimits`, `ModelAccess` is
    /// not one of them and has no `From` into one, and `model_for` reads nothing
    /// else.
    #[test]
    fn a_connection_naming_a_model_does_not_put_it_in_the_allowlist() {
        let connected = ModelAccess {
            path: ModelPath::ApiKey,
            model: ModelId::Fable5,
            verified_at: Utc::now(),
        };

        // An operator who permits exactly one model, and it is not that one.
        let ceiling = PolicyLimits {
            allowed_models: [ModelId::Haiku45].into_iter().collect(),
            ..PolicyLimits::default()
        };
        let policy =
            EffectivePolicy::try_new(&ceiling, &ceiling, &ceiling, &ceiling).expect("coherent");

        assert_eq!(policy.limits().allowed_models.len(), 1);
        assert!(!policy.limits().allowed_models.contains(&connected.model));
        // The seat asked for the model the tenant proved. It runs the one the
        // operator permitted, and the fallback goes *down* the price list.
        assert_eq!(
            model_for(Some(&policy), connected.model),
            Some(ModelId::Haiku45)
        );

        // And an operator who permits nothing still permits nothing.
        let nothing =
            EffectivePolicy::try_new(&PolicyLimits::default(), &ceiling, &ceiling, &ceiling)
                .expect("coherent");
        assert_eq!(model_for(Some(&nothing), connected.model), None);
    }
}
