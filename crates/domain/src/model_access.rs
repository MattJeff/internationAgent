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
//! So it is a row the tenant owns, beside its secrets, and the two are kept
//! together on purpose: [`ModelAccess::secret_ref`] derives the pointer rather
//! than storing it, so there is no column anybody can edit to make one tenant's
//! row point at another tenant's key.
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
use uuid::Uuid;

use crate::ids::{EmployeeId, SecretRef, SecretRefError, TenantId};
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

/// The name every tenant's model credential is stored under.
///
/// A constant rather than a column: a stored pointer is a stored mistake, and
/// the mistake it invites is one tenant's row pointing at another tenant's
/// secret. Derived from the tenant id it belongs to, it cannot.
pub const MODEL_SECRET_NAME: &str = "tenant-model-key";

/// A tenant's model connection, as it was proven.
///
/// There is **no key in here and no way to put one in**: the credential lives
/// in the secret store and this names where. `Serialize` is therefore safe on
/// the whole struct, which is what lets it be an HTTP response body without a
/// second "public view" type that somebody has to remember to keep in sync.
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

impl ModelAccess {
    /// Where this tenant's model credential lives.
    ///
    /// The employee segment is the nil UUID, and that is load-bearing twice
    /// over. No employee has the nil id, so
    /// [`SecretStore::delete_prefix`](../../agentos_providers/secrets/trait.SecretStore.html)
    /// with `Some(employee)` — offboarding — can never take the tenant's model
    /// key with it, while `None` — tenant deletion — still does. And
    /// `agentos_app::secrets::SecretResolver` compares a ref against the acting
    /// principal, so an *employee* asking for this ref is refused and audited:
    /// no seat can read the company's model key, only the connect path can,
    /// and that one acts as the tenant.
    pub fn secret_ref(tenant_id: TenantId) -> Result<SecretRef, SecretRefError> {
        SecretRef::new(
            tenant_id,
            EmployeeId::from_uuid(Uuid::nil()),
            MODEL_SECRET_NAME,
        )
    }
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

    fn tenant() -> TenantId {
        TenantId::new_v7(Utc::now())
    }

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

    /// The ref is a pure function of the tenant, and no employee can be in it.
    #[test]
    fn the_secret_ref_is_derived_and_lands_outside_every_employee_subtree() {
        let (a, b) = (tenant(), tenant());
        let mine = ModelAccess::secret_ref(a).unwrap();

        assert_eq!(mine, ModelAccess::secret_ref(a).unwrap());
        assert_ne!(mine, ModelAccess::secret_ref(b).unwrap());
        assert_eq!(mine.tenant_id(), a);
        assert_eq!(mine.name(), MODEL_SECRET_NAME);
        // Nil, so `delete_prefix(tenant, Some(employee))` can never match it:
        // `EmployeeId::new_v7` cannot produce the nil uuid.
        assert_eq!(mine.employee_id().as_uuid(), Uuid::nil());
        assert!(mine.to_string().starts_with(&format!(
            "secret://tenant/{a}/employee/00000000-0000-0000-0000-000000000000/"
        )));
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
