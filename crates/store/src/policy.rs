//! Reading the policy an employee runs under out of Postgres.
//!
//! The gate used to be handed a `PolicyBook` at construction: limits lived in a
//! Rust struct, so changing what an AI employee was allowed to spend meant a
//! redeploy, and an operator could not see the current answer at all. The rows
//! in `0006_policy.sql` are that struct, persisted; this module turns them back
//! into a [`EffectivePolicy`].
//!
//! Four layers, most restrictive wins:
//!
//! ```text
//! platform  (tenant_id IS NULL — the ceiling, writable only by an admin tx)
//!   ∧ tenant
//!     ∧ role
//!       ∧ employee
//! ```
//!
//! Two properties carry the whole design:
//!
//! * **A lower layer can only tighten.** The combination is
//!   [`EffectivePolicy::try_new`], which takes the minimum of every cap and the
//!   intersection of every allowlist. A tenant row saying `999_999` where the
//!   platform says `50_000` does not produce `999_999`; it produces `50_000`.
//!   There is no read path that skips that call — [`load`] is the only public
//!   reader, and it returns the intersected value, never the raw layers.
//! * **An absent layer inherits the layer above.** Not `PolicyLimits::default()`,
//!   which grants *nothing* and would make "the tenant did not write a role
//!   layer" mean "this employee may not send email". The layer above is
//!   substituted, and intersecting a layer with itself is a no-op.
//!
//! A stored policy that is not coherent fails here, loudly, with the layer named
//! — before it reaches the gate. `approval_above` above `max_per_transaction`
//! is a policy where the approval step can never fire, and the safe reading of
//! it is not "approve nothing", it is "this configuration is wrong, refuse to
//! run on it".

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use agentos_domain::action::{CallingCode, Domain, McpTool};
use agentos_domain::ids::{EmployeeId, Slug, TenantId};
use agentos_domain::message::Channel;
use agentos_domain::money::{Currency, Money};
use agentos_domain::policy::{EffectivePolicy, PolicyError, PolicyLimits, SpendLimits};
use thiserror::Error;
use uuid::Uuid;

use crate::db::{Db, StoreError, TenantTx};

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/// Which of the four layers a row belongs to.
///
/// The discriminants are the intersection order, and [`load`] indexes an array
/// with them, so they are not decorative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyLayer {
    /// The ceiling. Global, and no tenant transaction can write it.
    Platform = 0,
    Tenant = 1,
    Role = 2,
    Employee = 3,
}

impl PolicyLayer {
    /// The `layer` column's value, matching the CHECK constraint in
    /// `0006_policy.sql`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyLayer::Platform => "platform",
            PolicyLayer::Tenant => "tenant",
            PolicyLayer::Role => "role",
            PolicyLayer::Employee => "employee",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        [
            PolicyLayer::Platform,
            PolicyLayer::Tenant,
            PolicyLayer::Role,
            PolicyLayer::Employee,
        ]
        .into_iter()
        .find(|l| l.as_str() == raw)
    }
}

impl fmt::Display for PolicyLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the stored policy could not be turned into an enforceable one.
///
/// Every variant is a refusal to run. None of them degrades to "use the parts
/// that parsed": a policy assembled from the rows that happened to be readable
/// is a policy nobody wrote.
#[derive(Debug, Error)]
pub enum PolicyLoadError {
    /// No active platform version, or one with no platform layer. The ceiling
    /// is the one layer that has no layer above it to inherit from, so its
    /// absence is a misconfigured deployment rather than a permissive default.
    #[error("no active platform policy layer: there is no ceiling to enforce")]
    NoPlatformLayer,

    /// A column held something the domain cannot represent.
    #[error("{layer} policy layer (row {row}): {column} value {value:?} is unusable: {detail}")]
    Malformed {
        layer: PolicyLayer,
        row: Uuid,
        column: &'static str,
        value: String,
        detail: String,
    },

    /// The `layer` column held a value outside the four names. The CHECK
    /// constraint prevents it; this exists so a dropped constraint surfaces as
    /// an error instead of a silently ignored layer.
    #[error("policy layer row {row} names an unknown layer {found:?}")]
    UnknownLayer { row: Uuid, found: String },

    /// One layer's own limits contradict each other — most usefully, an
    /// approval threshold above the per-transaction cap, which is an approval
    /// step that can never fire.
    #[error("{layer} policy layer (row {row}) is incoherent: {source}")]
    Incoherent {
        layer: PolicyLayer,
        row: Uuid,
        #[source]
        source: PolicyError,
    },

    /// Each layer is coherent but they cannot be combined — layers denominated
    /// in different currencies, which has no answer short of an exchange rate.
    #[error("stored policy layers cannot be intersected: {source}")]
    Irreconcilable {
        #[source]
        source: PolicyError,
    },

    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for PolicyLoadError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// The active layers that apply to one employee: the platform ceiling plus
/// whatever this tenant's active version says about the tenant, the role and
/// the employee.
///
/// RLS already confines the tenant rows; the predicates are written out anyway
/// so the statement says what it means when read on its own.
///
/// The `coalesce` on the role layer is the org layer plugging in (0012_org):
/// an employee that belongs to a team takes that team's role name, and the
/// `role` argument is the fallback for an employee on no team. It is a
/// sub-select rather than a second query because this runs on the hot path of
/// every gate decision, and `team_memberships`' primary key is
/// `(tenant_id, employee_id)`, so it is one index lookup. That key is also what
/// makes the sub-select single-valued: an employee is on at most one team, so
/// there is never a coin-flip between two teams' limits.
const SELECT_ACTIVE_LAYERS: &str = "\
    SELECT l.id, l.layer, l.spend_currency, l.max_per_transaction_minor, \
           l.max_per_day_minor, l.approval_above_minor, l.allowed_channels, \
           l.allowed_calling_codes, l.allowed_domains, l.denied_domains, \
           l.allowed_mcp_tools, l.allowed_a2a_peers, l.max_new_contacts_per_day, \
           l.max_turns_per_day, \
           l.allow_file_upload, l.allow_credential_change, l.allow_data_delete \
    FROM policy_layers l \
    JOIN policy_versions v ON v.id = l.version_id \
    WHERE v.active AND ( \
          (l.layer = 'platform' AND v.tenant_id IS NULL) \
       OR (l.layer = 'tenant'   AND v.tenant_id = $1) \
       OR (l.layer = 'role'     AND v.tenant_id = $1 AND l.role_name = coalesce(( \
              SELECT tp.role_name FROM team_memberships m \
                JOIN team_policy tp \
                  ON tp.tenant_id = m.tenant_id AND tp.team_id = m.team_id \
               WHERE m.tenant_id = $1 AND m.employee_id = $3), $2)) \
       OR (l.layer = 'employee' AND v.tenant_id = $1 AND l.employee_id = $3))";

/// Load and intersect the policy for one employee.
///
/// The role layer is the employee's **team**, when it has one: `store::org`
/// records which role name a team's limits are written under, and the statement
/// above resolves it in the same round trip. `role` is the fallback for an
/// employee on no team — there is no role model in the domain, so the caller
/// names it. Either way an unmatched role is simply an absent layer, which
/// inherits the tenant's; a team that nobody wrote limits for does not become a
/// team that may do nothing.
///
/// A team layer can therefore only ever *tighten*: it goes through
/// [`EffectivePolicy::try_new`] like every other layer, which takes the minimum
/// of each cap, so a team naming a bigger number than its tenant gets the
/// tenant's.
///
/// The tenant is not a parameter: it comes from `tx`, which is the only thing
/// row-level security honours anyway.
pub async fn load(
    tx: &mut TenantTx<'_>,
    employee_id: EmployeeId,
    role: Option<&str>,
) -> Result<EffectivePolicy, PolicyLoadError> {
    let rows: Vec<LayerRow> = sqlx::query_as(SELECT_ACTIVE_LAYERS)
        .bind(tx.tenant_id().as_uuid())
        .bind(role)
        .bind(employee_id.as_uuid())
        .fetch_all(&mut ***tx)
        .await?;

    // At most one row per layer: `policy_layers_scope_key` is unique per
    // (version, layer, scope) and exactly one version per scope is active.
    let mut found: [Option<PolicyLimits>; 4] = [const { None }; 4];
    for row in rows {
        let (layer, limits) = row.into_limits()?;
        found[layer as usize] = Some(limits);
    }
    let [platform, tenant, role_layer, employee] = found;

    // Inheritance: an absent layer is the layer above, not the empty layer.
    // `PolicyLimits::default()` grants nothing, so using it here would turn a
    // tenant that never wrote a role layer into a tenant that can do nothing.
    let platform = platform.ok_or(PolicyLoadError::NoPlatformLayer)?;
    let tenant = tenant.unwrap_or_else(|| platform.clone());
    let role_layer = role_layer.unwrap_or_else(|| tenant.clone());
    let employee = employee.unwrap_or_else(|| role_layer.clone());

    EffectivePolicy::try_new(&platform, &tenant, &role_layer, &employee)
        .map_err(|source| PolicyLoadError::Irreconcilable { source })
}

/// Make `version_id` this tenant's active policy version — the rollback verb.
///
/// Two statements rather than one `SET active = (id = $1)`: the partial unique
/// index that keeps "one active version" true is not deferrable, so a single
/// statement that both clears and sets can trip over itself depending on the
/// order Postgres visits the rows. Deactivate first, then activate.
///
/// Confined to this tenant's versions by RLS *and* by the WHERE clause; the
/// platform version is not a tenant's to activate.
pub async fn activate(tx: &mut TenantTx<'_>, version_id: Uuid) -> Result<(), StoreError> {
    let tenant = tx.tenant_id().as_uuid();

    sqlx::query("UPDATE policy_versions SET active = false WHERE tenant_id = $1 AND active")
        .bind(tenant)
        .execute(&mut ***tx)
        .await?;

    let switched =
        sqlx::query("UPDATE policy_versions SET active = true WHERE id = $1 AND tenant_id = $2")
            .bind(version_id)
            .bind(tenant)
            .execute(&mut ***tx)
            .await?
            .rows_affected();

    if switched == 0 {
        // Either it does not exist or it belongs to someone else; RLS makes
        // those indistinguishable on purpose.
        return Err(StoreError::NotFound);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing a layer
// ---------------------------------------------------------------------------

/// Which layer [`install`] is writing.
///
/// Not `platform`: the ceiling is not a scope anybody installs on purpose, it
/// is the one row [`install`] maintains for everybody. See its docs.
#[derive(Debug, Clone, Copy)]
pub enum Scope<'a> {
    /// The tenant's own layer.
    Tenant,
    /// A role layer, matched on `role_name` — which is what a team's
    /// `team_policy` row points at, so this is how a team gets limits.
    Role(&'a str),
    /// One employee's layer.
    Employee(EmployeeId),
}

/// The one platform ceiling [`install`] maintains. Fixed ids, because the
/// active platform version is a global singleton: concurrent callers have to
/// upsert the *same* row rather than race to be the one active version.
const CEILING_VERSION: Uuid = Uuid::from_u128(0x0006_0000_0000_7000_8000_0000_0000_0001);
const CEILING_LAYER: Uuid = Uuid::from_u128(0x0006_0000_0000_7000_8000_0000_0000_0002);

/// Write `limits` as one layer of `tenant_id`'s active policy version, under a
/// platform ceiling wide enough not to bind.
///
/// **This is fixture and bootstrap support, not an operator API.** There is no
/// route that writes `policy_layers` yet; when one lands it will write a *new*
/// version and activate it, because that is what makes a policy change
/// reversible, and this replaces a layer of the active one in place. What it is
/// for is the thing every test that touches [`crate::db::Db`] now needs: a
/// deployment with a policy in it, because the gate reads the stored one and
/// [`PolicyLoadError::NoPlatformLayer`] refuses everything.
///
/// # Why the ceiling is widened rather than written
///
/// There is exactly one active platform version per database
/// (`policy_versions_one_active_idx`), so callers cannot each have their own.
/// The row is therefore *unioned* with every `limits` installed through here:
/// the maximum of each cap, the concatenation of each allowlist, the OR of each
/// flag. That is safe in the only direction that matters — a wider ceiling
/// grants nothing on its own, because every caller also writes its own layer
/// and [`EffectivePolicy::try_new`] takes the minimum. It is also why
/// `denied_domains` is deliberately **not** unioned into the ceiling: denials
/// union rather than intersect, so one caller's block would become every
/// tenant's.
///
/// Concurrency-safe without a lock: the ceiling row is one row, and concurrent
/// upserts of it serialise on it.
pub async fn install(
    db: &Db,
    tenant_id: TenantId,
    scope: Scope<'_>,
    limits: &PolicyLimits,
) -> Result<(), StoreError> {
    let (layer, role_name, employee_id) = match scope {
        Scope::Tenant => (PolicyLayer::Tenant, None, None),
        Scope::Role(name) => (PolicyLayer::Role, Some(name), None),
        Scope::Employee(id) => (PolicyLayer::Employee, None, Some(id.as_uuid())),
    };

    // Saturating rather than failing: every cap here is smaller than i64::MAX by
    // eleven orders of magnitude in practice, and a saturated *ceiling* is
    // wider, never narrower, so it cannot silently tighten a limit either.
    let minor = |m: Money| i64::try_from(m.minor()).unwrap_or(i64::MAX);
    let (currency, per_txn, per_day, approval) =
        limits.spend.map_or((None, None, None, None), |s| {
            (
                Some(s.currency().code().to_owned()),
                Some(minor(s.max_per_transaction())),
                Some(minor(s.max_per_day())),
                Some(minor(s.approval_above())),
            )
        });
    let strings = |set: &BTreeSet<Domain>| set.iter().map(ToString::to_string).collect::<Vec<_>>();

    let mut tx = db.admin_tx_bypassing_rls().await?;

    // The ceiling. Anything else claiming to be the active platform version is
    // a leftover from a fixture that wrote one by hand; there is one ceiling.
    sqlx::query("DELETE FROM policy_versions WHERE tenant_id IS NULL AND id <> $1")
        .bind(CEILING_VERSION)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO policy_versions (id, tenant_id, label, active) \
         VALUES ($1, NULL, 'ceiling', true) ON CONFLICT DO NOTHING",
    )
    .bind(CEILING_VERSION)
    .execute(&mut *tx)
    .await?;

    // This tenant's active version, created on first use. A second layer for
    // the same tenant joins the version already there rather than starting a
    // rival one, which would leave two versions fighting over `active`.
    let version: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM policy_versions WHERE tenant_id = $1 AND active")
            .bind(tenant_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await?;
    let version = match version {
        Some(id) => id,
        None => {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO policy_versions (id, tenant_id, label, active) \
                 VALUES ($1, $2, 'installed', true)",
            )
            .bind(id)
            .bind(tenant_id.as_uuid())
            .execute(&mut *tx)
            .await?;
            id
        }
    };

    // Replace this scope's layer rather than add a second one: the unique index
    // is (version, layer, role, employee), so a second would be rejected, and
    // installing twice is what a fixture that re-seeds does.
    sqlx::query(
        "DELETE FROM policy_layers WHERE version_id = $1 AND layer = $2 \
           AND role_name IS NOT DISTINCT FROM $3 \
           AND employee_id IS NOT DISTINCT FROM $4",
    )
    .bind(version)
    .bind(layer.as_str())
    .bind(role_name)
    .bind(employee_id)
    .execute(&mut *tx)
    .await?;

    // Both rows in one statement, sharing one set of binds: the ceiling widens
    // on conflict, the scope row is a fresh id and simply inserts.
    sqlx::query(
        "INSERT INTO policy_layers \
           (id, version_id, tenant_id, layer, role_name, employee_id, \
            spend_currency, max_per_transaction_minor, max_per_day_minor, \
            approval_above_minor, allowed_channels, allowed_calling_codes, \
            allowed_domains, denied_domains, allowed_mcp_tools, allowed_a2a_peers, \
            max_new_contacts_per_day, max_turns_per_day, \
            allow_file_upload, allow_credential_change, allow_data_delete) \
         VALUES \
           ($1, $2, NULL, 'platform', NULL, NULL, \
            $9, $10, $11, $12, $13, $14, $15, '{}', $17, $18, $19, $20, $21, $22, $23), \
           ($3, $4, $5, $6, $7, $8, \
            $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) \
         ON CONFLICT (id) DO UPDATE SET \
           spend_currency = coalesce(policy_layers.spend_currency, excluded.spend_currency), \
           max_per_transaction_minor = \
             greatest(policy_layers.max_per_transaction_minor, excluded.max_per_transaction_minor), \
           max_per_day_minor = greatest(policy_layers.max_per_day_minor, excluded.max_per_day_minor), \
           approval_above_minor = \
             greatest(policy_layers.approval_above_minor, excluded.approval_above_minor), \
           allowed_channels = policy_layers.allowed_channels || excluded.allowed_channels, \
           allowed_calling_codes = \
             policy_layers.allowed_calling_codes || excluded.allowed_calling_codes, \
           allowed_domains = policy_layers.allowed_domains || excluded.allowed_domains, \
           allowed_mcp_tools = policy_layers.allowed_mcp_tools || excluded.allowed_mcp_tools, \
           allowed_a2a_peers = policy_layers.allowed_a2a_peers || excluded.allowed_a2a_peers, \
           max_new_contacts_per_day = \
             greatest(policy_layers.max_new_contacts_per_day, excluded.max_new_contacts_per_day), \
           max_turns_per_day = greatest(policy_layers.max_turns_per_day, excluded.max_turns_per_day), \
           allow_file_upload = policy_layers.allow_file_upload OR excluded.allow_file_upload, \
           allow_credential_change = \
             policy_layers.allow_credential_change OR excluded.allow_credential_change, \
           allow_data_delete = policy_layers.allow_data_delete OR excluded.allow_data_delete",
    )
    .bind(CEILING_LAYER)
    .bind(CEILING_VERSION)
    .bind(Uuid::now_v7())
    .bind(version)
    .bind(tenant_id.as_uuid())
    .bind(layer.as_str())
    .bind(role_name)
    .bind(employee_id)
    .bind(currency)
    .bind(per_txn)
    .bind(per_day)
    .bind(approval)
    .bind(
        limits
            .allowed_channels
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
    .bind(
        limits
            .allowed_calling_codes
            .iter()
            .map(|c| i32::from(c.as_u16()))
            .collect::<Vec<_>>(),
    )
    .bind(strings(&limits.allowed_domains))
    .bind(strings(&limits.denied_domains))
    .bind(
        limits
            .allowed_mcp_tools
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .bind(strings(&limits.allowed_a2a_peers))
    .bind(i32::try_from(limits.max_new_contacts_per_day).unwrap_or(i32::MAX))
    .bind(i32::try_from(limits.max_turns_per_day).unwrap_or(i32::MAX))
    .bind(limits.allow_file_upload)
    .bind(limits.allow_credential_change)
    .bind(limits.allow_data_delete)
    .execute(&mut *tx)
    .await?;

    // One deployment, one ceiling, therefore one spend currency — that is the
    // schema and the loader, not this function: layers in two currencies cannot
    // be intersected and `load` refuses them. Said out loud here because the
    // symptom otherwise is every action in the deployment being refused with
    // `broken_policy`, which reads like a bug in whatever was being tested.
    let ceiling: Option<String> =
        sqlx::query_scalar("SELECT spend_currency FROM policy_layers WHERE id = $1")
            .bind(CEILING_LAYER)
            .fetch_one(&mut *tx)
            .await?;
    if let (Some(ceiling), Some(mine)) = (ceiling.as_deref(), limits.spend.map(|s| s.currency()))
        && ceiling != mine.code()
    {
        return Err(StoreError::conflict(format!(
            "this deployment's policy ceiling is denominated in {ceiling} and these limits are in \
             {mine}: a policy in two currencies cannot be intersected"
        )));
    }

    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Row → domain
// ---------------------------------------------------------------------------

/// One `policy_layers` row, as Postgres hands it over.
///
/// Typed columns, not a jsonb blob: a misspelled key in a blob reads as "no
/// limit", and "no limit" is the widest possible reading of a spending cap.
/// Here a missing column is a schema error and a malformed value is a load
/// failure.
#[derive(sqlx::FromRow)]
struct LayerRow {
    id: Uuid,
    layer: String,
    spend_currency: Option<String>,
    max_per_transaction_minor: Option<i64>,
    max_per_day_minor: Option<i64>,
    approval_above_minor: Option<i64>,
    allowed_channels: Vec<String>,
    allowed_calling_codes: Vec<i32>,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    allowed_mcp_tools: Vec<String>,
    allowed_a2a_peers: Vec<String>,
    max_new_contacts_per_day: i32,
    max_turns_per_day: i32,
    allow_file_upload: bool,
    allow_credential_change: bool,
    allow_data_delete: bool,
}

impl LayerRow {
    fn into_limits(self) -> Result<(PolicyLayer, PolicyLimits), PolicyLoadError> {
        let row = self.id;
        let layer =
            PolicyLayer::parse(&self.layer).ok_or_else(|| PolicyLoadError::UnknownLayer {
                row,
                found: self.layer.clone(),
            })?;
        let at = |column: &'static str, value: &str, detail: String| PolicyLoadError::Malformed {
            layer,
            row,
            column,
            value: value.to_owned(),
            detail,
        };

        let spend = match (
            self.spend_currency.as_deref(),
            self.max_per_transaction_minor,
            self.max_per_day_minor,
            self.approval_above_minor,
        ) {
            // No spend columns: this layer permits no spending, which is
            // exactly what `spend: None` means in the domain.
            (None, None, None, None) => None,
            (Some(code), Some(per_txn), Some(per_day), Some(approval)) => {
                let currency = Currency::from_str(code)
                    .map_err(|e| at("spend_currency", code, e.to_string()))?;
                let money = |column, minor: i64| -> Result<Money, PolicyLoadError> {
                    let minor = u64::try_from(minor)
                        .map_err(|_| at(column, &minor.to_string(), "negative".to_owned()))?;
                    Money::new(minor, currency)
                        .map_err(|e| at(column, &minor.to_string(), e.to_string()))
                };
                let limits = SpendLimits::try_new(
                    money("max_per_transaction_minor", per_txn)?,
                    money("max_per_day_minor", per_day)?,
                    money("approval_above_minor", approval)?,
                )
                // The loud one: an approval threshold above the per-transaction
                // cap never reaches the gate.
                .map_err(|source| PolicyLoadError::Incoherent { layer, row, source })?;
                Some(limits)
            }
            // `policy_layers_spend_all_or_nothing` makes this unreachable, and
            // it stays an error rather than a partial policy if it is dropped.
            _ => {
                return Err(at(
                    "spend_currency",
                    self.spend_currency.as_deref().unwrap_or(""),
                    "spend limits are partially set".to_owned(),
                ));
            }
        };

        let domains = |column, raw: &[String]| parse_set(at, column, raw, Domain::parse);

        Ok((
            layer,
            PolicyLimits {
                spend,
                allowed_channels: parse_set(at, "allowed_channels", &self.allowed_channels, |s| {
                    Channel::ALL
                        .into_iter()
                        .find(|c| c.as_str() == s)
                        .ok_or("not a known channel")
                })?,
                allowed_calling_codes: self
                    .allowed_calling_codes
                    .iter()
                    .map(|code| {
                        u16::try_from(*code)
                            .map_err(|_| "out of range".to_owned())
                            .and_then(|c| CallingCode::new(c).map_err(|e| e.to_string()))
                            .map_err(|detail| {
                                at("allowed_calling_codes", &code.to_string(), detail)
                            })
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?,
                allowed_domains: domains("allowed_domains", &self.allowed_domains)?,
                denied_domains: domains("denied_domains", &self.denied_domains)?,
                allowed_mcp_tools: parse_set(
                    at,
                    "allowed_mcp_tools",
                    &self.allowed_mcp_tools,
                    parse_tool,
                )?,
                allowed_a2a_peers: domains("allowed_a2a_peers", &self.allowed_a2a_peers)?,
                // CHECKed non-negative in the schema; clamping a *budget* to
                // zero fails closed if it ever is not.
                max_new_contacts_per_day: u32::try_from(self.max_new_contacts_per_day).unwrap_or(0),
                // Same treatment, same reason: `policy_layers_turns_nonneg`
                // CHECKs it, and clamping a budget to zero fails closed — an
                // employee that does not wake, rather than one that never
                // stops.
                max_turns_per_day: u32::try_from(self.max_turns_per_day).unwrap_or(0),
                allow_file_upload: self.allow_file_upload,
                allow_credential_change: self.allow_credential_change,
                allow_data_delete: self.allow_data_delete,
            },
        ))
    }
}

/// Parse every element or fail. No element is skipped: a domain that does not
/// parse in `denied_domains` would be a block quietly dropped.
fn parse_set<T, E, F, M>(
    at: M,
    column: &'static str,
    raw: &[String],
    parse: F,
) -> Result<BTreeSet<T>, PolicyLoadError>
where
    T: Ord,
    E: fmt::Display,
    F: Fn(&str) -> Result<T, E>,
    M: Fn(&'static str, &str, String) -> PolicyLoadError,
{
    raw.iter()
        .map(|value| parse(value).map_err(|e| at(column, value, e.to_string())))
        .collect()
}

/// `"server/tool"`, the same shape [`McpTool`] displays as.
fn parse_tool(raw: &str) -> Result<McpTool, String> {
    let (server, name) = raw
        .split_once('/')
        .ok_or_else(|| "expected \"server/tool\"".to_owned())?;
    Ok(McpTool::new(
        Slug::parse(server).map_err(|e| e.to_string())?,
        Slug::parse(name).map_err(|e| e.to_string())?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::LazyLock;

    use agentos_domain::ids::TenantId;
    use agentos_domain::money::Currency::{Eur, Usd};
    use chrono::Utc;
    use sqlx::{Postgres, Transaction};
    use tokio::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::db::Db;

    /// The platform layer is global by construction, and exactly one version of
    /// it may be active. Tests that install one therefore cannot run
    /// concurrently.
    ///
    /// ponytail: a mutex, not a per-test schema. The serialised section is
    /// milliseconds of SQL; if this file ever grows enough tests for that to
    /// matter, give each test its own database instead.
    static PLATFORM: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the policy loader needs a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// What a test wants written into one `policy_layers` row. Everything the
    /// tests do not vary keeps its column default.
    #[derive(Default)]
    struct Row<'a> {
        tenant: Option<Uuid>,
        layer: &'a str,
        role: Option<&'a str>,
        employee: Option<Uuid>,
        /// `(max_per_transaction, max_per_day, approval_above)` in minor units —
        /// three bare numbers so a test can write an *incoherent* set, which
        /// `SpendLimits` cannot represent.
        spend: Option<(i64, i64, i64)>,
        currency: Option<&'a str>,
        domains: &'a [&'a str],
        contacts: i32,
        /// `max_turns_per_day`. Zero by default, like the column, which means
        /// a layer a test did not think about grants no turns.
        turns: i32,
    }

    async fn insert_version(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Option<Uuid>,
        label: &str,
        active: bool,
    ) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, label, active) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(tenant)
        .bind(label)
        .bind(active)
        .execute(&mut **tx)
        .await
        .expect("insert version");
        id
    }

    async fn insert_layer(tx: &mut Transaction<'_, Postgres>, version: Uuid, row: Row<'_>) {
        let (per_txn, per_day, approval) = match row.spend {
            Some((a, b, c)) => (Some(a), Some(b), Some(c)),
            None => (None, None, None),
        };
        let currency = row.currency.or(row.spend.map(|_| "USD"));
        let domains: Vec<String> = row.domains.iter().map(|d| (*d).to_owned()).collect();

        sqlx::query(
            "INSERT INTO policy_layers \
               (id, version_id, tenant_id, layer, role_name, employee_id, \
                spend_currency, max_per_transaction_minor, max_per_day_minor, \
                approval_above_minor, allowed_domains, max_new_contacts_per_day, \
                max_turns_per_day) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(Uuid::now_v7())
        .bind(version)
        .bind(row.tenant)
        .bind(row.layer)
        .bind(row.role)
        .bind(row.employee)
        .bind(currency)
        .bind(per_txn)
        .bind(per_day)
        .bind(approval)
        .bind(domains)
        .bind(row.contacts)
        .bind(row.turns)
        .execute(&mut **tx)
        .await
        .expect("insert layer");
    }

    /// Install the one global platform layer, replacing whatever was there.
    /// Returns the lock that keeps a concurrent test from doing the same.
    ///
    /// `pub(crate)` because `store::org`'s tests load policies too, and the
    /// platform layer is a global singleton: a second mutex in a second module
    /// would guard nothing.
    pub(crate) async fn platform(
        db: &Db,
        spend: (i64, i64, i64),
        domains: &[&str],
    ) -> MutexGuard<'static, ()> {
        let guard = PLATFORM.lock().await;
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM policy_versions WHERE tenant_id IS NULL")
            .execute(&mut *tx)
            .await
            .expect("clear platform versions");
        let version = insert_version(&mut tx, None, "platform", true).await;
        insert_layer(
            &mut tx,
            version,
            Row {
                layer: "platform",
                spend: Some(spend),
                domains,
                contacts: 100,
                turns: 200,
                ..Row::default()
            },
        )
        .await;
        tx.commit().await.expect("commit platform");
        guard
    }

    /// A committed tenant + employee.
    async fn seed(db: &Db, label: &str) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");

        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind(format!("{label}-{}", tenant.as_uuid()))
            .bind(label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(label)
        .bind(label)
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");
        (tenant, employee)
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    /// `(max_per_transaction, max_per_day, approval_above)` of the loaded
    /// policy, in minor units.
    fn caps(policy: &EffectivePolicy) -> (u64, u64, u64) {
        let spend = policy.limits().spend.expect("a spend policy");
        (
            spend.max_per_transaction().minor(),
            spend.max_per_day().minor(),
            spend.approval_above().minor(),
        )
    }

    #[tokio::test]
    async fn a_tenant_layer_narrower_than_the_platform_wins() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "narrow").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((10_000, 40_000, 5_000)),
                domains: &["example.com"],
                contacts: 7,
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let policy = load(&mut tx, employee, None).await.expect("load");
        assert_eq!(caps(&policy), (10_000, 40_000, 5_000));
        assert_eq!(policy.limits().max_new_contacts_per_day, 7);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_tenant_layer_wider_than_the_platform_does_not_widen_it() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "greedy").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                // Every number bigger, and an extra domain on the allowlist.
                spend: Some((999_999, 999_999, 999_999)),
                domains: &["example.com", "anything.example.net"],
                contacts: 10_000,
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let policy = load(&mut tx, employee, None).await.expect("load");
        assert_eq!(
            caps(&policy),
            (50_000, 200_000, 50_000),
            "the platform ceiling must survive a greedy tenant layer"
        );
        assert_eq!(policy.limits().max_new_contacts_per_day, 100);
        assert_eq!(
            policy.limits().allowed_domains,
            [Domain::parse("example.com").unwrap()].into(),
            "a tenant must not add a domain the platform never allowed"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_absent_employee_layer_inherits_the_tenants() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "inherit").await;
        let (_, other_employee) = seed(&db, "inherit-other").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((20_000, 60_000, 10_000)),
                domains: &["example.com"],
                contacts: 5,
                ..Row::default()
            },
        )
        .await;
        // A layer for a *different* employee, so the query is proven to be
        // selecting rather than the table merely being empty.
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "employee",
                employee: Some(other_employee.as_uuid()),
                spend: Some((1, 1, 1)),
                domains: &["example.com"],
                contacts: 0,
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        // No employee layer and no role layer: both inherit the tenant's.
        let policy = load(&mut tx, employee, Some("sales")).await.expect("load");
        assert_eq!(caps(&policy), (20_000, 60_000, 10_000));
        assert_eq!(policy.limits().max_new_contacts_per_day, 5);
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_employee_layer_tightens_and_a_role_layer_sits_between() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "layers").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        for row in [
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((30_000, 90_000, 30_000)),
                domains: &["example.com"],
                contacts: 50,
                ..Row::default()
            },
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "role",
                role: Some("sales"),
                spend: Some((20_000, 80_000, 20_000)),
                domains: &["example.com"],
                contacts: 20,
                ..Row::default()
            },
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "employee",
                employee: Some(employee.as_uuid()),
                spend: Some((15_000, 80_000, 2_000)),
                domains: &["example.com"],
                contacts: 30,
                ..Row::default()
            },
        ] {
            insert_layer(&mut admin, version, row).await;
        }
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let policy = load(&mut tx, employee, Some("sales")).await.expect("load");
        // Minimum of each cap taken independently across all four layers.
        assert_eq!(caps(&policy), (15_000, 80_000, 2_000));
        assert_eq!(policy.limits().max_new_contacts_per_day, 20);

        // A role nobody wrote a layer for is an absent layer, not a wider one.
        let unknown_role = load(&mut tx, employee, Some("legal")).await.expect("load");
        assert_eq!(caps(&unknown_role), (15_000, 80_000, 2_000));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_incoherent_stored_layer_fails_to_load() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "incoherent").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                // Approval threshold above the per-transaction cap: the cap
                // fires first, so the approval step can never happen.
                spend: Some((1_000, 10_000, 5_000)),
                domains: &["example.com"],
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = load(&mut tx, employee, None)
            .await
            .expect_err("an incoherent layer must not load");
        assert!(
            matches!(
                err,
                PolicyLoadError::Incoherent {
                    layer: PolicyLayer::Tenant,
                    source: PolicyError::ApprovalAboveTransactionCap { .. },
                    ..
                }
            ),
            "expected a named incoherence, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("tenant") && message.contains("incoherent"),
            "the error must name the layer: {message}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn layers_in_different_currencies_do_not_load() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "currency").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((10_000, 40_000, 5_000)),
                currency: Some("EUR"),
                domains: &["example.com"],
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = load(&mut tx, employee, None).await.expect_err("no rate");
        assert!(
            matches!(
                err,
                PolicyLoadError::Irreconcilable {
                    source: PolicyError::MixedCurrency {
                        left: Usd,
                        right: Eur
                    }
                }
            ),
            "expected a currency clash, got {err:?}"
        );
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn one_tenants_policy_is_invisible_to_another() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (a, a_employee) = seed(&db, "iso-a").await;
        let (b, b_employee) = seed(&db, "iso-b").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let version = insert_version(&mut admin, Some(a.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            version,
            Row {
                tenant: Some(a.as_uuid()),
                layer: "tenant",
                spend: Some((1_000, 2_000, 1_000)),
                domains: &["example.com"],
                contacts: 1,
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        // B has no layers of its own, so it inherits the platform ceiling —
        // NOT A's much narrower one.
        let mut tx = db.tenant_tx(b).await.expect("tenant tx");
        let policy = load(&mut tx, b_employee, None).await.expect("load");
        assert_eq!(caps(&policy), (50_000, 200_000, 50_000));

        // And A's rows are not merely unselected, they are invisible: asked for
        // by primary key with no tenant filter in the SQL at all.
        let seen: i64 =
            sqlx::query_scalar("SELECT count(*) FROM policy_layers WHERE version_id = $1")
                .bind(version)
                .fetch_one(&mut **tx)
                .await
                .expect("count");
        assert_eq!(seen, 0, "tenant B must not see tenant A's policy layers");

        // Nor can B write a platform row, whatever it claims.
        let forged = sqlx::query(
            "INSERT INTO policy_versions (id, tenant_id, label, active) \
             VALUES ($1, NULL, 'forged', true)",
        )
        .bind(Uuid::now_v7())
        .execute(&mut **tx)
        .await;
        assert!(
            forged.is_err(),
            "a tenant must not be able to write the platform layer"
        );
        tx.rollback().await.expect("rollback");

        // A still sees its own.
        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        let policy = load(&mut tx, a_employee, None).await.expect("load");
        assert_eq!(caps(&policy), (1_000, 2_000, 1_000));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }

    #[tokio::test]
    async fn rolling_back_a_version_restores_the_previous_policy() {
        let Some(db) = db().await else { return };
        let _guard = platform(&db, (50_000, 200_000, 50_000), &["example.com"]).await;
        let (tenant, employee) = seed(&db, "rollback").await;

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let v1 = insert_version(&mut admin, Some(tenant.as_uuid()), "v1", true).await;
        insert_layer(
            &mut admin,
            v1,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((30_000, 90_000, 30_000)),
                domains: &["example.com"],
                contacts: 40,
                ..Row::default()
            },
        )
        .await;
        // The bad change: same shape, much tighter, and it becomes active.
        let v2 = insert_version(&mut admin, Some(tenant.as_uuid()), "v2", false).await;
        insert_layer(
            &mut admin,
            v2,
            Row {
                tenant: Some(tenant.as_uuid()),
                layer: "tenant",
                spend: Some((100, 200, 100)),
                domains: &["example.com"],
                contacts: 1,
                ..Row::default()
            },
        )
        .await;
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        assert_eq!(
            caps(&load(&mut tx, employee, None).await.expect("load")),
            (30_000, 90_000, 30_000)
        );

        activate(&mut tx, v2).await.expect("activate v2");
        assert_eq!(
            caps(&load(&mut tx, employee, None).await.expect("load")),
            (100, 200, 100)
        );

        // Roll back. The old version was never edited, so this is a pointer flip.
        activate(&mut tx, v1).await.expect("activate v1");
        let restored = load(&mut tx, employee, None).await.expect("load");
        assert_eq!(caps(&restored), (30_000, 90_000, 30_000));
        assert_eq!(restored.limits().max_new_contacts_per_day, 40);

        // Activating someone else's version is a NotFound, not a silent no-op.
        let stranger = activate(&mut tx, Uuid::now_v7()).await;
        assert!(matches!(stranger, Err(StoreError::NotFound)));
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn no_platform_layer_is_an_error_not_an_open_gate() {
        let Some(db) = db().await else { return };
        let _guard = PLATFORM.lock().await;
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM policy_versions WHERE tenant_id IS NULL")
            .execute(&mut *admin)
            .await
            .expect("clear platform versions");
        admin.commit().await.expect("commit");

        let (tenant, employee) = seed(&db, "no-platform").await;
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let err = load(&mut tx, employee, None)
            .await
            .expect_err("no ceiling, no policy");
        assert!(matches!(err, PolicyLoadError::NoPlatformLayer), "{err:?}");
        tx.rollback().await.expect("rollback");

        drop_tenant(&db, tenant).await;
    }
}
