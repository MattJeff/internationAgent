//! Approvals that authorise **one exact action**, not a category of them.
//!
//! The failure this module exists to prevent: a human reads "pay €100 to
//! supplier A", presses approve, and the agent then executes "pay €100 to
//! supplier B" under the same token — because the token said `payment_create`
//! and nothing narrower. Here the token is bound to a hash of the whole action,
//! and [`redeem`] re-hashes whatever is presented at execution time. A single
//! changed byte anywhere in the action produces a different hash and the
//! redemption is refused.
//!
//! # The canonical form
//!
//! The hash is `sha256` over the UTF-8 bytes of a canonical JSON serialisation
//! of the [`Action`], hex-encoded lowercase. Canonical means, precisely:
//!
//! * **Object keys sorted**, ascending by UTF-8 byte order, so serde's field
//!   order — or a future reordering of a struct's fields — cannot change the
//!   hash.
//! * **No insignificant whitespace**: no spaces after `:` or `,`, no newlines.
//! * **Arrays keep their order**, which is semantic.
//! * **Numbers are integers, written in the shortest decimal form**. Floats are
//!   *rejected*, not rounded: no `Action` carries one today ([`Money`] is
//!   `u64` minor units plus a currency code), and if one ever appears, an
//!   `Err` is the right answer rather than a hash that depends on a formatting
//!   library's mood.
//! * **Strings** use serde_json's escaping, which is minimal and deterministic:
//!   only `"`, `\` and control characters are escaped, and UTF-8 is emitted
//!   literally.
//!
//! ponytail: byte-order key sorting rather than RFC 8785's UTF-16 code-unit
//! order. The two agree for every key below U+10000, and every key here is an
//! ASCII identifier emitted by a `#[derive(Serialize)]`. If actions ever carry
//! caller-chosen object keys outside the BMP, switch the comparator — the
//! stored hashes would have to be re-derived, so do it in a migration.
//!
//! # Where the hash is computed
//!
//! In Postgres, by `sha256(convert_to($canonical, 'UTF8'))`. This crate has no
//! hashing dependency, and pulling one in for this is not worth a `Cargo.toml`
//! edit — but the better reason is that *one* implementation now computes the
//! hash on both the write and the redeem path, inside the same statement that
//! does the compare, so the two can never drift.
//!
//! `convert_to(text, 'UTF8')` and not `$1::bytea`: the text-to-bytea cast reads
//! `\x41` and `\101` escapes, and JSON strings contain backslashes, so that
//! cast would hash something other than the bytes we canonicalised.
//!
//! # Storage note
//!
//! `approvals` in `0001_core.sql` has no `action_hash`, `nonce`,
//! `requested_by` or `required_role` column, and a migration is owned by
//! someone else. Those four live inside the existing `action` jsonb as an
//! envelope:
//!
//! ```json
//! { "action": {…}, "action_hash": "…", "nonce": "…",
//!   "requested_by": "…", "required_role": "…" }
//! ```
//!
//! ponytail: envelope-in-jsonb instead of four real columns. `approvals` is
//! `0001_core.sql`'s; promote them in a migration of their own when someone
//! needs to index or report on them. The one
//! thing lost is the brief's `UNIQUE` on `nonce`; it is not load-bearing here,
//! because [`redeem`] matches on `id AND nonce` together — a nonce is only ever
//! usable against the approval it was minted for, so a (vanishingly unlikely)
//! collision between two approvals' nonces authorises nothing.

use std::fmt;

use agentos_domain::action::Action;
use agentos_domain::ids::{ApprovalId, EmployeeId};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// A freshly created approval is `pending` until it is redeemed.
const STATE_PENDING: &str = "pending";
/// Terminal state after a successful [`redeem`].
const STATE_REDEEMED: &str = "redeemed";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an approval could not be created or redeemed.
///
/// The redemption failures are deliberately distinct: "you presented a
/// different action" and "this was already used" are different incidents, and
/// collapsing them into one error loses the alarm.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The database said no for a reason that is not about this approval.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// **The interesting one.** The action presented at execution time hashes
    /// differently from the one a human approved.
    #[error("action does not match the approved one (approved {approved}, presented {presented})")]
    ActionMismatch {
        /// Hash stored on the approval.
        approved: String,
        /// Hash of the action handed to [`redeem`].
        presented: String,
    },

    /// The nonce does not belong to this approval.
    #[error("nonce does not match this approval")]
    BadNonce,

    /// Already redeemed, denied or otherwise no longer pending. Carries the
    /// state found, so a double redemption is legible in a log.
    #[error("approval is no longer pending (state: {0})")]
    AlreadyDecided(String),

    /// Past `expires_at`, or — failing closed — `expires_at` was NULL.
    #[error("approval has expired")]
    Expired,

    /// No such approval, or it belongs to another tenant. RLS makes those two
    /// indistinguishable on purpose.
    #[error("approval not found")]
    NotFound,

    /// A request to create an approval that is already dead.
    #[error("expires_at must be in the future")]
    ExpiresInThePast,

    /// The action does not have a canonical JSON form; see the module docs.
    #[error("action has no canonical form: {0}")]
    NotCanonical(String),

    /// A money amount that does not fit a Postgres `bigint`.
    #[error("amount does not fit in a bigint")]
    AmountOutOfRange,
}

impl From<sqlx::Error> for ApprovalError {
    fn from(err: sqlx::Error) -> Self {
        // Route through StoreError so 23505/40001/RowNotFound keep the
        // classification the rest of the crate relies on.
        Self::Store(StoreError::from(err))
    }
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// What to ask a human to approve.
///
/// There is no `tenant_id` field: [`create`] takes it from the
/// [`TenantTx`], which is the same value row-level security is enforcing
/// against. A caller cannot file an approval into a tenant it is not in.
#[derive(Debug, Clone)]
pub struct NewApproval<'a> {
    /// The employee that will execute the action, when there is one.
    pub employee_id: Option<EmployeeId>,
    /// The exact action being authorised. The hash is taken over this.
    pub action: &'a Action,
    /// Who asked (an employee slug, a service name, a user id).
    pub requested_by: &'a str,
    /// The role a human must hold to redeem this. Stored for the approval UI
    /// to enforce; this crate does not check it, because it has no notion of
    /// who is calling.
    pub required_role: &'a str,
    /// One line for the human. Display only.
    pub reason: Option<&'a str>,
    /// Hard deadline. Not optional: an approval that never expires is a
    /// standing authorisation nobody remembers granting.
    pub expires_at: DateTime<Utc>,
}

/// A created approval, plus the single-use secret that redeems it.
///
/// `Debug` is written by hand so the nonce cannot reach a log line by accident.
#[derive(Clone)]
pub struct Requested {
    id: ApprovalId,
    nonce: String,
    action_hash: String,
}

impl Requested {
    /// The approval's id. Safe to log.
    pub const fn id(&self) -> ApprovalId {
        self.id
    }

    /// The single-use redemption secret. **Bearer credential** — hand it to the
    /// approving human over an authenticated channel, never to the agent that
    /// requested the action, and never to a log.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Hex sha256 of the canonical action. Safe to log; useful to correlate.
    pub fn action_hash(&self) -> &str {
        &self.action_hash
    }
}

impl fmt::Debug for Requested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Requested")
            .field("id", &self.id)
            .field("nonce", &"<redacted>")
            .field("action_hash", &self.action_hash)
            .finish()
    }
}

/// Proof that this exact action was approved and that the approval has now
/// been spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    /// The approval that was consumed.
    pub approval_id: ApprovalId,
    /// The employee the approval was filed for, if any.
    pub employee_id: Option<EmployeeId>,
    /// Hash of the action, which by construction equals the hash of the action
    /// passed to [`redeem`].
    pub action_hash: String,
    /// Database clock at the moment of redemption.
    pub decided_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/// The canonical JSON serialisation of an action. See the module docs.
///
/// Public because the hash is only meaningful if callers can reproduce it, and
/// because an audit record wants the exact bytes that were hashed.
pub fn canonical_json(action: &Action) -> Result<String, ApprovalError> {
    let value =
        serde_json::to_value(action).map_err(|e| ApprovalError::NotCanonical(e.to_string()))?;
    let mut out = String::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), ApprovalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // Integers only, shortest form. A float here would make the hash
            // depend on formatting, so it is an error instead.
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(ApprovalError::NotCanonical(format!(
                    "non-integer number {n}"
                )));
            }
        }
        Value::String(s) => {
            let escaped =
                serde_json::to_string(s).map_err(|e| ApprovalError::NotCanonical(e.to_string()))?;
            out.push_str(&escaped);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(&Value::String(key.clone()), out)?;
                out.push(':');
                write_canonical(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

const INSERT_SQL: &str = "\
INSERT INTO approvals (
    id, tenant_id, employee_id, action_kind, action, reason, risk,
    state, amount_minor, currency, requested_at, expires_at)
VALUES (
    $1, $2, $3, $4,
    jsonb_build_object(
        'action',        $5::text::jsonb,
        'action_hash',   encode(sha256(convert_to($5::text, 'UTF8')), 'hex'),
        'nonce',         replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''),
        'requested_by',  $6::text,
        'required_role', $7::text),
    $8, $9, $10, $11, $12, $13, $14)
RETURNING action->>'action_hash', action->>'nonce'";

/// File an approval request for one exact action and mint its nonce.
///
/// The nonce is generated by Postgres from `gen_random_uuid()` (its CSPRNG),
/// two of them concatenated — 244 bits, because this is a bearer token. It
/// never travels into this process as an input, only out as a result.
pub async fn create(
    tx: &mut TenantTx<'_>,
    req: &NewApproval<'_>,
    now: DateTime<Utc>,
) -> Result<Requested, ApprovalError> {
    if req.expires_at <= now {
        return Err(ApprovalError::ExpiresInThePast);
    }

    let canonical = canonical_json(req.action)?;
    let id = ApprovalId::new_v7(now);

    // Only one action variant carries money; the rest leave the columns NULL,
    // which the `approvals_amount_has_currency` check requires to be in step.
    let (amount_minor, currency) = match req.action {
        Action::PaymentCreate { amount } => (
            Some(i64::try_from(amount.minor()).map_err(|_| ApprovalError::AmountOutOfRange)?),
            Some(amount.currency().code()),
        ),
        _ => (None, None),
    };

    let (action_hash, nonce): (String, String) = sqlx::query_as(INSERT_SQL)
        .bind(id.as_uuid())
        .bind(tx.tenant_id().as_uuid())
        .bind(req.employee_id.map(|e| e.as_uuid()))
        .bind(req.action.kind().as_str())
        .bind(&canonical)
        .bind(req.requested_by)
        .bind(req.required_role)
        .bind(req.reason)
        .bind(if req.action.risk().is_high() {
            "high"
        } else {
            "low"
        })
        .bind(STATE_PENDING)
        .bind(amount_minor)
        .bind(currency)
        .bind(now)
        .bind(req.expires_at)
        .fetch_one(&mut ***tx)
        .await?;

    Ok(Requested {
        id,
        nonce,
        action_hash,
    })
}

// ---------------------------------------------------------------------------
// redeem
// ---------------------------------------------------------------------------

/// The atomic redemption. Every guard is in the `WHERE`, so two concurrent
/// callers contend for the same row lock and exactly one of them updates it.
const REDEEM_SQL: &str = "\
UPDATE approvals
   SET state = $5, decided_at = now(), decided_by = $4
 WHERE id = $1
   AND state = 'pending'
   AND expires_at > now()
   AND action->>'nonce' = $2
   AND action->>'action_hash' = encode(sha256(convert_to($3::text, 'UTF8')), 'hex')
RETURNING employee_id, action->>'action_hash', decided_at";

/// Run only when the redemption matched nothing, to say *why*.
const DIAGNOSE_SQL: &str = "\
SELECT state,
       coalesce(expires_at, '-infinity'::timestamptz) <= now()  AS expired,
       coalesce(action->>'nonce', '') = $2                      AS nonce_ok,
       coalesce(action->>'action_hash', '')                     AS approved_hash,
       encode(sha256(convert_to($3::text, 'UTF8')), 'hex')      AS presented_hash
  FROM approvals
 WHERE id = $1";

/// Spend an approval on the action that is about to execute.
///
/// `action` is the action the executor is *actually* about to perform, not the
/// one that was filed. It is re-canonicalised and re-hashed here, and a
/// mismatch is [`ApprovalError::ActionMismatch`] — that is the whole point of
/// the module.
///
/// Redemption is a single guarded `UPDATE`. Under `READ COMMITTED` a second
/// caller blocks on the row lock, re-evaluates the predicate against the
/// committed row, sees `state = 'redeemed'`, and matches nothing. There is no
/// window in which both succeed.
///
/// `decided_by` records the human who presented the nonce. It is not in the
/// brief's four-argument signature, but a decision record with no decider is
/// not an audit trail.
pub async fn redeem(
    tx: &mut TenantTx<'_>,
    approval_id: ApprovalId,
    nonce: &str,
    action: &Action,
    decided_by: &str,
) -> Result<Redeemed, ApprovalError> {
    let canonical = canonical_json(action)?;

    let redeemed: Option<(Option<Uuid>, String, DateTime<Utc>)> = sqlx::query_as(REDEEM_SQL)
        .bind(approval_id.as_uuid())
        .bind(nonce)
        .bind(&canonical)
        .bind(decided_by)
        .bind(STATE_REDEEMED)
        .fetch_optional(&mut ***tx)
        .await?;

    if let Some((employee_id, action_hash, decided_at)) = redeemed {
        return Ok(Redeemed {
            approval_id,
            employee_id: employee_id.map(EmployeeId::from_uuid),
            action_hash,
            decided_at,
        });
    }

    let found: Option<(String, bool, bool, String, String)> = sqlx::query_as(DIAGNOSE_SQL)
        .bind(approval_id.as_uuid())
        .bind(nonce)
        .bind(&canonical)
        .fetch_optional(&mut ***tx)
        .await?;

    let Some((state, expired, nonce_ok, approved_hash, presented_hash)) = found else {
        return Err(ApprovalError::NotFound);
    };

    // Ordered by how alarming the answer is. A mutated action is an incident;
    // a double redemption is a bug; an expiry is a Tuesday.
    if !nonce_ok {
        Err(ApprovalError::BadNonce)
    } else if approved_hash != presented_hash {
        Err(ApprovalError::ActionMismatch {
            approved: approved_hash,
            presented: presented_hash,
        })
    } else if state != STATE_PENDING {
        Err(ApprovalError::AlreadyDecided(state))
    } else if expired {
        Err(ApprovalError::Expired)
    } else {
        // Every guard in REDEEM_SQL is covered above, so this is unreachable
        // unless the two statements drift apart.
        Err(ApprovalError::Store(StoreError::conflict(
            "approvals.redeem matched no row for an unexplained reason",
        )))
    }
}

#[cfg(test)]
mod tests {
    use agentos_domain::action::{Domain, E164, EmailAddress};
    use agentos_domain::money::{Currency, Money};

    use super::*;
    use crate::db::Db;

    // -- fixtures ----------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; approvals tests need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// A tenant plus one employee, committed.
    async fn seed(db: &Db, label: &str) -> (agentos_domain::ids::TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = agentos_domain::ids::TenantId::new_v7(now);
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

    async fn drop_tenant(db: &Db, tenant: agentos_domain::ids::TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit teardown");
    }

    fn pay(minor: u64) -> Action {
        Action::PaymentCreate {
            amount: Money::new(minor, Currency::Eur).expect("nonzero"),
        }
    }

    fn email_to(addr: &str) -> Action {
        Action::EmailSend {
            to: EmailAddress::parse(addr).expect("address"),
        }
    }

    fn request<'a>(action: &'a Action, expires_at: DateTime<Utc>) -> NewApproval<'a> {
        NewApproval {
            employee_id: None,
            action,
            requested_by: "lena",
            required_role: "finance_admin",
            reason: Some("over the daily limit"),
            expires_at,
        }
    }

    // -- canonical form ----------------------------------------------------

    #[test]
    fn key_order_and_number_spelling_do_not_change_the_canonical_form() {
        // The same document, written three ways a JSON producer might write it.
        let spellings = [
            r#"{"b":1,"a":{"y":[1,2],"x":"e"}}"#,
            r#"{"a":{"x":"e","y":[1,2]},"b":1}"#,
            "{ \"a\" : { \"y\" : [ 1 , 2 ] , \"x\" : \"e\" } , \"b\" : 1 }",
        ];
        let mut canonical = Vec::new();
        for raw in spellings {
            let value: Value = serde_json::from_str(raw).expect("parse");
            let mut out = String::new();
            write_canonical(&value, &mut out).expect("canonicalise");
            canonical.push(out);
        }
        assert_eq!(canonical[0], r#"{"a":{"x":"e","y":[1,2]},"b":1}"#);
        assert!(canonical.windows(2).all(|w| w[0] == w[1]), "{canonical:?}");

        // Array order is semantic and is preserved.
        let reversed: Value = serde_json::from_str(r#"{"a":{"y":[2,1],"x":"e"},"b":1}"#).unwrap();
        let mut out = String::new();
        write_canonical(&reversed, &mut out).unwrap();
        assert_ne!(out, canonical[0]);
    }

    #[test]
    fn floats_have_no_canonical_form() {
        let value: Value = serde_json::from_str(r#"{"amount":1.10}"#).unwrap();
        let mut out = String::new();
        assert!(matches!(
            write_canonical(&value, &mut out),
            Err(ApprovalError::NotCanonical(_))
        ));
    }

    #[test]
    fn actions_canonicalise_to_stable_bytes() {
        assert_eq!(
            canonical_json(&pay(10_000)).unwrap(),
            r#"{"action":"payment_create","amount":{"currency":"EUR","minor":10000}}"#
        );
        assert_eq!(
            canonical_json(&Action::SmsSend {
                to: E164::parse("+33612345678").unwrap()
            })
            .unwrap(),
            r#"{"action":"sms_send","to":"+33612345678"}"#
        );
        // Different actions, different bytes — which is what the hash relies on.
        assert_ne!(
            canonical_json(&email_to("a@example.com")).unwrap(),
            canonical_json(&email_to("b@example.com")).unwrap()
        );
        assert_ne!(
            canonical_json(&Action::BrowserRead {
                domain: Domain::parse("example.com").unwrap()
            })
            .unwrap(),
            canonical_json(&Action::BrowserWrite {
                domain: Domain::parse("example.com").unwrap()
            })
            .unwrap()
        );
    }

    // -- the headline property --------------------------------------------

    /// A human approves "pay supplier A". The executor presents "pay supplier
    /// B". The nonce is correct, the approval is live, and it is still refused.
    #[tokio::test]
    async fn an_approval_does_not_authorise_a_mutated_action() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db, "mutated").await;
        let now = Utc::now();

        let approved = email_to("supplier-a@example.com");
        let mutated = email_to("supplier-b@example.com");

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let mut req = request(&approved, now + chrono::Duration::hours(1));
        req.employee_id = Some(employee);
        let requested = create(&mut tx, &req, now).await.unwrap();
        tx.commit().await.unwrap();

        // Execution time: a different action, same token.
        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = redeem(
            &mut tx,
            requested.id(),
            requested.nonce(),
            &mutated,
            "cfo@example.com",
        )
        .await
        .expect_err("a mutated action must not redeem");
        match &err {
            ApprovalError::ActionMismatch {
                approved: a,
                presented: p,
            } => {
                assert_eq!(a, requested.action_hash());
                assert_ne!(a, p);
            }
            other => panic!("expected ActionMismatch, got {other:?}"),
        }
        tx.commit().await.unwrap();

        // The failed attempt must not have consumed the approval: the real
        // action still redeems.
        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let ok = redeem(
            &mut tx,
            requested.id(),
            requested.nonce(),
            &approved,
            "cfo@example.com",
        )
        .await
        .expect("the approved action redeems");
        assert_eq!(ok.action_hash, requested.action_hash());
        assert_eq!(ok.employee_id, Some(employee));
        tx.commit().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn a_wrong_nonce_is_refused() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "nonce").await;
        let now = Utc::now();
        let action = pay(4_200);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = redeem(&mut tx, requested.id(), "not-the-nonce", &action, "cfo")
            .await
            .expect_err("a wrong nonce must not redeem");
        assert!(matches!(err, ApprovalError::BadNonce), "{err:?}");
        tx.commit().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    // -- single use --------------------------------------------------------

    #[tokio::test]
    async fn a_nonce_is_single_use() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "singleuse").await;
        let now = Utc::now();
        let action = pay(99_900);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        redeem(&mut tx, requested.id(), requested.nonce(), &action, "cfo")
            .await
            .expect("first redemption wins");
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = redeem(&mut tx, requested.id(), requested.nonce(), &action, "cfo")
            .await
            .expect_err("second redemption must fail");
        match &err {
            ApprovalError::AlreadyDecided(state) => assert_eq!(state, STATE_REDEEMED),
            other => panic!("expected AlreadyDecided, got {other:?}"),
        }
        tx.commit().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    // -- expiry ------------------------------------------------------------

    #[tokio::test]
    async fn an_expired_approval_is_rejected() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "expired").await;
        let now = Utc::now();
        let action = pay(1_000);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Fast-forward rather than sleep: move the deadline into the past.
        let mut tx = db.admin_tx_bypassing_rls().await.unwrap();
        sqlx::query("UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id = $1")
            .bind(requested.id().as_uuid())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = redeem(&mut tx, requested.id(), requested.nonce(), &action, "cfo")
            .await
            .expect_err("an expired approval must not redeem");
        assert!(matches!(err, ApprovalError::Expired), "{err:?}");
        tx.commit().await.unwrap();

        // NULL expires_at fails closed too, even though `create` never writes
        // one: an approval with no deadline authorises nothing.
        let mut tx = db.admin_tx_bypassing_rls().await.unwrap();
        sqlx::query("UPDATE approvals SET expires_at = NULL, state = 'pending' WHERE id = $1")
            .bind(requested.id().as_uuid())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = redeem(&mut tx, requested.id(), requested.nonce(), &action, "cfo")
            .await
            .expect_err("a NULL deadline must not redeem");
        assert!(matches!(err, ApprovalError::Expired), "{err:?}");
        tx.commit().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    #[tokio::test]
    async fn an_approval_cannot_be_born_expired() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "bornexpired").await;
        let now = Utc::now();
        let action = pay(1);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let err = create(
            &mut tx,
            &request(&action, now - chrono::Duration::seconds(1)),
            now,
        )
        .await
        .expect_err("a dead approval is not worth storing");
        assert!(matches!(err, ApprovalError::ExpiresInThePast), "{err:?}");
        tx.rollback().await.unwrap();

        drop_tenant(&db, tenant).await;
    }

    // -- concurrency -------------------------------------------------------

    /// Eight callers race for one approval. Postgres serialises them on the
    /// row lock, so exactly one `UPDATE` matches.
    #[tokio::test]
    async fn a_concurrent_double_redeem_has_exactly_one_winner() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "race").await;
        let now = Utc::now();
        let action = pay(50_000);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tasks = Vec::new();
        for i in 0..8 {
            let db = db.clone();
            let id = requested.id();
            let nonce = requested.nonce().to_owned();
            let action = action.clone();
            tasks.push(tokio::spawn(async move {
                let mut tx = db.tenant_tx(tenant).await.unwrap();
                let outcome = redeem(&mut tx, id, &nonce, &action, &format!("cfo-{i}")).await;
                tx.commit().await.unwrap();
                outcome
            }));
        }

        let mut winners = 0;
        for task in tasks {
            match task.await.expect("task panicked") {
                Ok(_) => winners += 1,
                Err(ApprovalError::AlreadyDecided(state)) => assert_eq!(state, STATE_REDEEMED),
                Err(other) => panic!("unexpected loser error: {other:?}"),
            }
        }
        assert_eq!(winners, 1, "exactly one redemption may succeed");

        drop_tenant(&db, tenant).await;
    }

    // -- isolation ---------------------------------------------------------

    #[tokio::test]
    async fn another_tenant_cannot_redeem_an_approval_it_can_see_the_id_of() {
        let Some(db) = db().await else { return };
        let (mine, _) = seed(&db, "owner").await;
        let (theirs, _) = seed(&db, "attacker").await;
        let now = Utc::now();
        let action = pay(7_777);

        let mut tx = db.tenant_tx(mine).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // The attacker has the id *and* the nonce, and still gets nothing:
        // RLS hides the row, so it is indistinguishable from a typo.
        let mut tx = db.tenant_tx(theirs).await.unwrap();
        let err = redeem(&mut tx, requested.id(), requested.nonce(), &action, "them")
            .await
            .expect_err("cross-tenant redemption must fail");
        assert!(matches!(err, ApprovalError::NotFound), "{err:?}");
        tx.commit().await.unwrap();

        // ... and the approval is still spendable by its owner.
        let mut tx = db.tenant_tx(mine).await.unwrap();
        redeem(&mut tx, requested.id(), requested.nonce(), &action, "us")
            .await
            .expect("the owner still holds a live approval");
        tx.commit().await.unwrap();

        drop_tenant(&db, mine).await;
        drop_tenant(&db, theirs).await;
    }

    // -- stored row --------------------------------------------------------

    #[tokio::test]
    async fn the_row_carries_the_action_its_hash_and_its_money() {
        let Some(db) = db().await else { return };
        let (tenant, _) = seed(&db, "row").await;
        let now = Utc::now();
        let action = pay(12_345);

        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let requested = create(
            &mut tx,
            &request(&action, now + chrono::Duration::hours(1)),
            now,
        )
        .await
        .unwrap();

        let row: (
            String,
            String,
            String,
            String,
            Option<i64>,
            Option<String>,
            String,
        ) = sqlx::query_as(
            "SELECT action_kind, risk, action->>'requested_by', action->>'required_role', \
                 amount_minor, currency, action->'action' #>> '{}' \
                 FROM approvals WHERE id = $1",
        )
        .bind(requested.id().as_uuid())
        .fetch_one(&mut **tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(row.0, "payment_create");
        assert_eq!(row.1, "high");
        assert_eq!(row.2, "lena");
        assert_eq!(row.3, "finance_admin");
        assert_eq!(row.4, Some(12_345));
        assert_eq!(row.5.as_deref(), Some("EUR"));
        // Semantically the action we filed (jsonb normalises the spelling).
        assert_eq!(
            serde_json::from_str::<Action>(&row.6).unwrap(),
            action,
            "the stored action must round-trip"
        );

        // The nonce never appears in a Debug rendering.
        let rendered = format!("{requested:?}");
        assert!(!rendered.contains(requested.nonce()), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        drop_tenant(&db, tenant).await;
    }
}
