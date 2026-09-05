//! The tenant's model connection: one row, read on every turn, written once per
//! proof.
//!
//! `migrations/0041_tenant_model_access.sql` carries the argument for the table
//! and `agentos_domain::model_access` for the types. Two things about this
//! module rather than that one:
//!
//! **`load` returns `Option`, and `None` is the answer, not an error.** A tenant
//! with no row is not a failed read — it is a tenant nobody has connected a
//! model for yet, which is the state every tenant is in the moment 0041 lands.
//! Making it an error would put "the first-run step nobody did" and "the
//! database is broken" in the same branch, and the caller has to tell a person
//! which one it was in a five-minute setup flow.
//!
//! **A row this build cannot read is [`StoreError::Conflict`], never a skipped
//! row.** The `path` and `verified_model` columns hold closed enums whose
//! parsers return `None` for anything unknown. Text that does not parse means
//! the database and the binary disagree about what paths or models exist — a
//! rollback to an older build, or a `psql` session — and the safe reading of
//! that is *stop*, because the alternative is treating a connected tenant as
//! unconnected and refusing every one of their turns with a message that names
//! the wrong remedy.
//!
//! There is no `WHERE tenant_id` in either statement. `tenant_model_access` has
//! RLS forced and the policy is `with check` as well as `using`, so the tenant
//! filter is the database's rather than something a reader has to verify is
//! present in every query.
//!
//! **The credential travels with the row, sealed.** `0050_tenant_model_key`
//! argues why; what it means here is that [`load`] returns a [`Connection`] and
//! not a bare [`ModelAccess`], and that the pair is written by [`save`] in one
//! statement. Nothing in this module can open the blob — the cipher is
//! `agentos_app::mcp::Credentials`, one crate up — which is the property that
//! keeps a plaintext credential out of every SQL error, every `sqlx` log line
//! and every `Debug` this module could ever render.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use agentos_domain::model_access::{ModelAccess, ModelPath};
use agentos_domain::policy::ModelId;

use crate::db::{StoreError, TenantTx};

/// One row of [`tenant_model_access`](self), still as text.
#[derive(Debug, sqlx::FromRow)]
struct Row {
    path: String,
    verified_model: String,
    verified_at: DateTime<Utc>,
    sealed_key: Option<Vec<u8>>,
    usd_per_mtok_input: Option<f64>,
    usd_per_mtok_output: Option<f64>,
    usd_per_mtok_cache_read: Option<f64>,
}

impl Row {
    /// Parse the closed enums, or refuse. See the module docs for why an
    /// unreadable row is louder than a missing one.
    fn into_connection(self) -> Result<Connection, StoreError> {
        let path = ModelPath::parse(&self.path).ok_or_else(|| {
            StoreError::conflict(format!(
                "tenant_model_access.path is {:?}, which this build has no model path for",
                self.path
            ))
        })?;
        let model = ModelId::parse(&self.verified_model).ok_or_else(|| {
            StoreError::conflict(format!(
                "tenant_model_access.verified_model is {:?}, which this build has no model for",
                self.verified_model
            ))
        })?;
        Ok(Connection {
            access: ModelAccess {
                path,
                model,
                verified_at: self.verified_at,
            },
            sealed_key: self.sealed_key,
            tariff: Tariff {
                usd_per_mtok_input: self.usd_per_mtok_input,
                usd_per_mtok_output: self.usd_per_mtok_output,
                usd_per_mtok_cache_read: self.usd_per_mtok_cache_read,
            }
            .declared(),
        })
    }
}

// ---------------------------------------------------------------------------
// The tariff
// ---------------------------------------------------------------------------

/// What the tenant says a token costs them, in USD per million tokens.
///
/// **A claim, not a measurement.** `migrations/0079_tenant_model_tariff.sql`
/// argues why it sits on the connection row; what matters here is what the
/// type is *not*: it is not a price this repository knows, and it is not
/// `Money`. A rate per million tokens is a multiplier — `f64` in Rust, NUMERIC
/// in the column, cast on the way in and out so `0.30` survives the round trip
/// — and the thing it produces, tokens × rate rounded to the cent, is the
/// `Money` that `GET /v1/pnl` reports. The float never reaches an amount: the
/// multiplication and the rounding happen in SQL over the NUMERIC column, and
/// only the resulting cents come back.
///
/// A component left `None` is unknown, never free. A partial tariff still
/// yields a figure, but a floor — see `cost_is_floor` on the P&L.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Tariff {
    #[serde(default)]
    pub usd_per_mtok_input: Option<f64>,
    #[serde(default)]
    pub usd_per_mtok_output: Option<f64>,
    #[serde(default)]
    pub usd_per_mtok_cache_read: Option<f64>,
}

impl Tariff {
    /// `Some` if any component was declared; three `None`s are no tariff.
    pub fn declared(self) -> Option<Self> {
        (self.usd_per_mtok_input.is_some()
            || self.usd_per_mtok_output.is_some()
            || self.usd_per_mtok_cache_read.is_some())
        .then_some(self)
    }

    /// Every token kind the ledger meters has a rate. Anything less makes a
    /// cost computed from it a floor.
    pub fn is_complete(self) -> bool {
        self.usd_per_mtok_input.is_some()
            && self.usd_per_mtok_output.is_some()
            && self.usd_per_mtok_cache_read.is_some()
    }

    /// A rate that is not a non-negative number: below zero, NaN or infinite.
    /// Refused by the caller so the tenant gets a sentence rather than the
    /// check constraint's name (or a NUMERIC cast error for NaN).
    pub fn is_malformed(self) -> bool {
        [
            self.usd_per_mtok_input,
            self.usd_per_mtok_output,
            self.usd_per_mtok_cache_read,
        ]
        .into_iter()
        .flatten()
        .any(|rate| !(rate >= 0.0 && rate.is_finite()))
    }
}

/// Where a cost figure comes from — the label every reader of `cost_usd` has
/// to show beside it.
///
/// Closed, low-cardinality and serialized as the wire string, for the reason
/// `Verdict` is: this becomes a word on a screen, and a free-form string would
/// invite a provider's number to be pasted in as the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    /// Tokens × the tariff the tenant declared, on the `api_key` path — the
    /// path whose tokens their key actually pays for.
    DeclaredTariff,
    /// Tokens × the tariff, but the connection is `cli`: the host's logged-in
    /// CLI spends them and nobody meters that against this rate. Indicative.
    DeclaredTariffOnCliPath,
    /// No tariff declared, so no figure: `cost_usd` is null. The default,
    /// because an empty ledger has no tariff to speak of.
    #[default]
    NoTariff,
}

impl CostSource {
    /// For a connection that may not exist: no row is no tariff.
    pub fn of(connection: Option<&Connection>) -> Self {
        match connection {
            Some(c) if c.tariff.is_some() => match c.access.path {
                ModelPath::ApiKey => CostSource::DeclaredTariff,
                ModelPath::Cli => CostSource::DeclaredTariffOnCliPath,
            },
            _ => CostSource::NoTariff,
        }
    }
}

/// A tenant's connection: what was proven, and the credential that proved it.
///
/// # Why the two halves are one type
///
/// Because for eight migrations they were not, and that is the whole of
/// `0050_tenant_model_key`. The row lived in Postgres and the credential lived in
/// a `HashMap` in one server process, so a restart left a row asserting a
/// connection nothing could honour — and `GET /v1/model`, which reads only the
/// row, answered 200 for a key that no longer existed. Handing callers a single
/// value they cannot destructure into a half-truth is what makes that
/// unrepresentable rather than merely fixed.
///
/// **Not `Serialize`, and it must not become so.** [`Connection::access`] is the
/// public half and is serialized by `apps/server`'s `/v1/model`; adding a derive
/// here would put a ciphertext into an HTTP body the first time somebody wrote
/// `Json(connection)`.
pub struct Connection {
    /// What the verification call proved: the path, the model and the moment.
    /// Safe to serialize; there is no credential field on it.
    pub access: ModelAccess,
    /// The sealed credential, or `None` on [`ModelPath::Cli`], which has none.
    ///
    /// The envelope from `agentos_providers::secrets::Envelope::to_bytes`, under
    /// AAD `model://<tenant>`. `0050`'s CHECK constraint makes this a
    /// biconditional with `path`: an `api_key` row always has one and a `cli`
    /// row never does, so the `None` arm below the `ApiKey` match in
    /// `agentos_app::model_access::llm_for` is a database corruption and not an
    /// ordinary state.
    pub sealed_key: Option<Vec<u8>>,
    /// What the tenant says a token costs them, if they said. Safe to serialize
    /// and safe to be absent: `0079_tenant_model_tariff` makes it nullable.
    pub tariff: Option<Tariff>,
}

/// Renders the ciphertext's length and never its bytes.
///
/// Hand-written rather than derived: a derived one dumps a hundred bytes of
/// envelope into every log line that formats an `Assignment`, which is noise
/// that looks like a leak — and reviewing it as "not a leak" is a judgement
/// nobody should have to make twice.
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("access", &self.access)
            .field(
                "sealed_key",
                &self
                    .sealed_key
                    .as_ref()
                    .map(|k| format!("{} bytes", k.len())),
            )
            .field("tariff", &self.tariff)
            .finish()
    }
}

/// This tenant's model connection, or `None` if nobody has connected one.
///
/// Read on the path of every turn, so it is one row by primary key and nothing
/// else. `None` is what makes a tenant a tenant whose employees take no turns —
/// see `agentos_app::model_access::for_turn`, which is the only caller allowed
/// to decide what that means.
///
/// The sealed credential comes back in the same row read rather than in a second
/// query, which is what makes "the row and the key agree" a fact about one
/// snapshot instead of a race between two.
pub async fn load(tx: &mut TenantTx<'_>) -> Result<Option<Connection>, StoreError> {
    // `::float8` on the NUMERIC columns: this crate has no decimal type, and a
    // rate is a multiplier — see [`Tariff`] for why that is not a money leak.
    let row: Option<Row> = sqlx::query_as(
        "SELECT path, verified_model, verified_at, sealed_key, \
                usd_per_mtok_input::float8      AS usd_per_mtok_input, \
                usd_per_mtok_output::float8     AS usd_per_mtok_output, \
                usd_per_mtok_cache_read::float8 AS usd_per_mtok_cache_read \
           FROM tenant_model_access",
    )
    .fetch_optional(&mut ***tx)
    .await?;

    row.map(Row::into_connection).transpose()
}

/// Record a connection that has just been proven, credential included.
///
/// An upsert, because reconnecting with a different key is the only shape of
/// "change my model connection" this product offers — there is no DELETE grant
/// on the table and no verb that would use one.
///
/// # `sealed_key` is not optional in the sense the type suggests
///
/// It is `Option` because [`ModelPath::Cli`] genuinely has no credential, not
/// because an `api_key` connection may omit one. `0050`'s CHECK constraint makes
/// the pairing a biconditional, so the wrong combination is a failed statement
/// and not a row somebody discovers a week later:
///
/// ```text
/// new row for relation "tenant_model_access" violates check constraint
/// "tenant_model_access_key_matches_path"
/// ```
///
/// **One statement, so there is no order to get wrong.** Before 0050 this
/// function's docs asked the caller to write the credential to the vault first
/// and warned about the window between the two. There is no window now: the
/// proof and the thing that proved it are the same INSERT, and the upsert
/// replaces both together — a reconnect cannot leave the previous tenant's key
/// under a fresh `verified_at`.
///
/// The plaintext is never here. `sealed_key` is already an envelope when it
/// arrives, so a statement this function logs, or a `StoreError` it renders,
/// contains ciphertext at worst.
pub async fn save(
    tx: &mut TenantTx<'_>,
    access: &ModelAccess,
    sealed_key: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO tenant_model_access \
           (tenant_id, path, verified_model, verified_at, sealed_key, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (tenant_id) DO UPDATE SET \
           path = excluded.path, \
           verified_model = excluded.verified_model, \
           verified_at = excluded.verified_at, \
           sealed_key = excluded.sealed_key, \
           updated_at = excluded.updated_at",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(access.path.as_str())
    .bind(access.model.as_str())
    .bind(access.verified_at)
    .bind(sealed_key)
    .bind(now)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

/// Write the tenant's declared tariff onto their connection row.
///
/// All three columns at once: a declaration replaces the previous one, so a
/// component the caller left out becomes null (unknown), not the old value.
/// `false` when there is no row to write on — a tenant declaring a price for a
/// model they have not connected, which the caller turns into the sentence
/// naming `POST /v1/model`.
///
/// [`save`]'s upsert deliberately does not touch these columns, so reconnecting
/// keeps the tariff: the rate is the tenant's contract, and pasting a rotated
/// key does not change what Anthropic charges them.
pub async fn set_tariff(tx: &mut TenantTx<'_>, tariff: Tariff) -> Result<bool, StoreError> {
    // `$n::float8::numeric`: the parameter arrives as float8 and lands in a
    // NUMERIC column by an explicit cast, so `0.30` is stored as `0.3`, not as
    // the float's 17-digit expansion.
    let written = sqlx::query(
        "UPDATE tenant_model_access SET \
           usd_per_mtok_input      = $1::float8::numeric, \
           usd_per_mtok_output     = $2::float8::numeric, \
           usd_per_mtok_cache_read = $3::float8::numeric, \
           updated_at = now()",
    )
    .bind(tariff.usd_per_mtok_input)
    .bind(tariff.usd_per_mtok_output)
    .bind(tariff.usd_per_mtok_cache_read)
    .execute(&mut ***tx)
    .await?;
    Ok(written.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use chrono::SubsecRound;

    use super::*;
    use crate::db::Db;

    /// A database with the migrations applied, and one tenant in it.
    async fn fixture() -> Option<(Db, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; model_access needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");

        Some((db.clone(), seed_tenant(&db).await))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'model access test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("ma-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    #[tokio::test]
    async fn an_unconnected_tenant_reads_as_none_and_a_reconnect_replaces_the_row() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        // `timestamptz` holds microseconds, and this compares a `verified_at`
        // it made against the one it reads back, so the clock has to be one the
        // column can hold. `capability.rs` carries why this was green on macOS
        // and red on Linux for as long as it existed.
        let now = Utc::now().trunc_subsecs(6);

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        assert!(load(&mut tx).await.expect("load").is_none());

        let first = ModelAccess {
            path: ModelPath::ApiKey,
            model: ModelId::Opus5,
            verified_at: now,
        };
        save(&mut tx, &first, Some(b"sealed-one"), now)
            .await
            .expect("save");
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.access, first);
        assert_eq!(read.sealed_key.as_deref(), Some(&b"sealed-one"[..]));

        // Reconnecting on the other path replaces rather than adding: one
        // credential per tenant, enforced by the primary key. And the key goes
        // with it — a `cli` row that kept the previous key would be a credential
        // nothing reads and nobody can see, which 0050's CHECK forbids.
        let second = ModelAccess {
            path: ModelPath::Cli,
            model: ModelId::Haiku45,
            verified_at: now + chrono::Duration::seconds(30),
        };
        save(&mut tx, &second, None, now).await.expect("save");
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.access, second);
        assert_eq!(read.sealed_key, None, "the replaced key is gone with it");

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenant_model_access")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        assert_eq!(count, 1);
        tx.commit().await.expect("commit");
    }

    /// **A row may not claim a connection this deployment cannot prove.**
    ///
    /// The invariant `0050_tenant_model_key` exists for, asked of the database
    /// rather than of the code that usually writes it — because the row that
    /// caused the outage was written by correct code and only became a lie when
    /// the process holding the other half restarted. A constraint has no other
    /// half.
    ///
    /// Both directions, and the second is not decoration: a `cli` row carrying a
    /// credential is a key nothing will ever read and nobody can ever see, which
    /// is the shape `connect`'s narrowing exists to prevent and which only the
    /// table can enforce against a `psql` session.
    #[tokio::test]
    async fn the_table_refuses_an_api_key_row_with_no_key_and_a_cli_row_with_one() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let now = Utc::now();

        for (path, sealed, what) in [
            (ModelPath::ApiKey, None, "api_key with no credential"),
            (ModelPath::Cli, Some(&b"x"[..]), "cli carrying a credential"),
            (ModelPath::ApiKey, Some(&b""[..]), "an empty envelope"),
        ] {
            let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
            let refused = save(
                &mut tx,
                &ModelAccess {
                    path,
                    model: ModelId::Opus5,
                    verified_at: now,
                },
                sealed,
                now,
            )
            .await;
            let err = refused.err().unwrap_or_else(|| panic!("{what} was stored"));
            assert!(
                err.to_string()
                    .contains("tenant_model_access_key_matches_path"),
                "{what}: {err}"
            );
            tx.rollback().await.expect("rollback");
        }
    }

    /// A row this build cannot read stops the read. See the module docs: the
    /// alternative reads as "nobody connected a model", which is a different
    /// sentence with a different remedy.
    ///
    /// No database, on purpose. [`load`] is `fetch_optional` and then this
    /// function, so the only thing a database adds here is the twenty lines of
    /// `ALTER TABLE … DROP CONSTRAINT` it would take to write a `path` the check
    /// constraint exists to refuse — which would be a test of the belt getting
    /// in the way of the braces.
    #[test]
    fn a_path_or_a_model_this_build_does_not_know_refuses_the_read() {
        let now = Utc::now();
        let row = |path: &str, model: &str| Row {
            path: path.to_owned(),
            verified_model: model.to_owned(),
            verified_at: now,
            sealed_key: Some(b"sealed".to_vec()),
            usd_per_mtok_input: None,
            usd_per_mtok_output: None,
            usd_per_mtok_cache_read: None,
        };

        let read = row("api_key", "claude-opus-5")
            .into_connection()
            .expect("parses");
        assert_eq!(
            read.access,
            ModelAccess {
                path: ModelPath::ApiKey,
                model: ModelId::Opus5,
                verified_at: now,
            }
        );
        assert_eq!(read.sealed_key.as_deref(), Some(&b"sealed"[..]));

        for (path, model, needle) in [
            ("bedrock", "claude-opus-5", "bedrock"),
            ("api_key", "gpt-5", "gpt-5"),
        ] {
            let err = row(path, model).into_connection().expect_err("must refuse");
            assert!(
                matches!(&err, StoreError::Conflict(msg) if msg.contains(needle)),
                "{path}/{model}: {err}"
            );
        }
    }

    /// `Debug` says how many bytes, never which. See [`Connection`]'s own impl:
    /// the envelope is not a secret, but a hundred bytes of it in every log line
    /// that renders an assignment is noise somebody has to re-audit as harmless.
    ///
    /// **The instant is fixed, and it is not decoration.** The second assertion
    /// scans the *whole* rendering for `171` — `0xAB`, what a derived `Debug`
    /// prints for each byte — and `verified_at` is the only other thing in that
    /// string made of digits. A clock puts six fractional digits there on macOS
    /// and nine on Linux, so `171` lands in the search space on its own: four
    /// three-digit windows, or seven, each one chance in a thousand. Measured
    /// under `Utc::now()`: 8 failures in 3 000 runs here, ~7 in 1 000 on a
    /// nanosecond clock — a leak reported where there was none, rare enough that
    /// the run gets restarted rather than read. Nothing here needs the time of
    /// day; put `Utc::now()` back and the flake comes back with it.
    #[test]
    fn debug_gives_the_length_of_the_envelope_and_not_its_bytes() {
        let rendered = format!(
            "{:?}",
            Connection {
                access: ModelAccess {
                    path: ModelPath::ApiKey,
                    model: ModelId::Opus5,
                    verified_at: DateTime::from_timestamp(1_700_000_000, 0).expect("an instant"),
                },
                sealed_key: Some(vec![0xAB; 96]),
                tariff: None,
            }
        );
        assert!(rendered.contains("96 bytes"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
    }

    /// RLS, not a `WHERE` anybody has to remember. Another tenant's connection
    /// is not merely unlisted; it is invisible.
    #[tokio::test]
    async fn one_tenants_connection_is_invisible_to_another() {
        let Some((db, mine)) = fixture().await else {
            return;
        };
        let theirs = seed_tenant(&db).await;

        let now = Utc::now();
        let access = ModelAccess {
            path: ModelPath::ApiKey,
            model: ModelId::Sonnet5,
            verified_at: now,
        };
        let mut tx = db.tenant_tx(mine).await.expect("tx");
        save(&mut tx, &access, Some(b"sealed-mine"), now)
            .await
            .expect("save");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        assert!(
            load(&mut tx).await.expect("load").is_none(),
            "the row and the credential are invisible together, because they are one row"
        );
        tx.commit().await.expect("commit");

        // And a tenant cannot file a row wearing somebody else's id: the policy
        // is `with check`, so the INSERT below is refused by the database.
        //
        // Deliberately the `cli` path, which needs no `sealed_key`. On
        // `api_key` this statement would now also violate 0050's CHECK, and the
        // assertion below would go green on a constraint that has nothing to do
        // with tenant isolation — a test that stopped testing what it names.
        let mut tx = db.tenant_tx(theirs).await.expect("tx");
        let forged = sqlx::query(
            "INSERT INTO tenant_model_access (tenant_id, path, verified_model, verified_at) \
             VALUES ($1, 'cli', 'claude-opus-5', now())",
        )
        .bind(mine.as_uuid())
        .execute(&mut **tx)
        .await;
        let err = forged.expect_err("with check must refuse a forged tenant_id");
        assert!(
            err.to_string().contains("row-level security"),
            "the refusal has to be RLS, not a check constraint: {err}"
        );
        tx.rollback().await.expect("rollback");
    }

    /// The tariff survives a reconnect, is null until declared, and comes back
    /// as the decimal that went in — `0.30` and not the float's expansion.
    #[tokio::test]
    async fn a_declared_tariff_outlives_a_reconnect_and_needs_a_row_to_land_on() {
        let Some((db, tenant_id)) = fixture().await else {
            return;
        };
        let now = Utc::now();
        let tariff = Tariff {
            usd_per_mtok_input: Some(3.0),
            usd_per_mtok_output: Some(15.0),
            usd_per_mtok_cache_read: Some(0.30),
        };

        let mut tx = db.tenant_tx(tenant_id).await.expect("tx");
        assert!(
            !set_tariff(&mut tx, tariff).await.expect("set"),
            "no connection, nothing to write on"
        );

        let cli = ModelAccess {
            path: ModelPath::Cli,
            model: ModelId::Opus5,
            verified_at: now,
        };
        save(&mut tx, &cli, None, now).await.expect("save");
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.tariff, None, "not declared is null, not zero");
        assert_eq!(CostSource::of(Some(&read)), CostSource::NoTariff);

        assert!(set_tariff(&mut tx, tariff).await.expect("set"));
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.tariff, Some(tariff));
        assert_eq!(
            CostSource::of(Some(&read)),
            CostSource::DeclaredTariffOnCliPath
        );
        let stored: String =
            sqlx::query_scalar("SELECT usd_per_mtok_cache_read::text FROM tenant_model_access")
                .fetch_one(&mut **tx)
                .await
                .expect("text");
        assert_eq!(stored, "0.3", "NUMERIC holds the decimal, not the float");

        // Reconnecting on the key path replaces the proof and keeps the rate.
        save(
            &mut tx,
            &ModelAccess {
                path: ModelPath::ApiKey,
                ..cli
            },
            Some(b"sealed"),
            now,
        )
        .await
        .expect("save");
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.tariff, Some(tariff));
        assert_eq!(CostSource::of(Some(&read)), CostSource::DeclaredTariff);

        // A partial redeclaration nulls what it does not name.
        let partial = Tariff {
            usd_per_mtok_input: Some(1.0),
            ..Tariff::default()
        };
        assert!(set_tariff(&mut tx, partial).await.expect("set"));
        let read = load(&mut tx).await.expect("load").expect("connected");
        assert_eq!(read.tariff, Some(partial));
        assert!(!partial.is_complete());
        tx.rollback().await.expect("rollback");
    }
}
