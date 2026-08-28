//! `appointments`: the diary, in SQL and with no opinion about it.
//!
//! `migrations/0063_appointments.sql` carries the argument for why the row has
//! three columns that matter, why the time zone is one of them, and why this is
//! not `outbox_events` with `available_at` in the future. This module is the
//! four statements underneath it: promise a moment, read one seat's outstanding
//! promises, read the whole company's, and ring whatever has come round.
//!
//! # Why the tenant is never a parameter, and why the employee always is
//!
//! [`book`], [`upcoming`] and [`diary`] take a [`TenantTx`] and nothing else for
//! [`crate::backlog`]'s reason: the tenant is the one `SET LOCAL app.tenant_id`
//! on that transaction, and a `tenant_id` argument beside it would be a second
//! answer to a question that already has one.
//!
//! [`claim_due`] takes a bare `PgConnection` instead, because ringing every
//! company's due appointments is its whole job — the same documented exception
//! [`crate::initiative::claim_due`] and [`crate::outbox::claim`] take, and the
//! reason `0063`'s policy still binds every connection the API serves.
//!
//! # Why the local time is rendered here and not in Rust
//!
//! `to_char(at AT TIME ZONE at_zone, …)` is one expression in one place, and it
//! is here because **PostgreSQL is the only tzdata this deployment has.** The
//! workspace has `chrono` and not `chrono-tz`, so rendering an instant in an
//! arbitrary IANA zone in Rust would mean a new dependency for a job the
//! database already does — and doing it in the database keeps the rendering next
//! to the CHECK that decides which zone names are real.
//!
//! It is ISO and locale-free (`YYYY-MM-DD HH24:MI`) on purpose. `to_char`'s
//! `Dy` and `Mon` read the server's `lc_time`, so a deployment whose locale
//! changed would start writing a different sentence into an employee's brief
//! with nothing else changed.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use sqlx::Row;
use sqlx::postgres::PgRow;

use agentos_domain::ids::{AppointmentId, EmployeeId, TenantId};

use crate::db::{StoreError, TenantTx};

/// The longest subject `appointments_subject_shape` accepts, named once so
/// nothing upstream invents a second number.
///
/// [`crate::backlog::MAX_TITLE`]'s argument, for the other table, and the cost
/// of not having had it was the same: the constraint is
/// `char_length(btrim(subject)) between 1 and 200`, so an over-long line is a
/// `23514` out of the driver, which [`StoreError`] classifies as `Database`,
/// which ends whatever turn wrote it. Characters and not bytes, for
/// `MAX_TITLE`'s reason.
pub const MAX_SUBJECT: usize = 200;

/// One row of `appointments`.
///
/// `subject` is a plain `String` here and is wrapped by
/// [`agentos_app::calendar`](../../agentos_app/calendar/index.html) on the way
/// to a turn, not here: this crate speaks SQL, and the trust boundary is a
/// decision about a *reader*, taken where the reader is. Same split
/// [`crate::backlog::Item::title`] makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appointment {
    /// The appointment.
    pub id: AppointmentId,
    /// Whose moment it is.
    pub employee_id: EmployeeId,
    /// The instant. This is what fires.
    pub at: DateTime<Utc>,
    /// Whose Tuesday: the IANA zone the promise was made in.
    pub zone: String,
    /// [`Appointment::at`] as it was promised — wall time in
    /// [`Appointment::zone`], rendered by the database. Ours, not a
    /// counterparty's: a formatted timestamp.
    pub local_time: String,
    /// What the moment is about, in one line.
    pub subject: String,
    /// When the moment stopped being a promise. `None` is still ahead; a value
    /// earlier than [`Appointment::at`] is a cancellation, and one later is a
    /// promise kept — see `0063`.
    pub rang_at: Option<DateTime<Utc>>,
    /// When it was written down.
    pub created_at: DateTime<Utc>,
}

/// An appointment that has just been rung, and whose ring is already recorded.
///
/// The parallel of [`crate::initiative::Due`], and the difference between the
/// two types is the difference between the two claims: a `Due` carries the
/// **next** deadline the claim wrote, because a rhythm has a next beat, and this
/// carries the instant that was promised and nothing about a future one,
/// because an appointment has no next.
#[derive(Debug, Clone)]
pub struct Kept {
    /// The appointment that rang.
    pub id: AppointmentId,
    /// Which company it belongs to, taken from the `appointments` row. The
    /// claim is cross-tenant, so the caller has to re-scope itself with this
    /// before touching anything else.
    pub tenant_id: TenantId,
    /// Whose moment it was.
    pub employee_id: EmployeeId,
    /// The instant that was promised.
    pub at: DateTime<Utc>,
    /// The IANA zone it was promised in.
    pub zone: String,
    /// The promised instant as wall time in [`Kept::zone`].
    pub local_time: String,
    /// What was promised, in the words of whoever promised it. Wrapped in
    /// [`Untrusted`](agentos_domain::untrusted::Untrusted) by its reader.
    pub subject: String,
}

/// The columns, in one spelling, so the statements below cannot disagree about
/// what a row is.
///
/// Interpolated, so every statement here goes through `sqlx::AssertSqlSafe`.
/// **The audit that asks for is this sentence**, and it is [`crate::backlog`]'s:
/// both halves are compile-time constants of this module, nothing a caller
/// passes reaches the string — every value is a bind parameter — so there is no
/// input for an injection to arrive on.
const COLUMNS: &str = "id, employee_id, at, at_zone, \
                       to_char(at AT TIME ZONE at_zone, 'YYYY-MM-DD HH24:MI') AS local_time, \
                       subject, rang_at, created_at";

/// One row, decoded. By reference so both reads can name it in a `map`.
fn row_of(row: &PgRow) -> Appointment {
    Appointment {
        id: AppointmentId::from_uuid(row.get("id")),
        employee_id: EmployeeId::from_uuid(row.get("employee_id")),
        at: row.get("at"),
        zone: row.get("at_zone"),
        local_time: row.get("local_time"),
        subject: row.get("subject"),
        rang_at: row.get("rang_at"),
        created_at: row.get("created_at"),
    }
}

/// Does this server's tzdata know this name?
///
/// Asked before [`book`] rather than left to the table's CHECK, and the
/// difference is what the caller is told. The CHECK raises `22023` from inside
/// `timezone()`, which arrives as an opaque driver error; this answers `false`,
/// which [`agentos_app::calendar`](../../agentos_app/calendar/index.html) turns
/// into a 400 naming the field. The CHECK stays anyway, for `0020`'s reason: a
/// row is also reachable by psql.
///
/// `pg_timezone_names` is a system view every role may read, and it is not
/// tenant data — there is nothing here for the policy to confine.
pub async fn zone_is_real(tx: &mut TenantTx<'_>, zone: &str) -> Result<bool, StoreError> {
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)")
            .bind(zone)
            .fetch_one(&mut ***tx)
            .await?;
    Ok(known)
}

/// Promise one moment.
///
/// The id is the caller's, not this function's: nothing in this crate reads the
/// clock (see [`agentos_domain::ids`]), and a caller that already holds the id
/// can write it into an audit row in the same transaction.
///
/// # Why the `EXISTS` clause is not what the foreign key already does
///
/// `appointments.employee_id references employees (id)` is checked by Postgres
/// as the table's *owner*, which walks past row-level security — so the
/// constraint alone accepts any employee uuid in the whole deployment. Two
/// things then go wrong at once, and the second is worse here than it is on
/// `work_items`: the insert succeeding is an existence oracle for another
/// company's employee id, and **the row it writes is a way to make another
/// company's employee take a turn at an hour you chose.** A work item filed
/// across the boundary sits there; an appointment filed across the boundary
/// rings.
///
/// The `EXISTS` runs inside *this* transaction, where `employees` is already
/// confined by the policy, so an employee that is not this company's makes the
/// `SELECT` produce no row and this return [`StoreError::NotFound`] — the same
/// silence a read of somebody else's appointment keeps.
pub async fn book(
    tx: &mut TenantTx<'_>,
    id: AppointmentId,
    employee: EmployeeId,
    at: DateTime<Utc>,
    zone: &str,
    subject: &str,
) -> Result<Appointment, StoreError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO appointments (id, tenant_id, employee_id, at, at_zone, subject) \
         SELECT $1, $2, $3, $4, $5, $6 \
          WHERE EXISTS (SELECT 1 FROM employees WHERE id = $3) \
         RETURNING {COLUMNS}"
    )))
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(employee.as_uuid())
    .bind(at)
    .bind(zone)
    .bind(subject)
    .fetch_optional(&mut ***tx)
    .await?
    .ok_or(StoreError::NotFound)?;
    Ok(row_of(&row))
}

/// What one seat has promised and not yet kept, soonest first.
///
/// Outstanding only: an appointment that has rung is a record, and a diary that
/// showed it back to the employee that kept it would be telling it to keep it
/// again.
///
/// ponytail: no `LIMIT`. A diary is a thing a human types into by hand, and the
/// same FOUNDER'S QUESTION `loops::initiative::waiting` leaves open applies
/// here — how much of it may one turn be shown before it costs more in tokens
/// than it saves in rediscovery? The place for the answer is the `LIMIT` this
/// read does not have.
pub async fn upcoming(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
) -> Result<Vec<Appointment>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM appointments \
         WHERE employee_id = $1 AND rang_at IS NULL \
         ORDER BY at ASC, id ASC"
    )))
    .bind(employee.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// Every appointment this company has, rung and outstanding, soonest first.
///
/// The founder's read, and it deliberately shows both halves for
/// `routes::work::board`'s reason: what somebody wants to know at the top of the
/// week is what is coming *and* what was kept, and a diary that hid the second
/// half would make the first look like nothing had happened.
///
/// ponytail: no pagination and no window. Same argument as [`upcoming`].
pub async fn diary(tx: &mut TenantTx<'_>) -> Result<Vec<Appointment>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM appointments ORDER BY at ASC, id ASC"
    )))
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(row_of).collect())
}

/// Ring whatever has come round: at most `limit` appointments, at most one per
/// company, each marked rung by the statement that hands it out.
///
/// # The three ways this is [`crate::initiative::claim_due`] and the two ways it
/// is not
///
/// Same: the claim is what marks the work taken, so a worker killed mid-turn
/// costs the appointment rather than spinning on it, and this needs no lease, no
/// heartbeat and no reaper. Same `FOR UPDATE … SKIP LOCKED`, so two replicas on
/// one database is a supported configuration. Same halt window through
/// [`not_stopped!`](crate::not_stopped) and the same `lifecycle = 'active'`
/// filter, because a stopped company and a suspended seat must not be woken by
/// anything, a promise included.
///
/// Not the same, and both differences are the difference between a rhythm and a
/// promise:
///
/// * **It consumes rather than advances.** `employee_initiative`'s claim writes
///   the *next* deadline; this writes `rang_at`, which is what stops the row
///   ringing twice and is the only state it has.
/// * **It starts from `appointments` and never touches `employee_initiative`.**
///   An employee that keeps a promise need not have a cadence at all — 0020 says
///   chartered-and-unscheduled is the ordinary state — so a claim that began at
///   the schedule could not reach the seats this exists for.
///
/// # Fairness, in one `DISTINCT ON` instead of a lateral
///
/// `0052`'s defect, avoided rather than repeated: a claim ordered on the due
/// instant across every company hands the whole batch to whoever has the most
/// due rows, and the customer's only symptom is that their company does not act.
/// `DISTINCT ON (tenant_id)` is a stronger answer than `0046`'s round-robin and
/// a much shorter one — **at most one appointment per company per claim**, so
/// nobody can queue in front of anybody. It is affordable here and would not be
/// on the outbox: a company has a handful of appointments a day, not a stream of
/// effects, and one per tick at the initiative loop's five-second idle is 720 an
/// hour.
///
/// ponytail: the `DISTINCT ON` reads every due row to dedupe them, where a
/// `CROSS JOIN LATERAL` from `tenants` would read one per company. It is an
/// index-only scan of a partial index over rows that are due *now*, which is a
/// human-scale set; swap in `0052`'s lateral the day a plan says otherwise.
pub async fn claim_due(
    conn: &mut PgConnection,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<Kept>, StoreError> {
    let rows = sqlx::query(concat!(
        "WITH seated AS MATERIALIZED ( \
             SELECT DISTINCT ON (a.tenant_id) a.id, a.at \
               FROM appointments a \
               JOIN employees e ON e.id = a.employee_id AND e.tenant_id = a.tenant_id \
              WHERE a.rang_at IS NULL \
                AND a.at <= $1::timestamptz \
                AND e.lifecycle = $3::text \
                AND ",
        crate::not_stopped!("a.tenant_id"),
        " \
              ORDER BY a.tenant_id, a.at, a.id \
         ), due AS MATERIALIZED ( \
             SELECT a2.id \
               FROM seated s \
               JOIN appointments a2 ON a2.id = s.id \
              WHERE a2.rang_at IS NULL \
              ORDER BY s.at, s.id \
                FOR UPDATE OF a2 SKIP LOCKED \
              LIMIT $2::bigint) \
         UPDATE appointments AS a SET rang_at = $1::timestamptz \
           FROM due d \
          WHERE a.id = d.id \
        RETURNING a.id, a.tenant_id, a.employee_id, a.at, a.at_zone, \
                  to_char(a.at AT TIME ZONE a.at_zone, 'YYYY-MM-DD HH24:MI') AS local_time, \
                  a.subject",
    ))
    .bind(now)
    .bind(limit)
    // Bound rather than written as a literal, so the spelling stays tied to
    // `Lifecycle::as_str` and a rename is a compile error somewhere rather than
    // a claim that silently rings nothing. `crate::initiative::claim_due` binds
    // it the same way for the same reason.
    .bind(agentos_domain::employee::Lifecycle::Active.as_str())
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows
        .iter()
        .map(|row| Kept {
            id: AppointmentId::from_uuid(row.get("id")),
            tenant_id: TenantId::from_uuid(row.get("tenant_id")),
            employee_id: EmployeeId::from_uuid(row.get("employee_id")),
            at: row.get("at"),
            zone: row.get("at_zone"),
            local_time: row.get("local_time"),
            subject: row.get("subject"),
        })
        .collect())
}

/// Settle every promise one seat has left outstanding and cannot now keep.
/// Returns how many rows were settled.
///
/// # The board's problem, and deliberately not the board's answer
///
/// [`crate::backlog::unassign_all`] is the twin of this and they do opposite
/// things, because `0063` already decided the difference and this is only the
/// `UPDATE` side of that decision. A work item is work **the company** wants
/// done, so it goes back on a board somebody else reads. An appointment is a
/// moment **this seat** undertook: `employee_id` is NOT NULL, there is no
/// spelling of an unassigned appointment, and 0063's own words are that "nothing
/// else can keep it". Handing it to a manager would need a rule nobody has
/// written — the founder has not said that a line manager inherits an hour, and
/// `org::manager_of` answering the question is not the same as him answering it.
/// `inbound::may_message` and `directs` are the only places the chart carries
/// authority today and both are about *reaching* somebody, never about
/// *becoming* them.
///
/// What is left is the row itself, and left alone it is a lie. `claim_due`
/// filters `lifecycle = 'active'`, so a terminated seat's appointment can never
/// ring; `rang_at` stays NULL forever, and NULL is the value [`diary`] renders
/// to the founder as *still ahead*. So the promise is **settled** here, using
/// the only vocabulary `0063` gave: `rang_at` written **before** `at` is a
/// cancellation, and no second column is needed.
///
/// `at > $2` is what keeps this honest, and it is the reason this is not simply
/// "everything still NULL". `rang_at` **after** `at` means *kept late* — the gap
/// between the two is the only thing in the schema that can say a promise was
/// kept at all — so stamping `now` onto a moment that has already gone by would
/// forge a record that somebody did something. A past-due promise of a departed
/// seat keeps its NULL and stays visibly overdue in the diary, which is a
/// smaller untruth than a manufactured "kept": nobody is credited with anything.
///
/// Termination only, in the transaction that writes it, for
/// [`crate::backlog::unassign_all`]'s reason. A suspension is reversible, and a
/// seat that comes back keeps the hours it promised — late, and told so by
/// `kept_brief`.
pub async fn cancel_outstanding(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let settled = sqlx::query(
        "UPDATE appointments SET rang_at = $2 \
          WHERE employee_id = $1 AND rang_at IS NULL AND at > $2",
    )
    .bind(employee.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use chrono::{SubsecRound, TimeDelta};

    use super::*;
    use crate::db::Db;

    async fn fixture() -> Option<(Db, TenantId, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the diary needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let a = seed_tenant(&db).await;
        let b = seed_tenant(&db).await;
        Some((db, a, b))
    }

    async fn seed_tenant(db: &Db) -> TenantId {
        let tenant_id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'diary test')")
            .bind(tenant_id.as_uuid())
            .bind(format!("cal-{}", tenant_id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("insert tenant");
        admin.commit().await.expect("commit");
        tenant_id
    }

    async fn seed_employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!(
            "{slug}-{}",
            &id.as_uuid().simple().to_string()[..8]
        ))
        .bind(slug)
        .execute(&mut *admin)
        .await
        .expect("insert employee");
        admin.commit().await.expect("commit");
        id
    }

    /// Turn a seat off. `lifecycle` is the column [`claim_due`] joins on, and
    /// the product's own suspension path writes exactly this.
    async fn suspend(db: &Db, employee: EmployeeId) {
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("UPDATE employees SET lifecycle = 'suspended' WHERE id = $1")
            .bind(employee.as_uuid())
            .execute(&mut *admin)
            .await
            .expect("suspend");
        admin.commit().await.expect("commit");
    }

    /// **The whole of "promise an hour", in one run**: a moment is written down
    /// with the zone it was promised in, it survives the transaction that wrote
    /// it, the claim rings it exactly once at the instant it names, and the
    /// instant is rendered back in the words the promise was made in.
    ///
    /// The zone half is the point of the test rather than decoration. Two
    /// appointments are booked **at the same instant** in two zones; a schema
    /// that stored only `timestamptz` could not tell them apart afterwards, and
    /// this asserts that it can.
    #[tokio::test]
    async fn a_promised_moment_rings_once_and_says_itself_back_in_its_own_zone() {
        let Some((db, tenant, _)) = fixture().await else {
            return;
        };
        let ada = seed_employee(&db, tenant, "ada-diary").await;
        let dormant = seed_employee(&db, tenant, "dormant-diary").await;
        suspend(&db, dormant).await;
        let now = Utc::now().trunc_subsecs(6);
        // 2026-09-01 13:00Z is 15:00 in Vienna and 15:00 in Paris — the same
        // instant, and it is the pair that is *not* the same that matters.
        let instant = DateTime::parse_from_rfc3339("2026-09-01T13:00:00Z")
            .expect("literal")
            .with_timezone(&Utc);

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            zone_is_real(&mut tx, "Europe/Vienna").await.expect("zone"),
            "a real IANA name is real"
        );
        assert!(
            !zone_is_real(&mut tx, "Mars/Olympus").await.expect("zone"),
            "…and an invented one is refused before the row is attempted"
        );

        // A seat that has been turned off, holding the company's *earliest* due
        // promise. `DISTINCT ON (tenant_id)` offers one appointment per company
        // and takes the soonest, so if the lifecycle filter did not bite, this
        // row would be the one handed out and Ada's would not — which makes the
        // assertion below a proof of the filter rather than a description of it.
        // An hour earlier, so the ordering is not a coincidence.
        let ignored = book(
            &mut tx,
            AppointmentId::new_v7(now),
            dormant,
            instant - TimeDelta::hours(1),
            "Europe/Vienna",
            "a promise nobody is left to keep",
        )
        .await
        .expect("book");

        let vienna = book(
            &mut tx,
            AppointmentId::new_v7(now),
            ada,
            instant,
            "Europe/Vienna",
            "call back about the tariff code",
        )
        .await
        .expect("book");
        // The same instant, promised to somebody in Tokyo. `timestamptz` alone
        // could not tell these two rows apart.
        //
        // The id is stamped a millisecond later on purpose, and it is not
        // decoration: both reads order `at ASC, id ASC`, so two appointments at
        // the *same* instant are ordered by their ids — and two UUIDv7s stamped
        // from one `now` differ only in their random bits, which is a coin toss
        // rather than an order. A real caller stamps each id when it writes it;
        // this does the same thing explicitly so the assertions below are about
        // the statements and not about entropy.
        let tokyo = book(
            &mut tx,
            AppointmentId::new_v7(now + TimeDelta::milliseconds(1)),
            ada,
            instant,
            "Asia/Tokyo",
            "call back about the freight quote",
        )
        .await
        .expect("book");
        tx.commit().await.expect("commit");

        assert_eq!(
            vienna.local_time, "2026-09-01 15:00",
            "the promise says itself back in the zone it was made in"
        );
        assert_eq!(
            tokyo.local_time, "2026-09-01 22:00",
            "…and the same instant is a different sentence to somebody else"
        );

        // Read back in another transaction, which is the whole of "the promise
        // outlives the turn that made it".
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            upcoming(&mut tx, ada)
                .await
                .expect("upcoming")
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>(),
            vec![vienna.id, tokyo.id],
            "both are outstanding, soonest first"
        );
        tx.rollback().await.expect("rollback");

        // Nothing rings before its instant — **and the suspended seat's promise,
        // which is already an hour overdue, does not ring here either.**
        //
        // The second half of that sentence is in this claim rather than only in
        // the one further down, and it is not tidiness: it was written the other
        // way first and it was green under a mutation that deleted the lifecycle
        // filter altogether. With the filter gone, `ignored` is due at *this*
        // instant, gets rung by *this* claim, and is therefore missing from the
        // later one for a reason that has nothing to do with being suspended. An
        // assertion that only looked at the later claim could not tell the two
        // stories apart.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let early = claim_due(&mut admin, 8, instant - TimeDelta::seconds(1))
            .await
            .expect("claim");
        admin.commit().await.expect("commit");
        assert!(
            early
                .iter()
                .all(|k| k.employee_id != ada && k.employee_id != dormant),
            "an appointment a second away has not come round, and a suspended \
             seat's — which is an hour overdue — must not ring at all: {:?}",
            early.iter().map(|k| k.id).collect::<Vec<_>>()
        );

        // **And nothing rings for a company that has been stopped.** The
        // `not_stopped!` predicate is one line of a macro and is the kind of
        // line that compiles, produces valid SQL, and quietly filters nothing —
        // so it is asserted rather than read. It also matters more here than on
        // the other three claims: the founder who threw the switch expects the
        // company to go quiet, and an appointment ringing through it is the
        // company acting after being told to stop.
        //
        // Asserted at the instant that is about to ring, and then released, so
        // everything below is the ordinary path.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO company_halts (tenant_id, reason, halted_by) \
             VALUES ($1, 'testing the stop', 'ops-test')",
        )
        .bind(tenant.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("halt");
        admin.commit().await.expect("commit");

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let during_halt = claim_due(&mut admin, 8, instant).await.expect("claim");
        admin.commit().await.expect("commit");
        assert!(
            during_halt.iter().all(|k| k.employee_id != ada),
            "a stopped company's promises must not ring: {:?}",
            during_halt.iter().map(|k| k.id).collect::<Vec<_>>()
        );

        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("DELETE FROM company_halts WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *admin)
            .await
            .expect("release");
        admin.commit().await.expect("commit");

        // …and it defers rather than refusing: the promise is still outstanding
        // once the company is let go, with nothing to replay and nothing to
        // repair. That is the property `not_stopped!`'s own docs demand of every
        // caller, and it is free here only because the halt made the claim *not
        // select* the row rather than select it and drop it.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert_eq!(
            upcoming(&mut tx, ada).await.expect("upcoming").len(),
            2,
            "a halt defers a promise, it does not consume it"
        );
        tx.rollback().await.expect("rollback");

        // …and at the instant, one per company per claim, rung and recorded.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let rung = claim_due(&mut admin, 8, instant).await.expect("claim");
        admin.commit().await.expect("commit");
        let mine: Vec<_> = rung.iter().filter(|k| k.employee_id == ada).collect();
        assert_eq!(
            mine.len(),
            1,
            "at most one appointment per company per claim: {:?}",
            mine.iter().map(|k| k.id).collect::<Vec<_>>()
        );
        assert_eq!(
            mine[0].id, vienna.id,
            "the soonest of the company's is rung"
        );
        assert_eq!(mine[0].local_time, "2026-09-01 15:00");
        // …and the soonest of all was the suspended seat's, which is why the
        // line above is a proof of the lifecycle filter. A seat somebody turned
        // off must not be woken by a promise it made while it was on.
        assert!(
            rung.iter().all(|k| k.id != ignored.id),
            "a suspended seat's promise must not ring, and it was the earliest \
             one this company had"
        );

        // Rung once. A second claim at the same instant must not hand it out
        // again — this is `rang_at`, and it is the only thing standing between
        // a promise and a loop.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let again = claim_due(&mut admin, 8, instant).await.expect("claim");
        admin.commit().await.expect("commit");
        assert!(
            !again.iter().any(|k| k.id == vienna.id),
            "an appointment that rang does not ring again"
        );
        assert!(
            again.iter().any(|k| k.id == tokyo.id),
            "…and the company's next one is now the one it gets"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        assert!(
            upcoming(&mut tx, ada).await.expect("upcoming").is_empty(),
            "a rung appointment is not a promise any more"
        );
        assert_eq!(
            diary(&mut tx)
                .await
                .expect("diary")
                .iter()
                .filter(|a| a.employee_id == ada)
                .count(),
            2,
            "…and is still in the diary: ringing is not forgetting"
        );
        let kept = diary(&mut tx)
            .await
            .expect("diary")
            .into_iter()
            .find(|a| a.id == vienna.id)
            .expect("the rung one");
        assert_eq!(
            kept.rang_at,
            Some(instant),
            "`rang_at` records when it actually rang, which is how a promise \
             kept late is visible at all"
        );
        tx.rollback().await.expect("rollback");
    }

    /// One company's diary is invisible to another, the isolation is asserted
    /// **from the catalogue** and not only from behaviour, and an appointment
    /// cannot be filed against somebody else's employee.
    ///
    /// The last of those is the one a foreign key cannot make, and it is sharper
    /// here than it is on `work_items`: `references employees (id)` is checked
    /// as the table's owner and would accept another company's seat, which on
    /// this table is a way to make their employee take a turn at an hour you
    /// chose.
    #[tokio::test]
    async fn a_diary_is_one_company_s_and_the_catalogue_says_so() {
        let Some((db, a, b)) = fixture().await else {
            return;
        };
        let now = Utc::now().trunc_subsecs(6);
        let ada = seed_employee(&db, a, "ada-isolated").await;

        let mut tx = db.tenant_tx(a).await.expect("tx a");
        let mine = book(
            &mut tx,
            AppointmentId::new_v7(now),
            ada,
            now + TimeDelta::hours(1),
            "Europe/Paris",
            "A's call",
        )
        .await
        .expect("book");
        tx.commit().await.expect("commit");

        let mut tx = db.tenant_tx(b).await.expect("tx b");
        assert!(
            diary(&mut tx).await.expect("diary").is_empty(),
            "B must not see A's diary"
        );
        assert!(
            upcoming(&mut tx, ada).await.expect("upcoming").is_empty(),
            "…nor read one of A's seats' promises by naming it"
        );
        assert!(
            matches!(
                book(
                    &mut tx,
                    AppointmentId::new_v7(now),
                    ada,
                    now + TimeDelta::hours(1),
                    "Europe/Paris",
                    "wake A's employee at an hour I chose",
                )
                .await,
                Err(StoreError::NotFound)
            ),
            "an employee from another company must be refused, not filed: the \
             foreign key would have accepted this"
        );
        tx.rollback().await.expect("rollback");

        // A's own row is untouched by any of that.
        let mut tx = db.tenant_tx(a).await.expect("tx a");
        assert_eq!(
            diary(&mut tx)
                .await
                .expect("diary")
                .iter()
                .map(|x| x.id)
                .collect::<Vec<_>>(),
            vec![mine.id]
        );
        tx.rollback().await.expect("rollback");

        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = 'appointments'::regclass",
        )
        .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
        .await
        .expect("catalogue");
        assert!(enabled, "appointments has row-level security enabled");
        assert!(
            forced,
            "…and forced, or the owning role reads and writes every company's diary"
        );

        let deletable: bool =
            sqlx::query_scalar("SELECT has_table_privilege('app_role', 'appointments', 'DELETE')")
                .fetch_one(&mut *db.admin_tx_bypassing_rls().await.expect("admin"))
                .await
                .expect("privilege");
        assert!(
            !deletable,
            "app_role must not be able to delete a promise: cancelling is an UPDATE"
        );

        // And the zone CHECK, which is the psql-shaped hole `zone_is_real`
        // cannot close. Written as the owner, bypassing RLS and bypassing the
        // port, which is exactly the writer the constraint exists for.
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        let refused = sqlx::query(
            "INSERT INTO appointments (id, tenant_id, employee_id, at, at_zone, subject) \
             VALUES ($1, $2, $3, $4, 'Mars/Olympus', 'ring at a time nobody has')",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(a.as_uuid())
        .bind(ada.as_uuid())
        .bind(now)
        .execute(&mut *admin)
        .await;
        assert!(
            refused.is_err(),
            "a zone this server's tzdata does not know must not reach the table"
        );
    }
}
