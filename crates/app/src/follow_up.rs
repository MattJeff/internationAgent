//! La relance : a prospect who did not answer is written to again, without
//! anybody remembering to.
//!
//! That is the one thing a company pays a sequencer (Smartlead, Lemlist) for,
//! and everything it needs was already here. An employee can promise an hour
//! and be woken by it ([`crate::calendar`], `0063`); a reply has exactly one
//! door in (`inbound::land`); the gate already refuses a suppressed address
//! and already knows a contact it has written to before is not a new one. What
//! was missing was the reflex, and a reflex is a rule rather than an
//! intention — so it is code on the send path and not a sentence in the brief
//! asking the model to please remember.
//!
//! # The three statements, and where each one runs
//!
//! * **[`sent`] + [`schedule`]** — from [`Effects::chase`](crate::effects::Effects::chase),
//!   in one transaction, right after a `send_email` to somebody outside the
//!   company came back with a provider id. The send is recorded on its thread
//!   as an outbound `messages` row (the same thread a reply will land on, by
//!   `inbound::conversation_for`'s key), and a promise is booked
//!   [`FOLLOW_UP_AFTER`] out with the thread on it (`0082`).
//! * **`calendar::cancel_for_conversation`** — from `inbound::land`, in the
//!   transaction that lands a reply. The promise is settled in `0068`'s
//!   spelling and the employee is not woken for it.
//! * **[`brief`]** — from `loops::initiative`, when the promise rings: the turn
//!   is told, in our voice, that this hour is a follow-up and how long the
//!   silence has been. The model then proposes an ordinary `send_email`, which
//!   goes through the gate like any other — a suppression that arrived in the
//!   meantime refuses it there, and the contact reads as
//!   `ContactStanding::Known`, so the day's stranger budget is not charged a
//!   second time for the same person.
//!
//! # What is deliberately not here
//!
//! **No table and no verb.** The promise is an `appointments` row and the
//! chase is a `send_email` the model writes; the only schema change is the
//! column that lets a reply find the promise. **No text of theirs.** The
//! subject line is our word and a masked address, and the brief carries a
//! date; the address the model needs is inside the frame the wake already
//! shows it. **No opinion about the vertical's own chase.** `crate::vertical`
//! spaces its touches on `contacts.next_follow_up_at` with the same
//! [`FOLLOW_UP_AFTER`], through its own sender rather than through a turn's
//! `send_email`, so the two never meet on one thread.

use agentos_domain::action::EmailAddress;
use agentos_domain::ids::{AppointmentId, ConversationId, EmployeeId, TenantId};
use agentos_domain::message::Channel;
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError, TenantTx};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::inbound::{self, InboundError};
pub use crate::revenue::FOLLOW_UP_AFTER;

/// How many times one thread is chased after the first message, at most.
///
/// Counted from the thread's outbound messages and never from a column: the
/// approach is one, so a thread with three outbound rows has been chased twice
/// and is not chased again. It is `revenue::MAX_TOUCHES - 1` by construction
/// — the seller's sequence is "the approach and two follow-ups" — and named
/// separately because that is what this module counts.
///
/// ponytail: a constant, not a policy field, for `MAX_TOUCHES`'s reason.
/// Nobody who ignored three emails is waiting for a fourth. Make it a
/// `PolicyLimits` column the day a tenant has a counter-example.
pub const MAX_FOLLOW_UPS: usize = crate::revenue::MAX_TOUCHES - 1;

/// The zone a follow-up is promised in.
///
/// ponytail: UTC, because a follow-up has no "whose Tuesday" — nobody said
/// "three o'clock" to anybody; the instant is `now + 72h` and the zone is a
/// column `0063` refuses to leave empty. The prospect's zone is the upgrade,
/// the day `contacts` carries one.
const ZONE: &str = "UTC";

/// The one line the promise carries: our word and the masked address.
///
/// Nothing the model or the counterparty wrote reaches it — not the email's
/// subject, not the body — because `appointments.subject` is read back into a
/// brief, and `0080`'s argument for a ticket title holds for a promise.
pub fn subject(contact: &str) -> String {
    format!("follow up · {}", inbound::masked_contact(contact))
        .chars()
        .take(calendar::MAX_SUBJECT)
        .collect()
}

/// Record one outbound email on the thread it belongs to, and return the
/// thread.
///
/// The thread is `inbound::conversation_for`'s — one per `(employee, email,
/// address)` — so the reply, when it comes, lands on this same row and
/// `land` can settle the promise by it. The address is the parsed one off the
/// gate's token, lower-cased by `EmailAddress::parse` exactly as `contact_of`
/// lower-cases the sender of a reply, so the two spellings meet.
///
/// The idempotency key is the provider's message id: one send, one row,
/// however many times the recording is replayed.
pub async fn sent(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    to: &EmailAddress,
    subject: Option<&str>,
    provider_message_id: &str,
    now: DateTime<Utc>,
) -> Result<ConversationId, StoreError> {
    let contact = to.to_string();
    let conversation =
        inbound::conversation_for(tx, employee, Channel::Email, &contact, subject, now)
            .await
            .map_err(|err| match err {
                InboundError::Store(err) => err,
                other => StoreError::conflict(other.to_string()),
            })?;
    sqlx::query(
        "INSERT INTO messages \
             (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
              recipients, provider_message_id, subject, trust_label, idempotency_key, \
              received_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'outbound', '', $6, $7, $8, 'trusted', $9, $10, $10) \
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(tx.tenant_id().as_uuid())
    .bind(conversation.as_uuid())
    .bind(employee.as_uuid())
    .bind(Channel::Email.as_str())
    .bind(serde_json::json!([contact]))
    .bind(provider_message_id)
    .bind(subject)
    .bind(format!("sent:{provider_message_id}"))
    .bind(now)
    .execute(&mut ***tx)
    .await?;
    sqlx::query("UPDATE conversations SET last_message_at = $2, updated_at = $2 WHERE id = $1")
        .bind(conversation.as_uuid())
        .bind(now)
        .execute(&mut ***tx)
        .await?;
    Ok(conversation)
}

/// Promise to chase this thread [`FOLLOW_UP_AFTER`] from now, if it is still
/// a thread worth chasing. `None` when it is not, and that is not an error.
///
/// Not chased: a thread they have already answered on (this send is a reply,
/// and a reply is not an approach), and a thread that has had its
/// [`MAX_FOLLOW_UPS`] — counted from the outbound rows, the one just written
/// included. Chased: everything else, and the promise that was already
/// outstanding on the thread is settled first, so the silence is measured from
/// the newest message and one thread never holds two promises.
pub async fn schedule(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    conversation: ConversationId,
    to: &EmailAddress,
    now: DateTime<Utc>,
) -> Result<Option<AppointmentId>, StoreError> {
    let (outbound, answered): (i64, bool) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE direction = 'outbound'), \
                coalesce(bool_or(direction = 'inbound'), false) \
           FROM messages WHERE conversation_id = $1",
    )
    .bind(conversation.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    // Settled before the ceiling is asked, not after: a send on the thread
    // voids whatever silence the earlier promise was measuring, whether or not
    // a new one is booked in its place.
    calendar::cancel_for_conversation(tx, conversation, now).await?;
    if answered || outbound > MAX_FOLLOW_UPS as i64 {
        return Ok(None);
    }
    let booked = calendar::book_on(
        tx,
        AppointmentId::new_v7(now),
        employee,
        now + FOLLOW_UP_AFTER,
        ZONE,
        &subject(&to.to_string()),
        Some(conversation),
    )
    .await?;
    Ok(Some(booked.id))
}

/// What is said, in our voice, when a follow-up's hour comes round.
///
/// Every value in it is ours: the date is `max(received_at)` over the thread's
/// outbound rows. The address is *not* here, on purpose — it is in the
/// promise's subject line, which the wake already shows inside a frame, and a
/// domain is a stranger's text however short. `None` when the thread cannot be
/// read, and the turn runs on the frame alone.
pub async fn brief(db: &Db, tenant: TenantId, conversation: ConversationId) -> Option<String> {
    let mut tx = db.tenant_tx(tenant).await.ok()?;
    let since: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(received_at) FROM messages \
          WHERE conversation_id = $1 AND direction = 'outbound'",
    )
    .bind(conversation.as_uuid())
    .fetch_one(&mut **tx)
    .await
    .ok()?;
    let _ = tx.rollback().await;
    let since = since?;
    Some(format!(
        "This hour is a follow-up. You wrote to the contact named in the frame below on {} and \
         nothing has come back since. Write to them once more on the same thread, briefly, with \
         one reason to answer — and if the send is refused, they have asked to be left alone and \
         that is the answer.",
        since.format("%Y-%m-%d")
    ))
}

#[cfg(test)]
mod tests {
    use agentos_domain::message::{CanonicalMessage, Direction, ProviderRef};
    use agentos_domain::untrusted::Untrusted;
    use chrono::TimeDelta;

    use super::*;

    async fn fixture() -> Option<(Db, TenantId, EmployeeId, TenantId)> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the follow-up needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let (tenant, employee) = seed(&db).await;
        let (other, _) = seed(&db).await;
        Some((db, tenant, employee, other))
    }

    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'follow-up test')")
            .bind(tenant.as_uuid())
            .bind(format!("fu-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("employee");
        admin.commit().await.expect("commit");
        (tenant, employee)
    }

    fn prospect() -> EmailAddress {
        EmailAddress::parse("Paul@Prospect.example").expect("address")
    }

    /// One send recorded and its promise scheduled, as `Effects::chase` does it.
    async fn send(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        id: &str,
        now: DateTime<Utc>,
    ) -> (ConversationId, Option<AppointmentId>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let conversation = sent(&mut tx, employee, &prospect(), Some("hello"), id, now)
            .await
            .expect("record the send");
        let promised = schedule(&mut tx, employee, conversation, &prospect(), now)
            .await
            .expect("schedule");
        tx.commit().await.expect("commit");
        (conversation, promised)
    }

    async fn outstanding(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
    ) -> Vec<calendar::Appointment> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let all = calendar::upcoming(&mut tx, employee)
            .await
            .expect("upcoming");
        tx.rollback().await.expect("rollback");
        all
    }

    /// The reply, as `ingest_email` would land it: same employee, same channel,
    /// the prospect's own spelling of their address.
    async fn reply(db: &Db, tenant: TenantId, employee: EmployeeId, now: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let from = Untrusted::new("Paul <paul@prospect.example>".to_owned());
        let conversation = inbound::conversation_for(
            &mut tx,
            employee,
            Channel::Email,
            &inbound::contact_of(&from),
            None,
            now,
        )
        .await
        .expect("thread");
        let message = CanonicalMessage {
            tenant_id: tenant,
            employee_id: employee,
            conversation_id: conversation,
            provider_message_id: ProviderRef::new("reply-1"),
            idempotency_key: CanonicalMessage::dedupe_key(
                employee,
                Channel::Email,
                &ProviderRef::new("reply-1"),
            ),
            channel: Channel::Email,
            direction: Direction::Inbound,
            received_at: now,
            from,
            subject: None,
            body_text: Untrusted::new("yes, tell me more".to_owned()),
            attachments: Vec::new(),
        };
        inbound::land(&mut tx, &message, now).await.expect("land");
        tx.commit().await.expect("commit");
    }

    /// **The sequence, end to end, without a model.** A first email books a
    /// promise three days out that names the thread; a reply on the thread
    /// settles it in the transaction that lands the reply; a send on a thread
    /// they have answered books nothing; and the other company sees none of it.
    #[tokio::test]
    async fn an_unanswered_email_is_chased_in_three_days_and_a_reply_calls_it_off() {
        let Some((db, tenant, lena, other)) = fixture().await else {
            return;
        };
        let now = Utc::now();

        let (thread, promised) = send(&db, tenant, lena, "msg-1", now).await;
        let promised = promised.expect("a first email to a stranger is chased");
        let diary = outstanding(&db, tenant, lena).await;
        assert_eq!(diary.len(), 1);
        assert_eq!(diary[0].id, promised);
        assert_eq!(diary[0].conversation_id, Some(thread));
        assert_eq!(diary[0].at, now + TimeDelta::hours(72));
        assert_eq!(diary[0].subject, "follow up · p…@prospect.example");
        assert!(
            brief(&db, tenant, thread)
                .await
                .expect("the thread has a last outbound")
                .contains(&now.format("%Y-%m-%d").to_string()),
            "the wake says since when"
        );
        assert!(
            brief(&db, other, thread).await.is_none(),
            "tenant B reads nothing on tenant A's thread"
        );

        // A second email before the hour: one promise, measured from the newest.
        let later = now + TimeDelta::hours(1);
        let (same, again) = send(&db, tenant, lena, "msg-2", later).await;
        assert_eq!(same, thread, "one thread per (employee, channel, address)");
        let again = again.expect("still unanswered, still chased");
        let diary = outstanding(&db, tenant, lena).await;
        assert_eq!(
            diary.len(),
            1,
            "the earlier promise was settled, not doubled"
        );
        assert_eq!(diary[0].id, again);
        assert_eq!(diary[0].at, later + FOLLOW_UP_AFTER);

        // They answer. The promise is settled in `land`'s transaction.
        reply(&db, tenant, lena, later + TimeDelta::hours(2)).await;
        assert!(outstanding(&db, tenant, lena).await.is_empty());
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let all = calendar::diary(&mut tx).await.expect("diary");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            all.iter()
                .find(|a| a.id == again)
                .expect("row")
                .outcome
                .as_deref(),
            Some(calendar::CANCELLED)
        );

        // And what we write back on an answered thread is a reply, not a chase.
        let (_, none) = send(&db, tenant, lena, "msg-3", later + TimeDelta::hours(3)).await;
        assert_eq!(none, None);
        assert!(outstanding(&db, tenant, lena).await.is_empty());
        assert!(outstanding(&db, other, lena).await.is_empty());
    }

    /// The ceiling: the approach and [`MAX_FOLLOW_UPS`] chases, then silence
    /// is the answer. Counted off the thread's outbound rows, so a third send
    /// books nothing.
    #[tokio::test]
    async fn the_third_follow_up_is_not_booked() {
        let Some((db, tenant, lena, _)) = fixture().await else {
            return;
        };
        // Each chase is sent by the turn the promise woke, so the promise has
        // rung by then — as it has in production, where `claim_due` writes
        // `rang_at` before the turn starts. The claim's own statement, scoped
        // to this seat: `claim_due` is cross-tenant and a clock three days
        // ahead would ring every other test's promises too.
        let ring = |when: DateTime<Utc>| {
            let db = db.clone();
            async move {
                let mut tx = db.tenant_tx(tenant).await.expect("tx");
                sqlx::query(
                    "UPDATE appointments SET rang_at = $2 \
                      WHERE employee_id = $1 AND rang_at IS NULL AND at <= $2",
                )
                .bind(lena.as_uuid())
                .bind(when)
                .execute(&mut **tx)
                .await
                .expect("ring");
                tx.commit().await.expect("commit");
            }
        };
        let now = Utc::now();
        let (_, first) = send(&db, tenant, lena, "t-1", now).await;
        assert!(first.is_some(), "approach → chase 1 promised");
        let day_three = now + FOLLOW_UP_AFTER;
        ring(day_three).await;
        let (_, second) = send(&db, tenant, lena, "t-2", day_three).await;
        assert!(second.is_some(), "chase 1 → chase 2 promised");
        let day_six = day_three + FOLLOW_UP_AFTER;
        ring(day_six).await;
        let (_, third) = send(&db, tenant, lena, "t-3", day_six).await;
        assert_eq!(third, None, "chase 2 → nothing more is promised");
        assert!(
            outstanding(&db, tenant, lena).await.is_empty(),
            "the second chase's promise rang, and no third replaced it"
        );
    }

    /// **Through the gate and the façade, the way a turn does it.** The
    /// promise is ruled on as an `AppointmentBook`; the chase three days on is
    /// an ordinary `send_email` to a contact the gate already knows, so the
    /// day's one stranger is not charged twice; a colleague's note books
    /// nothing; and an unsubscribe in between refuses the chase at the gate,
    /// which is the only door it has.
    #[tokio::test]
    async fn a_chase_is_ruled_on_a_known_contact_is_no_stranger_and_an_opt_out_refuses_it() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        use agentos_domain::ids::Slug;
        use agentos_domain::policy::PolicyLimits;
        use agentos_store::revenue as suppressions;
        use agentos_store::{org, outreach, policy};

        use crate::effects::{AppointmentBook, Effects, EmailSend, InternalNote, InternalSend};
        use crate::gate::{Denied, PolicyGate, Principal};
        use crate::inbound::Errand;

        let Some((db, tenant, lena, _)) = fixture().await else {
            return;
        };
        policy::install(
            &db,
            tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([
                    agentos_domain::action::Channel::Email,
                    agentos_domain::action::Channel::Internal,
                ]),
                max_new_contacts_per_day: 1,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
        let principal = Principal::employee(tenant, lena);
        let gate = PolicyGate::new(db.clone());
        let effects = Effects::new(
            db.clone(),
            Arc::new(crate::mocks::ports()),
            principal.clone(),
        );

        let ok = gate
            .authorize(&principal, EmailSend { to: prospect() })
            .await
            .expect("the day's one stranger");
        let id = effects
            .send_email(
                ok,
                crate::effects::RenderedEmail {
                    from: "lena@ours.example".to_owned(),
                    subject: "hello".to_owned(),
                    body_text: "…".to_owned(),
                    in_reply_to: None,
                },
            )
            .await
            .expect("sent");
        let ok = gate
            .authorize(&principal, AppointmentBook)
            .await
            .expect("this seat may promise an hour");
        let promised = effects
            .chase(ok, &prospect(), "hello", &id)
            .await
            .expect("recorded and promised");
        assert!(promised.is_some());
        let diary = outstanding(&db, tenant, lena).await;
        assert_eq!(diary.len(), 1);
        assert_eq!(diary[0].subject, "follow up · p…@prospect.example");

        // The chase, three days on: the same address, ruled on again — and it
        // is `ContactStanding::Known`, so a ceiling of one stranger a day is
        // not what stops a follow-up.
        gate.authorize(&principal, EmailSend { to: prospect() })
            .await
            .expect("a contact already written to is not a second stranger");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let strangers = outreach::taken_today(&mut tx, lena, Utc::now().date_naive())
            .await
            .expect("bucket");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            strangers, 1,
            "one stranger, however many times they are written to"
        );

        // A note to a colleague is an internal send, and it books nothing.
        let marc = EmployeeId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'marc', 'marc', 'active')",
        )
        .bind(marc.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("hire marc");
        admin.commit().await.expect("commit");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let team = org::create_team(&mut tx, &Slug::parse("sales").expect("slug"), "sales")
            .await
            .expect("team");
        org::set_member(&mut tx, lena, team, None)
            .await
            .expect("lena");
        org::set_member(&mut tx, marc, team, None)
            .await
            .expect("marc");
        tx.commit().await.expect("commit");
        let ok = gate
            .authorize(
                &principal,
                InternalSend {
                    to: Slug::parse("marc").expect("slug"),
                },
            )
            .await
            .expect("a team-mate");
        effects
            .send_internal(
                ok,
                &InternalNote {
                    errand: Errand::Question,
                    body: "did they answer?".to_owned(),
                    thread: None,
                },
            )
            .await
            .expect("delivered");
        assert_eq!(
            outstanding(&db, tenant, lena).await.len(),
            1,
            "an internal note is not chased"
        );

        // They unsubscribe in the meantime. The chase the wake proposes is an
        // ordinary `send_email`, and the gate refuses it on the list.
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        suppressions::suppress(
            &mut tx,
            Uuid::now_v7(),
            &suppressions::NewSuppression {
                channel: suppressions::Channel::Email,
                address: &prospect().to_string(),
                reason: "opt_out",
                scope: suppressions::Scope::Tenant,
                contact_id: None,
                note: Some("recorded by a follow-up test"),
                suppressed_at: Utc::now(),
            },
        )
        .await
        .expect("record the opt-out");
        tx.commit().await.expect("commit");
        let err = gate
            .authorize(&principal, EmailSend { to: prospect() })
            .await
            .expect_err("an opted-out address is not chased");
        assert!(matches!(err, Denied::Suppressed(_)), "{err}");
    }

    #[test]
    fn the_subject_is_ours_and_masked() {
        assert_eq!(
            subject("paul@prospect.example"),
            "follow up · p…@prospect.example"
        );
        assert!(subject(&"a".repeat(400)).chars().count() <= calendar::MAX_SUBJECT);
    }
}
