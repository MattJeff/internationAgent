//! La boucle de la patience : toutes les [`IDLE`], chaque question interne
//! sans réponse depuis plus de `inbound::QUESTION_PATIENCE` (24 h) reçoit la
//! réponse de l'horloge — `inbound::NO_ANSWER`, signée du collègue interrogé,
//! par `inbound::answer_for_silence`, qui passe par `inbound::send` comme
//! n'importe quelle réponse.
//!
//! # Pourquoi
//!
//! Le 2026-09-28, 97 questions attendaient le fondateur, qui ne prend aucun
//! tour. Une question ouverte bloque la suivante du même siège
//! (`question_still_pending`) pendant un jour, puis reste sur le bureau du
//! destinataire pour toujours. Passé un jour, la réponse est « applique ton
//! plan », et c'est ce qu'écrit cette boucle.
//!
//! Seulement les questions de **un à deux jours** : passé deux jours, la
//! question ne bloque plus rien (`still_pending` ne lit que 24 h) et la
//! réponse réveillerait un siège pour rien — le 2026-09-28, 94 questions
//! dormaient depuis le 19, soit 94 tours de modèle à la première passe.
//! ponytail: borne dans la requête ; une colonne « fermée par l'horloge »
//! le jour où il faut distinguer « répondue » de « expirée ».
//!
//! # Comment elle traverse les locataires
//!
//! Le même geste que `sequence` : une lecture sous `admin_tx_bypassing_rls`
//! pour savoir *quelles* questions sont dues, puis **une `TenantTx` par
//! question**. `answer_for_silence` relit la question sous sa transaction et
//! ne répond que si elle est encore ouverte ; deux réplicas qui lisent la même
//! ligne n'écrivent qu'une réponse — l'anti-jointure et la clé d'idempotence
//! `silence:<id>` le garantissent chacune seule.
//!
//! Répondre coûte un tour à celui qui a demandé (il est réveillé, comme par
//! toute réponse) : un siège à court de tours est laissé dû et repris à la
//! passe suivante.

use std::time::Duration;

use agentos_domain::ids::TenantId;
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Entre deux passes.
const IDLE: Duration = Duration::from_secs(300);

/// Combien de questions une passe ferme au plus.
const BATCH: i64 = 100;

pub async fn run(db: Db, cancel: CancellationToken) {
    tracing::info!("patience loop started");
    loop {
        match tick(&db, Utc::now()).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(closed = n, "questions closed by the clock"),
            Err(err) => tracing::error!(error = %err, "patience tick failed"),
        }
        if cancel.is_cancelled() {
            break;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }
    tracing::info!("patience loop stopped");
}

/// Une passe : les questions dues, chacune fermée dans sa propre transaction
/// de locataire. Rend combien ont été fermées.
pub async fn tick(db: &Db, now: DateTime<Utc>) -> Result<usize, StoreError> {
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let due = sqlx::query(concat!(
        "SELECT q.id, q.tenant_id FROM messages q \
           JOIN employees a ON a.tenant_id = q.tenant_id AND a.slug = q.sender \
                            AND a.lifecycle = 'active' \
          WHERE q.internal_kind = 'question' AND q.created_at <= $1::timestamptz \
            AND q.created_at > $1::timestamptz - interval '1 day' \
            AND NOT EXISTS (SELECT 1 FROM messages r WHERE r.answers_message_id = q.id) AND ",
        agentos_store::not_stopped!("q.tenant_id", "$2::timestamptz"),
        " ORDER BY q.created_at, q.id LIMIT $3::bigint",
    ))
    .bind(now - agentos_app::inbound::QUESTION_PATIENCE)
    .bind(now)
    .bind(BATCH)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;

    let mut closed = 0;
    for row in &due {
        let question: Uuid = row.get("id");
        let tenant = TenantId::from_uuid(row.get("tenant_id"));
        let mut tx = db.tenant_tx(tenant).await?;
        match agentos_app::inbound::answer_for_silence(&mut tx, question, now).await {
            Ok(Some(_)) => {
                tx.commit().await?;
                closed += 1;
            }
            Ok(None) => {
                let _ = tx.rollback().await;
            }
            Err(err) => {
                // One question's refusal is not the batch's: log it, leave it
                // due, and let the others through.
                tracing::warn!(error = %err, code = err.code(), question = %question, tenant = %tenant, "question not closed");
                let _ = tx.rollback().await;
            }
        }
    }
    Ok(closed)
}

#[cfg(test)]
mod tests {
    use agentos_app::inbound::{self, Errand};
    use agentos_domain::ids::{EmployeeId, IdempotencyKey, Slug};
    use agentos_domain::untrusted::TrustLabel;
    use chrono::TimeDelta;

    use super::*;

    /// **Une question de 25 h reçoit la réponse, une de 2 h non, et un second
    /// passage n'en ajoute pas.** La règle elle-même est prouvée dans
    /// `agentos_app::inbound` ; ce que la boucle possède, c'est la traversée
    /// des locataires et l'idempotence d'une passe à l'autre.
    #[tokio::test]
    async fn the_loop_closes_what_waited_a_day_and_only_once() {
        let Some(db) = crate::loops::private_db("patience").await else {
            return;
        };
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let lena = EmployeeId::new_v7(now);
        let bruno = EmployeeId::new_v7(now);
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'patience loop')")
            .bind(tenant.as_uuid())
            .bind(format!("patience-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        for (id, slug) in [(lena, "lena"), (bruno, "bruno")] {
            sqlx::query(
                "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
                 VALUES ($1, $2, $3, $3, 'active')",
            )
            .bind(id.as_uuid())
            .bind(tenant.as_uuid())
            .bind(slug)
            .execute(&mut *admin)
            .await
            .expect("employee");
        }
        admin.commit().await.expect("commit");
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let team =
            agentos_store::org::create_team(&mut tx, &Slug::parse("desk").expect("slug"), "Desk")
                .await
                .expect("team");
        for who in [lena, bruno] {
            agentos_store::org::set_member(&mut tx, who, team, None)
                .await
                .expect("join");
        }
        tx.commit().await.expect("commit");
        agentos_store::policy::install(
            &db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &agentos_domain::policy::PolicyLimits {
                allowed_channels: std::collections::BTreeSet::from([
                    agentos_domain::message::Channel::Internal,
                ]),
                max_turns_per_day: 5,
                ..agentos_domain::policy::PolicyLimits::default()
            },
        )
        .await
        .expect("policy");

        let db = &db;
        let ask = |from, to: &'static str, when: chrono::DateTime<chrono::Utc>| async move {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            // One key per question: the same key would resume the earlier one.
            let step = format!("internal:patience:{}", when.timestamp());
            let sent = inbound::send(
                &mut tx,
                from,
                &Slug::parse(to).expect("slug"),
                Errand::Question,
                "Which warehouse do I quote for PO-4471?",
                TrustLabel::Trusted,
                None,
                &IdempotencyKey::for_step(from, &step),
                when,
            )
            .await
            .expect("asked");
            tx.commit().await.expect("commit");
            sent
        };
        // Asked first: at 25 h before now it is already older than the
        // patience window, so the stale one is not refused as a second
        // question on the same colleague.
        let forgotten = ask(lena, "bruno", now - TimeDelta::hours(50)).await;
        let stale = ask(lena, "bruno", now - TimeDelta::hours(25)).await;
        let fresh = ask(bruno, "lena", now - TimeDelta::hours(2)).await;

        assert!(tick(db, now).await.expect("tick") >= 1, "the stale one");
        let answers = |question: Uuid| async move {
            let mut tx = db.tenant_tx(tenant).await.expect("tx");
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM messages \
                  WHERE answers_message_id = $1 AND sender = 'bruno' AND body = $2",
            )
            .bind(question)
            .bind(inbound::NO_ANSWER)
            .fetch_one(&mut **tx)
            .await
            .expect("count");
            tx.rollback().await.expect("rollback");
            n
        };
        assert_eq!(
            answers(stale.message_id).await,
            1,
            "25 h: answered by the clock"
        );
        assert_eq!(answers(fresh.message_id).await, 0, "2 h: still waiting");
        assert_eq!(
            answers(forgotten.message_id).await,
            0,
            "50 h: blocks nothing any more, nobody is woken for it"
        );

        tick(db, now).await.expect("second tick");
        assert_eq!(
            answers(stale.message_id).await,
            1,
            "a second pass adds nothing"
        );
    }
}
