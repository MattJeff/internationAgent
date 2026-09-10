//! La boucle des séquences : toutes les [`IDLE`], chaque run actif dont
//! `next_at` est passé avance d'un pas (`agentos_app::sequence::advance`).
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle n'envoie rien et ne réveille personne. Un pas `email` réserve une
//! promesse calendrier, et c'est `loops::initiative` — la même boucle, le même
//! `claim_due`, le même budget de tours — qui réveille le siège quand elle
//! sonne. Cette boucle ne fait que déplacer une position dans une table ; tout
//! ce qui coûte de l'argent ou touche un inconnu est ailleurs, derrière la
//! Gate.
//!
//! # Comment elle traverse les locataires
//!
//! Le même geste que `provisioning` : une lecture sous
//! `admin_tx_bypassing_rls` pour savoir *quels* runs sont dus et à qui, puis
//! **une `TenantTx` par run** pour avancer — `advance` prend le verrou
//! (`FOR UPDATE SKIP LOCKED`) dans cette transaction-là, relit l'état sous le
//! verrou et ignore un run qu'un autre réplica tient. La lecture admin n'écrit
//! rien et ne verrouille rien : une ligne vue deux fois par deux réplicas est
//! avancée une fois.
//!
//! [`not_stopped!`](agentos_store::not_stopped) borne la lecture comme les
//! autres claims : une entreprise arrêtée n'avance pas ses séquences.

use std::time::Duration;

use agentos_domain::ids::{SequenceRunId, TenantId};
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;

/// Entre deux passes. Trente secondes : un pas se mesure en heures, et la
/// promesse qu'il réserve sonne à la cadence de `loops::initiative`, pas à
/// celle-ci.
const IDLE: Duration = Duration::from_secs(30);

/// Combien de runs une passe avance au plus. Au-delà, la passe suivante
/// reprend sans attendre.
const BATCH: i64 = 100;

pub async fn run(db: Db, cancel: CancellationToken) {
    tracing::info!("sequence loop started");
    loop {
        let advanced = match tick(&db, Utc::now()).await {
            Ok(n) => n,
            Err(err) => {
                tracing::error!(error = %err, "sequence tick failed");
                0
            }
        };
        if cancel.is_cancelled() {
            break;
        }
        if advanced >= BATCH as usize {
            continue;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }
    tracing::info!("sequence loop stopped");
}

/// Une passe : les runs dus, chacun avancé dans sa propre transaction de
/// locataire. Rend combien ont été tentés.
pub async fn tick(db: &Db, now: DateTime<Utc>) -> Result<usize, StoreError> {
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let due = sqlx::query(concat!(
        "SELECT r.id, r.tenant_id FROM sequence_runs r \
          WHERE r.state = 'active' AND r.next_at <= $1::timestamptz AND ",
        agentos_store::not_stopped!("r.tenant_id"),
        " ORDER BY r.next_at, r.id LIMIT $2::bigint",
    ))
    .bind(now)
    .bind(BATCH)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;

    for row in &due {
        let run = SequenceRunId::from_uuid(row.get("id"));
        let tenant = TenantId::from_uuid(row.get("tenant_id"));
        let mut tx = db.tenant_tx(tenant).await?;
        match agentos_app::sequence::advance(&mut tx, run, now).await {
            Ok(()) => tx.commit().await?,
            Err(err) => {
                // One run's failure is not the batch's: log it, leave it due,
                // and let the others through.
                tracing::error!(error = %err, run = %run, tenant = %tenant, "sequence run did not advance");
                let _ = tx.rollback().await;
            }
        }
    }
    Ok(due.len())
}

#[cfg(test)]
mod tests {
    use agentos_app::sequence::{self, Step};
    use agentos_domain::ids::EmployeeId;
    use chrono::{SubsecRound, TimeDelta};
    use uuid::Uuid;

    use super::*;

    /// **A future `next_at` is not due, and a past one is.** The loop is the
    /// one reader of that column, so the proof is at the loop.
    #[tokio::test]
    async fn the_loop_advances_what_is_due_and_leaves_the_future_alone() {
        let Some(db) = crate::loops::private_db("sequence").await else {
            return;
        };
        let now = Utc::now().trunc_subsecs(6);
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let (account, paul, marie) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'sequence loop')")
            .bind(tenant.as_uuid())
            .bind(format!("seq-loop-{}", tenant.as_uuid().simple()))
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
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Prospect', $3, 'airline', 'FR')",
        )
        .bind(account)
        .bind(tenant.as_uuid())
        .bind(format!("{}.example", account.simple()))
        .execute(&mut *admin)
        .await
        .expect("account");
        for (id, name) in [(paul, "paul"), (marie, "marie")] {
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, account_id, full_name, email) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(id)
            .bind(tenant.as_uuid())
            .bind(account)
            .bind(name)
            .bind(format!("{name}@{}.example", account.simple()))
            .execute(&mut *admin)
            .await
            .expect("contact");
        }
        admin.commit().await.expect("commit");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let seq = sequence::define(
            &mut tx,
            "loop",
            &[
                Step::Wait { hours: 1 },
                Step::Email {
                    brief: "hello".to_owned(),
                },
            ],
        )
        .await
        .expect("define");
        let due = sequence::enroll(&mut tx, seq, paul, employee, now - TimeDelta::minutes(1))
            .await
            .expect("paul, due");
        let later = sequence::enroll(&mut tx, seq, marie, employee, now + TimeDelta::hours(1))
            .await
            .expect("marie, later");
        tx.commit().await.expect("commit");

        assert_eq!(tick(&db, now).await.expect("tick"), 1, "one run was due");

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let paul_run = sequence::find(&mut tx, due)
            .await
            .expect("find")
            .expect("mine");
        let marie_run = sequence::find(&mut tx, later)
            .await
            .expect("find")
            .expect("mine");
        tx.rollback().await.expect("rollback");
        assert_eq!(paul_run.step, 1, "the wait was consumed");
        assert_eq!(paul_run.next_at, Some(now + TimeDelta::hours(1)));
        assert_eq!(marie_run.step, 0, "a future next_at is left alone");
        assert_eq!(marie_run.next_at, Some(now + TimeDelta::hours(1)));

        assert_eq!(
            tick(&db, now).await.expect("tick"),
            0,
            "nothing else is due yet"
        );
    }
}
