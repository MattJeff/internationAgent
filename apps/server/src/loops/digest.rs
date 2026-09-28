//! La boucle du compte rendu : chaque jour à partir de [`SEND_HOUR`] UTC,
//! chaque locataire qui n'a pas encore reçu le sien voit sa journée
//! ([`agentos_app::digest::compute`]) partir en HTML à l'adresse de
//! `AGENTOS_APPROVAL_NOTIFY` — le fondateur, la même personne que le mail
//! d'approbation écrit.
//!
//! # Une fois par jour, par la base
//!
//! Le geste de `loops::citation` : la mémoire est une colonne,
//! `tenants.digest_sent_on` (0119), et l'UPDATE qui la pose est la
//! réclamation — deux réplicas n'envoient qu'un mail. Un processus qui meurt
//! entre la réclamation et l'envoi perd un soir ; le prix d'un crash, pas
//! d'un bug. La clé d'idempotence du port (`platform:digest:…`) est la
//! seconde ceinture.
//!
//! # Pas de jeton de la Gate
//!
//! Pour la raison de `effects::notify_approver` : c'est la plate-forme qui
//! écrit à l'opérateur, à une adresse qu'il a posée lui-même. L'expéditeur est
//! `digest@` la primaire du locataire ; un locataire sans domaine ne reçoit
//! rien et le journal le dit.

use std::sync::Arc;
use std::time::Duration;

use agentos_app::digest;
use agentos_app::effects::Ports;
use agentos_app::sending_domain;
use agentos_domain::ids::TenantId;
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Timelike as _, Utc};
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;

/// Entre deux passes. Une minute : le mail part dans la minute qui suit 18 h.
const IDLE: Duration = Duration::from_secs(60);

/// L'heure UTC à partir de laquelle la journée est envoyée.
pub const SEND_HOUR: u32 = 18;

pub async fn run(db: Db, ports: Arc<Ports>, notify: Option<String>, cancel: CancellationToken) {
    let Some(notify) = notify else {
        tracing::info!("digest loop not started: AGENTOS_APPROVAL_NOTIFY is unset");
        return;
    };
    tracing::info!("digest loop started");
    loop {
        match tick(&db, &ports, &notify, Utc::now()).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(sent = n, "digests sent"),
            Err(err) => tracing::error!(error = %err, "digest tick failed"),
        }
        if cancel.is_cancelled() {
            break;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }
    tracing::info!("digest loop stopped");
}

/// Une passe : avant [`SEND_HOUR`] rien ; après, chaque locataire pas encore
/// servi ce jour-là est réclamé et écrit. Rend combien de mails sont partis.
pub async fn tick(
    db: &Db,
    ports: &Arc<Ports>,
    notify: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    if now.hour() < SEND_HOUR {
        return Ok(0);
    }
    let day = now.date_naive();
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let claimed = sqlx::query(concat!(
        "UPDATE tenants t SET digest_sent_on = $1::date \
          WHERE (t.digest_sent_on IS NULL OR t.digest_sent_on < $1::date) AND ",
        agentos_store::not_stopped!("t.id", "$2::timestamptz"),
        " RETURNING t.id",
    ))
    .bind(day)
    .bind(now)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;

    let mut sent = 0;
    for row in &claimed {
        let tenant = TenantId::from_uuid(row.get("id"));
        let mut tx = db.tenant_tx(tenant).await?;
        let digest = digest::compute(&mut tx, day, now).await?;
        let primary = sending_domain::primary(&mut tx).await?;
        tx.rollback().await?;
        let Some(primary) = primary else {
            tracing::warn!(tenant = %tenant, "digest not sent: the tenant has no sending domain");
            continue;
        };
        match digest::send(ports, notify, &primary.domain, tenant, &digest).await {
            Ok(_) => sent += 1,
            Err(err) => tracing::warn!(tenant = %tenant, error = %err, "digest not sent"),
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use agentos_app::mocks::MockEmailProvider;
    use chrono::TimeDelta;

    use super::*;

    /// **Rien avant 18 h ; un mail à 18 h, pas deux ; un autre le lendemain.**
    #[tokio::test]
    async fn the_loop_writes_the_founder_once_a_day_from_six_pm() {
        let Some(db) = crate::loops::private_db("digest").await else {
            return;
        };
        let tenant = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        // La base est à ce test seul, et les locataires d'un passage
        // précédent seraient dus eux aussi.
        sqlx::query("DELETE FROM tenants WHERE name = 'digest loop'")
            .execute(&mut *admin)
            .await
            .expect("clear");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'digest loop')")
            .bind(tenant.as_uuid())
            .bind(format!("digest-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        admin.commit().await.expect("commit");
        let domain = sending_domain::adopt_for_tests(&db, tenant).await;

        let email = Arc::new(MockEmailProvider::new());
        let ports = Arc::new(Ports {
            email: email.clone(),
            ..agentos_app::mocks::ports()
        });
        let day = Utc::now().date_naive();
        let at = |h: u32, m: u32| day.and_hms_opt(h, m, 0).expect("time").and_utc();

        assert_eq!(
            tick(&db, &ports, "fondateur@x.example", at(17, 59))
                .await
                .expect("tick"),
            0
        );
        assert_eq!(
            tick(&db, &ports, "fondateur@x.example", at(18, 0))
                .await
                .expect("tick"),
            1
        );
        assert_eq!(
            tick(&db, &ports, "fondateur@x.example", at(18, 1))
                .await
                .expect("tick"),
            0,
            "once a day"
        );
        let sent = email.sent_emails();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, vec!["fondateur@x.example".to_owned()]);
        assert_eq!(sent[0].from, format!("digest@{domain}"));
        assert_eq!(sent[0].subject, format!("Orizn — journée du {day}"));
        assert!(
            sent[0]
                .body_html
                .as_deref()
                .is_some_and(|h| h.contains(&format!("Journée du {day}"))),
            "{:?}",
            sent[0].body_html
        );

        assert_eq!(
            tick(
                &db,
                &ports,
                "fondateur@x.example",
                at(18, 0) + TimeDelta::days(1)
            )
            .await
            .expect("tick"),
            1
        );
    }
}
