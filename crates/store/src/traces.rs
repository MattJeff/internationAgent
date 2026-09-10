//! Les traces d'un envoi : ce que le fournisseur nous dit d'un mail après
//! l'avoir pris — livré, ouvert, cliqué — et ce qu'on en relit.
//!
//! `migrations/0091_un_envoi_laisse_des_traces.sql` est le document de
//! conception ; ce module est les trois requêtes qui touchent la table.
//!
//! # Une ligne par événement, dédoublonnée par le fournisseur
//!
//! Resend livre au moins une fois (relu le 2026-09-10 sur
//! <https://resend.com/docs/dashboard/webhooks/introduction>, « at-least-once
//! delivery ») et rejoue tout webhook sans 2xx ; l'en-tête `svix-id` identifie
//! la livraison et c'est lui que [`record`] pose dans `provider_event_id`.
//! `ON CONFLICT DO NOTHING` sur `(tenant_id, provider, provider_event_id)` :
//! deux « ouvert » pour un seul geste faussent tout ce qui compte, et la
//! table le refuse avant que le code ait à y penser.
//!
//! # L'ordre n'est pas garanti, donc deux jointures
//!
//! La même page dit qu'un `email.opened` peut précéder l'`email.delivered` du
//! même mail — et rien n'empêche l'un ou l'autre de précéder la ligne
//! `messages` que `app::follow_up::sent` écrit dans la transaction de l'envoi.
//! [`record`] pose `message_id` quand la ligne existe et le laisse nul sinon ;
//! [`engagement`] retrouve un événement par `message_id` **ou** par
//! `provider_message_id`, donc une trace arrivée avant la ligne n'est pas
//! perdue, seulement non liée.
//!
//! # Pas de `WHERE tenant_id`
//!
//! `message_events` a RLS en `force` comme `messages` et `suppressions` :
//! chaque fonction prend une [`TenantTx`] et ce que lit un autre locataire
//! n'est pas filtré, il est invisible. Le test `un_autre_locataire_ne_voit_rien`
//! le tient.

use agentos_domain::ids::ConversationId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{StoreError, TenantTx};

/// Un signal, tel que le fournisseur l'a dit et tel que la table le range.
///
/// `kind` est la chaîne que `message_events_kind` admet — `delivered`,
/// `opened`, `clicked` — et `link` n'est posé que sur un `clicked`
/// (`message_events_link_only_when_clicked`). Le parseur
/// (`agentos_providers::email::Signal`) garantit les deux ; ce type ne fait
/// que porter, parce que ce crate ne dépend pas des fournisseurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal<'a> {
    /// `delivered`, `opened` ou `clicked`.
    pub kind: &'a str,
    /// L'identifiant que le fournisseur donne au mail qu'on a envoyé.
    pub provider_message_id: &'a str,
    /// Le lien cliqué, pour `clicked` seulement.
    pub link: Option<&'a str>,
    /// Quand le fournisseur dit que c'est arrivé.
    pub occurred_at: DateTime<Utc>,
}

/// Écrit une trace, une seule fois par livraison.
///
/// Rend `true` si une ligne a été écrite, `false` si `provider_event_id` était
/// déjà là — une relivraison, qui n'est ni une erreur ni un second geste.
/// `message_id` est posé depuis la ligne `messages` sortante qui porte le même
/// `provider_message_id` quand elle existe, nul sinon.
pub async fn record(
    tx: &mut TenantTx<'_>,
    provider: &str,
    signal: Signal<'_>,
    provider_event_id: &str,
) -> Result<bool, StoreError> {
    let written = sqlx::query(
        "INSERT INTO message_events \
             (id, tenant_id, provider, provider_message_id, message_id, kind, link, \
              occurred_at, provider_event_id) \
         VALUES ($1, $2, $3, $4, \
                 (SELECT id FROM messages \
                   WHERE tenant_id = $2 AND provider_message_id = $4 \
                     AND direction = 'outbound' \
                   ORDER BY received_at LIMIT 1), \
                 $5, $6, $7, $8) \
         ON CONFLICT ON CONSTRAINT message_events_dedupe DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(tx.tenant_id().as_uuid())
    .bind(provider)
    .bind(signal.provider_message_id)
    .bind(signal.kind)
    .bind(signal.link)
    .bind(signal.occurred_at)
    .bind(provider_event_id)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(written == 1)
}

/// Ce qu'un fil a reçu comme traces sur ses mails sortants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Engagement {
    /// Les `messages` sortants e-mail du fil.
    pub sent: u32,
    /// Traces `delivered` sur ces mails.
    pub delivered: u32,
    /// Traces `opened` — un pixel par ouverture, donc un mail relu compte deux.
    pub opened: u32,
    /// Traces `clicked`.
    pub clicked: u32,
    /// La plus récente ouverture.
    pub last_opened_at: Option<DateTime<Utc>>,
    /// Le plus récent clic.
    pub last_clicked_at: Option<DateTime<Utc>>,
    /// Les liens cliqués, distincts, dans l'ordre du texte.
    pub links: Vec<String>,
}

/// Les sept colonnes d'[`engagement`], dans l'ordre du `SELECT`.
type EngagementRow = (
    i64,
    i64,
    i64,
    i64,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Vec<String>,
);

/// Les traces des mails sortants d'un fil, joints par `message_id` **ou** par
/// `provider_message_id` — voir le module pour pourquoi les deux.
pub async fn engagement(
    tx: &mut TenantTx<'_>,
    conversation: ConversationId,
) -> Result<Engagement, StoreError> {
    let row: EngagementRow = sqlx::query_as(
        "SELECT (SELECT count(*) FROM messages \
                  WHERE conversation_id = $1 AND direction = 'outbound' \
                    AND channel = 'email')::bigint, \
                count(*) FILTER (WHERE e.kind = 'delivered')::bigint, \
                count(*) FILTER (WHERE e.kind = 'opened')::bigint, \
                count(*) FILTER (WHERE e.kind = 'clicked')::bigint, \
                max(e.occurred_at) FILTER (WHERE e.kind = 'opened'), \
                max(e.occurred_at) FILTER (WHERE e.kind = 'clicked'), \
                coalesce(array_agg(DISTINCT e.link) FILTER (WHERE e.link IS NOT NULL), '{}') \
           FROM message_events e \
          WHERE EXISTS (SELECT 1 FROM messages m \
                         WHERE m.conversation_id = $1 AND m.direction = 'outbound' \
                           AND m.channel = 'email' \
                           AND (m.id = e.message_id \
                                OR m.provider_message_id = e.provider_message_id))",
    )
    .bind(conversation.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    Ok(Engagement {
        sent: clamp(row.0),
        delivered: clamp(row.1),
        opened: clamp(row.2),
        clicked: clamp(row.3),
        last_opened_at: row.4,
        last_clicked_at: row.5,
        links: row.6,
    })
}

/// La santé du domaine d'envoi sur une fenêtre : ce qui est parti, ce qui a été
/// pris, lu, cliqué — et ce qui a été refusé.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Health {
    /// `messages` sortants e-mail depuis `since`.
    pub sent: u32,
    /// Traces `delivered` depuis `since`.
    pub delivered: u32,
    /// Traces `opened` depuis `since`.
    pub opened: u32,
    /// Traces `clicked` depuis `since`.
    pub clicked: u32,
    /// `suppressions` de motif `bounce` depuis `since`.
    pub bounced: u32,
    /// `suppressions` de motif `complaint` depuis `since`.
    pub complained: u32,
}

/// Six comptes depuis `since`. Les quatre premiers depuis `messages` et
/// `message_events`, les deux derniers depuis `suppressions` — les refus n'ont
/// jamais été recopiés dans `message_events`, et `0011` est déjà leur registre.
///
/// `bounced` ne compte que les rebonds **permanents** : c'est le seul cas où
/// `app::inbound::record_refusal` écrit une suppression. Un rebond transitoire
/// est sur `audit_log` et pas ici.
pub async fn health(tx: &mut TenantTx<'_>, since: DateTime<Utc>) -> Result<Health, StoreError> {
    let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM messages \
                  WHERE direction = 'outbound' AND channel = 'email' \
                    AND received_at >= $1)::bigint, \
                (SELECT count(*) FROM message_events \
                  WHERE kind = 'delivered' AND occurred_at >= $1)::bigint, \
                (SELECT count(*) FROM message_events \
                  WHERE kind = 'opened' AND occurred_at >= $1)::bigint, \
                (SELECT count(*) FROM message_events \
                  WHERE kind = 'clicked' AND occurred_at >= $1)::bigint, \
                (SELECT count(*) FROM suppressions \
                  WHERE reason = 'bounce' AND suppressed_at >= $1)::bigint, \
                (SELECT count(*) FROM suppressions \
                  WHERE reason = 'complaint' AND suppressed_at >= $1)::bigint",
    )
    .bind(since)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(Health {
        sent: clamp(row.0),
        delivered: clamp(row.1),
        opened: clamp(row.2),
        clicked: clamp(row.3),
        bounced: clamp(row.4),
        complained: clamp(row.5),
    })
}

/// Un `count(*)` tient dans un `u32` pour tout locataire de ce déploiement ;
/// au-delà, on plafonne plutôt que de paniquer sur un chiffre d'affichage.
fn clamp(n: i64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use chrono::{SubsecRound as _, TimeDelta};

    use super::*;
    use crate::db::Db;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the traces need a real Postgres");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'traces test')")
            .bind(tenant.as_uuid())
            .bind(format!("traces-{}", tenant.as_uuid().simple()))
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'Lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");
        (tenant, employee)
    }

    /// Un fil e-mail avec un mail sortant dessus, comme `follow_up::sent`
    /// l'écrit : `provider_message_id` posé, `direction = 'outbound'`.
    async fn sent(
        db: &Db,
        tenant: TenantId,
        employee: EmployeeId,
        provider_message_id: &str,
        at: DateTime<Utc>,
    ) -> ConversationId {
        let conversation = ConversationId::new_v7(at);
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO conversations (id, tenant_id, employee_id, channel) \
             VALUES ($1, $2, $3, 'email')",
        )
        .bind(conversation.as_uuid())
        .bind(tenant.as_uuid())
        .bind(employee.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("conversation");
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, conversation_id, employee_id, channel, direction, sender, \
                  provider_message_id, trust_label, idempotency_key, received_at, created_at) \
             VALUES ($1, $2, $3, $4, 'email', 'outbound', '', $5, 'trusted', $6, $7, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(conversation.as_uuid())
        .bind(employee.as_uuid())
        .bind(provider_message_id)
        .bind(format!("sent:{provider_message_id}"))
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("message");
        tx.commit().await.expect("commit");
        conversation
    }

    async fn record_once(
        db: &Db,
        tenant: TenantId,
        signal: Signal<'_>,
        provider_event_id: &str,
    ) -> bool {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let written = record(&mut tx, "resend", signal, provider_event_id)
            .await
            .expect("record");
        tx.commit().await.expect("commit");
        written
    }

    async fn read(db: &Db, tenant: TenantId, conversation: ConversationId) -> Engagement {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let read = engagement(&mut tx, conversation).await.expect("engagement");
        tx.rollback().await.expect("rollback");
        read
    }

    async fn rows(db: &Db, tenant: TenantId) -> Vec<(String, Option<Uuid>)> {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let rows = sqlx::query_as("SELECT kind, message_id FROM message_events ORDER BY kind")
            .fetch_all(&mut **tx)
            .await
            .expect("rows");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// **Une relivraison n'est pas un second geste.** Le même `svix-id` deux
    /// fois : une ligne, et le second appel dit qu'il n'a rien écrit.
    ///
    /// Garde vérifiée mordante le 2026-09-10 : sans le `ON CONFLICT`, le second
    /// appel casse sur `message_events_dedupe` et le test rougit.
    #[tokio::test]
    async fn la_meme_livraison_deux_fois_est_une_ligne() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let now = Utc::now().trunc_subsecs(6);
        let thread = sent(&db, tenant, lena, "email_1", now).await;
        let opened = Signal {
            kind: "opened",
            provider_message_id: "email_1",
            link: None,
            occurred_at: now + TimeDelta::hours(1),
        };

        assert!(record_once(&db, tenant, opened, "svix_1").await);
        assert!(
            !record_once(&db, tenant, opened, "svix_1").await,
            "the redelivery must report nothing written"
        );
        // Un autre `svix-id` est bien un second geste.
        assert!(record_once(&db, tenant, opened, "svix_2").await);

        let seen = read(&db, tenant, thread).await;
        assert_eq!(seen.opened, 2, "{seen:?}");
        assert_eq!(seen.sent, 1);
        assert_eq!(seen.last_opened_at, Some(now + TimeDelta::hours(1)));
    }

    /// **La trace peut précéder la ligne `messages`.** Écrite avec
    /// `message_id` nul, elle est quand même retrouvée par
    /// `provider_message_id` une fois l'envoi enregistré — et un clic porte son
    /// lien.
    ///
    /// Garde vérifiée mordante le 2026-09-10 : sans le
    /// `OR m.provider_message_id = e.provider_message_id` d'[`engagement`],
    /// `clicked` lit 0 et le test rougit.
    #[tokio::test]
    async fn une_trace_arrivee_avant_la_ligne_est_retrouvee_par_le_fournisseur() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let now = Utc::now().trunc_subsecs(6);

        let clicked = Signal {
            kind: "clicked",
            provider_message_id: "email_early",
            link: Some("https://example.com/offer"),
            occurred_at: now,
        };
        assert!(record_once(&db, tenant, clicked, "svix_early").await);
        assert_eq!(
            rows(&db, tenant).await,
            vec![("clicked".to_owned(), None)],
            "no messages row yet: message_id is null, the trace is kept"
        );

        // L'envoi est enregistré après coup, sur le même identifiant.
        let thread = sent(
            &db,
            tenant,
            lena,
            "email_early",
            now - TimeDelta::minutes(1),
        )
        .await;
        let seen = read(&db, tenant, thread).await;
        assert_eq!(seen.clicked, 1, "{seen:?}");
        assert_eq!(seen.last_clicked_at, Some(now));
        assert_eq!(seen.links, vec!["https://example.com/offer".to_owned()]);

        // Et une trace écrite *après* la ligne est liée par `message_id`.
        let delivered = Signal {
            kind: "delivered",
            provider_message_id: "email_early",
            link: None,
            occurred_at: now,
        };
        assert!(record_once(&db, tenant, delivered, "svix_late").await);
        let linked = rows(&db, tenant).await;
        assert!(
            linked
                .iter()
                .any(|(kind, id)| kind == "delivered" && id.is_some()),
            "{linked:?}"
        );
        assert_eq!(read(&db, tenant, thread).await.delivered, 1);
    }

    /// **RLS, pas un `WHERE`.** Le même `svix-id` chez deux locataires est deux
    /// lignes, et chacun ne lit que la sienne.
    ///
    /// Garde vérifiée mordante le 2026-09-10 : en lisant via
    /// `admin_tx_bypassing_rls`, l'autre locataire voit la ligne et le test
    /// rougit.
    #[tokio::test]
    async fn un_autre_locataire_ne_voit_rien() {
        let Some(db) = db().await else { return };
        let (a, lena) = seed(&db).await;
        let (b, _) = seed(&db).await;
        let now = Utc::now();
        let thread = sent(&db, a, lena, "email_a", now).await;
        let opened = Signal {
            kind: "opened",
            provider_message_id: "email_a",
            link: None,
            occurred_at: now,
        };
        assert!(record_once(&db, a, opened, "svix_shared").await);
        assert!(
            record_once(&db, b, opened, "svix_shared").await,
            "one provider account, two tenants: the same delivery id is two rows"
        );

        assert_eq!(read(&db, a, thread).await.opened, 1);
        assert_eq!(
            read(&db, b, thread).await,
            Engagement::default(),
            "tenant B reads nothing on tenant A's thread"
        );
        assert_eq!(rows(&db, b).await.len(), 1);
    }

    /// **`health` lit les refus dans `suppressions`**, jamais dans
    /// `message_events`, et ne compte que la fenêtre.
    ///
    /// Garde vérifiée mordante le 2026-09-10 : avec `reason = 'opt_out'` à la
    /// place de `bounce`, `bounced` lit 0 et le test rougit.
    #[tokio::test]
    async fn la_sante_compte_les_refus_depuis_les_suppressions() {
        let Some(db) = db().await else { return };
        let (tenant, lena) = seed(&db).await;
        let now = Utc::now();
        let since = now - TimeDelta::days(7);

        sent(&db, tenant, lena, "email_h1", now).await;
        sent(&db, tenant, lena, "email_h2", now - TimeDelta::days(30)).await;
        for (kind, id, event) in [
            ("delivered", "email_h1", "s1"),
            ("opened", "email_h1", "s2"),
            ("opened", "email_h1", "s3"),
            ("clicked", "email_h1", "s4"),
        ] {
            let signal = Signal {
                kind,
                provider_message_id: id,
                link: (kind == "clicked").then_some("https://x.example"),
                occurred_at: now,
            };
            assert!(record_once(&db, tenant, signal, event).await);
        }
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        for (address, reason, at) in [
            ("a@x.example", "bounce", now),
            ("b@x.example", "complaint", now),
            ("c@x.example", "opt_out", now),
            ("d@x.example", "bounce", now - TimeDelta::days(30)),
        ] {
            sqlx::query(
                "INSERT INTO suppressions \
                     (id, tenant_id, scope, channel, address, reason, suppressed_at) \
                 VALUES ($1, $2, 'tenant', 'email', $3, $4, $5)",
            )
            .bind(Uuid::now_v7())
            .bind(tenant.as_uuid())
            .bind(address)
            .bind(reason)
            .bind(at)
            .execute(&mut **tx)
            .await
            .expect("suppression");
        }
        let health = health(&mut tx, since).await.expect("health");
        tx.commit().await.expect("commit");

        assert_eq!(
            health,
            Health {
                sent: 1,
                delivered: 1,
                opened: 2,
                clicked: 1,
                bounced: 1,
                complained: 1,
            }
        );
    }
}
