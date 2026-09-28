//! Le compte rendu du jour : ce qui s'est passé pour un locataire pendant une
//! journée UTC, en une lecture.
//!
//! Avant ce module, savoir « ce qui s'est passé aujourd'hui » demandait vingt
//! requêtes SQL à la main : les lettres parties, les réponses reçues, les
//! questions qui bloquent un siège, les approbations qui attendent, les tours
//! pris, les flux nourris. [`compute`] les rend en une struct que
//! `GET /v1/digest` sérialise telle quelle et que la boucle `loops::digest`
//! met en HTML ([`html`]) dans un mail au fondateur à 18 h UTC.
//!
//! # Ce que « le jour » veut dire
//!
//! Minuit à minuit UTC, la même journée que `turn_buckets` et
//! `GET /v1/health/company`. Tout ce qui est daté — lettres, réponses, runs
//! arrêtés, tours — est borné par `[jour, jour + 1)`. Deux lectures ne le sont
//! pas, parce qu'elles décrivent un **état** et pas un événement : les
//! questions sans réponse de moins de 24 h (celles qui bloquent un siège, le
//! prédicat de `inbound::still_pending`) et les approbations `pending` non
//! expirées. Elles se lisent à `now`, quel que soit le jour demandé.
//!
//! # Rien n'est inventé
//!
//! Chaque nombre est un `count(*)` sur une table existante, sous RLS par la
//! [`TenantTx`]. Les deux champs de santé sont les deux prédicats de
//! `routes::health` recopiés : cette route vit dans le binaire et cette caisse
//! ne peut pas l'appeler, et deux `count` valent moins qu'un déplacement de
//! module.

use std::collections::BTreeMap;

use agentos_domain::ids::{IdempotencyKey, TenantId};
use agentos_providers::ProviderError;
use agentos_providers::email::{OutboundEmail, ProviderMessageId};
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::outbox::MAX_ATTEMPTS;
use chrono::{DateTime, NaiveDate, TimeDelta, Utc};
use serde::Serialize;
use sqlx::Row as _;

use crate::effects::{Ports, escape_html};
use crate::sequence::DEFAULT_HOUR;

/// Au-delà de quoi une question sans réponse ne bloque plus le siège qui l'a
/// posée — la valeur de `inbound::QUESTION_PATIENCE`, qu'un autre module ne
/// lit pas.
const QUESTION_PATIENCE: TimeDelta = TimeDelta::hours(24);

/// La journée d'un locataire.
#[derive(Debug, Default, Serialize)]
pub struct Digest {
    pub day: NaiveDate,
    /// Par séquence : lettres e-mail parties, et runs arrêtés par raison.
    pub sequences: Vec<SequenceDay>,
    /// Les réponses entrantes par e-mail, dans l'ordre d'arrivée.
    pub replies: Vec<Reply>,
    /// Les questions internes sans réponse de moins de 24 h, par siège
    /// demandeur : chacune bloque ce siège (`question_still_pending`).
    pub questions_pending: Vec<Pending>,
    /// Les approbations `pending` non expirées, par `action_kind`.
    pub approvals_pending: Vec<Pending>,
    /// Les tours du jour, par siège et par issue.
    pub turns: Vec<Turn>,
    /// Les séquences qui ont un flux : l'heure prévue et si elles ont nourri
    /// ce jour-là.
    pub feeds: Vec<Feed>,
    pub health: Health,
}

#[derive(Debug, Default, Serialize)]
pub struct SequenceDay {
    pub sequence: String,
    pub sent: i64,
    /// `stop_reason` → combien de runs arrêtés ce jour-là.
    pub stopped: BTreeMap<String, i64>,
}

#[derive(Debug, Serialize)]
pub struct Reply {
    pub sender: String,
    pub subject: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Un compte sous un nom — un siège, un `action_kind`.
#[derive(Debug, Serialize)]
pub struct Pending {
    pub name: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct Turn {
    pub employee: String,
    pub code: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct Feed {
    pub sequence: String,
    pub hour: i32,
    pub fed: bool,
}

/// Les deux nombres de `GET /v1/health/company` qui se recomptent sans son
/// verdict.
#[derive(Debug, Default, Serialize)]
pub struct Health {
    pub turns_attempted_today: i64,
    pub dead_lettered_today: i64,
}

/// La journée `day` du locataire de `tx`, lue à `now`.
pub async fn compute(
    tx: &mut TenantTx<'_>,
    day: NaiveDate,
    now: DateTime<Utc>,
) -> Result<Digest, StoreError> {
    let from = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let to = from + TimeDelta::days(1);

    // ponytail: un message est rattaché à une séquence par la conversation de
    // son run ; un contact enrôlé deux fois sur le même fil compterait pour
    // les deux. Joindre sur `last_message_id` ne verrait que le dernier pas.
    let mut sequences: BTreeMap<String, SequenceDay> = BTreeMap::new();
    for row in sqlx::query(
        "SELECT coalesce(s.name, '(hors séquence)') AS sequence, count(DISTINCT m.id) AS sent \
           FROM messages m \
           LEFT JOIN sequence_runs r ON r.conversation_id = m.conversation_id \
           LEFT JOIN sequences s ON s.id = r.sequence_id \
          WHERE m.direction = 'outbound' AND m.channel = 'email' \
            AND m.created_at >= $1 AND m.created_at < $2 \
          GROUP BY 1",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut ***tx)
    .await?
    {
        let name: String = row.get("sequence");
        let entry = sequences.entry(name.clone()).or_default();
        entry.sequence = name;
        entry.sent = row.get("sent");
    }
    for row in sqlx::query(
        "SELECT s.name, r.stop_reason, count(*) AS n \
           FROM sequence_runs r JOIN sequences s ON s.id = r.sequence_id \
          WHERE r.stop_reason IS NOT NULL AND r.ended_at >= $1 AND r.ended_at < $2 \
          GROUP BY 1, 2",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut ***tx)
    .await?
    {
        let name: String = row.get("name");
        let entry = sequences.entry(name.clone()).or_default();
        entry.sequence = name;
        entry.stopped.insert(row.get("stop_reason"), row.get("n"));
    }

    let replies = sqlx::query(
        "SELECT sender, subject, created_at FROM messages \
          WHERE direction = 'inbound' AND channel = 'email' \
            AND created_at >= $1 AND created_at < $2 \
          ORDER BY created_at",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    .map(|row| Reply {
        sender: row.get("sender"),
        subject: row.get("subject"),
        created_at: row.get("created_at"),
    })
    .collect();

    let questions_pending = counts(
        tx,
        "SELECT q.sender AS name, count(*) AS count FROM messages q \
          WHERE q.internal_kind = 'question' AND q.created_at > $1 \
            AND NOT EXISTS (SELECT 1 FROM messages a WHERE a.answers_message_id = q.id) \
          GROUP BY 1 ORDER BY 1",
        now - QUESTION_PATIENCE,
    )
    .await?;
    let approvals_pending = counts(
        tx,
        "SELECT action_kind AS name, count(*) AS count FROM approvals \
          WHERE state = 'pending' AND (expires_at IS NULL OR expires_at > $1) \
          GROUP BY 1 ORDER BY 1",
        now,
    )
    .await?;

    let turns = sqlx::query(
        "SELECT e.slug, o.code, count(*) AS n \
           FROM turn_outcomes o JOIN employees e ON e.id = o.employee_id \
          WHERE o.at >= $1 AND o.at < $2 GROUP BY 1, 2 ORDER BY 1, 2",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    .map(|row| Turn {
        employee: row.get("slug"),
        code: row.get("code"),
        count: row.get("n"),
    })
    .collect();

    let feeds = sqlx::query(
        "SELECT name, coalesce((feed->>'hour')::int, $2) AS hour, fed_on = $1::date AS fed \
           FROM sequences WHERE feed IS NOT NULL AND archived_at IS NULL ORDER BY name",
    )
    .bind(day)
    .bind(i32::from(DEFAULT_HOUR))
    .fetch_all(&mut ***tx)
    .await?
    .iter()
    .map(|row| Feed {
        sequence: row.get("name"),
        hour: row.get("hour"),
        fed: row.get::<Option<bool>, _>("fed").unwrap_or(false),
    })
    .collect();

    // Les deux prédicats de `routes::health`, `COUNTS_SQL` et
    // `DEAD_LETTERED_SQL`, bornés par le jour demandé plutôt qu'ouverts.
    let turns_attempted_today: i64 =
        sqlx::query_scalar("SELECT count(*) FROM turn_outcomes WHERE at >= $1 AND at < $2")
            .bind(from)
            .bind(to)
            .fetch_one(&mut ***tx)
            .await?;
    let dead_lettered_today: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_events \
          WHERE published_at IS NULL AND attempt_count >= $1 \
            AND available_at >= $2 AND available_at < $3",
    )
    .bind(MAX_ATTEMPTS)
    .bind(from)
    .bind(to)
    .fetch_one(&mut ***tx)
    .await?;

    Ok(Digest {
        day,
        sequences: sequences.into_values().collect(),
        replies,
        questions_pending,
        approvals_pending,
        turns,
        feeds,
        health: Health {
            turns_attempted_today,
            dead_lettered_today,
        },
    })
}

/// `(name, count)` groupé, avec une borne de temps.
async fn counts(
    tx: &mut TenantTx<'_>,
    sql: &'static str,
    since: DateTime<Utc>,
) -> Result<Vec<Pending>, StoreError> {
    Ok(sqlx::query(sql)
        .bind(since)
        .fetch_all(&mut ***tx)
        .await?
        .iter()
        .map(|row| Pending {
            name: row.get("name"),
            count: row.get("count"),
        })
        .collect())
}

/// Écrire la journée au fondateur, à `notify`, depuis `digest@{from_domain}`.
///
/// Le geste de [`crate::effects::notify_approver`] : pas d'effet, pas de
/// jeton — la plate-forme écrit à l'opérateur, à une adresse qu'il a posée
/// lui-même. Idempotent par locataire et par jour, par la clé du port.
pub async fn send(
    ports: &Ports,
    notify: &str,
    from_domain: &str,
    tenant: TenantId,
    digest: &Digest,
) -> Result<ProviderMessageId, ProviderError> {
    let email = OutboundEmail {
        from: format!("digest@{from_domain}"),
        to: vec![notify.to_owned()],
        subject: format!("Orizn — journée du {}", digest.day),
        body_text: text(digest),
        body_html: Some(html(digest)),
        in_reply_to: None,
        unsubscribe_token: None,
        attachments: Vec::new(),
    };
    let key = IdempotencyKey::for_platform(&format!("digest:{tenant}:{}", digest.day));
    ports.email.send(&key, &email).await
}

/// Le digest en lignes, pour `body_text` : la même chose que [`html`], sans
/// balise.
pub fn text(d: &Digest) -> String {
    let mut out = format!("Journée du {} (UTC)\n\n", d.day);
    out.push_str("Lettres par séquence\n");
    for s in &d.sequences {
        out.push_str(&format!("  {} : {} envoyées", s.sequence, s.sent));
        for (reason, n) in &s.stopped {
            out.push_str(&format!(", {n} {reason}"));
        }
        out.push('\n');
    }
    out.push_str(&format!("\nRéponses reçues : {}\n", d.replies.len()));
    for r in &d.replies {
        out.push_str(&format!(
            "  {} — {} — {}\n",
            r.created_at.format("%H:%M"),
            r.sender,
            r.subject.as_deref().unwrap_or("(sans objet)")
        ));
    }
    out.push_str("\nQuestions sans réponse (bloquent un siège)\n");
    for p in &d.questions_pending {
        out.push_str(&format!("  {} : {}\n", p.name, p.count));
    }
    out.push_str("\nApprobations en attente\n");
    for p in &d.approvals_pending {
        out.push_str(&format!("  {} : {}\n", p.name, p.count));
    }
    out.push_str("\nTours par siège\n");
    for t in &d.turns {
        out.push_str(&format!("  {} : {} × {}\n", t.employee, t.count, t.code));
    }
    out.push_str("\nNourrissages\n");
    for f in &d.feeds {
        out.push_str(&format!(
            "  {} : prévu {:02}h UTC, {}\n",
            f.sequence,
            f.hour,
            if f.fed { "nourri" } else { "pas nourri" }
        ));
    }
    out.push_str(&format!(
        "\nSanté : {} tours tentés, {} effets au rebut\n",
        d.health.turns_attempted_today, d.health.dead_lettered_today
    ));
    out
}

/// Le digest en tableaux HTML lisibles sur un téléphone : une colonne, des
/// tableaux pleine largeur, le même habillage que le mail d'approbation
/// (`effects::approval_html`). Tout texte venu de la base passe par
/// [`escape_html`] — un objet de mail est du texte d'un inconnu.
pub fn html(d: &Digest) -> String {
    let mut body = format!(
        "<h2 style=\"margin:0 0 16px;font-size:18px\">Journée du {} (UTC)</h2>",
        d.day
    );
    body.push_str(&table(
        "Lettres par séquence",
        &["Séquence", "Envoyées", "Arrêtées"],
        d.sequences.iter().map(|s| {
            vec![
                s.sequence.clone(),
                s.sent.to_string(),
                s.stopped
                    .iter()
                    .map(|(reason, n)| format!("{n} {reason}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ]
        }),
    ));
    body.push_str(&table(
        &format!("Réponses reçues : {}", d.replies.len()),
        &["Heure", "De", "Objet"],
        d.replies.iter().map(|r| {
            vec![
                r.created_at.format("%H:%M").to_string(),
                r.sender.clone(),
                r.subject
                    .clone()
                    .unwrap_or_else(|| "(sans objet)".to_owned()),
            ]
        }),
    ));
    body.push_str(&table(
        "Questions sans réponse (bloquent un siège)",
        &["Siège", "Questions"],
        d.questions_pending
            .iter()
            .map(|p| vec![p.name.clone(), p.count.to_string()]),
    ));
    body.push_str(&table(
        "Approbations en attente",
        &["Action", "En attente"],
        d.approvals_pending
            .iter()
            .map(|p| vec![p.name.clone(), p.count.to_string()]),
    ));
    body.push_str(&table(
        "Tours par siège",
        &["Siège", "Issue", "Tours"],
        d.turns
            .iter()
            .map(|t| vec![t.employee.clone(), t.code.clone(), t.count.to_string()]),
    ));
    body.push_str(&table(
        "Nourrissages",
        &["Séquence", "Heure prévue", "Aujourd'hui"],
        d.feeds.iter().map(|f| {
            vec![
                f.sequence.clone(),
                format!("{:02}h UTC", f.hour),
                (if f.fed { "nourri" } else { "pas nourri" }).to_owned(),
            ]
        }),
    ));
    body.push_str(&format!(
        "<p style=\"margin:16px 0 0\">Santé : {} tours tentés, {} effets au rebut.</p>",
        d.health.turns_attempted_today, d.health.dead_lettered_today
    ));
    format!(
        "<!doctype html><html><body style=\"margin:0;padding:16px;background:#f6f6f4\">\
         <div style=\"max-width:680px;margin:0 auto;background:#fff;padding:16px;\
         border-radius:8px;font:15px/1.5 system-ui,sans-serif;color:#1d1d1b\">{body}\
         </div></body></html>"
    )
}

/// Un titre et un tableau pleine largeur ; « rien » quand il n'y a pas de ligne.
fn table(title: &str, head: &[&str], rows: impl Iterator<Item = Vec<String>>) -> String {
    let cell = |tag: &str, s: &str| {
        format!(
            "<{tag} style=\"text-align:left;padding:6px 8px;border-bottom:1px solid #e6e6e2;\
             vertical-align:top\">{}</{tag}>",
            escape_html(s)
        )
    };
    let mut out = format!(
        "<h3 style=\"margin:20px 0 8px;font-size:15px\">{}</h3>",
        escape_html(title)
    );
    let body: Vec<String> = rows
        .map(|row| {
            format!(
                "<tr>{}</tr>",
                row.iter().map(|s| cell("td", s)).collect::<String>()
            )
        })
        .collect();
    if body.is_empty() {
        out.push_str("<p style=\"margin:0;color:#6b6b66\">rien</p>");
        return out;
    }
    out.push_str(&format!(
        "<table style=\"width:100%;border-collapse:collapse;font-size:14px\"><tr>{}</tr>{}</table>",
        head.iter().map(|h| cell("th", h)).collect::<String>(),
        body.concat()
    ));
    out
}

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::message::Channel;
    use agentos_store::db::Db;
    use uuid::Uuid;

    use super::*;
    use crate::inbound;
    use crate::sequence::{self, Step};

    struct Fixture {
        db: Db,
        tenant: TenantId,
        lena: EmployeeId,
        contact: Uuid,
    }

    /// Un locataire neuf sur la base partagée : le digest est tenant-scopé, la
    /// RLS isole ce test de ses voisins.
    async fn fixture() -> Option<Fixture> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; a digest is a SQL question");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let tenant = TenantId::new_v7(Utc::now());
        let lena = EmployeeId::new_v7(Utc::now());
        let account = Uuid::now_v7();
        let contact = Uuid::now_v7();
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'digest test')")
            .bind(tenant.as_uuid())
            .bind(format!("digest-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(lena.as_uuid())
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
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, account_id, full_name, email) \
             VALUES ($1, $2, $3, 'Paul', 'paul@prospect.example')",
        )
        .bind(contact)
        .bind(tenant.as_uuid())
        .bind(account)
        .execute(&mut *admin)
        .await
        .expect("contact");
        admin.commit().await.expect("commit");
        Some(Fixture {
            db,
            tenant,
            lena,
            contact,
        })
    }

    /// Une ligne de `messages`, telle que le test la veut : neuf champs
    /// parce que la table en a neuf qui comptent ici.
    #[allow(clippy::too_many_arguments)]
    async fn message(
        tx: &mut TenantTx<'_>,
        f: &Fixture,
        conversation: Uuid,
        channel: &str,
        direction: &str,
        sender: &str,
        subject: Option<&str>,
        kind: Option<&str>,
        at: DateTime<Utc>,
    ) {
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, conversation_id, employee_id, channel, \
                                   direction, sender, subject, body, idempotency_key, \
                                   internal_kind, received_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'corps', $9, $10, $11, $11)",
        )
        .bind(Uuid::now_v7())
        .bind(f.tenant.as_uuid())
        .bind(conversation)
        .bind(f.lena.as_uuid())
        .bind(channel)
        .bind(direction)
        .bind(sender)
        .bind(subject)
        .bind(Uuid::now_v7().to_string())
        .bind(kind)
        .bind(at)
        .execute(&mut ***tx)
        .await
        .expect("message");
    }

    /// **Deux lettres, une réponse, une question sans réponse, un run
    /// `not_sent` : les compteurs disent exactement cela, et la veille est
    /// vide.**
    #[tokio::test]
    async fn the_digest_counts_what_the_day_held_and_nothing_of_the_day_before() {
        let Some(f) = fixture().await else {
            return;
        };
        // Midi, pour que « il y a une heure » reste dans le jour.
        let now = Utc::now()
            .date_naive()
            .and_hms_opt(12, 0, 0)
            .expect("noon")
            .and_utc();
        let day = now.date_naive();

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let seq = sequence::define(
            &mut tx,
            "tech-quotidien",
            &[Step::Email {
                brief: Some("dis bonjour".to_owned()),
                variants: Vec::new(),
            }],
            None,
        )
        .await
        .expect("define");
        let run = sequence::enroll(&mut tx, seq, f.contact, f.lena, now)
            .await
            .expect("enroll");
        let thread = inbound::conversation_for(&mut tx, f.lena, Channel::Email, "paul", None, now)
            .await
            .expect("thread");
        // Le run porte le fil ; il meurt `not_sent` dans la journée.
        sqlx::query(
            "UPDATE sequence_runs SET conversation_id = $2, state = 'stopped', \
                    stop_reason = 'not_sent', ended_at = $3 WHERE id = $1",
        )
        .bind(run.as_uuid())
        .bind(thread.as_uuid())
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("stop");
        let hour = TimeDelta::hours(1);
        for at in [now - hour, now] {
            message(
                &mut tx,
                &f,
                thread.as_uuid(),
                "email",
                "outbound",
                "lena@orizn.example",
                Some("Bonjour"),
                None,
                at,
            )
            .await;
        }
        message(
            &mut tx,
            &f,
            thread.as_uuid(),
            "email",
            "inbound",
            "paul@prospect.example",
            Some("Re: Bonjour"),
            None,
            now + hour,
        )
        .await;
        let desk =
            inbound::conversation_for(&mut tx, f.lena, Channel::Internal, "founder", None, now)
                .await
                .expect("desk");
        message(
            &mut tx,
            &f,
            desk.as_uuid(),
            "internal",
            "inbound",
            "lena",
            None,
            Some("question"),
            now - hour,
        )
        .await;
        tx.commit().await.expect("commit");

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let d = compute(&mut tx, day, now + TimeDelta::hours(6))
            .await
            .expect("compute");
        assert_eq!(d.sequences.len(), 1, "{d:?}");
        assert_eq!(d.sequences[0].sequence, "tech-quotidien");
        assert_eq!(d.sequences[0].sent, 2);
        assert_eq!(d.sequences[0].stopped.get("not_sent"), Some(&1));
        assert_eq!(d.replies.len(), 1);
        assert_eq!(d.replies[0].sender, "paul@prospect.example");
        assert_eq!(d.replies[0].subject.as_deref(), Some("Re: Bonjour"));
        assert_eq!(d.questions_pending.len(), 1);
        assert_eq!(d.questions_pending[0].name, "lena");
        assert_eq!(d.questions_pending[0].count, 1);
        assert!(d.approvals_pending.is_empty());
        assert!(d.turns.is_empty());
        assert!(d.feeds.is_empty());
        assert_eq!(d.health.turns_attempted_today, 0);

        // La veille : rien n'est daté de ce jour-là ; la question, elle, est
        // un état et reste visible.
        let yesterday = compute(&mut tx, day - TimeDelta::days(1), now + TimeDelta::hours(6))
            .await
            .expect("compute");
        assert!(yesterday.sequences.is_empty(), "{yesterday:?}");
        assert!(yesterday.replies.is_empty());
        assert_eq!(yesterday.questions_pending.len(), 1);

        // Deux jours plus tard, la question ne bloque plus personne.
        let later = compute(&mut tx, day, now + TimeDelta::days(2))
            .await
            .expect("compute");
        assert!(later.questions_pending.is_empty());
        tx.rollback().await.expect("rollback");

        let json = serde_json::to_value(&d).expect("json");
        assert_eq!(json["sequences"][0]["stopped"]["not_sent"], 1);
        let html = html(&d);
        assert!(html.contains("tech-quotidien"));
        assert!(html.contains("Re: Bonjour"));
        assert!(text(&d).contains("tech-quotidien : 2 envoyées, 1 not_sent"));
    }

    #[test]
    fn the_html_escapes_what_a_stranger_wrote_and_says_nothing_for_empty_tables() {
        let d = Digest {
            replies: vec![Reply {
                sender: "x@y.example".to_owned(),
                subject: Some("<script>&".to_owned()),
                created_at: Utc::now(),
            }],
            ..Digest::default()
        };
        let html = html(&d);
        assert!(html.contains("&lt;script&gt;&amp;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains(">rien<"));
    }
}
