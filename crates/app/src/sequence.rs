//! La séquence : ce qu'un séquenceur vend — déclencheur, email, attente,
//! branche — sans l'interface. Les employés écrivent les mails ; ce module
//! tient la position et la règle.
//!
//! [`crate::follow_up`] a choisi « ni table ni verbe », et pour un pas c'était
//! juste : une promesse posée après l'envoi, annulée par la réponse, un réveil
//! qui dit « écris encore ». Une séquence a plusieurs pas, saute d'un pas à
//! l'autre sur une lecture (`message_events`, `0091`) et doit savoir où elle en
//! est entre deux ticks. Une position est une ligne, donc une table (`0092`),
//! et une position qui avance est un verbe, donc [`advance`].
//!
//! # Pas de second chemin d'envoi
//!
//! Un pas [`Step::Email`] **ne poste rien**. Il réserve une promesse calendrier
//! *maintenant* qui porte le run (`appointments.sequence_run_id`) ; quand elle
//! sonne, `loops::initiative` réveille le siège avec [`brief`] — quel pas, quoi
//! écrire, ce qu'est devenu le précédent — et le `send_email` que le modèle
//! propose passe la Gate comme tout autre : suppression, budget d'inconnus du
//! jour, `MAX_TOUCHES`. Toutes les protections existantes s'appliquent parce
//! qu'elles ne sont pas réécrites. Le run apprend que l'envoi est parti par
//! [`sent`], appelé depuis [`Effects::chase`](crate::effects::Effects::chase)
//! dans la transaction qui enregistre le message sur son fil.
//!
//! # Les statements, et où chacun s'exécute
//!
//! * **[`advance`]** — depuis `loops::sequence`, toutes les 30 s, pour chaque
//!   run actif dont `next_at` est passé. La machine à états d'un tick : un
//!   `Email` réserve et attend ; un `Wait` pousse `next_at` ; un `Branch` lit
//!   les traces et saute ; la fin de liste est `done`.
//! * **[`sent`]** — depuis `Effects::chase`, à côté de `follow_up::sent`. Trouve
//!   le run par la promesse claim-ée que ce siège est en train de tenir, pose
//!   le fil et le message, avance d'un pas. Quand un run a pris l'envoi, la
//!   relance J+3 n'est **pas** posée : la séquence est la relance, et deux
//!   mécanismes pour « réécrire dans trois jours » se contredisent.
//! * **[`replied`]** — depuis `inbound::land`, à côté de
//!   `calendar::cancel_for_conversation` : tout run actif sur le fil passe en
//!   `replied` dans la transaction qui pose la réponse.
//! * **[`brief`]** — depuis `loops::initiative`, quand la promesse qui sonne
//!   porte un run.
//!
//! # Ce qui arrête un run, et pourquoi c'est ici et pas dans la Gate
//!
//! La suppression est vérifiée dans [`advance`] **avant de réserver**, par la
//! même fonction que la Gate (`revenue_suppression_of`) : c'est plus court que
//! de remonter le refus depuis `Effects`, et ça évite de réveiller un siège pour
//! un envoi que la Gate refuserait de toute façon. Si la suppression arrive
//! entre la réservation et le réveil, la Gate refuse, rien ne part, et le run
//! s'arrête au tick suivant en `not_sent` — un délai de [`SEND_DEADLINE`] sans
//! envoi après un réveil est la seule lecture possible de « le siège a été
//! réveillé et rien n'est parti ».
//!
//! `MAX_TOUCHES` reste la limite d'emails par fil : la séquence s'arrête là
//! (`stopped`, `max_touches`) plutôt que de la contourner. Personne qui a
//! ignoré trois mails n'attend le quatrième, et une séquence qui en promettrait
//! cinq est une séquence dont les deux derniers pas ne s'exécutent pas.

use agentos_domain::action::EmailAddress;
use agentos_domain::ids::{
    AppointmentId, ConversationId, EmployeeId, SequenceId, SequenceRunId, TenantId,
};
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError, TenantTx};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::inbound;
use crate::revenue::MAX_TOUCHES;

/// Au plus tant de pas. Douze est trois emails, leurs attentes et leurs
/// branches ; une séquence plus longue est une séquence qu'aucun `MAX_TOUCHES`
/// ne laisse finir.
pub const MAX_STEPS: usize = 12;

/// Une attente est entre une heure et trente jours.
pub const MAX_WAIT_HOURS: u32 = 24 * 30;

/// Combien de temps un pas `Email` attend son envoi après avoir réservé la
/// promesse. Passé ce délai sans [`sent`], le siège a été réveillé et rien
/// n'est parti — la Gate a refusé, ou le modèle n'a pas écrit — et le run
/// s'arrête en `not_sent` plutôt que de réveiller encore.
pub const SEND_DEADLINE: TimeDelta = TimeDelta::hours(24);

/// Le fuseau des promesses de séquence : UTC, pour la raison de
/// `follow_up::ZONE` — personne n'a dit « trois heures » à personne.
const ZONE: &str = "UTC";

/// Ce qu'une branche lit dans `message_events`.
///
/// Pas de `Replied` : [`replied`] termine le run dans la transaction qui pose
/// la réponse, donc un pas qui brancherait dessus ne serait jamais évalué.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Opened,
    Clicked,
}

impl Signal {
    const fn kind(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Clicked => "clicked",
        }
    }
}

/// Un pas, tel qu'il est sérialisé dans `sequences.steps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Ce que l'employé doit écrire — pas le texte du mail.
    Email { brief: String },
    /// Attendre tant d'heures avant le pas suivant.
    Wait { hours: u32 },
    /// Sauter à `then` si le dernier mail a reçu le signal, à `otherwise`
    /// sinon. Un index égal au nombre de pas est la fin de la liste.
    Branch {
        on: Signal,
        then: usize,
        otherwise: usize,
    },
}

/// Pourquoi une liste de pas est refusée. Chaque variante nomme le pas.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Invalid {
    #[error("a sequence needs at least one step")]
    Empty,
    #[error("at most {MAX_STEPS} steps; got {0}")]
    TooMany(usize),
    #[error("a sequence needs at least one `email` step")]
    NoEmail,
    #[error("step {0}: an `email` step needs a brief")]
    EmptyBrief(usize),
    #[error("step {0}: `hours` is 1 to {MAX_WAIT_HOURS}")]
    WaitOutOfRange(usize),
    #[error("step {0}: a branch target must be a step index or the end of the list")]
    JumpOutOfRange(usize),
    #[error("step {0}: a branch cannot jump to itself")]
    JumpToSelf(usize),
    #[error("step {0}: a cycle with no `wait` in it would run every tick")]
    CycleWithoutWait(usize),
}

/// Les règles de forme, toutes, avant qu'une ligne existe.
///
/// La passe de cycle ne regarde que les pas qui ne sont pas des `Wait` : un
/// cycle qui traverse une attente est une boucle voulue (relancer tant que ce
/// n'est pas ouvert, jusqu'à `MAX_TOUCHES`), un cycle sans attente tournerait
/// à chaque tick.
pub fn validate(steps: &[Step]) -> Result<(), Invalid> {
    if steps.is_empty() {
        return Err(Invalid::Empty);
    }
    if steps.len() > MAX_STEPS {
        return Err(Invalid::TooMany(steps.len()));
    }
    if !steps.iter().any(|s| matches!(s, Step::Email { .. })) {
        return Err(Invalid::NoEmail);
    }
    for (i, step) in steps.iter().enumerate() {
        match step {
            Step::Email { brief } if brief.trim().is_empty() => return Err(Invalid::EmptyBrief(i)),
            Step::Wait { hours } if !(1..=MAX_WAIT_HOURS).contains(hours) => {
                return Err(Invalid::WaitOutOfRange(i));
            }
            Step::Branch {
                then, otherwise, ..
            } => {
                if *then > steps.len() || *otherwise > steps.len() {
                    return Err(Invalid::JumpOutOfRange(i));
                }
                if *then == i || *otherwise == i {
                    return Err(Invalid::JumpToSelf(i));
                }
            }
            _ => {}
        }
    }
    // DFS three-colour over the non-`Wait` nodes. An edge into a `Wait` or past
    // the end is dropped: it cannot close a cycle that matters.
    let next = |i: usize| -> Vec<usize> {
        match &steps[i] {
            Step::Email { .. } | Step::Wait { .. } => vec![i + 1],
            Step::Branch {
                then, otherwise, ..
            } => vec![*then, *otherwise],
        }
    };
    let mut colour = vec![0u8; steps.len()];
    fn visit(
        i: usize,
        steps: &[Step],
        colour: &mut [u8],
        next: &dyn Fn(usize) -> Vec<usize>,
    ) -> Option<usize> {
        if i >= steps.len() || matches!(steps[i], Step::Wait { .. }) {
            return None;
        }
        match colour[i] {
            1 => return Some(i),
            2 => return None,
            _ => {}
        }
        colour[i] = 1;
        for j in next(i) {
            if let Some(at) = visit(j, steps, colour, next) {
                return Some(at);
            }
        }
        colour[i] = 2;
        None
    }
    for i in 0..steps.len() {
        if let Some(at) = visit(i, steps, &mut colour, &next) {
            return Err(Invalid::CycleWithoutWait(at));
        }
    }
    Ok(())
}

/// Pourquoi une définition est refusée.
#[derive(Debug, thiserror::Error)]
pub enum DefineError {
    #[error(transparent)]
    Invalid(#[from] Invalid),
    #[error("a live sequence of this company already has this name")]
    NameTaken,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for DefineError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::from(err))
    }
}

/// Écrire une séquence. Le nom est unique parmi les vivantes du locataire.
pub async fn define(
    tx: &mut TenantTx<'_>,
    name: &str,
    steps: &[Step],
) -> Result<SequenceId, DefineError> {
    validate(steps)?;
    let id = SequenceId::new_v7(Utc::now());
    let inserted = sqlx::query(
        "INSERT INTO sequences (id, tenant_id, name, steps) VALUES ($1, $2, $3, $4) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(name.trim())
    .bind(serde_json::to_value(steps).map_err(|e| StoreError::conflict(e.to_string()))?)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(DefineError::NameTaken);
    }
    Ok(id)
}

/// Une séquence, telle que le fondateur la relit.
#[derive(Debug, Clone, Serialize)]
pub struct Sequence {
    pub id: SequenceId,
    pub name: String,
    pub steps: Vec<Step>,
    pub created_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

/// Les séquences du locataire, vivantes d'abord, les plus récentes en tête.
pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Sequence>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, name, steps, created_at, archived_at FROM sequences \
         ORDER BY archived_at IS NOT NULL, created_at DESC",
    )
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows
        .iter()
        .map(|row| Sequence {
            id: SequenceId::from_uuid(row.get("id")),
            name: row.get("name"),
            steps: serde_json::from_value(row.get("steps")).unwrap_or_default(),
            created_at: row.get("created_at"),
            archived_at: row.get("archived_at"),
        })
        .collect())
}

/// Archiver : le nom est libéré, les runs actifs continuent jusqu'au bout.
/// [`StoreError::NotFound`] pour une séquence d'un autre locataire ou déjà
/// archivée.
pub async fn archive(tx: &mut TenantTx<'_>, id: SequenceId) -> Result<(), StoreError> {
    let n = sqlx::query(
        "UPDATE sequences SET archived_at = now() WHERE id = $1 AND archived_at IS NULL",
    )
    .bind(id.as_uuid())
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Pourquoi une inscription est refusée.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// Une séquence, un contact ou un siège que ce locataire n'a pas — ou un
    /// contact inactif, sans adresse, ou un siège qui n'est plus actif.
    #[error("no such {0} in this company")]
    NotFound(&'static str),
    #[error("this address has asked to be left alone")]
    Suppressed,
    #[error("this contact is already in this sequence")]
    AlreadyActive,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for EnrollError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::from(err))
    }
}

/// Inscrire un contact : un run à la position 0, dû maintenant.
pub async fn enroll(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
    contact: Uuid,
    employee: EmployeeId,
    now: DateTime<Utc>,
) -> Result<SequenceRunId, EnrollError> {
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sequences WHERE id = $1 AND archived_at IS NULL)",
    )
    .bind(sequence.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    if !live {
        return Err(EnrollError::NotFound("sequence"));
    }
    let seat: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM employees WHERE id = $1 AND lifecycle = 'active')",
    )
    .bind(employee.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    if !seat {
        return Err(EnrollError::NotFound("employee"));
    }
    // Suppressed before inactive: `suppressions_deactivate_contacts` (0011)
    // flips `active` on an opt-out, and the caller is owed the reason, not
    // the trigger's side effect.
    let contact_row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT revenue_suppression_of(email, null::text) IS NOT NULL, active \
           FROM contacts WHERE id = $1 AND email IS NOT NULL",
    )
    .bind(contact)
    .fetch_optional(&mut ***tx)
    .await?;
    match contact_row {
        Some((true, _)) => return Err(EnrollError::Suppressed),
        Some((false, true)) => {}
        _ => return Err(EnrollError::NotFound("contact")),
    }
    let id = SequenceRunId::new_v7(now);
    let inserted = sqlx::query(
        "INSERT INTO sequence_runs (id, tenant_id, sequence_id, contact_id, employee_id, \
                                    next_at, started_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $6) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(sequence.as_uuid())
    .bind(contact)
    .bind(employee.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(EnrollError::AlreadyActive);
    }
    Ok(id)
}

/// Un run, tel que le fondateur le relit.
#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub id: SequenceRunId,
    pub sequence_id: SequenceId,
    pub contact_id: Uuid,
    pub employee_id: EmployeeId,
    pub conversation_id: Option<ConversationId>,
    pub step: i32,
    pub state: String,
    pub stop_reason: Option<String>,
    pub next_at: Option<DateTime<Utc>>,
    pub last_message_id: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

const RUN_COLUMNS: &str = "id, sequence_id, contact_id, employee_id, conversation_id, step, state, \
                           stop_reason, next_at, last_message_id, started_at, ended_at";

fn run_of(row: &sqlx::postgres::PgRow) -> Run {
    Run {
        id: SequenceRunId::from_uuid(row.get("id")),
        sequence_id: SequenceId::from_uuid(row.get("sequence_id")),
        contact_id: row.get("contact_id"),
        employee_id: EmployeeId::from_uuid(row.get("employee_id")),
        conversation_id: row
            .get::<Option<Uuid>, _>("conversation_id")
            .map(ConversationId::from_uuid),
        step: row.get("step"),
        state: row.get("state"),
        stop_reason: row.get("stop_reason"),
        next_at: row.get("next_at"),
        last_message_id: row.get("last_message_id"),
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
    }
}

/// Les runs d'une séquence, les plus récents en tête.
pub async fn runs(tx: &mut TenantTx<'_>, sequence: SequenceId) -> Result<Vec<Run>, StoreError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM sequence_runs WHERE sequence_id = $1 \
         ORDER BY started_at DESC, id DESC"
    )))
    .bind(sequence.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;
    Ok(rows.iter().map(run_of).collect())
}

/// Un run, lu. `None` hors du locataire.
pub async fn find(tx: &mut TenantTx<'_>, run: SequenceRunId) -> Result<Option<Run>, StoreError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM sequence_runs WHERE id = $1"
    )))
    .bind(run.as_uuid())
    .fetch_optional(&mut ***tx)
    .await?;
    Ok(row.as_ref().map(run_of))
}

/// La promesse réservée pour le pas courant, s'il y en a une : posée après le
/// dernier envoi du run (`at > received_at`), ou après le départ quand rien
/// n'est parti. `rang_at IS NULL` tant qu'elle n'a pas sonné.
///
/// `$1` est le run, `$2` son `last_message_id`. Les deux moitiés de ce
/// fragment sont des constantes de ce module ; aucune valeur d'appelant n'y
/// entre, tout passe en paramètre — l'audit que `AssertSqlSafe` demande.
const PENDING_PROMISE: &str = "SELECT a.rang_at IS NULL FROM appointments a \
     WHERE a.sequence_run_id = $1 \
       AND a.at > coalesce((SELECT m.received_at FROM messages m WHERE m.id = $2), \
                           '-infinity'::timestamptz) \
     ORDER BY a.at DESC LIMIT 1";

async fn stop(
    tx: &mut TenantTx<'_>,
    run: SequenceRunId,
    state: &str,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE sequence_runs SET state = $2, stop_reason = $3, next_at = NULL, ended_at = $4 \
          WHERE id = $1",
    )
    .bind(run.as_uuid())
    .bind(state)
    .bind(reason)
    .bind(now)
    .execute(&mut ***tx)
    .await?;
    Ok(())
}

async fn goto(
    tx: &mut TenantTx<'_>,
    run: SequenceRunId,
    step: usize,
    next_at: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE sequence_runs SET step = $2, next_at = $3 WHERE id = $1")
        .bind(run.as_uuid())
        .bind(step as i32)
        .bind(next_at)
        .execute(&mut ***tx)
        .await?;
    Ok(())
}

/// The one line the promise carries: our word and the masked address.
fn subject(contact: &str) -> String {
    format!("sequence · {}", inbound::masked_contact(contact))
        .chars()
        .take(calendar::MAX_SUBJECT)
        .collect()
}

/// La machine à états d'un tick, sous verrou (`FOR UPDATE SKIP LOCKED`) : un
/// run qu'un autre tick tient, ou qui n'est plus actif, est laissé tel quel.
pub async fn advance(
    tx: &mut TenantTx<'_>,
    run: SequenceRunId,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let Some(row) = sqlx::query(
        "SELECT r.step, r.employee_id, r.conversation_id, r.last_message_id, s.steps, \
                c.email, c.active, revenue_suppression_of(c.email, null::text) IS NOT NULL AS suppressed \
           FROM sequence_runs r \
           JOIN sequences s ON s.id = r.sequence_id \
           JOIN contacts c ON c.id = r.contact_id \
          WHERE r.id = $1 AND r.state = 'active' \
            FOR UPDATE OF r SKIP LOCKED",
    )
    .bind(run.as_uuid())
    .fetch_optional(&mut ***tx)
    .await?
    else {
        return Ok(());
    };
    let step = row.get::<i32, _>("step") as usize;
    let employee = EmployeeId::from_uuid(row.get("employee_id"));
    let conversation = row
        .get::<Option<Uuid>, _>("conversation_id")
        .map(ConversationId::from_uuid);
    let last_message: Option<Uuid> = row.get("last_message_id");
    let steps: Vec<Step> = serde_json::from_value(row.get("steps")).unwrap_or_default();
    let email: Option<String> = row.get("email");

    match steps.get(step) {
        None => stop(tx, run, "done", None, now).await,
        Some(Step::Wait { hours }) => {
            goto(tx, run, step + 1, now + TimeDelta::hours(i64::from(*hours))).await
        }
        Some(Step::Branch {
            on,
            then,
            otherwise,
            ..
        }) => {
            let seen = match last_message {
                None => false,
                Some(id) => signal_seen(tx, id, *on).await?,
            };
            goto(tx, run, if seen { *then } else { *otherwise }, now).await
        }
        Some(Step::Email { .. }) => {
            if row.get::<bool, _>("suppressed") {
                return stop(tx, run, "stopped", Some("suppressed"), now).await;
            }
            let Some(email) = email.filter(|_| row.get::<bool, _>("active")) else {
                return stop(tx, run, "stopped", Some("inactive"), now).await;
            };
            if let Some(thread) = conversation {
                let outbound: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM messages \
                      WHERE conversation_id = $1 AND direction = 'outbound'",
                )
                .bind(thread.as_uuid())
                .fetch_one(&mut ***tx)
                .await?;
                if outbound >= MAX_TOUCHES as i64 {
                    return stop(tx, run, "stopped", Some("max_touches"), now).await;
                }
            }
            let pending: Option<bool> = sqlx::query_scalar(PENDING_PROMISE)
                .bind(run.as_uuid())
                .bind(last_message)
                .fetch_optional(&mut ***tx)
                .await?;
            match pending {
                // Le siège a été réveillé et rien n'est parti dans le délai.
                Some(false) => stop(tx, run, "stopped", Some("not_sent"), now).await,
                // Réservée, pas encore sonné : la boucle initiative est en
                // retard, on attend encore.
                //
                // ponytail: un siège qui n'est plus `active` ne sonne jamais
                // (`claim_due` filtre le cycle de vie), et ce run se renouvelle
                // alors tous les `SEND_DEADLINE` sans fin. Le jour où ça gêne,
                // `stop(…, "seat_gone")` quand `employees.lifecycle` a changé.
                Some(true) => goto(tx, run, step, now + SEND_DEADLINE).await,
                None => {
                    let booked = calendar::book_on(
                        tx,
                        AppointmentId::new_v7(now),
                        employee,
                        now,
                        ZONE,
                        &subject(&email),
                        conversation,
                    )
                    .await?;
                    sqlx::query("UPDATE appointments SET sequence_run_id = $2 WHERE id = $1")
                        .bind(booked.id.as_uuid())
                        .bind(run.as_uuid())
                        .execute(&mut ***tx)
                        .await?;
                    goto(tx, run, step, now + SEND_DEADLINE).await
                }
            }
        }
    }
}

/// Une trace `0091` sur ce message : par son id, ou par l'id fournisseur quand
/// la trace est arrivée avant que l'outbox ait posé la ligne.
async fn signal_seen(
    tx: &mut TenantTx<'_>,
    message: Uuid,
    signal: Signal,
) -> Result<bool, StoreError> {
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM message_events e \
                         WHERE e.kind = $2 \
                           AND (e.message_id = $1 \
                                OR e.provider_message_id = \
                                   (SELECT provider_message_id FROM messages WHERE id = $1)))",
    )
    .bind(message)
    .bind(signal.kind())
    .fetch_one(&mut ***tx)
    .await?;
    Ok(seen)
}

/// L'envoi qu'une promesse de run attendait est parti : poser le fil et le
/// message, avancer d'un pas, dû maintenant. `None` quand aucun run de ce siège
/// n'attendait un envoi à cette adresse — l'ordinaire, et la relance J+3 prend
/// alors le relais.
///
/// Le run est trouvé par **la promesse claim-ée que ce siège tient** : une
/// promesse du run qui a sonné (`rang_at`), posée pour le pas courant. Un
/// second `send_email` du même tour à la même adresse ne trouve rien, parce que
/// le premier a déplacé `last_message_id` derrière la promesse.
pub async fn sent(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    conversation: ConversationId,
    to: &EmailAddress,
    provider_message_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<SequenceRunId>, StoreError> {
    let message: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM messages \
          WHERE conversation_id = $1 AND provider_message_id = $2 AND direction = 'outbound'",
    )
    .bind(conversation.as_uuid())
    .bind(provider_message_id)
    .fetch_optional(&mut ***tx)
    .await?;
    let Some(message) = message else {
        return Ok(None);
    };
    let advanced: Option<Uuid> = sqlx::query_scalar(
        "UPDATE sequence_runs r \
            SET last_message_id = $3, conversation_id = $2, step = r.step + 1, next_at = $5 \
           FROM contacts c \
          WHERE c.id = r.contact_id AND r.state = 'active' AND r.employee_id = $1 \
            AND c.email = $4 \
            AND (r.conversation_id IS NULL OR r.conversation_id = $2) \
            AND EXISTS (SELECT 1 FROM appointments a \
                         WHERE a.sequence_run_id = r.id AND a.rang_at IS NOT NULL \
                           AND a.at > coalesce((SELECT m.received_at FROM messages m \
                                                 WHERE m.id = r.last_message_id), \
                                               '-infinity'::timestamptz)) \
         RETURNING r.id",
    )
    .bind(employee.as_uuid())
    .bind(conversation.as_uuid())
    .bind(message)
    .bind(to.to_string())
    .bind(now)
    .fetch_optional(&mut ***tx)
    .await?;
    Ok(advanced.map(SequenceRunId::from_uuid))
}

/// Une réponse sur le fil : tout run actif dessus est `replied`. Combien.
pub async fn replied(
    tx: &mut TenantTx<'_>,
    conversation: ConversationId,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let n = sqlx::query(
        "UPDATE sequence_runs SET state = 'replied', next_at = NULL, ended_at = $2 \
          WHERE conversation_id = $1 AND state = 'active'",
    )
    .bind(conversation.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    Ok(n)
}

/// Ce qui est dit, dans notre voix, quand la promesse d'un pas sonne.
///
/// L'adresse est dedans, en clair, et c'est voulu : le premier pas d'une
/// séquence n'a pas de fil, donc pas de cadre qui la montre déjà, et le modèle
/// doit savoir à qui écrire. La ligne `contacts.email` est celle que le
/// fondateur a importée, sous une CHECK qui n'admet que `local@domaine` sans
/// espace — aucune phrase ne tient dedans. Le brief du pas est le texte du
/// fondateur, comme la charte. `None` hors du locataire ou sur un run fini,
/// et le tour tourne sur le cadre seul.
pub async fn brief(db: &Db, tenant: TenantId, run: SequenceRunId) -> Option<String> {
    let mut tx = db.tenant_tx(tenant).await.ok()?;
    let row = sqlx::query(
        "SELECT s.name, s.steps, r.step, c.email, r.conversation_id, r.last_message_id \
           FROM sequence_runs r \
           JOIN sequences s ON s.id = r.sequence_id \
           JOIN contacts c ON c.id = r.contact_id \
          WHERE r.id = $1 AND r.state = 'active'",
    )
    .bind(run.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .ok()??;
    let steps: Vec<Step> = serde_json::from_value(row.get("steps")).unwrap_or_default();
    let step = row.get::<i32, _>("step") as usize;
    let Some(Step::Email { brief }) = steps.get(step) else {
        let _ = tx.rollback().await;
        return None;
    };
    let name: String = row.get("name");
    let email: Option<String> = row.get("email");
    let conversation: Option<Uuid> = row.get("conversation_id");
    let last_message: Option<Uuid> = row.get("last_message_id");
    let outbound: i64 = match conversation {
        Some(thread) => sqlx::query_scalar(
            "SELECT count(*) FROM messages WHERE conversation_id = $1 AND direction = 'outbound'",
        )
        .bind(thread)
        .fetch_one(&mut **tx)
        .await
        .ok()?,
        None => 0,
    };
    let (opened, clicked) = match last_message {
        Some(id) => (
            signal_seen(&mut tx, id, Signal::Opened).await.ok()?,
            signal_seen(&mut tx, id, Signal::Clicked).await.ok()?,
        ),
        None => (false, false),
    };
    let _ = tx.rollback().await;
    let history = match (outbound, opened, clicked) {
        (0, _, _) => "Nothing has gone out to them in this sequence yet.".to_owned(),
        (n, _, true) => format!(
            "{n} email(s) have gone out on this thread; the last one was opened and a link in it was clicked."
        ),
        (n, true, false) => format!(
            "{n} email(s) have gone out on this thread; the last one was opened and nothing came back."
        ),
        (n, false, false) => {
            format!("{n} email(s) have gone out on this thread; the last one was never opened.")
        }
    };
    Some(format!(
        "This hour is step {} of {} of the sequence \"{}\", for {}. What this step asks of you: {}. \
         {} Write that email now, as one `send_email` to that address — and if the send is \
         refused, they have asked to be left alone and that is the answer.",
        step + 1,
        steps.len(),
        name.trim(),
        email.unwrap_or_default(),
        brief.trim().trim_end_matches('.'),
        history,
    ))
}

// ---------------------------------------------------------------------------
// Catalogue : deux lignes prêtes, appliquées par personne d'autre que le
// fondateur
// ---------------------------------------------------------------------------
//
// Une ligne de `turn.rs::catalogue()` est facturée à **chaque appel modèle** et
// déplace `cost::DIGEST` ; le re-pin du 2026-09-05 a mesuré ce que coûte une
// ligne de plus ($87 → $450/mois quand les appels par tour sont passés de 2 à
// 8). Les deux lignes ci-dessous sont donc écrites ici et nulle part ailleurs :
// le fondateur les applique après un re-pin `--live`, jamais un agent.
//
// ```text
// ActionKind::DefineSequence  — "define_sequence"
//   {"type":"object","required":["name","steps"],"properties":{
//     "name":{"type":"string","minLength":1,"maxLength":200},
//     "steps":{"type":"array","minItems":1,"maxItems":12,"items":{"oneOf":[
//       {"type":"object","required":["kind","brief"],"properties":{
//         "kind":{"const":"email"},"brief":{"type":"string","minLength":1}}},
//       {"type":"object","required":["kind","hours"],"properties":{
//         "kind":{"const":"wait"},"hours":{"type":"integer","minimum":1,"maximum":720}}},
//       {"type":"object","required":["kind","on","then","otherwise"],"properties":{
//         "kind":{"const":"branch"},"on":{"enum":["opened","clicked"]},
//         "then":{"type":"integer","minimum":0},"otherwise":{"type":"integer","minimum":0}}}
//     ]}}}}
//   → `sequence::define` ; 400 avec `Invalid` en motif.
//
// ActionKind::EnrollInSequence — "enroll_in_sequence"
//   {"type":"object","required":["sequence_id","contact_id"],"properties":{
//     "sequence_id":{"type":"string","format":"uuid"},
//     "contact_id":{"type":"string","format":"uuid"}}}
//   → `sequence::enroll` avec le siège du tour comme `employee` ; refus pour
//     suppression (`Suppressed`) et doublon (`AlreadyActive`).
// ```

#[cfg(test)]
mod tests {
    use agentos_domain::message::{CanonicalMessage, Channel, Direction, ProviderRef};
    use agentos_domain::untrusted::Untrusted;
    use agentos_store::revenue as suppressions;
    use chrono::SubsecRound;

    use super::*;
    use crate::follow_up;

    fn email(brief: &str) -> Step {
        Step::Email {
            brief: brief.to_owned(),
        }
    }
    fn wait(hours: u32) -> Step {
        Step::Wait { hours }
    }
    fn branch(on: Signal, then: usize, otherwise: usize) -> Step {
        Step::Branch {
            on,
            then,
            otherwise,
        }
    }

    #[test]
    fn every_shape_rule_bites() {
        assert_eq!(validate(&[]), Err(Invalid::Empty));
        assert_eq!(
            validate(&vec![email("x"); MAX_STEPS + 1]),
            Err(Invalid::TooMany(MAX_STEPS + 1))
        );
        assert_eq!(validate(&[wait(1)]), Err(Invalid::NoEmail));
        assert_eq!(validate(&[email("  ")]), Err(Invalid::EmptyBrief(0)));
        assert_eq!(
            validate(&[email("x"), wait(0)]),
            Err(Invalid::WaitOutOfRange(1))
        );
        assert_eq!(
            validate(&[email("x"), wait(MAX_WAIT_HOURS + 1)]),
            Err(Invalid::WaitOutOfRange(1))
        );
        assert_eq!(
            validate(&[email("x"), branch(Signal::Opened, 3, 0)]),
            Err(Invalid::JumpOutOfRange(1))
        );
        assert_eq!(
            validate(&[email("x"), branch(Signal::Opened, 1, 0)]),
            Err(Invalid::JumpToSelf(1))
        );
        // email(0) → branch(1) → email(0): no wait between two passes.
        assert_eq!(
            validate(&[email("x"), branch(Signal::Opened, 2, 0)]),
            Err(Invalid::CycleWithoutWait(0))
        );
        // The same loop through a wait is a sequence: chase until opened.
        assert_eq!(
            validate(&[
                email("x"),
                wait(72),
                branch(Signal::Opened, 4, 0),
                email("y")
            ]),
            Ok(())
        );
        // Jumping to the end of the list is "done".
        assert_eq!(
            validate(&[email("x"), branch(Signal::Clicked, 2, 2)]),
            Ok(())
        );
    }

    #[test]
    fn steps_serialise_as_the_catalogue_says() {
        let json =
            serde_json::to_value([email("say hello"), wait(48), branch(Signal::Opened, 3, 0)])
                .expect("json");
        assert_eq!(
            json,
            serde_json::json!([
                {"kind": "email", "brief": "say hello"},
                {"kind": "wait", "hours": 48},
                {"kind": "branch", "on": "opened", "then": 3, "otherwise": 0},
            ])
        );
    }

    struct Fixture {
        db: Db,
        tenant: TenantId,
        lena: EmployeeId,
        contact: Uuid,
        other: TenantId,
    }

    async fn fixture() -> Option<Fixture> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; a sequence needs a database");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let (tenant, lena, contact) = seed(&db).await;
        let (other, _, _) = seed(&db).await;
        Some(Fixture {
            db,
            tenant,
            lena,
            contact,
            other,
        })
    }

    async fn seed(db: &Db) -> (TenantId, EmployeeId, Uuid) {
        let now = Utc::now().trunc_subsecs(6);
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let account = Uuid::now_v7();
        let contact = Uuid::now_v7();
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'sequence test')")
            .bind(tenant.as_uuid())
            .bind(format!("seq-{}", tenant.as_uuid().simple()))
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
        (tenant, employee, contact)
    }

    fn prospect() -> EmailAddress {
        EmailAddress::parse("paul@prospect.example").expect("address")
    }

    async fn defined(f: &Fixture, steps: &[Step]) -> SequenceId {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let id = define(&mut tx, &format!("seq-{}", Uuid::now_v7().simple()), steps)
            .await
            .expect("define");
        tx.commit().await.expect("commit");
        id
    }

    async fn enrolled(f: &Fixture, sequence: SequenceId, now: DateTime<Utc>) -> SequenceRunId {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let run = enroll(&mut tx, sequence, f.contact, f.lena, now)
            .await
            .expect("enroll");
        tx.commit().await.expect("commit");
        run
    }

    async fn tick(f: &Fixture, run: SequenceRunId, now: DateTime<Utc>) -> Run {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        advance(&mut tx, run, now).await.expect("advance");
        let run = find(&mut tx, run).await.expect("find").expect("mine");
        tx.commit().await.expect("commit");
        run
    }

    async fn promises(f: &Fixture, run: SequenceRunId) -> Vec<(AppointmentId, bool)> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let rows: Vec<(Uuid, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT id, rang_at FROM appointments WHERE sequence_run_id = $1 ORDER BY at",
        )
        .bind(run.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("promises");
        tx.rollback().await.expect("rollback");
        rows.into_iter()
            .map(|(id, rang)| (AppointmentId::from_uuid(id), rang.is_some()))
            .collect()
    }

    /// The promise rings, as `calendar::claim_due` writes it. By SQL and not
    /// by the claim itself: the claim is cross-tenant and the shared test
    /// database carries every other test's overdue promises in front of ours.
    async fn rung(f: &Fixture, run: SequenceRunId, now: DateTime<Utc>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let n = sqlx::query(
            "UPDATE appointments SET rang_at = $2 WHERE sequence_run_id = $1 AND rang_at IS NULL",
        )
        .bind(run.as_uuid())
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("ring")
        .rows_affected();
        tx.commit().await.expect("commit");
        assert_eq!(n, 1, "one promise names this run and had not rung");
    }

    /// The employee's `send_email` went out, as `Effects::chase` records it.
    async fn sent_by_lena(f: &Fixture, id: &str, now: DateTime<Utc>) -> Option<SequenceRunId> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let thread = follow_up::sent(&mut tx, f.lena, &prospect(), Some("hello"), id, now)
            .await
            .expect("record");
        let run = sent(&mut tx, f.lena, thread, &prospect(), id, now)
            .await
            .expect("sent");
        tx.commit().await.expect("commit");
        run
    }

    async fn reply(f: &Fixture, now: DateTime<Utc>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let from = Untrusted::new("Paul <paul@prospect.example>".to_owned());
        let conversation = inbound::conversation_for(
            &mut tx,
            f.lena,
            Channel::Email,
            &inbound::contact_of(&from),
            None,
            now,
        )
        .await
        .expect("thread");
        let message = CanonicalMessage {
            tenant_id: f.tenant,
            employee_id: f.lena,
            conversation_id: conversation,
            provider_message_id: ProviderRef::new("reply-1"),
            idempotency_key: CanonicalMessage::dedupe_key(
                f.lena,
                Channel::Email,
                &ProviderRef::new("reply-1"),
            ),
            channel: Channel::Email,
            direction: Direction::Inbound,
            received_at: now,
            from,
            subject: None,
            body_text: Untrusted::new("yes".to_owned()),
            attachments: Vec::new(),
        };
        inbound::land(&mut tx, &message, now).await.expect("land");
        tx.commit().await.expect("commit");
    }

    async fn opened(f: &Fixture, message: Uuid) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO message_events (id, tenant_id, provider, provider_message_id, message_id, \
                                         kind, occurred_at, provider_event_id) \
             SELECT $1, $2, 'resend', provider_message_id, id, 'opened', now(), $3 \
               FROM messages WHERE id = $4",
        )
        .bind(Uuid::now_v7())
        .bind(f.tenant.as_uuid())
        .bind(Uuid::now_v7().to_string())
        .bind(message)
        .execute(&mut **tx)
        .await
        .expect("trace");
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn enroll_refuses_a_suppressed_contact_and_a_duplicate() {
        let Some(f) = fixture().await else {
            return;
        };
        let now = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello")]).await;
        let first = enrolled(&f, seq, now).await;

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let err = enroll(&mut tx, seq, f.contact, f.lena, now)
            .await
            .expect_err("twice");
        assert!(matches!(err, EnrollError::AlreadyActive), "{err}");
        let err = enroll(&mut tx, seq, Uuid::now_v7(), f.lena, now)
            .await
            .expect_err("nobody");
        assert!(matches!(err, EnrollError::NotFound("contact")), "{err}");
        tx.rollback().await.expect("rollback");

        // The other company cannot enroll into our sequence, nor see the run.
        let mut tx = f.db.tenant_tx(f.other).await.expect("tx");
        let err = enroll(&mut tx, seq, f.contact, f.lena, now)
            .await
            .expect_err("not theirs");
        assert!(matches!(err, EnrollError::NotFound("sequence")), "{err}");
        assert!(find(&mut tx, first).await.expect("find").is_none());
        tx.rollback().await.expect("rollback");

        // Once they have asked to be left alone, a fresh run is refused.
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        stop(&mut tx, first, "stopped", Some("max_touches"), now)
            .await
            .expect("free the slot");
        suppressions::suppress(
            &mut tx,
            Uuid::now_v7(),
            &suppressions::NewSuppression {
                channel: suppressions::Channel::Email,
                address: "paul@prospect.example",
                reason: "opt_out",
                scope: suppressions::Scope::Tenant,
                contact_id: None,
                note: None,
                suppressed_at: now,
            },
        )
        .await
        .expect("suppress");
        let err = enroll(&mut tx, seq, f.contact, f.lena, now)
            .await
            .expect_err("suppressed");
        assert!(matches!(err, EnrollError::Suppressed), "{err}");
        tx.rollback().await.expect("rollback");
    }

    /// **The whole machine, tick by tick, without a model.** Email books a
    /// promise that names the run; the send advances; wait sets the clock; a
    /// branch reads the trace; the end is `done`; and `MAX_TOUCHES` is counted
    /// on the thread, strays included.
    #[tokio::test]
    async fn a_run_walks_its_steps_on_promises_and_traces() {
        let Some(f) = fixture().await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(
            &f,
            &[
                email("introduce us"),
                wait(48),
                branch(Signal::Opened, 3, 4),
                email("they read it: offer a call"),
                email("they did not: a shorter subject line"),
            ],
        )
        .await;
        let run = enrolled(&f, seq, t0).await;

        // Step 0, email: a promise now, carrying the run; the run waits.
        let r = tick(&f, run, t0).await;
        assert_eq!((r.step, r.state.as_str()), (0, "active"));
        assert_eq!(r.next_at, Some(t0 + SEND_DEADLINE));
        let booked = promises(&f, run).await;
        assert_eq!(booked.len(), 1);
        assert!(!booked[0].1, "not rung yet");
        // A second tick before the ring books nothing more.
        tick(&f, run, t0 + TimeDelta::minutes(1)).await;
        assert_eq!(promises(&f, run).await.len(), 1);

        // A send to the same address before the promise rang is not the
        // sequence's: `sent` looks for a promise the seat is keeping.
        assert!(
            sent_by_lena(&f, "stray", t0 + TimeDelta::minutes(2))
                .await
                .is_none()
        );

        rung(&f, run, t0 + TimeDelta::minutes(3)).await;
        let text = brief(&f.db, f.tenant, run).await.expect("a step to brief");
        assert!(text.contains("step 1 of 5"), "{text}");
        assert!(text.contains("introduce us"), "{text}");
        assert!(text.contains("paul@prospect.example"), "{text}");
        assert!(text.contains("Nothing has gone out"), "{text}");
        assert!(brief(&f.db, f.other, run).await.is_none(), "RLS");

        // The wake's send_email went out: step 1, thread and message known.
        let t1 = t0 + TimeDelta::minutes(5);
        assert_eq!(sent_by_lena(&f, "msg-1", t1).await, Some(run));
        let r = tick(&f, run, t1).await; // wait(48)
        assert_eq!(r.step, 2);
        assert_eq!(r.next_at, Some(t1 + TimeDelta::hours(48)));
        assert!(r.conversation_id.is_some());
        assert!(r.last_message_id.is_some());
        // A second send in the same turn does not advance twice.
        assert!(
            sent_by_lena(&f, "msg-1b", t1 + TimeDelta::seconds(1))
                .await
                .is_none()
        );

        // Branch, never opened: otherwise → step 4.
        let t2 = t1 + TimeDelta::hours(48);
        let r = tick(&f, run, t2).await;
        assert_eq!(r.step, 4);

        // Step 4 is an email, and the thread already carries three outbound
        // (the stray, msg-1, msg-1b): the ceiling stops the run, books nothing.
        assert_eq!(MAX_TOUCHES, 3);
        let r = tick(&f, run, t2).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("max_touches"))
        );
        assert_eq!(promises(&f, run).await.len(), 1);

        // A fresh company, so the thread is empty: the opened branch, the
        // brief that says so, and the end of the list.
        let (tenant, lena, contact) = seed(&f.db).await;
        let g = Fixture {
            db: f.db.clone(),
            tenant,
            lena,
            contact,
            other: f.tenant,
        };
        let seq2 = defined(&g, &[email("a"), branch(Signal::Opened, 2, 3), email("b")]).await;
        let t4 = t2 + TimeDelta::hours(1);
        let run2 = enrolled(&g, seq2, t4).await;
        tick(&g, run2, t4).await;
        rung(&g, run2, t4 + TimeDelta::minutes(1)).await;
        let t5 = t4 + TimeDelta::minutes(2);
        assert_eq!(sent_by_lena(&g, "msg-3", t5).await, Some(run2));
        let r = tick(&g, run2, t5).await; // branch: no trace yet → otherwise → 3 = end
        assert_eq!(r.step, 3);
        // Undo the jump to show the other arm on the same run: the trace lands.
        let mut tx = g.db.tenant_tx(g.tenant).await.expect("tx");
        goto(&mut tx, run2, 1, t5).await.expect("rewind");
        tx.commit().await.expect("commit");
        opened(&g, r.last_message_id.expect("msg-3")).await;
        assert_eq!(tick(&g, run2, t5).await.step, 2, "opened → then");
        // Strictly after msg-3: a promise is "for this step" when its `at`
        // is later than the last send, and the loop's clock always is.
        tick(&g, run2, t5 + TimeDelta::minutes(1)).await; // email b: promise
        rung(&g, run2, t5 + TimeDelta::minutes(2)).await;
        let text = brief(&g.db, g.tenant, run2).await.expect("brief");
        assert!(text.contains("step 3 of 3"), "{text}");
        assert!(text.contains("1 email(s)"), "{text}");
        assert!(text.contains("was opened"), "{text}");
        let t6 = t5 + TimeDelta::minutes(3);
        assert_eq!(sent_by_lena(&g, "msg-4", t6).await, Some(run2));
        let r = tick(&g, run2, t6).await;
        assert_eq!(r.state, "done");
        assert!(r.ended_at.is_some());
    }

    #[tokio::test]
    async fn a_reply_ends_the_run_and_a_silent_wake_stops_it() {
        let Some(f) = fixture().await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello"), wait(24), email("again")]).await;
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        rung(&f, run, t0 + TimeDelta::minutes(1)).await;
        let t1 = t0 + TimeDelta::minutes(2);
        assert_eq!(sent_by_lena(&f, "msg-1", t1).await, Some(run));
        tick(&f, run, t1).await; // wait
        // The reply lands: the run is `replied` in the landing transaction.
        reply(&f, t1 + TimeDelta::hours(1)).await;
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let r = find(&mut tx, run).await.expect("find").expect("mine");
        tx.rollback().await.expect("rollback");
        assert_eq!(r.state, "replied");
        assert!(r.ended_at.is_some());
        // Terminal: a later tick changes nothing.
        assert_eq!(
            tick(&f, run, t1 + TimeDelta::days(2)).await.state,
            "replied"
        );

        // A wake that sends nothing: after SEND_DEADLINE the run is stopped.
        let seq = defined(&f, &[email("hello")]).await;
        let t2 = t1 + TimeDelta::days(3);
        let run = enrolled(&f, seq, t2).await;
        tick(&f, run, t2).await;
        rung(&f, run, t2 + TimeDelta::minutes(1)).await;
        let r = tick(&f, run, t2 + SEND_DEADLINE).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("not_sent"))
        );

        // A suppression that arrives mid-run stops the next email step.
        let seq = defined(&f, &[wait(1), email("hello")]).await;
        let t3 = t2 + TimeDelta::days(2);
        let run = enrolled(&f, seq, t3).await;
        tick(&f, run, t3).await;
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        suppressions::suppress(
            &mut tx,
            Uuid::now_v7(),
            &suppressions::NewSuppression {
                channel: suppressions::Channel::Email,
                address: "paul@prospect.example",
                reason: "opt_out",
                scope: suppressions::Scope::Tenant,
                contact_id: None,
                note: None,
                suppressed_at: t3,
            },
        )
        .await
        .expect("suppress");
        tx.commit().await.expect("commit");
        let r = tick(&f, run, t3 + TimeDelta::hours(1)).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("suppressed"))
        );
        assert!(
            promises(&f, run).await.is_empty(),
            "nothing was booked for it"
        );
    }

    #[tokio::test]
    async fn define_archive_and_the_other_company() {
        let Some(f) = fixture().await else {
            return;
        };
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let err = define(&mut tx, "x", &[wait(1)]).await.expect_err("shape");
        assert!(
            matches!(err, DefineError::Invalid(Invalid::NoEmail)),
            "{err}"
        );
        let id = define(&mut tx, "intro", &[email("hi")])
            .await
            .expect("define");
        let err = define(&mut tx, "intro", &[email("hi")])
            .await
            .expect_err("same name");
        assert!(matches!(err, DefineError::NameTaken), "{err}");
        assert_eq!(list(&mut tx).await.expect("list")[0].id, id);
        tx.commit().await.expect("commit");

        let mut tx = f.db.tenant_tx(f.other).await.expect("tx");
        assert!(list(&mut tx).await.expect("list").is_empty(), "RLS");
        assert!(matches!(
            archive(&mut tx, id).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        archive(&mut tx, id).await.expect("archive");
        assert!(matches!(
            archive(&mut tx, id).await,
            Err(StoreError::NotFound)
        ));
        // The name is free again, and the archived one cannot enroll.
        define(&mut tx, "intro", &[email("hi")])
            .await
            .expect("name freed");
        let err = enroll(&mut tx, id, f.contact, f.lena, Utc::now())
            .await
            .expect_err("archived");
        assert!(matches!(err, EnrollError::NotFound("sequence")), "{err}");
        tx.rollback().await.expect("rollback");
    }
}
