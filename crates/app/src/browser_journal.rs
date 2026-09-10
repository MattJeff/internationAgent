//! Le journal des tâches de navigateur, et la vue en direct : le lecteur du
//! port [`BrowserObserver`].
//!
//! `docs/BROWSER.md` § v2 : l'adaptateur narre (une tâche commence, une étape
//! a tourné, une image a été prise, la tâche finit) et ne sait pas qui écoute.
//! Ce module est **le** qui : une ligne de `browser_tasks` (migration 0096)
//! par tâche, et un flux d'images en mémoire vers la console qui regarde.
//!
//! # Pourquoi une file, et pourquoi elle perd
//!
//! Les méthodes du port sont synchrones et appelées depuis l'adaptateur, entre
//! deux commandes CDP. Une écriture SQL là-dedans ralentirait chaque étape du
//! temps d'un aller-retour Postgres, et un Postgres lent ferait attendre le
//! navigateur — l'inverse du journal, qui doit être invisible. Donc une file
//! bornée et une tâche tokio qui la draine dans l'ordre (un seul consommateur :
//! l'`INSERT` du début précède toujours l'`UPDATE` d'une étape). Quand la file
//! déborde, la narration est **perdue et comptée**, jamais attendue : un
//! journal troué vaut mieux qu'un navigateur bloqué par son propre journal.
//!
//! # Pourquoi les images ne touchent jamais la base
//!
//! Une image de la vue en direct vaut le temps qu'on la regarde. Elle part
//! dans un `broadcast` par employé, capacité 4 : un lecteur en retard de cinq
//! images reprend à la plus récente, il ne les revoit pas. `wants_frames`
//! est « quelqu'un est abonné » — c'est la connexion SSE
//! (`GET /v1/browser/live/{employee_id}`) qui allume le screencast de
//! l'adaptateur, et sa fermeture qui l'éteint. Seul le *nombre* d'images
//! diffusées est écrit, à la fin, dans `frames_sent`.
//!
//! # Le locataire
//!
//! Comme le pot de cookies (`cookie_jar.rs`, 0095) : l'adaptateur ne connaît
//! que l'employé. Le locataire est lu dans `employees` sous
//! `admin_tx_bypassing_rls`, puis la ligne s'écrit sous `tenant_tx` — la
//! recherche précède le locataire, l'écriture ne le contourne pas.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentos_domain::ids::{EmployeeId, TenantId};
pub use agentos_providers::browser_observer::{BrowserObserver, StepOutcome, StepReport, TaskRef};
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

/// Ce que la vue en direct reçoit : une image, ou une borne de tâche.
#[derive(Debug, Clone)]
pub enum Live {
    /// Un JPEG de la fenêtre, tel que l'adaptateur l'a capturé.
    Frame(Arc<[u8]>),
    /// `started` ou `finished` ; `outcome` seulement à la fin.
    Task {
        task_id: Uuid,
        state: &'static str,
        outcome: Option<String>,
    },
}

/// Ce que la file porte vers Postgres. Les images n'y passent pas.
enum Write {
    Started(TaskRef, DateTime<Utc>),
    Step(TaskRef, serde_json::Value),
    Finished {
        task: TaskRef,
        at: DateTime<Utc>,
        outcome: String,
        frames_sent: i32,
    },
    /// Répond quand tout ce qui précède est écrit. Pour les tests, et pour un
    /// arrêt qui ne veut pas perdre la dernière tâche.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Assez pour une rafale d'étapes de trois onglets pendant qu'un `UPDATE`
/// attend ; peu assez pour qu'un Postgres tombé ne retienne pas la mémoire.
const QUEUE: usize = 256;
/// Une image toutes les ~250 ms : quatre, c'est une seconde de retard toléré.
const FRAMES: usize = 4;

/// Le journal. Un par processus, partagé entre l'adaptateur (qui narre) et
/// les routes (qui lisent et s'abonnent).
pub struct Journal {
    writes: mpsc::Sender<Write>,
    /// Les narrations que la file n'a pas prises. Lu par les tests et le log.
    dropped: AtomicU64,
    /// Un canal par employé, créé au premier abonné ou à la première image.
    // ponytail: never pruned — a Sender without receivers is a hundred bytes,
    // and a deployment has tens of employees, not millions.
    live: Mutex<HashMap<EmployeeId, broadcast::Sender<Live>>>,
    /// Images diffusées par tâche en cours ; retiré et écrit à la fin.
    frames: Mutex<HashMap<Uuid, i32>>,
}

impl Journal {
    /// Démarre le consommateur sur le runtime courant. À appeler depuis lui :
    /// `main` ou un test `#[tokio::test]`.
    pub fn new(db: Db) -> Arc<Self> {
        Self::with_queue(db, QUEUE)
    }

    fn with_queue(db: Db, queue: usize) -> Arc<Self> {
        let (writes, rx) = mpsc::channel(queue);
        tokio::spawn(drain(db, rx));
        Arc::new(Self {
            writes,
            dropped: AtomicU64::new(0),
            live: Mutex::new(HashMap::new()),
            frames: Mutex::new(HashMap::new()),
        })
    }

    /// S'abonner aux images et aux bornes de tâche d'un employé. Tant que le
    /// récepteur vit, [`BrowserObserver::wants_frames`] répond vrai pour lui.
    pub fn subscribe(&self, employee: EmployeeId) -> broadcast::Receiver<Live> {
        self.live
            .lock()
            .expect("live map poisoned")
            .entry(employee)
            .or_insert_with(|| broadcast::channel(FRAMES).0)
            .subscribe()
    }

    /// Combien de narrations la file a refusées depuis le démarrage.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn enqueue(&self, write: Write) {
        if let Err(err) = self.writes.try_send(write) {
            // Pleine ou fermée : dans les deux cas on ne retient pas
            // l'adaptateur, on compte et on le dit.
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(reason = %err, "browser journal: a narration was dropped");
        }
    }

    /// Le canal de l'employé, seulement s'il existe : sans abonné il n'y a
    /// personne à qui parler et rien à créer.
    fn channel(&self, employee: EmployeeId) -> Option<broadcast::Sender<Live>> {
        self.live
            .lock()
            .expect("live map poisoned")
            .get(&employee)
            .cloned()
    }

    fn tell(&self, employee: EmployeeId, live: Live) {
        if let Some(tx) = self.channel(employee) {
            // `Err` = plus aucun récepteur : la connexion s'est fermée entre
            // `wants_frames` et ici, et l'image n'intéresse plus personne.
            let _ = tx.send(live);
        }
    }

    /// Attend que tout ce qui a été narré jusqu'ici soit écrit. Passe par la
    /// file (et attend sa place, contrairement au port) : ce que la file a
    /// déjà perdu n'est pas rattrapé.
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.writes.send(Write::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

/// `ok` | `refused:<code>` | `failed:<code>` — la forme de `browser_tasks.outcome`
/// et de chaque `steps[].outcome`.
pub fn outcome_text(outcome: &StepOutcome) -> String {
    match outcome {
        StepOutcome::Ok => "ok".to_owned(),
        StepOutcome::Refused { code } => format!("refused:{code}"),
        StepOutcome::Failed { code } => format!("failed:{code}"),
    }
}

impl BrowserObserver for Journal {
    fn task_started(&self, task: &TaskRef, at: DateTime<Utc>) {
        self.tell(
            task.employee_id,
            Live::Task {
                task_id: task.task_id,
                state: "started",
                outcome: None,
            },
        );
        self.enqueue(Write::Started(task.clone(), at));
    }

    fn step_done(&self, task: &TaskRef, step: &StepReport, at: DateTime<Utc>) {
        // Cinq champs, jamais le contenu : c'est la garantie de 0096, tenue
        // ici et non par une contrainte SQL qui ne saurait pas lire un blob.
        let entry = serde_json::json!({
            "kind": step.kind,
            "url": step.url,
            "outcome": outcome_text(&step.outcome),
            "took_ms": u64::try_from(step.took.as_millis()).unwrap_or(u64::MAX),
            "at": at,
        });
        self.enqueue(Write::Step(task.clone(), entry));
    }

    fn frame(&self, task: &TaskRef, jpeg: &[u8], _at: DateTime<Utc>) {
        let Some(tx) = self.channel(task.employee_id) else {
            return;
        };
        if tx.send(Live::Frame(Arc::from(jpeg))).is_ok() {
            *self
                .frames
                .lock()
                .expect("frames map poisoned")
                .entry(task.task_id)
                .or_default() += 1;
        }
    }

    fn wants_frames(&self, task: &TaskRef) -> bool {
        self.channel(task.employee_id)
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    fn task_finished(&self, task: &TaskRef, outcome: &StepOutcome, at: DateTime<Utc>) {
        let outcome = outcome_text(outcome);
        self.tell(
            task.employee_id,
            Live::Task {
                task_id: task.task_id,
                state: "finished",
                outcome: Some(outcome.clone()),
            },
        );
        let frames_sent = self
            .frames
            .lock()
            .expect("frames map poisoned")
            .remove(&task.task_id)
            .unwrap_or(0);
        self.enqueue(Write::Finished {
            task: task.clone(),
            at,
            outcome,
            frames_sent,
        });
    }
}

// ---------------------------------------------------------------------------
// Le consommateur
// ---------------------------------------------------------------------------

async fn drain(db: Db, mut rx: mpsc::Receiver<Write>) {
    while let Some(write) = rx.recv().await {
        if let Write::Flush(done) = write {
            let _ = done.send(());
            continue;
        }
        if let Err(err) = apply(&db, write).await {
            tracing::warn!(error = %err, "browser journal: a write failed");
        }
    }
}

/// Le locataire de l'employé, sous admin : la seule lecture qui précède le
/// locataire. `None` pour un employé que la cascade a déjà emporté.
async fn tenant_of(db: &Db, employee: EmployeeId) -> Result<Option<TenantId>, StoreError> {
    let mut tx = db.admin_tx_bypassing_rls().await?;
    let row: Option<(Uuid,)> = sqlx::query_as("SELECT tenant_id FROM employees WHERE id = $1")
        .bind(employee.as_uuid())
        .fetch_optional(&mut *tx)
        .await?;
    tx.rollback().await?;
    Ok(row.map(|(id,)| TenantId::from_uuid(id)))
}

async fn apply(db: &Db, write: Write) -> Result<(), StoreError> {
    let task = match &write {
        Write::Started(task, _) | Write::Step(task, _) => task,
        Write::Finished { task, .. } => task,
        Write::Flush(_) => unreachable!("flushed by drain"),
    };
    let Some(tenant) = tenant_of(db, task.employee_id).await? else {
        tracing::warn!(task = %task.task_id, "browser journal: the employee is gone; not written");
        return Ok(());
    };
    let mut tx = db.tenant_tx(tenant).await?;
    // Les deux `UPDATE` exigent `ended_at IS NULL` : une étape ou une fin qui
    // arrivent après la fin (l'adaptateur qui re-narre, une file réordonnée
    // par un redémarrage) ne réécrivent pas une tâche close.
    let query = match write {
        Write::Started(task, at) => sqlx::query(
            "INSERT INTO browser_tasks \
                 (id, tenant_id, employee_id, provider, context, started_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(task.task_id)
        .bind(tenant.as_uuid())
        .bind(task.employee_id.as_uuid())
        .bind(task.provider)
        .bind(task.context)
        .bind(at),
        Write::Step(task, entry) => sqlx::query(
            "UPDATE browser_tasks SET steps = steps || jsonb_build_array($2::jsonb) \
              WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(task.task_id)
        .bind(entry),
        Write::Finished {
            task,
            at,
            outcome,
            frames_sent,
        } => sqlx::query(
            "UPDATE browser_tasks SET ended_at = $2, outcome = $3, frames_sent = $4 \
              WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(task.task_id)
        .bind(at)
        .bind(outcome)
        .bind(frames_sent),
        Write::Flush(_) => unreachable!("flushed by drain"),
    };
    query.execute(&mut **tx).await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the journal is a table");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Un locataire et un employé, comme `cookie_jar` les sème.
    pub(crate) async fn seed(db: &Db) -> (TenantId, EmployeeId) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'journal-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'ada', 'ada', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("employee");
        tx.commit().await.expect("commit");
        (tenant, employee)
    }

    fn task(employee: EmployeeId) -> TaskRef {
        TaskRef {
            task_id: Uuid::now_v7(),
            employee_id: employee,
            context: "ctx-test".to_owned(),
            provider: "chrome",
        }
    }

    fn step(kind: &'static str, url: Option<&str>, outcome: StepOutcome, ms: u64) -> StepReport {
        StepReport {
            kind,
            url: url.map(str::to_owned),
            outcome,
            took: Duration::from_millis(ms),
        }
    }

    type Row = (
        Uuid,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        serde_json::Value,
        i32,
    );

    async fn row(db: &Db, tenant: TenantId, id: Uuid) -> Option<Row> {
        let mut tx = db.tenant_tx(tenant).await.unwrap();
        let row = sqlx::query_as(
            "SELECT employee_id, provider, context, ended_at, outcome, steps, frames_sent \
               FROM browser_tasks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        row
    }

    /// Début, deux étapes, fin : une ligne, juste. Puis une étape après la fin,
    /// qui ne change rien. Et le locataire voisin qui ne voit rien.
    #[tokio::test]
    async fn a_whole_narration_is_one_true_row_and_nothing_after_the_end() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db).await;
        let (other, _) = seed(&db).await;
        let journal = Journal::new(db.clone());
        let task = task(employee);
        let t0 = Utc::now();

        journal.task_started(&task, t0);
        journal.step_done(
            &task,
            &step(
                "goto",
                Some("https://portal.example.com/"),
                StepOutcome::Ok,
                420,
            ),
            t0,
        );
        journal.step_done(
            &task,
            &step(
                "fill",
                None,
                StepOutcome::Refused {
                    code: "blocked_by_site",
                },
                7,
            ),
            t0,
        );
        journal.task_finished(&task, &StepOutcome::Failed { code: "timeout" }, t0);
        journal.flush().await;

        let (emp, provider, context, ended, outcome, steps, frames) =
            row(&db, tenant, task.task_id).await.expect("a row");
        assert_eq!(emp, employee.as_uuid());
        assert_eq!(
            (provider.as_str(), context.as_str()),
            ("chrome", "ctx-test")
        );
        assert!(ended.is_some());
        assert_eq!(outcome.as_deref(), Some("failed:timeout"));
        assert_eq!(frames, 0);
        let steps = steps.as_array().expect("an array");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["kind"], "goto");
        assert_eq!(steps[0]["url"], "https://portal.example.com/");
        assert_eq!(steps[0]["outcome"], "ok");
        assert_eq!(steps[0]["took_ms"], 420);
        assert_eq!(steps[1]["url"], serde_json::Value::Null);
        assert_eq!(steps[1]["outcome"], "refused:blocked_by_site");
        assert!(steps[1]["at"].is_string());

        // After the end: neither a step nor a second end touches the row.
        journal.step_done(&task, &step("click", None, StepOutcome::Ok, 1), Utc::now());
        journal.task_finished(&task, &StepOutcome::Ok, Utc::now());
        journal.flush().await;
        let (_, _, _, ended_again, outcome_again, steps_again, _) =
            row(&db, tenant, task.task_id).await.expect("still a row");
        assert_eq!(ended_again, ended);
        assert_eq!(outcome_again.as_deref(), Some("failed:timeout"));
        assert_eq!(steps_again.as_array().unwrap().len(), 2);

        // RLS: the neighbour has no such task.
        assert!(row(&db, other, task.task_id).await.is_none());
    }

    /// Une file d'une place, un consommateur qui n'a pas encore tourné (runtime
    /// à un fil, pas de `.await` entre les appels) : la deuxième et la
    /// troisième narration sont perdues, comptées, et l'appelant n'a pas
    /// attendu. La première atterrit quand même.
    #[tokio::test]
    async fn a_full_queue_loses_without_blocking() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db).await;
        let journal = Journal::with_queue(db.clone(), 1);
        let task = task(employee);

        let before = Instant::now();
        journal.task_started(&task, Utc::now());
        journal.step_done(&task, &step("goto", None, StepOutcome::Ok, 1), Utc::now());
        journal.task_finished(&task, &StepOutcome::Ok, Utc::now());
        assert!(before.elapsed() < Duration::from_millis(100), "it waited");
        assert_eq!(journal.dropped(), 2);

        journal.flush().await;
        let (_, _, _, ended, _, _, _) = row(&db, tenant, task.task_id)
            .await
            .expect("the start landed");
        assert!(ended.is_none(), "the end was the one dropped");
    }

    /// `wants_frames` est « quelqu'un regarde » : vrai avec un récepteur, faux
    /// avant et faux dès qu'il est lâché. Une image part au récepteur, est
    /// comptée, et le compte s'écrit à la fin.
    #[tokio::test]
    async fn wants_frames_follows_the_subscriber_and_frames_are_counted() {
        let Some(db) = db().await else { return };
        let (tenant, employee) = seed(&db).await;
        let journal = Journal::new(db.clone());
        let task = task(employee);

        assert!(!journal.wants_frames(&task));
        journal.frame(&task, b"\xFF\xD8nobody", Utc::now());

        let mut rx = journal.subscribe(employee);
        assert!(journal.wants_frames(&task));
        assert!(!journal.wants_frames(&self::task(EmployeeId::new_v7(Utc::now()))));

        journal.task_started(&task, Utc::now());
        journal.frame(&task, b"\xFF\xD8one", Utc::now());
        journal.frame(&task, b"\xFF\xD8two", Utc::now());
        assert!(matches!(
            rx.try_recv(),
            Ok(Live::Task {
                state: "started",
                ..
            })
        ));
        assert!(matches!(rx.try_recv(), Ok(Live::Frame(jpeg)) if &*jpeg == b"\xFF\xD8one"));

        drop(rx);
        assert!(!journal.wants_frames(&task));
        journal.frame(&task, b"\xFF\xD8three", Utc::now());

        journal.task_finished(&task, &StepOutcome::Ok, Utc::now());
        journal.flush().await;
        let (_, _, _, _, outcome, _, frames) = row(&db, tenant, task.task_id).await.expect("a row");
        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(frames, 2, "the unwatched frames are not sent");
    }
}
