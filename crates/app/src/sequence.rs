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
//! s'arrête en `not_sent` — un délai de [`SEND_DEADLINE`] sans envoi après le
//! premier réveil est la seule lecture possible de « le siège a été réveillé et
//! rien n'est parti ».
//!
//! `MAX_TOUCHES` reste la limite d'emails par fil : la séquence s'arrête là
//! (`stopped`, `max_touches`) plutôt que de la contourner. Personne qui a
//! ignoré trois mails n'attend le quatrième, et une séquence qui en promettrait
//! cinq est une séquence dont les deux derniers pas ne s'exécutent pas.
//!
//! # Rejouer, ou pas
//!
//! Une promesse qui sonne est **consommée** (`0072`) : si le réveil n'envoie
//! rien, personne ne la rejoue. Mesuré trois fois — la charte n'existait pas
//! encore (`no_charter`, répétition du 2026-09-19), la Gate a refusé le sixième
//! inconnu du jour (`contact_budget_exhausted`, 2026-09-20), le siège a posé
//! une question au fondateur au lieu d'écrire (AssoConnect, 2026-09-20) — et
//! chaque fois le run restait `active`, `step` inchangé, puis mourait
//! `not_sent` un jour plus tard. Ce sont trois situations différentes qui
//! méritent trois réponses, et la promesse dit laquelle : `appointments.outcome`
//! porte ce que `loops::initiative` a fait du réveil, et le tour laisse ses
//! traces (`messages.internal_kind = 'question'`, le refus de la Gate dans
//! `audit_log`).
//!
//! * **Cause transitoire — rejouer.** `no_charter` (la charte a été posée
//!   depuis), `over_budget` ou un refus `contact_budget_exhausted` (le budget
//!   revient à minuit UTC), `error` (`max_turns`, une panne). Rejouer, c'est
//!   réserver une **nouvelle** promesse pour le même pas, au plus tôt quand la
//!   cause peut avoir disparu : le lendemain à minuit UTC — plus l'heure du
//!   flux s'il y en a un, pour que les mails ne partent pas la nuit — pour un
//!   budget ; tout de suite pour une panne ; dès que la charte existe pour
//!   `no_charter`, et pas avant, parce qu'un rejeu à l'aveugle brûlerait ses
//!   deux chances en deux minutes sur la même absence.
//! * **Décision du siège — ne pas rejouer.** Le réveil a produit une question
//!   au fondateur et pas d'envoi : le siège a lu le brief, le contact, le fil,
//!   et jugé qu'il ne fallait pas écrire — c'est exactement ce qu'on lui
//!   demande, et le rejouer serait lui demander de se déjuger. Le run s'arrête
//!   **tout de suite** en `stopped`/`declined` (`0112`) au lieu d'attendre un
//!   jour pour dire `not_sent`, qui est un autre mot pour une autre chose. Ce
//!   n'est pas une panne : rien n'est cassé, quelqu'un a choisi.
//! * **Inconnu.** Un tour (`turn`) sans envoi, sans question, sans refus : le
//!   modèle n'a pas écrit et on ne sait pas pourquoi. Une seule reprise, tout
//!   de suite, puis `not_sent`. Les autres issues (`clarify`, `no_work`,
//!   `no_model`, `unreadable_charter`, `cancelled`) ne se lèvent pas toutes
//!   seules et le run s'arrête `not_sent` sans attendre : une promesse consommée
//!   ne sonnera plus, attendre n'apprend rien.
//!
//! Deux bornes, dans cet ordre. Au plus [`MAX_REPLAYS`] rejeux par pas : le
//! premier couvre la cause ordinaire (le budget revenu, la charte posée), le
//! second couvre le rejeu qui retombe sur un mauvais jour (le fondateur a écrit
//! cinq inconnus à la main ce matin-là) ; un troisième serait un run qui attend
//! une condition que personne ne répare, et le fondateur doit le voir en
//! `not_sent` plutôt que le croire en cours. Et jamais au-delà de
//! [`SEND_DEADLINE`] compté depuis le **premier** réveil : un rejeu qui ne
//! peut pas sonner dans ce délai n'est pas réservé. Un flux à 8 h UTC rejoue
//! donc son refus de budget à 8 h le lendemain, à la limite exacte ; un run
//! réveillé à 7 h avec ce même flux ne le peut pas et meurt `not_sent`, ce qui
//! se lit et se réinscrit.
//!
//! **Comment le run apprend l'issue.** Rien ne le réveille : `record` écrit
//! `outcome` dans sa propre transaction, après le tour, et ce module n'en est
//! pas averti. Un run dont la promesse est posée revient donc dans [`advance`]
//! toutes les [`WAKE_POLL`] — pas [`SEND_DEADLINE`] — et relit ses promesses :
//! pas sonné, on attend encore ; sonné sans issue, le tour est en cours ; sonné
//! avec une issue, on décide. Cinq minutes est la latence maximale d'un
//! `declined`, et une transaction de locataire par run posé par cinq minutes
//! est un coût qu'aucune liste de 1300 ne fait sentir. La boucle
//! `loops::sequence` ne change pas : elle lit `next_at`, et `next_at` est
//! maintenant court.
//!
//! # A/B : on compare des runs, pas des mails
//!
//! Un pas `email` peut porter plusieurs briefs (`variants`) ; `brief` seul
//! reste valide et vaut une variante unique, donc aucune séquence existante ne
//! change. La variante est **tirée une fois, à l'inscription**, et écrite sur
//! le run (`sequence_runs.variant`, `0110`) : tous les pas `email` d'un run
//! lisent la même. C'est ce qui rend la comparaison propre — un run de la
//! variante A est un parcours entier écrit dans l'esprit A, et [`variants`]
//! compte des *runs* (inscrits, envoyés, ouverts, cliqués, répondus), jamais
//! des mails isolés dont on ne saurait plus à quel parcours ils appartiennent.
//!
//! Le tirage est **déterministe** : l'id du run modulo le nombre de variantes
//! ([`draw`]). Pas de RNG parce qu'un tirage qu'on ne peut pas rejouer est un
//! tirage qu'on ne peut pas tester, et parce que l'id v7 porte déjà soixante-deux
//! bits aléatoires — en tirer un reste est aussi équitable qu'un dé et se relit
//! depuis n'importe quelle base sans autre état. Quand un pas a moins de
//! variantes que le maximum de la séquence, il lit la sienne modulo son propre
//! nombre : un run n'est jamais sans brief.
//!
//! # Le flux : une séquence qui se nourrit seule
//!
//! Un inscrit que la Gate refuse a **dépensé sa promesse pour rien** — mesuré
//! le 2026-09-20 : le sixième du jour est refusé `contact_budget_exhausted` et
//! son run meurt en `not_sent` [`SEND_DEADLINE`] plus tard. Tenir cinq par jour
//! sur une liste de 1300 demandait que quelqu'un inscrive exactement cinq
//! contacts chaque matin. Un [`Feed`] sur la séquence (`sequences.feed`,
//! `0111`) le fait à sa place : un siège, `per_day` contacts, un segment,
//! l'ordre des pays, une liste d'origine ; [`feed`] les choisit et les inscrit
//! par [`enroll`], le même verbe que la route, donc les mêmes refus.
//!
//! **Nourrir à une heure, sans lire le budget.** `per_day` est validé une
//! fois, à la pose ([`set_feed`]), contre le `max_new_contacts_per_day`
//! effectif du siège (`policy::load`, les quatre couches intersectées). Ensuite
//! la boucle ne lit jamais le budget : elle nourrit **une fois par jour UTC, au
//! premier tick à partir de `hour`** (défaut [`DEFAULT_HOUR`], 8 h UTC). Lire
//! le budget dans la boucle serait le lire au mauvais moment : il est dépensé
//! à l'**envoi**, pas à l'inscription — la Gate compte les inconnus écrits du
//! jour — et une promesse posée maintenant sonne quand `loops::initiative` la
//! prend ; ce qu'on lirait à l'inscription ne dit rien de l'envoi. Nourrir à
//! minuit rendrait le compteur neuf à coup sûr, et ferait partir les mails vers
//! deux heures du matin à Paris. **Le compromis : à 8 h UTC, le seul concurrent
//! possible dans la fenêtre est un envoi autonome du siège avant l'heure — un
//! défaut reproduit chez une OTA, rare — et ce risque est préféré à des mails de
//! nuit ; la ceinture est que `per_day` reste borné par le budget à la pose,
//! donc un jour sans envoi autonome ne gaspille jamais rien.** Le jour de la
//! pose compte comme nourri (`fed_on = aujourd'hui`) : on ne sait pas ce que le
//! siège a déjà écrit ce jour-là, et le premier jour sûr est demain. Ce que le
//! fondateur inscrit à la main par-dessus est son choix et se voit dans
//! `refusals_get`.
//!
//! **Un contact déjà écrit n'est pas re-démarché.** La sélection exclut tout
//! contact vers qui une ligne `messages` sortante existe, quel que soit le
//! siège. Pas parce qu'il coûterait un inconnu — il n'en coûte justement pas —
//! mais parce qu'un flux est une prospection à froid et qu'une personne à qui
//! l'on a déjà écrit a un fil, une histoire et une réponse peut-être : lui
//! renvoyer « présentons-nous » par une machine est exactement ce que
//! `MAX_TOUCHES` et la relance J+3 existent pour éviter. Le fondateur qui veut
//! remettre quelqu'un sur une séquence le fait par `enroll`, en le sachant.
//!
//! Le reste des exclusions est celui d'`enroll`, vérifié avant plutôt qu'après
//! pour ne pas dépenser une place du jour sur un refus : inactif, supprimé
//! (`revenue_suppression_of`), déjà inscrit **un jour** sur cette séquence
//! (n'importe quel état — un run fini est une séquence déjà jouée). L'ordre est
//! celui des pays donnés (`array_position`) puis du plus ancien `created_at` :
//! la liste se consomme comme elle a été importée, pays par pays.
//!
//! Zéro contact restant pose quand même `fed_on` et prévient (« feed
//! exhausted », WARN) : le fondateur doit le voir sans deviner, et sans que la
//! boucle recommence toutes les trente secondes.

use agentos_domain::action::EmailAddress;
use agentos_domain::ids::{
    AppointmentId, ConversationId, EmployeeId, SequenceId, SequenceRunId, TenantId,
};
use agentos_domain::policy::DenyReason;
use agentos_store::calendar;
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::policy::{self, PolicyLoadError};
use chrono::{DateTime, NaiveDate, TimeDelta, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::inbound;
use crate::prospects::SEGMENTS;
use crate::revenue::MAX_TOUCHES;

/// Au plus tant de pas. Douze est trois emails, leurs attentes et leurs
/// branches ; une séquence plus longue est une séquence qu'aucun `MAX_TOUCHES`
/// ne laisse finir.
pub const MAX_STEPS: usize = 12;

/// Une attente est entre une heure et trente jours.
pub const MAX_WAIT_HOURS: u32 = 24 * 30;

/// Combien de temps un pas `Email` attend son envoi après le premier réveil.
/// Passé ce délai sans [`sent`], le siège a été réveillé — et rejoué, peut-être
/// — et rien n'est parti : le run s'arrête en `not_sent` plutôt que de
/// réveiller encore. Aucun rejeu n'est réservé au-delà.
pub const SEND_DEADLINE: TimeDelta = TimeDelta::hours(24);

/// Au plus tant de rejeux d'un même pas après un réveil sans envoi. Deux :
/// l'argument est en tête de module, « Rejouer, ou pas ».
pub const MAX_REPLAYS: usize = 2;

/// La cadence à laquelle un run dont la promesse est posée relit ce qu'elle
/// est devenue. Cinq minutes : la latence maximale d'un `declined`, et une
/// transaction par run posé par cinq minutes (« Comment le run apprend
/// l'issue », en tête).
pub const WAKE_POLL: TimeDelta = TimeDelta::minutes(5);

/// L'heure UTC à partir de laquelle un flux nourrit, quand la pose n'en dit
/// pas : 8 h, la fin de la nuit partout en Europe. L'argument est en tête de
/// module, « Nourrir à une heure ».
pub const DEFAULT_HOUR: u8 = 8;

const fn default_hour() -> u8 {
    DEFAULT_HOUR
}

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
    /// Ce que l'employé doit écrire — pas le texte du mail. `brief` est la
    /// forme d'origine ; `variants` en porte plusieurs et le run lit la sienne
    /// (voir « A/B » en tête de module). Les deux ensemble se lisent `brief`
    /// d'abord.
    Email {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brief: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        variants: Vec<String>,
    },
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

impl Step {
    /// Les briefs d'un pas `email`, `brief` en tête puis `variants` ; vide
    /// pour les autres pas.
    fn briefs(&self) -> Vec<&str> {
        match self {
            Self::Email { brief, variants } => {
                brief.iter().chain(variants).map(String::as_str).collect()
            }
            _ => Vec::new(),
        }
    }
}

/// Combien de variantes une séquence tire : le plus grand nombre de briefs
/// d'un de ses pas `email`, jamais moins d'une.
fn variant_count(steps: &[Step]) -> usize {
    steps
        .iter()
        .map(|s| s.briefs().len())
        .max()
        .unwrap_or(0)
        .max(1)
}

/// Le tirage : l'id du run modulo `n`. Déterministe, rejouable, sans RNG —
/// l'argument est en tête de module.
pub fn draw(run: SequenceRunId, n: usize) -> i32 {
    (run.as_uuid().as_u128() % n.max(1) as u128) as i32
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
    #[error("step {0}: an `email` step needs a `brief` or non-empty `variants`")]
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
            Step::Email { .. } => {
                let briefs = step.briefs();
                if briefs.is_empty() || briefs.iter().any(|b| b.trim().is_empty()) {
                    return Err(Invalid::EmptyBrief(i));
                }
            }
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
/// `welcomes_tier` en fait un parcours d'accueil (`0114`) : le palier Stripe
/// qu'elle accueille, en minuscules, ou `upgrade` / `downgrade` / `churned` —
/// `crate::stripe` § « Un abonnement crée un client » dit qui y inscrit.
pub async fn define(
    tx: &mut TenantTx<'_>,
    name: &str,
    steps: &[Step],
    welcomes_tier: Option<&str>,
) -> Result<SequenceId, DefineError> {
    validate(steps)?;
    let id = SequenceId::new_v7(Utc::now());
    let inserted = sqlx::query(
        "INSERT INTO sequences (id, tenant_id, name, steps, welcomes_tier) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(name.trim())
    .bind(serde_json::to_value(steps).map_err(|e| StoreError::conflict(e.to_string()))?)
    .bind(
        welcomes_tier
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty()),
    )
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
    /// Le flux qui la nourrit, s'il y en a un (voir « Le flux » en tête).
    pub feed: Option<Feed>,
    /// Le dernier jour UTC nourri ; posé aussi à la pose du flux.
    pub fed_on: Option<NaiveDate>,
    /// Le palier qu'elle accueille (`0114`), ou `None` : pas un parcours
    /// d'accueil.
    pub welcomes_tier: Option<String>,
}

/// Les séquences du locataire, vivantes d'abord, les plus récentes en tête.
pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Sequence>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, name, steps, created_at, archived_at, feed, fed_on, welcomes_tier \
           FROM sequences ORDER BY archived_at IS NOT NULL, created_at DESC",
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
            feed: row
                .get::<Option<serde_json::Value>, _>("feed")
                .and_then(|v| serde_json::from_value(v).ok()),
            fed_on: row.get("fed_on"),
            welcomes_tier: row.get("welcomes_tier"),
        })
        .collect())
}

/// Ce qui nourrit une séquence, tel que `sequences.feed` (`0111`) le porte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feed {
    /// Le siège qui écrira : c'est son budget qui borne `per_day`.
    pub employee_id: EmployeeId,
    /// Combien de contacts par jour UTC, au plus le budget du siège.
    pub per_day: u32,
    /// L'heure UTC (0–23) à partir de laquelle le jour courant est nourri.
    #[serde(default = "default_hour")]
    pub hour: u8,
    /// `accounts.segment`, l'une des valeurs de [`SEGMENTS`].
    pub segment: String,
    /// Codes pays ISO-2, dans l'ordre où les servir ; vide = tous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    /// Le nom de liste écrit à l'import (`contacts.origin_ref`, `0107`) ;
    /// `None` = toutes les listes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Pourquoi un flux est refusé.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("no such {0} in this company")]
    NotFound(&'static str),
    #[error("`per_day` is at least 1")]
    ZeroPerDay,
    #[error("`hour` is 0 to 23, UTC")]
    BadHour,
    #[error("`segment` is one of {SEGMENTS:?}")]
    BadSegment,
    #[error("`countries` are ISO 3166-1 alpha-2 codes; {0:?} is not one")]
    BadCountry(String),
    #[error("`per_day` {per_day} is over this seat's max_new_contacts_per_day of {budget}")]
    OverBudget { per_day: u32, budget: u32 },
    #[error(transparent)]
    Policy(PolicyLoadError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for FeedError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::from(err))
    }
}

/// Poser (ou remplacer) le flux d'une séquence vivante. `per_day` est borné
/// par le budget effectif du siège, et `fed_on` est posé à `today` : le premier
/// jour nourri est demain, le seul dont on sait que le budget est neuf.
pub async fn set_feed(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
    feed: &Feed,
    today: NaiveDate,
) -> Result<(), FeedError> {
    if feed.per_day == 0 {
        return Err(FeedError::ZeroPerDay);
    }
    if feed.hour > 23 {
        return Err(FeedError::BadHour);
    }
    if !SEGMENTS.contains(&feed.segment.as_str()) {
        return Err(FeedError::BadSegment);
    }
    let countries: Vec<String> = feed
        .countries
        .iter()
        .map(|c| {
            let code = c.trim().to_ascii_uppercase();
            (code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()))
                .then_some(code)
                .ok_or_else(|| FeedError::BadCountry(c.clone()))
        })
        .collect::<Result<_, _>>()?;
    let seat: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM employees WHERE id = $1 AND lifecycle = 'active')",
    )
    .bind(feed.employee_id.as_uuid())
    .fetch_one(&mut ***tx)
    .await?;
    if !seat {
        return Err(FeedError::NotFound("employee"));
    }
    let budget = policy::load(tx, feed.employee_id)
        .await
        .map_err(FeedError::Policy)?
        .limits()
        .max_new_contacts_per_day;
    if feed.per_day > budget {
        return Err(FeedError::OverBudget {
            per_day: feed.per_day,
            budget,
        });
    }
    let stored = Feed {
        countries,
        source: feed
            .source
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        ..feed.clone()
    };
    let n = sqlx::query(
        "UPDATE sequences SET feed = $2, fed_on = $3 WHERE id = $1 AND archived_at IS NULL",
    )
    .bind(sequence.as_uuid())
    .bind(serde_json::to_value(&stored).map_err(|e| StoreError::conflict(e.to_string()))?)
    .bind(today)
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(FeedError::NotFound("sequence"));
    }
    Ok(())
}

/// Enlever le flux. [`StoreError::NotFound`] hors du locataire ou archivée ;
/// une séquence sans flux est laissée telle quelle.
pub async fn remove_feed(tx: &mut TenantTx<'_>, sequence: SequenceId) -> Result<(), StoreError> {
    let n = sqlx::query("UPDATE sequences SET feed = NULL WHERE id = $1 AND archived_at IS NULL")
        .bind(sequence.as_uuid())
        .execute(&mut ***tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Nourrir une séquence pour le jour UTC de `now`, si elle a un flux, que
/// l'heure du flux est passée et qu'elle n'a pas encore été nourrie ce jour-là.
/// `None` sinon — y compris quand un autre tick vient de la réclamer :
/// l'UPDATE qui pose `fed_on` est la réclamation, et le second ne touche
/// aucune ligne. `Some(n)` : combien ont été inscrits, zéro compris.
///
/// Un siège du flux qui n'est plus actif rend l'erreur d'`enroll` et la
/// transaction est à défaire : `fed_on` reste, la boucle réessaie au tick
/// suivant et le journal le dit à chaque fois — un flux qui pointe sur un
/// siège parti est à corriger, pas à taire.
pub async fn feed(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
    now: DateTime<Utc>,
) -> Result<Option<usize>, EnrollError> {
    let claimed: Option<serde_json::Value> = sqlx::query_scalar(
        "UPDATE sequences SET fed_on = $2 \
          WHERE id = $1 AND feed IS NOT NULL AND archived_at IS NULL \
            AND (fed_on IS NULL OR fed_on < $2) \
            AND coalesce((feed->>'hour')::int, $4) <= $3 \
         RETURNING feed",
    )
    .bind(sequence.as_uuid())
    .bind(now.date_naive())
    .bind(i32::from(now.hour() as u8))
    .bind(i32::from(DEFAULT_HOUR))
    .fetch_optional(&mut ***tx)
    .await?;
    let Some(feed) = claimed.and_then(|v| serde_json::from_value::<Feed>(v).ok()) else {
        return Ok(None);
    };
    let picked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM contacts c JOIN accounts a ON a.id = c.account_id \
          WHERE c.active AND c.email IS NOT NULL AND a.segment = $1 \
            AND (cardinality($2::text[]) = 0 OR a.country = ANY($2)) \
            AND ($3::text IS NULL OR c.origin_ref = $3) \
            AND revenue_suppression_of(c.email, null::text) IS NULL \
            AND NOT EXISTS (SELECT 1 FROM sequence_runs r \
                             WHERE r.sequence_id = $4 AND r.contact_id = c.id) \
            AND NOT EXISTS (SELECT 1 FROM messages m \
                             WHERE m.direction = 'outbound' AND m.recipients ? c.email) \
          ORDER BY array_position($2::text[], a.country) NULLS LAST, c.created_at, c.id \
          LIMIT $5",
    )
    .bind(&feed.segment)
    .bind(&feed.countries)
    .bind(&feed.source)
    .bind(sequence.as_uuid())
    .bind(i64::from(feed.per_day))
    .fetch_all(&mut ***tx)
    .await?;
    for contact in &picked {
        enroll(tx, sequence, *contact, feed.employee_id, now).await?;
    }
    Ok(Some(picked.len()))
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

/// Inscrire un contact : un run à la position 0, dû maintenant, et sa
/// variante tirée ([`draw`]).
pub async fn enroll(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
    contact: Uuid,
    employee: EmployeeId,
    now: DateTime<Utc>,
) -> Result<SequenceRunId, EnrollError> {
    let steps: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT steps FROM sequences WHERE id = $1 AND archived_at IS NULL")
            .bind(sequence.as_uuid())
            .fetch_optional(&mut ***tx)
            .await?;
    let Some(steps) = steps else {
        return Err(EnrollError::NotFound("sequence"));
    };
    let steps: Vec<Step> = serde_json::from_value(steps).unwrap_or_default();
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
                                    next_at, started_at, variant) \
         VALUES ($1, $2, $3, $4, $5, $6, $6, $7) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id.as_uuid())
    .bind(tx.tenant_id().as_uuid())
    .bind(sequence.as_uuid())
    .bind(contact)
    .bind(employee.as_uuid())
    .bind(now)
    .bind(draw(id, variant_count(&steps)))
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
    /// La variante tirée à l'inscription ; `0` pour une séquence sans A/B.
    pub variant: i32,
    pub state: String,
    pub stop_reason: Option<String>,
    pub next_at: Option<DateTime<Utc>>,
    pub last_message_id: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

const RUN_COLUMNS: &str = "id, sequence_id, contact_id, employee_id, conversation_id, step, variant, \
                           state, stop_reason, next_at, last_message_id, started_at, ended_at";

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
        variant: row.get("variant"),
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

/// Ce qu'une variante a donné, en runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VariantStats {
    pub variant: i32,
    /// Inscrits, quel que soit l'état.
    pub runs: i64,
    /// Runs dont au moins un mail est parti.
    pub sent: i64,
    /// Runs dont le dernier mail a été ouvert / cliqué — la même trace que
    /// celle qu'une branche lit.
    pub opened: i64,
    pub clicked: i64,
    /// Runs terminés par une réponse — l'état que [`replied`] pose.
    pub replied: i64,
}

/// Par variante, ce que la séquence a donné : une ligne par variante tirable,
/// zéros compris. Vide hors du locataire.
pub async fn variants(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
) -> Result<Vec<VariantStats>, StoreError> {
    let steps: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT steps FROM sequences WHERE id = $1")
            .bind(sequence.as_uuid())
            .fetch_optional(&mut ***tx)
            .await?;
    let Some(steps) = steps else {
        return Ok(Vec::new());
    };
    let steps: Vec<Step> = serde_json::from_value(steps).unwrap_or_default();
    let mut out: Vec<VariantStats> = (0..variant_count(&steps))
        .map(|v| VariantStats {
            variant: v as i32,
            ..VariantStats::default()
        })
        .collect();
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT r.variant, count(*) AS runs, count(r.last_message_id) AS sent, \
                count(*) FILTER (WHERE {opened}) AS opened, \
                count(*) FILTER (WHERE {clicked}) AS clicked, \
                count(*) FILTER (WHERE r.state = 'replied') AS replied \
           FROM sequence_runs r WHERE r.sequence_id = $1 GROUP BY r.variant",
        opened = seen_sql("r.last_message_id", Signal::Opened),
        clicked = seen_sql("r.last_message_id", Signal::Clicked),
    )))
    .bind(sequence.as_uuid())
    .fetch_all(&mut ***tx)
    .await?;
    for row in &rows {
        let variant: i32 = row.get("variant");
        if let Some(slot) = out.get_mut(variant as usize) {
            slot.runs = row.get("runs");
            slot.sent = row.get("sent");
            slot.opened = row.get("opened");
            slot.clicked = row.get("clicked");
            slot.replied = row.get("replied");
        }
    }
    Ok(out)
}

/// Les promesses réservées pour le pas courant, dans l'ordre où elles l'ont
/// été : posées après le dernier envoi du run (`at > received_at`), ou après le
/// départ quand rien n'est parti. La première qui a sonné est le premier
/// réveil ; la dernière est celle qui compte. `rang_at IS NULL` tant qu'elle
/// n'a pas sonné, `outcome` ce que `loops::initiative` en a fait (`0072`),
/// `NULL` tant que le tour n'est pas fini.
///
/// `$1` est le run, `$2` son `last_message_id`.
const STEP_PROMISES: &str = "SELECT a.at, a.rang_at, a.outcome FROM appointments a \
     WHERE a.sequence_run_id = $1 \
       AND a.at > coalesce((SELECT m.received_at FROM messages m WHERE m.id = $2), \
                           '-infinity'::timestamptz) \
     ORDER BY a.at";

/// Une ligne de [`STEP_PROMISES`] : `at`, `rang_at`, `outcome`.
type Wake = (DateTime<Utc>, Option<DateTime<Utc>>, Option<String>);

/// Le siège a posé une question au fondateur depuis `since` — le réveil dont
/// on juge l'issue. Par le `sender`, qui est son slug sur le canal interne.
///
/// ponytail: le siège, pas le contact — une question n'a pas de fil quand le
/// pas est le premier. Un siège qui interroge le fondateur pendant le réveil
/// d'une séquence a décliné d'écrire, sur quoi que ce soit.
async fn asked_founder(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    since: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let asked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM messages m JOIN employees e ON e.slug = m.sender \
          WHERE e.id = $1 AND m.channel = 'internal' AND m.internal_kind = 'question' \
            AND m.received_at >= $2)",
    )
    .bind(employee.as_uuid())
    .bind(since)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(asked)
}

/// La Gate a refusé un inconnu à ce siège depuis `since` : la ligne d'audit
/// que `refusals_get` lit, avec son code.
async fn budget_refused(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    since: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let refused: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_log a \
          WHERE a.employee_id = $1 AND a.decision = 'deny' AND a.deny_reason_code = $2 \
            AND a.occurred_at >= $3)",
    )
    .bind(employee.as_uuid())
    .bind(DenyReason::ContactBudgetExhausted.code())
    .bind(since)
    .fetch_one(&mut ***tx)
    .await?;
    Ok(refused)
}

/// Le lendemain de `now`, à `hour` UTC : quand un budget du jour est neuf.
fn tomorrow(now: DateTime<Utc>, hour: u32) -> DateTime<Utc> {
    (now.date_naive() + TimeDelta::days(1))
        .and_hms_opt(hour, 0, 0)
        .expect("an hour of the day")
        .and_utc()
}

/// Réserver la promesse d'un pas `email` à `at`, portant le run.
async fn book(
    tx: &mut TenantTx<'_>,
    run: SequenceRunId,
    employee: EmployeeId,
    at: DateTime<Utc>,
    email: &str,
    conversation: Option<ConversationId>,
) -> Result<(), StoreError> {
    let booked = calendar::book_on(
        tx,
        AppointmentId::new_v7(at),
        employee,
        at,
        ZONE,
        &subject(email),
        conversation,
    )
    .await?;
    sqlx::query("UPDATE appointments SET sequence_run_id = $2 WHERE id = $1")
        .bind(booked.id.as_uuid())
        .bind(run.as_uuid())
        .execute(&mut ***tx)
        .await?;
    Ok(())
}

/// Pourquoi un retrait a échoué.
#[derive(Debug, thiserror::Error)]
pub enum UnenrollError {
    /// Pas de run actif de ce contact dans cette séquence — jamais inscrit,
    /// déjà fini, ou déjà retiré. Un 404, pas un 409 : il n'y a rien à
    /// défaire.
    #[error("no active run for this contact in this sequence")]
    NotFound,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for UnenrollError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// Retirer un contact d'une séquence : son run actif passe `stopped` avec la
/// raison `unenrolled` (0118), et la promesse qui n'a pas encore sonné est
/// annulée pour que le siège ne soit pas réveillé pour rien.
///
/// C'est le geste qui manquait le 2026-09-20 : `archive` ferme une séquence
/// entière et laisse ses runs finir, la suppression vaut pour toutes les
/// séquences. Ici le contact reste joignable, il n'est plus dans celle-là.
/// Une promesse pas encore sonnée est réglée sur-le-champ : `cancelled` si son
/// heure n'est pas venue, `no_work` si elle est déjà due —
/// `appointments_outcome_agrees_with_the_clock` (0072) n'admet `cancelled`
/// qu'avant l'heure, et une promesse due dont le run est arrêté n'a plus
/// rien à faire sonner. Dans les deux cas le siège n'est pas réveillé.
pub async fn unenroll(
    tx: &mut TenantTx<'_>,
    sequence: SequenceId,
    contact: Uuid,
    now: DateTime<Utc>,
) -> Result<SequenceRunId, UnenrollError> {
    let run: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sequence_runs \
          WHERE sequence_id = $1 AND contact_id = $2 AND state = 'active'",
    )
    .bind(sequence.as_uuid())
    .bind(contact)
    .fetch_optional(&mut ***tx)
    .await?;
    let Some(run) = run else {
        return Err(UnenrollError::NotFound);
    };
    let run = SequenceRunId::from_uuid(run);
    stop(tx, run, "stopped", Some("unenrolled"), now).await?;
    sqlx::query(
        "UPDATE appointments \
            SET rang_at = $2, \
                outcome = CASE WHEN at > $2 THEN 'cancelled' ELSE 'no_work' END \
          WHERE sequence_run_id = $1 AND rang_at IS NULL",
    )
    .bind(run.as_uuid())
    .bind(now)
    .execute(&mut ***tx)
    .await?;
    Ok(run)
}

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
        "SELECT r.step, r.employee_id, r.conversation_id, r.last_message_id, s.steps, s.feed, \
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
            let wakes: Vec<Wake> = sqlx::query_as(STEP_PROMISES)
                .bind(run.as_uuid())
                .bind(last_message)
                .fetch_all(&mut ***tx)
                .await?;
            let (rang, outcome) = match wakes.last() {
                None => {
                    book(tx, run, employee, now, &email, conversation).await?;
                    return goto(tx, run, step, now + WAKE_POLL).await;
                }
                // Réservée, pas encore sonné : la boucle initiative est en
                // retard, on attend encore.
                //
                // ponytail: un siège qui n'est plus `active` ne sonne jamais
                // (`claim_due` filtre le cycle de vie), et ce run se renouvelle
                // alors tous les `WAKE_POLL` sans fin. Le jour où ça gêne,
                // `stop(…, "seat_gone")` quand `employees.lifecycle` a changé.
                Some((_, None, _)) => return goto(tx, run, step, now + WAKE_POLL).await,
                Some((_, Some(rang), outcome)) => (*rang, outcome.as_deref()),
            };
            // « Rejouer, ou pas », en tête de module.
            let first_wake = wakes.iter().find_map(|(_, r, _)| *r).unwrap_or(rang);
            let deadline = first_wake + SEND_DEADLINE;
            if now >= deadline {
                return stop(tx, run, "stopped", Some("not_sent"), now).await;
            }
            let Some(outcome) = outcome else {
                // Sonné, pas d'issue : le tour est en cours.
                return goto(tx, run, step, (now + WAKE_POLL).min(deadline)).await;
            };
            if asked_founder(tx, employee, rang).await? {
                return stop(tx, run, "stopped", Some("declined"), now).await;
            }
            let replays = wakes.len() - 1;
            let hour = row
                .get::<Option<serde_json::Value>, _>("feed")
                .and_then(|v| serde_json::from_value::<Feed>(v).ok())
                .map_or(0, |f| u32::from(f.hour));
            let again = match outcome {
                "over_budget" => tomorrow(now, hour),
                "turn" if budget_refused(tx, employee, rang).await? => tomorrow(now, hour),
                "turn" if replays == 0 => now,
                "error" => now,
                "no_charter" => {
                    let chartered: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM employee_charters WHERE employee_id = $1)",
                    )
                    .bind(employee.as_uuid())
                    .fetch_one(&mut ***tx)
                    .await?;
                    if !chartered {
                        return goto(tx, run, step, (now + WAKE_POLL).min(deadline)).await;
                    }
                    now
                }
                _ => return stop(tx, run, "stopped", Some("not_sent"), now).await,
            };
            if replays >= MAX_REPLAYS || again > deadline {
                return stop(tx, run, "stopped", Some("not_sent"), now).await;
            }
            book(tx, run, employee, again, &email, conversation).await?;
            goto(tx, run, step, again + WAKE_POLL).await
        }
    }
}

/// Une trace `0091` sur `message` : par son id, ou par l'id fournisseur quand
/// la trace est arrivée avant que l'outbox ait posé la ligne. `message` est une
/// expression SQL de ce module — un paramètre ou une colonne — jamais une
/// valeur d'appelant : c'est l'audit que `AssertSqlSafe` demande. Une seule
/// définition, lue par la branche et par [`variants`], pour que « ouvert »
/// veuille dire la même chose des deux côtés.
fn seen_sql(message: &str, signal: Signal) -> String {
    format!(
        "EXISTS (SELECT 1 FROM message_events e \
                  WHERE e.kind = '{}' \
                    AND (e.message_id = {message} \
                         OR e.provider_message_id = \
                            (SELECT provider_message_id FROM messages WHERE id = {message})))",
        signal.kind()
    )
}

async fn signal_seen(
    tx: &mut TenantTx<'_>,
    message: Uuid,
    signal: Signal,
) -> Result<bool, StoreError> {
    let seen: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT {}",
        seen_sql("$1", signal)
    )))
    .bind(message)
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
        "SELECT s.name, s.steps, r.step, r.variant, c.email, r.conversation_id, r.last_message_id \
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
    let briefs = steps.get(step).map(Step::briefs).unwrap_or_default();
    let Some(brief) = briefs
        .get(row.get::<i32, _>("variant") as usize % briefs.len().max(1))
        .copied()
    else {
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
            brief: Some(brief.to_owned()),
            variants: Vec::new(),
        }
    }
    fn ab(variants: &[&str]) -> Step {
        Step::Email {
            brief: None,
            variants: variants.iter().map(|v| (*v).to_owned()).collect(),
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
        assert_eq!(validate(&[ab(&[])]), Err(Invalid::EmptyBrief(0)));
        assert_eq!(validate(&[ab(&["a", " "])]), Err(Invalid::EmptyBrief(0)));
        assert_eq!(validate(&[ab(&["a", "b"])]), Ok(()));
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
        // `brief` alone is still the wire form, and `variants` is the other.
        let back: Vec<Step> = serde_json::from_value(serde_json::json!([
            {"kind": "email", "brief": "x"},
            {"kind": "email", "variants": ["a", "b"]},
        ]))
        .expect("both shapes");
        assert_eq!(back, [email("x"), ab(&["a", "b"])]);
        assert_eq!(
            serde_json::to_value(&back).expect("json"),
            serde_json::json!([
                {"kind": "email", "brief": "x"},
                {"kind": "email", "variants": ["a", "b"]},
            ])
        );
    }

    /// The draw is a function of the id: the same id gives the same arm, and
    /// over a few dozen ids every arm comes up.
    #[test]
    fn the_draw_is_stable_and_covers_every_variant() {
        let ids: Vec<SequenceRunId> = (0..64).map(|_| SequenceRunId::new_v7(Utc::now())).collect();
        for n in [1usize, 2, 3] {
            let mut seen = vec![false; n];
            for id in &ids {
                let v = draw(*id, n);
                assert_eq!(v, draw(*id, n), "replayable");
                assert!((0..n as i32).contains(&v));
                seen[v as usize] = true;
            }
            assert!(seen.iter().all(|s| *s), "n={n}: an arm never came up");
        }
        assert_eq!(variant_count(&[email("x"), wait(1)]), 1);
        assert_eq!(
            variant_count(&[email("x"), ab(&["a", "b", "c"]), ab(&["d", "e"])]),
            3
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
        let id = define(
            &mut tx,
            &format!("seq-{}", Uuid::now_v7().simple()),
            steps,
            None,
        )
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
        let thread = follow_up::sent(
            &mut tx,
            f.lena,
            &prospect(),
            Some("hello"),
            "the body that left",
            "lena@ours.example",
            id,
            now,
        )
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
        assert_eq!(r.next_at, Some(t0 + WAKE_POLL));
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

        // A wake that sends nothing and whose outcome is never written: the
        // run polls, and SEND_DEADLINE after the wake it is stopped.
        let seq = defined(&f, &[email("hello")]).await;
        let t2 = t1 + TimeDelta::days(3);
        let run = enrolled(&f, seq, t2).await;
        tick(&f, run, t2).await;
        rung(&f, run, t2 + TimeDelta::minutes(1)).await;
        let r = tick(&f, run, t2 + TimeDelta::minutes(2)).await;
        assert_eq!(
            (r.state.as_str(), r.next_at),
            ("active", Some(t2 + TimeDelta::minutes(2) + WAKE_POLL))
        );
        let r = tick(&f, run, t2 + TimeDelta::minutes(1) + SEND_DEADLINE).await;
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

    /// A database of this test's own. A replay reads the seat's questions and
    /// refusals *since the wake*, and the shared base carries every
    /// neighbour's; same mechanism as `gate::tests::private_db`.
    async fn fixture_alone(suffix: &str) -> Option<Fixture> {
        use sqlx::Connection as _;

        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; a replay needs a database");
            return None;
        };
        let (host_part, tail) = url.rsplit_once('/').expect("DATABASE_URL names a database");
        let (base, options) = tail.split_once('?').map_or((tail, ""), |(b, o)| (b, o));
        let name = format!("{base}_{suffix}");
        let mine = if options.is_empty() {
            format!("{host_part}/{name}")
        } else {
            format!("{host_part}/{name}?{options}")
        };
        let db = match Db::connect(&mine).await {
            Ok(db) => db,
            Err(_) => {
                let mut admin = sqlx::PgConnection::connect(&url).await.expect("connect");
                let _ = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
                    .execute(&mut admin)
                    .await;
                admin.close().await.expect("close");
                Db::connect(&mine).await.expect("connect")
            }
        };
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

    /// The promise rang at `at` and `loops::initiative` wrote `code` on it.
    async fn woken(f: &Fixture, run: SequenceRunId, at: DateTime<Utc>, code: &str) {
        rung(f, run, at).await;
        woken_outcome(f, run, code).await;
    }

    async fn chartered(f: &Fixture) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO employee_charters (employee_id, tenant_id, role, objective) \
             VALUES ($1, $2, 'sales-development', '{}'::jsonb)",
        )
        .bind(f.lena.as_uuid())
        .bind(f.tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("charter");
        tx.commit().await.expect("commit");
    }

    /// Lena asks the founder something, as `inbound::send` writes it.
    async fn asked(f: &Fixture, now: DateTime<Utc>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let thread =
            inbound::conversation_for(&mut tx, f.lena, Channel::Internal, "founder", None, now)
                .await
                .expect("thread");
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, conversation_id, employee_id, channel, \
                                   direction, sender, body, idempotency_key, internal_kind, \
                                   received_at) \
             VALUES ($1, $2, $3, $4, 'internal', 'inbound', 'lena', 'should I write to them?', \
                     $5, 'question', $6)",
        )
        .bind(Uuid::now_v7())
        .bind(f.tenant.as_uuid())
        .bind(thread.as_uuid())
        .bind(f.lena.as_uuid())
        .bind(Uuid::now_v7().to_string())
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("question");
        tx.commit().await.expect("commit");
    }

    /// The Gate refused lena a stranger, as the trail records it.
    async fn refused(f: &Fixture, now: DateTime<Utc>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, employee_id, decision_id, actor, \
                                    action_kind, decision, deny_reason_code, occurred_at) \
             VALUES ($1, $2, $3, $4, 'system', 'send_email', 'deny', $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(f.tenant.as_uuid())
        .bind(f.lena.as_uuid())
        .bind(Uuid::now_v7())
        .bind(DenyReason::ContactBudgetExhausted.code())
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("refusal");
        tx.commit().await.expect("commit");
    }

    /// **No charter: the run waits, and is replayed the moment one exists.**
    /// Not before — a blind replay would spend both chances on the same
    /// absence — and the replayed wake sends and the run finishes.
    /// Le geste qui manquait le 2026-09-20 : retirer un contact arrête son run
    /// tout de suite, annule la promesse qui n'a pas sonné, et ne touche à
    /// rien d'autre — un second retrait est un 404, pas un second arrêt.
    #[tokio::test]
    async fn unenrolling_stops_the_run_and_cancels_its_unrung_promise() {
        let Some(f) = fixture_alone("desinscrit").await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello")]).await;
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        let before = promises(&f, run).await;
        assert_eq!(before.len(), 1);
        assert!(!before[0].1, "the promise has not rung");

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let stopped = unenroll(&mut tx, seq, f.contact, t0 + TimeDelta::minutes(1))
            .await
            .expect("unenroll");
        assert_eq!(stopped, run);
        let (state, reason): (String, Option<String>) =
            sqlx::query_as("SELECT state, stop_reason FROM sequence_runs WHERE id = $1")
                .bind(run.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("row");
        assert_eq!(
            (state.as_str(), reason.as_deref()),
            ("stopped", Some("unenrolled"))
        );
        let settled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM appointments \
              WHERE sequence_run_id = $1 AND rang_at IS NOT NULL \
                AND outcome IN ('cancelled', 'no_work')",
        )
        .bind(run.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("count");
        assert_eq!(
            settled, 1,
            "the unrung promise is settled, not left to ring"
        );

        // Nothing to undo twice.
        let again = unenroll(&mut tx, seq, f.contact, t0 + TimeDelta::minutes(2)).await;
        assert!(matches!(again, Err(UnenrollError::NotFound)), "{again:?}");
        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn no_charter_is_replayed_once_the_charter_is_there() {
        let Some(f) = fixture_alone("rejeu_charte").await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello")]).await;
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        woken(&f, run, t0 + TimeDelta::minutes(1), "no_charter").await;

        let t1 = t0 + TimeDelta::minutes(2);
        let r = tick(&f, run, t1).await;
        assert_eq!((r.state.as_str(), r.step), ("active", 0));
        assert_eq!(r.next_at, Some(t1 + WAKE_POLL), "polling, not replaying");
        assert_eq!(promises(&f, run).await.len(), 1);

        chartered(&f).await;
        let t2 = t1 + WAKE_POLL;
        let r = tick(&f, run, t2).await;
        assert_eq!(r.state, "active");
        let booked = promises(&f, run).await;
        assert_eq!(booked.len(), 2, "a new promise for the same step");
        assert!(!booked[1].1, "not rung yet");
        assert_eq!(r.next_at, Some(t2 + WAKE_POLL));

        rung(&f, run, t2 + TimeDelta::minutes(1)).await;
        let t3 = t2 + TimeDelta::minutes(2);
        assert_eq!(sent_by_lena(&f, "msg-1", t3).await, Some(run));
        assert_eq!(tick(&f, run, t3).await.state, "done");
    }

    /// **A spent budget is replayed after midnight UTC, at the feed's hour,
    /// and never past `SEND_DEADLINE` from the first wake.** The first wake is
    /// `over_budget`; the replay rings at 8 h the next day and the Gate refuses
    /// the stranger; the next possible replay is beyond the deadline, so the
    /// run stops `not_sent` — the reading the founder acts on.
    #[tokio::test]
    async fn an_exhausted_budget_is_replayed_after_midnight_and_not_past_the_deadline() {
        use agentos_domain::policy::PolicyLimits;

        let Some(f) = fixture_alone("rejeu_budget").await else {
            return;
        };
        policy::install(
            &f.db,
            f.tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                max_new_contacts_per_day: 5,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
        let today = Utc::now().date_naive();
        let at = |days: i64, h: u32, m: u32| {
            (today + TimeDelta::days(days))
                .and_hms_opt(h, m, 0)
                .expect("time")
                .and_utc()
        };
        let seq = defined(&f, &[email("hello")]).await;
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        set_feed(
            &mut tx,
            seq,
            &Feed {
                employee_id: f.lena,
                per_day: 1,
                hour: 8,
                segment: "airline".to_owned(),
                countries: Vec::new(),
                source: None,
            },
            today,
        )
        .await
        .expect("feed");
        tx.commit().await.expect("commit");

        let t0 = at(0, 10, 0);
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        woken(&f, run, at(0, 10, 1), "over_budget").await;
        let r = tick(&f, run, at(0, 10, 2)).await;
        assert_eq!(r.state, "active");
        assert_eq!(
            r.next_at,
            Some(at(1, 8, 0) + WAKE_POLL),
            "tomorrow, at the feed's hour"
        );
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let ats: Vec<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT at FROM appointments WHERE sequence_run_id = $1 ORDER BY at",
        )
        .bind(run.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .expect("promises");
        tx.rollback().await.expect("rollback");
        assert_eq!(ats, [t0, at(1, 8, 0)]);
        // Before it rings, ticks change nothing.
        tick(&f, run, at(0, 23, 0)).await;
        assert_eq!(promises(&f, run).await.len(), 2);

        // It rings, the turn runs, the Gate refuses the sixth stranger.
        rung(&f, run, at(1, 8, 1)).await;
        refused(&f, at(1, 8, 1)).await;
        woken_outcome(&f, run, "turn").await;
        let r = tick(&f, run, at(1, 8, 2)).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("not_sent")),
            "the day after is past SEND_DEADLINE from the first wake"
        );
        assert_eq!(promises(&f, run).await.len(), 2, "nothing more was booked");
    }

    /// Only the outcome, on a promise that already rang.
    async fn woken_outcome(f: &Fixture, run: SequenceRunId, code: &str) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let n = sqlx::query(
            "UPDATE appointments SET outcome = $2 \
              WHERE sequence_run_id = $1 AND rang_at IS NOT NULL AND outcome IS NULL",
        )
        .bind(run.as_uuid())
        .bind(code)
        .execute(&mut **tx)
        .await
        .expect("outcome")
        .rows_affected();
        tx.commit().await.expect("commit");
        assert_eq!(n, 1);
    }

    /// **A question to the founder is a decision, not a fault.** The run stops
    /// `declined` on the next poll, and the reading says so.
    #[tokio::test]
    async fn a_question_to_the_founder_stops_the_run_at_once_as_declined() {
        let Some(f) = fixture_alone("rejeu_question").await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello"), wait(24), email("again")]).await;
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        rung(&f, run, t0 + TimeDelta::minutes(1)).await;
        asked(&f, t0 + TimeDelta::minutes(2)).await;
        woken_outcome(&f, run, "turn").await;
        let r = tick(&f, run, t0 + TimeDelta::minutes(3)).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref(), r.step),
            ("stopped", Some("declined"), 0)
        );
        assert!(r.ended_at.is_some());
        assert_eq!(promises(&f, run).await.len(), 1, "not replayed");
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let listed = runs(&mut tx, seq).await.expect("runs");
        tx.rollback().await.expect("rollback");
        assert_eq!(listed[0].stop_reason.as_deref(), Some("declined"));
    }

    /// **Two replays at most, and an unknown turn gets one.** Three `error`
    /// wakes in a row end `not_sent`; a `turn` that neither sent nor asked is
    /// tried once more, then `not_sent`.
    #[tokio::test]
    async fn an_error_is_replayed_twice_at_most_and_an_unknown_turn_once() {
        let Some(f) = fixture_alone("rejeu_borne").await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(&f, &[email("hello")]).await;
        let run = enrolled(&f, seq, t0).await;
        tick(&f, run, t0).await;
        let mut t = t0;
        for replay in 1..=MAX_REPLAYS {
            woken(&f, run, t + TimeDelta::minutes(1), "error").await;
            t += TimeDelta::minutes(2);
            let r = tick(&f, run, t).await;
            assert_eq!(r.state, "active", "replay {replay}");
            assert_eq!(promises(&f, run).await.len(), replay + 1);
            assert_eq!(r.next_at, Some(t + WAKE_POLL), "replayed at once");
        }
        woken(&f, run, t + TimeDelta::minutes(1), "error").await;
        let r = tick(&f, run, t + TimeDelta::minutes(2)).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("not_sent"))
        );
        assert_eq!(promises(&f, run).await.len(), MAX_REPLAYS + 1);

        let seq = defined(&f, &[email("hello")]).await;
        let t1 = t + TimeDelta::hours(1);
        let run = enrolled(&f, seq, t1).await;
        tick(&f, run, t1).await;
        woken(&f, run, t1 + TimeDelta::minutes(1), "turn").await;
        assert_eq!(
            tick(&f, run, t1 + TimeDelta::minutes(2)).await.state,
            "active"
        );
        assert_eq!(promises(&f, run).await.len(), 2, "one more try");
        woken(&f, run, t1 + TimeDelta::minutes(3), "turn").await;
        let r = tick(&f, run, t1 + TimeDelta::minutes(4)).await;
        assert_eq!(
            (r.state.as_str(), r.stop_reason.as_deref()),
            ("stopped", Some("not_sent"))
        );
        assert_eq!(promises(&f, run).await.len(), 2);
    }

    /// **A run keeps its arm, the wake carries that arm's brief, and the
    /// reading counts runs.** One enrolment, so the arm is whichever the id
    /// draws; the test reads it back rather than assuming it.
    #[tokio::test]
    async fn a_run_keeps_its_variant_and_the_reading_counts_runs() {
        let Some(f) = fixture().await else {
            return;
        };
        let t0 = Utc::now().trunc_subsecs(6);
        let seq = defined(
            &f,
            &[
                ab(&["arm A: a question", "arm B: a number"]),
                email("plain"),
            ],
        )
        .await;
        let run = enrolled(&f, seq, t0).await;
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let r = find(&mut tx, run).await.expect("find").expect("mine");
        assert_eq!(r.variant, draw(run, 2), "written at enrolment, from the id");
        let (mine, other) = (r.variant as usize, 1 - r.variant as usize);
        // Nothing has happened yet: one row per arm, zeros included.
        let before = variants(&mut tx, seq).await.expect("variants");
        assert_eq!(before.len(), 2);
        assert_eq!(before[mine].runs, 1);
        assert_eq!(
            before[other],
            VariantStats {
                variant: other as i32,
                ..Default::default()
            }
        );
        tx.rollback().await.expect("rollback");

        tick(&f, run, t0).await;
        rung(&f, run, t0 + TimeDelta::minutes(1)).await;
        let text = brief(&f.db, f.tenant, run).await.expect("brief");
        let (yes, no) = if mine == 0 {
            ("arm A", "arm B")
        } else {
            ("arm B", "arm A")
        };
        assert!(text.contains(yes), "{text}");
        assert!(!text.contains(no), "{text}");

        let t1 = t0 + TimeDelta::minutes(2);
        assert_eq!(sent_by_lena(&f, "msg-1", t1).await, Some(run));
        let r = tick(&f, run, t1).await; // step 1: the plain email, same run, same arm
        assert_eq!((r.step, r.variant as usize), (1, mine));
        opened(&f, r.last_message_id.expect("msg-1")).await;
        reply(&f, t1 + TimeDelta::hours(1)).await;

        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let after = variants(&mut tx, seq).await.expect("variants");
        assert_eq!(
            after[mine],
            VariantStats {
                variant: mine as i32,
                runs: 1,
                sent: 1,
                opened: 1,
                clicked: 0,
                replied: 1
            }
        );
        assert_eq!(after[other].runs, 0);
        tx.rollback().await.expect("rollback");
        // The other company reads nothing.
        let mut tx = f.db.tenant_tx(f.other).await.expect("tx");
        assert!(
            variants(&mut tx, seq).await.expect("variants").is_empty(),
            "RLS"
        );
        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn define_archive_and_the_other_company() {
        let Some(f) = fixture().await else {
            return;
        };
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let err = define(&mut tx, "x", &[wait(1)], None)
            .await
            .expect_err("shape");
        assert!(
            matches!(err, DefineError::Invalid(Invalid::NoEmail)),
            "{err}"
        );
        let id = define(&mut tx, "intro", &[email("hi")], None)
            .await
            .expect("define");
        let err = define(&mut tx, "intro", &[email("hi")], None)
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
        define(&mut tx, "intro", &[email("hi")], None)
            .await
            .expect("name freed");
        let err = enroll(&mut tx, id, f.contact, f.lena, Utc::now())
            .await
            .expect_err("archived");
        assert!(matches!(err, EnrollError::NotFound("sequence")), "{err}");
        tx.rollback().await.expect("rollback");
    }

    /// One more account and contact under `f.tenant`, with the columns the
    /// feed reads: segment, country, list name, and an explicit `created_at`
    /// so the order is the test's and not the clock's.
    async fn prospect_in(
        f: &Fixture,
        segment: &str,
        country: &str,
        source: Option<&str>,
        created_at: DateTime<Utc>,
    ) -> Uuid {
        let (account, contact) = (Uuid::now_v7(), Uuid::now_v7());
        let mut admin = f.db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, legal_name, domain, segment, country) \
             VALUES ($1, $2, 'Prospect', $3, $4, $5)",
        )
        .bind(account)
        .bind(f.tenant.as_uuid())
        .bind(format!("{}.example", account.simple()))
        .bind(segment)
        .bind(country)
        .execute(&mut *admin)
        .await
        .expect("account");
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, account_id, full_name, email, origin, \
                                   origin_ref, created_at) \
             VALUES ($1, $2, $3, 'Someone', $4, $5, $6, $7)",
        )
        .bind(contact)
        .bind(f.tenant.as_uuid())
        .bind(account)
        .bind(format!("someone@{}.example", account.simple()))
        .bind(source.map(|_| "import"))
        .bind(source)
        .bind(created_at)
        .execute(&mut *admin)
        .await
        .expect("contact");
        admin.commit().await.expect("commit");
        contact
    }

    /// The contacts the feed enrolled on `seq` — the active runs, as a set:
    /// the runs of one feeding share a `started_at`, so their order is not
    /// readable back.
    async fn fed_contacts(f: &Fixture, seq: SequenceId) -> std::collections::BTreeSet<Uuid> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let all = runs(&mut tx, seq).await.expect("runs");
        tx.rollback().await.expect("rollback");
        all.into_iter()
            .filter(|r| r.state == "active")
            .map(|r| r.contact_id)
            .collect()
    }

    /// Feed at `hh:mm` UTC on `day`.
    async fn fed_at(
        f: &Fixture,
        seq: SequenceId,
        day: NaiveDate,
        hh: u32,
        mm: u32,
    ) -> Option<usize> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let n = feed(
            &mut tx,
            seq,
            day.and_hms_opt(hh, mm, 0).expect("time").and_utc(),
        )
        .await
        .expect("feed");
        tx.commit().await.expect("commit");
        n
    }

    /// Feed at the default hour on `day`.
    async fn fed(f: &Fixture, seq: SequenceId, day: NaiveDate) -> Option<usize> {
        fed_at(f, seq, day, u32::from(DEFAULT_HOUR), 0).await
    }

    async fn fed_on(f: &Fixture, seq: SequenceId) -> Option<NaiveDate> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let mine = list(&mut tx).await.expect("list");
        tx.rollback().await.expect("rollback");
        mine.into_iter().find(|s| s.id == seq).expect("mine").fed_on
    }

    /// **The feed picks who is next, once a day, and says when it is dry.**
    /// Countries in the order given, then the oldest first; the suppressed,
    /// the already-enrolled, the already-written and the inactive are never
    /// offered; the day it is set counts as fed; a second call the same day
    /// does nothing; zero left still stamps the day.
    #[tokio::test]
    async fn a_feed_picks_who_is_next_once_a_day_and_says_when_it_is_dry() {
        use agentos_domain::policy::PolicyLimits;
        use agentos_store::policy;

        let Some(f) = fixture().await else {
            return;
        };
        policy::install(
            &f.db,
            f.tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                max_new_contacts_per_day: 5,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
        let t0 = Utc::now().trunc_subsecs(6);
        let day = |n: i64| (t0 + TimeDelta::days(n)).date_naive();
        let seq = defined(&f, &[email("hello")]).await;

        let fr_old = prospect_in(&f, "airline", "FR", None, t0 - TimeDelta::days(5)).await;
        let fr_new = prospect_in(&f, "airline", "FR", None, t0 - TimeDelta::days(1)).await;
        let gb = prospect_in(&f, "airline", "GB", None, t0 - TimeDelta::days(3)).await;
        let us = prospect_in(&f, "airline", "US", None, t0 - TimeDelta::days(8)).await;
        let de_listed = prospect_in(
            &f,
            "airline",
            "DE",
            Some("liste-b"),
            t0 - TimeDelta::days(2),
        )
        .await;
        // Never offered: another segment, suppressed, enrolled once, inactive,
        // and paul, to whom lena has already written.
        prospect_in(&f, "ota", "FR", None, t0 - TimeDelta::days(9)).await;
        let opted_out = prospect_in(&f, "airline", "FR", None, t0 - TimeDelta::days(9)).await;
        let once = prospect_in(&f, "airline", "FR", None, t0 - TimeDelta::days(9)).await;
        let gone = prospect_in(&f, "airline", "FR", None, t0 - TimeDelta::days(9)).await;
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, channel, address, reason) \
             SELECT $1, $2, 'email', email, 'opt_out' FROM contacts WHERE id = $3",
        )
        .bind(Uuid::now_v7())
        .bind(f.tenant.as_uuid())
        .bind(opted_out)
        .execute(&mut **tx)
        .await
        .expect("suppress");
        let run = enroll(&mut tx, seq, once, f.lena, t0).await.expect("once");
        stop(&mut tx, run, "stopped", Some("not_sent"), t0)
            .await
            .expect("and finished");
        sqlx::query("UPDATE contacts SET active = false WHERE id = $1")
            .bind(gone)
            .execute(&mut **tx)
            .await
            .expect("inactive");
        tx.commit().await.expect("commit");
        assert!(sent_by_lena(&f, "msg-1", t0).await.is_none());

        // The rules of the shape, and the one that reads the seat's budget.
        let plan = Feed {
            employee_id: f.lena,
            per_day: 2,
            hour: DEFAULT_HOUR,
            segment: "airline".to_owned(),
            countries: vec!["gb".to_owned(), " fr ".to_owned()],
            source: None,
        };
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        for (bad, why) in [
            (
                Feed {
                    per_day: 0,
                    ..plan.clone()
                },
                "ZeroPerDay",
            ),
            (
                Feed {
                    hour: 24,
                    ..plan.clone()
                },
                "BadHour",
            ),
            (
                Feed {
                    segment: "cruise_line".to_owned(),
                    ..plan.clone()
                },
                "BadSegment",
            ),
            (
                Feed {
                    countries: vec!["FRA".to_owned()],
                    ..plan.clone()
                },
                "BadCountry",
            ),
            (
                Feed {
                    employee_id: EmployeeId::new_v7(t0),
                    ..plan.clone()
                },
                "NotFound",
            ),
        ] {
            let err = set_feed(&mut tx, seq, &bad, day(0)).await.expect_err(why);
            assert!(format!("{err:?}").starts_with(why), "{why}: {err:?}");
        }
        let err = set_feed(
            &mut tx,
            seq,
            &Feed {
                per_day: 6,
                ..plan.clone()
            },
            day(0),
        )
        .await
        .expect_err("over the seat's budget");
        assert!(
            matches!(
                err,
                FeedError::OverBudget {
                    per_day: 6,
                    budget: 5
                }
            ),
            "{err:?}"
        );
        set_feed(&mut tx, seq, &plan, day(0)).await.expect("set");
        let mine = list(&mut tx).await.expect("list");
        let stored = mine[0].feed.as_ref().expect("a feed");
        assert_eq!(stored.countries, ["GB", "FR"], "normalised on the way in");
        assert_eq!(
            mine[0].fed_on,
            Some(day(0)),
            "the day it is set counts as fed"
        );
        tx.commit().await.expect("commit");
        // The other company cannot set, remove, or see it.
        let mut tx = f.db.tenant_tx(f.other).await.expect("tx");
        let err = set_feed(
            &mut tx,
            seq,
            &Feed {
                employee_id: f.lena,
                ..plan.clone()
            },
            day(0),
        )
        .await
        .expect_err("not theirs");
        assert!(matches!(err, FeedError::NotFound("employee")), "{err:?}");
        assert!(matches!(
            remove_feed(&mut tx, seq).await,
            Err(StoreError::NotFound)
        ));
        tx.rollback().await.expect("rollback");

        // Today is already fed; tomorrow, not before the hour — then GB
        // first, then the oldest FR.
        assert_eq!(fed(&f, seq, day(0)).await, None);
        assert_eq!(
            fed_at(&f, seq, day(1), 7, 59).await,
            None,
            "before the hour"
        );
        assert_eq!(fed_at(&f, seq, day(1), 8, 0).await, Some(2));
        assert_eq!(fed_contacts(&f, seq).await, [gb, fr_old].into());
        assert_eq!(fed_at(&f, seq, day(1), 8, 30).await, None, "once a day");
        assert_eq!(fed_contacts(&f, seq).await.len(), 2);
        // The next day: the newer FR, and nobody else of GB or FR is left.
        assert_eq!(fed(&f, seq, day(2)).await, Some(1));
        assert_eq!(fed_contacts(&f, seq).await, [gb, fr_old, fr_new].into());
        // Dry: the day is stamped all the same, so the loop does not retry.
        assert_eq!(fed(&f, seq, day(3)).await, Some(0));
        assert_eq!(fed_on(&f, seq).await, Some(day(3)));

        // No countries: everyone of the segment, oldest first — US before DE.
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        set_feed(
            &mut tx,
            seq,
            &Feed {
                per_day: 1,
                countries: Vec::new(),
                ..plan.clone()
            },
            day(3),
        )
        .await
        .expect("set");
        tx.commit().await.expect("commit");
        assert_eq!(fed(&f, seq, day(4)).await, Some(1));
        assert!(fed_contacts(&f, seq).await.contains(&us));
        // One list only: the DE contact, and only it.
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        set_feed(
            &mut tx,
            seq,
            &Feed {
                per_day: 5,
                countries: Vec::new(),
                source: Some("liste-b".to_owned()),
                ..plan.clone()
            },
            day(4),
        )
        .await
        .expect("set");
        tx.commit().await.expect("commit");
        assert_eq!(fed(&f, seq, day(5)).await, Some(1));
        assert_eq!(
            fed_contacts(&f, seq).await,
            [gb, fr_old, fr_new, us, de_listed].into()
        );

        // Removed: nothing is fed, and the day is not stamped.
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        remove_feed(&mut tx, seq).await.expect("remove");
        tx.commit().await.expect("commit");
        assert_eq!(fed(&f, seq, day(6)).await, None);
        assert_eq!(fed_on(&f, seq).await, Some(day(5)));
    }
}
