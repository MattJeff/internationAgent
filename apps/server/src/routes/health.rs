//! `GET /v1/health/company` : est-ce que cette société pense encore.
//!
//! # Le jour où cette route aurait dû exister
//!
//! Le 2026-09-06, `NoModel::SubscriptionIsNotOursToHold` s'est mis à refuser
//! chaque tour d'Orizn. Le fondateur l'a vu le 2026-09-10, parce qu'un employé
//! ne lui répondait pas. Pendant quatre jours, **tout ce qu'on savait
//! interroger disait que l'entreprise allait bien** : `/readyz` répondait — il
//! mesure ce processus, pas le travail —, les sièges étaient `active`,
//! `GET /v1/model` rendait une connexion vérifiée (elle l'était : c'est la
//! *règle* qui a changé, pas la clé), et `GET /v1/employees/{id}/initiative`
//! rendait `error` sur une ligne que personne n'ouvre quand rien ne crie.
//!
//! La seule trace était trois lignes dans les journaux d'un conteneur. Une
//! entreprise dont plus aucun employé ne pense doit le dire sur un écran, en
//! rouge, dès le premier tour perdu — pas dans `docker logs`.
//!
//! # Ce que cette route n'invente pas
//!
//! Rien. Les quatre nombres viennent de `turn_outcomes` (`migrations/0099`),
//! écrit par `loops::initiative::record` à l'endroit exact où « no turn taken »
//! est journalisé, et les rebuts viennent d'`outbox_events` par le prédicat que
//! `store::outbox::dead_letters` lit déjà. Le modèle vient de la même lecture
//! que `GET /v1/model`. Il n'y a pas de moyenne, pas de score, pas de
//! pourcentage : trois verdicts, et les chiffres qui les produisent, à côté.
//!
//! # `last_failure_detail` est notre texte
//!
//! Publier la phrase d'un fournisseur dans une bannière de console serait
//! donner à un tiers un pinceau sur notre écran d'accueil. Ce n'est pas le cas
//! ici, et c'est une propriété de l'écriture plutôt qu'un filtre à la lecture :
//! `loops::initiative::take_turn` réduit déjà l'erreur d'un tour à
//! `failed.error.code()`, un vocabulaire fermé, et tout le reste de
//! `Outcome::detail()` est une phrase de ce dépôt — les variantes de
//! `agentos_app::model_access::NoModel`, la phrase du plafond d'abonnement.
//! Les deux moitiés sont tenues par des tests de la boucle plutôt que par un
//! filtre ici : `a_provider_that_fails_forever…` relit ce qu un vrai
//! fournisseur en panne a laissé dans `turn_outcomes`, et
//! `la_phrase_publiee_quand_le_modele_refuse_est_la_notre` relit la phrase que
//! la bannière affichera. Un filtre à la lecture serait un deuxième endroit à
//! garder vrai.
//!
//! # L'auth
//!
//! Celle d'`outreach` : la clé du locataire, par [`Principal`], et toutes les
//! lectures sous [`Db::tenant_tx`]. La santé d'une autre entreprise n'est pas
//! filtrée, elle est invisible.

use agentos_store::db::{Db, StoreError};
use agentos_store::outbox::MAX_ATTEMPTS;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::loops::initiative::TURN;

/// Ce module.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/health/company", get_route(get))
        .with_state(db)
}

/// Au-delà de quoi « aucun succès » cesse d'être un creux et devient un arrêt.
///
/// Six heures parce que c'est plus long que toute cadence qu'un opérateur pose
/// en pratique (le maximum est de 30 jours, mais une société qui travaille bat
/// en minutes) et assez court pour qu'un fondateur qui ouvre la console le
/// matin voie la nuit qui s'est mal passée. La borne n'est franchie que par une
/// société qui a **essayé** dans cette même fenêtre : voir [`verdict`].
const STALE_AFTER: Duration = Duration::hours(6);

// ---------------------------------------------------------------------------
// La réponse
// ---------------------------------------------------------------------------

/// Ce qu'une société répond quand on lui demande si elle pense.
#[derive(Debug, Serialize)]
struct CompanyHealth {
    /// Battements qui comptaient aujourd'hui (UTC) : succès plus échecs. Un
    /// battement au repos n'y est pas — voir `Outcome::health`.
    turns_attempted_today: i64,
    turns_failed_today: i64,
    /// Le dernier tour qui a abouti, **sans borne de temps**. C'est la phrase
    /// qui manquait au fondateur : « dernier travail effectué il y a quatre
    /// jours » n'est pas dérivable d'une fenêtre d'aujourd'hui.
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_failure_code: Option<String>,
    last_failure_detail: Option<String>,
    /// Des effets de bord qui n'auront pas lieu. Voir [`dead_lettered`] pour ce
    /// que « aujourd'hui » veut dire sur une table sans date de rebut.
    dead_lettered_today: i64,
    /// La connexion au modèle, telle que `GET /v1/model` la rend. `null` quand
    /// il n'y en a aucune — ce qui est en soi une des façons de ne plus penser.
    model: Option<agentos_domain::model_access::ModelAccess>,
    verdict: Verdict,
}

/// Trois états, et pas un score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    /// Aucun échec, ou aucun tour tenté. **Une société au repos n'est pas
    /// malade** : une entreprise neuve, un samedi, une flotte sans cadence
    /// posée sont trois façons de ne rien faire qui ne sont pas des pannes, et
    /// une bannière rouge le premier matin est une bannière que plus personne
    /// ne lit le deuxième.
    Working,
    /// Des échecs et des succès mêlés. Quelque chose casse par intermittence :
    /// à regarder, pas à réveiller quelqu'un.
    Degraded,
    /// Elle essaie et n'y arrive plus. Le cas d'Orizn.
    Stopped,
}

/// Les quatre nombres que `turn_outcomes` rend, séparés du verdict pour que
/// [`verdict`] soit une fonction pure qu'un test appelle sans base.
#[derive(Debug, Clone, Copy, sqlx::FromRow)]
struct Counts {
    attempted_today: i64,
    failed_today: i64,
    /// Battements dans les six dernières heures, quelle que soit leur issue.
    attempted_recently: i64,
    last_success_at: Option<DateTime<Utc>>,
}

/// Le verdict, à partir des seuls chiffres.
///
/// L'ordre des trois questions est le sens de la route :
///
/// 1. **Rien tenté, ou rien raté → `working`.** Dit en premier parce que c'est
///    le cas d'une société qui va bien *et* de celle qui dort, et que confondre
///    les deux avec une panne est la faute qui décrédibilise l'écran.
/// 2. **Elle essaie encore, et rien n'a abouti depuis plus de six heures →
///    `stopped`.** Les deux moitiés comptent : « aucun succès depuis six
///    heures » tout seul est vrai d'une entreprise fermée le week-end, et
///    « elle essaie » tout seul est vrai d'une entreprise qui travaille. C'est
///    leur conjonction qui décrit un employé qui se lève, échoue, et
///    recommence — quatre jours durant.
/// 3. **Sinon → `degraded`.** Il y a eu des échecs aujourd'hui, et quelque
///    chose a quand même abouti récemment.
///
/// « Plus de six heures » est strict : à six heures pile, le dernier succès est
/// encore dans la fenêtre et le verdict est `degraded`.
/// `la_fenetre_de_six_heures_a_ses_deux_bornes` tient les deux côtés.
fn verdict(counts: Counts, now: DateTime<Utc>) -> Verdict {
    if counts.attempted_today == 0 || counts.failed_today == 0 {
        return Verdict::Working;
    }
    let stale = counts
        .last_success_at
        .is_none_or(|at| at < now - STALE_AFTER);
    if stale && counts.attempted_recently > 0 {
        return Verdict::Stopped;
    }
    Verdict::Degraded
}

// ---------------------------------------------------------------------------
// Les lectures
// ---------------------------------------------------------------------------

/// Les quatre nombres, en une passe.
///
/// `count(*) FILTER` plutôt que quatre requêtes : `turn_outcomes_tenant_at_idx`
/// est parcouru une fois, et RLS fournit le `tenant_id`. `code <> TURN` est un
/// échec par construction — la table ne contient que des succès et des échecs,
/// jamais un battement au repos.
const COUNTS_SQL: &str = "\
    SELECT \
      count(*) FILTER (WHERE at >= $2)::bigint                  AS attempted_today, \
      count(*) FILTER (WHERE at >= $2 AND code <> $1)::bigint   AS failed_today, \
      count(*) FILTER (WHERE at >= $3)::bigint                  AS attempted_recently, \
      max(at)  FILTER (WHERE code = $1)                         AS last_success_at \
    FROM turn_outcomes";

/// Le dernier échec, sans borne : une société arrêtée depuis quatre jours doit
/// pouvoir nommer ce qui l'a arrêtée même si le premier refus est plus vieux
/// que la fenêtre du jour.
const LAST_FAILURE_SQL: &str = "\
    SELECT at, code, detail FROM turn_outcomes \
     WHERE code <> $1 ORDER BY at DESC LIMIT 1";

/// Combien d'effets de bord ont été abandonnés aujourd'hui.
///
/// `outbox_events` n'a **pas** de colonne de rebut : `store::outbox` explique
/// que brûler le compteur de tentatives *est* l'état de rebut, et le prédicat
/// ci-dessous est celui de `dead_letters`, à une borne de temps près.
///
/// Cette borne est `available_at`, qui pour une ligne au rebut est l'instant où
/// la dernière tentative a reprogrammé un essai qui n'aura jamais lieu — donc
/// « quand elle est morte », à un backoff près. C'est la seule date que la
/// table porte, et le dire ici vaut mieux que de rendre un total de tous les
/// temps sous un nom qui dit « today ».
const DEAD_LETTERED_SQL: &str = "\
    SELECT count(*)::bigint FROM outbox_events \
     WHERE published_at IS NULL AND attempt_count >= $1 AND available_at >= $2";

/// `GET /v1/health/company`.
///
/// 200 en toutes circonstances, y compris `stopped` : ce n'est pas une sonde de
/// disponibilité, c'est une lecture. Un 503 ici ferait sortir la console de la
/// route au moment précis où elle a quelque chose à afficher.
async fn get(State(db): State<Db>, principal: Principal) -> Result<Response, ApiError> {
    let now = Utc::now();
    // Minuit UTC, la même journée que `turn_buckets`, `spend_buckets` et
    // `model_usage_daily`. Un employé n'a pas deux « aujourd'hui ».
    let today = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    let recent = now - STALE_AFTER;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let counts: Counts = sqlx::query_as(COUNTS_SQL)
        .bind(TURN)
        .bind(today)
        .bind(recent)
        .fetch_one(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let failure: Option<(DateTime<Utc>, String, Option<String>)> = sqlx::query_as(LAST_FAILURE_SQL)
        .bind(TURN)
        .fetch_optional(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let dead_lettered: i64 = sqlx::query_scalar(DEAD_LETTERED_SQL)
        .bind(MAX_ATTEMPTS)
        .bind(today)
        .fetch_one(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let model = agentos_store::model_access::load(&mut tx).await?;
    tx.rollback().await?;

    let (last_failure_at, last_failure_code, last_failure_detail) = match failure {
        Some((at, code, detail)) => (Some(at), Some(code), detail),
        None => (None, None, None),
    };

    Ok(axum::Json(CompanyHealth {
        turns_attempted_today: counts.attempted_today,
        turns_failed_today: counts.failed_today,
        last_success_at: counts.last_success_at,
        last_failure_at,
        last_failure_code,
        last_failure_detail,
        dead_lettered_today: dead_lettered,
        model: model.map(|connection| connection.access),
        verdict: verdict(counts, now),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::{EmployeeId, TenantId};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Une horloge fixe, pour que les bornes soient des soustractions plutôt
    /// que des instants qui bougent pendant le test.
    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_757_500_000, 0).expect("un instant")
    }

    /// `last` est un âge en heures, parce que c'est ainsi que la fenêtre se
    /// lit : « le dernier succès remonte à N heures ».
    fn counts(attempted: i64, failed: i64, recently: i64, last: Option<i64>) -> Counts {
        Counts {
            attempted_today: attempted,
            failed_today: failed,
            attempted_recently: recently,
            last_success_at: last.map(|h| now() - Duration::hours(h)),
        }
    }

    /// Le cas d'Orizn, en quatre nombres : elle essaie, elle rate, et le
    /// dernier travail effectué remonte à quatre jours.
    #[test]
    fn une_societe_qui_essaie_et_ne_reussit_plus_est_stopped() {
        assert_eq!(
            verdict(counts(288, 288, 72, Some(96)), now()),
            Verdict::Stopped
        );
        // Et sans le moindre succès depuis toujours, même verdict : `None`
        // n'est pas « récent », c'est « jamais ».
        assert_eq!(verdict(counts(12, 12, 12, None), now()), Verdict::Stopped);
    }

    #[test]
    fn des_echecs_et_des_succes_meles_sont_degraded() {
        assert_eq!(
            verdict(counts(40, 9, 12, Some(1)), now()),
            Verdict::Degraded
        );
    }

    /// Les deux moitiés de `working`, et la seconde est celle qui compte : une
    /// société au repos n'est pas malade.
    #[test]
    fn pas_dechec_ou_aucun_tour_tente_est_working() {
        assert_eq!(verdict(counts(40, 0, 12, Some(0)), now()), Verdict::Working);
        // Aucun battement du tout — une entreprise neuve, un samedi, une flotte
        // sans cadence posée. Aucun succès non plus, et pourtant rien de rouge.
        assert_eq!(verdict(counts(0, 0, 0, None), now()), Verdict::Working);
    }

    /// La fenêtre, aux deux bornes. « Plus de six heures » est strict : à six
    /// heures pile le dernier succès est encore dedans.
    #[test]
    fn la_fenetre_de_six_heures_a_ses_deux_bornes() {
        let dedans = Counts {
            last_success_at: Some(now() - STALE_AFTER),
            ..counts(48, 40, 12, None)
        };
        assert_eq!(verdict(dedans, now()), Verdict::Degraded);

        let dehors = Counts {
            last_success_at: Some(now() - STALE_AFTER - Duration::seconds(1)),
            ..counts(48, 40, 12, None)
        };
        assert_eq!(verdict(dehors, now()), Verdict::Stopped);
    }

    /// L'autre moitié de `stopped`. Une entreprise qui a raté ce matin et que
    /// plus rien ne réveille est `degraded`, pas `stopped` : il n'y a pas
    /// d'arrêt en cours tant que rien ne réessaie.
    #[test]
    fn sans_tentative_dans_la_fenetre_ce_nest_pas_un_arret() {
        assert_eq!(
            verdict(counts(20, 20, 0, Some(30)), now()),
            Verdict::Degraded
        );
    }

    // -----------------------------------------------------------------------
    // Contre une vraie base
    // -----------------------------------------------------------------------

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; company health is a SQL question");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B}",
                a.as_uuid(),
                b.as_uuid()
            ))
            .expect("keyring");

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                db,
                a,
                b,
            })
        }

        async fn health(&self, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri("/v1/health/company")
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::empty())
                .expect("request");
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b] {
                let mut tx = self.db.admin_tx_bypassing_rls().await.expect("admin tx");
                sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("delete tenant");
                tx.commit().await.expect("commit");
            }
        }
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'health-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    /// Par le même chemin que la boucle : l'écriture est cross-tenant depuis
    /// `admin_tx_bypassing_rls`, la lecture ne l'est pas.
    async fn trace(
        db: &Db,
        tenant: TenantId,
        employee_id: EmployeeId,
        at: DateTime<Utc>,
        code: &str,
        detail: Option<&str>,
    ) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        agentos_store::initiative::record_turn_trace(
            &mut tx,
            tenant,
            employee_id,
            at,
            code,
            detail,
        )
        .await
        .expect("trace");
        tx.commit().await.expect("commit");
    }

    /// Le défaut du 2026-09-10, bout en bout : la route rend `stopped`, la
    /// phrase qui répare, et la date du dernier travail effectué — que la
    /// fenêtre du jour, elle, ne contient pas.
    #[tokio::test]
    async fn la_route_rend_larret_dorizn_avec_sa_cause_et_son_dernier_succes() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let seat = employee(&h.db, h.a, "orizn-ventes").await;
        let at = Utc::now();
        trace(&h.db, h.a, seat, at - Duration::hours(30), TURN, None).await;
        for minutes in [5_i64, 65, 125] {
            trace(
                &h.db,
                h.a,
                seat,
                at - Duration::minutes(minutes),
                "error",
                Some("this tenant's model connection carries a Claude subscription token"),
            )
            .await;
        }

        let (status, body) = h.health(SECRET_A).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verdict"], "stopped", "{body}");
        assert_eq!(body["turns_failed_today"], 3);
        assert_eq!(body["turns_attempted_today"], 3);
        assert_eq!(body["last_failure_code"], "error");
        assert!(
            body["last_failure_detail"]
                .as_str()
                .expect("un détail")
                .contains("subscription token"),
            "la cause est publiée telle que le produit l'écrit : {body}"
        );
        assert!(
            body["last_success_at"].is_string(),
            "« dernier travail effectué » est la phrase qui manquait : {body}"
        );
        // Aucune connexion au modèle sur ce locataire de test, et c'est dit
        // plutôt qu'omis.
        assert!(body["model"].is_null());
        h.teardown().await;
    }

    /// Une société qui n'a jamais battu répond 200 et `working` : pas de
    /// bannière le premier matin.
    #[tokio::test]
    async fn une_societe_au_repos_reste_working() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let (status, body) = h.health(SECRET_B).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verdict"], "working", "{body}");
        assert_eq!(body["turns_attempted_today"], 0);
        assert!(body["last_success_at"].is_null());
        assert!(body["last_failure_at"].is_null());
        assert_eq!(body["dead_lettered_today"], 0);
        h.teardown().await;
    }

    /// RLS. Qu'une entreprise soit à l'arrêt depuis quatre jours est un fait
    /// commercial : un concurrent qui le lirait saurait quand appeler.
    #[tokio::test]
    async fn larret_dune_societe_est_invisible_a_lautre() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let seat = employee(&h.db, h.a, "a-ventes").await;
        trace(
            &h.db,
            h.a,
            seat,
            Utc::now() - Duration::minutes(5),
            "error",
            Some("la panne de A"),
        )
        .await;

        let (_, chez_a) = h.health(SECRET_A).await;
        assert_eq!(chez_a["turns_failed_today"], 1, "{chez_a}");

        let (status, chez_b) = h.health(SECRET_B).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            chez_b["turns_failed_today"], 0,
            "B ne doit pas voir la panne de A : {chez_b}"
        );
        assert!(chez_b["last_failure_detail"].is_null());
        assert_eq!(chez_b["verdict"], "working");
        h.teardown().await;
    }
}
