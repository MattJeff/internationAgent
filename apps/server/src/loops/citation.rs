//! La boucle de citation : toutes les [`IDLE`], chaque locataire qui a un
//! dépôt avec un `site` et dont la dernière mesure date de
//! [`content::MEASURE_EVERY`] jours ou plus voit **toutes ses questions**
//! mesurées, une fois (`agentos_app::content`, « La boucle se ferme, sauf le
//! clic »).
//!
//! # Ce qu'elle fait, et par où
//!
//! Le même chemin qu'un opérateur qui appelle `content_questions_measure` :
//! un jeton `BrowserRead` que la Gate émet **pour le siège du dépôt**, puis
//! [`content::measure`] sur le seul moteur lisible, puis
//! [`content::citations::record`]. Le résultat est ce que
//! `content_citations_list` rend ; rien ici n'a de table à lui.
//!
//! # Comment elle traverse les locataires
//!
//! Le geste de `loops::discovery` : une lecture sous `admin_tx_bypassing_rls`
//! pour savoir quels dépôts sont dus — un par locataire, le plus ancien qui
//! porte un `site` —, puis **une `TenantTx` par dépôt** pour réclamer
//! ([`content::repos::claim_measure`] pose `measured_on` : deux réplicas n'en
//! mesurent qu'un), les lectures hors de toute transaction, puis une
//! `TenantTx` par mesure pour l'écrire. Une réclamation dont le processus
//! meurt avant l'écriture est une semaine sans point : le prix d'un crash, pas
//! d'un bug.
//!
//! [`not_stopped!`](agentos_store::not_stopped) borne la lecture : une
//! entreprise arrêtée ne mesure pas.

use std::sync::Arc;
use std::time::Duration;

use agentos_app::content::{self, Engine};
use agentos_app::effects::{Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal};
use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Entre deux passes. Trente secondes, comme `loops::discovery` : une mesure
/// se fait une fois par semaine, et la latence après l'échéance n'importe pas.
const IDLE: Duration = Duration::from_secs(30);

pub async fn run(db: Db, ports: Arc<Ports>, cancel: CancellationToken) {
    tracing::info!("citation loop started");
    loop {
        if let Err(err) = tick(&db, &ports, Utc::now()).await {
            tracing::error!(error = %err, "citation tick failed");
        }
        if cancel.is_cancelled() {
            break;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }
    tracing::info!("citation loop stopped");
}

/// Une passe : chaque locataire dû, réclamé sur un dépôt, et chacune de ses
/// questions mesurée. Rend combien de mesures ont été écrites.
pub async fn tick(db: &Db, ports: &Arc<Ports>, now: DateTime<Utc>) -> Result<usize, StoreError> {
    // Un dépôt par locataire — le plus ancien qui porte un `site` — et seulement
    // si aucun dépôt de ce locataire n'a été mesuré cette semaine. Relu sous le
    // locataire par `claim_measure`, qui est la réclamation.
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let due = sqlx::query(concat!(
        "SELECT DISTINCT ON (r.tenant_id) r.tenant_id, r.employee_id \
           FROM content_repos r \
          WHERE r.site IS NOT NULL \
            AND NOT EXISTS (SELECT 1 FROM content_repos m \
                             WHERE m.tenant_id = r.tenant_id AND m.site IS NOT NULL \
                               AND m.measured_on > $1::date - $2::int) \
            AND ",
        agentos_store::not_stopped!("r.tenant_id", "$3::timestamptz"),
        " ORDER BY r.tenant_id, r.created_at, r.employee_id",
    ))
    .bind(now.date_naive())
    .bind(content::MEASURE_EVERY)
    .bind(now)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;

    let mut measured = 0;
    for row in &due {
        let tenant = TenantId::from_uuid(row.get("tenant_id"));
        let employee: Uuid = row.get("employee_id");
        let mut tx = db.tenant_tx(tenant).await?;
        let claimed = content::repos::claim_measure(&mut tx, employee, now).await?;
        let ours = content::our_domains(&mut tx).await?;
        let questions = content::questions::list(&mut tx).await?;
        tx.commit().await?;
        if claimed.is_none() {
            continue;
        }

        let principal = Principal::employee(tenant, EmployeeId::from_uuid(employee));
        let gate = PolicyGate::new(db.clone());
        let effects = Effects::new(db.clone(), ports.clone(), principal);
        for question in &questions {
            let engine = Engine::DuckDuckGoLite;
            match content::measure(&effects, &gate, &ours, &question.question, engine).await {
                Ok(citation) => {
                    let mut tx = db.tenant_tx(tenant).await?;
                    content::citations::record(&mut tx, question.id, &citation).await?;
                    tx.commit().await?;
                    measured += 1;
                    tracing::info!(
                        tenant = %tenant,
                        question = %question.id,
                        engine = engine.as_str(),
                        cited = citation.cited,
                        rank = citation.rank,
                        "citation measured"
                    );
                }
                Err(err) => tracing::warn!(
                    tenant = %tenant,
                    question = %question.id,
                    code = err.code(),
                    "citation not measured"
                ),
            }
        }
    }
    // Et à chaque tour, pas une fois par semaine : les articles proposés dont
    // la pull request a été fusionnée et déployée se constatent seuls
    // (`content::observe_proposed`) — c'est ce qui déclenche le post.
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let sites = sqlx::query(concat!(
        "SELECT DISTINCT ON (r.tenant_id) r.tenant_id, r.employee_id, r.site \
           FROM content_repos r \
          WHERE r.site IS NOT NULL AND ",
        agentos_store::not_stopped!("r.tenant_id", "$1::timestamptz"),
        " ORDER BY r.tenant_id, r.created_at, r.employee_id",
    ))
    .bind(now)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;
    for row in &sites {
        let tenant = TenantId::from_uuid(row.get("tenant_id"));
        let employee: Uuid = row.get("employee_id");
        let site: String = row.get("site");
        let base = format!("https://{site}/");
        let principal = Principal::employee(tenant, EmployeeId::from_uuid(employee));
        let gate = PolicyGate::new(db.clone());
        let effects = Effects::new(db.clone(), ports.clone(), principal);
        match content::observe_proposed(db, &effects, &gate, &base).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(tenant = %tenant, observed = n, "articles observed online"),
            Err(err) => tracing::warn!(tenant = %tenant, error = %err, "articles not observed"),
        }
    }
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_app::content::{Source, citations, questions, repos};
    use agentos_app::mocks::MockBrowser;
    use agentos_domain::message::Channel;
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::policy;
    use chrono::TimeDelta;

    use super::*;

    /// Ce que `browser_http::visible_text` rend d'une page de résultats où
    /// nous sommes troisièmes — la forme que `content::read_results` lit.
    const RESULTS: &str = "1. Visa API by Travel Buddy\n\
                           Free tier included.\n\
                           travel-buddy.ai/api/\n\
                           2. Post-covid visa requirements API\n\
                           Real-time visa requirements.\n\
                           visadb.io/api\n\
                           3. Visa Requirements API | Orizn\n\
                           47,362 pairs across 199 passports.\n\
                           visa.orizn.app\n";

    struct Fixture {
        db: Db,
        ports: Arc<Ports>,
        browser: Arc<MockBrowser>,
        tenant: TenantId,
        employee: Uuid,
    }

    async fn fixture(suffix: &str) -> Option<Fixture> {
        let db = crate::loops::private_db(suffix).await?;
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = Uuid::now_v7();
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'citation loop')")
            .bind(tenant.as_uuid())
            .bind(format!("cit-loop-{}", tenant.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee)
        .bind(tenant.as_uuid())
        .execute(&mut *admin)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'mock-browser', $3)",
        )
        .bind(employee)
        .bind(tenant.as_uuid())
        .bind(format!("ctx-{}", employee.simple()))
        .execute(&mut *admin)
        .await
        .expect("browser resource");
        admin.commit().await.expect("commit");

        policy::install(
            &db,
            tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Web]),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");

        let browser = Arc::new(MockBrowser::new());
        browser.set_text("body", &[RESULTS]);
        let ports = Arc::new(Ports {
            browser: browser.clone(),
            ..agentos_app::mocks::ports()
        });
        Some(Fixture {
            db,
            ports,
            browser,
            tenant,
            employee,
        })
    }

    /// Un dépôt sur ce siège, avec ou sans `site`.
    async fn repo(f: &Fixture, site: Option<&str>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        sqlx::query(
            "INSERT INTO mcp_servers (tenant_id, server, url, reach, connector) \
             VALUES ($1, 'github', 'https://api.githubcopilot.com/mcp/', 'public', 'github') \
             ON CONFLICT DO NOTHING",
        )
        .bind(f.tenant.as_uuid())
        .execute(&mut **tx)
        .await
        .expect("binding");
        repos::set(
            &mut tx,
            f.employee,
            "github",
            "acme/site",
            "main",
            "content",
            site,
        )
        .await
        .expect("set")
        .expect("bound");
        tx.commit().await.expect("commit");
    }

    async fn question(f: &Fixture, text: &str) -> Uuid {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let q = questions::add(&mut tx, text, "en", Source::Founder, 1)
            .await
            .expect("add");
        tx.commit().await.expect("commit");
        q.id
    }

    async fn series(f: &Fixture, question: Uuid) -> Vec<citations::Measured> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let rows = citations::list(&mut tx, question, 366).await.expect("list");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// **Une fois par semaine, pas deux ; seulement avec un dépôt qui porte un
    /// `site` ; et le résultat est la série que `content_citations_list` rend.**
    #[tokio::test]
    async fn the_loop_measures_every_question_once_a_week_and_only_with_a_site() {
        let Some(f) = fixture("citation").await else {
            return;
        };
        let now = Utc::now();
        let q1 = question(&f, "how do I check visa requirements by API").await;
        let q2 = question(&f, "visa API with a free tier").await;

        // Un dépôt sans `site` : « nous » n'a pas de sens, rien n'est mesuré.
        repo(&f, None).await;
        assert_eq!(tick(&f.db, &f.ports, now).await.expect("tick"), 0);
        assert!(
            f.browser.log().is_empty(),
            "no site, no page: {:?}",
            f.browser.log()
        );

        // Avec un site : chaque question, une fois.
        repo(&f, Some("orizn.app")).await;
        assert_eq!(tick(&f.db, &f.ports, now).await.expect("tick"), 2);
        let first = series(&f, q1).await;
        assert_eq!(first.len(), 1);
        assert!(first[0].cited, "{first:?}");
        assert_eq!(first[0].rank, Some(3));
        assert_eq!(first[0].engine, "duckduckgo_lite");
        assert_eq!(series(&f, q2).await.len(), 1);

        // Le lendemain, et six jours plus tard : rien. Une semaine : encore une.
        for days in [1, 6] {
            assert_eq!(
                tick(&f.db, &f.ports, now + TimeDelta::days(days))
                    .await
                    .expect("tick"),
                0,
                "day {days}: once a week"
            );
        }
        assert_eq!(
            tick(&f.db, &f.ports, now + TimeDelta::days(7))
                .await
                .expect("tick"),
            2
        );
        assert_eq!(series(&f, q1).await.len(), 2);

        // Un siège que la Gate refuse : la semaine est réclamée quand même,
        // et rien n'est relu toutes les trente secondes.
        policy::install(
            &f.db,
            f.tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels: BTreeSet::from([Channel::Email]),
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("narrow the policy");
        let reads = f.browser.log().len();
        assert_eq!(
            tick(&f.db, &f.ports, now + TimeDelta::days(14))
                .await
                .expect("tick"),
            0
        );
        assert_eq!(
            tick(&f.db, &f.ports, now + TimeDelta::days(14))
                .await
                .expect("tick"),
            0,
            "a refused seat is not retried within the week"
        );
        assert_eq!(f.browser.log().len(), reads, "nothing asked of the engine");
        assert_eq!(series(&f, q1).await.len(), 2);
    }
}
