//! La boucle des annuaires : toutes les [`IDLE`], chaque source dont
//! `read_on` est avant aujourd'hui UTC et dont l'heure est passée est lue une
//! fois (`agentos_app::discovery`, « Le flux d'annuaires »).
//!
//! # Ce qu'elle fait, et par où
//!
//! Le même chemin qu'un opérateur qui appelle `prospects_discover` : un
//! jeton `BrowserRead` que la Gate émet **pour le siège de la source**, puis
//! `Effects::discover_prospects_in`, qui lit le plafond
//! `max_new_contacts_per_day` dans les quatre couches du siège et le dépense.
//! Rien ici ne lit un budget ni n'en tient un second — quand la page dit que
//! le plafond est atteint, la source le note et attend demain. Avant la page,
//! `/robots.txt` du même hôte, sous un jeton de même forme : un hôte qui nous
//! refuse n'est pas lu, et la source le note aussi.
//!
//! # Comment elle traverse les locataires
//!
//! Le geste de `loops::sequence` : une lecture sous `admin_tx_bypassing_rls`
//! pour savoir quelles sources sont dues et à qui, dans l'ordre de
//! `created_at` — la première posée passe la première, et c'est elle qui
//! mange le budget —, puis **une `TenantTx` par source** pour réclamer
//! (`discovery::claim` pose `read_on` : deux réplicas qui lisent la même
//! source n'en lisent qu'une), la lecture hors de toute transaction (une page
//! prend des secondes ; un verrou tenu pendant ce temps est un verrou sur
//! rien), puis une seconde `TenantTx` pour écrire l'issue. Une source
//! réclamée dont le processus meurt avant l'issue est une source lue pour rien
//! ce jour-là et relue demain : le prix d'un crash, pas d'un bug.
//!
//! [`not_stopped!`](agentos_store::not_stopped) borne la lecture : une
//! entreprise arrêtée ne lit pas ses annuaires.

use std::sync::Arc;
use std::time::Duration;

use agentos_app::discovery::{self, Outcome, ROBOTS_REFUSED, Source};
use agentos_app::effects::{BrowserRead, Effects, Ports};
use agentos_app::gate::{PolicyGate, Principal};
use agentos_app::turn::page_at;
use agentos_domain::ids::{EmployeeId, TenantId};
use agentos_store::db::{Db, StoreError};
use chrono::{DateTime, Timelike as _, Utc};
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Entre deux passes. Trente secondes, comme `loops::sequence` : une source
/// se lit une fois par jour, et la latence après son heure n'importe pas.
const IDLE: Duration = Duration::from_secs(30);

pub async fn run(db: Db, ports: Arc<Ports>, cancel: CancellationToken) {
    tracing::info!("discovery loop started");
    loop {
        if let Err(err) = tick(&db, &ports, Utc::now()).await {
            tracing::error!(error = %err, "discovery tick failed");
        }
        if cancel.is_cancelled() {
            break;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDLE) => {}
        }
    }
    tracing::info!("discovery loop stopped");
}

/// Une passe : chaque source due, réclamée, lue, et son issue écrite. Rend
/// combien ont été lues.
pub async fn tick(db: &Db, ports: &Arc<Ports>, now: DateTime<Utc>) -> Result<usize, StoreError> {
    // The same three conditions `discovery::claim` claims on, read once for
    // every tenant so that a source before its hour costs no tenant transaction.
    let mut admin = db.admin_tx_bypassing_rls().await?;
    let due = sqlx::query(concat!(
        "SELECT s.id, s.tenant_id FROM discovery_sources s \
          WHERE (s.read_on IS NULL OR s.read_on < $1::date) AND s.hour <= $2 \
            AND s.last_outcome IS DISTINCT FROM $3 AND ",
        agentos_store::not_stopped!("s.tenant_id"),
        " ORDER BY s.created_at, s.id",
    ))
    .bind(now.date_naive())
    .bind(i16::try_from(now.hour()).unwrap_or(i16::MAX))
    .bind(discovery::STALLED)
    .fetch_all(&mut *admin)
    .await?;
    admin.commit().await?;

    let mut read = 0;
    for row in &due {
        let id: Uuid = row.get("id");
        let tenant = TenantId::from_uuid(row.get("tenant_id"));
        let mut tx = db.tenant_tx(tenant).await?;
        let claimed = discovery::claim(&mut tx, id, now).await?;
        tx.commit().await?;
        let Some(source) = claimed else {
            continue;
        };

        let outcome = read_source(db, ports, tenant, &source).await;
        let mut tx = db.tenant_tx(tenant).await?;
        discovery::record(&mut tx, id, &outcome).await?;
        tx.commit().await?;
        read += 1;
        match &outcome {
            Outcome::Read { added, .. } => {
                tracing::info!(source = %id, tenant = %tenant, host = %source.host, added, "annuaire read");
            }
            Outcome::Failed(why) => {
                tracing::warn!(source = %id, tenant = %tenant, host = %source.host, why, "annuaire not read");
            }
        }
    }
    Ok(read)
}

/// Lire une source : la Gate pour le siège, `robots.txt`, puis la page. Chaque
/// refus est une phrase à nous — un code de la Gate ou de l'effet, jamais un
/// mot du site.
async fn read_source(db: &Db, ports: &Arc<Ports>, tenant: TenantId, source: &Source) -> Outcome {
    let (url, domain) = match page_at(&source.url) {
        Ok(at) => at,
        // `discovery::add` parsed it once; a row that no longer parses is a
        // row somebody edited by hand.
        Err(_) => return Outcome::Failed("bad url".to_owned()),
    };
    let principal = Principal::employee(tenant, EmployeeId::from_uuid(source.employee_id));
    let gate = PolicyGate::new(db.clone());
    let effects = Effects::new(db.clone(), ports.clone(), principal.clone());
    let reading = || BrowserRead {
        domain: domain.clone(),
    };

    let token = match gate.authorize(&principal, reading()).await {
        Ok(token) => token,
        Err(denied) => return Outcome::Failed(format!("denied: {}", denied.code())),
    };
    match discovery::robots_permits(&effects, token, &url).await {
        Ok(true) => {}
        Ok(false) => return Outcome::Failed(ROBOTS_REFUSED.to_owned()),
        Err(err) => return Outcome::Failed(format!("robots unreachable: {}", err.code())),
    }

    let token = match gate.authorize(&principal, reading()).await {
        Ok(token) => token,
        Err(denied) => return Outcome::Failed(format!("denied: {}", denied.code())),
    };
    match effects
        .discover_prospects_in(token, &url, &source.segment, source.country.as_deref())
        .await
    {
        Ok(report) => Outcome::of(&report),
        Err(err) => Outcome::Failed(format!("unreadable: {}", err.code())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentos_app::discovery::{DEFAULT_HOUR, NewSource, STALLED};
    use agentos_app::mocks::{MockBrowser, MockMailDomains};
    use agentos_domain::message::Channel;
    use agentos_domain::policy::PolicyLimits;
    use agentos_store::policy;
    use chrono::{NaiveDate, SubsecRound, TimeDelta};

    use super::*;

    /// A page of six addresses, and a robots file that lets us read it. The
    /// mock browser answers every `Text` read with the next entry, so the
    /// first read (robots) gets the first and the page reads get the rest.
    const ROBOTS_OPEN: &str = "User-agent: *\nDisallow: /private\n";
    const ROBOTS_SHUT: &str = "User-agent: *\nDisallow: /membres\n";
    const DIRECTORY: &str = "Membres 2026\n\
         office@reisehaus.example\n\
         contact@bertrand.example\n\
         info@nordictravel.example\n\
         bonjour@alpes-mobilite.example\n\
         info@adriatica.example\n\
         hola@meridiano.example\n";

    struct Fixture {
        db: Db,
        ports: Arc<Ports>,
        browser: Arc<MockBrowser>,
        tenant: TenantId,
        employee: EmployeeId,
    }

    async fn fixture(suffix: &str) -> Option<Fixture> {
        let db = crate::loops::private_db(suffix).await?;
        let now = Utc::now().trunc_subsecs(6);
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'discovery loop')")
            .bind(tenant.as_uuid())
            .bind(format!("disc-loop-{}", tenant.as_uuid().simple()))
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
        // The browser row `Effects::browser_session` rebuilds a session from.
        sqlx::query(
            "INSERT INTO employee_resources \
                 (employee_id, step, tenant_id, state, provider, external_id) \
             VALUES ($1, 'browser', $2, 'ready', 'mock-browser', $3)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!("ctx-{}", employee.as_uuid().simple()))
        .execute(&mut *admin)
        .await
        .expect("browser resource");
        admin.commit().await.expect("commit");

        let browser = Arc::new(MockBrowser::new());
        let ports = Arc::new(Ports {
            browser: browser.clone(),
            mail_domains: Arc::new(MockMailDomains::everywhere()),
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

    async fn policy(f: &Fixture, web: bool, contacts_per_day: u32) {
        policy::install(
            &f.db,
            f.tenant,
            policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels: if web {
                    BTreeSet::from([Channel::Web])
                } else {
                    BTreeSet::from([Channel::Email])
                },
                max_new_contacts_per_day: contacts_per_day,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install the policy");
    }

    async fn add(f: &Fixture, url: &str, hour: u8) -> Uuid {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let source = discovery::add(
            &mut tx,
            &NewSource {
                url,
                segment: "ota",
                country: Some("FR"),
                employee_id: f.employee,
                hour,
            },
        )
        .await
        .expect("add");
        tx.commit().await.expect("commit");
        source.id
    }

    async fn sources(f: &Fixture) -> Vec<Source> {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let all = discovery::list(&mut tx).await.expect("list");
        tx.rollback().await.expect("rollback");
        all
    }

    async fn contacts(f: &Fixture) -> (i64, Vec<String>) {
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM contacts")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        let countries: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT country FROM accounts ORDER BY country")
                .fetch_all(&mut **tx)
                .await
                .expect("countries");
        tx.rollback().await.expect("rollback");
        (n, countries)
    }

    fn at(day: NaiveDate, h: u32, m: u32) -> DateTime<Utc> {
        day.and_hms_opt(h, m, 0).expect("time").and_utc()
    }

    /// **A source is read on the first tick at or after its hour, once a day,
    /// with the country the human posed — and the daily budget is
    /// `discover`'s own: the first-posed source spends it, the second waits.**
    #[tokio::test]
    async fn the_loop_reads_each_source_once_a_day_under_discover_s_budget() {
        let Some(f) = fixture("discovery").await else {
            return;
        };
        policy(&f, true, 4).await;
        f.browser.set_text("body", &[ROBOTS_OPEN, DIRECTORY]);
        let today = Utc::now().date_naive();
        let first = add(&f, "https://annuaire.example/membres", DEFAULT_HOUR).await;
        let second = add(&f, "https://federation.example/adherents", DEFAULT_HOUR).await;

        assert_eq!(
            tick(&f.db, &f.ports, at(today, 6, 59)).await.expect("tick"),
            0
        );
        assert!(f.browser.log().is_empty(), "before the hour, no page");

        assert_eq!(
            tick(&f.db, &f.ports, at(today, 7, 0)).await.expect("tick"),
            2
        );
        let all = sources(&f).await;
        let (a, b) = (&all[0], &all[1]);
        assert_eq!((a.id, b.id), (first, second), "created_at order");
        assert_eq!(a.read_on, Some(today));
        assert_eq!((a.pages_read, a.contacts_added, a.failures), (1, 4, 0));
        assert_eq!(a.last_outcome.as_deref(), Some("4 added, budget reached"));
        assert_eq!(
            (b.pages_read, b.contacts_added),
            (1, 0),
            "the budget was spent by the first"
        );
        assert_eq!(b.last_outcome.as_deref(), Some("0 added, budget reached"));
        assert_eq!(
            contacts(&f).await,
            (4, vec!["FR".to_owned()]),
            "the posed country, not ZZ"
        );

        assert_eq!(
            tick(&f.db, &f.ports, at(today, 7, 1)).await.expect("tick"),
            0,
            "once a day"
        );
        assert_eq!(sources(&f).await[0].pages_read, 1);

        // Tomorrow: the first source finds its last two. The budget is
        // `discover`'s and it is counted on the wall clock (`new_contacts_since`
        // over `created_at`), which this test's `now` does not move — so the
        // four of "today" are still spent, and the day is widened to six
        // instead. The mock serves one page whatever the URL, so the second
        // source's six are the first's six, all on file by then — and it
        // still reads `budget reached`, because `discover` stops at the first
        // address once the day is spent rather than look whether it is new
        // (the conservative direction, argued there).
        policy(&f, true, 6).await;
        let tomorrow = today + TimeDelta::days(1);
        assert_eq!(
            tick(&f.db, &f.ports, at(tomorrow, 7, 0))
                .await
                .expect("tick"),
            2
        );
        let all = sources(&f).await;
        assert_eq!(all[0].contacts_added, 6, "{:?}", all[0].last_outcome);
        assert_eq!(all[0].last_outcome.as_deref(), Some("2 added"));
        assert_eq!(
            all[1].last_outcome.as_deref(),
            Some("0 added, budget reached")
        );
        assert_eq!(all[0].read_on, Some(tomorrow));
        assert_eq!(contacts(&f).await.0, 6);
    }

    /// **A host whose `robots.txt` refuses us is never read, and three such
    /// mornings stall the source; reposing it starts over.**
    #[tokio::test]
    async fn a_robots_refusal_is_a_failure_and_three_of_them_stall_the_source() {
        let Some(f) = fixture("discovery_stall").await else {
            return;
        };
        policy(&f, true, 50).await;
        f.browser.set_text("body", &[ROBOTS_SHUT]);
        let today = Utc::now().date_naive();
        let id = add(&f, "https://annuaire.example/membres", 9).await;

        for day in 0..3 {
            let when = at(today + TimeDelta::days(day), 9, 0);
            assert_eq!(
                tick(&f.db, &f.ports, when).await.expect("tick"),
                1,
                "day {day}"
            );
        }
        let text_reads = f
            .browser
            .log()
            .iter()
            .filter(|l| l.contains(" text "))
            .count();
        assert_eq!(
            text_reads,
            3,
            "robots.txt only, never the page: {:?}",
            f.browser.log()
        );
        assert_eq!(contacts(&f).await.0, 0);
        let stalled = &sources(&f).await[0];
        assert_eq!(stalled.last_outcome.as_deref(), Some(STALLED));
        assert_eq!((stalled.failures, stalled.pages_read), (3, 0));

        assert_eq!(
            tick(&f.db, &f.ports, at(today + TimeDelta::days(3), 9, 0))
                .await
                .expect("tick"),
            0,
            "stalled: not read again"
        );
        assert_eq!(
            sources(&f).await[0].read_on,
            Some(today + TimeDelta::days(2))
        );

        // Reposed by a human, with the site now open: it reads.
        let mut tx = f.db.tenant_tx(f.tenant).await.expect("tx");
        discovery::remove(&mut tx, id).await.expect("remove");
        tx.commit().await.expect("commit");
        f.browser.set_text("body", &[ROBOTS_OPEN, DIRECTORY]);
        add(&f, "https://annuaire.example/membres", 9).await;
        assert_eq!(
            tick(&f.db, &f.ports, at(today + TimeDelta::days(3), 9, 0))
                .await
                .expect("tick"),
            1
        );
        let fresh = &sources(&f).await[0];
        assert_eq!(fresh.last_outcome.as_deref(), Some("6 added"));
        assert_eq!((fresh.failures, fresh.pages_read), (0, 1));

        // And a seat the Gate refuses is a failure of the same kind, with the
        // Gate's own code, before robots.txt is even asked.
        policy(&f, false, 50).await;
        let before = f.browser.log().len();
        tick(&f.db, &f.ports, at(today + TimeDelta::days(4), 9, 0))
            .await
            .expect("tick");
        assert_eq!(f.browser.log().len(), before, "nothing asked of the site");
        assert_eq!(
            sources(&f).await[0].last_outcome.as_deref(),
            Some("denied: channel_not_allowed")
        );
    }
}
