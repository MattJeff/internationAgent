//! Le domaine d'envoi est au locataire, vérifié chez le fournisseur avant
//! qu'un siège s'y assoie.
//!
//! # Ce qui manquait, mesuré le 2026-09-10
//!
//! Le domaine d'envoi était une variable par déploiement : `AGENT_EMAIL_DOMAIN`
//! → `EmailCredentials::domain` → `ResendEmailProvider::new(…, domain)`, et
//! `ensure_identity` réconciliait ce nom-là sans lire la fiche de l'employé.
//! Or chaque employé porte déjà **son** domaine (`employees.domain`, posé par
//! `POST /v1/org` et `POST /v1/employees`) et son adresse est `slug@domain`.
//! Rien ne vérifiait que ce domaine existe chez le fournisseur : Orizn a
//! tourné cinq jours sur `agent-orizn.com`, un domaine que personne ne
//! possède. Un deuxième client doit pouvoir poser **son** domaine depuis la
//! console, et ses sièges doivent attendre qu'il soit vérifié.
//!
//! # La forme
//!
//! Une ligne par locataire dans `tenant_domains` (0093) : le nom, l'id que le
//! fournisseur lui donne, son verdict (`pending | verified | failed`) et les
//! enregistrements DNS qu'il demande, recopiés tels quels. Quatre gestes :
//!
//! * [`register`] — trouve ou crée le domaine chez le fournisseur
//!   ([`EmailProvider::ensure_domain`], qui *trouve* d'abord : celui d'Orizn
//!   existe déjà) et écrit la ligne. Le même nom deux fois rend la même ligne
//!   sans rappeler le fournisseur ; un autre nom est
//!   [`Refusal::AnotherDomain`] — changer de domaine est une autre histoire,
//!   les adresses déjà imprimées dans des mails partis vivent sur l'ancien.
//! * [`verify`] — demande au fournisseur de regarder le DNS et relit ; quand
//!   il dit `verified`, **réveille les sièges** qui attendaient.
//! * [`require`] — le domaine d'un employé à créer doit être celui du
//!   locataire : un corps qui n'en nomme aucun embauche sur celui du
//!   locataire, un corps qui en nomme un autre est refusé, et un locataire
//!   sans ligne l'obtient au passage (le nom du corps, sinon
//!   `AGENT_EMAIL_DOMAIN`), ce qui fait un appel de moins pour la console.
//! * [`pose_dns`] — recopie les enregistrements dans la zone Cloudflare qui
//!   contient le domaine, avec un jeton utilisé une fois et gardé nulle part.
//!
//! # Le réveil, et pourquoi il est ici
//!
//! Un siège dont le domaine n'est pas vérifié est `pending_external` avec
//! l'id fournisseur du domaine pour `poll_ref` — voir
//! [`agentos_providers::email::DOMAIN_VERIFY_WAIT`] pour la cadence lente,
//! une relecture par heure et par siège. Le chemin rapide est [`verify`] :
//! au premier `verified`, les pas `email` du locataire en `pending_external`
//! ou `failed` repassent `pending`, et la boucle les reprend au tick suivant.
//! `PendingExternal → Pending` n'est pas dans la table de transitions de
//! `ResourceState` — elle protège `Ready`, où une ressource réelle serait
//! oubliée — mais un pas en attente externe n'a **aucune** ressource (« while
//! pending there is no resource yet »), donc rien n'est perdu à le remettre à
//! zéro, et c'est ce que le SQL fait, sous RLS.

use agentos_domain::action::Domain;
use agentos_providers::dns_cloudflare::{Cloudflare, Posed};
use agentos_providers::email::{DnsRecord, DomainStatus, EmailProvider};
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub use agentos_providers::dns_cloudflare::API_BASE as CLOUDFLARE_API;

/// La ligne du locataire, telle que la console la lit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub domain: String,
    pub provider: String,
    pub provider_domain_id: Option<String>,
    pub region: Option<String>,
    pub status: DomainStatus,
    pub records: Vec<DnsRecord>,
    pub created_at: DateTime<Utc>,
    pub checked_at: Option<DateTime<Utc>>,
    pub verified_at: Option<DateTime<Utc>>,
}

/// Pourquoi un geste sur le domaine n'a pas eu lieu.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// Pas un hôte public à deux étiquettes — `Domain::parse` dit lequel.
    #[error("domain: {0}")]
    BadDomain(String),
    /// Le locataire envoie déjà depuis un autre domaine.
    #[error("this tenant already sends from {current}")]
    AnotherDomain { current: String },
    /// Un autre locataire de ce déploiement envoie déjà depuis ce nom.
    #[error("another tenant already sends from this domain")]
    DomainTaken,
    /// Le locataire n'a pas encore de domaine.
    #[error("this tenant has no sending domain yet")]
    NoDomain,
    /// Le fournisseur (email ou DNS) a répondu autre chose qu'oui.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Trouve ou crée `name` chez le fournisseur et l'écrit comme domaine du
/// locataire. Idempotent sur le même nom ; 409 sur un autre.
pub async fn register(
    tx: &mut TenantTx<'_>,
    provider: &dyn EmailProvider,
    name: &str,
) -> Result<Row, Refusal> {
    let domain = Domain::parse(name).map_err(|err| Refusal::BadDomain(err.to_string()))?;
    if let Some(row) = current(tx).await? {
        return if row.domain == domain.as_str() {
            Ok(row)
        } else {
            Err(Refusal::AnotherDomain {
                current: row.domain,
            })
        };
    }

    let state = provider.ensure_domain(domain.as_str()).await?;
    let now = Utc::now();
    let verified_at = (state.status == DomainStatus::Verified).then_some(now);
    let inserted = sqlx::query(
        "INSERT INTO tenant_domains \
           (tenant_id, domain, provider, provider_domain_id, region, status, records, \
            created_at, checked_at, verified_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)",
    )
    .bind(tx.tenant_id().as_uuid())
    .bind(domain.as_str())
    .bind(state.provider)
    .bind(&state.provider_domain_id)
    .bind(&state.region)
    .bind(state.status.as_str())
    .bind(sqlx::types::Json(&state.records))
    .bind(now)
    .bind(verified_at)
    .execute(&mut ***tx)
    .await;
    match inserted {
        Ok(_) => {}
        // `tenant_domains_domain_key` : le nom est à quelqu'un d'autre.
        Err(err)
            if err
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            return Err(Refusal::DomainTaken);
        }
        Err(err) => return Err(Refusal::Store(err.into())),
    }
    current(tx).await?.ok_or(Refusal::NoDomain)
}

/// La ligne telle que Postgres la rend, avant que `status` et `records`
/// soient relus dans leurs types.
#[derive(sqlx::FromRow)]
struct Stored {
    domain: String,
    provider: String,
    provider_domain_id: Option<String>,
    region: Option<String>,
    status: String,
    records: Value,
    created_at: DateTime<Utc>,
    checked_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
}

/// Le domaine du locataire, s'il en a un.
pub async fn current(tx: &mut TenantTx<'_>) -> Result<Option<Row>, StoreError> {
    let row: Option<Stored> = sqlx::query_as(
        "SELECT domain, provider, provider_domain_id, region, status, records, \
                created_at, checked_at, verified_at \
           FROM tenant_domains",
    )
    .fetch_optional(&mut ***tx)
    .await?;
    Ok(row.map(|stored| Row {
        domain: stored.domain,
        provider: stored.provider,
        provider_domain_id: stored.provider_domain_id,
        region: stored.region,
        status: match stored.status.as_str() {
            "verified" => DomainStatus::Verified,
            "failed" => DomainStatus::Failed,
            _ => DomainStatus::Pending,
        },
        // La colonne est ce que ce module y a écrit ; une forme qu'il ne
        // relit pas est une liste vide, pas une lecture qui échoue.
        records: serde_json::from_value(stored.records).unwrap_or_default(),
        created_at: stored.created_at,
        checked_at: stored.checked_at,
        verified_at: stored.verified_at,
    }))
}

/// Demande au fournisseur de regarder le DNS, relit, écrit — et réveille les
/// sièges qui attendaient si le verdict est `verified`.
pub async fn verify(tx: &mut TenantTx<'_>, provider: &dyn EmailProvider) -> Result<Row, Refusal> {
    let row = current(tx).await?.ok_or(Refusal::NoDomain)?;
    let id = row.provider_domain_id.as_deref().ok_or(Refusal::NoDomain)?;
    let state = provider.verify_domain(id).await?;
    let now = Utc::now();
    sqlx::query(
        "UPDATE tenant_domains \
            SET status = $1, records = $2, region = coalesce($3, region), checked_at = $4, \
                verified_at = coalesce(verified_at, $5)",
    )
    .bind(state.status.as_str())
    .bind(sqlx::types::Json(&state.records))
    .bind(&state.region)
    .bind(now)
    .bind((state.status == DomainStatus::Verified).then_some(now))
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    if state.status == DomainStatus::Verified {
        wake_seats(tx).await?;
    }
    current(tx).await?.ok_or(Refusal::NoDomain)
}

/// Le domaine d'un employé à créer est celui du locataire.
///
/// `requested` est ce que le corps a nommé, s'il a nommé quelque chose ;
/// `default` est `AGENT_EMAIL_DOMAIN`. Un locataire qui a déjà sa ligne
/// embauche dessus quand le corps se tait, et se voit refuser tout autre
/// nom ; un locataire sans ligne est enregistré sous le nom demandé, sinon
/// sous le défaut — et `register` fait le reste, y compris la 409.
pub async fn require(
    tx: &mut TenantTx<'_>,
    provider: &dyn EmailProvider,
    requested: Option<&str>,
    default: &str,
) -> Result<Row, Refusal> {
    match (current(tx).await?, requested) {
        (Some(row), None) => Ok(row),
        (Some(_), Some(name)) | (None, Some(name)) => register(tx, provider, name).await,
        (None, None) => register(tx, provider, default).await,
    }
}

/// Pose les enregistrements du domaine dans la zone Cloudflare qui le
/// contient. Le jeton vit le temps de l'appel.
pub async fn pose_dns(
    tx: &mut TenantTx<'_>,
    token: Secret,
    cloudflare_api: &str,
) -> Result<Posed, Refusal> {
    let row = current(tx).await?.ok_or(Refusal::NoDomain)?;
    let mut records = row.records.clone();
    // Le MX de réception n'est pas dans `records` tant que la réception n'est
    // pas activée côté fournisseur ; on le dérive de la région plutôt que
    // d'attendre, sauf si le fournisseur a fini par le donner.
    let has_inbound_mx = records.iter().any(|r| {
        r.kind.eq_ignore_ascii_case("MX")
            && (matches!(r.name.trim(), "" | "@") || r.name == row.domain)
    });
    if let Some(region) = row.region.as_deref().filter(|_| !has_inbound_mx) {
        records.push(agentos_providers::email_resend::inbound_mx(region));
    }
    let posed = Cloudflare::new(token)
        .with_base_url(cloudflare_api)
        .pose(&row.domain, &records)
        .await?;
    Ok(posed)
}

/// Les pas `email` du locataire qui attendaient le domaine repartent de zéro.
/// Voir le module : un pas en attente externe n'a aucune ressource, donc rien
/// n'est perdu ; `attempt_count` aussi, parce que les tentatives dépensées
/// l'ont été sur un domaine qui n'était pas prêt, pas sur le fournisseur.
async fn wake_seats(tx: &mut TenantTx<'_>) -> Result<u64, StoreError> {
    let woken = sqlx::query(
        "UPDATE employee_resources \
            SET state = 'pending', poll_ref = NULL, expected_by = NULL, \
                attempt_count = 0, last_error = NULL, updated_at = now() \
          WHERE step = 'email' AND state IN ('pending_external', 'failed')",
    )
    .execute(&mut ***tx)
    .await?
    .rows_affected();
    if woken > 0 {
        tracing::info!(
            tenant = %tx.tenant_id().as_uuid(),
            seats = woken,
            "sending domain verified; the seats that waited on it are pending again"
        );
    }
    Ok(woken)
}

// ---------------------------------------------------------------------------
// Tests — with a database: every claim above is a row or an RLS boundary.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_providers::email::MockEmailProvider;
    use agentos_store::db::Db;
    use uuid::Uuid;

    use super::*;

    struct Fixture {
        db: Db,
        a: TenantId,
        b: TenantId,
    }

    async fn fixture() -> Option<Fixture> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; a sending domain is a row");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let a = tenant(&db).await;
        let b = tenant(&db).await;
        Some(Fixture { db, a, b })
    }

    async fn tenant(db: &Db) -> TenantId {
        let id = TenantId::new_v7(Utc::now());
        let mut admin = db.admin_tx_bypassing_rls().await.expect("admin");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'domain test')")
            .bind(id.as_uuid())
            .bind(format!("dom-{}", id.as_uuid().simple()))
            .execute(&mut *admin)
            .await
            .expect("tenant");
        admin.commit().await.expect("commit");
        id
    }

    /// Un nom unique par test : `tenant_domains.domain` est unique dans
    /// toute la base, et les tests d'un même binaire partagent la base.
    fn unique(label: &str) -> String {
        format!("{label}-{}.example.com", Uuid::now_v7().simple())
    }

    #[tokio::test]
    async fn register_then_current_reads_the_row_back_and_a_second_register_is_the_same_row() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let name = unique("agents");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");

        // Mixed case in, lower case stored: `Domain::parse` normalises.
        let row = register(&mut tx, &mock, &name.to_uppercase())
            .await
            .expect("register");
        assert_eq!(row.domain, name);
        assert_eq!(row.provider, MockEmailProvider::PROVIDER);
        assert_eq!(
            row.status,
            DomainStatus::Verified,
            "the mock verifies on sight"
        );
        assert!(row.verified_at.is_some());
        assert_eq!(row.records.len(), 1, "the provider's records, as they came");
        assert_eq!(row.records[0].kind, "TXT");

        assert_eq!(current(&mut tx).await.expect("current"), Some(row.clone()));
        let again = register(&mut tx, &mock, &name).await.expect("again");
        assert_eq!(again, row);
        assert_eq!(mock.domain_count(), 1, "the provider was asked once");
        tx.commit().await.expect("commit");
    }

    #[tokio::test]
    async fn another_domain_is_refused_and_so_is_a_bad_one_and_another_tenants() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let name = unique("first");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        register(&mut tx, &mock, &name).await.expect("register");

        let other = unique("second");
        match register(&mut tx, &mock, &other).await {
            Err(Refusal::AnotherDomain { current }) => assert_eq!(current, name),
            other => panic!("changing domain is another story: {other:?}"),
        }
        assert!(matches!(
            register(&mut tx, &mock, "localhost").await,
            Err(Refusal::BadDomain(_))
        ));
        tx.commit().await.expect("commit");

        // Tenant B: sees nothing of A (RLS), and cannot take A's name.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        assert_eq!(current(&mut tx).await.expect("current"), None);
        assert!(matches!(
            register(&mut tx, &mock, &name).await,
            Err(Refusal::DomainTaken)
        ));
    }

    #[tokio::test]
    async fn verify_moves_pending_to_verified_when_the_provider_says_so_and_wakes_the_seats() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        mock.hold_domain_pending();
        let name = unique("slow");

        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        let row = register(&mut tx, &mock, &name).await.expect("register");
        assert_eq!(row.status, DomainStatus::Pending);
        assert_eq!(row.verified_at, None);
        // Still pending: DNS is not there. `checked_at` moved, nothing else.
        let checked = verify(&mut tx, &mock).await.expect("verify");
        assert_eq!(checked.status, DomainStatus::Pending);
        assert!(checked.checked_at.is_some());
        assert_eq!(checked.verified_at, None);

        // A seat waiting on this domain, and one that failed on it.
        let waiting = seat(&mut tx, f.a, "pending_external").await;
        let failed = seat(&mut tx, f.a, "failed").await;

        mock.release_domains();
        let done = verify(&mut tx, &mock).await.expect("verify");
        assert_eq!(done.status, DomainStatus::Verified);
        assert!(done.verified_at.is_some());
        assert_eq!(
            state_of(&mut tx, waiting).await,
            "pending",
            "the wait is over"
        );
        assert_eq!(
            state_of(&mut tx, failed).await,
            "pending",
            "so is the failure"
        );
        tx.commit().await.expect("commit");

        // Tenant B has no domain to verify.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        assert!(matches!(
            verify(&mut tx, &mock).await,
            Err(Refusal::NoDomain)
        ));
    }

    #[tokio::test]
    async fn require_registers_a_tenant_with_no_domain_and_refuses_another() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let name = unique("req");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");

        // Nothing named, no row: the deployment's default is registered.
        let row = require(&mut tx, &mock, None, &name)
            .await
            .expect("registered on the way");
        assert_eq!(row.domain, name);
        // Nothing named, a row: the row, and the default is not consulted.
        let same = require(&mut tx, &mock, None, "other.example.com")
            .await
            .expect("the tenant's own");
        assert_eq!(same, row);
        require(&mut tx, &mock, Some(&name), "x.example.com")
            .await
            .expect("the same domain is fine");
        assert!(matches!(
            require(&mut tx, &mock, Some(&unique("else")), &name).await,
            Err(Refusal::AnotherDomain { .. })
        ));
        assert_eq!(mock.domain_count(), 1);
    }

    // -- helpers ------------------------------------------------------------

    /// An employee whose `email` step is in `state`, on the tenant's domain.
    async fn seat(tx: &mut TenantTx<'_>, tenant: TenantId, state: &str) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, 'active')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(format!("s{}", id.simple()))
        .execute(&mut ***tx)
        .await
        .expect("employee");
        sqlx::query(
            "INSERT INTO employee_resources \
               (employee_id, step, tenant_id, state, poll_ref, expected_by, attempt_count, last_error) \
             VALUES ($1, 'email', $2, $3, 'dom_0001', now() + interval '1 hour', 3, \
                     'domain_not_registered: x')",
        )
        .bind(id)
        .bind(tenant.as_uuid())
        .bind(state)
        .execute(&mut ***tx)
        .await
        .expect("resource");
        id
    }

    async fn state_of(tx: &mut TenantTx<'_>, employee: Uuid) -> String {
        let (state, attempts, poll_ref): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT state, attempt_count, poll_ref FROM employee_resources \
              WHERE employee_id = $1 AND step = 'email'",
        )
        .bind(employee)
        .fetch_one(&mut ***tx)
        .await
        .expect("row");
        if state == "pending" {
            assert_eq!((attempts, poll_ref), (0, None), "a woken seat starts over");
        }
        state
    }
}
