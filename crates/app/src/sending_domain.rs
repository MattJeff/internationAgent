//! Les domaines d'envoi sont au locataire — plusieurs, vérifiés chez le
//! fournisseur, chacun sous un plafond journalier — et l'expéditeur d'un mail
//! vers l'extérieur est choisi à l'envoi.
//!
//! # Ce qui manquait, mesuré le 2026-09-10
//!
//! Le domaine d'envoi était une variable par déploiement : `AGENT_EMAIL_DOMAIN`
//! → `EmailCredentials::domain` → `ResendEmailProvider::new(…, domain)`, et
//! `ensure_identity` réconciliait ce nom-là sans lire la fiche de l'employé.
//! Rien ne vérifiait que ce domaine existe chez le fournisseur : Orizn a
//! tourné cinq jours sur `agent-orizn.com`, un domaine que personne ne
//! possède. 0093 a fait du domaine une ligne du locataire, vérifiée avant
//! qu'un siège s'y assoie — **une** ligne. Le jour même du déploiement, Orizn
//! avait `agents.getorizn.com` vérifié et `agent.oriznapi.uk` vérifié chez
//! Resend et inutilisé : la prospection à volume tourne sur plusieurs
//! domaines, chacun sous un plafond, pour que la réputation d'aucun ne
//! s'effondre — ce que Smartlead et Lumail vendent sous « sending domains ».
//! 0094 ouvre la table à plusieurs lignes par locataire.
//!
//! # La forme
//!
//! Plusieurs lignes par locataire dans `tenant_domains` (0093, 0094) : le
//! nom, l'id que le fournisseur lui donne, son verdict (`pending | verified |
//! failed`), les enregistrements DNS qu'il demande, `is_primary` et
//! `daily_cap`. Une ligne est **la primaire** : celle dont les sièges lisent
//! le domaine à l'embauche, celle que `GET /v1/domain` rend. Les gestes :
//!
//! * [`register`] — trouve ou crée le domaine chez le fournisseur
//!   ([`EmailProvider::ensure_domain`], qui *trouve* d'abord : celui d'Orizn
//!   existe déjà) et **ajoute** la ligne ; la première d'un locataire est la
//!   primaire. Le même nom deux fois rend la même ligne sans rappeler le
//!   fournisseur.
//! * [`verify`] — demande au fournisseur de regarder le DNS et relit ; quand
//!   il dit `verified`, **réveille les sièges** qui attendaient.
//! * [`require`] — le domaine d'un employé à créer : n'importe lequel du
//!   locataire quand le corps en nomme un (ajouté au passage s'il n'y est
//!   pas), la primaire quand il se tait, et un locataire sans ligne obtient
//!   celle-ci (le nom du corps, sinon `AGENT_EMAIL_DOMAIN`).
//! * [`pose_dns`] — recopie les enregistrements dans la zone Cloudflare qui
//!   contient le domaine, avec un jeton utilisé une fois et gardé nulle part.
//! * [`set_cap`], [`remove`] — le plafond d'un domaine, et le retrait d'un
//!   domaine secondaire ; la primaire ne se retire pas (`PrimaryDomain`).
//! * [`pick_from`] — **l'expéditeur d'un mail vers l'extérieur**, voir
//!   ci-dessous.
//!
//! # L'expéditeur est choisi à l'envoi
//!
//! `Turn` rend `slug@domaine-primaire` dans `RenderedEmail::from` — c'est ce
//! que la fiche de l'employé dit, et le pas `email` de son siège lie ce
//! domaine-là. Pour un mail **vers l'extérieur** — le même embranchement que
//! la délivrabilité, [`crate::effects::Effects::send_email`] et lui seul ; un
//! mot à un collègue et une facture gardent l'adresse primaire —
//! `pick_from` remplace l'expéditeur :
//!
//! 1. **Collant.** Si cet employé a déjà écrit à ce destinataire (une ligne
//!    `messages` sortante dont `recipients` le contient — `follow_up::sent`
//!    l'écrit avec l'expéditeur choisi), le même expéditeur qu'alors : un fil
//!    ne change pas d'adresse. L'envoi est compté sur son domaine, sans
//!    plafond — c'est une réponse à quelqu'un qui nous connaît, pas une
//!    approche, et une réponse qu'on retient n'améliore aucune réputation.
//! 2. Sinon le domaine **vérifié** du locataire dont il reste le plus de
//!    plafond aujourd'hui, réservé dans `domain_send_buckets` par
//!    `INSERT … ON CONFLICT DO UPDATE SET sent = sent + 1 WHERE sent < cap
//!    RETURNING` — jamais compté puis écrit, la forme de
//!    `agentos_store::outreach::reserve` et de 0055. Le classement est lu
//!    sans verrou et n'est qu'une préférence ; la réservation est le verrou,
//!    et si le domaine préféré se remplit entre les deux, le suivant est
//!    tenté.
//! 3. Aucun domaine avec du plafond → [`Exhausted`], que `Effects::send_email`
//!    rend au modèle comme `domain_caps_exhausted` avec l'heure du prochain
//!    créneau, avant tout appel fournisseur.
//!
//! La réponse à un mail parti de `slug@second-domaine` rentre déjà :
//! `inbound::resolve_recipient` retrouve l'employé par le seul `slug`
//! (`SELECT id FROM employees WHERE slug = $1`, la partie locale de
//! l'adresse, quel que soit le domaine), vérifié le 2026-09-10 — aucun
//! changement de réception n'accompagne celui-ci.
//!
//! ponytail: `daily_cap` est un plafond fixe, posé à la main. Une rampe de
//! warm-up (10 → 20 → 40 … par domaine, comme `outreach_warmup` le fait par
//! locataire) est l'étape suivante, quand un client en aura besoin ; ce
//! module n'a alors qu'à lire un `cap` du jour au lieu de la colonne.
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

use agentos_domain::action::{Domain, EmailAddress};
use agentos_domain::ids::EmployeeId;
use agentos_providers::dns_cloudflare::{Cloudflare, Posed};
use agentos_providers::email::{DnsRecord, DomainStatus, EmailProvider};
use agentos_providers::{ProviderError, Secret};
use agentos_store::db::{StoreError, TenantTx};
use chrono::{DateTime, NaiveDate, TimeDelta, Utc};
use serde_json::Value;

pub use agentos_providers::dns_cloudflare::API_BASE as CLOUDFLARE_API;

/// Le plafond d'un domaine que personne n'a réglé : la valeur de la colonne.
pub const DEFAULT_DAILY_CAP: u32 = 50;

/// Une ligne du locataire, telle que la console la lit.
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
    /// Celle dont les sièges lisent le domaine ; une par locataire.
    pub is_primary: bool,
    /// Mails vers l'extérieur par jour UTC, depuis ce domaine.
    pub daily_cap: u32,
    /// Ce qui est parti aujourd'hui (UTC), fil collant compris.
    pub sent_today: u32,
}

/// Pourquoi un geste sur le domaine n'a pas eu lieu.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// Pas un hôte public à deux étiquettes — `Domain::parse` dit lequel.
    #[error("domain: {0}")]
    BadDomain(String),
    /// Un autre locataire de ce déploiement envoie déjà depuis ce nom.
    #[error("another tenant already sends from this domain")]
    DomainTaken,
    /// Le locataire n'a pas ce domaine — ou aucun.
    #[error("this tenant has no such sending domain")]
    NoDomain,
    /// La primaire ne se retire pas : les sièges lisent son nom.
    #[error("the primary domain cannot be removed")]
    PrimaryDomain,
    /// Un plafond à zéro est un domaine éteint, pas un plafond.
    #[error("daily_cap must be at least 1")]
    BadCap,
    /// Le fournisseur (email ou DNS) a répondu autre chose qu'oui.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Aucun domaine du locataire ne peut envoyer maintenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhausted {
    /// Minuit UTC suivant, quand les compteurs repartent — `None` quand le
    /// locataire n'a **aucun** domaine vérifié, et qu'aucune heure ne changera
    /// ça.
    pub next_slot: Option<DateTime<Utc>>,
}

/// Trouve ou crée `name` chez le fournisseur et l'ajoute aux domaines du
/// locataire. Idempotent sur le même nom ; la première ligne est la primaire.
pub async fn register(
    tx: &mut TenantTx<'_>,
    provider: &dyn EmailProvider,
    name: &str,
) -> Result<Row, Refusal> {
    let domain = Domain::parse(name).map_err(|err| Refusal::BadDomain(err.to_string()))?;
    if let Some(row) = find(tx, domain.as_str()).await? {
        return Ok(row);
    }

    let state = provider.ensure_domain(domain.as_str()).await?;
    let now = Utc::now();
    let verified_at = (state.status == DomainStatus::Verified).then_some(now);
    // `is_primary` : vrai si le locataire n'a encore rien — sous RLS, le
    // `NOT EXISTS` ne voit que ses lignes. Deux premières inscriptions
    // concurrentes se départagent sur `tenant_domains_one_primary`.
    let inserted = sqlx::query(
        "INSERT INTO tenant_domains \
           (tenant_id, domain, provider, provider_domain_id, region, status, records, \
            created_at, checked_at, verified_at, is_primary) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, \
                 NOT EXISTS (SELECT 1 FROM tenant_domains))",
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
            if err.as_database_error().is_some_and(|e| {
                e.is_unique_violation() && e.constraint() == Some("tenant_domains_domain_key")
            }) =>
        {
            return Err(Refusal::DomainTaken);
        }
        Err(err) => return Err(Refusal::Store(err.into())),
    }
    find(tx, domain.as_str()).await?.ok_or(Refusal::NoDomain)
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
    is_primary: bool,
    daily_cap: i32,
    sent_today: i32,
}

/// Les colonnes d'une ligne, plus le compteur du jour UTC — `sent_today` est
/// un chiffre d'affichage, lu sans verrou ; la réservation est dans
/// [`pick_from`]. Une macro et pas un `const`, parce que sqlx 0.9 n'accepte
/// qu'une chaîne statique et que `concat!` n'accepte qu'un littéral.
macro_rules! select {
    ($tail:literal) => {
        concat!(
            "SELECT d.domain, d.provider, d.provider_domain_id, d.region, d.status, \
                    d.records, d.created_at, d.checked_at, d.verified_at, d.is_primary, \
                    d.daily_cap, \
                    coalesce((SELECT b.sent FROM domain_send_buckets b \
                               WHERE b.tenant_id = d.tenant_id AND b.domain = d.domain \
                                 AND b.day = (now() AT TIME ZONE 'utc')::date), 0) \
                      AS sent_today \
               FROM tenant_domains d ",
            $tail
        )
    };
}

impl From<Stored> for Row {
    fn from(stored: Stored) -> Self {
        Row {
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
            is_primary: stored.is_primary,
            daily_cap: u32::try_from(stored.daily_cap).unwrap_or(DEFAULT_DAILY_CAP),
            sent_today: u32::try_from(stored.sent_today).unwrap_or(0),
        }
    }
}

/// La primaire du locataire, s'il a un domaine.
pub async fn primary(tx: &mut TenantTx<'_>) -> Result<Option<Row>, StoreError> {
    let row: Option<Stored> = sqlx::query_as(select!("WHERE d.is_primary"))
        .fetch_optional(&mut ***tx)
        .await?;
    Ok(row.map(Row::from))
}

/// Un domaine du locataire, par son nom normalisé.
pub async fn find(tx: &mut TenantTx<'_>, name: &str) -> Result<Option<Row>, StoreError> {
    let row: Option<Stored> = sqlx::query_as(select!("WHERE d.domain = $1"))
        .bind(name)
        .fetch_optional(&mut ***tx)
        .await?;
    Ok(row.map(Row::from))
}

/// Tous les domaines du locataire, la primaire en tête.
pub async fn all(tx: &mut TenantTx<'_>) -> Result<Vec<Row>, StoreError> {
    let rows: Vec<Stored> = sqlx::query_as(select!("ORDER BY d.is_primary DESC, d.domain"))
        .fetch_all(&mut ***tx)
        .await?;
    Ok(rows.into_iter().map(Row::from).collect())
}

/// `name` s'il est donné, sinon la primaire ; `NoDomain` quand ni l'un ni
/// l'autre n'est là.
async fn named_or_primary(tx: &mut TenantTx<'_>, name: Option<&str>) -> Result<Row, Refusal> {
    let row = match name {
        Some(name) => {
            let domain = Domain::parse(name).map_err(|err| Refusal::BadDomain(err.to_string()))?;
            find(tx, domain.as_str()).await?
        }
        None => primary(tx).await?,
    };
    row.ok_or(Refusal::NoDomain)
}

/// Demande au fournisseur de regarder le DNS de `name` (la primaire sans
/// nom), relit, écrit — et réveille les sièges qui attendaient si le verdict
/// est `verified`.
pub async fn verify(
    tx: &mut TenantTx<'_>,
    provider: &dyn EmailProvider,
    name: Option<&str>,
) -> Result<Row, Refusal> {
    let row = named_or_primary(tx, name).await?;
    let id = row.provider_domain_id.as_deref().ok_or(Refusal::NoDomain)?;
    let state = provider.verify_domain(id).await?;
    let now = Utc::now();
    sqlx::query(
        "UPDATE tenant_domains \
            SET status = $1, records = $2, region = coalesce($3, region), checked_at = $4, \
                verified_at = coalesce(verified_at, $5) \
          WHERE domain = $6",
    )
    .bind(state.status.as_str())
    .bind(sqlx::types::Json(&state.records))
    .bind(&state.region)
    .bind(now)
    .bind((state.status == DomainStatus::Verified).then_some(now))
    .bind(&row.domain)
    .execute(&mut ***tx)
    .await
    .map_err(StoreError::from)?;

    if state.status == DomainStatus::Verified {
        wake_seats(tx).await?;
    }
    find(tx, &row.domain).await?.ok_or(Refusal::NoDomain)
}

/// Le domaine d'un employé à créer.
///
/// `requested` est ce que le corps a nommé, s'il a nommé quelque chose ;
/// `default` est `AGENT_EMAIL_DOMAIN`. Un nom est accepté s'il est au
/// locataire et ajouté sinon — `register` fait le reste, y compris la 409
/// quand il est à un autre locataire. Un corps qui se tait embauche sur la
/// primaire ; un locataire sans ligne est enregistré sous le défaut.
pub async fn require(
    tx: &mut TenantTx<'_>,
    provider: &dyn EmailProvider,
    requested: Option<&str>,
    default: &str,
) -> Result<Row, Refusal> {
    match (requested, primary(tx).await?) {
        (Some(name), _) => register(tx, provider, name).await,
        (None, Some(row)) => Ok(row),
        (None, None) => register(tx, provider, default).await,
    }
}

/// Pose les enregistrements de `name` (la primaire sans nom) dans la zone
/// Cloudflare qui le contient. Le jeton vit le temps de l'appel.
pub async fn pose_dns(
    tx: &mut TenantTx<'_>,
    token: Secret,
    cloudflare_api: &str,
    name: Option<&str>,
) -> Result<Posed, Refusal> {
    let row = named_or_primary(tx, name).await?;
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

/// Le plafond journalier de `name`. Zéro est refusé : un domaine qu'on veut
/// taire se retire ([`remove`]) ou se laisse non vérifié.
pub async fn set_cap(tx: &mut TenantTx<'_>, name: &str, daily_cap: u32) -> Result<Row, Refusal> {
    let cap = i32::try_from(daily_cap)
        .ok()
        .filter(|cap| *cap > 0)
        .ok_or(Refusal::BadCap)?;
    let row = named_or_primary(tx, Some(name)).await?;
    sqlx::query("UPDATE tenant_domains SET daily_cap = $1 WHERE domain = $2")
        .bind(cap)
        .bind(&row.domain)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    find(tx, &row.domain).await?.ok_or(Refusal::NoDomain)
}

/// Retire un domaine secondaire. Ses compteurs partent avec lui (cascade) ;
/// les adresses imprimées dans des mails partis vivent dans `messages`, et
/// [`pick_from`] n'y colle plus puisque le domaine n'est plus vérifié ici.
pub async fn remove(tx: &mut TenantTx<'_>, name: &str) -> Result<(), Refusal> {
    let row = named_or_primary(tx, Some(name)).await?;
    if row.is_primary {
        return Err(Refusal::PrimaryDomain);
    }
    sqlx::query("DELETE FROM tenant_domains WHERE domain = $1")
        .bind(&row.domain)
        .execute(&mut ***tx)
        .await
        .map_err(StoreError::from)?;
    Ok(())
}

/// L'expéditeur d'un mail de `employee` vers `recipient`, réservé pour
/// aujourd'hui — voir le module. `Ok(Err(Exhausted))` est un refus qui laisse
/// la transaction propre ; `Err` est la base.
pub async fn pick_from(
    tx: &mut TenantTx<'_>,
    employee: EmployeeId,
    recipient: &EmailAddress,
    now: DateTime<Utc>,
) -> Result<Result<EmailAddress, Exhausted>, StoreError> {
    let day = now.date_naive();
    let slug: String = sqlx::query_scalar("SELECT slug FROM employees WHERE id = $1")
        .bind(employee.as_uuid())
        .fetch_one(&mut ***tx)
        .await?;

    // 1. Collant : le dernier expéditeur de cet employé vers cette adresse,
    //    s'il est encore un domaine vérifié du locataire.
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT sender FROM messages \
          WHERE employee_id = $1 AND channel = 'email' AND direction = 'outbound' \
            AND recipients @> $2::jsonb AND sender <> '' \
          ORDER BY received_at DESC LIMIT 1",
    )
    .bind(employee.as_uuid())
    .bind(serde_json::json!([recipient.to_string()]))
    .fetch_optional(&mut ***tx)
    .await?;
    if let Some(previous) = previous.and_then(|raw| EmailAddress::parse(&raw).ok()) {
        let counted: Option<i32> = sqlx::query_scalar(
            "INSERT INTO domain_send_buckets (tenant_id, domain, day, sent) \
             SELECT $1::uuid, domain, $3::date, 1 FROM tenant_domains \
              WHERE domain = $2 AND status = 'verified' \
             ON CONFLICT (tenant_id, domain, day) DO UPDATE \
               SET sent = domain_send_buckets.sent + 1, updated_at = now() \
             RETURNING sent",
        )
        .bind(tx.tenant_id().as_uuid())
        .bind(previous.domain().as_str())
        .bind(day)
        .fetch_optional(&mut ***tx)
        .await?;
        if counted.is_some() {
            return Ok(Ok(previous));
        }
    }

    // 2. Le domaine vérifié le moins chargé — une préférence, lue sans
    //    verrou ; la réservation en dessous est ce qui compte.
    let ranked: Vec<String> = sqlx::query_scalar(
        "SELECT d.domain FROM tenant_domains d \
           LEFT JOIN domain_send_buckets b \
             ON b.tenant_id = d.tenant_id AND b.domain = d.domain AND b.day = $1 \
          WHERE d.status = 'verified' \
          ORDER BY d.daily_cap - coalesce(b.sent, 0) DESC, d.is_primary DESC, d.domain",
    )
    .bind(day)
    .fetch_all(&mut ***tx)
    .await?;
    if ranked.is_empty() {
        return Ok(Err(Exhausted { next_slot: None }));
    }
    for domain in ranked {
        // Créer-ou-verrouiller-et-incrémenter en un ordre ; `WHERE sent <
        // daily_cap` sur la ligne verrouillée est le plafond, et un `None`
        // est un domaine plein — le suivant est tenté.
        let reserved: Option<i32> = sqlx::query_scalar(
            "INSERT INTO domain_send_buckets (tenant_id, domain, day, sent) \
             VALUES ($1, $2, $3, 1) \
             ON CONFLICT (tenant_id, domain, day) DO UPDATE \
               SET sent = domain_send_buckets.sent + 1, updated_at = now() \
             WHERE domain_send_buckets.sent < (SELECT t.daily_cap FROM tenant_domains t \
                                                WHERE t.tenant_id = $1 AND t.domain = $2) \
             RETURNING sent",
        )
        .bind(tx.tenant_id().as_uuid())
        .bind(&domain)
        .bind(day)
        .fetch_optional(&mut ***tx)
        .await?;
        if reserved.is_some() {
            let from = EmailAddress::parse(&format!("{slug}@{domain}"))
                .map_err(|err| StoreError::conflict(format!("sender address: {err}")))?;
            return Ok(Ok(from));
        }
    }
    Ok(Err(Exhausted {
        next_slot: Some(next_slot(day)),
    }))
}

/// Donne à `tenant` un domaine vérifié sur le champ, `<uuid>.example.com`,
/// pour qu'un test qui embauche par SQL puisse envoyer.
///
/// Compilé hors `cfg(test)` parce que les tests d'`apps/server` en ont
/// besoin autant que ceux d'ici, et qu'un item `cfg(test)` ne traverse pas
/// une caisse. Depuis 0094 un locataire sans domaine vérifié n'envoie rien
/// ([`pick_from`] → [`Exhausted`]) : chaque fixture qui pose un employé par
/// `INSERT` et attend qu'un mail parte doit passer ici — c'est ce que
/// `require` fait pour une vraie embauche. Le nom est dérivé du locataire
/// parce que `tenant_domains.domain` est unique dans toute la base et que les
/// tests d'un binaire la partagent.
pub async fn adopt_for_tests(
    db: &agentos_store::db::Db,
    tenant: agentos_domain::ids::TenantId,
) -> String {
    let mock = agentos_providers::email::MockEmailProvider::new();
    let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
    let row = register(
        &mut tx,
        &mock,
        &format!("{}.example.com", tenant.as_uuid().simple()),
    )
    .await
    .expect("register the tenant's domain");
    tx.commit().await.expect("commit");
    row.domain
}

/// Minuit UTC après `day` : les compteurs sont par jour, et ils repartent là.
fn next_slot(day: NaiveDate) -> DateTime<Utc> {
    (day + TimeDelta::days(1))
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
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
    use std::sync::Arc;

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

    fn prospect(label: &str) -> EmailAddress {
        EmailAddress::parse(&format!("{label}@prospect.example")).expect("address")
    }

    /// Un employé `lena` du locataire.
    async fn hire_lena(tx: &mut TenantTx<'_>, tenant: TenantId) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'Lena', 'active')",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut ***tx)
        .await
        .expect("employee");
        id
    }

    async fn pick(tx: &mut TenantTx<'_>, lena: EmployeeId, to: &str) -> Result<String, Exhausted> {
        pick_from(tx, lena, &prospect(to), Utc::now())
            .await
            .expect("store")
            .map(|from| from.to_string())
    }

    #[tokio::test]
    async fn the_first_domain_is_primary_the_second_is_not_and_the_same_name_is_the_same_row() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let first = unique("agents");
        let second = unique("agent");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");

        // Mixed case in, lower case stored: `Domain::parse` normalises.
        let row = register(&mut tx, &mock, &first.to_uppercase())
            .await
            .expect("register");
        assert_eq!(row.domain, first);
        assert!(row.is_primary, "the first domain is the primary");
        assert_eq!(row.daily_cap, DEFAULT_DAILY_CAP);
        assert_eq!(row.sent_today, 0);
        assert_eq!(row.provider, MockEmailProvider::PROVIDER);
        assert_eq!(
            row.status,
            DomainStatus::Verified,
            "the mock verifies on sight"
        );
        assert!(row.verified_at.is_some());
        assert_eq!(row.records.len(), 1, "the provider's records, as they came");
        assert_eq!(row.records[0].kind, "TXT");
        assert_eq!(primary(&mut tx).await.expect("primary"), Some(row.clone()));

        let again = register(&mut tx, &mock, &first).await.expect("again");
        assert_eq!(again, row);
        assert_eq!(mock.domain_count(), 1, "the provider was asked once");

        // A second name is another row, not a refusal — and not the primary.
        let more = register(&mut tx, &mock, &second).await.expect("add");
        assert!(!more.is_primary);
        assert_eq!(mock.domain_count(), 2);
        assert_eq!(primary(&mut tx).await.expect("primary"), Some(row.clone()));
        let listed = all(&mut tx).await.expect("all");
        assert_eq!(
            listed.iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(),
            [first.as_str(), second.as_str()],
            "the primary first, then by name"
        );
        assert!(matches!(
            register(&mut tx, &mock, "localhost").await,
            Err(Refusal::BadDomain(_))
        ));
        tx.commit().await.expect("commit");

        // Tenant B: sees nothing of A (RLS), and cannot take A's names.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        assert_eq!(primary(&mut tx).await.expect("primary"), None);
        assert!(all(&mut tx).await.expect("all").is_empty());
        assert!(matches!(
            register(&mut tx, &mock, &second).await,
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
        let checked = verify(&mut tx, &mock, None).await.expect("verify");
        assert_eq!(checked.status, DomainStatus::Pending);
        assert!(checked.checked_at.is_some());
        assert_eq!(checked.verified_at, None);

        // A seat waiting on this domain, and one that failed on it.
        let waiting = seat(&mut tx, f.a, "pending_external").await;
        let failed = seat(&mut tx, f.a, "failed").await;

        mock.release_domains();
        // By name this time: the same row.
        let done = verify(&mut tx, &mock, Some(&name)).await.expect("verify");
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
        assert!(matches!(
            verify(&mut tx, &mock, Some(&unique("nobody"))).await,
            Err(Refusal::NoDomain)
        ));
        tx.commit().await.expect("commit");

        // Tenant B has no domain to verify.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        assert!(matches!(
            verify(&mut tx, &mock, None).await,
            Err(Refusal::NoDomain)
        ));
    }

    #[tokio::test]
    async fn require_registers_a_tenant_with_no_domain_and_accepts_any_of_its_own() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let name = unique("req");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");

        // Nothing named, no row: the deployment's default is registered.
        let row = require(&mut tx, &mock, None, &name)
            .await
            .expect("registered on the way");
        assert_eq!(row.domain, name);
        assert!(row.is_primary);
        // Nothing named, a row: the primary, and the default is not consulted.
        let same = require(&mut tx, &mock, None, "other.example.com")
            .await
            .expect("the tenant's own");
        assert_eq!(same, row);
        require(&mut tx, &mock, Some(&name), "x.example.com")
            .await
            .expect("the same domain is fine");
        // Another name: added, not refused — a seat may sit on any of them.
        let other = unique("else");
        let added = require(&mut tx, &mock, Some(&other), &name)
            .await
            .expect("a second domain of the tenant's");
        assert_eq!(added.domain, other);
        assert!(!added.is_primary);
        assert_eq!(mock.domain_count(), 2);
    }

    #[tokio::test]
    async fn the_cap_is_set_by_hand_and_only_a_secondary_domain_can_be_removed() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let first = unique("prim");
        let second = unique("sec");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        register(&mut tx, &mock, &first).await.expect("register");
        register(&mut tx, &mock, &second).await.expect("register");

        let capped = set_cap(&mut tx, &second, 7).await.expect("cap");
        assert_eq!(capped.daily_cap, 7);
        assert!(matches!(
            set_cap(&mut tx, &second, 0).await,
            Err(Refusal::BadCap)
        ));
        assert!(matches!(
            set_cap(&mut tx, &unique("nobody"), 3).await,
            Err(Refusal::NoDomain)
        ));

        assert!(matches!(
            remove(&mut tx, &first).await,
            Err(Refusal::PrimaryDomain)
        ));
        remove(&mut tx, &second).await.expect("a secondary goes");
        assert_eq!(find(&mut tx, &second).await.expect("find"), None);
        assert!(matches!(
            remove(&mut tx, &second).await,
            Err(Refusal::NoDomain)
        ));
        tx.commit().await.expect("commit");

        // Tenant B cannot cap or remove A's domain.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        assert!(matches!(
            set_cap(&mut tx, &first, 3).await,
            Err(Refusal::NoDomain)
        ));
        assert!(matches!(
            remove(&mut tx, &first).await,
            Err(Refusal::NoDomain)
        ));
    }

    /// **Le collant.** Lena a écrit à Marie depuis le second domaine ; la
    /// prochaine lettre à Marie part du même, quel que soit le plafond — et
    /// une lettre à Paul part du domaine le moins chargé.
    #[tokio::test]
    async fn a_thread_keeps_its_sender_and_a_new_recipient_gets_the_least_loaded_domain() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let first = unique("a");
        let second = unique("b");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        let lena = hire_lena(&mut tx, f.a).await;
        register(&mut tx, &mock, &first).await.expect("register");
        register(&mut tx, &mock, &second).await.expect("register");

        // As `Effects::chase` records a send: the sender chosen then.
        let then = format!("lena@{second}");
        crate::follow_up::sent(
            &mut tx,
            lena,
            &prospect("marie"),
            Some("hello"),
            &then,
            "msg_1",
            Utc::now(),
        )
        .await
        .expect("record");
        // The second domain is full for the day; the thread does not care.
        set_cap(&mut tx, &second, 1).await.expect("cap");
        assert_eq!(pick(&mut tx, lena, "marie").await, Ok(then.clone()));
        assert_eq!(pick(&mut tx, lena, "marie").await, Ok(then));
        let counted = find(&mut tx, &second).await.expect("find").expect("row");
        assert_eq!(
            counted.sent_today, 2,
            "a sticky send is counted, over the cap if it must"
        );

        // Paul is new: the first domain has 50 left, the second none.
        assert_eq!(
            pick(&mut tx, lena, "paul").await,
            Ok(format!("lena@{first}"))
        );
        tx.commit().await.expect("commit");
    }

    /// **Le plafond mord.** Cap 1 partout : le deuxième inconnu tombe sur
    /// l'autre domaine, le troisième sur `Exhausted` avec minuit UTC — et rien
    /// n'est réservé pour lui.
    #[tokio::test]
    async fn the_caps_bite_and_the_third_stranger_waits_for_midnight() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let first = unique("a");
        let second = unique("b");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        let lena = hire_lena(&mut tx, f.a).await;
        register(&mut tx, &mock, &first).await.expect("register");
        register(&mut tx, &mock, &second).await.expect("register");
        set_cap(&mut tx, &first, 1).await.expect("cap");
        set_cap(&mut tx, &second, 1).await.expect("cap");

        let one = pick(&mut tx, lena, "p1").await.expect("room");
        let two = pick(&mut tx, lena, "p2").await.expect("room on the other");
        assert_ne!(one, two, "one each");
        let now = Utc::now();
        let refused = pick_from(&mut tx, lena, &prospect("p3"), now)
            .await
            .expect("store")
            .expect_err("both full");
        assert_eq!(refused.next_slot, Some(next_slot(now.date_naive())));
        assert!(
            refused.next_slot.expect("a slot") > now,
            "the next slot is in the future"
        );
        for name in [&first, &second] {
            assert_eq!(
                find(&mut tx, name)
                    .await
                    .expect("find")
                    .expect("row")
                    .sent_today,
                1
            );
        }
        tx.commit().await.expect("commit");

        // Tenant B: no domain at all is exhausted with no slot to wait for.
        let mut tx = f.db.tenant_tx(f.b).await.expect("tx");
        let lena_b = hire_lena(&mut tx, f.b).await;
        assert_eq!(
            pick(&mut tx, lena_b, "p1").await,
            Err(Exhausted { next_slot: None })
        );
    }

    #[tokio::test]
    async fn an_unverified_domain_is_never_chosen() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let good = unique("good");
        let pending = unique("pending");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        let lena = hire_lena(&mut tx, f.a).await;
        register(&mut tx, &mock, &good).await.expect("register");
        set_cap(&mut tx, &good, 1).await.expect("cap");
        mock.hold_domain_pending();
        let row = register(&mut tx, &mock, &pending).await.expect("register");
        assert_eq!(row.status, DomainStatus::Pending);

        assert_eq!(pick(&mut tx, lena, "p1").await, Ok(format!("lena@{good}")));
        // The verified one is full and the pending one has 50 of room: still no.
        assert!(pick(&mut tx, lena, "p2").await.is_err());
        // Not even for a thread that once left from it.
        crate::follow_up::sent(
            &mut tx,
            lena,
            &prospect("old"),
            None,
            &format!("lena@{pending}"),
            "msg_old",
            Utc::now(),
        )
        .await
        .expect("record");
        assert!(pick(&mut tx, lena, "old").await.is_err());
        tx.commit().await.expect("commit");
    }

    /// **N envois derrière une barrière ne dépassent jamais `cap`.** La forme
    /// de `outreach::reserve`'s test, sans l'assertion de recouvrement des
    /// fenêtres : chaque tâche réserve dans sa transaction et commet, et le
    /// compteur final est le plafond, pas une fois de plus.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sends_never_exceed_the_cap() {
        let Some(f) = fixture().await else { return };
        let mock = MockEmailProvider::new();
        let name = unique("race");
        const CAP: u32 = 3;
        const SENDERS: usize = 8;
        let lena = {
            let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
            let lena = hire_lena(&mut tx, f.a).await;
            register(&mut tx, &mock, &name).await.expect("register");
            set_cap(&mut tx, &name, CAP).await.expect("cap");
            tx.commit().await.expect("commit");
            lena
        };

        let barrier = Arc::new(tokio::sync::Barrier::new(SENDERS));
        let tasks: Vec<_> = (0..SENDERS)
            .map(|i| {
                let db = f.db.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    let mut tx = db.tenant_tx(f.a).await.expect("tx");
                    barrier.wait().await;
                    let out = pick(&mut tx, lena, &format!("p{i}")).await;
                    // Commit either way: a wrongly granted send must be
                    // visible in the bucket, not rolled back by a tidy test.
                    tx.commit().await.expect("commit");
                    out
                })
            })
            .collect();
        let mut granted = 0;
        for task in tasks {
            if task.await.expect("task").is_ok() {
                granted += 1;
            }
        }
        assert_eq!(granted, CAP, "exactly the cap was granted");
        let mut tx = f.db.tenant_tx(f.a).await.expect("tx");
        assert_eq!(
            find(&mut tx, &name)
                .await
                .expect("find")
                .expect("row")
                .sent_today,
            CAP
        );
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
