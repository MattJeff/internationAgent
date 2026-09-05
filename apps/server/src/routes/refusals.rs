//! `GET /v1/refusals` : ce que la gate a refusé, pour un locataire, sur une
//! fenêtre.
//!
//! # Pourquoi cette route existe
//!
//! Un client qui met 5K$/mois d'infrastructure derrière des agents n'a pas
//! peur de ce qu'ils font — il a peur de ce qu'ils *pourraient* faire. La seule
//! réponse honnête est la liste de ce qu'on les a empêchés de faire, et elle
//! existe déjà : `agentos_app::gate` écrit une ligne d'audit par verdict, avec le
//! motif. Rien à instrumenter, aucune table : c'est une lecture de `audit_log`.
//!
//! # Ce que « refus » veut dire ici, exactement
//!
//! Une ligne compte comme un refus quand **la gate** l'a écrite et que le
//! verdict n'a pas laissé passer l'action. `gate::audit_event` écrit une seule
//! ligne par appel à `authorize` / `redeem_approval`, toujours avec un
//! `decision_id`, et un refus y a l'une de deux formes :
//!
//! | forme | colonnes | qui l'écrit |
//! |---|---|---|
//! | **refus de politique** | `decision = 'deny'`, motif dans `deny_reason_code` | `Outcome::Deny(DenyReason)` — canal interdit, plafond, texte non fiable… |
//! | **refus sans `DenyReason`** | `decision IS NULL`, motif dans `payload.denied` | `Outcome::Halted`, `Suppressed`, `NotActive`, `UnknownEmployee`, `BrokenPolicy`, `Redemption` |
//!
//! Le prédicat SQL est `refusal_predicate!`, écrit une fois et partagé par le
//! décompte et la liste, pour que « refus » n'ait pas deux définitions. Le motif
//! rendu est `coalesce(deny_reason_code, payload->>'denied')` : les deux
//! vocabulaires sont fermés et écrits dans ce dépôt (`DenyReason::code`,
//! `audit::COMPANY_HALTED`, les codes de `gate.rs`), donc rien qu'un tiers a
//! choisi n'atterrit dans `by_reason`.
//!
//! Une escalade (`decision = 'require_approval'`) **n'est pas un refus** : la
//! gate n'a pas dit non, elle attend quelqu'un. La compter ici ferait paraître
//! `payment_above_threshold` dans une liste intitulée « ce qu'on a refusé ».
//!
//! # L'acteur
//!
//! Aucun filtre sur `actor`. Un refus est un verdict de la gate, quelle que
//! soit la main qui a proposé l'action — l'employé lui-même, ou un opérateur qui
//! a conduit l'action par l'API et s'est fait refuser de la même façon. La
//! lecture la moins flatteuse pour l'agent est celle qui ne cache aucun refus
//! derrière la question « mais c'était un humain ».
//!
//! # Pourquoi les refus d'un opérateur via l'API ne sont **pas** ici
//!
//! `POST /v1/approvals/{id}/deny` et la réponse négative à une demande de
//! capacité écrivent `action_kind = 'approval_decided'` /
//! `'capability_decided'` avec `payload.outcome = 'denied'`. C'est **un humain
//! qui refuse**, pas la gate : la ligne n'a ni `decision_id` ni `decision`, et
//! l'action refusée n'a jamais atteint le moment où la politique aurait tranché.
//! Les mélanger ferait passer une décision de management pour un contrôle
//! automatique — et c'est exactement le contrôle automatique que le client veut
//! voir. Ces lignes ont déjà leur place : `human_rejected` dans
//! [`super::autonomy`]. De même, `mail_refused` (le destinataire nous refuse)
//! n'est pas un refus de la gate.
//!
//! Le prédicat les exclut par construction — `decision_id IS NOT NULL` — et pas
//! par une liste de kinds à tenir à jour.
//!
//! # La source non fiable
//!
//! Chaque entrée de `recent` porte, **quand la ligne d'audit le porte**, la
//! trace de la source qui a produit l'action refusée : le label de confiance du
//! tour (`trust_label`), le canal (`channel`), l'expéditeur (`from`) ou l'hôte
//! (`host`). Jamais le texte non fiable lui-même — ni `body`, ni `subject`, ni
//! `detail` — parce qu'une route qui recopie une injection de prompt dans un
//! tableau de bord est une route qui la fait relire à un humain.
//!
//! La gate écrit `trust_label` dès que l'action vient d'un texte non fiable, et
//! les trois autres quand l'appelant lui a dit d'où venait la tache
//! (`gate::TaintOrigin`, posé par `turn.rs` au moment où le label bascule :
//! message entrant, page lue, document rappelé). Un refus d'un tour propre ne
//! porte donc aucune de ces clés, et `source` est absent de son entrée.
//!
//! # Le locataire
//!
//! Tout sous [`Db::tenant_tx`] : pas de `WHERE tenant_id`, la policy de
//! `audit_log` et celle de `employees` fournissent le prédicat, et les refus
//! d'un autre locataire ne sont pas filtrés — ils sont invisibles.

use agentos_store::db::{Db, StoreError};
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get as get_route;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::autonomy::{Window, WindowQuery};
use super::public_register::ranked;
use crate::auth::Principal;
use crate::error::ApiError;

/// Combien d'entrées `recent` rend. Cinquante est ce qu'un humain relit ; le
/// reste est dans les décomptes.
const RECENT_LIMIT: i64 = 50;

/// Ce module.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/refusals", get_route(get))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// La fenêtre
// ---------------------------------------------------------------------------

/// `?days=30`, ou `?from=…&to=…` comme [`super::usage`].
///
/// `days` est la forme courte de la même fenêtre : `N` jours calendaires UTC
/// qui finissent aujourd'hui, résolus par [`Window::resolve`] pour que les
/// bornes et la limite soient celles de `/v1/usage` et `/v1/autonomy`.
#[derive(Debug, Deserialize)]
struct RefusalsQuery {
    days: Option<i64>,
    #[serde(flatten)]
    window: WindowQuery,
}

impl RefusalsQuery {
    fn resolve(self) -> Result<Window, ApiError> {
        let mut window = self.window;
        if let Some(days) = self.days {
            if days < 1 {
                return Err(ApiError::bad_request("days: at least 1"));
            }
            let to = window.to.unwrap_or_else(|| Utc::now().date_naive());
            window.from = Some(
                to.checked_sub_signed(Duration::days(days - 1))
                    .ok_or_else(|| ApiError::bad_request("days: too many"))?,
            );
        }
        Window::resolve(&window)
    }
}

// ---------------------------------------------------------------------------
// La lecture
// ---------------------------------------------------------------------------

/// **La définition d'un refus**, une fois. Voir les docs du module.
///
/// Une macro et pas une `const` : sqlx n'accepte que du SQL `&'static str`, et
/// `concat!` ne splice que des littéraux. C'est le seul moyen d'écrire le
/// prédicat une fois et de le lire dans deux requêtes.
///
/// `$1` et `$2` sont les bornes `timestamptz`, `[from, end)`.
macro_rules! refusal_predicate {
    () => {
        "a.decision_id IS NOT NULL \
         AND (a.decision = 'deny' OR (a.decision IS NULL AND a.payload ? 'denied')) \
         AND a.occurred_at >= $1 AND a.occurred_at < $2"
    };
}

/// Une classe de refus et son décompte. Les trois groupements de la réponse
/// sont ces lignes repliées trois fois, donc ils ne peuvent pas se contredire.
#[derive(Debug, sqlx::FromRow)]
struct TallyRow {
    slug: Option<String>,
    display_name: Option<String>,
    action_kind: String,
    reason: Option<String>,
    count: i64,
}

/// Une entrée de `recent`, telle que la ligne la porte.
#[derive(Debug, sqlx::FromRow)]
struct RecentRow {
    occurred_at: DateTime<Utc>,
    slug: Option<String>,
    display_name: Option<String>,
    action_kind: String,
    reason: Option<String>,
    trust_label: Option<String>,
    channel: Option<String>,
    sender: Option<String>,
    host: Option<String>,
}

/// `LEFT JOIN`, pas `JOIN` : un refus `unknown_employee` porte un `employee_id`
/// sans ligne derrière, et il compte quand même — c'est même un de ceux qu'on
/// veut voir.
const TALLY_SQL: &str = concat!(
    "SELECT e.slug, e.display_name, a.action_kind, \
            coalesce(a.deny_reason_code, a.payload->>'denied') AS reason, \
            count(*) AS count \
       FROM audit_log a \
       LEFT JOIN employees e ON e.id = a.employee_id \
      WHERE ",
    refusal_predicate!(),
    " GROUP BY e.slug, e.display_name, a.action_kind, reason"
);

const RECENT_SQL: &str = concat!(
    "SELECT a.occurred_at, e.slug, e.display_name, a.action_kind, \
            coalesce(a.deny_reason_code, a.payload->>'denied') AS reason, \
            a.payload->>'trust_label' AS trust_label, \
            a.payload->>'channel'     AS channel, \
            a.payload->>'from'        AS sender, \
            a.payload->>'host'        AS host \
       FROM audit_log a \
       LEFT JOIN employees e ON e.id = a.employee_id \
      WHERE ",
    refusal_predicate!(),
    " ORDER BY a.occurred_at DESC, a.id DESC \
      LIMIT $3"
);

// ---------------------------------------------------------------------------
// La réponse
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct WindowView {
    /// Inclusive, UTC.
    from: NaiveDate,
    /// Inclusive, UTC.
    to: NaiveDate,
}

#[derive(Debug, Serialize)]
struct ReasonLine {
    reason: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct KindLine {
    action_kind: String,
    count: i64,
}

/// Un siège, nommé. `slug` est `None` pour un refus `unknown_employee`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct EmployeeRef {
    slug: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmployeeLine {
    #[serde(flatten)]
    employee: EmployeeRef,
    count: i64,
}

/// D'où venait ce que la gate a refusé — voir « La source non fiable ».
#[derive(Debug, Serialize)]
struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

#[derive(Debug, Serialize)]
struct Recent {
    at: DateTime<Utc>,
    employee: EmployeeRef,
    action_kind: String,
    /// `None` seulement pour une ligne que le prédicat admet sans motif, ce
    /// qu'aucun écrivain actuel ne produit ; gardé nullable pour ne pas rendre
    /// 500 sur une ligne d'un build plus récent.
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
}

#[derive(Debug, Serialize)]
struct RefusalsView {
    window: WindowView,
    total: i64,
    by_reason: Vec<ReasonLine>,
    by_action_kind: Vec<KindLine>,
    by_employee: Vec<EmployeeLine>,
    /// Les cinquante derniers, le plus récent d'abord.
    recent: Vec<Recent>,
}

/// Le motif d'une ligne sans motif. Aucun écrivain n'en produit ; s'il en
/// arrive une, elle est comptée sous un nom qui dit qu'elle est anormale plutôt
/// que perdue.
const NO_REASON: &str = "unknown";

fn fold(rows: Vec<TallyRow>, recent: Vec<RecentRow>, window: Window) -> RefusalsView {
    let mut by_reason: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_employee: BTreeMap<EmployeeRef, i64> = BTreeMap::new();
    let mut total = 0_i64;
    for row in rows {
        total = total.saturating_add(row.count);
        *by_reason
            .entry(row.reason.unwrap_or_else(|| NO_REASON.to_owned()))
            .or_default() += row.count;
        *by_kind.entry(row.action_kind).or_default() += row.count;
        *by_employee
            .entry(EmployeeRef {
                slug: row.slug,
                display_name: row.display_name,
            })
            .or_default() += row.count;
    }

    RefusalsView {
        window: WindowView {
            from: window.from,
            to: window.to,
        },
        total,
        by_reason: ranked(
            by_reason
                .into_iter()
                .map(|(reason, count)| ReasonLine { reason, count })
                .collect(),
            |l| l.count,
            |l| l.reason.clone(),
        ),
        by_action_kind: ranked(
            by_kind
                .into_iter()
                .map(|(action_kind, count)| KindLine { action_kind, count })
                .collect(),
            |l| l.count,
            |l| l.action_kind.clone(),
        ),
        by_employee: ranked(
            by_employee
                .into_iter()
                .map(|(employee, count)| EmployeeLine { employee, count })
                .collect(),
            |l| l.count,
            |l| l.employee.slug.clone().unwrap_or_default(),
        ),
        recent: recent
            .into_iter()
            .map(|row| {
                let source = (row.trust_label.is_some()
                    || row.channel.is_some()
                    || row.sender.is_some()
                    || row.host.is_some())
                .then_some(Source {
                    trust_label: row.trust_label,
                    channel: row.channel,
                    sender: row.sender,
                    host: row.host,
                });
                Recent {
                    at: row.occurred_at,
                    employee: EmployeeRef {
                        slug: row.slug,
                        display_name: row.display_name,
                    },
                    action_kind: row.action_kind,
                    reason: row.reason,
                    source,
                }
            })
            .collect(),
    }
}

/// `GET /v1/refusals?days=30`.
///
/// 200 avec des zéros et des listes vides est la réponse ordinaire d'une
/// fenêtre sans refus : « rien refusé » est un fait, pas une ressource absente.
async fn get(
    State(db): State<Db>,
    principal: Principal,
    query: Result<Query<RefusalsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let window = query.resolve()?;
    let since = window
        .from
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    let until = window
        .end()
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    let rows: Vec<TallyRow> = sqlx::query_as(TALLY_SQL)
        .bind(since)
        .bind(until)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    let recent: Vec<RecentRow> = sqlx::query_as(RECENT_SQL)
        .bind(since)
        .bind(until)
        .bind(RECENT_LIMIT)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::from)?;
    tx.rollback().await?;

    Ok(axum::Json(fold(rows, recent, window)).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_app::gate::{Denied, PolicyGate, Principal as GatePrincipal, TaintOrigin};
    use agentos_domain::action::{Action, Channel, E164, EmailAddress};
    use agentos_domain::ids::{EmployeeId, TenantId};
    use agentos_domain::policy::{DenyReason, PolicyLimits};
    use agentos_domain::untrusted::Untrusted;
    use agentos_store::audit::{self, AuditActor, AuditEvent, AuditKind};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Email permis, rien d'autre : un SMS est refusé pour le canal, un contrat
    /// depuis un texte non fiable est refusé pour la tache.
    fn limits() -> PolicyLimits {
        PolicyLimits {
            allowed_channels: BTreeSet::from([Channel::Email]),
            max_new_contacts_per_day: 1_000,
            ..PolicyLimits::default()
        }
    }

    struct Harness {
        app: Router,
        db: Db,
        gate: PolicyGate,
        a: TenantId,
        b: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; refusals are a SQL question");
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
            for tenant in [a, b] {
                agentos_store::policy::install(
                    &db,
                    tenant,
                    agentos_store::policy::Scope::Tenant,
                    &limits(),
                )
                .await
                .expect("install the policy");
            }

            Some(Self {
                app: crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                ),
                gate: PolicyGate::new(db.clone()),
                db,
                a,
                b,
            })
        }

        async fn refusals(&self, uri: &str, secret: &str) -> (StatusCode, Value) {
            let req = HttpRequest::builder()
                .method("GET")
                .uri(uri)
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'refusals-test')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    async fn employee(db: &Db, tenant: TenantId, slug: &str, lifecycle: &str) -> EmployeeId {
        let id = EmployeeId::new_v7(Utc::now());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, $3, $3, $4)",
        )
        .bind(id.as_uuid())
        .bind(tenant.as_uuid())
        .bind(slug)
        .bind(lifecycle)
        .execute(&mut **tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit");
        id
    }

    fn email() -> Action {
        Action::EmailSend {
            to: EmailAddress::parse("prospect@example.com").expect("address"),
        }
    }

    fn sms() -> Action {
        Action::SmsSend {
            to: E164::parse("+33123456789").expect("number"),
        }
    }

    fn contract() -> Action {
        Action::ContractSign {
            title: "supply agreement".to_owned(),
        }
    }

    fn count_of(body: &Value, list: &str, key: &str, value: &str) -> i64 {
        body[list]
            .as_array()
            .unwrap_or_else(|| panic!("{list} in {body}"))
            .iter()
            .find(|line| line[key] == json!(value))
            .and_then(|line| line["count"].as_i64())
            .unwrap_or(0)
    }

    /// **Trois refus réels, par la gate, et une chose qui n'en est pas un.**
    ///
    /// Un SMS hors canal (`deny` + `deny_reason_code`), un contrat proposé par
    /// un texte non fiable (`deny` + `untrusted_input`), et un employé suspendu
    /// (`decision IS NULL` + `payload.denied`) : les deux formes du prédicat.
    /// À côté, un email permis et un refus *humain* d'approbation, tel que
    /// `routes::approvals::deny` l'écrit — ni l'un ni l'autre n'est un refus de
    /// la gate.
    #[tokio::test]
    async fn a_real_refusal_is_in_every_grouping_and_in_recent() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena", "active").await;
        let mo = employee(&h.db, h.a, "mo", "suspended").await;
        let as_lena = GatePrincipal::employee(h.a, lena);

        h.gate
            .authorize(&as_lena, email())
            .await
            .expect("email is allowed");
        let err = h
            .gate
            .authorize(&as_lena, sms())
            .await
            .expect_err("sms is not an allowed channel");
        assert_eq!(err.code(), DenyReason::ChannelNotAllowed.code());
        let err = h
            .gate
            .authorize(&as_lena, Untrusted::new(contract()))
            .await
            .expect_err("a contract from untrusted text is refused");
        assert_eq!(err.code(), DenyReason::UntrustedInput.code());
        // The same refusal, from a turn that knew who tainted it: the origin
        // is what `turn.rs` hands the gate, and the sender is masked on the
        // way in.
        let err = h
            .gate
            .authorize_from(
                &as_lena,
                Untrusted::new(contract()),
                Some(&TaintOrigin::message("email", "alice@supplier.example")),
            )
            .await
            .expect_err("a contract from an untrusted email is refused");
        assert_eq!(err.code(), DenyReason::UntrustedInput.code());
        match h
            .gate
            .authorize(&GatePrincipal::employee(h.a, mo), email())
            .await
        {
            Err(Denied::NotActive(_)) => {}
            other => panic!("a suspended seat is refused: {other:?}"),
        }
        // Le refus humain, dans la forme exacte de `routes::approvals::deny`.
        let mut tx = h.db.tenant_tx(h.a).await.expect("tenant tx");
        audit::append(
            &mut tx,
            &AuditEvent {
                employee_id: Some(lena),
                payload: json!({ "outcome": "denied" }),
                ..AuditEvent::new(
                    AuditActor::Operator("ops-a".to_owned()),
                    AuditKind::ApprovalDecided,
                    Utc::now(),
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");

        let (status, body) = h.refusals("/v1/refusals?days=7", SECRET_A).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 4, "{body}");

        assert_eq!(
            count_of(&body, "by_reason", "reason", "channel_not_allowed"),
            1
        );
        assert_eq!(count_of(&body, "by_reason", "reason", "untrusted_input"), 2);
        assert_eq!(
            count_of(&body, "by_reason", "reason", "employee_not_active"),
            1
        );
        assert_eq!(body["by_reason"].as_array().expect("by_reason").len(), 3);

        assert_eq!(
            count_of(&body, "by_action_kind", "action_kind", "sms_send"),
            1
        );
        assert_eq!(
            count_of(&body, "by_action_kind", "action_kind", "contract_sign"),
            2
        );
        assert_eq!(
            count_of(&body, "by_action_kind", "action_kind", "email_send"),
            1
        );

        assert_eq!(count_of(&body, "by_employee", "slug", "lena"), 3);
        assert_eq!(count_of(&body, "by_employee", "slug", "mo"), 1);
        assert_eq!(
            body["by_employee"][0]["slug"], "lena",
            "most refused first: {body}"
        );
        assert_eq!(body["by_employee"][0]["display_name"], "lena");

        let recent = body["recent"].as_array().expect("recent");
        assert_eq!(recent.len(), 4, "{body}");
        // Le plus récent d'abord : le siège suspendu est le dernier refus.
        assert_eq!(recent[0]["employee"]["slug"], "mo");
        assert_eq!(recent[0]["reason"], "employee_not_active");
        assert_eq!(recent[0]["action_kind"], "email_send");
        assert_eq!(recent[1]["reason"], "untrusted_input");
        assert_eq!(recent[2]["reason"], "untrusted_input");
        assert_eq!(recent[3]["reason"], "channel_not_allowed");
        for entry in recent {
            assert!(entry["at"].is_string(), "{entry}");
        }
        // La source, telle que la gate l'écrit : le refus d'un tour qui savait
        // d'où venait sa tache porte le canal et l'expéditeur masqué ; celui
        // d'un `Untrusted<Action>` sans origine ne porte que le label ; un
        // refus d'un tour propre n'en porte aucune — une source venue de nulle
        // part serait une fuite.
        assert_eq!(
            recent[1]["source"],
            json!({
                "trust_label": "untrusted",
                "channel": "email",
                "sender": "a…@supplier.example",
            }),
            "{body}"
        );
        assert_eq!(
            recent[2]["source"],
            json!({ "trust_label": "untrusted" }),
            "{body}"
        );
        assert!(recent[0].get("source").is_none(), "{body}");
        assert!(recent[3].get("source").is_none(), "{body}");
        // Le texte d'un payload ne sort pas, ni le destinataire, ni
        // l'expéditeur en clair.
        let rendered = body.to_string();
        assert!(!rendered.contains("prospect@example.com"), "{body}");
        assert!(!rendered.contains("supply agreement"), "{body}");
        assert!(!rendered.contains("alice@"), "{body}");

        // La fenêtre est bornée comme celle de `/v1/usage`.
        for bad in ["/v1/refusals?days=0", "/v1/refusals?days=400"] {
            let (status, _) = h.refusals(bad, SECRET_A).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} was accepted");
        }

        h.teardown().await;
    }

    /// Le locataire B ne voit pas les refus de A — ni dans un décompte, ni
    /// dans `recent` — et voit les siens.
    #[tokio::test]
    async fn one_tenants_refusals_are_invisible_to_another() {
        let Some(h) = Harness::new().await else {
            return;
        };
        let lena = employee(&h.db, h.a, "lena", "active").await;
        let bob = employee(&h.db, h.b, "bob", "active").await;
        for _ in 0..2 {
            h.gate
                .authorize(&GatePrincipal::employee(h.a, lena), sms())
                .await
                .expect_err("sms is refused");
        }
        h.gate
            .authorize(&GatePrincipal::employee(h.b, bob), sms())
            .await
            .expect_err("sms is refused");

        let (status, body) = h.refusals("/v1/refusals", SECRET_B).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 1, "{body}");
        assert_eq!(count_of(&body, "by_employee", "slug", "bob"), 1);
        assert_eq!(count_of(&body, "by_employee", "slug", "lena"), 0, "{body}");
        assert_eq!(body["recent"].as_array().expect("recent").len(), 1);
        assert_eq!(body["recent"][0]["employee"]["slug"], "bob");
        assert!(!body.to_string().contains("lena"), "{body}");

        let (_, body) = h.refusals("/v1/refusals", SECRET_A).await;
        assert_eq!(body["total"], 2, "{body}");
        assert!(!body.to_string().contains("bob"), "{body}");

        h.teardown().await;
    }

    #[test]
    fn days_is_a_window_ending_today() {
        let window = RefusalsQuery {
            days: Some(7),
            window: WindowQuery {
                from: None,
                to: None,
            },
        }
        .resolve()
        .expect("seven days");
        assert_eq!(window.to, Utc::now().date_naive());
        assert_eq!((window.to - window.from).num_days(), 6);
    }
}
