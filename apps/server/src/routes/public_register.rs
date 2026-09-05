//! **Le registre public** : ce que la gate a refusé, publié, et rien d'autre.
//!
//! # Pourquoi ce chiffre-là
//!
//! nanocorp.so publie en temps réel l'argent que ses entreprises ont gagné, et
//! c'est tout leur marketing. On ne peut pas transposer le chiffre — on vend à
//! de vraies entreprises, dont le chiffre d'affaires ne nous appartient pas et
//! ne nous regarde pas. Mais on peut transposer la forme : **un tableau public,
//! en temps réel, d'un nombre que seul ce produit possède.**
//!
//! Ce nombre est ce que la gate a arrêté. Il ne s'invente pas — chaque unité
//! vient d'une ligne d'un journal en ajout seul — et un concurrent sans gate ne
//! peut pas le copier, parce qu'il n'a rien à mettre dedans. C'est la seule
//! preuve de ce genre que ce dépôt produise.
//!
//! # Trois choses le rendent publiable, et aucune n'est une intention
//!
//! 1. **Le consentement explicite, jamais par défaut.**
//!    `tenants.public_register_opt_in` (0078) est `false` à la création. Une
//!    entreprise qui n'a rien accepté n'apparaît pas, y compris agrégée : elle
//!    n'est pas filtrée à la lecture, elle est absente de la vue que la requête
//!    lit. `POST /v1/public-register/consent` la fait entrer, et l'en retire.
//! 2. **L'anonymat est une projection.** [`agentos_store::public_register`]
//!    porte l'argument en entier : la requête ne peut nommer ni locataire, ni
//!    employé, ni bénéficiaire, ni montant, parce que ces colonnes ne sont pas
//!    dans la vue. Un test relit la requête et échoue si l'un de ces noms y
//!    réapparaît.
//! 3. **Le seuil de deux.** Sous deux entreprises consentantes, la route rend
//!    des zéros et `tenants: 0`, sans agrégat — et ne lit même pas le journal.
//!    Avec un seul participant, « agrégé » est un mot qui ment : chaque ligne du
//!    tableau est la sienne, et publier « 47 refus » revient à publier son
//!    activité sous une étiquette qui prétend le contraire.
//!
//! # Pas de clé, et surtout pas la liste blanche `platform/*`
//!
//! Un registre public derrière une clé n'est pas un registre public — c'est la
//! même raison que `well_known` et que la carte d'agent, montés sur le même
//! étage. Il est **hors** de `with_api_stack`.
//!
//! Et hors de `platform/*` aussi, qui est un autre débat : cet étage-là protège
//! l'émission de clés, c'est-à-dire un pouvoir. Ceci est une lecture agrégée
//! d'un consentement déjà donné. Les mettre derrière la même porte reviendrait à
//! dire que lire et pouvoir sont la même chose.
//!
//! Ce que ça implique, dit franchement : la route lit à travers les locataires,
//! par `admin_tx_bypassing_rls`, sans credential. C'est le seul endroit du dépôt
//! qui fait ça, et il ne le peut que parce que la vue derrière lui est
//! incapable de distinguer un locataire d'un autre. La RLS n'est pas contournée
//! au profit d'un appelant de confiance ; elle est remplacée par une projection
//! qui n'a rien à protéger.
//!
//! # Ce que la fenêtre ne fait pas
//!
//! `?days=` borne combien de jours en arrière, pas plus. Il n'y a ni `from` ni
//! `to` : des bornes libres sur un agrégat public sont un outil de
//! dé-anonymisation — deux requêtes qui diffèrent d'une heure isolent une
//! décision, et une décision isolée a un auteur. Une fenêtre qui finit toujours
//! aujourd'hui laisse la différence entre deux appels être du temps qui passe.

use agentos_store::audit::{self, AuditEvent, AuditKind};
use agentos_store::db::{Db, StoreError};
use agentos_store::public_register::{self, Tally};
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get as get_route, post as post_route};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::Principal;
use crate::error::ApiError;

/// Fenêtre par défaut, la même que `/v1/autonomy` : trente jours est ce que
/// « récemment » veut dire partout ailleurs dans ce produit.
const DEFAULT_DAYS: i64 = 30;

/// Au-delà, la requête scanne un journal entier pour un tableau que personne ne
/// lit à cette profondeur. Un an est aussi la limite de [`super::autonomy`].
const MAX_DAYS: i64 = 365;

/// Sous ce nombre d'entreprises consentantes, « agrégé » est un mot qui ment.
const MIN_TENANTS: i64 = 2;

/// La route publique. Sans credential — voir les docs du module.
pub fn public_router(db: Db) -> Router {
    Router::new()
        .route("/v1/public-register", get_route(get))
        .with_state(db)
}

/// La bascule du consentement. Celle-ci, en revanche, est l'acte d'un locataire
/// identifié et vit sur l'étage à clé.
pub fn router(db: Db) -> Router {
    Router::new()
        .route("/v1/public-register/consent", post_route(consent))
        .with_state(db)
}

// ---------------------------------------------------------------------------
// La lecture
// ---------------------------------------------------------------------------

/// `?days=30`.
#[derive(Debug, Deserialize)]
struct DaysQuery {
    days: Option<i64>,
}

/// Un motif de refus et combien de fois il a servi.
#[derive(Debug, Serialize)]
struct ReasonLine {
    /// Le code stable du refus — `tool_not_allowed`. Jamais une phrase : les
    /// codes viennent de `DenyReason::code`, dont le vocabulaire est fermé et
    /// écrit dans ce dépôt, donc rien qu'un tiers a choisi ne peut atterrir ici.
    reason: String,
    count: i64,
}

/// Une tranche de montant retenu, jamais un montant.
#[derive(Debug, Serialize)]
struct AmountLine {
    /// `0_100`, `100_1k`, `1k_5k`, `gt_5k`.
    bucket: String,
    count: i64,
}

/// Le registre.
#[derive(Debug, Serialize)]
struct RegisterView {
    /// Inclusive, UTC.
    since: NaiveDate,
    /// Inclusive, UTC.
    until: NaiveDate,
    /// Combien d'entreprises ont accepté. Zéro quand le seuil n'est pas atteint,
    /// y compris s'il y en a une : le tableau ne dit pas « une ».
    tenants: i64,
    /// Décisions de la fenêtre, permises et refusées.
    decisions: i64,
    /// Celles que la gate a refusées.
    refused: i64,
    /// Celles qui attendent un humain.
    held: i64,
    /// Les motifs des refus, le plus fréquent d'abord.
    by_reason: Vec<ReasonLine>,
    /// Les tranches de ce qui est retenu. Somme ≤ `held` : une décision retenue
    /// qui ne portait pas d'argent n'a pas de tranche.
    held_amounts: Vec<AmountLine>,
    /// Quand ce tableau a été calculé. Il n'est mis en cache nulle part, donc
    /// c'est aussi l'heure de la requête — mais un lecteur ne devrait pas avoir
    /// à le savoir pour dater le chiffre.
    generated_at: DateTime<Utc>,
}

/// Trier par fréquence décroissante, puis par nom.
///
/// Le second critère n'est pas cosmétique : deux motifs à égalité doivent sortir
/// dans le même ordre à chaque appel, sinon un tableau public qui n'a pas bougé
/// a l'air d'avoir bougé.
pub(super) fn ranked<T>(
    mut lines: Vec<T>,
    count: impl Fn(&T) -> i64,
    key: impl Fn(&T) -> String,
) -> Vec<T> {
    lines.sort_by(|a, b| count(b).cmp(&count(a)).then_with(|| key(a).cmp(&key(b))));
    lines
}

/// Replier le décompte en un tableau.
///
/// Les cinq nombres viennent des mêmes lignes comptées cinq fois, donc
/// `refused + held ≤ decisions` tient par construction et non par relecture.
fn fold(rows: &[Tally], since: NaiveDate, until: NaiveDate, tenants: i64) -> RegisterView {
    let sum = |keep: &dyn Fn(&Tally) -> bool| -> i64 {
        rows.iter()
            .filter(|row| keep(row))
            .map(|row| row.tally)
            .sum()
    };

    let mut by_reason: std::collections::BTreeMap<String, i64> = Default::default();
    let mut held_amounts: std::collections::BTreeMap<String, i64> = Default::default();
    for row in rows {
        // Le motif d'une escalade n'est pas un motif de refus : `deny_reason_code`
        // porte les deux (voir `audit::decision_columns`), et les mélanger ferait
        // apparaître `payment_above_threshold` dans une liste intitulée « ce que
        // nous avons refusé », ce qui est faux — cette décision-là n'est pas
        // refusée, elle attend quelqu'un.
        if row.decision == "deny"
            && let Some(reason) = &row.deny_reason_code
        {
            *by_reason.entry(reason.clone()).or_default() += row.tally;
        }
        if let Some(bucket) = &row.held_bucket {
            *held_amounts.entry(bucket.clone()).or_default() += row.tally;
        }
    }

    RegisterView {
        since,
        until,
        tenants,
        decisions: sum(&|_| true),
        refused: sum(&|row| row.decision == "deny"),
        held: sum(&|row| row.decision == "require_approval"),
        by_reason: ranked(
            by_reason
                .into_iter()
                .map(|(reason, count)| ReasonLine { reason, count })
                .collect(),
            |line| line.count,
            |line| line.reason.clone(),
        ),
        held_amounts: ranked(
            held_amounts
                .into_iter()
                .map(|(bucket, count)| AmountLine { bucket, count })
                .collect(),
            |line| line.count,
            |line| line.bucket.clone(),
        ),
        generated_at: Utc::now(),
    }
}

/// `GET /v1/public-register?days=30`.
async fn get(
    State(db): State<Db>,
    query: Result<Query<DaysQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|err| ApiError::bad_request(err.body_text()))?;
    let days = query.days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "days: between 1 and {MAX_DAYS}"
        )));
    }

    let now = Utc::now();
    let until = now.date_naive();
    let since = until - Duration::days(days);

    let mut tx = db.admin_tx_bypassing_rls().await?;
    let tenants = public_register::consenting(&mut tx).await?;

    // Le seuil est un `return`, pas un champ mis à zéro après coup : sous deux
    // participants le journal n'est pas lu du tout, donc il n'y a pas de version
    // de ce code où un agrégat d'un seul consentant existe en mémoire et attend
    // qu'on pense à ne pas le sérialiser.
    if tenants < MIN_TENANTS {
        tx.rollback().await.map_err(StoreError::from)?;
        return Ok(axum::Json(fold(&[], since, until, 0)).into_response());
    }

    let rows = public_register::tally(
        &mut tx,
        since.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc(),
        now,
    )
    .await?;
    tx.rollback().await.map_err(StoreError::from)?;

    Ok(axum::Json(fold(&rows, since, until, tenants)).into_response())
}

// ---------------------------------------------------------------------------
// Le consentement
// ---------------------------------------------------------------------------

/// `{"consent": true}`.
///
/// Un booléen obligatoire et pas un verbe dans l'URL : retirer son consentement
/// doit être exactement aussi facile que le donner, sur la même route, avec la
/// même forme.
#[derive(Debug, Deserialize, Serialize)]
struct Consent {
    consent: bool,
}

/// `POST /v1/public-register/consent`.
///
/// La bascule et sa ligne d'audit dans la même transaction : un registre dont
/// on ne peut pas prouver quand une entreprise y est entrée est un registre
/// qu'on ne peut pas défendre.
async fn consent(
    State(db): State<Db>,
    principal: Principal,
    body: Result<axum::Json<Consent>, JsonRejection>,
) -> Result<Response, ApiError> {
    let axum::Json(body) = body.map_err(|err| ApiError::bad_request(err.body_text()))?;

    let mut tx = db.tenant_tx(principal.tenant_id).await?;
    public_register::set_consent(&mut tx, body.consent).await?;
    audit::append(
        &mut tx,
        &AuditEvent {
            payload: serde_json::json!({
                "event": "public_register.consent",
                "consent": body.consent,
            }),
            ..AuditEvent::new(
                principal.actor.clone(),
                AuditKind::PolicyChanged,
                Utc::now(),
            )
        },
    )
    .await?;
    tx.commit().await?;

    Ok(axum::Json(body).into_response())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::action::ActionKind;
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::{ApprovalReason, Decision, DenyReason};
    use agentos_store::audit::{AuditActor, AuditKind};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ApiKeys;

    const SECRET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SECRET_C: &str = "cccccccccccccccccccccccccccccccc";

    /// **Le motif que seules les entreprises consentantes émettent dans ce
    /// test**, et celui que seule la non-consentante émet. C'est ce qui rend les
    /// assertions insensibles à ce que d'autres tests écrivent dans la même base
    /// à la même seconde : le registre est un agrégat mondial, donc un total
    /// brut serait une assertion sur tout le reste du dépôt.
    const CONSENTED_REASON: &str = "tool_not_allowed";
    const WITHHELD_REASON: &str = "domain_denied";

    struct Harness {
        app: Router,
        db: Db,
        a: TenantId,
        b: TenantId,
        c: TenantId,
    }

    impl Harness {
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!("SKIP: DATABASE_URL is unset; the register is a SQL question");
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            // Le registre est un agrégat mondial, donc le seuil de deux se
            // mesure sur *toute* la base : un consentement laissé derrière lui
            // par un run interrompu fait échouer chaque run suivant, et le
            // symptôme (« tenants: 1 ») ne ressemble pas du tout à sa cause.
            // Dans une base de test, un locataire consentant est par définition
            // un résidu.
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query("UPDATE tenants SET public_register_opt_in = false")
                .execute(&mut *tx)
                .await
                .expect("reset consent");
            tx.commit().await.expect("commit");

            let a = new_tenant(&db).await;
            let b = new_tenant(&db).await;
            let c = new_tenant(&db).await;
            let keys = ApiKeys::parse(&format!(
                "ops-a:{}:{SECRET_A},ops-b:{}:{SECRET_B},ops-c:{}:{SECRET_C}",
                a.as_uuid(),
                b.as_uuid(),
                c.as_uuid()
            ))
            .expect("keyring");

            Some(Self {
                // Les deux étages, comme `main` les monte : la lecture nue, la
                // bascule derrière la clé. Un test qui n'assemblerait que le
                // second ne dirait rien de la question qui compte ici.
                app: public_router(db.clone()).merge(crate::with_api_stack(
                    router(db.clone()),
                    db.clone(),
                    crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY),
                )),
                db,
                a,
                b,
                c,
            })
        }

        /// Sans credential — c'est la moitié du sujet.
        async fn register(&self) -> (StatusCode, Value) {
            self.send(
                HttpRequest::builder()
                    .method("GET")
                    .uri("/v1/public-register")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
        }

        async fn consent(&self, tenant_secret: &str, yes: bool) -> StatusCode {
            self.send(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/public-register/consent")
                    .header(header::AUTHORIZATION, format!("Bearer {tenant_secret}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "consent": yes }).to_string()))
                    .expect("request"),
            )
            .await
            .0
        }

        async fn send(&self, req: HttpRequest<Body>) -> (StatusCode, Value) {
            let response = self.app.clone().oneshot(req).await.expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        async fn decide(&self, tenant: TenantId, decision: Decision) {
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            audit::append(
                &mut tx,
                &AuditEvent {
                    decision: Some(decision),
                    ..AuditEvent::new(
                        AuditActor::System,
                        AuditKind::Action(ActionKind::EmailSend),
                        Utc::now(),
                    )
                },
            )
            .await
            .expect("append");
            tx.commit().await.expect("commit");
        }

        /// Une escalade et la ligne `approvals` que la gate dépose avec elle.
        async fn hold(&self, tenant: TenantId, amount_minor: i64) {
            let approval = Uuid::now_v7();
            let mut tx = self.db.tenant_tx(tenant).await.expect("tenant tx");
            sqlx::query(
                "INSERT INTO approvals (id, tenant_id, action_kind, amount_minor, currency) \
                 VALUES ($1, $2, 'payment_create', $3, 'EUR')",
            )
            .bind(approval)
            .bind(tenant.as_uuid())
            .bind(amount_minor)
            .execute(&mut **tx)
            .await
            .expect("insert approval");
            audit::append(
                &mut tx,
                &AuditEvent {
                    decision: Some(Decision::RequireApproval {
                        reason: ApprovalReason::PaymentAboveThreshold,
                        summary: "pay the supplier".to_owned(),
                    }),
                    payload: json!({ "approval_id": approval.to_string() }),
                    ..AuditEvent::new(
                        AuditActor::System,
                        AuditKind::Action(ActionKind::PaymentCreate),
                        Utc::now(),
                    )
                },
            )
            .await
            .expect("append");
            tx.commit().await.expect("commit");
        }

        async fn teardown(self) {
            for tenant in [self.a, self.b, self.c] {
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
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'register-route')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    fn count_of(body: &Value, list: &str, key: &str, value: &str) -> i64 {
        body[list]
            .as_array()
            .expect(list)
            .iter()
            .find(|line| line[key] == value)
            .and_then(|line| line["count"].as_i64())
            .unwrap_or(0)
    }

    /// **Le registre entier, en un test**, parce qu'il agrège tous les
    /// locataires : deux tests en parallèle se compteraient l'un l'autre, et un
    /// registre qui dépend de l'ordonnanceur de `cargo test` ne prouve rien.
    ///
    /// Il vérifie, dans l'ordre, les quatre choses qui font tenir la publication :
    /// le consentement, le seuil de deux, l'anonymat sur le fil, et le retrait.
    #[tokio::test]
    async fn the_register_publishes_only_what_two_companies_agreed_to_and_names_none_of_them() {
        let Some(h) = Harness::new().await else {
            return;
        };

        // A et B consentent, C non — et C fait exactement les mêmes gestes.
        for tenant in [h.a, h.b, h.c] {
            h.decide(tenant, Decision::Allow).await;
            h.hold(tenant, 250_000).await;
        }
        for _ in 0..2 {
            h.decide(
                h.a,
                Decision::Deny {
                    reason: DenyReason::ToolNotAllowed,
                },
            )
            .await;
        }
        h.decide(
            h.b,
            Decision::Deny {
                reason: DenyReason::ToolNotAllowed,
            },
        )
        .await;
        h.decide(
            h.c,
            Decision::Deny {
                reason: DenyReason::DomainDenied,
            },
        )
        .await;

        // --- Un seul consentant : des zéros, et pas un agrégat d'un seul.
        assert_eq!(h.consent(SECRET_A, true).await, StatusCode::OK);
        let (status, body) = h.register().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tenants"], 0, "one participant is not an aggregate");
        assert_eq!(body["decisions"], 0, "{body}");
        assert_eq!(body["refused"], 0, "{body}");
        assert_eq!(body["held"], 0, "{body}");
        assert!(body["by_reason"].as_array().expect("by_reason").is_empty());
        assert!(
            body["held_amounts"]
                .as_array()
                .expect("held_amounts")
                .is_empty()
        );

        // --- Deux : le tableau existe.
        assert_eq!(h.consent(SECRET_B, true).await, StatusCode::OK);
        let (status, body) = h.register().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["tenants"].as_i64().expect("tenants") >= 2, "{body}");

        // Trois refus chez A et B, et rien de C : le motif de C n'est pas
        // soustrait du tableau, il n'y est jamais entré.
        assert_eq!(count_of(&body, "by_reason", "reason", CONSENTED_REASON), 3);
        assert_eq!(
            count_of(&body, "by_reason", "reason", WITHHELD_REASON),
            0,
            "a company that consented to nothing appears nowhere, not even aggregated: {body}"
        );
        // Le motif d'une escalade n'est pas un motif de refus.
        assert_eq!(
            count_of(&body, "by_reason", "reason", "payment_above_threshold"),
            0,
            "{body}"
        );
        assert!(body["refused"].as_i64().expect("refused") >= 3, "{body}");
        assert!(body["held"].as_i64().expect("held") >= 2, "{body}");
        assert!(
            body["decisions"].as_i64().expect("decisions")
                >= body["refused"].as_i64().unwrap() + body["held"].as_i64().unwrap(),
            "the three headline numbers are one population counted three ways: {body}"
        );
        // 2 500,00 € tombe dans `1k_5k`, deux fois, et le montant n'est nulle
        // part.
        assert_eq!(count_of(&body, "held_amounts", "bucket", "1k_5k"), 2);

        // --- L'anonymat, sur le fil, contre le document entier: un champ ajouté
        // plus tard est attrapé par la forme de la réponse et pas par un
        // relecteur.
        let rendered = body.to_string().to_lowercase();
        for banned in [
            h.a.as_uuid().to_string(),
            h.b.as_uuid().to_string(),
            h.c.as_uuid().to_string(),
            "register-route".to_owned(),
            "250000".to_owned(),
            "2500".to_owned(),
            "eur".to_owned(),
            "pay the supplier".to_owned(),
        ] {
            assert!(
                !rendered.contains(&banned.to_lowercase()),
                "`{banned}` identifies or prices somebody in a public register: {body}"
            );
        }

        // --- Le retrait est aussi réel que l'entrée : on repasse sous le seuil.
        assert_eq!(h.consent(SECRET_B, false).await, StatusCode::OK);
        let (_, body) = h.register().await;
        assert_eq!(body["tenants"], 0, "{body}");
        assert_eq!(body["decisions"], 0, "{body}");

        // --- Et la fenêtre est bornée.
        for bad in ["/v1/public-register?days=0", "/v1/public-register?days=400"] {
            let (status, _) = h
                .send(
                    HttpRequest::builder()
                        .method("GET")
                        .uri(bad)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} was accepted");
        }

        h.teardown().await;
    }
}
