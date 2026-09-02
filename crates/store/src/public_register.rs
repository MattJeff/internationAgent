//! **Le registre public des refus** : ce que la gate a arrêté, agrégé, et rien
//! d'autre.
//!
//! # Ce que ce module ne peut pas lire, et pourquoi c'est un mécanisme
//!
//! Un registre public est une promesse faite à des entreprises qui ne sont pas
//! en train de la relire. La promesse tient si elle est impossible à trahir par
//! distraction, pas si elle est écrite quelque part.
//!
//! Deux consentements et une projection, dans cet ordre :
//!
//! * **Le consentement.** `tenants.public_register_opt_in`, `false` par défaut
//!   (0078). Une entreprise qui n'a rien accepté n'est pas filtrée à la lecture,
//!   elle n'existe pas dans la vue — donc pas non plus dans l'agrégat.
//! * **La projection.** [`REGISTER_TALLY_SQL`] lit `public_register_decisions`,
//!   une vue à quatre colonnes dont aucune ne désigne quelqu'un. Il n'y a pas de
//!   `tenant_id` à oublier dans un `GROUP BY`, pas de montant à arrondir de
//!   travers : la colonne n'est pas là. [`the_register_query_can_name_nothing_that_identifies`]
//!   relit la constante et échoue si un de ces noms y réapparaît, ce qui est le
//!   seul genre de garde qui survit à une modification pressée.
//! * **Le seuil.** Sous deux entreprises consentantes, l'appelant rend des zéros
//!   — voir [`consenting`]. Ce module compte, il ne décide pas ; mais il compte
//!   ce qu'il faut pour que la route puisse décider.
//!
//! # Dérivé, jamais accumulé
//!
//! Le même arbitrage que [`crate::billing`] et [`crate::capability`], et pour la
//! même raison : un `GROUP BY` sur le journal se recalcule un an plus tard,
//! contre un compteur qui ne vaut que la disponibilité du process qui
//! l'incrémente et dont l'erreur ne se voit jamais.
//!
//! [`the_register_query_can_name_nothing_that_identifies`]: tests::the_register_query_can_name_nothing_that_identifies

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};

use crate::db::{StoreError, TenantTx};

/// Combien d'entreprises ont accepté de figurer au registre.
///
/// `count(*)`, donc aucune ligne ne remonte : le nombre est la seule chose que
/// cette requête sache produire. Elle ne nomme que la colonne de consentement,
/// ce qui la fait passer la même garde que [`REGISTER_TALLY_SQL`].
pub const CONSENTING_SQL: &str = "SELECT count(*) FROM tenants WHERE public_register_opt_in";

/// Le décompte, groupé sur les trois colonnes qui classent une décision.
///
/// Un `GROUP BY` et pas quatre agrégats séparés : `decisions`, `refused`,
/// `held`, la ventilation par motif et celle par tranche sont **les mêmes lignes
/// comptées cinq fois**, donc elles ne peuvent pas se contredire. Un second
/// `SELECT` serait un second endroit où la définition de « décision » vivrait.
///
/// Pas de prédicat de locataire, et il n'y en a pas à écrire : la vue porte le
/// filtre de consentement et n'expose pas de quoi en distinguer un.
pub const REGISTER_TALLY_SQL: &str = "\
SELECT decision, deny_reason_code, held_bucket, count(*) AS tally \
  FROM public_register_decisions \
 WHERE occurred_at >= $1 AND occurred_at < $2 \
 GROUP BY decision, deny_reason_code, held_bucket";

/// La bascule du consentement.
///
/// Pas de `WHERE`, délibérément : la policy `tenant_isolation` de `tenants` est
/// `force`, donc la transaction ne voit qu'une ligne et c'est la sienne. Une
/// clause `WHERE id = $2` serait un second avis sur une question que la base
/// tranche déjà, et le seul cas où les deux pourraient diverger est celui où
/// l'un des deux est faux.
///
/// Et pas de `updated_at = now()` : 0078 accorde à `app_role` l'UPDATE d'une
/// seule colonne, donc toucher la seconde rend l'instruction impossible. C'est
/// la bonne direction — la date de la bascule est dans la ligne d'audit que la
/// route écrit dans la même transaction, et `updated_at` sur `tenants` ne dirait
/// pas *quoi* a changé.
const SET_CONSENT_SQL: &str = "UPDATE tenants SET public_register_opt_in = $1";

/// Une classe du décompte. Aucun champ ne désigne quelqu'un — c'est la forme de
/// la vue, pas une discipline de ce fichier.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Tally {
    /// `allow`, `deny` ou `require_approval`.
    pub decision: String,
    /// Le code du motif d'un refus, ou de l'escalade. `NULL` pour un `allow`.
    pub deny_reason_code: Option<String>,
    /// La tranche du montant retenu, ou `NULL` quand la décision n'en portait
    /// pas. Jamais la valeur.
    pub held_bucket: Option<String>,
    /// Combien de décisions dans cette classe.
    pub tally: i64,
}

/// Combien d'entreprises ont accepté.
///
/// Prend une transaction sans locataire : la question traverse par nature les
/// locataires, et c'est la seule chose que ce module ait le droit de faire à
/// travers eux.
pub async fn consenting(tx: &mut Transaction<'_, Postgres>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(CONSENTING_SQL)
        .fetch_one(&mut **tx)
        .await?)
}

/// Le décompte des décisions consenties sur `[since, until)`.
///
/// Bornes en `timestamptz` et non en dates : le journal est horodaté, et
/// convertir en date ici obligerait à choisir un fuseau une seconde fois.
pub async fn tally(
    tx: &mut Transaction<'_, Postgres>,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<Tally>, StoreError> {
    Ok(sqlx::query_as(REGISTER_TALLY_SQL)
        .bind(since)
        .bind(until)
        .fetch_all(&mut **tx)
        .await?)
}

/// Faire entrer ce locataire au registre, ou l'en retirer.
///
/// Retire aussi bien qu'ajoute : un consentement qu'on ne peut pas reprendre
/// n'est pas un consentement.
pub async fn set_consent(tx: &mut TenantTx<'_>, consent: bool) -> Result<(), StoreError> {
    sqlx::query(SET_CONSENT_SQL)
        .bind(consent)
        .execute(&mut ***tx)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agentos_domain::ids::TenantId;
    use agentos_domain::policy::{ApprovalReason, Decision, DenyReason};
    use chrono::Duration;
    use serde_json::json;

    use super::*;
    use crate::audit::{self, AuditActor, AuditEvent, AuditKind};
    use crate::db::Db;

    /// **La garde qui survit à une modification distraite.**
    ///
    /// Elle lit les requêtes elles-mêmes. Une colonne identifiante ne peut pas
    /// être ajoutée à la projection sans que ce test la voie, et elle ne peut
    /// pas non plus arriver par une jointure écrite ici — il n'y a qu'une table
    /// dans le `FROM`, et c'est une vue à quatre colonnes.
    ///
    /// La liste est celle des noms de colonnes qui désignent quelqu'un dans ce
    /// schéma, pas une liste de mots vaguement sensibles : un test qui
    /// interdirait « tenant » échouerait sur `FROM tenants`, qu'il faut bien
    /// écrire pour compter les consentements, et la première réaction serait de
    /// l'affaiblir.
    #[test]
    fn the_register_query_can_name_nothing_that_identifies() {
        for banned in [
            "tenant_id",
            "employee_id",
            "conversation_id",
            "decision_id",
            "slug",
            "display_name",
            "actor",
            "counterparty",
            "recipients",
            "sender",
            "payload",
            "amount_minor",
            "currency",
        ] {
            for (name, sql) in [
                ("REGISTER_TALLY_SQL", REGISTER_TALLY_SQL),
                ("CONSENTING_SQL", CONSENTING_SQL),
            ] {
                assert!(
                    !sql.to_lowercase().contains(banned),
                    "`{banned}` names somebody, and {name} must not be able to \
                     read it: {sql}"
                );
            }
        }
    }

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL is unset; the register is a SQL question");
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    async fn new_tenant(db: &Db) -> TenantId {
        let tenant = TenantId::new_v7(Utc::now());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'register')")
            .bind(tenant.as_uuid())
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        tx.commit().await.expect("commit");
        tenant
    }

    /// Le locataire s'en va ; ses lignes d'audit restent, parce que `audit_log`
    /// n'a pas de clé étrangère et ne se supprime pas — c'est le sujet de 0001.
    /// La vue les perd quand même : elle joint `tenants`, et la ligne n'est plus
    /// là. L'anonymat et le nettoyage sont le même mécanisme.
    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    /// Une décision, écrite comme la gate l'écrit.
    async fn decide(db: &Db, tenant: TenantId, decision: Decision, when: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        audit::append(
            &mut tx,
            &AuditEvent {
                decision: Some(decision),
                ..AuditEvent::new(
                    AuditActor::System,
                    AuditKind::Action(agentos_domain::action::ActionKind::EmailSend),
                    when,
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    /// Une escalade, avec la ligne `approvals` que la gate dépose dans la même
    /// transaction : c'est cette paire qui donne sa tranche au registre.
    async fn hold(db: &Db, tenant: TenantId, amount_minor: i64, when: DateTime<Utc>) {
        let approval = uuid::Uuid::now_v7();
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
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
                    summary: "pay".to_owned(),
                }),
                payload: json!({ "approval_id": approval.to_string() }),
                ..AuditEvent::new(
                    AuditActor::System,
                    AuditKind::Action(agentos_domain::action::ActionKind::PaymentCreate),
                    when,
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    /// Une décision dont le `payload` porte un `approval_id` qui n'est pas un
    /// UUID. Personne n'écrit ça exprès ; le point est que rien ne l'empêche.
    async fn junk_approval_id(db: &Db, tenant: TenantId, when: DateTime<Utc>) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        audit::append(
            &mut tx,
            &AuditEvent {
                decision: Some(Decision::Allow),
                payload: json!({ "approval_id": "pas-un-uuid" }),
                ..AuditEvent::new(
                    AuditActor::System,
                    AuditKind::Action(agentos_domain::action::ActionKind::EmailSend),
                    when,
                )
            },
        )
        .await
        .expect("append");
        tx.commit().await.expect("commit");
    }

    async fn consent(db: &Db, tenant: TenantId, yes: bool) {
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        set_consent(&mut tx, yes).await.expect("set consent");
        tx.commit().await.expect("commit");
    }

    /// **Le consentement est le mécanisme.** Deux entreprises font exactement
    /// les mêmes gestes ; seule celle qui a dit oui est comptée, et l'autre
    /// n'est pas soustraite de l'agrégat — elle n'y est jamais entrée.
    #[tokio::test]
    async fn a_company_that_consented_to_nothing_is_absent_even_from_the_aggregate() {
        let Some(db) = db().await else { return };
        // Une fenêtre lointaine et étroite, pas « maintenant » : cet agrégat
        // traverse les locataires par construction, donc deux tests qui
        // écriraient à la même seconde se compteraient l'un l'autre. Trois cents
        // jours en arrière, une heure de large, appartient à ce test seul.
        let now = Utc::now() - Duration::days(300);
        let yes = new_tenant(&db).await;
        let no = new_tenant(&db).await;

        for tenant in [yes, no] {
            decide(&db, tenant, Decision::Allow, now).await;
            decide(
                &db,
                tenant,
                Decision::Deny {
                    reason: DenyReason::ToolNotAllowed,
                },
                now,
            )
            .await;
            hold(&db, tenant, 250_000, now).await;
        }
        // **La ligne qui faisait tomber le registre entier.** `payload` est un
        // objet libre : rien n'oblige `approval_id` à être un UUID, et le
        // premier écrit de la vue joignait `approvals` par
        // `(payload ->> 'approval_id')::uuid`. Le `decision = 'require_approval'`
        // d'à côté ne gardait pas le cast — le planificateur réordonne — donc
        // cette ligne-ci, un `allow` d'un locataire consentant, faisait rendre
        // 500 à `GET /v1/public-register` pour tous les visiteurs, sans recours
        // puisque `audit_log` est en ajout seul. La comparaison en texte ne peut
        // pas lever ; la tranche est simplement nulle.
        junk_approval_id(&db, yes, now).await;
        consent(&db, yes, true).await;

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rows = tally(&mut tx, now - Duration::hours(1), now + Duration::hours(1))
            .await
            .expect("tally");
        tx.rollback().await.expect("rollback");

        let total: i64 = rows.iter().map(|row| row.tally).sum();
        assert_eq!(
            total, 4,
            "only the consenting company's four rows: {rows:?}"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.deny_reason_code.as_deref() == Some("tool_not_allowed"))
                .map(|row| row.tally)
                .sum::<i64>(),
            1
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.decision == "require_approval")
                .and_then(|row| row.held_bucket.as_deref()),
            Some("1k_5k"),
            "2 500,00 € falls in 1k_5k, and the exact amount never leaves the database"
        );

        // Et le retrait est aussi réel que l'entrée.
        //
        // Sur les lignes, et pas sur [`consenting`] : ce compteur est mondial,
        // donc un `before - 1` serait une assertion sur ce que les autres tests
        // font à la même seconde. C'est le prix de l'anonymat et il est correct
        // — rien ici ne peut demander « combien, dont celui-ci ». Le seuil est
        // vérifié de bout en bout par `routes::public_register`, où il y a une
        // réponse HTTP à lire.
        consent(&db, yes, false).await;
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let rows = tally(&mut tx, now - Duration::hours(1), now + Duration::hours(1))
            .await
            .expect("tally");
        tx.rollback().await.expect("rollback");
        assert!(rows.is_empty(), "consent withdrawn, rows gone: {rows:?}");

        drop_tenant(&db, yes).await;
        drop_tenant(&db, no).await;
    }

    /// Un locataire ne peut basculer que sa propre ligne, et rien d'autre dans
    /// `tenants` : le GRANT de 0078 est par colonne, la policy borne la ligne.
    #[tokio::test]
    async fn a_tenant_can_flip_its_own_flag_and_nothing_else_about_itself() {
        let Some(db) = db().await else { return };
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        consent(&db, a, true).await;

        let mut tx = db.tenant_tx(a).await.expect("tenant tx");
        // La même instruction, sans `WHERE`, ne touche toujours qu'une ligne.
        let renamed = sqlx::query("UPDATE tenants SET name = 'stolen'")
            .execute(&mut **tx)
            .await;
        assert!(renamed.is_err(), "app_role holds UPDATE on one column only");
        tx.rollback().await.expect("rollback");

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        let flags: Vec<bool> =
            sqlx::query_scalar("SELECT public_register_opt_in FROM tenants WHERE id = ANY($1)")
                .bind(vec![a.as_uuid(), b.as_uuid()])
                .fetch_all(&mut *tx)
                .await
                .expect("flags");
        tx.rollback().await.expect("rollback");
        assert_eq!(flags.iter().filter(|on| **on).count(), 1, "{flags:?}");

        drop_tenant(&db, a).await;
        drop_tenant(&db, b).await;
    }
}
