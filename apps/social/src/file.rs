//! File durable : créneaux, approbation, et le passage du worker.
//!
//! Rien ici n'appelle une plateforme. Ça pose des lignes, ça les reprend, et
//! ça demande à `mcp` de publier avec la clé déjà posée — l'idempotence de
//! `social_posts` empêche le double post quand un essai a réussi sans qu'on
//! ait eu le temps de le noter.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::mcp::{self, Erreur};
use crate::store::{self, LigneFile, PoseFile};

/// ISO 8601 / RFC 3339. Une date illisible est un argument, pas un créneau.
pub(crate) fn parse_quand(texte: &str) -> Result<DateTime<Utc>, Erreur> {
    DateTime::parse_from_rfc3339(texte)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| {
            Erreur::nouvelle(
                "argument_invalide",
                format!("`publish_at` doit être une date RFC 3339, pas `{texte}`"),
            )
        })
}

pub fn json_ligne(ligne: &LigneFile, replayed: bool) -> Value {
    json!({
        "scheduled_id": ligne.id,
        "account_id": ligne.account_id,
        "idempotency_key": ligne.idempotency_key,
        "kind": ligne.kind,
        "digest": ligne.digest,
        "status": ligne.status,
        "publish_at": ligne.publish_at.map(|d| d.to_rfc3339()),
        "attempts": ligne.attempts,
        "post_id": ligne.post_id,
        "replayed": replayed,
    })
}

/// Pose la ligne. `Err` de digest différent = clé déjà prise par un autre contenu.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poser(
    etat: &mcp::Etat,
    tenant: Uuid,
    compte: Uuid,
    cle: &str,
    kind: &str,
    payload: &Value,
    digest: &str,
    publish_at: Option<DateTime<Utc>>,
    en_attente: bool,
) -> Result<Value, Erreur> {
    let status = if en_attente {
        "pending_approval"
    } else {
        "scheduled"
    };
    let expires = if en_attente {
        Some(Utc::now() + chrono::Duration::hours(etat.approval_ttl_hours))
    } else {
        None
    };
    match store::poser_file(
        &etat.pool, tenant, compte, cle, kind, payload, digest, publish_at, status, expires,
    )
    .await?
    {
        Ok(PoseFile::Nouvelle(ligne)) => Ok(json_ligne(&ligne, false)),
        Ok(PoseFile::Meme(ligne)) => Ok(json_ligne(&ligne, true)),
        Err(()) => Err(Erreur::nouvelle(
            "cle_reutilisee",
            "cette idempotency_key a déjà servi pour un AUTRE contenu",
        )),
    }
}

/// Le worker : expire, reprend les publications coincées, poste une échéance.
pub(crate) async fn passer(etat: &mcp::Etat) -> Result<(), Erreur> {
    store::expirer_file(&etat.pool).await?;
    store::reprendre_publishing_perime(&etat.pool).await?;
    let Some(ligne) = store::prendre_echeance(&etat.pool).await? else {
        return Ok(());
    };
    match executer(etat, &ligne).await {
        Ok(valeur) => {
            if ligne.kind == "youtube" {
                store::marquer_file_resultat(&etat.pool, ligne.id, &valeur).await?;
                return Ok(());
            }
            let etat_pub = valeur
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("published");
            let post_id = valeur
                .get("post_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok());
            if etat_pub == "published" {
                if let Some(post_id) = post_id {
                    store::marquer_file_publiee(&etat.pool, ligne.id, post_id).await?;
                }
            } else {
                // `partial` ou `failed` : la clé dans social_posts reprendra
                // là où le fil s'est arrêté, sans renvoyer le début.
                store::marquer_file_echec(
                    &etat.pool,
                    ligne.id,
                    true,
                    store::delai_reessai(ligne.attempts + 1),
                    etat_pub,
                )
                .await?;
            }
            Ok(())
        }
        Err(e) => {
            let suivant = ligne.attempts + 1;
            let reprendre = suivant < 5;
            store::marquer_file_echec(
                &etat.pool,
                ligne.id,
                reprendre,
                store::delai_reessai(suivant),
                &e.message,
            )
            .await?;
            Ok(())
        }
    }
}

pub(crate) async fn executer(etat: &mcp::Etat, ligne: &LigneFile) -> Result<Value, Erreur> {
    let mut args = ligne.payload.clone();
    if let Some(objet) = args.as_object_mut() {
        objet.insert("idempotency_key".to_owned(), json!(ligne.idempotency_key));
        objet.insert("account_id".to_owned(), json!(ligne.account_id.to_string()));
    }
    if ligne.kind == "thread" {
        mcp::publier_fil(etat, ligne.tenant_id, &args, true).await
    } else if ligne.kind == "youtube" {
        crate::youtube_outils::executer_depuis_la_file(etat, ligne).await
    } else {
        mcp::publier_depuis_la_file(etat, ligne.tenant_id, &args).await
    }
}
