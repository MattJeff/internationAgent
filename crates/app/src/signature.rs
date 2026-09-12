//! **La signature d'un document** : le pli qu'on envoie, la décision humaine
//! qui le libère, et l'exemplaire exécuté qui prouve qu'elle a eu lieu.
//!
//! `migrations/0105_une_signature_est_un_constat.sql` porte la table et son
//! argument ; `crate::effects::Effects::send_for_signature` porte l'effet ;
//! ceci est ce qui les tient ensemble, comme `crate::content` tient la boucle
//! de citation.
//!
//! # Qui signe : personne, seul
//!
//! La réponse ne vient pas de ce fichier, elle vient de
//! `domain::policy::evaluate`, et elle est déjà écrite :
//!
//! ```text
//! Action::ContractSign { title } => Decision::RequireApproval { … }
//! ```
//!
//! Sans condition. Pas de seuil, pas de champ de politique, pas d'`if` — le
//! commentaire du domaine dit *« signing binds the tenant, so a human signs
//! off »*. Les trois familles de packs de rôles le disent aussi, chacune dans
//! ses mots : `rolepack_sales` (*« `ContractSign` est absent, et le gate
//! l'escalade plutôt qu'il ne le refuse »*), `rolepack_service` (*« aucun
//! d'entre eux ne peut signer quoi que ce soit »*) et `rolepack`, où le pack
//! acheteur le **propose** — c'est-à-dire dépose la demande dans la file d'un
//! humain — sans jamais l'obtenir.
//!
//! Donc un siège peut *mettre une signature sur la table*, et rien d'autre. Ce
//! module n'élargit pas d'un cran : il donne un exécuteur à la décision que
//! l'humain prenait déjà et qui ne menait nulle part.
//!
//! **Et c'est le bon cran, pas un cran trop haut.** Le cran du dessous serait
//! celui d'un paiement — `approval_above`, les petits passent, les gros
//! montent. Il ne s'applique pas ici : un contrat n'a pas de montant qui joue
//! le rôle que le montant joue pour un paiement (un contrat à un euro porte une
//! reconduction tacite ou une exclusivité), et `Action::ContractSign` ne porte
//! qu'un **titre**, c'est-à-dire de la prose — un seuil serait une règle sur une
//! phrase. `Effects::send_for_signature` porte l'argument complet, dont la
//! moitié qui décide : une facture fausse s'annule par un avoir, un paiement
//! faux se rattrape par un second paiement, **et une signature n'a pas de
//! second document qui la retire.**
//!
//! # « Signé » est un constat, et la base l'oblige
//!
//! Ce dépôt a déjà cette discipline deux fois. `content_drafts.url` est une
//! adresse **constatée** — quelqu'un a vu l'article là — et un CHECK interdit de
//! mentir sur le mot *publié*. `POST /v1/invoices/{id}/paid` est un acte
//! d'opérateur parce que rien dans ce processus n'observe un paiement.
//!
//! Une signature arrive pareil, et `0105` la tient par la contrainte plutôt que
//! par la bonne volonté : `signed_at` ne s'écrit **que** si `executed_name`
//! nomme un fichier du classeur, et cet exemplaire exécuté ne peut pas être le
//! document qu'on a envoyé. Il n'y a donc aucun chemin — ni route, ni employé,
//! ni opérateur — qui écrive « signé » sans que les octets signés soient
//! d'abord déposés. Le mot ne peut pas mentir.
//!
//! Ce qui reste affirmé, dit franchement : **que ces octets-là soient bien ce
//! que le prestataire a produit.** La route qui les enregistre est une clé
//! d'opérateur, exactement comme celle qui encaisse une facture. Le jour où
//! DocuSign Connect pousse la complétion, l'écrivain change et `0105` explique
//! ce que la table gagne ce jour-là ; ce n'est pas ici parce qu'un vérificateur
//! de webhook a besoin du **nom de l'en-tête** où le prestataire met sa
//! signature, et qu'aucun compte n'existe pour l'avoir lu une fois. Ce dépôt
//! refuse déjà de le deviner ailleurs — `inbound::SMARTLEAD_SIGNATURE_HEADER`
//! vaut `None` et refuse toutes les livraisons pour cette raison exacte.
//!
//! # L'ordre, et ce qu'il coûte quand il casse
//!
//! ```text
//! prepare  -> la Gate statue, une approbation est déposée, la ligne est écrite
//! approve  -> un humain décide ; la rédemption rend le jeton, l'effet envoie
//! signed   -> l'exemplaire exécuté est déposé, puis la ligne le nomme
//! ```
//!
//! La première étape dépose l'approbation **avant** d'écrire la ligne, parce
//! que la ligne porte l'identifiant de l'approbation. Si l'écriture échoue après
//! coup, ce qui reste est une approbation orpheline dans la file d'un humain :
//! l'approuver retombe sur le chemin que `routes::approvals` a toujours eu pour
//! un `ContractSign` — émis, rapporté, jeté — donc rien ne part. C'est la
//! direction d'échec sûre, et c'est pourquoi le document est vérifié avant que
//! la Gate soit appelée plutôt qu'après.

use agentos_domain::action::McpTool;
use agentos_domain::ids::{EmployeeId, Slug};
use agentos_providers::email::ProviderMessageId;
use agentos_store::db::{Db, StoreError, TenantTx};
use agentos_store::files;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::effects::{ContractSign, EffectError, Effects, SignatureRequest};
use crate::gate::{Authorized, Denied, PolicyGate, Principal};

/// Un pli, tel qu'il est rangé. Une ligne de `signature_envelopes`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Envelope {
    pub id: Uuid,
    /// Le siège pour lequel la Gate a statué.
    pub employee_id: Uuid,
    /// La décision humaine dont ce pli dépend, et la seule porte vers l'envoi.
    pub approval_id: Uuid,
    /// La phrase que l'humain a lue, et sur laquelle le hachage est pris.
    pub title: String,
    pub signatory: String,
    /// Le handle du branchement MCP qui parle au prestataire.
    pub server: String,
    /// Le document, par son adresse dans le classeur (`files`, `0067`).
    pub document_name: String,
    /// Le numéro de pli du prestataire. `None` : rien n'est parti.
    pub provider_envelope_id: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
    /// L'exemplaire exécuté, dans le classeur. `None` : pas signé.
    pub executed_name: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Envelope {
    /// Le handle, en [`Slug`]. `None` pour une ligne qu'`crate::mcp` ne saurait
    /// pas router non plus — la forme de `content::repos::Repo::handle`.
    #[must_use]
    pub fn handle(&self) -> Option<Slug> {
        Slug::parse(&self.server).ok()
    }
}

/// Le SQL de la table. Ici plutôt que dans `agentos_store` pour la raison de
/// `crate::content` : ces quatre requêtes n'ont qu'un appelant, et il est dans
/// ce fichier.
pub mod envelopes {
    use super::{DateTime, Envelope, StoreError, TenantTx, Utc, Uuid};

    // Les colonnes sont épelées à chaque requête plutôt que composées : `sqlx`
    // refuse une chaîne construite (`dynamic SQL strings should be audited`), et
    // un `SELECT *` laisserait une colonne neuve arriver sans que personne la
    // nomme. C'est la forme de `agentos_store::quotes`.

    /// Ce qu'il faut pour écrire une ligne. Tout est déjà décidé à ce
    /// moment-là : la Gate a statué et l'approbation est déposée.
    #[derive(Debug, Clone)]
    pub struct Draft<'a> {
        pub id: Uuid,
        pub employee_id: Uuid,
        pub approval_id: Uuid,
        pub title: &'a str,
        pub signatory: &'a str,
        pub server: &'a str,
        pub document_name: &'a str,
    }

    /// Écrire le pli qui attend la décision.
    pub async fn prepare(tx: &mut TenantTx<'_>, draft: Draft<'_>) -> Result<Envelope, StoreError> {
        let row = sqlx::query_as(
            "INSERT INTO signature_envelopes \
               (tenant_id, id, employee_id, approval_id, title, signatory, server, document_name) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at",
        )
        .bind(tx.tenant_id().as_uuid())
        .bind(draft.id)
        .bind(draft.employee_id)
        .bind(draft.approval_id)
        .bind(draft.title)
        .bind(draft.signatory)
        .bind(draft.server)
        .bind(draft.document_name)
        .fetch_one(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Le pli qu'une approbation libère. `None` : cette approbation n'en a pas,
    /// et c'est le cas ordinaire — `revenue::Seller::propose_terms` et
    /// `sourcing::Buyer::place_order` déposent des `ContractSign` sans pli.
    pub async fn of_approval(
        tx: &mut TenantTx<'_>,
        approval_id: Uuid,
    ) -> Result<Option<Envelope>, StoreError> {
        let row = sqlx::query_as(
            "SELECT id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at \
               FROM signature_envelopes WHERE approval_id = $1",
        )
        .bind(approval_id)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Un pli, par son identifiant.
    pub async fn find(tx: &mut TenantTx<'_>, id: Uuid) -> Result<Option<Envelope>, StoreError> {
        let row = sqlx::query_as(
            "SELECT id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at \
               FROM signature_envelopes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// Le registre, le plus récent d'abord.
    pub async fn list(tx: &mut TenantTx<'_>) -> Result<Vec<Envelope>, StoreError> {
        let rows = sqlx::query_as(
            "SELECT id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at \
               FROM signature_envelopes ORDER BY created_at DESC",
        )
        .fetch_all(&mut ***tx)
        .await?;
        Ok(rows)
    }

    /// Noter que le pli est parti, et sous quel numéro.
    ///
    /// `WHERE sent_at IS NULL` autant que le déclencheur de `0105` : sans lui,
    /// un second envoi sortirait en panne de base plutôt qu'en `None` qu'un
    /// appelant sait lire.
    pub async fn mark_sent(
        tx: &mut TenantTx<'_>,
        id: Uuid,
        provider_envelope_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Envelope>, StoreError> {
        let row = sqlx::query_as(
            "UPDATE signature_envelopes \
                SET provider_envelope_id = $2, sent_at = $3 \
              WHERE id = $1 AND sent_at IS NULL \
             RETURNING id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at",
        )
        .bind(id)
        .bind(provider_envelope_id)
        .bind(now)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }

    /// **Constater la signature.** `executed_name` est une ligne de `files`, et
    /// la clé étrangère de `0105` est ce qui le garantit ; la contrainte qui
    /// interdit de l'omettre est dans la même migration.
    ///
    /// `WHERE sent_at IS NOT NULL AND signed_at IS NULL` : on ne signe pas un
    /// pli qui n'est jamais parti, et pas deux fois.
    pub async fn mark_signed(
        tx: &mut TenantTx<'_>,
        id: Uuid,
        executed_name: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Envelope>, StoreError> {
        let row = sqlx::query_as(
            "UPDATE signature_envelopes \
                SET executed_name = $2, signed_at = $3 \
              WHERE id = $1 AND sent_at IS NOT NULL AND signed_at IS NULL \
             RETURNING id, employee_id, approval_id, title, signatory, server, document_name, \
             provider_envelope_id, sent_at, executed_name, signed_at, created_at",
        )
        .bind(id)
        .bind(executed_name)
        .bind(now)
        .fetch_optional(&mut ***tx)
        .await?;
        Ok(row)
    }
}

/// Ce qui peut rater quand on prépare un pli.
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    /// Le classeur ne contient rien sous ce nom. Vérifié **avant** la Gate, pour
    /// la raison des docs du module : une approbation déposée pour un document
    /// qui n'existe pas est une ligne dans la file d'un humain qui ne mène nulle
    /// part.
    #[error("no such document")]
    NoDocument,

    /// La Gate a refusé pour une raison qui n'est pas l'escalade : la société
    /// est arrêtée, le siège n'est pas actif, la politique ne se lit pas.
    #[error(transparent)]
    Denied(Denied),

    /// La Gate a répondu autre chose qu'une escalade. Inatteignable —
    /// `evaluate` n'a pas de condition à contourner sur ce bras — et traité
    /// plutôt que `unreachable!`, pour que le jour où le domaine change ce soit
    /// un refus et pas une panne en production. Le jeton est jeté, donc rien
    /// n'est engagé dans les deux cas.
    #[error("the gate did not escalate a signature")]
    NotEscalated,

    #[error(transparent)]
    Store(StoreError),
}

/// Ce qu'on demande : quel document, à qui, par quel branchement.
#[derive(Debug, Clone)]
pub struct Request {
    pub employee_id: EmployeeId,
    /// La phrase que l'humain lira dans sa file, et sur laquelle le hachage de
    /// l'approbation est pris.
    pub title: String,
    pub signatory: String,
    pub server: String,
    pub document_name: String,
}

/// **Préparer un pli : la Gate statue, et un humain hérite de la décision.**
///
/// Rend l'approbation déposée et la ligne écrite. Il n'y a pas de variante où
/// cette fonction envoie quoi que ce soit — ce que `evaluate` rend pour un
/// `ContractSign` est une `RequireApproval` et rien d'autre.
pub async fn prepare(
    db: &Db,
    gate: &PolicyGate,
    principal: &Principal,
    request: &Request,
) -> Result<Envelope, PrepareError> {
    let mut tx = db
        .tenant_tx(principal.tenant_id)
        .await
        .map_err(PrepareError::Store)?;
    // La lecture du document, avant la Gate. Ses octets ne sont pas lus ici :
    // ce qu'on veut savoir est qu'il y a une ligne, et `0067` fait du nom
    // l'adresse.
    let filed: Option<(String,)> = sqlx::query_as("SELECT name FROM files WHERE name = $1")
        .bind(&request.document_name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|err| PrepareError::Store(StoreError::from(err)))?;
    let _ = tx.rollback().await;
    if filed.is_none() {
        return Err(PrepareError::NoDocument);
    }

    let approval_id = match gate
        .authorize(
            principal,
            ContractSign {
                title: request.title.clone(),
            },
        )
        .await
    {
        Err(Denied::PendingApproval(id)) => id,
        Err(other) => return Err(PrepareError::Denied(other)),
        Ok(_) => return Err(PrepareError::NotEscalated),
    };

    let mut tx = db
        .tenant_tx(principal.tenant_id)
        .await
        .map_err(PrepareError::Store)?;
    let written = envelopes::prepare(
        &mut tx,
        envelopes::Draft {
            id: Uuid::now_v7(),
            employee_id: principal.employee_id.as_uuid(),
            approval_id: approval_id.as_uuid(),
            title: &request.title,
            signatory: &request.signatory,
            server: &request.server,
            document_name: &request.document_name,
        },
    )
    .await;
    match written {
        Ok(envelope) => {
            tx.commit().await.map_err(PrepareError::Store)?;
            Ok(envelope)
        }
        Err(err) => {
            let _ = tx.rollback().await;
            Err(PrepareError::Store(err))
        }
    }
}

/// Ce qui peut rater à l'envoi.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Le pli est déjà parti. Le jeton d'approbation ne peut pas être rejoué
    /// (`approvals::redeem` exige `pending`), donc ceci ne s'atteint que si la
    /// ligne a été envoyée par un autre chemin — et le refus arrive **avant**
    /// que le prestataire soit appelé.
    #[error("this envelope has already been sent")]
    AlreadySent,

    /// Le handle du branchement ne se lit pas comme un slug ; `crate::mcp` ne
    /// saurait pas le router non plus.
    #[error("malformed connector handle")]
    MalformedServer,

    #[error(transparent)]
    Effect(EffectError),

    #[error(transparent)]
    Store(StoreError),
}

/// **Envoyer le pli**, avec le jeton qu'une approbation humaine vient de rendre.
///
/// Le jeton n'est pas fabriqué ici et ne peut pas l'être :
/// `Authorized<ContractSign>` ne sort que de `PolicyGate::redeem_approval`,
/// puisque `evaluate` n'a aucun bras qui réponde `Allow` pour cette action. La
/// signature de cette fonction est donc la preuve, à la compilation, que rien ne
/// part sans qu'un humain ait décidé.
///
/// L'ordre : lire les octets, appeler le prestataire, écrire que c'est parti. La
/// ligne s'écrit après, comme `content::propose` écrit `state = 'proposed'`
/// après la pull request — et si l'écriture échoue, le pli est chez le
/// prestataire et la ligne ne le dit pas. C'est ce que la barrière de
/// `Effects::send_for_signature` rend visible : une ligne `provider_intents`
/// réglée, que `provisioning::unsettled_calls` rend à une personne.
pub async fn send(
    db: &Db,
    effects: &Effects,
    ok: Authorized<ContractSign>,
    envelope: &Envelope,
) -> Result<ProviderMessageId, SendError> {
    if envelope.sent_at.is_some() {
        return Err(SendError::AlreadySent);
    }
    let server = envelope.handle().ok_or(SendError::MalformedServer)?;

    let mut tx = db
        .tenant_tx(effects.principal().tenant_id)
        .await
        .map_err(SendError::Store)?;
    let document = files::fetch(&mut tx, &envelope.document_name).await;
    let _ = tx.rollback().await;
    let document = document.map_err(SendError::Store)?;

    let sent = effects
        .send_for_signature(
            ok,
            &SignatureRequest {
                server: &server,
                signatory: &envelope.signatory,
                document_name: &envelope.document_name,
                bytes: &document.content,
            },
        )
        .await
        .map_err(SendError::Effect)?;

    let mut tx = db
        .tenant_tx(effects.principal().tenant_id)
        .await
        .map_err(SendError::Store)?;
    let marked = envelopes::mark_sent(&mut tx, envelope.id, sent.as_str(), Utc::now()).await;
    match marked {
        Ok(_) => {
            tx.commit().await.map_err(SendError::Store)?;
            Ok(sent)
        }
        Err(err) => {
            let _ = tx.rollback().await;
            Err(SendError::Store(err))
        }
    }
}

/// L'outil du prestataire, nommé pour un pli donné.
///
/// Public parce que c'est ce qu'un test monte un faux serveur pour répondre, et
/// parce qu'un lecteur qui cherche « quel outil DocuSign » doit tomber sur
/// [`crate::effects::SEND_ENVELOPE`] et son avertissement.
#[must_use]
pub fn send_tool(server: &Slug) -> McpTool {
    McpTool::new(
        server.clone(),
        Slug::parse(crate::effects::SEND_ENVELOPE).expect("une constante du module des effets"),
    )
}
