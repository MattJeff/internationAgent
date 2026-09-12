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

use agentos_domain::ids::Slug;
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
///
/// Pas de champ `employee_id` : le siège est celui du [`Principal`] que la Gate
/// statue pour, et un second exemplaire ici serait un champ que quelqu'un
/// pourrait un jour remplir autrement que celui sur lequel le jeton est émis.
#[derive(Debug, Clone)]
pub struct Request {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use agentos_domain::action::McpTool;
    use agentos_domain::ids::{ApprovalId, EmployeeId, TenantId};
    use agentos_domain::policy::PolicyLimits;
    use agentos_domain::untrusted::Untrusted;
    use agentos_providers::ProviderError;
    use serde_json::{Value, json};

    use super::*;
    use crate::effects::{McpCaller, Ports, SEND_ENVELOPE};

    /// Le handle sous lequel ces tests branchent le prestataire.
    const HANDLE: &str = "docusign";

    /// **Un faux prestataire de signature**, au port plutôt qu'au fil.
    ///
    /// `crate::content`'s `FauxGithub` argues the shape and every word applies:
    /// the protocol is already held by an in-process MCP server in `crate::mcp`'s
    /// tests, and what is held nowhere is what **we** send — which tool, with
    /// which arguments, and what is made of the answer.
    ///
    /// The one thing it cannot be is faithful. GitHub publishes its tool list to
    /// an anonymous caller, so `FauxGithub` answers to names that are facts;
    /// `mcp.docusign.com` answers `403` without a token and there is no account
    /// here, so this double answers to a name this workspace invented. What it
    /// proves is the wiring, and `crate::effects::SEND_ENVELOPE` says so at the
    /// one place somebody would be misled.
    struct FauxDocuSign {
        seen: std::sync::Mutex<Vec<(String, Value)>>,
        /// Le numéro de pli qu'il s'attribue, en texte — pour qu'un test puisse
        /// en mettre un qui n'est pas un UUID.
        envelope: String,
        /// Répondre `isError` : une réponse *réussie* qui dit non.
        refusing: bool,
    }

    impl FauxDocuSign {
        fn new(envelope: &str) -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
                envelope: envelope.to_owned(),
                refusing: false,
            })
        }

        fn refusing() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
                envelope: String::new(),
                refusing: true,
            })
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.seen.lock().expect("pas empoisonné").clone()
        }
    }

    #[async_trait::async_trait]
    impl McpCaller for FauxDocuSign {
        async fn call(
            &self,
            tool: &McpTool,
            arguments: &Value,
        ) -> Result<Untrusted<Value>, ProviderError> {
            let name = tool.name.as_str().to_owned();
            self.seen
                .lock()
                .expect("pas empoisonné")
                .push((name.clone(), arguments.clone()));
            if name != SEND_ENVELOPE {
                return Err(ProviderError::Terminal {
                    code: "unknown_tool",
                });
            }
            let text = if self.refusing {
                "The document could not be read".to_owned()
            } else {
                json!({ "envelopeId": self.envelope, "status": "sent" }).to_string()
            };
            Ok(Untrusted::new(json!({
                "content": [{ "type": "text", "text": text }],
                "isError": self.refusing,
            })))
        }
    }

    fn ports_signing(provider: Arc<FauxDocuSign>) -> Arc<Ports> {
        Arc::new(Ports {
            mcp: provider,
            ..crate::mocks::ports()
        })
    }

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!(
                "SKIP: DATABASE_URL is unset; les tests de signature veulent un vrai Postgres"
            );
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Un locataire, un siège actif, une politique large, et un document dans le
    /// classeur.
    ///
    /// **La politique est délibérément la plus permissive que `PolicyLimits`
    /// sache écrire.** C'est ce qui fait dire quelque chose au premier test : si
    /// la signature était escaladée parce qu'un plafond manquait, le test
    /// passerait pour la mauvaise raison.
    async fn seed(db: &Db) -> (Principal, String) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("signe-{}", employee.as_uuid().simple());

        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'lena', 'lena', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        tx.commit().await.expect("commit seed");

        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &PolicyLimits {
                allowed_channels: agentos_domain::action::Channel::ALL
                    .iter()
                    .copied()
                    .collect(),
                allow_credential_change: true,
                allow_data_delete: true,
                max_turns_per_day: 50,
                ..PolicyLimits::default()
            },
        )
        .await
        .expect("install policy");

        let name = format!("contrat-{}.pdf", employee.as_uuid().simple());
        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let bytes = b"%PDF-1.4 le contrat".to_vec();
        files::deposit(
            &mut tx,
            &name,
            "application/pdf",
            &bytes,
            &crate::files::digest_of(&bytes),
        )
        .await
        .expect("deposit the document");
        tx.commit().await.expect("commit the classeur");

        (Principal::employee(tenant, employee), name)
    }

    fn asked(document: &str) -> Request {
        Request {
            title: "abonnement annuel Orizn, 12 000 EUR".to_owned(),
            signatory: "acheteur@client.example".to_owned(),
            server: HANDLE.to_owned(),
            document_name: document.to_owned(),
        }
    }

    async fn nonce_of(db: &Db, tenant: TenantId, id: ApprovalId) -> String {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let nonce: String =
            sqlx::query_scalar("SELECT action->>'nonce' FROM approvals WHERE id = $1")
                .bind(id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("the approval carries a nonce");
        tx.rollback().await.expect("rollback");
        nonce
    }

    async fn drop_tenant(db: &Db, tenant: TenantId) {
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.as_uuid())
            .execute(&mut *tx)
            .await
            .expect("delete tenant");
        tx.commit().await.expect("commit");
    }

    /// **Promesse 1 : un siège ne signe jamais seul.**
    ///
    /// La politique du locataire est la plus large que ce produit sache écrire —
    /// tous les canaux, les secrets, l'effacement — et la signature monte quand
    /// même chez un humain. C'est le plus petit test qui retombe si quelqu'un
    /// ajoute une condition au bras de `evaluate`, un seuil, ou un champ de
    /// `PolicyLimits` qui laisserait passer : il n'y a rien à élargir ici pour
    /// le faire échouer autrement.
    #[tokio::test]
    async fn une_signature_monte_toujours_chez_un_humain() {
        let Some(db) = db().await else { return };
        let (principal, document) = seed(&db).await;

        let envelope = prepare(&db, &gate(&db), &principal, &asked(&document))
            .await
            .expect("le pli est préparé");

        assert!(
            envelope.sent_at.is_none() && envelope.provider_envelope_id.is_none(),
            "préparer a envoyé quelque chose"
        );
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let state: String = sqlx::query_scalar("SELECT state FROM approvals WHERE id = $1")
            .bind(envelope.approval_id)
            .fetch_one(&mut **tx)
            .await
            .expect("l'approbation existe");
        tx.rollback().await.expect("rollback");
        assert_eq!(state, "pending", "la décision n'attend personne");

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Promesses 3 et 4 : rien ne part sans la Gate, et ce qui part revient
    /// avec le numéro du prestataire.**
    ///
    /// Le jeton ne se fabrique pas : `Authorized<ContractSign>` ne sort que de
    /// `redeem_approval`, donc ce test *doit* passer par l'approbation pour
    /// pouvoir appeler `send`. C'est la preuve à la compilation, rejouée à
    /// l'exécution.
    #[tokio::test]
    async fn le_pli_part_sur_la_decision_humaine_et_note_le_numero() {
        let Some(db) = db().await else { return };
        let (principal, document) = seed(&db).await;
        let gate = gate(&db);

        let envelope = prepare(&db, &gate, &principal, &asked(&document))
            .await
            .expect("préparé");
        let approval = ApprovalId::from_uuid(envelope.approval_id);
        let nonce = nonce_of(&db, principal.tenant_id, approval).await;

        let ok = gate
            .redeem_approval(
                &principal,
                approval,
                &nonce,
                ContractSign {
                    title: envelope.title.clone(),
                },
            )
            .await
            .expect("l'humain approuve");

        let provider = FauxDocuSign::new("3f6b9c2e-4d5a-4b1e-9f8a-0c1d2e3f4a5b");
        let effects = Effects::new(
            db.clone(),
            ports_signing(provider.clone()),
            principal.clone(),
        );
        let sent = send(&db, &effects, ok, &envelope).await.expect("envoyé");

        // Ce que **nous** avons prononcé : un outil, une fois, avec le document.
        let calls = provider.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, SEND_ENVELOPE);
        assert_eq!(calls[0].1["signerEmail"], json!("acheteur@client.example"));
        assert!(
            calls[0].1["documentBase64"]
                .as_str()
                .is_some_and(|b| !b.is_empty()),
            "le document n'est pas parti avec le pli"
        );

        assert_eq!(sent.as_str(), "3f6b9c2e-4d5a-4b1e-9f8a-0c1d2e3f4a5b");
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let row = envelopes::find(&mut tx, envelope.id)
            .await
            .expect("read")
            .expect("la ligne existe");
        // La ligne d'audit est celle de la signature, pas celle d'un appel
        // d'outil : c'est la signature qui engage l'entreprise.
        let kind: String = sqlx::query_scalar(
            "SELECT action_kind FROM audit_log WHERE tenant_id = $1 \
               AND action_kind = 'contract_sign' LIMIT 1",
        )
        .bind(principal.tenant_id.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("une ligne d'audit de signature");
        tx.rollback().await.expect("rollback");

        assert_eq!(kind, "contract_sign");
        assert_eq!(
            row.provider_envelope_id.as_deref(),
            Some("3f6b9c2e-4d5a-4b1e-9f8a-0c1d2e3f4a5b")
        );
        assert!(row.sent_at.is_some());

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Le `isError` de MCP est une réponse réussie qui dit non**, et rien ne
    /// doit être enregistré comme parti sur la foi d'un message d'erreur.
    #[tokio::test]
    async fn un_refus_du_prestataire_ne_marque_rien_comme_parti() {
        let Some(db) = db().await else { return };
        let (principal, document) = seed(&db).await;
        let gate = gate(&db);

        let envelope = prepare(&db, &gate, &principal, &asked(&document))
            .await
            .expect("préparé");
        let approval = ApprovalId::from_uuid(envelope.approval_id);
        let nonce = nonce_of(&db, principal.tenant_id, approval).await;
        let ok = gate
            .redeem_approval(
                &principal,
                approval,
                &nonce,
                ContractSign {
                    title: envelope.title.clone(),
                },
            )
            .await
            .expect("approuvé");

        let effects = Effects::new(
            db.clone(),
            ports_signing(FauxDocuSign::refusing()),
            principal.clone(),
        );
        let failed = send(&db, &effects, ok, &envelope).await;
        assert!(failed.is_err(), "un refus est passé pour un envoi");

        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let row = envelopes::find(&mut tx, envelope.id)
            .await
            .expect("read")
            .expect("la ligne existe");
        tx.rollback().await.expect("rollback");
        assert!(
            row.sent_at.is_none() && row.provider_envelope_id.is_none(),
            "le pli est noté parti alors que le prestataire a dit non"
        );

        drop_tenant(&db, principal.tenant_id).await;
    }

    /// **Promesse 2 : on ne peut pas mentir sur le mot « signé ».**
    ///
    /// Le plus petit test qui retombe si la contrainte de `0105` disparaît, et
    /// il attaque la base **directement** plutôt que par `mark_signed` : ce qui
    /// est promis n'est pas qu'une fonction Rust soit prudente, c'est qu'aucun
    /// chemin ne puisse écrire la date sans l'artefact. Un test qui passerait
    /// par le code ne prouverait que le code.
    #[tokio::test]
    async fn la_base_refuse_de_mentir_sur_le_mot_signe() {
        let Some(db) = db().await else { return };
        let (principal, document) = seed(&db).await;
        let envelope = prepare(&db, &gate(&db), &principal, &asked(&document))
            .await
            .expect("préparé");

        // Le pli est parti — sans quoi le refus ci-dessous pourrait venir de
        // `signature_envelopes_signed_after_sent` et le test dirait autre chose.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        envelopes::mark_sent(&mut tx, envelope.id, "pli-1", Utc::now())
            .await
            .expect("parti");
        tx.commit().await.expect("commit");

        // 1. Une date sans exemplaire exécuté.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let bare = sqlx::query("UPDATE signature_envelopes SET signed_at = now() WHERE id = $1")
            .bind(envelope.id)
            .execute(&mut **tx)
            .await;
        let _ = tx.rollback().await;
        assert!(
            bare.is_err(),
            "« signé » s'est écrit sans que personne ait l'exemplaire signé"
        );

        // 2. L'exemplaire exécuté qui serait le document qu'on a envoyé.
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let same = envelopes::mark_signed(&mut tx, envelope.id, &document, Utc::now()).await;
        let _ = tx.rollback().await;
        assert!(
            same.is_err(),
            "le PDF non signé qu'on a envoyé est passé pour l'exemplaire exécuté"
        );

        // Et le chemin honnête marche : déposer les octets signés, puis
        // constater.
        let signed = format!("signe-{document}");
        let mut tx = db.tenant_tx(principal.tenant_id).await.expect("tx");
        let bytes = b"%PDF-1.4 le contrat, signe".to_vec();
        files::deposit(
            &mut tx,
            &signed,
            "application/pdf",
            &bytes,
            &crate::files::digest_of(&bytes),
        )
        .await
        .expect("deposit");
        let row = envelopes::mark_signed(&mut tx, envelope.id, &signed, Utc::now())
            .await
            .expect("constaté")
            .expect("la ligne existe");
        tx.commit().await.expect("commit");
        assert_eq!(row.executed_name.as_deref(), Some(signed.as_str()));
        assert!(row.signed_at.is_some());

        drop_tenant(&db, principal.tenant_id).await;
    }

    fn gate(db: &Db) -> PolicyGate {
        PolicyGate::new(db.clone())
    }

    /// **Le seul `expect` de ce chemin, et ce qui l'empêche d'être une panne.**
    ///
    /// `Effects::send_for_signature` parse [`SEND_ENVELOPE`] en [`Slug`] et
    /// `expect`e — ce qui est juste tant que la constante est un slug, et qui
    /// est un panic en production le jour où quelqu'un la corrige contre la
    /// vraie liste de DocuSign en écrivant `send_envelope`. C'est exactement ce
    /// qui est arrivé à l'écriture : `Slug` refuse `_`, et seul un test à la
    /// base l'a dit. Sans base, il ne dit rien — celui-ci n'en veut pas.
    #[test]
    fn le_nom_de_loutil_est_un_slug() {
        assert!(
            Slug::parse(SEND_ENVELOPE).is_ok(),
            "{SEND_ENVELOPE} n'est pas un slug : un tiret, jamais un souligné"
        );
    }
}
