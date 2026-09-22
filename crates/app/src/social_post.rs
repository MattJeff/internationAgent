//! Un post LinkedIn tiré d'un contenu publié, relu par le fondateur, publié
//! sur son clic — et sur rien d'autre.
//!
//! # Le chemin, en quatre lignes
//!
//! 1. Un article du client passe à `published` (`content_drafts.url` est
//!    constatée par une personne). L'événement outbox
//!    [`CONTENT_PUBLISHED_EVENT`] — `aggregate_id` = l'`id` du brouillon —
//!    réveille [`on_content_published`].
//! 2. Le siège **growth** du locataire (sa charte, `employee_charters.role =
//!    'growth'`) propose un post : [`compose`] tire un texte court de
//!    l'article, [`check`] le refuse s'il est trop long, s'il porte un prix ou
//!    un lien raccourci — **avant** qu'une approbation existe, donc un post
//!    trop long n'arrive jamais dans la boîte du fondateur.
//! 3. [`propose`] pose l'approbation, avec la nature qu'un siège a déjà pour
//!    publier — `Action::McpCall` sur `social/post-publish`, celle que
//!    `docs/SOCIAL.md` § « Et l'employé, lui ? » nomme — et le texte attaché sur
//!    la ligne, comme une lettre (`approvals.action->'draft'`). Le même
//!    événement `approval.requested` part, le même gestionnaire écrit au
//!    fondateur (`Effects::notify_approver`, qui rend [`letter`] pour un post).
//! 4. `approvals_approve` avec l'action du mail publie par [`approve`] : le
//!    compte LinkedIn connecté est cherché **avant** de dépenser le clic ; sans
//!    compte l'approbation reste `pending` et la réponse dit le geste
//!    ([`CONNECT_HINT`]). `approvals_deny` archive le post avec le motif : la
//!    ligne `denied` + `decision_note` EST l'archive, il n'y a pas de seconde
//!    table.
//!
//! # Un seul réseau, et pourquoi rien ne part quand le compte se connecte
//!
//! LinkedIn seul. C'est là que sont les acheteurs — voyagistes, assureurs,
//! TMC ; X, Instagram, TikTok et YouTube existent chez le service et ne sont
//! pas prononcés ici : un post qui paraît sur quatre réseaux à la fois est
//! quatre fois la même erreur, et aucun de ces quatre n'a d'acheteur dessus.
//!
//! Le compte peut se connecter **après** la proposition. L'approbation attend
//! toujours le clic — rien ne repasse la file en publiant ce qui y dort — parce
//! qu'un post posté sans relecture est un post signé de l'entreprise, et que le
//! fondateur qui connecte un compte n'a pas relu ce qui a été proposé pendant
//! qu'il n'en avait pas. Il relit, puis il clique ; les deux gestes sont dans
//! le mail.
//!
//! # Ce qui n'est pas ici
//!
//! Pas de modèle : le texte est **tiré** de l'article (titre, premier
//! paragraphe, adresse), pas rédigé. ponytail: un appel de modèle dans un
//! gestionnaire d'outbox est un coût par rejeu et une prose que personne n'a
//! relue avant l'approbation ; le jour où la voix du pack manque, c'est un
//! tour du siège growth qui écrit et `propose` qui pose — l'aval ne change pas.
//! Pas de rythme hebdomadaire non plus : l'événement suffit, et un post sans
//! article derrière est un post qui n'a rien à dire.

use agentos_domain::action::{Action, McpTool};
use agentos_domain::ids::{ApprovalId, EmployeeId, Slug};
use agentos_domain::untrusted::Untrusted;
use agentos_providers::ProviderError;
use agentos_store::approvals::{self, ApprovalError, NewApproval};
use agentos_store::db::{StoreError, TenantTx};
use agentos_store::outbox::{self, NewEvent};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::content::drafts::Draft as Article;
use crate::effects::{APPROVAL_REQUESTED_EVENT, EffectError, Effects, McpCall, McpCaller};
use crate::gate::{APPROVAL_TTL, APPROVER_ROLE, Denied, PolicyGate, Principal};

/// L'événement outbox qui déclenche une proposition. Émis par la boucle
/// contenu quand `content_drafts.state` passe à `published` ; `aggregate_id`
/// est l'`id` du brouillon. Nommé ici pour que l'émetteur et le gestionnaire
/// lisent la même chaîne.
pub const CONTENT_PUBLISHED_EVENT: &str = "content.published";

/// Le seul réseau de cette brique. Voir les docs du module.
pub const PLATFORM: &str = "linkedin";

/// Le handle sous lequel le locataire branche `apps/social` —
/// `routes::social::SERVEUR`, même convention.
pub const SERVER: &str = "social";

/// La borne LinkedIn d'un post de membre : au-delà, le texte est replié
/// derrière « voir plus » et personne ne lit la suite.
pub const MAX_CHARS: usize = 1300;

/// La phrase du mail et de la réponse quand aucun compte n'est connecté.
pub const CONNECT_HINT: &str = "Aucun compte LinkedIn n'est connecté : `social_connect_url_get \
                                platform=\"linkedin\"`, ouvrez l'URL rendue, puis revenez \
                                approuver — rien ne partira tout seul.";

/// Hôtes de raccourcisseurs : LinkedIn les pénalise et personne ne sait où ils
/// mènent avant de cliquer.
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "lnkd.in",
    "t.co/",
    "tinyurl.com",
    "ow.ly",
    "buff.ly",
    "goo.gl",
    "rebrand.ly",
    "cutt.ly",
    "is.gd",
    "shorturl.at",
    "tiny.cc",
];

/// Codes ISO qu'un prix écrit en toutes lettres porte.
const CURRENCIES: &[&str] = &["EUR", "USD", "GBP", "CHF"];

/// L'outil que l'approbation autorise : `social/post-publish`.
#[must_use]
pub fn tool() -> McpTool {
    McpTool::new(
        Slug::parse(SERVER).expect("une constante de ce fichier"),
        Slug::parse("post-publish").expect("une constante de ce fichier"),
    )
}

fn accounts_tool() -> McpTool {
    McpTool::new(
        Slug::parse(SERVER).expect("une constante de ce fichier"),
        Slug::parse("accounts-list").expect("une constante de ce fichier"),
    )
}

/// La nature de l'approbation, telle que le hachage la prend.
#[must_use]
pub fn action() -> Action {
    Action::McpCall { tool: tool() }
}

/// Le geste exact du fondateur, tel qu'il le tape.
#[must_use]
pub fn approve_command(approval: Uuid) -> String {
    let action = serde_json::to_string(&action()).expect("une action se sérialise");
    format!("approvals_approve id=\"{approval}\" action={action}")
}

// ---------------------------------------------------------------------------
// Ce qui est vérifié avant qu'une approbation existe
// ---------------------------------------------------------------------------

/// Pourquoi un texte ne devient pas un brouillon de post.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejet {
    #[error("le post est vide")]
    Vide,
    #[error("le post fait {0} caractères ; LinkedIn en montre {MAX_CHARS}")]
    TropLong(usize),
    #[error("le post porte un prix (`{0}`) : les prix vivent sur la page de tarifs")]
    Prix(String),
    #[error("le post porte un lien raccourci (`{0}`) : personne ne sait où il mène")]
    LienRaccourci(String),
}

/// Longueur, prix, lien raccourci — dans cet ordre, le premier qui tombe.
pub fn check(text: &str) -> Result<(), Rejet> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Rejet::Vide);
    }
    let len = text.chars().count();
    if len > MAX_CHARS {
        return Err(Rejet::TropLong(len));
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if word.contains(['€', '$', '£']) {
            return Err(Rejet::Prix((*word).to_owned()));
        }
        let code = word.trim_matches(|c: char| !c.is_alphanumeric());
        let neighbour_has_digit = |j: Option<usize>| {
            j.and_then(|j| words.get(j))
                .is_some_and(|w| w.chars().any(|c| c.is_ascii_digit()))
        };
        if CURRENCIES.contains(&code.to_ascii_uppercase().as_str())
            && (neighbour_has_digit(i.checked_sub(1)) || neighbour_has_digit(Some(i + 1)))
        {
            return Err(Rejet::Prix(format!(
                "{} {code}",
                i.checked_sub(1).map_or("", |j| words[j])
            )));
        }
    }
    let lower = text.to_lowercase();
    if let Some(host) = SHORTENERS.iter().find(|host| lower.contains(*host)) {
        return Err(Rejet::LienRaccourci((*host).to_owned()));
    }
    Ok(())
}

/// Le texte d'un post, **tiré** de l'article : titre, premier paragraphe,
/// adresse constatée. Tient dans [`MAX_CHARS`] par construction — le
/// paragraphe est coupé, jamais le titre ni l'adresse.
#[must_use]
pub fn compose(article: &Article) -> String {
    let title = article.title.trim();
    let url = article.url.as_deref().unwrap_or("").trim();
    let paragraph = article
        .body
        .split("\n\n")
        .map(str::trim)
        .find(|p| !p.is_empty() && !p.starts_with('#'))
        .unwrap_or("");
    // Titre + deux sauts + paragraphe + deux sauts + adresse.
    let budget = MAX_CHARS
        .saturating_sub(title.chars().count())
        .saturating_sub(url.chars().count())
        .saturating_sub(4);
    let paragraph: String = if paragraph.chars().count() > budget {
        let cut: String = paragraph.chars().take(budget.saturating_sub(1)).collect();
        format!("{}…", cut.trim_end())
    } else {
        paragraph.to_owned()
    };
    [title, paragraph.as_str(), url]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

// ---------------------------------------------------------------------------
// Proposer
// ---------------------------------------------------------------------------

/// Ce qui peut empêcher une proposition.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    #[error(transparent)]
    Rejet(#[from] Rejet),
    #[error("l'approbation n'a pas pu être posée : {0}")]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Poser le post comme brouillon attaché à une approbation, et déposer
/// l'événement qui fait écrire au fondateur — une transaction, celle de
/// l'appelant.
///
/// `article` est l'`id` du brouillon de contenu d'où le texte vient, pour
/// qu'un rejeu ne propose pas deux fois le même post ([`on_content_published`]
/// le lit) ; `None` pour un post proposé à la main.
pub async fn propose(
    tx: &mut TenantTx<'_>,
    seat: EmployeeId,
    requested_by: &str,
    text: &str,
    article: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<ApprovalId, ProposeError> {
    check(text)?;
    let text = text.trim();
    let action = action();
    let first_line = text.lines().next().unwrap_or("");
    let summary = format!("publier sur LinkedIn : « {first_line} »");
    let requested = approvals::create(
        tx,
        &NewApproval {
            employee_id: Some(seat),
            action: &action,
            requested_by,
            required_role: APPROVER_ROLE,
            reason: Some(&summary),
            expires_at: now + APPROVAL_TTL,
        },
        now,
    )
    .await?;
    let id = requested.id();
    let draft = json!({ "platform": PLATFORM, "text": text, "article": article });
    // La ligne vient d'être créée `pending` et sans brouillon : `false` ici
    // serait une base qui ment.
    approvals::attach_draft(tx, id, &draft).await?;
    let mut event = NewEvent::new("approval", id.as_uuid(), APPROVAL_REQUESTED_EVENT);
    event.dedupe_key = Some(format!("{APPROVAL_REQUESTED_EVENT}:{}", id.as_uuid()));
    event.payload = json!({ "employee_id": seat.as_uuid(), "draft": draft });
    outbox::enqueue(tx, &event, now).await?;
    Ok(id)
}

/// `content.published` : le siège growth propose un post tiré de l'article.
///
/// `Ok(None)` couvre tout ce qui n'est pas une panne — l'article a disparu, le
/// locataire n'a pas de siège growth actif, le post a déjà été proposé, le
/// texte est refusé par [`check`] — parce qu'aucun de ces cas ne change au
/// huitième réessai de l'outbox. Le journal dit lequel.
pub async fn on_content_published(
    tx: &mut TenantTx<'_>,
    article: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<ApprovalId>, ProposeError> {
    let found: Option<Article> = sqlx::query_as(
        "SELECT id, question_id, title, body, state, url, review_url, note, created_at, published_at \
           FROM content_drafts WHERE id = $1 AND state = 'published'",
    )
    .bind(article)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    let Some(found) = found else {
        tracing::info!(article = %article, "no published article under that id; no post proposed");
        return Ok(None);
    };
    let already: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM approvals WHERE action->'draft'->>'article' = $1 LIMIT 1",
    )
    .bind(article.to_string())
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    if let Some(id) = already {
        tracing::info!(article = %article, approval = %id, "a post was already proposed for this article");
        return Ok(None);
    }
    let seat: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT e.id, e.slug FROM employees e \
           JOIN employee_charters c ON c.employee_id = e.id \
          WHERE c.role = 'growth' AND e.lifecycle = 'active' \
          ORDER BY e.slug LIMIT 1",
    )
    .fetch_optional(&mut ***tx)
    .await
    .map_err(StoreError::from)?;
    let Some((seat, slug)) = seat else {
        tracing::info!(article = %article, "no active growth seat; no post proposed");
        return Ok(None);
    };
    let text = compose(&found);
    match propose(
        tx,
        EmployeeId::from_uuid(seat),
        &slug,
        &text,
        Some(article),
        now,
    )
    .await
    {
        Ok(id) => Ok(Some(id)),
        Err(ProposeError::Rejet(rejet)) => {
            tracing::warn!(article = %article, %rejet, "the post drawn from the article was refused before any approval");
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

// ---------------------------------------------------------------------------
// Ce que le fondateur lit, et ce qu'il clique
// ---------------------------------------------------------------------------

/// Le brouillon de post sur une ligne d'approbation, s'il y en a un.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostDraft {
    pub text: String,
}

/// `Some` si et seulement si `action->'draft'` est un post de cette brique.
#[must_use]
pub fn post_draft(draft: &Value) -> Option<PostDraft> {
    if draft.get("platform").and_then(Value::as_str) != Some(PLATFORM) {
        return None;
    }
    Some(PostDraft {
        text: draft.get("text")?.as_str()?.to_owned(),
    })
}

/// L'objet et le corps du mail au fondateur pour un post — `None` pour une
/// lettre, que `notify_approver` rend comme avant.
#[must_use]
pub fn letter(slug: &Slug, approval: Uuid, draft: &Value) -> Option<(String, String)> {
    let post = post_draft(draft)?;
    let subject = format!("[approbation] {slug} veut publier un post LinkedIn");
    let body = format!(
        "Le siège {slug} propose un post LinkedIn, tiré d'un article publié.\n\
         Approbation : {approval}\n\
         Elle expire 24 h après son dépôt ; passé ce délai, seule approvals_deny la \
         retire de la file.\n\
         \n\
         {text}\n\
         \n\
         --\n\
         Pour le voir tel qu'il paraîtra : social_post_preview_get avec l'account_id de \
         social_accounts_list et ce texte.\n\
         Pour le publier tel quel, avec votre clé d'approbateur :\n\
         {command}\n\
         Pour le refuser (le motif est gardé avec le post) :\n\
         approvals_deny id=\"{approval}\" note=\"…\"\n\
         {hint}\n",
        text = post.text,
        command = approve_command(approval),
        hint = CONNECT_HINT,
    );
    Some((subject, body))
}

// ---------------------------------------------------------------------------
// Approuver
// ---------------------------------------------------------------------------

/// Pourquoi un clic n'a pas publié.
#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    /// Rien n'est dépensé : l'approbation reste `pending`, le geste est
    /// [`CONNECT_HINT`].
    #[error("{CONNECT_HINT}")]
    NoAccount,
    /// Rien n'est dépensé non plus : l'agrégateur n'a pas répondu à la liste
    /// des comptes — pas branché, outil non déclaré, ou en panne. Le mot du
    /// `Fleet`, pour que la route rende le même refus que `/v1/social`.
    #[error("the social aggregator did not answer: {0}")]
    Unreachable(ProviderError),
    #[error(transparent)]
    Denied(#[from] Denied),
    /// L'approbation est dépensée et le service n'a pas publié. Les deux
    /// faits sont vrais et se contredisent, donc les deux sont portés.
    #[error("the approval was redeemed and the post was not published: {reason}")]
    NotPublished { decision_id: Uuid, reason: String },
}

/// Ce qu'un clic a publié.
#[derive(Debug, Clone)]
pub struct Published {
    pub decision_id: Uuid,
    /// La réponse de l'outil du service — `post_id`, `platform_post_id`,
    /// `url` — telle quelle : c'est un tiers qui parle.
    pub post: Untrusted<Value>,
}

/// Le compte LinkedIn connecté chez l'agrégateur, s'il y en a un.
pub async fn linkedin_account(mcp: &dyn McpCaller) -> Result<Option<String>, ProviderError> {
    let answer = mcp.call(&accounts_tool(), &json!({})).await?;
    let value = answer.into_inner_for_rendering();
    let Some(text) = value["content"][0]["text"].as_str() else {
        return Ok(None);
    };
    let parsed: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    Ok(parsed["accounts"].as_array().and_then(|accounts| {
        accounts
            .iter()
            .find(|a| a["platform"] == PLATFORM && a["status"] == "connected")
            .and_then(|a| a["account_id"].as_str().map(str::to_owned))
    }))
}

/// Dépenser l'approbation sur la publication qu'elle nomme.
///
/// L'ordre est celui de `routes::approvals::sign` : le compte d'abord (une
/// lecture, rien de dépensé), le rachat ensuite, la publication en dernier.
/// `effects` porte le `Fleet` du locataire comme port MCP ; `principal` est le
/// siège que l'approbation nomme, l'humain est déjà sur la ligne de la Gate.
pub async fn approve(
    gate: &PolicyGate,
    effects: &Effects,
    principal: &Principal,
    approval: ApprovalId,
    nonce: &str,
    post: &PostDraft,
) -> Result<Published, ApproveError> {
    let account = linkedin_account(effects.mcp())
        .await
        .map_err(ApproveError::Unreachable)?
        .ok_or(ApproveError::NoAccount)?;

    let authorized = gate
        .redeem_approval(principal, approval, nonce, McpCall { tool: tool() })
        .await?;
    let decision_id = authorized.decision_id().as_uuid();

    let arguments = json!({
        "idempotency_key": format!("approval:{}", approval.as_uuid()),
        "account_id": account,
        "text": post.text,
    });
    let not_published = |reason: String| ApproveError::NotPublished {
        decision_id,
        reason,
    };
    let answer = effects
        .call_tool(authorized, &arguments)
        .await
        .map_err(|err: EffectError| not_published(err.to_string()))?;
    let value = answer.expose_for_parsing();
    if value["isError"] == true {
        return Err(not_published("the service refused the post".to_owned()));
    }
    let Some(text) = value["content"][0]["text"].as_str() else {
        return Err(not_published(
            "the service answered without a result".to_owned(),
        ));
    };
    let post: Value = serde_json::from_str(text).unwrap_or_else(|_| json!({ "raw": text }));
    Ok(Published {
        decision_id,
        post: Untrusted::new(post),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use agentos_domain::ids::TenantId;
    use agentos_providers::email::MockEmailProvider;
    use agentos_store::db::Db;
    use async_trait::async_trait;

    use super::*;
    use crate::content::drafts;
    use crate::effects::{Ports, notify_approver};

    // -- ce qui se vérifie sans base ----------------------------------------

    fn article(title: &str, body: &str, url: Option<&str>) -> Article {
        Article {
            id: Uuid::now_v7(),
            question_id: Uuid::now_v7(),
            title: title.to_owned(),
            body: body.to_owned(),
            state: "published".to_owned(),
            url: url.map(str::to_owned),
            review_url: None,
            created_at: Utc::now(),
            published_at: Some(Utc::now()),
            note: None,
        }
    }

    #[test]
    fn la_longueur_le_prix_et_le_lien_raccourci_sont_refuses() {
        assert_eq!(check("   "), Err(Rejet::Vide));
        assert_eq!(check(&"a".repeat(1301)), Err(Rejet::TropLong(1301)));
        assert!(check(&"a".repeat(1300)).is_ok());
        assert_eq!(
            check("Notre API coûte 49 $ par mois."),
            Err(Rejet::Prix("$".to_owned()))
        );
        assert_eq!(
            check("Dès 49 EUR par mois."),
            Err(Rejet::Prix("49 EUR".to_owned()))
        );
        assert!(
            check("Le dollar et l'euro sont des mots, pas des prix.").is_ok(),
            "un mot n'est pas un prix"
        );
        assert_eq!(
            check("Lire ici : https://bit.ly/3xyz"),
            Err(Rejet::LienRaccourci("bit.ly".to_owned()))
        );
        assert!(check("Lire ici : https://visa.orizn.app/blog/api").is_ok());
    }

    #[test]
    fn le_post_est_tire_de_l_article_et_tient_dans_la_borne() {
        let short = article(
            "Vérifier un visa par API",
            "# Titre Markdown\n\nUn développeur demande…\n\nSecond paragraphe.",
            Some("https://visa.example.com/blog/visa-api"),
        );
        assert_eq!(
            compose(&short),
            "Vérifier un visa par API\n\nUn développeur demande…\n\nhttps://visa.example.com/blog/visa-api"
        );
        let long = article("T", &"mot ".repeat(2000), Some("https://x.example/a"));
        let text = compose(&long);
        assert!(
            text.chars().count() <= MAX_CHARS,
            "{}",
            text.chars().count()
        );
        assert!(text.ends_with("…\n\nhttps://x.example/a"), "{text}");
        assert!(check(&text).is_ok());
    }

    #[test]
    fn le_geste_du_fondateur_est_l_action_que_le_hachage_prend() {
        let id = Uuid::nil();
        let command = approve_command(id);
        assert_eq!(
            command,
            "approvals_approve id=\"00000000-0000-0000-0000-000000000000\" \
             action={\"action\":\"mcp_call\",\"tool\":{\"server\":\"social\",\"name\":\"post-publish\"}}"
        );
        let json = command.split_once("action=").expect("action=").1;
        let parsed: Action = serde_json::from_str(json).expect("l'action se relit");
        assert_eq!(parsed, action());
        assert!(post_draft(&json!({ "to": "a@b.c", "subject": "x", "body": "y" })).is_none());
    }

    // -- la base -------------------------------------------------------------

    async fn db() -> Option<Db> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!(
                "SKIP: DATABASE_URL is unset; les tests de post social veulent un vrai Postgres"
            );
            return None;
        };
        let db = Db::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        Some(db)
    }

    /// Un locataire, un siège growth actif (chartré), un article publié.
    async fn seed(db: &Db) -> (TenantId, EmployeeId, Uuid) {
        let now = Utc::now();
        let tenant = TenantId::new_v7(now);
        let employee = EmployeeId::new_v7(now);
        let label = format!("post-{}", employee.as_uuid().simple());
        let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
        sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2)")
            .bind(tenant.as_uuid())
            .bind(&label)
            .execute(&mut *tx)
            .await
            .expect("insert tenant");
        sqlx::query(
            "INSERT INTO employees (id, tenant_id, slug, display_name, lifecycle) \
             VALUES ($1, $2, 'ada', 'ada', 'active')",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert employee");
        sqlx::query(
            "INSERT INTO employee_charters (employee_id, tenant_id, role, objective) \
             VALUES ($1, $2, 'growth', '{}'::jsonb)",
        )
        .bind(employee.as_uuid())
        .bind(tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("insert charter");
        tx.commit().await.expect("commit seed");
        agentos_store::policy::install(
            db,
            tenant,
            agentos_store::policy::Scope::Tenant,
            &agentos_domain::policy::PolicyLimits::default(),
        )
        .await
        .expect("install the policy");

        let mut tx = db.tenant_tx(tenant).await.expect("tenant tx");
        let question = crate::content::questions::add(
            &mut tx,
            "comment vérifier un visa par API",
            "fr",
            crate::content::Source::Founder,
            1,
        )
        .await
        .expect("question");
        let draft = drafts::create(
            &mut tx,
            question.id,
            "Vérifier un visa par API",
            "Un développeur demande à un modèle comment vérifier un passeport.\n\nSuite.",
        )
        .await
        .expect("draft");
        drafts::update(
            &mut tx,
            draft.id,
            &drafts::Revision {
                title: &draft.title,
                body: &draft.body,
                url: Some("https://visa.example.com/blog/visa-api"),
            },
        )
        .await
        .expect("publish");
        tx.commit().await.expect("commit");
        (tenant, employee, draft.id)
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

    async fn row(db: &Db, tenant: TenantId, id: ApprovalId) -> (String, String, Value) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let row = sqlx::query_as(
            "SELECT state, coalesce(action->>'nonce', ''), action->'draft' \
               FROM approvals WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .expect("the approval");
        tx.rollback().await.expect("rollback");
        row
    }

    /// **Un contenu publié → un brouillon de post, une approbation avec le
    /// texte, un mail** — et un second réveil ne propose pas deux fois.
    #[tokio::test]
    async fn un_contenu_publie_devient_un_post_a_approuver_et_un_mail() {
        let Some(db) = db().await else { return };
        let (tenant, employee, article) = seed(&db).await;
        let now = Utc::now();

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let id = on_content_published(&mut tx, article, now)
            .await
            .expect("proposed")
            .expect("un siège growth et un article publié font un post");
        assert!(
            on_content_published(&mut tx, article, now)
                .await
                .expect("second wake")
                .is_none(),
            "un rejeu de l'événement a proposé un second post"
        );
        tx.commit().await.expect("commit");

        let (state, _, draft) = row(&db, tenant, id).await;
        assert_eq!(state, "pending");
        let post = post_draft(&draft).expect("un brouillon de post sur la ligne");
        assert_eq!(
            post.text,
            "Vérifier un visa par API\n\nUn développeur demande à un modèle comment vérifier \
             un passeport.\n\nhttps://visa.example.com/blog/visa-api"
        );

        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let (kind, payload): (String, Value) =
            sqlx::query_as("SELECT event_type, payload FROM outbox_events WHERE aggregate_id = $1")
                .bind(id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .expect("one event");
        tx.rollback().await.expect("rollback");
        assert_eq!(kind, APPROVAL_REQUESTED_EVENT);
        assert_eq!(payload["employee_id"], json!(employee.as_uuid()));

        // Le mail, par le même gestionnaire que les lettres. Le siège est
        // rebâti ici plutôt que chargé : la fixture n'a pas de fiche, et c'est
        // `main::on_approval_requested` qui charge la vraie.
        let seat = agentos_domain::employee::Employee::new(
            employee,
            tenant,
            Slug::parse("ada").expect("slug"),
            agentos_domain::action::Domain::parse("acme.example.com").expect("domain"),
            now,
        );
        let email = Arc::new(MockEmailProvider::new());
        let ports = Ports {
            email: email.clone(),
            ..crate::mocks::ports()
        };
        notify_approver(
            &ports,
            "fondateur@acme.example.com",
            &seat,
            id.as_uuid(),
            &payload["draft"],
            None,
        )
        .await
        .expect("notify");
        let mail = &email.sent_emails()[0];
        assert!(mail.subject.contains("post LinkedIn"), "{}", mail.subject);
        for needle in [
            post.text.as_str(),
            &approve_command(id.as_uuid()),
            "social_post_preview_get",
            "approvals_deny id=",
            CONNECT_HINT,
        ] {
            assert!(
                mail.body_text.contains(needle),
                "{needle:?} absent de :\n{}",
                mail.body_text
            );
        }

        drop_tenant(&db, tenant).await;
    }

    /// Un post qui ne passe pas [`check`] n'arrive pas dans la boîte : pas
    /// d'approbation, pas d'événement.
    #[tokio::test]
    async fn un_post_avec_un_prix_ne_devient_pas_une_approbation() {
        let Some(db) = db().await else { return };
        let (tenant, employee, _) = seed(&db).await;
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let err = propose(
            &mut tx,
            employee,
            "ada",
            "Dès 49 € par mois.",
            None,
            Utc::now(),
        )
        .await
        .expect_err("un prix est refusé");
        assert!(matches!(err, ProposeError::Rejet(Rejet::Prix(_))), "{err}");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM approvals")
            .fetch_one(&mut **tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        assert_eq!(count, 0);
        drop_tenant(&db, tenant).await;
    }

    // -- l'agrégateur, en faux ---------------------------------------------

    /// Le service `apps/social`, réduit à ses trois outils de ce chemin : la
    /// liste des comptes, publier, et ce qui est parti.
    struct FauxSocial {
        accounts: Value,
        posts: Mutex<Vec<Value>>,
    }

    impl FauxSocial {
        fn with_linkedin() -> Arc<Self> {
            Arc::new(Self {
                accounts: json!([
                    { "account_id": "acc-x", "platform": "x", "handle": "@orizn", "status": "connected" },
                    { "account_id": "acc-li", "platform": "linkedin", "handle": "orizn", "status": "connected" },
                ]),
                posts: Mutex::new(Vec::new()),
            })
        }

        fn without_accounts() -> Arc<Self> {
            Arc::new(Self {
                accounts: json!([]),
                posts: Mutex::new(Vec::new()),
            })
        }

        fn ok(value: Value) -> Untrusted<Value> {
            Untrusted::new(json!({
                "content": [{ "type": "text", "text": value.to_string() }],
                "isError": false,
            }))
        }
    }

    #[async_trait]
    impl McpCaller for FauxSocial {
        async fn call(
            &self,
            tool: &McpTool,
            arguments: &Value,
        ) -> Result<Untrusted<Value>, ProviderError> {
            match tool.name.as_str() {
                "accounts-list" => Ok(Self::ok(json!({ "accounts": self.accounts }))),
                "post-publish" => {
                    let post = json!({
                        "post_id": Uuid::now_v7(),
                        "account_id": arguments["account_id"],
                        "text": arguments["text"],
                        "idempotency_key": arguments["idempotency_key"],
                        "platform_post_id": "urn:li:share:1",
                        "url": "https://www.linkedin.com/feed/update/urn:li:share:1",
                    });
                    self.posts.lock().expect("poisoned").push(post.clone());
                    Ok(Self::ok(post))
                }
                "posts-list" => Ok(Self::ok(
                    json!({ "posts": self.posts.lock().expect("poisoned").clone() }),
                )),
                _ => Err(ProviderError::Terminal {
                    code: "unknown_tool",
                }),
            }
        }
    }

    async fn proposed(db: &Db, tenant: TenantId, employee: EmployeeId) -> (ApprovalId, String) {
        let mut tx = db.tenant_tx(tenant).await.expect("tx");
        let id = propose(
            &mut tx,
            employee,
            "ada",
            "Un post à relire.",
            None,
            Utc::now(),
        )
        .await
        .expect("proposed");
        tx.commit().await.expect("commit");
        let (_, nonce, _) = row(db, tenant, id).await;
        (id, nonce)
    }

    fn effects_with(db: &Db, faux: Arc<FauxSocial>, principal: &Principal) -> Effects {
        let mcp: Arc<dyn McpCaller> = faux;
        Effects::new(
            db.clone(),
            Arc::new(Ports {
                mcp,
                ..crate::mocks::ports()
            }),
            principal.clone(),
        )
    }

    /// **Approuver avec un compte connecté publie**, sur le compte LinkedIn et
    /// pas sur l'autre, et `posts-list` le montre.
    #[tokio::test]
    async fn approuver_avec_un_compte_connecte_publie_sur_linkedin() {
        let Some(db) = db().await else { return };
        let (tenant, employee, _) = seed(&db).await;
        let (id, nonce) = proposed(&db, tenant, employee).await;
        let principal = Principal::operator(tenant, employee, "fondateur");
        let faux = FauxSocial::with_linkedin();
        let effects = effects_with(&db, faux.clone(), &principal);

        let published = approve(
            &PolicyGate::new(db.clone()),
            &effects,
            &principal,
            id,
            &nonce,
            &PostDraft {
                text: "Un post à relire.".to_owned(),
            },
        )
        .await
        .expect("published");

        let post = published.post.into_inner_for_rendering();
        assert_eq!(post["account_id"], json!("acc-li"));
        assert_eq!(post["text"], json!("Un post à relire."));
        assert_eq!(
            post["idempotency_key"],
            json!(format!("approval:{}", id.as_uuid()))
        );
        let (state, _, _) = row(&db, tenant, id).await;
        assert_eq!(state, "redeemed");

        let listed = faux
            .call(
                &McpTool::new(
                    Slug::parse("social").unwrap(),
                    Slug::parse("posts-list").unwrap(),
                ),
                &json!({}),
            )
            .await
            .expect("posts-list")
            .into_inner_for_rendering();
        let listed: Value =
            serde_json::from_str(listed["content"][0]["text"].as_str().unwrap()).expect("json");
        assert_eq!(listed["posts"].as_array().map(Vec::len), Some(1));
        assert_eq!(listed["posts"][0]["post_id"], post["post_id"]);

        drop_tenant(&db, tenant).await;
    }

    /// **Sans compte, rien n'est dépensé** : `pending`, et la phrase du geste.
    #[tokio::test]
    async fn sans_compte_l_approbation_reste_pending_et_dit_le_geste() {
        let Some(db) = db().await else { return };
        let (tenant, employee, _) = seed(&db).await;
        let (id, nonce) = proposed(&db, tenant, employee).await;
        let principal = Principal::operator(tenant, employee, "fondateur");
        let faux = FauxSocial::without_accounts();
        let effects = effects_with(&db, faux.clone(), &principal);

        let err = approve(
            &PolicyGate::new(db.clone()),
            &effects,
            &principal,
            id,
            &nonce,
            &PostDraft {
                text: "Un post à relire.".to_owned(),
            },
        )
        .await
        .expect_err("no account");
        assert!(matches!(err, ApproveError::NoAccount), "{err}");
        assert_eq!(err.to_string(), CONNECT_HINT);
        let (state, _, _) = row(&db, tenant, id).await;
        assert_eq!(state, "pending", "le clic a été dépensé sans compte");
        assert!(faux.posts.lock().expect("poisoned").is_empty());

        drop_tenant(&db, tenant).await;
    }
}
