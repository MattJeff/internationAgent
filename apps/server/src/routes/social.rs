//! `/v1/social` : publier sur les réseaux sociaux du locataire, par le service
//! `apps/social` que le locataire a branché comme n'importe quel connecteur.
//!
//! # Le chemin choisi : **A — un connecteur, pas un service interne**
//!
//! `apps/social` est un serveur MCP séparé, avec sa base, ses jetons par tenant
//! et ses six outils (`docs/SOCIAL.md`). Il y avait deux façons de le rattacher
//! au produit, et le code a tranché :
//!
//! * **A — un connecteur** que le locataire branche comme il branche GitHub ou
//!   Linear : `POST /v1/mcp/connect`, le jeton de tenant frappé par
//!   `agentos-social mint-tenant`, puis `discover` et `declare_tool` pour
//!   épingler chaque outil au digest qu'un humain a lu. **C'est ce module.**
//! * **B — hébergé par le déploiement** et branché tout seul pour chaque
//!   locataire, comme un service interne. Refusé, et pour deux raisons
//!   mesurées et non pour un goût :
//!   1. *Le code.* [`crate::routes::mcp`] est déjà toute la machinerie : la
//!      vérification d'adresse au bind, le scellement du credential, le pin
//!      SHA-256 par outil, la classe de risque qu'un opérateur seul peut
//!      baisser, le `Fleet` que le tour d'un employé traverse. B rejouerait
//!      tout ça à côté — et surtout il faudrait *frapper* un jeton de tenant
//!      dans une SECONDE base (`SOCIAL_DATABASE_URL`), depuis ce binaire, alors
//!      que `apps/social` expose délibérément ce geste en ligne de commande et
//!      pas en route. Le câblage le plus court est celui qui n'écrit rien.
//!   2. *L'honnêteté.* Brancher automatiquement chaque locataire promettrait
//!      que chaque locataire peut publier. C'est faux tant que les revues d'app
//!      ne sont pas passées : l'app Meta du fondateur ne sert que les comptes
//!      qui ont un RÔLE dessus, TikTok reste `SELF_ONLY` et plafonné à cinq
//!      comptes avant audit, l'écran Google en `Testing` rend un refresh token
//!      qui meurt en sept jours (`docs/SOCIAL.md`, § « Les revues d'app »). Un
//!      branchement explicite dit la vérité : ce locataire-ci a des comptes.
//!
//! # Ce que l'argument de `docs/SOCIAL.md` gardait, et ce qu'il ne gardait pas
//!
//! `SOCIAL.md` repousse l'entrée au catalogue, et son argument **tient
//! toujours** : chaque littéral de [`agentos_app::catalog::CATALOG`] est resondé
//! le jour où il est écrit, et le service n'est pas déployé — une entrée
//! `Provision::Dial` sur une URL qui ne répond pas encore serait la première
//! affirmation fausse de ce fichier. Mais cet argument ne portait que sur
//! l'entrée NOMMÉE. Brancher le service, lui, n'a jamais eu besoin d'elle :
//! `catalog::CUSTOM` prend l'URL dans la requête, c'est exactement le cas
//! « le client fait tourner ce serveur et donne son adresse », et c'est le
//! chemin que ce module sert aujourd'hui. Le jour où `agentos-social` est
//! déployé et sondé, l'entrée nommée est douze lignes et **rien ici ne change** :
//! ce module ne lit pas le connecteur, il lit le HANDLE.
//!
//! # Le handle est une convention, et c'est la seule
//!
//! [`SERVEUR`] : le locataire branche l'agrégateur sous le nom `social`. Rien
//! dans une requête ne choisit vers quel branchement ces routes parlent, ni quel
//! outil elles appellent — les deux moitiés de chaque `McpTool` sont des
//! constantes de ce fichier. C'est ce qui rend la garde ci-dessous démontrable.
//!
//! # La garde qui compte : aucune surface de contact privé
//!
//! `apps/social` est le seul agrégateur dont `OptOuts::NoStrangers` est vrai par
//! construction — sa table d'éditeur n'a AUCUNE surface de contact privé, et son
//! test anti-DM le lit nom par nom. Ce module est la première chose qui pouvait
//! rouvrir cette porte, parce qu'il est un appelant, et il ne le fait pas : les
//! cinq noms d'outils qu'il sait prononcer sont dans [`OUTILS`], ils sont
//! criblés par le même jeu d'interdits que le service, et la SECONDE table du
//! service — `/mcp/messagerie`, quatorze outils qui, eux, parlent à des gens —
//! est inatteignable d'ici : aucun de ses noms n'est dans [`OUTILS`], et un nom
//! hors `OUTILS` n'a aucun chemin jusqu'au `Fleet`. Le test
//! `aucune_route_ne_parle_a_quelqu_un` lit la liste ET le source, sur le modèle
//! du test anti-DM de `apps/social/src/mcp.rs`.
//!
//! # Ce que ces routes ne valident pas, et pourquoi
//!
//! Le corps part tel quel comme arguments de l'outil. Le service EST l'autorité
//! sur son propre schéma : il parse à la main, borne chaque champ au maximum
//! inter-plateformes et cite la limite exacte de chaque plateforme dans son
//! adaptateur. Recopier ces bornes ici ferait deux validateurs d'une même règle,
//! qui divergent le jour où l'un est corrigé — le même argument que
//! `crate::routes::mcp_server` fait pour n'avoir qu'une implémentation par
//! fonctionnalité. Ce qui est déclaré, et qu'il FAUT tenir à jour, c'est le
//! schéma de `crates/app/src/mcp_tools/social.rs` : c'est lui que le modèle lit,
//! et notre propre exécuteur refuse un argument qui n'y est pas. Il reflète la
//! table v3 du service.
//!
//! **Deux idempotences, qui ne se remplacent pas.** L'en-tête `Idempotency-Key`
//! de cette API rejoue une RÉPONSE HTTP déjà rendue ; le champ
//! `idempotency_key` du corps, lui, est celui du service, il est OBLIGATOIRE et
//! c'est une contrainte de SA base qui empêche un second post. Un appelant qui
//! ne poserait que l'en-tête publierait deux fois le jour où la ligne
//! d'idempotence de ce déploiement a expiré.
//!
//! La réponse, elle, est le `CallToolResult` du service, tel quel : `content[0]`
//! porte le JSON de l'outil en texte, et `isError` dit si l'outil a refusé. Un
//! refus d'outil (`media_change`, une limite de plateforme, un compte inconnu)
//! est une réponse et pas une panne — 200, et le mot du service intact plutôt
//! que retraduit dans un vocabulaire qui n'est pas le nôtre.

use std::sync::Arc;

use agentos_app::effects::McpCaller;
use agentos_app::mcp::Fleet;
use agentos_app::mocks::ProviderError;
use agentos_domain::action::McpTool;
use agentos_domain::ids::Slug;
use agentos_store::audit::AuditActor;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use super::mcp::Fleets;
use crate::auth::Principal;
use crate::error::ApiError;

/// Le handle sous lequel le locataire branche son agrégateur.
///
/// Une convention, assumée comme telle : `Fleet` route sur le handle, et le
/// produit n'a aucune autre façon de savoir lequel des branchements d'un
/// locataire est son agrégateur tant que le service n'a pas son entrée nommée au
/// catalogue. Un locataire qui n'a rien branché sous ce nom lit le 404 de
/// [`refus`], qui dit quoi faire.
const SERVEUR: &str = "social";

/// Les cinq outils que cette surface sait prononcer, en orthographe `Slug`.
///
/// `agentos_app::mcp` replie les `_` de la table du service en `-` :
/// `post_publish` chez lui est `post-publish` ici. Cette liste est la surface
/// entière — le test anti-contact-privé la crible, et rien d'une requête ne
/// peut l'agrandir.
const OUTILS: &[&str] = &[
    "accounts-list",
    "account-connect-url",
    "post-preview",
    "post-publish",
    "posts-list",
    "thread-preview",
    "thread-publish",
    "calendar-list",
    "schedule-post",
    "schedule-cancel",
    "submit-for-approval",
    "approval-decide",
    "youtube-channel-get",
    "youtube-channel-update",
    "youtube-video-update",
    "youtube-video-visibility",
    "youtube-video-delete",
    "youtube-playlists-list",
    "youtube-playlist-create",
    "youtube-playlist-update",
    "youtube-playlist-visibility",
    "youtube-playlist-delete",
    "youtube-playlist-items-list",
    "youtube-playlist-item-add",
    "youtube-playlist-item-reorder",
    "youtube-playlist-item-remove",
    "youtube-comments-list",
    "youtube-comment-create",
    "youtube-comment-moderate",
    "youtube-comment-delete",
    "youtube-captions-list",
    "youtube-caption-upload",
    "youtube-caption-download",
    "youtube-caption-delete",
    "youtube-analytics-report",
];

/// Ce module.
pub fn router(fleets: Fleets) -> Router {
    Router::new()
        .route("/v1/social/accounts", get(accounts))
        .route("/v1/social/accounts/connect", post(connect))
        .route("/v1/social/preview", post(preview))
        // Deux verbes, un chemin : publier, et relire ce qui est parti.
        .route("/v1/social/posts", post(publish).get(posts))
        .route("/v1/social/threads/preview", post(thread_preview))
        .route("/v1/social/threads", post(thread_publish))
        .route("/v1/social/calendar", get(calendar).post(calendar_create))
        .route("/v1/social/calendar/move", post(calendar_move))
        .route("/v1/social/calendar/cancel", post(calendar_cancel))
        .route("/v1/social/approvals", post(approval_propose))
        // Humain seulement : absent de la table d'outils des employés.
        .route("/v1/social/approvals/decide", post(approval_decide))
        .route(
            "/v1/social/youtube/channel",
            get(yt_channel_get).post(yt_channel_update),
        )
        .route(
            "/v1/social/youtube/playlists",
            get(yt_playlists_list).post(yt_playlist_create),
        )
        .route(
            "/v1/social/youtube/playlists/update",
            post(yt_playlist_update),
        )
        .route(
            "/v1/social/youtube/playlists/visibility",
            post(yt_playlist_visibility),
        )
        .route(
            "/v1/social/youtube/playlists/delete",
            post(yt_playlist_delete),
        )
        .route(
            "/v1/social/youtube/playlist-items",
            get(yt_items_list).post(yt_item_add),
        )
        .route(
            "/v1/social/youtube/playlist-items/reorder",
            post(yt_item_reorder),
        )
        .route(
            "/v1/social/youtube/playlist-items/remove",
            post(yt_item_remove),
        )
        .route("/v1/social/youtube/videos/update", post(yt_video_update))
        .route(
            "/v1/social/youtube/videos/visibility",
            post(yt_video_visibility),
        )
        .route("/v1/social/youtube/videos/delete", post(yt_video_delete))
        .route(
            "/v1/social/youtube/comments",
            get(yt_comments_list).post(yt_comment_create),
        )
        .route(
            "/v1/social/youtube/comments/moderate",
            post(yt_comment_moderate),
        )
        .route(
            "/v1/social/youtube/comments/delete",
            post(yt_comment_delete),
        )
        .route(
            "/v1/social/youtube/captions",
            get(yt_captions_list).post(yt_caption_upload),
        )
        .route(
            "/v1/social/youtube/captions/download",
            get(yt_caption_download),
        )
        .route(
            "/v1/social/youtube/captions/delete",
            post(yt_caption_delete),
        )
        .route("/v1/social/youtube/analytics", get(yt_analytics))
        .with_state(fleets)
}

/// Appeler un outil de l'agrégateur branché, pour le locataire de la clé.
///
/// `outil` est toujours une constante de ce fichier, jamais une valeur de la
/// requête : c'est l'invariant sur lequel la garde repose.
async fn appeler(
    fleets: &Fleets,
    principal: &Principal,
    outil: &'static str,
    arguments: Value,
) -> Result<Json<Value>, ApiError> {
    debug_assert!(OUTILS.contains(&outil), "un outil hors de la surface");
    let fleet: Arc<Fleet> = fleets.for_tenant(principal.tenant_id);
    let tool = McpTool::new(
        Slug::parse(SERVEUR).expect("une constante de ce fichier"),
        Slug::parse(outil).expect("une constante de ce fichier"),
    );
    fleet
        .call(&tool, &arguments)
        .await
        .map(|value| Json(value.into_inner_for_rendering()))
        .map_err(refus)
}

/// Le mot du `Fleet`, traduit en la seule chose que l'appelant peut corriger.
pub(crate) fn refus(err: ProviderError) -> ApiError {
    match err {
        // Rien n'est branché sous ce handle, ou le branchement ne sert pas cet
        // outil — un `/mcp/messagerie` branché sous ce nom tombe ici aussi.
        ProviderError::Terminal {
            code: "unknown_tool",
        } => ApiError::new(
            StatusCode::NOT_FOUND,
            "no_social_binding",
            "no social aggregator is bound",
        )
        .with_detail(
            "branchez `apps/social` sous le handle `social` : `integrations_connect` avec \
             `connector: \"custom\"`, l'URL du service et le jeton de tenant frappé par \
             `agentos-social mint-tenant`.",
        ),
        // Le branchement existe mais l'outil n'a pas été vetté : un outil que
        // personne n'a déclaré est `Destructive`, donc il demande un humain que
        // cette route ne peut pas produire.
        ProviderError::Terminal { code: "refused" } => ApiError::new(
            StatusCode::FORBIDDEN,
            "tool_not_declared",
            "the tool is not declared for this tenant",
        )
        .with_detail(
            "lisez la table avec `integrations_discover`, puis épinglez chaque outil au \
             digest lu avec `integrations_declare_tool` (`risk: \"write\"` pour publier).",
        ),
        // Le service a dit non à quelque chose que l'appelant contrôle.
        ProviderError::Terminal { code } => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "the social service refused",
        ),
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "social_unavailable",
            "the social service did not answer; try again",
        ),
    }
}

// ---------------------------------------------------------------------------
// Les cinq outils, sur quatre chemins — `/v1/social/posts` porte les deux
// verbes que son nom permet : y écrire, et le lire.
// ---------------------------------------------------------------------------

/// `GET /v1/social/accounts` — les comptes branchés du locataire.
async fn accounts(
    State(fleets): State<Fleets>,
    principal: Principal,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[0], json!({})).await
}

/// Ce qu'une plateforme s'appelle. L'enum est celui de la table v3 du service ;
/// c'est lui qui refuse, pas nous — voir les docs du module.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    platform: String,
}

/// `POST /v1/social/accounts/connect` — l'URL d'autorisation à ouvrir.
async fn connect(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Connect>,
) -> Result<Json<Value>, ApiError> {
    appeler(
        &fleets,
        &principal,
        OUTILS[1],
        json!({ "platform": body.platform }),
    )
    .await
}

/// `POST /v1/social/preview` — le contenu exact qui partirait, et son empreinte.
async fn preview(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[2], objet(body)?).await
}

/// `POST /v1/social/posts` — publier.
async fn publish(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[3], objet(body)?).await
}

/// `?limit=` de `posts_list`. Borné par le service (1 à 200) ; ici on ne fait
/// que transporter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Combien {
    limit: Option<i64>,
}

/// `GET /v1/social/posts` — ce qui est parti.
async fn posts(
    State(fleets): State<Fleets>,
    principal: Principal,
    Query(combien): Query<Combien>,
) -> Result<Json<Value>, ApiError> {
    let arguments = combien
        .limit
        .map_or_else(|| json!({}), |limit| json!({ "limit": limit }));
    appeler(&fleets, &principal, OUTILS[4], arguments).await
}

/// `POST /v1/social/threads/preview` — l'empreinte du fil entier.
async fn thread_preview(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[5], objet(body)?).await
}

/// `POST /v1/social/threads` — publier un fil, une clé pour toute la chaîne.
async fn thread_publish(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[6], objet(body)?).await
}

/// `?account_id=&from=&to=` du calendrier.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Calendrier {
    account_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

/// `GET /v1/social/calendar` — créneaux et files d'attente.
async fn calendar(
    State(fleets): State<Fleets>,
    principal: Principal,
    Query(q): Query<Calendrier>,
) -> Result<Json<Value>, ApiError> {
    let mut arguments = serde_json::Map::new();
    if let Some(id) = q.account_id {
        arguments.insert("account_id".to_owned(), json!(id));
    }
    if let Some(from) = q.from {
        arguments.insert("from".to_owned(), json!(from));
    }
    if let Some(to) = q.to {
        arguments.insert("to".to_owned(), json!(to));
    }
    appeler(&fleets, &principal, OUTILS[7], Value::Object(arguments)).await
}

/// `POST /v1/social/calendar` — poser un créneau (en attente par défaut).
async fn calendar_create(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[8], objet(body)?).await
}

/// `POST /v1/social/calendar/move` — déplacer un créneau.
async fn calendar_move(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[9], objet(body)?).await
}

/// `POST /v1/social/calendar/cancel` — retirer un créneau.
async fn calendar_cancel(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[9], objet(body)?).await
}

/// `POST /v1/social/approvals` — soumettre, sans rien publier.
async fn approval_propose(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    appeler(&fleets, &principal, OUTILS[10], objet(body)?).await
}

/// `POST /v1/social/approvals/decide` — approuver, refuser ou éditer.
///
/// Pas un outil d'employé : la table MCP du produit ne déclare pas ce chemin.
/// Et pas n'importe quelle clé non plus : seul le rôle approbateur décide.
async fn approval_decide(
    State(fleets): State<Fleets>,
    principal: Principal,
    crate::error::JsonBody(body): crate::error::JsonBody<Value>,
) -> Result<Json<Value>, ApiError> {
    approbateur(&principal.actor)?;
    appeler(&fleets, &principal, OUTILS[11], objet(body)?).await
}

/// La règle de `routes::approvals`, lue de la même façon : le rôle d'une clé
/// est son étiquette, et seule `approver` publie ce qu'un employé a proposé.
/// Sans ce contrôle, toute clé du locataire — un terminal, un assistant tiers
/// à qui l'on a confié une clé de pilotage — approuvait et faisait partir un
/// post public.
fn approbateur(actor: &AuditActor) -> Result<(), ApiError> {
    if super::approvals::held_role(actor) != Some(agentos_app::gate::APPROVER_ROLE) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "role_required",
            "this credential does not hold the role this approval requires",
        ));
    }
    Ok(())
}

/// Les arguments d'un outil sont un objet. Un tableau ou une chaîne est une
/// requête que ce client ne sait pas faire, et le dire ici épargne un
/// aller-retour réseau.
fn args_query(q: &std::collections::HashMap<String, String>, cles: &[&str]) -> Value {
    let mut arguments = serde_json::Map::new();
    for cle in cles {
        if let Some(valeur) = q.get(*cle) {
            arguments.insert((*cle).to_owned(), json!(valeur));
        }
    }
    Value::Object(arguments)
}

macro_rules! post_yt {
    ($nom:ident, $outil:literal) => {
        async fn $nom(
            State(fleets): State<Fleets>,
            principal: Principal,
            crate::error::JsonBody(body): crate::error::JsonBody<Value>,
        ) -> Result<Json<Value>, ApiError> {
            appeler(&fleets, &principal, $outil, objet(body)?).await
        }
    };
}

macro_rules! get_yt {
    ($nom:ident, $outil:literal, $($cle:literal),* $(,)?) => {
        async fn $nom(
            State(fleets): State<Fleets>,
            principal: Principal,
            Query(q): Query<std::collections::HashMap<String, String>>,
        ) -> Result<Json<Value>, ApiError> {
            appeler(&fleets, &principal, $outil, args_query(&q, &[$($cle),*])).await
        }
    };
}

post_yt!(yt_channel_update, "youtube-channel-update");
post_yt!(yt_playlist_create, "youtube-playlist-create");
post_yt!(yt_playlist_update, "youtube-playlist-update");
post_yt!(yt_playlist_visibility, "youtube-playlist-visibility");
post_yt!(yt_playlist_delete, "youtube-playlist-delete");
post_yt!(yt_item_add, "youtube-playlist-item-add");
post_yt!(yt_item_reorder, "youtube-playlist-item-reorder");
post_yt!(yt_item_remove, "youtube-playlist-item-remove");
post_yt!(yt_video_update, "youtube-video-update");
post_yt!(yt_video_visibility, "youtube-video-visibility");
post_yt!(yt_video_delete, "youtube-video-delete");
post_yt!(yt_comment_create, "youtube-comment-create");
post_yt!(yt_comment_moderate, "youtube-comment-moderate");
post_yt!(yt_comment_delete, "youtube-comment-delete");
post_yt!(yt_caption_upload, "youtube-caption-upload");
post_yt!(yt_caption_delete, "youtube-caption-delete");

get_yt!(yt_channel_get, "youtube-channel-get", "account_id");
get_yt!(
    yt_playlists_list,
    "youtube-playlists-list",
    "account_id",
    "page_token",
    "max_results"
);
get_yt!(
    yt_items_list,
    "youtube-playlist-items-list",
    "account_id",
    "playlist_id",
    "page_token",
    "max_results"
);
get_yt!(
    yt_comments_list,
    "youtube-comments-list",
    "account_id",
    "video_id",
    "page_token",
    "max_results"
);
get_yt!(
    yt_captions_list,
    "youtube-captions-list",
    "account_id",
    "video_id"
);
get_yt!(
    yt_caption_download,
    "youtube-caption-download",
    "account_id",
    "caption_id",
    "format"
);
get_yt!(
    yt_analytics,
    "youtube-analytics-report",
    "account_id",
    "start_date",
    "end_date",
    "video_id",
    "metrics",
    "dimensions"
);

fn objet(body: Value) -> Result<Value, ApiError> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(ApiError::bad_request("le corps est un objet JSON"))
    }
}

// ---------------------------------------------------------------------------
// Tests — la garde, et rien d'autre : ce module n'a pas de logique à éprouver
// au-delà d'elle, il transporte.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Seule la clé `approver` décide d'une publication ; une clé de pilotage
    /// à une autre étiquette, ou le système, est refusée avant tout appel.
    #[test]
    fn seul_le_role_approbateur_decide_d_une_publication() {
        assert!(approbateur(&AuditActor::Operator("approver".to_owned())).is_ok());
        for etiquette in ["friday", "ops", "owner", "session-1"] {
            assert!(
                approbateur(&AuditActor::Operator(etiquette.to_owned())).is_err(),
                "la clé `{etiquette}` a pu approuver une publication"
            );
        }
        assert!(approbateur(&AuditActor::System).is_err());
    }

    /// Les interdits, et pour chacun un nom hostile qui doit le déclencher.
    /// La même liste que `apps/social/src/mcp.rs` : un interdit qui diverge
    /// serait une porte ouverte d'un côté et fermée de l'autre.
    const INTERDITS: &[(&str, &str)] = &[
        ("dm", "send_dm"),
        ("message", "message_user"),
        ("broadcast", "broadcast_all"),
        ("direct", "direct_post"),
        ("inbox", "inbox_read"),
        ("chat", "chat_open"),
        ("reply", "reply_to_user"),
        ("send", "send_note"),
        ("mention", "mention_user"),
    ];

    /// Un test qui ne peut pas échouer est pire que pas de test : d'abord on
    /// prouve que chaque interdit reconnaît ce qu'il prétend reconnaître.
    #[test]
    fn les_interdits_attrapent_ce_qu_ils_pretendent_attraper() {
        for (motif, hostile) in INTERDITS {
            assert!(
                hostile.contains(motif),
                "l'interdit `{motif}` ne reconnaît pas `{hostile}`"
            );
        }
    }

    /// **La promesse fondatrice, tenue par l'appelant.**
    ///
    /// Deux moitiés, parce que la liste seule ne prouverait rien si un sixième
    /// appel vivait ailleurs dans le fichier : la table des cinq noms, puis le
    /// source lui-même, commentaires retirés — les commentaires ont le droit de
    /// nommer ce qu'ils refusent, le code non.
    #[test]
    fn aucune_route_ne_parle_a_quelqu_un() {
        assert!(!OUTILS.is_empty(), "une liste vide ne prouve rien");
        for outil in OUTILS {
            for (motif, _) in INTERDITS {
                assert!(
                    !outil.contains(motif),
                    "`{outil}` contient l'interdit `{motif}` : cette surface n'atteint \
                     personne qui n'a rien demandé, par construction"
                );
            }
        }

        let source = include_str!("social.rs");
        // Le module de tests porte les noms hostiles volontairement ; ce qui est
        // criblé est le code qui tourne en production.
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("le fichier a un début");
        let sans_commentaires: String = code
            .lines()
            .filter(|ligne| !ligne.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();
        // Ce qu'un crible qui ne lit plus rien passerait en vert : si le
        // découpage ou le retrait des commentaires mange le code, cette ligne
        // tombe AVANT que le silence soit pris pour une preuve.
        assert!(
            sans_commentaires.contains("post-publish"),
            "le crible ne lit plus le code de ce module"
        );
        for (motif, _) in INTERDITS {
            assert!(
                !sans_commentaires.contains(motif),
                "le code de ce module porte l'interdit `{motif}` : une surface de contact \
                 privé est en train d'apparaître du côté appelant"
            );
        }
    }

    /// La seconde table du service — quatorze outils qui, eux, atteignent des
    /// gens — est inatteignable d'ici. Les noms sont recopiés de
    /// `apps/social/src/messagerie.rs` : si l'un d'eux entrait un jour dans
    /// [`OUTILS`], ce test tomberait avant la revue.
    #[test]
    fn la_seconde_table_du_service_est_hors_de_portee() {
        const MESSAGERIE: &[&str] = &[
            "inbox-list",
            "dm-reply",
            "dm-open",
            "post-reply",
            "post-comment",
            "post-like",
            "post-unlike",
            "post-bookmark",
            "post-unbookmark",
            "post-repost",
            "search-posts",
            "read-post",
            "read-profile",
            "read-timeline",
        ];
        for nom in MESSAGERIE {
            assert!(
                !OUTILS.contains(nom),
                "`{nom}` est un outil de la seconde table : cette surface ne le prononce pas"
            );
        }
    }

    /// Les deux moitiés de chaque appel sont des `Slug` valides. Un `expect`
    /// sur une constante est une promesse ; celle-ci est tenue ici plutôt qu'au
    /// premier appel d'un client.
    #[test]
    fn le_handle_et_les_cinq_outils_sont_des_slugs() {
        Slug::parse(SERVEUR).expect("le handle");
        for outil in OUTILS {
            Slug::parse(outil).unwrap_or_else(|_| panic!("`{outil}` n'est pas un slug"));
        }
    }
}
