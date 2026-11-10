//! Miroir employé de la gestion YouTube (table v5 du service).
//!
//! Les lectures sont `Read`. Les écritures qui partent tout de suite sont
//! `Write`. Suppressions, visibilité et modération sont `Destructive` : le
//! service ne les joue qu'après `approval_decide`, et l'annotation le dit
//! au modèle avant l'appel.

use serde_json::{Value, json};

use crate::mcp_server::{Method, Risk, ToolDef};

const DESTRUCTIFS: &[&str] = &[
    "social_youtube_video_privacy_set",
    "social_youtube_video_remove",
    "social_youtube_playlist_privacy_set",
    "social_youtube_playlist_remove",
    "social_youtube_playlist_item_remove",
    "social_youtube_comment_moderation_set",
    "social_youtube_comment_remove",
    "social_youtube_caption_remove",
    "social_youtube_reporting_job_remove",
];

pub fn est_destructif(nom: &str) -> bool {
    DESTRUCTIFS.contains(&nom)
}

#[must_use]
pub fn tools() -> Vec<ToolDef> {
    vec![
        lire(
            "social_youtube_channel_get",
            "La chaîne YouTube du compte",
            "Description, mots-clés, pays, langue et bande-annonce du compte. Les liens de la section À propos, les posts Communauté et la bannière ne sont pas supportés.",
            "/v1/social/youtube/channel",
            json!({"account_id": {"type": "string"}}),
            &["account_id"],
            &["account_id"],
        ),
        ecrire(
            "social_youtube_channel_set",
            "La chaîne YouTube mise à jour",
            "Met à jour description, keywords, country, default_language ou unsubscribed_trailer. Le service relit la chaîne et fusionne : l'API remplace toute la partie brandingSettings. La bannière n'est pas éditée.",
            "/v1/social/youtube/channel",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "description": {"type": "string"},
                "keywords": {"type": "string"},
                "country": {"type": "string"},
                "default_language": {"type": "string"},
                "unsubscribed_trailer": {"type": "string"}
            }),
            &["idempotency_key", "account_id"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_video_set",
            "La vidéo mise à jour",
            "Titre, description, tags, category_id, made_for_kids. La visibilité ne se change pas ici.",
            "/v1/social/youtube/videos/update",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "video_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "category_id": {"type": "string"},
                "made_for_kids": {"type": "boolean"}
            }),
            &["idempotency_key", "account_id", "video_id"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_video_privacy_set",
            "La visibilité d'une vidéo en attente",
            "Demande un changement de privacy ou un publish_at. Rien ne part vers YouTube tant qu'un humain n'a pas approuvé (approval_decide). publish_at force private.",
            "/v1/social/youtube/videos/visibility",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "video_id": {"type": "string"},
                "privacy": {"type": "string", "enum": ["private", "public", "unlisted"]},
                "publish_at": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "video_id"],
            Risk::Destructive,
        ),
        ecrire(
            "social_youtube_video_remove",
            "La suppression d'une vidéo en attente",
            "Pose l'approbation qui supprimera la vidéo. approval_decide joue l'appel. Rien n'est effacé avant.",
            "/v1/social/youtube/videos/delete",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "video_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "video_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_playlists_list",
            "Les playlists de la chaîne",
            "Les playlists du compte connecté. À appeler pour choisir un playlist_id avant d'y ajouter une vidéo.",
            "/v1/social/youtube/playlists",
            json!({
                "account_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }),
            &["account_id"],
            &["account_id", "page_token", "max_results"],
        ),
        ecrire(
            "social_youtube_playlist_create",
            "Une playlist créée",
            "Crée une playlist. Sans privacy, elle est private.",
            "/v1/social/youtube/playlists",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "privacy": {"type": "string", "enum": ["private", "public", "unlisted"]}
            }),
            &["idempotency_key", "account_id", "title"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_playlist_set",
            "Une playlist mise à jour",
            "Titre ou description. La visibilité passe par social_youtube_playlist_privacy_set.",
            "/v1/social/youtube/playlists/update",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "playlist_id"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_playlist_privacy_set",
            "La visibilité d'une playlist en attente",
            "Demande un changement de visibilité. approval_decide l'envoie à YouTube.",
            "/v1/social/youtube/playlists/visibility",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_id": {"type": "string"},
                "privacy": {"type": "string", "enum": ["private", "public", "unlisted"]}
            }),
            &["idempotency_key", "account_id", "playlist_id", "privacy"],
            Risk::Destructive,
        ),
        ecrire(
            "social_youtube_playlist_remove",
            "La suppression d'une playlist en attente",
            "Pose l'approbation qui supprimera la playlist. Rien n'est effacé avant approval_decide.",
            "/v1/social/youtube/playlists/delete",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "playlist_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_playlist_items_list",
            "Les vidéos d'une playlist",
            "Les éléments d'une playlist, dans l'ordre. À appeler pour trouver un playlist_item_id avant de le déplacer ou de le retirer.",
            "/v1/social/youtube/playlist-items",
            json!({
                "account_id": {"type": "string"},
                "playlist_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }),
            &["account_id", "playlist_id"],
            &["account_id", "playlist_id", "page_token", "max_results"],
        ),
        ecrire(
            "social_youtube_playlist_item_add",
            "Une vidéo ajoutée à une playlist",
            "Ajoute une vidéo. position est optionnelle.",
            "/v1/social/youtube/playlist-items",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_id": {"type": "string"},
                "video_id": {"type": "string"},
                "position": {"type": "integer", "minimum": 0}
            }),
            &["idempotency_key", "account_id", "playlist_id", "video_id"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_playlist_item_set",
            "Un élément de playlist déplacé",
            "Change la position d'un élément. Le service relit l'élément avant d'écrire.",
            "/v1/social/youtube/playlist-items/reorder",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_item_id": {"type": "string"},
                "position": {"type": "integer", "minimum": 0}
            }),
            &[
                "idempotency_key",
                "account_id",
                "playlist_item_id",
                "position",
            ],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_playlist_item_remove",
            "Un élément de playlist en attente de retrait",
            "Pose l'approbation qui retirera la vidéo de la playlist. Rien n'est retiré avant approval_decide.",
            "/v1/social/youtube/playlist-items/remove",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "playlist_item_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "playlist_item_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_comments_list",
            "Les commentaires de la chaîne",
            "Fils de commentaires d'une vidéo (video_id) ou de toute la chaîne. Les textes sont ceux des spectateurs.",
            "/v1/social/youtube/comments",
            json!({
                "account_id": {"type": "string"},
                "video_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }),
            &["account_id"],
            &["account_id", "video_id", "page_token", "max_results"],
        ),
        ecrire(
            "social_youtube_comment_create",
            "Un commentaire publié",
            "Commentaire sur une vidéo (video_id) ou suite d'un commentaire (parent_id). À utiliser quand la chaîne doit répondre sous une vidéo.",
            "/v1/social/youtube/comments",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "text": {"type": "string"},
                "video_id": {"type": "string"},
                "parent_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "text"],
            Risk::Write,
        ),
        ecrire(
            "social_youtube_comment_moderation_set",
            "Une modération de commentaire en attente",
            "heldForReview, published ou rejected, avec ban_author optionnel. approval_decide envoie l'appel.",
            "/v1/social/youtube/comments/moderate",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "comment_id": {"type": "string"},
                "moderation_status": {"type": "string"},
                "ban_author": {"type": "boolean"}
            }),
            &[
                "idempotency_key",
                "account_id",
                "comment_id",
                "moderation_status",
            ],
            Risk::Destructive,
        ),
        ecrire(
            "social_youtube_comment_remove",
            "La suppression d'un commentaire en attente",
            "Pose l'approbation qui supprimera le commentaire. Rien n'est effacé avant approval_decide.",
            "/v1/social/youtube/comments/delete",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "comment_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "comment_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_captions_list",
            "Les sous-titres d'une vidéo",
            "Les pistes de sous-titres d'une vidéo. À appeler pour obtenir un caption_id avant de télécharger ou de supprimer.",
            "/v1/social/youtube/captions",
            json!({
                "account_id": {"type": "string"},
                "video_id": {"type": "string"}
            }),
            &["account_id", "video_id"],
            &["account_id", "video_id"],
        ),
        ecrire(
            "social_youtube_caption_create",
            "Une piste de sous-titres envoyée",
            "Envoie le texte des sous-titres (content) pour une langue. 400 unités de quota YouTube.",
            "/v1/social/youtube/captions",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "video_id": {"type": "string"},
                "language": {"type": "string"},
                "name": {"type": "string"},
                "content": {"type": "string"},
                "is_draft": {"type": "boolean"}
            }),
            &[
                "idempotency_key",
                "account_id",
                "video_id",
                "language",
                "content",
            ],
            Risk::Write,
        ),
        lire(
            "social_youtube_caption_get",
            "Une piste de sous-titres",
            "Télécharge le texte d'une piste. format vaut srt, vtt, sbv ou ttml ; absent, c'est srt.",
            "/v1/social/youtube/captions/download",
            json!({
                "account_id": {"type": "string"},
                "caption_id": {"type": "string"},
                "format": {"type": "string"}
            }),
            &["account_id", "caption_id"],
            &["account_id", "caption_id", "format"],
        ),
        ecrire(
            "social_youtube_caption_remove",
            "La suppression d'une piste en attente",
            "Pose l'approbation qui supprimera la piste de sous-titres. Rien n'est effacé avant approval_decide.",
            "/v1/social/youtube/captions/delete",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "caption_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "caption_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_analytics_get",
            "Le rapport YouTube Analytics",
            "Vues, temps de visionnage, abonnés gagnés et perdus, sur une plage de dates. video_id limite à une vidéo. Un compte connecté avant les portées Analytics doit être reconnecté.",
            "/v1/social/youtube/analytics",
            json!({
                "account_id": {"type": "string"},
                "start_date": {"type": "string"},
                "end_date": {"type": "string"},
                "video_id": {"type": "string"},
                "metrics": {"type": "string"},
                "dimensions": {"type": "string"}
            }),
            &["account_id", "start_date", "end_date"],
            &[
                "account_id",
                "start_date",
                "end_date",
                "video_id",
                "metrics",
                "dimensions",
            ],
        ),
        lire(
            "social_youtube_report_types_list",
            "Les types de rapports YouTube",
            "Les rapports bulk que cette chaîne peut planifier. monetary signale un type de revenu. À appeler avant de créer un job.",
            "/v1/social/youtube/report-types",
            json!({
                "account_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
                "include_system_managed": {"type": "boolean"}
            }),
            &["account_id"],
            &[
                "account_id",
                "page_token",
                "max_results",
                "include_system_managed",
            ],
        ),
        ecrire(
            "social_youtube_reporting_job_create",
            "Un job de rapport créé",
            "Planifie un rapport quotidien. Le premier fichier arrive sous 24 h. Un type de revenu sans la portée monétaire demande une reconnexion.",
            "/v1/social/youtube/reporting-jobs",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "report_type_id": {"type": "string"},
                "name": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "report_type_id"],
            Risk::Write,
        ),
        lire(
            "social_youtube_reporting_jobs_list",
            "Les jobs de rapports de la chaîne",
            "Les jobs déjà planifiés. À appeler pour retrouver un job_id avant de lister ses fichiers.",
            "/v1/social/youtube/reporting-jobs",
            json!({
                "account_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }),
            &["account_id"],
            &["account_id", "page_token", "max_results"],
        ),
        ecrire(
            "social_youtube_reporting_job_remove",
            "La suppression d'un job de rapport en attente",
            "Pose l'approbation qui supprimera le job. YouTube cesse alors de générer ce rapport. Rien n'est effacé avant approval_decide.",
            "/v1/social/youtube/reporting-jobs/delete",
            json!({
                "idempotency_key": {"type": "string"},
                "account_id": {"type": "string"},
                "job_id": {"type": "string"}
            }),
            &["idempotency_key", "account_id", "job_id"],
            Risk::Destructive,
        ),
        lire(
            "social_youtube_reporting_reports_list",
            "Les fichiers d'un job de rapport",
            "Les CSV déjà produits pour un job. À appeler pour choisir un report_id à télécharger.",
            "/v1/social/youtube/reporting-reports",
            json!({
                "account_id": {"type": "string"},
                "job_id": {"type": "string"},
                "page_token": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }),
            &["account_id", "job_id"],
            &["account_id", "job_id", "page_token", "max_results"],
        ),
        lire(
            "social_youtube_reporting_report_get",
            "Un rapport CSV lu",
            "Télécharge le CSV avec le jeton du compte et rend les lignes plus le SHA-256 des octets. Le fichier ne passe pas par la route publique des médias.",
            "/v1/social/youtube/reporting-reports/get",
            json!({
                "account_id": {"type": "string"},
                "job_id": {"type": "string"},
                "report_id": {"type": "string"}
            }),
            &["account_id", "job_id", "report_id"],
            &["account_id", "job_id", "report_id"],
        ),
    ]
}

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

fn lire(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    path: &'static str,
    properties: Value,
    required: &'static [&'static str],
    query: &'static [&'static str],
) -> ToolDef {
    ToolDef {
        name,
        title,
        description,
        method: Method::Get,
        path,
        schema: schema(properties, required),
        query,
        raw_body: None,
        risk: Risk::Read,
    }
}

fn ecrire(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    path: &'static str,
    properties: Value,
    required: &'static [&'static str],
    risk: Risk,
) -> ToolDef {
    ToolDef {
        name,
        title,
        description,
        method: Method::Post,
        path,
        schema: schema(properties, required),
        query: &[],
        raw_body: None,
        risk,
    }
}
