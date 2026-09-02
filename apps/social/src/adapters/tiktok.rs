//! TikTok : vidéo (octets directs, chunké) et photos (pull depuis chez nous),
//! via la Content Posting API ; lectures via la Display API.
//!
//! Tout vient de developers.tiktok.com, relevé le 2026-09-02 :
//!
//! * Préalable OBLIGATOIRE : `POST /v2/post/publish/creator_info/query/`
//!   (20 req/min/token) — rend `privacy_level_options`,
//!   `max_video_post_duration_sec`, `comment_disabled`… Pour DIRECT_POST le
//!   `privacy_level` « must match one of the privacy_level_options returned »
//!   (photo-post, relevé le 2026-09-02).
//! * Vidéo : `POST /v2/post/publish/video/init/` (« Each user access_token is
//!   limited to 6 requests per minute »), `source_info.source=FILE_UPLOAD` +
//!   `video_size`, `chunk_size`, `total_chunk_count` ; puis PUT des octets
//!   vers `upload_url` (« valid for one hour after issuance »), en-têtes
//!   `Content-Range: bytes {FIRST}-{LAST}/{TOTAL}` et `Content-Type` —
//!   content-posting-api-reference-direct-post, relevé le 2026-09-02.
//!   Chunking (media-transfer-guide, relevé le 2026-09-02) : « Each chunk
//!   must be at least 5 MB but no greater than 64 MB, except for the final
//!   chunk, which can be greater than chunk_size (up to 128 MB) » ; < 5 MB =
//!   un seul morceau ; upload séquentiel. `title` max « 2200 in UTF-16
//!   runes ». PULL_FROM_URL existe (domaine vérifié requis) : repli
//!   seulement — le direct est le chemin principal.
//! * Photos : `POST /v2/post/publish/content/init/`, `media_type=PHOTO`,
//!   `post_mode=DIRECT_POST` — « Only PULL_FROM_URL is allowed »
//!   (photo-post, relevé le 2026-09-02) : le dépôt sert
//!   `{base}/medias/{digest}` et le PRÉFIXE d'URL doit être vérifié dans le
//!   portail développeur (étape fondateur). WebP/JPEG, « Maximum of 20MB for
//!   each image », jusqu'à 35 `photo_images` ; `title` ≤ « 90 UTF-16
//!   runes », `description` ≤ 4000. `is_aigc` est au NIVEAU RACINE du corps
//!   photo, dans `post_info` pour la vidéo (les deux référence, relevées le
//!   2026-09-02).
//! * Statut : `POST /v2/post/publish/status/fetch/` (micro-sonde du
//!   2026-09-02, content-posting-api-reference-get-video-status) — corps
//!   `{publish_id}` ; `status` ∈ PROCESSING_UPLOAD, PROCESSING_DOWNLOAD,
//!   SEND_TO_USER_INBOX, PUBLISH_COMPLETE, FAILED ;
//!   `publicaly_available_post_id` (sic) « returned only for public posts
//!   approved by moderation » ; 30 req/min.
//! * Lectures (Display API, scope video.list) : `POST /v2/video/query/`
//!   (champs like_count, comment_count, share_count, view_count),
//!   `POST /v2/video/list/` (max_count 20), `GET /v2/user/info/` — relevés
//!   le 2026-09-02.
//! * Avant audit : « Unaudited API Clients can only post contents in
//!   SELF_ONLY viewership », « All content posted by unaudited clients will
//!   be restricted to private viewing mode », « up to 5 users to post in a
//!   24 hour window » (relevés le 2026-09-02).
//!
//! Restes nommés (pas de stub) : WebM (magic EBML absent du téléchargeur —
//! medias.rs détecte MP4/MOV via ftyp) ; PULL_FROM_URL vidéo (repli non
//! câblé tant que le direct marche).

use std::sync::Arc;

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{
    ActionFaite, Apercu, ApercuMedia, ContexteAdaptateurs, ElementLu, ErreurMessagerie,
    ErreurPlateforme, Inbox, MediaPret, MessagePrive, Metriques, OptionsPost, Plateforme,
    PlateformeMessagerie, PostsLus, Privacy, ProfilLu, Publication, ReponsePubliee, Sondage,
    TypeMedia, empreinte_globale, envoyer, http, http_upload, url_pull,
};
use crate::medias::DepotMedias;

/// Les points d'API — developers.tiktok.com, relevés le 2026-09-02.
pub const POINT_CREATOR_INFO: &str =
    "https://open.tiktokapis.com/v2/post/publish/creator_info/query/";
pub const POINT_VIDEO_INIT: &str = "https://open.tiktokapis.com/v2/post/publish/video/init/";
pub const POINT_CONTENT_INIT: &str = "https://open.tiktokapis.com/v2/post/publish/content/init/";
/// Micro-sonde du 2026-09-02 (content-posting-api-reference-get-video-status).
pub const POINT_STATUS: &str = "https://open.tiktokapis.com/v2/post/publish/status/fetch/";
pub const POINT_VIDEO_QUERY: &str = "https://open.tiktokapis.com/v2/video/query/";
pub const POINT_VIDEO_LIST: &str = "https://open.tiktokapis.com/v2/video/list/";
pub const POINT_USER_INFO: &str = "https://open.tiktokapis.com/v2/user/info/";

/// Taille de chunk figée : 16 MiB — dans la fenêtre citée [5 MB, 64 MB], peu
/// de requêtes sous notre plafond service de 512 MiB (32 PUT au pire).
pub const TAILLE_CHUNK: u64 = 16 * 1024 * 1024;
/// « at least 5 MB » — lecture décimale (media-transfer-guide, 2026-09-02).
pub const CHUNK_MIN: u64 = 5_000_000;
/// `title` vidéo : « 2200 in UTF-16 runes » (direct-post, 2026-09-02).
pub const TITRE_VIDEO_MAX_UTF16: usize = 2200;
/// Photo : titre 90, description 4000 « UTF-16 runes » (photo-post, 2026-09-02).
pub const TITRE_PHOTO_MAX_UTF16: usize = 90;
pub const DESCRIPTION_PHOTO_MAX_UTF16: usize = 4000;
/// « Maximum of 20MB for each image » (photo-post, 2026-09-02).
pub const OCTETS_MAX_PHOTO: u64 = 20_000_000;
/// Jusqu'à 35 `photo_images` (photo-post, 2026-09-02).
pub const PHOTOS_MAX: usize = 35;

/// ponytail: polling status/fetch toutes les 5 s sous 5 min — la limite
/// citée est 30 req/min, on reste très en dessous.
pub const BUDGET_TRAITEMENT_SECS: u64 = 300;
pub const PAS_DE_POLLING_SECS: u64 = 5;

/// Les états avant-audit, rendus en verdicts INFORMATIFS (relevés le
/// 2026-09-02) — statiques : le service ne peut pas sonder l'état d'audit.
pub const CITATION_AVANT_AUDIT: &str = "avant l'audit TikTok : « Unaudited API Clients can only post contents in \
     SELF_ONLY viewership », « All content posted by unaudited clients will be \
     restricted to private viewing mode », « up to 5 users to post in a 24 hour \
     window » (relevés le 2026-09-02) — demander `public` avant audit rend \
     `unaudited_client_can_only_post_to_private_accounts` ; l'utilisateur peut \
     repasser le post en public à la main";

/// Le mot TikTok pour chaque `privacy` de la table — `None` = TikTok ne le
/// sert pas (`unlisted` n'existe pas dans l'enum privacy_level, direct-post,
/// relevé le 2026-09-02).
pub fn privacy_tiktok(p: Privacy) -> Option<&'static str> {
    match p {
        Privacy::Public => Some("PUBLIC_TO_EVERYONE"),
        Privacy::Friends => Some("MUTUAL_FOLLOW_FRIENDS"),
        Privacy::Followers => Some("FOLLOWER_OF_CREATOR"),
        Privacy::Private => Some("SELF_ONLY"),
        Privacy::Unlisted => None,
    }
}

/// Le défaut quand `privacy` est absent : SELF_ONLY — la seule valeur qu'un
/// client non audité peut poster de toute façon (citation ci-dessus), et la
/// moins surprenante : rien ne devient public sans le demander.
pub const PRIVACY_DEFAUT: &str = "SELF_ONLY";

/// Le plan de chunking FILE_UPLOAD, pur et testé : `(chunk_size,
/// total_chunk_count, bornes)`. Règles citées (media-transfer-guide,
/// 2026-09-02) : < 5 MB = un seul morceau ; sinon chunks de 16 MiB, le
/// DERNIER absorbe le reste (« the final chunk... can be greater than
/// chunk_size, up to 128 MB » — avec 16 MiB le dernier reste < 32 MiB).
pub fn plan_chunks(taille: u64) -> (u64, u64, Vec<(u64, u64)>) {
    if taille < CHUNK_MIN || taille <= TAILLE_CHUNK {
        // Un seul morceau : sous 5 MB c'est la règle, sous 16 MiB c'est le
        // plan le plus simple qui la respecte (5 MB ≤ chunk ≤ 64 MB).
        return (taille, 1, vec![(0, taille.saturating_sub(1))]);
    }
    let total = taille / TAILLE_CHUNK;
    let bornes = (0..total)
        .map(|i| {
            let premier = i * TAILLE_CHUNK;
            let dernier = if i == total - 1 {
                taille - 1
            } else {
                (i + 1) * TAILLE_CHUNK - 1
            };
            (premier, dernier)
        })
        .collect();
    (TAILLE_CHUNK, total, bornes)
}

/// Le corps de `POST /v2/post/publish/video/init/` — direct-post, relevé le
/// 2026-09-02. `is_aigc` vit dans `post_info` pour la vidéo, et n'apparaît
/// que quand il est vrai : un champ absent et un champ nul ne sont pas la
/// même requête.
pub fn corps_video_init(
    titre: &str,
    privacy_level: &str,
    is_aigc: bool,
    taille: u64,
) -> serde_json::Value {
    let (chunk, total, _) = plan_chunks(taille);
    let mut post_info = json!({
        "title": titre,
        "privacy_level": privacy_level,
    });
    if is_aigc {
        post_info["is_aigc"] = json!(true);
    }
    json!({
        "post_info": post_info,
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": taille,
            "chunk_size": chunk,
            "total_chunk_count": total
        }
    })
}

/// Le corps de `POST /v2/post/publish/content/init/` (photos) — photo-post,
/// relevé le 2026-09-02. « Only PULL_FROM_URL is allowed » : chaque URL est
/// dérivée ICI, par `url_pull(base, digest)` — NOS octets vettés, jamais
/// l'URL du client (que `MediaPret` ne porte même pas). La dérivation vit
/// DANS cette fonction pure pour que le test de fixture épingle le chemin
/// réel de `publier_photos`, pas une copie qui pourrait diverger.
/// `is_aigc` est au NIVEAU RACINE pour les photos (photo-post, 2026-09-02).
pub fn corps_photo_init(
    titre: Option<&str>,
    description: &str,
    privacy_level: &str,
    base: &str,
    medias: &[MediaPret],
    is_aigc: bool,
) -> serde_json::Value {
    let urls: Vec<String> = medias.iter().map(|m| url_pull(base, &m.digest)).collect();
    let mut post_info = json!({
        "description": description,
        "privacy_level": privacy_level,
    });
    if let Some(t) = titre {
        post_info["title"] = json!(t);
    }
    let mut corps = json!({
        "media_type": "PHOTO",
        "post_mode": "DIRECT_POST",
        "post_info": post_info,
        "source_info": {
            "source": "PULL_FROM_URL",
            "photo_images": urls,
            "photo_cover_index": 0
        }
    });
    if is_aigc {
        corps["is_aigc"] = json!(true);
    }
    corps
}

/// `{"publish_id": ...}` — status/fetch, micro-sonde du 2026-09-02.
pub fn corps_status(publish_id: &str) -> serde_json::Value {
    json!({ "publish_id": publish_id })
}

/// `Content-Range: bytes {FIRST}-{LAST}/{TOTAL}` — direct-post, 2026-09-02.
pub fn content_range(premier: u64, dernier: u64, total: u64) -> String {
    format!("bytes {premier}-{dernier}/{total}")
}

/// TikTok répond 200 avec `error.code` : un code autre que « ok » est un
/// refus — nommé, SANS recopier le corps (le code d'erreur voyage dans un
/// 200 ; la discipline anti-fuite tient, le statut 400 est le nôtre).
fn verifier_code(document: &serde_json::Value) -> Result<(), ErreurPlateforme> {
    match document.pointer("/error/code").and_then(|v| v.as_str()) {
        None | Some("ok") => Ok(()),
        Some(_) => Err(ErreurPlateforme::Refus { statut: 400 }),
    }
}

fn lire_document(statut: u16, corps: &[u8]) -> Result<serde_json::Value, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    verifier_code(&document)?;
    Ok(document)
}

/// Lit `data.publish_id` (+ `data.upload_url` pour la vidéo).
pub fn init_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<(String, Option<String>), ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    let publish_id = document
        .pointer("/data/publish_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(ErreurPlateforme::Illisible)?;
    let upload_url = document
        .pointer("/data/upload_url")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok((publish_id, upload_url))
}

/// Lit `data.privacy_level_options` de creator_info/query.
pub fn creator_info_depuis(statut: u16, corps: &[u8]) -> Result<Vec<String>, ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    document
        .pointer("/data/privacy_level_options")
        .and_then(|v| v.as_array())
        .map(|liste| {
            liste
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or(ErreurPlateforme::Illisible)
}

/// Où en est une publication après status/fetch (micro-sonde du 2026-09-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtatPublication {
    /// PUBLISH_COMPLETE (ou SEND_TO_USER_INBOX : le post attend l'utilisateur
    /// dans son inbox TikTok — terminal pour nous, commenté honnête).
    Publie {
        id_public: Option<String>,
    },
    EnCours,
    Echec,
}

pub fn statut_publication_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<EtatPublication, ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    match document.pointer("/data/status").and_then(|v| v.as_str()) {
        Some("PUBLISH_COMPLETE") | Some("SEND_TO_USER_INBOX") => Ok(EtatPublication::Publie {
            // `publicaly_available_post_id` (l'orthographe est celle de la
            // doc) : « returned only for public posts approved by
            // moderation » — souvent absent (SELF_ONLY), et c'est normal.
            id_public: document
                .pointer("/data/publicaly_available_post_id")
                .and_then(|v| v.as_array())
                .and_then(|liste| liste.first())
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string()),
        }),
        Some("PROCESSING_UPLOAD") | Some("PROCESSING_DOWNLOAD") => Ok(EtatPublication::EnCours),
        // FAILED : TikTok a mangé les octets puis dit non (fail_reason reste
        // dans le corps, qui n'entre pas dans l'erreur) — rejeu sensé.
        Some("FAILED") => Ok(EtatPublication::Echec),
        _ => Err(ErreurPlateforme::Illisible),
    }
}

/// Lit `data.videos[0]` de video/query en métriques — champs like_count,
/// comment_count, share_count, view_count (scope video.list, 2026-09-02).
pub fn metriques_depuis(statut: u16, corps: &[u8]) -> Result<Metriques, ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    let video = document
        .pointer("/data/videos/0")
        .ok_or(ErreurPlateforme::Illisible)?;
    let compte = |nom: &str| video.get(nom).and_then(|v| v.as_u64());
    Ok(Metriques {
        impressions: compte("view_count"),
        likes: compte("like_count").unwrap_or(0),
        replies: compte("comment_count").unwrap_or(0),
        reposts: compte("share_count").unwrap_or(0),
    })
}

/// Lit `data.videos` (list/query) en éléments — id + title, contenu de tiers.
pub fn videos_depuis(statut: u16, corps: &[u8]) -> Result<Vec<ElementLu>, ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    document
        .pointer("/data/videos")
        .and_then(|v| v.as_array())
        .map(|liste| {
            liste
                .iter()
                .filter_map(|v| {
                    // L'id vidéo est un int64 chez TikTok.
                    let id = match v.get("id")? {
                        serde_json::Value::String(s) => s.clone(),
                        autre => autre.as_i64()?.to_string(),
                    };
                    Some(ElementLu {
                        id,
                        auteur_id: None,
                        texte: v
                            .get("title")
                            .and_then(|t| t.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        third_party: true,
                    })
                })
                .collect::<Vec<_>>()
        })
        .ok_or(ErreurPlateforme::Illisible)
}

/// Lit `data.user` de user/info — (open_id, display_name).
pub fn utilisateur_depuis(statut: u16, corps: &[u8]) -> Result<(String, String), ErreurPlateforme> {
    let document = lire_document(statut, corps)?;
    let lire = |champ: &str| {
        document
            .pointer(&format!("/data/user/{champ}"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    };
    Ok((lire("open_id")?, lire("display_name")?))
}

/// Le poids « UTF-16 runes » cité par TikTok : des unités UTF-16, comptées
/// comme la doc les compte.
pub fn poids_utf16(texte: &str) -> usize {
    texte.encode_utf16().count()
}

/// Le verdict d'UN média, mots exacts et chiffres cités.
fn apercu_media(m: &MediaPret) -> ApercuMedia {
    let taille = m.octets.len() as u64;
    let mut verdicts = Vec::new();
    let mut ok = true;
    match m.type_detecte {
        TypeMedia::Jpeg | TypeMedia::Webp => {
            if taille > OCTETS_MAX_PHOTO {
                ok = false;
                verdicts.push(format!(
                    "« Maximum of 20MB for each image » (photo-post, relevé le 2026-09-02), \
                     reçu {taille} octets"
                ));
            }
            // ponytail: 1080p max non vérifiable aux octets sans parseur —
            // la plateforme tranchera.
        }
        TypeMedia::Png | TypeMedia::Gif => {
            ok = false;
            verdicts.push(format!(
                "tiktok ne sert que WebP et JPEG pour les photos (photo-post, relevé le \
                 2026-09-02) — reçu {}",
                m.type_detecte.mime()
            ));
        }
        TypeMedia::Mp4 => {
            // Notre détection ftyp couvre MP4 et MOV, deux formats servis ;
            // WebM (magic EBML) n'est pas détecté par medias.rs — reste nommé
            // en tête de module. La durée max est PAR CRÉATEUR
            // (max_video_post_duration_sec de creator_info) : connue à la
            // publication seulement.
            verdicts.push(
                "la durée max est par créateur (max_video_post_duration_sec, \
                 creator_info/query, relevé le 2026-09-02) — vérifiée à la publication"
                    .to_owned(),
            );
        }
        TypeMedia::Pdf => {
            ok = false;
            verdicts.push(
                "tiktok ne sert aucun type document (video/init et content/init, relevés \
                 le 2026-09-02)"
                    .to_owned(),
            );
        }
    }
    if m.alt_text.is_some() {
        ok = false;
        verdicts.push(
            "tiktok ne sert pas d'alt_text (aucun champ dans video/init ni content/init, \
             relevés le 2026-09-02)"
                .to_owned(),
        );
    }
    if let Some(titre) = &m.title {
        // Le title d'un média photo devient le `title` du post (≤ 90).
        let n = poids_utf16(titre);
        if m.type_detecte == TypeMedia::Jpeg || m.type_detecte == TypeMedia::Webp {
            if n > TITRE_PHOTO_MAX_UTF16 {
                ok = false;
                verdicts.push(format!(
                    "title photo « 90 UTF-16 runes » max (photo-post, relevé le \
                     2026-09-02), reçu {n}"
                ));
            }
        } else {
            ok = false;
            verdicts.push(
                "le title de post vidéo TikTok EST le texte de l'outil — pas de title \
                 de média vidéo (direct-post, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
    }
    ApercuMedia {
        digest: m.digest.clone(),
        size_bytes: taille,
        detected_type: m.type_detecte.mime(),
        alt_text: m.alt_text.clone(),
        limits_ok: ok,
        verdicts,
    }
}

pub struct Tiktok {
    base_publique: String,
    depot: Arc<DepotMedias>,
}

impl Tiktok {
    pub fn nouvel(ctx: &ContexteAdaptateurs) -> Self {
        Self {
            base_publique: ctx.base_publique.trim_end_matches('/').to_owned(),
            depot: ctx.depot.clone(),
        }
    }

    /// Le privacy_level effectif : mapping de la table, défaut SELF_ONLY.
    fn privacy_level(options: &OptionsPost) -> Option<&'static str> {
        match options.privacy {
            None => Some(PRIVACY_DEFAUT),
            Some(p) => privacy_tiktok(p),
        }
    }

    /// Le préalable obligatoire : creator_info/query, et le refus LOCAL si le
    /// privacy demandé n'est pas dans `privacy_level_options` — on ne brûle
    /// pas un init pour un refus connu d'avance.
    async fn verifier_creator_info(
        &self,
        jeton: &Secret,
        privacy_level: &str,
    ) -> Result<(), ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .post(POINT_CREATOR_INFO)
                .bearer_auth(jeton.expose_for_transport())
                .header("Content-Type", "application/json; charset=UTF-8"),
        )
        .await?;
        let permis = creator_info_depuis(statut, &corps)?;
        if permis.iter().any(|p| p == privacy_level) {
            Ok(())
        } else {
            // Le 400 est le nôtre : le privacy demandé n'est pas offert à ce
            // créateur (avant audit : SELF_ONLY seul) — l'aperçu l'a déjà dit.
            Err(ErreurPlateforme::Refus { statut: 400 })
        }
    }

    /// Poll status/fetch jusqu'à un état terminal, sous budget.
    async fn attendre_publication(
        &self,
        jeton: &Secret,
        publish_id: &str,
    ) -> Result<Option<String>, ErreurPlateforme> {
        let mut budget = BUDGET_TRAITEMENT_SECS;
        loop {
            let (statut, corps) = envoyer(
                http()
                    .post(POINT_STATUS)
                    .bearer_auth(jeton.expose_for_transport())
                    .json(&corps_status(publish_id)),
            )
            .await?;
            match statut_publication_depuis(statut, &corps)? {
                EtatPublication::Publie { id_public } => return Ok(id_public),
                EtatPublication::Echec => return Err(ErreurPlateforme::Injoignable),
                EtatPublication::EnCours => {
                    if budget < PAS_DE_POLLING_SECS {
                        return Err(ErreurPlateforme::Injoignable);
                    }
                    budget -= PAS_DE_POLLING_SECS;
                    tokio::time::sleep(std::time::Duration::from_secs(PAS_DE_POLLING_SECS)).await;
                }
            }
        }
    }

    /// La vidéo : init FILE_UPLOAD → PUT séquentiel des chunks (Content-Range
    /// cité) → publish_id.
    async fn publier_video(
        &self,
        jeton: &Secret,
        m: &MediaPret,
        titre: &str,
        privacy_level: &str,
        is_aigc: bool,
    ) -> Result<String, ErreurPlateforme> {
        let taille = m.octets.len() as u64;
        let (statut, corps) = envoyer(
            http()
                .post(POINT_VIDEO_INIT)
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_video_init(titre, privacy_level, is_aigc, taille)),
        )
        .await?;
        let (publish_id, upload_url) = init_depuis(statut, &corps)?;
        let upload_url = upload_url.ok_or(ErreurPlateforme::Illisible)?;
        let (_, _, bornes) = plan_chunks(taille);
        for (premier, dernier) in bornes {
            let chunk = m.octets[premier as usize..=dernier as usize].to_vec();
            let (statut, _corps) = envoyer(
                http_upload()
                    .put(&upload_url)
                    .header("Content-Type", m.type_detecte.mime())
                    .header("Content-Range", content_range(premier, dernier, taille))
                    .body(chunk),
            )
            .await?;
            // 201 par chunk final, 206 (Partial Content) pour les autres —
            // tout 2xx passe, un 4xx/5xx sort nommé.
            if !(200..=299).contains(&statut) {
                return Err(
                    ErreurPlateforme::depuis_statut(statut).unwrap_or(ErreurPlateforme::Illisible)
                );
            }
        }
        Ok(publish_id)
    }

    /// Les photos : dépôt des octets vettés → content/init PULL_FROM_URL avec
    /// `{base}/medias/{digest}` — jamais l'URL du client (par construction :
    /// `MediaPret` ne la porte pas) → publish_id. Le retrait du dépôt attend
    /// la fin du téléchargement TikTok (état terminal du polling).
    async fn publier_photos(
        &self,
        jeton: &Secret,
        medias: &[MediaPret],
        texte: &str,
        privacy_level: &str,
        is_aigc: bool,
    ) -> Result<String, ErreurPlateforme> {
        for m in medias {
            self.depot
                .deposer(&m.digest, m.octets.clone(), m.type_detecte);
        }
        // Le title photo vient du title du PREMIER média quand il existe ; le
        // texte de l'outil est la description (photo-post : les deux champs).
        let titre = medias.first().and_then(|m| m.title.as_deref());
        let (statut, corps) = envoyer(
            http()
                .post(POINT_CONTENT_INIT)
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_photo_init(
                    titre,
                    texte,
                    privacy_level,
                    &self.base_publique,
                    medias,
                    is_aigc,
                )),
        )
        .await?;
        let (publish_id, _) = init_depuis(statut, &corps)?;
        Ok(publish_id)
    }
}

#[async_trait]
impl Plateforme for Tiktok {
    fn nom(&self) -> &'static str {
        "tiktok"
    }

    fn apercu(
        &self,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Apercu {
        let mut refus = Vec::new();
        let mut infos = Vec::new();

        let photos = medias
            .iter()
            .filter(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Webp))
            .count();
        let videos = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Mp4)
            .count();
        if medias.is_empty() {
            refus.push(
                "tiktok ne publie pas de post texte seul : video/init exige une vidéo, \
                 content/init des photos (relevés le 2026-09-02)"
                    .to_owned(),
            );
        }
        if videos > 1 {
            refus.push(format!("1 seule vidéo par post TikTok, reçu {videos}"));
        }
        if photos > PHOTOS_MAX {
            refus.push(format!(
                "jusqu'à 35 photo_images (photo-post, relevé le 2026-09-02), reçu {photos}"
            ));
        }
        if photos > 0 && videos > 0 {
            refus.push(
                "pas de mélange photo+vidéo : video/init OU content/init, jamais les deux \
                 (relevés le 2026-09-02)"
                    .to_owned(),
            );
        }
        if sondage.is_some() {
            refus.push(
                "tiktok ne sert pas de sondage (aucun champ poll dans video/init ni \
                 content/init, relevés le 2026-09-02)"
                    .to_owned(),
            );
        }
        // made_with_ai : SERVI — TikTok a `is_aigc` (relevé le 2026-09-02).
        let _ = made_with_ai;
        if options.publish_at.is_some() {
            refus.push(
                "tiktok ne sert pas `publish_at` : aucune planification dans la Content \
                 Posting API (relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        match Self::privacy_level(options) {
            Some(niveau) => {
                // Le privacy effectif est RENDU : l'humain qui contresigne
                // doit savoir ce qui partira (défaut : SELF_ONLY).
                infos.push(format!(
                    "privacy_level = {niveau} (REQUIS par TikTok ; défaut sans `privacy` : \
                     SELF_ONLY) — vérifié contre privacy_level_options à la publication"
                ));
            }
            None => {
                refus.push(
                    "tiktok ne sert pas `unlisted` : privacy_level ∈ {PUBLIC_TO_EVERYONE, \
                     MUTUAL_FOLLOW_FRIENDS, FOLLOWER_OF_CREATOR, SELF_ONLY} (direct-post, \
                     relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
        }
        // Le texte : title vidéo (≤ 2200) ou description photo (≤ 4000).
        let poids = poids_utf16(texte);
        if videos > 0 && poids > TITRE_VIDEO_MAX_UTF16 {
            refus.push(format!(
                "title vidéo « 2200 in UTF-16 runes » max (direct-post, relevé le \
                 2026-09-02), reçu {poids}"
            ));
        }
        if photos > 0 && poids > DESCRIPTION_PHOTO_MAX_UTF16 {
            refus.push(format!(
                "description photo « 4000 UTF-16 runes » max (photo-post, relevé le \
                 2026-09-02), reçu {poids}"
            ));
        }
        infos.push(CITATION_AVANT_AUDIT.to_owned());

        let media: Vec<ApercuMedia> = medias.iter().map(apercu_media).collect();
        let limites_ok = refus.is_empty() && media.iter().all(|m| m.limits_ok);
        let mut verdicts = refus;
        verdicts.append(&mut infos);
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai, options),
            platform_limits_ok: limites_ok,
            // TikTok ne facture pas la publication : None, pas 0,0.
            cost_estimate_usd: None,
            media,
            verdicts,
            cout_quota: None,
        }
    }

    /// `handle` est le display_name (identite_depuis range (display_name,
    /// open_id)) — il sert l'URL de repli, honnêtement approximative.
    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
        medias: &[MediaPret],
        _sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        // C7 : l'aperçu passe avant — sondage/publish_at/unlisted/mélange
        // sont déjà refusés. Un contournement prend un refus local.
        let Some(privacy_level) = Self::privacy_level(options) else {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        };
        self.verifier_creator_info(jeton, privacy_level).await?;

        let publish_id = match medias {
            [] => return Err(ErreurPlateforme::Refus { statut: 400 }),
            [seul] if seul.type_detecte == TypeMedia::Mp4 => {
                self.publier_video(jeton, seul, texte, privacy_level, made_with_ai)
                    .await?
            }
            tous if tous
                .iter()
                .all(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Webp)) =>
            {
                self.publier_photos(jeton, tous, texte, privacy_level, made_with_ai)
                    .await?
            }
            _ => return Err(ErreurPlateforme::Refus { statut: 400 }),
        };

        let id_public = self.attendre_publication(jeton, &publish_id).await;
        // Les octets déposés pour le pull n'ont plus rien à faire sur la
        // route publique une fois l'état terminal atteint (succès OU échec).
        for m in medias {
            self.depot.retirer(&m.digest);
        }
        let id_public = id_public?;
        Ok(match id_public {
            Some(id) => Publication {
                url: format!("https://www.tiktok.com/@{handle}/video/{id}"),
                id_plateforme: id,
            },
            // Pas d'id public (SELF_ONLY avant audit, ou modération en
            // cours) : le publish_id EST notre identifiant, et l'URL du
            // profil est ce qu'on peut dire de plus vrai — honnête et
            // commenté (le display_name peut différer du @username, que
            // user.info.basic ne sert pas).
            None => Publication {
                id_plateforme: publish_id,
                url: format!("https://www.tiktok.com/@{handle}"),
            },
        })
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        // Un publish_id (pas d'id public rendu avant audit) ne se requête pas
        // dans video/query : dire « pas de données » plutôt qu'un 400 obscur.
        let Ok(id) = id_plateforme.parse::<i64>() else {
            return Ok(None);
        };
        let (statut, corps) = envoyer(
            http()
                .post(POINT_VIDEO_QUERY)
                .query(&[(
                    "fields",
                    "id,like_count,comment_count,share_count,view_count",
                )])
                .bearer_auth(jeton.expose_for_transport())
                .json(&json!({ "filters": { "video_ids": [id] } })),
        )
        .await?;
        metriques_depuis(statut, &corps).map(Some)
    }
}

// ---------------------------------------------------------------------------
// La messagerie — TikTok sert TROIS lectures (ses propres vidéos, son propre
// profil) et refuse tout le reste, citations datées. Sondes du 2026-09-02.
// ---------------------------------------------------------------------------

const CITATION_COMMENTAIRES: &str = "il n'existe AUCUNE API de lecture/réponse aux commentaires pour un développeur \
     self-serve — la seule lecture est /v2/research/video/comment/list/ (Research \
     API, chercheurs vettés seulement ; relevé le 2026-09-02)";

const CITATION_RECHERCHE: &str = "la Research API est réservée aux chercheurs « the U.S., Europe, Canada, and \
     Brazil » affiliés à des institutions académiques (relevé le 2026-09-02)";

const CITATION_AUCUN_SCOPE: &str = "aucun endpoint public — la liste exhaustive des scopes (tiktok-api-scopes, \
     relevé le 2026-09-02) ne porte ni DM, ni like, ni bookmark, ni repost, ni quote";

const CITATION_PAS_DE_TIERS: &str = "video/list et user/info ne servent que le compte du jeton (Display API, relevé \
     le 2026-09-02) — pas de lecture de tiers";

fn ne_sert_pas(citation: &'static str, deblocage: &'static str) -> ErreurMessagerie {
    ErreurMessagerie::NeSertPas {
        citation,
        deblocage,
    }
}

#[async_trait]
impl PlateformeMessagerie for Tiktok {
    fn nom(&self) -> &'static str {
        "tiktok"
    }

    async fn dm_reply(
        &self,
        _jeton: &Secret,
        _dm_conversation_id: &str,
        _texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn dm_open(
        &self,
        _jeton: &Secret,
        _participant_id: &str,
        _texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn inbox(&self, _jeton: &Secret, _user_id: &str) -> Result<Inbox, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_reply(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _in_reply_to_post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_COMMENTAIRES,
            "être un chercheur vetté de la Research API — inaccessible à un produit \
             commercial",
        ))
    }

    async fn post_comment(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        _parent_comment: Option<&str>,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_COMMENTAIRES,
            "être un chercheur vetté de la Research API — inaccessible à un produit \
             commercial",
        ))
    }

    async fn post_like(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_unlike(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_bookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_unbookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_repost(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn post_quote(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_SCOPE, "rien"))
    }

    async fn search_posts(
        &self,
        _jeton: &Secret,
        _query: &str,
        _max_results: u8,
    ) -> Result<PostsLus, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_RECHERCHE,
            "rien pour un client commercial",
        ))
    }

    /// SES vidéos : video/query (scope video.list).
    async fn read_post(
        &self,
        jeton: &Secret,
        post_id: &str,
    ) -> Result<ElementLu, ErreurMessagerie> {
        let id: i64 = post_id
            .parse()
            .map_err(|_| ErreurPlateforme::Refus { statut: 400 })?;
        let (statut, corps) = envoyer(
            http()
                .post(POINT_VIDEO_QUERY)
                .query(&[("fields", "id,title")])
                .bearer_auth(jeton.expose_for_transport())
                .json(&json!({ "filters": { "video_ids": [id] } })),
        )
        .await?;
        videos_depuis(statut, &corps)?
            .into_iter()
            .next()
            .ok_or_else(|| ErreurPlateforme::Refus { statut: 404 }.into())
    }

    async fn read_profile(
        &self,
        jeton: &Secret,
        username: &str,
    ) -> Result<ProfilLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_USER_INFO)
                .query(&[("fields", "open_id,display_name")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let (open_id, display_name) = utilisateur_depuis(statut, &corps)?;
        // Son propre profil UNIQUEMENT : un autre nom est un tiers, refusé
        // avec la citation — jamais un appel qui « essaie ».
        if username != open_id && username != display_name {
            return Err(ne_sert_pas(CITATION_PAS_DE_TIERS, "rien"));
        }
        Ok(ProfilLu {
            id: open_id,
            // user.info.basic ne sert pas le @username (scope
            // user.info.profile) : le display_name est ce qu'on tient.
            username: display_name.clone(),
            nom: display_name,
            third_party: true,
        })
    }

    /// SES vidéos publiques : video/list, max_count 20 — uniquement si
    /// `user_id` est l'open_id du compte.
    async fn read_timeline(
        &self,
        jeton: &Secret,
        user_id: &str,
    ) -> Result<PostsLus, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_USER_INFO)
                .query(&[("fields", "open_id,display_name")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let (open_id, _) = utilisateur_depuis(statut, &corps)?;
        if user_id != open_id {
            return Err(ne_sert_pas(CITATION_PAS_DE_TIERS, "rien"));
        }
        let (statut, corps) = envoyer(
            http()
                .post(POINT_VIDEO_LIST)
                .query(&[("fields", "id,title")])
                .bearer_auth(jeton.expose_for_transport())
                .json(&json!({ "max_count": 20 })),
        )
        .await?;
        let posts = videos_depuis(statut, &corps)?;
        Ok(PostsLus {
            posts,
            // La Display API ne facture pas : 0,0 est un fait.
            cout_usd: 0.0,
            cout_quota: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::test_medias::media;

    /// Des options vides — le cas de tous les posts d'avant la table v3.
    const SANS: OptionsPost = OptionsPost {
        privacy: None,
        publish_at: None,
    };

    fn tiktok() -> Tiktok {
        Tiktok::nouvel(&ContexteAdaptateurs {
            base_publique: "https://social.example".to_owned(),
            depot: Arc::new(DepotMedias::new()),
        })
    }

    fn mp4(octets: usize) -> MediaPret {
        media(&vec![7u8; octets], TypeMedia::Mp4)
    }

    /// Le chunking cité : < 5 MB = un morceau ; ≤ 16 MiB = un morceau ;
    /// au-delà, des chunks de 16 MiB dont le DERNIER absorbe le reste
    /// (« up to 128 MB » — ici toujours < 32 MiB).
    #[test]
    fn le_plan_de_chunks_suit_les_regles_citees() {
        // 3 MB : un seul morceau, la règle « < 5 MB ».
        let (chunk, total, bornes) = plan_chunks(3_000_000);
        assert_eq!((chunk, total), (3_000_000, 1));
        assert_eq!(bornes, vec![(0, 2_999_999)]);
        // 10 MB (≥ 5 MB, < 16 MiB) : un seul morceau dans [5, 64] MB.
        assert_eq!(plan_chunks(10_000_000).1, 1);
        // 40 MiB : 2 chunks — 16 MiB puis 24 MiB (le dernier absorbe).
        let taille = 40 * 1024 * 1024;
        let (chunk, total, bornes) = plan_chunks(taille);
        assert_eq!((chunk, total), (TAILLE_CHUNK, 2));
        assert_eq!(bornes[0], (0, TAILLE_CHUNK - 1));
        assert_eq!(bornes[1], (TAILLE_CHUNK, taille - 1));
        // Les bornes couvrent tout, sans trou ni recouvrement.
        assert_eq!(bornes[1].1 - bornes[1].0 + 1, 24 * 1024 * 1024);
        // Et le Content-Range est celui de la doc.
        assert_eq!(
            content_range(0, TAILLE_CHUNK - 1, taille),
            format!("bytes 0-{}/{}", TAILLE_CHUNK - 1, taille)
        );
    }

    /// Le corps video/init de la doc — FILE_UPLOAD, privacy_level REQUIS,
    /// is_aigc dans post_info quand made_with_ai est vrai.
    #[test]
    fn le_corps_video_init_est_celui_de_la_doc() {
        let corps = corps_video_init("Mon titre", "SELF_ONLY", true, 3_000_000);
        assert_eq!(
            corps,
            serde_json::json!({
                "post_info": {
                    "title": "Mon titre",
                    "privacy_level": "SELF_ONLY",
                    "is_aigc": true
                },
                "source_info": {
                    "source": "FILE_UPLOAD",
                    "video_size": 3_000_000,
                    "chunk_size": 3_000_000,
                    "total_chunk_count": 1
                }
            })
        );
        // is_aigc absent quand faux : champ absent ≠ champ nul.
        assert!(
            corps_video_init("t", "SELF_ONLY", false, 10)["post_info"]
                .get("is_aigc")
                .is_none()
        );
    }

    /// Le corps photo : PULL_FROM_URL et des URLs dérivées du digest PAR la
    /// fonction elle-même (le chemin réel de `publier_photos`) — LA preuve du
    /// modèle pull : jamais l'URL du client (que `MediaPret` ne porte même
    /// pas). Substituer une autre URL dans le corps fait rougir CE test.
    #[test]
    fn le_corps_photo_tire_chez_nous_jamais_chez_le_client() {
        let a = media(b"photo A", TypeMedia::Jpeg);
        let corps = corps_photo_init(
            Some("Titre"),
            "La description",
            "SELF_ONLY",
            "https://social.example",
            std::slice::from_ref(&a),
            true,
        );
        assert_eq!(corps["media_type"], "PHOTO");
        assert_eq!(corps["post_mode"], "DIRECT_POST");
        assert_eq!(corps["source_info"]["source"], "PULL_FROM_URL");
        assert_eq!(
            corps["source_info"]["photo_images"][0],
            format!("https://social.example/medias/{}", a.digest)
        );
        assert_eq!(corps["source_info"]["photo_cover_index"], 0);
        assert_eq!(corps["post_info"]["title"], "Titre");
        assert_eq!(corps["post_info"]["description"], "La description");
        // is_aigc au NIVEAU RACINE pour les photos (photo-post, 2026-09-02).
        assert_eq!(corps["is_aigc"], true);
        assert!(corps["post_info"].get("is_aigc").is_none());
    }

    /// Le mapping privacy figé — et unlisted n'existe pas chez TikTok.
    #[test]
    fn le_mapping_privacy_est_celui_de_la_doc() {
        assert_eq!(privacy_tiktok(Privacy::Public), Some("PUBLIC_TO_EVERYONE"));
        assert_eq!(
            privacy_tiktok(Privacy::Friends),
            Some("MUTUAL_FOLLOW_FRIENDS")
        );
        assert_eq!(
            privacy_tiktok(Privacy::Followers),
            Some("FOLLOWER_OF_CREATOR")
        );
        assert_eq!(privacy_tiktok(Privacy::Private), Some("SELF_ONLY"));
        assert_eq!(privacy_tiktok(Privacy::Unlisted), None);
        // Défaut absent : SELF_ONLY — rien ne devient public sans le demander.
        assert_eq!(Tiktok::privacy_level(&SANS), Some(PRIVACY_DEFAUT));
    }

    #[test]
    fn les_lecteurs_lisent_les_formes_documentees() {
        let init = br#"{"data":{"publish_id":"v_pub_url~v2.123","upload_url":"https://open-upload.tiktokapis.com/video/?upload_id=1"},"error":{"code":"ok","message":"","log_id":"x"}}"#;
        let (id, url) = init_depuis(200, init).unwrap();
        assert_eq!(id, "v_pub_url~v2.123");
        assert!(url.unwrap().starts_with("https://open-upload"));

        // Un 200 avec error.code non-ok est un REFUS, pas un succès.
        let refuse = br#"{"data":{},"error":{"code":"unaudited_client_can_only_post_to_private_accounts","message":"..."}}"#;
        assert_eq!(
            init_depuis(200, refuse),
            Err(ErreurPlateforme::Refus { statut: 400 })
        );

        let options =
            creator_info_depuis(200, br#"{"data":{"privacy_level_options":["SELF_ONLY","PUBLIC_TO_EVERYONE"]},"error":{"code":"ok"}}"#)
                .unwrap();
        assert_eq!(options, vec!["SELF_ONLY", "PUBLIC_TO_EVERYONE"]);

        // Les statuts de la micro-sonde du 2026-09-02.
        assert_eq!(
            statut_publication_depuis(
                200,
                br#"{"data":{"status":"PROCESSING_UPLOAD"},"error":{"code":"ok"}}"#
            )
            .unwrap(),
            EtatPublication::EnCours
        );
        assert_eq!(
            statut_publication_depuis(
                200,
                br#"{"data":{"status":"PUBLISH_COMPLETE","publicaly_available_post_id":[7345678901234567890]},"error":{"code":"ok"}}"#
            )
            .unwrap(),
            EtatPublication::Publie {
                id_public: Some("7345678901234567890".to_owned())
            }
        );
        assert_eq!(
            statut_publication_depuis(
                200,
                br#"{"data":{"status":"PUBLISH_COMPLETE"},"error":{"code":"ok"}}"#
            )
            .unwrap(),
            EtatPublication::Publie { id_public: None }
        );
        assert_eq!(
            statut_publication_depuis(
                200,
                br#"{"data":{"status":"FAILED","fail_reason":"spam_risk"},"error":{"code":"ok"}}"#
            )
            .unwrap(),
            EtatPublication::Echec
        );

        let m = metriques_depuis(
            200,
            br#"{"data":{"videos":[{"id":7345,"like_count":5,"comment_count":2,"share_count":1,"view_count":90}]},"error":{"code":"ok"}}"#,
        )
        .unwrap();
        assert_eq!(m.impressions, Some(90));
        assert_eq!(m.likes, 5);
        assert_eq!(m.replies, 2);
        assert_eq!(m.reposts, 1);

        let (open_id, nom) =
            utilisateur_depuis(200, br#"{"data":{"user":{"open_id":"abc-123","display_name":"Orizn"}},"error":{"code":"ok"}}"#)
                .unwrap();
        assert_eq!((open_id.as_str(), nom.as_str()), ("abc-123", "Orizn"));
    }

    #[test]
    fn aucun_lecteur_ne_laisse_fuir_un_jeton() {
        let hostile =
            br#"{"error":{"code":"access_token_invalid","message":"Bearer JETON-SECRET refuse"}}"#;
        for statut in [200, 400, 401, 429, 500] {
            let rendus = [
                format!("{:?}", init_depuis(statut, hostile)),
                format!("{:?}", creator_info_depuis(statut, hostile)),
                format!("{:?}", statut_publication_depuis(statut, hostile)),
                format!("{:?}", metriques_depuis(statut, hostile)),
                format!("{:?}", utilisateur_depuis(statut, hostile)),
            ];
            for rendu in rendus {
                assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
            }
        }
    }

    /// Le poids « UTF-16 runes » : la doc compte en unités UTF-16 — un émoji
    /// hors BMP pèse 2, un latin 1.
    #[test]
    fn le_poids_utf16_compte_comme_la_doc() {
        assert_eq!(poids_utf16("abc"), 3);
        assert_eq!(poids_utf16("🦀"), 2);
        let tiktok = tiktok();
        // 2200 unités passent en titre vidéo, 2201 non.
        let v = [mp4(10)];
        assert!(
            tiktok
                .apercu(&"a".repeat(2200), &v, None, false, &SANS)
                .platform_limits_ok
        );
        assert!(
            !tiktok
                .apercu(&"a".repeat(2201), &v, None, false, &SANS)
                .platform_limits_ok
        );
        // 1101 émojis = 2202 unités : refusé aussi — le comptage est UTF-16,
        // pas en caractères.
        assert!(
            !tiktok
                .apercu(&"🦀".repeat(1101), &v, None, false, &SANS)
                .platform_limits_ok
        );
    }

    #[test]
    fn l_apercu_refuse_ce_que_tiktok_refuse_mots_exacts() {
        let tiktok = tiktok();
        // PNG : WebP/JPEG seuls.
        let png = [media(&crate::medias::octets_png(b"x"), TypeMedia::Png)];
        let apercu = tiktok.apercu("t", &png, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("WebP et JPEG")),
            "{:?}",
            apercu.media[0].verdicts
        );
        // Photo de 21 MB : « Maximum of 20MB », chiffre cité.
        let lourde = [media(&vec![0u8; 21_000_000], TypeMedia::Jpeg)];
        let apercu = tiktok.apercu("t", &lourde, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("20MB") && v.contains("21000000")),
            "{:?}",
            apercu.media[0].verdicts
        );
        // Mélange photo+vidéo : refusé.
        let mix = [media(b"i", TypeMedia::Jpeg), mp4(10)];
        assert!(
            !tiktok
                .apercu("t", &mix, None, false, &SANS)
                .platform_limits_ok
        );
        // unlisted : TikTok ne le sert pas.
        let unlisted = OptionsPost {
            privacy: Some(Privacy::Unlisted),
            publish_at: None,
        };
        let apercu = tiktok.apercu("t", &[mp4(10)], None, false, &unlisted);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("unlisted")),
            "{:?}",
            apercu.verdicts
        );
        // publish_at : aucune planification.
        let differe = OptionsPost {
            privacy: None,
            publish_at: Some("2026-10-01T09:00:00Z".to_owned()),
        };
        assert!(
            !tiktok
                .apercu("t", &[mp4(10)], None, false, &differe)
                .platform_limits_ok
        );
        // Texte seul : pas de post texte chez TikTok.
        assert!(
            !tiktok
                .apercu("t", &[], None, false, &SANS)
                .platform_limits_ok
        );
    }

    /// Une vidéo propre passe — made_with_ai est SERVI (is_aigc) — et l'état
    /// avant-audit + le privacy effectif sont RENDUS.
    #[test]
    fn une_video_propre_passe_et_l_etat_avant_audit_est_rendu() {
        let tiktok = tiktok();
        let apercu = tiktok.apercu("Mon titre", &[mp4(10)], None, true, &SANS);
        assert!(apercu.platform_limits_ok, "{:?}", apercu.verdicts);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("Unaudited API Clients")),
            "{:?}",
            apercu.verdicts
        );
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("privacy_level = SELF_ONLY")),
            "{:?}",
            apercu.verdicts
        );
        // 35 photos passent, 36 non.
        let n35: Vec<_> = (0..35)
            .map(|i| media(&[i as u8], TypeMedia::Webp))
            .collect();
        assert!(
            tiktok
                .apercu("t", &n35, None, false, &SANS)
                .platform_limits_ok
        );
        let n36: Vec<_> = (0..36)
            .map(|i| media(&[i as u8], TypeMedia::Webp))
            .collect();
        assert!(
            !tiktok
                .apercu("t", &n36, None, false, &SANS)
                .platform_limits_ok
        );
    }

    /// Chaque refus messagerie est un fait cité et daté — jamais un stub.
    #[tokio::test]
    async fn les_refus_messagerie_portent_leurs_citations() {
        let tiktok = tiktok();
        let jeton = Secret::new("jeton");
        let cas: Vec<(&str, ErreurMessagerie)> = vec![
            (
                "dm_reply",
                tiktok.dm_reply(&jeton, "1", "t").await.unwrap_err(),
            ),
            (
                "dm_open",
                tiktok.dm_open(&jeton, "1", "t").await.unwrap_err(),
            ),
            ("inbox", tiktok.inbox(&jeton, "1").await.unwrap_err()),
            (
                "post_reply",
                tiktok.post_reply(&jeton, "h", "1", "t").await.unwrap_err(),
            ),
            (
                "post_comment",
                tiktok
                    .post_comment(&jeton, "h", "1", None, "t")
                    .await
                    .unwrap_err(),
            ),
            (
                "post_like",
                tiktok.post_like(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "bookmark",
                tiktok.post_bookmark(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "repost",
                tiktok.post_repost(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "quote",
                tiktok.post_quote(&jeton, "h", "1", "t").await.unwrap_err(),
            ),
            (
                "search",
                tiktok.search_posts(&jeton, "q", 10).await.unwrap_err(),
            ),
        ];
        for (nom, erreur) in cas {
            assert_eq!(erreur.code(), "plateforme_ne_sert_pas", "{nom}");
            let ErreurMessagerie::NeSertPas { citation, .. } = erreur else {
                panic!("{nom} doit être NeSertPas");
            };
            assert!(citation.contains("2026-09-02"), "{nom}: {citation}");
        }
    }

    #[test]
    fn les_points_d_api_sont_en_https() {
        for point in [
            POINT_CREATOR_INFO,
            POINT_VIDEO_INIT,
            POINT_CONTENT_INIT,
            POINT_STATUS,
            POINT_VIDEO_QUERY,
            POINT_VIDEO_LIST,
            POINT_USER_INFO,
        ] {
            assert!(point.starts_with("https://open.tiktokapis.com/"), "{point}");
        }
    }
}
