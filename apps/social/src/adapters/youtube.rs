//! YouTube : vidéo en octets DIRECTS (protocole resumable), miniature,
//! commentaires, likes, recherche, lectures — Data API v3, la plus riche des
//! trois plateformes du chantier.
//!
//! Tout vient de developers.google.com/youtube/v3, relevé le 2026-09-02 :
//!
//! * Upload resumable (guides/using_resumable_upload_protocol) : (1)
//!   `POST /upload/youtube/v3/videos?uploadType=resumable&part=snippet,status`
//!   avec `X-Upload-Content-Length`/`X-Upload-Content-Type`, corps = les
//!   métadonnées ; (2) l'en-tête `Location` = l'URI de session ; (3) PUT des
//!   octets, chunks MULTIPLES DE 256 KB, 308 par chunk non final, 200/201 à
//!   la fin ; (4) reprise : `Content-Range: bytes */TOTAL` → 308 + `Range`.
//!   256 GB max côté plateforme — notre plafond service reste 512 MiB (C5,
//!   medias.rs). Aucun modèle pull : les octets partent directs, toujours.
//! * `videos.insert` (docs/videos/insert) : « All videos uploaded via the
//!   videos.insert endpoint from unverified API projects created after
//!   28 July 2020 will be restricted to private viewing mode. To lift this
//!   restriction, each project must undergo an audit » ; `snippet.title`
//!   OBLIGATOIRE, `snippet.description`, `status.privacyStatus` ∈ {private,
//!   public, unlisted}, `status.publishAt` (ISO 8601) « réglable seulement si
//!   privacyStatus=private ; une date passée publie immédiatement »
//!   (docs/videos, relevé le 2026-09-02).
//! * Miniature : `POST /upload/youtube/v3/thumbnails/set?videoId=` — 2 MB
//!   max, image/jpeg|png, ~50 unités (docs/thumbnails/set, 2026-09-02).
//! * Shorts : « AUCUN champ dans la ressource videos — un Short est une
//!   vidéo verticale/carrée ≤ 3 minutes, classée automatiquement »
//!   (support.google.com/youtube/answer/10059070, relevé le 2026-09-02).
//! * Quotas (guides/quota_and_compliance_audits + revision_history, relevés
//!   le 2026-09-02) : depuis le 2026-06-01, `videos.insert` et `search.list`
//!   ont leurs PROPRES buckets — 100 appels/jour chacun, 1 point par appel —
//!   et le pool général reste 10 000 unités/jour (reset minuit Pacifique).
//!   L'API est GRATUITE : le quota est la seule monnaie —
//!   `cost_estimate_usd: None`, `cout_quota` porte les unités.
//! * Écritures du pool général : commentThreads.insert 50,
//!   comments.insert 50, videos.rate 50, thumbnails.set 50 ; lectures 1
//!   (videos.list, channels.list, playlistItems.list).
//!
//! Restes nommés (pas de stub) : la reprise d'upload (`bytes */TOTAL`) —
//! ponytail: échec net + rejeu par clé d'idempotence, la reprise mi-vol
//! viendra si les uploads réels cassent ; captions.insert (400 unités,
//! docs/captions/insert) — aucun argument d'outil ne la porte.

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{
    ActionFaite, Apercu, ApercuMedia, ElementLu, ErreurMessagerie, ErreurPlateforme, Inbox,
    MediaPret, MessagePrive, Metriques, OptionsPost, Plateforme, PlateformeMessagerie, PostsLus,
    Privacy, ProfilLu, Publication, ReponsePubliee, Sondage, TypeMedia, empreinte_globale, envoyer,
    http, http_upload,
};

/// Les points d'API — developers.google.com/youtube/v3, relevés le 2026-09-02.
pub const POINT_UPLOAD_VIDEOS: &str = "https://www.googleapis.com/upload/youtube/v3/videos";
pub const POINT_VIDEOS: &str = "https://www.googleapis.com/youtube/v3/videos";
pub const POINT_VIDEOS_RATE: &str = "https://www.googleapis.com/youtube/v3/videos/rate";
pub const POINT_THUMBNAILS: &str = "https://www.googleapis.com/upload/youtube/v3/thumbnails/set";
pub const POINT_COMMENT_THREADS: &str = "https://www.googleapis.com/youtube/v3/commentThreads";
pub const POINT_COMMENTS: &str = "https://www.googleapis.com/youtube/v3/comments";
pub const POINT_SEARCH: &str = "https://www.googleapis.com/youtube/v3/search";
pub const POINT_CHANNELS: &str = "https://www.googleapis.com/youtube/v3/channels";
pub const POINT_PLAYLIST_ITEMS: &str = "https://www.googleapis.com/youtube/v3/playlistItems";

/// Chunk d'upload : 16 MiB — multiple de 256 KB comme le protocole l'exige
/// (using_resumable_upload_protocol, relevé le 2026-09-02).
pub const TAILLE_CHUNK: usize = 16 * 1024 * 1024;
/// « 2MB » miniature (thumbnails/set, relevé le 2026-09-02) — décimal strict.
pub const OCTETS_MAX_MINIATURE: u64 = 2_000_000;

/// Les coûts en unités de quota (determine_quota_cost, relevé le 2026-09-02).
pub const QUOTA_MINIATURE: u64 = 50;
pub const QUOTA_COMMENTAIRE: u64 = 50;
pub const QUOTA_RATE: u64 = 50;
pub const QUOTA_LECTURE: u64 = 1;

/// L'état avant-audit, rendu en verdict INFORMATIF (videos/insert, relevé le
/// 2026-09-02) — statique : le service ne peut pas sonder l'état d'audit.
pub const CITATION_AVANT_AUDIT: &str = "« All videos uploaded via the videos.insert endpoint from unverified API \
     projects created after 28 July 2020 will be restricted to private viewing \
     mode. To lift this restriction, each project must undergo an audit » \
     (videos/insert, relevé le 2026-09-02) — demander `public` avant audit publie \
     quand même, mais PRIVÉ";

/// Le bucket dédié de videos.insert (revision_history, relevé le 2026-09-02).
pub const CITATION_BUCKET_INSERT: &str = "1 appel videos.insert — bucket dédié : 100 appels/jour depuis le 2026-06-01, \
     1 point par appel (revision_history, relevé le 2026-09-02)";

/// Le verdict Shorts (support.google.com/youtube/answer/10059070, 2026-09-02).
pub const CITATION_SHORTS: &str = "un Short n'est pas un champ : toute vidéo verticale/carrée de 3 minutes ou \
     moins est classée Short automatiquement (support.google.com/youtube/answer/\
     10059070, relevé le 2026-09-02)";

/// Le mot YouTube pour chaque `privacy` — `None` = pas servi (privacyStatus
/// ∈ {private, public, unlisted}, docs/videos, relevé le 2026-09-02).
pub fn privacy_youtube(p: Privacy) -> Option<&'static str> {
    match p {
        Privacy::Public => Some("public"),
        Privacy::Private => Some("private"),
        Privacy::Unlisted => Some("unlisted"),
        Privacy::Friends | Privacy::Followers => None,
    }
}

/// Le défaut quand `privacy` est absent : `private` — la seule visibilité
/// qu'un projet non audité obtient de toute façon (citation ci-dessus).
pub const PRIVACY_DEFAUT: &str = "private";

/// Les métadonnées de l'étape (1) du resumable : `snippet.title` OBLIGATOIRE
/// (media[].title), `snippet.description` = le texte de l'outil,
/// `status.privacyStatus`, `status.publishAt` — qui FORCE private (« réglable
/// seulement si privacyStatus=private », docs/videos, relevé le 2026-09-02).
pub fn corps_metadonnees(
    titre: &str,
    description: &str,
    privacy: &str,
    publish_at: Option<&str>,
) -> serde_json::Value {
    let mut status = json!({
        "privacyStatus": if publish_at.is_some() { "private" } else { privacy }
    });
    if let Some(quand) = publish_at {
        status["publishAt"] = json!(quand);
    }
    json!({
        "snippet": { "title": titre, "description": description },
        "status": status
    })
}

/// `commentThreads.insert` : commentaire de premier niveau sur une vidéo —
/// `snippet.channelId` + `snippet.videoId` + `topLevelComment.snippet.
/// textOriginal`, scope youtube.force-ssl, 50 unités (commentThreads/insert,
/// relevé le 2026-09-02).
pub fn corps_comment_thread(channel_id: &str, video_id: &str, texte: &str) -> serde_json::Value {
    json!({
        "snippet": {
            "channelId": channel_id,
            "videoId": video_id,
            "topLevelComment": { "snippet": { "textOriginal": texte } }
        }
    })
}

/// `comments.insert` : réponse à un commentaire — `snippet.parentId` +
/// `snippet.textOriginal`, 50 unités (comments/insert, relevé le 2026-09-02).
pub fn corps_comment_reply(parent_id: &str, texte: &str) -> serde_json::Value {
    json!({ "snippet": { "parentId": parent_id, "textOriginal": texte } })
}

/// Lit `{"id": "..."}` de la ressource rendue (vidéo, thread, commentaire).
pub fn id_depuis(statut: u16, corps: &[u8]) -> Result<String, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    document
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(ErreurPlateforme::Illisible)
}

/// Lit `items[0].statistics` de videos.list — `impressions: None` : le
/// viewCount n'est PAS une impression (compté « dès que la vidéo démarre »
/// depuis le 2026-08-24, relevé le 2026-09-02) ; `reposts: 0` : pas de
/// repost YouTube — un fait, pas une donnée manquante.
pub fn metriques_depuis(statut: u16, corps: &[u8]) -> Result<Metriques, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let stats = document
        .pointer("/items/0/statistics")
        .ok_or(ErreurPlateforme::Illisible)?;
    // Les compteurs sont des CHAÎNES chez YouTube ("likeCount": "5").
    let compte = |nom: &str| {
        stats
            .get(nom)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
    };
    Ok(Metriques {
        impressions: None,
        likes: compte("likeCount").unwrap_or(0),
        replies: compte("commentCount").unwrap_or(0),
        reposts: 0,
    })
}

/// Lit `items[]` de search.list : id.videoId + snippet.title/description.
pub fn recherche_depuis(statut: u16, corps: &[u8]) -> Result<Vec<ElementLu>, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    Ok(document
        .get("items")
        .and_then(|v| v.as_array())
        .map(|liste| {
            liste
                .iter()
                .filter_map(|e| {
                    Some(ElementLu {
                        id: e.pointer("/id/videoId")?.as_str()?.to_owned(),
                        auteur_id: e
                            .pointer("/snippet/channelId")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                        texte: texte_snippet(e.get("snippet")?),
                        third_party: true,
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Lit `items[0]` de videos.list en élément — texte = title + description.
pub fn element_depuis(statut: u16, corps: &[u8]) -> Result<ElementLu, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let element = document
        .pointer("/items/0")
        .ok_or(ErreurPlateforme::Refus { statut: 404 })?;
    Ok(ElementLu {
        id: element
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(ErreurPlateforme::Illisible)?
            .to_owned(),
        auteur_id: element
            .pointer("/snippet/channelId")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        texte: element
            .get("snippet")
            .map(texte_snippet)
            .unwrap_or_default(),
        third_party: true,
    })
}

fn texte_snippet(snippet: &serde_json::Value) -> String {
    let titre = snippet.get("title").and_then(|v| v.as_str()).unwrap_or("");
    let description = snippet
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if description.is_empty() {
        titre.to_owned()
    } else {
        format!("{titre}\n{description}")
    }
}

/// Lit `items[0]` de channels.list en profil.
pub fn profil_depuis(statut: u16, corps: &[u8]) -> Result<ProfilLu, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let element = document
        .pointer("/items/0")
        .ok_or(ErreurPlateforme::Refus { statut: 404 })?;
    let id = element
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    let titre = element
        .pointer("/snippet/title")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    Ok(ProfilLu {
        id: id.to_owned(),
        // channels.list ne rend pas de @handle séparé dans snippet.title —
        // le titre de chaîne sert les deux champs, honnête et commenté.
        username: titre.to_owned(),
        nom: titre.to_owned(),
        third_party: true,
    })
}

/// Lit la playlist « uploads » de channels.list part=contentDetails.
pub fn playlist_uploads_depuis(statut: u16, corps: &[u8]) -> Result<String, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    document
        .pointer("/items/0/contentDetails/relatedPlaylists/uploads")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(ErreurPlateforme::Illisible)
}

/// Lit `items[]` de playlistItems.list — id vidéo sous
/// `snippet.resourceId.videoId`.
pub fn playlist_items_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<Vec<ElementLu>, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    Ok(document
        .get("items")
        .and_then(|v| v.as_array())
        .map(|liste| {
            liste
                .iter()
                .filter_map(|e| {
                    Some(ElementLu {
                        id: e
                            .pointer("/snippet/resourceId/videoId")?
                            .as_str()?
                            .to_owned(),
                        auteur_id: e
                            .pointer("/snippet/channelId")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                        texte: texte_snippet(e.get("snippet")?),
                        third_party: true,
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Découpe en chunks de 16 MiB pour le PUT resumable.
pub fn chunks(octets: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    octets
        .chunks(TAILLE_CHUNK)
        .enumerate()
        .map(|(i, c)| (i * TAILLE_CHUNK, c))
}

/// Le verdict d'UN média, mots exacts et chiffres cités.
fn apercu_media(m: &MediaPret) -> ApercuMedia {
    let taille = m.octets.len() as u64;
    let mut verdicts = Vec::new();
    let mut ok = true;
    match m.type_detecte {
        TypeMedia::Mp4 => {
            if m.title.is_none() {
                ok = false;
                verdicts.push(
                    "YouTube exige un titre : poser media[].title (snippet.title est \
                     obligatoire — videos/insert, relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
            if m.alt_text.is_some() {
                ok = false;
                verdicts.push(
                    "youtube ne sert pas d'alt_text vidéo (aucun champ dans la ressource \
                     videos, relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
            verdicts.push(CITATION_SHORTS.to_owned());
        }
        TypeMedia::Jpeg | TypeMedia::Png => {
            // Une image ACCOMPAGNANT la vidéo = la miniature (thumbnails.set).
            if taille > OCTETS_MAX_MINIATURE {
                ok = false;
                verdicts.push(format!(
                    "2 MB max pour une miniature (thumbnails/set, relevé le 2026-09-02), \
                     reçu {taille} octets"
                ));
            }
            if m.title.is_some() || m.alt_text.is_some() {
                ok = false;
                verdicts.push(
                    "une miniature ne porte ni title ni alt_text (thumbnails/set, relevé \
                     le 2026-09-02)"
                        .to_owned(),
                );
            }
        }
        TypeMedia::Gif | TypeMedia::Webp | TypeMedia::Pdf => {
            ok = false;
            verdicts.push(format!(
                "youtube ne sert ni GIF, ni WebP, ni document : une vidéo (et sa miniature \
                 JPEG/PNG) — reçu {} (videos/insert + thumbnails/set, relevés le \
                 2026-09-02)",
                m.type_detecte.mime()
            ));
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

pub struct Youtube;

impl Youtube {
    /// Le channel id du compte : channels.list mine=true — 1 unité, comptée
    /// dans le cout_quota des appels qui en ont besoin.
    async fn mon_channel_id(&self, jeton: &Secret) -> Result<String, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_CHANNELS)
                .query(&[("part", "id"), ("mine", "true")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur);
        }
        let document: serde_json::Value =
            serde_json::from_slice(&corps).map_err(|_| ErreurPlateforme::Illisible)?;
        document
            .pointer("/items/0/id")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    }

    /// Le protocole resumable, étapes (1) à (3). ponytail: pas de reprise
    /// `bytes */TOTAL` — un chunk qui casse rend Injoignable et le rejeu
    /// passe par la clé d'idempotence ; la reprise mi-vol viendra si les
    /// uploads réels cassent.
    async fn televerser_video(
        &self,
        jeton: &Secret,
        m: &MediaPret,
        metadonnees: &serde_json::Value,
    ) -> Result<String, ErreurPlateforme> {
        let taille = m.octets.len();
        let reponse = http()
            .post(POINT_UPLOAD_VIDEOS)
            .query(&[("uploadType", "resumable"), ("part", "snippet,status")])
            .bearer_auth(jeton.expose_for_transport())
            .header("X-Upload-Content-Length", taille.to_string())
            .header("X-Upload-Content-Type", m.type_detecte.mime())
            .json(metadonnees)
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(reponse.status().as_u16()) {
            return Err(erreur);
        }
        // (2) L'URI de session est dans l'en-tête Location.
        let session = reponse
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)?;

        // (3) PUT des chunks — 308 (Resume Incomplete) par chunk non final,
        // 200/201 avec la ressource vidéo à la fin.
        let mut id = None;
        for (depart, chunk) in chunks(&m.octets) {
            let fin = depart + chunk.len() - 1;
            let reponse = http_upload()
                .put(&session)
                .header("Content-Range", format!("bytes {depart}-{fin}/{taille}"))
                .body(chunk.to_vec())
                .send()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            let statut = reponse.status().as_u16();
            if statut == 308 {
                continue; // chunk non final accepté — le suivant part.
            }
            if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
                return Err(erreur);
            }
            let corps = reponse
                .bytes()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            id = Some(id_depuis(statut, &corps)?);
        }
        id.ok_or(ErreurPlateforme::Illisible)
    }

    /// thumbnails.set : les octets de l'image, 2 MB max, 50 unités.
    async fn poser_miniature(
        &self,
        jeton: &Secret,
        video_id: &str,
        m: &MediaPret,
    ) -> Result<(), ErreurPlateforme> {
        let (statut, _corps) = envoyer(
            http_upload()
                .post(POINT_THUMBNAILS)
                .query(&[("videoId", video_id)])
                .bearer_auth(jeton.expose_for_transport())
                .header("Content-Type", m.type_detecte.mime())
                .body(m.octets.as_ref().clone()),
        )
        .await?;
        match ErreurPlateforme::depuis_statut(statut) {
            None => Ok(()),
            Some(erreur) => Err(erreur),
        }
    }
}

#[async_trait]
impl Plateforme for Youtube {
    fn nom(&self) -> &'static str {
        "youtube"
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

        let videos = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Mp4)
            .count();
        let images = medias
            .iter()
            .filter(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Png))
            .count();
        if videos == 0 {
            refus.push(
                "youtube publie des vidéos : une vidéo MP4/MOV est requise (une image \
                 seule n'est pas un post YouTube — videos/insert, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        if videos > 1 {
            refus.push(format!("UNE vidéo par videos.insert, reçu {videos}"));
        }
        if images > 1 {
            refus.push(format!(
                "une seule image accompagnant la vidéo (la miniature, thumbnails.set), \
                 reçu {images}"
            ));
        }
        if sondage.is_some() {
            refus.push(
                "youtube ne sert pas de sondage par la Data API (aucun champ poll dans la \
                 ressource videos, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        if made_with_ai {
            refus.push(
                "youtube ne sert pas made_with_ai (aucun champ dans la ressource videos, \
                 relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        match options.privacy {
            None => {}
            Some(p) => match privacy_youtube(p) {
                Some(_) => {}
                None => refus.push(format!(
                    "youtube ne sert pas `{}` : privacyStatus ∈ {{private, public, \
                     unlisted}} (docs/videos, relevé le 2026-09-02)",
                    p.nom()
                )),
            },
        }
        if options.publish_at.is_some() {
            infos.push(
                "publish_at : status.publishAt force privacyStatus=private (« réglable \
                 seulement si privacyStatus=private ; une date passée publie \
                 immédiatement » — docs/videos, relevé le 2026-09-02) — la vidéo restera \
                 privée jusqu'à la date"
                    .to_owned(),
            );
        }
        infos.push(CITATION_BUCKET_INSERT.to_owned());
        infos.push(CITATION_AVANT_AUDIT.to_owned());
        infos.push(format!(
            "privacyStatus = {} (défaut sans `privacy` : private — la seule visibilité \
             d'un projet non audité de toute façon)",
            match (options.publish_at.is_some(), options.privacy) {
                (true, _) => "private",
                (false, Some(p)) => privacy_youtube(p).unwrap_or(PRIVACY_DEFAUT),
                (false, None) => PRIVACY_DEFAUT,
            }
        ));

        let media: Vec<ApercuMedia> = medias.iter().map(apercu_media).collect();
        let limites_ok = refus.is_empty() && media.iter().all(|m| m.limits_ok);
        let mut verdicts = refus;
        verdicts.append(&mut infos);
        // La miniature ajoute ses 50 unités du pool général ; videos.insert
        // vit dans son bucket dédié (le verdict le dit), pas dans le pool.
        let cout_quota = if limites_ok && images == 1 {
            Some(QUOTA_MINIATURE)
        } else {
            None
        };
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai, options),
            platform_limits_ok: limites_ok,
            // « L'API est GRATUITE — le quota est la seule monnaie »
            // (2026-09-02) : None, jamais 0,0.
            cost_estimate_usd: None,
            media,
            verdicts,
            cout_quota,
        }
    }

    async fn publier(
        &self,
        jeton: &Secret,
        _handle: &str,
        texte: &str,
        medias: &[MediaPret],
        _sondage: Option<&Sondage>,
        _made_with_ai: bool,
        options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        // C7 : l'aperçu passe avant — un contournement prend un refus local.
        let Some(video) = medias.iter().find(|m| m.type_detecte == TypeMedia::Mp4) else {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        };
        let Some(titre) = video.title.as_deref() else {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        };
        let privacy = match options.privacy {
            None => PRIVACY_DEFAUT,
            Some(p) => privacy_youtube(p).ok_or(ErreurPlateforme::Refus { statut: 400 })?,
        };
        let metadonnees = corps_metadonnees(titre, texte, privacy, options.publish_at.as_deref());
        let id = self.televerser_video(jeton, video, &metadonnees).await?;
        // La miniature APRÈS la vidéo — best effort refusé : si elle échoue,
        // la vidéo est déjà publiée ; échouer maquillerait un post existant
        // en 'failed' et un rejeu le dupliquerait. La miniature manquante se
        // repose à la main — moindre mal, commenté.
        if let Some(miniature) = medias
            .iter()
            .find(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Png))
        {
            let _ = self.poser_miniature(jeton, &id, miniature).await;
        }
        Ok(Publication {
            url: format!("https://www.youtube.com/watch?v={id}"),
            id_plateforme: id,
        })
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_VIDEOS)
                .query(&[("part", "statistics"), ("id", id_plateforme)])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        metriques_depuis(statut, &corps).map(Some)
    }
}

// ---------------------------------------------------------------------------
// La messagerie — YouTube sert commentaires, likes, recherche et lectures ;
// les DM, bookmarks et reposts n'existent pas. Sondes du 2026-09-02.
// ---------------------------------------------------------------------------

const CITATION_PAS_DE_DM: &str = "aucune ressource de DM dans la YouTube Data API v3 (index des ressources, relevé \
     le 2026-09-02)";

const CITATION_PAS_DE_BOOKMARK: &str = "la playlist Watch Later n'est plus accessible par l'API (retrait WL, revision \
     history, relevé le 2026-09-02) et aucune notion de favori générique n'existe";

const CITATION_PAS_DE_REPOST: &str =
    "pas de repost YouTube — aucune ressource correspondante (relevé le 2026-09-02)";

fn ne_sert_pas(citation: &'static str, deblocage: &'static str) -> ErreurMessagerie {
    ErreurMessagerie::NeSertPas {
        citation,
        deblocage,
    }
}

#[async_trait]
impl PlateformeMessagerie for Youtube {
    fn nom(&self) -> &'static str {
        "youtube"
    }

    async fn dm_reply(
        &self,
        _jeton: &Secret,
        _dm_conversation_id: &str,
        _texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_DM, "rien"))
    }

    async fn dm_open(
        &self,
        _jeton: &Secret,
        _participant_id: &str,
        _texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_DM, "rien"))
    }

    async fn inbox(&self, _jeton: &Secret, _user_id: &str) -> Result<Inbox, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_DM, "rien"))
    }

    /// Commentaire de premier niveau sur une vidéo : commentThreads.insert
    /// (50 unités) + channels.list mine (1 unité) pour le channelId exigé.
    async fn post_reply(
        &self,
        jeton: &Secret,
        _handle: &str,
        in_reply_to_post_id: &str,
        texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        // `handle` est le TITRE de chaîne (identite_depuis) — pas le
        // channelId que commentThreads.insert exige : on le lit (1 unité).
        let channel_id = self.mon_channel_id(jeton).await?;
        let (statut, corps) = envoyer(
            http()
                .post(POINT_COMMENT_THREADS)
                .query(&[("part", "snippet")])
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_comment_thread(
                    &channel_id,
                    in_reply_to_post_id,
                    texte,
                )),
        )
        .await?;
        let id = id_depuis(statut, &corps)?;
        Ok(ReponsePubliee {
            url: format!("https://www.youtube.com/watch?v={in_reply_to_post_id}&lc={id}"),
            id_plateforme: id,
            cout_usd: 0.0,
            // 50 (commentThreads.insert) + 1 (channels.list mine) — le coût
            // RÉEL de l'appel, pas le tarif nominal seul.
            cout_quota: Some(QUOTA_COMMENTAIRE + QUOTA_LECTURE),
        })
    }

    /// Sans parent : même geste que post_reply. Avec parent : comments.insert.
    async fn post_comment(
        &self,
        jeton: &Secret,
        handle: &str,
        post_id: &str,
        parent_comment: Option<&str>,
        texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        let Some(parent) = parent_comment else {
            return self.post_reply(jeton, handle, post_id, texte).await;
        };
        let (statut, corps) = envoyer(
            http()
                .post(POINT_COMMENTS)
                .query(&[("part", "snippet")])
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_comment_reply(parent, texte)),
        )
        .await?;
        let id = id_depuis(statut, &corps)?;
        Ok(ReponsePubliee {
            url: format!("https://www.youtube.com/watch?v={post_id}&lc={id}"),
            id_plateforme: id,
            cout_usd: 0.0,
            cout_quota: Some(QUOTA_COMMENTAIRE),
        })
    }

    /// videos.rate rating=like — 50 unités (videos/rate, relevé le
    /// 2026-09-02). Répond 204 No Content.
    async fn post_like(
        &self,
        jeton: &Secret,
        _user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        self.noter(jeton, post_id, "like").await
    }

    /// rating=none retire la note — le « unlike » documenté.
    async fn post_unlike(
        &self,
        jeton: &Secret,
        _user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        self.noter(jeton, post_id, "none").await
    }

    async fn post_bookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_BOOKMARK, "rien"))
    }

    async fn post_unbookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_BOOKMARK, "rien"))
    }

    async fn post_repost(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_REPOST, "rien"))
    }

    async fn post_quote(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_REPOST, "rien"))
    }

    /// search.list — « depuis le 2026-06-01 dans son PROPRE bucket : 100
    /// appels/jour, 1 point par appel ; chaque page = un appel »
    /// (determine_quota_cost, relevé le 2026-09-02).
    async fn search_posts(
        &self,
        jeton: &Secret,
        query: &str,
        max_results: u8,
    ) -> Result<PostsLus, ErreurMessagerie> {
        let borne = max_results.clamp(1, 50); // maxResults 0-50 documenté.
        let (statut, corps) = envoyer(
            http()
                .get(POINT_SEARCH)
                .query(&[
                    ("part", "snippet"),
                    ("q", query),
                    ("type", "video"),
                    ("maxResults", &borne.to_string()),
                ])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let posts = recherche_depuis(statut, &corps)?;
        Ok(PostsLus {
            posts,
            cout_usd: 0.0,
            cout_quota: Some(1),
        })
    }

    /// videos.list part=snippet — 1 unité ; texte = title + description.
    async fn read_post(
        &self,
        jeton: &Secret,
        post_id: &str,
    ) -> Result<ElementLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_VIDEOS)
                .query(&[("part", "snippet"), ("id", post_id)])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        Ok(element_depuis(statut, &corps)?)
    }

    /// channels.list forHandle — 1 unité, données publiques, tout channel.
    async fn read_profile(
        &self,
        jeton: &Secret,
        username: &str,
    ) -> Result<ProfilLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_CHANNELS)
                .query(&[("part", "snippet"), ("forHandle", username)])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        Ok(profil_depuis(statut, &corps)?)
    }

    /// channels.list contentDetails → playlistItems.list de la playlist
    /// uploads — 1+1 unités, données publiques, tout channel.
    async fn read_timeline(
        &self,
        jeton: &Secret,
        user_id: &str,
    ) -> Result<PostsLus, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_CHANNELS)
                .query(&[("part", "contentDetails"), ("id", user_id)])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let uploads = playlist_uploads_depuis(statut, &corps)?;
        let (statut, corps) = envoyer(
            http()
                .get(POINT_PLAYLIST_ITEMS)
                .query(&[
                    ("part", "snippet"),
                    ("playlistId", &uploads),
                    ("maxResults", "20"),
                ])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let posts = playlist_items_depuis(statut, &corps)?;
        Ok(PostsLus {
            posts,
            cout_usd: 0.0,
            cout_quota: Some(2),
        })
    }
}

impl Youtube {
    async fn noter(
        &self,
        jeton: &Secret,
        post_id: &str,
        rating: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _corps) = envoyer(
            http()
                .post(POINT_VIDEOS_RATE)
                .query(&[("id", post_id), ("rating", rating)])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: 0.0,
            cout_quota: Some(QUOTA_RATE),
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

    fn video_titree() -> MediaPret {
        let mut m = media(b"\x00\x00\x00\x20ftypisom-octets", TypeMedia::Mp4);
        m.title = Some("Mon titre".to_owned());
        m
    }

    /// Les métadonnées de l'étape (1) — et publishAt FORCE private, comme la
    /// doc l'exige (« réglable seulement si privacyStatus=private »).
    #[test]
    fn les_metadonnees_suivent_la_doc_et_publish_at_force_private() {
        assert_eq!(
            corps_metadonnees("Titre", "Description", "unlisted", None),
            json!({
                "snippet": { "title": "Titre", "description": "Description" },
                "status": { "privacyStatus": "unlisted" }
            })
        );
        assert_eq!(
            corps_metadonnees("T", "D", "public", Some("2026-10-01T09:00:00Z")),
            json!({
                "snippet": { "title": "T", "description": "D" },
                "status": {
                    "privacyStatus": "private",
                    "publishAt": "2026-10-01T09:00:00Z"
                }
            })
        );
    }

    #[test]
    fn les_corps_de_commentaires_sont_ceux_des_docs() {
        assert_eq!(
            corps_comment_thread("UCchannel", "videoABC", "Bien vu !"),
            json!({
                "snippet": {
                    "channelId": "UCchannel",
                    "videoId": "videoABC",
                    "topLevelComment": { "snippet": { "textOriginal": "Bien vu !" } }
                }
            })
        );
        assert_eq!(
            corps_comment_reply("threadXYZ", "Merci"),
            json!({ "snippet": { "parentId": "threadXYZ", "textOriginal": "Merci" } })
        );
    }

    /// Le mapping privacy figé : private/public/unlisted servis,
    /// friends/followers refusés.
    #[test]
    fn le_mapping_privacy_est_celui_de_la_doc() {
        assert_eq!(privacy_youtube(Privacy::Public), Some("public"));
        assert_eq!(privacy_youtube(Privacy::Private), Some("private"));
        assert_eq!(privacy_youtube(Privacy::Unlisted), Some("unlisted"));
        assert_eq!(privacy_youtube(Privacy::Friends), None);
        assert_eq!(privacy_youtube(Privacy::Followers), None);
    }

    /// Les chunks sont des multiples de 256 KB (16 MiB), le dernier plus
    /// court — l'exigence du protocole resumable.
    #[test]
    fn les_chunks_sont_multiples_de_256_kb() {
        assert_eq!(TAILLE_CHUNK % (256 * 1024), 0);
        let octets = vec![7u8; TAILLE_CHUNK + 3];
        let morceaux: Vec<_> = chunks(&octets).collect();
        assert_eq!(morceaux.len(), 2);
        assert_eq!(morceaux[0].0, 0);
        assert_eq!(morceaux[0].1.len(), TAILLE_CHUNK);
        assert_eq!(morceaux[1].0, TAILLE_CHUNK);
        assert_eq!(morceaux[1].1.len(), 3);
    }

    #[test]
    fn les_lecteurs_lisent_les_formes_documentees() {
        assert_eq!(
            id_depuis(200, br#"{"id":"dQw4w9WgXcQ","kind":"youtube#video"}"#).unwrap(),
            "dQw4w9WgXcQ"
        );
        // Les compteurs statistics sont des CHAÎNES chez YouTube.
        let m = metriques_depuis(
            200,
            br#"{"items":[{"id":"v1","statistics":{"viewCount":"907","likeCount":"5","commentCount":"2"}}]}"#,
        )
        .unwrap();
        assert_eq!(m.likes, 5);
        assert_eq!(m.replies, 2);
        // viewCount N'EST PAS une impression (compté dès que la vidéo
        // démarre, changement du 2026-08-24) : None, pas 907.
        assert_eq!(m.impressions, None);
        assert_eq!(m.reposts, 0);

        let posts = recherche_depuis(
            200,
            br#"{"items":[{"id":{"videoId":"abc"},"snippet":{"title":"Un","channelId":"UC1","description":"D"}}]}"#,
        )
        .unwrap();
        assert_eq!(posts[0].id, "abc");
        assert_eq!(posts[0].texte, "Un\nD");
        assert!(posts[0].third_party);

        let element = element_depuis(
            200,
            br#"{"items":[{"id":"v9","snippet":{"title":"Titre","description":"Desc","channelId":"UC2"}}]}"#,
        )
        .unwrap();
        assert_eq!(element.id, "v9");
        assert_eq!(element.auteur_id.as_deref(), Some("UC2"));

        let profil = profil_depuis(
            200,
            br#"{"items":[{"id":"UCdev","snippet":{"title":"Ma chaine"}}]}"#,
        )
        .unwrap();
        assert_eq!(profil.id, "UCdev");
        assert_eq!(profil.nom, "Ma chaine");

        assert_eq!(
            playlist_uploads_depuis(
                200,
                br#"{"items":[{"contentDetails":{"relatedPlaylists":{"uploads":"UUdev"}}}]}"#
            )
            .unwrap(),
            "UUdev"
        );
        let liste = playlist_items_depuis(
            200,
            br#"{"items":[{"snippet":{"title":"T","resourceId":{"videoId":"v3"},"channelId":"UC3"}}]}"#,
        )
        .unwrap();
        assert_eq!(liste[0].id, "v3");
    }

    #[test]
    fn aucun_lecteur_ne_laisse_fuir_un_jeton() {
        let hostile = br#"{"error":{"message":"Bearer JETON-SECRET refuse"}}"#;
        for statut in [400, 401, 403, 404, 429, 500] {
            let rendus = [
                format!("{:?}", id_depuis(statut, hostile)),
                format!("{:?}", metriques_depuis(statut, hostile)),
                format!("{:?}", recherche_depuis(statut, hostile)),
                format!("{:?}", element_depuis(statut, hostile)),
                format!("{:?}", profil_depuis(statut, hostile)),
                format!("{:?}", playlist_uploads_depuis(statut, hostile)),
                format!("{:?}", playlist_items_depuis(statut, hostile)),
            ];
            for rendu in rendus {
                assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
            }
        }
    }

    #[test]
    fn l_apercu_refuse_ce_que_youtube_refuse_mots_exacts() {
        // Vidéo sans titre : « poser media[].title ».
        let sans_titre = [media(b"\x00\x00\x00\x20ftypisom", TypeMedia::Mp4)];
        let apercu = Youtube.apercu("desc", &sans_titre, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("poser media[].title")),
            "{:?}",
            apercu.media[0].verdicts
        );

        // Image seule : YouTube ne publie pas d'images.
        let image = [media(b"\xFF\xD8\xFF\xE0", TypeMedia::Jpeg)];
        let apercu = Youtube.apercu("t", &image, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("une vidéo MP4/MOV est requise")),
            "{:?}",
            apercu.verdicts
        );

        // Miniature de 3 MB : « 2 MB max », chiffre cité.
        let grosse = media(&vec![0u8; 3_000_000], TypeMedia::Png);
        let apercu = Youtube.apercu("t", &[video_titree(), grosse], None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu
                .media
                .iter()
                .flat_map(|m| &m.verdicts)
                .any(|v| v.contains("2 MB") && v.contains("3000000")),
            "{:?}",
            apercu.media
        );

        // GIF/WEBP/PDF, made_with_ai, sondage, friends : refusés cités.
        for mauvais in [TypeMedia::Gif, TypeMedia::Webp, TypeMedia::Pdf] {
            assert!(
                !Youtube
                    .apercu(
                        "t",
                        &[video_titree(), media(b"x", mauvais)],
                        None,
                        false,
                        &SANS
                    )
                    .platform_limits_ok
            );
        }
        assert!(
            !Youtube
                .apercu("t", &[video_titree()], None, true, &SANS)
                .platform_limits_ok
        );
        let amis = OptionsPost {
            privacy: Some(Privacy::Friends),
            publish_at: None,
        };
        assert!(
            !Youtube
                .apercu("t", &[video_titree()], None, false, &amis)
                .platform_limits_ok
        );
    }

    /// Une vidéo titrée passe ; les états avant-audit, le bucket dédié et le
    /// verdict Shorts sont RENDUS ; la miniature coûte ses 50 unités.
    #[test]
    fn une_video_titree_passe_et_le_quota_est_la_monnaie() {
        let apercu = Youtube.apercu("description", &[video_titree()], None, false, &SANS);
        assert!(apercu.platform_limits_ok, "{:?}", apercu.verdicts);
        assert_eq!(apercu.cost_estimate_usd, None); // l'API est gratuite.
        assert_eq!(apercu.cout_quota, None); // pas de miniature : bucket dédié seul.
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("bucket dédié")),
            "{:?}",
            apercu.verdicts
        );
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("restricted to private viewing mode")),
            "{:?}",
            apercu.verdicts
        );
        assert!(
            apercu
                .media
                .iter()
                .flat_map(|m| &m.verdicts)
                .any(|v| v.contains("Short")),
            "{:?}",
            apercu.media
        );

        // Avec miniature : cout_quota = 50 (thumbnails.set, pool général).
        let miniature = media(b"\xFF\xD8\xFF\xE0", TypeMedia::Jpeg);
        let apercu = Youtube.apercu("d", &[video_titree(), miniature], None, false, &SANS);
        assert!(apercu.platform_limits_ok, "{:?}", apercu.verdicts);
        assert_eq!(apercu.cout_quota, Some(50));

        // publish_at : informatif (private forcé), limits_ok reste vrai.
        let differe = OptionsPost {
            privacy: Some(Privacy::Public),
            publish_at: Some("2026-10-01T09:00:00Z".to_owned()),
        };
        let apercu = Youtube.apercu("d", &[video_titree()], None, false, &differe);
        assert!(apercu.platform_limits_ok, "{:?}", apercu.verdicts);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("force privacyStatus=private")),
            "{:?}",
            apercu.verdicts
        );
    }

    /// Chaque refus messagerie est un fait cité et daté — jamais un stub.
    #[tokio::test]
    async fn les_refus_messagerie_portent_leurs_citations() {
        let jeton = Secret::new("jeton");
        let cas: Vec<(&str, ErreurMessagerie)> = vec![
            (
                "dm_reply",
                Youtube.dm_reply(&jeton, "1", "t").await.unwrap_err(),
            ),
            (
                "dm_open",
                Youtube.dm_open(&jeton, "1", "t").await.unwrap_err(),
            ),
            ("inbox", Youtube.inbox(&jeton, "1").await.unwrap_err()),
            (
                "bookmark",
                Youtube.post_bookmark(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "unbookmark",
                Youtube.post_unbookmark(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "repost",
                Youtube.post_repost(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "quote",
                Youtube.post_quote(&jeton, "h", "2", "t").await.unwrap_err(),
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
            POINT_UPLOAD_VIDEOS,
            POINT_VIDEOS,
            POINT_VIDEOS_RATE,
            POINT_THUMBNAILS,
            POINT_COMMENT_THREADS,
            POINT_COMMENTS,
            POINT_SEARCH,
            POINT_CHANNELS,
            POINT_PLAYLIST_ITEMS,
        ] {
            assert!(point.starts_with("https://www.googleapis.com/"), "{point}");
        }
    }
}
