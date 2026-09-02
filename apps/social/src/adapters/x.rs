//! X : texte, photos, GIF, vidéo, sondage, made_with_ai.
//!
//! Tout ce qui suit vient de la doc officielle (docs.x.com, spec OpenAPI
//! v2.168), relevée le 2026-09-02 par la sonde X :
//!
//! * Création : `POST https://api.x.com/2/tweets`, corps `{"text": "..."}`,
//!   plus `media.media_ids` (1 à 4), `poll {options, duration_minutes}` et
//!   `made_with_ai`, contexte utilisateur OAuth 2.0, scopes `tweet.write` et
//!   `media.write` pour les médias —
//!   <https://docs.x.com/x-api/posts/creation-of-a-post>. Réponse :
//!   `{"data": {"id": "...", "text": "..."}}`. `quote_tweet_id` est
//!   Enterprise seulement (warning de la même page) : pas exposé.
//! * Upload simple (images) : `POST https://api.x.com/2/media/upload`,
//!   multipart (`media` + `media_category=tweet_image`), réponse `data.id`.
//! * Upload chunké (GIF, vidéo) : la note officielle dit que
//!   `command=INIT/APPEND/FINALIZE` en POST est l'ANCIEN protocole — seul
//!   `command=STATUS` survit, en GET. Le protocole courant :
//!   `POST /2/media/upload/initialize` (JSON `media_type`, `total_bytes`,
//!   `media_category`) → `POST /2/media/upload/{id}/append` multipart
//!   (`segment_index` 0.., `media`) → `POST /2/media/upload/{id}/finalize` →
//!   si `processing_info` : `GET /2/media/upload?command=STATUS&media_id={id}`
//!   en respectant `check_after_secs` jusqu'à `succeeded`/`failed`.
//! * Texte alternatif : `POST https://api.x.com/2/media/metadata`,
//!   `{id, metadata: {alt_text: {text}}}`.
//! * Limites médias : image 5 MB (`tweet_image`), GIF animé 15 MB
//!   (`tweet_gif`), 4 photos OU 1 GIF OU 1 vidéo — jamais de mélange ;
//!   alt_text 1000 caractères ; la vidéo suit le statut Premium du compte
//!   (20 min/8 GB standard, 125 min/16 GB Premium). Aucun type document dans
//!   l'enum `media_type`.
//! * Sondage : 2 à 4 options de 1 à 25 caractères, durée 5 à 10080 minutes ;
//!   pas de champ question (le texte du post EST la question).
//! * Lecture : `GET https://api.x.com/2/tweets/{id}` avec
//!   `post.fields=public_metrics` (le paramètre s'appelle bien `post.fields`
//!   dans l'OpenAPI servi par la doc), scope `tweet.read` ou `users.read` —
//!   <https://docs.x.com/x-api/posts/get-post-by-id>. `public_metrics` porte
//!   `impression_count`, `like_count`, `repost_count`, `reply_count`,
//!   `quote_count`, `bookmark_count`.
//! * Tarif : « Post: Create $0.015 per request », « Post: Create (with URL)
//!   $0.200 per request », « Media Metadata $0.005 per request » —
//!   <https://docs.x.com/x-api/getting-started/pricing.md>. L'upload média
//!   lui-même n'a AUCUNE ligne de facturation relevée — une absence, pas une
//!   garantie.
//! * Longueur : 280 pondérés ; toute URL compte 23 ; émojis et CJC comptent 2 ;
//!   « Latin, punctuation, common symbols » comptent 1 —
//!   <https://docs.x.com/resources/fundamentals/counting-characters>.

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{
    ActionFaite, Apercu, ApercuMedia, ElementLu, ErreurMessagerie, ErreurPlateforme, Inbox,
    MediaPret, MessagePrive, Metriques, OptionsPost, Plateforme, PlateformeMessagerie, PostsLus,
    ProfilLu, Publication, ReponsePubliee, Sondage, TypeMedia, empreinte_globale, envoyer, http,
    http_upload,
};

/// <https://docs.x.com/x-api/posts/creation-of-a-post>, relevé le 2026-09-02.
pub const POINT_PUBLICATION: &str = "https://api.x.com/2/tweets";
/// <https://docs.x.com/x-api/posts/get-post-by-id>, relevé le 2026-09-02. L'id
/// se concatène, le paramètre `post.fields=public_metrics` s'ajoute en query.
pub const POINT_LECTURE: &str = "https://api.x.com/2/tweets/";
/// Upload simple (images) en POST multipart, et `command=STATUS` en GET —
/// docs.x.com, spec OpenAPI v2.168, relevé le 2026-09-02.
pub const POINT_UPLOAD: &str = "https://api.x.com/2/media/upload";
/// Première étape du protocole chunké courant — docs.x.com, relevé le 2026-09-02.
pub const POINT_INITIALIZE: &str = "https://api.x.com/2/media/upload/initialize";
/// Texte alternatif d'un média — docs.x.com, relevé le 2026-09-02.
pub const POINT_METADATA: &str = "https://api.x.com/2/media/metadata";

/// « Post: Create $0.015 per request » / « Post: Create (with URL) $0.200 » /
/// « Media Metadata $0.005 per request » —
/// <https://docs.x.com/x-api/getting-started/pricing.md>, relevé le 2026-09-02.
pub const COUT_PAR_POST_USD: f64 = 0.015;
pub const COUT_PAR_POST_AVEC_URL_USD: f64 = 0.200;
pub const COUT_PAR_ALT_TEXT_USD: f64 = 0.005;

/// 280 pondérés — <https://docs.x.com/resources/fundamentals/counting-characters>.
pub const LIMITE_PONDEREE: usize = 280;

/// « 5 MB » image, « 15 MB » GIF — docs.x.com, relevé le 2026-09-02. La doc
/// ne définit pas l'unité ; on prend l'interprétation stricte (décimale) :
/// comme `poids()`, elle ne peut que refuser un passable près de la borne,
/// jamais laisser partir un refusable.
pub const OCTETS_MAX_TWEET_IMAGE: u64 = 5_000_000;
pub const OCTETS_MAX_TWEET_GIF: u64 = 15_000_000;
/// « 4 photos OU 1 GIF OU 1 vidéo » — docs.x.com, relevé le 2026-09-02.
pub const PHOTOS_MAX: usize = 4;
/// alt_text : 1000 caractères max — docs.x.com, relevé le 2026-09-02.
pub const ALT_TEXT_MAX: usize = 1000;
/// Segments d'append de 4 MiB : sous le conseil « ≤ 5 MB » et loin du max
/// serveur 8 MB — docs.x.com, relevé le 2026-09-02.
pub const TAILLE_SEGMENT: usize = 4 * 1024 * 1024;
/// Sondage : 2–4 options de 1–25 caractères, 5–10080 minutes — docs.x.com,
/// relevé le 2026-09-02.
pub const SONDAGE_OPTION_CHARS_MAX: usize = 25;
pub const SONDAGE_DUREE_MIN: u32 = 5;
pub const SONDAGE_DUREE_MAX: u32 = 10080;

/// ponytail: budget global du polling STATUS (5 min) — au-delà, Injoignable
/// et l'appelant rejouera avec sa clé d'idempotence ; si un tenant pousse des
/// vidéos que X transcode plus lentement, remonter ce budget.
pub const BUDGET_TRAITEMENT_SECS: u64 = 300;

/// La catégorie d'upload par type détecté. `None` = X ne sert pas ce type
/// (aucun media_type document dans l'enum de la spec, relevé le 2026-09-02).
///
/// ponytail: tout GIF part en `tweet_gif` — distinguer un GIF statique (qui
/// irait en `tweet_image`) demande un compteur de frames ; le jour où un
/// tenant poste des GIF statiques refusés, écrire le parseur de frames.
pub fn categorie(t: TypeMedia) -> Option<&'static str> {
    match t {
        TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Webp => Some("tweet_image"),
        TypeMedia::Gif => Some("tweet_gif"),
        TypeMedia::Mp4 => Some("tweet_video"),
        TypeMedia::Pdf => None,
    }
}

/// Le poids d'un texte selon les règles citées en tête de module.
///
/// ponytail: approximation de twitter-text — poids 1 jusqu'à U+10FF (latin,
/// grec, cyrillique, ponctuation ASCII), 2 au-delà (émojis, CJC), URL = 23.
/// Elle SURcompte la ponctuation typographique (U+2013, U+2019… que X compte
/// pour 1), donc elle ne peut que refuser un texte passable près de la borne,
/// jamais laisser passer un refusable. Le jour où un tenant bute dessus :
/// reprendre les plages exactes de twitter-text v3.
pub fn poids(texte: &str) -> usize {
    let blancs = texte.chars().filter(|c| c.is_whitespace()).count();
    texte
        .split(char::is_whitespace)
        .map(|morceau| {
            if contient_url(morceau) {
                23
            } else {
                morceau
                    .chars()
                    .map(|c| if (c as u32) <= 0x10FF { 1 } else { 2 })
                    .sum()
            }
        })
        .sum::<usize>()
        + blancs
}

/// Ce qui fait basculer le tarif de 0,015 à 0,200 USD.
fn contient_url(morceau: &str) -> bool {
    morceau.starts_with("https://") || morceau.starts_with("http://")
}

/// Le coût d'UN `POST /2/tweets` selon son texte — « Post: Create $0.015 »,
/// « Post: Create (with URL) $0.200 » (pricing, relevé le 2026-09-02). Servi
/// par l'aperçu de l'éditeur ET par `post_reply` côté messagerie : le facteur
/// treize se calcule à un seul endroit.
pub fn cout_creation_post(texte: &str) -> f64 {
    if texte.split(char::is_whitespace).any(contient_url) {
        COUT_PAR_POST_AVEC_URL_USD
    } else {
        COUT_PAR_POST_USD
    }
}

/// Le corps exact de `POST /2/tweets` — un post texte reste `{"text": ...}`
/// à l'octet près (la fixture d'origine le fige) ; médias, sondage et
/// made_with_ai s'ajoutent seulement quand ils existent, parce qu'un champ
/// absent et un champ nul ne sont pas la même requête.
pub fn corps_de_publication(
    texte: &str,
    media_ids: &[String],
    sondage: Option<&Sondage>,
    made_with_ai: bool,
) -> serde_json::Value {
    let mut corps = json!({ "text": texte });
    if !media_ids.is_empty() {
        corps["media"] = json!({ "media_ids": media_ids });
    }
    if let Some(s) = sondage {
        // Pas de champ question : chez X le texte du post EST la question.
        corps["poll"] = json!({
            "options": s.options,
            "duration_minutes": s.duration_minutes
        });
    }
    if made_with_ai {
        corps["made_with_ai"] = json!(true);
    }
    corps
}

/// `POST /2/media/upload/initialize` — JSON `media_type`, `total_bytes`,
/// `media_category` (docs.x.com, relevé le 2026-09-02).
pub fn corps_initialize(media: &MediaPret) -> serde_json::Value {
    json!({
        "media_type": media.type_detecte.mime(),
        "total_bytes": media.octets.len(),
        "media_category": categorie(media.type_detecte)
            .expect("l'aperçu refuse les types sans catégorie avant publier (C7)"),
    })
}

/// `{id, metadata: {alt_text: {text}}}` — `POST /2/media/metadata`
/// (docs.x.com, relevé le 2026-09-02).
pub fn corps_metadata(media_id: &str, alt_text: &str) -> serde_json::Value {
    json!({ "id": media_id, "metadata": { "alt_text": { "text": alt_text } } })
}

/// Un corps multipart/form-data écrit à la main : reqwest est compilé sans la
/// feature `multipart` dans ce workspace, et vingt lignes déterministes se
/// comparent à une fixture — un builder opaque, non.
fn multipart(frontiere: &str, champs: &[(&str, &str)], octets: &[u8]) -> Vec<u8> {
    let mut corps = Vec::with_capacity(octets.len() + 512);
    for (nom, valeur) in champs {
        corps.extend_from_slice(
            format!(
                "--{frontiere}\r\nContent-Disposition: form-data; name=\"{nom}\"\r\n\r\n{valeur}\r\n"
            )
            .as_bytes(),
        );
    }
    corps.extend_from_slice(
        format!(
            "--{frontiere}\r\nContent-Disposition: form-data; name=\"media\"; filename=\"media\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    corps.extend_from_slice(octets);
    corps.extend_from_slice(format!("\r\n--{frontiere}--\r\n").as_bytes());
    corps
}

/// L'upload simple d'une image : `media` + `media_category=tweet_image`.
pub fn multipart_image(frontiere: &str, octets: &[u8]) -> Vec<u8> {
    multipart(frontiere, &[("media_category", "tweet_image")], octets)
}

/// Un segment d'append : `segment_index` 0.. + le chunk.
pub fn multipart_append(frontiere: &str, index: usize, chunk: &[u8]) -> Vec<u8> {
    multipart(frontiere, &[("segment_index", &index.to_string())], chunk)
}

pub fn type_contenu_multipart(frontiere: &str) -> String {
    format!("multipart/form-data; boundary={frontiere}")
}

/// 128 bits d'aléa : la frontière ne peut pas apparaître dans les octets par
/// accident exploitable.
fn frontiere_aleatoire() -> String {
    format!(
        "agentos{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}

/// Découpe pour l'append chunké — chaque segment sauf le dernier fait
/// exactement [`TAILLE_SEGMENT`].
pub fn segments(octets: &[u8]) -> impl Iterator<Item = &[u8]> {
    octets.chunks(TAILLE_SEGMENT)
}

/// Lit `data.id` des réponses d'upload et d'initialize. Le corps n'entre
/// jamais dans l'erreur (il peut écho la requête, Authorization comprise).
pub fn media_id_depuis(statut: u16, corps: &[u8]) -> Result<String, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    document
        .pointer("/data/id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(ErreurPlateforme::Illisible)
}

/// Où en est le transcodage après finalize / STATUS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traitement {
    Pret,
    EnCours { attendre_secs: u64 },
    Echec,
}

/// Lit `data.processing_info` (finalize et STATUS ont la même forme). Pas de
/// `processing_info` = le média est prêt tout de suite (cas des images et des
/// petits GIF). Le 403 post-finalize (vidéo au-dessus du droit Premium du
/// compte) sort ici en `Refus { statut: 403 }` via `depuis_statut` — sans un
/// octet du corps.
pub fn traitement_depuis(statut: u16, corps: &[u8]) -> Result<Traitement, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let Some(info) = document.pointer("/data/processing_info") else {
        return Ok(Traitement::Pret);
    };
    match info.get("state").and_then(|v| v.as_str()) {
        Some("succeeded") => Ok(Traitement::Pret),
        Some("pending") | Some("in_progress") => Ok(Traitement::EnCours {
            attendre_secs: info
                .get("check_after_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(1),
        }),
        // « failed » : X a mangé les octets puis dit non. Injoignable et pas
        // Refus : le corps (et sa raison) n'entrent pas dans l'erreur, et un
        // rejeu avec la même clé d'idempotence reste sensé.
        Some("failed") => Ok(Traitement::Echec),
        _ => Err(ErreurPlateforme::Illisible),
    }
}

/// Lit la réponse de création. Un refus devient une [`ErreurPlateforme`]
/// nommée et jamais une [`Publication`] ; le corps n'entre pas dans l'erreur
/// (il écho la requête, et l'erreur finit dans des logs).
pub fn publication_depuis(
    statut: u16,
    corps: &[u8],
    handle: &str,
) -> Result<Publication, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let id = document
        .pointer("/data/id")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    Ok(Publication {
        id_plateforme: id.to_owned(),
        // Le format public `x.com/<handle>/status/<id>` : construit depuis le
        // handle du compte connecté, pas depuis la réponse (elle n'en porte pas).
        url: format!("https://x.com/{handle}/status/{id}"),
    })
}

/// Lit `GET /2/tweets/{id}?post.fields=public_metrics`.
pub fn metriques_depuis(statut: u16, corps: &[u8]) -> Result<Metriques, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let publiques = document
        .pointer("/data/public_metrics")
        .ok_or(ErreurPlateforme::Illisible)?;
    let compte = |nom: &str| publiques.get(nom).and_then(|v| v.as_u64());
    Ok(Metriques {
        impressions: compte("impression_count"),
        likes: compte("like_count").unwrap_or(0),
        reposts: compte("repost_count").unwrap_or(0),
        replies: compte("reply_count").unwrap_or(0),
    })
}

/// Le verdict d'UN média, mots exacts et chiffres cités.
fn apercu_media(m: &MediaPret) -> ApercuMedia {
    let taille = m.octets.len() as u64;
    let mut verdicts = Vec::new();
    let mut ok = true;
    match m.type_detecte {
        TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Webp => {
            if taille > OCTETS_MAX_TWEET_IMAGE {
                ok = false;
                verdicts.push(format!("5 MB max pour tweet_image, reçu {taille} octets"));
            }
        }
        TypeMedia::Gif => {
            if taille > OCTETS_MAX_TWEET_GIF {
                ok = false;
                verdicts.push(format!("15 MB max pour tweet_gif, reçu {taille} octets"));
            }
            // ponytail: ≤1280x1080 et ≤350 frames ne se vérifient pas aux
            // octets sans parseur GIF — la plateforme tranchera.
        }
        TypeMedia::Mp4 => {
            // Informative, pas un refus : le plafond service est 512 MiB (C5,
            // medias.rs) ; la limite réelle suit le compte, X tranche au
            // finalize (403 → Refus{403}).
            verdicts.push(
                "la limite vidéo réelle suit le statut Premium du compte qui poste \
                 (20 min/8 GB standard, 125 min/16 GB Premium) — X tranche au finalize"
                    .to_owned(),
            );
        }
        TypeMedia::Pdf => {
            ok = false;
            verdicts.push(
                "X ne sert aucun type document : pas de media_type document dans l'enum \
                 (spec OpenAPI v2.168, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
    }
    if let Some(alt) = &m.alt_text {
        let n = alt.chars().count();
        if n > ALT_TEXT_MAX {
            ok = false;
            verdicts.push(format!("alt_text 1000 caractères max, reçu {n}"));
        }
    }
    if m.title.is_some() {
        ok = false;
        verdicts.push("X ne sert pas de title de média".to_owned());
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

/// L'adaptateur lui-même : l'assemblage des fonctions pures ci-dessus et d'un
/// client HTTP, rien d'autre — c'est ce qui rend le reste testable hors ligne.
pub struct X;

impl X {
    /// Une image : un seul POST multipart sur `/2/media/upload`.
    async fn televerser_image(
        &self,
        jeton: &Secret,
        m: &MediaPret,
    ) -> Result<String, ErreurPlateforme> {
        let frontiere = frontiere_aleatoire();
        let reponse = http_upload()
            .post(POINT_UPLOAD)
            .bearer_auth(jeton.expose_for_transport())
            .header("Content-Type", type_contenu_multipart(&frontiere))
            .body(multipart_image(&frontiere, &m.octets))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        media_id_depuis(statut, &corps)
    }

    /// GIF et vidéo : initialize → append (segments de 4 MiB) → finalize →
    /// STATUS tant que `processing_info` dit d'attendre.
    async fn televerser_chunke(
        &self,
        jeton: &Secret,
        m: &MediaPret,
    ) -> Result<String, ErreurPlateforme> {
        let reponse = http()
            .post(POINT_INITIALIZE)
            .bearer_auth(jeton.expose_for_transport())
            .json(&corps_initialize(m))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let media_id = media_id_depuis(statut, &corps)?;

        for (index, segment) in segments(&m.octets).enumerate() {
            let frontiere = frontiere_aleatoire();
            let reponse = http_upload()
                .post(format!("{POINT_UPLOAD}/{media_id}/append"))
                .bearer_auth(jeton.expose_for_transport())
                .header("Content-Type", type_contenu_multipart(&frontiere))
                .body(multipart_append(&frontiere, index, segment))
                .send()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            if let Some(erreur) = ErreurPlateforme::depuis_statut(reponse.status().as_u16()) {
                return Err(erreur);
            }
        }

        let reponse = http()
            .post(format!("{POINT_UPLOAD}/{media_id}/finalize"))
            .bearer_auth(jeton.expose_for_transport())
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let mut etat = traitement_depuis(statut, &corps)?;

        // Le polling respecte `check_after_secs` de la doc, sous un budget
        // total : un transcodage qui n'aboutit pas n'est pas un post.
        let mut budget = BUDGET_TRAITEMENT_SECS;
        loop {
            match etat {
                Traitement::Pret => return Ok(media_id),
                Traitement::Echec => return Err(ErreurPlateforme::Injoignable),
                Traitement::EnCours { attendre_secs } => {
                    if attendre_secs > budget {
                        // Budget épuisé : mieux vaut un échec net qu'un outil
                        // qui pend sans fin sous un agent.
                        return Err(ErreurPlateforme::Injoignable);
                    }
                    budget -= attendre_secs;
                    tokio::time::sleep(std::time::Duration::from_secs(attendre_secs)).await;
                    let reponse = http()
                        .get(POINT_UPLOAD)
                        .query(&[("command", "STATUS"), ("media_id", &media_id)])
                        .bearer_auth(jeton.expose_for_transport())
                        .send()
                        .await
                        .map_err(|_| ErreurPlateforme::Injoignable)?;
                    let statut = reponse.status().as_u16();
                    let corps = reponse
                        .bytes()
                        .await
                        .map_err(|_| ErreurPlateforme::Injoignable)?;
                    etat = traitement_depuis(statut, &corps)?;
                }
            }
        }
    }

    /// `POST /2/media/metadata` — 0,005 USD, compté dans l'aperçu.
    async fn poser_alt_text(
        &self,
        jeton: &Secret,
        media_id: &str,
        alt_text: &str,
    ) -> Result<(), ErreurPlateforme> {
        let reponse = http()
            .post(POINT_METADATA)
            .bearer_auth(jeton.expose_for_transport())
            .json(&corps_metadata(media_id, alt_text))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        match ErreurPlateforme::depuis_statut(reponse.status().as_u16()) {
            None => Ok(()),
            Some(erreur) => Err(erreur),
        }
    }
}

#[async_trait]
impl Plateforme for X {
    fn nom(&self) -> &'static str {
        "x"
    }

    fn apercu(
        &self,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Apercu {
        // made_with_ai : X le sert (champ de POST /2/tweets) — rien à refuser.
        let _ = made_with_ai;
        let mut verdicts = Vec::new();

        // Table v3 : X ne sert ni visibilité ni planification à la création —
        // aucun champ correspondant dans POST /2/tweets (creation-of-a-post,
        // relevé le 2026-09-02). Un refus cité, jamais une ignorance muette.
        if options.privacy.is_some() {
            verdicts.push(
                "x ne sert pas `privacy` : aucun champ de visibilité dans POST /2/tweets \
                 (creation-of-a-post, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        if options.publish_at.is_some() {
            verdicts.push(
                "x ne sert pas `publish_at` : aucune planification dans POST /2/tweets \
                 (creation-of-a-post, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }

        let photos = medias
            .iter()
            .filter(|m| categorie(m.type_detecte) == Some("tweet_image"))
            .count();
        let gifs = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Gif)
            .count();
        let videos = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Mp4)
            .count();
        if photos > PHOTOS_MAX {
            verdicts.push(format!("4 photos max, reçu {photos}"));
        }
        if gifs > 1 {
            verdicts.push(format!("1 GIF max, reçu {gifs}"));
        }
        if videos > 1 {
            verdicts.push(format!("1 vidéo max, reçu {videos}"));
        }
        if [photos > 0, gifs > 0, videos > 0]
            .iter()
            .filter(|&&b| b)
            .count()
            > 1
        {
            verdicts.push("pas de mélange : 4 photos OU 1 GIF OU 1 vidéo".to_owned());
        }

        if let Some(s) = sondage {
            if !medias.is_empty() {
                // La doc n'établit pas la combinaison sondage+média : refus
                // nommé plutôt qu'invention.
                verdicts.push(
                    "sondage et média ensemble : combinaison non documentée chez X — refusée"
                        .to_owned(),
                );
            }
            if s.question.is_some() {
                verdicts.push(
                    "X ne sert pas de question séparée : le texte du post EST la question"
                        .to_owned(),
                );
            }
            if !(2..=4).contains(&s.options.len()) {
                verdicts.push(format!(
                    "2 à 4 options de sondage, reçu {}",
                    s.options.len()
                ));
            }
            for option in &s.options {
                let n = option.chars().count();
                if !(1..=SONDAGE_OPTION_CHARS_MAX).contains(&n) {
                    verdicts.push(format!(
                        "options de sondage de 1 à 25 caractères, « {option} » en fait {n}"
                    ));
                }
            }
            if !(SONDAGE_DUREE_MIN..=SONDAGE_DUREE_MAX).contains(&s.duration_minutes) {
                verdicts.push(format!(
                    "durée de sondage de 5 à 10080 minutes, reçu {}",
                    s.duration_minutes
                ));
            }
        }

        let media: Vec<ApercuMedia> = medias.iter().map(apercu_media).collect();
        let alt_texts = medias.iter().filter(|m| m.alt_text.is_some()).count();
        let base = cout_creation_post(texte);
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai, options),
            platform_limits_ok: !texte.trim().is_empty()
                && poids(texte) <= LIMITE_PONDEREE
                && verdicts.is_empty()
                && media.iter().all(|m| m.limits_ok),
            // « Media Metadata $0.005 per request » : un POST par alt_text.
            // L'upload média lui-même n'a aucune ligne de facturation relevée.
            cost_estimate_usd: Some(base + COUT_PAR_ALT_TEXT_USD * alt_texts as f64),
            media,
            verdicts,
            // X compte en dollars, pas en unités de quota.
            cout_quota: None,
        }
    }

    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        _options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        // `options` : refusé par l'aperçu (C7 le passe avant publier) — un
        // privacy/publish_at posé ne peut pas arriver ici.
        let mut media_ids = Vec::with_capacity(medias.len());
        for m in medias {
            let media_id = match m.type_detecte {
                TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Webp => {
                    self.televerser_image(jeton, m).await?
                }
                TypeMedia::Gif | TypeMedia::Mp4 => self.televerser_chunke(jeton, m).await?,
                // Jamais atteint : C7 passe l'aperçu (qui refuse le PDF)
                // avant publier. Si un appelant contourne, refus local plutôt
                // qu'un octet de PDF vers X — le statut 400 est le nôtre.
                TypeMedia::Pdf => return Err(ErreurPlateforme::Refus { statut: 400 }),
            };
            if let Some(alt) = &m.alt_text {
                self.poser_alt_text(jeton, &media_id, alt).await?;
            }
            media_ids.push(media_id);
        }
        let reponse = http()
            .post(POINT_PUBLICATION)
            .bearer_auth(jeton.expose_for_transport())
            .json(&corps_de_publication(
                texte,
                &media_ids,
                sondage,
                made_with_ai,
            ))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        publication_depuis(statut, &corps, handle)
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        let reponse = http()
            .get(format!("{POINT_LECTURE}{id_plateforme}"))
            .query(&[("post.fields", "public_metrics")])
            .bearer_auth(jeton.expose_for_transport())
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        metriques_depuis(statut, &corps).map(Some)
    }
}

// ---------------------------------------------------------------------------
// La messagerie — endpoints, tarifs et citations recopiés du plan figé sur les
// sondes du 2026-09-02. Rien d'inventé : chaque constante porte sa source.
// ---------------------------------------------------------------------------

/// DM reçus : `GET /2/dm_events`, scopes dm.read + users.read + tweet.read ;
/// 15 req/15 min/user ; rétention 30 jours —
/// docs.x.com/x-api/direct-messages/lookup/introduction, relevé le 2026-09-02.
pub const POINT_DM_EVENTS: &str = "https://api.x.com/2/dm_events";
/// « Available to all developers », fenêtre 7 jours, query 1-4096 caractères,
/// max_results 10-100 — docs.x.com, relevé le 2026-09-02.
pub const POINT_RECHERCHE: &str = "https://api.x.com/2/tweets/search/recent";
/// Racine des chemins `/2/users/{id}/…` (mentions, likes, bookmarks,
/// retweets, tweets) — docs.x.com, relevés le 2026-09-02.
pub const POINT_USERS: &str = "https://api.x.com/2/users/";

/// Tarifs pay-per-use — docs.x.com/x-api/getting-started/pricing.md, relevé le
/// 2026-09-02 (« subject to change », les rates courants vivent dans la
/// Console) :
/// « DM Interaction: Create » — dm_reply comme dm_open.
pub const COUT_DM_CREATE_USD: f64 = 0.015;
/// Lecture DM : 0,010 USD PAR ÉVÉNEMENT RETOURNÉ.
pub const COUT_DM_EVENEMENT_USD: f64 = 0.010;
/// Mentions : 0,005 USD/post lu — le tarif Owned Read 0,001 exige que {id}
/// soit le propriétaire de l'app, ce que nos tenants ne sont pas.
pub const COUT_MENTION_USD: f64 = 0.005;
/// « User Interaction: Create » — like 0,015, retweet 0,015.
pub const COUT_INTERACTION_CREATE_USD: f64 = 0.015;
/// « Interaction: Delete » — unlike 0,010, retweet delete 0,010. Le plan ne
/// relève AUCUNE ligne propre au delete de bookmark : on rend ce chiffre-ci,
/// la ligne delete relevée, plutôt qu'un zéro inventé.
pub const COUT_INTERACTION_DELETE_USD: f64 = 0.010;
/// Bookmark : 0,005 USD — le write le moins cher ; OAuth2 PKCE uniquement
/// (notre flux X est déjà PKCE).
pub const COUT_BOOKMARK_USD: f64 = 0.005;
/// Lecture de posts (recherche PAR RÉSULTAT, timeline, read_post) : 0,005
/// USD/post — une recherche à 100 résultats coûte jusqu'à 0,50 USD, d'où le
/// coût réel constaté dans chaque retour. Plafond global : 3 000 000 lectures
/// de posts/cycle.
pub const COUT_PAR_POST_LU_USD: f64 = 0.005;
/// « User: Read » : 0,010 USD/user.
pub const COUT_PAR_USER_LU_USD: f64 = 0.010;

/// « Quote-posting (using the quote_tweet_id parameter) requires an
/// Enterprise plan. It is not available on self-serve (pay-per-use) tiers. »
/// — docs.x.com/x-api/posts/create-post, relevé le 2026-09-02.
pub const CITATION_QUOTE_ENTERPRISE: &str = "« Quote-posting (using the quote_tweet_id parameter) requires an Enterprise plan. \
     It is not available on self-serve (pay-per-use) tiers. » \
     — docs.x.com/x-api/posts/create-post, relevé le 2026-09-02";

/// Refuse tout identifiant qui ne peut pas être un id X : des chiffres, plus
/// `-` pour un id de conversation (forme `{id}-{id}` documentée). Un id
/// hostile ne devient jamais un morceau de chemin — ni `../`, ni `with/…` qui
/// transformerait une réponse (dm_reply) en ouverture (dm_open). Le statut
/// 400 est le nôtre : le refus part d'ici, aucun octet ne part vers X.
fn id_x(id: &str, avec_tiret: bool) -> Result<&str, ErreurPlateforme> {
    if !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_digit() || (avec_tiret && c == '-'))
    {
        Ok(id)
    } else {
        Err(ErreurPlateforme::Refus { statut: 400 })
    }
}

/// Même garde pour un username X : alphanumériques et `_`, rien d'autre.
fn username_x(username: &str) -> Result<&str, ErreurPlateforme> {
    if !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(username)
    } else {
        Err(ErreurPlateforme::Refus { statut: 400 })
    }
}

/// Conversation EXISTANTE : `POST /2/dm_conversations/{dm_conversation_id}/messages`
/// (docs.x.com/x-api/direct-messages/manage/integrate, relevé le 2026-09-02 ;
/// dm.write, qui exige dm.read + tweet.read + users.read ; app-only interdit :
/// « All Direct Messages are private » ; 15/15 min + 1440/24 h par user).
pub fn url_dm_reply(dm_conversation_id: &str) -> String {
    format!("https://api.x.com/2/dm_conversations/{dm_conversation_id}/messages")
}

/// NOUVELLE conversation : `POST /2/dm_conversations/with/{participant_id}/messages`
/// — « Creates a new conversation if one doesn't exist » (même page, relevé le
/// 2026-09-02). Le chemin `/with/` est CE qui sépare initier de répondre :
/// c'est l'API elle-même qui découpe les deux risques.
pub fn url_dm_open(participant_id: &str) -> String {
    format!("https://api.x.com/2/dm_conversations/with/{participant_id}/messages")
}

/// `GET /2/users/{id}/mentions` — 300/15 min/user (relevé le 2026-09-02).
pub fn url_mentions(user_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/mentions")
}

/// `POST /2/users/{id}/likes` — like.write ; 50/15 min + 1000/24 h (relevé le
/// 2026-09-02).
pub fn url_likes(user_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/likes")
}

/// `DELETE /2/users/{id}/likes/{tweet_id}` (relevé le 2026-09-02).
pub fn url_unlike(user_id: &str, tweet_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/likes/{tweet_id}")
}

/// `POST /2/users/{id}/bookmarks` — bookmark.write, OAuth2 PKCE uniquement ;
/// 50/15 min (relevé le 2026-09-02).
pub fn url_bookmarks(user_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/bookmarks")
}

/// `DELETE /2/users/{id}/bookmarks/{tweet_id}` (relevé le 2026-09-02).
pub fn url_unbookmark(user_id: &str, tweet_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/bookmarks/{tweet_id}")
}

/// `POST /2/users/{id}/retweets` — tweet.write ; 50/15 min (relevé le
/// 2026-09-02).
pub fn url_retweets(user_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/retweets")
}

/// `GET /2/users/{id}/tweets` — 900/15 min/user (relevé le 2026-09-02).
pub fn url_timeline(user_id: &str) -> String {
    format!("{POINT_USERS}{user_id}/tweets")
}

/// `GET /2/users/by/username/{username}` (relevé le 2026-09-02).
pub fn url_profil(username: &str) -> String {
    format!("{POINT_USERS}by/username/{username}")
}

/// Le corps d'un DM : `{"text": ...}` — les deux endpoints DM (reply et open)
/// portent la même forme (integrate, relevé le 2026-09-02).
pub fn corps_dm(texte: &str) -> serde_json::Value {
    json!({ "text": texte })
}

/// Une réponse publique : `POST /2/tweets` avec
/// `reply.in_reply_to_tweet_id` (creation-of-a-post, relevé le 2026-09-02).
pub fn corps_reponse_publique(texte: &str, in_reply_to_tweet_id: &str) -> serde_json::Value {
    json!({ "text": texte, "reply": { "in_reply_to_tweet_id": in_reply_to_tweet_id } })
}

/// Le corps des actions like/bookmark/retweet : `{"tweet_id": ...}` (relevé le
/// 2026-09-02).
pub fn corps_action(tweet_id: &str) -> serde_json::Value {
    json!({ "tweet_id": tweet_id })
}

/// Lit `{"data": {"dm_conversation_id", "dm_event_id"}}` — la réponse
/// documentée des deux endpoints DM. Le corps n'entre jamais dans l'erreur.
pub fn message_prive_depuis(statut: u16, corps: &[u8]) -> Result<MessagePrive, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let lire = |champ: &str| {
        document
            .pointer(&format!("/data/{champ}"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    };
    Ok(MessagePrive {
        dm_conversation_id: lire("dm_conversation_id")?,
        dm_event_id: lire("dm_event_id")?,
        cout_usd: COUT_DM_CREATE_USD,
    })
}

/// Lit un tableau `data` d'éléments (DM events : auteur sous `sender_id` ;
/// posts : sous `author_id`). Un `data` absent est une liste vide — c'est la
/// forme documentée d'un résultat sans rien (meta.result_count: 0), pas une
/// réponse illisible. Tout texte rendu est du contenu de tiers : marqué.
pub fn elements_depuis(
    statut: u16,
    corps: &[u8],
    champ_auteur: &str,
) -> Result<Vec<ElementLu>, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let Some(data) = document.get("data") else {
        return Ok(Vec::new());
    };
    data.as_array()
        .ok_or(ErreurPlateforme::Illisible)?
        .iter()
        .map(|e| {
            Ok(ElementLu {
                id: e
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or(ErreurPlateforme::Illisible)?
                    .to_owned(),
                auteur_id: e
                    .get(champ_auteur)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                // Un événement DM sans texte existe (pièce jointe seule) :
                // texte vide, pas Illisible.
                texte: e
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                third_party: true,
            })
        })
        .collect()
}

/// Lit UN post : `{"data": {"id", "text", "author_id"?}}`.
pub fn element_depuis(statut: u16, corps: &[u8]) -> Result<ElementLu, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let data = document.get("data").ok_or(ErreurPlateforme::Illisible)?;
    Ok(ElementLu {
        id: data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(ErreurPlateforme::Illisible)?
            .to_owned(),
        auteur_id: data
            .get("author_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        texte: data
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        third_party: true,
    })
}

/// Lit `{"data": {"id", "name", "username"}}` — get-user-by-username, relevé
/// le 2026-09-02.
pub fn profil_depuis(statut: u16, corps: &[u8]) -> Result<ProfilLu, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let lire = |champ: &str| {
        document
            .pointer(&format!("/data/{champ}"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    };
    Ok(ProfilLu {
        id: lire("id")?,
        username: lire("username")?,
        nom: lire("name")?,
        third_party: true,
    })
}

#[async_trait]
impl PlateformeMessagerie for X {
    fn nom(&self) -> &'static str {
        "x"
    }

    async fn dm_reply(
        &self,
        jeton: &Secret,
        dm_conversation_id: &str,
        texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .post(url_dm_reply(id_x(dm_conversation_id, true)?))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_dm(texte)),
        )
        .await?;
        Ok(message_prive_depuis(statut, &corps)?)
    }

    async fn dm_open(
        &self,
        jeton: &Secret,
        participant_id: &str,
        texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        // La gate des suppressions appartient au cœur, AVANT cet appel : ici
        // il n'y a plus que le réseau.
        let (statut, corps) = envoyer(
            http()
                .post(url_dm_open(id_x(participant_id, false)?))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_dm(texte)),
        )
        .await?;
        Ok(message_prive_depuis(statut, &corps)?)
    }

    async fn inbox(&self, jeton: &Secret, user_id: &str) -> Result<Inbox, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(POINT_DM_EVENTS)
                .query(&[("dm_event.fields", "sender_id,text")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let dm_events = elements_depuis(statut, &corps, "sender_id")?;
        let (statut, corps) = envoyer(
            http()
                .get(url_mentions(id_x(user_id, false)?))
                .query(&[("tweet.fields", "author_id")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let mentions = elements_depuis(statut, &corps, "author_id")?;
        // Le coût réel constaté : facturation PAR élément retourné.
        let cout_usd = dm_events.len() as f64 * COUT_DM_EVENEMENT_USD
            + mentions.len() as f64 * COUT_MENTION_USD;
        Ok(Inbox {
            dm_events,
            mentions,
            cout_usd,
        })
    }

    async fn post_reply(
        &self,
        jeton: &Secret,
        handle: &str,
        in_reply_to_post_id: &str,
        texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .post(POINT_PUBLICATION)
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_reponse_publique(texte, in_reply_to_post_id)),
        )
        .await?;
        let publication = publication_depuis(statut, &corps, handle)?;
        Ok(ReponsePubliee {
            id_plateforme: publication.id_plateforme,
            url: publication.url,
            // 0,015 — ou 0,200 dès que le texte porte une URL : le même
            // calcul que l'aperçu de l'éditeur, à un seul endroit.
            cout_usd: cout_creation_post(texte),
            cout_quota: None,
        })
    }

    async fn post_comment(
        &self,
        jeton: &Secret,
        handle: &str,
        post_id: &str,
        parent_comment: Option<&str>,
        texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        // Chez X commenter EST répondre : un seul geste, un seul endpoint —
        // répondre à un commentaire, c'est répondre à ce commentaire-post.
        self.post_reply(jeton, handle, parent_comment.unwrap_or(post_id), texte)
            .await
    }

    async fn post_like(
        &self,
        jeton: &Secret,
        user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _) = envoyer(
            http()
                .post(url_likes(id_x(user_id, false)?))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_action(post_id)),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: COUT_INTERACTION_CREATE_USD,
            cout_quota: None,
        })
    }

    async fn post_unlike(
        &self,
        jeton: &Secret,
        user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _) = envoyer(
            http()
                .delete(url_unlike(id_x(user_id, false)?, id_x(post_id, false)?))
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: COUT_INTERACTION_DELETE_USD,
            cout_quota: None,
        })
    }

    async fn post_bookmark(
        &self,
        jeton: &Secret,
        user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _) = envoyer(
            http()
                .post(url_bookmarks(id_x(user_id, false)?))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_action(post_id)),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: COUT_BOOKMARK_USD,
            cout_quota: None,
        })
    }

    async fn post_unbookmark(
        &self,
        jeton: &Secret,
        user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _) = envoyer(
            http()
                .delete(url_unbookmark(id_x(user_id, false)?, id_x(post_id, false)?))
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: COUT_INTERACTION_DELETE_USD,
            cout_quota: None,
        })
    }

    async fn post_repost(
        &self,
        jeton: &Secret,
        user_id: &str,
        post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        let (statut, _) = envoyer(
            http()
                .post(url_retweets(id_x(user_id, false)?))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_action(post_id)),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        Ok(ActionFaite {
            cout_usd: COUT_INTERACTION_CREATE_USD,
            cout_quota: None,
        })
    }

    async fn post_quote(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        // Refusé au palier pay-per-use — pas un stub : le fait cité, et ce
        // qui débloquerait.
        Err(ErreurMessagerie::NeSertPas {
            citation: CITATION_QUOTE_ENTERPRISE,
            deblocage: "un plan Enterprise chez X",
        })
    }

    async fn search_posts(
        &self,
        jeton: &Secret,
        query: &str,
        max_results: u8,
    ) -> Result<PostsLus, ErreurMessagerie> {
        // max_results documenté : 10-100 (relevé le 2026-09-02) — on borne
        // plutôt que de laisser la plateforme répondre 400 pour un 5.
        let borne = max_results.clamp(10, 100);
        let (statut, corps) = envoyer(
            http()
                .get(POINT_RECHERCHE)
                .query(&[
                    ("query", query),
                    ("max_results", &borne.to_string()),
                    ("tweet.fields", "author_id"),
                ])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let posts = elements_depuis(statut, &corps, "author_id")?;
        // Facturé PAR RÉSULTAT (0,005, dédup 24 h UTC) : le coût réel est
        // résultats × tarif — le plan exige que l'outil le rende.
        let cout_usd = posts.len() as f64 * COUT_PAR_POST_LU_USD;
        Ok(PostsLus {
            posts,
            cout_usd,
            cout_quota: None,
        })
    }

    async fn read_post(
        &self,
        jeton: &Secret,
        post_id: &str,
    ) -> Result<ElementLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(format!("{POINT_LECTURE}{}", id_x(post_id, false)?))
                .query(&[("tweet.fields", "author_id")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        Ok(element_depuis(statut, &corps)?)
    }

    async fn read_profile(
        &self,
        jeton: &Secret,
        username: &str,
    ) -> Result<ProfilLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(url_profil(username_x(username)?))
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        Ok(profil_depuis(statut, &corps)?)
    }

    async fn read_timeline(
        &self,
        jeton: &Secret,
        user_id: &str,
    ) -> Result<PostsLus, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(url_timeline(id_x(user_id, false)?))
                .query(&[("tweet.fields", "author_id")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        let posts = elements_depuis(statut, &corps, "author_id")?;
        let cout_usd = posts.len() as f64 * COUT_PAR_POST_LU_USD;
        Ok(PostsLus {
            posts,
            cout_usd,
            cout_quota: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::empreinte;
    use crate::adapters::test_medias::media;

    /// Des options vides — le cas de tous les posts d'avant la table v3.
    const SANS: OptionsPost = OptionsPost {
        privacy: None,
        publish_at: None,
    };

    fn avec_alt(mut m: MediaPret, alt: &str) -> MediaPret {
        m.alt_text = Some(alt.to_owned());
        m
    }

    /// La forme documentée d'un post texte : `{"text": "Your post content
    /// here"}` — docs.x.com/x-api/posts/creation-of-a-post, relevé le
    /// 2026-09-02. AUCUN champ média/sondage quand il n'y en a pas.
    #[test]
    fn le_corps_est_celui_de_la_doc() {
        assert_eq!(
            corps_de_publication("Hello world", &[], None, false),
            json!({ "text": "Hello world" })
        );
    }

    /// `media.media_ids`, `poll {options, duration_minutes}`, `made_with_ai` —
    /// creation-of-a-post, relevé le 2026-09-02.
    #[test]
    fn le_corps_porte_medias_sondage_et_made_with_ai_comme_la_doc() {
        assert_eq!(
            corps_de_publication(
                "Hello world",
                &["1146654567674912769".to_owned()],
                None,
                true
            ),
            json!({
                "text": "Hello world",
                "media": { "media_ids": ["1146654567674912769"] },
                "made_with_ai": true
            })
        );
        let sondage = Sondage {
            question: None,
            options: vec!["oui".to_owned(), "non".to_owned()],
            duration_minutes: 1440,
        };
        assert_eq!(
            corps_de_publication("Une question ?", &[], Some(&sondage), false),
            json!({
                "text": "Une question ?",
                "poll": { "options": ["oui", "non"], "duration_minutes": 1440 }
            })
        );
    }

    /// initialize : `media_type`, `total_bytes`, `media_category` — docs.x.com,
    /// relevé le 2026-09-02.
    #[test]
    fn le_corps_initialize_est_celui_de_la_doc() {
        assert_eq!(
            corps_initialize(&media(&[0u8; 10], TypeMedia::Mp4)),
            json!({
                "media_type": "video/mp4",
                "total_bytes": 10,
                "media_category": "tweet_video"
            })
        );
        assert_eq!(
            corps_initialize(&media(&[0u8; 3], TypeMedia::Gif))["media_category"],
            json!("tweet_gif")
        );
    }

    /// metadata : `{id, metadata: {alt_text: {text}}}` — docs.x.com, relevé le
    /// 2026-09-02.
    #[test]
    fn le_corps_metadata_est_celui_de_la_doc() {
        assert_eq!(
            corps_metadata("1146654567674912769", "Un chat orange"),
            json!({
                "id": "1146654567674912769",
                "metadata": { "alt_text": { "text": "Un chat orange" } }
            })
        );
    }

    /// Le multipart écrit à la main, octet par octet — s'il bouge, c'est la
    /// requête vers X qui bouge.
    #[test]
    fn le_multipart_image_se_fige_a_l_octet() {
        let corps = multipart_image("XXX", b"OCTETS");
        let attendu = b"--XXX\r\nContent-Disposition: form-data; name=\"media_category\"\r\n\r\ntweet_image\r\n--XXX\r\nContent-Disposition: form-data; name=\"media\"; filename=\"media\"\r\nContent-Type: application/octet-stream\r\n\r\nOCTETS\r\n--XXX--\r\n";
        assert_eq!(corps, attendu.to_vec());
        assert_eq!(
            type_contenu_multipart("XXX"),
            "multipart/form-data; boundary=XXX"
        );
    }

    /// Le protocole chunké se teste en découpant un buffer connu et en
    /// vérifiant chaque requête construite.
    #[test]
    fn les_segments_font_4_mib_et_les_appends_sont_indexes() {
        let octets = vec![7u8; TAILLE_SEGMENT + 3];
        let morceaux: Vec<&[u8]> = segments(&octets).collect();
        assert_eq!(morceaux.len(), 2);
        assert_eq!(morceaux[0].len(), TAILLE_SEGMENT);
        assert_eq!(morceaux[1], &[7u8; 3]);
        // Chaque append porte son index et son chunk, rien d'autre.
        let corps = multipart_append("XXX", 1, morceaux[1]);
        let texte = String::from_utf8_lossy(&corps);
        assert!(
            texte.contains("name=\"segment_index\"\r\n\r\n1\r\n"),
            "{texte}"
        );
        assert!(!texte.contains("media_category"), "{texte}");
    }

    #[test]
    fn le_traitement_se_lit_comme_la_doc_et_le_403_reste_un_refus_nu() {
        // Pas de processing_info : prêt tout de suite (images, petits GIF).
        assert_eq!(
            traitement_depuis(200, br#"{"data":{"id":"1"}}"#),
            Ok(Traitement::Pret)
        );
        // `check_after_secs` est respecté, pas inventé.
        assert_eq!(
            traitement_depuis(
                200,
                br#"{"data":{"id":"1","processing_info":{"state":"pending","check_after_secs":5}}}"#
            ),
            Ok(Traitement::EnCours { attendre_secs: 5 })
        );
        assert_eq!(
            traitement_depuis(
                200,
                br#"{"data":{"id":"1","processing_info":{"state":"succeeded"}}}"#
            ),
            Ok(Traitement::Pret)
        );
        assert_eq!(
            traitement_depuis(
                200,
                br#"{"data":{"id":"1","processing_info":{"state":"failed"}}}"#
            ),
            Ok(Traitement::Echec)
        );
        // Le 403 post-finalize (vidéo au-dessus du droit du compte) : géré,
        // nommé, sans corps — même si le corps porte un écho hostile.
        let hostile = br#"{"errors":[{"detail":"Bearer JETON-SECRET refuse"}]}"#;
        let erreur = traitement_depuis(403, hostile).expect_err("403 n'est pas un média");
        assert_eq!(erreur, ErreurPlateforme::Refus { statut: 403 });
        assert!(!format!("{erreur} / {erreur:?}").contains("JETON-SECRET"));
    }

    #[test]
    fn un_refus_ne_devient_jamais_une_publication_et_ne_porte_pas_le_jeton() {
        // Un point qui échoue écho volontiers la requête — y compris son
        // Authorization. Si ce corps hostile traversait vers l'erreur, le
        // jeton finirait dans un log.
        let corps_hostile = br#"{"errors":[{"detail":"Bearer JETON-SECRET refuse"}]}"#;
        for statut in [400, 401, 403, 429, 500] {
            let erreur = publication_depuis(statut, corps_hostile, "orizn")
                .expect_err("un non-2xx n'est pas un post");
            let rendu = format!("{erreur} / {erreur:?}");
            assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
            // Même discipline sur le lecteur d'upload.
            let erreur = media_id_depuis(statut, corps_hostile).expect_err("pas un média");
            assert!(!format!("{erreur} / {erreur:?}").contains("JETON-SECRET"));
        }
    }

    #[test]
    fn une_reponse_de_creation_se_lit_comme_la_doc_le_montre() {
        let corps = br#"{"data":{"id":"1234567890","text":"Hello world","edit_history_post_ids":["1234567890"]}}"#;
        let publication = publication_depuis(201, corps, "orizn").expect("201 documenté");
        assert_eq!(publication.id_plateforme, "1234567890");
        assert_eq!(publication.url, "https://x.com/orizn/status/1234567890");
        // Un 2xx au corps difforme est illisible, pas un post à moitié.
        assert_eq!(
            publication_depuis(201, b"{}", "orizn"),
            Err(ErreurPlateforme::Illisible)
        );
    }

    /// Chaque règle de comptage citée a un cas qui échouerait si elle cassait.
    #[test]
    fn le_poids_suit_les_regles_citees() {
        // 280 latins passent, 281 non.
        assert_eq!(poids(&"a".repeat(280)), 280);
        assert!(
            X.apercu(&"a".repeat(280), &[], None, false, &SANS)
                .platform_limits_ok
        );
        assert!(
            !X.apercu(&"a".repeat(281), &[], None, false, &SANS)
                .platform_limits_ok
        );
        // « All URLs count as exactly 23 characters ».
        assert_eq!(poids("https://exemple.example/un/chemin/vraiment/long"), 23);
        // « emojis count as 2 » : 140 passent, 141 débordent.
        assert!(
            X.apercu(&"🦀".repeat(140), &[], None, false, &SANS)
                .platform_limits_ok
        );
        assert!(
            !X.apercu(&"🦀".repeat(141), &[], None, false, &SANS)
                .platform_limits_ok
        );
        // Les blancs comptent aussi.
        assert_eq!(poids("a b"), 3);
        // Un texte vide ne part pas.
        assert!(!X.apercu("   ", &[], None, false, &SANS).platform_limits_ok);
    }

    /// « Post: Create (with URL) $0.200 » contre « Post: Create $0.015 » — le
    /// facteur treize doit être visible dans l'aperçu contresigné. Et chaque
    /// alt_text ajoute son POST metadata à 0,005 USD.
    #[test]
    fn le_cout_distingue_un_post_avec_lien_et_compte_les_alt_texts() {
        assert_eq!(
            X.apercu("bonjour", &[], None, false, &SANS)
                .cost_estimate_usd,
            Some(0.015)
        );
        assert_eq!(
            X.apercu("bonjour https://orizn.example", &[], None, false, &SANS)
                .cost_estimate_usd,
            Some(0.200)
        );
        let medias = vec![
            avec_alt(media(b"a", TypeMedia::Png), "un chat"),
            avec_alt(media(b"b", TypeMedia::Png), "un chien"),
            media(b"c", TypeMedia::Png),
        ];
        assert_eq!(
            X.apercu("bonjour", &medias, None, false, &SANS)
                .cost_estimate_usd,
            Some(0.015 + 2.0 * 0.005)
        );
    }

    #[test]
    fn l_apercu_rend_le_texte_exact_et_son_empreinte() {
        let apercu = X.apercu("Texte à publier", &[], None, false, &SANS);
        assert_eq!(apercu.rendered_text, "Texte à publier");
        assert_eq!(apercu.digest, empreinte("Texte à publier"));
        assert!(apercu.media.is_empty());
    }

    /// Les verdicts médias exigés par le brief : mots exacts, chiffres cités.
    #[test]
    fn les_verdicts_medias_refusent_ce_que_x_refuse() {
        // 5 photos → « 4 max ».
        let cinq: Vec<_> = (0..5).map(|i| media(&[i as u8], TypeMedia::Jpeg)).collect();
        let apercu = X.apercu("t", &cinq, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("4 photos max")),
            "{:?}",
            apercu.verdicts
        );

        // image + vidéo → « pas de mélange ».
        let mixte = vec![media(b"i", TypeMedia::Png), media(b"v", TypeMedia::Mp4)];
        let apercu = X.apercu("t", &mixte, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("pas de mélange")),
            "{:?}",
            apercu.verdicts
        );

        // 6 MB en tweet_image → « 5 MB max », taille citée.
        let lourde = vec![media(&vec![0u8; 6_000_000], TypeMedia::Jpeg)];
        let apercu = X.apercu("t", &lourde, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("5 MB max") && v.contains("6000000")),
            "{:?}",
            apercu.media[0].verdicts
        );
        // Un GIF de 6 MB passe (15 MB max), à 16 MB il tombe.
        assert!(
            X.apercu(
                "t",
                &[media(&vec![0u8; 6_000_000], TypeMedia::Gif)],
                None,
                false,
                &SANS
            )
            .platform_limits_ok
        );
        assert!(
            !X.apercu(
                "t",
                &[media(&vec![0u8; 16_000_000], TypeMedia::Gif)],
                None,
                false,
                &SANS
            )
            .platform_limits_ok
        );

        // alt 1001 → « 1000 max ».
        let alt_long = vec![avec_alt(media(b"i", TypeMedia::Png), &"x".repeat(1001))];
        let apercu = X.apercu("t", &alt_long, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0].verdicts.iter().any(|v| v.contains("1000")),
            "{:?}",
            apercu.media[0].verdicts
        );
        assert!(
            X.apercu(
                "t",
                &[avec_alt(media(b"i", TypeMedia::Png), &"x".repeat(1000))],
                None,
                false,
                &SANS
            )
            .platform_limits_ok
        );

        // title → refusé (X ne le sert pas).
        let mut avec_titre = media(b"i", TypeMedia::Png);
        avec_titre.title = Some("Titre".to_owned());
        assert!(
            !X.apercu("t", &[avec_titre], None, false, &SANS)
                .platform_limits_ok
        );

        // PDF → refusé, « aucun type document dans l'enum media_type ».
        let apercu = X.apercu("t", &[media(b"%PDF-", TypeMedia::Pdf)], None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("document")),
            "{:?}",
            apercu.media[0].verdicts
        );

        // 4 photos propres passent.
        let quatre: Vec<_> = (0..4).map(|i| media(&[i as u8], TypeMedia::Webp)).collect();
        assert!(
            X.apercu("t", &quatre, None, false, &SANS)
                .platform_limits_ok
        );
    }

    #[test]
    fn les_verdicts_sondage_suivent_la_doc() {
        let bon = Sondage {
            question: None,
            options: vec!["oui".to_owned(), "non".to_owned()],
            duration_minutes: 1440,
        };
        assert!(
            X.apercu("La question ?", &[], Some(&bon), false, &SANS)
                .platform_limits_ok
        );

        // Une question séparée : X ne la sert pas.
        let avec_question = Sondage {
            question: Some("Q ?".to_owned()),
            ..bon.clone()
        };
        let apercu = X.apercu("t", &[], Some(&avec_question), false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("EST la question")),
            "{:?}",
            apercu.verdicts
        );

        // Option de 26 caractères : « 1 à 25 ».
        let option_longue = Sondage {
            options: vec!["a".repeat(26), "non".to_owned()],
            ..bon.clone()
        };
        assert!(
            !X.apercu("t", &[], Some(&option_longue), false, &SANS)
                .platform_limits_ok
        );

        // Durées hors 5–10080.
        for duree in [4, 10081] {
            let hors = Sondage {
                duration_minutes: duree,
                ..bon.clone()
            };
            let apercu = X.apercu("t", &[], Some(&hors), false, &SANS);
            assert!(!apercu.platform_limits_ok);
            assert!(
                apercu.verdicts.iter().any(|v| v.contains("10080")),
                "{:?}",
                apercu.verdicts
            );
        }

        // Sondage + média : non documenté, donc refusé.
        let apercu = X.apercu(
            "t",
            &[media(b"i", TypeMedia::Png)],
            Some(&bon),
            false,
            &SANS,
        );
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("sondage et média")),
            "{:?}",
            apercu.verdicts
        );
    }

    #[test]
    fn privacy_et_publish_at_sont_refuses_avec_citation() {
        // Table v3 : X ne les sert pas — le verdict le dit, l'ignorance
        // silencieuse est interdite.
        let avec_privacy = OptionsPost {
            privacy: Some(crate::adapters::Privacy::Private),
            publish_at: None,
        };
        let apercu = X.apercu("t", &[], None, false, &avec_privacy);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("privacy")),
            "{:?}",
            apercu.verdicts
        );
        let avec_date = OptionsPost {
            privacy: None,
            publish_at: Some("2026-10-01T09:00:00Z".to_owned()),
        };
        let apercu = X.apercu("t", &[], None, false, &avec_date);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("publish_at")),
            "{:?}",
            apercu.verdicts
        );
    }

    #[test]
    fn made_with_ai_passe_chez_x_et_entre_dans_l_empreinte() {
        let apercu = X.apercu("t", &[], None, true, &SANS);
        assert!(apercu.platform_limits_ok);
        assert_ne!(apercu.digest, X.apercu("t", &[], None, false, &SANS).digest);
    }

    #[test]
    fn les_points_d_api_sont_en_https() {
        for point in [
            POINT_PUBLICATION,
            POINT_LECTURE,
            POINT_UPLOAD,
            POINT_INITIALIZE,
            POINT_METADATA,
        ] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }
}

#[cfg(test)]
mod tests_messagerie {
    use super::*;

    /// LE test du découpage : les deux chemins d'API sont distincts, et un
    /// dm_conversation_id ne tombe JAMAIS dans le chemin `/with/` — répondre
    /// ne peut pas devenir initier par construction d'URL.
    #[test]
    fn les_deux_chemins_dm_sont_figes_et_disjoints() {
        assert_eq!(
            url_dm_reply("123123123-456456456"),
            "https://api.x.com/2/dm_conversations/123123123-456456456/messages"
        );
        assert_eq!(
            url_dm_open("2244994945"),
            "https://api.x.com/2/dm_conversations/with/2244994945/messages"
        );
        // Quel que soit l'id VALIDE, le chemin reply ne contient jamais /with/.
        for id in ["1", "123-456", "2244994945"] {
            assert!(!url_dm_reply(id).starts_with("https://api.x.com/2/dm_conversations/with/"));
        }
        assert!(url_dm_open("2244994945").contains("/with/"));
    }

    /// Un id qui n'a pas la forme d'un id X (« with », « ../ », vide…) est
    /// refusé AVANT de construire une URL : un conversation_id hostile ne
    /// peut pas fabriquer le chemin `/with/` et transformer une réponse en
    /// ouverture — le refus est local (400 à nous), aucun octet ne part.
    #[tokio::test]
    async fn un_id_hostile_est_refuse_avant_toute_url() {
        let jeton = Secret::new("jeton");
        for hostile in ["with", "../123", "123/messages", "", "with/99"] {
            let erreur = X
                .dm_reply(&jeton, hostile, "texte")
                .await
                .expect_err("un id difforme n'est pas une conversation");
            assert_eq!(
                erreur,
                ErreurMessagerie::Plateforme(ErreurPlateforme::Refus { statut: 400 }),
                "{hostile}"
            );
            let erreur = X
                .dm_open(&jeton, hostile, "texte")
                .await
                .expect_err("un id difforme n'est pas un participant");
            assert_eq!(
                erreur,
                ErreurMessagerie::Plateforme(ErreurPlateforme::Refus { statut: 400 }),
                "{hostile}"
            );
        }
        // Et un id de conversation (tirets permis) n'est pas un participant.
        assert!(X.dm_open(&jeton, "123-456", "t").await.is_err());
    }

    /// `{"text": ...}` — integrate, relevé le 2026-09-02. La même forme pour
    /// les deux endpoints DM.
    #[test]
    fn le_corps_dm_est_celui_de_la_doc() {
        assert_eq!(
            corps_dm("Hello, just you!"),
            json!({ "text": "Hello, just you!" })
        );
    }

    /// `reply.in_reply_to_tweet_id` — creation-of-a-post, relevé le 2026-09-02.
    #[test]
    fn le_corps_de_reponse_publique_est_celui_de_la_doc() {
        assert_eq!(
            corps_reponse_publique("Bien vu !", "1455953449422516226"),
            json!({
                "text": "Bien vu !",
                "reply": { "in_reply_to_tweet_id": "1455953449422516226" }
            })
        );
    }

    /// `{"tweet_id": ...}` pour like/bookmark/retweet — relevé le 2026-09-02.
    #[test]
    fn le_corps_d_action_et_les_urls_d_action_sont_ceux_de_la_doc() {
        assert_eq!(
            corps_action("1455953449422516226"),
            json!({ "tweet_id": "1455953449422516226" })
        );
        assert_eq!(url_likes("42"), "https://api.x.com/2/users/42/likes");
        assert_eq!(
            url_unlike("42", "7"),
            "https://api.x.com/2/users/42/likes/7"
        );
        assert_eq!(
            url_bookmarks("42"),
            "https://api.x.com/2/users/42/bookmarks"
        );
        assert_eq!(
            url_unbookmark("42", "7"),
            "https://api.x.com/2/users/42/bookmarks/7"
        );
        assert_eq!(url_retweets("42"), "https://api.x.com/2/users/42/retweets");
        assert_eq!(url_mentions("42"), "https://api.x.com/2/users/42/mentions");
        assert_eq!(url_timeline("42"), "https://api.x.com/2/users/42/tweets");
        assert_eq!(
            url_profil("XDevelopers"),
            "https://api.x.com/2/users/by/username/XDevelopers"
        );
    }

    /// La réponse documentée des deux endpoints DM porte les deux ids — et le
    /// coût DM (0,015 USD, « DM Interaction: Create ») sort avec.
    #[test]
    fn un_dm_parti_se_lit_comme_la_doc_et_porte_son_cout() {
        let corps = br#"{"data":{"dm_conversation_id":"123123123-456456456","dm_event_id":"1050118621198921728"}}"#;
        let message = message_prive_depuis(201, corps).expect("forme documentée");
        assert_eq!(message.dm_conversation_id, "123123123-456456456");
        assert_eq!(message.dm_event_id, "1050118621198921728");
        assert_eq!(message.cout_usd, COUT_DM_CREATE_USD);
        // Un 2xx difforme est illisible, pas un DM à moitié parti.
        assert!(message_prive_depuis(201, b"{}").is_err());
    }

    /// Aucun corps hostile (écho de la requête, Authorization comprise) ne
    /// traverse vers l'erreur — sur TOUS les lecteurs messagerie.
    #[test]
    fn aucun_lecteur_messagerie_ne_laisse_fuir_un_jeton() {
        let hostile = br#"{"errors":[{"detail":"Bearer JETON-SECRET refuse"}]}"#;
        for statut in [400, 401, 403, 404, 429, 500] {
            let rendus = [
                format!("{:?}", message_prive_depuis(statut, hostile)),
                format!("{:?}", elements_depuis(statut, hostile, "author_id")),
                format!("{:?}", element_depuis(statut, hostile)),
                format!("{:?}", profil_depuis(statut, hostile)),
            ];
            for rendu in rendus {
                assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
            }
        }
    }

    /// La recherche est facturée PAR RÉSULTAT (0,005 USD) : trois posts
    /// rendus = 0,015 USD constaté — et zéro résultat coûte zéro.
    #[test]
    fn le_cout_de_lecture_est_par_resultat_constate() {
        let corps = br#"{"data":[
            {"id":"1","text":"un","author_id":"11"},
            {"id":"2","text":"deux","author_id":"22"},
            {"id":"3","text":"trois"}
        ],"meta":{"result_count":3}}"#;
        let posts = elements_depuis(200, corps, "author_id").expect("forme documentée");
        assert_eq!(posts.len(), 3);
        assert_eq!(posts.len() as f64 * COUT_PAR_POST_LU_USD, 0.015);
        assert_eq!(posts[0].auteur_id.as_deref(), Some("11"));
        assert!(posts[2].auteur_id.is_none());
        // Tout ce qui est lu est marqué contenu de tiers.
        assert!(posts.iter().all(|p| p.third_party));
        // `data` absent = résultat vide documenté (meta.result_count: 0).
        let vide = elements_depuis(200, br#"{"meta":{"result_count":0}}"#, "author_id")
            .expect("un résultat vide n'est pas une panne");
        assert!(vide.is_empty());
    }

    /// Les DM events lisent l'auteur sous `sender_id` (dm_event.fields), et un
    /// événement sans texte (pièce jointe seule) ne casse rien.
    #[test]
    fn les_dm_events_se_lisent_avec_sender_id() {
        let corps = br#"{"data":[{"id":"e1","text":"salut","sender_id":"99"},{"id":"e2","sender_id":"98"}]}"#;
        let events = elements_depuis(200, corps, "sender_id").expect("forme documentée");
        assert_eq!(events[0].auteur_id.as_deref(), Some("99"));
        assert_eq!(events[1].texte, "");
    }

    #[test]
    fn un_profil_se_lit_comme_la_doc() {
        let corps = br#"{"data":{"id":"2244994945","name":"Developers","username":"XDevelopers"}}"#;
        let profil = profil_depuis(200, corps).expect("forme documentée");
        assert_eq!(profil.id, "2244994945");
        assert_eq!(profil.username, "XDevelopers");
        assert_eq!(profil.nom, "Developers");
        assert!(profil.third_party);
    }

    /// Le quote est refusé au palier pay-per-use — un fait cité (Enterprise),
    /// jamais un stub silencieux ni un panic.
    #[tokio::test]
    async fn le_quote_rend_le_refus_cite_sans_reseau() {
        let erreur = X
            .post_quote(&Secret::new("jeton"), "orizn", "1", "je cite")
            .await
            .expect_err("aucune plateforme ne sert le quote à notre palier");
        assert_eq!(erreur.code(), "plateforme_ne_sert_pas");
        let ErreurMessagerie::NeSertPas {
            citation,
            deblocage,
        } = erreur
        else {
            panic!("le refus doit être NeSertPas, reçu {erreur:?}");
        };
        assert!(citation.contains("Enterprise plan"));
        assert!(citation.contains("2026-09-02"));
        assert!(deblocage.contains("Enterprise"));
    }

    /// Le coût d'une réponse publique suit la règle de l'éditeur : 0,015 nu,
    /// 0,200 dès qu'une URL est dans le texte (« Post: Create (with URL) »).
    #[test]
    fn le_cout_d_une_reponse_bascule_avec_une_url() {
        assert_eq!(cout_creation_post("merci !"), 0.015);
        assert_eq!(cout_creation_post("voir https://orizn.example"), 0.200);
    }

    #[test]
    fn les_points_messagerie_sont_en_https() {
        for point in [
            POINT_DM_EVENTS,
            POINT_RECHERCHE,
            &url_dm_reply("1"),
            &url_dm_open("1"),
            &url_likes("1"),
            &url_bookmarks("1"),
            &url_retweets("1"),
            &url_profil("a"),
        ] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }
}
