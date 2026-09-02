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
    Apercu, ApercuMedia, ErreurPlateforme, MediaPret, Metriques, Plateforme, Publication, Sondage,
    TypeMedia, empreinte_globale, http, http_upload,
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
    ) -> Apercu {
        // made_with_ai : X le sert (champ de POST /2/tweets) — rien à refuser.
        let _ = made_with_ai;
        let mut verdicts = Vec::new();

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
        let avec_url = texte.split(char::is_whitespace).any(contient_url);
        let base = if avec_url {
            COUT_PAR_POST_AVEC_URL_USD
        } else {
            COUT_PAR_POST_USD
        };
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai),
            platform_limits_ok: !texte.trim().is_empty()
                && poids(texte) <= LIMITE_PONDEREE
                && verdicts.is_empty()
                && media.iter().all(|m| m.limits_ok),
            // « Media Metadata $0.005 per request » : un POST par alt_text.
            // L'upload média lui-même n'a aucune ligne de facturation relevée.
            cost_estimate_usd: Some(base + COUT_PAR_ALT_TEXT_USD * alt_texts as f64),
            media,
            verdicts,
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
    ) -> Result<Publication, ErreurPlateforme> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::empreinte;
    use crate::adapters::test_medias::media;

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
            X.apercu(&"a".repeat(280), &[], None, false)
                .platform_limits_ok
        );
        assert!(
            !X.apercu(&"a".repeat(281), &[], None, false)
                .platform_limits_ok
        );
        // « All URLs count as exactly 23 characters ».
        assert_eq!(poids("https://exemple.example/un/chemin/vraiment/long"), 23);
        // « emojis count as 2 » : 140 passent, 141 débordent.
        assert!(
            X.apercu(&"🦀".repeat(140), &[], None, false)
                .platform_limits_ok
        );
        assert!(
            !X.apercu(&"🦀".repeat(141), &[], None, false)
                .platform_limits_ok
        );
        // Les blancs comptent aussi.
        assert_eq!(poids("a b"), 3);
        // Un texte vide ne part pas.
        assert!(!X.apercu("   ", &[], None, false).platform_limits_ok);
    }

    /// « Post: Create (with URL) $0.200 » contre « Post: Create $0.015 » — le
    /// facteur treize doit être visible dans l'aperçu contresigné. Et chaque
    /// alt_text ajoute son POST metadata à 0,005 USD.
    #[test]
    fn le_cout_distingue_un_post_avec_lien_et_compte_les_alt_texts() {
        assert_eq!(
            X.apercu("bonjour", &[], None, false).cost_estimate_usd,
            Some(0.015)
        );
        assert_eq!(
            X.apercu("bonjour https://orizn.example", &[], None, false)
                .cost_estimate_usd,
            Some(0.200)
        );
        let medias = vec![
            avec_alt(media(b"a", TypeMedia::Png), "un chat"),
            avec_alt(media(b"b", TypeMedia::Png), "un chien"),
            media(b"c", TypeMedia::Png),
        ];
        assert_eq!(
            X.apercu("bonjour", &medias, None, false).cost_estimate_usd,
            Some(0.015 + 2.0 * 0.005)
        );
    }

    #[test]
    fn l_apercu_rend_le_texte_exact_et_son_empreinte() {
        let apercu = X.apercu("Texte à publier", &[], None, false);
        assert_eq!(apercu.rendered_text, "Texte à publier");
        assert_eq!(apercu.digest, empreinte("Texte à publier"));
        assert!(apercu.media.is_empty());
    }

    /// Les verdicts médias exigés par le brief : mots exacts, chiffres cités.
    #[test]
    fn les_verdicts_medias_refusent_ce_que_x_refuse() {
        // 5 photos → « 4 max ».
        let cinq: Vec<_> = (0..5).map(|i| media(&[i as u8], TypeMedia::Jpeg)).collect();
        let apercu = X.apercu("t", &cinq, None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("4 photos max")),
            "{:?}",
            apercu.verdicts
        );

        // image + vidéo → « pas de mélange ».
        let mixte = vec![media(b"i", TypeMedia::Png), media(b"v", TypeMedia::Mp4)];
        let apercu = X.apercu("t", &mixte, None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("pas de mélange")),
            "{:?}",
            apercu.verdicts
        );

        // 6 MB en tweet_image → « 5 MB max », taille citée.
        let lourde = vec![media(&vec![0u8; 6_000_000], TypeMedia::Jpeg)];
        let apercu = X.apercu("t", &lourde, None, false);
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
                false
            )
            .platform_limits_ok
        );
        assert!(
            !X.apercu(
                "t",
                &[media(&vec![0u8; 16_000_000], TypeMedia::Gif)],
                None,
                false
            )
            .platform_limits_ok
        );

        // alt 1001 → « 1000 max ».
        let alt_long = vec![avec_alt(media(b"i", TypeMedia::Png), &"x".repeat(1001))];
        let apercu = X.apercu("t", &alt_long, None, false);
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
                false
            )
            .platform_limits_ok
        );

        // title → refusé (X ne le sert pas).
        let mut avec_titre = media(b"i", TypeMedia::Png);
        avec_titre.title = Some("Titre".to_owned());
        assert!(!X.apercu("t", &[avec_titre], None, false).platform_limits_ok);

        // PDF → refusé, « aucun type document dans l'enum media_type ».
        let apercu = X.apercu("t", &[media(b"%PDF-", TypeMedia::Pdf)], None, false);
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
        assert!(X.apercu("t", &quatre, None, false).platform_limits_ok);
    }

    #[test]
    fn les_verdicts_sondage_suivent_la_doc() {
        let bon = Sondage {
            question: None,
            options: vec!["oui".to_owned(), "non".to_owned()],
            duration_minutes: 1440,
        };
        assert!(
            X.apercu("La question ?", &[], Some(&bon), false)
                .platform_limits_ok
        );

        // Une question séparée : X ne la sert pas.
        let avec_question = Sondage {
            question: Some("Q ?".to_owned()),
            ..bon.clone()
        };
        let apercu = X.apercu("t", &[], Some(&avec_question), false);
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
            !X.apercu("t", &[], Some(&option_longue), false)
                .platform_limits_ok
        );

        // Durées hors 5–10080.
        for duree in [4, 10081] {
            let hors = Sondage {
                duration_minutes: duree,
                ..bon.clone()
            };
            let apercu = X.apercu("t", &[], Some(&hors), false);
            assert!(!apercu.platform_limits_ok);
            assert!(
                apercu.verdicts.iter().any(|v| v.contains("10080")),
                "{:?}",
                apercu.verdicts
            );
        }

        // Sondage + média : non documenté, donc refusé.
        let apercu = X.apercu("t", &[media(b"i", TypeMedia::Png)], Some(&bon), false);
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
    fn made_with_ai_passe_chez_x_et_entre_dans_l_empreinte() {
        let apercu = X.apercu("t", &[], None, true);
        assert!(apercu.platform_limits_ok);
        assert_ne!(apercu.digest, X.apercu("t", &[], None, false).digest);
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
