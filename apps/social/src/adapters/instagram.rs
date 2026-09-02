//! Instagram : images JPEG, vidéos REELS, carrousels — chemin « Instagram API
//! with Instagram Login » (compte professionnel, PAS de Page Facebook).
//!
//! Tout vient des docs Meta, relevées le 2026-09-02 :
//!
//! * Conteneur : `POST graph.instagram.com/<v>/me/media` — paramètres
//!   `image_url`, `video_url`, `media_type` (REELS | STORIES | CAROUSEL —
//!   VIDEO pour un enfant de carrousel), `is_carousel_item`, `children`,
//!   `caption`, `alt_text`, `upload_type`, `is_ai_generated` —
//!   <https://developers.facebook.com/docs/instagram-api/reference/ig-user/media>.
//!   Image : JPEG SEUL (« JPEG is the only image format supported »), « 8 MB
//!   maximum », largeur 320–1440 px, ratio 4:5 à 1.91:1. REELS : « 15 mins
//!   maximum, 3 seconds minimum », « 300MB maximum ».
//! * Vidéo (REELS) : par `video_url` — le PULL depuis CHEZ NOUS. L'upload
//!   direct (`upload_type=resumable` + rupload.facebook.com) existe mais est
//!   « Only for apps that have implemented Facebook Login for Business »
//!   (content-publishing du chemin Instagram Login, relevé le 2026-09-02) —
//!   notre chemin est Instagram Login : le resumable nous est FERMÉ, le
//!   déblocage serait une app Facebook Login for Business. Le pull tire
//!   `video_url` sur un serveur public (« We cURL the video using the
//!   passed-in URL, so it must be on a public server », ig-user/media,
//!   relevé le 2026-09-02) : la plateforme tire NOS octets vettés à
//!   `{base}/medias/{digest}`, jamais l'URL du client. Idem pour les images
//!   (`image_url`, aucun upload direct décrit).
//! * Statut : `GET /<CONTENEUR>?fields=status_code` → « EXPIRED, ERROR,
//!   FINISHED, IN_PROGRESS, PUBLISHED » (content-publishing, 2026-09-02).
//! * Publication : `POST /me/media_publish` avec `creation_id` ; carrousel :
//!   `children` = « a comma separated list of up to 10 container IDs », et
//!   « Carousels count as a single post ».
//! * URL publique : `GET /<IG_MEDIA_ID>?fields=permalink` (micro-sonde du
//!   2026-09-02 sur la référence instagram-media : `permalink`, `like_count`,
//!   `comments_count` sont servis ; `caption` est réservé au chemin Facebook
//!   Login ; « Some fields, such as permalink, cannot be used on photos
//!   within albums (children) »).
//! * Limite : « Instagram accounts are limited to 100 API-published posts
//!   within a 24-hour moving period. » (content-publishing, 2026-09-02).
//! * Version Graph courante : v26.0 (changelog Graph API, 2026-07-29, relevé
//!   le 2026-09-02).
//! * Messagerie : `POST graph.instagram.com/<v>/me/messages`, corps
//!   `{recipient: {id: IGSID}, message: {text}}`, scopes
//!   instagram_business_basic + instagram_business_manage_messages ; « Your
//!   app has 24 hours to respond to any message sent from an Instagram
//!   user » (messaging-api, relevé le 2026-09-02) — le business RÉPOND, il
//!   n'initie pas ; divulgation d'automatisation obligatoire
//!   (policy-overview, 2026-09-02).
//!
//! Restes nommés (pas de stub) : STORIES (exigerait un champ de placement
//! dans la table — l'API les sert) ; ratio/pixels non vérifiables aux octets
//! sans parseur JPEG.

use std::sync::Arc;

use agentos_providers::Secret;
use async_trait::async_trait;

use super::{
    ActionFaite, Apercu, ApercuMedia, ContexteAdaptateurs, ElementLu, ErreurMessagerie,
    ErreurPlateforme, Inbox, MediaPret, MessagePrive, Metriques, OptionsPost, Plateforme,
    PlateformeMessagerie, PostsLus, ProfilLu, Publication, ReponsePubliee, Sondage, TypeMedia,
    empreinte_globale, envoyer, http, url_pull,
};
use crate::medias::DepotMedias;

/// graph.instagram.com — « All endpoints can be accessed via the
/// graph.instagram.com host » (messaging-api, relevé le 2026-09-02).
pub const BASE_GRAPH: &str = "https://graph.instagram.com";
/// La version Graph courante : v26.0, publiée le 2026-07-29 (changelog Graph
/// API, relevé le 2026-09-02). UN endroit à bumper quand Meta l'éteindra.
pub const VERSION_GRAPH: &str = "v26.0";

/// « 8 MB maximum » image (ig-user/media, relevé le 2026-09-02) — lecture
/// décimale, la plus stricte pour un maximum.
pub const OCTETS_MAX_IMAGE: u64 = 8_000_000;
/// « 300MB maximum » REELS (ig-user/media, relevé le 2026-09-02).
pub const OCTETS_MAX_REELS: u64 = 300_000_000;
/// `children` : « up to 10 container IDs », 2 minimum (content-publishing,
/// relevé le 2026-09-02). Le maxItems 20 de la table est inter-plateformes ;
/// CE resserrement est le travail de cet adaptateur.
pub const CARROUSEL_MIN: usize = 2;
pub const CARROUSEL_MAX: usize = 10;

/// ponytail: polling status_code toutes les 5 s sous un budget de 5 min —
/// même coupe que X/LinkedIn ; IG ne publie pas de check_after_secs.
pub const BUDGET_TRAITEMENT_SECS: u64 = 300;
pub const PAS_DE_POLLING_SECS: u64 = 5;

/// La divulgation d'automatisation obligatoire, préfixée à chaque DM :
/// « You are interacting with an automated experience » (policy-overview,
/// relevé le 2026-09-02). L'humain d'en face doit le savoir — toujours.
pub const DIVULGATION_AUTOMATISATION: &str = "You are interacting with an automated experience.";

/// « Instagram accounts are limited to 100 API-published posts within a
/// 24-hour moving period. Carousels count as a single post. » —
/// content-publishing, relevé le 2026-09-02. Rendu en verdict INFORMATIF :
/// le service ne peut pas compter les posts faits hors de lui.
pub const CITATION_100_POSTS: &str = "« Instagram accounts are limited to 100 API-published posts within a 24-hour \
     moving period. Carousels count as a single post. » (content-publishing, relevé le \
     2026-09-02)";

/// L'état avant-revue : « Standard Access... can only be requested from app
/// users who have a role on the requesting app » (access-levels, relevé le
/// 2026-09-02) — statique : le service ne peut pas sonder l'état d'audit.
pub const CITATION_AVANT_REVUE: &str = "avant l'Advanced Access, seuls les comptes ayant un rôle sur l'app \
     (admin/développeur/testeur) peuvent se connecter — « Standard Access... can only be \
     requested from app users who have a role on the requesting app » (access-levels, \
     relevé le 2026-09-02)";

/// Un chemin Graph versionné : `https://graph.instagram.com/v26.0/{chemin}`.
pub fn url_graph(chemin: &str) -> String {
    format!("{BASE_GRAPH}/{VERSION_GRAPH}/{chemin}")
}

/// Refuse tout identifiant qui n'a pas la forme d'un id Graph (des chiffres,
/// rien d'autre) : un id hostile ne devient jamais un morceau de chemin —
/// même garde que `id_x` chez X. Le statut 400 est le nôtre.
fn id_ig(id: &str) -> Result<&str, ErreurPlateforme> {
    if !id.is_empty() && id.bytes().all(|o| o.is_ascii_digit()) {
        Ok(id)
    } else {
        Err(ErreurPlateforme::Refus { statut: 400 })
    }
}

/// Les paramètres du conteneur d'UNE image. `image_url` est TOUJOURS dérivée
/// du digest contresigné (`url_pull`) — `MediaPret` ne porte même pas l'URL
/// du client, la plateforme ne peut pas la tirer, par construction.
pub fn params_conteneur_image(
    base: &str,
    m: &MediaPret,
    caption: Option<&str>,
    en_carrousel: bool,
    is_ai_generated: bool,
) -> Vec<(&'static str, String)> {
    let mut params = vec![("image_url", url_pull(base, &m.digest))];
    if let Some(alt) = &m.alt_text {
        // `alt_text` : paramètre du conteneur (ig-user/media, introduit le
        // 2025-03-24 — content-publishing, relevé le 2026-09-02).
        params.push(("alt_text", alt.clone()));
    }
    if let Some(c) = caption {
        params.push(("caption", c.to_owned()));
    }
    if en_carrousel {
        params.push(("is_carousel_item", "true".to_owned()));
    }
    if is_ai_generated {
        params.push(("is_ai_generated", "true".to_owned()));
    }
    params
}

/// Le conteneur REELS : `video_url` dérivée du digest contresigné — le pull
/// depuis CHEZ NOUS. L'upload direct (`upload_type=resumable` + rupload) est
/// « Only for apps that have implemented Facebook Login for Business »
/// (content-publishing Instagram Login, relevé le 2026-09-02) : fermé à notre
/// chemin ; le déblocage serait une app Facebook Login for Business.
pub fn params_conteneur_reels(
    base: &str,
    m: &MediaPret,
    caption: Option<&str>,
    is_ai_generated: bool,
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("media_type", "REELS".to_owned()),
        ("video_url", url_pull(base, &m.digest)),
    ];
    if let Some(c) = caption {
        params.push(("caption", c.to_owned()));
    }
    if is_ai_generated {
        params.push(("is_ai_generated", "true".to_owned()));
    }
    params
}

/// Un enfant vidéo de carrousel : `media_type=VIDEO` + `is_carousel_item` +
/// `video_url` (ig-user/media, relevé le 2026-09-02) — ici le pull est le
/// repli documenté, et il tire NOS octets vettés.
pub fn params_conteneur_video_carrousel(
    base: &str,
    m: &MediaPret,
    is_ai_generated: bool,
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("media_type", "VIDEO".to_owned()),
        ("is_carousel_item", "true".to_owned()),
        ("video_url", url_pull(base, &m.digest)),
    ];
    if is_ai_generated {
        params.push(("is_ai_generated", "true".to_owned()));
    }
    params
}

/// Le conteneur parent d'un carrousel : `children` = liste d'ids séparés par
/// des virgules (content-publishing, relevé le 2026-09-02).
pub fn params_conteneur_carrousel(
    caption: Option<&str>,
    enfants: &[String],
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("media_type", "CAROUSEL".to_owned()),
        ("children", enfants.join(",")),
    ];
    if let Some(c) = caption {
        params.push(("caption", c.to_owned()));
    }
    params
}

/// `POST /me/media_publish` avec `creation_id` (content-publishing, relevé le
/// 2026-09-02).
pub fn params_publish(creation_id: &str) -> Vec<(&'static str, String)> {
    vec![("creation_id", creation_id.to_owned())]
}

/// Le corps d'un DM : `{recipient: {id: IGSID}, message: {text}}`
/// (messaging-api, relevé le 2026-09-02). Le texte part TOUJOURS préfixé de
/// la divulgation d'automatisation — obligatoire (policy-overview,
/// 2026-09-02), donc posée ICI, pas laissée à la bonne volonté de l'agent.
pub fn corps_dm(igsid: &str, texte: &str) -> serde_json::Value {
    serde_json::json!({
        "recipient": { "id": igsid },
        "message": { "text": format!("{DIVULGATION_AUTOMATISATION}\n{texte}") }
    })
}

/// Lit `{"id": "..."}` — la réponse des conteneurs, de media_publish et des
/// commentaires. Le corps n'entre jamais dans l'erreur.
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

/// Où en est un conteneur après `GET ?fields=status_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatConteneur {
    Pret,
    EnCours,
    Echec,
}

/// « EXPIRED, ERROR, FINISHED, IN_PROGRESS, PUBLISHED » — content-publishing,
/// relevé le 2026-09-02. ERROR et EXPIRED : IG a mangé les octets puis dit
/// non — même coupe que le `failed` de X, le corps n'entre pas dans l'erreur.
pub fn statut_conteneur_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<EtatConteneur, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    match document.get("status_code").and_then(|v| v.as_str()) {
        Some("FINISHED") | Some("PUBLISHED") => Ok(EtatConteneur::Pret),
        Some("IN_PROGRESS") => Ok(EtatConteneur::EnCours),
        Some("ERROR") | Some("EXPIRED") => Ok(EtatConteneur::Echec),
        _ => Err(ErreurPlateforme::Illisible),
    }
}

/// Lit `{"permalink": "..."}` — `None` quand le champ manque (il ne se sert
/// pas sur les enfants d'album, micro-sonde instagram-media du 2026-09-02).
pub fn permalink_depuis(statut: u16, corps: &[u8]) -> Option<String> {
    if !(200..=299).contains(&statut) {
        return None;
    }
    serde_json::from_slice::<serde_json::Value>(corps)
        .ok()?
        .get("permalink")?
        .as_str()
        .map(str::to_owned)
}

/// Lit `like_count`/`comments_count` (référence instagram-media, relevé le
/// 2026-09-02). Les insights complets (impressions…) exigent le chemin
/// Facebook Login + `instagram_manage_insights` : `impressions: None` dit
/// « pas servi ici », pas zéro.
pub fn metriques_depuis(statut: u16, corps: &[u8]) -> Result<Metriques, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    Ok(Metriques {
        impressions: None,
        likes: document
            .get("like_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        replies: document
            .get("comments_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        // Pas de repost Instagram — 0 est un fait, pas une donnée manquante.
        reposts: 0,
    })
}

/// Lit `{"recipient_id", "message_id"}` — la réponse du Send API
/// (messaging-api, relevé le 2026-09-02).
pub fn message_depuis(
    statut: u16,
    corps: &[u8],
    igsid: &str,
) -> Result<MessagePrive, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let message_id = document
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    Ok(MessagePrive {
        // IG n'a pas d'id de conversation séparé : le fil EST l'IGSID du
        // correspondant — c'est ce que l'outil a reçu, on le rend tel quel.
        dm_conversation_id: igsid.to_owned(),
        dm_event_id: message_id.to_owned(),
        // Meta ne facture pas l'appel : 0,0 est un fait, pas une estimation.
        cout_usd: 0.0,
    })
}

/// Le verdict d'UN média, mots exacts et chiffres cités.
fn apercu_media(m: &MediaPret) -> ApercuMedia {
    let taille = m.octets.len() as u64;
    let mut verdicts = Vec::new();
    let mut ok = true;
    match m.type_detecte {
        TypeMedia::Jpeg => {
            if taille > OCTETS_MAX_IMAGE {
                ok = false;
                verdicts.push(format!("8 MB maximum pour une image, reçu {taille} octets"));
            }
            if let Some(alt) = &m.alt_text
                && alt.chars().count() > 1000
            {
                // « Alternative text, up to 1000 character, for an image »
                // (ig-user/media, rejoué le 2026-09-02) — le 4086 de la table
                // est inter-plateformes, CE resserrement est le nôtre.
                ok = false;
                verdicts.push(format!(
                    "alt_text « up to 1000 character » chez instagram (ig-user/media, \
                     relevé le 2026-09-02), reçu {}",
                    alt.chars().count()
                ));
            }
            // ponytail: largeur 320–1440 px et ratio 4:5 à 1.91:1 ne se
            // vérifient pas aux octets sans parseur JPEG — verdict informatif,
            // la plateforme tranchera.
            verdicts.push(
                "largeur 320-1440 px et ratio 4:5 à 1.91:1 non vérifiés aux octets — \
                 instagram tranchera (ig-user/media, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        TypeMedia::Png | TypeMedia::Gif | TypeMedia::Webp => {
            ok = false;
            verdicts.push(format!(
                "« JPEG is the only image format supported » (ig-user/media, relevé le \
                 2026-09-02) — reçu {}",
                m.type_detecte.mime()
            ));
        }
        TypeMedia::Mp4 => {
            if taille > OCTETS_MAX_REELS {
                ok = false;
                verdicts.push(format!(
                    "« 300MB maximum » pour un REELS, reçu {taille} octets"
                ));
            }
            verdicts.push(
                "REELS : « 15 mins maximum, 3 seconds minimum » — durée non vérifiable \
                 aux octets, instagram tranchera (ig-user/media, relevé le 2026-09-02)"
                    .to_owned(),
            );
            if m.alt_text.is_some() {
                ok = false;
                verdicts.push(
                    "`alt_text` est un paramètre d'IMAGE chez instagram (ig-user/media, \
                     relevé le 2026-09-02) — pas de texte alternatif vidéo"
                        .to_owned(),
                );
            }
        }
        TypeMedia::Pdf => {
            ok = false;
            verdicts.push(
                "instagram ne sert aucun type document (aucun paramètre document dans \
                 ig-user/media, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
    }
    if m.title.is_some() {
        ok = false;
        verdicts.push(
            "instagram ne sert pas de title de média (aucun paramètre title dans \
             ig-user/media, relevé le 2026-09-02)"
                .to_owned(),
        );
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

/// L'adaptateur. Il tient la base publique et le dépôt : ses images (et ses
/// vidéos de carrousel) partent en « pull depuis chez nous ».
pub struct Instagram {
    base_publique: String,
    depot: Arc<DepotMedias>,
}

impl Instagram {
    pub fn nouvel(ctx: &ContexteAdaptateurs) -> Self {
        Self {
            base_publique: ctx.base_publique.trim_end_matches('/').to_owned(),
            depot: ctx.depot.clone(),
        }
    }

    /// Poll `?fields=status_code` jusqu'à FINISHED, sous budget.
    async fn attendre_conteneur(
        &self,
        jeton: &Secret,
        conteneur: &str,
    ) -> Result<(), ErreurPlateforme> {
        let mut budget = BUDGET_TRAITEMENT_SECS;
        loop {
            let (statut, corps) = envoyer(
                http()
                    .get(url_graph(conteneur))
                    .query(&[("fields", "status_code")])
                    .bearer_auth(jeton.expose_for_transport()),
            )
            .await?;
            match statut_conteneur_depuis(statut, &corps)? {
                EtatConteneur::Pret => return Ok(()),
                // IG a mangé les octets puis dit non : Injoignable, pas de
                // corps dans l'erreur, et un rejeu (même clé) reste sensé.
                EtatConteneur::Echec => return Err(ErreurPlateforme::Injoignable),
                EtatConteneur::EnCours => {
                    if budget < PAS_DE_POLLING_SECS {
                        return Err(ErreurPlateforme::Injoignable);
                    }
                    budget -= PAS_DE_POLLING_SECS;
                    tokio::time::sleep(std::time::Duration::from_secs(PAS_DE_POLLING_SECS)).await;
                }
            }
        }
    }

    /// Crée UN conteneur (POST /me/media, paramètres en formulaire) et attend
    /// qu'il soit prêt.
    async fn conteneur(
        &self,
        jeton: &Secret,
        params: &[(&'static str, String)],
    ) -> Result<String, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .post(url_graph("me/media"))
                .bearer_auth(jeton.expose_for_transport())
                .form(params),
        )
        .await?;
        let id = id_depuis(statut, &corps)?;
        self.attendre_conteneur(jeton, &id).await?;
        Ok(id)
    }

    /// Une image : dépôt des octets vettés → conteneur qui tire
    /// `{base}/medias/{digest}` → retrait du dépôt une fois le conteneur prêt
    /// (« hosted on a publicly accessible server at the time of the
    /// attempt », content-publishing, relevé le 2026-09-02 — après FINISHED,
    /// l'attempt est passée). En erreur, le TTL du dépôt (1 h) nettoie.
    async fn conteneur_pull(
        &self,
        jeton: &Secret,
        m: &MediaPret,
        params: &[(&'static str, String)],
    ) -> Result<String, ErreurPlateforme> {
        self.depot
            .deposer(&m.digest, m.octets.clone(), m.type_detecte);
        let resultat = self.conteneur(jeton, params).await;
        self.depot.retirer(&m.digest);
        resultat
    }

    /// L'URL publique du post — best effort : après media_publish le post
    /// EXISTE, échouer ici marquerait 'failed' un post publié et un rejeu le
    /// DUPLIQUERAIT. Un permalink illisible rend la racine, pas une erreur.
    async fn permalink(&self, jeton: &Secret, media_id: &str) -> String {
        let Ok((statut, corps)) = envoyer(
            http()
                .get(url_graph(media_id))
                .query(&[("fields", "permalink")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await
        else {
            return "https://www.instagram.com".to_owned();
        };
        permalink_depuis(statut, &corps).unwrap_or_else(|| "https://www.instagram.com".to_owned())
    }
}

#[async_trait]
impl Plateforme for Instagram {
    fn nom(&self) -> &'static str {
        "instagram"
    }

    fn apercu(
        &self,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Apercu {
        // Les refus font tomber platform_limits_ok ; les verdicts informatifs
        // (précédent : la vidéo Premium de X) le laissent vrai.
        let mut refus = Vec::new();
        let mut infos = Vec::new();

        if medias.is_empty() {
            refus.push(
                "instagram ne publie pas de post texte seul : un conteneur exige image_url \
                 ou un média (ig-user/media, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        if medias.len() > CARROUSEL_MAX {
            refus.push(format!(
                "carrousel « limited to 10 images, videos, or a mix of the two » \
                 (content-publishing, relevé le 2026-09-02) — 10 max, reçu {}",
                medias.len()
            ));
        }
        if sondage.is_some() {
            refus.push(
                "instagram ne sert pas de sondage (aucun champ poll dans ig-user/media, \
                 relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        // made_with_ai : SERVI — paramètre `is_ai_generated` du conteneur
        // (ig-user/media, relevé le 2026-09-02). Rien à refuser.
        let _ = made_with_ai;
        if options.privacy.is_some() {
            refus.push(
                "instagram ne sert pas `privacy` : aucune visibilité à la publication dans \
                 content-publishing (relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        if options.publish_at.is_some() {
            refus.push(
                "instagram ne sert pas `publish_at` : aucune planification dans \
                 content-publishing (relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        infos.push(CITATION_100_POSTS.to_owned());
        infos.push(CITATION_AVANT_REVUE.to_owned());

        let media: Vec<ApercuMedia> = medias.iter().map(apercu_media).collect();
        let limites_ok = refus.is_empty() && media.iter().all(|m| m.limits_ok);
        let mut verdicts = refus;
        verdicts.append(&mut infos);
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai, options),
            platform_limits_ok: limites_ok,
            // Meta ne facture pas la publication : None, pas 0,0.
            cost_estimate_usd: None,
            media,
            verdicts,
            cout_quota: None,
        }
    }

    /// `handle` est le username (identite_depuis a rangé (username, user_id)) ;
    /// les chemins passent par `me` — l'alias du compte du jeton, le même que
    /// le `GET /me?fields=user_id,username` documenté.
    async fn publier(
        &self,
        jeton: &Secret,
        _handle: &str,
        texte: &str,
        medias: &[MediaPret],
        _sondage: Option<&Sondage>,
        made_with_ai: bool,
        _options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        // C7 : l'aperçu (sondage/privacy/publish_at refusés, types refusés)
        // passe avant publier. Un contournement prend un refus local.
        let creation_id = match medias {
            [] => return Err(ErreurPlateforme::Refus { statut: 400 }),
            [seul] => match seul.type_detecte {
                TypeMedia::Jpeg => {
                    self.conteneur_pull(
                        jeton,
                        seul,
                        &params_conteneur_image(
                            &self.base_publique,
                            seul,
                            Some(texte),
                            false,
                            made_with_ai,
                        ),
                    )
                    .await?
                }
                TypeMedia::Mp4 => {
                    self.conteneur_pull(
                        jeton,
                        seul,
                        &params_conteneur_reels(
                            &self.base_publique,
                            seul,
                            Some(texte),
                            made_with_ai,
                        ),
                    )
                    .await?
                }
                _ => return Err(ErreurPlateforme::Refus { statut: 400 }),
            },
            plusieurs => {
                if plusieurs.len() > CARROUSEL_MAX {
                    return Err(ErreurPlateforme::Refus { statut: 400 });
                }
                let mut enfants = Vec::with_capacity(plusieurs.len());
                for m in plusieurs {
                    let id = match m.type_detecte {
                        TypeMedia::Jpeg => {
                            self.conteneur_pull(
                                jeton,
                                m,
                                &params_conteneur_image(
                                    &self.base_publique,
                                    m,
                                    None,
                                    true,
                                    made_with_ai,
                                ),
                            )
                            .await?
                        }
                        // L'enfant vidéo passe aussi par le pull : le
                        // resumable n'est documenté que pour REELS/stories —
                        // video_url tire NOS octets vettés (repli documenté).
                        TypeMedia::Mp4 => {
                            self.conteneur_pull(
                                jeton,
                                m,
                                &params_conteneur_video_carrousel(
                                    &self.base_publique,
                                    m,
                                    made_with_ai,
                                ),
                            )
                            .await?
                        }
                        _ => return Err(ErreurPlateforme::Refus { statut: 400 }),
                    };
                    enfants.push(id);
                }
                self.conteneur(jeton, &params_conteneur_carrousel(Some(texte), &enfants))
                    .await?
            }
        };

        let (statut, corps) = envoyer(
            http()
                .post(url_graph("me/media_publish"))
                .bearer_auth(jeton.expose_for_transport())
                .form(&params_publish(&creation_id)),
        )
        .await?;
        let media_id = id_depuis(statut, &corps)?;
        let url = self.permalink(jeton, &media_id).await;
        Ok(Publication {
            id_plateforme: media_id,
            url,
        })
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .get(url_graph(id_ig(id_plateforme)?))
                .query(&[("fields", "like_count,comments_count")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        metriques_depuis(statut, &corps).map(Some)
    }
}

// ---------------------------------------------------------------------------
// La messagerie — IG sert une PARTIE de la table ; chaque méthode non servie
// rend NeSertPas avec la citation datée. Sondes du 2026-09-02.
// ---------------------------------------------------------------------------

/// Fenêtre 24 h : « Your app has 24 hours to respond to any message sent
/// from an Instagram user to your app user » (messaging-api, relevé le
/// 2026-09-02) — c'est « User sends a message » qui OUVRE la fenêtre : le
/// business répond, il n'initie pas.
pub const CITATION_DM_REPONSE_SEULE: &str = "la fenêtre de 24 h s'ouvre quand « User sends a message » — le business RÉPOND, \
     il n'initie pas ; et chaque message porte la divulgation d'automatisation \
     obligatoire (messaging-api + policy-overview, relevés le 2026-09-02)";

const CITATION_PAS_DE_LIKE: &str = "la liste exhaustive d'opérations de comment-moderation (lire/répondre/hide/\
     supprimer) ne contient pas de like ; la référence media n'expose que like_count en \
     lecture (relevé le 2026-09-02)";

const CITATION_PAS_DE_COMMENTAIRE_RACINE: &str = "la liste exhaustive de comment-moderation ne contient pas de création de \
     commentaire de premier niveau sur un média (relevé le 2026-09-02)";

const CITATION_RECHERCHE: &str = "le hashtag search est réservé au chemin Facebook Login + feature « Instagram \
     Public Content Access » + App Review — « maximum of 30 unique hashtags... within a \
     rolling, 7 day period », interdiction de commenter les médias découverts \
     (hashtag-search, relevé le 2026-09-02)";

const CITATION_INBOX_WEBHOOKS: &str = "la lecture des messages passe par les webhooks (« we strongly recommend using \
     webhooks ») et « Allow Access to Messages » côté utilisateur (relevé le \
     2026-09-02) — ce service n'a pas de callback webhook";

const CITATION_AUCUN_ENDPOINT: &str = "aucun endpoint dans la plateforme sondée (bookmarks/reposts/quotes/profils \
     tiers — Instagram Platform, relevé le 2026-09-02)";

const CITATION_PAS_DE_TIERS: &str = "GET /{ig-user-id}/media ne sert que le compte du jeton — pas de lecture de \
     timeline de tiers (ig-user/media, relevé le 2026-09-02)";

fn ne_sert_pas(citation: &'static str, deblocage: &'static str) -> ErreurMessagerie {
    ErreurMessagerie::NeSertPas {
        citation,
        deblocage,
    }
}

#[async_trait]
impl PlateformeMessagerie for Instagram {
    fn nom(&self) -> &'static str {
        "instagram"
    }

    /// Répondre dans la fenêtre de 24 h. Le `conversation_id` de l'outil
    /// porte l'IGSID du correspondant — IG n'a pas d'id de fil séparé.
    async fn dm_reply(
        &self,
        jeton: &Secret,
        dm_conversation_id: &str,
        texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        let igsid = id_ig(dm_conversation_id)?;
        let (statut, corps) = envoyer(
            http()
                .post(url_graph("me/messages"))
                .bearer_auth(jeton.expose_for_transport())
                .json(&corps_dm(igsid, texte)),
        )
        .await?;
        Ok(message_depuis(statut, &corps, igsid)?)
    }

    async fn dm_open(
        &self,
        _jeton: &Secret,
        _participant_id: &str,
        _texte: &str,
    ) -> Result<MessagePrive, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_DM_REPONSE_SEULE,
            "rien — la prospection sortante automatisée est interdite par les règles citées",
        ))
    }

    async fn inbox(&self, _jeton: &Secret, _user_id: &str) -> Result<Inbox, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_INBOX_WEBHOOKS,
            "câbler les webhooks Meta (messages entrants poussés, pas tirés)",
        ))
    }

    /// Répondre publiquement à un post = créer un commentaire de premier
    /// niveau — ce que comment-moderation ne sert pas.
    async fn post_reply(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _in_reply_to_post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_PAS_DE_COMMENTAIRE_RACINE,
            "rien — seule la RÉPONSE à un commentaire existant est servie (post_comment \
             avec parent_comment_id)",
        ))
    }

    /// AVEC parent : `POST /<IG_COMMENT_ID>/replies` (comment-moderation,
    /// relevé le 2026-09-02). SANS parent : le refus cité.
    async fn post_comment(
        &self,
        jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        parent_comment: Option<&str>,
        texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        let Some(parent) = parent_comment else {
            return Err(ne_sert_pas(
                CITATION_PAS_DE_COMMENTAIRE_RACINE,
                "rien — passer parent_comment_id pour répondre à un commentaire existant",
            ));
        };
        let (statut, corps) = envoyer(
            http()
                .post(url_graph(&format!("{}/replies", id_ig(parent)?)))
                .bearer_auth(jeton.expose_for_transport())
                .form(&[("message", texte)]),
        )
        .await?;
        let id = id_depuis(statut, &corps)?;
        Ok(ReponsePubliee {
            id_plateforme: id,
            // IG ne rend pas d'URL publique pour un commentaire — vide, pas
            // inventé.
            url: String::new(),
            cout_usd: 0.0,
            cout_quota: None,
        })
    }

    async fn post_like(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_LIKE, "rien"))
    }

    async fn post_unlike(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_PAS_DE_LIKE, "rien"))
    }

    async fn post_bookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_ENDPOINT, "rien"))
    }

    async fn post_unbookmark(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_ENDPOINT, "rien"))
    }

    async fn post_repost(
        &self,
        _jeton: &Secret,
        _user_id: &str,
        _post_id: &str,
    ) -> Result<ActionFaite, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_ENDPOINT, "rien"))
    }

    async fn post_quote(
        &self,
        _jeton: &Secret,
        _handle: &str,
        _post_id: &str,
        _texte: &str,
    ) -> Result<ReponsePubliee, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_ENDPOINT, "rien"))
    }

    async fn search_posts(
        &self,
        _jeton: &Secret,
        _query: &str,
        _max_results: u8,
    ) -> Result<PostsLus, ErreurMessagerie> {
        Err(ne_sert_pas(
            CITATION_RECHERCHE,
            "une app Facebook Login + la revue « Instagram Public Content Access »",
        ))
    }

    /// SES médias — `caption` est réservé au chemin Facebook Login (micro-
    /// sonde instagram-media du 2026-09-02) : le texte rendu est le
    /// permalink, pas la légende — un champ servi, jamais un champ deviné.
    async fn read_post(
        &self,
        jeton: &Secret,
        post_id: &str,
    ) -> Result<ElementLu, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(url_graph(id_ig(post_id)?))
                .query(&[("fields", "id,permalink")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        let document: serde_json::Value =
            serde_json::from_slice(&corps).map_err(|_| ErreurPlateforme::Illisible)?;
        Ok(ElementLu {
            id: document
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or(ErreurPlateforme::Illisible)?
                .to_owned(),
            auteur_id: None,
            texte: document
                .get("permalink")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            third_party: true,
        })
    }

    async fn read_profile(
        &self,
        _jeton: &Secret,
        _username: &str,
    ) -> Result<ProfilLu, ErreurMessagerie> {
        Err(ne_sert_pas(CITATION_AUCUN_ENDPOINT, "rien"))
    }

    /// UNIQUEMENT le compte du jeton : `user_id` est comparé à `GET /me` —
    /// un tiers prend le refus cité, jamais un appel qui « essaie ».
    async fn read_timeline(
        &self,
        jeton: &Secret,
        user_id: &str,
    ) -> Result<PostsLus, ErreurMessagerie> {
        let (statut, corps) = envoyer(
            http()
                .get(url_graph("me"))
                .query(&[("fields", "user_id")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        let document: serde_json::Value =
            serde_json::from_slice(&corps).map_err(|_| ErreurPlateforme::Illisible)?;
        let moi = document
            .get("user_id")
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                autre => autre.to_string(),
            })
            .ok_or(ErreurPlateforme::Illisible)?;
        if moi != user_id {
            return Err(ne_sert_pas(CITATION_PAS_DE_TIERS, "rien"));
        }
        let (statut, corps) = envoyer(
            http()
                .get(url_graph("me/media"))
                .query(&[("fields", "id,permalink")])
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
            return Err(erreur.into());
        }
        let document: serde_json::Value =
            serde_json::from_slice(&corps).map_err(|_| ErreurPlateforme::Illisible)?;
        let posts = document
            .get("data")
            .and_then(|v| v.as_array())
            .map(|liste| {
                liste
                    .iter()
                    .filter_map(|e| {
                        Some(ElementLu {
                            id: e.get("id")?.as_str()?.to_owned(),
                            auteur_id: Some(user_id.to_owned()),
                            texte: e
                                .get("permalink")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_owned(),
                            third_party: true,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(PostsLus {
            posts,
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

    fn contexte() -> ContexteAdaptateurs {
        ContexteAdaptateurs {
            base_publique: "https://social.example".to_owned(),
            depot: Arc::new(DepotMedias::new()),
        }
    }

    fn ig() -> Instagram {
        Instagram::nouvel(&contexte())
    }

    /// LA preuve du modèle pull : le corps de conteneur porte
    /// `{base}/medias/{digest}` — dérivée du digest contresigné, et JAMAIS
    /// l'URL du client, que `MediaPret` ne porte même pas (par construction :
    /// medias.rs la jette après téléchargement).
    #[test]
    fn le_conteneur_image_tire_chez_nous_jamais_chez_le_client() {
        let m = media(&[0xFF, 0xD8, 0xFF, 0xE0], TypeMedia::Jpeg);
        let params =
            params_conteneur_image("https://social.example", &m, Some("légende"), false, false);
        assert_eq!(
            params[0],
            (
                "image_url",
                format!("https://social.example/medias/{}", m.digest)
            )
        );
        // Aucune valeur ne peut être autre chose que la dérivée du digest :
        // l'URL envoyée est celle du contreseing, à l'octet.
        assert!(
            params
                .iter()
                .all(|(_, v)| !v.contains("http") || v.ends_with(&m.digest)),
            "{params:?}"
        );
        assert!(params.contains(&("caption", "légende".to_owned())));
        // En carrousel : is_carousel_item, pas de caption.
        let enfant = params_conteneur_image("https://social.example", &m, None, true, false);
        assert!(enfant.contains(&("is_carousel_item", "true".to_owned())));
        assert!(!enfant.iter().any(|(n, _)| *n == "caption"));
        // L'enfant vidéo tire aussi chez nous.
        let v = media(b"\x00\x00\x00\x20ftypisom", TypeMedia::Mp4);
        let enfant_video = params_conteneur_video_carrousel("https://social.example", &v, false);
        assert!(enfant_video.contains(&("media_type", "VIDEO".to_owned())));
        assert!(enfant_video.contains(&(
            "video_url",
            format!("https://social.example/medias/{}", v.digest)
        )));
    }

    /// REELS : `video_url` dérivée du digest — le pull depuis chez nous (le
    /// resumable est fermé au chemin Instagram Login, cité sur la fonction) —
    /// et `is_ai_generated` quand made_with_ai est vrai.
    #[test]
    fn le_conteneur_reels_tire_chez_nous_et_sert_is_ai_generated() {
        let v = media(b"\x00\x00\x00\x20ftypisom", TypeMedia::Mp4);
        let params = params_conteneur_reels("https://social.example", &v, Some("texte"), true);
        assert!(params.contains(&("media_type", "REELS".to_owned())));
        assert!(params.contains(&(
            "video_url",
            format!("https://social.example/medias/{}", v.digest)
        )));
        // Jamais le resumable : fermé à notre chemin de login (cité).
        assert!(!params.iter().any(|(n, _)| *n == "upload_type"));
        assert!(params.contains(&("is_ai_generated", "true".to_owned())));
        // Absent quand faux : un champ absent et un champ nul ne sont pas la
        // même requête.
        assert!(
            !params_conteneur_reels("https://s.example", &v, None, false)
                .iter()
                .any(|(n, _)| *n == "is_ai_generated")
        );
    }

    #[test]
    fn le_carrousel_joint_les_enfants_par_des_virgules() {
        let enfants = vec!["111".to_owned(), "222".to_owned()];
        let params = params_conteneur_carrousel(Some("t"), &enfants);
        assert!(params.contains(&("media_type", "CAROUSEL".to_owned())));
        assert!(params.contains(&("children", "111,222".to_owned())));
        assert_eq!(
            params_publish("333"),
            vec![("creation_id", "333".to_owned())]
        );
    }

    /// La divulgation d'automatisation est posée PAR l'adaptateur — un agent
    /// ne peut pas l'omettre (policy-overview, relevé le 2026-09-02).
    #[test]
    fn le_dm_porte_toujours_la_divulgation() {
        let corps = corps_dm("1234", "Bonjour !");
        assert_eq!(corps["recipient"]["id"], "1234");
        let texte = corps["message"]["text"].as_str().unwrap();
        assert!(texte.starts_with(DIVULGATION_AUTOMATISATION), "{texte}");
        assert!(texte.ends_with("Bonjour !"), "{texte}");
    }

    #[test]
    fn les_lecteurs_lisent_les_formes_documentees() {
        assert_eq!(
            id_depuis(200, br#"{"id":"17889455560051444"}"#).unwrap(),
            "17889455560051444"
        );
        assert_eq!(
            statut_conteneur_depuis(200, br#"{"status_code":"FINISHED","id":"1"}"#).unwrap(),
            EtatConteneur::Pret
        );
        assert_eq!(
            statut_conteneur_depuis(200, br#"{"status_code":"IN_PROGRESS"}"#).unwrap(),
            EtatConteneur::EnCours
        );
        for fini in ["ERROR", "EXPIRED"] {
            assert_eq!(
                statut_conteneur_depuis(200, format!(r#"{{"status_code":"{fini}"}}"#).as_bytes())
                    .unwrap(),
                EtatConteneur::Echec
            );
        }
        assert_eq!(
            permalink_depuis(
                200,
                br#"{"permalink":"https://www.instagram.com/p/abc/","id":"1"}"#
            ),
            Some("https://www.instagram.com/p/abc/".to_owned())
        );
        // permalink absent (enfant d'album) : None, pas une panne.
        assert_eq!(permalink_depuis(200, br#"{"id":"1"}"#), None);
        let m = metriques_depuis(200, br#"{"like_count":7,"comments_count":3,"id":"1"}"#).unwrap();
        assert_eq!(m.likes, 7);
        assert_eq!(m.replies, 3);
        assert_eq!(m.impressions, None);
        assert_eq!(m.reposts, 0);
        let dm = message_depuis(
            200,
            br#"{"recipient_id":"1234","message_id":"mid.xyz"}"#,
            "1234",
        )
        .unwrap();
        assert_eq!(dm.dm_event_id, "mid.xyz");
        assert_eq!(dm.dm_conversation_id, "1234");
    }

    /// Aucun corps hostile (écho de la requête, Authorization comprise) ne
    /// traverse vers l'erreur — sur TOUS les lecteurs.
    #[test]
    fn aucun_lecteur_ne_laisse_fuir_un_jeton() {
        let hostile = br#"{"error":{"message":"Bearer JETON-SECRET refuse"}}"#;
        for statut in [400, 401, 403, 404, 429, 500] {
            let rendus = [
                format!("{:?}", id_depuis(statut, hostile)),
                format!("{:?}", statut_conteneur_depuis(statut, hostile)),
                format!("{:?}", metriques_depuis(statut, hostile)),
                format!("{:?}", message_depuis(statut, hostile, "1")),
                format!("{:?}", permalink_depuis(statut, hostile)),
            ];
            for rendu in rendus {
                assert!(!rendu.contains("JETON-SECRET"), "le jeton a fui: {rendu}");
            }
        }
    }

    #[test]
    fn l_apercu_refuse_ce_qu_instagram_refuse_mots_exacts() {
        let ig = ig();
        // Texte seul : pas de post texte chez IG.
        let apercu = ig.apercu("bonjour", &[], None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("texte seul")),
            "{:?}",
            apercu.verdicts
        );

        // PNG : « JPEG is the only image format supported ».
        let png = [media(&crate::medias::octets_png(b"x"), TypeMedia::Png)];
        let apercu = ig.apercu("t", &png, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("JPEG is the only image format supported")),
            "{:?}",
            apercu.media[0].verdicts
        );

        // JPEG de 9 MB : « 8 MB maximum », chiffre cité.
        let lourde = [media(&vec![0u8; 9_000_000], TypeMedia::Jpeg)];
        let apercu = ig.apercu("t", &lourde, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("8 MB") && v.contains("9000000")),
            "{:?}",
            apercu.media[0].verdicts
        );

        // alt_text de 1001 : « up to 1000 character » (ig-user/media).
        let mut avec_alt = media(&[0xFF, 0xD8, 0xFF, 0xE0], TypeMedia::Jpeg);
        avec_alt.alt_text = Some("x".repeat(1001));
        let apercu = ig.apercu("t", &[avec_alt.clone()], None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("1000") && v.contains("1001")),
            "{:?}",
            apercu.media[0].verdicts
        );
        avec_alt.alt_text = Some("x".repeat(1000));
        assert!(
            ig.apercu("t", &[avec_alt], None, false, &SANS)
                .platform_limits_ok
        );

        // 11 éléments : « 10 max, reçu 11 ».
        let onze: Vec<_> = (0..11)
            .map(|i| media(&[i as u8], TypeMedia::Jpeg))
            .collect();
        let apercu = ig.apercu("t", &onze, None, false, &SANS);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("reçu 11")),
            "{:?}",
            apercu.verdicts
        );

        // Sondage, privacy, publish_at : refusés avec citation.
        let sondage = Sondage {
            question: None,
            options: vec!["a".into(), "b".into()],
            duration_minutes: 1440,
        };
        let seul = [media(&[1u8], TypeMedia::Jpeg)];
        assert!(
            !ig.apercu("t", &seul, Some(&sondage), false, &SANS)
                .platform_limits_ok
        );
        let avec_privacy = OptionsPost {
            privacy: Some(crate::adapters::Privacy::Public),
            publish_at: None,
        };
        assert!(
            !ig.apercu("t", &seul, None, false, &avec_privacy)
                .platform_limits_ok
        );
        let avec_date = OptionsPost {
            privacy: None,
            publish_at: Some("2026-10-01T09:00:00Z".to_owned()),
        };
        assert!(
            !ig.apercu("t", &seul, None, false, &avec_date)
                .platform_limits_ok
        );
    }

    /// Un JPEG propre passe — et les états avant-revue + la limite 100/24 h
    /// sont RENDUS (verdicts informatifs, limits_ok reste vrai) : l'agent et
    /// l'humain qui contresigne les voient.
    #[test]
    fn un_jpeg_propre_passe_et_les_etats_avant_revue_sont_rendus() {
        let ig = ig();
        let seul = [media(&[0xFF, 0xD8, 0xFF, 0xE0], TypeMedia::Jpeg)];
        let apercu = ig.apercu("légende", &seul, None, false, &SANS);
        assert!(apercu.platform_limits_ok, "{:?}", apercu.verdicts);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("100 API-published posts")),
            "{:?}",
            apercu.verdicts
        );
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("Standard Access")),
            "{:?}",
            apercu.verdicts
        );
        // made_with_ai est SERVI (is_ai_generated) : rien ne tombe.
        assert!(ig.apercu("t", &seul, None, true, &SANS).platform_limits_ok);
        // Un mix JPEG+MP4 en carrousel passe (« a mix of the two »).
        let mix = [
            media(&[0xFF, 0xD8, 0xFF, 0xE0], TypeMedia::Jpeg),
            media(b"\x00\x00\x00\x20ftypisom", TypeMedia::Mp4),
        ];
        assert!(
            ig.apercu("t", &mix, None, false, &SANS).platform_limits_ok,
            "{:?}",
            ig.apercu("t", &mix, None, false, &SANS).verdicts
        );
    }

    /// Chaque refus messagerie est un fait cité et daté — jamais un stub.
    #[tokio::test]
    async fn les_refus_messagerie_portent_leurs_citations() {
        let ig = ig();
        let jeton = Secret::new("jeton");
        let cas: Vec<(&str, ErreurMessagerie)> = vec![
            ("dm_open", ig.dm_open(&jeton, "1", "t").await.unwrap_err()),
            (
                "post_like",
                ig.post_like(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "post_reply",
                ig.post_reply(&jeton, "h", "2", "t").await.unwrap_err(),
            ),
            (
                "post_comment sans parent",
                ig.post_comment(&jeton, "h", "2", None, "t")
                    .await
                    .unwrap_err(),
            ),
            (
                "search",
                ig.search_posts(&jeton, "q", 10).await.unwrap_err(),
            ),
            ("inbox", ig.inbox(&jeton, "1").await.unwrap_err()),
            (
                "bookmark",
                ig.post_bookmark(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "repost",
                ig.post_repost(&jeton, "1", "2").await.unwrap_err(),
            ),
            (
                "quote",
                ig.post_quote(&jeton, "h", "2", "t").await.unwrap_err(),
            ),
            ("profil", ig.read_profile(&jeton, "u").await.unwrap_err()),
        ];
        for (nom, erreur) in cas {
            assert_eq!(erreur.code(), "plateforme_ne_sert_pas", "{nom}");
            let ErreurMessagerie::NeSertPas { citation, .. } = erreur else {
                panic!("{nom} doit être NeSertPas");
            };
            assert!(citation.contains("2026-09-02"), "{nom}: {citation}");
        }
    }

    /// Un id hostile ne devient jamais un morceau de chemin Graph.
    #[tokio::test]
    async fn un_id_hostile_est_refuse_avant_toute_url() {
        let ig = ig();
        let jeton = Secret::new("jeton");
        for hostile in ["", "../me", "me/messages", "abc?x=1"] {
            assert!(
                ig.dm_reply(&jeton, hostile, "t").await.is_err(),
                "{hostile}"
            );
            assert!(
                ig.post_comment(&jeton, "h", "1", Some(hostile), "t")
                    .await
                    .is_err(),
                "{hostile}"
            );
        }
    }

    #[test]
    fn les_urls_sont_versionnees_et_en_https() {
        assert_eq!(
            url_graph("me/media"),
            "https://graph.instagram.com/v26.0/me/media"
        );
        assert!(url_graph("me").starts_with("https://"));
    }
}
