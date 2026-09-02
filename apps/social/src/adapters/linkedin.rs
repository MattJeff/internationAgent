//! LinkedIn : texte, image(s), vidéo, document PDF, sondage — sur le profil
//! du membre.
//!
//! Tout vient de Microsoft Learn (`view=li-lms-2026-08`), relevé le
//! 2026-09-02 par la sonde LinkedIn :
//!
//! * Création : `POST https://api.linkedin.com/rest/posts`, en-têtes
//!   `LinkedIn-Version: {YYYYMM}` et `X-Restli-Protocol-Version: 2.0.0`
//!   obligatoires sur toutes les APIs ; permission `w_member_social` —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/posts-api>.
//!   Réponse : `201`, l'URN du post dans l'en-tête `x-restli-id` ; le champ
//!   `content` porte les formes ALTERNATIVES `media` | `multiImage` | `poll`.
//! * Images : `POST /rest/images?action=initializeUpload`
//!   `{initializeUploadRequest: {owner}}` → `PUT uploadUrl` AVEC Bearer (la
//!   page Assets : l'upload image porte l'OAuth, l'upload vidéo NON) ; pas de
//!   polling (pas d'état bloquant documenté, et un jeton `w_member_social`
//!   seul est write-only sur `GET /rest/images`). Formats JPG/GIF/PNG —
//!   pas de WEBP ; altText ≤ 4086 (recommandé < 120) ; AUCUNE limite d'octets
//!   publiée ; 1 image ou 2–20 en multiImage (organique seulement) —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/images-api>
//!   et multiimage-post-api.
//! * Vidéos : `POST /rest/videos?action=initializeUpload`
//!   `{owner, fileSizeBytes, uploadCaptions: false, uploadThumbnail: false}` →
//!   PUT chaque part SELON `uploadInstructions` (plages `firstByte`/`lastByte`
//!   fournies, parts de 4 194 304 octets, la dernière plus courte — suivre
//!   les instructions, ne pas recalculer), `Content-Type:
//!   application/octet-stream`, SANS Authorization, relever l'ETag de CHAQUE
//!   part → `?action=finalizeUpload` `{video, uploadToken: "",
//!   uploadedPartIds: [etags DANS L'ORDRE]}` → poller `GET /rest/videos/{urn}`
//!   jusqu'à `AVAILABLE` (WAITING_UPLOAD/PROCESSING/PROCESSING_FAILED). MP4
//!   seul, 75 KB à 500 MB (borne feed sûre ; le schéma dit 5 GB — les deux
//!   chiffres coexistent, on prend 500 MB), une seule vidéo —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/videos-api>.
//! * Documents : `POST /rest/documents?action=initializeUpload` → PUT AVEC
//!   Bearer → poller `GET /rest/documents/{urn}` jusqu'à AVAILABLE. PDF ≤
//!   100 MB (≤ 300 pages, non vérifiable aux octets) —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/documents-api>.
//! * Sondage : `question` OBLIGATOIRE ≤ 140, 2–4 options ≤ 30 caractères,
//!   `settings.duration` ∈ {ONE_DAY, THREE_DAYS, SEVEN_DAYS, FOURTEEN_DAYS} —
//!   posts-api (poll content), relevé le 2026-09-02.
//! * Auteur membre : `urn:li:person:{id}` —
//!   <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/post-api-schema>.
//! * Version courante : le moniker par défaut de la doc est `li-lms-2026-08`,
//!   d'où `202608` ; la même page avertit que 202508 est éteinte le 2026-08-17.

use agentos_providers::Secret;
use async_trait::async_trait;
use serde_json::json;

use super::{
    Apercu, ApercuMedia, ErreurMessagerie, ErreurPlateforme, MediaPret, Metriques, Plateforme,
    Publication, Sondage, TypeMedia, empreinte_globale, http, http_upload,
};

/// <https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/posts-api>,
/// relevé le 2026-09-02.
pub const POINT_PUBLICATION: &str = "https://api.linkedin.com/rest/posts";
/// images-api, relevé le 2026-09-02.
pub const POINT_INIT_IMAGE: &str = "https://api.linkedin.com/rest/images?action=initializeUpload";
/// videos-api, relevé le 2026-09-02.
pub const POINT_INIT_VIDEO: &str = "https://api.linkedin.com/rest/videos?action=initializeUpload";
pub const POINT_FINALIZE_VIDEO: &str = "https://api.linkedin.com/rest/videos?action=finalizeUpload";
/// documents-api, relevé le 2026-09-02.
pub const POINT_INIT_DOCUMENT: &str =
    "https://api.linkedin.com/rest/documents?action=initializeUpload";

/// Le moniker par défaut de la doc au 2026-09-02 (`li-lms-2026-08`). Une
/// constante et pas une chaîne en ligne : quand LinkedIn éteindra cette
/// version, il y aura UN endroit à bumper, et le test d'en-têtes à mettre à jour
/// avec lui.
pub const VERSION_LINKEDIN: &str = "202608";

/// « All APIs require the request header `X-Restli-Protocol-Version: 2.0.0` ».
pub const PROTOCOLE_RESTLI: &str = "2.0.0";

/// « 1 image ou 2–20 » (multiimage-post-api, relevé le 2026-09-02).
pub const IMAGES_MAX: usize = 20;
/// altText ≤ 4086 (images-api, relevé le 2026-09-02 ; recommandé < 120).
pub const ALT_TEXT_MAX: usize = 4086;
/// « 75 KB » min vidéo — l'unité n'est pas définie, on prend la lecture
/// binaire (76 800 octets), la plus stricte pour un minimum.
pub const OCTETS_MIN_VIDEO: u64 = 75 * 1024;
/// « 500 MB » max vidéo feed (le schéma dit 5 GB ; on prend la borne feed
/// sûre) — lecture décimale, la plus stricte pour un maximum.
pub const OCTETS_MAX_VIDEO: u64 = 500_000_000;
/// « 100 MB » max document (documents-api, relevé le 2026-09-02) — lecture
/// décimale, la plus stricte pour un maximum.
pub const OCTETS_MAX_DOCUMENT: u64 = 100_000_000;
/// Sondage : question ≤ 140, options ≤ 30 caractères (posts-api, relevé le
/// 2026-09-02).
pub const SONDAGE_QUESTION_MAX: usize = 140;
pub const SONDAGE_OPTION_MAX: usize = 30;

/// ponytail: polling AVAILABLE toutes les 5 s sous un budget de 5 min —
/// LinkedIn ne publie pas de `check_after_secs` ; si les transcodages réels
/// débordent, remonter le budget.
pub const BUDGET_TRAITEMENT_SECS: u64 = 300;
pub const PAS_DE_POLLING_SECS: u64 = 5;

/// Les quatre durées que LinkedIn sert, et pas une de plus (posts-api, poll
/// content, relevé le 2026-09-02). Toute autre valeur est refusée en citant
/// les quatre.
pub fn duree_sondage(minutes: u32) -> Option<&'static str> {
    match minutes {
        1440 => Some("ONE_DAY"),
        4320 => Some("THREE_DAYS"),
        10080 => Some("SEVEN_DAYS"),
        20160 => Some("FOURTEEN_DAYS"),
        _ => None,
    }
}

/// Les deux en-têtes versionnés, sortis en fonction pour que le test compare
/// exactement ce que `publier` enverra — pas une copie qui divergerait.
pub fn entetes_versionnees() -> [(&'static str, &'static str); 2] {
    [
        ("LinkedIn-Version", VERSION_LINKEDIN),
        ("X-Restli-Protocol-Version", PROTOCOLE_RESTLI),
    ]
}

/// Le corps d'un post de membre — la fixture « Text-Only Post Creation Sample
/// Request » de la doc, l'auteur organisation remplacé par l'URN de personne
/// que `w_member_social` autorise. `content` s'ajoute seulement quand le post
/// en porte un : un post texte reste identique à l'octet près.
pub fn corps_de_publication(
    auteur: &str,
    texte: &str,
    contenu: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut corps = json!({
        "author": auteur,
        "commentary": texte,
        "visibility": "PUBLIC",
        "distribution": {
            "feedDistribution": "MAIN_FEED",
            "targetEntities": [],
            "thirdPartyDistributionChannels": []
        },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": false
    });
    if let Some(c) = contenu {
        corps["content"] = c;
    }
    corps
}

/// `{initializeUploadRequest: {owner}}` — images-api et documents-api ont la
/// même forme (relevé le 2026-09-02).
pub fn corps_initialize_simple(owner: &str) -> serde_json::Value {
    json!({ "initializeUploadRequest": { "owner": owner } })
}

/// videos-api, relevé le 2026-09-02 : ni sous-titres ni miniature en v1.
pub fn corps_initialize_video(owner: &str, taille: u64) -> serde_json::Value {
    json!({
        "initializeUploadRequest": {
            "owner": owner,
            "fileSizeBytes": taille,
            "uploadCaptions": false,
            "uploadThumbnail": false
        }
    })
}

/// `{video, uploadToken: "", uploadedPartIds: [etags DANS L'ORDRE]}` —
/// videos-api, relevé le 2026-09-02.
pub fn corps_finalize_video(urn: &str, etags: &[String]) -> serde_json::Value {
    json!({
        "finalizeUploadRequest": {
            "video": urn,
            "uploadToken": "",
            "uploadedPartIds": etags
        }
    })
}

/// Les cinq formes de `content` (posts-api, relevé le 2026-09-02) — des
/// ALTERNATIVES, jamais combinées.
pub fn contenu_image(urn: &str, alt_text: Option<&str>) -> serde_json::Value {
    let mut media = json!({ "id": urn });
    if let Some(alt) = alt_text {
        media["altText"] = json!(alt);
    }
    json!({ "media": media })
}

pub fn contenu_multi_images(images: &[(String, Option<String>)]) -> serde_json::Value {
    json!({
        "multiImage": {
            "images": images
                .iter()
                .map(|(urn, alt)| {
                    let mut image = json!({ "id": urn });
                    if let Some(alt) = alt {
                        image["altText"] = json!(alt);
                    }
                    image
                })
                .collect::<Vec<_>>()
        }
    })
}

pub fn contenu_video(urn: &str, title: Option<&str>) -> serde_json::Value {
    let mut media = json!({ "id": urn });
    if let Some(t) = title {
        media["title"] = json!(t);
    }
    json!({ "media": media })
}

pub fn contenu_document(urn: &str, title: Option<&str>) -> serde_json::Value {
    // Même forme que la vidéo : `{media: {id, title}}`.
    contenu_video(urn, title)
}

pub fn contenu_sondage(s: &Sondage) -> serde_json::Value {
    json!({
        "poll": {
            "question": s.question.as_deref().unwrap_or(""),
            "options": s.options.iter().map(|o| json!({ "text": o })).collect::<Vec<_>>(),
            "settings": {
                "duration": duree_sondage(s.duration_minutes)
                    .expect("l'aperçu refuse les durées hors des quatre valeurs avant publier (C7)")
            }
        }
    })
}

/// Lit `{value: {uploadUrl, image|document}}` d'un initializeUpload simple.
/// Le corps n'entre jamais dans l'erreur.
pub fn init_simple_depuis(
    statut: u16,
    corps: &[u8],
    champ_urn: &str,
) -> Result<(String, String), ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let lire = |champ: &str| {
        document
            .pointer(&format!("/value/{champ}"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(ErreurPlateforme::Illisible)
    };
    Ok((lire("uploadUrl")?, lire(champ_urn)?))
}

/// Une plage d'upload vidéo, telle que `uploadInstructions` la fournit — on
/// SUIT les instructions, on ne recalcule pas les plages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionPart {
    pub upload_url: String,
    pub first_byte: u64,
    pub last_byte: u64,
}

/// Lit `{value: {video, uploadInstructions: [{uploadUrl, firstByte, lastByte}]}}`.
pub fn init_video_depuis(
    statut: u16,
    corps: &[u8],
) -> Result<(String, Vec<InstructionPart>), ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    let urn = document
        .pointer("/value/video")
        .and_then(|v| v.as_str())
        .ok_or(ErreurPlateforme::Illisible)?
        .to_owned();
    let instructions = document
        .pointer("/value/uploadInstructions")
        .and_then(|v| v.as_array())
        .ok_or(ErreurPlateforme::Illisible)?
        .iter()
        .map(|i| {
            Ok(InstructionPart {
                upload_url: i
                    .get("uploadUrl")
                    .and_then(|v| v.as_str())
                    .ok_or(ErreurPlateforme::Illisible)?
                    .to_owned(),
                first_byte: i
                    .get("firstByte")
                    .and_then(|v| v.as_u64())
                    .ok_or(ErreurPlateforme::Illisible)?,
                last_byte: i
                    .get("lastByte")
                    .and_then(|v| v.as_u64())
                    .ok_or(ErreurPlateforme::Illisible)?,
            })
        })
        .collect::<Result<Vec<_>, ErreurPlateforme>>()?;
    Ok((urn, instructions))
}

/// Lit le `status` d'un `GET /rest/videos/{urn}` ou `/rest/documents/{urn}`.
pub fn statut_ressource_depuis(statut: u16, corps: &[u8]) -> Result<String, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let document: serde_json::Value =
        serde_json::from_slice(corps).map_err(|_| ErreurPlateforme::Illisible)?;
    document
        .get("status")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(ErreurPlateforme::Illisible)
}

/// Un URN dans un chemin Rest.li s'encode : les `:` deviennent `%3A`
/// (protocole 2.0.0).
pub fn urn_dans_chemin(urn: &str) -> String {
    urn.replace(':', "%3A")
}

/// Lit la réponse de création : le post est dans l'en-tête `x-restli-id`, pas
/// dans le corps. Un refus est une erreur nommée, jamais une [`Publication`].
pub fn publication_depuis(
    statut: u16,
    restli_id: Option<&str>,
) -> Result<Publication, ErreurPlateforme> {
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(erreur);
    }
    let urn = restli_id.ok_or(ErreurPlateforme::Illisible)?;
    Ok(Publication {
        id_plateforme: urn.to_owned(),
        // « an authorized member can view the post using the follow URL
        // structure: https://www.linkedin.com/feed/update/urn:li:ugcPost:<id>/ »
        url: format!("https://www.linkedin.com/feed/update/{urn}/"),
    })
}

/// Le verdict d'UN média, mots exacts et chiffres cités.
fn apercu_media(m: &MediaPret) -> ApercuMedia {
    let taille = m.octets.len() as u64;
    let mut verdicts = Vec::new();
    let mut ok = true;
    match m.type_detecte {
        TypeMedia::Webp => {
            ok = false;
            verdicts.push(
                "linkedin ne sert pas image/webp (formats image : JPG, GIF, PNG — \
                 images-api, relevé le 2026-09-02)"
                    .to_owned(),
            );
        }
        TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Gif => {
            // AUCUNE limite d'octets publiée pour les images : le plafond
            // 512 MiB du téléchargeur (C5) reste le seul garde-fou, et c'est
            // le nôtre, pas celui de LinkedIn.
            // ponytail: pixels < 36 152 320 et GIF ≤ 250 frames ne se
            // vérifient pas aux octets sans parseur — la plateforme tranchera.
            if let Some(alt) = &m.alt_text {
                let n = alt.chars().count();
                if n > ALT_TEXT_MAX {
                    ok = false;
                    verdicts.push(format!("altText 4086 caractères max, reçu {n}"));
                }
            }
            if m.title.is_some() {
                ok = false;
                verdicts.push(
                    "le contenu image LinkedIn porte altText, pas de title \
                     (posts-api, relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
        }
        TypeMedia::Mp4 => {
            if taille < OCTETS_MIN_VIDEO {
                ok = false;
                verdicts.push(format!("75 KB min pour une vidéo, reçu {taille} octets"));
            }
            if taille > OCTETS_MAX_VIDEO {
                ok = false;
                verdicts.push(format!(
                    "500 MB max pour une vidéo feed (le schéma dit 5 GB — on prend la \
                     borne feed sûre), reçu {taille} octets"
                ));
            }
            if m.alt_text.is_some() {
                ok = false;
                verdicts.push(
                    "le contenu vidéo LinkedIn porte un title, pas d'altText \
                     (posts-api, relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
        }
        TypeMedia::Pdf => {
            // ponytail: PDF seul en v1 — PPT/PPTX/DOC/DOCX ont des magic
            // bytes OLE/zip ambigus ; pour les servir, apprendre au
            // téléchargeur à lever l'ambiguïté d'abord. ≤ 300 pages non
            // vérifiable aux octets : la plateforme tranchera.
            if taille > OCTETS_MAX_DOCUMENT {
                ok = false;
                verdicts.push(format!("100 MB max pour un document, reçu {taille} octets"));
            }
            if m.alt_text.is_some() {
                ok = false;
                verdicts.push(
                    "le contenu document LinkedIn porte un title, pas d'altText \
                     (posts-api, relevé le 2026-09-02)"
                        .to_owned(),
                );
            }
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

pub struct Linkedin;

impl Linkedin {
    /// Une requête POST JSON avec Bearer + les deux en-têtes versionnés.
    fn poste_json(
        &self,
        jeton: &Secret,
        url: &str,
        corps: &serde_json::Value,
    ) -> reqwest::RequestBuilder {
        let mut requete = http().post(url).bearer_auth(jeton.expose_for_transport());
        for (nom, valeur) in entetes_versionnees() {
            requete = requete.header(nom, valeur);
        }
        requete.json(corps)
    }

    /// Image ou document : initializeUpload → PUT AVEC Bearer (dixit la page
    /// Assets : l'upload image/document porte l'OAuth, l'upload vidéo non).
    async fn televerser_simple(
        &self,
        jeton: &Secret,
        owner: &str,
        point_init: &str,
        champ_urn: &str,
        octets: &[u8],
    ) -> Result<String, ErreurPlateforme> {
        let reponse = self
            .poste_json(jeton, point_init, &corps_initialize_simple(owner))
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let (upload_url, urn) = init_simple_depuis(statut, &corps, champ_urn)?;
        let reponse = http_upload()
            .put(&upload_url)
            .bearer_auth(jeton.expose_for_transport())
            .header("Content-Type", "application/octet-stream")
            .body(octets.to_vec())
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(reponse.status().as_u16()) {
            return Err(erreur);
        }
        Ok(urn)
    }

    /// Poller un GET jusqu'à AVAILABLE, sous budget.
    ///
    /// ponytail: la restriction « write-only avec w_member_social » n'est
    /// écrite QUE pour les images — si le GET vidéo/document est refusé au
    /// jeton membre à l'exécution, le refus sort nommé (Refus{statut}) au
    /// lieu d'être présumé ; à vérifier sur un vrai compte.
    async fn attendre_disponible(&self, jeton: &Secret, url: &str) -> Result<(), ErreurPlateforme> {
        let mut budget = BUDGET_TRAITEMENT_SECS;
        loop {
            let mut requete = http().get(url).bearer_auth(jeton.expose_for_transport());
            for (nom, valeur) in entetes_versionnees() {
                requete = requete.header(nom, valeur);
            }
            let reponse = requete
                .send()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            let statut = reponse.status().as_u16();
            let corps = reponse
                .bytes()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            match statut_ressource_depuis(statut, &corps)?.as_str() {
                "AVAILABLE" => return Ok(()),
                // La plateforme a mangé les octets puis dit non : pas de corps
                // dans l'erreur, et un rejeu reste sensé — même coupe que le
                // `failed` de X.
                "PROCESSING_FAILED" => return Err(ErreurPlateforme::Injoignable),
                // WAITING_UPLOAD / PROCESSING : on attend.
                _ => {
                    if budget < PAS_DE_POLLING_SECS {
                        return Err(ErreurPlateforme::Injoignable);
                    }
                    budget -= PAS_DE_POLLING_SECS;
                    tokio::time::sleep(std::time::Duration::from_secs(PAS_DE_POLLING_SECS)).await;
                }
            }
        }
    }

    /// La vidéo : initialize → PUT chaque part selon `uploadInstructions`
    /// (SANS Authorization, ETag relevé) → finalize → AVAILABLE.
    async fn televerser_video(
        &self,
        jeton: &Secret,
        owner: &str,
        m: &MediaPret,
    ) -> Result<String, ErreurPlateforme> {
        let reponse = self
            .poste_json(
                jeton,
                POINT_INIT_VIDEO,
                &corps_initialize_video(owner, m.octets.len() as u64),
            )
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let corps = reponse
            .bytes()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let (urn, instructions) = init_video_depuis(statut, &corps)?;

        let mut etags = Vec::with_capacity(instructions.len());
        for part in &instructions {
            // Des plages hors du fichier = des instructions illisibles, pas
            // un upload à moitié.
            let tranche = m
                .octets
                .get(part.first_byte as usize..=part.last_byte as usize)
                .ok_or(ErreurPlateforme::Illisible)?;
            // SANS Authorization : la page Assets le dit explicitement pour
            // l'upload vidéo (l'URL signée EST l'autorisation).
            let reponse = http_upload()
                .put(&part.upload_url)
                .header("Content-Type", "application/octet-stream")
                .body(tranche.to_vec())
                .send()
                .await
                .map_err(|_| ErreurPlateforme::Injoignable)?;
            let statut = reponse.status().as_u16();
            let etag = reponse
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
                return Err(erreur);
            }
            // Un ETag n'est pas un secret, mais sans lui le finalize est
            // impossible : réponse illisible.
            etags.push(etag.ok_or(ErreurPlateforme::Illisible)?);
        }

        let reponse = self
            .poste_json(
                jeton,
                POINT_FINALIZE_VIDEO,
                &corps_finalize_video(&urn, &etags),
            )
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        if let Some(erreur) = ErreurPlateforme::depuis_statut(reponse.status().as_u16()) {
            return Err(erreur);
        }

        let url = format!(
            "https://api.linkedin.com/rest/videos/{}",
            urn_dans_chemin(&urn)
        );
        self.attendre_disponible(jeton, &url).await?;
        Ok(urn)
    }

    /// Téléverse les médias et rend la forme `content` du post.
    async fn televerser_et_contenu(
        &self,
        jeton: &Secret,
        owner: &str,
        medias: &[MediaPret],
    ) -> Result<serde_json::Value, ErreurPlateforme> {
        match medias[0].type_detecte {
            TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Gif => {
                let mut images = Vec::with_capacity(medias.len());
                for m in medias {
                    let urn = self
                        .televerser_simple(jeton, owner, POINT_INIT_IMAGE, "image", &m.octets)
                        .await?;
                    images.push((urn, m.alt_text.clone()));
                }
                Ok(if images.len() == 1 {
                    contenu_image(&images[0].0, images[0].1.as_deref())
                } else {
                    contenu_multi_images(&images)
                })
            }
            TypeMedia::Mp4 => {
                let m = &medias[0];
                let urn = self.televerser_video(jeton, owner, m).await?;
                Ok(contenu_video(&urn, m.title.as_deref()))
            }
            TypeMedia::Pdf => {
                let m = &medias[0];
                let urn = self
                    .televerser_simple(jeton, owner, POINT_INIT_DOCUMENT, "document", &m.octets)
                    .await?;
                let url = format!(
                    "https://api.linkedin.com/rest/documents/{}",
                    urn_dans_chemin(&urn)
                );
                self.attendre_disponible(jeton, &url).await?;
                Ok(contenu_document(&urn, m.title.as_deref()))
            }
            // Jamais atteint : C7 passe l'aperçu (qui refuse le WEBP) avant
            // publier. Si un appelant contourne, refus local plutôt qu'un
            // octet vers LinkedIn — le statut 400 est le nôtre.
            TypeMedia::Webp => Err(ErreurPlateforme::Refus { statut: 400 }),
        }
    }
}

#[async_trait]
impl Plateforme for Linkedin {
    fn nom(&self) -> &'static str {
        "linkedin"
    }

    fn apercu(
        &self,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
    ) -> Apercu {
        let mut verdicts = Vec::new();

        if made_with_ai {
            verdicts.push(
                "linkedin ne sert pas made_with_ai (champ de POST /2/tweets — X seulement)"
                    .to_owned(),
            );
        }

        let images = medias
            .iter()
            .filter(|m| {
                matches!(
                    m.type_detecte,
                    TypeMedia::Jpeg | TypeMedia::Png | TypeMedia::Gif | TypeMedia::Webp
                )
            })
            .count();
        let videos = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Mp4)
            .count();
        let documents = medias
            .iter()
            .filter(|m| m.type_detecte == TypeMedia::Pdf)
            .count();
        if images > IMAGES_MAX {
            verdicts.push(format!("20 images max (multiImage), reçu {images}"));
        }
        if videos > 1 {
            verdicts.push(format!("1 seule vidéo par post, reçu {videos}"));
        }
        if documents > 1 {
            verdicts.push(format!("1 seul document par post, reçu {documents}"));
        }
        if [images > 0, videos > 0, documents > 0]
            .iter()
            .filter(|&&b| b)
            .count()
            > 1
        {
            // Les formes de `content` sont des alternatives : media OU
            // multiImage OU poll — jamais combinées.
            verdicts.push(
                "pas de mélange : image(s) OU 1 vidéo OU 1 document (les formes de \
                 content sont des alternatives)"
                    .to_owned(),
            );
        }

        if let Some(s) = sondage {
            if !medias.is_empty() {
                verdicts.push(
                    "sondage exclusif de tout média (les formes de content sont des \
                     alternatives)"
                        .to_owned(),
                );
            }
            match &s.question {
                None => verdicts.push("question obligatoire pour un sondage LinkedIn".to_owned()),
                Some(q) => {
                    let n = q.chars().count();
                    if n > SONDAGE_QUESTION_MAX {
                        verdicts.push(format!("question 140 caractères max, reçu {n}"));
                    }
                }
            }
            if !(2..=4).contains(&s.options.len()) {
                verdicts.push(format!(
                    "2 à 4 options de sondage, reçu {}",
                    s.options.len()
                ));
            }
            for option in &s.options {
                let n = option.chars().count();
                if n > SONDAGE_OPTION_MAX {
                    verdicts.push(format!(
                        "options de sondage de 30 caractères max, « {option} » en fait {n}"
                    ));
                }
            }
            if duree_sondage(s.duration_minutes).is_none() {
                verdicts.push(format!(
                    "durée de sondage ∈ {{1440, 4320, 10080, 20160}} minutes \
                     (ONE_DAY, THREE_DAYS, SEVEN_DAYS, FOURTEEN_DAYS), reçu {}",
                    s.duration_minutes
                ));
            }
        }

        let media: Vec<ApercuMedia> = medias.iter().map(apercu_media).collect();
        Apercu {
            rendered_text: texte.to_owned(),
            digest: empreinte_globale(texte, medias, sondage, made_with_ai),
            // La doc nomme les refus `INVALID_VALUE_BLANK_FIELD` et
            // `FIELD_LENGTH_TOO_LONG` mais ne publie AUCUN nombre pour
            // `commentary` (vérifié dans posts-api et post-api-schema le
            // 2026-09-02). On vérifie donc ce qui est documenté — pas vide —
            // et rien d'inventé.
            platform_limits_ok: !texte.trim().is_empty()
                && verdicts.is_empty()
                && media.iter().all(|m| m.limits_ok),
            // LinkedIn ne facture pas la création d'un post : `None`, pas 0.0 —
            // zéro affirmerait un tarif, None dit qu'il n'y a pas de compteur.
            cost_estimate_usd: None,
            media,
            verdicts,
        }
    }

    /// `handle` EST l'URN d'auteur (`urn:li:person:{id}`) : le flux de
    /// connexion range l'identité que `GET /v2/userinfo` a rendue — c'est la
    /// seule que `w_member_social` connaisse, c'est le champ `author` que le
    /// schéma exige, et « the caller must match the owner » des uploads.
    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        _made_with_ai: bool,
    ) -> Result<Publication, ErreurPlateforme> {
        // made_with_ai : refusé par l'aperçu (C7 le passe avant publier) —
        // ignoré ici serait un mensonge, mais il ne peut pas arriver vrai.
        let contenu = if let Some(s) = sondage {
            Some(contenu_sondage(s))
        } else if medias.is_empty() {
            None
        } else {
            Some(self.televerser_et_contenu(jeton, handle, medias).await?)
        };
        let reponse = self
            .poste_json(
                jeton,
                POINT_PUBLICATION,
                &corps_de_publication(handle, texte, contenu),
            )
            .send()
            .await
            .map_err(|_| ErreurPlateforme::Injoignable)?;
        let statut = reponse.status().as_u16();
        let restli_id = reponse
            .headers()
            .get("x-restli-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        publication_depuis(statut, restli_id.as_deref())
    }

    /// `Ok(None)`, et c'est un fait documenté, pas une paresse : lire les posts
    /// d'un membre demande `r_member_social`, que la doc marque « restricted…
    /// available to approved users only » (table Permissions de posts-api,
    /// relevé le 2026-09-02) — la sonde du 2026-09-02 l'avait établi. Rendre
    /// des zéros à la place serait un mensonge de plus que ne rien rendre :
    /// un agent lirait « 0 impressions » et conclurait que le post est mort,
    /// alors que la vérité est « personne n'a le droit de compter ».
    async fn metriques(
        &self,
        _jeton: &Secret,
        _id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// La messagerie : LinkedIn ne sert RIEN de cette table à un membre self-serve
// aujourd'hui. LinkedIn n'implémente donc PAS `PlateformeMessagerie` —
// l'absence d'implémentation EST le refus, et le dispatcher du cœur rend
// `refus_messagerie(outil)` : un fait cité et daté, jamais un stub silencieux.
// Sondes du 2026-09-02, figées dans le plan.
// ---------------------------------------------------------------------------

/// Le refus LinkedIn pour UN outil de la table messagerie — citation datée +
/// le fait qui débloquerait. `None` pour un nom d'outil inconnu (au cœur de
/// dire « outil inexistant », pas à nous d'inventer un refus).
///
/// Les entrées CONDITIONNELLES (comment, like, timeline) portent le fait
/// exact : le jour où la candidature Community Management du fondateur est
/// approuvée, l'implémentation arrive et cette table rétrécit — SANS bump de
/// la table d'outils (les outils existaient déjà, seul l'adaptateur change).
pub fn refus_messagerie(outil: &str) -> Option<ErreurMessagerie> {
    let (citation, deblocage): (&'static str, &'static str) = match outil {
        "inbox_list" => (
            "« aucun endpoint feed ni notifications membre documenté » (index \
             learn.microsoft.com, 198 docs LinkedIn, relevé le 2026-09-02)",
            "le scope r_member_social_feed, « select developers only », via le \
             Developer Support Portal",
        ),
        "dm_reply" => (
            "POST /v2/messages est « restricted to approved partners, subject to \
             limitations via API agreement » (learn.microsoft.com, page NOINDEX, \
             ms.date 2019-11-20, consultée le 2026-09-02)",
            "un accord partenaire ad hoc via le Developer Support Portal",
        ),
        "dm_open" => (
            // Doublement fermé : l'accès, ET les règles produit même approuvé.
            "accès « restricted to approved partners », ET même approuvé « chaque \
             message doit être une action membre explicite, pas d'événement \
             automatisé ou planifié, 1er degré uniquement » (learn.microsoft.com, \
             page messages NOINDEX, consultée le 2026-09-02)",
            "rien — le DM froid automatisé est interdit par l'accès ET par les \
             règles produit ; aucun fait ne le débloque pour un agent",
        ),
        "post_reply" => (
            "pour un membre self-serve, la page Share on LinkedIn ne documente que \
             POST /v2/ugcPosts, et la page Comments API ne liste pas \
             w_member_social (relevé le 2026-09-02)",
            "le Community Management API — le même chemin que post_comment",
        ),
        "post_comment" => (
            "POST /rest/socialActions/{urn}/comments exige w_member_social_feed, \
             délivré uniquement par le Community Management API sur candidature \
             (palier Development : 500 appels/app/24 h, 100/membre/24 h — \
             learn.microsoft.com/increasing-access, ms.date 2026-07-28, consulté \
             le 2026-09-02)",
            "la candidature Community Management API du fondateur approuvée",
        ),
        "post_like" | "post_unlike" => (
            "POST /rest/reactions?actor= exige w_member_social_feed, délivré \
             uniquement par le Community Management API sur candidature (relevé le \
             2026-09-02)",
            "la candidature Community Management API du fondateur approuvée",
        ),
        "post_bookmark" | "post_unbookmark" => (
            "« aucune API de bookmarks/saved items n'existe dans la doc » \
             (getting-access + index learn.microsoft.com, relevés le 2026-09-02)",
            "rien — l'API n'existe pas",
        ),
        "post_repost" | "post_quote" => (
            "aucun endpoint de reshare membre documenté (sondes de l'index \
             learn.microsoft.com, relevées le 2026-09-02)",
            "rien de documenté",
        ),
        "search_posts" => (
            "« aucune API de recherche n'apparaît dans getting-access ni dans \
             l'index learn.microsoft.com ; zéro people-search API » (relevé le \
             2026-09-02)",
            "rien de générique — SNAP ne donne que r_sales_nav_* en \
             display/validation",
        ),
        "read_post" => (
            "les posts d'autrui ne se lisent pas, et ses propres posts exigent \
             r_member_social « restricted, approved users only » (Posts API, \
             ms.date 2026-05-07, consulté le 2026-09-02)",
            "r_member_social accordé (approved users only) — et seulement pour \
             SES propres posts",
        ),
        "read_profile" => (
            "aucune API de lecture de profil tiers pour un membre (relevé le \
             2026-09-02)",
            "rien de documenté",
        ),
        "read_timeline" => (
            "uniquement SES posts, via GET /rest/posts?q=author sous \
             r_member_social « restricted » (relevé le 2026-09-02)",
            "r_member_social accordé — et la timeline reste limitée à SES posts",
        ),
        _ => return None,
    };
    Some(ErreurMessagerie::NeSertPas {
        citation,
        deblocage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::test_medias::media;

    fn avec_alt(mut m: MediaPret, alt: &str) -> MediaPret {
        m.alt_text = Some(alt.to_owned());
        m
    }

    fn avec_titre(mut m: MediaPret, titre: &str) -> MediaPret {
        m.title = Some(titre.to_owned());
        m
    }

    /// Champ pour champ, la fixture « Text-Only Post Creation Sample Request »
    /// de la doc (posts-api, relevé le 2026-09-02), auteur membre. AUCUN champ
    /// `content` sur un post texte.
    #[test]
    fn le_corps_est_celui_de_la_doc() {
        assert_eq!(
            corps_de_publication("urn:li:person:5abc_dEfgH", "Sample text Post", None),
            json!({
                "author": "urn:li:person:5abc_dEfgH",
                "commentary": "Sample text Post",
                "visibility": "PUBLIC",
                "distribution": {
                    "feedDistribution": "MAIN_FEED",
                    "targetEntities": [],
                    "thirdPartyDistributionChannels": []
                },
                "lifecycleState": "PUBLISHED",
                "isReshareDisabledByAuthor": false
            })
        );
    }

    /// initializeUpload : images-api / videos-api / documents-api, relevés le
    /// 2026-09-02.
    #[test]
    fn les_corps_initialize_sont_ceux_des_docs() {
        assert_eq!(
            corps_initialize_simple("urn:li:person:5abc_dEfgH"),
            json!({ "initializeUploadRequest": { "owner": "urn:li:person:5abc_dEfgH" } })
        );
        assert_eq!(
            corps_initialize_video("urn:li:person:5abc_dEfgH", 20_000_000),
            json!({
                "initializeUploadRequest": {
                    "owner": "urn:li:person:5abc_dEfgH",
                    "fileSizeBytes": 20_000_000,
                    "uploadCaptions": false,
                    "uploadThumbnail": false
                }
            })
        );
    }

    /// finalizeUpload : `{video, uploadToken: "", uploadedPartIds}` — les
    /// ETags DANS L'ORDRE des parts (videos-api, relevé le 2026-09-02).
    #[test]
    fn le_corps_finalize_garde_les_etags_dans_l_ordre() {
        assert_eq!(
            corps_finalize_video(
                "urn:li:video:C5F10AQGKQg_6y2a4sQ",
                &["etag-part-1".to_owned(), "etag-part-2".to_owned()]
            ),
            json!({
                "finalizeUploadRequest": {
                    "video": "urn:li:video:C5F10AQGKQg_6y2a4sQ",
                    "uploadToken": "",
                    "uploadedPartIds": ["etag-part-1", "etag-part-2"]
                }
            })
        );
    }

    /// Les cinq formes de `content` (posts-api, relevé le 2026-09-02).
    #[test]
    fn les_cinq_formes_de_contenu_sont_celles_de_la_doc() {
        assert_eq!(
            contenu_image("urn:li:image:C5F10AQGKQg_6y2a4sQ", Some("Un chat")),
            json!({ "media": { "id": "urn:li:image:C5F10AQGKQg_6y2a4sQ", "altText": "Un chat" } })
        );
        // Sans alt_text, pas de champ altText — un champ vide et un champ
        // absent ne sont pas la même requête.
        assert_eq!(
            contenu_image("urn:li:image:A", None),
            json!({ "media": { "id": "urn:li:image:A" } })
        );
        assert_eq!(
            contenu_multi_images(&[
                ("urn:li:image:A".to_owned(), Some("alt A".to_owned())),
                ("urn:li:image:B".to_owned(), None),
            ]),
            json!({
                "multiImage": {
                    "images": [
                        { "id": "urn:li:image:A", "altText": "alt A" },
                        { "id": "urn:li:image:B" }
                    ]
                }
            })
        );
        assert_eq!(
            contenu_video("urn:li:video:V", Some("Ma vidéo")),
            json!({ "media": { "id": "urn:li:video:V", "title": "Ma vidéo" } })
        );
        assert_eq!(
            contenu_document("urn:li:document:D", Some("Mon PDF")),
            json!({ "media": { "id": "urn:li:document:D", "title": "Mon PDF" } })
        );
        let sondage = Sondage {
            question: Some("Votre avis ?".to_owned()),
            options: vec!["oui".to_owned(), "non".to_owned()],
            duration_minutes: 10080,
        };
        assert_eq!(
            contenu_sondage(&sondage),
            json!({
                "poll": {
                    "question": "Votre avis ?",
                    "options": [{ "text": "oui" }, { "text": "non" }],
                    "settings": { "duration": "SEVEN_DAYS" }
                }
            })
        );
        // Et le tout s'accroche sous `content`.
        let corps = corps_de_publication(
            "urn:li:person:X",
            "t",
            Some(contenu_image("urn:li:image:A", None)),
        );
        assert_eq!(
            corps["content"],
            json!({ "media": { "id": "urn:li:image:A" } })
        );
    }

    #[test]
    fn les_reponses_initialize_se_lisent_comme_les_docs() {
        let corps = br#"{"value":{"uploadUrlExpiresAt":1650567510704,"uploadUrl":"https://www.linkedin.com/dms-uploads/C4E10AQ","image":"urn:li:image:C4E10AQ"}}"#;
        let (upload_url, urn) = init_simple_depuis(200, corps, "image").expect("forme documentée");
        assert_eq!(upload_url, "https://www.linkedin.com/dms-uploads/C4E10AQ");
        assert_eq!(urn, "urn:li:image:C4E10AQ");
        // Le même lecteur sert les documents.
        let corps =
            br#"{"value":{"uploadUrl":"https://u.example","document":"urn:li:document:D1"}}"#;
        assert_eq!(
            init_simple_depuis(200, corps, "document")
                .expect("forme documentée")
                .1,
            "urn:li:document:D1"
        );

        let corps = br#"{"value":{"uploadUrlsExpireAt":1657111025000,"video":"urn:li:video:C5F10AQGKQg","uploadInstructions":[{"uploadUrl":"https://part1.example","lastByte":4194303,"firstByte":0},{"uploadUrl":"https://part2.example","lastByte":5242879,"firstByte":4194304}],"uploadToken":""}}"#;
        let (urn, instructions) = init_video_depuis(200, corps).expect("forme documentée");
        assert_eq!(urn, "urn:li:video:C5F10AQGKQg");
        assert_eq!(
            instructions,
            vec![
                InstructionPart {
                    upload_url: "https://part1.example".to_owned(),
                    first_byte: 0,
                    last_byte: 4_194_303
                },
                InstructionPart {
                    upload_url: "https://part2.example".to_owned(),
                    first_byte: 4_194_304,
                    last_byte: 5_242_879
                },
            ]
        );

        // Aucun corps hostile ne traverse vers l'erreur.
        let hostile = br#"{"message":"Bearer JETON-SECRET refuse"}"#;
        for statut in [400, 401, 403] {
            let erreur = init_video_depuis(statut, hostile).expect_err("pas un upload");
            assert!(!format!("{erreur} / {erreur:?}").contains("JETON-SECRET"));
        }
    }

    #[test]
    fn le_statut_d_une_ressource_se_lit_et_l_urn_s_encode() {
        assert_eq!(
            statut_ressource_depuis(200, br#"{"status":"AVAILABLE","owner":"urn:li:person:X"}"#)
                .expect("forme documentée"),
            "AVAILABLE"
        );
        assert_eq!(
            urn_dans_chemin("urn:li:video:C5F10AQGKQg"),
            "urn%3Ali%3Avideo%3AC5F10AQGKQg"
        );
    }

    #[test]
    fn les_entetes_portent_la_version_et_le_protocole() {
        assert_eq!(
            entetes_versionnees(),
            [
                ("LinkedIn-Version", "202608"),
                ("X-Restli-Protocol-Version", "2.0.0"),
            ]
        );
    }

    #[test]
    fn un_refus_ne_devient_jamais_une_publication() {
        for statut in [400, 401, 403, 422, 429, 503] {
            publication_depuis(statut, Some("urn:li:share:1"))
                .expect_err("un non-2xx n'est pas un post");
        }
        // Un 201 sans `x-restli-id` n'est pas un post identifiable non plus.
        assert_eq!(
            publication_depuis(201, None),
            Err(ErreurPlateforme::Illisible)
        );
    }

    #[test]
    fn une_creation_reussie_rend_l_urn_et_son_url_publique() {
        let publication = publication_depuis(201, Some("urn:li:share:6844785523593134080"))
            .expect("201 documenté");
        assert_eq!(
            publication.id_plateforme,
            "urn:li:share:6844785523593134080"
        );
        assert_eq!(
            publication.url,
            "https://www.linkedin.com/feed/update/urn:li:share:6844785523593134080/"
        );
    }

    #[tokio::test]
    async fn les_metriques_membre_disent_pas_de_donnees_au_lieu_de_zeros() {
        let resultat = Linkedin
            .metriques(&Secret::new("jeton"), "urn:li:share:1")
            .await
            .expect("l'absence de métriques n'est pas une panne");
        assert!(resultat.is_none(), "des zéros inventés sont un mensonge");
    }

    #[test]
    fn l_apercu_refuse_le_vide_et_n_invente_pas_de_tarif() {
        assert!(!Linkedin.apercu("  ", &[], None, false).platform_limits_ok);
        let apercu = Linkedin.apercu("Bonjour", &[], None, false);
        assert!(apercu.platform_limits_ok);
        assert_eq!(apercu.cost_estimate_usd, None);
        assert_eq!(apercu.rendered_text, "Bonjour");
        assert_eq!(apercu.digest, crate::adapters::empreinte("Bonjour"));
        assert!(apercu.media.is_empty());
    }

    /// Les verdicts médias exigés par le brief : mots exacts, chiffres cités.
    #[test]
    fn les_verdicts_medias_refusent_ce_que_linkedin_refuse() {
        // WEBP → refus nommé.
        let apercu = Linkedin.apercu("t", &[media(b"RIFFxxxxWEBP", TypeMedia::Webp)], None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("ne sert pas image/webp")),
            "{:?}",
            apercu.media[0].verdicts
        );

        // 21 images → « 20 max ». 20 passent.
        let vingt_et_une: Vec<_> = (0..21)
            .map(|i| media(&[i as u8], TypeMedia::Jpeg))
            .collect();
        let apercu = Linkedin.apercu("t", &vingt_et_une, None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("20 images max")),
            "{:?}",
            apercu.verdicts
        );
        assert!(
            Linkedin
                .apercu("t", &vingt_et_une[..20], None, false)
                .platform_limits_ok
        );

        // altText 4087 → refus chiffré ; 4086 passe.
        let apercu = Linkedin.apercu(
            "t",
            &[avec_alt(media(b"i", TypeMedia::Png), &"x".repeat(4087))],
            None,
            false,
        );
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0].verdicts.iter().any(|v| v.contains("4086")),
            "{:?}",
            apercu.media[0].verdicts
        );
        assert!(
            Linkedin
                .apercu(
                    "t",
                    &[avec_alt(media(b"i", TypeMedia::Png), &"x".repeat(4086))],
                    None,
                    false
                )
                .platform_limits_ok
        );

        // Vidéo : sous 75 KB refusée, mélange vidéo+image refusé.
        let apercu = Linkedin.apercu("t", &[media(&[0u8; 1000], TypeMedia::Mp4)], None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("75 KB min")),
            "{:?}",
            apercu.media[0].verdicts
        );
        let mixte = vec![
            media(&vec![0u8; 100_000], TypeMedia::Mp4),
            media(b"i", TypeMedia::Png),
        ];
        let apercu = Linkedin.apercu("t", &mixte, None, false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("pas de mélange")),
            "{:?}",
            apercu.verdicts
        );
        // Une vidéo propre passe, avec un title.
        assert!(
            Linkedin
                .apercu(
                    "t",
                    &[avec_titre(
                        media(&vec![0u8; 100_000], TypeMedia::Mp4),
                        "Ma vidéo"
                    )],
                    None,
                    false
                )
                .platform_limits_ok
        );

        // made_with_ai → X seulement.
        let apercu = Linkedin.apercu("t", &[], None, true);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("made_with_ai")),
            "{:?}",
            apercu.verdicts
        );

        // title sur une image → refus (le contenu image porte altText).
        assert!(
            !Linkedin
                .apercu(
                    "t",
                    &[avec_titre(media(b"i", TypeMedia::Png), "Titre")],
                    None,
                    false
                )
                .platform_limits_ok
        );

        // Un PDF avec title passe ; un PDF de 101 MB non.
        assert!(
            Linkedin
                .apercu(
                    "t",
                    &[avec_titre(media(b"%PDF-", TypeMedia::Pdf), "Mon PDF")],
                    None,
                    false
                )
                .platform_limits_ok
        );
        let apercu = Linkedin.apercu(
            "t",
            &[media(&vec![0u8; 100_000_001], TypeMedia::Pdf)],
            None,
            false,
        );
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.media[0]
                .verdicts
                .iter()
                .any(|v| v.contains("100 MB max")),
            "{:?}",
            apercu.media[0].verdicts
        );
    }

    #[test]
    fn les_verdicts_sondage_suivent_la_doc() {
        let bon = Sondage {
            question: Some("Votre avis ?".to_owned()),
            options: vec!["oui".to_owned(), "non".to_owned()],
            duration_minutes: 1440,
        };
        assert!(
            Linkedin
                .apercu("t", &[], Some(&bon), false)
                .platform_limits_ok
        );

        // Question obligatoire.
        let sans_question = Sondage {
            question: None,
            ..bon.clone()
        };
        let apercu = Linkedin.apercu("t", &[], Some(&sans_question), false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu
                .verdicts
                .iter()
                .any(|v| v.contains("question obligatoire")),
            "{:?}",
            apercu.verdicts
        );

        // Durée 3000 → les QUATRE valeurs citées.
        let hors = Sondage {
            duration_minutes: 3000,
            ..bon.clone()
        };
        let apercu = Linkedin.apercu("t", &[], Some(&hors), false);
        assert!(!apercu.platform_limits_ok);
        let verdict = apercu
            .verdicts
            .iter()
            .find(|v| v.contains("durée"))
            .expect("un verdict de durée");
        for valeur in ["1440", "4320", "10080", "20160"] {
            assert!(verdict.contains(valeur), "{verdict}");
        }

        // Option de 31 caractères.
        let option_longue = Sondage {
            options: vec!["a".repeat(31), "non".to_owned()],
            ..bon.clone()
        };
        assert!(
            !Linkedin
                .apercu("t", &[], Some(&option_longue), false)
                .platform_limits_ok
        );

        // Question de 141 caractères.
        let question_longue = Sondage {
            question: Some("q".repeat(141)),
            ..bon.clone()
        };
        assert!(
            !Linkedin
                .apercu("t", &[], Some(&question_longue), false)
                .platform_limits_ok
        );

        // Sondage + média : les formes de content sont des alternatives.
        let apercu = Linkedin.apercu("t", &[media(b"i", TypeMedia::Png)], Some(&bon), false);
        assert!(!apercu.platform_limits_ok);
        assert!(
            apercu.verdicts.iter().any(|v| v.contains("exclusif")),
            "{:?}",
            apercu.verdicts
        );

        // Les quatre durées servies passent toutes.
        for duree in [1440, 4320, 10080, 20160] {
            let s = Sondage {
                duration_minutes: duree,
                ..bon.clone()
            };
            assert!(
                Linkedin
                    .apercu("t", &[], Some(&s), false)
                    .platform_limits_ok,
                "{duree}"
            );
        }
    }

    #[test]
    fn les_points_d_api_sont_en_https() {
        for point in [
            POINT_PUBLICATION,
            POINT_INIT_IMAGE,
            POINT_INIT_VIDEO,
            POINT_FINALIZE_VIDEO,
            POINT_INIT_DOCUMENT,
        ] {
            assert!(point.starts_with("https://"), "{point}");
        }
    }
}

#[cfg(test)]
mod tests_messagerie {
    use super::*;

    /// La liste FERMÉE des outils de la table messagerie (plan du 2026-09-02).
    const OUTILS: &[&str] = &[
        "inbox_list",
        "dm_reply",
        "dm_open",
        "post_reply",
        "post_comment",
        "post_like",
        "post_unlike",
        "post_bookmark",
        "post_unbookmark",
        "post_repost",
        "post_quote",
        "search_posts",
        "read_post",
        "read_profile",
        "read_timeline",
    ];

    /// Chaque refus est un fait : code stable, citation datée, fait de
    /// déblocage — jamais un stub silencieux.
    #[test]
    fn chaque_outil_de_la_table_a_son_refus_cite_et_date() {
        for outil in OUTILS {
            let erreur = refus_messagerie(outil)
                .unwrap_or_else(|| panic!("{outil} doit avoir un refus cité"));
            assert_eq!(erreur.code(), "plateforme_ne_sert_pas", "{outil}");
            let ErreurMessagerie::NeSertPas {
                citation,
                deblocage,
            } = erreur
            else {
                panic!("{outil}: le refus doit être NeSertPas");
            };
            assert!(
                citation.contains("2026-09-02"),
                "{outil}: citation non datée"
            );
            assert!(
                !deblocage.is_empty(),
                "{outil}: le déblocage se dit, même « rien »"
            );
        }
        // Un outil inconnu n'a pas de refus inventé.
        assert!(refus_messagerie("post_teleport").is_none());
    }

    /// Les citations clés, mot pour mot — si une sonde future les contredit,
    /// c'est ici que ça casse.
    #[test]
    fn les_citations_portent_les_faits_sondes() {
        let citation = |outil: &str| match refus_messagerie(outil) {
            Some(ErreurMessagerie::NeSertPas { citation, .. }) => citation,
            autre => panic!("{outil}: {autre:?}"),
        };
        // Les DM sont un partenariat fermé.
        assert!(citation("dm_reply").contains("restricted to approved partners"));
        // Le DM froid : interdit par l'accès ET par les règles produit.
        assert!(citation("dm_open").contains("action membre explicite"));
        // comment/like : Community Management API, quotas cités.
        assert!(citation("post_comment").contains("Community Management"));
        assert!(citation("post_comment").contains("500 appels/app/24 h"));
        assert!(citation("post_like").contains("w_member_social_feed"));
        // Bookmarks et recherche : l'API n'existe pas.
        assert!(citation("post_bookmark").contains("aucune API de bookmarks"));
        assert!(citation("search_posts").contains("aucune API de recherche"));
    }

    /// Ce que « rien ne débloque » dit, il le dit — bookmarks et dm_open.
    #[test]
    fn les_impasses_se_disent_au_lieu_de_promettre() {
        for outil in ["post_bookmark", "dm_open"] {
            let Some(ErreurMessagerie::NeSertPas { deblocage, .. }) = refus_messagerie(outil)
            else {
                panic!("{outil}");
            };
            assert!(deblocage.starts_with("rien"), "{outil}: {deblocage}");
        }
    }
}
