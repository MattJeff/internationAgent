//! Second connecteur Meta — une autre app que `instagram`.
//!
//! Trois plateformes, trois jeux de portées, relevés le 2026-11-10 :
//!
//! * **`instagram_reels`** — même Facebook Login for Business que la Page
//!   (pas « Instagram Login » : indisponible, « Invalid platform app »).
//!   Le compte professionnel est `instagram_business_account` sur la Page.
//!   Publication sur `graph.facebook.com` :
//!   `POST /{ig-user-id}/media` (`media_type=REELS`, `video_url`), attente
//!   de `status_code=FINISHED`, puis `POST /{ig-user-id}/media_publish`.
//!   Jeton de Page. Permissions : `instagram_basic`,
//!   `instagram_content_publish`.
//! * **`facebook_page`** — Facebook Login for Business, jeton de Page
//!   (<https://developers.facebook.com/docs/video-api/guides/reels-publishing>,
//!   feed / photos / videos). Portées : `pages_show_list`,
//!   `pages_manage_posts`, `pages_read_engagement`. Texte → `POST /feed`,
//!   photo → `POST /photos` (`url`), vidéo → `POST /videos` (`file_url`),
//!   Reel → `video_reels` (`upload_phase=start`, envoi hébergé
//!   `file_url` vers `rupload.facebook.com`, `upload_phase=finish`).
//! * **`threads`** — Threads API
//!   (<https://developers.facebook.com/docs/threads/posts>). Portées :
//!   `threads_basic`, `threads_content_publish`. Conteneur
//!   `POST /{id}/threads` puis `threads_publish`.
//!
//! Les trois tirent une URL publique que NOUS servons (`/medias/{digest}`),
//! jamais l'URL du client. Les jetons vivent dans le callback OAuth, pas ici.

use std::sync::Arc;
use std::time::Duration;

use agentos_providers::Secret;
use async_trait::async_trait;
use url::Url;

use super::{
    Apercu, ApercuMedia, ContexteAdaptateurs, ErreurPlateforme, MediaPret, Metriques, OptionsPost,
    Placement, Plateforme, Publication, Sondage, TypeMedia, empreinte_globale, envoyer, http,
    lire_json, url_pull,
};
use crate::medias::DepotMedias;

/// Version Graph partagée avec le connecteur historique. v27.0 (phase 1).
const VERSION_GRAPH: &str = super::instagram::VERSION_GRAPH;
const VERSION_THREADS: &str = "v1.0";

pub const GRAPHE_FACEBOOK: &str = "https://graph.facebook.com";
pub const GRAPHE_THREADS: &str = "https://graph.threads.net";
pub const RUPLOAD: &str = "https://rupload.facebook.com";

/// « 300MB maximum » REELS (ig-user/media). Lecture décimale.
pub const OCTETS_MAX_REELS: u64 = 300_000_000;
/// Légende Instagram : 2 200 caractères (ig-user/media).
pub const CARACTERES_LEGENDE_IG: usize = 2_200;
/// `message` d'un post de Page : 63 206 caractères (Graph API, feed).
pub const CARACTERES_PAGE: usize = 63_206;
/// Texte Threads : 500 caractères (Threads posts).
pub const CARACTERES_THREADS: usize = 500;
pub const PHOTOS_PAGE_MAX: usize = 10;

const PAS_PROD: Duration = Duration::from_secs(5);
const ESSAIS_PROD: u32 = 60;

const CITE_IG_100: &str = "« Instagram accounts are limited to 100 API-published posts within a \
     24-hour moving period » (content publishing, relevé le 2026-11-10). \
     Le sous-code 2207042 sort en limite_publication — le quota vivant est \
     GET /content_publishing_limit (quota_total)";
const CITE_REELS_30: &str = "« Reels API is limited to 30 API-published posts within a 24-hour \
     moving period » (reels-publishing, relevé le 2026-11-10)";
const CITE_THREADS_250: &str = "Threads : 250 posts API par profil sur 24 h glissantes \
     (threads_publishing_limit, relevé le 2026-11-10). Un carrousel compte pour un";
const CITE_TESTEURS: &str = "avant la revue, seuls les rôles de l'app (admin, développeur, \
     testeur) peuvent se connecter — Standard Access / mode Development";

struct Socle {
    base_publique: String,
    depot: Arc<DepotMedias>,
    graph: String,
    rupload: String,
    version: &'static str,
    pas: Duration,
    essais: u32,
}

impl Socle {
    fn prod(ctx: &ContexteAdaptateurs, graph: &str, rupload: &str, version: &'static str) -> Self {
        Self {
            base_publique: ctx.base_publique.trim_end_matches('/').to_owned(),
            depot: ctx.depot.clone(),
            graph: graph.to_owned(),
            rupload: rupload.to_owned(),
            version,
            pas: PAS_PROD,
            essais: ESSAIS_PROD,
        }
    }

    fn url(&self, chemin: &str) -> String {
        format!(
            "{}/{}/{}",
            self.graph.trim_end_matches('/'),
            self.version,
            chemin.trim_start_matches('/')
        )
    }

    fn garder(&self, medias: &[MediaPret]) -> GardeDepot {
        for m in medias {
            self.depot
                .deposer(&m.digest, m.octets.clone(), m.type_detecte);
        }
        GardeDepot {
            depot: self.depot.clone(),
            digests: medias.iter().map(|m| m.digest.clone()).collect(),
        }
    }

    async fn poster(
        &self,
        chemin: &str,
        jeton: &Secret,
        params: &[(String, String)],
    ) -> Result<serde_json::Value, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .post(self.url(chemin))
                .bearer_auth(jeton.expose_for_transport())
                .form(params),
        )
        .await?;
        lire_json(statut, &corps)
    }

    async fn obtenir(
        &self,
        chemin: &str,
        jeton: &Secret,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, ErreurPlateforme> {
        let (statut, corps) = envoyer(
            http()
                .get(self.url(chemin))
                .query(query)
                .bearer_auth(jeton.expose_for_transport()),
        )
        .await?;
        lire_json(statut, &corps)
    }

    async fn attendre<F, Fut>(&self, mut sonde: F) -> Result<(), ErreurPlateforme>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<Attente, ErreurPlateforme>>,
    {
        for i in 0..self.essais {
            match sonde().await? {
                Attente::Pret => return Ok(()),
                Attente::Echec => return Err(ErreurPlateforme::Injoignable),
                Attente::EnCours => {
                    if i + 1 == self.essais {
                        break;
                    }
                    if !self.pas.is_zero() {
                        tokio::time::sleep(self.pas).await;
                    }
                }
            }
        }
        Err(ErreurPlateforme::Injoignable)
    }

    async fn attendre_code(
        &self,
        jeton: &Secret,
        id: &str,
        champs: &'static str,
    ) -> Result<(), ErreurPlateforme> {
        self.attendre(|| async {
            let v = self.obtenir(id, jeton, &[("fields", champs)]).await?;
            etat_code(&v)
        })
        .await
    }
}

struct GardeDepot {
    depot: Arc<DepotMedias>,
    digests: Vec<String>,
}

impl Drop for GardeDepot {
    fn drop(&mut self) {
        for d in &self.digests {
            self.depot.retirer(d);
        }
    }
}

enum Attente {
    Pret,
    Echec,
    EnCours,
}

fn etat_code(v: &serde_json::Value) -> Result<Attente, ErreurPlateforme> {
    let code = v
        .get("status_code")
        .and_then(|s| s.as_str())
        .or_else(|| v.get("status").and_then(|s| s.as_str()));
    match code {
        Some("FINISHED" | "PUBLISHED") => Ok(Attente::Pret),
        Some("ERROR" | "EXPIRED") => Ok(Attente::Echec),
        Some("IN_PROGRESS") => Ok(Attente::EnCours),
        _ => Err(ErreurPlateforme::Illisible),
    }
}

fn etat_video(v: &serde_json::Value) -> Result<Attente, ErreurPlateforme> {
    match v.pointer("/status/video_status").and_then(|s| s.as_str()) {
        Some("ready") => Ok(Attente::Pret),
        Some("error" | "expired" | "upload_failed") => Ok(Attente::Echec),
        Some("uploading" | "processing" | "upload_complete") => Ok(Attente::EnCours),
        _ => Err(ErreurPlateforme::Illisible),
    }
}

fn id_graphique(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

fn id_de(v: &serde_json::Value, champ: &str) -> Result<String, ErreurPlateforme> {
    let id = v
        .get(champ)
        .and_then(|x| x.as_str())
        .ok_or(ErreurPlateforme::Illisible)?;
    if id_graphique(id) {
        Ok(id.to_owned())
    } else {
        Err(ErreurPlateforme::Refus { statut: 400 })
    }
}

fn paire(nom: &str, valeur: impl Into<String>) -> (String, String) {
    (nom.to_owned(), valeur.into())
}

fn url_upload_autorise(url: &str, base_rupload: &str) -> bool {
    let (Ok(u), Ok(b)) = (Url::parse(url), Url::parse(base_rupload)) else {
        return false;
    };
    u.scheme() == b.scheme()
        && u.host_str() == b.host_str()
        && u.port_or_known_default() == b.port_or_known_default()
        && u.path().starts_with("/video-upload/")
}

fn entete_sur(s: &str) -> bool {
    !s.is_empty() && s.len() < 2_048 && s.bytes().all(|b| b.is_ascii() && b != b'\r' && b != b'\n')
}

fn carte(m: &MediaPret, ok: bool, verdicts: Vec<String>) -> ApercuMedia {
    ApercuMedia {
        digest: m.digest.clone(),
        size_bytes: m.octets.len() as u64,
        detected_type: m.type_detecte.mime(),
        alt_text: m.alt_text.clone(),
        limits_ok: ok,
        verdicts,
    }
}

fn refuser_communs(
    options: &OptionsPost,
    sondage: Option<&Sondage>,
    refus: &mut Vec<String>,
    infos: &mut Vec<String>,
) {
    if sondage.is_some() {
        refus.push(
            "ce connecteur ne sert pas de sondage (aucun champ poll sur ces API, relevé le 2026-11-10)"
                .to_owned(),
        );
    }
    if options.privacy.is_some() {
        refus.push(
            "pas de paramètre de visibilité à la publication sur ces API (compte professionnel, Page, Threads)"
                .to_owned(),
        );
    }
    if options.livraison.is_some() {
        refus.push("delivery n'est servi que par TikTok".to_owned());
    }
    if options.publish_at.is_some() {
        infos.push(super::VERDICT_CRENEAU.to_owned());
    }
}

#[allow(clippy::too_many_arguments)]
fn assembler(
    texte: &str,
    medias: &[MediaPret],
    sondage: Option<&Sondage>,
    made_with_ai: bool,
    options: &OptionsPost,
    mut refus: Vec<String>,
    mut infos: Vec<String>,
    media: Vec<ApercuMedia>,
) -> Apercu {
    let ok = refus.is_empty() && media.iter().all(|m| m.limits_ok);
    refus.append(&mut infos);
    Apercu {
        rendered_text: texte.to_owned(),
        digest: empreinte_globale(texte, medias, sondage, made_with_ai, options),
        platform_limits_ok: ok,
        cost_estimate_usd: None,
        media,
        verdicts: refus,
        cout_quota: None,
    }
}

fn hors_limites(apercu: &Apercu) -> bool {
    !apercu.platform_limits_ok || apercu.media.iter().any(|m| !m.limits_ok)
}

async fn pousser_heberge(
    upload_url: &str,
    base_rupload: &str,
    jeton: &Secret,
    file_url: &str,
) -> Result<(), ErreurPlateforme> {
    if !url_upload_autorise(upload_url, base_rupload) || !entete_sur(file_url) {
        return Err(ErreurPlateforme::Refus { statut: 400 });
    }
    let (statut, corps) = envoyer(
        http()
            .post(upload_url)
            .header(
                "Authorization",
                format!("OAuth {}", jeton.expose_for_transport()),
            )
            .header("file_url", file_url),
    )
    .await?;
    let v = lire_json(statut, &corps)?;
    if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
        return Err(ErreurPlateforme::Refus { statut: 400 });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Instagram Reels
// ---------------------------------------------------------------------------

pub struct InstagramReels {
    socle: Socle,
}

impl InstagramReels {
    pub fn nouvel(ctx: &ContexteAdaptateurs) -> Self {
        Self {
            socle: Socle::prod(ctx, GRAPHE_FACEBOOK, RUPLOAD, VERSION_GRAPH),
        }
    }

    #[cfg(test)]
    fn pour_essai(base: &str, depot: Arc<DepotMedias>, origine: &str) -> Self {
        Self {
            socle: Socle {
                base_publique: base.trim_end_matches('/').to_owned(),
                depot,
                graph: origine.to_owned(),
                rupload: origine.to_owned(),
                version: VERSION_GRAPH,
                pas: Duration::ZERO,
                essais: 5,
            },
        }
    }

    async fn permalink(&self, jeton: &Secret, id: &str) -> String {
        match self
            .socle
            .obtenir(id, jeton, &[("fields", "permalink")])
            .await
        {
            Ok(v) => v
                .get("permalink")
                .and_then(|s| s.as_str())
                .unwrap_or("https://www.instagram.com")
                .to_owned(),
            Err(_) => "https://www.instagram.com".to_owned(),
        }
    }
}

#[async_trait]
impl Plateforme for InstagramReels {
    fn nom(&self) -> &'static str {
        "instagram_reels"
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
        let mut infos = vec![
            CITE_IG_100.to_owned(),
            CITE_TESTEURS.to_owned(),
            "compte Instagram professionnel lié à la Page (instagram_business_account) — le jeton est celui de la Page, l'hôte est graph.facebook.com"
                .to_owned(),
        ];
        refuser_communs(options, sondage, &mut refus, &mut infos);
        if texte.chars().count() > CARACTERES_LEGENDE_IG {
            refus.push(format!(
                "légende Instagram : {CARACTERES_LEGENDE_IG} caractères maximum, reçu {}",
                texte.chars().count()
            ));
        }
        match options.placement {
            Some(Placement::Reel) | None => {}
            Some(Placement::Flux | Placement::Story) => refus.push(
                "instagram_reels ne publie que des Reels (media_type=REELS). placement=feed ou story est refusé"
                    .to_owned(),
            ),
        }
        if medias.len() != 1 {
            refus.push(
                "un Reel est une seule vidéo : conteneur REELS, video_url (content publishing, relevé le 2026-11-10)"
                    .to_owned(),
            );
        }
        if made_with_ai {
            infos.push(
                "made_with_ai part en is_ai_generated=true sur le conteneur REELS".to_owned(),
            );
        }
        infos.push(
            "durée « 3 seconds minimum, 15 mins maximum » non vérifiable aux octets (ig-user/media)"
                .to_owned(),
        );
        let media = medias
            .iter()
            .map(|m| {
                let mut v = Vec::new();
                let mut ok = true;
                if m.type_detecte != TypeMedia::Mp4 {
                    ok = false;
                    v.push("REELS : vidéo MP4 (video_url), reçu un autre type".to_owned());
                }
                let taille = m.octets.len() as u64;
                if taille > OCTETS_MAX_REELS {
                    ok = false;
                    v.push(format!(
                        "« 300MB maximum » pour un REELS, reçu {taille} octets"
                    ));
                }
                carte(m, ok, v)
            })
            .collect();
        assembler(
            texte,
            medias,
            sondage,
            made_with_ai,
            options,
            refus,
            infos,
            media,
        )
    }

    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        // Le handle est l'id Instagram (chiffres). Le jeton est celui de la
        // Page : `/me` serait la Page, pas le compte Instagram.
        if !id_graphique(handle) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let vu = self.apercu(texte, medias, sondage, made_with_ai, options);
        if hors_limites(&vu) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let m = &medias[0];
        let _garde = self.socle.garder(medias);
        let mut params = vec![
            paire("media_type", "REELS"),
            paire("share_to_feed", "true"),
            paire("video_url", url_pull(&self.socle.base_publique, &m.digest)),
        ];
        if !texte.is_empty() {
            params.push(paire("caption", texte));
        }
        if made_with_ai {
            params.push(paire("is_ai_generated", "true"));
        }
        let conteneur = id_de(
            &self
                .socle
                .poster(&format!("{handle}/media"), jeton, &params)
                .await?,
            "id",
        )?;
        self.socle
            .attendre_code(jeton, &conteneur, "status_code")
            .await?;
        let media_id = id_de(
            &self
                .socle
                .poster(
                    &format!("{handle}/media_publish"),
                    jeton,
                    &[paire("creation_id", &conteneur)],
                )
                .await?,
            "id",
        )?;
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
        if !id_graphique(id_plateforme) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let v = self
            .socle
            .obtenir(
                id_plateforme,
                jeton,
                &[("fields", "like_count,comments_count")],
            )
            .await?;
        Ok(Some(Metriques {
            impressions: None,
            likes: v.get("like_count").and_then(|n| n.as_u64()).unwrap_or(0),
            replies: v
                .get("comments_count")
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
            reposts: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// Facebook Page
// ---------------------------------------------------------------------------

pub struct FacebookPage {
    socle: Socle,
}

impl FacebookPage {
    pub fn nouvel(ctx: &ContexteAdaptateurs) -> Self {
        Self {
            socle: Socle::prod(ctx, GRAPHE_FACEBOOK, RUPLOAD, VERSION_GRAPH),
        }
    }

    #[cfg(test)]
    fn pour_essai(base: &str, depot: Arc<DepotMedias>, origine: &str) -> Self {
        Self {
            socle: Socle {
                base_publique: base.trim_end_matches('/').to_owned(),
                depot,
                graph: origine.to_owned(),
                rupload: origine.to_owned(),
                version: VERSION_GRAPH,
                pas: Duration::ZERO,
                essais: 5,
            },
        }
    }

    async fn permalink(&self, jeton: &Secret, id: &str, repli: &str) -> String {
        match self
            .socle
            .obtenir(id, jeton, &[("fields", "permalink_url")])
            .await
        {
            Ok(v) => v
                .get("permalink_url")
                .and_then(|s| s.as_str())
                .unwrap_or(repli)
                .to_owned(),
            Err(_) => repli.to_owned(),
        }
    }

    async fn attendre_video(&self, jeton: &Secret, id: &str) -> Result<(), ErreurPlateforme> {
        self.socle
            .attendre(|| async {
                let v = self
                    .socle
                    .obtenir(id, jeton, &[("fields", "status")])
                    .await?;
                etat_video(&v)
            })
            .await
    }
}

#[async_trait]
impl Plateforme for FacebookPage {
    fn nom(&self) -> &'static str {
        "facebook_page"
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
        let mut infos = vec![CITE_TESTEURS.to_owned()];
        refuser_communs(options, sondage, &mut refus, &mut infos);
        if texte.chars().count() > CARACTERES_PAGE {
            refus.push(format!(
                "message de Page : {CARACTERES_PAGE} caractères maximum, reçu {}",
                texte.chars().count()
            ));
        }
        if options.placement == Some(Placement::Story) {
            refus.push(
                "les stories de Page ne sont pas servies par ce connecteur (feed, photo, vidéo, Reel)"
                    .to_owned(),
            );
        }
        let reel = options.placement == Some(Placement::Reel);
        if reel {
            infos.push(CITE_REELS_30.to_owned());
            let pas_une_video = medias.len() != 1
                || medias
                    .first()
                    .is_none_or(|m| m.type_detecte != TypeMedia::Mp4);
            if pas_une_video {
                refus.push(
                    "un Reel de Page est une seule vidéo (video_reels, relevé le 2026-11-10)"
                        .to_owned(),
                );
            }
        }
        let photos = medias
            .iter()
            .all(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Png));
        let video = medias.len() == 1 && medias[0].type_detecte == TypeMedia::Mp4;
        if medias.is_empty() {
            infos.push("post texte : POST /{page-id}/feed (message)".to_owned());
        } else if photos && (1..=PHOTOS_PAGE_MAX).contains(&medias.len()) && !reel {
            infos.push(
                "photo : POST /{page-id}/photos (url). Plusieurs photos : published=false puis attached_media"
                    .to_owned(),
            );
        } else if video && !reel {
            infos.push(
                "vidéo de fil : POST /{page-id}/videos (file_url). placement=reel publie un Reel (video_reels)"
                    .to_owned(),
            );
        } else if !(video && reel) {
            refus.push(format!(
                "Page : texte seul, 1 à {PHOTOS_PAGE_MAX} JPEG/PNG, ou une vidéo MP4 — reçu {} média(s)",
                medias.len()
            ));
        }
        if made_with_ai {
            infos.push(
                "made_with_ai reste dans l'empreinte : l'API Page n'a pas d'équivalent is_ai_generated"
                    .to_owned(),
            );
        }
        if medias.iter().any(|m| m.alt_text.is_some()) {
            infos.push(
                "alt_text reste dans l'empreinte : pas de paramètre alt sur POST /photos (relevé le 2026-11-10)"
                    .to_owned(),
            );
        }
        let media = medias.iter().map(|m| carte(m, true, Vec::new())).collect();
        assembler(
            texte,
            medias,
            sondage,
            made_with_ai,
            options,
            refus,
            infos,
            media,
        )
    }

    async fn publier(
        &self,
        jeton: &Secret,
        handle: &str,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        if !id_graphique(handle) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let vu = self.apercu(texte, medias, sondage, made_with_ai, options);
        if hors_limites(&vu) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let _ = made_with_ai;
        let _garde = self.socle.garder(medias);
        if options.placement == Some(Placement::Reel) {
            return self.publier_reel(jeton, texte, &medias[0]).await;
        }
        if medias.is_empty() {
            let id = id_de(
                &self
                    .socle
                    .poster("me/feed", jeton, &[paire("message", texte)])
                    .await?,
                "id",
            )?;
            let url = self
                .permalink(jeton, &id, &format!("https://www.facebook.com/{id}"))
                .await;
            return Ok(Publication {
                id_plateforme: id,
                url,
            });
        }
        if medias.len() == 1 && medias[0].type_detecte == TypeMedia::Mp4 {
            return self.publier_video(jeton, texte, &medias[0]).await;
        }
        self.publier_photos(jeton, texte, medias).await
    }

    async fn metriques(
        &self,
        jeton: &Secret,
        id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        if !id_graphique(id_plateforme) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let v = self
            .socle
            .obtenir(
                id_plateforme,
                jeton,
                [(
                    "fields",
                    "shares,reactions.summary(true),comments.summary(true)",
                )]
                .as_slice(),
            )
            .await?;
        Ok(Some(Metriques {
            impressions: None,
            likes: v
                .pointer("/reactions/summary/total_count")
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
            replies: v
                .pointer("/comments/summary/total_count")
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
            reposts: v
                .pointer("/shares/count")
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
        }))
    }
}

impl FacebookPage {
    async fn publier_photos(
        &self,
        jeton: &Secret,
        texte: &str,
        medias: &[MediaPret],
    ) -> Result<Publication, ErreurPlateforme> {
        if medias.len() == 1 {
            let m = &medias[0];
            let params = vec![
                paire("url", url_pull(&self.socle.base_publique, &m.digest)),
                paire("caption", texte),
                paire("published", "true"),
            ];
            let v = self.socle.poster("me/photos", jeton, &params).await?;
            let post = v
                .get("post_id")
                .and_then(|s| s.as_str())
                .filter(|s| id_graphique(s))
                .map(str::to_owned)
                .unwrap_or(id_de(&v, "id")?);
            let url = self
                .permalink(jeton, &post, &format!("https://www.facebook.com/{post}"))
                .await;
            return Ok(Publication {
                id_plateforme: post,
                url,
            });
        }
        let mut fbids = Vec::with_capacity(medias.len());
        for m in medias {
            let v = self
                .socle
                .poster(
                    "me/photos",
                    jeton,
                    &[
                        paire("url", url_pull(&self.socle.base_publique, &m.digest)),
                        paire("published", "false"),
                    ],
                )
                .await?;
            fbids.push(id_de(&v, "id")?);
        }
        let mut params = vec![paire("message", texte)];
        for (i, id) in fbids.iter().enumerate() {
            params.push(paire(
                &format!("attached_media[{i}]"),
                format!(r#"{{"media_fbid":"{id}"}}"#),
            ));
        }
        let id = id_de(&self.socle.poster("me/feed", jeton, &params).await?, "id")?;
        let url = self
            .permalink(jeton, &id, &format!("https://www.facebook.com/{id}"))
            .await;
        Ok(Publication {
            id_plateforme: id,
            url,
        })
    }

    async fn publier_video(
        &self,
        jeton: &Secret,
        texte: &str,
        m: &MediaPret,
    ) -> Result<Publication, ErreurPlateforme> {
        let mut params = vec![
            paire("file_url", url_pull(&self.socle.base_publique, &m.digest)),
            paire("description", texte),
            paire("published", "true"),
        ];
        if let Some(titre) = &m.title {
            params.push(paire("title", titre));
        }
        let id = id_de(&self.socle.poster("me/videos", jeton, &params).await?, "id")?;
        self.attendre_video(jeton, &id).await?;
        let url = self
            .permalink(jeton, &id, &format!("https://www.facebook.com/{id}"))
            .await;
        Ok(Publication {
            id_plateforme: id,
            url,
        })
    }

    async fn publier_reel(
        &self,
        jeton: &Secret,
        texte: &str,
        m: &MediaPret,
    ) -> Result<Publication, ErreurPlateforme> {
        let demarre = self
            .socle
            .poster("me/video_reels", jeton, &[paire("upload_phase", "start")])
            .await?;
        let video_id = id_de(&demarre, "video_id")?;
        let upload_url = demarre
            .get("upload_url")
            .and_then(|s| s.as_str())
            .ok_or(ErreurPlateforme::Illisible)?;
        let file_url = url_pull(&self.socle.base_publique, &m.digest);
        pousser_heberge(upload_url, &self.socle.rupload, jeton, &file_url).await?;
        let mut fin = vec![
            paire("upload_phase", "finish"),
            paire("video_id", &video_id),
            paire("video_state", "PUBLISHED"),
            paire("description", texte),
        ];
        if let Some(titre) = &m.title {
            fin.push(paire("title", titre));
        }
        let fini = self.socle.poster("me/video_reels", jeton, &fin).await?;
        if fini.get("success").and_then(|s| s.as_bool()) == Some(false) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        self.attendre_video(jeton, &video_id).await?;
        let url = self
            .permalink(
                jeton,
                &video_id,
                &format!("https://www.facebook.com/reel/{video_id}"),
            )
            .await;
        Ok(Publication {
            id_plateforme: video_id,
            url,
        })
    }
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

pub struct Threads {
    socle: Socle,
}

impl Threads {
    pub fn nouvel(ctx: &ContexteAdaptateurs) -> Self {
        Self {
            socle: Socle::prod(ctx, GRAPHE_THREADS, RUPLOAD, VERSION_THREADS),
        }
    }

    #[cfg(test)]
    fn pour_essai(base: &str, depot: Arc<DepotMedias>, origine: &str) -> Self {
        Self {
            socle: Socle {
                base_publique: base.trim_end_matches('/').to_owned(),
                depot,
                graph: origine.to_owned(),
                rupload: origine.to_owned(),
                version: VERSION_THREADS,
                pas: Duration::ZERO,
                essais: 5,
            },
        }
    }

    async fn conteneur(
        &self,
        jeton: &Secret,
        params: &[(String, String)],
    ) -> Result<String, ErreurPlateforme> {
        let id = id_de(&self.socle.poster("me/threads", jeton, params).await?, "id")?;
        self.socle
            .attendre_code(jeton, &id, "status,error_message")
            .await?;
        Ok(id)
    }

    async fn publier_id(
        &self,
        jeton: &Secret,
        creation_id: &str,
    ) -> Result<Publication, ErreurPlateforme> {
        let id = id_de(
            &self
                .socle
                .poster(
                    "me/threads_publish",
                    jeton,
                    &[paire("creation_id", creation_id)],
                )
                .await?,
            "id",
        )?;
        let url = match self
            .socle
            .obtenir(&id, jeton, &[("fields", "permalink")])
            .await
        {
            Ok(v) => v
                .get("permalink")
                .and_then(|s| s.as_str())
                .unwrap_or("https://www.threads.net")
                .to_owned(),
            Err(_) => "https://www.threads.net".to_owned(),
        };
        Ok(Publication {
            id_plateforme: id,
            url,
        })
    }
}

#[async_trait]
impl Plateforme for Threads {
    fn nom(&self) -> &'static str {
        "threads"
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
        let mut infos = vec![CITE_THREADS_250.to_owned(), CITE_TESTEURS.to_owned()];
        refuser_communs(options, sondage, &mut refus, &mut infos);
        if options.placement.is_some() {
            refus.push(
                "Threads n'a pas de placement feed/story/reel : le conteneur est TEXT, IMAGE, VIDEO ou CAROUSEL"
                    .to_owned(),
            );
        }
        if texte.chars().count() > CARACTERES_THREADS {
            refus.push(format!(
                "texte Threads : {CARACTERES_THREADS} caractères maximum, reçu {}",
                texte.chars().count()
            ));
        }
        if medias.is_empty() && texte.is_empty() {
            refus.push("un post Threads texte exige un texte (media_type=TEXT)".to_owned());
        }
        let photos = medias
            .iter()
            .all(|m| matches!(m.type_detecte, TypeMedia::Jpeg | TypeMedia::Png));
        let video = medias.len() == 1 && medias[0].type_detecte == TypeMedia::Mp4;
        if medias.is_empty() {
            infos.push("TEXT : POST /threads puis threads_publish".to_owned());
        } else if video {
            infos.push(
                "VIDEO : video_url, attente de status=FINISHED, puis threads_publish".to_owned(),
            );
        } else if photos && medias.len() == 1 {
            infos.push("IMAGE : image_url publique servie par /medias/{digest}".to_owned());
        } else if photos && (2..=PHOTOS_PAGE_MAX).contains(&medias.len()) {
            infos.push(
                "CAROUSEL : un conteneur is_carousel_item par image, puis children (2 à 10)"
                    .to_owned(),
            );
        } else {
            refus.push(
                "Threads : texte, une image JPEG/PNG, une vidéo MP4, ou 2 à 10 images".to_owned(),
            );
        }
        if made_with_ai {
            infos.push(
                "made_with_ai reste dans l'empreinte : le conteneur Threads n'a pas de champ équivalent"
                    .to_owned(),
            );
        }
        let media = medias.iter().map(|m| carte(m, true, Vec::new())).collect();
        assembler(
            texte,
            medias,
            sondage,
            made_with_ai,
            options,
            refus,
            infos,
            media,
        )
    }

    async fn publier(
        &self,
        jeton: &Secret,
        _handle: &str,
        texte: &str,
        medias: &[MediaPret],
        sondage: Option<&Sondage>,
        made_with_ai: bool,
        options: &OptionsPost,
    ) -> Result<Publication, ErreurPlateforme> {
        let vu = self.apercu(texte, medias, sondage, made_with_ai, options);
        if hors_limites(&vu) {
            return Err(ErreurPlateforme::Refus { statut: 400 });
        }
        let _ = made_with_ai;
        let _garde = self.socle.garder(medias);
        if medias.is_empty() {
            return self
                .publier_id(
                    jeton,
                    &self
                        .conteneur(jeton, &[paire("media_type", "TEXT"), paire("text", texte)])
                        .await?,
                )
                .await;
        }
        if medias.len() == 1 && medias[0].type_detecte == TypeMedia::Mp4 {
            let mut params = vec![
                paire("media_type", "VIDEO"),
                paire(
                    "video_url",
                    url_pull(&self.socle.base_publique, &medias[0].digest),
                ),
            ];
            if !texte.is_empty() {
                params.push(paire("text", texte));
            }
            let id = self.conteneur(jeton, &params).await?;
            return self.publier_id(jeton, &id).await;
        }
        if medias.len() == 1 {
            let mut params = vec![
                paire("media_type", "IMAGE"),
                paire(
                    "image_url",
                    url_pull(&self.socle.base_publique, &medias[0].digest),
                ),
            ];
            if !texte.is_empty() {
                params.push(paire("text", texte));
            }
            if let Some(alt) = &medias[0].alt_text {
                params.push(paire("alt_text", alt));
            }
            let id = self.conteneur(jeton, &params).await?;
            return self.publier_id(jeton, &id).await;
        }
        let mut enfants = Vec::with_capacity(medias.len());
        for m in medias {
            let mut params = vec![
                paire("media_type", "IMAGE"),
                paire("is_carousel_item", "true"),
                paire("image_url", url_pull(&self.socle.base_publique, &m.digest)),
            ];
            if let Some(alt) = &m.alt_text {
                params.push(paire("alt_text", alt));
            }
            enfants.push(self.conteneur(jeton, &params).await?);
        }
        let mut parent = vec![
            paire("media_type", "CAROUSEL"),
            paire("children", enfants.join(",")),
        ];
        if !texte.is_empty() {
            parent.push(paire("text", texte));
        }
        let id = self.conteneur(jeton, &parent).await?;
        self.publier_id(jeton, &id).await
    }

    async fn metriques(
        &self,
        _jeton: &Secret,
        _id_plateforme: &str,
    ) -> Result<Option<Metriques>, ErreurPlateforme> {
        // threads_manage_insights n'est pas demandé : dire l'absence, pas des zéros.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::any;

    fn video(lest: &[u8]) -> MediaPret {
        let mut o = b"\x00\x00\x00\x18ftypisom".to_vec();
        o.extend_from_slice(lest);
        super::super::test_medias::media(&o, TypeMedia::Mp4)
    }

    fn photo(lest: &[u8]) -> MediaPret {
        super::super::test_medias::media(&crate::medias::octets_png(lest), TypeMedia::Png)
    }

    fn opts(placement: Option<Placement>) -> OptionsPost {
        OptionsPost {
            placement,
            ..OptionsPost::default()
        }
    }

    struct Mock {
        base: std::sync::Mutex<String>,
        limite: AtomicBool,
        suivant: AtomicU64,
        journal: std::sync::Mutex<Vec<String>>,
    }

    async fn servir(State(st): State<Arc<Mock>>, req: Request<Body>) -> impl IntoResponse {
        let path = req.uri().path().to_owned();
        let query = req.uri().query().unwrap_or("").to_owned();
        let method = req.method().clone();
        let file_url = req
            .headers()
            .get("file_url")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if !auth.contains("jeton-de-test") {
            return (StatusCode::UNAUTHORIZED, "{}").into_response();
        }
        let octets = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap_or_default();
        let corps = String::from_utf8_lossy(&octets).to_string();
        st.journal.lock().expect("journal").push(format!(
            "{method} {path}?{query} {corps} file_url={file_url}"
        ));
        if st.limite.load(Ordering::SeqCst) && method == axum::http::Method::POST {
            let err = r#"{"error":{"message":"access_token=NE-DOIT-PAS-FUITER","code":9,"error_subcode":2207042}}"#;
            return (StatusCode::BAD_REQUEST, err).into_response();
        }
        if path.contains("/video_reels") && corps.contains("upload_phase=start") {
            let url = format!(
                "{}/video-upload/v27.0/9001",
                st.base.lock().expect("base").clone()
            );
            return (
                StatusCode::OK,
                format!(r#"{{"video_id":"9001","upload_url":"{url}"}}"#),
            )
                .into_response();
        }
        if path.contains("/video-upload/")
            || (path.contains("/video_reels") && corps.contains("finish"))
        {
            return (StatusCode::OK, r#"{"success":true}"#).into_response();
        }
        if method == axum::http::Method::GET {
            let id = path.rsplit('/').next().unwrap_or("0");
            if query.contains("status_code") {
                return (
                    StatusCode::OK,
                    format!(r#"{{"status_code":"FINISHED","id":"{id}"}}"#),
                )
                    .into_response();
            }
            if query.contains("error_message") {
                return (
                    StatusCode::OK,
                    format!(r#"{{"status":"FINISHED","id":"{id}"}}"#),
                )
                    .into_response();
            }
            if query.contains("fields=status") {
                return (
                    StatusCode::OK,
                    format!(r#"{{"status":{{"video_status":"ready"}},"id":"{id}"}}"#),
                )
                    .into_response();
            }
            if query.contains("permalink_url") {
                return (
                    StatusCode::OK,
                    format!(r#"{{"permalink_url":"https://www.facebook.com/{id}","id":"{id}"}}"#),
                )
                    .into_response();
            }
            if query.contains("like_count") {
                return (StatusCode::OK, r#"{"like_count":4,"comments_count":1}"#).into_response();
            }
            if query.contains("reactions") {
                return (
                    StatusCode::OK,
                    r#"{"reactions":{"summary":{"total_count":10}},"comments":{"summary":{"total_count":2}},"shares":{"count":3}}"#,
                )
                    .into_response();
            }
            if path.starts_with("/v1.0") {
                return (
                    StatusCode::OK,
                    format!(r#"{{"permalink":"https://www.threads.net/post/{id}","id":"{id}"}}"#),
                )
                    .into_response();
            }
            return (
                StatusCode::OK,
                format!(r#"{{"permalink":"https://www.instagram.com/reel/{id}/","id":"{id}"}}"#),
            )
                .into_response();
        }
        let id = st.suivant.fetch_add(1, Ordering::SeqCst).to_string();
        if path.ends_with("/photos") {
            return (
                StatusCode::OK,
                format!(r#"{{"id":"{id}","post_id":"55_{id}"}}"#),
            )
                .into_response();
        }
        (StatusCode::OK, format!(r#"{{"id":"{id}"}}"#)).into_response()
    }

    async fn origine(limite: bool) -> (String, Arc<Mock>) {
        let st = Arc::new(Mock {
            base: std::sync::Mutex::new(String::new()),
            limite: AtomicBool::new(limite),
            suivant: AtomicU64::new(10),
            journal: std::sync::Mutex::new(Vec::new()),
        });
        let app = Router::new().fallback(any(servir)).with_state(st.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{adresse}");
        *st.base.lock().expect("base") = base.clone();
        (base, st)
    }

    fn jeton() -> Secret {
        Secret::new("jeton-de-test")
    }

    fn adaptateur_ig(origine: &str) -> (InstagramReels, Arc<DepotMedias>) {
        let depot = Arc::new(DepotMedias::new());
        (
            InstagramReels::pour_essai("https://social.example", depot.clone(), origine),
            depot,
        )
    }

    #[test]
    fn l_apercu_reel_refuse_ce_qui_n_est_pas_une_video() {
        let (ig, _) = adaptateur_ig("https://graph.instagram.com");
        let png = photo(b"pas-une-video");
        let vu = ig.apercu("salut", &[png], None, false, &opts(None));
        assert!(!vu.platform_limits_ok);
        let mp4 = video(b"reel");
        let ok = ig.apercu(
            "salut",
            std::slice::from_ref(&mp4),
            None,
            true,
            &opts(Some(Placement::Reel)),
        );
        assert!(ok.platform_limits_ok, "{:?}", ok.verdicts);
        assert!(ok.verdicts.iter().any(|v| v.contains("2207042")));
        assert!(ok.verdicts.iter().any(|v| v.contains("is_ai_generated")));
        let story = ig.apercu("salut", &[mp4], None, false, &opts(Some(Placement::Story)));
        assert!(!story.platform_limits_ok);
    }

    #[test]
    fn l_apercu_page_et_threads_cite_ses_limites() {
        let depot = Arc::new(DepotMedias::new());
        let page = FacebookPage::pour_essai(
            "https://social.example",
            depot.clone(),
            "https://graph.facebook.com",
        );
        let texte = page.apercu("bonjour", &[], None, false, &opts(None));
        assert!(texte.platform_limits_ok, "{:?}", texte.verdicts);
        let reel = page.apercu(
            "bonjour",
            &[video(b"r")],
            None,
            false,
            &opts(Some(Placement::Reel)),
        );
        assert!(reel.platform_limits_ok, "{:?}", reel.verdicts);
        assert!(reel.verdicts.iter().any(|v| v.contains("30")));
        let threads =
            Threads::pour_essai("https://social.example", depot, "https://graph.threads.net");
        let long = "a".repeat(CARACTERES_THREADS + 1);
        assert!(
            !threads
                .apercu(&long, &[], None, false, &opts(None))
                .platform_limits_ok
        );
        let post = threads.apercu("bonjour", &[], None, false, &opts(None));
        assert!(post.platform_limits_ok, "{:?}", post.verdicts);
        assert!(post.verdicts.iter().any(|v| v.contains("250")));
        assert!(
            !threads
                .apercu("bonjour", &[], None, false, &opts(Some(Placement::Flux)))
                .platform_limits_ok
        );
    }

    #[tokio::test]
    async fn le_reel_instagram_cree_le_conteneur_puis_publie() {
        let (origine, st) = origine(false).await;
        let (ig, depot) = adaptateur_ig(&origine);
        let media = video(b"octets-reel");
        let digest = media.digest.clone();
        let jeton = jeton();
        let pub_ = ig
            .publier(
                &jeton,
                "17841405822304914",
                "légende",
                &[media],
                None,
                true,
                &opts(None),
            )
            .await
            .expect("publication");
        assert!(pub_.url.contains("instagram.com/reel/"), "{}", pub_.url);
        assert!(id_graphique(&pub_.id_plateforme));
        let journal = st.journal.lock().expect("journal").join("\n");
        assert!(journal.contains("REELS"), "{journal}");
        assert!(journal.contains(&digest), "{journal}");
        assert!(journal.contains("share_to_feed"), "{journal}");
        assert!(journal.contains("is_ai_generated"), "{journal}");
        assert!(journal.contains("creation_id"), "{journal}");
        assert!(journal.contains("media_publish"), "{journal}");
        assert!(journal.contains("/17841405822304914/media"), "{journal}");
        assert!(!journal.contains("/me/media"), "{journal}");
        assert!(!journal.contains("client.example"));
        assert!(depot.servir(&digest).is_none(), "le dépôt est retiré");
    }

    #[tokio::test]
    async fn la_limite_de_publication_ne_recopie_pas_le_corps() {
        let (origine, _) = origine(true).await;
        let (ig, _) = adaptateur_ig(&origine);
        let err = ig
            .publier(
                &jeton(),
                "17841405822304914",
                "légende",
                &[video(b"x")],
                None,
                false,
                &opts(None),
            )
            .await
            .expect_err("limite");
        assert_eq!(err, ErreurPlateforme::LimitePublication);
        assert!(!err.to_string().contains("NE-DOIT-PAS-FUITER"));
        assert!(!err.to_string().contains("access_token"));
    }

    #[tokio::test]
    async fn la_page_publie_texte_photo_video_et_reel() {
        let (origine, st) = origine(false).await;
        let depot = Arc::new(DepotMedias::new());
        let page = FacebookPage::pour_essai("https://social.example", depot, &origine);
        let jeton = jeton();
        let texte = page
            .publier(&jeton, "123", "un texte", &[], None, false, &opts(None))
            .await
            .expect("texte");
        assert!(texte.url.contains("facebook.com"), "{}", texte.url);

        let photo = page
            .publier(
                &jeton,
                "123",
                "une photo",
                &[photo(b"img")],
                None,
                false,
                &opts(None),
            )
            .await
            .expect("photo");
        assert!(
            photo.id_plateforme.starts_with("55_"),
            "{}",
            photo.id_plateforme
        );

        let film = page
            .publier(
                &jeton,
                "123",
                "une video",
                &[video(b"vid")],
                None,
                false,
                &opts(Some(Placement::Flux)),
            )
            .await
            .expect("video");
        assert!(film.url.contains("facebook.com"));

        let mut reel_media = video(b"reel");
        reel_media.title = Some("Titre".into());
        let reel = page
            .publier(
                &jeton,
                "123",
                "un reel",
                &[reel_media],
                None,
                false,
                &opts(Some(Placement::Reel)),
            )
            .await
            .expect("reel");
        assert_eq!(reel.id_plateforme, "9001");
        assert!(reel.url.contains("facebook.com"));

        let journal = st.journal.lock().expect("journal").join("\n");
        assert!(journal.contains("/me/feed"), "{journal}");
        assert!(journal.contains("/me/photos"), "{journal}");
        assert!(journal.contains("file_url="), "{journal}");
        assert!(journal.contains("upload_phase=start"), "{journal}");
        assert!(journal.contains("PUBLISHED"), "{journal}");
        assert!(journal.contains("/video-upload/"), "{journal}");
    }

    #[tokio::test]
    async fn threads_publie_un_texte_et_une_video() {
        let (origine, st) = origine(false).await;
        let depot = Arc::new(DepotMedias::new());
        let threads = Threads::pour_essai("https://social.example", depot, &origine);
        let jeton = jeton();
        let texte = threads
            .publier(&jeton, "ada", "bonjour", &[], None, false, &opts(None))
            .await
            .expect("texte");
        assert!(texte.url.contains("threads.net"), "{}", texte.url);
        let video = threads
            .publier(
                &jeton,
                "ada",
                "clip",
                &[video(b"t")],
                None,
                false,
                &opts(None),
            )
            .await
            .expect("video");
        assert!(video.url.contains("threads.net"));
        let journal = st.journal.lock().expect("journal").join("\n");
        assert!(journal.contains("TEXT"), "{journal}");
        assert!(journal.contains("VIDEO"), "{journal}");
        assert!(journal.contains("threads_publish"), "{journal}");
        assert!(threads.metriques(&jeton, "1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn les_metriques_page_lisent_les_compteurs() {
        let (origine, _) = origine(false).await;
        let depot = Arc::new(DepotMedias::new());
        let page = FacebookPage::pour_essai("https://social.example", depot, &origine);
        let (ig, _) = adaptateur_ig(&origine);
        let m = page.metriques(&jeton(), "55_10").await.unwrap().unwrap();
        assert_eq!((m.likes, m.replies, m.reposts), (10, 2, 3));
        assert!(m.impressions.is_none());
        let igm = ig.metriques(&jeton(), "10").await.unwrap().unwrap();
        assert_eq!((igm.likes, igm.replies), (4, 1));
    }
}
