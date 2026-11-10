//! Gestion d'une chaîne YouTube : Data API v3 (chaîne, vidéos, playlists,
//! commentaires, captions) et Analytics v2 (`reports.query`).
//!
//! Relevés le 2026-11-10, en plus des citations du 2026-09-02 déjà dans
//! `youtube.rs` :
//!
//! * `channels.update` avec `part=brandingSettings` **remplace** l'objet
//!   entier (developers.google.com/youtube/v3/docs/channels/update). On
//!   relit, on n'écrase que les champs demandés, et on renvoie `image` et
//!   `watch` tels quels — sinon la bannière part avec la description.
//! * `videos.update` / `playlists.update` ont la même règle, par partie.
//!   `status.publishAt` n'est accepté que si `privacyStatus=private`.
//!   `madeForKids` est en lecture : l'écriture est `selfDeclaredMadeForKids`.
//! * `reports.query` (page datée 2026-10-15) : « API requests to this method
//!   now require access to the `youtube.readonly` scope », et les métriques
//!   d'activité passent par `yt-analytics.readonly`. Un jeton d'avant ces
//!   portées n'est pas un crash : [`scopes_analytics_ok`] est faux, et
//!   l'outil dit de reconnecter via `account_connect_url`.
//!
//! Ce que l'API ne permet pas, et qu'on ne simule pas :
//!
//! * les liens de la section À propos (site, réseaux) — pas de ressource ;
//! * les posts Communauté — pas de ressource ;
//! * la bannière — `channelBanners.insert` existe, on ne l'appelle pas.

use agentos_providers::Secret;
use serde_json::{Map, Value, json};

use super::youtube::{
    POINT_CHANNELS, POINT_COMMENT_THREADS, POINT_COMMENTS, POINT_PLAYLIST_ITEMS, POINT_VIDEOS,
};
use super::{ErreurPlateforme, envoyer, http, http_upload};

pub const POINT_PLAYLISTS: &str = "https://www.googleapis.com/youtube/v3/playlists";
pub const POINT_CAPTIONS: &str = "https://www.googleapis.com/youtube/v3/captions";
pub const POINT_CAPTIONS_UPLOAD: &str = "https://www.googleapis.com/upload/youtube/v3/captions";
pub const POINT_COMMENT_MODERATION: &str =
    "https://www.googleapis.com/youtube/v3/comments/setModerationStatus";
pub const POINT_ANALYTICS: &str = "https://youtubeanalytics.googleapis.com/v2/reports";
/// YouTube Reporting API v1 (bulk CSV), relevé le 2026-11-10.
pub const POINT_REPORTING: &str = "https://youtubereporting.googleapis.com/v1";

pub const SCOPE_READONLY: &str = "https://www.googleapis.com/auth/youtube.readonly";
pub const SCOPE_ANALYTICS: &str = "https://www.googleapis.com/auth/yt-analytics.readonly";
pub const SCOPE_ANALYTICS_MONETAIRE: &str =
    "https://www.googleapis.com/auth/yt-analytics-monetary.readonly";

/// Le mot exact rendu à l'agent. Il nomme `account_connect_url` : c'est le
/// seul geste qui réécrit les portées scellées.
pub const MESSAGE_RECONNEXION: &str = "ce compte YouTube a été connecté avant les portées Analytics \
     (youtube.readonly et yt-analytics.readonly) — reconnecter via account_connect_url";
/// Même geste, pour un type de rapport qui porte des revenus.
pub const MESSAGE_RECONNEXION_REVENU: &str = "ce type de rapport YouTube contient des revenus et exige \
     yt-analytics-monetary.readonly — reconnecter via account_connect_url";

pub const NON_SUPPORTE: &[&str] = &[
    "Liens de la section À propos (site, autres réseaux) : aucune ressource dans la Data API. Non supporté.",
    "Posts Communauté : aucune ressource dans la Data API. Non supporté.",
    "Bannière de chaîne : non supporté (channelBanners.insert n'est pas appelé ; channels.update préserve brandingSettings.image pour ne pas l'effacer).",
];

pub const COUT_LECTURE: u64 = 1;
pub const COUT_ECRITURE: u64 = 50;
pub const COUT_CAPTIONS_LIST: u64 = 50;
pub const COUT_CAPTIONS_INSERT: u64 = 400;
pub const COUT_CAPTIONS_DOWNLOAD: u64 = 200;
pub const COUT_CAPTIONS_DELETE: u64 = 50;

const METRIQUES_CHAINE: &str = "views,estimatedMinutesWatched,averageViewDuration,subscribersGained,subscribersLost,likes,comments,shares";
const METRIQUES_VIDEO: &str =
    "views,estimatedMinutesWatched,averageViewDuration,likes,comments,shares";

#[derive(Debug)]
pub enum EchecYoutube {
    Plateforme(ErreurPlateforme),
    ScopesInsuffisants,
    Argument(&'static str),
}

impl std::fmt::Display for EchecYoutube {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plateforme(e) => write!(f, "{e}"),
            Self::ScopesInsuffisants => f.write_str(MESSAGE_RECONNEXION),
            Self::Argument(m) => f.write_str(m),
        }
    }
}

impl EchecYoutube {
    pub fn est_401(&self) -> bool {
        matches!(
            self,
            Self::Plateforme(ErreurPlateforme::Refus { statut: 401 })
        )
    }
}

/// `None` (compte d'avant 0008) et l'ancien couple upload+force-ssl sont
/// insuffisants : la doc de `reports.query` exige `youtube.readonly` par son
/// nom, pas seulement un scope plus large.
pub fn scopes_analytics_ok(scopes: Option<&str>) -> bool {
    let Some(scopes) = scopes else {
        return false;
    };
    let porte = |attendu: &str| scopes.split_whitespace().any(|s| s == attendu);
    let analytics = porte(SCOPE_ANALYTICS) || porte(SCOPE_ANALYTICS_MONETAIRE);
    let lecture = porte(SCOPE_READONLY);
    analytics && lecture
}

/// Les rapports bulk non monétaires passent avec `yt-analytics.readonly`.
/// Le Reporting API ne redemande pas `youtube.readonly` (guide d'autorisation,
/// page datée 2026-11-05) : on garde pourtant le même contrôle que
/// `reports.query`, pour qu'un vieux jeton reçoive la même erreur.
pub fn scopes_reporting_ok(scopes: Option<&str>) -> bool {
    scopes_analytics_ok(scopes)
}

pub fn scopes_revenu_ok(scopes: Option<&str>) -> bool {
    scopes.is_some_and(|s| s.split_whitespace().any(|x| x == SCOPE_ANALYTICS_MONETAIRE))
}

/// Identifiants de types qui portent des revenus ou des performances pub
/// (channel/content-owner revenue, ad rates). Le reste du catalogue bulk
/// n'a pas besoin de la portée monétaire.
pub fn type_rapport_monetaire(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    id.contains("revenue")
        || id.contains("ad_rate")
        || id.contains("earning")
        || id.contains("monetary")
}

/// 403 « insufficient authentication scopes » — le corps ne sort pas de
/// cette fonction, seul le booléen. Un 403 de quota (`quotaExceeded`) reste
/// un refus de plateforme.
pub fn porte_scopes_insuffisants(statut: u16, corps: &[u8]) -> bool {
    if statut != 403 {
        return false;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(corps) else {
        return false;
    };
    let raison = doc
        .pointer("/error/errors/0/reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    if raison == "insufficientPermissions" || raison == "insufficientScopes" {
        return true;
    }
    doc.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("insufficient authentication scopes")
}

pub fn id_youtube(valeur: &str) -> bool {
    let n = valeur.len();
    (1..=128).contains(&n)
        && valeur
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(Debug, Default, Clone)]
pub struct PatchChaine {
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub country: Option<String>,
    pub default_language: Option<String>,
    pub unsubscribed_trailer: Option<String>,
}

impl PatchChaine {
    pub fn est_vide(&self) -> bool {
        self.description.is_none()
            && self.keywords.is_none()
            && self.country.is_none()
            && self.default_language.is_none()
            && self.unsubscribed_trailer.is_none()
    }
}

#[derive(Debug, Default, Clone)]
pub struct PatchVideo {
    pub title: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub category_id: Option<String>,
    pub made_for_kids: Option<bool>,
}

impl PatchVideo {
    fn touche_snippet(&self) -> bool {
        self.title.is_some()
            || self.description.is_some()
            || self.tags.is_some()
            || self.category_id.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct Visibilite {
    pub privacy: Option<String>,
    pub publish_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rapport<'a> {
    pub debut: &'a str,
    pub fin: &'a str,
    pub video_id: Option<&'a str>,
    pub metrics: Option<&'a str>,
    pub dimensions: Option<&'a str>,
}

pub fn valider_chaine(patch: &PatchChaine) -> Result<(), EchecYoutube> {
    if patch.est_vide() {
        return Err(EchecYoutube::Argument("aucun champ de chaîne à modifier"));
    }
    if let Some(d) = &patch.description
        && d.chars().count() > 1000
    {
        return Err(EchecYoutube::Argument(
            "description de chaîne : 1000 caractères maximum (brandingSettings.channel.description)",
        ));
    }
    if let Some(k) = &patch.keywords
        && k.chars().count() > 500
    {
        return Err(EchecYoutube::Argument(
            "keywords : 500 caractères maximum (brandingSettings.channel.keywords)",
        ));
    }
    if let Some(c) = &patch.country
        && (c.len() != 2 || !c.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return Err(EchecYoutube::Argument(
            "country : code ISO 3166-1 alpha-2 (brandingSettings.channel.country)",
        ));
    }
    if let Some(l) = &patch.default_language
        && !langue_ok(l)
    {
        return Err(EchecYoutube::Argument(
            "default_language : code BCP-47 court (ex. fr, en, pt-BR)",
        ));
    }
    if let Some(v) = &patch.unsubscribed_trailer
        && !id_youtube(v)
    {
        return Err(EchecYoutube::Argument(
            "unsubscribed_trailer : identifiant de vidéo YouTube",
        ));
    }
    Ok(())
}

pub fn valider_video(patch: &PatchVideo) -> Result<(), EchecYoutube> {
    if !patch.touche_snippet() && patch.made_for_kids.is_none() {
        return Err(EchecYoutube::Argument("aucun champ de vidéo à modifier"));
    }
    if let Some(t) = &patch.title
        && (t.is_empty() || t.chars().count() > 100)
    {
        return Err(EchecYoutube::Argument(
            "title : 1 à 100 caractères (videos snippet.title)",
        ));
    }
    if let Some(d) = &patch.description
        && d.chars().count() > 5000
    {
        return Err(EchecYoutube::Argument(
            "description : 5000 caractères maximum (videos snippet.description)",
        ));
    }
    if let Some(tags) = &patch.tags {
        let total: usize = tags.iter().map(|t| t.chars().count()).sum();
        if total > 500 {
            return Err(EchecYoutube::Argument(
                "tags : 500 caractères au total (videos snippet.tags)",
            ));
        }
    }
    if let Some(c) = &patch.category_id
        && (c.is_empty() || !c.bytes().all(|b| b.is_ascii_digit()) || c.len() > 3)
    {
        return Err(EchecYoutube::Argument(
            "category_id : identifiant numérique (videos snippet.categoryId)",
        ));
    }
    Ok(())
}

pub fn valider_visibilite(v: &Visibilite) -> Result<(), EchecYoutube> {
    if v.privacy.is_none() && v.publish_at.is_none() {
        return Err(EchecYoutube::Argument(
            "privacy ou publish_at est obligatoire",
        ));
    }
    if let Some(p) = &v.privacy
        && !matches!(p.as_str(), "private" | "public" | "unlisted")
    {
        return Err(EchecYoutube::Argument(
            "privacy : private, public ou unlisted",
        ));
    }
    if v.publish_at.is_some() && v.privacy.as_deref() == Some("public") {
        return Err(EchecYoutube::Argument(
            "publish_at n'est accepté que si privacy vaut private (videos status.publishAt)",
        ));
    }
    if v.publish_at.is_some() && v.privacy.as_deref() == Some("unlisted") {
        return Err(EchecYoutube::Argument(
            "publish_at n'est accepté que si privacy vaut private (videos status.publishAt)",
        ));
    }
    Ok(())
}

fn langue_ok(l: &str) -> bool {
    let mut morceaux = l.split('-');
    let Some(base) = morceaux.next() else {
        return false;
    };
    if !(2..=3).contains(&base.len()) || !base.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    match morceaux.next() {
        None => morceaux.next().is_none(),
        Some(region) => {
            (2..=8).contains(&region.len())
                && region.bytes().all(|b| b.is_ascii_alphanumeric())
                && morceaux.next().is_none()
        }
    }
}

pub fn date_ymd(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// Corps de `channels.update`. L'objet `brandingSettings` relu est recopié,
/// puis seuls les champs demandés écrasent `channel`.
pub fn corps_chaine(ressource: &Value, patch: &PatchChaine) -> Result<Value, EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let mut branding = ressource
        .get("brandingSettings")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !branding.is_object() {
        branding = json!({});
    }
    let canal = branding
        .as_object_mut()
        .expect("objet")
        .entry("channel")
        .or_insert_with(|| json!({}));
    if !canal.is_object() {
        *canal = json!({});
    }
    let ch = canal.as_object_mut().expect("objet");
    if let Some(v) = &patch.description {
        ch.insert("description".into(), json!(v));
    }
    if let Some(v) = &patch.keywords {
        ch.insert("keywords".into(), json!(v));
    }
    if let Some(v) = &patch.country {
        ch.insert("country".into(), json!(v.to_ascii_uppercase()));
    }
    if let Some(v) = &patch.default_language {
        ch.insert("defaultLanguage".into(), json!(v));
    }
    if let Some(v) = &patch.unsubscribed_trailer {
        ch.insert("unsubscribedTrailer".into(), json!(v));
    }
    Ok(json!({ "id": id, "brandingSettings": branding }))
}

fn copier_cles(source: &Value, cles: &[&str]) -> Map<String, Value> {
    let mut out = Map::new();
    for cle in cles {
        if let Some(v) = source.get(*cle)
            && !v.is_null()
        {
            out.insert((*cle).to_owned(), v.clone());
        }
    }
    out
}

/// `(part, corps)` de `videos.update`. On n'envoie que les parties touchées,
/// et seulement les champs écrivables — un champ en trop dans `snippet`
/// (thumbnails, channelId) fait rejeter l'appel.
pub fn corps_video(ressource: &Value, patch: &PatchVideo) -> Result<(String, Value), EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let mut parties = Vec::new();
    let mut corps = json!({ "id": id });
    if patch.touche_snippet() {
        let mut snippet = copier_cles(
            ressource.get("snippet").unwrap_or(&Value::Null),
            &[
                "title",
                "description",
                "tags",
                "categoryId",
                "defaultLanguage",
                "defaultAudioLanguage",
            ],
        );
        if let Some(v) = &patch.title {
            snippet.insert("title".into(), json!(v));
        }
        if let Some(v) = &patch.description {
            snippet.insert("description".into(), json!(v));
        }
        if let Some(v) = &patch.tags {
            snippet.insert("tags".into(), json!(v));
        }
        if let Some(v) = &patch.category_id {
            snippet.insert("categoryId".into(), json!(v));
        }
        let titre = snippet.get("title").and_then(Value::as_str).unwrap_or("");
        let categorie = snippet
            .get("categoryId")
            .and_then(Value::as_str)
            .unwrap_or("");
        if titre.is_empty() || categorie.is_empty() {
            return Err(EchecYoutube::Argument(
                "videos.update exige snippet.title et snippet.categoryId — la vidéo courante ne les a pas, passe title et category_id",
            ));
        }
        corps["snippet"] = Value::Object(snippet);
        parties.push("snippet");
    }
    if patch.made_for_kids.is_some() {
        let mut status = status_ecriture(ressource.get("status").unwrap_or(&Value::Null));
        if let Some(v) = patch.made_for_kids {
            status.insert("selfDeclaredMadeForKids".into(), json!(v));
        }
        corps["status"] = Value::Object(status);
        parties.push("status");
    }
    Ok((parties.join(","), corps))
}

fn status_ecriture(status: &Value) -> Map<String, Value> {
    let mut out = copier_cles(
        status,
        &[
            "privacyStatus",
            "embeddable",
            "license",
            "publicStatsViewable",
            "selfDeclaredMadeForKids",
            "containsSyntheticMedia",
        ],
    );
    // publishAt n'est légal qu'avec private. On ne le recopie pas sur une
    // vidéo publique : l'API rejetterait toute l'écriture.
    if out.get("privacyStatus").and_then(Value::as_str) == Some("private")
        && let Some(quand) = status.get("publishAt")
        && !quand.is_null()
    {
        out.insert("publishAt".into(), quand.clone());
    }
    out
}

pub fn corps_visibilite_video(
    ressource: &Value,
    visibilite: &Visibilite,
) -> Result<Value, EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let mut status = status_ecriture(ressource.get("status").unwrap_or(&Value::Null));
    let mut privacy = visibilite.privacy.clone();
    if visibilite.publish_at.is_some() {
        privacy = Some("private".to_owned());
    }
    if let Some(p) = privacy {
        status.insert("privacyStatus".into(), json!(p));
    }
    match &visibilite.publish_at {
        Some(quand) => {
            status.insert("publishAt".into(), json!(quand));
        }
        None => {
            if status.get("privacyStatus").and_then(Value::as_str) != Some("private") {
                status.remove("publishAt");
            }
        }
    }
    Ok(json!({ "id": id, "status": status }))
}

pub fn corps_playlist(titre: &str, description: Option<&str>, privacy: &str) -> Value {
    let mut snippet = json!({ "title": titre });
    if let Some(d) = description {
        snippet["description"] = json!(d);
    }
    json!({
        "snippet": snippet,
        "status": { "privacyStatus": privacy }
    })
}

pub fn corps_playlist_meta(
    ressource: &Value,
    titre: Option<&str>,
    description: Option<&str>,
) -> Result<Value, EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let mut snippet = copier_cles(
        ressource.get("snippet").unwrap_or(&Value::Null),
        &["title", "description", "defaultLanguage"],
    );
    if let Some(t) = titre {
        snippet.insert("title".into(), json!(t));
    }
    if let Some(d) = description {
        snippet.insert("description".into(), json!(d));
    }
    if snippet
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        return Err(EchecYoutube::Argument(
            "playlists.update exige snippet.title",
        ));
    }
    Ok(json!({ "id": id, "snippet": snippet }))
}

pub fn corps_playlist_visibilite(ressource: &Value, privacy: &str) -> Result<Value, EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    Ok(json!({
        "id": id,
        "status": { "privacyStatus": privacy }
    }))
}

pub fn corps_ajout_item(playlist_id: &str, video_id: &str, position: Option<u32>) -> Value {
    let mut snippet = json!({
        "playlistId": playlist_id,
        "resourceId": { "kind": "youtube#video", "videoId": video_id }
    });
    if let Some(p) = position {
        snippet["position"] = json!(p);
    }
    json!({ "snippet": snippet })
}

pub fn corps_reordonner(ressource: &Value, position: u32) -> Result<Value, EchecYoutube> {
    let id = ressource
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let playlist_id = ressource
        .pointer("/snippet/playlistId")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let resource_id = ressource
        .pointer("/snippet/resourceId")
        .cloned()
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    Ok(json!({
        "id": id,
        "snippet": {
            "playlistId": playlist_id,
            "resourceId": resource_id,
            "position": position
        }
    }))
}

pub fn parametres_rapport(rapport: &Rapport<'_>) -> Vec<(&'static str, String)> {
    let metrics = rapport.metrics.unwrap_or(if rapport.video_id.is_some() {
        METRIQUES_VIDEO
    } else {
        METRIQUES_CHAINE
    });
    let dimensions = rapport.dimensions.unwrap_or("day");
    let mut params = vec![
        ("ids", "channel==MINE".to_owned()),
        ("startDate", rapport.debut.to_owned()),
        ("endDate", rapport.fin.to_owned()),
        ("metrics", metrics.to_owned()),
        ("dimensions", dimensions.to_owned()),
    ];
    if let Some(video) = rapport.video_id {
        params.push(("filters", format!("video=={video}")));
    }
    if let Some(premier) = dimensions.split(',').next()
        && !premier.is_empty()
    {
        params.push(("sort", premier.to_owned()));
    }
    params
}

fn chaine_projetee(item: &Value) -> Value {
    let canal = item.pointer("/brandingSettings/channel");
    json!({
        "channel_id": item.get("id").and_then(Value::as_str).unwrap_or(""),
        "title": item.pointer("/snippet/title").and_then(Value::as_str).unwrap_or(""),
        "custom_url": item.pointer("/snippet/customUrl").and_then(Value::as_str),
        "description": canal.and_then(|c| c.get("description")).and_then(Value::as_str).unwrap_or(""),
        "keywords": canal.and_then(|c| c.get("keywords")).and_then(Value::as_str).unwrap_or(""),
        "country": canal.and_then(|c| c.get("country")).and_then(Value::as_str),
        "default_language": canal.and_then(|c| c.get("defaultLanguage")).and_then(Value::as_str),
        "unsubscribed_trailer": canal.and_then(|c| c.get("unsubscribedTrailer")).and_then(Value::as_str),
        "uploads_playlist": item.pointer("/contentDetails/relatedPlaylists/uploads").and_then(Value::as_str),
        "cout_quota": COUT_LECTURE,
        "unsupported": NON_SUPPORTE,
    })
}

fn premier_item(doc: &Value) -> Result<&Value, EchecYoutube> {
    doc.pointer("/items/0")
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Refus {
            statut: 404,
        }))
}

async fn echanger(requete: reqwest::RequestBuilder) -> Result<(u16, Vec<u8>), EchecYoutube> {
    let (statut, corps) = envoyer(requete).await.map_err(EchecYoutube::Plateforme)?;
    if porte_scopes_insuffisants(statut, &corps) {
        return Err(EchecYoutube::ScopesInsuffisants);
    }
    if let Some(erreur) = ErreurPlateforme::depuis_statut(statut) {
        return Err(EchecYoutube::Plateforme(erreur));
    }
    Ok((statut, corps))
}

fn document(corps: &[u8]) -> Result<Value, EchecYoutube> {
    serde_json::from_slice(corps).map_err(|_| EchecYoutube::Plateforme(ErreurPlateforme::Illisible))
}

fn jeton(requete: reqwest::RequestBuilder, secret: &Secret) -> reqwest::RequestBuilder {
    requete.bearer_auth(secret.expose_for_transport())
}

pub async fn lire_chaine(
    point: &str,
    secret: &Secret,
    channel_id: Option<&str>,
) -> Result<Value, EchecYoutube> {
    let mut requete = jeton(http().get(point), secret)
        .query(&[("part", "snippet,brandingSettings,contentDetails")]);
    requete = match channel_id {
        Some(id) => requete.query(&[("id", id)]),
        None => requete.query(&[("mine", "true")]),
    };
    let (_statut, corps) = echanger(requete).await?;
    let doc = document(&corps)?;
    Ok(chaine_projetee(premier_item(&doc)?))
}

pub async fn ecrire_chaine(
    point: &str,
    secret: &Secret,
    channel_id: &str,
    patch: &PatchChaine,
) -> Result<Value, EchecYoutube> {
    valider_chaine(patch)?;
    let lecture = jeton(http().get(point), secret)
        .query(&[("part", "snippet,brandingSettings"), ("id", channel_id)]);
    let (_s, corps) = echanger(lecture).await?;
    let doc = document(&corps)?;
    let ressource = premier_item(&doc)?.clone();
    let corps_envoi = corps_chaine(&ressource, patch)?;
    let (_s, corps) = echanger(
        jeton(http().put(point), secret)
            .query(&[("part", "brandingSettings")])
            .json(&corps_envoi),
    )
    .await?;
    let rendu = document(&corps)?;
    Ok(json!({
        "channel_id": rendu.get("id").and_then(Value::as_str).unwrap_or(channel_id),
        "description": rendu.pointer("/brandingSettings/channel/description").and_then(Value::as_str),
        "keywords": rendu.pointer("/brandingSettings/channel/keywords").and_then(Value::as_str),
        "country": rendu.pointer("/brandingSettings/channel/country").and_then(Value::as_str),
        "default_language": rendu.pointer("/brandingSettings/channel/defaultLanguage").and_then(Value::as_str),
        "unsubscribed_trailer": rendu.pointer("/brandingSettings/channel/unsubscribedTrailer").and_then(Value::as_str),
        "cout_quota": COUT_LECTURE + COUT_ECRITURE,
    }))
}

pub async fn ecrire_video(
    point: &str,
    secret: &Secret,
    video_id: &str,
    patch: &PatchVideo,
) -> Result<Value, EchecYoutube> {
    valider_video(patch)?;
    let ressource = lire_ressource(point, secret, video_id, "snippet,status").await?;
    let (part, corps_envoi) = corps_video(&ressource, patch)?;
    let (_s, corps) = echanger(
        jeton(http().put(point), secret)
            .query(&[("part", part.as_str())])
            .json(&corps_envoi),
    )
    .await?;
    let rendu = document(&corps)?;
    Ok(video_projetee(&rendu, COUT_LECTURE + COUT_ECRITURE))
}

pub async fn ecrire_visibilite_video(
    point: &str,
    secret: &Secret,
    video_id: &str,
    visibilite: &Visibilite,
) -> Result<Value, EchecYoutube> {
    valider_visibilite(visibilite)?;
    let ressource = lire_ressource(point, secret, video_id, "status").await?;
    let corps_envoi = corps_visibilite_video(&ressource, visibilite)?;
    let (_s, corps) = echanger(
        jeton(http().put(point), secret)
            .query(&[("part", "status")])
            .json(&corps_envoi),
    )
    .await?;
    let rendu = document(&corps)?;
    Ok(video_projetee(&rendu, COUT_LECTURE + COUT_ECRITURE))
}

fn video_projetee(item: &Value, cout: u64) -> Value {
    json!({
        "video_id": item.get("id").and_then(Value::as_str).unwrap_or(""),
        "title": item.pointer("/snippet/title").and_then(Value::as_str),
        "privacy": item.pointer("/status/privacyStatus").and_then(Value::as_str),
        "publish_at": item.pointer("/status/publishAt").and_then(Value::as_str),
        "made_for_kids": item.pointer("/status/selfDeclaredMadeForKids").and_then(Value::as_bool),
        "cout_quota": cout,
    })
}

pub async fn supprimer(
    point: &str,
    secret: &Secret,
    id: &str,
    cout: u64,
) -> Result<Value, EchecYoutube> {
    let (statut, _corps) =
        echanger(jeton(http().delete(point), secret).query(&[("id", id)])).await?;
    Ok(json!({ "id": id, "deleted": true, "statut": statut, "cout_quota": cout }))
}

async fn lire_ressource(
    point: &str,
    secret: &Secret,
    id: &str,
    part: &str,
) -> Result<Value, EchecYoutube> {
    let (_s, corps) =
        echanger(jeton(http().get(point), secret).query(&[("part", part), ("id", id)])).await?;
    let doc = document(&corps)?;
    Ok(premier_item(&doc)?.clone())
}

pub async fn lister(
    point: &str,
    secret: &Secret,
    query: &[(&str, &str)],
    cout: u64,
) -> Result<Value, EchecYoutube> {
    let (_s, corps) = echanger(jeton(http().get(point), secret).query(query)).await?;
    let doc = document(&corps)?;
    Ok(json!({
        "items": doc.get("items").cloned().unwrap_or_else(|| json!([])),
        "next_page_token": doc.get("nextPageToken").and_then(Value::as_str),
        "cout_quota": cout,
    }))
}

pub fn playlists_projetees(brut: &Value) -> Value {
    let items = brut
        .get("items")
        .and_then(Value::as_array)
        .map(|liste| {
            liste
                .iter()
                .map(|e| {
                    json!({
                        "playlist_id": e.get("id").and_then(Value::as_str).unwrap_or(""),
                        "title": e.pointer("/snippet/title").and_then(Value::as_str).unwrap_or(""),
                        "description": e.pointer("/snippet/description").and_then(Value::as_str).unwrap_or(""),
                        "privacy": e.pointer("/status/privacyStatus").and_then(Value::as_str),
                        "item_count": e.pointer("/contentDetails/itemCount").and_then(Value::as_u64),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "playlists": items,
        "next_page_token": brut.get("next_page_token"),
        "cout_quota": brut.get("cout_quota"),
    })
}

pub fn items_projetes(brut: &Value) -> Value {
    let items = brut
        .get("items")
        .and_then(Value::as_array)
        .map(|liste| {
            liste
                .iter()
                .map(|e| {
                    json!({
                        "playlist_item_id": e.get("id").and_then(Value::as_str).unwrap_or(""),
                        "video_id": e.pointer("/snippet/resourceId/videoId").and_then(Value::as_str).unwrap_or(""),
                        "title": e.pointer("/snippet/title").and_then(Value::as_str).unwrap_or(""),
                        "position": e.pointer("/snippet/position").and_then(Value::as_u64),
                        "playlist_id": e.pointer("/snippet/playlistId").and_then(Value::as_str),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "items": items,
        "next_page_token": brut.get("next_page_token"),
        "cout_quota": brut.get("cout_quota"),
    })
}

pub fn fils_projetes(brut: &Value) -> Value {
    let items = brut
        .get("items")
        .and_then(Value::as_array)
        .map(|liste| liste.iter().filter_map(fil_projete).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "threads": items,
        "next_page_token": brut.get("next_page_token"),
        "cout_quota": brut.get("cout_quota"),
    })
}

fn fil_projete(item: &Value) -> Option<Value> {
    let top = item.pointer("/snippet/topLevelComment")?;
    let mut reponses = Vec::new();
    if let Some(liste) = item.pointer("/replies/comments").and_then(Value::as_array) {
        for c in liste {
            reponses.push(commentaire_projete(c));
        }
    }
    Some(json!({
        "thread_id": item.get("id").and_then(Value::as_str).unwrap_or(""),
        "video_id": item.pointer("/snippet/videoId").and_then(Value::as_str),
        "comment_id": top.get("id").and_then(Value::as_str).unwrap_or(""),
        "text": top.pointer("/snippet/textOriginal").and_then(Value::as_str).unwrap_or(""),
        "author": top.pointer("/snippet/authorDisplayName").and_then(Value::as_str).unwrap_or(""),
        "published_at": top.pointer("/snippet/publishedAt").and_then(Value::as_str),
        "like_count": top.pointer("/snippet/likeCount").and_then(Value::as_u64).unwrap_or(0),
        "reply_count": item.pointer("/snippet/totalReplyCount").and_then(Value::as_u64).unwrap_or(0),
        "moderation_status": top.pointer("/snippet/moderationStatus").and_then(Value::as_str),
        "third_party": true,
        "replies": reponses,
    }))
}

fn commentaire_projete(c: &Value) -> Value {
    json!({
        "comment_id": c.get("id").and_then(Value::as_str).unwrap_or(""),
        "text": c.pointer("/snippet/textOriginal").and_then(Value::as_str).unwrap_or(""),
        "author": c.pointer("/snippet/authorDisplayName").and_then(Value::as_str).unwrap_or(""),
        "published_at": c.pointer("/snippet/publishedAt").and_then(Value::as_str),
        "parent_id": c.pointer("/snippet/parentId").and_then(Value::as_str),
        "third_party": true,
    })
}

pub fn captions_projetees(brut: &Value) -> Value {
    let items = brut
        .get("items")
        .and_then(Value::as_array)
        .map(|liste| {
            liste
                .iter()
                .map(|e| {
                    json!({
                        "caption_id": e.get("id").and_then(Value::as_str).unwrap_or(""),
                        "video_id": e.pointer("/snippet/videoId").and_then(Value::as_str),
                        "language": e.pointer("/snippet/language").and_then(Value::as_str),
                        "name": e.pointer("/snippet/name").and_then(Value::as_str),
                        "track_kind": e.pointer("/snippet/trackKind").and_then(Value::as_str),
                        "is_draft": e.pointer("/snippet/isDraft").and_then(Value::as_bool),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "captions": items,
        "cout_quota": brut.get("cout_quota"),
    })
}

pub fn corps_commentaire_racine(channel_id: &str, video_id: &str, texte: &str) -> Value {
    super::youtube::corps_comment_thread(channel_id, video_id, texte)
}

pub fn corps_commentaire_suite(parent_id: &str, texte: &str) -> Value {
    super::youtube::corps_comment_reply(parent_id, texte)
}

pub async fn inserer_put(
    point: &str,
    secret: &Secret,
    part: &str,
    corps_envoi: &Value,
    cout: u64,
) -> Result<Value, EchecYoutube> {
    let (_s, corps) = echanger(
        jeton(http().put(point), secret)
            .query(&[("part", part)])
            .json(corps_envoi),
    )
    .await?;
    let mut rendu = document(&corps)?;
    if let Some(obj) = rendu.as_object_mut() {
        obj.insert("cout_quota".into(), json!(cout));
    }
    Ok(rendu)
}

pub async fn inserer(
    point: &str,
    secret: &Secret,
    part: &str,
    corps_envoi: &Value,
    cout: u64,
) -> Result<Value, EchecYoutube> {
    let (_s, corps) = echanger(
        jeton(http().post(point), secret)
            .query(&[("part", part)])
            .json(corps_envoi),
    )
    .await?;
    let rendu = document(&corps)?;
    let mut sortie = rendu.clone();
    if let Some(obj) = sortie.as_object_mut() {
        obj.insert("cout_quota".into(), json!(cout));
    }
    Ok(sortie)
}

pub async fn moderer(
    point: &str,
    secret: &Secret,
    comment_id: &str,
    statut: &str,
    ban_author: bool,
) -> Result<Value, EchecYoutube> {
    if !matches!(statut, "heldForReview" | "published" | "rejected") {
        return Err(EchecYoutube::Argument(
            "moderation_status : heldForReview, published ou rejected",
        ));
    }
    let ban = if ban_author { "true" } else { "false" };
    let (http_statut, _corps) = echanger(jeton(http().post(point), secret).query(&[
        ("id", comment_id),
        ("moderationStatus", statut),
        ("banAuthor", ban),
    ]))
    .await?;
    Ok(json!({
        "comment_id": comment_id,
        "moderation_status": statut,
        "ban_author": ban_author,
        "statut": http_statut,
        "cout_quota": COUT_ECRITURE,
    }))
}

pub fn multipart_caption(meta: &Value, texte: &str) -> Result<(String, Vec<u8>), EchecYoutube> {
    const BORNE: &str = "agentos-yt-caption-7f3c9a";
    if texte.contains(BORNE) {
        return Err(EchecYoutube::Argument(
            "le fichier de sous-titres contient la borne multipart",
        ));
    }
    let meta = serde_json::to_string(meta)
        .map_err(|_| EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let mut corps = Vec::new();
    let entete = format!(
        "--{BORNE}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n--{BORNE}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
    );
    corps.extend(entete.as_bytes());
    corps.extend(texte.as_bytes());
    corps.extend(format!("\r\n--{BORNE}--\r\n").as_bytes());
    Ok((format!("multipart/related; boundary={BORNE}"), corps))
}

pub fn meta_caption(video_id: &str, langue: &str, nom: &str, brouillon: bool) -> Value {
    json!({
        "snippet": {
            "videoId": video_id,
            "language": langue,
            "name": nom,
            "isDraft": brouillon
        }
    })
}

pub async fn televerser_caption(
    point: &str,
    secret: &Secret,
    video_id: &str,
    langue: &str,
    nom: &str,
    texte: &str,
    brouillon: bool,
) -> Result<Value, EchecYoutube> {
    if !langue_ok(langue) {
        return Err(EchecYoutube::Argument(
            "language : code BCP-47 court (ex. fr, en)",
        ));
    }
    if texte.is_empty() || texte.len() > 1_000_000 {
        return Err(EchecYoutube::Argument(
            "content : sous-titres non vides, 1 000 000 octets maximum",
        ));
    }
    let meta = meta_caption(video_id, langue, nom, brouillon);
    let (content_type, octets) = multipart_caption(&meta, texte)?;
    let (_s, corps) = echanger(
        jeton(http_upload().post(point), secret)
            .query(&[("part", "snippet"), ("uploadType", "multipart")])
            .header("content-type", content_type)
            .body(octets),
    )
    .await?;
    let rendu = document(&corps)?;
    Ok(json!({
        "caption_id": rendu.get("id").and_then(Value::as_str).unwrap_or(""),
        "video_id": video_id,
        "language": langue,
        "name": nom,
        "is_draft": brouillon,
        "cout_quota": COUT_CAPTIONS_INSERT,
    }))
}

pub async fn telecharger_caption(
    point: &str,
    secret: &Secret,
    caption_id: &str,
    format: &str,
) -> Result<Value, EchecYoutube> {
    if !matches!(format, "srt" | "vtt" | "sbv" | "ttml") {
        return Err(EchecYoutube::Argument("format : srt, vtt, sbv ou ttml"));
    }
    let url = format!("{point}/{caption_id}");
    let (statut, corps) =
        echanger(jeton(http().get(&url), secret).query(&[("tfmt", format)])).await?;
    let texte = String::from_utf8(corps)
        .map_err(|_| EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    Ok(json!({
        "caption_id": caption_id,
        "format": format,
        "body": texte,
        "statut": statut,
        "cout_quota": COUT_CAPTIONS_DOWNLOAD,
    }))
}

pub async fn rapport(
    point: &str,
    secret: &Secret,
    demande: &Rapport<'_>,
) -> Result<Value, EchecYoutube> {
    if !date_ymd(demande.debut) || !date_ymd(demande.fin) {
        return Err(EchecYoutube::Argument(
            "start_date et end_date : AAAA-MM-JJ",
        ));
    }
    if demande.debut > demande.fin {
        return Err(EchecYoutube::Argument("start_date est après end_date"));
    }
    let params = parametres_rapport(demande);
    let paires: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (_s, corps) = echanger(jeton(http().get(point), secret).query(&paires)).await?;
    let doc = document(&corps)?;
    Ok(json!({
        "start_date": demande.debut,
        "end_date": demande.fin,
        "video_id": demande.video_id,
        "column_headers": doc.get("columnHeaders").cloned().unwrap_or_else(|| json!([])),
        "rows": doc.get("rows").cloned().unwrap_or_else(|| json!([])),
        "cout_quota": null,
        "note": "YouTube Analytics a son propre quota, distinct des unités Data API",
    }))
}

pub const OCTETS_MAX_RAPPORT: usize = 8 * 1024 * 1024;
pub const LIGNES_RAPPORT_RENDUES: usize = 200;

/// Hôtes sur lesquels on accepte de rejouer le jeton du compte. Un
/// `downloadUrl` ailleurs n'est pas téléchargé : le Bearer ne sort pas.
const HOTES_RAPPORT: &[&str] = &[
    "youtubereporting.googleapis.com",
    "youtube.googleapis.com",
    "www.googleapis.com",
    "storage.googleapis.com",
];

pub fn url_rapport_autorisee(url: &str) -> bool {
    let Ok(parse) = url::Url::parse(url) else {
        return false;
    };
    let hote = parse.host_str().unwrap_or("");
    let hote_ok = HOTES_RAPPORT.contains(&hote) || (cfg!(test) && hote == "127.0.0.1");
    // En test, le mock est en http sur la boucle locale. Ailleurs : https seul.
    let scheme_ok = parse.scheme() == "https"
        || (cfg!(test) && parse.scheme() == "http" && hote == "127.0.0.1");
    hote_ok && scheme_ok
}

/// CSV YouTube (en-tête + lignes). Les guillemets doublés sont un guillemet.
pub fn parser_csv(texte: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let texte = texte.strip_prefix('\u{feff}').unwrap_or(texte);
    let mut lignes = Vec::new();
    let mut courante = String::new();
    let mut guillemets = false;
    for c in texte.chars() {
        if c == '"' {
            guillemets = !guillemets;
            courante.push(c);
        } else if c == '\n' && !guillemets {
            if courante.ends_with('\r') {
                courante.pop();
            }
            if !courante.is_empty() {
                lignes.push(std::mem::take(&mut courante));
            }
        } else {
            courante.push(c);
        }
    }
    if !courante.is_empty() && courante != "\r" {
        if courante.ends_with('\r') {
            courante.pop();
        }
        lignes.push(courante);
    }
    let mut champs = lignes.into_iter().map(|l| champs_csv(&l));
    let colonnes = champs.next().unwrap_or_default();
    let rangees: Vec<Vec<String>> = champs.collect();
    (colonnes, rangees)
}

fn champs_csv(ligne: &str) -> Vec<String> {
    let mut champs = Vec::new();
    let mut cur = String::new();
    let mut guillemets = false;
    let mut chars = ligne.chars().peekable();
    while let Some(c) = chars.next() {
        if guillemets {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    guillemets = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' && cur.is_empty() {
            guillemets = true;
        } else if c == ',' {
            champs.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    champs.push(cur);
    champs
}

fn job_projete(job: &Value) -> Value {
    json!({
        "job_id": job.get("id").and_then(Value::as_str).unwrap_or(""),
        "name": job.get("name").and_then(Value::as_str).unwrap_or(""),
        "report_type_id": job.get("reportTypeId").and_then(Value::as_str).unwrap_or(""),
        "create_time": job.get("createTime").and_then(Value::as_str),
    })
}

pub async fn lister_types_rapport(
    base: &str,
    secret: &Secret,
    page_token: Option<&str>,
    page_size: u32,
    systeme: bool,
) -> Result<Value, EchecYoutube> {
    let mut q = vec![
        ("pageSize".to_owned(), page_size.to_string()),
        (
            "includeSystemManaged".to_owned(),
            if systeme { "true" } else { "false" }.to_owned(),
        ),
    ];
    if let Some(token) = page_token {
        q.push(("pageToken".into(), token.to_owned()));
    }
    let paires = paires_owned(&q);
    let (_s, corps) =
        echanger(jeton(http().get(format!("{base}/reportTypes")), secret).query(&paires)).await?;
    let doc = document(&corps)?;
    let types = doc
        .get("reportTypes")
        .and_then(Value::as_array)
        .map(|liste| {
            liste
                .iter()
                .map(|t| {
                    let id = t.get("id").and_then(Value::as_str).unwrap_or("");
                    json!({
                        "id": id,
                        "name": t.get("name").and_then(Value::as_str).unwrap_or(""),
                        "monetary": type_rapport_monetaire(id),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "report_types": types,
        "next_page_token": doc.get("nextPageToken").and_then(Value::as_str),
    }))
}

pub async fn creer_job_rapport(
    base: &str,
    secret: &Secret,
    report_type_id: &str,
    nom: Option<&str>,
) -> Result<Value, EchecYoutube> {
    if !id_youtube(report_type_id) {
        return Err(EchecYoutube::Argument("report_type_id invalide"));
    }
    let mut corps = json!({ "reportTypeId": report_type_id });
    if let Some(nom) = nom {
        if nom.chars().count() > 100 {
            return Err(EchecYoutube::Argument("name : 100 caractères maximum"));
        }
        corps["name"] = json!(nom);
    }
    let (_s, octets) =
        echanger(jeton(http().post(format!("{base}/jobs")), secret).json(&corps)).await?;
    Ok(job_projete(&document(&octets)?))
}

pub async fn lister_jobs_rapport(
    base: &str,
    secret: &Secret,
    page_token: Option<&str>,
    page_size: u32,
) -> Result<Value, EchecYoutube> {
    let mut q = vec![("pageSize".to_owned(), page_size.to_string())];
    if let Some(token) = page_token {
        q.push(("pageToken".into(), token.to_owned()));
    }
    let paires = paires_owned(&q);
    let (_s, corps) =
        echanger(jeton(http().get(format!("{base}/jobs")), secret).query(&paires)).await?;
    let doc = document(&corps)?;
    let jobs = doc
        .get("jobs")
        .and_then(Value::as_array)
        .map(|liste| liste.iter().map(job_projete).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(json!({
        "jobs": jobs,
        "next_page_token": doc.get("nextPageToken").and_then(Value::as_str),
    }))
}

pub async fn supprimer_job_rapport(
    base: &str,
    secret: &Secret,
    job_id: &str,
) -> Result<Value, EchecYoutube> {
    if !id_youtube(job_id) {
        return Err(EchecYoutube::Argument("job_id invalide"));
    }
    let (statut, _corps) = echanger(jeton(
        http().delete(format!("{base}/jobs/{job_id}")),
        secret,
    ))
    .await?;
    Ok(json!({ "job_id": job_id, "deleted": true, "statut": statut }))
}

pub async fn lister_rapports_job(
    base: &str,
    secret: &Secret,
    job_id: &str,
    page_token: Option<&str>,
    page_size: u32,
) -> Result<Value, EchecYoutube> {
    if !id_youtube(job_id) {
        return Err(EchecYoutube::Argument("job_id invalide"));
    }
    let mut q = vec![("pageSize".to_owned(), page_size.to_string())];
    if let Some(token) = page_token {
        q.push(("pageToken".into(), token.to_owned()));
    }
    let paires = paires_owned(&q);
    let (_s, corps) =
        echanger(jeton(http().get(format!("{base}/jobs/{job_id}/reports")), secret).query(&paires))
            .await?;
    let doc = document(&corps)?;
    let rapports = doc
        .get("reports")
        .and_then(Value::as_array)
        .map(|liste| {
            liste
                .iter()
                .map(|r| {
                    json!({
                        "report_id": r.get("id").and_then(Value::as_str).unwrap_or(""),
                        "job_id": r.get("jobId").and_then(Value::as_str).unwrap_or(job_id),
                        "start_time": r.get("startTime").and_then(Value::as_str),
                        "end_time": r.get("endTime").and_then(Value::as_str),
                        "create_time": r.get("createTime").and_then(Value::as_str),
                        "downloadable": r.get("downloadUrl").and_then(Value::as_str).is_some(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "reports": rapports,
        "next_page_token": doc.get("nextPageToken").and_then(Value::as_str),
    }))
}

/// `reports.get` puis GET du `downloadUrl` avec le jeton du compte. Le CSV
/// n'est pas déposé sur `/medias` : cette route est publique et sans auth,
/// elle sert les octets d'une publication, pas un rapport de chaîne. Le
/// `digest` est le SHA-256 des octets, la même empreinte que les médias.
pub async fn telecharger_rapport(
    base: &str,
    secret: &Secret,
    job_id: &str,
    report_id: &str,
) -> Result<Value, EchecYoutube> {
    if !id_youtube(job_id) || !id_youtube(report_id) {
        return Err(EchecYoutube::Argument("identifiant de rapport invalide"));
    }
    let (_s, corps) = echanger(jeton(
        http().get(format!("{base}/jobs/{job_id}/reports/{report_id}")),
        secret,
    ))
    .await?;
    let doc = document(&corps)?;
    let url = doc
        .get("downloadUrl")
        .and_then(Value::as_str)
        .ok_or(EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    if !url_rapport_autorisee(url) {
        return Err(EchecYoutube::Argument(
            "downloadUrl hors des hôtes YouTube Reporting — le jeton n'est pas envoyé",
        ));
    }
    let (_s, octets) = echanger(jeton(http().get(url), secret)).await?;
    if octets.len() > OCTETS_MAX_RAPPORT {
        return Err(EchecYoutube::Argument(
            "rapport au-dessus de 8 Mio — refusé avant d'être rendu",
        ));
    }
    let texte = String::from_utf8(octets)
        .map_err(|_| EchecYoutube::Plateforme(ErreurPlateforme::Illisible))?;
    let (colonnes, rangees) = parser_csv(&texte);
    let total = rangees.len();
    let tronque = total > LIGNES_RAPPORT_RENDUES;
    let rendu: Vec<&Vec<String>> = rangees.iter().take(LIGNES_RAPPORT_RENDUES).collect();
    Ok(json!({
        "job_id": job_id,
        "report_id": report_id,
        "digest": super::empreinte(&texte),
        "byte_size": texte.len(),
        "columns": colonnes,
        "rows": rendu,
        "row_count": total,
        "truncated": tronque,
    }))
}

fn paires_owned(q: &[(String, String)]) -> Vec<(&str, &str)> {
    q.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// Les points officiels, pour les tests qui vérifient le schéma d'URL.
pub fn points_officiels() -> [&'static str; 12] {
    [
        POINT_CHANNELS,
        POINT_VIDEOS,
        POINT_PLAYLISTS,
        POINT_PLAYLIST_ITEMS,
        POINT_COMMENT_THREADS,
        POINT_COMMENTS,
        POINT_COMMENT_MODERATION,
        POINT_CAPTIONS,
        POINT_CAPTIONS_UPLOAD,
        POINT_ANALYTICS,
        POINT_REPORTING,
        "https://www.googleapis.com/youtube/v3/captions",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ressource_chaine() -> Value {
        json!({
            "id": "UCabc",
            "brandingSettings": {
                "channel": {
                    "title": "Ma chaîne",
                    "description": "ancien",
                    "keywords": "voyage \"afrique du sud\"",
                    "country": "FR",
                    "moderateComments": true
                },
                "image": { "bannerExternalUrl": "https://yt.example/banner" },
                "watch": { "textColor": "red" }
            }
        })
    }

    #[test]
    fn les_anciennes_portees_ne_suffisent_pas_a_analytics() {
        assert!(!scopes_analytics_ok(None));
        assert!(!scopes_analytics_ok(Some(
            "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.force-ssl"
        )));
        assert!(!scopes_analytics_ok(Some(SCOPE_ANALYTICS)));
        assert!(!scopes_analytics_ok(Some(SCOPE_READONLY)));
        assert!(scopes_analytics_ok(Some(
            "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.force-ssl https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/yt-analytics.readonly"
        )));
        assert!(scopes_analytics_ok(Some(
            "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/yt-analytics-monetary.readonly"
        )));
        assert!(MESSAGE_RECONNEXION.contains("account_connect_url"));
    }

    #[test]
    fn un_403_de_quota_n_est_pas_un_probleme_de_portees() {
        let quota = br#"{"error":{"errors":[{"reason":"quotaExceeded"}],"message":"quota"}}"#;
        assert!(!porte_scopes_insuffisants(403, quota));
        let scopes = br#"{"error":{"errors":[{"reason":"insufficientPermissions","message":"TOKEN-NE-DOIT-PAS-FUIR"}],"message":"Request had insufficient authentication scopes."}}"#;
        assert!(porte_scopes_insuffisants(403, scopes));
        let rendu = EchecYoutube::ScopesInsuffisants.to_string();
        assert!(rendu.contains("account_connect_url"));
        assert!(!rendu.contains("TOKEN-NE-DOIT-PAS-FUIR"));
        assert!(!porte_scopes_insuffisants(401, scopes));
    }

    #[test]
    fn la_mise_a_jour_de_chaine_preserve_le_reste_de_la_partie() {
        let patch = PatchChaine {
            description: Some("nouveau".into()),
            ..PatchChaine::default()
        };
        let corps = corps_chaine(&ressource_chaine(), &patch).unwrap();
        assert_eq!(corps["id"], "UCabc");
        assert_eq!(
            corps["brandingSettings"]["channel"]["description"],
            "nouveau"
        );
        assert_eq!(
            corps["brandingSettings"]["channel"]["keywords"],
            "voyage \"afrique du sud\""
        );
        assert_eq!(corps["brandingSettings"]["channel"]["country"], "FR");
        assert_eq!(
            corps["brandingSettings"]["channel"]["moderateComments"],
            true
        );
        assert_eq!(
            corps["brandingSettings"]["image"]["bannerExternalUrl"],
            "https://yt.example/banner"
        );
        assert_eq!(corps["brandingSettings"]["watch"]["textColor"], "red");
        assert!(corps.get("snippet").is_none());
    }

    #[test]
    fn la_video_n_envoie_que_la_partie_touchee_et_garde_le_titre() {
        let ressource = json!({
            "id": "vid1",
            "snippet": {
                "title": "Ancien",
                "description": "d",
                "categoryId": "22",
                "channelId": "UCabc",
                "thumbnails": { "default": { "url": "https://i.ytimg.example/x" } },
                "tags": ["a"]
            },
            "status": { "privacyStatus": "public", "publishAt": "2020-01-01T00:00:00Z" }
        });
        let patch = PatchVideo {
            description: Some("neuf".into()),
            ..PatchVideo::default()
        };
        let (part, corps) = corps_video(&ressource, &patch).unwrap();
        assert_eq!(part, "snippet");
        assert!(corps.get("status").is_none());
        assert_eq!(corps["snippet"]["title"], "Ancien");
        assert_eq!(corps["snippet"]["description"], "neuf");
        assert_eq!(corps["snippet"]["categoryId"], "22");
        assert!(corps["snippet"].get("channelId").is_none());
        assert!(corps["snippet"].get("thumbnails").is_none());
        // publishAt d'une vidéo publique ne doit pas revenir dans un status.
        let enfants = PatchVideo {
            made_for_kids: Some(false),
            ..PatchVideo::default()
        };
        let (part, corps) = corps_video(&ressource, &enfants).unwrap();
        assert_eq!(part, "status");
        assert!(corps["status"].get("publishAt").is_none());
        assert_eq!(corps["status"]["privacyStatus"], "public");
        assert_eq!(corps["status"]["selfDeclaredMadeForKids"], false);
    }

    #[test]
    fn publish_at_force_private_et_une_video_publique_perd_l_ancienne_date() {
        let ressource = json!({
            "id": "vid1",
            "status": { "privacyStatus": "public", "license": "youtube", "publishAt": "2020-01-01T00:00:00Z" }
        });
        let vis = Visibilite {
            privacy: Some("private".into()),
            publish_at: Some("2026-12-01T09:00:00Z".into()),
        };
        let corps = corps_visibilite_video(&ressource, &vis).unwrap();
        assert_eq!(corps["status"]["privacyStatus"], "private");
        assert_eq!(corps["status"]["publishAt"], "2026-12-01T09:00:00Z");
        assert_eq!(corps["status"]["license"], "youtube");
        let publique = Visibilite {
            privacy: Some("public".into()),
            publish_at: None,
        };
        let corps = corps_visibilite_video(&ressource, &publique).unwrap();
        assert_eq!(corps["status"]["privacyStatus"], "public");
        assert!(corps["status"].get("publishAt").is_none());
    }

    #[test]
    fn le_rapport_video_n_emporte_pas_les_abonnes_par_defaut() {
        let video = Rapport {
            debut: "2026-01-01",
            fin: "2026-01-31",
            video_id: Some("dQw4w9WgXcQ"),
            metrics: None,
            dimensions: None,
        };
        let params = parametres_rapport(&video);
        let metrics = params
            .iter()
            .find(|(k, _)| *k == "metrics")
            .unwrap()
            .1
            .as_str();
        assert!(!metrics.contains("subscribersGained"));
        assert!(metrics.contains("estimatedMinutesWatched"));
        assert_eq!(
            params
                .iter()
                .find(|(k, _)| *k == "filters")
                .unwrap()
                .1
                .as_str(),
            "video==dQw4w9WgXcQ"
        );
        assert_eq!(
            params.iter().find(|(k, _)| *k == "ids").unwrap().1.as_str(),
            "channel==MINE"
        );
        let chaine = Rapport {
            video_id: None,
            ..video
        };
        let params = parametres_rapport(&chaine);
        let metrics = params
            .iter()
            .find(|(k, _)| *k == "metrics")
            .unwrap()
            .1
            .as_str();
        assert!(metrics.contains("subscribersGained"));
        assert!(metrics.contains("subscribersLost"));
        assert!(params.iter().all(|(k, _)| *k != "filters"));
    }

    #[test]
    fn le_multipart_porte_la_langue_et_le_texte() {
        let meta = meta_caption("vid1", "fr", "Français", false);
        let (ctype, octets) =
            multipart_caption(&meta, "1\n00:00:00,000 --> 00:00:01,000\nBonjour").unwrap();
        assert!(ctype.contains("multipart/related"));
        let texte = String::from_utf8(octets).unwrap();
        assert!(texte.contains("\"language\":\"fr\""));
        assert!(texte.contains("Bonjour"));
        assert!(texte.contains("application/json"));
    }

    #[test]
    fn les_points_sont_en_https_chez_google() {
        for point in points_officiels() {
            assert!(
                point.starts_with("https://www.googleapis.com/")
                    || point.starts_with("https://youtubeanalytics.googleapis.com/")
                    || point.starts_with("https://youtubereporting.googleapis.com/"),
                "{point}"
            );
        }
    }

    #[tokio::test]
    async fn les_appels_http_fusionnent_et_un_403_de_portees_ne_panique_pas() {
        use std::sync::Mutex;

        use axum::extract::{Query, State};
        use axum::http::StatusCode;
        use axum::routing::{get, post};
        use axum::{Json, Router};

        #[derive(Clone)]
        struct Recueil(std::sync::Arc<Mutex<Vec<(String, String, Value)>>>);

        let recueil = Recueil(std::sync::Arc::new(Mutex::new(Vec::new())));
        let app = Router::new()
            .route(
                "/youtube/v3/channels",
                get(|| async {
                    Json(json!({"items":[{
                        "id":"UCabc",
                        "brandingSettings":{
                            "channel":{"description":"ancien","keywords":"mots","title":"T"},
                            "image":{"bannerExternalUrl":"https://yt.example/b"}
                        }
                    }]}))
                })
                .put(
                    |State(rec): State<Recueil>, Json(corps): Json<Value>| async move {
                        rec.0.lock().expect("verrou").push((
                            "PUT".into(),
                            "/channels".into(),
                            corps.clone(),
                        ));
                        Json(corps)
                    },
                ),
            )
            .route(
                "/youtube/v3/videos",
                get(|| async {
                    Json(json!({"items":[{
                        "id":"vid1",
                        "snippet":{"title":"T","description":"d","categoryId":"22","tags":["a"]},
                        "status":{"privacyStatus":"private"}
                    }]}))
                })
                .put(
                    |State(rec): State<Recueil>, Query(q): Query<std::collections::HashMap<String, String>>, Json(corps): Json<Value>| async move {
                        rec.0.lock().expect("verrou").push((
                            "PUT".into(),
                            q.get("part").cloned().unwrap_or_default(),
                            corps.clone(),
                        ));
                        Json(corps)
                    },
                ),
            )
            .route(
                "/v2/reports",
                get(
                    |State(rec): State<Recueil>, Query(q): Query<std::collections::HashMap<String, String>>| async move {
                        rec.0.lock().expect("verrou").push((
                            "GET".into(),
                            q.get("filters").cloned().unwrap_or_default(),
                            json!(q),
                        ));
                        Json(json!({
                            "columnHeaders":[{"name":"day"},{"name":"views"}],
                            "rows":[["2026-01-01", 3]]
                        }))
                    },
                ),
            )
            .route(
                "/youtube/v3/comments/setModerationStatus",
                post(
                    |State(rec): State<Recueil>, Query(q): Query<std::collections::HashMap<String, String>>| async move {
                        rec.0.lock().expect("verrou").push((
                            "POST".into(),
                            q.get("moderationStatus").cloned().unwrap_or_default(),
                            json!(q),
                        ));
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/upload/youtube/v3/captions",
                post(
                    |State(rec): State<Recueil>, corps: String| async move {
                        rec.0.lock().expect("verrou").push((
                            "POST".into(),
                            "caption".into(),
                            json!(corps),
                        ));
                        Json(json!({"id":"cap1"}))
                    },
                ),
            )
            .with_state(recueil.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{adresse}");
        let secret = Secret::new("jeton-test");
        let patch = PatchChaine {
            description: Some("nouveau".into()),
            ..PatchChaine::default()
        };
        let rendu = ecrire_chaine(
            &format!("{base}/youtube/v3/channels"),
            &secret,
            "UCabc",
            &patch,
        )
        .await
        .unwrap();
        assert_eq!(rendu["description"], "nouveau");
        assert_eq!(rendu["cout_quota"], COUT_LECTURE + COUT_ECRITURE);

        let video = PatchVideo {
            tags: Some(vec!["b".into()]),
            ..PatchVideo::default()
        };
        let rendu = ecrire_video(
            &format!("{base}/youtube/v3/videos"),
            &secret,
            "vid1",
            &video,
        )
        .await
        .unwrap();
        assert_eq!(rendu["video_id"], "vid1");

        let rapport = rapport(
            &format!("{base}/v2/reports"),
            &secret,
            &Rapport {
                debut: "2026-01-01",
                fin: "2026-01-07",
                video_id: Some("vid1"),
                metrics: None,
                dimensions: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(rapport["rows"][0][1], 3);

        let moderation = moderer(
            &format!("{base}/youtube/v3/comments/setModerationStatus"),
            &secret,
            "Ugz1",
            "heldForReview",
            false,
        )
        .await
        .unwrap();
        assert_eq!(moderation["moderation_status"], "heldForReview");

        let caption = televerser_caption(
            &format!("{base}/upload/youtube/v3/captions"),
            &secret,
            "vid1",
            "fr",
            "Français",
            "1\n00:00:00,000 --> 00:00:01,000\nSalut",
            false,
        )
        .await
        .unwrap();
        assert_eq!(caption["caption_id"], "cap1");
        assert_eq!(caption["cout_quota"], COUT_CAPTIONS_INSERT);

        let journal = recueil.0.lock().expect("verrou");
        assert_eq!(journal[0].0, "PUT");
        assert_eq!(
            journal[0].2["brandingSettings"]["channel"]["description"],
            "nouveau"
        );
        assert_eq!(
            journal[0].2["brandingSettings"]["channel"]["keywords"],
            "mots"
        );
        assert_eq!(
            journal[0].2["brandingSettings"]["image"]["bannerExternalUrl"],
            "https://yt.example/b"
        );
        assert_eq!(journal[1].1, "snippet");
        assert_eq!(journal[1].2["snippet"]["title"], "T");
        assert_eq!(journal[1].2["snippet"]["tags"], json!(["b"]));
        assert_eq!(journal[1].2["snippet"]["categoryId"], "22");
        assert_eq!(journal[2].1, "video==vid1");
        assert_eq!(journal[3].1, "heldForReview");
        let caption_corps = journal[4].2.as_str().unwrap_or("");
        assert!(caption_corps.contains("Salut"));
        assert!(caption_corps.contains("\"language\":\"fr\""));
        drop(journal);

        let refus = Router::new().route(
            "/youtube/v3/videos",
            axum::routing::delete(|| async {
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error":{"message":"Request had insufficient authentication scopes.","errors":[{"reason":"insufficientPermissions","message":"TOKEN-NE-DOIT-PAS-FUIR"}]}})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, refus).await.unwrap();
        });
        let erreur = supprimer(
            &format!("http://{adresse}/youtube/v3/videos"),
            &secret,
            "vid1",
            COUT_ECRITURE,
        )
        .await
        .expect_err("un 403 de portées est une erreur");
        assert!(matches!(erreur, EchecYoutube::ScopesInsuffisants));
        let rendu = erreur.to_string();
        assert!(rendu.contains("account_connect_url"));
        assert!(!rendu.contains("TOKEN-NE-DOIT-PAS-FUIR"));
        assert!(!rendu.contains("jeton-test"));
    }

    #[test]
    fn le_csv_garde_une_virgule_entre_guillemets_et_le_revenu_est_nomme() {
        let (colonnes, lignes) = parser_csv("date,views,titre\n2026-01-01,3,\"un, deux\"\n");
        assert_eq!(colonnes, vec!["date", "views", "titre"]);
        assert_eq!(lignes.len(), 1);
        assert_eq!(lignes[0][2], "un, deux");
        assert!(type_rapport_monetaire("content_owner_estimated_revenue_a1"));
        assert!(!type_rapport_monetaire("channel_basic_a3"));
        assert!(url_rapport_autorisee(
            "https://youtubereporting.googleapis.com/v1/media/CHANNEL/job/report"
        ));
        assert!(!url_rapport_autorisee("https://evil.example/steal"));
        assert!(!url_rapport_autorisee(
            "http://youtubereporting.googleapis.com/v1/x"
        ));
        assert!(MESSAGE_RECONNEXION_REVENU.contains("account_connect_url"));
        assert!(!scopes_revenu_ok(Some(SCOPE_ANALYTICS)));
        assert!(scopes_revenu_ok(Some(SCOPE_ANALYTICS_MONETAIRE)));
        assert!(!scopes_reporting_ok(None));
    }

    #[tokio::test]
    async fn le_reporting_liste_cree_et_telecharge_le_csv_avec_le_jeton() {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::{delete, get, post};
        use axum::{Json, Router};
        use std::sync::Mutex;

        let jetons = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let jetons_delete = jetons.clone();
        let app = Router::new()
            .route(
                "/v1/reportTypes",
                get(|| async {
                    Json(json!({"reportTypes":[
                        {"id":"channel_basic_a3","name":"activité"},
                        {"id":"content_owner_estimated_revenue_a1","name":"revenu"}
                    ]}))
                }),
            )
            .route(
                "/v1/jobs",
                post(|Json(corps): Json<Value>| async move {
                    Json(json!({
                        "id": "job1",
                        "name": corps.get("name").and_then(Value::as_str).unwrap_or(""),
                        "reportTypeId": corps.get("reportTypeId").and_then(Value::as_str).unwrap_or(""),
                        "createTime": "2026-11-10T00:00:00Z"
                    }))
                })
                .get(|| async { Json(json!({"jobs":[{"id":"job1","name":"quotidien","reportTypeId":"channel_basic_a3"}]})) }),
            )
            .route(
                "/v1/jobs/{id}",
                delete(|State(jetons): State<std::sync::Arc<Mutex<Vec<String>>>>, headers: HeaderMap| async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    jetons.lock().expect("verrou").push(auth);
                    StatusCode::NO_CONTENT
                }),
            )
            .route(
                "/v1/jobs/{job}/reports",
                get(|| async {
                    Json(json!({"reports":[{
                        "id": "rep1",
                        "jobId": "job1",
                        "startTime": "2026-11-01T00:00:00Z",
                        "downloadUrl": "present"
                    }]}))
                }),
            )
            .with_state(jetons_delete);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = listener.local_addr().unwrap();
        let base_http = format!("http://{adresse}");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let secret = Secret::new("jeton-test");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse_csv = listener.local_addr().unwrap();
        let csv = format!("http://{adresse_csv}/v1/media/rapport.csv");
        let meta = Router::new()
            .route(
                "/v1/jobs/{job}/reports/{report}",
                get({
                    let csv = csv.clone();
                    move || {
                        let csv = csv.clone();
                        async move { Json(json!({"id":"rep1","downloadUrl": csv})) }
                    }
                }),
            )
            .route(
                "/v1/media/rapport.csv",
                get(|headers: HeaderMap| async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    if auth != "Bearer jeton-test" {
                        return (StatusCode::UNAUTHORIZED, "non".to_owned());
                    }
                    (
                        StatusCode::OK,
                        "date,views\n2026-11-01,7\n2026-11-02,\"8,5\"\n".to_owned(),
                    )
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, meta).await.unwrap();
        });
        let fichier =
            telecharger_rapport(&format!("http://{adresse_csv}/v1"), &secret, "job1", "rep1")
                .await
                .unwrap();
        assert_eq!(fichier["columns"][0], "date");
        assert_eq!(fichier["rows"][0][1], "7");
        assert_eq!(fichier["rows"][1][1], "8,5");
        assert_eq!(fichier["row_count"], 2);
        assert_eq!(fichier["truncated"], false);
        assert_eq!(fichier["digest"].as_str().unwrap_or("").len(), 64);
        let base = format!("{base_http}/v1");
        let types = lister_types_rapport(&base, &secret, None, 20, false)
            .await
            .unwrap();
        assert_eq!(types["report_types"][0]["id"], "channel_basic_a3");
        assert_eq!(types["report_types"][0]["monetary"], false);
        assert_eq!(types["report_types"][1]["monetary"], true);
        let job = creer_job_rapport(&base, &secret, "channel_basic_a3", Some("quotidien"))
            .await
            .unwrap();
        assert_eq!(job["job_id"], "job1");
        assert_eq!(job["report_type_id"], "channel_basic_a3");
        let jobs = lister_jobs_rapport(&base, &secret, None, 20).await.unwrap();
        assert_eq!(jobs["jobs"][0]["job_id"], "job1");
        let liste = lister_rapports_job(&base, &secret, "job1", None, 20)
            .await
            .unwrap();
        assert_eq!(liste["reports"][0]["downloadable"], true);
        let supprime = supprimer_job_rapport(&base, &secret, "job1").await.unwrap();
        assert_eq!(supprime["deleted"], true);
        let auth = jetons.lock().expect("verrou");
        assert_eq!(auth[0], "Bearer jeton-test");
        drop(auth);

        // downloadUrl hors hôtes : le jeton ne part pas.
        let piege = Router::new().route(
            "/v1/jobs/{job}/reports/{report}",
            get(|| async { Json(json!({"id":"rep1","downloadUrl":"https://evil.example/csv"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, piege).await.unwrap();
        });
        let erreur = telecharger_rapport(&format!("http://{adresse}/v1"), &secret, "job1", "rep1")
            .await
            .expect_err("hôte refusé");
        let rendu = erreur.to_string();
        assert!(rendu.contains("hôtes YouTube"));
        assert!(!rendu.contains("jeton-test"));
    }
}
