//! Le serveur MCP : la table des six outils, le JSON-RPC, et le trait que le
//! lot adaptateurs implemente.
//!
//! La promesse du produit est NEGATIVE : aucune surface DM, jamais. Comme pour
//! packages/docker-mcp, une promesse negative ne se prouve pas en appelant les
//! outils — elle se prouve en lisant la table. Le test `aucun_outil_ne_parle_a_
//! quelqu_un` lit la table et echoue si un nom sent le message prive.

use std::sync::Arc;

use agentos_domain::ids::TenantId;
use agentos_providers::Secret;
use agentos_providers::secrets::LocalEnvelopeSecretStore;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::adapters::{ErreurPlateforme, MediaPret, Plateforme, Sondage};
use crate::medias;
use crate::oauth_flux::{self, PlateformeOauth};
use crate::store::{self, Reclamation};

// ---------------------------------------------------------------------------
// L'etat du serveur
// ---------------------------------------------------------------------------

/// Le client OAuth d'UNE plateforme, enregistre par le fondateur sur son
/// portail dev. Pas de credentials : la plateforme n'est pas connectable, et
/// account_connect_url le dit au lieu d'envoyer un humain consentir pour rien.
pub struct CredentielsClient {
    pub client_id: String,
    pub client_secret: Secret,
}

pub struct Etat {
    pub pool: PgPool,
    pub chiffreur: Arc<LocalEnvelopeSecretStore>,
    /// Le trait unique vit dans crate::adapters ; les tests d'ici y glissent
    /// leur adaptateur compteur, main.rs y met adapters::adaptateurs().
    pub adaptateurs: Vec<Box<dyn Plateforme>>,
    /// Le téléchargeur de médias — la surface d'attaque vettée de medias.rs.
    /// Les tests d'ici le remplacent par le constructeur `de_test`, seul
    /// chemin qui parle à un serveur 127.0.0.1.
    pub telechargeur: medias::Telechargeur,
    /// Base publique du service, pour construire le redirect_uri OAuth.
    pub url_publique: String,
    pub oauth_x: Option<CredentielsClient>,
    pub oauth_linkedin: Option<CredentielsClient>,
}

impl Etat {
    fn adaptateur(&self, plateforme: &str) -> Option<&dyn Plateforme> {
        self.adaptateurs
            .iter()
            .find(|a| a.nom() == plateforme)
            .map(AsRef::as_ref)
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/oauth/callback", self.url_publique.trim_end_matches('/'))
    }

    /// Le nom de plateforme des tables vers le flux OAuth et ses credentials.
    pub fn oauth(&self, plateforme: &str) -> Option<(PlateformeOauth, &CredentielsClient)> {
        match plateforme {
            "x" => Some(PlateformeOauth::X).zip(self.oauth_x.as_ref()),
            "linkedin" => Some(PlateformeOauth::Linkedin).zip(self.oauth_linkedin.as_ref()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// La table d'outils, versionnee
// ---------------------------------------------------------------------------

/// La version de la table. REGLE : tout changement de nom ou de schema dans
/// `description_outils` bumpe cette constante ET ajoute une ligne a
/// `EMPREINTES` dans les tests — sinon `la_table_ne_change_pas_sans_bumper`
/// echoue, et c'est son travail.
pub const VERSION_TABLE: &str = "2";

/// Les six outils, et pas un de plus. C'est la piece que le pin SHA-256 du
/// runtime fige, donc elle est une valeur deterministe, pas du code.
pub fn description_outils() -> Value {
    json!([
        {
            "name": "accounts_list",
            "description": "Les comptes connectes de ce tenant (plateforme, handle, etat).",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "account_connect_url",
            "description": "L'URL d'autorisation OAuth a ouvrir pour connecter un compte. Le retour se fait sur GET /oauth/callback.",
            "inputSchema": {
                "type": "object",
                "properties": { "platform": { "type": "string", "enum": ["x", "linkedin"] } },
                "required": ["platform"],
                "additionalProperties": false
            }
        },
        // Bornes des champs media/poll = le MAXIMUM inter-plateformes, cite :
        // maxItems 20 (LinkedIn multiImage max 20, multiimage-post-api,
        // releve 2026-09-02), alt_text maxLength 4086 (altText LinkedIn,
        // images-api, 2026-09-02), duration_minutes max 20160 (FOURTEEN_DAYS
        // LinkedIn). Le RESSERREMENT par plateforme est le travail de
        // l'adaptateur, avec le mot exact et le chiffre cite — jamais
        // d'ignorance silencieuse.
        {
            "name": "post_preview",
            "description": "Le contenu EXACT qui partirait — texte, medias telecharges et empreintes (SHA-256 de chaque octet), sondage — l'empreinte globale, le verdict des limites de plateforme et le cout estime. C'est ce qu'une approbation humaine contresigne.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "text": { "type": "string" },
                    "media": {
                        "type": "array", "minItems": 1, "maxItems": 20,
                        "items": {
                            "type": "object",
                            "properties": {
                                "url":      { "type": "string" },
                                "alt_text": { "type": "string", "maxLength": 4086 },
                                "title":    { "type": "string" }
                            },
                            "required": ["url"],
                            "additionalProperties": false
                        }
                    },
                    "poll": {
                        "type": "object",
                        "properties": {
                            "question":         { "type": "string" },
                            "options":          { "type": "array", "minItems": 2, "maxItems": 4, "items": { "type": "string" } },
                            "duration_minutes": { "type": "integer", "minimum": 5, "maximum": 20160 }
                        },
                        "required": ["options", "duration_minutes"],
                        "additionalProperties": false
                    },
                    "made_with_ai": { "type": "boolean" }
                },
                "required": ["account_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_publish",
            "description": "Publie un contenu (texte, medias, sondage). idempotency_key OBLIGATOIRE : rejouer la meme cle rend le meme post sans republier. expected_media_digests (ceux de post_preview) garantit que les octets publies sont ceux contresignes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "idempotency_key": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "account_id": { "type": "string" },
                    "text": { "type": "string" },
                    "media": {
                        "type": "array", "minItems": 1, "maxItems": 20,
                        "items": {
                            "type": "object",
                            "properties": {
                                "url":      { "type": "string" },
                                "alt_text": { "type": "string", "maxLength": 4086 },
                                "title":    { "type": "string" }
                            },
                            "required": ["url"],
                            "additionalProperties": false
                        }
                    },
                    "poll": {
                        "type": "object",
                        "properties": {
                            "question":         { "type": "string" },
                            "options":          { "type": "array", "minItems": 2, "maxItems": 4, "items": { "type": "string" } },
                            "duration_minutes": { "type": "integer", "minimum": 5, "maximum": 20160 }
                        },
                        "required": ["options", "duration_minutes"],
                        "additionalProperties": false
                    },
                    "made_with_ai": { "type": "boolean" },
                    "expected_media_digests": {
                        "type": "array",
                        "items": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                    }
                },
                "required": ["idempotency_key", "account_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_metrics",
            "description": "Impressions/likes/reposts si la plateforme les sert. Quand elle ne les sert pas (LinkedIn membre), l'outil le dit au lieu de rendre des zeros.",
            "inputSchema": {
                "type": "object",
                "properties": { "post_id": { "type": "string" } },
                "required": ["post_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "posts_list",
            "description": "L'historique des posts de ce tenant, du plus recent au plus ancien.",
            "inputSchema": {
                "type": "object",
                "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 200 } },
                "additionalProperties": false
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

/// Une erreur d'outil : un code stable pour l'agent, un message pour l'humain.
struct Erreur {
    code: &'static str,
    message: String,
}

impl Erreur {
    fn nouvelle(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for Erreur {
    fn from(e: sqlx::Error) -> Self {
        Erreur::nouvelle("stockage", e.to_string())
    }
}

fn reponse(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn erreur_rpc(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Traite un message JSON-RPC deja authentifie. `None` = notification, rien a
/// repondre (le transport rend 202).
pub async fn traiter(etat: &Etat, tenant: Uuid, req: &Value) -> Option<Value> {
    let methode = req.get("method").and_then(Value::as_str).unwrap_or("");
    let id = req.get("id")?; // pas d'id : notification (notifications/initialized, etc.)

    Some(match methode {
        "initialize" => reponse(
            id,
            json!({
                // Version de protocole relevee du client rmcp deja dans le
                // workspace (transport streamable-http) ; on repond la meme
                // famille que lui.
                "protocolVersion": req.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2025-03-26"),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "agentos-social", "version": VERSION_TABLE }
            }),
        ),
        "ping" => reponse(id, json!({})),
        "tools/list" => reponse(id, json!({ "tools": description_outils() })),
        "tools/call" => {
            let nom = req
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let vide = json!({});
            let args = req.pointer("/params/arguments").unwrap_or(&vide);
            match appeler_outil(etat, tenant, nom, args).await {
                Ok(v) => reponse(
                    id,
                    json!({ "content": [{ "type": "text", "text": v.to_string() }], "isError": false }),
                ),
                Err(e) => reponse(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": json!({ "erreur": e.code, "message": e.message }).to_string() }],
                        "isError": true
                    }),
                ),
            }
        }
        _ => erreur_rpc(id, -32601, &format!("methode inconnue: {methode}")),
    })
}

// ---------------------------------------------------------------------------
// Les outils
// ---------------------------------------------------------------------------

fn arg_str<'a>(args: &'a Value, nom: &'static str) -> Result<&'a str, Erreur> {
    args.get(nom)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Erreur::nouvelle("argument_manquant", format!("`{nom}` est obligatoire")))
}

fn arg_uuid(args: &Value, nom: &'static str) -> Result<Uuid, Erreur> {
    Uuid::parse_str(arg_str(args, nom)?)
        .map_err(|_| Erreur::nouvelle("argument_invalide", format!("`{nom}` n'est pas un uuid")))
}

fn invalide(message: impl Into<String>) -> Erreur {
    Erreur::nouvelle("argument_invalide", message)
}

/// Une demande de média AVANT téléchargement : l'URL et ses annotations.
struct MediaDemande {
    url: String,
    alt_text: Option<String>,
    title: Option<String>,
}

/// Les arguments de contenu partagés par post_preview et post_publish.
struct Contenu {
    medias: Vec<MediaDemande>,
    sondage: Option<Sondage>,
    made_with_ai: bool,
}

fn champ_texte(
    objet: &serde_json::Map<String, Value>,
    nom: &str,
) -> Result<Option<String>, Erreur> {
    match objet.get(nom) {
        None => Ok(None),
        Some(v) => Ok(Some(
            v.as_str()
                .ok_or_else(|| invalide(format!("`{nom}` doit etre une chaine")))?
                .to_owned(),
        )),
    }
}

/// Parse `media`/`poll`/`made_with_ai` À LA MAIN contre le schéma C1 : ce
/// serveur ne roule pas de validateur JSON-Schema, donc le schéma publié et
/// ce parseur doivent dire la même phrase — bornes inter-plateformes ici, le
/// resserrement par plateforme dans l'adaptateur.
fn parser_contenu(args: &Value) -> Result<Contenu, Erreur> {
    let mut medias = Vec::new();
    if let Some(v) = args.get("media") {
        let tableau = v
            .as_array()
            .ok_or_else(|| invalide("`media` doit etre un tableau"))?;
        if tableau.is_empty() || tableau.len() > 20 {
            return Err(invalide(
                "`media` porte 1 a 20 elements (20 = multiImage LinkedIn, le maximum servi)",
            ));
        }
        for (i, element) in tableau.iter().enumerate() {
            let objet = element
                .as_object()
                .ok_or_else(|| invalide(format!("`media[{i}]` doit etre un objet")))?;
            for cle in objet.keys() {
                if !["url", "alt_text", "title"].contains(&cle.as_str()) {
                    return Err(invalide(format!("`media[{i}].{cle}` n'existe pas")));
                }
            }
            let url = champ_texte(objet, "url")?
                .filter(|u| !u.is_empty())
                .ok_or_else(|| invalide(format!("`media[{i}].url` est obligatoire")))?;
            let alt_text = champ_texte(objet, "alt_text")?;
            if let Some(alt) = &alt_text
                && alt.chars().count() > 4086
            {
                return Err(invalide(format!(
                    "`media[{i}].alt_text` depasse 4086 caracteres (altText LinkedIn, le maximum servi)"
                )));
            }
            let title = champ_texte(objet, "title")?;
            medias.push(MediaDemande {
                url,
                alt_text,
                title,
            });
        }
    }

    let sondage = match args.get("poll") {
        None => None,
        Some(v) => {
            let objet = v
                .as_object()
                .ok_or_else(|| invalide("`poll` doit etre un objet"))?;
            for cle in objet.keys() {
                if !["question", "options", "duration_minutes"].contains(&cle.as_str()) {
                    return Err(invalide(format!("`poll.{cle}` n'existe pas")));
                }
            }
            let options: Vec<String> = objet
                .get("options")
                .and_then(Value::as_array)
                .ok_or_else(|| invalide("`poll.options` est obligatoire"))?
                .iter()
                .map(|o| {
                    o.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| invalide("chaque option de `poll.options` est une chaine"))
                })
                .collect::<Result<_, _>>()?;
            if !(2..=4).contains(&options.len()) {
                return Err(invalide("`poll.options` porte 2 a 4 options"));
            }
            let duree = objet
                .get("duration_minutes")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalide("`poll.duration_minutes` est obligatoire"))?;
            if !(5..=20160).contains(&duree) {
                return Err(invalide(
                    "`poll.duration_minutes` va de 5 (minimum X) a 20160 (FOURTEEN_DAYS LinkedIn)",
                ));
            }
            Some(Sondage {
                question: champ_texte(objet, "question")?,
                options,
                duration_minutes: duree as u32,
            })
        }
    };

    let made_with_ai = match args.get("made_with_ai") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| invalide("`made_with_ai` doit etre un booleen"))?,
    };

    Ok(Contenu {
        medias,
        sondage,
        made_with_ai,
    })
}

/// `expected_media_digests`, optionnel sur post_publish seul.
fn parser_digests_attendus(args: &Value) -> Result<Option<Vec<String>>, Erreur> {
    let Some(v) = args.get("expected_media_digests") else {
        return Ok(None);
    };
    let tableau = v
        .as_array()
        .ok_or_else(|| invalide("`expected_media_digests` doit etre un tableau"))?;
    tableau
        .iter()
        .map(|d| {
            d.as_str()
                .filter(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|o| o.is_ascii_hexdigit() && !o.is_ascii_uppercase())
                })
                .map(str::to_owned)
                .ok_or_else(|| invalide("chaque digest attendu est un SHA-256 hex minuscule de 64"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// Télécharge, vet et empreinte chaque média demandé, dans l'ordre.
/// ponytail: séquentiel — 20 médias max et l'agent attend de toute façon ;
/// paralléliser viendra si un profil s'en plaint.
async fn telecharger_tous(
    etat: &Etat,
    demandes: &[MediaDemande],
) -> Result<Vec<MediaPret>, Erreur> {
    let mut prets = Vec::with_capacity(demandes.len());
    for demande in demandes {
        prets.push(
            etat.telechargeur
                .telecharger(
                    &demande.url,
                    demande.alt_text.clone(),
                    demande.title.clone(),
                )
                .await
                .map_err(|e| Erreur::nouvelle(e.code(), e.to_string()))?,
        );
    }
    Ok(prets)
}

async fn appeler_outil(
    etat: &Etat,
    tenant: Uuid,
    nom: &str,
    args: &Value,
) -> Result<Value, Erreur> {
    match nom {
        "accounts_list" => {
            let comptes = store::comptes(&etat.pool, tenant).await?;
            Ok(json!({ "accounts": comptes.iter().map(|c| json!({
                "account_id": c.id, "platform": c.platform, "handle": c.handle, "status": c.status
            })).collect::<Vec<_>>() }))
        }
        "account_connect_url" => connecter(etat, tenant, args).await,
        "post_preview" => previsualiser(etat, tenant, args).await,
        "post_publish" => publier(etat, tenant, args).await,
        "post_metrics" => metriques(etat, tenant, args).await,
        "posts_list" => {
            let limite = args
                .get("limit")
                .and_then(Value::as_i64)
                .unwrap_or(50)
                .clamp(1, 200);
            let posts = store::posts(&etat.pool, tenant, limite).await?;
            Ok(json!({ "posts": posts.iter().map(|p| json!({
                "post_id": p.id, "account_id": p.account_id, "text": p.text_body,
                "digest": p.digest, "media_digests": p.media_digests, "status": p.status,
                "platform_post_id": p.platform_post_id, "url": p.url
            })).collect::<Vec<_>>() }))
        }
        autre => Err(Erreur::nouvelle(
            "outil_inconnu",
            format!("pas d'outil `{autre}`"),
        )),
    }
}

async fn connecter(etat: &Etat, tenant: Uuid, args: &Value) -> Result<Value, Erreur> {
    let plateforme = arg_str(args, "platform")?;
    if etat.adaptateur(plateforme).is_none() {
        return Err(Erreur::nouvelle(
            "plateforme_inconnue",
            format!("pas d'adaptateur `{plateforme}`"),
        ));
    }
    // Refuser AVANT d'envoyer un humain consentir : sans client_id/secret,
    // l'echange du retour echouerait de toute facon.
    let Some((pf, credentiels)) = etat.oauth(plateforme) else {
        return Err(Erreur::nouvelle(
            "oauth_non_configure",
            format!(
                "pas de credentials client pour `{plateforme}` — poser SOCIAL_{}_CLIENT_ID et SOCIAL_{}_CLIENT_SECRET",
                plateforme.to_uppercase(),
                plateforme.to_uppercase()
            ),
        ));
    };

    // oauth_flux fabrique le state (32 octets d'OS), le defi PKCE (X) et
    // l'URL ; seul le SHA-256 du state atterrit en base — la table ne permet
    // pas de finir un flux.
    let flux = oauth_flux::demarrer(
        pf,
        &credentiels.client_id,
        &etat.redirect_uri(),
        TenantId::from_uuid(tenant),
        &etat.chiffreur,
    )
    .map_err(|_| Erreur::nouvelle("scellement", "le flux n'a pas pu etre scelle"))?;

    store::creer_attente_oauth(
        &etat.pool,
        &oauth_flux::hex(&flux.empreinte_state),
        tenant,
        plateforme,
        flux.verifieur_scelle.as_deref(),
    )
    .await?;
    Ok(json!({ "authorization_url": flux.authorize_url }))
}

async fn previsualiser(etat: &Etat, tenant: Uuid, args: &Value) -> Result<Value, Erreur> {
    let compte_id = arg_uuid(args, "account_id")?;
    let texte = arg_str(args, "text")?;
    let compte = store::compte_scelle(&etat.pool, tenant, compte_id)
        .await?
        .ok_or_else(|| {
            Erreur::nouvelle("compte_inconnu", "ce compte n'appartient pas a ce tenant")
        })?;
    let adaptateur = etat.adaptateur(&compte.platform).ok_or_else(|| {
        Erreur::nouvelle(
            "plateforme_inconnue",
            format!("pas d'adaptateur `{}`", compte.platform),
        )
    })?;

    // L'aperçu couvre le contenu EXACT : les médias sont TÉLÉCHARGÉS ici,
    // maintenant, et chaque octet entre dans son digest — une preview qui
    // n'empreinterait que le texte laisserait changer l'image après
    // contreseing. Le champ `digest` rendu est l'empreinte GLOBALE (C3), et
    // les digests par média sont ceux que post_publish acceptera en
    // expected_media_digests.
    let contenu = parser_contenu(args)?;
    let medias_prets = telecharger_tous(etat, &contenu.medias).await?;
    let apercu = adaptateur.apercu(
        texte,
        &medias_prets,
        contenu.sondage.as_ref(),
        contenu.made_with_ai,
    );
    Ok(serde_json::to_value(apercu).expect("Apercu se serialise"))
}

async fn publier(etat: &Etat, tenant: Uuid, args: &Value) -> Result<Value, Erreur> {
    let cle = arg_str(args, "idempotency_key")?;
    let compte_id = arg_uuid(args, "account_id")?;
    let texte = arg_str(args, "text")?;
    let compte = store::compte_scelle(&etat.pool, tenant, compte_id)
        .await?
        .ok_or_else(|| {
            Erreur::nouvelle("compte_inconnu", "ce compte n'appartient pas a ce tenant")
        })?;
    let adaptateur = etat.adaptateur(&compte.platform).ok_or_else(|| {
        Erreur::nouvelle(
            "plateforme_inconnue",
            format!("pas d'adaptateur `{}`", compte.platform),
        )
    })?;

    // L'ordre du contrat C7 : tout ce qui precede `reclamer` ne consomme pas
    // la cle — un refus ici laisse le tour corrige la reutiliser.
    let contenu = parser_contenu(args)?;
    let attendus = parser_digests_attendus(args)?;
    let medias_prets = telecharger_tous(etat, &contenu.medias).await?;

    // Le pont contreseing -> octets publies : ce que post_preview a montre
    // doit etre ce qu'on tient. On ne re-telecharge JAMAIS pour
    // « reverifier » — une URL peut servir un octet different une minute
    // plus tard, et c'est exactement ce que cette comparaison attrape.
    if let Some(attendus) = &attendus {
        if attendus.len() != medias_prets.len() {
            return Err(invalide(format!(
                "`expected_media_digests` porte {} digests pour {} medias",
                attendus.len(),
                medias_prets.len()
            )));
        }
        for (i, (attendu, media)) in attendus.iter().zip(&medias_prets).enumerate() {
            if attendu != &media.digest {
                return Err(Erreur::nouvelle(
                    "media_change",
                    format!(
                        "media {i} a change depuis l'apercu : attendu {attendu}, obtenu {} — re-previsualiser et refaire contresigner",
                        media.digest
                    ),
                ));
            }
        }
    }

    // Limites AVANT la reclamation : un contenu invalide ne consomme pas la
    // cle, pour que le tour corrige puisse la reutiliser.
    let apercu = adaptateur.apercu(
        texte,
        &medias_prets,
        contenu.sondage.as_ref(),
        contenu.made_with_ai,
    );
    if !apercu.platform_limits_ok || apercu.media.iter().any(|m| !m.limits_ok) {
        // Les mots exacts de l'adaptateur : les verdicts globaux (sondage,
        // melange interdit) puis ceux de chaque media — jamais un refus muet.
        let verdicts: Vec<&str> = apercu
            .verdicts
            .iter()
            .map(String::as_str)
            .chain(
                apercu
                    .media
                    .iter()
                    .flat_map(|m| m.verdicts.iter().map(String::as_str)),
            )
            .collect();
        return Err(Erreur::nouvelle(
            "limites_plateforme",
            if verdicts.is_empty() {
                format!(
                    "contenu hors limites pour {} — post_preview donne le verdict avant de bruler un appel",
                    compte.platform
                )
            } else {
                format!(
                    "contenu hors limites pour {} : {}",
                    compte.platform,
                    verdicts.join(" ; ")
                )
            },
        ));
    }

    // La meme empreinte GLOBALE que post_preview a montree (texte + digest de
    // chaque media + sondage, contrat C3) : c'est elle que l'approbation
    // humaine a contresignee, et elle que le rejeu compare — une image
    // differente sous la meme cle tombe dans TexteDifferent toute seule.
    let digest = apercu.digest;
    let empreintes_medias: Vec<String> = medias_prets.iter().map(|m| m.digest.clone()).collect();
    let id = match store::reclamer(
        &etat.pool,
        tenant,
        compte_id,
        cle,
        texte,
        &digest,
        &empreintes_medias,
    )
    .await?
    {
        Reclamation::ANous(id) => id,
        Reclamation::DejaPublie(p) => {
            // LE rejeu : meme post_id, aucune republication.
            return Ok(json!({
                "post_id": p.id, "platform_post_id": p.platform_post_id,
                "url": p.url, "replayed": true
            }));
        }
        Reclamation::TexteDifferent => {
            return Err(Erreur::nouvelle(
                "cle_reutilisee",
                "cette idempotency_key a deja servi pour un AUTRE texte — nouvelle cle pour un nouveau texte",
            ));
        }
        Reclamation::EnVol => {
            return Err(Erreur::nouvelle(
                "publication_en_cours",
                "une publication avec cette cle est en vol ; rejouer dans un instant",
            ));
        }
    };

    // La cle est a nous : ouvrir le jeton, publier, marquer. Toute sortie en
    // erreur marque 'failed' pour qu'un rejeu puisse re-reclamer. Le jeton
    // reste un `Secret` jusqu'au bearer_auth de l'adaptateur — pas de String
    // intermediaire qui trainerait dans un Debug.
    let jeton = match &compte.sealed_token {
        None => {
            store::marquer_echec(&etat.pool, id).await?;
            return Err(Erreur::nouvelle(
                "compte_sans_jeton",
                "ce compte n'a pas de jeton scelle — reconnecter via account_connect_url",
            ));
        }
        Some(octets) => {
            match oauth_flux::ouvrir_jeton(
                &etat.chiffreur,
                TenantId::from_uuid(tenant),
                &compte.platform,
                &compte.handle,
                octets,
            ) {
                Ok(secret) => secret,
                Err(_) => {
                    store::marquer_echec(&etat.pool, id).await?;
                    return Err(Erreur::nouvelle(
                        "descellement",
                        "le jeton de ce compte ne s'ouvre pas — reconnecter",
                    ));
                }
            }
        }
    };

    // Premier essai, puis UN rejeu si — et seulement si — la plateforme a dit
    // 401 et qu'on tient de quoi rafraîchir. Un jeton d'accès X meurt en deux
    // heures : sans ce chemin, chaque initiative quotidienne finirait en
    // `plateforme_refus` et en re-consentement humain, alors que le refresh
    // token dort scellé en base depuis la connexion. Un seul rejeu, jamais de
    // boucle : si le jeton frais prend aussi un 401, le problème n'est pas
    // l'expiration et le dire vaut mieux que retenter.
    let resultat = adaptateur
        .publier(
            &jeton,
            &compte.handle,
            texte,
            &medias_prets,
            contenu.sondage.as_ref(),
            contenu.made_with_ai,
        )
        .await;
    let resultat = match resultat {
        Err(ErreurPlateforme::Refus { statut: 401 }) => {
            match jeton_rafraichi(etat, tenant, &compte).await {
                Some(frais) => {
                    adaptateur
                        .publier(
                            &frais,
                            &compte.handle,
                            texte,
                            &medias_prets,
                            contenu.sondage.as_ref(),
                            contenu.made_with_ai,
                        )
                        .await
                }
                // Rien à rafraîchir (pas de refresh token, pas de credentials
                // client, ou la plateforme refuse le grant) : le 401 d'origine
                // est la vérité, on le rend tel quel.
                None => Err(ErreurPlateforme::Refus { statut: 401 }),
            }
        }
        autre => autre,
    };

    match resultat {
        Ok(publie) => {
            store::marquer_publie(&etat.pool, id, &publie.id_plateforme, Some(&publie.url)).await?;
            Ok(json!({
                "post_id": id, "platform_post_id": publie.id_plateforme,
                "url": publie.url, "replayed": false
            }))
        }
        Err(e) => {
            store::marquer_echec(&etat.pool, id).await?;
            Err(Erreur::nouvelle(e.code(), e.to_string()))
        }
    }
}

/// Tente un rafraîchissement et rend le jeton d'accès frais, ou `None` si le
/// chemin n'existe pas pour ce compte. `None` et pas une erreur : l'appelant
/// tient déjà la bonne erreur — le 401 d'origine — et rien ici ne doit la
/// maquiller en autre chose.
///
/// Le nouveau jeton est rescellé AVANT d'être rendu : si l'écriture échoue, on
/// préfère rendre `None` et laisser le 401 d'origine sortir plutôt que publier
/// avec un jeton que la base ne connaît pas — au tour suivant, le jeton scellé
/// serait redevenu le mort, et le symptôme un 401 sur deux, indiagnosticable.
async fn jeton_rafraichi(
    etat: &Etat,
    tenant: Uuid,
    compte: &store::CompteScelle,
) -> Option<Secret> {
    let scelle = compte.sealed_refresh.as_deref()?;
    let (plateforme, credentiels) = etat.oauth(&compte.platform)?;
    let tenant_id = TenantId::from_uuid(tenant);

    let rafraichissement = oauth_flux::ouvrir_rafraichissement(
        &etat.chiffreur,
        tenant_id,
        &compte.platform,
        &compte.handle,
        scelle,
    )
    .ok()?;

    let emis = oauth_flux::rafraichir(
        plateforme,
        &credentiels.client_id,
        &credentiels.client_secret,
        &rafraichissement,
    )
    .await
    .ok()?;

    let sealed_token = oauth_flux::sceller_jeton(
        &etat.chiffreur,
        tenant_id,
        &compte.platform,
        &compte.handle,
        &emis.acces,
    )
    .ok()?;
    // X fait tourner ses refresh tokens : quand la réponse en porte un
    // nouveau, l'ancien est dépensé et le garder serait garder un mort.
    // Quand elle n'en porte pas, `resceller_jetons` conserve l'existant
    // (COALESCE) — on ne troque jamais un jeton vivant contre un NULL.
    let sealed_refresh = match &emis.rafraichissement {
        Some(neuf) => Some(
            oauth_flux::sceller_rafraichissement(
                &etat.chiffreur,
                tenant_id,
                &compte.platform,
                &compte.handle,
                neuf,
            )
            .ok()?,
        ),
        None => None,
    };
    store::resceller_jetons(
        &etat.pool,
        tenant,
        compte.id,
        &sealed_token,
        sealed_refresh.as_deref(),
    )
    .await
    .ok()?;

    Some(emis.acces)
}

async fn metriques(etat: &Etat, tenant: Uuid, args: &Value) -> Result<Value, Erreur> {
    let post_id = arg_uuid(args, "post_id")?;
    let post = store::post(&etat.pool, tenant, post_id)
        .await?
        .ok_or_else(|| Erreur::nouvelle("post_inconnu", "ce post n'appartient pas a ce tenant"))?;
    if post.status != "published" {
        return Err(Erreur::nouvelle(
            "post_non_publie",
            format!("ce post est `{}`", post.status),
        ));
    }
    let compte = store::compte_scelle(&etat.pool, tenant, post.account_id)
        .await?
        .ok_or_else(|| Erreur::nouvelle("compte_inconnu", "le compte de ce post a disparu"))?;
    let adaptateur = etat.adaptateur(&compte.platform).ok_or_else(|| {
        Erreur::nouvelle(
            "plateforme_inconnue",
            format!("pas d'adaptateur `{}`", compte.platform),
        )
    })?;

    let jeton = match &compte.sealed_token {
        None => {
            return Err(Erreur::nouvelle(
                "compte_sans_jeton",
                "reconnecter via account_connect_url",
            ));
        }
        Some(octets) => oauth_flux::ouvrir_jeton(
            &etat.chiffreur,
            TenantId::from_uuid(tenant),
            &compte.platform,
            &compte.handle,
            octets,
        )
        .map_err(|_| Erreur::nouvelle("descellement", "le jeton de ce compte ne s'ouvre pas"))?,
    };
    let id_plateforme = post.platform_post_id.ok_or_else(|| {
        Erreur::nouvelle("post_sans_id", "publie sans id de plateforme — incoherent")
    })?;

    match adaptateur.metriques(&jeton, &id_plateforme).await {
        // La difference entre « zero vue » et « la plateforme ne le dit pas »
        // est exactement ce que cet outil existe pour dire. `impressions` peut
        // etre null (servi nulle part dans la reponse) sans que ce soit un
        // zero invente.
        Ok(Some(m)) => Ok(json!({
            "available": true,
            "impressions": m.impressions, "likes": m.likes,
            "reposts": m.reposts, "replies": m.replies
        })),
        Ok(None) => Ok(json!({
            "available": false,
            "raison": format!("{} ne sert pas de metriques pour ce type de post", compte.platform)
        })),
        Err(e) => Err(Erreur::nouvelle(e.code(), e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::adapters::{
        Apercu, ApercuMedia, ErreurPlateforme, Metriques, Publication, empreinte,
    };

    // -- Le test anti-DM : la promesse fondatrice du produit. ---------------
    //
    // Meme forme que packages/docker-mcp/test/forbidden.test.js : d'abord on
    // prouve que chaque interdit RECONNAIT un nom hostile (un test qui ne peut
    // pas echouer est pire que pas de test), puis on passe la table au crible.

    /// Les interdits, et pour chacun un nom d'outil hostile qui doit le
    /// declencher.
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

    fn noms_de_la_table() -> Vec<String> {
        description_outils()
            .as_array()
            .expect("la table est un tableau")
            .iter()
            .map(|o| {
                o["name"]
                    .as_str()
                    .expect("chaque outil a un nom")
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn les_interdits_attrapent_ce_qu_ils_pretendent_attraper() {
        for (motif, hostile) in INTERDITS {
            assert!(
                hostile.contains(motif),
                "l'interdit `{motif}` ne reconnait pas `{hostile}`"
            );
        }
    }

    #[test]
    fn aucun_outil_ne_parle_a_quelqu_un() {
        let noms = noms_de_la_table();
        assert!(!noms.is_empty(), "une table vide ne prouve rien");
        for nom in &noms {
            for (motif, _) in INTERDITS {
                assert!(
                    !nom.contains(motif),
                    "`{nom}` contient l'interdit `{motif}` : ce serveur n'a AUCUNE surface DM, par construction"
                );
            }
        }
    }

    #[test]
    fn la_table_expose_exactement_les_six_outils_convenus() {
        assert_eq!(
            noms_de_la_table(),
            [
                "accounts_list",
                "account_connect_url",
                "post_preview",
                "post_publish",
                "post_metrics",
                "posts_list"
            ]
        );
    }

    // -- Le test de version : changer un schema sans bumper echoue. ---------

    /// L'histoire complete des versions de la table et de leur empreinte.
    /// Changer `description_outils` change l'empreinte calculee ; si la
    /// derniere ligne d'ici ne la porte pas, ce test echoue — et le corriger
    /// exige d'ajouter une ligne AVEC une nouvelle version. Reecrire une
    /// ligne existante est une falsification, pas une correction.
    const EMPREINTES: &[(&str, &str)] = &[
        (
            "1",
            "2d8f2821a0c4cc02f85ea5cdf650c1e6e3c0d57afb4d87bad514013cf9cbffbe",
        ),
        // v2 : post_preview et post_publish gagnent media/poll/made_with_ai,
        // post_publish gagne expected_media_digests (contrat C1).
        (
            "2",
            "5e0d09aa3063c5a058935a2afe2d9230a9965b015e32c5071ca7140216d78870",
        ),
    ];

    #[test]
    fn la_table_ne_change_pas_sans_bumper_la_version() {
        let calculee = empreinte(&description_outils().to_string());
        let (version, attendue) = EMPREINTES.last().expect("au moins une version");
        assert_eq!(
            *version, VERSION_TABLE,
            "VERSION_TABLE et EMPREINTES ont diverge"
        );
        assert_eq!(
            &calculee, attendue,
            "la table d'outils a change : bumper VERSION_TABLE et ajouter (version, empreinte) a EMPREINTES"
        );
        // Deux versions ne partagent jamais un numero.
        let mut versions: Vec<_> = EMPREINTES.iter().map(|(v, _)| *v).collect();
        versions.dedup();
        assert_eq!(versions.len(), EMPREINTES.len());
    }

    // -- L'idempotence, prouvee contre la base. -----------------------------

    /// Un adaptateur qui compte ses publications : si l'idempotence fuit, le
    /// compteur le dit.
    struct Faux {
        publications: Arc<AtomicUsize>,
        /// `true` : chaque `publier` rend un 401, comme un jeton d'accès mort.
        jeton_mort: bool,
    }

    #[async_trait]
    impl Plateforme for Faux {
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
            Apercu {
                rendered_text: texte.to_owned(),
                // L'empreinte GLOBALE du contrat C3 — LA formule partagée de
                // mod.rs, pour que le rejeu compare la même chose que les
                // vrais adaptateurs.
                digest: crate::adapters::empreinte_globale(texte, medias, sondage, made_with_ai),
                platform_limits_ok: texte.chars().count() <= 280,
                cost_estimate_usd: Some(0.015),
                verdicts: Vec::new(),
                media: medias
                    .iter()
                    .map(|m| ApercuMedia {
                        digest: m.digest.clone(),
                        size_bytes: m.octets.len() as u64,
                        detected_type: m.type_detecte.mime(),
                        alt_text: m.alt_text.clone(),
                        limits_ok: true,
                        verdicts: Vec::new(),
                    })
                    .collect(),
            }
        }
        async fn publier(
            &self,
            jeton: &Secret,
            handle: &str,
            _texte: &str,
            _medias: &[MediaPret],
            _sondage: Option<&Sondage>,
            _made_with_ai: bool,
        ) -> Result<Publication, ErreurPlateforme> {
            assert_eq!(
                jeton.expose_for_transport(),
                "jeton-plateforme",
                "le jeton descelle doit etre celui scelle"
            );
            assert_eq!(handle, "agent_test", "le handle du compte doit voyager");
            self.publications.fetch_add(1, Ordering::SeqCst);
            if self.jeton_mort {
                return Err(ErreurPlateforme::Refus { statut: 401 });
            }
            Ok(Publication {
                id_plateforme: "faux-123".into(),
                url: "https://x.com/agent_test/status/faux-123".into(),
            })
        }
        async fn metriques(
            &self,
            _jeton: &Secret,
            _id: &str,
        ) -> Result<Option<Metriques>, ErreurPlateforme> {
            Ok(None)
        }
    }

    /// Un Etat de test : pool reel, chiffreur de test, adaptateur compteur, et
    /// un tenant avec un compte au jeton scelle sous la vraie AAD.
    async fn etat_de_test() -> Option<(Etat, Uuid, Uuid, Arc<AtomicUsize>)> {
        let pool = crate::store::pool_de_test("mcp").await?;
        let chiffreur = Arc::new(LocalEnvelopeSecretStore::new(
            Sha256::digest("clef-de-test").into(),
        ));
        let tenant = Uuid::now_v7();
        sqlx::query("INSERT INTO social_tenants (id, label, token_hash) VALUES ($1, $2, $3)")
            .bind(tenant)
            .bind(format!("test-{tenant}"))
            .bind(vec![0u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        // Scelle par la MEME fonction que le vrai callback OAuth : si l'AAD
        // de sceller_jeton et celle d'ouvrir_jeton divergeaient, ce test-ci
        // ne descellerait plus rien.
        let scelle = oauth_flux::sceller_jeton(
            &chiffreur,
            TenantId::from_uuid(tenant),
            "x",
            "agent_test",
            &Secret::new("jeton-plateforme"),
        )
        .unwrap();
        let compte =
            crate::store::connecter_compte(&pool, tenant, "x", "agent_test", &scelle, None)
                .await
                .unwrap();
        let publications = Arc::new(AtomicUsize::new(0));
        let etat = Etat {
            pool,
            chiffreur,
            adaptateurs: vec![Box::new(Faux {
                publications: publications.clone(),
                jeton_mort: false,
            })],
            // Le constructeur de test : seul chemin qui accepte de parler aux
            // serveurs 127.0.0.1 que ces tests montent.
            telechargeur: medias::Telechargeur::de_test(medias::PLAFOND_ABSOLU_OCTETS),
            url_publique: "http://127.0.0.1:0".into(),
            oauth_x: None,
            oauth_linkedin: None,
        };
        Some((etat, tenant, compte, publications))
    }

    async fn appel(etat: &Etat, tenant: Uuid, outil: &str, args: Value) -> (bool, Value) {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": outil, "arguments": args }
        });
        let rep = traiter(etat, tenant, &req).await.expect("une reponse");
        let result = &rep["result"];
        let texte = result["content"][0]["text"]
            .as_str()
            .expect("contenu texte");
        (
            result["isError"].as_bool().unwrap(),
            serde_json::from_str(texte).unwrap(),
        )
    }

    #[tokio::test]
    async fn publier_deux_fois_avec_la_meme_cle_ne_publie_qu_une_fois() {
        let Some((etat, tenant, compte, publications)) = etat_de_test().await else {
            return;
        };
        let args = json!({
            "idempotency_key": "tour-42",
            "account_id": compte.to_string(),
            "text": "Bonjour le monde"
        });

        let (err1, un) = appel(&etat, tenant, "post_publish", args.clone()).await;
        let (err2, deux) = appel(&etat, tenant, "post_publish", args.clone()).await;
        assert!(!err1 && !err2, "{un} / {deux}");

        // Un seul appel plateforme, le meme post_id, et le rejeu se declare.
        assert_eq!(publications.load(Ordering::SeqCst), 1);
        assert_eq!(un["post_id"], deux["post_id"]);
        assert_eq!(un["platform_post_id"], deux["platform_post_id"]);
        assert_eq!(un["replayed"], false);
        assert_eq!(deux["replayed"], true);

        // La meme cle avec un AUTRE texte est un bug d'agent : refuse, et
        // toujours une seule publication.
        let (err3, trois) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({
                "idempotency_key": "tour-42",
                "account_id": compte.to_string(),
                "text": "Un texte different"
            }),
        )
        .await;
        assert!(err3, "{trois}");
        assert_eq!(trois["erreur"], "cle_reutilisee");
        assert_eq!(publications.load(Ordering::SeqCst), 1);
    }

    /// Le 401 sans matériel de rafraîchissement : la vérité sort telle quelle.
    ///
    /// Le compte n'a pas de refresh token et l'Etat n'a pas de credentials
    /// client — les deux raisons pour lesquelles `jeton_rafraichi` rend `None`.
    /// Ce qui se vérifie : l'erreur rendue est bien le `plateforme_refus`
    /// d'origine (pas un `descellement` ni un mot inventé par le chemin de
    /// refresh), il n'y a eu qu'UN appel plateforme (pas de rejeu aveugle ni de
    /// boucle), et le post est `failed` — donc la clé d'idempotence est
    /// re-réclamable, ce que le second appel prouve en repartant de zéro.
    #[tokio::test]
    async fn un_401_sans_refresh_rend_le_refus_d_origine_et_un_seul_appel() {
        let Some((mut etat, tenant, compte, publications)) = etat_de_test().await else {
            return;
        };
        etat.adaptateurs = vec![Box::new(Faux {
            publications: publications.clone(),
            jeton_mort: true,
        })];
        let args = json!({
            "idempotency_key": "tour-mort",
            "account_id": compte.to_string(),
            "text": "Bonjour le monde"
        });

        let (err, corps) = appel(&etat, tenant, "post_publish", args.clone()).await;
        assert!(err, "{corps}");
        // Le champ s'appelle `erreur` dans le corps rendu — c'est la forme
        // que `Erreur` serialise, pas une convention a moi.
        assert_eq!(corps["erreur"], "plateforme_refus", "{corps}");
        assert_eq!(
            publications.load(Ordering::SeqCst),
            1,
            "un 401 sans refresh ne doit produire aucun rejeu"
        );

        // La clé se re-réclame : l'échec a marqué 'failed', pas 'en vol'.
        let (err2, corps2) = appel(&etat, tenant, "post_publish", args).await;
        assert!(err2, "{corps2}");
        assert_eq!(publications.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn la_previsualisation_rend_l_empreinte_que_l_approbation_contresigne() {
        let Some((etat, tenant, compte, publications)) = etat_de_test().await else {
            return;
        };
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_preview",
            json!({ "account_id": compte.to_string(), "text": "Bonjour" }),
        )
        .await;
        assert!(!err, "{rep}");
        assert_eq!(rep["rendered_text"], "Bonjour");
        assert_eq!(rep["digest"], empreinte("Bonjour"));
        assert_eq!(rep["platform_limits_ok"], true);
        assert_eq!(rep["cost_estimate_usd"], 0.015);
        // Previsualiser ne publie RIEN.
        assert_eq!(publications.load(Ordering::SeqCst), 0);

        // Un texte hors limites est refuse a la publication sans consommer la
        // cle : le tour corrige la reutilise.
        let long = "a".repeat(300);
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({ "idempotency_key": "tour-l", "account_id": compte.to_string(), "text": long }),
        )
        .await;
        assert!(err);
        assert_eq!(rep["erreur"], "limites_plateforme");
        let (err, _) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({ "idempotency_key": "tour-l", "account_id": compte.to_string(), "text": "court" }),
        )
        .await;
        assert!(!err, "la cle d'un texte refuse doit rester utilisable");
    }

    #[tokio::test]
    async fn les_metriques_disent_quand_la_plateforme_ne_les_sert_pas() {
        let Some((etat, tenant, compte, _)) = etat_de_test().await else {
            return;
        };
        let (_, publie) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({ "idempotency_key": "tour-m", "account_id": compte.to_string(), "text": "Metriques" }),
        )
        .await;
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_metrics",
            json!({ "post_id": publie["post_id"] }),
        )
        .await;
        assert!(!err, "{rep}");
        // Le Faux rend Ok(None) — comme LinkedIn membre : pas des zeros, un
        // refus explique.
        assert_eq!(rep["available"], false);
        assert!(rep["raison"].as_str().unwrap().contains("ne sert pas"));
    }

    // -- Les medias : le pont contreseing -> octets publies. ----------------

    /// Le flux complet du contrat C4 : post_preview montre les digests, un
    /// expected divergent refuse en `media_change` SANS consommer la cle, le
    /// meme expected correct publie — et l'historique porte les digests.
    #[tokio::test]
    async fn un_digest_attendu_divergent_refuse_avant_de_bruler_la_cle() {
        let Some((etat, tenant, compte, publications)) = etat_de_test().await else {
            return;
        };
        let png = medias::octets_png(b"les octets contresignes");
        let base = medias::serveur_brut(medias::reponse_http("image/png", &png)).await;
        let url = format!("{base}/photo.png");

        // 1. L'apercu telecharge et empreinte : c'est ce que l'humain signe.
        let (err, apercu) = appel(
            &etat,
            tenant,
            "post_preview",
            json!({ "account_id": compte.to_string(), "text": "Avec image",
                    "media": [{ "url": url, "alt_text": "une image" }] }),
        )
        .await;
        assert!(!err, "{apercu}");
        let digest_media = apercu["media"][0]["digest"].as_str().unwrap().to_owned();
        assert_eq!(digest_media, medias::hex_sha256(&png));
        assert_eq!(apercu["media"][0]["detected_type"], "image/png");
        // L'empreinte globale n'est PLUS celle du texte seul : l'image est
        // dans le contreseing.
        assert_ne!(apercu["digest"], json!(empreinte("Avec image")));

        // 2. Un digest attendu divergent : refus nomme, index et valeurs, et
        //    AUCUN appel plateforme — la comparaison precede `reclamer`.
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({ "idempotency_key": "tour-img", "account_id": compte.to_string(),
                    "text": "Avec image", "media": [{ "url": url, "alt_text": "une image" }],
                    "expected_media_digests": ["0".repeat(64)] }),
        )
        .await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "media_change");
        assert!(
            rep["message"].as_str().unwrap().contains("media 0"),
            "{rep}"
        );
        assert_eq!(publications.load(Ordering::SeqCst), 0);

        // 3. La MEME cle avec le bon digest publie : elle n'a pas ete brulee.
        let (err, rep) = appel(
            &etat,
            tenant,
            "post_publish",
            json!({ "idempotency_key": "tour-img", "account_id": compte.to_string(),
                    "text": "Avec image", "media": [{ "url": url, "alt_text": "une image" }],
                    "expected_media_digests": [digest_media] }),
        )
        .await;
        assert!(!err, "{rep}");
        assert_eq!(publications.load(Ordering::SeqCst), 1);

        // 4. L'historique rend les digests des medias publies.
        let (err, liste) = appel(&etat, tenant, "posts_list", json!({})).await;
        assert!(!err, "{liste}");
        let post = liste["posts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["post_id"] == rep["post_id"])
            .expect("le post publie est dans l'historique");
        assert_eq!(post["media_digests"], json!([medias::hex_sha256(&png)]));
    }

    /// Le rejeu C3 : meme cle, meme texte, IMAGE differente — l'empreinte
    /// globale diverge et `reclamer` repond TexteDifferent sans qu'on ait
    /// touche sa logique.
    #[tokio::test]
    async fn la_meme_cle_avec_une_autre_image_est_refusee_comme_un_autre_texte() {
        let Some((etat, tenant, compte, publications)) = etat_de_test().await else {
            return;
        };
        let premiere = medias::serveur_brut(medias::reponse_http(
            "image/png",
            &medias::octets_png(b"image approuvee"),
        ))
        .await;
        let autre = medias::serveur_brut(medias::reponse_http(
            "image/png",
            &medias::octets_png(b"image substituee"),
        ))
        .await;

        let args = |base: &str| {
            json!({ "idempotency_key": "tour-swap", "account_id": compte.to_string(),
                    "text": "Le meme texte", "media": [{ "url": format!("{base}/i.png") }] })
        };
        let (err, rep) = appel(&etat, tenant, "post_publish", args(&premiere)).await;
        assert!(!err, "{rep}");

        let (err, rep) = appel(&etat, tenant, "post_publish", args(&autre)).await;
        assert!(err, "{rep}");
        assert_eq!(rep["erreur"], "cle_reutilisee");
        assert_eq!(publications.load(Ordering::SeqCst), 1);
    }
}
