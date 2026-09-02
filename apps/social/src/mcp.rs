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

use crate::adapters::Plateforme;
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
pub const VERSION_TABLE: &str = "1";

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
        {
            "name": "post_preview",
            "description": "Le contenu EXACT qui partirait, son empreinte SHA-256, le verdict des limites de plateforme et le cout estime. C'est ce qu'une approbation humaine contresigne.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "text": { "type": "string" }
                },
                "required": ["account_id", "text"],
                "additionalProperties": false
            }
        },
        {
            "name": "post_publish",
            "description": "Publie un texte. idempotency_key OBLIGATOIRE : rejouer la meme cle rend le meme post sans republier.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "idempotency_key": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "account_id": { "type": "string" },
                    "text": { "type": "string" }
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
                "digest": p.digest, "status": p.status,
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

    // Texte seul, jour un : ce qui part est exactement ce qui entre — c'est
    // l'adaptateur qui le promet (son test fige rendered_text == texte), et
    // l'empreinte rendue ici est celle que post_publish recalculera.
    // cost_estimate_usd est PAR TEXTE : un lien dans un post X multiplie le
    // tarif par treize, et l'apercu contresigne doit le montrer.
    Ok(serde_json::to_value(adaptateur.apercu(texte)).expect("Apercu se serialise"))
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

    // Limites AVANT la reclamation : un texte invalide ne consomme pas la cle,
    // pour que le tour corrige puisse la reutiliser.
    let apercu = adaptateur.apercu(texte);
    if !apercu.platform_limits_ok {
        return Err(Erreur::nouvelle(
            "limites_plateforme",
            format!(
                "texte hors limites pour {} — post_preview donne le verdict avant de bruler un appel",
                compte.platform
            ),
        ));
    }

    // La meme empreinte que post_preview a montree : c'est elle que
    // l'approbation humaine a contresignee, et elle que le rejeu compare.
    let digest = apercu.digest;
    let id = match store::reclamer(&etat.pool, tenant, compte_id, cle, texte, &digest).await? {
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

    match adaptateur.publier(&jeton, &compte.handle, texte).await {
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
    use crate::adapters::{Apercu, ErreurPlateforme, Metriques, Publication, empreinte};

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
    const EMPREINTES: &[(&str, &str)] = &[(
        "1",
        "2d8f2821a0c4cc02f85ea5cdf650c1e6e3c0d57afb4d87bad514013cf9cbffbe",
    )];

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
    }

    #[async_trait]
    impl Plateforme for Faux {
        fn nom(&self) -> &'static str {
            "x"
        }
        fn apercu(&self, texte: &str) -> Apercu {
            Apercu {
                rendered_text: texte.to_owned(),
                digest: empreinte(texte),
                platform_limits_ok: texte.chars().count() <= 280,
                cost_estimate_usd: Some(0.015),
            }
        }
        async fn publier(
            &self,
            jeton: &Secret,
            handle: &str,
            _texte: &str,
        ) -> Result<Publication, ErreurPlateforme> {
            assert_eq!(
                jeton.expose_for_transport(),
                "jeton-plateforme",
                "le jeton descelle doit etre celui scelle"
            );
            assert_eq!(handle, "agent_test", "le handle du compte doit voyager");
            self.publications.fetch_add(1, Ordering::SeqCst);
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
            })],
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
}
