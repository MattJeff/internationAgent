//! `POST /v1/mcp/server` : la société entière, pilotable depuis un terminal.
//!
//! [`agentos_app::mcp_server`] a posé la table — un outil est une ligne, pas une
//! fonction. Ce module est les deux moitiés qui manquaient : **l'exécuteur** qui
//! joue une ligne sur le `Router` d'axum déjà construit, et **le transport**
//! JSON-RPC que Claude Code parle.
//!
//! # Pourquoi un serveur et pas un abonnement sur le VPS
//!
//! Poser l'abonnement Claude du fondateur sur le VPS n'est pas une question de
//! faisabilité. **Et ce n'est pas non plus une clause** — la vérification du
//! 2026-09-10 a contredit la phrase que ce commentaire disait d'abord : aucun
//! document publié par Anthropic ne nomme l'arrangement « abonnement hébergé qui
//! intermédie » pour l'interdire. Ce qui l'interdit est la conjonction de deux
//! phrases des Conditions consommateur (effet 2025-10-08), « You may not […]
//! make your Account available to anyone else » et la barre sur l'accès
//! automatisé hors clé d'API. `docs/MCP_SERVEUR.md` les cite mot pour mot, avec
//! leur date et l'édition servie ; une doc qui invente un numéro de clause est
//! une doc qu'un juriste démonte au premier contrôle.
//!
//! Le sens de la marche, lui, ne pose aucune de ces deux questions : **son**
//! Claude Code, sur **sa** machine, sous **ses** identifiants, se connecte à un
//! serveur MCP tiers. C'est un humain devant un terminal, pas un service qui
//! rend le compte de quelqu'un disponible à quelqu'un d'autre.
//!
//! # Le protocole est écrit à la main, et rmcp reste un client
//!
//! `rmcp` est dans le workspace en `default-features = false` avec **seulement**
//! les features client — c'est [`agentos_app::mcp`], qui appelle les serveurs des
//! autres. Activer `server` pour ce module ferait entrer un transport, un cycle
//! de vie de session, un routeur d'outils et un jeu de types dérivés d'une macro
//! `#[tool]`, pour un besoin qui tient en un `match` sur trois noms de méthode et
//! deux objets JSON. Le dépôt a déjà tranché ainsi une fois — CDP est du JSON-RPC
//! sur une websocket et `crates/providers` le parle à la main plutôt que
//! d'embarquer chromiumoxide — et pour la même raison : la surface qu'on écrit
//! est plus petite que la surface qu'on importerait.
//!
//! Trois méthodes suffisent parce que le serveur est sans état : pas de
//! ressources, pas de prompts, pas d'abonnement à un changement de liste
//! (`listChanged: false`, et c'est vrai — la table est une constante).
//!
//! # Les permissions ne sont pas réinventées, elles sont rejouées
//!
//! L'en-tête `Authorization` reçu est recopié tel quel dans chaque requête
//! interne, et cette requête interne traverse `with_api_stack` : la Gate, les
//! rôles, la limite de débit et l'isolation par locataire s'appliquent sans une
//! ligne de plus ici. Un refus remonte au client MCP avec **le code et le détail
//! que le produit écrit déjà** — le document de problème RFC 9457 de
//! `crate::error`, recopié, jamais reformulé.
//!
//! La route elle-même est montée **hors** de `with_api_stack`, et c'est le seul
//! endroit où ce module s'écarte du reste : un client MCP appelle `initialize`
//! avant d'avoir quoi que ce soit à présenter, et un 401 sur cette sonde est un
//! client qui n'affiche jamais le serveur. Donc `initialize` passe sans clé, et
//! `tools/list` comme `tools/call` sont refusés par [`Keyring`] — la même
//! résolution que `auth::require_api_key`, par la même fonction
//! ([`Keyring::principal_of`]), rendue par le même `auth::unauthorized()`. Une
//! clé absente échoue **avant** qu'un outil soit atteint, et échoue exactement
//! comme partout ailleurs.
//!
//! # La boucle, fermée deux fois
//!
//! Un outil qui rappellerait `/v1/mcp/server` serait une récursion dont le fond
//! est la pile. Le routeur qu'on donne à l'exécuteur est **le seul étage `api`**,
//! construit avant que la route MCP ne soit greffée : la boucle n'est pas
//! seulement interdite, elle n'est pas exprimable, et il n'y a pas non plus de
//! cycle `Arc` entre un routeur et l'état d'un de ses propres gestionnaires. La
//! deuxième garde est déclarative — `no_tool_can_call_the_mcp_server_back` relit
//! toute la table — parce que la première protège d'une erreur de câblage et la
//! seconde d'une ligne ajoutée par distraction.

use std::sync::{Arc, Mutex, OnceLock};

use agentos_app::mcp_server::ToolDef;
use agentos_app::mcp_tools::registry;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use crate::MAX_BODY_BYTES;
use crate::auth::Keyring;
use crate::error::ApiError;

/// Le seul chemin de ce module. Nommé plutôt qu'écrit deux fois : la garde
/// anti-boucle le compare à chaque ligne de la table.
pub const PATH: &str = "/v1/mcp/server";

/// Le voyant d'installation : combien d'outils, et si un client s'est déjà
/// présenté.
///
/// Sous `PATH`, donc **hors** du routeur que l'exécuteur rejoue, donc aucun
/// outil ne peut l'appeler (`no_tool_can_call_the_mcp_server_back` refuse tout
/// ce qui est sous ce chemin, et cette route n'est de toute façon pas dans
/// l'étage `api`). C'est la console qui la lit, avec la clé de la session.
pub const STATUS_PATH: &str = "/v1/mcp/server/status";

/// La révision du protocole que ce serveur parle.
///
/// Annoncée en dur et non négociée : les trois méthodes implémentées existent à
/// l'identique dans toutes les révisions publiées, donc renvoyer la version du
/// client serait prétendre parler la sienne sans rien y gagner.
const PROTOCOL: &str = "2025-06-18";

/// Ce que le modèle lit **avant** la liste des outils, une fois par session.
///
/// En français, et long d'un écran plutôt que d'une ligne, parce que c'est le
/// seul endroit où l'on peut dire ce que cette société *est*. Un client qui
/// reçoit trente outils sans ce texte les essaie dans l'ordre alphabétique.
const INSTRUCTIONS: &str = "\
Ce serveur est le panneau de commande d'une société d'employés logiciels : des \
sièges qui prospectent, écrivent, relancent, facturent et rendent compte, sous \
une politique qui peut refuser une action et le dire.

Par où commencer : `tools/list`, puis les outils du domaine « société » — les \
employés, les équipes, les limites. C'est l'état des lieux. Les outils de \
« commerce » agissent vers l'extérieur (prospects, séquences, devis, factures) \
et ceux d'« exploitation » regardent la machine (journal, dépenses, files, \
approbations).

Trois choses à savoir avant d'agir :

1. Chaque outil est une route HTTP de ce déploiement, jouée avec votre clé. Ce \
que vous n'avez pas le droit de faire est refusé ici comme il le serait depuis \
la console, avec le même code d'erreur.
2. Un refus n'est pas une panne. `pending_approval` veut dire qu'un humain doit \
valider, `halted` que la société est à l'arrêt, `daily_limit` qu'un plafond est \
atteint. Rapportez le code, ne le contournez pas.
3. Les outils marqués destructifs engagent la société devant un tiers — un \
envoi, un paiement, une signature. Demandez avant.";

// ---------------------------------------------------------------------------
// L'état, et le routeur qu'il rejoue
// ---------------------------------------------------------------------------

/// Ce que la route MCP a besoin de connaître : qui appelle, et sur quoi rejouer.
#[derive(Clone)]
pub struct McpServerState {
    /// La même composition de trousseaux que `auth::require_api_key` consulte.
    keys: Keyring,
    /// L'étage `api` de `crate::app`, posé par [`McpServerState::attach`] une
    /// fois qu'il est construit.
    ///
    /// Un `OnceLock` et non un champ, parce que le routeur ne peut pas exister
    /// avant l'état qu'un de ses gestionnaires détient. C'est une dépendance
    /// circulaire dans le temps, pas dans le graphe d'objets : l'étage `api` ne
    /// contient pas cette route, donc rien ne se référence soi-même et rien ne
    /// fuit. Non posé, tout `tools/call` répond une erreur interne plutôt que de
    /// paniquer — une route qui n'est pas câblée est une panne de déploiement,
    /// pas de requête.
    inner: Arc<OnceLock<Router>>,
    /// La dernière poignée de main réussie, **en mémoire de ce processus**.
    ///
    /// Pas une table, et c'est un choix plutôt qu'une économie : ce que le
    /// fondateur demande à cet écran est « est-ce que mon terminal parle à ce
    /// déploiement », question dont la réponse utile vaut quelques minutes. Une
    /// ligne par `initialize` serait un journal — une écriture sur le chemin
    /// d'une sonde non authentifiée, donc un chemin d'écriture ouvert à qui
    /// n'a pas de clé.
    ///
    /// ponytail : une seule case pour tout le déploiement, et elle est perdue
    /// au redémarrage. Perdue = « aucune session vue » sur un serveur qui
    /// marche, ce qui se rattrape en relançant `/mcp` dans le terminal ; c'est
    /// acceptable parce que c'est un voyant d'installation, pas une preuve. La
    /// case n'est pas non plus par locataire : `initialize` passe sans clé (voir
    /// les docs du module), donc il n'y a personne à qui l'attribuer. Le jour où
    /// le multi-locataire s'allume, il faudra d'abord décider ce qu'on retient
    /// d'une sonde anonyme — et sans doute ne noter que les `tools/list`, qui
    /// eux portent une clé.
    seen: Arc<Mutex<Option<Handshake>>>,
}

/// Qui s'est présenté, et quand.
#[derive(Clone)]
struct Handshake {
    /// `clientInfo.name` et sa version, tels que le client les a dits. Une
    /// chaîne et pas deux champs : le seul lecteur l'affiche telle quelle.
    client: Option<String>,
    at: DateTime<Utc>,
}

impl McpServerState {
    /// L'état, avant que le routeur n'existe.
    #[must_use]
    pub fn new(keys: Keyring) -> Self {
        Self {
            keys,
            inner: Arc::new(OnceLock::new()),
            seen: Arc::new(Mutex::new(None)),
        }
    }

    /// Donne à l'exécuteur le routeur qu'il jouera. Appelé une fois, au boot.
    pub fn attach(&self, api: Router) {
        // `set` échoue si quelqu'un a déjà posé un routeur ; le deuxième serait
        // le même de toute façon, et paniquer au boot pour ça serait pire.
        let _ = self.inner.set(api);
    }

    /// Retenir qui vient de se présenter.
    ///
    /// Un verrou empoisonné est ignoré plutôt que propagé : ce qu'il garde est
    /// un voyant, et refuser une poignée de main parce qu'un thread a paniqué
    /// ailleurs coûterait la session qu'on essaie justement d'établir.
    fn note_handshake(&self, client: Option<String>, at: DateTime<Utc>) {
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(Handshake { client, at });
        }
    }

    fn last_handshake(&self) -> Option<Handshake> {
        self.seen.lock().ok().and_then(|seen| seen.clone())
    }
}

/// `clientInfo` d'un `initialize`, en une ligne affichable.
///
/// `None` quand le client ne se nomme pas : MCP le demande, tous ne le font
/// pas, et inventer « inconnu » ici mettrait ce mot dans une console au lieu de
/// la laisser dire ce qu'elle veut d'une absence.
fn client_of(request: &Value) -> Option<String> {
    let info = request.get("params")?.get("clientInfo")?;
    let name = info.get("name").and_then(Value::as_str)?;
    Some(match info.get("version").and_then(Value::as_str) {
        Some(version) => format!("{name} {version}"),
        None => name.to_owned(),
    })
}

/// La route. **À monter hors de `with_api_stack`** — voir les docs du module.
pub fn router(state: McpServerState) -> Router {
    Router::new()
        .route(PATH, post(rpc))
        .route(STATUS_PATH, get(status))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// L'exécuteur
// ---------------------------------------------------------------------------

/// Un outil qui n'a pas abouti.
///
/// `problem` est le document RFC 9457 de la route, **recopié**. Le produit a
/// déjà écrit ce texte une fois ; le réécrire ici, c'est deux vocabulaires pour
/// une même règle, et un tableau de bord qui cesse de compter le jour où l'un
/// des deux est reformulé.
#[derive(Debug)]
pub struct ToolError {
    /// Le code stable du produit (`not_found`, `daily_limit`…), ou celui que cet
    /// exécuteur donne à un appel qu'il refuse avant d'avoir appelé quoi que ce
    /// soit.
    pub code: String,
    /// Une phrase pour un humain : le `title` de la route, plus son `detail`.
    pub message: String,
    /// Le document de problème entier, quand le refus vient d'une route.
    pub problem: Option<Value>,
}

impl ToolError {
    /// Un appel que l'exécuteur refuse : arguments hors schéma, trou non fourni.
    /// Rien n'a été joué, donc il n'y a pas de document de produit à recopier.
    fn refused(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            problem: None,
        }
    }

    /// Le refus d'une route, tel qu'elle l'a écrit.
    fn from_problem(status: StatusCode, problem: Option<Value>) -> Self {
        let field = |key: &str| {
            problem
                .as_ref()
                .and_then(|doc| doc.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let code = field("code").unwrap_or_else(|| status.as_u16().to_string());
        let title = field("title").unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("la route a refusé")
                .to_owned()
        });
        let message = match field("detail") {
            Some(detail) => format!("{title} : {detail}"),
            None => title,
        };
        Self {
            code,
            message,
            problem,
        }
    }

    /// Ce que le client MCP affiche : le document du produit s'il y en a un,
    /// sinon la phrase.
    fn text(&self) -> String {
        match &self.problem {
            Some(problem) => {
                serde_json::to_string_pretty(problem).unwrap_or_else(|_| self.message.clone())
            }
            None => format!("{} : {}", self.code, self.message),
        }
    }
}

/// Les caractères qu'un segment d'URL garde tels quels : l'`unreserved` de la
/// RFC 3986, et rien d'autre.
///
/// Encoder est le sujet, pas un détail. Un identifiant peut contenir un `/` — un
/// nom de domaine d'envoi, un nom de fichier du classeur — et un `/` non encodé
/// n'est pas un caractère de plus dans un segment, c'est un segment de plus dans
/// le chemin : la requête part sur une autre route, qui répond 404 à un outil que
/// le modèle croit avoir bien appelé. Le même jeu sert la chaîne de requête, où
/// `&` et `=` posent le problème symétrique.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode(raw: &str) -> String {
    utf8_percent_encode(raw, UNRESERVED).to_string()
}

/// La valeur d'un argument, telle qu'elle s'écrit dans une URL.
///
/// `to_string()` d'une `Value::String` rendrait les guillemets ; tout le reste
/// (nombre, booléen) s'écrit déjà comme il se lit.
fn as_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Joue une ligne de la table sur le routeur, en interne.
///
/// Jamais par le réseau : `tower::ServiceExt::oneshot` appelle le `Service`
/// directement, donc aucune socket, aucun TLS, aucune résolution DNS et — ce qui
/// compte davantage — aucun moyen pour un outil d'atteindre un hôte que ce
/// routeur ne sert pas.
///
/// `authorization` est recopié **tel quel**. Pas re-signé, pas re-préfixé : ce
/// que le client MCP a présenté est ce que la pile d'authentification voit.
///
/// # Erreurs
///
/// [`ToolError`] si les arguments ne correspondent pas au schéma, ou si la route
/// a répondu autre chose qu'un 2xx — auquel cas l'erreur porte le code et le
/// détail que la route a écrits.
pub async fn execute(
    router: &Router,
    tool: &ToolDef,
    args: Value,
    authorization: Option<&str>,
) -> Result<Value, ToolError> {
    let args = match args {
        Value::Null => Map::new(),
        Value::Object(map) => map,
        _ => {
            return Err(ToolError::refused(
                "bad_arguments",
                "les arguments doivent être un objet JSON",
            ));
        }
    };

    // Refusé **avant** l'appel, et pas filtré en silence : un argument que le
    // schéma ne nomme pas est soit une faute de frappe du modèle, soit une
    // tentative de pousser un champ que la route lit et que l'outil n'annonce
    // pas. Les deux méritent d'être dits.
    let declared = tool.properties();
    if let Some(unknown) = args.keys().find(|key| !declared.contains(&key.as_str())) {
        return Err(ToolError::refused(
            "bad_arguments",
            format!(
                "{unknown:?} n'est pas une propriété du schéma de {}",
                tool.name
            ),
        ));
    }

    let mut path = String::with_capacity(tool.path.len());
    let mut rest = tool.path;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        let name = &rest[open + 1..open + close];
        path.push_str(&rest[..open]);
        let Some(value) = args.get(name) else {
            return Err(ToolError::refused(
                "bad_arguments",
                format!(
                    "{name:?} est requis : le chemin de {} en a un trou",
                    tool.name
                ),
            ));
        };
        path.push_str(&encode(&as_text(value)));
        rest = &rest[open + close + 1..];
    }
    path.push_str(rest);

    let mut query = String::new();
    for name in tool.query {
        // Absente des arguments : la propriété n'est pas envoyée du tout. Un
        // `?status=` vide n'est pas la même requête qu'un `?` absent — la
        // première dit « filtre sur la chaîne vide ».
        if let Some(value) = args.get(*name) {
            query.push(if query.is_empty() { '?' } else { '&' });
            query.push_str(&encode(name));
            query.push('=');
            query.push_str(&encode(&as_text(value)));
        }
    }

    let holes = tool.placeholders();
    // Le corps brut, s'il y en a un : la propriété nommée part telle quelle,
    // avec son type MIME, et rien d'autre ne devient un corps. C'est ce qui
    // rend `POST /v1/prospects/import` atteignable — elle lit des octets et
    // refuse en 415 tout ce qui n'est pas `text/csv`.
    let raw = tool.raw_body.and_then(|(mime, property)| {
        args.get(property)
            .map(|value| (mime, as_text(value).into_bytes()))
    });
    let body: Map<String, Value> = args
        .into_iter()
        .filter(|(key, _)| {
            !holes.contains(&key.as_str())
                && !tool.query.contains(&key.as_str())
                && tool.raw_body.is_none_or(|(_, property)| key != property)
        })
        .collect();

    let mut request = HttpRequest::builder()
        .method(tool.method.as_str())
        .uri(format!("{path}{query}"));
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    // Corps vide : **aucun** corps, et pas un `{}`. C'est ce qui distingue un
    // `DELETE` d'un `POST {}` — la seconde forme donne un `content-type` et un
    // corps à une route qui n'attend rien, et l'extracteur y répond par un code
    // que personne n'associerait à un outil sans argument.
    let request = if let Some((mime, bytes)) = raw {
        request
            .header(header::CONTENT_TYPE, mime)
            .body(Body::from(bytes))
    } else if body.is_empty() {
        request.body(Body::empty())
    } else {
        request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(Value::Object(body).to_string()))
    };
    let request = request.map_err(|err| {
        ToolError::refused("bad_arguments", format!("requête inconstructible : {err}"))
    })?;

    let response = match router.clone().oneshot(request).await {
        Ok(response) => response,
        // Le type d'erreur d'un `Router` est `Infallible` : il n'y a pas de
        // branche à écrire, seulement à prouver qu'elle n'existe pas.
        Err(never) => match never {},
    };

    let status = response.status();
    let Ok(bytes) = to_bytes(response.into_body(), MAX_BODY_BYTES).await else {
        return Err(ToolError::refused(
            "internal",
            "la réponse de la route n'a pas pu être lue",
        ));
    };

    if status.is_success() {
        if bytes.is_empty() {
            // 204, ou toute route qui réussit sans rien dire. `{"ok": true}`
            // plutôt que `null` : un modèle qui lit `null` conclut qu'il a
            // échoué et recommence.
            return Ok(json!({"ok": true}));
        }
        return serde_json::from_slice(&bytes).map_err(|_| {
            ToolError::refused("internal", "la route a répondu autre chose que du JSON")
        });
    }

    Err(ToolError::from_problem(
        status,
        serde_json::from_slice(&bytes).ok(),
    ))
}

// ---------------------------------------------------------------------------
// Le transport
// ---------------------------------------------------------------------------

/// Codes JSON-RPC 2.0. Les mêmes littéraux que `routes::a2a::code`, et pour la
/// même raison : il n'y a pas de constantes à importer.
mod code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// Une méthode qui n'a pas abouti, répondue dans un 200 : l'appel HTTP a réussi,
/// la méthode non.
struct RpcError {
    code: i32,
    message: String,
}

impl RpcError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Les deux façons dont une requête MCP s'arrête.
enum Refusal {
    /// Une erreur de méthode : l'enveloppe JSON-RPC, dans un 200.
    Rpc(RpcError),
    /// Une réponse HTTP entière, parce que le client doit la voir comme telle —
    /// le 401 qui le fait retenter avec une clé, le 503 d'une base absente.
    ///
    /// Boxée : une `Response` pèse quatre fois une `RpcError`, et `clippy`
    /// compte la taille de la variante la plus grosse dans chaque `Result` que
    /// ce module rend, y compris ceux qui n'échouent jamais par là.
    Http(Box<Response>),
}

impl From<RpcError> for Refusal {
    fn from(err: RpcError) -> Self {
        Self::Rpc(err)
    }
}

/// Un outil, tel que `tools/list` l'annonce.
fn described(tool: &ToolDef) -> Value {
    json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.schema,
        "annotations": {
            // Répété ici parce que les clients d'avant 2025-06-18 lisent le
            // titre dans les annotations et ceux d'après à la racine ; deux
            // copies d'un `&'static str` valent mieux qu'un outil sans nom
            // lisible dans la moitié des terminaux.
            "title": tool.title,
            "readOnlyHint": tool.risk.read_only(),
            "destructiveHint": tool.risk.destructive(),
        },
    })
}

fn failure(id: Value, err: &RpcError) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": err.code, "message": err.message},
    }))
    .into_response()
}

/// `GET /v1/mcp/server/status` — le voyant que la console relit.
///
/// Authentifié comme `tools/list`, par la même fonction et rendu par le même
/// `auth::unauthorized()` : cette route dit ce que ce déploiement expose, et
/// c'est une phrase de locataire.
async fn status(State(state): State<McpServerState>, headers: HeaderMap) -> Response {
    match state
        .keys
        .principal_of(headers.get(header::AUTHORIZATION))
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return crate::auth::unauthorized(),
        Err(err) => return ApiError::from(err).into_response(),
    }

    let seen = state.last_handshake();
    Json(json!({
        // La table, comptée là où elle est écrite. Un nombre en dur ici serait
        // un nombre faux le jour où un outil est ajouté.
        "tools": registry().len(),
        "last_session_at": seen.as_ref().map(|handshake| handshake.at),
        "last_client": seen.and_then(|handshake| handshake.client),
    }))
    .into_response()
}

async fn rpc(State(state): State<McpServerState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return failure(
            Value::Null,
            &RpcError::new(code::PARSE_ERROR, "le corps n'est pas du JSON"),
        );
    };

    // Pas d'`id` : c'est une notification, et JSON-RPC interdit d'y répondre.
    // Claude Code en envoie une (`notifications/initialized`) juste après
    // `initialize`, et le transport HTTP de MCP demande un 202 sans corps. Ce
    // n'est pas une quatrième méthode — c'est la règle d'enveloppe qui rend les
    // trois autres utilisables par un vrai client.
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };

    match dispatch(&state, &headers, &request).await {
        Ok(result) => Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response(),
        Err(Refusal::Rpc(err)) => failure(id, &err),
        Err(Refusal::Http(response)) => *response,
    }
}

/// Enveloppe, méthode, clé — puis, et seulement puis, le travail.
///
/// L'ordre est le sujet. Une enveloppe qui n'est pas du JSON-RPC est refusée
/// avant qu'on lise un nom de méthode ; une méthode inconnue avant qu'on touche
/// au trousseau ; et la clé est exigée avant que le nom d'un outil soit même
/// cherché dans la table, donc un appelant sans clé n'apprend pas quels outils
/// existent.
async fn dispatch(
    state: &McpServerState,
    headers: &HeaderMap,
    request: &Value,
) -> Result<Value, Refusal> {
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(RpcError::new(code::INVALID_REQUEST, "jsonrpc doit valoir \"2.0\"").into());
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(code::INVALID_REQUEST, "method est requis"))?;

    if method == "initialize" {
        // Notée avant de répondre, et sans clé : c'est la poignée de main
        // elle-même qu'on note, et elle n'en présente pas (voir les docs du
        // module). Un client qui se présente mais dont la clé est fausse
        // s'affichera donc comme « vu » ici et échouera sur `tools/list` — ce
        // qui est la vérité, et la distinction que la console rend en disant
        // le nom du client plutôt qu'« authentifié ».
        state.note_handshake(client_of(request), Utc::now());
        return Ok(json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "siglair", "version": env!("CARGO_PKG_VERSION")},
            "instructions": INSTRUCTIONS,
        }));
    }
    if !matches!(method, "tools/list" | "tools/call") {
        return Err(RpcError::new(
            code::METHOD_NOT_FOUND,
            format!("aucune méthode MCP nommée {method}"),
        )
        .into());
    }

    // Tout ce qui suit touche aux données d'un locataire.
    let authorization = headers.get(header::AUTHORIZATION);
    match state.keys.principal_of(authorization).await {
        Ok(Some(_)) => {}
        // Un 401 HTTP et non une erreur JSON-RPC : c'est ce qui fait retenter un
        // client avec une clé, et c'est mot pour mot ce que toute autre route de
        // ce serveur répond à la même requête, `WWW-Authenticate` compris.
        Ok(None) => return Err(Refusal::Http(Box::new(crate::auth::unauthorized()))),
        // Jamais un 401 : une base indisponible ne se distinguerait pas d'une
        // mauvaise clé, et tout le monde ferait tourner un secret qui va bien.
        Err(err) => return Err(Refusal::Http(Box::new(ApiError::from(err).into_response()))),
    }

    if method == "tools/list" {
        return Ok(json!({"tools": registry().iter().map(described).collect::<Vec<_>>()}));
    }

    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "params.name est requis"))?;
    let table = registry();
    let tool = table
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, format!("aucun outil nommé {name}")))?;

    let Some(api) = state.inner.get() else {
        return Err(RpcError::new(
            code::INTERNAL_ERROR,
            "le serveur MCP n'a pas de routeur : ce déploiement est mal câblé",
        )
        .into());
    };

    // `to_str` échoue sur un en-tête non ASCII, qui n'aurait de toute façon
    // authentifié personne — mais on n'arrive ici qu'une fois la clé prouvée,
    // donc le cas est mort et le `and_then` est ce qui le dit sans paniquer.
    let authorization = authorization.and_then(|value| value.to_str().ok());
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    Ok(match execute(api, tool, arguments, authorization).await {
        Ok(value) => json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            }],
        }),
        // `isError` et non une erreur JSON-RPC : un refus du produit est un
        // résultat que le modèle doit lire et rapporter, pas une panne de
        // transport que le client doit retenter.
        Err(err) => json!({
            "content": [{"type": "text", "text": err.text()}],
            "isError": true,
        }),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentos_app::mcp_server::{Method, Risk};
    use agentos_domain::ids::TenantId;
    use agentos_store::db::Db;
    use axum::extract::Request as Extracted;
    use axum::routing::any;

    use super::*;
    use crate::auth::ApiKeys;

    /// Assez long pour `ApiKeys::MIN_SECRET_LEN`.
    const SECRET: &str = "mcpmcpmcpmcpmcpmcpmcpmcpmcpmcpmc";

    /// Une ligne de table, fabriquée pour un test.
    ///
    /// Le registre réel est **vide** sur cette branche — trois autres chantiers
    /// le remplissent en parallèle — et c'est délibérément ce que ces tests
    /// supposent : un exécuteur qui ne marche que sur les lignes déjà écrites
    /// est un exécuteur testé contre lui-même.
    fn tool(
        name: &'static str,
        method: Method,
        path: &'static str,
        schema: Value,
        query: &'static [&'static str],
        risk: Risk,
    ) -> ToolDef {
        ToolDef {
            name,
            title: "un outil de test",
            description: "ce que ça fait, et quand s'en servir",
            method,
            path,
            schema,
            query,
            raw_body: None,
            risk,
        }
    }

    /// Un routeur qui répond ce qu'il a reçu. La seule façon d'affirmer quelque
    /// chose sur la requête que l'exécuteur **construit** plutôt que sur ce
    /// qu'une route en fait.
    fn echo() -> Router {
        Router::new().fallback(any(|request: Extracted| async move {
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let content_type = request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let authorization = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let bytes = to_bytes(request.into_body(), 64 * 1024)
                .await
                .expect("body");
            Json(json!({
                "method": method,
                "uri": uri,
                "content_type": content_type,
                "authorization": authorization,
                "body": String::from_utf8_lossy(&bytes),
            }))
        }))
    }

    // -- l'exécuteur --------------------------------------------------------

    /// Un trou vaut un segment, pas un chemin. Un identifiant qui porte un `/`
    /// et qu'on recopierait tel quel enverrait la requête sur une autre route.
    #[tokio::test]
    async fn a_hole_is_filled_and_percent_encoded() {
        let tool = tool(
            "files_get",
            Method::Get,
            "/v1/files/{name}",
            json!({"properties": {"name": {"type": "string"}}}),
            &[],
            Risk::Read,
        );
        let played = execute(
            &echo(),
            &tool,
            json!({"name": "dossier/note d'été.txt"}),
            None,
        )
        .await
        .expect("2xx");

        assert_eq!(
            played["uri"],
            json!("/v1/files/dossier%2Fnote%20d%27%C3%A9t%C3%A9.txt")
        );
        // Le désarmement : sans encodage, l'URI porterait un segment de plus, et
        // c'est exactement ce que la route ne verrait jamais.
        assert!(
            !played["uri"].as_str().expect("uri").contains("/note"),
            "le `/` de l'identifiant a fabriqué un segment : {}",
            played["uri"]
        );
    }

    /// Un trou que les arguments ne nomment pas est un 404 qu'on refuse d'aller
    /// chercher.
    #[tokio::test]
    async fn a_missing_hole_is_refused_rather_than_sent_as_braces() {
        let tool = tool(
            "files_get",
            Method::Get,
            "/v1/files/{name}",
            json!({"properties": {"name": {"type": "string"}}}),
            &[],
            Risk::Read,
        );
        let err = execute(&echo(), &tool, json!({}), None)
            .await
            .expect_err("le trou n'est pas rempli");
        assert_eq!(err.code, "bad_arguments");
        assert!(err.message.contains("name"), "{}", err.message);
    }

    /// Un `DELETE` sans corps n'est pas un `POST {}` : rien ne part, et pas même
    /// un `content-type`.
    #[tokio::test]
    async fn a_delete_with_nothing_left_over_sends_no_body_at_all() {
        let bare = tool(
            "employees_terminate",
            Method::Delete,
            "/v1/employees/{id}",
            json!({"properties": {"id": {"type": "string"}}}),
            &[],
            Risk::Destructive,
        );
        let played = execute(&echo(), &bare, json!({"id": "abc"}), None)
            .await
            .expect("2xx");
        assert_eq!(played["method"], json!("DELETE"));
        assert_eq!(played["body"], json!(""), "un corps est parti");
        assert_eq!(played["content_type"], Value::Null);

        // Le désarmement : la même ligne avec une propriété de corps, fournie.
        let with_body = tool(
            "employees_terminate",
            Method::Delete,
            "/v1/employees/{id}",
            json!({"properties": {"id": {"type": "string"}, "reason": {"type": "string"}}}),
            &[],
            Risk::Destructive,
        );
        let played = execute(
            &echo(),
            &with_body,
            json!({"id": "abc", "reason": "fin"}),
            None,
        )
        .await
        .expect("2xx");
        assert_eq!(played["body"], json!("{\"reason\":\"fin\"}"));
        assert_eq!(played["content_type"], json!("application/json"));
    }

    /// Une propriété du schéma absente des arguments n'est jamais envoyée :
    /// `?status=` dit « filtre sur la chaîne vide », ce qui n'est pas « ne
    /// filtre pas ».
    #[tokio::test]
    async fn a_property_absent_from_the_arguments_is_not_sent() {
        let tool = tool(
            "employees_list",
            Method::Get,
            "/v1/employees",
            json!({"properties": {"status": {"type": "string"}, "note": {"type": "string"}}}),
            &["status"],
            Risk::Read,
        );

        let played = execute(&echo(), &tool, json!({}), None).await.expect("2xx");
        assert_eq!(played["uri"], json!("/v1/employees"));
        assert_eq!(played["body"], json!(""), "un corps vide n'est pas envoyé");

        // Le désarmement : fournie, elle part — en chaîne de requête pour celle
        // que `query` nomme, en corps pour l'autre.
        let played = execute(&echo(), &tool, json!({"status": "a b", "note": "x"}), None)
            .await
            .expect("2xx");
        assert_eq!(played["uri"], json!("/v1/employees?status=a%20b"));
        assert_eq!(played["body"], json!("{\"note\":\"x\"}"));
    }

    /// Un argument hors schéma est refusé **avant** l'appel : c'est une faute de
    /// frappe du modèle, ou un champ que la route lit et que l'outil n'annonce
    /// pas. Le filtrer en silence ferait passer la seconde pour la première.
    #[tokio::test]
    async fn an_argument_outside_the_schema_is_refused_before_the_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let router = Router::new().fallback(any(move || {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Json(json!({"ok": true}))
            }
        }));
        let tool = tool(
            "employees_list",
            Method::Get,
            "/v1/employees",
            json!({"properties": {"status": {"type": "string"}}}),
            &["status"],
            Risk::Read,
        );

        let err = execute(&router, &tool, json!({"tenant_id": "someone-else"}), None)
            .await
            .expect_err("hors schéma");
        assert_eq!(err.code, "bad_arguments");
        assert!(err.message.contains("tenant_id"), "{}", err.message);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "la route a été jouée");

        // Le désarmement : la propriété déclarée passe, et la route est jouée.
        execute(&router, &tool, json!({"status": "active"}), None)
            .await
            .expect("2xx");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Le refus du produit remonte avec son code et son détail, pas avec une
    /// phrase inventée ici.
    #[tokio::test]
    async fn a_refusal_carries_the_code_the_product_wrote() {
        let router = Router::new().fallback(any(|| async {
            ApiError::bad_request("le nom est vide").into_response()
        }));
        let tool = tool(
            "teams_create",
            Method::Post,
            "/v1/teams",
            json!({"properties": {"name": {"type": "string"}}}),
            &[],
            Risk::Write,
        );

        let err = execute(&router, &tool, json!({"name": ""}), None)
            .await
            .expect_err("400");
        assert_eq!(err.code, "bad_request");
        assert!(err.message.contains("le nom est vide"), "{}", err.message);
        // Le document entier, recopié : c'est ce que le client MCP affiche.
        let problem = err.problem.as_ref().expect("problem+json");
        assert_eq!(problem["status"], json!(400));
        assert_eq!(problem["type"], json!("/problems/bad_request"));
        assert!(err.text().contains("bad_request"), "{}", err.text());
    }

    /// Une route qui réussit sans rien dire rend `{"ok": true}` et non `null` —
    /// un modèle qui lit `null` conclut qu'il a échoué et recommence.
    #[tokio::test]
    async fn a_204_becomes_an_acknowledgement() {
        let router = Router::new().fallback(any(|| async { StatusCode::NO_CONTENT }));
        let tool = tool(
            "halt_clear",
            Method::Delete,
            "/v1/halt",
            json!({"properties": {}}),
            &[],
            Risk::Write,
        );
        assert_eq!(
            execute(&router, &tool, json!({}), None).await.expect("204"),
            json!({"ok": true})
        );
    }

    /// L'en-tête est recopié tel quel : ni re-signé, ni re-préfixé.
    #[tokio::test]
    async fn the_authorization_header_is_copied_verbatim() {
        let tool = tool(
            "employees_list",
            Method::Get,
            "/v1/employees",
            json!({"properties": {}}),
            &[],
            Risk::Read,
        );
        let played = execute(&echo(), &tool, json!({}), Some("Bearer secret-tel-quel"))
            .await
            .expect("2xx");
        assert_eq!(played["authorization"], json!("Bearer secret-tel-quel"));

        let played = execute(&echo(), &tool, json!({}), None).await.expect("2xx");
        assert_eq!(played["authorization"], Value::Null);
    }

    // -- la table -----------------------------------------------------------

    /// Le risque déclaré devient l'annotation que le client lit pour décider
    /// quoi faire confirmer. Deux lignes fabriquées, parce que le registre réel
    /// est vide ici et qu'un test qui passe sur zéro ligne n'affirme rien.
    #[test]
    fn tools_list_annotates_each_tool_from_its_risk() {
        let read = described(&tool(
            "employees_list",
            Method::Get,
            "/v1/employees",
            json!({"type": "object", "properties": {}}),
            &[],
            Risk::Read,
        ));
        let destructive = described(&tool(
            "employees_terminate",
            Method::Delete,
            "/v1/employees/{id}",
            json!({"type": "object", "properties": {"id": {"type": "string"}}}),
            &[],
            Risk::Destructive,
        ));

        assert_eq!(read["name"], json!("employees_list"));
        assert_eq!(read["title"], json!("un outil de test"));
        assert_eq!(read["inputSchema"]["type"], json!("object"));
        assert_eq!(read["annotations"]["readOnlyHint"], json!(true));
        assert_eq!(read["annotations"]["destructiveHint"], json!(false));

        assert_eq!(destructive["annotations"]["readOnlyHint"], json!(false));
        assert_eq!(destructive["annotations"]["destructiveHint"], json!(true));
        assert_eq!(
            destructive["inputSchema"]["properties"]["id"]["type"],
            json!("string")
        );
    }

    /// La deuxième garde anti-boucle, celle qui protège d'une ligne ajoutée par
    /// distraction. La première est structurelle : l'exécuteur reçoit l'étage
    /// `api`, où cette route n'est pas.
    #[test]
    fn no_tool_can_call_the_mcp_server_back() {
        // `starts_with` seul est **faux**, et la table pleine l'a montré le
        // 2026-09-11 : `/v1/mcp/servers` — la liste des serveurs qu'un
        // locataire a branchés, côté client — commence par `/v1/mcp/server`.
        // La garde accusait un outil parfaitement légitime. Ce qui est une
        // boucle, c'est cette route exactement, ou quelque chose dessous.
        let under = format!("{PATH}/");
        for line in registry() {
            assert!(
                line.path != PATH && !line.path.starts_with(&under),
                "{} rappelle le serveur MCP : {}",
                line.name,
                line.path
            );
        }
        // Et la preuve que la garde n'est pas devenue aveugle en se resserrant :
        // le voisin d'une lettre passe, la route elle-même ne passerait pas.
        assert!(registry().iter().any(|line| line.path == "/v1/mcp/servers"));
        // Le désarmement, parce que le registre est vide sur cette branche et
        // qu'une boucle `for` sur zéro ligne n'affirme rien.
        let loop_tool = tool(
            "mcp_server",
            Method::Post,
            "/v1/mcp/server",
            json!({"properties": {}}),
            &[],
            Risk::Write,
        );
        assert!(loop_tool.path.starts_with(PATH));
    }

    // -- le transport -------------------------------------------------------

    /// Le serveur MCP monté comme en production : hors de `with_api_stack`,
    /// devant un étage `api` qui, lui, est derrière.
    struct Harness {
        app: Router,
        api: Router,
        tenant: TenantId,
    }

    impl Harness {
        /// `None` sans base : le trousseau interroge `api_keys` dès qu'une clé
        /// n'est pas dans l'environnement, et un faux de cette table serait un
        /// faux du test.
        async fn new() -> Option<Self> {
            let Ok(url) = std::env::var("DATABASE_URL") else {
                eprintln!(
                    "SKIP: DATABASE_URL est absent ; le serveur MCP authentifie sur Postgres"
                );
                return None;
            };
            let db = Db::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");

            let tenant = TenantId::new_v7(chrono::Utc::now());
            let mut tx = db.admin_tx_bypassing_rls().await.expect("admin tx");
            sqlx::query("INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'mcp-server-test')")
                .bind(tenant.as_uuid())
                .bind(tenant.as_uuid().to_string())
                .execute(&mut *tx)
                .await
                .expect("insert tenant");
            tx.commit().await.expect("commit");

            let keys = ApiKeys::parse(&format!("ops:{}:{SECRET}", tenant.as_uuid())).expect("keys");
            let keyring = crate::auth::Keyring::new(keys, db.clone(), crate::auth::TEST_MASTER_KEY);
            // Une vraie route de ce dépôt, sous sa vraie pile : c'est elle que
            // `a_tool_plays_a_real_route_end_to_end` joue.
            let api = crate::with_api_stack(
                crate::routes::employees::router(crate::routes::domain::Hiring::for_tests(
                    db.clone(),
                )),
                db.clone(),
                keyring.clone(),
            );
            let state = McpServerState::new(keyring);
            state.attach(api.clone());

            Some(Self {
                app: router(state),
                api,
                tenant,
            })
        }

        /// Un appel JSON-RPC. `secret` absent : aucune clé présentée.
        async fn rpc(&self, body: Value, secret: Option<&str>) -> (StatusCode, Value) {
            let mut request =
                HttpRequest::post(PATH).header(header::CONTENT_TYPE, "application/json");
            if let Some(secret) = secret {
                request = request.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).expect("request"))
                .await
                .expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// Le voyant, lu comme la console le lit.
        async fn status(&self, secret: Option<&str>) -> (StatusCode, Value) {
            let mut request = HttpRequest::get(STATUS_PATH);
            if let Some(secret) = secret {
                request = request.header(header::AUTHORIZATION, format!("Bearer {secret}"));
            }
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::empty()).expect("request"))
                .await
                .expect("service");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
                .await
                .expect("body");
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }
    }

    /// Le voyant : il compte la table, il ne prétend pas avoir vu une session
    /// avant d'en voir une, et il en nomme une après.
    #[tokio::test]
    async fn the_status_counts_the_tools_and_only_sees_a_session_after_one() {
        let Some(harness) = Harness::new().await else {
            return;
        };

        // Sans clé, comme toute lecture de locataire.
        let (status, _) = harness.status(None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, before) = harness.status(Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK, "{before}");
        assert_eq!(before["tools"], json!(registry().len()));
        assert!(
            before["tools"].as_u64().unwrap_or_default() > 0,
            "un registre vide ferait passer ce test sans rien compter"
        );
        assert_eq!(before["last_session_at"], Value::Null);
        assert_eq!(before["last_client"], Value::Null);

        let (status, _) = harness
            .rpc(
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"clientInfo": {"name": "claude-code", "version": "2.1.0"}}}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, after) = harness.status(Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK, "{after}");
        assert_eq!(after["last_client"], json!("claude-code 2.1.0"));
        let seen: chrono::DateTime<Utc> = after["last_session_at"]
            .as_str()
            .expect("un instant")
            .parse()
            .expect("une date");
        assert!(
            (Utc::now() - seen).num_seconds().abs() < 60,
            "l'instant noté n'est pas celui de la poignée de main : {seen}"
        );
    }

    /// La poignée de main : la version, l'identité, et le texte qu'un modèle lit
    /// avant tout le reste. Sans clé, parce qu'un client sonde avant de
    /// s'authentifier et qu'un 401 ici est un serveur qui ne s'affiche jamais.
    #[tokio::test]
    async fn an_initialize_answers_the_protocol_and_the_instructions() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let (status, answer) = harness
            .rpc(
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK, "initialize sans clé doit passer");
        let result = &answer["result"];
        assert_eq!(result["protocolVersion"], json!(PROTOCOL));
        assert_eq!(result["serverInfo"]["name"], json!("siglair"));
        assert_eq!(
            result["serverInfo"]["version"],
            json!(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(result["capabilities"]["tools"]["listChanged"], json!(false));
        let instructions = result["instructions"].as_str().expect("instructions");
        assert!(
            instructions.contains("tools/list"),
            "les instructions doivent dire par où commencer : {instructions}"
        );
        assert!(
            instructions.contains("société"),
            "en français, et sur ce que cette société est : {instructions}"
        );
    }

    /// La table, annotée, et seulement pour qui a une clé.
    #[tokio::test]
    async fn tools_list_needs_a_key_and_then_renders_the_table() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});

        let (status, answer) = harness.rpc(list.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
        assert_eq!(answer["code"], json!("unauthenticated"));

        let (status, answer) = harness.rpc(list, Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        // Vide sur cette branche — trois chantiers remplissent les trois modules
        // en parallèle — mais un tableau, jamais `null` : un client qui lit
        // `null` ici abandonne le serveur.
        assert!(answer["result"]["tools"].is_array(), "{answer}");
    }

    /// Une clé absente échoue **avant** qu'un outil soit atteint, et échoue
    /// comme partout ailleurs : le même document, le même `WWW-Authenticate`.
    #[tokio::test]
    async fn tools_call_without_a_key_is_refused_before_any_tool() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let call = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "employees_list", "arguments": {}}});

        let (status, answer) = harness.rpc(call.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer["code"], json!("unauthenticated"));
        // Un nom d'outil inexistant sous une clé valide dirait `-32602`. Sans
        // clé, on n'apprend même pas ça : le refus précède la table.
        assert_eq!(answer["error"], Value::Null, "{answer}");

        // Le désarmement : la même requête avec la clé atteint bien la table.
        //
        // Elle demandait `employees_list` et attendait `-32602`, ce qui ne
        // tenait que tant que la table était vide — l'outil existe depuis le
        // 2026-09-11 et l'appel réussit. Un désarmement qui repose sur
        // l'absence d'une ligne est un désarmement qui expire ; celui-ci
        // nomme un outil qui n'existera jamais.
        let absent = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "aucun_outil_ne_porte_ce_nom", "arguments": {}}});
        let (status, answer) = harness.rpc(absent, Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["error"]["code"], json!(-32602), "{answer}");

        // Et le vrai outil, sous la même clé, répond : c'est ce qui prouve que
        // le refus d'au-dessus venait de la clé absente et de rien d'autre.
        let (status, answer) = harness.rpc(call, Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["error"], Value::Null, "{answer}");
    }

    /// Toute autre méthode que les trois : `-32601`, et pas un 404 HTTP.
    #[tokio::test]
    async fn an_unknown_method_is_a_method_not_found() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let (status, answer) = harness
            .rpc(
                json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
                Some(SECRET),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "l'appel HTTP a réussi");
        assert_eq!(answer["error"]["code"], json!(-32601));
        assert_eq!(answer["result"], Value::Null);

        // Le désarmement : une des trois, sur la même enveloppe, aboutit.
        let (_, answer) = harness
            .rpc(
                json!({"jsonrpc": "2.0", "id": 4, "method": "initialize"}),
                Some(SECRET),
            )
            .await;
        assert_eq!(answer["error"], Value::Null, "{answer}");
    }

    /// Une notification n'a pas d'`id`, donc pas de réponse. Claude Code en
    /// envoie une juste après `initialize` ; y répondre par une erreur JSON-RPC
    /// est ce qui fait qu'une session ne s'ouvre jamais.
    #[tokio::test]
    async fn a_notification_gets_an_acknowledgement_and_no_body() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let (status, answer) = harness
            .rpc(
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(answer, Value::Null, "une notification ne reçoit rien");
    }

    /// De bout en bout, sur une vraie route de ce dépôt : `GET /v1/employees`,
    /// derrière `with_api_stack`, avec la clé recopiée depuis l'appel MCP.
    ///
    /// Par `execute` et non par `tools/call`, parce que le registre est vide sur
    /// cette branche : le chemin qui reste à prouver est celui de l'exécuteur,
    /// et `tools_call_without_a_key_is_refused_before_any_tool` a déjà montré
    /// que `tools/call` y descend.
    #[tokio::test]
    async fn a_tool_plays_a_real_route_end_to_end() {
        let Some(harness) = Harness::new().await else {
            return;
        };
        let line = tool(
            "employees_list",
            Method::Get,
            "/v1/employees",
            json!({"type": "object", "properties": {}}),
            &[],
            Risk::Read,
        );

        let answer = execute(
            &harness.api,
            &line,
            json!({}),
            Some(&format!("Bearer {SECRET}")),
        )
        .await
        .expect("la route répond 200");
        assert!(
            answer["employees"].is_array(),
            "la vraie route de ce dépôt : {answer}"
        );
        assert!(!harness.tenant.as_uuid().is_nil());

        // Le désarmement : sans la clé, la **même** ligne prend le 401 de la
        // pile — l'exécuteur n'a pas de porte à lui.
        let err = execute(&harness.api, &line, json!({}), None)
            .await
            .expect_err("401");
        assert_eq!(err.code, "unauthenticated");
    }
}
