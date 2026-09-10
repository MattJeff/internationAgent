//! La prise pour un solveur de captcha : le port, le refus par défaut, et
//! **un seul** adaptateur réel, derrière une clé que le client apporte.
//!
//! `docs/BROWSER.md` § v3 : ce qui est du **logiciel** se construit, ce qui est
//! une **ressource** se paie. Résoudre un captcha, c'est faire regarder une
//! image par quelqu'un — une ressource, la plus explicitement humaine de
//! toutes. Ce module ne résout rien : il détecte (côté `browser_chrome.rs`),
//! il refuse ([`NoSolver`], le défaut), et il sait parler à un service **si le
//! client en paie un**. Aucun compte n'est ouvert d'ici, et sans
//! `CAPTCHA_API_KEY` un déploiement se comporte exactement comme la v2.
//!
//! # Trois défis et pas trente
//!
//! [`ChallengeKind`] tient les trois qui se lisent dans le DOM en une ligne de
//! JavaScript et dont la clé de site est publique par construction — c'est
//! l'attribut `data-sitekey` que la page donne au widget. Les autres familles
//! (Arkose, DataDome, GeeTest…) n'ont pas de clé lisible de cette façon, ou
//! demandent de rejouer un flux propriétaire ; les détecter à moitié serait
//! promettre une résolution qui échouerait au moment de l'injection. Elles
//! restent [`crate::browser_chrome::BLOCKED_BY_SITE`], l'issue honnête.
//!
//! # Le jeton se pose dans un champ, et c'est tout ce que ce port promet
//!
//! Un solveur rend une chaîne. Ce que la page en fait — un `<textarea>` caché
//! nommé `g-recaptcha-response`, un `input[name=cf-turnstile-response]`, un
//! rappel JavaScript — est la connaissance de `browser_chrome.rs`, qui a la
//! page. Le port ne connaît ni DOM ni navigateur : il prend une clé de site et
//! une adresse, il rend un jeton. Un deuxième fournisseur s'écrit à côté sans
//! toucher au navigateur, ce qui est la seule raison d'avoir un trait pour une
//! implémentation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Value, json};
use url::Url;

use crate::{ProviderError, Secret};

/// Aucun solveur n'est branché, ou celui qui l'est a refusé.
///
/// Distinct de [`crate::browser_chrome::BLOCKED_BY_SITE`] exprès : un mur sans
/// défi lisible ne se franchit avec rien, alors qu'un défi nommé se franchit
/// avec une clé que le client peut apporter demain. Un opérateur qui lit
/// `captcha` dans le journal sait quoi acheter ; `blocked_by_site` ne le dit
/// pas.
pub const CAPTCHA: &str = "captcha";

/// Le service a répondu, et il n'a pas de jeton : le défi n'a pas été résolu,
/// la clé est refusée, le solde est vide. Terminal — un deuxième essai coûte
/// une deuxième résolution pour la même page.
pub const CAPTCHA_UNSOLVED: &str = "captcha_unsolved";

/// La famille du défi, telle que la page la porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// `<div class="g-recaptcha" data-sitekey="…">`.
    Recaptcha2,
    /// `<div class="cf-turnstile" data-sitekey="…">`.
    Turnstile,
    /// `<div class="h-captcha" data-sitekey="…">`.
    HCaptcha,
}

impl ChallengeKind {
    /// Le nom que la détection écrit dans la page et que le journal lit.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::Recaptcha2 => "recaptcha2",
            ChallengeKind::Turnstile => "turnstile",
            ChallengeKind::HCaptcha => "hcaptcha",
        }
    }

    /// Ce que la détection a lu, relu ici — la traversée `&str` est le contrat
    /// avec `Runtime.evaluate`, qui ne sait rendre que du JSON.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "recaptcha2" => Some(ChallengeKind::Recaptcha2),
            "turnstile" => Some(ChallengeKind::Turnstile),
            "hcaptcha" => Some(ChallengeKind::HCaptcha),
            _ => None,
        }
    }

    /// Le champ où la page attend le jeton. Le nom est celui du widget, pas le
    /// nôtre : c'est ce que le script du site lit au `submit`.
    pub const fn response_field(self) -> &'static str {
        match self {
            ChallengeKind::Recaptcha2 => "g-recaptcha-response",
            ChallengeKind::Turnstile => "cf-turnstile-response",
            ChallengeKind::HCaptcha => "h-captcha-response",
        }
    }
}

/// Un défi lu sur une page : ce qu'un solveur a besoin de savoir, et rien de
/// plus.
///
/// `page_url` et non le document : le service refait la navigation lui-même,
/// depuis sa propre adresse, et n'a que faire de ce que Chromium a rendu. Rien
/// de la page ne traverse ce port — pas de HTML, pas de cookie, pas de texte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub kind: ChallengeKind,
    /// L'attribut `data-sitekey` : public par construction, c'est le widget qui
    /// l'affiche.
    pub site_key: String,
    /// L'adresse de la page qui porte le widget.
    pub page_url: Url,
}

/// Qui sait franchir un défi. Une implémentation réelle
/// ([`TwoCaptcha`]) et un refus ([`NoSolver`], le défaut).
#[async_trait]
pub trait CaptchaSolver: Send + Sync {
    /// Le jeton à poser dans [`ChallengeKind::response_field`].
    async fn solve(&self, challenge: &Challenge) -> Result<String, ProviderError>;

    /// Y a-t-il quelque chose derrière ce port ? Lu par `/readyz`, pour qu'un
    /// opérateur dont un employé rapporte `captcha` sache si c'est « personne
    /// n'a branché de clé » ou « le service a échoué ».
    fn configured(&self) -> bool {
        true
    }
}

/// Le défaut : refuse toujours, et le dit avec le code que le journal lit.
///
/// Ce n'est pas un faux — un faux rendrait un jeton, et un jeton inventé fait
/// échouer la page une seconde plus tard, à un endroit où plus personne ne
/// comprend pourquoi. C'est un refus, et c'est l'état de tout déploiement qui
/// n'a pas de `CAPTCHA_API_KEY`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSolver;

#[async_trait]
impl CaptchaSolver for NoSolver {
    async fn solve(&self, _challenge: &Challenge) -> Result<String, ProviderError> {
        Err(ProviderError::Terminal { code: CAPTCHA })
    }

    fn configured(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// 2Captcha
// ---------------------------------------------------------------------------

/// L'origine de l'API v2 de 2Captcha.
pub const TWOCAPTCHA_API: &str = "https://api.2captcha.com";

/// Le nom du fournisseur dans `CAPTCHA_API_KEY=<fournisseur>:<clé>`.
pub const TWOCAPTCHA: &str = "2captcha";

/// Ceiling on one solve, polling included. Un captcha se résout en 10 à 30
/// secondes chez eux ; au-delà d'une minute et demie, le tour a plus à gagner
/// à rendre `captcha_unsolved` qu'à tenir un onglet ouvert.
const SOLVE_DEADLINE: Duration = Duration::from_secs(90);
/// Entre deux `getTaskResult`. Leur documentation demande d'attendre avant le
/// premier sondage ; cinq secondes est ce qu'ils recommandent pour reCAPTCHA.
const POLL_EVERY: Duration = Duration::from_secs(5);

/// Le client HTTP de l'API v2 de 2Captcha.
///
/// # La source, et la date
///
/// Relevé le **2026-09-10** sur leur documentation :
///
/// * `https://2captcha.com/api-docs/create-task` — `POST https://api.2captcha.com/createTask`,
///   corps `{"clientKey": …, "task": {…}}`, réponse `{"errorId": 0, "taskId": 72345678901}`.
/// * `https://2captcha.com/api-docs/get-task-result` — `POST https://api.2captcha.com/getTaskResult`,
///   corps `{"clientKey": …, "taskId": …}`, réponse `{"errorId":0,"status":"processing"}`
///   puis `{"errorId":0,"status":"ready","solution":{…}}`, et en échec
///   `{"errorId":12,"errorCode":"ERROR_CAPTCHA_UNSOLVABLE",…}`.
/// * `https://2captcha.com/api-docs/recaptcha-v2` — type `RecaptchaV2TaskProxyless`,
///   `{websiteURL, websiteKey}`, solution dans `solution.gRecaptchaResponse`
///   (et `solution.token`, la même valeur).
/// * `https://2captcha.com/api-docs/cloudflare-turnstile` — type
///   `TurnstileTaskProxyless`, solution dans `solution.token`.
///
/// **Ce que la mesure a corrigé.** Leur index de types
/// (`https://2captcha.com/api-docs`, même jour) ne liste **plus de page
/// hCaptcha** et `/api-docs/hcaptcha` répond 404 — donc le type
/// `HCaptchaTaskProxyless` n'est plus documenté. Il est toujours *accepté* :
/// `POST /createTask` avec une clé volontairement invalide répond
/// `ERROR_KEY_DOES_NOT_EXIST` (errorId 1) pour les trois types ci-dessus et
/// `ERROR_TASK_ABSENT` (errorId 22) pour un type inventé — l'API valide le
/// type **avant** la clé, ce qui fait de cet appel une vérification de nom
/// gratuite et sans compte. Mesuré le 2026-09-10 ; c'est la seule chose ici
/// qui ne vienne pas d'une page de documentation, et elle est nommée comme
/// telle.
///
/// La solution est lue dans `solution.token` **puis** `solution.gRecaptchaResponse` :
/// reCAPTCHA rend les deux, Turnstile n'en rend qu'un, et lire le champ commun
/// d'abord évite un `match` sur le type au moment où le jeton arrive.
pub struct TwoCaptcha {
    api_key: Secret,
    /// [`TWOCAPTCHA_API`], ou un faux serveur dans les tests.
    base: String,
    http: reqwest::Client,
    poll_every: Duration,
    deadline: Duration,
}

impl std::fmt::Debug for TwoCaptcha {
    /// À la main : le champ voisin est une clé d'API.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoCaptcha")
            .field("base", &self.base)
            .finish()
    }
}

impl TwoCaptcha {
    /// Un client sur l'API publique.
    pub fn new(api_key: Secret) -> Self {
        Self {
            api_key,
            base: TWOCAPTCHA_API.to_owned(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            poll_every: POLL_EVERY,
            deadline: SOLVE_DEADLINE,
        }
    }

    /// Parler à un faux serveur, et l'interroger plus vite. Les tests seuls.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>, poll_every: Duration) -> Self {
        self.base = base.into();
        self.poll_every = poll_every;
        self
    }

    /// Le type de tâche de leur API v2. Voir la source citée sur le type.
    const fn task_type(kind: ChallengeKind) -> &'static str {
        match kind {
            ChallengeKind::Recaptcha2 => "RecaptchaV2TaskProxyless",
            ChallengeKind::Turnstile => "TurnstileTaskProxyless",
            ChallengeKind::HCaptcha => "HCaptchaTaskProxyless",
        }
    }

    /// Un `POST` JSON, rendu en `Value`. La clé voyage dans le corps et dans
    /// rien qu'on formate : `body` est construit par l'appelant et n'est jamais
    /// tracé.
    async fn post(&self, path: &str, body: Value) -> Result<Value, ProviderError> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .map_err(|_| ProviderError::timeout())?;
        if response.status().is_server_error() {
            return Err(ProviderError::Retryable {
                after: Duration::from_secs(10),
            });
        }
        response
            .json::<Value>()
            .await
            .map_err(|_| ProviderError::timeout())
    }
}

#[async_trait]
impl CaptchaSolver for TwoCaptcha {
    async fn solve(&self, challenge: &Challenge) -> Result<String, ProviderError> {
        let created = self
            .post(
                "/createTask",
                json!({
                    "clientKey": self.api_key.expose_for_transport(),
                    "task": {
                        "type": Self::task_type(challenge.kind),
                        "websiteURL": challenge.page_url.as_str(),
                        "websiteKey": challenge.site_key,
                    },
                }),
            )
            .await?;
        // `errorId` non nul est un refus du service — clé fausse, solde vide,
        // type refusé. Le `errorCode` est leur mot et ne devient pas notre
        // code : `ProviderError::Terminal::code` est une étiquette de métrique.
        if created["errorId"].as_i64().unwrap_or(1) != 0 {
            tracing::warn!(
                code = created["errorCode"].as_str().unwrap_or("unknown"),
                kind = challenge.kind.as_str(),
                "the captcha service refused the task"
            );
            return Err(ProviderError::Terminal {
                code: CAPTCHA_UNSOLVED,
            });
        }
        let task_id = created["taskId"].clone();
        if task_id.is_null() {
            return Err(ProviderError::Terminal {
                code: CAPTCHA_UNSOLVED,
            });
        }

        let started = Instant::now();
        // La première attente est avant le premier sondage, pas après : leur
        // documentation le demande, et une tâche n'est jamais prête à la
        // seconde zéro.
        while started.elapsed() < self.deadline {
            tokio::time::sleep(self.poll_every).await;
            let result = self
                .post(
                    "/getTaskResult",
                    json!({
                        "clientKey": self.api_key.expose_for_transport(),
                        "taskId": task_id,
                    }),
                )
                .await?;
            if result["errorId"].as_i64().unwrap_or(0) != 0 {
                tracing::warn!(
                    code = result["errorCode"].as_str().unwrap_or("unknown"),
                    kind = challenge.kind.as_str(),
                    "the captcha service gave up on the task"
                );
                return Err(ProviderError::Terminal {
                    code: CAPTCHA_UNSOLVED,
                });
            }
            if result["status"] != "ready" {
                continue;
            }
            let solution = &result["solution"];
            if let Some(token) = solution["token"]
                .as_str()
                .or_else(|| solution["gRecaptchaResponse"].as_str())
                .filter(|token| !token.is_empty())
            {
                return Ok(token.to_owned());
            }
            // « prêt » sans jeton est un contrat rompu, pas une attente.
            return Err(ProviderError::Terminal {
                code: CAPTCHA_UNSOLVED,
            });
        }
        // La tâche est peut-être encore en cours chez eux — et c'est
        // précisément pourquoi ce n'est pas `Retryable` : le `taskId` meurt
        // avec cette fonction, donc un deuxième essai est une deuxième
        // résolution facturée pour la même page, jamais la reprise de
        // celle-ci. Terminal, l'onglet est rendu, et l'employé rapporte
        // honnêtement qu'il n'est pas passé.
        Err(ProviderError::Terminal {
            code: CAPTCHA_UNSOLVED,
        })
    }
}

/// `CAPTCHA_API_KEY=<fournisseur>:<clé>` → le solveur qu'il nomme.
///
/// Un seul fournisseur reconnu, et un nom inconnu est une **erreur** et non un
/// [`NoSolver`] silencieux : un opérateur qui écrit `2capcha:` a payé un
/// service et croit l'avoir branché. La forme de `split_pair` dans
/// `apps/server/src/config.rs`, dite ici parce que c'est ici que vit la liste.
pub fn solver_from(provider: &str, api_key: Secret) -> Result<Box<dyn CaptchaSolver>, String> {
    match provider {
        TWOCAPTCHA => Ok(Box::new(TwoCaptcha::new(api_key))),
        other => Err(format!(
            "{other:?} is not a captcha provider this build knows ({TWOCAPTCHA} is the only one)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::routing::post;

    use super::*;

    /// Le faux service : deux routes, et ce qu'il a reçu.
    #[derive(Default)]
    struct Seen {
        created: Vec<Value>,
        polls: usize,
        /// Combien de `getTaskResult` répondent `processing` avant `ready`.
        wait: usize,
        /// Ce que `createTask` répond quand ce n'est pas un succès.
        refuse_create: Option<Value>,
        /// Ce que `getTaskResult` répond au lieu de `ready`.
        refuse_result: Option<Value>,
        /// La forme de la solution : `token`, `gRecaptchaResponse`, ou rien.
        solution: Value,
    }

    async fn fake_2captcha(state: Arc<Mutex<Seen>>) -> SocketAddr {
        async fn create(
            axum::extract::State(state): axum::extract::State<Arc<Mutex<Seen>>>,
            axum::Json(body): axum::Json<Value>,
        ) -> axum::Json<Value> {
            let mut seen = state.lock().unwrap_or_else(|e| e.into_inner());
            seen.created.push(body);
            axum::Json(
                seen.refuse_create
                    .clone()
                    .unwrap_or_else(|| json!({ "errorId": 0, "taskId": 4242 })),
            )
        }
        async fn result(
            axum::extract::State(state): axum::extract::State<Arc<Mutex<Seen>>>,
            axum::Json(_body): axum::Json<Value>,
        ) -> axum::Json<Value> {
            let mut seen = state.lock().unwrap_or_else(|e| e.into_inner());
            seen.polls += 1;
            if let Some(refusal) = seen.refuse_result.clone() {
                return axum::Json(refusal);
            }
            if seen.polls <= seen.wait {
                return axum::Json(json!({ "errorId": 0, "status": "processing" }));
            }
            let solution = seen.solution.clone();
            axum::Json(json!({ "errorId": 0, "status": "ready", "solution": solution }))
        }
        let app = Router::new()
            .route("/createTask", post(create))
            .route("/getTaskResult", post(result))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        addr
    }

    fn challenge(kind: ChallengeKind) -> Challenge {
        Challenge {
            kind,
            site_key: "6LfD3PIbAAAAAJs".to_owned(),
            page_url: Url::parse("https://portal.example.com/login").expect("url"),
        }
    }

    fn client(addr: SocketAddr) -> TwoCaptcha {
        TwoCaptcha::new(Secret::new("client-key-7f3a"))
            .with_base(format!("http://{addr}"), Duration::from_millis(10))
    }

    /// Le défaut refuse, et il le dit avec le code que le journal lit — pas
    /// avec un jeton inventé.
    #[tokio::test]
    async fn the_default_solver_refuses_and_says_it_is_not_configured() {
        let no = NoSolver;
        assert!(!no.configured());
        let err = no
            .solve(&challenge(ChallengeKind::Recaptcha2))
            .await
            .expect_err("nothing is plugged in");
        assert_eq!(err.code(), CAPTCHA);
        assert!(!err.is_retryable(), "a second try has no solver either");
    }

    /// L'aller-retour complet : la tâche part dans la forme de leur
    /// documentation, l'attente est sondée, et le jeton revient.
    #[tokio::test]
    async fn a_task_is_created_polled_and_answered_in_the_documented_shape() {
        let seen = Arc::new(Mutex::new(Seen {
            wait: 2,
            solution: json!({ "gRecaptchaResponse": "03ADUVZw", "token": "03ADUVZw" }),
            ..Seen::default()
        }));
        let addr = fake_2captcha(Arc::clone(&seen)).await;
        let token = client(addr)
            .solve(&challenge(ChallengeKind::Recaptcha2))
            .await
            .expect("solved");
        assert_eq!(token, "03ADUVZw");

        let created = seen.lock().unwrap().created[0].clone();
        assert_eq!(created["clientKey"], "client-key-7f3a");
        assert_eq!(created["task"]["type"], "RecaptchaV2TaskProxyless");
        assert_eq!(created["task"]["websiteKey"], "6LfD3PIbAAAAAJs");
        assert_eq!(
            created["task"]["websiteURL"],
            "https://portal.example.com/login"
        );
        assert_eq!(
            seen.lock().unwrap().polls,
            3,
            "processing twice, then ready"
        );
    }

    /// Turnstile ne rend que `solution.token`, et hCaptcha porte le type que
    /// leur documentation ne liste plus (voir l'en-tête de [`TwoCaptcha`]).
    #[tokio::test]
    async fn each_family_sends_its_own_task_type_and_reads_the_common_field() {
        for (kind, expected) in [
            (ChallengeKind::Turnstile, "TurnstileTaskProxyless"),
            (ChallengeKind::HCaptcha, "HCaptchaTaskProxyless"),
        ] {
            let seen = Arc::new(Mutex::new(Seen {
                solution: json!({ "token": "0.abc" }),
                ..Seen::default()
            }));
            let addr = fake_2captcha(Arc::clone(&seen)).await;
            assert_eq!(
                client(addr).solve(&challenge(kind)).await.expect("solved"),
                "0.abc"
            );
            assert_eq!(seen.lock().unwrap().created[0]["task"]["type"], expected);
        }
    }

    /// Les trois refus du service — à la création, à la lecture, et un
    /// « prêt » sans jeton — sont un seul code terminal, et jamais un jeton.
    #[tokio::test]
    async fn every_refusal_is_terminal_and_carries_no_provider_text() {
        for state in [
            Seen {
                refuse_create: Some(
                    json!({ "errorId": 1, "errorCode": "ERROR_KEY_DOES_NOT_EXIST" }),
                ),
                ..Seen::default()
            },
            Seen {
                refuse_result: Some(
                    json!({ "errorId": 12, "errorCode": "ERROR_CAPTCHA_UNSOLVABLE" }),
                ),
                ..Seen::default()
            },
            Seen {
                solution: json!({}),
                ..Seen::default()
            },
        ] {
            let addr = fake_2captcha(Arc::new(Mutex::new(state))).await;
            let err = client(addr)
                .solve(&challenge(ChallengeKind::Recaptcha2))
                .await
                .expect_err("refused");
            assert_eq!(err.code(), CAPTCHA_UNSOLVED);
            assert!(!err.is_retryable());
        }

        // Désarmée : le même faux serveur, sans refus, rend bien un jeton — donc
        // les trois échecs ci-dessus sont les refus et pas le harnais.
        let addr = fake_2captcha(Arc::new(Mutex::new(Seen {
            solution: json!({ "token": "ok" }),
            ..Seen::default()
        })))
        .await;
        assert_eq!(
            client(addr)
                .solve(&challenge(ChallengeKind::Recaptcha2))
                .await
                .expect("solved"),
            "ok"
        );
    }

    /// Un fournisseur qu'on ne connaît pas est une erreur de démarrage, pas un
    /// `NoSolver` silencieux : l'opérateur a payé quelque chose.
    #[test]
    fn an_unknown_provider_refuses_to_boot_rather_than_solving_nothing() {
        assert!(solver_from(TWOCAPTCHA, Secret::new("k")).is_ok());
        // `err()` et non `expect_err` : le succès porte un `Box<dyn …>` sans
        // `Debug`, et lui en donner un serait un `Debug` qui atteint une clé.
        let err = solver_from("2capcha", Secret::new("k"))
            .err()
            .expect("a typo is a refusal");
        assert!(err.contains("2capcha"), "{err}");
    }

    /// Les trois familles se traversent en `&str` sans se perdre : c'est le
    /// contrat avec `Runtime.evaluate`, qui ne rend que du JSON.
    #[test]
    fn a_kind_survives_the_round_trip_through_the_page() {
        for kind in [
            ChallengeKind::Recaptcha2,
            ChallengeKind::Turnstile,
            ChallengeKind::HCaptcha,
        ] {
            assert_eq!(ChallengeKind::parse(kind.as_str()), Some(kind));
            assert!(kind.response_field().ends_with("-response"));
        }
        assert_eq!(ChallengeKind::parse("datadome"), None);
    }
}
