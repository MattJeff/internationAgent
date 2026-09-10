# Notre Browserbase — le navigateur qu'on fait tourner soi-même

Décidé le 2026-09-10, avant d'écrire une ligne. Ce document est le contrat des
deux chantiers qui le suivent (adaptateur Rust, infrastructure siglair) et la
réponse à « pourquoi pas simplement payer Browserbase ».

## Ce que Browserbase vend, réduit à ce que notre code en consomme

`crates/providers/src/browser_browserbase.rs` n'utilise que deux choses :

1. **`POST /v1/contexts`** — un profil durable par employé (cookies,
   localStorage, sessions ouvertes), ré-hydraté dans le prochain navigateur.
2. **`POST /v1/sessions`** → un `connectUrl` **CDP** (Chrome DevTools
   Protocol, JSON-RPC sur websocket), sur lequel `crates/providers/src/cdp.rs`
   joue lui-même chaque `BrowserStep` (`Page.navigate`, `DOM.*`, `Input.*`,
   `Page.captureScreenshot`).

Tout le reste du produit Browserbase — enregistrements, proxys résidentiels,
résolution de captchas, furtivité — n'est lu nulle part chez nous. Donc
« notre Browserbase », c'est **un Chromium sans tête qui parle CDP, plus la
persistance par employé**. Le pilote CDP existe déjà et ne bouge pas.

## Les trois mesures qui fixent la forme

| Mesure (2026-09-10) | Conséquence |
|---|---|
| VPS : 3 819 Mo de RAM, 2 vCPU ; `db` plafonné à 1 Go, `api` et `web` à 512 Mo, ~2,9 Go disponibles | Un seul processus Chromium, plafonné à **1 Go**, **3 onglets** simultanés au plus (≈ 400 Mo de base + 100–150 Mo par onglet). Au-delà, on attend, on ne lance pas. |
| Un seul réseau compose (`siglair_default`), aucun port publié pour l'API en dehors de Caddy | Le port CDP **n'est jamais publié** : il n'a pas d'authentification. Le navigateur est joignable par nom (`browser:9222`) depuis `api` seulement. |
| Notre propre doc, `browser_browserbase.rs` : « persistance liée à `--user-data-dir`, donc un processus par employé ; `Target.createBrowserContext` isole sans persister » | On ne prend ni l'un ni l'autre : **un contexte CDP par tâche** (isolation, multiplexage) **et le pot de cookies exporté à la fin, scellé, ré-injecté au début** (`Network.getAllCookies` / `Network.setCookies`). C'est exactement ce que Browserbase fait côté serveur, sans qu'on le voie. |

## L'architecture, en une page

```
api (Rust) ── ws://browser:9222/devtools/browser/<id> ──► Chromium headless-shell
   │             Target.createBrowserContext                    (conteneur `browser`,
   │             Target.createTarget {browserContextId}          mem_limit 1g,
   │             Network.setCookies (pot scellé de l'employé)    aucun port publié)
   │
   └── ws://browser:9222/devtools/page/<targetId> ──► cdp.rs joue les BrowserStep
                                                      (inchangé)
   à la fin : Network.getAllCookies → scellé → employee_resources(browser).state
              Target.closeTarget, Target.disposeBrowserContext
```

**Adaptateur** : `crates/providers/src/browser_chrome.rs`, `ChromeBrowser`,
implémente `BrowserProvider` comme les trois autres.

- `ensure_context(ctx)` → `Provisioned { provider: "chrome", external_id: "ctx-<tag>" }`.
  Rien n'est créé chez Chromium à ce moment : un contexte CDP ne survit pas au
  processus, donc l'identifiant est **le nôtre**, stable, et le contexte est
  recréé à chaque tâche. Le pot de cookies scellé est la seule chose durable.
- `act(session, step)` : prend un **jeton du sémaphore** (`BROWSER_MAX_TABS`,
  défaut 3, attente bornée `BROWSER_QUEUE_WAIT`, défaut 60 s → `Retryable`),
  ouvre le websocket navigateur (`GET http://browser:9222/json/version` →
  `webSocketDebuggerUrl`), crée contexte + cible, injecte les cookies scellés
  s'il y en a, hand l'URL de page `ws://browser:9222/devtools/page/<targetId>`
  au `CdpWebsocket` existant **verbatim**, puis exporte les cookies, ferme la
  cible et jette le contexte. Un onglet ne survit jamais à une étape hors du
  tour ; les étapes d'un même tour partagent l'onglet tant que le tour dure
  (même règle que `BrowserSession` aujourd'hui — lire `effects.rs::drive`).
- **Toute navigation passe par `resolve_and_vet(Reach::Public)`** avant
  `Page.navigate`, comme `HttpBrowser` ; et Chromium est lancé avec
  `--host-resolver-rules` qui envoie `db`, `api`, `web`, `caddy` et
  `localhost` sur `~NOTFOUND` : un script de page ne peut pas frapper la base
  par le navigateur. Le port CDP n'étant pas publié, personne d'autre ne le
  peut non plus.
- **Un site qui bloque** (page d'attente Cloudflare, « Just a moment… »,
  « Access denied », 403 après navigation) → `Terminal { code: "blocked_by_site" }`.
  On n'a ni proxy résidentiel ni furtivité : c'est le plafond de la v1, écrit
  ici et dans `PROVIDERS.md`, et Browserbase reste sélectionnable par clé le
  jour où un client en a besoin.
- **Sélection** (`mocks.rs::browser_provider`, dans cet ordre) : clé Browserbase →
  Browserbase ; `BROWSER_CDP_URL=http://browser:9222` → `ChromeBrowser` ;
  `BROWSER_FETCH=http` → `HttpBrowser` ; sinon le faux. `readyz.browser_js` vaut
  vrai pour les deux premiers.

**Infrastructure** (`~/siglair/compose.yml`) : service `browser`, image
`chromedp/headless-shell:stable` épinglée par digest, `mem_limit: 1g`,
`shm_size: 256m` (Chromium sans `/dev/shm` suffisant plante en silence),
`healthcheck` sur `/json/version`, **aucun `ports:`**, `depends_on` depuis `api`
(condition `service_healthy`), journaux plafonnés comme les autres. Rien ne
change dans `Caddyfile` ni `deploy.sh` (il fait déjà `pull` de toutes les images).

## Ce qu'on ne fait pas, et pourquoi

- **Pas de furtivité, pas de proxy, pas de captcha.** Ce sont des ressources à
  guichet (des IP résidentielles, un service de résolution), pas du logiciel.
  Règle du dépôt : rien à payer avant d'en avoir besoin.
- **Pas de Playwright, pas de Node.** Le pilote CDP en Rust existe et est testé.
- **Pas d'enregistrement vidéo.** Les captures d'écran par étape existent déjà.
- **Pas de processus par employé.** Le pot de cookies scellé donne la
  persistance sans le coût.

## Ce qui prouve que ça marche

1. `browser::contract_suite` contre un Chromium réel (`docker run chromedp/headless-shell`),
   test qui **saute** sans `BROWSER_CDP_URL` — comme les tests de base sans
   `DATABASE_URL` — et que la CI de siglair lance avec le conteneur en service.
2. Un faux CDP (websocket tokio) pour ce qui ne demande pas Chromium : le
   sémaphore mord, le pot de cookies fait l'aller-retour scellé, `blocked_by_site`
   est reconnu, `--host-resolver-rules` est bien dans la commande du conteneur
   (lu depuis `compose.yml` par un test de siglair).
3. En production : `readyz.browser_js == true`, `mock_adapters` sans `browser`,
   et un `read_page` d'employé sur une page rendue en JavaScript.

## Les trois phases — décidé le 2026-09-10, à la demande du fondateur : « tout ce que fait Browserbase »

Le tri qui compte : ce qui est **du logiciel** se construit ; ce qui est **une
ressource** (des adresses IP, un service de résolution, des machines) se paie,
et on ne construit que la prise.

### v1 — le navigateur et la persistance (ce document, en cours)
Chromium sans tête, CDP, un contexte par tâche, pot de cookies scellé par
employé, trois onglets, `blocked_by_site`.

### v2 — ce que Browserbase montre dans son tableau de bord, en logiciel
- **Furtivité** : scripts injectés à chaque document
  (`Page.addScriptToEvaluateOnNewDocument` : `navigator.webdriver`, plugins,
  langues, empreinte WebGL/canvas stables par employé), User-Agent réel et
  cohérent avec la plateforme, et **mode avec tête sous Xvfb** dans le
  conteneur, qui passe mieux que `--headless` face aux détecteurs.
- **Émulation** : géolocalisation, fuseau, langue, viewport, mobile
  (`Emulation.*`), par employé ou par tâche.
- **Fichiers** : téléchargements (`Browser.setDownloadBehavior`) rangés au
  classeur (`files`), envois (`DOM.setFileInputFiles`) depuis le classeur.
- **Vue en direct et enregistrement** : `Page.startScreencast` → flux d'images
  vers la console (SSE), et l'enregistrement d'une tâche rangé au classeur.
- **Journal** : table `browser_tasks` (employé, URL, étapes, durée, issue,
  captures) et sa page console.

### v3 — les prises, et la flotte
- **Proxy par session** : `--proxy-server` + `Fetch.authRequired`, le
  fournisseur (Bright Data, Oxylabs, ou une IP du client) est une clé dans
  Intégrations. On ne loue pas d'IP.
- **Captcha** : détection (`blocked_by_site` affiné) et prise pour un solveur
  par clé. On n'en paie pas.
- **Flotte** : un ordonnanceur qui répartit les tâches sur N conteneurs
  Chromium (`BROWSER_CDP_URLS`, santé, jetons par machine). N est une facture,
  l'ordonnanceur est du code.

Chaque phase s'appuie sur l'adaptateur de la précédente et ne démarre qu'une
fois celle-ci fusionnée : deux agents sur `browser_chrome.rs` en même temps,
c'est le bug de couture qu'on connaît.
