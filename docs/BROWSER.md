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

*(Cette liste est celle de la v1. Les deux premiers points ont été **révisés**
par la v2 et la v3, plus bas, et la révision ne contredit pas la règle : la
furtivité s'est révélée être du logiciel, et du proxy comme du captcha on n'a
construit que la prise. Le troisième et le quatrième tiennent tels quels.)*

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

### v3 — les prises, et la flotte (faite le 2026-09-10)
- **Proxy par contexte** : `Target.createBrowserContext { proxyServer,
  proxyBypassList }` + `Fetch.authRequired`, une ligne par locataire dans
  `browser_proxies` (0098), identifiants scellés. Le fournisseur (Bright Data,
  Oxylabs, ou une IP du client) est une clé que le client apporte. On ne loue
  pas d'IP.
- **Captcha** : détection des trois signatures lisibles (`blocked_by_site`
  affiné en `captcha`) et prise pour un solveur derrière `CAPTCHA_API_KEY`. On
  n'en paie pas.
- **Flotte** : `BROWSER_CDP_URL` accepte une liste, chaque machine a son
  sémaphore, sa santé et ses onglets. N est une facture, l'ordonnanceur est du
  code.

Chaque phase s'appuie sur l'adaptateur de la précédente et ne démarre qu'une
fois celle-ci fusionnée : deux agents sur `browser_chrome.rs` en même temps,
c'est le bug de couture qu'on connaît.
## Ce qui a été mesuré en construisant la v1

Adaptateur écrit le 2026-09-10 contre Google Chrome 152 en local (Docker
absent sur la machine de développement) ; l'agent infra a mesuré la même
chose sur `chromedp/headless-shell` (Chromium 151). Quatre points où la
mesure a corrigé le document, et ce que le code fait à la place.

1. **`http://browser:9222` ne se dialle pas tel quel.** `GET /json/version`
   avec `Host: browser:9222` répond `500 Host header is specified and is not
   an IP address or localhost.` (`devtools_http_handler.cc`,
   `RequestIsSafeToServe`) — et le `webSocketDebuggerUrl` rendu porte
   `127.0.0.1`, l'adresse à laquelle Chromium *s'écoute*, pas celle par
   laquelle on l'atteint. `BROWSER_CDP_URL=http://browser:9222` reste la
   forme de configuration ; `ChromeBrowser::endpoint` résout le nom à chaque
   ouverture d'onglet (l'adresse d'un conteneur change au redémarrage), IPv4
   d'abord, et compose *tous* ses appels sur `ws://<ip>:9222/…` — le chemin
   du `webSocketDebuggerUrl` est repris, son hôte non. Le faux CDP des tests
   refuse un `Host` nommé avec la phrase exacte de Chromium, et le test
   `the_cdp_host_is_resolved_and_dialled_by_address_never_by_name` vérifie
   que l'adaptateur arrive avec l'adresse. En production le 9222 est un
   `socat` devant Chromium sur 9223, l'image ne sachant écouter que sur
   `127.0.0.1` ; c'est invisible d'ici.

2. **Le trait ne dit pas quand une tâche finit.** `BrowserProvider::act`
   prend une étape ; `effects::load_page` en envoie deux sur la même session
   (`Goto` puis `Text`) et `drive` demande `Location` avant chaque étape qui
   ne navigue pas. Browserbase ouvre une session *par étape* — et lit donc
   `about:blank` à la seconde, ce que `RecordingCdp` masque. « L'onglet vit le
   temps du tour » s'implémente donc comme `HttpBrowser` tient son document :
   **par liaison**, entre deux `act`, fermé par la première de trois choses —
   le `Goto(about:blank)` qu'`effects` envoie pour parquer (la seule fin de
   tâche que le trait sache dire), une erreur qui concerne le navigateur et
   non notre sélecteur (`tab_survives`), ou 120 s sans étape (un moissonneur
   par onglet ; deux minutes parce qu'entre deux étapes il y a un appel de
   modèle). Le sémaphore est pris à l'ouverture et rendu à la fermeture, pas
   par étape. Un processus qui meurt avec un onglet ouvert perd les cookies
   de cette tâche-là ; le pot précédent est intact.

3. **`employee_resources(browser).state` n'est pas l'endroit du pot.** `state`
   est la colonne du cycle de vie (`provisioning`, `ready`…), lue par
   `claim_step` et `Effects::browser_session`. Le pot est une colonne à part,
   `sealed_cookies bytea` (migration `0095`), scellée sous
   `browser://<locataire>/<employé>` par `agentos_app::cookie_jar`, lue par
   `(provider = 'chrome', external_id)` sous `admin_tx_bypassing_rls` — la
   recherche précède le locataire, l'argument de 0053 et 0085, et l'AAD porte
   ce que la RLS aurait porté. Inscrite dans `identity::SEALED_COLUMNS`, donc
   sous la rotation de clé maître. Le port `CookieJar` est indexé par
   l'identifiant de contexte et non par l'employé : c'est la seule chose que
   `release(binding)` tient.

4. **`Page.navigate` revient avant le titre.** La détection d'un mur lit
   `document.title` et `performance.getEntriesByType('navigation')[0].responseStatus`
   (Chrome 109+, `0` avant, donc « pas un mur ») dans une promesse qui attend
   `DOMContentLoaded` : juste après `Page.navigate` le `<title>` n'est pas
   encore analysé. Un 403 réel et un titre « Just a moment… » sont mesurés
   `blocked_by_site` ; `Network.responseReceived` n'est pas utilisé — le
   pilote ignore les événements, exprès.

5. **Le journal ne tient pas de « captures ».** Le § v2 ci-dessus range les
   captures dans `browser_tasks` ; le port `BrowserObserver` ne les fait pas
   passer — une image n'est qu'un flux vers qui regarde, et rien de la page
   (texte, cookie, valeur tapée) n'a de chemin vers une colonne. La table
   (0096) tient donc l'employé, le fournisseur, le contexte, les bornes, cinq
   champs par étape (`kind`, `url` pour `goto` seulement, `outcome`,
   `took_ms`, `at`) et le *nombre* d'images diffusées (`frames_sent`). Une
   capture à conserver est l'enregistrement de tâche, au classeur, pas encore
   construit. Et l'écriture est asynchrone derrière une file bornée qui perd
   plutôt que d'attendre : le port est synchrone et l'adaptateur ne doit pas
   payer un aller-retour Postgres par étape.

Ce qui s'est confirmé sans surprise : `Network.setCookies` sur un contexte
neuf, avec les `CookieParam` dérivés de `Network.getAllCookies` (sept champs,
`expires` seulement s'il est positif), remet la session sur la requête
suivante — mesuré par un site qui pose `seat=ada` puis renvoie l'en-tête
`Cookie` reçu, à travers deux contextes. Une page `<div id=app></div><script>…
textContent='rendu'</script>` se lit `rendu` par `read_page` sur ce navigateur
et `""` par `HttpBrowser`, dans le même test.

Pour lancer les tests Chromium sans Docker :

```
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --remote-debugging-port=9222 --user-data-dir=$(mktemp -d) \
  --host-resolver-rules="MAP portal.example.com 127.0.0.1" about:blank &
BROWSER_CDP_URL=http://127.0.0.1:9222 cargo test -p agentos-providers -p agentos-app chromium
```

La règle de résolution sert au test de bout en bout d'`effects.rs`
(`Domain::parse` refuse une IP littérale) ; sans la variable, les tests
sautent en le disant.

## Ce qui a été mesuré en construisant la v2

Adaptateur étendu le 2026-09-10, même machine, même Chrome 152. Le document
ci-dessus promettait cinq choses ; trois se sont écrites comme prévu et
**quatre l'ont été autrement**, chaque fois parce que la mesure a contredit
la première lecture.

1. **`Xvfb` est retiré du plan, et ce n'est pas un report.** La v2 disait
   « mode avec tête sous Xvfb dans le conteneur, qui passe mieux que
   `--headless` face aux détecteurs ». C'était vrai de l'ancien headless.
   `--headless=new` (le mode par défaut depuis Chrome 112) est le *même*
   binaire de rendu que le mode avec tête : `Permissions.query`,
   `Notification.permission`, `window.chrome` et le rendu WebGL y répondent
   comme avec tête, et la seule chose que le mode ancien trahissait encore —
   le jeton `HeadlessChrome` de l'UA — est un `replace` d'une ligne. Xvfb
   aurait coûté un serveur X, ~80 Mo et un point de panne dans un conteneur
   plafonné à 1 Go, pour une différence qu'on ne sait pas mesurer. Ce qui
   reste vrai : ni l'un ni l'autre ne passe Turnstile ou DataDome, parce que
   ces deux-là ne lisent pas le navigateur, ils lisent l'adresse, le TLS et le
   temps.

2. **Le pilote ne peut pas voir un événement, donc les événements ont leurs
   propres sockets.** `CdpDriver::run` ignore tout ce qui n'est pas la réponse
   à sa propre commande — exprès, argumenté dans `cdp.rs` — et le contrat
   interdisait de changer sa signature. Deux besoins de la v2 sont pourtant
   des événements : `Page.screencastFrame` et `Fetch.requestPaused`. La sortie
   n'est pas de faire tamponner les événements par `call` (ce serait une file
   sans borne que personne ne vide, sur *chaque* commande) : c'est **une
   deuxième socket sur la même cible**, une par usage, avec pour seul travail
   de lire des événements. CDP diffuse un domaine activé au client qui l'a
   activé, donc `Fetch.enable` sur une socket et `Page.navigate` sur l'autre
   fonctionnent ensemble. `Cdp::next_event` est le seul ajout, et il rend
   `Ok(None)` (rien n'est arrivé) et `Err` (la socket est morte) séparément —
   une pompe qui ne saurait pas les distinguer tournerait à vide contre un
   pair mort jusqu'à ce qu'autre chose le remarque.

3. **`Fetch.enable` met la navigation en attente, donc la décision se prend
   *pendant*.** `Page.navigate` ne rend la main que lorsque la réponse a été
   continuée ou remplie : un document ne peut donc pas être détecté après la
   navigation, seulement à travers elle. D'où une tâche détachée armée
   **avant** `Page.navigate` et récoltée après. Et le motif est restreint à
   `resourceType: "Document"` : un `Fetch.enable` sans motif met en attente
   *chaque* sous-ressource, ce qui ajouterait un aller-retour de socket devant
   chaque image de chaque page, pour une réponse sur mille.

4. **Le premier document d'une navigation décide, et un 3xx ne compte pas.**
   Une redirection est mise en attente elle aussi (`responseStatusCode` 302,
   pas de corps utile) : elle est laissée passer et la surveillance continue,
   ce qui est la seule façon que `Goto(/tarifs)` → `302` → `/tarifs.pdf`
   arrive quand même en `Document`. La première réponse de type document qui
   n'est pas une redirection est la navigation principale — un iframe ne peut
   pas devancer la réponse de son propre parent — donc « la première » est
   « la principale » sans avoir à lire `Page.getFrameTree`.

5. **Le plafond de 8 Mo est celui de la socket, pas celui du classeur.** Le
   corps traverse CDP en base64 : 8 Mo de PDF, c'est ~10,7 Mo de trame tenue
   deux fois en mémoire, dans un conteneur à 1 Go avec deux autres onglets.
   `files` en prendrait bien plus. Et le `Content-Length` déclaré est lu
   **avant** `Fetch.getResponseBody`, sinon le refus arrive après avoir payé
   le transfert.

6. **Le défaut d'émulation n'est pas neutre, et c'est mesuré.** Un Chromium
   sans tête non configuré répond `en-US` et `UTC` à
   `Intl.DateTimeFormat().resolvedOptions().timeZone`, sur une machine dont
   l'horloge est à Paris. Un employé qui écrit en français depuis un
   navigateur américain dans un fuseau que personne n'habite est incohérent
   *gratuitement* — donc le défaut est `fr-FR / Europe/Paris / 1366×768`, et
   `employees.spec.browser` le remplace sans migration : `spec` est déjà la
   colonne jsonb de ce qui décrit un employé sans avoir de colonne.

7. **Une empreinte stable est meilleure qu'une empreinte absente, et bien
   meilleure qu'une empreinte neuve à chaque visite.** Le bruit canvas/WebGL
   est dérivé d'une graine SHA-256 de `ctx-<tag>` : un siège est une machine
   tant que son contexte dure. Un bruit aléatoire par tâche donnerait « un
   nouvel appareil à chaque visite », une forme qu'aucun parc de vrais
   portables n'a — c'est-à-dire un signal, pas une protection.

8. **Une session CDP qui se ferme emporte son émulation, et un script accepté
   n'est pas un script qui tourne.** Les deux mesures les plus coûteuses de ce
   chantier, toutes deux contre Chrome 152, toutes deux invisibles sans un vrai
   navigateur :

   * `Emulation.setLocaleOverride` et ses quatre voisins sont **portés par le
     client qui les a envoyés**. La première version habillait l'onglet sur une
     socket qu'elle refermait aussitôt ; la page sonde a lu `Asia/Manila` —
     le fuseau de la *machine* — au lieu d'`Europe/Paris`. La socket qui habille
     l'onglet vit donc aussi longtemps que lui.
   * `Page.addScriptToEvaluateOnNewDocument` **ne fait rien sans `Page.enable`**,
     et rend un `identifier` parfaitement valide dans les deux cas. Avec la
     socket tenue ouverte mais le domaine jamais activé, la sonde lisait le
     `navigator.languages` de Chrome et un vendeur WebGL `null` : le script
     avait été accepté et n'avait jamais tourné. Un `Page.disable` ensuite le
     dés-enregistre — la session doit rester abonnée.

   Et le prix de rester abonné : `Page` est un domaine bavard, une douzaine de
   trames par navigation, dans une socket que personne ne lit. Donc la socket
   n'est pas un champ de l'onglet mais appartient à une petite tâche qui lit et
   jette, jusqu'à ce que l'onglet se ferme. Trois onglets, trois tâches.

   Ce que ça dit du reste : **trois des quatre assertions de la page sonde
   passaient déjà avant le correctif.** `navigator.webdriver` est déjà `false`
   sous `--headless=new`, les cinq greffons PDF sont déjà là, et l'UA était
   corrigé par `Emulation.setUserAgentOverride`, qui lui marchait. Seul le
   vendeur WebGL — `null` sans l'extension, une chaîne de notre table avec —
   distinguait « le script tourne » de « le script a été accepté ». C'est
   l'assertion qui est restée dans le test, et c'est le genre de garde que
   `docs/` appelle « une garde qui mord ».

9. **Le screencast ne tourne jamais pour personne.** `wants_frames` est
   demandé à l'ouverture, après chaque étape, et par la pompe elle-même entre
   deux images ; l'observateur par défaut répond toujours non, donc un
   déploiement que personne ne regarde n'encode pas un octet. La pompe attend
   au plus une seconde entre deux lectures pour pouvoir reposer la question :
   une page qui n'affiche rien n'envoie rien, donc « quand la prochaine image
   arrive » ne peut pas être la réponse. Et l'acquittement part avant le
   décodage — Chromium n'envoie qu'une image non acquittée à la fois, donc
   décoder d'abord diviserait la cadence par deux et une image illisible
   arrêterait le flux pour de bon.

## Ce qui a été mesuré en construisant la v3

Adaptateur étendu le 2026-09-10, contre **Chrome 152.0.7977.83** en local. Le
tri du document tient : la prise se construit, la ressource s'achète, et rien
ici n'a ouvert de compte nulle part. Un déploiement sans ligne dans
`browser_proxies` et sans `CAPTCHA_API_KEY` envoie exactement les trames que la
v2 envoyait.

1. **Le nom des paramètres est `proxyServer` / `proxyBypassList`, et ils sont
   sur le contexte.** Relevés dans `GET /json/protocol` du binaire lui-même,
   pas dans une page de documentation : `Target.createBrowserContext` les
   documente « similar to the one passed to `--proxy-server` », tous deux
   `experimental` et optionnels. C'est ce qui permet **une adresse de sortie par
   tâche sans redémarrer Chromium** — un `--proxy-server` est un drapeau de
   processus, donc un Chromium par locataire — et c'est pour ça que le drapeau
   n'est pas touché.

2. **`Fetch.authRequired` n'arrive pas avec le motif de la v2, et ça n'est pas
   une question de `handleAuthRequests`.** C'est la mesure qui a coûté le plus
   cher à ce chantier, parce que le brief supposait le contraire. Avec le seul
   motif de la v2 — `{ requestStage: "Response", resourceType: "Document" }` —
   plus `handleAuthRequests: true`, contre un proxy qui répond `407` :

   * aucun `Fetch.authRequired` n'est émis ;
   * le `407` arrive en `Fetch.requestPaused` **au stade réponse**, comme une
     réponse ordinaire ;
   * et le continuer donne `net::ERR_INVALID_AUTH_CREDENTIALS` à la navigation.

   L'interception au stade réponse *avale* le défi avant que la pile réseau ait
   pu le poser. En ajoutant `{ requestStage: "Request", resourceType:
   "Document" }`, la même navigation donne : pause au stade requête →
   `continueRequest` → `Fetch.authRequired` → `continueWithAuth
   { ProvideCredentials }` → pause au stade réponse avec un `200`, **sur le
   même `requestId`**, et le proxy voit une deuxième requête portant
   `Proxy-Authorization: Basic …`. Le motif au stade requête n'est donc ajouté
   que quand le locataire a des identifiants à fournir : il coûte un
   aller-retour de socket **par document**, jamais par sous-ressource, et
   seulement à qui a acheté un proxy authentifié.

3. **Une seule session `Fetch` par onglet, et c'est le bug que ce chantier
   prévoyait.** La v2 montait un `Fetch.enable` sur une socket à elle **avant
   chaque navigation** et le refermait après ; l'authentification en voulait
   une deuxième, tenue pour la vie de l'onglet. Deux sessions `Fetch` sur une
   même cible sont deux interceptions qui se disputent le même
   `requestPaused` — un `continueResponse` en double, ou pire, une réponse que
   personne ne continue et une navigation qui ne rend jamais la main. La sortie
   n'était pas d'arbitrer entre les deux : c'est que la socket qui **tenait
   déjà l'habillage** (vivante aussi longtemps que l'onglet, déjà en train de
   lire des événements pour ne pas les accumuler — v2 § 8) fasse le travail au
   lieu de le jeter. Un `Fetch.enable`, un jeu de motifs, un consommateur.
   `one_tab_enables_fetch_exactly_once_however_many_navigations` les compte.

   Conséquence gratuite : la synchronisation entre l'étape qui navigue et la
   pompe est **l'ordre d'écriture**, pas un canal. `Fetch.enable` met la réponse
   en attente, donc `Page.navigate` ne rend la main que lorsque quelqu'un l'a
   continuée ; la pompe écrit sa décision *avant* de répondre ; donc au retour
   de `Page.navigate` la décision est posée. Un `oneshot` par navigation aurait
   fait le même travail avec une allocation et une branche « et si l'émetteur
   est mort » qui n'a pas de bonne réponse.

4. **Chromium essaie `https://` d'abord, et il proxifie ses propres sondes.**
   Deux choses qu'on ne voit qu'avec un vrai navigateur et un vrai proxy. La
   première requête d'un `Goto(http://…)` n'est pas le `GET` attendu : c'est un
   `CONNECT hôte:443` (HTTPS-first), lui aussi envoyé au proxy — et c'est *sur
   ce `CONNECT`* que le 407 tombe et que l'authentification se joue ; quand
   Chromium retombe sur `http://`, les identifiants sont déjà en cache. Il
   passe par ailleurs des `CONNECT www.google.com:443` de son cru (ses sondes de
   connectivité) par le même proxy : à savoir avant de facturer des octets à un
   client au gigaoctet.

   Et la boucle locale n'est pas proxifiée par défaut : `<-loopback>` dans
   `proxyBypassList` est ce qui retire l'exception. Sans lui, le test contre un
   vrai Chrome part en direct et le faux proxy ne voit rien — ce qui a
   ressemblé pendant une minute à « `proxyServer` ne marche pas ».

5. **Un défi de captcha n'est pas un mur, et l'ordre des deux tests compte.**
   Une page Turnstile porte le titre « Just a moment… » *et* un
   `.cf-turnstile[data-sitekey]` : les deux détections réussissent. C'est la
   plus précise qui gagne, parce que c'est celle qui dit quoi faire —
   `Terminal { code: "captcha" }` nomme quelque chose qu'une clé franchirait,
   là où `blocked_by_site` reste pour ce qu'aucune clé ne changerait. Les deux
   lectures sortent d'une **seule** `Runtime.evaluate` : elles attendent le même
   `DOMContentLoaded`, et deux évaluations seraient deux fois la même promesse
   et deux façons de désaccorder ce que « la page » veut dire.

6. **2Captcha valide le type de tâche avant la clé, ce qui rend le nom d'un
   type vérifiable sans compte.** Leur index de types
   (`https://2captcha.com/api-docs`, 2026-09-10) ne liste **plus de page
   hCaptcha** et `/api-docs/hcaptcha` répond 404 — le type
   `HCaptchaTaskProxyless` n'est donc plus documenté. Il est toujours accepté :
   `POST https://api.2captcha.com/createTask` avec une clé volontairement
   invalide répond `ERROR_KEY_DOES_NOT_EXIST` (errorId 1) pour
   `RecaptchaV2TaskProxyless`, `TurnstileTaskProxyless` et
   `HCaptchaTaskProxyless`, et `ERROR_TASK_ABSENT` (errorId 22) pour un type
   inventé. Une requête, aucun compte, et la seule chose de cet adaptateur qui
   ne vienne pas d'une page de documentation est nommée comme telle dans le
   code.

7. **Le pot de cookies est ce qui rend la flotte possible, et ce n'est pas une
   remarque en passant.** Un `--user-data-dir` par employé aurait attaché
   chaque siège à une machine : sa session vit sur ce disque-là. Ici la session
   est une colonne scellée (`employee_resources.sealed_cookies`, 0095) et le
   profil est une clé jsonb — les deux chez nous, aucun des deux sur un
   Chromium. N'importe quel point de la flotte peut donc ouvrir l'onglet de
   n'importe quel employé. Ce qui reste attaché, c'est la **tâche** : son onglet
   est sur une machine, donc elle y reste pour toute sa vie, et `Tab::at` garde
   l'adresse plutôt que de la re-résoudre à la fermeture.

8. **« Aucune machine saine » se distingue de « la flotte est pleine » par le
   fait de ne rien composer.** Les deux rendent `Retryable`, et un adaptateur
   sans flotte rendrait aussi `Retryable` en échouant sur `/json/version` — donc
   `is_retryable()` seul est une assertion aveugle, et le désarmement l'a montrée
   telle avant qu'elle ne parte au dépôt. La garde qui mord est le **compte de
   requêtes HTTP** : quand rien n'est sain, aucun `/json/version` n'est envoyé,
   et la ligne de journal nomme le total et le nombre de malades. La sonde est à
   trente secondes et **hors du chemin d'une tâche** ; l'état initial est
   « saine » parce que présumer le contraire ferait attendre trente secondes à
   la première tâche d'un déploiement qui vient de démarrer, et le prix d'une
   erreur optimiste est une ouverture d'onglet ratée, c'est-à-dire un
   `Retryable`.

9. **Ce que `POST /v1/browser/proxy/check` prouve, et ce qu'il ne prouve pas.**
   Il fait un `GET` *depuis ce processus* à travers le proxy du locataire, vers
   un service d'écho **que le client nomme** — il n'y a pas d'URL de tiers en
   dur dans ce dépôt, et sans `echo_url` la route ne vérifie rien et le dit. Ça
   prouve l'adresse, le port, les identifiants et l'adresse de sortie : les
   quatre choses qui se trompent quand on recopie une ligne depuis la console
   d'un fournisseur. Ça ne prouve pas que Chromium l'honore — c'est le rôle des
   deux tests contre un vrai Chrome, et c'est la place d'une assertion, pas
   d'une route. Un proxy SOCKS n'est pas vérifié du tout et répond
   `socks_not_checked` : le client HTTP de ce dépôt est construit sans le
   greffon SOCKS de `reqwest`, et l'activer tirerait une caisse de plus dans
   l'arbre pour une route de diagnostic. Chromium, lui, parle SOCKS.

10. **Le mot de passe du proxy n'a pas de chemin de retour, et c'est prouvé par
    un test qui lit le journal.** Il entre dans le corps d'un `PUT`, il est
    scellé à la ligne suivante sous `browser://<locataire>/proxy`, et il ne
    ressort ni de la vue (qui n'a pas de champ pour — c'est le type qui
    l'empêche), ni d'un `Debug` (`ProxyConfig` en écrit un à la main), ni d'une
    ligne de trace : `the_proxy_password_never_appears_in_a_response_or_a_log`
    capture tout ce que `tracing` émet pendant les quatre routes et y cherche
    les octets, après avoir vérifié que la capture a vu *quelque chose* — une
    capture vide prouverait n'importe quoi.
