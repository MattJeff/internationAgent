# Être cité : la boucle, sa mesure, et ce qu'elle ne mesure pas

Écrit le 2026-09-11, en même temps que le code qu'il décrit ; repris le
2026-09-12, quand deux des trois trous du § 7 ont été refermés et le troisième
arbitré (§ 8).
`docs/ROADMAP_CROISSANCE.md` § 2.1 dit **pourquoi** ce chantier passe devant les
autres. Ce document dit **ce qui existe**, **ce qui est mesuré**, **ce qui ne
peut pas l'être et pourquoi**, et **ce qui manque pour publier**.

---

## 1. La thèse, et pourquoi elle tient

Quand un développeur demande à un modèle *« comment vérifier par API si un
passeport permet d'entrer quelque part »*, la réponse cite deux ou trois
produits. Le développeur en essaie un. Il n'ouvre pas dix onglets, il ne compare
pas huit fournisseurs : il prend celui qui est nommé.

Y être vaut donc plus que n'importe quelle campagne, et pour trois raisons qui
ne sont pas des opinions :

* **Le coût marginal par article est proche de zéro** et l'effet est cumulatif —
  un texte publié en septembre est encore lu en mars, là qu'une annonce s'arrête
  le jour où on cesse de payer.
* **C'est le seul canal où un petit acteur bat un gros à budget égal.** Sur une
  question précise (« quels documents pour un Vietnamien en Pologne, par API »),
  la meilleure page gagne, et la meilleure page est celle écrite par qui connaît
  le sujet — pas celle de qui a le plus gros budget média.
* **Personne ne sait encore l'acheter.** Il n'y a pas de régie, pas de tarif, pas
  de commercial à appeler. Ce qui remplace l'achat est **une mesure** : quelles
  questions, qui est cité aujourd'hui, ce qui manque à notre page, et est-ce que
  ça bouge.

Le reste de ce document est cette mesure.

---

## 2. Ce qui est mesurable, et ce qui ne l'est pas

C'est la section la plus importante, parce que la tentation est d'écrire « on
mesure si ChatGPT nous cite » et de livrer quelque chose qui ne le fait pas.

### Mesurable aujourd'hui, et mesuré

**Une page de résultats servie publiquement, sans compte.** Depuis le
2026-09-10, notre navigateur sait lire une page rendue en JavaScript
(`docs/BROWSER.md`) ; une page de résultats en HTML pur se lit même sans lui.
`agentos_app::content::measure` la lit par `Effects::read_page` — le même jeton,
le même contrôle de portée et la même ligne d'audit qu'une lecture de site de
prospect — et en tire : **sommes-nous cités, à quel rang, et qui l'est à notre
place**.

Le moteur livré est **`duckduckgo_lite`** (`lite.duckduckgo.com/lite/`). Le
choix est daté et vérifié le **2026-09-11** :

```
$ curl -s https://lite.duckduckgo.com/robots.txt
User-agent: *
Allow: /
```

`html.duckduckgo.com/robots.txt` dit la même chose. C'est
`duckduckgo.com/robots.txt`, sur l'hôte principal, qui interdit `/lite` et
`/html` — donc on lit l'hôte qui l'autorise, et pas l'autre.

### Non mesurable, et pourquoi — un par un

| moteur | pourquoi pas |
|---|---|
| **ChatGPT, Claude, Gemini** (l'interface de chat) | La réponse n'existe que derrière un compte. La lire demanderait de s'y connecter avec des identifiants et d'automatiser une session, ce que les conditions d'utilisation de chacun interdisent explicitement. **Rien dans ce dépôt ne le fait, et rien n'expose de moyen de le faire.** |
| **Google, Bing, Brave, Mojeek, Startpage** | Pas de compte à franchir, mais leur `robots.txt` refuse leur page de résultats — vérifié le 2026-09-11 sur les cinq (`Disallow: /search` chez Bing, Brave et Mojeek ; `Disallow: /do/` et `/sp/` chez Startpage). Un refus écrit par le site est un refus, même quand rien ne l'applique techniquement. |
| **Les API de recherche payantes** (Serper, SerpAPI, Brave Search API) | Elles rendraient Google et Bing mesurables pour quelques dizaines de dollars par mois, avec l'accord du fournisseur. **C'est le chemin d'extension évident** — un `Engine` de plus, une clé dans `Credentials`, rien d'autre à changer. Il n'est pas codé parce que rien dans ce dépôt n'appelle un service payant sans qu'on l'ait décidé. |

### Donc : un moteur, et ce que ça vaut

Une mesure sur un moteur **n'est pas** la citation par un modèle. C'en est le
meilleur indicateur disponible gratuitement, parce que ce que les modèles citent
sort en grande partie de ce que les moteurs classent — et parce qu'il bouge dans
le même sens quand on publie. Le dire autrement serait vendre une mesure qu'on ne
fait pas.

### Ce que la mesure lit, et son plafond

`lite.duckduckgo.com` rend chaque résultat en trois lignes : le rang collé au
titre, le résumé, puis **l'hôte affiché**. Le scan
(`agentos_app::content::read_results`) est écrit en Rust, jamais confié à un
modèle, et il en tire les hôtes dans l'ordre. Deux limites, nommées plutôt que
tues :

* un résumé dont le premier caractère est exactement le rang suivant suivi d'un
  point ouvrirait un faux résultat. Les rangs doivent se suivre, ce qui écarte
  presque tous les cas ; le reste rendrait la mesure de cette question-là basse
  d'un cran, pas fausse ailleurs ;
* **le brief ne lit que les résumés**, pas les pages citées. Un résumé de deux
  lignes sous-estime ce qu'une page couvre, donc « ce qui manque » veut dire *ce
  qui n'est pas mis en avant*. C'est une information différente d'« absent », et
  souvent la plus utile pour écrire un titre. L'extension — un `read_page` par
  page citée — est un appel réseau par concurrent et par mesure ; elle attend
  qu'on ait une raison de la payer.

### Une mesure sur le vrai moteur, le 2026-09-11

Posée à la main, avant d'écrire une ligne de ce module, sur
`visa requirements api` :

| rang | hôte |
|---|---|
| 1 | `travel-buddy.ai` |
| **2** | **`visa.orizn.app`** |
| 3 | `visadb.io` |
| 4 | `rapidapi.com` |
| 5 | `www.oanor.com` |

C'est le chiffre de départ, et c'est exactement ce que la boucle ci-dessous sert
à faire bouger.

### La même mesure, par la boucle, le 2026-09-12

Rejouée le lendemain sur la même question et par le produit cette fois —
`content_questions_measure`, un siège, le vrai moteur : `travel-buddy.ai`,
`visadb.io`, puis **`visa.orizn.app` au rang 3**. Un cran plus bas qu'à la main
la veille, sur une page qui bouge d'un jour à l'autre : c'est précisément
pourquoi `content_citations` empile et ne réécrit pas, et pourquoi une mesure
isolée ne dit rien.

Et c'est cette marche-là qui a trouvé qu'une ligne d'hôte portant un espace dans
son chemin faisait perdre un rang de plus — voir § 7.

---

## 3. La boucle, de bout en bout

```
  question  ──→  mesure  ──→  brief  ──→  texte  ──→  publication  ──→  mesure…
 (fondateur,    (un siège,   (structure,  (un       (une personne,   (la série
  un client)     un moteur)   pas prose)   employé)   à la main)      qui parle)
```

| étape | ce qui la fait | où ça vit |
|---|---|---|
| **0. ce que « nous » veut dire** | `content_repos_set`, champ `site` | `content_repos.site` (`migrations/0105`) |
| **1. la question** | `content_questions_add` / `POST /v1/content/questions` | `content_questions` |
| **2. la mesure** | `content_questions_measure` / `POST /v1/content/questions/{id}/measure` — **nomme un siège** | `content_citations`, en ajout seul |
| **3. le brief** | `content_briefs_get` / `GET /v1/content/briefs?question_id` | rien : une fonction pure de (1) et (2) |
| **4. le texte** | **un employé, avec son modèle** — rien dans ce dépôt n'engendre de prose | `content_drafts`, par `content_drafts_add` |
| **5a. la proposition** | `content_drafts_propose` / `POST /v1/content/drafts/{id}/propose` — **nomme un siège** | `content_drafts.state = 'proposed'`, `review_url` |
| **5b. la publication** | **une personne**, qui fusionne la pull request — voir § 5 | `content_drafts.url`, constatée par `content_drafts_amend` |
| **6. la mesure suivante** | `content_questions_measure`, à nouveau | la série de `content_citations` |

Trois choses méritent d'être dites au-dessus du tableau.

**La mesure nomme un siège, et ce n'est pas une décoration.** Lire une page
publique est un `ActionKind::BrowserRead` sur lequel la Policy Gate statue —
pour un *employé*, jamais pour une clé d'API. Un siège dont la politique n'a pas
`Channel::Web` ne mesure pas, et le refus est une ligne d'`audit_log` comme les
autres. Une route d'opérateur qui lirait la page « au nom du locataire » aurait
été une deuxième porte vers le web sans décision derrière elle.

**Le brief n'a pas de table**, et c'est une décision. C'est une fonction pure
d'une question et d'une mesure, toutes deux stockées : une table serait un cache
d'un calcul de trois microsecondes, et surtout une deuxième vérité qui vieillit
pendant que la mesure, elle, bouge. Le jour où un employé *annote* un brief à la
main, la table sera celle des annotations.

**La série ne se réécrit jamais.** `app_role` n'a ni `UPDATE` ni `DELETE` sur
`content_citations` (`migrations/0100`). Le fait intéressant n'est pas « sommes
nous cités » mais « depuis quand » et « qu'est-ce qui a changé quand on a
publié » — et une colonne mise à jour à chaque mesure rend ces deux questions
inrépondables. C'est exactement l'erreur que `contacts.last_contacted_at` a faite
côté prospection.

---

## 4. Ce que ça donne, en commandes

```bash
# 0. ce que « nous » veut dire. SANS CETTE LIGNE, la mesure rend 409
#    `no_domain_of_ours` — et c'est voulu : avant le 2026-09-12 elle lisait les
#    domaines d'ENVOI D'E-MAIL du locataire et répondait faux sans le dire.
PUT  /v1/content/repos/{employee_id}
  { …, "site": "visa.orizn.app" }

# 1. les questions qu'on veut gagner
POST /v1/content/questions
  { "question": "how do I check visa requirements by API",
    "locale": "en", "source": "customer", "weight": 9 }

# 2. la mesure, par un siège dont la politique porte `web`
POST /v1/content/questions/{id}/measure
  { "employee_id": "…", "engine": "duckduckgo_lite" }
→ { "citation": { "cited": true, "rank": 2,
                  "competitors": ["travel-buddy.ai", "visa.orizn.app", …] } }

# 3. le brief : ce que les pages citées couvrent, ce qu'elles ne couvrent pas
GET /v1/content/briefs?question_id={id}
→ { "brief": { "angle": "outrank",
               "covered": ["prix", "couverture", "exemple"],
               "missing": ["limites", "fiabilité"],
               "outrank": ["travel-buddy.ai"] } }

# 4. l'employé écrit, et le range
POST /v1/content/drafts   { "question_id": "…", "title": "…", "body": "…" }

# 4bis. ce qu'il faut avoir posé UNE FOIS avant la première proposition.
#       Les trois premières lignes ne se devinent pas, et c'est ce qui a
#       arrêté la première marche de bout en bout, le 2026-09-12.
POST /v1/mcp/connect            { "connector": "github", "server": "github", … }
POST /v1/mcp/servers/github/discover
→ chaque outil avec son `digest` : c'est ce qu'un humain lit avant d'accorder.
PUT  /v1/mcp/servers/github/tools/{get-file-contents|create-branch|create-or-update-file|create-pull-request}
  { "risk": "write", "digest": "…" }
→ SANS CES TROIS LIGNES, un outil est classé destructif (il n'est déclaré par
  personne), la Gate le refuse avant le transport, et la proposition rend
  409 `tool_unavailable`.

# …et la politique du siège doit nommer les quatre outils. Ce n'est PAS
# `policy_role_set` : ajouter un outil à une allowlist est un élargissement,
# qu'une clé de locataire ne peut pas faire (409 `policy_widens`). C'est
# l'opérateur, sur son propre DATABASE_URL :
#   agentos-server policy install --tenant <uuid> --role <rôle> <couche.json>
# et le plafond de la plateforme doit les nommer aussi — la Gate intersecte,
# donc un outil absent de `docs/orizn-ceiling.json` est inatteignable même
# nommé par le rôle.

# 4ter. le dépôt qui sert le site du client, attaché à un siège (une fois)
PUT  /v1/content/repos/{employee_id}
  { "server": "github", "repo": "orizn/site",
    "branch": "main", "folder": "content/blog",
    "site": "visa.orizn.app" }
→ `site` est l'hôte public où les articles ressortent, et c'est LUI que la
  mesure cherche dans les résultats. Ce n'est pas un domaine d'envoi ;
  `migrations/0105` argumente la séparation.

# 5a. l'article part dans le dépôt, sur une branche à lui, et une pull request
#     demande à une personne de le lire. Ça ne publie pas.
POST /v1/content/drafts/{id}/propose   { "employee_id": "…" }
→ { "draft": { "state": "proposed",
               "review_url": "https://github.com/orizn/site/pull/7" },
    "proposal": { "branch": "article/019…", "path": "content/blog/…md" } }

# 5b. une personne fusionne, puis constate l'adresse publique
PUT  /v1/content/drafts/{id}
  { "title": "…", "body": "…", "url": "https://visa.orizn.app/blog/…" }

# 6. et on remesure
GET /v1/content/citations?question_id={id}&days=90
```

---

## 5. Ce qui publie, et ce qui ne publie toujours pas

**Le produit ne publie toujours pas, et c'est une propriété, pas un manque.**
`content_drafts.url` reste une adresse **constatée**, écrite par la personne qui
a vu l'article en ligne. Le mot « publié » dans `state` veut dire *quelqu'un a vu
l'article à cette adresse*, et le `CHECK` de `0100` refuse un publié sans adresse
ni date pour que ce mot ne puisse pas être menti.

Ce qui a changé le 2026-09-11 est ce qui vient **avant** ce mot : l'article sort
d'ici tout seul, jusqu'à la porte du client.

### Chemin A — le dépôt GitHub du client : **codé**

L'article devient un fichier Markdown poussé sur le dépôt qui sert le site du
client (Jekyll, Hugo, Next, Astro — peu importe, ils lisent tous un dossier),
sur une branche à lui, et une pull request demande à une personne de le lire.

* **Le dépôt, la branche et le site sont une ressource d'un siège** :
  `content_repos` (`migrations/0102`, `site` par `migrations/0105`), posée par
  `content_repos_set`. Deux clients ont deux
  dépôts ; rien ne vient d'une variable d'environnement. La table pend au
  branchement MCP par une clé étrangère, donc un dépôt ne se pose pas sur un
  GitHub que personne n'a branché. Ce n'est **pas** une ligne
  d'`employee_resources`, et 0102 dit pourquoi : `employee::load` exige de cette
  table-là une ligne par étape de provisionnement, exactement, et un dépôt n'est
  pas une étape — personne ne l'achète et rien ne le relâche.
* **Quatre appels d'outil, quatre verdicts de la Gate, dans cet ordre** :
  `get-file-contents`, `create-branch`, `create-or-update-file`,
  `create-pull-request` sur le connecteur GitHub, qui était déjà au catalogue.
  Un `McpCall` par geste, pas d'`ActionKind` nouveau — la Gate savait déjà
  statuer là-dessus, pour un siège nommé, avec sa ligne d'`audit_log`. Un siège
  dont la politique ne nomme pas les quatre outils n'ouvre rien, et le refus
  arrive avant que quoi que ce soit sorte. **L'ordre est le mécanisme** : la
  lecture passe avant la création de la branche, donc ce qui peut manquer manque
  avant qu'il y ait quoi que ce soit à nettoyer chez le client — voir § 7.
* **Et un quatrième verrou, qui n'est pas la Gate** : `agentos_app::mcp`
  classe *destructif* tout outil qu'aucune déclaration ne couvre, et refuse un
  destructif sans approbation — donc les quatre outils doivent avoir été
  déclarés (`PUT /v1/mcp/servers/{server}/tools/{tool}`, § 4) même quand la
  politique les nomme. Les deux verrous sont indépendants et se lisent
  différemment : la politique manquante est un 403 `no_rule`, la déclaration
  manquante un 409 `tool_unavailable`.
* **La relecture humaine est la pull request**, et rien n'a été inventé à côté.
  Ce dépôt ne sait pas fusionner.
* **`proposed` n'est pas `published`.** Le brouillon passe à `proposed` et porte
  `review_url` — l'adresse de la demande, rebâtie à partir de nos propres
  chaînes et d'un entier lu chez GitHub, jamais d'un lien recopié. `url` et
  `published_at` ne bougent pas. `migrations/0102` argumente le troisième état
  et les trois façons de s'en passer qui ne tiennent pas.

*Ce qu'il coûte* : rien en argent. *Ce qu'il demande* : que le client héberge son
site sur un dépôt qu'il accepte de nous ouvrir. *Ce qu'il gagne* : la revue de
code du client est déjà le garde-fou, et une pull request est un brouillon qu'un
humain approuve sans que nous ayons à inventer un circuit d'approbation.

*Ce qui n'est pas vérifié, et ne pouvait pas l'être* : aucun appel n'a jamais été
fait contre le vrai serveur MCP de GitHub. Il demande un compte et un passage
OAuth, et ce chantier n'avait pas le droit d'en ouvrir un. Les tests parlent à un
faux GitHub monté à la main. Ce qui reste à prouver au premier vrai branchement
est que GitHub épelle ces quatre outils comme nous — et un nom faux sort en
`unknown_tool` au premier appel, avant qu'un octet soit écrit.

### Chemin B — un domaine web à nous, pour le client : **pas codé**

Le client nous donne un sous-domaine (`blog.client.com` en CNAME), et le produit
sert les articles. `tenant_domains` existe déjà et `sending_domain.rs` sait poser
un enregistrement chez Cloudflare pour l'e-mail — donc la moitié DNS est faite.
Ce qui manque est un serveur de pages : un gabarit, un rendu Markdown, un cache,
et un certificat.

*Ce qu'il coûte* : un hébergement, un certificat, et surtout **un produit de
plus à tenir** — un site web public qui tombe est une panne client. *Ce qu'il
gagne* : le client n'a rien à ouvrir, et le domaine vit sous notre contrôle.

### Ce qu'on ne fera pas

Publier sur un domaine **à nous** (un blog `orizn-content.com` qui parle au nom
de dix clients) : ce serait une ferme de contenu, les moteurs la classent comme
telle, et le premier client à s'en apercevoir aurait raison de partir.

---

## 6. Où est quoi

| fichier | ce qu'il porte |
|---|---|
| `migrations/0100_une_question_merite_une_reponse.sql` | les trois tables, leur RLS, et l'argument de l'ajout seul |
| `migrations/0102_une_pull_request_nest_pas_une_publication.sql` | le dépôt d'un siège, le troisième état, et pourquoi ce n'est pas `employee_resources` |
| `migrations/0106_un_site_nest_pas_un_expediteur.sql` | le site où l'on publie, et pourquoi ce n'est pas le domaine d'où l'on envoie |
| `crates/app/src/content.rs` | la mesure, le scan, le brief, la proposition, et les limites de chacun |
| `apps/server/src/routes/content.rs` | les douze routes, et pourquoi la mesure comme la proposition nomment un siège |
| `crates/app/src/mcp_tools/contenu.rs` | les douze outils, un par route |
| `docs/ROADMAP_CROISSANCE.md` § 2.1 | pourquoi ce levier passe devant les autres |

---

## 7. La marche de bout en bout du 2026-09-12, et ce qu'elle a trouvé

La boucle n'avait jamais été parcourue d'un bout à l'autre depuis un terminal.
Elle l'a été ce jour-là, sur une instance locale, contre le **vrai**
`lite.duckduckgo.com` pour la mesure et contre un **faux serveur MCP de GitHub**
monté pour l'occasion — HTTP/1.1 sur le loopback, corps JSON-RPC, un dépôt en
mémoire, `server/discover` répondu en `-32601` comme le font les SDK de
référence. Aucun vrai dépôt n'a été touché et aucun compte n'a été créé.

**Les sept étapes passent.** Question → mesure → citations → brief → brouillon →
pull request chez le client → adresse constatée. Le fichier arrive au bon
chemin, sur une branche à lui, avec son en-tête ; le brouillon sort `proposed`
et pas `published`.

### Ce qui a cassé, et qui est réparé

* **La mesure inventait un concurrent et nous coûtait un rang.** Sur « how do I
  check visa requirements by API », le moteur affichait un résultat comme
  `zylalabs.com/api-marketplace/top-search/visa requirements` — la requête
  affichée met un espace dans le chemin. `display_host` refusait toute ligne
  portant un blanc, l'hôte n'était pas lu, le résultat se refermait sans nom, et
  `visa.orizn.app` sortait **4ᵉ au lieu de 3ᵉ**, avec une chaîne vide en
  troisième concurrent — qui remontait telle quelle dans l'`outrank` du brief.
  Le blanc se cherche maintenant avant la première barre, pas sur la ligne
  entière.
* **Une déclaration d'outil manquante accusait GitHub.** Un outil que
  `integrations_tools_declare` n'a pas classé est destructif par défaut et refusé
  *avant le transport* ; la route rendait « the repository host did not answer ».
  C'est maintenant un 409 `tool_unavailable` qui nomme les deux outils à
  rejouer.
* **`content_repos_set` renvoyait à `integrations_list`, qui n'existe pas** (la
  vraie ligne est `integrations_servers_list`). Un test relit toute la table
  d'outils et refuse un nom cité qui n'en est pas un ; il en a trouvé un second
  tout seul, dans un autre domaine.
* **La carte d'entrée (`INSTRUCTIONS`) ne parlait pas du contenu.** Elle portait
  quatre enchaînements et aucun n'était celui-ci — donc un modèle qui lit
  `tools/list` et rien d'autre ne pouvait pas mener la boucle. Il y en a cinq, et
  un test refuse que la carte nomme un outil absent.

### Ce que la marche a confirmé sans le réparer

* **Le brief n'a pas de table, et ça tient.** `content_citations` porte tout ce
  que `brief` lit (`excerpt`, `rank`, `competitors`), et `content_citations_list`
  les rend — donc le brief d'une mesure de mars se recalcule en mars prochain.
  Une seule nuance : `GET /v1/content/briefs` bâtit sur la **dernière** mesure et
  ne sait pas viser une mesure précise. Recalculer un ancien brief se fait à la
  main depuis la ligne, pas par la route. Une table serait toujours une
  deuxième vérité ; un `citation_id` optionnel sur la route serait, lui, une
  ligne — le jour où quelqu'un le demande.
* **Republier un article corrigé échouait**, et c'est refermé le 2026-09-12 —
  voir « Les deux trous refermés » ci-dessous.

### Les deux trous refermés le 2026-09-12

Ce sont, dans les mots de la veille, le **point 3** de « ce qui manque encore »
et le deuxième tiret de « ce que la marche a confirmé sans le réparer » —
`migrations/0105` cite le premier sous son ancien numéro, § 7.3.

**1. `our_domains` lisait la table des domaines d'envoi.** C'était le plus court
et le plus grave : `SELECT domain FROM tenant_domains` rend, pour Orizn,
`agents.getorizn.com` et `agent.oriznapi.uk` — jamais `visa.orizn.app`. Le site
du client pouvait sortir premier, la mesure annonçait qu'il n'était pas cité, et
le brief, l'angle et « qui dépasser » sont tous bâtis sur ce booléen.

Le chemin court aurait été de verser `visa.orizn.app` dans `tenant_domains`. Il
est refusé, et pas pour la propreté : `tenant_domains` n'est pas une liste de
noms, c'est **une rotation d'envoi**. `sending_domain::pick_from` choisit
l'expéditeur d'un mail parmi « le domaine *vérifié* dont il reste le plus de
plafond », donc une ligne en `verified` fait partir le premier mail de
prospection d'un domaine sans DKIM ni SPF ; et en `pending`, un siège attendrait
la vérification d'un domaine que personne n'a déclaré chez Resend. **L'asymétrie
tranche** : un domaine d'envoi non vérifié interdit à un siège de s'y asseoir, un
domaine de site n'a rien à vérifier — deux `status` qui ne veulent pas dire la
même chose ne partagent pas une colonne.

Donc `content_repos.site` (`migrations/0105`), et pas une table `tenant_sites` :
0102 range déjà le dépôt qui sert le site du client, et l'adresse publique de ce
site est le cinquième fait de la même phrase, sue par la même personne au même
moment. Ce qu'une table à part aurait acheté — déclarer un site sans dépôt — n'est
pas un besoin tant que le seul chemin de publication codé passe par ce dépôt. Un
locataire sans `site` déclaré sort en 409 `no_domain_of_ours`, avec le geste à
faire : un refus lisible remplace une mesure fausse.

**2. Republier un article corrigé échouait, et laissait un déchet.** Proposer,
faire fusionner, puis proposer un second brouillon **du même titre** :
`file_stem` rend le même chemin, la nouvelle branche part de `main` qui porte
désormais le fichier, et `create-or-update-file` répond `isError` faute de `sha`.
Mesuré la veille : `github_refused` sur le deuxième des trois appels, **avec une
branche orpheline laissée chez le client**.

Le quatrième appel est `get-file-contents`, et **il passe en premier**. C'est ce
qui referme les deux moitiés d'un coup : lu en quatrième position il aurait
réparé l'échec en gardant la branche que le deuxième avait déjà créée ; lu en
premier, ce qui peut manquer manque avant qu'une branche existe. Les deux refus
ordinaires — une politique qui ne nomme pas l'outil, un `sha` qu'on n'a pas —
tombent maintenant sur une lecture, et le dépôt du client est exactement comme
avant.

Le `sha` est **la seule valeur de tout ce module qui vienne vraiment d'un
étranger** : `review_url` rebâtit son adresse à partir de nos propres chaînes, et
ici c'est impossible — un `sha` *est* ce que GitHub a à en dire. Ce qui en tient
lieu de garde-fou est sa forme, quarante chiffres hexadécimaux et rien d'autre.
Un `sha` faux ne fait pas écrire ailleurs (le chemin et la branche viennent de
nous), il fait refuser l'écriture.

*Ce qui n'est pas fait, et pourquoi* : aucun nettoyage compensatoire pour le cas
qui reste — le réseau qui meurt entre le deuxième et le quatrième appel.
Supprimer une branche demanderait un cinquième outil, donc une ligne de plus dans
la politique de chaque siège et dans le plafond de la plateforme, c'est-à-dire un
`policy install` chez chaque client, pour rattraper un échec qui ne se produit
plus par la voie qu'on sait nommer. Et le rappel de `propose` sur un brouillon
dont la branche traîne sort en `github_refused` sur `create-branch` : GitHub
refuse une référence qui existe, et distinguer ce refus-là d'un autre demanderait
de lire sa prose.

### Ce qui manque encore pour qu'un article du client soit réellement en ligne

1. **Personne n'est prévenu quand un humain a fusionné.** C'est le trou nommé au
   § 5, et il reste ouvert : entre `proposed` et `published`, il n'y a que
   quelqu'un qui pense à regarder la pull request. Le chaînon évident est un
   webhook GitHub `pull_request.closed` — **et le § 8 dit pourquoi il ne vaut pas
   sa vague**, et ce qui vaudrait mieux pour le même prix.
2. **La politique d'un siège ne s'élargit pas depuis le terminal.** Ajouter les
   **quatre** outils de GitHub à une allowlist est un élargissement :
   `policy_role_set` répond 409 `policy_widens`, et il faut
   `agentos-server policy install` sur le `DATABASE_URL` de l'opérateur — **deux
   fois**, parce que le plafond de la plateforme (`docs/orizn-ceiling.json`)
   porte `allowed_mcp_tools: []` et que la Gate intersecte. Tant que c'est vrai,
   aucun client ne peut ouvrir sa première pull request sans que l'opérateur
   touche la base. Le fichier livré devrait nommer les quatre outils ; le changer
   est un élargissement de plafond, et ça se décide, ça ne se glisse pas dans un
   commit de code.

---

## 8. Le webhook de fusion : ce qu'il coûte, ce qu'il achète, et pourquoi non

Le chaînon manquant du § 7.1, chiffré plutôt que supposé.

**Ce qui existe déjà** : `POST /v1/webhooks/{path}` (`routes::webhooks`) lit le
corps brut avant toute désérialisation, vérifie la signature dessus et écrit une
ligne ; `webhook_endpoints` (`migrations/0053`) tient un secret par locataire et
par fournisseur, derrière un chemin opaque ; `POST /v1/platform/webhooks` émet
l'adresse à coller. GitHub signe `X-Hub-Signature-256: sha256=<hex>` en
HMAC-SHA256 sur le corps brut — **exactement** le schéma de Smartlead, déjà
compilé.

**Ce qu'il faudrait** : une migration qui élargit
`webhook_endpoints_provider_is_wired` à `'github'` (0081 est le modèle, six
lignes) ; une branche de vérification dans `routes::webhooks` (une vingtaine) ;
et — c'est la moitié qui coûte — **un lecteur**, parce que 0053 interdit de
nommer un fournisseur dont aucun ingest ne lit les livraisons.

**Et surtout, ce que le lecteur peut écrire, qui est moins qu'on ne croit.** Une
pull request fusionnée ne dit pas à quelle adresse l'article est en ligne : le
générateur du client décide de l'URL, et il la publie quand son déploiement
passe. Donc le webhook **ne peut pas** remplir `content_drafts.url` — le § 5
tient toujours, `url` est un constat. Ce qu'il peut faire est réveiller
quelqu'un : une ligne de `work_items` (`migrations/0061`) sur le siège qui a
proposé, « la demande est fusionnée, va constater l'adresse ». Et ça demande de
retrouver le brouillon depuis la livraison, c'est-à-dire un `SELECT` sur
`content_drafts.review_url` — qui est la colonne indexée pour ça, et la seule
chose de tout ce chantier qui existe déjà telle quelle.

**Verdict, arrêté le 2026-09-12 : non, et ce n'est pas un « pas maintenant ».**

Quatre raisons, de la plus décisive à la plus circonstancielle.

1. **Il n'achète pas la publication, il déplace le geste humain d'un cran.** Le
   webhook ne peut pas remplir `url` — une pull request fusionnée ne dit pas à
   quelle adresse l'article est en ligne. Ce qu'il achète est « va constater
   l'adresse » au lieu de « va regarder la pull request ». La personne fait
   toujours exactement un geste, au même endroit, un jour plus tard.
2. **Le rappel qu'il achète existe déjà.** `content_drafts_list` rend l'état et
   `review_url`, et le § 8 d'origine le dit lui-même en dernière ligne. Ce qui
   manque n'est pas l'information, c'est l'attention — et une ligne de
   `work_items` de plus est un deuxième endroit où ne pas regarder.
3. **Son prix caché est chez le client.** `webhook_endpoints` tient un secret par
   locataire et par fournisseur et `POST /v1/platform/webhooks` émet l'adresse à
   coller : quelqu'un doit ouvrir les réglages du dépôt du client, créer le
   webhook, coller l'adresse et le secret. C'est un geste manuel par client, du
   même ordre que celui qu'on prétend supprimer, et il tombe sur celui qu'on
   voulait épargner. Le compte honnête est donc : une vague de notre côté, un
   geste de plus du sien, contre un rappel.
4. **Il est attaché au chemin A.** Le jour du chemin B — un domaine servi par
   nous — il ne dit plus rien : c'est nous qui publions, et nous connaissons
   l'adresse sans que personne nous prévienne.

### Ce qui vaudrait mieux pour le même prix : constater au lieu de demander

« Publié » veut dire *quelqu'un a vu l'article à cette adresse* (§ 5). Or
**voir une page est déjà une capacité de ce dépôt** : `Effects::read_page`,
derrière la Policy Gate, avec son jeton, son contrôle de portée et sa ligne
d'`audit_log` — c'est exactement ce que `content_questions_measure` fait tous
les jours. Un siège qui relit l'adresse d'un article et y trouve son titre *a
vu l'article*, au sens plein que le `CHECK` de `0100` protège.

Ce qu'il manquait pour ça était l'hôte, et il est arrivé aujourd'hui :
`content_repos.site`. Ce qui manque encore est la **forme du chemin**, qui est
propre au générateur du client — `/blog/<stem>/` chez Hugo et Astro,
`/blog/AAAA/MM/JJ/<stem>.html` chez Jekyll. C'est **une colonne de plus sur
`content_repos`**, exactement ce que le commentaire `ponytail:` d'`article()`
prévoit déjà pour l'en-tête YAML, plus une lecture qui écrit `url` et
`published_at` quand elle trouve le titre.

Le compte, en regard :

| | le webhook | le constat |
|---|---|---|
| migration | une, sur `webhook_endpoints` | une colonne |
| vérification de signature | une branche, un secret par locataire | rien |
| geste chez le client | créer un webhook, coller un secret | rien |
| ce que ça écrit | une ligne de `work_items` | `url`, `published_at`, `state = 'published'` |
| survit au chemin B | non | oui |
| ce qu'il reste à faire à un humain | constater l'adresse | rien |

*Ce que la contre-proposition coûte, dit franchement* : un gabarit d'URL est une
supposition sur le générateur du client, et une supposition fausse laisse un
article en ligne en `proposed`. C'est le sens conservateur — on n'écrit jamais
`published` à tort — c'est réparable par la personne qui corrige le gabarit une
fois, et c'est un fait sur **un** client là où le webhook est une infrastructure
pour **tous**. Reste le déclencheur : le moins cher est un outil que le siège
appelle sur ses brouillons `proposed`, ce qu'un objectif de siège sait déjà
réveiller — pas une boucle de plus.

*Et pourquoi ce n'est pas codé ici* : la question posée était un avis avant du
code, et l'avis est « non » pour le webhook. Coder la contre-proposition sans
qu'elle soit arbitrée serait construire la deuxième vague du même jour.
