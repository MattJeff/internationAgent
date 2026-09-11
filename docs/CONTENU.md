# Être cité : la boucle, sa mesure, et ce qu'elle ne mesure pas

Écrit le 2026-09-11, en même temps que le code qu'il décrit.
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

---

## 3. La boucle, de bout en bout

```
  question  ──→  mesure  ──→  brief  ──→  texte  ──→  publication  ──→  mesure…
 (fondateur,    (un siège,   (structure,  (un       (une personne,   (la série
  un client)     un moteur)   pas prose)   employé)   à la main)      qui parle)
```

| étape | ce qui la fait | où ça vit |
|---|---|---|
| **1. la question** | `content_questions_add` / `POST /v1/content/questions` | `content_questions` |
| **2. la mesure** | `content_questions_measure` / `POST /v1/content/questions/{id}/measure` — **nomme un siège** | `content_citations`, en ajout seul |
| **3. le brief** | `content_briefs_get` / `GET /v1/content/briefs?question_id` | rien : une fonction pure de (1) et (2) |
| **4. le texte** | **un employé, avec son modèle** — rien dans ce dépôt n'engendre de prose | `content_drafts`, par `content_drafts_add` |
| **5. la publication** | **une personne, à la main** — voir § 5 | `content_drafts.url`, constatée par `content_drafts_amend` |
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

# 5. une personne publie, puis le constate
PUT  /v1/content/drafts/{id}
  { "title": "…", "body": "…", "url": "https://visa.orizn.app/blog/…" }

# 6. et on remesure
GET /v1/content/citations?question_id={id}&days=90
```

---

## 5. Ce qui manque pour publier — et il manque tout

**Aujourd'hui, rien ne publie.** Un brouillon est un document rangé dans une
table ; `content_drafts.url` est une adresse **constatée**, écrite par la
personne qui a publié, pas par le produit. Le mot « publié » dans `state` veut
dire *quelqu'un a vu l'article à cette adresse*, et le `CHECK` de `0100` refuse
un publié sans adresse ni date pour que ce mot ne puisse pas être menti.

Il y a deux chemins pour lever ça, et **aucun des deux n'est codé** :

### Chemin A — le dépôt GitHub du client

L'article devient un fichier Markdown poussé sur le dépôt qui sert le site du
client (Jekyll, Hugo, Next, Astro — peu importe, ils lisent tous un dossier).
Le connecteur GitHub est déjà au catalogue (`agentos_app::catalog`), donc ce qui
manque est : une entrée dans `employee_resources` pour le dépôt et la branche, un
effet `publish_article` derrière la Gate — un `McpCall` ou un `ActionKind`
nouveau, à trancher — et la relecture d'un humain avant la fusion.

*Ce qu'il coûte* : rien en argent. *Ce qu'il demande* : que le client héberge son
site sur un dépôt qu'il accepte de nous ouvrir. *Ce qu'il gagne* : la revue de
code du client est déjà le garde-fou, et une pull request est un brouillon qu'un
humain approuve sans que nous ayons à inventer un circuit d'approbation.

### Chemin B — un domaine web à nous, pour le client

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
| `crates/app/src/content.rs` | la mesure, le scan, le brief, et les limites de chacun |
| `apps/server/src/routes/content.rs` | les neuf routes, et pourquoi la mesure nomme un siège |
| `crates/app/src/mcp_tools/contenu.rs` | les neuf outils, un par route |
| `docs/ROADMAP_CROISSANCE.md` § 2.1 | pourquoi ce levier passe devant les autres |
