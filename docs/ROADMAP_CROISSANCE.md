# De 190 $ à 1 900 $ : la feuille de route, et l'ordre

Écrite le 2026-09-11, à la demande du fondateur, **avant** d'écrire une ligne
des chantiers qu'elle décrit. Elle a une consigne au-dessus des autres :
*consolider ce qui existe avant d'ajouter*. Ce qui suit est donc d'abord une
liste de ce qui est construit et pas fini, ensuite seulement une liste de ce qui
manque.

L'objectif du fondateur : Orizn fait **190 $/mois** ; l'objectif est **×10 en
trois à quatre mois**. Et la question qui gouverne chaque arbitrage ci-dessous :
*est-ce que 5 000 à 100 000 $ investis ici sont l'argent le mieux placé de cette
entreprise ?* Une ligne qui ne répond pas à cette question ne mérite pas d'être
codée.

---

## Phase 0 — Ce qui est construit et ne sert à rien aujourd'hui

C'est la phase la plus rentable du document, parce que son coût est proche de
zéro et que son effet est le passage de « rien ne tourne » à « tout tourne ».

| Bloqueur | Ce qu'il empêche | Qui peut le lever |
|---|---|---|
| **Aucune clé d'API Anthropic** | Tout. Aucun employé ne prend un tour depuis le 2026-09-06. Le navigateur, les séquences, la prospection, les factures : construits, déployés, et immobiles. | Le fondateur, en dix minutes |
| Le serveur MCP n'est pas déployé | Les 116 outils existent sur `main` et ne répondent nulle part | Moi — rattrapage siglair + Caddyfile |
| Aucune clé Browserbase | Rien : notre Chromium remplace Browserbase depuis le 2026-09-10 | Personne, c'est réglé |
| Le re-pin `--live` en attente | Deux verbes de séquence restent hors du catalogue des employés | Le fondateur, deux runs |
| Stripe sans endpoint | Une facture payée ne se voit pas | Le fondateur, le `whsec_…` |

**Rien de ce qui suit ne produit un euro tant que la première ligne n'est pas
levée.** C'est la seule phrase de ce document qui compte vraiment.

---

## Phase 1 — Consolider : finir ce qui est à moitié

Dans l'ordre, et chacun se mesure.

### 1.1 Déployer le serveur MCP, et l'installer pour de vrai
Le rattrapage vers siglair, le chemin dans Caddy, puis **une session réelle
depuis Claude Code** : `initialize`, `tools/list`, trois appels qui écrivent.
Tant que personne ne s'est connecté une fois, ce n'est pas livré.

### 1.2 Une console pour la connexion, pas un fichier de doc
Aujourd'hui, brancher le MCP demande de lire `docs/MCP_SERVEUR.md` et de coller
une clé à la main. Ce qu'il faut : une page **Connexion** dans la console qui
émet une clé nommée, affiche la commande prête à copier, et dit si une session
MCP a été vue. C'est la différence entre un produit et un dépôt.

### 1.3 La couverture des outils, tenue dans le temps
Le test existe et a déjà attrapé deux trous en une heure. Il lui manque une
moitié : **la CI de siglair doit le faire échouer**, et le tableau des outils
doit être publié quelque part qu'un client lise.

### 1.4 Les descriptions, relues comme du produit
116 outils écrits par trois mains en parallèle. Le nom, le titre, la phrase
« quand s'en servir » sont ce qu'un modèle lit pour choisir : c'est de
l'interface, pas de la documentation. Une passe de relecture unique, avec une
convention écrite (singulier/pluriel, verbe, ordre des mots).

### 1.5 Ce que les rapports d'agents ont laissé, et qui est vrai

**Fermé le 2026-09-11.** Les cinq lignes ci-dessous et ce qu'elles sont
devenues — trois corrigées, une écrite plutôt que codée, une refusée faute de
preuve.

- ~~`GET /v1/quotes` et `GET /v1/invoices` n'ont **ni filtre ni pagination**~~ —
  fait. `state` / `after` / `limit` (défaut 50, plafond 200) sur les deux, sur
  la forme de `GET /v1/employees`. Le curseur des devis est un UUID comparé sur
  la paire `(issued_at, id)` dont l'ordre est fait ; celui des factures est le
  **numéro**, parce que le numéro *est* l'ordre. `outstanding_minor` reste
  calculé sur le registre entier et jamais sur la page : un total qui rétrécit
  quand on pagine est le mauvais chiffre sous le bon nom.
- ~~`Risk` n'a que trois crans~~ — **pas de quatrième cran**, et c'est la
  décision. On n'a trouvé que deux outils dans le cas « sort sans écrire »
  (`integrations_discover`, déjà classé `Write`, et `knowledge_search`, resté
  `Read`) ; deux ne valent pas un cran qu'il faudrait ensuite trancher pour 116
  outils. Et le cran serait le mauvais outil : « ça sort » est un axe
  *orthogonal* au risque, que MCP appelle déjà `openWorldHint`, donc la vraie
  suite est un booléen à côté de `Risk` et non une valeur dedans. La règle est
  écrite à la place, dans la doc de `Risk` (`crates/app/src/mcp_server.rs`) :
  ce qui départage les trois crans, et où tombent les cas limites.
- ~~`echo_url` est `Option` dans le type et obligatoire dans le gestionnaire~~ —
  fait, le type dit la vérité. Le code d'erreur d'un corps absent, vide ou mal
  formé reste `no_echo_url` et non un 400 de désérialisation, avec un test qui
  le tient.
- ~~Le Postgres local diverge de la CI ; deux tests de gate rougissent ici~~ —
  **non reproduit**, donc rien n'a été changé. Mesuré base vierge, base
  partagée, seuls et en compagnie, sur Homebrew PG 17.11 : verts partout, et
  les 40 bases dérivées de cette machine sont intactes. Ce qu'il faut regarder
  en premier la prochaine fois est écrit dans `docs/OPERATIONS.md` §1.7.
- ~~Le plafond de corps de 1 Mio, dont trois surfaces se plaignent~~ — inchangé,
  et **dit une fois** : `docs/OPERATIONS.md` §1.4e³ donne le plafond, ce qu'il
  vaut en base64 (≈ 760 Kio de fichier réel) et pourquoi il ne se relève pas
  route par route — la couche est au-dessus de l'authentification, donc le
  plafond est ce qu'un appelant anonyme peut faire allouer.

---

## Phase 2 — Les leviers, par rentabilité décroissante

Chaque levier est jugé sur une seule question : **combien d'euros par euro
investi, à trois mois ?**

### 2.1 L'inbound : être cité par les modèles (GEO), puis référencé (SEO)
**Le levier le plus rentable de 2026 pour un produit d'API**, et le seul que
personne ne sait encore acheter. Quand un développeur demande à un modèle
« comment vérifier les conditions d'entrée d'un pays par API », la réponse cite
trois produits. Y être vaut plus que n'importe quelle campagne.

Ce que ça demande, et rien de plus : les questions que les gens posent
réellement, du contenu qui y répond mieux que la concurrence, publié sur un
domaine, et **une mesure** — sommes-nous cités, par quel modèle, sur quelle
question. La mesure est possible depuis le 2026-09-10 : notre navigateur sait
lire une page rendue en JavaScript.

*Pourquoi en premier* : coût marginal proche de zéro par article, effet
cumulatif, et c'est le seul canal où un petit acteur bat un gros à budget égal.

### 2.2 La prospection, à l'échelle
Elle existe de bout en bout et n'a jamais tourné. Avant d'en écrire une ligne
de plus : la faire tourner une semaine, mesurer taux d'ouverture, de réponse,
de rendez-vous. **Ensuite** seulement, l'enrichissement et la qualification.

### 2.3 Le social
`apps/social` est un agrégateur abouti, hors du produit. Le rattacher — un
locataire branche ses comptes, ses employés publient — est du câblage, pas de
la conception.

### 2.4 Les appels
L'adaptateur Twilio est réel et mocké en production. Le levier est vrai mais il
vient après : un appel coûte cher, et il ne sert qu'à des prospects déjà
qualifiés par les trois canaux au-dessus.

### 2.5 L'entreprise qui améliore son propre code
Le connecteur GitHub est au catalogue. C'est le levier le plus spectaculaire et
le plus risqué ; il n'a de sens qu'une fois le reste stable.

---

## Ce que ce document refuse

- **Tout coder en parallèle.** Sept chantiers simultanés ont produit, le
  2026-09-10, cinq déploiements rouges dont aucun ne portait un défaut du
  produit. La couture coûte plus que l'écriture.
- **Ajouter avant de mesurer.** Chaque levier de la phase 2 attend un chiffre
  de la semaine précédente. Une entreprise qui ne mesure pas ne scale pas, elle
  grossit.
- **Promettre le ×10 par le code.** Le code rend le ×10 possible ; ce qui le
  produit est une clé d'API, une semaine de prospection réelle, et dix articles
  qu'un modèle cite.
