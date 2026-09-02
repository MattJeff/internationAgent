# SOCIAL — notre agrégateur de publication sociale

Le service : `apps/social` (binaire `agentos-social`), un serveur MCP
Streamable HTTP qui publie sur les réseaux sociaux au nom d'un tenant.
L'équivalent d'Ayrshare/Blotato/Zernio, mais conçu pour des agents — et c'est
une catégorie, pas un slogan : chaque propriété « pour IA » est portée par un
test qui peut échouer.

## La thèse : le seul agrégateur où `NoStrangers` est vrai par construction

La sonde du 2026-09-02 (seize candidats, tous sondés en direct — le détail est
dans `docs/CATALOGUE.md`, « La vague réseaux sociaux du 2026-09-02 », et dans
les entrées de `crates/app/src/catalog.rs`) a établi le fait fondateur :
**aucun des trois agrégateurs du catalogue n'a pu recevoir
`OptOuts::NoStrangers`**, parce que tous exposent des messages privés :

* **Ayrshare** — 27 outils lus en direct, dont `send_message` et
  `get_messages` : des DM Facebook/Instagram/X/WhatsApp vers un destinataire
  que l'appelant fournit. Aucune liste d'opt-out chez le fournisseur (index
  complet des docs, 218 pages, négatif) → `HeldHere`.
* **Blotato** — 35 outils, dont `blotato_send_message` (DM
  Instagram/Facebook ; les docs disent « reply only », le schéma prend un
  `recipientId` libre). Lecture opt-out négative → `HeldHere`.
* **Zernio** — 52 outils sondés, mais `search_tools`/`call_tool` atteignent
  496 outils au total, dont DM, WhatsApp, SMS et Broadcasts — `call_tool`
  défait même la promesse du pin par-outil. → `Pulled { from: "GET
  /v1/sms/opt-outs" }`.

Un post PUBLIC ne met pas un message devant une personne qui n'a rien
demandé : les abonnés ont choisi de suivre. `NoStrangers` peut donc être
honnête pour un outil de publication — mais seulement si le serveur ne sait
PAS envoyer de message privé. Le nôtre ne saura pas, par construction : la
table d'outils ne contient aucune surface DM, et un test lit cette table et le
source pour que ce soit vérifiable et pas promis. Ce sera la première entrée
`NoStrangers` du registre dont la revendication est PROUVÉE par un test du
service lui-même, pas seulement par une lecture datée de la liste d'outils
d'un tiers.

## Les quatre propriétés « pour IA », et le test qui porte chacune

1. **Aucun DM, jamais.** Pas d'outil `message`/`dm`/`broadcast`, ni
   aujourd'hui ni par régression. Le test a la même forme que
   `packages/docker-mcp/test/forbidden.test.js` : il lit la table d'outils
   nom par nom (ajouter un outil casse le test), il passe le source au crible
   d'expressions interdites (commentaires retirés — les commentaires ont le
   droit de nommer ce qu'ils refusent), et il vérifie que chaque expression
   interdite reconnaît bien un extrait hostile — un test qui ne peut pas
   échouer est pire que pas de test.
2. **Idempotent.** Un agent qui retente un tour ne double-poste pas :
   `idempotency_key` est OBLIGATOIRE sur `post_publish`, la clé est unique en
   base (contrainte, pas code applicatif), et un rejeu rend le même `post_id`
   sans republier. Le test publie deux fois avec la même clé et vérifie une
   seule ligne, un seul appel plateforme.
3. **Prévisualisable.** `post_preview` rend le contenu EXACT qui partirait,
   plus son empreinte SHA-256 — c'est cette empreinte qu'une approbation
   humaine contresigne. Le test vérifie que le digest de la preview est le
   hash de ce que `post_publish` enverrait pour le même texte.
4. **Table d'outils stable et versionnée.** Le pin SHA-256 du runtime fige un
   schéma : la table porte une version, et un test recalcule l'empreinte des
   schémas — changer un schéma sans bumper la version fait échouer le test.

## Le contrat des six outils — et pas un de plus

| Outil | Entrée | Sortie |
|---|---|---|
| `accounts_list` | `{}` | comptes connectés (plateforme, handle, état) |
| `account_connect_url` | `{ platform }` | l'URL d'autorisation OAuth à ouvrir (retour : `GET /oauth/callback`) |
| `post_preview` | `{ account_id, text }` | `{ rendered_text, digest, platform_limits_ok, cost_estimate }` |
| `post_publish` | `{ idempotency_key, account_id, text }` | `{ post_id, platform_post_id, url }` — rejouable sans double |
| `post_metrics` | `{ post_id }` | impressions/likes/reposts si la plateforme les sert — et quand elle ne les sert pas (LinkedIn membre), l'outil LE DIT au lieu de rendre des zéros |
| `posts_list` | `{ limit? }` | l'historique du tenant |

Transport : `POST /mcp` (JSON-RPC 2.0 : `initialize`, `tools/list`,
`tools/call`), `GET /livez`. Auth : `Authorization: Bearer <jeton par
tenant>` ; table `social_tenants` (id, label, `token_hash` = SHA-256 du
jeton, comparé en temps constant, jamais le jeton en clair) ; un jeton se
frappe par `agentos-social mint-tenant <label>`, pas par une route. Base
Postgres SÉPARÉE (`SOCIAL_DATABASE_URL`, migrations dans
`apps/social/migrations/`) — ce service est un produit vendable seul, il ne
partage pas la base du runtime. Jetons de plateforme scellés en AES-256-GCM
sous `SOCIAL_MASTER_KEY`, AAD `social://<tenant>/<platform>/<account>` —
même discipline que `crates/app/src/mcp.rs` sur
`crates/providers/src/secrets.rs` : un chiffré déplacé ne déchiffre rien.

## Périmètre jour un, et il est fermé : X et LinkedIn, texte seul

Les deux seules plateformes en libre-service — aucune revue d'app entre le
fondateur et le premier post :

* **X** — `POST /2/tweets`, contexte utilisateur OAuth 2.0. Le document
  RFC 8414 d'`api.x.com` annonce `token_endpoint_auth_methods_supported:
  ["none", "client_secret_basic"]` (sondé 2026-09-02) : le client
  confidentiel passe. Pas d'enregistrement dynamique (`POST
  /2/oauth2/register` → 404) : l'app vient du portail développeur, où la
  redirect URI est librement enregistrable. Coût mesuré : **0,015 USD par
  post créé**, pay-per-usage à crédits, sans abonnement
  (docs.x.com/x-api/getting-started/pricing.md, relu 2026-09-02).
* **LinkedIn** — `POST /rest/posts`, versionné par l'en-tête
  `LinkedIn-Version`, scope `w_member_social`, publication sur le profil du
  membre. Le produit « Share on LinkedIn » est self-serve : onglet Products
  de l'app, sans revue (learn.microsoft.com, Share on LinkedIn, relu
  2026-09-02 ; limites : 150 requêtes/jour/membre, 100 000/jour/app).
  **Aucune analytics membre n'existe** (sonde 2026-09-02) : `post_metrics`
  répond « la plateforme ne les sert pas » au lieu de zéros — les analytics
  d'organisation sont derrière le Marketing API Program, hors périmètre.

Texte seul : les médias (images/vidéo) sont une phase 2 nommée, pas un début
d'implémentation. Meta/TikTok/Threads exigent des revues que seul le
fondateur peut déposer — la liste exécutable est ci-dessous, on ne les code
pas aujourd'hui.

## Les revues d'app — la part que seul le fondateur peut faire

Chaque ligne : le portail, ce qu'on demande, ce que ça débloque, le délai
quand la doc le donne. Faits repris de la sonde du 2026-09-02
(`catalog.rs`, `CATALOGUE.md`) et complétés par lecture des docs officielles
le 2026-09-02.

### X — pas une revue, un compte à créditer (jour un)

* **Portail** : https://console.x.com (Developer Console).
* **Quoi** : créer le projet/app ; configurer le client OAuth 2.0
  **confidentiel** (`client_secret_basic` accepté — RFC 8414 d'`api.x.com`,
  2026-09-02) ; enregistrer la redirect URI (libre — pas le piège Canva) ;
  poser la paire client dans la config du service (`SOCIAL_X_CLIENT_ID` /
  `SOCIAL_X_CLIENT_SECRET`) ; acheter des crédits (pay-per-usage, aucun
  abonnement). Scopes demandés par le service : `tweet.read tweet.write
  users.read offline.access`.
* **Débloque** : la publication immédiatement — aucune revue.
* **Coût** : 0,015 USD/post créé ; 0,200 USD/post avec URL ; lectures de
  posts 0,005 USD/ressource (pricing.md, 2026-09-02). **Délai : aucun.**

### LinkedIn — un produit à cocher (jour un)

* **Portail** : https://www.linkedin.com/developers/apps.
* **Quoi** : créer l'app (adossée à une Page LinkedIn), onglet **Products**,
  ajouter « **Share on LinkedIn** » → accorde `w_member_social`
  (learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/share-on-linkedin,
  2026-09-02). Ajouter « Sign In with LinkedIn using OpenID Connect » pour
  récupérer l'URN de la personne : le service demande les scopes
  `openid profile w_member_social` et lit `GET /v2/userinfo` (`sub` → l'URN
  d'auteur `urn:li:person:{sub}`) — sans ce produit, le callback OAuth ne
  peut pas nommer le compte. La paire client va dans
  `SOCIAL_LINKEDIN_CLIENT_ID` / `SOCIAL_LINKEDIN_CLIENT_SECRET`.
* **Débloque** : la publication sur le profil du membre authentifié.
  Self-serve, **sans revue. Délai : aucun.**
* **Ne débloque PAS** : les analytics (membre : inexistantes ; organisation :
  Marketing API Program, une candidature séparée avec revue).

### Meta (Pages + Instagram) — Advanced Access (phase 2)

* **Portail** : https://developers.facebook.com (App Review → Permissions
  and Features → Advanced Access).
* **Quoi** : demander, pour publier au nom de tiers via Facebook Login :
  `pages_manage_posts` (+ ses dépendances `pages_read_engagement`,
  `pages_show_list`) pour les Pages, et `instagram_basic` +
  `instagram_content_publish` pour Instagram ; la voie Instagram Login
  demande `instagram_business_basic` + `instagram_business_content_publish`
  (developers.facebook.com/docs/instagram-platform/content-publishing et
  /docs/permissions, 2026-09-02).
* **La revue exige** : une URL de politique de confidentialité, une vidéo de
  démo (screencast montrant chaque permission en usage — « provide specific
  examples of why your app needs to create or manage posts on behalf of
  other users »), et la vérification business de l'entreprise.
* **Débloque** : publier pour des comptes qui n'ont aucun rôle sur notre
  app. **Délai : non publié par la doc** ; la sonde note seulement que la
  revue « impose son délai avant de publier pour un tiers ».

### TikTok — l'audit qui lève SELF_ONLY (phase 2)

* **Portail** : https://developers.tiktok.com.
* **Quoi** : enregistrer l'app, ajouter la **Content Posting API** (Direct
  Post activé), obtenir le scope `video.publish` — puis demander **l'audit**
  du client : « All content posted by unaudited clients will be restricted
  to private viewing mode » — c'est le `SELF_ONLY` de la sonde — et « your
  API client must undergo an audit to verify compliance with our Terms of
  Service » (doc Content Posting API, get-started, 2026-09-02).
* **Débloque** : des posts publics pour des comptes tiers ; sans audit,
  l'app ne poste qu'en privé pour son propre compte de test.
  **Délai : non publié par la doc.**

### Threads — cinq scopes et une revue (phase 2)

* **Portail** : https://developers.facebook.com (docs/threads).
* **Quoi** : les cinq scopes exacts — `threads_basic` (requis partout),
  `threads_content_publish`, `threads_manage_replies`,
  `threads_read_replies`, `threads_manage_insights`
  (developers.facebook.com/docs/threads/get-started, 2026-09-02).
* **La revue** : les testeurs déclarés fonctionnent sans revue ; pour tout
  autre utilisateur, « each permission must first be approved through the
  App Review process, and your app must be published ».
* **Débloque** : publier sur Threads pour des tiers.
  **Délai : non publié par la doc.**

## Phase 2, nommée

1. **Médias** — images puis vidéo. LinkedIn : register/upload d'asset avant
   le post ; X : upload média puis attache. Rien de tout cela n'est commencé.
2. **Meta, TikTok, Threads** — après les revues ci-dessus, chacune une
   plateforme de plus derrière les six mêmes outils, sans nouvel outil.

## L'entrée au catalogue — plus tard, et pourquoi

Le service n'a pas d'entrée dans `CATALOG` aujourd'hui, et c'est voulu :
chaque littéral du catalogue est resondé le jour de son écriture, et une
entrée `Dial` sur une URL qui ne répond pas encore violerait cette règle. Le
jour où `agentos-social` est DÉPLOYÉ et sondé, l'entrée aura cette forme :
`Provision::Dial` vers notre hôte, `Credential::Bearer` (le jeton par
tenant), `floor: RiskClass::Write` (publier engage l'entreprise, jamais
`Read` ; rien n'efface un compte, pas `Destructive`), et
`OptOuts::NoStrangers` — prouvé par le test anti-DM du service, une première
pour ce registre.
