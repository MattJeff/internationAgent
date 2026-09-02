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
   humaine contresigne. Depuis la phase médias, l'empreinte est GLOBALE :
   texte + SHA-256 des octets de chaque média (téléchargés au moment de la
   preview), dans un ordre fixe, + sondage + made_with_ai. Une preview qui
   n'empreinterait que le texte laisserait changer l'image après contreseing ;
   le test le prouve — même clé, même texte, autre image → refus. Et
   `expected_media_digests` sur `post_publish` compare terme à terme les
   octets réellement téléchargés à ceux contresignés (`media_change` sinon,
   AVANT de consommer la clé d'idempotence).
4. **Table d'outils stable et versionnée.** Le pin SHA-256 du runtime fige un
   schéma : la table porte une version, et un test recalcule l'empreinte des
   schémas — changer un schéma sans bumper la version fait échouer le test.

## Le contrat des six outils — et pas un de plus

| Outil | Entrée | Sortie |
|---|---|---|
| `accounts_list` | `{}` | comptes connectés (plateforme, handle, état) |
| `account_connect_url` | `{ platform }` | l'URL d'autorisation OAuth à ouvrir (retour : `GET /oauth/callback`) |
| `post_preview` | `{ account_id, text, media?, poll?, made_with_ai? }` | `{ rendered_text, digest, platform_limits_ok, cost_estimate, media[], verdicts[] }` — digest = empreinte globale ; un verdict par média (digest, taille, type détecté aux octets, limites) |
| `post_publish` | `{ idempotency_key, account_id, text, media?, poll?, made_with_ai?, expected_media_digests? }` | `{ post_id, platform_post_id, url }` — rejouable sans double ; `expected_media_digests` refuse (`media_change`) si les octets ne sont plus ceux contresignés |
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

## Périmètre, et il est fermé : X et LinkedIn — texte, médias, sondages

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

Les médias sont LÀ (phase 2 livrée — voir plus bas) : photos, vidéo,
sondages, et documents PDF côté LinkedIn, dans les ARGUMENTS de
`post_preview`/`post_publish` — table toujours à six outils, version bumpée
1 → 2. Meta/TikTok/Threads exigent des revues que seul le fondateur peut
déposer — la liste exécutable est ci-dessous, on ne les code pas
aujourd'hui.

## La seconde surface — `/mcp/messagerie`

L'éditeur (`/mcp`) ne peut atteindre personne qui n'a rien demandé —
`NoStrangers`, prouvé par un test qui lit sa table. La messagerie
(`/mcp/messagerie`) peut atteindre des gens : c'est son métier. Elle n'est
donc pas `NoStrangers` et ne le prétendra jamais — elle est `HeldHere` :
chaque premier contact passe la table des suppressions, chaque refus y entre
pour toujours, et `dm_open` est l'outil qu'une politique fait contresigner.
La garantie de l'éditeur survit à l'extension parce que les deux tables ne
partagent pas une ligne : même serveur, même jeton de tenant, mais SA table,
SA version (`VERSION_TABLE_MESSAGERIE`), SES empreintes — et un test croisé
qui fige l'empreinte de l'éditeur depuis la messagerie.

Quatorze outils (`apps/social/src/messagerie.rs`), tous servis par X au
palier pay-per-use, chaque endpoint/scope/prix relevé le 2026-09-02 :
`inbox_list` (0,010 USD/événement DM + 0,005/mention), `dm_reply` et
`dm_open` (0,015 chacun — DEUX outils parce que X en fait deux chemins d'API
distincts : répondre `POST /2/dm_conversations/{id}/messages`, initier
`POST /2/dm_conversations/with/{participant_id}/messages` ; un test fige que
le chemin de `dm_reply` ne tombe jamais dans `/with/`), `post_reply` (0,015 ;
0,200 avec URL), `post_comment` (chez X = `post_reply`, même endpoint),
`post_like`/`post_unlike` (0,015/0,010), `post_bookmark`/`post_unbookmark`
(0,005/0,010 — aucune ligne pricing propre au delete de bookmark relevée : on
rend la ligne « Interaction: Delete »), `post_repost` (0,015), `search_posts`
(0,005 PAR RÉSULTAT — jusqu'à 0,50 USD pour 100 résultats ; le retour porte
le coût réel constaté), `read_post` (0,005), `read_profile` (0,010),
`read_timeline` (0,005/post, plafond global 3 M lectures/cycle). Ce qui n'y
est pas est un choix cité : `post_quote` (Enterprise seulement chez X),
`dm_delete` (doc ambiguë v1.1/v2), DM de groupe (aucun besoin jour un).

* **La règle des suppressions** (`social_suppressions`, migration 0004) : X
  ne sert aucune liste d'opt-out — le refus n'est détectable qu'à l'envoi
  (403 « The recipient may have DM settings that prevent messages from
  unknown users, or may have blocked you », relevé 2026-09-02). Donc
  `dm_open` consulte la table AVANT tout appel réseau (un supprimé = refus
  nommé `destinataire_supprime`, compteur adaptateur à zéro — testé), et un
  403 de plateforme insère la ligne pour toujours. `dm_reply` n'est PAS gaté :
  répondre à qui a écrit en premier n'est pas un contact à froid. Aucun outil
  MCP ne lit ni n'écrit cette table : un agent n'efface pas la liste des gens
  qui ont dit non.
* **LinkedIn ne sert RIEN de cette table à un membre self-serve** : chaque
  outil rend `plateforme_ne_sert_pas` avec la citation datée du 2026-09-02 et
  le fait qui débloquerait (`apps/social/src/adapters/linkedin.rs`) — jamais
  un stub. Les conditionnels (`post_comment`, `post_like`, `read_timeline`)
  nomment le Community Management API ; le jour où la candidature est
  approuvée, l'adaptateur arrive SANS bump de la table d'outils.
* **Contenu de tiers** : tout texte rendu par `inbox_list`, `search_posts`,
  `read_post`, `read_profile`, `read_timeline` porte `third_party: true` —
  le runtime l'enveloppe en `Untrusted`, même discipline que les lectures
  GitHub du catalogue. Le service marque, il ne « nettoie » rien.
* **L'id plateforme** (migration 0005) : le `handle` X est le USERNAME, mais
  `/2/users/{id}/…` (mentions, likes, bookmarks, retweets) exige l'id
  NUMÉRIQUE — `/2/users/me` donne les deux au connect, on garde les deux. Un
  compte connecté avant 0005 (ou avant les scopes `dm.read dm.write
  like.write bookmark.write`) répond par une erreur nommée qui renvoie vers
  `account_connect_url` : un seul re-consentement humain répare les deux.

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
  users.read offline.access dm.read dm.write like.write bookmark.write`
  (les quatre derniers pour `/mcp/messagerie` ; un compte connecté avant
  leur ajout re-consent via `account_connect_url`).
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

### LinkedIn — Community Management API, la candidature (messagerie)

* **Portail** : https://www.linkedin.com/developers (Products → Community
  Management API, candidature avec revue).
* **Quoi** : demander l'accès qui délivre `w_member_social_feed` — le scope
  qu'exigent `POST /rest/socialActions/{urn}/comments` et
  `POST /rest/reactions` (learn.microsoft.com/increasing-access, ms.date
  2026-07-28, consulté 2026-09-02). Palier Development par défaut :
  500 appels/app/24 h, 100/membre/24 h.
* **Débloque** : `post_comment`, `post_like`/`post_unlike` et
  `read_timeline` (ses propres posts) côté LinkedIn sur `/mcp/messagerie` —
  les outils existent déjà, seul l'adaptateur change, sans bump de table.
  Gratuit : l'accès LinkedIn est gaté par programme, pas facturé.
* **Ne débloque PAS** : les DM (`POST /v2/messages` reste « restricted to
  approved partners » — accord partenaire ad hoc via le Developer Support
  Portal), la recherche, les bookmarks (l'API n'existe pas).
  **Délai : non publié par la doc.**

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

## Phase 2 — les médias sont livrés, le reste attend le fondateur

1. **Médias — LIVRÉ.** Les deux outils de post acceptent `media` (1–20 URLs
   https, avec `alt_text`/`title`), `poll` et `made_with_ai` ; `post_publish`
   accepte `expected_media_digests`. Le service TÉLÉCHARGE les médias
   lui-même (`apps/social/src/medias.rs`) et cette surface est vettée :
   https seul, IP publique seule (même discipline que `placement()` de
   `crates/app/src/mcp.rs` — plages privées, loopback, link-local,
   metadata cloud refusées), connexion épinglée sur l'IP vettée (anti
   DNS-rebinding), redirections coupées, plafond 512 MiB vérifié sur
   l'annonce ET compté en vol (un Content-Length menteur ne remplit pas la
   RAM), timeout 60 s, type détecté aux MAGIC BYTES (jpeg/png/gif/webp/mp4/
   pdf), jamais à l'extension ni au Content-Type. Chaque limite de
   plateforme vit dans son adaptateur, mot exact et chiffre cité de la doc
   officielle (relevée le 2026-09-02) : X — 5 MB image, 15 MB GIF, 4 photos
   OU 1 GIF OU 1 vidéo sans mélange, alt_text ≤ 1000, sondage 2–4 options de
   1–25 chars sur 5–10080 min, PDF refusé, upload chunké
   initialize→append→finalize→STATUS, 403 post-finalize géré ; LinkedIn —
   JPG/GIF/PNG (WEBP refusé), 1 ou 2–20 images (multiImage), altText ≤ 4086,
   vidéo MP4 75 KB–500 MB en parts de 4 MiB (ETags dans l'ordre), PDF
   ≤ 100 MB, sondage question obligatoire ≤ 140 / options ≤ 30 / durées
   ∈ {1440, 4320, 10080, 20160} min. L'historique (`posts_list`) rend les
   `media_digests` publiés — l'audit du contreseing, octet par octet.
   Restes nommés en `ponytail:` dans le code : vidéos X 8/16 GB (streaming
   vers l'upload chunké), PPT/PPTX/DOC/DOCX LinkedIn (magic bytes zip/OLE
   ambigus), frames/pixels/durée non vérifiés aux octets, GIF statique non
   distingué du GIF animé.
2. **Meta, TikTok, Threads** — après les revues ci-dessus (credentials et
   dépôts que seul le fondateur peut faire), chacune une plateforme de plus
   derrière les six mêmes outils, sans nouvel outil.

## L'entrée au catalogue — plus tard, et pourquoi

Le service n'a pas d'entrée dans `CATALOG` aujourd'hui, et c'est voulu :
chaque littéral du catalogue est resondé le jour de son écriture, et une
entrée `Dial` sur une URL qui ne répond pas encore violerait cette règle. Le
jour où `agentos-social` est DÉPLOYÉ et sondé, l'entrée aura cette forme :
`Provision::Dial` vers notre hôte, `Credential::Bearer` (le jeton par
tenant), `floor: RiskClass::Write` (publier engage l'entreprise, jamais
`Read` ; rien n'efface un compte, pas `Destructive`), et
`OptOuts::NoStrangers` — prouvé par le test anti-DM du service, une première
pour ce registre. La messagerie aura SA seconde entrée (`social-messagerie`,
`Dial` vers `/mcp/messagerie`, même jeton Bearer de tenant) : `floor:
RiskClass::Write` et `OptOuts::HeldHere` — la seule liste des refus est
`social_suppressions`, tenue chez nous, parce que X ne rend le refus d'un
destinataire qu'à l'envoi.
