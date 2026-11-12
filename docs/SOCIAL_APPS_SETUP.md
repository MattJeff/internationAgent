# Brancher les apps sociales — relevé du 2026-11-10

La carte des revues (ce que chaque portail débloque, et ce qu'il ne
débloque pas) reste dans `docs/SOCIAL.md`, § « Les revues d'app ». Cette
page est le geste qui a marché ce jour-là pour `apps/social` (binaire
`agentos-social`), vérifié contre `main.rs`, `oauth_flux.rs` et les
adaptateurs. Aucun secret ne vit ici : les identifiants publics non plus,
seulement les noms de variables.

Le déploiement local de ce jour-là écoute sur `127.0.0.1:8791`. Un tunnel
cloudflared rend cette boucle joignable en
`https://social-local.orizn.app`.

## Un seul callback, recopié tel quel

Toutes les plateformes reviennent sur la même route, `GET /oauth/callback`
(`main.rs`). L'URI que le binaire met dans l'URL d'autorisation est
construite une fois :

```text
{SOCIAL_PUBLIC_URL sans slash final}/oauth/callback
```

(`Etat::redirect_uri` retire les `/` finaux de `SOCIAL_PUBLIC_URL`, puis
ajoute `/oauth/callback`). Le `state` distingue le tenant et la plateforme ;
l'URI, elle, ne change pas. En local, avec
`SOCIAL_PUBLIC_URL=https://social-local.orizn.app`, chaque app officielle
enregistre exactement :

```text
https://social-local.orizn.app/oauth/callback
```

Le tunnel pointe vers `127.0.0.1:8791`, qui est le `SOCIAL_BIND` par défaut.
L'URI enregistrée est celle que le binaire envoie, pas le `Host` vu par le
navigateur : si `SOCIAL_PUBLIC_URL` dit autre chose que l'origine du tunnel,
le portail et le binaire ne parlent plus de la même redirection. LinkedIn,
dans ce cas, répond « redirect_uri does not match ». Les autres portails
comparent aussi à l'octet près (schéma, hôte, chemin, pas de slash final
sur `/oauth/callback`).

Sans `SOCIAL_PUBLIC_URL`, le binaire retombe sur `http://{SOCIAL_BIND}` —
`http://127.0.0.1:8791/oauth/callback`. Ce n'est pas une URI qu'un portail
accepte à la place du tunnel.

## Une paire par réseau, pour tout le service

Les credentials client se lisent au démarrage, une paire par réseau, sur le
processus entier — pas par tenant (`credentiels_env` dans `main.rs`, champs
de `Etat`) :

| Réseau des tables | Variables | Ce que la valeur est, côté portail |
|---|---|---|
| `x` | `SOCIAL_X_CLIENT_ID`, `SOCIAL_X_CLIENT_SECRET` | client OAuth 2.0 confidentiel |
| `linkedin` | `SOCIAL_LINKEDIN_CLIENT_ID`, `SOCIAL_LINKEDIN_CLIENT_SECRET` | l'app membre (voir plus bas) |
| `instagram` | `SOCIAL_META_CLIENT_ID`, `SOCIAL_META_CLIENT_SECRET` | l'Instagram App ID, pas l'App ID Meta |
| `tiktok` | `SOCIAL_TIKTOK_CLIENT_ID`, `SOCIAL_TIKTOK_CLIENT_SECRET` | le `client_key` du portail |
| `youtube` | `SOCIAL_GOOGLE_CLIENT_ID`, `SOCIAL_GOOGLE_CLIENT_SECRET` | le client Web du projet Google |

Les deux valeurs ou aucune. Une seule des deux désactive OAuth pour ce
réseau et laisse un avertissement dans les logs ; `account_connect_url`
répond alors `oauth_non_configure` en nommant le préfixe
(`SOCIAL_META` pour Instagram, `SOCIAL_GOOGLE` pour YouTube, sinon
`SOCIAL_{PLATEFORME}`).

**Conséquence, et limite connue.** Ces paires ne sont pas dans une table.
Tous les tenants de ce processus consentent devant la même app : changer
une paire change l'écran de consentement (nom, logo, domaine) pour tout le
monde, au prochain `account_connect_url`. Les jetons d'accès déjà scellés
continuent de servir les appels — ils partent en Bearer, sans le secret
client — jusqu'à leur échéance. Le rafraîchissement, lui, présente la paire
du processus (`mcp::jeton_rafraichi`) : X, YouTube et TikTok ne rafraîchissent
pas un jeton émis par l'ancienne app ; Instagram rafraîchit le jeton long
sans renvoyer le secret (`ig_refresh_token`) ; LinkedIn ne rafraîchit pas
(`RafraichissementIndisponible`, avant tout réseau) et un humain re-consent
à l'échéance. Des credentials d'app par tenant sont un travail possible,
pas fait : aucune colonne ne les porterait aujourd'hui.

Le fichier qui porte ces valeurs reste hors du dépôt. La veille le connaît
déjà : `$AGENTOS_CE_SOIR_ETAT/social.env`, défaut
`~/.agentos-ce-soir/social.env` (`scripts/ce-soir.sh`). Mode `600`. Le
copier avant de l'éditer. `.env.example` ne contient que les noms, vides.
Un jeton de tenant (`mint-tenant`), un client secret, un secret de tunnel
n'entrent dans aucun fichier du dépôt.

## LinkedIn — le profil, puis la Page qui ne tient pas sur la même app

Portail : `https://www.linkedin.com/developers/apps`.

**Profil personnel.** L'app qui poste au nom du membre porte deux produits
self-serve, onglet Products, sans revue :

* « Sign In with LinkedIn using OpenID Connect » — sans lui, pas de
  `GET /v2/userinfo`, pas d'URN d'auteur ;
* « Share on LinkedIn » — `w_member_social`.

C'est exactement `LINKEDIN_SCOPES` : `openid profile w_member_social`. La
paire va dans `SOCIAL_LINKEDIN_CLIENT_ID` / `SOCIAL_LINKEDIN_CLIENT_SECRET`.
`SOCIAL_LINKEDIN_ORG_POSTING` reste vide sur cette app.

**Pages.** `w_organization_social` (le drapeau
`SOCIAL_LINKEDIN_ORG_POSTING`) vient du produit « Community Management
API ». LinkedIn veut ce produit seul sur son app : ajouter « Sign In with
LinkedIn using OpenID Connect » à une app où Community Management a été
demandé est refusé, et l'autorisation sort en `unauthorized_scope_error`.
L'app Pages se prépare donc à part. La marche constatée le 2026-11-10 :

1. Un administrateur de la Page vérifie l'app (Settings > Verify, l'URL
   que LinkedIn génère).
2. Un code arrive sur l'e-mail professionnel.
3. Accepter les conditions de l'API.
4. Déposer le formulaire d'accès Development Tier.
5. Le palier Standard, plus tard, demande un enregistrement d'écran et des
   identifiants de test. Ce n'est pas le palier du jour un.

**Ce que le binaire fait, et pourquoi le drapeau ne suffit pas.** Il n'a
qu'une paire LinkedIn. `SOCIAL_LINKEDIN_ORG_POSTING` (`1`, `true`, `yes`
ou `on`) ne sélectionne pas une autre app : `account_connect_url` appelle
`demarrer_page` au lieu de `demarrer`, et la seule chose qui change est la
chaîne de scopes, qui devient `LINKEDIN_SCOPES_ORG` —
`openid profile w_member_social w_organization_social`. Au retour, le
callback identifie toujours le membre par `GET /v2/userinfo` (donc
`openid`), puis `organizationAcls?q=roleAssignee` liste les pages, et
chaque page est une ligne de plus scellée avec le même jeton
(`retour_oauth` dans `main.rs`). Rôles gardés : `ADMINISTRATOR` et
`CONTENT_ADMIN`.

Aucune des deux apps ne peut honorer cette chaîne :

* l'app membre a `openid profile w_member_social` et pas
  `w_organization_social` — le drapeau allumé demande un scope que l'app
  n'a pas ;
* l'app Pages a Community Management et ne peut pas recevoir `openid` /
  `profile` — le drapeau les demande quand même, et le callback refuse
  d'enregistrer le compte si `/v2/userinfo` échoue
  (« identite du compte introuvable »), avant toute ligne de page.

Publier sur une Page demanderait une seconde paire, lue comme les autres
(les deux valeurs ou aucune), utilisée seulement pour la connexion
organisation. Le callback actuel ne sait pas s'en servir : il n'enregistre
rien sans l'identité OpenID, et les lignes de page sont des handles en plus
sur le jeton du membre, pas un second client. Ce n'est pas implémenté. Tant
que ça ne l'est pas, le drapeau reste vide et la publication membre passe
par l'app OpenID + Share on LinkedIn.

Le Community Management de la messagerie (`w_member_social_feed`,
commentaires et likes, § du même nom dans `docs/SOCIAL.md`) est le même
produit, donc la même contrainte d'app seule. Ce n'est pas le scope que le
drapeau demande.

## Google / YouTube

Portail : `https://console.cloud.google.com`. Les variables sont
`SOCIAL_GOOGLE_*` parce que le client vit dans ce projet, pas sur un
portail YouTube.

* Client OAuth de type **Application Web**. Le flux est celui cité en tête
  de `oauth_flux.rs` (web-server) : `client_id` et secret dans le corps du
  jeton, `redirect_uri` en https. `access_type=offline` et `prompt=consent`
  sont ajoutés par le binaire, pour qu'une reconnexion ré-émette un refresh
  token.
* Activer **YouTube Data API v3** dans le même projet. L'identité du compte
  est `GET /youtube/v3/channels?part=snippet&mine=true`. L'API absente, cet
  appel répond 403 : l'échange du code a pu réussir, et le callback s'arrête
  quand même. La page dit « Connexion refusee : identite du compte
  introuvable : la plateforme a refusé (statut 403) ». Aucune ligne n'est
  écrite. On reconnecte après avoir activé l'API.
* Tant que l'écran de consentement est en **Testing**, chaque compte Google
  qui doit se connecter est ajouté comme utilisateur de test. Sinon Google
  refuse par `access_denied` (403). Si le refus revient jusqu'au callback,
  la page dit « Connexion refusee : access_denied ».
* L'écran de consentement affiche le domaine du callback. Avec
  `social-local.orizn.app`, c'est `orizn.app`.
* Plusieurs chaînes : on recommence le flux de connexion, une fois par
  identité Google (un compte de marque est une autre identité à
  l'écran de consentement). Le binaire ne garde que `items[0]` — le titre
  (`snippet.title`) comme handle, l'id `UC…` comme id plateforme. Une
  réponse qui listerait plusieurs chaînes n'en enregistre qu'une. Deux
  chaînes au même titre se heurtent à `UNIQUE (tenant_id, platform, handle)`
  et la seconde reconnexion écrase le jeton de la première.
* En Testing, le refresh meurt en sept jours (déjà dans `docs/SOCIAL.md`).
  `oauth_flux.rs` cite aussi la limite de 100 refresh tokens par compte
  Google et par `client_id` : le plus ancien meurt en silence.

Les vidéos déposées par `videos.insert` depuis un projet non audité restent
en visibilité privée. L'audit YouTube est l'autre verrou, indépendant de
l'écran de consentement — le détail est dans `docs/SOCIAL.md`.

## Meta / Instagram — Instagram Login, et le bon identifiant

Le chemin du code est « Instagram API with Instagram Login »
(`adapters/instagram.rs`, `oauth_flux.rs`) : autorisation
`https://www.instagram.com/oauth/authorize`, échange
`POST https://api.instagram.com/oauth/access_token`, puis le jeton long sur
`graph.instagram.com`. Aucun appel ne part vers l'OAuth Facebook. Les scopes
partent séparés par des virgules : `INSTAGRAM_SCOPES`
(`instagram_business_basic`, `instagram_business_content_publish`,
`instagram_business_manage_comments`, `instagram_business_manage_messages`).

L'URI de redirection s'ajoute dans les réglages **Instagram Login** de
l'app Meta (Business login settings), pas seulement dans Facebook Login.
Absente de là, la page `instagram.com/oauth/authorize` reste blanche, sans
message, et le callback du service ne voit rien : le navigateur n'y arrive
pas.

La paire que le binaire envoie s'appelle `SOCIAL_META_CLIENT_ID` /
`SOCIAL_META_CLIENT_SECRET`. Le nom dit Meta parce que l'app se crée sur
`developers.facebook.com` (`main.rs` : nommer la variable d'après Instagram
enverrait chercher un portail qui n'existe pas). La valeur que cette
autorisation attend est l'**Instagram App ID** et l'**Instagram App Secret**
des réglages Instagram Login (Instagram > API setup with Instagram login >
Business login settings) — la doc business-login citée en tête de
`oauth_flux.rs` appelle ainsi le `client_id` de
`https://www.instagram.com/oauth/authorize`. Le binaire copie la variable
telle quelle : `client_id` dans l'URL et dans le corps du jeton,
`client_secret` dans ce corps puis dans l'échange du jeton long. L'App ID
affiché dans le bandeau Basic de l'app est un autre numéro. Rien dans
l'adaptateur ne distingue les deux : poser le numéro du bandeau, c'est
envoyer à Instagram Login un `client_id` qui n'est pas le sien. Il n'existe
pas de seconde paire dans le code.

Le jour un sans revue reste celui de `docs/SOCIAL.md` : un rôle sur l'app
pour le compte qui publie. `SOCIAL_PUBLIC_URL` doit être joignable par
Instagram, qui tire les médias sur `GET /medias/{digest}`.

## X

Un client OAuth 2.0 confidentiel sur `https://console.x.com`. La paire va
dans `SOCIAL_X_CLIENT_ID` / `SOCIAL_X_CLIENT_SECRET`. Le binaire
s'authentifie en Basic sur `POST https://api.x.com/2/oauth2/token` (le
secret n'est pas dans le corps) et envoie quand même PKCE `S256`. Les
scopes (`X_SCOPES`) : `tweet.read tweet.write users.read offline.access
media.write dm.read dm.write like.write bookmark.write`. Même callback que
les autres. Pas de revue ; des crédits. Le prix et le détail sont dans
`docs/SOCIAL.md`.

## TikTok

Au 2026-11-10 l'app est en revue. Le binaire est prêt pour le jour où elle
passe : `SOCIAL_TIKTOK_CLIENT_ID` reçoit le `client_key` du portail (le
paramètre d'autorisation s'appelle `client_key`, jamais `client_id`),
`SOCIAL_TIKTOK_CLIENT_SECRET` le secret. Scopes, virgules :
`user.info.basic,video.list,video.publish,video.upload`. Le callback est le
même, en https. Tant que la revue n'est pas passée, les limites Sandbox et
`SELF_ONLY` de `docs/SOCIAL.md` tiennent.

## Relancer

Le binaire lit l'environnement au démarrage et ne le relit pas. Éditer
`social.env` ne change rien pour le processus déjà là.

1. Copier le fichier, puis l'éditer. `chmod 600` sur le fichier vivant.
2. Tuer le processus `agentos-social`.
3. Le relancer avec le fichier sourcé. La veille de `scripts/ce-soir.sh` le
   fait toute seule quand plus rien n'écoute sur 8791, et elle source
   `$ETAT/social.env` au moment du lancement — le fichier doit déjà être le
   bon avant le kill. À la main, depuis le dépôt :

```bash
ETAT="${AGENTOS_CE_SOIR_ETAT:-$HOME/.agentos-ce-soir}"
set -a
. "$ETAT/social.env"
set +a
./target/debug/agentos-social
```

4. Vérifier l'écoute. `GET http://127.0.0.1:8791/livez` rend le texte `ok`.
   `lsof -nP -iTCP:8791 -sTCP:LISTEN` montre le processus. Le défaut de
   `SOCIAL_BIND` est `127.0.0.1:8791` ; un autre bind se vérifie sur le port
   qu'il nomme, et le tunnel doit viser le même.

Le service `social` de `docker-compose.yml` lit les mêmes noms, au
démarrage du conteneur. Recréer le conteneur est l'équivalent du kill pour
ce chemin-là. Le branchement du 2026-11-10 est le binaire et `social.env`,
pas le compose.

## Ce que les sièges voient

Le locataire est branché comme les autres connecteurs (`docs/SOCIAL.md`,
« Comment un locataire publie ») : `integrations_connect` avec
`connector: "custom"`, le handle **`social`** — c'est le nom que
`apps/server/src/routes/social.rs` cherche — et l'URL
`http://127.0.0.1:8791/mcp`. C'est le MCP d'édition du service. `/mcp/messagerie`
n'est pas cette URL.

Les outils de publication sont déclarés `destructive`
(`integrations_declare_tool`, au digest lu par `integrations_discover`).
Un appel destructif attend un humain avant de partir : chaque publication
est validée. Côté produit, la
table des employés dit déjà la même chose pour `social_post_publish` et
`social_thread_publish` (`Risk::Destructive` dans
`crates/app/src/mcp_tools/social.rs`). `social_calendar_remove` est
destructif aussi : il retire un créneau, il ne publie pas. Un outil que
personne n'a déclaré est traité comme destructif puis refusé
(`403 tool_not_declared`) — le déclarer est ce qui laisse l'appel arriver
jusqu'à l'humain.

`approval_decide` est dans la table MCP du service (nom
`approval_decide` ; le produit replie le souligné en `approval-decide`).
La route opérateur `POST /v1/social/approvals/decide` l'appelle. Il n'est
pas dans la table des employés — le test
`approuver_n_est_pas_un_outil_employe` tombe si un outil de cette table
décide. Le câblage du 2026-11-10 ne le donne pas aux sièges IA : un modèle
propose (`submit_for_approval` / `social_approval_propose`), il n'approuve
pas. `tools/list` sur `http://127.0.0.1:8791/mcp` le rend quand même,
parce que la route opérateur doit pouvoir l'appeler. Ne pas le déclarer
pour ces sièges.
