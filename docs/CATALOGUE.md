# Le catalogue des connecteurs — ce qui est branchable, et ce qui ne l'est pas

Une soixantaine d'applications qualifiées les 2026-08-30 et 2026-08-31, **en
sondant les serveurs en direct** — `initialize`, `WWW-Authenticate`,
`.well-known` — et non en lisant des annonces. Ce document existe pour qu'on
ajoute les entrées une par une sans refaire la mesure, et surtout pour qu'on ne
réessaie pas ce qui est fermé.

Le catalogue lui-même est `crates/app/src/catalog.rs`. Une entrée y est une
**affirmation** : sur l'adresse, sur ce que le connecteur sait faire, et sur qui
il peut atteindre. Ce document est ce qui adosse chaque affirmation à une
mesure.

## Les cinq murs

Ce ne sont pas des préférences, ce sont des propriétés du code. Les connaître
explique 90 % des refus ci-dessous.

1. **Streamable HTTP uniquement** (`mcp.rs`, `StreamableHttpClientTransport`).
   Le vieux transport HTTP+SSE à deux endpoints est hors jeu. stdio impose
   `Provision::Host`, c'est-à-dire un paquet **npm** épinglé qu'on fait tourner
   soi-même.
2. **`Dial` exige https et une IP globalement routable** (`resolve_and_vet`). Un
   serveur « desktop » sur `127.0.0.1` est inatteignable depuis un VPS.
3. **OAuth exige un client confidentiel** — `client_id` **et** `client_secret`.
   `OauthClients::parse` refuse un secret vide. Un fournisseur qui n'émet que des
   clients publics (`token_endpoint_auth_methods_supported: ["none"]`) est fermé.
4. **L'indicateur `resource` (RFC 8707) n'est jamais envoyé.** C'est le risque
   résiduel de tout serveur dont l'autorité sert plusieurs ressources.
5. **Une seule URL de retour** pour tout le déploiement :
   `https://siglair.com/v1/mcp/oauth/callback`.

### Le mur n°3 est plus perméable qu'il n'y paraît

Il interdit l'enregistrement dynamique **au moment de l'appel**. Il n'interdit
pas un `curl` fait **une fois, à la main**, sur le `registration_endpoint` d'un
serveur — plusieurs rendent alors un `client_secret` **permanent**
(`client_secret_expires_at: 0`) qu'on colle dans `AGENTOS_OAUTH_CLIENTS`. C'est
une étape d'exploitation, pas du code, exactement comme « créer une app dans une
console ».

Sept serveurs rendent une telle paire : Notion, Canva, Atlassian, monday,
Granola, Higgsfield, Magnific. **Deux la font expirer** : Linear et Sentry à
90 jours, Plaud à 30 — une rotation que rien dans le produit ne rappelle
aujourd'hui.

## Comment lire un verdict

| | |
|---|---|
| **AJOUTABLE** | Une entrée peut être écrite. Ce qui reste à faire n'est pas du code : créer une app OAuth, ou coller une clé. |
| **TRAVAIL PRODUIT** | Le chemin existe mais quelque chose manque — une mesure à faire, une décision à prendre, ou une inscription chez le fournisseur. |
| **IMPOSSIBLE** | Fermé, et la raison est nommée. Ne pas réessayer sans que la raison ait changé. |

Et une colonne qui compte autant que le verdict : **peut-il mettre un message
devant quelqu'un qui n'a rien demandé ?** C'est la question que le champ
`OptOuts` pose, et le bloc `const NO_OUTREACH` fait échouer la compilation d'une
entrée qui y répond « non » sans qu'on ait lu la liste d'outils du fournisseur.

---

# Ce qui est ajoutable aujourd'hui

Quinze entrées, dont sept sans la moindre inscription préalable.

| Connecteur | Forme | Plancher | Ce qu'il reste à faire |
|---|---|---|---|
| **GitHub** | `Dial` + OAuth | `Write` | ✅ **déjà dans le catalogue.** Créer l'OAuth App et poser `AGENTOS_OAUTH_CLIENTS` |
| **Gmail** | `Dial` + OAuth | `Write` | Client OAuth Web dans la Google Cloud Console |
| **Google Drive** | `Dial` + OAuth | `Write` | Le même client Google |
| **Zoom** | `Dial` + OAuth (`Basic`) | `Read` | Une *General app* sur le Marketplace Zoom |
| **Notion** | `Dial` + OAuth | `Write` | Un `POST /register` à la main, secret permanent |
| **Canva** | `Dial` + OAuth | `Write` | Idem, secret permanent |
| **Granola** | `Dial` + OAuth | `Read` | Idem, secret permanent |
| **Magnific** | `Dial` + OAuth | `Write` | Idem, secret permanent |
| **Atlassian Rovo** | `Dial` + `Bearer` | `Write` | Une clé de compte de service |
| **Malwarebytes** | `Dial` + **aucun credential** | `Read` | **Rien.** L'entrée la moins chère du document |
| **Context7** | `Dial` + `None` ou `Bearer` | `Read` | Rien, ou une clé pour une limite plus haute |
| **Supabase** | `Dial` + `Bearer` | `Destructive` | Un PAT — ⚠ voir plus bas |
| **Neon** | `Dial` + `Bearer` | `Destructive` | Une clé API — ⚠ voir plus bas |
| **PostHog** | `Dial` + `Bearer` | `Destructive` | Une clé personnelle |
| **Mixpanel** | `Dial` + `Bearer` | `Destructive` | Un Service Account |
| **MotherDuck** | `Dial` + `Bearer` | `Destructive` | Un jeton d'accès |
| **Linear** | `Dial` + `Bearer` | `Write` / `Read` | Une clé API. Deux entrées possibles, dont `/mcp/readonly` |
| **Stripe** | `Dial` + `Bearer` | `Write` | Une clé restreinte **en lecture seule** — ⚠ voir plus bas |
| **Serpstat** | `Host` (npm) | `Read` | Épingler la version et capturer sa surface d'outils |
| **Exa** | `Dial` + `Bearer` | `Read` | Vérifier qu'il accepte `Authorization: Bearer` et pas seulement `x-api-key` |

## Les jetons dont un mauvais accord coûte cher

À lire avant d'écrire l'une de ces entrées.

**Stripe** est le plus coûteux du document. `stripe_api_write` couvre les
remboursements, la finalisation de factures et la résiliation d'abonnements —
c'est la caisse. Et finaliser une facture **envoie un e-mail à un client**, sans
qu'aucune liste de désabonnement Stripe existe à rapatrier. **La seule forme
honnête est une clé restreinte en lecture seule** : le plancher tombe à `Write`,
`NoStrangers` redevient vrai, et on garde l'essentiel de ce qu'un employé a à
faire — lire les soldes, les rapports et l'analytique.

**Cloudflare** est le plus dangereux, et il ne le montre pas.
`https://mcp.cloudflare.com/mcp` n'expose que deux outils, `search()` et
`execute()` — et `execute()` fait écrire du JavaScript qui appelle **n'importe
lequel des ~2 500 endpoints de l'API Cloudflare**. Détruire une zone DNS est
atteignable sans qu'aucun nom d'outil destructeur n'apparaisse. Le plancher de
risque ne voit que deux outils d'apparence anodine ; déclarer `execute` en `Read`
serait une faute grave.

**Trois entrepôts exposent un SQL en écriture qu'aucun plancher ne distingue de
son jumeau en lecture** : `execute_sql` chez BigQuery (accepte DML *et* DDL, donc
`DROP TABLE`, alors qu'un `execute_sql_readonly` existe), `query_rw` chez
MotherDuck, `execute-sql` chez PostHog. Un plancher `Destructive` force
l'approbation humaine sur les deux, et c'est le prix correct d'une seule classe
par connecteur.

**Supabase** : un PAT non restreint donne la base de production entière, et
`execute_sql` accepte `DROP TABLE`. L'endpoint `?read_only=true` justifie une
seconde entrée à plancher `Write`, et c'est probablement celle à écrire d'abord.

**Neon** : une clé API porte le **compte entier**, pas un projet.

**Alpaca et Longbridge** passent des ordres réels. **Binance est le seul
connecteur financier du document qui borne structurellement le sinistre** : sa
documentation dit qu'il n'existe aucune portée de retrait, et que l'agent ne peut
jamais sortir de fonds vers une adresse externe.

---

# Ce qui demande un travail avant d'être ajouté

## Une mesure à faire

| Connecteur | Ce qu'il faut mesurer |
|---|---|
| **Trello** | Son autorité sert **deux** ressources, Trello et Rovo, et l'indicateur `resource` est le seul discriminant — or on ne l'envoie jamais (mur n°4). Un vrai passage de consentement dira si le jeton sort avec la bonne audience. |
| **COROS** | Son `WWW-Authenticate` porte un `resource_metadata` : il pourrait exiger le mur n°4. Un appel réel tranche, et doit précéder l'entrée. |
| **BigQuery** | Même doute sur `resource`, plus la vérification que `refresh_due` tourne réellement (les jetons Google expirent en une heure). |
| **Higgsfield** | La liste d'outils **n'est pas publiée** et le serveur exige un jeton avant `tools/list`. Or `floor` et `opt_outs` sont des affirmations : il faut l'avoir lue. |
| **Ubersuggest** | Le chemin exact de l'endpoint n'est documenté nulle part. On n'écrit pas un `&'static str` au jugé. |
| **Tableau** | Idem, plus la vérification qu'un client confidentiel est possible. |

## Une inscription chez le fournisseur

**Vercel** tient une liste blanche d'URI de retour : il faut faire allowlister la
nôtre. **Sentry**, **HubSpot**, **ZoomInfo**, **Porter Metrics** et **Binance**
demandent chacun d'enregistrer une application OAuth dont rien ne dit
aujourd'hui qu'elle vaut pour leur serveur MCP. **Tredict** est le cas le plus
propre du document : on écrit à `support@tredict.com` avec l'URL de retour et les
portées, et on reçoit un client confidentiel — c'est exactement notre modèle.

**Slack** est un cas à part : techniquement conforme aux cinq murs, mais servir
plusieurs workspaces clients impose une **publication au Marketplace**, avec revue
et délai. Une app *interne* ne vit que dans un workspace.

## Une décision de produit

Ces trois-là passent tous les murs techniques. C'est le champ `OptOuts` qui les
retient, et c'est le catalogue qui fonctionne comme prévu.

**Google Calendar** — `create_event` prend une liste de participants et **envoie
une invitation à une adresse arbitraire**. `NoStrangers` serait faux, et Google
n'expose aucune liste de désabonnement : ni `Pulled` ni `Pushed` ne peut nommer
une chaîne honnête. Il n'y a pas de bonne valeur à écrire aujourd'hui.
`delete_event` est en outre irréversible.

**Superhuman Mail** — `send_email` prend To/Cc/**Bcc** et atteint n'importe
quelle adresse. C'est une boîte personnelle, pas une plateforme d'envoi : aucune
liste de désabonnement n'existe nulle part.

**PostHog** est l'exception heureuse, et mérite d'être signalée : il **peut**
envoyer (`subscriptions-create`, `workflows-patch-action-email`) **et il expose
`opt-outs-list`**. C'est le seul connecteur de tout le document dont le
désabonnement est nommable, donc dont l'entrée est écrivable honnêtement en
`OptOuts::Pulled`.

---

# Ce qui est fermé

## Le fournisseur nous refuse

**Figma** — son serveur d'autorisation MCP répond **403** à l'enregistrement des
clients hors de son catalogue, et sa documentation le dit : seuls VS Code, Cursor
et Claude Code y ont accès. Il y a une liste d'attente, pas une URL. Le serveur
local, lui, tombe sur le mur n°2.

**Apollo.io** — l'enregistrement OAuth est conditionné à un partenariat. Et
surtout : il **envoie des e-mails à des destinataires arbitraires et inscrit des
contacts dans des séquences outbound**, sans qu'aucun outil de lecture des
désabonnements apparaisse. Deux murs, dont le second est le vrai.

## Client public uniquement (mur n°3)

**Fathom**, **OpenArt**, **Hostinger Mail**, **RingCentral**, **Interactive
Brokers** : `token_endpoint_auth_methods_supported: ["none"]`. Ces fournisseurs
n'émettent aucun `client_secret`, ni par portail ni par enregistrement.
RingCentral cumule d'ailleurs trois murs — il est aussi en SSE.

## La forme du catalogue ne peut pas les porter

**Outlook Email**, **Outlook Calendar** et **Microsoft Teams** — les trois
serveurs *Work IQ* ont une URL **par locataire**
(`…/tenants/{tenantId}/servers/…`), et `Provision::Dial` porte un `&'static str`,
pas un gabarit. S'y ajoutent le statut *preview* et une licence Copilot par
utilisateur. Le client passe par `CUSTOM`.

**Shopify** — même raison, son endpoint Storefront est par boutique. `CUSTOM`
couvre le cas, mais le client colle l'URL lui-même et perd donc la promesse
anti-hameçonnage que le catalogue fait partout ailleurs. Son **Dev MCP**, en
revanche, est ajoutable en `Provision::Host`.

**Metricool**, **Tableau**, **Alpaca** — `Package::env` ne porte **qu'une**
variable, et il leur en faut deux. Trois connecteurs bloqués par le même champ.
Metricool et Alpaca sont en outre sur PyPI, alors que tout le chemin hébergé est
écrit autour de `npx`.

## Le serveur n'existe pas

**Bitdefender** — aucun serveur officiel. Le seul existant est un enrobage
Pipedream tiers ; écrire une entrée « Bitdefender » qui pointe vers un
intermédiaire serait la fausse promesse que `Provision::Dial` existe pour
empêcher.

**PureVPN** — aucun serveur, ni officiel ni communautaire.

**PrivacyHawk** — annoncé, mais **l'adresse n'est publiée nulle part**. Et s'il
l'était : il envoie des demandes de suppression à des courtiers de données, donc
il met bien un message devant des tiers.

**Garmin en direct** — aucun serveur officiel, et les candidatures à l'API Health
ne sont plus soumissibles en 2026. Le connecteur tiers qui existe est une
instance Render non affiliée : écrire « Garmin » en face serait affirmer sur un
tiers ce qu'on ne sait pas. **Tredict est le contournement propre** — il s'appuie
sur l'API Garmin Training officielle.

## Un mur d'architecture

**Apple Health** — le seul « impossible » du document qui ne dépende d'aucune
décision commerciale. HealthKit est en bac à sable sur l'appareil, Apple n'opère
aucun service qui agrège ces données, et il n'existe donc aucune adresse à
appeler. Notre mur n°2 et le modèle d'Apple sont mutuellement exclusifs.

**Windsor.ai** et **Porter Metrics** — techniquement les plus faciles à brancher,
et refusés pour la même raison : un outil `execute_action` unique qui atteint des
centaines d'actions d'écriture chez des tiers, **dont la publication de posts et
l'envoi d'e-mails Klaviyo**. Leurs désabonnements vivent chez Klaviyo et chez
Meta, et aucune chaîne de ce binaire ne peut nommer cette lecture.

---

# Trois limites du catalogue que cette qualification a révélées

Elles ne bloquent rien d'urgent, mais elles reviendront.

1. **`Package::env` ne porte qu'une variable.** Trois connecteurs sur trente sont
   fermés par ce seul champ.
2. **Le chemin hébergé est écrit autour de `npx`**, donc tout paquet PyPI est
   hors de portée même quand il n'a qu'une variable.
3. **`Provision::Dial` prend une URL fixe, pas un gabarit.** C'est ce qui exclut
   les quatre serveurs dont l'adresse contient l'identifiant du client — les
   trois Microsoft et Shopify. Un `Provision` porteur d'un gabarit serait une
   nouvelle surface de sécurité : il faudrait décider ce qu'un client a le droit
   de substituer, et c'est précisément la question que `Dial` évite en écrivant
   l'URL dans le binaire.
