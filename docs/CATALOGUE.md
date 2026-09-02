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

> **Mise à jour du 2026-08-31, deuxième vague.** Quatorze entrées écrites, une
> cinquième variante d'`OptOuts` (`HeldHere`) et un second registre public
> (`OUTREACH_HELD_HERE`). Le catalogue nomme vingt-deux connecteurs, plus
> `CUSTOM`. Chaque
> endpoint ci-dessous a été resondé avant d'être écrit en littéral, et **cinq
> verdicts de la première vague se sont révélés faux** — dont Canva, qui passe
> d'ajoutable à impossible. Les contradictions sont listées à leur place plutôt
> que corrigées en silence.

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

Quatre d'entre eux ont été réenregistrés à la main le 2026-08-31 pour vérifier
plutôt que pour croire, et les quatre rendent bien `client_secret_expires_at: 0`
avec `token_endpoint_auth_method: client_secret_basic` : Notion, Canva, Granola,
Magnific. **Et c'est là qu'apparaît un mur que ce document n'avait pas :
enregistrer n'est pas autoriser.** Canva accepte l'enregistrement de notre URL de
retour et refuse ensuite la même URL à `/authorize`. Le secret permanent n'était
donc pas la dernière question à poser à ces serveurs — la question suivante est
« et le `/authorize` accepte-t-il notre redirection ? », et elle se pose avec un
seul `curl`.

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

### Ce que la deuxième vague a changé à cette colonne

`OptOuts` a une cinquième variante, **`HeldHere`**, et trois connecteurs que ce
document classait bloqués sont entrés grâce à elle. Elle dit : *ce serveur peut
atteindre quelqu'un qui n'a rien demandé, et le fournisseur ne tient aucune liste
de désabonnement à rapatrier — donc le seul registre de ce refus est
`suppressions`, chez nous.*

Le raisonnement qui manquait était celui-ci : **`NO_OUTREACH` est un registre, pas
un verrou d'exécution.** Rien ne le lit au moment de l'appel. Refuser une entrée
n'a donc jamais empêché un message de partir — le client branchait le même
fournisseur par `CUSTOM`, et le registre se taisait exactement là où il aurait dû
parler. Ce qui arrête un appel, c'est la Policy Gate et l'approbation humaine, et
les deux sont en aval de toutes les valeurs de cet enum.

Il y a donc maintenant **deux registres publics**, qui se lisent ensemble :
`NO_OUTREACH` nomme les connecteurs qui n'atteignent personne, et
`OUTREACH_HELD_HERE` nomme ceux qui atteignent des inconnus sans liste amont.
Chacun a son bloc `const` qui casse la compilation si on ajoute une entrée sans
monter sa longueur, et le message de `OUTREACH_HELD_HERE` réclame **deux**
lectures et pas une : la liste d'outils du fournisseur, puis son API, pour
vérifier qu'aucun endpoint de suppression n'existe. Un test,
`every_entry_is_on_exactly_one_of_the_two_registers`, additionne les deux et
refuse qu'une entrée tombe entre.

---

# Ce qui est ajoutable aujourd'hui

Vingt-deux connecteurs sont nommés dans le catalogue. La première vague en avait
écrit huit, la deuxième en a écrit quatorze, et une seule des entrées qui
restaient s'est révélée fermée à la mesure.

| Connecteur | Forme | Plancher | État |
|---|---|---|---|
| **GitHub** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue.** Reste à créer l'OAuth App et poser `AGENTOS_OAUTH_CLIENTS` |
| **Sentry** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue** (2026-09-02). Reste l'app OAuth. ⚠ pas de portée en lecture seule — voir plus bas |
| **Netlify** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue** (2026-09-02). Reste l'app OAuth |
| **Vercel** | — | — | ❌ **IMPOSSIBLE.** `token_endpoint_auth_methods_supported: ["none"]` — client public seulement, mur n°3 |
| **Docker Hub** | — | — | ⏳ **TRAVAIL PRODUIT.** Serveur officiel réel, mais ni endpoint hébergé ni paquet publié : on clone et on compile |
| **Smartlead** | — | — | ⏳ **TRAVAIL PRODUIT.** `OptOuts::Pushed` — l'événement `EMAIL_UNSUBSCRIBED` existe. Manque le nom de l'en-tête de signature |
| **Gmail** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue.** Reste le client OAuth Web dans la Google Cloud Console |
| **Google Drive** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue.** Le même client Google |
| **Google Calendar** | `Dial` + OAuth | `Destructive` | ✅ **dans le catalogue**, débloqué par `OptOuts::HeldHere` — ⚠ voir plus bas |
| **Zoom** | `Dial` + OAuth (`Basic`) | `Read` | ✅ **dans le catalogue.** Reste une *General app* sur le Marketplace Zoom |
| **Notion** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue.** Secret permanent confirmé (`client_secret_expires_at: 0`) |
| **Canva** | — | — | ❌ **IMPOSSIBLE.** La mesure a contredit ce document — voir plus bas |
| **Granola** | `Dial` + OAuth | `Read` | ✅ **dans le catalogue.** Secret permanent confirmé |
| **Magnific** | `Dial` + OAuth | `Write` | ✅ **dans le catalogue**, à `https://mcp.magnific.com` et non `.ai` — voir plus bas |
| **Atlassian Rovo** | `Dial` + `Bearer` | `Write` | ✅ **dans le catalogue.** Reste une clé de compte de service |
| **Malwarebytes** | `Dial` + **aucun credential** | `Write` | ✅ **dans le catalogue.** L'entrée la moins chère du document — plancher corrigé, voir plus bas |
| **Context7** | `Dial` + `None` | `Read` | ✅ **dans le catalogue.** Rien à faire du tout |
| **Supabase** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue.** Reste un PAT — ⚠ voir plus bas |
| **Neon** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue**, en `HeldHere` — ⚠ voir plus bas |
| **PostHog** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue**, en `Pulled { from: "opt-outs-list" }` |
| **Mixpanel** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue.** ⚠ l'en-tête n'est pas une clé — voir plus bas |
| **MotherDuck** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue.** Reste un jeton d'accès |
| **Linear** | `Dial` + `Bearer` | `Write` / `Read` | ✅ **deux entrées dans le catalogue**, dont `/mcp/readonly` |
| **Stripe** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue**, débloqué par `OptOuts::HeldHere` — ⚠ voir plus bas |
| **Cloudflare** | `Dial` + `Bearer` | `Destructive` | ✅ **dans le catalogue**, débloqué par `OptOuts::HeldHere` — ⚠⚠ voir plus bas |
| **Exa** | `Dial` + `Bearer` | `Read` | ✅ **dans le catalogue.** `Authorization: Bearer` **vérifié par la mesure** — voir plus bas |
| **Serpstat** | `Host` (npm) | `Read` | Reste à faire : épingler la version et capturer sa surface d'outils |

## Ce que la mesure a contredit dans ce document

Cinq points, chacun tranché par un appel réel le 2026-08-31 et non par une
relecture.

**Canva passe d'AJOUTABLE à IMPOSSIBLE.** `POST https://mcp.canva.com/register`
accepte `https://siglair.com/v1/mcp/oauth/callback` et le renvoie tel quel dans
sa réponse — puis `GET /authorize` répond **400 `Invalid redirect URI`** pour
cette URI, pour `https://example.com/cb`, et pour toute URI en `https`. Le même
client réenregistré avec `http://localhost:33418/oauth/callback` obtient un 302
vers la page de consentement. Le serveur d'autorisation MCP de Canva n'accepte
que des redirections de bouclage : c'est un flux de client de bureau, et il est
incompatible avec le mur n°5. Second constat de la même sonde, sans objet mais
utile : Canva ignore le `scope` qu'on envoie et lui substitue ses seize portées
complètes, donc `OAuth::scopes` y aurait été décoratif de toute façon.

**Le serveur MCP de Magnific n'est pas où ce document le laissait croire.**
`mcp.magnific.ai` ne résout pas. `https://api.freepik.com/mcp` répond 200 avec
une erreur JSON-RPC qui nomme elle-même son successeur :
`https://mcp.magnific.com` — en `.com`, et **sans chemin `/mcp`**, ce que confirme
le champ `resource` de son document de ressource protégée.

**Le plancher de Malwarebytes passe de `Read` à `Write`.** Le bloc
`instructions` du serveur annonce cinq outils ; `tools/list` en répond **six**, et
le sixième est `reputation-report`, qui « soumet l'indicateur au système de
renseignement sur les menaces ». `RiskClass::Read` est défini comme « observe sans
rien changer », et ce n'en est pas. Le coût de la correction est nul : `Read` et
`Write` valent tous deux `Risk::Low`.

**Exa lit bien `Authorization: Bearer`.** Trois appels sur la même session :
sans en-tête, `web_search_exa` renvoie des résultats (palier gratuit) ; avec
`Authorization: Bearer 0000…`, `error (401): Invalid API key` ; avec
`x-api-key: 0000…`, le même message au caractère près. Les deux en-têtes
atteignent la même vérification amont — donc le bearer *est* lu comme la clé, et
l'entrée n'est pas le bouton cassé qu'Atlassian a failli être.

**La portée de Granola n'était lisible dans aucune métadonnée.** Le document
d'autorisation liste `["email", "offline_access", "openid", "profile"]` et **pas**
`mcp` ; celui de la ressource protégée liste `["mcp"]`. Tranché en enregistrant un
client à la main puis en sondant `/authorize` : `scope=mcp` → 302 vers le
consentement, `scope=mcp offline_access` → 302, `scope=bogus_scope_xyz` → retour
avec `error=invalid_scope`. L'endpoint valide donc réellement, `mcp` existe, et
c'est la métadonnée du serveur d'autorisation qui est incomplète.

## Les jetons dont un mauvais accord coûte cher

À lire avant d'écrire l'une de ces entrées.

**Stripe** est le plus coûteux du document, et il est entré à **`Destructive`**.
`stripe_api_write` est documenté comme « écrire avec n'importe quelle méthode
`POST`, `PATCH`, `PUT` et `DELETE` de l'API Stripe » : un outil dont le paramètre
est le verbe. Remboursements, finalisation de factures et résiliation
d'abonnements sont dedans, et aucun n'est défait par un autre appel. La forme la
moins chère reste une **clé restreinte en lecture seule**, mais c'est un choix qui
se fait chez le client et qu'aucun champ d'ici ne voit — donc le plancher est
écrit pour la pire clé qu'il puisse coller, pas pour la meilleure. Finaliser une
facture **envoie un e-mail à un client**, sans qu'aucune liste de désabonnement
Stripe existe à rapatrier : c'est `OptOuts::HeldHere`, et la sortie propre est
nommée dans le code — couper l'e-mail de facture de Stripe et le faire passer par
le fournisseur dont le `List-Unsubscribe` atterrit déjà sur une de nos routes fait
basculer l'entrée en `Pushed`.

**Cloudflare** est le plus dangereux, et il ne le montre pas. Son serveur expose
`search`, `execute` et — d'après le dépôt, contre deux dans la page produit — un
`docs`. **La liste d'outils ne dit rien de ce qu'il peut faire** : `execute` fait
écrire du JavaScript qui appelle `cloudflare.request()` sur **n'importe lequel des
~2 500 endpoints de l'API Cloudflare**. Détruire une zone DNS, vider un bucket R2,
supprimer une base D1 ou un Worker sont tous atteignables sans qu'aucun nom
d'outil destructeur n'apparaisse nulle part. La méthode habituelle — énumérer les
outils, prendre le pire, écrire sa classe — lit trois noms anodins et répond
`Read` ; **déclarer `execute` en `Read` serait une faute grave.** La seule
frontière de permission réelle est la portée du jeton API que le client a collé,
et rien dans ce binaire ne la voit. Le plancher `Destructive` est donc la seule
chose qui rattrape ce connecteur, et il force l'approbation humaine jusque sur
`docs`, qui est une recherche documentaire. C'est le prix correct.

Même serveur, même couvercle, pointé sur l'autre affirmation : les invitations de
membre de compte et la vérification de destination d'Email Routing sont des
endpoints de l'API Cloudflare, donc `execute` peut mettre du courrier devant une
adresse que quelqu'un a tapée — et aucun nom d'outil ne le dirait jamais. D'où
`HeldHere` plutôt que `NoStrangers`.

**Quatre serveurs donnent un SQL arbitraire à l'agent**, et aucun plancher ne
distingue le SQL en écriture de son jumeau en lecture : `execute_sql` chez
Supabase, `run_sql` chez Neon, `query_rw` chez MotherDuck, `execute-sql` chez
PostHog. (`stripe_analytics` fait du SQL sur des tables de reporting seulement.)
Un plancher `Destructive` force l'approbation humaine sur les deux jumeaux, et
c'est le prix correct d'une seule classe par connecteur. La bonne réponse pour un
tenant qui veut lire sans approbation n'est pas de déclarer l'outil plus bas,
c'est une **seconde entrée** sur l'endpoint en lecture seule — `?read_only=true`
chez Supabase, `/mcp/readonly` chez Linear, qui est déjà écrite ainsi.

**Supabase** : un PAT non restreint donne la base de production entière.
`delete_branch`, `reset_branch` et `pause_project` sont irréversibles en plus du
SQL. Aucun outil n'y prend d'adresse — `deploy_edge_function` prend du *code*, et
la ligne que ce catalogue trace est celle d'un outil dont le **paramètre est un
destinataire**, pas d'un outil qu'on pourrait écrire pour en devenir un. C'est la
même ligne qui laisse GitHub en `NoStrangers` alors que GitHub Actions exécute
n'importe quoi.

**Neon** : une clé API porte le **compte entier**, pas un projet. C'est aussi la
seule entrée de cette vague dont la revendication d'opt-out n'a pas pu être
énumérée : `https://mcp.neon.tech/mcp` exige un jeton avant `tools/list`, et la
surface documentée contient `create_auth_user`, un outil dont le paramètre est
l'adresse e-mail d'une personne. La page de Neon ne dit ni que cet appel envoie un
courrier ni qu'il n'en envoie pas (vérifié le 2026-08-31). `NoStrangers` affirme
qu'aucun outil ne peut atteindre quelqu'un : c'est exactement la phrase que
l'énumération manquante ne soutient pas. La moitié certaine est l'autre — Neon ne
publie aucune liste de suppression — donc `HeldHere`, en se trompant *vers* le
registre plutôt qu'en dehors. Une entrée listée à tort est une ligne qu'on lit et
qu'on retire ; une entrée absente à tort est une ligne que personne ne sait
chercher.

**Mixpanel** : ⚠ **la chaîne que le client colle n'est pas une clé.** Le chemin
compte de service veut la valeur d'en-tête littérale
`Authorization: Bearer Basic <base64(nom:secret)>` — un credential Basic transporté
dans le jeton du schéma Bearer. `mcp.rs` écrit le préfixe `Bearer ` lui-même, donc
ce qui va dans le champ est `Basic <base64>` et le fil ressort correct. Un client
qui colle le secret seul obtient un 401 indébogable. C'est le piège d'Atlassian à
l'envers, et Mixpanel marque lui-même cette interface **beta**. Son plancher est
`Destructive` pour les suppressions et `Update-Feature-Flag` (qui change le ciblage
sur du trafic de production), pas pour du SQL : `Run-Query` est un appel structuré.

**Google Calendar** est entré à **`Destructive`**, et c'est le seul plancher de ce
document qui ne suit pas la règle « `Write` pour le reste ». `delete_event` est
dans la liste des neuf outils et Google Calendar n'a pas de corbeille : l'événement
disparaît du calendrier de tous les participants, et le courrier d'annulation est
déjà parti. `RiskClass::Destructive` est défini comme « irréversible, ou coûteux à
défaire ». Le prix est réel et assumé : `list_events` doit être déclaré
`Destructive` aussi, donc un humain approuve une lecture de calendrier. C'est ce
que coûte une classe grossière par connecteur quand un connecteur a un outil
irréversible — et Atlassian en est le miroir, où `Write` est écrit *parce que* rien
sur ce serveur ne supprime. Une entrée Calendar en lecture seule sur des portées
réduites serait celle qui porterait `Read` ; personne n'a pris cette décision.

Sur l'autre affirmation : le schéma d'entrée de `create_event` a un tableau
`attendees` dont le membre exige un `email`, mesuré le 2026-08-31, et **Google
envoie une invitation à chaque adresse**. Google ne publie aucune liste de
désabonnement pour ces invitations — donc `HeldHere`.

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

## Une décision de produit — et ce qu'elle est devenue

Ce paragraphe disait que trois connecteurs passaient tous les murs techniques et
que le champ `OptOuts` les retenait. **Deux d'entre eux sont entrés**, et ce n'est
pas le champ qui a cédé : c'est l'inférence qu'on en tirait. Voir plus haut — un
registre qui refuse une entrée ne protège personne, il se tait.

**Google Calendar** — entré en `OptOuts::HeldHere`, plancher `Destructive`.
L'argument est intégralement au-dessus.

**Superhuman Mail** — reste dehors, et pour une raison qui n'a rien à voir avec
`OptOuts` : `send_email` prend To/Cc/**Bcc** et atteint n'importe quelle adresse,
depuis une boîte personnelle. `HeldHere` serait techniquement écrivable, et le
serait malhonnêtement : ce connecteur *est* un envoyeur, pas un produit qui envoie
en passant. Un connecteur dont la fonction principale est de mettre un message
devant quelqu'un appartient au chemin `EmailProvider`, où `opt_outs` est une
méthode requise et où aucune des deux variantes bon marché n'existe. Le catalogue
n'est pas la bonne porte pour lui.

**PostHog** est l'exception heureuse, et c'est elle qui garde `HeldHere` honnête :
il **peut** envoyer (`subscriptions-create`, dont le `target_type` est `email` ou
`slack`, et un workflow publié) **et il expose `opt-outs-list`** — orthographié
exactement ainsi, minuscules et traits d'union, défini dans le
`products/messaging/mcp/tools.yaml` de PostHog comme
`messaging_preferences_opt_outs_retrieve`, annoté `readOnly: true`, avec
`opt-outs-add` et `opt-outs-remove` à côté. C'est le seul connecteur de tout le
document dont le désabonnement est nommable, donc son entrée est écrite en
`OptOuts::Pulled { from: "opt-outs-list" }` et **pas** en `HeldHere`, qui aurait
été un mot moins cher et aurait jeté la seule liste rapatriable de la
qualification. C'est exactement pour ça que le message d'échec de
`OUTREACH_HELD_HERE` réclame la deuxième lecture.

---

# Ce qui est fermé

## Le fournisseur nous refuse

**Figma** — son serveur d'autorisation MCP répond **403** à l'enregistrement des
clients hors de son catalogue, et sa documentation le dit : seuls VS Code, Cursor
et Claude Code y ont accès. Il y a une liste d'attente, pas une URL. Le serveur
local, lui, tombe sur le mur n°2.

**Canva** — le seul verdict que la deuxième vague a **retourné**. Son
`/register` accepte notre URL de retour et la renvoie ; son `/authorize` la
refuse ensuite en **400 `Invalid redirect URI`**, comme il refuse toute URI en
`https`. Seul `http://localhost` obtient une page de consentement. C'est un flux
de client de bureau, et il est incompatible avec le mur n°5 — une seule URL de
retour publique pour tout le déploiement. Ce n'est pas une inscription qui manque,
c'est le fournisseur qui doit changer. La mesure est datée du 2026-08-31 et vaut
pour trois clients enregistrés séparément.

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

# Cinq limites du catalogue que cette qualification a révélées

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
4. **`Credential` n'a pas de « facultatif ».** Context7 marche sans rien et
   accepte une clé qui monte la limite de débit ; `Credential::None` refuse la
   clé qu'un client voudrait coller, `Credential::Bearer` l'exige. L'entrée est
   écrite en `None`, parce que celle qui ne demande aucune inscription est celle
   qui vaut la peine, et ça devient `Bearer` en un mot le jour où un tenant tape
   dans la limite. Une variante `Optional` serait un troisième état à porter dans
   la route de connexion pour un seul connecteur — pas encore.
5. **Le plancher est une classe par connecteur, et deux serveurs en font une
   fiction.** Chez Cloudflare et chez Stripe, un outil unique dont le paramètre
   est « n'importe quelle méthode de l'API du fournisseur » n'a pas de liste
   d'outils à lire : `Destructive` est alors la seule valeur défendable, et elle
   fait approuver par un humain jusqu'à une recherche documentaire. La sortie
   n'est pas une table par outil ici — l'argument contre est dans les docs du
   module — c'est une **seconde entrée sur un endpoint en lecture seule**, comme
   `linear-readonly`, quand le fournisseur en publie un.


---

## L'ajout du 2026-09-02 — deux entrées, trois refus

Demande : Smartlead, plus « un GitHub, un serveur et un Docker » pour qu'une
équipe de développeurs puisse travailler.

**GitHub y était déjà**, avec ses portées choisies et non recopiées : `repo`,
`read:org`, `read:user`, et ni `delete_repo` ni `workflow`.

**Deux sont entrés**, tous deux sondés en direct — les requêtes sont recopiées
dans le commentaire de leur entrée, et se rejouent en deux `curl` :

* **Sentry** — `https://mcp.sentry.dev/mcp`. Les erreurs en production : ce qui
  casse, où, depuis quand. Un point désagréable est écrit dans l'entrée plutôt
  qu'annoncé plus doucement : Sentry n'expose **aucune portée de lecture seule pour un projet**
  (`org:read` est la seule lecture pure), donc on ne peut pas promettre un
  employé qui regarde sans toucher. Le plancher est `Write` en conséquence.
* **Netlify** — `https://mcp.netlify.com/mcp`. Les sites, les déploiements et
  leurs variables. Trois portées sur quatre : `claudeai` est écartée parce que
  c'est une portée nommée d'après un client et non d'après un droit, et qu'une
  limite dont on ne sait pas dire ce qu'elle autorise n'est pas une limite.

**Trois sont refusés, et la raison de chacun est un fait, pas un avis :**

* **Vercel** — le mur n°3, mesuré. Son document RFC 8414 annonce
  `token_endpoint_auth_methods_supported: ["none"]` et rien d'autre : client
  public, PKCE seul. Netlify annonce `client_secret_post` en plus ; c'est toute
  la différence entre les deux, et c'est pour ça qu'il y en a un dans la liste.
* **Docker Hub** — `github.com/docker/hub-mcp` est bien le serveur officiel,
  mais il n'a ni endpoint hébergé (`mcp.docker.com` → 404, `hub-mcp.docker.com`
  ne résout pas) ni paquet publié : on clone et on compile. `Provision::Host`
  veut un `Package::spec` que le binaire nomme ; « clonez et compilez » n'est pas
  un spec. **Le chemin qui marche aujourd'hui est `CUSTOM`** : le client fait
  tourner ce serveur sur sa machine et branche son adresse — ce qui est
  exactement l'argument « SSH est un déploiement, pas un connecteur ».
* **Smartlead** — bloqué par `OptOuts`, et c'est le cas d'école que le test
  `a_sender` décrit depuis le début. **La première lecture était fausse et elle
  est corrigée ci-dessous.**

### Et « connecter un serveur » ?

C'est déjà là, et ça s'appelle `CUSTOM`. Le client fait tourner un serveur MCP
sur sa machine — la sienne, ou l'une des nombreuses qui en hébergent — et colle
son adresse ; `Reach::Private` existe pour le cas du sidecar. Ce que le
catalogue refuse, c'est une variante `Ssh`, et l'argument tient en une phrase :
une clé SSH est un droit d'exécuter *ce que le porteur décide*, il n'y a pas de
serveur MCP au bout, et un programme que personne n'a écrit n'a aucune propriété
vérifiable. Un allowlist d'un côté, un interpréteur de l'autre.


---

## Smartlead, la correction du 2026-09-02

> « En abonnement payant Smartlead on a une API, c'est pas utilisable ? »

Si, et la première conclusion écrite plus haut était fausse. Elle disait « une
écriture sans lecture en face », parce que le serveur MCP expose
`unsubscribe_lead_globally` sans rien qui liste les désabonnés, et parce que la
référence publique ne documente aucun point d'entrée de liste de blocage.

**Smartlead ne se tire pas, il pousse.** `api.smartlead.ai/core/webhooks` sert
un catalogue d'événements qui contient **`EMAIL_UNSUBSCRIBED`** — à côté de
`EMAIL_BOUNCED`, `EMAIL_REPLIED`, `EMAIL_OPENED`, `EMAIL_SENT`, `EMAIL_CLICKED`
— enregistrables par `POST /webhooks`. C'est donc `OptOuts::Pushed { at }` et
non `OptOuts::Pulled { from }` : la catégorie était la mauvaise, pas la
plateforme.

La même page documente la vérification : un **HMAC-SHA256 sur le corps brut**,
comparé en temps constant (`hmac.compare_digest`). C'est le bon niveau
d'exigence, et c'est ce que `routes::webhooks` sait déjà faire pour deux autres
schémas.

### Ce qui manque, et ce n'est plus une catégorie mais un nom

1. **Le nom de l'en-tête de signature.** Le `provider` d'un endpoint choisit le
   schéma dans `routes::webhooks`, et la page ne dit pas quel en-tête Smartlead
   envoie. L'écrire au jugé donnerait soit des livraisons authentiques répondues
   `401`, soit — bien pire — un vérificateur qui accepte ce qu'il ne devrait pas.
2. **Une migration.** `webhook_endpoints_provider_is_wired` est contraint à
   `('email', 'twilio')` ; la CHECK existe précisément pour qu'on ne puisse pas
   enregistrer un handle qu'aucune ingestion ne lit.
3. **L'ingestion** qui transforme un `EMAIL_UNSUBSCRIBED` en une ligne de
   `suppressions` — laquelle désactive le **contact**, donc le téléphone tombe
   avec le mail (`0011_revenue.sql`, `suppressions_deactivate_contacts`).

### Ce qui débloque, dans l'ordre

1. Une **clé d'API valide** — celle configurée répond `401`.
2. **Une livraison réelle** vers une URL qu'on contrôle, et le nom de l'en-tête
   lu dessus. C'est le seul fait qui ne s'obtient pas en lisant.
3. Puis : la migration, le troisième schéma de signature, l'ingestion, l'entrée.
   **Rien dans cette liste n'est incertain.**

C'est un après-midi de travail, pas un mur. Le mur était une phrase fausse.
