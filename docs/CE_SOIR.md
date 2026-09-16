# Ce soir, sur ta machine — le mode `cli`

`scripts/ce-soir.sh` monte l'instance complète sur la machine du fondateur et
imprime la ligne à coller. Ce document dit **ce que ce mode est**, **ce qu'il
n'est pas**, et **pourquoi il est légal ici et pas sur le VPS**.

---

## 1. Le mur, et l'ouverture

Un e-mail n'est pas envoyé par un outil. Il est envoyé par un **siège**, pendant
un **tour**, et un tour demande un modèle côté serveur. Le fondateur n'a pas de
clé Anthropic. Tout le reste du produit est là — l'organigramme, les domaines,
l'import, les séquences, la Gate — et rien ne bouge sans cette dernière pièce.

`model_connect` a deux chemins :

| chemin | ce qu'il dépense | la clé |
|---|---|---|
| `api_key` | la clé du locataire, scellée dans le coffre | obligatoire |
| `cli` | **la session du `claude` de l'hôte** | refusée |

Le second est l'ouverture. Sur la machine du fondateur, l'hôte *est* le
fondateur : son binaire `claude`, sa session, son terminal. `AGENTOS_LLM=cli`
sélectionne `CliLlm`, qui lance `claude` et lit sa réponse ; `CliLlm::new()` ne
porte **aucun** jeton, donc l'enfant hérite de la session de l'utilisateur qui a
lancé le serveur, comme n'importe quel programme qu'il lance lui-même.

## 2. Pourquoi c'est légal ici

L'argument entier, sourcé et daté, est dans `docs/MCP_SERVEUR.md` §1 ; il n'est
pas recopié ici, il est **appliqué**. Ce qui l'interdit sur le VPS, en une
phrase de la page `code.claude.com/docs/en/legal-and-compliance`, section
*Authentication and credential use*, relevée le 2026-09-10 :

> « Anthropic does not permit third-party developers to offer Claude.ai login
> into their own applications, **or to route requests through Free, Pro, or Max
> plan credentials on behalf of their users**. Moreover, developers may not
> collect, store, or intermediate Claude.ai credentials or session tokens […] »

Et ce qui l'autorise ici, la phrase suivante de la même page :

> « Nor does it prevent an end user from signing in to the unmodified Claude
> Code binary with their own Claude subscription. »

La différence n'est pas une nuance de rédaction, c'est **qui est devant le
clavier** :

| | sur le VPS | sur sa machine |
|---|---|---|
| qui lance `claude` | notre backend, pour un client | le fondateur, pour lui-même |
| d'où vient la session | collectée, scellée, rejouée | déjà là, jamais lue par nous |
| pour le compte de qui | d'un tiers | de lui-même |
| accès automatisé non humain | oui | non : il est devant le terminal |

Ce que ce mode ne fait **jamais**, et le code le refuse plutôt que de le
documenter :

* **il ne collecte pas de jeton.** `model_access::connect` refuse un `cli`
  accompagné d'une clé — `SubscriptionIsNotOursToHold`, avant tout appel, parce
  que le prouver serait déjà l'intermédier. Ne pas rouvrir ce refus : c'est une
  violation de licence, pas une fonctionnalité.
* **il ne rejoue pas une session stockée.** Une ligne d'accès `cli` portant une
  `sealed_key` est refusée à la lecture aussi (`NoModel::SubscriptionIsNotOursToHold`),
  pour les lignes écrites avant le 2026-09-06.
* **il ne modifie pas le binaire `claude`.** Il le lance, avec des drapeaux
  documentés.
* **il ne sert personne d'autre.** Un seul utilisateur, sa propre machine, son
  propre locataire.

La garde technique qui tient tout ça : `LlmBackend::pays_with_our_key()`. Elle
est fausse pour `mock` et `cli`, vraie pour `anthropic` — et `connect` **comme**
`client_for` refusent le chemin `cli` sur un hôte dont le modèle est une clé à
nous. On ne peut donc pas faire payer notre clé à un locataire en changeant une
variable d'environnement après coup.

## 3. Ce que ce mode n'est pas

* **Ce n'est pas le déploiement.** Le VPS reste sur `api_key`, une clé par
  locataire, scellée. Ce mode n'y a rien à faire et le script ne s'y installe
  pas.
* **Ce n'est pas gratuit.** Chaque tour consomme le quota de l'abonnement du
  fondateur. Un siège avec `interval_secs: 300` se réveille toutes les cinq
  minutes ; c'est un abonnement individuel qui paie, et la même page parle
  d'« ordinary, individual usage ».
* **Ce n'est pas multi-locataire.** Une machine, une session, un locataire.
* **Ce n'est pas une démonstration à distance** — sauf sous `--recevoir`, et il
  faut le dire franchement. `APP_BIND` reste `127.0.0.1` dans tous les cas ; ce
  qui change, c'est qu'un tunnel rapide relaie une adresse publique vers ce
  port, donc pendant qu'il tourne, l'instance EST joignable depuis Internet.
  Ce qui tient alors n'est plus le fait d'écouter sur la boucle locale, c'est la
  porte : `/v1/webhooks/{chemin}` a un chemin opaque, vérifie une signature
  avant d'écrire un octet, et tout le reste de l'API demande une clé. Arrêter le
  tunnel — `--arreter` — referme la porte, et l'adresse ne revient jamais.

## 4. Les faux adaptateurs, et ce qui les enlève

Par défaut, `telephony` et `embedder` sont faux, et le serveur le dit au
démarrage, à `warn`, à chaque fois. `email` l'est aussi sans `--reel`. Un tour
va jusqu'au bout — la Gate décide, la séquence avance, le journal s'écrit — mais
**rien ne sort de la machine**. C'est le défaut parce qu'un e-mail est
irréversible et qu'un prospect réel n'est pas un décor de démonstration.

`--reel` remplace le seul adaptateur qui compte, l'e-mail, par Resend. Il exige
`EMAIL_API_KEY`, il exige `AGENT_EMAIL_DOMAIN` — un domaine **vérifié**, sinon
Resend refuse chaque envoi — et il exige un `OUI` tapé à la main après avoir
écrit ce que ça implique. Le téléphone et l'embedder restent faux : il n'y a pas
de raison d'acheter un numéro pour prouver qu'un e-mail part.

**Le navigateur, lui, n'est plus faux.** Si `/Applications/Google Chrome.app`
existe, le script le lance en `--headless=new` avec un `--user-data-dir` sous
l'état, pose `BROWSER_CDP_URL`, et l'arrête par son pid avec `--arreter` ;
`/readyz` rend alors `browser_js: true` et un `browser_endpoints` non nul. Sans
Chrome, `MockBrowser` répond `no_such_element` à chaque lecture — un siège dont
la charte exige de lire le site d'un prospect avant d'écrire renonce toujours,
et il le fait en silence, la charte satisfaite — donc le script le **dit** au
lieu de laisser croire. Le port de débogage est `CDP_PORT` (9222 par défaut) ;
un port déjà occupé par quelque chose qui répond à `/json/version` est adopté
tel quel, un port occupé par autre chose est un refus.

### La répétition générale de `--reel`, sans clé et sans destinataire

`--reel` n'était prouvable que par ses refus : personne n'avait vu un envoi
aller jusqu'au `provider_message_id`. `scripts/faux-resend.py` sert les six
routes de Resend que le chemin touche — le dépôt en avait déjà un, `FakeResend`,
mais enfermé dans `#[cfg(test)]`, donc inlançable — et `EMAIL_API_BASE` pointe
l'adaptateur **réel** dessus :

```sh
python3 scripts/faux-resend.py --port 8081 \
  --journal /tmp/envois.jsonl --etat /tmp/faux-resend.json &
EMAIL_API_KEY=re_faux AGENT_EMAIL_DOMAIN=envoi.example.com \
  EMAIL_API_BASE=http://127.0.0.1:8081 scripts/ce-soir.sh --reel
```

`EMAIL_API_BASE` est **refusée par le serveur sans `AGENTOS_ALLOW_MOCKS`**, et
le refus est à cet endroit parce que c'est la même question que les faux
adaptateurs posent : à qui la clé du fournisseur est présentée. L'adaptateur
n'est pas un faux pour autant — la ligne de démarrage dit toujours
`email=resend` — il parle simplement à quelqu'un d'autre, et le script ne
demande pas de `OUI` quand c'est le cas : il n'y a rien à confirmer quand rien
ne sort de la machine.

## 4 bis. Recevoir : `--recevoir`

Pour qu'un e-mail **arrive**, il faut deux choses qu'aucune des deux n'était là.

1. **Une ligne `webhook_endpoints`** (`0053`). Seul
   `POST /v1/platform/webhooks` l'écrit, derrière `AGENTOS_PLATFORM_KEYS` — et
   c'est délibéré : aucun handler n'accepte un `auth::Principal` pour cette
   table, parce qu'un locataire qui écrirait sa propre ligne pourrait nommer un
   chemin et se mettre à ramasser le courrier d'un autre. `--recevoir` tire une
   clé de plate-forme, la pose dans l'environnement du serveur, appelle cette
   route-là, et imprime le chemin opaque qu'elle rend.
2. **Une adresse publique.** Un portable n'en a pas. `cloudflared tunnel --url`
   ouvre un **tunnel rapide** : une adresse `https://…trycloudflare.com`, sans
   compte et sans dépense, `brew install cloudflared`. Le script le lance
   **avant** le serveur, parce que `PUBLIC_HOST` est lu au démarrage et que
   c'est lui qui écrit le lien de désabonnement d'un e-mail — pointé sur
   `127.0.0.1`, ce lien est mort chez le destinataire, et Google et Yahoo le
   lisent (RFC 8058).

Ce que ça coûte : **l'adresse change à chaque lancement**, donc le webhook est à
recoller chez le fournisseur à chaque fois. C'est le prix de ne demander ni
compte ni carte. Un **tunnel nommé** (`cloudflared tunnel create`) garderait
l'adresse ; il demande le compte Cloudflare du fondateur et un `cloudflared
login`, et ce script ne le fait pas et ne le fera pas tout seul. Le **secret**,
lui, ne bouge pas : il vit dans `secrets.env`, et ré-inscrire le webhook fait
tourner le secret en **gardant** le chemin.

**La signature est vérifiée sur ce chemin**, et c'est ce qui rend un tunnel
public tenable. `routes::webhooks` lit le corps en octets **avant** toute
désérialisation, résout le chemin, puis vérifie : pour `email` c'est le schéma
Standard Webhooks — HMAC-SHA256 sur `id.horodatage.corps`, avec la fenêtre de
rejeu de `REPLAY_WINDOW_SECS`. Une livraison non signée, ou signée d'un autre
secret, est un **401 avant qu'une ligne soit écrite** ; un chemin inconnu est un
404 et non un 401, pour ne pas dire à un sondeur quelles portes existent.

## 5. Où le script s'arrête, et pourquoi

Il monte l'**infrastructure** : la base, les migrations (appliquées par le
serveur à son démarrage), le locataire, le plafond de politique, le serveur, les
clés. Trois de ces étapes ne sont atteignables par **aucun outil MCP** et c'est
la raison d'être du script :

* `AGENTOS_API_KEYS` est une variable d'environnement lue au démarrage : la clé
  qui sert à parler au serveur ne peut pas être créée en parlant au serveur ;
* `policy new-tenant` écrit la ligne `tenants` que cette clé nomme — une clé
  nommant un locataire absent est un 500 au premier écrit ;
* `policy install` pose le plafond. **Aucune route ne l'écrit.** Sans lui la
  Gate est fermée : chaque action est refusée en `no_platform_policy` et
  `/readyz` reste rouge.

Sous `--recevoir` il y en a une quatrième, et elle est du même genre :
`AGENTOS_PLATFORM_KEYS` est lue au démarrage comme l'autre, donc la clé qui peut
écrire `webhook_endpoints` ne peut pas être créée en parlant au serveur. Le
script la pose, puis appelle la vraie route avec.

Il s'arrête là. Créer la société, poser les chartes, importer, enrôler — c'est
le geste que le fondateur veut faire depuis son terminal, et un script qui le
ferait à sa place lui retirerait la démonstration.

**Une quatrième étape reste hors de portée du terminal MCP, et le script ne la
fait pas non plus** : `agentos-server flow set` / `flow confirm`, les sélecteurs
du parcours de réservation d'un prospect. `0032_prospect_flows.sql` n'accorde à
`app_role` ni INSERT ni UPDATE sur cette table : il n'existe **aucun** chemin
depuis le serveur vers une de ses lignes, et c'est délibéré — un employé qui
pourrait écrire un flux pourrait pointer un sélecteur sur n'importe quel élément
d'un domaine que sa politique le laisse déjà lire, puis produire un constat
reproductible et capturé à propos de ce que cet élément disait. La confirmation
est le fait qu'**une personne a ouvert la page**, et le script ne peut pas
l'ouvrir à sa place.

Ce que ça coûte ce soir : un siège `sales-development` qui se réveille sur sa
**cadence** ne trouve rien à faire tant qu'aucun flux n'est confirmé, et rend
`no_work`. Une **séquence**, elle, n'en a pas besoin : la promesse porte déjà son
brief, et le tour part.

## 6. La marche, une fois la ligne collée

`docs/PLUGIN.md` § `lancer-une-campagne` donne l'ordre complet. Le minimum, et
les deux endroits où ça s'arrête si on les oublie :

1. `model_connect {"path":"cli"}` — sans ça, `company_health_get` rend
   `stopped` et aucun siège ne prend de tour.
2. `company_create` — l'organigramme, les rôles, la fenêtre.
3. `domains_register` → `domains_dns_publish` → `domains_verify`. Un siège ne
   s'assied pas sur un domaine non vérifié.
4. **`initiatives_set` sur chaque siège qui doit agir.** C'est le second oubli,
   et il est silencieux : un run de séquence réveille le siège, le siège n'a pas
   de charte, le tour rend `no_charter`, et le run attend vingt-quatre heures
   avant de s'arrêter en `not_sent`. Rien dans la réponse de `sequences_enroll`
   ne le dit. Poser la charte **avant** d'enrôler.
5. `prospects_import` en `dry_run: true` d'abord — l'en-tête attendu est celui
   de Smartlead, aux huit colonnes près, et le mode à blanc est la seule façon
   de le voir avant d'avoir importé la moitié d'un fichier.
6. `sequences_create`, puis `sequences_enroll`, puis `sequences_runs_list`.

**Ce qui n'arrivera pas au bout, et ce n'est pas une panne** — mesuré le
2026-09-17, marche complète contre le faux Resend : un siège
`sales-development` enrôlé sur une séquence prend son tour, lit son brief, et
**refuse d'écrire**. `rolepack_sales` livre `max_new_contacts_per_day: 0`, donc
démarcher un inconnu est fermé, et le siège l'écrit sur le bureau du fondateur
plutôt que de s'arrêter en silence. C'est la bonne réponse : la lever demande
un opérateur qui répond de la base légale, et aucun script ne le fait à sa
place. Ce qui part, en revanche, c'est une **réponse** — quelqu'un écrit à
`support@…`, la boucle entrante pose le message, le siège `customer-success`
répond, et la ligne `messages` porte le `provider_message_id` du fournisseur.
C'est ce chemin-là qui a été suivi de bout en bout.

## 7. Quand ça ne marche pas

| ce qu'on lit | ce que c'est |
|---|---|
| `role "anonymous" does not exist` | `DATABASE_URL` ne nomme pas d'utilisateur et sqlx a deviné. Le script le nomme ; si tu montes à la main, nomme-le. |
| `no_platform_policy` sur tout | `agentos-server policy install` n'a pas tourné. Aucun redémarrage nécessaire après. |
| `company_health_get` → `stopped`, `no_model` | `model_connect` n'a pas été appelé. |
| le tour rend `no_charter` | pas d'`initiatives_set` sur ce siège. |
| `cli_spawn_failed` / `cli_failed` | `claude` n'est pas sur le `PATH` du serveur, ou sa session a expiré. Relance `claude` à la main. |
| une file qui n'avance plus l'après-midi | le plafond journalier du domaine (`domains_cap_set`, 50 par défaut). |
| un siège qui lit `no_such_element` sur chaque page | pas de Chrome : `/readyz` rend `browser_js: false`. Installe Google Chrome, ou lis la ligne que le script imprime. |
| `EMAIL_API_BASE` refusée au démarrage | elle demande `AGENTOS_ALLOW_MOCKS=1`. Sur une machine de développement le script le pose ; ailleurs, c'est le refus qu'on veut. |
| `422 not_found` sur `domains_verify` | le fournisseur ne connaît plus le `provider_domain_id` que `tenant_domains` retient. Avec le faux, c'est un redémarrage sans `--etat`. Le domaine primaire ne se retire pas : repartir d'une base neuve. |
| le webhook répond 404 | l'URL collée chez le fournisseur n'est plus celle du tunnel du jour. Relis la ligne que `--recevoir` imprime. |
