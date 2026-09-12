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
* **Ce n'est pas une démonstration à distance.** Le serveur écoute sur
  `127.0.0.1`. Ce n'est pas un durcissement de plus, c'est ce qui rend la phrase
  « il n'y a qu'un humain, devant son terminal » vraie.

## 4. Les faux adaptateurs, et le drapeau qui les enlève

Par défaut, `email`, `telephony`, `browser` et `embedder` sont faux, et le
serveur le dit au démarrage, à `warn`, à chaque fois. Un tour va jusqu'au bout —
la Gate décide, la séquence avance, le journal s'écrit — mais **rien ne sort de
la machine**. C'est le défaut parce qu'un e-mail est irréversible et qu'un
prospect réel n'est pas un décor de démonstration.

`--reel` remplace le seul adaptateur qui compte, l'e-mail, par Resend. Il exige
`EMAIL_API_KEY`, il exige `AGENT_EMAIL_DOMAIN` — un domaine **vérifié**, sinon
Resend refuse chaque envoi — et il exige un `OUI` tapé à la main après avoir
écrit ce que ça implique. Les trois autres restent faux : il n'y a pas de raison
d'acheter un numéro de téléphone pour prouver qu'un e-mail part.

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

## 7. Quand ça ne marche pas

| ce qu'on lit | ce que c'est |
|---|---|
| `role "anonymous" does not exist` | `DATABASE_URL` ne nomme pas d'utilisateur et sqlx a deviné. Le script le nomme ; si tu montes à la main, nomme-le. |
| `no_platform_policy` sur tout | `agentos-server policy install` n'a pas tourné. Aucun redémarrage nécessaire après. |
| `company_health_get` → `stopped`, `no_model` | `model_connect` n'a pas été appelé. |
| le tour rend `no_charter` | pas d'`initiatives_set` sur ce siège. |
| `cli_spawn_failed` / `cli_failed` | `claude` n'est pas sur le `PATH` du serveur, ou sa session a expiré. Relance `claude` à la main. |
| une file qui n'avance plus l'après-midi | le plafond journalier du domaine (`domains_cap_set`, 50 par défaut). |
