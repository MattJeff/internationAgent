# `@internationalagent/docker-mcp`

Un serveur MCP stdio qui parle à l'API du moteur Docker par sa socket unix, et
qui n'expose **que la moitié de cette API qui est une liste**.

---

## Les deux moitiés, et pourquoi une seule est ici

L'API du moteur Docker est documentée et ouverte ; écrire un serveur MCP qui la
parle est une journée de travail. Le piège est qu'un `POST /containers/{id}/exec`,
ou un `POST /containers/create` sur une image que le client nomme, **est
exactement l'interpréteur que `crates/app/src/mcp.rs` passe quatre-vingt-dix
lignes à refuser sous le nom de SSH** : `docker run -v /:/host alpine sh` est
root sur la machine, avec un autre chapeau. Un connecteur Docker qui expose
`exec` n'est pas un connecteur, c'est une session.

La décision est écrite et argumentée dans `crates/app/src/catalog.rs`, dans le
bloc au-dessus de `CATALOG` : **on expose la moitié qui est une liste, jamais
celle qui est un interpréteur.**

| Exposé | Refusé |
|---|---|
| lister les conteneurs, leur état, leurs journaux | `exec` sous toutes ses formes |
| inspecter, lire les statistiques, suivre les événements | `create`/`run` avec une image que le client nomme |
| démarrer, arrêter, redémarrer **un conteneur qui existe déjà, par son id** | tout montage hôte, `--privileged`, `network: host` |
| lister les images présentes | `commit`, `push`, la suppression de volumes ou d'images |

Cette moitié-là répond à ce qu'une équipe demande dix fois par jour — *est-ce que
ça tourne, pourquoi c'est tombé, redémarre-le* — et ne contient aucun verbe qui
invente un programme. Le `floor` de l'entrée de catalogue correspondante serait
`Write` : un redémarrage se refait, il ne se perd pas.

### Ce n'est pas une promesse, c'est un test

`test/forbidden.test.js` est le test le plus important du paquet. Une promesse
négative ne se prouve pas en appelant les outils — on ne peut pas appeler ceux
qui n'existent pas — donc il **lit le code et la table** :

1. **La table d'outils, nom par nom.** Les neuf noms sont écrits en dur dans le
   test ; en ajouter un dixième le casse.
2. **Le source, commentaires retirés.** Quatorze expressions interdites — `exec`,
   `create`, `run`, `commit`, `/push`, `/images/create`, `/build`, `HostConfig`,
   `Binds`, `Mounts`, `privileged`, `NetworkMode`, `/volumes`, les méthodes
   `DELETE`/`PUT`/`PATCH`, `prune`, `kill`, `attach`. Écrire le mot dans du code
   casse le test. Les commentaires ont le droit de nommer ce qu'ils refusent,
   c'est pour ça qu'ils sont retirés d'abord.
3. **Les gabarits de chemin, nourris d'arguments hostiles** (`../../exec`,
   `abc123abc123/exec`, `%2e%2e%2fexec`, `alpine sh -c id`) : ce qu'ils
   produisent doit être refusé par la couche HTTP.
4. **La couche HTTP elle-même**, appelée directement sur douze chemins interdits.
   `ALLOWED_PATHS` dans `src/docker.ts` est une liste littérale de quatre
   expressions, et rien d'autre ne fabrique de requête — un cinquième test
   compte les ouvertures de connexion et exige qu'il n'y en ait qu'une, dans
   `docker.ts`.
5. **Et une lecture qui garde les quatre autres** :
   `les interdits attrapent ce qu'ils prétendent attraper` vérifie que chaque
   expression interdite reconnaît bien un extrait hostile. Un test qui ne peut
   pas échouer est pire que pas de test ; celui-ci a été éprouvé en ajoutant un
   vrai outil `container_exec`, et **quatre tests sur seize sont tombés**.

---

## Les outils

Neuf, et pas un de plus.

| Outil | Méthode et chemin | Ce qu'il fait |
|---|---|---|
| `containers_list` | `GET /containers/json` | les conteneurs et leur état ; `all`, `limit`, `status`, `name` |
| `container_inspect` | `GET /containers/{id}/json` | la configuration complète d'un conteneur |
| `container_logs` | `GET /containers/{id}/logs` | les dernières lignes de stdout/stderr, **bornées** |
| `container_stats` | `GET /containers/{id}/stats` | CPU, mémoire, réseau, E/S bloc, un relevé |
| `images_list` | `GET /images/json` | les images déjà présentes ; ne va rien chercher au registre |
| `events_recent` | `GET /events` | ce qui s'est passé pendant une fenêtre **fermée** |
| `container_start` | `POST /containers/{id}/start` | démarre un conteneur qui existe déjà |
| `container_stop` | `POST /containers/{id}/stop` | SIGTERM puis SIGKILL après le délai |
| `container_restart` | `POST /containers/{id}/restart` | arrêt puis démarrage du même conteneur |

**L'identifiant est de l'hexadécimal, 12 à 64 caractères, et rien d'autre.** Le
démon accepterait aussi un nom ; on le refuse parce que le catalogue dit « par
son id », parce qu'un identifiant hexadécimal n'a aucune forme qui puisse
redevenir un morceau de chemin, et parce que le coût pour l'appelant est nul —
`containers_list` rend l'`Id` complet.

### Ce qui borne `container_logs`

Un conteneur bavard ne doit pas pouvoir remplir un tour, donc la borne est
**double** et elle est appliquée aux deux bouts :

| | défaut | maximum |
|---|---|---|
| lignes (`tail`, demandé au démon) | 200 | 2000 |
| octets rendus (`max_bytes`, coupé à la lecture) | 65 536 | 262 144 |

La lecture de la socket est coupée à `max_bytes × 2 + 8 × tail + 4096` octets —
le cadrage de huit octets par trame et les lignes qu'on va jeter doivent tenir
dans la lecture. Ce qui dépasse est coupé **par le début** : quand un conteneur
déborde, ce qui intéresse est ce qu'il a dit en dernier. La coupe est annoncée
en tête du texte rendu.

Toute autre réponse est plafonnée à 256 Kio, et un plafond atteint est une
erreur explicite (« restreignez la demande ») plutôt qu'un JSON tronqué.

### `events_recent` ne laisse pas de flux ouvert

`GET /events` sans `until` garde la connexion et attend le prochain événement,
c'est-à-dire pour toujours. Cet outil passe toujours `since` **et** `until`, ce
qui en fait une lecture de fenêtre et jamais un abonnement.

### `container_stats` coûte environ une seconde

`stream=false` et **pas** `one-shot=true` : `one-shot` rend `precpu_stats` à
zéro, donc un pourcentage CPU incalculable — la seule chose qu'on vient
chercher. Le prix est le temps de deux cycles du démon.

---

## Ce qui sort d'ici est `Untrusted`

Les noms d'images, les journaux, les libellés, les messages d'erreur, les
variables d'environnement rendues par `container_inspect` : **tout cela est du
texte écrit par quelqu'un d'autre.** Le nom d'une image vient d'un registre, une
ligne de journal vient du programme qui tourne dedans, un libellé vient de
quiconque a écrit le `Dockerfile`.

Côté runtime InternationalAgent, ce texte arrive `Untrusted` — c'est ce que
`crates/app/src/mcp.rs` garantit en rendant tout résultat d'outil dans un
`Untrusted<CallToolResult>`, pour qu'il ne puisse pas être recollé dans une
invite sans qu'un point d'appel le voie. **Rien dans ce paquet ne prétend le
contraire** : les réponses du démon sont passées telles quelles, sans être
reformatées en prose ni ré-étiquetées, précisément pour qu'aucune couche ici ne
puisse donner l'impression de les avoir vérifiées.

---

## Lancer

```sh
npm install && npm run build
node dist/index.js          # ou: npx @internationalagent/docker-mcp
```

Le serveur parle MCP sur stdin/stdout. Il ne sert rien sur le réseau ; pour
l'atteindre en Streamable HTTP, c'est `supergateway` qui s'en charge, comme
partout ailleurs dans ce dépôt :

```sh
npx -y supergateway --stdio "node /chemin/vers/dist/index.js" \
    --outputTransport streamableHttp --port 8931 --streamableHttpPath /mcp
```

### La variable d'environnement

Une seule : **`DOCKER_HOST`**.

| Valeur | Effet |
|---|---|
| absente | `/var/run/docker.sock` |
| `unix:///var/run/docker.sock` | ce chemin |
| `/chemin/absolu/vers/docker.sock` | ce chemin |
| `tcp://…`, `ssh://…`, `npipe://…` | **refus au démarrage**, avec un message |

`ssh://` est refusé parce que c'est littéralement le « droit d'exécuter ce que le
porteur décide » que le catalogue argumente sur quatre-vingt-dix lignes.
`tcp://` est refusé parce qu'une socket TCP sans mTLS est un démon root ouvert
sur un réseau, et que décider de la confiance à lui accorder n'est pas la
question à laquelle ce paquet répond. Le refus est au démarrage plutôt qu'à
l'appel : un serveur qui démarre puis refuse chaque appel est plus dur à
diagnostiquer qu'un serveur qui ne démarre pas.

### La version d'API

Les chemins sont préfixés par **`/v1.43`** (Docker Engine 24.0). La dernière est
1.55 (Engine 29.6/29.7, relevée le 2026-09-02) ; on vise le plancher commun
plutôt que le plafond, parce qu'un démon sert toutes les versions antérieures à
la sienne et refuse celles qu'il ne connaît pas. Docker 29.7 accepte encore
1.40. Le contrat de chaque chemin sort de la spécification OpenAPI que Docker
sert lui-même — `docs.docker.com/reference/api/engine/version/v1.43.yaml`, lue le
2026-09-02 — et pas d'un billet de blog.

### Les trois versions de `package.json`, et d'où elles sortent

`package.json` est du JSON : il ne porte pas de commentaire, donc les sources
des versions qu'il épingle sont ici. Relevées sur le registre npm le
2026-09-02 (`npm view <paquet> version`).

| Littéral | Source |
|---|---|
| `@modelcontextprotocol/sdk@^1.30.0` | 1.30.0 est la version courante publiée sur npm (publiée le 2026-07-27). L'API utilisée — `McpServer`, `registerTool`, `StdioServerTransport` — a été lue dans les `.d.ts` du paquet installé, pas de mémoire. |
| `zod@^3.25.76` | **v3 et pas v4, et c'est un choix contraint.** Le SDK déclare `zod: "^3.25 \|\| ^4.0"` : les deux marchent pour lui. On prend v3 parce que `Tool.input` est un `z.ZodRawShape` passé tel quel à `registerTool`, et que c'est la forme contre laquelle le SDK 1.30 a été lu. v4 est la version courante du registre (4.5.4) et sera une montée à faire, pas un oubli. |
| `engines.node >= 22` | **Le seul des trois qui n'est pas un fait mais une décision.** Le SDK lui-même dit `>= 18`. On monte à 22 parce que les tests sont `node --test` sans framework et que `index.ts` finit sur un `await` de premier niveau. |

---

---

## Les deux chemins de branchement

### Aujourd'hui : `CUSTOM`

C'est le chemin qui marche **maintenant**, et c'est exactement l'argument « SSH
est un déploiement, pas un connecteur ». Le client fait tourner ce serveur sur
sa machine, derrière `supergateway`, et colle l'adresse dans une liaison
`CUSTOM` :

* `provision: Provision::Customer` — la seule entrée du catalogue qui lit une URL
  dans le corps d'une requête ;
* `reach: Reach::Private` — le cas du sidecar, pour lequel `Reach::Private`
  existe ; il refuse toujours le link-local, donc le point de métadonnées du
  cloud reste hors de portée ;
* `floor: RiskClass::Read` — aucune prétention : nous n'avons pas vu ce serveur
  à cette adresse. Ce qui défend la liaison, c'est le contrôle d'adresse au
  moment du bind, l'épinglage SHA-256 de chaque outil déclaré, et le fait qu'un
  outil que personne n'a déclaré reste `Destructive`.

Le démon reste chez le client, sur sa machine, avec sa socket. Rien de ce
déploiement ne le touche.

### Le jour où le paquet est publié : `Provision::Host`

`Provision::Host` veut un `Package::spec` que **le binaire Rust nomme** et qu'on
accepte de faire tourner — un paquet npm à version épinglée. « Clonez et
compilez » n'est pas un spec, c'est un chantier, et c'est la raison pour laquelle
`docker/hub-mcp` (le serveur officiel de Docker Hub) n'a pas d'entrée : ni
endpoint hébergé, ni paquet publié. Ce paquet-ci n'a pas ce problème — il est
publiable — et l'entrée devient alors :

```rust
Connector {
    key: "docker",
    label: "Docker (le démon d'un serveur)",
    provision: Provision::Host(Package {
        spec: "@internationalagent/docker-mcp@0.1.0",  // version épinglée
        env: None,                                      // aucun credential
    }),
    reach: Reach::Public,          // inutilisé sur le chemin hébergé, voir `Connector::reach`
    credential: Credential::None,
    floor: RiskClass::Write,       // un redémarrage se refait, il ne se perd pas
    opt_outs: OptOuts::NoStrangers, // aucun outil ne prend l'adresse de qui que ce soit
}
```

**Et il y a un mur avant, qui n'est pas dans ce paquet.** Un bridge hébergé est
un conteneur *isolé* : `crates/app/src/hosted.rs` exige une racine en lecture
seule, aucun montage, et un réseau sans route vers Postgres. Un serveur MCP qui
parle à `/var/run/docker.sock` a besoin qu'on lui monte cette socket — c'est-à-dire
exactement le montage hôte que le contrat de conteneur interdit, et monter la
socket du démon dans un conteneur, c'est lui donner root sur l'hôte.

Donc `Provision::Host` **ne convient pas pour piloter le démon d'un client** : le
bridge tourne chez nous et le démon est chez lui. Il conviendrait pour un serveur
qui parle à une API distante — Docker Hub, par exemple. Pour le démon d'un
serveur, `CUSTOM` n'est pas une étape en attendant mieux : c'est la bonne réponse,
et c'est le même argument, une couche plus bas.

---

## Développer

```sh
npm install
npm run build
npm test        # 16 tests, node --test, aucun framework — et aucun besoin d'un démon Docker
```

Aucun test n'exige un démon Docker qui tourne : les tests de refus s'arrêtent
avant d'ouvrir la socket, le désentrelacement est nourri de trames construites à
la main, et la poignée de main MCP lance le binaire et lui demande `tools/list`,
qui ne fait aucune requête au démon.
