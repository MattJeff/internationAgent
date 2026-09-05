# Déployer `agentos-server` sur le VPS de production

Plan préparé le 2026-08-30 contre l'état réel de `root@204.168.244.123`, en
lecture seule. **Rien de ce document n'a été exécuté sur le serveur.** Aucune
image n'a été tirée, aucun conteneur créé, aucun fichier écrit, aucun
`docker compose` lancé.

Le principe qui gouverne tout ce qui suit : **orizn.app et le backend `wandr`
n'apprennent jamais que ce déploiement existe.** Chaque décision ci-dessous est
prise pour que le retour arrière soit `docker compose down` sur *notre* pile, et
rien d'autre.

---

## 0. Ce que la machine contient réellement

18 conteneurs, tous `Up` depuis 3 à 4 semaines (sauf `orizn-web`, redémarré il y
a peu). Ubuntu 24.04, noyau 6.8, x86_64.

| Ressource | Constat |
|---|---|
| Disque | 61 Go utilisés sur 75, **12 Go libres (85 %)** |
| RAM | 15 Go au total, 3,5 Go utilisés, **11 Go disponibles** (dont 10 Go de cache) |
| Reverse proxy | **nginx sur l'hôte**, pas de conteneur proxy. 10 vhosts dans `/etc/nginx/sites-enabled/` |
| Pare-feu | `ufw` actif, `deny incoming` par défaut, seuls 22/80/443 + TURN sont ouverts |
| Registre | `/root/.docker/config.json` contient une entrée **`ghcr.io`** : la machine est déjà authentifiée |

### Le disque n'est pas plein, il est encombré

```
docker system df
Images          20   17   42.38GB   723.3MB reclaimable
Containers      19   18    3.141GB
Local Volumes    6    6    4.295GB
Build Cache    136    0   34.18GB   33.08GB reclaimable
```

**33 Go de cache de build BuildKit sont récupérables et ne servent rien qui
tourne.** C'est le levier le plus rentable de tout ce document et il ne touche
aucun conteneur en service. Voir §5 et §7 (étape 1) — avec une réserve : le
déploiement d'`orizn-verify` construit son image *sur la machine*, donc une
partie de ce cache lui fait gagner du temps. La variante douce est
`docker builder prune -f --filter until=168h`.

### Ports hôte déjà pris

`22, 80, 443, 3001-3010, 3100, 3478, 5000, 5349, 5432, 5672, 8080, 9000, 9001,
15672`.

**Le port 8080 de l'hôte est occupé par `webrtc-sfu`**, en `0.0.0.0`. Le
`EXPOSE 8080` du `Dockerfile` est interne au conteneur et n'entre pas en
conflit — mais toute publication sur l'hôte devra viser autre chose. Le premier
port libre dans la plage utilisée par la maison est **3011**. Ce plan n'en
publie aucun (§4).

### Réseaux Docker

`backend_data` (172.19.0.0/16) porte 14 conteneurs, dont **`orizn-web`**
(172.19.0.15) et `backend-postgres-1`. C'est le réseau par lequel `orizn-web`
doit nous joindre.

---

## 1. La base de données

### Le besoin, exactement

`migrations/0004_knowledge.sql` ligne 24 :

```sql
create extension if not exists vector;
```

et la colonne `embedding vector(1536)` avec un index HNSW
(`using hnsw (embedding vector_cosine_ops)`). Ce n'est pas négociable : la
migration échoue au premier démarrage sans l'extension, et `Db::migrate()` tourne
**au boot** avant que le listener ne se lie. Pas de pgvector, pas de serveur.

Une extension PostgreSQL n'est pas un `GRANT` : ce sont des fichiers
(`vector.control`, `vector.so`) présents sur le serveur, donc une propriété de
**l'image**. `CREATE EXTENSION` ne peut pas les installer.

### Constat, vérifié en lecture pure

```
find /var/lib/docker -name "vector.control"   →   aucun résultat
```

Ni `postgis/postgis:16-3.4-alpine` (`backend-postgres-1`, bases `wandr_*`), ni
`postgres:18-alpine` (`orizn-verify-prod-postgres-1`) ne portent pgvector.
Vérification faite sans `docker exec` — aucun processus n'a été lancé dans un
conteneur de production.

### Les options, et ce qu'elles coûtent

| | Option | Coût réel |
|---|---|---|
| **A** | **Nouveau conteneur `pgvector/pgvector:pg18`**, volume dédié, sur `backend_data`, sans port publié | ~450–700 Mo d'image, ~1 Go de RAM plafonnée, les données. **Zéro risque pour l'existant.** Se supprime avec `docker rm` |
| B | Ajouter pgvector à `backend-postgres-1` (postgis:16) | Il n'existe pas d'image officielle postgis+pgvector : il faudrait en construire une (**pas sur ce VPS**), puis **recréer le conteneur** → les 6 bases `wandr_*` et le site tombent le temps du swap. Et PG16 alors que le compose et la CI épinglent **pg18** |
| C | Ajouter pgvector à `orizn-verify-prod-postgres-1` (postgres:18) | Bonne version majeure, même objection : image à refaire, conteneur à recréer, et les données de `verify` partagent désormais notre sort |
| D | Postgres managé externe avec pgvector (Neon, Supabase…) | 0 Mo de disque, 0 Mo de RAM sur le VPS. Mais latence réseau sur chaque requête d'une boucle qui interroge toutes les 200 ms, dépendance externe, et **c'est une décision de dépense** → §9 |

### Recommandation : **A**, un conteneur dédié

L'argument tient en une asymétrie. Pour ajouter pgvector à l'un des deux clusters
existants (B ou C), il faut **remplacer son image et recréer le conteneur** —
c'est-à-dire couper le service qu'il sert, sans retour arrière qui ne le coupe
pas une seconde fois. Un conteneur neuf ne coûte que de la place et se détruit
sans que personne d'autre ne s'en aperçoive.

Deux raisons de plus, propres à ce schéma :

1. **`0001_core.sql` crée un objet à l'échelle du cluster** :
   `create role app_role nologin`, puis des `GRANT`/`REVOKE` table par table sur
   `public`. Partager un cluster, c'est mettre notre rôle RLS dans le même
   catalogue que l'administrateur de `wandr` ou de `verify`.
2. **RLS et le rôle de connexion.** `Db::tenant_tx` fait
   `SET LOCAL ROLE app_role` et les tables sont en `FORCE ROW LEVEL SECURITY` —
   donc se connecter en superutilisateur est sûr *et* c'est ce que le code
   attend. Sur un cluster à nous, le superutilisateur `postgres` a les droits
   `CREATE ROLE` et DDL que les migrations exigent (§1.3 d'OPERATIONS), et il n'y
   a rien à arbitrer. Sur un cluster partagé il faudrait un rôle de connexion
   dédié, membre de `app_role`, et un superutilisateur pour les seules
   migrations : deux comptes de plus dans une base qui n'est pas la nôtre.

Image `pgvector/pgvector:pg18` — la même que `docker-compose.yml` et que le
service Postgres de la CI. Le volume se monte sur **`/var/lib/postgresql`**, pas
`.../data` : pg18 refuse de démarrer sur l'ancien chemin
(docker-library/postgres#1259).

---

## 2. L'image : où la construire, comment elle arrive

**Pas sur le VPS.** 12 Go ne suffisent pas à un build release de ce workspace, et
le disque plein a déjà détruit un cluster ici aujourd'hui.

**Pas sur le Mac non plus**, et pour une raison qui n'est pas seulement la place :
le Mac est arm64, le VPS est x86_64. Un `--platform linux/amd64` sur le portable,
c'est une compilation Rust complète sous émulation — des heures, et plusieurs Go
sur une machine qui a 14 Go libres et un `target/` de 28 Go.

**Sur GitHub Actions**, donc : runner amd64 natif, gratuit, et c'est déjà par là
que les sept images `ghcr.io/mattjeff/wandr-*` arrivent sur ce serveur. La CI
actuelle construit l'image (`docker build --tag agentos-server:ci .`) mais ne la
pousse pas, volontairement — « publishing is a different workflow with different
secrets ». Il faut donc **un second workflow**.

`.github/workflows/publish.yml` :

```yaml
name: publish
on:
  push:
    tags: ["v*"]          # ou workflow_dispatch — jamais sur chaque push main
permissions: { contents: read, packages: write }
jobs:
  image:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v5
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      # Un seul tag, le sha. Pas de `latest` : un tag mutable est un retour
      # arrière qui n'a plus de cible.
      - run: |
          docker build -t ghcr.io/mattjeff/agentos-server:${{ github.sha }} .
          docker push  ghcr.io/mattjeff/agentos-server:${{ github.sha }}
```

Sur le VPS, la livraison est alors un `pull` et rien d'autre :

```bash
docker pull ghcr.io/mattjeff/agentos-server:<sha>
```

L'authentification `ghcr.io` est déjà en place dans `/root/.docker/config.json`.
Le paquet devra être rendu visible par l'organisation/le compte propriétaire (le
premier `pull` d'un paquet privé le dira).

**Taguer par sha de commit, jamais `latest`.** Le retour arrière est alors
« repose le sha précédent dans le fichier d'environnement, `up -d` », ce qui est
exactement le motif de `orizn-verify/rollout.sh` (`current` / `previous`) adapté
à une image qui vient d'un registre au lieu d'être construite sur place.

---

## 3. Les variables d'environnement

Source unique : `apps/server/src/config.rs`. Rien d'autre dans le binaire
n'appelle `std::env::var`, et le fichier le dit lui-même. **Une variable exportée
vide compte comme absente** — c'est délibéré.

### Obligatoires — le processus refuse de démarrer sans

| Variable | Valeur pour ce déploiement | Si absente |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:<mdp>@agentos-postgres:5432/agentos` | `refusing to start: DATABASE_URL is not set…` |
| `PUBLIC_HOST` | **schéma compris.** Voir §4 : tant que rien d'externe n'appelle, `http://agentos-server:8080` suffit ; le jour où un webhook arrive, ce doit être l'URL publique | Refus au boot. Interpolée dans la carte d'agent A2A (`{PUBLIC_HOST}/a2a/jsonrpc?employee=…`) : une mauvaise valeur envoie les pairs nulle part |
| `AGENT_EMAIL_DOMAIN` | le domaine d'envoi vérifié chez Resend — **pas à moi de le choisir**, §9 | Refus au boot |
| `AGENTOS_MASTER_KEY` | `openssl rand -base64 32`, **généré une fois** | Refus au boot |

#### `AGENTOS_MASTER_KEY` — à lire avant de la générer

C'est la racine du chiffrement enveloppe. **Chaque clé privée Ed25519 d'employé
est scellée dessous** (`employee_signing_keys.sealed_private_key`), ainsi que
chaque identifiant MCP de tenant depuis `0040_mcp_credentials`.

- **La changer en place orpheline toute identité déjà émise.** `UPDATE` est
  révoqué sur cette table et il n'existe aucun chemin de rotation : la
  récupération consiste à supprimer les lignes et à re-provisionner l'identité,
  ce qui change tous les `kid` publiés.
- Elle n'est **pas** couverte par un `pg_dump`. Elle se sauvegarde avec la base
  et se restaure avec elle. Une base restaurée sans sa clé donne toutes les clés
  publiques et aucun moyen de signer avec.
- Elle est validée « non vide » et rien de plus : ni décodée en hexadécimal, ni
  contrôlée en longueur, contrairement à ce que `.env.example` laisse croire.
  Elle est portée à 32 octets par SHA-256, pas par une KDF — donc l'entropie doit
  venir de la valeur elle-même.
- Le cas moins grave et plus visible : un `sealed_token` MCP qui ne s'ouvre plus
  sort de la flotte avec `secret_decrypt_failed` sur `GET /v1/mcp/servers`, et
  `POST /v1/mcp/connect` le répare.

**Générer une fois, écrire dans `.env.production` (mode 600), copier dans le
gestionnaire de secrets du fondateur avant le premier boot.**

### Ce qui sélectionne un adaptateur réel plutôt qu'un mock

Chaque variable est lue **une seule fois**, et cette lecture décide à la fois du
garde-fou et de la construction du client : ils ne peuvent pas diverger. La
sélection est **par adaptateur** — un réel et trois mocks est un déploiement
normal, pas une erreur.

| Variable | Absente | Présente |
|---|---|---|
| `EMAIL_API_KEY` | `MockEmailProvider` | construit le vrai client Resend (`re_…`) |
| `TELEPHONY_API_KEY` | `MockTelephony` | vrai client Twilio. Format `ACxxxx:auth_token` — **une moitié seule est un refus au boot nommé** |
| `BROWSER_API_KEY` | `MockBrowser` | vrai Browserbase + driver CDP. Format `project-id:api-key`, même refus sur une moitié |
| `EMBEDDER_API_KEY` | hash SHA-256 (`mock-sha256-1536`) | `OpenAiEmbedder`, `text-embedding-3-small`, sur la clé **du client** |
| `AGENTOS_LLM` | `mock` → répond `MOCK_REPLY` | `anthropic` (seul réel) ou `cli`. Une valeur inconnue est un refus qui liste les valeurs valides |
| `ANTHROPIC_API_KEY` | — | **exigée au boot** quand `AGENTOS_LLM=anthropic` |

Deux conséquences à connaître :

- **`AGENTOS_ALLOW_MOCKS=1` est obligatoire tant qu'un seul adaptateur est un
  mock**, sinon le processus refuse de démarrer en nommant lesquels et quelles
  variables les corrigeraient. C'est le comportement voulu, pas une gêne.
- **Poser `EMBEDDER_API_KEY` ne ré-embarque pas ce qui est déjà stocké.** Chaque
  chunk enregistre le modèle sous lequel il a été embarqué et chaque recherche
  lie un modèle : un corpus ingéré sur le hash garde `mock-sha256-1536` et cesse
  d'être trouvable jusqu'à réingestion. C'est une migration des documents du
  client, pas un redémarrage.

L'adaptateur email prend son secret de signature `whsec_…` dans l'entrée `email`
de `AGENTOS_WEBHOOK_SECRETS`, et son domaine d'envoi dans `AGENT_EMAIL_DOMAIN` :
ni l'un ni l'autre n'a de variable propre.

### Ce qui peut rester vide, et ce que ça coûte

| Variable | Défaut | Conséquence si vide |
|---|---|---|
| `APP_BIND` | `0.0.0.0:8080` | Correct ici (§4). Note : `.env.example` et le README disent 8090 — non défini vaut **8080** |
| `RUST_LOG` | `info,agentos_server=debug` | JSON sur stdout dans les deux cas |
| `AGENTOS_API_KEYS` | vide | Format `label:tenant-uuid:secret[,…]`, secret ≥ 32 caractères. Vide **et** sans clé plateforme = tout est 401 et rien ne peut l'y changer ; le serveur le crie au boot |
| `AGENTOS_PLATFORM_KEYS` | vide | `/v1/platform/*` répond 401 à tout le monde. Format `label:secret`, sans uuid, délibérément |
| `AGENTOS_WEBHOOK_SECRETS` | vide | Tout `/v1/webhooks/{path}` est un 404, aucun message entrant ne peut arriver. **Un seul tenant par provider** — deux entrées sur un même chemin est un refus au boot |
| `AGENTOS_OAUTH_CLIENTS` | vide | Aucun connecteur annoncé par `GET /v1/mcp/catalog`. Portée déploiement, jamais tenant |
| `MCP_BRIDGE_BIND` | non défini | **Hébergement MCP éteint** : tout binding répond `hosting_unavailable`. **À laisser non défini** — c'est un conteneur par slug qu'un tenant peut inventer, sur cette machine-ci |
| `MCP_BRIDGES_PER_TENANT` | `0` | Sans effet tant que `MCP_BRIDGE_BIND` est vide |
| `MCP_BRIDGE_IMAGE` | `node:22-alpine` | Idem |

Le coffre à secrets d'employé (`secrets=MOCK(in-memory)`) est un mock permanent
qu'aucune variable ne corrige. Il est nommé dans **chaque** ligne de boot, pour
qu'une ligne sans `MOCK` ne puisse pas être fabriquée par omission.

### Ce que le boot dit de lui-même

```
adapters: email=MOCK telephony=MOCK browser=MOCK embedder=MOCK
          llm=MOCK(mock) secrets=MOCK(in-memory)
```

`/readyz` republie la même chose sous `mock_adapters`, pour que la question
survive à la rotation des logs.

---

## 4. L'exposition : aucun port publié

`orizn-web` est sur **`backend_data`** (172.19.0.15) et sur `backend_default`.
Donc :

> **Notre conteneur rejoint `backend_data` et ne publie aucun port sur l'hôte.**
> `orizn-web` l'appelle par son nom DNS Docker : `http://agentos-server:8080`.

Ce que ça donne :

- **Rien à ajouter dans nginx.** Pas de vhost, pas de `proxy_pass`.
- **Rien à ajouter dans `ufw`.** Le pare-feu est déjà en `deny incoming` et le
  port n'existe pas sur l'hôte.
- **Rien à ajouter dans Cloudflare.** Pas d'enregistrement DNS, donc pas de
  surface publique.
- Le vhost `000-default-deny` renvoie déjà `444` à toute requête dont le `Host`
  ne correspond à rien — mais il n'a même pas à intervenir.

C'est plus étanche que le motif `127.0.0.1:PORT` + nginx utilisé par
`orizn-verify` et par les services `wandr`, parce qu'il n'y a pas de port sur
l'hôte du tout. Le seul appelant possible est un conteneur de `backend_data`.

**Déclarer le réseau `external: true`** dans notre compose : il appartient au
projet `backend`, notre pile ne doit ni le créer ni le supprimer.

### Ce que ça implique pour `PUBLIC_HOST`

`PUBLIC_HOST` est interpolée dans les cartes d'agent A2A et dans les URL de
webhook. Tant qu'aucun callback de provider n'est enregistré et qu'aucun pair A2A
n'existe, sa valeur est obligatoire mais sans effet observable :
`http://agentos-server:8080` est honnête et n'induit personne en erreur.

**Le jour où l'email devient réel**, Resend doit pouvoir livrer, et il faut alors
une surface publique — mais **seulement `/v1/webhooks/`**, jamais `/v1/*`. Le
vhost minimal, à ajouter ce jour-là et pas avant :

```nginx
# api-agents.orizn.app — À N'INSTALLER QUE QUAND UN WEBHOOK EXISTE.
# Publie /v1/webhooks/ et rien d'autre. Le reste de l'API reste interne.
server {
    listen 80;
    listen 443 ssl http2;
    server_name api-agents.orizn.app;
    ssl_certificate     /etc/ssl/certs/cloudflare-origin.pem;
    ssl_certificate_key /etc/ssl/private/cloudflare-origin.key;

    location /v1/webhooks/ {
        proxy_pass http://127.0.0.1:3011;   # 8080 est pris par webrtc-sfu
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location / { return 404; }
}
```

Et il faut alors publier `127.0.0.1:3011:8080` dans le compose. **Pas
maintenant** : c'est une surface d'attaque qu'aucun besoin actuel ne justifie.

---

## 5. Les ressources : est-ce que ça tient ?

### RAM — oui, largement

Consommation mesurée des 18 conteneurs : **~2,3 Go au total**. Le plus gros est
`backend-postgres-1` à 1,15 Go (plafond 2 Go). Tous les services `wandr` ont un
`mem_limit` de 384 Mo, `verify` 1 Go.

Notre pile, en suivant le même style :

| | Plafond | Attendu |
|---|---|---|
| `agentos-server` | 512 Mo | un binaire, 5 boucles tokio, un pool sqlx. Pas de JVM, pas de node_modules |
| `agentos-postgres` | 1 Go | même plafond que le Postgres de `verify` |

**~1,5 Go de plafond sur 11 Go disponibles.** Aucune tension.

### Disque — oui, **après** avoir vidé le cache de build

Le coût du déploiement :

| | Estimation |
|---|---|
| `pgvector/pgvector:pg18` | ~450–700 Mo |
| `agentos-server` (debian-bookworm-slim + un binaire) | ~150–250 Mo — **estimation, non mesurée**, voir §8 |
| Volume de données au départ | quelques dizaines de Mo, puis croissance |
| **Total ponctuel** | **~1 Go** |

1 Go sur 12 Go libres, ça passe. Mais **ça laisse la machine à 85 % de
remplissage**, sans marge pour un pic de WAL Postgres — et un disque plein a déjà
tué un cluster ici aujourd'hui.

**Soyons francs : à 12 Go libres c'est trop juste, et ce n'est pas la faute du
déploiement.** 33 Go de cache de build BuildKit dorment sur cette machine sans
rien servir de ce qui tourne. `docker builder prune` fait passer 12 Go à ~45 Go
et ne touche aucun conteneur en service. **Faire ça d'abord.** C'est la
différence entre un déploiement confortable et un déploiement qui joue avec le
même incident qu'il y a quelques heures.

Deux garde-fous à poser dès le départ, comme le fait `orizn-verify` :

- **Plafonner les logs** (`json-file`, `max-size: 10m`, `max-file: 5`). Le
  serveur écrit du JSON sur stdout à `agentos_server=debug` ; sans plafond un
  conteneur bavard remplit un disque de serveur et emporte la base avec lui.
- **Plafonner la mémoire** des deux conteneurs.

### Croissance à surveiller

Le magasin de fichiers est une colonne `bytea` dans Postgres (`files`, `0067`),
pas un bucket. **Les pièces jointes des mails entrants grossissent le volume de
la base**, pas MinIO. C'est ce qui décidera de la croissance réelle, et c'est
imprévisible depuis ici.

---

## 6. Le risque, et le retour arrière

### Ce qui peut casser sur cette machine

| Risque | Probabilité | Parade |
|---|---|---|
| **Le disque se remplit** et emporte un cluster | La plus réelle des six | `docker builder prune` avant tout (33 Go). Plafond de logs. Surveiller `df -h` |
| **Le réseau `backend_data`** : un `docker compose down` sur la pile `wandr` avec notre conteneur attaché | Faible | `external: true` dans notre compose. Notre pile ne crée ni ne supprime ce réseau. Docker refuse de supprimer un réseau encore utilisé |
| **Collision de port** | Nulle | Aucun port publié |
| **Collision de rôle/extension au niveau cluster** (`app_role`) | Nulle | Cluster dédié |
| **Une image tirée épuise le disque en plein `pull`** | Faible | Tirer l'image **avant** de toucher au compose, et vérifier `df -h` entre les deux |
| **`/readyz` reste 503** après le premier boot | **Certaine** — ce n'est pas une panne | `no_platform_policy` : le plafond de politique n'est pas installé. §7 étape 6. Le processus démarre quand même, exprès, pour laisser quelque chose à lire |

### Ce qui ne peut pas casser orizn.app

Par construction, ce déploiement :

- n'écrit rien dans `/etc/nginx` ;
- ne touche aucune règle `ufw` ;
- ne recrée, ne redémarre et ne reconfigure **aucun conteneur existant** ;
- ne publie aucun port hôte ;
- ne touche aucune base existante.

La seule interaction avec l'existant est un `docker network connect` sur
`backend_data`, qui ajoute une entrée DNS et ne modifie aucun conteneur déjà
attaché.

### Le retour arrière

```bash
cd /opt/agentos
docker compose -f docker-compose.prod.yml down          # les 2 conteneurs, rien d'autre
```

Le volume de données survit (`down` sans `-v`). nginx n'a jamais été rechargé.
`ufw` n'a jamais changé. orizn.app n'a rien su.

**Pour revenir à la version d'image précédente** : reposer le sha précédent dans
`.env.production`, `docker compose up -d`. C'est pour ça qu'on tague par sha et
jamais `latest`.

**La réserve honnête sur le retour arrière d'image** : les migrations tournent au
boot et il n'existe pas de migration descendante. Revenir à un sha antérieur
contre un schéma déjà migré n'est sûr que si la migration était tolérable par
l'ancienne version — c'est une discipline de déploiement (expand, deploy,
contract), et aucun script ne la remplace. `sqlx` prend un verrou consultatif sur
toute la série, donc plusieurs répliques qui démarrent ensemble se sérialisent au
lieu de courir ; ce n'est pas ce problème-là.

**Pour tout supprimer, volume compris** : `down -v`. Irréversible — et la clé
maîtresse ne sert alors plus à rien, voir §3.

---

## 7. La procédure, dans l'ordre

Chaque étape est à exécuter par le fondateur. Aucune n'a été lancée.

**1. Faire de la place — avant tout le reste.**

```bash
df -h /                                  # 12 Go
docker builder prune -f                  # ~33 Go de cache, aucun conteneur touché
# variante douce si le cache de build d'orizn-verify est encore utile :
#   docker builder prune -f --filter until=168h
df -h /                                  # attendu : ~45 Go
```

**2. Publier l'image** (GitHub Actions, §2) et vérifier qu'elle existe :

```bash
docker pull ghcr.io/mattjeff/agentos-server:<sha>
docker images ghcr.io/mattjeff/agentos-server
df -h /
```

**3. Vérifier l'image avant de la câbler à quoi que ce soit.** Un conteneur
jetable, sans base, sans réseau, sans variable :

```bash
docker run --rm --network none ghcr.io/mattjeff/agentos-server:<sha> doctor
echo "code de sortie: $?"      # DOIT être 1, avec une liste [MISSING]
```

C'est la vérification que je n'ai pas pu faire ici (§8). Si elle sort 0, ou si
elle panique, **arrêter là**.

**4. Poser l'arborescence.**

```bash
mkdir -p /opt/agentos && cd /opt/agentos
# docker-compose.prod.yml : ci-dessous
# .env.production : chmod 600, jamais dans git
```

`docker-compose.prod.yml` :

```yaml
# Pile AgentOS — deux conteneurs, aucun port publié.
#
# Joignable uniquement depuis le réseau `backend_data`, où vit orizn-web :
#   http://agentos-server:8080
#
# Le réseau appartient au projet `backend` (wandr) : `external: true` pour que
# cette pile ne le crée ni ne le supprime jamais.
name: agentos

x-logs: &logs
  driver: json-file
  options: { max-size: "10m", max-file: "5" }

services:
  postgres:
    container_name: agentos-postgres
    image: pgvector/pgvector:pg18
    restart: unless-stopped
    mem_limit: 1g
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD manquante}
      POSTGRES_DB: agentos
    # pg18 veut le montage sur /var/lib/postgresql, PAS .../data — l'image
    # refuse de démarrer sur l'ancien chemin (docker-library/postgres#1259).
    volumes: [agentos_pgdata:/var/lib/postgresql]
    # Aucun `ports:`. Rien de cette pile n'est joignable depuis l'hôte.
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d agentos"]
      interval: 5s
      timeout: 5s
      retries: 30
    networks: [agentos]
    logging: *logs

  server:
    container_name: agentos-server
    # Tag par sha, jamais `latest` : un tag mutable est un retour arrière sans
    # cible. Aucune section `build:` — cette image ne se construit pas ici.
    image: ghcr.io/mattjeff/agentos-server:${AGENTOS_SHA:?AGENTOS_SHA manquante}
    restart: unless-stopped
    mem_limit: 512m
    env_file: [.env.production]
    depends_on:
      postgres: { condition: service_healthy }
    # `agentos` pour la base, `backend_data` pour être joignable par orizn-web.
    networks: [agentos, backend_data]
    logging: *logs

volumes:
  agentos_pgdata:

networks:
  agentos:
  backend_data:
    external: true
```

`.env.production` (mode 600) :

```bash
AGENTOS_SHA=<sha>
POSTGRES_PASSWORD=<openssl rand -hex 24>

DATABASE_URL=postgres://postgres:<le même>@postgres:5432/agentos
PUBLIC_HOST=http://agentos-server:8080
AGENT_EMAIL_DOMAIN=<le domaine d'envoi vérifié — §9>
AGENTOS_MASTER_KEY=<openssl rand -base64 32 — GÉNÉRÉE UNE FOIS, SAUVEGARDÉE>

# Aucun adaptateur réel au premier boot : obligatoire, sinon refus de démarrer.
AGENTOS_ALLOW_MOCKS=1
AGENTOS_LLM=mock

AGENTOS_PLATFORM_KEYS=signup:<openssl rand -hex 32>
RUST_LOG=info,agentos_server=debug

# Volontairement non défini : MCP_BRIDGE_BIND. L'hébergement MCP reste éteint.
```

**5. Démarrer.**

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --wait postgres
docker compose --env-file .env.production -f docker-compose.prod.yml up -d server
docker compose logs -f server        # les migrations passent au boot
```

Trois lignes comptent dans le log : `provider adapters`, `RUNNING WITH MOCK
ADAPTERS` (attendu ici), et `listening`.

**6. Installer le plafond de politique.** Sans lui, le portail refuse **toute**
action pour **tout** tenant, et `/readyz` reste 503 `no_platform_policy`.

```bash
docker compose exec server agentos-server policy install
```

Il ne lit que `DATABASE_URL`. Idempotent : un second passage écrit `unchanged`.
Pas de redémarrage — le portail relit le plafond à chaque décision. Les valeurs
par défaut ($500 par transaction, $100 de seuil d'approbation, $2 000 par jour)
sont un **plafond**, pas une recommandation → §9.

**7. Vérifier depuis `orizn-web`, c'est-à-dire depuis le bon endroit.**

```bash
docker exec orizn-web wget -qO- http://agentos-server:8080/livez     # -> ok
docker exec orizn-web wget -qO- http://agentos-server:8080/readyz    # -> {"ready":true,...}
```

Puis vérifier que **personne d'autre** ne le joint :

```bash
curl -s --max-time 3 http://127.0.0.1:8080/livez   # -> le SFU, pas nous
ss -tlnp | grep -c ':8080'                          # inchangé
```

**8. Vérifier que rien n'a bougé.**

```bash
docker ps --format '{{.Names}}\t{{.Status}}' | wc -l   # 18 + 2 = 20
curl -sI https://orizn.app | head -1                   # 200
df -h /
```

---

## 8. Vérifications : ce qui a été fait, ce qui ne l'a pas été

### Fait — le binaire refuse proprement, sans base

Exécuté localement sur `target/debug/agentos-server` (build du 2026-08-30) :

| Cas | Résultat |
|---|---|
| `env -i agentos-server doctor` | **sortie 1**, 12 lignes `[MISSING]` nommant chaque variable et où trouver sa valeur, plus la ligne `boot` qui dit que le serveur refuserait de démarrer et pourquoi. Aucune panique, aucune base contactée |
| `env -i agentos-server` (servir) | **sortie 1**, `refusing to start: PUBLIC_HOST is not set, and there is no safe default for it` |
| Configuration complète, base injoignable | **sortie 1**, `refusing to start: database: pool timed out while waiting for an open connection`. Le `Debug` de la config est imprimé avant, avec `database_url: "<redacted>"` et `master_key: "<redacted>"` — sûr à coller dans un ticket |

### Fait — cohérence du `Dockerfile`

Les 6 membres du workspace (`crates/{domain,eval,store,providers,app}`,
`apps/server`) sont bien tous présents dans la couche de dépendances du
`Dockerfile`. C'est exactement le mode de casse que le commentaire du fichier
anticipe (« somebody adds a workspace member and does not add its Cargo.toml »),
et il ne s'est pas produit.

### Pas fait — le build local de l'image, et pourquoi

**Je ne l'ai pas construite.** La machine de développement a **14 Go libres**
(pas 27), un répertoire `target/` de **28 Go** et un `~/Library/Containers/
com.docker.docker/Data` de **40 Go**, avec le démon Docker éteint. Un build
release complet du workspace dans Docker aurait consommé plusieurs Go
supplémentaires pour aboutir à une image arm64 qui n'est de toute façon pas
celle qui sera déployée. Le rapport bénéfice/risque ne le justifiait pas — c'est
précisément le scénario « les vagues d'agents remplissent le disque ».

**Ce qui reste donc non vérifié**, et c'est un écart réel :

- que l'étape `runtime` démarre effectivement (glibc, `USER 10001:10001`,
  `ENTRYPOINT`) ;
- que `doctor` sorte 1 **depuis l'intérieur du conteneur**.

La CI construit l'image à chaque PR, donc *qu'elle se construise* est prouvé.
Ce qui ne l'est pas, c'est qu'elle **démarre** : la CI teste le `doctor` sur le
binaire debug (`env -i PATH="$PATH" ./target/debug/agentos-server doctor`), pas
sur l'image.

**L'étape 3 de §7 comble ce trou avant tout câblage.** Et pour le fermer
durablement, deux lignes à ajouter à `.github/workflows/ci.yml`, juste après
`the image builds` :

```yaml
      # L'image se construit — mais démarre-t-elle ? Le doctor sur le binaire
      # debug plus haut ne dit rien de l'étape runtime : glibc, uid 10001,
      # entrypoint. Ici, avec zéro configuration, il doit sortir non-zéro.
      - name: the image starts and its doctor refuses cleanly
        run: "! docker run --rm --network none agentos-server:ci doctor"
```

---

## 9. Les questions que je laisse au fondateur

Elles ne sont pas les miennes.

1. **Postgres sur la machine ou managé ?** Je recommande le conteneur dédié
   (§1). Un Neon/Supabase avec pgvector ne coûterait rien en disque ni en RAM
   sur ce VPS — mais c'est une dépense externe, et la note « rien à payer avant
   d'avoir construit » est une décision de fondateur, pas de plan de
   déploiement. À noter aussi : la boucle de provisioning interroge toutes les
   200 ms ; une base à un aller-retour Internet, ce n'est pas la même machine.

2. **Quel domaine d'envoi pour `AGENT_EMAIL_DOMAIN` ?** Il doit être vérifié
   chez le fournisseur d'email. Je ne peux pas l'inventer, et une mauvaise
   valeur ne se voit qu'au premier mail.

3. **`PUBLIC_HOST` et la surface publique.** Reste-t-on entièrement interne
   (recommandé maintenant), ou ouvre-t-on `api-agents.orizn.app` limité à
   `/v1/webhooks/` ? Cela demande un enregistrement Cloudflare, un vhost nginx
   et un port hôte (3011). Aucun besoin actuel ne le justifie.

4. **Démarrer avec `AGENTOS_ALLOW_MOCKS=1` ?** Ça veut dire un déploiement qui
   ne fait rien de réel : les employés répondent `MOCK_REPLY`, aucun mail ne
   part. C'est le bon premier pas pour valider la plomberie, mais c'est un choix
   à faire les yeux ouverts. L'alternative est d'attendre d'avoir
   `EMAIL_API_KEY` et `ANTHROPIC_API_KEY`.

5. **Le cache de build : 33 Go.** `orizn-verify` se construit sur cette machine,
   donc une partie de ce cache lui fait gagner du temps. Purge totale
   (`prune -f`) ou partielle (`--filter until=168h`) ?

6. **Le plafond de politique.** $500 par transaction, $100 de seuil
   d'approbation, $2 000 par jour, canaux `email, internal, web`, aucun domaine
   et aucun outil MCP autorisé. Ce sont des défauts, pas des recommandations, et
   les élargir est une décision d'opérateur.

7. **Les sauvegardes.** Rien ne sauvegarde ce nouveau volume. Toute la durabilité
   du système est cette base — pièces jointes comprises, elles sont en `bytea`
   dans `files`. Qui lance le `pg_dump`, à quelle fréquence, et où atterrit-il ?
   Et **la clé maîtresse se sauvegarde avec, au même endroit et avec le même
   soin** : une base restaurée sans elle est une base dont aucune identité ne
   peut plus signer.

8. **`ghcr.io/mattjeff/agentos-server` — visibilité du paquet.** Le VPS est
   authentifié sur `ghcr.io`, mais un nouveau paquet est privé par défaut et
   c'est le propriétaire du compte qui donne l'accès.

---

## 10. Ce qui, dans ce plan, me paraît risqué

Trois choses, par ordre décroissant.

1. **Le disque, et rien d'autre.** 12 Go sur une machine qui a perdu un cluster
   Postgres aujourd'hui pour cette raison. Le déploiement ne coûte qu'~1 Go,
   mais il l'ajoute au mauvais moment. **Purger le cache de build d'abord n'est
   pas une optimisation, c'est la condition.**

2. **Le premier boot exécute les migrations sur une base neuve.** 69 fichiers
   SQL, dont `create extension vector` et la création d'un rôle à l'échelle du
   cluster. Sur un cluster dédié c'est sans conséquence pour les autres — mais
   c'est aussi le moment où le disque est le plus sollicité, et un échec à
   mi-chemin laisse un schéma partiel. Les migrations sont écrites
   `IF NOT EXISTS` / `DROP`-puis-`CREATE` et sont rejouables, donc la reprise
   est de relancer ; mais vérifier `df -h` juste avant est gratuit.

3. **L'image n'a jamais démarré nulle part.** La CI prouve qu'elle se construit,
   pas qu'elle démarre. L'étape 3 de §7 est là pour ça et **ne doit pas être
   sautée** — c'est trente secondes contre la classe d'erreur qui se manifeste
   en boucle de crash à 3 h du matin.

Ce qui ne m'inquiète pas, et qui pourrait sembler devoir : la RAM (1,5 Go de
plafond sur 11 Go disponibles), les collisions de port (aucun port publié), et
l'impact sur orizn.app (aucun conteneur existant n'est touché, nginx n'est pas
rechargé, `ufw` n'est pas modifié).
