# Le serveur MCP — piloter la société depuis un terminal

`POST /v1/mcp/server`. Un serveur MCP qui expose **les routes de ce déploiement**
comme outils, pour que le Claude Code du fondateur — sur sa machine, sous ses
identifiants — puisse embaucher, relancer, facturer et lire le journal sans
ouvrir la console.

Code : `apps/server/src/routes/mcp_server.rs` (l'exécuteur et le transport),
`crates/app/src/mcp_server.rs` (le contrat d'une ligne),
`crates/app/src/mcp_tools/` (les lignes, un module par domaine).

Ne pas confondre avec `apps/server/src/routes/mcp.rs`, qui est **l'autre sens** :
le client MCP, celui qui appelle les serveurs des autres (GitHub, Smartlead, la
boîte du client). Celui-ci n'appelle personne.

---

## 1. Pourquoi un serveur, et pas l'abonnement sur le VPS

La question posée était : peut-on mettre l'abonnement Claude du fondateur sur le
VPS et laisser la société s'en servir ? La réponse est non, et **la raison n'est
pas celle qu'on croyait**.

Vérifié le **2026-09-10**, en lisant le HTML des pages et non un résumé :
**aucun** document publié par Anthropic ne contient de clause nommant
l'arrangement « un service hébergé qui intermédie l'accès à Claude au nom d'un
utilisateur » pour l'interdire. Il n'y a pas de numéro de clause à citer. Ce qui
l'interdit est la **conjonction** de deux phrases, qu'il faut citer séparément.

**Conditions d'utilisation consommateur** — <https://www.anthropic.com/legal/consumer-terms>,
mention imprimée sur la page : `Effective October 8, 2025`. Section
`2. Account creation and access.`, sous l'intertitre `Your Anthropic Account.`
(la phrase elle-même n'est pas numérotée) :

> « You may not share your Account login information, Anthropic API key, or
> Account credentials with anyone else or make your Account available to anyone
> else. You are responsible for all activity occurring under your Account […] »

C'est la phrase porteuse. `make your Account available to anyone else` atteint un
intermédiaire hébergé ; elle ne parle ni de serveur ni d'intermédiation.

Même document, section `3. Use of our Services.`, dans la liste à puces
introduite par « You may not access or use, or help another person to access or
use, our Services in the following ways: » :

> « Except when you are accessing our Services via an Anthropic API Key or where
> we otherwise explicitly permit it, to access the Services through automated or
> non-human means, whether through a bot, script, or otherwise. »

C'est celle qui mord le plus directement sur un binaire côté serveur piloté par
un abonnement : un processus Claude Code lancé par notre backend est un accès
automatisé, non humain, et pas par une clé d'API.

Deux mises en garde, parce qu'une doc qui surinterprète est une doc qui se
retourne :

* La même liste contient « To develop any products or services that compete with
  our Services, including to develop or train any artificial intelligence or
  machine learning algorithms or models or resell the Services. » Le `resell` y
  est grammaticalement accroché à la liste « concurrencer / entraîner ». Ce n'est
  **pas** une clause anti-revente autonome ; ne pas s'appuyer dessus seul.
* La page est **géo-servie**. L'édition lue ici est celle d'Anthropic Ireland
  Limited (EEE et Suisse) — elle le dit en tête. La phrase sur le compte est
  attendue dans les deux éditions ; le « Non-commercial use only » de la section
  10 est propre à l'édition EEE et **ne doit pas** être cité pour un lecteur hors
  EEE sans avoir relu la page servie là-bas.
* La *Usage Policy* (<https://www.anthropic.com/legal/aup>, `Effective September
  15, 2025`) ne contient **rien** sur le partage de compte ni sur la revente
  d'accès. Sa première phrase va même dans l'autre sens — elle étend la politique
  aux utilisateurs finaux « via any authorized resellers or passthrough access »,
  c'est-à-dire qu'elle prévoit le passe-plat *autorisé* plutôt qu'elle ne
  l'interdit. Ne pas la citer comme si elle interdisait quoi que ce soit ici.

Ce que les Conditions font, plutôt que de nommer et interdire ce montage, c'est
de **router** l'accès programmatique et multi-utilisateur vers l'API sous les
*Commercial Terms* (<https://www.anthropic.com/legal/commercial-terms>,
`Effective June 17, 2025`), qui disent en préambule : « Services under these
Terms are not for consumer use. Our consumer offerings (e.g., Claude.ai) are
governed by our Consumer Terms of Service instead. »

**Le sens inverse ne pose aucune de ces deux questions.** Le fondateur lance
*son* Claude Code, sur *sa* machine, sous *ses* identifiants, et ce client se
connecte à un serveur MCP tiers. Il n'y a ni compte rendu disponible à autrui, ni
accès non humain : il y a un humain devant un terminal. C'est ce que ce module
rend possible, et c'est la seule forme qui tienne sans avoir à interpréter une
phrase.

---

## 2. L'installer

Vérifié dans la documentation de Claude Code le **2026-09-10** —
<https://code.claude.com/docs/en/mcp> (la page ne porte pas de date de mise à
jour visible ; elle se date par ses mentions de version, du type « requires
Claude Code v2.1.265 »). La forme documentée, verbatim :

```bash
claude mcp add --transport http <name> <url> \
  --header "Authorization: Bearer your-token"
```

Pour ce déploiement :

```bash
claude mcp add --transport http siglair https://siglair.com/v1/mcp/server \
  --header "Authorization: Bearer <la clé du locataire>"
```

Ce que la page dit d'autre, et qui compte :

* `--transport http` — pas de forme courte documentée (`-t` et `-H` n'apparaissent
  dans aucun exemple). Le nom et l'URL sont **positionnels**, dans cet ordre,
  après le drapeau.
* `--header "Clé: Valeur"`, guillemets compris. Plusieurs en-têtes : plusieurs
  `--header`. Le séparateur `--` ne concerne que les arguments d'un serveur
  stdio.
* En JSON (`.mcp.json`, `~/.claude.json`, `claude mcp add-json`), le champ `type`
  accepte `streamable-http` comme alias de `http`.

Vérifier :

```bash
claude mcp list          # tous les serveurs configurés
claude mcp get siglair   # le détail de celui-ci
```

et, depuis Claude Code, `/mcp`.

La clé est une clé de locataire ordinaire — une entrée de `AGENTOS_API_KEYS`, ou
une clé émise par `POST /v1/platform/keys`. Voir `OPERATIONS.md` §1.4. **Rien de
spécifique au MCP n'est à provisionner** : pas de compte, pas d'OAuth, pas de
rôle à part.

---

## 3. Ce que couvrent les outils

La liste qui fait foi est `tools/list` — c'est le registre, rendu. Ce qui suit
dit comment il est découpé, pas ce qu'il contient : au 2026-09-10 les trois
modules sont écrits et vides, remplis par trois chantiers en parallèle.

Un outil par route utile de `/v1/*`, groupés en trois domaines
(`crates/app/src/mcp_tools/`) :

| domaine        | ce qu'on y fait                                                              |
|----------------|------------------------------------------------------------------------------|
| `societe`      | ce que la société **est** : employés, équipes, entreprises, limites, arrêt   |
| `commerce`     | ce qu'elle **vend** : prospects, séquences, devis, factures, rendez-vous     |
| `exploitation` | ce qu'elle **exploite** : journal, dépenses, files, approbations, rapports   |

Chaque outil déclare un risque, et le risque devient l'annotation que le client
lit pour décider quoi faire confirmer :

| `Risk`        | `readOnlyHint` | `destructiveHint` | ce que ça veut dire                     |
|---------------|----------------|-------------------|-----------------------------------------|
| `Read`        | `true`         | `false`           | ne change rien                          |
| `Write`       | `false`        | `false`           | écrit, crée, met à jour ; rien ne disparaît |
| `Destructive` | `false`        | `true`            | retire, annule, ou engage la société devant un tiers |

Une ligne qui ment sur son risque fait cliquer « oui » sans lire. C'est la seule
partie de la table qu'aucun test ne peut vérifier à votre place.

---

## 4. La règle : un outil est une ligne

C'est le cœur du dessin, et il faut le tenir pour que le reste marche.

Un outil ne **fait** rien. Il déclare une route — une méthode, un chemin, un
schéma d'entrée, un risque — et un exécuteur unique la joue *en interne* sur le
`Router` d'axum déjà construit (`tower::ServiceExt::oneshot`, aucun aller-retour
réseau, aucune socket).

```rust
ToolDef {
    name: "employees_suspend",
    title: "Suspendre un employé",
    description: "…et quand s'en servir",
    method: Method::Post,
    path: "/v1/employees/{id}/suspend",
    schema: json!({"type": "object",
                   "properties": {"id": {"type": "string"}},
                   "required": ["id"]}),
    query: &[],
    risk: Risk::Write,
}
```

Ce que le chemin, `query` et le schéma décident ensemble :

* les trous `{ainsi}` sont remplis depuis les arguments et **encodés** — un
  identifiant peut contenir un `/`, et un `/` non encodé n'est pas un caractère
  de plus dans un segment, c'est un segment de plus dans le chemin ;
* les propriétés que `query` nomme partent en chaîne de requête ;
* **tout le reste du schéma devient le corps JSON**, et un corps vide n'est pas
  envoyé du tout — c'est ce qui distingue un `DELETE` d'un `POST {}` ;
* une propriété absente des arguments n'est **jamais** envoyée (`?status=` dit
  « filtre sur la chaîne vide », ce qui n'est pas « ne filtre pas ») ;
* un argument que le schéma ne nomme pas est **refusé avant l'appel**.

Trois conséquences, et ce sont elles qu'on achète :

1. **Tout ce que le site sait faire est atteignable.** Une fonctionnalité qui a
   une route peut avoir un outil, pour le prix d'une ligne.
2. **Les permissions ne sont pas réinventées.** L'en-tête `Authorization` du
   client MCP est recopié tel quel dans la requête interne, qui traverse
   `with_api_stack` : la Gate, les rôles, la limite de débit et l'isolation par
   locataire s'appliquent sans une ligne de plus. Un refus remonte au client avec
   le `code` et le `detail` que le produit écrit déjà (le document RFC 9457 de
   `crate::error`), jamais reformulé.
3. **Rien ne dérive.** Corriger la route corrige l'outil. Un gestionnaire par
   outil aurait été une deuxième implémentation de chaque règle, et deux
   implémentations divergent le jour où l'une est corrigée.

### Ce qu'un outil ne peut pas être

Aucune ligne ne pointe sur `/v1/mcp/server` : ce serait une récursion dont le
fond est la pile. Deux gardes, parce qu'elles protègent de deux fautes
différentes :

* **structurelle** — l'exécuteur reçoit l'étage `api` du routeur, construit
  *avant* que la route MCP y soit greffée. La boucle n'est pas seulement
  interdite, elle n'est pas exprimable ;
* **déclarative** — `no_tool_can_call_the_mcp_server_back` relit toute la table à
  chaque `cargo test`, pour la ligne ajoutée par distraction.

---

## 5. Le protocole

JSON-RPC 2.0 sur `POST /v1/mcp/server`, MCP `2025-06-18`. **Trois méthodes**, et
c'est tout ce qui est implémenté :

| méthode      | clé requise | ce qu'elle rend                                                    |
|--------------|-------------|--------------------------------------------------------------------|
| `initialize` | non         | `protocolVersion`, `serverInfo {name: "siglair", version}`, `capabilities.tools.listChanged: false`, et une `instructions` en français |
| `tools/list` | oui         | la table, avec `title`, `inputSchema` et `annotations`              |
| `tools/call` | oui         | le résultat en `content: [{type: "text", text: <JSON indenté>}]`, ou `isError: true` portant le document du produit |

Toute autre méthode : `-32601`. Une requête sans `id` est une notification —
Claude Code envoie `notifications/initialized` juste après la poignée de main —
et reçoit un `202` sans corps, comme le demande le transport HTTP de MCP.

`initialize` passe **sans clé** parce qu'un client sonde avant d'avoir présenté
quoi que ce soit, et qu'un 401 sur cette sonde est un serveur qui ne s'affiche
jamais dans le terminal. `tools/list` et `tools/call` exigent la clé, par la même
fonction du même trousseau que toutes les autres routes (`Keyring::principal_of`)
et rendue par le même `auth::unauthorized()` : le refus est le document
`unauthenticated` habituel, `WWW-Authenticate` compris.

### Pourquoi le protocole est écrit à la main

`rmcp` est dans le workspace en `default-features = false` avec **seulement** les
features client — c'est `agentos_app::mcp`. Activer la moitié serveur ferait
entrer un transport, un cycle de vie de session, un routeur d'outils et un jeu de
types dérivés d'une macro, pour un besoin qui tient en un `match` sur trois noms.
Le dépôt a déjà tranché ainsi une fois : CDP est du JSON-RPC sur une websocket, et
`crates/providers` le parle à la main plutôt que d'embarquer chromiumoxide.

---

## 6. Ajouter un outil

1. Ouvrir le module du bon domaine dans `crates/app/src/mcp_tools/`.
2. Ajouter une `ToolDef`. Chaque trou du chemin **doit** être une propriété du
   schéma — `every_hole_of_every_tool_is_a_property` échoue sinon, et sans lui
   l'URL partirait avec `{id}` en toutes lettres.
3. Le nom est `domaine_verbe`, en minuscules, sans tiret (certains clients les
   refusent). Il doit être unique dans tout le registre.
4. La `description` dit ce que ça fait **et quand s'en servir** : c'est ce que le
   modèle lit pour choisir, donc la seconde moitié compte autant que la première.
5. `cargo test -p agentos-app -p agentos-server`.

Il n'y a rien d'autre à écrire. Pas de gestionnaire, pas d'enregistrement, pas de
test par outil — la route est déjà testée, et l'exécuteur l'est une fois pour
toutes.
