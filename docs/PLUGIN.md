# Le plugin Claude Code — l'interface par-dessus les 116 outils

Le serveur MCP (`docs/MCP_SERVEUR.md`) rend 116 outils. Brancher une URL et une
clé donne 116 verbes bruts et aucun mode d'emploi : le modèle doit deviner
qu'on lit `health_company` avant de croire un chiffre, qu'un import se fait à
blanc d'abord, qu'une action d'approbation se recopie octet par octet.

Ce plugin est cette moitié manquante. Une commande d'installation, et le
fondateur a **quatre gestes nommés** plutôt qu'un catalogue.

---

## 1. L'installation, en trois lignes

```
/plugin marketplace add MattJeff/InternationalAgent
/plugin install siglair@siglair
```

et, quand l'installateur demande la **clé d'API du locataire**, la coller.

Vérifier : `/mcp` doit montrer `siglair` connecté, et `/help` (onglet *Custom
commands*) les quatre gestes sous le préfixe `siglair:`.

Le dépôt est privé : `/plugin marketplace add` sur une source GitHub privée
suppose un `gh` authentifié sur la machine du fondateur.

## 2. La règle sur la clé — et pourquoi c'est celle-là

**Aucun fichier versionné de ce dépôt ne contient de clé, et le dépôt d'un
client n'en contiendra jamais non plus.**

Le manifeste déclare la clé comme une entrée `userConfig` marquée
`"sensitive": true` ; `plugin/.mcp.json` ne porte que la référence :

```json
"headers": { "Authorization": "Bearer ${user_config.cle_api}" }
```

Ce que ce choix achète, par rapport aux deux autres chemins documentés :

* contre **une clé en clair dans `.mcp.json`** — il n'y a rien à oublier de
  retirer avant un `git add`, parce qu'il n'y a rien à écrire ;
* contre **une variable d'environnement `${SIGLAIR_API_KEY}`**, que la page
  `/mcp` documente pour `.mcp.json` — la variable finit dans un `.zshrc`, donc
  dans une sauvegarde, et l'installation demande au fondateur d'éditer un
  fichier de shell avant de pouvoir essayer le produit. Le champ `sensitive` est
  masqué à la saisie et **stocké dans le trousseau, pas dans `settings.json`**.

Un deuxième champ, `base_url`, a un défaut (`https://siglair.com`) et n'est là
que pour viser un déploiement de recette. Il n'est pas sensible.

**Si une version de Claude Code ne demande pas la clé à l'installation**, le
chemin de repli est celui de `docs/MCP_SERVEUR.md` §2 — `claude mcp add
--transport http siglair https://siglair.com/v1/mcp/server --header
"Authorization: Bearer <clé>"` — et les quatre skills fonctionnent par-dessus
sans changement, puisqu'ils ne nomment que des outils.

## 3. Les quatre gestes

Un geste n'est pas une liste d'outils : il dit **dans quel ordre** appeler, ce
qu'on lit entre deux étapes, et ce qu'il ne faut jamais faire. Chacun porte une
phrase de garde.

| Geste | La question | La garde |
|---|---|---|
| **`point-du-jour`** | « où en est ma société ? » | N'approuve, ne refuse, n'enrôle et n'embauche rien : c'est une lecture. |
| **`lancer-une-campagne`** | de l'import d'une liste au premier envoi | Jamais `sequences_enroll` avant que `domain_get` ait rendu le domaine **vérifié**. |
| **`repondre-aux-demandes`** | vider la file humaine | Ne jamais reformuler l'action d'une approbation ; ne jamais approuver sa propre demande. |
| **`embaucher`** | un siège, sa place, sa charte, ses limites | `policy_role_put` est un document entier : un champ manquant est un retrait. |

**`point-du-jour`** — `health_company` **d'abord et toujours** (un `stopped`
arrête la lecture et renvoie vers `model_status` ; une société au repos rend
`working`, pas `degraded`), puis `approvals_list` + `capability_requests_list` +
`work_board` pour ce qui attend une décision — les lignes de plus de 24 h
comptées à part, parce que rien ne sort de cette file tout seul —, puis
`outreach_summary` et `outreach_health` pour la prospection, puis `pnl_read` et
`invoices_list` pour l'argent. Finit par trois phrases et une question.

**`lancer-une-campagne`** — le domaine en premier parce que c'est la seule étape
qu'on ne rattrape pas (`domain_list` → `domain_dns` → `domain_verify`), sa
réputation et son plafond (`outreach_health`, `domain_set_cap`), le segment lu
depuis `prospects_segments`, l'import **`dry_run: true` d'abord** puis réel, la
séquence (`sequences_list`, `sequences_define`), l'enrôlement
(`sequences_enroll`), la vérification (`sequences_runs`). Les trois pièges qu'il
nomme : le **plafond journalier par domaine s'épuise** — c'est la première
explication d'une file qui n'avance plus l'après-midi —, le **mode à blanc est
obligatoire** parce qu'il est la seule façon de voir un en-tête de travers avant
d'avoir importé la moitié d'un fichier, et une **séquence ne poste rien
elle-même** : un pas `email` porte un brief et réveille un siège qui écrit.

**`repondre-aux-demandes`** — `approvals_list` traité **du plus récent au plus
ancien** (la tête de file est le travail le plus certainement mort),
`approvals_get` pour lire l'action exacte, `approvals_approve` avec cette action
recopiée sans un octet de différence ou `approvals_deny` avec une note, puis les
`capability_requests_*` — accorder n'élargit rien, il reste à installer la
couche — et enfin `desk_send` depuis un fauteuil pour dire à l'employé ce qui a
été décidé et pourquoi.

**`embaucher`** — `teams_list` pour savoir sous quel `role_name` ses limites
seront lues, `employees_create` (202 et non 201 : commandé, pas embauché) ou
`org_apply` pour plus d'un siège, `teams_member_add` / `teams_member_set` pour
la position, `teams_mission_set` + `initiative_set` pour la charte — ni l'une ni
l'autre n'est une limite —, `policy_role_get` puis `policy_role_put` et
`spend_caps_set` pour les limites, et enfin `employees_get` + `controls_get`
pour vérifier qu'il s'est provisionné.

## 4. Les trois commandes courtes

`plugin/commands/{point,campagne,demandes}.md` donnent une invocation brève avec
un argument. **Elles ne s'appellent pas `/siglair-point`** : la documentation dit
que les skills d'un plugin sont *toujours* namespacés `/<nom-du-plugin>:<nom>`,
et il n'existe aucun champ pour changer le séparateur. La forme atteignable la
plus proche est donc, le plugin s'appelant `siglair` :

```
/siglair:point 7d
/siglair:campagne agences-marketing
/siglair:demandes
```

Les quatre gestes complets restent invocables directement —
`/siglair:point-du-jour`, `/siglair:lancer-une-campagne`,
`/siglair:repondre-aux-demandes`, `/siglair:embaucher` — et les trois gestes de
lecture-décision sont aussi choisis tout seuls par le modèle quand la question
les appelle. Les trois commandes courtes portent `disable-model-invocation:
true` pour ne pas doubler les skills dans ce choix.

## 5. L'arborescence, et pourquoi le marketplace est à la racine

```
.claude-plugin/marketplace.json      ← le catalogue, imposé à la racine du dépôt
plugin/
  .claude-plugin/plugin.json         ← le manifeste, dont userConfig
  .mcp.json                          ← le serveur siglair, en http
  skills/{point-du-jour,lancer-une-campagne,repondre-aux-demandes,embaucher}/SKILL.md
  commands/{point,campagne,demandes}.md
```

Le `marketplace.json` **doit** être à `<racine-du-dépôt>/.claude-plugin/` : c'est
là que la forme courte `owner/repo` de `/plugin marketplace add` va le chercher.
Le plugin lui-même vit dans `plugin/`, déclaré par `"source": "./plugin"` — un
chemin relatif à la racine du marketplace, pas au dossier `.claude-plugin/`.

Rien d'autre ne va dans `.claude-plugin/` : `skills/`, `commands/` et `.mcp.json`
sont à la racine **du plugin**, et les y mettre est l'erreur que la doc signale
en premier.

## 6. Les sources, datées

Relevées le **2026-09-11**. Aucune de ces pages ne porte de date de mise à jour
visible ; elles se datent par leurs mentions de version (« requires Claude Code
v2.1.265 »).

| Ce qui en vient | Page |
|---|---|
| `.claude-plugin/plugin.json`, le `name` obligatoire, `userConfig` et `sensitive`, `${user_config.KEY}` dans une config MCP, le format `.mcp.json` d'un plugin, le frontmatter d'un `SKILL.md`, les fichiers plats de `commands/` | <https://code.claude.com/docs/en/plugins-reference> |
| La disposition `skills/<nom>/SKILL.md`, l'avertissement « ne mettez pas `commands/`, `skills/` dans `.claude-plugin/` », `--plugin-dir`, `/reload-plugins` | <https://code.claude.com/docs/en/plugins> |
| `<racine>/.claude-plugin/marketplace.json`, `"source": "./plugin"` relatif à la racine du marketplace, `/plugin marketplace add owner/repo`, `/plugin install nom@marketplace`, les dépôts privés | <https://code.claude.com/docs/en/plugin-marketplaces> |
| Les champs de frontmatter tous facultatifs sauf les marqueurs, `$ARGUMENTS`, `${CLAUDE_PLUGIN_ROOT}`, `disable-model-invocation`, le namespace `/<plugin>:<skill>` | <https://code.claude.com/docs/en/skills> |
| `"type": "http"` avec `url` et `headers`, l'expansion `${VAR}` et `${VAR:-défaut}` dans `.mcp.json`, et « ne committez pas de secrets » | <https://code.claude.com/docs/en/mcp> |

Rien n'a été écrit ici qui ne soit dans une de ces cinq pages. Un champ non
documenté n'a pas été inventé — c'est pourquoi le manifeste ne porte pas de
`license` ni de `repository` tant que le dépôt est privé.

## 7. Ce qui n'a pas été vérifié

```bash
python3 scripts/verifier-plugin.py
```

Vérifié par ce script : chaque JSON parse, chaque `SKILL.md` porte un
frontmatter délimité dont tous les champs sont documentés et dont le `name`
correspond à son dossier, **chacun des 55 outils nommés par les quatre gestes
existe encore dans `crates/app/src/mcp_tools/`**, aucun fichier ne contient
`sk-`, `re_`, `whsec_` ni un `Bearer ` suivi d'un jeton, et la `source` du
marketplace mène à un manifeste dont le nom correspond.

La troisième ligne est la seule qui mérite un script plutôt qu'une relecture :
les 116 lignes du registre sont éditées par d'autres chantiers, et un outil
renommé rend un geste faux **sans rien casser d'autre**. Le script a été vu
rougir — renommer `health_company` dans `point-du-jour` le fait échouer — parce
qu'une vérification qui n'a jamais échoué ne prouve rien.

**Non vérifié, et ça ne peut pas l'être depuis un worktree :** l'installation
elle-même. Le marketplace n'est atteignable qu'une fois la branche poussée sur
`MattJeff/InternationalAgent`, donc personne n'a encore vu `/plugin marketplace
add` résoudre ce catalogue, ni l'installateur demander la clé, ni
`${user_config.cle_api}` être remplacé dans l'en-tête `Authorization`, ni le
serveur `siglair` apparaître dans `/mcp`. Tant que quelqu'un ne l'a pas fait une
fois, **ce n'est pas livré** — au même titre que le déploiement du serveur MCP
lui-même (`docs/ROADMAP_CROISSANCE.md` §1.1).

Le chemin le plus court pour lever ce doute, sans rien publier :

```bash
claude --plugin-dir ./plugin
```

qui charge le plugin sans marketplace ni installation.
