---
name: monter-la-societe
description: Monte une entreprise entière depuis rien — le modèle prouvé, l'organigramme et les limites par rôle en un seul appel, le domaine d'envoi vérifié, la charte de chaque siège, les prospects importés, la première séquence enrôlée et qui tourne. À utiliser quand le fondateur dit « monte-moi l'entreprise », « installe tout », ou quand une instance neuve rend `stopped` / `no_model`.
argument-hint: [le nom de la société, ex. « Orizn »]
---

# Monter la société

Six pas, dans cet ordre, et **chacun se relit avant qu'on passe au suivant**. Demandé :
« $ARGUMENTS ».

**Garde : ne monte jamais une société neuve avec `org_apply`.** C'est la porte d'*édition* — elle
embauche, elle place, et elle **n'accorde rien** : pas une ligne de limites n'est écrite. Un
organigramme posé par là laisse chaque équipe sans couche de rôle, et une couche absente
**hérite de celle du dessus**, c'est-à-dire du plafond de la plateforme : le siège au sommet du
tableau devient le plus permissif de la maison. Pire, on ne s'en aperçoit qu'en voulant réparer
— `policy_role_set` **retouche** une couche et n'en crée pas, donc il rend 404 sur chacun des
rôles, et il n'y a plus de chemin. La seule route qui écrive la **première** couche d'un rôle est
`company_create`, et elle le fait dans la même transaction que l'organigramme, exprès.

**Seconde garde : n'invente aucun chiffre.** `company_create` réclame un document de limites
**complet par rôle** — un champ omis n'est pas « ne touche pas », c'est un refus. Ces documents
sont livrés avec ce geste ; ils se lisent, ils ne se rédigent pas. Voir le pas 2.

**Troisième garde : chaque pas porte une barrière, et une barrière se franchit sur place.**
Pas à la fin, pas « je vérifierai tout d'un coup une fois que ça tournera ». Cinq des six pas
posent quelque chose que le pas suivant tient pour acquis, et le seul moment où la réponse est
encore petite et lisible est juste après l'avoir écrite.

| pas | ce qu'on relit **avant** de passer au suivant |
|---|---|
| 1 le modèle | `company_health_get` ne dit plus `no_model` |
| 2 la société | `employees_list` rend un siège par ligne du tableau |
| 3 le domaine | `domains_list` le dit **`verified`** |
| 4 les chartes | la réponse d'`initiatives_set` porte **un plan** et `clarify: null` |
| 5 les prospects | le `dry_run` rend **zéro refus** avant l'import réel |
| 6 la séquence | `sequences_runs_list` rend chaque inscrit **actif** |

---

## 0. Ce que tu ne peux pas deviner — et rien de plus

Pose ces questions **en un seul message**, avant le premier appel, et attends la réponse. Un
geste qui interroge entre chaque pas n'est pas jouable.

1. **Le nom de la société**, tel qu'on l'écrit. Le handle s'en déduit, et s'il est faux il se
   corrige tout seul au pas 2 — ne le demande pas.
2. **Quand ses agents s'arrêtent** (`window_ends_at`). C'est un instant, pas une durée, il est
   obligatoire et **il n'a pas de défaut** : une durée par défaut serait un prix, et personne ici
   n'a le droit d'en inventer un. Demande-le en clair — « deux jours, une semaine, un mois ? » —
   et convertis la réponse en instant UTC.
3. **Le domaine d'envoi** (`agents.exemple.com`). Ce sera celui de l'organigramme et celui des
   adresses ; il est frappé à la création d'un siège et ne se change plus.
4. **Le fichier de prospects** — son chemin — et **le nom de la liste**, qui sera écrit sur
   chaque contact créé. Sans ce nom, les contacts portent « importé, d'une liste sans nom » et
   plus rien ne saura d'où vient un euro.
5. **Le segment.** Deux fois, et ce ne sont pas les mêmes listes — voir le pas 4 et le pas 5.
   Lis-lui les valeurs admises et laisse-le choisir ; ne choisis pas à sa place.
6. **L'objectif de chaque siège qui doit agir.** Propose-le depuis la mission du gabarit
   d'organigramme et fais-le valider en une phrase par siège. C'est un choix commercial, pas une
   valeur par défaut.

Tout le reste se lit : le handle du locataire (pas 2), les limites de chaque rôle (les gabarits),
les segments admis, tous les identifiants. **Ne demande rien d'autre.**

---

## 1. Le modèle — sans lui, aucun siège ne prend de tour

**`model_connect`** avec `{"path": "cli"}` sur la machine du fondateur : il prouve le `claude`
de l'hôte par **un vrai appel**, et ne stocke rien. **Ne joins jamais de clé à `cli`** — c'est
refusé avant la sonde, et le rouvrir serait une violation de licence, pas une option. Sur un
déploiement hébergé, c'est `{"path": "api_key"}` avec la clé du locataire, qui paie.

C'est le premier pas parce que tous les autres se font sans lui **et ne servent à rien** : la
société, le domaine, les chartes, la séquence se posent très bien sur une société à l'arrêt, et
pas un tour n'est pris.

**Lis ensuite `company_health_get`.**

| ce que tu lis | ce que ça veut dire |
|---|---|
| `verdict: working`, `last_success_at: null` | c'est ça. Rien ne tourne encore ; plus rien n'empêche de tourner. Passe au pas 2. |
| `verdict: stopped`, `last_failure_code: no_model` | l'appel n'a pas pris. Relis sa réponse : elle nomme le modèle prouvé, ou l'échec. |
| `cli_spawn_failed` / `cli_failed` | `claude` n'est pas sur le `PATH` **du serveur**, ou sa session a expiré. C'est au fondateur de relancer `claude` une fois à la main ; tu ne peux pas le faire pour lui. |

Un `working` ici ne prouve pas que la société travaille — elle n'a pas encore un seul siège. Il
prouve que ce n'est plus le modèle qui la retient. Dis-le comme ça.

---

## 2. La société — l'organigramme et les limites, en une transaction

**`company_create`**, et rien d'autre. Elle écrit la ligne du locataire, l'organigramme complet,
**une couche de limites par rôle** et la date d'arrêt, en une transaction ; elle **se rejoue**
sans rien casser (identique = rien écrit) ; et tout ce qu'elle refuse, elle le refuse **avant
d'écrire une ligne**, en nommant le champ.

### Les documents de limites, qui existent déjà

Lis-les, ne les écris pas. Ils sont livrés avec ce geste :

```
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/organigramme.json
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/direction.json
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/sales-development.json
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/customer-success.json
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/growth.json
${CLAUDE_PLUGIN_ROOT}/skills/monter-la-societe/gabarits/finance.json
```

Cinq rôles, cinq fichiers, et un sixième qui est le tableau. Le corps de l'appel se compose
ainsi, et **la composition est la seule chose que tu écris** :

- `slug` — le nom de la société en handle. **S'il ne correspond pas au locataire que porte la
  clé, c'est un 409 `tenant_mismatch` qui te dit le bon**, et rien n'a été écrit : rejoue avec
  celui-là. C'est pour ça qu'on ne le demande pas au fondateur.
- `name` — le nom tel qu'on l'écrit.
- `org` — le contenu d'`organigramme.json`, avec **deux** changements : `domain` devient le
  domaine du pas 0, et chaque `mission` / `name` / `title` est réécrit pour cette société-ci.
  **Ne touche pas aux cinq `team`** : ce sont les `role_name` sous lesquels les limites seront
  lues, et ce sont les noms des cinq fichiers ci-dessus. Les changer, c'est décrocher le tableau
  de ses limites.
- `window_ends_at` — l'instant du pas 0.
- `roles` — un objet à cinq clés, `{"direction": <le contenu de direction.json>, ...}`, chaque
  valeur **recopiée entière**. Le seul champ qui mérite une question est `allowed_domains`,
  qui nomme les domaines que ces sièges ont le droit de lire : remplace ceux du gabarit par
  ceux de cette société, ou laisse-les vides.

`direction` porte `max_turns_per_day: 0` et pas un canal : ce n'est pas un oubli, c'est **le
fauteuil** — la façon dont ce système écrit « une personne s'assoit ici ». C'est ce siège qui
pourra parler aux employés au pas 6, et sans lui il n'y a personne pour le faire.

### Ce qu'elle refuse, et ce que tu en fais

| refus | ce qu'il faut faire |
|---|---|
| 400, une équipe sans couche | tu as ajouté une ligne au tableau sans ajouter son rôle à `roles`. Les deux vont ensemble, toujours. |
| 400, un champ manquant dans un rôle | tu as recopié un gabarit à moitié. Recopie-le entier. |
| 400 sur `window_ends_at` | absent, ou dans le passé. Redemande la durée, ne la choisis pas. |
| 409 `tenant_mismatch` | rejoue avec le `slug` que le refus nomme. |
| 409 `role_layer_exists` / `window_exists` | la société existe déjà et dit autre chose. **Arrête-toi** : ce geste monte, il ne réécrit pas. Dis au fondateur ce qui diffère. |
| 409 `no_platform_policy` | le déploiement n'a pas de plafond. Aucune route ne l'écrit — c'est `agentos-server policy install`, sur la base, par l'opérateur. Tu ne peux pas le faire d'ici. |

**Lis ensuite `employees_list`.** Elle doit rendre **un siège par ligne du tableau**, chacun avec
son slug et son `lifecycle`. `draft` est normal et attendu : la réponse de `company_create` est
202, « commandé », pas « embauché » — une boucle achète la boîte, le numéro, l'identité. Si la
liste est vide alors que l'appel a rendu 200 ou 202, ne continue pas : relis la réponse, les
sièges sont nommés dedans.

Garde les UUID. Ils servent aux pas 4 et 6, et `employees_list` est leur seule source.

---

## 3. Le domaine — un siège ne s'assied jamais sur un domaine non vérifié

C'est l'étape qui prend des heures, la seule qu'on ne rattrape pas après coup, et celle dont
l'oubli produit une campagne qui a l'air lancée et dont pas un mail ne part.

1. **`domains_register`** avec le domaine du pas 0. Le premier domaine déclaré devient la
   primaire. 409 `domain_taken` s'il est à quelqu'un d'autre ; un 200 au lieu d'un 201 veut dire
   qu'il était déjà là, ce qui n'est pas une erreur.
   **Lis sa réponse avant d'aller plus loin : certains fournisseurs vérifient à vue**, et elle
   rend alors le domaine déjà `verified`. Dans ce cas les deux pas suivants n'ont rien à faire
   — passe à la barrière. Chez un fournisseur réel il sera `pending`, et alors :
2. **`domains_dns_publish`** rend les enregistrements à poser, et sait les poser chez Cloudflare
   si le fondateur te donne un jeton — **ne le demande pas de toi-même** : s'il n'en propose pas,
   rends-lui les enregistrements et dis-lui de les poser chez son registrar. Ce geste ne touche
   pas au DNS de quelqu'un sans qu'il l'ait demandé.
3. **`domains_verify`**. À répéter après que le DNS est posé ; la propagation prend ce qu'elle
   prend. Quand il passe, les sièges qui attendaient pour écrire sont réveillés tout seuls.

**Lis ensuite `domains_list`.** Le domaine doit y être, en primaire, **vérifié**, avec son
plafond journalier.

- Pas vérifié → n'avance pas. Dis au fondateur ce qui manque au DNS, et reprends au 2.
  Enrôler quelqu'un maintenant produit une campagne muette, pas une campagne lente.
- Vérifié → dis-lui le plafond du jour et **combien de jours il faudra à ce plafond pour
  absorber la liste qu'on va importer**. C'est la première explication d'une file qui n'avance
  plus l'après-midi, et il vaut mieux qu'il l'entende maintenant que demain.

---

## 4. La charte de chaque siège — l'oubli silencieux

C'est le pas qu'on saute, et le seul dont l'oubli **ne dit rien** : une séquence réveille le
siège, le siège n'a pas de charte, le tour rend `no_charter`, et le run attend vingt-quatre
heures avant de mourir en `not_sent`. Rien dans la réponse de `sequences_enroll` ne l'annonce.
**Pose la charte avant d'enrôler.**

**`initiatives_set`** sur **chaque siège qui doit agir**. Pas sur `direction` : c'est le
fauteuil, son plafond de tours est zéro, il ne se réveille pas et n'a pas d'objectif.

Trois choses qu'on se prend une fois :

- C'est un **remplacement**, jamais un correctif : les deux champs sont obligatoires et
  l'ancien objectif est perdu.
- La cadence (`interval_secs`) va de **300 s à 30 jours**, et hors bornes est **refusé, jamais
  raboté**. Demande au fondateur à quelle fréquence ce siège doit se lever plutôt que de poser
  cinq minutes parce que c'est le minimum : c'est son abonnement qui paie chaque réveil.
- L'objectif est une union étiquetée par `role`, et l'étiquette doit être celle du siège :
  `sales-development` veut `segment`, `market` (code pays à deux lettres, `FR` et non `France`)
  et `target_accounts`; `customer-success` veut `product`, `first_response_hours`,
  `escalate_to`; `growth` veut `topic`, `market`, `measure`; `finance` veut `period`,
  `currency`, `obligations`.

**Le piège des deux `segment`.** L'objectif `sales-development` en admet **cinq** — `airline`,
`ota`, `corporate_travel`, `insurer`, `cruise_line` — et **ce n'est pas la liste de
`prospects_segments_list`**, qui en admet huit, épelle la croisière `cruise` et connaît `tmc`,
`relocation` et `other`. Prendre une valeur de l'une pour l'autre est un 400 `objective_field`.
Deux listes, deux questions, jamais la même réponse recopiée.

**La barrière est dans la réponse de l'écriture elle-même**, et c'est la seule du geste qui ne
coûte pas un appel de plus : `initiatives_set` rend déjà le **plan**, recalculé depuis
l'objectif, `clarify`, et `next_at`. Lis-la avant le siège suivant.

- Un `plan` et `clarify: null` → c'est bon. Dis sa prochaine échéance.
- `clarify` avec une question → l'objectif a un trou, et la réponse te dit lequel. Rapporte la
  question au fondateur et rejoue `initiatives_set` **complet** (c'est un remplacement).
- **`initiatives_get`** relit exactement la même chose plus tard, et c'est par elle qu'on passe
  quand on doute d'une charte posée un autre jour, ou qu'un run meurt en `not_sent`. 404 veut
  dire que le siège n'a pas d'initiative, ou n'est pas de cette société : reprends son UUID
  dans `employees_list`.

---

## 5. Les prospects — à blanc d'abord, toujours

1. **`prospects_segments_list`**. La liste est **fermée** et c'est la seule façon d'en connaître
   l'orthographe exacte ; un segment inventé est un 400 `bad_segment` après que tu auras déjà
   préparé le fichier. Lis-la au fondateur et fais-lui choisir.
2. **`prospects_import` avec `dry_run: true`**, `segment`, et `source` (le nom de la liste du
   pas 0). Le corps est le **CSV lui-même**, pas du JSON : les huit premières colonnes de
   l'export Smartlead, en-tête compris, 1 Mio au plus.
3. **Lis le rapport.** Il **nomme chaque ligne refusée avec son numéro** — c'est exactement ce
   pour quoi ce mode existe. Regarde aussi `country` : la colonne `location` d'un export
   Smartlead est de la **prose** (« États-Unis »), elle ne devient jamais un pays, et le rapport
   rend `ZZ` quand rien ne l'a dit. Le paramètre `country` vaut pour **tout** le fichier — une
   liste qui mélange les pays s'importe donc en un appel par pays, ou s'assume en `ZZ`, et une
   liste en `ZZ` ne se segmente plus par pays ensuite. Dis-le au fondateur, ne choisis pas seul.
   - **Zéro refus** → passe au 4.
   - **Un seul refus** → n'importe pas. Corrige le fichier, rejoue à blanc. Une liste presque
     bonne est un en-tête de travers dans neuf cas sur dix, et l'import réel ne se défait pas.
   - Si le fondateur veut importer quand même, dis-lui **en toutes lettres** combien de lignes
     vont tomber et lesquelles, et attends qu'il le dise.
4. Le **même appel sans `dry_run`**. Réimporter après correction est sûr : un compte est son
   domaine, un contact son adresse, rien ne se duplique.

Le rapport ne rend **aucun identifiant**. C'est normal, et c'est le pas 6 qui va les chercher.

---

## 6. La séquence — et la preuve qu'elle tourne

1. **`sequences_list`** pour ne pas en créer une deuxième sous un nom voisin, puis
   **`sequences_create`**. Un pas `email` porte un **brief** — l'intention, ce que l'employé doit
   dire — **et jamais le texte du mail** : la séquence ne poste rien elle-même, elle réveille le
   siège qui écrit. Y mettre un mail fini produit un employé qui paraphrase son propre brouillon.
   12 pas au plus, au moins un `email`, une boucle sans `wait` est refusée, et un `branch` ne
   connaît que `opened` et `clicked` — **il n'y a pas de `replied`**, une réponse termine le run
   avant qu'une branche soit évaluée.
2. **`contacts_list`**, paginée jusqu'au bout. **C'est la seule source du `contact_id`** :
   l'import rend des compteurs, la file rend un CSV, et un UUID inventé est un 404 qui ressemble
   à une erreur de ta part.
3. **`sequences_enroll`**, un appel par contact : la séquence, le contact, et **le siège qui
   écrira** — c'est son budget et sa Gate qui s'appliqueront. Avant le premier, redis au
   fondateur le domaine vérifié, le plafond du jour, le nombre de contacts et le siège
   responsable : cet appel engage la société devant des inconnus. Refus à reconnaître : 403
   `suppressed` (définitif, ne réessaie pas), 409 (déjà inscrit), 404 (pas de cette entreprise).

**Lis ensuite `sequences_runs_list`.** Chaque inscrit doit y avoir une position, et le run doit
être **actif** avec une prochaine échéance.

- Actif → la marche est finie. **Actif veut dire « la position est posée », pas « un mail est
  parti »** : le premier pas se joue au réveil du siège, à l'heure que `next_at` porte.
- `not_sent` → le siège a été réveillé et rien n'est parti. Dans l'ordre : `domains_primary_get`
  (plafond journalier épuisé, la cause la plus fréquente), puis `initiatives_get` sur ce siège
  (pas de charte — c'est le pas 4 qu'on a sauté), puis `company_health_get`.
- Rien du tout → l'enrôlement n'a pas pris. Relis sa réponse.

---

## Quand c'est monté : le dire, et le premier message

Récapitule en cinq lignes, et pas une de plus : le handle et le nom de la société, **quand ses
agents s'arrêtent**, le domaine et son plafond du jour, un siège par ligne avec sa cadence et
l'étape de provisionnement qui n'est pas encore revenue (`employees_get` la nomme), et le nombre
d'inscrits sur la séquence.

Et dis-lui où regarder après le premier réveil, parce qu'un siège qui ne trouve rien à faire ne
se plaint nulle part ailleurs : `company_health_get` — `last_success_at` cesse d'être `null` dès
qu'un tour aboutit —, puis `events_list` pour ce que le siège a tenté, puis
**`desk_messages_list` sur le fauteuil**, où un employé sans constat dépose sa question. Un tour
qui aboutit sans rien envoyer est le cas ordinaire du premier jour, pas une panne.

Si le fondateur veut parler à un employé, c'est **`desk_messages_send`**, et deux choses lui
manquent tant qu'il ne les sait pas :

- **Le siège dans le chemin est l'expéditeur, pas le destinataire**, et il doit être un
  *fauteuil* — un plafond de tours à zéro. C'est `direction`, et c'est pour ça que le pas 2 l'a
  créé.
- Le destinataire doit être **relié au fauteuil par l'organigramme**. Le gabarit fait rendre
  compte les quatre chefs à `direction`, donc ça marche ; sans ce lien, un slug pourtant juste
  rend un 409 `unreachable_colleague` qui se lit comme « ce nom n'existe pas ».

**Et le premier message juste après `company_create` rend un 409 `unreachable_colleague` qui
passe au second essai** — les sièges viennent d'être commandés. Réessaie une fois avant de
soupçonner l'organigramme.
