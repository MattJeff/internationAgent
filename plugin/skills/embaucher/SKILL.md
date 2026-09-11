---
name: embaucher
description: Crée un siège, le place dans l'organigramme, lui donne sa charte et ses limites, puis vérifie qu'il s'est provisionné. À utiliser pour embaucher un employé, ajouter un poste, monter une équipe, ou quand le fondateur dit qu'il lui manque quelqu'un pour faire quelque chose.
argument-hint: [le poste à créer, ex. « un SDR sur le segment agences »]
---

# Embaucher

Demandé : « $ARGUMENTS ».

**Garde : ne passe jamais `policy_role_set` en croyant faire une retouche.** Le corps est un
document **entier**, pas un correctif : `{"max_turns_per_day": 30}` a l'air d'une petite
correction et coûte au siège ses canaux, ses domaines et son modèle. Lis `policy_role_get`
d'abord, modifie le document rendu, renvoie-le en entier.

## 1. Savoir où il atterrit, avant de le créer

**`teams_list`**. Chaque équipe rend son `id`, son slug, sa mission et le **`role_name` sous
lequel ses limites sont lues** — et c'est ce dernier qui décide ce que la recrue aura le droit
de faire, bien plus que tout ce que tu écriras ensuite.

Un employé appartient à **une équipe au plus**. Ce n'est pas une convention, c'est une clé
primaire : deux équipes donneraient au chargeur de politique deux couches `role` et il
garderait celle arrivée en dernier — un tirage au sort entre le budget des achats et celui des
ventes, chaque décision paraissant correcte dans les journaux.

Si l'équipe n'existe pas : **`teams_create`**. Son slug devient son `role_name` initial, ce qui
**ne crée pas** ses limites — tant que personne n'a écrit de couche sous ce rôle, l'équipe
hérite de celle du locataire, c'est-à-dire de la plus large.

## 2. Créer le siège

**Un seul siège : `employees_create`.** Deux choses à savoir avant d'appeler :

- Le **`slug` est définitif**. Il devient la partie locale de l'adresse et l'identité du siège ;
  il ne se change plus. Fais-le valider par le fondateur, pas par toi.
- La réponse est **202, jamais 201**. La ligne existe, et rien de ce qu'il lui faut pour
  travailler n'existe encore : boîte mail, numéro, identité sont `pending`, et une boucle vient
  les acheter. Ne dis pas « il est embauché » à ce stade ; dis « il est commandé ».

**Plus d'un siège, ou un organigramme entier : `org_apply`.** Le tableau *Fonction ·
Responsable · Mission*, appliqué **en une transaction** — donc une mauvaise ligne 7 défait
l'équipe de la ligne 1, ce qui est ce qu'on veut. Il est déclaratif : on le ré-édite et on le
ré-applique, cela converge. Deux choses qu'il ne fait **pas** : il n'enlève jamais (un siège
tombé du document reste debout), et il **n'accorde rien** — pas une ligne de politique n'est
écrite ici.

## 3. L'asseoir dans l'organigramme

- **`teams_members_add`** l'ajoute et **ne remplace jamais** : un siège déjà sur une équipe est
  un 409 qui nomme laquelle. Cette ligne n'écrit ni titre ni `reports_to`.
- **`teams_members_set`** est le seul verbe qui écrive une **position** (titre, responsable,
  section) — et **chaque champ omis est effacé, jamais conservé**. Il n'y a pas d'état « garde
  l'ancienne valeur » : lis `teams_members_list` d'abord et renvoie ce que tu veux garder.
- Le CEO est le siège dont `reports_to` est vide ; ce n'est pas un cas particulier. Une boucle
  hiérarchique est refusée par la base, pas par une fonction Rust : un 409 `reporting_cycle`.

## 4. Sa charte : ce pour quoi il est là

Deux écritures, et **ni l'une ni l'autre n'est une limite**.

- **`teams_mission_set`** — la mission de l'équipe, la seule phrase durable qu'elle possède en
  propre. Sans elle, une recrue de l'équipe croissance connaît sa tâche et rien de la
  croissance. De la prose, 240 caractères au plus, et elle n'ouvre ni ne ferme rien.
- **`initiatives_set`** — l'objectif (*ce pour quoi* le siège est là) et la cadence (*quand* il
  agit seul), écrits ensemble dans une transaction. C'est un **remplacement** : les deux champs
  sont obligatoires et l'ancien objectif est perdu, donc lis `initiatives_get` avant si tu veux
  en garder une partie. C'est aussi la route qui **choisit le rôle**, dans une liste fermée, et
  aucun modèle ne fait ce choix à ta place : demande-le au fondateur. La cadence va de 300 s à
  30 jours et **hors bornes est refusé, jamais raboté** ; la poser déplace la prochaine
  échéance à un intervalle d'ici.

Si l'objectif se dit mieux en prose qu'en JSON : **`interview_questions_list`** pose les
questions, **`interview_answer`** les remplit une par une.

## 5. Ses limites

Dans cet ordre, parce que l'ordre inverse écrase.

1. **`policy_role_get`** sur le `role_name` de l'équipe. Un 404 veut dire « rien d'écrit sous ce
   rôle », ce qui est différent de « les limites du plafond » : la couche absente hérite au
   chargement.
2. **`policy_role_set`** avec le document complet, resserré. Elle ne peut que **rétrécir** — un
   corps qui élargit est un 409 `policy_widens`, refusé et non silencieusement intersecté — et
   elle **ne crée pas** : un rôle sans couche est un 404, la création appartient à
   `company_create`, qui connaît l'organigramme.
3. L'argent : **`spend_caps_get`** puis **`spend_caps_set`**, **par devise**. `caps: null` ne
   veut pas dire « illimité » mais « ne peut pas payer » : sans ligne de plafonds, la Gate
   refuse toute dépense avec `no_spend_policy`. Un siège neuf est dans cet état.
4. Le budget de l'équipe, si elle en a un : **`teams_budget_get`** / **`teams_budget_set`**.

## 6. Vérifier qu'il s'est provisionné

C'est l'étape qu'on saute et qui fait dire « l'employé ne fait rien » trois jours plus tard.

- **`employees_get`** — le siège complet : `lifecycle`, la santé dérivée, **les onze étapes de
  provisionnement** avec leur fournisseur, et les appels partis sans revenir. C'est ici, et
  nulle part ailleurs, qu'on voit *pourquoi* un siège reste en `draft`. Tant qu'il est `draft`,
  il n'a ni boîte, ni numéro, ni identité — et on ne le force pas : `employees_resume` refuse un
  `draft` par un 409 `draft_is_not_resumable`, exprès.
- **`controls_get`** — ce qui borne réellement ce siège, **quelle couche a posé chaque plafond**
  (`set_by`), s'il agit de lui-même (`acts_on_its_own`), et ce que le plafond libère
  aujourd'hui une fois la chauffe du domaine passée, avec `contacts_held_back` qui nomme le mur.
  À préférer à `policy_role_get` dès que la question est « qu'est-ce qui l'arrête en premier ».
- **`employees_turns_get`** — `turns_taken: 0` avec un 200 est la réponse ordinaire d'un siège
  qui ne s'est pas encore réveillé, pas une panne.
- Si rien ne bouge : **`company_health_get`**, puis **`model_get`**. Un 404 sur le modèle veut
  dire que rien n'est connecté, et alors aucun siège de cette société ne prend de tour — ce
  n'est pas la recrue qui est en cause.

Dis au fondateur, pour finir : le slug définitif, l'équipe et le rôle sous lequel ses limites
sont lues, sa cadence, et **quelle étape de provisionnement n'est pas encore revenue**.
