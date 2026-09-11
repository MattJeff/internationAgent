---
name: repondre-aux-demandes
description: Vide la file humaine — lire ce qui attend une approbation, comprendre ce qui est demandé, décider, puis écrire à l'employé concerné. À utiliser quand le fondateur parle d'approbations, de demandes en attente, de validations, ou dit qu'un employé est bloqué.
argument-hint: [l'id d'une approbation, ou rien pour toute la file]
---

# Répondre aux demandes

Demandé : « $ARGUMENTS » — sans argument, toute la file.

**Garde : ne reformule jamais l'action d'une approbation, et n'approuve jamais une demande que
tu as toi-même déposée.** L'action est re-hachée **octet par octet** contre celle déposée ; un
même nom écrit en NFC et en NFD sont deux approbations différentes. Et la règle des quatre yeux
refuse l'approbateur qui est le demandeur — c'est la seule chose qui distingue ce système d'un
employé qui signe ses propres dépenses.

## 1. Lire la file

**`approvals_list`**. Elle rend les `pending`, du plus ancien au plus récent.

Ce qu'il faut comprendre avant de la traiter : **rien n'en sort tout seul**. Un jeton dure
24 heures, `state` n'a pas de valeur « expirée », et personne ne déplace une ligne périmée. Une
quinzaine sans surveillance donne donc une file dont **la tête est le travail le plus
certainement mort** et dont la seule ligne encore utilisable est en bas. Le compteur de
supervision, lui, filtre les périmées : les deux chiffres ne coïncident pas, c'est connu, ne le
rapporte pas comme un bug.

Traite donc **du plus récent vers le plus ancien**, et compte les périmées à part.

## 2. Comprendre ce qui est demandé

**`approvals_get`** sur chaque ligne à décider. C'est là — et nulle part ailleurs — qu'on lit
l'action exacte, celle qu'il faudra recopier.

Avant de décider, réponds à trois questions pour toi-même, et écris-les au fondateur :

- **Qui demande, et pour quoi faire ?** Si l'objectif du siège ne rend pas la demande évidente,
  lis `employees_get` puis `initiatives_get` : une dépense sensée pour un acheteur ne l'est pas
  pour un siège de support.
- **Qu'est-ce qui se passe si on approuve ?** Pour `payment_create`, **l'argent part vraiment**.
  Pour les autres natures, le jeton est frappé, la décision enregistrée et le jeton jeté.
- **Est-ce encore vivant ?** Une ligne de plus de 24 h ne s'approuve pas ; elle se refuse.

## 3. Décider

**Approuver** — **`approvals_approve`**, avec l'action **restituée telle qu'`approvals_get` l'a
rendue**, sans reformuler, sans réordonner, sans corriger une faute. L'échec que cette route
existe pour empêcher n'est pas « on a approuvé la mauvaise chose », c'est « on a approuvé
*ceci* et *cela* a été exécuté ». Une différence est un `approval_action_mismatch` ; un 502
signifie approbation dépensée et argent peut-être en vol, et **il n'y a pas de rejeu** —
n'appelle pas une seconde fois, lis `invoices_list` ou `events_list` pour voir ce qui a eu lieu.

**Refuser** — **`approvals_deny`**. Le nonce est brûlé définitivement et l'employé devra
redéposer. Pas de règle des quatre yeux ici, et une ligne périmée s'accepte sans regarder sa
date : c'est la seule façon de vider la file. **Écris toujours la `note`** : elle est
facultative, et c'est exactement ce que lira le prochain opérateur — ou le même, dans trois
semaines, devant la même demande revenue.

## 4. Les demandes de permission, qui sont un autre objet

**`capability_requests_list`** rend les refus récurrents de la Gate : un siège qui bute chaque
jour sur la même limite. Elles n'ont pas d'identifiant — ce sont des clés de regroupement —
donc on les nomme par leur forme : `employee_id`, `action_kind`, `deny_reason`, recopiés depuis
la liste.

**`capability_requests_decide`** enregistre la décision d'un humain. **Cela n'élargit rien**, et
c'est la moitié honnête de la fonctionnalité : accorder ici n'écrit pas une couche de politique.
Si tu accordes, dis-le en toutes lettres au fondateur : il reste à installer la couche par
**`policy_role_set`**, qui exige le document complet et **ne peut que resserrer**. Un accord que
personne n'installe n'est pas perdu — l'employé continue d'être refusé et la demande revient
avec son ancienne décision attachée — mais il n'a rien débloqué.

## 5. Écrire à l'employé

Une décision que l'employé n'apprend pas est une décision qui n'a pas eu lieu : il redéposera.

**`employees_list`** pour le slug du destinataire, puis **`desk_messages_send`**. Trois choses, dans
l'ordre où elles mordent :

- **Le siège dans le chemin est l'expéditeur, pas le destinataire.** Il doit être un
  *fauteuil* : un siège dont le plafond de tours vaut zéro, ce qui est la façon dont ce système
  écrit « une personne s'assoit ici ». Le destinataire est le `to`, par slug.
- **Le message réveille le destinataire et lui coûte un tour** de son budget du jour, sur le
  modèle et la facture du client. Un budget épuisé est un 409 : n'envoie pas cinq messages là
  où une phrase suffit.
- `kind: "answer"` exige `answers`, qui porte l'`id` d'un message lu sur **`desk_messages_list`**. Pour
  annoncer une décision que l'employé n'a pas posée comme question au bureau, c'est `order`.

Dis ce qui a été décidé et **pourquoi**. Un refus sans raison revient dans la file la semaine
suivante, à l'identique.
