---
name: point-du-jour
description: Répond à « où en est ma société ? » — la santé d'abord, puis l'entonnoir contre sa cible, ce qui est réellement parti, et ce qui attend une décision. À utiliser au réveil, ou dès que le fondateur demande un état général, un résumé, un point, ou « quoi de neuf ».
argument-hint: [fenêtre, ex. 7d ou 30d]
---

# Le point du jour

Une lecture, jamais une écriture. Fenêtre demandée : « $ARGUMENTS » — à défaut, **7 jours**.

**Garde : ce geste n'approuve, ne refuse, n'enrôle et n'embauche rien.** S'il faut décider
quelque chose, nomme-le à la fin et arrête-toi. Un rapport qui a agi en passant n'est plus un
rapport.

**Six appels, et ils tiennent dans cet ordre.** Ce geste a été parcouru pour la première fois le
2026-09-12, sur trois sociétés — une neuve, une qui tourne, une à l'arrêt. Il en faisait huit,
dont trois que `growth_get` rend en un seul, et il ne lisait jamais la seule réponse du produit
qui porte un verdict. L'ordre ci-dessous est celui qui produit une décision ; en sortir, c'est
réciter des compteurs.

## 1. La santé, toujours en premier

Appelle **`company_health_get`** avant tout le reste. Sans lui, chaque chiffre qui suit peut être
le chiffre d'hier rendu par une société qui ne tourne plus depuis.

Quatre champs de cette réponse portent tout le reste du geste :

- **`verdict`** — `working`, `degraded` ou `stopped`.
- **`last_success_at`** — la date du dernier tour qui a abouti, sans borne de temps. C'est le seul
  champ qui distingue **une société neuve d'une société arrêtée** : les deux rendent `stopped`
  faute de modèle, et l'une a `null` (elle n'a jamais rien fait) quand l'autre porte une date
  (elle le faisait, et ne le fait plus depuis ce jour-là). Dis lequel des deux, toujours.
- **`last_failure_detail`** — notre phrase, jamais celle d'un fournisseur.
- **`last_failure_employee_slug`** — **le siège qui a produit cet échec.** Une panne sans nom
  envoie le fondateur chercher ; une panne nommée est une décision. Cite-le dès que le verdict
  n'est pas `working`.

Et ce que tu en fais :

- `working` — continue. Une société au repos rend `working`, pas `degraded` : ne rien avoir à
  faire n'est pas une panne, ne le rapporte pas comme telle. Si elle est `working` et que
  l'entonnoir du §2 est plat, la cause n'est pas une panne — c'est `initiatives_list` : un siège
  sans cadence ne se réveille jamais tout seul. Nomme-le, ne va pas le lire.
- `degraded` — continue, mais cite le siège et sa phrase : les chiffres du bas sont partiels,
  dis-le.
- `stopped` — **saute les §2 et §3.** La cause est dans `last_failure_detail`, et c'est presque
  toujours la connexion au modèle : appelle **`model_get`** (un 404 veut dire que rien n'est
  connecté, ce qui est une cause et pas une erreur de ta part). Lire la prospection et l'argent
  d'une société arrêtée produit un rapport rassurant et faux : ces chiffres datent d'avant
  l'arrêt et les rapporter au présent est un mensonge sur le temps.
  **Fais quand même le §4**, et un seul de ses trois appels — `approvals_list`. Rien ne sort de
  cette file toute seule : ce qui s'y est accumulé pendant l'arrêt sera là à la reprise, et c'est
  la seule chose qu'un fondateur peut traiter *avant* d'avoir rebranché quoi que ce soit.

## 2. L'entonnoir, la recette et le coût — un seul appel

**`growth_get`** sur la fenêtre. C'est la seule lecture de ce produit qui réponde à « est-ce que
j'y arrive » plutôt qu'à « combien ». Elle rend les sept étapes qui mènent d'un inconnu à une
facture réglée avec leurs taux de passage, la recette, le coût du modèle, la cible et un
**`verdict`** (`ahead`, `on_track`, `behind`, `no_target`).

N'appelle **pas** `outreach_summary_get`, ni `pnl_get`, ni `invoices_list` : ce qu'ils ont
d'utile ici est dans celui-ci, sur une seule fenêtre, et aucun des trois ne porte de verdict. Ils
sont des suites, pas des étapes — voir §5, qui dit aussi les deux chiffres que `growth_get` ne
porte pas.

Les trois pièges de cette réponse, et ils sont dans l'ordre où on les commet :

- **`null` n'est jamais zéro.** Un taux dont le dénominateur est vide n'existe pas ; un coût de
  modèle `null` est un tarif non déclaré ou un abonnement local, jamais un modèle gratuit ; une
  recette `null` est un registre à plusieurs monnaies ou un registre vide. Écris `null`, ne
  l'arrondis pas à 0 €.
- **Ce n'est pas une cohorte.** Les sept comptes mesurent la même fenêtre, pas les mêmes
  personnes : un `to_next_rate` de `40.0` veut dire quarante contacts approchés par prospect
  ajouté cette semaine-là, pas un taux de conversion de 4 000 %. Lis `unmeasured` avant de citer
  un taux.
- **`verdict: no_target` n'est pas un mauvais résultat, c'est une case vide.** Personne n'a posé
  de cible, ou elle est libellée dans une monnaie que le registre n'emploie pas. C'est alors la
  question du §5 : sans cible, aucun de ces chiffres ne dit s'il est bon.

## 3. Ce qui est réellement parti

**`outreach_health_get`** sur les mêmes jours.

**Compare `sent` d'ici à `contacted` du §2, et dis l'écart.** Ce sont deux tables : `contacted`
compte des créneaux réservés, `sent` compte des messages que nous avons écrits. Un `contacted` à
120 face à un `sent` à 40 veut dire que quatre-vingts personnes ont été réservées et jamais
écrites — un fichier exporté et jamais chargé chez le prestataire, le cas le plus fréquent.
C'est le genre de phrase qu'un fondateur ne peut pas déduire d'un seul de ces deux nombres, et
personne d'autre ne la dira.

**Les deux fenêtres ne coïncident pas tout à fait** : `growth_get` compte des jours UTC pleins,
bornes incluses, quand `outreach_health_get` compte à rebours depuis maintenant. À `days=7` cela
fait jusqu'à une journée d'écart à chaque bout. Dis l'écart comme un ordre de grandeur — « deux
tiers des créneaux ne sont jamais partis » — jamais comme une soustraction exacte.

Les deux taux sont **en pour mille des envois**, l'unité des seuils publics (0,3 % de plaintes =
3 ‰), et ils valent `null` tant que rien n'est parti **ou que rien n'est revenu** : `sent` est
compté sur nos lignes, les livraisons et les rebonds n'arrivent que par le rappel du
fournisseur. Un `sent` élevé face à `delivered: 0` ne dit pas que la livraison est parfaite, il
dit que le canal de retour ne parle pas. Un taux de plaintes qui monte est la seule ligne de tout
ce rapport qui vaille une interruption : un domaine ne se répare pas.

## 4. Ce qui attend une décision

Trois files, et elles ne se recouvrent pas.

- **`approvals_list`** — ce que les employés demandent. **Rien n'en sort tout seul** : un jeton
  dure 24 heures et personne ne déplace une ligne périmée, donc la tête de file est le travail
  le plus certainement mort. Compte les lignes dont `expires_at` est passé **à part** du reste,
  sinon tu annonces douze décisions à prendre là où il y en a deux.
- **`capability_requests_list`** — les refus récurrents de la Gate, c'est-à-dire les employés
  qui butent chaque jour sur la même limite. Une ligne ici est un travail bloqué, pas une
  alerte de sécurité. `raised_after_denials` est le **seuil** qui fait naître une ligne, pas un
  compte de lignes : ne le rapporte pas.
- **`work_items_list`** — le tableau de travail, ouvert et clos ensemble et sans filtre. Ne cite
  que ce qui est ouvert, et signale ce qui n'a personne : un élément sans `assignee_id`
  n'avancera pas de lui-même.

## 5. Ce qu'on ne lit pas, et quand on y va quand même

Ce geste doit tenir en six appels. Ces quatre-là sont des **suites** : on les appelle quand le
fondateur a posé la question, jamais à tout hasard.

| S'il demande | Alors |
|---|---|
| pourquoi ça coûte ce que ça coûte | `pnl_get`, puis `usage_get` — le détail siège par siège |
| quelle facture relancer | `invoices_list` en `state=outstanding` — `growth_get` donne le total dû, pas les lignes |
| si quelqu'un a pris rendez-vous, ou combien d'adresses ont été retirées | `outreach_summary_get` — **`booked` et `suppressed` ne sont dans aucune étape de l'entonnoir**, ce sont les deux chiffres de la prospection que `growth_get` ne porte pas |
| pourquoi un siège nommé au §1 ne travaille pas | `initiatives_get` sur ce siège |

## 6. La sortie

Termine par **exactement trois phrases** :

1. La santé, avec son verdict tel quel, le siège nommé s'il y en a un, et — si c'est `stopped` —
   depuis quand, d'après `last_success_at`, ou « elle n'a jamais tourné » si c'est `null`.
2. Où en est l'entonnoir contre sa cible : le verdict de `growth_get`, un chiffre qui l'appuie,
   et l'écart entre ce qui a été réservé et ce qui est parti.
3. Ce qui attend le fondateur, chiffré, périmées comptées à part.

Puis **une seule question**, celle dont la réponse débloque le plus. Dans cet ordre de priorité,
et prends la première qui s'applique :

1. la cause de l'arrêt, si le verdict est `stopped` ;
2. le siège nommé, s'il casse depuis plus d'un jour ;
3. l'écart entre `contacted` et `sent`, s'il est large — c'est du travail déjà payé qui n'est
   pas parti ;
4. la cible, si `verdict` vaut `no_target` — sans elle rien de ce rapport ne se juge ;
5. la décision la plus ancienne encore vivante.

Pas trois options, pas un menu.
