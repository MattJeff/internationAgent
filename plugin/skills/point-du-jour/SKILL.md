---
name: point-du-jour
description: Répond à « où en est ma société ? » — la santé d'abord, puis ce qui attend une décision, ce que la prospection a produit, et l'argent. À utiliser au réveil, ou dès que le fondateur demande un état général, un résumé, un point, ou « quoi de neuf ».
argument-hint: [fenêtre, ex. 7d ou 30d]
---

# Le point du jour

Une lecture, jamais une écriture. Fenêtre demandée : « $ARGUMENTS » — à défaut, **7 jours**.

**Garde : ce geste n'approuve, ne refuse, n'enrôle et n'embauche rien.** S'il faut décider
quelque chose, nomme-le à la fin et arrête-toi. Un rapport qui a agi en passant n'est plus un
rapport.

## 1. La santé, toujours en premier

Appelle **`health_company`** avant tout le reste. Sans lui, chaque chiffre qui suit peut être
le chiffre d'hier rendu par une société qui ne tourne plus depuis.

Ce que tu lis dans la réponse, et ce que tu en fais :

- `working` — continue. Une société au repos rend `working`, pas `degraded` : ne rien avoir à
  faire n'est pas une panne, ne le rapporte pas comme telle.
- `degraded` — continue, mais cite `last_failure_detail` dans le rapport : les chiffres du bas
  sont partiels, dis-le.
- `stopped` — **arrête la lecture ici**. La cause est dans `last_failure_detail`, et c'est
  presque toujours la connexion au modèle : appelle **`model_status`** (un 404 veut dire que
  rien n'est connecté, ce qui est une cause et pas une erreur de ta part) et rapporte cette
  seule chose. Lire la prospection d'une société arrêtée produit un rapport rassurant et faux.

## 2. Ce qui attend une décision

Trois files, et elles ne se recouvrent pas.

- **`approvals_list`** — ce que les employés demandent. **Rien n'en sort tout seul** : un jeton
  dure 24 heures et personne ne déplace une ligne périmée, donc la tête de file est le travail
  le plus certainement mort. Compte les lignes de plus de 24 h **à part** du reste, sinon tu
  annonces douze décisions à prendre là où il y en a deux.
- **`capability_requests_list`** — les refus récurrents de la Gate, c'est-à-dire les employés
  qui butent chaque jour sur la même limite. Une ligne ici est un travail bloqué, pas une
  alerte de sécurité.
- **`work_board`** — le tableau de travail, ouvert et clos ensemble et sans filtre. Ne cite que
  ce qui est ouvert, et signale ce qui n'a personne : un élément sans propriétaire n'avancera
  pas de lui-même.

## 3. Ce que la prospection a produit

- **`outreach_summary`** sur la fenêtre. **Lis `unmeasured` avant de citer un chiffre** — c'est
  la liste de ce que ces nombres ne couvrent pas, et la citer est la différence entre un
  chiffre et une vantardise. `approached` compte des créneaux réservés, **pas** des envois
  partis : ne dis jamais « N mails envoyés » à partir de ce champ.
- **`outreach_health`** sur les mêmes jours. Les deux taux sont **en pour mille des envois**,
  l'unité des seuils publics (0,3 % de plaintes = 3 ‰). Un taux de plaintes qui monte est la
  seule ligne de tout ce rapport qui vaille une interruption : un domaine ne se répare pas.

## 4. L'argent

- **`pnl_read`** sur la fenêtre. Un coût `null` veut dire « aucun tarif déclaré », **jamais**
  « zéro » : écris `null`, ne l'arrondis pas à 0 €. Les montants ne s'additionnent pas entre
  devises, et `cost_source` dit d'où vient chaque chiffre.
- **`invoices_list`** — `outstanding_minor` est **par devise**. Il n'y a pas de taux de change
  dans ce produit ; une somme unique serait une invention.

Si le fondateur a demandé pourquoi ça coûte ce que ça coûte, ajoute **`usage_read`** ; sinon,
non : ce geste doit tenir en une poignée d'appels.

## 5. La sortie

Termine par **exactement trois phrases** :

1. La santé, avec son verdict tel quel.
2. Ce qui a bougé dans la fenêtre — prospection et argent, un chiffre chacun, avec sa réserve.
3. Ce qui attend le fondateur, chiffré, périmées comptées à part.

Puis **une seule question**, celle dont la réponse débloque le plus : la décision la plus
ancienne encore vivante, ou la cause de l'arrêt. Pas trois options, pas un menu.
