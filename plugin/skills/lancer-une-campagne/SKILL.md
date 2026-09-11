---
name: lancer-une-campagne
description: Mène une liste de prospects jusqu'au premier envoi — segments, import à blanc puis réel, domaine d'envoi vérifié, séquence définie, contacts enrôlés. À utiliser pour lancer une campagne, importer un CSV de prospects, monter une séquence de relance ou démarrer la prospection.
argument-hint: [le fichier CSV, le segment, ou ce qu'on veut lancer]
---

# Lancer une campagne

Cinq étapes, dans cet ordre. Demandé : « $ARGUMENTS ».

**Garde : n'appelle jamais `sequences_enroll` avant d'avoir lu, dans la réponse de
`domain_get`, que le domaine d'envoi est vérifié.** Un siège ne peut pas s'asseoir sur un
domaine non vérifié ; enrôler d'abord produit une campagne qui a l'air lancée et dont pas un
mail ne part.

## 1. Le domaine d'envoi, avant tout le reste

C'est l'étape qui prend des heures — la propagation DNS — et la seule qu'on ne peut pas
rattraper après. Elle passe donc en premier, pas en dernier.

1. **`domain_list`**, puis **`domain_get`** sur celui qu'on veut utiliser. S'il n'existe pas,
   **`domain_register`**.
2. S'il n'est pas vérifié : **`domain_dns`** rend les enregistrements à poser. Pose-les chez le
   registrar — ce plugin ne le fait pas et ne peut pas le faire — puis **`domain_verify`**, et
   répète-le jusqu'à ce qu'il passe. Quand il passe, les sièges qui attendaient pour écrire
   sont réveillés tout seuls.
3. **`outreach_health`** sur ce domaine. Les taux sont **en pour mille des envois**. Si les
   plaintes montent, ne lance pas : une campagne sur un domaine qui se dégrade accélère la
   dégradation, et aucune cadence ne la répare.
4. Le **plafond journalier** : `domain_get` le rend. **Il s'épuise.** Une fois atteint, les
   envois du jour sont refusés et attendent le lendemain — c'est la première explication d'une
   file qui n'avance plus l'après-midi, et c'est ce qu'il faut dire au fondateur avant qu'il le
   découvre. Pour le changer, **`domain_set_cap`**, et seulement après avoir lu
   `outreach_health` : monter le plafond sans regarder la santé est la façon habituelle de
   griller un domaine. Zéro est refusé ; pour ne plus envoyer du tout, c'est `domain_remove`.

Dis au fondateur, à ce stade : le domaine, son état, son plafond, et combien de jours il faut
au plafond pour absorber la liste qu'on va importer.

## 2. Le segment, puis l'import à blanc

1. **`prospects_segments`** d'abord, toujours. La liste des segments est **fermée**, et cet
   appel est la seule façon de connaître l'orthographe exacte : un segment inventé est refusé
   en 400 `bad_segment` après que tu auras déjà préparé le fichier.
2. **`prospects_import` avec `dry_run: true`.** Rien n'est écrit, et le rapport **nomme chaque
   ligne refusée avec son numéro**. C'est la seule façon de voir un en-tête de travers avant
   d'avoir importé la moitié d'un fichier. Le corps est le **CSV lui-même**, pas du JSON : les
   huit premières colonnes de l'export Smartlead, en-tête compris, 1 Mio au plus.
3. Lis le rapport ligne par ligne. Corrige le fichier, rejoue à blanc. **Ne passe à l'import
   réel que quand le rapport est propre** — ou que tu as dit au fondateur, en toutes lettres,
   combien de lignes vont tomber et lesquelles.
4. Le même appel **sans** `dry_run`. Un second import du même fichier ne duplique rien : un
   compte est son domaine, un contact son adresse. Réimporter après correction est donc sûr.

## 3. La séquence

**`sequences_list`** pour voir ce qui existe déjà et ne pas en définir une deuxième sous un
nom proche, puis **`sequences_define`**.

Ce qu'il faut avoir en tête en l'écrivant :

- **Une séquence ne poste rien elle-même.** Un pas `email` porte un **brief** — l'intention, ce
  que l'employé doit dire — et pas le texte du mail. Quand la promesse sonne, le siège est
  réveillé et écrit le mail lui-même, qui repasse par la Gate comme n'importe quel envoi.
  Écrire un mail fini dans un `brief` produit un employé qui paraphrase son propre brouillon.
- 12 pas au plus, au moins un pas `email`, et une liste vide est refusée.
- Un `branch` ne connaît que `opened` et `clicked` : **il n'y a pas de `replied`**, parce
  qu'une réponse termine le run avant qu'une branche soit évaluée. Ne construis pas une
  logique qui l'attend.
- Une boucle sans `wait` est refusée — elle tournerait à chaque tick.
- Un nom déjà porté par une séquence vivante est un 409 `name_taken`.

## 4. L'enrôlement

**`sequences_enroll`**, un appel par contact : la séquence, le contact, et **le siège qui
écrira**. C'est le budget et la Gate de ce siège qui s'appliqueront, pas les tiens — choisis-le
en connaissance de cause, et relis `controls_get` si tu ne sais pas ce qui le borne.

L'appel est marqué destructif parce qu'il engage la société devant des inconnus. Avant le
premier, redis au fondateur : le domaine vérifié, le plafond du jour, le nombre de contacts, et
le siège responsable. Puis enrôle.

Refus à reconnaître : 403 `suppressed` (l'adresse a demandé qu'on la laisse tranquille — c'est
définitif, ne réessaie pas), 409 (déjà inscrit), 404 (la séquence, le contact ou le siège n'est
pas de cette entreprise).

## 5. Vérifier que ça part

**`sequences_runs`** tout de suite : les positions sont-elles posées. Puis, le lendemain,
**`outreach_summary`** — et s'il ne s'est rien passé, **`health_company`** avant de soupçonner
la campagne : une société arrêtée ressemble beaucoup à une séquence cassée.
