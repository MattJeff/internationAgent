# Roadmap — « 5K$/mois d'infra, et le client sait qu'il peut être rentable »

Décidée le 2026-09-05, à partir d'une lecture du dépôt tel qu'il est (pas des
docs). Le trou n'est pas une capacité : c'est que les quatre chiffres qui
rassurent un acheteur — *qu'ont-ils fait, combien ça a coûté, combien ça a
rapporté, où est le point mort* — vivent chacun sur une route et personne ne
les met côte à côte. Le dépôt refuse d'imprimer un chiffre qu'il n'a pas
mesuré ; cette roadmap garde la règle : **chaque nombre ci-dessous sort d'une
ligne qui existe déjà**, ou d'un tarif que le tenant a déclaré lui-même.

Une case cochée est une case fusionnée sur la branche avec `scripts/test.sh`
vert (1969 tests, clippy, fmt, digest re-pinné le 2026-09-05) — pas un
`tests_passing: true` rapporté par un agent. CI n'a pas encore arbitré : la
branche n'est pas poussée.

## Vague 1 — le client voit ce qu'il paie et ce que ça rapporte (en parallèle)

- [x] **A. Tarif déclaré + `GET /v1/pnl`** — migration 0079. `POST /v1/model`
      accepte `usd_per_mtok_input`, `usd_per_mtok_output`, `usd_per_mtok_cache_read`
      (le contrat Anthropic du client, jamais un prix du dépôt). `GET /v1/pnl?days=N`
      rend, par siège et en total : tours, tokens, `cost_usd` (null sans tarif,
      avec `cost_source`), factures émises / encaissées (nombre et montant),
      dépenses réservées / réglées, items du board clos, approbations demandées,
      refus de la gate. Même fenêtre que `/v1/usage`.
- [x] **B. `GET /v1/refusals`** — le flux « ce qu'on a refusé » : les rows
      d'audit `decision = 'deny'` par motif, par verbe, par siège, avec la
      source non fiable quand le payload la nomme. Aucune table : c'est une
      lecture de l'audit.
- [x] **C. `invoice_issue` atteignable depuis un tour** — la douzième ligne
      de catalogue, écrite en commentaire dans `turn.rs`, est appliquée ;
      `InvoiceIssue` reste haut risque donc invisible sur un tour taché ; seul
      le pack finance le propose. **Pas de verbe file store** : `files.rs`
      argumente qu'un tour produit du texte, pas des octets, et que le lecteur
      du contrat est celui qui ne doit plus payer de tokens — on le garde.
      Le re-pin de `cost::DIGEST` est fait à la main après fusion (deux runs
      `--live`, jamais par un agent) ; tant qu'il n'est pas fait,
      `every_correctness_check_passes` est rouge et c'est attendu.
- [x] **D. Un message entrant devient un ticket** — un inbound (email ou SMS)
      d'un tiers qui atterrit chez un employé ouvre un item sur le work board,
      un seul par conversation tant qu'il est ouvert. Migration 0080 si un
      lien conversation ↔ item est nécessaire.

### Coutures laissées par la vague 1, à reprendre

- Le brief finance n'imprime pas les opportunités `closed_won` ; un tour
  finance ne peut facturer qu'un deal qu'un collègue lui a nommé.

## Vague 2 — la boucle argent se ferme sans rail de paiement

- [x] **E. Point mort dans `/v1/forecast`** — avec le tarif de A et le montant
      moyen des factures du tenant : *N tours ≈ X$ de tokens + infra ⇒ K
      factures de M pour être à l'équilibre.* Une division, pas un pourcentage.
- [x] **F. Facture → PDF → email → encaissée** — la facture émise part par
      `EmailSend` avec le PDF en pièce jointe ; la livraison Stripe déjà
      stockée brute passe `declare_paid` automatiquement.
- [x] **G. Relance d'outreach** — « relance J+3 sans réponse » est une promesse
      calendrier (`AppointmentBook`) que l'employé sait déjà poser ; remplace
      un séquenceur.
- [x] **H. Export comptable** — CSV `invoices` + `spend` sur une fenêtre, pack
      finance.

### Coutures laissées par la vague 2, à reprendre

- Un envoi fait par `Seller::touch` (vertical) ou `sourcing` n'est pas relancé
  par G : ces chemins ont leur propre espacement (`contacts.next_follow_up_at`).
  Deux mécanismes pour une même idée ; en garder un.

## Vague 3 — ce qu'une entreprise paie ailleurs

- [x] **I. Page publique de réservation** sur `AppointmentBook` (remplace
      Calendly).
- [x] **J. Le briefing vente passe à l'axe catégoriel** avant toute ouverture
      d'outreach supplémentaire.
- [x] **K. Un écran « caps + bouton d'arrêt »** : `max_turns_per_day`,
      `max_new_contacts_per_day`, plafonds de dépense, `/v1/halt` — au même
      endroit que le P&L.

### Coutures laissées par la vague 3, à reprendre

- Une réservation publique réveille le siège avec le sujet masqué, mais le
  motif du tiers n'est pas dans le brief du réveil (`follow_up::brief` rend
  `None` sur un fil sans sortant) : une ligne dans `initiative.rs`.
- `GET /v1/controls` ne montre pas le budget d'équipe
  (`PUT /v1/teams/{team_id}/budget`) — un plafond de plus quand quelqu'un le
  demande.

## Deux décisions prises le 2026-09-05, pour ne pas les reprendre

- **`rate_card` reste.** C'est la seule façon de mettre un dollar sur la
  mesure d'Orizn (`docs/ORIZN.md`) et le repli de `/v1/forecast` quand rien
  n'est déclaré, étiqueté `cost_source: "rate_card"`. Le tarif déclaré prime
  toujours. Les en-têtes de `usage.rs` et `pnl.rs` qui disaient « aucun prix
  dans le dépôt » sont corrigés : la règle vraie est « aucun prix appliqué au
  client qu'il n'ait déclaré ».
- **`send_invoice` reste `Risk::Low`.** Le catalogue doit porter le risque du
  domaine pour son `ActionKind` (un test l'exige), et c'est un `EmailSend` ;
  le passer High casserait cet invariant pour un gain nul : l'adresse est
  relue en base, un texte étranger ne peut qu'envoyer une facture émise à son
  propre client.

## Ce qu'on ne fait pas, et pourquoi

- **% de succès** : refusé par `forecast.rs`, et à raison. E le remplace.
- **Téléphone / voix / WhatsApp** : une facture opérateur par employé est
  exactement la ligne qui fait peur à 5K$. Reste éteint.
- **Rail de paiement, multi-région, rotation de clés** : aucun ne réduit la
  peur du client ; chacun coûte une vague.
- **Slack, GitHub, Notion, Salesforce, signature électronique** : intégrations
  par MCP, jamais reconstruites — l'humain y est l'utilisateur principal.
