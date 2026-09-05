# Roadmap — « 5K$/mois d'infra, et le client sait qu'il peut être rentable »

Décidée le 2026-09-05, à partir d'une lecture du dépôt tel qu'il est (pas des
docs). Le trou n'est pas une capacité : c'est que les quatre chiffres qui
rassurent un acheteur — *qu'ont-ils fait, combien ça a coûté, combien ça a
rapporté, où est le point mort* — vivent chacun sur une route et personne ne
les met côte à côte. Le dépôt refuse d'imprimer un chiffre qu'il n'a pas
mesuré ; cette roadmap garde la règle : **chaque nombre ci-dessous sort d'une
ligne qui existe déjà**, ou d'un tarif que le tenant a déclaré lui-même.

Une case cochée est une case fusionnée sur `main` avec `scripts/test.sh` vert
et CI vert — pas un `tests_passing: true` rapporté par un agent.

## Vague 1 — le client voit ce qu'il paie et ce que ça rapporte (en parallèle)

- [ ] **A. Tarif déclaré + `GET /v1/pnl`** — migration 0079. `POST /v1/model`
      accepte `usd_per_mtok_input`, `usd_per_mtok_output`, `usd_per_mtok_cache_read`
      (le contrat Anthropic du client, jamais un prix du dépôt). `GET /v1/pnl?days=N`
      rend, par siège et en total : tours, tokens, `cost_usd` (null sans tarif,
      avec `cost_source`), factures émises / encaissées (nombre et montant),
      dépenses réservées / réglées, items du board clos, approbations demandées,
      refus de la gate. Même fenêtre que `/v1/usage`.
- [ ] **B. `GET /v1/refusals`** — le flux « ce qu'on a refusé » : les rows
      d'audit `decision = 'deny'` par motif, par verbe, par siège, avec la
      source non fiable quand le payload la nomme. Aucune table : c'est une
      lecture de l'audit.
- [ ] **C. `invoice_issue` et le file store atteignables depuis un tour** —
      les lignes de catalogue écrites en commentaire dans `turn.rs` sont
      appliquées ; `InvoiceIssue` reste haut risque donc invisible sur un tour
      taché ; les packs qui peuvent le proposer sont nommés. Le re-pin de
      `cost::DIGEST` et du tool-choice est fait à la main après fusion (deux
      runs `--live`, jamais par un agent).
- [ ] **D. Un message entrant devient un ticket** — un inbound (email ou SMS)
      d'un tiers qui atterrit chez un employé ouvre un item sur le work board,
      un seul par conversation tant qu'il est ouvert. Migration 0080 si un
      lien conversation ↔ item est nécessaire.

## Vague 2 — la boucle argent se ferme sans rail de paiement

- [ ] **E. Point mort dans `/v1/forecast`** — avec le tarif de A et le montant
      moyen des factures du tenant : *N tours ≈ X$ de tokens + infra ⇒ K
      factures de M pour être à l'équilibre.* Une division, pas un pourcentage.
- [ ] **F. Facture → PDF → email → encaissée** — la facture émise part par
      `EmailSend` avec le PDF en pièce jointe ; la livraison Stripe déjà
      stockée brute passe `declare_paid` automatiquement.
- [ ] **G. Relance d'outreach** — « relance J+3 sans réponse » est une promesse
      calendrier (`AppointmentBook`) que l'employé sait déjà poser ; remplace
      un séquenceur.
- [ ] **H. Export comptable** — CSV `invoices` + `spend` sur une fenêtre, pack
      finance.

## Vague 3 — ce qu'une entreprise paie ailleurs

- [ ] **I. Page publique de réservation** sur `AppointmentBook` (remplace
      Calendly).
- [ ] **J. Le briefing vente passe à l'axe catégoriel** avant toute ouverture
      d'outreach supplémentaire.
- [ ] **K. Un écran « caps + bouton d'arrêt »** : `max_turns_per_day`,
      `max_new_contacts_per_day`, plafonds de dépense, `/v1/halt` — au même
      endroit que le P&L.

## Ce qu'on ne fait pas, et pourquoi

- **% de succès** : refusé par `forecast.rs`, et à raison. E le remplace.
- **Téléphone / voix / WhatsApp** : une facture opérateur par employé est
  exactement la ligne qui fait peur à 5K$. Reste éteint.
- **Rail de paiement, multi-région, rotation de clés** : aucun ne réduit la
  peur du client ; chacun coûte une vague.
- **Slack, GitHub, Notion, Salesforce, signature électronique** : intégrations
  par MCP, jamais reconstruites — l'humain y est l'utilisateur principal.
