-- 0081_stripe_est_un_endpoint_aussi: une livraison Stripe est une livraison
-- de webhook comme les trois autres, et elle est la première qui fait entrer
-- de l'argent.
--
-- 0053 a posé la règle : `webhook_endpoints.provider` ne peut nommer qu'un
-- fournisseur dont un ingest lit les livraisons, parce qu'une ligne qui nomme
-- un fournisseur sans lecteur est huit réessais et une lettre morte par
-- livraison. 0069 a élargi à `twilio`, 0077 à `smartlead`. Celle-ci élargit à
-- `stripe`, et la moitié compilée est `main::handlers`, qui enregistre
-- `on_stripe_webhook` sans condition — `agentos_app::stripe` porte l'argument
-- sur ce que ce lecteur fait et ne fait pas.
--
-- Rien d'autre ne bouge : ni table, ni colonne. Le règlement d'une facture
-- est déjà `invoices.paid_at` (0066), le document est déjà une ligne de
-- `files` (0067), et la trace est une ligne de `audit_log` d'un genre nouveau
-- (`invoice_paid`, `invoice_payment_mismatch`) que 0001 n'a jamais borné par
-- une CHECK. Le tenant est celui de l'endpoint, comme pour les trois autres.
--
-- Replayable : DROP IF EXISTS puis ADD.

alter table webhook_endpoints
  drop constraint if exists webhook_endpoints_provider_is_wired;

alter table webhook_endpoints
  add constraint webhook_endpoints_provider_is_wired
  check (provider in ('email', 'twilio', 'smartlead', 'stripe'));
