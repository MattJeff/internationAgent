-- 0077_un_desabonnement_pousse_est_un_endpoint_aussi : le troisième ingest.
--
-- `0069_a_number_is_an_endpoint_too.sql` a écrit le brief de celle-ci, et il
-- tient en une phrase de son propre commentaire :
--
--     It is not a taxonomy of providers we like. It is the assertion that every
--     value in this column names an `event_type` some handler in
--     `main::handlers` is registered for.
--
-- Le handler est `main::on_smartlead_webhook`, enregistré sans condition sous
-- `webhook.smartlead.received` dans le même commit que cette ligne, et il
-- appelle `agentos_app::inbound::record_smartlead_unsubscribe` — qui écrit une
-- ligne de `suppressions`. Le reste est déjà là depuis `0011_revenue.sql` :
-- `suppressions_deactivate_contacts` désactive le CONTACT, donc le téléphone
-- tombe avec le mail, ce qu'aucune liste par canal ne sait faire.
--
-- ---------------------------------------------------------------------------
-- POURQUOI 'smartlead' MAINTENANT, ALORS QUE RIEN NE PEUT ENCORE S'Y ENREGISTRER
-- ---------------------------------------------------------------------------
--
-- Le câblage a deux moitiés et elles ferment la même porte par les deux bouts.
-- Cette CHECK dit « un ingest lit ces livraisons » ; `agentos_app::webhooks::
-- register` dit « et on sait les authentifier », et il refuse aujourd'hui avec
-- `EndpointError::SignatureHeaderUnposed`, parce que le nom de l'en-tête de
-- signature de Smartlead n'a jamais été lu sur une livraison réelle (la
-- recherche du 2026-09-02 conclut qu'il n'existe pas ; voir ce const et
-- `crates/app/src/inbound.rs`).
--
-- Poser la moitié base de données d'abord ne crée aucune ligne morte : aucune
-- ligne ne peut nommer `'smartlead'` tant que l'autre moitié refuse, et le jour
-- où quelqu'un lit l'en-tête sur une vraie livraison, la seule chose à changer
-- est un `const` dans du code compilé — pas une migration à écrire sous
-- pression pendant qu'un client attend ses désabonnements.
--
-- `'smartlead'` et pas `'email'`, pour la raison que 0069 donne pour `'twilio'`
-- et pas `'sms'` : la colonne nomme l'adaptateur dont le schéma de signature
-- vérifie la livraison, pas le canal. `'email'` est le schéma Standard Webhooks
-- (Svix/Resend) et son ingest est `main::on_webhook` ; Smartlead signe
-- autrement — HMAC-SHA256 sur le corps brut, comparé en temps constant, exemple
-- Python de https://api.smartlead.ai/core/webhooks relevé le 2026-09-02 — et
-- ses livraisons ne sont pas des mails reçus mais des rapports sur des mails
-- envoyés. Deux schémas, deux lecteurs, deux valeurs.
--
-- ---------------------------------------------------------------------------
-- ÉLARGISSEMENT, PAS REMPLACEMENT
-- ---------------------------------------------------------------------------
--
-- Toute ligne existante dit `'email'` ou `'twilio'` — l'ancienne CHECK n'a
-- jamais permis autre chose — donc ceci ne peut ni échouer sur des données
-- vivantes ni orpheliner une ligne. La contrainte est supprimée par son nom et
-- recréée sous le même nom, si bien qu'une base qui a joué 0069 et une base qui
-- ne l'a pas jouée finissent avec exactement une contrainte de ce nom et la
-- même définition. `drop constraint if exists` pour la raison que tout ce
-- répertoire donne : une migration à moitié appliquée doit être rejouable.
--
-- Ni RLS, ni grants, ni index : ceci touche une CHECK sur une table dont 0053 a
-- déjà forcé la RLS et à qui il n'a accordé aucun droit sur `app_role`.

alter table webhook_endpoints
  drop constraint if exists webhook_endpoints_provider_is_wired;

alter table webhook_endpoints
  add constraint webhook_endpoints_provider_is_wired
  check (provider in ('email', 'twilio', 'smartlead'));
