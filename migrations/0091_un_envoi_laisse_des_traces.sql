-- 0091_un_envoi_laisse_des_traces : ce que le fournisseur nous dit d'un mail
-- après l'avoir pris — livré, ouvert, cliqué — et où ça se range.
--
-- Jusqu'ici `Delivery::parse` (crates/providers/src/email.rs) ne lisait que
-- trois événements Resend : `email.received` (un courrier entrant),
-- `email.bounced` et `email.complained` (un refus, qui finit dans
-- `suppressions`). Tout le reste — `email.delivered`, `email.opened`,
-- `email.clicked` — était rendu `Unread { kind }` et jeté à la porte. Le
-- fournisseur nous le pousse déjà, signé ; on ne le regardait pas.
--
-- Ce que ça change pour un employé : la relance J+3 (`follow_up`, 0082) sait
-- aujourd'hui qu'on n'a pas répondu, pas si on a lu. « Ouvert deux fois, pas
-- répondu » et « jamais ouvert » n'appellent pas le même mail — et une
-- séquence (0092) branche là-dessus.
--
-- Une ligne par événement, jamais mise à jour. Le message est retrouvé par
-- `provider_message_id` (`messages`, 0001) : c'est le seul identifiant que le
-- fournisseur connaît. `message_id` est posé à l'écriture quand la ligne
-- existe, et laissé nul sinon — un événement peut arriver avant que l'outbox
-- ait enregistré l'envoi, et on ne perd pas la trace pour autant.
--
-- `provider_event_id` dédoublonne les relivraisons du fournisseur : Resend
-- rejoue un webhook qui n'a pas reçu de 2xx, et deux « ouvert » pour un seul
-- geste faussent tout ce qui compte.

create table if not exists message_events (
  id                   uuid        primary key,
  tenant_id            uuid        not null references tenants (id) on delete cascade,
  provider             text        not null,
  provider_message_id  text        not null,
  message_id           uuid        references messages (id) on delete set null,
  -- `delivered`, `opened`, `clicked`. Les refus (`bounce`, `complaint`) ont
  -- déjà leur table, `suppressions`, et ne sont pas recopiés ici.
  kind                 text        not null,
  -- Le lien cliqué, pour `clicked` seulement.
  link                 text,
  occurred_at          timestamptz not null,
  -- L'identifiant de livraison du fournisseur (`svix-id` chez Resend), ou, à
  -- défaut, une clé dérivée du corps — voir `inbound::record_signal`.
  provider_event_id    text        not null,
  created_at           timestamptz not null default now(),
  constraint message_events_kind check (kind in ('delivered', 'opened', 'clicked')),
  constraint message_events_link_only_when_clicked
    check (link is null or kind = 'clicked'),
  constraint message_events_dedupe unique (tenant_id, provider, provider_event_id)
);

create index if not exists message_events_message_idx
  on message_events (tenant_id, provider_message_id, occurred_at);

create index if not exists message_events_by_message_idx
  on message_events (message_id, kind)
  where message_id is not null;

-- `force` autant qu'`enable`, comme `appointments` (0063) et
-- `unsubscribe_links` (0085) : le rôle applicatif ne lit que son locataire.
alter table message_events enable row level security;
alter table message_events force row level security;
drop policy if exists tenant_isolation on message_events;
create policy tenant_isolation on message_events
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Ajout seul. Pas d'`update`, pas de `delete` : une trace n'est pas corrigée.
grant select, insert on message_events to app_role;
