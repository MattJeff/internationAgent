-- 0092_une_sequence_est_une_suite_de_promesses : ce que Lumail, Smartlead et
-- Lemlist vendent — déclencheur, email, attente, branche — sans l'interface,
-- et sans second chemin d'envoi.
--
-- La relance J+3 (`follow_up`, 0082) a choisi « ni table ni verbe » : une
-- promesse `appointments` posée après un `send_email`, annulée par la réponse,
-- et un réveil qui dit « écris encore une fois ». C'était juste pour UN pas.
-- Une séquence en a plusieurs, s'arrête sur une lecture (`message_events`,
-- 0091) et saute d'un pas à l'autre : il lui faut une position, et une
-- position est une ligne.
--
-- ---------------------------------------------------------------------------
-- CE QU'UN PAS N'EST PAS : UN ENVOI
-- ---------------------------------------------------------------------------
--
-- Un pas `email` ne poste rien. Il réserve une promesse calendrier *maintenant*
-- qui porte le run (`appointments.sequence_run_id`, ci-dessous) ; quand elle
-- sonne, `loops::initiative` réveille le siège avec un brief qui dit quoi
-- écrire, et le `send_email` que le modèle propose passe la Gate comme tout
-- autre : suppression, budget d'inconnus du jour, `MAX_TOUCHES`. Rien n'est
-- réécrit ici, rien n'est contourné. Les employés IA écrivent les mails ; le
-- code tient la règle.
--
-- Les pas eux-mêmes sont un `jsonb` et non une table : ils sont validés en
-- Rust (`agentos_app::sequence::validate`) à la définition, lus en bloc à
-- chaque tick, jamais requêtés colonne par colonne. Une table `sequence_steps`
-- serait une jointure pour rien.
--
-- ---------------------------------------------------------------------------
-- UN RUN PAR (SÉQUENCE, CONTACT) TANT QU'IL EST ACTIF
-- ---------------------------------------------------------------------------
--
-- L'index unique partiel est la garde : inscrire deux fois la même personne à
-- la même séquence, c'est lui écrire deux fois la même chose. Un run terminé
-- (`done`, `replied`, `stopped`) n'empêche pas une réinscription — c'est au
-- fondateur de juger — mais l'actif, oui.
--
-- `state` est un vocabulaire fermé : `active` avance, `done` a fini la liste,
-- `replied` a été arrêté par une réponse (`inbound::land`, dans la transaction
-- qui la pose), `stopped` par une règle et `stop_reason` dit laquelle
-- (`suppressed`, `max_touches`, `not_sent`).
--
-- `next_at` est ce que la boucle lit : `where state = 'active' and next_at <=
-- now()`. Un pas `email` la pousse d'un délai d'envoi pendant que la promesse
-- sonne ; `sent` la ramène à maintenant.

create table if not exists sequences (
  id          uuid        primary key,
  tenant_id   uuid        not null references tenants (id) on delete cascade,
  name        text        not null
                          constraint sequences_name_shape
                          check (char_length(btrim(name)) between 1 and 200),
  steps       jsonb       not null,
  created_at  timestamptz not null default now(),
  archived_at timestamptz
);

-- Un nom par locataire tant que la séquence vit ; une archivée libère le nom.
create unique index if not exists sequences_name_live_idx
  on sequences (tenant_id, name)
  where archived_at is null;

create table if not exists sequence_runs (
  id              uuid        primary key,
  tenant_id       uuid        not null references tenants (id) on delete cascade,
  sequence_id     uuid        not null references sequences (id) on delete cascade,
  contact_id      uuid        not null references contacts (id) on delete cascade,
  employee_id     uuid        not null references employees (id) on delete cascade,
  -- Le fil, connu après le premier envoi : `sent` le pose depuis
  -- `follow_up::sent`, dont c'est la clé (siège, canal, adresse).
  conversation_id uuid        references conversations (id) on delete set null,
  step            integer     not null default 0
                              constraint sequence_runs_step_nonneg check (step >= 0),
  state           text        not null default 'active'
                              constraint sequence_runs_state
                              check (state in ('active', 'done', 'replied', 'stopped')),
  stop_reason     text,
  next_at         timestamptz,
  last_message_id uuid        references messages (id) on delete set null,
  started_at      timestamptz not null default now(),
  ended_at        timestamptz,
  constraint sequence_runs_reason_only_when_stopped
    check (stop_reason is null or state = 'stopped')
);

create unique index if not exists sequence_runs_one_active_idx
  on sequence_runs (sequence_id, contact_id)
  where state = 'active';

create index if not exists sequence_runs_due_idx
  on sequence_runs (next_at)
  where state = 'active';

-- Même geste que 0082 : nullable, `set null`, pas d'index — une promesse qui
-- porte un run est lue par le run (« ma promesse a-t-elle sonné ? ») et par le
-- réveil (« ce coup de sonnette est-il une séquence ? »), jamais en masse.
alter table appointments
  add column if not exists sequence_run_id uuid references sequence_runs (id) on delete set null;

-- ---------------------------------------------------------------------------
-- Row-level security : copiée de 0085, `force` autant qu'`enable`.
-- ---------------------------------------------------------------------------

alter table sequences enable row level security;
alter table sequences force row level security;
drop policy if exists tenant_isolation on sequences;
create policy tenant_isolation on sequences
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table sequence_runs enable row level security;
alter table sequence_runs force row level security;
drop policy if exists tenant_isolation on sequence_runs;
create policy tenant_isolation on sequence_runs
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Pas de `delete` : une séquence s'archive (`archived_at`), un run se termine
-- (`state`). Ce qui a été écrit à quelqu'un reste lisible.
grant select, insert, update on sequences to app_role;
grant select, insert, update on sequence_runs to app_role;
