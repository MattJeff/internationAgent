-- 0096_le_navigateur_tient_son_journal : une ligne par tâche de navigateur,
-- ce que Browserbase montre dans son tableau de bord — en logiciel.
--
-- `docs/BROWSER.md` § v2 (2026-09-10) : le journal et la vue en direct sont
-- deux lecteurs de la même narration, le port `BrowserObserver`
-- (`crates/providers/src/browser_observer.rs`). Cette table est ce que le
-- lecteur « journal » garde ; la vue en direct ne garde rien.
--
-- ---------------------------------------------------------------------------
-- CE QUI N'Y ENTRE PAS, PAR CONSTRUCTION
-- ---------------------------------------------------------------------------
--
-- Rien de la page. Pas de texte lu, pas d'image, pas de cookie, pas de valeur
-- tapée. Le port ne les transmet pas : une étape est *nommée* (`goto`,
-- `fill`…), son URL n'est donnée que pour `goto`, et une image n'est qu'un
-- flux vers qui regarde, jamais une colonne. La ligne qu'un `Fill` a remplie
-- avec un mot de passe ne peut donc pas finir ici — il n'y a pas de chemin.
-- C'est la raison pour laquelle `steps` est un tableau de cinq champs fixes
-- (`kind`, `url`, `outcome`, `took_ms`, `at`) et non un blob libre.
--
-- ---------------------------------------------------------------------------
-- POURQUOI `steps` EST UN JSONB ET NON UNE TABLE
-- ---------------------------------------------------------------------------
--
-- Une tâche a de une à quelques dizaines d'étapes, lues toujours ensemble et
-- toujours avec leur tâche, jamais requêtées seules. Une table fille serait un
-- `join` à chaque lecture pour un rangement que personne ne demande, et une
-- deuxième RLS à prouver. Un `jsonb || '[…]'` par étape est une écriture
-- courte sur une ligne chaude, et le lecteur reçoit le tableau tel quel.
--
-- ---------------------------------------------------------------------------
-- LE LOCATAIRE
-- ---------------------------------------------------------------------------
--
-- L'adaptateur ne le connaît pas (l'argument de `browser_chrome.rs` sur le pot
-- de cookies, 0095) : il narre un employé. `agentos_app::browser_journal` le
-- retrouve depuis `employees` sous `admin_tx_bypassing_rls`, puis écrit ici
-- sous `tenant_tx` — la lecture précède le locataire, l'écriture ne le
-- contourne pas. RLS `force`, comme 0091 : la console lit ses tâches sans
-- `WHERE tenant_id`, celles des autres sont invisibles.
--
-- `update` est accordé, contrairement à 0091 : une tâche est une ligne qui
-- s'écrit trois fois (début, étapes, fin), pas une trace. Pas de `delete` —
-- la cascade du locataire suffit.

create table if not exists browser_tasks (
  id           uuid        primary key,
  tenant_id    uuid        not null references tenants (id) on delete cascade,
  employee_id  uuid        not null references employees (id) on delete cascade,
  provider     text        not null,
  context      text        not null,
  started_at   timestamptz not null,
  ended_at     timestamptz,
  -- `ok` | `refused:<code>` | `failed:<code>` ; null tant que la tâche court.
  outcome      text,
  steps        jsonb       not null default '[]',
  frames_sent  integer     not null default 0,
  constraint browser_tasks_outcome_when_ended
    check ((ended_at is null) = (outcome is null)),
  constraint browser_tasks_steps_is_array
    check (jsonb_typeof(steps) = 'array')
);

create index if not exists browser_tasks_by_employee_idx
  on browser_tasks (tenant_id, employee_id, started_at desc);

alter table browser_tasks enable row level security;
alter table browser_tasks force row level security;
drop policy if exists tenant_isolation on browser_tasks;
create policy tenant_isolation on browser_tasks
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select, insert, update on browser_tasks to app_role;
