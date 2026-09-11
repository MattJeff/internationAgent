-- 0103: toute clé étrangère vers `employees` porte le locataire.
--
-- # Le défaut, une fois, en entier
--
-- La RLS ne s'applique pas à la vérification d'une clé étrangère. Postgres
-- exécute le déclencheur `RI_FKey_check_ins` en tant que **propriétaire de la
-- table référencée**, et le propriétaire ici est `postgres` : la lecture de
-- `employees` que la contrainte fait ne voit aucune policy. Donc
-- `references employees (id)` accepte l'identifiant du siège de n'importe quel
-- locataire.
--
-- La policy de la table enfant, elle, ne regarde que `tenant_id` — que la ligne
-- écrite porte correctement, puisque le code la remplit depuis
-- `tx.tenant_id()`. Les deux gardes sont satisfaites et la ligne passe :
--
--   locataire B, sous RLS, écrit `(employee_id = <siège de A>, tenant_id = B)`.
--
-- B n'en tire rien — la Gate refuse un employé que sa transaction ne voit pas —
-- mais la ligne **occupe la clé primaire**, et A ne peut plus poser la sienne.
-- Sur `employee_charters`, dont la clé primaire est `employee_id` seul, c'est un
-- déni de service à une ligne : B squatte la charte d'un siège de A, et A ne
-- peut plus en écrire une, ni voir pourquoi — la ligne fautive lui est
-- invisible, la RLS, elle, fonctionne.
--
-- # Pourquoi le schéma plutôt que Rust
--
-- Le correctif applicatif est une lecture de `employees` sous la RLS avant
-- l'écriture. `apps/server/src/routes/initiative.rs` la fait, et son commentaire
-- décrit déjà exactement ce défaut ; `content::repos::set` la fait aussi. Le
-- problème d'une lecture, c'est qu'elle vit *dans un appelant* : il y a
-- trente-sept clés étrangères vers `employees`, chacune atteinte par plusieurs
-- chemins, et un chemin neuf qui l'oublie ne se voit pas — les deux gardes
-- restent vertes et la ligne s'écrit.
--
-- Une clé étrangère composite est vérifiée par Postgres, sur chaque écriture,
-- par tous les chemins à la fois, y compris ceux que personne n'a encore
-- écrits. Ce n'est pas une idée neuve dans ce dépôt : `0007_sourcing`,
-- `0011_revenue` et `0037` font déjà porter le locataire à leurs clés, et
-- `0049_capability_requests` a créé pour cela l'index unique
-- `employees_tenant_id_key (tenant_id, id)` — dont cette migration se sert sans
-- rien ajouter. Son commentaire dit la même chose en une phrase : « composite,
-- pour que la paire soit vérifiée par Postgres plutôt que par un handler ».
--
-- # Deux détails qui décident de la forme
--
-- **`on delete set null` devient `on delete set null (employee_id)`.** Sans la
-- liste de colonnes, Postgres annulerait aussi `tenant_id`, qui est `not null`
-- partout sauf sur `policy_layers` : supprimer un employé échouerait au lieu
-- d'orpheliner sa ligne. La liste de colonnes est du PostgreSQL 15 ; le CI
-- tourne sur `pgvector/pgvector:pg18`, comme `docker-compose.yml`.
--
-- **`match simple` est le bon défaut**, et `policy_layers_version_scope` s'en
-- sert déjà pour la même raison. Une clé composite dont une colonne est NULL
-- n'est pas vérifiée. `employee_id` nullable avec `tenant_id` non nul : quand
-- `employee_id` est NULL la contrainte ne dit rien, exactement comme avant.
-- `policy_layers` est le cas inverse — `tenant_id` y est NULL pour la seule
-- couche `platform`, et le CHECK `policy_layers_scope` y interdit déjà un
-- `employee_id`. Les deux colonnes sont donc non nulles ensemble, ou jamais.
--
-- # Ce que cette migration peut casser, dit avant
--
-- `add constraint` valide les lignes existantes. Une base où le défaut a déjà
-- été exploité — une ligne dont le `tenant_id` ne correspond pas à celui de son
-- employé — fera échouer la migration en nommant la table fautive. C'est voulu :
-- un `not valid` laisserait la ligne squattée en place et le vrai propriétaire
-- du siège toujours dehors.

-- a2a_tasks
alter table a2a_tasks drop constraint if exists a2a_tasks_employee_id_fkey;
alter table a2a_tasks add constraint a2a_tasks_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- accounts
alter table accounts drop constraint if exists accounts_employee_id_fkey;
alter table accounts add constraint accounts_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- appointments
alter table appointments drop constraint if exists appointments_employee_id_fkey;
alter table appointments add constraint appointments_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- approvals
alter table approvals drop constraint if exists approvals_employee_id_fkey;
alter table approvals add constraint approvals_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- browser_tasks
alter table browser_tasks drop constraint if exists browser_tasks_employee_id_fkey;
alter table browser_tasks add constraint browser_tasks_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- conversations
alter table conversations drop constraint if exists conversations_employee_id_fkey;
alter table conversations add constraint conversations_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- counterparty_affinity
alter table counterparty_affinity drop constraint if exists counterparty_affinity_employee_id_fkey;
alter table counterparty_affinity add constraint counterparty_affinity_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- employee_charters
alter table employee_charters drop constraint if exists employee_charters_employee_id_fkey;
alter table employee_charters add constraint employee_charters_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- employee_initiative
alter table employee_initiative drop constraint if exists employee_initiative_employee_id_fkey;
alter table employee_initiative add constraint employee_initiative_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- employee_resources
alter table employee_resources drop constraint if exists employee_resources_employee_id_fkey;
alter table employee_resources add constraint employee_resources_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- employee_signing_keys
alter table employee_signing_keys drop constraint if exists employee_signing_keys_employee_id_fkey;
alter table employee_signing_keys add constraint employee_signing_keys_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- knowledge_sources
alter table knowledge_sources drop constraint if exists knowledge_sources_employee_id_fkey;
alter table knowledge_sources add constraint knowledge_sources_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- messages
alter table messages drop constraint if exists messages_employee_id_fkey;
alter table messages add constraint messages_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- model_usage_daily
alter table model_usage_daily drop constraint if exists model_usage_daily_employee_id_fkey;
alter table model_usage_daily add constraint model_usage_daily_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- negotiations
alter table negotiations drop constraint if exists negotiations_employee_id_fkey;
alter table negotiations add constraint negotiations_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- number_allocations
alter table number_allocations drop constraint if exists number_allocations_employee_id_fkey;
alter table number_allocations add constraint number_allocations_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- opportunities
alter table opportunities drop constraint if exists opportunities_employee_id_fkey;
alter table opportunities add constraint opportunities_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- opportunity_events
alter table opportunity_events drop constraint if exists opportunity_events_employee_id_fkey;
alter table opportunity_events add constraint opportunity_events_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- outreach_buckets
alter table outreach_buckets drop constraint if exists outreach_buckets_employee_id_fkey;
alter table outreach_buckets add constraint outreach_buckets_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- policy_layers
alter table policy_layers drop constraint if exists policy_layers_employee_id_fkey;
alter table policy_layers add constraint policy_layers_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- proof_of_need_attempts
alter table proof_of_need_attempts drop constraint if exists proof_of_need_attempts_employee_id_fkey;
alter table proof_of_need_attempts add constraint proof_of_need_attempts_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- prospect_flow_proposals
alter table prospect_flow_proposals drop constraint if exists prospect_flow_proposals_proposed_by_fkey;
alter table prospect_flow_proposals add constraint prospect_flow_proposals_proposed_by_fkey
  foreign key (tenant_id, proposed_by) references employees (tenant_id, id)
  on delete cascade;

-- provider_intents
alter table provider_intents drop constraint if exists provider_intents_employee_id_fkey;
alter table provider_intents add constraint provider_intents_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- psyche_beliefs
alter table psyche_beliefs drop constraint if exists psyche_beliefs_employee_id_fkey;
alter table psyche_beliefs add constraint psyche_beliefs_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- psyche_expectations
alter table psyche_expectations drop constraint if exists psyche_expectations_employee_id_fkey;
alter table psyche_expectations add constraint psyche_expectations_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- psyche_trust
alter table psyche_trust drop constraint if exists psyche_trust_employee_id_fkey;
alter table psyche_trust add constraint psyche_trust_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- purchase_orders
alter table purchase_orders drop constraint if exists purchase_orders_employee_id_fkey;
alter table purchase_orders add constraint purchase_orders_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- rfqs
alter table rfqs drop constraint if exists rfqs_employee_id_fkey;
alter table rfqs add constraint rfqs_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete set null (employee_id);

-- sequence_runs
alter table sequence_runs drop constraint if exists sequence_runs_employee_id_fkey;
alter table sequence_runs add constraint sequence_runs_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- spend_buckets
alter table spend_buckets drop constraint if exists spend_buckets_employee_id_fkey;
alter table spend_buckets add constraint spend_buckets_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- spend_caps
alter table spend_caps drop constraint if exists spend_caps_employee_id_fkey;
alter table spend_caps add constraint spend_caps_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- spend_reservations
alter table spend_reservations drop constraint if exists spend_reservations_employee_id_fkey;
alter table spend_reservations add constraint spend_reservations_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- team_memberships
alter table team_memberships drop constraint if exists team_memberships_employee_id_fkey;
alter table team_memberships add constraint team_memberships_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- turn_buckets
alter table turn_buckets drop constraint if exists turn_buckets_employee_id_fkey;
alter table turn_buckets add constraint turn_buckets_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- turn_outcomes
alter table turn_outcomes drop constraint if exists turn_outcomes_employee_id_fkey;
alter table turn_outcomes add constraint turn_outcomes_employee_id_fkey
  foreign key (tenant_id, employee_id) references employees (tenant_id, id)
  on delete cascade;

-- work_items : deux sièges nommés par la même ligne, chacun le sien.
alter table work_items drop constraint if exists work_items_assignee_id_fkey;
alter table work_items add constraint work_items_assignee_id_fkey
  foreign key (tenant_id, assignee_id) references employees (tenant_id, id)
  on delete set null (assignee_id);

alter table work_items drop constraint if exists work_items_posted_by_fkey;
alter table work_items add constraint work_items_posted_by_fkey
  foreign key (tenant_id, posted_by) references employees (tenant_id, id)
  on delete set null (posted_by);
