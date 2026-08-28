-- 0067_files: le classeur — the bytes somebody gave us, kept as they are,
-- found by the name they were filed under.
--
-- The founder's sentence: *"knowledge stores in order to find again; nothing
-- keeps the signed contract, as it is."* This table is the second half.
--
-- ---------------------------------------------------------------------------
-- WHAT ALREADY HOLDS BYTES IN THIS SCHEMA, AND WHY NONE OF IT IS THIS
-- ---------------------------------------------------------------------------
--
--   1. **`agentos_app::inbound::BlobStore`** — the closest thing, and the one
--      that had to be read in full before this file was written. It is a trait
--      with **one method, `put`**, whose doc says in as many words: *"Whoever
--      reads them later can add `get` then, against a real object store."*
--      Nobody added it. It has exactly one implementation in the workspace,
--      `InMemoryBlobs`, a `HashMap` behind a `Mutex`, and
--      `apps/server/src/main.rs` constructs *that one* for the running server.
--      So a customer's attachments live for as long as the process does and are
--      gone on the next deploy, there is no second process that could see them,
--      and there is no reader at all: nothing in this workspace can hand an
--      attachment back. That is a defect this migration does **not** repair —
--      see the last section — but it settles the question this table exists to
--      answer, which was whether the store already existed. It does not.
--
--   2. **`knowledge_chunks` / `knowledge_sources` (0014, 0026)** — it *indexes*.
--      A document is split, each piece is embedded, and what comes back out is
--      the pieces a similarity search chose, as
--      `Untrusted<String>` passages with a `source_id`. The original bytes are
--      not a column anywhere in it: a PDF that went in cannot come back out, the
--      chunk boundaries are the chunker's and not the document's, and every read
--      is a *ranking*, never "this file". Keeping and finding-what-resembles are
--      different jobs and this schema now has both.
--
--   3. **`inbound_messages.attachments jsonb` (0001)** — metadata, and a derived
--      **key**: `agentos_app::inbound::blob_key` formats
--      `inbound/<tenant>/<message>/<attachment>` and stores that string in the
--      jsonb. The comment beside its writer reads *"a lost invoice is bad;
--      losing the email that carried it is worse"* — the message lands with a
--      key that resolves to nothing whenever the bytes could not be fetched. So
--      the column is a **pointer into a store that has no reader and no
--      durability**, which is the same finding as (1) from the other side.
--
--   4. **`bytea` elsewhere** — `sealed_*` (0014, 0040, 0042, 0050, 0053),
--      `api_keys.secret_hash` (0044), `mcp_tools.digest` (0013). Every one is a
--      ciphertext or a hash: bytes we produced about something, never bytes
--      somebody gave us. `identity.public_key` is ours too.
--
-- ---------------------------------------------------------------------------
-- WHERE THE BYTES LIVE: `bytea`, AND THE TWO SHAPES IT BEAT
-- ---------------------------------------------------------------------------
--
-- There is no cloud account and no S3 key in this deployment and none will be
-- registered, so the real options were three.
--
--   * **The local filesystem behind the port.** Rejected, and the deciding
--     reason is row-level security: **a file on a disk has none.** Every other
--     tenant boundary in this schema is one `USING` clause on one policy, and a
--     directory tree would move this one table's isolation into path arithmetic
--     over a *name a counterparty typed* — the exact string `blob_key`'s own
--     doc refuses to build a path from ("that string is attacker-chosen and this
--     one becomes a path"). Two more, each independently fatal: two server
--     processes on two machines do not share a directory, so the deployment
--     stops being horizontally scalable the day this ships; and a file written
--     outside the transaction that references it means a commit that fails
--     leaves an orphan and a rollback that succeeds leaves a lie. `pg_dump`
--     would also stop being a backup of the product.
--
--   * **Large objects (`lo_*`).** They hold 4 TB, which is the only argument for
--     them, and they lose everything this table is for: `pg_largeobject` is a
--     single system catalogue shared by the whole database, **it cannot carry a
--     row-level security policy**, and its rows are addressed by an oid that
--     every tenant's oid sits beside. Ownership is per-object and per-role, not
--     per-tenant, so isolation would have to be re-invented; the API for them is
--     a server-side function call rather than a value; and an unreferenced large
--     object is not deleted by deleting the row that pointed at it, so the
--     schema would acquire a vacuum job it does not have.
--
--   * **`bytea` in this table.** Chosen. The bytes are a *value in the row*, so
--     they are inside the transaction, inside `pg_dump`, and inside the same
--     `tenant_isolation` policy as the name beside them — the isolation is the
--     one this schema already enforces fifty times and not a second mechanism.
--
-- **THE CEILING THIS CHOICE IMPOSES, WRITTEN DOWN.** `bytea` tops out at 1 GB,
-- which is not the real limit. The real limits are two and both are smaller:
--
--   a. Postgres and sqlx materialise a `bytea` **whole, in memory, twice** (once
--      in the backend, once in this process) on both write and read. There is no
--      streaming read of a value.
--   b. `apps/server`'s `RequestBodyLimitLayer` is `MAX_BODY_BYTES` = 1 MiB for
--      every route in the API, and `POST /v1/files` carries its content as
--      base64 inside JSON — the shape `routes::queue` already argues for, since
--      the idempotency layer records `jsonb` responses only and would release a
--      raw body rather than replay it. Base64 is 4/3, so **the largest file this
--      API can accept is about 768 KiB.**
--
-- So the CHECK below is 1 MiB: the number the deployment already has, borrowed
-- rather than invented, and the same number `MAX_BODY_BYTES` holds. It is here
-- as well as at the HTTP layer for `0063`'s reason — a row is also reachable by
-- psql, and an unbounded `bytea` written that way is a `pg_dump` that never
-- finishes and a `SELECT` that takes the process down.
--
-- FOUNDER'S QUESTION, LEFT OPEN: 768 KiB does not hold every signed contract.
-- Raising it is two edits and a decision, not a redesign: a per-route
-- `DefaultBodyLimit` on `POST /v1/files` and this CHECK, moved together. Past a
-- few megabytes the answer is not a bigger number, it is the next adapter.
--
-- **THE NEXT ADAPTER, AND THE EXACT PATH TO IT.** `agentos_app::files::Files` is
-- a port for `crate::backlog`'s reason, so the day a customer wants their own S3
-- or Drive it is a constructor and not a rewrite. What that migration does to
-- *this* table is one line: `content` drops its NOT NULL. Everything else in the
-- row — the name, the declared type, the size, **the digest** — is ours and
-- stays, because it is the catalogue and not the storage. The digest is what
-- makes that adapter safe at all: it is the only thing that can say the bytes
-- somebody else's bucket handed back are the bytes we deposited.
--
-- ---------------------------------------------------------------------------
-- THE NAME IS THE ADDRESS, SO THE PRIMARY KEY IS `(tenant_id, name)`
-- ---------------------------------------------------------------------------
--
-- "Findable by their name" is the requirement, so the name is what the reads
-- take and there is no uuid beside it. A `id uuid primary key` with a unique
-- `(tenant_id, name)` next to it would be **two addresses for one file**, which
-- is the "two answers to one question" `0061` refuses for `ordinal` and a
-- priority enum. Nothing anywhere would have named the uuid: the port's `get`
-- takes a name, the index shows names, and the founder types a name.
--
-- The composite key is well precedented here — `mcp_servers` (0013),
-- `employee_teams` (0012), `turn_ledger` (0016) and eight others are keyed
-- `(tenant_id, …)` — and it is also the index both reads need, so this table
-- has no second index. The `on delete cascade` from `tenants` scans on
-- `tenant_id`, which leads the key, so `0061`'s extra index is not needed here.
--
-- **The name is text a counterparty may have typed.** It is bounded 1..=200,
-- borrowed from `a2a_tasks_id_length` (0005), `work_items_title_shape` (0061)
-- and `appointments_subject_shape` (0063) rather than invented, and control
-- characters are refused: a name is a label, and a label with a newline in it is
-- a way to forge a second line in an index somebody reads. It is **not** parsed
-- and never becomes a path — that is the whole of what choosing `bytea` bought —
-- so a name containing `/` or `..` is a name and nothing more.
--
-- ---------------------------------------------------------------------------
-- `digest`, AND WHY THE CHECK IS THE POINT OF IT
-- ---------------------------------------------------------------------------
--
-- "As it is" is checkable or it is a promise. `digest` is SHA-256 of `content`,
-- and the constraint `files_digest_is_the_content` says so **in the schema**:
-- `sha256(bytea)` is built in and IMMUTABLE since PostgreSQL 11, so it is legal
-- in a CHECK, and a row whose digest does not describe its bytes cannot be
-- written by anything — not by the port, not by psql, not by a restore of an
-- edited dump.
--
-- The column is not redundant with the constraint. A generated column would tie
-- the digest to whatever the bytes are *now*, which is exactly the question a
-- digest is asked; stored and constrained, it is a value that was true when the
-- row was written and is re-derivable at any later moment.
-- `agentos_app::files::PgFiles::get` recomputes it on every read and refuses a
-- mismatch, which is the half a CHECK cannot do — constraints are evaluated on
-- write, and bytes that rot afterwards rot silently.
--
-- ---------------------------------------------------------------------------
-- `content_type` IS AN ASSERTION AND IS STORED AS ONE
-- ---------------------------------------------------------------------------
--
-- Whoever deposited the bytes said what they were. Nothing verified it and this
-- table does not pretend otherwise: there is no sniffing, no allow-list, and no
-- CHECK beyond the length. It is recorded because a customer asking for their
-- contract back wants to be told what they filed, and it is
-- `Untrusted<String>` on the far side of the port for the same reason the name
-- is. **It is never echoed as a response `Content-Type` header** — see
-- `routes::files` — because a declared type that becomes a response header is
-- somebody else choosing how a browser executes their own bytes.
--
-- ---------------------------------------------------------------------------
-- NO DELETE, NO UPDATE: STRICTER THAN 0061 AND 0063, ON PURPOSE
-- ---------------------------------------------------------------------------
--
-- `work_items` and `appointments` get SELECT, INSERT and UPDATE, because each
-- has one state to advance — `closed_at`, `rang_at`. A file has none. So
-- `app_role` gets **SELECT and INSERT and nothing else**, and the row is
-- immutable from the moment it is written.
--
-- `0061` refused DELETE with an argument this table is the strongest case for:
-- *the instruction that erases a closed item is indistinguishable from the
-- instruction that erases an inconvenient one.* A signed contract is that
-- argument at its limit. Withholding UPDATE as well is the same sentence about
-- the other verb — an UPDATE grant on `content` is a way to replace a contract
-- with a different one and leave a row that looks untouched, which is worse than
-- deleting it, because a deletion is at least visible as an absence. A second
-- deposit under the same name is refused by the primary key, so **first write
-- wins and there is no spelling of "overwrite"**.
--
-- **THE FORCE ON THE OTHER SIDE, WHICH 0061 DID NOT HAVE.** A person has a right
-- to demand their data be erased, and a store that cannot erase is a store that
-- cannot honour it. That is a real obligation and not a hypothetical, and it is
-- the reason this section is longer than `0061`'s.
--
-- The door stays shut to `app_role` anyway, and the argument is about *who*
-- rather than *whether*. Erasure is lawful, rare, identified, and decided by a
-- human who has checked that the demand is genuine and that no retention duty
-- outweighs it. Nothing in that description is a thing a request or a turn
-- should be able to do. It remains possible today: the owning role — the
-- credential migrations run as, held by whoever runs the deployment — has every
-- privilege on this table and can `DELETE FROM files WHERE …` at a psql prompt.
-- That is not a hole; **it is the control**. The erasure right is exercised by a
-- person at a terminal, which is exactly the shape the obligation has.
--
-- WHAT IT WOULD TAKE TO OPEN IT, EXACTLY, so the day somebody wants a route it
-- is a decision and not a discovery:
--
--   1. `grant delete on files to app_role;` in a new migration.
--   2. A tombstone, or the deletion destroys its own evidence: a
--      `files_erased (tenant_id, name, digest, size, erased_at, erased_by,
--      reason)` table, written in the same transaction as the DELETE. The digest
--      is what makes it worth keeping — it proves which bytes were erased
--      without holding them, which is the only record that survives erasure
--      *and* satisfies it.
--   3. `DELETE /v1/files/{name}`, an operator key only, with a required
--      `reason`, and never a port method — see `agentos_app::files`.
--   4. A new `AuditKind`, because `agentos_store::audit`'s vocabulary is closed
--      and an erasure that is not in it is an erasure with no trail.
--
-- Until all four exist, this table forgets nothing.

create table if not exists files (
  -- Whose file. Written by the caller's transaction and never by the payload,
  -- like every other tenant column here; the policy below is what enforces it.
  tenant_id    uuid        not null references tenants (id) on delete cascade,

  -- What it was filed under, and the only address it has. Text somebody else
  -- may have typed — see above for the bound, the control characters, and why
  -- this never becomes a path.
  name         text        not null
                           constraint files_name_shape
                           check (char_length(btrim(name)) between 1 and 200
                                  and name !~ '[[:cntrl:]]'),

  -- What the depositor said these bytes are. An assertion, recorded as one.
  content_type text        not null
                           constraint files_content_type_shape
                           check (char_length(btrim(content_type)) between 1 and 200
                                  and content_type !~ '[[:cntrl:]]'),

  -- The bytes, unchanged. The floor is 1 for `0061`'s reason at one remove: a
  -- zero-byte file is not a document, and every empty file in a deployment
  -- would share one digest, which would make the column below say nothing.
  -- The ceiling is `MAX_BODY_BYTES`; see above for why it is that number and
  -- what raising it costs.
  content      bytea       not null
                           constraint files_content_size
                           check (octet_length(content) between 1 and 1048576),

  -- SHA-256 of `content`, and the constraint is what makes it a fact rather
  -- than a field. 32 bytes, checked, for `0042`'s reason.
  digest       bytea       not null
                           constraint files_digest_is_the_content
                           check (octet_length(digest) = 32 and digest = sha256(content)),

  created_at   timestamptz not null default now(),

  -- The name is the address. See above for why there is no uuid beside it.
  primary key (tenant_id, name)
);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
--
-- `force` as well as `enable`, so the owning role the migrations and the
-- cross-tenant loops connect as does not walk past the policy — `enable` alone
-- binds `app_role` and leaves the owner reading every company's documents,
-- which on this table is every company's contracts. `crates/store`'s
-- `a_classeur_is_one_company_s_and_the_catalogue_says_so` asserts it from
-- `pg_class.relforcerowsecurity` rather than from behaviour, because a
-- behavioural test passes on a table that only has `enable`.
--
-- `with check` as well as `using`, so nothing can be filed wearing another
-- company's id — a file deposited across the boundary is a document planted in
-- somebody else's records, and under `select`-only isolation it would be
-- invisible to us and readable by them.
--
-- No loop bypasses this. Unlike `appointments` and `outbox_events` there is no
-- cross-tenant claim here: nothing polls this table, so the policy binds every
-- connection that ever reads it.

alter table files enable row level security;
alter table files force row level security;
drop policy if exists tenant_isolation on files;
create policy tenant_isolation on files
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- No UPDATE and no DELETE. See the header: a deposited file is a record, first
-- write wins, and erasure is a person at a terminal.
grant select, insert on files to app_role;
