-- 0056_one_open_round_per_employee: the constraint behind a sentence that was
-- only ever a convention.
--
-- `crates/store/src/sourcing.rs::open_rfq` says of itself: "**This is what
-- stops an RFQ going out twice.**" It is a `SELECT`, and `app::vertical`'s
-- `purchasing_turn` reads it in a transaction it *rolls back* — deliberately,
-- because the next thing it does is N emails and a pooled connection held
-- across somebody else's SMTP timeout is a connection nobody gets back. The
-- `rfqs` row is then written in a later transaction, after the last letter.
--
-- So between the read and the write there is a gap the width of a mail run, and
-- nothing in it serialises two turns of the same employee. The module's docs
-- reason about that gap for the *crash* case and take the honest trade — one
-- duplicate letter beats an open round nobody was asked. They do not reason
-- about the *concurrent* case, and the concurrent case costs more than a
-- duplicate letter: `Material::read` reads the newest open round only, so the
-- second round hides every quote the first one is answered with. The suppliers
-- did the work, we asked for it, and the buyer never sees it.
--
-- Two turns for one employee needs two replicas and a turn that starts more
-- than one cadence after its claim — `MIN_INTERVAL` is 300s and a full
-- initiative pass is documented at up to four minutes, so it is arithmetic
-- rather than a hypothetical.
--
-- The index is the fix rather than a lock or a state column, for the reason
-- `idempotency::begin` is arbitrated by a unique index and
-- `policy_versions_one_active_idx` holds "exactly one active version per
-- scope": a constraint cannot be forgotten by the next caller, and there will
-- be a next caller. The loser's `INSERT` fails, its transaction rolls back, the
-- first round stays the open one, and its quotes stay visible.
--
-- `employee_id` alone, not `(tenant_id, employee_id)`: `employee_id` is the
-- primary key of `employees` and therefore already identifies the tenant, so
-- the pair is the weaker of the two constraints — a row filed under the wrong
-- `tenant_id` would slip past it. It is also the leading column `open_rfq`
-- looks the round up by, so this index serves that read as well.
--
-- NULL `employee_id` is exempt and that is correct: a unique index treats every
-- NULL as distinct, `employee_id` is `on delete set null` so a round outlives
-- the employee who ran it, and a round belonging to nobody stops nobody asking.

-- Existing rows first, or the index does not apply and every database that
-- already has one refuses to migrate. Keeping the **newest** is not a choice
-- made here: it is exactly what `open_rfq`'s `ORDER BY created_at DESC, id DESC
-- LIMIT 1` already returns, so nothing any reader sees changes. The quotes on
-- the rows this closes were already invisible for the same reason; closing the
-- row does not lose them, it stops pretending they might come back. A round
-- swept here gets no `quote_returned` / `quote_missed` evidence, because
-- nobody was owed an answer by a round that should never have opened.
update rfqs r
   set state = 'closed', updated_at = now()
 where r.state = 'open'
   and r.employee_id is not null
   and exists (
         select 1 from rfqs newer
          where newer.employee_id = r.employee_id
            and newer.state = 'open'
            and (newer.created_at, newer.id) > (r.created_at, r.id));

create unique index if not exists rfqs_one_open_round_per_employee_idx
  on rfqs (employee_id)
  where state = 'open';
