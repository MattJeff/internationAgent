-- 0052_initiative_fair_claim: the index a round-robin initiative claim needs,
-- and the removal of the one it replaces.
--
-- This is `0046_outbox_fair_claim` arriving by the second road. That migration
-- fixed the queue every *inbound* effect passes through; `employee_initiative`
-- is the queue every effect an employee starts **by itself** passes through, and
-- it had the same defect, unfixed, with the same absence of any symptom.
--
-- `crates/store/src/initiative.rs`'s `claim_due` ordered the whole table
-- `next_at, employee_id` across every tenant at once and took the first `BATCH`.
-- That is first-in-first-out over a shared resource with no ceiling on what one
-- participant may put in it: a customer with two hundred employees on a
-- five-minute cadence has forty due at any instant, `apps/server`'s initiative
-- loop drains four at a time, and a turn runs up to `TURN_DEADLINE`. A second
-- customer's single employee is then not late by a batch, it is late by however
-- long the first customer's backlog takes — and nothing about that is visible as
-- an error. No row leaked, no lock was held, no handler failed. The company
-- simply does not act, and the only person who can see it is the customer.
--
-- The claim is now round-robin: every tenant is offered a seat before any tenant
-- is offered a second one, expressed as a `CROSS JOIN LATERAL` from `tenants`
-- into each tenant's own due rows. This index is what makes that lateral an
-- index range scan of at most a batch's worth of rows per tenant rather than a
-- filter over the whole table.

create index if not exists employee_initiative_tenant_due_idx
  on employee_initiative (tenant_id, next_at, employee_id);

-- WHY THE OLD INDEX GOES, WHERE THE OUTBOX'S EQUIVALENT STAYED
--
-- `0046` argued for keeping `outbox_events_due_idx (available_at, id)` beside
-- the new one, because it still had a reader with a different shape:
-- `loops::outbox::lag_secs` asks for the oldest due row across every tenant,
-- which is a leading scan on `available_at`.
--
-- `employee_initiative_due_idx (next_at)` has no such reader. Its only consumer
-- in the workspace was the `ORDER BY next_at` this migration just replaced —
-- `initiative::get` and `routes::initiative` reach the row by its primary key,
-- and nothing anywhere asks "what is the oldest deadline in the deployment".
-- An index nobody reads is not free: it is a write on every claim, and a claim
-- writes `next_at` on every row it takes. So it goes, and the day something does
-- want the cross-tenant question it comes back in its own migration with a
-- caller attached.
drop index if exists employee_initiative_due_idx;
