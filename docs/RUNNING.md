# The company, running

*Last walked: 2026-08-28 (fifth pass, after waves C and D. The first two of the
founder's five internal tools are in — a shared work queue an employee can post
to, claim from and sign off, and a calendar that can promise an hour and be
woken by it.)*

This is the map of what a company does once it is live, and how much of it is
built. It exists because the shape is easy to draw and easy to get wrong in two
specific ways, both of which cost the customer money. Keep it current: when a
node changes state, change it here in the same commit, and move the date. A map
nobody walks is worse than no map, because it gets quoted.

Every claim below was checked against the tree on the date above. `file.rs` means
the thing exists there; **absent** means it does not exist anywhere, which is a
claim about the whole workspace and not about one file.

```
founder → defines the company
              models        ← first, because the guided interview is a turn
              objectives    ← so it runs on their model, never ours
              organisation · budgets · policies · tools
                          │
      ══════════════ COMPANY RUNNING ══════════════
                          │
   initiatives → work → a2a → browser / email / MCP
        ↑                            │
        │                    queues · chases · turns
        │                            │
        └──── new turns ─────────────┤
                                     │
              ┌──────────────────────┴─────────┐
        HUMAN REQUEST                       STOP
   (a purchase, a missing tool)     (halt · budget · window)
              │                              │
          founder ──────────────────────→ resumes
```

## Why the order of the setup column is not arbitrary

Models come before objectives. The guided objectives interview is a turn like
any other — gated, budgeted, audited — so it needs a model connected before it
can ask its first question. `model_for` is called in exactly one place,
`turn.rs`, when a turn is assembled; `provisioning::Step` is `Email | Phone |
Whatsapp` with no model step. So the line is already in the code: everything up
to "employees exist with real addresses" is model-free, and the first model call
is the first turn.

This is also what makes "priced on infrastructure only" hold. The moment AI
enters the flow it is the customer's key. We never spend a token, so there is no
token to price.

## Why the two bottom boxes are not decoration

A diagram of this product that goes down and loops, with nothing coming back up
and no way out, describes two bugs rather than a design.

**Without the return arrow**, a company that hits a wall either was omniscient at
setup or is silently stuck. Neither happens. An employee that needs a tool
nobody connected has to be able to say so.

**Without the stop**, the loop keeps taking turns forever, and every turn spends
the customer's model budget. A run that nobody told to end is the single most
expensive defect available in this product.

## Node by node

| Node | State | Where |
|---|---|---|
| Create the company | over HTTP | `POST /v1/companies` |
| Connect a model | built | `/v1/model`, `model_access.rs` |
| Teams, budgets, org chart | built | `/v1/org`, `/v1/teams`, runbook in `docs/TEAMS.md` |
| **Org from a ready-made template** | **absent** | the founder describes each team; nothing offers a starting shape |
| Employees, emails, phones | built | `/v1/employees`, `provisioning.rs` |
| Guided objectives interview | built | `/v1/interview`, `/v1/employees/{id}/interview` |
| Connect tools (MCP) | built | `/v1/mcp/*`, `catalog.rs`, `mcp.rs` |
| Budget and caps | built | `/v1/employees/{id}/spend-caps`, `/v1/billing`, `/v1/usage` |
| Duration → forecast | built | `/v1/forecast`, `forecast.rs` |
| Duration → enforced stop | built | `company_windows` (0054), `halt.rs`, `PUT /v1/window` |
| A new company gets one | built, **required** | `POST /v1/companies` refuses without `window_ends_at` |
| Hiring into a company with no window | allowed, on purpose | hiring is not acting: the seat is inert until a window exists |
| Provisioning during a stop | closed | the claim defers, except the one row whose provider call already went out |
| Cold-outreach ceiling | has a ledger | `outreach_buckets` (0055) — it was the only limit reserving nothing |
| Initiatives | built | `initiative.rs`, `loops/initiative.rs` |
| Employees talk to each other | built | `a2a.rs` |
| Browser | built | `browser.rs`, `effects.rs` |
| Email | built | `providers/src/email.rs`, `email_resend.rs` |
| Inbound STOP → suppression | built | `inbound.rs::land`, and the quote is cut first |
| Provider refusal → suppression | built | `inbound.rs::record_refusal`, gated on `permanent` |
| Work queues | built | `outbox.rs`, `queue.rs` |
| Chases (follow-ups) | built | `vertical.rs`, `due_chase` |
| New turns | built | `turn.rs` |
| Human requests | built | `/v1/capability-requests`, `/v1/approvals` |
| Emergency halt | built | `/v1/halt`, `halt.rs` |

## The gaps, stated plainly

**The run window is closed at the front door and open at the side one.** Step 8
of the onboarding lets the founder choose 2 days, 1 week or 1 month.
`/v1/forecast` prices that window, `company_windows` enforces it, `PUT
/v1/window` sets it, and `POST /v1/companies` now **refuses to build a company
without one** — optional would have handed the hurried caller the pre-0054
behaviour as the silent consequence of a missing field, and a default duration
would be a price nobody here may invent.

`POST /v1/org`, the *editing* door, still hires into a company with no window,
and that is now a decision rather than an oversight. **Hiring is not acting.** No
route reads `halt::halted` before hiring — not even under a manual stop — so
refusing a hire on an expired window would make a calendar stricter than the
emergency switch, which carries a human's sentence and no date. And the seat is
inert anyway: it cannot take a turn, be claimed by the outbox or the initiative
loop, or have a token minted for it, because all four read `halted()`.

**What is genuinely open is provisioning, and it spends real money.**
**That gap is closed, and this paragraph described it as open long after.**
`loops/provisioning.rs`'s `CLAIM_SQL` now ends in `not_stopped!("r.tenant_id")`,
so a stopped company's `pending`, `failed` and `pending_external` rows are not
claimed at all and nothing is bought for a company that is stopped. It still
runs on `admin_tx_bypassing_rls`, which is why the predicate is spelled into the
SQL rather than asked of a per-tenant reader.

The old argument — half-covering convergence is worse than not covering it,
because interrupting one leaves resources bought and unbound, which is what
`GET /v1/inventory/stranded` exists to find — was written when a stop was rare,
brief, and thrown by a human who meant to lift it. Since `0054` a company stops
**by itself, on a date, and can stay stopped for weeks**, which turned "we buy
anyway" from an hour's tolerance into a standing bill. The wedge that resolved
it: *not starting* a convergence that has bought nothing yet strands nothing at
all, and is not the same act as interrupting one in flight.

**What is still open, named rather than implied.** The one row a stopped company
*does* still get claimed for is a `provisioning` row whose lease has lapsed —
a provider call whose outcome nobody knows, and the only reconciler of one is
`converge`. `converge` takes an employee and not a step list, so that employee's
other pending steps converge with it. Closing that last gap is the resumable
state machine, and it is still not built.

There is still no backfill for companies that predate `0054`, because a backfill
needs a default duration, and a duration is a price.

The shape it shipped in: **an expired window IS a halt.** It surfaces through
`halt::halted()` with its own sentence, so every place that already respects the
emergency stop respects the window with no change, and no second list of callers
has to be kept in sync. A manual halt beats a window that is still open; a
window can only close, never re-open.

**The exception is the price of that shape, and it has been paid twice.** Some
statements are cross-tenant and cannot open a per-tenant transaction, so they
cannot ask `halt::halted()` and must spell the predicate into their own SQL. The
halt clause once landed in one and the window clause in the other, and for a
while a company whose month had ended still had its employees claimed and their
cadence spent — which is what "copy it by hand into both" costs.

**It is no longer copied by hand, and there are no longer two.**
`agentos_store::not_stopped!` is the one spelling of the predicate, pasted at
compile time, and it has **four** call sites: `store::outbox::claim_of`,
`store::initiative::claim_due`, `server::loops::outbox::lag_secs` and
`server::loops::provisioning`'s `CLAIM_SQL`. Two of those did not exist when
this paragraph said "two … by hand". The macro takes the clock as an argument
because the pollers inject a movable `now` and `lag_secs` reads the
transaction's own `now()`; passing the wrong one does not typecheck, which is
how the second arm was found. Anything added to `halt::halted()` still has to
be added to the macro — but to the macro, once.

**Three doors now demand an opt-out declaration, and nobody reads the answers.**
`LeadSink::opted_out` has always been a required trait method. The MCP catalogue
got the same lock on 2026-08-27 (`OptOuts` is a required field on `Connector`;
a `const` block makes the lazy answer a compile error), and `EmailProvider` on
2026-08-28 (`opt_outs()` is required with no default, and its enum has no lazy
variant — an email adapter's whole job is putting mail in front of people, so
there is nothing left to be lazy about).

There are now **three** production writers of a `suppressions` row: the campaign
platform's own list (`queue::reconcile_opt_outs`), a reply that asks not to be
contacted (`inbound.rs::land`), and a provider reporting a permanent refusal
(`record_refusal`). Every outbound message carries `vertical::OPT_OUT` inviting
the recipient to reply STOP, and that word finally does something.

Two details worth keeping, because both were nearly wrong:

* **The quotation cut is what makes a bare STOP work at all.** Our own footer
  contains the word and every mail client re-quotes it, so a rule that searches
  the whole message silences everyone who replies, and a length-bounded one
  never fires.
* **A bounce only counts when the provider itself calls it permanent.**
  `suppressions` takes no DELETE, so a full mailbox or a weekend outage read as
  a refusal removes a live customer with no way back — and nobody would find
  out, because the mail simply stops and the trail says it was asked for.

Third writer, third guard: `record_refusal` shipped without the
`EmailAddress::parse` its two siblings run first, so a complaint whose address
carried a display name rolled its own audit row back and dead-lettered. Found by
a pass whose only job was to look at the seams.

**There is no ready-made org chart.** `POST /v1/companies` stands a whole
company from one call, but the founder describes every team in it. Nothing
offers "a dev team, a growth team" as a starting shape. This one may not be a
gap at all: the decided target is people who *already have a SaaS*, and they
arrive with a stack, a server and a problem rather than a blank page. Left
unbuilt on purpose until somebody who is not the founder asks for it.

## The five internal tools, and where each one stands

The founder named five things a company cannot run without, and asked for them
built rather than integrated: *if the customer wants Slack and Salesforce they
plug them in, and if they want the AI to run the company on its own tools, that
has to exist too.* Each is a **port first and a table second** — an internal
tool that cannot become an integration is not worth building, because the day a
customer brings their own, the adapter has to have somewhere to plug in.

| # | Tool | State on the date above |
|---|---|---|
| 1 | **A shared work queue** | **Built, and the loop closes.** `work_items` (0061, `posted_by` in 0064), `Backlog` port, `/v1/work`. An employee posts, another claims, works, closes — `propose`/`perform` carry it, and the brief carries the pool and the seat's own items with the id on each line. |
| 2 | **A calendar** | **Built.** `appointments` (0063), `Calendar` port, `/v1/calendar`. An hour is promised, claimed when it comes round, and consumed. |
| 3 | **A thread with a human** | **Built, and it needed no table.** Half the mechanism was already here: a zero-turn seat is delivered to without being woken, which is the founder's own seat, so escalations already landed on a real desk. What was missing was a window and a pen — nothing read `messages.body`, and `/v1/reports` gave a *count* of questions owed rather than a sentence. `/v1/desk/{id}` reads it and writes back; 0065 is one partial index. |
| 4 | **Invoicing** | Not built. The company buys end to end and the selling path stops at the opportunity. |
| 5 | **A file store** | Not built. `knowledge` stores to retrieve; nothing keeps *the signed contract, as it is*. |

**The one thing tools 1 and 2 still wait on is the same thing**, and it is
not code: the catalogue line in `turn.rs::catalogue()` that lets a model reach
the verb. (Tool 3 needed none — the verb an employee uses to answer the founder
is `InternalSend`, already in the vocabulary and already in every role pack.)
Both are written out in full, in place, as comments — because
applying them moves `toolchoice::{TRUSTED_PROMPT, UNTRUSTED_PROMPT}`, and the
only thing entitled to re-pin those is a live measurement. The measurement
harness is proven (`cargo run -p agentos-eval -- --live`, five prompts through
the host's `claude` CLI, no key and no spend); running it is a deliberate act,
not a wave's.

**Two holes are named and open.** `0061` promises in writing that a terminated
employee's items *go back on the board unassigned*, and the referential action
that would do it never fires — termination is a column (`lifecycle =
'terminated'`), never a `DELETE`. The item stays assigned to somebody who will
never be briefed again, while `GET /v1/work` still shows it assigned: work
stops silently. The calendar has the mirror of it — its claim filters
`lifecycle = 'active'`, so a departed employee's promise never rings and sits
`rang_at IS NULL` for good.

## Not on the map, deliberately

**A success percentage.** Step 8 as originally stated returns "a % estimate of
the company's success". `forecast.rs` refuses to, argues why in its module docs,
and has a test that bans the words `success`, `probability`, `likelihood` and
`confidence` from any response it can produce. There is no population to draw
that number from. A percentage with decimals that nobody measured is worse than
no number, because it gets quoted back.

What the endpoint returns instead is what was actually measured: calls per turn,
sampled and dated, turned into a cost and a volume of work, as a range rather
than a point.

**`vertical::follow_up`.** It is `pub`, tested, argued at length, and called by
nothing outside `#[cfg(test)]`. It is the road not taken: it re-sends a message
that *carries the claim*, so it needs a freshness bar. `due_chase` shipped
instead and needs none, because a chase makes no claim at all — it says "we
wrote to you on this date", off our own column, past tense. Kept, and labelled,
rather than deleted.

## Still only the founder's to decide

These block work and cannot be guessed. They are listed here because a map that
hides its blanks is a map that lies.

- **The Smartlead opt-out endpoint.** Most urgent — outbound moves to the API on
  2026-09-01, and the catalogue entry is now a compile error without it.
- **Is the Resend endpoint subscribed to `email.bounced` and `email.complained`?**
  A checkbox in a dashboard; no process here can read it. If it is unticked, the
  complaint path is correct and simply never runs, and the dashboard is what to
  fix rather than any code.
- **A default run duration**, and what happens to work in flight when a window
  ends. Needed twice over: `POST /v1/org` still hires where there is no window,
  and there is no backfill for companies that predate `0054` — both blocked on
  the same number, and a duration is a price, so nobody here may invent it.
- ~~**`max_new_contacts_per_day: 0` ships in one of `docs/orizn-roles/*.json`.**~~
  **Decided 2026-08-28, and the question was the wrong one.** Two packs ship 0,
  and both are right: `growth` and `direction` have no outbound channel, so a
  cold-contact budget is a budget the channel rules refuse to spend, and
  `direction` is a figurehead seat with no channels and no turns, existing so
  the org chart's reporting lines are real. The prospecting seat's 5 a day is a
  warming schedule, not caution — a new sending domain that jumps to volume is
  classified as spam. **What is actually open is that nothing ramps**: the
  ceiling is a static number in a policy document, no path raises it as the
  domain ages, and there is no deliverability measurement to raise it against.
  Right the first week, wrong by the sixth month, and only a hand edit changes
  it. See `docs/ORIZN.md`.
- **How long can Resend re-deliver a webhook we have not acknowledged?** One
  number, two decisions: it is the floor under any retention on
  `outbox_events` — the row *is* the deduplication record, so deleting one and
  letting a provider re-deliver sends a second email and buys a second model
  call — and it bounds how long a stopped company's inbound mail can wait.
- **A ceiling on model round-trips inside one turn.** `Budgets` is a hard-coded
  default of ten with no lever, so a turn that needs eleven is stuck for good.
  Raising it must intersect like every other policy, which means a platform
  number that does not exist yet.
- **Should extending an expired window restart the company in one call?** It
  does today. The safer alternative is to require the two deliberate gestures a
  halt requires.
- Whether we host a Google Ads MCP server, and carry the developer key.
- Whether we host the Smartlead stdio bridge.
- The pricing tariff itself.
