# The company, running

*Last walked: 2026-08-28 (third pass, after waves O, P and Q).*

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
| **Provisioning during a stop** | **open, and it spends money** | `loops/provisioning.rs` filters neither halts nor windows |
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
`loops/provisioning.rs`'s claim filters neither `company_halts` nor
`company_windows`, and runs on `admin_tx_bypassing_rls`. So the eleven resources
a hire leaves `pending` — mailboxes, phone numbers — are bought for a company
that is stopped. This module argues, correctly, that half-covering convergence
is worse than not covering it: interrupting one leaves resources bought and
unbound, which is what `GET /v1/inventory/stranded` exists to find.

That argument was written when a stop was rare, brief, and thrown by a human who
meant to lift it. Since `0054` a company stops **by itself, on a date, and can
stay stopped for weeks**, which turns "we buy anyway" from an hour's tolerance
into a standing bill. The wedge the old argument misses: *not starting* a
convergence that has bought nothing yet strands nothing at all, and is not the
same act as interrupting one in flight.

There is still no backfill for companies that predate `0054`, because a backfill
needs a default duration, and a duration is a price.

The shape it shipped in: **an expired window IS a halt.** It surfaces through
`halt::halted()` with its own sentence, so every place that already respects the
emergency stop respects the window with no change, and no second list of callers
has to be kept in sync. A manual halt beats a window that is still open; a
window can only close, never re-open.

**The exception is the price of that shape, and it has already been paid.** Two
statements are cross-tenant SQL driven by `tenants` with an injected clock —
`outbox::claim_of` and `initiative::claim_due` — so they cannot ask a per-tenant
reader and spell the predicate out instead. The halt clause landed in one and
the window clause in the other, and for a while a company whose month had ended
still had its employees claimed and their cadence spent. Anything added to
`halt::halted()` has to be copied into both by hand.

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
- **Should extending an expired window restart the company in one call?** It
  does today. The safer alternative is to require the two deliberate gestures a
  halt requires.
- Whether we host a Google Ads MCP server, and carry the developer key.
- Whether we host the Smartlead stdio bridge.
- The pricing tariff itself.
