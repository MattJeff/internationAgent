# The company, running

*Last walked: 2026-08-28.*

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
| **Duration → enforced stop** | **absent** | — |
| Initiatives | built | `initiative.rs`, `loops/initiative.rs` |
| Employees talk to each other | built | `a2a.rs` |
| Browser | built | `browser.rs`, `effects.rs` |
| Email | built, one hole | `providers/src/email.rs` — see below |
| Work queues | built | `outbox.rs`, `queue.rs` |
| Chases (follow-ups) | built | `vertical.rs`, `due_chase` |
| New turns | built | `turn.rs` |
| Human requests | built | `/v1/capability-requests`, `/v1/approvals` |
| Emergency halt | built | `/v1/halt`, `halt.rs` |

## The gaps, stated plainly

**The run window does not exist.** Step 8 of the onboarding lets the founder
choose 2 days, 1 week or 1 month. `/v1/forecast` will *price* that window — it
even bounds itself to a quarter because its four inputs have a shorter shelf
life than that — but nothing enforces it. A company started today runs forever.

The intended shape, when it is built, is that **an expired window IS a halt**:
it surfaces through `halt::active()` with its own reason, so every place that
already respects the emergency stop respects the window for free and no second
list of callers has to be kept in sync. A manual halt beats a window that is
still open; a window can only close, never re-open.

**`EmailProvider` has no mandatory opt-out.** `LeadSink::opted_out` is a required
trait method, so a sending connector cannot be written without saying where
complaints arrive. The MCP catalogue got the same lock on 2026-08-27 — `OptOuts`
is a required field on `Connector` and a `const` block makes the lazy answer a
compile error. `EmailProvider` is `send` / `verify_webhook` / `fetch_inbound`
with no such method: an adapter written today would send mail with nobody forced
to name where the unsubscribes land.

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

- The Smartlead opt-out endpoint. Most urgent — outbound moves to the API on
  2026-09-01, and the catalogue entry is now a compile error without it.
- Whether we host a Google Ads MCP server, and carry the developer key.
- Whether we host the Smartlead stdio bridge.
- A default run duration, and what happens to work in flight when a window ends.
- The pricing tariff itself.
