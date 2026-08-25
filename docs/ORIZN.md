# Standing up Orizn

Orizn sells entry-requirement data — passport plus destination in, visa or no
visa, documents, cost, processing time, vaccinations, overstay penalties and
embassies out, in fifteen languages — to the companies that are punished when
entry requirements are wrong: airlines carrying the fine and the return flight,
travel platforms carrying the refunds and the chargebacks, corporate travel
teams carrying duty of care, insurers and cruise lines carrying the claims.

This is how you build *that* company on this platform, in order, with the
commands you type. `docs/TEAMS.md` is the reference for what each call does;
this is the sequence, the numbers, and what those numbers cost.

Three files are the company, and they are meant to be read, edited and
re-applied rather than typed once:

| file | what it is |
|---|---|
| `docs/orizn-ceiling.json` | the platform ceiling — the widest anything in this deployment may be |
| `docs/orizn-org.json` | the org chart: five functions, five missions, five seats, one reporting line |
| `docs/orizn-policy.sql` | the role layers — the limits, because **no route writes one** |

`apps/server/tests/orizn.rs` applies all three against a real database and
asserts the company they produce. If this document and those files drift apart,
that test is what says so.

---

## What Orizn is staffed with, and what it deliberately is not

There are five role packs in this workspace. Orizn uses four of them.

| Function | Team slug | Head | Role pack | Turns/day |
|---|---|---|---|---|
| Direction | `direction` | `founder` | **none** | 0 |
| Commercial | `sales-development` | `sdr` | `sales-development` | 30 |
| Clients | `customer-success` | `support` | `customer-success` | 20 |
| Growth | `growth` | `acquisition` | `growth` | 10 |
| Finance | `finance` | `books` | `finance` | 6 |

**The team slug is the role pack's name, and that is not cosmetic.** A team's
slug is its initial `role_name`, and `role_name` is the key the policy loader
joins on. Name a team `commercial` while its seat wears the `sales-development`
pack and the limits you write under `sales-development` are limits the gate
never reads — until somebody remembers `PUT /v1/teams/{id}/policy-role`. Name
them the same and there is nothing to remember. The human-readable name is the
`name` field, which is what an operator sees and what nothing joins on.

### Direction is a chair, not an employee

`POST /v1/org` hires an employee for every row's head; there is no way to draw a
reporting line to a seat that holds nobody. So `founder` is minted as an AI
employee — and then given a role layer that permits nothing: zero turns, no
channel, no domain, no spend.

That row exists for one reason. An **absent** role layer inherits the layer
above it, so a team pointed at a `role_name` nobody has written limits for runs
on the ceiling. Leave `direction` unwritten and the seat at the root of the org
chart quietly becomes the most permissive employee in the company. The layer is
one `INSERT` with almost no columns, and it is the cheapest thing in this
document.

The founder is a person. This seat is the person's place in the chart and the
`reports_to` target of every head, and it is `UNCHARTERED` — `SystemPrompt::new`
alone is the internal channel and nothing else — because no role pack briefs it.

### Three functions deliberately left empty

`docs/TEAMS.md` §7 draws a seven-row generic startup. Orizn is not that company,
and copying the table would have produced two seats with a mission and no
briefing.

**Produit et technologie (CTO/CPO) — no seat.** There is no engineering role
pack in this workspace. Nothing here briefs a model to write, review and ship
*this* product's code. A CTO row would mint an employee with a mission an
operator can read back and a model has never been told, which is exactly the
gap `docs/TEAMS.md` already admits to under "a mission is stored, served and
never spoken". The founder writes the code.

**Opérations (COO) — no seat.** "Automatisation, procédures, partenaires" is not
a job any of the five packs does. The nearest is `international-buyer`, whose
briefing is about landed cost, incoterms and supplier lead times.

**`international-buyer` — the pack Orizn does not need.** It is the most
thoroughly built pack in the workspace: a whole objective type, a five-stage
plan, a psyche that learns which suppliers lie about lead times, and an
end-to-end test of a purchasing round. Orizn sources nothing. It sells an API.
Staffing a purchasing function here would put a supplier-negotiation briefing
and a purchasing budget in front of a company with nothing to purchase, and the
first thing it would do is go looking for suppliers that do not exist.

---

## The policy layer, function by function

Four layers intersect: `platform ∧ tenant ∧ role ∧ employee`. `store::policy::load`
takes the **minimum** of every cap and the **intersection** of every allowlist,
inside each decision's own transaction. `denied_domains` is the single field
that unions, so a lower layer can always add a block and never remove one.

> **Nothing below can widen anything, and the reason is arithmetic rather than
> discipline.** A role layer that names `max_per_day_minor = 10_000_000` under a
> ceiling that says `200_000` is worth `200_000`; a role layer that lists a
> domain the ceiling does not list resolves to the empty intersection. Writing a
> number bigger than the ceiling is not dangerous here, it is *dead* — and the
> only way to widen is `agentos-server policy install`, at the platform layer,
> by somebody with the database URL.

### The ceiling — `docs/orizn-ceiling.json`

| field | value | why |
|---|---|---|
| `max_per_transaction` | $500 | The largest single thing Orizn buys without a person deciding. Cloud, model credits, a domain, a provider plan — none is a $500 surprise. |
| `max_per_day` | $2,000 | Two days of everything, at once, in one day. |
| `approval_above` | **$1** | The default ceiling ships $100, i.e. an unsupervised band under a hundred dollars. Orizn has exactly one function that may pay and it already sends every payment to a person; a band nobody at this company is entitled to should not exist at the top either. One dollar means no configuration mistake *below* the ceiling can produce an unsupervised payment. |
| `allowed_channels` | `email`, `internal`, `web` | `web` is the operator console — inbound only, never gated as an outbound channel — so it grants nothing and is kept only to match the shipped default. |
| `allowed_calling_codes` | **empty** | Orizn phones nobody. The `sales-development` pack lists thirteen calling codes and `Channel::Voice`; this empty set intersects all fourteen away before any role layer is read. That is the ceiling doing its job, and it is why the sales role layer below writes `{email,internal}` rather than restating a `voice` grant that cannot survive. |
| `allowed_domains` | `orizn.com` | **This is where the prospect account list goes**, and it is the one genuinely awkward consequence of intersection: an allowlist entry can only be *removed* by a lower layer, so a domain that is not here is unreachable by everybody. `orizn.com` covers `docs.`, `status.` and every other subdomain — entries match themselves and everything beneath them. Adding an account to probe is a ceiling change: `policy install` again, and `/readyz` needs no restart. |
| `max_new_contacts_per_day` | 20 | The largest any function gets (customer success). |
| `max_turns_per_day` | 30 | The largest any function gets (sales). This is the blast radius of a typo: a team pointed at an unwritten `role_name` runs on exactly this. Thirty turns a day is about **$21 a month** — a number you can afford to be wrong about. The shipped default is 200. |
| the three booleans | `false` | Uploading, rotating a credential and deleting data are `AND`ed down the stack, so `false` here is `false` everywhere, forever, until the ceiling changes. |

**There is no tenant layer, on purpose.** This deployment has one tenant, so the
platform ceiling *is* Orizn's ceiling. A second, identical layer would be a
second place to forget to tighten. Write one the day a second tenant exists.

### The role layers — `docs/orizn-policy.sql`

Every number is at or below the ceiling. The full table with its inline
arguments is in the SQL file; the reasoning that does not fit in a comment is
here.

#### `sales-development` — 30 turns, **0 new contacts**, `{email,internal}`, `orizn.com`

The pack sets `max_new_contacts_per_day` to `0` and explains why: the gate reads
zero as "every first contact is denied", on every channel, with no second flag,
and B2B prospecting in the EU is lawful on legitimate interest — not
automatically. **This document keeps it at zero.** A document that switches cold
outreach on the moment it is applied is precisely the default the pack refuses
to be.

**What raising it commits you to.** Not a throughput setting; a legal boundary
you become the answer for. Before you type the number:

1. A **documented lawful basis** per approach — legitimate interest under GDPR
   Art. 6(1)(f), with a balancing test you could produce if asked. "They are a
   business" is not a basis; it is a precondition.
2. A **suppression list that is actually checked**, before every approach, and
   one opt-out treated as final across every channel and every future quarter.
   The briefing already instructs this; the list has to exist for the
   instruction to mean anything.
3. A **plain opt-out in every message**, and businesses only.
4. Being the **person who answers a supervisory authority** about a machine that
   mailed strangers on your behalf.

**Raise it to five.** The right number is the number of approaches you can
personally read that day, and at a company of one founder that is single digits.
Five approaches on thirty turns is a seller that spends most of its day on
evidence, which is what the pack's own plan puts before contacting anyone.

```sql
update policy_layers set max_new_contacts_per_day = 5
 where layer = 'role' and role_name = 'sales-development'
   and version_id = (select id from policy_versions
                      where tenant_id = :tenant and active);
```

Thirty turns a day is roughly ten findings, because the briefing makes a finding
require *two* runs of the same passport/destination pair — an unreproduced claim
about another company's booking flow is the one mistake in this job that cannot
be walked back. Ten findings a day is already more than one founder can follow
up on. The pack's default is 40; Orizn has one seller and no pipeline yet.

#### `customer-success` — 20 turns, 20 new contacts, `{email,internal}`, `orizn.com`

**Twenty new contacts, not zero, and the reason is a subtlety worth knowing.**
`ContactStanding` is computed from this employee's *own outbound trail*
(`app::gate::contacts`), so the first reply to somebody who wrote to us first is
a new contact as far as the gate is concerned. Zero would produce a support seat
that can only answer people it has already answered — which is every ticket
except the ones that matter. Twenty rather than the pack's forty because it
bounds how many strangers one support seat can mail in a day if the inbox is
flooded, deliberately or otherwise, and Orizn does not have twenty new
correspondents a day.

Twenty turns rather than the pack's eighty. Eighty is a ticket queue. Orizn's
inbound today is evaluation questions from prospects in technical trial, not a
queue. **This is the setting most likely to be wrong first** — the day an
airline goes live, a wrong entry requirement is a denied boarding, and this is
the number to raise.

#### `growth` — 10 turns, 0 new contacts, `{internal}` only, `orizn.com`

Zero contacts here means what it says rather than standing in for a policy
decision: there is no outward channel for a contact to happen on. The pack omits
`EmailSend` and `BrowserWrite` entirely, so nothing this seat produces reaches
the public through the model — it reads and hands drafts to a colleague.

That makes ten turns a purely economic decision, and the only one in this
document that is. A runaway growth seat costs tokens and nothing else. Ten is a
keyword study and three drafts; the pack's forty is a research team.

#### `finance` — 6 turns, 5 new contacts, `{email,internal}`, **no domains**, and the only spend row

The one function whose work genuinely ends in a payment. Refusing it would not
remove the payment, it would move it — to the buyer, whose interest is the goods
arriving. A company where purchasing is also treasury is the arrangement
double-entry bookkeeping was invented to prevent.

| | Orizn | pack default | why |
|---|---|---|---|
| per transaction | **$500** | $10,000 | Equal to the ceiling, restated deliberately: if the ceiling is ever raised, finance does not rise with it. $10,000 would have been dead anyway. |
| per day | **$1,000** | $25,000 | Half the ceiling. Two maximum-size transactions is a day; Orizn's recurring bills at this size are cloud, model credits, a domain and provider plans, and two of them landing in one day is already unusual. This is the structuring stop. |
| approval above | **$1** | $1 | Unchanged, and it is the counterweight to the whole arrangement. Finance's payees arrive on documents sent *to* us, which is the entire attack surface of this role, so there is no amount small enough to be routine. One dollar is this layer's way of spelling *every payment goes to a person*. |
| new contacts | **5** | 15 | The first chaser to a supplier's accounts inbox counts as new. Five, because a finance seat writing to five parties it has never written to before in one day is either a migration or something wrong. Fifteen was sized for a company with fifteen suppliers. |
| turns | **6** | 30 | Periodic, not continuous: one reconciliation pass and one payment run. Six is two of each with slack — and since every payment goes to a human anyway, a finance seat that wakes more often does not move money faster, it only produces more approvals for one person to read. |

`allowed_domains` is **empty** for finance, and that is a tightening rather than
an omission. The only sites it would want are the bank portal and the tax
authority, and a role that may not change a credential cannot log in to either.
A filing that genuinely needs a browser is a person's job or a declared MCP tool
with a name an operator wrote.

**A spend row is not a grant, and this is the step most likely to be missed.**
Three independent things must all say yes before a euro moves, and the policy
layer is only the first:

1. the **role layer** above — the ceiling on any one payment and on the day;
2. `spend_caps` for the employee — `PUT /v1/employees/{id}/spend-caps`. No row
   means no spending; there is no "unlimited";
3. `team_budgets` for the team, per currency — `PUT /v1/teams/{id}/budget`.
   **Absence of a budget is "may not spend", not "unlimited"**: `org::reserve`
   refuses outright with `team … has no budget in USD`.

Both calls are in the sequence below. Two of them and not the third is a finance
seat that passes the gate and is then refused at the reservation, which reads in
the logs like a bug and is a missing row.

---

## What this costs per month

Every turn pays for the context it carries, and `crates/eval/src/scoping.rs`
measured how much. Run it yourself — no API key, no network:

```sh
cargo run -p agentos-eval
```

> `one turn's context at 2 / 10 / 50 staff — 4188 → 4639 → 4863 tok`
> `(prompt 1238 + schemas 812 + context 2138)`

**4,639 input tokens per model call** at ten staff, by `scoping::tokens` — a
stated ±20% estimator, unverified against a real tokenizer, because there is
none in this workspace. Orizn has five employees, so ten staff is the closer of
the two published points.

The model is `claude-opus-5` (`providers::llm_anthropic::DEFAULT_MODEL`) at
**$5.00 per million input tokens and $25.00 per million output**. That rate card
is the one thing here that comes from outside this repository; `scoping.rs` says
so itself under what it does not measure.

`max_turns_per_day` counts **reserved turns**, and one reserved turn makes
between one and `app::turn::Budgets::max_turns` = **ten** model calls. The table
is the floor.

| Function | turns/day | input tokens/day | input $/month |
|---|---:|---:|---:|
| `direction` | 0 | 0 | $0.00 |
| `sales-development` | 30 | 139,170 | $20.88 |
| `customer-success` | 20 | 92,780 | $13.92 |
| `growth` | 10 | 46,390 | $6.96 |
| `finance` | 6 | 27,834 | $4.18 |
| **total** | **66** | **306,174** | **$45.93** |

`306,174 × 30 days = 9,185,220 tokens × $5/1M = $45.93`.

**Output is not measured anywhere in this workspace**, so it is an assumption and
labelled as one: at ~600 output tokens per model call, 66 turns a day is
1,188,000 output tokens a month = **$29.70**. The hard per-request ceiling is
`max_tokens = 4096`, so the worst case is about seven times that.

> ### **≈ $76 a month, and that is the number to budget.**
>
> $45.93 input + $29.70 output, at these settings, one model call per reserved
> turn. Two things move it, in opposite directions and both by a lot:
>
> * **Prompt caching lowers it.** `llm_anthropic` puts a `cache_control`
>   breakpoint on the system block, which caches tools and system together —
>   2,501 of the 4,639 tokens at ten staff. A prefix re-sent inside the cache
>   window bills at a tenth, which takes the input half to roughly $24 and the
>   total to about **$53**. `scoping.rs` deliberately prices cache reads at full
>   rate and says why: no rate card lives in this workspace, so full price is the
>   honest ceiling and the cache is upside.
> * **A ten-call turn raises it tenfold.** A turn that reads a page, calls a
>   tool, reads the result and answers is several model calls, each re-sending
>   the prefix. If every reserved turn ran the full loop the bill would be
>   **≈ $760**. The truth is between; `scoping.rs` lists "growth WITHIN a run"
>   as unmeasured, and it is the largest thing nobody here has numbers for.
>
> Two things are **not** in this figure: the provisioning loop's own calls, and
> the three trusted paragraphs the real path adds that `scoping.rs` cannot reach
> (the server's `TURN_BRIEF`, the initiative loop's, and `knowledge::RECALLED_BRIEF`).
> All three are constants, so they raise the per-turn number and cannot make it
> slope.

The lever an operator actually has is the turns column. Each turn per day, on
one employee, is **$0.70 a month** at the floor and $7 at the ceiling. Doubling
sales from 30 to 60 costs about $21 a month more and is a one-line `update`.

---

## The sequence

Everything below assumes:

```sh
export API=http://127.0.0.1:8080
export DATABASE_URL=postgres://…                 # the same one the server reads
export TENANT=$(uuidgen | tr 'A-Z' 'a-z')        # Orizn's tenant id — keep it
export KEY=$(openssl rand -hex 24)               # 48 chars; the minimum is 32
alias call='curl -sS -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"'
```

### 1. Boot the server once, so the migrations run

Nothing else creates the schema. `agentos-server policy install` reads
`DATABASE_URL` and nothing else — it does not migrate.

```sh
export AGENTOS_API_KEYS="ops:$TENANT:$KEY"
agentos-server
```

**It worked:** `curl $API/livez` returns `ok`.

**Most likely failure:** the process exits non-zero naming a provider variable
(`EMAIL_API_KEY`, `TELEPHONY_API_KEY`, `BROWSER_API_KEY`). That guard is
deliberate — a deployment that silently runs on mock adapters has detected
nothing. Set the credentials, or set `AGENTOS_ALLOW_MOCKS=1` and mean it.

**Second most likely:** a 401 on every request afterwards. `AGENTOS_API_KEYS` is
`label:tenant-uuid:secret`, comma-separated, and the secret must be **at least
32 bytes**. A short secret is a boot failure that names the entry's index; an
unset variable is a valid *empty* keyring and 401s silently.

### 2. Install the ceiling

```sh
agentos-server policy install docs/orizn-ceiling.json
```

**It worked:** it echoes the whole ceiling back as JSON and says
`/readyz will report ready on the next probe; no restart is needed`. Check it:

```sh
curl -sS $API/readyz
```
```json
{"mock_adapters":[],"outbox_lag_secs":0,"ready":true}
```

Before this step `/readyz` is `503 no_platform_policy`, and that is the safe
direction: **a deployment with no platform layer has no ceiling, and the gate
refuses everything until one is installed.**

**Most likely failure:**

```
agentos-server policy: this database has no policy tables yet. The migrations run
when the server boots: start agentos-server once — it will warn that there is no
ceiling and report not-ready — then run this.
```

You skipped step 1.

Re-running the same file changes nothing and says so — the installer compares
the parsed ceiling to the active one. To undo: `agentos-server policy rollback`,
which re-activates the previous version and deletes nothing.

### 3. Create the tenant row

There is no route and no CLI subcommand for this. `tenants` is RLS-protected
with `grant select` only, so a tenant can read its own row and cannot insert it.

```sh
psql "$DATABASE_URL" -c \
  "insert into tenants (id, slug, name) values ('$TENANT', 'orizn', 'Orizn')"
```

**It worked:** `INSERT 0 1`, and `call $API/v1/whoami` returns your `tenant_id`
and the key's label.

**Most likely failure — and it is an ugly one.** Skip this step and step 4
answers **`500 internal`** with an opaque body. The cause is only in the server
log:

```
insert or update on table "teams" violates foreign key constraint "teams_tenant_id_fkey"
```

The API key names a tenant; nothing checks the row exists until a foreign key
does. If `POST /v1/org` 500s at 2am, this is the first thing to check.

### 4. Apply the org chart

```sh
call -X POST $API/v1/org -d @docs/orizn-org.json
```

**It worked:** `202`, and the body is the whole chart — five teams, five
missions, five `employee_id`s, four `reports_to` pointing at `founder`, every
`hired` true. `202` means somebody is still being provisioned; a re-apply that
hires nobody answers `200`.

One transaction: either the whole chart exists or none of it does. Idempotent on
the slugs, so this file is meant to be edited and re-applied. It never
*removes* — deleting a row from the document leaves its team and its seat
standing, because taking down a head takes down every line under it and that
must be something you asked for.

**It grants nothing.** Not one `policy_layers` row. The only policy-adjacent row
it writes is the `team_policy` *pointer*, so a new team has a scope at all.

**Most likely failure:** `400` naming a `reports_to` that no row of the document
defines, with nothing written. Every `reports_to` must name a `head` **inside
this same document** — the resolution does not look at employees that already
exist.

Wait for the provisioning loop before step 6:

```sh
call $API/v1/employees | python3 -m json.tool
```

Every employee should reach `"lifecycle": "active"`. Until then the gate refuses
its actions, and an employee the gate refuses everything for is a row, not a
seat.

### 5. Write the policy layers — **this part is not an HTTP call**

```sh
psql "$DATABASE_URL" -v tenant="'$TENANT'" -f docs/orizn-policy.sql
```

Note the doubled quoting: `-v tenant="'$TENANT'"` so the substitution lands as a
SQL literal.

**There is no endpoint for this, and that is on purpose.** Grep confirms it:
outside test modules, exactly one function writes a `policy_layers` row —
`store::policy::install_ceiling`, whose `layer` is the string literal
`'platform'` inside the SQL text. `store::policy::install`, which *can* write a
role layer, carries a runtime guard that refuses on any database an operator has
run `policy install` against; it is fixture support and says so. Two places to
write a limit is one place to forget to tighten.

The file also creates the tenant's **active `policy_versions` row**, which
nothing else creates either. Role layers hang off that row: the loader's
predicate is `v.active AND l.layer = 'role' AND v.tenant_id = $1`, so a role
layer with no active tenant version is invisible.

**It worked:** `INSERT 0 5`. Then read the layers back:

```sh
psql "$DATABASE_URL" -c "select role_name, max_turns_per_day, max_new_contacts_per_day,
                                allowed_channels, max_per_day_minor
                           from policy_layers where layer = 'role' order by role_name"
```

```
     role_name     | max_turns_per_day | max_new_contacts_per_day | allowed_channels | max_per_day_minor
-------------------+-------------------+--------------------------+------------------+-------------------
 customer-success  |                20 |                       20 | {email,internal} |
 direction         |                 0 |                        0 | {}               |
 finance           |                 6 |                        5 | {email,internal} |            100000
 growth            |                10 |                        0 | {internal}       |
 sales-development |                30 |                        0 | {email,internal} |
```

**Most likely failure:**

```
ERROR: duplicate key value violates unique constraint "policy_versions_one_active_idx"
```

You ran it twice. That index permits one active version per tenant, and the file
is a create rather than an upsert on purpose: silently replacing a company's
policy version is not something a re-run should do. To change a number, `update`
the layer — the example is in the file's header — and the gate picks it up on
the next action, not the next deploy.

### 6. Give finance the two rows a spend row does not give it

```sh
export FINANCE=$(call $API/v1/teams | python3 -c \
  "import sys,json;print([t['id'] for t in json.load(sys.stdin)['teams'] if t['slug']=='finance'][0])")
export BOOKS=$(call $API/v1/employees | python3 -c \
  "import sys,json;print([e['id'] for e in json.load(sys.stdin)['employees'] if e['slug']=='books'][0])")

# The team's daily budget, reserved under a row lock on every permitted payment.
call -X PUT $API/v1/teams/$FINANCE/budget \
  -d '{"daily_total": {"minor": 100000, "currency": "USD"}}'

# The seat's own caps. `daily_transactions` is the count, not the money.
call -X PUT $API/v1/employees/$BOOKS/spend-caps \
  -d '{"daily_total":      {"minor": 100000, "currency": "USD"},
       "per_transaction":  {"minor":  50000, "currency": "USD"},
       "daily_transactions": 2}'
```

`daily_transactions: 2` is not a redundant copy of the money caps. At $500 a
transaction, two payments reach the $1,000 daily total exactly — so the count
keeps binding where the money caps stop noticing. A day with three $10 payments
is a day something is looping.

**It worked:** both return `200` echoing the numbers, and the budget read shows
`"remaining_minor": 100000`.

**Most likely failure:** forgetting one of them. The symptom is a payment that
passes the Policy Gate and is then refused at the reservation — `no spend caps`
or `team … has no budget in USD` — which reads in the logs like a bug and is a
missing row.

**No other function gets either call.** Sales, support and growth have no spend
columns in their role layer, which the loader reads as `spend: None` — "this
layer permits no spending at all" — and their packs do not list `PaymentCreate`
as proposable. Refused twice, in two independent places.

### 7. Verify, then watch the first turn

```sh
curl -sS $API/readyz            # {"ready":true,…}
call $API/v1/teams              # five teams, five missions, five policy_roles
call $API/v1/teams/$FINANCE/members
```

Give one employee an objective and watch:

```sh
call $API/v1/employees/$BOOKS/turns
```

`turns_today` climbs to `max_turns_per_day` and stops. That number is the one
you decided in the table above, and it is the token bill.

The audit trail is the record of everything step 4 onward did, attributed to the
**label of the API key** that did it — which is what makes "who gave the sales
seat a budget" answerable:

```sql
select occurred_at, actor, payload ->> 'event' as event
  from audit_log
 where action_kind = 'policy_changed' and payload ? 'event'
 order by occurred_at desc;
```

`decision_id` is null on all of them, and that is honest: no Policy Gate ruling
authorised these. They are an operator's key acting directly.

---

## What this document knows it does not do

**A mission is stored, served, and never spoken.** Every mission in
`docs/orizn-org.json` is a durable statement an operator can read back and an
employee has not been told. `Charter::system_prompt` takes the employee's
identity string and the caller composes it, so putting the team's mission in
front of a new employee is a `format!` at that call site. Until somebody makes
that call, these five sentences are documentation for humans.

**`POST /v1/org` 500s on a missing tenant row.** Step 3 is the workaround; the
fix would be a pre-flight check in `apply_org` that answers `400` naming the
tenant instead of letting a foreign key answer `500` with an opaque body.

**Nothing here proves the numbers are right.** The test asserts the company
matches this document. Whether thirty sales turns a day is the right number for
Orizn is a question that needs a month of running, and the honest answer today is
that it is the largest number that costs less than a coffee a week.
