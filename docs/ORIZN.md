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

Three documents are the company, and they are meant to be read, edited and
re-applied rather than typed once:

| file | what it is |
|---|---|
| `docs/orizn-ceiling.json` | the platform ceiling — the widest anything in this deployment may be |
| `docs/orizn-org.json` | the org chart: five functions, five missions, five seats, one reporting line |
| `docs/orizn-roles/*.json` | the role layers — one document per function, one command each |

`apps/server/tests/orizn.rs` applies all of them against a real database and
asserts the company they produce. If this document and those files drift apart,
that test is what says so.

> **There is no `psql` in this runbook any more.** Three steps used to be
> hand-written SQL — creating the tenant, creating its active policy version,
> and writing the role layers — because nothing in the codebase wrote those
> rows. All three are `agentos-server policy` subcommands now. Steps **3** and
> **5** are the ones that changed; the only SQL left below *reads*, and a read
> was never the problem. See "What stopped being SQL" at the end.

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
chart quietly becomes the most permissive employee in the company.
`docs/orizn-roles/direction.json` is the emptiest document in this repository
and it is the cheapest thing in this runbook.

The founder is a person. This seat is the person's place in the chart and the
`reports_to` target of every head, and it is `UNCHARTERED` — `SystemPrompt::new`
alone is the internal channel and nothing else — because no role pack briefs it.

#### The zero is still zero, and it now means something it did not

**A live dry run of this document found that no employee at Orizn could escalate
to its owner.** The gate allowed every `message_colleague` to `founder` —
`audit_log` says `internal_send | allow` — and the executor then refused it with
`no_turn_budget`, because sending an internal message reserves one of the
*recipient's* turns and this seat has none. The seller's next move was to invent
an email address for the founder and report the escalation as done.

Both halves were right. The zero above is right: this seat holds no charter and
must not burn model turns. The recipient-pays reservation is right: it is the
only throttle that stops two employees waking each other forever
(`crates/app/src/inbound.rs` argues it at length). What was wrong was that
nobody had reconciled them, and the seat where they collide is the root of the
org chart.

So `crates/app/src/inbound.rs::send` now asks one more question before it
charges anybody: **can a turn ever run for this recipient?** A seat whose
intersected `max_turns_per_day` is zero is *delivered to and not woken* — no
turn reserved, and no `agent.turn.requested` queued either. The message is a
real `messages` row on the founder's desk with a real `audit_log` receipt saying
`"woken": false`, and the seller is told in its tool result that a person reads
it and no reply will come.

Three things did **not** change, and they are the point:

* **The number.** `max_turns_per_day` is still `0`, so the bill below is
  untouched: `cost::turns_per_day` sums the five role layers and this seat
  contributes nothing to the sum. Giving it a budget would have been the cheaper
  fix and it would have bought a language model answering on the founder's
  behalf, at five sixty-sixths of whatever "What this costs per month" says
  today — and a charter for the one seat this file exists to keep empty.
* **The throttle.** Waking is what costs money, and nothing is woken here. The
  ceiling is still the sum of every employee's `max_turns_per_day`, because the
  only recipients exempted are the ones contributing zero to that sum. A seat
  with no budget can receive and can never send: it is a sink, not a relay.
* **The gate.** `may_message` is asked first and is unchanged, and the gate has
  already ruled before any of this runs. There is no escalation verb and no side
  door — only a price of zero for a recipient that consumes nothing.

**Who reads it.** `GET /v1/employees/{founder-id}/reports` — the morning screen
— already counts `questions_waiting_on` per direct report, off the same
anti-join that makes a question "outstanding". A seller blocked on the founder
shows up there as a number against its own name, with no new endpoint and no new
table. That is why escalation is an ordinary internal message rather than an
approval-queue entry: `approvals` binds a token to the hash of one `Action` and
re-checks it at execution, and an escalation authorises nothing.

**What it costs.** An employee you zero *by mistake* used to refuse its incoming
messages loudly and now accepts them into a mailbox nobody wakes for. That is
the real price, and `GET /v1/employees/{id}/turns` is where you find a zero you
did not mean.

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
> only way to widen past it is `agentos-server policy install` with no
> `--tenant`, at the platform layer, by somebody with the database URL.
>
> The one thing that does widen is a **rollback**: removing a layer returns that
> scope to inheriting the layer above. That is what an undo is, it is bounded by
> the ceiling like everything else, and it is why the ceiling is the operator's
> to write and a tenant's layers are not.

### The ceiling — `docs/orizn-ceiling.json`

| field | value | why |
|---|---|---|
| `max_per_transaction` | $500 | The largest single thing Orizn buys without a person deciding. Cloud, model credits, a domain, a provider plan — none is a $500 surprise. |
| `max_per_day` | $2,000 | Two days of everything, at once, in one day. |
| `approval_above` | **$1** | The default ceiling ships $100, i.e. an unsupervised band under a hundred dollars. Orizn has exactly one function that may pay and it already sends every payment to a person; a band nobody at this company is entitled to should not exist at the top either. One dollar means no configuration mistake *below* the ceiling can produce an unsupervised payment. |
| `allowed_channels` | `email`, `internal`, `web` | **`web` is not inert, and this cell said it was.** It is the operator console *and* — since reading became a channel — the one thing that permits `ActionKind::BrowserRead`, against any host not on `denied_domains` (`crates/domain/src/policy.rs`, `BrowserRead => closed(Channel::Web)`). Because the ceiling intersects downward, deleting it here takes **every** employee of this deployment off the web in one edit, and the refusal is invisible in `audit_log` because the tool is withheld rather than a call refused. Dropping the channel from a *layer* is the intended way to say "this seat does not browse" — see the `finance` section below, which does exactly that. |
| `allowed_calling_codes` | **empty** | Orizn phones nobody. The `sales-development` pack lists thirteen calling codes and `Channel::Voice`; this empty set intersects all fourteen away before any role layer is read. That is the ceiling doing its job, and it is why the sales role layer below writes `{email,internal}` rather than restating a `voice` grant that cannot survive. |
| `allowed_domains` | `booking.com`, `orizn.app` | **This is the *write* allowlist, and it is still where the prospect list goes.** Reading a page consults `Channel::Web` and `denied_domains` and not this — so an employee reads any public host without an entry here. But `Prober` *types* into a prospect's booking form (passport, destination, date) and that is a `BrowserWrite` on purpose, so the audit trail says what we did on their site. **A prospect the seller can read is not a prospect it can probe until its domain is here.** Entries match themselves and everything beneath them. |
| `denied_domains` | **empty** | The one thing a policy can still say about a *read*, and the strongest thing it can say about anything: denylists **union** across layers, so a host blocked at any layer is blocked for everybody and no lower layer can put it back. Empty because nobody has needed to block a host yet; this is where a competitor, a rate-limiting complaint, or a site that asked us to stop would go. |
| `max_new_contacts_per_day` | 20 | The largest any function gets (customer success). |
| `max_turns_per_day` | 30 | The largest any function gets (sales). This is the blast radius of a typo: a team pointed at an unwritten `role_name` runs on exactly this. Thirty turns a day is 30/66 of the bill in "What this costs per month" — a number you can afford to be wrong about. The shipped default is 200. |
| the three booleans | `false` | Uploading, rotating a credential and deleting data are `AND`ed down the stack, so `false` here is `false` everywhere, forever, until the ceiling changes. |

**There is no tenant layer, on purpose.** This deployment has one tenant, so the
platform ceiling *is* Orizn's ceiling. A second, identical layer would be a
second place to forget to tighten. Write one the day a second tenant exists.

### The role layers — `docs/orizn-roles/*.json`

Every number is at or below the ceiling. One document per function, named after
the `role_name` it is installed under, and the reasoning is here rather than in
the file because JSON has no comments.

Three fields are `[]` in every document and that emptiness is the control:

* `allowed_calling_codes` — Orizn phones nobody. The sales pack lists thirteen
  calling codes and the ceiling's empty set intersects all of them away before
  these documents are even read.
* `allowed_mcp_tools` — Orizn has bound no MCP server. When one is bound, its
  tools go into the *ceiling* first: a tool named here and not there is a tool
  no employee can reach.
* `allowed_a2a_peers` — selling to a company is not talking to its agent.

`allowed_models` is the one allowlist here that is **not** empty in any
document, and it cannot be: an employee with no permitted model takes no turn at
all. What each document names is its role's own model and everything cheaper —
see "Every seat used to run the same model" below for the table and for what an
operator changes to move it.

`denied_domains` is `[]` too, and it is the one field that *unions* across
layers, so a later document can add a block and nothing can remove one.

> **Empty means deny, and a missing field means deny too.** An empty allowlist
> is `DenyReason::NoRule` — not "unset", not "inherit". Because the layers
> intersect, **every document has to restate every grant it wants to keep**;
> there is no inherit marker and there deliberately is not one. That makes a
> hand-written layer lethal in a way that reads as harmless:
> `{"max_turns_per_day": 30}` looks like an edit and is a total replacement, and
> the seat that receives it quietly loses its channels, its domains and its
> spend while continuing to answer. Since `allowed_models` joined the struct it
> also loses its *model*, and that one is not quiet: the seat stops taking turns
> and says `no_model` rather than carrying on diminished. The trap is the same
> trap; one of its fields now sets off an alarm.
>
> So `policy install` **refuses a document that omits a field**, naming the ones
> missing. `"allowed_domains": []` is accepted and means deny — a finance seat
> with no bank portal is real, and so is a chair with no channel at all — but
> leaving the key out is not. The quickest complete starting point is what
> `agentos-server policy install` prints back: it is a whole layer, and every
> layer here is a whole layer.

#### `sales-development` — 30 turns, **5 new contacts**, `{email,internal,web}`, two write domains

The pack sets `max_new_contacts_per_day` to `0` and explains why: the gate reads
zero as "every first contact is denied", on every channel, with no second flag,
and B2B prospecting in the EU is lawful on legitimate interest — not
automatically. **The pack still ships zero.** A pack that switches cold outreach
on the moment it is installed is precisely the default it refuses to be.

**This document raises it to five**, which is an operator's decision and is
recorded here as one. It was made on 2026-08-26 by the founder, who is the
person point 4 below describes. What follows is what that number commits them
to, kept in the imperative it was written in because it is a standing
obligation and not a step that was completed.

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

**Five, and the reason is arithmetic rather than caution.** The right number is
the number of approaches you can personally read that day, and at a company of
one founder that is single digits. Five approaches on thirty turns is a seller
that spends most of its day on evidence, which is what the pack's own plan puts
before contacting anyone.

It is also the number the *delivery* path can absorb. Until 2026-09-01 the
seller's output is a queue a human uploads to Smartlead by hand, so a day's
openers have to be a day's reading. When the Smartlead API lands, the sending
becomes automatic and this number does not: it is a boundary on people
approached, not on the machinery that approaches them.

**One number, two counters — read this before you trust it.** `discover` spends
it against contacts *created* (`revenue::new_contacts_since`) and the approach
path spends it against contacts *written to*. They are separate counts against
the same limit, so five permits five rows created **and** five people
approached in one day, not five events in total. That is defensible — filing a
public business address and mailing its owner are not the same act — but it is
not what the field name says, and the number you write is doubled before it
becomes a promise.

**The prospect domains, and why there are none.** `booking.com` was added here
for one commit and then removed, because the question that put it there —
*"isn't it the research team that finds the sites we can sell Orizn to?"* — had
the answer *no, you type them by hand*, and that was a defect rather than a
design.

`PolicyLimits` had **one** `allowed_domains` set doing two jobs. Posting to
somebody's site is dangerous, so the set was kept tight; because it was tight,
the seller could only read `orizn.app`. A live dry run reported it in the
employee's own words: *"blocked on tool access — I have no way to read their
booking/servicing flows."*

The two jobs are now separate. **Reading is a channel**: an employee whose
layer carries `Channel::Web` reads any public host, and one whose layer does
not reads nothing — no list either way. **Writing keeps the allowlist**, which
is what `allowed_domains` means from here on.

**Half of the research problem is solved, and you should know which half.** The
seller reads any prospect's page without being handed it. It cannot *probe* one
— running a passport and a destination through their booking flow, which is
where the evidence comes from — until that host is on the write list, because
typing into somebody's form is a write. An early version of this change emptied
`allowed_domains` on the theory that nothing writes; the whole selling vertical
came back `no_rule`, three dry-run passes out of three. Widening the write list
the same way reading was widened is a second decision and has not been made.

What makes that defensible here rather than in general is not the policy, it is
the type system. `read_page` returns `Untrusted<String>`, which has no
`Display`, no `Deref` and no `Into<String>` — `crates/app/tests/ui` proves that
`format!("{}", …)` fails to compile — so a page's bytes cannot become an email,
a prompt or a column. And no role pack proposes `ActionKind::BrowserWrite` at
all, so nothing this company runs can post anywhere.

**What you give up.** You no longer know in advance which sites an employee
touched; you know afterwards, from `audit_log`, one `browser_read` row per
page. **What you keep.** `denied_domains` still refuses a host by name and
unions across layers, and `Domain::parse` refuses a name that is not on the
public internet at all — `.local`, `.internal`, `.home.arpa`, an IP literal —
so an employee cannot be pointed at something inside a network. What that
cannot see is a public name resolving to a private address; that needs the
resolver, and it is named in `PRIVATE_USE_SUFFIXES`' own documentation as not
covered.

Edit `max_new_contacts_per_day` in `docs/orizn-roles/sales-development.json`
and install it again:

```sh
agentos-server policy install --tenant $TENANT \
  --role sales-development docs/orizn-roles/sales-development.json
```

That is a **new policy version**, not an edit: the old one stays in
`policy_versions` and `agentos-server policy rollback --tenant $TENANT` puts it
back. The gate picks the change up on the next action, not the next deploy.

Thirty turns a day is roughly ten findings, because the briefing makes a finding
require *two* runs of the same passport/destination pair — an unreproduced claim
about another company's booking flow is the one mistake in this job that cannot
be walked back. Ten findings a day is already more than one founder can follow
up on. The pack's default is 40; Orizn has one seller and no pipeline yet.

#### `customer-success` — 20 turns, 20 new contacts, `{email,internal,web}`, `orizn.app`

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

#### `growth` — 10 turns, 0 new contacts, `{internal,web}`, `orizn.app`

Zero contacts here means what it says rather than standing in for a policy
decision: there is no outward channel for a contact to happen on. The pack omits
`EmailSend` and `BrowserWrite` entirely, so nothing this seat produces reaches
the public through the model — it reads and hands drafts to a colleague.

That makes ten turns a purely economic decision, and the only one in this
document that is. A runaway growth seat costs tokens and nothing else. Ten is a
keyword study and three drafts; the pack's forty is a research team.

#### `finance` — 6 turns, 5 new contacts, `{email,internal}` — **no web**, and the only spend row

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

**Finance does not browse**, and that is a tightening rather than an omission.
It used to be said with an empty `allowed_domains`; it is said with the absent
`web` channel now, which is the field that actually means it — and the change
is not cosmetic, because an empty allowlist would no longer withhold anything
from a read. The only sites this seat would want are the bank portal and the
tax authority, and a role that may not change a credential cannot log in to
either. A filing that genuinely needs a browser is a person's job or a declared
MCP tool with a name an operator wrote.

This is the seat to look at first if you want to know what the web channel
costs you: it is the one that says no.

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

**This section holds no arithmetic of its own, and that is the point.**

It used to. It published **≈ $76 a month**, derived here in prose from three
numbers: 4,639 input tokens per model call, an assumed 600 output tokens, and
**one model call per reserved turn**. The first was measured once and then moved.
The second was a guess. The third was the *floor* of a range that runs to ten,
quoted as though it were an estimate. When somebody finally ran the thing and
counted, every one of the three was wrong in the same direction, and the honest
figure was several times what this document said — because prose cannot be
re-run, so a number typed into it is right on the day it is written and drifts
silently forever after.

So the arithmetic now lives in `crates/eval/src/cost.rs`, in one function, with a
unit test anyone can redo by hand. Read it in thirty seconds:

```sh
cargo run -p agentos-eval          # the `orizn (bill)` surface
```

**The sentence in the box below is checked character-for-character against this
file on every `cargo test`** — the row `the runbook quotes this measurement`.
Edit it here and the build goes red. Measure a new one and the build stays red
until it is pasted in. There is exactly one copy of the number and this is not
it.

### Where each term comes from

| term | source |
|---|---|
| reserved turns a day | **`docs/orizn-roles/*.json`, summed by `cost::turns_per_day`.** Not restated anywhere |
| which model each seat runs | **`crates/app/src/rolepack*.rs` ∧ `docs/orizn-roles/*.json`.** The role pack names the model its job needs; the role layer's `allowed_models` bounds what the operator permits; `policy::model_for` intersects them, and `cost::seats` prices the answer. Neither half is restated |
| model calls per reserved turn | **measured**, by a live `--dry-run`. Between 1 and `app::turn::Budgets::max_turns` = 10 |
| input tokens per model call | **measured**, `scoping::tokens` over the bytes *we* send — a stated ±20% estimator, unverified against a real tokenizer because there is none in this workspace |
| output tokens per model call | **measured**, as the `claude` CLI reported them. Nothing of ours weighs a completion |
| the rate card | **Four rows, in `cost::rate_card`** — the only numbers from outside this repository. Anthropic list prices per million tokens, read 2026-08-26: `claude-haiku-4-5` $1/$5, `claude-sonnet-5` $3/$15, `claude-opus-5` $5/$25, `claude-fable-5` $10/$50 |

`direction`'s zero turns is a real zero and stays one, so the founder's chair
contributes nothing to the first row even though four employees can now reach it
— see "The zero is still zero" above.

### Every seat used to run the same model

It ran `claude-opus-5`, because the model was one process-wide string read from
`AGENTOS_LLM` and nothing between the config and the provider could vary it. A
seller writing three paragraphs from a template and an entry-requirements
analyst deciding whether a bilateral treaty is a revocable tolerance were billed
at identical rates.

They are not any more. Each role pack names the model its job needs and each
role layer bounds what this deployment will pay for, and what runs is the
intersection:

| seat | turns/day | asks for | layer permits | runs |
|---|---|---|---|---|
| `sales-development` | 30 | `claude-sonnet-5` | haiku, sonnet | **`claude-sonnet-5`** |
| `customer-success` | 20 | `claude-sonnet-5` | haiku, sonnet | **`claude-sonnet-5`** |
| `growth` | 10 | `claude-sonnet-5` | haiku, sonnet | **`claude-sonnet-5`** |
| `finance` | 6 | `claude-opus-5` | haiku, sonnet, opus | **`claude-opus-5`** |
| `direction` | 0 | — (no pack) | haiku | **`claude-haiku-4-5`** |

**These assignments are a starting point, not a finding.** Which model a role
needs is a claim about work quality, and nothing in this workspace measures that:
the closest instrument is `agentos_eval::toolchoice`, which has five cases and
scores which tool was reached for rather than the judgement the briefings are
about. Every one of them carries its reason in the pack, so moving one is an
argument rather than a preference swap.

**An operator narrows this by writing a layer, not by editing code.**
`allowed_models` is an allowlist and it intersects like every other one —
platform ∧ tenant ∧ role ∧ employee, narrowing only — so a tenant layer naming
only `claude-haiku-4-5` puts the whole fleet on Haiku whatever the packs prefer.
Two rules are worth knowing before you write one:

* **A role whose preference you exclude falls to the cheapest model you did
  permit**, never to the most expensive. "Only Sonnet, everywhere" is a sentence
  an operator is entitled to say without killing the fleet.
* **An empty set denies, exactly as it does for channels and domains.** An
  employee with no permitted model does not fall back to anything: its turn does
  not start, and it is recorded as `no_model` with the role and the preference
  named. That is not a provider failure and retrying will not fix it.

### Re-measuring it

One command, a database and the local `claude` binary. No API key and no spend:

```sh
DATABASE_URL=postgres://…/orizn_dryrun \
  cargo run -p agentos-eval --features live-orizn -- --dry-run 3
```

Three passes, not one: one run of a language model is an anecdote, and every
figure it prints is a spread across passes. It exits non-zero when a
**structural** check fails — the loop did not run, no tool was called, a tool
call got no ruling, the provider errored — and never for a number, because a
threshold on a sample is a flaky build that ends up deleted.

It prints a `RECORD` block. Paste it into `cost.rs` **together with its digest**,
which covers the three charters, the turn brief, the five operator documents
above, and the prospect the run seeds for the seller. Change any of them and the
recorded runs are answering a question about a different company; the suite says
so rather than letting the figure rot.

The prospect is in there because without one the seller has no work:
`vertical::due_prospect` answers `None`, the initiative loop resolves `no_work`,
and the sales seat takes an ordinary conversational turn instead of running
somebody's booking flow. Every figure recorded before 2026-08-26 was measured in
that state. The run now seeds one prospect per pass — an account, a contact and a
booking flow **confirmed** by a named human, written with the operator's own
database credential because `app_role` may not write `prospect_flows` — and the
seller probes it twice, files a finding, and has its approach refused by
`max_new_contacts_per_day`, which this deployment ships at `0`.

> ### $70–$84 a month over 3 measured runs at 66 reserved turns a day (3 on claude-sonnet-5, 1 on claude-opus-5); $50 floor at 1.00 model calls per turn, $526 ceiling at 10.00
>
> A **range**, because a reserved turn makes between one and ten model calls and
> any point estimate inside that is a choice. The floor is the arithmetic this
> document used to publish as its estimate.
>
> Three things move it and none of them is in the figure:
>
> * **Prompt caching lowers it.** `llm_anthropic` puts a `cache_control`
>   breakpoint on the system block, which caches tools and system together —
>   roughly half the prefix. A prefix re-sent inside the cache window bills at a
>   tenth. `cost.rs` prices cache reads at full rate and says why: no rate card
>   for them lives in this workspace, so full price is the honest ceiling and the
>   cache is upside.
> * **The provisioning loop's own model calls raise it.** The dry run stands the
>   company up before it starts counting.
> * **The shim is not the production path.** `--dry-run` drives the local
>   `claude` CLI, which renders tool schemas into the prompt and demands JSON
>   back, so the measured output tokens are a completion `llm_anthropic` would
>   not have produced.
> * **The token counts were all sampled from `claude-opus-5`**, which is what
>   every seat ran when the runs were recorded. The *prices* above are each
>   seat's own; the *counts* they multiply are borrowed. A seat on Sonnet will
>   plan differently and tokenize differently, and nothing here re-measures that
>   — re-run `--dry-run` to.
> * **`claude-sonnet-5` is at an introductory $2/$10 through 2026-08-31**, so the
>   three Sonnet seats bill about a third less than this until then. The standard
>   rate is used deliberately: a figure with five days left on it is exactly the
>   kind this document published once already.
> * **Under a subscription none of this is the right unit.** The local `claude`
>   CLI has no per-token invoice at all — the currency is a monthly seat and the
>   binding constraint is throughput. Every figure in this box is the metered-API
>   reading of a run that was not metered.
>
> And the turns column is a **ceiling on turns, not a forecast of them**: an
> employee with nothing to do reserves nothing and bills nothing.

The operator has two levers and both are `update` statements against a policy
layer. **Turns are linear**: the whole bill scales with `max_turns_per_day`, so
halving it halves every figure in the box, and doubling sales from 30 to 60
raises the total by 30/66 of it. **Models are the multiplier**: the same turn
costs $1/$5 per million on Haiku and $10/$50 on Fable, so the mix moves the bill
by up to ten times without a single turn being added or removed. Moving the whole
fleet to `claude-opus-5` — which is what this deployment did until the packs
could name a model — costs $303–$560 rather than the $193–$357 above; the
`the_company_bill_is_a_sum_over_seats_not_one_multiplication` test asserts that
direction of the inequality so the claim cannot rot.

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

### 3. Create the tenant — and the policy version its layers hang off

```sh
agentos-server policy new-tenant orizn Orizn --id $TENANT
```

**This used to be `psql`.** `tenants` is RLS-protected with `grant select` only,
so a tenant transaction can read its own row and cannot insert it — and there is
no route that could, because every route derives its tenant from the API key and
the key for a tenant that does not exist yet cannot authorise creating it. The
authorisation for this is `DATABASE_URL`, which is why it is a subcommand.

`--id` because your `AGENTOS_API_KEYS` entry already carries that uuid. Leave it
off and one is minted and printed, and then you have to put it in the keyring
and restart.

**It worked:** it names the tenant id **and an active policy version**. Then
`call $API/v1/whoami` returns your `tenant_id` and the key's label.

**Why one command writes two rows, and this is the part worth reading.** The
loader's predicate is `v.active AND l.layer = 'role' AND v.tenant_id = $1`. A
tenant with no *active* `policy_versions` row therefore has **invisible layers**:
every row you write in step 5 is skipped, every scope falls back to inheritance,
and the whole company runs on the ceiling. Nothing errors. `psql` shows the rows.
The gate has never read one. That version had no writer at all before this
command, so it could not be created without a database console and it could very
easily not be created at all — which is why creating a tenant without one is not
something this command can be asked to do.

**Most likely failure — and it is an ugly one.** Skip this step and step 4
answers **`500 internal`** with an opaque body. The cause is only in the server
log:

```
insert or update on table "teams" violates foreign key constraint "teams_tenant_id_fkey"
```

The API key names a tenant; nothing checks the row exists until a foreign key
does. If `POST /v1/org` 500s at 2am, this is the first thing to check.

**Second most likely:** `a tenant with this id or slug already exists`. This
command creates; it does not adopt. If the tenant is already there from an
earlier run, skip to step 4 — and note that `policy install --tenant` will give
a tenant that predates this command the active version it is missing, so an old
deployment is repaired by step 5 rather than by re-running this one.

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

### 5. Write the role layers

```sh
for f in docs/orizn-roles/*.json; do
  agentos-server policy install --tenant $TENANT \
    --role "$(basename "$f" .json)" "$f"
done
```

The filename is the `role_name`, which is the team slug, which is the role
pack's name — the one string the top of this document argues should be one
string.

**This step used to say "this part is not an HTTP call", and that is no longer
true — for a company being *created*.** Steps 3, 4 and 5 are one request now;
see "The whole company, in one call" below. What is still not an endpoint is
**changing** a limit that already exists, and that is the line rather than an
omission: `POST /v1/companies` writes a role layer where the tenant has none and
refuses `409 role_layer_exists` where it has one.

The asymmetry is arithmetic, not caution. An absent layer inherits the layer
above, so the effective policy before an install is `above ∧ above` and after it
is `above ∧ new` — and the loader takes the minimum of every cap and the
intersection of every allowlist, so **writing a layer where none existed cannot
widen anything, field by field.** Replacing one has no such property: the new
layer is not intersected with the one it displaces. So creating is safe for a
route to do and replacing stays here, on `DATABASE_URL`, which keeps two
sentences true that this system leans on —
`apps/server/src/routes/teams.rs`'s "two places to write a limit is one place to
forget to tighten" (there is still exactly one place to *change* one) and
`apps/server/src/policy.rs`'s warning that "the API key is the operator" is one
variable wide (the day something mints a per-seat token, that token finds every
role layer already written and can only be refused).

Editing a number is therefore still the command above: a new policy version, the
old one intact, `policy rollback --tenant $TENANT` to undo.

**One command per layer, therefore one policy version per layer.** The SQL file
this replaced was a single transaction: all five layers or none. That is gone,
and what replaces it is better for the failure that actually happens — a re-run
is **idempotent** rather than a duplicate-key error, so a loop that died after
three roles is repaired by running the loop again. Each of the five is separately
reversible with `policy rollback --tenant $TENANT`, which is what "undo the
customer-success change" actually means.

**It worked:** five lines saying `installed role layer <name> for tenant … as
policy version …`. Running the loop twice says `unchanged` five times and writes
nothing. Then read the layers back — this SQL is a *read*, and a read was never
the problem:

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

**Most likely failure — and it is the one this whole step exists to prevent:**

```
docs/orizn-roles/growth.json: this document omits spend, allowed_calling_codes,
denied_domains, …, and an omitted field is not "leave it alone" — the layers
intersect, so it is DENY.
```

You hand-wrote a layer with only the fields you meant to change. Because the
layers intersect and there is no inherit marker, everything you left out would
have been written as *nothing*: no channels, no domains, no spend, no turns. The
seat would keep answering and would silently have lost the web. Write the whole
layer — copy what `policy install` printed and edit it.

**Second most likely:**

```
this role layer is denominated in EUR and this deployment's active policy is
already in USD: a policy in two currencies cannot be intersected …
```

`EffectivePolicy::try_new` will not intersect two currencies, so this would have
refused *every* action the layer touches with `broken_policy` — which reads in
the logs like a bug in the gate rather than like a typo in a file. It is refused
before a row is written, in both directions: the ceiling refuses a currency the
layers below disagree with, and a layer refuses one the ceiling disagrees with.

**Third:** `no tenant … in this database`, naming the uuid and the `new-tenant`
command that makes one. You skipped step 3, or the uuid in `$TENANT` is not the
one in your API key.

To change a number, edit the document and install it again — a new version, the
old one still there, `policy rollback --tenant $TENANT` to undo. The gate picks
it up on the next action, not the next deploy.

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

### 8. Load the prospect lists

Everything above stands up a company with an empty pipeline. `accounts` and
`contacts` had no writer outside tests, so `contacts_due_for_follow_up` returned
nothing and the seller had nobody to write to. The lists are Smartlead exports
in `~/Desktop/VOYAGEURS`:

```sh
IMPORT="$BIN import --tenant $TENANT"

# Look first. --dry-run does every judgement and commits nothing.
$IMPORT --segment relocation --country PH --dry-run \
  ~/Desktop/VOYAGEURS/gisement_dmw_philippines.csv

# Then for real. Several files in one run are one transaction.
$IMPORT --segment relocation --country PH ~/Desktop/VOYAGEURS/gisement_dmw_philippines.csv
$IMPORT --segment tmc        --country HK ~/Desktop/VOYAGEURS/gisement_hongkong_tia.csv
$IMPORT --segment other                   ~/Desktop/VOYAGEURS/gisement_associations_eu.csv
```

**Run it twice if you are not sure.** A prospect is its domain and a person is
their address, both already unique per tenant in `0011_revenue.sql`, so a second
run reports `already there` and writes nothing. That is not a nicety: the
`getorizn_*` and `oriznapi_*` files are the same people under two sending
domains, and `gisement_associations_eu.csv` contains every row of
`smartlead_associations_ectaa.csv` **and** every row of the two FIDI files. Of
2,209 rows across the prospect lists, 1,133 are distinct people.

`--segment` is not guessed from the filename and `--country` is not guessed from
the row. Imported contacts are due for follow-up immediately; what leaves the
building is still capped by `max_new_contacts_per_day`, which for
`sales-development` ships at **0** — so an import is not a send, and step 5's
table is still the thing that decides.

**What the import will not store, and says so every run:**

| the founder's column | where it goes |
|---|---|
| `email` | `contacts.email`, lower-cased. The natural key. |
| `first_name` `last_name` | joined into `contacts.full_name` — **empty for 3,012 of 3,048 rows**, and nothing is invented to fill it. Smartlead's API requires `first_name` from 2026-09-01; that decision is not made here. |
| `company_name` | `accounts.legal_name`. **A row without one is refused by name** — its account would be its mailbox provider. |
| `phone_number` | `contacts.phone` only if it is already E.164. **584 of 2,044 are not** (`(02)83518906`) and are dropped, because that CHECK is what lets the suppression list match a number by equality, and normalising one means guessing a country. |
| `website` | `accounts.website` verbatim; `accounts.domain` is the host, minus `www.`, and is the identity. |
| `linkedin_profile` | **nowhere.** No column, and no data either — empty in all 3,048 rows. Any that turn up are counted and dropped, and that is the day to add the column. |
| `location` | `accounts.location` verbatim. `accounts.country` is `ZZ` unless you pass `--country`, because 118 spellings in three languages do not map to ISO-2 without guessing. |

An address on the suppression list is skipped, is not created, and is not
re-activated if it opted out between two imports. That is enforced inside the
INSERT *and* by a trigger under it.

### 9. Get the booking flows written — the employee proposes, you confirm

Step 8 gives the seller people to write to. It does not give it the thing the
cold email is *about*: the proof of need — the contradiction `proof_of_need`
finds by putting one passport/destination pair through a prospect's own booking
flow twice. That needs a `prospect_flows` row: an entry URL and five CSS
selectors, per prospect.

`app_role` holds no INSERT and no UPDATE on that table and it never will. The
reason is in `migrations/0032_prospect_flows.sql` and it is the reason this
vertical is sellable: a selector aimed at the wrong element that *exists* reads
the same wrong thing on both runs, passes the two-run bar, gets screenshotted,
and goes out as a dated claim about somebody's checkout with steps to reproduce
it. Nothing downstream can tell that from a real finding, because from the
inside it *is* one.

So the only thing that changes is who does the typing. The employee reads the
page and files a **proposal**; you read the proposal and **promote** it, in
batches. `0037_prospect_flow_proposals.sql` is the table it writes: full grants
for `app_role`, no column that can hold a person's name, and nothing anywhere
reads it into a probe.

```sh
# What is waiting: the page to open and the selectors to check on it.
agentos-server flow review --tenant $TENANT

# Then, having opened each page and checked each selector:
agentos-server flow promote --tenant $TENANT --by "Mathis Higuinen" --all

# Or only the ones you actually looked at:
agentos-server flow promote --tenant $TENANT --by "Mathis Higuinen" <account-uuid>...
```

`--by` means the same thing it means in `flow confirm`, because `promote` *is*
`flow set` followed by `flow confirm`, run in a loop on your own database
credential. A batch is one person's attention spent once instead of 1,615 times.
It is not a looser rule, and the caveat printed after it is the same caveat.

**What proposals do not cover.** A form whose fields carry no `id`, a submit
button whose `id` says nothing about itself, and — most of the time — the
results panel, which an entry-requirements widget usually renders only after the
form is submitted. `flow review` prints `NOT FOUND` against any of the three
columns `prospect_flows` has NOT NULL, `flow promote` refuses that prospect by
naming the column, and the answer is `flow set` for that one. Four selectors read
and one typed is still four fewer than five typed.

**Promotion grants nothing else, and this is the part that will surprise you.**
A promoted flow whose host is not on `allowed_domains` **will not probe**.
Reading a page consults `Channel::Web` and needs no entry there, which is why
the employee could look at the page in the first place — but the prober *types*
into the form, and that is a `BrowserWrite`, which is exactly what the row for
`allowed_domains` at the top of this document says. `sales-development` ships
with two write domains and neither of them is a prospect's. So promoting a flow
for `lufthansa.com` and expecting a probe is the mistake to expect; the probe
comes back refused with the domain named. Widening that list is
`agentos-server policy install` with the host added, per host, deliberately —
and it is a decision about typing into a stranger's system, which is not a
decision a data command gets to make on your behalf.

---

## What this document knows it does not do

**A mission is stored, served, and never spoken.** Every mission in
`docs/orizn-org.json` is a durable statement an operator can read back and an
employee has not been told. `Charter::system_prompt` takes the employee's
identity string and the caller composes it, so putting the team's mission in
front of a new employee is a `format!` at that call site. Until somebody makes
that call, these five sentences are documentation for humans.

**`POST /v1/org` still 500s on a missing tenant row.** Step 3 creates that row
with a command instead of a database console, so it is much harder to skip — but
it is still *possible* to skip, and the symptom is unchanged. `POST /v1/companies`
does not have this failure, because it creates the tenant its own API key names
before it applies anything; `POST /v1/org` on its own was not given the same
pre-flight, and the fix there is still the `400` naming the tenant.

**Five role layers are five policy versions, not one**, whichever door writes
them. Step 5 trades the SQL file's "all five or none" for a re-run that is
idempotent, which is the better trade for the failure that happens — but a loop,
or a call, that dies after three roles does leave two functions inheriting the
tenant's limits until it is run again, and nothing warns you. Re-run it;
`unchanged` five times is the all-clear. What the one-call form adds is that it
cannot die with the *chart* applied and the layers missing, because the layers
go first.

**The one-call form creates limits and never changes them.** That is the line
argued in step 5, and the cost is real: re-sending an edited `roles` map is a
`409` rather than an edit, so correcting a number after the company exists is
`agentos-server policy install --tenant`, one document at a time, exactly as it
was. A console that wants to edit limits over HTTP needs the thing
`apps/server/src/policy.rs` names as missing — a principal that *is* the
operator, rather than a key assumed to be — and not a wider route.

**`policy rollback --tenant` is a toggle, not a walk.** It moves to the most
recent version that is not the active one, so rolling back twice returns to
where you started — the same behaviour as the ceiling's rollback. Undoing three
changes is not three rollbacks; it is installing the layer you want.

**Nothing here proves the numbers are right.** The test asserts the company
matches this document. Whether thirty sales turns a day is the right number for
Orizn is a question that needs a month of running, and the honest answer today is
that it is the largest number that costs less than a coffee a week.

---

## What stopped being SQL

Three steps of standing this system up were hand-written `psql`, and they were
the three that decide what every employee may do. Each of them was SQL for the
same reason: **nothing in the codebase wrote that row.**

| step | was | is |
|---|---|---|
| 3. the tenant row | `insert into tenants …` | `agentos-server policy new-tenant orizn Orizn --id $TENANT` |
| 3. its active `policy_versions` row | a `with version as (insert …)` inside the policy file | the same command — the two rows are one transaction and cannot be separated |
| 5. the role layers | `psql -v tenant=… -f docs/orizn-policy.sql` | `agentos-server policy install --tenant $TENANT --role <name> <file>`, once per document |

`docs/orizn-policy.sql` is gone. Its five layers are `docs/orizn-roles/*.json`,
one document per function, each a complete `PolicyLimits` — because an omitted
field is a denial and the installer refuses a document that has one.

**What is still SQL, and correctly so:**

* the read-back in step 5 and the audit query in step 7. Both *read*. A read
  cannot silently deny an employee the web, which is the failure this exercise
  was about.
* nothing else. There is no write left in this runbook that is not a command.

**What is still not a route, and why.** The platform ceiling, and it never can
be: it belongs to no tenant, and every route derives its tenant from the API
key, so a platform write authorised by one tenant's key binds every other
tenant. That is a privilege escalation with a JSON body and no header fixes it —
the honest version of "prove you are the operator" is the database credential.
`agentos-server policy install` with no `--tenant` stays the only writer.

The tenant, role and employee layers were the same sentence until `POST
/v1/companies` split it in two. They belong to a tenant, and a tenant is exactly
what an API key proves — so *creating* one over HTTP is defensible and, because
an absent layer inherits, provably cannot widen. *Replacing* one can, so it did
not move. `apps/server/src/policy.rs` still argues both sides and both arguments
still hold; what changed is that they turn out to be arguments about replacing
rather than about writing.

---

## The whole company, in one call

Steps 3, 4 and 5 above are one request. The nine-step sequence is what you run
when you are *editing* a company that exists; this is what you run to bring one
into being, and it is what the product's own entry journey calls.

```sh
python3 - <<'PY' > /tmp/orizn.json
import json, pathlib
docs = pathlib.Path("docs")
json.dump({
  "slug": "orizn", "name": "Orizn",
  "org": json.loads((docs / "orizn-org.json").read_text()),
  "roles": {p.stem: json.loads(p.read_text()) for p in (docs / "orizn-roles").glob("*.json")},
}, __import__("sys").stdout)
PY

call -X POST $API/v1/companies -d @/tmp/orizn.json
```

The body is the runbook's own documents with two keys around them. There is no
third document in it, and that is the important part.

**The ceiling is not in this call and no default is invented for it.** It is the
one document here that belongs to no tenant, and `store::policy::default_ceiling`
— which exists, and is deliberately defensible *as* a policy — is 200 turns a
day, 50 new contacts and a $100 band nobody looks at, against this company's 30,
20 and **$1**. A route that filled a missing ceiling with the shipped default
would hand every company created through it something six times wider than the
one this document argues for, as the silent consequence of an omitted field. So
step 2 stays step 2, and a deployment with no ceiling gets
`409 no_platform_policy` naming the command — the same answer `/readyz` and the
boot warning already give.

**The empty seat cannot be forgotten.** Every `team` in `org.rows` must have an
entry in `roles`, checked against the body before a row is written. That is the
`direction` argument at the top of this document turned into a refusal: an
absent role layer inherits the layer above, so a team whose `role_name` nobody
wrote limits for runs on the ceiling — and the seat that would end up widest is
the one at the *root* of the chart, which every head reports to.
`docs/orizn-roles/direction.json` is every field present and every one of them
empty, and leaving it out is now a `400` naming it rather than a company.

**What is atomic and what is not.** The tenant row and its first
`policy_versions` row are one transaction (the pair is the invariant — a tenant
with no active version has *invisible* layers). Each role layer is one version,
as in step 5. The whole org chart is one transaction, as in step 4. **The call is
not**, and the guarantee is convergence rather than atomicity: re-send the same
body and every step that already happened answers `unchanged`, so a call that
died anywhere is repaired by replaying it. No `Idempotency-Key` — the tenant is
the key's own, a layer is its `role_name` and a seat is its slug, so a retry
converges by construction.

**And the order is the safety property.** The layers are written *before* the
chart, always. A call that dies in the middle leaves limits with nobody bound by
them; the other order would leave five employees on the platform ceiling with
nothing anywhere reporting it. `apps/server/tests/orizn.rs` cuts the call in both
places and asserts that neither one has hired.

**It still grants no money.** Step 6 is two more calls, deliberately: a budget is
the thing that moves money, and `org::reserve` reads the absence of one as "may
not spend". A company that stands up unable to pay anybody is the correct company
to stand up.
