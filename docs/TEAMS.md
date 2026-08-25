# Teams

Two teams of AI employees sharing one tenant — purchasing sourcing suppliers,
sales bringing in accounts — with different budgets, different tools and
different limits. This is how you set that up, end to end, with the calls you
actually type.

Everything below assumes:

```sh
export API=https://api.example.com
export KEY=…                       # the secret half of an AGENTOS_API_KEYS entry
alias call='curl -sS -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"'
```

The tenant is never in a URL or a body. It comes from the key, and only from the
key. A team id belonging to another tenant is a **404**, not a 403 — that is
deliberate, a 403 would confirm the id exists.

---

## Start here: the whole company in one call

The org chart an operator actually draws is a table, and `POST /v1/org` takes
the table. All of it, in one transaction.

```sh
call -X POST $API/v1/org -d '{
  "domain": "agents.example.com",
  "rows": [
    {"team": "direction", "name": "Direction",
     "mission": "Vision, stratégie, priorités",
     "head": "fondateur", "title": "CEO / fondateur"},

    {"team": "produit-et-technologie", "name": "Produit et technologie",
     "mission": "Produit, code, infrastructure, sécurité",
     "head": "cto", "title": "CTO/CPO", "reports_to": "fondateur"},

    {"team": "growth", "name": "Growth",
     "mission": "Acquisition, contenu, SEO, publicité",
     "head": "head-of-growth", "title": "Head of Growth", "reports_to": "fondateur"},

    {"team": "commercial", "name": "Commercial",
     "mission": "Prospection, démos, contrats",
     "head": "head-of-sales", "title": "Head of Sales", "reports_to": "fondateur"},

    {"team": "clients", "name": "Clients",
     "mission": "Support, activation, fidélisation",
     "head": "customer-success", "title": "Customer Success", "reports_to": "fondateur"},

    {"team": "operations", "name": "Opérations",
     "mission": "Automatisation, procédures, partenaires",
     "head": "coo", "title": "COO", "reports_to": "fondateur"},

    {"team": "finance-et-juridique", "name": "Finance et juridique",
     "mission": "Comptabilité, trésorerie, conformité",
     "head": "cfo", "title": "CFO externalisé", "reports_to": "fondateur"}
  ]
}'
```

```json
{"chart": [
  {"team": "direction", "team_id": "0198e6c1-…", "name": "Direction",
   "mission": "Vision, stratégie, priorités",
   "head": "fondateur", "employee_id": "0198e6b0-…", "title": "CEO / fondateur",
   "reports_to": null, "hired": true},
  …
]}
```

That was roughly twenty calls until now — create team, set mission, hire, seat,
point the line, per row — **with no transaction across them.** Any failure in the
middle left teams with no head, employees on no team and reporting lines aimed
at seats that were never made. That is not a request to retry; it is a company
to go and read first, by hand, before you dare send anything else.

Six things to know about it, and then the rest of this document is the same
table one field at a time.

**It is one transaction.** Either the whole chart exists or none of it does.
Every seat is resolved before a single reporting line is drawn, so row 3 may
name a manager that row 7 defines and the rows may be in any order at all. A
bad row leaves **zero** rows behind — not six good teams and a stuck seventh.

**It is idempotent, and honestly so.** A team is its `team` slug; an employee is
its `head` slug. Send the same body twice and you have the same company, no
error. Send it with a *changed* mission, name, title or `reports_to` and that
cell changes — this is a document you keep in git, edit and re-apply, not a form
you fill in once. It never *removes*: a row you delete from the document leaves
its team and its seat standing, because taking down a head takes down every line
under it and that must be something you asked for. No `Idempotency-Key` header
is needed; every object is keyed on a slug you chose.

**It hires.** A row may name an employee that does not exist yet, and it is
created exactly as `POST /v1/employees` creates one — the row, eleven `pending`
resources, and the outbox event that sends the provisioning loop after them. An
employee that already exists is found by its slug, never duplicated and never
re-slugged; `hired` in the response says which is which. `domain` applies only
to the hires: an existing employee keeps the address it was minted with.

**`202` means somebody is still being provisioned; `200` means nobody is.** A
first apply hires and answers 202. A re-apply that only corrected a mission has
nothing outstanding and says so.

**It grants nothing.** Not one `policy_layers` row. A mission is prose; every
restriction stays in the four-layer intersection at the top of this document,
where the loader can take the minimum. An endpoint that drew the org chart *and*
could widen a cap would be a second gate — see below, it is the one rule here
worth reading twice. The one policy-adjacent row it writes is the `team_policy`
*pointer* for a team it creates, so a new team has a scope at all; an existing
team's pointer is never moved by a re-apply.

**The refusals are all readable.**

| | |
|---|---|
| two rows naming one team, or one head | `400` — the document means two things |
| `reports_to` naming a head no row of the document defines | `400`, and nothing written |
| a reporting line that closes a loop | `409 reporting_cycle`, naming both ends |
| more than 500 rows | `400` — an org chart is written by humans |

```json
{
  "type": "/problems/reporting_cycle",
  "title": "that reporting line closes a loop in the org chart",
  "status": 409, "code": "reporting_cycle",
  "head": "cto", "reports_to": "fondateur"
}
```

One audit row per call, `payload.event = "org.applied"`, carrying the whole
chart — plus one `employee_created` row per hire, because that is the durable
record of which key minted something that will go on to buy a phone number.

---

## The one thing to understand first: a team can only tighten

A team does not have a policy mechanism of its own. `policy_layers` already
intersects four layers —

```
platform  ∧  tenant  ∧  role  ∧  employee
```

— and a team plugs into the **`role`** layer. `team_policy` is a *pointer*: it
records which `role_name` a team's limits are written under. There is no second
set of limit columns anywhere, and **no endpoint in this API writes a limit.**

What follows from that, and it is the sentence to remember:

> **A team can only ever tighten. It can never widen.**
>
> `store::policy::load` takes the **minimum** of each cap across the four
> layers. A role layer that says `max_per_day_minor = 10_000_000` under a tenant
> that says `1_000_000` is worth `1_000_000`. Allowlists intersect, so a role
> layer can only remove tools, channels, domains and peers from what the tenant
> already permits. `denied_domains` is the one field that *unions* — a lower
> layer can always add a block, never remove one.

> ### This is on the hot path
>
> `crates/app/src/gate.rs` calls `store::policy::load` **per decision, inside
> the decision's own transaction** — so what you write into `policy_layers`
> under a team's `role_name` is what the Policy Gate rules with, and an
> operator's change takes effect on the next action rather than the next
> deploy. A deployment with no `platform` layer has no ceiling and the gate
> refuses everything until one is installed; that is deliberate, and it is the
> safe direction.
>
> (Earlier revisions of this file warned that the gate used an in-memory
> `PolicyBook` and read none of this. That is no longer true — `gate.rs` reads
> the four layers, and its payment path reserves through `store::org::reserve`,
> which is the team budget below.)

Two more consequences that surprise people:

* **A team with no `policy_layers` row is not a team that may do nothing.** It is
  an *absent* layer, and an absent layer inherits the one above it — the
  tenant's. Pointing a team at a role name nobody has written limits for
  therefore **un-restricts** it back to the tenant ceiling. It does not lock it
  out. Same for taking an employee off a team: it goes back to the tenant's
  limits, it does not lose them.
* **An employee is on at most one team.** That is the primary key of
  `team_memberships`, not a house style. Two memberships would give the policy
  loader two `role` layers and it would keep whichever it read last — a coin
  flip between the purchasing budget and the sales budget, with every individual
  decision looking correct in the logs. `POST …/members` refuses a second one.

| The API can | The API cannot |
|---|---|
| Build the whole org chart in one transaction | Grant one thing by doing so |
| Create a team and its policy *scope* | Set a cap, an allowlist or a threshold |
| Repoint a team at a different `role_name` | Widen anything, at any layer, ever |
| Set a team's daily budget, per currency | Give a **section** a policy or a budget |
| Say what a team is for (its **mission**) | Make a mission mean anything to the gate |
| Move an employee between teams | Put one employee on two teams |
| Name a seat and point a reporting line | Give anybody a capability for being senior |
| Read the budget and today's spend | Delete a budget or a spend bucket (the ledger is append/update only) |

---

## 1. Create the two teams

The slug is the handle **and** the initial `role_name`. Creating a team creates
its scope, not its limits.

```sh
call -X POST $API/v1/teams \
  -d '{"slug": "purchasing", "name": "Purchasing"}'

call -X POST $API/v1/teams \
  -d '{"slug": "sales", "name": "Sales"}'
```

```json
{
  "id": "0198e6c1-3f42-7a10-9c55-2b1d0f9a7e31",
  "slug": "purchasing",
  "name": "Purchasing",
  "policy_role": "purchasing",
  "created_at": "2026-08-24T09:12:44.118Z"
}
```

`201`, not `202` — unlike an employee, a team is finished the moment the row is
written. A duplicate slug inside one tenant is a `409`; the same slug in another
tenant is fine.

Keep the ids:

```sh
export PURCHASING=0198e6c1-3f42-7a10-9c55-2b1d0f9a7e31
export SALES=0198e6c1-4a07-7bd2-83e0-5c9f11ab4402
```

List them back at any time:

```sh
call $API/v1/teams
```

```json
{"teams": [
  {"id": "0198e6c1-4a07-…", "slug": "sales",      "name": "Sales",      "policy_role": "sales",      "created_at": "…"},
  {"id": "0198e6c1-3f42-…", "slug": "purchasing", "name": "Purchasing", "policy_role": "purchasing", "created_at": "…"}
]}
```

## 2. Write the limits — and this part is **not** an HTTP call

The limits live in `policy_layers`, under the `role_name` the team points at, in
the tenant's **active** `policy_versions` row. There is no endpoint for it, on
purpose: two places to write a limit is one place to forget to tighten. There is
a **command**, which runs on the operator's own `DATABASE_URL`:

```sh
agentos-server policy install --tenant $TENANT --role purchasing purchasing.json
```

`purchasing.json` is a complete layer. Every field, every time — see the warning
below.

```json
{
  "spend": {
    "max_per_transaction": { "minor": 200000, "currency": "USD" },
    "max_per_day":         { "minor": 500000, "currency": "USD" },
    "approval_above":      { "minor": 100000, "currency": "USD" }
  },
  "allowed_channels": ["email", "whatsapp"],
  "allowed_calling_codes": [],
  "allowed_domains": [],
  "denied_domains": [],
  "allowed_mcp_tools": ["sourcing/rfq-send", "sourcing/quote-read"],
  "allowed_a2a_peers": [],
  "max_new_contacts_per_day": 15,
  "max_turns_per_day": 30,
  "allow_file_upload": false,
  "allow_credential_change": false,
  "allow_data_delete": false
}
```

A tool is `"server/tool"`, with a slash and slugs on both sides — that is how
`McpTool` displays and how `store::policy` parses it back. A dot does not parse,
and a layer with an unparseable tool does not *skip* it: the whole load fails and
every action for that employee is refused with `broken_policy`.

Sales may not spend at all, which is `"spend": null` — a layer with no spend
block permits no spending, whatever the tenant allows.

> **Every field, every time.** The layers *intersect*, so there is no "inherit"
> marker and an omitted field is **deny**, not "leave it alone". A file
> containing only `{"max_turns_per_day": 30}` looks like an edit and is a total
> replacement: that role silently loses its channels, its domains, its tools and
> its spend, and the seat keeps answering. The installer refuses a document that
> omits a field, naming the ones missing. `[]` and `null` written on purpose are
> accepted, because "no domains" and "no spend" are things people genuinely mean.

Every number is still a ceiling, not a grant: if the tenant's `max_per_day` is
`300000`, purchasing gets `300000`. And every install is a **new policy version**
— re-running the same document says `unchanged` and writes nothing, and
`agentos-server policy rollback --tenant $TENANT` puts the previous one back.

The tenant and its first policy version come from
`agentos-server policy new-tenant <slug> <name>`, which writes both in one
transaction: a tenant with no *active* version has invisible layers, because the
loader joins on `v.active`.

## 3. Point a team at a shared role (optional)

Two teams can share one set of limits — `purchasing-eu` and `purchasing-us` both
reading `purchasing` — and a team can be renamed without losing its policy,
because the pointer is separate from the slug.

```sh
call -X PUT $API/v1/teams/$PURCHASING/policy-role \
  -d '{"role_name": "purchasing"}'
```

```json
{"team_id": "0198e6c1-3f42-…", "policy_role": "purchasing"}
```

This moves a pointer and writes nothing else. Repointing at a role with no
layer written for it makes the team inherit the tenant's limits — see the
warning at the top. The audit row records both the old role and the new, so a
typo is at least attributable.

## 4. Budgets, per team and per currency

This is the half that pays for the org layer. Each employee already has its own
cap (`0003_spend`), but ten employees on one team can each be under their own
cap and jointly blow the team's budget, and every individual decision looks
correct in the logs. So the team budget is **reserved** under a row lock, not
checked — by `store::org::reserve`, which the Policy Gate calls on every
permitted payment, in the same transaction as its ruling.

```sh
# Purchasing: $5,000 a day, across the whole team.
call -X PUT $API/v1/teams/$PURCHASING/budget \
  -d '{"daily_total": {"minor": 500000, "currency": "USD"}}'
```

```json
{
  "team_id": "0198e6c1-3f42-…",
  "currency": "USD",
  "day": "2026-08-24",
  "daily_total": {"minor": 500000, "currency": "USD"},
  "spent_minor": 0,
  "remaining_minor": 500000
}
```

Sales gets **no budget row at all**, and that is the configuration, not an
omission:

> **Absence of a budget is "may not spend", not "unlimited".** A team with no
> `team_budgets` row in a currency is refused outright by `org::reserve`, with
> `team … has no budget in USD`. Fails closed, exactly like `spend_caps`.

Read the day's position:

```sh
call "$API/v1/teams/$PURCHASING/budget?currency=USD"
```

```json
{
  "team_id": "0198e6c1-3f42-…",
  "currency": "USD",
  "day": "2026-08-24",
  "daily_total": {"minor": 500000, "currency": "USD"},
  "spent_minor": 120000,
  "remaining_minor": 380000
}
```

`currency` is required — a budget denominated in USD says nothing about a
payment in JPY, and there is nothing sensible to guess. A currency with no
budget answers `"daily_total": null, "remaining_minor": null`.

Lowering a budget below what today has already reserved does not claw anything
back; `remaining_minor` floors at `0` and the next reservation is refused.
`team_spend_buckets` is a ledger, and this endpoint never writes to it.

## 5. Sections — an org chart, and nothing else

EMEA and APAC inside purchasing, tier-1 and tier-2 inside support.

```sh
call -X POST $API/v1/teams/$PURCHASING/sections \
  -d '{"slug": "emea", "name": "EMEA"}'

call $API/v1/teams/$PURCHASING/sections
```

> **A section carries no policy and no budget.** There is no endpoint that gives
> one either. The moment a section has limits of its own it is a fifth layer in
> a four-layer intersection, and the policy loader grows a case for it. If you
> need EMEA to be more restricted than APAC, they are two teams.

## 6. Staff the teams

```sh
export LENA=0198e6b0-11c2-7f4a-b8d3-6a2e5c7f9d10   # an existing employee id

call -X POST $API/v1/teams/$PURCHASING/members \
  -d "{\"employee_id\": \"$LENA\", \"section_id\": \"$EMEA\"}"
```

```json
{"team_id": "0198e6c1-3f42-…", "employee_id": "0198e6b0-11c2-…", "section_id": "0198e6c1-…"}
```

`section_id` is optional and must name a section **of this team** — another
team's section is a `400`, not a foreign-key error at 500.

Adding an employee that is already on a team is refused, and the refusal names
the team it is on:

```sh
call -X POST $API/v1/teams/$SALES/members -d "{\"employee_id\": \"$LENA\"}"
```

```json
{
  "type": "/problems/already_on_a_team",
  "title": "that employee is already on a team; move it instead of adding it",
  "status": 409,
  "code": "already_on_a_team",
  "team_id": "0198e6c1-3f42-7a10-9c55-2b1d0f9a7e31"
}
```

**Moving** is the explicit way to change it, and it is the only call that
replaces a membership:

```sh
call -X PUT $API/v1/teams/$SALES/members/$LENA -d '{}'
```

```json
{"team_id": "0198e6c1-4a07-…", "employee_id": "0198e6b0-11c2-…",
 "section_id": null, "from_team_id": "0198e6c1-3f42-…"}
```

The body is optional; sending none is the same as `{"section_id": null}`. There
is no "keep the old section" — a section belongs to one team, and the old one is
not on this one.

Take someone off a team:

```sh
call -X DELETE $API/v1/teams/$SALES/members/$LENA     # 204
```

The team id is in the path *and* in the `WHERE`, so deleting a membership the
employee does not have is a `404` — never a cheerful no-op that strips the
membership they do have. An employee on no team falls back to the tenant's
limits (see the top), so this **loosens** them.

Read the roster:

```sh
call $API/v1/teams/$PURCHASING/members
```

```json
{"members": [
  {"employee_id": "0198e6b0-11c2-…", "employee_slug": "lena",
   "section_id": "0198e6c1-…", "title": "Head of Growth",
   "reports_to": "0198e6b0-0001-…", "since": "2026-08-24T09:31:02.774Z"}
]}
```

## 7. The org chart: function, head, mission

`POST /v1/org` at the top of this document draws this whole table in one call,
and that is how you should build it. What follows is the same table one field at
a time — which is what you reach for to correct one cell, and what the one call
is doing underneath.

The table an operator actually draws has three columns, and each is one thing
here:

| Fonction | Responsable | Mission |
|---|---|---|
| Direction | CEO / fondateur | Vision, stratégie, priorités |
| Produit et technologie | CTO/CPO | Produit, code, infrastructure, sécurité |
| Growth | Head of Growth | Acquisition, contenu, SEO, publicité |
| Commercial | Head of Sales | Prospection, démos, contrats |
| Clients | Customer Success | Support, activation, fidélisation |
| Opérations | COO | Automatisation, procédures, partenaires |
| Finance et juridique | CFO externalisé | Comptabilité, trésorerie, conformité |

* **Fonction** is a team — the same team as everywhere else in this document,
  with the same policy scope and the same budget. "Growth" is a team.
* **Responsable** is a **position**: a `title` and a `reports_to` on the
  membership row that employee already has. There is no positions table. One
  employee, one team, one seat.
* **Mission** is one string on the team.

### The mission

```sh
call -X PUT $API/v1/teams/$GROWTH/mission \
  -d '{"mission": "Acquisition, contenu, SEO, publicité"}'
```

```json
{"team_id": "0198e6c1-…", "mission": "Acquisition, contenu, SEO, publicité"}
```

Idempotent, and it works on a team created a year ago — you do not get to
restart the company to give it an org chart. It appears on every team read:

```json
{"teams": [{"id": "…", "slug": "growth", "name": "Growth",
            "policy_role": "growth",
            "mission": "Acquisition, contenu, SEO, publicité",
            "created_at": "…"}]}
```

At most 240 characters, not blank, and **no control characters** — a mission is
prose an employee gets told, and a newline is a free line in a system prompt.
It is parsed on the way in and re-parsed on every read, so a row edited by hand
into something that would not have been accepted is refused rather than served.

> **A mission is not a limit.** It grants nothing and restricts nothing. Every
> restriction is still a `policy_layers` row under the team's `role_name`.

### The head

The same `PUT` that moves an employee is the one that seats it:

```sh
# The CEO: a seat with nobody above it.
call -X PUT $API/v1/teams/$DIRECTION/members/$FOUNDER \
  -d '{"title": "CEO / fondateur"}'

# A head, answering to it.
call -X PUT $API/v1/teams/$GROWTH/members/$LENA \
  -d "{\"title\": \"Head of Growth\", \"reports_to\": \"$FOUNDER\"}"
```

```json
{"team_id": "0198e6c1-…", "employee_id": "0198e6b0-11c2-…",
 "section_id": null, "title": "Head of Growth",
 "reports_to": "0198e6b0-0001-…", "from_team_id": null}
```

`PUT` replaces the **whole seat** — team, section, title and manager together.
A field you leave out is *cleared*, not kept: an employee that keeps last
quarter's reporting line after being moved into a new job is the stale half of
an org chart nobody edited on purpose.

Four refusals, and none of them is a 500:

| | |
|---|---|
| `reports_to` names somebody with no seat, or another tenant's employee | `400` |
| `reports_to` closes a loop — including reporting to yourself | `409 reporting_cycle` |
| `DELETE` on a head that still has reports | `409 has_reports`, listing them |
| `POST …/members` for an employee already on a team | `409 already_on_a_team` |

The third is the one worth dwelling on: an org chart that quietly orphans half a
department is worse than one that refuses to change until you say what happens
to the people. Re-point or remove the reports first, then remove the head.

### What "senior" means here, and what it does not

> **Seniority decides who may direct whom. It never decides what a principal may
> do.**

A head's limits are its **team's** limits, intersected exactly like everybody
else's. `reports_to` is not a policy layer, `store::policy::load` does not join
it, and there is no field on this API that widens anything. Making the CTO
report to the Head of Sales does not move one tool, one euro or one domain into
the Head of Sales' allowlist — asserted directly in
`crates/app/src/vertical.rs`, against a real stored policy.

What a reporting line does buy is one thing: a head may set the **charter** —
the standing objective — of the employees that report to it *directly*. That
goes through the Policy Gate like any other action an employee takes, produces
an audit row with `action_kind = 'charter_set'` naming both parties, and is
refused for a peer (`outside_chain_of_command`) or for oneself
(`self_direction`), however senior. It is not an HTTP endpoint: it is one
employee acting on another, `app::vertical::delegate`.

Direct reports only, deliberately. A CEO directs its heads, not the whole
company: an authority that reached transitively would be a principal that can
re-task every employee in the tenant.

---

## The audit trail

Every mutation above writes a row into `audit_log`, in the same transaction as
the change, attributed to the **label of the API key** that made it. That is
what makes "who gave the sales agent the purchasing budget" answerable:

```sql
SELECT occurred_at, actor, payload ->> 'event' AS event, payload
  FROM audit_log
 WHERE action_kind = 'policy_changed'
   AND payload ? 'event'
 ORDER BY occurred_at DESC;
```

| `payload.event` | written by |
|---|---|
| `org.applied` | `POST /v1/org` — one row per call, carrying the whole chart and the slugs it hired |
| `team.created` | `POST /v1/teams` |
| `section.created` | `POST /v1/teams/{id}/sections` |
| `team.member_added` | `POST /v1/teams/{id}/members` |
| `team.member_moved` | `PUT /v1/teams/{id}/members/{employee_id}` — carries `from_team_id`, `title`, `reports_to` |
| `team.mission_set` | `PUT /v1/teams/{id}/mission` — carries `from_mission` |
| `team.member_removed` | `DELETE /v1/teams/{id}/members/{employee_id}` |
| `team.policy_role_set` | `PUT /v1/teams/{id}/policy-role` — carries `from_policy_role` |
| `team.budget_set` | `PUT /v1/teams/{id}/budget` — carries `from_daily_total_minor` |

`decision_id` is null on all of them, and that is honest: no Policy Gate ruling
authorised these. They are an operator's key acting directly.

## Known gaps

**Delegation has no HTTP door.** A head setting a subordinate's charter goes
through the Policy Gate (`app::vertical::delegate`) and is tested end to end,
but nothing in the running binary calls it yet: the org chart it reads is
operator configuration, and the act itself is one employee directing another,
which is not an operator endpoint. Wiring it is a call site in the turn loop,
not a change to any rule here.

**A mission is stored, served and never spoken.** `Charter::system_prompt`
takes the employee's identity string and the caller composes it, so putting the
team's mission in front of a new employee is a `format!` at that call site
rather than a change here. Until somebody makes that call, the mission is a
durable statement an operator can read back and an employee has not been told.

## Endpoint summary

| Method | Path | |
|---|---|---|
| `POST` | `/v1/org` | the whole chart, one transaction, idempotent → `202` if it hired, else `200` |
| `POST` | `/v1/teams` | create a team and its policy scope → `201` |
| `GET` | `/v1/teams` | this tenant's teams |
| `POST` | `/v1/teams/{team_id}/sections` | create a section → `201` |
| `GET` | `/v1/teams/{team_id}/sections` | the team's sections |
| `POST` | `/v1/teams/{team_id}/members` | add — `409` if already on a team → `201` |
| `GET` | `/v1/teams/{team_id}/members` | the roster |
| `PUT` | `/v1/teams/{team_id}/members/{employee_id}` | seat: team, section, title, reporting line |
| `DELETE` | `/v1/teams/{team_id}/members/{employee_id}` | remove → `204`, `409` if it has reports |
| `PUT` | `/v1/teams/{team_id}/mission` | say what this function is for |
| `PUT` | `/v1/teams/{team_id}/policy-role` | repoint at a `role_name` |
| `PUT` | `/v1/teams/{team_id}/budget` | set the daily total for one currency |
| `GET` | `/v1/teams/{team_id}/budget?currency=USD` | budget, today's spend, headroom |
