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

> ### Before you configure anything: the loader is not on the hot path
>
> `store::policy::load` behaves exactly as described, and it is tested. But
> **the Policy Gate does not call it.** `apps/server/src/main.rs` builds
> `PolicyGate::new(db, PolicyBook::default())` — an in-memory book holding the
> empty platform layer, with the *employee* layer folded into the role slot.
>
> So on today's build, everything you write into `policy_layers` is read by
> exactly two things: `GET /v1/employees/{id}/turns`, and the initiative loop's
> turn-budget reservation. **The turn budget is genuinely enforced. No other cap
> in this document is**, because the gate that would enforce it is loaded with a
> book that grants nothing — which means it denies every agent-initiated side
> effect regardless of what you configure.
>
> That is the correct failure direction and it is still not enforcement.
> Configure the layers anyway: they are the thing that becomes live the moment
> `main.rs` loads them, and that is a one-function change. See the **Known gap**
> at the end of this file for the second half of the same problem.

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
| Create a team and its policy *scope* | Set a cap, an allowlist or a threshold |
| Repoint a team at a different `role_name` | Widen anything, at any layer, ever |
| Set a team's daily budget, per currency | Give a **section** a policy or a budget |
| Move an employee between teams | Put one employee on two teams |
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
purpose: two places to write a limit is one place to forget to tighten.

Today that means SQL (or whatever console owns your policy versions):

```sql
-- Purchasing may spend, and only through the tools it needs.
INSERT INTO policy_layers
  (id, version_id, tenant_id, layer, role_name,
   spend_currency, max_per_transaction_minor, max_per_day_minor, approval_above_minor,
   allowed_channels, allowed_mcp_tools)
VALUES
  (gen_random_uuid(), :active_version, :tenant, 'role', 'purchasing',
   'USD', 200000, 500000, 100000,
   '{email,whatsapp}', '{sourcing.rfq_send,sourcing.quote_read}');

-- Sales may not spend at all: no spend columns means this layer permits no
-- spending, whatever the tenant allows.
INSERT INTO policy_layers
  (id, version_id, tenant_id, layer, role_name, allowed_channels, allowed_mcp_tools)
VALUES
  (gen_random_uuid(), :active_version, :tenant, 'role', 'sales',
   '{email}', '{revenue.contact_create,revenue.opportunity_update}');
```

Both numbers are still ceilings, not grants: if the tenant's
`max_per_day_minor` is `300000`, purchasing gets `300000`.

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
checked — by `store::org::reserve`, which is written and tested and which
nothing on the payment path currently calls. Read the **Known gap** at the end
before you rely on the number you are about to set.

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
   "section_id": "0198e6c1-…", "since": "2026-08-24T09:31:02.774Z"}
]}
```

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
| `team.created` | `POST /v1/teams` |
| `section.created` | `POST /v1/teams/{id}/sections` |
| `team.member_added` | `POST /v1/teams/{id}/members` |
| `team.member_moved` | `PUT /v1/teams/{id}/members/{employee_id}` — carries `from_team_id` |
| `team.member_removed` | `DELETE /v1/teams/{id}/members/{employee_id}` |
| `team.policy_role_set` | `PUT /v1/teams/{id}/policy-role` — carries `from_policy_role` |
| `team.budget_set` | `PUT /v1/teams/{id}/budget` — carries `from_daily_total_minor` |

`decision_id` is null on all of them, and that is honest: no Policy Gate ruling
authorised these. They are an operator's key acting directly.

## Known gaps

Two, and they are the same gap seen from two sides: the org layer is fully
built, fully tested, and has no reader in the running binary.

**The team budget is not checked.** It is stored, read and reported correctly,
and `store::org::reserve` enforces it under a row lock — but the Policy Gate's
payment path (`crates/app/src/gate.rs`) calls `spend::reserve`, which takes the
*employee's* headroom only. `org::reserve` has **no non-test call site**. Until
that call moves, a team's daily budget is configuration nothing on the hot path
checks. Per-employee caps are enforced; the team ceiling is not.

**The team's limits are not read at all.** The gate uses an in-memory
`PolicyBook` and never calls `store::policy::load`, so `policy_layers` — the
`role` layer this whole document points teams at — reaches the gate through no
path. `main.rs` constructs the book as `PolicyBook::default()`, the empty
platform layer, which denies everything. The only live readers of the loader are
`GET /v1/employees/{id}/turns` and the initiative loop's turn budget, which is
therefore the one limit in this document that genuinely holds today.

Both are fixed in `main.rs` plus `PolicyBook::effective`, and nothing else has
to change. Until then, read a configured limit here as *the value that will take
effect*, not as one that is taking effect.

## Endpoint summary

| Method | Path | |
|---|---|---|
| `POST` | `/v1/teams` | create a team and its policy scope → `201` |
| `GET` | `/v1/teams` | this tenant's teams |
| `POST` | `/v1/teams/{team_id}/sections` | create a section → `201` |
| `GET` | `/v1/teams/{team_id}/sections` | the team's sections |
| `POST` | `/v1/teams/{team_id}/members` | add — `409` if already on a team → `201` |
| `GET` | `/v1/teams/{team_id}/members` | the roster |
| `PUT` | `/v1/teams/{team_id}/members/{employee_id}` | move onto this team |
| `DELETE` | `/v1/teams/{team_id}/members/{employee_id}` | remove → `204` |
| `PUT` | `/v1/teams/{team_id}/policy-role` | repoint at a `role_name` |
| `PUT` | `/v1/teams/{team_id}/budget` | set the daily total for one currency |
| `GET` | `/v1/teams/{team_id}/budget?currency=USD` | budget, today's spend, headroom |
