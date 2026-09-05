# The company, running

*Last walked: 2026-09-05 (eighth pass. Invoicing became reachable from a turn;
the seventh pass, after waves F through N, is when all five internal tools came
in and the sweep that followed them found the most serious defect of the
programme — see "What the sweep found", below.)*

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
| Declared tariff → P&L per seat | built | `POST /v1/model` carries `usd_per_mtok_*`; `GET /v1/pnl?days=N`, `pnl.rs` |
| Accounting export | built | `GET /v1/accounting/export?days=N&journal=invoices\|spend\|usage`, one CSV line per movement, foots to `/v1/pnl`; `accounting.rs` |
| Duration → forecast, and the point mort | built | `/v1/forecast?days=N&infra_usd_per_month=M`, `forecast.rs` — tokens at the declared tariff (else the rate card, `cost_source` says which) + our contract prorated, ÷ the mean collected invoice = `break_even.invoices_to_break_even`; `null` with its reason, never a conversion |
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
| What the gate refused | built | `/v1/refusals`, `refusals.rs` — one audit read, no table |

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

## Closed: attachments were write-only, and now they are rows

**The gap, as it stood on 2026-08-28.** A customer's email attachment went into a
`HashMap` in process memory that nothing could read back, and that emptied on
every restart. Three facts, each of which was one grep:

* `apps/server/src/main.rs` built `InMemoryBlobs` for the running server.
* `impl BlobStore for` appeared **once** in the whole workspace. There was no
  durable adapter to switch to.
* The trait had exactly one method, `put`. **There was no `get`.**
  `InMemoryBlobs` had a `bytes()` accessor, but it was on the concrete type and
  production held an `Arc<dyn BlobStore>` — so through the trait the store was
  write-only. The doc on `put` said whoever reads them later can add `get`;
  nobody did.

So the restart was the second-worst part. The worst was that nothing could read
an attachment back even without one.

**What was done.** `BlobStore` and `InMemoryBlobs` are deleted, not extended.
`ingest_email` deposits attachments into `files` (0067) through
`agentos_app::files::Files` — durable, tenant-isolated by RLS rather than by a
formatted key, and carrying `digest = sha256(content)` as a CHECK. The port
already had a `get` that **verifies** that digest rather than asserting it, and
an operator surface: `GET /v1/files/content?name=…` returns the bytes. No new
trait method and no new route were needed; the write path was simply pointed at
the store that already had a reader.

Adding `get` to `BlobStore` instead would have been a second, weaker spelling of
a port that already existed — one with no tenant argument, so no adapter could
have had row-level security.

**Nothing was migrated, because there was nothing to migrate.** Every attachment
held in memory at the moment of deploy was already unreachable: no reader
existed, and the map dies with the process. They are lost, and they were lost
before the deploy. Mail that arrives after it lands in a table.

**What is still not covered**, named rather than implied:

* An attachment the `files` CHECKs refuse — over 1 MiB, or a provider id long
  enough to bust the 200-character name — is **warned and skipped**, and the
  message still lands. That is deliberate: a lost invoice is bad, losing the
  email that carried it is worse. The `tracing::warn!` carrying `blob = <name>`
  is the only record, because attachments have no state column.
* A database failure during the deposit that heals within milliseconds loses
  that one attachment permanently. One that does not heal costs nothing, because
  the landing transaction fails too and the whole job retries.
* **Four CHECKs are reachable by a stranger, not one.** `files_content_size` is
  `between 1 and 1048576`, so a **zero-byte attachment is refused and lost** —
  and an empty part is a thing mail clients really send. `files_name_shape` and
  `files_content_type_shape` each cap at 200 characters and reject control
  characters, while the provider-supplied id and content type they are built
  from are unbounded `String`s. Each of the four ends the same way: a
  `tracing::warn!` and no state column. That is also why pre-validating in Rust
  was refused — it would be four SQL constraints copied into another language,
  with guaranteed drift.
* An **employee** still cannot read an attachment. There is no `ActionKind` for
  it, deliberately — see `crates/app/src/files.rs`. Only an operator key can.

**The rewiring had a trap, and it was handled in the same change.** Named
by the agent that built `files` and repeated here because it is the kind of fix
that quietly makes things worse: an attachment larger than the column's ceiling
fails the CHECK, arrives as `StoreError::Database`, and
`InboundError::is_retryable` calls that **retryable** — a message that can never
land and a job that retries for ever. Today's path warns and continues, on
purpose, because *losing an invoice is bad and losing the email that carried it
is worse*. Preserving that meant **classifying** the store failure rather than
propagating it, and the mutation that proves it restores the propagation and
watches a message vanish on `violates check constraint "files_content_size"`.

**And one premise changed underneath 0067 when this landed.** That migration
argued its refusal of `DELETE` — and of `UPDATE` — about a cabinet an operator
fills by hand, where erasure is lawful, rare, identified, and decided by a
person at a psql prompt. `files` now takes bytes from unauthenticated third
parties, so the set is sized and named by whoever writes to us. The refusal is
still right, and for the same reason — an UPDATE on `content` would swap a
contract while leaving a row that looks untouched — but the erasure question is
no longer hypothetical, and neither is the missing `LIMIT` on `GET /v1/files`.

## The five internal tools, and where each one stands

The founder named five things a company cannot run without, and asked for them
built rather than integrated: *if the customer wants Slack and Salesforce they
plug them in, and if they want the AI to run the company on its own tools, that
has to exist too.* Each is a **port first and a table second** — an internal
tool that cannot become an integration is not worth building, because the day a
customer brings their own, the adapter has to have somewhere to plug in.

| # | Tool | State on the date above |
|---|---|---|
| 1 | **A shared work queue** | **Built, and the loop closes.** `work_items` (0061, `posted_by` in 0064), `Backlog` port, `/v1/work`. An employee posts, another claims, works, closes — `propose`/`perform` carry it, and the brief carries the pool and the seat's own items with the id on each line. **And a stranger's message is a ticket:** `inbound::land` opens one item per thread on the addressed employee's board in the transaction that lands an email or a text — one open item per conversation by a partial unique index (0080), the title carrying channel, masked contact and date and never the sender's words — so no inbound message is off the board until the employee closes it. |
| 2 | **A calendar** | **Built.** `appointments` (0063), `Calendar` port, `/v1/calendar`. An hour is promised, claimed when it comes round, and consumed. |
| 3 | **A thread with a human** | **Built, and it needed no table.** Half the mechanism was already here: a zero-turn seat is delivered to without being woken, which is the founder's own seat, so escalations already landed on a real desk. What was missing was a window and a pen — nothing read `messages.body`, and `GET /v1/employees/{id}/reports` gave a *count* of questions owed rather than a sentence. `GET`/`POST /v1/employees/{id}/desk` reads it and writes back; 0065 is one partial index. |
| 4 | **Invoicing** | **Built.** `invoices` (0066), a seventeenth `ActionKind::InvoiceIssue`, `/v1/invoices`. No invoice can exist against a deal nobody won, and 0011 already refused `closed_won` without an approval — so the ceiling needed no invented number. **0071 makes the document issuable:** a gap-free number per company (a counter row, never a sequence — a sequence is exempt from rollback and therefore full of holes), line items that must total the head, a due date with no default term, and a credit note, because "corrected by a credit note" was 0066's argument for immutability and the remedy did not exist. **No tax rate, no PDF, nothing sent** — a rate is the founder's jurisdiction and the lines can carry one; the other two are still not built. **Reachable from a turn:** `issue_invoice`, the twelfth row of `turn.rs::catalogue()`, proposed by the finance pack and no other, `Risk::High` so a turn that has read anything from outside is never shown it. The store's `closed_won` refusal comes back to the model as one sentence (`failed (no_won_deal): …`) rather than as the end of the run. |
| 5 | **A file store** | **Built.** `files` (0067), `bytea` under the same RLS policy as the name beside it, `digest = sha256(content)` as a CHECK. No DELETE and no UPDATE grant — an UPDATE on `content` would swap a contract while leaving a row that looks untouched. **Not reachable from a turn, by design** — `files.rs`'s module docs carry the argument: a turn produces text and not bytes, the reader that most wants a contract is the one that must not then pay it, and `knowledge` already puts the *text* in front of a turn. |

**The catalogue rows for tools 1 and 2 have landed and been measured.**
`turn.rs::catalogue()` went from eight rows to eleven, both toolchoice pins
moved, and so did a third nobody had planned for — `cost::digest` hashes the
tool schemas too. Tool 3 needed no row at all: the verb an employee uses to
answer the founder is `InternalSend`, already in the vocabulary. **Tool 4's row
is applied now** — `issue_invoice`, the twelfth — and it moved exactly one pin:
the toolchoice fixture wears the buyer's pack, which does not propose
`InvoiceIssue`, so `TRUSTED_PROMPT` and `UNTRUSTED_PROMPT` stood still, while
`cost::DIGEST` moved because Orizn's finance seat now carries a twelfth schema
on every call. That digest is red until the re-measure is bought (`cargo run -p
agentos-eval -- --live`, then `--dry-run 3`), which no agent may run. Tool 5 has
no turn surface by design.

**What the measurement said, and it is the reason to be slow about a twelfth
row.** Tool choice did not move: 4/5 before and after, the same failing case,
zero safety violations. The bill did: $70–$84 a month became $87–$105, because
input tokens per call went from ~4.6k to ~6.0k. **A catalogue row is billed on
every model call whether or not anybody ever uses it.**

**Two holes were named and are now closed.** `0061` promised in writing that a
terminated employee's items *go back on the board unassigned*, and the
referential action never fired: termination is a column (`lifecycle =
'terminated'`), never a `DELETE`. The item stayed assigned to somebody who
would never be briefed again while `GET /v1/work` still showed it assigned, and
work stopped silently. Termination now unassigns in the transaction that writes
the lifecycle, and a suspension deliberately does not — suspension is documented
as pausing an employee *without* releasing what it owns, which is the only thing
separating the two verbs.

`employees` is referenced `on delete set null` from **ten** columns and all ten
of those actions are equally dead. Only this one was a defect: `assignee_id IS
NULL` is the single place in the schema where "nobody holds this" is a state
something reads. Everywhere else the column is provenance, and nulling it would
destroy a record without giving the work to anyone.

The calendar's mirror is settled rather than reassigned. A departed seat's
promise never rang and sat `rang_at IS NULL` forever, which `diary` shows the
founder as *still ahead*; 0063 already says an appointment has no unassigned
state and nothing else can keep it, and the founder never said a manager
inherits an hour. So it is cancelled in the only vocabulary 0063 gave —
`rang_at` written *before* `at` — and only for hours still ahead, because
stamping `now` on an hour already past would manufacture a record saying
somebody kept it.

## The gap the preflight names and this map did not: memory does not work
until somebody sets `EMBEDDER_API_KEY`

`agentos-server doctor` now reports the embedder the way it reports every other
adapter: `[MISSING]` with nothing set, `[OK] MOCK — …` once
`AGENTOS_ALLOW_MOCKS=1` accepts it, `[OK] REAL` with a key. On a box that has
accepted the mock, what it says beside it is the part that matters:

> `MOCK — a SHA-256 hash (mock-sha256-1536), not semantics. Retrieval therefore
> runs on word matching alone: an employee finds a document that repeats the
> words of the question and finds nothing otherwise, which on an inbound email is
> most of the time. Set EMBEDDER_API_KEY for the real thing — and note that
> documents already ingested keep the model they were embedded under, so they
> have to be ingested again to be findable.`

That line used to end "this build ships no real embedder, so no credential
changes it", and that is what changed:
`agentos_providers::embedder::Embedder` has a second variant, `OpenAi`, built by
`EMBEDDER_API_KEY` against the customer's own key. `Mock` is still the default
and still what every test and every laptop runs on.

So on a deployment that has not set it, `knowledge` — what an employee recalls
before it answers — ingests, chunks, stores and retrieves, and cannot rank by
meaning. Everything around it is real: the tenant isolation, the chunking, the
`source_id`, the storage. The one thing that makes retrieval *retrieval* is not.

**What changed since this section was written.** It used to say the ranking *is*
a hash, and it was: `retrieve` fused a hash-ranked vector leg with the full-text
leg, and because the vector leg always returns a full `LIMIT` worth of rows, a
turn asking a question its store could not answer got five confident, scored,
unrelated passages and was told they had been "selected by matching". It no
longer does — `Embedder::is_semantic()` is `false`, and `retrieve` runs the
full-text leg alone. The symptom an operator sees is now an *empty* recall rather
than a wrong one. The gap itself is unchanged and this section stays: there is
still no semantic retrieval on this build.

**Why it belongs on this map rather than in a backlog.** It is the only piece of
the running company that is wired, green, exercised by tests, and short of what
its name promises — every other gap here is either absent (nothing to mistake for
working) or off behind a switch. A reader who sees `knowledge` in the node table
and the doctor's `[OK]` will conclude an employee has memory. It has word search
over documents somebody uploaded, and on the turn path — where the query is the
counterparty's whole email and `plainto_tsquery` ANDs every lexeme in it — that
search almost never matches anything.

That parser is `plainto_tsquery` and not `websearch_to_tsquery` for a security
reason rather than an ergonomic one: the recall query is a message a stranger
wrote, and while the embedder is not semantic the full-text leg is the *only*
thing choosing what an employee recalls. `websearch_to_tsquery` would let that
stranger write `or` and `-` into the query — steer an ordinary-looking email
onto a named document, or delete the passage that constrains them out of the
answer. See `crates/store/src/knowledge.rs`.

**It is a credential now, and the decision it was waiting on has one answer and
one open question.** Answered: whose key — the customer's, like every other model
spend, and `EMBEDDER_API_KEY` is one value because the model name is a constant
of the adapter rather than a setting (the HNSW index is partial on it, and a
partial index predicate is a SQL literal that cannot name an environment
variable). Still open: this is the first place where "the customer brings their
own model" and "we run on the CLI" give different answers, because the CLI
subscription exposes no embeddings endpoint at all. A customer on the CLI path
who wants memory has to hold a second, separate key — and nothing in the product
tells them that yet.

**Two things about the real adapter are worth knowing before setting the
variable.** The dimension is fixed at 1536 because the column is `vector(1536)`;
`text-embedding-3-small` is natively that wide, the request asks for it
explicitly, and a vector of any other width is refused at the adapter rather than
projected to fit or discovered by Postgres mid-ingest. And a turn's recall runs
under a two-second budget (`RECALL_TIMEOUT`) that was sized when embedding was a
local hash — with a network round trip inside it, a slow provider minute becomes
"could not reach the document store", which the employee says out loud but which
is a different failure rate from the one that constant was chosen against.

## What the sweep found, and it is worth reading before trusting the gate

**The taint wire was forgotten in exactly the branch its own comment swore it
could not be.** `evaluate` refuses a high-risk action derived from untrusted
text — a web page, an inbound email, an MCP result — and the comment said the
check is applied after the rules "so it cannot be forgotten in one branch". The
expression ended in `&& decision.is_allow()`, so an action answering
`RequireApproval` was not tainted at all. That is the answer for payments,
contract signatures, credential changes, bulk erasure and charters.

The path was live, traced link by link: an inbound email taints the turn, the
model guesses the name `pay`, `propose` hands it over because it is a bare
`match name` that never consults `visible`, the gate answers `RequireApproval`
instead of denying, and a row lands in the founder's queue carrying an amount
and a payee a stranger chose, presented as the employee's own proposal.

Three things made it worse than a latent bug. The repository already knew —
`action.rs` said `ContractSign` *slips past the taint wire*, written as
behaviour. In the shipped Orizn configuration it never fired for a payment at
all, because `approval_above` is $1 and one cent for finance, so **every**
injection took the escalating branch. And it was tested: the property test
asserted `!decision.is_allow()`, which `RequireApproval` satisfies.

Both layers are closed now — the gate denies, and `propose` refuses a name that
was not offered to this turn — and the seal's real protection turned out to be
sixteen `Subject<Of = X>` bounds that nothing tested. Relaxing one left five
harnesses green while an untrusted token could act.

**And the approval ceremony could not see who was being paid.** It promised that
restating an approved payment with a different payee is refused; the hash is over
the `Action`, and `Action::PaymentCreate` carried `amount` and nothing else. Two
payments to different counterparties for the same amount hashed identically, and
the queue showed `pay EUR 500.00` because no payee had ever been filed. Fixed,
and `Effects::pay` now builds the instruction from the token so the gate and the
provider cannot be handed different names.

**The lesson generalises, and it is the one to carry forward.** Five defects on
five unrelated surfaces survived a green test because the assertion admitted more
than its author believed: `!is_allow()` admits an escalation; a race harness held
a transaction production never holds; `contains("no such tool")` admits "that
tool exists but not for you"; two ceremony tests mutated fields that were in the
action and none mutated the one that was not. **Ask what an assertion admits, not
whether it is green.**

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
