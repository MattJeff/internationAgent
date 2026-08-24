# Providers

What each external account is for, which credential to copy where, and which
capabilities are gated on a **human** at the other end — the ones no amount of
code shortens.

---

## Read this first

**Only one provider is wired into the running server today: Anthropic.**

`apps/server/src/main.rs` builds its adapters with
`agentos_app::mocks::ports()` and `agentos_app::mocks::adapters()`,
unconditionally. Real Resend, Twilio and Browserbase clients exist in
`agentos-providers`, are complete, and are tested against hermetic HTTP servers —
but `ResendEmailProvider::new`, `TwilioTelephony::new` and
`BrowserbaseBrowser::new` appear only inside that crate's own test modules.
Nothing else constructs them. Only the model is chosen at runtime, by
`AGENTOS_LLM`.

One thing in `mocks::adapters()` is **not** a mock: the envelope cipher.
`AGENTOS_MASTER_KEY` is threaded into a real `LocalEnvelopeSecretStore`, because
`Step::Identity` mints a real Ed25519 keypair and seals its private half into a
database column. A mock provider that invents a phone number costs nothing; a
mock cipher costs an identity.

So `EMAIL_API_KEY`, `TELEPHONY_API_KEY`, `BROWSER_API_KEY` and
`EMBEDDER_API_KEY` do exactly one thing: they satisfy the boot guard in
`config.rs`, which otherwise refuses to start rather than run a mock silently.
Setting them changes **no behaviour**. Do not set them expecting email to be
sent.

| Provider | Adapter exists | Wired into the server | Credential |
|---|---|---|---|
| **Anthropic** | yes — `llm_anthropic.rs` | **yes** | `ANTHROPIC_API_KEY` + `AGENTOS_LLM=anthropic` |
| local `claude` CLI | yes — `llm_cli.rs` | **yes** | none — `AGENTOS_LLM=cli` |
| **Resend** | yes — `email_resend.rs` | no | `EMAIL_API_KEY` gates the boot guard only |
| **Twilio** | yes — `telephony_twilio.rs` | no | `TELEPHONY_API_KEY` gates the boot guard only |
| **Browserbase** | yes — `browser_browserbase.rs` + `cdp.rs` | no | `BROWSER_API_KEY` gates the boot guard only |
| Meta WhatsApp | no adapter at all | no | — |
| embedder | mock only (a SHA-256 hash) | n/a | `EMBEDDER_API_KEY` gates the boot guard only |
| MCP | none — refuses | n/a | — |
| payments | none — refuses | n/a | — |

Wiring a real adapter in is a change to `crates/app/src/mocks.rs` (which is the
only file that may name a concrete provider type — the binary must not depend on
`agentos-providers`, and that absence is what makes the capability token
unforgeable).

---

## Anthropic — the model the employee reasons with

**What it is for.** The only live external call this binary makes today. Every
inbound message becomes an agent turn: the model reads the message, may ask for
tools, and writes the reply that is recorded on the conversation.

**Status: real, wired, in use.**

### The account and the credential

1. Open an account at [console.anthropic.com](https://console.anthropic.com).
2. **Settings → API keys → Create key.** Copy the `sk-ant-…` value; it is shown
   once.
3. Put it in the deployment's environment:

```bash
export AGENTOS_LLM=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

Both, together. `AGENTOS_LLM=anthropic` **without** the key is a named boot
failure — deliberately, because the alternative is an employee that accepts mail
for a week and answers none of it. `AGENTOS_LLM` with any other spelling
(`claude`, `openai`, a typo) is also a boot failure listing the valid values; it
never falls back to the mock.

### What it does

`POST https://api.anthropic.com/v1/messages`, `anthropic-version: 2023-06-01`,
120s per-request timeout. Model: `claude-opus-5` (`DEFAULT_MODEL`), hard-coded —
there is nowhere yet for an operator to record a different one.

Three behaviours worth knowing operationally:

* `cache_read_input_tokens` is carried through into the budget counter. It is
  what makes prompt caching visible in cost enforcement.
* `stop_reason == "refusal"` arrives as a **200** with a possibly-empty content
  array. It is a refusal, not an error.
* A timeout is **never** classified terminal — a timed-out request may still have
  landed, so the only safe classification is retryable, and the turn comes back
  on the outbox's backoff.

Not sent, on purpose: `temperature` / `top_p` / `top_k` and
`thinking.budget_tokens` (all removed on `claude-opus-5`; sending them 400s), and
any assistant-turn prefill.

### The zero-credential alternative

```bash
export AGENTOS_LLM=cli
```

Shells out to the `claude` binary on your `PATH`, using the login you already
have. Real inference, no API key — the whole point of it. It still counts as a
mock adapter for the boot guard (`AGENTOS_ALLOW_MOCKS=1` required), because it
runs on somebody's laptop login and should not be a production path.

It is lossier in ways that matter:

* **Tool calls are a shim.** The CLI exposes no structured `tool_use` blocks, so
  the adapter renders the schemas into the prompt and demands strict JSON back.
  A model that answers with prose gets you `cli_not_json`, not a tool call.
* **Caching is not ours.** `cache_breakpoint` is ignored; the reported
  `cache_read_tokens` is dominated by the CLI's own system prompt, so cost
  numbers from this backend do not resemble production ones.
* **One turn, no history reuse.** Every call is a fresh `claude -p`.

Two things it does deliberately: the prompt goes in on **stdin**, never argv (a
prompt is attacker-influenced text, and an argument starting with `--` is a
flag); and the CLI's own tools are disabled with an empty `--allowed-tools`, so a
text completion cannot read files or run bash on the host.

### Default if you configure nothing

`AGENTOS_LLM` unset means `mock`: a scripted model that answers every message
with a string that says out loud it is a mock and that no judgement is behind
it. That wording is on purpose — a mock model that writes a plausible customer
reply is a mock that ends up in a demo and then in a thread with a real supplier.

---

## Resend — email identity, sending, and inbound

**What it is for.** The employee's mailbox: the sending domain (provisioning
step `email`), outbound mail, and inbound mail via webhook.

**Status: real adapter written and tested; not constructed by the server.** The
`email` step provisions against `MockEmailProvider` today.

### The account and the credentials — *two* of them

1. Open an account at [resend.com](https://resend.com).
2. **Domains → Add domain.** Enter the same value you set as
   `AGENT_EMAIL_DOMAIN`. Resend gives you DNS records (SPF, DKIM, and a
   `MX`/return-path record). Add them at your DNS host and wait for Resend to
   show the domain as verified. *This is DNS propagation, not human review — it
   is usually minutes, occasionally hours.*
3. **API Keys → Create API Key**, sending permission. Copy the `re_…` value.
   This is the API key: `ResendEmailProvider::new(api_key, …)`.
4. **Webhooks → Add endpoint**, pointing at
   `{PUBLIC_HOST}/v1/webhooks/email`, subscribed to `email.received` (and
   whatever delivery events you want). Copy the **signing secret**, a separate
   `whsec_…` value. This is *not* the API key.

Where each goes:

| Credential | Goes into | Today |
|---|---|---|
| `re_…` API key | `EMAIL_API_KEY` | boot guard only; the adapter is not built |
| `whsec_…` signing secret | `AGENTOS_WEBHOOK_SECRETS` as `email:<tenant-uuid>:whsec_…` | **live** — this one is genuinely used |
| the sending domain | `AGENT_EMAIL_DOMAIN` | live |

The webhook half really works even with the mock adapter: the route verifies the
signature against the configured secret and stores the raw bytes. The path
segment (`email`) is the `{provider}` in `/v1/webhooks/{provider}` and must match
the label in `AGENTOS_WEBHOOK_SECRETS`. An unregistered provider is a **404**,
and an empty registry means no inbound message can arrive at all.

### Four Resend facts encoded in the adapter

**Inbound is two-phase, and the second phase is on a clock.** `email.received`
carries **metadata only** — an id, envelope addresses, attachment *descriptors*.
No subject, no body, no bytes. The inbound loop retrieves the message, then
follows each descriptor's `download_url`, which Resend expires after **one hour**.
Fetch bytes immediately after the body, never lazily at render time. This is why
the inbound loop is a separate poller with a small batch.

**On a received event `from` is the bare address.** The display name is only in
the headers on the retrieve endpoint, so the adapter prefers the `From` header
over the top-level field.

**Suppression is ACCOUNT-scoped.** One list per account — not per tenant, not per
sending domain. Suppressing `ap@supplier.example` for one tenant would silently
stop every other tenant's employees mailing them. Per-tenant suppression has to
be **our own table**, checked before `send`. The provider does not give it to us
and no caller should assume it does. That table does not exist yet.

**The sending domain cannot be released.** `ensure_identity` reconciles on the
domain *name* (Resend domains have no free-form metadata field to stamp the
idempotency tag into), so one adapter owns one sending domain and every employee
sits on it. `release` therefore returns
`Terminal { code: "release_not_supported" }` — not `Ok(())`, which would clear the
binding on a domain that is still very much alive, and not a transient failure,
which would make **every** termination end in the dead-letter queue.

Operationally, once this adapter is wired: terminating an employee will leave its
`email` resource row bound, with `release_not_supported` in `last_error`,
permanently and by design. It will appear in the stranded-resources query
(`docs/OPERATIONS.md` §6) and it is the one entry there you should expect to see
and ignore — nothing per employee is being billed for it. On today's
`MockEmailProvider` the release simply succeeds, so you will not see it yet.

### Signature verification

Standard Webhooks / Svix scheme: `webhook-id` (or `svix-id`), `webhook-timestamp`,
`webhook-signature` (`v1,<base64>`, possibly several space-separated). HMAC-SHA256
over `id.timestamp.body`, verified over **exactly the bytes received** — the
handler takes a raw `Request`, never `Json<T>`, because a re-serialisation breaks
every signature scheme in existence. Replay window: **300 seconds**.

The secret is base64-decoded after stripping `whsec_`; a plain non-base64 string
falls back to its literal bytes, so pasting the wrong shape gives you a working
(if non-standard) secret rather than a silent verification failure.

---

## Twilio — phone numbers, SMS, WhatsApp transport

**What it is for.** Provisioning step `phone`: buying an E.164 number and binding
its webhook. Also SMS and WhatsApp sends.

**Status: real adapter written and tested; not constructed by the server.**

### The account and the credential

1. Open an account at [twilio.com](https://www.twilio.com).
2. **Console dashboard** → copy the **Account SID** (`AC…`) and the **Auth
   Token**. That is the whole credential: the API is HTTP basic auth
   (`AccountSid:AuthToken`) with form-encoded bodies and JSON responses. There is
   no maintained Rust Twilio SDK and there does not need to be.
3. Today, put the auth token in `TELEPHONY_API_KEY` to satisfy the boot guard.
   When the adapter is wired, `TwilioTelephony::new(account_sid, auth_token)` is
   the constructor and the SID needs a home of its own.

Twilio's inbound webhook signature is a **different scheme** — HMAC-SHA1 over the
callback URL plus sorted form parameters. It is implemented
(`telephony::verify_twilio_signature`) but **not reachable from
`/v1/webhooks/{provider}`**, which does the Svix scheme only. There is no
telephony ingest at the other end of the queue to read the row, so wiring it
would be a route that fills a table nobody drains. When it lands, `Endpoint`
grows a `scheme` field and the `verify` call grows a `match`.

### The human gate: the regulatory bundle

**This is the capability no code can shortcut.**

In regulated countries — DE, ES, AU and many others — buying a local number
requires an approved **regulatory Bundle**: proof of address, business
registration, sometimes a local representative. A human at Twilio reads it.

Two things about this are commonly got wrong, and both are encoded here:

**There is no number in a pending state.** Until the bundle is approved the
`POST /IncomingPhoneNumbers` simply *fails*. Twilio does not hand back a
half-created number. So the adapter returns
`ProviderError::PendingExternal { poll_ref: <bundle sid>, expected_by }` and
**no `Provisioned` at all** — a `Provisioned` with an empty id would be a number
that does not exist. Twilio signals this with error codes 21631 / 21649 / 21650,
and because those drift as the catalogue is reshuffled, the adapter also sniffs
the message text.

**Do not wait for a bundle callback.** The lifecycle is
`draft → pending-review → in-review → twilio-approved | twilio-rejected`, and the
status callback fires on every transition **except** `pending-review → in-review`.
A state machine that blocks on an `in-review` callback hangs forever. There is no
such machine here: the caller re-runs `ensure_number`, which retries the purchase
and either succeeds or reports the same `PendingExternal` again. **Polling is the
protocol.**

### What the system does while a human reviews

1. The `phone` resource row goes to `pending_external`, carrying the bundle sid
   in `poll_ref` and a deadline in `expected_by`. The expected review is
   **3 days** (`TwilioTelephony::BUNDLE_REVIEW`).
2. `GET /v1/employees/{id}` renders that state honestly:
   `{"state":"pending_external","poll_ref":"BU…","expected_by":"…"}`. **It never
   renders a green check.** That is the whole reason the state exists.
3. `phone` is **not a blocking step** (`Step::is_blocking` — only `identity`,
   `email`, `vault` and `permissions` are), so the employee still reaches
   `active` and can work over email while the bundle is in review. Its `health`
   is degraded, not `online`.
4. The provisioning loop keeps re-running the step on its own schedule. Each pass
   either buys the number or re-reports the same wait.
5. If `expected_by` passes, the **reaper** files an approval — actor
   `provisioning-reaper`, role `operator` — whose reason names the bundle sid and
   says what to do:

   > *…has been waiting on BU:FR:1234 since before …, which is past due. Nothing
   > on our side will move it: check the provider (a rejected bundle or sender
   > review looks exactly like one still in progress from here), then either
   > resolve it there or disable the channel.*

   and moves the step to `failed`, so it stops reporting as a wait that is still
   going somewhere. You clear it from the approvals queue with a key labelled
   `operator`.

A `twilio-rejected` bundle never becomes approved on its own. From our side it is
indistinguishable from one still in review — which is exactly why the deadline
and the escalation exist.

### Release

`DELETE /IncomingPhoneNumbers/{sid}` is what actually stops the monthly charge;
nothing else does. A **404 is treated as success** — somebody already released
it, and reporting a failure would strand the binding. This is the release
contract for every adapter: releasing twice, or releasing something the provider
no longer has, is `Ok(())`.

### Send-side ceilings worth knowing

**The 24-hour WhatsApp customer-service window is a type, not a check.** Outside
24 hours from the customer's last inbound message, only an approved template may
be sent. `OutboundWhatsapp::FreeForm` carries an `OpenWindow`, and an
`OpenWindow` can only be obtained while the window is genuinely open. A free-text
send outside the window is not a runtime error — it is unspellable.

**SMS de-duplication is process-local.** The Messages API has no idempotency
header at all, so the adapter keeps an in-process map from idempotency key to
message SID. It stops a retry *inside one process* from double-texting; it does
not survive a restart. Combined with the outbox's at-least-once delivery, a pod
killed between Twilio accepting a message and our `COMMIT` will send it twice.

---

## Meta WhatsApp — the second human gate

**What it is for.** The `whatsapp` provisioning step: a verified business sender
that employees are routed to.

**Status: there is no provider call at all.** Not a mock — nothing. The step
resolves to a *local* routing binding built from `EngineConfig::whatsapp_sender`
(`"<sender>/<employee-uuid>"`, so two employees on one sender cannot collide on
the `(provider, external_id)` unique index).

`EngineConfig::default()` sets `whatsapp_sender: None`, and `main.rs` uses the
default — so **on every deployment today the step fails with
`Terminal { code: "no_whatsapp_sender" }`**. It is non-blocking, so the employee
still reaches `active` — but because `health` is derived from all eleven rows, a
failed optional step means `health` settles at **`degraded`** and never reaches
`online`. Expect to see `whatsapp` at `failed` and `health` at `degraded` on an
otherwise healthy employee; that is this, and nothing is wrong.

### The human gate, when you do get there

Registering a WhatsApp Business sender requires Meta to approve a **display
name** — a human reads it and can reject it for being misleading, for containing
a URL, for not matching the business. Business verification (documents, a
registered entity) sits behind the same queue. Days, not minutes, and no API
shortens it.

The model the code is built around is deliberate: **one verified company sender,
employees routed to it.** Not one sender per employee. Per-employee senders would
mean per-employee display-name approvals, i.e. a human in the loop of every hire.

### What the system does in the meantime

**Today: nothing.** There is no call, so there is no wait to represent — the step
fails immediately with `no_whatsapp_sender` and stays failed.

**Once a sender is configured and an adapter exists**, it takes the same shape as
the Twilio bundle, because `PendingExternal` is the shared vocabulary: a step in
`pending_external` with a `poll_ref` and an `expected_by`, rendered honestly by
the API, non-blocking so the employee works over its other channels, and
escalated to an `operator` approval if the deadline passes. A rejected display
name looks exactly like one still in review from our side, which is why the
deadline exists.

---

## Browserbase — the browser the employee logs in with

**What it is for.** The `browser` provisioning step: a persistent, isolated
browser context per employee, so it can stay logged into a supplier portal
between tasks.

**Status: real adapter written and tested; not constructed by the server.**
`BrowserbaseBrowser` (`crates/providers/src/browser_browserbase.rs`) implements
`BrowserProvider` against `https://api.browserbase.com` — `POST /v1/contexts`
then `POST /v1/sessions` — and then drives the session over **CDP** through our
own websocket driver, `CdpWebsocket` (`crates/providers/src/cdp.rs`): `goto`,
`fill`, `screenshot`, `expect_hit`, `evaluate`.

The websocket client is `tokio-tungstenite` and the choice is deliberate: CDP is
JSON-RPC over a websocket and Browserbase launches Chrome for us, so a websocket
client is all that is needed — `chromiumoxide` would bring a whole browser model
we never drive.

The `browser` provisioning step still runs against `MockBrowser`, because
`main.rs` builds `mocks::adapters()`.

### The account

1. [browserbase.com](https://www.browserbase.com) → create a project.
2. **Settings** → copy the **API key** and the **Project ID**. Both are needed;
   `BrowserbaseBrowser::new(project_id, api_key)` takes both, and the API key
   alone is not enough.
3. Today: `BROWSER_API_KEY` for the boot guard. There is nowhere for the project
   id to go until the adapter is wired.

No human review is involved. This one is credentials-and-go.

**The shared `BrowserProvider` contract suite is private to `browser.rs` and is
run against `MockBrowser` only** — `BrowserbaseBrowser` has its own tests against
a hermetic HTTP server but never invokes the suite. Making a vendor swap
*provable* rather than hopeful means making that suite `pub` and running it, the
way `EmailProvider`'s is.

### Why the trait looks the way it does

Worth reading before writing the adapter, because the shape encodes a real
constraint. Chrome keeps cookies, localStorage, IndexedDB and saved logins in the
profile directory named by `--user-data-dir`, and that is a **process** argument:
one running Chrome, one profile. CDP's `Target.createBrowserContext` gives a
clean isolated context inside a running process, but it is incognito-shaped — it
dies with the browser and writes nothing to the profile. So it buys **isolation
without persistence**.

An employee that must stay logged in needs persistence *and* isolation. Self
hosted, that means **one browser process per employee**, each with its own
`--user-data-dir`. A session is therefore a unit of infrastructure with a memory
footprint and a lifetime, not a free object — which is why:

* there is no `new_session()`; the only way to get a context is
  `ensure_context(&EnsureCtx)`, under the same reconcile-before-create contract
  as buying a phone number, because it costs about as much;
* `BrowserSession::user_data_dir` is `Option`, and `None` means the context does
  not survive the process. **A hosted provider like Browserbase is exactly the
  legitimate `None` case** — it persists state its own way. `None` is a bug only
  for a self-hosted session that has to stay signed in;
* `act` takes a `&BrowserSession` rather than creating one, so no call site can
  quietly conjure a browser.

And `BrowserStep::Fill` takes a `&Secret`, not a `String`. A plan is data: it
gets logged, persisted, replayed and — for an LLM-authored plan — round-tripped
through a model. The plaintext leaves the vault only inside the adapter, on the
way into the DOM field, and the model that decided "type the password here" never
sees the password. Keep that when you write the real adapter.

---

## The embedder

`Embedder` has one variant: `Mock`, which derives a unit-length 1536-dimension
vector from a SHA-256 hash of the input. Same string in, byte-identical vector
out, on any machine, forever, with no network and no key.

It is a *hash*, so it makes no attempt at semantics: "cat" and "kitten" are as
unrelated as "cat" and "diesel". Use it to test plumbing — dimensions, batching,
storage round-trips, top-k ordering, cosine arithmetic — and a real embedder to
test whether retrieval finds the right documents.

Every knowledge chunk records its `model_name`, and the mock's is
`mock-sha256-1536`, deliberately **not** `text-embedding-3-small`. A
`vector(1536)` from one embedder and a `vector(1536)` from another are the same
Postgres type and are not the same space; mixing them returns nonsense rather
than an error. Labelling hash vectors as a real model would be exactly that
silent mixing.

`EMBEDDER_API_KEY` gates the boot guard. There is no real embedder adapter to
give it to.

---

## MCP and payments — the ports that refuse

Both are wired to a `NotConfigured` adapter that returns
`Terminal { code: "not_configured" }` and logs it — MCP at `warn`, payments at
`error` with the amount.

This is deliberate and worth preserving. A fake that returns a plausible payment
id is a fake that will one day be believed; `not_configured` is the honest answer
and shows up in the audit trail as one. If you are testing a payment flow and
seeing `not_configured`, the system is working.

---

## The two contracts every adapter must satisfy

If you wire one of the above in, or write a new one, these are not optional.

There is a shared contract suite per trait in `agentos-providers` — but be clear
about what it currently proves. **Every suite runs against the mock; none of
them runs against the real adapter.** `SecretStore`'s is the only one exercised
by two implementations. `EmailProvider`'s is the only one that is `pub` and
therefore even callable from another module; `TelephonyProvider`'s and
`BrowserProvider`'s are private to their own `mod tests`. The real adapters have
their own hand-written tests against hermetic HTTP servers, which is good but is
not the same guarantee. Making a vendor swap provable means running the suite
against both.

### Reconcile before create

In this order, every time:

1. **Look the resource up by tag.** The tag is `EnsureCtx::tag()` — the string
   form of the idempotency key — stamped into whatever field the provider gives
   you for free-form labels: Twilio `friendly_name`, Resend domain name,
   Browserbase context name, a Stripe `metadata` entry. If the provider has a
   native idempotency header, send that too; it is a second belt, not a
   replacement for the lookup.
2. **Return the hit.** One resource carrying the tag: return it without creating
   anything. **Two hits is a bug in a past version of the adapter, not something
   to paper over** — return `Terminal` so a human looks at it.
3. **Only then create**, stamping the tag into the same field the lookup reads. A
   create that cannot carry the tag is not idempotent and must not ship.

The observable guarantee: calling `ensure` twice with the same `EnsureCtx`
yields **one** external resource with the **same** `external_id`.
`IdempotencyKey::for_step` is pure, so a process that crashes between the
provider's `201 Created` and our own commit rebuilds the identical key on restart
and finds the resource it already paid for. `EnsureCtx::retry()` bumps `attempt`
and deliberately leaves the key alone — that is the whole mechanism.

`FaultMode::FailAfterExternalSuccess` exists to make a chaos test reproduce
exactly that crash window: point it at a step, run the step twice, assert one
`external_id`.

### Release, which is the same discipline pointing the other way

`release` must be **idempotent and tolerant of an already-gone resource**.
Releasing twice, or releasing something the provider no longer has, is `Ok(())`:
the caller is asserting a desired state ("this must not exist"), and if the state
is already true there is nothing to report. **A 404 from a delete is success.**

`ensure` reconciles before it creates because a *duplicate* is the expensive
mistake; `release` tolerates the missing resource because a *stranded binding
nobody may clear* is. The write order follows: `ensure` records its intent before
it calls, `release` clears the binding only after the provider confirms. A crash
in either gap is repaired by running the same operation again.

A provider that genuinely **cannot** release something must say so —
`Terminal { code: RELEASE_NOT_SUPPORTED }` — and must not return `Ok(())`.
Pretending success clears the binding on a resource that still exists, which is
precisely how a thing gets billed forever with nothing left pointing at it.

### Error classification is load-bearing

The provisioning engine branches on these, so mapping a transport timeout to
`Terminal` would abandon a healthy provider mid-run.

| Variant | Meaning | Engine's response |
|---|---|---|
| `Retryable { after }` | timeout or 5xx — the provider is fine, we were unlucky | backoff and retry |
| `RateLimited { retry_after }` | 429, using the provider's own advice | backoff and retry |
| `PendingExternal { poll_ref, expected_by }` | **not an error, a wait.** A Twilio bundle, a Meta display name. The resource exists; someone external must bless it. | park the step, escalate at the deadline |
| `Terminal { code }` | a 4xx we caused. Retrying makes it worse. | fail the step |

`Secret::expose_for_transport()` is the only way to the plaintext of a
credential. Put the result straight into the header or body being sent; never
bind it to a named variable that outlives that expression.
