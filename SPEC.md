# Agent Employee OS — Production Specification v1.0

## 0. Product invariant

`Create employee` must create a durable machine identity which can communicate, browse, use tools, receive company knowledge, transact under policy and interoperate with other agents.

The UI is never allowed to report a provider resource as ready until the provider has confirmed it. `pending_external` is a first-class state for telecom, WhatsApp, domain verification, KYC/KYB and similar external processes.

## 1. Product surface

### Required provisioning sequence

1. Identity
2. Email
3. Phone
4. WhatsApp
5. Wallet
6. Browser
7. Vault
8. Company knowledge
9. MCP
10. A2A identity
11. Permissions
12. Employee online

All steps are idempotent `ensure_*` operations. Re-running the workflow must converge on the desired state without creating duplicate phone numbers, wallets, mailboxes or browser contexts.

### Employee status

- `draft`
- `provisioning`
- `degraded`
- `online`
- `suspended`
- `failed`
- `terminated`

`degraded` means all blocking resources are ready but one or more optional/external channels are unavailable.

## 2. Architecture

### Control plane (Rust)

- Axum API
- Tokio runtime
- SQLx + PostgreSQL as source of truth
- pgvector for company knowledge
- NATS JetStream for event fanout
- S3-compatible object storage
- OpenTelemetry + tracing

### Workers

- provisioning-worker
- communication-worker
- knowledge-worker
- browser-worker
- payment-worker
- a2a-worker
- mcp-worker
- audit/outbox-worker

Long-running workflows are state machines persisted in PostgreSQL. Never rely on an in-memory task for provisioning or money.

### Provider boundary

Every external capability is behind a trait:

- `EmailProvider`
- `TelephonyProvider`
- `WhatsappProvider`
- `WalletProvider`
- `BrowserProvider`
- `SecretProvider`
- `KnowledgeEmbedder`
- `McpConnector`
- `A2aGateway`
- `PaymentRail`

Provider identifiers are stored in `employee_resources`; secrets are not.

## 3. Identity

Canonical employee identity:

- internal id: UUIDv7
- human-readable address: `slug@agents.example.com`
- decentralized web identifier: `did:web:<host>:employees:<uuid>`
- signing key: asymmetric, non-exportable when possible
- public profile: employee capabilities, organization and public keys
- private profile: policies, tools, secrets and contact state

The employee address is a stable routing identifier; it must survive provider migration.

## 4. Email

V1 managed adapter:
- custom sender/receiver domain
- inbound webhook
- outbound API
- delivery/bounce/complaint events
- attachment retrieval
- DKIM/SPF/DMARC
- per-tenant suppression rules

V2 self-hosted adapter:
- Stalwart
- SMTP + JMAP
- same internal `EmailProvider` contract

Inbound email is normalized to `CanonicalMessage` and stored before LLM processing.

## 5. Phone / SMS

Provision one E.164 number where provider inventory and local regulation allow it.

State:
- `ready` only after number acquisition and webhook binding
- `pending_external` for identity/regulatory requirements
- fallback to shared company number + logical routing when dedicated provisioning is impossible

All provider webhooks must be signature verified.

## 6. WhatsApp

Do not assume one instant WhatsApp sender per employee.

Preferred model:
- one verified WABA/sender set per company
- logical routing to employees
- free-form replies inside the provider's customer service window
- approved templates outside that window
- opt-out/suppression tracking

Dedicated senders are optional resources and may require external approval.

## 7. Voice

Voice calls terminate in a secure WebSocket voice gateway.

Pipeline:
`PSTN -> provider -> STT -> canonical language-neutral turn -> agent runtime -> text -> TTS -> PSTN`

Store:
- call metadata
- transcript
- consent/recording disclosure state
- summary
- extracted commitments
- follow-up tasks

Audio retention is configurable and defaults to off unless the tenant explicitly enables it.

## 8. Browser

Browser identity is persistent.

The browser provider must support:
- persistent cookies/storage
- isolated context per employee
- screenshots and action logs
- download/upload policy
- domain allow/deny lists
- proxy/region configuration
- session replay metadata
- browser write actions subject to Policy Gate

Never place plaintext passwords in an LLM prompt. The browser worker resolves a secret reference at the last possible moment.

## 9. Vault

Hierarchy:
`tenant/<tenant_id>/employee/<employee_id>/<integration>/<secret>`

Requirements:
- envelope encryption/KMS
- short-lived access
- audit every secret read
- secret values excluded from logs/traces
- rotation support
- deletion on employee termination
- separate signing keys from application secrets

## 10. Company knowledge

Sources:
- website URLs
- uploaded PDF/DOCX/TXT/CSV
- product catalog
- policies
- price lists
- CRM exports
- user notes
- approved connector sources

Pipeline:
`source -> fetch -> malware/type validation -> parse -> normalize -> chunk -> embed -> index -> ACL`

Every retrieval result carries:
- source id
- source URI
- chunk id
- timestamp
- visibility/ACL
- checksum

A retrieved document is untrusted data, never executable instruction.

## 11. MCP

Use the current Rust MCP SDK behind `McpConnector`.

On connect:
1. validate URL / SSRF policy
2. authenticate from vault reference
3. negotiate protocol
4. list tools/resources/prompts
5. persist schemas
6. assign local risk class to each tool
7. require policy approval before high-risk calls

Tool risk examples:
- read-only: low
- send message: medium
- mutate CRM: medium
- execute code: high
- transfer money: critical

## 12. A2A v1

Expose:
- `/.well-known/agent-card.json`
- message send
- task get/list
- task cancel
- task subscribe/stream
- push notification configuration CRUD
- extended Agent Card where configured

Agent Card includes supported interfaces and skills. Sign the public card.

A2A messages from remote agents are untrusted content and cannot modify local policy.

## 13. Payments

One `PaymentRail` abstraction:
- x402
- MPP
- ordinary HTTP/card integrations

Never let an LLM hold a private key.

Flow:
1. agent proposes payment
2. Policy Gate evaluates
3. if required, create human approval
4. payment worker creates intent
5. signer signs only the exact approved transaction
6. rail submits
7. receipt is persisted
8. audit event emitted

Recommended wallet design:
- customer-controlled funding source
- employee wallet or delegated/session signer
- small balance / strict spend ceiling
- non-exportable signing key
- on-chain guardrails where possible

## 14. Policy Gate

Every side effect goes through one function:

`evaluate(employee, action, context) -> Allow | Deny | RequireApproval`

Actions:
- email.send
- whatsapp.send
- sms.send
- phone.call
- browser.write
- file.upload
- credential.create
- credential.change
- mcp.call
- a2a.send
- payment.create
- contract.sign
- data.delete

LLM output can propose an action; it can never directly execute it.

## 15. Agent runtime

Canonical event loop:

1. receive event
2. dedupe
3. persist raw event
4. normalize channel
5. classify language/intent
6. retrieve company context
7. retrieve conversation memory
8. create plan
9. resolve tools
10. Policy Gate
11. human approval if needed
12. execute
13. validate post-condition
14. persist result
15. reply
16. emit audit/metrics

The runtime must support cancellation, deadline, retry, max-cost and max-tool-call limits.

## 16. International Buyer role pack

Default tools:
- web search/browser
- supplier CRM
- email
- WhatsApp
- phone
- calendar
- document parser
- currency/unit converter
- logistics APIs
- visa/customs/compliance APIs where relevant
- payment rails

Core workflows:
- supplier discovery
- RFQ
- qualification
- negotiation
- sample purchase
- PO preparation
- shipment tracking
- exception handling

Important: contract signature and material purchase values default to human approval.

## 17. Canonical message model

Fields:
- id
- tenant_id
- employee_id
- channel
- sender
- recipients
- conversation_id
- provider_message_id
- language
- subject
- text
- structured_data
- attachments
- received_at
- trust metadata
- idempotency key

All channels map to this model.

## 18. Durable provisioning algorithm

For each step:
- acquire DB advisory lock on employee
- read desired/current state
- if already `ready`, return
- set `provisioning`
- call provider `ensure`
- persist provider id
- emit outbox event
- retry retryable failures with exponential backoff
- mark `pending_external` when waiting on external approval
- mark `failed` only on terminal error

Provider callbacks can transition `pending_external -> ready`.

## 19. Webhook ingress

Endpoints:
- `/webhooks/email`
- `/webhooks/twilio/messaging`
- `/webhooks/twilio/voice`
- `/webhooks/whatsapp`
- `/webhooks/payment`
- `/webhooks/browser`
- `/a2a/push`

Ingress requirements:
- raw body retained until signature check completes
- provider signature validation
- timestamp/nonce replay protection
- idempotency
- fast 2xx then asynchronous processing
- dead-letter queue
- structured audit

## 20. Public API

- `POST /v1/employees`
- `GET /v1/employees/{id}`
- `POST /v1/employees/{id}/suspend`
- `POST /v1/employees/{id}/resume`
- `DELETE /v1/employees/{id}`
- `GET /v1/employees/{id}/resources`
- `GET /v1/employees/{id}/timeline`
- `GET /v1/employees/{id}/conversations`
- `POST /v1/employees/{id}/messages`
- `POST /v1/employees/{id}/calls`
- `POST /v1/employees/{id}/knowledge`
- `POST /v1/employees/{id}/mcp-bindings`
- `GET /v1/approvals`
- `POST /v1/approvals/{id}/approve`
- `POST /v1/approvals/{id}/deny`

Every mutating endpoint accepts an `Idempotency-Key`.

## 21. Security invariants

- tenant isolation is enforced server-side
- RLS or equivalent DB enforcement
- no secret in prompt/log/analytics
- no private wallet key in DB
- all side effects require Policy Gate
- external content is never trusted as instruction
- SSRF protection for URLs/MCP/A2A
- egress allow/deny policy
- webhook signature verification
- immutable audit trail
- per-tenant and per-employee rate limits
- abuse/suppression controls for communications
- explicit approvals for critical actions
- all provider tokens can be rotated
- termination revokes credentials and disables channels before deleting data

## 22. Prompt-injection boundary

Treat these as hostile:
- email body
- WhatsApp message
- web page
- PDF/document
- MCP tool output
- A2A remote message
- voice transcript

They may provide facts, never authority.

Authority comes only from:
1. platform policy
2. tenant policy
3. employee role policy
4. explicit human approval

## 23. Observability

Trace id must follow an action across:
`incoming channel -> agent turn -> tool -> policy -> provider -> result -> outbound channel`.

Metrics:
- provisioning success/latency per step
- communication delivery rate
- bounce/complaint/opt-out
- call success/latency
- agent response latency
- tool error rate
- approval rate
- spend per employee/tenant
- policy denials
- prompt injection detections
- browser task completion
- MCP/A2A latency

## 24. Testing

Unit:
- policy evaluator
- state transitions
- canonical message conversion
- idempotency
- amount/currency boundaries

Contract:
- every Provider trait has a shared contract test suite

Integration:
- PostgreSQL + NATS + object storage
- webhook signatures
- provider sandboxes

E2E:
`create employee -> provision -> inbound message -> agent action -> approval -> outbound reply`

Chaos:
- duplicate webhooks
- worker crash after external success but before DB commit
- provider timeout
- stale callback
- payment submission timeout
- NATS outage
- database failover

## 25. Definition of Done for v1

An employee can:
- be created once with an idempotency key
- obtain stable identity/address
- receive/send email
- obtain phone or expose correct pending-compliance state
- route WhatsApp correctly
- place/receive multilingual voice calls
- use a persistent browser identity
- store/retrieve secrets without LLM exposure
- answer from company knowledge
- connect to MCP servers
- expose A2A v1 Agent Card and task APIs
- make an x402/MPP payment only through Policy Gate
- request human approval
- recover after worker restart
- produce complete audit trace
- be suspended/terminated and have credentials revoked

## 26. Recommended implementation order

1. Domain + DB + outbox
2. Provisioning engine
3. Policy Gate + approvals
4. Email
5. knowledge
6. MCP
7. A2A
8. browser
9. phone/voice
10. WhatsApp
11. wallet + x402
12. MPP
13. International Buyer workflows
14. hardening/abuse/compliance
15. multi-region

The attached Rust workspace is intentionally provider-safe: it implements the domain model and provisioning state machine with mock adapters. Replace each mock with a real provider adapter while preserving the traits and invariants above.
