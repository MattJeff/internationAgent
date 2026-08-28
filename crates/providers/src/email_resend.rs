//! The real [`EmailProvider`] against Resend's HTTP API.
//!
//! The shape is [`crate::email`]'s — this module only supplies the wire calls.
//! Three things about Resend are load-bearing and none of them are guessable
//! from the trait, so they are written down here:
//!
//! # Inbound is two-phase, and the second phase is on a clock
//!
//! `email.received` carries **metadata only**: an id, the envelope addresses,
//! attachment *descriptors*. No subject, no body, no bytes. So
//! [`ResendEmailProvider::fetch_inbound`] retrieves the message, and
//! [`ResendEmailProvider::fetch_attachment`] then follows the descriptor's
//! `download_url` — which Resend expires after **one hour**. Fetch bytes
//! immediately after the body, never lazily at render time.
//!
//! On a received event `from` is the bare address; the display name is only in
//! the headers on the retrieve endpoint, so `fetch_inbound` prefers the `From`
//! header over the top-level field.
//!
//! # Suppression is ACCOUNT-scoped
//!
//! Resend's suppression list is one list per **account**, not per tenant and
//! not per sending domain. Suppressing `ap@supplier.example` for one tenant
//! would silently stop every other tenant's employees mailing them. Per-tenant
//! suppression therefore has to be **our own table**, checked before
//! [`EmailProvider::send`]; the provider does not give it to us and no caller
//! should assume it does.
//!
//! # `ensure_identity` reconciles a domain *name*
//!
//! Resend domains have no free-form metadata field to stamp
//! [`EnsureCtx::tag`] into, so the reconcile key is the domain name itself —
//! which is fine, because a name is unique per account by construction. The
//! consequence: one adapter owns one sending domain, and every employee sits on
//! it.
//!
//! That is the one place this adapter differs from
//! [`crate::email::contract_suite`]'s default expectation, and it is a
//! parameter rather than an exemption: the suite runs here as
//! [`crate::email::IdentityScope::AccountWide`], which flips "distinct keys
//! must not collapse onto one resource" into "distinct keys must collapse onto
//! *the* resource" and checks everything else unchanged, against the hermetic
//! server below.

use agentos_domain::ids::IdempotencyKey;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// Hard ceiling on one request to Resend, connect included.
///
/// `reqwest::Client::new()` has **no request timeout**, and until this constant
/// existed neither did this adapter. That is not a latency preference, it is
/// what bounds a turn: `Turn::attempt` races the *model* call against its
/// cancellation token and nothing races an effect, so a provider that never
/// answers is a turn that never ends. On the inbound path that turn runs inside
/// the outbox handler's tenant transaction — so the wedge is an open Postgres
/// transaction and a pooled connection held indefinitely, while the lease
/// expires and a second poller re-runs the same turn.
///
/// 60 seconds, and generous on purpose: this is a backstop against a hung
/// socket, not a service-level objective. A vendor that is merely slow should
/// still succeed; one that has stopped answering should stop costing us a
/// connection. `agentos_app::mcp::CALL_TIMEOUT` makes the same argument at the
/// same value, and `peer_keys::FETCH_TIMEOUT` is two seconds because a key
/// directory is on a request path and this is not.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

use crate::email::{
    EmailProvider, OptOuts, OutboundEmail, ProviderMessageId, RawAttachment, RawInbound, SigError,
    WebhookHeaders, verify_signature,
};
use crate::{
    EnsureCtx, ProviderBinding, ProviderError, Provisioned, RELEASE_NOT_SUPPORTED, Secret,
};

/// Resend's public API root.
pub const API_BASE: &str = "https://api.resend.com";

/// How long an attachment `download_url` lives. Resend does not return an
/// expiry, it just stops working, so we stamp the documented hour ourselves.
pub const ATTACHMENT_URL_TTL_SECS: i64 = 3600;

/// The real Resend adapter.
#[derive(Debug)]
pub struct ResendEmailProvider {
    http: reqwest::Client,
    base_url: String,
    api_key: Secret,
    webhook_secret: Secret,
    domain: String,
}

impl ResendEmailProvider {
    /// Adapter identity, as recorded in a [`Provisioned`].
    pub const PROVIDER: &'static str = "resend";

    /// Where a person who replies "stop" to mail this adapter sent is heard.
    ///
    /// `"email"` is the `provider` handle in `webhook_endpoints`, and it is the
    /// only value `0053_webhook_endpoints.sql`'s
    /// `webhook_endpoints_provider_is_wired` CHECK accepts — so this names a
    /// door that exists, is registered per tenant, and verifies a signature
    /// before it accepts a byte.
    ///
    /// # What this claim does NOT say, and nobody should read into it
    ///
    /// **Nothing on this deployment turns a Resend complaint into a
    /// `suppressions` row.** That is still true, and it is now the *only* thing
    /// left of a gap that used to be three:
    ///
    /// * `apps/server/src/routes/webhooks.rs` files every verified delivery
    ///   under `received_event(provider)` — literally
    ///   `webhook.email.received`, whatever event Resend actually sent.
    ///   **Unchanged, and deliberately so**: the edge must not deserialise a
    ///   body before it has verified it, and an `event_type` no handler is
    ///   registered for is the eight-retries-and-a-dead-letter failure applied
    ///   to every message at once. The name is a filing name, not a claim.
    /// * [`crate::email::InboundNotice::parse`] still refuses anything that is
    ///   not `email.received` with [`crate::email::ParseError::WrongEvent`] —
    ///   also unchanged, because nothing should be able to build an inbound
    ///   notice out of a bounce. What changed is that it is no longer the front
    ///   door: [`crate::email::Delivery::parse`] classifies a delivery first,
    ///   and `main::on_webhook` no longer turns "not an inbound message" into a
    ///   handler error. A `email.bounced` or `email.complained` is now read,
    ///   recorded on the audit trail as `mail_refused`, and **completed** —
    ///   where before it was retried eight times and dead-lettered.
    /// * `agentos_app::queue::reconcile_opt_outs` — the one thing in this
    ///   workspace that writes an opt-out home — reads
    ///   `agentos_providers::leads::LeadSink`, which is the *campaign*
    ///   platform. It has never had anything to say about direct mail.
    ///
    /// So the honest reading of this declaration is now "the refusals arrive
    /// here, are read, and are recorded on an append-only trail", and still not
    /// "the person is suppressed". The remaining step is one call, it needs no
    /// migration, and it is named in full on
    /// `agentos_app::inbound::record_refusal`.
    ///
    /// # The two questions only the founder can answer
    ///
    /// 1. **Is that endpoint subscribed to `email.bounced` and
    ///    `email.complained` at Resend at all?** Which events an endpoint
    ///    receives is a setting in Resend's dashboard. Nothing in this binary
    ///    can read it, and no code here should guess: if those events are not
    ///    selected, this declaration names a door nothing is ever pushed
    ///    through, and the gap above is not the first thing to fix.
    /// 2. **Does Resend expose a read of its account-scoped suppression
    ///    list?** If it does, the second declaration is
    ///    [`OptOuts::Pulled`]`{ from: … }` and the reader is
    ///    `reconcile_opt_outs`-shaped and cheap. Nobody here has called the
    ///    live API — deliberately, see this module's header — so the endpoint
    ///    is not named, because a named endpoint nobody has read is worse than
    ///    an absent one.
    pub const OPT_OUTS: OptOuts = OptOuts::Pushed { at: "email" }.vetted();

    /// Build an adapter for one sending `domain`.
    ///
    /// `webhook_secret` is the `whsec_…` signing secret from the Resend
    /// webhook page, not the API key.
    pub fn new(api_key: Secret, webhook_secret: Secret, domain: impl Into<String>) -> Self {
        Self {
            // Built rather than `new()`: see `REQUEST_TIMEOUT`. `build` fails
            // only if the TLS backend cannot be initialised, at which point
            // nothing else in this process works either.
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: API_BASE.to_owned(),
            api_key,
            webhook_secret,
            domain: domain.into(),
        }
    }

    /// Point the adapter at another origin. For hermetic tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// [`EmailProvider::verify_webhook`] with the clock passed in, so the
    /// replay window is testable without sleeping.
    pub fn verify_webhook_at(
        &self,
        raw_body: &[u8],
        headers: &WebhookHeaders,
        now: DateTime<Utc>,
    ) -> Result<(), SigError> {
        verify_signature(&self.webhook_secret, headers, raw_body, now)
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(self.api_key.expose_for_transport())
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(self.api_key.expose_for_transport())
    }

    /// Send a request and classify the outcome.
    ///
    /// ponytail: every transport failure becomes [`ProviderError::timeout`] —
    /// connect, TLS and read errors are all "we do not know whether it landed",
    /// which is the same retryable answer. Split them only if a metric needs to
    /// tell them apart.
    async fn call(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, ProviderError> {
        let response = req.send().await.map_err(|_| ProviderError::timeout())?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        Err(ProviderError::from_status(
            status.as_u16(),
            retry_after(response.headers()),
        ))
    }

    /// [`Self::call`], then the body.
    ///
    /// A body that did not arrive is [`ProviderError::timeout`] and **not**
    /// terminal, which is the same answer [`Self::call`] gives a socket that
    /// dies before the headers and the same one `fetch_attachment`'s own
    /// `.bytes()` already gave a byte stream cut short. It used to be
    /// `Terminal { code: "malformed_response" }`, and the price of that word
    /// was paid on the inbound path: `ingest_email` wraps this in
    /// `InboundError::Provider`, whose `is_retryable` forwards straight to
    /// here, and both inbound seams **park** what they are told is unretryable.
    /// So one reset connection in the middle of a `GET /emails/{id}` — a
    /// message that is sitting there and would be readable a second later —
    /// dead-lettered a customer's email on its first attempt. `Retryable` is
    /// bounded (the outbox gives up after eight and dead-letters *with* a
    /// reason), so the schema-really-did-change case still ends somewhere a
    /// human looks; it just stops taking live mail with it.
    ///
    /// # The word really is gone, and it is not coming back as a code
    ///
    /// What that trade cost is real and worth naming: `last_error` is
    /// `format!("{}: {err}", err.code())`, so a vendor that renamed a field and
    /// a socket that died now produce the identical string, and the two ask an
    /// operator for opposite things — a ticket with the vendor, or nothing at
    /// all. The obvious repair is a distinct retryable code. It is not worth
    /// its price, twice over:
    ///
    /// * [`ProviderError::Retryable`] has no `code` field, so this is a new
    ///   field or a new variant — which means a specimen in
    ///   [`ProviderError::ALL`], growing [`RETRYABLE_CODES`] past two, and
    ///   `CLAIM_SQL` binding that list. A retryable code missing from it is a
    ///   step given one attempt instead of five, silently. That constant's own
    ///   docs exist because of exactly that failure; reopening the retry rule
    ///   to improve a metrics label is the wrong direction of risk.
    /// * The distinction is already on the row, in the column next to it. A
    ///   reset socket clears on attempt two; a schema break fails identically
    ///   until `attempt_count` hits the cap and `CLAIM_SQL` stops claiming it.
    ///   "Retryable, and retried to the cap" *is* "the vendor changed
    ///   something", and it needs no new vocabulary to read.
    async fn call_json<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, ProviderError> {
        self.call(req)
            .await?
            .json::<T>()
            .await
            .map_err(|_| ProviderError::timeout())
    }
}

/// `Retry-After` in seconds. The HTTP-date form is legal and Resend does not
/// send it; an unparseable header just means "use our default backoff".
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DomainList {
    #[serde(default)]
    data: Vec<DomainRow>,
}

#[derive(Deserialize)]
struct DomainRow {
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct Created {
    id: String,
}

#[derive(Deserialize)]
struct RetrievedEmail {
    id: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: Vec<String>,
    subject: Option<String>,
    text: Option<String>,
    html: Option<String>,
    created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    attachments: Vec<RetrievedAttachment>,
    #[serde(default)]
    headers: Vec<Header>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct RetrievedAttachment {
    #[serde(default)]
    id: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    content_type: String,
    #[serde(default, alias = "size")]
    content_length: u64,
    #[serde(default)]
    download_url: String,
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

#[async_trait]
impl EmailProvider for ResendEmailProvider {
    async fn ensure_identity(&self, _ctx: &EnsureCtx) -> Result<Provisioned, ProviderError> {
        // 1 & 2: look up first, return the hit without creating. This is the
        // whole reason a crashed provisioning run does not buy a second domain.
        let listed: DomainList = self.call_json(self.get("/domains")).await?;
        let mut hits = listed.data.iter().filter(|d| d.name == self.domain);
        if let Some(hit) = hits.next() {
            if hits.next().is_some() {
                // Two domains with one name means a past adapter created
                // blind. Papering over it picks one at random.
                return Err(ProviderError::Terminal {
                    code: "duplicate_resource",
                });
            }
            return Ok(Provisioned::new(Self::PROVIDER, hit.id.clone()));
        }

        // 3: only now create, under the same name the lookup reads.
        let created: Created = self
            .call_json(
                self.post("/domains")
                    .json(&serde_json::json!({ "name": self.domain })),
            )
            .await?;
        Ok(Provisioned::new(Self::PROVIDER, created.id))
    }

    /// **Not supported, on purpose.**
    ///
    /// The resource `ensure_identity` binds is the account's *sending domain*,
    /// reconciled by name — one adapter, one domain, every employee on it. So
    /// there is no per-employee thing to give back: `DELETE /domains/{id}` here
    /// would stop email for the whole tenant because one employee was
    /// terminated. Saying so is the only honest answer; returning `Ok(())`
    /// would clear the binding on a domain that is still very much alive.
    ///
    /// The day Resend grows a per-employee identity (a dedicated subdomain, a
    /// per-address suppression), this becomes a real delete and nothing above
    /// it changes.
    async fn release(&self, _binding: &ProviderBinding) -> Result<(), ProviderError> {
        Err(ProviderError::Terminal {
            code: RELEASE_NOT_SUPPORTED,
        })
    }

    async fn send(
        &self,
        key: &IdempotencyKey,
        email: &OutboundEmail,
    ) -> Result<ProviderMessageId, ProviderError> {
        let mut body = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.body_text,
        });
        if let Some(parent) = &email.in_reply_to {
            // Threading lives in the RFC-5322 headers, not in a Resend field.
            let reference = format!("<{}>", parent.as_str());
            body["headers"] = serde_json::json!({
                "In-Reply-To": reference,
                "References": reference,
            });
        }

        let sent: Created = self
            .call_json(
                self.post("/emails")
                    // Resend's native de-dupe, on the key the engine already
                    // holds constant across retries.
                    .header("Idempotency-Key", key.as_str())
                    .json(&body),
            )
            .await?;
        Ok(ProviderMessageId::new(sent.id))
    }

    fn opt_outs(&self) -> OptOuts {
        Self::OPT_OUTS
    }

    fn verify_webhook(&self, raw_body: &[u8], headers: &WebhookHeaders) -> Result<(), SigError> {
        self.verify_webhook_at(raw_body, headers, Utc::now())
    }

    async fn fetch_inbound(&self, id: &ProviderMessageId) -> Result<RawInbound, ProviderError> {
        let email: RetrievedEmail = self
            .call_json(self.get(&format!("/emails/{}", id.as_str())))
            .await?;

        // The webhook only had the bare address. The display name is here.
        let from = email
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("from"))
            .map_or(email.from, |h| h.value.clone());

        let received_at = email.created_at.unwrap_or_else(Utc::now);
        let expires_at = Utc::now() + Duration::seconds(ATTACHMENT_URL_TTL_SECS);

        Ok(RawInbound {
            provider_message_id: ProviderMessageId::new(email.id),
            from,
            to: email.to,
            subject: email.subject,
            text: email.text,
            html: email.html,
            received_at,
            attachments: email
                .attachments
                .into_iter()
                .map(|a| RawAttachment {
                    id: a.id,
                    filename: a.filename,
                    content_type: a.content_type,
                    size_bytes: a.content_length,
                    download_url: a.download_url,
                    url_expires_at: expires_at,
                })
                .collect(),
        })
    }

    async fn fetch_attachment(
        &self,
        id: &ProviderMessageId,
        attachment_id: &str,
    ) -> Result<Vec<u8>, ProviderError> {
        // ponytail: re-retrieves the message to get a live `download_url`. The
        // trait hands us two ids and nothing else, and a URL cached from an
        // earlier retrieve may already be past its hour — so paying for one
        // extra GET is cheaper than serving a dead link. Pass the descriptor
        // through instead only if the retrieve shows up in a profile.
        let raw = self.fetch_inbound(id).await?;
        let attachment = raw
            .attachments
            .iter()
            .find(|a| a.id == attachment_id)
            .ok_or(ProviderError::Terminal { code: "not_found" })?;

        // The URL is provider-supplied but it is still third-party input:
        // anything that is not http(s) is not a download, it is an SSRF probe.
        let url =
            url::Url::parse(&attachment.download_url).map_err(|_| ProviderError::Terminal {
                code: "bad_attachment_url",
            })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ProviderError::Terminal {
                code: "bad_attachment_url",
            });
        }

        let bytes = self
            .call(self.http.get(url))
            .await?
            .bytes()
            .await
            .map_err(|_| ProviderError::timeout())?;
        Ok(bytes.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Tests — hermetic: a loopback HTTP server, no account, no network.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::email::{REPLAY_WINDOW_SECS, sign_webhook};
    use agentos_domain::ids::EmployeeId;

    const WEBHOOK_SECRET: &str = "whsec_cmVzZW5kLXRlc3Qtc2VjcmV0";

    // -- the fake Resend ---------------------------------------------------

    #[derive(Default)]
    struct FakeState {
        /// `"GET /domains"`, in the order the adapter asked.
        seen: Vec<String>,
        domains: Vec<Value>,
        /// `Idempotency-Key` -> the id the first send under it was given.
        sent: std::collections::BTreeMap<String, String>,
        next: u64,
        /// When set, every route answers with this status instead.
        force_status: Option<u16>,
        /// Answer the next request with its status line and `Content-Length`,
        /// then hang up before the body — a connection reset mid-response,
        /// which is the one thing a fake that always finishes its writes
        /// cannot show.
        cut_short_next: bool,
    }

    struct FakeResend {
        addr: SocketAddr,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeResend {
        async fn start() -> Self {
            Self::with_status(None).await
        }

        async fn with_status(force_status: Option<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(FakeState {
                force_status,
                ..FakeState::default()
            }));

            let served = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let state = Arc::clone(&served);
                    tokio::spawn(async move { serve(stream, addr, state).await });
                }
            });
            Self { addr, state }
        }

        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn provider(&self) -> ResendEmailProvider {
            ResendEmailProvider::new(
                Secret::new("re_test_key"),
                Secret::new(WEBHOOK_SECRET),
                "agents.example.com",
            )
            .with_base_url(self.base())
        }

        fn seen(&self) -> Vec<String> {
            self.state.lock().expect("not poisoned").seen.clone()
        }

        fn domain_count(&self) -> usize {
            self.state.lock().expect("not poisoned").domains.len()
        }
    }

    async fn serve(mut stream: TcpStream, addr: SocketAddr, state: Arc<Mutex<FakeState>>) {
        let mut buffer = Vec::new();
        loop {
            let Some((line, headers, body)) = read_request(&mut stream, &mut buffer).await else {
                return;
            };
            let idempotency_key = headers
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("idempotency-key")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            let (status, payload, content_type, cut_short) = {
                let mut state = state.lock().expect("not poisoned");
                state.seen.push(line.clone());
                let cut_short = std::mem::take(&mut state.cut_short_next);
                let (status, payload, content_type) = match state.force_status {
                    Some(code) => (code, b"{}".to_vec(), "application/json"),
                    None => route(&line, &idempotency_key, &body, addr, &mut state),
                };
                (status, payload, content_type, cut_short)
            };

            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
                payload.len()
            );
            if status == 429 {
                head.push_str("Retry-After: 7\r\n");
            }
            head.push_str("\r\n");
            let mut out = head.into_bytes();
            if cut_short {
                // Head only, promising a body, then the socket goes away.
                let _ = stream.write_all(&out).await;
                return;
            }
            out.extend_from_slice(&payload);
            if stream.write_all(&out).await.is_err() {
                return;
            }
        }
    }

    fn route(
        line: &str,
        idempotency_key: &str,
        body: &[u8],
        addr: SocketAddr,
        state: &mut FakeState,
    ) -> (u16, Vec<u8>, &'static str) {
        let json = |v: Value| {
            (
                200u16,
                serde_json::to_vec(&v).expect("serialize"),
                "application/json",
            )
        };
        match line {
            "GET /domains" => {
                let data = state.domains.clone();
                json(json!({ "data": data }))
            }
            "POST /domains" => {
                let name = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|v| v["name"].as_str().map(str::to_owned))
                    .unwrap_or_default();
                state.next += 1;
                let id = format!("dom_{:04}", state.next);
                state.domains.push(json!({ "id": id, "name": name }));
                json(json!({ "id": id, "name": name }))
            }
            // Resend's own de-duplication, modelled: the same key gets the
            // first message's id back and nothing is sent again. Without this
            // the fake would accept an adapter that dropped the header.
            "POST /emails" => {
                let id = match state.sent.get(idempotency_key) {
                    Some(already) => already.clone(),
                    None => {
                        state.next += 1;
                        let id = format!("email_sent_{:04}", state.next);
                        state.sent.insert(idempotency_key.to_owned(), id.clone());
                        id
                    }
                };
                json(json!({ "id": id }))
            }
            "GET /emails/email_2" => json(json!({
                "object": "email",
                "id": "email_2",
                // The bare address, as the webhook had it...
                "from": "ap@supplier.example",
                "to": ["lena@agents.example.com"],
                "subject": "RE: PO-4471",
                "text": "See attached.",
                "created_at": "2026-01-02T03:04:05Z",
                "attachments": [{
                    "id": "att_1",
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "content_length": 3,
                    "download_url": format!("http://{addr}/dl/att_1"),
                }],
                // ...and the display name, which only lives here.
                "headers": [{ "name": "From", "value": "Accounts <ap@supplier.example>" }],
            })),
            "GET /emails/email_hostile" => json(json!({
                "id": "email_hostile",
                "from": "ap@supplier.example",
                "to": ["lena@agents.example.com"],
                "attachments": [{
                    "id": "att_1",
                    "filename": "passwd",
                    "content_type": "text/plain",
                    "download_url": "file:///etc/passwd",
                }],
            })),
            "GET /dl/att_1" => (200, b"PDF".to_vec(), "application/octet-stream"),
            _ => (404, b"{}".to_vec(), "application/json"),
        }
    }

    /// One HTTP/1.1 request: its `METHOD /path` line, its header block and its
    /// body.
    ///
    /// The headers come back whole because `Idempotency-Key` is part of the
    /// contract the adapter is being held to — a fake that answers the same id
    /// to every POST would let a broken de-duplication pass.
    async fn read_request(
        stream: &mut TcpStream,
        buffer: &mut Vec<u8>,
    ) -> Option<(String, String, Vec<u8>)> {
        loop {
            if let Some(head) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buffer[..head]).into_owned();
                let length = headers
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let start = head + 4;
                if buffer.len() >= start + length {
                    let line = headers
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .rsplit_once(' ')
                        .map(|(request, _http)| request.to_owned())
                        .unwrap_or_default();
                    let body = buffer[start..start + length].to_vec();
                    buffer.drain(..start + length);
                    return Some((line, headers, body));
                }
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    // -- fixtures ----------------------------------------------------------

    fn webhook_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "email.received",
            "created_at": "2026-01-02T03:04:05Z",
            "data": {
                "email_id": "email_2",
                "from": "ap@supplier.example",
                "to": ["lena@agents.example.com"],
                "attachments": [{ "id": "att_1", "filename": "invoice.pdf" }],
            }
        }))
        .expect("serialize")
    }

    fn signed(secret: &str, body: &[u8], now: DateTime<Utc>) -> WebhookHeaders {
        let id = "msg_2Kx".to_owned();
        let timestamp = now.timestamp().to_string();
        WebhookHeaders {
            signature: sign_webhook(&Secret::new(secret), &id, &timestamp, body),
            id,
            timestamp,
        }
    }

    fn ctx() -> EnsureCtx {
        EnsureCtx::new(
            agentos_domain::ids::TenantId::new_v7(Utc::now()),
            EmployeeId::new_v7(Utc::now()),
            agentos_domain::ids::Slug::parse("lena").expect("slug"),
            "email",
        )
    }

    // -- signatures --------------------------------------------------------

    #[tokio::test]
    async fn signature_verification_accepts_only_an_honest_fresh_body() {
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let now = Utc::now();
        let body = webhook_body();
        let headers = signed(WEBHOOK_SECRET, &body, now);

        p.verify_webhook_at(&body, &headers, now).expect("honest");

        // Tampered body: one byte, anywhere.
        let mut tampered = body.clone();
        let victim = tampered.len() / 2;
        tampered[victim] ^= 0x01;
        assert_eq!(
            p.verify_webhook_at(&tampered, &headers, now),
            Err(SigError::Mismatch)
        );

        // Wrong secret — the attacker signed it, just not with our key.
        let forged = signed("whsec_c29tZS1vdGhlci1zZWNyZXQ=", &body, now);
        assert_eq!(
            p.verify_webhook_at(&body, &forged, now),
            Err(SigError::Mismatch)
        );

        // Stale: perfectly signed, replayed outside the window.
        let stale = now - Duration::seconds(REPLAY_WINDOW_SECS + 1);
        let old = signed(WEBHOOK_SECRET, &body, stale);
        assert_eq!(p.verify_webhook_at(&body, &old, now), Err(SigError::Stale));
        // ...and it verified fine at the time it was sent, so `Stale` is the
        // replay window doing its job and not a broken signature.
        assert_eq!(p.verify_webhook_at(&body, &old, stale), Ok(()));

        // A missing header is its own diagnosis, not a mismatch.
        assert_eq!(
            p.verify_webhook_at(
                &body,
                &WebhookHeaders {
                    signature: String::new(),
                    ..headers
                },
                now
            ),
            Err(SigError::MissingHeader)
        );
    }

    /// A `==` on a MAC returns as soon as two bytes differ, so a forger can
    /// walk the signature out one byte at a time. The comparison must look at
    /// every byte and reach the same verdict wherever the difference is.
    ///
    /// Structural, not a stopwatch: a wall-clock assertion here would be flaky
    /// in CI *and* meaningless, since recomputing the HMAC dominates either
    /// way. What this catches is a comparison that short-circuits — the length
    /// check included.
    #[tokio::test]
    async fn verification_examines_the_whole_mac_not_just_its_prefix() {
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let now = Utc::now();
        let body = webhook_body();
        let good = signed(WEBHOOK_SECRET, &body, now);
        let mac = B64
            .decode(good.signature.strip_prefix("v1,").expect("v1 prefix"))
            .expect("base64");

        for victim in [0, mac.len() / 2, mac.len() - 1] {
            let mut bad = mac.clone();
            bad[victim] ^= 0x01;
            assert_eq!(
                p.verify_webhook_at(
                    &body,
                    &WebhookHeaders {
                        signature: format!("v1,{}", B64.encode(&bad)),
                        ..good.clone()
                    },
                    now
                ),
                Err(SigError::Mismatch),
                "a difference at byte {victim} must be caught like any other"
            );
        }

        // Truncated and over-long MACs are rejected, not indexed off the end.
        for length in [0, mac.len() - 1] {
            assert_eq!(
                p.verify_webhook_at(
                    &body,
                    &WebhookHeaders {
                        signature: format!("v1,{}", B64.encode(&mac[..length])),
                        ..good.clone()
                    },
                    now
                ),
                Err(SigError::Mismatch)
            );
        }
        let mut long = mac.clone();
        long.push(0);
        assert_eq!(
            p.verify_webhook_at(
                &body,
                &WebhookHeaders {
                    signature: format!("v1,{}", B64.encode(&long)),
                    ..good
                },
                now
            ),
            Err(SigError::Mismatch)
        );
    }

    // -- two-phase inbound -------------------------------------------------

    #[tokio::test]
    async fn inbound_fetches_the_body_first_then_the_attachment_bytes() {
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let id = ProviderMessageId::new("email_2");

        let raw = p.fetch_inbound(&id).await.expect("phase two");
        // The webhook only had the bare address; the retrieve carries the name.
        assert_eq!(raw.from, "Accounts <ap@supplier.example>");
        assert_eq!(raw.text.as_deref(), Some("See attached."));
        assert_eq!(raw.attachments.len(), 1);
        let attachment = &raw.attachments[0];
        assert_eq!(attachment.id, "att_1");
        assert_eq!(attachment.size_bytes, 3);
        // The hour is stamped by us, because Resend does not send one.
        let ttl = attachment.url_expires_at - Utc::now();
        assert!(
            ttl > Duration::seconds(ATTACHMENT_URL_TTL_SECS - 60)
                && ttl <= Duration::seconds(ATTACHMENT_URL_TTL_SECS),
            "{ttl}"
        );

        let bytes = p.fetch_attachment(&id, "att_1").await.expect("phase three");
        assert_eq!(bytes, b"PDF");

        // The order is the point: never a download before a retrieve, because
        // the URL only exists on the retrieve and only for an hour. The second
        // retrieve is `fetch_attachment` refreshing that URL rather than
        // trusting a possibly-expired one.
        assert_eq!(
            fake.seen(),
            vec![
                "GET /emails/email_2".to_owned(),
                "GET /emails/email_2".to_owned(),
                "GET /dl/att_1".to_owned(),
            ]
        );

        assert_eq!(
            p.fetch_attachment(&id, "att_missing").await,
            Err(ProviderError::Terminal { code: "not_found" })
        );
    }

    /// A body that never arrived is not the message being unreadable.
    ///
    /// This is the mail half of the same question the status mapping answers:
    /// `ingest_email` wraps whatever `fetch_inbound` returns in
    /// `InboundError::Provider`, whose `is_retryable` forwards straight to
    /// [`ProviderError::is_retryable`], and both inbound seams **park** what
    /// they are told is unretryable. So the terminal reading of a reset
    /// connection was a customer's email dead-lettered on attempt one over a
    /// busy minute — the same sentence `a_late_body_is_retryable_and_a_bad_
    /// address_is_not` keeps for the database, applied to the socket.
    ///
    /// The assertion is `is_retryable` and not "it failed": every wrong answer
    /// here is also a failure, and only one of them is retried.
    #[tokio::test]
    async fn a_retrieve_whose_body_never_arrived_is_a_wait_not_a_refusal() {
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let id = ProviderMessageId::new("email_2");

        fake.state.lock().expect("not poisoned").cut_short_next = true;
        let cut_short = p
            .fetch_inbound(&id)
            .await
            .expect_err("the socket died mid-body");
        assert!(
            cut_short.is_retryable(),
            "a body cut short parks the customer's mail on attempt one: {cut_short:?}"
        );

        // And the message really was readable a moment later, which is the
        // whole reason parking it was wrong.
        assert_eq!(
            p.fetch_inbound(&id).await.expect("readable").from,
            "Accounts <ap@supplier.example>"
        );
    }

    // -- reconcile before create -------------------------------------------

    #[tokio::test]
    async fn ensure_twice_yields_one_domain_with_the_same_external_id() {
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let ctx = ctx();

        let first = p.ensure_identity(&ctx).await.expect("first ensure");
        let second = p
            .ensure_identity(&ctx.clone().retry())
            .await
            .expect("second ensure");

        assert_eq!(first, second);
        assert_eq!(first.provider, ResendEmailProvider::PROVIDER);
        assert_eq!(first.external_id, "dom_0001");
        assert_eq!(fake.domain_count(), 1, "exactly one domain, ever");
        assert_eq!(
            fake.seen(),
            vec![
                // Look up, miss, create.
                "GET /domains".to_owned(),
                "POST /domains".to_owned(),
                // Look up, hit, create NOTHING.
                "GET /domains".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn two_domains_with_one_name_is_a_human_problem_not_a_coin_flip() {
        let fake = FakeResend::start().await;
        {
            let mut state = fake.state.lock().expect("not poisoned");
            state
                .domains
                .push(json!({"id": "dom_a", "name": "agents.example.com"}));
            state
                .domains
                .push(json!({"id": "dom_b", "name": "agents.example.com"}));
        }
        assert_eq!(
            fake.provider().ensure_identity(&ctx()).await,
            Err(ProviderError::Terminal {
                code: "duplicate_resource"
            })
        );
    }

    // -- status mapping ----------------------------------------------------

    #[tokio::test]
    async fn a_429_is_rate_limited_and_a_422_is_terminal() {
        let throttled = FakeResend::with_status(Some(429)).await;
        let email = OutboundEmail {
            from: "lena@agents.example.com".to_owned(),
            to: vec!["ap@supplier.example".to_owned()],
            subject: "PO-4471".to_owned(),
            body_text: "Attached.".to_owned(),
            in_reply_to: Some(ProviderMessageId::new("email_1")),
        };
        let key = IdempotencyKey::for_step(EmployeeId::new_v7(Utc::now()), "send:po-4471");

        let err = throttled
            .provider()
            .send(&key, &email)
            .await
            .expect_err("throttled");
        assert_eq!(
            err,
            ProviderError::RateLimited {
                retry_after: std::time::Duration::from_secs(7)
            },
            "the provider's own Retry-After must survive the mapping"
        );
        assert!(err.is_retryable());

        let rejected = FakeResend::with_status(Some(422)).await;
        let err = rejected
            .provider()
            .send(&key, &email)
            .await
            .expect_err("rejected");
        assert_eq!(
            err,
            ProviderError::Terminal {
                code: "unprocessable"
            }
        );
        assert!(!err.is_retryable(), "retrying a 422 only wastes quota");
    }

    #[tokio::test]
    async fn send_returns_the_provider_message_id() {
        let fake = FakeResend::start().await;
        let key = IdempotencyKey::for_step(EmployeeId::new_v7(Utc::now()), "send:po-1");
        let sent = fake
            .provider()
            .send(
                &key,
                &OutboundEmail {
                    from: "lena@agents.example.com".to_owned(),
                    to: vec!["ap@supplier.example".to_owned()],
                    subject: "PO-1".to_owned(),
                    body_text: "hi".to_owned(),
                    in_reply_to: None,
                },
            )
            .await
            .expect("send");
        assert_eq!(sent.as_str(), "email_sent_0001");
        assert_eq!(fake.seen(), vec!["POST /emails".to_owned()]);
    }

    #[tokio::test]
    async fn an_attachment_url_that_is_not_http_is_refused() {
        // A compromised or buggy provider handing us `file:///etc/passwd` is a
        // read primitive, not a download.
        let fake = FakeResend::start().await;
        let p = fake.provider();
        let id = ProviderMessageId::new("email_hostile");

        // The metadata still comes back — only following the URL is refused.
        let raw = p.fetch_inbound(&id).await.expect("retrieve");
        assert_eq!(raw.attachments[0].download_url, "file:///etc/passwd");
        assert_eq!(
            p.fetch_attachment(&id, "att_1").await,
            Err(ProviderError::Terminal {
                code: "bad_attachment_url"
            })
        );
    }

    /// The real client against the shared contract — the thing that makes
    /// swapping a vendor provable rather than hopeful.
    ///
    /// [`IdentityScope::AccountWide`] because Resend genuinely reconciles every
    /// employee onto one sending domain (see this module's header). That one
    /// difference used to keep the adapter out of the suite entirely, which
    /// bought a documented exception at the price of testing nothing.
    #[tokio::test]
    async fn the_real_client_satisfies_the_contract() {
        let fake = FakeResend::start().await;
        crate::email::contract_suite(&fake.provider(), crate::email::IdentityScope::AccountWide)
            .await;

        // One domain for three ensures, checked on the socket rather than taken
        // from the adapter's word.
        assert_eq!(fake.domain_count(), 1);

        // All three sends *do* reach the wire, and that is correct: this
        // adapter does not keep a de-duplication map, it sends Resend's own
        // `Idempotency-Key` and lets the provider collapse the replay. The
        // suite's "same key, same id" assertion is what proves the header is
        // really being sent — drop it and the fake keys every send on the empty
        // string, and the *next* assertion, "distinct keys, distinct ids",
        // fails instead. Either way a broken header is caught.
        assert_eq!(
            fake.seen()
                .iter()
                .filter(|line| *line == "POST /emails")
                .count(),
            3,
        );
    }
}
