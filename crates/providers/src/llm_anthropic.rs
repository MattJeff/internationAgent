//! The real [`Llm`]: `POST https://api.anthropic.com/v1/messages` over reqwest.
//!
//! There is no official Anthropic Rust SDK — see the [`crate::llm`] module docs
//! for the two crates that claim to be one and are not. So this is the adapter:
//! a mapping layer between our types and the wire shape, and nothing else. The
//! agent loop, the budget and the retry policy all live above [`Llm`].
//!
//! Three things here are load-bearing rather than decorative:
//!
//! * **`cache_read_input_tokens` is carried through.** The budget counter reads
//!   [`Usage::cache_read_tokens`]; drop the field and cost enforcement silently
//!   stops working — no error, just a counter that reads zero forever.
//! * **`stop_reason == "refusal"` is a 200.** It is [`StopReason::Refusal`], not
//!   an error and not a parse failure. Code that reads `content[0]` breaks on it
//!   because the content array can be empty.
//! * **Timeouts are never [`ProviderError::Terminal`].** A timed-out request may
//!   still have landed; the only safe classification is retryable.
//!
//! Deliberately not sent: `temperature` / `top_p` / `top_k` (removed on
//! claude-opus-5, they 400), `thinking.budget_tokens` (removed, it 400s), and
//! any assistant-turn prefill (it 400s). Extended thinking and `output_config`
//! are left at their defaults.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::llm::{Content, Llm, LlmRequest, LlmResponse, StopReason, Usage};
use crate::{ProviderError, Secret};

/// The model this adapter is written against.
pub const DEFAULT_MODEL: &str = "claude-opus-5";

const API_BASE: &str = "https://api.anthropic.com";
const API_VERSION: &str = "2023-06-01";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A `/v1/messages` client.
///
/// `Debug` is safe: [`Secret`] renders as `[redacted]`, and the key lives
/// nowhere else — not in the base URL, not in an error, not in a log line.
#[derive(Debug)]
pub struct AnthropicLlm {
    http: reqwest::Client,
    api_key: Secret,
    base_url: String,
}

impl AnthropicLlm {
    /// A client against the real API with a bounded per-request timeout.
    pub fn new(api_key: Secret) -> Self {
        Self::with_timeout(api_key, DEFAULT_TIMEOUT)
    }

    /// As [`AnthropicLlm::new`], with an explicit timeout. Every request is
    /// bounded: an unbounded LLM call hangs an employee turn forever.
    pub fn with_timeout(api_key: Secret, timeout: Duration) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("reqwest client"),
            api_key,
            base_url: API_BASE.to_owned(),
        }
    }

    /// Point at another origin — a local test server, or a proxy.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }

    /// The wire body for one turn.
    ///
    /// Render order is tools -> system -> messages, so the breakpoint on the
    /// last (only) system block caches tools and system together.
    fn body(req: &LlmRequest) -> Value {
        let mut body = json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": messages(req),
        });

        // An empty system block is a 400, so send the field only when there is one.
        if !req.system.is_empty() {
            body["system"] = json!([{
                "type": "text",
                "text": req.system,
                "cache_control": { "type": "ephemeral" },
            }]);
        }
        if !req.tools.is_empty() {
            body["tools"] = json!(req.tools);
        }
        body
    }
}

/// The message array, with the caller's cache breakpoint applied.
fn messages(req: &LlmRequest) -> Vec<Value> {
    let mut messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m| json!({ "role": m.role, "content": m.content }))
        .collect();

    // Caching is a prefix match, so the breakpoint goes on the LAST block of
    // the last stable message — everything before it is what gets reused.
    if let Some(block) = req
        .cache_breakpoint
        .and_then(|i| messages.get_mut(i))
        .and_then(|m| m["content"].as_array_mut())
        .and_then(|blocks| blocks.last_mut())
    {
        block["cache_control"] = json!({ "type": "ephemeral" });
    }
    messages
}

#[async_trait]
impl Llm for AnthropicLlm {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, ProviderError> {
        let response = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", self.api_key.expose_for_transport())
            .header("anthropic-version", API_VERSION)
            .json(&Self::body(&req))
            .send()
            .await
            .map_err(|e| {
                // Transport, connect or timeout: the request may have landed, so
                // this is retryable no matter what. Never Terminal.
                tracing::warn!(error = %e, "anthropic request failed in transport");
                ProviderError::timeout()
            })?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
            .map(Duration::from_secs);

        if !status.is_success() {
            return Err(ProviderError::from_status(status.as_u16(), retry_after));
        }

        let bytes = response.bytes().await.map_err(|e| {
            tracing::warn!(error = %e, "anthropic response body truncated");
            ProviderError::timeout()
        })?;

        serde_json::from_slice::<Wire>(&bytes)
            .map(Wire::into_response)
            .map_err(|e| {
                tracing::warn!(error = %e, "anthropic response did not parse");
                ProviderError::Terminal {
                    code: "invalid_response",
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Wire {
    #[serde(default)]
    content: Vec<Block>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: WireUsage,
}

/// Only the blocks we can represent. Thinking blocks and anything the API adds
/// later fall into `Other` and are dropped rather than failing the parse — a new
/// block type must not take an employee down.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Block {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    #[serde(other)]
    Other,
}

#[derive(Default, Deserialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

impl Wire {
    fn into_response(self) -> LlmResponse {
        LlmResponse {
            content: self
                .content
                .into_iter()
                .filter_map(|block| match block {
                    Block::Text { text } => Some(Content::Text { text }),
                    Block::ToolUse { id, name, input } => {
                        Some(Content::ToolUse { id, name, input })
                    }
                    Block::Other => None,
                })
                .collect(),
            stop_reason: stop_reason(self.stop_reason.as_deref()),
            usage: Usage {
                // ponytail: cache writes are billed above fresh input and `Usage`
                // has no slot for them, so they fold into `input_tokens` —
                // over-counting slightly beats not counting at all. Split it out
                // the day the budget needs per-rate accounting.
                input_tokens: self
                    .usage
                    .input_tokens
                    .saturating_add(self.usage.cache_creation_input_tokens),
                output_tokens: self.usage.output_tokens,
                cache_read_tokens: self.usage.cache_read_input_tokens,
            },
        }
    }
}

/// Wire `stop_reason` -> [`StopReason`]. Never branch on `stop_details`: it is
/// populated only for a refusal and is null for everything else.
fn stop_reason(wire: Option<&str>) -> StopReason {
    match wire {
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("stop_sequence") => StopReason::StopSequence,
        Some("refusal") => StopReason::Refusal,
        // `pause_turn` is a turn the model wants continued; we have nowhere to
        // put that, and the answer in hand is incomplete, so it reads as a
        // truncation. Everything else, including a missing field, ends the turn.
        Some("pause_turn") => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::*;
    use crate::llm::{Message, ToolDef};

    const KEY: &str = "sk-ant-do-not-leak-me";

    /// A one-shot HTTP server. Returns its origin and a handle yielding the raw
    /// request it received. No wiremock in this workspace, and a listener plus
    /// twenty lines is less machinery than a dependency.
    async fn server(status: &str, headers: &str, body: &str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{headers}connection: close\r\n\r\n{body}",
            body.len()
        );

        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let raw = read_request(&mut sock).await;
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            raw
        });
        (origin, handle)
    }

    async fn read_request(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
            let len: usize = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split(['\r', '\n']).next())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn client(origin: &str) -> AnthropicLlm {
        AnthropicLlm::with_timeout(Secret::new(KEY), Duration::from_secs(5)).with_base_url(origin)
    }

    fn request() -> LlmRequest {
        LlmRequest::new(DEFAULT_MODEL, "you are lena", 16_000)
            .with_tools(vec![ToolDef {
                name: "search".into(),
                description: "search the web".into(),
                input_schema: json!({ "type": "object" }),
            }])
            .with_message(Message::user("hello"))
            .cache_here()
            .with_message(Message::assistant("hi"))
    }

    /// Split a raw request into its lowercased head and its parsed JSON body.
    fn split(raw: &str) -> (String, Value) {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        (head.to_lowercase(), serde_json::from_str(body).unwrap())
    }

    const OK_BODY: &str = r#"{"content":[{"type":"text","text":"ok"}],
        "stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#;

    #[tokio::test]
    async fn the_outgoing_request_carries_the_headers_and_none_of_the_removed_params() {
        let (origin, handle) = server("200 OK", "", OK_BODY).await;
        client(&origin).complete(request()).await.unwrap();
        let raw = handle.await.unwrap();
        let (head, body) = split(&raw);

        assert!(raw.starts_with("POST /v1/messages "), "{raw}");
        assert!(head.contains(&format!("x-api-key: {KEY}")), "{head}");
        assert!(head.contains("anthropic-version: 2023-06-01"), "{head}");
        assert!(head.contains("content-type: application/json"), "{head}");

        assert_eq!(body["model"], "claude-opus-5");
        assert_eq!(body["max_tokens"], 16_000);
        for removed in ["temperature", "top_p", "top_k", "thinking"] {
            assert!(body.get(removed).is_none(), "{removed} must not be sent");
        }
        assert!(!raw.contains("budget_tokens"), "{raw}");
        // No assistant-turn prefill: the last message we send is ours to send,
        // but it is history, not a half-written answer for the model to finish.
        assert_eq!(body["messages"].as_array().unwrap().len(), 2);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][1]["role"], "assistant");
    }

    #[tokio::test]
    async fn the_cache_breakpoints_land_on_the_system_block_and_the_stable_prefix() {
        let (origin, handle) = server("200 OK", "", OK_BODY).await;
        client(&origin).complete(request()).await.unwrap();
        let (_, body) = split(&handle.await.unwrap());

        // Tools render before system, so one breakpoint on the last system
        // block caches tools and system together.
        assert_eq!(body["system"][0]["text"], "you are lena");
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(body["tools"][0]["name"], "search");
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");

        // `cache_here()` marked messages[0]; messages[1] came after it.
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert!(
            body["messages"][1]["content"][0]
                .get("cache_control")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_tool_use_response_parses_into_tool_calls_with_the_full_usage() {
        let body = r#"{
            "content": [
                {"type":"thinking","thinking":"hmm","signature":"sig"},
                {"type":"text","text":"let me look"},
                {"type":"tool_use","id":"toolu_01","name":"search","input":{"q":"lena"}}
            ],
            "stop_reason": "tool_use",
            "stop_details": null,
            "usage": {"input_tokens":120,"output_tokens":34,
                      "cache_creation_input_tokens":6,"cache_read_input_tokens":4096}
        }"#;
        let (origin, _handle) = server("200 OK", "", body).await;

        let response = client(&origin).complete(request()).await.unwrap();

        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert!(response.stop_reason.wants_tools());
        // The thinking block is dropped, the other two survive in order.
        assert_eq!(response.content.len(), 2);
        assert_eq!(response.content[0], Content::text("let me look"));
        assert_eq!(response.tool_uses().count(), 1);
        assert_eq!(
            response.content[1],
            Content::tool_use("toolu_01", "search", json!({ "q": "lena" }))
        );
        // cache_read is its own field or the budget silently stops enforcing.
        assert_eq!(response.usage.cache_read_tokens, 4096);
        assert_eq!(response.usage.input_tokens, 126); // cache writes folded in
        assert_eq!(response.usage.output_tokens, 34);
    }

    #[tokio::test]
    async fn a_refusal_is_a_normal_two_hundred_with_no_content_to_read() {
        let body = r#"{
            "content": [],
            "stop_reason": "refusal",
            "stop_details": {"type":"refusal","category":"csam","explanation":"no"},
            "usage": {"input_tokens":9,"output_tokens":0}
        }"#;
        let (origin, _handle) = server("200 OK", "", body).await;

        let response = client(&origin).complete(request()).await.unwrap();

        assert_eq!(response.stop_reason, StopReason::Refusal);
        assert!(!response.stop_reason.wants_tools());
        assert!(response.content.is_empty(), "nothing to read at content[0]");
        assert_eq!(response.usage.input_tokens, 9);
    }

    #[tokio::test]
    async fn a_pause_turn_and_an_unknown_stop_reason_both_end_the_turn() {
        assert_eq!(stop_reason(Some("pause_turn")), StopReason::MaxTokens);
        assert_eq!(stop_reason(Some("something_new")), StopReason::EndTurn);
        assert_eq!(stop_reason(None), StopReason::EndTurn);
        assert_eq!(stop_reason(Some("end_turn")), StopReason::EndTurn);
        assert_eq!(stop_reason(Some("stop_sequence")), StopReason::StopSequence);
    }

    #[tokio::test]
    async fn a_429_honours_retry_after_and_a_400_is_terminal() {
        let (origin, _h) = server("429 Too Many Requests", "retry-after: 7\r\n", "{}").await;
        assert_eq!(
            client(&origin).complete(request()).await.unwrap_err(),
            ProviderError::RateLimited {
                retry_after: Duration::from_secs(7)
            }
        );

        let (origin, _h) = server("400 Bad Request", "", r#"{"type":"error"}"#).await;
        let err = client(&origin).complete(request()).await.unwrap_err();
        assert!(!err.is_retryable());
        assert_eq!(err.code(), "bad_request");

        let (origin, _h) = server("529 Overloaded", "", "{}").await;
        let overloaded = client(&origin).complete(request()).await.unwrap_err();
        assert!(overloaded.is_retryable());
        assert_eq!(overloaded.code(), "retryable");
    }

    #[tokio::test]
    async fn a_timeout_is_retryable_and_never_terminal() {
        // A server that accepts the connection and then says nothing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let _keep = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(conn);
        });

        let llm = AnthropicLlm::with_timeout(Secret::new(KEY), Duration::from_millis(150))
            .with_base_url(&origin);
        let err = llm.complete(request()).await.unwrap_err();

        assert!(err.is_retryable(), "a timeout may mean the request landed");
        assert!(matches!(err, ProviderError::Retryable { .. }));
    }

    #[tokio::test]
    async fn the_api_key_never_reaches_debug_or_an_error() {
        let (origin, _h) = server("401 Unauthorized", "", "{}").await;
        let llm = client(&origin);

        let debug = format!("{llm:?}");
        assert!(!debug.contains(KEY), "{debug}");
        assert!(debug.contains(Secret::REDACTED), "{debug}");

        let err = llm.complete(request()).await.unwrap_err();
        assert_eq!(err.code(), "unauthorized");
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains(KEY), "{rendered}");
    }
}
