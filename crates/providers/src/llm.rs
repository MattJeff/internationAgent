//! The LLM port: one trait, one scripted mock.
//!
//! # There is no official Anthropic Rust SDK
//!
//! Two crates on crates.io advertise themselves as one and are **not**:
//! `claude-agent-sdk` and `anthropic_rust` both point their `repository`
//! metadata at `github.com/anthropics/...` URLs that 404. They are unaffiliated
//! with Anthropic, unaudited, and must never be added to this workspace — an
//! LLM client sees every secret, every customer message and every tool result
//! that passes through an employee.
//!
//! The real adapter is therefore ours: roughly 200 lines of `reqwest` against
//! `POST /v1/messages`, living beside this trait once it is needed. It is
//! deliberately not written yet, and `reqwest` is deliberately not a dependency
//! of this crate yet — the agent runtime is built and tested against [`Llm`]
//! and [`ScriptedLlm`], so nothing downstream needs the network to exist.
//!
//! # Why the mock is scripted
//!
//! The agent loop has exactly two ways to end: it runs out of budget, or the
//! model stops asking for tools. Both are properties of the *sequence* of
//! responses, not of any single one, so the mock replays a caller-supplied
//! sequence:
//!
//! * [`ScriptedLlm::new`] replays its script in order and then refuses,
//!   turning "the runtime asked for one more turn than I scripted" into a
//!   loud, attributable failure instead of a hang.
//! * [`ScriptedLlm::looping`] never runs out. Point it at a single
//!   [`StopReason::ToolUse`] turn and you have a model that will happily spin
//!   forever — the only honest way to prove the budget counter, and not the
//!   model, is what terminates the loop.
//!
//! [`ScriptedLlm::usage`] accumulates across turns for the same reason: a
//! budget that only ever reads the last response's usage is not a budget.

use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ProviderError;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Who produced a message.
///
/// There is no `System` role: the system prompt is [`LlmRequest::system`], a
/// separate field, because it is the stable prefix every cache read depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Us, or a tool result we are handing back.
    User,
    /// The model.
    Assistant,
}

/// One block inside a message.
///
/// A tool-using conversation is not a list of strings: an assistant turn can
/// carry prose *and* a tool call, and the reply to that call has to name the
/// call it answers, or a parallel tool turn cannot be reassembled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    /// Prose.
    Text {
        /// The text.
        text: String,
    },
    /// The model asking for a tool to be run.
    ToolUse {
        /// Correlation id; the matching [`Content::ToolResult`] repeats it.
        id: String,
        /// Tool name, matching a [`ToolDef::name`] from the request.
        name: String,
        /// Arguments, shaped by that tool's [`ToolDef::input_schema`].
        input: Value,
    },
    /// Our answer to one [`Content::ToolUse`].
    ToolResult {
        /// The [`Content::ToolUse::id`] being answered.
        tool_use_id: String,
        /// Rendered result, or the error text when `is_error`.
        content: String,
        /// True when the tool failed. The model is expected to recover, so a
        /// failure is reported in-band rather than aborting the turn.
        is_error: bool,
    },
}

impl Content {
    /// Shorthand for a prose block.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Shorthand for a tool call.
    pub fn tool_use(id: impl Into<String>, name: impl Into<String>, input: Value) -> Self {
        Self::ToolUse {
            id: id.into(),
            name: name.into(),
            input,
        }
    }

    /// Shorthand for a successful tool result.
    pub fn tool_result(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::ToolResult {
            tool_use_id: tool_use_id.into(),
            content: content.into(),
            is_error: false,
        }
    }
}

/// One turn of the conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Who spoke.
    pub role: Role,
    /// What they said, in order.
    pub content: Vec<Content>,
}

impl Message {
    /// A user turn carrying a single prose block.
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: vec![Content::text(text)],
        }
    }

    /// An assistant turn carrying a single prose block.
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: vec![Content::text(text)],
        }
    }

    /// A turn carrying arbitrary blocks.
    pub fn new(role: Role, content: Vec<Content>) -> Self {
        Self { role, content }
    }
}

/// A tool the model may call this turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDef {
    /// Stable name; the model echoes it in [`Content::ToolUse::name`].
    pub name: String,
    /// What the tool does and when to reach for it. The model reads this.
    pub description: String,
    /// JSON Schema for [`Content::ToolUse::input`].
    pub input_schema: Value,
}

/// One call to the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    /// Model identifier, passed through to the provider untouched.
    pub model: String,
    /// The system prompt. Part of the stable prefix, so it is a field of its
    /// own rather than a message.
    pub system: String,
    /// The conversation, oldest first.
    pub messages: Vec<Message>,
    /// Tools available this turn. Adding or reordering these invalidates every
    /// cache read, so treat the list as frozen for a conversation.
    pub tools: Vec<ToolDef>,
    /// Hard ceiling on generated tokens for this turn.
    pub max_tokens: u32,
    /// Index of the last message of the stable prefix, inclusive.
    ///
    /// `Some(i)` means "everything up to and including `messages[i]` is
    /// byte-identical to the previous call, cache it". `None` means no
    /// breakpoint: the whole prompt is re-read at full price. The system prompt
    /// and tools always precede the breakpoint — they are the prefix.
    pub cache_breakpoint: Option<usize>,
}

impl LlmRequest {
    /// A request with no tools and no cache breakpoint.
    pub fn new(model: impl Into<String>, system: impl Into<String>, max_tokens: u32) -> Self {
        Self {
            model: model.into(),
            system: system.into(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens,
            cache_breakpoint: None,
        }
    }

    /// Append a turn.
    #[must_use]
    pub fn with_message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    /// Set the tool list.
    #[must_use]
    pub fn with_tools(mut self, tools: Vec<ToolDef>) -> Self {
        self.tools = tools;
        self
    }

    /// Mark everything already in `messages` as the stable prefix.
    ///
    /// Call this after loading history and before appending the new turn, which
    /// is the only ordering that produces a cache hit.
    #[must_use]
    pub fn cache_here(mut self) -> Self {
        self.cache_breakpoint = self.messages.len().checked_sub(1);
        self
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// What the model spent on one turn.
///
/// The budget counter reads this, so `cache_read_tokens` is not decoration:
/// cached input is billed at a fraction of fresh input, and a counter that
/// folds it into `input_tokens` over-charges every long conversation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Fresh input tokens, billed at full rate.
    pub input_tokens: u64,
    /// Generated tokens.
    pub output_tokens: u64,
    /// Input tokens served from cache, billed at a fraction of full rate.
    pub cache_read_tokens: u64,
}

impl Usage {
    /// Usage for one turn.
    pub const fn new(input_tokens: u64, output_tokens: u64, cache_read_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
        }
    }

    /// Fold another turn in. Saturating: a budget must not wrap to zero and
    /// hand a runaway loop an unlimited allowance.
    pub fn add(&mut self, other: Usage) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(other.cache_read_tokens);
    }

    /// Every token the turn touched, cached or not.
    pub fn total(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cache_read_tokens)
    }
}

/// Why the model stopped generating.
///
/// The agent loop branches on this and nothing else: [`StopReason::ToolUse`]
/// means run the tools and go round again, everything else means stop. A new
/// variant here is a compile error at every loop, which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The model finished its answer. The loop ends.
    EndTurn,
    /// The model wants tools run. The loop continues.
    ToolUse,
    /// Hit [`LlmRequest::max_tokens`]. The answer is truncated.
    MaxTokens,
    /// Hit a caller-supplied stop sequence.
    StopSequence,
    /// The model declined. Not an error: a 200 with nothing usable in it.
    Refusal,
}

impl StopReason {
    /// Whether the agent loop should run tools and call again.
    pub fn wants_tools(&self) -> bool {
        matches!(self, Self::ToolUse)
    }

    /// Low-cardinality metric label.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EndTurn => "end_turn",
            Self::ToolUse => "tool_use",
            Self::MaxTokens => "max_tokens",
            Self::StopSequence => "stop_sequence",
            Self::Refusal => "refusal",
        }
    }
}

/// One turn back from the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmResponse {
    /// The assistant turn's blocks, in order.
    pub content: Vec<Content>,
    /// Why generation ended.
    pub stop_reason: StopReason,
    /// What this turn cost.
    pub usage: Usage,
}

impl LlmResponse {
    /// A plain text answer that ends the loop.
    pub fn text(text: impl Into<String>, usage: Usage) -> Self {
        Self {
            content: vec![Content::text(text)],
            stop_reason: StopReason::EndTurn,
            usage,
        }
    }

    /// A turn that asks for one tool and continues the loop.
    pub fn tool_use(
        id: impl Into<String>,
        name: impl Into<String>,
        input: Value,
        usage: Usage,
    ) -> Self {
        Self {
            content: vec![Content::tool_use(id, name, input)],
            stop_reason: StopReason::ToolUse,
            usage,
        }
    }

    /// The tool calls in this turn, in order.
    pub fn tool_uses(&self) -> impl Iterator<Item = &Content> {
        self.content
            .iter()
            .filter(|block| matches!(block, Content::ToolUse { .. }))
    }
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// One turn of inference.
///
/// Deliberately single-shot: the agent loop, the budget and the termination
/// rule live above this trait, where they can be tested without a network.
#[async_trait]
pub trait Llm: Send + Sync {
    /// Run one turn.
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, ProviderError>;
}

// ---------------------------------------------------------------------------
// Scripted mock
// ---------------------------------------------------------------------------

/// A model that replays a fixed sequence of turns.
///
/// See the module docs for why this, and not a canned single response, is what
/// the agent runtime is tested against.
#[derive(Debug)]
pub struct ScriptedLlm {
    script: Vec<Result<LlmResponse, ProviderError>>,
    looping: bool,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    cursor: usize,
    calls: usize,
    usage: Usage,
    requests: Vec<LlmRequest>,
}

impl ScriptedLlm {
    /// Replay `script` in order, then fail every further call.
    ///
    /// The failure is [`ProviderError::Terminal`] with code
    /// `script_exhausted`: an over-running loop should break the test at the
    /// call that over-ran, not somewhere downstream.
    pub fn new(script: Vec<Result<LlmResponse, ProviderError>>) -> Self {
        Self {
            script,
            looping: false,
            state: Mutex::new(State::default()),
        }
    }

    /// Replay `script` forever, wrapping round at the end.
    ///
    /// With a single [`StopReason::ToolUse`] turn this is the never-terminating
    /// model: the loop only ends if something above the model ends it.
    pub fn looping(script: Vec<Result<LlmResponse, ProviderError>>) -> Self {
        Self {
            script,
            looping: true,
            state: Mutex::new(State::default()),
        }
    }

    /// Convenience for the common all-successful script.
    pub fn responses(responses: Vec<LlmResponse>) -> Self {
        Self::new(responses.into_iter().map(Ok).collect())
    }

    /// Error the exhausted script returns.
    pub const EXHAUSTED: ProviderError = ProviderError::Terminal {
        code: "script_exhausted",
    };

    /// How many times [`Llm::complete`] has been called.
    pub fn calls(&self) -> usize {
        self.lock().calls
    }

    /// Usage accumulated across every successful turn so far.
    pub fn usage(&self) -> Usage {
        self.lock().usage
    }

    /// Every request received, in order — for asserting on prompt assembly.
    pub fn requests(&self) -> Vec<LlmRequest> {
        self.lock().requests.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl Llm for ScriptedLlm {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, ProviderError> {
        let mut state = self.lock();
        state.calls += 1;
        state.requests.push(req);

        if state.cursor >= self.script.len() {
            if !self.looping || self.script.is_empty() {
                return Err(Self::EXHAUSTED);
            }
            state.cursor = 0;
        }

        let turn = self.script[state.cursor].clone();
        state.cursor += 1;
        if let Ok(response) = &turn {
            state.usage.add(response.usage);
        }
        turn
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn req() -> LlmRequest {
        LlmRequest::new("claude-opus-5", "you are lena", 1024).with_message(Message::user("hi"))
    }

    fn turn(n: u64) -> LlmResponse {
        LlmResponse::tool_use(
            format!("toolu_{n}"),
            "search",
            json!({ "q": n }),
            Usage::new(10, 5, 2),
        )
    }

    #[tokio::test]
    async fn the_script_replays_in_order_then_refuses() {
        let llm = ScriptedLlm::responses(vec![
            turn(1),
            turn(2),
            LlmResponse::text("done", Usage::new(30, 4, 90)),
        ]);

        let first = llm.complete(req()).await.unwrap();
        assert_eq!(first, turn(1));
        assert!(first.stop_reason.wants_tools());

        assert_eq!(llm.complete(req()).await.unwrap(), turn(2));

        let last = llm.complete(req()).await.unwrap();
        assert_eq!(last.stop_reason, StopReason::EndTurn);
        assert!(!last.stop_reason.wants_tools());

        // One turn past the end of the script.
        assert_eq!(llm.complete(req()).await, Err(ScriptedLlm::EXHAUSTED));
        assert_eq!(ScriptedLlm::EXHAUSTED.code(), "script_exhausted");
        assert_eq!(llm.calls(), 4);
    }

    #[tokio::test]
    async fn usage_accumulates_across_turns() {
        let llm = ScriptedLlm::responses(vec![turn(1), turn(2), turn(3)]);
        assert_eq!(llm.usage(), Usage::default());

        for expected in 1..=3u64 {
            llm.complete(req()).await.unwrap();
            assert_eq!(
                llm.usage(),
                Usage::new(10 * expected, 5 * expected, 2 * expected)
            );
        }

        // The failed fourth call adds nothing.
        assert!(llm.complete(req()).await.is_err());
        assert_eq!(llm.usage(), Usage::new(30, 15, 6));
        assert_eq!(llm.usage().total(), 51);
    }

    #[tokio::test]
    async fn a_looping_script_never_terminates_on_its_own() {
        // A model that asks for a tool, forever. Only a budget stops this.
        let llm = ScriptedLlm::looping(vec![Ok(turn(1))]);

        let mut budget = 0u64;
        let mut turns = 0;
        while budget < 100 {
            let response = llm.complete(req()).await.unwrap();
            assert!(
                response.stop_reason.wants_tools(),
                "the model never volunteers to stop"
            );
            budget += response.usage.total();
            turns += 1;
        }

        assert_eq!(turns, 6); // 17 tokens a turn
        assert_eq!(llm.usage(), Usage::new(60, 30, 12));
        // And it would have kept going.
        assert!(llm.complete(req()).await.is_ok());
    }

    #[tokio::test]
    async fn scripted_errors_replay_too() {
        let llm = ScriptedLlm::new(vec![
            Err(ProviderError::from_status(429, None)),
            Ok(LlmResponse::text("ok", Usage::new(1, 1, 0))),
        ]);

        let err = llm.complete(req()).await.unwrap_err();
        assert!(err.is_retryable());
        assert!(llm.complete(req()).await.is_ok());
        // The failed turn cost nothing.
        assert_eq!(llm.usage(), Usage::new(1, 1, 0));
    }

    #[tokio::test]
    async fn requests_are_recorded_for_prompt_assertions() {
        let llm = ScriptedLlm::responses(vec![LlmResponse::text("ok", Usage::default())]);
        let request = req()
            .with_tools(vec![ToolDef {
                name: "search".into(),
                description: "search the web".into(),
                input_schema: json!({ "type": "object" }),
            }])
            .cache_here();

        llm.complete(request.clone()).await.unwrap();

        assert_eq!(llm.requests(), vec![request]);
        assert_eq!(llm.requests()[0].cache_breakpoint, Some(0));
    }

    #[test]
    fn cache_here_marks_the_prefix_and_survives_an_empty_history() {
        let empty = LlmRequest::new("m", "s", 16).cache_here();
        assert_eq!(empty.cache_breakpoint, None);

        let two = LlmRequest::new("m", "s", 16)
            .with_message(Message::user("a"))
            .with_message(Message::assistant("b"))
            .cache_here()
            .with_message(Message::user("c"));
        assert_eq!(two.cache_breakpoint, Some(1));
        assert_eq!(two.messages.len(), 3);
    }

    #[test]
    fn a_tool_turn_round_trips_through_serde() {
        let response = LlmResponse {
            content: vec![
                Content::text("let me look"),
                Content::tool_use("toolu_1", "search", json!({ "q": "lena" })),
            ],
            stop_reason: StopReason::ToolUse,
            usage: Usage::new(120, 34, 4096),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["stop_reason"], "tool_use");
        assert_eq!(json["content"][1]["type"], "tool_use");
        assert_eq!(json["usage"]["cache_read_tokens"], 4096);
        assert_eq!(
            serde_json::from_value::<LlmResponse>(json).unwrap(),
            response
        );

        assert_eq!(response.tool_uses().count(), 1);
    }

    #[test]
    fn usage_saturates_rather_than_wrapping() {
        let mut usage = Usage::new(u64::MAX, 0, 0);
        usage.add(Usage::new(10, 0, 0));
        assert_eq!(usage.input_tokens, u64::MAX);
        assert_eq!(usage.total(), u64::MAX);
    }

    #[test]
    fn stop_reason_codes_are_distinct() {
        let all = [
            StopReason::EndTurn,
            StopReason::ToolUse,
            StopReason::MaxTokens,
            StopReason::StopSequence,
            StopReason::Refusal,
        ];
        let codes: std::collections::HashSet<&str> = all.iter().map(|s| s.code()).collect();
        assert_eq!(codes.len(), all.len());
        assert!(all.iter().filter(|s| s.wants_tools()).count() == 1);
    }
}
