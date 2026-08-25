//! A **testing** [`Llm`] backend that shells out to the local `claude` CLI.
//!
//! This exists for one reason: to let someone run the whole employee OS end to
//! end without an Anthropic API key, using the `claude` binary they already
//! have logged in on their machine. It is not the production path — that is
//! [`crate::llm_anthropic`], a direct `POST /v1/messages` client — and it is
//! lossier in ways that matter:
//!
//! * **Tool calls are a shim.** The CLI does not expose structured `tool_use`
//!   blocks to its caller, so when [`LlmRequest::tools`] is non-empty this
//!   adapter renders the schemas into the prompt and demands a strict JSON
//!   reply, then re-inflates that into [`Content::ToolUse`]. A model that
//!   answers with prose instead gets you `cli_not_json`, not a tool call. The
//!   real adapter has none of this guesswork.
//! * **Caching is not ours.** [`LlmRequest::cache_breakpoint`] is ignored; the
//!   CLI manages its own prefix cache. `cache_read_tokens` is whatever the CLI
//!   reports, which is dominated by its own system prompt, so cost numbers from
//!   this backend do not resemble production ones.
//! * **One turn, no history reuse.** Every call is a fresh `claude -p`; the
//!   conversation is re-rendered as text each time.
//!
//! # What it deliberately does
//!
//! The prompt goes in on **stdin**, never argv. A prompt is attacker-influenced
//! text (a customer email is in there); as an argument, one starting with `--`
//! is a flag, and there is no shell string to quote wrong because we spawn the
//! program directly with [`tokio::process::Command`].
//!
//! Everything is bounded by [`CliLlm::DEFAULT_TIMEOUT`] and the child is killed
//! on drop, so a wedged CLI costs one turn, not a worker forever.
//!
//! # `--allowed-tools ""` does **not** disable the CLI's own tools
//!
//! This module used to claim it did, and `agentos_eval::dryrun` measured the
//! claim against `claude` 2.1.231 on 2026-08-26. It is false, twice over:
//!
//! * The session's `system`/`init` event listed **122 tools and 18 MCP
//!   servers**. `--allowed-tools` is an auto-approve list, not a registration
//!   list, so an empty one approves nothing and *withholds* nothing.
//! * Asked to read a file, the CLI called `Read` and returned the file's
//!   contents, with `permission_denials: []`. Naming the built-ins in
//!   `--disallowed-tools` does not close it either — the model reached for
//!   `ToolSearch` instead, and enumerating a moving list of 122 names is not a
//!   fix.
//!
//! So this adapter runs the prompt — which contains a counterparty's text —
//! through an agent that has file and shell tools on the operator's host. That
//! is why this backend is for a workstation and never for a deployment, and it
//! is a second reason on top of the lossiness above.
//!
//! **It is also the most common way a turn dies.** When the CLI's own agent
//! loop calls one of those tools, `--max-turns 1` ends the session as
//! `subtype: error_max_turns`, `is_error: true`, **exit 1** — so this adapter
//! reports `cli_failed`, `Turn::run` raises `TurnError::Llm`, and the whole
//! employee turn is lost with no reply. The dry run saw it on 2 of 9 turns.
//!
//! Closing it properly is an interface change, not a flag: `--system-prompt`
//! for [`LlmRequest::system`] (which would also stop the employee arguing with
//! Claude Code's own identity — see the dry run's transcripts), plus
//! `--strict-mcp-config` and `--setting-sources`, which together move the
//! `--live` numbers and need the digests in `agentos_eval::toolchoice`
//! re-pinned.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::ProviderError;
use crate::llm::{Content, Llm, LlmRequest, LlmResponse, Role, StopReason, Usage};

/// An [`Llm`] backed by the local `claude` CLI. See the module docs — testing
/// only.
#[derive(Debug, Clone)]
pub struct CliLlm {
    program: PathBuf,
    timeout: Duration,
}

impl Default for CliLlm {
    fn default() -> Self {
        Self::new()
    }
}

impl CliLlm {
    /// How long one turn may take before the child is killed.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

    /// Use `claude` from `PATH`.
    pub fn new() -> Self {
        Self {
            program: PathBuf::from("claude"),
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Point at a specific binary — an absolute path in production-ish setups,
    /// a fake script in tests.
    #[must_use]
    pub fn with_program(mut self, program: impl AsRef<Path>) -> Self {
        self.program = program.as_ref().to_path_buf();
        self
    }

    /// Override [`Self::DEFAULT_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Spawn the CLI, feed it `prompt` on stdin, and return raw stdout.
    async fn run(&self, model: &str, prompt: &str) -> Result<String, ProviderError> {
        let mut child = Command::new(&self.program)
            .arg("-p")
            .args(["--output-format", "json"])
            .args(["--model", model])
            // Intended as "no Read, no Bash, no Edit". It is not: see this
            // module's header — an empty allow-list approves nothing and
            // withholds nothing, and the CLI reads files anyway. Kept because
            // removing it would change nothing except the record of intent.
            .args(["--allowed-tools", ""])
            .args(["--max-turns", "1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // The one line that makes the timeout below an actual kill.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                tracing::warn!(error = %e, program = ?self.program, "claude CLI would not spawn");
                ProviderError::Terminal {
                    code: "cli_spawn_failed",
                }
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            // EPIPE here just means the child died early; the exit status and
            // the stdout parse below say what actually went wrong.
            let _ = stdin.write_all(prompt.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }

        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(_)) => return Err(ProviderError::Terminal { code: "cli_failed" }),
            // Dropping the future drops the Child, and kill_on_drop reaps it.
            Err(_) => return Err(ProviderError::timeout()),
        };

        if !output.status.success() {
            return Err(ProviderError::Terminal { code: "cli_failed" });
        }
        String::from_utf8(output.stdout).map_err(|_| ProviderError::Terminal {
            code: "cli_bad_output",
        })
    }
}

#[async_trait]
impl Llm for CliLlm {
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, ProviderError> {
        let stdout = self.run(&req.model, &render_prompt(&req)).await?;
        let (text, stop_reason, usage) = parse_result_event(&stdout)?;

        let content = if req.tools.is_empty() {
            vec![Content::text(text)]
        } else {
            bridge_tool_call(&text)?
        };
        let stop_reason = if content.iter().any(|c| matches!(c, Content::ToolUse { .. })) {
            StopReason::ToolUse
        } else {
            stop_reason
        };

        Ok(LlmResponse {
            content,
            stop_reason,
            usage,
        })
    }
}

// ---------------------------------------------------------------------------
// Prompt rendering
// ---------------------------------------------------------------------------

/// Flatten the request into one prompt string.
///
/// The system prompt leads, the conversation follows as labelled sections, and
/// the tool contract is last so it is the freshest instruction in context.
fn render_prompt(req: &LlmRequest) -> String {
    let mut out = String::new();
    if !req.system.is_empty() {
        out.push_str(&req.system);
        out.push_str("\n\n");
    }

    for message in &req.messages {
        out.push_str(match message.role {
            Role::User => "## user\n",
            Role::Assistant => "## assistant\n",
        });
        for block in &message.content {
            match block {
                Content::Text { text } => out.push_str(text),
                Content::ToolUse { id, name, input } => {
                    out.push_str(&format!("[called tool {name} ({id}) with {input}]"));
                }
                Content::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => {
                    let label = if *is_error { "failed" } else { "returned" };
                    out.push_str(&format!("[tool {tool_use_id} {label}: {content}]"));
                }
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !req.tools.is_empty() {
        out.push_str(TOOL_CONTRACT);
        for tool in &req.tools {
            out.push_str(&format!(
                "\n- name: {}\n  description: {}\n  input_schema: {}\n",
                tool.name, tool.description, tool.input_schema
            ));
        }
    }
    out
}

/// The whole tool shim, in prose. The CLI gives us no structured `tool_use`, so
/// this is the wire format.
const TOOL_CONTRACT: &str = "\
## reply format
Reply with a single JSON object and nothing else — no prose, no markdown fence.
To call a tool: {\"tool\": \"<name>\", \"input\": { ... }}
To answer instead: {\"tool\": null, \"text\": \"<your answer>\"}

## tools
";

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Pull the `result` event out of the CLI's event array.
///
/// stdout is a JSON *array* of events (`system`, `assistant`, `rate_limit_event`,
/// …); the last `result` one carries the answer, the usage and the stop reason.
fn parse_result_event(stdout: &str) -> Result<(String, StopReason, Usage), ProviderError> {
    const BAD: ProviderError = ProviderError::Terminal {
        code: "cli_bad_output",
    };
    let events: Vec<Value> = serde_json::from_str(stdout).map_err(|_| BAD)?;
    let event = events
        .into_iter()
        .rev()
        .find(|e| e.get("type").and_then(Value::as_str) == Some("result"))
        .ok_or(ProviderError::Terminal {
            code: "cli_no_result",
        })?;

    if event.get("is_error").and_then(Value::as_bool) == Some(true) {
        return Err(ProviderError::Terminal { code: "cli_error" });
    }
    let text = event.get("result").and_then(Value::as_str).ok_or(BAD)?;

    let u = &event["usage"];
    let tokens = |field: &str| u.get(field).and_then(Value::as_u64).unwrap_or(0);
    let usage = Usage::new(
        tokens("input_tokens"),
        tokens("output_tokens"),
        tokens("cache_read_input_tokens"),
    );

    let stop_reason = match event.get("stop_reason").and_then(Value::as_str) {
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("stop_sequence") => StopReason::StopSequence,
        Some("refusal") => StopReason::Refusal,
        // "end_turn", and anything a future CLI invents: the turn is over.
        _ => StopReason::EndTurn,
    };

    Ok((text.to_owned(), stop_reason, usage))
}

/// Re-inflate the strict JSON reply demanded by [`TOOL_CONTRACT`].
///
/// Prose where JSON was required is a clean `cli_not_json` — the shim's failure
/// mode, and the reason this backend is for testing only.
fn bridge_tool_call(text: &str) -> Result<Vec<Content>, ProviderError> {
    const NOT_JSON: ProviderError = ProviderError::Terminal {
        code: "cli_not_json",
    };
    let value: Value = serde_json::from_str(strip_fence(text.trim())).map_err(|_| NOT_JSON)?;

    match value.get("tool").and_then(Value::as_str) {
        Some(name) => Ok(vec![Content::tool_use(
            format!("toolu_cli_{}", uuid::Uuid::now_v7().simple()),
            name,
            value.get("input").cloned().unwrap_or_else(|| json!({})),
        )]),
        None => Ok(vec![Content::text(
            value.get("text").and_then(Value::as_str).ok_or(NOT_JSON)?,
        )]),
    }
}

/// Undo a ```json fence the model wrapped its answer in anyway.
fn strip_fence(text: &str) -> &str {
    let Some(rest) = text.strip_prefix("```") else {
        return text;
    };
    let body = rest.split_once('\n').map_or("", |(_, body)| body);
    body.trim_end().trim_end_matches("```").trim_end()
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use super::*;
    use crate::llm::{Message, ToolDef};

    const EVENTS: &str = r#"[
      {"type":"system","subtype":"init","session_id":"s1"},
      {"type":"assistant","message":{"content":[{"type":"text","text":"OK"}]}},
      {"type":"rate_limit_event","status":"allowed"},
      {"type":"result","subtype":"success","is_error":false,"num_turns":1,
       "session_id":"s1","total_cost_usd":0.112958,"stop_reason":"end_turn","result":"OK",
       "usage":{"input_tokens":2,"output_tokens":4,"cache_creation_input_tokens":10348,
                "cache_read_input_tokens":18736,"service_tier":"standard"}}
    ]"#;

    /// A throwaway dir that takes its contents with it.
    struct Fake(PathBuf);

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl Fake {
        /// Write an executable `/bin/sh` script standing in for `claude`.
        fn new(script: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("agentos-llm-cli-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("claude");
            fs::write(&bin, format!("#!/bin/sh\n{script}\n")).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
            Fake(dir)
        }

        fn llm(&self) -> CliLlm {
            CliLlm::new().with_program(self.0.join("claude"))
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    fn req() -> LlmRequest {
        LlmRequest::new("claude-opus-5", "you are lena", 16000).with_message(Message::user("hi"))
    }

    /// Echo a canned array, ignoring stdin.
    fn echo(payload: &str) -> String {
        format!("cat > /dev/null\ncat <<'JSON_EOF'\n{payload}\nJSON_EOF")
    }

    #[tokio::test]
    async fn the_result_event_is_picked_out_of_the_array() {
        let fake = Fake::new(&echo(EVENTS));
        let response = fake.llm().complete(req()).await.unwrap();

        assert_eq!(response.content, vec![Content::text("OK")]);
        assert_eq!(response.stop_reason, StopReason::EndTurn);
        // cache_read_input_tokens maps across; cache_creation is not ours to bill.
        assert_eq!(response.usage, Usage::new(2, 4, 18736));
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_an_error_not_a_panic() {
        let fake = Fake::new("echo boom >&2\nexit 3");
        assert_eq!(
            fake.llm().complete(req()).await,
            Err(ProviderError::Terminal { code: "cli_failed" })
        );
    }

    #[tokio::test]
    async fn a_missing_binary_is_an_error_not_a_panic() {
        let llm = CliLlm::new().with_program("/nonexistent/claude");
        assert_eq!(
            llm.complete(req()).await,
            Err(ProviderError::Terminal {
                code: "cli_spawn_failed"
            })
        );
    }

    #[tokio::test]
    async fn malformed_stdout_is_a_clean_error() {
        for (script, code) in [
            (echo("this is not json at all"), "cli_bad_output"),
            (echo(r#"{"type":"result","result":"OK"}"#), "cli_bad_output"), // object, not array
            (echo(r#"[{"type":"system"}]"#), "cli_no_result"),
            (
                echo(r#"[{"type":"result","is_error":true,"result":"nope"}]"#),
                "cli_error",
            ),
        ] {
            let fake = Fake::new(&script);
            assert_eq!(
                fake.llm().complete(req()).await,
                Err(ProviderError::Terminal { code }),
                "{script}"
            );
        }
    }

    #[tokio::test]
    async fn a_prompt_starting_with_dashes_is_not_a_flag() {
        let fake = Fake::new(&format!(
            "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\ncat > \"$(dirname \"$0\")/stdin\"\ncat <<'JSON_EOF'\n{EVENTS}\nJSON_EOF"
        ));
        // Quotes, newlines, and a leading `--`: none of it may reach argv.
        let hostile = "--output-format \"evil\"\n--dangerously-skip-permissions";
        let request =
            LlmRequest::new("claude-opus-5", "", 16000).with_message(Message::user(hostile));

        assert!(fake.llm().complete(request).await.is_ok());

        let stdin = fs::read_to_string(fake.path("stdin")).unwrap();
        assert!(
            stdin.contains(hostile),
            "prompt must arrive on stdin: {stdin}"
        );

        let argv = fs::read_to_string(fake.path("argv")).unwrap();
        assert!(
            !argv.contains("dangerously"),
            "prompt text leaked into argv: {argv}"
        );
        // And the flag is on argv. That is *all* this asserts: it is a check on
        // this process, not on the CLI's behaviour, and against `claude`
        // 2.1.231 the CLI ignores it — 122 tools stay live and `Read` runs.
        // See this module's header. Nothing in this file can prove otherwise
        // without the real binary, which is `agentos_eval::dryrun`'s job.
        assert!(argv.contains("--allowed-tools\n\n"), "{argv}");
    }

    #[tokio::test]
    async fn the_timeout_kills_the_child() {
        // The marker is only written if the shell survives its sleep.
        let fake = Fake::new("sleep 5\ntouch \"$(dirname \"$0\")/survived\"");
        let llm = fake.llm().with_timeout(Duration::from_millis(200));

        let started = std::time::Instant::now();
        assert_eq!(llm.complete(req()).await, Err(ProviderError::timeout()));
        assert!(started.elapsed() < Duration::from_secs(2));

        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(
            !fake.path("survived").exists(),
            "child outlived the timeout"
        );
    }

    fn with_tools(req: LlmRequest) -> LlmRequest {
        req.with_tools(vec![ToolDef {
            name: "send_email".into(),
            description: "send an email".into(),
            input_schema: json!({"type": "object", "properties": {"to": {"type": "string"}}}),
        }])
    }

    #[tokio::test]
    async fn a_json_reply_is_bridged_back_into_a_tool_call() {
        let reply = r#"{\"tool\": \"send_email\", \"input\": {\"to\": \"a@b.c\"}}"#;
        let fake = Fake::new(&echo(&format!(
            r#"[{{"type":"result","is_error":false,"stop_reason":"end_turn","result":"{reply}",
                 "usage":{{"input_tokens":7,"output_tokens":9,"cache_read_input_tokens":1}}}}]"#
        )));

        let response = fake.llm().complete(with_tools(req())).await.unwrap();

        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert_eq!(response.usage, Usage::new(7, 9, 1));
        let Some(Content::ToolUse { id, name, input }) = response.content.first() else {
            panic!("expected a tool_use block, got {:?}", response.content);
        };
        assert!(id.starts_with("toolu_cli_"));
        assert_eq!(name, "send_email");
        assert_eq!(input["to"], "a@b.c");
    }

    #[tokio::test]
    async fn prose_where_json_was_required_is_a_clean_error() {
        let fake = Fake::new(&echo(
            r#"[{"type":"result","is_error":false,"result":"Sure! I'll send that email now."}]"#,
        ));
        assert_eq!(
            fake.llm().complete(with_tools(req())).await,
            Err(ProviderError::Terminal {
                code: "cli_not_json"
            })
        );
    }

    #[test]
    fn the_shim_accepts_a_fenced_reply_and_a_plain_answer() {
        let fenced = "```json\n{\"tool\": null, \"text\": \"all done\"}\n```";
        assert_eq!(
            bridge_tool_call(fenced).unwrap(),
            vec![Content::text("all done")]
        );
        // A JSON object that is neither shape is still a clean error.
        assert!(bridge_tool_call("{\"nope\": 1}").is_err());
    }

    #[test]
    fn the_prompt_carries_the_conversation_and_the_tool_contract() {
        let request = with_tools(req().with_message(Message::new(
            Role::Assistant,
            vec![Content::tool_use(
                "toolu_1",
                "send_email",
                json!({"to": "a@b.c"}),
            )],
        )));
        let prompt = render_prompt(&request);

        assert!(prompt.starts_with("you are lena"));
        assert!(prompt.contains("## user\nhi"));
        assert!(prompt.contains("[called tool send_email (toolu_1)"));
        assert!(prompt.contains("input_schema: {"));
        assert!(prompt.contains("{\"tool\": \"<name>\""));

        // No tools, no contract: the shim only exists when it has to.
        assert!(!render_prompt(&req()).contains("reply format"));
    }

    /// Costs money and needs a logged-in CLI. `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "shells out to the real claude binary"]
    async fn the_real_cli_answers() {
        let response = CliLlm::new()
            .complete(
                LlmRequest::new("claude-opus-5", "Reply with exactly: OK", 16000)
                    .with_message(Message::user("say OK")),
            )
            .await
            .unwrap();
        assert_eq!(response.stop_reason, StopReason::EndTurn);
        assert!(response.usage.total() > 0);
    }
}
