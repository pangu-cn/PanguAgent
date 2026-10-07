//! MCP stdio transport: spawn a server process and speak JSON-RPC over its
//! stdin/stdout.
//!
//! # Why this is bounded and supervised
//!
//! A stdio MCP server is an arbitrary program the operator configures. This
//! module's job is to make that fact survivable rather than to pretend it away:
//!
//! - The command comes from configuration, never from the model. The model can
//!   call tools on a server already running; it cannot start one.
//! - stdout is read line by line with a **bounded** size. A server that never
//!   emits a newline cannot exhaust memory.
//! - Every read is bounded by a deadline. A hung server fails the call instead
//!   of hanging the run.
//! - stderr is drained concurrently and kept bounded. A server that fills its
//!   stderr pipe would otherwise block on write while we wait on stdout, which
//!   looks exactly like a deadlock.
//! - The child is killed on drop. A leaked server process outlives the run that
//!   spawned it and keeps whatever access it was given.
//!
//! # What this does not do
//!
//! It does not sandbox the server, restrict its filesystem or network access,
//! or verify that it does what its name suggests. Pangu cannot confine an
//! arbitrary child process from inside itself; the honest position is that an
//! MCP server runs with the privileges Pangu has, which is why the declaration
//! is an operator decision and why its tools are mapped to capabilities
//! explicitly. See `crates/pangu`'s config validation for the operator-facing
//! contract.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use anyhow::{anyhow, Result};
use pangu_core::mcp::{
    initialise_params, read_server_info, read_tools, IdAllocator, Incoming, McpTool, Request,
    ServerInfo,
};

/// Upper bound on one JSON-RPC frame from a server.
///
/// A tool result is not a payload Pangu wants unbounded: it is read into memory
/// to be parsed, then bounded again before it reaches the model. 8 MiB is far
/// above a text tool result and far below anything that threatens the run.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// How much server stderr to retain for diagnostics.
pub const MAX_STDERR_BYTES: usize = 16 * 1024;

/// A running MCP server, spoken to over stdio.
pub struct StdioServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    ids: IdAllocator,
    /// Most recent stderr lines, for diagnosing a failure. Bounded.
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    stderr_bytes: Arc<std::sync::atomic::AtomicUsize>,
    server: Option<ServerInfo>,
    /// Human-readable description of the command, for error messages. The
    /// command itself is not included: it may embed a token.
    label: String,
}

impl std::fmt::Debug for StdioServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioServer")
            .field("label", &self.label)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl StdioServer {
    /// Spawn a server and complete the MCP handshake.
    pub async fn start(
        label: &str,
        program: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&std::path::Path>,
        timeouts: pangu_core::mcp::McpTimeouts,
    ) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A server inherits nothing by default: an inherited environment can
            // carry provider keys and tokens that the server was never meant to
            // see. Only explicitly configured variables are passed.
            .env_clear();
        for (key, value) in env {
            command.env(key, value);
        }
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        // Kill the child if this handle is dropped, so a leaked server cannot
        // outlive the run with the access it was given.
        command.kill_on_drop(true);

        let mut child = command.spawn().map_err(|error| {
            anyhow!(format!(
                "MCP server `{label}` could not be started: {error}"
            ))
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!(format!("MCP server `{label}` has no stdin pipe")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!(format!("MCP server `{label}` has no stdout pipe")))?;

        let stderr_tail = Arc::new(Mutex::new(VecDeque::new()));
        let stderr_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        if let Some(stderr) = child.stderr.take() {
            let tail = Arc::clone(&stderr_tail);
            let count = Arc::clone(&stderr_bytes);
            // Drained concurrently and bounded. Left unread, a chatty server
            // fills the pipe and blocks on write, which presents as a hang.
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    count.fetch_add(line.len() + 1, std::sync::atomic::Ordering::Relaxed);
                    let mut guard = tail.lock().await;
                    if guard.len() >= 200 {
                        guard.pop_front();
                    }
                    guard.push_back(redact(&line));
                }
            });
        }

        let mut server = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            ids: IdAllocator::new(),
            stderr_tail,
            stderr_bytes,
            server: None,
            label: label.to_string(),
        };

        // Keep the server's reported identity: the operator needs to know what
        // answered, and a revision mismatch must be visible rather than only
        // affecting behaviour silently.
        let info = server
            .call("initialize", Some(initialise_params()), timeouts.handshake)
            .await
            .map_err(|error| server.enrich(error))
            .and_then(|value| {
                read_server_info(&value).map_err(|error| server.enrich(anyhow!(error.to_string())))
            })?;
        server.server = Some(info);

        // `notifications/initialized` completes the handshake. It is a
        // notification: no id, no reply expected.
        server
            .notify("notifications/initialized", None)
            .await
            .map_err(|error| server.enrich(error))?;

        Ok(server)
    }

    /// The server's reported identity, once the handshake completed.
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.server.as_ref()
    }

    /// This server's tools.
    pub async fn list_tools(&mut self, timeout: Duration) -> Result<Vec<McpTool>> {
        let value = self
            .call("tools/list", None, timeout)
            .await
            .map_err(|error| self.enrich(error))?;
        read_tools(&value).map_err(|error| self.enrich(anyhow!(error.to_string())))
    }

    /// Call one tool by its server-local name.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value> {
        let params = serde_json::json!({ "name": name, "arguments": arguments });
        self.call("tools/call", Some(params), timeout)
            .await
            .map_err(|error| self.enrich(error))
    }

    async fn notify(&mut self, method: &str, params: Option<serde_json::Value>) -> Result<()> {
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&frame)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Send a request and await its response, skipping notifications.
    async fn call(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
        timeout: Duration,
    ) -> Result<serde_json::Value> {
        let id = self.ids.next();
        let request = Request::new(id.clone(), method, params);
        let mut line = request.to_line()?;
        line.push('\n');

        tokio::time::timeout(timeout, self.stdin.write_all(line.as_bytes()))
            .await
            .map_err(|_| {
                anyhow!(format!(
                    "writing `{method}` to MCP server `{}` timed out after {timeout:?}",
                    self.label
                ))
            })??;
        self.stdin.flush().await?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(format!(
                    "MCP server `{}` did not answer `{method}` within {timeout:?}",
                    self.label
                )));
            }
            let frame = tokio::time::timeout(remaining, self.read_frame())
                .await
                .map_err(|_| {
                    anyhow!(format!(
                        "MCP server `{}` did not answer `{method}` within {timeout:?}",
                        self.label
                    ))
                })??;
            let Some(frame) = frame else {
                // EOF before the answer: the server exited.
                return Err(anyhow!(format!(
                    "MCP server `{}` closed its output while answering `{method}`",
                    self.label
                )));
            };
            match Incoming::parse(&frame)? {
                Incoming::Notification { .. } => continue,
                Incoming::Response { id: got, .. } => {
                    if got != id {
                        // A response to a different request would be a
                        // correlation bug; treating it as ours could attribute
                        // one tool's output to another.
                        return Err(anyhow!(format!(
                            "MCP server `{}` answered id {got} while `{method}` awaited id {id}",
                            self.label
                        )));
                    }
                    // `into_result` speaks the core crate's error type; this
                    // crate reports anyhow, so the conversion is explicit.
                    return Incoming::parse(&frame)?
                        .into_result()
                        .map_err(|error| anyhow!(error.to_string()));
                }
            }
        }
    }

    /// Read one newline-delimited frame, bounded in size.
    async fn read_frame(&mut self) -> Result<Option<String>> {
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let read = tokio::io::AsyncReadExt::read(&mut self.stdout, &mut byte).await?;
            if read == 0 {
                return if buffer.is_empty() {
                    Ok(None)
                } else {
                    // An unterminated final frame is not valid line-delimited
                    // JSON-RPC; accepting it would parse a truncated message.
                    Err(anyhow!(format!(
                        "MCP server `{}` ended output mid-frame",
                        self.label
                    )))
                };
            }
            if buffer.len() >= MAX_FRAME_BYTES {
                return Err(anyhow!(format!(
                    "MCP server `{}` sent a frame larger than {MAX_FRAME_BYTES} bytes",
                    self.label
                )));
            }
            if byte[0] == b'\n' {
                let text = String::from_utf8(buffer).map_err(|error| {
                    anyhow!(format!(
                        "MCP server `{}` sent output that is not UTF-8: {error}",
                        self.label
                    ))
                })?;
                let trimmed = text.trim_end_matches('\r').trim();
                if trimmed.is_empty() {
                    // A blank line is not a frame; keep reading rather than
                    // failing a well-behaved server that pads its output.
                    buffer = Vec::new();
                    continue;
                }
                return Ok(Some(trimmed.to_string()));
            }
            buffer.push(byte[0]);
        }
    }

    /// Attach recent server stderr to an error, so a failure explains itself.
    fn enrich(&self, error: anyhow::Error) -> anyhow::Error {
        let tail = self
            .stderr_tail
            .try_lock()
            .map(|guard| guard.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if tail.is_empty() {
            return error;
        }
        let joined = tail.join(" | ");
        anyhow!(format!("{error} (server stderr: {joined})"))
    }

    /// Whether the child process has exited.
    pub fn has_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Total bytes the server has written to stderr, and the retained tail.
    ///
    /// Exposed because a chatty server is a real operational signal: the tail
    /// alone cannot distinguish "quiet" from "wrote 400 MB that we discarded",
    /// and the second case means the drain is doing real work.
    pub fn stderr_report(&self) -> (usize, Vec<String>) {
        let total = self.stderr_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let tail = self
            .stderr_tail
            .try_lock()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default();
        (total, tail)
    }

    /// Stop the server and reap it.
    pub async fn shutdown(&mut self) {
        // Closing stdin is the polite signal; a server that ignores it is
        // killed rather than waited on forever.
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}

/// Remove likely secrets from a server's stderr before it is shown.
///
/// A server is free to print its environment, and its environment is exactly
/// where configured tokens live. Diagnostics must not become a credential leak.
///
/// The rule: after a sensitive **name** (`token=`, `Authorization:`), redact the
/// value that follows. An `Authorization` header is the common shape
/// `Authorization: Bearer <token>`, where the secret is the *second* word — so a
/// single scheme word (`Bearer`, `Basic`) is skipped rather than redacted, and
/// the credential after it is what gets removed. Redacting only `Bearer` and
/// leaving the token would look like redaction while leaking the secret, which
/// is worse than not redacting at all.
fn redact(line: &str) -> String {
    /// Words that name an auth scheme rather than carrying the secret.
    const SCHEMES: &[&str] = &["bearer", "basic", "digest", "token", "apikey", "api-key"];

    let lower = line.to_lowercase();
    // Tokens are replaced by byte range, collected then applied in reverse so
    // earlier offsets stay valid.
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    for marker in [
        "token",
        "key",
        "secret",
        "password",
        "authorization",
        "apikey",
    ] {
        let mut from = 0;
        while let Some(offset) = lower[from..].find(marker) {
            let at = from + offset;
            from = at + marker.len();

            // Find the separator that ends the name part.
            let rest = &line[from..];
            let Some(sep) = rest.find(['=', ':', ' ']) else {
                continue;
            };
            let mut cursor = from + sep;
            // Step over separators and whitespace to reach the value.
            while cursor < line.len() {
                let ch = line[cursor..].chars().next().unwrap();
                if ch == '=' || ch == ':' || ch.is_whitespace() || ch == '"' || ch == '\'' {
                    cursor += ch.len_utf8();
                } else {
                    break;
                }
            }
            // Read one word.
            let value_start = cursor;
            let mut value_end = value_start;
            for ch in line[value_start..].chars() {
                if ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',' || ch == ';' {
                    break;
                }
                value_end += ch.len_utf8();
            }
            if value_end <= value_start {
                continue;
            }
            let word = &line[value_start..value_end];

            // `Authorization: Bearer <token>`: skip the scheme, redact the
            // credential that follows it.
            if SCHEMES.contains(&word.to_lowercase().as_str()) {
                let mut next = value_end;
                while next < line.len() {
                    let ch = line[next..].chars().next().unwrap();
                    if ch.is_whitespace() || ch == '"' || ch == '\'' {
                        next += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                let next_start = next;
                let mut next_end = next_start;
                for ch in line[next_start..].chars() {
                    if ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',' || ch == ';' {
                        break;
                    }
                    next_end += ch.len_utf8();
                }
                if next_end > next_start {
                    ranges.push((next_start, next_end));
                }
                continue;
            }

            ranges.push((value_start, value_end));
        }
    }

    // Apply from the end so earlier offsets remain valid.
    ranges.sort_unstable();
    ranges.dedup();
    let mut text = line.to_string();
    for (start, end) in ranges.into_iter().rev() {
        if end <= text.len() && start < end {
            text.replace_range(start..end, "[redacted]");
        }
    }

    // Bound the retained line: a server can print one enormous line.
    if text.len() > 512 {
        let mut end = 512;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_value_is_redacted() {
        let text = redact("connecting with token=abc123secret to host");
        assert!(text.contains("[redacted]"), "{text}");
        assert!(!text.contains("abc123secret"), "{text}");
    }

    #[test]
    fn an_authorization_header_is_redacted() {
        let text = redact("Authorization: Bearer xyzzy");
        assert!(!text.contains("xyzzy"), "{text}");
    }

    #[test]
    fn an_ordinary_line_is_untouched() {
        let text = redact("server listening on stdio");
        assert_eq!(text, "server listening on stdio");
    }

    #[test]
    fn an_overlong_stderr_line_is_bounded() {
        let text = redact(&"x".repeat(5000));
        assert!(text.len() <= 520, "{}", text.len());
    }

    #[test]
    fn redaction_terminates_on_pathological_input() {
        // Must not loop forever on repeated markers.
        let text = redact("key=key=key=key=key");
        assert!(!text.is_empty());
    }

    #[test]
    fn an_api_key_in_json_is_redacted() {
        let text = redact(r#"{"apiKey": "sk-live-abcdef123456"}"#);
        assert!(!text.contains("sk-live-abcdef123456"), "{text}");
        assert!(text.contains("[redacted]"), "{text}");
    }

    #[test]
    fn a_password_assignment_is_redacted() {
        let text = redact("connecting db password=hunter2 host=localhost");
        assert!(!text.contains("hunter2"), "{text}");
        // The rest of the line survives: redaction must not destroy diagnostics.
        assert!(text.contains("host=localhost"), "{text}");
    }

    #[test]
    fn a_basic_auth_header_redacts_the_credential_not_the_scheme() {
        let text = redact("Authorization: Basic dXNlcjpwYXNz");
        assert!(!text.contains("dXNlcjpwYXNz"), "{text}");
        // Redacting only the scheme word would look like redaction while
        // leaving the actual credential in place.
        assert!(!text.contains("Basic dXNlcjpwYXNz"), "{text}");
    }

    #[test]
    fn redacting_the_scheme_only_would_leak_the_token() {
        // Guards the specific regression: `Authorization: Bearer xyzzy` must
        // not leave `xyzzy` behind.
        let text = redact("Authorization: Bearer xyzzy");
        assert!(
            !text.contains("xyzzy"),
            "the credential must be removed, not the scheme: {text}"
        );
    }

    #[test]
    fn multiple_secrets_on_one_line_are_all_redacted() {
        let text = redact("token=aaa battery=low secret=bbb");
        assert!(!text.contains("aaa"), "{text}");
        assert!(!text.contains("bbb"), "{text}");
        assert!(
            text.contains("battery=low"),
            "unrelated fields survive: {text}"
        );
    }
}
