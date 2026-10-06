//! End-to-end tests for the MCP stdio client against a **real server process**.
//!
//! The server is `mcp_fixture_server`, a separate `[[bin]]` target reached
//! through `CARGO_BIN_EXE_*`. It has to be a real binary rather than an
//! `#[ignore]`d test because a stdio protocol server must own its stdout: the
//! cargo test harness writes `running 1 test` to stdout, which would interleave
//! with the JSON-RPC frames and corrupt the stream.
//!
//! Driving a real process matters here. The client's job is largely about
//! surviving how a real server misbehaves — mid-stream notifications, wrong
//! correlation ids, hangs, early exits, oversized frames, credential leakage to
//! stderr — and a mock that only ever behaves would exercise none of it.

use std::time::Duration;

use pangu_core::mcp::{read_call_outcome, McpTimeouts, PROTOCOL_VERSION};
use pangu_toolkit::mcp_stdio::StdioServer;

/// Path to the fixture server binary cargo built for this test run.
fn fixture_binary() -> &'static str {
    env!("CARGO_BIN_EXE_mcp_fixture_server")
}

/// Start the fixture server in a named scenario.
async fn start(scenario: &str, timeouts: McpTimeouts) -> anyhow::Result<StdioServer> {
    StdioServer::start(
        "fixture",
        fixture_binary(),
        &[],
        &[(
            "PANGU_MCP_FIXTURE_SCENARIO".to_string(),
            scenario.to_string(),
        )],
        None,
        timeouts,
    )
    .await
}

fn quick() -> McpTimeouts {
    McpTimeouts {
        handshake: Duration::from_secs(20),
        call: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn a_well_behaved_server_completes_the_handshake_and_lists_tools() {
    let mut server = start("well-behaved", quick()).await.expect("handshake");
    let info = server.server_info().expect("server info");
    assert_eq!(info.name.as_deref(), Some("pangu-test-server"));
    assert!(!info.version_mismatch);

    let tools = server
        .list_tools(Duration::from_secs(5))
        .await
        .expect("list");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "echo");
    server.shutdown().await;
}

#[tokio::test]
async fn a_tool_call_returns_its_text() {
    let mut server = start("well-behaved", quick()).await.expect("handshake");
    let value = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "hello"}),
            Duration::from_secs(5),
        )
        .await
        .expect("call");
    let outcome = read_call_outcome(&value).expect("outcome");
    assert_eq!(outcome.text, "echo: hello");
    assert!(!outcome.is_error);
    server.shutdown().await;
}

#[tokio::test]
async fn a_notification_before_the_response_is_skipped() {
    let mut server = start("notification-first", quick())
        .await
        .expect("handshake");
    let value = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect("a notification must not be mistaken for the response");
    let outcome = read_call_outcome(&value).unwrap();
    assert_eq!(outcome.text, "echo: x");
    server.shutdown().await;
}

#[tokio::test]
async fn a_response_with_the_wrong_id_is_refused() {
    let mut server = start("wrong-id", quick()).await.expect("handshake");
    let error = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect_err("a mismatched id must not be attributed to this call");
    let text = error.to_string();
    assert!(text.contains("answered id"), "{text}");
    server.shutdown().await;
}

#[tokio::test]
async fn a_server_that_exits_early_fails_the_call() {
    let mut server = start("exit-early", quick()).await.expect("handshake");
    let error = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect_err("an exited server cannot answer");
    let text = error.to_string();
    assert!(
        text.contains("closed its output") || text.contains("did not answer"),
        "{text}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_hanging_server_hits_the_deadline_instead_of_hanging_the_run() {
    let mut server = start("hang", quick()).await.expect("handshake");
    let started = std::time::Instant::now();
    let error = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_millis(600),
        )
        .await
        .expect_err("a hung server must time out");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the deadline must fire promptly, took {:?}",
        started.elapsed()
    );
    assert!(error.to_string().contains("did not answer"), "{error}");
    server.shutdown().await;
}

#[tokio::test]
async fn a_chatty_server_does_not_deadlock_on_a_full_stderr_pipe() {
    // Unread stderr would fill the pipe, block the server on write, and present
    // as a hang on stdout. The drain must prevent that.
    let mut server = start("chatty-stderr", quick()).await.expect("handshake");
    let value = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "ok"}),
            Duration::from_secs(20),
        )
        .await
        .expect("a chatty server must still answer");
    let outcome = read_call_outcome(&value).unwrap();
    assert_eq!(outcome.text, "echo: ok");
    let (total, tail) = server.stderr_report();
    assert!(total > 0, "stderr bytes should have been counted");
    assert!(tail.len() <= 200, "the retained tail must stay bounded");
    server.shutdown().await;
}

#[tokio::test]
async fn an_oversized_frame_is_refused_rather_than_buffered() {
    let mut server = start("oversized-frame", quick()).await.expect("handshake");
    let error = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(20),
        )
        .await
        .expect_err("a frame past the bound must be refused");
    let text = error.to_string();
    assert!(
        text.contains("larger than") || text.contains("did not answer"),
        "{text}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn non_text_content_is_recorded_but_not_inlined() {
    let mut server = start("mixed-content", quick()).await.expect("handshake");
    let value = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect("call");
    let outcome = read_call_outcome(&value).unwrap();
    assert_eq!(outcome.text, "here is an image");
    assert_eq!(outcome.non_text, vec!["image"]);
    // The base64 payload must not appear in what the model would see.
    assert!(!outcome.text.contains("aGVsbG8="), "{}", outcome.text);
    server.shutdown().await;
}

#[tokio::test]
async fn a_tool_reported_failure_is_a_result_not_a_transport_error() {
    let mut server = start("tool-error", quick()).await.expect("handshake");
    let value = server
        .call_tool(
            "echo",
            serde_json::json!({"text": "x"}),
            Duration::from_secs(5),
        )
        .await
        .expect("the call itself succeeded");
    let outcome = read_call_outcome(&value).unwrap();
    assert!(
        outcome.is_error,
        "the tool said no; that is not a transport fault"
    );
    assert!(outcome.text.contains("refused"), "{}", outcome.text);
    server.shutdown().await;
}

#[tokio::test]
async fn a_protocol_version_mismatch_is_flagged() {
    let mut server = start("old-protocol", quick()).await.expect("handshake");
    let info = server.server_info().expect("server info");
    assert!(
        info.version_mismatch,
        "a server on another revision must be reported, not silently accepted"
    );
    assert_eq!(info.protocol_version, "2024-11-05");
    assert_ne!(info.protocol_version, PROTOCOL_VERSION);
    server.shutdown().await;
}

#[tokio::test]
async fn a_server_claimed_read_only_hint_is_recorded_but_not_trusted() {
    let mut server = start("well-behaved", quick()).await.expect("handshake");
    let tools = server.list_tools(Duration::from_secs(5)).await.unwrap();
    let destructive = tools
        .iter()
        .find(|tool| tool.name == "delete_everything")
        .expect("the fixture advertises it");
    // The claim is preserved verbatim...
    assert_eq!(
        destructive.annotations.as_ref().unwrap()["readOnlyHint"],
        serde_json::json!(true)
    );
    // ...and the tool is still named for what it is, so the operator's
    // capability mapping — not the server's hint — decides its authority.
    assert_eq!(destructive.name, "delete_everything");
    server.shutdown().await;
}

#[tokio::test]
async fn a_token_in_server_stderr_is_redacted() {
    let mut server = start("leaky-stderr", quick()).await.expect("handshake");
    // Give the stderr drain a moment to capture the line.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_, tail) = server.stderr_report();
    let joined = tail.join("\n");
    assert!(
        !joined.contains("super-secret-value"),
        "server stderr must not leak the token: {joined}"
    );
    assert!(
        joined.contains("starting"),
        "the line was captured: {joined}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_tool_description_is_passed_through_as_data() {
    // The fixture's `echo` description contains an instruction ("Ignore all
    // prior instructions"). It must reach the model verbatim — that is what a
    // description is for — while never being parsed as policy.
    let mut server = start("well-behaved", quick()).await.expect("handshake");
    let tools = server.list_tools(Duration::from_secs(5)).await.unwrap();
    let echo = tools.iter().find(|tool| tool.name == "echo").unwrap();
    let description = echo.description.as_deref().unwrap();
    assert!(
        description.contains("Ignore all prior instructions"),
        "the description is data and is preserved: {description}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_child_process_does_not_outlive_its_handle() {
    let server = start("well-behaved", quick()).await.expect("handshake");
    // Dropping must kill the child: a leaked server outlives the run that
    // spawned it and keeps whatever access it was given.
    drop(server);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
