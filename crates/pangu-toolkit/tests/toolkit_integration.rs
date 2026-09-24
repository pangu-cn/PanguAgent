use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use pangu_agent::{Agent, Provider};
use pangu_boundary::{ApprovalMode, Config, GoalContract, Policy, Rule, Sandbox, ScriptedApproval};
use pangu_core::{ChatResponse, EventKind, MemSink, Message, ToolCall, ToolSpec, Usage};
use pangu_toolkit::Toolkit;
use serde_json::json;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct ScriptedProvider {
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Provider for ScriptedProvider {
    fn name(&self) -> &str {
        "toolkit-integration-test"
    }

    fn model(&self) -> &str {
        "toolkit-integration-test-model"
    }

    fn describe(&self) -> String {
        "toolkit integration test provider".into()
    }

    async fn chat(&self, _messages: Vec<Message>, _tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        Ok(self
            .responses
            .lock()
            .expect("provider response lock")
            .pop_front()
            .expect("scripted provider response"))
    }
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "pangu-toolkit-test-{label}-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("create toolkit test workspace");
    root
}

fn response(calls: Vec<ToolCall>) -> ChatResponse {
    ChatResponse {
        messages: vec![Message::assistant_calls("", calls)],
        usage: Usage::default(),
    }
}

fn finish_response() -> ChatResponse {
    response(vec![ToolCall::new("finish", json!({"status": "complete"}))])
}

fn build_agent(
    root: &Path,
    responses: Vec<ChatResponse>,
    max_tool_output_bytes: Option<usize>,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.boundary.max_tool_output_bytes = max_tool_output_bytes.unwrap_or(16 * 1024);
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];

    let contract =
        GoalContract::from_config("toolkit integration test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(responses.into()),
    });
    let approval = Arc::new(ScriptedApproval::new(
        ApprovalMode::DestructiveAndAbove,
        Vec::new(),
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::new()),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, sink)
}

fn assert_no_secret_in_events(sink: &MemSink, secret: &str) {
    assert!(!format!("{:?}", sink.snapshot()).contains(secret));
}

#[tokio::test]
async fn workspace_tools_execute_through_the_verified_action_chain() {
    let root = temp_root("success");
    std::fs::write(root.join("notes.txt"), "needle\nsecond line\n").expect("seed notes");
    std::fs::create_dir(root.join("nested")).expect("create nested directory");
    std::fs::write(root.join("nested/child.txt"), "child\n").expect("seed child");

    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![
                ToolCall::new("read_file", json!({"path": "notes.txt"})),
                ToolCall::new("list_dir", json!({"path": "."})),
                ToolCall::new("search", json!({"path": ".", "query": "needle"})),
                ToolCall::new(
                    "write_file",
                    json!({"path": "created.txt", "content": "needle written\n"}),
                ),
            ]),
            finish_response(),
        ],
        None,
    );

    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert_eq!(outcome.evidence.len(), 4);
    assert_eq!(
        std::fs::read_to_string(root.join("created.txt")).expect("created output"),
        "needle written\n"
    );

    let events = sink.snapshot();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == EventKind::ToolStarted)
            .count(),
        4
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.kind == EventKind::ToolFinished
                    && event
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("ok"))
                        .and_then(|v| v.as_bool())
                        == Some(true)
            })
            .count(),
        4
    );
    assert!(!events
        .iter()
        .any(|event| event.kind == EventKind::ToolBlocked));
    assert!(format!("{:?}", outcome.messages).contains("needle"));

    std::fs::remove_dir_all(root).expect("remove toolkit workspace");
}

#[tokio::test]
async fn traversal_and_forbidden_paths_are_blocked_before_tool_execution() {
    let root = temp_root("blocked-paths");
    let outside = root.with_extension("outside.txt");
    std::fs::write(&outside, "outside-secret").expect("seed outside file");
    std::fs::write(root.join(".env.secret"), "environment-secret").expect("seed forbidden file");

    let outside_name = outside
        .file_name()
        .expect("outside file name")
        .to_string_lossy();
    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![
                ToolCall::new("read_file", json!({"path": format!("../{outside_name}")})),
                ToolCall::new("read_file", json!({"path": ".env.secret"})),
            ]),
            finish_response(),
        ],
        None,
    );

    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(outcome.evidence.is_empty());
    assert!(!format!("{:?}", outcome.messages).contains("outside-secret"));
    assert!(!format!("{:?}", outcome.messages).contains("environment-secret"));
    assert_no_secret_in_events(&sink, "outside-secret");
    assert_no_secret_in_events(&sink, "environment-secret");
    assert!(!sink
        .snapshot()
        .iter()
        .any(|event| event.kind == EventKind::ToolStarted));
    assert!(
        sink.snapshot()
            .iter()
            .filter(|event| event.kind == EventKind::ToolBlocked)
            .count()
            >= 2
    );

    std::fs::remove_file(outside).expect("remove outside file");
    std::fs::remove_dir_all(root).expect("remove toolkit workspace");
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[tokio::test]
async fn symlink_escape_is_blocked_before_tool_execution() {
    let root = temp_root("symlink");
    let outside = root.with_extension("symlink-target.txt");
    let link = root.join("linked.txt");
    std::fs::write(&outside, "symlink-secret").expect("seed symlink target");
    if let Err(error) = create_file_symlink(&outside, &link) {
        if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314) {
            std::fs::remove_file(outside).expect("remove outside file");
            std::fs::remove_dir_all(root).expect("remove toolkit workspace");
            return;
        }
        panic!("failed to create symlink for test: {error}");
    }

    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "read_file",
                json!({"path": "linked.txt"}),
            )]),
            finish_response(),
        ],
        None,
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(!sink
        .snapshot()
        .iter()
        .any(|event| event.kind == EventKind::ToolStarted));
    assert!(sink
        .snapshot()
        .iter()
        .any(|event| event.kind == EventKind::ToolBlocked));
    assert_no_secret_in_events(&sink, "symlink-secret");

    std::fs::remove_file(link).expect("remove symlink");
    std::fs::remove_file(outside).expect("remove outside file");
    std::fs::remove_dir_all(root).expect("remove toolkit workspace");
}

#[tokio::test]
async fn output_limit_failure_cannot_create_evidence() {
    let root = temp_root("output-limit");
    std::fs::write(root.join("large.txt"), "x".repeat(512)).expect("seed large file");

    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "read_file",
                json!({"path": "large.txt"}),
            )]),
            finish_response(),
        ],
        Some(256),
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(outcome.evidence.is_empty());
    assert!(sink.snapshot().iter().any(|event| {
        event.kind == EventKind::ToolFinished
            && event
                .payload
                .as_ref()
                .and_then(|payload| payload.get("ok"))
                .and_then(|value| value.as_bool())
                == Some(false)
    }));

    std::fs::remove_dir_all(root).expect("remove toolkit workspace");
}
