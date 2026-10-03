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
async fn git_diff_reports_the_workspace_diff_through_the_verified_action_chain() {
    let root = temp_root("git-diff");
    let git_available = std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !git_available {
        return;
    }
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .expect("git init");
    std::fs::write(
        root.join("tracked.txt"),
        "before
",
    )
    .expect("seed");
    for args in [
        vec!["add", "tracked.txt"],
        vec![
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        ],
    ] {
        assert!(std::process::Command::new("git")
            .args(&args)
            .current_dir(&root)
            .status()
            .expect("git")
            .success());
    }
    std::fs::write(
        root.join("tracked.txt"),
        "after
",
    )
    .expect("modify");

    let (agent, _sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "git_diff",
                json!({"path": "tracked.txt"}),
            )]),
            finish_response(),
        ],
        None,
    );

    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert_eq!(outcome.evidence.len(), 1);
    let tool_text = outcome
        .messages
        .iter()
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool message");
    assert!(tool_text.contains("-before"), "tool output: {tool_text}");
    assert!(tool_text.contains("+after"), "tool output: {tool_text}");
    std::fs::remove_dir_all(root).expect("cleanup");
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

/// F3: a verify harness. The command comes from the config, the approval
/// handler allows (verify is NeedsHuman, so it always reaches L4), and the
/// toolkit must advertise exactly the contract-frozen argv.
fn build_verify_agent(
    root: &Path,
    responses: Vec<ChatResponse>,
    verify_command: Vec<String>,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.verify.command = verify_command.clone();

    let contract =
        GoalContract::from_config("verify integration test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(responses.into()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::with_verify_command(verify_command)),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, sink)
}

fn git_ready() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn git(root: &Path, args: &[&str]) {
    assert!(
        std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .expect("git")
            .success(),
        "git {args:?} failed"
    );
}

#[tokio::test]
async fn verify_runs_the_configured_command_and_yields_evidence() {
    if !git_ready() {
        return;
    }
    let root = temp_root("verify-ok");
    git(&root, &["init", "-q"]);
    std::fs::write(root.join("sample.txt"), "before\n").expect("seed");
    git(&root, &["add", "sample.txt"]);
    git(
        &root,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "init",
        ],
    );
    std::fs::write(root.join("sample.txt"), "after\n").expect("modify");

    let (agent, _sink) = build_verify_agent(
        &root,
        vec![
            response(vec![ToolCall::new("verify", json!({}))]),
            finish_response(),
        ],
        vec!["git".into(), "status".into(), "--porcelain".into()],
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert_eq!(outcome.evidence.len(), 1);
    assert!(
        outcome.evidence[0].starts_with("verify:"),
        "evidence tag: {:?}",
        outcome.evidence[0]
    );
    let tool_text = outcome
        .messages
        .iter()
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool message");
    assert!(
        tool_text.contains("M sample.txt"),
        "tool output: {tool_text}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn failing_verify_cannot_create_evidence_or_complete() {
    if !git_ready() {
        return;
    }
    let root = temp_root("verify-fail");
    // A repository with no commits: `git log` fails deterministically.
    git(&root, &["init", "-q"]);

    let (agent, sink) = build_verify_agent(
        &root,
        vec![
            response(vec![ToolCall::new("verify", json!({}))]),
            finish_response(),
        ],
        vec!["git".into(), "log".into(), "-n".into(), "1".into()],
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(outcome.evidence.is_empty());
    let tool_text = outcome
        .messages
        .iter()
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool message");
    assert!(
        tool_text.contains("exited with"),
        "exit status must reach the model: {tool_text}"
    );
    assert!(sink.snapshot().iter().any(|event| {
        event.kind == EventKind::ToolFinished
            && event
                .payload
                .as_ref()
                .and_then(|payload| payload.get("ok"))
                .and_then(|value| value.as_bool())
                == Some(false)
    }));
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn verify_rejects_model_supplied_arguments() {
    if !git_ready() {
        return;
    }
    let root = temp_root("verify-args");
    git(&root, &["init", "-q"]);

    let (agent, sink) = build_verify_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "verify",
                json!({"command": "cat secrets.txt"}),
            )]),
            finish_response(),
        ],
        vec!["git".into(), "status".into()],
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(outcome.evidence.is_empty());
    assert!(
        sink.snapshot()
            .iter()
            .any(|event| event.kind == EventKind::ToolBlocked),
        "a verify call carrying model arguments must be blocked before execution"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn agent_new_refuses_verify_command_mismatch() {
    if !git_ready() {
        return;
    }
    let root = temp_root("verify-mismatch");
    git(&root, &["init", "-q"]);
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.verify.command = vec!["git".into(), "status".into()];
    let contract = GoalContract::from_config("verify mismatch", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(Vec::new().into()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let error = match Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::new()),
        approval,
        Arc::new(MemSink::default()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("toolkit without the configured verify command must be refused"),
    };
    assert!(
        error
            .to_string()
            .contains("verify command does not match GoalContract"),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- F4: plan/act phase discipline ---------------------------------------

use pangu_boundary::{ApprovalHandler, ApprovalRequest, ApprovalResponse};

/// Records the approval requests it sees, then delegates to a scripted
/// handler — used to assert the F4 diff preview reaches the human gate.
struct RecordingApproval {
    inner: ScriptedApproval,
    requests: Arc<Mutex<Vec<ApprovalRequest>>>,
}

impl RecordingApproval {
    fn allow_all() -> (Self, Arc<Mutex<Vec<ApprovalRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner: ScriptedApproval::allow_all(ApprovalMode::DestructiveAndAbove),
                requests: requests.clone(),
            },
            requests,
        )
    }
}

#[async_trait]
impl ApprovalHandler for RecordingApproval {
    fn mode(&self) -> ApprovalMode {
        self.inner.mode()
    }

    async fn decide(&self, request: &ApprovalRequest) -> ApprovalResponse {
        self.requests
            .lock()
            .expect("approval request lock")
            .push(request.clone());
        self.inner.decide(request).await
    }
}

fn build_plan_first_agent(
    root: &Path,
    responses: Vec<ChatResponse>,
) -> (Agent, Arc<MemSink>, Arc<Mutex<Vec<ApprovalRequest>>>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.goal.plan_first = true;
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];

    let contract = GoalContract::from_config("plan-first test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(responses.into()),
    });
    let (approval, requests) = RecordingApproval::allow_all();
    let approval: Arc<dyn ApprovalHandler> = Arc::new(approval);
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
    (agent, sink, requests)
}

#[tokio::test]
async fn plan_first_blocks_mutations_until_begin_act() {
    let root = temp_root("plan-first");
    std::fs::write(root.join("out.txt"), "old\n").expect("seed");

    let (agent, sink, _requests) = build_plan_first_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "write_file",
                json!({"path": "out.txt", "content": "new\n"}),
            )]),
            response(vec![ToolCall::new("begin_act", json!({}))]),
            response(vec![ToolCall::new(
                "write_file",
                json!({"path": "out.txt", "content": "new\n"}),
            )]),
            finish_response(),
        ],
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    // The write happened exactly once, after the transition.
    assert_eq!(
        std::fs::read_to_string(root.join("out.txt")).expect("read"),
        "new\n"
    );
    // Order: the plan-phase block precedes the phase change; the later write
    // finishes successfully.
    let snapshot = sink.snapshot();
    let blocked = snapshot
        .iter()
        .position(|event| event.kind == EventKind::ToolBlocked)
        .expect("plan-phase block recorded");
    let changed = snapshot
        .iter()
        .position(|event| event.kind == EventKind::PhaseChanged)
        .expect("phase change recorded");
    let finished = snapshot
        .iter()
        .position(|event| event.kind == EventKind::ToolFinished)
        .expect("write finished");
    assert!(blocked < changed && changed < finished);
    // The blocked model input names the transition path.
    let tool_text = outcome
        .messages
        .iter()
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool message");
    assert!(
        tool_text.contains("begin_act"),
        "block message must point at the transition: {tool_text}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn plan_first_run_can_complete_read_only() {
    let root = temp_root("plan-readonly");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");

    let (agent, sink, _requests) = build_plan_first_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "read_file",
                json!({"path": "note.txt"}),
            )]),
            finish_response(),
        ],
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert_eq!(outcome.evidence.len(), 1);
    assert!(
        !sink
            .snapshot()
            .iter()
            .any(|event| event.kind == EventKind::PhaseChanged),
        "a read-only plan needs no transition"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn begin_act_is_not_advertised_without_plan_first() {
    let root = temp_root("no-plan-first");
    let (agent, _sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new("begin_act", json!({}))]),
            finish_response(),
        ],
        None,
    );
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    let tool_text = outcome
        .messages
        .iter()
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("tool message");
    assert!(
        tool_text.contains("not advertised"),
        "unconfigured begin_act must be refused: {tool_text}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn begin_act_twice_is_refused() {
    let root = temp_root("begin-act-twice");
    let (agent, sink, _requests) = build_plan_first_agent(
        &root,
        vec![
            response(vec![ToolCall::new("begin_act", json!({}))]),
            response(vec![ToolCall::new("begin_act", json!({}))]),
            finish_response(),
        ],
    );
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert_eq!(
        sink.snapshot()
            .iter()
            .filter(|event| event.kind == EventKind::PhaseChanged)
            .count(),
        1,
        "the phase changes exactly once"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn write_file_approval_carries_a_bounded_diff() {
    let root = temp_root("approval-diff");
    std::fs::write(
        root.join("out.txt"),
        "old line
",
    )
    .expect("seed");

    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    // Keep the embedded rules: their `ask-write-file` rule is what routes the
    // write through L4, which is the only place the diff preview is shown.
    let contract = GoalContract::from_config("diff preview test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response(vec![ToolCall::new(
                    "write_file",
                    json!({"path": "out.txt", "content": "old line
new line
"}),
                )]),
                finish_response(),
            ]
            .into(),
        ),
    });
    let (approval, requests) = RecordingApproval::allow_all();
    let sink = Arc::new(MemSink::default());
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::new()),
        Arc::new(approval),
        sink.clone(),
    )
    .expect("agent");
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    let requests = requests.lock().expect("requests lock");
    assert_eq!(requests.len(), 1, "one approval was requested");
    let diffs = &requests[0].impact.diffs;
    assert_eq!(
        diffs.len(),
        1,
        "one diff attached: {:?}",
        requests[0].impact
    );
    // "old line" is kept (context), "new line" is appended.
    assert!(diffs[0].contains(" old line"), "{:?}", diffs[0]);
    assert!(diffs[0].contains("+new line"), "{:?}", diffs[0]);
    // The human-facing render includes it.
    let rendered =
        pangu_boundary::StdinApproval::new(ApprovalMode::Never, std::time::Duration::from_secs(1))
            .render(&requests[0]);
    assert!(rendered.contains("+new line"), "{rendered}");
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- C5: execution profile declaration -----------------------------------

#[tokio::test]
async fn run_started_records_the_declared_execution_backend() {
    let root = temp_root("execution-profile");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");

    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.execution.profile = pangu_boundary::ExecutionProfile::Container;
    config.execution.description = Some("docker:ubuntu-24.04 image sha256:abc".into());
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];

    let contract = GoalContract::from_config("c5 audit test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response(vec![ToolCall::new(
                    "read_file",
                    json!({"path": "note.txt"}),
                )]),
                finish_response(),
            ]
            .into(),
        ),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
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
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    let snapshot = sink.snapshot();
    let started = snapshot
        .iter()
        .find(|event| event.kind == EventKind::RunStarted)
        .expect("run started event");
    let payload = started.payload.as_ref().expect("run started payload");
    assert_eq!(
        payload
            .get("execution_profile")
            .and_then(|value| value.as_str()),
        Some("container"),
        "the declared backend must be auditable: {payload}"
    );
    assert_eq!(
        payload
            .get("execution_description")
            .and_then(|value| value.as_str()),
        Some("docker:ubuntu-24.04 image sha256:abc")
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn undeclared_execution_is_absent_from_run_started() {
    let root = temp_root("execution-default");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");
    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "read_file",
                json!({"path": "note.txt"}),
            )]),
            finish_response(),
        ],
        None,
    );
    agent.run().await.expect("agent run");
    let snapshot = sink.snapshot();
    let started = snapshot
        .iter()
        .find(|event| event.kind == EventKind::RunStarted)
        .expect("run started event");
    let payload = started.payload.as_ref().expect("payload");
    assert!(
        payload.get("execution_profile").is_none(),
        "undeclared backend must stay absent: {payload}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}
