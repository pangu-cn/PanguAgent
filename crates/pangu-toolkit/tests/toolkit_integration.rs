use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use pangu_agent::{Agent, Provider, ToolExecutor};
use pangu_boundary::{
    ApprovalMode, Config, FallbackCandidate, GoalContract, Policy, Rule, Sandbox, ScriptedApproval,
};
use pangu_core::{ChatResponse, EventKind, MemSink, Message, ToolCall, ToolSpec, Usage};
use pangu_core::{
    DeliverableSpec, DeliverableStore, MemoryLimits, MemoryStatus, MemoryStore, SkillLimits,
    SkillLock, SkillRegistry,
};
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

fn finish_call() -> Vec<ToolCall> {
    vec![ToolCall::new("finish", json!({"status": "complete"}))]
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

// ---- B5: provider fallback chain ------------------------------------------

/// A provider that fails specific 1-based call numbers, then serves scripted
/// responses. Used to exercise the fallback chain deterministically.
struct FlakyProvider {
    model: String,
    fail_calls: Vec<usize>,
    calls: AtomicUsize,
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Provider for FlakyProvider {
    fn name(&self) -> &str {
        "flaky"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn describe(&self) -> String {
        format!("flaky model={}", self.model)
    }

    async fn chat(&self, _messages: Vec<Message>, _tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_calls.contains(&call) {
            anyhow::bail!("simulated provider outage");
        }
        Ok(self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("scripted response"))
    }
}

/// A scripted provider with a configurable model name, for chain positions
/// whose model name must match the frozen contract candidate.
struct NamedScriptedProvider {
    model: String,
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Provider for NamedScriptedProvider {
    fn name(&self) -> &str {
        "named-fallback"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn describe(&self) -> String {
        format!("named fallback model={}", self.model)
    }

    async fn chat(&self, _messages: Vec<Message>, _tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        let response = self.responses.lock().expect("responses lock").pop_front();
        match response {
            Some(response) => Ok(response),
            None => anyhow::bail!("script exhausted"),
        }
    }
}

fn response_with_usage(calls: Vec<ToolCall>, input_tokens: u64) -> ChatResponse {
    ChatResponse {
        messages: vec![Message::assistant_calls("", calls)],
        usage: Usage {
            input_tokens,
            output_tokens: 0,
            cache_read_tokens: 0,
        },
    }
}

/// One declared fallback candidate (`gpt-4.1-mini` at 2.0/0.0 explicit) plus
/// the matching chain: a flaky primary and the scripted fallback.
fn build_chain_agent(
    root: &Path,
    primary_fail_calls: Vec<usize>,
    fallback_responses: Vec<ChatResponse>,
    max_cost_usd: f64,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(5.0);
    config.model.output_usd_per_mtok = Some(0.0);
    // Token budgets must sit above the scripted usage (400k) but below the
    // fallback's declared context window, so the cost gate is the only
    // constraint under test.
    config.budget.max_input_tokens = 900_000;
    config.budget.max_output_tokens = 1_000_000;
    config.budget.max_cost_usd = max_cost_usd;
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.model.fallback = vec![FallbackCandidate {
        provider: Some("openai".into()),
        model: Some("gpt-4.1-mini".into()),
        base_url: None,
        api_key_env: None,
        input_usd_per_mtok: Some(12.0),
        output_usd_per_mtok: Some(0.0),
    }];

    let contract = GoalContract::from_config("b5 test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let primary = Arc::new(FlakyProvider {
        model: "primary-model".into(),
        fail_calls: primary_fail_calls,
        calls: AtomicUsize::new(0),
        responses: Mutex::new(
            vec![response_with_usage(
                vec![ToolCall::new("read_file", json!({"path": "note.txt"}))],
                400_000,
            )]
            .into(),
        ),
    });
    let fallback = Arc::new(NamedScriptedProvider {
        model: "gpt-4.1-mini".into(),
        responses: Mutex::new(fallback_responses.into()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![primary, fallback],
        Arc::new(Toolkit::new()),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, sink)
}

#[tokio::test]
async fn fallback_switches_after_primary_failure_and_audits() {
    let root = temp_root("b5-switch");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");

    // Turn 1 is served by the primary; turn 2's primary attempt fails and the
    // fallback takes over for the rest of the run.
    let (agent, sink) = build_chain_agent(
        &root,
        vec![2],
        vec![
            response_with_usage(
                vec![ToolCall::new("read_file", json!({"path": "note.txt"}))],
                0,
            ),
            finish_response(),
        ],
        3.0,
    );
    let outcome = agent.run().await.expect("agent run");

    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    let snapshot = sink.snapshot();
    let switches = snapshot
        .iter()
        .filter(|event| event.kind == EventKind::ProviderSwitched)
        .count();
    assert_eq!(switches, 1, "exactly one audited switch");
    let notes = snapshot
        .iter()
        .filter(|event| event.kind == EventKind::Note)
        .count();
    assert!(notes >= 1, "the failed attempt must be audited");
    // The request after the switch names the fallback model.
    let last_request = snapshot
        .iter()
        .rev()
        .find(|event| event.kind == EventKind::ModelRequest)
        .expect("model request");
    assert!(
        last_request.message.contains("model=gpt-4.1-mini"),
        "the fallback model serves the run: {}",
        last_request.message
    );
    assert_eq!(outcome.evidence.len(), 2, "two successful reads");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn per_segment_pricing_never_under_counts_a_pricier_fallback() {
    let root = temp_root("b5-cost");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");

    // Primary segment costs 2.0 (400k input at 5.0/MTok); the fallback
    // segment costs 4.8 (400k at its declared 12.0). Cumulative 6.8 crosses
    // the 5.0 budget. If the switch under-counted at the primary price
    // (4.0 total), the run would finish instead of exhausting.
    let (agent, _sink) = build_chain_agent(
        &root,
        vec![2],
        vec![ChatResponse {
            messages: vec![Message::assistant("")],
            usage: Usage {
                input_tokens: 400_000,
                output_tokens: 0,
                cache_read_tokens: 0,
            },
        }],
        5.0,
    );
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(
        outcome.status,
        pangu_boundary::GoalStatus::BudgetExhausted,
        "per-segment pricing must count the pricier fallback segment"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn exhausted_fallback_chain_fails_the_run() {
    let root = temp_root("b5-exhausted");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");

    // Primary fails on every call; the fallback script is empty so its first
    // chat also fails: the whole chain is exhausted and the run errors out.
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(1.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.model.fallback = vec![FallbackCandidate {
        provider: Some("openai".into()),
        model: Some("gpt-4.1-mini".into()),
        base_url: None,
        api_key_env: None,
        input_usd_per_mtok: Some(2.0),
        output_usd_per_mtok: Some(0.0),
    }];
    let contract = GoalContract::from_config("b5 exhausted", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let primary = Arc::new(FlakyProvider {
        model: "primary-model".into(),
        fail_calls: (1..=10).collect(),
        calls: AtomicUsize::new(0),
        responses: Mutex::new(VecDeque::new()),
    });
    let fallback = Arc::new(NamedScriptedProvider {
        model: "gpt-4.1-mini".into(),
        responses: Mutex::new(VecDeque::new()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![primary, fallback],
        Arc::new(Toolkit::new()),
        approval,
        Arc::new(MemSink::default()),
    )
    .expect("agent");

    let error = match agent.run().await {
        Err(error) => error,
        Ok(outcome) => panic!("expected a failed run, got {:?}", outcome.status),
    };
    assert!(
        error.to_string().contains("all declared providers failed"),
        "{error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn with_chain_refuses_a_mismatched_fallback_chain() {
    let root = temp_root("b5-binding");
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(1.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.model.fallback = vec![FallbackCandidate {
        provider: Some("openai".into()),
        model: Some("gpt-4.1-mini".into()),
        base_url: None,
        api_key_env: None,
        input_usd_per_mtok: Some(2.0),
        output_usd_per_mtok: Some(0.0),
    }];
    let contract = GoalContract::from_config("b5 binding", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let primary = Arc::new(FlakyProvider {
        model: "primary-model".into(),
        fail_calls: Vec::new(),
        calls: AtomicUsize::new(0),
        responses: Mutex::new(VecDeque::new()),
    });

    // Chain too short.
    let error = match Agent::with_chain(
        contract.clone(),
        policy.clone(),
        sandbox.clone(),
        vec![primary.clone()],
        Arc::new(Toolkit::new()),
        approval.clone(),
        Arc::new(MemSink::default()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a shortened chain must be refused"),
    };
    assert!(
        error
            .to_string()
            .contains("does not match GoalContract fallbacks"),
        "{error}"
    );

    // Right length, wrong model.
    let wrong = Arc::new(NamedScriptedProvider {
        model: "wrong-model".into(),
        responses: Mutex::new(VecDeque::new()),
    });
    let error = match Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![primary, wrong],
        Arc::new(Toolkit::new()),
        approval,
        Arc::new(MemSink::default()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a model mismatch must be refused"),
    };
    assert!(
        error
            .to_string()
            .contains("does not match GoalContract fallback model"),
        "{error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- B3: controlled memory candidate queue --------------------------------

/// A scripted provider that also records every message list it is shown, so
/// tests can assert what actually reached the model (e.g. the memory block).
struct RecordingProvider {
    model: String,
    responses: Mutex<VecDeque<ChatResponse>>,
    captured: Mutex<Vec<Vec<Message>>>,
}

#[async_trait]
impl Provider for RecordingProvider {
    fn name(&self) -> &str {
        "recording"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn describe(&self) -> String {
        format!("recording model={}", self.model)
    }

    async fn chat(&self, messages: Vec<Message>, _tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        self.captured.lock().expect("captured lock").push(messages);
        self.responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("script exhausted"))
    }
}

fn memory_limits() -> MemoryLimits {
    MemoryLimits::default()
}

/// A memory-enabled agent: contract `memory.enabled = true`, the store backed
/// toolkit and agent, scripted provider, scripted approvals.
fn build_memory_agent(
    root: &Path,
    store: Arc<MemoryStore>,
    provider: Arc<dyn Provider>,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    // Scripted usage is zero, but the fail-closed cost gate still requires a
    // parseable price: without one, every run exhausts its budget.
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.memory.enabled = true;
    let contract = GoalContract::from_config("b3 test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new().with_memory(store.clone())),
        approval,
        sink.clone(),
    )
    .expect("agent")
    .with_memory(store);
    (agent, sink)
}

#[tokio::test]
async fn memory_proposal_is_audited_and_stays_inert() {
    let root = temp_root("b3-propose");
    let store = Arc::new(
        MemoryStore::open_with_label(
            &root.join(".pangu").join("memory"),
            memory_limits(),
            Some("test-run".into()),
        )
        .expect("store"),
    );
    let proposal = response_with_usage(
        vec![ToolCall::new(
            "propose_memory",
            json!({"content": "the project always uses tabs", "kind": "preference"}),
        )],
        0,
    );
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![proposal, finish_response()].into()),
    });
    let (agent, sink) = build_memory_agent(&root, store.clone(), provider);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    // The proposal landed as pending - inert data, never active memory.
    let pending = store.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].content, "the project always uses tabs");
    assert_eq!(pending[0].kind, "preference");
    assert_eq!(pending[0].status, MemoryStatus::Pending);
    assert_eq!(pending[0].proposed_in_run.as_deref(), Some("test-run"));
    assert!(store.accepted().is_empty(), "a proposal is never active");

    // The run audited the proposal with id + digest; the raw content lives
    // only in the store.
    let proposed = sink
        .snapshot()
        .into_iter()
        .find(|event| event.kind == EventKind::MemoryProposed)
        .expect("MemoryProposed event");
    let payload = proposed.payload.expect("payload");
    assert_eq!(payload["id"], pending[0].id);
    assert_eq!(payload["content_sha256"], pending[0].content_digest);
    assert!(payload.get("content").is_none(), "no raw content in events");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn accepted_memory_reaches_the_system_turn_as_untrusted() {
    let root = temp_root("b3-inject");
    let store = Arc::new(
        MemoryStore::open(&root.join(".pangu").join("memory"), memory_limits()).expect("store"),
    );
    let candidate = store
        .propose("the project always uses tabs", "preference")
        .expect("propose");
    store.accept(&candidate.id, "cli", None).expect("accept");
    // A still-pending proposal must never be injected.
    store.propose("pending and inert", "note").expect("propose");

    // One successful tool call so the evidence requirement is satisfied.
    std::fs::write(
        root.join("note.txt"),
        "data
",
    )
    .expect("seed");
    let read = response_with_usage(
        vec![ToolCall::new("read_file", json!({"path": "note.txt"}))],
        0,
    );
    let provider = Arc::new(RecordingProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![read, finish_response()].into()),
        captured: Mutex::new(Vec::new()),
    });
    let (agent, _sink) = build_memory_agent(&root, store, provider.clone());
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    let captured = provider.captured.lock().expect("captured lock");
    assert!(!captured.is_empty(), "the model was called");
    let system = captured[0]
        .iter()
        .find(|message| matches!(message, Message::System { .. }))
        .expect("system turn");
    let Message::System { content } = system else {
        panic!("expected system message")
    };
    assert!(
        content.contains("UNTRUSTED"),
        "the block is labeled: {content}"
    );
    assert!(content.contains("no authorization"));
    assert!(content.contains("the project always uses tabs"));
    assert!(
        !content.contains("pending and inert"),
        "pending candidates are never injected"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn memory_disabled_refuses_an_advertising_toolkit() {
    let root = temp_root("b3-disabled");
    let store = Arc::new(
        MemoryStore::open(&root.join(".pangu").join("memory"), memory_limits()).expect("store"),
    );
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    // memory stays disabled
    let contract = GoalContract::from_config("b3 off", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(VecDeque::new()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let error = match Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new().with_memory(store.clone())),
        approval,
        Arc::new(MemSink::default()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a toolkit advertising propose_memory must be refused when disabled"),
    };
    assert!(
        error
            .to_string()
            .contains("propose_memory advertisement does not match"),
        "{error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn pangu_owned_storage_is_never_tool_writable() {
    let root = temp_root("b3-forbidden");
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    let sandbox = Sandbox::from_config(&config.boundary).expect("sandbox");
    std::fs::create_dir_all(root.join(".pangu/memory")).expect("dir");
    std::fs::write(root.join(".pangu/memory/candidates.json"), "{}").expect("seed store file");
    let outcome = sandbox.resolve_write(&root.join(".pangu/memory/candidates.json"));
    assert!(matches!(
        outcome,
        pangu_boundary::sandbox::ResolveOutcome::ForbiddenGlob(_)
    ));
    let outcome = sandbox.resolve_write(&root.join(".pangu/anything.txt"));
    assert!(matches!(
        outcome,
        pangu_boundary::sandbox::ResolveOutcome::ForbiddenGlob(_)
    ));
    // The internal read path (used by the checkpoint runtime itself) is not
    // blocked: Pangu must read its own storage.
    let outcome = sandbox.resolve_read_internal(&root.join(".pangu/memory/candidates.json"));
    assert!(matches!(
        outcome,
        pangu_boundary::sandbox::ResolveOutcome::Allowed(_)
    ));
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- B2: skill registry and signed packages -------------------------------

/// Install a skill package into `<workspace>/.pangu/skills/` the way the CLI
/// would: compute the lock from a source dir, copy locked files, write the
/// lock. Returns the lock for assertions.
fn install_skill(workspace: &Path, name: &str, description: &str, doc: &str) -> SkillLock {
    let source = workspace.join(format!("src-{name}"));
    std::fs::create_dir_all(&source).expect("source dir");
    std::fs::write(
        source.join("SKILL.toml"),
        format!(
            "schema = \"pangu-skill-manifest/1\"\nname = \"{name}\"\nversion = \"1.0.0\"\ndescription = \"{description}\"\nfiles = [\"SKILL.md\"]\nscripts = []\n"
        ),
    )
    .expect("manifest");
    std::fs::write(source.join("SKILL.md"), doc).expect("doc");
    let lock =
        pangu_core::skills::compute_lock(&source, &SkillLimits::default()).expect("compute lock");
    let target = workspace.join(".pangu").join("skills").join(name);
    std::fs::create_dir_all(&target).expect("target");
    for file in &lock.files {
        let from = source.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let to = target.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        std::fs::copy(&from, &to).expect("copy");
    }
    std::fs::write(
        target.join("skill.lock"),
        serde_json::to_string_pretty(&lock).expect("lock json"),
    )
    .expect("write lock");
    lock
}

fn build_skills_agent(
    root: &Path,
    registry: Arc<SkillRegistry>,
    provider: Arc<dyn Provider>,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.skills.enabled = true;
    let contract = GoalContract::from_config("b2 test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new().with_skills(registry.clone())),
        approval,
        sink.clone(),
    )
    .expect("agent")
    .with_skills(registry);
    (agent, sink)
}

#[tokio::test]
async fn skill_index_is_injected_and_the_doc_is_readable() {
    let root = temp_root("b2-index");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");
    let lock = install_skill(
        &root,
        "release-checklist",
        "how to cut a release",
        "# Release\n\n1. Run the tests. 2. Tag the commit.\n",
    );
    let registry = Arc::new(
        SkillRegistry::load(
            &root.join(".pangu").join("skills"),
            &SkillLimits::default(),
            None,
        )
        .expect("registry"),
    );
    assert_eq!(registry.skills().len(), 1);
    assert_eq!(
        registry.skills()[0].lock.package_digest,
        lock.package_digest
    );

    let read = response_with_usage(
        vec![ToolCall::new(
            "read_skill",
            json!({"name": "release-checklist"}),
        )],
        0,
    );
    let provider = Arc::new(RecordingProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![read, finish_response()].into()),
        captured: Mutex::new(Vec::new()),
    });
    let (agent, _sink) = build_skills_agent(&root, registry, provider.clone());
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    // The system turn the model saw carried the labeled skill index.
    let captured = provider.captured.lock().expect("captured lock");
    let system = captured[0]
        .iter()
        .find(|message| matches!(message, Message::System { .. }))
        .expect("system turn");
    let Message::System { content } = system else {
        panic!("expected system message")
    };
    assert!(content.contains("Installed skills"), "{content}");
    assert!(content.contains("release-checklist v1.0.0 [unsigned]"));
    assert!(content.contains("carry no permissions"));
    // The read_skill result reached the conversation as a tool message in
    // the turn after the call.
    let tool_message = captured
        .iter()
        .flat_map(|messages| messages.iter())
        .find(|message| matches!(message, Message::Tool { name, .. } if name == "read_skill"))
        .expect("read_skill tool result");
    let Message::Tool { content, .. } = tool_message else {
        panic!("expected tool message")
    };
    assert!(content.contains("Tag the commit"));
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn tampered_skill_diverges_from_the_frozen_contract_and_fails_the_run() {
    let root = temp_root("b2-tamper");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");
    install_skill(
        &root,
        "release-checklist",
        "how to cut a release",
        "# Release\n",
    );
    // The contract freezes the skill set from the intact registry...
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.skills.enabled = true;
    let contract = GoalContract::from_config("b2 tamper", &config).expect("goal contract");
    assert_eq!(contract.skills().skills.len(), 1);

    // ...then the package is tampered with: the loaded registry is now
    // missing the skill, and the run refuses to start rather than silently
    // operating with a different set than the contract froze.
    let doc = root
        .join(".pangu")
        .join("skills")
        .join("release-checklist")
        .join("SKILL.md");
    std::fs::write(&doc, "# replaced by an attacker\n").expect("tamper");
    let registry = Arc::new(
        SkillRegistry::load(
            &root.join(".pangu").join("skills"),
            &SkillLimits::default(),
            None,
        )
        .expect("registry"),
    );
    assert!(registry.rejected().len() == 1);
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(VecDeque::new()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new().with_skills(registry.clone())),
        approval,
        Arc::new(MemSink::default()),
    )
    .expect("agent")
    .with_skills(registry);
    let error = match agent.run().await {
        Err(error) => error,
        Ok(outcome) => panic!("expected a failed run, got {:?}", outcome.status),
    };
    assert!(
        error
            .to_string()
            .contains("does not match GoalContract frozen skill set"),
        "{error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn skills_disabled_refuses_an_advertising_toolkit() {
    let root = temp_root("b2-disabled");
    let registry = Arc::new(
        SkillRegistry::load(
            &root.join(".pangu").join("skills"),
            &SkillLimits::default(),
            None,
        )
        .expect("registry"),
    );
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    // skills stay disabled
    let contract = GoalContract::from_config("b2 off", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(VecDeque::new()),
    });
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let error = match Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new().with_skills(registry.clone())),
        approval,
        Arc::new(MemSink::default()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a toolkit advertising read_skill must be refused when disabled"),
    };
    assert!(
        error
            .to_string()
            .contains("read_skill advertisement does not match"),
        "{error}"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- D3/D4: deliverable pipeline and acceptance ---------------------------

/// A memory/skills-style builder: contract declares one deliverable, the
/// registry is attached, provider is scripted.
fn build_deliverable_agent(
    root: &Path,
    store: Arc<DeliverableStore>,
    provider: Arc<dyn Provider>,
    declare: bool,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    if declare {
        config.goal.deliverable = vec![DeliverableSpec {
            name: "report".into(),
            path: "out/report.md".into(),
            kind: "report".into(),
            acceptor: pangu_core::Acceptor::Json,
            min_bytes: 1,
        }];
    }
    let contract = GoalContract::from_config("d4 test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let mut agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new()),
        approval,
        sink.clone(),
    )
    .expect("agent");
    if declare {
        agent = agent.with_deliverables(store);
    }
    (agent, sink)
}

#[tokio::test]
async fn complete_without_the_deliverable_is_refused_and_fed_back() {
    let root = temp_root("d4-refuse");
    let store =
        Arc::new(DeliverableStore::open(&root.join(".pangu").join("deliverables")).expect("store"));
    // Turn 1: write an unrelated file (satisfies the evidence floor),
    // turn 2: finish(complete) with the declared artifact missing - the
    // refusal is fed back as a tool error -, turn 3: the model gives up
    // with finish(failed).
    let seed = response_with_usage(
        vec![ToolCall::new(
            "write_file",
            json!({"path": "other.txt", "content": "x"}),
        )],
        0,
    );
    let give_up = response_with_usage(
        vec![ToolCall::new("finish", json!({"status": "failed"}))],
        0,
    );
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![seed, finish_response(), give_up].into()),
    });
    let (agent, sink) = build_deliverable_agent(&root, store.clone(), provider, true);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);

    // The complete was audibly refused with a model-readable reason ...
    let blocked = sink
        .snapshot()
        .into_iter()
        .find(|event| {
            event.kind == EventKind::ToolBlocked && event.tool.as_deref() == Some("finish")
        })
        .expect("finish must be audibly blocked");
    assert!(
        blocked.message.contains("deliverable acceptance failed"),
        "{}",
        blocked.message
    );
    assert!(
        blocked.message.contains("write it with write_file first"),
        "the failure detail must be model-readable: {}",
        blocked.message
    );
    // ... and nothing is recorded on refusal.
    assert!(store.records().is_empty(), "nothing is recorded on refusal");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn complete_records_audited_deliverables_after_checks_pass() {
    let root = temp_root("d4-record");
    let store =
        Arc::new(DeliverableStore::open(&root.join(".pangu").join("deliverables")).expect("store"));
    std::fs::create_dir_all(root.join("out")).expect("out dir");
    std::fs::write(root.join("out/report.md"), "{\"status\": \"done\"}").expect("artifact");

    // Turn 1: read the artifact (satisfies evidence), turn 2: finish.
    let read = response_with_usage(
        vec![ToolCall::new("read_file", json!({"path": "out/report.md"}))],
        0,
    );
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![read, finish_response()].into()),
    });
    let (agent, sink) = build_deliverable_agent(&root, store.clone(), provider, true);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    // The registry holds the audited snapshot: path, SHA-256, byte count.
    let records = store.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.name, "report");
    assert_eq!(record.path, "out/report.md");
    assert_eq!(record.bytes, "{\"status\": \"done\"}".len() as u64);
    assert_eq!(record.acceptance, pangu_core::Acceptance::Pending);
    assert_eq!(record.sha256.len(), 64);

    // The run audited the recording.
    let recorded = sink
        .snapshot()
        .into_iter()
        .find(|event| event.kind == EventKind::DeliverableRecorded)
        .expect("DeliverableRecorded event");
    let payload = recorded.payload.expect("payload");
    assert_eq!(payload["name"], "report");
    assert_eq!(payload["sha256"], record.sha256);
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn no_declared_deliverables_keeps_finish_semantics_unchanged() {
    let root = temp_root("d4-undeclared");
    std::fs::write(root.join("note.txt"), "data\n").expect("seed");
    let store =
        Arc::new(DeliverableStore::open(&root.join(".pangu").join("deliverables")).expect("store"));
    let read = response_with_usage(
        vec![ToolCall::new("read_file", json!({"path": "note.txt"}))],
        0,
    );
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![read, finish_response()].into()),
    });
    // declare = false: no deliverable semantics at all.
    let (agent, _sink) = build_deliverable_agent(&root, store, provider, false);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- F5: issue-to-patch evaluation record ---------------------------------

#[tokio::test]
async fn eval_context_captures_the_run_facts() {
    let root = temp_root("f5-eval");
    let store =
        Arc::new(DeliverableStore::open(&root.join(".pangu").join("deliverables")).expect("store"));
    let eval_dir = root.join(".pangu").join("eval");
    let eval_store = pangu_core::EvalStore::open(&eval_dir).expect("eval store");
    std::fs::create_dir_all(root.join("out")).expect("out dir");
    let patch_body =
        "{\"diff\": \"--- a/lib.rs\\n+++ b/lib.rs\", \"summary\": \"swap old for new\"}";
    std::fs::write(root.join("out/report.md"), patch_body).expect("patch");

    // The run reads the workspace (evidence), then finishes complete.
    let read = response_with_usage(
        vec![ToolCall::new("read_file", json!({"path": "out/report.md"}))],
        0,
    );
    let provider = Arc::new(NamedScriptedProvider {
        model: "toolkit-integration-test-model".into(),
        responses: Mutex::new(vec![read, finish_response()].into()),
    });
    let (agent, _sink) = build_deliverable_agent(&root, store.clone(), provider, true);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    // F5: the outcome now carries the trajectory/cost summary.
    assert!(outcome.turns >= 2, "turns: {}", outcome.turns);
    assert_eq!(
        outcome.cost_usd,
        Some(0.0),
        "test config declares zero prices"
    );

    // Assemble the evaluation record from the run's facts.
    let deliverables = store
        .records()
        .into_iter()
        .map(|record| pangu_core::EvalDeliverable {
            name: record.name,
            path: record.path,
            sha256: record.sha256,
            bytes: record.bytes,
            acceptance: record.acceptance.as_str().to_string(),
        })
        .collect();
    let context = pangu_core::EvalContext {
        profile: "issue-fix".into(),
        issue: pangu_core::EvalIssue {
            path: "issues/001.md".into(),
            sha256: "a".repeat(64),
        },
        workspace_version: "unknown".into(),
        contract_digest: "c".repeat(64),
        started_at: pangu_core::now_rfc3339(),
        store: eval_store,
    };
    let facts = pangu_core::EvalRunFacts {
        status: outcome.status.as_str().to_string(),
        turns: outcome.turns,
        usage: outcome.usage,
        cost_usd: outcome.cost_usd,
        evidence: outcome.evidence.clone(),
    };
    let record = context
        .finish(&facts, deliverables, "journal-run-test.jsonl")
        .expect("eval record");
    assert_eq!(record.status, "complete");
    assert_eq!(record.turns, outcome.turns);
    assert_eq!(record.cost_usd, Some(0.0));
    assert_eq!(record.deliverables.len(), 1);
    assert_eq!(record.deliverables[0].name, "report");
    assert_eq!(record.verify_evidence, 0, "no verify command in this run");
    // The disclaimer travels with every record.
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("do not assert the issue is fixed")));
    // And the registry holds it.
    let records = pangu_core::EvalStore::open(&eval_dir)
        .expect("reopen")
        .records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, record.id);
    std::fs::remove_dir_all(root).expect("cleanup");
}

// ---- D1: restricted sub-agent delegation ----------------------------------

/// D1: builds the restricted executor each sub-agent runs with — a fresh
/// toolkit with the contract-frozen verify command and nothing else.
struct FreshToolkitTestFactory;

impl pangu_agent::SubtoolFactory for FreshToolkitTestFactory {
    fn build(&self, verify_command: Vec<String>) -> Result<Arc<dyn ToolExecutor>> {
        Ok(Arc::new(Toolkit::with_verify_command(verify_command)))
    }
}

fn build_delegation_agent(
    root: &Path,
    provider: Arc<dyn Provider>,
    allow: bool,
    max_cost_usd: f64,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.boundary.allow_delegation = allow;
    config.budget.max_cost_usd = max_cost_usd;
    config.budget.max_input_tokens = 4_000_000;
    config.budget.max_output_tokens = 4_000_000;
    config.model.input_usd_per_mtok = Some(1.0);
    config.model.output_usd_per_mtok = Some(1.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    let contract = GoalContract::from_config("d1 test", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let mut agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new()),
        approval,
        sink.clone(),
    )
    .expect("agent");
    if allow {
        agent = agent.with_delegation(Arc::new(FreshToolkitTestFactory));
    }
    (agent, sink)
}

#[tokio::test]
async fn parent_delegates_and_child_spend_is_aggregated() {
    let root = temp_root("d1-aggregate");
    std::fs::write(root.join("notes.txt"), "the subtask evidence\n").expect("notes");
    // One shared scripted provider serves both the parent turns and the
    // child turns, in call order: parent delegates, child reads, child
    // finishes complete, parent finishes complete.
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response_with_usage(
                    vec![ToolCall::new(
                        "delegate_task",
                        json!({"task": "Read notes.txt and report its contents.", "max_turns": 4}),
                    )],
                    200_000,
                ),
                response_with_usage(
                    vec![ToolCall::new("read_file", json!({"path": "notes.txt"}))],
                    200_000,
                ),
                response_with_usage(finish_call(), 200_000),
                response_with_usage(finish_call(), 200_000),
            ]
            .into(),
        ),
    });
    let (agent, sink) = build_delegation_agent(&root, provider, true, 10.0);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);

    // Aggregation: 4 responses x 200k input tokens x 1.0 USD/MTok = 0.8 USD
    // total. The parent alone produced only 2 of those responses — the other
    // 0.4 USD is the child's spend, merged into the parent's ledger.
    assert_eq!(
        outcome.cost_usd,
        Some(0.8),
        "child spend must be aggregated"
    );
    let kinds = sink.kinds();
    assert!(
        kinds.contains(&EventKind::TaskDelegated),
        "delegation must be audited: {kinds:?}"
    );
    // Central journal: both the parent and the child run in the same sink.
    let run_starts = kinds
        .iter()
        .filter(|kind| **kind == EventKind::RunStarted)
        .count();
    assert!(
        run_starts >= 2,
        "child run must share the journal: {kinds:?}"
    );
    // Evidence: the delegation itself is recorded.
    assert!(
        outcome
            .evidence
            .iter()
            .any(|item| item.starts_with("delegate: ")),
        "evidence: {:?}",
        outcome.evidence
    );
    // The event records the clamped grant and the task by digest only.
    let delegated = sink
        .snapshot()
        .into_iter()
        .find(|event| event.kind == EventKind::TaskDelegated)
        .expect("TaskDelegated event");
    let payload = delegated.payload.expect("payload");
    assert_eq!(payload["sub_max_turns"], 4);
    assert!(
        payload["task_sha256"].as_str().is_some(),
        "task travels by digest, never raw"
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn child_cannot_delegate_further() {
    let root = temp_root("d1-depth");
    // The child tries to re-delegate: its contract has allow_delegation
    // stripped, so the tool is not advertised and the call is blocked. The
    // child then honestly reports failure; the parent completes.
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response(vec![ToolCall::new(
                    "delegate_task",
                    json!({"task": "outer task"}),
                )]),
                response(vec![ToolCall::new(
                    "delegate_task",
                    json!({"task": "inner task"}),
                )]),
                response(vec![ToolCall::new("finish", json!({"status": "failed"}))]),
                finish_response(),
            ]
            .into(),
        ),
    });
    let (agent, sink) = build_delegation_agent(&root, provider, true, 10.0);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    // Exactly one delegation happened: the parent's. The child's attempt
    // was blocked.
    let delegated = sink
        .kinds()
        .into_iter()
        .filter(|kind| *kind == EventKind::TaskDelegated)
        .count();
    assert_eq!(delegated, 1, "depth-1 delegation only: {delegated}");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn delegation_disabled_keeps_the_tool_absent() {
    let root = temp_root("d1-off");
    // Delegation is default-off: the tool is never advertised, so the call
    // is refused like any unknown tool.
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response(vec![ToolCall::new(
                    "delegate_task",
                    json!({"task": "nope"}),
                )]),
                response(vec![ToolCall::new("finish", json!({"status": "failed"}))]),
            ]
            .into(),
        ),
    });
    let (agent, sink) = build_delegation_agent(&root, provider, false, 10.0);
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    let kinds = sink.kinds();
    assert!(!kinds.contains(&EventKind::TaskDelegated));
    let blocked = sink.snapshot().into_iter().any(|event| {
        event.kind == EventKind::ToolBlocked && event.tool.as_deref() == Some("delegate_task")
    });
    assert!(blocked, "the call must be refused as unadvertised");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn cost_clamp_bounds_the_child_and_its_spend_still_aggregates() {
    let root = temp_root("d1-clamp");
    std::fs::write(
        root.join("notes.txt"),
        "evidence
",
    )
    .expect("notes");
    // The model asks for a $0.05 cost cap; each response costs $0.20. The
    // clamped child therefore dies of its own budget on its first response,
    // returns budget_exhausted honestly, and its $0.20 still lands in the
    // parent's ledger.
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.boundary.allow_delegation = true;
    config.budget.max_cost_usd = 1.0;
    config.budget.max_input_tokens = 4_000_000;
    config.budget.max_output_tokens = 4_000_000;
    config.model.input_usd_per_mtok = Some(1.0);
    config.model.output_usd_per_mtok = Some(1.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];
    let contract = GoalContract::from_config("d1 clamp", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let approval = Arc::new(ScriptedApproval::allow_all(
        ApprovalMode::DestructiveAndAbove,
    ));
    let sink = Arc::new(MemSink::default());
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(
            vec![
                response_with_usage(
                    vec![ToolCall::new(
                        "delegate_task",
                        json!({"task": "bounded work", "max_cost_usd": 0.05}),
                    )],
                    200_000,
                ),
                response_with_usage(
                    vec![ToolCall::new("read_file", json!({"path": "notes.txt"}))],
                    200_000,
                ),
                response_with_usage(
                    vec![ToolCall::new("read_file", json!({"path": "notes.txt"}))],
                    200_000,
                ),
                response_with_usage(finish_call(), 200_000),
            ]
            .into(),
        ),
    });
    let agent = Agent::with_chain(
        contract,
        policy,
        sandbox,
        vec![provider],
        Arc::new(Toolkit::new()),
        approval,
        sink.clone(),
    )
    .expect("agent")
    .with_delegation(Arc::new(FreshToolkitTestFactory));
    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    // $0.20 (delegate turn) + $0.20 (child) + $0.20 (evidence) + $0.20
    // (finish) = $0.80. The child's spend is in the parent's ledger even
    // though the child itself hit its clamped budget.
    assert_eq!(outcome.cost_usd, Some(0.8));
    assert!(
        outcome
            .evidence
            .iter()
            .any(|item| item.contains("-> budget_exhausted")),
        "the child's terminal status is reported honestly: {:?}",
        outcome.evidence
    );
    // The recorded grant is the clamped cost cap the model asked for.
    let delegated = sink
        .snapshot()
        .into_iter()
        .find(|event| event.kind == EventKind::TaskDelegated)
        .expect("TaskDelegated event");
    assert_eq!(
        delegated.payload.expect("payload")["sub_max_cost_usd"],
        0.05
    );
    std::fs::remove_dir_all(root).expect("cleanup");
}
