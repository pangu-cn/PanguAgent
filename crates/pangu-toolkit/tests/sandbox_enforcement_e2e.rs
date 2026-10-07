//! F8 end to end, through the real agent: a broken sandbox refuses commands and
//! a working configuration is unaffected.
//!
//! # Why this test exists in this shape
//!
//! An earlier version of this suite checked only that `Runtime::refusal()` said
//! the right thing. Sabotaging the executor to stop calling the gate left that
//! suite green — it verified the message, not the enforcement.
//!
//! This suite drives a real `Agent` with a real `Toolkit` through a full run and
//! asserts on what the run *observed*, so both halves are load-bearing: the gate
//! and its call site.
//!
//! # The scenario that mattered
//!
//! Before F8, declaring `[execution] profile = "container"` wrote "container"
//! into the audit trail and ran the command on the host anyway. The first test
//! below is that situation with the fix in place: the runtime is declared, it
//! cannot be probed, and the command must not execute.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use pangu_agent::{Agent, Provider};
use pangu_boundary::runtime::{Runtime, RuntimeConfig, SandboxRuntime};
use pangu_boundary::{ApprovalMode, Config, GoalContract, Policy, Rule, Sandbox, ScriptedApproval};
use pangu_core::{ChatResponse, EventKind, MemSink, Message, ToolCall, ToolSpec, Usage};
use pangu_toolkit::Toolkit;
use serde_json::json;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct ScriptedProvider {
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Provider for ScriptedProvider {
    fn name(&self) -> &str {
        "f8-sandbox-test"
    }
    fn model(&self) -> &str {
        "f8-sandbox-test-model"
    }
    fn describe(&self) -> String {
        "F8 sandbox enforcement test provider".into()
    }
    async fn chat(&self, _messages: Vec<Message>, _tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        Ok(self
            .responses
            .lock()
            .expect("lock")
            .pop_front()
            .expect("scripted response"))
    }
}

/// The OS temp directory with symlinked ancestors resolved.
///
/// The journal and artifact layers reject any path containing a symlink
/// component, and the sandbox canonicalizes its workspace before comparing
/// prefixes. On Linux container images `/tmp` is often a symlink, so a raw
/// `temp_dir()` path is refused there while working on a machine whose temp
/// directory is a real directory — the test passes locally and fails in CI for a
/// reason unrelated to the code under test. Resolving the base once removes the
/// whole class of mistake.
fn temp_base() -> std::path::PathBuf {
    let base = std::env::temp_dir();
    std::fs::canonicalize(&base).unwrap_or(base)
}
fn temp_root(label: &str) -> PathBuf {
    let root = temp_base().join(format!(
        "pangu-f8-e2e-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("create workspace");
    root
}

fn response(calls: Vec<ToolCall>) -> ChatResponse {
    ChatResponse {
        messages: vec![Message::assistant_calls("", calls)],
        usage: Usage::default(),
    }
}

/// A runtime that cannot work anywhere, so the refusal is exercised on every
/// machine rather than only where a container runtime happens to be missing.
///
/// Firecracker is chosen because its unavailability is a property of the
/// platform, not of local installation state.
fn broken_runtime(workspace: PathBuf) -> Runtime {
    RuntimeConfig {
        runtime: SandboxRuntime::Firecracker,
        image: "rootfs.img".into(),
        workspace,
        network: false,
        memory_mib: 128,
        cpus: 1,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    }
    .resolve()
}

/// Build an agent whose toolkit has the given runtime attached.
fn build_agent(
    root: &Path,
    responses: Vec<ChatResponse>,
    runtime: Option<Arc<Runtime>>,
) -> (Agent, Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    // The approval handler must match the contract's mode, so both are set from
    // one place rather than two that can drift.
    config.boundary.approval.mode = ApprovalMode::Always;
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "test tools")];

    let contract =
        GoalContract::from_config("f8 sandbox enforcement", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(ScriptedProvider {
        responses: Mutex::new(responses.into()),
    });
    // `run_command` is `NeedsHuman`, so the approval gate must let it through —
    // otherwise the test would measure the approval gate rather than the
    // sandbox. Approving leaves the sandbox as the only reason a command can
    // fail.
    let approval = Arc::new(ScriptedApproval::allow_all(ApprovalMode::Always));
    let sink = Arc::new(MemSink::default());

    let toolkit = match runtime {
        Some(runtime) => Toolkit::new().with_runtime(runtime),
        None => Toolkit::new(),
    };

    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(toolkit),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, sink)
}

/// The core requirement: a declared sandbox that does not work stops the
/// command, and the run says so rather than proceeding silently.
#[tokio::test]
async fn a_broken_sandbox_stops_a_command_from_reaching_the_host() {
    let root = temp_root("broken");
    let runtime = Arc::new(broken_runtime(root.clone()));
    assert!(
        !runtime.allows_execution(),
        "the test requires an unusable runtime; got {}",
        runtime.probe().summary()
    );

    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "run_command",
                json!({ "command": "git", "args": ["diff"] }),
            )]),
            response(vec![ToolCall::new("finish", json!({"status": "complete"}))]),
        ],
        Some(runtime),
    );

    let outcome = agent.run().await;
    let events = sink.snapshot();

    // Show what the run recorded, so a failure names its own cause rather than
    // requiring a re-run to diagnose.
    for event in &events {
        println!("  {:?}: {}", event.kind, event.message);
    }

    // Ground truth: the sandbox refused, and the refusal is *the sandbox's*
    // refusal rather than an unrelated failure.
    //
    // This asserts on the sandbox message specifically: `run_command` can fail
    // for several unrelated reasons (allow-list, argument validation, a missing
    // path), and accepting any of them would let the test pass while the sandbox
    // gate was never consulted — which is exactly the mistake an earlier version
    // of this suite made.
    let messages: Vec<String> = events.iter().map(|e| e.message.clone()).collect();
    let refusal = messages
        .iter()
        .find(|message| message.contains("refusing to execute"))
        .unwrap_or_else(|| {
            panic!(
                "the sandbox must be the reason the command did not run; events were: {:#?}",
                events
                    .iter()
                    .map(|e| (e.kind, e.message.clone()))
                    .collect::<Vec<_>>()
            )
        });
    // The refusal must explain the situation, not merely assert failure.
    assert!(
        refusal.contains("not usable"),
        "the refusal must name what is wrong: {refusal}"
    );
    assert!(
        refusal.contains("audit trail"),
        "the refusal must explain why there is no host fallback: {refusal}"
    );
    assert!(
        refusal.contains("fall back"),
        "the refusal must say the command is not run on the host: {refusal}"
    );

    // Nothing was executed: a command that runs produces an evidence entry, and
    // a refused one produces none.
    assert!(
        outcome
            .as_ref()
            .map(|o| o.evidence.is_empty())
            .unwrap_or(true),
        "a refused command must produce no evidence of execution"
    );

    println!(
        "run outcome with a broken sandbox: {:?}",
        outcome.map(|o| o.status)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The compatibility half: with no runtime declared, nothing changes.
///
/// Without this, a change that blocked *every* command would pass the test
/// above. `read_file` is used rather than a command because this test is about
/// the toolkit being unaffected when no sandbox is declared; command execution
/// with `local` is covered by the existing toolkit integration tests.
#[tokio::test]
async fn without_a_declared_sandbox_the_toolkit_is_unchanged() {
    let root = temp_root("local");
    std::fs::write(root.join("note.txt"), "hello from the workspace\n").expect("seed file");

    let (agent, sink) = build_agent(
        &root,
        vec![
            response(vec![ToolCall::new(
                "read_file",
                json!({"path": "note.txt"}),
            )]),
            response(vec![ToolCall::new("finish", json!({"status": "complete"}))]),
        ],
        None,
    );

    let outcome = agent.run().await.expect("run must succeed");
    let events = sink.snapshot();
    assert_eq!(
        outcome.status,
        pangu_boundary::GoalStatus::Complete,
        "with no declared sandbox the run must be unaffected; events: {:#?}",
        events
            .iter()
            .map(|e| (e.kind, e.message.clone()))
            .collect::<Vec<_>>()
    );
    // The tool really ran.
    assert!(
        events
            .iter()
            .any(|event| event.kind == EventKind::ToolFinished),
        "the tool must have executed"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A usable runtime is admitted, and the toolkit keeps the handle it was given.
#[tokio::test]
async fn a_usable_runtime_is_admitted_and_retained() {
    let root = temp_root("usable");
    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Local,
        image: String::new(),
        workspace: root.clone(),
        network: false,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    }
    .resolve();
    assert!(runtime.allows_execution());

    let toolkit = Toolkit::new().with_runtime(Arc::new(runtime));
    assert!(toolkit.runtime().is_some());
    assert!(
        pangu_toolkit::sandbox_admits(toolkit.runtime().map(|r| r.as_ref())).is_ok(),
        "a usable runtime must be admitted"
    );
    // And no runtime at all is admitted too: the unchanged local profile.
    assert!(pangu_toolkit::sandbox_admits(None).is_ok());

    let _ = std::fs::remove_dir_all(&root);
}
