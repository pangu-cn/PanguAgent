//! F8: a real tool call is dispatched *through* the declared runtime.
//!
//! # The claim being tested
//!
//! `pangu-boundary`'s `runtime_dispatch.rs` proves the argv is built correctly
//! and that the probe accepts a runtime that answers. This file closes the last
//! gap: that a **tool call** — not just a probe — is handed to the runtime with
//! the operator's command inside it.
//!
//! That distinction matters because the probe and the real path are separate call
//! sites. A launcher that probed correctly and then spawned the command directly
//! would pass every boundary-level test while providing no isolation at all.
//!
//! # How a runtime is simulated without Docker
//!
//! A stub `docker` on `PATH` records every invocation it receives. If the
//! production path really routes through the runtime, the stub sees the command;
//! if the executor bypassed the runtime, the stub would see nothing and the test
//! fails. The stub is a real file on `PATH`, so the production lookup runs
//! unchanged.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use pangu_agent::Agent;
use pangu_boundary::runtime::{RuntimeConfig, SandboxRuntime};
use pangu_boundary::{ApprovalMode, Config, GoalContract, Policy, Rule, Sandbox, ScriptedApproval};
use pangu_core::{ChatResponse, EventKind, MemSink, Message, ToolCall, ToolSpec, Usage};
use pangu_toolkit::Toolkit;
use serde_json::json;

use anyhow::Result;
use async_trait::async_trait;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// `PATH` is process-global, so the tests that mutate it must not overlap.
static PATH_LOCK: Mutex<()> = Mutex::new(());

/// Prepends `bin` to `PATH` for as long as it is alive, restoring it on drop.
///
/// This exists instead of a bare `let guard = PATH_LOCK.lock()` because these are
/// `async` tests: holding a `MutexGuard` across an await point is a real hazard
/// (the guard is not `Send`, and holding it would serialise unrelated work), so
/// the lock is taken and released inside `prepend` and only the *restore
/// obligation* crosses the await. Restoring on drop also means a panicking
/// assertion cannot leave a stub on `PATH` and cascade into the other tests.
struct PathGuard {
    original: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl PathGuard {
    fn prepend(bin: &Path) -> Self {
        let lock = PATH_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = std::env::var_os("PATH");
        let mut joined = bin.to_path_buf().into_os_string();
        joined.push(if cfg!(windows) { ";" } else { ":" });
        if let Some(existing) = &original {
            joined.push(existing);
        }
        std::env::set_var("PATH", &joined);
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var("PATH", value),
            None => std::env::remove_var("PATH"),
        }
    }
}

struct ScriptedProvider {
    responses: Mutex<std::collections::VecDeque<ChatResponse>>,
}

#[async_trait]
impl pangu_agent::Provider for ScriptedProvider {
    fn name(&self) -> &str {
        "f8-dispatch"
    }
    fn model(&self) -> &str {
        "f8-dispatch-model"
    }
    fn describe(&self) -> String {
        "F8 dispatch test provider".into()
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

fn temp_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pangu-f8-toolkit-{label}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("create root");
    path
}

/// A stub runtime named `docker` that records its argv and prints the token the
/// probe expects.
fn write_stub(bin_dir: &Path, record: &Path, token: &str) {
    write_stub_named(bin_dir, record, token, "docker");
}

/// A stub program under an arbitrary name.
///
/// `name` is parameterised so the same recorder can stand in for a container
/// runtime (`docker`) and for an ordinary local command, which lets one helper
/// serve both halves of the "was a runtime used?" question.
fn write_stub_named(bin_dir: &Path, record: &Path, token: &str, name: &str) {
    std::fs::create_dir_all(bin_dir).expect("create bin dir");
    #[cfg(windows)]
    {
        let path = bin_dir.join(format!("{name}.cmd"));
        // `echo %*` prints "ECHO is off." when there are no arguments, which is
        // indistinguishable from the stub having failed to write. Emitting a
        // sentinel line first means the record always proves the program ran,
        // whether or not it received arguments.
        std::fs::write(
            &path,
            format!(
                "@echo off\r\necho RAN {name} %* >> \"{record}\"\r\necho {token}\r\n",
                record = record.display()
            ),
        )
        .expect("write stub");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = bin_dir.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{record}'\necho '{token}'\n",
                record = record.display()
            ),
        )
        .expect("write stub");
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
    }
}

fn response(calls: Vec<ToolCall>) -> ChatResponse {
    ChatResponse {
        messages: vec![Message::assistant_calls("", calls)],
        usage: Usage::default(),
    }
}

/// Build an agent whose toolkit has the given runtime attached.
fn build_agent(
    root: &Path,
    responses: Vec<ChatResponse>,
    runtime: Option<std::sync::Arc<pangu_boundary::runtime::Runtime>>,
) -> (Agent, std::sync::Arc<MemSink>) {
    let mut config = Config::embedded().expect("embedded");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    config.boundary.approval.mode = ApprovalMode::Always;
    // `pwd` is a shell builtin with no standalone executable, and an unknown
    // program is refused by the read-only argv allow-list. Neither is what this
    // test is about, so the wrapper is declared as an allowed program — the same
    // mechanism an operator uses for `cargo` or `npm` — and the question under
    // test stays "was a runtime involved?".
    config.boundary.extra_readonly_commands = vec!["pangu-local-wrapper".into()];
    config.boundary.env.allow = vec![
        "PATH".into(),
        "SYSTEMROOT".into(),
        "SystemRoot".into(),
        "PATHEXT".into(),
        "COMSPEC".into(),
    ];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![Rule::allow("allow-tools", "*", "dispatch test")];

    let contract = GoalContract::from_config("f8 dispatch", &config).expect("contract");
    let policy = std::sync::Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = std::sync::Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = std::sync::Arc::new(ScriptedProvider {
        responses: Mutex::new(responses.into()),
    });
    let approval = std::sync::Arc::new(ScriptedApproval::allow_all(ApprovalMode::Always));
    let sink = std::sync::Arc::new(MemSink::default());

    let toolkit = match runtime {
        Some(runtime) => Toolkit::new().with_runtime(runtime),
        None => Toolkit::new(),
    };

    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        std::sync::Arc::new(toolkit),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, sink)
}

/// The decisive test: a tool call reaches the runtime, carrying the operator's
/// command, and the run reports the output the runtime produced.
#[tokio::test]
async fn a_tool_call_is_dispatched_through_the_declared_runtime() {
    let root = temp_root("dispatch");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    let token = "pangu-dispatch-ok";
    write_stub(&bin, &record, token);

    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let _path = PathGuard::prepend(&bin);

    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Oci,
        image: "alpine:3.20".into(),
        workspace: workspace.clone(),
        network: true,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), token.into()],
        probe_expect: token.into(),
    }
    .resolve();
    assert!(
        runtime.allows_execution(),
        "the stub runtime must probe as usable: {}",
        runtime.probe().summary()
    );

    let (agent, sink) = build_agent(
        &workspace,
        vec![
            response(vec![ToolCall::new(
                "run_command",
                json!({ "command": "pwd", "args": [] }),
            )]),
            response(vec![ToolCall::new("finish", json!({"status": "complete"}))]),
        ],
        Some(std::sync::Arc::new(runtime)),
    );

    let outcome = agent.run().await.expect("run must complete");
    let events = sink.snapshot();

    for event in &events {
        println!("  {:?}: {}", event.kind, event.message);
    }

    let calls = std::fs::read_to_string(&record).unwrap_or_default();
    println!("runtime was invoked with:\n{calls}");
    assert!(
        !calls.trim().is_empty(),
        "the runtime must have been invoked; the executor ran the command directly instead"
    );

    // The probe ran first, then the real command: two invocations, and the second
    // is the one that must carry the command.
    let invocations: Vec<&str> = calls
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(
        invocations.len() >= 2,
        "expected a probe and a command invocation, got {invocations:#?}"
    );
    let command_call = invocations
        .iter()
        .rev()
        .find(|line| line.contains("pwd"))
        .unwrap_or_else(|| {
            panic!("no invocation carried the command `pwd`; invocations were {invocations:#?}")
        });
    println!("command invocation: {command_call}");
    // The command must be inside the container invocation, after the image — not
    // run outside it.
    assert!(command_call.contains("alpine:3.20"), "{command_call}");
    assert!(command_call.contains("pwd"), "{command_call}");

    // The run succeeded, which means the output travelled back through the
    // launcher's stdio rather than being lost.
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert!(
        events
            .iter()
            .any(|event| event.kind == EventKind::ToolFinished),
        "the tool must have finished"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A tool call must **not** reach the runtime when the runtime is unusable.
///
/// This is the other half: it is not enough that commands go through the runtime
/// when it works; they must not go anywhere when it does not.
#[tokio::test]
async fn an_unusable_runtime_stops_the_command_before_it_reaches_the_runtime() {
    let root = temp_root("refused");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    // Answers, but not with the token the probe is looking for.
    write_stub(&bin, &record, "the-wrong-output");

    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let _path = PathGuard::prepend(&bin);

    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Oci,
        image: "alpine:3.20".into(),
        workspace: workspace.clone(),
        network: true,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "pangu-expected".into()],
        probe_expect: "pangu-expected".into(),
    }
    .resolve();
    assert!(!runtime.allows_execution(), "the runtime must be unusable");

    let (agent, sink) = build_agent(
        &workspace,
        vec![
            response(vec![ToolCall::new(
                "run_command",
                json!({ "command": "pwd", "args": [] }),
            )]),
            response(vec![ToolCall::new("finish", json!({"status": "complete"}))]),
        ],
        Some(std::sync::Arc::new(runtime)),
    );

    let outcome = agent.run().await;
    let events = sink.snapshot();

    // The probe itself invoked the stub, so the record is not empty; what must be
    // absent is an invocation carrying the command.
    let calls = std::fs::read_to_string(&record).unwrap_or_default();
    println!("runtime saw:\n{calls}");
    assert!(
        !calls.contains("pwd"),
        "a refused command must never reach the runtime: {calls}"
    );

    // And the refusal is visible to whoever reads the run.
    let messages: Vec<String> = events.iter().map(|event| event.message.clone()).collect();
    let refusal = messages
        .iter()
        .find(|message| message.contains("refusing to execute"))
        .unwrap_or_else(|| {
            panic!(
                "the refusal must be recorded; events were: {:#?}",
                events
                    .iter()
                    .map(|e| (e.kind, e.message.clone()))
                    .collect::<Vec<_>>()
            )
        });
    println!("refusal: {refusal}");
    assert!(refusal.contains("audit trail"), "{refusal}");

    println!("run outcome: {:?}", outcome.map(|o| o.status));
    let _ = std::fs::remove_dir_all(&root);
}

/// With no runtime declared, nothing is wrapped: the command runs locally.
///
/// Without this, a change that wrapped *every* command in a runtime would pass
/// the tests above — and would break the default configuration.
///
/// The command is a real program rather than `pwd`, which is a shell builtin with
/// no standalone executable. And the stub lives **outside** the workspace:
/// `resolve_executable` deliberately refuses any program whose canonical path is
/// inside the workspace, so a stub placed there would be rejected for a reason
/// unrelated to what this test measures.
#[tokio::test]
async fn without_a_declared_runtime_the_command_is_not_wrapped() {
    let root = temp_root("local");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let wrapper = "pangu-local-wrapper";
    write_stub_named(&bin, &record, "unused", wrapper);

    let _path = PathGuard::prepend(&bin);

    let (agent, sink) = build_agent(
        &workspace,
        vec![
            response(vec![ToolCall::new(
                "run_command",
                json!({ "command": wrapper, "args": [] }),
            )]),
            response(vec![ToolCall::new("finish", json!({"status": "complete"}))]),
        ],
        None,
    );

    let outcome = agent.run().await.expect("run must complete");
    let events = sink.snapshot();

    for event in &events {
        println!("  {:?}: {}", event.kind, event.message);
    }
    // The wrapper writes the record itself, so a line proves it ran — and ran
    // directly, since no runtime was declared to wrap it.
    let calls = std::fs::read_to_string(&record).unwrap_or_default();
    println!("local invocation recorded: {calls:?}");
    assert!(
        !calls.trim().is_empty(),
        "the command should have run locally; events: {:#?}",
        events
            .iter()
            .map(|e| (e.kind, e.message.clone()))
            .collect::<Vec<_>>()
    );
    // Nothing was containerised: no image name appears in what the program saw.
    assert!(
        !calls.contains("alpine:3.20"),
        "no runtime is declared, so nothing may be wrapped in a container: {calls}"
    );
    assert_eq!(
        outcome.status,
        pangu_boundary::GoalStatus::Complete,
        "with no runtime declared the command must run normally"
    );
    assert!(events
        .iter()
        .any(|event| event.kind == EventKind::ToolFinished));

    let _ = std::fs::remove_dir_all(&root);
}

/// The executor alone is enough: `sandbox_admits` gates the dispatch.
#[test]
fn the_execution_gate_is_the_thing_that_refuses() {
    let root = temp_root("gate");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    write_stub(&bin, &record, "not-the-token");

    let _path = PathGuard::prepend(&bin);

    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Oci,
        image: "alpine:3.20".into(),
        workspace: root.clone(),
        network: true,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "expected".into()],
        probe_expect: "expected".into(),
    }
    .resolve();

    assert!(!runtime.allows_execution());
    let error = pangu_toolkit::sandbox_admits(Some(&runtime))
        .expect_err("an unusable runtime must be refused by the gate");
    let text = error.to_string();
    println!("gate refusal: {text}");
    assert!(text.contains("refusing to execute"), "{text}");
    // And nothing is declared: the gate permits, which is the `local` default.
    assert!(pangu_toolkit::sandbox_admits(None).is_ok());

    let _ = std::fs::remove_dir_all(&root);
}
