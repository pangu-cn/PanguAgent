//! 不变量测试矩阵 —— 对应 `docs/BOUNDARY.md` §4 Invariants。
//!
//! 每个函数测试一条或一组不变量；PR 时必须同时修改对应的代码和测试，否则视为回归。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use pangu_agent::{
    Agent, EffectDescriptor, EffectScope, Provider, Reversibility, ToolAssessment, ToolExecutor,
    ToolOutput, VerifiedAction,
};
use pangu_boundary::policy::{ActionRequest, Effect, Policy, Rule};
use pangu_boundary::risk::Risk;
use pangu_boundary::{
    ApprovalMode, CheckpointBackend, Config, GoalContract, Sandbox, ScriptedApproval,
};
use pangu_core::{
    ArtifactStore, ChatResponse, CheckpointArtifact, CheckpointFileEntry, EffectRecord, EventKind,
    EventRef, EventSink, FailedPathRecord, FailedPathStatus, FailureClass, Journal, MemSink,
    Message, RestoreDisposition, RollbackOperation, RollbackOperationStatus, RollbackRequest,
    SessionNode, SnapshotLimits, SnapshotRequest, TeeSink, ToolCall, ToolSpec, Usage, Value,
    JOURNAL_FORMAT_V2, ROLLBACK_OPERATION_SCHEMA_VERSION,
};
use pangu_toolkit::Toolkit;
use serde_json::json;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_path(label: &str) -> std::path::PathBuf {
    // Nanoseconds matter here: `Journal::create` refuses a path that already
    // exists, and the process id plus a per-process counter is reused once the
    // id wraps around. Without the timestamp a leftover journal from an
    // earlier run turns a passing test into a fail-closed error.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pangu-invariant-{label}-{}-{nanos}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

struct OneShotProvider {
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Provider for OneShotProvider {
    fn name(&self) -> &str {
        "invariant-test"
    }

    fn model(&self) -> &str {
        "invariant-test-model"
    }

    fn describe(&self) -> String {
        "invariant test provider".into()
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

struct ReservedTool {
    executions: AtomicUsize,
}

#[async_trait]
impl ToolExecutor for ReservedTool {
    fn specs(&self) -> Vec<ToolSpec> {
        vec![
            ToolSpec::new("rollback", "reserved", json!({"type": "object"})),
            ToolSpec::new("finish", "finish", json!({"type": "object"})),
        ]
    }

    async fn assess(&self, _call: &ToolCall, _sandbox: &Sandbox) -> Result<ToolAssessment> {
        Ok(
            ToolAssessment::new(Risk::ReadOnly).with_effect(EffectDescriptor::new(
                EffectScope::Workspace,
                Reversibility::NoEffect,
            )),
        )
    }

    async fn execute(&self, _action: &VerifiedAction) -> Result<ToolOutput> {
        self.executions.fetch_add(1, Ordering::Relaxed);
        Ok(ToolOutput::text("reserved capability must not execute"))
    }
}

struct MissingEffectTool {
    executions: AtomicUsize,
}

#[async_trait]
impl ToolExecutor for MissingEffectTool {
    fn specs(&self) -> Vec<ToolSpec> {
        vec![
            ToolSpec::new("test_tool", "test", json!({"type": "object"})),
            ToolSpec::new("finish", "finish", json!({"type": "object"})),
        ]
    }

    async fn assess(&self, _call: &ToolCall, _sandbox: &Sandbox) -> Result<ToolAssessment> {
        Ok(ToolAssessment::new(Risk::ReadOnly))
    }

    async fn execute(&self, _action: &VerifiedAction) -> Result<ToolOutput> {
        self.executions.fetch_add(1, Ordering::Relaxed);
        Ok(ToolOutput::evidenced(
            "must not execute",
            "must-not-execute",
        ))
    }
}

fn ws() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join("test-workspace")
}

fn empty_request() -> ActionRequest<'static> {
    let args: &'static Value = Box::leak(Box::new(json!({})));
    ActionRequest {
        tool: "bash",
        call_id: "c0",
        args,
        risk: Risk::ReadOnly,
        paths: vec![],
        hosts: vec![],
        argv: vec![],
        escapes_workspace: false,
    }
}

#[test]
fn invariant_i_default_deny_no_rules_means_all_denied() {
    // I-Default-Deny: 没有规则的动作一律拒绝
    let policy = Policy::empty();
    let req = empty_request();
    let decision = policy.evaluate(&req, &ws());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.invariant.as_deref(), Some("I-Default-Deny"));
}

#[test]
fn invariant_i_no_silent_bypass_allow_cannot_overwrite_deny() {
    // I-No-Silent-Bypass: deny 类规则永不被"允许"覆盖
    let policy = Policy::new(vec![
        Rule::deny("block-shutdown", "*", "禁止关机命令"),
        Rule::allow("trust-all", "*", "信任所有人"), // 这不能覆盖 deny
    ])
    .unwrap();
    let req = empty_request();
    let decision = policy.evaluate(&req, &ws());
    assert_eq!(decision.effect, Effect::Deny); // deny 优先
    assert_eq!(decision.rule_id.as_deref(), Some("block-shutdown"));
}

#[test]
fn invariant_i_model_cannot_self_approve_destructive_must_ask() {
    // I-Model-Cannot-Self-Approve: destructive 及以上必须回到人面前
    let policy = Policy::new(vec![Rule::allow("auto-delete", "*", "自动删除")]).unwrap();
    let mut req = empty_request();
    req.risk = Risk::Destructive;
    let decision = policy.evaluate(&req, &ws());
    assert_eq!(decision.effect, Effect::Ask); // 降级为 ask
    assert_eq!(
        decision.invariant.as_deref(),
        Some("I-Model-Cannot-Self-Approve")
    );
}

#[test]
fn invariant_i_budget_terminates_zero_turn_rejected() {
    // I-Budget-Terminates: 零 turn 预算被拒绝
    let budget = pangu_boundary::budget::Budget {
        max_turns: 0,
        ..Default::default()
    };
    assert!(!budget
        .check(1, 100, 50, 0.1, std::time::Duration::from_secs(1))
        .is_empty());
}

#[test]
fn invariant_i_hash_chain_integrity() {
    use pangu_core::{events::Event, journal::Journal};

    let path = temp_path("journal");
    {
        let journal = Journal::create(&path).expect("create journal");
        journal
            .record(&Event::new(EventKind::RunStarted, 0, "start"))
            .expect("record start");
        journal
            .record(&Event::new(EventKind::RunFinished, 0, "done"))
            .expect("record finish");
    }

    let events = pangu_core::replay::read(&path).expect("read valid journal");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, 0);
    assert_eq!(events[1].seq, 1);
    assert_eq!(events[1].prev_sha, events[0].sha);

    let content = std::fs::read_to_string(&path).expect("read journal bytes");
    let mut lines = content.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut tampered = serde_json::from_str::<Event>(&lines[0]).expect("parse first event");
    tampered.message.push_str(" tampered");
    lines[0] = serde_json::to_string(&tampered).expect("serialize tampered event");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write tampered journal");
    let error = pangu_core::replay::read(&path).expect_err("tampered journal must fail");
    let error = error.to_string();
    assert!(error.contains("sha mismatch") || error.contains("failed verification"));

    std::fs::remove_file(path).expect("remove journal");
}

#[test]
fn invariant_i_redact_at_boundary_secrets_not_in_events() {
    use pangu_core::{redact_event, Event, EventKind};
    let event = Event::new(EventKind::Note, 0, "authorization: Bearer sk-live-secret")
        .tool("password: secret")
        .call_id("token: ghp_secret")
        .payload(json!({
            "api_key": "sk-live-secret",
            "nested": {"password": "secret"},
            "safe": "ok"
        }));
    let redacted = redact_event(event);
    let serialized = serde_json::to_string(&redacted).unwrap();
    assert!(!serialized.contains("sk-live-secret"));
    assert!(!serialized.contains("ghp_secret"));
    assert!(!serialized.contains("secret"));
    assert!(serialized.contains("[REDACTED]"));
}

#[tokio::test]
async fn invariant_i_honest_terminal_complete_requires_evidence() {
    let root = temp_path("agent");
    std::fs::create_dir_all(&root).expect("create agent workspace");

    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = root.clone();
    config.boundary.readable_roots = vec![root.clone()];
    config.boundary.writable_roots = vec![root.clone()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);

    let contract =
        GoalContract::from_config("finish without evidence", &config).expect("goal contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(OneShotProvider {
        responses: Mutex::new(VecDeque::from([ChatResponse {
            messages: vec![Message::assistant_calls(
                "",
                vec![ToolCall::new("finish", json!({"status": "complete"}))],
            )],
            usage: Usage::default(),
        }])),
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

    let outcome = agent.run().await.expect("agent run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(outcome.evidence.is_empty());
    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventKind::FinishRequested
            && event
                .payload
                .as_ref()
                .and_then(|p| p.get("status"))
                .is_none()
    }));
    assert!(events.iter().any(|event| {
        event.kind == EventKind::RunFinished
            && event
                .payload
                .as_ref()
                .and_then(|p| p.get("status"))
                .and_then(|s| s.as_str())
                == Some("failed")
    }));

    std::fs::remove_dir_all(root).expect("remove agent workspace");
}

#[test]
fn test_serde_roundtrip_of_risk_class() {
    use pangu_boundary::risk::Risk;
    for r in [
        Risk::ReadOnly,
        Risk::Reversible,
        Risk::Destructive,
        Risk::NeedsHuman,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: Risk = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn test_rule_with_max_risk_filtering() {
    let rules = vec![Rule {
        id: "read-only-allow".into(),
        effect: Effect::Allow,
        tool: "*".into(),
        arg: None,
        path_glob: None,
        host_glob: None,
        max_risk: Some(Risk::ReadOnly),
        min_risk: None,
        reason: "只读放行".into(),
        invariant: None,
    }];
    let policy = Policy::new(rules).unwrap();
    let mut read_req = empty_request();
    read_req.risk = Risk::ReadOnly;
    assert_eq!(policy.evaluate(&read_req, &ws()).effect, Effect::Allow);
    let mut write_req = read_req.clone();
    write_req.risk = Risk::Reversible;
    assert_ne!(policy.evaluate(&write_req, &ws()).effect, Effect::Allow); // 因为 max_risk=ReadOnly 不匹配写操作
}

// ADR-0001 phase-one contract tests. These verify schemas and fail-closed
// boundaries only; they do not claim that checkpoint/rollback is active.
fn phase1_digest() -> String {
    "a".repeat(64)
}

fn phase1_event_ref() -> pangu_core::EventRef {
    pangu_core::EventRef::new("event-1", "run-1")
}

#[test]
fn phase1_effect_declarations_are_required_and_risk_consistent() {
    let external_mutation =
        EffectDescriptor::new(EffectScope::ExternalMutation, Reversibility::Irreversible);
    assert!(external_mutation
        .validate_for_risk(Risk::Destructive)
        .is_ok());
    assert!(external_mutation
        .validate_for_risk(Risk::Reversible)
        .is_err());
    assert!(
        EffectDescriptor::new(EffectScope::ExternalMutation, Reversibility::Reversible)
            .validate_for_risk(Risk::Destructive)
            .is_err()
    );
    assert!(ToolAssessment::new(Risk::ReadOnly)
        .validate_effect()
        .is_err());
    assert_eq!(EffectScope::ProcessRead.as_str(), "process_read");
    assert_eq!(Reversibility::NoEffect.as_str(), "no_effect");
}

#[test]
fn effect_scope_resource_declarations_must_not_mix_boundaries() {
    let process = ToolAssessment::new(Risk::NeedsHuman).with_effect(EffectDescriptor::new(
        EffectScope::ProcessRead,
        Reversibility::NoEffect,
    ));
    let process = ToolAssessment {
        argv: vec!["inspect".into()],
        ..process
    };
    assert!(process.validate_effect().is_ok());
    let process_with_write = ToolAssessment {
        write_paths: vec![ws().join("write.txt")],
        ..process.clone()
    };
    assert!(process_with_write.validate_effect().is_err());
    let external_read = ToolAssessment::new(Risk::NeedsHuman)
        .with_effect(EffectDescriptor::new(
            EffectScope::ExternalRead,
            Reversibility::NoEffect,
        ))
        .host("example.com");
    assert!(external_read.validate_effect().is_ok());
    let external_with_argv = ToolAssessment {
        argv: vec!["curl".into()],
        ..external_read.clone()
    };
    assert!(external_with_argv.validate_effect().is_err());
    let external_with_cwd = ToolAssessment {
        cwd: Some(ws()),
        ..external_read
    };
    assert!(external_with_cwd.validate_effect().is_err());
}

#[tokio::test]
async fn model_cannot_invoke_reserved_internal_checkpoint_capabilities() {
    let root = temp_path("reserved-capability");
    std::fs::create_dir_all(&root).expect("create workspace");
    let mut config = Config::embedded().expect("config");
    config.boundary.workspace = root.clone();
    config.boundary.readable_roots = vec![root.clone()];
    config.boundary.writable_roots = vec![root.clone()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    let contract = GoalContract::from_config("reserved capability", &config).expect("contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(OneShotProvider {
        responses: Mutex::new(VecDeque::from([
            ChatResponse {
                messages: vec![Message::assistant_calls(
                    "",
                    vec![ToolCall::new("rollback", json!({}))],
                )],
                usage: Usage::default(),
            },
            ChatResponse {
                messages: vec![Message::assistant_calls(
                    "",
                    vec![ToolCall::new("finish", json!({"status": "complete"}))],
                )],
                usage: Usage::default(),
            },
        ])),
    });
    let tool = Arc::new(ReservedTool {
        executions: AtomicUsize::new(0),
    });
    let sink = Arc::new(MemSink::default());
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        tool.clone(),
        Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            vec![],
        )),
        sink.clone(),
    )
    .expect("agent");

    let _ = agent.run().await.expect("run");
    assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
    let events = sink.snapshot();
    assert!(
        events
            .iter()
            .any(|event| event.kind == EventKind::ToolBlocked
                && event.tool.as_deref() == Some("rollback")),
        "events: {events:?}"
    );
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn phase1_missing_effect_fails_closed_before_policy_and_executor() {
    let root = temp_path("missing-effect");
    std::fs::create_dir_all(&root).expect("create workspace");
    let rule = Rule::allow("allow-test", "test_tool", "test action");
    let mut config = Config::embedded().expect("config");
    config.boundary.workspace = root.clone();
    config.boundary.readable_roots = vec![root.clone()];
    config.boundary.writable_roots = vec![root.clone()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.rules = vec![rule.clone()];
    let contract = GoalContract::from_config("effect test", &config).expect("contract");
    let policy = Arc::new(Policy::new(vec![rule]).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(OneShotProvider {
        responses: Mutex::new(VecDeque::from([
            ChatResponse {
                messages: vec![Message::assistant_calls(
                    "",
                    vec![ToolCall::new("test_tool", json!({}))],
                )],
                usage: Usage::default(),
            },
            ChatResponse {
                messages: vec![Message::assistant_calls(
                    "",
                    vec![ToolCall::new("finish", json!({"status": "complete"}))],
                )],
                usage: Usage::default(),
            },
        ])),
    });
    let sink = Arc::new(MemSink::default());
    let tool = Arc::new(MissingEffectTool {
        executions: AtomicUsize::new(0),
    });
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        tool.clone(),
        Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            Vec::new(),
        )),
        sink.clone(),
    )
    .expect("agent");

    let outcome = agent.run().await.expect("run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
    let events = sink.snapshot();
    assert!(events.iter().any(|event| {
        event.kind == EventKind::ToolBlocked && event.message.contains("EffectDescriptor")
    }));
    assert!(!events
        .iter()
        .any(|event| event.kind == EventKind::PolicyDecision));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn phase1_checkpoint_contract_is_opt_in_and_binds_effective_root() {
    let root = temp_path("checkpoint-contract");
    std::fs::create_dir_all(&root).expect("create workspace");
    let mut config = Config::embedded().expect("config");
    config.boundary.workspace = root.clone();
    config.boundary.readable_roots = vec![root.clone()];
    config.boundary.writable_roots = vec![root.clone()];
    let legacy_digest = config.boundary_digest();
    config.checkpoint.enabled = true;
    config.validate().expect("enabled checkpoint config");
    assert_ne!(legacy_digest, config.boundary_digest());
    let contract = GoalContract::from_config("checkpoint", &config).expect("contract");
    assert!(contract.checkpoint.enabled);
    assert!(contract.checkpoint.artifact_root.is_absolute());
    assert!(contract.checkpoint.rollback_requires_approval);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn phase1_artifact_session_failed_path_and_rollback_records_validate() {
    let workspace = std::env::current_dir().expect("workspace");
    let mut artifact = CheckpointArtifact::new(
        "checkpoint-1",
        "run-1",
        "session-1",
        "node-1",
        phase1_event_ref(),
        workspace,
        phase1_digest(),
        phase1_digest(),
        phase1_digest(),
    );
    artifact.file_entries.push(CheckpointFileEntry::file(
        "src/main.rs",
        3,
        phase1_digest(),
        "blob-1",
    ));
    artifact
        .validate_limits(10, 2, 10)
        .expect("artifact limits");
    let encoded = serde_json::to_string(&artifact).expect("serialize artifact");
    let decoded: CheckpointArtifact = serde_json::from_str(&encoded).expect("decode artifact");
    assert_eq!(decoded, artifact);

    let mut node = SessionNode::new("node-1", phase1_event_ref(), Some("checkpoint-1".into()));
    node.parent_session_node_id = Some("node-0".into());
    node.applied_rollback_ids.push("rollback-1".into());
    node.validate().expect("session node");

    let mut failed = FailedPathRecord {
        schema_version: 1,
        failure_id: "failure-1".into(),
        failure_class: FailureClass::ToolFailed,
        tool: "write_file".into(),
        canonical_args_digest: phase1_digest(),
        resource_digest: phase1_digest(),
        contract_digest: phase1_digest(),
        policy_digest: phase1_digest(),
        attempt_count: 1,
        first_seen_event_ref: phase1_event_ref(),
        last_seen_event_ref: phase1_event_ref(),
        run_id: "run-1".into(),
        status: FailedPathStatus::Active,
        superseded_by: None,
    };
    failed.validate().expect("failed path");
    failed.mark_superseded("failure-2").expect("supersede");
    assert_eq!(failed.status, FailedPathStatus::Superseded);
    assert!(serde_json::to_string(&failed)
        .expect("serialize failed path")
        .contains("failure-2"));

    let rollback = RollbackRequest {
        rollback_id: "rollback-1".into(),
        checkpoint_id: "checkpoint-1".into(),
        source_session_node_id: "node-1".into(),
        reason: "recover from failed path".into(),
        failed_path_ref: Some("failure-1".into()),
        requested_by: "operator".into(),
    };
    rollback.validate().expect("rollback request");
}

#[tokio::test]
async fn phase2_event_tee_rejects_inconsistent_durable_receipts() {
    let first = Arc::new(MemSink::default());
    let second = Arc::new(MemSink::default());
    second
        .emit(pangu_core::Event::new_v2(
            EventKind::Note,
            0,
            "different durable position",
        ))
        .await
        .unwrap();
    let tee = TeeSink::new(vec![first, second]);
    let result = tee
        .emit_with_receipt(pangu_core::Event::new_v2(
            EventKind::Note,
            0,
            "must not be accepted with divergent receipts",
        ))
        .await;
    assert!(result.is_err());
}

/// Regression guard for a CI-only failure.
///
/// `Journal::create` refuses a path that already exists so a previous chain is
/// never overwritten, and the tests used to derive their path from the process
/// id plus a per-process counter. Once the id wrapped around, a run inherited a
/// leftover journal and the fail-closed error surfaced as a test failure. The
/// two properties together are the contract: the path must be unique, and a
/// collision must stay a refusal rather than a silent overwrite.
#[test]
fn test_paths_are_unique_and_journal_creation_refuses_an_existing_path() {
    use pangu_core::Event;

    let first = temp_path("uniqueness");
    let second = temp_path("uniqueness");
    assert_ne!(first, second, "temp_path must not repeat a path");

    let path = temp_path("journal-refusal");
    let journal = Journal::create_v2(&path).expect("create a journal");
    drop(journal);
    let refusal = Journal::create_v2(&path)
        .err()
        .expect("creating over an existing journal must be refused");
    assert!(
        refusal.to_string().contains("already exists"),
        "the refusal must say why: {refusal}"
    );
    assert_ne!(path, temp_path("journal-refusal-other"));
    let _ = std::fs::remove_dir_all(&path);
    let _ = Event::new_v2(EventKind::Note, 0, "unused");
}

#[test]
fn phase1_journal_v1_v2_and_unknown_schema_are_explicit() {
    use pangu_core::Event;

    let v2_path = temp_path("journal-v2");
    let journal = Journal::create_v2(&v2_path).expect("create v2 journal");
    let sealed = journal
        .record(&Event::new_v2(
            EventKind::CheckpointCreated,
            0,
            "checkpoint created",
        ))
        .expect("record v2 event");
    assert_eq!(sealed.schema.as_deref(), Some(JOURNAL_FORMAT_V2));
    assert!(sealed.event_id.is_some());
    drop(journal);
    let replayed = pangu_core::replay::read(&v2_path).expect("replay v2");
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].event_id, sealed.event_id);
    assert!(std::fs::read_to_string(&v2_path)
        .expect("read v2 bytes")
        .contains("pangu-journal/v2"));
    let appended = Journal::append_to_v2(&v2_path).expect("append v2");
    appended
        .record(&Event::new_v2(EventKind::RunFinished, 1, "done"))
        .expect("append v2 event");
    drop(appended);
    assert_eq!(pangu_core::replay::read(&v2_path).unwrap().len(), 2);

    let v1_path = temp_path("journal-v1");
    let v1 = Journal::create(&v1_path).expect("create v1 journal");
    let mut legacy_event = Event::new(EventKind::RunStarted, 0, "start");
    legacy_event.effect_scope = Some("workspace".into());
    legacy_event.reversibility = Some("no_effect".into());
    legacy_event.action_digest = Some(phase1_digest());
    legacy_event.external_mutation = Some(false);
    v1.record(&legacy_event).expect("record v1 event");
    assert!(v1
        .record(&Event::new_v2(EventKind::RollbackRequested, 1, "rollback"))
        .is_err());
    let v1_bytes = std::fs::read_to_string(&v1_path).expect("read v1 bytes");
    assert!(!v1_bytes.contains("pangu-journal/v2"));
    assert!(!v1_bytes.contains("event_id"));
    assert!(!v1_bytes.contains("effect_scope"));
    assert!(!v1_bytes.contains("action_digest"));
    drop(v1);
    assert!(Journal::append_to_v2(&v1_path).is_err());

    let mut unknown = Event::new_v2(EventKind::Note, 0, "unknown");
    unknown.schema = Some("pangu-journal/v999".into());
    assert!(pangu_core::replay::verify(&[unknown]).is_err());
}

struct Phase2Tool {
    path: std::path::PathBuf,
    executions: AtomicUsize,
    external: bool,
    fail_execution: bool,
}

#[async_trait]
impl ToolExecutor for Phase2Tool {
    fn specs(&self) -> Vec<ToolSpec> {
        vec![
            ToolSpec::new("test_tool", "phase2 test tool", json!({"type": "object"})),
            ToolSpec::new("finish", "finish", json!({"type": "object"})),
        ]
    }

    async fn assess(&self, call: &ToolCall, _sandbox: &Sandbox) -> Result<ToolAssessment> {
        let (risk, scope, reversibility) = if self.external
            || call
                .args
                .get("external")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            (
                Risk::Destructive,
                EffectScope::ExternalMutation,
                Reversibility::Irreversible,
            )
        } else {
            (
                Risk::Reversible,
                EffectScope::Workspace,
                Reversibility::Reversible,
            )
        };
        Ok(ToolAssessment::new(risk)
            .with_effect(EffectDescriptor::new(scope, reversibility))
            .write(self.path.clone()))
    }

    async fn execute(&self, action: &VerifiedAction) -> Result<ToolOutput> {
        self.executions.fetch_add(1, Ordering::Relaxed);
        if self.fail_execution {
            anyhow::bail!("synthetic phase2 failure");
        }
        let value = action
            .call()
            .args
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("changed");
        std::fs::write(&self.path, value)?;
        Ok(ToolOutput::evidenced("phase2 evidence", "phase2-evidence"))
    }
}

fn phase2_config(workspace: &std::path::Path, rules: Vec<Rule>) -> Config {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = workspace.to_path_buf();
    config.boundary.readable_roots = vec![workspace.to_path_buf()];
    config.boundary.writable_roots = vec![workspace.to_path_buf()];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.checkpoint.enabled = true;
    config.checkpoint.artifact_root = workspace.join(".pangu/checkpoints");
    config.rules = rules;
    config.validate().expect("phase2 config");
    config
}

fn phase2_response(tool: &str, args: Value) -> ChatResponse {
    ChatResponse {
        messages: vec![Message::assistant_calls(
            "",
            vec![ToolCall::new(tool, args)],
        )],
        usage: Usage::default(),
    }
}

fn phase2_finish() -> ChatResponse {
    phase2_response("finish", json!({"status": "complete"}))
}

fn phase2_agent(
    config: Config,
    workspace: &std::path::Path,
    responses: Vec<ChatResponse>,
    approvals: Vec<pangu_boundary::ApprovalResponse>,
    external: bool,
    fail_execution: bool,
) -> (Agent, Arc<Phase2Tool>, Arc<MemSink>) {
    let contract = GoalContract::from_config("phase2 invariant", &config).expect("contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(OneShotProvider {
        responses: Mutex::new(VecDeque::from(responses)),
    });
    let tool = Arc::new(Phase2Tool {
        path: workspace.join("state.txt"),
        executions: AtomicUsize::new(0),
        external,
        fail_execution,
    });
    let approval = Arc::new(ScriptedApproval::new(
        config.boundary.approval.mode,
        approvals,
    ));
    let sink = Arc::new(MemSink::default());
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        tool.clone(),
        approval,
        sink.clone(),
    )
    .expect("agent");
    (agent, tool, sink)
}

fn phase2_artifact(workspace: &std::path::Path, checkpoint_id: &str) -> CheckpointArtifact {
    CheckpointArtifact::new(
        checkpoint_id,
        "run-phase2",
        "session-phase2",
        format!("node-{checkpoint_id}"),
        EventRef::new(format!("event-{checkpoint_id}"), "run-phase2"),
        workspace.to_path_buf(),
        phase1_digest(),
        phase1_digest(),
        "0".repeat(64),
    )
}

fn phase2_request(workspace: &std::path::Path, store_root: &std::path::Path) -> SnapshotRequest {
    SnapshotRequest::new(
        workspace.to_path_buf(),
        vec![workspace.to_path_buf()],
        vec![store_root.to_path_buf()],
        vec!["**/.git/**".into()],
        SnapshotLimits::default(),
    )
}

#[tokio::test]
async fn invariant_i_checkpoint_after_verified_action() {
    let root = temp_path("checkpoint-after-success");
    std::fs::create_dir_all(&root).expect("workspace");
    let config = phase2_config(
        &root,
        vec![Rule::allow(
            "allow-phase2",
            "test_tool",
            "phase2 test action",
        )],
    );
    let (agent, tool, sink) = phase2_agent(
        config,
        &root,
        vec![
            phase2_response("test_tool", json!({"value": "one"})),
            phase2_response("test_tool", json!({"value": "two"})),
            phase2_finish(),
        ],
        Vec::new(),
        false,
        false,
    );
    let outcome = agent.run().await.expect("run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Complete);
    assert_eq!(tool.executions.load(Ordering::Relaxed), 2);

    let events = sink.snapshot();
    let mut last_success = None;
    let mut checkpoint_count = 0;
    for (index, event) in events.iter().enumerate() {
        if event.kind == EventKind::ToolFinished
            && event
                .payload
                .as_ref()
                .and_then(|payload| payload.get("ok"))
                .and_then(Value::as_bool)
                == Some(true)
        {
            last_success = Some(index);
            assert_eq!(event.schema.as_deref(), Some(JOURNAL_FORMAT_V2));
        }
        if event.kind == EventKind::CheckpointCreated {
            assert!(
                last_success.is_some(),
                "checkpoint preceded successful ToolFinished"
            );
            assert_eq!(event.schema.as_deref(), Some(JOURNAL_FORMAT_V2));
            checkpoint_count += 1;
        }
    }
    assert_eq!(checkpoint_count, 2);
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn invariant_i_checkpoint_not_created_for_failed_tool_or_finish() {
    let root = temp_path("checkpoint-after-failure");
    std::fs::create_dir_all(&root).expect("workspace");
    let config = phase2_config(
        &root,
        vec![Rule::allow(
            "allow-phase2",
            "test_tool",
            "phase2 test action",
        )],
    );
    let (agent, _, sink) = phase2_agent(
        config,
        &root,
        vec![
            phase2_response("test_tool", json!({})),
            phase2_response("finish", json!({"status": "failed"})),
        ],
        Vec::new(),
        false,
        true,
    );
    let outcome = agent.run().await.expect("run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert!(!sink
        .snapshot()
        .iter()
        .any(|event| event.kind == EventKind::CheckpointCreated));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn invariant_i_checkpoint_atomic_requires_commit_marker() {
    let root = temp_path("checkpoint-atomic");
    std::fs::create_dir_all(&root).expect("workspace");
    std::fs::write(root.join("state.txt"), "before").expect("state");
    let store_root = root.join(".pangu/checkpoints");
    let store = ArtifactStore::open(&store_root).expect("store");
    let request = phase2_request(&root, &store_root);
    let target = phase2_artifact(&root, "cp-atomic");
    let node = SessionNode::new(
        target.session_node_id.clone(),
        target.event_ref.clone(),
        Some(target.checkpoint_id.clone()),
    );
    let committed = store
        .commit_snapshot_with_node(&request, target, Some(&node))
        .expect("commit");
    assert!(store.load_checkpoint(&committed.checkpoint_id).is_ok());
    std::fs::remove_file(
        store
            .root()
            .join(&committed.checkpoint_id)
            .join("COMMITTED"),
    )
    .expect("remove marker");
    assert!(store.load_checkpoint(&committed.checkpoint_id).is_err());
    assert!(store
        .restore_checkpoint(&request, &committed, "atomic-restore")
        .is_err());
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn invariant_i_rollback_trigger_is_typed_and_not_a_model_tool() {
    let specs = Toolkit::new().specs();
    assert!(specs.iter().all(|spec| spec.name != "rollback"));
    assert!(specs.iter().all(|spec| spec.name != "checkpoint"));

    let root = temp_path("rollback-trigger");
    std::fs::create_dir_all(&root).expect("workspace");
    std::fs::write(root.join("state.txt"), "unchanged").expect("state");
    let config = phase2_config(&root, Vec::new());
    let (agent, _, _) = phase2_agent(config, &root, Vec::new(), Vec::new(), false, false);
    let result = agent
        .rollback(RollbackRequest {
            rollback_id: "typed-rollback".into(),
            checkpoint_id: "missing-checkpoint".into(),
            source_session_node_id: "missing-node".into(),
            reason: " ".into(),
            failed_path_ref: None,
            requested_by: "operator".into(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(
        std::fs::read_to_string(root.join("state.txt")).unwrap(),
        "unchanged"
    );
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn invariant_i_irreversible_external_mutation_requires_human() {
    let root = temp_path("irreversible-human");
    std::fs::create_dir_all(&root).expect("workspace");
    let config = phase2_config(
        &root,
        vec![Rule::allow(
            "allow-external",
            "test_tool",
            "external test action",
        )],
    );
    let (agent, tool, sink) = phase2_agent(
        config,
        &root,
        vec![
            phase2_response("test_tool", json!({"external": true})),
            phase2_response("finish", json!({"status": "failed"})),
        ],
        vec![pangu_boundary::ApprovalResponse::Deny],
        true,
        false,
    );
    let outcome = agent.run().await.expect("run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
    assert!(!root.join(".pangu/checkpoints/effects.jsonl").exists());
    assert!(sink
        .snapshot()
        .iter()
        .any(|event| event.kind == EventKind::ApprovalResolved
            && event.verdict.as_deref() == Some("deny")));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn invariant_i_rollback_scope_blocks_external_effect_without_compensation() {
    let root = temp_path("rollback-scope");
    std::fs::create_dir_all(&root).expect("workspace");
    std::fs::write(root.join("state.txt"), "before").expect("state");
    let store_root = root.join(".pangu/checkpoints");
    let store = ArtifactStore::open(&store_root).expect("store");
    let request = phase2_request(&root, &store_root);
    let target = store
        .commit_snapshot(&request, phase2_artifact(&root, "cp-scope"))
        .expect("snapshot");
    std::fs::write(root.join("state.txt"), "after").expect("change");
    let mut effect_event = EventRef::new("evt-effect", "run-phase2");
    effect_event.seq = Some(1);
    store
        .record_effect(&EffectRecord {
            schema_version: pangu_core::ARTIFACT_STORE_SCHEMA_VERSION,
            effect_id: "effect-phase2".into(),
            run_id: "run-phase2".into(),
            action_digest: phase1_digest(),
            effect_scope: "external_mutation".into(),
            reversibility: "irreversible".into(),
            external_mutation: true,
            event_ref: effect_event,
            recorded_at: "2026-01-01T00:00:00Z".into(),
        })
        .expect("record effect");
    let expected = store.compute_workspace_digest(&request).expect("digest");
    assert!(store
        .restore_checkpoint_with_expected(&request, &target, "scope-rollback", &expected)
        .is_err());
    assert_eq!(
        std::fs::read_to_string(root.join("state.txt")).unwrap(),
        "after"
    );
    assert!(
        store_root.exists(),
        "rollback must not delete its own artifact store"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn invariant_i_rollback_idempotent_returns_same_operation() {
    let root = temp_path("rollback-idempotent");
    std::fs::create_dir_all(&root).expect("workspace");
    std::fs::write(root.join("state.txt"), "before").expect("state");
    let store_root = root.join(".pangu/checkpoints");
    let store = ArtifactStore::open(&store_root).expect("store");
    let request = phase2_request(&root, &store_root);
    let target = store
        .commit_snapshot(&request, phase2_artifact(&root, "cp-idempotent"))
        .expect("snapshot");
    std::fs::write(root.join("state.txt"), "after").expect("change");
    let expected = store.compute_workspace_digest(&request).expect("digest");
    let first = store
        .restore_checkpoint_with_expected(&request, &target, "same-rollback", &expected)
        .expect("first restore");
    let second = store
        .restore_checkpoint_with_expected(&request, &target, "same-rollback", &expected)
        .expect("repeat restore");
    assert_eq!(first.disposition, RestoreDisposition::Applied);
    assert_eq!(second.disposition, RestoreDisposition::AlreadyApplied);
    assert_eq!(first.operation.rollback_id, second.operation.rollback_id);
    assert_eq!(first.operation.status, RollbackOperationStatus::Applied);
    assert_eq!(
        std::fs::read_to_string(root.join("state.txt")).unwrap(),
        "before"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn invariant_i_failed_rollback_operation_is_not_retried() {
    let root = temp_path("failed-rollback-operation");
    std::fs::create_dir_all(&root).expect("workspace");
    let state = root.join("state.txt");
    std::fs::write(&state, "before").expect("state");
    let store_root = root.join(".pangu/checkpoints");
    let store = ArtifactStore::open(&store_root).expect("store");
    let request = phase2_request(&root, &store_root);
    let target = store
        .commit_snapshot(&request, phase2_artifact(&root, "cp-failed-operation"))
        .expect("snapshot");
    std::fs::write(&state, "after").expect("change");
    let expected_current = store
        .compute_workspace_digest(&request)
        .expect("current digest");
    let operation = RollbackOperation {
        schema_version: ROLLBACK_OPERATION_SCHEMA_VERSION,
        rollback_id: "failed-rollback".into(),
        checkpoint_id: target.checkpoint_id.clone(),
        status: RollbackOperationStatus::Failed,
        workspace_digest: expected_current.clone(),
        transition_session_node_id: None,
        transition_event_ref: None,
        error: Some("simulated restore failure".into()),
        created_at: "2026-01-01T00:00:00Z".into(),
        completed_at: Some("2026-01-01T00:00:01Z".into()),
    };
    let operations = store.root().join("operations");
    std::fs::create_dir_all(&operations).expect("operations directory");
    std::fs::write(
        operations.join("failed-rollback.json"),
        serde_json::to_vec(&operation).expect("serialize operation"),
    )
    .expect("write operation");

    let error = store
        .restore_checkpoint_with_expected(&request, &target, "failed-rollback", &expected_current)
        .expect_err("failed operation must not retry");
    assert!(error.to_string().contains("previously failed"));
    assert_eq!(std::fs::read_to_string(&state).unwrap(), "after");
    let loaded = store
        .load_operation(&target.checkpoint_id, "failed-rollback")
        .expect("load operation")
        .expect("operation exists");
    assert_eq!(loaded.status, RollbackOperationStatus::Failed);
    assert_eq!(loaded.error.as_deref(), Some("simulated restore failure"));
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn invariant_i_failed_path_not_repeated() {
    let root = temp_path("failed-path-not-repeated");
    std::fs::create_dir_all(&root).expect("workspace");
    let config = phase2_config(
        &root,
        vec![Rule::allow(
            "allow-phase2",
            "test_tool",
            "phase2 test action",
        )],
    );
    let (agent, tool, sink) = phase2_agent(
        config,
        &root,
        vec![
            phase2_response("test_tool", json!({"value": "same"})),
            phase2_response("test_tool", json!({"value": "same"})),
            phase2_response("finish", json!({"status": "failed"})),
        ],
        Vec::new(),
        false,
        true,
    );
    let outcome = agent.run().await.expect("run");
    assert_eq!(outcome.status, pangu_boundary::GoalStatus::Failed);
    assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
    let events = sink.snapshot();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == EventKind::ToolStarted)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == EventKind::FailedPathRecorded)
            .count(),
        2
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn invariant_i_no_implicit_git_checkpoint_backend() {
    let root = temp_path("no-implicit-git");
    std::fs::create_dir_all(&root).expect("workspace");
    let mut config = phase2_config(
        &root,
        vec![Rule::allow(
            "allow-phase2",
            "test_tool",
            "phase2 test action",
        )],
    );
    config.checkpoint.backend = CheckpointBackend::Git;
    config
        .validate()
        .expect("git backend is explicit config, not implicit");
    let contract = GoalContract::from_config("git backend", &config).expect("contract");
    let policy = Arc::new(Policy::new(config.rules.clone()).expect("policy"));
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary).expect("sandbox"));
    let provider = Arc::new(OneShotProvider {
        responses: Mutex::new(VecDeque::new()),
    });
    let result = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::new()),
        Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            Vec::new(),
        )),
        Arc::new(MemSink::default()),
    );
    assert!(
        result.is_err(),
        "git backend must not become an implicit capability"
    );
    std::fs::remove_dir_all(root).ok();
}
