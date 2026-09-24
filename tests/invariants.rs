//! 不变量测试矩阵 —— 对应 `docs/BOUNDARY.md` §4 Invariants。
//!
//! 每个函数测试一条或一组不变量；PR 时必须同时修改对应的代码和测试，否则视为回归。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use pangu_agent::{Agent, Provider};
use pangu_boundary::policy::{ActionRequest, Effect, Policy, Rule};
use pangu_boundary::risk::Risk;
use pangu_boundary::{ApprovalMode, Config, GoalContract, Sandbox, ScriptedApproval};
use pangu_core::{ChatResponse, EventKind, MemSink, Message, ToolCall, ToolSpec, Usage, Value};
use pangu_toolkit::Toolkit;
use serde_json::json;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "pangu-invariant-{label}-{}-{}",
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
