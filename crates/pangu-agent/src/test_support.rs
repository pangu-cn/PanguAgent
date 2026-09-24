#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::{Agent, Provider, ToolAssessment, ToolExecutor, ToolOutput, VerifiedAction};
    use pangu_boundary::{
        ApprovalMode, ApprovalResponse, Config, GoalContract, GoalStatus, Policy, Risk, Rule,
        Sandbox, ScriptedApproval,
    };
    use pangu_core::{ChatResponse, Event, MemSink, Message, ToolCall, ToolSpec, Usage};

    struct ScriptedProvider {
        responses: Mutex<VecDeque<ChatResponse>>,
        fail: bool,
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        fn name(&self) -> &str {
            "test"
        }

        fn model(&self) -> &str {
            "test-model"
        }

        fn describe(&self) -> String {
            "test provider".into()
        }

        async fn chat(
            &self,
            _messages: Vec<Message>,
            _tools: Vec<ToolSpec>,
        ) -> Result<ChatResponse> {
            if self.fail {
                anyhow::bail!("synthetic provider failure")
            }
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| response(vec![finish_call()], Usage::default())))
        }
    }

    struct CountingTool {
        executions: AtomicUsize,
        risk: Risk,
        fail_execution: bool,
        output: String,
    }

    #[async_trait]
    impl ToolExecutor for CountingTool {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![
                ToolSpec::new("test_tool", "test", serde_json::json!({"type": "object"})),
                ToolSpec::new("finish", "finish", serde_json::json!({"type": "object"})),
            ]
        }

        async fn assess(&self, _call: &ToolCall, _sandbox: &Sandbox) -> Result<ToolAssessment> {
            Ok(ToolAssessment::new(self.risk))
        }

        async fn execute(&self, _action: &VerifiedAction) -> Result<ToolOutput> {
            self.executions.fetch_add(1, Ordering::Relaxed);
            if self.fail_execution {
                anyhow::bail!("synthetic tool failure")
            } else {
                Ok(ToolOutput::evidenced(self.output.clone(), "test-evidence"))
            }
        }
    }

    static TEST_ROOT_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct SetupOptions {
        rules: Vec<Rule>,
        risk: Risk,
        responses: Vec<ChatResponse>,
        approvals: Vec<ApprovalResponse>,
        fail_execution: bool,
        output: String,
        input_limit: Option<u64>,
        provider_error: bool,
        price_configured: bool,
    }

    impl Default for SetupOptions {
        fn default() -> Self {
            Self {
                rules: Vec::new(),
                risk: Risk::ReadOnly,
                responses: vec![
                    response(vec![tool_call()], Usage::default()),
                    response(vec![finish_call()], Usage::default()),
                ],
                approvals: Vec::new(),
                fail_execution: false,
                output: "ok".into(),
                input_limit: None,
                provider_error: false,
                price_configured: true,
            }
        }
    }

    fn setup(options: SetupOptions) -> (Agent, Arc<CountingTool>, Arc<MemSink>, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "pangu-agent-test-{}-{}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.rules = options.rules.clone();
        // The in-process test provider is free; make that pricing explicit so
        // the cost gate does not treat a scripted provider as unbudgeted.
        if options.price_configured {
            config.model.input_usd_per_mtok = Some(0.0);
            config.model.output_usd_per_mtok = Some(0.0);
        } else {
            config.model.input_usd_per_mtok = None;
            config.model.output_usd_per_mtok = None;
        }
        if let Some(limit) = options.input_limit {
            config.budget.max_input_tokens = limit;
        }
        let contract = GoalContract::from_config("test goal", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(options.rules).unwrap());
        let tool = Arc::new(CountingTool {
            executions: AtomicUsize::new(0),
            risk: options.risk,
            fail_execution: options.fail_execution,
            output: options.output,
        });
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(options.responses.into()),
            fail: options.provider_error,
        });
        let approval = Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            options.approvals,
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
        .unwrap();
        (agent, tool, sink, root)
    }

    fn tool_call() -> ToolCall {
        ToolCall::new("test_tool", serde_json::json!({}))
    }

    fn finish_call() -> ToolCall {
        ToolCall::new("finish", serde_json::json!({"status": "complete"}))
    }

    fn response(calls: Vec<ToolCall>, usage: Usage) -> ChatResponse {
        ChatResponse {
            messages: vec![Message::assistant_calls("", calls)],
            usage,
        }
    }

    fn clean(root: PathBuf) {
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn denied_action_never_reaches_executor() {
        let (agent, tool, sink, root) = setup(SetupOptions::default());
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        assert!(sink.snapshot().iter().any(|event: &Event| {
            event.kind == pangu_core::EventKind::PolicyDecision
                && event.verdict.as_deref() == Some("deny")
        }));
        assert!(!sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolStarted));
        clean(root);
    }

    #[tokio::test]
    async fn invalid_wire_calls_are_redacted_before_history() {
        let invalid = ToolCall {
            id: "token=super-secret".into(),
            name: "bad\nname".into(),
            args: serde_json::json!({}),
        };
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-all", "*", "test action")],
            responses: vec![
                response(vec![invalid], Usage::default()),
                response(vec![finish_call()], Usage::default()),
            ],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        assert!(!format!("{:?}", outcome.messages).contains("super-secret"));
        assert!(!format!("{:?}", sink.snapshot()).contains("super-secret"));
        clean(root);
    }

    #[tokio::test]
    async fn unadvertised_tool_never_reaches_executor() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-all", "*", "test action")],
            responses: vec![
                response(
                    vec![ToolCall::new("hidden_tool", serde_json::json!({}))],
                    Usage::default(),
                ),
                response(vec![finish_call()], Usage::default()),
            ],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolBlocked));
        clean(root);
    }

    #[tokio::test]
    async fn sensitive_tool_output_is_redacted_before_history_and_events() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            output: "token=super-secret".into(),
            ..SetupOptions::default()
        };
        let (agent, _tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        assert!(!outcome
            .messages
            .iter()
            .any(|message| format!("{message:?}").contains("super-secret")));
        assert!(!sink
            .snapshot()
            .iter()
            .any(|event: &Event| format!("{event:?}").contains("super-secret")));
        clean(root);
    }

    #[tokio::test]
    async fn complete_without_successful_evidence_is_failed() {
        let options = SetupOptions {
            responses: vec![response(vec![finish_call()], Usage::default())],
            ..SetupOptions::default()
        };
        let (agent, tool, _sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        clean(root);
    }

    #[tokio::test]
    async fn successful_tool_can_support_complete() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        assert_eq!(outcome.evidence.len(), 1);
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolStarted));
        clean(root);
    }

    #[tokio::test]
    async fn approval_denial_blocks_execution() {
        let options = SetupOptions {
            rules: vec![Rule::ask("ask-test", "test_tool", "human gate")],
            risk: Risk::Reversible,
            approvals: vec![ApprovalResponse::Deny],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolBlocked));
        clean(root);
    }

    #[tokio::test]
    async fn explicit_approval_allows_execution() {
        let options = SetupOptions {
            rules: vec![Rule::ask("ask-test", "test_tool", "human gate")],
            risk: Risk::Reversible,
            approvals: vec![ApprovalResponse::AllowOnce],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ApprovalResolved));
        clean(root);
    }

    #[tokio::test]
    async fn approval_abort_produces_aborted_status() {
        let options = SetupOptions {
            rules: vec![Rule::ask("ask-test", "test_tool", "human gate")],
            risk: Risk::Reversible,
            approvals: vec![ApprovalResponse::Abort("operator stopped".into())],
            ..SetupOptions::default()
        };
        let (agent, tool, _sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Aborted);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        clean(root);
    }

    #[tokio::test]
    async fn budget_exhaustion_prevents_execution() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            input_limit: Some(1000),
            responses: vec![response(
                vec![tool_call()],
                Usage {
                    input_tokens: 1001,
                    output_tokens: 0,
                    cache_read_tokens: 0,
                },
            )],
            ..SetupOptions::default()
        };
        let (agent, tool, _sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::BudgetExhausted);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        clean(root);
    }

    #[tokio::test]
    async fn missing_price_stops_before_provider_request() {
        let options = SetupOptions {
            price_configured: false,
            ..SetupOptions::default()
        };
        let (agent, _tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::BudgetExhausted);
        assert!(!sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ModelRequest));
        clean(root);
    }

    #[tokio::test]
    async fn provider_failure_emits_terminal_event_and_returns_error() {
        let options = SetupOptions {
            provider_error: true,
            ..SetupOptions::default()
        };
        let (agent, _tool, sink, root) = setup(options);
        assert!(agent.run().await.is_err());
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::RunFinished));
        clean(root);
    }

    #[tokio::test]
    async fn tool_error_is_returned_to_the_model() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            fail_execution: true,
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        assert!(outcome
            .messages
            .iter()
            .any(|message| matches!(message, Message::Tool { is_error: true, .. })));
        assert!(sink
            .snapshot()
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolFinished));
        clean(root);
    }
}
