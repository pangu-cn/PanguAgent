#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::{
        Agent, EffectDescriptor, EffectScope, Provider, Reversibility, ToolAssessment,
        ToolExecutor, ToolOutput, VerifiedAction,
    };
    use pangu_boundary::{
        ApprovalHandler, ApprovalMode, ApprovalRequest, ApprovalResponse, CheckpointFailurePolicy,
        Config, GoalContract, GoalStatus, Policy, Risk, Rule, Sandbox, ScriptedApproval,
    };
    use pangu_core::{
        ArtifactStore, ChatResponse, Event, MemSink, Message, RollbackRequest, ToolCall, ToolSpec,
        Usage,
    };

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
        omit_effect: bool,
        declared_write: PathBuf,
    }

    struct MutatingTool {
        path: PathBuf,
    }

    struct SlowApproval;

    #[async_trait]
    impl ApprovalHandler for SlowApproval {
        fn mode(&self) -> ApprovalMode {
            ApprovalMode::DestructiveAndAbove
        }

        async fn decide(&self, _request: &ApprovalRequest) -> ApprovalResponse {
            tokio::time::sleep(Duration::from_millis(2_100)).await;
            ApprovalResponse::AllowOnce
        }
    }

    #[async_trait]
    impl ToolExecutor for MutatingTool {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![
                ToolSpec::new("test_tool", "test", serde_json::json!({"type": "object"})),
                ToolSpec::new("finish", "finish", serde_json::json!({"type": "object"})),
            ]
        }

        async fn assess(&self, call: &ToolCall, _sandbox: &Sandbox) -> Result<ToolAssessment> {
            let external = call
                .args
                .get("external")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let (risk, scope, reversibility) = if external {
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
            let value = action
                .call()
                .args
                .get("value")
                .and_then(|value| value.as_str())
                .unwrap_or("changed");
            fs::write(&self.path, value)?;
            Ok(ToolOutput::evidenced("mutated", "mutation-evidence"))
        }
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
            if self.omit_effect {
                return Ok(ToolAssessment::new(self.risk));
            }
            let (scope, reversibility) = match self.risk {
                Risk::ReadOnly => (EffectScope::Workspace, Reversibility::NoEffect),
                Risk::Reversible => (EffectScope::Workspace, Reversibility::Reversible),
                Risk::Destructive | Risk::NeedsHuman => {
                    (EffectScope::Workspace, Reversibility::Irreversible)
                }
            };
            let mut assessment = ToolAssessment::new(self.risk)
                .with_effect(EffectDescriptor::new(scope, reversibility));
            if self.risk != Risk::ReadOnly {
                assessment = assessment.write(self.declared_write.clone());
            }
            Ok(assessment)
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
        omit_effect: bool,
        input_limit: Option<u64>,
        provider_error: bool,
        price_configured: bool,
        checkpoint_enabled: bool,
        checkpoint_failure_policy: CheckpointFailurePolicy,
        approval_mode: ApprovalMode,
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
                omit_effect: false,
                input_limit: None,
                provider_error: false,
                price_configured: true,
                checkpoint_enabled: false,
                checkpoint_failure_policy: CheckpointFailurePolicy::FailRun,
                approval_mode: ApprovalMode::DestructiveAndAbove,
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
        config.checkpoint.enabled = options.checkpoint_enabled;
        config.checkpoint.failure_policy = options.checkpoint_failure_policy;
        if options.checkpoint_enabled {
            config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        }
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
        config.boundary.approval.mode = options.approval_mode;
        let contract = GoalContract::from_config("test goal", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(options.rules).unwrap());
        let tool = Arc::new(CountingTool {
            executions: AtomicUsize::new(0),
            risk: options.risk,
            fail_execution: options.fail_execution,
            output: options.output,
            omit_effect: options.omit_effect,
            declared_write: root.join("tool-effect.txt"),
        });
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(options.responses.into()),
            fail: options.provider_error,
        });
        let approval = Arc::new(ScriptedApproval::new(
            options.approval_mode,
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
    async fn an_equivalent_failed_path_is_blocked_before_reexecution() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            fail_execution: true,
            checkpoint_enabled: true,
            responses: vec![
                response(vec![tool_call()], Usage::default()),
                response(vec![tool_call()], Usage::default()),
                response(vec![finish_call()], Usage::default()),
            ],
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        let events = sink.snapshot();
        assert!(events
            .iter()
            .any(|event| { event.kind == pangu_core::EventKind::FailedPathRecorded }));
        assert!(events.iter().any(|event| {
            event.kind == pangu_core::EventKind::ToolBlocked
                && event.message.contains("equivalent failed path")
        }));
        clean(root);
    }

    #[tokio::test]
    async fn successful_tool_creates_an_opt_in_checkpoint() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            checkpoint_enabled: true,
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        let events = sink.snapshot();
        assert!(events
            .iter()
            .any(|event| event.kind == pangu_core::EventKind::CheckpointCreated));
        let checkpoint_root = root.join(".pangu/checkpoints");
        assert!(checkpoint_root.is_dir());
        let dirs = std::fs::read_dir(&checkpoint_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().is_dir()
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("checkpoint_")
            })
            .collect::<Vec<_>>();
        assert_eq!(dirs.len(), 1);
        clean(root);
    }

    #[tokio::test]
    async fn journal_v2_receipt_is_bound_to_the_published_checkpoint() {
        // Nanoseconds: see the note in tests/invariants.rs. A reused process id
        // plus counter would inherit another run's journal and workspace.
        let root = std::env::temp_dir().join(format!(
            "pangu-agent-journal-receipt-{}-{}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        config.model.input_usd_per_mtok = Some(0.0);
        config.model.output_usd_per_mtok = Some(0.0);
        config.rules = vec![Rule::allow("allow-test", "test_tool", "test action")];
        let contract = GoalContract::from_config("journal receipt", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(config.rules.clone()).unwrap());
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(VecDeque::from([
                response(vec![tool_call()], Usage::default()),
                response(vec![finish_call()], Usage::default()),
            ])),
            fail: false,
        });
        let tool = Arc::new(CountingTool {
            executions: AtomicUsize::new(0),
            risk: Risk::ReadOnly,
            fail_execution: false,
            output: "ok".into(),
            omit_effect: false,
            declared_write: root.join("tool-effect.txt"),
        });
        let approval = Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            Vec::new(),
        ));
        let journal =
            Arc::new(pangu_core::Journal::create_v2(root.join(".pangu/journal-v2.jsonl")).unwrap());
        let agent = Agent::new(
            contract,
            policy,
            sandbox,
            provider,
            tool,
            approval,
            journal.clone(),
        )
        .unwrap();
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        let events = pangu_core::replay::read(journal.path()).unwrap();
        let finished = events
            .iter()
            .find(|event| event.kind == pangu_core::EventKind::ToolFinished)
            .expect("sealed ToolFinished event");
        let created = events
            .iter()
            .find(|event| event.kind == pangu_core::EventKind::CheckpointCreated)
            .expect("checkpoint event");
        let checkpoint_id = created.payload.as_ref().unwrap()["checkpoint_id"]
            .as_str()
            .unwrap();
        let artifact = ArtifactStore::open(root.join(".pangu/checkpoints"))
            .unwrap()
            .load_checkpoint(checkpoint_id)
            .unwrap();
        assert_eq!(
            finished.event_id.as_deref(),
            Some(artifact.event_ref.event_id.as_str())
        );
        assert!(artifact.workspace_digest.is_some());
        clean(root);
    }

    #[tokio::test]
    async fn checkpoint_policy_deny_records_policy_failure_stage() {
        let options = SetupOptions {
            rules: vec![
                Rule::allow("allow-test", "test_tool", "test action"),
                Rule::deny("deny-checkpoint", "checkpoint", "checkpoints are disabled"),
            ],
            checkpoint_enabled: true,
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let error = agent.run().await.unwrap_err();
        assert!(error.to_string().contains("checkpoint creation failed"));
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        let failure = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::CheckpointFailed)
            .expect("checkpoint failure event");
        assert_eq!(
            failure
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("policy"))
        );
        assert!(!root
            .join(".pangu/checkpoints")
            .read_dir()
            .map(|mut entries| entries.any(|entry| entry.is_ok() && entry.unwrap().path().is_dir()))
            .unwrap_or(false));
        clean(root);
    }

    #[tokio::test]
    async fn checkpoint_ask_requires_approval_and_never_mode_fails_closed() {
        let options = SetupOptions {
            rules: vec![
                Rule::allow("allow-test", "test_tool", "test action"),
                Rule::ask("ask-checkpoint", "checkpoint", "checkpoint needs review"),
            ],
            approvals: vec![ApprovalResponse::Deny],
            checkpoint_enabled: true,
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let error = agent.run().await.unwrap_err();
        assert!(error.to_string().contains("checkpoint creation failed"));
        assert_eq!(tool.executions.load(Ordering::Relaxed), 1);
        let failure = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::CheckpointFailed)
            .expect("checkpoint failure event");
        assert_eq!(
            failure
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("approval"))
        );
        clean(root);

        let options = SetupOptions {
            rules: vec![
                Rule::allow("allow-test", "test_tool", "test action"),
                Rule::ask("ask-checkpoint", "checkpoint", "checkpoint needs review"),
            ],
            checkpoint_enabled: true,
            approval_mode: ApprovalMode::Never,
            ..SetupOptions::default()
        };
        let (agent, _tool, sink, root) = setup(options);
        let error = agent.run().await.unwrap_err();
        assert!(error.to_string().contains("checkpoint creation failed"));
        let failure = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::CheckpointFailed)
            .expect("checkpoint failure event");
        assert_eq!(
            failure
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("approval"))
        );
        clean(root);
    }

    #[tokio::test]
    async fn checkpoint_needs_input_policy_stops_after_checkpoint_failure() {
        let options = SetupOptions {
            rules: vec![
                Rule::allow("allow-test", "test_tool", "test action"),
                Rule::deny("deny-checkpoint", "checkpoint", "checkpoints are disabled"),
            ],
            checkpoint_enabled: true,
            checkpoint_failure_policy: CheckpointFailurePolicy::NeedsInput,
            ..SetupOptions::default()
        };
        let (agent, _tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::NeedsInput);
        assert!(sink
            .snapshot()
            .iter()
            .any(|event| event.kind == pangu_core::EventKind::CheckpointFailed));
        clean(root);
    }

    #[tokio::test]
    async fn rollback_restores_an_older_checkpoint_and_is_idempotent() {
        let root = std::env::temp_dir().join(format!(
            "pangu-agent-rollback-test-{}-{}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("state.txt");
        fs::write(&file, "initial").unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        config.model.input_usd_per_mtok = Some(0.0);
        config.model.output_usd_per_mtok = Some(0.0);
        config.rules = vec![
            Rule::allow("allow-test", "test_tool", "test mutation"),
            // An allow rule does not self-approve a destructive rollback; the
            // L4 gate below must still be crossed.
            Rule::allow(
                "allow-rollback",
                "rollback",
                "rollback still needs human gate",
            ),
        ];
        let contract = GoalContract::from_config("rollback test", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(config.rules.clone()).unwrap());
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(VecDeque::from([
                response(
                    vec![ToolCall::new(
                        "test_tool",
                        serde_json::json!({"value": "after"}),
                    )],
                    Usage::default(),
                ),
                response(
                    vec![ToolCall::new(
                        "test_tool",
                        serde_json::json!({"value": "later"}),
                    )],
                    Usage::default(),
                ),
                response(vec![finish_call()], Usage::default()),
            ])),
            fail: false,
        });
        let tool = Arc::new(MutatingTool { path: file.clone() });
        let approval = Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            vec![ApprovalResponse::AllowOnce],
        ));
        let sink = Arc::new(MemSink::default());
        let agent = Agent::new(
            contract,
            policy,
            sandbox,
            provider,
            tool,
            approval.clone(),
            sink.clone(),
        )
        .unwrap();
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        let events = sink.snapshot();
        let checkpoints = events
            .iter()
            .filter(|event| event.kind == pangu_core::EventKind::CheckpointCreated)
            .collect::<Vec<_>>();
        assert_eq!(checkpoints.len(), 2);
        let first = checkpoints[0].payload.as_ref().unwrap();
        let second = checkpoints[1].payload.as_ref().unwrap();
        let request = RollbackRequest {
            rollback_id: "rollback-test-1".into(),
            checkpoint_id: first["checkpoint_id"].as_str().unwrap().into(),
            source_session_node_id: second["session_node_id"].as_str().unwrap().into(),
            reason: "restore the first verified state".into(),
            failed_path_ref: None,
            requested_by: "operator".into(),
        };
        let mut missing_failure_request = request.clone();
        missing_failure_request.rollback_id = "rollback-missing-failure".into();
        missing_failure_request.failed_path_ref = Some("failed-does-not-exist".into());
        let error = agent.rollback(missing_failure_request).await.unwrap_err();
        assert!(error.to_string().contains("failed-path reference"));
        let missing_failure_event = sink
            .snapshot()
            .into_iter()
            .find(|event| {
                event.kind == pangu_core::EventKind::RollbackFailed
                    && event.call_id.as_deref() == Some("rollback-missing-failure")
            })
            .expect("missing failed-path failure event");
        assert_eq!(
            missing_failure_event
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("failed_path"))
        );

        let result = agent.rollback(request.clone()).await.unwrap();
        assert_eq!(approval.seen_ids().len(), 1);
        assert_eq!(result.disposition, pangu_core::RestoreDisposition::Applied);
        let transition_node = result
            .session_node_id
            .as_deref()
            .expect("applied rollback creates a transition node");
        let store = ArtifactStore::open(root.join(".pangu/checkpoints")).unwrap();
        let node = store
            .load_session_node_by_id(transition_node)
            .unwrap()
            .expect("transition node persisted");
        assert_eq!(node.applied_rollback_ids, vec!["rollback-test-1"]);
        assert_eq!(fs::read_to_string(&file).unwrap(), "after");
        // Simulate a crash after the restore/operation commit but before the
        // standalone transition node reached its ledger. The immutable
        // operation binding must repair it on the idempotent retry.
        fs::remove_file(
            root.join(".pangu/checkpoints/sessions")
                .join(format!("{transition_node}.json")),
        )
        .unwrap();
        let repeated = agent.rollback(request).await.unwrap();
        assert_eq!(
            repeated.disposition,
            pangu_core::RestoreDisposition::AlreadyApplied
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "after");
        let repaired = store
            .load_session_node_by_id(transition_node)
            .unwrap()
            .expect("idempotent retry repairs transition node");
        assert_eq!(repaired.applied_rollback_ids, vec!["rollback-test-1"]);
        clean(root);
    }

    #[tokio::test]
    async fn rollback_wall_clock_budget_stops_after_slow_approval() {
        let root = std::env::temp_dir().join(format!(
            "pangu-agent-rollback-budget-{}-{}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("state.txt");
        fs::write(&file, "initial").unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.boundary.subprocess_timeout_secs = 1;
        config.boundary.approval.ask_timeout_secs = 1;
        config.model.request_timeout_secs = Some(1);
        config.budget.max_wall_clock_secs = Duration::from_secs(2);
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        config.model.input_usd_per_mtok = Some(0.0);
        config.model.output_usd_per_mtok = Some(0.0);
        config.rules = vec![
            Rule::allow("allow-test", "test_tool", "test mutation"),
            Rule::allow("allow-rollback", "rollback", "rollback gate"),
        ];
        let contract = GoalContract::from_config("rollback budget", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(config.rules.clone()).unwrap());
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(VecDeque::from([
                response(
                    vec![ToolCall::new(
                        "test_tool",
                        serde_json::json!({"value": "after"}),
                    )],
                    Usage::default(),
                ),
                response(vec![finish_call()], Usage::default()),
            ])),
            fail: false,
        });
        let tool = Arc::new(MutatingTool { path: file.clone() });
        let sink = Arc::new(MemSink::default());
        let agent = Agent::new(
            contract,
            policy,
            sandbox,
            provider,
            tool,
            Arc::new(SlowApproval),
            sink.clone(),
        )
        .unwrap();
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        let checkpoint = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::CheckpointCreated)
            .expect("checkpoint created");
        let payload = checkpoint.payload.as_ref().unwrap();
        let request = RollbackRequest {
            rollback_id: "rollback-budget-1".into(),
            checkpoint_id: payload["checkpoint_id"].as_str().unwrap().into(),
            source_session_node_id: payload["session_node_id"].as_str().unwrap().into(),
            reason: "budget test".into(),
            failed_path_ref: None,
            requested_by: "operator".into(),
        };
        let error = agent.rollback(request).await.unwrap_err();
        assert!(error.to_string().contains("wall-clock budget"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "after");
        let failure = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::RollbackFailed)
            .expect("budget failure event");
        assert_eq!(
            failure
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("budget"))
        );
        clean(root);
    }

    #[tokio::test]
    async fn external_mutation_after_a_checkpoint_blocks_rollback() {
        let root = std::env::temp_dir().join(format!(
            "pangu-agent-external-rollback-{}-{}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("state.txt");
        fs::write(&file, "initial").unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        config.model.input_usd_per_mtok = Some(0.0);
        config.model.output_usd_per_mtok = Some(0.0);
        config.rules = vec![Rule::ask("ask-tool", "test_tool", "human gate")];
        let contract = GoalContract::from_config("external rollback test", &config).unwrap();
        let sandbox = Arc::new(Sandbox::from_config(&config.boundary).unwrap());
        let policy = Arc::new(Policy::new(config.rules.clone()).unwrap());
        let provider = Arc::new(ScriptedProvider {
            responses: Mutex::new(VecDeque::from([
                response(
                    vec![ToolCall::new(
                        "test_tool",
                        serde_json::json!({"value": "checkpoint"}),
                    )],
                    Usage::default(),
                ),
                response(
                    vec![ToolCall::new(
                        "test_tool",
                        serde_json::json!({"value": "external", "external": true}),
                    )],
                    Usage::default(),
                ),
                response(vec![finish_call()], Usage::default()),
            ])),
            fail: false,
        });
        let tool = Arc::new(MutatingTool { path: file.clone() });
        let approval = Arc::new(ScriptedApproval::new(
            ApprovalMode::DestructiveAndAbove,
            vec![ApprovalResponse::AllowOnce, ApprovalResponse::AllowOnce],
        ));
        let sink = Arc::new(MemSink::default());
        let agent = Agent::new(
            contract,
            policy,
            sandbox,
            provider,
            tool,
            approval,
            sink.clone(),
        )
        .unwrap();
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Complete);
        let events = sink.snapshot();
        let checkpoints = events
            .iter()
            .filter(|event| event.kind == pangu_core::EventKind::CheckpointCreated)
            .collect::<Vec<_>>();
        assert_eq!(checkpoints.len(), 2);
        let first = checkpoints[0].payload.as_ref().unwrap();
        let second = checkpoints[1].payload.as_ref().unwrap();
        let request = RollbackRequest {
            rollback_id: "rollback-external-1".into(),
            checkpoint_id: first["checkpoint_id"].as_str().unwrap().into(),
            source_session_node_id: second["session_node_id"].as_str().unwrap().into(),
            reason: "try to undo local state".into(),
            failed_path_ref: None,
            requested_by: "operator".into(),
        };
        let error = agent.rollback(request).await.unwrap_err();
        assert!(error.to_string().contains("external effect"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "external");
        let failure = sink
            .snapshot()
            .into_iter()
            .find(|event| event.kind == pangu_core::EventKind::RollbackFailed)
            .expect("rollback failure event");
        assert_eq!(
            failure
                .payload
                .as_ref()
                .and_then(|payload| payload.get("failure_stage")),
            Some(&serde_json::json!("external_effect_check"))
        );
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
        let events = sink.snapshot();
        assert!(events
            .iter()
            .any(|event: &Event| event.kind == pangu_core::EventKind::ToolStarted));
        let finished = events
            .iter()
            .find(|event| event.kind == pangu_core::EventKind::ToolFinished)
            .expect("successful tool event");
        assert_eq!(finished.effect_scope.as_deref(), Some("workspace"));
        assert_eq!(finished.reversibility.as_deref(), Some("no_effect"));
        assert!(finished
            .action_digest
            .as_deref()
            .is_some_and(|digest| digest.len() == 64));
        assert_eq!(finished.external_mutation, Some(false));
        clean(root);
    }

    #[tokio::test]
    async fn missing_effect_descriptor_fails_closed_before_policy() {
        let options = SetupOptions {
            rules: vec![Rule::allow("allow-test", "test_tool", "test action")],
            omit_effect: true,
            ..SetupOptions::default()
        };
        let (agent, tool, sink, root) = setup(options);
        let outcome = agent.run().await.unwrap();
        assert_eq!(outcome.status, GoalStatus::Failed);
        assert_eq!(tool.executions.load(Ordering::Relaxed), 0);
        let events = sink.snapshot();
        assert!(events.iter().any(|event: &Event| {
            event.kind == pangu_core::EventKind::ToolBlocked
                && event.message.contains("EffectDescriptor")
        }));
        assert!(!events
            .iter()
            .any(|event: &Event| { event.kind == pangu_core::EventKind::PolicyDecision }));
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
