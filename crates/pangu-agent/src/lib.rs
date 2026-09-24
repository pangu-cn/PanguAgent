//! Pangu Agent runtime.
//!
//! The runtime owns the only path from a model tool call to a side effect:
//! assess -> policy -> L3 validation -> approval -> execute -> evidence. The
//! concrete provider and tool implementations depend on this crate, rather
//! than the runtime depending on adapters.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use pangu_boundary::{
    ActionRequest, ApprovalHandler, ApprovalMode, ApprovalRequest, ApprovalResponse, GoalContract,
    GoalStatus, Policy, ResourceRequest, Sandbox, ValidatedResources,
};
use pangu_core::{
    redact_event, redact_text, truncate_middle, ChatResponse, Event, EventKind, EventSink,
    JournalMeta, Message, ToolCall, ToolSpec, Usage, Value,
};

const MAX_TOOL_CALLS_PER_RESPONSE: usize = 128;

#[derive(Debug, Clone)]
pub struct ToolAssessment {
    pub risk: pangu_boundary::Risk,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub preview: String,
    pub escapes_workspace: bool,
}

impl ToolAssessment {
    pub fn new(risk: pangu_boundary::Risk) -> Self {
        Self {
            risk,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            hosts: Vec::new(),
            argv: Vec::new(),
            cwd: None,
            preview: String::new(),
            escapes_workspace: false,
        }
    }

    pub fn read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }

    pub fn write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.hosts.push(host.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: String,
    pub evidence: Option<String>,
}

impl ToolOutput {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            evidence: None,
        }
    }

    pub fn evidenced(content: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            evidence: Some(evidence.into()),
        }
    }
}

/// A provider adapter must return a typed response. Untrusted JSON is parsed
/// inside the adapter, not by the orchestration loop.
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn describe(&self) -> String;
    async fn chat(&self, messages: Vec<Message>, tools: Vec<ToolSpec>) -> Result<ChatResponse>;
}

/// Tools assess arguments without side effects and execute only a token that
/// the runtime created after all gates passed.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    fn specs(&self) -> Vec<ToolSpec>;
    async fn assess(&self, call: &ToolCall, sandbox: &Sandbox) -> Result<ToolAssessment>;
    async fn execute(&self, action: &VerifiedAction) -> Result<ToolOutput>;
}

/// Capability token for one already-approved, already-validated action.
pub struct VerifiedAction {
    call: ToolCall,
    resources: ValidatedResources,
    sandbox: Arc<Sandbox>,
}

impl VerifiedAction {
    fn new(call: ToolCall, resources: ValidatedResources, sandbox: Arc<Sandbox>) -> Self {
        Self {
            call,
            resources,
            sandbox,
        }
    }

    pub fn call(&self) -> &ToolCall {
        &self.call
    }

    pub fn resources(&self) -> &ValidatedResources {
        &self.resources
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }
}

pub struct Agent {
    contract: GoalContract,
    policy: Arc<Policy>,
    sandbox: Arc<Sandbox>,
    provider: Arc<dyn Provider>,
    tools: Arc<dyn ToolExecutor>,
    approval: Arc<dyn ApprovalHandler>,
    event_sink: Arc<dyn EventSink>,
}

impl Agent {
    pub fn new(
        contract: GoalContract,
        policy: Arc<Policy>,
        sandbox: Arc<Sandbox>,
        provider: Arc<dyn Provider>,
        tools: Arc<dyn ToolExecutor>,
        approval: Arc<dyn ApprovalHandler>,
        event_sink: Arc<dyn EventSink>,
    ) -> Result<Self> {
        contract.validate_against(&sandbox)?;
        if approval.mode() != contract.approval_mode {
            return Err(anyhow!(
                "approval handler mode does not match GoalContract approval mode"
            ));
        }
        if contract.policy_digest != policy.digest() {
            return Err(anyhow!(
                "GoalContract and Policy do not describe the same rule set"
            ));
        }
        Ok(Self {
            contract,
            policy,
            sandbox,
            provider,
            tools,
            approval,
            event_sink,
        })
    }

    /// Run the agent. The event sink is the streaming audit interface; this
    /// convenience method preserves the documented library entry point while
    /// keeping the terminal result awaitable.
    pub async fn run_stream(&self) -> Result<Outcome> {
        self.run().await
    }

    pub async fn run(&self) -> Result<Outcome> {
        match self.run_inner().await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let message = redact_text(&error.to_string());
                if let Err(event_error) = self
                    .emit(
                        Event::new(EventKind::RunFinished, 0, format!("run failed: {message}"))
                            .verdict("failed")
                            .payload(serde_json::json!({"status": "failed", "error": message})),
                    )
                    .await
                {
                    return Err(anyhow!(
                        "{error}; additionally failed to emit terminal event: {event_error}"
                    ));
                }
                Err(error)
            }
        }
    }

    async fn run_inner(&self) -> Result<Outcome> {
        let started = Instant::now();
        let mut usage = Usage::default();
        let mut evidence = Vec::new();
        let mut history = vec![
            Message::system(self.contract.system_prompt()),
            Message::user(self.contract.goal.clone()),
        ];
        let mut terminal = None;
        let mut last_turn = 0;

        let meta = JournalMeta {
            format: JournalMeta::FORMAT.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            model: self.provider.model().to_string(),
            workspace: self.contract.workspace().display().to_string(),
            goal: redact_text(&self.contract.goal),
            boundary_digest: self.contract.digest(),
            unattended: self.contract.is_unattended(),
            config_files: self.contract.config_files.clone(),
        };
        self.emit(Event::new(EventKind::RunStarted, 0, "run started").payload(meta.to_value()))
            .await?;

        let specs = self.tools.specs();
        for turn in 1..=self.contract.budget().max_turns {
            last_turn = turn;
            let estimated_input = history.iter().fold(0u64, |total, message| {
                total.saturating_add(message.approx_tokens())
            });
            let mut breaches =
                self.budget_breaches(turn.saturating_sub(1), &usage, started.elapsed());
            if estimated_input >= self.contract.budget().max_input_tokens {
                breaches.push(pangu_boundary::Breach::InputTokens);
            }
            if !breaches.is_empty() {
                self.emit_budget(turn, &breaches).await?;
                terminal = Some(GoalStatus::BudgetExhausted);
                break;
            }

            self.emit(Event::new(
                EventKind::TurnStarted,
                turn,
                format!("turn {turn}"),
            ))
            .await?;
            self.emit(Event::new(
                EventKind::ModelRequest,
                turn,
                format!(
                    "provider={} model={} messages={} tools={}",
                    self.provider.name(),
                    self.provider.model(),
                    history.len(),
                    specs.len()
                ),
            ))
            .await?;

            let response = self.provider.chat(history.clone(), specs.clone()).await?;
            let response_usage = response.usage;
            usage.merge(&response_usage);
            self.emit(
                Event::new(EventKind::ModelResponse, turn, "provider response received")
                    .usage(response_usage),
            )
            .await?;

            let post_response_breaches = self.budget_breaches(turn, &usage, started.elapsed());
            if !post_response_breaches.is_empty() {
                self.emit_budget(turn, &post_response_breaches).await?;
                terminal = Some(GoalStatus::BudgetExhausted);
                break;
            }

            let mut tool_calls = Vec::new();
            for message in response.messages {
                match message {
                    Message::Assistant {
                        content,
                        tool_calls: calls,
                    } => {
                        // Keep untrusted wire calls out of history when their
                        // shape is invalid. The raw value is used only for a
                        // bounded, redacted ToolBlocked diagnostic below.
                        let history_calls = calls
                            .iter()
                            .map(|call| {
                                if call.validate().is_ok() {
                                    call.clone()
                                } else {
                                    sanitized_invalid_call(call)
                                }
                            })
                            .collect();
                        if tool_calls.len().saturating_add(calls.len())
                            > MAX_TOOL_CALLS_PER_RESPONSE
                        {
                            return Err(anyhow!(
                                "provider returned too many tool calls in one response"
                            ));
                        }
                        tool_calls.extend(calls);
                        history.push(Message::assistant_calls(content, history_calls));
                    }
                    other => {
                        return Err(anyhow!(
                            "provider returned an unexpected {:?} message",
                            other.role()
                        ));
                    }
                }
            }
            if tool_calls.is_empty() {
                terminal = Some(GoalStatus::Failed);
                break;
            }

            for call in tool_calls {
                let mut call_breaches = self.budget_breaches(turn, &usage, started.elapsed());
                let estimated_input = history.iter().fold(0u64, |total, message| {
                    total.saturating_add(message.approx_tokens())
                });
                if estimated_input >= self.contract.budget().max_input_tokens
                    && !call_breaches.contains(&pangu_boundary::Breach::InputTokens)
                {
                    call_breaches.push(pangu_boundary::Breach::InputTokens);
                }
                if !call_breaches.is_empty() {
                    self.emit_budget(turn, &call_breaches).await?;
                    terminal = Some(GoalStatus::BudgetExhausted);
                    break;
                }
                if let Err(error) = call.validate() {
                    self.emit(
                        Event::new(EventKind::ToolRequested, turn, "invalid tool call received")
                            .tool(&call.name)
                            .call_id(&call.id),
                    )
                    .await?;
                    let safe_call = sanitized_invalid_call(&call);
                    self.record_tool_error(
                        &mut history,
                        &safe_call,
                        turn,
                        EventKind::ToolBlocked,
                        error,
                    )
                    .await?;
                    continue;
                }
                if !specs.iter().any(|spec| spec.name == call.name) {
                    self.emit(
                        Event::new(
                            EventKind::ToolRequested,
                            turn,
                            format!("tool requested: {}", call.name),
                        )
                        .tool(&call.name)
                        .call_id(&call.id),
                    )
                    .await?;
                    let error = pangu_core::Error::Denied {
                        reason: format!("tool `{}` was not advertised by the executor", call.name),
                    };
                    self.record_tool_error(
                        &mut history,
                        &call,
                        turn,
                        EventKind::ToolBlocked,
                        error,
                    )
                    .await?;
                    continue;
                }
                if call.name == "finish" {
                    match self.finish_status(&call, evidence.len()) {
                        Ok(status) => {
                            self.emit(
                                Event::new(
                                    EventKind::FinishRequested,
                                    turn,
                                    format!("finish requested: {status}"),
                                )
                                .call_id(&call.id),
                            )
                            .await?;
                            history.push(Message::tool_result(&call.id, "finish", status.as_str()));
                            terminal = Some(status);
                            break;
                        }
                        Err(error) => {
                            self.record_tool_error(
                                &mut history,
                                &call,
                                turn,
                                EventKind::ToolBlocked,
                                error,
                            )
                            .await?;
                        }
                    }
                } else if let Some(status) = self
                    .process_tool(&mut history, call, turn, &mut evidence)
                    .await?
                {
                    terminal = Some(status);
                    break;
                }
            }
            if terminal.is_none() {
                let mut final_breaches = self.budget_breaches(turn, &usage, started.elapsed());
                let estimated_input = history.iter().fold(0u64, |total, message| {
                    total.saturating_add(message.approx_tokens())
                });
                if estimated_input >= self.contract.budget().max_input_tokens
                    && !final_breaches.contains(&pangu_boundary::Breach::InputTokens)
                {
                    final_breaches.push(pangu_boundary::Breach::InputTokens);
                }
                if !final_breaches.is_empty() {
                    self.emit_budget(turn, &final_breaches).await?;
                    terminal = Some(GoalStatus::BudgetExhausted);
                }
            }
            if terminal.is_some() {
                break;
            }
        }

        let status = terminal.unwrap_or(GoalStatus::Failed);
        self.emit(
            Event::new(
                EventKind::RunFinished,
                last_turn,
                format!("run finished: {status}"),
            )
            .payload(serde_json::json!({"status": status.as_str(), "evidence": evidence})),
        )
        .await?;
        Ok(Outcome {
            status,
            messages: history,
            usage,
            evidence,
        })
    }

    async fn process_tool(
        &self,
        history: &mut Vec<Message>,
        call: ToolCall,
        turn: u32,
        evidence: &mut Vec<String>,
    ) -> Result<Option<GoalStatus>> {
        self.emit(
            Event::new(
                EventKind::ToolRequested,
                turn,
                format!("tool requested: {}", call.name),
            )
            .tool(&call.name)
            .call_id(&call.id),
        )
        .await?;
        let assessment = match self.tools.assess(&call, &self.sandbox).await {
            Ok(assessment) => assessment,
            Err(error) => {
                self.tool_blocked(history, &call, turn, error).await?;
                return Ok(None);
            }
        };
        let paths: Vec<std::path::PathBuf> = assessment
            .read_paths
            .iter()
            .chain(assessment.write_paths.iter())
            .cloned()
            .collect();
        let escapes_workspace = assessment.escapes_workspace
            || paths.iter().any(|path| {
                path.components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            });
        let path_count = paths
            .len()
            .saturating_add(usize::from(assessment.cwd.is_some()));
        if path_count > self.sandbox.max_paths_per_action {
            let error = anyhow!("action touches too many paths");
            self.tool_blocked(history, &call, turn, error).await?;
            return Ok(None);
        }
        let request = ActionRequest {
            tool: &call.name,
            call_id: &call.id,
            args: &call.args,
            risk: assessment.risk,
            paths,
            hosts: assessment.hosts.clone(),
            argv: assessment.argv.clone(),
            escapes_workspace,
        };
        let decision = self.policy.evaluate(&request, &self.sandbox.workspace);
        self.emit(
            Event::new(
                EventKind::PolicyDecision,
                turn,
                if decision.is_deny() {
                    decision.denial_message()
                } else {
                    decision.reason.clone()
                },
            )
            .tool(&call.name)
            .call_id(&call.id)
            .verdict(decision.effect.as_str())
            .risk(decision.risk.as_str())
            .rule(decision.rule_id.as_deref().unwrap_or("default-deny")),
        )
        .await?;
        if decision.is_deny() {
            let error = pangu_core::Error::Denied {
                reason: decision.denial_message(),
            };
            self.tool_blocked(history, &call, turn, error).await?;
            return Ok(None);
        }

        let resource_request = ResourceRequest {
            read_paths: assessment.read_paths,
            write_paths: assessment.write_paths,
            hosts: assessment.hosts,
            argv: assessment.argv,
            cwd: assessment.cwd,
        };
        let resources = match self.sandbox.validate_resources(&resource_request) {
            Ok(resources) => resources,
            Err(error) => {
                self.tool_blocked(history, &call, turn, error).await?;
                return Ok(None);
            }
        };

        let needs_approval = decision.effect == pangu_boundary::Effect::Ask
            || self.contract.approval_mode.needs_approval(assessment.risk);
        if needs_approval {
            if self.contract.approval_mode == ApprovalMode::Never {
                let error = pangu_core::Error::Denied {
                    reason: "action requires approval but run is unattended".into(),
                };
                self.tool_blocked(history, &call, turn, error).await?;
                return Ok(None);
            }
            let safe_call_id = sanitized_text(&call.id, 256, "call");
            let approval_id = format!("ap_{}_{}", turn, safe_call_id);
            let target = resources
                .write_paths
                .first()
                .or_else(|| resources.read_paths.first())
                .map(|path| path.display().to_string())
                .or_else(|| resources.hosts.first().cloned())
                .map(|value| truncate_middle(&redact_text(&value), 4096));
            let approval_request = ApprovalRequest {
                id: approval_id,
                tool: sanitized_text(&call.name, 128, "tool"),
                call_id: safe_call_id,
                risk: assessment.risk,
                rule_id: decision.rule_id.clone(),
                reason: truncate_middle(&redact_text(&decision.reason), 4096),
                target,
                invariant: decision.invariant.clone(),
                preview: truncate_middle(&redact_text(&assessment.preview), 16 * 1024),
                args: approval_args(&call.args),
            };
            self.emit(
                Event::new(
                    EventKind::ApprovalRequested,
                    turn,
                    "human approval requested",
                )
                .tool(&call.name)
                .call_id(&call.id)
                .risk(assessment.risk.as_str()),
            )
            .await?;
            let response = self.approval.decide(&approval_request).await;
            self.emit(
                Event::new(EventKind::ApprovalResolved, turn, response.as_str())
                    .tool(&call.name)
                    .call_id(&call.id)
                    .verdict(response.as_str()),
            )
            .await?;
            match response {
                ApprovalResponse::AllowOnce | ApprovalResponse::AllowRule(_) => {}
                ApprovalResponse::Abort(reason) => {
                    let error = pangu_core::Error::Denied { reason };
                    self.tool_blocked(history, &call, turn, error).await?;
                    return Ok(Some(GoalStatus::Aborted));
                }
                ApprovalResponse::Deny | ApprovalResponse::NoAnswer => {
                    let error = pangu_core::Error::Denied {
                        reason: "human approval was not granted".into(),
                    };
                    self.tool_blocked(history, &call, turn, error).await?;
                    return Ok(None);
                }
            }
        }

        let action = VerifiedAction::new(call.clone(), resources, Arc::clone(&self.sandbox));
        self.emit(
            Event::new(EventKind::ToolStarted, turn, "tool execution started")
                .tool(&call.name)
                .call_id(&call.id),
        )
        .await?;
        match self.tools.execute(&action).await {
            Ok(output) => {
                if output.content.len() > self.sandbox.max_tool_output_bytes {
                    let error = anyhow!("tool output exceeds configured limit");
                    self.tool_failure(history, &call, turn, error).await?;
                    return Ok(None);
                }
                let bounded_evidence = output
                    .evidence
                    .as_deref()
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| redact_text(&truncate_middle(item, 4096)));
                if let Some(item) = bounded_evidence.clone() {
                    if evidence.len() < 128 {
                        evidence.push(item);
                    }
                }
                let content = truncate_middle(
                    &redact_text(&output.content),
                    self.sandbox.max_tool_output_bytes,
                );
                let output_bytes = output.content.len();
                let output_digest = pangu_core::hex_sha256(&output.content);
                self.emit(
                    Event::new(
                        EventKind::ToolFinished,
                        turn,
                        format!("tool succeeded bytes={output_bytes} sha256={output_digest}"),
                    )
                    .tool(&call.name)
                    .call_id(&call.id)
                    .payload(serde_json::json!({
                        "ok": true,
                        "evidence": bounded_evidence,
                        "output_bytes": output_bytes,
                        "output_sha256": output_digest,
                    })),
                )
                .await?;
                history.push(Message::tool_result(&call.id, &call.name, content));
                Ok(None)
            }
            Err(error) => {
                self.tool_failure(history, &call, turn, error).await?;
                Ok(None)
            }
        }
    }

    async fn tool_blocked(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        error: impl std::fmt::Display,
    ) -> Result<()> {
        self.record_tool_error(history, call, turn, EventKind::ToolBlocked, error)
            .await
    }

    async fn tool_failure(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        error: impl std::fmt::Display,
    ) -> Result<()> {
        self.record_tool_error(history, call, turn, EventKind::ToolFinished, error)
            .await
    }

    async fn record_tool_error(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        kind: EventKind,
        error: impl std::fmt::Display,
    ) -> Result<()> {
        let message = redact_text(&error.to_string());
        let message = truncate_middle(&message, self.sandbox.max_tool_output_bytes.min(16 * 1024));
        let safe_name = sanitized_text(&call.name, 128, "tool");
        let safe_call_id = sanitized_text(&call.id, 256, "call");
        self.emit(
            Event::new(kind, turn, message.clone())
                .tool(&safe_name)
                .call_id(&safe_call_id)
                .payload(serde_json::json!({"ok": false, "error": message})),
        )
        .await?;
        history.push(Message::Tool {
            call_id: safe_call_id,
            name: safe_name,
            content: serde_json::json!({"error": message, "code": "tool_error"}).to_string(),
            is_error: true,
        });
        Ok(())
    }

    fn finish_status(&self, call: &ToolCall, evidence_count: usize) -> Result<GoalStatus> {
        let object = call
            .args
            .as_object()
            .ok_or_else(|| anyhow!("finish arguments must be an object"))?;
        if object.keys().any(|key| key != "status") {
            return Err(anyhow!("finish accepts only the status field"));
        }
        let requested = call
            .args
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("finish requires a string status"))?;
        if !matches!(requested, "complete" | "failed" | "needs_input" | "aborted") {
            return Err(anyhow!("unsupported finish status `{requested}`"));
        }
        let status: GoalStatus = requested.parse().map_err(|error: String| anyhow!(error))?;
        if status == GoalStatus::Complete
            && evidence_count < self.contract.min_successful_tool_calls as usize
        {
            return Ok(GoalStatus::Failed);
        }
        Ok(status)
    }

    fn budget_breaches(
        &self,
        turn: u32,
        usage: &Usage,
        elapsed: std::time::Duration,
    ) -> Vec<pangu_boundary::Breach> {
        let cost = self
            .contract
            .price
            .map(|price| price.cost_usd(usage))
            // An absent price is not zero cost. Treat it as an unknown,
            // unbudgeted provider and fail closed before the next request.
            .unwrap_or(f64::INFINITY);
        self.contract.budget.check(
            turn,
            usage.input_tokens.saturating_add(usage.cache_read_tokens),
            usage.output_tokens,
            cost,
            elapsed,
        )
    }

    async fn emit_budget(&self, turn: u32, breaches: &[pangu_boundary::Breach]) -> Result<()> {
        let text = breaches
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        self.emit(Event::new(EventKind::BudgetExhausted, turn, text))
            .await
    }

    async fn emit(&self, event: Event) -> Result<()> {
        self.event_sink
            .emit(redact_event(event))
            .await
            .map_err(|error| anyhow!(error))
    }
}

fn sanitized_text(value: &str, max_bytes: usize, fallback: &str) -> String {
    let redacted = redact_text(value);
    let sanitized = redacted
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    let bounded = truncate_middle(&sanitized, max_bytes);
    if bounded.trim().is_empty() {
        fallback.to_string()
    } else {
        bounded
    }
}

fn sanitized_invalid_call(call: &ToolCall) -> ToolCall {
    ToolCall {
        id: sanitized_text(&call.id, 256, "invalid_call"),
        name: sanitized_text(&call.name, 128, "invalid_tool"),
        args: serde_json::json!({}),
    }
}

fn approval_url_preview(raw: &str) -> String {
    let base = raw.split(['?', '#']).next().unwrap_or_default();
    let Some((scheme, rest)) = base.split_once("://") else {
        return "[invalid URL]".into();
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let authority = authority.rsplit('@').next().unwrap_or_default();
    if authority.is_empty() {
        return "[invalid URL]".into();
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/[path_sha256={}]", pangu_core::short_hash(path))
    };
    format!("{scheme}://{authority}{path}")
}

fn approval_args(args: &Value) -> Vec<(String, String)> {
    match args.as_object() {
        Some(map) => map
            .iter()
            .map(|(key, value)| {
                let mut text = if key == "content" || key == "query" {
                    let raw = value.as_str().unwrap_or_default();
                    format!("bytes={} sha256={}", raw.len(), pangu_core::hex_sha256(raw))
                } else if key == "url" {
                    approval_url_preview(value.as_str().unwrap_or_default())
                } else {
                    redact_text(&value.to_string())
                };
                text = text
                    .chars()
                    .map(|character| {
                        if character.is_control() {
                            '�'
                        } else {
                            character
                        }
                    })
                    .collect::<String>();
                if text.len() > 4096 {
                    text = truncate_middle(&text, 4096);
                }
                let safe_key = redact_text(key);
                let safe_key = safe_key
                    .chars()
                    .map(|character| {
                        if character.is_control() {
                            '�'
                        } else {
                            character
                        }
                    })
                    .collect::<String>();
                (truncate_middle(&safe_key, 128), text)
            })
            .collect(),
        None => vec![("arguments".into(), redact_text(&args.to_string()))],
    }
}

#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;

#[derive(Debug)]
pub struct Outcome {
    pub status: GoalStatus,
    pub messages: Vec<Message>,
    pub usage: Usage,
    pub evidence: Vec<String>,
}
