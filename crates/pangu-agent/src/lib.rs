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
    ActionRequest, ApprovalHandler, ApprovalMode, ApprovalRequest, ApprovalResponse,
    CheckpointFailurePolicy, GoalContract, GoalStatus, Policy, ResourceRequest, Sandbox,
    ValidatedResources,
};
use pangu_core::{
    redact_event, redact_text, truncate_middle, ChatResponse, CheckpointArtifact, Event, EventKind,
    EventSink, FailureClass, JournalMeta, Message, RestoreDisposition, RollbackOperation,
    RollbackRequest, ToolCall, ToolSpec, Usage, Value, JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2,
};

mod checkpoint;
mod effect;

pub use effect::{EffectDescriptor, EffectScope, Reversibility};

const MAX_TOOL_CALLS_PER_RESPONSE: usize = 128;

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(value) = object.remove(&key) {
                    sorted.insert(key, canonical_json(value));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        value => value,
    }
}

fn rollback_action_digest(request: &RollbackRequest) -> String {
    pangu_core::hex_sha256(
        &serde_json::to_string(&canonical_json(serde_json::json!({
            "rollback_id": request.rollback_id,
            "checkpoint_id": request.checkpoint_id,
            "source_session_node_id": request.source_session_node_id,
        })))
        .unwrap_or_default(),
    )
}

fn action_digest(call: &ToolCall, assessment: &ToolAssessment) -> String {
    let mut read_paths = assessment
        .read_paths
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut write_paths = assessment
        .write_paths
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut hosts = assessment.hosts.clone();
    read_paths.sort();
    write_paths.sort();
    hosts.sort();
    let value = serde_json::json!({
        "tool": call.name,
        "args": call.args,
        "read_paths": read_paths,
        "write_paths": write_paths,
        "hosts": hosts,
        "argv": assessment.argv,
        "cwd": assessment.cwd.as_ref().map(|path| path.to_string_lossy().replace('\\', "/")),
    });
    pangu_core::hex_sha256(&serde_json::to_string(&canonical_json(value)).unwrap_or_default())
}

#[derive(Debug, Clone)]
struct FailureContext {
    args_digest: String,
    resource_digest: String,
}

impl FailureContext {
    fn from_call(call: &ToolCall) -> Self {
        Self {
            args_digest: canonical_args_digest(call),
            resource_digest: pangu_core::hex_sha256(
                &serde_json::to_string(&canonical_json(serde_json::json!({
                    "workspace": "<unassessed>"
                })))
                .unwrap_or_default(),
            ),
        }
    }

    fn from_assessment(call: &ToolCall, assessment: &ToolAssessment) -> Self {
        Self {
            args_digest: canonical_args_digest(call),
            resource_digest: resource_digest(assessment),
        }
    }
}

fn canonical_args_digest(call: &ToolCall) -> String {
    pangu_core::hex_sha256(
        &serde_json::to_string(&canonical_json(call.args.clone())).unwrap_or_default(),
    )
}

fn resource_digest(assessment: &ToolAssessment) -> String {
    let mut read_paths = assessment
        .read_paths
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut write_paths = assessment
        .write_paths
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut hosts = assessment.hosts.clone();
    read_paths.sort();
    write_paths.sort();
    hosts.sort();
    let value = serde_json::json!({
        "read_paths": read_paths,
        "write_paths": write_paths,
        "hosts": hosts,
        "argv": assessment.argv,
        "cwd": assessment.cwd.as_ref().map(|path| path.to_string_lossy().replace('\\', "/")),
    });
    pangu_core::hex_sha256(&serde_json::to_string(&canonical_json(value)).unwrap_or_default())
}

#[derive(Debug, Clone)]
pub struct ToolAssessment {
    pub risk: pangu_boundary::Risk,
    /// The adapter-declared effect boundary. `None` is retained for wire/API
    /// compatibility with older adapters and is rejected by the runtime
    /// before Policy.
    pub effect: Option<EffectDescriptor>,
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
            effect: None,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            hosts: Vec::new(),
            argv: Vec::new(),
            cwd: None,
            preview: String::new(),
            escapes_workspace: false,
        }
    }

    pub fn with_effect(mut self, effect: EffectDescriptor) -> Self {
        self.effect = Some(effect);
        self
    }

    pub fn validate_effect(&self) -> anyhow::Result<()> {
        let effect = self
            .effect
            .ok_or_else(|| anyhow!("tool assessment is missing EffectDescriptor"))?;
        effect.validate_for_risk(self.risk)?;
        match effect.scope {
            EffectScope::Workspace => {
                if !self.hosts.is_empty() || !self.argv.is_empty() {
                    return Err(anyhow!(
                        "workspace effect assessment must not declare hosts or subprocesses"
                    ));
                }
                match effect.reversibility {
                    Reversibility::NoEffect if !self.write_paths.is_empty() => {
                        return Err(anyhow!(
                            "no-effect workspace assessment must not declare write paths"
                        ));
                    }
                    Reversibility::Reversible | Reversibility::Irreversible
                        if self.write_paths.is_empty() =>
                    {
                        return Err(anyhow!(
                            "mutating workspace assessment must declare a write path"
                        ));
                    }
                    _ => {}
                }
            }
            EffectScope::Session => {
                if !self.read_paths.is_empty()
                    || !self.write_paths.is_empty()
                    || !self.hosts.is_empty()
                    || !self.argv.is_empty()
                    || self.cwd.is_some()
                {
                    return Err(anyhow!(
                        "session effect assessment must not declare external or filesystem resources"
                    ));
                }
            }
            EffectScope::ProcessRead => {
                if self.argv.is_empty() {
                    return Err(anyhow!("process-read assessment must declare an argv"));
                }
                if !self.hosts.is_empty() || !self.write_paths.is_empty() {
                    return Err(anyhow!(
                        "process-read assessment must not declare network or write resources"
                    ));
                }
                if effect.reversibility != Reversibility::NoEffect {
                    return Err(anyhow!("process-read assessment must be no-effect"));
                }
            }
            EffectScope::ExternalRead => {
                if self.hosts.is_empty() {
                    return Err(anyhow!("external-read assessment must declare a host"));
                }
                if !self.argv.is_empty()
                    || !self.read_paths.is_empty()
                    || !self.write_paths.is_empty()
                    || self.cwd.is_some()
                {
                    return Err(anyhow!(
                        "external-read assessment must not declare process or filesystem resources"
                    ));
                }
                if effect.reversibility != Reversibility::NoEffect {
                    return Err(anyhow!("external-read assessment must be no-effect"));
                }
            }
            EffectScope::ExternalMutation => {
                if self.hosts.is_empty() && self.argv.is_empty() && self.write_paths.is_empty() {
                    return Err(anyhow!(
                        "external-mutation assessment must declare a host, argv, or write path"
                    ));
                }
            }
        }
        Ok(())
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
    checkpoint: Option<Arc<checkpoint::CheckpointRuntime>>,
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
        let checkpoint = checkpoint::CheckpointRuntime::from_contract(&contract)?;
        Ok(Self {
            contract,
            policy,
            sandbox,
            provider,
            tools,
            approval,
            event_sink,
            checkpoint: checkpoint.map(Arc::new),
        })
    }

    /// Run the agent. The event sink is the streaming audit interface; this
    /// convenience method preserves the documented library entry point while
    /// keeping the terminal result awaitable.
    pub async fn run_stream(&self) -> Result<Outcome> {
        self.run().await
    }

    /// Request a bounded, policy-gated rollback of one committed workspace
    /// checkpoint. This is an operator/library API, never a model tool.
    pub async fn rollback(&self, request: RollbackRequest) -> Result<RollbackOutcome> {
        let started = Instant::now();
        request.validate().map_err(|error| anyhow!(error))?;
        let runtime = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| anyhow!("checkpoint/rollback is disabled for this run"))?;
        let store = runtime.store();
        let rollback_digest = rollback_action_digest(&request);
        self.emit(
            Event::new_v2(
                EventKind::RollbackRequested,
                0,
                format!("rollback requested: {}", redact_text(&request.rollback_id)),
            )
            .tool("rollback")
            .call_id(&request.rollback_id)
            .effect_scope("workspace")
            .reversibility("reversible")
            .action_digest(rollback_digest.clone())
            .external_mutation(false)
            .payload(serde_json::json!({
                "rollback_id": request.rollback_id,
                "checkpoint_id": request.checkpoint_id,
                "source_session_node_id": request.source_session_node_id,
                "reason": redact_text(&truncate_middle(&request.reason, 4096)),
                "requested_by": redact_text(&truncate_middle(&request.requested_by, 128)),
            })),
        )
        .await?;

        if self.rollback_wall_clock_exceeded(started) {
            let error = anyhow!("rollback wall-clock budget exhausted");
            self.emit_rollback_failure(&request, "budget", &error)
                .await?;
            return Err(error);
        }
        let artifact = match store.load_checkpoint(&request.checkpoint_id) {
            Ok(artifact) => artifact,
            Err(error) => {
                let error = anyhow!(error);
                self.emit_rollback_failure(&request, "checkpoint_load", &error)
                    .await?;
                return Err(error);
            }
        };
        if artifact.contract_digest != runtime.contract_digest()
            || artifact.policy_digest != runtime.policy_digest()
            || artifact.workspace != self.contract.workspace().clone()
        {
            let error = anyhow!("checkpoint boundary binding does not match this run");
            self.emit_rollback_failure(&request, "boundary_binding", &error)
                .await?;
            return Err(error);
        }
        let source_node = match store.load_session_node_by_id(&request.source_session_node_id) {
            Ok(Some(node)) => node,
            Ok(None) => {
                let error = anyhow!("rollback source session node was not found");
                self.emit_rollback_failure(&request, "source_node_load", &error)
                    .await?;
                return Err(error);
            }
            Err(error) => {
                let error = anyhow!(error);
                self.emit_rollback_failure(&request, "source_node_load", &error)
                    .await?;
                return Err(error);
            }
        };
        let source_artifact = match source_node.checkpoint_id.as_deref() {
            Some(checkpoint_id) => match store.load_checkpoint(checkpoint_id) {
                Ok(source) => source,
                Err(error) => {
                    let error = anyhow!(error);
                    self.emit_rollback_failure(&request, "source_checkpoint_load", &error)
                        .await?;
                    return Err(error);
                }
            },
            None => {
                let error = anyhow!("rollback source session node has no checkpoint state");
                self.emit_rollback_failure(&request, "source_node_state", &error)
                    .await?;
                return Err(error);
            }
        };
        if source_artifact.contract_digest != runtime.contract_digest()
            || source_artifact.policy_digest != runtime.policy_digest()
            || source_artifact.workspace != self.contract.workspace().clone()
            || source_artifact.session_id != artifact.session_id
        {
            let error =
                anyhow!("rollback source session node boundary binding does not match this run");
            self.emit_rollback_failure(&request, "source_boundary", &error)
                .await?;
            return Err(error);
        }
        if source_node.session_node_id != source_artifact.session_node_id
            || source_node.event_ref != source_artifact.event_ref
            || source_node.checkpoint_id.as_deref() != Some(source_artifact.checkpoint_id.as_str())
        {
            let error = anyhow!("rollback source session node is not bound to its checkpoint");
            self.emit_rollback_failure(&request, "source_node_state", &error)
                .await?;
            return Err(error);
        }
        let Some(expected_current_digest) = source_artifact.workspace_digest.as_deref() else {
            let error = anyhow!("rollback source checkpoint is missing its workspace digest");
            self.emit_rollback_failure(&request, "source_digest", &error)
                .await?;
            return Err(error);
        };
        // An already-applied operation is a deterministic short-circuit. It
        // must not request a second approval, consult the current workspace,
        // or become blocked by a later external effect. The source digest is
        // checked first so a reused rollback id cannot silently bind to a
        // different logical starting state.
        let existing_operation =
            match store.load_operation(&request.checkpoint_id, &request.rollback_id) {
                Ok(operation) => operation,
                Err(error) => {
                    let error = anyhow!(error);
                    self.emit_rollback_failure(&request, "operation_load", &error)
                        .await?;
                    return Err(error);
                }
            };
        if let Some(operation) = existing_operation {
            if operation.workspace_digest != expected_current_digest {
                let error = anyhow!("rollback operation is bound to a different source state");
                self.emit_rollback_failure(&request, "operation_binding", &error)
                    .await?;
                return Err(error);
            }
            return self
                .finish_rollback_operation(&request, artifact, operation)
                .await;
        }
        if let Some(failure_id) = &request.failed_path_ref {
            let failure = match store.load_failed_path(&source_artifact.run_id, failure_id) {
                Ok(Some(failure)) => failure,
                Ok(None) => {
                    let error =
                        anyhow!("rollback failed-path reference was not found in the source run");
                    self.emit_rollback_failure(&request, "failed_path", &error)
                        .await?;
                    return Err(error);
                }
                Err(error) => {
                    let error = anyhow!(error);
                    self.emit_rollback_failure(&request, "failed_path", &error)
                        .await?;
                    return Err(error);
                }
            };
            if failure.contract_digest != runtime.contract_digest()
                || failure.policy_digest != runtime.policy_digest()
            {
                let error = anyhow!("rollback failed-path reference is not bound to this boundary");
                self.emit_rollback_failure(&request, "failed_path", &error)
                    .await?;
                return Err(error);
            }
        }
        let external_effect_seen = match store.has_external_effect_after(&artifact) {
            Ok(seen) => seen,
            Err(error) => {
                let error = anyhow!(error);
                self.emit_rollback_failure(&request, "external_effect_check", &error)
                    .await?;
                return Err(error);
            }
        };
        if external_effect_seen {
            let error = anyhow!(
                "rollback is blocked because an irreversible external effect occurred after the checkpoint"
            );
            self.emit_rollback_failure(&request, "external_effect_check", &error)
                .await?;
            return Err(error);
        }

        let args = serde_json::json!({
            "rollback_id": request.rollback_id,
            "checkpoint_id": request.checkpoint_id,
            "source_session_node_id": request.source_session_node_id,
        });
        let action_request = ActionRequest {
            tool: "rollback",
            call_id: &request.rollback_id,
            args: &args,
            risk: pangu_boundary::Risk::Destructive,
            paths: vec![
                self.contract.workspace().clone(),
                self.contract.checkpoint.artifact_root.clone(),
            ],
            hosts: Vec::new(),
            argv: Vec::new(),
            escapes_workspace: false,
        };
        if self.rollback_wall_clock_exceeded(started) {
            let error = anyhow!("rollback wall-clock budget exhausted");
            self.emit_rollback_failure(&request, "budget", &error)
                .await?;
            return Err(error);
        }
        let decision = self
            .policy
            .evaluate(&action_request, &self.sandbox.workspace);
        self.emit(
            Event::new_v2(
                EventKind::PolicyDecision,
                0,
                if decision.is_deny() {
                    decision.denial_message()
                } else {
                    decision.reason.clone()
                },
            )
            .tool("rollback")
            .call_id(&request.rollback_id)
            .verdict(decision.effect.as_str())
            .risk(decision.risk.as_str())
            .rule(decision.rule_id.as_deref().unwrap_or("default-deny"))
            .effect_scope("workspace")
            .reversibility("reversible")
            .action_digest(rollback_digest.clone())
            .external_mutation(false),
        )
        .await?;
        if decision.is_deny() {
            let error = anyhow!(decision.denial_message());
            self.emit_rollback_failure(&request, "policy", &error)
                .await?;
            return Err(error);
        }

        let resource_probes = self
            .contract
            .writable_roots()
            .iter()
            .map(|root| root.join(".pangu-rollback-probe"))
            .collect::<Vec<_>>();
        let resources = ResourceRequest {
            read_paths: vec![
                self.contract.workspace().clone(),
                self.contract.checkpoint.artifact_root.clone(),
            ],
            write_paths: vec![self.contract.checkpoint.artifact_root.clone()]
                .into_iter()
                .chain(resource_probes)
                .collect(),
            ..ResourceRequest::default()
        };
        if self.sandbox.validate_resources(&resources).is_err()
            || runtime.validate_rollback_resources().is_err()
        {
            let error = anyhow!("rollback resources are outside the active sandbox");
            self.emit_rollback_failure(&request, "sandbox", &error)
                .await?;
            return Err(error);
        }
        if self.rollback_wall_clock_exceeded(started) {
            let error = anyhow!("rollback wall-clock budget exhausted");
            self.emit_rollback_failure(&request, "budget", &error)
                .await?;
            return Err(error);
        }
        let approval_request = ApprovalRequest {
            id: format!(
                "ap_rollback_{}",
                pangu_core::short_hash(&request.rollback_id)
            ),
            tool: "rollback".into(),
            call_id: request.rollback_id.clone(),
            risk: pangu_boundary::Risk::Destructive,
            rule_id: decision.rule_id.clone(),
            reason: truncate_middle(&redact_text(&decision.reason), 4096),
            target: Some(redact_text(&request.checkpoint_id)),
            invariant: Some("I-Rollback-Trigger".into()),
            preview: format!(
                "restore checkpoint={} node={} reason={}",
                request.checkpoint_id,
                request.source_session_node_id,
                redact_text(&truncate_middle(&request.reason, 1024))
            ),
            args: approval_args(&args),
        };
        self.emit(
            Event::new_v2(
                EventKind::ApprovalRequested,
                0,
                "rollback approval requested",
            )
            .tool("rollback")
            .call_id(&request.rollback_id)
            .risk(pangu_boundary::Risk::Destructive.as_str())
            .effect_scope("workspace")
            .reversibility("reversible")
            .action_digest(rollback_digest.clone())
            .external_mutation(false),
        )
        .await?;
        let approval_response = if self.approval.mode() == ApprovalMode::Never {
            ApprovalResponse::NoAnswer
        } else {
            self.approval.decide(&approval_request).await
        };
        self.emit(
            Event::new_v2(EventKind::ApprovalResolved, 0, approval_response.as_str())
                .tool("rollback")
                .call_id(&request.rollback_id)
                .verdict(approval_response.as_str())
                .effect_scope("workspace")
                .reversibility("reversible")
                .action_digest(rollback_digest.clone())
                .external_mutation(false),
        )
        .await?;
        if !approval_response.allowed() {
            let error = anyhow!("rollback approval was not granted");
            self.emit_rollback_failure(&request, "approval", &error)
                .await?;
            return Err(error);
        }
        if self.rollback_wall_clock_exceeded(started) {
            let error = anyhow!("rollback wall-clock budget exhausted");
            self.emit_rollback_failure(&request, "budget", &error)
                .await?;
            return Err(error);
        }
        let started_event = match self
            .emit_receipt(
                Event::new_v2(EventKind::RollbackStarted, 0, "rollback started")
                    .tool("rollback")
                    .call_id(&request.rollback_id)
                    .effect_scope("workspace")
                    .reversibility("reversible")
                    .action_digest(rollback_digest.clone())
                    .external_mutation(false),
            )
            .await
        {
            Ok(event) => event,
            Err(error) => {
                let error = anyhow!(error);
                self.emit_rollback_failure(&request, "start_event", &error)
                    .await?;
                return Err(error);
            }
        };
        if self.rollback_wall_clock_exceeded(started) {
            let error = anyhow!("rollback wall-clock budget exhausted");
            self.emit_rollback_failure(&request, "budget", &error)
                .await?;
            return Err(error);
        }
        let transition_node_id = runtime.rollback_transition_node_id(
            &artifact,
            &request.source_session_node_id,
            &request.rollback_id,
        );
        let transition_event_ref = checkpoint::event_ref(&started_event, &artifact.run_id);
        let capability =
            match runtime.prepare_rollback(&request, &artifact, expected_current_digest) {
                Ok(capability) => capability,
                Err(error) => {
                    let error = anyhow!(error);
                    self.emit_rollback_failure(&request, "capability", &error)
                        .await?;
                    return Err(error);
                }
            };
        match runtime.execute_rollback(
            &capability,
            Some(&transition_node_id),
            Some(&transition_event_ref),
        ) {
            Ok(result) => {
                if self.rollback_wall_clock_exceeded(started) {
                    let error = anyhow!("rollback wall-clock budget exhausted after restore");
                    self.emit_rollback_failure(&request, "budget", &error)
                        .await?;
                    return Err(error);
                }
                let operation = result.operation;
                // The operation binding is durable before restore starts. Use
                // the recorded values, rather than a newly guessed id, so a
                // retry can repair a node write that failed after the restore.
                let session_node_id = match (
                    operation.transition_session_node_id.as_deref(),
                    operation.transition_event_ref.as_ref(),
                ) {
                    (Some(node_id), Some(event_ref)) => {
                        match runtime.save_rollback_transition_node(
                            &request.source_session_node_id,
                            &artifact,
                            &request.rollback_id,
                            node_id.to_string(),
                            event_ref,
                        ) {
                            Ok(node) => Some(node.session_node_id),
                            Err(error) => {
                                let error = anyhow!(error);
                                self.emit_rollback_failure(
                                    &request,
                                    "transition_node_persistence",
                                    &error,
                                )
                                .await?;
                                return Err(error);
                            }
                        }
                    }
                    (None, None) if result.disposition == RestoreDisposition::AlreadyApplied => {
                        None
                    }
                    (None, None) => {
                        let error = anyhow!(
                            "applied rollback operation is missing its transition-node binding"
                        );
                        self.emit_rollback_failure(&request, "transition_node_persistence", &error)
                            .await?;
                        return Err(error);
                    }
                    _ => {
                        let error =
                            anyhow!("rollback operation has an incomplete transition-node binding");
                        self.emit_rollback_failure(&request, "transition_node_persistence", &error)
                            .await?;
                        return Err(error);
                    }
                };
                if self.rollback_wall_clock_exceeded(started) {
                    let error = anyhow!("rollback wall-clock budget exhausted before completion");
                    self.emit_rollback_failure(&request, "budget", &error)
                        .await?;
                    return Err(error);
                }
                let completion_event = self
                    .emit_receipt(
                        Event::new_v2(
                            if result.disposition == RestoreDisposition::AlreadyApplied {
                                EventKind::RollbackSkippedAlreadyApplied
                            } else {
                                EventKind::RollbackApplied
                            },
                            0,
                            "rollback completed",
                        )
                        .tool("rollback")
                        .call_id(&request.rollback_id)
                        .effect_scope("workspace")
                        .reversibility("reversible")
                        .action_digest(rollback_digest.clone())
                        .external_mutation(false)
                        .payload(serde_json::json!({
                            "rollback_id": request.rollback_id,
                            "checkpoint_id": request.checkpoint_id,
                            "session_node_id": session_node_id.clone().unwrap_or_else(|| artifact.session_node_id.clone()),
                            "disposition": format!("{:?}", result.disposition).to_lowercase(),
                        })),
                    )
                    .await;
                if let Err(error) = completion_event {
                    let error = anyhow!(error);
                    self.emit_rollback_failure(&request, "completion_event", &error)
                        .await?;
                    return Err(error);
                }
                Ok(RollbackOutcome {
                    artifact,
                    operation,
                    disposition: result.disposition,
                    session_node_id,
                })
            }
            Err(error) => {
                let error = anyhow!(error);
                self.emit_rollback_failure(&request, "execution", &error)
                    .await?;
                Err(error)
            }
        }
    }

    async fn authorize_checkpoint(
        &self,
        runtime: &checkpoint::CheckpointRuntime,
        finished_event: &Event,
        turn: u32,
        source_action_digest: &str,
    ) -> std::result::Result<(), (&'static str, anyhow::Error)> {
        finished_event
            .validate_v2_receipt()
            .map_err(|error| ("policy", anyhow!(error)))?;
        if finished_event.action_digest.as_deref() != Some(source_action_digest) {
            return Err((
                "policy",
                anyhow!("checkpoint source event action digest does not match the verified action"),
            ));
        }
        let checkpoint_digest = pangu_core::hex_sha256(&format!(
            "checkpoint-source:{}",
            finished_event
                .event_id
                .as_deref()
                .unwrap_or("unsealed-event")
        ));
        let args = serde_json::json!({
            "source_event_id": finished_event.event_id,
            "source_action_digest": source_action_digest,
        });
        let call_id = finished_event
            .call_id
            .as_deref()
            .unwrap_or("checkpoint")
            .to_string();
        let request = ActionRequest {
            tool: "checkpoint",
            call_id: &call_id,
            args: &args,
            risk: pangu_boundary::Risk::Reversible,
            paths: vec![
                self.contract.workspace().clone(),
                self.contract.checkpoint.artifact_root.clone(),
            ],
            hosts: Vec::new(),
            argv: Vec::new(),
            escapes_workspace: false,
        };
        let decision = self.policy.evaluate_internal(
            &request,
            &self.sandbox.workspace,
            "I-Checkpoint-After-Verified-Action",
            "checkpoint is enabled by the immutable run contract",
        );
        self.emit(
            Event::new_v2(
                EventKind::PolicyDecision,
                turn,
                if decision.is_deny() {
                    decision.denial_message()
                } else {
                    decision.reason.clone()
                },
            )
            .tool("checkpoint")
            .call_id(&call_id)
            .verdict(decision.effect.as_str())
            .risk(decision.risk.as_str())
            .rule(decision.rule_id.as_deref().unwrap_or("internal-contract"))
            .effect_scope("session")
            .reversibility("reversible")
            .action_digest(checkpoint_digest.clone())
            .external_mutation(false),
        )
        .await
        .map_err(|error| ("policy_event", error))?;
        if decision.is_deny() {
            return Err(("policy", anyhow!(decision.denial_message())));
        }

        if let Err(error) = runtime.request().validate() {
            return Err(("sandbox", anyhow!(error)));
        }
        let resources = ResourceRequest {
            read_paths: vec![
                self.contract.workspace().clone(),
                self.contract.checkpoint.artifact_root.clone(),
            ],
            write_paths: vec![self.contract.checkpoint.artifact_root.clone()],
            ..ResourceRequest::default()
        };
        if let Err(error) = self.sandbox.validate_resources(&resources) {
            return Err(("sandbox", anyhow!(error)));
        }

        if decision.effect == pangu_boundary::Effect::Ask {
            if self.contract.approval_mode == ApprovalMode::Never {
                return Err((
                    "approval",
                    anyhow!("checkpoint approval was not granted in Never mode"),
                ));
            }
            let approval_request = ApprovalRequest {
                id: format!("ap_checkpoint_{}", pangu_core::short_hash(&call_id)),
                tool: "checkpoint".into(),
                call_id: call_id.clone(),
                risk: pangu_boundary::Risk::Reversible,
                rule_id: decision.rule_id.clone(),
                reason: truncate_middle(&redact_text(&decision.reason), 4096),
                target: Some(redact_text(
                    &self.contract.workspace().display().to_string(),
                )),
                invariant: Some("I-Checkpoint-After-Verified-Action".into()),
                preview: "create an internal workspace checkpoint".into(),
                args: approval_args(&args),
            };
            self.emit(
                Event::new_v2(
                    EventKind::ApprovalRequested,
                    turn,
                    "checkpoint approval requested",
                )
                .tool("checkpoint")
                .call_id(&call_id)
                .risk(pangu_boundary::Risk::Reversible.as_str())
                .effect_scope("session")
                .reversibility("reversible")
                .action_digest(checkpoint_digest.clone())
                .external_mutation(false),
            )
            .await
            .map_err(|error| ("approval_event", error))?;
            let response = self.approval.decide(&approval_request).await;
            self.emit(
                Event::new_v2(EventKind::ApprovalResolved, turn, response.as_str())
                    .tool("checkpoint")
                    .call_id(&call_id)
                    .verdict(response.as_str())
                    .effect_scope("session")
                    .reversibility("reversible")
                    .action_digest(checkpoint_digest.clone())
                    .external_mutation(false),
            )
            .await
            .map_err(|error| ("approval_event", error))?;
            if !response.allowed() {
                return Err(("approval", anyhow!("checkpoint approval was not granted")));
            }
        }
        Ok(())
    }

    fn rollback_wall_clock_exceeded(&self, started: Instant) -> bool {
        started.elapsed() >= self.contract.budget().max_wall_clock_secs
    }

    async fn emit_rollback_failure(
        &self,
        request: &RollbackRequest,
        failure_stage: &str,
        error: &anyhow::Error,
    ) -> Result<()> {
        let message = truncate_middle(&redact_text(&error.to_string()), 4096);
        self.emit(
            Event::new_v2(EventKind::RollbackFailed, 0, "rollback failed")
                .tool("rollback")
                .call_id(&request.rollback_id)
                .effect_scope("workspace")
                .reversibility("reversible")
                .action_digest(rollback_action_digest(request))
                .external_mutation(false)
                .payload(serde_json::json!({
                    "rollback_id": request.rollback_id,
                    "checkpoint_id": request.checkpoint_id,
                    "source_session_node_id": request.source_session_node_id,
                    "failure_stage": failure_stage,
                    "error": message,
                })),
        )
        .await
    }

    async fn finish_rollback_operation(
        &self,
        request: &RollbackRequest,
        artifact: CheckpointArtifact,
        operation: RollbackOperation,
    ) -> Result<RollbackOutcome> {
        if operation.status != pangu_core::RollbackOperationStatus::Applied {
            let error =
                anyhow!("rollback operation is not complete and cannot be replayed automatically");
            self.emit_rollback_failure(request, "operation_replay", &error)
                .await?;
            return Err(error);
        }
        let runtime = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| anyhow!("checkpoint/rollback is disabled for this run"))?;
        // A previous attempt may have completed the restore and crashed (or
        // lost the standalone node write) before emitting the completion
        // event. Replaying the immutable node write is safe because the node
        // ledger rejects replacement with different contents.
        let session_node_id = match (
            operation.transition_session_node_id.as_deref(),
            operation.transition_event_ref.as_ref(),
        ) {
            (Some(node_id), Some(event_ref)) => {
                let expected_node_id = runtime.rollback_transition_node_id(
                    &artifact,
                    &request.source_session_node_id,
                    &request.rollback_id,
                );
                if node_id != expected_node_id {
                    let error = anyhow!(
                        "rollback operation transition node is bound to another source state"
                    );
                    self.emit_rollback_failure(request, "operation_binding", &error)
                        .await?;
                    return Err(error);
                }
                match runtime.save_rollback_transition_node(
                    &request.source_session_node_id,
                    &artifact,
                    &request.rollback_id,
                    node_id.to_string(),
                    event_ref,
                ) {
                    Ok(node) => Some(node.session_node_id),
                    Err(error) => {
                        let error = anyhow!(error);
                        self.emit_rollback_failure(request, "transition_node_persistence", &error)
                            .await?;
                        return Err(error);
                    }
                }
            }
            (None, None) => {
                let error = anyhow!("rollback operation is missing its transition-node binding");
                self.emit_rollback_failure(request, "operation_replay", &error)
                    .await?;
                return Err(error);
            }
            _ => {
                let error = anyhow!("rollback operation has an incomplete transition-node binding");
                self.emit_rollback_failure(request, "operation_replay", &error)
                    .await?;
                return Err(error);
            }
        };
        self.emit(
            Event::new_v2(
                EventKind::RollbackSkippedAlreadyApplied,
                0,
                "rollback already applied",
            )
            .tool("rollback")
            .call_id(&request.rollback_id)
            .effect_scope("workspace")
            .reversibility("reversible")
            .action_digest(rollback_action_digest(request))
            .external_mutation(false)
            .payload(serde_json::json!({
                "rollback_id": request.rollback_id,
                "checkpoint_id": request.checkpoint_id,
                "session_node_id": session_node_id,
                "disposition": "already_applied",
            })),
        )
        .await?;
        Ok(RollbackOutcome {
            artifact,
            operation,
            disposition: RestoreDisposition::AlreadyApplied,
            session_node_id,
        })
    }

    pub async fn run(&self) -> Result<Outcome> {
        match self.run_inner().await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let message = redact_text(&error.to_string());
                if let Err(event_error) = self
                    .emit(
                        self.event(EventKind::RunFinished, 0, format!("run failed: {message}"))
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
        let mut checkpoint_state = self
            .checkpoint
            .as_ref()
            .map(|runtime| runtime.new_run_state());

        let meta = JournalMeta {
            format: if self.checkpoint.is_some() {
                JOURNAL_FORMAT_V2.to_string()
            } else {
                JOURNAL_FORMAT_V1.to_string()
            },
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            model: self.provider.model().to_string(),
            workspace: self.contract.workspace().display().to_string(),
            goal: redact_text(&self.contract.goal),
            boundary_digest: self.contract.digest(),
            unattended: self.contract.is_unattended(),
            config_files: self.contract.config_files.clone(),
        };
        self.emit(
            self.event(EventKind::RunStarted, 0, "run started")
                .payload(meta.to_value()),
        )
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

            self.emit(self.event(EventKind::TurnStarted, turn, format!("turn {turn}")))
                .await?;
            self.emit(self.event(
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
                self.event(EventKind::ModelResponse, turn, "provider response received")
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
                        self.event(EventKind::ToolRequested, turn, "invalid tool call received")
                            .tool(&call.name)
                            .call_id(&call.id),
                    )
                    .await?;
                    let safe_call = sanitized_invalid_call(&call);
                    let context = FailureContext::from_call(&call);
                    self.record_tool_error_with_context(
                        &mut history,
                        &safe_call,
                        turn,
                        EventKind::ToolBlocked,
                        error,
                        checkpoint_state.as_ref(),
                        &context,
                        FailureClass::InvalidToolCall,
                    )
                    .await?;
                    continue;
                }
                if !specs.iter().any(|spec| spec.name == call.name) {
                    self.emit(
                        self.event(
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
                    let context = FailureContext::from_call(&call);
                    self.record_tool_error_with_context(
                        &mut history,
                        &call,
                        turn,
                        EventKind::ToolBlocked,
                        error,
                        checkpoint_state.as_ref(),
                        &context,
                        FailureClass::InvalidToolCall,
                    )
                    .await?;
                    continue;
                }
                if call.name == "finish" {
                    match self.finish_status(&call, evidence.len()) {
                        Ok(status) => {
                            self.emit(
                                self.event(
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
                            let context = FailureContext::from_call(&call);
                            self.record_tool_error_with_context(
                                &mut history,
                                &call,
                                turn,
                                EventKind::ToolBlocked,
                                error,
                                checkpoint_state.as_ref(),
                                &context,
                                FailureClass::InvalidToolCall,
                            )
                            .await?;
                        }
                    }
                } else if let Some(status) = self
                    .process_tool(
                        &mut history,
                        call,
                        turn,
                        &mut evidence,
                        &mut checkpoint_state,
                    )
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
            self.event(
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
        checkpoint_state: &mut Option<checkpoint::RunCheckpointState>,
    ) -> Result<Option<GoalStatus>> {
        self.emit(
            self.event(
                EventKind::ToolRequested,
                turn,
                format!("tool requested: {}", call.name),
            )
            .tool(&call.name)
            .call_id(&call.id),
        )
        .await?;
        if call.name.eq_ignore_ascii_case("checkpoint")
            || call.name.eq_ignore_ascii_case("rollback")
        {
            let context = FailureContext::from_call(&call);
            let error = anyhow!(
                "{} is an internal operator capability and cannot be model-invoked",
                call.name
            );
            self.tool_blocked_with_context(
                history,
                &call,
                turn,
                error,
                checkpoint_state.as_ref(),
                &context,
                FailureClass::InvalidToolCall,
            )
            .await?;
            return Ok(None);
        }
        let assessment = match self.tools.assess(&call, &self.sandbox).await {
            Ok(assessment) => assessment,
            Err(error) => {
                let context = FailureContext::from_call(&call);
                self.tool_blocked_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    checkpoint_state.as_ref(),
                    &context,
                    FailureClass::ToolFailed,
                )
                .await?;
                return Ok(None);
            }
        };
        if let Err(error) = assessment.validate_effect() {
            let context = FailureContext::from_assessment(&call, &assessment);
            self.tool_blocked_with_context(
                history,
                &call,
                turn,
                error,
                checkpoint_state.as_ref(),
                &context,
                FailureClass::ToolFailed,
            )
            .await?;
            return Ok(None);
        }
        let effect = assessment
            .effect
            .expect("validated tool assessment must have an effect descriptor");
        let effect_scope = effect.scope.as_str();
        let reversibility = effect.reversibility.as_str();
        let external_mutation = effect.is_external_mutation();
        let action_digest = action_digest(&call, &assessment);
        let failure_context = FailureContext::from_assessment(&call, &assessment);
        if let (Some(runtime), Some(state)) = (self.checkpoint.as_ref(), checkpoint_state.as_ref())
        {
            if let Some(record) = runtime.find_failed_path(
                state,
                &call.name,
                &failure_context.args_digest,
                &failure_context.resource_digest,
            )? {
                let error = anyhow!("equivalent failed path is blocked: {}", record.failure_id);
                self.tool_blocked_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    Some(state),
                    &failure_context,
                    FailureClass::ToolFailed,
                )
                .await?;
                return Ok(None);
            }
        }
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
            self.tool_blocked_with_context(
                history,
                &call,
                turn,
                error,
                checkpoint_state.as_ref(),
                &failure_context,
                FailureClass::SandboxDenied,
            )
            .await?;
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
            self.event(
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
            .rule(decision.rule_id.as_deref().unwrap_or("default-deny"))
            .effect_scope(effect_scope)
            .reversibility(reversibility)
            .action_digest(action_digest.clone())
            .external_mutation(external_mutation),
        )
        .await?;
        if decision.is_deny() {
            let error = pangu_core::Error::Denied {
                reason: decision.denial_message(),
            };
            self.tool_blocked_with_context(
                history,
                &call,
                turn,
                error,
                checkpoint_state.as_ref(),
                &failure_context,
                FailureClass::PolicyDenied,
            )
            .await?;
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
                self.tool_blocked_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    checkpoint_state.as_ref(),
                    &failure_context,
                    FailureClass::SandboxDenied,
                )
                .await?;
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
                self.tool_blocked_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    checkpoint_state.as_ref(),
                    &failure_context,
                    FailureClass::ApprovalDenied,
                )
                .await?;
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
                self.event(
                    EventKind::ApprovalRequested,
                    turn,
                    "human approval requested",
                )
                .tool(&call.name)
                .call_id(&call.id)
                .risk(assessment.risk.as_str())
                .effect_scope(effect_scope)
                .reversibility(reversibility)
                .action_digest(action_digest.clone())
                .external_mutation(external_mutation),
            )
            .await?;
            let response = self.approval.decide(&approval_request).await;
            self.emit(
                self.event(EventKind::ApprovalResolved, turn, response.as_str())
                    .tool(&call.name)
                    .call_id(&call.id)
                    .verdict(response.as_str())
                    .effect_scope(effect_scope)
                    .reversibility(reversibility)
                    .action_digest(action_digest.clone())
                    .external_mutation(external_mutation),
            )
            .await?;
            match response {
                ApprovalResponse::AllowOnce | ApprovalResponse::AllowRule(_) => {}
                ApprovalResponse::Abort(reason) => {
                    let error = pangu_core::Error::Denied { reason };
                    self.tool_blocked_with_context(
                        history,
                        &call,
                        turn,
                        error,
                        checkpoint_state.as_ref(),
                        &failure_context,
                        FailureClass::ApprovalDenied,
                    )
                    .await?;
                    return Ok(Some(GoalStatus::Aborted));
                }
                ApprovalResponse::Deny | ApprovalResponse::NoAnswer => {
                    let error = pangu_core::Error::Denied {
                        reason: "human approval was not granted".into(),
                    };
                    self.tool_blocked_with_context(
                        history,
                        &call,
                        turn,
                        error,
                        checkpoint_state.as_ref(),
                        &failure_context,
                        FailureClass::ApprovalDenied,
                    )
                    .await?;
                    return Ok(None);
                }
            }
        }

        let action = VerifiedAction::new(call.clone(), resources, Arc::clone(&self.sandbox));
        let started_event = self
            .emit_receipt(
                self.event(EventKind::ToolStarted, turn, "tool execution started")
                    .tool(&call.name)
                    .call_id(&call.id)
                    .effect_scope(effect_scope)
                    .reversibility(reversibility)
                    .action_digest(action_digest.clone())
                    .external_mutation(external_mutation),
            )
            .await?;
        if let (Some(runtime), Some(state)) = (self.checkpoint.as_ref(), checkpoint_state.as_mut())
        {
            if let Err(error) =
                runtime.record_external_effect(state, &started_event, effect, &action_digest)
            {
                // The external adapter has not been called yet, so a ledger
                // failure is a normal blocked tool path, not a claimed effect.
                self.tool_failure_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    checkpoint_state.as_ref(),
                    &failure_context,
                    FailureClass::IrreversibleExternalBlocked,
                )
                .await?;
                return Ok(None);
            }
        }
        match self.tools.execute(&action).await {
            Ok(output) => {
                if output.content.len() > self.sandbox.max_tool_output_bytes {
                    let error = anyhow!("tool output exceeds configured limit");
                    self.tool_failure_with_context(
                        history,
                        &call,
                        turn,
                        error,
                        checkpoint_state.as_ref(),
                        &failure_context,
                        FailureClass::ToolFailed,
                    )
                    .await?;
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
                let finished_event = self
                    .emit_receipt(
                        self.event(
                            EventKind::ToolFinished,
                            turn,
                            format!("tool succeeded bytes={output_bytes} sha256={output_digest}"),
                        )
                        .tool(&call.name)
                        .call_id(&call.id)
                        .effect_scope(effect_scope)
                        .reversibility(reversibility)
                        .action_digest(action_digest.clone())
                        .external_mutation(external_mutation)
                        .payload(serde_json::json!({
                            "ok": true,
                            "evidence": bounded_evidence,
                            "output_bytes": output_bytes,
                            "output_sha256": output_digest,
                        })),
                    )
                    .await?;
                let mut checkpoint_error: Option<(&'static str, anyhow::Error)> = None;
                if let (Some(runtime), Some(state)) =
                    (self.checkpoint.as_ref(), checkpoint_state.as_mut())
                {
                    match self
                        .authorize_checkpoint(runtime, &finished_event, turn, &action_digest)
                        .await
                    {
                        Ok(()) => {
                            match runtime.commit_after_success(state, &finished_event, effect) {
                                Ok(commit) => {
                                    self.emit(
                                    Event::new_v2(
                                        EventKind::CheckpointCreated,
                                        turn,
                                        "checkpoint created",
                                    )
                                    .tool("checkpoint")
                                    .call_id(&commit.artifact.session_node_id)
                                    .effect_scope("session")
                                    .reversibility("reversible")
                                    .action_digest(pangu_core::hex_sha256(&format!(
                                        "checkpoint:{}",
                                        commit.artifact.event_ref.event_id
                                    )))
                                    .external_mutation(false)
                                    .payload(serde_json::json!({
                                        "checkpoint_id": commit.artifact.checkpoint_id,
                                        "session_node_id": commit.artifact.session_node_id,
                                        "event_ref": commit.artifact.event_ref,
                                        "snapshot_digest": commit.artifact.snapshot_digest,
                                        "workspace_digest": commit.artifact.workspace_digest,
                                        "contract_digest": commit.artifact.contract_digest,
                                        "policy_digest": commit.artifact.policy_digest,
                                        "parent_checkpoint_id": commit.artifact.parent_checkpoint_id,
                                    })),
                                )
                                .await?;
                                }
                                Err(error) => checkpoint_error = Some(("snapshot", error)),
                            }
                        }
                        Err((stage, error)) => checkpoint_error = Some((stage, error)),
                    }
                }
                let checkpoint_message = checkpoint_error.as_ref().map(|(_, error)| {
                    truncate_middle(
                        &redact_text(&error.to_string()),
                        self.sandbox.max_tool_output_bytes.min(16 * 1024),
                    )
                });
                let history_content = checkpoint_message
                    .as_ref()
                    .map(|message| format!("{content}\n[checkpoint failed: {message}]"))
                    .unwrap_or(content);
                history.push(Message::tool_result(&call.id, &call.name, history_content));
                if let Some((failure_stage, error)) = checkpoint_error {
                    let safe_error = truncate_middle(
                        &redact_text(&error.to_string()),
                        self.sandbox.max_tool_output_bytes.min(16 * 1024),
                    );
                    self.emit(
                        Event::new_v2(
                            EventKind::CheckpointFailed,
                            turn,
                            "checkpoint creation failed",
                        )
                        .tool("checkpoint")
                        .effect_scope("session")
                        .reversibility("reversible")
                        .action_digest(action_digest.clone())
                        .external_mutation(false)
                        .payload(serde_json::json!({
                            "ok": false,
                            "failure_stage": failure_stage,
                            "error": safe_error,
                            "failure_policy": self.checkpoint_failure_policy(),
                        })),
                    )
                    .await?;
                    if self.checkpoint_failure_policy() == CheckpointFailurePolicy::NeedsInput {
                        return Ok(Some(GoalStatus::NeedsInput));
                    }
                    return Err(anyhow!(
                        "checkpoint creation failed after a successful tool action"
                    ));
                }
                Ok(None)
            }
            Err(error) => {
                self.tool_failure_with_context(
                    history,
                    &call,
                    turn,
                    error,
                    checkpoint_state.as_ref(),
                    &failure_context,
                    FailureClass::ToolFailed,
                )
                .await?;
                Ok(None)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn tool_blocked_with_context(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        error: impl std::fmt::Display,
        state: Option<&checkpoint::RunCheckpointState>,
        context: &FailureContext,
        class: FailureClass,
    ) -> Result<()> {
        self.record_tool_error_with_context(
            history,
            call,
            turn,
            EventKind::ToolBlocked,
            error,
            state,
            context,
            class,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn tool_failure_with_context(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        error: impl std::fmt::Display,
        state: Option<&checkpoint::RunCheckpointState>,
        context: &FailureContext,
        class: FailureClass,
    ) -> Result<()> {
        self.record_tool_error_with_context(
            history,
            call,
            turn,
            EventKind::ToolFinished,
            error,
            state,
            context,
            class,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_tool_error_with_context(
        &self,
        history: &mut Vec<Message>,
        call: &ToolCall,
        turn: u32,
        kind: EventKind,
        error: impl std::fmt::Display,
        state: Option<&checkpoint::RunCheckpointState>,
        context: &FailureContext,
        class: FailureClass,
    ) -> Result<()> {
        let message = redact_text(&error.to_string());
        let message = truncate_middle(&message, self.sandbox.max_tool_output_bytes.min(16 * 1024));
        let safe_name = sanitized_text(&call.name, 128, "tool");
        let safe_call_id = sanitized_text(&call.id, 256, "call");
        let event = self
            .emit_receipt(
                self.event(kind, turn, message.clone())
                    .tool(&safe_name)
                    .call_id(&safe_call_id)
                    .payload(serde_json::json!({"ok": false, "error": message})),
            )
            .await?;
        if let (Some(runtime), Some(state)) = (self.checkpoint.as_ref(), state) {
            let record = runtime.record_failed_path(
                state,
                &safe_name,
                &context.args_digest,
                &context.resource_digest,
                class,
                &event,
            )?;
            self.emit(
                Event::new_v2(EventKind::FailedPathRecorded, turn, "failed path recorded")
                    .tool(&safe_name)
                    .call_id(&safe_call_id)
                    .payload(serde_json::json!({
                        "failure_id": record.failure_id,
                        "failure_class": format!("{class:?}"),
                        "attempt_count": record.attempt_count,
                    })),
            )
            .await?;
        }
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
        self.emit(self.event(EventKind::BudgetExhausted, turn, text))
            .await
    }

    fn event(&self, kind: pangu_core::EventKind, turn: u32, message: impl Into<String>) -> Event {
        if self.checkpoint.is_some() {
            Event::new_v2(kind, turn, message)
        } else {
            Event::new(kind, turn, message)
        }
    }

    async fn emit(&self, event: Event) -> Result<()> {
        self.event_sink
            .emit(redact_event(event))
            .await
            .map_err(|error| anyhow!(error))
    }

    async fn emit_receipt(&self, event: Event) -> Result<Event> {
        self.event_sink
            .emit_with_receipt(redact_event(event))
            .await
            .map_err(|error| anyhow!(error))
    }

    fn checkpoint_failure_policy(&self) -> CheckpointFailurePolicy {
        self.checkpoint
            .as_ref()
            .map(|runtime| runtime.failure_policy())
            .unwrap_or(CheckpointFailurePolicy::FailRun)
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

#[derive(Debug, Clone)]
pub struct RollbackOutcome {
    pub artifact: CheckpointArtifact,
    pub operation: RollbackOperation,
    pub disposition: RestoreDisposition,
    /// The immutable post-rollback transition node, when this call applied a
    /// new restore. A repeated idempotent call returns `None` because it did
    /// not create another node.
    pub session_node_id: Option<String>,
}
