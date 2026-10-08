//! Pangu Agent runtime.
//!
//! The runtime owns the only path from a model tool call to a side effect:
//! assess -> policy -> L3 validation -> approval -> execute -> evidence. The
//! concrete provider and tool implementations depend on this crate, rather
//! than the runtime depending on adapters.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How many trailing turns are always in the assembled window (§3.2 FORCED).
const RECENT_TURNS: usize = 8;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use pangu_boundary::{
    ActionRequest, ApprovalHandler, ApprovalMode, ApprovalRequest, ApprovalResponse,
    CheckpointFailurePolicy, GoalContract, GoalStatus, Policy, ResourceRequest, Sandbox,
    ValidatedResources,
};
use pangu_core::{
    assemble, redact_event, redact_text, truncate_middle, ChatResponse, CheckpointArtifact,
    DeliverableStore, Event, EventKind, EventSink, FailureClass, JournalMeta, MemoryStore, Message,
    RestoreDisposition, RollbackOperation, RollbackRequest, SkillRegistry, ToolCall, ToolSpec,
    Usage, Value, JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2,
};

pub mod capability;
mod checkpoint;
pub mod conversation;
mod effect;

pub use capability::{Capability, CapabilityManifest};
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
    /// The action uses the browser session the operator enabled. It is not a
    /// path, host, or launchable command, but it is still a named resource.
    pub browser_session: bool,
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
            browser_session: false,
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
                if self.argv.is_empty() && !self.browser_session {
                    return Err(anyhow!(
                        "process-read assessment must declare an argv or browser session"
                    ));
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
                if self.hosts.is_empty()
                    && self.argv.is_empty()
                    && self.write_paths.is_empty()
                    && !self.browser_session
                {
                    return Err(anyhow!(
                        "external-mutation assessment must declare a host, argv, write path, or browser session"
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
    /// F3: the exact argv the executor's `verify` tool will run. Must equal
    /// the contract-frozen `GoalContract::verify_command`; `Agent::new`
    /// refuses a mismatch. Empty means the executor has no verify tool.
    fn verify_command(&self) -> Vec<String> {
        Vec::new()
    }
    async fn assess(&self, call: &ToolCall, sandbox: &Sandbox) -> Result<ToolAssessment>;
    async fn execute(&self, action: &VerifiedAction) -> Result<ToolOutput>;
}

/// D1: builds the tool executor a restricted sub-agent will use. Called by
/// the parent run once per delegation. The factory is operator wiring (the
/// CLI builds a fresh toolkit); whatever it returns is checked against the
/// derived child contract like any other executor, so a factory cannot
/// smuggle capabilities the child contract does not declare.
pub trait SubtoolFactory: Send + Sync {
    fn build(&self, verify_command: Vec<String>) -> Result<std::sync::Arc<dyn ToolExecutor>>;
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

fn parse_text_actions(content: &str) -> Result<Vec<pangu_core::ToolCall>> {
    let mut calls = Vec::new();
    for (index, block) in content.split("```action").skip(1).enumerate() {
        let body = block.split("```").next().unwrap_or("").trim();
        if body.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(body)?;
        let name = value
            .get("name")
            .and_then(|item| item.as_str())
            .unwrap_or("");
        let args = value
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if name.trim().is_empty() || !args.is_object() {
            return Err(anyhow!(
                "text action block must contain a name and object arguments"
            ));
        }
        let call = pangu_core::ToolCall {
            id: format!("text-action-{index}"),
            name: name.to_string(),
            args,
        };
        call.validate().map_err(|error| anyhow!(error))?;
        calls.push(call);
    }
    Ok(calls)
}

pub struct Agent {
    contract: GoalContract,
    policy: Arc<Policy>,
    sandbox: Arc<Sandbox>,
    provider: Arc<dyn Provider>,
    /// B5: declared fallback providers, in contract order. Empty = no
    /// fallback.
    fallbacks: Vec<Arc<dyn Provider>>,
    tools: Arc<dyn ToolExecutor>,
    initial_tool_digest: String,
    approval: Arc<dyn ApprovalHandler>,
    event_sink: Arc<dyn EventSink>,
    checkpoint: Option<Arc<checkpoint::CheckpointRuntime>>,
    conversation: Option<Arc<conversation::ConversationRuntime>>,
    /// History to continue from. Model input only: it carries no decision and
    /// no approval, and every action in the resumed run is re-evaluated.
    resume_from: Option<Vec<Message>>,
    /// B3: the memory candidate store. Attached only when the contract
    /// enables the queue; used to inject accepted, clearly-labeled memory
    /// into fresh runs.
    memory: Option<Arc<MemoryStore>>,
    /// B2: the skill registry. Attached only when the contract enables the
    /// registry; used to inject the skill index and to pin the readable set.
    skills: Option<Arc<SkillRegistry>>,
    /// D3/D4: the deliverable registry. Attached only when the contract
    /// declares deliverables; `complete` runs the acceptance checks against
    /// it and finished runs record their delivery snapshots into it.
    deliverables: Option<Arc<DeliverableStore>>,
    /// D1: the sub-agent tool factory. Attached only when the contract
    /// enables delegation; builds the restricted executor each child runs
    /// with.
    delegation: Option<Arc<dyn SubtoolFactory>>,
    /// D1/D2: whether a delegated child must hold the workspace write lock.
    /// Defaults on: a child shares the parent's workspace, so concurrent
    /// children would otherwise race. Kept as a field so a deployment that
    /// serialises its own writers can turn the wait off.
    delegation_workspace_lock: bool,
    /// How long a delegated child waits for the workspace lock before the
    /// delegation fails closed. Bounded on purpose: a holder that died without
    /// releasing leaves an unreleasable file (see `pangu_core::lockfile`).
    delegation_lock_timeout: std::time::Duration,
    /// Whether each tool call takes per-path locks.
    ///
    /// This is the fine-grained default: only overlapping files serialise. The
    /// whole-workspace lock (`delegation_workspace_lock`) is the coarse option
    /// for callers that cannot say which paths they will touch.
    workspace_path_lock: bool,
    /// How long a tool call waits for its paths before failing closed.
    path_lock_timeout: std::time::Duration,
    /// Discovered build modules, used to widen a build-file edit into a module
    /// lock. `None` means module locking is off.
    ///
    /// Only a confident map is consulted when locking; see
    /// [`pangu_core::ModuleMap::is_confident`].
    module_map: Option<std::sync::Arc<pangu_core::ModuleMap>>,
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
        Self::with_chain(
            contract,
            policy,
            sandbox,
            vec![provider],
            tools,
            approval,
            event_sink,
        )
    }

    /// B5: build a run over a declared provider chain. `providers[0]` is the
    /// primary; the rest are the fallbacks, in the order the contract froze
    /// them. The chain must match the contract position by position (model
    /// name), or the run is refused — a fallback is never injected silently.
    pub fn with_chain(
        contract: GoalContract,
        policy: Arc<Policy>,
        sandbox: Arc<Sandbox>,
        providers: Vec<Arc<dyn Provider>>,
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
        if tools.verify_command() != contract.verify_command {
            return Err(anyhow!(
                "tool executor's verify command does not match GoalContract verify_command"
            ));
        }
        // B3: the propose_memory advertisement must match the contract — a
        // tool the contract does not know about must not exist, and a
        // contract-enabled queue without its tool is a broken freeze.
        let memory_advertised = tools
            .specs()
            .iter()
            .any(|spec| spec.name == "propose_memory");
        if contract.memory.enabled != memory_advertised {
            return Err(anyhow!(
                "tool executor's propose_memory advertisement does not match GoalContract memory.enabled"
            ));
        }
        // B2: the read_skill advertisement must match the contract the same
        // way.
        let skills_advertised = tools.specs().iter().any(|spec| spec.name == "read_skill");
        if contract.skills.enabled != skills_advertised {
            return Err(anyhow!(
                "tool executor's read_skill advertisement does not match GoalContract skills.enabled"
            ));
        }
        if contract.policy_digest != policy.digest() {
            return Err(anyhow!(
                "GoalContract and Policy do not describe the same rule set"
            ));
        }
        if providers.is_empty() {
            return Err(anyhow!("provider chain must contain the primary provider"));
        }
        if providers.len() != contract.fallbacks.len() + 1 {
            return Err(anyhow!(
                "provider chain length ({}) does not match GoalContract fallbacks ({})",
                providers.len(),
                contract.fallbacks.len()
            ));
        }
        for (index, candidate) in contract.fallbacks.iter().enumerate() {
            if providers[index + 1].model() != candidate.model {
                return Err(anyhow!(
                    "fallback provider at position {index} does not match GoalContract \
                     fallback model `{}`",
                    candidate.model
                ));
            }
        }
        let checkpoint = checkpoint::CheckpointRuntime::from_contract(&contract)?;
        let conversation = conversation::ConversationRuntime::from_contract(&contract)?;
        let mut fallback_iter = providers.into_iter();
        let provider = fallback_iter.next().expect("primary checked above");
        Ok(Self {
            contract,
            policy,
            sandbox,
            provider,
            fallbacks: fallback_iter.collect(),
            initial_tool_digest: pangu_core::hex_sha256(
                &tools
                    .specs()
                    .iter()
                    .map(|spec| spec.name.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            tools,
            approval,
            delegation: None,
            // Off by default: the child's tool calls take per-path locks, so
            // unrelated work is not blocked. Turning this on excludes the whole
            // workspace, which is only wanted when the caller needs to stop
            // *everything* else rather than just overlapping paths.
            delegation_workspace_lock: false,
            delegation_lock_timeout: Duration::from_secs(120),
            workspace_path_lock: true,
            path_lock_timeout: Duration::from_secs(120),
            module_map: None,
            event_sink,
            checkpoint: checkpoint.map(Arc::new),
            conversation: conversation.map(Arc::new),
            resume_from: None,
            memory: None,
            skills: None,
            deliverables: None,
        })
    }

    /// B3: attach the memory candidate store. The same store instance must
    /// back the toolkit's `propose_memory` tool; the run refuses to start if
    /// the contract enables the queue but no store was attached.
    pub fn with_memory(mut self, store: Arc<MemoryStore>) -> Self {
        self.memory = Some(store);
        self
    }

    /// B2: attach the skill registry. The same registry instance must back
    /// the toolkit's `read_skill` tool; the run refuses to start if the
    /// contract enables the registry but no registry was attached, or if the
    /// loaded set diverges from the contract-frozen one.
    pub fn with_skills(mut self, registry: Arc<SkillRegistry>) -> Self {
        self.skills = Some(registry);
        self
    }

    /// D3/D4: attach the deliverable registry. The run refuses to start if
    /// the contract declares deliverables but no registry was attached.
    pub fn with_deliverables(mut self, store: Arc<DeliverableStore>) -> Self {
        self.deliverables = Some(store);
        self
    }

    /// D1: attach the sub-agent tool factory. The `delegate_task` tool
    /// exists only when the contract enables delegation AND a factory is
    /// attached; run_inner refuses a contract/attachment mismatch.
    pub fn with_delegation(mut self, factory: Arc<dyn SubtoolFactory>) -> Self {
        self.delegation = Some(factory);
        self
    }

    /// Configure the workspace lock a delegated child must hold while running.
    ///
    /// The child's own tool calls already take **per-path** locks, so
    /// overlapping files serialise and unrelated files do not. This coarse
    /// whole-workspace lock is for callers that need to exclude everything at
    /// once — it is off by default precisely because it blocks unrelated work.
    ///
    /// `timeout` bounds the wait. It is deliberately not `Option<Duration>`:
    /// an unbounded wait cannot be satisfied when the previous holder died
    /// without releasing, so there is no useful sense in which it is "more
    /// permissive" — it only converts a reportable failure into a hang.
    pub fn with_delegation_workspace_lock(mut self, enabled: bool, timeout: Duration) -> Self {
        self.delegation_workspace_lock = enabled;
        self.delegation_lock_timeout = timeout;
        self
    }

    /// Configure the per-path lock every tool call takes.
    ///
    /// `timeout` bounds the wait for each path, for the same reason the
    /// workspace lock is bounded: a holder killed before it could release
    /// leaves a lock file nothing will remove.
    pub fn with_path_locks(mut self, enabled: bool, timeout: Duration) -> Self {
        self.workspace_path_lock = enabled;
        self.path_lock_timeout = timeout;
        self
    }

    /// Supply the discovered build-module layout for module-aware locking.
    ///
    /// With a map attached, a tool call that edits a build file additionally
    /// locks the module that file declares. This is what lets one agent own a
    /// Gradle subproject or a Rust crate without blocking agents working in
    /// sibling modules.
    ///
    /// An **unconfident** map is accepted here and ignored at lock time: it is
    /// stored so the run can still report what was found, but scoping locks by
    /// a map that failed to parse would let two agents into one module with no
    /// lock reporting anything wrong.
    pub fn with_module_map(mut self, map: Option<std::sync::Arc<pangu_core::ModuleMap>>) -> Self {
        self.module_map = map;
        self
    }

    /// Whether a delegated child must take the workspace write lock.
    fn delegation_needs_workspace_lock(&self) -> bool {
        self.delegation_workspace_lock
    }

    /// Continue from a stored conversation.
    ///
    /// The restored history is **model input only**. It does not carry a
    /// decision, an effect, or any memory of an approval, and this method does
    /// not skip a single gate: every tool call the resumed run makes is
    /// re-evaluated through `Policy -> Sandbox -> Approval` exactly as in a
    /// fresh run.
    ///
    /// The workspace is *not* restored. That is rollback's job, and doing it
    /// here would mean a resume could silently change files without the
    /// compare-and-swap, approval, and effect accounting that rollback goes
    /// through. Resuming a conversation while the workspace is in a different
    /// state is the operator's call to make, visibly, with
    /// `pangu rollback`.
    pub fn resume_from(mut self, conversation: &pangu_core::ConversationSnapshot) -> Result<Self> {
        conversation.validate()?;
        let history = conversation.restore()?;
        conversation::validate_resumable(&history)?;
        self.resume_from = Some(history);
        Ok(self)
    }

    /// The conversation ids this agent could resume from, oldest first.
    pub fn resumable_conversations(&self) -> anyhow::Result<Vec<String>> {
        match &self.conversation {
            Some(runtime) => runtime.list().map_err(|error| anyhow!(error)),
            None => Ok(Vec::new()),
        }
    }

    /// Continue from the most recently stored conversation.
    pub fn resume_latest(self) -> Result<Self> {
        let Some(runtime) = &self.conversation else {
            return Err(anyhow!(
                "conversation persistence is disabled; enable `conversation.enabled` to resume"
            ));
        };
        let Some(latest) = runtime.latest()? else {
            return Err(anyhow!("no stored conversation to resume from"));
        };
        self.resume_from(&latest)
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
            // Pangu-internal I/O: the artifact root lives under `.pangu`,
            // which tools can never touch (forbidden glob), but the runtime
            // itself must.
            hosts: Vec::new(),
            argv: Vec::new(),
            cwd: None,
            browser_session: false,
            internal: true,
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
            impact: pangu_boundary::ApprovalImpact {
                writes: vec![format!(
                    "checkpoint {} 恢复到 node {}",
                    request.checkpoint_id, request.source_session_node_id
                )],
                ..Default::default()
            },
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
            hosts: Vec::new(),
            argv: Vec::new(),
            cwd: None,
            browser_session: false,
            // Pangu-internal I/O: see the rollback site note.
            internal: true,
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
                // Recorded in an approval event, which is part of the audit
                // trail; see the journal header for why the displayable form is
                // used rather than the canonicalized one.
                target: Some(redact_text(&pangu_core::util::displayable_path(
                    self.contract.workspace(),
                ))),
                invariant: Some("I-Checkpoint-After-Verified-Action".into()),
                preview: "create an internal workspace checkpoint".into(),
                args: approval_args(&args),
                impact: pangu_boundary::ApprovalImpact {
                    writes: vec![pangu_core::util::displayable_path(
                        self.contract.workspace(),
                    )],
                    ..Default::default()
                },
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
                let message = redact_text(&describe_error(&error));
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

    /// B2: the run's skill registry must exist when enabled and must match
    /// the contract-frozen skill set position by position (name, version,
    /// package digest, signing status). Rejected packages are audible `Note`
    /// events — a skill that fails its integrity check is never silently
    /// skipped.
    async fn check_skills_binding(&self) -> Result<()> {
        if !self.contract.skills.enabled {
            return Ok(());
        }
        let registry = self.skills.as_ref().ok_or_else(|| {
            anyhow!(
                "GoalContract enables the skill registry but no registry was attached;                  build the agent with `with_skills`"
            )
        })?;
        for rejected in registry.rejected() {
            self.emit(self.event(
                EventKind::Note,
                0,
                format!(
                    "skill `{}` rejected: {}",
                    rejected.dir_name, rejected.reason
                ),
            ))
            .await?;
        }
        let frozen = &self.contract.skills.skills;
        let loaded = registry.skills();
        if frozen.len() != loaded.len() {
            anyhow::bail!(
                "loaded skill set ({}) does not match GoalContract frozen skill set ({})",
                loaded.len(),
                frozen.len()
            );
        }
        for (frozen, loaded) in frozen.iter().zip(loaded.iter()) {
            if frozen.name != loaded.name
                || frozen.version != loaded.version
                || frozen.package_digest != loaded.lock.package_digest
                || frozen.signed != loaded.signature_verified()
            {
                anyhow::bail!(
                    "skill `{}` does not match the GoalContract-frozen entry (name/version/digest/signature)",
                    loaded.name
                );
            }
        }
        Ok(())
    }

    /// B2: the skill index injection block for this run, or `None`.
    fn skills_index_block(&self) -> Result<Option<String>> {
        if !self.contract.skills.enabled {
            return Ok(None);
        }
        let registry = self.skills.as_ref().ok_or_else(|| {
            anyhow!(
                "GoalContract enables the skill registry but no registry was attached;                  build the agent with `with_skills`"
            )
        })?;
        Ok(registry.index_block())
    }

    /// B3: the accepted-memory injection block for this run, or `None`. The
    /// store must exist when the contract enables the queue.
    fn memory_block(&self) -> Result<Option<String>> {
        if !self.contract.memory.enabled {
            return Ok(None);
        }
        let store = self.memory.as_ref().ok_or_else(|| {
            anyhow!(
                "GoalContract enables the memory queue but no memory store was attached; \
                 build the agent with `with_memory`"
            )
        })?;
        Ok(store.injection_block())
    }

    async fn run_inner(&self) -> Result<Outcome> {
        // D3/D4: declared deliverables require the registry; undeclared
        // deliverables make the registry irrelevant.
        if !self.contract.deliverables.deliverables.is_empty() && self.deliverables.is_none() {
            return Err(anyhow!(
                "GoalContract declares deliverables but no deliverable registry was attached;                  build the agent with `with_deliverables`"
            ));
        }
        // D1: a delegation-enabled contract without its factory is a broken
        // freeze — refuse before the first turn (fail-fast, like the
        // deliverables registry check).
        if self.contract.allow_delegation && self.delegation.is_none() {
            return Err(anyhow!(
                "GoalContract enables delegation but no sub-tool factory was attached; build the                  agent with `with_delegation`"
            ));
        }
        self.check_skills_binding().await?;
        let started = Instant::now();
        let mut usage = Usage::default();
        let mut evidence = Vec::new();
        let mut history = match &self.resume_from {
            // A resumed history already carries its system turn and goal.
            // Re-seeding them would duplicate the instructions at the head and
            // leave the model with two goals.
            Some(history) => {
                conversation::validate_resumable(history)?;
                history.clone()
            }
            None => {
                let mut seeded =
                    conversation::seed_history(self.contract.system_prompt(), &self.contract.goal);
                // B3/B2: fresh runs get the accepted-memory block and the
                // skill index appended to the system turn, both explicitly
                // labeled. Resumed runs keep the blocks from when they were
                // seeded — no mid-history context mutation.
                let mut appended = String::new();
                if let Some(block) = self.memory_block()? {
                    appended.push_str("\n\n");
                    appended.push_str(&block);
                }
                if let Some(block) = self.skills_index_block()? {
                    appended.push_str("\n\n");
                    appended.push_str(&block);
                }
                if !appended.is_empty() {
                    if let Some(pangu_core::Message::System { content }) = seeded.first_mut() {
                        content.push_str(&appended);
                    }
                }
                seeded
            }
        };
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
            // The journal header is archived evidence and is read on machines
            // other than the one that wrote it, so the workspace is recorded in
            // the form an operator can use. The contract's workspace is
            // canonicalized, which on Windows yields `\\?\F:\ws` — correct for
            // the filesystem, meaningless pasted into a shell elsewhere.
            workspace: pangu_core::util::displayable_path(self.contract.workspace()),
            goal: redact_text(&self.contract.goal),
            boundary_digest: self.contract.digest(),
            unattended: self.contract.is_unattended(),
            config_files: self.contract.config_files.clone(),
            // C5: record the declared backend so audit trails show what the
            // operator claimed about the environment. Redacted like every
            // payload string; absent when undeclared.
            execution_profile: if self.contract.execution().is_declared() {
                Some(self.contract.execution().profile.as_str().to_string())
            } else {
                None
            },
            execution_description: self
                .contract
                .execution()
                .description
                .as_deref()
                .map(redact_text),
        };
        self.emit(
            self.event(EventKind::RunStarted, 0, "run started")
                .payload(meta.to_value()),
        )
        .await?;

        let mut act_phase = !self.contract.plan_first();
        // B5: the active position in the provider chain (0 = primary) and the
        // accumulated spend. Cost is summed per segment: each response's usage
        // is priced by the provider that served it, so a switch can never
        // under-count the cost of tokens consumed on a pricier fallback.
        let mut active_provider = 0usize;
        let mut spent = if self.contract.price.is_some() {
            0.0
        } else {
            f64::INFINITY
        };
        // F4: the begin_act control tool exists only in plan-first runs. It is
        // agent-owned (like `finish`): it executes nothing and passes no gate,
        // it just ends the read-only phase.
        let mut specs = self.tools.specs();
        // D1: the agent-owned `delegate_task` control tool exists only in
        // delegation-enabled runs. The child contract is derived from the
        // parent at call time; the model can only narrow it.
        if self.contract.allow_delegation {
            specs.push(pangu_core::ToolSpec::new(
                "delegate_task",
                "Delegate one bounded subtask to a restricted sub-agent. The sub-agent gets a \
                     fresh context, the same workspace/sandbox/policy as this run, and a budget \
                     clamped to this run's remaining budget (it can never exceed them). It \
                     cannot delegate further. Arguments: task (required string), max_turns and \
                     max_cost_usd (optional narrowing). Returns the sub-agent's final summary \
                     and its status; its spend counts against this run's budget.",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["task"],
                    "properties": {
                        "task": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Self-contained instructions for the sub-agent."
                        },
                        "max_turns": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Optional tighter turn cap for the sub-agent."
                        },
                        "max_cost_usd": {
                            "type": "number",
                            "minimum": 0,
                            "description": "Optional tighter cost cap for the sub-agent."
                        }
                    }
                }),
            ));
        }
        if self.contract.plan_first() {
            specs.push(pangu_core::ToolSpec::new(
                "begin_act",
                "End the read-only plan phase and start the act phase. Takes no arguments; \
                 mutating actions still require approval one by one.",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": [],
                    "properties": {}
                }),
            ));
        }
        for turn in 1..=self.contract.budget().max_turns {
            last_turn = turn;
            let breaches =
                self.budget_breaches(turn.saturating_sub(1), &usage, started.elapsed(), spent);
            if !breaches.is_empty() {
                self.emit_budget(turn, &breaches).await?;
                terminal = Some(GoalStatus::BudgetExhausted);
                break;
            }

            // A6-5: the assembled window is what the model sees. The full
            // history stays in memory (and in `history`); assembly is a pure
            // projection (§3.9). Input-token pressure is resolved here — by
            // degradation — not by ending the run.
            let (assembled, assembly) = match assemble(
                &history,
                RECENT_TURNS,
                &[],
                self.contract.budget().max_input_tokens,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    // "组装器组装不出来" must be distinguishable from "上下文确实
                    // 太大": it is an assembler failure, not a budget event.
                    self.emit(self.event(
                        EventKind::ModelRequest,
                        turn,
                        format!("context assembly failed: {error}"),
                    ))
                    .await?;
                    return Err(anyhow!("context assembly failed: {error}"));
                }
            };
            let modes = assembly.selections.iter().fold(
                (0usize, 0usize, 0usize),
                |(full, summary, omitted), selection| match selection.mode {
                    pangu_core::DegradeMode::Full => (full + 1, summary, omitted),
                    pangu_core::DegradeMode::Summary => (full, summary + 1, omitted),
                    pangu_core::DegradeMode::Omitted => (full, summary, omitted + 1),
                },
            );
            let current_tool_digest = pangu_core::hex_sha256(
                &self
                    .tools
                    .specs()
                    .iter()
                    .map(|spec| spec.name.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            let prefix_stable = turn == 1
                && !assembly.forced_over_budget
                && assembled.seams.is_empty()
                && current_tool_digest == self.initial_tool_digest;
            let mut assembled_event = self.event(
                EventKind::ContextAssembled,
                turn,
                format!(
                    "messages={} tokens~{} forced_over_budget={} prefix_stable={} slices: {} full, {} summary, \
                     {} omitted, {} seam(s)",
                    assembled.messages.len(),
                    assembly.estimated_tokens,
                    assembly.forced_over_budget,
                    prefix_stable,
                    modes.0,
                    modes.1,
                    modes.2,
                    assembled.seams.len()
                ),
            );
            assembled_event.payload = Some(serde_json::json!({
                "derived": true,
                "authoritative": false,
                "prefix_stable": prefix_stable
            }));
            self.emit(assembled_event).await?;
            if assembly.forced_over_budget {
                // The honest tail of the chain: even every forced slice at its
                // summary form does not fit. Terminate — but for a *budget*
                // reason, with the report attached.
                self.emit_budget(turn, &[pangu_boundary::Breach::InputTokens])
                    .await?;
                terminal = Some(GoalStatus::BudgetExhausted);
                break;
            }

            self.emit(self.event(EventKind::TurnStarted, turn, format!("turn {turn}")))
                .await?;
            let active = self.provider_for(active_provider);
            self.emit(self.event(
                EventKind::ModelRequest,
                turn,
                format!(
                    "provider={} model={} messages={} tools={} (history={})",
                    active.name(),
                    active.model(),
                    assembled.messages.len(),
                    specs.len(),
                    history.len()
                ),
            ))
            .await?;

            let response = self
                .chat_with_fallback(
                    &mut active_provider,
                    turn,
                    assembled.messages.clone(),
                    specs.clone(),
                )
                .await?;
            let response_usage = response.usage;
            // B5: price this segment by the provider that served it.
            match self.active_price(active_provider) {
                Some(price) => spent += price.cost_usd(&response_usage),
                None => spent = f64::INFINITY,
            }
            usage.merge(&response_usage);
            self.emit(
                self.event(EventKind::ModelResponse, turn, "provider response received")
                    .usage(response_usage),
            )
            .await?;

            let post_response_breaches =
                self.budget_breaches(turn, &usage, started.elapsed(), spent);
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
                        let mut calls = calls;
                        if calls.is_empty() && self.contract.model_raw_tool_calls {
                            calls = parse_text_actions(&content)?;
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
                let call_breaches = self.budget_breaches(turn, &usage, started.elapsed(), spent);
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
                if call.name == "begin_act" {
                    // F4 control call: no assess, no gates, no side effect —
                    // it only ends the read-only plan phase. Every mutating
                    // action afterwards still passes L1-L4 individually.
                    if act_phase {
                        let context = FailureContext::from_call(&call);
                        let error = anyhow!("already in the act phase");
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
                    } else {
                        act_phase = true;
                        self.emit(
                            self.event(
                                EventKind::PhaseChanged,
                                turn,
                                "plan phase complete; entering the act phase",
                            )
                            .tool("begin_act")
                            .call_id(&call.id),
                        )
                        .await?;
                        history.push(Message::tool_result(
                            &call.id,
                            "begin_act",
                            "act phase started; mutating actions now proceed through the gates",
                        ));
                    }
                } else if call.name == "finish" {
                    match self.finish_status(&call, &evidence) {
                        Ok(status) => {
                            if status == GoalStatus::Complete {
                                // D3/D4: record the delivery snapshots before
                                // the run ends; a registry failure refuses
                                // the completion.
                                if let Err(error) = self.record_deliverables(turn).await {
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
                            }
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
                } else if call.name == "delegate_task" {
                    // D1 control call: the parent run itself derives the
                    // child contract, spawns the restricted sub-agent, and
                    // merges the child's spend into its own ledger. The
                    // model supplied only the task text and optional
                    // narrowing; every budget is clamped here.
                    if let Err(error) = self
                        .handle_delegation(
                            &call,
                            turn,
                            started,
                            spent,
                            &mut usage,
                            &mut spent,
                            &mut evidence,
                            &mut history,
                        )
                        .await
                    {
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
                } else if let Some(status) = self
                    .process_tool(
                        &mut history,
                        call,
                        turn,
                        act_phase,
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
                let final_breaches = self.budget_breaches(turn, &usage, started.elapsed(), spent);
                if !final_breaches.is_empty() {
                    self.emit_budget(turn, &final_breaches).await?;
                    terminal = Some(GoalStatus::BudgetExhausted);
                }
            }
            // Per-turn save, so a crash mid-run is still resumable. Gated on
            // `save_every_turn` because it costs a write per turn.
            if let Some(runtime) = &self.conversation {
                if runtime.saves_every_turn() && terminal.is_none() {
                    // Tie the snapshot to the node the run is currently at, so
                    // `pangu session replay` can find the conversation that
                    // belongs to a node. `None` when checkpointing is off: a
                    // conversation may exist without a tree, but never the
                    // reverse.
                    let node = checkpoint_state
                        .as_ref()
                        .map(|state| state.session_node_id.as_str());
                    runtime.save(&self.contract.goal, &history, node)?;
                }
            }

            if terminal.is_some() {
                break;
            }
        }

        // Persist the conversation at the end whatever the outcome. A run that
        // hit a budget or failed partway is exactly the one an operator wants
        // to resume, so a save only on success would be useless.
        if let Some(runtime) = &self.conversation {
            let node = checkpoint_state
                .as_ref()
                .map(|state| state.session_node_id.as_str());
            runtime.save(&self.contract.goal, &history, node)?;
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
            turns: last_turn,
            cost_usd: if spent.is_finite() { Some(spent) } else { None },
        })
    }

    /// D1: execute the agent-owned `delegate_task` control call. The child
    /// contract is derived from this run's contract (never wider), the child
    /// budget is clamped to the parent's remaining budget, and the child
    /// writes into the same central journal through the same sink. The
    /// child's tokens and cost are merged into the parent's ledger, so a
    /// delegation can never be used to escape the parent's budget. Any
    /// failure here is a tool error the parent model sees — delegation is
    /// never fatal to the parent run.
    #[allow(clippy::too_many_arguments)]
    async fn handle_delegation(
        &self,
        call: &ToolCall,
        turn: u32,
        started: Instant,
        spent_now: f64,
        usage: &mut Usage,
        spent: &mut f64,
        evidence: &mut Vec<String>,
        history: &mut Vec<Message>,
    ) -> Result<()> {
        let object = call
            .args
            .as_object()
            .ok_or_else(|| anyhow!("delegate_task arguments must be an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "task" | "max_turns" | "max_cost_usd"))
        {
            return Err(anyhow!(
                "delegate_task accepts only task, max_turns, and max_cost_usd"
            ));
        }
        let task = call
            .args
            .get("task")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("delegate_task requires a string task"))?;
        if task.trim().is_empty() {
            return Err(anyhow!("delegate_task task must not be empty"));
        }
        if task.len() > 16_384 {
            return Err(anyhow!(
                "delegate_task task is {} bytes; the limit is 16384 bytes",
                task.len()
            ));
        }
        let grant_turns = match call.args.get("max_turns") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .ok_or_else(|| anyhow!("max_turns must be an integer"))?
                    .try_into()
                    .map_err(|_| anyhow!("max_turns must fit in u32"))?,
            ),
        };
        let grant_cost = match call.args.get("max_cost_usd") {
            None => None,
            Some(value) => {
                let cost = value
                    .as_f64()
                    .ok_or_else(|| anyhow!("max_cost_usd must be a number"))?;
                if !cost.is_finite() || cost < 0.0 {
                    return Err(anyhow!("max_cost_usd must be finite and >= 0"));
                }
                Some(cost)
            }
        };

        // The grant is clamped to what this run still has left. The model
        // can narrow; it can never widen — and it cannot grant what the
        // parent no longer has.
        let remaining_turns = self.contract.budget.max_turns.saturating_sub(turn);
        if remaining_turns == 0 {
            return Err(anyhow!(
                "delegation refused: no remaining turns to grant (this is the parent run's last \
                 turn)"
            ));
        }
        if !spent_now.is_finite() {
            return Err(anyhow!(
                "delegation refused: cost accounting is unavailable (unpriced run)"
            ));
        }
        let remaining_cost = self.contract.budget.max_cost_usd - spent_now;
        if remaining_cost <= 0.0 {
            return Err(anyhow!("delegation refused: no remaining cost budget"));
        }
        let remaining_wall = self
            .contract
            .budget
            .max_wall_clock_secs
            .checked_sub(started.elapsed())
            .unwrap_or_default();
        if remaining_wall.is_zero() {
            return Err(anyhow!(
                "delegation refused: no remaining wall-clock budget"
            ));
        }
        let child_budget = pangu_boundary::Budget {
            max_turns: grant_turns.unwrap_or(remaining_turns).min(remaining_turns),
            max_input_tokens: self.contract.budget.max_input_tokens,
            max_output_tokens: self.contract.budget.max_output_tokens,
            max_cost_usd: match grant_cost {
                Some(cost) => cost.min(remaining_cost),
                None => remaining_cost,
            },
            max_wall_clock_secs: remaining_wall,
        };
        let sub_max_turns = child_budget.max_turns;
        let sub_max_cost_usd = child_budget.max_cost_usd;
        let sub_max_wall_clock_secs = child_budget.max_wall_clock_secs.as_secs();
        let task_digest = pangu_core::hex_sha256(task);
        let child_contract = self
            .contract
            .derive_sub_contract(task, child_budget)
            .map_err(|error| anyhow!("delegation refused: {error}"))?;
        let factory = self
            .delegation
            .as_ref()
            .ok_or_else(|| anyhow!("delegation refused: no sub-tool factory attached"))?;
        let child_tools = factory.build(self.contract.verify_command.clone())?;
        let mut providers = vec![self.provider.clone()];
        providers.extend(self.fallbacks.iter().cloned());
        let child = Agent::with_chain(
            child_contract.clone(),
            self.policy.clone(),
            self.sandbox.clone(),
            providers,
            child_tools,
            self.approval.clone(),
            self.event_sink.clone(),
        )?;

        self.emit(
            self.event(
                EventKind::TaskDelegated,
                turn,
                format!(
                    "subtask delegated (task digest {}); child contract {}",
                    &task_digest[..12],
                    &child_contract.digest()[..12]
                ),
            )
            .tool("delegate_task")
            .call_id(&call.id)
            .payload(serde_json::json!({
                "task_sha256": task_digest,
                "task_bytes": task.len(),
                "sub_contract_digest": child_contract.digest(),
                "sub_max_turns": sub_max_turns,
                "sub_max_cost_usd": sub_max_cost_usd,
                "sub_max_wall_clock_secs": sub_max_wall_clock_secs,
            })),
        )
        .await?;

        // The child writes into the same journal and approval surface as
        // the parent; nothing about the delegation bypasses the gates.
        //
        // A sub-agent shares the parent's workspace, so it must hold the
        // workspace write lock while it runs: two writers touching the same
        // files would race, and the resulting state would match neither run's
        // recorded actions. The lock is taken here rather than inside the child
        // so that the wait is attributable to the delegation as a whole.
        //
        // Waiting is bounded. A holder that died without releasing (crash,
        // SIGKILL) leaves the file behind and nothing will ever remove it, so an
        // unbounded wait would hang the parent run forever instead of reporting
        // a problem. On expiry this is a normal tool error: the delegation fails
        // closed, the parent keeps running, and the message names the holder so
        // an operator can act. The lock file is never deleted to force progress.
        let _workspace_lock = if self.delegation_needs_workspace_lock() {
            Some(pangu_core::WorkspaceLock::acquire(
                &self.sandbox.workspace,
                pangu_core::LockMode::Write,
                self.delegation_lock_timeout,
            )?)
        } else {
            None
        };

        // Boxed because a parent run containing a child run is (bounded)
        // structural recursion.
        let outcome = Box::pin(child.run()).await?;
        drop(_workspace_lock);
        usage.merge(&outcome.usage);
        if let Some(cost) = outcome.cost_usd {
            *spent += cost;
        }
        evidence.push(format!(
            "delegate: {} -> {} (turns={})",
            &task_digest[..12],
            outcome.status.as_str(),
            outcome.turns
        ));
        let summary = outcome
            .messages
            .iter()
            .rev()
            .find_map(|message| match message {
                Message::Assistant { content, .. } if !content.trim().is_empty() => {
                    Some(content.clone())
                }
                _ => None,
            })
            .map(|content| truncate_middle(&redact_text(&content), 4000))
            .unwrap_or_else(|| "(no final assistant message)".to_string());
        let cost_text = match outcome.cost_usd {
            Some(cost) => format!("${cost:.4}"),
            None => "unpriced".to_string(),
        };
        history.push(Message::tool_result(
            &call.id,
            "delegate_task",
            format!(
                "subtask {} finished: {} (turns={}, tokens in={}, out={}, cost={})\n\n{}",
                &task_digest[..12],
                outcome.status.as_str(),
                outcome.turns,
                outcome.usage.input_tokens,
                outcome.usage.output_tokens,
                cost_text,
                summary
            ),
        ));
        Ok(())
    }

    async fn process_tool(
        &self,
        history: &mut Vec<Message>,
        call: ToolCall,
        turn: u32,
        act_phase: bool,
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
        // F4: in the plan phase the run is read-only. Mutating actions are
        // refused before any gate can approve them; only the typed `begin_act`
        // control call ends the phase, and it executes nothing.
        if !act_phase && assessment.risk.at_least(pangu_boundary::Risk::Reversible) {
            let context = FailureContext::from_assessment(&call, &assessment);
            let error = pangu_core::Error::Denied {
                reason: "plan phase is read-only; call `begin_act` before any mutating action"
                    .into(),
            };
            self.tool_blocked_with_context(
                history,
                &call,
                turn,
                error,
                checkpoint_state.as_ref(),
                &context,
                FailureClass::PolicyDenied,
            )
            .await?;
            return Ok(None);
        }
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
            read_paths: assessment.read_paths.clone(),
            write_paths: assessment.write_paths.clone(),
            hosts: assessment.hosts.clone(),
            argv: assessment.argv.clone(),
            cwd: assessment.cwd.clone(),
            browser_session: assessment.browser_session,
            // B3/B2: `propose_memory` writes and `read_skill` reads exactly
            // one Pangu-owned location (declared in their manifest entries)
            // whose path comes from the operator's config, never from model
            // output. The forbidden globs exist to keep model-controlled tool
            // paths out of Pangu-owned storage; the sanctioned tools
            // themselves are validated with the internal rule set (root
            // containment, symlinks, limits) instead.
            internal: call.name == "propose_memory" || call.name == "read_skill",
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
            let target = if resources.browser_session {
                Some("browser session".to_string())
            } else {
                resources
                    .write_paths
                    .first()
                    .or_else(|| resources.read_paths.first())
                    // The approval target is recorded in the audit trail and shown to
                    // the human asked to approve, so it uses the form they can act on.
                    .map(|path| pangu_core::util::displayable_path(path))
                    .or_else(|| resources.hosts.first().cloned())
                    .map(|value| truncate_middle(&redact_text(&value), 4096))
            };
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
                impact: pangu_boundary::ApprovalImpact {
                    command: (!assessment.argv.is_empty())
                        .then(|| truncate_middle(&redact_text(&assessment.argv.join(" ")), 4_096)),
                    network: (!assessment.hosts.is_empty()).then(|| assessment.hosts.join(", ")),
                    reads: resources
                        .read_paths
                        .iter()
                        .map(|path| pangu_core::util::displayable_path(path))
                        .collect(),
                    writes: resources
                        .write_paths
                        .iter()
                        .map(|path| pangu_core::util::displayable_path(path))
                        .collect(),
                    cwd: assessment
                        .cwd
                        .as_ref()
                        .map(|path| pangu_core::util::displayable_path(path)),
                    // F4: show what would change, bounded and redacted; honest
                    // summary when no inline diff is possible.
                    diffs: write_file_diffs(&call, &resources),
                },
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

        // Serialise this action against other agents touching the same files.
        //
        // The lock is per path, not per workspace: two agents editing different
        // files must not wait for each other, and only overlapping paths need
        // serialising. `acquire_for_action` sorts the keys, so a call touching
        // several paths cannot deadlock against another call touching the same
        // paths in a different order.
        //
        // When this action edits a build file, the owning *module* is locked as
        // well, because a build edit changes which files the module owns. The
        // module map is only consulted when it is confident: a wrong map fails
        // silently, letting two agents into one module with nothing reported.
        //
        // Taken after approval, so a denied action never reserves paths. Held
        // only for the duration of the tool call; every lock taken is released
        // on drop if the call fails, so a failed action cannot strand a lock
        // the rest of the run would wait on.
        let _path_locks = if self.workspace_path_lock {
            Some(pangu_core::PathLock::acquire_for_action_with_modules(
                &self.sandbox.workspace,
                &resources.read_paths,
                &resources.write_paths,
                self.module_map.as_deref(),
                self.path_lock_timeout,
            )?)
        } else {
            None
        };

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
                let content = redact_text(&output.content);
                let preview = truncate_middle(&content, 240);
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
                            "output_complete": true,
                            "collapsed": true,
                            "preview": preview,
                            "output": content,
                            "output_bytes": output_bytes,
                            "output_sha256": output_digest,
                        })),
                    )
                    .await?;
                // B3: audit the proposal into the journal. The event carries
                // the candidate id and content digest, never the raw content:
                // model text may contain secrets, and the store is the only
                // place the full content lives.
                if call.name == "propose_memory" {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&output.content) {
                        let id = parsed.get("id").and_then(Value::as_str);
                        let digest = parsed.get("content_sha256").and_then(Value::as_str);
                        if let (Some(id), Some(digest)) = (id, digest) {
                            self.emit(
                                self.event(
                                    EventKind::MemoryProposed,
                                    turn,
                                    format!("memory candidate {id} queued for operator review"),
                                )
                                .tool(&call.name)
                                .call_id(&call.id)
                                .action_digest(action_digest.clone())
                                .payload(serde_json::json!({
                                    "id": id,
                                    "content_sha256": digest,
                                    "status": "pending",
                                })),
                            )
                            .await?;
                        }
                    }
                }
                let mut checkpoint_error: Option<(&'static str, anyhow::Error)> = None;
                let mut completed_checkpoint: Option<checkpoint::CheckpointCommit> = None;
                // The node must record the conversation as it will stand once
                // this tool result is in it. Computing it from the pre-push
                // history would make the node point at a state the conversation
                // never held, and `pangu session replay` would then report a
                // digest that matches no snapshot.
                let history_digest = Self::history_digest_after_tool_result(
                    history, &call.id, &call.name, &content,
                )?;
                if let (Some(runtime), Some(state)) =
                    (self.checkpoint.as_ref(), checkpoint_state.as_mut())
                {
                    match self
                        .authorize_checkpoint(runtime, &finished_event, turn, &action_digest)
                        .await
                    {
                        Ok(()) => {
                            match runtime.commit_after_success(
                                state,
                                &finished_event,
                                effect,
                                history_digest.as_deref(),
                            ) {
                                Ok(commit) => completed_checkpoint = Some(commit),
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
                if let Some(commit) = completed_checkpoint {
                    self.emit(
                        Event::new_v2(EventKind::CheckpointCreated, turn, "checkpoint created")
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

    fn finish_status(&self, call: &ToolCall, evidence: &[String]) -> Result<GoalStatus> {
        let evidence_count = evidence.len();
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
        // D3/D4: a `complete` over declared deliverables must pass every
        // acceptance check. Failures come back as a tool error so the model
        // can repair the artifact and retry - an Aider-style verify loop at
        // the finish gate.
        if status == GoalStatus::Complete && !self.contract.deliverables.deliverables.is_empty() {
            let has_verify_evidence = evidence.iter().any(|item| item.starts_with("verify:"));
            let mut failures = Vec::new();
            for frozen in &self.contract.deliverables.deliverables {
                let spec = pangu_core::DeliverableSpec::from(frozen);
                let outcome = pangu_core::deliverable::check_spec(
                    &spec,
                    self.contract.workspace(),
                    has_verify_evidence,
                );
                if !outcome.passed {
                    failures.push(format!("  - {}: {}", spec.name, outcome.detail));
                }
            }
            if !failures.is_empty() {
                return Err(anyhow!(
                    "deliverable acceptance failed ({} of {}); fix and call finish again:\n{}",
                    failures.len(),
                    self.contract.deliverables.deliverables.len(),
                    failures.join("\n")
                ));
            }
        }
        Ok(status)
    }

    /// D3/D4: record every declared deliverable into the registry and emit
    /// one `DeliverableRecorded` event per artifact. Called only after all
    /// acceptance checks passed; a registry failure refuses the `complete`
    /// the same way a failed check does - an unaudited completion is not a
    /// completion.
    async fn record_deliverables(&self, turn: u32) -> Result<()> {
        let Some(store) = self.deliverables.as_ref() else {
            return Ok(());
        };
        for frozen in &self.contract.deliverables.deliverables {
            let spec = pangu_core::DeliverableSpec::from(frozen);
            let outcome =
                pangu_core::deliverable::check_spec(&spec, self.contract.workspace(), false);
            let sha256 = outcome.sha256.ok_or_else(|| {
                anyhow!(
                    "deliverable `{}` disappeared between the finish check and recording",
                    spec.name
                )
            })?;
            let bytes = outcome.bytes.unwrap_or(0);
            store
                .record(&spec, &sha256, bytes, None)
                .map_err(|error| anyhow!("deliverable registry: {error}"))?;
            self.emit(
                self.event(
                    EventKind::DeliverableRecorded,
                    turn,
                    format!(
                        "deliverable `{}` recorded: {} bytes={} sha256={}",
                        spec.name,
                        spec.path,
                        bytes,
                        &sha256[..12]
                    ),
                )
                .tool("finish")
                .payload(serde_json::json!({
                    "name": spec.name,
                    "path": spec.path,
                    "kind": spec.kind,
                    "acceptor": spec.acceptor.as_str(),
                    "sha256": sha256,
                    "bytes": bytes,
                })),
            )
            .await?;
        }
        Ok(())
    }

    fn budget_breaches(
        &self,
        turn: u32,
        usage: &Usage,
        elapsed: std::time::Duration,
        spent: f64,
    ) -> Vec<pangu_boundary::Breach> {
        // B5: the spend is accumulated per segment — each response's usage is
        // priced by the provider that served it — so a fallback switch can
        // never under-count cost. An absent primary price starts the run at
        // INFINITY, which preserves the old fail-closed behavior.
        self.contract.budget.check(
            turn,
            usage.input_tokens.saturating_add(usage.cache_read_tokens),
            usage.output_tokens,
            spent,
            elapsed,
        )
    }

    /// B5: the provider at a chain position (0 = primary).
    fn provider_for(&self, active: usize) -> &Arc<dyn Provider> {
        if active == 0 {
            &self.provider
        } else {
            self.fallbacks
                .get(active - 1)
                .expect("active position within the declared chain")
        }
    }

    /// B5: the price of the provider at a chain position, from the frozen
    /// contract (primary) or the frozen candidate list (fallbacks).
    fn active_price(&self, active: usize) -> Option<pangu_core::Price> {
        if active == 0 {
            self.contract.price
        } else {
            let candidate = self.contract.fallbacks.get(active - 1)?;
            Some(pangu_core::Price {
                input_usd_per_mtok: candidate.input_usd_per_mtok,
                output_usd_per_mtok: candidate.output_usd_per_mtok,
            })
        }
    }

    fn provider_label(&self, active: usize) -> String {
        let provider = self.provider_for(active);
        format!("{}/{}", provider.name(), provider.model())
    }

    /// B5: run the declared chain. On a chat failure the next declared
    /// candidate is tried; every failed attempt and every successful switch
    /// is audited. The active position persists across turns — the run never
    /// silently jumps back to the primary.
    async fn chat_with_fallback(
        &self,
        active: &mut usize,
        turn: u32,
        messages: Vec<Message>,
        specs: Vec<pangu_core::ToolSpec>,
    ) -> Result<ChatResponse> {
        let total = 1 + self.fallbacks.len();
        let mut attempt = *active;
        let mut last_error = String::from("unknown");
        loop {
            let provider = self.provider_for(attempt);
            match provider.chat(messages.clone(), specs.clone()).await {
                Ok(response) => {
                    if attempt != *active {
                        let from = self.provider_label(*active);
                        let to = self.provider_label(attempt);
                        self.emit(self.event(
                            EventKind::ProviderSwitched,
                            turn,
                            format!(
                                "provider fallback: {from} -> {to}; prior attempt failed: \
                                     {last_error}"
                            ),
                        ))
                        .await?;
                        *active = attempt;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    let reason = redact_text(&error.to_string());
                    self.emit(self.event(
                        EventKind::Note,
                        turn,
                        format!(
                            "provider attempt failed: {}: {reason}",
                            self.provider_label(attempt)
                        ),
                    ))
                    .await?;
                    last_error = reason;
                    attempt += 1;
                    if attempt >= total {
                        return Err(anyhow!(
                            "all declared providers failed; last error: {last_error}"
                        ));
                    }
                }
            }
        }
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

    /// The conversation digest as it will stand once this tool result lands.
    ///
    /// Computed through `ConversationSnapshot::new`, which is the same
    /// constructor `ConversationRuntime::save` uses — including its redaction
    /// step. Reimplementing the encoding here would produce a digest that can
    /// never match a stored snapshot, which is worse than no digest at all: it
    /// would look like evidence.
    ///
    /// Works whether or not the caller's history is already redacted, because
    /// redaction is idempotent for the values this stores.
    fn history_digest_after_tool_result(
        history: &[Message],
        call_id: &str,
        tool: &str,
        content: &str,
    ) -> Result<Option<String>> {
        let mut projected = history.to_vec();
        projected.push(Message::tool_result(call_id, tool, content));
        let snapshot =
            pangu_core::ConversationSnapshot::new("node-digest-projection", "", projected)?;
        Ok(Some(snapshot.history_digest))
    }
}

/// Describe an error including its cause chain.
///
/// `anyhow::Error`'s `Display` prints only the outermost message, so a failure
/// reported through a context wrapper loses the actual cause: an operator sees
/// `io: os error 2` with no indication of which path or program produced it. The
/// chain is what makes a failure diagnosable.
///
/// Only the chain is added — no backtrace, no internal types — so the result
/// stays safe for the journal and for a model-visible message.
fn describe_error(error: &anyhow::Error) -> String {
    let mut text = error.to_string();
    for (index, cause) in error.chain().skip(1).enumerate() {
        // Bounded: a deep or repetitive chain must not produce an unbounded
        // message.
        if index >= 4 {
            text.push_str(" | (further causes omitted)");
            break;
        }
        let next = cause.to_string();
        if !next.is_empty() && !text.contains(&next) {
            text.push_str(" | caused by: ");
            text.push_str(&next);
        }
    }
    text
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
    /// F5: number of the last turn executed (trajectory summary).
    pub turns: u32,
    /// F5: total priced cost of the run; `None` when the primary model has
    /// no declared price. Unpriced is distinguishable from free.
    pub cost_usd: Option<f64>,
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

/// F4: bounded, redacted content diff for a `write_file` approval preview.
/// Says honestly when no inline diff is possible (non-regular target, too
/// large, non-UTF-8, unreadable) instead of faking a "new file" diff. The
/// read is display-only: the path is already validated as a write target.
fn write_file_diffs(call: &ToolCall, resources: &ValidatedResources) -> Vec<String> {
    const MAX_INLINE_BYTES: u64 = 256 * 1024;
    const DIFF_CAP: usize = 8 * 1024;
    if call.name != "write_file" {
        return Vec::new();
    }
    let Some(content) = call.args.get("content").and_then(serde_json::Value::as_str) else {
        return Vec::new();
    };
    let Some(path) = resources.write_paths.first() else {
        return Vec::new();
    };
    let shown = path.display().to_string();
    let diff = match std::fs::metadata(path) {
        Ok(meta) if !meta.is_file() => {
            format!("`{shown}` exists and is not a regular file; inline diff unavailable")
        }
        Ok(meta) if meta.len() > MAX_INLINE_BYTES => {
            format!(
                "existing `{shown}` is {} bytes; too large for an inline diff",
                meta.len()
            )
        }
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(old) => pangu_core::unified_diff(&old, content, &shown, DIFF_CAP),
            Err(_) => {
                format!("existing `{shown}` is not valid UTF-8; inline diff unavailable")
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            pangu_core::unified_diff("", content, &shown, DIFF_CAP)
        }
        Err(error) => {
            format!("existing `{shown}` could not be read ({error}); inline diff unavailable")
        }
    };
    vec![truncate_middle(&redact_text(&diff), DIFF_CAP)]
}
