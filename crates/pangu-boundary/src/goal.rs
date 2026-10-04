use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use pangu_core::{Error, Price, Result};

use crate::approval::ApprovalMode;
use crate::budget::Budget;
use crate::config::{canonicalize_with_missing, CheckpointSection, Config, ConversationSection};
use crate::execution::ExecutionSection;

/// B5: one declared fallback candidate, frozen into the contract. The agent's
/// per-segment cost accounting uses these prices; `Agent::with_chain` refuses
/// an injected provider chain that does not match this list position by
/// position (model name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractFallback {
    pub model: String,
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
}

/// B2: one loaded skill, frozen into the contract. The package digest pins
/// exactly what content the model could read during the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractSkill {
    pub name: String,
    pub version: String,
    pub package_digest: String,
    pub signed: bool,
}

/// B2: the frozen skill set. `enabled = false` keeps historical digests and
/// runs unchanged; `enabled = true` with an empty list still changes the
/// digest (the read_skill tool exists even when nothing is installed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContractSkills {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<ContractSkill>,
}

/// D3/D4: one declared deliverable, frozen into the contract. The acceptor
/// semantics and the minimum size are part of what `complete` must pass, so
/// they ride with the digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractDeliverable {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub acceptor: pangu_core::Acceptor,
    pub min_bytes: u64,
}

impl From<&ContractDeliverable> for pangu_core::DeliverableSpec {
    fn from(frozen: &ContractDeliverable) -> Self {
        pangu_core::DeliverableSpec {
            name: frozen.name.clone(),
            path: frozen.path.clone(),
            kind: frozen.kind.clone(),
            acceptor: frozen.acceptor,
            min_bytes: frozen.min_bytes,
        }
    }
}

/// D3/D4: the frozen deliverable set. Empty = no deliverable semantics; runs
/// keep their historical digests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContractDeliverables {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deliverables: Vec<ContractDeliverable>,
}

/// F5: the declared evaluation profile, frozen into the contract. The issue
/// *path* rides with the digest; the issue *content* is pinned by the digest
/// recorded in the evaluation record at run start. Empty profile = no
/// evaluation semantics; runs keep their historical digests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContractEval {
    pub profile: String,
    pub issue_path: String,
}

impl ContractEval {
    pub fn is_declared(&self) -> bool {
        !self.profile.is_empty()
    }
}

/// B3: the controlled memory queue, frozen into the contract. The bounds ride
/// with the contract so an injected store cannot quietly widen them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContractMemory {
    pub enabled: bool,
    pub max_pending: usize,
    pub max_content_bytes: usize,
    pub max_kind_bytes: usize,
    pub max_injected: usize,
    pub max_injected_bytes: usize,
}
use crate::sandbox::{absolute_path_from, Sandbox};

/// The immutable, human-supplied portion of one run. The agent builds its
/// enforcement objects from this contract; it does not consult a second
/// mutable boundary configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalContract {
    pub goal: String,
    pub workspace: PathBuf,
    pub readable_roots: Vec<PathBuf>,
    pub writable_roots: Vec<PathBuf>,
    pub forbidden_globs: Vec<String>,
    pub approval_mode: ApprovalMode,
    pub budget: Budget,
    pub system_prompt: String,
    pub unattended: bool,
    pub config_files: Vec<String>,
    pub network_egress: Vec<String>,
    pub allow_localhost: bool,
    pub env_allow: Vec<String>,
    pub max_tool_output_bytes: usize,
    pub max_arg_bytes: usize,
    pub subprocess_timeout_secs: u64,
    pub subprocess_output_limit: usize,
    pub max_write_bytes: usize,
    pub max_paths_per_action: usize,
    /// F4: when true, the run starts in the read-only plan phase; only the
    /// model's `begin_act` control call enters the act phase, where every
    /// mutating action still passes L1-L4 individually. Frozen at contract
    /// construction; the model cannot change it.
    #[serde(default)]
    pub plan_first: bool,
    /// B5: the declared fallback chain, frozen at contract construction.
    /// Empty = single-provider run (no fallback). Prices here drive the
    /// per-segment cost accounting after a switch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<ContractFallback>,
    /// C5: the declared execution backend, frozen at contract construction.
    /// A declaration, not a verified fact: Pangu does not launch, manage, or
    /// verify backends; L1-L4 apply identically in every profile.
    #[serde(default)]
    pub execution: ExecutionSection,
    /// F3: the operator-configured verification command, frozen at contract
    /// construction. The toolkit must advertise exactly this argv; `Agent::new`
    /// refuses a mismatch. Empty = the verify tool does not exist.
    #[serde(default)]
    pub verify_command: Vec<String>,
    /// F3: extra programs admitted to the read-only argv allow-list. Kept on
    /// the contract so an injected Sandbox cannot quietly widen it.
    #[serde(default)]
    pub extra_readonly_commands: Vec<String>,
    /// B3: the controlled memory queue, frozen at contract construction.
    /// `enabled = false` keeps historical digests and runs unchanged.
    #[serde(default)]
    pub memory: ContractMemory,
    /// B2: the frozen skill set. `enabled = false` keeps historical digests
    /// and runs unchanged.
    #[serde(default)]
    pub skills: ContractSkills,
    /// D3/D4: the frozen deliverable set. Empty keeps historical digests.
    #[serde(default)]
    pub deliverables: ContractDeliverables,
    /// F5: the declared evaluation profile. Undeclared keeps historical digests.
    #[serde(default)]
    pub eval: ContractEval,
    /// D1: whether the model may delegate bounded subtasks to restricted
    /// sub-agents. Default off keeps historical digests unchanged. The child
    /// contract is derived from this one (never wider) and the child budget
    /// is clamped to the parent's remaining budget by the run loop — the
    /// model can only narrow, never widen.
    #[serde(default)]
    pub allow_delegation: bool,
    #[serde(default)]
    pub checkpoint: CheckpointSection,
    #[serde(default)]
    pub conversation: ConversationSection,
    pub require_evidence: bool,
    pub min_successful_tool_calls: u32,
    pub price: Option<Price>,
    /// Digest of the exact policy rule set bound to this contract.
    pub policy_digest: String,
}

impl GoalContract {
    pub fn new(goal: impl Into<String>) -> Self {
        let workspace = std::env::current_dir()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            goal: goal.into(),
            readable_roots: vec![workspace.clone()],
            writable_roots: vec![workspace.clone()],
            workspace,
            forbidden_globs: vec![
                "**/.git/**".into(),
                "**/.env".into(),
                "**/.env.*".into(),
                "**/secrets/**".into(),
                "**/*.pem".into(),
                "**/id_rsa*".into(),
                // B3: Pangu-owned storage is never tool-writable.
                "**/.pangu/**".into(),
            ],
            approval_mode: ApprovalMode::DestructiveAndAbove,
            budget: Budget::default(),
            system_prompt: crate::config::DEFAULT_SYSTEM_PROMPT.to_string(),
            unattended: false,
            config_files: Vec::new(),
            network_egress: Vec::new(),
            allow_localhost: false,
            env_allow: crate::config::EnvSection::default().allow,
            max_tool_output_bytes: 16_384,
            max_arg_bytes: 8_192,
            subprocess_timeout_secs: 45,
            subprocess_output_limit: 200_000,
            max_write_bytes: 4_194_304,
            max_paths_per_action: 64,
            verify_command: Vec::new(),
            memory: ContractMemory::default(),
            skills: ContractSkills::default(),
            deliverables: ContractDeliverables::default(),
            eval: ContractEval::default(),
            allow_delegation: false,
            extra_readonly_commands: Vec::new(),
            checkpoint: CheckpointSection::default(),
            conversation: ConversationSection::default(),
            require_evidence: true,
            min_successful_tool_calls: 1,
            plan_first: false,
            fallbacks: Vec::new(),
            execution: ExecutionSection::default(),
            price: None,
            policy_digest: crate::Policy::empty().digest(),
        }
    }

    pub fn from_config(goal: impl Into<String>, config: &Config) -> Result<Self> {
        config.validate()?;
        let workspace = config.workspace_abs();
        let readable_roots = canonical_roots(&workspace, &config.boundary.readable_roots)?;
        let writable_roots = canonical_roots(&workspace, &config.boundary.writable_roots)?;
        let resolved = config.resolve_provider()?;
        let price = match (resolved.input_usd_per_mtok, resolved.output_usd_per_mtok) {
            (Some(input), Some(output)) => Some(Price {
                input_usd_per_mtok: input,
                output_usd_per_mtok: output,
            }),
            _ => None,
        };
        let mut checkpoint = config.checkpoint.clone();
        if checkpoint.enabled {
            checkpoint.artifact_root = canonicalize_with_missing(&absolute_path_from(
                &workspace,
                &checkpoint.artifact_root,
            )?)?;
            checkpoint.exclude_roots = checkpoint
                .exclude_roots
                .iter()
                .map(|path| {
                    absolute_path_from(&workspace, path)
                        .and_then(|resolved| canonicalize_with_missing(&resolved))
                })
                .collect::<Result<Vec<_>>>()?;
        }
        // Same treatment as the checkpoint root: only resolve it when the
        // feature is on, so a disabled section cannot fail the whole contract
        // over a path nobody will read.
        let mut conversation = config.conversation.clone();
        if conversation.enabled {
            conversation.artifact_root = canonicalize_with_missing(&absolute_path_from(
                &workspace,
                &conversation.artifact_root,
            )?)?;
        }
        // B2: freeze the installed skill set while the feature is on. The
        // package digests pin exactly what the model could read this run.
        let skills = if config.skills.enabled {
            let registry = pangu_core::SkillRegistry::load(
                &workspace.join(".pangu").join("skills"),
                &config.skills.limits(),
                if config.skills.verify_key.trim().is_empty() {
                    None
                } else {
                    Some(config.skills.verify_key.trim())
                },
            )?;
            ContractSkills {
                enabled: true,
                skills: registry
                    .skills()
                    .iter()
                    .map(|skill| ContractSkill {
                        name: skill.name.clone(),
                        version: skill.version.clone(),
                        package_digest: skill.lock.package_digest.clone(),
                        signed: skill.signature_verified(),
                    })
                    .collect(),
            }
        } else {
            ContractSkills::default()
        };
        let contract = Self {
            goal: goal.into(),
            readable_roots,
            writable_roots,
            workspace,
            forbidden_globs: config.boundary.forbidden_globs.clone(),
            approval_mode: config.boundary.approval.mode,
            budget: config.budget.clone(),
            system_prompt: config.goal.system_prompt.clone(),
            unattended: config.unattended,
            config_files: Vec::new(),
            network_egress: config.boundary.network.hosts.clone(),
            allow_localhost: config.boundary.network.allow_localhost,
            env_allow: config.boundary.env.allow.clone(),
            max_tool_output_bytes: config.boundary.max_tool_output_bytes,
            max_arg_bytes: config.boundary.max_arg_bytes,
            subprocess_timeout_secs: config.boundary.subprocess_timeout_secs,
            subprocess_output_limit: config.boundary.subprocess_output_limit,
            max_write_bytes: config.boundary.max_write_bytes,
            max_paths_per_action: config.boundary.max_paths_per_action,
            verify_command: config.verify.command.clone(),
            skills,
            deliverables: ContractDeliverables {
                deliverables: config
                    .goal
                    .deliverable
                    .iter()
                    .map(|spec| ContractDeliverable {
                        name: spec.name.clone(),
                        path: spec.path.clone(),
                        kind: spec.kind.clone(),
                        acceptor: spec.acceptor,
                        min_bytes: spec.min_bytes,
                    })
                    .collect(),
            },
            eval: ContractEval {
                profile: config.eval.profile.clone(),
                issue_path: config.eval.issue_path.clone(),
            },
            allow_delegation: config.boundary.allow_delegation,
            memory: ContractMemory {
                enabled: config.memory.enabled,
                max_pending: config.memory.max_pending,
                max_content_bytes: config.memory.max_content_bytes,
                max_kind_bytes: config.memory.max_kind_bytes,
                max_injected: config.memory.max_injected,
                max_injected_bytes: config.memory.max_injected_bytes,
            },
            extra_readonly_commands: config.boundary.extra_readonly_commands.clone(),
            checkpoint,
            conversation,
            require_evidence: config.goal.require_evidence,
            min_successful_tool_calls: config.goal.min_successful_tool_calls,
            plan_first: config.goal.plan_first,
            fallbacks: config
                .resolve_fallbacks()?
                .into_iter()
                .map(|candidate| ContractFallback {
                    model: candidate.model,
                    input_usd_per_mtok: candidate.input_usd_per_mtok,
                    output_usd_per_mtok: candidate.output_usd_per_mtok,
                })
                .collect(),
            execution: config.execution.clone(),
            price,
            policy_digest: crate::Policy::new(config.rules.clone())?.digest(),
        };
        contract.validate()?;
        Ok(contract)
    }

    /// Bind a contract created with [`GoalContract::new`] to the exact policy
    /// that will be passed to the Agent. Configuration-built contracts do
    /// this automatically.
    pub fn bind_policy(mut self, policy: &crate::Policy) -> Self {
        self.policy_digest = policy.digest();
        self
    }

    pub fn workspace(&self) -> &PathBuf {
        &self.workspace
    }

    pub fn writable_roots(&self) -> &[PathBuf] {
        &self.writable_roots
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn approval_mode(&self) -> ApprovalMode {
        self.approval_mode
    }

    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }

    pub fn is_unattended(&self) -> bool {
        self.unattended
    }

    /// F4: whether the run starts in the read-only plan phase.
    pub fn plan_first(&self) -> bool {
        self.plan_first
    }

    /// B3: the frozen memory-queue settings.
    pub fn memory(&self) -> &ContractMemory {
        &self.memory
    }

    /// B2: the frozen skill set.
    pub fn skills(&self) -> &ContractSkills {
        &self.skills
    }

    /// D3/D4: the frozen deliverable set.
    pub fn deliverables(&self) -> &ContractDeliverables {
        &self.deliverables
    }

    /// F5: the declared evaluation profile.
    pub fn eval(&self) -> &ContractEval {
        &self.eval
    }

    /// D1: whether delegation is enabled for this run.
    pub fn allows_delegation(&self) -> bool {
        self.allow_delegation
    }

    /// D1: derive a restricted sub-agent contract from this (parent)
    /// contract. Every enforcement field is copied from the parent — the
    /// sandbox, policy, approval mode, network rules, and limits are the
    /// parent's, so the child can never exceed them — while the run-scoped
    /// features (plan-first, memory, skills, deliverables, eval,
    /// checkpointing, conversation, delegation itself) are stripped: the
    /// child is a bounded worker, and a sub-agent can never spawn its own
    /// sub-agents.
    ///
    /// The budget must already be clamped by the caller to the parent's
    /// remaining budget; this constructor refuses any dimension wider than
    /// the parent's as defense in depth. Delegation is thus an intersection
    /// by construction: child ⊆ parent on every axis.
    pub fn derive_sub_contract(&self, task: impl Into<String>, budget: Budget) -> Result<Self> {
        budget.validate()?;
        if budget.max_turns > self.budget.max_turns {
            return Err(Error::Config(
                "sub-contract budget.max_turns exceeds the parent contract".into(),
            ));
        }
        if budget.max_input_tokens > self.budget.max_input_tokens {
            return Err(Error::Config(
                "sub-contract budget.max_input_tokens exceeds the parent contract".into(),
            ));
        }
        if budget.max_output_tokens > self.budget.max_output_tokens {
            return Err(Error::Config(
                "sub-contract budget.max_output_tokens exceeds the parent contract".into(),
            ));
        }
        if budget.max_cost_usd > self.budget.max_cost_usd {
            return Err(Error::Config(
                "sub-contract budget.max_cost_usd exceeds the parent contract".into(),
            ));
        }
        if budget.max_wall_clock_secs > self.budget.max_wall_clock_secs {
            return Err(Error::Config(
                "sub-contract budget.max_wall_clock_secs exceeds the parent contract".into(),
            ));
        }
        let mut child = Self::new(format!("[delegated subtask] {}", task.into()));
        child.workspace = self.workspace.clone();
        child.readable_roots = self.readable_roots.clone();
        child.writable_roots = self.writable_roots.clone();
        child.forbidden_globs = self.forbidden_globs.clone();
        child.approval_mode = self.approval_mode;
        child.budget = budget;
        child.system_prompt = self.system_prompt.clone();
        child.unattended = self.unattended;
        child.config_files = self.config_files.clone();
        child.network_egress = self.network_egress.clone();
        child.allow_localhost = self.allow_localhost;
        child.env_allow = self.env_allow.clone();
        child.max_tool_output_bytes = self.max_tool_output_bytes;
        child.max_arg_bytes = self.max_arg_bytes;
        child.subprocess_timeout_secs = self.subprocess_timeout_secs;
        child.subprocess_output_limit = self.subprocess_output_limit;
        child.max_write_bytes = self.max_write_bytes;
        child.max_paths_per_action = self.max_paths_per_action;
        child.verify_command = self.verify_command.clone();
        child.extra_readonly_commands = self.extra_readonly_commands.clone();
        child.require_evidence = self.require_evidence;
        child.min_successful_tool_calls = self.min_successful_tool_calls;
        child.price = self.price;
        child.policy_digest = self.policy_digest.clone();
        // B5: the child keeps the parent's declared fallback chain so a
        // subtask survives a provider failure exactly as the parent would.
        child.fallbacks = self.fallbacks.clone();
        // allow_delegation stays false: depth-1 delegation by construction.
        Ok(child)
    }

    /// C5: the declared execution backend.
    pub fn execution(&self) -> &ExecutionSection {
        &self.execution
    }

    /// Digest of the effective boundary, excluding user text and config file
    /// names. Every field that can change enforcement is included.
    pub fn digest(&self) -> String {
        let normalize_paths = |values: &[PathBuf]| {
            let mut values = values
                .iter()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            values
        };
        let readable_roots = normalize_paths(&self.readable_roots);
        let writable_roots = normalize_paths(&self.writable_roots);
        let workspace = self.workspace.to_string_lossy().replace('\\', "/");
        let mut forbidden = self.forbidden_globs.clone();
        forbidden.sort();
        forbidden.dedup();
        let mut network = self.network_egress.clone();
        network.sort();
        network.dedup();
        let mut env = self.env_allow.clone();
        env.sort();
        env.dedup();
        let mut value = serde_json::json!({
            "workspace": workspace,
            "readable_roots": readable_roots,
            "writable_roots": writable_roots,
            "forbidden_globs": forbidden,
            "approval_mode": self.approval_mode,
            "budget": self.budget,
            "network_egress": network,
            "allow_localhost": self.allow_localhost,
            "env_allow": env,
            "max_tool_output_bytes": self.max_tool_output_bytes,
            "max_arg_bytes": self.max_arg_bytes,
            "subprocess_timeout_secs": self.subprocess_timeout_secs,
            "subprocess_output_limit": self.subprocess_output_limit,
            "max_write_bytes": self.max_write_bytes,
            "max_paths_per_action": self.max_paths_per_action,
            "require_evidence": self.require_evidence,
            "min_successful_tool_calls": self.min_successful_tool_calls,
            "price": self.price,
            "policy_digest": &self.policy_digest,
            "unattended": self.unattended,
        });
        // F4: only a plan-first run carries the phase discipline; a default
        // single-phase run must keep its historical digest.
        if self.plan_first {
            if let Some(object) = value.as_object_mut() {
                object.insert("plan_first".into(), serde_json::json!(true));
            }
        }
        // C5: only a declared backend changes the digest; the default local
        // profile is undeclared and keeps historical digests stable.
        if self.execution.is_declared() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "execution".into(),
                    serde_json::json!({
                        "profile": self.execution.profile.as_str(),
                        "description": &self.execution.description,
                    }),
                );
            }
        }
        // B5: a declared fallback chain is part of the run's contract (its
        // prices drive cost accounting); a single-provider run keeps its
        // historical digest.
        if !self.fallbacks.is_empty() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "fallbacks".into(),
                    serde_json::to_value(&self.fallbacks).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        // B3: only an enabled memory queue changes the digest; disabled runs
        // keep their historical digest.
        if self.memory.enabled {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "memory".into(),
                    serde_json::to_value(&self.memory).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        // D3/D4: only declared deliverables change the digest; undeclared
        // runs keep their historical digest.
        if !self.deliverables.deliverables.is_empty() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "deliverables".into(),
                    serde_json::to_value(&self.deliverables).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        // F5: only a declared evaluation profile changes the digest;
        // undeclared runs keep their historical digest.
        if self.eval.is_declared() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "eval".into(),
                    serde_json::to_value(&self.eval).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        // D1: only a delegation-enabled run changes the digest; the default
        // keeps historical digests stable.
        if self.allow_delegation {
            if let Some(object) = value.as_object_mut() {
                object.insert("allow_delegation".into(), serde_json::json!(true));
            }
        }
        // B2: only an enabled skill registry changes the digest; disabled
        // runs keep their historical digest.
        if self.skills.enabled {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "skills".into(),
                    serde_json::to_value(&self.skills).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        if self.checkpoint.enabled {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "checkpoint".into(),
                    serde_json::to_value(&self.checkpoint).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        if !self.verify_command.is_empty() || !self.extra_readonly_commands.is_empty() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "verify".into(),
                    serde_json::json!({
                        "command": &self.verify_command,
                        "extra_readonly_commands": &self.extra_readonly_commands,
                    }),
                );
            }
        }
        pangu_core::hex_sha256(&serde_json::to_string(&value).unwrap_or_default())
    }

    pub fn validate_against(&self, sandbox: &Sandbox) -> Result<()> {
        self.validate()?;
        if self.workspace != sandbox.workspace
            || self.readable_roots != sandbox.readable_roots
            || self.writable_roots != sandbox.writable_roots
            || self.allow_localhost != sandbox.allow_localhost
            || self.max_tool_output_bytes != sandbox.max_tool_output_bytes
            || self.max_arg_bytes != sandbox.max_arg_bytes
            || self.subprocess_timeout_secs != sandbox.subprocess_timeout_secs
            || self.subprocess_output_limit != sandbox.subprocess_output_limit
            || self.max_write_bytes != sandbox.max_write_bytes
            || self.max_paths_per_action != sandbox.max_paths_per_action
            || self.extra_readonly_commands != sandbox.extra_readonly_commands
        {
            return Err(Error::Config(
                "GoalContract and Sandbox do not describe the same effective boundary".into(),
            ));
        }
        let forbidden = self
            .forbidden_globs
            .iter()
            .map(String::as_str)
            .eq(sandbox.forbidden_globs.iter().map(|glob| glob.pattern()));
        let hosts = self.network_egress.iter().map(String::as_str).eq(sandbox
            .network_allowed_hosts
            .iter()
            .map(|glob| glob.pattern()));
        let env = self.env_allow.iter().eq(&sandbox.env_allow);
        if !forbidden || !hosts || !env {
            return Err(Error::Config(
                "GoalContract and Sandbox resource filters differ".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.goal.trim().is_empty() {
            return Err(Error::Config("goal must not be empty".into()));
        }
        if self.goal.len() > 1024 * 1024 {
            return Err(Error::Config("goal exceeds 1 MiB".into()));
        }
        if self.system_prompt.len() > 1024 * 1024 {
            return Err(Error::Config("system_prompt exceeds 1 MiB".into()));
        }
        if self.policy_digest.len() != 64
            || !self
                .policy_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::Config(
                "policy_digest must be a SHA-256 hex digest".into(),
            ));
        }
        self.budget.validate()?;
        if self.price.is_some_and(|price| {
            !price.input_usd_per_mtok.is_finite()
                || !price.output_usd_per_mtok.is_finite()
                || price.input_usd_per_mtok < 0.0
                || price.output_usd_per_mtok < 0.0
        }) {
            return Err(Error::Config(
                "contract prices must be finite and >= 0".into(),
            ));
        }
        if self.max_tool_output_bytes < 256
            || self.max_tool_output_bytes > 16 * 1024 * 1024
            || self.max_arg_bytes == 0
            || self.subprocess_timeout_secs == 0
            || self.subprocess_output_limit == 0
            || self.max_write_bytes == 0
            || self.max_paths_per_action == 0
        {
            return Err(Error::Config(
                "contract resource limits must be positive".into(),
            ));
        }
        if self.subprocess_timeout_secs >= self.budget.max_wall_clock_secs.as_secs() {
            return Err(Error::Config(
                "subprocess timeout must be shorter than the run wall-clock budget".into(),
            ));
        }
        if !self
            .readable_roots
            .iter()
            .any(|root| root == &self.workspace)
        {
            return Err(Error::Config(
                "readable roots must include the workspace".into(),
            ));
        }
        for root in self.readable_roots.iter().chain(self.writable_roots.iter()) {
            if !root.is_absolute() || !root.is_dir() {
                return Err(Error::Config(format!(
                    "boundary root is not an existing absolute directory: {}",
                    root.display()
                )));
            }
        }
        for root in &self.writable_roots {
            if !root.starts_with(&self.workspace) {
                return Err(Error::Config(format!(
                    "writable root {} is outside workspace {}",
                    root.display(),
                    self.workspace.display()
                )));
            }
        }
        self.checkpoint
            .validate(&self.workspace, &self.writable_roots)?;
        for pattern in &self.forbidden_globs {
            pangu_core::Glob::new(pattern)?;
        }
        for host in &self.network_egress {
            pangu_core::Glob::new(host)?;
        }
        if self.env_allow.iter().any(|key| {
            [
                "KEY",
                "TOKEN",
                "SECRET",
                "PASSWORD",
                "PASSWD",
                "AUTH",
                "CREDENTIAL",
            ]
            .iter()
            .any(|part| key.to_ascii_uppercase().contains(part))
        }) {
            return Err(Error::Config(
                "sensitive environment key cannot be allowed".into(),
            ));
        }
        Sandbox::from_config(&crate::config::BoundarySection {
            workspace: self.workspace.clone(),
            readable_roots: self.readable_roots.clone(),
            writable_roots: self.writable_roots.clone(),
            forbidden_globs: self.forbidden_globs.clone(),
            network: crate::config::NetworkSection {
                allow_localhost: self.allow_localhost,
                hosts: self.network_egress.clone(),
            },
            env: crate::config::EnvSection {
                allow: self.env_allow.clone(),
            },
            max_tool_output_bytes: self.max_tool_output_bytes,
            max_arg_bytes: self.max_arg_bytes,
            subprocess_timeout_secs: self.subprocess_timeout_secs,
            subprocess_output_limit: self.subprocess_output_limit,
            max_write_bytes: self.max_write_bytes,
            max_paths_per_action: self.max_paths_per_action,
            ..Default::default()
        })?;
        if !self.require_evidence {
            return Err(Error::Config(
                "goal.require_evidence cannot be disabled".into(),
            ));
        }
        if self.min_successful_tool_calls == 0 {
            return Err(Error::Config(
                "goal.min_successful_tool_calls must be > 0".into(),
            ));
        }
        Ok(())
    }
}

fn canonical_roots(workspace: &std::path::Path, roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for root in roots {
        let root = std::fs::canonicalize(absolute_path_from(workspace, root)?)?;
        if !root.is_dir() {
            return Err(Error::Config(format!(
                "boundary root is not a directory: {}",
                root.display()
            )));
        }
        if !result.contains(&root) {
            result.push(root);
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    Complete,
    Failed,
    NeedsInput,
    BudgetExhausted,
    Aborted,
}

impl GoalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::NeedsInput => "needs_input",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Aborted => "aborted",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Complete)
    }
}

impl std::fmt::Display for GoalStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for GoalStatus {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "complete" | "done" => Ok(Self::Complete),
            "failed" | "fail" | "incomplete" => Ok(Self::Failed),
            "needs_input" | "needs-human" | "question" => Ok(Self::NeedsInput),
            "budget_exhausted" | "budget" => Ok(Self::BudgetExhausted),
            "aborted" | "cancelled" | "canceled" => Ok(Self::Aborted),
            other => Err(format!("unknown goal status `{other}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        for value in [
            "complete",
            "failed",
            "needs_input",
            "budget_exhausted",
            "aborted",
        ] {
            let status: GoalStatus = value.parse().unwrap();
            assert_eq!(status.as_str(), value);
        }
    }
}
