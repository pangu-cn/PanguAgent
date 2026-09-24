use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use pangu_core::{Error, Price, Result};

use crate::approval::ApprovalMode;
use crate::budget::Budget;
use crate::config::Config;
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
            require_evidence: true,
            min_successful_tool_calls: 1,
            price: None,
            policy_digest: crate::Policy::empty().digest(),
        }
    }

    pub fn from_config(goal: impl Into<String>, config: &Config) -> Result<Self> {
        config.validate()?;
        let workspace = config.workspace_abs();
        let readable_roots = canonical_roots(&workspace, &config.boundary.readable_roots)?;
        let writable_roots = canonical_roots(&workspace, &config.boundary.writable_roots)?;
        let price = match (
            config.model.input_usd_per_mtok,
            config.model.output_usd_per_mtok,
        ) {
            (Some(input), Some(output)) => Some(Price {
                input_usd_per_mtok: input,
                output_usd_per_mtok: output,
            }),
            _ => None,
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
            require_evidence: config.goal.require_evidence,
            min_successful_tool_calls: config.goal.min_successful_tool_calls,
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
        let value = serde_json::json!({
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
