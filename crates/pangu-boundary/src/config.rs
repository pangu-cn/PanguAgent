use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use pangu_core::{Error, Result};

use crate::approval::ApprovalMode;
use crate::budget::Budget;
use crate::policy::{Policy, Rule};
use crate::sandbox::{absolute_path, absolute_path_from, Sandbox};

pub const EMBEDDED: &str = include_str!("../../../config/boundary.toml");
pub const DEFAULT_SYSTEM_PROMPT: &str = "\
你是 Pangu，一个在显式边界内工作的自主 agent。

规则：
1. 只能通过提供的工具改变外部世界；一次只执行一个可审计动作。
2. 先读后写，优先可逆操作；路径、主机和命令都服从当前回合边界。
3. 被策略、沙箱或审批拒绝后，不要重复同一动作；根据 tool error 换路或诚实结束。
4. 只有目标真实完成且已有成功工具证据时，才调用 finish(status=\"complete\")。
5. 不得虚构工具结果，不得尝试修改预算、工作区、审批模式或禁止项。
";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub model: ModelSection,
    pub budget: Budget,
    pub boundary: BoundarySection,
    pub goal: GoalSection,
    pub rules: Vec<Rule>,
    pub unattended: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ModelSection {
    pub protocol: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub input_usd_per_mtok: Option<f64>,
    pub output_usd_per_mtok: Option<f64>,
    pub request_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct BoundarySection {
    pub workspace: PathBuf,
    pub readable_roots: Vec<PathBuf>,
    pub writable_roots: Vec<PathBuf>,
    pub forbidden_globs: Vec<String>,
    pub approval: ApprovalSection,
    pub max_tool_output_bytes: usize,
    pub max_arg_bytes: usize,
    pub subprocess_timeout_secs: u64,
    pub subprocess_output_limit: usize,
    pub network: NetworkSection,
    pub env: EnvSection,
    pub max_write_bytes: usize,
    pub max_paths_per_action: usize,
}

pub type BoundaryConfig = BoundarySection;

impl Default for BoundarySection {
    fn default() -> Self {
        Self {
            workspace: PathBuf::from("."),
            readable_roots: vec![PathBuf::from(".")],
            writable_roots: vec![PathBuf::from(".")],
            forbidden_globs: vec![
                "**/.git/**".into(),
                "**/.env".into(),
                "**/.env.*".into(),
                "**/secrets/**".into(),
                "**/*.pem".into(),
                "**/id_rsa*".into(),
            ],
            approval: ApprovalSection::default(),
            max_tool_output_bytes: 16_384,
            max_arg_bytes: 8_192,
            subprocess_timeout_secs: 45,
            subprocess_output_limit: 200_000,
            network: NetworkSection::default(),
            env: EnvSection::default(),
            max_write_bytes: 4_194_304,
            max_paths_per_action: 64,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalSection {
    pub mode: ApprovalMode,
    pub ask_timeout_secs: u64,
}

impl Default for ApprovalSection {
    fn default() -> Self {
        Self {
            mode: ApprovalMode::DestructiveAndAbove,
            ask_timeout_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    pub allow_localhost: bool,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct EnvSection {
    pub allow: Vec<String>,
}

impl Default for EnvSection {
    fn default() -> Self {
        Self {
            allow: [
                "PATH",
                "HOME",
                "USER",
                "SHELL",
                "LANG",
                "LC_ALL",
                "TERM",
                "TMPDIR",
                "TEMP",
                "TMP",
                "SYSTEMROOT",
                "COMSPEC",
                "PATHEXT",
                "APPDATA",
                "LOCALAPPDATA",
                "USERPROFILE",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct GoalSection {
    pub require_evidence: bool,
    pub min_successful_tool_calls: u32,
    pub system_prompt: String,
}

impl Default for GoalSection {
    fn default() -> Self {
        Self {
            require_evidence: true,
            min_successful_tool_calls: 1,
            system_prompt: DEFAULT_SYSTEM_PROMPT.to_string(),
        }
    }
}

impl Config {
    pub fn embedded() -> Result<Self> {
        Self::from_toml(EMBEDDED)
    }

    pub fn from_toml(source: &str) -> Result<Self> {
        let config: Self = toml::from_str(source)
            .map_err(|error| Error::Config(format!("invalid config: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Explicit configuration must exist. Without an explicit path, the first
    /// existing user configuration is loaded once; repository defaults are
    /// already compiled in and cannot accidentally override a user's choice.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Vec<PathBuf>)> {
        let mut config = Self::embedded()?;
        let mut files = vec![PathBuf::from("<embedded>")];
        let candidate = if let Some(path) = explicit {
            if !path.is_file() {
                return Err(Error::Config(format!(
                    "config file does not exist: {}",
                    path.display()
                )));
            }
            Some(path.to_path_buf())
        } else if let Some(path) = std::env::var_os("PANGU_CONFIG") {
            let path = PathBuf::from(path);
            if !path.is_file() {
                return Err(Error::Config(format!(
                    "PANGU_CONFIG does not exist: {}",
                    path.display()
                )));
            }
            Some(path)
        } else {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .map(|home| home.join(".config").join("pangu").join("boundary.toml"));
            [Some(PathBuf::from("pangu.toml")), home]
                .into_iter()
                .flatten()
                .find(|path| path.is_file())
        };

        if let Some(path) = candidate {
            let source = std::fs::read_to_string(&path)?;
            let patch: toml::Value = toml::from_str(&source).map_err(|error| {
                Error::Config(format!("{}: invalid TOML: {error}", path.display()))
            })?;
            config = merge(config, patch)?;
            config.validate()?;
            files.push(path);
        }
        Ok((config, files))
    }

    pub fn merge_patch(&mut self, patch: &toml::Value) -> Result<()> {
        *self = merge(self.clone(), patch.clone())?;
        self.validate()
    }

    pub fn validate(&self) -> Result<()> {
        self.budget.validate()?;
        if self.unattended && self.boundary.approval.mode != ApprovalMode::Never {
            return Err(Error::Config(
                "unattended runs must use approval.mode = never".into(),
            ));
        }
        if !self.goal.require_evidence {
            return Err(Error::Config(
                "goal.require_evidence is a hard invariant and cannot be false".into(),
            ));
        }
        if self.goal.min_successful_tool_calls == 0 {
            return Err(Error::Config(
                "goal.min_successful_tool_calls must be > 0".into(),
            ));
        }
        if self.boundary.max_tool_output_bytes < 256
            || self.boundary.max_tool_output_bytes > 16 * 1024 * 1024
        {
            return Err(Error::Config(
                "boundary.max_tool_output_bytes must be between 256 and 16 MiB".into(),
            ));
        }
        for (name, value) in [
            ("max_arg_bytes", self.boundary.max_arg_bytes),
            (
                "subprocess_output_limit",
                self.boundary.subprocess_output_limit,
            ),
            ("max_write_bytes", self.boundary.max_write_bytes),
            ("max_paths_per_action", self.boundary.max_paths_per_action),
        ] {
            if value == 0 {
                return Err(Error::Config(format!("boundary.{name} must be > 0")));
            }
        }
        if self.boundary.subprocess_timeout_secs == 0 {
            return Err(Error::Config(
                "boundary.subprocess_timeout_secs must be > 0".into(),
            ));
        }
        if self.boundary.subprocess_timeout_secs >= self.budget.max_wall_clock_secs.as_secs() {
            return Err(Error::Config(
                "boundary.subprocess_timeout_secs must be shorter than budget.max_wall_clock_secs"
                    .into(),
            ));
        }
        if self.boundary.approval.ask_timeout_secs == 0 {
            return Err(Error::Config(
                "boundary.approval.ask_timeout_secs must be > 0".into(),
            ));
        }
        if self.boundary.approval.ask_timeout_secs >= self.budget.max_wall_clock_secs.as_secs() {
            return Err(Error::Config(
                "boundary.approval.ask_timeout_secs must be shorter than budget.max_wall_clock_secs"
                    .into(),
            ));
        }

        let workspace = absolute_path(&self.boundary.workspace)?;
        let workspace = std::fs::canonicalize(&workspace)?;
        if !workspace.is_dir() {
            return Err(Error::Config(
                "boundary.workspace must be a directory".into(),
            ));
        }
        if self.boundary.readable_roots.is_empty() {
            return Err(Error::Config(
                "boundary.readable_roots must include at least the workspace".into(),
            ));
        }
        if self.boundary.writable_roots.is_empty() {
            return Err(Error::Config(
                "boundary.writable_roots must include at least the workspace".into(),
            ));
        }
        let has_workspace_root = self.boundary.readable_roots.iter().any(|root| {
            absolute_path_from(&workspace, root)
                .ok()
                .and_then(|path| std::fs::canonicalize(path).ok())
                .is_some_and(|path| path == workspace)
        });
        if !has_workspace_root {
            return Err(Error::Config(
                "boundary.readable_roots must include the workspace".into(),
            ));
        }
        for root in &self.boundary.readable_roots {
            let root = std::fs::canonicalize(absolute_path_from(&workspace, root)?)?;
            if !root.is_dir() {
                return Err(Error::Config(format!(
                    "readable root is not a directory: {}",
                    root.display()
                )));
            }
        }
        for root in &self.boundary.writable_roots {
            let root = std::fs::canonicalize(absolute_path_from(&workspace, root)?)?;
            if !root.is_dir() || !root.starts_with(&workspace) {
                return Err(Error::Config(format!(
                    "writable root {} must be inside workspace {}",
                    root.display(),
                    workspace.display()
                )));
            }
        }
        for pattern in &self.boundary.forbidden_globs {
            if pattern.chars().any(char::is_control) {
                return Err(Error::Config(
                    "boundary.forbidden_globs must not contain control characters".into(),
                ));
            }
            pangu_core::Glob::new(pattern)?;
        }
        for host in &self.boundary.network.hosts {
            if host.chars().any(char::is_control) {
                return Err(Error::Config(
                    "boundary.network.hosts must not contain control characters".into(),
                ));
            }
            pangu_core::Glob::new(host)?;
        }
        for key in &self.boundary.env.allow {
            if key.trim().is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                || key
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_digit())
                || [
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
            {
                return Err(Error::Config(format!(
                    "sensitive or empty environment key is not allowed: {key}"
                )));
            }
        }
        if let Some(protocol) = &self.model.protocol {
            if !matches!(protocol.as_str(), "openai-compatible" | "openai" | "ollama") {
                return Err(Error::Config(format!(
                    "unsupported model protocol `{protocol}`"
                )));
            }
        }
        if let Some(base_url) = &self.model.base_url {
            if base_url.len() > 2_048 {
                return Err(Error::Config("model.base_url is too long".into()));
            }
            validate_base_url(base_url)?;
        }
        if self.model.model.as_deref().is_some_and(|model| {
            model.trim().is_empty() || model.len() > 256 || model.chars().any(char::is_control)
        }) {
            return Err(Error::Config(
                "model.model must be non-empty, bounded, and contain no control characters".into(),
            ));
        }
        if self
            .model
            .protocol
            .as_deref()
            .is_some_and(|protocol| protocol.len() > 64)
        {
            return Err(Error::Config("model.protocol is too long".into()));
        }
        if self.model.max_output_tokens == Some(0) {
            return Err(Error::Config("model.max_output_tokens must be > 0".into()));
        }
        if self
            .model
            .max_output_tokens
            .is_some_and(|tokens| u64::from(tokens) > self.budget.max_output_tokens)
        {
            return Err(Error::Config(
                "model.max_output_tokens must not exceed budget.max_output_tokens".into(),
            ));
        }
        if self.model.api_key_env.as_deref().is_some_and(|name| {
            name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control)
        }) {
            return Err(Error::Config(
                "model.api_key_env must be non-empty, bounded, and contain no control characters"
                    .into(),
            ));
        }
        if self
            .model
            .temperature
            .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
        {
            return Err(Error::Config(
                "model.temperature must be finite and between 0 and 2".into(),
            ));
        }
        if self.model.input_usd_per_mtok.is_some() != self.model.output_usd_per_mtok.is_some() {
            return Err(Error::Config(
                "model input/output prices must be configured together".into(),
            ));
        }
        for (name, value) in [
            ("input_usd_per_mtok", self.model.input_usd_per_mtok),
            ("output_usd_per_mtok", self.model.output_usd_per_mtok),
        ] {
            if value.is_some_and(|price| !price.is_finite() || price < 0.0) {
                return Err(Error::Config(format!(
                    "model.{name} must be finite and >= 0"
                )));
            }
        }
        if self.model.request_timeout_secs == Some(0) {
            return Err(Error::Config(
                "model.request_timeout_secs must be > 0".into(),
            ));
        }
        let request_timeout = self.model.request_timeout_secs.unwrap_or(60);
        if Duration::from_secs(request_timeout) >= self.budget.max_wall_clock_secs {
            return Err(Error::Config(
                "model request timeout must be shorter than budget.max_wall_clock_secs".into(),
            ));
        }
        // Construct the effective sandbox once during validation so roots,
        // symlink components, globs, limits, and network filters cannot drift
        // between configuration and runtime enforcement.
        Sandbox::from_config(&self.boundary)?;
        Policy::new(self.rules.clone())?;
        Ok(())
    }

    pub fn workspace_abs(&self) -> PathBuf {
        absolute_path(&self.boundary.workspace)
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .unwrap_or_else(|| self.boundary.workspace.clone())
    }

    /// Hash the effective enforcement boundary, not the spelling of a path in
    /// TOML. Relative roots are resolved against the workspace, roots and
    /// unordered filters are normalized, and the user goal/system prompt are
    /// intentionally excluded.
    pub fn boundary_digest(&self) -> String {
        let workspace = self.workspace_abs();
        let canonical = |path: &Path| {
            std::fs::canonicalize(path)
                .ok()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
        };
        let roots = |values: &[PathBuf]| {
            let mut values = values
                .iter()
                .filter_map(|path| {
                    absolute_path_from(&workspace, path)
                        .ok()
                        .and_then(|path| canonical(&path))
                })
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            values
        };
        let mut forbidden = self.boundary.forbidden_globs.clone();
        forbidden.sort();
        forbidden.dedup();
        let mut hosts = self.boundary.network.hosts.clone();
        hosts.sort();
        hosts.dedup();
        let mut env = self.boundary.env.allow.clone();
        env.sort();
        env.dedup();
        let value = serde_json::json!({
            "workspace": workspace.to_string_lossy().replace('\\', "/"),
            "readable_roots": roots(&self.boundary.readable_roots),
            "writable_roots": roots(&self.boundary.writable_roots),
            "forbidden_globs": forbidden,
            "approval": &self.boundary.approval,
            "network": {
                "allow_localhost": self.boundary.network.allow_localhost,
                "hosts": hosts,
            },
            "env_allow": env,
            "limits": {
                "max_tool_output_bytes": self.boundary.max_tool_output_bytes,
                "max_arg_bytes": self.boundary.max_arg_bytes,
                "subprocess_timeout_secs": self.boundary.subprocess_timeout_secs,
                "subprocess_output_limit": self.boundary.subprocess_output_limit,
                "max_write_bytes": self.boundary.max_write_bytes,
                "max_paths_per_action": self.boundary.max_paths_per_action,
            },
            "budget": &self.budget,
            "evidence": {
                "required": self.goal.require_evidence,
                "minimum_calls": self.goal.min_successful_tool_calls,
            },
            "rules": &self.rules,
            "unattended": self.unattended,
        });
        pangu_core::hex_sha256(&serde_json::to_string(&value).unwrap_or_default())
    }

    pub fn explain(&self) -> String {
        format!(
            "boundary digest : {}\nworkspace      : {}\nwritable roots : {:?}\nforbidden globs: {}\nbudget         : {} turns / {} in / {} out tokens / ${:.2} / {}s\napproval       : {} (timeout {}s)\negress         : {} (localhost {})\nchild env      : allow-list of {}\n\nrules:\n{}\n",
            self.boundary_digest(),
            self.workspace_abs().display(),
            self.boundary.writable_roots,
            self.boundary.forbidden_globs.join(", "),
            self.budget.max_turns,
            self.budget.max_input_tokens,
            self.budget.max_output_tokens,
            self.budget.max_cost_usd,
            self.budget.max_wall_clock_secs.as_secs(),
            self.boundary.approval.mode,
            self.boundary.approval.ask_timeout_secs,
            if self.boundary.network.hosts.is_empty() { "deny all".to_string() } else { self.boundary.network.hosts.join(", ") },
            if self.boundary.network.allow_localhost { "allowed" } else { "denied" },
            self.boundary.env.allow.len(),
            Policy::new(self.rules.clone()).map(|policy| policy.render()).unwrap_or_else(|error| format!("<invalid: {error}>")),
        )
    }

    pub fn sample() -> &'static str {
        EMBEDDED
    }
}

fn validate_base_url(raw: &str) -> Result<()> {
    let url = Url::parse(raw)
        .map_err(|error| Error::Config(format!("invalid model.base_url: {error}")))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(Error::Config(
            "model.base_url must use http or https".into(),
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Config(
            "model.base_url must not contain credentials, query, or fragment".into(),
        ));
    }
    if url.port() == Some(0) {
        return Err(Error::Config(
            "model.base_url must use a non-zero port when a port is specified".into(),
        ));
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host.is_empty() {
        return Err(Error::Config("model.base_url must contain a host".into()));
    }
    let loopback = host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() == "http" && !loopback {
        return Err(Error::Config("remote model.base_url must use https".into()));
    }
    Ok(())
}

fn merge(base: Config, patch: toml::Value) -> Result<Config> {
    let mut base = serde_json::to_value(base).map_err(|error| Error::Config(error.to_string()))?;
    let patch = serde_json::to_value(patch).map_err(|error| Error::Config(error.to_string()))?;
    deep_merge(&mut base, &patch);
    serde_json::from_value(base)
        .map_err(|error| Error::Config(format!("merged config is invalid: {error}")))
}

fn deep_merge(destination: &mut serde_json::Value, source: &serde_json::Value) {
    match destination {
        serde_json::Value::Object(destination) if source.is_object() => {
            let source = source.as_object().expect("checked above");
            for (key, value) in source {
                if value.is_null() {
                    continue;
                }
                match destination.get_mut(key) {
                    Some(slot) if slot.is_object() && value.is_object() => deep_merge(slot, value),
                    _ => {
                        destination.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        _ => *destination = source.clone(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub workspace: Option<PathBuf>,
    pub add_writable: Vec<PathBuf>,
    pub add_forbidden: Vec<String>,
    pub approval_mode: Option<ApprovalMode>,
    pub max_turns: Option<u32>,
    pub max_cost_usd: Option<f64>,
    pub add_egress: Vec<String>,
    pub unattended: bool,
    pub model: Option<String>,
    pub base_url: Option<String>,
}

impl Config {
    pub fn apply(mut self, overrides: &CliOverrides) -> Result<Self> {
        if let Some(workspace) = &overrides.workspace {
            self.boundary.workspace = workspace.clone();
        }
        self.boundary
            .writable_roots
            .extend(overrides.add_writable.iter().cloned());
        self.boundary
            .forbidden_globs
            .extend(overrides.add_forbidden.iter().cloned());
        self.boundary
            .network
            .hosts
            .extend(overrides.add_egress.iter().cloned());
        if let Some(mode) = overrides.approval_mode {
            self.boundary.approval.mode = mode;
        }
        if let Some(turns) = overrides.max_turns {
            self.budget.max_turns = turns;
        }
        if let Some(cost) = overrides.max_cost_usd {
            self.budget.max_cost_usd = cost;
        }
        if let Some(model) = &overrides.model {
            self.model.model = Some(model.clone());
        }
        if let Some(base_url) = &overrides.base_url {
            self.model.base_url = Some(base_url.clone());
        }
        if overrides.unattended {
            self.unattended = true;
            self.boundary.approval.mode = ApprovalMode::Never;
        }
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_config_parses() {
        let config = Config::embedded().unwrap();
        assert_eq!(config.budget.max_turns, 12);
        assert!(config.goal.require_evidence);
        assert!(!config.rules.is_empty());
    }

    #[test]
    fn boundary_digest_uses_effective_roots() {
        let root = std::env::temp_dir().join(format!(
            "pangu-digest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut absolute = Config::embedded().unwrap();
        absolute.boundary.workspace = root.clone();
        absolute.boundary.readable_roots = vec![root.clone()];
        absolute.boundary.writable_roots = vec![root.clone()];
        let mut relative = absolute.clone();
        relative.boundary.readable_roots = vec![std::path::PathBuf::from(".")];
        relative.boundary.writable_roots = vec![std::path::PathBuf::from(".")];
        assert_eq!(absolute.boundary_digest(), relative.boundary_digest());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn contract_and_sandbox_preserve_configured_root_order() {
        let root = std::env::temp_dir().join(format!(
            "pangu-root-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![nested.clone(), root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        let contract = crate::goal::GoalContract::from_config("root order", &config).unwrap();
        let sandbox = Sandbox::from_config(&config.boundary).unwrap();
        contract.validate_against(&sandbox).unwrap();
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn overrides_are_revalidated() {
        let error = Config::embedded()
            .unwrap()
            .apply(&CliOverrides {
                max_turns: Some(0),
                ..Default::default()
            })
            .unwrap_err();
        assert!(error.to_string().contains("max_turns"));
    }
}
