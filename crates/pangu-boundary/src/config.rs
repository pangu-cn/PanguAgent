use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use pangu_core::{Error, Result};

use crate::approval::ApprovalMode;
use crate::budget::Budget;
use crate::execution::ExecutionSection;
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
    pub checkpoint: CheckpointSection,
    pub conversation: ConversationSection,
    pub goal: GoalSection,
    pub rules: Vec<Rule>,
    pub unattended: bool,
    /// C5: the declared execution backend. A declaration, not a verified
    /// fact; frozen into the contract and recorded in `RunStarted`.
    #[serde(default)]
    pub execution: ExecutionSection,
    /// F3: the lint/test command the `verify` tool runs. Empty = the tool
    /// is not advertised, exactly as if F3 were not compiled in.
    #[serde(default)]
    pub verify: VerifySection,
    /// B3: the controlled memory candidate queue. Disabled by default: no
    /// tool, no injection, no digest change.
    #[serde(default)]
    pub memory: MemorySection,
    /// B2: the skill registry. Disabled by default: nothing loads.
    #[serde(default)]
    pub skills: SkillsSection,
    /// F5: the evaluation profile. Undeclared by default: no eval semantics,
    /// no digest change.
    #[serde(default)]
    pub eval: EvalSection,
}

/// B3: controlled memory candidate queue configuration. Disabled by default:
/// the `propose_memory` tool does not exist, nothing is injected, and the
/// contract digest is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MemorySection {
    pub enabled: bool,
    pub max_pending: usize,
    pub max_content_bytes: usize,
    pub max_kind_bytes: usize,
    pub max_injected: usize,
    pub max_injected_bytes: usize,
}

impl Default for MemorySection {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pending: 256,
            max_content_bytes: 4_096,
            max_kind_bytes: 32,
            max_injected: 24,
            max_injected_bytes: 16_384,
        }
    }
}

/// B2: skill registry configuration. Disabled by default: nothing loads,
/// nothing is advertised, nothing is injected, digests are unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SkillsSection {
    pub enabled: bool,
    /// Pinned ed25519 public key (64 hex chars). Empty = signatures are not
    /// checked and packages load with an honest `unsigned` marker.
    pub verify_key: String,
    pub max_skills: usize,
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_doc_bytes: usize,
    pub max_index_skills: usize,
    pub max_index_bytes: usize,
}

impl Default for SkillsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_key: String::new(),
            max_skills: 64,
            max_files: 64,
            max_file_bytes: 262_144,
            max_doc_bytes: 65_536,
            max_index_skills: 48,
            max_index_bytes: 8_192,
        }
    }
}

/// F5: issue-to-patch evaluation profile. An empty `profile` means no
/// evaluation semantics: nothing is frozen, nothing is recorded, digests and
/// runs are exactly as before. A declared profile pins the issue document
/// (by path; the content digest is taken at run start) so one run can be
/// reproduced and audited as an experiment.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EvalSection {
    /// Profile name (lowercase letters, digits, hyphen; 1-64 chars). Empty =
    /// evaluation not declared.
    pub profile: String,
    /// Workspace-relative path of the issue document. Must be a safe
    /// workspace-relative path and must not live under `.pangu`.
    pub issue_path: String,
}

impl EvalSection {
    /// F5: whether an evaluation profile is declared.
    pub fn is_declared(&self) -> bool {
        !self.profile.trim().is_empty()
    }
}

impl SkillsSection {
    /// The runtime limits derived from this section.
    pub fn limits(&self) -> pangu_core::SkillLimits {
        pangu_core::SkillLimits {
            max_skills: self.max_skills,
            max_files: self.max_files,
            max_file_bytes: self.max_file_bytes,
            max_doc_bytes: self.max_doc_bytes,
            max_index_skills: self.max_index_skills,
            max_index_bytes: self.max_index_bytes,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct VerifySection {
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointBackend {
    #[default]
    Artifact,
    Git,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointFailurePolicy {
    #[default]
    FailRun,
    NeedsInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct CheckpointSection {
    pub enabled: bool,
    pub backend: CheckpointBackend,
    pub artifact_root: PathBuf,
    pub max_snapshot_bytes: u64,
    pub max_snapshot_files: usize,
    pub max_snapshot_file_bytes: u64,
    pub failure_policy: CheckpointFailurePolicy,
    pub rollback_requires_approval: bool,
    /// Directories to leave out of the snapshot.
    ///
    /// Build output is the reason this exists. A snapshot walks the whole
    /// workspace, and a Rust `target/` is routinely gigabytes, so a
    /// checkpoint in an ordinary repo hits `max_snapshot_bytes` and fails the
    /// run. There is deliberately no built-in default list: `.gitignore` is
    /// not a safe basis for one, because plenty of projects gitignore real
    /// work (data and output directories) — silently dropping those from a
    /// snapshot would make rollback lose them. Deciding what is
    /// regenerable is the user's call, not a default.
    pub exclude_roots: Vec<PathBuf>,
}

/// Persisted conversation history, so an interrupted run can resume.
///
/// Off by default, like checkpointing. A stored conversation is a record of
/// what the model was told, not an authorization: restoring one does not
/// carry any decision or approval into the resumed run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConversationSection {
    pub enabled: bool,
    /// Artifact store root for conversation snapshots. Kept separate from
    /// `checkpoint.artifact_root` so the two features can be enabled,
    /// retained, or cleaned up independently.
    pub artifact_root: PathBuf,
    /// Save after every turn, not just at terminal states. Costs a write per
    /// turn and buys recovery from a crash mid-run.
    pub save_every_turn: bool,
}

impl Default for ConversationSection {
    fn default() -> Self {
        Self {
            enabled: false,
            artifact_root: PathBuf::from(".pangu/conversations"),
            save_every_turn: true,
        }
    }
}

impl Default for CheckpointSection {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CheckpointBackend::Artifact,
            artifact_root: PathBuf::from(".pangu/checkpoints"),
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_snapshot_files: 10_000,
            max_snapshot_file_bytes: 4 * 1024 * 1024,
            failure_policy: CheckpointFailurePolicy::FailRun,
            rollback_requires_approval: true,
            exclude_roots: Vec::new(),
        }
    }
}

impl CheckpointSection {
    pub fn validate(&self, workspace: &Path, writable_roots: &[PathBuf]) -> Result<()> {
        if self.max_snapshot_bytes == 0
            || self.max_snapshot_files == 0
            || self.max_snapshot_file_bytes == 0
        {
            return Err(Error::Config(
                "checkpoint snapshot limits must be > 0".into(),
            ));
        }
        pangu_core::SnapshotLimits {
            max_snapshot_bytes: self.max_snapshot_bytes,
            max_snapshot_files: self.max_snapshot_files,
            max_snapshot_file_bytes: self.max_snapshot_file_bytes,
        }
        .validate()?;
        if !self.rollback_requires_approval {
            return Err(Error::Config(
                "checkpoint.rollback_requires_approval cannot be disabled".into(),
            ));
        }
        // A disabled section is deliberately inert with respect to paths. In
        // particular, do not make older configurations fail merely because
        // their existing writable roots do not happen to contain the future
        // default path. Universal safety fields above are still validated.
        if !self.enabled {
            // Still reject malformed/traversing spellings so a dormant
            // section cannot become an unsafe path after a later edit.
            absolute_path_from(workspace, &self.artifact_root)?;
            return Ok(());
        }
        let artifact_path = absolute_path_from(workspace, &self.artifact_root)?;
        if path_has_symlink_component_under(workspace, &artifact_path) {
            return Err(Error::Config(
                "checkpoint.artifact_root must not contain symlink components".into(),
            ));
        }
        let artifact_root = canonicalize_with_missing(&artifact_path)?;
        let workspace = canonicalize_with_missing(workspace)?;
        if !path_starts_with(&artifact_root, &workspace) || same_path(&artifact_root, &workspace) {
            return Err(Error::Config(
                "checkpoint.artifact_root must be a dedicated directory inside the workspace"
                    .into(),
            ));
        }
        if artifact_root.exists() && !artifact_root.is_dir() {
            return Err(Error::Config(
                "checkpoint.artifact_root must be a directory".into(),
            ));
        }
        let inside_writable_root = writable_roots.iter().any(|root| {
            absolute_path_from(&workspace, root)
                .and_then(|root| std::fs::canonicalize(root).map_err(Into::into))
                .map(|root| path_starts_with(&artifact_root, &root))
                .unwrap_or(false)
        });
        if !inside_writable_root {
            return Err(Error::Config(
                "checkpoint.artifact_root must be inside a writable root".into(),
            ));
        }
        // An exclusion that reaches outside the workspace, or that swallows the
        // whole workspace, would quietly turn the snapshot into something other
        // than what it claims to be. Both are rejected here rather than at
        // snapshot time, so the mistake is reported before a run starts.
        for (index, exclude) in self.exclude_roots.iter().enumerate() {
            // Containment is decided first, and decided from the *spelling*.
            //
            // `absolute_path_from` rejects `..` outright, so a rule like
            // `../elsewhere` fails there. Reporting that would send the operator
            // looking for a traversal bug in a config field whose actual mistake
            // is "this exclusion points outside the workspace" — and the verdict
            // would differ between platforms, because on Windows a canonicalized
            // workspace plus `..` can normalize away before the rejection is
            // reached. Same config, same mistake, one message.
            //
            // Only the `..` spelling is handled here. An absolute path is *not*
            // suspicious by itself: the contract normalizes exclusions to
            // absolute paths before revalidating them, so rejecting one would
            // break every valid configuration. Containment below covers those.
            if exclude.components().any(escapes_workspace) {
                return Err(Error::Config(format!(
                    "checkpoint.exclude_roots[{index}] must be a subdirectory of the workspace"
                )));
            }
            let path = absolute_path_from(&workspace, exclude)?;
            let resolved = canonicalize_with_missing(&path)?;
            if !path_starts_with(&resolved, &workspace) || same_path(&resolved, &workspace) {
                return Err(Error::Config(format!(
                    "checkpoint.exclude_roots[{index}] must be a subdirectory of the workspace"
                )));
            }
            if path_has_symlink_component_under(&workspace, &path) {
                return Err(Error::Config(format!(
                    "checkpoint.exclude_roots[{index}] must not contain symlink components"
                )));
            }
            if same_path(&resolved, &artifact_root) {
                return Err(Error::Config(format!(
                    "checkpoint.exclude_roots[{index}] must not be the artifact root; it is \
                     already excluded"
                )));
            }
        }
        Ok(())
    }
}

/// True for a `..` component, i.e. a path spelling that leaves its base.
///
/// Used to decide "outside the workspace" from the spelling, before any
/// platform-specific path normalization can turn one mistake into two different
/// messages.
fn escapes_workspace(component: std::path::Component<'_>) -> bool {
    matches!(component, std::path::Component::ParentDir)
}

pub(crate) fn canonicalize_with_missing(path: &Path) -> Result<PathBuf> {
    let mut current = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(_) => {
                let mut canonical = std::fs::canonicalize(&current)?;
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = current.file_name().ok_or_else(|| {
                    Error::Config(format!("cannot resolve path: {}", path.display()))
                })?;
                missing.push(name.to_os_string());
                if !current.pop() {
                    return Err(Error::Config(format!(
                        "cannot resolve path: {}",
                        path.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    comparable_path(left) == comparable_path(right)
}

fn path_starts_with(path: &Path, base: &Path) -> bool {
    comparable_path(path).starts_with(comparable_path(base))
}

fn comparable_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.as_os_str().to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path.to_path_buf()
}

fn path_has_symlink_component_under(base: &Path, path: &Path) -> bool {
    let base = comparable_path(base);
    let path = comparable_path(path);
    let Ok(relative) = path.strip_prefix(&base) else {
        return true;
    };
    let mut current = base;
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return true,
            std::path::Component::Normal(value) => current.push(value),
            std::path::Component::Prefix(_) | std::path::Component::RootDir => return true,
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return true,
        }
    }
    false
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ModelSection {
    pub protocol: Option<String>,
    /// B4: name of a built-in registry preset (`pangu models list`). Naming
    /// the provider opts into its endpoint/key defaults and its price table
    /// for known models; explicit config values always win.
    pub provider: Option<String>,
    pub model: Option<String>,
    /// B5: fallback candidates, tried in order after the primary fails.
    /// Every candidate is fully resolved and capability-checked at config
    /// time; the declared chain is frozen into the contract and switches are
    /// audited — fallback is never silent and never implicit.
    #[serde(default)]
    pub fallback: Vec<FallbackCandidate>,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub input_usd_per_mtok: Option<f64>,
    pub output_usd_per_mtok: Option<f64>,
    pub request_timeout_secs: Option<u64>,
}

/// B5: one declared fallback candidate. Field semantics mirror the primary
/// `[model]` section; registry resolution and capability checks apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct FallbackCandidate {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub input_usd_per_mtok: Option<f64>,
    pub output_usd_per_mtok: Option<f64>,
}

/// A fully resolved fallback candidate (config-time output).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedFallback {
    pub model: String,
    pub base_url: String,
    pub api_key_env: Option<String>,
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
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
    /// F3: extra programs admitted to the read-only argv allow-list, for
    /// verify commands such as `cargo`/`npm`. Each entry must be a bare
    /// program name; declaring one does not weaken path/host checks.
    #[serde(default)]
    pub extra_readonly_commands: Vec<String>,
    /// D1: allow the model to delegate bounded subtasks to restricted
    /// sub-agents. Default off keeps historical digests and runs unchanged;
    /// a sub-agent's budget is always clamped to the parent's remaining
    /// budget and its contract is derived, never model-supplied.
    #[serde(default)]
    pub allow_delegation: bool,
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
                // B3: Pangu-owned storage (journal, checkpoints, conversation
                // store, memory queue) is never tool-writable.
                "**/.pangu/**".into(),
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
            extra_readonly_commands: Vec::new(),
            allow_delegation: false,
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
    /// D3/D4: declared deliverables. Empty = no deliverable semantics, runs
    /// behave exactly as before.
    #[serde(default)]
    pub deliverable: Vec<pangu_core::DeliverableSpec>,
    /// F4: when true, the run starts in a read-only plan phase; the model's
    /// `begin_act` control call is the only way into the act phase, where
    /// every mutating action is still individually approved. Default false:
    /// single-phase runs behave exactly as before.
    pub plan_first: bool,
}

impl Default for GoalSection {
    fn default() -> Self {
        Self {
            require_evidence: true,
            min_successful_tool_calls: 1,
            system_prompt: DEFAULT_SYSTEM_PROMPT.to_string(),
            plan_first: false,
            deliverable: Vec::new(),
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
        self.checkpoint
            .validate(&workspace, &self.boundary.writable_roots)?;
        for pattern in &self.boundary.forbidden_globs {
            if pattern.chars().any(char::is_control) {
                return Err(Error::Config(
                    "boundary.forbidden_globs must not contain control characters".into(),
                ));
            }
            pangu_core::Glob::new(pattern)?;
        }
        // D3/D4: deliverable declarations must be well-formed and unique.
        let mut deliverable_names = std::collections::HashSet::new();
        for deliverable in &self.goal.deliverable {
            if deliverable.name.is_empty()
                || deliverable.name.len() > 64
                || !deliverable
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(Error::Config(format!(
                    "goal.deliverable name `{}` is invalid (lowercase letters, digits, hyphen; 1-64 chars)",
                    deliverable.name
                )));
            }
            if !deliverable_names.insert(deliverable.name.as_str()) {
                return Err(Error::Config(format!(
                    "goal.deliverable name `{}` is declared twice",
                    deliverable.name
                )));
            }
            pangu_core::deliverable::validate_relative_path(&deliverable.path)?;
            if deliverable.kind.trim().is_empty() || deliverable.kind.len() > 32 {
                return Err(Error::Config(format!(
                    "goal.deliverable `{}` kind must be 1-32 chars",
                    deliverable.name
                )));
            }
            if deliverable.min_bytes == 0 || deliverable.min_bytes > 16_777_216 {
                return Err(Error::Config(format!(
                    "goal.deliverable `{}` min_bytes must be between 1 and 16777216",
                    deliverable.name
                )));
            }
        }
        // F5: a declared evaluation profile must name its issue document;
        // an undeclared profile must not carry a stray issue path.
        let eval = &self.eval;
        if eval.is_declared() {
            if eval.profile.len() > 64
                || !eval
                    .profile
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(Error::Config(
                    "eval.profile is invalid (lowercase letters, digits, hyphen; 1-64 chars)"
                        .into(),
                ));
            }
            if eval.issue_path.trim().is_empty() {
                return Err(Error::Config(
                    "eval.issue_path must be set when eval.profile is declared".into(),
                ));
            }
            pangu_core::deliverable::validate_relative_path(&eval.issue_path)
                .map_err(|error| Error::Config(format!("eval.issue_path: {error}")))?;
        } else if !eval.issue_path.trim().is_empty() {
            return Err(Error::Config(
                "eval.issue_path is set but eval.profile is empty (half-declared evaluation)"
                    .into(),
            ));
        }
        // B2: bounded skill registry behavior + a well-formed pinned key.
        let skills = &self.skills;
        if skills.enabled {
            if skills.max_skills == 0 || skills.max_skills > 1_024 {
                return Err(Error::Config(
                    "skills.max_skills must be between 1 and 1024".into(),
                ));
            }
            if skills.max_files == 0 || skills.max_files > 1_024 {
                return Err(Error::Config(
                    "skills.max_files must be between 1 and 1024".into(),
                ));
            }
            if skills.max_file_bytes < 64 || skills.max_file_bytes > 16_777_216 {
                return Err(Error::Config(
                    "skills.max_file_bytes must be between 64 and 16777216".into(),
                ));
            }
            if skills.max_doc_bytes < 64 || skills.max_doc_bytes > 1_048_576 {
                return Err(Error::Config(
                    "skills.max_doc_bytes must be between 64 and 1048576".into(),
                ));
            }
            if skills.max_index_skills > 512 {
                return Err(Error::Config(
                    "skills.max_index_skills must be at most 512".into(),
                ));
            }
            if skills.max_index_bytes < 256 || skills.max_index_bytes > 1_048_576 {
                return Err(Error::Config(
                    "skills.max_index_bytes must be between 256 and 1048576".into(),
                ));
            }
            let key = skills.verify_key.trim();
            if !key.is_empty() && (key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit())) {
                return Err(Error::Config(
                    "skills.verify_key must be 64 hex chars (an ed25519 public key) or empty"
                        .into(),
                ));
            }
        }
        // B3: bounded memory behavior. The bounds must themselves be bounded
        // so a misconfigured store cannot silently disable the guarantees.
        let memory = &self.memory;
        if memory.enabled {
            if memory.max_pending == 0 {
                return Err(Error::Config(
                    "memory.max_pending must be at least 1".into(),
                ));
            }
            if memory.max_content_bytes < 64 || memory.max_content_bytes > 1_048_576 {
                return Err(Error::Config(
                    "memory.max_content_bytes must be between 64 and 1048576".into(),
                ));
            }
            if memory.max_kind_bytes == 0 || memory.max_kind_bytes > 256 {
                return Err(Error::Config(
                    "memory.max_kind_bytes must be between 1 and 256".into(),
                ));
            }
            if memory.max_injected > 1_000 {
                return Err(Error::Config(
                    "memory.max_injected must be at most 1000".into(),
                ));
            }
            if memory.max_injected_bytes < 256 || memory.max_injected_bytes > 1_048_576 {
                return Err(Error::Config(
                    "memory.max_injected_bytes must be between 256 and 1048576".into(),
                ));
            }
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
        // B4: provider resolution and capability cross-checks. Fails closed at
        // config time for unknown providers, keyed providers without a key
        // variable, tool-less models, and budgets that exceed the model's
        // context window.
        let resolved = self.resolve_provider()?;
        // B5: when a fallback chain is declared, every candidate is fully
        // resolved and capability-checked here, and the primary must have
        // resolvable prices (resolve_fallbacks enforces both).
        if !self.model.fallback.is_empty() {
            self.resolve_fallbacks()?;
        }
        if let Some(capabilities) = resolved.capabilities {
            if self.budget.max_input_tokens > capabilities.context_window_tokens {
                return Err(Error::Config(format!(
                    "budget.max_input_tokens ({}) exceeds the `{}` context window ({}) on provider `{}`; lower budget.max_input_tokens",
                    self.budget.max_input_tokens,
                    capabilities.name,
                    capabilities.context_window_tokens,
                    resolved.preset.expect("preset").name,
                )));
            }
            if let Some(max_output) = self.model.max_output_tokens {
                if max_output as u64 > capabilities.max_output_tokens {
                    return Err(Error::Config(format!(
                        "model.max_output_tokens ({max_output}) exceeds the `{}` output limit ({}) on provider `{}`",
                        capabilities.name,
                        capabilities.max_output_tokens,
                        resolved.preset.expect("preset").name,
                    )));
                }
            }
        }
        // C5: validate the execution declaration.
        self.execution.validate()?;
        // F3: extra programs join the read-only argv allow-list, so each
        // entry must be a bare program name. Declaring one does not weaken
        // path, flag, or host checks.
        for command in &self.boundary.extra_readonly_commands {
            if command.is_empty()
                || command.len() > 128
                || command.starts_with('-')
                || command.contains('/')
                || command.contains('\\')
                || command.contains("..")
                || command.chars().any(char::is_control)
            {
                return Err(Error::Config(format!(
                    "boundary.extra_readonly_commands entries must be bare program names: {command}"
                )));
            }
        }
        for argument in &self.verify.command {
            if argument.is_empty()
                || argument.len() > 4_096
                || argument.chars().any(char::is_control)
            {
                return Err(Error::Config(
                    "verify.command entries must be non-empty, bounded, and free of control characters"
                        .into(),
                ));
            }
        }
        if self.verify.command.len() > 32 {
            return Err(Error::Config(
                "verify.command must not exceed 32 argv entries".into(),
            ));
        }
        // symlink components, globs, limits, and network filters cannot drift
        // between configuration and runtime enforcement. Building the Sandbox
        // here also fail-closes an unrunnable verify command: its program must
        // be on the read-only argv allow-list (built-in or declared through
        // extra_readonly_commands) and every flag must pass the same argv
        // rules as `run_command`.
        let sandbox = Sandbox::from_config(&self.boundary)?;
        if !self.verify.command.is_empty() {
            sandbox.validate_argv(&self.verify.command)?;
        }
        Policy::new(self.rules.clone())?;
        Ok(())
    }

    /// B4: resolve the effective provider endpoint, key variable, prices and
    /// capabilities from config + built-in registry. Pure function: nothing is
    /// mutated, so digest semantics are unchanged (the contract digest already
    /// covers the effective price).
    pub fn resolve_provider(&self) -> Result<crate::registry::ResolvedProvider> {
        crate::registry::resolve(
            self.model.provider.as_deref(),
            self.model.model.as_deref(),
            self.model.protocol.as_deref(),
            self.model.base_url.as_deref(),
            self.model.api_key_env.as_deref(),
            self.model.input_usd_per_mtok,
            self.model.output_usd_per_mtok,
        )
    }

    /// B5: fully resolve every declared fallback candidate. Fails closed at
    /// config time unless every candidate is compatible (registry-declared,
    /// tool-capable, context window fits the budget, prices resolvable) and
    /// distinct from the primary and from each other.
    pub fn resolve_fallbacks(&self) -> Result<Vec<ResolvedFallback>> {
        // An undeclared chain means a single-provider run: nothing to check,
        // and the primary's missing price must not fail legacy configs here.
        if self.model.fallback.is_empty() {
            return Ok(Vec::new());
        }
        let primary = self.resolve_provider()?;
        let primary_key = (
            primary.base_url.clone(),
            primary.model.clone().unwrap_or_default(),
        );
        // Cost integrity: the primary must have resolvable prices, otherwise
        // a switch to a priced fallback would start an unpriceable run.
        if primary.input_usd_per_mtok.is_none() {
            return Err(Error::Config(
                "model.fallback requires the primary model to have resolvable prices".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::from([primary_key]);
        let mut resolved_candidates = Vec::new();
        for (index, candidate) in self.model.fallback.iter().enumerate() {
            let resolved = crate::registry::resolve(
                candidate.provider.as_deref(),
                candidate.model.as_deref(),
                None,
                candidate.base_url.as_deref(),
                candidate.api_key_env.as_deref(),
                candidate.input_usd_per_mtok,
                candidate.output_usd_per_mtok,
            )?;
            let model = resolved.model.clone().ok_or_else(|| {
                Error::Config(format!("model.fallback[{index}].model is required"))
            })?;
            // W-10: compatibility must be provable, not assumed. A candidate
            // outside the registry has no capability declaration, so it
            // cannot be verified tool-capable or window-fitting.
            let capabilities = resolved.capabilities.ok_or_else(|| {
                Error::Config(format!(
                    "model.fallback[{index}] model `{model}` is not in the registry; \
                     fallback candidates must have declared capabilities"
                ))
            })?;
            if !capabilities.supports_tools {
                return Err(Error::Config(format!(
                    "model.fallback[{index}] model `{model}` does not support tool calling"
                )));
            }
            if self.budget.max_input_tokens > capabilities.context_window_tokens {
                return Err(Error::Config(format!(
                    "model.fallback[{index}] model `{model}` context window ({}) is smaller \
                     than budget.max_input_tokens ({})",
                    capabilities.context_window_tokens, self.budget.max_input_tokens,
                )));
            }
            let (input, output) = match (resolved.input_usd_per_mtok, resolved.output_usd_per_mtok)
            {
                (Some(input), Some(output)) => (input, output),
                _ => {
                    return Err(Error::Config(format!(
                        "model.fallback[{index}] model `{model}` has no resolvable prices; \
                         the cost gate refuses unknown-cost fallbacks"
                    )));
                }
            };
            let key = (resolved.base_url.clone(), model.clone());
            if !seen.insert(key) {
                return Err(Error::Config(format!(
                    "model.fallback[{index}] duplicates the primary model or an earlier candidate"
                )));
            }
            resolved_candidates.push(ResolvedFallback {
                model,
                base_url: resolved.base_url,
                api_key_env: resolved.api_key_env,
                input_usd_per_mtok: input,
                output_usd_per_mtok: output,
            });
        }
        Ok(resolved_candidates)
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
        let checkpoint_value = if self.checkpoint.enabled {
            let mut checkpoint = self.checkpoint.clone();
            checkpoint.artifact_root = absolute_path_from(&workspace, &checkpoint.artifact_root)
                .ok()
                .and_then(|path| canonicalize_with_missing(&path).ok())
                .unwrap_or_else(|| checkpoint.artifact_root.clone());
            serde_json::to_value(checkpoint).ok()
        } else {
            None
        };
        let mut value = serde_json::json!({
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
        // A disabled checkpoint remains configuration-compatible and must not
        // change the digest of an existing v1 run. Once enabled, every
        // checkpoint limit and policy field is part of the contract boundary.
        if let Some(checkpoint) = checkpoint_value {
            if let Some(object) = value.as_object_mut() {
                object.insert("checkpoint".into(), checkpoint);
            }
        }
        // Same compatibility rule as the checkpoint: an unconfigured verify
        // tool must not change the digest of an existing v1 run. Once either
        // F3 field is set, the exact command and the extended allow-list are
        // part of the effective boundary.
        if !self.verify.command.is_empty() || !self.boundary.extra_readonly_commands.is_empty() {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "verify".into(),
                    serde_json::json!({
                        "command": &self.verify.command,
                        "extra_readonly_commands": &self.boundary.extra_readonly_commands,
                    }),
                );
            }
        }
        // Same compatibility rule: the default local profile is undeclared and
        // must not change the digest of an existing deployment. A declared
        // backend is part of the effective boundary claims.
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
        pangu_core::hex_sha256(&serde_json::to_string(&value).unwrap_or_default())
    }

    pub fn explain(&self) -> String {
        let plan_line = if self.goal.plan_first {
            "plan_first      : true — run starts read-only; the model's `begin_act` control call starts the act phase\n"
                .to_string()
        } else {
            String::new()
        };
        let execution_line = if self.execution.is_declared() {
            let description = self
                .execution
                .description
                .as_deref()
                .map(|description| format!(" ({description})"))
                .unwrap_or_default();
            format!(
                "execution       : {}{description}\n                  {}\n",
                self.execution.profile.as_str(),
                self.execution.profile.scope_statement(),
            )
        } else {
            String::new()
        };
        let resolved = self.resolve_provider().ok();
        let provider_line = match &resolved {
            Some(resolved) => {
                let preset = resolved
                    .preset
                    .map(|preset| preset.name.to_string())
                    .unwrap_or_else(|| "(default)".to_string());
                let model = resolved
                    .model
                    .clone()
                    .unwrap_or_else(|| "unset".to_string());
                let prices = match resolved.input_usd_per_mtok {
                    Some(input) => format!(
                        "{input:.2}/{:.2} USD per MTok",
                        resolved.output_usd_per_mtok.unwrap_or(f64::NAN)
                    ),
                    None => "unset: fail closed".to_string(),
                };
                let price_source = match resolved.price_source {
                    crate::registry::PriceSource::Explicit => "explicit".to_string(),
                    crate::registry::PriceSource::Registry(as_of) => {
                        format!("registry as of {as_of}; verify before relying")
                    }
                    crate::registry::PriceSource::Absent => "no price".to_string(),
                };
                let capabilities = match resolved.capabilities {
                    Some(caps) => format!(
                        "context {}, max out {}, tools {}",
                        caps.context_window_tokens, caps.max_output_tokens, caps.supports_tools
                    ),
                    None => "unknown (not in registry)".to_string(),
                };
                format!(
                    "provider       : {preset} / {model}\nendpoint       : {} ({})\nprices         : {prices} ({price_source})\ncapabilities   : {capabilities}\n",
                    resolved.base_url,
                    resolved.base_url_source.as_str()
                )
            }
            None => "provider       : <unresolvable>\n".to_string(),
        };
        let memory_line = if self.memory.enabled {
            "memory         : enabled — proposals queue under .pangu/memory; accept/reject via `pangu memory`\n"
                .to_string()
        } else {
            String::new()
        };
        let delegation_line = if self.boundary.allow_delegation {
            "delegation     : enabled - the model may delegate bounded subtasks; a sub-agent's \
                  budget is clamped to the parent's remaining budget and its contract is \
                  derived from the parent's (never wider)\n"
                .to_string()
        } else {
            String::new()
        };
        let eval_line = if self.eval.is_declared() {
            format!(
                "eval           : profile `{}` — issue `{}`; records under .pangu/eval; scores never replace acceptance\n",
                self.eval.profile, self.eval.issue_path
            )
        } else {
            String::new()
        };
        let skills_line = if self.skills.enabled {
            let key = if self.skills.verify_key.trim().is_empty() {
                "no pinned key (unsigned/signed-unverified only)"
            } else {
                "verify_key pinned"
            };
            format!("skills         : enabled — registry under .pangu/skills; {key}\n")
        } else {
            String::new()
        };
        format!(
            "boundary digest : {}\nworkspace      : {}\nwritable roots : {:?}\nforbidden globs: {}\nbudget         : {} turns / {} in / {} out tokens / ${:.2} / {}s\napproval       : {} (timeout {}s)\negress         : {} (localhost {})\nchild env      : allow-list of {}\n{plan_line}{provider_line}{execution_line}{memory_line}{skills_line}{eval_line}{delegation_line}\nrules:\n{}\n",
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
    pub checkpoint_enabled: Option<bool>,
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
        if let Some(enabled) = overrides.checkpoint_enabled {
            self.checkpoint.enabled = enabled;
        }
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    /// The platform temporary directory can sit behind a symlink or junction on
    /// CI runners, and the runtime refuses such paths for artifact roots and
    /// journals. Resolve it once so fixtures satisfy that policy.
    fn test_temp_root() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        std::fs::canonicalize(&base).unwrap_or(base)
    }

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
        let root = test_temp_root().join(format!(
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
    fn disabled_checkpoint_is_inert_and_keeps_legacy_digest() {
        let base = Config::embedded().unwrap();
        let mut changed = base.clone();
        changed.checkpoint.enabled = false;
        changed.checkpoint.artifact_root = std::path::PathBuf::from("not-present");
        changed.checkpoint.max_snapshot_bytes = 1;
        changed.checkpoint.max_snapshot_file_bytes = 1;
        assert_eq!(base.boundary_digest(), changed.boundary_digest());
        changed.validate().unwrap();
        changed.checkpoint.rollback_requires_approval = false;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn enabled_checkpoint_is_bound_to_an_effective_absolute_root() {
        let root = test_temp_root().join(format!(
            "pangu-checkpoint-config-{}-{}",
            std::process::id(),
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
        config.checkpoint.enabled = true;
        // Absolute user paths are accepted even when Windows canonicalization
        // returns an extended-length spelling for the workspace.
        config.checkpoint.artifact_root = root.join("artifacts");
        let contract =
            crate::goal::GoalContract::from_config("checkpoint contract", &config).unwrap();
        assert!(contract.checkpoint.artifact_root.is_absolute());
        let canonical_root = std::fs::canonicalize(&root).unwrap();
        assert!(contract
            .checkpoint
            .artifact_root
            .starts_with(&canonical_root));
        assert_ne!(
            contract.digest(),
            crate::goal::GoalContract::from_config("legacy", &Config::embedded().unwrap())
                .unwrap()
                .digest()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn old_config_without_checkpoint_section_loads_with_defaults() {
        let base = Config::embedded().unwrap();
        let mut value = toml::Value::try_from(&base).unwrap();
        value.as_table_mut().unwrap().remove("checkpoint");
        let loaded = Config::from_toml(&toml::to_string(&value).unwrap()).unwrap();
        assert!(!loaded.checkpoint.enabled);
        assert_eq!(loaded.checkpoint.backend, CheckpointBackend::Artifact);
        assert!(loaded.checkpoint.rollback_requires_approval);
    }

    /// A config written before conversation persistence existed has no
    /// `[conversation]` section. It must still load, and it must load *off*: a
    /// missing section cannot mean "start writing files", because that would
    /// change what an existing deployment does the first time it upgrades.
    #[test]
    fn old_config_without_conversation_section_loads_with_defaults() {
        let base = Config::embedded().unwrap();
        let mut value = toml::Value::try_from(&base).unwrap();
        value.as_table_mut().unwrap().remove("conversation");
        let loaded = Config::from_toml(&toml::to_string(&value).unwrap()).unwrap();
        assert!(
            !loaded.conversation.enabled,
            "an absent section must not turn conversation persistence on"
        );
        assert!(loaded.conversation.save_every_turn);
        assert!(loaded.conversation.artifact_root.is_relative());
    }

    /// F3: an old config has no `[verify]` section; it must load with the
    /// tool absent.
    #[test]
    fn old_config_without_verify_section_loads_with_defaults() {
        let base = Config::embedded().unwrap();
        let mut value = toml::Value::try_from(&base).unwrap();
        value.as_table_mut().unwrap().remove("verify");
        let loaded = Config::from_toml(&toml::to_string(&value).unwrap()).unwrap();
        assert!(
            loaded.verify.command.is_empty(),
            "an absent section must not configure a verify command"
        );
    }

    fn config_with_verify(
        extras: Vec<String>,
        command: Vec<String>,
    ) -> std::result::Result<Config, Error> {
        let base = Config::embedded().unwrap();
        let mut value = toml::Value::try_from(&base).unwrap();
        {
            let table = value.as_table_mut().unwrap();
            let boundary = table.get_mut("boundary").unwrap().as_table_mut().unwrap();
            boundary.insert(
                "extra_readonly_commands".into(),
                toml::Value::Array(
                    extras
                        .into_iter()
                        .map(toml::Value::String)
                        .collect::<Vec<_>>(),
                ),
            );
            table.insert(
                "verify".into(),
                toml::Value::Table(
                    [(
                        "command".into(),
                        toml::Value::Array(
                            command
                                .into_iter()
                                .map(toml::Value::String)
                                .collect::<Vec<_>>(),
                        ),
                    )]
                    .into_iter()
                    .collect(),
                ),
            );
        }
        let config = Config::from_toml(&toml::to_string(&value).unwrap())?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn extra_readonly_commands_must_be_bare_program_names() {
        for bad in ["a/b", "a\\b", "..", "-x"] {
            let error = config_with_verify(vec![bad.to_string()], Vec::new())
                .expect_err("must reject non-bare extra command");
            assert!(
                error.to_string().contains("bare program names"),
                "unexpected error for {bad}: {error}"
            );
        }
        config_with_verify(vec!["cargo".into()], Vec::new()).expect("bare name is accepted");
    }

    #[test]
    fn verify_command_must_use_allowlisted_programs() {
        let error = config_with_verify(Vec::new(), vec!["python".into(), "-c".into()])
            .expect_err("undeclared program must fail at config time");
        assert!(
            error.to_string().contains("allow-list"),
            "unexpected error: {error}"
        );
        config_with_verify(
            vec!["cargo".into()],
            vec!["cargo".into(), "test".into(), "-q".into()],
        )
        .expect("declared program with a safe flag passes");
    }

    #[test]
    fn verify_command_flags_follow_run_command_rules() {
        let error = config_with_verify(
            vec!["cargo".into()],
            vec!["cargo".into(), "test".into(), "--quiet".into()],
        )
        .expect_err("flags outside the safe list must fail at config time");
        assert!(
            error.to_string().contains("not allowed"),
            "unexpected error: {error}"
        );
        let error = config_with_verify(Vec::new(), vec!["cat".into(), "/etc/passwd".into()])
            .expect_err("absolute path arguments must fail");
        assert!(
            error.to_string().contains("not allowed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unconfigured_verify_does_not_change_boundary_digest() {
        let base = Config::embedded().unwrap();
        let mut stripped = toml::Value::try_from(&base).unwrap();
        stripped.as_table_mut().unwrap().remove("verify");
        let kept = Config::from_toml(&toml::to_string(&base).unwrap()).unwrap();
        let stripped = Config::from_toml(&toml::to_string(&stripped).unwrap()).unwrap();
        assert_eq!(
            kept.boundary_digest(),
            stripped.boundary_digest(),
            "an empty verify section must not change the digest of an existing deployment"
        );
        let configured = config_with_verify(
            vec!["cargo".into()],
            vec!["cargo".into(), "test".into(), "-q".into()],
        )
        .unwrap();
        assert_ne!(configured.boundary_digest(), kept.boundary_digest());
    }

    /// F3 binding: a contract built with an extended allow-list must refuse a
    /// Sandbox that does not carry the same extension, exactly like any other
    /// effective-boundary field.
    #[test]
    fn contract_refuses_sandbox_with_different_extra_readonly_commands() {
        use crate::goal::GoalContract;

        let with_extras = config_with_verify(
            vec!["cargo".into()],
            vec!["cargo".into(), "test".into(), "-q".into()],
        )
        .unwrap();
        let without = Config::embedded().unwrap();
        let contract = GoalContract::from_config("binding test", &with_extras).unwrap();
        let sandbox = Sandbox::from_config(&without.boundary).unwrap();
        assert!(contract.validate_against(&sandbox).is_err());
        let matching = Sandbox::from_config(&with_extras.boundary).unwrap();
        contract
            .validate_against(&matching)
            .expect("same-config contract and sandbox agree");
    }

    /// B4: naming a provider in config fills the endpoint, the key variable,
    /// and the registry price for a known model; the contract inherits it.
    #[test]
    fn provider_resolution_fills_endpoint_and_prices() {
        use crate::goal::GoalContract;
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("openai".into());
        config.model.model = Some("gpt-4o-mini".into());
        config.budget.max_input_tokens = 100_000; // below the 128k context window
        config.validate().expect("valid");
        let resolved = config.resolve_provider().unwrap();
        assert_eq!(resolved.base_url, "https://api.openai.com/v1");
        assert_eq!(resolved.api_key_env.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(resolved.input_usd_per_mtok, Some(0.15));
        let contract = GoalContract::from_config("b4", &config).unwrap();
        let price = contract.price.expect("registry price reaches the contract");
        assert_eq!(price.input_usd_per_mtok, 0.15);
        assert_eq!(price.output_usd_per_mtok, 0.60);
    }

    #[test]
    fn context_window_smaller_than_input_budget_fails() {
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("openai".into());
        config.model.model = Some("gpt-4o".into()); // 128k context
                                                    // Embedded budget is 200k input tokens: impossible for this model.
        let error = config
            .validate()
            .expect_err("budget exceeds context window");
        assert!(error.to_string().contains("context window"), "{error}");
    }

    #[test]
    fn max_output_tokens_above_capability_fails() {
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("openai".into());
        config.model.model = Some("gpt-4o".into());
        config.model.max_output_tokens = Some(999_999);
        config.budget.max_input_tokens = 100_000;
        config.budget.max_output_tokens = 1_000_000; // avoid the budget-vs-request-cap check first
        let error = config
            .validate()
            .expect_err("request cap exceeds model output limit");
        assert!(error.to_string().contains("output limit"), "{error}");
    }

    #[test]
    fn unknown_provider_fails_with_known_names() {
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("nope".into());
        let error = config.validate().expect_err("unknown provider");
        assert!(error.to_string().contains("known providers"), "{error}");
    }

    /// C5: the default local profile is undeclared; removing the section (or
    /// never having had one) must not change the digest of an existing
    /// deployment. Declaring a backend does.
    #[test]
    fn execution_declaration_changes_digest_only_when_declared() {
        let base = Config::embedded().unwrap();
        let mut stripped = toml::Value::try_from(&base).unwrap();
        stripped.as_table_mut().unwrap().remove("execution");
        let kept = Config::from_toml(&toml::to_string(&base).unwrap()).unwrap();
        let stripped = Config::from_toml(&toml::to_string(&stripped).unwrap()).unwrap();
        assert_eq!(
            kept.boundary_digest(),
            stripped.boundary_digest(),
            "an undeclared execution section must not change the digest"
        );
        let mut declared = Config::embedded().unwrap();
        declared.execution.profile = crate::execution::ExecutionProfile::Container;
        declared.execution.description = Some("docker:ubuntu-24.04".into());
        declared.validate().unwrap();
        assert_ne!(declared.boundary_digest(), kept.boundary_digest());
    }

    #[test]
    fn execution_description_is_validated_at_config_time() {
        let mut config = Config::embedded().unwrap();
        config.execution.profile = crate::execution::ExecutionProfile::Remote;
        config.execution.description = Some(
            "bad
control"
                .into(),
        );
        let error = config.validate().expect_err("control characters refused");
        assert!(
            error.to_string().contains("execution.description"),
            "{error}"
        );
    }

    /// B5 helper: a config whose primary is a known registry model with a
    /// budget that fits, plus the given fallback candidates.
    fn config_with_fallback(
        candidates: Vec<FallbackCandidate>,
    ) -> std::result::Result<Config, Error> {
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("openai".into());
        config.model.model = Some("gpt-4o-mini".into());
        config.budget.max_input_tokens = 60_000; // fits every candidate window
        config.model.fallback = candidates;
        config.validate()?;
        Ok(config)
    }

    fn candidate(provider: &str, model: &str) -> FallbackCandidate {
        FallbackCandidate {
            provider: Some(provider.into()),
            model: Some(model.into()),
            ..FallbackCandidate::default()
        }
    }

    #[test]
    fn fallback_chain_validates_and_resolves() {
        let config = config_with_fallback(vec![
            candidate("openai", "gpt-4.1-mini"),
            candidate("deepseek", "deepseek-chat"),
        ])
        .unwrap();
        let resolved = config.resolve_fallbacks().unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].model, "gpt-4.1-mini");
        assert_eq!(resolved[0].input_usd_per_mtok, 0.40);
        assert_eq!(resolved[1].model, "deepseek-chat");
        assert_eq!(resolved[1].base_url, "https://api.deepseek.com/v1");
    }

    #[test]
    fn fallback_candidates_fail_closed() {
        // Unknown provider.
        let error =
            config_with_fallback(vec![candidate("nope", "x")]).expect_err("unknown provider");
        assert!(error.to_string().contains("known providers"), "{error}");
        // Missing model.
        let error =
            config_with_fallback(vec![FallbackCandidate::default()]).expect_err("model required");
        assert!(error.to_string().contains("model is required"), "{error}");
        // Model outside the registry: capabilities cannot be proven.
        let error = config_with_fallback(vec![candidate("openai", "gpt-9x-future")])
            .expect_err("registry-declared capabilities required");
        assert!(error.to_string().contains("not in the registry"), "{error}");
        // Tool-less model.
        let error = config_with_fallback(vec![candidate("deepseek", "deepseek-reasoner")])
            .expect_err("tool-less fallback");
        assert!(
            error.to_string().contains("does not support tool calling"),
            "{error}"
        );
        // Context window smaller than the input budget (100k vs 64k).
        let mut config = Config::embedded().unwrap();
        config.model.provider = Some("openai".into());
        config.model.model = Some("gpt-4o-mini".into());
        config.budget.max_input_tokens = 100_000;
        config.model.fallback = vec![candidate("deepseek", "deepseek-chat")];
        let error = config.validate().expect_err("context window too small");
        assert!(error.to_string().contains("context window"), "{error}");
        // Duplicate of the primary.
        let error = config_with_fallback(vec![candidate("openai", "gpt-4o-mini")])
            .expect_err("duplicate of primary");
        assert!(error.to_string().contains("duplicates"), "{error}");
        // Duplicate between candidates.
        let error = config_with_fallback(vec![
            candidate("openai", "gpt-4.1-mini"),
            candidate("openai", "gpt-4.1-mini"),
        ])
        .expect_err("duplicate candidate");
        assert!(error.to_string().contains("duplicates"), "{error}");
    }

    #[test]
    fn fallback_requires_primary_prices() {
        // Embedded config has no model and no prices: the primary price is
        // unresolvable, so declaring a fallback must fail at config time.
        let mut config = Config::embedded().unwrap();
        config.model.fallback = vec![candidate("openai", "gpt-4.1-mini")];
        let error = config.validate().expect_err("unpriceable primary");
        assert!(
            error
                .to_string()
                .contains("requires the primary model to have resolvable prices"),
            "{error}"
        );
    }

    #[test]
    fn contract_carries_the_fallback_chain() {
        use crate::goal::GoalContract;
        let declared = config_with_fallback(vec![candidate("openai", "gpt-4.1-mini")]).unwrap();
        let contract = GoalContract::from_config("b5", &declared).unwrap();
        assert_eq!(contract.fallbacks.len(), 1);
        assert_eq!(contract.fallbacks[0].model, "gpt-4.1-mini");
        assert_eq!(contract.fallbacks[0].input_usd_per_mtok, 0.40);
        // The digest carries the chain.
        let single = config_with_fallback(vec![]).unwrap();
        let single = GoalContract::from_config("b5", &single).unwrap();
        assert_ne!(contract.digest(), single.digest());
    }

    #[test]
    fn contract_carries_the_execution_declaration() {
        use crate::goal::GoalContract;
        let mut config = Config::embedded().unwrap();
        config.execution.profile = crate::execution::ExecutionProfile::Container;
        config.execution.description = Some("docker:ubuntu-24.04".into());
        let contract = GoalContract::from_config("c5", &config).unwrap();
        assert_eq!(
            contract.execution().profile,
            crate::execution::ExecutionProfile::Container
        );
        // The contract digest carries the declaration.
        let mut undeclared_config = config.clone();
        undeclared_config.execution = crate::execution::ExecutionSection::default();
        let undeclared = GoalContract::from_config("c5", &undeclared_config).unwrap();
        assert_ne!(contract.digest(), undeclared.digest());
    }

    #[test]
    fn unnamed_provider_keeps_legacy_resolution() {
        let config = Config::embedded().unwrap();
        let resolved = config.resolve_provider().unwrap();
        assert!(resolved.preset.is_none());
        assert_eq!(resolved.base_url, "https://api.openai.com/v1");
        assert_eq!(resolved.price_source, crate::registry::PriceSource::Absent);
        assert!(resolved.capabilities.is_none());
    }

    #[test]
    fn contract_and_sandbox_preserve_configured_root_order() {
        let root = test_temp_root().join(format!(
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

    /// A workspace with checkpointing on, for exercising `exclude_roots`.
    fn checkpoint_config(label: &str) -> (std::path::PathBuf, Config) {
        let root = test_temp_root().join(format!(
            "pangu-exclude-{label}-{}-{}",
            std::process::id(),
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
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = std::path::PathBuf::from(".pangu/checkpoints");
        (root, config)
    }

    /// Excluding the artifact root is redundant, not harmful — it is already
    /// excluded — so rejecting it is about not letting a config read as if the
    /// store were at risk when it is not. Worth a test because the reason is
    /// not obvious from the rule.
    #[test]
    fn exclude_roots_rejects_the_artifact_root() {
        let (root, mut config) = checkpoint_config("artifact-root");
        config.checkpoint.exclude_roots = vec![std::path::PathBuf::from(".pangu/checkpoints")];
        let error = config.validate().expect_err("excluding the artifact root");
        assert!(
            error.to_string().contains("must not be the artifact root"),
            "unexpected error: {error}"
        );
        std::fs::remove_dir_all(root).ok();
    }

    /// A symlinked exclusion is the same class of trick as a symlinked
    /// artifact root: the path the operator wrote and the path the snapshot
    /// walks are not the same directory, so the exclusion can be made to mean
    /// something other than it says.
    #[cfg(unix)]
    #[test]
    fn exclude_roots_rejects_a_symlinked_directory() {
        use std::os::unix::fs::symlink;
        let (root, mut config) = checkpoint_config("symlink");
        let real = root.join("real-output");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, root.join("linked-output")).unwrap();
        config.checkpoint.exclude_roots = vec![std::path::PathBuf::from("linked-output")];
        let error = config.validate().expect_err("excluding through a symlink");
        assert!(
            error.to_string().contains("symlink components"),
            "unexpected error: {error}"
        );
        std::fs::remove_dir_all(root).ok();
    }

    /// The exclusions are part of what a snapshot *is*, so they belong in the
    /// contract digest alongside the roots and the limits. Two runs whose
    /// snapshots differ must not share a digest, or a verified action could be
    /// attributed to a contract that would have produced a different artifact.
    #[test]
    fn exclude_roots_change_the_contract_digest() {
        let (root, mut config) = checkpoint_config("digest");
        let base = crate::goal::GoalContract::from_config("without exclusions", &config).unwrap();
        config.checkpoint.exclude_roots = vec![std::path::PathBuf::from("build-output")];
        let excluded = crate::goal::GoalContract::from_config("with exclusions", &config).unwrap();
        assert_ne!(base.digest(), excluded.digest());
        // And the paths must be effective, not the raw config spelling, or the
        // same directory written two ways would produce two digests.
        assert!(excluded.checkpoint.exclude_roots[0].is_absolute());
        std::fs::remove_dir_all(root).ok();
    }

    /// B3: memory enabled changes the digest; the default (disabled) keeps
    /// historical digests. The frozen bounds ride with the contract.
    #[test]
    fn memory_section_freezes_into_the_contract_and_digest() {
        let base = crate::Config::embedded().unwrap();
        let disabled = crate::goal::GoalContract::from_config("b3 off", &base).unwrap();
        assert!(!disabled.memory().enabled);
        assert!(!base.explain().contains("memory: enabled"));

        let mut enabled_config = base.clone();
        enabled_config.memory.enabled = true;
        enabled_config.memory.max_pending = 7;
        let enabled = crate::goal::GoalContract::from_config("b3 on", &enabled_config).unwrap();
        assert!(enabled.memory().enabled);
        assert_eq!(enabled.memory().max_pending, 7);
        assert_ne!(disabled.digest(), enabled.digest());
    }

    /// F5: a declared eval profile freezes into the contract and changes the
    /// digest; half-declared profiles fail at config time.
    #[test]
    fn eval_profile_freezes_into_the_contract_and_digest() {
        let base = crate::Config::embedded().unwrap();
        assert!(!base.eval.is_declared());
        let plain = crate::goal::GoalContract::from_config("no eval", &base).unwrap();
        assert!(!plain.eval().is_declared());

        let mut declared = base.clone();
        declared.eval.profile = "issue-fix".into();
        declared.eval.issue_path = "issues/001.md".into();
        declared.validate().expect("valid eval declaration");
        let with_eval = crate::goal::GoalContract::from_config("with eval", &declared).unwrap();
        assert_eq!(with_eval.eval().profile, "issue-fix");
        assert_ne!(plain.digest(), with_eval.digest());

        // Half-declared: issue path without a profile name.
        let mut stray = base.clone();
        stray.eval.issue_path = "issues/001.md".into();
        let error = stray.validate().expect_err("stray issue path");
        assert!(error.to_string().contains("half-declared"), "{error}");

        // Missing issue path with a declared profile.
        let mut no_issue = base.clone();
        no_issue.eval.profile = "issue-fix".into();
        let error = no_issue.validate().expect_err("missing issue path");
        assert!(
            error.to_string().contains("issue_path must be set"),
            "{error}"
        );

        // Unsafe issue path.
        let mut escape = base.clone();
        escape.eval.profile = "issue-fix".into();
        escape.eval.issue_path = ".pangu/issue.md".into();
        let error = escape.validate().expect_err(".pangu issue path");
        assert!(error.to_string().contains("eval.issue_path"), "{error}");
    }

    /// D3/D4: declared deliverables change the digest; bad declarations
    /// fail at config time.
    #[test]
    fn deliverables_freeze_into_the_contract_and_digest() {
        let base = crate::Config::embedded().unwrap();
        let plain = crate::goal::GoalContract::from_config("no deliverables", &base).unwrap();
        assert!(plain.deliverables().deliverables.is_empty());

        let mut declared = base.clone();
        declared.goal.deliverable = vec![pangu_core::DeliverableSpec {
            name: "report".into(),
            path: "out/report.md".into(),
            kind: "report".into(),
            acceptor: pangu_core::Acceptor::Manual,
            min_bytes: 1,
        }];
        declared.validate().expect("valid declaration");
        let with_deliverable =
            crate::goal::GoalContract::from_config("with deliverable", &declared).unwrap();
        assert_eq!(with_deliverable.deliverables().deliverables.len(), 1);
        assert_ne!(plain.digest(), with_deliverable.digest());

        // Duplicate names and unsafe paths fail at config time.
        declared.goal.deliverable.push(pangu_core::DeliverableSpec {
            name: "report".into(),
            path: "out/other.md".into(),
            kind: "report".into(),
            acceptor: pangu_core::Acceptor::Manual,
            min_bytes: 1,
        });
        let error = declared.validate().expect_err("duplicate name");
        assert!(error.to_string().contains("twice"), "{error}");

        declared.goal.deliverable[1].name = "other".into();
        declared.goal.deliverable[1].path = "../escape.md".into();
        let error = declared.validate().expect_err("path escape");
        assert!(
            error.to_string().contains("safe workspace-relative"),
            "{error}"
        );

        declared.goal.deliverable[1].path = ".pangu/x.md".into();
        let error = declared.validate().expect_err(".pangu path");
        assert!(error.to_string().contains(".pangu"), "{error}");
    }

    /// B2: skills enabled changes the digest and freezes the loaded set.
    #[test]
    fn skills_freeze_into_the_contract_and_digest() {
        let base = crate::Config::embedded().unwrap();
        let disabled = crate::goal::GoalContract::from_config("b2 off", &base).unwrap();
        assert!(!disabled.skills().enabled);

        let mut enabled_config = base.clone();
        enabled_config.skills.enabled = true;
        let enabled = crate::goal::GoalContract::from_config("b2 on", &enabled_config).unwrap();
        assert!(enabled.skills().enabled);
        assert!(enabled.skills().skills.is_empty()); // nothing installed here
        assert_ne!(disabled.digest(), enabled.digest());

        // A malformed pinned key fails at config time.
        enabled_config.skills.verify_key = "not-hex".into();
        let error = enabled_config.validate().expect_err("bad verify_key");
        assert!(error.to_string().contains("verify_key"), "{error}");
    }

    /// B3: the memory bounds must themselves be sane when the queue is on.
    #[test]
    fn memory_limits_fail_closed_when_enabled() {
        let mut config = crate::Config::embedded().unwrap();
        config.memory.enabled = true;
        config.memory.max_pending = 0;
        let error = config.validate().expect_err("max_pending must be >= 1");
        assert!(error.to_string().contains("max_pending"), "{error}");

        config.memory.max_pending = 256;
        config.memory.max_content_bytes = 8;
        let error = config
            .validate()
            .expect_err("max_content_bytes must be >= 64");
        assert!(error.to_string().contains("max_content_bytes"), "{error}");

        // Disabled runs do not care about the limits.
        let mut disabled = crate::Config::embedded().unwrap();
        disabled.memory.max_pending = 0;
        disabled
            .validate()
            .expect("disabled queue skips limit checks");
    }

    /// D1: the delegation flag freezes into the contract (digest only when
    /// enabled) and derive_sub_contract produces a strictly-narrowed child.
    #[test]
    fn delegation_freezes_into_the_contract_and_derives_narrower_children() {
        let base = crate::Config::embedded().unwrap();
        let plain = crate::goal::GoalContract::from_config("d1 off", &base).unwrap();
        assert!(!plain.allows_delegation());

        let mut enabled_config = base.clone();
        enabled_config.boundary.allow_delegation = true;
        let enabled = crate::goal::GoalContract::from_config("d1 on", &enabled_config).unwrap();
        assert!(enabled.allows_delegation());
        assert_ne!(plain.digest(), enabled.digest());

        // A derived child copies every enforcement field from the parent and
        // strips the run-scoped features: a sub-agent is a bounded worker.
        let parent_budget = enabled.budget().clone();
        let child = enabled
            .derive_sub_contract("fix the parser", parent_budget.clone())
            .unwrap();
        assert!(child.goal.starts_with("[delegated subtask]"));
        assert_eq!(child.workspace(), enabled.workspace());
        assert_eq!(child.readable_roots, enabled.readable_roots);
        assert_eq!(child.writable_roots, enabled.writable_roots);
        assert_eq!(child.forbidden_globs, enabled.forbidden_globs);
        assert_eq!(child.approval_mode, enabled.approval_mode);
        assert_eq!(child.budget(), &parent_budget);
        assert_eq!(child.price, enabled.price);
        assert_eq!(child.policy_digest, enabled.policy_digest);
        assert_eq!(child.fallbacks, enabled.fallbacks);
        assert!(
            !child.allows_delegation(),
            "depth-1 delegation by construction"
        );
        assert!(!child.memory().enabled);
        assert!(!child.skills().enabled);
        assert!(child.deliverables().deliverables.is_empty());
        assert!(!child.eval().is_declared());
        assert!(!child.plan_first());
        assert!(!child.checkpoint.enabled);
        assert!(!child.conversation.enabled);

        // Widening any budget dimension beyond the parent's is refused —
        // the caller clamps, the constructor is defense in depth.
        let mut wider = parent_budget.clone();
        wider.max_turns += 1;
        assert!(enabled.derive_sub_contract("t", wider).is_err());
        let mut wider = parent_budget.clone();
        wider.max_cost_usd += 0.01;
        assert!(enabled.derive_sub_contract("t", wider).is_err());
        let mut wider = parent_budget.clone();
        wider.max_input_tokens += 1;
        assert!(enabled.derive_sub_contract("t", wider).is_err());
        let mut wider = parent_budget.clone();
        wider.max_output_tokens += 1;
        assert!(enabled.derive_sub_contract("t", wider).is_err());
        let mut wider = parent_budget.clone();
        wider.max_wall_clock_secs += std::time::Duration::from_secs(1);
        assert!(enabled.derive_sub_contract("t", wider).is_err());

        // A narrowed budget derives cleanly.
        let mut narrower = parent_budget.clone();
        narrower.max_turns = (parent_budget.max_turns / 2).max(1);
        narrower.max_cost_usd = parent_budget.max_cost_usd / 2.0;
        narrower.max_wall_clock_secs = parent_budget.max_wall_clock_secs / 2;
        assert!(enabled.derive_sub_contract("t", narrower).is_ok());
    }
}
