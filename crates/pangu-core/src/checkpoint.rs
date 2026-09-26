//! Versioned data contracts for the checkpoint/rollback proposal.
//!
//! This module deliberately contains no filesystem mutation or Agent state
//! machine. It provides bounded, serializable records that a later runtime
//! can validate before committing or restoring anything.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{now_rfc3339, Error, Result};

pub const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const SESSION_SCHEMA_VERSION: u32 = 1;
pub const FAILED_PATH_SCHEMA_VERSION: u32 = 1;
pub const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_SNAPSHOT_FILES: usize = 100_000;
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;

const MAX_ID_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_FILE_ENTRIES: usize = 100_000;
const MAX_EXTERNAL_EFFECTS: usize = 1_024;
const MAX_ROLLBACK_IDS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRef {
    pub event_id: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
}

impl EventRef {
    pub fn new(event_id: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            event_id: event_id.into(),
            run_id: run_id.into(),
            journal_id: None,
            seq: None,
            sha: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_id("event_id", &self.event_id)?;
        validate_id("run_id", &self.run_id)?;
        if let Some(journal_id) = &self.journal_id {
            validate_id("journal_id", journal_id)?;
        }
        if let Some(sha) = &self.sha {
            validate_digest("event_ref.sha", sha)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointFileType {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointFileEntry {
    /// A normalized workspace-relative path. Absolute paths and parent
    /// traversal are never valid snapshot entries.
    pub path: String,
    pub file_type: CheckpointFileType,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u32>,
    pub content_sha256: String,
    pub blob_ref: String,
}

impl CheckpointFileEntry {
    pub fn file(
        path: impl Into<String>,
        size: u64,
        content_sha256: impl Into<String>,
        blob_ref: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            file_type: CheckpointFileType::File,
            size,
            permissions: None,
            content_sha256: content_sha256.into(),
            blob_ref: blob_ref.into(),
        }
    }

    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            file_type: CheckpointFileType::Directory,
            size: 0,
            permissions: None,
            content_sha256: crate::hex_sha256(""),
            blob_ref: String::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_relative_path("checkpoint.file_entry.path", &self.path)?;
        validate_digest("checkpoint.file_entry.content_sha256", &self.content_sha256)?;
        if self.permissions.is_some_and(|mode| mode > 0o7777) {
            return Err(Error::Config(
                "checkpoint file permissions exceed the supported mode bits".into(),
            ));
        }
        match self.file_type {
            CheckpointFileType::File => {
                if self.blob_ref.trim().is_empty() || self.blob_ref.len() > MAX_ID_BYTES {
                    return Err(Error::Config(
                        "checkpoint file entry requires a bounded blob_ref".into(),
                    ));
                }
            }
            CheckpointFileType::Directory => {
                if self.size != 0
                    || !self.blob_ref.is_empty()
                    || self.content_sha256 != crate::hex_sha256("")
                {
                    return Err(Error::Config(
                        "checkpoint directory entry must not carry file data".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectSummary {
    pub effect_scope: String,
    pub reversibility: String,
    #[serde(default)]
    pub external_mutation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventRef>,
}

impl ExternalEffectSummary {
    pub fn validate(&self) -> Result<()> {
        validate_text("external_effect.effect_scope", &self.effect_scope, 128)?;
        validate_text("external_effect.reversibility", &self.reversibility, 128)?;
        if !matches!(
            self.effect_scope.as_str(),
            "workspace" | "session" | "process_read" | "external_read" | "external_mutation"
        ) || !matches!(
            self.reversibility.as_str(),
            "no_effect" | "reversible" | "irreversible"
        ) {
            return Err(Error::Config(
                "external_effect contains an unknown scope or reversibility".into(),
            ));
        }
        if self.external_mutation
            && (self.effect_scope != "external_mutation" || self.reversibility != "irreversible")
        {
            return Err(Error::Config(
                "external_mutation summary must be irreversible external_mutation".into(),
            ));
        }
        if self.effect_scope == "external_mutation" && !self.external_mutation {
            return Err(Error::Config(
                "external_mutation scope must set external_mutation=true".into(),
            ));
        }
        if let Some(event_ref) = &self.event_ref {
            event_ref.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointArtifact {
    pub schema_version: u32,
    pub checkpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint_id: Option<String>,
    pub run_id: String,
    pub session_id: String,
    pub session_node_id: String,
    pub event_ref: EventRef,
    pub workspace: PathBuf,
    pub contract_digest: String,
    pub policy_digest: String,
    pub snapshot_digest: String,
    /// Digest of the complete post-action workspace state. Runtime-created
    /// checkpoints require it for compare-and-swap rollback; older stage-one
    /// records may omit it and remain readable but cannot be restored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_digest: Option<String>,
    pub file_entries: Vec<CheckpointFileEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_path_ledger_ref: Option<String>,
    #[serde(default)]
    pub external_effect_summary: Vec<ExternalEffectSummary>,
    pub created_at: String,
    pub state: ArtifactState,
}

impl CheckpointArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: impl Into<String>,
        run_id: impl Into<String>,
        session_id: impl Into<String>,
        session_node_id: impl Into<String>,
        event_ref: EventRef,
        workspace: PathBuf,
        contract_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        snapshot_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            checkpoint_id: checkpoint_id.into(),
            parent_checkpoint_id: None,
            run_id: run_id.into(),
            session_id: session_id.into(),
            session_node_id: session_node_id.into(),
            event_ref,
            workspace,
            contract_digest: contract_digest.into(),
            policy_digest: policy_digest.into(),
            snapshot_digest: snapshot_digest.into(),
            workspace_digest: None,
            file_entries: Vec::new(),
            failed_path_ledger_ref: None,
            external_effect_summary: Vec::new(),
            created_at: now_rfc3339(),
            state: ArtifactState::Complete,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported checkpoint schema version {}",
                self.schema_version
            )));
        }
        validate_id("checkpoint_id", &self.checkpoint_id)?;
        validate_text("checkpoint.created_at", &self.created_at, 128)?;
        if let Some(parent) = &self.parent_checkpoint_id {
            validate_id("parent_checkpoint_id", parent)?;
            if parent == &self.checkpoint_id {
                return Err(Error::Config("checkpoint cannot be its own parent".into()));
            }
        }
        validate_id("run_id", &self.run_id)?;
        validate_id("session_id", &self.session_id)?;
        validate_id("session_node_id", &self.session_node_id)?;
        self.event_ref.validate()?;
        if self.event_ref.run_id != self.run_id {
            return Err(Error::Config(
                "checkpoint event reference must belong to the same run".into(),
            ));
        }
        if !self.workspace.is_absolute() {
            return Err(Error::Config(
                "checkpoint.workspace must be an absolute path".into(),
            ));
        }
        validate_digest("checkpoint.contract_digest", &self.contract_digest)?;
        validate_digest("checkpoint.policy_digest", &self.policy_digest)?;
        validate_digest("checkpoint.snapshot_digest", &self.snapshot_digest)?;
        if let Some(digest) = &self.workspace_digest {
            validate_digest("checkpoint.workspace_digest", digest)?;
        }
        if let Some(reference) = &self.failed_path_ledger_ref {
            validate_id("failed_path_ledger_ref", reference)?;
        }
        if self.file_entries.len() > MAX_FILE_ENTRIES {
            return Err(Error::Config(
                "checkpoint contains too many file entries".into(),
            ));
        }
        if self.external_effect_summary.len() > MAX_EXTERNAL_EFFECTS {
            return Err(Error::Config(
                "checkpoint contains too many external effects".into(),
            ));
        }
        let mut paths = HashSet::new();
        // Artifacts are portable operator evidence. Windows filesystems are
        // normally case-insensitive, so accepting `Dir/file` and
        // `dir/file` in one manifest would make the same path appear twice
        // only after publication. Reject that ambiguity on every platform
        // rather than relying on the host running the restore.
        let mut portable_paths = HashSet::new();
        let mut entry_types = HashMap::new();
        for entry in &self.file_entries {
            entry.validate()?;
            if !paths.insert(entry.path.as_str()) {
                return Err(Error::Config(format!(
                    "checkpoint contains duplicate file entry `{}`",
                    entry.path
                )));
            }
            let portable_path = entry.path.to_lowercase();
            if !portable_paths.insert(portable_path) {
                return Err(Error::Config(format!(
                    "checkpoint contains case-insensitive duplicate file entry `{}`",
                    entry.path
                )));
            }
            entry_types.insert(entry.path.as_str(), entry.file_type);
        }
        for entry in &self.file_entries {
            let mut ancestor = entry.path.as_str();
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                if entry_types.get(parent) == Some(&CheckpointFileType::File) {
                    return Err(Error::Config(format!(
                        "checkpoint file entry `{}` is below file entry `{parent}`",
                        entry.path
                    )));
                }
                ancestor = parent;
            }
        }
        for effect in &self.external_effect_summary {
            effect.validate()?;
            if effect.external_mutation && effect.event_ref.is_none() {
                return Err(Error::Config(
                    "external mutation summary requires an event reference".into(),
                ));
            }
            if effect
                .event_ref
                .as_ref()
                .is_some_and(|reference| reference.run_id != self.run_id)
            {
                return Err(Error::Config(
                    "external effect summary event must belong to the checkpoint run".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_limits(
        &self,
        max_snapshot_bytes: u64,
        max_snapshot_files: usize,
        max_snapshot_file_bytes: u64,
    ) -> Result<()> {
        if max_snapshot_bytes == 0 || max_snapshot_files == 0 || max_snapshot_file_bytes == 0 {
            return Err(Error::Config(
                "checkpoint snapshot limits must be > 0".into(),
            ));
        }
        if max_snapshot_bytes > MAX_SNAPSHOT_BYTES
            || max_snapshot_files > MAX_SNAPSHOT_FILES
            || max_snapshot_file_bytes > MAX_SNAPSHOT_FILE_BYTES
        {
            return Err(Error::Config(
                "checkpoint snapshot limits exceed the supported hard maximum".into(),
            ));
        }
        if max_snapshot_file_bytes > max_snapshot_bytes {
            return Err(Error::Config(
                "checkpoint per-file limit exceeds total limit".into(),
            ));
        }
        self.validate()?;
        if self.file_entries.len() > max_snapshot_files {
            return Err(Error::Config("checkpoint file count exceeds limit".into()));
        }
        let mut total = 0u64;
        for entry in &self.file_entries {
            if entry.file_type == CheckpointFileType::File && entry.size > max_snapshot_file_bytes {
                return Err(Error::Config(format!(
                    "checkpoint file `{}` exceeds per-file limit",
                    entry.path
                )));
            }
            total = total
                .checked_add(entry.size)
                .ok_or_else(|| Error::Config("checkpoint snapshot size overflowed".into()))?;
            if total > max_snapshot_bytes {
                return Err(Error::Config(
                    "checkpoint snapshot exceeds total byte limit".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.state == ArtifactState::Complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionNode {
    pub schema_version: u32,
    pub session_node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_node_id: Option<String>,
    pub event_ref: EventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default)]
    pub history_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_state_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_path_ledger_ref: Option<String>,
    #[serde(default)]
    pub applied_rollback_ids: Vec<String>,
}

impl SessionNode {
    pub fn new(
        session_node_id: impl Into<String>,
        event_ref: EventRef,
        checkpoint_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: SESSION_SCHEMA_VERSION,
            session_node_id: session_node_id.into(),
            parent_session_node_id: None,
            event_ref,
            checkpoint_id,
            history_digest: None,
            bounded_state_ref: None,
            failed_path_ledger_ref: None,
            applied_rollback_ids: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SESSION_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported session schema version {}",
                self.schema_version
            )));
        }
        validate_id("session_node_id", &self.session_node_id)?;
        if let Some(parent) = &self.parent_session_node_id {
            validate_id("parent_session_node_id", parent)?;
            if parent == &self.session_node_id {
                return Err(Error::Config(
                    "session node cannot be its own parent".into(),
                ));
            }
        }
        self.event_ref.validate()?;
        if let Some(checkpoint_id) = &self.checkpoint_id {
            validate_id("checkpoint_id", checkpoint_id)?;
        }
        if let Some(digest) = &self.history_digest {
            validate_digest("history_digest", digest)?;
        }
        if let Some(reference) = &self.bounded_state_ref {
            validate_id("bounded_state_ref", reference)?;
        }
        if let Some(reference) = &self.failed_path_ledger_ref {
            validate_id("failed_path_ledger_ref", reference)?;
        }
        if self.applied_rollback_ids.len() > MAX_ROLLBACK_IDS {
            return Err(Error::Config(
                "session node contains too many rollback ids".into(),
            ));
        }
        let mut seen = HashSet::new();
        for id in &self.applied_rollback_ids {
            validate_id("applied_rollback_id", id)?;
            if !seen.insert(id.as_str()) {
                return Err(Error::Config(format!(
                    "session node contains duplicate rollback id `{id}`"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    InvalidToolCall,
    PolicyDenied,
    SandboxDenied,
    ApprovalDenied,
    ToolFailed,
    IrreversibleExternalBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedPathStatus {
    Active,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedPathRecord {
    pub schema_version: u32,
    pub failure_id: String,
    pub failure_class: FailureClass,
    pub tool: String,
    pub canonical_args_digest: String,
    pub resource_digest: String,
    pub contract_digest: String,
    pub policy_digest: String,
    pub attempt_count: u32,
    pub first_seen_event_ref: EventRef,
    pub last_seen_event_ref: EventRef,
    pub run_id: String,
    pub status: FailedPathStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}

impl FailedPathRecord {
    pub fn mark_superseded(&mut self, replacement_id: impl Into<String>) -> Result<()> {
        let replacement_id = replacement_id.into();
        validate_id("superseded_by", &replacement_id)?;
        if self.status == FailedPathStatus::Superseded {
            return Err(Error::Config(
                "failed-path record is already superseded".into(),
            ));
        }
        if replacement_id == self.failure_id {
            return Err(Error::Config(
                "failed-path replacement must differ from the original record".into(),
            ));
        }
        self.status = FailedPathStatus::Superseded;
        self.superseded_by = Some(replacement_id);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != FAILED_PATH_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported failed-path schema version {}",
                self.schema_version
            )));
        }
        validate_id("failure_id", &self.failure_id)?;
        validate_text("failed_path.tool", &self.tool, 128)?;
        validate_digest("canonical_args_digest", &self.canonical_args_digest)?;
        validate_digest("resource_digest", &self.resource_digest)?;
        validate_digest("contract_digest", &self.contract_digest)?;
        validate_digest("policy_digest", &self.policy_digest)?;
        if self.attempt_count == 0 {
            return Err(Error::Config(
                "failed-path attempt_count must be > 0".into(),
            ));
        }
        self.first_seen_event_ref.validate()?;
        self.last_seen_event_ref.validate()?;
        validate_id("failed_path.run_id", &self.run_id)?;
        if self.first_seen_event_ref.run_id != self.run_id
            || self.last_seen_event_ref.run_id != self.run_id
        {
            return Err(Error::Config(
                "failed-path event references must belong to the same run".into(),
            ));
        }
        match (self.status, &self.superseded_by) {
            (FailedPathStatus::Active, None) => Ok(()),
            (FailedPathStatus::Superseded, Some(replacement)) => {
                validate_id("superseded_by", replacement)?;
                if replacement == &self.failure_id {
                    return Err(Error::Config(
                        "failed-path replacement must differ from the original record".into(),
                    ));
                }
                Ok(())
            }
            _ => Err(Error::Config(
                "failed-path status and superseded_by are inconsistent".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub rollback_id: String,
    pub checkpoint_id: String,
    pub source_session_node_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_path_ref: Option<String>,
    pub requested_by: String,
}

impl RollbackRequest {
    pub fn validate(&self) -> Result<()> {
        validate_id("rollback_id", &self.rollback_id)?;
        validate_id("checkpoint_id", &self.checkpoint_id)?;
        validate_id("source_session_node_id", &self.source_session_node_id)?;
        validate_text("rollback.reason", &self.reason, MAX_REASON_BYTES)?;
        if let Some(reference) = &self.failed_path_ref {
            validate_id("failed_path_ref", reference)?;
        }
        validate_text("rollback.requested_by", &self.requested_by, 128)?;
        Ok(())
    }
}

fn validate_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(char::is_control)
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.ends_with(' ')
        || value.starts_with(' ')
        || value.ends_with('.')
        || is_windows_reserved_id(value)
    {
        return Err(Error::Config(format!(
            "{field} must be a non-empty, bounded path-safe identifier"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(Error::Config(format!(
            "{field} must be non-empty, bounded, and contain no control characters"
        )));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Config(format!(
            "{field} must be a SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn validate_relative_path(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || value.chars().any(char::is_control) {
        return Err(Error::Config(format!(
            "{field} must be non-empty, bounded, and contain no control characters"
        )));
    }
    if value.contains('\\') || value.contains(':') || value.starts_with('/') {
        return Err(Error::Config(format!(
            "{field} must use normalized workspace-relative separators"
        )));
    }
    if value.split('/').any(|segment| {
        segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.len() > 255
            || is_windows_reserved_component(segment)
    }) {
        return Err(Error::Config(format!(
            "{field} must use normalized workspace-relative separators"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::Config(format!("{field} must be workspace-relative")));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Config(format!(
            "{field} must not contain parent traversal"
        )));
    }
    Ok(())
}

fn is_windows_reserved_component(segment: &str) -> bool {
    is_windows_reserved_id(segment)
}

fn is_windows_reserved_id(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || stem.strip_prefix("COM").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "a".repeat(64)
    }

    fn event_ref() -> EventRef {
        EventRef::new("event-1", "run-1")
    }

    #[test]
    fn checkpoint_requires_supported_schema_and_valid_entries() {
        let mut artifact = CheckpointArtifact::new(
            "checkpoint-1",
            "run-1",
            "session-1",
            "node-1",
            event_ref(),
            std::env::current_dir().unwrap().join("workspace"),
            digest(),
            digest(),
            digest(),
        );
        artifact.file_entries.push(CheckpointFileEntry::file(
            "src/main.rs",
            3,
            digest(),
            "blob-1",
        ));
        artifact.validate().unwrap();
        artifact.validate_limits(10, 10, 10).unwrap();
        artifact.file_entries[0].path = "../outside".into();
        assert!(artifact.validate().is_err());
        artifact.file_entries[0].path = "src\\main.rs".into();
        assert!(artifact.validate().is_err());
        artifact.file_entries[0].path = "CON".into();
        assert!(artifact.validate().is_err());
        artifact.file_entries[0].path = "name.".into();
        assert!(artifact.validate().is_err());
        let mut case_collision = artifact.clone();
        case_collision.file_entries = vec![
            CheckpointFileEntry::file("Dir/file.txt", 0, digest(), "blob-1"),
            CheckpointFileEntry::file("dir/file.txt", 0, digest(), "blob-2"),
        ];
        assert!(case_collision.validate().is_err());
        let mut mismatched = CheckpointArtifact::new(
            "checkpoint-2",
            "run-2",
            "session-1",
            "node-1",
            event_ref(),
            std::env::current_dir().unwrap().join("workspace"),
            digest(),
            digest(),
            digest(),
        );
        mismatched.event_ref.run_id = "other-run".into();
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn external_effect_summary_rejects_inconsistent_declarations() {
        let mut summary = ExternalEffectSummary {
            effect_scope: "external_mutation".into(),
            reversibility: "reversible".into(),
            external_mutation: true,
            event_ref: None,
        };
        assert!(summary.validate().is_err());
        summary.reversibility = "irreversible".into();
        summary.validate().unwrap();
        summary.external_mutation = false;
        assert!(summary.validate().is_err());
    }

    #[test]
    fn identifiers_cannot_be_used_as_path_components() {
        let mut request = RollbackRequest {
            rollback_id: "../rollback".into(),
            checkpoint_id: "checkpoint-1".into(),
            source_session_node_id: "node-1".into(),
            reason: "test".into(),
            failed_path_ref: None,
            requested_by: "operator".into(),
        };
        assert!(request.validate().is_err());
        request.rollback_id = "rollback:windows".into();
        assert!(request.validate().is_err());
        request.rollback_id = "rollback-1".into();
        request.checkpoint_id = "..".into();
        assert!(request.validate().is_err());
        request.checkpoint_id = "CON".into();
        assert!(request.validate().is_err());
        request.checkpoint_id = "name.".into();
        assert!(request.validate().is_err());
    }

    #[test]
    fn failed_path_can_only_be_superseded_once() {
        let mut record = FailedPathRecord {
            schema_version: FAILED_PATH_SCHEMA_VERSION,
            failure_id: "failure-1".into(),
            failure_class: FailureClass::ToolFailed,
            tool: "write_file".into(),
            canonical_args_digest: digest(),
            resource_digest: digest(),
            contract_digest: digest(),
            policy_digest: digest(),
            attempt_count: 1,
            first_seen_event_ref: event_ref(),
            last_seen_event_ref: event_ref(),
            run_id: "run-1".into(),
            status: FailedPathStatus::Active,
            superseded_by: None,
        };
        record.validate().unwrap();
        assert!(record.mark_superseded("failure-1").is_err());
        record.mark_superseded("failure-2").unwrap();
        assert_eq!(record.status, FailedPathStatus::Superseded);
        assert!(record.mark_superseded("failure-3").is_err());
        let mut self_replacement = record;
        self_replacement.status = FailedPathStatus::Superseded;
        self_replacement.superseded_by = Some("failure-2".into());
        assert!(self_replacement.validate().is_ok());
        self_replacement.superseded_by = Some("failure-1".into());
        assert!(self_replacement.validate().is_err());
    }
}
