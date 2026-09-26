//! Read-only inspection of a Pangu Artifact store for operator recovery.
//!
//! [`inspect_artifact_root`] answers the evidence questions in
//! `docs/CHECKPOINT_RECOVERY.md` §3 without changing anything. It never
//! creates, repairs, renames, or deletes a file, never takes the artifact
//! transaction lock, and never treats an artifact it cannot fully verify as
//! safe. A non-`Verified` verdict is an operator decision point, never an
//! instruction to delete evidence.
//!
//! Checkpoint verification deliberately reuses the runtime path
//! ([`ArtifactStore::verify_checkpoint`]), so a verified checkpoint means
//! exactly what a restore would check — not a weaker parallel audit that could
//! drift from the real invariants.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifact::{
    self, ArtifactStore, RollbackOperation, RollbackOperationStatus, MAX_ARTIFACT_MANIFEST_BYTES,
    MAX_ROLLBACK_OPERATION_BYTES, MAX_SESSION_NODE_BYTES,
};
use crate::checkpoint::{ArtifactState, CheckpointArtifact, FailedPathStatus, SessionNode};
use crate::error::{Error, Result};
use crate::events::redact_text;
use crate::util::{now_rfc3339, one_line, truncate_middle};

/// Schema tag written into every inspection report.
pub const ARTIFACT_INSPECTION_SCHEMA: &str = "pangu-artifact-inspection/1";
/// Bounded number of checkpoint directories reported from one store.
pub const MAX_INSPECTION_CHECKPOINTS: usize = 1024;
/// Bounded number of rollback operation records reported from one store.
pub const MAX_INSPECTION_OPERATIONS: usize = 1024;
/// Bounded number of filesystem entries visited by one directory scan.
pub const MAX_INSPECTION_ENTRIES: usize = 20_000;
/// Bounded recursion depth for workspace evidence scans.
pub const MAX_INSPECTION_DEPTH: usize = 32;
/// Bounded number of Windows replacement backups reported as evidence.
pub const MAX_INSPECTION_REPLACE_BACKUPS: usize = 256;
/// Bounded number of problems retained in one report.
pub const MAX_INSPECTION_PROBLEMS: usize = 512;

const MAX_LOCK_EVIDENCE_BYTES: u64 = 64;
const MAX_COMMIT_MARKER_BYTES: u64 = 32;
const MAX_PATH_EVIDENCE_BYTES: usize = 200;
const MAX_DETAIL_BYTES: usize = 240;
const MAX_ROOT_BYTES: usize = 256;
const REPLACE_BACKUP_MARKER: &str = ".replace-backup-";
const TRANSACTION_LOCK_FILE: &str = ".rollback-operation.lock";
const COMMIT_MARKER_FILE: &str = "COMMITTED";
const COMMIT_MARKER_CONTENT: &[u8] = b"COMMITTED";
const UNVERIFIABLE_PREFIX: &str = "unverifiable.";
const OPERATOR_PREFIX: &str = "operator.";

/// What an operator may conclude from one inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionVerdict {
    /// Every artifact, ledger and binding in the store was fully verified.
    Verified,
    /// The store is internally consistent but contains an incident condition
    /// the runtime deliberately refuses to resolve on its own.
    OperatorRequired,
    /// The store could not be read or verified completely. Nothing may be
    /// assumed about the state of the workspace.
    Unverifiable,
}

impl InspectionVerdict {
    fn from_code(code: &str) -> Self {
        if code.starts_with(UNVERIFIABLE_PREFIX) {
            InspectionVerdict::Unverifiable
        } else {
            InspectionVerdict::OperatorRequired
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            InspectionVerdict::Verified => "verified",
            InspectionVerdict::OperatorRequired => "operator_required",
            InspectionVerdict::Unverifiable => "unverifiable",
        }
    }
}

/// One redacted, bounded finding. `code` is stable so drills, the runbook and
/// CI can refer to it; `detail` is never a substitute for the original
/// evidence on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionProblem {
    pub code: String,
    pub subject: String,
    pub detail: String,
}

impl InspectionProblem {
    fn new(code: &str, subject: &str, detail: impl AsRef<str>) -> Self {
        Self {
            code: code.to_string(),
            subject: bounded_text(subject, MAX_PATH_EVIDENCE_BYTES),
            detail: bounded_text(detail.as_ref(), MAX_DETAIL_BYTES),
        }
    }
}

/// Evidence for a leftover artifact transaction lock. The PID is a hint only:
/// it does not prove a process is alive, so it is reported separately from the
/// presence of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLockEvidence {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_hint: Option<String>,
    pub bytes: u64,
}

/// A leftover Windows replacement hand-off backup. These files are recovery
/// evidence: the runtime refuses to write over them, and so does this report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceBackupEvidence {
    /// `artifact` for the store itself, `workspace` for a snapshot workspace.
    pub scope: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionNodeInspection {
    pub session_node_id: String,
    pub embedded_present: bool,
    pub standalone_present: bool,
    pub consistent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInspection {
    pub checkpoint_id: String,
    pub workspace: String,
    pub state: ArtifactState,
    pub committed_marker: bool,
    pub verified: bool,
    pub file_entries: usize,
    pub total_bytes: u64,
    pub snapshot_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_digest: Option<String>,
    pub contract_digest: String,
    pub policy_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_node: Option<SessionNodeInspection>,
    pub external_effect_after: bool,
    pub problems: Vec<InspectionProblem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationInspection {
    pub rollback_id: String,
    pub checkpoint_id: String,
    pub status: RollbackOperationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_session_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub problems: Vec<InspectionProblem>,
}

/// The full read-only report. `read_only` is recorded so a report can never
/// be mistaken for a repair action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInspection {
    pub schema: String,
    pub generated_at: String,
    pub root: String,
    pub verdict: InspectionVerdict,
    pub read_only: bool,
    pub transaction_lock: TransactionLockEvidence,
    pub replace_backups: Vec<ReplaceBackupEvidence>,
    pub replace_backup_scan_truncated: bool,
    pub checkpoints: Vec<CheckpointInspection>,
    pub operations: Vec<OperationInspection>,
    pub effect_records: usize,
    pub external_mutations: usize,
    pub checkpoints_blocked_by_external_effect: Vec<String>,
    pub failed_path_records: usize,
    pub active_failed_paths: usize,
    pub problems: Vec<InspectionProblem>,
}

impl ArtifactInspection {
    /// Stable one-line summary for CLI output and CI log greps.
    pub fn summary(&self) -> String {
        format!(
            "verdict={} checkpoints={} operations={} effects={}/{} failed_paths={}/{} lock={} replace_backups={}{}",
            self.verdict.as_str(),
            self.checkpoints.len(),
            self.operations.len(),
            self.external_mutations,
            self.effect_records,
            self.active_failed_paths,
            self.failed_path_records,
            self.transaction_lock.present,
            self.replace_backups.len(),
            if self.replace_backup_scan_truncated {
                " (scan truncated)"
            } else {
                ""
            }
        )
    }
}

/// Inspect one artifact store without modifying it.
pub fn inspect_artifact_root(root: &Path) -> Result<ArtifactInspection> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    if !artifact::path_exists_without_symlink(&absolute)? {
        return Err(Error::Config(
            "artifact store root does not exist or resolves through a symlink".into(),
        ));
    }
    if !fs::symlink_metadata(&absolute)?.is_dir() {
        return Err(Error::Config(
            "artifact store root must be a directory".into(),
        ));
    }
    // The store itself refuses to operate through symlink components, so a
    // path like that cannot describe a store this runtime would ever use.
    artifact::reject_symlink_components(&absolute)?;
    // `open` is read-only for an existing directory: it canonicalizes and
    // re-checks the path. Existence is proven above, so it creates nothing.
    let store = ArtifactStore::open(&absolute)?;
    let store_root = store.root().to_path_buf();

    let mut problems = Problems::default();
    let transaction_lock = inspect_transaction_lock(&store_root, &mut problems);
    let mut checkpoints = inspect_checkpoints(&store, &mut problems);
    let mut replace_backups = Vec::new();
    let mut replace_backup_scan_truncated = false;
    // The runtime's Windows hand-off creates backups next to the artifact files
    // it replaces (manifest, operation record, session node, ledgers), while a
    // deployment can also be interrupted while a workspace file is being
    // written. Both are scanned so the runbook never has to guess the location.
    scan_for_replace_backups(
        &store_root,
        "artifact",
        &mut replace_backups,
        &mut replace_backup_scan_truncated,
    );
    for checkpoint in &checkpoints {
        scan_for_replace_backups(
            &PathBuf::from(&checkpoint.workspace),
            "workspace",
            &mut replace_backups,
            &mut replace_backup_scan_truncated,
        );
    }
    if !replace_backups.is_empty() {
        problems.operator(
            "operator.replace_backup_present",
            "artifact store",
            "a Windows replacement backup is present; it is recovery evidence and must not be deleted automatically",
        );
    }
    checkpoints.sort_by(|left, right| left.checkpoint_id.cmp(&right.checkpoint_id));
    let mut checkpoints_blocked_by_external_effect: Vec<String> = checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.external_effect_after)
        .map(|checkpoint| checkpoint.checkpoint_id.clone())
        .collect();
    checkpoints_blocked_by_external_effect.sort();

    let operations = inspect_operations(&store_root, &mut problems);
    let (effect_records, external_mutations) = inspect_effects(&store, &mut problems);
    let (failed_path_records, active_failed_paths) = inspect_failed_paths(&store, &mut problems);
    let verdict = problems.verdict();

    Ok(ArtifactInspection {
        schema: ARTIFACT_INSPECTION_SCHEMA.to_string(),
        generated_at: now_rfc3339(),
        root: bounded_text(&store_root.display().to_string(), MAX_ROOT_BYTES),
        verdict,
        read_only: true,
        transaction_lock,
        replace_backups,
        replace_backup_scan_truncated,
        checkpoints,
        operations,
        effect_records,
        external_mutations,
        checkpoints_blocked_by_external_effect,
        failed_path_records,
        active_failed_paths,
        problems: problems.into_vec(),
    })
}

fn inspect_transaction_lock(root: &Path, problems: &mut Problems) -> TransactionLockEvidence {
    let path = root.join(TRANSACTION_LOCK_FILE);
    let present = match artifact::path_exists_without_symlink(&path) {
        Ok(present) => present,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.transaction_lock_unreadable",
                TRANSACTION_LOCK_FILE,
                error.to_string(),
            );
            false
        }
    };
    if !present {
        return TransactionLockEvidence {
            present: false,
            pid_hint: None,
            bytes: 0,
        };
    }
    problems.operator(
        "operator.transaction_lock_present",
        TRANSACTION_LOCK_FILE,
        "a crash left the artifact transaction lock behind; the runtime will not guess recovery",
    );
    let mut evidence = TransactionLockEvidence {
        present: true,
        pid_hint: None,
        bytes: 0,
    };
    match artifact::read_regular_file_bounded(&path, MAX_LOCK_EVIDENCE_BYTES) {
        Ok(bytes) => {
            evidence.bytes = bytes.len() as u64;
            let text = String::from_utf8_lossy(&bytes);
            evidence.pid_hint = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("pid="))
                .map(|pid| bounded_text(pid, 32));
        }
        Err(error) => problems.unverifiable(
            "unverifiable.transaction_lock_unreadable",
            TRANSACTION_LOCK_FILE,
            error.to_string(),
        ),
    }
    evidence
}

fn inspect_checkpoints(
    store: &ArtifactStore,
    problems: &mut Problems,
) -> Vec<CheckpointInspection> {
    let mut inspections = Vec::new();
    let entries = match bounded_read_dir(store.root(), MAX_INSPECTION_ENTRIES) {
        Ok(entries) => entries,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.store_unreadable",
                "artifact root",
                error.to_string(),
            );
            return inspections;
        }
    };
    for (name, path, metadata) in entries {
        if !metadata.is_dir() || matches!(name.as_str(), "sessions" | "operations") {
            continue;
        }
        if inspections.len() >= MAX_INSPECTION_CHECKPOINTS {
            problems.unverifiable(
                "unverifiable.too_many_checkpoints",
                "artifact root",
                "checkpoint count exceeds the inspection limit",
            );
            break;
        }
        if artifact::validate_id("checkpoint_id", &name).is_err() {
            problems.unverifiable(
                "unverifiable.checkpoint_name",
                &name,
                "checkpoint directory name is not a safe artifact id",
            );
            continue;
        }
        let inspection = inspect_checkpoint(store, &path, &name, problems);
        inspections.push(inspection);
    }
    inspections
}

/// Inspect one checkpoint directory and merge its findings into `problems`.
fn inspect_checkpoint(
    store: &ArtifactStore,
    directory: &Path,
    checkpoint_id: &str,
    problems: &mut Problems,
) -> CheckpointInspection {
    let mut local = Problems::default();
    let manifest_path = directory.join("manifest.json");
    let bytes = match artifact::read_regular_file_bounded(
        &manifest_path,
        MAX_ARTIFACT_MANIFEST_BYTES as u64,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            local.unverifiable(
                "unverifiable.manifest_unreadable",
                checkpoint_id,
                error.to_string(),
            );
            return unusable_checkpoint(checkpoint_id, directory, &mut local, problems);
        }
    };
    let artifact: CheckpointArtifact = match serde_json::from_slice(&bytes) {
        Ok(artifact) => artifact,
        Err(error) => {
            local.unverifiable(
                "unverifiable.manifest_unparsable",
                checkpoint_id,
                error.to_string(),
            );
            return unusable_checkpoint(checkpoint_id, directory, &mut local, problems);
        }
    };
    if artifact.checkpoint_id != checkpoint_id {
        local.unverifiable(
            "unverifiable.manifest_id_mismatch",
            checkpoint_id,
            "manifest id does not match its directory",
        );
    }

    let committed_marker = inspect_commit_marker(directory, checkpoint_id, &mut local);
    if !committed_marker {
        local.operator(
            "operator.commit_marker_missing",
            checkpoint_id,
            "a visible checkpoint directory without a valid commit marker may be an interrupted publish",
        );
    }
    let verified = match store.verify_checkpoint(&artifact) {
        Ok(()) => true,
        Err(error) => {
            local.unverifiable(
                "unverifiable.checkpoint_verification_failed",
                checkpoint_id,
                error.to_string(),
            );
            false
        }
    };
    if artifact.state != ArtifactState::Complete {
        local.operator(
            "operator.checkpoint_not_complete",
            checkpoint_id,
            "checkpoint is not in the complete state",
        );
    }
    let session_node = inspect_session_node(store, directory, &artifact, checkpoint_id, &mut local);
    let external_effect_after = match store.has_external_effect_after(&artifact) {
        Ok(found) => found,
        Err(error) => {
            local.unverifiable(
                "unverifiable.effect_ledger_unreadable",
                checkpoint_id,
                error.to_string(),
            );
            false
        }
    };
    if external_effect_after {
        local.operator(
            "operator.external_effect_after_checkpoint",
            checkpoint_id,
            "a recorded external mutation follows this checkpoint; rollback is blocked and no external compensation exists",
        );
    }

    let total_bytes: u64 = artifact.file_entries.iter().map(|entry| entry.size).sum();
    let inspection = CheckpointInspection {
        checkpoint_id: artifact.checkpoint_id.clone(),
        workspace: bounded_text(
            &artifact.workspace.display().to_string(),
            MAX_PATH_EVIDENCE_BYTES,
        ),
        state: artifact.state,
        committed_marker,
        verified,
        file_entries: artifact.file_entries.len(),
        total_bytes,
        snapshot_digest: artifact.snapshot_digest.clone(),
        workspace_digest: artifact.workspace_digest.clone(),
        contract_digest: artifact.contract_digest.clone(),
        policy_digest: artifact.policy_digest.clone(),
        session_node,
        external_effect_after,
        problems: Vec::new(),
    };
    problems.extend(&local);
    let mut inspection = inspection;
    inspection.problems = local.into_vec();
    inspection
}

/// A checkpoint whose manifest could not be read at all. Everything unknown is
/// reported as unknown instead of being filled in with a safe-looking value.
fn unusable_checkpoint(
    checkpoint_id: &str,
    directory: &Path,
    local: &mut Problems,
    problems: &mut Problems,
) -> CheckpointInspection {
    let mut inspection = CheckpointInspection {
        checkpoint_id: checkpoint_id.to_string(),
        workspace: directory.display().to_string(),
        state: ArtifactState::Incomplete,
        committed_marker: false,
        verified: false,
        file_entries: 0,
        total_bytes: 0,
        snapshot_digest: String::new(),
        workspace_digest: None,
        contract_digest: String::new(),
        policy_digest: String::new(),
        session_node: None,
        external_effect_after: false,
        problems: Vec::new(),
    };
    inspection.workspace = bounded_text(&inspection.workspace, MAX_PATH_EVIDENCE_BYTES);
    problems.extend(local);
    inspection.problems = local.items.clone();
    inspection
}
fn inspect_commit_marker(directory: &Path, checkpoint_id: &str, problems: &mut Problems) -> bool {
    let marker = directory.join(COMMIT_MARKER_FILE);
    let embedded = directory.join("session-node.json");
    let has_embedded = match artifact::path_exists_without_symlink(&embedded) {
        Ok(exists) => exists,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.embedded_node_unreadable",
                checkpoint_id,
                error.to_string(),
            );
            false
        }
    };
    if !has_embedded {
        return false;
    }
    match artifact::read_regular_file_bounded(&marker, MAX_COMMIT_MARKER_BYTES) {
        Ok(bytes) => bytes == COMMIT_MARKER_CONTENT,
        Err(_) => false,
    }
}

fn inspect_session_node(
    store: &ArtifactStore,
    directory: &Path,
    checkpoint: &CheckpointArtifact,
    checkpoint_id: &str,
    problems: &mut Problems,
) -> Option<SessionNodeInspection> {
    let embedded_path = directory.join("session-node.json");
    let embedded_present = match artifact::path_exists_without_symlink(&embedded_path) {
        Ok(present) => present,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.embedded_node_unreadable",
                checkpoint_id,
                error.to_string(),
            );
            false
        }
    };
    if !embedded_present {
        return None;
    }
    let embedded: SessionNode =
        match artifact::read_regular_file_bounded(&embedded_path, MAX_SESSION_NODE_BYTES as u64) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(node) => node,
                Err(error) => {
                    problems.unverifiable(
                        "unverifiable.embedded_node_unparsable",
                        checkpoint_id,
                        error.to_string(),
                    );
                    return None;
                }
            },
            Err(error) => {
                problems.unverifiable(
                    "unverifiable.embedded_node_unreadable",
                    checkpoint_id,
                    error.to_string(),
                );
                return None;
            }
        };
    if let Err(error) = embedded.validate() {
        problems.unverifiable(
            "unverifiable.embedded_node_invalid",
            checkpoint_id,
            error.to_string(),
        );
    }
    if embedded.checkpoint_id.as_deref() != Some(checkpoint.checkpoint_id.as_str()) {
        problems.unverifiable(
            "unverifiable.embedded_node_binding",
            checkpoint_id,
            "embedded session node does not point at this checkpoint",
        );
    }
    let standalone = match store.load_session_node_by_id(&embedded.session_node_id) {
        Ok(node) => node,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.standalone_node_unreadable",
                checkpoint_id,
                error.to_string(),
            );
            None
        }
    };
    let consistent = standalone.as_ref() == Some(&embedded);
    if !consistent {
        problems.unverifiable(
            "unverifiable.session_node_ledger_mismatch",
            checkpoint_id,
            "embedded and standalone session nodes differ, or the standalone ledger entry is missing",
        );
    }
    Some(SessionNodeInspection {
        session_node_id: embedded.session_node_id.clone(),
        embedded_present,
        standalone_present: standalone.is_some(),
        consistent,
    })
}

fn inspect_operations(root: &Path, problems: &mut Problems) -> Vec<OperationInspection> {
    let mut inspections = Vec::new();
    let directory = root.join("operations");
    let entries = match bounded_read_dir(&directory, MAX_INSPECTION_ENTRIES) {
        Ok(entries) => entries,
        Err(error) => {
            problems.unverifiable(
                "unverifiable.operations_unreadable",
                "operations",
                error.to_string(),
            );
            return inspections;
        }
    };
    for (name, path, metadata) in entries {
        if !metadata.is_file() {
            continue;
        }
        if inspections.len() >= MAX_INSPECTION_OPERATIONS {
            problems.unverifiable(
                "unverifiable.too_many_operations",
                "operations",
                "operation count exceeds the inspection limit",
            );
            break;
        }
        let expected_id = name.strip_suffix(".json").unwrap_or_default().to_string();
        let bytes =
            match artifact::read_regular_file_bounded(&path, MAX_ROLLBACK_OPERATION_BYTES as u64) {
                Ok(bytes) => bytes,
                Err(error) => {
                    problems.unverifiable(
                        "unverifiable.operation_unreadable",
                        &name,
                        error.to_string(),
                    );
                    continue;
                }
            };
        let operation: RollbackOperation = match serde_json::from_slice(&bytes) {
            Ok(operation) => operation,
            Err(error) => {
                problems.unverifiable(
                    "unverifiable.operation_unparsable",
                    &name,
                    error.to_string(),
                );
                continue;
            }
        };
        let mut local = Problems::default();
        if operation.rollback_id != expected_id {
            local.unverifiable(
                "unverifiable.operation_id_mismatch",
                &name,
                "rollback id does not match its ledger file name",
            );
        }
        if let Err(error) = operation.validate() {
            local.unverifiable("unverifiable.operation_invalid", &name, error.to_string());
        }
        match operation.status {
            RollbackOperationStatus::InProgress => local.operator(
                "operator.operation_in_progress",
                &name,
                "a rollback operation never reached a terminal state; the workspace may be mid-restore",
            ),
            RollbackOperationStatus::Failed => local.operator(
                "operator.operation_failed",
                &name,
                "a rollback operation failed; the same rollback id must not be retried automatically",
            ),
            RollbackOperationStatus::Applied => {}
        }
        problems.extend(&local);
        inspections.push(OperationInspection {
            rollback_id: operation.rollback_id.clone(),
            checkpoint_id: operation.checkpoint_id.clone(),
            status: operation.status,
            transition_session_node_id: operation.transition_session_node_id.clone(),
            transition_event_id: operation
                .transition_event_ref
                .as_ref()
                .map(|event| event.event_id.clone()),
            error: operation
                .error
                .as_ref()
                .map(|error| bounded_text(error, MAX_DETAIL_BYTES)),
            created_at: operation.created_at.clone(),
            completed_at: operation.completed_at.clone(),
            problems: local.into_vec(),
        });
    }
    inspections.sort_by(|left, right| left.rollback_id.cmp(&right.rollback_id));
    inspections
}

fn inspect_effects(store: &ArtifactStore, problems: &mut Problems) -> (usize, usize) {
    match store.effect_records() {
        Ok(records) => {
            let external = records
                .iter()
                .filter(|record| record.external_mutation)
                .count();
            (records.len(), external)
        }
        Err(error) => {
            problems.unverifiable(
                "unverifiable.effect_ledger_unreadable",
                "effects.jsonl",
                error.to_string(),
            );
            (0, 0)
        }
    }
}

fn inspect_failed_paths(store: &ArtifactStore, problems: &mut Problems) -> (usize, usize) {
    match store.failed_path_ledger() {
        Ok(records) => {
            let active = records
                .iter()
                .filter(|record| record.status == FailedPathStatus::Active)
                .count();
            if active > 0 {
                problems.operator(
                    "operator.active_failed_paths",
                    crate::artifact::FAILED_PATH_LEDGER_FILE,
                    "an equivalent failed tool path is still blocked for this run",
                );
            }
            (records.len(), active)
        }
        Err(error) => {
            problems.unverifiable(
                "unverifiable.failed_path_ledger_unreadable",
                crate::artifact::FAILED_PATH_LEDGER_FILE,
                error.to_string(),
            );
            (0, 0)
        }
    }
}

/// Find Windows replacement hand-off backups. They are evidence of an
/// interrupted atomic replace, not temporary files to clean up, so they are
/// reported and never touched. The scan is bounded and reports truncation
/// instead of presenting a partial answer as complete.
fn scan_for_replace_backups(
    base: &Path,
    scope: &str,
    found: &mut Vec<ReplaceBackupEvidence>,
    truncated: &mut bool,
) {
    if !base.is_dir() {
        return;
    }
    let mut visited = 0usize;
    let mut stack = vec![(base.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_INSPECTION_DEPTH {
            *truncated = true;
            continue;
        }
        let Ok(entries) = fs::read_dir(&directory) else {
            *truncated = true;
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_INSPECTION_ENTRIES {
                *truncated = true;
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if !name.contains(REPLACE_BACKUP_MARKER) {
                continue;
            }
            if found.len() < MAX_INSPECTION_REPLACE_BACKUPS {
                let relative = path.strip_prefix(base).unwrap_or(&path);
                found.push(ReplaceBackupEvidence {
                    scope: scope.to_string(),
                    path: bounded_text(&relative.display().to_string(), MAX_PATH_EVIDENCE_BYTES),
                });
            } else {
                *truncated = true;
            }
        }
    }
    found.sort_by(|left, right| {
        (left.scope.clone(), left.path.clone()).cmp(&(right.scope.clone(), right.path.clone()))
    });
    found.dedup();
}

fn bounded_read_dir(
    directory: &Path,
    limit: usize,
) -> Result<Vec<(String, PathBuf, fs::Metadata)>> {
    if !artifact::path_exists_without_symlink(directory)? {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut visited = 0usize;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        visited += 1;
        if visited > limit {
            return Err(Error::Other(
                "inspection directory scan exceeds its bounded entry limit".into(),
            ));
        }
        let path = entry.path();
        artifact::reject_symlink_components(&path)?;
        let name = entry.file_name().to_string_lossy().to_string();
        let metadata = fs::symlink_metadata(&path)?;
        entries.push((name, path, metadata));
    }
    Ok(entries)
}

fn bounded_text(value: &str, max: usize) -> String {
    truncate_middle(&one_line(&redact_text(value), max), max)
}

/// Bounded problem accumulator. A problem code carries its own verdict
/// prefix, so the report verdict can never be softer than the worst finding.
#[derive(Default)]
struct Problems {
    items: Vec<InspectionProblem>,
    overflowed: bool,
}

impl Problems {
    fn push(&mut self, code: &str, subject: &str, detail: impl AsRef<str>) {
        if self.items.len() >= MAX_INSPECTION_PROBLEMS {
            self.overflowed = true;
            return;
        }
        self.items
            .push(InspectionProblem::new(code, subject, detail));
    }

    fn unverifiable(&mut self, code: &str, subject: &str, detail: impl AsRef<str>) {
        debug_assert!(code.starts_with(UNVERIFIABLE_PREFIX), "code: {code}");
        self.push(code, subject, detail);
    }

    fn operator(&mut self, code: &str, subject: &str, detail: impl AsRef<str>) {
        debug_assert!(code.starts_with(OPERATOR_PREFIX), "code: {code}");
        self.push(code, subject, detail);
    }

    fn extend(&mut self, other: &Problems) {
        for problem in &other.items {
            self.push(&problem.code, &problem.subject, &problem.detail);
        }
        self.overflowed |= other.overflowed;
    }
    /// The report verdict is the worst verdict any finding forces, so a report
    /// can never be softer than its own problems.
    fn verdict(&self) -> InspectionVerdict {
        let mut worst = InspectionVerdict::Verified;
        for problem in &self.items {
            match InspectionVerdict::from_code(&problem.code) {
                InspectionVerdict::Unverifiable => return InspectionVerdict::Unverifiable,
                InspectionVerdict::OperatorRequired => worst = InspectionVerdict::OperatorRequired,
                InspectionVerdict::Verified => {}
            }
        }
        if self.overflowed {
            return InspectionVerdict::Unverifiable;
        }
        worst
    }

    fn into_vec(self) -> Vec<InspectionProblem> {
        let mut items = self.items;
        if self.overflowed {
            items.push(InspectionProblem::new(
                "unverifiable.problem_list_truncated",
                "inspection",
                "the problem list exceeded its bound; treat the store as unverified",
            ));
        }
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::SnapshotRequest;
    use crate::checkpoint::SessionNode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Path, size and content digest of every file, used to prove that an
    /// inspection changed nothing.
    fn tree_fingerprint(root: &Path) -> Vec<(String, u64, String)> {
        fn walk(base: &Path, directory: &Path, out: &mut Vec<(String, u64, String)>) {
            let Ok(entries) = fs::read_dir(directory) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if metadata.is_dir() {
                    walk(base, &path, out);
                    continue;
                }
                let bytes = fs::read(&path).unwrap_or_default();
                out.push((relative, metadata.len(), artifact::digest_bytes(&bytes)));
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pangu-inspect-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        fs::canonicalize(path).unwrap()
    }

    /// A store holding one complete checkpoint with a bound session node.
    fn store_with_checkpoint(label: &str) -> (PathBuf, PathBuf) {
        let workspace = root(&format!("{label}-workspace"));
        let store_root = workspace.join("checkpoints");
        fs::write(workspace.join("state.txt"), "content").unwrap();
        let store = ArtifactStore::open(&store_root).unwrap();
        let request = SnapshotRequest::new(
            workspace.clone(),
            vec![workspace.clone()],
            vec![store_root.clone()],
            vec!["**/.git/**".into()],
            crate::artifact::SnapshotLimits::default(),
        );
        let artifact = CheckpointArtifact::new(
            "checkpoint-1",
            "run-1",
            "session-1",
            "node-1",
            crate::checkpoint::EventRef::new("event-1", "run-1"),
            workspace.clone(),
            digest('a'),
            digest('b'),
            digest('c'),
        );
        let node = SessionNode::new(
            "node-1",
            artifact.event_ref.clone(),
            Some("checkpoint-1".into()),
        );
        store
            .commit_snapshot_with_node(&request, artifact, Some(&node))
            .unwrap();
        (workspace, store_root)
    }

    #[test]
    fn a_clean_store_is_reported_as_verified_and_stays_byte_identical() {
        let (workspace, store_root) = store_with_checkpoint("clean");
        let before = tree_fingerprint(&store_root);
        let report = inspect_artifact_root(&store_root).unwrap();
        assert_eq!(report.verdict, InspectionVerdict::Verified);
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert!(report.read_only);
        assert_eq!(report.schema, ARTIFACT_INSPECTION_SCHEMA);
        assert_eq!(report.checkpoints.len(), 1);
        let checkpoint = &report.checkpoints[0];
        assert!(checkpoint.verified);
        assert!(checkpoint.committed_marker);
        assert_eq!(checkpoint.state, ArtifactState::Complete);
        assert_eq!(checkpoint.file_entries, 1);
        assert!(!checkpoint.external_effect_after);
        let node = checkpoint
            .session_node
            .as_ref()
            .expect("a bound checkpoint has a session node");
        assert!(node.consistent && node.standalone_present);
        assert!(report.summary().contains("verdict=verified"));
        assert_eq!(before, tree_fingerprint(&store_root));
        assert!(workspace.join("state.txt").exists());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn a_leftover_transaction_lock_is_an_operator_condition_not_a_verified_store() {
        let (workspace, store_root) = store_with_checkpoint("lock");
        fs::write(store_root.join(".rollback-operation.lock"), "pid=4242\n").unwrap();
        let report = inspect_artifact_root(&store_root).unwrap();
        assert_eq!(report.verdict, InspectionVerdict::OperatorRequired);
        assert!(report.transaction_lock.present);
        assert_eq!(report.transaction_lock.pid_hint.as_deref(), Some("4242"));
        assert!(report
            .problems
            .iter()
            .any(|problem| problem.code == "operator.transaction_lock_present"));
        // A PID is only a hint and never a claim that a process is alive.
        assert!(report.summary().contains("lock=true"));
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn a_tampered_manifest_is_unverifiable_rather_than_merely_suspect() {
        let (workspace, store_root) = store_with_checkpoint("tampered");
        let manifest = store_root.join("checkpoint-1/manifest.json");
        let mut bytes = fs::read(&manifest).unwrap();
        let text = String::from_utf8_lossy(&bytes).replace("checkpoint-1", "checkpoint-2");
        bytes = text.into_bytes();
        fs::write(&manifest, &bytes).unwrap();
        let report = inspect_artifact_root(&store_root).unwrap();
        assert_eq!(report.verdict, InspectionVerdict::Unverifiable);
        assert!(!report.checkpoints[0].verified);
        assert!(report.checkpoints[0].problems.iter().any(|problem| {
            problem.code == "unverifiable.manifest_id_mismatch"
                || problem.code == "unverifiable.checkpoint_verification_failed"
        }));
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn an_unreadable_root_is_an_error_not_an_empty_verified_report() {
        let missing = std::env::temp_dir().join(format!(
            "pangu-inspect-missing-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(inspect_artifact_root(&missing).is_err());
    }

    #[test]
    fn problem_codes_carry_the_verdict_they_force() {
        let mut problems = Problems::default();
        problems.operator("operator.example", "subject", "detail");
        assert_eq!(problems.verdict(), InspectionVerdict::OperatorRequired);
        problems.unverifiable("unverifiable.example", "subject", "detail");
        assert_eq!(problems.verdict(), InspectionVerdict::Unverifiable);
        assert_eq!(Problems::default().verdict(), InspectionVerdict::Verified);
    }

    #[test]
    fn details_are_redacted_bounded_and_single_line() {
        let secret = "sk-abcdef0123456789 and a very long tail \
                      that would otherwise blow past the bound";
        let problem = InspectionProblem::new("unverifiable.example", "subject", secret);
        assert!(!problem.detail.contains('\n'));
        assert!(problem.detail.len() <= 240, "{}", problem.detail.len());
        assert!(
            problem.detail.contains("[REDACTED]"),
            "secrets must be redacted: {}",
            problem.detail
        );
    }
}
