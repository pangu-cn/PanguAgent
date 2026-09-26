//! Content-addressed checkpoint artifacts and the bounded rollback store.
//!
//! This module is deliberately a storage primitive. It does not decide
//! policy, ask for approval, or call a tool. Callers must validate the
//! request against their effective boundary before invoking it. The store
//! nevertheless performs its own path, symlink, size, hash, and transaction
//! checks so a corrupt artifact fails closed instead of becoming a filesystem
//! side effect.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::{
    ArtifactState, CheckpointArtifact, CheckpointFileEntry, CheckpointFileType, EventRef,
    FailedPathRecord, FailedPathStatus, SessionNode, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_FILES,
    MAX_SNAPSHOT_FILE_BYTES,
};
use crate::{now_rfc3339, redact_text, Error, Glob, Result};

pub const ARTIFACT_STORE_SCHEMA_VERSION: u32 = 1;
pub const ROLLBACK_OPERATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_ARTIFACT_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ROLLBACK_OPERATION_BYTES: usize = 256 * 1024;
pub const MAX_SESSION_NODE_BYTES: usize = 1024 * 1024;
pub const MAX_CHECKPOINT_BLOB_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_FAILED_PATH_LEDGER_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_EFFECT_LEDGER_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SNAPSHOT_ROOTS: usize = 1_024;
pub const MAX_SNAPSHOT_EXCLUDED_ROOTS: usize = 1_024;
pub const MAX_FORBIDDEN_GLOBS: usize = 4_096;
#[cfg(windows)]
const MAX_REPLACE_BACKUP_SCAN_ENTRIES: usize = 16_384;
pub const FAILED_PATH_LEDGER_FILE: &str = "failed-paths.jsonl";
const CHECKPOINT_COMMIT_MARKER: &str = "COMMITTED";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLimits {
    pub max_snapshot_bytes: u64,
    pub max_snapshot_files: usize,
    pub max_snapshot_file_bytes: u64,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_snapshot_files: 10_000,
            max_snapshot_file_bytes: 4 * 1024 * 1024,
        }
    }
}

impl SnapshotLimits {
    pub fn validate(self) -> Result<()> {
        if self.max_snapshot_bytes == 0
            || self.max_snapshot_files == 0
            || self.max_snapshot_file_bytes == 0
        {
            return Err(Error::Config(
                "snapshot limits must all be greater than zero".into(),
            ));
        }
        if self.max_snapshot_bytes > MAX_SNAPSHOT_BYTES
            || self.max_snapshot_files > MAX_SNAPSHOT_FILES
            || self.max_snapshot_file_bytes > MAX_SNAPSHOT_FILE_BYTES
        {
            return Err(Error::Config(
                "snapshot limits exceed the supported hard maximum".into(),
            ));
        }
        if self.max_snapshot_file_bytes > self.max_snapshot_bytes {
            return Err(Error::Config(
                "snapshot per-file limit exceeds total snapshot limit".into(),
            ));
        }
        Ok(())
    }
}

/// The already-validated roots and exclusions for a snapshot.
///
/// The caller supplies roots from its effective GoalContract/Sandbox. This
/// type does not expand roots and does not interpret a model's arguments.
#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    pub workspace: PathBuf,
    pub roots: Vec<PathBuf>,
    pub excluded_roots: Vec<PathBuf>,
    pub forbidden_globs: Vec<String>,
    pub limits: SnapshotLimits,
}

impl SnapshotRequest {
    pub fn new(
        workspace: PathBuf,
        roots: Vec<PathBuf>,
        excluded_roots: Vec<PathBuf>,
        forbidden_globs: Vec<String>,
        limits: SnapshotLimits,
    ) -> Self {
        Self {
            workspace,
            roots,
            excluded_roots,
            forbidden_globs,
            limits,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.workspace.is_absolute() || !self.workspace.is_dir() {
            return Err(Error::Config(
                "snapshot workspace must be an existing absolute directory".into(),
            ));
        }
        reject_symlink_components(&self.workspace)?;
        if self.roots.is_empty() {
            return Err(Error::Config("snapshot requires at least one root".into()));
        }
        if self.roots.len() > MAX_SNAPSHOT_ROOTS
            || self.excluded_roots.len() > MAX_SNAPSHOT_EXCLUDED_ROOTS
            || self.forbidden_globs.len() > MAX_FORBIDDEN_GLOBS
        {
            return Err(Error::Config(
                "snapshot boundary lists exceed the supported limit".into(),
            ));
        }
        self.limits.validate()?;
        let workspace = fs::canonicalize(&self.workspace)?;
        for root in &self.roots {
            if !root.is_absolute() {
                return Err(Error::Config("snapshot roots must be absolute".into()));
            }
            reject_symlink_components(root)?;
            let root = canonicalize_existing_or_missing(root)?;
            if !root.starts_with(&workspace) {
                return Err(Error::Config(
                    "snapshot roots must remain inside the workspace".into(),
                ));
            }
            if !root.is_dir() {
                return Err(Error::Config(
                    "snapshot roots must be existing directories".into(),
                ));
            }
        }
        let mut canonical_excluded = Vec::with_capacity(self.excluded_roots.len());
        for root in &self.excluded_roots {
            if !root.is_absolute() {
                return Err(Error::Config("snapshot exclusions must be absolute".into()));
            }
            reject_symlink_components(root)?;
            let root = canonicalize_existing_or_missing(root)?;
            if !root.starts_with(&workspace) {
                return Err(Error::Config(
                    "snapshot exclusions must remain inside the workspace".into(),
                ));
            }
            if path_exists_without_symlink(&root)? && !root.is_dir() {
                return Err(Error::Config(
                    "snapshot exclusions must be directories".into(),
                ));
            }
            canonical_excluded.push(root);
        }
        if self.roots.iter().any(|root| {
            let root = canonicalize_existing_or_missing(root).unwrap_or_else(|_| root.clone());
            canonical_excluded
                .iter()
                .any(|excluded| root.starts_with(excluded))
        }) {
            return Err(Error::Config(
                "snapshot roots must not be inside an excluded directory".into(),
            ));
        }
        for pattern in &self.forbidden_globs {
            if pattern.chars().any(char::is_control) {
                return Err(Error::Config(
                    "snapshot forbidden glob contains control characters".into(),
                ));
            }
            Glob::new(pattern)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackOperationStatus {
    InProgress,
    Applied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackOperation {
    pub schema_version: u32,
    pub rollback_id: String,
    pub checkpoint_id: String,
    pub status: RollbackOperationStatus,
    pub workspace_digest: String,
    /// Optional transition-node binding. It is written in the in-progress
    /// operation before restore begins so a crash after the workspace write
    /// can be reconciled by an operator instead of becoming an untraceable
    /// successful rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_session_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_event_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

impl RollbackOperation {
    fn new(
        rollback_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
        workspace_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: ROLLBACK_OPERATION_SCHEMA_VERSION,
            rollback_id: rollback_id.into(),
            checkpoint_id: checkpoint_id.into(),
            status: RollbackOperationStatus::InProgress,
            workspace_digest: workspace_digest.into(),
            transition_session_node_id: None,
            transition_event_ref: None,
            error: None,
            created_at: now_rfc3339(),
            completed_at: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ROLLBACK_OPERATION_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported rollback operation schema {}",
                self.schema_version
            )));
        }
        validate_id("rollback_id", &self.rollback_id)?;
        validate_id("checkpoint_id", &self.checkpoint_id)?;
        validate_digest("workspace_digest", &self.workspace_digest)?;
        if let Some(node_id) = &self.transition_session_node_id {
            validate_id("transition_session_node_id", node_id)?;
        }
        if let Some(event_ref) = &self.transition_event_ref {
            event_ref.validate()?;
        }
        if self.transition_session_node_id.is_some() != self.transition_event_ref.is_some() {
            return Err(Error::Config(
                "rollback transition node and event reference must be present together".into(),
            ));
        }
        validate_text("created_at", &self.created_at, 128)?;
        if let Some(error) = &self.error {
            validate_text("rollback.error", error, 4_096)?;
        }
        if let Some(completed_at) = &self.completed_at {
            validate_text("completed_at", completed_at, 128)?;
        }
        match (
            self.status,
            self.completed_at.is_some(),
            self.error.is_some(),
        ) {
            (RollbackOperationStatus::InProgress, false, false)
            | (RollbackOperationStatus::Applied, true, false)
            | (RollbackOperationStatus::Failed, true, true) => Ok(()),
            _ => Err(Error::Config(
                "rollback operation status, error, and completed_at are inconsistent".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecord {
    pub schema_version: u32,
    pub effect_id: String,
    pub run_id: String,
    pub action_digest: String,
    pub effect_scope: String,
    pub reversibility: String,
    pub external_mutation: bool,
    pub event_ref: EventRef,
    pub recorded_at: String,
}

impl EffectRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ARTIFACT_STORE_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported effect record schema {}",
                self.schema_version
            )));
        }
        validate_id("effect_id", &self.effect_id)?;
        validate_id("run_id", &self.run_id)?;
        validate_digest("action_digest", &self.action_digest)?;
        if !matches!(
            self.effect_scope.as_str(),
            "workspace" | "session" | "process_read" | "external_read" | "external_mutation"
        ) || !matches!(
            self.reversibility.as_str(),
            "no_effect" | "reversible" | "irreversible"
        ) {
            return Err(Error::Config("effect record has an unknown scope".into()));
        }
        if self.external_mutation
            && (self.effect_scope != "external_mutation" || self.reversibility != "irreversible")
        {
            return Err(Error::Config(
                "external mutation effect record is inconsistent".into(),
            ));
        }
        if self.effect_scope == "external_mutation" && !self.external_mutation {
            return Err(Error::Config(
                "external mutation scope must set external_mutation=true".into(),
            ));
        }
        self.event_ref.validate()?;
        if self.event_ref.run_id != self.run_id {
            return Err(Error::Config(
                "effect event reference must belong to the same run".into(),
            ));
        }
        validate_text("recorded_at", &self.recorded_at, 128)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreDisposition {
    Applied,
    AlreadyApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreResult {
    pub disposition: RestoreDisposition,
    pub operation: RollbackOperation,
}

#[derive(Debug, Clone)]
struct SnapshotData {
    entries: Vec<CheckpointFileEntry>,
    blobs: Vec<(String, Vec<u8>)>,
}

/// A filesystem-backed, content-addressed Artifact store.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    operation_lock: Arc<Mutex<()>>,
}

/// A fail-closed cross-process transaction marker. The marker is removed on
/// normal return; a process crash intentionally leaves it behind so a later
/// operator must inspect the in-progress operation instead of guessing.
struct StoreProcessLock {
    path: PathBuf,
    file: Option<File>,
}

impl StoreProcessLock {
    fn acquire(root: &Path) -> Result<Self> {
        let path = root.join(".rollback-operation.lock");
        reject_symlink_components(&path)?;
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::Other(
                    "another artifact transaction is active or requires operator recovery".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = file
            .write_all(format!("pid={}\n", std::process::id()).as_bytes())
            .and_then(|_| file.sync_all())
        {
            let _ = fs::remove_file(&path);
            return Err(error.into());
        }
        Ok(Self {
            path,
            file: Some(file),
        })
    }
}

impl Drop for StoreProcessLock {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
        let _ = sync_directory(self.path.parent().unwrap_or(Path::new(".")));
    }
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return Err(Error::Config(
                "artifact store root must be an absolute path".into(),
            ));
        }
        reject_symlink_components(&root)?;
        fs::create_dir_all(&root)?;
        // Re-check after creation so a symlink swapped into a missing path
        // cannot redirect the store before the first ledger/artifact write.
        reject_symlink_components(&root)?;
        let canonical = fs::canonicalize(&root)?;
        if !canonical.is_dir() {
            return Err(Error::Config(
                "artifact store root must be a directory".into(),
            ));
        }
        reject_symlink_components(&canonical)?;
        Ok(Self {
            root: canonical,
            operation_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Capture a workspace snapshot and atomically publish its manifest and
    /// content-addressed blobs. No checkpoint directory is visible until all
    /// files, the manifest, and an optional session node have been persisted.
    pub fn commit_snapshot(
        &self,
        request: &SnapshotRequest,
        artifact: CheckpointArtifact,
    ) -> Result<CheckpointArtifact> {
        self.commit_snapshot_with_node(request, artifact, None)
    }

    pub fn commit_snapshot_with_node(
        &self,
        request: &SnapshotRequest,
        mut artifact: CheckpointArtifact,
        session_node: Option<&SessionNode>,
    ) -> Result<CheckpointArtifact> {
        let _operation_guard = self
            .operation_lock
            .lock()
            .map_err(|_| Error::Other("artifact operation lock is poisoned".into()))?;
        let _process_lock = StoreProcessLock::acquire(&self.root)?;
        request.validate()?;
        if !artifact.file_entries.is_empty()
            || artifact.state != ArtifactState::Complete
            || artifact.workspace != request.workspace
        {
            return Err(Error::Config(
                "snapshot artifact must be a new complete artifact for the requested workspace"
                    .into(),
            ));
        }
        if let Some(node) = session_node {
            validate_session_node_for_artifact(node, &artifact)?;
        }
        validate_id("checkpoint_id", &artifact.checkpoint_id)?;
        let checkpoint_dir = self.checkpoint_dir(&artifact.checkpoint_id)?;
        reject_symlink_components(&checkpoint_dir)?;
        if path_exists_without_symlink(&checkpoint_dir)? {
            return Err(Error::Config(format!(
                "checkpoint already exists: {}",
                artifact.checkpoint_id
            )));
        }

        let data = collect_snapshot(request)?;
        artifact.file_entries = data.entries;
        artifact.snapshot_digest = entries_digest(&artifact.file_entries)?;
        artifact.workspace_digest = Some(artifact.snapshot_digest.clone());
        artifact.validate_limits(
            request.limits.max_snapshot_bytes,
            request.limits.max_snapshot_files,
            request.limits.max_snapshot_file_bytes,
        )?;
        artifact.validate()?;

        let temporary = self.temporary_dir(&artifact.checkpoint_id)?;
        let result = (|| -> Result<()> {
            fs::create_dir(&temporary)?;
            let blob_dir = temporary.join("blobs");
            fs::create_dir(&blob_dir)?;
            for (digest, bytes) in &data.blobs {
                write_new_file(&blob_dir.join(digest), bytes)?;
            }
            let manifest = serialize_bounded(
                &artifact,
                MAX_ARTIFACT_MANIFEST_BYTES,
                "checkpoint manifest",
            )?;
            write_new_file(&temporary.join("manifest.json"), &manifest)?;
            if let Some(node) = session_node {
                let node_bytes =
                    serialize_bounded(node, MAX_SESSION_NODE_BYTES, "checkpoint session node")?;
                write_new_file(&temporary.join("session-node.json"), &node_bytes)?;
            }
            sync_directory(&temporary)?;
            reject_symlink_components(&checkpoint_dir)?;
            fs::rename(&temporary, &checkpoint_dir)?;
            reject_symlink_components(&checkpoint_dir)?;
            sync_directory(&self.root)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result?;
        if let Some(node) = session_node {
            if let Err(error) = self.save_session_node_unlocked(node) {
                // The embedded node makes the directory self-describing, but a
                // published checkpoint without its independently addressable
                // session ledger is not a complete logical commit.
                let _ = fs::remove_dir_all(&checkpoint_dir);
                return Err(error);
            }
            // The marker is written only after the manifest, embedded node,
            // and standalone session ledger are durable. A crash before this
            // point leaves an untrusted directory that load_checkpoint refuses
            // instead of treating it as a complete rollback source.
            let marker = checkpoint_dir.join("COMMITTED");
            if let Err(error) = write_atomic(&marker, CHECKPOINT_COMMIT_MARKER.as_bytes()) {
                let _ = self.remove_session_node_file(&node.session_node_id);
                let _ = fs::remove_dir_all(&checkpoint_dir);
                return Err(error);
            }
            if let Err(error) = sync_directory(&checkpoint_dir) {
                let _ = self.remove_session_node_file(&node.session_node_id);
                let _ = fs::remove_dir_all(&checkpoint_dir);
                return Err(error);
            }
        }
        Ok(artifact)
    }

    pub fn load_checkpoint(&self, checkpoint_id: &str) -> Result<CheckpointArtifact> {
        validate_id("checkpoint_id", checkpoint_id)?;
        let directory = self.checkpoint_dir(checkpoint_id)?;
        reject_symlink_components(&directory)?;
        let manifest_path = directory.join("manifest.json");
        reject_symlink_components(&manifest_path)?;
        let bytes = read_regular_file_bounded(&manifest_path, MAX_ARTIFACT_MANIFEST_BYTES as u64)?;
        if bytes.len() > MAX_ARTIFACT_MANIFEST_BYTES {
            return Err(Error::Other("checkpoint manifest is too large".into()));
        }
        let artifact: CheckpointArtifact = serde_json::from_slice(&bytes)?;
        if artifact.checkpoint_id != checkpoint_id {
            return Err(Error::Config(
                "checkpoint manifest id does not match its path".into(),
            ));
        }
        self.verify_commit_marker(&directory, Some(&artifact))?;
        self.verify_checkpoint(&artifact)?;
        Ok(artifact)
    }

    fn verify_commit_marker(
        &self,
        directory: &Path,
        artifact: Option<&CheckpointArtifact>,
    ) -> Result<()> {
        let embedded_node = directory.join("session-node.json");
        let marker = directory.join("COMMITTED");
        let embedded_exists = match fs::symlink_metadata(&embedded_node) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Config(
                        "checkpoint embedded session node must not be a symlink".into(),
                    ));
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if embedded_exists {
            let bytes = read_regular_file_bounded(&marker, 32)?;
            if bytes != CHECKPOINT_COMMIT_MARKER.as_bytes() {
                return Err(Error::Config(
                    "checkpoint session commit marker is missing or invalid".into(),
                ));
            }
            if let Some(artifact) = artifact {
                let node_bytes =
                    read_regular_file_bounded(&embedded_node, MAX_SESSION_NODE_BYTES as u64)?;
                let node: SessionNode = serde_json::from_slice(&node_bytes)?;
                node.validate()?;
                validate_session_node_for_artifact(&node, artifact)?;
                let standalone = self
                    .load_session_node_by_id(&node.session_node_id)?
                    .ok_or_else(|| {
                        Error::Config("checkpoint standalone session node ledger is missing".into())
                    })?;
                if standalone != node {
                    return Err(Error::Config(
                        "checkpoint embedded and standalone session nodes differ".into(),
                    ));
                }
            }
        } else {
            match fs::symlink_metadata(&marker) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::Config(
                        "checkpoint commit marker must not be a symlink".into(),
                    ));
                }
                Ok(_) => {
                    return Err(Error::Config(
                        "checkpoint commit marker has no embedded session node".into(),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn remove_session_node_file(&self, session_node_id: &str) -> Result<()> {
        let path = self
            .root
            .join("sessions")
            .join(format!("{}.json", safe_id(session_node_id)?));
        reject_symlink_components(&path)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn verify_checkpoint(&self, artifact: &CheckpointArtifact) -> Result<()> {
        artifact.validate()?;
        artifact.validate_limits(
            MAX_SNAPSHOT_BYTES,
            MAX_SNAPSHOT_FILES,
            MAX_SNAPSHOT_FILE_BYTES,
        )?;
        let directory = self.checkpoint_dir(&artifact.checkpoint_id)?;
        self.verify_commit_marker(&directory, Some(artifact))?;
        reject_symlink_components(&artifact.workspace)?;
        if !artifact.workspace.is_dir() {
            return Err(Error::Config(
                "checkpoint workspace is not an existing directory".into(),
            ));
        }
        if artifact.state != ArtifactState::Complete {
            return Err(Error::Config(
                "incomplete checkpoint artifacts cannot be used".into(),
            ));
        }
        let expected = entries_digest(&artifact.file_entries)?;
        if expected != artifact.snapshot_digest {
            return Err(Error::Config(
                "checkpoint snapshot digest does not match its entries".into(),
            ));
        }
        if let Some(workspace_digest) = &artifact.workspace_digest {
            validate_digest("workspace_digest", workspace_digest)?;
            if workspace_digest != &artifact.snapshot_digest {
                return Err(Error::Config(
                    "checkpoint workspace digest does not match its snapshot".into(),
                ));
            }
        }
        reject_symlink_components(&directory)?;
        let mut seen = HashSet::new();
        let mut verified_blobs = HashMap::<String, u64>::new();
        for entry in &artifact.file_entries {
            entry.validate()?;
            if !seen.insert(entry.path.as_str()) {
                return Err(Error::Config("checkpoint contains duplicate paths".into()));
            }
            if entry.file_type == CheckpointFileType::Directory {
                continue;
            }
            let blob = blob_path(&directory, &entry.blob_ref, &entry.content_sha256)?;
            if let Some(verified_size) = verified_blobs.get(&entry.content_sha256) {
                if *verified_size != entry.size {
                    return Err(Error::Config(
                        "checkpoint reuses a blob with inconsistent metadata".into(),
                    ));
                }
                continue;
            }
            let metadata = fs::symlink_metadata(&blob)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::Config(
                    "checkpoint blob is not a regular file".into(),
                ));
            }
            if metadata.len() != entry.size {
                return Err(Error::Config("checkpoint blob size mismatch".into()));
            }
            let bytes = read_regular_file_bounded(&blob, MAX_CHECKPOINT_BLOB_BYTES)?;
            if bytes.len() as u64 != entry.size || digest_bytes(&bytes) != entry.content_sha256 {
                return Err(Error::Config("checkpoint blob hash mismatch".into()));
            }
            verified_blobs.insert(entry.content_sha256.clone(), entry.size);
        }
        Ok(())
    }

    pub fn load_session_node(&self, checkpoint_id: &str) -> Result<SessionNode> {
        let directory = self.checkpoint_dir(checkpoint_id)?;
        let path = directory.join("session-node.json");
        reject_symlink_components(&path)?;
        let bytes = read_regular_file_bounded(&path, MAX_SESSION_NODE_BYTES as u64)?;
        let node: SessionNode = serde_json::from_slice(&bytes)?;
        node.validate()?;
        let artifact = self.load_checkpoint(checkpoint_id)?;
        validate_session_node_for_artifact(&node, &artifact)?;
        Ok(node)
    }

    /// Load a session node by its globally unique id. Session nodes are kept
    /// in a separate immutable ledger so a rollback can name the current
    /// source node even when the target checkpoint is older.
    pub fn load_session_node_by_id(&self, session_node_id: &str) -> Result<Option<SessionNode>> {
        validate_id("session_node_id", session_node_id)?;
        let sessions = self.root.join("sessions");
        if !path_exists_without_symlink(&sessions)? {
            return Ok(None);
        }
        let path = sessions.join(format!("{}.json", safe_id(session_node_id)?));
        if !path_exists_without_symlink(&path)? {
            return Ok(None);
        }
        let node: SessionNode = serde_json::from_slice(&read_regular_file_bounded(
            &path,
            MAX_SESSION_NODE_BYTES as u64,
        )?)?;
        node.validate()?;
        if node.session_node_id != session_node_id {
            return Err(Error::Config(
                "session node id does not match its ledger path".into(),
            ));
        }
        Ok(Some(node))
    }

    /// Persist an immutable session node independently of a checkpoint. This
    /// is used for the post-rollback transition node.
    pub fn save_session_node(&self, node: &SessionNode) -> Result<()> {
        let _operation_guard = self
            .operation_lock
            .lock()
            .map_err(|_| Error::Other("artifact operation lock is poisoned".into()))?;
        let _process_lock = StoreProcessLock::acquire(&self.root)?;
        self.save_session_node_unlocked(node)
    }

    fn save_session_node_unlocked(&self, node: &SessionNode) -> Result<()> {
        node.validate()?;
        validate_id("session_node_id", &node.session_node_id)?;
        let sessions = self.root.join("sessions");
        if !path_exists_without_symlink(&sessions)? {
            fs::create_dir(&sessions)?;
        }
        reject_symlink_components(&sessions)?;
        let path = sessions.join(format!("{}.json", safe_id(&node.session_node_id)?));
        if path_exists_without_symlink(&path)? {
            let existing: SessionNode = serde_json::from_slice(&read_regular_file_bounded(
                &path,
                MAX_SESSION_NODE_BYTES as u64,
            )?)?;
            if existing != *node {
                return Err(Error::Config(
                    "session node is immutable and cannot be replaced".into(),
                ));
            }
            return Ok(());
        }
        let bytes = serialize_bounded(node, MAX_SESSION_NODE_BYTES, "session node ledger record")?;
        write_atomic(&path, &bytes)
    }

    pub fn compute_workspace_digest(&self, request: &SnapshotRequest) -> Result<String> {
        request.validate()?;
        let snapshot = collect_snapshot(request)?;
        entries_digest(&snapshot.entries)
    }

    /// Append an immutable effect declaration. External mutation is recorded
    /// after approval and before execution, so a crash cannot make a later
    /// rollback believe that the external side effect never happened.
    pub fn record_effect(&self, record: &EffectRecord) -> Result<()> {
        record.validate()?;
        if !record.external_mutation {
            return Ok(());
        }
        let _process_lock = StoreProcessLock::acquire(&self.root)?;
        if let Some(previous) = self
            .read_effect_records()?
            .into_iter()
            .find(|candidate| candidate.effect_id == record.effect_id)
        {
            if &previous != record {
                return Err(Error::Config(
                    "effect ledger contains conflicting immutable records".into(),
                ));
            }
            return Ok(());
        }
        let path = self.root.join("effects.jsonl");
        reject_symlink_components(&path)?;
        let mut line = serialize_bounded(record, MAX_EFFECT_LEDGER_BYTES, "effect ledger record")?;
        line.push(b'\n');
        append_bounded_line(&path, &line, MAX_EFFECT_LEDGER_BYTES)?;
        Ok(())
    }

    pub fn record_failure(&self, record: &FailedPathRecord) -> Result<FailedPathRecord> {
        record.validate()?;
        let _process_lock = StoreProcessLock::acquire(&self.root)?;
        let path = self.root.join(FAILED_PATH_LEDGER_FILE);
        reject_symlink_components(&path)?;
        let records = self.failed_path_records(&record.run_id)?;
        let existing = records
            .iter()
            .find(|candidate| candidate.failure_id == record.failure_id)
            .cloned();
        let mut stored = record.clone();
        if let Some(mut previous) = existing {
            if !same_failed_path_identity(&previous, &stored) {
                return Err(Error::Config(
                    "failed-path ledger contains conflicting immutable identities".into(),
                ));
            }
            if stored.status != FailedPathStatus::Active {
                return Err(Error::Config(
                    "failed-path ledger can only append active retry records".into(),
                ));
            }
            if previous.status == FailedPathStatus::Superseded {
                return Err(Error::Config(
                    "superseded failed-path records cannot be reactivated".into(),
                ));
            }
            previous.attempt_count = previous
                .attempt_count
                .checked_add(1)
                .ok_or_else(|| Error::Other("failed-path attempt count overflowed".into()))?;
            previous.last_seen_event_ref = record.last_seen_event_ref.clone();
            stored = previous;
        }
        let mut line = serialize_bounded(
            &stored,
            MAX_ROLLBACK_OPERATION_BYTES,
            "failed-path ledger record",
        )?;
        line.push(b'\n');
        append_bounded_line(&path, &line, MAX_ROLLBACK_OPERATION_BYTES)?;
        Ok(stored)
    }

    /// Load the latest immutable record for a failure id within one run.
    /// Superseded records remain auditable and can be referenced by an
    /// operator rollback, but a missing or cross-run reference fails closed.
    pub fn load_failed_path(
        &self,
        run_id: &str,
        failure_id: &str,
    ) -> Result<Option<FailedPathRecord>> {
        validate_id("run_id", run_id)?;
        validate_id("failure_id", failure_id)?;
        Ok(self
            .failed_path_records(run_id)?
            .into_iter()
            .find(|record| record.failure_id == failure_id))
    }

    pub fn find_active_failure(
        &self,
        run_id: &str,
        tool: &str,
        canonical_args_digest: &str,
        resource_digest: &str,
        contract_digest: &str,
        policy_digest: &str,
    ) -> Result<Option<FailedPathRecord>> {
        validate_id("run_id", run_id)?;
        validate_digest("canonical_args_digest", canonical_args_digest)?;
        validate_digest("resource_digest", resource_digest)?;
        validate_digest("contract_digest", contract_digest)?;
        validate_digest("policy_digest", policy_digest)?;
        Ok(self
            .failed_path_records(run_id)?
            .into_iter()
            .rev()
            .find(|record| {
                record.status == FailedPathStatus::Active
                    && record.tool == tool
                    && record.canonical_args_digest == canonical_args_digest
                    && record.resource_digest == resource_digest
                    && record.contract_digest == contract_digest
                    && record.policy_digest == policy_digest
            }))
    }

    fn failed_path_records(&self, run_id: &str) -> Result<Vec<FailedPathRecord>> {
        let path = self.root.join(FAILED_PATH_LEDGER_FILE);
        if !path_exists_without_symlink(&path)? {
            return Ok(Vec::new());
        }
        let bytes = read_regular_file_bounded(&path, MAX_FAILED_PATH_LEDGER_BYTES as u64)?;
        if bytes.len() > MAX_FAILED_PATH_LEDGER_BYTES {
            return Err(Error::Other(
                "failed-path ledger exceeds the size limit".into(),
            ));
        }
        let text = String::from_utf8(bytes)
            .map_err(|error| Error::Other(format!("failed-path ledger is not UTF-8: {error}")))?;
        let mut latest = BTreeMap::<String, FailedPathRecord>::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: FailedPathRecord = serde_json::from_str(line)?;
            record.validate()?;
            if record.run_id != run_id {
                continue;
            }
            if let Some(previous) = latest.get(&record.failure_id) {
                if !same_failed_path_identity(previous, &record) {
                    return Err(Error::Config(
                        "failed-path ledger contains conflicting immutable identities".into(),
                    ));
                }
                if previous.first_seen_event_ref != record.first_seen_event_ref {
                    return Err(Error::Config(
                        "failed-path ledger contains a changed first-seen event reference".into(),
                    ));
                }
                if previous.status == FailedPathStatus::Superseded
                    && (record.status != FailedPathStatus::Superseded
                        || previous.superseded_by != record.superseded_by)
                {
                    return Err(Error::Config(
                        "failed-path ledger contains a conflicting supersession transition".into(),
                    ));
                }
                if record.attempt_count < previous.attempt_count
                    || (previous.status == FailedPathStatus::Superseded
                        && record.status == FailedPathStatus::Active)
                {
                    return Err(Error::Config(
                        "failed-path ledger contains a regressed immutable record".into(),
                    ));
                }
            }
            latest.insert(record.failure_id.clone(), record);
        }
        Ok(latest.into_values().collect())
    }

    pub fn has_external_effect_after(&self, artifact: &CheckpointArtifact) -> Result<bool> {
        artifact.validate()?;
        let target_seq = artifact.event_ref.seq;
        for record in self.read_effect_records()? {
            if !record.external_mutation || record.run_id != artifact.run_id {
                continue;
            }
            let after = match (target_seq, record.event_ref.seq) {
                (Some(target), Some(effect)) => effect > target,
                _ => true,
            };
            if after {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_effect_records(&self) -> Result<Vec<EffectRecord>> {
        let path = self.root.join("effects.jsonl");
        if !path_exists_without_symlink(&path)? {
            return Ok(Vec::new());
        }
        let bytes = read_regular_file_bounded(&path, MAX_EFFECT_LEDGER_BYTES as u64)?;
        if bytes.len() > MAX_EFFECT_LEDGER_BYTES {
            return Err(Error::Other("effect ledger exceeds the size limit".into()));
        }
        let text = String::from_utf8(bytes)
            .map_err(|error| Error::Other(format!("effect ledger is not UTF-8: {error}")))?;
        let mut seen_effects = HashMap::<String, EffectRecord>::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: EffectRecord = serde_json::from_str(line)?;
            record.validate()?;
            if let Some(previous) = seen_effects.get(&record.effect_id) {
                if previous != &record {
                    return Err(Error::Config(
                        "effect ledger contains conflicting immutable records".into(),
                    ));
                }
            } else {
                seen_effects.insert(record.effect_id.clone(), record.clone());
            }
        }
        Ok(seen_effects.into_values().collect())
    }

    pub fn load_operation(
        &self,
        checkpoint_id: &str,
        rollback_id: &str,
    ) -> Result<Option<RollbackOperation>> {
        validate_id("checkpoint_id", checkpoint_id)?;
        let process_lock_path = self.root.join(".rollback-operation.lock");
        reject_symlink_components(&process_lock_path)?;
        if path_exists_without_symlink(&process_lock_path)? {
            return Err(Error::Other(
                "another artifact transaction is active or requires operator recovery".into(),
            ));
        }
        let path = self.operation_path(rollback_id)?;
        reject_symlink_components(&path)?;
        if !path_exists_without_symlink(&path)? {
            return Ok(None);
        }
        let operation: RollbackOperation = serde_json::from_slice(&read_regular_file_bounded(
            &path,
            MAX_ROLLBACK_OPERATION_BYTES as u64,
        )?)?;
        operation.validate()?;
        if operation.rollback_id != rollback_id {
            return Err(Error::Config(
                "rollback operation id does not match its ledger path".into(),
            ));
        }
        if operation.checkpoint_id != checkpoint_id {
            return Err(Error::Config(
                "rollback id is bound to another checkpoint".into(),
            ));
        }
        Ok(Some(operation))
    }

    /// Restore a complete artifact after a compare-and-swap check. The
    /// operation ledger makes a repeated `(checkpoint_id, rollback_id)` a
    /// deterministic no-op and prevents automatic retries after failure.
    pub fn restore_checkpoint(
        &self,
        request: &SnapshotRequest,
        artifact: &CheckpointArtifact,
        rollback_id: &str,
    ) -> Result<RestoreResult> {
        let expected_digest = artifact
            .workspace_digest
            .as_deref()
            .ok_or_else(|| {
                Error::Config("runtime checkpoint is missing its workspace digest".into())
            })?
            .to_owned();
        self.restore_checkpoint_with_expected(request, artifact, rollback_id, &expected_digest)
    }

    /// Restore a complete artifact after comparing the current workspace to
    /// the source checkpoint's digest. The target snapshot may be older than
    /// the source, so the source digest must be supplied explicitly.
    pub fn restore_checkpoint_with_expected(
        &self,
        request: &SnapshotRequest,
        artifact: &CheckpointArtifact,
        rollback_id: &str,
        expected_current_digest: &str,
    ) -> Result<RestoreResult> {
        self.restore_checkpoint_with_expected_and_transition(
            request,
            artifact,
            rollback_id,
            expected_current_digest,
            None,
            None,
        )
    }

    /// Restore a checkpoint while recording the immutable post-rollback node
    /// binding in the operation ledger before any workspace mutation. The
    /// binding makes a crash between the restore and standalone node write
    /// recoverable without guessing from a bare rollback id.
    pub fn restore_checkpoint_with_expected_and_transition(
        &self,
        request: &SnapshotRequest,
        artifact: &CheckpointArtifact,
        rollback_id: &str,
        expected_current_digest: &str,
        transition_session_node_id: Option<&str>,
        transition_event_ref: Option<&EventRef>,
    ) -> Result<RestoreResult> {
        let _operation_guard = self
            .operation_lock
            .lock()
            .map_err(|_| Error::Other("artifact operation lock is poisoned".into()))?;
        let _process_lock = StoreProcessLock::acquire(&self.root)?;
        request.validate()?;
        artifact.validate_limits(
            request.limits.max_snapshot_bytes,
            request.limits.max_snapshot_files,
            request.limits.max_snapshot_file_bytes,
        )?;
        validate_id("rollback_id", rollback_id)?;
        validate_digest("expected_current_digest", expected_current_digest)?;
        if transition_session_node_id.is_some() != transition_event_ref.is_some() {
            return Err(Error::Config(
                "rollback transition node and event reference must be present together".into(),
            ));
        }
        if let Some(node_id) = transition_session_node_id {
            validate_id("transition_session_node_id", node_id)?;
        }
        if let Some(event_ref) = transition_event_ref {
            event_ref.validate()?;
            if event_ref.run_id != artifact.run_id {
                return Err(Error::Config(
                    "rollback transition event must belong to the target run".into(),
                ));
            }
        }
        if artifact.workspace != request.workspace {
            return Err(Error::Config(
                "checkpoint workspace does not match restore workspace".into(),
            ));
        }
        self.verify_checkpoint(artifact)?;
        let operation_path = self.operation_path(rollback_id)?;
        reject_symlink_components(&operation_path)?;
        if path_exists_without_symlink(&operation_path)? {
            let existing: RollbackOperation = serde_json::from_slice(&read_regular_file_bounded(
                &operation_path,
                MAX_ROLLBACK_OPERATION_BYTES as u64,
            )?)?;
            existing.validate()?;
            if existing.rollback_id != rollback_id {
                return Err(Error::Config(
                    "rollback operation id does not match its ledger path".into(),
                ));
            }
            if existing.checkpoint_id != artifact.checkpoint_id {
                return Err(Error::Config(
                    "rollback id is already bound to another checkpoint".into(),
                ));
            }
            if existing
                .transition_event_ref
                .as_ref()
                .is_some_and(|event_ref| event_ref.run_id != artifact.run_id)
            {
                return Err(Error::Config(
                    "rollback operation transition event belongs to another run".into(),
                ));
            }
            if let (Some(node_id), Some(event_ref)) =
                (transition_session_node_id, transition_event_ref)
            {
                if existing.transition_session_node_id.as_deref() != Some(node_id)
                    || existing.transition_event_ref.as_ref() != Some(event_ref)
                {
                    return Err(Error::Config(
                        "rollback operation has a conflicting transition binding".into(),
                    ));
                }
            }
            return match existing.status {
                RollbackOperationStatus::Applied => Ok(RestoreResult {
                    disposition: RestoreDisposition::AlreadyApplied,
                    operation: existing,
                }),
                RollbackOperationStatus::InProgress => Err(Error::Other(
                    "rollback operation is already in progress".into(),
                )),
                RollbackOperationStatus::Failed => Err(Error::Other(
                    "rollback operation previously failed and will not be retried".into(),
                )),
            };
        }

        // Re-check the external-effect ledger while holding the transaction
        // lock. The Agent performs an early check for a useful audit trail,
        // but this closes the race with an effect recorded during policy or
        // approval.
        if self.has_external_effect_after(artifact)? {
            return Err(Error::Other(
                "rollback is blocked because an irreversible external effect occurred after the checkpoint"
                    .into(),
            ));
        }
        let current_digest = self.compute_workspace_digest(request)?;
        if current_digest != expected_current_digest {
            return Err(Error::Other(
                "rollback compare-and-swap check failed: workspace changed since checkpoint".into(),
            ));
        }

        let mut operation =
            RollbackOperation::new(rollback_id, &artifact.checkpoint_id, &current_digest);
        operation.transition_session_node_id = transition_session_node_id.map(str::to_owned);
        operation.transition_event_ref = transition_event_ref.cloned();
        operation.validate()?;
        write_atomic(
            &operation_path,
            &serialize_bounded(
                &operation,
                MAX_ROLLBACK_OPERATION_BYTES,
                "rollback operation record",
            )?,
        )?;
        let temporary = self.temporary_dir(rollback_id)?;
        let result = (|| -> Result<()> {
            fs::create_dir(&temporary)?;
            stage_snapshot(
                &self.checkpoint_dir(&artifact.checkpoint_id)?,
                artifact,
                &temporary,
            )?;
            apply_snapshot(request, artifact, &temporary)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                operation.status = RollbackOperationStatus::Applied;
                operation.completed_at = Some(now_rfc3339());
                write_atomic(
                    &operation_path,
                    &serialize_bounded(
                        &operation,
                        MAX_ROLLBACK_OPERATION_BYTES,
                        "rollback operation record",
                    )?,
                )?;
                let _ = fs::remove_dir_all(&temporary);
                Ok(RestoreResult {
                    disposition: RestoreDisposition::Applied,
                    operation,
                })
            }
            Err(error) => {
                operation.status = RollbackOperationStatus::Failed;
                operation.error = Some(crate::truncate_middle(
                    &redact_text(&error.to_string()),
                    4096,
                ));
                operation.completed_at = Some(now_rfc3339());
                let _ = write_atomic(
                    &operation_path,
                    &serialize_bounded(
                        &operation,
                        MAX_ROLLBACK_OPERATION_BYTES,
                        "rollback operation record",
                    )?,
                );
                let _ = fs::remove_dir_all(&temporary);
                Err(error)
            }
        }
    }

    fn checkpoint_dir(&self, checkpoint_id: &str) -> Result<PathBuf> {
        validate_id("checkpoint_id", checkpoint_id)?;
        Ok(self.root.join(safe_id(checkpoint_id)?))
    }

    fn operation_path(&self, rollback_id: &str) -> Result<PathBuf> {
        validate_id("rollback_id", rollback_id)?;
        Ok(self
            .root
            .join("operations")
            .join(format!("{}.json", safe_id(rollback_id)?)))
    }

    fn temporary_dir(&self, label: &str) -> Result<PathBuf> {
        let label = safe_id(label)?;
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| Error::Other(format!("system clock error: {error}")))?
            .as_nanos();
        Ok(self
            .root
            .join(format!(".tmp-{label}-{}-{nonce}", nanos % 1_000_000_000)))
    }
}

fn collect_snapshot(request: &SnapshotRequest) -> Result<SnapshotData> {
    let workspace = fs::canonicalize(&request.workspace)?;
    let mut roots = request.roots.clone();
    for root in roots.iter_mut() {
        let canonical = fs::canonicalize(&*root)?;
        if !canonical.starts_with(&workspace) {
            return Err(Error::Config(
                "snapshot root changed outside the workspace".into(),
            ));
        }
        *root = canonical;
    }
    roots.sort();
    roots.dedup();
    let excluded_roots = request
        .excluded_roots
        .iter()
        .map(|path| canonicalize_existing_or_missing(path))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for excluded in &excluded_roots {
        if !excluded.starts_with(&workspace) {
            return Err(Error::Config(
                "snapshot exclusion changed outside the workspace".into(),
            ));
        }
    }
    let mut forbidden = Vec::with_capacity(request.forbidden_globs.len());
    for pattern in &request.forbidden_globs {
        forbidden.push(Glob::new(pattern)?);
    }
    let mut entries = BTreeMap::<String, CheckpointFileEntry>::new();
    let mut blobs = BTreeMap::<String, Vec<u8>>::new();
    let mut total_bytes = 0u64;
    let mut visited = 0usize;
    for root in roots {
        if is_excluded(&root, &excluded_roots) || !root.is_dir() {
            continue;
        }
        collect_directory(
            &workspace,
            &root,
            &excluded_roots,
            &forbidden,
            request.limits,
            &mut entries,
            &mut blobs,
            &mut total_bytes,
            &mut visited,
            0,
        )?;
    }
    if entries.len() > request.limits.max_snapshot_files {
        return Err(Error::Other("snapshot contains too many entries".into()));
    }
    Ok(SnapshotData {
        entries: entries.into_values().collect(),
        blobs: blobs.into_iter().collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_directory(
    workspace: &Path,
    directory: &Path,
    excluded_roots: &[PathBuf],
    forbidden: &[Glob],
    limits: SnapshotLimits,
    entries: &mut BTreeMap<String, CheckpointFileEntry>,
    blobs: &mut BTreeMap<String, Vec<u8>>,
    total_bytes: &mut u64,
    visited: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth > 128 {
        return Err(Error::Other(
            "snapshot directory depth exceeds limit".into(),
        ));
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Config(
            "snapshot root is not a regular directory".into(),
        ));
    }
    let mut children = Vec::new();
    for entry in fs::read_dir(directory)? {
        children.push(entry?.path());
        if children.len()
            > limits
                .max_snapshot_files
                .saturating_mul(4)
                .max(1)
                .saturating_add(1)
        {
            return Err(Error::Other(
                "snapshot traversal exceeds entry limit".into(),
            ));
        }
    }
    children.sort();
    for child in children {
        *visited = visited.saturating_add(1);
        if *visited > limits.max_snapshot_files.saturating_mul(4).max(1) {
            return Err(Error::Other(
                "snapshot traversal exceeds entry limit".into(),
            ));
        }
        if is_excluded(&child, excluded_roots) {
            continue;
        }
        let relative = relative_path(workspace, &child)?;
        if is_forbidden(&child, &relative, forbidden) {
            continue;
        }
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Config(format!(
                "snapshot encountered a symlink and cannot represent it safely: {relative}"
            )));
        }
        if metadata.is_dir() {
            let mut directory_entry = CheckpointFileEntry::directory(relative.clone());
            directory_entry.permissions = file_permissions(&metadata);
            entries.insert(relative.clone(), directory_entry);
            if entries.len() > limits.max_snapshot_files {
                return Err(Error::Other("snapshot contains too many entries".into()));
            }
            collect_directory(
                workspace,
                &child,
                excluded_roots,
                forbidden,
                limits,
                entries,
                blobs,
                total_bytes,
                visited,
                depth + 1,
            )?;
        } else if metadata.is_file() {
            if metadata.len() > limits.max_snapshot_file_bytes {
                return Err(Error::Other(format!(
                    "snapshot file exceeds per-file limit: {relative}"
                )));
            }
            let bytes = read_regular_file_bounded(&child, limits.max_snapshot_file_bytes)?;
            let digest = digest_bytes(&bytes);
            *total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::Other("snapshot byte count overflowed".into()))?;
            if *total_bytes > limits.max_snapshot_bytes {
                return Err(Error::Other("snapshot exceeds total byte limit".into()));
            }
            let size = bytes.len() as u64;
            blobs.entry(digest.clone()).or_insert(bytes);
            let mut file_entry = CheckpointFileEntry::file(
                relative.clone(),
                size,
                digest.clone(),
                format!("blobs/{digest}"),
            );
            file_entry.permissions = file_permissions(&metadata);
            entries.insert(relative.clone(), file_entry);
            if entries.len() > limits.max_snapshot_files {
                return Err(Error::Other("snapshot contains too many entries".into()));
            }
        } else {
            return Err(Error::Config(format!(
                "snapshot encountered an unsupported filesystem entry: {relative}"
            )));
        }
    }
    Ok(())
}

fn file_permissions(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized artifact size overflowed"))?;
        if next_len > self.limit {
            return Err(std::io::Error::other(
                "serialized artifact exceeds its size limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded<T: Serialize>(value: &T, limit: usize, label: &str) -> Result<Vec<u8>> {
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(limit.min(64 * 1024)),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        Error::Other(format!(
            "{label} exceeds the size limit or cannot be serialized"
        ))
    })?;
    Ok(writer.bytes)
}

fn append_bounded_line(path: &Path, line: &[u8], limit: usize) -> Result<()> {
    if line.len() > limit {
        return Err(Error::Other("ledger line exceeds the size limit".into()));
    }
    reject_symlink_components(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Config("ledger path is not a regular file".into()));
        }
        let new_len = metadata
            .len()
            .checked_add(line.len() as u64)
            .ok_or_else(|| Error::Other("ledger size overflowed".into()))?;
        if new_len > limit as u64 {
            return Err(Error::Other("ledger exceeds the size limit".into()));
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line)?;
    file.sync_all()?;
    Ok(())
}

fn read_file_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Other("snapshot file grew beyond its limit".into()));
    }
    // Recheck after reading so a path replacement cannot silently turn a
    // bounded regular-file read into a symlink or special-file read.
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Other(
            "snapshot file changed while being read".into(),
        ));
    }
    Ok(bytes)
}

fn read_regular_file_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::Config("artifact file is not a regular file".into()));
    }
    if metadata.len() > limit {
        return Err(Error::Other("artifact file exceeds the size limit".into()));
    }
    let bytes = read_file_bounded(path, limit)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Other(
            "artifact file grew beyond its size limit".into(),
        ));
    }
    Ok(bytes)
}

fn entries_digest(entries: &[CheckpointFileEntry]) -> Result<String> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    let bytes = serialize_bounded(
        &sorted,
        MAX_ARTIFACT_MANIFEST_BYTES,
        "snapshot digest input",
    )?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn relative_path(workspace: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| Error::Config("snapshot path is outside the workspace".into()))?;
    let text = relative
        .to_str()
        .ok_or_else(|| Error::Config("snapshot path is not valid UTF-8".into()))?
        .replace('\\', "/");
    if text.is_empty()
        || text.starts_with('/')
        || text
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Config("snapshot path is not normalized".into()));
    }
    Ok(text)
}

fn is_excluded(path: &Path, excluded: &[PathBuf]) -> bool {
    excluded
        .iter()
        .any(|root| path == root || path.starts_with(root))
}

fn is_forbidden(path: &Path, relative: &str, patterns: &[Glob]) -> bool {
    let absolute = path.to_string_lossy().replace('\\', "/");
    patterns
        .iter()
        .any(|pattern| pattern.is_match(&absolute) || pattern.is_match(relative))
}

fn canonicalize_existing_or_missing(path: &Path) -> Result<PathBuf> {
    if path_exists_without_symlink(path)? {
        return Ok(fs::canonicalize(path)?);
    }
    let mut current = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(_) => {
                let mut result = fs::canonicalize(&current)?;
                for component in missing.iter().rev() {
                    result.push(component);
                }
                return Ok(result);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = current
                    .file_name()
                    .ok_or_else(|| Error::Config("cannot resolve snapshot root".into()))?;
                missing.push(name.to_os_string());
                if !current.pop() {
                    return Err(Error::Config("cannot resolve snapshot root".into()));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Config(format!(
                    "artifact path must not contain symlink components: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if !current.pop() {
            break;
        }
    }
    Ok(())
}

fn path_exists_without_symlink(path: &Path) -> Result<bool> {
    reject_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.ends_with('.')
        || value == "."
        || value == ".."
        || is_windows_reserved_id(value)
    {
        return Err(Error::Config(format!(
            "{field} must be a safe, bounded path component"
        )));
    }
    Ok(())
}

fn safe_id(value: &str) -> Result<&str> {
    validate_id("artifact id", value)?;
    Ok(value)
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

fn same_failed_path_identity(left: &FailedPathRecord, right: &FailedPathRecord) -> bool {
    left.schema_version == right.schema_version
        && left.failure_id == right.failure_id
        && left.failure_class == right.failure_class
        && left.tool == right.tool
        && left.canonical_args_digest == right.canonical_args_digest
        && left.resource_digest == right.resource_digest
        && left.contract_digest == right.contract_digest
        && left.policy_digest == right.policy_digest
        && left.run_id == right.run_id
}

fn validate_text(field: &str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::Config(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Config(format!("{field} must be a SHA-256 digest")));
    }
    Ok(())
}

fn blob_path(directory: &Path, blob_ref: &str, digest: &str) -> Result<PathBuf> {
    if blob_ref != format!("blobs/{digest}") {
        return Err(Error::Config(
            "checkpoint blob_ref is not a safe blob path".into(),
        ));
    }
    let relative = Path::new(blob_ref);
    let mut components = relative.components();
    if components.next() != Some(Component::Normal(std::ffi::OsStr::new("blobs")))
        || components.next() != Some(Component::Normal(std::ffi::OsStr::new(digest)))
        || components.next().is_some()
    {
        return Err(Error::Config(
            "checkpoint blob_ref is not a safe blob path".into(),
        ));
    }
    let path = directory.join(relative);
    reject_symlink_components(&path)?;
    Ok(path)
}

fn validate_session_node_for_artifact(
    node: &SessionNode,
    artifact: &CheckpointArtifact,
) -> Result<()> {
    node.validate()?;
    if node.session_node_id != artifact.session_node_id
        || node.event_ref != artifact.event_ref
        || node.checkpoint_id.as_deref() != Some(artifact.checkpoint_id.as_str())
    {
        return Err(Error::Config(
            "session node is not bound to the checkpoint artifact".into(),
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_symlink_components(path)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_symlink_components(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() {
            return Err(Error::Config(
                "artifact destination must be a regular file".into(),
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config("artifact path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    reject_symlink_components(parent)?;
    reject_symlink_components(path)?;
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact"),
        std::process::id(),
        nonce
    ));
    write_new_file(&temporary, bytes)?;
    let result = replace_path(&temporary, path);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_path(source: &Path, destination: &Path) -> Result<()> {
    // POSIX rename replaces an existing regular file atomically.
    fs::rename(source, destination).map_err(Into::into)
}

#[cfg(windows)]
fn stale_replace_backup_exists(destination: &Path) -> Result<bool> {
    let parent = destination
        .parent()
        .ok_or_else(|| Error::Config("replacement destination has no parent".into()))?;
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::Config("replacement destination has no portable name".into()))?;
    let prefix = format!("{file_name}.replace-backup-");
    let mut visited = 0usize;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        visited = visited.saturating_add(1);
        if visited > MAX_REPLACE_BACKUP_SCAN_ENTRIES {
            return Err(Error::Other(
                "replacement backup scan exceeds its bounded entry limit".into(),
            ));
        }
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&prefix) {
            reject_symlink_components(&entry.path())?;
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn replace_path(source: &Path, destination: &Path) -> Result<()> {
    // Windows does not expose a portable std::rename replacement with the
    // same overwrite semantics. Preserve the old destination under a private
    // name first, then install the new file; if the second rename fails,
    // restore the old file instead of deleting it unconditionally. A crash in
    // the small hand-off window leaves the backup for operator inspection and
    // the next operation must be treated as stale/recovery-required.
    // Recheck the destination immediately before the hand-off as well as in
    // write_atomic; a caller may have replaced it with a symlink between
    // those checks.
    reject_symlink_components(destination)?;
    if stale_replace_backup_exists(destination)? {
        return Err(Error::Other(
            "stale Windows replacement backup requires operator recovery".into(),
        ));
    }
    if !path_exists_without_symlink(destination)? {
        return fs::rename(source, destination).map_err(Into::into);
    }
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let backup = destination.with_extension(format!(
        "{}.replace-backup-{}-{nonce}",
        destination
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("tmp"),
        std::process::id()
    ));
    reject_symlink_components(&backup)?;
    if path_exists_without_symlink(&backup)? {
        return Err(Error::Other(
            "stale Windows replacement backup requires operator recovery".into(),
        ));
    }
    fs::rename(destination, &backup)?;
    match fs::rename(source, destination) {
        Ok(()) => {
            fs::remove_file(&backup)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::rename(&backup, destination);
            Err(error.into())
        }
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<()> {
    // Windows does not allow opening a directory as a normal file. The
    // individual artifact files are synced above; the rename is still the
    // publication boundary.
    Ok(())
}

fn stage_snapshot(
    checkpoint_dir: &Path,
    artifact: &CheckpointArtifact,
    staging: &Path,
) -> Result<()> {
    let blob_dir = staging.join("blobs");
    fs::create_dir(&blob_dir)?;
    for entry in &artifact.file_entries {
        if entry.file_type == CheckpointFileType::Directory {
            continue;
        }
        let source = blob_path(checkpoint_dir, &entry.blob_ref, &entry.content_sha256)?;
        reject_symlink_components(&source)?;
        let source_metadata = fs::symlink_metadata(&source)?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(Error::Config(
                "checkpoint blob is not a regular file during staging".into(),
            ));
        }
        let bytes = read_regular_file_bounded(&source, entry.size)?;
        if bytes.len() as u64 != entry.size || digest_bytes(&bytes) != entry.content_sha256 {
            return Err(Error::Config(
                "checkpoint blob changed during staging".into(),
            ));
        }
        let destination = blob_dir.join(staged_file_name(&entry.path, &entry.content_sha256));
        write_new_file(&destination, &bytes)?;
    }
    Ok(())
}

fn staged_file_name(relative: &str, digest: &str) -> String {
    // Hashing the path avoids collisions such as `a/b` versus `a__b` while
    // keeping the staging directory independent of platform path separators.
    format!("{}_{}", digest_bytes(relative.as_bytes()), digest)
}

#[derive(Debug)]
struct RestoreChange {
    target: PathBuf,
    backup: Option<PathBuf>,
}

fn apply_snapshot(
    request: &SnapshotRequest,
    artifact: &CheckpointArtifact,
    staging: &Path,
) -> Result<()> {
    let workspace = fs::canonicalize(&request.workspace)?;
    let mut normalized = request.clone();
    normalized.workspace = workspace.clone();
    normalized.roots = normalized
        .roots
        .iter()
        .map(fs::canonicalize)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    normalized.excluded_roots = normalized
        .excluded_roots
        .iter()
        .map(|root| canonicalize_existing_or_missing(root))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    normalized.validate()?;

    let current = collect_snapshot(&normalized)?.entries;
    let current_by_path = current
        .iter()
        .map(|entry| (entry.path.as_str(), entry.file_type))
        .collect::<HashMap<_, _>>();
    let target_by_path = artifact
        .file_entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry.file_type))
        .collect::<HashMap<_, _>>();
    if current_by_path.len() != current.len() || target_by_path.len() != artifact.file_entries.len()
    {
        return Err(Error::Config("snapshot contains duplicate paths".into()));
    }

    // Validate every path before moving the first byte. This closes the gap
    // where a malicious manifest could make a later entry escape a root after
    // earlier files had already been replaced.
    for entry in current.iter() {
        target_path(&workspace, &normalized, &entry.path)?;
    }
    for entry in artifact.file_entries.iter() {
        artifact_target_path(&workspace, &normalized, &entry.path)?;
    }

    let staged_files = staging.join("blobs");
    let backup_root = staging.join("backup");
    let mut changes = Vec::<RestoreChange>::new();
    let mut created_dirs = Vec::<PathBuf>::new();
    let mut original_directory_permissions = Vec::<(PathBuf, Option<u32>)>::new();
    for entry in artifact
        .file_entries
        .iter()
        .filter(|entry| entry.file_type == CheckpointFileType::Directory)
    {
        let target = artifact_target_path(&workspace, &normalized, &entry.path)?;
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            if !metadata.file_type().is_symlink() && metadata.is_dir() {
                original_directory_permissions.push((target, file_permissions(&metadata)));
            }
        }
    }
    let result = (|| -> Result<()> {
        // First move every current entry that is not represented by the target
        // snapshot. Keeping backups (instead of deleting immediately) makes
        // errors and crashes recoverable until the operation is committed.
        for entry in current
            .iter()
            .filter(|entry| !target_by_path.contains_key(entry.path.as_str()))
        {
            let target = target_path(&workspace, &normalized, &entry.path)?;
            if entry.file_type == CheckpointFileType::File {
                backup_existing(&target, &backup_root, &mut changes)?;
            }
        }

        let mut entries = artifact.file_entries.clone();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        for entry in entries
            .iter()
            .filter(|entry| entry.file_type == CheckpointFileType::Directory)
        {
            let target = artifact_target_path(&workspace, &normalized, &entry.path)?;
            if let Ok(metadata) = fs::symlink_metadata(&target) {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Config("restore target became a symlink".into()));
                }
                if !metadata.is_dir() {
                    backup_existing(&target, &backup_root, &mut changes)?;
                    create_parent_dirs(&workspace, &normalized, &target, &mut created_dirs)?;
                    fs::create_dir(&target)?;
                    created_dirs.push(target);
                }
            } else {
                create_parent_dirs(&workspace, &normalized, &target, &mut created_dirs)?;
                fs::create_dir(&target)?;
                created_dirs.push(target);
            }
        }
        for entry in entries
            .iter()
            .filter(|entry| entry.file_type == CheckpointFileType::File)
        {
            let target = artifact_target_path(&workspace, &normalized, &entry.path)?;
            if let Ok(metadata) = fs::symlink_metadata(&target) {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Config("restore target became a symlink".into()));
                }
                backup_existing(&target, &backup_root, &mut changes)?;
            }
            let staged = staged_files.join(staged_file_name(&entry.path, &entry.content_sha256));
            if !staged.is_file() {
                return Err(Error::Config("staged rollback file is missing".into()));
            }
            create_parent_dirs(&workspace, &normalized, &target, &mut created_dirs)?;
            fs::rename(&staged, &target)?;
            apply_permissions(&target, entry.permissions)?;
            changes.push(RestoreChange {
                target,
                backup: None,
            });
        }

        // Remove only directories that are outside the target tree. Files
        // were moved above, so an extra directory should now be empty.
        for entry in current.iter().rev().filter(|entry| {
            entry.file_type == CheckpointFileType::Directory
                && !target_by_path.contains_key(entry.path.as_str())
                && !artifact
                    .file_entries
                    .iter()
                    .any(|target| target.path.starts_with(&format!("{}/", entry.path)))
        }) {
            let target = target_path(&workspace, &normalized, &entry.path)?;
            if path_exists_without_symlink(&target)? {
                // Keep the complete directory as a backup rather than merely
                // deleting it. This preserves permissions and lets an error
                // after the final digest check restore the pre-rollback state.
                backup_existing(&target, &backup_root, &mut changes)?;
            }
        }

        // Apply directory modes after all child mutations. Applying a parent
        // mode first could remove the write/search permission needed for the
        // remaining entries, while leaving modes untouched would make a
        // directory-only snapshot inexact.
        let mut target_directories = artifact
            .file_entries
            .iter()
            .filter(|entry| entry.file_type == CheckpointFileType::Directory)
            .collect::<Vec<_>>();
        target_directories.sort_by(|left, right| right.path.cmp(&left.path));
        for entry in target_directories {
            let target = artifact_target_path(&workspace, &normalized, &entry.path)?;
            apply_permissions(&target, entry.permissions)?;
        }

        let final_digest =
            collect_snapshot(&normalized).map(|snapshot| entries_digest(&snapshot.entries))??;
        if final_digest != artifact.snapshot_digest {
            return Err(Error::Other(
                "restore final digest check failed: workspace changed during rollback".into(),
            ));
        }
        Ok(())
    })();
    if let Err(error) = result {
        undo_changes(&mut changes, &created_dirs);
        for (path, permissions) in original_directory_permissions {
            if let Some(permissions) = permissions {
                let _ = apply_permissions(&path, Some(permissions));
            }
        }
        return Err(error);
    }
    Ok(())
}

fn apply_permissions(path: &Path, permissions: Option<u32>) -> Result<()> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Config("restore target became a symlink".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = permissions {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, permissions);
    }
    Ok(())
}

fn backup_existing(
    target: &Path,
    backup_root: &Path,
    changes: &mut Vec<RestoreChange>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(target)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Config("restore target became a symlink".into()));
    }
    reject_symlink_components(backup_root)?;
    fs::create_dir_all(backup_root)?;
    reject_symlink_components(backup_root)?;
    let relative = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Config("restore target has no safe file name".into()))?;
    let backup = backup_root.join(format!(
        "{}_{}",
        digest_bytes(relative.as_bytes()),
        changes.len()
    ));
    reject_symlink_components(&backup)?;
    fs::rename(target, &backup)?;
    changes.push(RestoreChange {
        target: target.to_path_buf(),
        backup: Some(backup),
    });
    Ok(())
}

fn undo_changes(changes: &mut [RestoreChange], created_dirs: &[PathBuf]) {
    for change in changes.iter().rev() {
        remove_restore_target(&change.target);
        if let Some(backup) = &change.backup {
            let _ = fs::rename(backup, &change.target);
        }
    }
    for directory in created_dirs.iter().rev() {
        let _ = fs::remove_dir(directory);
    }
}

fn remove_restore_target(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn target_path(workspace: &Path, request: &SnapshotRequest, relative: &str) -> Result<PathBuf> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Config("restore path is not normalized".into()));
    }
    let target = workspace.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
    if !request
        .roots
        .iter()
        .any(|root| target.starts_with(root) || root.starts_with(&target))
    {
        return Err(Error::Config(
            "restore path is outside snapshot roots".into(),
        ));
    }
    if is_excluded(&target, &request.excluded_roots) {
        return Err(Error::Config(
            "restore path enters the artifact store".into(),
        ));
    }
    let relative = relative_path(workspace, &target)?;
    for pattern in &request.forbidden_globs {
        if Glob::new(pattern)?.is_match(&relative) {
            return Err(Error::Config(
                "restore path is forbidden by the boundary".into(),
            ));
        }
    }
    reject_symlink_components(&target)?;
    Ok(target)
}

fn artifact_target_path(
    workspace: &Path,
    request: &SnapshotRequest,
    relative: &str,
) -> Result<PathBuf> {
    let target = target_path(workspace, request, relative)?;
    if !request.roots.iter().any(|root| target.starts_with(root)) {
        return Err(Error::Config(
            "artifact entry is outside the snapshot roots".into(),
        ));
    }
    Ok(target)
}

fn create_parent_dirs(
    workspace: &Path,
    request: &SnapshotRequest,
    target: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut parent = target
        .parent()
        .ok_or_else(|| Error::Config("restore target has no parent".into()))?;
    let mut missing = Vec::new();
    while !parent.starts_with(workspace) {
        missing.push(parent.to_path_buf());
        parent = parent
            .parent()
            .ok_or_else(|| Error::Config("restore parent escapes workspace".into()))?;
    }
    for directory in missing.into_iter().rev() {
        target_path(workspace, request, &relative_path(workspace, &directory)?)?;
        if !directory.exists() {
            fs::create_dir(&directory)?;
            created.push(directory);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{
        CheckpointArtifact, EventRef, FailedPathRecord, FailedPathStatus, FailureClass,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pangu-artifact-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn digest() -> String {
        "a".repeat(64)
    }

    #[test]
    fn bounded_serialization_rejects_oversized_values() {
        let value = vec!["x".repeat(128)];
        assert!(serialize_bounded(&value, 32, "test value").is_err());
    }

    fn event_ref() -> EventRef {
        EventRef::new("event-1", "run-1")
    }

    #[cfg(windows)]
    #[test]
    fn stale_windows_replacement_backup_fails_closed() {
        let directory = root("stale-replacement-backup");
        let destination = directory.join("state.json");
        fs::write(&destination, "old").unwrap();
        let stale = directory.join("state.json.replace-backup-stale");
        fs::write(&stale, "operator evidence").unwrap();
        let error = write_atomic(&destination, b"new").unwrap_err();
        assert!(error
            .to_string()
            .contains("stale Windows replacement backup"));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "old");
        assert_eq!(fs::read_to_string(&stale).unwrap(), "operator evidence");
        fs::remove_dir_all(directory).unwrap();
    }

    fn artifact(workspace: &Path, id: &str) -> CheckpointArtifact {
        CheckpointArtifact::new(
            id,
            "run-1",
            "session-1",
            "node-1",
            event_ref(),
            workspace.to_path_buf(),
            digest(),
            digest(),
            digest(),
        )
    }

    fn request(workspace: &Path, store_root: &Path) -> SnapshotRequest {
        SnapshotRequest::new(
            workspace.to_path_buf(),
            vec![workspace.to_path_buf()],
            vec![store_root.to_path_buf()],
            vec!["**/.git/**".into()],
            SnapshotLimits::default(),
        )
    }

    #[test]
    fn snapshot_is_content_addressed_and_loads_after_commit() {
        let workspace = root("workspace");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("a.txt"), "hello").unwrap();
        fs::create_dir_all(workspace.join("nested")).unwrap();
        fs::write(workspace.join("nested/b.txt"), "world").unwrap();
        let request = request(&workspace, &store_root);
        let committed = store
            .commit_snapshot(&request, artifact(&workspace, "cp-1"))
            .unwrap();
        assert_eq!(committed.snapshot_digest.len(), 64);
        assert!(committed
            .file_entries
            .iter()
            .any(|entry| entry.path == "a.txt"));
        let loaded = store.load_checkpoint("cp-1").unwrap();
        assert_eq!(loaded, committed);
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn corrupt_blob_fails_before_restore() {
        let workspace = root("workspace-corrupt");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("a.txt"), "hello").unwrap();
        let request = request(&workspace, &store_root);
        let committed = store
            .commit_snapshot(&request, artifact(&workspace, "cp-corrupt"))
            .unwrap();
        let file_entry = committed
            .file_entries
            .iter()
            .find(|entry| entry.file_type == CheckpointFileType::File)
            .expect("snapshot file entry");
        let blob = store
            .checkpoint_dir("cp-corrupt")
            .unwrap()
            .join(&file_entry.blob_ref);
        fs::write(blob, b"tampered").unwrap();
        assert!(store.load_checkpoint("cp-corrupt").is_err());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn restore_removes_files_and_directories_missing_from_the_target_snapshot() {
        let workspace = root("workspace-exact");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::create_dir_all(workspace.join("old-dir")).unwrap();
        fs::write(workspace.join("old-dir/a.txt"), "before").unwrap();
        let request = request(&workspace, &store_root);
        let target = store
            .commit_snapshot(&request, artifact(&workspace, "cp-exact"))
            .unwrap();
        fs::write(workspace.join("old-dir/a.txt"), "changed").unwrap();
        fs::write(workspace.join("remove.txt"), "present").unwrap();
        fs::write(workspace.join("new.txt"), "new").unwrap();
        let expected_current = store.compute_workspace_digest(&request).unwrap();
        let result = store
            .restore_checkpoint_with_expected(&request, &target, "rb-exact", &expected_current)
            .unwrap();
        assert_eq!(result.disposition, RestoreDisposition::Applied);
        assert_eq!(
            fs::read_to_string(workspace.join("old-dir/a.txt")).unwrap(),
            "before"
        );
        assert!(!workspace.join("remove.txt").exists());
        assert!(!workspace.join("new.txt").exists());
        assert!(workspace.join("old-dir").is_dir());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn restore_replaces_a_file_with_an_empty_target_directory() {
        let workspace = root("workspace-type-change");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::create_dir_all(workspace.join("target-dir")).unwrap();
        let snapshot_request = request(&workspace, &store_root);
        let target = store
            .commit_snapshot(&snapshot_request, artifact(&workspace, "cp-type-dir"))
            .unwrap();
        fs::remove_dir_all(workspace.join("target-dir")).unwrap();
        fs::write(workspace.join("target-dir"), "now a file").unwrap();
        let expected = store.compute_workspace_digest(&snapshot_request).unwrap();
        store
            .restore_checkpoint_with_expected(&snapshot_request, &target, "rb-type-dir", &expected)
            .unwrap();
        assert!(workspace.join("target-dir").is_dir());
        assert!(fs::read_dir(workspace.join("target-dir"))
            .unwrap()
            .next()
            .is_none());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn checkpoint_embedded_node_tampering_is_rejected() {
        let workspace = root("workspace-node-tamper");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("a.txt"), "value").unwrap();
        let target = artifact(&workspace, "cp-node-tamper");
        let node = SessionNode::new(
            target.session_node_id.clone(),
            target.event_ref.clone(),
            Some(target.checkpoint_id.clone()),
        );
        store
            .commit_snapshot_with_node(&request(&workspace, &store_root), target, Some(&node))
            .unwrap();
        let embedded = store
            .checkpoint_dir("cp-node-tamper")
            .unwrap()
            .join("session-node.json");
        fs::write(&embedded, b"{}").unwrap();
        assert!(store.load_checkpoint("cp-node-tamper").is_err());
        fs::remove_dir_all(workspace).ok();
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlinks_instead_of_silently_omitting_them() {
        use std::os::unix::fs::symlink;
        let workspace = root("workspace-symlink");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("target.txt"), "secret").unwrap();
        symlink(workspace.join("target.txt"), workspace.join("link.txt")).unwrap();
        let request = request(&workspace, &store_root);
        assert!(store
            .commit_snapshot(&request, artifact(&workspace, "cp-symlink"))
            .is_err());
        fs::remove_dir_all(workspace).ok();
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_special_filesystem_entries() {
        use std::os::unix::net::UnixListener;
        let workspace = root("workspace-special-file");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        let socket = workspace.join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let request = request(&workspace, &store_root);
        assert!(store
            .commit_snapshot(&request, artifact(&workspace, "cp-special-file"))
            .is_err());
        drop(_listener);
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn node_commit_is_not_trusted_without_the_completion_marker() {
        let workspace = root("workspace-atomic-node");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        let target = artifact(&workspace, "cp-atomic-node");
        let node = SessionNode::new(
            target.session_node_id.clone(),
            target.event_ref.clone(),
            Some(target.checkpoint_id.clone()),
        );
        let committed = store
            .commit_snapshot_with_node(&request(&workspace, &store_root), target, Some(&node))
            .unwrap();
        assert_eq!(
            store.load_checkpoint(&committed.checkpoint_id).unwrap(),
            committed
        );
        fs::remove_file(
            store
                .checkpoint_dir("cp-atomic-node")
                .unwrap()
                .join("COMMITTED"),
        )
        .unwrap();
        assert!(store.load_checkpoint("cp-atomic-node").is_err());
        fs::write(
            store
                .checkpoint_dir("cp-atomic-node")
                .unwrap()
                .join("COMMITTED"),
            b"NOT-COMMITTED",
        )
        .unwrap();
        assert!(store.load_checkpoint("cp-atomic-node").is_err());
        assert!(store.load_session_node_by_id("node-1").unwrap().is_some());
        fs::remove_dir_all(workspace).ok();
    }

    #[cfg(unix)]
    #[test]
    fn restore_applies_directory_permissions_after_children() {
        use std::os::unix::fs::PermissionsExt;
        let workspace = root("workspace-directory-mode");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        let directory = workspace.join("nested");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("file.txt"), "value").unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        let snapshot_request = request(&workspace, &store_root);
        let target = store
            .commit_snapshot(&snapshot_request, artifact(&workspace, "cp-mode"))
            .unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let expected = store.compute_workspace_digest(&snapshot_request).unwrap();
        store
            .restore_checkpoint_with_expected(&snapshot_request, &target, "rb-mode", &expected)
            .unwrap();
        let mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o750);
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn a_stale_process_transaction_marker_fails_closed() {
        let workspace = root("workspace-stale-lock");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("a.txt"), "value").unwrap();
        let snapshot_request = request(&workspace, &store_root);
        let target = store
            .commit_snapshot(&snapshot_request, artifact(&workspace, "cp-stale-lock"))
            .unwrap();
        fs::write(store.root().join(".rollback-operation.lock"), "stale").unwrap();
        assert!(store
            .restore_checkpoint(&snapshot_request, &target, "rb-stale-lock")
            .is_err());
        fs::remove_file(store.root().join(".rollback-operation.lock")).unwrap();
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn failed_path_references_are_scoped_to_their_run() {
        let workspace = root("workspace-failed-path");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        let record = FailedPathRecord {
            schema_version: crate::checkpoint::FAILED_PATH_SCHEMA_VERSION,
            failure_id: "failure-scope-1".into(),
            failure_class: FailureClass::ToolFailed,
            tool: "write_file".into(),
            canonical_args_digest: digest(),
            resource_digest: digest(),
            contract_digest: digest(),
            policy_digest: digest(),
            attempt_count: 1,
            first_seen_event_ref: EventRef::new("event-run-1", "run-1"),
            last_seen_event_ref: EventRef::new("event-run-1", "run-1"),
            run_id: "run-1".into(),
            status: FailedPathStatus::Active,
            superseded_by: None,
        };
        let stored = store.record_failure(&record).unwrap();
        assert_eq!(stored.failure_id, record.failure_id);
        assert!(store
            .load_failed_path("run-1", "failure-scope-1")
            .unwrap()
            .is_some());
        assert!(store
            .load_failed_path("run-2", "failure-scope-1")
            .unwrap()
            .is_none());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn failed_path_ledger_rejects_tampered_first_seen_reference() {
        let workspace = root("workspace-failed-path-tamper");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        let record = FailedPathRecord {
            schema_version: crate::checkpoint::FAILED_PATH_SCHEMA_VERSION,
            failure_id: "failure-tamper-1".into(),
            failure_class: FailureClass::ToolFailed,
            tool: "write_file".into(),
            canonical_args_digest: digest(),
            resource_digest: digest(),
            contract_digest: digest(),
            policy_digest: digest(),
            attempt_count: 1,
            first_seen_event_ref: EventRef::new("event-first", "run-1"),
            last_seen_event_ref: EventRef::new("event-first", "run-1"),
            run_id: "run-1".into(),
            status: FailedPathStatus::Active,
            superseded_by: None,
        };
        store.record_failure(&record).unwrap();
        let mut tampered = record;
        tampered.first_seen_event_ref = EventRef::new("event-forged", "run-1");
        let ledger = store.root().join(FAILED_PATH_LEDGER_FILE);
        let original_bytes = fs::read(&ledger).unwrap();
        let mut bytes = original_bytes;
        bytes.extend_from_slice(&serde_json::to_vec(&tampered).unwrap());
        bytes.push(b'\n');
        fs::write(&ledger, bytes).unwrap();
        assert!(store.load_failed_path("run-1", "failure-tamper-1").is_err());
        fs::remove_dir_all(workspace).ok();
    }

    #[test]
    fn rollback_requires_compare_and_swap_and_is_idempotent() {
        let workspace = root("workspace-rollback");
        let store_root = workspace.join(".pangu/checkpoints");
        let store = ArtifactStore::open(&store_root).unwrap();
        fs::write(workspace.join("a.txt"), "before").unwrap();
        let request = request(&workspace, &store_root);
        let committed = store
            .commit_snapshot(&request, artifact(&workspace, "cp-rollback"))
            .unwrap();
        fs::write(workspace.join("a.txt"), "after").unwrap();
        assert!(store
            .restore_checkpoint(&request, &committed, "rb-cas")
            .is_err());
        // Recreate the original state and apply the restore.
        fs::write(workspace.join("a.txt"), "before").unwrap();
        let result = store
            .restore_checkpoint(&request, &committed, "rb-once")
            .unwrap();
        assert_eq!(result.disposition, RestoreDisposition::Applied);
        assert_eq!(
            fs::read_to_string(workspace.join("a.txt")).unwrap(),
            "before"
        );
        let repeated = store
            .restore_checkpoint(&request, &committed, "rb-once")
            .unwrap();
        assert_eq!(repeated.disposition, RestoreDisposition::AlreadyApplied);
        fs::remove_dir_all(workspace).ok();
    }
}
