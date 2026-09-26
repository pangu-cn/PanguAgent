//! Internal checkpoint runtime used by the Agent state machine.
//!
//! The runtime never exposes a model-facing checkpoint or rollback tool. It
//! is constructed only from an enabled, validated GoalContract and writes
//! through the content-addressed store after a successful ToolFinished event.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};

use pangu_boundary::{CheckpointBackend, CheckpointFailurePolicy, GoalContract};
use pangu_core::{
    ArtifactStore, CheckpointArtifact, EffectRecord, Event, EventRef, ExternalEffectSummary,
    FailedPathRecord, FailureClass, RestoreResult, RollbackRequest, SessionNode, SnapshotLimits,
    SnapshotRequest, FAILED_PATH_LEDGER_FILE,
};

use crate::{EffectDescriptor, EffectScope};

static CHECKPOINT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct RunCheckpointState {
    pub run_id: String,
    pub session_id: String,
    pub session_node_id: String,
    pub parent_checkpoint_id: Option<String>,
    pub(crate) local_event_seq: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckpointCommit {
    pub artifact: CheckpointArtifact,
}

/// Internal capability token for a rollback that has passed L1-L4. It is
/// deliberately crate-private and is not exposed through `ToolExecutor`.
pub(crate) struct RollbackCapability {
    request: RollbackRequest,
    artifact: CheckpointArtifact,
    expected_current_digest: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckpointRuntime {
    store: ArtifactStore,
    artifact_root: PathBuf,
    limits: SnapshotLimits,
    failure_policy: CheckpointFailurePolicy,
    contract_digest: String,
    policy_digest: String,
    workspace: PathBuf,
    roots: Vec<PathBuf>,
    forbidden_globs: Vec<String>,
}

impl CheckpointRuntime {
    pub(crate) fn from_contract(contract: &GoalContract) -> Result<Option<Self>> {
        if !contract.checkpoint.enabled {
            return Ok(None);
        }
        if contract.checkpoint.backend != CheckpointBackend::Artifact {
            bail!("checkpoint backend `git` is not implemented by the v1 runtime");
        }
        let store = ArtifactStore::open(&contract.checkpoint.artifact_root)
            .map_err(|error| anyhow!(error))?;
        let limits = SnapshotLimits {
            max_snapshot_bytes: contract.checkpoint.max_snapshot_bytes,
            max_snapshot_files: contract.checkpoint.max_snapshot_files,
            max_snapshot_file_bytes: contract.checkpoint.max_snapshot_file_bytes,
        };
        limits.validate().map_err(|error| anyhow!(error))?;
        Ok(Some(Self {
            store,
            artifact_root: contract.checkpoint.artifact_root.clone(),
            limits,
            failure_policy: contract.checkpoint.failure_policy,
            contract_digest: contract.digest(),
            policy_digest: contract.policy_digest.clone(),
            workspace: contract.workspace().clone(),
            roots: contract.writable_roots().to_vec(),
            forbidden_globs: contract.forbidden_globs.clone(),
        }))
    }

    pub(crate) fn new_run_state(&self) -> RunCheckpointState {
        let nonce = CHECKPOINT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let run_id = format!("run_{}_{}_{}", self.contract_digest, nanos, nonce);
        let session_id = format!("session_{}_{}", nanos, nonce);
        RunCheckpointState {
            session_node_id: format!("node_root_{}_{}", nanos, nonce),
            run_id,
            session_id,
            parent_checkpoint_id: None,
            local_event_seq: 0,
        }
    }

    pub(crate) fn request(&self) -> SnapshotRequest {
        let internal_root = self.workspace.join(".pangu");
        SnapshotRequest::new(
            self.workspace.clone(),
            self.roots.clone(),
            vec![internal_root, self.artifact_root.clone()],
            self.forbidden_globs.clone(),
            self.limits,
        )
    }

    pub(crate) fn store(&self) -> &ArtifactStore {
        &self.store
    }

    pub(crate) fn failure_policy(&self) -> CheckpointFailurePolicy {
        self.failure_policy
    }

    pub(crate) fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    pub(crate) fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Record an approved external mutation before the adapter is invoked.
    /// A planned effect is intentionally sufficient to block a later rollback.
    pub(crate) fn record_external_effect(
        &self,
        state: &mut RunCheckpointState,
        event: &Event,
        effect: EffectDescriptor,
        action_digest: &str,
    ) -> Result<()> {
        if !effect.is_external_mutation() {
            return Ok(());
        }
        validate_sealed_v2_event(event, true)?;
        if event.kind != pangu_core::EventKind::ToolStarted
            || event.effect_scope.as_deref() != Some(effect.scope.as_str())
            || event.reversibility.as_deref() != Some(effect.reversibility.as_str())
            || event.external_mutation != Some(true)
            || event.action_digest.as_deref() != Some(action_digest)
        {
            bail!("external effect receipt does not match the verified action");
        }
        let event_ref = state_event_ref(state, event);
        let record = EffectRecord {
            schema_version: pangu_core::ARTIFACT_STORE_SCHEMA_VERSION,
            effect_id: format!(
                "effect_{}_{}",
                state.run_id,
                CHECKPOINT_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            run_id: state.run_id.clone(),
            action_digest: action_digest.to_string(),
            effect_scope: effect.scope.as_str().to_string(),
            reversibility: effect.reversibility.as_str().to_string(),
            external_mutation: true,
            event_ref,
            recorded_at: pangu_core::now_rfc3339(),
        };
        self.store.record_effect(&record)?;
        Ok(())
    }

    pub(crate) fn commit_after_success(
        &self,
        state: &mut RunCheckpointState,
        finished_event: &Event,
        effect: EffectDescriptor,
    ) -> Result<CheckpointCommit> {
        if finished_event.kind != pangu_core::EventKind::ToolFinished {
            bail!("checkpoint source event must be a successful ToolFinished event");
        }
        validate_sealed_v2_event(finished_event, true)?;
        if finished_event.effect_scope.as_deref() != Some(effect.scope.as_str())
            || finished_event.reversibility.as_deref() != Some(effect.reversibility.as_str())
            || finished_event.external_mutation != Some(effect.is_external_mutation())
        {
            bail!("checkpoint source event effect metadata does not match the verified action");
        }
        let event_ref = state_event_ref(state, finished_event);
        let checkpoint_id = new_id("checkpoint", &state.run_id, &event_ref.event_id);
        let session_node_id = new_id("node", &state.run_id, &event_ref.event_id);
        let mut artifact = CheckpointArtifact::new(
            checkpoint_id,
            &state.run_id,
            &state.session_id,
            &session_node_id,
            event_ref.clone(),
            self.workspace.clone(),
            self.contract_digest.clone(),
            self.policy_digest.clone(),
            // The store replaces this with the digest of the captured entries.
            "0".repeat(64),
        );
        artifact.parent_checkpoint_id = state.parent_checkpoint_id.clone();
        artifact.failed_path_ledger_ref = Some(FAILED_PATH_LEDGER_FILE.to_string());
        artifact
            .external_effect_summary
            .push(ExternalEffectSummary {
                effect_scope: effect.scope.as_str().to_string(),
                reversibility: effect.reversibility.as_str().to_string(),
                external_mutation: effect.is_external_mutation(),
                event_ref: Some(event_ref.clone()),
            });
        let mut node = SessionNode::new(
            session_node_id.clone(),
            event_ref,
            Some(artifact.checkpoint_id.clone()),
        );
        node.parent_session_node_id = Some(state.session_node_id.clone());
        let artifact =
            self.store
                .commit_snapshot_with_node(&self.request(), artifact, Some(&node))?;
        state.session_node_id = session_node_id;
        state.parent_checkpoint_id = Some(artifact.checkpoint_id.clone());
        Ok(CheckpointCommit { artifact })
    }

    pub(crate) fn find_failed_path(
        &self,
        state: &RunCheckpointState,
        tool: &str,
        canonical_args_digest: &str,
        resource_digest: &str,
    ) -> Result<Option<FailedPathRecord>> {
        Ok(self.store.find_active_failure(
            &state.run_id,
            tool,
            canonical_args_digest,
            resource_digest,
            &self.contract_digest,
            &self.policy_digest,
        )?)
    }

    pub(crate) fn record_failed_path(
        &self,
        state: &RunCheckpointState,
        tool: &str,
        canonical_args_digest: &str,
        resource_digest: &str,
        class: FailureClass,
        event: &Event,
    ) -> Result<FailedPathRecord> {
        validate_sealed_v2_event(event, false)?;
        let event_ref = event_ref(event, &state.run_id);
        let class_name = format!("{class:?}");
        let failure_key = format!(
            "{}|{}|{}|{}|{}|{}",
            state.run_id,
            tool,
            canonical_args_digest,
            resource_digest,
            class_name,
            self.contract_digest
        );
        let failure_id = format!("failed_{}", pangu_core::short_hash(&failure_key));
        let record = FailedPathRecord {
            schema_version: pangu_core::FAILED_PATH_SCHEMA_VERSION,
            failure_id,
            failure_class: class,
            tool: tool.to_string(),
            canonical_args_digest: canonical_args_digest.to_string(),
            resource_digest: resource_digest.to_string(),
            contract_digest: self.contract_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            attempt_count: 1,
            first_seen_event_ref: event_ref.clone(),
            last_seen_event_ref: event_ref,
            run_id: state.run_id.clone(),
            status: pangu_core::FailedPathStatus::Active,
            superseded_by: None,
        };
        Ok(self.store.record_failure(&record)?)
    }

    pub(crate) fn validate_rollback_resources(&self) -> Result<()> {
        self.request().validate().map_err(|error| anyhow!(error))
    }

    pub(crate) fn prepare_rollback(
        &self,
        request: &RollbackRequest,
        artifact: &CheckpointArtifact,
        expected_current_digest: &str,
    ) -> Result<RollbackCapability> {
        request.validate().map_err(|error| anyhow!(error))?;
        if artifact.checkpoint_id != request.checkpoint_id
            || artifact.contract_digest != self.contract_digest
            || artifact.policy_digest != self.policy_digest
            || artifact.workspace != self.workspace
        {
            bail!("rollback capability boundary binding is invalid");
        }
        if expected_current_digest.len() != 64
            || !expected_current_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("rollback capability expected digest is invalid");
        }
        Ok(RollbackCapability {
            request: request.clone(),
            artifact: artifact.clone(),
            expected_current_digest: expected_current_digest.to_string(),
        })
    }

    pub(crate) fn execute_rollback(
        &self,
        capability: &RollbackCapability,
        transition_session_node_id: Option<&str>,
        transition_event_ref: Option<&EventRef>,
    ) -> Result<RestoreResult> {
        self.store
            .restore_checkpoint_with_expected_and_transition(
                &self.request(),
                &capability.artifact,
                &capability.request.rollback_id,
                &capability.expected_current_digest,
                transition_session_node_id,
                transition_event_ref,
            )
            .map_err(|error| anyhow!(error))
    }

    pub(crate) fn rollback_transition_node_id(
        &self,
        target: &CheckpointArtifact,
        source_session_node_id: &str,
        rollback_id: &str,
    ) -> String {
        format!(
            "node_rollback_{}",
            pangu_core::hex_sha256(&format!(
                "{}:{}:{}:{}",
                target.run_id, target.checkpoint_id, source_session_node_id, rollback_id
            ))
        )
    }

    pub(crate) fn save_rollback_transition_node(
        &self,
        source_session_node_id: &str,
        target: &CheckpointArtifact,
        rollback_id: &str,
        session_node_id: String,
        event_ref: &EventRef,
    ) -> Result<SessionNode> {
        if event_ref.run_id != target.run_id {
            bail!("rollback transition event must belong to the target run");
        }
        let mut node = SessionNode::new(
            session_node_id.clone(),
            event_ref.clone(),
            Some(target.checkpoint_id.clone()),
        );
        node.parent_session_node_id = Some(source_session_node_id.to_string());
        node.failed_path_ledger_ref = Some(FAILED_PATH_LEDGER_FILE.to_string());
        node.applied_rollback_ids.push(rollback_id.to_string());
        self.store.save_session_node(&node)?;
        Ok(node)
    }
}

fn validate_sealed_v2_event(event: &Event, require_effect_metadata: bool) -> Result<()> {
    event.validate_v2_receipt()?;
    if require_effect_metadata
        && (event.effect_scope.is_none()
            || event.reversibility.is_none()
            || event.action_digest.is_none()
            || event.external_mutation.is_none())
    {
        bail!("checkpoint source event is missing effect metadata");
    }
    Ok(())
}

fn state_event_ref(state: &mut RunCheckpointState, event: &Event) -> EventRef {
    let mut reference = event_ref(event, &state.run_id);
    if reference.seq.is_none() {
        reference.seq = Some(state.local_event_seq);
        state.local_event_seq = state.local_event_seq.saturating_add(1);
    }
    reference
}

pub(crate) fn event_ref(event: &Event, run_id: &str) -> EventRef {
    let event_id = event
        .event_id
        .clone()
        .unwrap_or_else(|| format!("mem_{}", pangu_core::short_hash(&event.canonical())));
    let stable_journal_event = event_id.starts_with("evt_");
    EventRef {
        event_id,
        run_id: run_id.to_string(),
        journal_id: None,
        seq: stable_journal_event.then_some(event.seq),
        sha: if event.sha.is_empty() {
            None
        } else {
            Some(event.sha.clone())
        },
    }
}

fn new_id(prefix: &str, run_id: &str, event_id: &str) -> String {
    let counter = CHECKPOINT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{prefix}_{}_{}_{}_{counter}",
        short_component(run_id),
        short_component(event_id),
        nanos % 1_000_000_000
    )
}

fn short_component(value: &str) -> String {
    pangu_core::short_hash(value)
}

#[allow(dead_code)]
fn _effect_scope_is_external(scope: EffectScope) -> bool {
    scope == EffectScope::ExternalMutation
}
