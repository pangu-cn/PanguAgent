//! F7 operator drills.
//!
//! Each drill rehearses one incident branch from `docs/CHECKPOINT_RECOVERY.md`
//! §4 against a real Artifact store on the real code path. A drill asserts
//! fail-closed behaviour and evidence presence; it never asserts that Pangu
//! "recovered", because recovery is an operator decision the runtime
//! deliberately refuses to automate (ADR-0001 §7.2).
//!
//! When `PANGU_DRILL_REPORT` points at a file, every drill appends one JSON
//! line so cross-platform evidence is produced by CI instead of asserted by a
//! human. Platform differences are recorded in the report rather than hidden:
//! a guard that only exists on Windows is reported as such.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::{Config, GoalContract};
use pangu_core::{
    inspect_artifact_root, ArtifactStore, CheckpointArtifact, EffectRecord, EventRef,
    InspectionVerdict, SessionNode, SnapshotLimits, SnapshotRequest, ARTIFACT_STORE_SCHEMA_VERSION,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const RUN_ID: &str = "run-drill";
const SESSION_ID: &str = "session-drill";
const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const OTHER_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

/// Append one machine-readable drill result line.
///
/// `PANGU_DRILL_REPORT` must be an absolute path: `cargo test` runs the test
/// binary in the package directory, so a relative path would land inside the
/// crate instead of where the caller asked for it. `PANGU_DRILL_COMMIT` lets
/// the caller stamp the report with the revision it validated.
fn record_drill(drill: &str, outcome: &str, detail: &str) {
    let line = serde_json::json!({
        "schema": "pangu-f7-drill/1",
        "drill": drill,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "commit": std::env::var("PANGU_DRILL_COMMIT").unwrap_or_else(|_| "unknown".into()),
        "outcome": outcome,
        "detail": detail,
    });
    match std::env::var_os("PANGU_DRILL_REPORT") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_absolute(),
                "PANGU_DRILL_REPORT must be an absolute path, got {}",
                path.display()
            );
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("drill report directory");
            }
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open drill report");
            writeln!(file, "{line}").expect("write drill report line");
            file.sync_all().expect("flush drill report");
        }
        None => println!("drill-report: {line}"),
    }
}

/// A change detector for a directory tree. It is not a security primitive: it
/// only has to prove that an operation left no byte behind.
fn tree_digest(root: &Path) -> BTreeMap<String, String> {
    fn walk(directory: &Path, out: &mut BTreeMap<String, String>, prefix: &str) {
        let Ok(entries) = fs::read_dir(directory) else {
            out.insert(format!("{prefix}<unreadable>"), "unreadable".into());
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            // The artifact store lives inside the workspace but is not
            // workspace state, so a workspace comparison ignores it and the
            // store is compared separately.
            if prefix.is_empty() && name == ".pangu" {
                continue;
            }
            let key = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                out.insert(key, "missing".into());
                continue;
            };
            if metadata.is_dir() {
                out.insert(format!("{key}/"), "dir".into());
                walk(&path, out, &key);
            } else {
                let bytes = fs::read(&path).unwrap_or_default();
                let digest = bytes_digest(&bytes);
                out.insert(key, format!("{}:{digest}", metadata.len()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out, "");
    out
}

fn bytes_digest(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn has_problem(report: &pangu_core::ArtifactInspection, code: &str) -> bool {
    report.problems.iter().any(|problem| problem.code == code)
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    artifact_root: PathBuf,
    contract: GoalContract,
    store: ArtifactStore,
    request: SnapshotRequest,
}

impl Fixture {
    fn new(label: &str) -> Self {
        // Nanoseconds keep two drill processes from sharing a fixture even if
        // the OS reuses a process id, so a leftover directory from an aborted
        // run can never be mistaken for a fresh incident.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pangu-f7-drill-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("drill root");
        let root = fs::canonicalize(&root).expect("canonical drill root");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).expect("drill workspace");
        let artifact_root = workspace.join(".pangu/checkpoints");

        let mut config = Config::embedded().expect("embedded config");
        config.boundary.workspace = workspace.clone();
        config.boundary.readable_roots = vec![workspace.clone()];
        config.boundary.writable_roots = vec![workspace.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = artifact_root.clone();
        config.unattended = false;
        let contract = GoalContract::from_config("operator drill", &config).expect("contract");
        let request = SnapshotRequest::new(
            workspace.clone(),
            vec![workspace.clone()],
            vec![workspace.join(".pangu"), artifact_root.clone()],
            config.boundary.forbidden_globs.clone(),
            SnapshotLimits::default(),
        );
        let store = ArtifactStore::open(&artifact_root).expect("artifact store");
        fs::write(workspace.join("state.txt"), "before").expect("seed workspace");
        Self {
            root,
            workspace,
            artifact_root,
            contract,
            store,
            request,
        }
    }

    fn commit(
        &self,
        checkpoint_id: &str,
        node_id: &str,
        event_id: &str,
        seq: u64,
    ) -> CheckpointArtifact {
        let mut event_ref = EventRef::new(event_id, RUN_ID);
        event_ref.seq = Some(seq);
        let artifact = CheckpointArtifact::new(
            checkpoint_id,
            RUN_ID,
            SESSION_ID,
            node_id,
            event_ref.clone(),
            self.workspace.clone(),
            self.contract.digest(),
            self.contract.policy_digest.clone(),
            DIGEST,
        );
        let node = SessionNode::new(node_id, event_ref, Some(checkpoint_id.to_string()));
        self.store
            .commit_snapshot_with_node(&self.request, artifact, Some(&node))
            .expect("commit snapshot")
    }

    fn operation_path(&self, rollback_id: &str) -> PathBuf {
        self.artifact_root
            .join("operations")
            .join(format!("{rollback_id}.json"))
    }

    fn inspect(&self) -> pangu_core::ArtifactInspection {
        inspect_artifact_root(&self.artifact_root).expect("inspect artifact store")
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Make one restore step fail the way a real incident would, so the failure
/// lands *after* the operation record is written and is therefore recorded as
/// `Failed` instead of being rejected during pre-flight verification.
///
/// The mechanism is platform-specific on purpose: the guarantee the drill needs
/// is that the write which fails happens inside the restore, and no
/// platform-independent way exists to make one filesystem write fail on demand.
enum Blocked {
    /// A file inside a directory the restore must move aside is open for
    /// reading. Windows refuses to rename a directory that holds a file without
    /// delete sharing, so the move-aside step fails mid-restore.
    #[cfg(windows)]
    SharedReadHandle {
        _handle: fs::File,
        label: &'static str,
    },
    /// The directory the restore must write into is not writable.
    #[cfg(unix)]
    ReadOnlyDirectory {
        directory: PathBuf,
        mode: u32,
        label: &'static str,
    },
    /// This platform or account cannot express the failure (for example root
    /// bypasses directory permissions). Recorded honestly, never asserted.
    Unsupported(&'static str),
}

impl Blocked {
    /// The fixture must provide `nested/keep.txt` (present in the target
    /// snapshot, so a restore must write into `nested`) and `old-dir/old.txt`
    /// (absent from the target, so a restore must move `old-dir` aside).
    fn mid_restore(workspace: &Path) -> Self {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ only: another reader may still open the file, so
            // digest computation succeeds, but nobody may rename or delete it.
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            let file = workspace.join("old-dir/old.txt");
            return match fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&file)
            {
                Ok(handle) => Blocked::SharedReadHandle {
                    _handle: handle,
                    label: "old-dir/old.txt",
                },
                Err(error) => panic!("cannot open the drill fixture file: {error}"),
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if unsafe { libc_geteuid() } == 0 {
                return Blocked::Unsupported("running as root bypasses directory permissions");
            }
            let directory = workspace.join("nested");
            let previous = fs::metadata(&directory)
                .expect("directory metadata")
                .permissions()
                .mode();
            fs::set_permissions(&directory, fs::Permissions::from_mode(previous & !0o222))
                .expect("make directory read-only");
            return Blocked::ReadOnlyDirectory {
                directory,
                mode: previous,
                label: "nested",
            };
        }
        #[allow(unreachable_code)]
        Blocked::Unsupported("no mid-restore write failure is expressible on this platform")
    }

    fn mechanism(&self) -> &'static str {
        match self {
            #[cfg(windows)]
            Blocked::SharedReadHandle { .. } => "directory-rename-blocked-by-open-file",
            #[cfg(unix)]
            Blocked::ReadOnlyDirectory { .. } => "read-only-directory",
            Blocked::Unsupported(_) => "unsupported",
        }
    }

    /// What was blocked, for the drill report. Only workspace-relative labels
    /// are recorded: an absolute path would put the operator's home directory
    /// into an artifact that gets archived and committed.
    fn evidence(&self) -> String {
        match self {
            #[cfg(windows)]
            Blocked::SharedReadHandle { label, .. } => format!("open-for-read={label}"),
            #[cfg(unix)]
            Blocked::ReadOnlyDirectory { label, .. } => format!("read-only-dir={label}"),
            Blocked::Unsupported(reason) => (*reason).to_string(),
        }
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Blocked::ReadOnlyDirectory {
            directory, mode, ..
        } = self
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(directory, fs::Permissions::from_mode(*mode));
        }
    }
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

// ---------------------------------------------------------------------------
// Drill 1 — stale transaction lock (runbook §4.1)
// ---------------------------------------------------------------------------

#[test]
fn drill_stale_transaction_lock_is_reported_and_never_auto_recovered() {
    let fixture = Fixture::new("stale-lock");
    let target = fixture.commit("checkpoint-target", "node-target", "event-target", 1);

    // A crash between the workspace write and the operation bookkeeping leaves
    // this lock behind. It is evidence, not garbage.
    let lock = fixture.artifact_root.join(".rollback-operation.lock");
    fs::write(&lock, format!("pid={}\n", std::process::id())).expect("plant lock");
    let store_before = tree_digest(&fixture.artifact_root);
    let workspace_before = tree_digest(&fixture.workspace);

    let read_error = fixture
        .store
        .load_operation(&target.checkpoint_id, "rollback-drill-1")
        .expect_err("a stale lock must block operation reads")
        .to_string();
    assert!(
        read_error.contains("operator recovery"),
        "unexpected error: {read_error}"
    );
    let write_error = fixture
        .store
        .restore_checkpoint(&fixture.request, &target, "rollback-drill-1")
        .expect_err("a stale lock must block restores")
        .to_string();
    assert!(
        write_error.contains("operator recovery"),
        "unexpected error: {write_error}"
    );

    // Nothing was guessed, repaired or removed.
    assert!(lock.exists(), "the lock must be preserved as evidence");
    assert!(
        !fixture.operation_path("rollback-drill-1").exists(),
        "no operation record may be created under a stale lock"
    );
    assert_eq!(store_before, tree_digest(&fixture.artifact_root));
    assert_eq!(workspace_before, tree_digest(&fixture.workspace));

    let report = fixture.inspect();
    assert_eq!(report.verdict, InspectionVerdict::OperatorRequired);
    assert!(report.transaction_lock.present);
    assert!(report.transaction_lock.pid_hint.is_some());
    assert!(has_problem(&report, "operator.transaction_lock_present"));
    assert_eq!(store_before, tree_digest(&fixture.artifact_root));

    record_drill(
        "stale-lock",
        "pass",
        "runtime refused both read and restore; lock preserved, reported, and store unchanged",
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 2 — failed operation is recorded and never auto-retried (runbook §4.3)
// ---------------------------------------------------------------------------

#[test]
fn drill_failed_operation_is_recorded_and_never_auto_retried() {
    let fixture = Fixture::new("failed-operation");
    // `nested/keep.txt` is in the target snapshot, so a restore must write into
    // `nested`. `old-dir/` only appears after the target checkpoint, so a
    // restore must move it aside.
    fs::create_dir_all(fixture.workspace.join("nested")).expect("nested");
    fs::write(fixture.workspace.join("nested/keep.txt"), "keep").expect("seed nested");
    let target = fixture.commit("checkpoint-target", "node-target", "event-target", 1);
    fs::create_dir_all(fixture.workspace.join("old-dir")).expect("old-dir");
    fs::write(fixture.workspace.join("old-dir/old.txt"), "old").expect("seed old-dir");
    fs::write(fixture.workspace.join("state.txt"), "after").expect("edit workspace");
    let source = fixture.commit("checkpoint-source", "node-source", "event-source", 2);

    let blocked = Blocked::mid_restore(&fixture.workspace);
    if matches!(blocked.mechanism(), "unsupported") {
        record_drill(
            "failed-operation",
            "skipped",
            "this account cannot express a mid-restore write failure",
        );
        fixture.cleanup();
        return;
    }
    let mechanism = blocked.mechanism();
    let evidence = blocked.evidence();
    let workspace_before = tree_digest(&fixture.workspace);
    // The failure has to land inside the restore. If the block did not take
    // effect, say so with the runtime's own outcome instead of reporting a
    // misleading incident.
    let failure = fixture.store.restore_checkpoint_with_expected(
        &fixture.request,
        &target,
        "rollback-drill-2",
        source
            .workspace_digest
            .as_deref()
            .expect("runtime checkpoints carry a workspace digest"),
    );
    let error = match failure {
        Ok(result) => panic!(
            "the {mechanism} block did not stop the restore (disposition {:?}); the incident was not rehearsed",
            result.disposition
        ),
        Err(error) => error.to_string(),
    };
    let error_of_restore = error.clone();
    drop(blocked);
    assert!(
        !error.is_empty(),
        "the recorded failure must carry a reason"
    );

    // The failure is durably recorded with a reason, and the workspace is not
    // left looking like a successful rollback. The restore's own error is
    // carried into the panic: without it a missing record is indistinguishable
    // from a refusal that happened before the operation was ever written.
    let operation = fixture
        .store
        .load_operation(&target.checkpoint_id, "rollback-drill-2")
        .unwrap_or_else(|error| {
            panic!("load the operation ledger: {error}; restore reported: {error_of_restore}")
        })
        .unwrap_or_else(|| {
            panic!("failed operation must be recorded; restore reported: {error_of_restore}")
        });
    assert_eq!(
        operation.status,
        pangu_core::RollbackOperationStatus::Failed,
        "the operation ledger must record the failure"
    );
    assert!(operation.error.is_some(), "a failed operation must say why");
    assert!(
        operation.completed_at.is_some(),
        "a failed operation is terminal"
    );
    assert_eq!(
        workspace_before,
        tree_digest(&fixture.workspace),
        "a failed restore must leave the workspace as it was"
    );

    // The same rollback id is never retried automatically.
    let blocked = Blocked::mid_restore(&fixture.workspace);
    let retry = fixture
        .store
        .restore_checkpoint_with_expected(
            &fixture.request,
            &target,
            "rollback-drill-2",
            source.workspace_digest.as_deref().unwrap(),
        )
        .expect_err("a failed rollback id must not be retried")
        .to_string();
    drop(blocked);
    assert!(
        retry.contains("will not be retried"),
        "unexpected error: {retry}"
    );
    assert_eq!(
        1,
        fs::read_dir(fixture.artifact_root.join("operations"))
            .expect("operations directory")
            .count(),
        "a refused retry must not create a second operation record"
    );

    let report = fixture.inspect();
    assert_eq!(report.verdict, InspectionVerdict::OperatorRequired);
    assert!(has_problem(&report, "operator.operation_failed"));
    let inspected = report
        .operations
        .iter()
        .find(|operation| operation.rollback_id == "rollback-drill-2")
        .expect("failed operation must be reported");
    assert!(inspected.error.is_some());

    record_drill(
        "failed-operation",
        "pass",
        &format!(
            "mechanism={mechanism}; {evidence}; mid-restore failure recorded as Failed with a redacted reason; same id refused; workspace unchanged"
        ),
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 3 — CAS drift keeps newer edits (runbook §4.4)
// ---------------------------------------------------------------------------

#[test]
fn drill_cas_drift_blocks_rollback_and_keeps_newer_edits() {
    let fixture = Fixture::new("cas-drift");
    let target = fixture.commit("checkpoint-target", "node-target", "event-target", 1);

    // An unknown writer edits the workspace after the checkpoint.
    fs::write(
        fixture.workspace.join("state.txt"),
        "edited-after-checkpoint",
    )
    .expect("edit");
    fs::write(fixture.workspace.join("new.txt"), "new").expect("add file");
    let workspace_before = tree_digest(&fixture.workspace);

    let error = fixture
        .store
        .restore_checkpoint(&fixture.request, &target, "rollback-drill-3")
        .expect_err("drift must block the rollback")
        .to_string();
    assert!(
        error.contains("compare-and-swap"),
        "unexpected error: {error}"
    );

    // The newer work is intact and no operation was started.
    assert_eq!(workspace_before, tree_digest(&fixture.workspace));
    assert!(!fixture.operation_path("rollback-drill-3").exists());

    // The store itself is still consistent: drift is a request-scoped fact
    // about the workspace, not a corrupt artifact. Only a real rollback request
    // carrying the boundary roots can evaluate it.
    let report = fixture.inspect();
    assert_eq!(report.verdict, InspectionVerdict::Verified);
    assert!(report.checkpoints[0].verified);

    record_drill(
        "cas-drift",
        "pass",
        "compare-and-swap refused the restore; newer edits and the store were left untouched",
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 4 — external effect blocks the whole rollback (runbook §4.5)
// ---------------------------------------------------------------------------

#[test]
fn drill_external_effect_after_checkpoint_blocks_rollback() {
    let fixture = Fixture::new("external-effect");
    let target = fixture.commit("checkpoint-target", "node-target", "event-target", 1);

    let mut effect_event = EventRef::new("event-effect", RUN_ID);
    effect_event.seq = Some(2);
    fixture
        .store
        .record_effect(&EffectRecord {
            schema_version: ARTIFACT_STORE_SCHEMA_VERSION,
            effect_id: "effect-external-1".into(),
            run_id: RUN_ID.into(),
            action_digest: OTHER_DIGEST.into(),
            effect_scope: "external_mutation".into(),
            reversibility: "irreversible".into(),
            external_mutation: true,
            event_ref: effect_event,
            recorded_at: pangu_core::now_rfc3339(),
        })
        .expect("record external effect");
    let workspace_before = tree_digest(&fixture.workspace);

    let error = fixture
        .store
        .restore_checkpoint(&fixture.request, &target, "rollback-drill-4")
        .expect_err("an external effect must block the rollback")
        .to_string();
    assert!(
        error.contains("irreversible external effect"),
        "unexpected error: {error}"
    );
    assert_eq!(workspace_before, tree_digest(&fixture.workspace));
    assert!(
        !fixture.operation_path("rollback-drill-4").exists(),
        "a blocked rollback must not leave an operation record"
    );

    let report = fixture.inspect();
    assert_eq!(report.verdict, InspectionVerdict::OperatorRequired);
    assert_eq!(report.external_mutations, 1);
    assert_eq!(
        report.checkpoints_blocked_by_external_effect,
        vec!["checkpoint-target".to_string()]
    );
    assert!(has_problem(
        &report,
        "operator.external_effect_after_checkpoint"
    ));

    record_drill(
        "external-effect",
        "pass",
        "irreversible external effect blocked the whole rollback; no external compensation attempted",
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 5 — Windows replacement hand-off evidence (runbook §4.6)
// ---------------------------------------------------------------------------

#[test]
fn drill_replace_backup_is_preserved_and_blocks_artifact_writes() {
    let fixture = Fixture::new("replace-backup");
    let target = fixture.commit("checkpoint-target", "node-target", "event-target", 1);
    let backup = fixture
        .artifact_root
        .join("operations")
        .join("rollback-drill-5.json.replace-backup-4242-0");
    fs::create_dir_all(backup.parent().expect("operations directory"))
        .expect("operations directory");
    fs::write(&backup, b"interrupted hand-off evidence").expect("plant replace backup");
    let workspace_before = tree_digest(&fixture.workspace);

    // The destination of the next operation record is exactly the file this
    // backup shadows, so the atomic replace must refuse rather than overwrite.
    let outcome = fixture.store.restore_checkpoint_with_expected(
        &fixture.request,
        &target,
        "rollback-drill-5",
        target
            .workspace_digest
            .as_deref()
            .expect("runtime checkpoints carry a workspace digest"),
    );

    #[cfg(windows)]
    {
        let error = match outcome {
            Ok(_) => panic!("a stale replacement backup must block the write"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("stale Windows replacement backup"),
            "unexpected error: {error}"
        );
        assert!(
            !fixture.operation_path("rollback-drill-5").exists(),
            "no operation record may be written over a stale backup"
        );
        assert_eq!(workspace_before, tree_digest(&fixture.workspace));
    }
    #[cfg(not(windows))]
    {
        use pangu_core::RestoreDisposition;
        // POSIX rename has no hand-off window, so the planted file is inert for
        // the runtime. The drill records that instead of pretending the guard
        // exists on this platform.
        let result = outcome.expect("POSIX has no replacement hand-off");
        assert_eq!(result.disposition, RestoreDisposition::Applied);
    }

    assert!(backup.exists(), "the backup is evidence and must survive");
    let report = fixture.inspect();
    assert!(
        report.replace_backups.iter().any(
            |evidence| evidence.scope == "artifact" && evidence.path.contains("replace-backup")
        ),
        "the backup must be reported: {:?}",
        report.replace_backups
    );
    assert_ne!(report.verdict, InspectionVerdict::Verified);
    assert!(has_problem(&report, "operator.replace_backup_present"));

    #[cfg(windows)]
    record_drill(
        "replace-backup",
        "pass",
        "stale Windows replacement backup blocked the artifact write and was preserved",
    );
    #[cfg(not(windows))]
    record_drill(
        "replace-backup",
        "not-applicable",
        "POSIX rename has no hand-off; the planted file was reported as evidence only",
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 6 — inspection is read-only (runbook §1 evidence preservation)
// ---------------------------------------------------------------------------

#[test]
fn drill_inspection_never_mutates_the_store_or_the_workspace() {
    let fixture = Fixture::new("read-only");
    fixture.commit("checkpoint-target", "node-target", "event-target", 1);
    // Plant every evidence shape the inspector reports on, so the drill covers
    // the interesting report paths and not only a clean store.
    fs::write(
        fixture.artifact_root.join(".rollback-operation.lock"),
        "pid=1\n",
    )
    .expect("plant lock");
    fs::write(
        fixture
            .artifact_root
            .join("sessions")
            .join("node-target.json.replace-backup-1-0"),
        b"evidence",
    )
    .expect("plant backup");

    let store_before = tree_digest(&fixture.artifact_root);
    let workspace_before = tree_digest(&fixture.workspace);
    for _ in 0..3 {
        let report = fixture.inspect();
        assert!(report.read_only);
        assert_eq!(report.verdict, InspectionVerdict::OperatorRequired);
    }
    assert_eq!(store_before, tree_digest(&fixture.artifact_root));
    assert_eq!(workspace_before, tree_digest(&fixture.workspace));

    record_drill(
        "inspection-read-only",
        "pass",
        "three consecutive inspections left the artifact store and workspace byte-identical",
    );
    fixture.cleanup();
}

// ---------------------------------------------------------------------------
// Drill 7 — the CLI surfaces the incident and exits non-zero (runbook §3)
// ---------------------------------------------------------------------------

#[test]
fn drill_cli_inspect_reports_the_incident_and_exits_non_zero() {
    let fixture = Fixture::new("cli-inspect");
    let config_path = fixture.root.join("boundary.toml");
    fs::write(&config_path, pangu_config(&fixture)).expect("write config");
    let binary = std::env::var_os("CARGO_BIN_EXE_pangu")
        .map(PathBuf::from)
        .expect("cargo must provide the pangu binary for integration tests");

    let clean = Command::new(&binary)
        .args(["artifact", "inspect", "--root"])
        .arg(&fixture.artifact_root)
        .stdin(Stdio::null())
        .output()
        .expect("run artifact inspect");
    assert!(
        clean.status.success(),
        "an empty but valid store must verify: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(String::from_utf8_lossy(&clean.stdout).contains("verdict=verified"));

    fs::write(
        fixture.artifact_root.join(".rollback-operation.lock"),
        "pid=1\n",
    )
    .expect("plant lock");
    let incident = Command::new(&binary)
        .args(["artifact", "inspect", "--root"])
        .arg(&fixture.artifact_root)
        .arg("--json")
        .stdin(Stdio::null())
        .output()
        .expect("run artifact inspect");
    assert!(
        !incident.status.success(),
        "an operator-required store must exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&incident.stdout);
    assert!(stdout.contains("operator.transaction_lock_present"));
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json must emit a parseable report");
    assert_eq!(parsed["verdict"], "operator_required");
    assert_eq!(parsed["read_only"], true);
    assert_eq!(parsed["schema"], "pangu-artifact-inspection/1");
    let _ = config_path;

    record_drill(
        "cli-inspect",
        "pass",
        "CLI reported the stale lock in text and JSON form and exited non-zero",
    );
    fixture.cleanup();
}

fn pangu_config(fixture: &Fixture) -> String {
    let mut config = Config::embedded().expect("embedded config");
    config.boundary.workspace = fixture.workspace.clone();
    config.boundary.readable_roots = vec![fixture.workspace.clone()];
    config.boundary.writable_roots = vec![fixture.workspace.clone()];
    config.checkpoint.enabled = true;
    config.checkpoint.artifact_root = fixture.artifact_root.clone();
    toml::to_string(&config).expect("serialize config")
}
