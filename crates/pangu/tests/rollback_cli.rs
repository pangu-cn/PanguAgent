use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::{Config, GoalContract, Policy, Rule};
use pangu_core::{
    ArtifactStore, CheckpointArtifact, EventRef, SessionNode, SnapshotLimits, SnapshotRequest,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pangu-cli-process-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn artifact(
    contract: &GoalContract,
    workspace: &Path,
    checkpoint_id: &str,
    node_id: &str,
    event_id: &str,
) -> CheckpointArtifact {
    CheckpointArtifact::new(
        checkpoint_id,
        "run-cli",
        "session-cli",
        node_id,
        EventRef::new(event_id, "run-cli"),
        workspace.to_path_buf(),
        contract.digest(),
        contract.policy_digest.clone(),
        "0".repeat(64),
    )
}

fn commit(
    store: &ArtifactStore,
    request: &SnapshotRequest,
    contract: &GoalContract,
    workspace: &Path,
    checkpoint_id: &str,
    node_id: &str,
    event_id: &str,
) -> CheckpointArtifact {
    let value = artifact(contract, workspace, checkpoint_id, node_id, event_id);
    let node = SessionNode::new(
        node_id,
        value.event_ref.clone(),
        Some(checkpoint_id.to_string()),
    );
    store
        .commit_snapshot_with_node(request, value, Some(&node))
        .unwrap()
}

#[test]
fn rollback_subcommand_restores_a_checkpoint_in_a_real_process() {
    let root = temp_root("rollback");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let artifact_root = workspace.join(".pangu/checkpoints");
    let state = workspace.join("state.txt");
    std::fs::write(&state, "before").unwrap();

    let mut config = Config::embedded().unwrap();
    config.boundary.workspace = workspace.clone();
    config.boundary.readable_roots = vec![workspace.clone()];
    config.boundary.writable_roots = vec![workspace.clone()];
    config.checkpoint.enabled = true;
    config.checkpoint.artifact_root = artifact_root.clone();
    config.unattended = false;
    config.rules = vec![Rule::allow(
        "allow-rollback",
        "rollback",
        "operator rollback",
    )];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    let contract = GoalContract::from_config("cli rollback", &config).unwrap();
    let policy = Policy::new(config.rules.clone()).unwrap();
    assert_eq!(contract.policy_digest, policy.digest());
    let store = ArtifactStore::open(&artifact_root).unwrap();
    let request = SnapshotRequest::new(
        workspace.clone(),
        vec![workspace.clone()],
        vec![workspace.join(".pangu"), artifact_root.clone()],
        config.boundary.forbidden_globs.clone(),
        SnapshotLimits::default(),
    );
    let target = commit(
        &store,
        &request,
        &contract,
        &workspace,
        "checkpoint-target",
        "node-target",
        "event-target",
    );
    std::fs::write(&state, "after").unwrap();
    let source = commit(
        &store,
        &request,
        &contract,
        &workspace,
        "checkpoint-source",
        "node-source",
        "event-source",
    );
    let config_path = root.join("boundary.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

    let binary = std::env::var_os("CARGO_BIN_EXE_pangu")
        .map(PathBuf::from)
        .expect("cargo must provide the pangu binary for integration tests");
    let mut child = Command::new(binary)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "rollback",
            "--checkpoint-id",
            &target.checkpoint_id,
            "--source-node",
            &source.session_node_id,
            "--rollback-id",
            "rollback-cli-1",
            "--reason",
            "integration rollback",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("rollback: Applied"));
    assert_eq!(std::fs::read_to_string(&state).unwrap(), "before");

    std::fs::remove_dir_all(root).ok();
}
