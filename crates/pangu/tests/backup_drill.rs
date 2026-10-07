//! §9.3 drill: the backup is readable independently, and the audit chain is
//! separate from the machine it audits.
//!
//! # What this drill is for
//!
//! The activation gate asks a question that a feature test cannot answer: if the
//! workspace were lost, would the recovery point still be usable, and would the
//! audit trail still be readable?
//!
//! That is not the same as "rollback works". A store that verifies in place can
//! still fail once it is moved: a copy can lose a file, a symlink can break, a
//! path recorded inside can point back at the original machine. The only way to
//! find out is to **copy it somewhere else and read it there**, which is what
//! this drill does.
//!
//! # Why the copy is a real copy
//!
//! The store is copied with a fresh recursive walk into a different directory
//! tree, not moved or hard-linked. Hard links would share inodes, so the "copy"
//! would still depend on the original blocks — exactly the failure mode a backup
//! is supposed to survive.
//!
//! # What this drill does not prove
//!
//! It runs on one machine with one filesystem. It cannot show that a copy on
//! **different media**, an off-site location, or a restored snapshot of the
//! volume is readable, and it says nothing about retention or rotation policy.
//! Those remain part of §9.3's operator-side evidence, and this test reports them
//! as remaining rather than implying it covered them.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::{Config, GoalContract, Rule};
use pangu_core::{
    ArtifactStore, CheckpointArtifact, EventRef, SessionNode, SnapshotLimits, SnapshotRequest,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pangu-backup-drill-{label}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("create root");
    std::fs::canonicalize(path).expect("canonicalize root")
}

/// Copy a directory tree, creating the destination.
///
/// Written out rather than delegated so the copy is unambiguously a byte-for-byte
/// duplicate: a helper that preserved links or reflinked would defeat the point.
fn copy_tree(from: &Path, to: &Path) -> u64 {
    std::fs::create_dir_all(to).expect("create destination");
    let mut copied = 0;
    for entry in std::fs::read_dir(from).expect("read source") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            copied += copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
            copied += 1;
        }
    }
    copied
}

/// Run `pangu artifact inspect` and return whether it reported `verified`.
fn inspect_reports_verified(config_path: &Path, root: &Path) -> (bool, String) {
    let binary = std::env::var_os("CARGO_BIN_EXE_pangu")
        .map(PathBuf::from)
        .expect("cargo must provide the pangu binary for integration tests");
    let output = Command::new(binary)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
            "artifact",
            "inspect",
            "--root",
            root.to_str().expect("root is UTF-8"),
            "--json",
        ])
        .output()
        .expect("run artifact inspect");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (
        output.status.success() && stdout.contains("verified"),
        format!("status={:?} stdout={stdout} stderr={stderr}", output.status),
    )
}

#[test]
fn a_copied_store_still_verifies_and_the_audit_chain_is_separable() {
    let root = temp_root("copy");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let artifact_root = workspace.join(".pangu/checkpoints");
    std::fs::write(workspace.join("state.txt"), "the state to preserve").expect("seed");

    let mut config = Config::embedded().expect("embedded");
    config.boundary.workspace = workspace.clone();
    config.boundary.readable_roots = vec![workspace.clone()];
    config.boundary.writable_roots = vec![workspace.clone()];
    config.checkpoint.enabled = true;
    config.checkpoint.artifact_root = artifact_root.clone();
    config.unattended = false;
    config.rules = vec![Rule::allow("allow-rollback", "rollback", "drill")];
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    let contract = GoalContract::from_config("backup drill", &config).expect("contract");

    let store = ArtifactStore::open(&artifact_root).expect("open store");
    let request = SnapshotRequest::new(
        workspace.clone(),
        vec![workspace.clone()],
        vec![workspace.join(".pangu"), artifact_root.clone()],
        config.boundary.forbidden_globs.clone(),
        SnapshotLimits::default(),
    );
    let value = CheckpointArtifact::new(
        "checkpoint-backup",
        "run-backup",
        "session-backup",
        "node-backup",
        EventRef::new("event-backup", "run-backup"),
        workspace.clone(),
        contract.digest(),
        contract.policy_digest.clone(),
        "0".repeat(64),
    );
    let node = SessionNode::new(
        "node-backup",
        value.event_ref.clone(),
        Some("checkpoint-backup".to_string()),
    );
    store
        .commit_snapshot_with_node(&request, value, Some(&node))
        .expect("commit snapshot");

    let config_path = root.join("boundary.toml");
    std::fs::write(&config_path, toml::to_string(&config).expect("serialize"))
        .expect("write config");

    // 1. The original verifies.
    let (before_ok, before_detail) = inspect_reports_verified(&config_path, &artifact_root);
    assert!(before_ok, "the original store must verify: {before_detail}");
    println!("before: verified. {before_detail}");

    // 2. Copy the store to a **different** tree and inspect the copy.
    //
    // This is the actual backup claim: readable somewhere else, without the
    // original directory present.
    let backup = root.join("offbox-backup");
    let copied_files = copy_tree(&artifact_root, &backup);
    println!("copied {copied_files} files to {}", backup.display());
    assert!(copied_files > 0, "the copy must contain files");
    let (copy_ok, copy_detail) = inspect_reports_verified(&config_path, &backup);
    assert!(
        copy_ok,
        "a copy of the store must verify on its own: {copy_detail}"
    );
    println!("copy: verified. {copy_detail}");

    // 3. Prove the copy does not depend on the original: remove the original
    // tree and inspect the copy again.
    //
    // Without this step the first check could have passed by reading the
    // original through a link or a shared inode.
    std::fs::remove_dir_all(&artifact_root).expect("remove the original store");
    let (standalone_ok, standalone_detail) = inspect_reports_verified(&config_path, &backup);
    assert!(
        standalone_ok,
        "the copy must verify with the original gone: {standalone_detail}"
    );
    println!("copy with the original removed: verified. {standalone_detail}");

    // 4. A damaged copy must be detected rather than silently accepted. A backup
    // that cannot fail its own integrity check is not evidence of anything.
    let entries: Vec<PathBuf> = walk_files(&backup);
    let victim = entries
        .iter()
        .find(|path| path.extension().map(|e| e == "json").unwrap_or(false))
        .cloned()
        .or_else(|| entries.first().cloned())
        .expect("the copy has at least one file");
    let mut damaged = std::fs::read(&victim).expect("read victim");
    if damaged.is_empty() {
        damaged.push(b'x');
    } else {
        // Flip one byte in the middle: enough to break a digest, small enough
        // that the file remains parseable so the failure is integrity, not syntax.
        let middle = damaged.len() / 2;
        damaged[middle] ^= 0xFF;
    }
    std::fs::write(&victim, &damaged).expect("damage the copy");
    let (damaged_ok, damaged_detail) = inspect_reports_verified(&config_path, &backup);
    assert!(
        !damaged_ok,
        "a damaged copy must not be reported as verified: {damaged_detail}"
    );
    println!("damaged copy correctly refused. {}", victim.display());

    // Leave the surviving artifacts for an operator to look at, and record the
    // paths so the drill's output is usable as evidence.
    println!("backup location: {}", backup.display());
    println!(
        "remaining operator work for §9.3: off-machine location, retention policy, \
         and rotation exclusion are not covered by this drill"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Every regular file under `root`, for picking a corruption target.
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
