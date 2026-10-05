//! `SessionNode.history_digest` must name a conversation state that really
//! existed.
//!
//! The field was declared, serialized, and validated from the start, but never
//! assigned: every node carried `None`, so a node could not say which
//! conversation state it belonged to. A field that is always absent is worse
//! than a missing one — it reads like "this node has no conversation" when the
//! truth is "nobody ever filled it in".
//!
//! Filling it is only correct if the digest matches a snapshot the store
//! actually holds. `pangu session replay` reads the node, then loads the
//! conversation for that node; if the two disagree, the tree claims a
//! conversation state that no snapshot backs, which is exactly the kind of
//! plausible-looking-but-false evidence this project exists to avoid.
//!
//! These tests therefore assert *agreement between two independently stored
//! artifacts*, not merely that the field became non-null.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::Config;
use pangu_core::ArtifactStore;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Probe {
    root: PathBuf,
    artifact_root: PathBuf,
    conversation_root: PathBuf,
    config_path: PathBuf,
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Probe {
    /// A workspace with checkpointing and conversation persistence both on.
    ///
    /// Both must be on for this question to be askable at all: without
    /// persistence there is no snapshot to agree with, and without
    /// checkpointing there is no node to carry the digest.
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pangu-node-digest-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("probe root");
        let root = fs::canonicalize(&root).expect("canonical probe root");
        let artifact_root = root.join(".pangu/checkpoints");
        let conversation_root = root.join(".pangu/conversations");
        // The scripted demo reads Cargo.toml from the workspace, so the tool
        // call succeeds and a checkpoint is worth expecting.
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"node-digest-probe\"\nversion = \"0.1.0\"\n",
        )
        .expect("seed workspace");

        let mut config = Config::embedded().expect("embedded config");
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = artifact_root.clone();
        config.conversation.enabled = true;
        config.conversation.artifact_root = conversation_root.clone();
        config.conversation.save_every_turn = true;
        config.unattended = false;
        let config_path = root.join("boundary.toml");
        fs::write(
            &config_path,
            toml::to_string(&config).expect("serialize config"),
        )
        .expect("write config");

        Self {
            root,
            artifact_root,
            conversation_root,
            config_path,
        }
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let binary = std::env::var_os("CARGO_BIN_EXE_pangu")
            .map(PathBuf::from)
            .expect("cargo must provide the pangu binary for integration tests");
        let output = Command::new(&binary)
            .arg("--config")
            .arg(&self.config_path)
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .output()
            .expect("invoke pangu");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Every session node this run committed, as `(id, history_digest)`.
    fn session_nodes(&self) -> Vec<(String, Option<String>)> {
        ArtifactStore::open(&self.artifact_root)
            .expect("open artifact store")
            .list_session_nodes()
            .expect("list session nodes")
            .into_iter()
            .map(|node| (node.session_node_id, node.history_digest))
            .collect()
    }

    /// Every stored snapshot, as `(snapshot_id, history_digest)`.
    fn conversations(&self) -> Vec<(String, String)> {
        let store = ArtifactStore::open(&self.conversation_root).expect("open conversation store");
        store
            .list_conversations()
            .expect("list conversations")
            .into_iter()
            .map(|id| {
                let snapshot = store.load_conversation(&id).expect("load conversation");
                (id, snapshot.history_digest)
            })
            .collect()
    }
}

/// The field is no longer a dead field: a checkpointed run fills it in.
#[test]
fn a_committed_session_node_records_a_history_digest() {
    let probe = Probe::new("assigned");
    let (ok, stdout, stderr) = probe.run(&["--demo"]);
    assert!(ok, "demo must succeed; stderr: {stderr}\nstdout: {stdout}");

    let nodes = probe.session_nodes();
    assert!(
        !nodes.is_empty(),
        "a checkpointing demo must commit at least one session node"
    );
    for (id, digest) in &nodes {
        let digest = digest.as_deref().unwrap_or_else(|| {
            panic!("session node `{id}` carries no history_digest; the field is still unassigned")
        });
        assert_eq!(
            digest.len(),
            64,
            "node `{id}` must carry a SHA-256 hex digest, got {digest:?}"
        );
        assert!(
            digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "node `{id}` digest must be hex, got {digest:?}"
        );
    }
}

/// The digest on a node must equal the digest of a conversation the store
/// actually holds. Without this, the node asserts a conversation state that
/// no snapshot backs.
#[test]
fn the_node_digest_matches_a_stored_conversation_snapshot() {
    let probe = Probe::new("agrees");
    let (ok, _stdout, stderr) = probe.run(&["--demo"]);
    assert!(ok, "demo must succeed; stderr: {stderr}");

    let node_digests: Vec<String> = probe
        .session_nodes()
        .into_iter()
        .filter_map(|(_, digest)| digest)
        .collect();
    assert!(
        !node_digests.is_empty(),
        "the run must produce at least one node carrying a digest"
    );

    let snapshot_digests: Vec<String> = probe
        .conversations()
        .into_iter()
        .map(|(_, digest)| digest)
        .collect();

    for digest in &node_digests {
        assert!(
            snapshot_digests.contains(digest),
            "node digest {digest} matches no stored conversation snapshot. \
             Stored digests were {snapshot_digests:?}. A node digest that names \
             no snapshot is false evidence, which is worse than an absent field."
        );
    }
}

/// `pangu session replay` is the consumer that ties the two together.
///
/// A node can hold several snapshots (one per turn while the run sits there,
/// plus the final one), and `replay` deliberately reports the *latest*, which
/// is the furthest the run got before leaving the node. The node's digest
/// records the state at the moment the node was **created**. Those are
/// different moments, so the node digest must match *one* snapshot at that
/// node — not necessarily the newest. Asserting equality with the replay
/// output would be asserting a promise the design does not make.
#[test]
fn the_node_digest_matches_one_of_the_snapshots_taken_at_that_node() {
    let probe = Probe::new("replay");
    let (ok, _stdout, stderr) = probe.run(&["--demo"]);
    assert!(ok, "demo must succeed; stderr: {stderr}");

    let (node_id, node_digest) = probe
        .session_nodes()
        .into_iter()
        .find(|(_, digest)| digest.is_some())
        .expect("at least one node must carry a digest");
    let node_digest = node_digest.expect("checked above");

    // Collect every snapshot the store ties to this node.
    let store = ArtifactStore::open(&probe.conversation_root).expect("open conversation store");
    let at_node: Vec<String> = store
        .list_conversations()
        .expect("list conversations")
        .into_iter()
        .filter_map(|id| store.load_conversation(&id).ok())
        .filter(|snapshot| snapshot.session_node_id.as_deref() == Some(node_id.as_str()))
        .map(|snapshot| snapshot.history_digest)
        .collect();
    assert!(
        !at_node.is_empty(),
        "node `{node_id}` carries a digest but the store has no snapshot tied to it"
    );
    assert!(
        at_node.contains(&node_digest),
        "the digest on node `{node_id}` must describe a conversation state that was \
         actually stored at that node. Node said {node_digest}, the store has {at_node:?}. \
         A digest naming no snapshot is false evidence."
    );

    // And replay must still work, reporting a real snapshot for the node.
    let (ok, stdout, stderr) = probe.run(&["session", "replay", &node_id, "--json"]);
    assert!(
        ok,
        "replay of node `{node_id}` must succeed; stderr: {stderr}"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse replay json");
    let replayed = value["history_digest"]
        .as_str()
        .expect("replay must report a digest");
    assert!(
        at_node.iter().any(|digest| digest == replayed),
        "replay must report one of the snapshots stored at the node, got {replayed}"
    );
}

/// The digest must describe the conversation *after* the tool result landed,
/// not before it. Recording the pre-result history would point the node at a
/// state the conversation never held.
#[test]
fn the_digest_describes_the_history_that_includes_the_tool_result() {
    let probe = Probe::new("ordering");
    let (ok, _stdout, stderr) = probe.run(&["--demo"]);
    assert!(ok, "demo must succeed; stderr: {stderr}");

    let (node_id, node_digest) = probe
        .session_nodes()
        .into_iter()
        .find(|(_, digest)| digest.is_some())
        .expect("at least one node must carry a digest");
    let node_digest = node_digest.expect("checked above");

    let store = ArtifactStore::open(&probe.conversation_root).expect("open conversation store");
    let snapshot = store
        .list_conversations()
        .expect("list conversations")
        .into_iter()
        .filter_map(|id| store.load_conversation(&id).ok())
        .find(|snapshot| snapshot.session_node_id.as_deref() == Some(node_id.as_str()))
        .expect("a snapshot must be tied to the node that carries the digest");

    assert_eq!(
        snapshot.history_digest, node_digest,
        "the node must describe the same conversation state its own snapshot does"
    );
    // A tool result must be present: the checkpoint is created after a
    // successful tool action, so the digest cannot describe the initial
    // system+goal-only history.
    assert!(
        snapshot
            .messages
            .iter()
            .any(|message| matches!(message, pangu_core::Message::Tool { .. })),
        "the digested history must include the tool result that triggered the \
         checkpoint, not just the seeded system and goal turns"
    );
}
