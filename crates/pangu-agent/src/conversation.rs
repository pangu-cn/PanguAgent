//! Persisting and restoring the conversation across a run.
//!
//! The agent's `history` is otherwise rebuilt from scratch on every run, which
//! means an interrupted task can only be restarted, never resumed. This wires
//! the [`ConversationSnapshot`] concept (ADR-0004) into the run loop.
//!
//! The rule this module exists to enforce: a stored conversation is **model
//! input**. `restore` yields plain `Message` values and nothing else — no
//! decision, no effect, no memory of an approval. A resumed run re-evaluates
//! every action through `Policy -> Sandbox -> Approval` exactly as a fresh run
//! would. Restoring a history must never become a way to skip a gate.

use std::sync::atomic::{AtomicU64, Ordering};

use pangu_core::{ArtifactStore, ConversationSnapshot, Message, Result};

pub struct ConversationRuntime {
    store: ArtifactStore,
    save_every_turn: bool,
    /// Sequence within this process, so ids from one run are ordered.
    counter: AtomicU64,
}

impl ConversationRuntime {
    /// Open the runtime when conversation persistence is enabled.
    ///
    /// Returns `None` when it is off, matching how the checkpoint runtime
    /// behaves. A disabled feature must not be able to fail a run over a path
    /// it will never read.
    pub fn from_contract(contract: &pangu_boundary::GoalContract) -> Result<Option<Self>> {
        if !contract.conversation.enabled {
            return Ok(None);
        }
        Ok(Some(Self {
            store: ArtifactStore::open(&contract.conversation.artifact_root)?,
            save_every_turn: contract.conversation.save_every_turn,
            counter: AtomicU64::new(0),
        }))
    }

    /// Build a snapshot id that is unique within a process and groups the
    /// snapshots of one run together.
    ///
    /// The run label is a **digest**, never the goal text. The journal already
    /// redacts the goal before writing it anywhere; putting the raw goal into a
    /// filename would undo that, since a path is a place a secret is stored in
    /// and is trivially listed.
    fn next_snapshot_id(&self, run_label: &str) -> String {
        let ordinal = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let label = pangu_core::short_hash(&pangu_core::redact_text(run_label));
        format!("conv_{label}_{nanos}_{ordinal}_{}", std::process::id())
    }

    /// Persist the history as it stands right now.
    ///
    /// Errors are returned, not logged. A conversation store that silently
    /// drops writes would leave an operator believing a run is resumable when
    /// it is not.
    pub fn save(
        &self,
        run_id: &str,
        history: &[Message],
        session_node_id: Option<&str>,
    ) -> Result<ConversationSnapshot> {
        let snapshot_id = self.next_snapshot_id(run_id);
        let mut snapshot = ConversationSnapshot::new(snapshot_id, run_id, history.to_vec())?;
        if let Some(node) = session_node_id {
            snapshot = snapshot.with_session_node(node);
        }
        self.store.save_conversation(&snapshot)?;
        Ok(snapshot)
    }

    /// Load a snapshot for a resumed run.
    ///
    /// The digest is verified on the way out, so a snapshot edited since it was
    /// written is refused rather than fed to a model as if it were intact.
    pub fn load(&self, snapshot_id: &str) -> Result<ConversationSnapshot> {
        self.store.load_conversation(snapshot_id)
    }

    /// Every stored snapshot id, oldest first by id order.
    pub fn list(&self) -> Result<Vec<String>> {
        self.store.list_conversations()
    }

    /// The most recent snapshot, which is what a resume normally wants.
    ///
    /// "Most recent" is by id order, and ids embed a nanosecond timestamp, so
    /// that is chronological. Returns `None` on an empty store rather than an
    /// error: there is nothing to resume, which is a normal state.
    pub fn latest(&self) -> Result<Option<ConversationSnapshot>> {
        let Some(last) = self.list()?.pop() else {
            return Ok(None);
        };
        Ok(Some(self.load(&last)?))
    }

    pub fn saves_every_turn(&self) -> bool {
        self.save_every_turn
    }
}

/// The history a run starts with.
///
/// A fresh run seeds the system prompt and the goal. A resumed run must not:
/// re-adding them would duplicate the instructions at the head of a history
/// that already contains them, and the model would see two goals.
pub fn seed_history(system_prompt: &str, goal: &str) -> Vec<Message> {
    vec![
        Message::system(system_prompt),
        Message::user(goal.to_string()),
    ]
}

/// Guard against resuming a history that does not start where a real run does.
///
/// A conversation that lost its leading system turn is not a conversation this
/// agent can continue: without the boundary rules, the model would be resuming
/// into a context that never told it what it was not allowed to do. Refusing
/// here is the difference between "cannot resume" and "resumed into a run with
/// no guardrails".
pub fn validate_resumable(history: &[Message]) -> Result<()> {
    match history.first() {
        Some(Message::System { .. }) => Ok(()),
        Some(_) => Err(pangu_core::Error::Config(
            "conversation does not start with a system turn; it cannot be resumed safely because \
             the boundary instructions would be missing"
                .into(),
        )),
        None => Err(pangu_core::Error::Config(
            "conversation is empty; nothing to resume".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> Vec<Message> {
        seed_history("you are pangu", "read notes.md")
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pangu-conv-runtime-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn runtime(root: &std::path::PathBuf) -> ConversationRuntime {
        ConversationRuntime {
            store: ArtifactStore::open(root).expect("open"),
            save_every_turn: true,
            counter: AtomicU64::new(0),
        }
    }

    #[test]
    fn saved_conversations_are_listed_and_the_latest_loads() {
        let root = temp_root("save");
        let runtime = runtime(&root);
        for _ in 0..3 {
            runtime.save("run-1", &history(), None).expect("save");
        }
        let ids = runtime.list().expect("list");
        assert_eq!(ids.len(), 3);
        let latest = runtime.latest().expect("latest").expect("a snapshot");
        assert_eq!(latest.restore().expect("restore"), history());
        assert_eq!(latest.run_id, "run-1");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn an_empty_store_reports_nothing_to_resume_rather_than_failing() {
        let root = temp_root("empty");
        let runtime = runtime(&root);
        assert!(runtime.latest().expect("latest").is_none());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_conversation_without_a_leading_system_turn_cannot_be_resumed() {
        // This is the guardrail case: resuming into a history that never
        // carried the boundary instructions would continue a run with none.
        let history = vec![Message::user("read notes.md")];
        let error = validate_resumable(&history).expect_err("must refuse");
        assert!(
            error.to_string().contains("system turn"),
            "the error must say what is missing, got: {error}"
        );
        assert!(validate_resumable(&[]).is_err());
        assert!(validate_resumable(&seed_history("sys", "goal")).is_ok());
    }

    #[test]
    fn a_resumed_conversation_yields_only_messages() {
        // The type-level guarantee: what a resume can produce is `Message`, and
        // nothing the boundary would evaluate.
        let root = temp_root("shape");
        let runtime = runtime(&root);
        let snapshot = runtime.save("run-1", &history(), None).expect("save");
        let restored = runtime
            .load(&snapshot.snapshot_id)
            .expect("load")
            .restore()
            .expect("restore");
        let _: Vec<Message> = restored;
        std::fs::remove_dir_all(root).ok();
    }
}
