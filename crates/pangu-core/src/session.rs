//! Read-only navigation over the session node ledger (A1-3).
//!
//! A `SessionTree` is an **in-memory view**, built once from the immutable
//! ledger on disk. It holds no authority: it cannot create a node, cannot move
//! one, and cannot restore a workspace. Restoring a workspace is
//! `pangu rollback`'s job and nothing here is a substitute for it.
//!
//! # Why the traversal code is so defensive
//!
//! The ledger is a directory of independently written JSON files. Nothing at
//! write time guarantees the parent links form a tree — a store can be edited
//! by hand, truncated by a crash between two files, or restored from a partial
//! backup. In that state `parent_session_node_id` can point at an ancestor and
//! a naive walk up the chain spins forever.
//!
//! So every walk here is bounded twice: by a visited set, and by a hard step
//! ceiling derived from the node count. A cycle is reported as a corrupt store,
//! never as an answer. A navigation layer that hangs on damaged input is worse
//! than one that refuses, because the operator waiting on it cannot tell the
//! difference between "still working" and "never finishing".

use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::ArtifactStore;
use crate::checkpoint::{SessionNode, ROOT_NODE_PREFIX};
use crate::error::{Error, Result};

/// An immutable, fully loaded view of the session ledger.
#[derive(Debug, Clone, Default)]
pub struct SessionTree {
    nodes: BTreeMap<String, SessionNode>,
    children: BTreeMap<String, Vec<String>>,
    roots: Vec<String>,
    /// Parents named by a node but absent from the ledger. Surfaced rather than
    /// silently promoted to roots: a missing parent means the tree is
    /// incomplete, and an incomplete tree answers "where did this come from"
    /// with a confident wrong answer.
    orphans: Vec<(String, String)>,
}

impl SessionTree {
    /// Load every node from the store's ledger.
    pub fn load(store: &ArtifactStore) -> Result<Self> {
        Self::from_nodes(store.list_session_nodes()?)
    }

    /// Build a tree from an explicit node set. Kept separate from [`Self::load`]
    /// so the traversal logic can be tested against shapes a real store should
    /// never produce — cycles and orphans in particular.
    pub fn from_nodes(nodes: Vec<SessionNode>) -> Result<Self> {
        let mut tree = SessionTree {
            nodes: BTreeMap::new(),
            children: BTreeMap::new(),
            roots: Vec::new(),
            orphans: Vec::new(),
        };
        for node in nodes {
            node.validate()?;
            let id = node.session_node_id.clone();
            if tree.nodes.insert(id.clone(), node).is_some() {
                return Err(Error::Config(format!(
                    "duplicate session node id `{id}` in the ledger"
                )));
            }
        }
        for (id, node) in &tree.nodes {
            match &node.parent_session_node_id {
                Some(parent) if tree.nodes.contains_key(parent) => tree
                    .children
                    .entry(parent.clone())
                    .or_default()
                    .push(id.clone()),
                Some(parent) => tree.orphans.push((id.clone(), parent.clone())),
                None => tree.roots.push(id.clone()),
            }
        }
        for siblings in tree.children.values_mut() {
            siblings.sort();
        }
        tree.roots.sort();
        tree.orphans.sort();
        Ok(tree)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Nodes whose `parent` is absent from the ledger, as `(node, missing parent)`.
    pub fn orphans(&self) -> &[(String, String)] {
        &self.orphans
    }

    /// Refuse to navigate a tree that is known to be incomplete.
    ///
    /// Orphans do not make traversal unsafe — a walk stops at the missing link
    /// either way — but they do make the *result* misleading, because the walk
    /// looks like it reached the beginning of history when in fact history is
    /// missing. Callers that present a tree to a user should check this.
    ///
    /// **The run-root orphan is not damage.** A run's starting node is created
    /// in memory to name the run's first parent, but its `EventRef` cannot be
    /// sealed until the Journal writes it: `event_id` is derived from the
    /// event's sequence number and its predecessor's `sha`, neither of which
    /// exists before the write. Committing the root anyway would mean inventing
    /// an id that the Journal would later contradict — turning an honestly
    /// absent record into a false one. So every ordinary run leaves exactly one
    /// orphan, and it is expected.
    ///
    /// Only unknown gaps are treated as a broken ledger. Telling an operator
    /// "your tree is corrupt" when the shape is the one every run produces
    /// trains them to ignore the message, which is how a real gap gets missed.
    pub fn ensure_complete(&self) -> Result<()> {
        let unexpected = self.unexplained_orphans();
        if unexpected.is_empty() {
            return Ok(());
        }
        let sample = unexpected
            .iter()
            .take(3)
            .map(|(node, parent)| format!("{node} -> {parent}"))
            .collect::<Vec<_>>()
            .join(", ");
        Err(Error::Config(format!(
            "session tree is incomplete: {} node(s) name a parent that is not in \
             the ledger ({sample}); the history behind them is missing",
            unexpected.len()
        )))
    }

    /// Orphans that are not the known run-root gap.
    ///
    /// A missing parent named [`ROOT_NODE_PREFIX`] is the structural gap
    /// described on [`Self::ensure_complete`]. Anything else is an unexplained
    /// hole in the ledger.
    pub fn unexplained_orphans(&self) -> Vec<(String, String)> {
        self.orphans
            .iter()
            .filter(|(_, parent)| !parent.starts_with(ROOT_NODE_PREFIX))
            .cloned()
            .collect()
    }

    /// The expected run-root gap, as `(node, missing_root)`, when present.
    ///
    /// Reported separately so a caller can say "this run's start is not
    /// recorded, and that is how this version works" instead of either hiding
    /// the gap or calling it corruption.
    pub fn run_root_gaps(&self) -> Vec<(String, String)> {
        self.orphans
            .iter()
            .filter(|(_, parent)| parent.starts_with(ROOT_NODE_PREFIX))
            .cloned()
            .collect()
    }

    pub fn node(&self, session_node_id: &str) -> Result<&SessionNode> {
        self.nodes
            .get(session_node_id)
            .ok_or_else(|| Error::Config(format!("unknown session node `{session_node_id}`")))
    }

    /// Nodes with no parent, i.e. the starting points of each recorded history.
    pub fn roots(&self) -> Vec<&SessionNode> {
        self.roots
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .collect()
    }

    /// Direct children of a node, ordered by id.
    pub fn children(&self, session_node_id: &str) -> Result<Vec<&SessionNode>> {
        self.node(session_node_id)?;
        Ok(self
            .children
            .get(session_node_id)
            .map(|ids| ids.iter().filter_map(|id| self.nodes.get(id)).collect())
            .unwrap_or_default())
    }

    /// The chain from the root down to `session_node_id`, **excluding** the node
    /// itself. Empty when the node is a root.
    ///
    /// Bounded twice: a node may be visited at most once, and the walk may take
    /// at most `len()` steps. A ledger whose parent links form a cycle is a
    /// corrupt store, and it is reported as one.
    pub fn ancestors(&self, session_node_id: &str) -> Result<Vec<&SessionNode>> {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        seen.insert(session_node_id.to_string());
        let mut current = self.node(session_node_id)?.parent_session_node_id.clone();
        let ceiling = self.nodes.len();
        while let Some(id) = current {
            if chain.len() >= ceiling {
                return Err(Error::Config(format!(
                    "session tree walk from `{session_node_id}` exceeded {} steps; \
                     the parent links contain a cycle",
                    ceiling
                )));
            }
            if !seen.insert(id.clone()) {
                return Err(Error::Config(format!(
                    "session tree walk from `{session_node_id}` revisited node \
                     `{id}`; the parent links contain a cycle"
                )));
            }
            let node = self.node(&id)?;
            chain.push(node);
            current = node.parent_session_node_id.clone();
        }
        chain.reverse();
        Ok(chain)
    }

    /// The deepest node that is an ancestor of both inputs, or `None` when they
    /// are in unrelated histories.
    ///
    /// "Deepest" is measured by distance from each input, not by a stored
    /// depth: depth is not recorded, and inventing it from the ledger would
    /// mean trusting a structure that a corrupt store can contradict.
    pub fn common_ancestor(&self, left: &str, right: &str) -> Result<Option<&SessionNode>> {
        let left_chain = self.ancestors(left)?;
        let right_chain = self.ancestors(right)?;
        let right_ids: BTreeSet<&str> = right_chain
            .iter()
            .map(|node| node.session_node_id.as_str())
            .collect();
        Ok(left_chain
            .into_iter()
            .rev()
            .find(|node| right_ids.contains(node.session_node_id.as_str())))
    }

    /// The first node, in id order, that records the given checkpoint.
    pub fn by_checkpoint(&self, checkpoint_id: &str) -> Result<Option<&SessionNode>> {
        Ok(self
            .nodes
            .values()
            .find(|node| node.checkpoint_id.as_deref() == Some(checkpoint_id)))
    }

    /// A flat, indented rendering for humans. Children are visited in id order
    /// under their parent; an orphan is shown at the top level with its missing
    /// parent named, because hiding it would make the tree look whole.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut shown = BTreeSet::new();
        for root in self.roots() {
            self.render_node(&mut out, root, 0, &mut shown);
        }
        for (node_id, parent_id) in &self.orphans {
            let name = self
                .nodes
                .get(node_id)
                .map(|node| node.session_node_id.as_str())
                .unwrap_or(node_id.as_str());
            out.push_str(&format!(
                "orphan  {name}  (parent `{parent_id}` is missing)\n"
            ));
            shown.insert(node_id.clone());
        }
        // A pure cycle has no root and no orphan: every node names a parent
        // that exists. Rendering only the roots would then print nothing at
        // all, which reads as "an empty history" rather than "a broken one".
        for node in self.nodes.values() {
            if !shown.contains(&node.session_node_id) {
                out.push_str(&format!(
                    "unreachable  {}  (no root reaches it; the parent links cycle)\n",
                    node.session_node_id
                ));
            }
        }
        if out.is_empty() {
            out.push_str("no session nodes recorded\n");
        }
        out
    }

    /// Depth-first render. `path` breaks cycles that survived `from_nodes` —
    /// `ancestors` rejects them, but rendering must terminate too.
    fn render_node(
        &self,
        out: &mut String,
        node: &SessionNode,
        depth: usize,
        path: &mut BTreeSet<String>,
    ) {
        let id = node.session_node_id.as_str();
        let checkpoint = node
            .checkpoint_id
            .as_deref()
            .map(|value| format!("  checkpoint={value}"))
            .unwrap_or_default();
        out.push_str(&format!("{}{id}{checkpoint}\n", " ".repeat(depth * 2)));
        if !path.insert(node.session_node_id.clone()) {
            out.push_str(&format!(
                "{}  (already shown above; parent links cycle here)\n",
                " ".repeat(depth * 2)
            ));
            return;
        }
        for child in self.children(&node.session_node_id).unwrap_or_default() {
            self.render_node(out, child, depth + 1, path);
        }
        path.remove(&node.session_node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::EventRef;

    fn node(id: &str, parent: Option<&str>) -> SessionNode {
        let mut node = SessionNode::new(id, EventRef::new("evt_1", "run_1"), None);
        node.parent_session_node_id = parent.map(str::to_string);
        node
    }

    #[test]
    fn a_linear_tree_reports_its_chain_in_root_first_order() {
        let tree = SessionTree::from_nodes(vec![
            node("b", Some("a")),
            node("a", None),
            node("c", Some("b")),
        ])
        .expect("tree");
        tree.ensure_complete().expect("complete");
        let roots: Vec<&str> = tree
            .roots()
            .iter()
            .map(|node| node.session_node_id.as_str())
            .collect();
        assert_eq!(roots, vec!["a"]);
        let chain: Vec<&str> = tree
            .ancestors("c")
            .expect("ancestors")
            .iter()
            .map(|node| node.session_node_id.as_str())
            .collect();
        assert_eq!(
            chain,
            vec!["a", "b"],
            "root first, excluding the node itself"
        );
        assert_eq!(tree.children("b").expect("children").len(), 1);
        assert!(tree.ancestors("a").expect("root has no chain").is_empty());
    }

    /// The hazard that motivates the whole module: a store edited by hand can
    /// make a node its own ancestor. A naive walk would never return.
    #[test]
    fn a_parent_cycle_is_reported_instead_of_walking_forever() {
        let tree = SessionTree::from_nodes(vec![
            node("a", Some("c")),
            node("b", Some("a")),
            node("c", Some("b")),
        ])
        .expect("from_nodes does not itself walk");
        let error = tree
            .ancestors("a")
            .expect_err("a cycle must not be navigable");
        assert!(
            error.to_string().contains("cycle"),
            "the error must name the cause, got: {error}"
        );
        // And rendering must terminate on the same input, and must say the
        // history is broken rather than printing an empty tree.
        let rendered = tree.render();
        assert!(
            rendered.contains("unreachable") && rendered.contains("cycle"),
            "a pure cycle has no root and no orphan, so rendering only roots \
             would print nothing and read as an empty history: {rendered}"
        );
    }

    #[test]
    fn a_node_that_is_its_own_parent_is_rejected_at_construction() {
        let error = SessionTree::from_nodes(vec![node("a", Some("a"))])
            .expect_err("self-parenting is rejected by validate");
        assert!(error.to_string().contains("own parent"), "got: {error}");
    }

    /// A missing parent must not be quietly promoted to a root: the walk would
    /// then look like it reached the beginning of history.
    #[test]
    fn a_missing_parent_is_surfaced_and_blocks_complete_navigation() {
        let tree = SessionTree::from_nodes(vec![node("b", Some("gone"))]).expect("tree");
        assert_eq!(tree.orphans(), &[("b".to_string(), "gone".to_string())]);
        let error = tree
            .ensure_complete()
            .expect_err("an incomplete tree must refuse to present as whole");
        assert!(error.to_string().contains("incomplete"), "got: {error}");
        // The chain up to the gap is still available, it just stops there.
        assert!(
            tree.ancestors("b").is_err(),
            "the missing link is not walkable"
        );
        assert!(tree.render().contains("orphan"), "{}", tree.render());
    }

    #[test]
    fn common_ancestor_finds_the_deepest_shared_node_and_admits_unrelated_roots() {
        let tree = SessionTree::from_nodes(vec![
            node("root", None),
            node("left", Some("root")),
            node("right", Some("root")),
            node("left_leaf", Some("left")),
            node("unrelated", None),
        ])
        .expect("tree");
        assert_eq!(
            tree.common_ancestor("left_leaf", "right")
                .expect("walk")
                .map(|node| node.session_node_id.as_str()),
            Some("root")
        );
        assert_eq!(
            tree.common_ancestor("left", "unrelated")
                .expect("walk")
                .map(|node| node.session_node_id.as_str()),
            None,
            "separate histories have no shared ancestor and must say so"
        );
    }

    /// Every ordinary run leaves exactly one node whose parent is the run's
    /// uncommitted root. That shape is expected, so it must not be reported as
    /// ledger damage — an operator told "corrupt" about the one shape every run
    /// produces learns to ignore the warning that matters.
    #[test]
    fn an_expected_run_root_gap_is_not_reported_as_damage() {
        let tree = SessionTree::from_nodes(vec![node("node_abc_1", Some("node_root_123_0"))])
            .expect("tree");

        assert_eq!(tree.orphans().len(), 1, "the gap is still surfaced");
        assert!(
            tree.ensure_complete().is_ok(),
            "the run-root gap is how this version works, not corruption"
        );
        assert_eq!(tree.run_root_gaps().len(), 1);
        assert!(tree.unexplained_orphans().is_empty());
    }

    /// A gap that is not the known run-root shape is still damage, even when it
    /// appears alongside the expected gap. Suppressing this would be the exact
    /// failure the classification exists to prevent.
    #[test]
    fn an_unknown_gap_is_still_damage_even_next_to_an_expected_one() {
        let tree = SessionTree::from_nodes(vec![
            node("node_abc_1", Some("node_root_123_0")),
            node("node_def_2", Some("node_missing_9")),
        ])
        .expect("tree");

        assert_eq!(tree.orphans().len(), 2);
        assert_eq!(tree.run_root_gaps().len(), 1);
        assert_eq!(
            tree.unexplained_orphans(),
            vec![("node_def_2".to_string(), "node_missing_9".to_string())],
            "only the run-root gap is expected"
        );
        let error = tree
            .ensure_complete()
            .expect_err("an unexplained gap must still refuse");
        assert!(error.to_string().contains("incomplete"), "got: {error}");
        assert!(
            error.to_string().contains("node_def_2"),
            "the error must name the unexplained gap, not the expected one: {error}"
        );
    }

    /// A complete ledger has neither kind of gap.
    #[test]
    fn a_complete_tree_reports_no_gaps_of_either_kind() {
        let tree =
            SessionTree::from_nodes(vec![node("a", None), node("b", Some("a"))]).expect("tree");
        assert!(tree.ensure_complete().is_ok());
        assert!(tree.orphans().is_empty());
        assert!(tree.run_root_gaps().is_empty());
        assert!(tree.unexplained_orphans().is_empty());
    }

    #[test]
    fn a_duplicate_id_is_rejected_rather_than_silently_overwritten() {
        let error = SessionTree::from_nodes(vec![node("a", None), node("a", None)])
            .expect_err("duplicates");
        assert!(error.to_string().contains("duplicate"), "got: {error}");
    }

    #[test]
    fn lookup_by_checkpoint_and_absence_are_both_explicit() {
        let mut with_checkpoint = node("a", None);
        with_checkpoint.checkpoint_id = Some("cp_1".into());
        let tree =
            SessionTree::from_nodes(vec![with_checkpoint, node("b", Some("a"))]).expect("tree");
        assert_eq!(
            tree.by_checkpoint("cp_1")
                .expect("lookup")
                .map(|node| node.session_node_id.as_str()),
            Some("a")
        );
        assert!(tree.by_checkpoint("cp_absent").expect("lookup").is_none());
        assert!(tree
            .node("nope")
            .expect_err("unknown node")
            .to_string()
            .contains("unknown session node"));
    }
}
