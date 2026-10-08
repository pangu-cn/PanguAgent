use std::collections::BTreeSet;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNode {
    pub name: String,
    pub depends_on: Vec<String>,
    pub budget_turns: u32,
    pub idempotency_key: String,
    pub manager: bool,
}

impl DagNode {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.budget_turns == 0
            || self.idempotency_key.trim().is_empty()
        {
            return Err(Error::Config(
                "dag node requires name, budget, and idempotency".into(),
            ));
        }
        if self.manager && !self.depends_on.is_empty() {
            return Ok(());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedAction {
    pub name: String,
    pub tools: Vec<String>,
}

impl NamedAction {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.tools.is_empty() {
            return Err(Error::Config("named action requires tools".into()));
        }
        Ok(())
    }
}

pub struct Manager;

impl Manager {
    pub fn review(ok: bool) -> crate::EventKind {
        if ok {
            crate::EventKind::TaskDelegated
        } else {
            crate::EventKind::TaskRejected
        }
    }

    pub fn can_execute_tools() -> bool {
        false
    }
}

pub fn validate_graph(nodes: &[DagNode]) -> Result<()> {
    let names: BTreeSet<_> = nodes.iter().map(|node| node.name.as_str()).collect();
    if names.len() != nodes.len() {
        return Err(Error::Config("duplicate dag node".into()));
    }
    for node in nodes {
        node.validate()?;
        for parent in &node.depends_on {
            if !names.contains(parent.as_str()) || parent == &node.name {
                return Err(Error::Config(format!(
                    "dag dependency `{parent}` is invalid"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_cannot_execute_and_graph_rejects_missing_parent() {
        assert!(!Manager::can_execute_tools());
        assert_eq!(Manager::review(false), crate::EventKind::TaskRejected);
        let nodes = vec![DagNode {
            name: "child".into(),
            depends_on: vec!["missing".into()],
            budget_turns: 1,
            idempotency_key: "k".into(),
            manager: false,
        }];
        assert!(validate_graph(&nodes).is_err());
    }
}
