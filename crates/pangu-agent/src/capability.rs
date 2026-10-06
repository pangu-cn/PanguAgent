//! B1: the capability manifest.
//!
//! Every tool an extension/toolkit exposes is *declared* here once, as data,
//! before any model sees it. The declaration answers: what risk class it
//! belongs to, what effect boundary it claims, which roots/hosts/processes
//! it can touch, and how long it may run. Policy and approval consume the
//! declared risk; the assembler/inspection tooling can consume the rest
//! without executing anything.
//!
//! Invariants enforced by [`CapabilityManifest::validate`]:
//! unique non-empty names; a declared effect descriptor that is consistent
//! with the declared risk (same rules as the runtime's
//! `EffectDescriptor::validate_for_risk`); a `NoEffect` capability must not
//! declare writes/hosts/processes; bounded declaration sizes.

use pangu_boundary::Risk;
use serde::{Deserialize, Serialize};

use crate::{EffectDescriptor, EffectScope, Reversibility};

const MAX_NAME: usize = 128;
const MAX_ENTRIES: usize = 512;
const MAX_LIST: usize = 64;
const MAX_TIMEOUT_MS: u64 = 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub version: String,
    pub risk: Risk,
    pub effect: EffectDescriptor,
    /// Locations it may read (e.g. `"workspace"`, `"<root>"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    /// Locations it may write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    /// Network hosts it may contact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Subprocesses it may spawn (program names only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<String>,
    /// Wall-clock ceiling when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl Capability {
    fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() || self.name.len() > MAX_NAME {
            anyhow::bail!("capability name must be 1..={MAX_NAME} chars");
        }
        if self.version.is_empty() {
            anyhow::bail!("capability `{}` needs a version", self.name);
        }
        self.effect.validate_for_risk(self.risk)?;
        let total = self.reads.len() + self.writes.len() + self.hosts.len() + self.processes.len();
        if total > MAX_LIST * 4 {
            anyhow::bail!("capability `{}` declares too many roots/hosts", self.name);
        }
        if self.effect.reversibility == Reversibility::NoEffect && !self.writes.is_empty() {
            // Hosts/processes are allowed: an `ExternalRead`/`ProcessRead` +
            // `NoEffect` capability must still be able to name the targets
            // it reads through.
            anyhow::bail!(
                "capability `{}` declares NoEffect but lists writes",
                self.name
            );
        }
        if self.effect.scope == EffectScope::Workspace
            && (!self.hosts.is_empty() || !self.processes.is_empty())
        {
            anyhow::bail!(
                "workspace-scoped capability `{}` must not declare hosts/processes",
                self.name
            );
        }
        if let Some(timeout) = self.timeout_ms {
            if timeout == 0 || timeout > MAX_TIMEOUT_MS {
                anyhow::bail!("capability `{}` timeout out of range", self.name);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub capabilities: Vec<Capability>,
}

impl CapabilityManifest {
    pub fn new(capabilities: Vec<Capability>) -> Self {
        Self { capabilities }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.capabilities.len() > MAX_ENTRIES {
            anyhow::bail!("too many capabilities declared");
        }
        let mut seen = std::collections::HashSet::new();
        for capability in &self.capabilities {
            capability.validate()?;
            if !seen.insert(&capability.name) {
                anyhow::bail!("duplicate capability name `{}`", capability.name);
            }
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.name == name)
    }

    /// Names of every declared capability — the only tools an adapter may
    /// advertise through `ToolExecutor::specs`.
    pub fn names(&self) -> Vec<&str> {
        self.capabilities.iter().map(|c| c.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Capability {
        Capability {
            name: "read_file".into(),
            version: "1".into(),
            risk: Risk::ReadOnly,
            effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
            reads: vec!["workspace".into()],
            writes: vec![],
            hosts: vec![],
            processes: vec![],
            timeout_ms: Some(30_000),
        }
    }

    #[test]
    fn a_consistent_manifest_validates() {
        CapabilityManifest::new(vec![sample()]).validate().unwrap();
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let err = CapabilityManifest::new(vec![sample(), sample()])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn no_effect_with_writes_is_rejected() {
        let mut capability = sample();
        capability.writes = vec!["workspace".into()];
        let err = CapabilityManifest::new(vec![capability])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("NoEffect"));
    }

    #[test]
    fn external_mutation_must_be_irreversible() {
        let mut capability = sample();
        capability.risk = Risk::Destructive;
        capability.effect =
            EffectDescriptor::new(EffectScope::ExternalMutation, Reversibility::Reversible);
        let err = CapabilityManifest::new(vec![capability])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("external_mutation"));
    }

    #[test]
    fn workspace_effect_cannot_declare_hosts() {
        let mut capability = sample();
        capability.hosts = vec!["example.com".into()];
        let err = CapabilityManifest::new(vec![capability])
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("hosts"));
    }

    #[test]
    fn unknown_tool_lookup_is_none() {
        let manifest = CapabilityManifest::new(vec![sample()]);
        assert!(manifest.get("nope").is_none());
        assert_eq!(manifest.names(), vec!["read_file"]);
    }
}
