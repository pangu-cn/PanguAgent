use anyhow::{bail, Result};
use pangu_boundary::Risk;
use serde::{Deserialize, Serialize};

/// The side-effect boundary declared by a tool implementation.
///
/// This is intentionally separate from [`Risk`]: policy and approval consume
/// the risk class, while this descriptor records what kind of effect the
/// adapter claims it can produce. Model arguments cannot change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectScope {
    Workspace,
    Session,
    ProcessRead,
    ExternalRead,
    ExternalMutation,
}

impl EffectScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Session => "session",
            Self::ProcessRead => "process_read",
            Self::ExternalRead => "external_read",
            Self::ExternalMutation => "external_mutation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    NoEffect,
    Reversible,
    Irreversible,
}

impl Reversibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEffect => "no_effect",
            Self::Reversible => "reversible",
            Self::Irreversible => "irreversible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectDescriptor {
    pub scope: EffectScope,
    pub reversibility: Reversibility,
}

impl EffectDescriptor {
    pub const fn new(scope: EffectScope, reversibility: Reversibility) -> Self {
        Self {
            scope,
            reversibility,
        }
    }

    /// Validate the descriptor before it can reach Policy.
    ///
    /// External mutation is always irreversible in this API and must carry at
    /// least destructive risk. The reverse implication is also enforced so a
    /// tool cannot claim an irreversible effect while advertising a weaker
    /// risk class.
    pub fn validate_for_risk(self, risk: Risk) -> Result<()> {
        if self.scope == EffectScope::ExternalMutation
            && self.reversibility != Reversibility::Irreversible
        {
            bail!("external_mutation must be paired with irreversible");
        }
        if self.scope == EffectScope::ExternalMutation && !risk.at_least(Risk::Destructive) {
            bail!("external_mutation requires destructive or higher risk");
        }
        if self.reversibility == Reversibility::Irreversible && !risk.at_least(Risk::Destructive) {
            bail!("irreversible effects require destructive or higher risk");
        }
        Ok(())
    }

    pub fn is_external_mutation(self) -> bool {
        self.scope == EffectScope::ExternalMutation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_mutation_requires_irreversible_and_destructive_risk() {
        let descriptor =
            EffectDescriptor::new(EffectScope::ExternalMutation, Reversibility::Irreversible);
        assert!(descriptor.validate_for_risk(Risk::Destructive).is_ok());
        assert!(descriptor.validate_for_risk(Risk::NeedsHuman).is_ok());
        assert!(descriptor.validate_for_risk(Risk::Reversible).is_err());

        let inconsistent =
            EffectDescriptor::new(EffectScope::ExternalMutation, Reversibility::Reversible);
        assert!(inconsistent.validate_for_risk(Risk::Destructive).is_err());
    }
}
