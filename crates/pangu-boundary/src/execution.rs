//! C5: execution profile declaration.
//!
//! The operator declares **where the run executes** — directly on the host
//! (`local`), inside a container the deployer manages (`container`), or on
//! remote infrastructure the deployer manages (`remote`). The declaration is
//! frozen into the contract, recorded in `RunStarted`, and surfaced by
//! `doctor`, so audit trails show what the operator claimed about the
//! environment.
//!
//! Honesty rules (the whole point of C5):
//! - The profile is a **declaration, not a verified fact**. Pangu never
//!   launches, manages, or verifies containers, VMs, or remote backends —
//!   from inside the process they are indistinguishable from `local`.
//! - The declaration changes **claims and audit**, never the enforcement
//!   chain: L1–L4 apply identically in every profile.
//! - BOUNDARY §5 keeps "no OS-level seccomp/Landlock/container/VM isolation"
//!   as a non-goal; naming a container profile does not turn application-layer
//!   checks into an OS boundary.

use serde::{Deserialize, Serialize};

use pangu_core::{Error, Result};

/// The declared execution backend. Default `Local`: existing deployments keep
/// their behavior and digests unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    /// The process runs directly on the host machine. No OS-level isolation.
    #[default]
    Local,
    /// Declared to run inside a container managed by the deployer.
    Container,
    /// Declared to run on remote infrastructure managed by the deployer.
    Remote,
}

impl ExecutionProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Container => "container",
            Self::Remote => "remote",
        }
    }

    /// The honest protection-scope statement for this profile, quoted by
    /// `doctor`/`explain` and in the documentation. Wording is deliberate:
    /// container/remote isolation is *claimed by the deployer*, never
    /// *provided or verified by Pangu*.
    pub const fn scope_statement(self) -> &'static str {
        match self {
            Self::Local => {
                "runs directly on the host machine; only the application-layer L1-L4 gates \
                 protect it — no OS-level isolation, and child processes inherit host permissions"
            }
            Self::Container => {
                "declared to run inside a container managed by the deployer; Pangu does not \
                 launch, manage, or verify the container, and inside it only L1-L4 apply — \
                 the container boundary itself is the deployer's responsibility"
            }
            Self::Remote => {
                "declared to run on remote infrastructure managed by the deployer; Pangu does \
                 not manage connectivity, credentials, or lifecycle, and only L1-L4 apply — \
                 network and credential isolation are the deployer's responsibility"
            }
        }
    }
}

/// The `[execution]` config section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExecutionSection {
    pub profile: ExecutionProfile,
    /// Free-form operator description of the backend (e.g. image and digest,
    /// host name). Redacted and length-bounded like every payload string;
    /// recorded in `RunStarted` for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ExecutionSection {
    /// True when the operator declared something beyond the default — only
    /// then does the declaration enter digests and payloads.
    pub fn is_declared(&self) -> bool {
        self.profile != ExecutionProfile::Local || self.description.is_some()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(description) = &self.description {
            if description.trim().is_empty()
                || description.len() > 512
                || description.chars().any(char::is_control)
            {
                return Err(Error::Config(
                    "execution.description must be non-empty, at most 512 bytes, and free of \
                     control characters"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_undeclared_local() {
        let section = ExecutionSection::default();
        assert_eq!(section.profile, ExecutionProfile::Local);
        assert!(!section.is_declared());
        assert!(section.validate().is_ok());
    }

    #[test]
    fn profile_or_description_counts_as_declared() {
        let container = ExecutionSection {
            profile: ExecutionProfile::Container,
            description: None,
        };
        assert!(container.is_declared());
        let described = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("docker:ubuntu-24.04".into()),
        };
        assert!(described.is_declared());
    }

    #[test]
    fn description_is_bounded_and_control_free() {
        let ok = ExecutionSection {
            profile: ExecutionProfile::Remote,
            description: Some("k8s pod pangu-7f, namespace agents".into()),
        };
        assert!(ok.validate().is_ok());

        let too_long = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("x".repeat(513)),
        };
        assert!(too_long.validate().is_err());

        let control = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("bad\nmultiline".into()),
        };
        assert!(control.validate().is_err());

        let blank = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("   ".into()),
        };
        assert!(blank.validate().is_err());
    }

    #[test]
    fn scope_statements_are_honest_and_distinct() {
        let statements = [
            ExecutionProfile::Local.scope_statement(),
            ExecutionProfile::Container.scope_statement(),
            ExecutionProfile::Remote.scope_statement(),
        ];
        for statement in statements {
            assert!(statement.contains("L1-L4"), "{statement}");
            assert!(!statement.is_empty());
        }
        // The non-local profiles must not pretend Pangu provides or verifies
        // the isolation.
        assert!(Container
            .scope_statement()
            .contains("does not launch, manage, or verify"));
        assert!(Remote.scope_statement().contains("does not manage"));
        // Distinctness keeps the doctor output meaningful.
        assert_ne!(statements[0], statements[1]);
        assert_ne!(statements[1], statements[2]);
        use ExecutionProfile::{Container, Remote};
    }
}
