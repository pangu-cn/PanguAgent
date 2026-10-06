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
//!
//! # F8: what changed
//!
//! The rules above describe `profile`, and they are still true of it. F8 adds a
//! separate, **enforced** field: [`ExecutionSection::runtime`]. The two are kept
//! apart on purpose, because they make different promises:
//!
//! | field | meaning | enforced? |
//! |---|---|---|
//! | `profile` | where the operator says the process runs | no — audit only |
//! | `runtime` | which OS-level sandbox commands execute in | **yes** |
//!
//! Declaring `runtime` other than `local` makes Pangu **probe** that runtime and
//! execute commands inside it. If the probe fails, commands are **refused**;
//! they do not fall back to the host. See [`crate::runtime`].

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
    /// F8: the OS-level sandbox to execute commands in.
    ///
    /// `local` (the default) keeps the previous behaviour: commands run on the
    /// host under L1–L4 only. Any other value is **probed and enforced** — if it
    /// cannot be used, commands are refused rather than falling back to the host.
    #[serde(default, skip_serializing_if = "is_local_runtime")]
    pub runtime: crate::runtime::SandboxRuntime,
    /// F8: image or rootfs the runtime executes in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// F8: whether a sandboxed command gets network access. Default false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub network: bool,
    /// F8: memory cap in MiB for the sandbox, where supported.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub memory_mib: u32,
    /// F8: CPU count for the sandbox, where supported.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cpus: u32,
}

fn is_local_runtime(runtime: &crate::runtime::SandboxRuntime) -> bool {
    *runtime == crate::runtime::SandboxRuntime::Local
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl ExecutionSection {
    /// True when the operator declared something beyond the default — only
    /// then does the declaration enter digests and payloads.
    pub fn is_declared(&self) -> bool {
        self.profile != ExecutionProfile::Local || self.description.is_some()
    }

    /// F8: true when a real sandbox is asked for.
    ///
    /// Separate from [`Self::is_declared`] because the two answer different
    /// questions: `profile` describes where the process claims to run (audit
    /// only), while `runtime` is enforced. Conflating them would let an audit
    /// declaration silently start refusing commands.
    pub fn isolates(&self) -> bool {
        self.runtime.is_isolating()
    }

    /// F8: the config the runtime probe needs.
    pub fn runtime_config(&self, workspace: std::path::PathBuf) -> crate::runtime::RuntimeConfig {
        crate::runtime::RuntimeConfig {
            runtime: self.runtime,
            image: self.image.clone().unwrap_or_default(),
            workspace,
            network: self.network,
            memory_mib: self.memory_mib,
            cpus: self.cpus,
            // The probe runs inside the sandbox and must produce this exact
            // text, so a runtime that starts but cannot execute is caught.
            probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
            probe_expect: "pangu-probe-ok".into(),
        }
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
        if let Some(image) = &self.image {
            if image.trim().is_empty() || image.len() > 512 || image.chars().any(char::is_control) {
                return Err(Error::Config(
                    "execution.image must be non-empty, at most 512 bytes, and free of control \
                     characters"
                        .into(),
                ));
            }
        }
        // A sandbox needs something to execute in. Catching this at config time
        // means the operator learns before the run, not from every refused
        // command during it.
        if self.runtime.is_isolating() && self.image.is_none() {
            return Err(Error::Config(format!(
                "execution.runtime = \"{}\" needs execution.image to be set: a sandbox must \
                 know what to execute in",
                self.runtime.as_str()
            )));
        }
        // A runtime requires an OS boundary; asking for one while declaring that
        // the process runs on the host is a contradiction worth surfacing.
        if self.runtime.is_isolating()
            && self.profile == ExecutionProfile::Local
            && self.description.is_none()
        {
            return Err(Error::Config(format!(
                "execution.runtime = \"{}\" asks for OS-level isolation but execution.profile \
                 is \"local\"; declare profile = \"container\" (or \"remote\") as well, so the \
                 audit trail matches what is enforced",
                self.runtime.as_str()
            )));
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
        // F8: the default asks for no sandbox, so nothing is enforced and
        // existing deployments are unchanged.
        assert_eq!(section.runtime, crate::runtime::SandboxRuntime::Local);
        assert!(!section.isolates());
    }

    #[test]
    fn profile_or_description_counts_as_declared() {
        let container = ExecutionSection {
            profile: ExecutionProfile::Container,
            description: None,
            ..Default::default()
        };
        assert!(container.is_declared());
        let described = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("docker:ubuntu-24.04".into()),
            ..Default::default()
        };
        assert!(described.is_declared());
    }

    #[test]
    fn description_is_bounded_and_control_free() {
        let ok = ExecutionSection {
            profile: ExecutionProfile::Remote,
            description: Some("k8s pod pangu-7f, namespace agents".into()),
            ..Default::default()
        };
        assert!(ok.validate().is_ok());

        let too_long = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("x".repeat(513)),
            ..Default::default()
        };
        assert!(too_long.validate().is_err());

        let control = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("bad\nmultiline".into()),
            ..Default::default()
        };
        assert!(control.validate().is_err());

        let blank = ExecutionSection {
            profile: ExecutionProfile::Local,
            description: Some("   ".into()),
            ..Default::default()
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

    /// F8: a sandbox needs something to execute in, and that is caught at config
    /// time rather than surfacing as every command being refused mid-run.
    #[test]
    fn a_declared_runtime_without_an_image_is_refused_at_config_time() {
        let section = ExecutionSection {
            profile: ExecutionProfile::Container,
            runtime: crate::runtime::SandboxRuntime::Oci,
            image: None,
            ..Default::default()
        };
        let error = section
            .validate()
            .expect_err("a sandbox without an image must not validate");
        let message = error.to_string();
        assert!(message.contains("execution.image"), "{message}");

        let with_image = ExecutionSection {
            profile: ExecutionProfile::Container,
            runtime: crate::runtime::SandboxRuntime::Oci,
            image: Some("alpine:3.20".into()),
            ..Default::default()
        };
        assert!(with_image.validate().is_ok());
    }

    /// Asking for OS isolation while declaring the process runs on the host is a
    /// contradiction: the audit trail would say `local` while commands execute
    /// in a container.
    #[test]
    fn isolation_requires_the_profile_to_agree() {
        let contradictory = ExecutionSection {
            profile: ExecutionProfile::Local,
            runtime: crate::runtime::SandboxRuntime::Oci,
            image: Some("alpine:3.20".into()),
            description: None,
            ..Default::default()
        };
        let error = contradictory
            .validate()
            .expect_err("an isolating runtime with a local profile must not validate");
        assert!(
            error.to_string().contains("profile"),
            "{error} must point at the contradiction"
        );

        // Declaring the profile as well resolves it.
        let consistent = ExecutionSection {
            profile: ExecutionProfile::Container,
            ..contradictory.clone()
        };
        assert!(consistent.validate().is_ok());
    }

    /// The local default must stay completely inert: no image, no validation
    /// complaint, nothing enforced.
    #[test]
    fn the_local_runtime_needs_no_image_and_enforces_nothing() {
        let section = ExecutionSection::default();
        assert!(section.validate().is_ok());
        assert!(!section.isolates());
    }

    #[test]
    fn a_blank_or_control_bearing_image_is_rejected() {
        for bad in ["", "   ", "bad\nimage"] {
            let section = ExecutionSection {
                profile: ExecutionProfile::Container,
                runtime: crate::runtime::SandboxRuntime::Oci,
                image: Some(bad.into()),
                ..Default::default()
            };
            assert!(
                section.validate().is_err(),
                "image {bad:?} must be rejected"
            );
        }
    }

    /// `is_declared` (audit) and `isolates` (enforcement) must stay independent:
    /// an audit-only declaration must not start refusing commands, and an
    /// enforced sandbox must be visible as declared.
    #[test]
    fn audit_declaration_and_enforcement_stay_independent() {
        // Audit-only: profile declared, no runtime.
        let audit_only = ExecutionSection {
            profile: ExecutionProfile::Container,
            description: Some("deployer-managed".into()),
            ..Default::default()
        };
        assert!(audit_only.is_declared());
        assert!(
            !audit_only.isolates(),
            "audit-only must not enforce a sandbox"
        );
        assert!(audit_only.validate().is_ok());

        // Enforced: a real runtime.
        let enforced = ExecutionSection {
            profile: ExecutionProfile::Container,
            runtime: crate::runtime::SandboxRuntime::Oci,
            image: Some("alpine:3.20".into()),
            ..Default::default()
        };
        assert!(enforced.isolates());
        assert!(enforced.is_declared());
    }

    /// The runtime config handed to the probe must carry what the operator
    /// declared, so the probe checks the thing that will actually be used.
    #[test]
    fn runtime_config_carries_the_declared_options() {
        let section = ExecutionSection {
            profile: ExecutionProfile::Container,
            runtime: crate::runtime::SandboxRuntime::Oci,
            image: Some("alpine:3.20".into()),
            network: false,
            memory_mib: 384,
            cpus: 2,
            ..Default::default()
        };
        let config = section.runtime_config(std::path::PathBuf::from("/tmp/ws"));
        assert_eq!(config.runtime, crate::runtime::SandboxRuntime::Oci);
        assert_eq!(config.image, "alpine:3.20");
        assert!(!config.network, "network must default off");
        assert_eq!(config.memory_mib, 384);
        assert_eq!(config.cpus, 2);
        assert_eq!(config.workspace, std::path::PathBuf::from("/tmp/ws"));
        // The probe must expect a specific string, so a runtime that starts but
        // cannot execute is not mistaken for a working one.
        assert!(!config.probe_expect.is_empty());
        assert!(!config.probe_command.is_empty());
    }
}
