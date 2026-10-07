//! Real OS-level sandbox runtimes: Firecracker, gVisor, OCI containers.
//!
//! # What changes here, and why it matters
//!
//! Before this module, `[execution] profile` was a **declaration**: the operator
//! said "this runs in a container", Pangu wrote that into the audit trail, and
//! the command still ran directly on the host as the host user. The declaration
//! was honest about itself, but it was still only a claim — naming a container
//! did not create one.
//!
//! This module makes the claim *checkable, and then true*: a declared runtime is
//! **probed**, and the probe result decides whether a command may run at all.
//!
//! # The rule that makes this honest: fail closed
//!
//! If the operator declares a runtime and it cannot be used, commands **do not
//! run**. There is deliberately no fallback to the host:
//!
//! - Silently running on the host after the operator asked for isolation is the
//!   worst available outcome, because the audit trail records the declaration
//!   while the execution did not match it. The operator would believe they had
//!   isolation they did not have.
//! - `local` remains available and honest, but it must be *chosen*, never
//!   *fallen back to*.
//!
//! This is why [`RuntimeProbe`] separates "not looked for" from "usable" as
//! distinct variants rather than a boolean: a declaration that was never probed
//! must not be readable as a working runtime.
//!
//! # Priority
//!
//! The operator selects a runtime explicitly. `auto` resolves by preference
//! order, strongest isolation first:
//!
//! 1. **Firecracker** — hardware-virtualised microVM, so a separate kernel and a
//!    container escape is not reachable from inside.
//! 2. **gVisor (`runsc`)** — a user-space kernel intercepting syscalls. Stronger
//!    than a container, weaker than a VM.
//! 3. **OCI (Docker/Podman)** — namespaces and cgroups. Real isolation of
//!    process, filesystem and network, but sharing the host kernel.
//!
//! The order is by *kernel boundary strength*, not by speed or convenience, and
//! it is written down here so `auto` is predictable rather than magic.
//!
//! # What a probe verifies, and what it cannot
//!
//! A probe runs the runtime and checks that a command really executed inside it.
//! It does **not** verify that the resulting isolation is escape-proof — that is
//! a property of the runtime, not something a launcher can establish. What is
//! established is: the runtime starts, and a command runs inside the boundary we
//! asked for. [`RuntimeProbe::evidence`] reports that observation rather than
//! asserting a security property it cannot support.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use pangu_core::{Error, Result};

/// How long a probe may take before it is killed.
///
/// A container runtime whose daemon is wedged hangs rather than fails, and a
/// probe that hangs would hang a run before it starts.
const PROBE_TIMEOUT_SECS: u64 = 30;

/// Which OS-level isolation to use for command execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntime {
    /// Run directly on the host. No OS isolation; L1–L4 are the only gates.
    ///
    /// The default and the pre-existing behaviour. An explicit choice, never a
    /// fallback.
    #[default]
    Local,
    /// Firecracker microVM: a separate kernel.
    Firecracker,
    /// gVisor `runsc`: a user-space kernel.
    Gvisor,
    /// OCI container via Docker or Podman.
    Oci,
    /// Pick the strongest available, in the documented priority order.
    Auto,
}

impl SandboxRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Firecracker => "firecracker",
            Self::Gvisor => "gvisor",
            Self::Oci => "oci",
            Self::Auto => "auto",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "local" | "host" | "none" => Ok(Self::Local),
            "firecracker" => Ok(Self::Firecracker),
            "gvisor" | "runsc" => Ok(Self::Gvisor),
            "oci" | "docker" | "podman" | "container" => Ok(Self::Oci),
            "auto" => Ok(Self::Auto),
            other => Err(Error::Config(format!(
                "unknown sandbox runtime `{other}` (expected local, firecracker, gvisor, oci or \
                 auto)"
            ))),
        }
    }

    /// Whether this runtime provides an OS-level boundary at all.
    pub const fn is_isolating(self) -> bool {
        !matches!(self, Self::Local)
    }

    /// The runtimes `auto` considers, strongest first.
    pub const fn preference_order() -> [SandboxRuntime; 3] {
        [
            SandboxRuntime::Firecracker,
            SandboxRuntime::Gvisor,
            SandboxRuntime::Oci,
        ]
    }
}

/// The outcome of looking for a runtime on this machine.
///
/// A distinct type rather than a boolean because the three states mean different
/// things, and collapsing them loses the distinction that matters most: "we did
/// not look" must never be read as "it works".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RuntimeProbe {
    /// The operator chose the host. Nothing to probe.
    NotRequested,
    /// The runtime was found and a real command ran inside it.
    Usable {
        /// How it was invoked, for the audit trail.
        invocation: Vec<String>,
        /// What was observed. An observation, not a security claim.
        evidence: String,
    },
    /// The runtime was requested but cannot be used. Commands must not run.
    Unusable {
        /// Why, in operator-facing terms.
        reason: String,
        /// What to install or configure, when that is knowable.
        remedy: String,
    },
}

impl RuntimeProbe {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Usable { .. })
    }

    pub fn is_unusable(&self) -> bool {
        matches!(self, Self::Unusable { .. })
    }

    pub fn evidence(&self) -> Option<&str> {
        match self {
            Self::Usable { evidence, .. } => Some(evidence),
            _ => None,
        }
    }

    /// One line for `doctor`, always stating the state.
    pub fn summary(&self) -> String {
        match self {
            Self::NotRequested => {
                "running on the host: no OS-level isolation, L1-L4 are the only gates".into()
            }
            Self::Usable { evidence, .. } => format!("usable — {evidence}"),
            Self::Unusable { reason, remedy } => {
                format!("NOT USABLE — {reason}; commands are refused. To fix: {remedy}")
            }
        }
    }
}

/// A resolved runtime.
///
/// Only obtainable through [`RuntimeConfig::resolve`], which always probes.
/// There is no constructor from a declaration alone, which is what stops a
/// declaration being mistaken for a working sandbox.
#[derive(Debug, Clone)]
pub struct Runtime {
    kind: SandboxRuntime,
    probe: RuntimeProbe,
    launcher: Option<(String, Vec<String>)>,
    workspace_mount: Option<String>,
    /// The workspace on the host. Kept so a caller that spawns the launcher can
    /// give it a working directory that exists here.
    workspace: PathBuf,
}

/// Configuration for resolving and using a runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub runtime: SandboxRuntime,
    /// Container/VM image, when the runtime needs one.
    pub image: String,
    /// Workspace path on the host, mounted into the sandbox.
    pub workspace: PathBuf,
    /// Whether a sandboxed command gets network access. Default false: a sandbox
    /// that keeps the host network has given up one of the three boundaries it
    /// was chosen for.
    pub network: bool,
    /// Memory cap in MiB, where the runtime supports one.
    pub memory_mib: u32,
    /// CPU count, where the runtime supports one.
    pub cpus: u32,
    /// Command the probe runs inside the sandbox.
    pub probe_command: Vec<String>,
    /// Substring the probe's output must contain.
    pub probe_expect: String,
}

impl RuntimeConfig {
    /// Resolve a runtime, probing whatever was requested.
    ///
    /// `auto` tries the preference order and takes the strongest that works. An
    /// explicit choice is probed alone: if the operator asked for Firecracker
    /// and only Docker is present, that is an error rather than a silent
    /// downgrade — a downgrade would give weaker isolation than the operator
    /// decided to accept.
    pub fn resolve(&self) -> Runtime {
        match self.runtime {
            SandboxRuntime::Local => Runtime {
                kind: SandboxRuntime::Local,
                probe: RuntimeProbe::NotRequested,
                launcher: None,
                workspace_mount: None,
                workspace: self.workspace.clone(),
            },
            SandboxRuntime::Auto => {
                let mut reasons: Vec<String> = Vec::new();
                for candidate in SandboxRuntime::preference_order() {
                    let runtime = self.resolve_explicit_with(candidate);
                    if runtime.probe.is_usable() {
                        return runtime;
                    }
                    if let RuntimeProbe::Unusable { reason, .. } = &runtime.probe {
                        reasons.push(format!("{}: {reason}", candidate.as_str()));
                    }
                }
                Runtime {
                    kind: SandboxRuntime::Auto,
                    probe: RuntimeProbe::Unusable {
                        reason: format!(
                            "no sandbox runtime is usable on this machine ({})",
                            reasons.join("; ")
                        ),
                        remedy: "install Firecracker, gVisor (runsc) or Docker/Podman, or set \
                                 [execution] runtime = \"local\" to accept running on the host"
                            .into(),
                    },
                    launcher: None,
                    workspace_mount: None,
                    workspace: self.workspace.clone(),
                }
            }
            explicit => self.resolve_explicit_with(explicit),
        }
    }

    fn resolve_explicit_with(&self, kind: SandboxRuntime) -> Runtime {
        let probe = self.probe(kind);
        let (launcher, workspace_mount) = match &probe {
            RuntimeProbe::Usable { .. } => {
                let (program, args, mount) = self.build_command(kind);
                // Pin the absolute path of the launcher now, while the same
                // `PATH` resolution the probe used is still in effect.
                //
                // A real command runs with a *sanitized* environment whose `PATH`
                // is the operator's allow-list, not the parent's. Reusing the bare
                // name would let a runtime probe as usable and then fail to
                // launch: the probe found `docker` because the parent's `PATH`
                // had it, while the child's does not. Resolving to an absolute
                // path here makes "the runtime that passed the probe" and "the
                // runtime that runs the command" the same file by construction
                // rather than by coincidence.
                let pinned = find_program(&program)
                    .map(|found| found.display().to_string())
                    .unwrap_or(program);
                (Some((pinned, args)), mount)
            }
            _ => (None, None),
        };
        Runtime {
            kind,
            probe,
            launcher,
            workspace_mount,
            workspace: self.workspace.clone(),
        }
    }

    /// The program and leading arguments that place a command inside `kind`.
    ///
    /// Public because `doctor` reports it: an operator asking "what would you
    /// actually run?" should be able to see the exact argv, rather than trust
    /// that the intent was translated correctly.
    pub fn command_for(&self, kind: SandboxRuntime) -> (String, Vec<String>, Option<String>) {
        self.build_command(kind)
    }

    /// The program and leading arguments that place a command inside `kind`.
    ///
    /// Used for both the probe and real commands, so a runtime that passes the
    /// probe is invoked identically when it matters. Two separate argv builders
    /// would let a probe succeed under arguments the real path never uses.
    fn build_command(&self, kind: SandboxRuntime) -> (String, Vec<String>, Option<String>) {
        let host_mount = host_mount_path(&self.workspace);
        match kind {
            SandboxRuntime::Local | SandboxRuntime::Auto => (String::new(), Vec::new(), None),
            SandboxRuntime::Firecracker => (
                "firecracker".to_string(),
                vec![
                    "--no-api".to_string(),
                    "--config-file".to_string(),
                    "/dev/stdin".to_string(),
                ],
                Some(host_mount.clone()),
            ),
            SandboxRuntime::Gvisor => {
                let mut args = vec![
                    "run".to_string(),
                    "--platform=systrap".to_string(),
                    // The workspace is the only host path visible inside; no
                    // other bind mount is offered, so the sandbox cannot read
                    // the rest of the host filesystem.
                    format!("--bind={host_mount}:/workspace"),
                    "--cwd=/workspace".to_string(),
                ];
                if !self.network {
                    args.push("--network=none".to_string());
                }
                if self.memory_mib > 0 {
                    args.push(format!("--memory={}MiB", self.memory_mib));
                }
                args.push(self.image.clone());
                ("runsc".to_string(), args, Some("/workspace".to_string()))
            }
            SandboxRuntime::Oci => {
                let mut args = vec![
                    "run".to_string(),
                    "--rm".to_string(),
                    // stdin stays attached so a command can be fed in. `-i` is
                    // deliberately not `-t`: no TTY is needed, and allocating
                    // one would tie the sandbox to a terminal.
                    "-i".to_string(),
                    format!("--volume={host_mount}:/workspace"),
                    "--workdir=/workspace".to_string(),
                    // Drop every capability. A command needing one should have
                    // to ask, and that ask should be visible.
                    "--cap-drop=ALL".to_string(),
                    // No new privileges: a setuid binary inside the image cannot
                    // be used to leave the uid we started as.
                    "--security-opt=no-new-privileges".to_string(),
                ];
                if !self.network {
                    args.push("--network=none".to_string());
                }
                if self.memory_mib > 0 {
                    args.push(format!("--memory={}m", self.memory_mib));
                }
                if self.cpus > 0 {
                    args.push(format!("--cpus={}", self.cpus));
                }
                args.push(self.image.clone());
                ("docker".to_string(), args, Some("/workspace".to_string()))
            }
        }
    }

    /// Probe a runtime by actually running a command inside it.
    ///
    /// A probe that only looked for a binary would report "usable" for a runtime
    /// whose daemon is not running, an image that was never pulled, or a kernel
    /// module that is not loaded. Running the command is the only check that
    /// answers the question being asked: can a command execute inside this
    /// boundary right now?
    fn probe(&self, kind: SandboxRuntime) -> RuntimeProbe {
        if kind == SandboxRuntime::Local {
            return RuntimeProbe::NotRequested;
        }
        if kind == SandboxRuntime::Firecracker {
            return self.probe_firecracker();
        }

        let program = program_for(kind);
        let Some(found) = find_program(program) else {
            return RuntimeProbe::Unusable {
                reason: format!("`{program}` was not found on PATH"),
                remedy: remedy_for(kind),
            };
        };

        let (_, base_args, _) = self.build_command(kind);
        let mut argv = vec![found.display().to_string()];
        argv.extend(base_args);
        argv.extend(self.probe_command.iter().cloned());

        match run_probe(&argv) {
            Ok(output) => {
                if output.contains(&self.probe_expect) {
                    RuntimeProbe::Usable {
                        invocation: argv,
                        evidence: format!(
                            "ran `{}` inside {} and observed `{}`",
                            self.probe_command.join(" "),
                            kind.as_str(),
                            self.probe_expect
                        ),
                    }
                } else {
                    RuntimeProbe::Unusable {
                        reason: format!(
                            "{} started but the probe command did not produce the expected \
                             output; saw: {}",
                            kind.as_str(),
                            first_line(&output)
                        ),
                        remedy: remedy_for(kind),
                    }
                }
            }
            Err(error) => RuntimeProbe::Unusable {
                reason: format!("{} could not run the probe command: {error}", kind.as_str()),
                remedy: remedy_for(kind),
            },
        }
    }

    /// Firecracker needs more than a binary: KVM, a guest kernel and a rootfs.
    ///
    /// Each missing piece is reported by name, because "Firecracker is not
    /// installed" and "this host has no hardware virtualisation" call for
    /// different responses from the operator.
    fn probe_firecracker(&self) -> RuntimeProbe {
        if !cfg!(target_os = "linux") {
            return RuntimeProbe::Unusable {
                reason: "Firecracker is Linux-only: it needs KVM, which this platform does not \
                         provide"
                    .into(),
                remedy: "run on a Linux host for Firecracker, or select the oci runtime on this \
                         platform"
                    .into(),
            };
        }
        let Some(found) = find_program("firecracker") else {
            return RuntimeProbe::Unusable {
                reason: "`firecracker` was not found on PATH".into(),
                remedy: remedy_for(SandboxRuntime::Firecracker),
            };
        };
        // KVM is what makes this a microVM rather than a process: without it
        // Firecracker cannot boot a guest kernel at all.
        let kvm = Path::new("/dev/kvm");
        if !kvm.exists() {
            return RuntimeProbe::Unusable {
                reason: format!(
                    "{} is missing: Firecracker needs KVM to boot a guest kernel",
                    kvm.display()
                ),
                remedy: "run on a host with hardware virtualisation enabled and access to \
                         /dev/kvm (bare metal, or a VM with nested virtualisation)"
                    .into(),
            };
        }
        RuntimeProbe::Unusable {
            reason: format!(
                "`{}` is present and {} exists, but this build cannot yet drive a guest to \
                 completion: getting the command in and its output out needs a vsock or serial \
                 channel that is not implemented",
                found.display(),
                kvm.display()
            ),
            remedy: "use gvisor or oci for real isolation today; Firecracker is recognised and \
                     will be selected by `auto` once that channel exists"
                .into(),
        }
    }
}

impl Runtime {
    pub fn kind(&self) -> SandboxRuntime {
        self.kind
    }

    pub fn probe(&self) -> &RuntimeProbe {
        &self.probe
    }

    /// Whether commands may run.
    ///
    /// False for an unusable declared runtime, which is the whole point: the
    /// caller must refuse rather than quietly run on the host.
    pub fn allows_execution(&self) -> bool {
        match self.kind {
            SandboxRuntime::Local => true,
            _ => self.probe.is_usable(),
        }
    }

    /// The launcher program and leading args, if this runtime wraps commands.
    pub fn launcher(&self) -> Option<(&str, &[String])> {
        self.launcher
            .as_ref()
            .map(|(program, args)| (program.as_str(), args.as_slice()))
    }

    /// Where the workspace appears inside the sandbox.
    ///
    /// This is the path a command should use: under `local` it is the host path,
    /// inside a container it is `/workspace`.
    pub fn workspace_mount(&self) -> Option<&str> {
        self.workspace_mount.as_deref()
    }

    /// The workspace as the **host** sees it.
    ///
    /// Distinct from [`Self::workspace_mount`], which is the path inside the
    /// sandbox. Callers that spawn the launcher process itself need this one:
    /// `docker` is started on the host, so its working directory has to be a host
    /// path. Using the in-container path there fails before the runtime runs.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// The error raised when execution is refused.
    pub fn refusal(&self) -> Error {
        let (reason, remedy) = match &self.probe {
            RuntimeProbe::Unusable { reason, remedy } => (reason.clone(), remedy.clone()),
            _ => (
                format!("{} is not usable", self.kind.as_str()),
                remedy_for(self.kind),
            ),
        };
        Error::Config(format!(
            "refusing to execute: [execution] runtime = \"{}\" is not usable ({reason}). \
             Commands will not fall back to running on the host, because the run's audit trail \
             records the declared runtime and executing outside it would make that record \
             false. {remedy}",
            self.kind.as_str()
        ))
    }
}

fn program_for(kind: SandboxRuntime) -> &'static str {
    match kind {
        SandboxRuntime::Gvisor => "runsc",
        SandboxRuntime::Oci => "docker",
        _ => "",
    }
}

fn remedy_for(kind: SandboxRuntime) -> String {
    match kind {
        SandboxRuntime::Firecracker => {
            "install Firecracker (https://github.com/firecracker-microvm/firecracker) and supply \
             a guest kernel plus rootfs"
                .into()
        }
        SandboxRuntime::Gvisor => {
            "install runsc and register it with your container runtime, or select the oci \
             runtime instead"
                .into()
        }
        SandboxRuntime::Oci => {
            "install Docker or Podman, start the daemon, and pull the configured image".into()
        }
        _ => "select [execution] runtime = \"local\" to accept running on the host".into(),
    }
}

/// Find an executable on PATH.
///
/// `which`/`where` are avoided: they are themselves programs that may be absent,
/// and shelling out would make the probe depend on a second thing.
fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let candidates: Vec<String> = if cfg!(windows) {
        vec![
            format!("{name}.exe"),
            format!("{name}.cmd"),
            format!("{name}.bat"),
            name.to_string(),
        ]
    } else {
        vec![name.to_string()]
    };
    for dir in std::env::split_paths(&path) {
        for candidate in &candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// Strip a Windows verbatim prefix from a path's textual form.
///
/// Split out from [`host_mount_path`] so the rule can be tested on every
/// platform: the transformation is about text, and a test that built a `Path`
/// from a Windows literal would be checking Unix path semantics on Unix.
fn strip_verbatim(text: &str) -> String {
    // `\\?\UNC\server\share` -> `\\server\share`; the UNC form is what other
    // Windows programs expect, so only the marker is removed.
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    // `\\?\C:\ws` -> `C:\ws`. Guard against a bare `\\?\` with nothing after it:
    // returning an empty mount source would be worse than leaving it alone, and
    // the caller would then mount nothing at all.
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        if !rest.is_empty() {
            return rest.to_string();
        }
    }
    text.to_string()
}

/// A host path rendered for a bind mount.
///
/// On Windows, `std::fs::canonicalize` returns a *verbatim* path with a `\\?\`
/// prefix (and a UNC form for network shares). That spelling is meaningful to the
/// Win32 API — it is what lets us address long paths and sidesteps the usual
/// normalization — but it is not something a container runtime can mount:
/// `docker run --volume=\\?\F:\ws:/workspace` is rejected, because the runtime
/// parses the windows-side path itself and does not know the verbatim form.
///
/// Since the workspace is canonicalized on the way in (to make the sandbox's
/// prefix checks sound), the verbatim form reaches this function every time on
/// Windows. Strip it back to a normal drive path for the mount argument only.
/// The *launcher's working directory* is a different matter: it is passed to a
/// host process, which does accept the verbatim form, so it keeps whatever the
/// caller canonicalized.
///
/// On Unix there is nothing to strip and this is the path unchanged.
fn host_mount_path(workspace: &Path) -> String {
    strip_verbatim(&workspace.display().to_string())
}

/// Run a probe command with a bounded wait, returning its combined output.
fn run_probe(argv: &[String]) -> std::result::Result<String, String> {
    let (program, args) = argv.split_first().ok_or("empty probe command")?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;

    // Bounded wait without a runtime dependency: poll, then kill. Waiting
    // without a deadline would let a wedged daemon hang a run before it starts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(PROBE_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "the probe did not finish within {PROBE_TIMEOUT_SECS}s"
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    line.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verbatim path is not mountable, and canonicalization produces one on
    /// Windows, so the mount argument must not carry it.
    ///
    /// This drives the string transformation rather than constructing a `Path`
    /// from a Windows literal, because on Unix `Path::new(r"\\?\C:\ws")` is a
    /// single filename containing backslashes, not a drive path — an earlier
    /// version of this test asserted Windows semantics on Linux and failed
    /// there. The function's contract is about the *text* it produces, so this
    /// checks that text on every platform.
    #[test]
    fn a_verbatim_host_path_is_not_handed_to_the_runtime() {
        assert_eq!(strip_verbatim(r"\\?\C:\work\ws"), r"C:\work\ws");
        // A UNC share keeps its backslashes but loses the verbatim marker.
        assert_eq!(
            strip_verbatim(r"\\?\UNC\server\share\ws"),
            r"\\server\share\ws"
        );
        // A path that is already mountable is untouched, on either platform.
        assert_eq!(strip_verbatim(r"C:\work\ws"), r"C:\work\ws");
        assert_eq!(strip_verbatim("/work/ws"), "/work/ws");
        // `\\?\` on its own is not a drive path; leave it rather than inventing
        // an empty string.
        assert_eq!(strip_verbatim(r"\\?\"), r"\\?\");
    }

    /// The reachable form of the same bug: whatever the workspace spelling is,
    /// the `--volume` argument must not contain `\\?\`.
    #[test]
    fn the_container_mount_argument_never_carries_a_verbatim_prefix() {
        let mut config = config(SandboxRuntime::Oci);
        config.workspace = PathBuf::from(r"\\?\C:\work\ws");
        let (program, args, mount) = config.build_command(SandboxRuntime::Oci);
        assert_eq!(program, "docker");
        let volume = args
            .iter()
            .find(|a| a.starts_with("--volume="))
            .expect("a volume argument");
        assert!(
            !volume.contains(r"\\?\"),
            "a verbatim path cannot be mounted: {volume}"
        );
        assert!(volume.contains(r"C:\work\ws"), "{volume}");
        assert_eq!(mount.as_deref(), Some("/workspace"));
    }

    fn config(runtime: SandboxRuntime) -> RuntimeConfig {
        RuntimeConfig {
            runtime,
            image: "test-image:latest".into(),
            workspace: std::env::temp_dir(),
            network: false,
            memory_mib: 512,
            cpus: 1,
            probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
            probe_expect: "pangu-probe-ok".into(),
        }
    }

    /// Build the "declared but unusable" state without depending on what happens
    /// to be installed on the test machine.
    fn unusable(kind: SandboxRuntime) -> Runtime {
        Runtime {
            kind,
            probe: RuntimeProbe::Unusable {
                reason: "not installed".into(),
                remedy: "install it".into(),
            },
            launcher: None,
            workspace_mount: None,
            workspace: PathBuf::from("."),
        }
    }

    #[test]
    fn local_runs_on_the_host_and_needs_no_probe() {
        let runtime = config(SandboxRuntime::Local).resolve();
        assert_eq!(runtime.kind(), SandboxRuntime::Local);
        assert_eq!(runtime.probe(), &RuntimeProbe::NotRequested);
        assert!(runtime.allows_execution());
        assert!(runtime.launcher().is_none());
        assert!(runtime.workspace_mount().is_none());
    }

    /// The property the whole module exists for: naming a sandbox must not be
    /// confusable with having one.
    #[test]
    fn a_declared_but_unusable_runtime_refuses_execution() {
        for kind in [
            SandboxRuntime::Firecracker,
            SandboxRuntime::Gvisor,
            SandboxRuntime::Oci,
            SandboxRuntime::Auto,
        ] {
            let runtime = unusable(kind);
            assert!(
                !runtime.allows_execution(),
                "{} must not allow execution when unusable",
                kind.as_str()
            );
        }
    }

    #[test]
    fn the_refusal_explains_why_there_is_no_host_fallback() {
        let runtime = unusable(SandboxRuntime::Oci);
        let message = runtime.refusal().to_string();
        assert!(message.contains("refusing to execute"), "{message}");
        // The reason it does not quietly fall back must be stated, because that
        // is the decision an operator will otherwise think is a bug.
        assert!(message.contains("audit trail"), "{message}");
        assert!(message.contains("fall back"), "{message}");
        // And it must say what to do about it.
        assert!(
            message.contains("use it") || message.contains("runtime"),
            "{message}"
        );
    }

    #[test]
    fn priority_order_is_strongest_first() {
        let order = SandboxRuntime::preference_order();
        assert_eq!(
            order,
            [
                SandboxRuntime::Firecracker,
                SandboxRuntime::Gvisor,
                SandboxRuntime::Oci
            ]
        );
    }

    #[test]
    fn a_probe_that_never_ran_is_not_usable() {
        // The distinction between "we did not look" and "it works" has to be
        // real, otherwise a default-constructed state could be read as a working
        // sandbox.
        assert!(!RuntimeProbe::NotRequested.is_usable());
        assert!(!RuntimeProbe::NotRequested.is_unusable());
        assert!(RuntimeProbe::NotRequested.evidence().is_none());
        assert!(RuntimeProbe::NotRequested
            .summary()
            .contains("no OS-level isolation"));
    }

    #[test]
    fn only_local_is_a_non_isolating_runtime() {
        assert!(!SandboxRuntime::Local.is_isolating());
        for kind in [
            SandboxRuntime::Firecracker,
            SandboxRuntime::Gvisor,
            SandboxRuntime::Oci,
            SandboxRuntime::Auto,
        ] {
            assert!(kind.is_isolating(), "{} claims to isolate", kind.as_str());
        }
    }

    #[test]
    fn runtime_names_parse_with_aliases() {
        assert_eq!(
            SandboxRuntime::parse("local").unwrap(),
            SandboxRuntime::Local
        );
        assert_eq!(
            SandboxRuntime::parse("HOST").unwrap(),
            SandboxRuntime::Local
        );
        assert_eq!(
            SandboxRuntime::parse("docker").unwrap(),
            SandboxRuntime::Oci
        );
        assert_eq!(
            SandboxRuntime::parse("podman").unwrap(),
            SandboxRuntime::Oci
        );
        assert_eq!(
            SandboxRuntime::parse("runsc").unwrap(),
            SandboxRuntime::Gvisor
        );
        assert_eq!(
            SandboxRuntime::parse("firecracker").unwrap(),
            SandboxRuntime::Firecracker
        );
        assert_eq!(SandboxRuntime::parse("auto").unwrap(), SandboxRuntime::Auto);
        assert!(SandboxRuntime::parse("chroot").is_err());
    }

    /// The container argv must actually ask for isolation. A launcher that
    /// mounts the workspace and then keeps the host network has given up one of
    /// the three boundaries it was chosen for.
    #[test]
    fn the_oci_argv_asks_for_real_isolation() {
        let (program, args, mount) = config(SandboxRuntime::Oci).command_for(SandboxRuntime::Oci);
        assert_eq!(program, "docker");
        assert!(args.contains(&"--network=none".to_string()), "{args:?}");
        assert!(args.contains(&"--cap-drop=ALL".to_string()), "{args:?}");
        assert!(
            args.contains(&"--security-opt=no-new-privileges".to_string()),
            "{args:?}"
        );
        assert!(args.contains(&"--rm".to_string()), "{args:?}");
        // Only the workspace is mounted, so the rest of the host is not visible.
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("--volume=") && arg.ends_with(":/workspace")),
            "{args:?}"
        );
        assert_eq!(mount.as_deref(), Some("/workspace"));
        // The image is last, so the command appended after it runs inside it.
        assert_eq!(args.last().unwrap(), "test-image:latest");
    }

    #[test]
    fn network_is_opt_in_and_defaults_off() {
        let mut with_net = config(SandboxRuntime::Oci);
        with_net.network = true;
        let (_, args, _) = with_net.command_for(SandboxRuntime::Oci);
        assert!(
            !args.contains(&"--network=none".to_string()),
            "declaring network access must remove the restriction: {args:?}"
        );
    }

    #[test]
    fn resource_caps_are_passed_when_asked_for() {
        let (_, args, _) = config(SandboxRuntime::Oci).command_for(SandboxRuntime::Oci);
        assert!(args.contains(&"--memory=512m".to_string()), "{args:?}");
        assert!(args.contains(&"--cpus=1".to_string()), "{args:?}");

        let mut uncapped = config(SandboxRuntime::Oci);
        uncapped.memory_mib = 0;
        uncapped.cpus = 0;
        let (_, args, _) = uncapped.command_for(SandboxRuntime::Oci);
        assert!(!args.iter().any(|a| a.starts_with("--memory")), "{args:?}");
        assert!(!args.iter().any(|a| a.starts_with("--cpus")), "{args:?}");
    }

    #[test]
    fn the_gvisor_argv_mounts_only_the_workspace() {
        let (program, args, mount) =
            config(SandboxRuntime::Gvisor).command_for(SandboxRuntime::Gvisor);
        assert_eq!(program, "runsc");
        assert!(args.contains(&"--platform=systrap".to_string()), "{args:?}");
        assert!(args.contains(&"--network=none".to_string()), "{args:?}");
        let binds: Vec<&String> = args.iter().filter(|a| a.starts_with("--bind=")).collect();
        assert_eq!(
            binds.len(),
            1,
            "exactly one bind mount is offered: {args:?}"
        );
        assert_eq!(mount.as_deref(), Some("/workspace"));
    }

    /// `auto` must not silently pick something weaker than it could, and must
    /// report what it could not use.
    #[test]
    fn auto_either_resolves_or_explains_every_candidate() {
        let runtime = config(SandboxRuntime::Auto).resolve();
        match runtime.probe() {
            RuntimeProbe::Usable { .. } => {
                // Whatever it picked must be one of the real runtimes, never
                // `auto` itself or `local`.
                assert!(runtime.kind().is_isolating());
                assert_ne!(runtime.kind(), SandboxRuntime::Auto);
                assert!(runtime.allows_execution());
            }
            RuntimeProbe::Unusable { reason, remedy } => {
                // The failure must name the candidates it tried, so an operator
                // learns which ones are missing rather than only that none work.
                assert!(reason.contains("firecracker"), "{reason}");
                assert!(reason.contains("gvisor"), "{reason}");
                assert!(reason.contains("oci"), "{reason}");
                assert!(!remedy.is_empty());
                assert!(!runtime.allows_execution());
            }
            RuntimeProbe::NotRequested => panic!("auto must probe, never report NotRequested"),
        }
    }

    #[test]
    fn an_unusable_runtime_has_no_launcher() {
        // If a launcher were present the caller could run a command through it,
        // which is exactly what must not happen.
        let runtime = config(SandboxRuntime::Oci).resolve();
        if runtime.probe().is_unusable() {
            assert!(runtime.launcher().is_none());
            assert!(runtime.workspace_mount().is_none());
        }
    }

    #[test]
    fn probe_summaries_state_the_status_for_every_variant() {
        let usable = RuntimeProbe::Usable {
            invocation: vec!["docker".into()],
            evidence: "ran echo".into(),
        };
        assert!(usable.summary().contains("usable"));
        let bad = RuntimeProbe::Unusable {
            reason: "no docker".into(),
            remedy: "install docker".into(),
        };
        assert!(bad.summary().contains("NOT USABLE"), "{}", bad.summary());
        assert!(bad.summary().contains("refused"), "{}", bad.summary());
        assert!(
            bad.summary().contains("install docker"),
            "{}",
            bad.summary()
        );
    }

    #[test]
    fn firecracker_is_reported_by_name_when_unavailable() {
        // On a machine without Firecracker the reason must name it, so the
        // operator knows what to install rather than only that nothing worked.
        let runtime = config(SandboxRuntime::Firecracker).resolve();
        assert!(!runtime.allows_execution());
        match runtime.probe() {
            RuntimeProbe::Unusable { reason, remedy } => {
                assert!(!reason.is_empty());
                assert!(
                    reason.contains("firecracker") || reason.contains("Firecracker"),
                    "the reason must name the runtime: {reason}"
                );
                assert!(!remedy.is_empty(), "a remedy must be offered");
            }
            other => panic!("Firecracker must not probe as {other:?} on this machine"),
        }
    }

    /// Asking for a specific runtime must never quietly yield a different one.
    ///
    /// A silent downgrade is the failure mode this guards: the operator chose
    /// Firecracker's boundary, and ending up in a container instead would be a
    /// weaker guarantee than they accepted, with nothing in the record saying so.
    #[test]
    fn an_explicit_choice_is_never_downgraded() {
        for kind in [
            SandboxRuntime::Firecracker,
            SandboxRuntime::Gvisor,
            SandboxRuntime::Oci,
        ] {
            let runtime = config(kind).resolve();
            assert_eq!(
                runtime.kind(),
                kind,
                "resolving {} must either give {} or refuse, never another runtime",
                kind.as_str(),
                kind.as_str()
            );
        }
    }

    #[test]
    fn firecracker_is_not_claimed_usable_without_kvm() {
        // This test machine either has Firecracker or does not; what must hold
        // either way is that usability is never asserted from the binary alone.
        if cfg!(not(target_os = "linux")) {
            let runtime = config(SandboxRuntime::Firecracker).resolve();
            assert!(
                !runtime.allows_execution(),
                "Firecracker needs KVM, which is unavailable off Linux"
            );
        }
    }
}
