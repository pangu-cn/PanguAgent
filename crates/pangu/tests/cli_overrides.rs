//! CLI runtime overrides must reach the effective config.
//!
//! `--checkpoint` / `--no-checkpoint` are runtime overrides, not config-file
//! edits. Every entry point that loads a config — `run`, `demo`, `session`,
//! `rollback` — has to apply them itself, because `Config::load` returns the
//! file as written. An entry point that forgets does not fail: it runs with
//! whatever the file said, which is wrong in *both* directions, and silently,
//! because nothing in the output says which config won.
//!
//! These tests run the real binary on purpose. The defect is in the wiring
//! between clap and `Config::apply`, so neither the flag parser nor
//! `Config::apply` alone can observe it — only the process the operator
//! actually types.

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
    config_path: PathBuf,
}

impl Probe {
    /// A workspace plus a config file whose `checkpoint.enabled` is
    /// `enabled`. The scripted demo reads `Cargo.toml` from the workspace, so
    /// one is written: without it the tool call fails, there is no verified
    /// action, and a checkpoint would be the wrong thing to expect.
    fn new(label: &str, enabled: bool) -> Self {
        // Nanoseconds, so an aborted run's leftover directory cannot be
        // mistaken for this run's — which would make a "no checkpoint was
        // written" assertion pass on a stale store.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pangu-cli-override-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("probe root");
        let root = fs::canonicalize(&root).expect("canonical probe root");
        let artifact_root = root.join(".pangu/checkpoints");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"override-probe\"\nversion = \"0.1.0\"\n",
        )
        .expect("seed workspace");

        let mut config = Config::embedded().expect("embedded config");
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = enabled;
        config.checkpoint.artifact_root = artifact_root.clone();
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
            config_path,
        }
    }

    fn run_demo(&self, flag: &str) -> std::process::Output {
        let binary = std::env::var_os("CARGO_BIN_EXE_pangu")
            .map(PathBuf::from)
            .expect("cargo must provide the pangu binary for integration tests");
        let output = Command::new(&binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--demo")
            .arg(flag)
            .stdin(Stdio::null())
            .output()
            .expect("run demo");
        assert!(
            output.status.success(),
            "`--demo {flag}` must not fail the run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Checkpoints are committed together with a session node, so the node
    /// list is the store's record of whether checkpointing ran at all.
    fn session_nodes(&self) -> usize {
        ArtifactStore::open(&self.artifact_root)
            .expect("open artifact store")
            .list_session_nodes()
            .expect("list session nodes")
            .len()
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn demo_turns_checkpointing_on_although_the_config_leaves_it_off() {
    let probe = Probe::new("checkpoint-on", false);
    assert_eq!(probe.session_nodes(), 0, "nothing ran yet");

    probe.run_demo("--checkpoint");

    assert_ne!(
        probe.session_nodes(),
        0,
        "`--demo --checkpoint` must checkpoint even when the config file says \
         `enabled = false`"
    );
}

#[test]
fn demo_turns_checkpointing_off_although_the_config_leaves_it_on() {
    let probe = Probe::new("checkpoint-off", true);

    probe.run_demo("--no-checkpoint");

    assert_eq!(
        probe.session_nodes(),
        0,
        "`--demo --no-checkpoint` must not checkpoint even when the config file \
         says `enabled = true`"
    );
}
