//! Cross-process proof that per-file locks allow parallel work on unrelated
//! files, and serialise work on the same file.
//!
//! The unit tests in `pangu_core::lockfile` show the lock's behaviour through
//! its API. This test spawns real processes so the cross-process claim rests on
//! process separation rather than threads inside one test binary.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pangu-pathlock-e2e-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn spawn_child(workspace: &PathBuf, path: &str, hold_ms: u64, mark: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("path_lock_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_PATHLOCK_WORKSPACE", workspace)
        .env("PANGU_PATHLOCK_PATH", path)
        .env("PANGU_PATHLOCK_HOLD_MS", hold_ms.to_string())
        .env("PANGU_PATHLOCK_MARK", mark)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child")
}

fn output_of(child: std::process::Child) -> String {
    let out = child.wait_with_output().expect("wait for child");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Child body: lock one path, hold it, release. `#[ignore]`d so it only runs
/// when the parent asks for it explicitly.
#[test]
#[ignore = "helper process driven by the per-path contention tests"]
fn path_lock_child() {
    let workspace = match std::env::var("PANGU_PATHLOCK_WORKSPACE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };
    let path = std::env::var("PANGU_PATHLOCK_PATH").unwrap();
    let hold_ms: u64 = std::env::var("PANGU_PATHLOCK_HOLD_MS")
        .unwrap()
        .parse()
        .unwrap();
    let mark = std::env::var("PANGU_PATHLOCK_MARK").unwrap_or_default();

    let started = std::time::Instant::now();
    let lock = pangu_core::PathLock::acquire(
        &workspace,
        std::path::Path::new(&path),
        pangu_core::LockMode::Write,
        Duration::from_secs(30),
    )
    .expect("child acquires the path lock");
    println!("ACQUIRED {mark} after {}ms", started.elapsed().as_millis());
    std::thread::sleep(Duration::from_millis(hold_ms));
    drop(lock);
    println!("RELEASED {mark}");
}

fn waited_ms(output: &str, mark: &str) -> u128 {
    let needle = format!("ACQUIRED {mark} after ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .and_then(|rest| rest.trim_end_matches("ms").parse::<u128>().ok())
        .unwrap_or_else(|| panic!("no acquisition timing for {mark} in: {output}"))
}

/// The point of per-file locking: two agents on different files must not wait.
#[test]
fn different_files_do_not_serialise_across_processes() {
    let workspace = scratch("parallel");
    let holder = spawn_child(&workspace, "src/a.rs", 900, "first");
    std::thread::sleep(Duration::from_millis(250));
    let other = spawn_child(&workspace, "docs/b.md", 0, "second");

    let holder_out = output_of(holder);
    let other_out = output_of(other);

    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");

    // The second process touches a different file, so it must not have waited
    // for the first one's 900ms hold.
    let waited = waited_ms(&other_out, "second");
    assert!(
        waited < 400,
        "a different file must not wait for the first holder; waited {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}

/// The property that must survive: the same file still serialises.
#[test]
fn the_same_file_still_serialises_across_processes() {
    let workspace = scratch("serialise");
    let holder = spawn_child(&workspace, "src/a.rs", 900, "first");
    std::thread::sleep(Duration::from_millis(250));
    let other = spawn_child(&workspace, "src/a.rs", 0, "second");

    let holder_out = output_of(holder);
    let other_out = output_of(other);

    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");

    // Same file: the second process must have waited for the first to release.
    let waited = waited_ms(&other_out, "second");
    assert!(
        waited >= 300,
        "the same file must serialise; second waited only {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}

// ---------------------------------------------------------------------------
// Module-aware locking across processes
// ---------------------------------------------------------------------------

/// Build a Cargo workspace with two sibling crates, for module tests.
fn cargo_workspace(label: &str) -> PathBuf {
    let root = scratch(label);
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    )
    .unwrap();
    for (name, dir) in [("alpha", "crates/alpha"), ("beta", "crates/beta")] {
        let crate_dir = root.join(dir);
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        fs::write(
            crate_dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\n"),
        )
        .unwrap();
        fs::write(crate_dir.join("src/lib.rs"), "// src\n").unwrap();
    }
    root
}

/// Child that locks a path through the module-aware entry point.
fn spawn_module_child(
    workspace: &PathBuf,
    path: &str,
    hold_ms: u64,
    mark: &str,
) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("module_lock_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_MODLOCK_WORKSPACE", workspace)
        .env("PANGU_MODLOCK_PATH", path)
        .env("PANGU_MODLOCK_HOLD_MS", hold_ms.to_string())
        .env("PANGU_MODLOCK_MARK", mark)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn module child")
}

#[test]
#[ignore = "helper process driven by the module contention tests"]
fn module_lock_child() {
    let workspace = match std::env::var("PANGU_MODLOCK_WORKSPACE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };
    let path = std::env::var("PANGU_MODLOCK_PATH").unwrap();
    let hold_ms: u64 = std::env::var("PANGU_MODLOCK_HOLD_MS")
        .unwrap()
        .parse()
        .unwrap();
    let mark = std::env::var("PANGU_MODLOCK_MARK").unwrap_or_default();

    let map = pangu_core::discover(&workspace).expect("discover modules");
    assert!(map.is_confident(), "fixture build files must parse");

    let started = std::time::Instant::now();
    let lock = pangu_core::PathLock::acquire_for_action_with_modules(
        &workspace,
        &[],
        &[workspace.join(&path)],
        Some(&map),
        Duration::from_secs(30),
    )
    .expect("child acquires the module-aware lock");
    println!("ACQUIRED {mark} after {}ms", started.elapsed().as_millis());
    std::thread::sleep(Duration::from_millis(hold_ms));
    drop(lock);
    println!("RELEASED {mark}");
}

/// One agent owning a module must not block an agent in a sibling module.
#[test]
fn a_build_edit_in_one_crate_does_not_block_a_sibling_crate() {
    let workspace = cargo_workspace("module-parallel");
    let holder = spawn_module_child(&workspace, "crates/alpha/Cargo.toml", 900, "alpha");
    std::thread::sleep(Duration::from_millis(250));
    let sibling = spawn_module_child(&workspace, "crates/beta/Cargo.toml", 0, "beta");

    let holder_out = output_of(holder);
    let sibling_out = output_of(sibling);
    assert!(holder_out.contains("ACQUIRED alpha"), "{holder_out}");
    assert!(sibling_out.contains("ACQUIRED beta"), "{sibling_out}");

    let waited = waited_ms(&sibling_out, "beta");
    assert!(
        waited < 400,
        "a sibling module must proceed in parallel; waited {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}

/// The same module still serialises its build files.
#[test]
fn a_build_edit_in_the_same_crate_serialises_across_processes() {
    let workspace = cargo_workspace("module-serial");
    let holder = spawn_module_child(&workspace, "crates/alpha/Cargo.toml", 900, "first");
    std::thread::sleep(Duration::from_millis(250));
    let second = spawn_module_child(&workspace, "crates/alpha/Cargo.toml", 0, "second");

    let holder_out = output_of(holder);
    let second_out = output_of(second);
    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(second_out.contains("ACQUIRED second"), "{second_out}");

    let waited = waited_ms(&second_out, "second");
    assert!(
        waited >= 300,
        "the same module's build file must serialise; waited {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}
