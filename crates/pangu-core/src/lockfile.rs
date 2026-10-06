//! Workspace read/write locking for concurrent agents.
//!
//! Several agents (a parent run and the sub-agents it delegates to, or two
//! independent runs pointed at one workspace) can contend for the same files.
//! This module serialises that access with file-backed, cross-process locks.
//!
//! # Two granularities
//!
//! - [`PathLock`] 鈥?a lock per **file path**. Two agents editing different
//!   files never wait for each other; two agents editing the same file are
//!   serialised. This is the default for tool calls, because a tool call knows
//!   exactly which paths it touches.
//! - [`WorkspaceLock`] 鈥?one lock for the **whole workspace**. Coarser, and
//!   needed when a caller cannot say which paths it will touch. Delegation
//!   wraps a child run whose tool calls are not known in advance, so it uses
//!   this only when explicitly asked to.
//!
//! A per-file lock is only sound because the sets of paths a call touches are
//! known before it runs: see [`PathLock::acquire_all`].
//!
//! # Acquiring several paths without deadlocking
//!
//! A tool call can touch many paths at once. If each holder took its paths in
//! the order the tool happened to list them, two holders could each be waiting
//! on the other:
//!
//! ```text
//! A: holds src/a.rs, wants src/b.rs
//! B: holds src/b.rs, wants src/a.rs
//! ```
//!
//! So multi-path acquisition sorts its keys and takes them in that single
//! global order. Waiting is still bounded, so even a lost race reports rather
//! than hangs.
//!
//! # Why this is not `StoreProcessLock`
//!
//! [`crate::artifact`]'s `StoreProcessLock` guards *rollback transactions* and
//! is deliberately fail-closed: on contention it refuses instead of waiting,
//! because a leftover marker may be evidence of an interrupted operation that
//! only an operator may adjudicate. That property is asserted by the
//! `stale-lock` operator drill and must not be weakened here. This lock is a
//! separate mechanism with different semantics (it waits), so it is a separate
//! file and a separate type.
//!
//! # Why waiting is bounded
//!
//! A lock file outlives its creator when the creator dies without running
//! `Drop` (crash, `SIGKILL`, power loss, container teardown). Nothing will ever
//! remove such a file: whoever finds it cannot distinguish "holder is working"
//! from "holder is gone" using the file alone 鈥?the recorded `pid` is a hint,
//! not proof, since pids are reused.
//!
//! An unbounded wait therefore has no exit for the crashed-holder case: the
//! waiter blocks forever, and a human sees a hung process rather than a
//! reported problem. Waiting is still the right primary behaviour, but it is
//! paired with a deadline so that "no progress" becomes a reported failure with
//! the holder's recorded identity attached, instead of a hang.
//!
//! The deadline expiring is *not* permission to break the lock. Breaking it
//! would let two writers touch the workspace at once, which is exactly what the
//! lock exists to prevent, and it would leave the workspace in a state matching
//! neither run's recorded actions. Expiry is reported, never acted on.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Name of the read/write lock file.
///
/// The lock lives **inside** the workspace's `.pangu/` directory, which is
/// already Pangu's own storage: it is a forbidden tool-write glob and every
/// deployment that uses memory, skills, conversations or checkpoints already
/// creates it. Putting the lock at the workspace root instead would show a user
/// an untracked dotfile in `git status` for the duration of a delegation 鈥?/// visible clutter, and something they might wrongly commit or delete. Nothing
/// about the lock belongs in the user's tracked tree.
pub const WORKSPACE_LOCK_FILE: &str = "workspace.lock";

/// Directory holding the lock, relative to the workspace. Stored relative so
/// lock paths follow the effective workspace rather than the process CWD.
pub const WORKSPACE_LOCK_DIR: &str = ".pangu";

/// Absolute path of the lock file for a workspace.
pub fn lock_file_path(workspace: &Path) -> PathBuf {
    workspace.join(WORKSPACE_LOCK_DIR).join(WORKSPACE_LOCK_FILE)
}

/// Create the `.pangu` directory if needed and return the lock file path.
fn prepare_lock_dir(workspace: &Path) -> Result<PathBuf> {
    let dir = workspace.join(WORKSPACE_LOCK_DIR);
    fs::create_dir_all(&dir)?;
    Ok(dir.join(WORKSPACE_LOCK_FILE))
}

/// Create the parent directory of an explicit lock file path.
fn prepare_parent(path: &Path) -> Result<()> {
    match path.parent() {
        Some(parent) => {
            fs::create_dir_all(parent)?;
            Ok(())
        }
        None => Err(Error::Config(format!(
            "lock file path has no parent directory: {}",
            path.display()
        ))),
    }
}

/// Subdirectory of `.pangu/` holding per-path lock files.
pub const PATH_LOCK_DIR: &str = "locks";

/// Directory holding per-path lock files for a workspace.
pub fn path_lock_dir(workspace: &Path) -> PathBuf {
    workspace.join(WORKSPACE_LOCK_DIR).join(PATH_LOCK_DIR)
}

/// Lock file name for one workspace-relative path.
///
/// The name is a hash rather than the path itself: a nested path would need its
/// directories recreated, and a path can contain characters no filesystem in
/// general accepts. Hashing also keeps the lock directory flat, so a lock can
/// be taken for a path whose parent directory does not exist yet (a tool that
/// creates `src/new/mod.rs` locks that name before `src/new/` exists).
pub fn path_lock_file(workspace: &Path, relative: &Path) -> PathBuf {
    let key = relative.to_string_lossy().replace('\\', "/");
    path_lock_dir(workspace).join(format!("{}.lock", crate::hex_sha256(&key)))
}

/// A lock covering one file path.
///
/// Holders of the same path serialise; holders of different paths do not
/// interact at all. See [`Self::acquire_all`] for taking several at once.
#[derive(Debug)]
pub struct PathLock {
    guard: WorkspaceLock,
    /// Workspace-relative path this lock covers, normalised.
    key: PathBuf,
}

impl PathLock {
    /// Acquire the lock for a single workspace-relative path.
    pub fn acquire(
        workspace: &Path,
        relative: &Path,
        mode: LockMode,
        deadline: Duration,
    ) -> Result<Self> {
        let key = normalise_relative(relative)?;
        let path = path_lock_file(workspace, &key);
        // Name the file the user recognises, not the hashed lock name.
        let described = format!("lock on `{}`", key.display());
        let guard = WorkspaceLock::acquire_at_with_poll(
            &path,
            mode,
            deadline,
            Duration::from_millis(25),
            Some(&described),
        )?;
        Ok(Self { guard, key })
    }

    /// Acquire locks for validated **absolute** paths inside the workspace.
    ///
    /// The sandbox resolves action paths to absolute form during validation, so
    /// this is the entry point the tool path uses. Paths outside the workspace
    /// are ignored rather than refused: a validated action may legitimately
    /// touch a readable root that is not the workspace, and this lock only
    /// exists to serialise *workspace* writes. Refusing would turn an unrelated
    /// readable root into a failed run.
    pub fn acquire_for_action(
        workspace: &Path,
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
        deadline: Duration,
    ) -> Result<Vec<Self>> {
        let to_key = |path: &PathBuf| -> Option<PathBuf> {
            path.strip_prefix(workspace).ok().map(Path::to_path_buf)
        };
        let reads: Vec<PathBuf> = read_paths.iter().filter_map(to_key).collect();
        let writes: Vec<PathBuf> = write_paths.iter().filter_map(to_key).collect();
        if reads.is_empty() && writes.is_empty() {
            return Ok(Vec::new());
        }
        Self::acquire_all(workspace, &reads, &writes, deadline)
    }

    /// Acquire locks for several paths, deadlock-free.
    ///
    /// Keys are de-duplicated and sorted before acquisition, so every holder
    /// takes shared keys in the same global order. Without that, two calls
    /// touching `{a, b}` and `{b, a}` would each hold one and wait forever for
    /// the other.
    ///
    /// Reads may be requested alongside writes; a path needed for writing is
    /// taken exclusively, and a path merely read is taken shared. If a path
    /// appears in both lists it is locked for writing, since that is the
    /// stronger requirement.
    ///
    /// On failure nothing is retained: every lock already taken is released
    /// before the error is returned, so a caller that gives up cannot leak
    /// locks the rest of the run would then have to wait on.
    pub fn acquire_all(
        workspace: &Path,
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
        deadline: Duration,
    ) -> Result<Vec<Self>> {
        // Collapse to one mode per key, letting a write supersede a read.
        let mut wanted: std::collections::BTreeMap<PathBuf, LockMode> =
            std::collections::BTreeMap::new();
        for path in read_paths {
            let key = normalise_relative(path)?;
            wanted.entry(key).or_insert(LockMode::Read);
        }
        for path in write_paths {
            let key = normalise_relative(path)?;
            // A write need overrides a read need for the same path.
            wanted.insert(key, LockMode::Write);
        }

        // BTreeMap iterates in sorted key order, which is the global order that
        // makes concurrent multi-path acquisition deadlock-free.
        let mut held = Vec::with_capacity(wanted.len());
        for (key, mode) in wanted {
            match Self::acquire(workspace, &key, mode, deadline) {
                Ok(lock) => held.push(lock),
                Err(error) => {
                    drop(held);
                    return Err(error);
                }
            }
        }
        Ok(held)
    }

    /// The workspace-relative path this lock covers.
    pub fn key(&self) -> &Path {
        &self.key
    }

    /// The mode this lock was taken in.
    pub fn mode(&self) -> LockMode {
        self.guard.mode()
    }
}

/// Reject keys that cannot name a path safely, and normalise separators.
///
/// A path escaping the workspace is refused here rather than hashed: two
/// different spellings of the same outside path would otherwise produce two
/// different lock names and fail to serialise.
///
/// The workspace root itself is a *valid* key: reading `.` is an ordinary
/// action, so refusing it would fail runs for no reason. It normalises to an
/// empty relative path, which the caller represents explicitly.
fn normalise_relative(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy().replace('\\', "/");
    // `"."`, `"./"` and `"././x"` all name the same thing as `""` and `"x"`.
    // Comparing them as strings would give `src/a.rs` and `./src/a.rs` two
    // different lock names, so two agents editing one file would not serialise.
    let mut trimmed = text.as_str();
    loop {
        let next = trimmed
            .strip_prefix("./")
            .or_else(|| trimmed.strip_prefix(".").filter(|rest| rest.is_empty()));
        match next {
            Some(rest) => trimmed = rest,
            None => break,
        }
    }
    for component in Path::new(trimmed).components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(Error::Config(format!(
                    "path lock key must not escape the workspace: {text}"
                )))
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(Error::Config(format!(
                    "path lock key must be workspace-relative, not absolute: {text}"
                )))
            }
            _ => {}
        }
    }
    Ok(PathBuf::from(trimmed))
}

/// How the caller intends to use the workspace while holding the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Read-only access. Other readers may hold the lock at the same time.
    Read,
    /// Write access. Held exclusively: no other reader or writer may hold it.
    Write,
}

impl LockMode {
    /// The token stored in the lock file, used by contenders to decide whether
    /// an existing holder is compatible with what they want.
    fn token(self) -> &'static str {
        match self {
            LockMode::Read => "read",
            LockMode::Write => "write",
        }
    }
}

/// A held workspace lock. Releases on drop.
///
/// Dropping is the only release path, so the file's lifetime matches the
/// value's. A process that dies without unwinding leaves the file behind; see
/// the module docs for why that is reported rather than cleaned up.
#[derive(Debug)]
pub struct WorkspaceLock {
    path: PathBuf,
    mode: LockMode,
}

impl WorkspaceLock {
    /// Acquire the workspace lock, waiting for a conflicting holder.
    ///
    /// Returns once the lock is held, or an error if the deadline passes or the
    /// lock file cannot be used. On error the caller must not proceed as if it
    /// held the lock.
    pub fn acquire(workspace: &Path, mode: LockMode, deadline: Duration) -> Result<Self> {
        Self::acquire_with_poll(workspace, mode, deadline, Duration::from_millis(25))
    }

    /// As [`Self::acquire`], with an explicit poll interval.
    ///
    /// The interval is a parameter so tests can drive the wait loop without
    /// sleeping for real time.
    pub fn acquire_with_poll(
        workspace: &Path,
        mode: LockMode,
        deadline: Duration,
        poll: Duration,
    ) -> Result<Self> {
        let path = prepare_lock_dir(workspace)?;
        Self::acquire_at_with_poll(&path, mode, deadline, poll, None)
    }

    /// Acquire an explicit lock file, waiting for a conflicting holder.
    ///
    /// Used by [`PathLock`], which owns its own lock file per path and passes a
    /// description so the wait error names the path rather than a bare digest.
    pub(crate) fn acquire_at_with_poll(
        path: &Path,
        mode: LockMode,
        deadline: Duration,
        poll: Duration,
        describe: Option<&str>,
    ) -> Result<Self> {
        prepare_parent(path)?;
        let what = describe.unwrap_or("workspace lock");
        let started = Instant::now();

        loop {
            match Self::try_acquire(path, mode) {
                Ok(lock) => return Ok(lock),
                Err(TryLock::Busy(holder)) => {
                    if started.elapsed() >= deadline {
                        return Err(Error::Other(format!(
                            "{what} not acquired within {:?}: held by {} (path {}); \
                             another Pangu run is working on it. If no Pangu process \
                             is running, the lock was left by one that was killed before it could \
                             release it 鈥?deleting that file is then safe. It is only a \
                             mutual-exclusion marker, not evidence, so it is never removed \
                             automatically here.",
                            deadline,
                            holder.describe(),
                            path.display()
                        )));
                    }
                    std::thread::sleep(poll);
                }
                Err(TryLock::Failed(error)) => return Err(error),
            }
        }
    }

    /// Attempt to take the lock without waiting.
    pub fn try_acquire_now(workspace: &Path, mode: LockMode) -> Result<Option<Self>> {
        let path = prepare_lock_dir(workspace)?;
        match Self::try_acquire(&path, mode) {
            Ok(lock) => Ok(Some(lock)),
            Err(TryLock::Busy(_)) => Ok(None),
            Err(TryLock::Failed(error)) => Err(error),
        }
    }

    fn try_acquire(path: &Path, mode: LockMode) -> std::result::Result<Self, TryLock> {
        // `create_new` is the atomic claim: it fails if the file already
        // exists, so two contenders cannot both believe they created it.
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                let payload = format!("mode={}\npid={}\n", mode.token(), std::process::id());
                if let Err(error) = file
                    .write_all(payload.as_bytes())
                    .and_then(|_| file.sync_all())
                {
                    // Do not leave a half-written lock that later readers would
                    // have to interpret.
                    let _ = fs::remove_file(path);
                    return Err(TryLock::Failed(error.into()));
                }
                Ok(Self {
                    path: path.to_path_buf(),
                    mode,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let holder = LockHolder::read(path).unwrap_or_default();
                // Readers coexist; anything involving a writer does not.
                let compatible = mode == LockMode::Read && holder.mode == Some(LockMode::Read);
                if compatible {
                    // A shared read lock is represented by the file already
                    // being present in read mode. We do not append a second
                    // entry: the file is released by its creator's drop, and
                    // treating it as reference-counted would make a crash
                    // ambiguous about how many holders were counted.
                    return Ok(Self {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
                Err(TryLock::Busy(holder))
            }
            Err(error) => Err(TryLock::Failed(error.into())),
        }
    }

    /// The mode this lock was acquired in.
    pub fn mode(&self) -> LockMode {
        self.mode
    }

    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        // Only a writer, or the single reader that created the file, may remove
        // it. A shared reader that merely observed an existing read lock must
        // not delete a file another holder still relies on.
        if self.mode == LockMode::Write || Self::created_by_us(&self.path) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl WorkspaceLock {
    fn created_by_us(path: &Path) -> bool {
        // A reader that created the file is the sole holder at that moment (the
        // create is atomic), so it owns the removal. We distinguish ownership
        // by whether the recorded pid is ours.
        match LockHolder::read(path) {
            Some(holder) => holder.pid == Some(std::process::id()),
            None => false,
        }
    }
}

enum TryLock {
    Busy(LockHolder),
    Failed(Error),
}

/// What a contender can learn about the current holder.
///
/// Every field is a hint read from an untrusted file: `pid` may have been
/// reused, and `mode` may be absent for a file a foreign tool wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockHolder {
    /// Recorded process id, if present and parseable.
    pub pid: Option<u32>,
    /// Recorded mode, if present and recognised.
    pub mode: Option<LockMode>,
}

impl LockHolder {
    /// Read the holder description from a lock file, if it is readable.
    pub fn read(path: &Path) -> Option<Self> {
        let text: String = fs::read_to_string(path).ok()?;
        Some(Self::parse(&text))
    }

    fn parse(text: &str) -> Self {
        let mut holder = Self::default();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("pid=") {
                holder.pid = value.trim().parse().ok();
            } else if let Some(value) = line.strip_prefix("mode=") {
                holder.mode = match value.trim() {
                    "read" => Some(LockMode::Read),
                    "write" => Some(LockMode::Write),
                    // An unrecognised mode is treated as absent, and an absent
                    // mode is treated as incompatible by callers, so a foreign
                    // or corrupt file can only make us more cautious.
                    _ => None,
                };
            }
        }
        holder
    }

    fn describe(&self) -> String {
        let mode = match self.mode {
            Some(LockMode::Read) => "read",
            Some(LockMode::Write) => "write",
            None => "unknown mode",
        };
        match self.pid {
            Some(pid) => format!("{mode}, pid {pid}"),
            None => format!("{mode}, unidentified process"),
        }
    }

    /// Whether the recorded pid names a process that still exists.
    ///
    /// This is intentionally *only* a diagnostic: a live pid does not prove the
    /// holder still holds the lock (it may have exited and the pid been reused),
    /// and a dead pid does not authorise removing the file. Callers must not
    /// use this to decide to break a lock.
    pub fn pid_appears_alive(&self) -> Option<bool> {
        #[cfg(unix)]
        {
            let pid = self.pid?;
            // Signal 0 performs error checking without sending a signal.
            let result = unsafe { libc_kill(pid as i32, 0) };
            return Some(result == 0);
        }
        #[cfg(not(unix))]
        {
            // Without a portable probe, report "unknown" rather than guessing.
            None
        }
    }
}

#[cfg(unix)]
fn libc_kill(pid: i32, signal: i32) -> i32 {
    // Declared here to avoid taking a dependency on a libc crate for one call.
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, signal) }
}

/// Describe the lock file for error messages and inspection output.
pub fn describe_lock(workspace: &Path) -> Option<LockHolder> {
    LockHolder::read(&lock_file_path(workspace))
}

/// Open (without creating) the lock file, for read-only inspections.
pub fn peek_lock_file(workspace: &Path) -> Result<Option<File>> {
    let path = lock_file_path(workspace);
    match File::open(&path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn workspace(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pangu-lock-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn cleanup(path: &Path) {
        fs::remove_dir_all(path).ok();
    }

    /// Plant a lock file exactly as a crashed holder would leave it: the
    /// directory exists, the file is present, and nobody will remove it.
    fn plant_lock(root: &Path, contents: &str) {
        let path = prepare_lock_dir(root).expect("prepare lock dir");
        fs::write(path, contents).expect("plant lock");
    }

    // ---- per-path locking -------------------------------------------------

    #[test]
    fn different_paths_do_not_block_each_other() {
        let root = workspace("path-parallel");
        let _a = PathLock::acquire(
            &root,
            Path::new("src/a.rs"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();
        // A different file is a different lock: this must not wait.
        let b = PathLock::acquire(
            &root,
            Path::new("docs/b.md"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .expect("an unrelated path must be free");
        assert_eq!(b.key(), Path::new("docs/b.md"));
        cleanup(&root);
    }

    #[test]
    fn the_same_path_serialises() {
        let root = workspace("path-serialise");
        let _held = PathLock::acquire(
            &root,
            Path::new("src/a.rs"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();
        let second = PathLock::acquire(
            &root,
            Path::new("src/a.rs"),
            LockMode::Write,
            Duration::from_millis(80),
        );
        assert!(
            second.is_err(),
            "the same path must not be writable by two holders at once"
        );
        cleanup(&root);
    }

    #[test]
    fn a_path_lock_names_the_file_it_covers() {
        let root = workspace("path-naming");
        let _held = PathLock::acquire(
            &root,
            Path::new("src/deep/file.rs"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();
        let error = PathLock::acquire(
            &root,
            Path::new("src/deep/file.rs"),
            LockMode::Write,
            Duration::from_millis(50),
        )
        .expect_err("contended")
        .to_string();
        assert!(
            error.contains("src/deep/file.rs"),
            "the wait error must name the file, not the hashed lock name: {error}"
        );
        cleanup(&root);
    }

    #[test]
    fn equivalent_spellings_share_one_lock() {
        let root = workspace("path-spelling");
        let _held = PathLock::acquire(
            &root,
            Path::new("src/a.rs"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();
        // `./src/a.rs` is the same file; it must contend, not slip through.
        let other = PathLock::acquire(
            &root,
            Path::new("./src/a.rs"),
            LockMode::Write,
            Duration::from_millis(50),
        );
        assert!(
            other.is_err(),
            "two spellings of one path must not both be lockable"
        );
        cleanup(&root);
    }

    #[test]
    fn acquire_all_takes_every_path_and_a_write_supersedes_a_read() {
        let root = workspace("path-multi");
        let held = PathLock::acquire_all(
            &root,
            &[PathBuf::from("src/a.rs"), PathBuf::from("docs/b.md")],
            &[PathBuf::from("src/a.rs")],
            Duration::from_millis(500),
        )
        .unwrap();
        assert_eq!(held.len(), 2, "both paths must be locked");
        let a = held
            .iter()
            .find(|lock| lock.key() == Path::new("src/a.rs"))
            .expect("a.rs locked");
        assert_eq!(
            a.mode(),
            LockMode::Write,
            "a path needed for writing must be held exclusively even if also read"
        );
        let b = held
            .iter()
            .find(|lock| lock.key() == Path::new("docs/b.md"))
            .expect("b.md locked");
        assert_eq!(b.mode(), LockMode::Read);
        cleanup(&root);
    }

    /// Two holders that want the same pair of paths in opposite orders must not
    /// deadlock. Sorted acquisition is what makes that true.
    ///
    /// Each thread takes both paths, holds them briefly, and releases 鈥?so the
    /// test exercises real contention. Returning the locks instead would be
    /// useless: a thread that still holds them cannot be "finished", and the
    /// other would be waiting on a live holder rather than a deadlocked one.
    /// With unsorted acquisition this test deadlocks and fails on the deadline.
    #[test]
    fn acquire_all_is_deadlock_free_for_overlapping_sets() {
        let root = workspace("path-deadlock");

        let worker = |order: [&'static str; 2], root: PathBuf| {
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let paths = vec![PathBuf::from(order[0]), PathBuf::from(order[1])];
                    let held = PathLock::acquire_all(&root, &[], &paths, Duration::from_secs(5))?;
                    // Hold long enough that an unsorted implementation would
                    // reliably interleave into a deadlock.
                    std::thread::sleep(Duration::from_millis(2));
                    drop(held);
                }
                Ok::<_, crate::error::Error>(())
            })
        };

        let a = worker(["p/one", "p/two"], root.clone());
        let b = worker(["p/two", "p/one"], root.clone());

        let a = a.join().expect("thread a panicked");
        let b = b.join().expect("thread b panicked");
        assert!(a.is_ok(), "holder a must complete: {:?}", a.err());
        assert!(b.is_ok(), "holder b must complete: {:?}", b.err());
        cleanup(&root);
    }

    #[test]
    fn a_failed_multi_acquire_releases_what_it_already_took() {
        let root = workspace("path-rollback");
        // Hold one of the two paths, so acquire_all fails part-way through.
        let _blocker = PathLock::acquire(
            &root,
            Path::new("p/two"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();

        let attempt = PathLock::acquire_all(
            &root,
            &[],
            &[PathBuf::from("p/one"), PathBuf::from("p/two")],
            Duration::from_millis(80),
        );
        assert!(attempt.is_err(), "the blocked path must fail the call");
        assert!(
            attempt.unwrap_err().to_string().contains("p/two"),
            "the error must name the blocking path"
        );

        // `p/one` was taken before the failure. It must have been released, or
        // the rest of the run would wait on a lock nobody holds.
        let reclaimed = PathLock::acquire(
            &root,
            Path::new("p/one"),
            LockMode::Write,
            Duration::from_millis(200),
        );
        assert!(
            reclaimed.is_ok(),
            "a partially failed acquire must not leak the locks it took"
        );
        cleanup(&root);
    }

    #[test]
    fn path_keys_that_leave_the_workspace_are_refused() {
        let root = workspace("path-escape");
        for bad in ["../outside.rs", "/etc/passwd"] {
            let result = PathLock::acquire(
                &root,
                Path::new(bad),
                LockMode::Write,
                Duration::from_millis(50),
            );
            assert!(
                result.is_err(),
                "`{bad}` must not be lockable as a workspace path"
            );
        }
        cleanup(&root);
    }

    /// Reading `.` is an ordinary action, so the workspace root must be a
    /// usable key rather than an error. Refusing it failed real runs.
    #[test]
    fn the_workspace_root_is_a_valid_key() {
        let root = workspace("path-root");
        let held = PathLock::acquire(
            &root,
            Path::new("."),
            LockMode::Read,
            Duration::from_millis(200),
        )
        .expect("the workspace root must be lockable");
        assert_eq!(held.key(), Path::new(""));
        cleanup(&root);
    }

    #[test]
    fn path_locks_live_under_pangu_not_the_tracked_tree() {
        let root = workspace("path-location");
        let _held = PathLock::acquire(
            &root,
            Path::new("src/a.rs"),
            LockMode::Write,
            Duration::from_millis(200),
        )
        .unwrap();
        let dir = path_lock_dir(&root);
        assert!(dir.starts_with(root.join(WORKSPACE_LOCK_DIR)));
        // The tracked file itself must never be touched.
        assert!(!root.join("src/a.rs").exists());
        cleanup(&root);
    }

    #[test]
    fn a_write_lock_excludes_a_second_writer() {
        let root = workspace("write-excludes");
        let _held = WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();
        let second = WorkspaceLock::try_acquire_now(&root, LockMode::Write).unwrap();
        assert!(second.is_none(), "a second writer must not get the lock");
        cleanup(&root);
    }

    #[test]
    fn a_write_lock_excludes_readers() {
        let root = workspace("write-excludes-read");
        let _held = WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();
        let reader = WorkspaceLock::try_acquire_now(&root, LockMode::Read).unwrap();
        assert!(
            reader.is_none(),
            "a reader must not proceed while a writer holds the lock"
        );
        cleanup(&root);
    }

    #[test]
    fn readers_share_the_lock() {
        let root = workspace("read-shared");
        let first = WorkspaceLock::acquire(&root, LockMode::Read, Duration::from_secs(1)).unwrap();
        let second = WorkspaceLock::try_acquire_now(&root, LockMode::Read).unwrap();
        assert!(second.is_some(), "two readers must be able to coexist");
        drop(first);
        drop(second);
        cleanup(&root);
    }

    #[test]
    fn a_reader_blocks_a_writer() {
        let root = workspace("read-blocks-write");
        let _reader =
            WorkspaceLock::acquire(&root, LockMode::Read, Duration::from_secs(1)).unwrap();
        let writer = WorkspaceLock::try_acquire_now(&root, LockMode::Write).unwrap();
        assert!(
            writer.is_none(),
            "a writer must not start while a reader holds the lock"
        );
        cleanup(&root);
    }

    #[test]
    fn releasing_lets_the_next_holder_in() {
        let root = workspace("release");
        {
            let _held =
                WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();
            assert!(lock_file_path(&root).exists());
        }
        assert!(
            !lock_file_path(&root).exists(),
            "dropping the lock must remove the file"
        );
        let next = WorkspaceLock::try_acquire_now(&root, LockMode::Write).unwrap();
        assert!(next.is_some(), "the next writer must be able to proceed");
        cleanup(&root);
    }

    #[test]
    fn a_waiter_blocks_until_the_holder_releases() {
        let root = workspace("waits");
        let held = WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();

        let waiter_root = root.clone();
        let handle = std::thread::spawn(move || {
            // Generous deadline: the point is that it succeeds *because* the
            // holder released, not because the deadline was reached.
            WorkspaceLock::acquire(&waiter_root, LockMode::Write, Duration::from_secs(10))
                .map(|lock| lock.mode())
        });

        // Give the waiter time to observe the busy lock before releasing.
        std::thread::sleep(Duration::from_millis(150));
        drop(held);

        let acquired = handle.join().expect("waiter thread panicked");
        assert_eq!(
            acquired.expect("the waiter must acquire after release"),
            LockMode::Write
        );
        cleanup(&root);
    }

    /// The reason waiting is bounded: a crashed holder never releases, so an
    /// unbounded wait would hang forever. This pins that the waiter gives up
    /// and says why, rather than blocking.
    #[test]
    fn a_lock_left_by_a_crashed_holder_times_out_with_the_holder_named() {
        let root = workspace("stale");
        // Simulate a crash: the file exists but no live holder will remove it.
        plant_lock(&root, &format!("mode=write\npid={}\n", std::process::id()));

        let started = Instant::now();
        let error = WorkspaceLock::acquire_with_poll(
            &root,
            LockMode::Write,
            Duration::from_millis(120),
            Duration::from_millis(10),
        )
        .expect_err("a stale lock must not be waited on forever")
        .to_string();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must be bounded, took {:?}",
            started.elapsed()
        );
        assert!(
            error.contains("not acquired within"),
            "the error must report the timeout: {error}"
        );
        assert!(
            error.contains("write") && error.contains("pid"),
            "the error must name the holder so a user can act: {error}"
        );
        // This lock is a mutual-exclusion marker, not audit evidence, so the
        // message must tell a user what to do rather than forbid action. A
        // stranger running a public CLI has no "operator" to escalate to, and
        // an unactionable message gets worked around unsafely.
        assert!(
            error.contains("deleting that file is then safe"),
            "the error must tell a user how to recover: {error}"
        );
        assert!(
            error.contains("no Pangu process is running"),
            "the recovery advice must be conditioned on nothing running: {error}"
        );
        // The file must survive the failed acquisition regardless of the
        // advice: reporting it is the job, removing it is the user's call.
        assert!(
            lock_file_path(&root).exists(),
            "an expired wait must not remove the holder's file"
        );
        cleanup(&root);
    }

    #[test]
    fn the_holder_description_is_parsed_from_the_file() {
        let root = workspace("parse");
        let _held = WorkspaceLock::acquire(&root, LockMode::Read, Duration::from_secs(1)).unwrap();
        let holder = describe_lock(&root).expect("the lock file must be readable");
        assert_eq!(holder.pid, Some(std::process::id()));
        assert_eq!(holder.mode, Some(LockMode::Read));
        cleanup(&root);
    }

    #[test]
    fn an_unrecognised_mode_is_treated_as_unknown_and_never_as_compatible() {
        let root = workspace("unknown-mode");
        plant_lock(&root, "mode=exclusive\npid=1\n");
        let holder = describe_lock(&root).unwrap();
        assert_eq!(holder.mode, None);
        // Unknown must not be read as "read", or a writer would slip past.
        let attempt = WorkspaceLock::try_acquire_now(&root, LockMode::Write).unwrap();
        assert!(attempt.is_none());
        cleanup(&root);
    }

    #[test]
    fn a_corrupt_or_empty_lock_file_still_blocks() {
        let root = workspace("corrupt");
        plant_lock(&root, "not a lock file");
        let attempt = WorkspaceLock::try_acquire_now(&root, LockMode::Write).unwrap();
        assert!(
            attempt.is_none(),
            "an unreadable lock must fail closed, not be ignored"
        );
        let holder = describe_lock(&root).unwrap();
        assert_eq!(holder.mode, None);
        assert_eq!(holder.pid, None);
        cleanup(&root);
    }

    #[test]
    fn pid_liveness_is_reported_as_a_hint_only() {
        let root = workspace("pid-hint");
        let _held = WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();
        let holder = describe_lock(&root).unwrap();
        // Ourselves: must report alive where the platform can tell.
        #[cfg(unix)]
        assert_eq!(holder.pid_appears_alive(), Some(true));
        #[cfg(not(unix))]
        assert_eq!(
            holder.pid_appears_alive(),
            None,
            "without a portable probe the answer must be unknown, not a guess"
        );
        cleanup(&root);
    }

    #[test]
    fn the_lock_file_lives_under_pangu_storage() {
        let root = workspace("location");
        let _held = WorkspaceLock::acquire(&root, LockMode::Write, Duration::from_secs(1)).unwrap();
        let path = lock_file_path(&root);
        assert_eq!(
            path,
            root.join(WORKSPACE_LOCK_DIR).join(WORKSPACE_LOCK_FILE)
        );
        assert!(path.is_file());
        // It must sit inside `.pangu/`, which is already Pangu-owned and a
        // forbidden tool-write glob: a lock file loose in the workspace root
        // would show up in the user's `git status` and could be committed.
        assert!(
            path.starts_with(root.join(WORKSPACE_LOCK_DIR)),
            "the lock must not be written into the user's tracked tree: {}",
            path.display()
        );
        cleanup(&root);
    }
}
