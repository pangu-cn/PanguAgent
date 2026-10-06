//! Workspace read/write locking for concurrent agents.
//!
//! Several agents (a parent run and the sub-agents it delegates to, or two
//! independent runs pointed at one workspace) can contend for the same files.
//! This module serialises that access with a file-backed, cross-process lock.
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
//! from "holder is gone" using the file alone — the recorded `pid` is a hint,
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
//! lock exists to prevent, and it would destroy the evidence an operator needs.
//! Expiry is reported, never acted on.

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
/// an untracked dotfile in `git status` for the duration of a delegation —
/// visible clutter, and something they might wrongly commit or delete. Nothing
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
        let started = Instant::now();

        loop {
            match Self::try_acquire(&path, mode) {
                Ok(lock) => return Ok(lock),
                Err(TryLock::Busy(holder)) => {
                    if started.elapsed() >= deadline {
                        return Err(Error::Other(format!(
                            "workspace lock not acquired within {:?}: held by {} (path {}); \
                             another Pangu run is working in this workspace. If no Pangu process \
                             is running, the lock was left by one that was killed before it could \
                             release it — deleting that file is then safe. It is only a \
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
