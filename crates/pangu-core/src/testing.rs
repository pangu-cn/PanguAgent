//! A temporary directory that satisfies this project's path policy.
//!
//! # Why this exists
//!
//! `pangu-core`'s journal and artifact layers reject any path with a symlink
//! component, and the sandbox canonicalizes its workspace before comparing
//! prefixes. Both are deliberate: a symlinked ancestor is how a path escapes the
//! root it was checked against.
//!
//! The platform temporary directory can itself sit behind a symlink. On many
//! Linux container images `/tmp` is a link, and on macOS it resolves to
//! `/private/tmp`. A fixture that builds a path with plain `std::env::temp_dir()`
//! therefore produces a path the runtime refuses — and it does so **only on the
//! platforms where the temp directory is linked**, which is exactly the CI runner
//! and not the maintainer's machine. The result is a test suite that is green
//! locally and red in CI for a reason that has nothing to do with the code under
//! test.
//!
//! This was found the hard way: the same one-line helper had been copy-pasted
//! into `pangu-boundary/src/config.rs`, `pangu-agent/src/test_support.rs` and
//! `mcp_boundary.rs`, while `journal.rs`, `stream.rs` and several test binaries
//! were still using the raw form. One shared implementation removes the whole
//! class of mistake: there is now one place to get it right.
//!
//! # Not a `#[cfg(test)]` module
//!
//! It has to be reachable from *integration* tests (`crates/*/tests/*.rs`), which
//! are separate crates and cannot see a `#[cfg(test)]` item inside a library. It
//! lives behind `test-support` so it is only compiled when a test needs it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A unique directory under the resolved temporary root.
///
/// `label` makes the directory identifiable in a failing run; the process id and
/// a counter keep concurrent tests from colliding.
///
/// The path is created and returned as an **absolute, canonical** path, so it can
/// be compared against the sandbox's canonicalized workspace and passed to the
/// journal/artifact layers without tripping the symlink policy.
///
/// The directory is **not** removed automatically: tests that write real files
/// sometimes need to inspect them after a failure, and a `Drop` that deletes the
/// evidence makes a red CI run harder to diagnose. On failure the path is printed
/// by the assertion; on success it sits under the runner's temp directory, which
/// the runner discards. Tests that want cleanup can call
/// [`TempDir::remove`].
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a temporary directory for a test.
    pub fn new(label: &str) -> Self {
        Self::under(&resolved_temp_root(), label)
    }

    /// Create a temporary directory under a specific base.
    ///
    /// The base is canonicalized for the same reason as [`TempDir::new`]'s.
    pub fn under(base: &Path, label: &str) -> Self {
        // Canonicalize first: a caller may hand us a base reached through a
        // symlink, and joining onto the unresolved spelling would reintroduce
        // exactly the mismatch this module exists to prevent.
        let base = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
        let path = base.join(format!(
            "pangu-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        // Canonicalize the created directory too: on some systems the base
        // resolves only once the path exists.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Join a relative name onto this directory.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }

    /// Create a subdirectory and return it.
    pub fn child(&self, name: impl AsRef<Path>) -> PathBuf {
        let path = self.join(name);
        std::fs::create_dir_all(&path).expect("create temp subdir");
        path
    }

    /// Remove the directory, ignoring errors.
    ///
    /// Best-effort rather than fallible: a caller cleaning up should not fail a
    /// passing test over a leftover file on Windows, where a just-exited process
    /// can hold one briefly.
    pub fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

/// [`std::env::temp_dir`], with symlinked ancestors resolved.
///
/// Exposed for the callers that need a root rather than a directory of their own.
pub fn resolved_temp_root() -> PathBuf {
    let base = std::env::temp_dir();
    std::fs::canonicalize(&base).unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: the path is canonical, so a symlinked temp root cannot
    /// make it look like it is inside a sibling.
    #[test]
    fn the_path_is_canonical_even_when_the_temp_root_is_a_symlink() {
        let dir = TempDir::new("canonical");
        assert!(dir.path().is_absolute());
        assert_eq!(
            std::fs::canonicalize(dir.path()).expect("canonicalize"),
            dir.path(),
            "a fixture path must already be canonical, or the sandbox and the \
             journal will reject it on platforms whose temp dir is a symlink"
        );
        dir.remove();
    }

    /// Two tests asking for the same label must not collide.
    #[test]
    fn directories_are_unique() {
        let first = TempDir::new("unique");
        let second = TempDir::new("unique");
        assert_ne!(first.path(), second.path());
        first.remove();
        second.remove();
    }

    /// The result must be usable as a journal destination, which is the concrete
    /// failure this module was written to prevent: `Journal::create` rejects any
    /// symlink component, so a raw `temp_dir()` path fails on a linked `/tmp`.
    #[test]
    fn the_path_is_accepted_by_the_journal_symlink_policy() {
        let dir = TempDir::new("journal-policy");
        let path = dir.join("journal.jsonl");
        crate::journal::reject_symlink_components(&path)
            .expect("a canonical temp path must satisfy the symlink policy");
        dir.remove();
    }

    /// A caller-supplied base is canonicalized too, so passing the raw temp
    /// directory is not a silent mistake.
    #[test]
    fn a_raw_temp_root_is_canonicalized_by_the_caller_path() {
        let dir = TempDir::under(&std::env::temp_dir(), "raw-base");
        assert_eq!(
            std::fs::canonicalize(dir.path()).expect("canonicalize"),
            dir.path()
        );
        dir.remove();
    }
}
