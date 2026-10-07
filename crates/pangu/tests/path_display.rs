//! Keeps recorded paths usable outside the machine that recorded them.
//!
//! # The problem this guards
//!
//! `std::fs::canonicalize` returns Windows' *verbatim* form — `\\?\F:\ws`, or
//! `\\?\UNC\server\share`. That is the correct spelling to hand to the Win32 API
//! (it is how long paths are addressed without further normalization), and it is
//! the wrong spelling to show a person. It does not work pasted into a shell, and
//! it resolves on no other machine.
//!
//! Several of this project's outputs are evidence: the `demo`/`doctor` summary an
//! operator pastes into a ticket, the journal header, the audit export, and the
//! `artifact inspect --json` record that §9.3 stores off-box. All of them carried
//! the canonical spelling, because the values they print come from paths that
//! were canonicalized on the way in.
//!
//! The fix is `pangu_core::util::displayable_path`, and the risk is that a new
//! output site is added later that prints a raw canonical path. So this test
//! scans the source tree for the pattern and fails on it, rather than relying on
//! anyone remembering.
//!
//! # What it does not claim
//!
//! It checks the pattern, not every reachable string. A path that reaches output
//! through some other expression is not caught. It is a guard against the
//! recurrence we actually saw (six sites in three crates), not a proof.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root")
        .to_path_buf()
}

/// Does this line store a path in canonical form inside a record?
///
/// The concern is narrower than "prints a path". A diagnostic (`format!("cannot
/// read {}", p.display())`) *should* show the real path — that is what the
/// operator needs to fix the problem, and it is not archived. What matters is a
/// path that becomes part of a **record**: a journal field, an export, a JSON
/// report, an explain line someone keeps.
///
/// This stays local to the line on purpose. An earlier version tried to find
/// statement boundaries by scanning for `;`, and `"no journal found in {}; pass
/// --journal <path>"` contains one: the scan stopped inside the message and
/// missed the `ok_or_else` around it. Parsing Rust properly is out of scope for
/// a guard, so the rule is what can be decided from the surrounding two lines.
fn statement_stores_canonical_path(lines: &[&str], index: usize) -> bool {
    let line = lines[index];
    if !line.contains(".display()") {
        return false;
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with('*') {
        return false;
    }

    // A named field being assigned: `name: value.display()`. The text before the
    // colon must look like a bare identifier, which excludes `::` paths and
    // anything with a call in it.
    let before_colon = line.split(':').next().unwrap_or("");
    let field_assignment = line.contains(':')
        && !line.contains("::")
        && !before_colon.contains('(')
        && !before_colon.contains('.')
        && !before_colon.trim().is_empty()
        && before_colon
            .trim()
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_');

    // Or an element added to a collection, which is how these records are built.
    let collection_element = line.contains("vec![")
        || line.contains(".map(|path| path.display()")
        || line.contains(".map(|p| p.display()");

    if !(field_assignment || collection_element) {
        return false;
    }

    // Message construction never counts, on this line or a few before it —
    // `format!`/`anyhow!` and the `.display()` they feed are often several lines
    // apart, and looking only one line back misses the enclosing macro.
    for context in &lines[index.saturating_sub(4)..=index] {
        for marker in [
            "format!(",
            "with_context",
            "anyhow!",
            "bail!(",
            "println!",
            "eprintln!",
            "Error::Config(",
            "Error::Other(",
            "panic!(",
            "ok_or_else",
            "otherwise(",
        ] {
            if context.contains(marker) {
                return false;
            }
        }
    }
    true
}

/// Files that legitimately store a canonical path, with the reason.
///
/// Each entry is `(substring of the repository-relative path, why it is fine)`.
/// Adding a file here is a deliberate decision, which is the point: the default
/// is to use `displayable_path`.
const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/pangu-core/src/util.rs",
        "the helper itself: it is where the verbatim form is understood",
    ),
    (
        "crates/pangu-boundary/src/runtime.rs",
        "the launcher's working directory is handed to a host process, which \
         does accept the verbatim form; the mount argument goes through \
         displayable_path",
    ),
];

#[test]
fn no_record_stores_a_canonical_path() {
    let root = repo_root();
    let mut offenders: Vec<String> = Vec::new();

    for entry in walk(&root.join("crates")) {
        let rel = entry
            .strip_prefix(&root)
            .unwrap_or(&entry)
            .to_string_lossy()
            .replace('\\', "/");
        if !rel.ends_with(".rs") {
            continue;
        }
        if ALLOWED.iter().any(|(prefix, _)| rel.starts_with(prefix)) {
            continue;
        }
        let text = match std::fs::read_to_string(&entry) {
            Ok(text) => text,
            Err(_) => continue,
        };
        // Integration tests build fixtures and explain failures; they do not
        // ship to an operator.
        let is_test_file = rel.contains("/tests/") || rel.ends_with("/tests.rs");
        let lines: Vec<&str> = text.lines().collect();
        for index in 0..lines.len() {
            if statement_stores_canonical_path(&lines, index) {
                if is_test_file || in_test_block(&text, index + 1) {
                    continue;
                }
                offenders.push(format!("{rel}:{}: {}", index + 1, lines[index].trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these lines store a canonical path in a record, which on Windows \
         carries the `\\\\?\\` prefix and is unusable in a ticket, a shell, or \
         on another host. Use `pangu_core::util::displayable_path`, or add the \
         file to ALLOWED with a reason:\n{}",
        offenders.join("\n")
    );
}

/// Crude but sufficient: is `line` after the first `#[cfg(test)]` in the file?
fn in_test_block(text: &str, line: usize) -> bool {
    let mut in_test = false;
    for (index, current) in text.lines().enumerate() {
        if index + 1 == line {
            return in_test;
        }
        if current.trim_start().starts_with("#[cfg(test)]") {
            in_test = true;
        }
    }
    in_test
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// The helper must do what its callers depend on.
#[test]
fn displayable_path_removes_only_the_verbatim_marker() {
    use pangu_core::util::displayable_path;

    assert_eq!(
        displayable_path(Path::new(r"\\?\C:\work\ws")),
        r"C:\work\ws"
    );
    assert_eq!(
        displayable_path(Path::new(r"\\?\UNC\server\share\ws")),
        r"\\server\share\ws"
    );
    assert_eq!(displayable_path(Path::new(r"C:\work\ws")), r"C:\work\ws");
    assert_eq!(displayable_path(Path::new("/work/ws")), "/work/ws");
    // A bare marker is left alone: returning an empty path would be worse than
    // returning the odd-looking one.
    assert_eq!(displayable_path(Path::new(r"\\?\")), r"\\?\");
}
