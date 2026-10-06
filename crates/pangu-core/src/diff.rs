//! Deterministic, bounded unified diff for approval previews (F4).
//!
//! This is a display helper, not a storage format: the human deciding whether
//! to approve a `write_file` sees what would change before saying yes. The
//! output is deterministic for the same inputs (same algorithm, same order —
//! no hashing shortcuts on line content), always bounded by `max_bytes`, and
//! never pretends: when the input is too large to diff precisely, it says so
//! instead of silently dropping hunks.

use std::fmt::Write as _;

/// Compute a unified diff between two line sets, capped at `max_bytes`.
///
/// - `old`/`new` split on `\n`; a trailing newline is not significant.
/// - Lines compare by exact content, in order, with a bounded
///   longest-common-subsequence pass over the changed middle after common
///   prefix/suffix trimming; context lines come from the full inputs.
/// - When the changed middle is too large for the bounded pass, or the output
///   would exceed `max_bytes`, the result says so explicitly.
pub fn unified_diff(old: &str, new: &str, path: &str, max_bytes: usize) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    if old_lines == new_lines {
        return format!("`{path}`: content unchanged\n");
    }

    // Trim the common prefix and suffix; only the middle needs the LCS.
    let prefix = old_lines
        .iter()
        .zip(new_lines.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = old_lines[prefix..]
        .iter()
        .rev()
        .zip(new_lines[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let old_mid = &old_lines[prefix..old_lines.len() - suffix];
    let new_mid = &new_lines[prefix..new_lines.len() - suffix];

    let mut out = String::new();
    let _ = writeln!(out, "--- {path}");
    let _ = writeln!(out, "+++ {path}");

    const MAX_LCS_CELLS: usize = 250_000;
    if old_mid.len() * new_mid.len() > MAX_LCS_CELLS {
        let _ = writeln!(
            out,
            "@@ changed middle too large for an inline diff: {} old lines, {} new lines @@",
            old_mid.len(),
            new_mid.len()
        );
        return cap(out, path, max_bytes);
    }

    // Walk the LCS over the middle into an edit script, then re-base it onto
    // the full inputs so prefix/suffix context lines are ordinary Same steps
    // with absolute 0-based indices.
    #[derive(Clone, Copy, PartialEq)]
    enum Tag {
        Same,
        Del,
        Add,
    }
    let width = new_mid.len() + 1;
    let mut table = vec![0u32; (old_mid.len() + 1) * width];
    for i in (0..old_mid.len()).rev() {
        for j in (0..new_mid.len()).rev() {
            table[i * width + j] = if old_mid[i] == new_mid[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let mut script: Vec<(Tag, usize, usize)> = Vec::new();
    for idx in 0..prefix {
        script.push((Tag::Same, idx, idx));
    }
    let mut i = 0usize;
    let mut j = 0usize;
    while i < old_mid.len() && j < new_mid.len() {
        if old_mid[i] == new_mid[j] {
            script.push((Tag::Same, prefix + i, prefix + j));
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            script.push((Tag::Del, prefix + i, prefix + j));
            i += 1;
        } else {
            script.push((Tag::Add, prefix + i, prefix + j));
            j += 1;
        }
    }
    while i < old_mid.len() {
        script.push((Tag::Del, prefix + i, prefix + j));
        i += 1;
    }
    while j < new_mid.len() {
        script.push((Tag::Add, prefix + i, prefix + j));
        j += 1;
    }
    for k in 0..suffix {
        script.push((
            Tag::Same,
            prefix + old_mid.len() + k,
            prefix + new_mid.len() + k,
        ));
    }

    // Group the script into hunks with up to 3 context lines. Line numbers in
    // the header are 1-based absolute positions.
    const CONTEXT: usize = 3;
    let mut k = 0usize;
    while k < script.len() {
        let Some(change) = script[k..]
            .iter()
            .position(|(tag, _, _)| *tag != Tag::Same)
            .map(|delta| k + delta)
        else {
            break;
        };
        // Leading context, but never overlapping the previous hunk.
        let start = change.saturating_sub(CONTEXT).max(k);
        // Trailing scan: keep going while gaps of context stay short.
        let mut end = change + 1;
        let mut idx = change + 1;
        while idx < script.len() {
            if script[idx].0 == Tag::Same {
                let mut run = 0usize;
                let mut probe = idx;
                while probe < script.len() && script[probe].0 == Tag::Same {
                    run += 1;
                    probe += 1;
                }
                if run > CONTEXT {
                    end = (idx + CONTEXT).min(script.len());
                    break;
                }
                idx = probe;
                end = idx;
            } else {
                idx += 1;
                end = idx;
            }
        }

        let first_old = script[start].1 + 1;
        let first_new = script[start].2 + 1;
        let old_count = script[start..end]
            .iter()
            .filter(|(tag, _, _)| *tag != Tag::Add)
            .count();
        let new_count = script[start..end]
            .iter()
            .filter(|(tag, _, _)| *tag != Tag::Del)
            .count();
        let _ = writeln!(
            out,
            "@@ -{},{} +{},{} @@",
            if old_count == 0 {
                first_old - 1
            } else {
                first_old
            },
            old_count,
            if new_count == 0 {
                first_new - 1
            } else {
                first_new
            },
            new_count
        );
        for (tag, oi, ni) in &script[start..end] {
            match tag {
                Tag::Same => {
                    let _ = writeln!(out, " {}", old_lines[*oi]);
                }
                Tag::Del => {
                    let _ = writeln!(out, "-{}", old_lines[*oi]);
                }
                Tag::Add => {
                    let _ = writeln!(out, "+{}", new_lines[*ni]);
                }
            }
        }
        k = end;
    }

    cap(out, path, max_bytes)
}

/// Bound the rendered diff, saying explicitly when it was cut.
fn cap(mut out: String, path: &str, max_bytes: usize) -> String {
    if out.len() > max_bytes {
        let mut cut = max_bytes;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        let _ = writeln!(
            out,
            "... (diff for `{path}` truncated at {max_bytes} bytes)"
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_reports_no_change() {
        let out = unified_diff("a\nb\n", "a\nb\n", "f.txt", 4096);
        assert!(out.contains("content unchanged"), "{out}");
    }

    #[test]
    fn modification_shows_minus_and_plus_with_context() {
        let old = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
        let new = "one\ntwo\nthree\nfour\nfünf\nsix\nseven\neight\nnine\nten\n";
        let out = unified_diff(old, new, "f.txt", 4096);
        assert!(out.contains("-five"), "{out}");
        assert!(out.contains("+fünf"), "{out}");
        assert!(out.contains("@@"), "{out}");
        // Context lines around the change survive.
        assert!(out.contains(" three\n"), "{out}");
        assert!(out.contains(" six\n"), "{out}");
    }

    #[test]
    fn new_file_shows_everything_added() {
        let out = unified_diff("", "a\nb\n", "new.txt", 4096);
        assert!(out.contains("+a"), "{out}");
        assert!(out.contains("+b"), "{out}");
        assert!(!out.contains("\n-"), "{out}");
    }

    #[test]
    fn output_is_bounded_and_says_so() {
        // Every line changes, so the diff itself is genuinely large.
        let old: String = (0..300).map(|i| format!("line {i}\n")).collect();
        let new: String = (0..300).map(|i| format!("line {i} v2\n")).collect();
        let out = unified_diff(&old, &new, "big.txt", 2_048);
        assert!(out.len() <= 2_048 + 160, "len={}", out.len());
        assert!(out.contains("truncated"), "{out}");
    }

    #[test]
    fn huge_middle_degrades_to_an_honest_summary() {
        let old = "a\n".repeat(2_000);
        let new = "b\n".repeat(2_000);
        let out = unified_diff(&old, &new, "huge.txt", 4096);
        assert!(out.contains("too large for an inline diff"), "{out}");
        assert!(!out.contains("+b"), "{out}");
    }

    #[test]
    fn deterministic_for_same_input() {
        let old = "one\ntwo\nthree\n";
        let new = "one\nTWO\nthree\n";
        assert_eq!(
            unified_diff(old, new, "f", 4096),
            unified_diff(old, new, "f", 4096)
        );
    }

    #[test]
    fn separated_changes_produce_separate_hunks() {
        let mut old = String::new();
        let mut new = String::new();
        for i in 0..30 {
            old.push_str(&format!("line {i}\n"));
            if i == 5 {
                new.push_str("CHANGED-A\n");
            } else if i == 25 {
                new.push_str(&format!("line {i}\n"));
                new.push_str("CHANGED-B\n");
            } else {
                new.push_str(&format!("line {i}\n"));
            }
        }
        let out = unified_diff(&old, &new, "f.txt", 4096);
        assert_eq!(out.matches("@@ -").count(), 2, "{out}");
    }
}
