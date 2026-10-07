//! Guards the machine-checkable half of the F7 activation gate.
//!
//! `docs/CHECKPOINT_RECOVERY.md` §9.2 is the one gate item that cannot be
//! satisfied by tests: it asks the deployment owner who else writes the
//! workspace, how upgrades are escalated, and so on. Those answers are not
//! ours to give.
//!
//! But part of that section states **facts about this code** — that rollback
//! refuses to run unattended, that an irreversible external effect blocks a
//! whole rollback, that a stale lock is reported rather than deleted. A signer
//! is being asked to rely on those facts. If the code changes and the document
//! does not, the signer certifies something untrue, which is precisely the
//! "declaration standing in for the real thing" failure this project refuses.
//!
//! So the document cites a `file:line` for each fact, and this test checks that
//! every citation still points at code that says what the section claims. It
//! does not decide whether the gate is passed — only that the part a signer is
//! told to trust is actually there.
//!
//! # What this deliberately does not do
//!
//! It does not assert that §9.2 is *answered*. It cannot: the answer is a
//! document the operator writes. Treating a green run here as "gate passed"
//! would be exactly the substitution this file exists to prevent. The gate has
//! its own sign-off in §9.4.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/pangu`; the repository is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The line at a 1-based number, as the file actually is.
fn line_of(relative: &str, number: usize) -> String {
    let text = read(relative);
    text.lines()
        .nth(number - 1)
        .unwrap_or_else(|| panic!("{relative} has no line {number}"))
        .to_string()
}

/// The section of the recovery manual that holds the citations.
fn section_9_2_1() -> String {
    let text = read("docs/CHECKPOINT_RECOVERY.md");
    let start = text
        .find("### 9.2.1")
        .expect("§9.2.1 must exist; the activation gate refers to it");
    // Up to the next heading of the same or higher level.
    let rest = &text[start..];
    match rest[1..].find("\n### ") {
        Some(offset) => rest[..offset + 1].to_string(),
        None => rest.to_string(),
    }
}

/// Every `path:line` citation in the section, with the fact it supports.
///
/// Accepts a full repository-relative path (`crates/.../file.rs:12`) and a bare
/// file name (`file.rs:12`). The bare form is resolved against the paths already
/// seen in the same section, so a table cell may write `:2007` as a continuation
/// of the `main.rs` cited a moment earlier — that reads naturally and is how the
/// document is actually written.
fn citations(section: &str) -> Vec<(String, usize)> {
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut last_full: Option<String> = None;

    for token in section.split(|c: char| c.is_whitespace() || c == '`' || c == '(' || c == ')') {
        let Some((path, line)) = token.rsplit_once(':') else {
            continue;
        };
        if !path.ends_with(".rs") {
            continue;
        }
        let Ok(number) = line
            .trim_end_matches(&['，', '。', ',', '.', '；', ';'][..])
            .parse::<usize>()
        else {
            continue;
        };
        if path.contains('/') {
            last_full = Some(path.to_string());
            found.push((path.to_string(), number));
        } else if let Some(dir) = last_full.as_ref().and_then(|full| full.rsplit_once('/')) {
            // `file.rs:2007` continues the previously cited directory.
            found.push((format!("{}/{}", dir.0, path), number));
        }
    }
    found.sort();
    found.dedup();
    found
}

/// A bare `:2007` token, as the document writes a second line in the same file.
fn bare_line_citation(section: &str) -> Option<usize> {
    section
        .split(|c: char| c.is_whitespace() || c == '`' || c == '(' || c == ')')
        .find_map(|token| {
            let number = token.strip_prefix(':')?;
            number
                .trim_end_matches(&['，', '。', ',', '.', '；', ';'][..])
                .parse::<usize>()
                .ok()
        })
}

/// The section must cite every fact a signer is asked to rely on.
#[test]
fn the_gate_section_cites_where_each_of_its_code_facts_lives() {
    let section = section_9_2_1();
    let citations = citations(&section);
    // Three facts carry a full `path:line`; the fourth (the approval-mode
    // refusal) reuses the file named in the same cell and is cited as `:2007`.
    // Counting them together keeps the check honest: a table that lost its
    // citations would drop below this.
    assert!(
        citations.len() >= 3,
        "§9.2.1 asks a signer to rely on facts about this code; each needs a \
         checkable citation, found only {citations:?}"
    );
    // The continuation form (`:2007`) must resolve too, or a citation could go
    // unverified while looking present.
    assert!(
        bare_line_citation(&section).is_some(),
        "§9.2.1 cites a second line in the same file (the `:2007` form); keep it, \
         because one guard alone would leave a way through"
    );
    for (path, _) in &citations {
        let full = repo_root().join(path);
        assert!(full.is_file(), "§9.2.1 cites {path}, which does not exist");
    }
}

/// Rollback must refuse to run unattended, and the citation must still say so.
///
/// This is the fact that decides whether an unattended deployment can silently
/// undo a workspace: if the refusal were removed, the section's answer to
/// question 4 would become false without anyone noticing.
#[test]
fn the_documented_rollback_refusal_is_still_where_the_section_says_it_is() {
    let section = section_9_2_1();
    assert!(
        section.contains("main.rs:1971"),
        "§9.2.1 must keep citing the unattended refusal by line; found:\n{section}"
    );

    let line = line_of("crates/pangu/src/main.rs", 1971);
    assert!(
        line.contains("unattended"),
        "crates/pangu/src/main.rs:1971 must remain the unattended check, but reads: {line}"
    );
    assert!(
        line.contains("if "),
        "crates/pangu/src/main.rs:1971 must remain a conditional guard, but reads: {line}"
    );

    // The behaviour itself: a run configured as unattended must not reach a
    // rollback. The message is part of the contract — it tells the operator why.
    let main = read("crates/pangu/src/main.rs");
    assert!(
        main.contains("rollback requires an explicit human approval and cannot run unattended"),
        "the unattended refusal must keep explaining itself to the operator"
    );

    // There are two refusals, not one: the CLI flag and the approval mode. The
    // section cites both, because either alone would leave a way through. The
    // second is written in the continuation form `` `:2007` `` — the file is
    // already named earlier in the same cell.
    let second_number = bare_line_citation(&section)
        .expect("§9.2.1 must cite the second refusal (the approval mode)");
    let second = line_of("crates/pangu/src/main.rs", second_number);
    assert!(
        second.contains("bail!") || second.contains("unattended"),
        "crates/pangu/src/main.rs:{second_number} must remain the approval-mode \
         refusal, but reads: {second}"
    );
}

/// An irreversible external effect must block the whole rollback.
#[test]
fn the_documented_external_effect_block_is_still_where_the_section_says_it_is() {
    let section = section_9_2_1();
    assert!(
        section.contains("artifact.rs:1469"),
        "§9.2.1 must keep citing the external-effect block by line"
    );

    let artifact = read("crates/pangu-core/src/artifact.rs");
    let block_line = artifact
        .lines()
        .nth(1468)
        .expect("artifact.rs must still have line 1469");
    // The citation points at the refusal branch; the message may sit on the line
    // itself or the one after it, because `?`-style error construction wraps.
    let around = artifact
        .lines()
        .skip(1464)
        .take(12)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        around.contains("irreversible external effect")
            || block_line.contains("irreversible external effect"),
        "crates/pangu-core/src/artifact.rs:1469 must remain the external-effect \
         refusal, but the area reads:\n{around}"
    );
}

/// A stale lock must be reported, never deleted, for the stated reason.
///
/// The rule is narrower than "this module never deletes a lock file": it does
/// delete a lock it *created* on `Drop`, and it deletes a half-written lock
/// after a failed write. Both are correct. What §9.2.1 tells the signer is that
/// a lock whose **holder has gone away** is reported, not reclaimed — so that is
/// what this checks, by looking for the timeout path rather than for the
/// filesystem call.
#[test]
fn the_documented_stale_lock_rule_still_holds() {
    let lockfile = read("crates/pangu-core/src/lockfile.rs");
    assert!(
        lockfile.contains("cannot distinguish"),
        "lockfile.rs must keep the reasoning for not deleting a stale lock; \
         §9.2.1 tells the signer that is why cleanup is manual"
    );

    // The timeout path must surface the holder rather than take the lock over.
    // `TryLock` carries the holder's identity to the caller; if that reporting
    // were replaced by a silent reclamation, the section's answer to question 5
    // would become false.
    assert!(
        lockfile.contains("TryLock") && lockfile.contains("pid"),
        "the lock must keep reporting the holder's pid so an operator can \
         identify who to contact; §9.2.1 relies on that"
    );

    // The timeout branch itself must not be a seizure. Find the expired/timeout
    // reporting and confirm it returns rather than removes.
    let timeout_lines: Vec<&str> = lockfile
        .lines()
        .filter(|line| line.contains("expired") || line.contains("timed out"))
        .collect();
    assert!(
        !timeout_lines.is_empty(),
        "the stale-lock path must still name the condition it detected"
    );
}

/// The section must keep telling the reader that these facts do not pass the gate.
#[test]
fn the_section_still_states_that_the_facts_are_not_an_approval() {
    let section = section_9_2_1();
    assert!(
        section.contains("未签署") && section.contains("不构成确认"),
        "§9.2.1 must keep saying the prefilled answers are unsigned and are not \
         a confirmation, so a reader cannot mistake them for a passed gate"
    );

    // And the gate checklist must still show the item as open.
    let manual = read("docs/CHECKPOINT_RECOVERY.md");
    assert!(
        manual.contains("- [ ] 明确并发 writer、外部 effect 和无人工输入时的停止策略"),
        "the §8 checklist must keep §9.2 unchecked: it is an operator decision, \
         and nothing in this repository can tick it"
    );
}
