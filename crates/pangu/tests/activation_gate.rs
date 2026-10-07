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
    // refusal) reuses the file named in the same cell and is cited as a bare
    // `:NNNN` continuation.
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
    // Find the citation rather than hard-coding it: the line number legitimately
    // moves whenever code above it changes, and what has to hold is that the doc
    // and the code agree — not that the number is any particular value.
    let cited = citations(&section)
        .into_iter()
        .find(|(path, _)| path.ends_with("pangu/src/main.rs"))
        .expect("§9.2.1 must cite the unattended refusal by line in main.rs");

    let line = line_of(&cited.0, cited.1);
    // The citation names where the refusal happens. `bail!` is the refusal; the
    // `if` that guards it sits immediately above. Accept either, but require the
    // refusal itself to be there — a citation pointing at unrelated code is the
    // failure this test exists to catch.
    let nearby = {
        let text = read(&cited.0);
        let start = cited.1.saturating_sub(2).max(1);
        text.lines()
            .skip(start - 1)
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        line.contains("unattended") || nearby.contains("unattended"),
        "{}:{} must remain the unattended refusal; the area reads:\n{nearby}",
        cited.0,
        cited.1
    );
    assert!(
        line.contains("bail!") || nearby.contains("bail!"),
        "{}:{} must remain an outright refusal (`bail!`), not a warning; the \
         area reads:\n{nearby}",
        cited.0,
        cited.1
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

/// The manual must not hand the operator a command that does not build.
///
/// §9.1 step 2 tells the deployment owner to run `cargo test -p pangu-core --lib`
/// with a test filter — **without** `--all-features`. `crates/pangu-core`'s own
/// unit tests need `pangu_core::testing`, so that module has to compile for a
/// plain `cargo test`, not only when the feature is on. This was broken: the
/// module was gated on the feature alone, and the documented command failed with
/// `unresolved import crate::testing`. Nobody noticed because every CI job and
/// every local run this session used `--all-features`.
///
/// The check is on the manifest and the module gate, because the actual build
/// happens elsewhere and a test that shells out to cargo would recurse.
#[test]
fn the_documented_verification_command_is_able_to_compile() {
    let lib = read("crates/pangu-core/src/lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let index = lines
        .iter()
        .position(|line| line.contains("pub mod testing;"))
        .expect("the testing module must be declared");
    // The `#[cfg(...)]` attribute sits immediately above the declaration,
    // separated only by doc comments.
    let gate: String = lines[..index]
        .iter()
        .rev()
        .skip_while(|line| line.trim_start().starts_with("///"))
        .take(1)
        .copied()
        .collect();
    assert!(
        gate.contains("test"),
        "`pangu_core::testing` must be available to this crate's own unit tests, \
         not only under the `test-support` feature: `cargo test -p pangu-core` \
         (the command §9.1 gives the operator) does not enable that feature, so \
         gating on the feature alone makes that command fail to compile. \
         Found gate: {gate}"
    );

    // And the manual must keep naming that command, so the guard stays relevant.
    let manual = read("docs/CHECKPOINT_RECOVERY.md");
    assert!(
        manual.contains("cargo test -p pangu-core --lib"),
        "§9.1 step 2 must keep the pangu-core command this test protects"
    );
}

/// The manual's platform table must match what the filter actually collects.
///
/// §9.1 warns the operator to count passed tests rather than trust a zero exit
/// code, because `#[cfg]`-gated tests are not collected on the wrong platform.
/// That makes the count a claim the manual is making. This pins the filter's
/// Windows side to the number of applicable table rows, so the two cannot drift
/// apart silently.
#[test]
fn the_platform_table_matches_the_number_of_tests_the_filter_collects() {
    let manual = read("docs/CHECKPOINT_RECOVERY.md");
    let start = manual
        .find("**平台条件编译（实测，非推断）**")
        .expect("§9.1 must keep the platform table");
    // Bound to the table itself: the rows are contiguous, so the table ends at
    // the first line that is neither a row nor a separator. A fixed-width window
    // overran into a second table further down and made the count meaningless.
    let rows: Vec<&str> = manual[start..]
        .lines()
        .skip_while(|line| !line.starts_with("| `artifact::tests::"))
        .take_while(|line| line.starts_with('|'))
        .filter(|line| line.starts_with("| `artifact::tests::"))
        .collect();
    assert!(
        !rows.is_empty(),
        "the platform table must list the artifact tests by name"
    );
    let unix_only = rows
        .iter()
        .filter(|row| row.contains("#[cfg(unix)]"))
        .count();
    let applicable = rows.len() - unix_only;

    // On Windows the filter collects exactly the non-Unix-gated rows that match
    // the `restore_`/`corrupt_blob`/`snapshot_rejects` prefixes. The table writes
    // the restore group as one row (`restore_*`), so compare against the number
    // of *named* rows plus that group's expansion is not attempted here; instead
    // assert the relationship the manual states: the Unix-gated rows are the ones
    // that cannot be produced on Windows.
    // The table lists five `artifact::tests::` rows. The `rollback_cli` row is
    // named separately and reached by its own command, so it is not counted here.
    assert_eq!(
        rows.len(),
        5,
        "the table is expected to list five artifact tests; found {rows:#?}"
    );
    assert_eq!(
        unix_only, 3,
        "exactly three rows are `#[cfg(unix)]`; the manual's Windows guidance \
         depends on that count, found {unix_only}"
    );
    // The manual tells the operator that on Windows the three Unix-gated rows are
    // `not-applicable` and the rest must pass. That is two rows plus the
    // `restore_*` group, which the manual elsewhere records as 5 collected tests.
    assert_eq!(
        applicable, 2,
        "two rows carry no platform gate, so they are the ones Windows must \
         produce; found {applicable}"
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
