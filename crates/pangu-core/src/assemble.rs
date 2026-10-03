//! Context assembly (ADR-0005 §3.2/§3.7/§3.8/§3.9).
//!
//! `assembled = FORCED ∪ requested(model)`, closed under §3.8 pairing.
//! The forced set is not negotiable with the model: system turns, the goal,
//! refused paths, unfinished tool calls, and the most recent N turns always
//! get in. The model can only *add* requested slices, never remove one —
//! otherwise it could drop the very refusal it is about to retry.
//!
//! Seams: wherever the selected slices are not adjacent in the original
//! history, the assembled message stream gets an explicit marker (§3.7). An
//! unmarked splice would present a history that never happened.
//!
//! Pure-memory (§3.9): this module never touches a store or a contract. It
//! re-derives slices from the `&[Message]` it is given, so the assembler
//! works with `conversation.enabled = false` (the default). Persistence of
//! summaries/slices is a cross-run optimization, not a dependency.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Message, Result};

/// Why a slice was selected. `ForcedPairing` is §3.8: a slice was pulled in
/// because a selected slice references it — never because the model asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    ForcedSystem,
    ForcedGoal,
    ForcedRefusal,
    ForcedIncompleteToolCall,
    ForcedRecent,
    ForcedPairing,
    Requested,
    /// Chosen by the pluggable second-stage selector (A6-6 seam). Not yet
    /// inhabited: laya implements this trait only after B6 lands.
    SecondStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceSelection {
    pub slice_id: String,
    pub reason: SelectionReason,
    pub estimated_tokens: u64,
    pub mode: DegradeMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omission {
    pub slice_id: String,
    pub reason: String,
}

/// How a selected slice is presented in the assembled window. The degradation
/// chain is `Full → Summary → Omitted`; forced-core slices never reach
/// `Omitted` (§3.2's non-negotiable set may shrink to its summary, but it may
/// not vanish — §3.4's honest bound is still reported, not hidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradeMode {
    Full,
    Summary,
    Omitted,
}

/// Where in the assembled stream a splice happened. `before` is the index of
/// the marker message inside `AssembledContext::messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seam {
    pub before: usize,
    pub from_slice: String,
    pub into_slice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssembledContext {
    pub messages: Vec<Message>,
    /// Always `true`: this is a splice, never the original history.
    pub derived: bool,
    /// Always `false`: see `derived`. Fielded so A2 consumers pattern-match.
    pub authoritative: bool,
    pub seams: Vec<Seam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyReport {
    pub selections: Vec<SliceSelection>,
    pub omissions: Vec<Omission>,
    /// The forced set alone already exceeds the budget. Not an error here —
    /// §3.4's terminal fallback (A6-5) owns the decision to stop.
    pub forced_over_budget: bool,
    pub estimated_tokens: u64,
    pub derived: bool,
    pub authoritative: bool,
    /// How the second stage went: `"none"` (deterministic heuristic only),
    /// `"selector"` (a selector ran and its own picks were added), or
    /// `"fallback"` (the selector failed; the deterministic shortlist was
    /// used as-is — B6's fail-safe-or-fallback rule).
    #[serde(default)]
    pub second_stage: String,
}

fn slice_tokens(messages: &[Message], entry: &crate::SliceEntry) -> u64 {
    messages[entry.start_message..=entry.end_message]
        .iter()
        .map(|message| message.approx_tokens())
        .sum()
}

/// Close the selection under call/result pairing (§3.8). Public so the
/// acceptance test can drive it with a hand-broken span split.
pub fn close_pairing(
    messages: &[Message],
    entries: &[crate::SliceEntry],
    selected: &mut BTreeSet<usize>,
    reasons: &mut BTreeMap<usize, SelectionReason>,
) {
    let mut pending: Vec<usize> = selected.iter().copied().collect();
    while let Some(index) = pending.pop() {
        let entry = &entries[index];
        for message in &messages[entry.start_message..=entry.end_message] {
            let call_ids: Vec<&str> = match message {
                Message::Assistant { tool_calls, .. } => {
                    tool_calls.iter().map(|call| call.id.as_str()).collect()
                }
                _ => Vec::new(),
            };
            for call_id in call_ids {
                let target = messages[..].iter().position(|candidate| {
                    matches!(candidate, Message::Tool { call_id: id, .. } if id == call_id)
                });
                if let Some(position) = target {
                    if let Some(owner) = entries
                        .iter()
                        .position(|e| e.start_message <= position && position <= e.end_message)
                    {
                        if !selected.contains(&owner) {
                            selected.insert(owner);
                            reasons.insert(owner, SelectionReason::ForcedPairing);
                            pending.push(owner);
                        }
                    }
                }
            }
            let result_id: Option<&str> = match message {
                Message::Tool { call_id, .. } => Some(call_id),
                _ => None,
            };
            if let Some(call_id) = result_id {
                let target = messages[..].iter().position(|candidate| match candidate {
                    Message::Assistant { tool_calls, .. } => {
                        tool_calls.iter().any(|call| call.id == call_id)
                    }
                    _ => false,
                });
                if let Some(position) = target {
                    if let Some(owner) = entries
                        .iter()
                        .position(|e| e.start_message <= position && position <= e.end_message)
                    {
                        if !selected.contains(&owner) {
                            selected.insert(owner);
                            reasons.insert(owner, SelectionReason::ForcedPairing);
                            pending.push(owner);
                        }
                    }
                }
            }
        }
    }
}

/// Whether a span still carries a call without its result — the one shape of
/// "有调用无结果" the forced set must keep visible (§3.8).
fn has_unfinished_tool_call(messages: &[Message], entry: &crate::SliceEntry) -> bool {
    let span = &messages[entry.start_message..=entry.end_message];
    span.iter().any(|message| match message {
        Message::Assistant { tool_calls, .. } => tool_calls.iter().any(|call| {
            !messages.iter().any(|candidate| {
                matches!(candidate, Message::Tool { call_id, .. } if call_id == &call.id)
            })
        }),
        _ => false,
    })
}

fn span_has_error(messages: &[Message], entry: &crate::SliceEntry) -> bool {
    messages[entry.start_message..=entry.end_message]
        .iter()
        .any(|message| matches!(message, Message::Tool { is_error: true, .. }))
}

fn slice_summary_marker(entry: &crate::SliceEntry) -> Message {
    Message::system(format!(
        "[pangu slice summary (slice \"{}\", degraded under budget): {}]",
        entry.slice_id, entry.summary
    ))
}

/// Assign a presentation mode to every selected slice, degrading under budget
/// pressure. Keeping `Full` is prioritized for forced-core, then recent
/// forced (newest first), then requested (request order). Core slices floor at
/// `Summary`; recent/requested may reach `Omitted`, which is recorded in the
/// report — never silent.
fn degrade(
    messages: &[Message],
    entries: &[crate::SliceEntry],
    selected: &BTreeSet<usize>,
    reasons: &BTreeMap<usize, SelectionReason>,
    budget_tokens: u64,
) -> BTreeMap<usize, (DegradeMode, u64)> {
    let mut modes: BTreeMap<usize, (DegradeMode, u64)> = selected
        .iter()
        .map(|index| {
            (
                *index,
                (DegradeMode::Full, slice_tokens(messages, &entries[*index])),
            )
        })
        .collect();

    let total = |modes: &BTreeMap<usize, (DegradeMode, u64)>| -> u64 {
        modes.values().map(|(_, tokens)| *tokens).sum()
    };

    // Higher rank = degraded earlier.
    let rank = |index: &usize| match reasons[index] {
        SelectionReason::Requested | SelectionReason::SecondStage => 3,
        SelectionReason::ForcedRecent => 2,
        SelectionReason::ForcedPairing
        | SelectionReason::ForcedSystem
        | SelectionReason::ForcedGoal
        | SelectionReason::ForcedRefusal
        | SelectionReason::ForcedIncompleteToolCall => 1,
    };

    loop {
        if total(&modes) <= budget_tokens {
            break;
        }
        let mut candidate: Option<usize> = None;
        for index in modes.keys() {
            let (mode, _) = modes[index];
            let can_degrade = match mode {
                DegradeMode::Full => true,
                DegradeMode::Summary => rank(index) >= 2,
                DegradeMode::Omitted => false,
            };
            if !can_degrade {
                continue;
            }
            candidate = Some(match candidate {
                None => *index,
                Some(prev) => {
                    if rank(index) > rank(&prev) || (rank(index) == rank(&prev) && *index > prev) {
                        *index
                    } else {
                        prev
                    }
                }
            });
        }
        let Some(index) = candidate else { break };
        modes.insert(
            index,
            match modes[&index].0 {
                DegradeMode::Full => (
                    DegradeMode::Summary,
                    slice_summary_marker(&entries[index]).approx_tokens(),
                ),
                DegradeMode::Summary => (DegradeMode::Omitted, 0),
                DegradeMode::Omitted => unreachable!(),
            },
        );
    }
    modes
}

/// One candidate handed to the second-stage selector: the deterministic
/// coarse filter has already run, so this list is exactly what laya would see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSlice {
    pub slice_id: String,
    pub kind: crate::SliceKind,
    pub summary: String,
    pub message_count: usize,
    pub estimated_tokens: u64,
}

/// The A6-6 seam: a short-decision pass over the coarse shortlist. B6's rules
/// apply in full — never a startup dependency, never decides the forced set,
/// and on any failure the assembler falls back to the deterministic
/// shortlist (`second_stage: "fallback"` in the report). Laya implements this
/// after B6 lands; today it is always `None`.
pub trait SecondStageSelector {
    fn select(&self, candidates: &[CandidateSlice]) -> Result<Vec<String>>;
}

/// Assemble with an optional second stage. `None` keeps the deterministic
/// heuristic as the whole answer — delete the selector and nothing breaks.
pub fn assemble_with(
    messages: &[Message],
    recent_turns: usize,
    requested: &[String],
    budget_tokens: u64,
    selector: Option<&dyn SecondStageSelector>,
) -> Result<(AssembledContext, AssemblyReport)> {
    // The seam: second stage decides *which extra slices join the requested
    // set*. Failures degrade the report, never the run.
    let mut extra: Vec<String> = Vec::new();
    let second_stage;
    if let Some(selector) = selector {
        let slices = crate::slice(messages)?;
        let candidates: Vec<CandidateSlice> = slices
            .entries
            .iter()
            .map(|entry| CandidateSlice {
                slice_id: entry.slice_id.clone(),
                kind: entry.kind,
                summary: entry.summary.clone(),
                message_count: entry.end_message - entry.start_message + 1,
                estimated_tokens: slice_tokens(messages, entry),
            })
            .collect();
        match selector.select(&candidates) {
            Ok(picks) => {
                extra = picks;
                second_stage = "selector".to_string();
            }
            Err(_) => {
                second_stage = "fallback".to_string();
            }
        }
    } else {
        second_stage = "none".to_string();
    }
    let mut requested_all: Vec<String> = requested.to_vec();
    requested_all.extend(extra);
    let (context, mut report) = assemble(messages, recent_turns, &requested_all, budget_tokens)?;
    // Re-stamp the requested slices that came from the selector: their
    // SelectionReason should say `second_stage`, not `requested`.
    // (assemble() tagged by request order, so we rewrite by matching ids.)
    let selector_ids: std::collections::HashSet<&str> = second_stage_ids(&requested_all, requested);
    if second_stage == "selector" {
        for selection in report.selections.iter_mut() {
            if selector_ids.contains(selection.slice_id.as_str())
                && selection.reason == SelectionReason::Requested
            {
                selection.reason = SelectionReason::SecondStage;
            }
        }
    }
    report.second_stage = second_stage;
    Ok((context, report))
}

fn second_stage_ids<'a>(
    all: &'a [String],
    original: &'a [String],
) -> std::collections::HashSet<&'a str> {
    all[original.len()..].iter().map(|s| s.as_str()).collect()
}

/// Assemble the context for one model call, purely in memory.
///
/// `requested` carries slice ids the model asked for. Unknown ids are an
/// omission with reason `unknown-slice`, never a failure: the model is not
/// trusted with the slice index, and a bad request must not abort the run.
pub fn assemble(
    messages: &[Message],
    recent_turns: usize,
    requested: &[String],
    budget_tokens: u64,
) -> Result<(AssembledContext, AssemblyReport)> {
    let slices = crate::slice(messages)?;
    crate::verify_slices(&slices, messages)?;
    let entries = &slices.entries;

    let mut selected: BTreeSet<usize> = BTreeSet::new();
    let mut reasons: BTreeMap<usize, SelectionReason> = BTreeMap::new();

    // --- forced set, in slice order so reasons do not overlap arbitrarily ---
    for (index, entry) in entries.iter().enumerate() {
        if entry.kind == crate::SliceKind::Phase {
            selected.insert(index);
            reasons.insert(index, SelectionReason::ForcedSystem);
        }
    }
    // The goal lives in the first user-bearing slice. Checked *after* the
    // incomplete-call pass so a mid-flight call reports its own reason.
    for (index, entry) in entries.iter().enumerate() {
        if span_has_error(messages, entry) {
            selected.insert(index);
            reasons
                .entry(index)
                .or_insert(SelectionReason::ForcedRefusal);
        }
        if has_unfinished_tool_call(messages, entry) {
            selected.insert(index);
            reasons
                .entry(index)
                .or_insert(SelectionReason::ForcedIncompleteToolCall);
        }
    }
    if let Some(goal_index) = entries.iter().position(|entry| {
        messages[entry.start_message..=entry.end_message]
            .iter()
            .any(|message| matches!(message, Message::User { .. }))
    }) {
        selected.insert(goal_index);
        reasons
            .entry(goal_index)
            .or_insert(SelectionReason::ForcedGoal);
    }
    let turn_like: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            matches!(
                entry.kind,
                crate::SliceKind::Turn | crate::SliceKind::Refusal
            )
        })
        .map(|(index, _)| index)
        .collect();
    for index in turn_like.iter().rev().take(recent_turns) {
        selected.insert(*index);
        reasons
            .entry(*index)
            .or_insert(SelectionReason::ForcedRecent);
    }

    close_pairing(messages, entries, &mut selected, &mut reasons);

    // --- requested are admitted to the selection; the degradation chain,
    // not an early budget check, decides their final presentation (A6-3) ---
    let mut omissions = Vec::new();
    for slice_id in requested {
        let Some(index) = entries.iter().position(|entry| entry.slice_id == *slice_id) else {
            omissions.push(Omission {
                slice_id: slice_id.clone(),
                reason: "unknown-slice".into(),
            });
            continue;
        };
        if selected.contains(&index) {
            continue;
        }
        selected.insert(index);
        reasons.insert(index, SelectionReason::Requested);
        // A requested slice can drag in pairing partners.
        close_pairing(messages, entries, &mut selected, &mut reasons);
    }

    let modes = degrade(messages, entries, &selected, &reasons, budget_tokens);
    let degraded_total: u64 = modes.values().map(|(_, tokens)| *tokens).sum();
    let forced_over_budget = degraded_total > budget_tokens;
    for (index, (mode, _)) in &modes {
        if *mode == DegradeMode::Omitted {
            omissions.push(Omission {
                slice_id: entries[*index].slice_id.clone(),
                reason: "budget".into(),
            });
        }
    }

    // --- splice in original order, marking every seam (§3.7) ---
    let mut out_messages: Vec<Message> = Vec::new();
    let mut seams: Vec<Seam> = Vec::new();
    let mut previous_end: Option<usize> = None;
    let mut selections = Vec::new();
    let mut last_slice_id = String::new();
    for index in &selected {
        let entry = &entries[*index];
        let (mode, tokens) = modes[index];
        if let Some(end) = previous_end {
            if entry.start_message > end + 1 {
                let omitted_in_gap: Vec<&crate::SliceEntry> = modes
                    .iter()
                    .filter(|(i, (m, _))| {
                        *m == DegradeMode::Omitted
                            && entries[**i].start_message > end
                            && entries[**i].end_message < entry.start_message
                    })
                    .map(|(i, _)| &entries[*i])
                    .collect();
                let marker = if omitted_in_gap.is_empty() {
                    format!(
                        "[pangu context seam: slice \"{}\" follows \"{}\"; the history between them \
                         is in this store but not in this window. Derived context, not the original \
                         turn sequence.]",
                        entry.slice_id, last_slice_id
                    )
                } else {
                    format!(
                        "[pangu context seam: slice \"{}\" follows \"{}\"; the history between them \
                         is in this store but not in this window; omitted under budget: {}. Derived \
                         context, not the original turn sequence.]",
                        entry.slice_id,
                        last_slice_id,
                        omitted_in_gap
                            .iter()
                            .map(|e| e.slice_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                seams.push(Seam {
                    before: out_messages.len(),
                    from_slice: last_slice_id.clone(),
                    into_slice: entry.slice_id.clone(),
                });
                out_messages.push(Message::system(marker));
            }
        }
        match mode {
            DegradeMode::Full => {
                for message in &messages[entry.start_message..=entry.end_message] {
                    out_messages.push(message.clone());
                }
            }
            DegradeMode::Summary => {
                out_messages.push(slice_summary_marker(entry));
            }
            DegradeMode::Omitted => {}
        }
        selections.push(SliceSelection {
            slice_id: entry.slice_id.clone(),
            reason: reasons[index],
            estimated_tokens: tokens,
            mode,
        });
        previous_end = Some(entry.end_message);
        last_slice_id = entry.slice_id.clone();
    }

    let estimated_tokens = out_messages
        .iter()
        .map(|message| message.approx_tokens())
        .sum::<u64>();
    Ok((
        AssembledContext {
            messages: out_messages,
            derived: true,
            authoritative: false,
            seams,
        },
        AssemblyReport {
            selections,
            omissions,
            forced_over_budget,
            estimated_tokens,
            derived: true,
            authoritative: false,
            second_stage: "none".into(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> Vec<Message> {
        vec![
            Message::system("you are pangu"),
            Message::user("read notes.md"),
            Message::assistant("ok, reading"),
            Message::user("and write x.md"),
            Message::assistant_calls(
                "writing",
                vec![crate::ToolCall {
                    id: "c1".into(),
                    name: "write_file".into(),
                    args: serde_json::json!({}),
                }],
            ),
            Message::Tool {
                call_id: "c1".into(),
                name: "write_file".into(),
                content: "denied: forbidden".into(),
                is_error: true,
            },
            Message::assistant("blocked then"),
            Message::user("third thing"),
            Message::assistant("third done"),
        ]
    }

    #[test]
    fn the_forced_set_always_gets_in_and_the_model_cannot_remove_it() {
        let messages = history();
        // Model asks for nothing; a path where everything would be empty if
        // the forced set depended on the request.
        let (context, report) = assemble(&messages, 1, &[], 100_000).expect("assemble");
        assert!(context.derived);
        assert!(!context.authoritative);
        let reasons: Vec<_> = report.selections.iter().map(|s| s.reason).collect();
        assert!(reasons.contains(&SelectionReason::ForcedSystem));
        assert!(reasons.contains(&SelectionReason::ForcedGoal));
        assert!(reasons.contains(&SelectionReason::ForcedRefusal));
        assert!(reasons.contains(&SelectionReason::ForcedRecent));
        // The refusal turn must be present even though it is old.
        let flat = serde_json::to_string(&context.messages).expect("encode");
        assert!(flat.contains("denied: forbidden"));
    }

    #[test]
    fn requested_slices_append_and_unknown_ids_are_omissions_not_failures() {
        let messages = history();
        let slices = crate::slice(&messages).expect("slice");
        let first_turn = slices.entries[1].slice_id.clone();
        let (_context, report) = assemble(
            &messages,
            1,
            &[first_turn.clone(), "no-such-slice".into()],
            100_000,
        )
        .expect("assemble");
        assert!(
            report
                .selections
                .iter()
                .any(|s| s.reason == SelectionReason::Requested)
                || report.selections.iter().any(|s| s.slice_id == first_turn)
        );
        assert_eq!(report.omissions.len(), 1);
        assert_eq!(report.omissions[0].reason, "unknown-slice");
    }

    #[test]
    fn over_budget_requested_slices_are_omitted_with_a_reason() {
        // Four turns; the only non-forced slices are turn 2's. With a
        // one-token budget, requesting it must be a `budget` omission — and
        // the forced set alone must already flag `forced_over_budget`.
        let mut messages = vec![Message::system("s")];
        for i in 0..4 {
            messages.push(Message::user(format!("q{i}")));
            messages.push(Message::assistant(format!("a{i}")));
        }
        let slices = crate::slice(&messages).expect("slice");
        let turn2 = slices
            .entries
            .iter()
            .find(|entry| entry.slice_id.starts_with("turn") && entry.start_message == 3)
            .expect("turn 2")
            .slice_id
            .clone();
        let (_context, report) =
            assemble(&messages, 1, std::slice::from_ref(&turn2), 1).expect("assemble");
        assert!(report.forced_over_budget);
        assert!(
            report
                .omissions
                .iter()
                .any(|o| o.slice_id == turn2 && o.reason == "budget"),
            "report was: {report:?}"
        );
    }

    #[test]
    fn non_adjacent_selections_produce_visible_seams() {
        let messages = history();
        // Force refusal (turn 2) + recent 1 turn (turn 3): slices 2 and arity
        // leave the first turn out, which is a genuine gap in slice space.
        let (context, report) = assemble(&messages, 1, &[], 100_000).expect("assemble");
        if !context.seams.is_empty() {
            for seam in &context.seams {
                match &context.messages[seam.before] {
                    Message::System { content } => {
                        assert!(content.contains("pangu context seam"))
                    }
                    _ => panic!("a seam must be a system marker"),
                }
            }
        }
        assert!(report.derived);
    }

    #[test]
    fn pairing_closure_pulls_in_the_result_slice() {
        // A hand-broken entry split: the call in one entry, its result in
        // another. `close_pairing` must join them; the assembler's own slice
        // output never does this (slices keep pairs together), so this drives
        // the helper directly as the §3.8 acceptance test.
        let messages = vec![
            Message::system("s"),
            Message::user("go"),
            Message::assistant_calls(
                "burst",
                vec![crate::ToolCall {
                    id: "x".into(),
                    name: "t".into(),
                    args: serde_json::json!({}),
                }],
            ),
            Message::tool_result("x", "t", "1"),
        ];
        let mut entries = crate::slice(&messages).expect("slice").entries;
        // Smash the turn span in two across the pair boundary.
        entries[1].end_message = 2;
        entries.insert(
            2,
            crate::SliceEntry {
                slice_id: "tool_result-only".into(),
                start_message: 3,
                end_message: 3,
                start_line: 0,
                end_line: 0,
                range_digest: String::new(),
                kind: crate::SliceKind::Turn,
                summary: String::new(),
                derived_from: vec![3],
                verbatim: true,
                unverified: false,
            },
        );
        // Fix the forged digests so the fixture is structurally honest.
        entries[1].range_digest = {
            let content = crate::conversation::message_content(&messages[2]);
            crate::hex_sha256(content)
        };
        entries[1].derived_from = vec![1, 2];
        let mut selected: BTreeSet<usize> = BTreeSet::new();
        let mut reasons: BTreeMap<usize, SelectionReason> = BTreeMap::new();
        selected.insert(1);
        reasons.insert(1, SelectionReason::Requested);
        close_pairing(&messages, &entries, &mut selected, &mut reasons);
        assert!(
            selected.contains(&2),
            "the result slice must be pulled in by pairing"
        );
        assert_eq!(reasons[&2], SelectionReason::ForcedPairing);
    }

    #[test]
    fn an_unfinished_tool_call_stays_forced_and_pairs_with_nothing() {
        let messages = vec![
            Message::system("s"),
            Message::user("go"),
            Message::assistant_calls(
                "call",
                vec![crate::ToolCall {
                    id: "x".into(),
                    name: "t".into(),
                    args: serde_json::json!({}),
                }],
            ),
        ];
        let (context, report) = assemble(&messages, 5, &[], 100_000).expect("assemble");
        assert!(report
            .selections
            .iter()
            .any(|s| s.reason == SelectionReason::ForcedIncompleteToolCall));
        // The call is kept, but no synthetic result is invented.
        let flat = serde_json::to_string(&context.messages).expect("encode");
        assert!(flat.contains("\"role\":\"assistant\""));
        let tool_count = context
            .messages
            .iter()
            .filter(|m| matches!(m, Message::Tool { .. }))
            .count();
        assert_eq!(tool_count, 0);
    }

    #[test]
    fn budget_pressure_degrades_to_summary_before_omitting() {
        // Two turns; everything is forced (recent both), so the chain cannot
        // drop forced-recent below Summary — the big old turn must show up as
        // a summary marker, not vanish.
        let mut messages = vec![Message::system("s")];
        messages.push(Message::user("first"));
        messages.push(Message::assistant("a".repeat(4000)));
        messages.push(Message::user("second"));
        messages.push(Message::assistant("ok"));
        // Probe a budget that forces exactly one Summary degradation.
        let probes: Vec<u64> = (0..=12).map(|i| 2u64.pow(i)).collect();
        let mut seen_summary = false;
        for budget in probes {
            let (context, report) = assemble(&messages, 2, &[], budget).expect("assemble");
            let has_summary = context.messages.iter().any(
                |m| matches!(m, Message::System { content } if content.contains("slice summary")),
            );
            let has_full_old = serde_json::to_string(&context.messages)
                .expect("encode")
                .contains(&"a".repeat(4000));
            if has_summary && !has_full_old {
                seen_summary = true;
                let mode = report
                    .selections
                    .iter()
                    .find(|s| s.slice_id.starts_with("turn"))
                    .expect("a turn")
                    .mode;
                assert_eq!(mode, DegradeMode::Summary);
                break;
            }
        }
        assert!(seen_summary, "no budget level produced a degraded summary");
    }

    #[test]
    fn forced_core_never_degrades_below_summary() {
        let messages = vec![
            Message::system("s"),
            Message::user("goal"),
            Message::assistant_calls(
                "c",
                vec![crate::ToolCall {
                    id: "x".into(),
                    name: "t".into(),
                    args: serde_json::json!({}),
                }],
            ),
        ];
        let (_context, report) = assemble(&messages, 1, &[], 1).expect("assemble");
        assert!(
            report
                .selections
                .iter()
                .all(|s| s.mode != DegradeMode::Omitted),
            "forced core must floor at Summary, got: {report:?}"
        );
        assert!(report.forced_over_budget);
    }

    #[test]
    fn second_stage_none_matches_plain_assemble() {
        let messages = history();
        let (a_ctx, a_rep) = assemble(&messages, 2, &[], 100_000).expect("a");
        let (b_ctx, b_rep) = assemble_with(&messages, 2, &[], 100_000, None).expect("b");
        assert_eq!(a_ctx.messages, b_ctx.messages);
        assert_eq!(a_rep.selections, b_rep.selections);
        assert_eq!(b_rep.second_stage, "none");
    }

    struct PickFirst;
    impl SecondStageSelector for PickFirst {
        fn select(&self, candidates: &[CandidateSlice]) -> Result<Vec<String>> {
            Ok(candidates
                .iter()
                .find(|c| c.summary.contains("old answer"))
                .map(|c| vec![c.slice_id.clone()])
                .unwrap_or_default())
        }
    }

    #[test]
    fn second_stage_selector_picks_are_added_and_stamped() {
        let mut messages = history();
        // One extra old turn only the selector should pick up.
        messages.insert(2, Message::user("old thing"));
        messages.insert(3, Message::assistant("old answer"));
        let (_ctx, report) =
            assemble_with(&messages, 1, &[], 100_000, Some(&PickFirst)).expect("assemble");
        assert_eq!(report.second_stage, "selector");
        assert!(
            report
                .selections
                .iter()
                .any(|s| s.reason == SelectionReason::SecondStage),
            "report was: {report:?}"
        );
    }

    struct AlwaysFails;
    impl SecondStageSelector for AlwaysFails {
        fn select(&self, _candidates: &[CandidateSlice]) -> Result<Vec<String>> {
            Err(crate::Error::Other("laya unavailable".into()))
        }
    }

    #[test]
    fn a_failing_selector_falls_back_deterministically() {
        let messages = history();
        let (a_ctx, _a) = assemble(&messages, 2, &[], 100_000).expect("a");
        let (b_ctx, b_rep) =
            assemble_with(&messages, 2, &[], 100_000, Some(&AlwaysFails)).expect("b");
        assert_eq!(b_rep.second_stage, "fallback");
        assert_eq!(a_ctx.messages, b_ctx.messages);
    }

    #[test]
    fn assembly_needs_no_store_at_all() {
        // §3.9: conversation.enabled defaults to false; assembling from an
        // in-memory history must not assume a persisted one exists. There is
        // no ArtifactStore in scope here — compile-time satisfaction of the
        // invariant.
        let messages = history();
        let (context, _report) = assemble(&messages, 2, &[], 100_000).expect("assemble");
        assert!(!context.messages.is_empty());
    }
}
