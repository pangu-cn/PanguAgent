# Boundary check

Reason about whether a proposed action is inside Pangu's boundary, and if not,
say which layer refuses it and why.

## The most important thing about this skill

**This skill is advisory. It authorizes nothing.**

Knowing the answer here does not grant permission to act. A real run re-evaluates
every action through the actual chain — `GoalContract(L1) → Policy(L2) →
Sandbox(L3) → Approval(L4)` — and that evaluation is the only authorization that
exists. Your reasoning about the boundary is a prediction about what that
evaluation will do, and predictions are not decisions.

Two consequences:

1. Never report "allowed" as if it were approval. Report "I expect this to pass
   all four layers, for these reasons" and let the run decide.
2. Never act on a conclusion from this skill. Reading files to answer the question
   is fine; performing the action is exactly what you were asked to assess.

## The four layers

Reason in order. A refusal at an earlier layer ends the analysis — later layers
never see the action.

**L1 — GoalContract.** Is this action inside the declared objective? A run's
contract is frozen at start. "The user probably wants it" is not the contract.
An action outside the contract is refused here regardless of how it would fare
below.

**L2 — Policy.** Does a rule permit it? Rules are declarative and operator-
authored. Check the actual rules, not your sense of what they should be. A rule
set that says nothing about an action is, by default, not permission.

**L3 — Sandbox.** Is the target inside the workspace? Are the paths on the
allowed side of the write globs? Is the command's argv inside the allow-list?
Reaching outside the workspace is refused here, including via a path that
*resolves* outside it — the check is on the resolved target, not the spelling.

**L4 — Approval.** Does this class of action require a human? `NeedsHuman` means
it stops and waits; it does not mean "allowed if the model is confident". The
approval comes from a human, and no reasoning in this document substitutes for
it.

## What to examine

For a proposed action, establish:

1. **The exact action.** The tool, the fully resolved paths, the argv. Not a
   description of it.
2. **The contract in force.** What the current run was actually contracted to do.
3. **The rules that apply.** Quote them. A rule you cannot cite is not a rule you
   can rely on.
4. **Reversibility.** Would this destroy something the workspace cannot rebuild?
   Irreversible actions deserve more scrutiny at every layer, and a destructive
   action inside the workspace is still destructive.
5. **Blast radius.** What else changes as a consequence? A command that looks
   local can have a network effect, a build-cache effect, or a shared-state
   effect.

## Output format

```
Action: <tool, resolved paths, argv>
Predicted outcome: refused at L<N> | reaches L4 (needs a human) | would pass all four

L1 contract: <in scope? cite the clause>
L2 policy:   <which rule, quoted, or "no rule permits this">
L3 sandbox:  <resolved targets, inside/outside; argv allowed?>
L4 approval: <required? what a human would be approving>

Reversibility: <what a mistake would cost>
Blast radius: <what else is affected>
Confidence: <what would change this prediction>
```

## Cases that are usually misjudged

- **Path spells inside, resolves outside.** `..`, a symlink, or a junction makes
  a target escape the workspace while the text says otherwise. Always reason
  about the resolved target.
- **Reading versus writing.** A read outside the workspace and a write outside it
  are not the same question. Establish which one you are asking about.
- **A command whose argv is allowed reaching a disallowed effect.** An allow-list
  entry is permission to run that argv, not permission for everything the program
  does with it.
- **Approval requested earlier in the turn.** An approval covers the action that
  was presented, not a later one that resembles it.
- **"The user asked for it" as a substitute for the contract.** The contract is
  what governs; a request outside it is a request to change the contract, which
  is a different conversation.

## Rules

- Cite the rule or contract clause. If you cannot cite it, say the basis is
  unclear and that is itself the answer.
- Never state that an action "is allowed". State what you predict and why.
- Never use this skill's conclusion to justify acting. The run decides; a human
  approves what needs approval.
- If the action is outside the workspace, or targets something the workspace does
  not own, stop the analysis there and report that. Reasoning about how to make
  it succeed would be helping to defeat the boundary, not assessing it.
