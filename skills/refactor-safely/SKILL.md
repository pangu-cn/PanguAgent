# Refactor safely

Change structure without changing behaviour. The deliverable is a sequence of
small steps, each verifiable on its own, ending with evidence that behaviour is
unchanged.

## The central claim

A refactor asserts: **behaviour is identical; only its arrangement changed.**
That assertion is falsifiable, and this skill is about making it checkable
instead of asserted.

The failure mode is a refactor that quietly changes something — an error message,
an ordering, a default, a short-circuit — and passes review because the diff
"looks like" a restructure. So: name the observable behaviour *before* you touch
anything.

## Method

### 1. Write down the behaviour you are preserving

Not "it works" — the specific observables:

- outputs for given inputs
- error types and messages on the failure paths
- ordering, where anything downstream could depend on it
- side effects: what gets written, logged, called

This list is the specification you will check against. Without it, "behaviour
unchanged" has no content.

### 2. Establish a baseline you can compare against

Capture current behaviour: run the tests and record the exact command and result.
For anything the tests do not cover, capture the output directly.

If there are no tests over the code you are about to move, that is the first
finding. Either write characterisation tests first, or state clearly that the
refactor is unverified — and consider whether that is acceptable.

### 3. Take one step at a time, verifying each

A step should be small enough that if it breaks something, you know which step
did it. Verifying after each step is what makes the final claim supportable; a
refactor done as one large change and tested once at the end cannot tell you
where a behaviour change came from.

Prefer mechanically checkable steps:
- rename, then recompile
- extract a function, then recompile and re-run
- move a file, then recompile
- change one caller at a time

### 4. When behaviour must change, stop and say so

Refactors surface things that were wrong. Discovering that an error path is
unreachable, or a parameter is always the same value, is a finding — not licence
to change it inside the refactor.

Make the refactor, then make the behaviour change as a **separate, clearly
labelled** change. Mixing them means the behaviour change is reviewed as if it
were a restructure, which is exactly when it gets missed.

### 5. Confirm, then state the residual risk

Check the baseline list from step 1 against the result. Report the exact command
and its output.

Then state what you could not verify: uncovered paths, behaviour observed in
production you have no way to test, callers outside this repository.

## What a safe refactor looks like in review

- The diff is readable as a sequence of mechanical steps.
- Behavioural assertions are backed by a command someone can run.
- Any behaviour change is in a separate commit, labelled as one.
- Documentation describing the moved thing is updated in the same change — in
  this repository, a code change without its doc change is boundary drift
  (`docs/BOUNDARY.md` §7).

## Output format

```
Preserved behaviour: <the specific observables>
Baseline: <command> -> <result>
Steps:
1. <mechanical change> — verified by <command> -> <result>
2. ...
Behaviour changes found: <none | what, and where they were moved to>
Residual risk: <what is not covered>
```

## Rules

- No behaviour change inside a refactor. Separate change, separate commit.
- Do not touch tests to make them pass. If a test breaks, either the refactor
  changed behaviour (fix the refactor) or the test was asserting the old
  structure (say so explicitly, and justify the test change on its own merits).
- Do not mix a refactor with an unrelated fix, however small. The combination is
  what makes both unreviewable.
- If you cannot verify a step, say which step and why. An unverifiable step is
  the one to split further.
