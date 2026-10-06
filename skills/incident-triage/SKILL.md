# Incident triage

Work a failure from symptom to a bounded fix. Each step produces evidence that
the next step stands on, so the conclusion can be re-derived by someone else.

## What this skill is for

Something failed. You have an error, a stack, a failing test, a log, or a report
that "it doesn't work". The goal is not to make the symptom go away — it is to
establish why it happened, strongly enough that the fix addresses the cause
rather than the current instance of it.

## The rule that matters most

**A root cause you cannot demonstrate is a hypothesis.** Say "hypothesis" while
you are testing it, and only call it the cause once you can show the mechanism:
a specific input, a specific line, a specific reason it produces the observed
output.

The expensive failure in triage is a confident wrong diagnosis. It produces a fix
that appears to work — because the repro was flaky, or the symptom is
intermittent — and the real cause stays in the code.

## Method

### 1. Write down the observation, exactly

The literal error text, the exact command that produced it, the revision, the
environment. Not a paraphrase.

Paraphrasing is where triage goes wrong early: "the tests fail" becomes "the
tests fail because of a timeout", and from then on you are debugging a
conclusion instead of an observation.

### 2. Reproduce it, or establish that you cannot

Run it. A reproducible failure is worth more than any amount of reading, because
it lets you confirm a fix.

If you cannot reproduce it, say so immediately and find out why — different
environment, different data, an intermittent condition, a timing dependency. "I
could not reproduce" is a real result and often the key one: an intermittent
failure has a different cause than a deterministic one.

### 3. Narrow before you theorise

Cut the search space using evidence, not intuition:

- Does it fail at the same point every time?
- Does it fail with the input reduced to the minimum that still triggers it?
- Does it fail at an earlier revision?
- Does it fail when the suspected component is stubbed out?

Each of these answers eliminates a region of the code. Do this before proposing a
cause: a hypothesis formed before narrowing tends to be defended rather than
tested.

### 4. State the mechanism, then test it

Write the mechanism as a sentence connecting input to output through specific
code:

> The parser accepts a trailing comma, the collected list ends up with one extra
> element, and the length check two functions later rejects it.

Then design the cheapest test that distinguishes this from its alternatives. Run
it. Report what happened.

If the mechanism predicts something that does not happen, the hypothesis is dead
— discard it and say so. Do not patch the hypothesis to accommodate the
observation; that is how a wrong cause becomes unfalsifiable.

### 5. Fix the cause, with the smallest change that addresses it

Prefer the fix that makes the wrong state unrepresentable over the one that
checks for it. A guard added at the call site leaves the next caller free to make
the same mistake.

Say what the fix does **not** cover. A fix for one input path is not a fix for the
class.

### 6. Prove the fix, and prove the test

- Run the original reproduction. Report the exact command and result.
- Revert the fix and confirm the reproduction fails again. A test that passes
  both with and without the fix does not test the fix.
- State what you did not test.

## When to stop and say you do not know

Stop when the evidence does not distinguish between the remaining candidates, and
report the candidates plus the observation that would separate them. That is a
useful result: it tells the next person exactly what to look at.

Guessing to appear useful wastes more time than an honest "undetermined".

## Output format

```
Symptom: <the literal observation, and the command that produced it>
Reproduced: yes (<command>, <result>) | no (<why not>)
Mechanism: <input -> specific code -> observed output>
Evidence: <what distinguishes this from the alternatives>
Fix: <the change, and what it does not cover>
Verification: <command and result, plus the revert check>
Not established: <what remains unknown>
```

## Rules

- Never report a command's output you did not run. If you did not run it, write
  "not run".
- Never delete or weaken a failing test to make a suite green. That converts a
  visible failure into an invisible one.
- Do not restart a service, clear a cache, or delete state to make a symptom
  disappear before you know what caused it — you will have destroyed the
  evidence.
- One change at a time. Two simultaneous changes mean neither is proven.
