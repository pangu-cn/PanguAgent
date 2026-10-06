# Diff review

Review a change set. The output is a set of findings, each tied to evidence you
actually read, plus an explicit list of what you could not check.

## What this skill is for

A change set arrives with a claim: "this fixes X", "this is a refactor", "tests
pass". Reviewing it means establishing which parts of that claim you can verify
from the files, which parts you must take on trust, and which parts are false.

The failure mode this skill exists to prevent is a review that *sounds*
thorough. Prose that restates the diff, hedged with "seems correct", is worse
than no review: it consumes the reader's attention and returns nothing they can
act on.

## Method

### 1. Establish the claim before reading the diff

Read the commit message, the MR description, or whatever states the intent. Write
the claim down as one sentence. You need it first because a diff read without it
has no criterion — any change can look reasonable in isolation.

If no claim is stated, say so and treat "no stated intent" as the first finding.
Do not invent the intent from the code and then review against your invention.

### 2. Read the diff, not a summary of it

Read the actual changed files. A summary of a diff is someone else's reading of
it, and their reading is exactly what is under review.

For each changed file, note:
- what it did before, and what it does now
- whether the change is inside the file's stated responsibility

### 3. Check the claim against the code, one clause at a time

For "fixes X": find where X was broken and confirm the change actually addresses
that. A change that makes X stop happening *for a different reason* is not a fix;
it is a new behaviour that happens to hide the symptom. Say which one it is.

For "refactor": confirm behaviour is unchanged. A refactor claim is falsified by
any behaviour difference, including error messages and ordering.

For "tests pass": run them if you can, and report the exact command and its
result. If you cannot run them, say that — do not report a test result you did
not observe.

### 4. Look specifically for these

- **Scope creep**: changes unrelated to the stated claim. These are the hardest
  to review and the easiest to hide, so name them even when each is individually
  fine.
- **Silent behaviour change**: a default, an error path, an ordering, a
  short-circuit. Compare the before and after, not the after alone.
- **Test that cannot fail**: a test asserting something that was already true, or
  whose assertion never runs. Check that the test fails if you revert the change.
- **Documentation drift**: the change alters behaviour but not the doc that
  specifies it. In this repository that is boundary drift and is a finding, not a
  nitpick. See `docs/BOUNDARY.md` §7.
- **Claim stronger than evidence**: a commit message asserting more than the code
  shows.

### 5. State what you did not check

Close with an explicit list. "I did not run the tests." "I could not read the
generated file." "I did not verify the claim about the upstream dependency."

An unstated gap reads as coverage. The list is the difference between a review
someone can rely on and one they cannot.

## Output format

```
Claim: <one sentence, as stated — or "none stated">

Verified:
- <finding>, evidenced by <file:line or command output>

Findings:
1. <what is wrong or unproven> — <evidence> — <severity: blocks / should fix / note>

Not checked:
- <what you did not examine, and why>
```

## Rules

- Every finding cites evidence you read. No finding is "the code is complex".
- Do not edit the change set. This is a review; the author decides what to do.
- Do not approve. You can report that you found nothing wrong, which is different
  from approving — approval is a human decision made outside this skill.
- If the change set is too large to review honestly, say so and review the part
  you can, naming what you left out. A partial review that says it is partial is
  useful; one that implies completeness is not.
- Severity is about the change, not about your confidence. "Blocks" means the
  change should not land as written, and you can say why.
