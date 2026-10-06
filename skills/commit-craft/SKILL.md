# Commit craft

Write a commit that a stranger can use six months from now, when the context is
gone and the only remaining evidence is the message and the diff.

## What a commit message is for

Not a changelog entry. Not a status report. It answers three questions for
someone who was not there:

1. **What changed**, in terms of behaviour or structure — not "updated file x".
2. **Why**, including the alternative that was rejected, if it is not obvious.
3. **What was verified**, distinguished from what was not.

A message that restates the diff file by file answers none of these: the reader
can already see the diff. What they cannot see is the reason.

## Method

### 1. Establish what actually changed

Read your own diff before writing. Not what you intended to change — what is in
the index. Unintended changes are common and are exactly what a reader will
stumble over.

### 2. State the change in behaviour terms

- Poor: "update the parser"
- Better: "accept a trailing comma in list literals, which previously produced a
  confusing arity error two functions later"

The second version tells the reader what is now different from their point of
view, and names the symptom that motivated it.

### 3. Give the reason, including the rejected option

If there was a choice, say why this one. "Used a BTreeMap so acquisition order is
deterministic and two lockers cannot deadlock" is the kind of sentence that stops
someone from "simplifying" it back into a deadlock six months later.

If a constraint drove the design, name the constraint. A structure that looks
over-built is usually protecting against something the author knew and the reader
does not.

### 4. Separate verified from unverified

- What you ran, and its result: the exact command, and the number.
- What you did not run: say so, and say what the next step would be.

"A clean build is not evidence for an unbuilt file" is the practical version of
this: a check that did not compile the code you changed proves nothing about it.
State what was actually exercised.

### 5. Reference the identifier

Where a project uses identifiers (an issue, a specification section, an ADR),
reference them. In this repository the commit subject is
`<ID>: 中文标题（要点）`, and a code change without the matching documentation
change is drift (`docs/BOUNDARY.md` §7).

## What not to write

- **A summary of the diff.** The reader has the diff.
- **"Fixed a bug."** Which bug, how it manifested, what it affected.
- **"Refactored."** Which structure, and what it buys.
- **Tests I claim to have run but did not.** Never. A commit message asserting a
  result that was not observed is a false record, and it is worse than silence
  because it is trusted.
- **Hedged claims**: "should work", "probably fine". Either you checked or you did
  not.

## Output format

```
<ID>: <short imperative title>

<What changed, in behaviour or structure terms.>

<Why this way. The rejected alternative, if any. The constraint that drove it.>

<Verification: exact commands and results. Then, explicitly, what was not run.>

<References: issue, spec section, ADR.>
```

## Rules

- Never assert a command result you did not observe. Write "not run" instead.
- One commit, one change. A commit that does two things cannot be reverted for
  one of them.
- Do not include credentials, tokens, or private paths in a message. Assume the
  message is the most-read, most-copied, most-indexed artifact in the repository.
- If the change is not yet verified, either verify it or say plainly that it is
  unverified. Do not let the format imply verification.
