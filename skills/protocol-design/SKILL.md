# Protocol design

Design a wire format or interface that someone else can implement against
without asking you questions — including what happens when things go wrong.

## The test to design against

> **Could a competent stranger implement this from the document alone, and
> interoperate with an implementation they never saw?**

If any part requires reading your source, the specification is incomplete. If two
readers would build implementations that disagree, the document is ambiguous, and
ambiguity is a defect that surfaces later as an interoperability bug.

## Method

### 1. Specify what it is for, and what it is not

State the problem and the boundary. A format used for two purposes will be wrong
for one of them. Saying "this is not a transport for large payloads" prevents the
first person who needs one from extending this instead of choosing something
suitable.

### 2. Fix the encoding precisely

Byte-level or shape-level, unambiguously:

- Field names, types, presence (required / optional / defaulted).
- What "optional" means: absent, present-and-empty, and present-and-null are three
  different things. Choose and say which.
- Ordering: is it meaningful, guaranteed, or irrelevant? If a list is ordered,
  say whether a consumer may depend on it.
- Integer widths and overflow behaviour. Duplicate keys. Encoding of text.
- For binary: framing, byte order, alignment.

### 3. Decide versioning before you need it

- How does a consumer detect the version?
- What may a producer change without a version bump?
- What must a consumer do with a version it does not know?

The **fail-closed** answer is usually right: an unknown version is refused, not
parsed hopefully. Reading a future format with today's assumptions produces a
result that describes the wrong document, which is worse than an error.

### 4. Decide unknown-field behaviour, explicitly

Two legitimate answers:

- **Reject**: `deny_unknown_fields`. The format is closed; extensions require a
  version bump. Good when the fields carry meaning that a partial implementation
  would get wrong.
- **Ignore**: forward-compatible. Good when extensions are additive and a partial
  implementation is still correct.

Either is fine. Leaving it undecided is not: the two implementations will differ,
and neither is wrong.

### 5. Design the error path

This is the half people skip, and it is the half that determines whether the
protocol is usable.

- What does a receiver do with malformed input? Distinct error, or connection
  close? For which inputs?
- Is an error distinguishable from an absence of data? "No result" and "the
  request failed" are different facts and must not share a representation.
- Are errors retryable? Say which, and why. Retrying a non-idempotent operation
  after a timeout that was actually a success is a classic data-corruption bug,
  so state idempotency per operation.
- What happens on a partial read, a truncated frame, an oversized message?
- Is the error's text for a machine or a human? If a caller must branch on it,
  it needs a stable code.

### 6. State the security properties

- What is authenticated? What is only integrity-protected? What is neither?
- Does a receiver trust an identifier the sender supplies, when that identifier
  grants access to something? If so, say so, loudly — that is a design decision
  with consequences.
- Are there unbounded fields? A length that the receiver allocates from is an
  invitation.

### 7. Say what it does not guarantee

The honest limits: what is not covered, what a hostile peer can do, what the
format cannot detect (a consistently rewritten message with no external anchor,
for instance). A stated limit is a documented boundary; an unstated one is a
surprise.

## Worked example shape

```
Name:      <name>/<version>
Purpose:   <problem> — NOT <nearby problem it does not solve>
Encoding:  <byte-level or shape-level, unambiguously>
Presence:  required | optional(absent) | optional(null) — each defined
Ordering:  <meaningful | guaranteed | not relied upon>
Versioning: <how detected; unknown version => refuse>
Unknown fields: reject | ignore — and why
Errors:    <malformed input>, <distinguishable from no-result>, <idempotency>
Limits:    <every bounded field and its bound>
Security:  <authenticated / integrity-only / neither; trusted identifiers>
Not guaranteed: <the honest list>
```

## Rules

- Never define a field as "optional" without saying which of the three meanings.
- Every variable-length field has a stated bound, on the receiving side.
- Never let "error" and "no data" share a representation.
- State idempotency per operation, not per protocol.
- Write the failure cases down. A protocol specification that only describes the
  success path is half a specification.
