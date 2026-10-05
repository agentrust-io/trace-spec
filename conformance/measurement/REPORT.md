# Does `trace-tests` notice when its own conformance checks break?

**Measured** 2026-08-07 against `agentrust-io/trace-tests` @ `7fc189c` (release 0.4.1),
with the normative schema from `agentrust-io/trace-spec` @ `dc7491c`.

`trace-tests` is the suite an implementer runs to establish that their TRACE
implementation conforms. Its output is a conformance claim. That makes a question one
level up worth asking, and as far as the repository shows, unasked so far:

> If a check inside a conformance module silently stopped working, would the
> repository's own test suite catch it?

When this was first measured, the answer was no for ten of the thirty-three failure
paths. Those ten are now guarded, and the measurement is what established which ones
needed it.

---

## Result

```
modules   7        src/trace_tests/modules/tr_*.py
checks    18       distinct TR-xxx-nnn codes
sites     33       Finding(..., Status.FAIL, ...) constructions

by check   18 of 18 verified,  0 unverified
by site    33 of 33 verified,  0 unverified
```

Eight checks sit at margin 1, meaning exactly one test stands between them and silent
regression. That is a floor, not a comfortable state, and it is the number to watch.

### What the first measurement found

| Check | What it enforces | Sites then unverified |
|---|---|---|
| `TR-SIG-002` | `cnf.jwk` is an OKP/Ed25519 key and carries `x` | 2 of 2 |
| `TR-TXN-001` | `tool_transcript` is present at Level 2, is an object, and its hash is a well-formed digest | 3 of 3 |
| `TR-TXN-002` | `tool_transcript.call_count` is a non-negative integer | 1 of 1 |
| `TR-SCA-001` | `build_provenance` is an object | 1 site |
| `TR-SIG-004` | `cnf.jwk.kty` is a supported key type | 1 site |
| `TR-SIG-005` | a signature that cannot be checked fails rather than going unverified | 1 site |
| `TR-ANC-001` | a transparency URI that cannot be parsed fails cleanly | 1 site |

`tr_txn` and `tr_sca` had no unit tests at all, which is why every one of their failure
paths measured zero. `TR-TXN-001` carried the most weight: it is the Level 2 requirement
that a tool transcript exist, and nothing else in the suite enforced it.

**Counting by check understates the problem by more than threefold.** A check code emitted
from three places can have one failure path nothing verifies while the other two are
covered, and still count as verified. The sites are where the checks actually live.

`TR-TXN-001` carries the most weight. It is the Level 2 requirement that a tool
transcript exist at all. If it regressed, implementations would continue to be stamped
Level 2 conformant without that property being checked — and the transcript is the claim
Level 2 is largely about.

`TR-SIG-002` is the gate that rejects a key that is not Ed25519. With it inert, a record
carrying another key type reaches signature verification rather than being refused at the
key-type check.

### Seven further failure paths inside otherwise-verified checks

`TR-ANC-001`, `TR-SCA-001`, `TR-SIG-004` and `TR-SIG-005` each have at least one site at
margin 0 while other sites of the same code are verified. Those are the paths a
by-code count cannot see.

### Margin is thin where it exists

Twelve sites are held by exactly one test. That is the same no-margin property reported
for the `trace-spec` fixture set in agentrust-io/trace-spec#124, in the repository whose
output is the conformance stamp rather than in the informative fixture set.

---

## A separate finding: a hand-written enum has drifted

`tests/test_level0.py:7` defines `VALID_PLATFORMS` as a set literal restating the schema's
`runtime.platform` enum. It holds nine values; the schema holds ten. `software-only` is
missing.

The conformance module is correct — `tr_rte.py:_VALID_PLATFORMS` has all ten — so this is
a defect in the self-test, not in what implementers run. Three-way comparison on a Level 0
record carrying `software-only`:

```
tr_rte.check(record, level=0)   PASS      (what an implementer runs)
normative schema                accepts
tests/test_level0.py            FAIL      (contradicts both)
```

It is latent: no vector in `tests/vectors/` uses `software-only`, so nothing triggers it
today. It becomes active the moment one does — and it would then reject behaviour the
project deliberately added, in PR #16/#17, which updated the conformance module and added
`tests/test_software_only_platform.py` while leaving this copy behind.

---

## Method

For every `Finding(..., Status.FAIL, ...)` construction in the conformance modules, rewrite
that site so the check can never fail, run the entire suite, count how many tests notice,
restore. The count is the margin. Zero means the check's failure path is unverified.

### The cheap version gives the wrong answer

The obvious first approach is to grep the test files for `TR-xxx-nnn` codes and diff
against what the modules emit. On this tree it reports **12 unverified checks**. Mutation
reports **3**.

The proxy is wrong because tests exercise a module through `tr_xxx.check(...)` and assert
on the returned findings without naming the codes. Naming is a convention; changing outcome
is the property. The two are not related closely enough to substitute one for the other.

### Guards, each of which produced a wrong answer during development

- **A green baseline is a precondition.** Mutating an already-red suite attributes nothing.
  The script runs the baseline first and aborts if it is not green.
- **A mutation that did not apply is indistinguishable from a check nothing notices.** Each
  rewrite is verified to have changed the file before the suite runs. An earlier hand-run
  of this measurement replaced a string that did not occur in the target, left the suite
  green, and would have been recorded as evidence for the opposite of the truth.
- **An empty site list would report perfect coverage.** Zero sites is a hard stop.
- **Restoration is verified**, not assumed, after every site.
- **A suite that did not run against this code looks exactly like a suite that notices
  nothing.** A stale editable install, or any `trace_tests` earlier on `sys.path`, leaves
  the baseline green and every mutation unobserved: pytest never imports the file being
  rewritten, so the run reports zero verified. The import path is resolved and checked
  against this checkout before the baseline runs.
- **A stale `__pycache__` reports a margin the code does not have.** `Status.FAIL` and
  `Status.PASS` are the same length, so a rewrite changes no file size, and a run can end
  up measuring the previous iteration's bytecode. This is the worst of the guards to be
  missing, because it fails *upward*: the previous iteration's failures are attributed to
  the site under mutation, margins come out larger than they are, and a check held by
  exactly one test is reported as comfortably covered. Caches are purged before every
  suite run. Without the purge, four consecutive runs on one unchanged tree reported the
  margin-1 watch list as empty three times and as two entries once; the list has eight
  entries. A fourth run also left `pytest` failing on 14 tests against a tree `git status`
  reported as clean.
- **An empty path is rejected before it can look valid.** `Path("")` is `.`, which is a
  directory, so the obvious existence check passes and the script measures whichever tree
  it happens to be standing in. The enum comparison had exactly this hole and reported
  success having compared nothing — the failure it exists to find, in itself. It now
  refuses an empty argument, and refuses to report agreement when zero comparisons were
  made.

---

## What this does not establish

- **Not that implementations can skip these checks.** The measurement is about whether a
  regression *in the conformance module* would be caught by `trace-tests`' own suite. An
  implementation still faces whatever the module does today.
- **Not that the unverified checks are wrong.** They may be perfectly correct. They are
  unguarded, which is a statement about the suite, not about them.
- **Only `Status.FAIL` sites were mutated.** `PASS` and `SKIP` paths were not, so a check
  could pass for the wrong reason in a way this does not see.
- **The margin is a count of failing tests, not of independent tests.** Five tests that
  fail together because they share a fixture are one test for this purpose, and this
  measurement does not distinguish that.
- **Nothing here was reported upstream at the time of writing**, and nothing in
  `trace-tests` was modified. Every mutated source file is restored, and the restoration
  is verified, after every site. Restoring the *file* is not the same as leaving the
  checkout usable: until caches were purged between runs, a completed run could leave
  `pytest` failing against a tree `git status` reported as clean, because the interpreter
  was still loading bytecode compiled from a mutated source. The cache purge above is what
  makes "restored" mean what it reads as.

---

## Reproducing

```bash
pip install -e ".[dev]" && pytest -q          # expect 161 passed, 5 xpassed

python measurement/scripts/mutate_modules.py  # exits 1 if any check is unguarded
python measurement/scripts/enum_drift.py      # exits 1 on any drifted enum
```

Both default to the checkout they live in, derived from the script's own location rather
than the working directory, and accept an explicit path as `argv[1]`. Both exit non-zero
rather than reporting success over a corpus they could not find.
