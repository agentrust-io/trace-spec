# Contributing with an agent

This page is for a contributor who works on a change with an AI agent, and for
the agent session itself, which can read it and follow it. It is the long form
of [Reviewing your own pull request](CONTRIBUTING.md#reviewing-your-own-pull-request).
Nothing here adds a condition for review.
[Before a pull request is reviewed](CONTRIBUTING.md#before-a-pull-request-is-reviewed)
says what the conditions are, and where a line below describes a check that CI
runs, CI holds it, not this page. The rule that governs all of it is the one in
[Using AI to contribute](CONTRIBUTING.md#using-ai-to-contribute): you have to
understand what you submit, with the agent closed.

In short: measure before you write, write only what was measured, read the
change three times with one question each time until a read changes nothing,
have it read by a session that has seen none of the work, and put what all of
that found in the description.

## Before anything is written

Read these before the first line of the change.

- `CONTRIBUTING.md`, the pull request template at
  `.github/PULL_REQUEST_TEMPLATE.md`, and `.github/CODEOWNERS`, which names
  who reviews each path. The template has a heading for the test that fails
  when a fix is switched off, and a review starts there.
- Every workflow under `.github/workflows/` whose path filter matches the
  files you will touch. Five run test files on a pull request, and each of
  the path-filtered ones also runs on a change to itself.
  `.github/workflows/ci.yml` has one job, `test`, on Python 3.11 and 3.12:
  lint, the dash check, the type check, the suite with coverage, the verifier
  context replay experiment, and a portability pass under a C locale that
  runs the conformance tests as well. `conformance-ci.yml` runs the
  conformance tests on 3.11, 3.12 and 3.13. `trust-record-verify.yml` runs
  the Node verifier under `trust-record-verify/` on Node 20, 22 and 24, and a
  differential job against the Python library, on a change under that
  directory, `schema/`, `spec/`, `examples/`, `src/agentrust_trace/` or
  `requirements/`, or to `pyproject.toml`. `runtime-evidence.yml` runs the
  appraisal test under `examples/runtime-evidence/` on a change under that
  directory or to `schema/trace-claim-v0.3-draft.json`,
  `docs/rfcs/runtime-evidence-profile.md` or
  `requirements/runtime-evidence.txt`. `review-bar.yml` runs the pull
  request's changed tests against the merge base on Python 3.12 and writes a
  job summary, on a change under `src/` or `tests/` or to
  `tools/review_bar.py`. A specification, schema or docs pull request has no
  summary. The summary is built from the tests the pull request itself
  supplies, and the tool's own docstring says its sorting can be wrong both
  ways, so read what it counted before quoting it. Two more run on a pull
  request without test files: `cflite_pr.yml` runs the fuzzers on a change
  under `conformance/`, `src/agentrust_trace/` or `.clusterfuzzlite/` or to
  `requirements/dev.txt`, and `conformance-package.yml` builds the
  conformance package on a change under `conformance/` and runs the built
  command once per distribution on one vector.
- `CONTRIBUTING.md` installs with `pip install -e ".[dev]"`, which resolves
  the dependencies afresh. CI installs from the hash-pinned lock, and a
  number you will quote is measured on CI's install:

  ```bash
  pip install --require-hashes -r requirements/dev.txt
  pip install --no-deps -e .
  ```

- Every issue, pull request and discussion the task names, one hop deep, and
  whatever each of them names as its own origin. What they settled you are not
  reopening. What they asked for you are answering. A reference you cannot
  reach is named in the description as not read.
- The documents that govern the code you will touch, which can be more than
  one. Some modules name theirs in the docstring:
  `src/agentrust_trace/citation.py` names section 3.1.2 of the specification,
  `src/agentrust_trace/revocation.py` section 3.2.3, and
  `src/agentrust_trace/provenance.py` the two server-provenance documents.
  `src/agentrust_trace/models.py` and `src/agentrust_trace/validate.py` have
  no docstring, and a change to either is checked against `spec/trace-v0.2.md`
  and `schema/trace-claim.json`, which the validator loads a packaged copy of.
  The provenance module says in its first lines that the record it verifies
  is deliberately not a Trust Record, and section 3.2.2 of `spec/trace-v0.2.md`
  says that record is canonicalized under it and that its range rule for whole
  numbers reaches it too. Find every governing document before writing, not
  the first.

## Measure before you write

- Every number that will appear in the description, a commit message or a
  comment is computed on the commit it describes, by a command you can name,
  with its unit: tests or cases, lines or occurrences, files or vectors. A
  number remembered from an earlier run is not a measurement. After an amend,
  measure again, since a run cited by its URL is pinned to the commit it ran
  on.
- Write the enumeration, not the category. "Rejects malformed input" cannot be
  checked. The list of values that were run can, and it cannot be wider than
  what was run. A count of cases names the cases.
- A negative claim says what was searched. "No test covers this" and "nothing
  emits this code" are claims about the whole suite, every fixture, and every
  interpreter the workflow for that path runs, with every skip listed
  (`pytest -rs` prints them) and explained. A sweep that skipped something
  without saying so is a hole, not a clean result.
- A check decides on one form of a value, and the consumer of the value may
  see another. Section 3.2.2 of `spec/trace-v0.2.md` decides whether a number
  is an integer by its value and not by its spelling, because a verifier whose
  parser returns only the value, as `JSON.parse` does, has no spelling to
  decide by. A check written on the spelling would reject what such a verifier
  accepts, over the same signed bytes. Before writing a check, say in which
  form the thing checked reaches its consumer, and write the check on that
  form.

## The change

- One behaviour is stated in several places, and an edit leaves one of them
  stale. The suite pins the two packaged copies of `schema/trace-claim.json`
  to it, `tests/test_validate.py` the library's copy as parsed JSON and
  `conformance/tests/test_packaged_schema_accepts_real_records.py` the
  conformance copy byte for byte, so those turn red when they drift, the
  library's only when the parsed JSON differs. It holds `docs/schema.md` to a
  row for every field, a mention of every enum and const value and, where a
  pattern admits several digest algorithms, a name for each, in
  `tests/test_schema_doc_coverage.py`,
  whose docstring says what it does not decide: whether a description agrees
  with the specification in any wider sense. Two tables are held tighter:
  `tests/test_build_provenance_depth_doc.py` and
  `tests/test_references_block.py` read the `build_provenance` and
  `references` rows and compare their required flags with the schema. A
  description wrong in any other way stays green. The README of the example
  set you touched, the docs page that describes the behaviour, `CHANGELOG.md`
  and the description are checked by nothing unless you find the test. List the
  surfaces that state the behaviour you changed and read each after the last
  edit, counts and names first.
- A change to prose is checked against the code that implements it. Find
  that code and run it against what the sentence now says. Three documents
  that agree with each other are one source, not three. If nothing implements
  the sentence, the description says so.
- A check that cannot decide reports that, and the value it reports is chosen
  on purpose. The library has two answers, each documented where it is used,
  and one function can give both. The profile, trust-anchoring and freshness
  checks of `sign.verify_record` fail closed, as its docstring says, and its
  revocation check, `_check_not_revoked`, treats a store that cannot answer
  as a rejection. The same function's revocation result is a value of its
  own, with the cause where there is one: `unverified_for_revocation` for a
  bundle it could not use, `no_check_performed` with neither bundle nor
  store, as a citation's `unresolvable` or `not_attempted` are. Pick one,
  point at the test that pins it, and never report a pass for something that
  was not checked.
- Name the class of input the tests did not feed before adding another case
  of the class they did. `tools/sweep_public_surface.py` prints what each
  public parameter accepts and is the place to start. A whole number written
  as a float, a key outside the Basic Multilingual Plane, a value of the wrong
  JSON type, a member the schema forbids: each has a test here now. The class
  that has none yet is the one to look for.
- A vector set added here is registered in `tests/test_adequacy_all_sets.py`,
  which holds every set to the same criteria and fails on a set it does not
  know, and is reproduced by its generator under
  `tests/test_generators_reproduce_fixtures.py`. Both run in CI.
- A check is itself something to check. One that has never been seen to fail
  has not been verified, so see it fail once before you cite it. The mutation
  runner for the conformance modules,
  `conformance/measurement/scripts/mutate_modules.py`, guards against five
  ways a run can report what did not happen: it runs the baseline first and
  stops if it is not green, verifies that every rewrite changed the file,
  aborts on an empty site list, checks that the import path is this checkout,
  and purges cached bytecode before every run. It carries no mutant that must
  be killed. A runner you write does those five and adds that one: a mutant
  that breaks the module outright and must be reported killed, or the run is
  void.
- Mutate toward the near-miss. Reverting your change and watching the tests
  fail shows that they are not vacuous, and nothing more. The useful mutant is
  the fix a careful reviewer would have written instead: the one that closes
  the issue as titled and looks right. The tests it fails are the tests that
  hold your fix in place, and they are the one thing about your change that a
  reviewer could not have known first.
- A part of the change you would describe as separable is carved out, or the
  description says why it stays.
- The files a session keeps for itself stay out of the diff: `CLAUDE.md`,
  `AGENTS.md`, `.cursorrules`, prompts and session notes. The repository
  carries none of the three, and this page is not one of them: it is the
  project's, written for every contributor and every session.

## The description

The description is the first thing a reviewer reads and the document the
review is written against. Write it last, from the measurements. The template
fixes the headings. Under the first one, "What this changes", put these, in
this order.

- What has no answer: what the change leaves alone and why, what could not be
  measured and why, the reference that could not be read.
- Which commit each number was measured on, with which command, on which
  interpreter. A test run has more outcomes than two: `skipped`, `xfailed`
  and `error` are each their own, and a skip is not a pass.
- What the Review bar's summary says, where the pull request has one, read as
  evidence: if its sorting of a failure is wrong, say what the message behind
  the count was.
- What the reader described under
  [The read by someone who has seen none of the work](#the-read-by-someone-who-has-seen-none-of-the-work)
  found, what you changed because of it, and what you did not change and why.

The test that fails when the change is switched off, by name, with the names
it adds kept, as
[Before a pull request is reviewed](CONTRIBUTING.md#before-a-pull-request-is-reviewed)
describes, goes under the template's own heading for it. If you ran the
near-miss, the tests it fails go there too.

## Reading your own change, in two layers

Layer 1 is mechanical. Everything that can be an assertion goes into a script
you keep outside the diff, with the rest of what
[What to keep](#what-to-keep) lists. Each assertion has a positive control, a
known-bad input it must fail on, because a check that cannot fail reports
nothing. Assertions worth having: none of the four dash characters
`tools/check_dashes.py` bans anywhere in the change, which CI already holds
outside the paths the tool exempts. Every quoted string exists,
verbatim, in the file it is attributed to. Every path and section reference
resolves. Every number stands beside the command that produced it. The counts
that appear in more than one surface agree. One shape for such an assertion:
every backticked path in the description exists in the tree, and the check
fails when handed a path that does not. Run the script after every edit. It
is finished when one run on the final bytes is clean. A second run on
unchanged bytes measures nothing.

Layer 2 is three reads of the whole change, each with one question, run once
each, in this order.

- A, correspondence. Every sentence maps to a source or a measurement, and a
  sentence with neither is cut or measured. For each measured claim, restate
  it with its quantifier and its domain explicit, then compare that domain
  with the one you ran. Where they differ, the sentence is the defect.
- B, adversarial. For each claim, the strongest true reply a reviewer could
  make, and whether the sentence survives it. Four fixed questions. Is the
  claim at the right level, normative text or description, docstring or
  behaviour? Do the specification, the schema, the model, the conformance
  checks, the docs, the CHANGELOG entry and the description state one rule?
  How did the repository handle the same shape last time? And when the text
  is a review of someone else's work, which of the author's technical
  statements does it agree with, each checked against the code?
- C, commitments. What the text binds you to, which sentence can be quoted
  back, and whether it claims more checking than was done.

Then the stop rule. A read that changed wording re-runs Layer 1. A read that
changed substance means B and then C run again. Stop after a read that changed
nothing, once all three have run. That read will be B or C. A read that did
not run is listed as not run. Saying that nothing changed is a claim about a
read, and it needs the read.

## The read by someone who has seen none of the work

A read by the session that wrote the change finds what that session can see.
The read that
[Before a pull request is reviewed](CONTRIBUTING.md#before-a-pull-request-is-reviewed)
asks for is by a new session, or another person, given the finished change
and none of the work behind it. It works only on a change that has stopped
moving, so it comes after the two layers above.

Give the reader the repository at the commit, the description, the diff, the
sources the description cites, and `CONTRIBUTING.md`. Give them nothing of
yours: not your notes, not your evidence, not your conclusions, which a reader
given them hands back as agreement. The description you give them carries
what an earlier reader found, so a later reader starts primed by it. That is
the cost of reading the description the reviewer will read. For a read
without it, hand over the description with that paragraph removed, and say so
in the description. Ask a reader's questions, not a checker's. A brief to
paste as the first message of the new session, with the three placeholders
filled:

```
You are reading a pull request as the reviewer who will decide on it, by the
rules in CONTRIBUTING.md. You have the repository at commit <sha>, checked
out at <path>, the pull request description at <path or URL>, the diff, and
the sources the description cites. You have nothing else from the author. Do
not modify anything, and do not post, comment, approve or open anything.
Report as a numbered list, the most serious point first, each point naming
the sentence it concerns and the evidence: a file and line, or a command and
its output.

1. For each claim in the description, the strongest true reply a reviewer
   could make, and whether the claim survives it. Check every technical
   claim against the code.
2. Every sentence that is false, imprecise, wider than what was measured, or
   unprovable from the diff.
3. Run the test the description names as failing when the change is switched
   off, with the change switched off, and report what happened. If the
   description names none, say so.
4. What the change leaves stale: a docs page, a README, CHANGELOG.md, a
   packaged copy, or a sentence elsewhere that still states the old
   behaviour.
5. What a hostile, competent reader would attack first, and how.
6. What you could not read or run, by name, and why.
```

What comes back is a set of claims. Re-run any measurement you act on. Take
neither the reader's wording nor the reader's numbers into the description
unchecked. Keep the raw output, and beside it your disposition of each point:
changed, already changed, or rejected with the reason. The rejected ones are
the ones a reviewer most wants to see. Then say in the description what the
reader found, what you changed, and what you did not change and why. A read
of a draft that then changed was a read of a different change, so run it
again on what moved.

## Reviewing someone else's change with an agent

The same method, with the direction reversed, whether what you write is a
comment or an approval. Four additions.

- Read the author's own words first: the description, every reference it
  names, and the thread. A finding the author already made is not a finding,
  and a question the author already answered is not a question.
- Quote before disputing. Paste the sentence being disputed beside the claim
  that it is wrong, from the source and not from a summary of it.
- Mutate toward the near-miss, as above. If the author ran the revert, it
  showed that the tests are not vacuous. The fix that looks right and is
  narrower is the one that measures them.
- Ask what the code reports when it cannot decide, before anything else in
  the diff is read. If the answer is a pass, that is the first finding.

What a pull request approval does here is set by
`.github/workflows/require-maintainer-approval.yml`: at least one approving
review of the head commit by a maintainer other than the author. What the
project means by Approval is in `GOVERNANCE.md`. This page adds nothing to
either. What a reviewer can do before approving is check each technical
statement in the description against the code, the negative ones first:
"nothing in the codebase does X" is a claim about everything that was
searched, and it is only as wide as the search.

## What to keep

The list of checks, in two halves: what was run, with one line on what each
found, and what was not run, with why. The reader's raw output and your
dispositions. The description carries the summary of both. The rest stays
outside the diff, where you can produce it when asked.
