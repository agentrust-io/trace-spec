# Policy-resolution vectors

Conformance vectors for one question: **when a record declares a policy bundle
digest and says where the bundle lives, does the bundle at that location
actually hash to what was declared?**

Until `TR-POL-003`, nothing asked. `policy.bundle_hash` and `policy.policy_uri`
are both merged fields on `policy`, and no module compared them, so a record
could name a bundle, declare a digest, and have the two disagree without any
check noticing.

## What each vector asserts

**One value: the status of the `TR-POL-003` finding.** That is narrower than a
verdict on the whole record, deliberately. These records are unsigned, so they
carry findings from other modules — `TR-SIG-005` has an opinion about every one
of them — and grading at record level would blur the check under test with
everything standing around it. Every claim about coverage in this file is a
claim about that one finding.

## Anchors: what each expected outcome derives from

Every vector names the text its expected outcome comes from, and says which
surface that text lives on.

| Tier | Surface | What it can ground |
|---|---|---|
| 1 | Merged prose in `agentrust-io/trace-spec` `spec/trace-v0.2.md` | A claim about what the specification requires |
| 2 | The packaged `schemas/trace-claim.json` | A claim about conformance to the schema this suite tests against |
| 0 | Nothing governs the case | Only a fact about the run itself |

The distinction matters because schema `description` text reads exactly like
normative prose and sits in the same repository as the vectors. It is not the
specification. Where a vector's outcome rests on tier 2, it says so rather than
implying an authority it does not have.

**`policy_uri` appears nowhere in the merged specification.** Every outcome that
turns on `policy_uri` semantics is therefore tier 2 or tier 0, and the two
unresolvable vectors are tier 0: no merged sentence says what a verifier records
when a policy bundle cannot be fetched. Those vectors assert only that the
comparison did not happen, which is a fact about the run rather than a reading
of any text. **The level at which that stops being tolerable is suite policy**,
registered in `src/trace_tests/modules/unverified.py` and `docs/levels.md`, and
is not claimed here as a specification requirement.

## The vectors

Every record is identical except for the `policy` block, so the defect under
test is the only thing that varies. `appraisal.policy_ref` is fixed across the
set and never varied: this set is about `policy.*`, and a second moving field
would blur which one a finding is answering. All records are unsigned and
ASCII-only.

| # | Vector | Boundary | `TR-POL-003` | Anchor |
|---|---|---|---|---|
| 01 | `01-no-policy-uri.json` | accept | `skip` | tier 2 |
| 02 | `02-resolved-and-matches.json` | accept | `pass` | tier 1 |
| 03 | `03-digest-mismatch-minimal-mutation.json` | contradicted | `fail` | tier 1 |
| 04 | `04-digest-mismatch-different-object.json` | contradicted | `fail` | tier 1 |
| 05 | `05-referent-unreachable-no-route.json` | unresolvable | `unverified` | tier 0 |
| 06 | `06-resolved-and-matches-sha384.json` | accept | `pass` | tier 1 |
| 07 | `07-digest-bound-to-other-referent.json` | contradicted | `fail` | tier 1 |
| 08 | `08-policy-uri-is-a-relative-reference.json` | malformed | `fail` | tier 2 |
| 09 | `09-sha384-bound-to-other-referent.json` | contradicted | `fail` | tier 1 |
| 10 | `10-policy-uri-carries-a-space.json` | malformed | `fail` | tier 2 |
| 11 | `11-referent-unreachable-route-fails.json` | unresolvable | `unverified` | tier 0 |

## Why the set is paired the way it is

`agentrust-io/trace-spec#186` (merged 2026-08-20) states the criterion a vector
set is claiming: *a verifier that does not implement these rules will fail this
set*. A set must fail **both** unconditional implementations, and one vector
cannot separate a check that reads a prefix from one that reads the whole
object. Every rule below therefore sits on at least two vectors, and each pair
can be told apart by a weakened variant of the rule that deviates one and leaves
the other undisturbed.

**01, 02 and 06 are the must-accept group.** A set written from the motivating
problem alone would be all rejections, and a verifier that rejected everything
would pass it. 01 is the backward-compatibility control: every conformant record
today declares no `policy_uri` and must keep verifying, or this set would be
proposing a breaking change rather than describing a gap.

**03 and 04 keep the contradicted boundary off a single vector.** 03 differs
from the declared object in exactly one byte — the SLSA floor moves 2 → 3, which
changes what the policy permits. 04 substitutes a different object of a different
length. A verifier comparing lengths, or sampling a prefix, passes one and fails
the other.

**06 and 09 are the sha384 pair.** The schema admits `sha384:` as well as
`sha256:`, so a verifier that hardcodes `sha256` is wrong rather than merely
limited. Deleting sha384 support turns both to `skip`. A verifier that computes
only `sha256` deviates 06 alone; one that accepts `sha384` without comparing —
the fail-open shape — deviates 09 alone. 06 by itself would not catch the second.

**08 and 10 are the malformed pair, and they are caught by different rules.** 08
is a `uri-reference` where the schema asks for the absolute form: no authority,
so nothing can dereference it. 10 is absolute and correctly schemed, with a raw
space in the path — a transcription accident that survives a diff unnoticed.
Removing the character rule deviates 10 alone; removing the scheme rule deviates
08 alone.

**05 and 11 are both unreachable, by different roads.** 05 cites a URI nothing
routes. 11 cites one the manifest maps to a bundle that is not there. A resolver
handling only a missing key would leave 11 reporting a comparison it never made,
and one handling only a missing file would do the same to 05. The finding
carries the resolver's exception text, so the two are distinguishable in a
report even though they share a status.

**07 is the one a well-formedness check passes.** The declared digest is a valid
`sha256:` digest and is the true digest of a real object in this set — just not
of the one `policy_uri` names. Both halves are individually valid; the pair is
not.

## Malformed references are found offline

`08` and `10` report the same failure with or without a resolver. That is the
check's ordering, and it is deliberate: **a reference the record got wrong is a
defect in the record**, visible with no network at all, exactly like the digest
shape `TR-POL-001` tests. A referent that could not be fetched is weather.
Running without `--policy-dir` means no spurious unverified findings; it does
not mean being blind to a defect the record carries on its face.

## Resolving the bundles

`resolutions.json` maps each cited URI to a path inside this directory. It is
the single mapping: a vector cannot hold a private idea of what its URI
resolves to. Two entries are deliberate holes — the URI cited by `05` is absent
from the manifest, and the one cited by `11` maps to a file that is not written.

```
trace-tests verify --record tests/vectors/policy-resolution/02-resolved-and-matches.json \
    --policy-dir tests/vectors/policy-resolution
```

The manifest is checked for *form* only when it loads: an object, string to
string, relative paths, no parent traversal. **Whether a mapped file is there is
not checked at load time.** Existence is a resolve-time fact, and a manifest that
refused to load because one bundle had gone missing would be the manifest-level
version of treating a lost referent as a wrong reference — the confusion this
whole set exists to keep apart.

## Reproducing it

```
python tests/vectors/policy-resolution/gen_policy_resolution.py
```

Deterministic: no keys, no clock, no randomness, no network. The digests are
computed over the exact bytes of the sibling files under `policies/`, so anyone
holding only this directory can recompute every number in the set.

`tests/test_policy_resolution_reproduces.py` holds the generator to
byte-reproduction by regenerating into a temporary directory and comparing —
not in place, which would compare the files to themselves and agree regardless.

The guard is **self-contained**. `agentrust-io/trace-spec#171` provides the
equivalent for that repository's `examples/`, and `trace-tests` has no such
registry; `agentrust-io/trace-tests#66` gives the reason not to reach across for
one — *"a guard that needs another repository checked out is a guard that gets
skipped."*

`.gitattributes` in this directory pins `eol=lf`. This is load-bearing rather
than tidy: with `core.autocrlf=true`, a checkout rewrites LF to CRLF, every
policy digest stops matching, and the set fails on a clean clone.

## What this set does not establish

- **Nothing here exercises a network fetch.** The resolver in every test reads
  bytes from disk. A redirect, a timeout, a TLS failure and a 404 all map onto
  the same unverified status by assertion rather than by measurement.
- **The unresolvable level is suite policy, not a specification requirement.**
  No merged sentence governs the case; `agentrust-io/trace-spec#190` tracks the
  open cross-surface question of what a verifier records when a citation cannot
  be resolved.

Both are recorded as exact shortfalls in
`tests/test_policy_resolution_completeness.py::KNOWN_SHORTFALLS`, which fails
if the list changes without this file changing with it.

## Related

- `agentrust-io/trace-tests#63` — the module proposal these cases were built for
- `agentrust-io/trace-spec#66` — where the resolution gap was raised
- `agentrust-io/trace-spec#190` — the open cross-surface question
- `agentrust-io/trace-spec#186` — merged: the adequacy criteria this set was
  built to. It grades trace-spec's `examples/`; this repository has no adequacy
  harness, so the standard is one this set chose, not one imposed on it
- `agentrust-io/trace-tests#66` — merged: `tr_sig` canonicalizes with RFC 8785;
  source of the self-containment principle quoted above
- `agentrust-io/trace-tests#74` — merged: the published error codes and record
  samples realigned with the modules, and the guard that keeps them that way
