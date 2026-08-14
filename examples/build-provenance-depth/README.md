# build_provenance verification depth vectors

Spec section 3.3 step 7 requires that "SLSA provenance resolves to a trusted builder".
It does not say how far the verifier walks, and three stopping points satisfy that
sentence today:

1. **`surface`** — `build_provenance.digest` matches the artifact, `builder` is in a
   trusted set.
2. **`builder`** — also resolve `provenance_uri` and check the attestation binds to
   that digest and names that builder.
3. **`transitive`** — also walk the build inputs in `resolvedDependencies` to a
   publisher attestation for each one.

**Status.** These vectors are informative and encode no accepted requirement; no text
here carries an uppercase RFC 2119 keyword.
[#50](https://github.com/agentrust-io/trace-spec/issues/50) has since resolved, so the
names above are now the `build_provenance.provenance_depth` wire values rather than the
descriptive ones this directory first used. That was a rename; the separations it
encodes did not change. The normative rules are in
[docs/verification.md](../../docs/verification.md), and this directory is what a
conformance runner executes against them.

**Two outcomes, kept apart.** A depth can be unreachable for two different reasons and
they are the same event only to a verifier that never fetched the evidence:

- **Evidence does not resolve** — no `provenance_uri`, a URI that 404s, a build input
  with no publisher attestation. The check never ran. The verifier records the depth it
  *did* reach in `appraisal.provenance_depth_verified` and names the missing evidence in
  `unresolved`. The record is not at fault and is not rejected for it.
- **Evidence resolves and contradicts** — an attestation naming a different subject or a
  different builder, a build input signed under an untrusted issuer. The check ran and
  the record is wrong. It rejects, and no shallower reading makes that go away.

Whether the appraisal is then *accepted* is a separate question from depth: a deployment
profile with a floor of `transitive` rejects a `verified_depth` of `builder` on the floor,
not on the evidence. Depth records what happened; the floor decides what is enough.

## What these add

A vector that all three depths reject separates nothing: any verifier strict enough to
reject it passes, whatever depth it stopped at. Existing negative vectors are that kind
by construction, and they are the kind an implementer writes unprompted.

Each vector here **passes the depth below it with nothing to report, and the depth in its
filename is the first one that says something** — a rejection, or a `verified_depth`
lower than the one attempted. Run the set and a verifier's stopping point is visible in
its own output, which is the property that makes two verifiers' disagreement diagnosable
rather than just observable.

| Vector | `surface` | `builder` | `transitive` | Separates on |
|---|---|---|---|---|
| `01-all-depths-accept` | accept | accept | accept | — (control) |
| `02-…-attestation-subject-mismatch` | accept | reject | reject | attestation names a different subject |
| `03-…-attestation-builder-mismatch` | accept | reject | reject | attestation names a different builder |
| `04-…-dependency-unattested` | accept | accept | accept, verified `builder` | a build input has no publisher attestation |
| `05-…-dependency-publisher-untrusted` | accept | accept | reject | an input's attestation was signed under an untrusted issuer |
| `06-…-resolved-dependencies-absent` | accept | accept | accept, verified `builder` | the attestation declares no build inputs at all |

`04` and `06` are the vectors that separate a boundary without rejecting anything, and
they are why separation is defined over everything the verifier reports rather than over
rejections. Their evidence never resolves, so a verifier that walks the dependencies
learns only that it cannot finish — and says so, by recording `builder` and naming the
missing evidence. A verifier that stopped at `builder` records `builder` too, but with an
empty `unresolved`: it never looked. That difference is the separation. `05` is the
neighbouring case where evidence *does* resolve and refutes the record, so it rejects.

`01` is load-bearing in the way a positive control is: without it the set is satisfied
by a verifier that rejects unconditionally, and every separation below it means nothing.

Two vectors per boundary, on two different defects, is deliberate. One vector per
boundary has no margin — a single implementation shortcut that happens to catch that one
defect passes the whole boundary. `02` and `03` both sit at `surface` → `builder`: a
verifier that checks the subject but never compares the builder inside the attestation
passes `02` and fails `03`. `04`, `05` and `06` sit at `builder` → `transitive`:
presence of an attestation, trust in who signed it, and whether there was anything to
walk are three different implementations, and `06` is the one that catches a verifier
whose dependency loop accepts vacuously over an empty list — that verifier records
`transitive` where the honest answer is `builder`.

`02` is also the vector for the shortcut of comparing truncated digests. Its mismatching
subject digest shares the leading 12 hex characters with the real one — the prefix
container tooling displays — so a verifier comparing short IDs still has to reject it.
That digest is constructed rather than derived for exactly this reason. The three
dependency digests are `sha256("trace-spec/build-provenance-depth/" + purl)` over the
decoded package URL — `pkg:npm/@example-org/agent-core@1.8.2`, not the `%40` form the
`resolvedDependencies` entry carries — so they regenerate from the file itself. The
artifact digest the six vectors share is a fixed constant and derives from nothing.

## What each vector carries

- `build_provenance` — the record fragment under verification. These files are not TRACE
  Trust Records and are not validated against `schema/trace-claim.json`.
- `context.artifact_digest` — the digest of the artifact the verifier independently has.
  Surface verification is the comparison against this, not a self-comparison.
- `context.trusted_builders`, `context.trusted_publisher_issuers` — the verifier's trust
  configuration, so trust decisions are inputs rather than assumptions.
- `context.attestations` — what `provenance_uri` resolves to, keyed by URI, so the set
  runs offline.
- `context.dependency_attestations` — publisher attestations keyed by package URL, plus
  the `verified_identity` a Sigstore bundle verification would have established.
- `expected` — the verdict at each depth *attempted*, keyed by the `provenance_depth`
  wire values. Depths stack, so a deeper depth carries every finding the shallower depths
  made. Each block holds four fields:
  - `outcome` — `accept` or `reject`. Set by `failures` alone.
  - `verified_depth` — what belongs in `appraisal.provenance_depth_verified`: the depth
    the verifier reached. Never deeper than the one attempted, and one level below any
    depth whose evidence did not resolve.
  - `failures` — evidence that resolved and contradicts the record.
  - `unresolved` — evidence that never resolved, so the check could not run. This is what
    caps `verified_depth`; it is not a finding against the record.

## What there is deliberately no vector for

**Signature validity.** Every vector assumes signature verification already succeeded.
A bad signature rejects at every depth, so it cannot separate them, and `verified_identity`
carries the result rather than the bundle. What varies here is *binding* — subject,
builder identity, per-input publisher — which is where a shallower verifier accepts
silently rather than loudly.

**The absent and unresolvable `provenance_uri`.** Both downgrade to `surface` rather than
rejecting, and both are cases an implementer writes without prompting.
`tests/test_build_provenance_depth_vectors.py` exercises them by mutating the accepting
control, so they are covered without diluting the fixture set with the obvious. The
mutation pair is worth reading even so: the same control, mutated two ways, rejects when
the evidence contradicts and downgrades when the evidence is merely absent. That contrast
is the distinction in one screen.

## Running them

```bash
pytest tests/test_build_provenance_depth_vectors.py
```

The test module carries a reference verifier parameterised by depth. It asserts each
vector's verdict at each depth, and separately asserts the properties that keep the set
honest as it changes: verdicts are monotone over depth, no verifier records a depth
deeper than it attempted, a downgrade always names the evidence that caused it, every
boundary keeps two vectors separating on distinct defects, every rule is load-bearing
(delete it and some fixture stops matching), and no rule is exercised by declaration
alone.

The second and third of those are the machine-checkable half of a rule `docs/verification.md`
has to state in prose: a record is byte-identical whether the verifier walked the chain or
merely said it did, so no JSON Schema can hold *"MUST NOT record a depth higher than
executed"*. A conformance runner can hold it, against its own output.

An implementation in another language runs the vectors directly: read `build_provenance`
and `context`, verify at each depth, compare against `expected`.
