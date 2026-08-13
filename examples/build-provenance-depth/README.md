# build_provenance verification depth vectors

Spec section 3.3 step 7 requires that "SLSA provenance resolves to a trusted builder".
It does not say how far the verifier walks, and three stopping points satisfy that
sentence today:

1. **Surface** — `build_provenance.digest` matches the artifact, `builder` is in a
   trusted set.
2. **Builder-chain** — also resolve `provenance_uri` and check the attestation binds to
   that digest and names that builder.
3. **Dependency-chain** — also walk the build inputs in `resolvedDependencies` to a
   publisher attestation for each one.

**Status.** These vectors are informative and encode no accepted requirement. The depth
question is [#50](https://github.com/agentrust-io/trace-spec/issues/50), labelled
`policy: take-internal`; nothing here anticipates its outcome. The names `surface`,
`builder_chain` and `dependency_chain` describe where verifiers stop today, not a
proposed enum — if the internal outcome names the levels differently, the names in this
directory change and the separations they encode do not. No text here carries an
uppercase RFC 2119 keyword.

## What these add

A vector that all three depths reject separates nothing: any verifier strict enough to
reject it passes, whatever depth it stopped at. Existing negative vectors are that kind
by construction, and they are the kind an implementer writes unprompted.

Each vector here is **accepted by the depth below it and rejected by the depth in its
filename**. Run the set and a verifier's stopping point is visible in its verdicts
alone, which is the property that makes two verifiers' disagreement diagnosable rather
than just observable.

| Vector | Surface | Builder-chain | Dependency-chain | Separates on |
|---|---|---|---|---|
| `01-all-depths-accept` | accept | accept | accept | — (control) |
| `02-…-attestation-subject-mismatch` | accept | reject | reject | attestation names a different subject |
| `03-…-attestation-builder-mismatch` | accept | reject | reject | attestation names a different builder |
| `04-…-dependency-unattested` | accept | accept | reject | a build input has no publisher attestation |
| `05-…-dependency-publisher-untrusted` | accept | accept | reject | an input's attestation was signed under an untrusted issuer |
| `06-…-resolved-dependencies-absent` | accept | accept | reject | the attestation declares no build inputs at all |

`01` is load-bearing in the way a positive control is: without it the set is satisfied
by a verifier that rejects unconditionally, and every separation below it means nothing.

Two vectors per boundary, on two different defects, is deliberate. One vector per
boundary has no margin — a single implementation shortcut that happens to catch that one
defect passes the whole boundary. `02` and `03` both sit at Surface → Builder-chain: a
verifier that checks the subject but never compares the builder inside the attestation
passes `02` and fails `03`. `04`, `05` and `06` sit at Builder-chain →
Dependency-chain: presence of an attestation, trust in who signed it, and whether there
was anything to walk are three different implementations, and `06` is the one that
catches a verifier whose dependency loop accepts vacuously over an empty list.

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
- `expected` — the verdict at each depth. Depths stack, so a deeper depth carries every
  failure the shallower depths found.

## What there is deliberately no vector for

**Signature validity.** Every vector assumes signature verification already succeeded.
A bad signature rejects at every depth, so it cannot separate them, and `verified_identity`
carries the result rather than the bundle. What varies here is *binding* — subject,
builder identity, per-input publisher — which is where a shallower verifier accepts
silently rather than loudly.

**The absent and unresolvable `provenance_uri`.** Both reject at Builder-chain and both
are cases an implementer writes without prompting. `tests/test_build_provenance_depth_vectors.py`
exercises them by mutating the accepting control, so they are covered without diluting
the fixture set with the obvious.

## Running them

```bash
pytest tests/test_build_provenance_depth_vectors.py
```

The test module carries a reference verifier parameterised by depth. It asserts each
vector's verdict at each depth, and separately asserts the properties that keep the set
honest as it changes: verdicts are monotone over depth, every boundary keeps two
vectors separating on distinct defects, every rule is load-bearing (delete it and some
fixture stops matching), and no rule is exercised by declaration alone.

An implementation in another language runs the vectors directly: read `build_provenance`
and `context`, verify at each depth, compare against `expected`.
