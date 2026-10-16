# Manifest reference, v0.3 draft fixtures (trace-spec#483)

Six fixtures for an optional signed top-level `manifest {id, digest, media_type}` that names the agent manifest a
record ran under. Status: **v0.3 draft**. No conformance module implements the reference yet;
`tests/test_manifest_ref_draft_vectors.py` states the draft rule as a small reference checker.

The rule under test is reference-only. The verifier checks the record signature first (§3.3 step 1). It then
recomputes sha256 over the bytes the manifest id resolves to and compares that with the signed digest. A
`manifest_verification_result` written by the producer is never read (agentrust-io/agent-manifest#498: a verifier
MUST NOT report the producer's result as its own).

| Fixture | Record | Manifest |
|---|---|---|
| 01-digest-matches | valid | established |
| 02-digest-mismatch | valid | manifest-digest-mismatch |
| 03-mismatch-with-asserted-result | valid | manifest-digest-mismatch |
| 04-unresolvable | valid | manifest-unresolved (not a pass; the record is not rejected for it) |
| 05-added-after-signing | signature-invalid | not-evaluated |
| 06-control-no-manifest | valid | no-manifest-named |

Each of four wrong checkers is caught by at least one fixture: one trusts the asserted result, one treats an
unresolvable manifest as a pass, one reads the manifest before the signature, and one rejects the record when the
manifest is unresolvable.

Regenerate with `python tests/vectors/manifest-ref-v0.3-draft/generate.py`. Signing uses the `rfc8785` dependency
and a public test key derived from a fixed seed. Records 01-05 were first published as
[`trace-manifest-ref-v0`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/2cd4ae7f47551903cb10627ef619d7396270528a/examples/trace-manifest-ref-v0)
at `2cd4ae7`; they now carry the v0.3 profile tag (`tag:agentrust-io.com,2026:trace-v0.3`) and were re-signed for
that profile change, so each is schema-valid against `schema/trace-claim-v0.3-draft.json` exactly as signed, and a
checker can run the schema, the signature and the digest binding on the same bytes, but they are no longer
byte-identical to `2cd4ae7`. 03 is the exception on purpose: the draft schema rejects its signed
`manifest_verification_result`. 06 stays a v0.2 record, the control that verifies as today.
