# Case-003-only successor reconciliation

Review patch against TRACE `main` at `cd92e16dde6658eedbe1058c903f3fce92bb3a58`.
The held corpus source was recovered from its September 2 Drive backup. The
recovered case-003 bytes match SHA-256
`221413d83d753efbabe93d35957c7dd67779864e592a8eb5a59cff9e961d4bb1`.
The original working directory recorded in the September 4 audit is unavailable
on this machine. This is a separate review copy; no upstream runtime is edited.

The September 15 [PIC maintainer decision](https://github.com/agentrust-io/trace-spec/issues/206#issuecomment-5682052917)
separates authorization binding, successor-envelope binding, and successor outcome.
[PR #340](https://github.com/agentrust-io/trace-spec/pull/340), merged September 14,
implements the signed envelope and independent three-state evaluator accepted in
[#338](https://github.com/agentrust-io/trace-spec/issues/338#issuecomment-5651124900).

| Vector | Bridge classification/code | PIC bound | Envelope bound | Outcome |
|---|---|---|---|---|
| 003, complete relevant envelope | accepted | true | true | established |
| 003a, literal `after: {}` | mismatch / transcript_after_invalid | true | false | null (not evaluated) |
| 003b, envelope with empty observation | accepted | true | true | not-established |
| 003c, envelope with unrelated observation | accepted | true | true | not-established |

The old `transcript_bound: true` target is retired only for 003. The new profile
`trace.pic-trace-bridge.case003.v1` opts only this family into the new contract.
The other 101 base fixture files, v1 schema, approved 45-code registry, and #247
diagnostics remain byte-identical. Their hashes are pinned in
`contract/frozen-other-cases.sha256.json`.

All four review vectors have valid authorizer signatures, trusted key IDs, allow
decisions, time windows, scopes, PIC digest matches, declaration/tool-call digests,
before-call canonical bytes, and signed successor digests. For 003a, even the
digest of literal `{}` is correctly signed. It therefore reaches the missing
envelope-fields guard rather than failing on an earlier prerequisite.

`pic_authorization_bound` is true after the PIC comparison stage is established.
For an earlier refusal it is null (not evaluated), rather than an invented false
comparison. `successor_envelope_bound` is true only after the complete envelope
passes integrity checks. A bridge refusal has `successor_outcome: null` and no
outcome reason; it is not silently converted into the evaluator's
`not-established` evidence result. The two insufficient observations have an
explicit `successor_predicate_undecidable` reason.

The reason labels in the case-003 adapter are review-local normalization, not
additional entries in the approved global taxonomy. `transcript_after_invalid`
is reused for the exact missing-envelope-fields refusal, anchored to exception
type and full message. Unmapped reference signals fail loudly.

The fixture-local predicate `invoice-sent-v1` compares `observation.invoice_id`
with `tool_call.arguments.invoice_id`. For that invoice, status `sent` affirms,
status `failed` contradicts, and any other or missing value is undecidable. An
unrelated invoice is also undecidable. This is a synthetic test predicate, not
a universal transition language or a claim that an invoice was actually sent.

PIC digests remain opaque synthetic verifier outputs supplied to the bridge.
The corpus does not recompute or redefine PIC canonicalization, `intent_digest`,
or `args_digest`, and does not certify an upstream PIC verifier.

From a checkout with the package dependencies and pytest installed:

```text
python examples/pic-trace-bridge-v1/gen_bridge_vectors.py
python examples/pic-trace-bridge-v1/run_bridge_vectors.py --case-003 --json
python -m pytest tests/test_pic_bridge_case003.py tests/test_intent_bridge.py tests/test_successor_observation.py
```

The review tests check both verifier paths, exact refusal reasons, substitution
of each envelope field, unsigned digest replacement, trusted contradictory
evidence, observer policy, fixture regeneration from an empty destination, and
preservation of all other rows. Bypassing the reference envelope guard accepts
003a at the bridge surface; falsely promoting undecidable evidence to established
changes both insufficiency results in each verifier path. These tests establish
that the intended rules affect the verdict.

Full-corpus certification stays held. The default runner and old mutation command
explicitly refuse certification; `--case-003` reports only four review vectors.
The frozen denominator remains 100, and 101/102 stay excluded diagnostics. The
old empty-after positive credit remains withdrawn. Wider corpus reconciliation,
commit, push, and PR publication are outside this patch.
