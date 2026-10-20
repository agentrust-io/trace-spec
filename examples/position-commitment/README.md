# A position in an externally ordered sequence as a `position-commitment` entry

A TRACE Trust Record can carry a commitment to a position it took in an externally
ordered sequence before its own digest existed. These fixtures show that composition
under the v0.3 draft. Each record carries one `references` entry with
`rel: "position-commitment"` and `validation: "recompute"`, no `resolver` and no
`retention`, and its `id` is the SHA-256 of the RFC 8785 canonical form of the slot
object inside the proof the holder carries.

The relation is defined in [`docs/references-registry.md`](../../docs/references-registry.md),
and recomputation in §3.1.2, "Entries validated by recomputation". The v0.2 schema
refuses every record here, which is the version gate; the records validate against
[`schema/trace-claim-v0.3-draft.json`](../../schema/trace-claim-v0.3-draft.json) and bind
nothing until v0.3 is adopted.

Everything derives from one published seed through
[`gen_position_commitment_vectors.py`](gen_position_commitment_vectors.py), so the set
regenerates byte for byte; the sequence, the committing enclave and the records are
illustrative, and every digest and signature recomputes from the committed files.
[`tests/test_position_commitment_fixtures.py`](../../tests/test_position_commitment_fixtures.py)
recomputes every verdict from those bytes rather than reading it from `expected.json`,
and re-runs the generator against the committed files.

## Two inputs, kept apart

| File | Supplied by | What it is |
|---|---|---|
| `proof-*.json` | The holder | The slot, the committer's binding, and `committer_jwk`, a key the proof supplies for itself |
| `relying-party.json` | The relying party | The committer keys it trusts, by RFC 7638 thumbprint, and its own copy of the sequence: the value published at each position |

Only the second can make a position independently established. A proof whose digests
all agree and whose signatures verify under the key it carries is consistent with
itself, and anyone holding a key can produce one. Case `05` is that proof.

## The proof

| Member | What it is |
|---|---|
| `slot.sequence`, `slot.position`, `slot.sequence_value` | The external sequence, the position taken, and the value the sequence published there, so the slot cannot predate that position |
| `slot.committer`, `slot.committer_key_id` | The party that allocated the slot, and the thumbprint of its Ed25519 key |
| `slot.allocated_at`, `slot.signature` | When it was allocated, and the committer's signature over the RFC 8785 form of the slot without this member |
| `binding.slot_commitment` | The slot's digest, equal to the entry's `id` |
| `binding.record_digest` | This record's digest: the §3.1.3 preimage, the complete record as published with `signature` included |
| `binding.bound_at`, `binding.signature` | When the committer bound the slot to the record, and its signature over the binding |
| `committer_jwk` | The key the proof supplies; checked against `committer_key_id`, never trusted for it |

The slot exists before the record and the binding after it, which is how `id` can be
inside the record while the proof commits the record's digest.

No resolver undertakes to keep any of this, so the entry names none. Later
recomputation still needs the proof bytes: the holder keeps them, and a verifier
handed none has nothing to recompute (case `03`).

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every
record's signature verifies under the producer key, and every record validates against
the v0.3 draft schema; what differs is the proof the holder presents and what the
relying party holds.

| Record | Proof presented | Slot recomputes to `id` | Binds this record | Committer key held independently | Signatures | Sequence position | Verdict |
|---|---|---|---|---|---|---|---|
| `01-position-established.json` | `proof-01.json` | yes | yes | yes | verify | matches | position established |
| `02-same-proof-other-record.json` | `proof-01.json` | yes | **no** | not checked | not checked | not checked | contradiction: commits another record |
| `03-proof-not-held.json` | **none** | n/a | n/a | n/a | n/a | n/a | position absent |
| `04-proof-altered.json` | `proof-04-altered.json` | **no** | not checked | not checked | not checked | not checked | contradiction: commitment mismatch |
| `05-committer-key-self-supplied.json` | `proof-05.json` | yes | yes | **no** | verify under the proof's own key | matches | consistent, not established |

`01` is the matching record. The slot recomputes to the entry's `id`, the binding
commits this record's digest, both signatures verify under a committer key the
relying party holds, and the sequence value in the slot is the one the relying party's
own copy holds at that position.

`02` is another record carrying `01`'s entry byte for byte, presented with `01`'s
proof. The commitment recomputes, so a check that stopped there would pass it. The
binding commits `01`'s digest, not `02`'s, and that is a contradiction in the record.

`03` carries a real commitment whose proof the verifier is never handed. The entry is
absent. That is not a finding against the record, and it is a different answer from
the contradictions in `02` and `04`.

`04` was issued against `proof-04.json`, which establishes its position. The proof
presented, `proof-04-altered.json`, differs only in `slot.position`, rewritten to an
earlier one: a backdate. The slot no longer recomputes to the `id` the record signed,
and the result is a contradiction, never an absence.

`05` recomputes and binds, and both signatures verify, but only under
`committer_jwk`, the key the proof carries. The relying party holds no key for that
committer, so the agreement establishes consistency and not ordering. Adding that key
to the relying party's trust would turn the verdict into position established; the
tests show that step is the relying party's to take, never the proof's.

Two further verdicts are exercised in memory by the tests: a slot that names the
trusted committer's key id but is signed by another key (contradiction: signature
invalid), and a slot under the trusted key whose sequence value differs from the
relying party's copy (contradiction: sequence mismatch).

None of these outcomes changes `runtime.platform` or makes the entry attested evidence
of what the execution did.

## Running the checks

```
python -m pytest tests/test_position_commitment_fixtures.py
```

To regenerate, run the generator with no arguments. It is deterministic, so the
committed files only change when the generator does.
