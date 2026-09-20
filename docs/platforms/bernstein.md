# Platform: Bernstein (software-only)

Bernstein is an open-source governance layer for AI agents: a deterministic Python scheduler that coordinates agent workloads with no model in the coordination loop, records every run into a hash-chained journal, and signs a TRACE Trust Record over that journal with an Ed25519 install identity. This annex maps that producer onto the Trust Record. It is informative, in the sense GOVERNANCE gives vendor annexes: it binds no implementation, and where it quotes a requirement it names the section that carries it.

There is no hardware root. `runtime.platform` is `software-only` on every record, for the reason section 3.1.1 gives: nothing attested the execution. What the producer has instead is a different kind of evidence, and this page says exactly what it is and what it is not: a signed record whose digests a verifier recomputes from the journal, and, once the emitter carries section 3.1.4's claim, a coordination sequence a verifier re-derives without the producer.

Every code path and vector below is pinned to `sipyourdrink-ltd/bernstein` at [`4281e3c1`](https://github.com/sipyourdrink-ltd/bernstein/tree/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559). The emitter is [`src/bernstein/core/observability/trust_record.py`](https://github.com/sipyourdrink-ltd/bernstein/blob/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/src/bernstein/core/observability/trust_record.py); its module docstring is the producer's own specification of the mapping and this page follows it.

## What the producer records

Each run writes one journal, `.sdd/runs/<run_id>/journal.jsonl`, through a single always-on recorder. Every row carries `event_hash = H(prev_hash, event_type, payload_hash, index)`, where `payload_hash` is a digest of the event payload with the wall-clock envelope (`ts`, `elapsed_s`) excluded, so two identical executions chain to the same hashes regardless of timing. The head hash content-addresses the surviving journal state. A seal, taken separately, is what identifies that state as the complete finished journal; an unsealed clean prefix says the rows were not edited, not that none are missing. That is the seal boundary the emitter states for itself: the signed record proves the journal presented matches what was sealed, and cannot prove that every action taken was recorded in the first place.

One distinction matters for anyone recomputing anything. The journal's own hashes are computed under a code-point key order with ASCII escaping, the encoding this repository's `canonicalization-boundary` vectors exist to warn about. They identify journal state inside Bernstein and are not TRACE digests. Every digest that reaches a Trust Record is computed with the producer's `canonicalize_jcs`, an RFC 8785 canonicalizer with UTF-16 code-unit key order; the supplementary-plane pair below is the vector that tells the two apart.

## TRACE representation

One record per execution hop, minted from that hop's journal by `bernstein trace export`. The mapping, field by field:

| Field | Value on a Bernstein record | Derived from |
|---|---|---|
| `eat_profile` | `tag:agentrust-io.com,2026:trace-v0.2` | fixed |
| `iat` | execution completion time, Unix seconds | the last journal event's `ts`, rounded to the second; an empty journal cannot back a record and is refused |
| `subject` | `spiffe://bernstein.run/run/<run_id>/exec/<exec_id>` | `exec_id` is the journal's own identifier and the name of its directory on disk, so a verifier holding the journal recovers it without trusting the caller; `run_id` groups the hops of one delegated run and is caller-supplied |
| `model` | `{provider, model_id, version?}` | the last event carrying `model_id`, so a mid-run model switch is reflected |
| `runtime.platform` | `software-only` | fixed |
| `runtime.measurement` | the all-zero `sha256:` digest | fixed; see the note under commitments |
| `policy.bundle_hash` | `sha256:` over the RFC 8785 bytes of the resolved gate configuration | the last `gate_config` event |
| `policy.enforcement_mode` | `enforce` | fixed: the scheduler's gates act on the result |
| `data_class` | operator-declared sensitivity | the last `data_class` event; a conservative default when none was declared |
| `tool_transcript.hash` | `sha256:` over the RFC 8785 bytes of the ordered list of `tool_call` payloads, chain and timing fields excluded | every `tool_call` event, in journal order |
| `tool_transcript.call_count` | the number of those events | always present, at zero calls too: no calls is a fact, not a gap |
| `build_provenance` | `{slsa_level: 0, digest, provenance_uri}` | the installed build's digest and the release page |
| `appraisal` | `{status: "none", verifier: "https://bernstein.run/trace/verifier", timestamp}` | the producer appraises nothing about its own record; `timestamp` equals `iat` |
| `cnf.jwk` | `{kty: OKP, crv: Ed25519, x, kid: install-<rev>}` | the install identity's public key; two installs minting the same `(run_id, exec_id)` mint the same `subject` and different keys, so `cnf.jwk` is what tells them apart |
| `delegation` | `{parent_record_hash, credential_id}`, child hops only | see delegation below; absent, not null, on a root hop |
| `references` | `{rel: "produced-artifact", id, resolver, digest}` per artifact | every `artifact_produced` event; absent, not empty, when there were none |
| `signature` | base64url Ed25519, no padding | over the RFC 8785 bytes of every other member |

Optional members are omitted when absent, never carried as `null`. RFC 8785 treats a present key and an absent one as different bytes, and a producer that emitted `"delegation": null` would sign different bytes from one that omitted it.

### Delegation: one record per hop

A delegated run is a chain of hops, each with its own record, linked and not nested, which is the shape section 3.4 fixes. A child hop's `delegation.parent_record_hash` is SHA-256 over the RFC 8785 bytes of the complete signed parent record, `signature` included, the preimage section 3.1.3 states. The choice is load-bearing for an orchestrator: a digest over the signed body alone would let a chain be rebuilt from a differently-signed parent that says the same thing, and for a multi-agent run that is the attack. `credential_id` names the delegation credential the hop acted under.

The scheduler bounds spawn depth and narrows a child's `data_class` from its parent's. The three-hop vector set below is built so that both rules have something to fire on: a chain two links deep, and a narrowing pair.

### Aggregate: one record per run

A run-level record rolls the hops up. It reads no journal, since no journal exists for the run as a whole, and every member is a rollup: `iat` is the latest member's; `model` the last member's; `policy.bundle_hash` a digest over the ordered list of member bundle hashes, a hash of hashes and not a policy of its own; `data_class` the most restrictive member's; `tool_transcript` a digest over the ordered member transcript hashes with the counts summed. It carries no `delegation`. Its `references` hold one `{rel: "member-execution", id, resolver, digest}` entry per hop: `id` is the member's own `subject`, `digest` is SHA-256 over the RFC 8785 bytes of the member's complete signed record, the same preimage a delegation link uses, so a verifier resolves a member by name and binds it by recomputing that digest over the record it holds. Its `subject` is `spiffe://bernstein.run/run/<run_id>`.

Neither `member-execution` nor `produced-artifact` is a registered `rel` value. Section 3.1.2 keeps `rel` open and calls its values a registry; both are producer-defined relations until registered.

## Two commitments, and where they sit today

Section 3.1.4 notes that a software-only record can carry two recomputable commitments, `runtime.measurement` and `transcript_digest`, over different objects. On a Bernstein record today:

- `runtime.measurement` is all-zero. The value was chosen while the meaning of `measurement` under `software-only` was being settled, and it is left there deliberately until agentrust-io/trace-spec#242 settles it; the emitter records the choice in its own source. The reference SDK's adapters carry a non-zero software commitment in the same field, so the all-zero value is one reading of the field and not the field's definition.
- The journal commitment the record does carry is `tool_transcript.hash`, over the tool calls. The journal head itself is not on the record: a verifier that wants the whole chain reads the journal and recomputes it, which is the check described below.

## The reproducibility claim

The coordination logic is a deterministic function of the run, and the producer already ships the check that re-runs it: `bernstein replay <run> --re-derive` takes the two things coordination did not choose, the recorded plan graph and the recorded per-task outcomes, walks them through the scheduler's coordination state machine, refuses any step the rules could not have produced at that point, and appends the accepted steps to a fresh journal in a sandbox, so the result ends with a head computed from inputs rather than copied from the recorded chain. It re-executes no agent, needs no adapter, task server or network, and reads one file to write another. That is the shape section 3.1.4 gives the claim, and the mapping onto it is:

| Claim member | Bernstein value |
|---|---|
| `function` | the coordination state machine in `bernstein.core.replay.rederive` |
| `code_identity` | the digest of the release artifact that contains it; where `build_provenance.digest` names that same artifact the two are equal, as section 3.1.4 provides |
| `code_resolver` | the package index the release is published to |
| `input_closure` | the recorded plan graph and every recorded outcome the function reads, each as a content-addressed journal row; a recorded model interaction is an input here, never something a verifier re-invokes |
| `transcript_digest` | SHA-256 over the RFC 8785 bytes of the ordered list of accepted coordination steps, each projected as the journal projects a payload, chain and timing fields excluded |

Two things a verifier should know before re-running. The re-derived journal head that `--re-derive` compares is Bernstein's own commitment, computed under the journal's code-point encoding; the record's `transcript_digest` is the RFC 8785 digest over the same sequence, and the two are not interchangeable. And the outcome vocabulary is section 3.1.4's: `reproduced` when the digests agree, `diverged` with the observed digest when they do not, and `not-attempted` with the reason when a closure row cannot be obtained, the artifact at `code_identity` cannot be obtained, or the function reads beyond the closure. The re-derivation's own refusal codes, a step the rules cannot produce and a head that differs, are both `diverged` in that vocabulary, since in both cases the re-run completed on the closure alone and did not reach the claimed transcript.

The emitter at the pinned commit does not carry the block; the schema shape landed after it, in agentrust-io/trace-spec#366. Until it does, a verifier finds no claim on a Bernstein record and has nothing to re-run. The mapping is fixed here so that the emitter change is a change to what the record says, not to what the words mean.

## What a verifier can check without the producer

1. **Shape.** The record validates against `schema/trace-claim.json`, and `TrustRecord.model_validate` accepts it.
2. **Signature.** Ed25519 over the RFC 8785 bytes of the record with `signature` removed, against `cnf.jwk`. `agentrust_trace.verify_record` does this; the vectors carry a frozen clock, so pass `max_age_seconds=None` or the reference suite's `--max-age`.
3. **Links.** A child's `parent_record_hash` recomputes from the committed parent: canonicalize the complete signed parent with RFC 8785, hash, compare. An aggregate's member digests recompute the same way over each member.
4. **Journal.** With the journal in hand, recompute every `payload_hash` and `event_hash` from genesis and compare the head; fold the `tool_call` rows as the emitter does and compare `tool_transcript.hash`. Without the journal, the record attests that the producer signed these digests and nothing more.

Steps 1 to 3 need the records alone. Step 4 needs the journal, which is run-private and resolved through the producer, the integrity bar section 3.1.4 sets for a closure rather than a provenance one.

## Assurance boundary

Level 0. A software-only record cannot reach Level 1 by construction: the conformance suite's `TR-RTE-001` refuses `software-only` at hardware-attested levels and `TR-RTE-004` wants a verifier-issued nonce that a committed record cannot carry. A committed corpus also cannot pass `TR-ENV-002` without `--max-age`, since a record that regenerates byte-for-byte carries a fixed `iat`; this repository's own `examples/amd-sev-snp.json` has the same property. None of that is a defect of the producer; it is what a published record is. See [trust levels](../trust-levels.md).

What the producer's evidence establishes, once verified: that the install identity signed these digests over this journal, that the chain of hops is the chain the parent signed, and, when the claim is carried, that the coordination sequence re-derives from its recorded inputs. What it does not establish: that the journal is complete, beyond what the seal says; and anything about the workload's side effects or the model's answers, which are inputs.

## Vectors

Seven signed records in [`tests/fixtures/trust-record-vectors/`](https://github.com/sipyourdrink-ltd/bernstein/tree/4281e3c1ac86adbfae704dc4d1e69d4bb2a61559/tests/fixtures/trust-record-vectors), all minted by the emitter over journals written through the real recorder, never hand-written, under a frozen clock and a pinned Ed25519 seed. Regeneration is byte-identical and a test holds it to the committed files.

| Vector | What it is |
|---|---|
| `single-execution` | one root execution, with a tool call and a produced artifact |
| `delegated-parent`, `delegated-child`, `delegated-grandchild` | a three-hop chain, two links deep, with a narrowed `data_class` |
| `aggregate` | the run-level record over the three hops, with `member-execution` references |
| `supplementary-plane-parent`, `supplementary-plane-child` | a pair whose parent's `cnf.jwk` carries a private-use BMP member and a supplementary-plane member, so the child's link resolves under RFC 8785 key order and dangles under a code-point sort |

The supplementary-plane pair is the independent-producer counterpart of [`examples/delegation-link/24-parent-key-supplementary-plane.json`](https://github.com/agentrust-io/trace-spec/blob/main/examples/delegation-link/24-parent-key-supplementary-plane.json): same two members, a different producer, no shared code path. Its digests reproduce with the `rfc8785` package and its records verify with `agentrust_trace.verify_record`. The committed files are written with ASCII escapes in code-point order, so the astral key appears as `"😀"` in the bytes; digest what parsing yields, under RFC 8785, never the file.

To reproduce the mint:

```bash
git clone https://github.com/sipyourdrink-ltd/bernstein && cd bernstein
git checkout 4281e3c1ac86adbfae704dc4d1e69d4bb2a61559
uv run python tests/fixtures/trust-record-vectors/_build_trust_record_vectors.py
```

To run the reference suite against one record:

```bash
uv run --with agentrust-trace-tests trace-tests verify \
  --record tests/fixtures/trust-record-vectors/single-execution-trust-record.json \
  --level 0 --max-age 999999999999
```

Continue to [attestation platforms](index.md) or [trust levels](../trust-levels.md).
