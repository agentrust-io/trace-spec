# An observed mutation interval as an `observed-effect` reference

A TRACE Trust Record can point at what an observer outside the agent saw change while
the agent ran: the state before an interval, the state after it, the paths the
observation covered, and the authority change ran under. These fixtures show that
composition. Each record carries one `references` entry with `rel: "observed-effect"`,
and its `digest` is the SHA-256 of the RFC 8785 canonical form of the DSSE envelope as
the resolver retains it.

The relation is defined in [`docs/references-registry.md`](../../docs/references-registry.md).
What a relying party may establish from a resolved reference is bounded to the object:
that the resolved bytes are the cited bytes, and, under an observer key it holds, that
the named observer signed them. Neither reaches the record: under §3.1.2 rule 3 it
verifies the same whether the reference resolves or not, and nothing in the object
becomes attested evidence. An interval in which the observer and the observed party
agree is not attested evidence that the agent's report was true, and one in which they
disagree is not a finding against the record. Cases `01` and `03` are the same record
shape citing an agreeing and a disagreeing interval, and they verify identically.

## Where the objects come from

The two statements in [`source/`](source/) are copied byte for byte from the published
observed-effect conformance corpus, [`vectors-observed-effect/` at `b916489`](https://github.com/probityai/agent-evidence-vectors/tree/b91648940b2042ff1cc34d11ed2ac1d97b3e42d4/vectors-observed-effect), where each is a member that corpus's own verifier
accepts: `v1c6fdd82db5229e4` is an authoritative interval in which both sides agree, and
`v620e7755ba36aa0a` is one in which they disagree on the write count and the after-state
root. A member's identifier is the first 16 hex characters of SHA-256 over its file, so
a copy that drifted fails the generator. The corpus publishes the observer's public key
in its manifest, and that key is the one this relying party holds.

Everything else derives from one published seed through
[`gen_observed_effect_vectors.py`](gen_observed_effect_vectors.py): the Trust Record
producer key, a second observer key that re-signs the agreeing statement for case `05`,
and the altered store. The set regenerates byte for byte.
[`tests/test_observed_effect_fixtures.py`](../../tests/test_observed_effect_fixtures.py)
recomputes every verdict from the committed bytes rather than reading it from
`expected.json`, and re-runs the generator against the committed files.

## The referenced object

`effect-store.json` holds three DSSE envelopes by identifier. Each one carries an in-toto
Statement whose `predicateType` is
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect`:

| Member | What it is |
|---|---|
| `predicate.interval` | `beforeRoot`, `afterRoot`, `openedAt`, `sealedAt` |
| `predicate.pathScope`, `predicate.observation.coverage` | The paths observed, and whether any part of them went unseen |
| `predicate.authorityDigest` | The digest of the grant under which change was permitted |
| `predicate.dualValues` | Facts both sides report, with both values and whether they agree |
| `subject[0].digest.sha256` | Equal to `afterRoot` |
| `signatures[0]` | Ed25519 over the DSSE pre-authentication encoding, under the observer's `keyid` |

This example checks the envelope, not the predicate's own rules. Those belong to the
predicate's conformance corpus, which is where both source statements come from.

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every record
verifies as a TRACE record; what differs is what the reference resolves to. Resolution,
digest match and signature verification are three separate findings, each reported in
its own column and its own field. The verdict names the state of the referenced
observation, not the effect it reports: a verified observation does not establish that
the reported change occurred, and a digest mismatch does not establish that it did not.

| Record | Store | Reference | Digest | Observer key held | Envelope signature | Dual values | Verdict |
|---|---|---|---|---|---|---|---|
| `01-observation-verified.json` | `effect-store.json` | resolves | matches | yes | verifies | agree | observation verified |
| `02-observation-altered-after-issue.json` | `effect-store-altered.json` | resolves | **differs** | yes | **fails** | agree | observation digest mismatch |
| `03-observer-and-observed-disagree.json` | `effect-store.json` | resolves | matches | yes | verifies | **disagree** | observation verified |
| `04-reference-unresolvable.json` | `effect-store.json` | **no such entry** | n/a | n/a | n/a | n/a | observation unresolved |
| `05-observer-key-not-configured.json` | `effect-store.json` | resolves | matches | **no** | not checked | agree | observation unverified |

`02` is `interval/2`, issued with two disagreeing rows, rewritten in the stored copy so
that both rows agree with the observed party's report, with the signature left as
issued. Both checks catch it independently: the record's digest no longer matches, and
the observer's signature no longer verifies over the rewritten payload. Both findings
are about the stored copy; neither says anything about whether the interval's change
happened.

`03` cites the same `interval/2` from the unaltered store. The observer and the observed
party disagree, the record verifies exactly as `01` does, and the relying party reports
the disagreement without promoting it in either direction.

`04` is what §3.1.2 rule 3 requires: a verifier must not reject a record because a
reference cannot be resolved. The record verifies, and the observation it points at is
reported as unresolved, which is a different answer from "nothing changed".

`05` cites the agreeing statement re-signed by an observer whose key this relying party
does not hold. The rule §3.3.2 gives receipts applies: unverified, not invalid.

## Running the checks

```
python -m pytest tests/test_observed_effect_fixtures.py
```

To regenerate, run the generator with no arguments. It is deterministic, so the
committed files only change when the generator or a source statement does.
