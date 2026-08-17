# RFC Proposal: A2A delegation-link verification profile

**Status:** Draft proposal. Binds nothing.
**Scope:** Verification rules for the existing `delegation` block. No schema change.
**Target:** `spec/trace-v0.2.md` §3.1 surface, for the v0.3 A2A profile named in `ROADMAP.md`.
**Conformance material:** `examples/delegation-link/` — 23 vectors, generator, published key.

Requirement keywords are lowercase throughout this document, deliberately. `CONTRIBUTING.md`
draws the line that normative text lives in the specifications and informative text binds no
implementation; this file is informative until its rules are adopted, at which point they
become uppercase in `spec/` and this file becomes a pointer to where they went. A proposal
that writes itself in the imperative is a specification nobody agreed to.

---

## 1. What exists today

The `delegation` block is normative in v0.2. `schema/trace-claim.json` requires
`parent_record_hash` and `credential_id`, pins the first to `sha256:`/`sha384:` and the
second to a non-empty string, and forbids additional members.

What a verifier does with a chain of them is not normative anywhere.
`spec/trace-v0.2.md` does not mention either field. The only prose is `docs/schema.md`:

> A chain of records linked this way forms an offline-verifiable delegation DAG: a verifier
> walks `parent_record_hash` from a leaf record back to the root and confirms each hop acted
> under a credential in the delegation chain.

One sentence, and every operative word in it is undefined. What are the bytes the digest
covers. What is "the delegation chain" that a credential is in, given that no credential
object exists in the schema. What makes a hop's use of one legitimate. What a verifier does
when it cannot compute the digest algorithm the link names.

Two conforming implementations can satisfy every constraint the repository states today and
agree on nothing. This proposal is the smallest set of rules that closes that, written
against the block as it stands so that adopting it requires no schema change.

## 2. The verification model

A verifier is given a **record set**, a **leaf**, and **context**. The record set is a set:
it arrives in no defined order, and the leaf is named by digest rather than by position.
An implementation that reads the first element as the root, or the next element as the
parent, is reading a property of its input channel rather than of the evidence.

The verifier walks from the leaf towards the root, resolving each `parent_record_hash`
against the digests of the records it holds. The walk ends at a record with no `delegation`
block — the root — or at a link it could not follow.

Context is what a verifier knows that no record can tell it, and it is enumerated rather
than assumed:

| Context | Why it cannot come from the records |
|---|---|
| `trusted_root_keys` | A record naming its own key as trusted is not evidence. |
| `credentials` | `credential_id` is an identifier; the thing it identifies is held out of band. |
| `data_class_lattice` | `data_class` is an open string in the schema, so no ordering can be inferred from a record. |
| `max_depth` | A bound is a deployment decision, not a property of a chain. |
| `supported_digest_algorithms` | What the verifier can compute, which is not what the chain may name. |
| `now` | Present for completeness; §4.3 explains why no rule reads it. |

Each entry is a place where an implementation that guesses instead of being told produces
an answer that looks like verification and is not. Naming them is half the profile.

## 3. The rules

Ten rules, each with a stable code, a classification, and two independent vectors.
Classification is the three-way distinction the conformance corpus in `agentrust-io/ca2a`
already uses for its action cases: a structural failure, an authority failure, and a chain
that could not be read are three different findings, and a verifier that collapses any two
of them is reporting something other than what it found.

| # | Code | Class | Rule | Vectors |
|---|---|---|---|---|
| D-1 | `record_signature_invalid` | provenance | Every record on the walked chain verifies under the key it advertises in `cnf.jwk`. | 06, 07 |
| D-2 | `root_key_untrusted` | provenance | The record with no `delegation` block carries a key in `trusted_root_keys`. | 08, 09 |
| D-3 | `parent_not_found` | provenance | Each `parent_record_hash` resolves to a record in the set, under §4.1's preimage. | 04, 05 |
| D-4 | `depth_exceeded` | authorization | The walk follows no more than `max_depth` links. | 20, 21 |
| D-5 | `credential_unknown` | authorization | `credential_id` matches a registry entry as an exact octet string. | 10, 11 |
| D-6 | `credential_issuer_mismatch` | authorization | The credential's issuer is the parent record's `subject`. | 12, 13 |
| D-7 | `credential_holder_mismatch` | authorization | The credential's holder is this record's `subject`. | 14, 15 |
| D-8 | `credential_window` | authorization | This record's `iat` falls inside the credential's validity window. | 16, 17 |
| D-9 | `data_class_widened` | authorization | A hop's `data_class` is no more sensitive than its parent's, per the supplied lattice. | 18, 19 |
| D-10 | `digest_algorithm_unsupported` | unverifiable | A link naming an algorithm the verifier cannot compute yields an unverifiable chain. | 22, 23 |

Provenance outranks authorization in the reported classification. A chain whose structure is
broken has no established parent for a credential to be judged against, so reporting an
authority failure over it would describe a relationship that was never demonstrated.

D-6 and D-7 together are the whole of what "acted under a credential in the delegation
chain" can mean offline with the fields that exist: the credential came *from* the hop above
and was issued *to* this one. Vectors 13 and 15 are the two ways an implementation gets that
backwards while every comparison it makes still returns agreement.

## 4. Three decisions a vector could not be written without

These are not refinements. Each is a fork where the existing text supports both branches,
and no conformance material can exist until one is chosen.

### 4.1 The digest covers the complete record, signature included

"Digest of the parent hop's Trust Record" does not say which bytes. Over the RFC 8785
encoding of the complete record, or over the signed body with `signature` removed? Both are
natural readings and they are not interoperable: a chain built under one is a chain of
dangling links under the other, and neither side has a diagnostic that says so.

This profile takes the complete record, because the alternative does not bind the parent's
signer. Under the body reading, a child's `parent_record_hash` commits to bytes that any
holder of any key can re-sign. Two records with different signatures — one genuine, one
issued by an attacker — satisfy the same commitment, and a verifier walking the chain
resolves to whichever it was handed. The child would have committed to *what its parent
said* and not to *who said it*, which is the entire content of a provenance link.

The complete-record reading has a consequence worth stating, because it changes what an
attacker can reach: every ancestor's bytes are committed to by its child, so no record on a
chain can be altered in place except the leaf. An ancestor with an invalid signature is
still reachable — it has to be built that way before its child signs — which is why D-1
applies to every record on the walk and not only to the leaf. Vector 07 is that case, and
vector 06 is the leaf case; an implementation that verifies the leaf and takes the rest on
the strength of the hashes passes one and fails the other.

Vector 05 is this decision and nothing else: a complete, correctly signed two-record chain
whose only defect is that its link was computed over the parent's signed body.

### 4.2 No cycle rule, and why the depth bound is not a substitute for one

A delegation cycle would need record A's block to carry a digest of B while B's block
carries a digest of A. Each digest covers the block holding the other, so constructing the
pair is a hash collision. Cycles are not forbidden by this profile; they are unreachable,
and a rule against them would be untestable by construction — there is no vector that could
demonstrate an implementation lacking it.

The reachable analogue is an *unbounded* chain, which is trivially constructible, and a walk
without a limit is a denial of service on the verifier. That is the only reason D-4 exists,
and it is stated here so that a reader can tell which of the two was decided and which was
forgotten.

Vectors 20 and 21 pin the comparison from both sides: 21 sits one past the bound, and vector
02 sits exactly on it and verifies. A bound tested only from above accepts an off-by-one; a
bound tested only from below rejects legitimate chains at the limit.

### 4.3 A link that cannot be read is unverifiable, not invalid

The schema permits `sha384:` links. A verifier that implements only `sha256:` cannot resolve
such a link — and reporting `parent_not_found` for it would be a finding nobody made. The
verifier did not fail to find the parent; it did not look.

This follows the semantics already merged in `docs/verification.md`: evidence that resolves
and contradicts fails the appraisal, and a verifier does not downgrade to escape that;
evidence that does not resolve downgrades honestly, and the verifier records the depth it
actually achieved. D-10 is the delegation-surface instance of the second half. In the
reference walk, D-3 is explicitly guarded on algorithm support so that the two findings
cannot be produced together for the same link.

Vector 23 is why this needs a rule rather than a note: a chain whose leaf link is `sha256:`
and whose third link is `sha384:` reports "verified" from any implementation that reads the
algorithm once and assumes the chain is uniform, having never resolved half of it.

The related decision, made for the same reason: D-8 judges the credential window against the
hop's own `iat`, not against the verifier's `now`. A chain does not become invalid because
it is being read late, and a verifier using its own clock returns a different answer every
day for the same evidence. `now` stays in the context table because a deployment may impose
freshness policy on top of this profile; no rule here reads it.

## 5. The conformance corpus

`examples/delegation-link/` holds 23 vectors. Each is one scenario: a complete record set,
the verifier context to judge it under, and the classification and codes it expects, so a
third party can score an implementation without running anything from this repository.

Every record in every vector — including the ones built to fail — validates against
`schema/trace-claim.json`. A defect the schema already rejects is not a profile defect, and a
rule that appears covered only because its vector is malformed in some louder way is not
covered.

Reproducibility is a property of the corpus, not a courtesy. Keys derive from one published
seed by role label; the generator regenerates every byte; `tests/test_generators_reproduce_fixtures.py`
(#171) discovered it with no new guard code and holds it to that with no entry in the
`NOT_GENERATED` ledger. This is the bar issue #178 proposes for the repository's corpora,
adopted here from the first vector rather than retrofitted.

Coverage is held to the discipline argued in #124 and executed in
`tests/test_vector_completeness.py`: two load-bearing vectors per rule, and — the part that
is not satisfied by writing the same vector twice — at least one declared implementation
defect that one vector catches and the other misses. `tests/test_delegation_completeness.py`
declares those defects, all ten of them modelling a real shortcut: verifying the leaf only,
anchoring on any trusted key found, an off-by-one bound, case-insensitive identifier lookup,
issuer and holder compared to the wrong ends, half a validity window, narrowing checked at
one hop.

Vector identifiers are `TRACE-DELEG-NNN` and are never reused. They are deliberately not
`ACTION-*`: that namespace belongs to ca2a's conformance set, whose own rule is that its
identifiers are never reused, and borrowing it from another repository would collide the
first time either side adds a case. §7 proposes a cross-reference table instead.

## 6. What this proposal does not do

- **No schema change.** Every rule reads fields that exist in v0.2.
- **No credential format.** The registry is verifier context, like a trusted key set. What a
  credential *is*, how it is issued, signed, or revoked, is out of scope, and the vectors
  express one only as the fields the rules read.
- **No revocation.** A revoked credential is indistinguishable here from a valid one, which
  is a real gap and belongs in the same discussion as the credential format.
- **No withdrawal before execution.** An authorization revoked between issue and use is one
  of the two gaps issue #66 has already named on the approval-shaped surface; it needs a
  field this schema does not have.
- **No authority-epoch staleness**, the other #66 gap, for the same reason.
- **No cross-verifier agreement.** This is the load-bearing omission and §7 is about it.

## 7. The part that makes this worth doing

One implementation passing its own conformance corpus is self-agreement. What would make
this a profile rather than a local convention is the same vectors run through two
independently written verifiers.

Both exist. `agentrust-io/ca2a` verifies delegation DAGs offline in `ca2a_verify`;
`agentrust-io/agent-manifest` exports `verify_delegation_chain`, `DelegationHopSigner` and
`delegation_depth_exceeded` from its public API. `ca2a/src/ca2a_runtime/delegation/credential.py`
states that its credentials are "cross-verifiable with agent-manifest". Nothing in any of the
three repositories tests that claim.

The proposal for the next step, which is not this document's to decide:

1. A cross-reference table between `TRACE-DELEG-*` here and ca2a's `ACTION-*` group, so an
   implementation scored under one can be read against the other.
2. A harness running these vectors through both verifiers and asserting agreement on the
   shared surface — signature validity, hop continuity, scope narrowing, depth.
3. Divergences are the output. Each is either an ambiguity in this text, which comes back
   here as a vector and a paragraph, or a defect in one implementation, which is filed
   where it lives.

The same corpus would also close a gap on the agent-manifest side: of its 21 vectors, two
touch delegation and both are single-hop, so its own narrowing and depth logic has no vector
coverage at all.

## 8. Open questions

1. **Is the credential registry the right shape?** It is modelled here as verifier context
   because nothing in the schema describes a credential. The alternative — a credential
   object in the record — is a schema change and a much larger proposal.
2. **Should `data_class` narrowing be in this profile at all?** It is the only scope-like
   comparison the current fields support, and it may belong with a general scope model
   rather than with delegation.
3. **Is `max_depth` a profile constant or deployment context?** Context here, on the grounds
   that a bound is a deployment decision, but a fixed floor would make chains portable
   between verifiers in a way this does not.
4. **Where should the cross-verifier harness live** — ca2a's tests, agent-manifest's, or a
   neutral repository? Each choice makes one implementation the host of the corpus that
   scores it.
5. **Does the leaf need to be named at all?** It is context here. A record set with two
   unreferenced records has two candidate leaves, and picking wrong verifies a different
   thing than the caller asked about.
