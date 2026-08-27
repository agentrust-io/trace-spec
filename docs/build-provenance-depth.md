---
description: What each build_provenance verification depth does not assure. Surface, Builder-chain and Dependency-chain, and which unknowns a deployment accepts when it stops early.
---

# Build provenance verification depth

> **Non-normative.** This page is informative. It changes no schema field, wire format, required claim or conformance requirement, and carries no uppercase RFC 2119 keyword. The depth question itself was decided on [trace-spec#50](https://github.com/agentrust-io/trace-spec/issues/50). The names *Surface*, *Builder-chain* and *Dependency-chain* used on this page are the descriptive ones; they map one to one onto the `build_provenance.provenance_depth` values `surface`, `builder` and `transitive`. [Section 3.3.1 of the specification](../spec/trace-v0.2.md#331-build-provenance-verification-depth) carries the normative rules.

[Spec section 3.3](../spec/trace-v0.2.md) step 7 is one sentence: *"SLSA provenance resolves to a trusted builder."* It does not say how far the verifier walks, and three stopping points satisfy it. They are not equally strong, and the weakest is the cheapest to implement.

So this page states what each depth does **not** assure. A deployment picking a depth is choosing which unknowns it accepts, and that choice is invisible if the depths are described only by what they check.

## The three stopping points

| Depth | Additionally checks | Reads |
|---|---|---|
| Surface | `build_provenance.digest` matches the artifact the verifier holds; `builder` is in a trusted set | The record |
| Builder-chain | The attestation at `provenance_uri` binds to that digest and names that builder | The record, plus one attestation |
| Dependency-chain | Each build input the attestation declares resolves to a publisher attestation under a trusted identity | The record, plus one attestation, plus one per input |

The depths stack: a dependency-chain verifier performs the builder-chain and surface checks too.

## Surface

**What it checks.** Two comparisons. The digest in the record against the digest of the artifact the verifier is about to run, and the `builder` string against a configured trusted set. No fetch, no attestation parsing, no network.

**What it does not assure.** Anything about who built the artifact. `builder` is a string the issuer wrote next to a digest, and nothing read at this depth binds the two. What a surface check supports is "someone the verifier trusts is *named next to* this artifact", not "someone the verifier trusts built it". The two claims come apart exactly when the issuer is the problem, which is the case the evidence exists for.

It also does not assure that the record names a builder at all. In [`schema/trace-claim.json`](schema.md) only `slsa_level` and `digest` are required; `builder` and `provenance_uri` are optional, and the reference model accepts a record without either. A schema-valid `build_provenance` can be a digest and the integer `3`. Nor does any depth on this page check a claimed `slsa_level` against evidence: that integer is issuer-written at every depth, including the deepest.

**What it leaves open.** An attestation that is well-formed, signed and names a trusted builder, but whose subject is a different artifact. Or one that names a different builder inside than the record does. A surface check never opens the attestation, so both pass.

## Builder-chain

**What it checks.** Resolve `provenance_uri`, then check that the attestation's subject digest is the artifact digest and that the builder identity inside the attestation is the one the record claims. After this, a specific builder is bound to this specific artifact.

**What it does not assure.** Anything about what went into the build. The inputs are listed inside the same attestation the builder produced, and a poisoned input consumed by a legitimate builder yields an attestation that passes every builder-chain check: correct subject, correct builder, valid signature. [Spec section 2.2](../spec/trace-v0.2.md) puts that adversary in scope by name: *"Malicious or compromised dependency. A poisoned model artifact, agent package, container base image, or transitive build-chain dependency."* Builder-chain verification does not reach the transitive half of it.

Nor does it assure the artifact was built from the source you think. A trusted builder faithfully builds whatever it is pointed at, and nothing at this depth compares the source reference inside the attestation against the repository and ref the deployment expects.

**What it leaves open.** A build input with no publisher attestation at all, an input whose attestation was signed under an identity the verifier does not trust, and an attestation that declares no inputs whatsoever. All three are indistinguishable from a clean build at this depth.

## Dependency-chain

**What it checks.** Walk the build inputs the attestation declares. For each, resolve a publisher attestation and check it was signed under a trusted issuer identity.

**What it does not assure.**

**Completeness of the input list.** The declared inputs are what the builder recorded, not what the build read. An input fetched outside the declared graph appears nowhere, and a verifier walking the list cannot tell a complete list from a short one. An attestation declaring no inputs passes a dependency loop vacuously: zero inputs, zero failures, and the same verdict as a fully attested build.

**Transitivity, despite the name.** This is one hop. The inputs of the inputs are not walked unless each publisher attestation is itself dependency-chain verified, and in practice they are not.

**That a trusted publisher's package is safe.** Publisher identity is not code review. A maintainer whose signing identity is compromised publishes under the identity the verifier trusts, and the input verifies.

**Anything about the model.** `build_provenance` covers the workload, which the schema describes as agent code and container image. The weights the workload loads are described by the `model` claim and sit outside all three depths.

## What no depth assures

- **Signature validity.** That is a different axis, not a deeper one. The record's own signature binding is [step 1](../spec/trace-v0.2.md) and precedes all of this; walking deeper never rescues a record whose binding fails, and stopping shallow never excuses skipping it.
- **Current trust in the identities walked.** Depth measures how far back the walk goes, not whether the keys along it are still trusted at verification time. Offline verification cannot establish non-revocation for any of them; see [Limitations](../LIMITATIONS.md) and the [revocation store](verification.md#checking-revocation-status).
- **Anything about execution.** All three describe how the artifact was built. What it then did under policy is `runtime`, `policy` and `tool_transcript`, and a perfect dependency chain says nothing about any of them.

## Choosing a depth

| Depth | What the verifier needs | What happens when the ecosystem does not cooperate |
|---|---|---|
| Surface | The artifact digest and a trusted-builder list | Nothing. It always runs. |
| Builder-chain | Attestation retrieval at verification time, or a cached bundle | A record whose `provenance_uri` is absent or unresolvable cannot be verified past surface |
| Dependency-chain | A publisher attestation per input, and ecosystem coverage for those inputs | Inputs from ecosystems without attestation coverage cannot be verified past builder, benign ones included |

Deeper is not free, and the honest reason deployments stop early is usually not laziness. An unattested input is unverifiable rather than incriminating, so [verification.md](verification.md) has the verifier record `builder` and name what it could not fetch; a deployment whose floor is `transitive` then treats that record as `contraindicated`. Attestation coverage across package ecosystems is uneven, so such a deployment turns away a lot of software that is fine: the strictness lives in the floor, not in a finding against the record.

That trade-off is a legitimate choice. Picking Surface because it was the cheapest to implement, without recording that "trusted builder" is then a claim nobody checked, is not the same choice.

## Related

- [trace-spec#50](https://github.com/agentrust-io/trace-spec/issues/50): where the depth definition is being decided.
- [trace-spec#166](https://github.com/agentrust-io/trace-spec/pull/166): test vectors separating the three depths, each accepted by the depth below it and rejected by the depth in its name.
- [Verification protocol](verification.md): the record-level steps this page sits underneath.
- [Known limitations](../LIMITATIONS.md): what a TRACE claim does not prevent, at record level.
