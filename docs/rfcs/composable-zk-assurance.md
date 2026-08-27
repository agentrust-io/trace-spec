# RFC Proposal: Composable Zero-Knowledge Proofs for TRACE

**Status:** Draft issue proposal
**Author:** Florian Kluge
**Contact:** florian.kluge@o1labs.org
**Organisation:** o1Labs
**Scope:** Informative assurance-model proposal; normative implementation requires follow-up changes
**Target:** TRACE specification
**Primary topic:** Zero-knowledge proof as a composable mechanism

## Summary

TRACE currently describes trust through software signing, hardware-backed attestation and transparency mechanisms.

This proposal adds **zero-knowledge proofs** as an additional mechanism that can compose with the existing TRACE model.

**TEE attestation and ZK proofs establish different properties.** TEE attestation can establish properties about the measured runtime and execution boundary, while ZK can establish properties about a defined computation. They can therefore be used independently or composed when both types of assurance are required.

The proposal does not define zero-knowledge proofs as a trust level above or below a Trusted Execution Environment. ZK proofs and TEEs provide different security properties and rely on different trust assumptions. A ZK-based assurance composition relies on the soundness of the proof system, the correct identification of the proven program or policy, authenticated and committed inputs and correct proof verification. A TEE-based assurance composition relies on the hardware vendor and attestation chain, the measured workload and the correct deployment of the trusted runtime. In return, ZK can provide independently verifiable computation integrity without trusted hardware, while a TEE can provide runtime isolation, host confidentiality and protected credential handling. The two mechanisms can be used independently or composed when an implementation requires both sets of properties.

Instead, TRACE should support a **non-linear, composable assurance model**. An implementer can select and combine assurance mechanisms according to the required **security, privacy, verification and deployment properties**.

For example, ZK can provide independently verifiable computation without trusted hardware or selectively prove claims about TEE-attested execution without disclosing the underlying execution data.

For example:

```
TRACE
    |
    +-- Software evidence
    |
    +-- Computation assurance
    |      |
    |      +-- Zero-knowledge proof
    |
    +-- Runtime assurance
    |      |
    |      +-- Trusted Execution Environment
    |
    +-- Transparency/durability
           |
           +-- SCITT
```

_SCITT = Supply Chain Integrity, Transparency and Trust, a transparency architecture that can provide durable, independently verifiable evidence._

These branches can exist independently where the applicable assurance composition permits it or they can combine into a stronger assurance composition for a specific set of security properties.

## Motivation

A **Trusted Execution Environment (TEE)** is a hardware-backed isolated execution environment. A TEE can provide runtime isolation, hardware-rooted attestation, host confidentiality and protected credential handling.

A **proof of computation** is a cryptographic proof that lets a verifier check that a defined computation was performed correctly. For TRACE, this can provide independently verifiable evidence that an identified program evaluated committed inputs and produced a claimed result. Zero knowledge is an additional privacy property: where supported by the selected proof system and configuration, the proof can establish the claim without revealing the private witness.

These mechanisms answer different questions.

A TEE can answer questions such as:

- Did this measured workload execute in an attested protected environment?
- Was the signing or credential key bound to that environment?
- Was sensitive runtime state protected from the host?

A ZK proof can answer questions such as:

- Did the identified program evaluate the committed inputs according to the specified computation?
- Did the computation produce this decision or state transition?
- Does a committed execution transcript satisfy a defined policy claim without revealing the underlying private values or full transcript?

Because ZK proofs and TEEs provide assurance about different properties, they cannot be placed in a single general hierarchy. An assurance composition can provide stronger assurance for one property while providing less assurance for another.

For example, ZK can provide independently verifiable computation integrity, while a TEE can provide runtime isolation, confidentiality and protected credential handling. The next section expands on this distinction and defines a composable assurance model for TRACE.

## Proposed model: composable assurance

This section expands on the distinction above by modeling TRACE assurance as a set of mechanisms that can fan out across different assurance properties and recombine when multiple properties are required.

An **assurance composition** is the set of assurance mechanisms that support the claims made by a TRACE record.

Conceptually:

```
                    TRACE assurance composition
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
  Computation assurance   Runtime assurance   Evidence durability
          |                   |                   |
      +---+---+               TEE                 SCITT
      |       |
  Software   ZK
              \
               +-----------+
                           |
                      can compose
                       with TEE
                           |
                           v
                        TEE + ZK
```

ZK and TEE are **peer assurance mechanisms**. Neither mechanism is defined as the parent or child of the other.

The model can fan out according to the assurance property that an implementation requires and recombine when multiple properties are required.

Example assurance compositions include:

```
A. Software TRACE

B. TRACE + ZK

C. TRACE + TEE

D. TRACE + TEE + ZK

E. TRACE + TEE + SCITT

F. TRACE + TEE + ZK + SCITT
```

The existing TRACE trust levels do not currently express all of the assurance compositions described here.

In particular, a ZK-only assurance composition can provide independently verifiable computation assurance while still using a software runtime. Under the current linear runtime-oriented trust-level model, that assurance composition remains associated with the software-only level even though it provides an additional cryptographic assurance property.

This RFC therefore does not propose mapping ZK onto a new position in the existing trust-level ladder. Instead, it identifies a need for follow-up conformance work so that relying parties can evaluate orthogonal assurance properties without reducing them to a single scalar level.

Future normative work will need to address §7 conformance and the `TR-RTE` runtime checks so that relying parties can represent ZK computation assurance independently of hardware-runtime assurance.

## Relying-party interpretation

An assurance composition must distinguish between:

1. **evidence presence**: the record contains or references an assurance artifact;
2. **evidence verification**: the artifact has been successfully verified under a defined verification policy and context;
3. **claim support**: the verified artifact is cryptographically and semantically bound to the specific TRACE claim being evaluated.

Evidence presence alone does not establish assurance.

Conceptually:

```text
TRACE claim
    |
    v
evidence reference
    |
    v
verification under policy/context
    |
    v
claim supported
```

A relying party should only treat a claim as supported when the required evidence verifies successfully and is bound to that claim.

The assurance composition must also define how multiple mechanisms relate to a claim. Where several mechanisms are required together, all required mechanisms must verify (`AND`). Where an assurance composition permits alternative mechanisms, successful verification of one permitted mechanism can be sufficient (`OR`). The applicable rule must be explicit rather than inferred from evidence presence.

A relying party should handle the following cases explicitly:

- **Unsupported mechanism:** the relying party must not treat the associated claim as verified through that mechanism.
- **Verification failure:** the associated assurance claim fails.
- **Valid but unrelated evidence:** evidence that verifies successfully but is not bound to the claim being evaluated does not support that claim.
- **Multiple mechanisms:** the verifier must apply the assurance composition's explicit AND/OR requirements.

## Assurance dimensions

The following dimensions show why the model is non-linear.

### 1. Computation integrity

**Computation integrity** means evidence that an identified computation produced a claimed result from defined or committed inputs.

Possible mechanisms include:

- software assertion;
- ZK proof

A ZK proof can give an independent verifier evidence of the computation without requiring the verifier to trust the operator that executed the computation.

### 2. Runtime integrity and confidentiality

**Runtime integrity** means evidence about the identity and measured state of the execution environment.

**Runtime confidentiality** means protection of sensitive runtime state from an untrusted host, subject to the guarantees and limitations of the selected TEE platform.

Possible mechanisms include:

- TEE attestation;
- TEE-bound signing or credential keys

A ZK proof alone does not provide these runtime properties.

### ZK trust assumptions

A ZK-based assurance composition has its own Trusted Computing Base (TCB). Its guarantees depend on at least:

- the soundness of the selected proof system;
- correct implementation of the verifier;
- correct identification of the program or policy being proven;
- correct binding of public inputs and commitments to the corresponding TRACE claims;
- the integrity of proving and verification parameters;
- setup integrity where the selected proof system requires a trusted or structured setup.

These assumptions are proof-system dependent. For example, some proof systems require no trusted setup, while others rely on circuit-specific or universal setup parameters.

TRACE can remain proof-system neutral at the assurance-model level, but a concrete ZK assurance composition must identify the proof system and the assumptions required to verify its claims.

A future normative ZK assurance composition should extend §2.3 so that TRACE soundness is conditional on the TCB of the selected assurance mechanisms rather than only on a silicon root of trust.

### 3. Input authenticity

**Input authenticity** means evidence that an input came from the claimed source and that the proof or record is bound to that exact input.

Possible mechanisms can include:

- TEE-signed transcript commitments;
- signed tool receipts;
- authenticated external data;
- cryptographically authenticated messages

A valid ZK proof only proves the statement that was encoded in the proof. If an input is not authenticated, the proof does not establish that the input represents the claimed external event.

### 4. Proof-gated downstream actions

A verified ZK proof can be used to **gate a downstream action**. The proof verifier and the enforcement point do not need to run inside the TEE.

For example, an external credential or tool gateway can verify the proof before releasing a credential, forwarding a request, or allowing an action to proceed. The gateway must verify both the validity of the proof and its applicability to the current request. The proven statement must bind the intended action or audience, authorization scope, relevant session or state, and freshness information such as an expiry or nonce.

The gateway must fail closed for missing, invalid, stale, replayed, mismatched, or unsupported proofs.

```
Proven execution
      |
      v
   ZK proof
      |
      v
External verifier / gate
    - verify proof
    - verify request/context binding
      |
      v
Downstream action
```

This allows the TEE, the proof system and the enforcement point to remain separate components while still making the downstream action conditional on successful proof verification.

### 5. Evidence durability and transparency

**Evidence durability** means that an issued record cannot be silently removed, replaced or rewritten without detection.

A mechanism such as **SCITT (Supply Chain Integrity, Transparency and Trust)** can provide append-only transparency evidence.

This dimension is independent of whether computation assurance is based on software, ZK, TEE or a combination. The resulting evidence can also be verified by an external party, without requiring that verifier to participate in the original execution environment.

### 6. Privacy

Privacy is not implied by the presence of a computation proof. It requires that the selected proof system and configuration provide the required zero-knowledge guarantees for the relevant private witness.

**Privacy assurance** means that a verifier can confirm a required claim without receiving the complete underlying data. ZK can provide this by proving statements over private inputs, committed execution data or authenticated receipts while keeping sensitive values hidden.

For example, a verifier could confirm that all payments in a session were below EUR 10,000, that only approved tools were used or that an external service returned an acceptable result without seeing the full transcript, exact values, or complete receipt. In a TEE + ZK assurance composition, the TEE can authenticate the underlying execution evidence, while ZK enables selective disclosure of only the claims the verifier needs.

## ZK assurance branch

A ZK-enabled TRACE record can bind a proof to values such as:

```
program_id
policy_hash
input_commitment
session_state_commitment
destination_or_tool
decision_or_output_commitment
```

`program_id` is security-critical: it identifies the exact computation whose execution the proof attests to. A verifier must not treat two programs as equivalent unless their identifiers resolve to the same defined computation under the applicable verification rules.

A concrete ZK assurance composition must define a canonical derivation and comparison rule for `program_id` that uniquely identifies the verifier-relevant computation. Human-readable names or implementation-local identifiers are insufficient.

The proof and the TRACE record must also satisfy a **same-values binding** requirement. The public inputs and commitments verified by the proof must be cryptographically bound to the exact corresponding TRACE claims, or to an unambiguous digest of those claims.

A valid proof and a valid TRACE signature are not sufficient if they can refer to different program, input, state, destination, or output values.

The binding must define:

- an unambiguous mapping between proof public inputs and TRACE claims;
- canonical encoding of values before commitment;
- domain separation for commitments or hashes used for different purposes;
- explicit algorithm identifiers where cryptographic algorithms are used.

The exact wire-format fields remain outside the initial scope of this proposal. However, computation identity and same-values binding are requirements of the assurance model and must be defined unambiguously by any concrete assurance composition.

The verifier can use the proof to establish a statement such as:

> The program identified by `program_id` evaluated the inputs bound by `input_commitment` under the policy identified by `policy_hash` and produced the decision bound by `decision_or_output_commitment`.

This provides a hardware-independent path for computation assurance.

## TEE + ZK composition

ZK can also add computation assurance to a TEE-backed TRACE deployment.

The transcript commitment used as an input to the ZK proof must be the same commitment authenticated by the TEE evidence. Independently valid TEE evidence and independently valid ZK evidence do not establish a composed claim unless this binding is verified.

For example, a cMCP gateway can authenticate runtime events inside a TEE and create a signed commitment to the execution transcript.

A ZK prover can then prove a policy statement over that commitment.

```
TEE/cMCP
    |
    v
Authenticated execution transcript
    |
    v
Signed transcript commitment
    |
    v
ZK policy proof
    |
    v
TRACE evidence
    |
    v
Verifier
```

Example statement:

> Every payment in this committed session was below EUR 10,000 and used only approved tools.

The verifier can validate the policy claim without receiving the complete private transcript.

This composition provides different layers of assurance:

- the TEE authenticates and protects the runtime boundary;
- the transcript commitment (TEE attestation) binds the evidence to the authenticated execution;
- the ZK proof establishes the specified computation or policy claim;
- a transparency mechanism can add durable evidence

## Security properties

The mechanisms provide different properties.

| Security property                                              | Software | ZK                                                              | TEE                                         | TEE + ZK                                                                                                  |
| -------------------------------------------------------------- | -------- | --------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Records a policy decision                                      | Yes      | Yes                                                             | Yes                                         | Yes                                                                                                       |
| Independently proves a specified computation                   | No       | Yes                                                             | No, unless separately proven                | Yes                                                                                                       |
| Independently verifiable computation without trusted hardware  | No       | Yes                                                             | No                                          | Yes for computation; the overall assurance composition additionally depends on the TEE for runtime claims |
| Attests a measured protected runtime                           | No       | No                                                              | Yes                                         | Yes                                                                                                       |
| Protects runtime secrets from the host                         | No       | No                                                              | Yes, subject to TEE guarantees              | Yes, subject to TEE guarantees                                                                            |
| Can protect runtime credentials                                | No       | No                                                              | Yes                                         | Yes                                                                                                       |
| Can prove selective claims without disclosing the full witness | No       | Yes, when zero knowledge is provided by the proof configuration | No                                          | Yes                                                                                                       |
| Can support proof-gated action enforcement                     | No       | Yes, with a proof-verifying enforcement point                   | No, unless the TEE controls the action path | Yes                                                                                                       |

Transparency and durability mechanisms can compose with compatible assurance compositions independently of this table. They can also provide durable, externally verifiable evidence that a verifier or downstream gate can rely on after the original execution has completed.

## Non-goals

This proposal does not claim that ZK is a general replacement for TEE execution.

A ZK proof alone does not prove:

- that external inputs are authentic;
- that the operator could not bypass the proven path;
- that credentials were protected from the host;
- that private runtime state remained confidential;
- that an external tool performed the requested operation;
- that a physical or business outcome completed

These properties require separate assurance mechanisms.

This proposal also does not claim that TEE attestation proves semantic policy correctness. TEE attestation can establish properties about the measured runtime and the execution boundary, while ZK can establish properties about a defined computation.

## Proposed TRACE change

Add a proof-system-neutral ZK assurance mechanism to TRACE.

The specification should define how ZK evidence can:

1. attach to a software-backed TRACE record;
2. compose with a TEE-attested TRACE record;
3. bind to authenticated inputs or transcript commitments;
4. bind to the relevant program, policy, state, destination and decision;
5. support real-time enforcement when a verifier checks the proof before an action;
6. support post-hoc evidence when proof verification occurs after an action

ZK assurance should be represented as an orthogonal, composable assurance mechanism rather than a new linear trust level. Follow-up normative work is required so that conformance and relying-party evaluation can represent the assurance compositions described here without reducing them to a single scalar trust level.

## Compatibility

This RFC is informative and does not itself change TRACE conformance. Implementing the proposed assurance model in the current TRACE record format requires normative schema, verifier, and conformance work.

The current TRACE schema does not provide a generic extension point for unknown assurance evidence. A ZK evidence block therefore cannot be added to an existing TRACE record and ignored by older verifiers. A verifier that validates the current closed schema will reject an unknown field.

A future normative ZK EAT profile should define ZK evidence as an explicit signed TRACE member, following the existing pattern used for optional evidence fields. This keeps the evidence inside the signed TRACE record and therefore binds its integrity to the record signature.

Existing TRACE records that do not contain ZK evidence should remain valid. However, a verifier must explicitly support the future ZK evidence representation before it can accept and evaluate a TRACE record that uses that assurance composition.

A normative ZK representation also requires a distinct EAT profile identifier under the current TRACE versioning model.

The current `trace-v0.2` profile identifies the semantics defined by TRACE v0.2, and existing v0.2 verifiers require that exact identifier before verification. A record that introduces additional ZK assurance semantics therefore cannot continue to identify itself as `trace-v0.2` without changing the meaning of that profile identifier.

Future normative work should define a new EAT profile identifier for TRACE records that carry ZK assurance semantics. If TRACE later introduces explicit compatible-version or extension semantics for `eat_profile`, that versioning model can be revisited separately.

This also gives existing v0.2 verifiers the correct fail-closed behavior: they can reject a ZK-bearing record as using an unsupported EAT profile before attempting schema or cryptographic verification, rather than treating the record as malformed v0.2.

The exact schema fields and verifier behavior remain follow-up normative work.

## Next Steps

Detailed wire-format changes, required fields, proof-system identifiers and conformance requirements can be specified in follow-up work after the assurance model is accepted. Follow-up normative work must define the EAT profile identifier for TRACE records that carry ZK assurance semantics. Any future compatible-version or extension mechanism for `eat_profile` is a separate TRACE versioning concern and is outside the scope of this RFC. This RFC is proof-system neutral and does not require a specific ZK proof system; the choice of proving system remains an implementation detail.
