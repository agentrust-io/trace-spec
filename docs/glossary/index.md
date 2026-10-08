# Glossary

This page defines the terms used across the TRACE specification and these docs. Each entry starts with a plain explanation, followed by the exact technical meaning. For the basic ideas behind all the AgenTrust projects (AI agent, tool call, attestation, signed receipt, verifying offline), see [the terms in plain English](https://agentrust-io.com/#plain-terms) on the AgenTrust site.

______________________________________________________________________

**Appraisal** Checking hardware evidence against the values you expected, and writing down the verdict. The process of evaluating a TEE (trusted execution environment: a protected area of a processor whose memory the host cannot read) evidence bundle against a reference integrity manifest (RIM) to produce an `appraisal.status` verdict. An `"affirming"` verdict means the measured environment matches the expected state. Defined in IETF RFC 9334 (RATS).

______________________________________________________________________

**cnf / JWK** The public key that belongs to the record's signer, written inside the record. The TRACE `cnf` field (from RFC 7800) carries a JSON Web Key (`jwk` sub-field) that contains the Ed25519 public key used to sign the record. It is included in the signed payload so the verifier does not need to retrieve the key out-of-band. The verifier still has to compare it with a key it already trusts: a record cannot vouch for its own key (see [verification](https://trace.agentrust-io.com/docs/verification/index.md)).

______________________________________________________________________

**Conformance** Passing the official tests. A trust record is conformant if it passes all test cases required at its declared trust level. Conformance is verified by the `trace-tests` test suite. Partial conformance (record passes some but not all required tests) is not valid.

______________________________________________________________________

**EAT: Entity Attestation Token** An IETF standard format for a signed statement about a device or program, which TRACE records follow. A JWT-based format for conveying evidence about a hardware or software entity. TRACE records use the EAT `eat_profile` claim to identify the specific TRACE profile version. Defined in IETF draft-ietf-rats-eat, now published as RFC 9711.

______________________________________________________________________

**GatewayClaim** The part of a record that ties it to one session of the cMCP gateway, the component that sits between an agent and its tools. A cMCP claim embedded in a TRACE trust record that binds the record to a specific cMCP session. Contains the session ID, gateway DID, and the Cedar policy bundle hash that governed the session.

______________________________________________________________________

**Input closure** Everything a rerun of the agent would need to read, each item pinned by its fingerprint. The complete content-addressed set of everything a reproducibility claim's deterministic function reads: the initial configuration and every recorded external interaction, model calls included, each pinned as `{id, digest, resolver}`. A closure that omits anything which can change the transcript makes the claim malformed. Defined in §3.1.4 of the specification.

______________________________________________________________________

**JCS: JSON Canonicalization Scheme** A fixed way of writing JSON so the same data always produces the same bytes, which is what makes the signature repeatable. RFC 8785. A deterministic serialization of JSON objects: Unicode code-point-ordered keys, no whitespace, IEEE 754 double-precision number encoding. TRACE uses JCS to canonicalize the record before computing the Ed25519 signature.

______________________________________________________________________

**Reproducibility claim** An optional statement that running the same job again on the same inputs gives the same result. The optional `reproducibility` member of a Trust Record: a claim that re-executing a named deterministic function of the run over a pinned input closure yields a transcript whose RFC 8785 digest equals `transcript_digest`. The result of a verifier re-running it is carried under `appraisal.method: "re-execution"` as `reproduced`, `diverged` or `not-attempted`. Defined in §3.1.4 of the specification.

______________________________________________________________________

**RIM: Reference Integrity Manifest** The list of values the hardware should report if it is running the expected software. A signed document describing the expected firmware and software measurements for a TEE environment. During Level 1 appraisal, the verifier compares the TEE's runtime measurements against the RIM. The `runtime.rim_uri` field optionally points to a RIM.

______________________________________________________________________

**RATS: Remote Attestation Procedures** The IETF's standard roles for proving to someone far away what a machine is running. The IETF working group and architecture (RFC 9334) that defines the roles and flows for remote attestation: Attester (the hardware), Verifier (checks evidence against RIM), Relying Party (consumes the resulting attestation result). TRACE Level 1 and 2 follow the RATS architecture.

______________________________________________________________________

**SCITT: Supply Chain Integrity, Transparency, and Trust** A design for public logs that can only be added to, never quietly edited. An IETF draft standard for append-only transparency logs of software and attestation artifacts. TRACE Level 2 records include a SCITT receipt URI in the `transparency` field, anchoring the record to a public or shared log.

______________________________________________________________________

**SPIFFE / SPIRE** A standard way to name a running program, like a web address for a workload. SPIFFE (Secure Production Identity Framework For Everyone) defines URI-based workload identities of the form `spiffe://<trust-domain>/<workload-path>`. TRACE requires the `subject` field to be a SPIFFE URI or a DID. SPIRE is the reference implementation.

______________________________________________________________________

**Trust Level** How strong the evidence behind a record is, from software signing only (0) to hardware evidence (1) to public logging (2). A numeric value (0, 1, or 2) that summarizes the strength of the guarantees carried by a trust record. See [Trust Levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) for the full definition of each level.

______________________________________________________________________

**Trust Record** The signed receipt TRACE defines: what an agent ran, where, under which policy, touching which data. A signed JSON document emitted by an AI agent at the end of a governed session. It asserts the agent's identity, model, policy, data class, tool invocations, and (at Level 1+) hardware attestation state. Defined in full in the [TRACE Specification](https://trace.agentrust-io.com/spec/trace-v0.2/index.md).

______________________________________________________________________

**Transparency** Publishing a record to a shared log so others can audit it later. In the TRACE context, transparency means that a trust record has been submitted to an append-only log (SCITT) and can be independently audited by any party with access to the log. The `transparency` field holds the receipt URI. Required at Level 2.
