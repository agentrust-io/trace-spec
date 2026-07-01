# Glossary

Terms used in the TRACE specification and documentation.

______________________________________________________________________

**Appraisal** The process of evaluating a TEE evidence bundle against a reference integrity manifest (RIM) to produce an `appraisal.status` verdict. An `"affirming"` verdict means the measured environment matches the expected state. Defined in IETF RFC 9334 (RATS).

______________________________________________________________________

**cnf / JWK** The TRACE `cnf` field (from RFC 7800) carries a JSON Web Key (`jwk` sub-field) that contains the Ed25519 public key used to sign the record. It is included in the signed payload so the verifier does not need to retrieve the key out-of-band.

______________________________________________________________________

**Conformance** A trust record is conformant if it passes all test cases required at its declared trust level. Conformance is verified by the `trace-tests` test suite. Partial conformance (record passes some but not all required tests) is not valid.

______________________________________________________________________

**EAT — Entity Attestation Token** A JWT-based format for conveying evidence about a hardware or software entity. TRACE records use the EAT `eat_profile` claim to identify the specific TRACE profile version. Defined in IETF draft-ietf-rats-eat.

______________________________________________________________________

**GatewayClaim** A cMCP claim embedded in a TRACE trust record that binds the record to a specific cMCP session. Contains the session ID, gateway DID, and the Cedar policy bundle hash that governed the session.

______________________________________________________________________

**JCS — JSON Canonicalization Scheme** RFC 8785. A deterministic serialization of JSON objects: Unicode code-point-ordered keys, no whitespace, IEEE 754 double-precision number encoding. TRACE uses JCS to canonicalize the record before computing the Ed25519 signature.

______________________________________________________________________

**RIM — Reference Integrity Manifest** A signed document describing the expected firmware and software measurements for a TEE environment. During Level 1 appraisal, the verifier compares the TEE's runtime measurements against the RIM. The `runtime.rim_uri` field optionally points to a RIM.

______________________________________________________________________

**RATS — Remote Attestation Procedures** The IETF working group and architecture (RFC 9334) that defines the roles and flows for remote attestation: Attester (the hardware), Verifier (checks evidence against RIM), Relying Party (consumes the resulting attestation result). TRACE Level 1 and 2 follow the RATS architecture.

______________________________________________________________________

**SCITT — Supply Chain Integrity, Transparency, and Trust** An IETF draft standard for append-only transparency logs of software and attestation artifacts. TRACE Level 2 records include a SCITT receipt URI in the `transparency` field, anchoring the record to a public or shared log.

______________________________________________________________________

**SPIFFE / SPIRE** SPIFFE (Secure Production Identity Framework For Everyone) defines URI-based workload identities of the form `spiffe://<trust-domain>/<workload-path>`. TRACE requires the `subject` field to be a SPIFFE URI or a DID. SPIRE is the reference implementation.

______________________________________________________________________

**Trust Level** A numeric value (0, 1, or 2) that summarizes the strength of the guarantees carried by a trust record. See [Trust Levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) for the full definition of each level.

______________________________________________________________________

**Trust Record** A signed JSON document emitted by an AI agent at the end of a governed session. It asserts the agent's identity, model, policy, data class, tool invocations, and (at Level 1+) hardware attestation state. Defined in full in the [TRACE Specification](https://trace.agentrust-io.com/spec/trace-v0.1/index.md).

______________________________________________________________________

**Transparency** In the TRACE context, transparency means that a trust record has been submitted to an append-only log (SCITT) and can be independently audited by any party with access to the log. The `transparency` field holds the receipt URI. Required at Level 2.
