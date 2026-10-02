# Test Modules

The TRACE conformance suite is divided into eight modules. Each module maps to a section of the TRACE specification.

| Module | ID Prefix | Spec Section | What It Tests |
|--------|-----------|--------------|---------------|
| [Envelope](modules/tr-env.md) | TR-ENV | §3.2 | `eat_profile` URI, `iat` validity, `subject` form, presence of `cnf.jwk.kty` |
| [Signature](modules/tr-sig.md) | TR-SIG | §3.2.1 | Private key leak detection, key type support, and the Ed25519 signature verification outcome |
| [Runtime](modules/tr-rte.md) | TR-RTE | §3.1 | TEE platform enum, measurement format, RIM URI scheme, and verifier-issued nonce comparison |
| [Policy](modules/tr-pol.md) | TR-POL | §3.1 | Policy bundle hash format, enforcement mode values, and whether the bundle at `policy_uri` has the declared digest |
| [Appraisal](modules/tr-apr.md) | TR-APR | §3.1 | Appraisal status enum, verifier URI form, `policy_ref` URI form, and timestamp plausibility. The appraisal policy is never resolved |
| [Transcript](modules/tr-txn.md) | TR-TXN | §3.1 | Tool-call transcript hash binding |
| [Transparency](modules/tr-anc.md) | TR-ANC | §3.2 | SCITT receipt URI form (TR-ANC-001), and offline replay of the inclusion proof against the committed Merkle root when a receipt is supplied (TR-ANC-002). The URI itself is never resolved |
| [Provenance](modules/tr-sca.md) | TR-SCA | §3.1 | SLSA provenance level and digest format |
