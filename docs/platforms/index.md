# Attestation Platforms

This page is for anyone deciding which kind of machine can back a TRACE record with hardware evidence. It lists the processors and GPUs TRACE names, what evidence each one produces, and what you still have to check yourself.

Some processors can run a program in a sealed-off area called a trusted execution environment (TEE) and then produce a signed report, called an attestation, that describes what is running inside. That report is what hardware evidence means here. A record that carries checked hardware evidence can reach TRACE Level 1, and Level 2 adds a public log entry (transparency anchoring) on top.

Choosing a hardware platform does not give a record either level by itself. Whoever receives the record must check the evidence and confirm it is tied to the key that signed the record.

## Platform names and evidence

A standalone TRACE record names its platform in the `runtime.platform` field, using the values in the [canonical schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json). Other tools have their own names: cMCP's configuration names `sev-snp`, `tdx` and `opaque` are not the same values and cannot be swapped in.

| Platform guide                                                                    | Standalone `runtime.platform`                             | Evidence to appraise                                                              |
| --------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [AMD SEV-SNP](https://trace.agentrust-io.com/docs/platforms/amd-sev-snp/index.md) | `amd-sev-snp` or the profile-specific `azure-cvm-sev-snp` | Signed SNP report, certificate chain, measurement, and key/challenge binding      |
| [Intel TDX](https://trace.agentrust-io.com/docs/platforms/intel-tdx/index.md)     | `intel-tdx`                                               | Signed TD quote, collateral, measurement registers, and key/challenge binding     |
| [NVIDIA H100](https://trace.agentrust-io.com/docs/platforms/nvidia-h100/index.md) | `nvidia-h100`                                             | GPU attestation evidence and its explicit binding to the workload and signing key |
| TPM2                                                                              | `tpm2`                                                    | Quote, selected PCRs, trusted attestation-key provenance, and challenge binding   |
| Software                                                                          | `software-only`                                           | Software signature and producer-defined commitments; no hardware assurance        |

In the table, a measurement is a fingerprint (a hash) of the code and settings the hardware loaded, and a quote or report is the signed statement that carries it. "Appraise" means checking that evidence against trusted roots and expected values.

The schema also lists other platform names. Listing a name does not mean this Python library (the TRACE SDK) collects or checks evidence for that platform.

## Vendor annexes

A vendor annex is a page that shows how one specific product fills in a TRACE record. Annexes are informative (they bind no one) and are reviewed by the vendor author and one Maintainer, per GOVERNANCE.

| Annex                                                                         | `runtime.platform` | What the producer's evidence is                                                                                                                               |
| ----------------------------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Bernstein](https://trace.agentrust-io.com/docs/platforms/bernstein/index.md) | `software-only`    | An Ed25519-signed record over a hash-chained run journal, with a deterministic coordination sequence a verifier can re-derive. No hardware assurance; Level 0 |

## What the SDK checks

`agentrust_trace.verify_record` checks the standalone record's schema, profile, signature against a trusted key, freshness, and configured nonce/revocation inputs. It does not collect a hardware quote or turn a platform string into verified hardware evidence. There is no `agentrust-trace verify-hardware` command in this package.

To check hardware evidence, use a verifier built for the runtime that produced it and for that evidence format. For cMCP's own `RuntimeClaim` envelope, follow [cMCP verification](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) and its [hardware-validation record](https://cmcp.agentrust-io.com/testing/hardware-validation/).

Continue to [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) or [interpreting hardware evidence](https://trace.agentrust-io.com/docs/tutorials/hardware-attestation-platforms/index.md).
