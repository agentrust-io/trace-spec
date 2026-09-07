# Attestation Platforms

Hardware evidence can support TRACE Level 1. Level 2 additionally requires transparency anchoring; selecting a hardware platform does not establish either level by itself. A recipient must verify the evidence and its binding to the record-signing key.

## Platform names and evidence

Standalone TRACE records use the names in the [canonical schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json). Runtime configuration names such as cMCP's `sev-snp`, `tdx`, and `opaque` are not interchangeable with these wire values.

| Platform guide | Standalone `runtime.platform` | Evidence to appraise |
|---|---|---|
| [AMD SEV-SNP](amd-sev-snp.md) | `amd-sev-snp` or the profile-specific `azure-cvm-sev-snp` | Signed SNP report, certificate chain, measurement, and key/challenge binding |
| [Intel TDX](intel-tdx.md) | `intel-tdx` | Signed TD quote, collateral, measurement registers, and key/challenge binding |
| [NVIDIA H100](nvidia-h100.md) | `nvidia-h100` | GPU attestation evidence and its explicit binding to the workload and signing key |
| TPM2 | `tpm2` | Quote, selected PCRs, trusted attestation-key provenance, and challenge binding |
| Software | `software-only` | Software signature and producer-defined commitments; no hardware assurance |

The schema also registers other platform identifiers. Registration is not a claim that this Python SDK collects or appraises evidence for every platform.

## What the SDK checks

`agentrust_trace.verify_record` checks the standalone record's schema, profile, signature against a trusted key, freshness, and configured nonce/revocation inputs. It does not collect a hardware quote or turn a platform string into verified hardware evidence. There is no `agentrust-trace verify-hardware` command in this package.

Use a verifier for the producing runtime and evidence format. For cMCP's distinct `RuntimeClaim` envelope, follow [cMCP verification](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) and its [hardware-validation record](https://cmcp.agentrust-io.com/testing/hardware-validation/).

Continue to [trust levels](../trust-levels.md) or [interpreting hardware evidence](../tutorials/hardware-attestation-platforms.md).
