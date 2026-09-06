# Interpreting Hardware Attestation

A platform name and measurement in a signed TRACE record are claims. To treat them as hardware evidence, a recipient needs authenticated attestation evidence, accepted reference values, and a binding to the signing key. This guide explains that distinction; it does not provision a TEE.

## Start with the right format

Standalone TRACE records use the [canonical schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json). cMCP emits a distinct `RuntimeClaim` envelope and uses its own verifier. Do not pass that envelope directly to `agentrust_trace.verify_record`.

| Evidence | What the recipient checks |
|---|---|
| Signed record | Schema, supported profile, trusted signing key, signature, freshness, configured revocation and nonce checks |
| Hardware report or quote | Signature chain and collateral, platform policy, expected measurement, fresh challenge |
| Key binding | The authenticated report binds this record-signing key under the producing profile |
| Policy and transcript | Independently obtained artifacts match the signed commitments; their meaning depends on the producer |
| Transparency | Inclusion proof and an independently trusted log/checkpoint; a URL alone is insufficient |

## Software-only records

`runtime.platform="software-only"` carries no hardware assurance. Its measurement can be a producer-defined software commitment; all-zero is appropriate only when no commitment is offered. Software-signed records can support uses whose trust policy accepts software key custody. They must not satisfy a requirement for verified hardware evidence.

## Hardware-specific evidence

- [AMD SEV-SNP](../platforms/amd-sev-snp.md): distinguish the launch measurement from guest-supplied report data.
- [Intel TDX](../platforms/intel-tdx.md): interpret MRTD and RTMRs under the producing profile.
- [NVIDIA H100](../platforms/nvidia-h100.md): GPU appraisal does not automatically establish CPU workload or signing-key identity.
- TPM2: a quote and trusted attestation key can establish measured-state evidence. A TPM is not a general-purpose enclave for the application; it does not by itself protect agent process memory from the host OS. See [cMCP's TPM security model](https://cmcp.agentrust-io.com/spec/tpm-security-model/).

## What the TRACE SDK does

`verify_record` verifies the standalone signed object. It does not collect or appraise hardware quotes, fetch a Reference Integrity Manifest, or independently substantiate `appraisal.status`. There is no `verify-hardware` command in this package.

For cMCP evidence, use its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/), approved policy/catalog hashes, and required attestation inputs. For a local software example, use [quick start](../quickstart.md).

## Report the checks performed

Hardware appraisal corresponds to Level 1; Level 2 adds transparency anchoring. Report unavailable evidence as unavailable, and a contradictory result as a failure. A record that says `affirming` does not authorize an action without the recipient's own acceptance policy. See [trust levels](../trust-levels.md) and [verification outcomes](../verification-outcome-statements.md).
