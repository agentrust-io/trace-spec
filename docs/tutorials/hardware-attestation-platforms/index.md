# Interpreting Hardware Attestation

This page is for anyone deciding whether a TRACE record really came from protected hardware. A record can name a hardware platform and a measurement (a fingerprint of the software that was loaded), but those are only the producer's claims until someone checks them. You will learn what has to be checked before you can rely on them.

To count as hardware evidence, a recipient needs three things: attestation (a report signed by the processor itself, checked back to the chip maker), the expected measurement values the recipient has approved, and proof that the report is tied to the key that signed the record. This guide explains that difference; it does not set up a TEE (trusted execution environment, a sealed area of the processor that even the machine's operator cannot look into).

## Start with the right format

TRACE records and cMCP session claims are two different file formats, and each has its own checker.

Standalone TRACE records use the [canonical schema](https://github.com/agentrust-io/trace-spec/blob/main/schema/trace-claim.json). cMCP emits a distinct `RuntimeClaim` envelope and uses its own verifier. Do not pass that envelope directly to `agentrust_trace.verify_record`.

The table lists each piece of evidence and what the recipient has to check before relying on it.

| Evidence                 | What the recipient checks                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Signed record            | Schema, supported profile, trusted signing key, signature, freshness, configured revocation and nonce checks |
| Hardware report or quote | Signature chain and collateral, platform policy, expected measurement, fresh challenge                       |
| Key binding              | The authenticated report binds this record-signing key under the producing profile                           |
| Policy and transcript    | Independently obtained artifacts match the signed commitments; their meaning depends on the producer         |
| Transparency             | Inclusion proof and an independently trusted log/checkpoint; a URL alone is insufficient                     |

## Software-only records

`runtime.platform="software-only"` means there is no hardware protection behind the record. Its measurement can be a fingerprint the producer chose to describe its software; all zeros means the producer offers none. A software-signed record is fine where your rules accept a signing key kept in ordinary software. They must not satisfy a requirement for verified hardware evidence.

## Hardware-specific evidence

Each kind of hardware reports different values, and each page below explains what its values do and do not show.

- [AMD SEV-SNP](https://trace.agentrust-io.com/docs/platforms/amd-sev-snp/index.md): distinguish the launch measurement from guest-supplied report data.
- [Intel TDX](https://trace.agentrust-io.com/docs/platforms/intel-tdx/index.md): interpret MRTD and RTMRs under the producing profile.
- [NVIDIA H100](https://trace.agentrust-io.com/docs/platforms/nvidia-h100/index.md): GPU appraisal does not automatically establish CPU workload or signing-key identity.
- TPM2: a quote and trusted attestation key can establish measured-state evidence. A TPM is not a general-purpose enclave for the application; it does not by itself protect agent process memory from the host OS. See [cMCP's TPM security model](https://cmcp.agentrust-io.com/spec/tpm-security-model/).

## What the TRACE SDK does

`verify_record` checks the signature and contents of a standalone record. It does not collect or appraise hardware quotes, fetch a Reference Integrity Manifest, or independently substantiate `appraisal.status`. There is no `verify-hardware` command in this package.

For cMCP evidence, use its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/), approved policy/catalog hashes, and required attestation inputs. For a local software example, use [quick start](https://trace.agentrust-io.com/docs/quickstart/index.md).

## Report the checks performed

Checking the hardware evidence is Level 1; Level 2 also publishes the record to a public log (transparency anchoring). Say which checks you ran. If evidence was missing, report it as missing, and if it contradicted the record, report a failure. A record that says `affirming` does not authorize an action without the recipient's own acceptance policy. See [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) and [verification outcomes](https://trace.agentrust-io.com/docs/verification-outcome-statements/index.md).
