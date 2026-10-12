# Platform: AMD SEV-SNP

This page is for teams running agents on AMD processors with SEV-SNP, AMD's technology for running a virtual machine sealed off from the cloud host (a confidential VM). It explains what the processor's signed report proves, how a TRACE record refers to it, and what a verifier still has to check.

A signed SEV-SNP report is evidence about a confidential VM. To rely on it for a TRACE record, a verifier must check four things: that the report is genuine, that the platform state and the measurement (the fingerprint of what the VM booted) are ones it accepts, that the report is fresh, and that it is tied to the key that signed the record. A digest copied into JSON is not that verification.

## Measurement and key binding

The report carries two different values. `MEASUREMENT` is the fingerprint of what was loaded at launch. `REPORT_DATA` is a slot the guest fills in itself, which a profile can use to tie the report to a signing key and a one-time challenge.

??? info "Technical detail: field sizes and reference values"
    The SNP report's `MEASUREMENT` field is a 48-byte launch measurement. It is distinct from guest-supplied `REPORT_DATA`, which a profile can use to bind a key and challenge. See Google's [SEV-SNP ABI implementation](https://pkg.go.dev/github.com/google/go-sev-guest/abi) for the field sizes.

    An expected launch measurement must be independently approved. A certificate-distribution endpoint supplies signing collateral; it is not a Reference Integrity Manifest describing the expected workload. Matching a report's measurement to a record also does not establish what that measurement represents without the producing profile and reference values.

## TRACE representation

Standalone records use `runtime.platform="amd-sev-snp"`, or `azure-cvm-sev-snp` when the producing profile requires that identifier. `runtime.measurement` uses the schema's digest syntax; the producer must define its relationship to the verified report. Do not hash an already-computed measurement again unless the profile explicitly defines that transformation.

Checked hardware evidence supports Level 1. Level 2 also needs a public log entry (a transparency anchor) that is checked separately. See [trust levels](../trust-levels.md).

## Deployment and verification

Whether a cloud offers SEV-SNP depends on the machine family, region, firmware and guest configuration. For GCP, consult the current [Confidential VM configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations). C3 is an Intel TDX family; N2D is used for AMD SEV-SNP.

For the actual AgenTrust implementation and recorded hardware runs, use [cMCP hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/) and its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/). The TRACE SDK's signature verifier does not perform this hardware appraisal.
