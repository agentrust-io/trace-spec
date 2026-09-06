# Platform: AMD SEV-SNP

A signed SEV-SNP report supplies evidence about a confidential VM. To use it for TRACE, a verifier must check the report's authenticity, accepted platform state and measurement, freshness, and binding to the record-signing key. A digest copied into JSON is not that verification.

## Measurement and key binding

The SNP report's `MEASUREMENT` field is a 48-byte launch measurement. It is distinct from guest-supplied `REPORT_DATA`, which a profile can use to bind a key and challenge. See Google's [SEV-SNP ABI implementation](https://pkg.go.dev/github.com/google/go-sev-guest/abi) for the field sizes.

An expected launch measurement must be independently approved. A certificate-distribution endpoint supplies signing collateral; it is not a Reference Integrity Manifest describing the expected workload. Matching a report's measurement to a record also does not establish what that measurement represents without the producing profile and reference values.

## TRACE representation

Standalone records use `runtime.platform="amd-sev-snp"`, or `azure-cvm-sev-snp` when the producing profile requires that identifier. `runtime.measurement` uses the schema's digest syntax; the producer must define its relationship to the verified report. Do not hash an already-computed measurement again unless the profile explicitly defines that transformation.

Hardware appraisal supports Level 1. Level 2 adds a separately verified transparency anchor. See [trust levels](../trust-levels.md).

## Deployment and verification

Cloud support depends on machine family, region, firmware, and guest configuration. For GCP, consult the current [Confidential VM configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations). C3 is an Intel TDX family; N2D is used for AMD SEV-SNP.

For the actual AgenTrust implementation and recorded hardware runs, use [cMCP hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/) and its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/). The TRACE SDK's signature verifier does not perform this hardware appraisal.
