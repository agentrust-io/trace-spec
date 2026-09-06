# Platform: Intel TDX

Intel TDX isolates a Trust Domain and provides signed quote evidence about its measured state. A TRACE consumer still needs a verifier that checks the quote, accepted trust roots and collateral, expected measurements, freshness, and record-signing-key binding.

## Measurement and representation

Standalone TRACE uses `runtime.platform="intel-tdx"`. MRTD describes the initial Trust Domain measurement; RTMRs can carry additional runtime measurements. The producing profile must say which evidence the record commits to and how the recipient checks it. A generic combination of these registers is not defined by this page.

The `runtime.measurement` string is a claim until checked against authenticated evidence and independently approved reference values. Comparing two self-reported digests cannot establish key custody inside a Trust Domain.

## Deployment

GCP provides Intel TDX on C3 Confidential VMs; N2D is an AMD family. Availability and supported guest configurations change, so use Google's current [supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations) when provisioning.

For AgenTrust's collected evidence, verifier behavior, and remaining collateral checks, see [cMCP hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/). Follow its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) for the runtime's envelope and trust inputs.

## Assurance boundary

Hardware appraisal supports TRACE Level 1; Level 2 additionally requires transparency anchoring. The standalone TRACE SDK does not provide a `verify-hardware` CLI or automatically provision an Intel collateral service. See [trust levels](../trust-levels.md) and [attestation platforms](index.md).
