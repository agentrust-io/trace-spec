# Platform: Intel TDX

This page is for teams running agents on Intel processors with TDX, Intel's technology for running a virtual machine sealed off from the cloud host. It explains what TDX evidence proves, how a TRACE record names it, and what you still have to check.

Intel TDX runs a sealed-off virtual machine called a Trust Domain and can produce a signed report, called a quote, describing what was loaded into it. A TRACE consumer still needs a verifier that checks the quote, the trusted Intel roots and supporting data (collateral), the expected measurements, freshness, and that the quote is tied to the key that signed the record.

## Measurement and representation

Standalone TRACE uses `runtime.platform="intel-tdx"`. A measurement is a fingerprint of what was loaded. TDX keeps several of them in registers: MRTD describes the Trust Domain as it started, and RTMRs can carry further measurements taken while it runs. The producing profile must say which evidence the record commits to and how the recipient checks it. A generic combination of these registers is not defined by this page.

The `runtime.measurement` string is a claim until checked against authenticated evidence and independently approved reference values. Comparing two self-reported digests cannot establish key custody inside a Trust Domain.

## Deployment

GCP provides Intel TDX on C3 Confidential VMs; N2D is an AMD family. Availability and supported guest configurations change, so use Google's current [supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations) when provisioning.

For AgenTrust's collected evidence, verifier behavior, and remaining collateral checks, see [cMCP hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/). Follow its [verification tutorial](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) for the runtime's envelope and trust inputs.

## Assurance boundary

Checked hardware evidence supports TRACE Level 1; Level 2 also needs a public log entry (transparency anchoring). The standalone TRACE SDK does not provide a `verify-hardware` CLI or automatically provision an Intel collateral service. See [trust levels](../trust-levels.md) and [attestation platforms](index.md).
