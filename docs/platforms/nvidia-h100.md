# Platform: NVIDIA H100 Confidential Computing

This page is for teams whose agents use NVIDIA H100 GPUs in confidential computing mode. It explains what GPU evidence covers, what it does not, and how a TRACE record refers to it.

NVIDIA GPU attestation is a signed report about which GPU this is and what firmware it runs. Several NVIDIA services take part, each with its own job: NVIDIA Remote Attestation Service (NRAS) checks the evidence, a Reference Integrity Manifest service supplies the expected values, and certificate-status services say whether a certificate has been revoked. See [NVIDIA's attestation documentation](https://docs.nvidia.com/attestation/index.html) and [H100 attestation example](https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/hopper_single_gpu.html).

## TRACE representation

Standalone TRACE registers `runtime.platform="nvidia-h100"` and `"nvidia-blackwell"`. A registered identifier does not mean this Python SDK collects GPU evidence or verifies an NRAS result. The producer must define how its `runtime.measurement` relates to authenticated GPU evidence.

The cMCP configuration name `opaque` belongs to that runtime's provider interface; it is not a standalone TRACE platform value. Follow the producing runtime's envelope and verifier documentation rather than substituting names between formats.

## CPU, GPU, and signing-key binding

A good GPU report covers the GPU only. It does not, by itself, vouch for the program on the CPU, the model weights, whether a policy was enforced, or the key that signed the record. A deployment that uses both needs explicit evidence linking those parts and the signing key, under a documented profile. This page does not define a universal combined CPU/GPU digest or an additional `runtime.extensions` wire field.

Checked hardware evidence supports Level 1. Level 2 also needs a public log entry (transparency anchoring). Read [trust levels](../trust-levels.md) and the producing runtime's [hardware-validation record](https://cmcp.agentrust-io.com/testing/hardware-validation/) before relying on a deployment claim.

## Getting started

Use NVIDIA's current example for GPU evidence collection and appraisal. For standalone TRACE signing and signature verification, use the [local quick start](../quickstart.md). These are separate checks; this package has no `agentrust-trace verify-hardware` command.
