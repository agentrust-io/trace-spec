# Platform: NVIDIA H100 Confidential Computing

NVIDIA GPU attestation provides evidence about a GPU's identity and firmware state. NVIDIA Remote Attestation Service (NRAS), its Reference Integrity Manifest service, and certificate-status services have separate roles. See [NVIDIA's attestation documentation](https://docs.nvidia.com/attestation/index.html) and [H100 attestation example](https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/hopper_single_gpu.html).

## TRACE representation

Standalone TRACE registers `runtime.platform="nvidia-h100"` and `"nvidia-blackwell"`. A registered identifier does not mean this Python SDK collects GPU evidence or verifies an NRAS result. The producer must define how its `runtime.measurement` relates to authenticated GPU evidence.

The cMCP configuration name `opaque` belongs to that runtime's provider interface; it is not a standalone TRACE platform value. Follow the producing runtime's envelope and verifier documentation rather than substituting names between formats.

## CPU, GPU, and signing-key binding

An accepted GPU attestation does not automatically attest the CPU workload, model weights, policy enforcement, or record-signing key. A combined deployment needs explicit evidence linking the relevant components and the signing key under a documented profile. This page does not define a universal combined CPU/GPU digest or an additional `runtime.extensions` wire field.

Hardware appraisal supports Level 1. Level 2 additionally requires transparency anchoring. Read [trust levels](../trust-levels.md) and the producing runtime's [hardware-validation record](https://cmcp.agentrust-io.com/testing/hardware-validation/) before relying on a deployment claim.

## Getting started

Use NVIDIA's current example for GPU evidence collection and appraisal. For standalone TRACE signing and signature verification, use the [local quick start](../quickstart.md). These are separate checks; this package has no `agentrust-trace verify-hardware` command.
