# Platform: NVIDIA H100 Confidential Computing

NVIDIA H100 (and Blackwell) GPUs support Confidential Computing — hardware-isolated GPU execution with attestation rooted in NVIDIA's Attestation Root Certificate Authority (NRAS). TRACE Level 2 on NVIDIA CC is the first hardware-verifiable governance record for GPU-based AI inference.

## What NVIDIA H100 CC provides

| Property | Detail |
|---|---|
| Memory protection | GPU memory encrypted and isolated per VM |
| Attestation | NVIDIA RIM Service attestation, signed by NVIDIA NRAS |
| Measurement | GPU firmware + driver measurement |
| Combined attestation | CPU TEE + GPU CC — one unified attestation report |

TRACE on H100 is the first open standard to combine CPU TEE attestation and GPU CC attestation into a single signed governance record. This was demonstrated at GTC Berlin.

## TRACE fields populated by NVIDIA H100 CC

```json
{
  "runtime": {
    "platform": "nvidia-h100",
    "measurement": "sha256:f0e9d8c7b6a5f4e3d2c1b0a9...",
    "rim_uri": "https://nras.nvidia.com/rims/H100_SXM5/fw_v551.81",
    "firmware_version": "551.81"
  }
}
```

- `measurement` — Combined CPU+GPU measurement hash
- `rim_uri` — NVIDIA RIM Service URL for firmware Reference Integrity Manifest
- `firmware_version` — NVIDIA GPU driver/firmware version

## Verification flow

```bash
agentrust-trace verify-hardware session.trace.json \
  --platform nvidia-h100 \
  --check-rim
```

1. Fetches the GPU RIM from NVIDIA's RIM Service at `runtime.rim_uri`
2. Verifies firmware measurement against the RIM
3. Verifies the GPU attestation report using NVIDIA NRAS root certificate
4. Validates that the combined CPU+GPU measurement matches `runtime.measurement`
5. Confirms `cnf.jwk` is endorsed by both CPU TEE and GPU CC attestation

## Combined CPU+GPU attestation

For maximum assurance, run the agent in a combined AMD SEV-SNP + NVIDIA H100 CC deployment. The TRACE record carries both measurements:

```json
{
  "runtime": {
    "platform": "nvidia-h100",
    "measurement": "sha256:combined-cpu-gpu-measurement...",
    "rim_uri": "https://nras.nvidia.com/rims/...",
    "extensions": {
      "cpu_platform": "amd-sev-snp",
      "cpu_measurement": "sha384:cpu-only-measurement..."
    }
  }
}
```

## Supported configurations

| Configuration | Status |
|---|---|
| H100 SXM5 + AMD EPYC (SEV-SNP) | ✓ GA |
| H100 PCIe + Intel Xeon (TDX) | ✓ GA |
| H100 SXM5 + AMD EPYC (bare metal) | Preview |
| NVIDIA Blackwell B200 | Preview |

## Example record

See [`examples/nvidia-h100.json`](https://github.com/agentrust-io/trace-spec/blob/main/examples/nvidia-h100.json).
