# Attestation Platforms

TRACE Level 1 trust records require a TEE-backed signing key and a hardware measurement in the `runtime` field. The following platforms are supported.

| Platform | `runtime.platform` value | Measurement source |
|----------|-------------------------|-------------------|
| AMD SEV-SNP | `sev-snp` | Launch measurement (128-bit digest extended to sha256) |
| Intel TDX | `tdx` | MRTD + RTMRs combined measurement |
| NVIDIA H100 | `opaque` | GPU attestation report RIM hash |
| TPM2 | `tpm2` | PCR bank quote (sha256 bank, PCRs 0–7) |

For `software-only` (Level 0) records, no TEE is required and the `runtime.platform` value must be exactly `"software-only"`.

## How platform verification works

At Level 1, the cMCP runtime:

1. Requests a fresh quote from the TEE firmware at session start.
2. Submits the quote to the TRACE verifier endpoint, which checks it against the relevant RIM.
3. Embeds the verified measurement in `runtime.measurement` and sets `appraisal.status` to `"affirming"`.
4. Signs the completed record with the TEE-bound key.

The signing key is generated inside the TEE and never leaves the enclave boundary. The `cnf.jwk` in the record carries only the public half.

## Platform guides

- [AMD SEV-SNP](amd-sev-snp.md) — setup, measurement format, launch policy
- [Intel TDX](intel-tdx.md) — MRTD/RTMR layout, on-premises and cloud deployment
- [NVIDIA H100](nvidia-h100.md) — GPU attestation, RIM URI format

## Related

- [Trust Levels](../trust-levels.md) — what Level 1 guarantees and when to use it
- [Hardware Attestation Platforms tutorial](../tutorials/hardware-attestation-platforms.md) — end-to-end walkthrough
