# Hardware Attestation Platforms

Understand what the `runtime.measurement` field contains for each TEE platform, what it proves, and how a verifier uses it.

## What you'll learn

- What `runtime.platform` and `runtime.measurement` mean for each supported platform
- Why `software-only` is only safe for development and testing
- What measurement values prove about the code that signed the record
- How a verifier checks a measurement against a Reference Integrity Manifest
- What the `agentrust-trace` library does and does not do with measurements

## Prerequisites

```bash
pip install agentrust-trace
```

---

## The measurement Field

Every TRACE Trust Record carries a `runtime` object with two required fields:

```json
{
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:c9e4b1d2e3f4a5b6..."
  }
}
```

`measurement` is a digest that identifies the exact binary that ran inside the TEE at the moment the signing key was generated. The TEE hardware computes and seals this value; software running outside the TEE cannot forge it.

This is what makes hardware-attested TRACE records meaningful: the signing key was generated inside the measured enclave, so the measurement in the record is a claim about the code that produced the key. If the measurement matches a known-good reference value, you know the key came from the expected software, unmodified.

---

## software-only

```python
import time
from agentrust_trace import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": int(time.time()),
    "subject": "spiffe://dev.example.org/agent/local-test",
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    # ... other required fields ...
}
```

`platform: "software-only"` means no TEE is present. The measurement is conventionally all-zero bytes. This platform value exists so a development record can never be mistaken for a hardware-backed record by a consumer that inspects `runtime.platform`.

Use `software-only` only in development and testing. A production verifier should reject records with this platform:

```python
def check_platform(record: dict) -> None:
    platform = record["runtime"]["platform"]
    if platform == "software-only":
        raise ValueError("software-only records are not accepted in production")
```

---

## TPM2

```json
{
  "runtime": {
    "platform": "tpm2",
    "measurement": "sha256:<PCR digest>",
    "rim_uri": "https://vendor.example.org/rim/firmware-1.2.pem"
  }
}
```

For TPM2, `measurement` is a PCR (Platform Configuration Register) digest. TPM PCR banks accumulate measurements of firmware, bootloader, kernel, and application code during the boot sequence. The value in `measurement` reflects the state of specific PCR banks at the time the key was generated.

Which PCR banks are included depends on the deployment configuration. A verifier checks the measurement by fetching the Reference Integrity Manifest (RIM) at `runtime.rim_uri` and comparing the expected PCR values against the measurement.

---

## AMD SEV-SNP

```json
{
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:<SNP attestation report measurement field>",
    "rim_uri": "https://kdsintf.amd.com/vcek/v1/Milan/...",
    "firmware_version": "1.51.00"
  }
}
```

For AMD SEV-SNP, `measurement` is the `MEASUREMENT` field from the SNP attestation report. AMD's Secure Nested Paging hardware computes this value over the initial memory contents of the confidential VM: firmware, kernel, initrd, and the guest application image. The measurement is sealed by the hardware before any guest code runs.

The RIM is the AMD Key Distribution Service (KDS) URL for the Versioned Chip Endorsement Key (VCEK) or VLEK. A verifier fetches the platform attestation report from KDS, verifies the AMD root certificate chain, and confirms the `MEASUREMENT` field matches the expected value for the known-good image.

The `firmware_version` field helps correlate against published AMD firmware RIMs.

---

## Intel TDX

```json
{
  "runtime": {
    "platform": "intel-tdx",
    "measurement": "sha384:<TD report MRTD field>",
    "rim_uri": "https://api.trustedservices.intel.com/tdx/certification/v4/..."
  }
}
```

For Intel TDX, `measurement` is the `MRTD` (Measurement of the TD) field from the TDX TD Report. Intel TDX measures the initial TD memory (TDVF firmware, kernel, and workload image) into `MRTD` during TD build. This value cannot be changed after TD launch.

The RIM endpoint is Intel Trust Authority (ITA). A verifier fetches the TD Quote (via `tdx-attest` or a platform attestation proxy), verifies the Intel root certificate chain, and confirms the `MRTD` value matches the reference for the expected image.

TDX reports also carry `RTMR` (Runtime Measurement Registers) for post-launch measurements. TRACE v0.1 binds only `MRTD` in the `measurement` field; `RTMR` values are outside the current scope.

---

## NVIDIA H100

```json
{
  "runtime": {
    "platform": "nvidia-h100",
    "measurement": "sha384:<NRAS attestation report digest>",
    "rim_uri": "https://nras.attestation.nvidia.com/v3/attestation/..."
  }
}
```

For NVIDIA H100 (Confidential Computing mode), `measurement` is the attestation report digest from the NVIDIA Remote Attestation Service (NRAS). NVIDIA's hardware attestation chain covers the GPC firmware, the driver, and the GPU workload configuration.

A verifier fetches the attestation certificate from NRAS, verifies the NVIDIA root certificate chain, and confirms the digest corresponds to an approved GPU firmware and driver version.

---

## How a Verifier Checks a Measurement

The `agentrust-trace` Python library carries the `measurement` field and makes it available in the signed record. It does not perform hardware measurement verification. That is the TEE platform's responsibility and requires platform-specific tooling.

A complete verifier for hardware-attested records does three things:

1. Verify the TRACE record signature with `verify_record()` (this library).
2. Fetch the platform attestation report for the stated `rim_uri`.
3. Confirm the `measurement` in the TRACE record matches the expected value in the RIM.

Step 3 proves the key that signed the TRACE record was generated by the expected software running inside the attested enclave. Without step 3, you know the record was not tampered with after signing, but you do not know whether the signing key came from legitimate code.

```python
from agentrust_trace import verify_record, validate_json

# Step 1: verify the TRACE record structure and signature
validate_json(record)
verify_record(record)

# Step 2 + 3: platform-specific — outside the scope of agentrust-trace
# For cMCP-issued records, use cmcp-verify which handles the full chain:
# from cmcp_verify import verify_trace_claim
# verify_trace_claim(record)
```

---

## Platform Enum Reference

The `RuntimeInfo` model accepts exactly these platform values:

| Value | Attestation root |
|---|---|
| `software-only` | None — development only |
| `tpm2` | TPM PCR digest |
| `amd-sev-snp` | AMD SEV-SNP MEASUREMENT field |
| `intel-tdx` | Intel TDX MRTD field |
| `nvidia-h100` | NVIDIA NRAS attestation digest |
| `nvidia-blackwell` | NVIDIA Blackwell confidential computing |
| `aws-nitro` | AWS Nitro Enclave attestation document |
| `arm-cca` | Arm CCA Realm Measurement |
| `google-confidential-space` | Google Confidential Space measurement |

Records with any other platform string will fail schema validation.

---

## Summary

The `runtime.measurement` field identifies the binary that generated the signing key, as measured by the TEE hardware. Each platform computes this differently: PCR digest for TPM2, `MEASUREMENT` for AMD SEV-SNP, `MRTD` for Intel TDX, and an NRAS digest for NVIDIA H100. The `agentrust-trace` library carries this field in the signed record; verifying the measurement against the TEE platform's attestation chain is a separate step that requires platform-specific tooling. For cMCP-issued records, the `cmcp-verify` library handles the full chain.

Related tutorials:

- [Sign your first trust record](signing-your-first-trust-record.md)
- [Integration with cMCP](integrating-with-cmcp.md)
