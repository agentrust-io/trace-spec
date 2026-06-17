# Platform: Intel TDX

Intel TDX (Trust Domain Extensions) provides hardware-isolated Trust Domains (TDs) — VMs with encrypted memory, isolated register state, and hardware-signed attestation. TRACE Level 2 on TDX is supported on GCP Confidential VM (N2D-TDX) and select on-premises Intel Xeon Scalable deployments.

## What Intel TDX provides

| Property | Detail |
|---|---|
| Memory encryption | AES-256-XTS per-TD |
| Attestation report | TD Quote, signed by Intel's QE (Quoting Enclave) |
| Measurement | SHA-384 MRTD (TD measurement register) |
| Extensible registers | RTMR0–3 for measuring additional components |

## TRACE fields populated by TDX

```json
{
  "runtime": {
    "platform": "intel-tdx",
    "measurement": "sha384:a1b2c3d4e5f6a7b8...",
    "rim_uri": "https://api.trustedservices.intel.com/tdx/certification/v4/",
    "firmware_version": "5.35.1",
    "nonce": "dGRhY2Uzz..."
  }
}
```

- `measurement` — SHA-384 of the TDX TD Quote's MRTD field
- `rim_uri` — Intel Trust Authority / PCCS URL for TDX certificate chain
- `firmware_version` — TDX firmware version from the TD Quote header

## Verification flow

```bash
agentrust-trace verify-hardware session.trace.json \
  --platform intel-tdx \
  --check-rim
```

The verifier:
1. Fetches the TDX certificate chain from Intel's PCCS or Trust Authority
2. Verifies the TD Quote using Intel's SGX QVL (Quote Verification Library)
3. Compares `runtime.measurement` against the TD Quote MRTD
4. Validates that `cnf.jwk` was generated inside the TD at that measurement

## Supported cloud instances

| Cloud | Instance type |
|---|---|
| GCP | C3 Confidential VM (TDX) |
| Azure | DCesv5, ECesv5 (Intel TDX preview) |
| On-premises | Intel Xeon Scalable 4th Gen (Sapphire Rapids) and newer |

## Example record

See [`examples/intel-tdx.json`](https://github.com/agentrust-io/trace-spec/blob/main/examples/intel-tdx.json).
