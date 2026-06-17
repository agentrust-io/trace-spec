# Platform: AMD SEV-SNP

AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is the primary hardware root of trust for TRACE Level 2 records on AMD-based cloud instances and on-premises servers.

## What AMD SEV-SNP provides

| Property | Detail |
|---|---|
| Memory encryption | AES-128 per-VM encrypted memory |
| Attestation report | Signed by AMD's VCEK (chip-unique key) |
| Measurement | SHA-384 of the VM image + policy |
| Replay protection | Nonce-based freshness |

## TRACE fields populated by SEV-SNP

```json
{
  "runtime": {
    "platform": "amd-sev-snp",
    "measurement": "sha384:c9e4b1d2e3f4a5b6...",
    "rim_uri": "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
    "firmware_version": "1.53.0",
    "nonce": "ZRVkXG1w..."
  }
}
```

- `measurement` — SHA-384 of the SNP attestation report's `measurement` field (the VM image digest)
- `rim_uri` — AMD Key Distribution Service URL for VCEK certificate chain verification
- `firmware_version` — SNP firmware version embedded in the attestation report
- `nonce` — replay-protection nonce from the attestation challenge

## Verification flow

To verify a SEV-SNP TRACE record offline:

1. Parse `runtime.rim_uri` and fetch the VCEK certificate chain from AMD KDS
2. Verify the VCEK chain up to AMD's root CA (publicly available)
3. Verify the SNP attestation report signature using the VCEK certificate
4. Compare `runtime.measurement` against the report's `measurement` field
5. Confirm `cnf.jwk` was generated inside the enclave at that measurement

```bash
# cMCP does steps 1-5 automatically and embeds the result in the TRACE record
agentrust-trace verify-hardware session.trace.json \
  --platform amd-sev-snp \
  --check-rim
```

## Supported cloud instances

| Cloud | Instance family |
|---|---|
| Azure | DCasv5, ECasv5, DCadsv5, ECadsv5 |
| GCP | C3 (with AMD SEV-SNP enabled) |
| AWS | Not supported (AWS uses Nitro — separate profile) |
| On-premises | Any server with EPYC Genoa / Bergamo or newer |

## On-premises deployment

For on-premises SEV-SNP (e.g., Supermicro H13 with EPYC Genoa), Opaque ships the verifier with the platform — same cryptographic guarantees as cloud deployments, no cloud attestation service dependency. See [agentrust-io/cmcp](https://github.com/agentrust-io/cmcp) for the Helm chart.

## Example record

See [`examples/amd-sev-snp.json`](https://github.com/agentrust-io/trace-spec/blob/main/examples/amd-sev-snp.json) for a complete TRACE Level 2 record from an AMD SEV-SNP deployment.
