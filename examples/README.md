# TRACE v0.1 example Trust Records

Each file is a canonical TRACE v0.1 Trust Record that validates as-is against
`schema/trace-claim.json` (no preprocessing, no comment stripping).

- `intel-tdx.json`: Intel TDX example.
- `amd-sev-snp.json`: AMD SEV-SNP example.
- `nvidia-h100.json`: NVIDIA H100 Confidential Computing example.
- `action-receipts/`: informative fixture shapes for action-level receipt
  verification. These are not TRACE Trust Records and are not validated against
  `schema/trace-claim.json`.

The schema sets `additionalProperties: false`, so examples must not carry
non-schema keys such as `_comment`. Keep descriptive notes in this file.
