# TRACE v0.1 example Trust Records

Each file is a canonical TRACE v0.1 Trust Record that validates as-is against
`schema/trace-claim.json` (no preprocessing, no comment stripping).

- `intel-tdx.json`: Intel TDX example.
- `amd-sev-snp.json`: AMD SEV-SNP example.
- `nvidia-h100.json`: NVIDIA H100 Confidential Computing example.
- `tpm2.json`: TPM 2.0 example.
- `sandbox-runtime.json`: a sandboxed agent runtime, TPM 2.0 rooted. Produced by
  `TraceSandboxAdapter`; the decision log is a kernel-sandbox policy trace rather
  than MCP tool calls.
- `action-receipts/`: informative fixture shapes for action-level receipt
  verification. These are not TRACE Trust Records and are not validated against
  `schema/trace-claim.json`.
- `canonicalization-boundary/`: three signed Trust Records that separate an
  RFC 8785-conformant canonicalizer from `json.dumps(sort_keys=True)`, which
  §3.2.2 requires and names as insufficient. These *are* Trust Records and do
  validate against the schema. See that directory's README.

The schema sets `additionalProperties: false`, so examples must not carry
non-schema keys such as `_comment`. Keep descriptive notes in this file.
