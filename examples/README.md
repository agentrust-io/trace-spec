# TRACE v0.2 example Trust Records

Each file in this directory is a canonical TRACE v0.2 Trust Record that validates
as-is against `schema/trace-claim.json` (no preprocessing, no comment stripping).

These records are unsigned, so they are **Level 0** artifacts: they show the record
shape and the claim set, not a cryptographically verifiable record. Check them with

```bash
pip install agentrust-trace-tests
trace-tests verify --record examples/amd-sev-snp.json --level 0
```

At `--level 1` and above every one of them fails `TR-SIG-005` by design, because
Level 1 requires a signature and `TR-SIG` fails closed. Signed records are produced
by cmcp at runtime; see [docs/quickstart.md](../docs/quickstart.md) to sign your own.
`TR-ENV-002` also enforces a 24-hour maximum record age, so pass `--max-age` when
checking any archived record, including these.

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
  §3.2.2 requires and names as insufficient. Each file is a test-vector envelope;
  the Trust Record is under the `record` key and validates against the schema.
  See that directory's README.

The schema sets `additionalProperties: false`, so examples must not carry
non-schema keys such as `_comment`. Keep descriptive notes in this file.
