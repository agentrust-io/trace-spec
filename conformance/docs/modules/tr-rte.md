# TR-RTE: Runtime

Checks runtime claim fields and, at Level 1 or above, the verifier's nonce. This module does not fetch reference manifests, verify hardware quotes, authenticate platform certificates, or compare measurements against an approved image.

## Checks

| Test ID | Actual check | Boundary |
|---|---|---|
| TR-RTE-001 | Platform belongs to the registered set; `software-only` is rejected above Level 0 | A registered platform string is not hardware evidence |
| TR-RTE-002 | Measurement has `sha256:` plus 64 lowercase hex digits or `sha384:` plus 96 | Format only; all-zero values also match this check |
| TR-RTE-003 | If present, `rim_uri` is a string starting with `https://`; absent means skipped | No network request, HTTP status check, URI resolution, or reference-image appraisal |
| TR-RTE-004 | At Level 1 or above, a nonempty runtime nonce matches the verifier's nonempty expected nonce | Compares claim values; does not establish binding to a hardware quote |

The registered set includes `intel-tdx`, `amd-sev-snp`, `azure-cvm-sev-snp`, `nvidia-h100`, `nvidia-blackwell`, `aws-nitro`, `arm-cca`, `google-confidential-space`, `tpm2`, and `software-only`.

Use independently trusted hardware evidence, expected measurements, key binding, and provider-specific appraisal outside these format checks. See the [suite limitations](../../LIMITATIONS.md) and [runtime checker source](https://github.com/agentrust-io/trace-tests/blob/main/src/trace_tests/modules/tr_rte.py).
