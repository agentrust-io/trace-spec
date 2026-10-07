# Writing Custom TRACE Conformance Tests

Write a custom pytest test that verifies a specific field in a TRACE Trust Record using the `trace_tests` library.

## What you'll learn

- What the three conformance levels require and which modules activate at each level
- How to build a minimal TRACE record fixture and call the module `check()` functions directly
- How to interpret `Finding` results and match them to error codes

## Prerequisites

```bash
pip install agentrust-trace-tests pytest cryptography
```

---

## Understand the conformance levels

TRACE defines three levels. Each level activates a cumulative set of modules:

| Level | Required modules | Typical use |
|-------|-----------------|-------------|
| 0 | TR-ENV, TR-SIG, TR-POL | Software-only development and staging |
| 1 | Level 0 + TR-RTE, TR-SCA | Records that declare a TEE platform and measurement |
| 2 | Level 1 + TR-TXN, TR-ANC | Full records with SCITT transparency anchoring |

At Level 0 you can set `runtime.platform` to `"software-only"` and skip hardware attestation entirely. At Level 1 you must supply a real TEE measurement from AMD SEV-SNP, Intel TDX, NVIDIA H100, or similar. Level 2 adds a SCITT receipt URI and a bound tool-call transcript hash.

The `runner.run()` function respects this table. Modules not required at the requested level are never invoked.

---

## Run the existing test suite

The published suite uses pytest markers to group tests by level:

```bash
# Run everything
pytest

# Run only Level 0 tests
pytest -m level0

# Short traceback, stop after the first failure
pytest --tb=short -x
```

Each test file uses a pytest fixture (defined in `tests/conftest.py`) that loads a JSON vector or builds a signed record in memory. The fixture names match the level they cover: `valid_level0`, `signed_eat_fixture`, `trust_record`.

A passing run looks like:

```
tests/test_level0.py::TestLevel0Conformance::test_schema_valid PASSED
tests/test_level0.py::TestLevel0Conformance::test_eat_profile_sentinel PASSED
...
```

A skip appears when a test is conditional on an optional field:

```
tests/test_level0.py::TestLevel0Conformance::test_transcript_digest_when_present SKIPPED
```

A failure looks like:

```
FAILED tests/test_level1.py::test_tee_platform_present
AssertionError: TR-RTE-001: runtime.platform must be a recognised TEE enum value
```

---

## Understand the module system

Each module is a Python file under `src/trace_tests/modules/`. Every module exposes a `check()` function that accepts the extracted TRACE fields dict and returns `list[Finding]`.

```python
# Every module follows this pattern
from trace_tests.modules import tr_pol
from trace_tests.result import Finding, Status

findings: list[Finding] = tr_pol.check(trace_dict)
```

A `Finding` carries three fields:

```python
finding.code     # e.g. "TR-POL-001"
finding.status   # Status.PASS, Status.FAIL, Status.SKIP, or Status.UNVERIFIED
finding.message  # human-readable detail

finding.passed()      # True when status == PASS
finding.failed()      # True when status == FAIL
finding.skipped()     # True when status == SKIP
finding.unverified()  # True when status == UNVERIFIED
```

`UNVERIFIED` is distinct from `SKIP`. It means the record carries no signature that can be verified. At Level 0 this is allowed; at Level 1 and above it counts as a failure so a caller cannot mistake an unverified record for a passing one.

---

## Write a custom test

The simplest pattern is to build a minimal trace dict, call the module directly, and assert on the findings.

```python
# tests/custom/test_my_policy.py
import pytest
from trace_tests.modules import tr_pol
from trace_tests.result import Status


def _policy_trace(bundle_hash: str, enforcement_mode: str) -> dict:
    return {
        "policy": {
            "bundle_hash": bundle_hash,
            "enforcement_mode": enforcement_mode,
        }
    }


def test_sha256_bundle_hash_passes():
    trace = _policy_trace(
        bundle_hash="sha256:" + "a" * 64,
        enforcement_mode="enforce",
    )
    findings = tr_pol.check(trace)
    assert all(not f.failed() for f in findings), findings


def test_md5_bundle_hash_fails_tr_pol_001():
    trace = _policy_trace(bundle_hash="md5:abc123", enforcement_mode="enforce")
    codes = {f.code for f in tr_pol.check(trace) if f.failed()}
    assert "TR-POL-001" in codes


def test_unknown_enforcement_mode_fails_tr_pol_002():
    trace = _policy_trace(
        bundle_hash="sha256:" + "b" * 64,
        enforcement_mode="strict",  # not in {enforce, advisory, silent, declared}
    )
    codes = {f.code for f in tr_pol.check(trace) if f.failed()}
    assert "TR-POL-002" in codes
```

For modules that need the full raw record (TR-SIG), pass both the extracted trace and the raw record:

```python
from trace_tests.modules.tr_sig import check as check_sig

# fmt is "cmcp-runtime" for cMCP envelopes, "trace" for plain TRACE records
findings = check_sig(trace=record["trace"], record=record, fmt="cmcp-runtime", level=0)
```

For TR-ENV, pass `max_age_seconds` to override the default 24-hour freshness window in tests:

```python
from trace_tests.modules.tr_env import check as check_env

findings = check_env(trace, max_age_seconds=3600)
```

---

## Build a signed fixture

When you need a cryptographically valid record (required for TR-SIG tests at Level 1+), generate a key pair and sign the canonical JSON body yourself:

```python
import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _canonical_json(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def build_signed_cmcp_record(platform: str = "tpm2") -> dict:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    x = _b64url(pub_raw)
    kid = f"test-{pub_raw[:4].hex()}"

    record = {
        "cmcp_version": "1.0",
        "trace": {
            "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
            "iat": int(time.time()) - 30,
            "subject": "spiffe://cmcp.gateway/session/my-test",
            "runtime": {
                "platform": platform,
                "measurement": "sha256:" + "a" * 64,
            },
            "policy": {
                "bundle_hash": "sha256:" + "b" * 64,
                "enforcement_mode": "enforce",
            },
            "data_class": "internal",
            "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}},
        },
        "gateway": {"session_id": "my-test"},
        "signature": "",
    }

    body = _canonical_json({k: v for k, v in record.items() if k != "signature"})
    record["signature"] = _b64url(priv.sign(body))
    return record
```

This matches the helper pattern in `tests/conftest.py` and the `_build_signed_cmcp_record` function used by the published fixtures.

---

## Interpret error codes

Error codes follow the pattern `TR-<MODULE>-<NNN>`. The module prefix tells you which spec section failed; the number points to the specific field. The full table is at [Error Codes](../error-codes.md).

Common codes you will encounter:

| Code | Field | Fix |
|------|-------|-----|
| TR-ENV-001 | `eat_profile` | Must be `tag:agentrust-io.com,2026:trace-v0.2` |
| TR-ENV-002 | `iat` | Must be a Unix timestamp in the last 24 hours |
| TR-SIG-005 | `signature` | Signature missing, unverifiable, or does not verify |
| TR-SIG-004 | `cnf.jwk` | Supported key type, and no private key material |
| TR-POL-001 | `policy.bundle_hash` | Must match `sha256:<64 hex chars>` |
| TR-POL-002 | `policy.enforcement_mode` | Must be `enforce`, `advisory`, `silent`, or `declared` |
| TR-RTE-001 | `runtime.platform` | Must be a registered TEE platform enum |

When a finding carries `status == Status.UNVERIFIED`, the record has no signature. This is not a benign skip at Level 1 or above.

---

## Summary

You ran the existing suite with pytest, called individual module `check()` functions directly, and built a signed test fixture from scratch. The `Finding` dataclass with `code`, `status`, and `message` fields is the single interface across all eight modules.

Next steps: [CI Integration](./ci-integration.md) shows how to run these tests in GitHub Actions with matrix Python versions and artifact upload.
