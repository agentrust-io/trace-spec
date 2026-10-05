# Quick Start

## Install

```bash
pip install agentrust-trace-tests
```

The distribution is `agentrust-trace-tests`; `trace-tests` is the command it
installs. `pip install trace-tests` returns 404.

## Create a sample fixture

The test suite runs against a signed TRACE Trust Record. Generate a Level 0 development record with the `agentrust-trace` library:

```bash
pip install agentrust-trace
```

```python
# generate_sample.py
import time, json
from agentrust_trace import generate_key, sign_record

key = generate_key()

record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://trust.example.org/agent/sample",
    "model": {
        "provider": "example-provider",
        "model_id": "example-model-1",
        "version": "20251001",
    },
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {
        "bundle_hash": "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
                       "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {
        "slsa_level": 1,
        "digest": "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
                  "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    },
    "appraisal": {
        "status": "none",
        "verifier": "https://verifier.example.org",
    },
    "transparency": "https://registry.agentrust-io.com/claim/placeholder",
}

signed = sign_record(record, key)

with open("sample-record.json", "w") as f:
    json.dump(signed, f, indent=2)

print("Wrote sample-record.json")
```

```bash
python generate_sample.py
```

`software-only` platform and all-zero measurement are the correct values for Level 0 development records. `generate_key()` produces a fresh Ed25519 key on each run; for CI use, load a persisted key via the `TRACE_PRIVATE_KEY_PEM` environment variable instead.

## Run against a Trust Record

```bash
trace-tests verify --record sample-record.json --level 0
```

Level 0 is software-only (development). Level 1 requires TEE attestation. Level 2 adds transparency anchoring.

## Run all levels

```bash
trace-tests verify --record sample-record.json --level 0
trace-tests verify --record sample-record.json --level 1 --expected-nonce "$VERIFIER_CHALLENGE"
trace-tests verify --record sample-record.json --level 2 --expected-nonce "$VERIFIER_CHALLENGE"
```

The sample fixture passes Level 0. Levels 1 and 2 will fail on runtime attestation and transparency fields — that is expected. See [Trust Levels](levels.md) for what each level requires.

## Resolving the policy bundle

If your record carries `policy.policy_uri`, TR-POL-003 can fetch the bundle and
check that it has the digest `policy.bundle_hash` declares. Point `--policy-dir`
at a directory holding a `resolutions.json` that maps each URI to a relative
path inside it:

```bash
trace-tests verify --record sample-record.json --level 0 --policy-dir ./bundles
```

```text
{
  "https://policy.example.org/bundles/agent-v1.json": "agent-v1.json"
}
```

Without `--policy-dir` the resolution part of the check skips, so verifying
offline costs you nothing. A `policy_uri` that is malformed rather than
unreachable is still reported either way: that is a defect in the record, not a
fetch that failed.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | All required tests passed |
| 1    | One or more tests failed |
| 2    | Record could not be loaded |

## Output format

Each finding prints its **module**, its status, and its message:

```
  TR-ENV  PASS        eat_profile sentinel matches
  TR-ENV  PASS        cnf.jwk.kty present ('EC')
  TR-SIG  PASS        cnf.jwk key type is supported (kty='EC', crv='P-256')
  TR-SIG  UNVERIFIED  TR-SIG-005: no signature present; this record is NOT cryptographically verified
  TR-POL  PASS        policy.bundle_hash has valid digest format
```

Error codes follow the form `TR-<MODULE>-<NNN>`. A failing or unverified finding
carries its code at the front of the message; a passing one usually does not, so the
module column is what identifies a `PASS`. The JSON and HTML reports carry the code as
its own field for every finding.

## Next steps

| What | Where |
|------|-------|
| Understand what each test checks | [Test Modules](modules.md) |
| Look up a specific error code | [Error Codes](error-codes.md) |
| Write your own conformance tests | [Tutorial: Writing conformance tests](tutorials/writing-conformance-tests.md) |
| Set up CI | [Tutorial: CI integration](tutorials/ci-integration.md) |
