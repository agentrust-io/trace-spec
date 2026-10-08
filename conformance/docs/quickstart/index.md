# Quick Start

This page installs the suite, makes a sample TRACE record, and checks it. It is for anyone who wants to see the suite work before reading the details. You need Python 3.11 or later and `pip`.

## Install

```
pip install agentrust-trace-tests
```

The distribution is `agentrust-trace-tests`; `trace-tests` is the command it installs. `pip install trace-tests` returns 404.

## Create a sample fixture

The suite checks a signed TRACE record (also called a Trust Record): a small JSON file describing one agent run, signed so that any later change is detectable. Make a Level 0 record, the level meant for development, with the `agentrust-trace` library:

```
pip install agentrust-trace
```

```
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

```
python generate_sample.py
```

`software-only` means the record makes no claim about secure hardware, and the all-zero measurement is the matching placeholder. Both are the correct values for Level 0 development records. `generate_key()` produces a fresh Ed25519 key on each run; for CI use, load a persisted key via the `TRACE_PRIVATE_KEY_PEM` environment variable instead.

## Run against a Trust Record

```
trace-tests verify --record sample-record.json --level 0
```

Level 0 is for development records with no secure hardware. Level 1 requires the record to name a TEE (a trusted execution environment: a processor mode that keeps a program's memory sealed off and can report what code is running) and its measurement. Level 2 adds proof that the record was entered in a public transparency log.

## Run all levels

```
trace-tests verify --record sample-record.json --level 0
trace-tests verify --record sample-record.json --level 1 --expected-nonce "$VERIFIER_CHALLENGE"
trace-tests verify --record sample-record.json --level 2 --expected-nonce "$VERIFIER_CHALLENGE"
```

The sample fixture passes Level 0. Levels 1 and 2 will fail on the runtime attestation and transparency fields, which is expected. See [Trust Levels](https://trace.agentrust-io.com/conformance/docs/levels/index.md) for what each level requires.

## Resolving the policy bundle

A policy bundle is the file of rules the agent ran under. The record carries the bundle's digest (a fingerprint of its bytes), and the suite can fetch the bundle from a local folder to confirm the fingerprint matches.

If your record carries `policy.policy_uri`, TR-POL-003 can fetch the bundle and check that it has the digest `policy.bundle_hash` declares. Point `--policy-dir` at a directory holding a `resolutions.json` that maps each URI to a relative path inside it:

```
trace-tests verify --record sample-record.json --level 0 --policy-dir ./bundles
```

```
{
  "https://policy.example.org/bundles/agent-v1.json": "agent-v1.json"
}
```

Without `--policy-dir` the resolution part of the check skips, so verifying offline costs you nothing. A `policy_uri` that is malformed rather than unreachable is still reported either way: that is a defect in the record, not a fetch that failed.

## Exit codes

| Code | Meaning                    |
| ---- | -------------------------- |
| 0    | All required tests passed  |
| 1    | One or more tests failed   |
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

Error codes follow the form `TR-<MODULE>-<NNN>`. A failing or unverified finding carries its code at the front of the message; a passing one usually does not, so the module column is what identifies a `PASS`. The JSON and HTML reports carry the code as its own field for every finding.

## Next steps

| What                             | Where                                                                                                                               |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Understand what each test checks | [Test Modules](https://trace.agentrust-io.com/conformance/docs/modules/index.md)                                                    |
| Look up a specific error code    | [Error Codes](https://trace.agentrust-io.com/conformance/docs/error-codes/index.md)                                                 |
| Write your own conformance tests | [Tutorial: Writing conformance tests](https://trace.agentrust-io.com/conformance/docs/tutorials/writing-conformance-tests/index.md) |
| Set up CI                        | [Tutorial: CI integration](https://trace.agentrust-io.com/conformance/docs/tutorials/ci-integration/index.md)                       |
