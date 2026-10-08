# Quickstart

This page walks you through making your first TRACE record on your own computer in about ten minutes. A TRACE record (also called a Trust Record) is a signed receipt that says what an AI agent ran and under which rules; signing it means anyone with the matching public key can tell who made it and whether it was changed afterwards. It is for developers who want to see that work before reading the specification.

You will create a signed record, check it, then change one field and watch the check fail. The example uses made-up values and a key held in software. It does not run an AI agent, enforce a policy, contact a registry, or produce hardware attestation (a signed report from the processor itself, covered under [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md)).

## Install

Use Python 3.11+, Git, and Bash on Linux, macOS, or Windows with WSL. The steps below install the library from a copy of this repository, so the code matches this page. An older published release, agentrust-trace 0.9.0, bundled a schema that demanded a transparency entry even for a record that was never logged; 0.11.0 on PyPI no longer does (checked 2026-10-07 by running this page's scripts against it).

```
git clone https://github.com/agentrust-io/trace-spec.git trace-quickstart
cd trace-quickstart
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Generate a signing key

Signing uses a key pair: a private key that only the signer holds, and a public key that anyone can use to check the signature. The script below makes one pair and signs the record with the private key. It saves only the public key, so you can check the record later in a separate run. Keep that public key apart from the records you receive, because a record cannot vouch for its own key. In a real deployment, the verifier must obtain an approved issuer key through its own trust channel.

## Emit a Trust Record (standalone)

Save this complete block as `first_record.py` in `trace-quickstart`:

```
import copy
import json
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from agentrust_trace import generate_key, sign_record, validate_json, verify_record

key = generate_key()
trusted_key = key.public_key()
record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://example.test/agent/demo",
    "model": {"provider": "example", "model_id": "demo-model"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
    "data_class": "internal",
    "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
    "appraisal": {"status": "none", "verifier": "https://verifier.example.test"},
}

signed = sign_record(record, key)
validate_json(signed)
verify_record(signed, public_key_or_jwk=trusted_key)
print("PASS: schema and signature against the retained public key")

Path("session.trace.json").write_text(json.dumps(signed, indent=2))
Path("issuer-public.pem").write_bytes(trusted_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
))

changed = copy.deepcopy(signed)
changed["data_class"] = "public"
try:
    verify_record(changed, public_key_or_jwk=trusted_key)
except InvalidSignature:
    print("PASS: changed record rejected")
else:
    raise RuntimeError("Expected the changed record to fail verification")

print("Saved session.trace.json and issuer-public.pem; no hardware attestation")
```

Run it:

```
python first_record.py
```

Expected output:

```
PASS: schema and signature against the retained public key
PASS: changed record rejected
Saved session.trace.json and issuer-public.pem; no hardware attestation
```

The policy and build hashes are placeholders. (A hash is a short fingerprint of a file: change one byte and the fingerprint changes.) A valid signature locks these statements in place; it does not prove that a model ran or a policy was enforced.

## Emit with a persistent key

The example's private key exists only while the script runs. Its saved public key can still verify earlier records after the process exits. To sign future records as the same issuer, retain the private key through an approved key-management mechanism. See [signing your first trust record](https://trace.agentrust-io.com/docs/tutorials/signing-your-first-trust-record/index.md) for signing APIs and [verification](https://trace.agentrust-io.com/docs/verification/index.md) for trust and revocation requirements.

## Verify

Save this as `verify_saved.py` beside the two generated files, then run `python verify_saved.py`:

```
import json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from agentrust_trace import validate_json, verify_record

trusted_key = load_pem_public_key(Path("issuer-public.pem").read_bytes())
record = json.loads(Path("session.trace.json").read_text())
validate_json(record)
verify_record(record, public_key_or_jwk=trusted_key)
print("PASS: saved record verified against the retained public key")
```

Expected: `PASS: saved record verified against the retained public key`. By default a record older than 24 hours is refused, so rerun the first script if the demo record has expired. A wrong key, changed record, or stale timestamp must fail; investigate the error instead of enabling embedded-key trust to make it pass.

## What you now have

| Artifact                          | What it establishes                                  |
| --------------------------------- | ---------------------------------------------------- |
| `session.trace.json`              | A schema-valid, signed set of synthetic declarations |
| `issuer-public.pem`               | The key retained by this demo's verifier             |
| Tamper check                      | A modified signed field fails signature verification |
| `runtime.platform: software-only` | This example provides no hardware provenance         |
| `appraisal.status: none`          | No external appraisal occurred                       |

The verification call above does not check hardware attestation or whether the record was published to a registry. Production verification also needs an issuer trust policy and any required revocation, nonce, measurement, and transparency checks.

## Add hardware evidence and transparency (Levels 1 and 2)

To show that a record came from protected hardware, follow the [cMCP integration guide](https://trace.agentrust-io.com/docs/integration/cmcp/index.md), [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md), and [platform documentation](https://trace.agentrust-io.com/docs/platforms/index.md). Hardware evidence and transparency receipts require their own generation and verification steps. Installing a runtime or declaring a hardware platform does not automatically establish a conformance level.

## Troubleshooting

- **Module not found:** activate `.venv` in the terminal where you run the scripts.
- **File not found:** run both scripts from `trace-quickstart`; run `first_record.py` first.
- **Signature failure:** confirm the record matches the retained public key. Deliberately changing a signed field should fail.
- **Record too old:** generate a fresh demo record. Keep production freshness requirements explicit.

## Next steps

- [Verification protocol](https://trace.agentrust-io.com/docs/verification/index.md): checks beyond the signature.
- [Anchor a record](https://trace.agentrust-io.com/docs/tutorials/anchoring-to-the-registry/index.md): publish and verify a transparency anchor.
- [Schema reference](https://trace.agentrust-io.com/docs/schema/index.md): field definitions.
- [Full specification](https://trace.agentrust-io.com/spec/trace-v0.2/index.md): normative contracts and conformance.
