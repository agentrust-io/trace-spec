# Integration: sandboxed agent runtimes

A sandboxed agent runtime confines one agent on one machine. Filesystem, process and
network isolation at the kernel, an egress policy, and credentials injected so the agent
never holds them. That answers what a single agent may touch.

It does not answer, on its own, three questions that arrive next:

- **Across the estate.** Which agent, on which of the two hundred machines, took that
  action, and under whose authority?
- **From a regulator.** Not what the policy said, but what actually ran, evidenced.
- **From a sovereign or on-prem buyer.** The same answer on a machine with a TPM, or a
  confidential VM, or no secure hardware at all.

`TraceSandboxAdapter` answers them from what the runtime already has at session close.
It requires no change to the runtime.

## Install

```
pip install agentrust-trace
```

## Quick start

```python
from pathlib import Path
from agentrust_trace import TrustRecord, load_signing_key, sign_record
from agentrust_trace.adapters import SandboxSessionResult, TraceSandboxAdapter

# Configure once per deployment.
adapter = TraceSandboxAdapter(
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    data_class="confidential",
)

# Per session, from what the runtime already knows at close.
session = SandboxSessionResult(
    sandbox_id="spiffe://runtime.example.org/sandbox/code-review-7f2a",
    image_digest="sha256:5e8b2d1a...",
    policy_bundle_bytes=Path("sandbox-policy.yaml").read_bytes(),
    decisions=runtime.decision_log(),
)

record = sign_record(adapter.build_trust_record(session), load_signing_key())
TrustRecord.model_validate(record)
```

That record is Level 0: signed, offline-verifiable, and honest that no hardware backed
it. `runtime.platform` reads `software-only`.

## Adding a root of trust

Pass a `SandboxAttestation` and the same call emits a Level 1-*shaped* record:
`runtime.platform` and `runtime.measurement` carry the supplied evidence verbatim.
Nothing else about the call changes. Actual Level 1 assurance requires that evidence
to have been independently verified -- by your own attestation verifier, against
genuine hardware from the named platform -- *before* you construct the
`SandboxAttestation` below. See the boundary spelled out just after the example.

```python
from agentrust_trace.adapters import SandboxAttestation

session = SandboxSessionResult(
    ...,
    attestation=SandboxAttestation(
        platform="tpm2",                       # or amd-sev-snp, intel-tdx, nvidia-h100, ...
        measurement="sha256:3b4c2a1f...",      # supplied by the platform, not computed here
        firmware_version="7.85",
    ),
)
```

This is the point of the adapter spanning both levels. A sandbox runs wherever the
customer runs it, and the deployments that most need evidence are often the ones with
the least hardware. One code path covers a developer laptop and a confidential VM.

**The adapter checks the shape of an attestation, not its truth.** `platform` is only
ever set from a supplied attestation; an attestation may not name `software-only`; the
platform is checked against the enum on `RuntimeInfo` rather than a copy of it; and the
measurement must be a `sha256:` or `sha384:` digest. None of that is cryptographic
verification: nothing here checks a quote, a signature, or a nonce, so code in your own
process can construct a `SandboxAttestation` with an invented platform and an invented
digest and the adapter will emit a record that says `tpm2` (or any other platform)
anyway. Call this adapter only after your own attestation verifier has checked genuine
evidence from the named platform. This is the same boundary [trust levels](../trust-levels.md#level-1-hardware-evidence)
states for every Level 1 producer: `agentrust_trace.verify_record` does not appraise
hardware quotes, and this adapter does not either.

**Verified evidence is still not the whole requirement.** [Trust levels](../trust-levels.md#level-1-hardware-evidence)
says Level 1 needs "authenticated evidence binding the record-signing key to the expected
environment," and [verification](../verification.md#verifying-hardware-rooted-records)
puts the responsibility for that binding on the producing profile -- this adapter, for a
sandbox runtime. It does not define one: nothing here ties `measurement` or `nonce` to the
key you eventually pass to `sign_record`, and that key is chosen independently of, and
after, whatever attestation you verified. Verifying a genuine quote and then signing with
an unrelated key is still not Level 1 assurance; this code cannot distinguish that case
from a fabricated one. If your platform's quote supports a caller-supplied challenge
(TPM qualifying data, SEV-SNP `REPORT_DATA`, TDX `REPORTDATA`), request it with that field
set to a value derived from the signing key's RFC 7638 thumbprint, verify the binding
yourself, and only then carry the challenge through as `nonce`.

## Field mapping

| Record field | Source |
|---|---|
| `subject` | `sandbox_id`, a SPIFFE URI or DID |
| `build_provenance.digest` | `image_digest` |
| `policy.bundle_hash` | SHA-256 of `policy_bundle_bytes` |
| `tool_transcript.hash` | SHA-256 of the RFC 8785 canonical form of `decisions` |
| `tool_transcript.call_count` | `len(decisions)`, or `call_count` if given |
| `runtime.platform` | `software-only`, or the attestation's platform |
| `runtime.measurement` | `sha256(image_digest + "\n" + bundle_hash)`, or the attestation's measurement |

The hash helpers are public static methods, so a runtime written in another language can
reproduce them: `TraceSandboxAdapter.bundle_hash`, `.transcript_hash`,
`.software_measurement`.

## Three things worth getting right

**The policy bundle must be bytes you can reproduce.** The bundle hash is the load
bearing field: edit the policy and the record changes. Where a runtime composes policy
from several files, concatenate them in a defined order and keep that order stable. A
hash both sides derive differently proves nothing.

**The decision log is canonicalised with JCS, not `json.dumps(sort_keys=True)`.** The two
agree on ASCII and diverge on non-ASCII strings and number formatting, and a decision log
carries paths and hostnames. Using the same canonicalisation as the signature pre-image
keeps the record reproducible across implementations.

**An unappraised record says so.** `appraisal.status` defaults to `"none"`. Building a
record does not appraise it, and stamping `affirming` on an unappraised record puts a
verdict in the field a consumer reads to find out whether anybody checked. Set it only
when an appraisal actually happened.

## Levels

| Level | What you pass                                    | `runtime.platform`    | Assurance this establishes on its own |
| ----- | ------------------------------------------------ | ---------------------- | -------------------------------------- |
| 0     | nothing extra                                    | `software-only`       | None claimed -- honestly unattested |
| 1     | a `SandboxAttestation`                           | the attested platform | Record shape only. Real Level 1 assurance requires the supplied evidence to have been independently verified by your own attestation verifier before construction, *and* that verification to bind the record-signing key to the attested environment -- this adapter defines no such binding |
| 2     | Level 1 plus `transparency=` a SCITT receipt URI | the attested platform | Same as Level 1, plus a transparency receipt -- the receipt does not itself verify the hardware evidence |

`transparency` defaults to `None`, which leaves the key out of the record. That is
correct below Level 2: an unanchored record has no receipt to name.

Note: `schema/trace-claim.json` still lists `transparency` in `required`, so an
unanchored record validates against the model and not against the published JSON Schema.
That divergence is tracked in `tests/test_sandbox_adapter.py` and is not introduced by
this adapter.

## Worked example

`examples/sandbox-runtime.json` shows the record *shape* this adapter emits for a
`tpm2` attestation, and it validates as-is against the schema. It is not a TPM-rooted
record: `runtime.measurement`, `runtime.nonce`, and `cnf.jwk` in that file are
illustrative placeholder values with no relationship to each other or to any real quote
-- decoding the `nonce` shows it is literally the string `sandbox-runtime-nonce`, not a
challenge bound to the `cnf.jwk` beside it. Do not copy this file as a template for a
genuinely attested record without replacing every one of those fields with values your
own attestation verifier produced, including a `nonce` actually bound to your signing
key if your platform supports that (see "Adding a root of trust" above).

## Related

- [Integration: AGT](agt.md)
- [Integration: cMCP](cmcp.md)
- [Trust levels](../trust-levels.md)
