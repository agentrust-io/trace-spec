# Boundary between a valid signature and verified execution

An executable, synthetic example building on the [quickstart](../../docs/quickstart.md),
[verifying a trust record](../../docs/tutorials/verifying-a-trust-record.md), and
[known limitations](../../LIMITATIONS.md). It demonstrates the boundary between
cryptographic signature validity and verified execution in TRACE v0.2 without changing
the specification, schema, or SDK behavior.

## Reproduce at pinned commit `66665745bb7d334d9805abefad77ed35898fad55`

Install the repository's development dependencies and run from the repository root:

```sh
git rev-parse HEAD
example_out=$(mktemp -d)
python examples/signature-execution-boundary/signature_execution_boundary.py --out "$example_out"
pytest tests/test_signature_execution_boundary.py
```

Actual output from `python examples/signature-execution-boundary/signature_execution_boundary.py --out "$example_out"`:

```text
PASS [1/4]: baseline record validates and verifies against separately retained trusted key (revocation=no_check_performed)
PASS [2/4]: tampered signed field (data_class changed after signing) rejected with InvalidSignature
PASS [3/4]: wrong issuer key rejected with ValueError (cnf.jwk thumbprint mismatch); substituting cnf.jwk without re-signing rejected with InvalidSignature; allow_embedded_key=True warns and checks self-consistency only
PASS [4/4]: invented execution claims signed by the trusted issuer also pass verify_record; external transcript commitment comparison separates baseline=matched, invented=mismatch, unretained=unavailable
```

The script writes `baseline-record.trace.json`, `invented-execution-record.trace.json`,
and `verification-inputs.json` into `--out` using deterministic UTF-8/LF bytes. Those
generated files are not committed; the script is the single source and
`tests/test_signature_execution_boundary.py` reproduces them twice and pins their exact
SHA-256 byte digests and stdout lines. The deterministic signing seeds are public test
material with no real-world identity.

## What each check establishes and leaves unproven

| Check | Outcome | What it establishes | What it leaves unproven |
|---|---|---|---|
| **1. Signed record with separately retained trusted key** | `verify_record` returns `VerificationResult` (`revocation.outcome == "no_check_performed"`) | The record conforms to `schema/trace-claim.json`, names `tag:agentrust-io.com,2026:trace-v0.2`, binds `cnf.jwk` to the caller's configured trusted key (`thumbprint=8WEkIEIu0xGWVjA1V8weTlFmpl0D7N3EHC0yfRjfnQQ`), satisfies the configured freshness bounds at `now=1791936000`, and carries a valid Ed25519 signature over its RFC 8785 canonical preimage. | Whether the signing key has been revoked since issuance, whether any AI model or tool call actually ran, whether the named policy was evaluated or enforced, or whether the runtime had hardware isolation. |
| **2. Signed field modified after signing** | Raises `cryptography.exceptions.InvalidSignature` (while `validate_json` still passes) | Any post-signing mutation to a signed claim field (`data_class` in the script, and parametrized across `subject`, `iat`, `data_class`, `model`, `runtime`, `policy`, `build_provenance`, `appraisal`, and `tool_transcript` in `tests/test_signature_execution_boundary.py`) changes the RFC 8785 preimage and invalidates the Ed25519 signature, even when the modified record remains schema-valid. | Whether the original signed values were truthful when the issuer signed them. Integrity after signing does not establish truthfulness at signing. |
| **3. Wrong issuer key and `cnf.jwk` binding** | Raises `ValueError` on `cnf.jwk` thumbprint mismatch; raises `InvalidSignature` if `cnf.jwk` is replaced to match the wrong key without re-signing | A record cannot vouch for its own issuer key, and an attacker or misconfigured caller cannot verify a record against a different trusted key or rebind `cnf.jwk` after signing. By contrast, `allow_embedded_key=True` emits a `UserWarning` and proves internal self-consistency only. | Whether the configured trusted key is protected in hardware or remains uncompromised (`LIMITATIONS.md`: operator-forged software-only records and key revocation after issuance). |
| **4. Invented execution claims signed by the trusted issuer** | `verify_record` succeeds for `invented-execution-record.trace.json` (`enforcement_mode: "enforce"`, `slsa_level: 3`, `appraisal.status: "affirming"`, `call_count: 12`) with the same `VerificationResult` thumbprint; external transcript digest check reports `mismatch` (or `unavailable` when absent) | A trusted issuer key can sign arbitrary or contradictory execution claims (`affirming` appraisal, `enforce` policy mode, higher SLSA levels, or invented tool-call counts) and pass `verify_record` cleanly. Separating a genuine transcript commitment (`matched`) from an invented or missing one (`mismatch` or `unavailable`) requires independent appraisal of retained external evidence. | Even when a retained transcript matches `tool_transcript.hash`, a Level 0 software signature does not prove the transcript was captured from a live execution rather than synthesized before signing. |

## Scope and limits

The commitment helper uses `example-only/jcs-safe-integers-v1` (UTF-8 RFC 8785 via
`rfc8785`, refusing duplicate JSON members, floats, and integers outside
`[-9007199254740991, 9007199254740991]`). Both the script and the test suite's
independent commitment check share `rfc8785`; this example does not independently
validate that canonicalizer.

No hardware attestation quote, live revocation store, transparency receipt, or policy
engine runs here. See [verification protocol](../../docs/verification.md) and
[verification outcome statements](../../docs/verification-outcome-statements.md) for the
additional checks required before relying on execution, hardware, or compliance claims.
