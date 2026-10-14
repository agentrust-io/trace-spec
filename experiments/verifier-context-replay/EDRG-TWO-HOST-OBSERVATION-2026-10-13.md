# EDRG two-host replay checkpoint: 2026-10-13

## Source and tests

Source revision tested: `d80afdb080081060956cf9f82acd37177300ec88`, draft PR #2.

- Prometheus: Python 3.13, isolated uv environment; complete test suite `tests experiments/verifier-context-replay`: **1,091 passed, 1 skipped, 0 failed**.
- VPS vps-377a113a: Python 3.14.4, dedicated virtualenv; same suite: **1,091 passed, 1 skipped, 0 failed**.
- Reproduced exact policy and resolver semantic snapshot comparison, enforcing-mode matching, signed policy digest checks, retained byte integrity, and differential cryptographic decisions.
- New tests confirm that policy/resolver context mismatches are not mistaken for success.

## Development observer signature

After the VPS test run, an Ed25519 development key was generated on VPS at `/var/tmp/trace-independent-vps/observer-key.pem`, mode 0600. The VPS signed the following run assertion. Prometheus separately verified the receipt signature.

Public key (base64 raw Ed25519): `QoZe/iFHOgu4YxrH7diA6TvfytE5pjt7VKBfJBC8vVY=`

Receipt:
```json
{"format":"trace-observer-receipt-v1","observation":{"command":"python -m pytest -q tests experiments/verifier-context-replay","commit":"d80afdb080081060956cf9f82acd37177300ec88","exit_code":0,"host":"vps-377a113a","summary":"1091 passed, 1 skipped; observed execution on VPS Python 3.14.4"},"signature":"YkEnepktPMp0dEUL1rruTDR9KFO1X1RuYJnlz_RdVWmCIeJWanBlhk31KfwhOho50zbSC0IlJ7lqohkRi0vlCA"}
```

Prometheus output: `VPS_RECEIPT_SIGNATURE_VALID True`.

**Trust boundary:** This proves possession of the generated key for the asserted bytes; it does not establish independent third-party certification, trusted key enrollment, tamper-proof runtime capture, or independent observation of the test process. The human/assistant-assembled observation is not an autonomously collected process receipt. The public key is disclosed here only for reproducibility and must not be treated as an independently trusted root.

## Release disposition

- Reference historical-time pinning: PASS.
- Offline bounded cryptographic differential: PASS.
- Retained exact policy/resolver snapshot consistency: PASS.
- Cross-host repeatability: PASS.
- Development signed-observer receipt crypto verification: PASS.
- Trusted external observer enrollment / automatically measured process identity / external policy authority / live resolver trust: **NOT ESTABLISHED**.
- Production release and third-party conformance: **BLOCKED**.

Do not claim production approval from passing tests alone; keep PR experimental and in draft.
