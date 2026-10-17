# TRACE two-host operator acceptance: 2026-10-15

## Scope and identity

This is an operator-controlled cross-host experiment on a single pinned source
SHA, not a third-party attestation or proof of independent key enrollment.

Pinned checkout: aed444729430b01c92ff44e86894d8d7d3ba48fe
Operator execution host: vps-377a113a
Operator verification host: prometheus

## Observed execution and tests

On the VPS the full standard test suite completed with 1,040 passed and one
skipped. The experiment suite completed with 97 passed. The bounded observer
ran the exact /usr/bin/true command from an allowlisted argv, under requested
Bubblewrap network isolation, at the pinned clean checkout, with exit code 0.
It produced an Ed25519-signed observation receipt with an ephemeral test key.

The receipt and its public key were transferred via the authorized remote
connector and verified on Prometheus. The verifier checked the asserted host
label, exit code, and pinned SHA, and verified the cryptographic signature.
Changing the receipt's exit code or supplying the wrong public key caused
verification to fail. SHA-256 of the JSON bundle with sorted keys, compact
separators and UTF-8 encoding:

c9ed524b694e776edf3941e277ee16c768e06ca880960d063950fc6b941321a9

## Assurance boundaries

Both machines and the test key remain under one operator's control. The host
label is self-asserted, the key was ephemeral and not enrolled out of band by
a separate trust authority, and the transfer occurred through the same
operator-authorized control plane. Therefore this is a positive
cross-host cryptographic verification result but NOT independently governed
attestation, hardware-backed proof, trusted time, or a real production
execution-policy decision. The receipt remains on the respective operator
hosts; the digest above is only a reference and does not make the contents
independently available or establish their origin.

In particular, T05 cannot be upgraded to fully independent observation and
T09 remains EXTERNALLY-BLOCKED. Source and executable race resistance,
key custody, production policy evaluation, full hostile-workload sandbox
testing, and signer rotation/revocation require separate evidence.
