# EDRG : strict simulated TPM/TEE enrollment gate
**Assessment date:** 2026-10-15
**Tested source commit:** `c68c3d7d6ef07c808716d38a03d67bd99549a7d2`
**Repository:** `altrudev/trace-spec`, draft PR #2

## Outcome

**PASS : fully exercised bounded software-only attestation and retained-context gate.**

**NOT ESTABLISHED : production hardware-backed attestation, trusted outside-party enrollment, or third-party certification.**

## Observed execution

| Host | Environment | Result | Exit |
| --- | --- | --- | --- |
| Prometheus | Python 3.13; local user-space swtpm 0.10.1, TPM2 tools 5.7, Bubblewrap | **1,164 passed, 1 skipped, 0 failed** | **0** |
| VPS vps-377a113a | Python 3.14.4; isolated venv and user-space swtpm 0.10.1, TPM2 tools 5.7, Bubblewrap | **1,164 passed, 1 skipped, 0 failed** | **0** |

Both worktrees were clean and pinned to the same tested SHA. The complete suite was
`pytest -q tests experiments/verifier-context-replay` with all live swtpm and
Bubblewrap integration variables configured, so none of the simulated
attestation integration cases was skipped. The single pre-existing skip was
`tests/test_version.py`'s source-tree-vs-installed-distribution comparison.

Static analysis on Prometheus: `ruff check src/agentrust_trace` and selected
`E501,F,C402` rules on enrollment, replay and implementation modules passed.

## Verified scope

- Actual software TPM2 key generation, PCR0 event extension from immutable
  source/executable digests, nonce-bound TPM2 Quote and independent
  `tpm2_checkquote` verification.
- Separately signed Bubblewrap-isolated software execution observation, with
  deterministic workload output hashes, nonce and bounded freshness.
- TRACE reference and independent Ed25519/JCS paths agreed on the signed record;
  policy/resolver snapshots, trusted public keys, and missing evidence remained
  explicit.
- Cross-host **bidirectional** replay on the earlier software-simulation
  acceptance revision: Prometheus evidence independently reverified on the VPS
  and VPS evidence independently reverified on Prometheus, both positive and
  simulation-only. See `EDRG-SIMULATED-TPM-TEE-2026-10-15.md` for pinned
  manifest digests and the original direction-by-direction outputs.
- New **verifier-owned enrollment control** requires an externally pinned
  registry separate from the producer evidence, with commit/host/root/AK/policy/
  resolver/PCR/challenge selectors, maximum live freshness, and a validity
  interval. Missing registries, changed pins, substituted roots, software-to-
  hardware promotion and stale historical evidence are rejected.
- The new live `test_enrolled_live.py` passed on both machines by creating an
  explicit **test-only proposed registry** alongside a fresh actual emulator
  run, verifying the positive case and mutation cases for root replacement,
  registry-pin removal and operational expiry. Such a proposed registry must
  never be mistaken for actual independent enrollment: its selectors were
  assembled using fixture evidence, not an outside approving authority.

## Hardware/authority evidence limitation

Neither connected host exposed a real `/dev/tpm*` TPM device. Prometheus is an
OptiPlex 9010, and the VPS runs as an OpenStack Nova virtual guest. Neither
machine provided directly accessible TPM EK manufacturer certification or
hardware SGX/TDX/SEV-SNP attestation evidence. Software-only simulation cannot
establish those hardware properties.

No trusted external CA, auditor-held signing key or separately approved
authority-rooted verifier registry was provided. It would be misleading to
manufacture any of them or to call the user-owned VPS an external auditor.
Root custody, independent authorization and hardware provenance therefore
remain **NOT ESTABLISHED**, deliberately distinct from the executable
simulation gate.

## Follow-on acceptance for real hardware

1. Acquire/access a physically protected TPM or confidential-computing
   provider's hardware quote and its vendor-endorsed trust chain.
2. Verify real boot/firmware event provenance and replay, rather than a
   synthetic PCR event stream.
3. Pre-enroll, independently authorize, version, revoke and rotate the
   observer and reference-value roots and effective policy.
4. Prove cross-host observed execution with signed source/nonce and
   certificate-backed origin on an independently administered verifier.
5. Repeat the same adversarial EDRG with hardware-only roots, and require all
   production cases to pass without `simulation-only` classification.

**Release gate:** Simulation-only **PASS**; external-hardware production
**BLOCKED**. Keep draft PR #2 under review, not automatically mergeable.
