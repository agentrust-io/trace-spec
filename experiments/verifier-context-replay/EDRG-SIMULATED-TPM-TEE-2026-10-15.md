# EDRG: rootless simulated TPM + isolated software execution
**Observed:** 2026-10-15
**Candidate under test:** `dcd222c2962eb4d35c4c6d88fb1378ee09f68c54`
**Review branch:** `freq/retained-context-replay-20261013`, draft PR #2 in `altrudev/trace-spec`

## Acceptance decision

**PASS: bounded software-simulation end-to-end acceptance.**

**NOT ESTABLISHED: hardware-backed TPM/TEE authenticity, real guest measured boot, independently enrolled production trust roots, external auditor certification, or full upstream conformance.**

Those two statuses are separate by design. A software TPM's signed quote verifies that a software TPM held the signing key and produced the asserted PCR selection; it cannot prove a physical TPM. A Bubblewrap sandbox is an OS namespace process sandbox, **not** a confidential-computing TEE.

## Live environment and observed results

| Test node | Runtime | TPM toolchain | Complete-suite result | Exit |
| --- | --- | --- | --- | --- |
| Prometheus (operator-controlled Ubuntu) | Python 3.13 / isolated uv | `swtpm 0.10.1`, `tpm2-tools 5.7`, Bubblewrap | **1,156 passed; 1 skipped; 0 failed** | **0** |
| vps-377a113a (operator-controlled Ubuntu VPS) | Python 3.14.4 / isolated venv | `swtpm 0.10.1`, `tpm2-tools 5.7`, Bubblewrap | **1,156 passed; 1 skipped; 0 failed** | **0** |

Both clean checked-out trees were at the exact candidate commit above. Full suite is `pytest -q tests experiments/verifier-context-replay` with fresh rootless swtpm test instances and explicit `TRACE_SWTPM_BINARY`, `TRACE_SWTPM_TOOL_DIR`, `TRACE_SWTPM_TCTI` and `TRACE_REPLAY_REPO`. The **one pre-existing skip** in `test_version.py` is an installed-distribution path comparison that refuses to treat venv site-packages as the checked-out source tree. No simulation integration test was skipped.

Static checking on the candidate (Prometheus) passed:
- `ruff check src/agentrust_trace`
- `ruff check --select E501,F,C402` for the five formatted simulation and replay implementation/test files and the software workload source.

## Executable flow, not a mock

1. Each node used ordinary `apt download`/ `dpkg-deb -x` to install TPM binaries and dependencies in a **user-owned /var/tmp directory**, without system-level installation, sudo, GPU or external AI models.
2. The integration harness started a **loopback-only ephemeral swtpm TPM2** instance, generated software Endorsement and Attestation Keys, performed PCR0 SHA256 extensions for the committed source, exact Python executable, isolated workload file and TPM verification source, and produced real TPM2 Quote signature/message/PCR bytes over PCR0, PCR1 and PCR7 with a fresh challenge.
3. `tpm2_checkquote` checked the actual RSA-attested quote, PCR selection and nonce. Separate Python code recomputed PCR0 from the exact event sequence. PCR1/PCR7 remain unmeasured zero values and are **not** reported as established required layers.
4. `captured_observer.capture` ran `software_tee_workload.py` under Bubblewrap with read-only checkout, isolated network and bounded process scope; the workload computed a deterministic nonce- and source-bound measurement. The observer independently captured exit status, runtime executable identity and output hashes and signed a development Ed25519 receipt.
5. The replay envelope preserved exact signed TRACE record bytes, trusted public root, policy bytes, revocation identifiers, resolver snapshot, TPM quote/AK/public attestation material and TEE execution receipt, all with content hashes. An **out-of-band manifest SHA256** was required. Verifier configuration, effective time/freshness, expected PCR0, quote challenge, trusted AK digest, expected code/TEE output hashes and observer public-key digest were pinned.
6. Two separate TRACE signature implementations compared signed-record decisions; the software TPM and TEE results also had to match each other on the committed workload measurement closure. Any mismatch produced `rejected` or `not-established`, never a positive simulation result.

## Independent cross-host replay: same candidate source

Evidence originated independently on each machine; public synthetic evidence bundles (no private keys) were transferred directly to the **other** machine for fresh offline verification.

| Producer | Independent replay node | Externally supplied manifest digest | TRACE reference | Independent crypto verifier | TPM | Software TEE |
| --- | --- | --- | --- | --- | --- | --- |
| Prometheus | VPS | `sha256:dba0306c67143383a94569963867b9c0c66f23605cfa8f3d8f7823406a9e7ffc` | verified | verified | verified-simulation-only | verified-simulation-only |
| VPS | Prometheus | `sha256:9eb1aaae0c8d0e08b13afe723c6349802c0d311203e610b8a65598580182e0f1` | verified | verified | verified-simulation-only | verified-simulation-only |

The aggregate decision in **both directions** was `simulated-evidence-validated`, with `semantic_status=exact-snapshot-matched`. This was independently checked with `tpm2_checkquote` on the receiving node **without network access to the producer swtpm**.

## Adversarial controls verified

The runnable corpus rejects tampered quote signatures; a substituted AK/trust root; wrong nonce; stale/future signed observation; forged observer signature; mismatched policy or resolver; changed evidence under a pinned manifest; missing TPM/TEE evidence; an unprovisioned quote verifier; invalid PCR extension digests; changed software workload output; false hardware classifications; and mismatched TPM-versus-TEE source/executable/commit measurement closures **even when the altered manifest is freshly rehashed**.

The enforced positive result is explicitly labelled **simulation-only**. The full-suite tests and live cross-node results form reproducible evidence, but neither the operator's own VPS nor Prometheus constitutes an external independent auditor.

## Environment hygiene and ownership

The manually started swtpm test daemons were terminated after verification. The executable `simulation_gate.py create` path starts and terminates its own disposable emulator and retains only **public synthetic evidence**, not private signing keys, in the configured evidence directory. Its local-only ports are never exposed to the public network. Source code and user credentials were not exported to third-party AI services.

Upstream license boundaries remain authoritative: TRACE specifications and normative schemas follow the repository's Community Specification License 1.0; SDK/test source additions follow Apache-2.0 unless stated otherwise. `swtpm`, `libtpms`, `tpm2-tools` and Bubblewrap retain their respective upstream licensing; their binaries were not committed to this repository. See the experiment `README.md` for About, trust summary, setup, IP boundary and full technical glossary.

## Outstanding, distinct production gates

- Genuine hardware trust chain: manufacturer-rooted TPM EK or SGX/TDX/SEV-SNP quote, with supported hardware/firmware and nonce/freshness policy.
- Verified measured boot: real firmware/OS event logs or a reproducible QEMU guest boot with a defined measured-boot event source; the present software lab exercises PCR extension and event reconstruction, **not a complete guest boot**.
- Production observer identity: independent certificate enrollment, key custody, revocation and secure run-capture / source TOCTOU defenses.
- External policy and reference-value authorization: published approved root registry, authoritatively signed policy, and remote source validation.
- Release governance: upstream review and conformance beyond this bounded simulation scope.

**Release decision:** simulation integration **PASS**; production independent hardware attestation **NOT ESTABLISHED**. Keep draft PR #2 unmerged until its wider release acceptance requirements are met.
