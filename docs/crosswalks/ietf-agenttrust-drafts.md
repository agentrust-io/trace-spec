# IETF AgentTrust drafts: informative crosswalk

> **Non-normative.** Nothing in this page changes TRACE v0.2 schema fields, wire formats, required claims, or conformance. Internet-Drafts are work in progress and must not be cited as standards.

Personal-capacity informative map from TRACE evidence gaps called out in [`owasp-agentic-top-10.md`](owasp-agentic-top-10.md) to four live individual Internet-Drafts, the archived OWASP ASI01-ASI10 scenario corpus, and companion technical reports.

| Draft | Datatracker | Companion report DOI | What a relying party can check | TRACE v0.2 gap it informs (does not close) |
|---|---|---|---|---|
| `draft-durga-agenttrust-trace-verification-00` | https://datatracker.ietf.org/doc/draft-durga-agenttrust-trace-verification/ | `10.5281/zenodo.23775009` (`TR-2026-03`), `10.5281/zenodo.23775532` (`TR-2026-04`) | RFC 8785 JCS pre-image, fail-closed delegation attestation, claim-to-evidence binding | No normative parent/child record pointer; transcript hash is not a JCS execution receipt |
| `draft-durga-wimse-ctx-isolation-00` | https://datatracker.ietf.org/doc/draft-durga-wimse-ctx-isolation/ | `10.5281/zenodo.23735274` (`TR-2026-01`), `10.5281/zenodo.23735497` (`TR-2026-02`) | Data-plane taint separated from control-plane tool parameters | TRACE does not bind the context window that induced a tool call |
| `draft-durga-pquip-pqc-agentic-delegation-00` | https://datatracker.ietf.org/doc/draft-durga-pquip-pqc-agentic-delegation/ | `10.5281/zenodo.23776217` (`TR-2026-05`) | Hybrid Ed25519 + ML-DSA-65 delegation; archival SLH-DSA receipt | v0.2 signature suite is classical; long-horizon non-repudiation is out of scope |
| `draft-durga-agent-tx-compensation-lease-00` | https://datatracker.ietf.org/doc/draft-durga-agent-tx-compensation-lease/ | `10.5281/zenodo.23776574` (`TR-2026-06`) | Pre-release compensation lease, `T_req <= T_granted`, CAS epoch fence | TRACE records an effect; it does not reserve a rollback window before commit |

## Corpus, benchmark, and archival DOIs

- Corpus (draft sources, adapters, tests, `CITATION.cff`): https://github.com/drk-ram/agentic-security-ietf-corpus
- Reference benchmarks (`agentic-governance-benchmarks` v1.0.0): https://github.com/drk-ram/enterprise-agentic-governance-benchmarks (`10.5281/zenodo.23723284`)
- OWASP ASI01-ASI10 100-scenario dataset DOI: https://doi.org/10.57967/hf/11352 (`10.57967/hf/11352`)
- Foundational Zero Trust and Agentic AI Systems articles: https://doi.org/10.38124/ijsrmt.v4i12.1050 (`10.38124/ijsrmt.v4i12.1050`), https://doi.org/10.38124/ijsrmt.v4i11.1049 (`10.38124/ijsrmt.v4i11.1049`), https://doi.org/10.38124/ijsrmt.v4i5.1043 (`10.38124/ijsrmt.v4i5.1043`)

## ASI map (informative)

| ASI | Primary draft | Secondary | Companion report DOI |
|---|---|---|---|
| ASI01 Agent Goal Hijack | `draft-durga-wimse-ctx-isolation-00` | `draft-durga-agenttrust-trace-verification-00` | `10.5281/zenodo.23735497` (`TR-2026-02`) |
| ASI02 Tool Misuse | `draft-durga-wimse-ctx-isolation-00` | `draft-durga-agent-tx-compensation-lease-00` | `10.5281/zenodo.23735274` (`TR-2026-01`) |
| ASI03 Identity and Privilege Abuse | `draft-durga-pquip-pqc-agentic-delegation-00` | `draft-durga-agenttrust-trace-verification-00` | `10.5281/zenodo.23776217` (`TR-2026-05`) |
| ASI04 Agentic Supply Chain | `draft-durga-agenttrust-trace-verification-00` | `draft-durga-pquip-pqc-agentic-delegation-00` | `10.5281/zenodo.23775009` (`TR-2026-03`) |
| ASI05 Unexpected Code Execution | `draft-durga-agenttrust-trace-verification-00` | `draft-durga-wimse-ctx-isolation-00` | `10.5281/zenodo.23735497` (`TR-2026-02`) |
| ASI06 Memory and Context Poisoning | `draft-durga-wimse-ctx-isolation-00` | `draft-durga-agenttrust-trace-verification-00` | `10.5281/zenodo.23776574` (`TR-2026-06`) |
| ASI07 Insecure Inter-Agent Communication | `draft-durga-pquip-pqc-agentic-delegation-00` | `draft-durga-wimse-ctx-isolation-00` | `10.5281/zenodo.23775532` (`TR-2026-04`) |
| ASI08 Cascading Failures | `draft-durga-agent-tx-compensation-lease-00` | `draft-durga-agenttrust-trace-verification-00` | `10.5281/zenodo.23735274` (`TR-2026-01`) |
| ASI09 Human-Agent Trust Exploitation | `draft-durga-agenttrust-trace-verification-00` | `draft-durga-agent-tx-compensation-lease-00` | `10.5281/zenodo.23776574` (`TR-2026-06`) |
| ASI10 Rogue Agents | `draft-durga-agent-tx-compensation-lease-00` | `draft-durga-pquip-pqc-agentic-delegation-00` | `10.5281/zenodo.23776217` (`TR-2026-05`) |

## References

- TRACE v0.2: [`../../spec/trace-v0.2.md`](../../spec/trace-v0.2.md)
- Existing OWASP crosswalk: [`owasp-agentic-top-10.md`](owasp-agentic-top-10.md)
