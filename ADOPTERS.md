# ADOPTERS

Organizations using or evaluating the TRACE specification.

To add your organization, open a pull request editing this file.

| Organization | Project | Use | Status |
|---|---|---|---|
| Sip Your Drink Ltd | [Bernstein](https://github.com/sipyourdrink-ltd/bernstein), open-source governance layer for AI agents (Apache-2.0) | `bernstein trace export` mints a TRACE v0.2 Trust Record for a run from its hash-chained journal, with delegation links between the hops of a multi-agent run and an aggregate record over them. Shipped as the `bernstein[trace]` extra since v3.19.0 and held to `agentrust-trace-tests` in CI. A hosted verifier for Trust Records and delegation chains runs at [mcp.bernstein.run](https://mcp.bernstein.run). | Using. Software-only (Level 0): no hardware attestation, and no third-party relying party is claimed. |
| xChk (Sean MacGuire) | [in.xchk.io](https://in.xchk.io), a registry that licenses AI agents under a verified person, gates their acts, and seals the record | The registry mints a TRACE v0.2 Trust Record per run of a plate (`GET /api/agents/:id/runs/:runSeq/trace-record`) and points at its sealed receipts as `approval-outcome` references; the receipts verify offline with the registry's standard-library verifier (Ed25519 half without extras). Cross-walk and fixtures in this repository. | Using. Software-only (Level 0): no hardware attestation; the registry is the only relying party so far. |

Project sponsors and their contributions are listed separately in [SPONSORS.md](SPONSORS.md); sponsorship does not imply adoption.
