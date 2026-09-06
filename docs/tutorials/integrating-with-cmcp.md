# Integration with cMCP

Use cMCP's runtime verifier for its signed session claims. The standalone TRACE SDK and cMCP share evidence concepts, but their record envelopes are different.

## Walkthrough

1. Run the [local cMCP quick start](https://cmcp.agentrust-io.com/quickstart/). It shows allowed and denied calls and creates a signed session claim in software mode.
2. Follow [verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) to supply independently approved policy and catalog hashes and inspect the verification result.
3. Review [hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/) before adding hardware requirements. Keep unavailable evidence distinct from an affirmative result.

These pages contain the runtime's maintained commands and complete examples. Do not pass a cMCP `RuntimeClaim` directly to `agentrust_trace.validate_json` or `verify_record`; those APIs consume standalone TRACE objects.

## Trust boundary

The gateway checks routed tool calls and records its decisions. It does not observe calls that bypass it, prove an upstream tool's internal behavior, or establish physical task completion. Its [architecture](https://cmcp.agentrust-io.com/concepts/) separates the client, gateway, tools, and evidence consumer.

The signing key's hardware protection must be established by actual provider evidence and key binding. A development-mode claim remains software evidence. A claimed policy hash must be compared with an independently approved artifact, not copied from the incoming claim into the verifier's allowlist.

## TRACE levels

Hardware appraisal supports Level 1. Level 2 adds a verified transparency anchor. Neither a TEE platform name nor the presence of a registry URL establishes those checks. See [trust levels](../trust-levels.md) and [verification protocol](../verification.md).
