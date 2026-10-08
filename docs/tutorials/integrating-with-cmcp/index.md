# Integration with cMCP

This page is for people running cMCP, a gateway that sits between an AI agent and its tools (MCP is the common protocol agents use to call tools) and checks each call against rules. It points you to the cMCP pages that create and check its signed session records, and explains where TRACE fits.

cMCP and the standalone TRACE library describe the same kinds of evidence but package them in different formats, so use cMCP's own checker for cMCP's records.

## Walkthrough

1. Run the [local cMCP quick start](https://cmcp.agentrust-io.com/quickstart/). It shows allowed and denied calls and creates a signed session claim in software mode.
1. Follow [verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) to supply independently approved policy and catalog hashes and inspect the verification result.
1. Review [hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/) before adding hardware requirements. Keep unavailable evidence distinct from an affirmative result.

These pages contain the runtime's maintained commands and complete examples. Do not pass a cMCP `RuntimeClaim` directly to `agentrust_trace.validate_json` or `verify_record`; those APIs consume standalone TRACE objects.

## Trust boundary

The gateway can only vouch for what passes through it.

The gateway checks routed tool calls and records its decisions. It does not observe calls that bypass it, prove an upstream tool's internal behavior, or establish physical task completion. Its [architecture](https://cmcp.agentrust-io.com/concepts/) separates the client, gateway, tools, and evidence consumer.

The signing key's hardware protection must be established by actual provider evidence and key binding. In plain terms: a key only counts as hardware-protected when a report signed by the hardware says so and is tied to that key. A claim made in development mode is still software evidence. A claimed policy hash must be compared with an independently approved artifact, not copied from the incoming claim into the verifier's allowlist.

## TRACE levels

TRACE grades evidence in levels. Checked hardware evidence supports Level 1. Level 2 adds a checked entry in a public log (a transparency anchor). Neither a TEE platform name nor the presence of a registry URL establishes those checks. See [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) and [verification protocol](https://trace.agentrust-io.com/docs/verification/index.md).
