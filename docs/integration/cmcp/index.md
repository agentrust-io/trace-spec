# Integration: cMCP

This page is for anyone who receives TRACE evidence from cMCP and needs to know how to check it. It explains what cMCP covers, which verifier to use, and what a cMCP session does and does not prove.

MCP (Model Context Protocol) is the common way AI agents call outside tools. [cMCP](https://cmcp.agentrust-io.com/) is a gateway that sits between an agent (the MCP client) and the tool servers it calls. It checks each call passing through it against rules written in the Cedar policy language, blocks calls the rules deny when it is set to enforce, records each decision, and signs a session claim when the session closes. The client and upstream tools remain outside the gateway's enforcement boundary.

## Start with a local call

Use the [cMCP quick start](https://cmcp.agentrust-io.com/quickstart/) to run an allow/deny example without hardware. Its software-mode evidence does not establish hardware isolation. The [architecture page](https://cmcp.agentrust-io.com/concepts/) shows the request path and trust boundaries.

cMCP only governs traffic routed through it. Other tool connections are not covered by its policy decision or session transcript.

## Verify the correct envelope

cMCP wraps its evidence in its own format, so the standalone TRACE verifier is the wrong tool for it. cMCP's `RuntimeClaim` contains nested TRACE fields and runtime-specific evidence. It is not the flat standalone object accepted by `agentrust_trace.verify_record`. Use `cmcp_verify.verify_trace_claim` with independently approved policy and catalog hashes and the required evidence inputs.

The [verification walkthrough](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) explains the result states. A software-only or incomplete hardware result must not be promoted to `verified` by the consumer.

## Hardware and transparency

Hardware assurance depends on the configured provider, the evidence actually collected, its tie to the signing key, the expected measurements (fingerprints of the loaded code), and a successful check of all of these. Running on a confidential VM (a virtual machine sealed off from the cloud host) is not enough on its own; consult [hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/).

Level 2 also needs transparency anchoring, an entry in a public log that anyone can check. A cMCP session is not automatically Level 2 because it ran on hardware. Nor does it automatically supersede an AGT record or guarantee matching transcript hashes: their producing profiles and envelopes must be reconciled explicitly.

Continue to [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) or [AGT integration](https://trace.agentrust-io.com/docs/integration/agt/index.md).
