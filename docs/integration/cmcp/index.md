# Integration: cMCP

[cMCP](https://cmcp.agentrust-io.com/) is a gateway between an MCP client and its tool servers. It evaluates routed calls against Cedar policy, blocks policy denials in enforcing mode, records decisions, and signs a session claim when the session closes. The client and upstream tools remain outside the gateway's enforcement boundary.

## Start with a local call

Use the [cMCP quick start](https://cmcp.agentrust-io.com/quickstart/) to run an allow/deny example without hardware. Its software-mode evidence does not establish hardware isolation. The [architecture page](https://cmcp.agentrust-io.com/concepts/) shows the request path and trust boundaries.

cMCP only governs traffic routed through it. Other tool connections are not covered by its policy decision or session transcript.

## Verify the correct envelope

cMCP's `RuntimeClaim` contains nested TRACE fields and runtime-specific evidence. It is not the flat standalone object accepted by `agentrust_trace.verify_record`. Use `cmcp_verify.verify_trace_claim` with independently approved policy and catalog hashes and the required evidence inputs.

The [verification walkthrough](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/) explains the result states. A software-only or incomplete hardware result must not be promoted to `verified` by the consumer.

## Hardware and transparency

Hardware assurance depends on the configured provider, actual evidence, key binding, expected measurements, and successful appraisal. Deployment on a confidential VM alone is insufficient; consult [hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/).

Level 2 additionally requires transparency anchoring. A cMCP session is not automatically Level 2 because it ran on hardware. Nor does it automatically supersede an AGT record or guarantee matching transcript hashes: their producing profiles and envelopes must be reconciled explicitly.

Continue to [trust levels](https://trace.agentrust-io.com/docs/trust-levels/index.md) or [AGT integration](https://trace.agentrust-io.com/docs/integration/agt/index.md).
