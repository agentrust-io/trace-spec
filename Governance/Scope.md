# Scope

The TRACE Specification Project develops technical specifications for portable, independently verifiable evidence about governed AI-agent and confidential-workload execution.

The Project's Scope includes normative requirements for:

- the structure, syntax, semantics, and serialization of TRACE Trust Records;
- cryptographic signing, integrity protection, key binding, verification, and freshness of those records;
- claims that identify workloads, policies, data classifications, tools, execution sessions, and verification results;
- profiles that bind TRACE evidence to trusted-execution-environment attestation and other authenticated evidence;
- transparency, receipt, and anchoring mechanisms used to make TRACE evidence independently verifiable and durable;
- conformance levels, verification procedures, registries, and testable requirements necessary to implement the specification; and
- compatibility and composition with external standards expressly profiled by TRACE.

The Scope includes required and optional portions of TRACE specifications only to the extent they are described in detail in a Draft Specification or Approved Specification. A reference to an external standard does not bring that external standard into Scope.

The following are outside Scope:

- source code, SDKs, test harnesses, examples, and reference implementations, which are licensed separately;
- the internal design or implementation of processors, trusted execution environments, cryptographic libraries, transparency services, or external standards;
- AI-model architecture, training, safety, quality, or semantic behavior except where TRACE defines evidence fields about those properties;
- runtime policy-enforcement products, credential brokers, gateways, or hosted services except for the interfaces and evidence semantics expressly specified by TRACE;
- hardware side-channel mitigations and physical security; and
- business, regulatory, or operational requirements that are not expressed as normative TRACE conformance requirements.

Any changes to Scope are not retroactive.
