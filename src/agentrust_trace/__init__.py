"""agentrust-trace: TRACE Trust Record models, validation, and signing."""

from importlib import metadata as _metadata

from agentrust_trace.adapters import (
    AGTSessionResult,
    SandboxAttestation,
    SandboxSessionResult,
    TraceAGTAdapter,
    TraceSandboxAdapter,
)
from agentrust_trace.models import (
    Appraisal,
    BuildProvenance,
    ConfirmationKey,
    Delegation,
    Origin,
    JWK,
    ModelInfo,
    PolicyInfo,
    Reference,
    RuntimeInfo,
    ToolTranscript,
    TrustRecord,
)
from agentrust_trace.sign import (
    TRACE_PROFILE_V0_2,
    RevocationStore,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    load_key,
    load_signing_key,
    sign_record,
    verify_record,
)
from agentrust_trace.revocation import (
    RevocationCheck,
    VerificationResult,
    check_bundle,
)
from agentrust_trace.validate import (
    iter_errors,
    SCHEMA,
    validate_json,
)

try:
    __version__ = _metadata.version("agentrust-trace")
except _metadata.PackageNotFoundError:  # source tree, not installed
    __version__ = "0.0.0+unknown"
"""Read from installed package metadata rather than hardcoded.

A literal here drifted from ``pyproject.toml`` at #36 and stayed wrong through
v0.3.0, v0.4.0, v0.5.0 and v0.5.1, so four releases reported ``0.2.0`` at runtime.
Deriving it from the metadata makes that class of drift impossible; a test pins the
two together for the source tree.
"""

__all__ = [
    "__version__",
    "AGTSessionResult",
    "TraceAGTAdapter",
    "SandboxAttestation",
    "SandboxSessionResult",
    "TraceSandboxAdapter",
    "Appraisal",
    "BuildProvenance",
    "ConfirmationKey",
    "Delegation",
    "Origin",
    "JWK",
    "ModelInfo",
    "PolicyInfo",
    "Reference",
    "RuntimeInfo",
    "ToolTranscript",
    "TrustRecord",
    "RevocationCheck",
    "RevocationStore",
    "VerificationResult",
    "check_bundle",
    "TRACE_PROFILE_V0_2",
    "SCHEMA",
    "iter_errors",
    "validate_json",
    "generate_key",
    "jwk_thumbprint",
    "key_to_jwk",
    "load_key",
    "load_signing_key",
    "sign_record",
    "verify_record",
]

# MCP Server Provenance Records (spec/server-provenance-v1.md) live in their own
# module: they describe an artifact rather than an execution, so importing them
# from the top level alongside TrustRecord would invite exactly the conflation
# the specification opens by ruling out.
from agentrust_trace import provenance as provenance  # noqa: E402

__all__ = [*__all__, "provenance"]
from agentrust_trace import content_marking as content_marking  # noqa: E402

__all__ = [*__all__, "content_marking"]
from agentrust_trace import intent_bridge as intent_bridge  # noqa: E402

__all__ = [*__all__, "intent_bridge"]
