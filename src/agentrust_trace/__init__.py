"""agentrust-trace — TRACE Trust Record models, validation, and signing."""

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
    JWK,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
    ToolTranscript,
    TrustRecord,
)
from agentrust_trace.sign import (
    RevocationStore,
    generate_key,
    jwk_thumbprint,
    key_to_jwk,
    load_key,
    load_signing_key,
    sign_record,
    verify_record,
)
from agentrust_trace.validate import (
    iter_errors,
    SCHEMA,
    validate_json,
)

__version__ = "0.2.0"

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
    "JWK",
    "ModelInfo",
    "PolicyInfo",
    "RuntimeInfo",
    "ToolTranscript",
    "TrustRecord",
    "RevocationStore",
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
