"""agentrust-trace — TRACE v0.1 Trust Record models and validation."""

from agentrust_trace.models import (
    Appraisal,
    BuildProvenance,
    ConfirmationKey,
    JWK,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
    ToolTranscript,
    TrustRecord,
)
from agentrust_trace.validate import (
    iter_errors,
    SCHEMA,
    validate_json,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Appraisal",
    "BuildProvenance",
    "ConfirmationKey",
    "JWK",
    "ModelInfo",
    "PolicyInfo",
    "RuntimeInfo",
    "ToolTranscript",
    "TrustRecord",
    "SCHEMA",
    "iter_errors",
    "validate_json",
]
