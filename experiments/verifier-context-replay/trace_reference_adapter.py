"""Adapter to the actual TRACE reference verifier; never treats replay integrity as TRACE validity.

Requires installation of the upstream trace-spec Python package and its dependencies
(including rfc8785). Offline/no network at verification time.
"""
import importlib
from dataclasses import dataclass

@dataclass(frozen=True)
class ReferenceResult:
    status: str
    reason: str

def verify_trace_record(record, trusted_keys, *, verification_time, max_age_seconds,
                        max_future_skew_seconds, expected_nonce=None, revoked_keys=None):
    if type(verification_time) is not int:
        return ReferenceResult("not-established", "verification-time-required")
    try:
        module = importlib.import_module("agentrust_trace.sign")
    except ImportError:
        return ReferenceResult("not-established", "trace-reference-dependency-unavailable")
    # Refuse to guess the reference verifier API or inject ambient time.
    import inspect
    verifier = getattr(module, "verify_record", None)
    if verifier is None:
        return ReferenceResult("not-established", "reference-verifier-missing")
    parameters = inspect.signature(verifier).parameters
    if "now" not in parameters and "verification_time" not in parameters:
        return ReferenceResult("not-established", "reference-verifier-cannot-pin-time")
    kwargs = {"max_age_seconds": max_age_seconds,
              "max_future_skew_seconds": max_future_skew_seconds}
    if "verification_time" in parameters:
        kwargs["verification_time"] = verification_time
    else:
        kwargs["now"] = verification_time
    if expected_nonce is not None and "expected_nonce" not in parameters:
        return ReferenceResult("not-established", "reference-verifier-cannot-check-nonce")
    if expected_nonce is not None:
        kwargs["expected_nonce"] = expected_nonce
    if revoked_keys is not None and "revocation" not in parameters:
        return ReferenceResult("not-established", "reference-verifier-cannot-check-revocation")
    if revoked_keys is not None:
        kwargs["revocation"] = revoked_keys
    try:
        result = verifier(record, trusted_keys, **kwargs)
    except Exception as exc:
        return ReferenceResult("rejected", type(exc).__name__)
    # The upstream verifier returns a typed VerificationResult on success.
    # Refuse unknown values, including false, true and silent None returns.
    result_type = getattr(module, "VerificationResult", None)
    if not isinstance(result_type, type) or not isinstance(result, result_type):
        return ReferenceResult("not-established", "unexpected-reference-verdict")
    return ReferenceResult("verified", "trace-signature-and-requested-checks-passed")
