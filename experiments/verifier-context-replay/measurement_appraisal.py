"""Deterministic, bounded platform-measurement appraisal with retained verifier context.

This is a synthetic signed-evidence interchange for the replay experiment, NOT a
TPM quote parser or a normative TRACE measurement format. It tests whether
identical record bytes produce differing policy appraisals when reference sets,
trust keys or required layers differ. Public key authority MUST be independently
pinned by the caller, not sourced solely from the record under appraisal.
"""
import base64
import hashlib
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _public(raw):
    if type(raw) is not bytes or len(raw) != 32:
        raise ValueError("missing-or-invalid-external-trust-root")
    return Ed25519PublicKey.from_public_bytes(raw)

def _signed_payload(document, trusted_key):
    if not isinstance(document, dict) or set(document) != {"payload", "signature"}:
        raise ValueError("missing-signed-evidence")
    payload, signature = document["payload"], document["signature"]
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("malformed-signed-evidence")
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in signature):
        raise ValueError("signature-encoding")
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    if len(raw) != 64:
        raise ValueError("signature-length")
    _public(trusted_key).verify(raw, rfc8785.dumps(payload))
    return payload

def appraise(record, *, reference, quote, policy, reference_public_key,
            quote_public_key, expected_reference_digest=None):
    """Return evidence-derived appraisal. Never infer authority from embedded claims."""
    try:
        if type(expected_reference_digest) is not str:
            return {"status": "not-established", "reason": "missing-reference-pin"}
        if digest(rfc8785.dumps(reference)) != expected_reference_digest:
            return {"status": "rejected", "reason": "reference-evidence-changed"}
        if not isinstance(policy, dict) or set(policy) != {
            "policy_id", "required_layers", "trusted_reference_key_digest",
            "trusted_quote_key_digest", "require_preexecution_appraisal"
        }:
            return {"status":"not-established","reason":"missing-effective-policy"}
        if not isinstance(policy["policy_id"], str) or not policy["policy_id"]:
            return {"status":"not-established","reason":"policy-id-missing"}
        if policy["trusted_reference_key_digest"] != digest(reference_public_key) or policy["trusted_quote_key_digest"] != digest(quote_public_key):
            return {"status":"rejected","reason":"trust-root-substitution"}
        required = policy["required_layers"]
        if not isinstance(required, list) or not required or not all(isinstance(x, str) and x for x in required) or len(set(required)) != len(required):
            return {"status":"not-established","reason":"invalid-required-layer-selection"}
        if type(policy["require_preexecution_appraisal"]) is not bool:
            return {"status":"not-established","reason":"invalid-appraisal-policy"}
        trusted = _signed_payload(reference, reference_public_key)
        measured = _signed_payload(quote, quote_public_key)
        if not isinstance(record, dict) or not isinstance(record.get("runtime"), dict):
            return {"status":"not-established","reason":"record-missing-runtime"}
        if measured.get("measurement") != record["runtime"].get("measurement"):
            return {"status":"rejected","reason":"quote-record-measurement-mismatch"}
        ref_layers, observed = trusted.get("layers"), measured.get("layers")
        if not isinstance(ref_layers, dict) or not isinstance(observed, dict):
            return {"status":"not-established","reason":"missing-layer-values"}
        results = {}
        for layer in required:
            value = observed.get(layer)
            target = ref_layers.get(layer)
            if not isinstance(value, dict) or not isinstance(target, dict):
                results[layer]={"outcome":"not-established","reason":"missing-layer-evidence"}
                continue
            if value.get("event_log_present") is True and value.get("event_log_replays") is not True:
                results[layer]={"outcome":"not-established","reason":"evidence-spans-multiple-boots"}
            elif value.get("value") != target.get("value") or not isinstance(value.get("value"), str):
                results[layer]={"outcome":"not-established","reason":"reference-value-mismatch"}
            elif value.get("holds_measurements") is not True:
                results[layer]={"outcome":"not-established","reason":"layer-not-measured"}
            elif policy["require_preexecution_appraisal"] and value.get("preexecution_appraised") is not True:
                results[layer]={"outcome":"not-established","reason":"measured-not-appraised"}
            else:
                results[layer]={"outcome":"established","route":"event-log" if value.get("event_log_present") else "trusted-reference"}
        complete=all(item["outcome"]=="established" for item in results.values())
        return {"status":"affirming" if complete else "not-established",
                "reason":"required-layers-established" if complete else "required-layer-not-established",
                "policy_id":policy["policy_id"],"reference_digest":expected_reference_digest,
                "layers":results}
    except Exception as exc:
        # Invalid signatures and untrusted evidence never generate a positive appraisal.
        return {"status":"rejected","reason":"invalid-or-unauthenticated-evidence:"+type(exc).__name__}
