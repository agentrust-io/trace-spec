"""Offline verifier-context consistency checker; does NOT verify TRACE signatures."""
import hashlib
import json
import sys

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

REQUIRED = ("record_digest", "issued_at", "verification_time", "max_age_seconds",
            "max_future_skew_seconds", "policy_digest", "trust_roots_digest",
            "verifier_identity", "verifier_version", "resolver_evidence")

def evaluate(case):
    missing = [key for key in REQUIRED if key not in case or case[key] is None]
    if missing:
        return {"outcome": "not-established", "reason": "missing-context", "missing": missing}
    if type(case["verification_time"]) is not int or type(case["issued_at"]) is not int:
        return {"outcome": "not-established", "reason": "invalid-time"}
    if any(type(case[key]) is not int or case[key] < 0
           for key in ("max_age_seconds", "max_future_skew_seconds")):
        return {"outcome": "not-established", "reason": "invalid-bounds"}
    evidence = case["resolver_evidence"]
    if not isinstance(evidence, list) or not evidence or any(
        not isinstance(item, dict) or not isinstance(item.get("digest"), str)
        or not isinstance(item.get("bytes_digest"), str)
        for item in evidence
    ):
        return {"outcome": "not-established", "reason": "resolver-evidence-missing"}
    if any(item["digest"] != item["bytes_digest"] for item in evidence):
        return {"outcome": "rejected", "reason": "resolver-digest-mismatch"}
    age = case["verification_time"] - case["issued_at"]
    if age > case["max_age_seconds"]:
        return {"outcome": "rejected", "reason": "stale"}
    if age < -case["max_future_skew_seconds"]:
        return {"outcome": "rejected", "reason": "future"}
    return {"outcome": "context-consistent", "reason": "signature-and-policy-not-verified"}

def envelope(case):
    return {"context_digest": digest(case), "result": evaluate(case)}

if __name__ == "__main__":
    print(json.dumps(envelope(json.load(sys.stdin)), sort_keys=True))
