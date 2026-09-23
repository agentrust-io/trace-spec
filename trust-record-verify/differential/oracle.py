"""Run the differential corpus through the Python implementation and record verdicts.

The reference reports a rejection as an exception, and several distinct checks
raise the same exception type with a message that is not machine readable. Two of
them raise the *same message* from the same helper, called twice: once for the
trusted key and once for the record's `cnf.jwk`. Classifying on the message alone
would merge those two checks, so the classifier reads the traceback and asks which
call site inside `verify_record` the exception came from. The line numbers are
looked up in the installed source rather than written down here, so a release that
moves them is a lookup failure rather than a silent misclassification.

An exception this classifier does not recognise is recorded as `unclassified` with
its text, and the comparison reports it. Nothing is guessed.

    python differential/oracle.py [--cases build/cases.json] [--out build/python.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import pathlib
import re
import traceback
import warnings
from typing import Any

import agentrust_trace
import rfc8785
from agentrust_trace.sign import jwk_thumbprint, verify_record
from cryptography.exceptions import InvalidSignature


def _call_sites() -> dict[str, int]:
    """Line numbers of the two `_pubkey_from_jwk` calls inside `verify_record`."""
    lines, start = inspect.getsourcelines(verify_record)
    sites: dict[str, int] = {}
    for offset, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("pub = _pubkey_from_jwk(public_key_or_jwk)"):
            sites["trusted_key"] = start + offset
        elif stripped.startswith("_pubkey_from_jwk(embedded_jwk)"):
            sites["cnf_key"] = start + offset
    missing = {"trusted_key", "cnf_key"} - set(sites)
    if missing:
        raise SystemExit(
            f"cannot locate the {sorted(missing)} call site in this release of "
            "agentrust_trace; the classifier would merge two checks, so it refuses to run"
        )
    return sites


CALL_SITES = _call_sites()

MESSAGE_CODES: list[tuple[str, str]] = [
    ("now must be an integer", "invalid_argument"),
    ("must be non-negative", "invalid_argument"),
    ("record must be a JSON object", "record_not_object"),
    ("record has no 'eat_profile'", "profile_missing"),
    ("carries the superseded v0.1 profile", "profile_superseded"),
    ("is not 'tag:agentrust-io.com,2026:trace-v0.2'", "profile_unsupported"),
    ("is not in this verifier's accepted set", "profile_unsupported"),
    ("record has no 'signature' field", "signature_missing"),
    ("signature must be a base64url string", "signature_malformed"),
    ("signature is not valid base64url", "signature_malformed"),
    ("record does not conform to the TRACE v0.2 schema", "schema_invalid"),
    ("verify_record requires a trusted key", "trusted_key_missing"),
    ("record has no cnf.jwk and no public key was supplied", "trusted_key_missing"),
    ("revocation status for key", "revocation_unavailable"),
    ("signing key is revoked", "key_revoked"),
    ("record has no valid cnf.jwk confirmation key", "cnf_key_malformed"),
    ("record cnf.jwk does not identify the trusted key", "cnf_key_mismatch"),
    ("record has no valid integer 'iat'", "iat_invalid"),
    ("is dated", "record_in_future"),
    ("record is stale", "record_stale"),
    ("record runtime.nonce does not match", "nonce_mismatch"),
]

KEY_MESSAGES: list[tuple[str, str]] = [
    ("unsupported JWK kty", "unsupported"),
    ("unsupported JWK crv", "unsupported"),
    ("JWK missing 'x' field", "malformed"),
    ("JWK 'x' must be a base64url string", "malformed"),
    ("JWK 'x' is not valid base64url", "malformed"),
    ("An Ed25519 public key is 32 bytes", "malformed"),
    ("public key is 32 bytes", "malformed"),
]

SCHEMA_LOCATION = re.compile(r"schema at (?P<location>[^:]*):")


def classify(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, InvalidSignature):
        return {"code": "signature_invalid"}
    text = str(exc)
    if isinstance(exc, TypeError) and "comparing strings with non-ASCII" in text:
        # `hmac.compare_digest` refuses a str outside ASCII, so a record whose
        # nonce is not ASCII leaves `verify_record` as a TypeError, which is not a
        # documented outcome. Named rather than left unclassified: the classifier
        # has understood it, and the comparison reports it as a divergence.
        return {"code": "nonce_compare_unsupported"}
    if isinstance(exc, rfc8785.CanonicalizationError) or type(exc).__name__ in {
        "CanonicalizationError",
        "IntegerDomainError",
        "NaNError",
        "InfError",
    }:
        return {"code": "canonicalization_failed", "detail": text}
    if isinstance(exc, RecursionError):
        # rfc8785 recurses once per nesting level; a value nested past the
        # interpreter's stack has no canonical form this runner can produce,
        # which is what the other side reports for the same text.
        return {"code": "canonicalization_failed", "detail": f"RecursionError: {text}"}
    if isinstance(exc, ValueError):
        for fragment, code in MESSAGE_CODES:
            if fragment in text:
                result: dict[str, Any] = {"code": code}
                if code == "schema_invalid":
                    match = SCHEMA_LOCATION.search(text)
                    result["path"] = match.group("location").strip() if match else None
                return result
        for fragment, kind in KEY_MESSAGES:
            if fragment in text:
                frames = [f for f in traceback.extract_tb(exc.__traceback__)
                          if f.name == "verify_record"]
                if not frames:
                    return {"code": f"jwk_{kind}", "detail": text}
                line = frames[-1].lineno
                role = "trusted_key" if line <= CALL_SITES["cnf_key"] else "cnf_key"
                if line == CALL_SITES["cnf_key"]:
                    role = "cnf_key"
                elif line == CALL_SITES["trusted_key"]:
                    role = "trusted_key"
                return {"code": f"{role}_{kind}"}
        if "thumbprint" in text or "jwk must be a JSON object" in text:
            return {"code": "jwk_invalid", "detail": text}
    return {"code": "unclassified", "detail": f"{type(exc).__name__}: {text}"}


def store_from(spec: dict[str, Any] | None):
    if spec is None:
        return None
    kind = spec["kind"]
    if kind == "list":
        return list(spec["ids"])
    if kind == "raises":
        def raising(identifier: str) -> bool:
            raise RuntimeError("the revocation source is unreachable")
        return raising
    if kind == "non_bool":
        return lambda identifier: None
    raise SystemExit(f"unknown revocation store kind {kind!r}")


def scrub(evidence: dict[str, Any]) -> dict[str, Any]:
    """Evidence without the two members that carry a human-readable message."""
    return {k: v for k, v in evidence.items() if k not in {"error", "key"}}


def parse(text: str) -> Any:
    """json.loads with the two failures a corpus can provoke turned into one exception.

    A case's text is arbitrary bytes from another repository; a text this parser
    refuses, or nests deeper than the interpreter's stack, is a verdict on the
    case, not a crash of the runner. `run.mjs` reports the same case as
    `parse_error`, so the comparison sees a verdict on both sides.
    """
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ParseError(f"{type(exc).__name__}: {exc}") from exc


class ParseError(Exception):
    pass


def run_verify(case: dict[str, Any]) -> dict[str, Any]:
    options = case["options"]
    try:
        record = parse(case["record_json"])
    except ParseError as exc:
        return {"verdict": "parse_error", "detail": str(exc)}
    bundle_json = options.get("revocation_bundle_json")
    try:
        bundle = parse(bundle_json) if bundle_json is not None else None
    except ParseError as exc:
        return {"verdict": "parse_error", "detail": f"bundle: {exc}"}
    keywords: dict[str, Any] = {
        "allow_embedded_key": options.get("allow_embedded_key", False),
        "now": options.get("now"),
        "max_future_skew_seconds": options.get("max_future_skew_seconds", 300),
        "max_bundle_age_seconds": options.get("max_bundle_age_seconds", 86400),
        "expected_nonce": options.get("expected_nonce"),
        "revocation": store_from(options.get("revocation")),
        "revocation_bundle": bundle,
        "trusted_bundle_keys": options.get("trusted_bundle_keys"),
    }
    if "max_age_seconds" in options:
        keywords["max_age_seconds"] = options["max_age_seconds"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            result = verify_record(record, options.get("trusted_key"), **keywords)
        except BaseException as exc:  # noqa: BLE001 - every rejection is classified
            return {"verdict": "rejected", **classify(exc)}
    return {
        "verdict": "verified",
        "thumbprint": result.trusted_key_thumbprint,
        # Which key verified the record. The result carries no such member, so
        # this states it the way verify_record resolves it: the caller's key when
        # one is passed, the record's own cnf.jwk otherwise. The TypeScript side
        # reports what it used, and the two must agree even where the thumbprints
        # would, as they do whenever the caller passes the key the record embeds.
        "key_source": "caller" if options.get("trusted_key") is not None else "record",
        "revocation": {
            "outcome": result.revocation.outcome,
            "cause": result.revocation.cause,
            "evidence": scrub(dict(result.revocation.evidence)),
        },
    }


def run_jcs(case: dict[str, Any]) -> dict[str, Any]:
    try:
        value = parse(case["value_json"])
    except ParseError as exc:
        return {"verdict": "parse_error", "detail": str(exc)}
    try:
        return {"verdict": "canonical", "bytes": rfc8785.dumps(value).decode("utf-8")}
    except BaseException as exc:  # noqa: BLE001
        return {"verdict": "rejected", **classify(exc)}


def run_thumbprint(case: dict[str, Any]) -> dict[str, Any]:
    try:
        value = parse(case["value_json"])
    except ParseError as exc:
        return {"verdict": "parse_error", "detail": str(exc)}
    try:
        return {"verdict": "thumbprint", "value": jwk_thumbprint(value)}
    except BaseException as exc:  # noqa: BLE001
        return {"verdict": "rejected", **classify(exc)}


def run_chain_digest(case: dict[str, Any]) -> dict[str, Any]:
    try:
        record = parse(case["value_json"])
    except ParseError as exc:
        return {"verdict": "parse_error", "detail": str(exc)}
    algorithm = case["algorithm"]
    try:
        canonical = rfc8785.dumps(record)
    except BaseException as exc:  # noqa: BLE001
        return {"verdict": "rejected", **classify(exc)}
    return {"verdict": "digest",
            "value": f"{algorithm}:{hashlib.new(algorithm, canonical).hexdigest()}"}


RUNNERS = {
    "verify": run_verify,
    "jcs": run_jcs,
    "thumbprint": run_thumbprint,
    "chain_digest": run_chain_digest,
}


def main() -> None:
    here = pathlib.Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=pathlib.Path, default=here / "build" / "cases.json")
    parser.add_argument("--out", type=pathlib.Path, default=here / "build" / "python.jsonl")
    arguments = parser.parse_args()
    corpus = json.loads(arguments.cases.read_text(encoding="utf-8"))
    with arguments.out.open("w", encoding="utf-8") as handle:
        for case in corpus["cases"]:
            verdict = RUNNERS[case["kind"]](case)
            handle.write(json.dumps({"id": case["id"], "group": case["group"], **verdict},
                                    sort_keys=True) + "\n")
    print(f"{len(corpus['cases'])} verdicts from agentrust-trace {agentrust_trace.__version__} "
          f"written to {arguments.out}")


if __name__ == "__main__":
    main()
