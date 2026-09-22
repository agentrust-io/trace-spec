"""Build the differential corpus: one JSON file both implementations read.

Every case carries the record as *text*, not as a parsed object, because several
of them exist to probe a difference that only survives in text: an `iat` written
`1785000000.0`, a lone surrogate in a string, a signature spelled with padding.
Both runners parse the same bytes with their own JSON parser, which is part of
what is being compared.

Keys derive from a published seed by role label, so the corpus regenerates
byte-identically for anyone. Nothing here is secret and nothing is fetched.

    python differential/generate_cases.py [--out differential/build/cases.json]
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
from typing import Any

from agentrust_trace.sign import jwk_thumbprint, key_to_jwk, sign_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
EXAMPLES = REPO / "examples"
BUILD = HERE / "build"
"""Generated artifacts live here: nothing under it is committed."""

NOW = 1785000000
"""The moment the repository's own vectors are written against."""


CORPUS_SEED_DOMAIN = "trace-verify-ts/differential"
"""Frozen: the label the corpus keys are derived from, not the package name.

It keeps its original spelling deliberately. Changing it reissues every key in
the corpus, which moves the outcomes the ledger in known-divergences.json pins
by case and count, so the rename of the package leaves it alone.
"""


def seeded_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"{CORPUS_SEED_DOMAIN}/{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


SIGNER = seeded_key("signer")
OTHER = seeded_key("other")

BASE_RECORD: dict[str, Any] = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": NOW,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
        "nonce": "a-nonce-value",
    },
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "internal",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    "cnf": {"jwk": {}},
}


def signed(record: dict[str, Any], key: Ed25519PrivateKey = SIGNER) -> dict[str, Any]:
    body = {k: v for k, v in record.items() if k not in {"signature", "cnf"}}
    return sign_record(body, key)


RECORD = signed(BASE_RECORD)
SIGNER_JWK = key_to_jwk(SIGNER)
OTHER_JWK = key_to_jwk(OTHER)
EC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}


def compact(value: Any) -> str:
    """Compact JSON text: the mutations are textual, so the spelling has to be fixed."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


VALID_BUNDLE = load(EXAMPLES / "revocation-bundle" / "01-fresh-well-inside-both-bounds.json")


def contexts() -> dict[str, dict[str, Any]]:
    """Verifier configurations, each naming one decision the record is judged under."""
    bundle_context = VALID_BUNDLE["context"]
    bundle_text = json.dumps(bundle_context["bundle"])
    signer_thumbprint = jwk_thumbprint(SIGNER_JWK)
    base = {"trusted_key": SIGNER_JWK, "now": NOW}
    return {
        "c00-pinned-key": {**base},
        "c01-no-key": {"now": NOW},
        "c02-embedded-key": {"now": NOW, "allow_embedded_key": True},
        "c03-age-at-bound": {**base, "now": NOW + 86400},
        "c04-age-one-past-bound": {**base, "now": NOW + 86401},
        "c05-future-at-skew": {**base, "now": NOW - 300},
        "c06-future-one-past-skew": {**base, "now": NOW - 301},
        "c07-no-age-bound": {**base, "now": NOW + 10**6, "max_age_seconds": None},
        "c08-zero-age-bound": {**base, "max_age_seconds": 0},
        "c09-nonce-matches": {**base, "expected_nonce": "a-nonce-value"},
        "c10-nonce-differs": {**base, "expected_nonce": "another-nonce"},
        "c11-store-lists-nothing": {**base, "revocation": {"kind": "list", "ids": []}},
        "c12-store-lists-thumbprint": {
            **base,
            "revocation": {"kind": "list", "ids": [signer_thumbprint]},
        },
        "c13-store-raises": {**base, "revocation": {"kind": "raises"}},
        "c14-store-answers-non-bool": {**base, "revocation": {"kind": "non_bool"}},
        "c15-wrong-key": {**base, "trusted_key": OTHER_JWK},
        "c16-ec-key": {**base, "trusted_key": EC_JWK},
        "c17-key-x-truncated": {**base, "trusted_key": {**SIGNER_JWK, "x": SIGNER_JWK["x"][:-4]}},
        "c18-key-x-non-canonical": {
            **base,
            "trusted_key": {**SIGNER_JWK, "x": SIGNER_JWK["x"][:-1] + "_"},
        },
        "c19-bundle": {
            **base,
            "revocation_bundle_json": bundle_text,
            "trusted_bundle_keys": bundle_context["trusted_bundle_keys"],
            "max_bundle_age_seconds": bundle_context["max_bundle_age_seconds"],
            "max_future_skew_seconds": bundle_context["max_future_skew_seconds"],
        },
        "c20-bundle-and-store": {
            **base,
            "revocation": {"kind": "list", "ids": []},
            "revocation_bundle_json": bundle_text,
            "trusted_bundle_keys": bundle_context["trusted_bundle_keys"],
        },
        "c21-bundle-untrusted-key": {
            **base,
            "revocation_bundle_json": bundle_text,
            "trusted_bundle_keys": [],
        },
        "c22-bundle-malformed": {
            **base,
            "revocation_bundle_json": json.dumps({"type": "TraceRevocationBundle/1.0"}),
            "trusted_bundle_keys": bundle_context["trusted_bundle_keys"],
        },
        "c23-bundle-lone-surrogate": {
            **base,
            "revocation_bundle_json": bundle_text.replace(
                "log.example/trace", "log.example/trace\\ud800"
            ),
            "trusted_bundle_keys": bundle_context["trusted_bundle_keys"],
        },
    }


def mutations() -> list[tuple[str, str]]:
    """(name, record text) pairs, each one thing done to the signed base record."""
    text = compact(RECORD)
    out: list[tuple[str, str]] = [("m00-unmodified", text)]

    def structural(name: str, change) -> None:
        record = copy.deepcopy(RECORD)
        change(record)
        out.append((name, compact(record)))

    def resigned(name: str, change) -> None:
        record = copy.deepcopy(RECORD)
        change(record)
        out.append((name, compact(signed(record))))

    sig = RECORD["signature"]
    for name, value in [
        ("m01-signature-padded", sig + "="),
        ("m02-signature-standard-alphabet", sig.replace("-", "+").replace("_", "/")),
        ("m03-signature-non-canonical-pad-bits", sig[:-1] + "_"),
        ("m04-signature-truncated", sig[:-4]),
        ("m05-signature-trailing-newline", sig + "\n"),
        ("m06-signature-empty", ""),
        ("m07-signature-flipped", ("B" if sig[0] != "B" else "C") + sig[1:]),
    ]:
        structural(name, lambda record, v=value: record.__setitem__("signature", v))
    for name, literal in [
        ("m08-signature-zero", "0"),
        ("m09-signature-false", "false"),
        ("m10-signature-null", "null"),
        ("m11-signature-empty-array", "[]"),
        ("m12-signature-empty-object", "{}"),
        ("m13-signature-number", "1785000000"),
    ]:
        out.append((
            name,
            text.replace(f'"signature":{compact(sig)}', f'"signature":{literal}'),
        ))
    out.append(("m14-signature-absent",
                compact({k: v for k, v in RECORD.items() if k != "signature"})))

    structural(
        "m15-profile-v0-1",
        lambda r: r.__setitem__("eat_profile", "tag:agentrust.io,2026:trace-v0.1"),
    )
    structural("m16-profile-unknown", lambda r: r.__setitem__("eat_profile", "urn:example:other"))
    structural("m17-profile-empty", lambda r: r.__setitem__("eat_profile", ""))
    structural("m18-profile-number", lambda r: r.__setitem__("eat_profile", 2))
    structural("m19-profile-absent", lambda r: r.pop("eat_profile"))

    iat_literal = f'"iat":{NOW}'
    for name, literal in [
        ("m20-iat-float-form", f'"iat":{NOW}.0'),
        ("m21-iat-exponent-form", '"iat":1.785e9'),
        ("m22-iat-string", f'"iat":"{NOW}"'),
        ("m23-iat-true", '"iat":true'),
        ("m24-iat-negative", '"iat":-1'),
        ("m25-iat-past-safe-integer", '"iat":9007199254740993'),
    ]:
        out.append((name, text.replace(iat_literal, literal)))
    structural("m26-iat-absent", lambda r: r.pop("iat"))

    resigned(
        "m27-subject-trailing-newline",
        lambda r: r.__setitem__("subject", r["subject"] + "\n"),
    )
    resigned(
        "m28-subject-carriage-return",
        lambda r: r.__setitem__("subject", r["subject"] + "\r"),
    )
    resigned("m29-subject-line-separator", lambda r: r.__setitem__("subject", r["subject"] + " "))
    resigned("m30-subject-empty", lambda r: r.__setitem__("subject", ""))
    resigned(
        "m31-verifier-uri-trailing-newline",
        lambda r: r["appraisal"].__setitem__("verifier", r["appraisal"]["verifier"] + "\n"),
    )
    resigned(
        "m32-verifier-uri-ipv6-leading-zero",
        lambda r: r["appraisal"].__setitem__("verifier", "https://[::1.2.3.04]/"),
    )
    resigned(
        "m33-verifier-uri-not-a-uri",
        lambda r: r["appraisal"].__setitem__("verifier", "not a uri"),
    )
    resigned("m34-unknown-top-level-member", lambda r: r.__setitem__("unknown_member", 1))
    resigned("m35-unknown-nested-member", lambda r: r["appraisal"].__setitem__("unknown", 1))
    resigned(
        "m36-measurement-not-a-digest",
        lambda r: r["runtime"].__setitem__("measurement", "sha256:zz"),
    )
    resigned(
        "m37-slsa-level-out-of-range",
        lambda r: r["build_provenance"].__setitem__("slsa_level", 5),
    )
    resigned(
        "m38-enforcement-mode-unknown",
        lambda r: r["policy"].__setitem__("enforcement_mode", "audit-ish"),
    )
    resigned("m39-runtime-absent", lambda r: r.pop("runtime"))
    resigned(
        "m40-appraisal-status-unknown",
        lambda r: r["appraisal"].__setitem__("status", "excellent"),
    )
    resigned("m41-nonce-non-ascii", lambda r: r["runtime"].__setitem__("nonce", "nønce"))
    resigned("m42-nonce-absent", lambda r: r["runtime"].pop("nonce"))

    structural("m43-cnf-jwk-kty-ec", lambda r: r["cnf"].__setitem__("jwk", EC_JWK))
    structural(
        "m44-cnf-jwk-crv-x25519",
        lambda r: r["cnf"]["jwk"].__setitem__("crv", "X25519"),
    )
    structural("m45-cnf-jwk-x-absent", lambda r: r["cnf"]["jwk"].pop("x"))
    structural(
        "m46-cnf-jwk-x-non-canonical",
        lambda r: r["cnf"]["jwk"].__setitem__("x", SIGNER_JWK["x"][:-1] + "_"),
    )
    structural(
        "m47-cnf-jwk-x-truncated",
        lambda r: r["cnf"]["jwk"].__setitem__("x", SIGNER_JWK["x"][:-4]),
    )
    structural("m48-cnf-jwk-other-key", lambda r: r["cnf"].__setitem__("jwk", OTHER_JWK))
    structural("m49-cnf-jwk-with-kid", lambda r: r["cnf"]["jwk"].__setitem__("kid", "a-kid"))
    structural("m50-cnf-absent", lambda r: r.pop("cnf"))
    structural("m51-cnf-jwk-empty", lambda r: r["cnf"].__setitem__("jwk", {}))

    out.append(("m52-lone-surrogate-in-subject", text.replace(
        compact(RECORD["subject"]), compact(RECORD["subject"])[:-1] + '\\ud800"')))
    out.append(("m53-duplicate-member", text.replace(
        '"eat_profile":', '"eat_profile":"urn:example:shadowed","eat_profile":', 1)))
    out.append(("m54-not-an-object-array", "[]"))
    out.append(("m55-not-an-object-string", '"a record"'))
    out.append(("m56-not-an-object-null", "null"))
    out.append(("m57-not-an-object-number", "1"))
    out.append(("m58-empty-object", "{}"))
    return out


def jcs_cases() -> list[dict[str, Any]]:
    """Values whose canonical form, or refusal to have one, is compared directly."""
    literals = [
        "{}", "[]", "0", "-0", "1", "-1", "1.0", "0.1", "1e2", "1e-7", "1.0e+21",
        "9007199254740991", "9007199254740992", "-9007199254740991", "9007199254740993",
        '"\\u00e9"', '"\\ud83d\\ude00"', '"\\u0000"', '"\\u001f"', '"\\u007f"',
        '"\\u2028"', '"\\ud800"', '"\\udfff"', '"\\ud800\\udc00"', '"\\ufffe"',
        '{"b":1,"a":2}', '{"\\u00e9":1,"z":2}', '{"\\ud83d\\ude00":1,"\\ufb33":2}',
        '{"a":{"d":1,"c":[3,2,{"f":1,"e":2}]}}', '{"":1}', '{"a":null,"b":true,"c":false}',
        '[1,"two",{"three":3},[4]]', '{"a":1e400}',
        '{"k":"line\\nbreak\\tand\\\\slash\\"quote"}',
    ]
    return [{"id": f"jcs-{i:02d}", "kind": "jcs", "group": "D2-jcs", "value_json": literal}
            for i, literal in enumerate(literals)]


def thumbprint_cases() -> list[dict[str, Any]]:
    keys: list[Any] = [
        SIGNER_JWK,
        {**SIGNER_JWK, "kid": "a-kid", "use": "sig", "alg": "EdDSA"},
        EC_JWK,
        {**EC_JWK, "y": None},
        {"kty": "OKP", "crv": "Ed25519"},
        {"kty": "OKP", "crv": "Ed25519", "x": ""},
        {"kty": "oct", "k": "AQID"},
        {"kty": "RSA", "n": "0vx7ag", "e": "AQAB"},
        {"kty": None},
        {},
        [],
        "jwk",
        None,
        {"kty": "OKP", "crv": "Ed25519", "x": SIGNER_JWK["x"], "extra": {"nested": True}},
    ]
    return [{"id": f"thumb-{i:02d}", "kind": "thumbprint", "group": "D3-thumbprint",
             "value_json": json.dumps(key)} for i, key in enumerate(keys)]


def chain_digest_cases() -> list[dict[str, Any]]:
    """Every record in the delegation corpus, digested under both algorithms."""
    cases = []
    for path in sorted((EXAMPLES / "delegation-link").glob("*.json")):
        vector = load(path)
        for index, record in enumerate(vector.get("records", [])):
            for algorithm in ("sha256", "sha384"):
                cases.append({
                    "id": f"chain-{path.stem}-{index}-{algorithm}",
                    "kind": "chain_digest",
                    "group": "D4-chain-digest",
                    "algorithm": algorithm,
                    "value_json": json.dumps(record, ensure_ascii=False),
                })
    return cases


def repository_vector_cases() -> list[dict[str, Any]]:
    """The repository's own signed records, under the context each vector states."""
    cases = []
    for path in sorted((EXAMPLES / "canonicalization-boundary").glob("*.json")):
        vector = load(path)
        cases.append({
            "id": f"repo-canon-{path.stem}",
            "kind": "verify",
            "group": "D5-repository-vectors",
            "record_json": json.dumps(vector["record"], ensure_ascii=False),
            "options": {"trusted_key": vector["trusted_key"], "now": vector["record"]["iat"]},
        })
    for path in sorted((EXAMPLES / "revocation-bundle").glob("*.json")):
        vector = load(path)
        context = vector["context"]
        for index, record in enumerate(vector["records"]):
            cases.append({
                "id": f"repo-bundle-{path.stem}-{index}",
                "kind": "verify",
                "group": "D5-repository-vectors",
                "record_json": json.dumps(record, ensure_ascii=False),
                "options": {
                    "trusted_key": context["trusted_key"],
                    "now": context["now"],
                    "revocation_bundle_json": json.dumps(context["bundle"]),
                    "trusted_bundle_keys": context["trusted_bundle_keys"],
                    "max_bundle_age_seconds": context["max_bundle_age_seconds"],
                    "max_future_skew_seconds": context["max_future_skew_seconds"],
                },
            })
    return cases


def external_vector_cases(root: pathlib.Path | None) -> list[dict[str, Any]]:
    """The published conformance vectors, read from a pinned checkout.

    Nothing is vendored: the directory is passed in, and `build/manifest.json`
    records the SHA-256 of every file the corpus was built from. A root that is
    passed and cannot be read is an error, not an empty group: the workflow pins
    the checkout and asserts the case count, and a silent empty group would print
    the same `unexpected: 0` as a full one.
    """
    cases: list[dict[str, Any]] = []
    manifest: dict[str, str] = {}
    if root is None:
        write_manifest(manifest)
        return cases
    if not root.is_dir():
        raise SystemExit(f"--external {root}: not a directory")
    for path in sorted(root.rglob("*.json")):
        raw = path.read_bytes()
        name = path.relative_to(root).as_posix()
        manifest[name] = hashlib.sha256(raw).hexdigest()
        document = json.loads(raw.decode("utf-8"))
        record = None
        if isinstance(document, dict):
            for member in ("record", "trace"):
                candidate = document.get(member)
                if isinstance(candidate, dict) and "eat_profile" in candidate:
                    record = candidate
                    break
            if record is None:
                record = document
        if not isinstance(record, dict) or "eat_profile" not in record:
            continue
        trusted_key = document.get("trusted_key") if isinstance(document, dict) else None
        issued = record.get("iat")
        # `now` is the verifier's own argument and is refused outside the safe
        # range before the record is read; a vector whose point is an `iat`
        # outside that range must be judged at a valid `now`.
        valid_now = (
            isinstance(issued, int) and not isinstance(issued, bool)
            and 0 <= issued <= 2**53 - 1
        )
        options: dict[str, Any] = {"now": issued if valid_now else NOW}
        if isinstance(trusted_key, dict):
            options["trusted_key"] = trusted_key
        else:
            options["allow_embedded_key"] = True
        cases.append({
            "id": f"external-{name.removesuffix('.json').replace('/', '-')}",
            "kind": "verify",
            "group": "D6-published-vectors",
            "record_json": json.dumps(record, ensure_ascii=False),
            "options": options,
        })
    write_manifest(manifest)
    if not cases:
        raise SystemExit(f"--external {root}: {len(manifest)} JSON files, no Trust Record in them")
    return cases


def write_manifest(manifest: dict[str, str]) -> None:
    """Always written, empty when no vectors were read, so compare.py never reads a
    manifest left behind by an earlier run against a different checkout."""
    (BUILD / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build(external: pathlib.Path | None) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for context_name, options in contexts().items():
        for mutation_name, record_json in mutations():
            cases.append({
                "id": f"{context_name}/{mutation_name}",
                "kind": "verify",
                "group": "D1-record-under-context",
                "record_json": record_json,
                "options": options,
            })
    cases += repository_vector_cases()
    cases += external_vector_cases(external)
    cases += jcs_cases()
    cases += thumbprint_cases()
    cases += chain_digest_cases()
    return {
        "signer_jwk": SIGNER_JWK,
        "other_jwk": OTHER_JWK,
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, default=BUILD / "cases.json")
    parser.add_argument("--external", type=pathlib.Path, default=None,
                        help="a checkout of the published conformance vectors")
    arguments = parser.parse_args()
    BUILD.mkdir(exist_ok=True)
    corpus = build(arguments.external)
    arguments.out.write_text(
        json.dumps(corpus, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"{len(corpus['cases'])} cases written to {arguments.out}")


if __name__ == "__main__":
    main()
