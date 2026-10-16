"""Generate the citation-resolution conformance vectors (spec section 3.1.2).

A Trust Record cites objects it does not carry: `appraisal.policy_ref`,
`runtime.rim_uri` and `model.aibom_uri` are URIs the schema constrains to
`format: uri`, two of which the adapters write, and, until this module,
nothing under `src/` read. The consumer in `agentrust_trace.citation` records,
per surface, whether a caller-supplied resolver produced bytes for the URI and
what they hashed to. These vectors pin that record and nothing more: no vector
asserts that a resolved object binds the record (agentrust-io/trace-spec#280
holds that question), and no vector reads `references[]` (section 3.1.2 rule
3).

**The three fields are record members, not `references[]` entries.** The
section 3.1.2 anchor names the discipline this set mirrors, rule 3 and the
paragraph explaining why TR-POL-003 takes its resolver from the caller, not
the block it describes.

**Bytes in hand.** `context.resolutions` maps each URI the harness can resolve
to the cited object's bytes, base64-encoded so the bytes the digest covers are
exact and unescaped. That is what the revocation and delegation-link sets
already do with their bundles and credentials: a resolver that reaches the
network is a harness question and lives in `tests/`, not here. The cited
objects are small ASCII documents so a reader can decode them; their content is
irrelevant to the consumer, which hashes what it is handed and reads none of it.

**What the set discriminates.** Per consumed surface: no resolver at all;
a resolver that lacks the URI; a resolver that has it; a record that does not
carry the field; and a record that carries it, a resolver that lacks it, and a
verification that still completes. One vector resolves all three at once. Every
vector carries `transparency`, and every expected block shows it deferred, so a
consumer that reads that surface fails the whole set. Raising and non-bytes
resolvers are not vectors: a fixture cannot carry a function, so those live in
`tests/test_citation_resolution.py`.

**The context block.** `context.now`, `max_age_seconds` and
`max_future_skew_seconds` bound the record itself, as the revocation vectors
bound the bundle with `max_bundle_age_seconds`, so the record's own freshness
check reproduces from retained facts. `resolutions` is absent, not
empty, in the no-resolver vectors: absent means the harness supplies no
resolver; present and lacking a URI means the resolver raises `KeyError`.

The key derives from one published seed so the set regenerates byte-for-byte.
Files are written as bytes with LF line endings, so the set regenerates
identically on every platform.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.sign import key_to_jwk, sign_record

OUT = Path("examples/citation-resolution")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SPEC = "spec/trace-v0.2.md#312-references-facts-this-record-points-at"

SEED = hashlib.sha256(b"trace-spec citation-resolution fixture key").digest()

#: Fixed verification moment; the record is issued one hour before it.
NOW = 1785000000
IAT = NOW - 3600
MAX_AGE = 86400
SKEW = 300

#: The consumed surfaces, in the consumer's report order, and the deferred one.
CONSUMED = ("appraisal.policy_ref", "runtime.rim_uri", "model.aibom_uri")
DEFERRED_REASON = (
    "coordinated in agentrust-io/trace-tests#92; spec section 7 open question 3"
)
SHORT = {
    "appraisal.policy_ref": "policy-ref",
    "runtime.rim_uri": "rim-uri",
    "model.aibom_uri": "aibom-uri",
}
URI = {
    "appraisal.policy_ref": "https://policy.example/trace/appraisal-policy-v1.json",
    "runtime.rim_uri": "https://rim.example/software-only/measurement-00.json",
    "model.aibom_uri": "https://aibom.example/claude-sonnet-4-6/cyclonedx-1.7.json",
}
TRANSPARENCY = "https://log.example/trace/receipts/1"

#: The cited objects. Small ASCII documents; the consumer reads none of them.
OBJECTS: dict[str, bytes] = {
    URI["appraisal.policy_ref"]: (
        b'{"policy": "appraisal-policy-v1", '
        b'"note": "content is irrelevant to the consumer"}\n'
    ),
    URI["runtime.rim_uri"]: (
        b'{"rim": "software-only/measurement-00", '
        b'"note": "content is irrelevant to the consumer"}\n'
    ),
    URI["model.aibom_uri"]: (
        b'{"bomFormat": "CycloneDX", "specVersion": "1.7", '
        b'"note": "content is irrelevant to the consumer"}\n'
    ),
    TRANSPARENCY: (
        b'{"receipt": "1", '
        b'"note": "never read: the transparency surface is deferred"}\n'
    ),
}


def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEED)


def base_record() -> dict[str, Any]:
    """A schema-valid v0.2 record with nothing optional except what the set needs."""
    return {
        "eat_profile": V0_2,
        "iat": IAT,
        "subject": "spiffe://acme.example/agent/citer",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "00" * 32},
        "policy": {"bundle_hash": "sha256:" + "aa" * 32, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "bb" * 32},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
        "transparency": TRANSPARENCY,
    }


def record_citing(*surfaces: str) -> dict[str, Any]:
    """A signed record carrying exactly the named consumed surfaces."""
    body = base_record()
    for path in surfaces:
        head, leaf = path.split(".")
        body[head][leaf] = URI[path]
    return sign_record(body, key())


def resolutions_for(*uris: str) -> dict[str, dict[str, str]]:
    return {u: {"bytes_base64": base64.b64encode(OBJECTS[u]).decode("ascii")} for u in uris}


def lookup(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def expected_for(
    record: dict[str, Any], resolutions: dict[str, dict[str, str]] | None
) -> dict[str, Any]:
    """The consumer's decision procedure, restated here so `expected` cannot drift."""
    rows: dict[str, dict[str, Any]] = {}
    for path in CONSUMED:
        if resolutions is None:
            rows[path] = {"outcome": "not_attempted", "cause": "no_resolver", "evidence": {}}
            continue
        uri = lookup(record, path)
        if uri is None:
            rows[path] = {"outcome": "not_attempted", "cause": "field_absent", "evidence": {}}
        elif uri not in resolutions:
            rows[path] = {
                "outcome": "unresolvable",
                "cause": "resolver_raised",
                "evidence": {"uri": uri, "exception": "KeyError"},
            }
        else:
            raw = base64.b64decode(resolutions[uri]["bytes_base64"])
            rows[path] = {
                "outcome": "resolved",
                "cause": None,
                "evidence": {
                    "uri": uri,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                },
            }
    rows["transparency"] = {
        "outcome": "not_attempted",
        "cause": "surface_deferred",
        "evidence": {"reason": DEFERRED_REASON},
    }
    return {"rejected": False, "codes": [], "citations": rows}


def vector(
    n: int,
    name: str,
    description: str,
    *,
    record: dict[str, Any],
    resolutions: dict[str, dict[str, str]] | None,
) -> tuple[str, dict[str, Any]]:
    context: dict[str, Any] = {
        "now": NOW,
        "max_age_seconds": MAX_AGE,
        "max_future_skew_seconds": SKEW,
        "trusted_key": key_to_jwk(key()),
    }
    if resolutions is not None:
        context["resolutions"] = resolutions
    return f"{n:02d}-{name}.json", {
        "id": f"TRACE-CRES-{n:03d}",
        "name": name,
        "description": description,
        "spec": SPEC,
        "context": context,
        "records": [copy.deepcopy(record)],
        "expected": expected_for(record, resolutions),
    }


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []
    n = 0
    for path in CONSUMED:
        short = SHORT[path]
        others = tuple(u for u in CONSUMED if u != path)
        n += 1
        out.append(vector(
            n, f"{short}-no-resolver",
            f"The record cites {path}; the harness supplies no resolver. Every consumed "
            "surface reports not_attempted with cause no_resolver, whether or not the "
            "record carries it.",
            record=record_citing(path), resolutions=None,
        ))
        n += 1
        out.append(vector(
            n, f"{short}-uri-not-in-resolver",
            f"The record cites {path}; the resolver holds only the transparency URI, "
            "which is never asked for. The resolver raises KeyError on the cited URI and "
            "the surface reports unresolvable with cause resolver_raised and the "
            "exception's class name.",
            record=record_citing(path), resolutions=resolutions_for(TRANSPARENCY),
        ))
        n += 1
        out.append(vector(
            n, f"{short}-resolved",
            f"The record cites {path} and the resolver holds it. The surface reports "
            "resolved with the SHA-256 over exactly the returned bytes and their count.",
            record=record_citing(path), resolutions=resolutions_for(URI[path]),
        ))
        n += 1
        out.append(vector(
            n, f"{short}-field-absent",
            "The record carries none of the three consumed fields; the resolver holds "
            f"the URI for {path} and is never asked. The surface reports not_attempted "
            "with cause field_absent, which is not unresolvable: nothing was cited.",
            record=record_citing(), resolutions=resolutions_for(URI[path]),
        ))
        n += 1
        out.append(vector(
            n, f"{short}-unresolved-record-still-verifies",
            f"The record cites {path}; the resolver holds the other two URIs and lacks "
            "this one. The surface reports unresolvable and verify_record returns a "
            "result rather than raising: inability to resolve is not evidence of a "
            "defect in the record.",
            record=record_citing(path),
            resolutions=resolutions_for(*(URI[u] for u in others)),
        ))
    n += 1
    out.append(vector(
        n, "all-three-resolved",
        "The record cites all three consumed surfaces and the resolver holds all three. "
        "Each reports resolved with its own digest; transparency is still deferred.",
        record=record_citing(*CONSUMED),
        resolutions=resolutions_for(*(URI[u] for u in CONSUMED)),
    ))

    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in sorted(out):
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / name).write_bytes(text.encode("utf-8"))
        print("wrote", name)


if __name__ == "__main__":
    main()
