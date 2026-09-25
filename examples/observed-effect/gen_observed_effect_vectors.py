"""Generate examples/observed-effect: five signed Trust Records, each citing an
`observed-effect` reference, against an effect store and an altered copy of it.

The two statements in `source/` are copied byte for byte from the published
observed-effect conformance corpus, so the referenced objects here are ones a second
implementation already resolves and verifies. Everything this script adds (the Trust
Record producer key, the second observer key, the store and the altered store) derives
from one published seed, so the set regenerates byte for byte and
tests/test_observed_effect_fixtures.py holds the committed files to this script.
Nothing here is a production record.

Usage: python examples/observed-effect/gen_observed_effect_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agentrust_trace import key_to_jwk, sign_record

SEED = b"trace-spec examples/observed-effect 2026-09-23"
HERE = Path(__file__).resolve().parent

PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
RESOLVER = "https://observer.example.org/intervals"
IAT = int(datetime(2026, 9, 19, 0, 0, 10, tzinfo=UTC).timestamp())

# The corpus observer key, as its manifest publishes it. The corpus derives it from a
# published seed too, so anyone can rebuild the two source statements.
CORPUS_OBSERVER_PUBLIC = bytes.fromhex(
    "4f2a59edc8367deb40047ce83ee7f5ce711a57d93abbda9d1ce8588c56a3ce88"
)
# An authoritative interval in which the observer and the observed party agree.
AGREE = "v1c6fdd82db5229e4"
# The same shape of interval in which they disagree on two facts, which the predicate
# records rather than rejects.
DISAGREE = "v620e7755ba36aa0a"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jcs_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SEED + b"|" + label.encode()).digest()
    )


def raw_public(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def keyid(raw: bytes) -> str:
    """The corpus rule: the first 32 hex characters of SHA-256 over the raw public key."""
    return hashlib.sha256(raw).hexdigest()[:32]


def okp_jwk(raw: bytes) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)


def source(member: str) -> dict[str, Any]:
    raw = (HERE / "source" / f"{member}.json").read_bytes()
    # A corpus member's identifier is the first 16 hex characters of SHA-256 over its
    # file, so a copy that drifted from the corpus fails here rather than downstream.
    assert "v" + hashlib.sha256(raw).hexdigest()[:16] == member, member
    return json.loads(raw)


def resign(envelope: dict[str, Any], signer: Ed25519PrivateKey) -> dict[str, Any]:
    """The same payload bytes under a different observer's signature."""
    payload = base64.b64decode(envelope["payload"])
    sig = signer.sign(pae(envelope["payloadType"], payload))
    return {
        "payload": envelope["payload"],
        "payloadType": envelope["payloadType"],
        "signatures": [{"keyid": keyid(raw_public(signer)), "sig": base64.b64encode(sig).decode()}],
    }


def erase_disagreement(envelope: dict[str, Any]) -> dict[str, Any]:
    """The stored copy as a relying party later finds it: every disagreeing row
    rewritten to agree with the observed party's report, signature left as issued."""
    altered = copy.deepcopy(envelope)
    statement = json.loads(base64.b64decode(altered["payload"]))
    for row in statement["predicate"]["dualValues"]:
        row["observedValue"] = row["reportedValue"]
        row["agreement"] = "agree"
    altered["payload"] = base64.b64encode(rfc8785.dumps(statement)).decode()
    return altered


def record(producer: Ed25519PrivateKey, reference: dict[str, Any]) -> dict[str, Any]:
    unsigned = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": IAT,
        "subject": "spiffe://trust.example.org/agent/build-bot",
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(producer)},
        "references": [reference],
    }
    return sign_record(unsigned, producer)


def reference(id_: str, digest: str) -> dict[str, Any]:
    return {
        "rel": "observed-effect", "id": id_, "resolver": RESOLVER,
        "digest": digest, "retention": "P1Y",
    }


def case(store: str, resolves: bool, matches: bool | None, held: bool | None,
         verifies: bool | None, agreement: str | None, verdict: str) -> dict[str, Any]:
    return {
        "store": store, "trace_record_verifies": True, "reference_resolves": resolves,
        "digest_matches": matches, "observer_key_configured": held,
        "envelope_verifies": verifies, "dual_values": agreement, "verdict": verdict,
    }


def build() -> dict[str, Any]:
    producer, other_observer = key("producer"), key("other-observer")
    agree, disagree = source(AGREE), source(DISAGREE)

    store = {
        "resolver": RESOLVER,
        "effects": {
            "interval/1": agree,
            "interval/2": disagree,
            "interval/3": resign(agree, other_observer),
        },
    }
    altered = copy.deepcopy(store)
    altered["effects"]["interval/2"] = erase_disagreement(disagree)

    cite = lambda id_: reference(id_, jcs_sha256(store["effects"][id_]))  # noqa: E731
    unresolvable = "sha256:" + hashlib.sha256(SEED + b"|digest|interval/9").hexdigest()
    records = {
        "01-observation-verified.json": record(producer, cite("interval/1")),
        "02-observation-altered-after-issue.json": record(producer, cite("interval/2")),
        "03-observer-and-observed-disagree.json": record(producer, cite("interval/2")),
        "04-reference-unresolvable.json": record(producer, reference("interval/9", unresolvable)),
        "05-observer-key-not-configured.json": record(producer, cite("interval/3")),
    }

    expected = {
        "trace_signer_jwk": key_to_jwk(producer),
        "resolver": RESOLVER,
        "predicate_type": PREDICATE_TYPE,
        # The keys this relying party holds, by DSSE keyid. The second observer's key is
        # deliberately absent: spec section 3.3.2 says a receipt whose issuer key is
        # unknown to the verifier is unverified, not invalid.
        "observer_keys": {keyid(CORPUS_OBSERVER_PUBLIC): okp_jwk(CORPUS_OBSERVER_PUBLIC)},
        "cases": {
            "01-observation-verified.json": case(
                "effect-store.json", True, True, True, True, "agree", "observation-verified"),
            "02-observation-altered-after-issue.json": case(
                "effect-store-altered.json", True, False, True, False, "agree",
                "observation-digest-mismatch"),
            "03-observer-and-observed-disagree.json": case(
                "effect-store.json", True, True, True, True, "disagree", "observation-verified"),
            "04-reference-unresolvable.json": case(
                "effect-store.json", False, None, None, None, None, "observation-unresolved"),
            "05-observer-key-not-configured.json": case(
                "effect-store.json", True, True, False, None, "agree", "observation-unverified"),
        },
    }

    return {
        **records,
        "effect-store.json": store,
        "effect-store-altered.json": altered,
        "expected.json": expected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, value in files.items():
        text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
        (out / name).write_bytes(text.encode("utf-8"))
    print(f"{len(files)} files written to {out}")


if __name__ == "__main__":
    main()
