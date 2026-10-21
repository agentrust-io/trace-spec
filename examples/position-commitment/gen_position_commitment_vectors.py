"""Generate examples/position-commitment: five signed v0.3 draft Trust Records, each
carrying one `position-commitment` entry with `validation: "recompute"`, the proofs a
holder presents for them, and the trust a relying party supplies for itself.

Every key derives from one published seed, so the set regenerates byte for byte and
tests/test_position_commitment_fixtures.py holds the committed files to this script.
The sequence, the committing enclave and the records are illustrative, and every
digest and signature in the set recomputes from what is committed. Nothing here is a
production record.

Two inputs are kept apart on purpose. A proof is what the holder presents, and it may
carry a key for the party that signed it. `relying-party.json` is what the relying
party supplies itself: the committer keys it trusts and its own copy of the ordered
sequence. Only the second can make the position independently established; a proof
that verifies under the key it carries is consistent with itself and nothing more.

Usage: python examples/position-commitment/gen_position_commitment_vectors.py [--out DIR]
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

from agentrust_trace import key_to_jwk, sign_record

SEED = b"trace-spec examples/position-commitment 2026-10-20"
HERE = Path(__file__).resolve().parent

PROFILE = "tag:agentrust-io.com,2026:trace-v0.3"
SEQUENCE = "https://beacon.example.org/sequence/1"
COMMITTER = "https://slots.enclave.example"
OTHER_COMMITTER = "https://slots.unknown.example"
IAT = int(datetime(2026, 10, 20, 9, 5, tzinfo=UTC).timestamp())


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jcs_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SEED + b"|" + label.encode()).digest()
    )


def thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638: SHA-256 over the required members, lexically ordered, no whitespace."""
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    encoded = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(encoded).digest())


def sequence_value(position: int) -> str:
    """The value the external sequence published at a position, derived from the seed.
    A slot carries it, so the slot cannot have been taken before that position."""
    return "sha256:" + hashlib.sha256(SEED + b"|sequence|" + str(position).encode()).hexdigest()


def signed(body: dict[str, Any], signer: Ed25519PrivateKey) -> dict[str, Any]:
    """Ed25519 over the RFC 8785 canonical form of the object without `signature`."""
    return {**body, "signature": b64u(signer.sign(rfc8785.dumps(body)))}


def slot(position: int, committer: str, signer: Ed25519PrivateKey, at: str) -> dict[str, Any]:
    """Allocated before any record exists. The entry's `id` is the digest of this object."""
    return signed(
        {
            "type": "position-slot",
            "sequence": SEQUENCE,
            "position": position,
            "sequence_value": sequence_value(position),
            "committer": committer,
            "committer_key_id": thumbprint(key_to_jwk(signer)),
            "allocated_at": at,
        },
        signer,
    )


def record(producer: Ed25519PrivateKey, subject: str, commitment: str) -> dict[str, Any]:
    unsigned = {
        "eat_profile": PROFILE,
        "iat": IAT,
        "subject": subject,
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "confidential",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(producer)},
        "references": [
            {"rel": "position-commitment", "id": commitment, "validation": "recompute"}
        ],
    }
    return sign_record(unsigned, producer)


def record_digest(rec: dict[str, Any]) -> str:
    """Spec section 3.1.3: RFC 8785 canonical form of the complete record as published,
    `signature` member included."""
    return jcs_sha256(rec)


def proof(
    slot_obj: dict[str, Any], rec: dict[str, Any], signer: Ed25519PrivateKey, at: str
) -> dict[str, Any]:
    """What the holder carries: the slot, and the committer's binding of the slot to the
    record digest, taken once the record exists. `committer_jwk` is the key the proof
    supplies for itself; a relying party that trusts it has trusted the proof."""
    binding = signed(
        {
            "type": "position-binding",
            "slot_commitment": jcs_sha256(slot_obj),
            "record_digest": record_digest(rec),
            "committer_key_id": slot_obj["committer_key_id"],
            "bound_at": at,
        },
        signer,
    )
    return {
        "type": "position-commitment-proof",
        "slot": slot_obj,
        "binding": binding,
        "committer_jwk": key_to_jwk(signer),
    }


def build() -> dict[str, Any]:
    producer = key("producer")
    committer, other_committer = key("committer"), key("other-committer")
    subject = "spiffe://trust.example.org/agent/settlement"
    other_subject = "spiffe://trust.example.org/agent/settlement-replay"

    slot1 = slot(8812, COMMITTER, committer, "2026-10-20T09:00:00Z")
    rec1 = record(producer, subject, jcs_sha256(slot1))
    proof1 = proof(slot1, rec1, committer, "2026-10-20T09:05:01Z")

    # Another record carrying exactly the same entry. The proof is public once
    # presented, so nothing stops a second record from carrying it.
    rec2 = record(producer, other_subject, jcs_sha256(slot1))

    # A real commitment whose proof the verifier is never handed.
    slot3 = slot(8813, COMMITTER, committer, "2026-10-20T09:00:10Z")
    rec3 = record(producer, subject + "/3", jcs_sha256(slot3))

    slot4 = slot(8814, COMMITTER, committer, "2026-10-20T09:00:20Z")
    rec4 = record(producer, subject + "/4", jcs_sha256(slot4))
    proof4 = proof(slot4, rec4, committer, "2026-10-20T09:05:02Z")
    # The proof as later presented, its position rewritten to an earlier one: the
    # backdate the relation exists to expose. The slot no longer recomputes to the
    # entry's `id`, and the committer's signature no longer covers the slot.
    proof4_altered = copy.deepcopy(proof4)
    proof4_altered["slot"]["position"] = 8700

    # Signed by a committer the relying party does not hold a key for. The proof
    # carries that key, so every digest and signature checks out under it.
    slot5 = slot(8815, OTHER_COMMITTER, other_committer, "2026-10-20T09:00:30Z")
    rec5 = record(producer, subject + "/5", jcs_sha256(slot5))
    proof5 = proof(slot5, rec5, other_committer, "2026-10-20T09:05:03Z")

    committer_jwk = key_to_jwk(committer)
    relying_party = {
        "note": (
            "Supplied by the relying party, never read from a proof: the committer keys "
            "it trusts and its own copy of the ordered sequence."
        ),
        "committer_keys": {thumbprint(committer_jwk): committer_jwk},
        "sequence": {
            "id": SEQUENCE,
            "positions": {str(p): sequence_value(p) for p in (8700, 8812, 8813, 8814, 8815)},
        },
    }

    absent = {
        "proof_held": False,
        "commitment_recomputes": None,
        "binds_this_record": None,
        "committer_key_independent": None,
        "signatures_verify": None,
        "sequence_position_matches": None,
    }
    expected = {
        "trace_signer_jwk": key_to_jwk(producer),
        "cases": {
            "01-position-established.json": {
                "proof": "proof-01.json",
                "record_signature_verifies": True,
                "proof_held": True,
                "commitment_recomputes": True,
                "binds_this_record": True,
                "committer_key_independent": True,
                "signatures_verify": True,
                "sequence_position_matches": True,
                "verdict": "position-established",
            },
            "02-same-proof-other-record.json": {
                "proof": "proof-01.json",
                "record_signature_verifies": True,
                "proof_held": True,
                "commitment_recomputes": True,
                "binds_this_record": False,
                "committer_key_independent": None,
                "signatures_verify": None,
                "sequence_position_matches": None,
                "verdict": "contradiction-commits-another-record",
            },
            "03-proof-not-held.json": {
                "proof": None,
                "record_signature_verifies": True,
                **absent,
                "verdict": "position-absent",
            },
            "04-proof-altered.json": {
                "proof": "proof-04-altered.json",
                "record_signature_verifies": True,
                "proof_held": True,
                "commitment_recomputes": False,
                "binds_this_record": None,
                "committer_key_independent": None,
                "signatures_verify": None,
                "sequence_position_matches": None,
                "verdict": "contradiction-commitment-mismatch",
            },
            "05-committer-key-self-supplied.json": {
                "proof": "proof-05.json",
                "record_signature_verifies": True,
                "proof_held": True,
                "commitment_recomputes": True,
                "binds_this_record": True,
                "committer_key_independent": False,
                "signatures_verify": True,
                "sequence_position_matches": True,
                "verdict": "position-consistent-not-established",
            },
        },
    }

    return {
        "01-position-established.json": rec1,
        "02-same-proof-other-record.json": rec2,
        "03-proof-not-held.json": rec3,
        "04-proof-altered.json": rec4,
        "05-committer-key-self-supplied.json": rec5,
        "proof-01.json": proof1,
        "proof-04.json": proof4,
        "proof-04-altered.json": proof4_altered,
        "proof-05.json": proof5,
        "relying-party.json": relying_party,
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
