"""OpenProof approvals as TRACE `approval-outcome` references.

Re-verifies examples/openproof-approval-outcome/ without importing OpenProof. The
OpenProof objects were made by the `openproof-witness` binary, and the rest by the
generator in antagoninc/openproof, integrations/trace/generate_examples.py, which also
wrote expected.json. A generator's own summary of its output is a claim, so every
outcome here is recomputed from the committed bytes with this repository's
dependencies and compared with expected.json, never read from it.

OpenProof signs its objects with Ed25519 over domain-separated OPEC-1 bytes, not over
RFC 8785. The encoder below is the one in OpenProof's Python reference,
reference/python/openproof_ref.py: a one-byte type tag, 64-bit big-endian lengths, and
object keys sorted by their UTF-8 bytes. The TRACE `digest` is separate from that: it
is the RFC 8785 SHA-256 of the stored request, as for every registered relation.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentrust_trace import verify_record

OP_DIR = Path(__file__).resolve().parents[1] / "examples" / "openproof-approval-outcome"
EXPECTED = json.loads((OP_DIR / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
ROOT_KEY = EXPECTED["openproof_root_public_key"]
ID_PREFIX = "openproof/approval/"
OUTCOME_KEYS = (
    "reference_resolves",
    "digest_matches",
    "approval_attributable",
    "executed_as_approved",
    "witnessed",
    "verdict",
)


def _load(name: str) -> dict:
    return json.loads((OP_DIR / name).read_text(encoding="utf-8"))


def _jcs_sha256(obj: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _opec(value: object) -> bytes:
    """OpenProof OPEC-1 canonical bytes."""

    def frame(n: int) -> bytes:
        return n.to_bytes(8, "big")

    def enc(v: object) -> bytes:
        if v is None:
            return b"\x00"
        if v is False:
            return b"\x01"
        if v is True:
            return b"\x02"
        if type(v) is int:
            if not 0 <= v < 2**64:
                raise ValueError("OPEC-1 integers are unsigned 64-bit")
            return b"\x03" + frame(v)
        if type(v) is str:
            raw = v.encode("utf-8")
            return b"\x04" + frame(len(raw)) + raw
        if type(v) is list:
            return b"\x05" + frame(len(v)) + b"".join(enc(x) for x in v)
        if type(v) is dict:
            keys = sorted(v, key=lambda k: k.encode("utf-8"))
            return b"\x06" + frame(len(v)) + b"".join(enc(k) + enc(v[k]) for k in keys)
        raise ValueError(f"OPEC-1 has no encoding for {type(v).__name__}")

    return b"OPEC\x01" + enc(value)


def _preimage(domain: str, payload: object) -> bytes:
    return b"OpenProof/v1/" + domain.encode("utf-8") + b"\x00" + _opec(payload)


def _signed_by(signed: dict, domain: str, key_hex: str) -> bool:
    """An OpenProof Signed<T>: Ed25519 over the domain-separated OPEC-1 bytes."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            bytes.fromhex(signed["signature"]), _preimage(domain, signed["payload"])
        )
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def _approval_digest(request: dict) -> str:
    preimage = _preimage("document-approval/1", request["approval"]["payload"])
    return hashlib.sha256(preimage).hexdigest()


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _passkey_signed(request: dict, passkey: dict, digest_hex: str) -> bool:
    """A WebAuthn ES256 assertion whose challenge is the approval digest, made with user
    verification for the relying party and origin the owner's trust names."""
    try:
        assertion = request["owner_assertion"]
        auth = _unb64u(assertion["authenticator_data"])
        client = _unb64u(assertion["client_data_json"])
        data = json.loads(client)
        challenge = base64.urlsafe_b64encode(bytes.fromhex(digest_hex)).rstrip(b"=").decode()
        if (
            data.get("type") != "webauthn.get"
            or data.get("challenge") != challenge
            or data.get("origin") != passkey["origin"]
            or data.get("crossOrigin", False) is not False
            or len(auth) < 37
            or auth[:32] != hashlib.sha256(passkey["rp_id"].encode("utf-8")).digest()
            or auth[32] & 0x05 != 0x05
        ):
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(passkey["public_key"])
        )
        key.verify(
            _unb64u(assertion["signature"]),
            auth + hashlib.sha256(client).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def _assess(record: dict, store: dict, root_key: str = ROOT_KEY) -> dict:
    """What a relying party concludes about the approval a record points at.

    The steps are those of docs/crosswalks/openproof-approvals.md, in order, and each
    later finding is None when an earlier one already decided the verdict.
    """
    out: dict = {
        "reference_resolves": False,
        "digest_matches": None,
        "approval_attributable": None,
        "executed_as_approved": None,
        "witnessed": None,
    }

    def done(verdict: str) -> dict:
        return {**out, "verdict": verdict}

    (reference,) = record["references"]
    assert reference["rel"] == "approval-outcome"
    assert reference["resolver"] == EXPECTED["resolver"]
    entry = store["entries"].get(reference["id"])
    if entry is None:
        return done("approval-unconfirmed")
    out["reference_resolves"] = True
    request = entry["request"]
    out["digest_matches"] = _jcs_sha256(request) == reference["digest"]
    if not out["digest_matches"]:
        return done("approval-contradicted")
    if not _signed_by(store["signed_trust"], "witness-trust/1", root_key):
        out["approval_attributable"] = False
        return done("trust-unverified")
    trust = store["signed_trust"]["payload"]
    digest_hex = _approval_digest(request)
    approval = request["approval"]["payload"]
    attributable = (
        reference["id"] == ID_PREFIX + digest_hex
        and approval["authority"] not in trust["revoked_authorities"]
        and approval["authority"] in [trust["authority"], *trust["previous_authorities"]]
        and _signed_by(request["approval"], "document-approval/1", approval["authority"])
        and approval["content_sha256"]
        == hashlib.sha256(request["content"].encode("utf-8")).hexdigest()
        and approval["receiver"] == trust["receiver"]
    )
    if attributable and trust.get("owner_passkey") is not None:
        attributable = _passkey_signed(request, trust["owner_passkey"], digest_hex)
    out["approval_attributable"] = attributable
    if not attributable:
        return done("approval-not-attributable")
    receipt = entry.get("receipt")
    if receipt is None:
        out["executed_as_approved"] = False
        return done("approved-not-executed")
    r = receipt["payload"]
    out["executed_as_approved"] = (
        _signed_by(receipt, "receiver-receipt/1", trust["receiver"])
        and r["kind"] == "update"
        and r["approval_sha256"] == digest_hex
        and r["content_sha256"] == approval["content_sha256"]
        and r["document"] == approval["document"]
        and r["document_version"] == approval["expected_version"] + 1
    )
    if not out["executed_as_approved"]:
        return done("execution-contradicted")
    checkpoint = entry.get("checkpoint")
    out["witnessed"] = bool(
        checkpoint
        and _signed_by(checkpoint, "witness-checkpoint/1", trust["witness"])
        and checkpoint["payload"]["receiver"] == trust["receiver"]
        and checkpoint["payload"]["count"] >= r["sequence"]
    )
    return done("approval-confirmed-and-executed" if out["witnessed"] else "executed-unwitnessed")


def _rereferenced(record: dict, store: dict) -> dict:
    """An unsigned copy of a record whose digest follows a deliberately changed store.

    `_assess` never reads the record signature, so this isolates a later step from the
    digest check that would otherwise stop at step 3.
    """
    record = copy.deepcopy(record)
    request = store["entries"][record["references"][0]["id"]]["request"]
    record["references"][0]["digest"] = _jcs_sha256(request)
    return record


def test_the_committed_records_are_exactly_the_declared_cases() -> None:
    committed = {p.name for p in OP_DIR.glob("0*.json")}
    assert committed == set(CASES)
    for case in EXPECTED["cases"].values():
        assert (OP_DIR / case["store"]).is_file()


@pytest.mark.parametrize("name", CASES)
def test_every_case_verifies_as_a_trust_record(name: str) -> None:
    # Section 3.1.2 rule 3: what a reference resolves to never decides whether the
    # record verifies, so the unresolvable and contradicted cases verify too.
    verify_record(_load(name), EXPECTED["trace_signer_jwk"], max_age_seconds=None)
    assert EXPECTED["cases"][name]["trace_record_verifies"] is True


@pytest.mark.parametrize("name", CASES)
def test_the_outcome_is_recomputed_from_the_committed_bytes(name: str) -> None:
    case = EXPECTED["cases"][name]
    assert _assess(_load(name), _load(case["store"])) == {k: case[k] for k in OUTCOME_KEYS}


def test_the_record_signature_covers_the_reference() -> None:
    record = copy.deepcopy(_load("01-approval-executed.json"))
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    # verify_record documents InvalidSignature for a signature that does not verify.
    with pytest.raises(InvalidSignature):
        verify_record(record, EXPECTED["trace_signer_jwk"], max_age_seconds=None)


def test_each_resolvable_id_is_derived_from_the_approval_it_names() -> None:
    """The id is the SHA-256 of the approval's OPEC-1 signing bytes, so an entry
    cannot be filed under the id of a different approval."""
    store = _load("openproof-approvals.json")
    for entry_id, entry in store["entries"].items():
        assert entry_id == ID_PREFIX + _approval_digest(entry["request"])


def _differences(a: object, b: object, path: tuple = ()) -> list[tuple]:
    """Every path at which two JSON values differ, keys present on either side included."""
    if isinstance(a, dict) and isinstance(b, dict):
        return [
            d
            for key in sorted(a.keys() | b.keys())
            for d in _differences(a.get(key, KeyError), b.get(key, KeyError), (*path, key))
        ]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        pairs = enumerate(zip(a, b, strict=True))
        return [d for i, (x, y) in pairs for d in _differences(x, y, (*path, i))]
    return [] if a == b else [path]


def test_the_altered_store_differs_from_the_original_in_the_cited_content_only() -> None:
    original = _load("openproof-approvals.json")
    altered = _load("openproof-approvals-altered.json")
    cited = _load("02-approval-altered-after-issue.json")["references"][0]["id"]
    assert cited == _load("01-approval-executed.json")["references"][0]["id"]
    assert _differences(original, altered) == [("entries", cited, "request", "content")]


def test_every_number_in_the_referenced_requests_is_a_safe_integer() -> None:
    """RFC 8785 implementations disagree mostly on numbers. Every number a reference
    digest here covers is a non-negative integer below 2**53."""

    def numbers(v: object):
        if isinstance(v, bool):
            return
        if isinstance(v, (int, float)):
            yield v
        elif isinstance(v, dict):
            for x in v.values():
                yield from numbers(x)
        elif isinstance(v, list):
            for x in v:
                yield from numbers(x)

    for name in ("openproof-approvals.json", "openproof-approvals-altered.json"):
        for entry in _load(name)["entries"].values():
            found = list(numbers(entry["request"]))
            assert found
            assert all(type(n) is int and 0 <= n < 2**53 for n in found)


def test_each_later_step_changes_the_verdict() -> None:
    """Steps 4 to 6 each turn the confirmed case into a different verdict. Steps 2, 3 and
    4 already have committed cases, 04, 02 and 05; case 05 fails on its authority.

    The receipt is changed after it was signed, so step 5 fails on its signature as well
    as on the version; nothing here holds the receiver key to sign a wrong receipt.
    """
    record = _load("01-approval-executed.json")
    store = _load("openproof-approvals.json")
    entry_id = record["references"][0]["id"]
    assert _assess(record, store)["verdict"] == "approval-confirmed-and-executed"

    # Step 4, trust: a root the relying party holds that did not sign this trust.
    assert _assess(record, store, root_key="00" * 32)["verdict"] == "trust-unverified"

    # Step 4, passkey: one bit of the assertion signature changed, and the record's
    # digest made to follow it so that step 3 passes.
    changed = copy.deepcopy(store)
    assertion = changed["entries"][entry_id]["request"]["owner_assertion"]
    raw = bytearray(_unb64u(assertion["signature"]))
    raw[-1] ^= 0x01
    assertion["signature"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    verdict = _assess(_rereferenced(record, changed), changed)["verdict"]
    assert verdict == "approval-not-attributable"

    # Step 4, passkey challenge: the owner's valid assertion for the other approval of the
    # same document, replayed onto this one.
    changed = copy.deepcopy(store)
    other = _load("03-approved-not-executed.json")["references"][0]["id"]
    changed["entries"][entry_id]["request"]["owner_assertion"] = copy.deepcopy(
        store["entries"][other]["request"]["owner_assertion"]
    )
    verdict = _assess(_rereferenced(record, changed), changed)["verdict"]
    assert verdict == "approval-not-attributable"

    # Step 4, content: the approval and its signature untouched, the content changed.
    changed = copy.deepcopy(store)
    changed["entries"][entry_id]["request"]["content"] += " "
    verdict = _assess(_rereferenced(record, changed), changed)["verdict"]
    assert verdict == "approval-not-attributable"

    # Step 4, id: the same request filed under the id of a different approval.
    changed = copy.deepcopy(store)
    moved = copy.deepcopy(record)
    changed["entries"][other] = changed["entries"][entry_id]
    moved["references"][0]["id"] = other
    verdict = _assess(_rereferenced(moved, changed), changed)["verdict"]
    assert verdict == "approval-not-attributable"

    # Step 5: the receipt names a version other than the next one.
    changed = copy.deepcopy(store)
    changed["entries"][entry_id]["receipt"]["payload"]["document_version"] += 1
    assert _assess(record, changed)["verdict"] == "execution-contradicted"

    # Step 6: no checkpoint.
    changed = copy.deepcopy(store)
    changed["entries"][entry_id]["checkpoint"] = None
    assert _assess(record, changed)["verdict"] == "executed-unwitnessed"
