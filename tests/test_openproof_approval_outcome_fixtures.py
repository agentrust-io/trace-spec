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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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


# Every comparison `_assess` makes, by name. A test below turns each one off in turn
# and shows that a defect then passes, so the list cannot hold a check that nothing
# exercises, and `_assess` refuses a name that is not in it.
CHECKS = (
    "reference-digest",
    "trust-signature",
    "id-is-approval-digest",
    "authority-not-revoked",
    "authority-named",
    "approval-signature",
    "content-hash",
    "approval-receiver",
    "assertion-required",
    "assertion-unexpected",
    "assertion-fields",
    "assertion-encoding",
    "assertion-size",
    "client-data-duplicate-key",
    "client-data-depth",
    "client-data-type",
    "client-data-challenge",
    "client-data-origin",
    "client-data-cross-origin",
    "authenticator-data-length",
    "authenticator-data-rp-id",
    "authenticator-data-user-present",
    "authenticator-data-user-verified",
    "assertion-signature",
    "receipt-signature",
    "receipt-kind",
    "receipt-approval",
    "receipt-content",
    "receipt-document",
    "receipt-version",
    "checkpoint-signature",
    "checkpoint-receiver",
    "checkpoint-count",
    "checkpoint-head",
)

# Limits of crates/openproof-witness/src/passkey.rs at the pinned commit.
MAX_AUTHENTICATOR_DATA = 1024
MAX_CLIENT_DATA_JSON = 2048
MAX_ASSERTION_SIGNATURE = 80
# OpenProof's JSON parser has a nesting limit of 128. Python's has none that matters
# here, and a browser's client data has two levels. This limit is far below
# OpenProof's, so that depth never lets through what OpenProof refuses. It is stricter
# than OpenProof from 9 levels up to that limit.
MAX_CLIENT_DATA_DEPTH = 8
ASSERTION_FIELDS = ("authenticator_data", "client_data_json", "signature")


def _checker(skip: frozenset[str]):
    """`ok(name, passed)` for one named comparison. A name in `skip` counts as passed."""
    unknown = skip - set(CHECKS)
    assert not unknown, unknown

    def ok(name: str, passed: object) -> bool:
        assert name in CHECKS, name
        return name in skip or bool(passed)

    return ok


def _is_int(value: object) -> bool:
    return type(value) is int


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64u(text: str) -> bytes:
    """A lenient decode. `_strict_b64u` then says whether OpenProof would accept it."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _strict_b64u(text: object, raw: bytes) -> bool:
    """Base64url as OpenProof decodes it: the URL-safe alphabet, no padding, and no
    unused bit set in the last character. The lenient decode drops or accepts all of
    those, so a spelling that is not the one canonical spelling of `raw` is refused."""
    return type(text) is str and _b64u(raw) == text


def _depth(value: object) -> int:
    deepest, pending = 0, [(value, 1)]
    while pending:
        item, level = pending.pop()
        if type(item) in (dict, list):
            deepest = max(deepest, level)
            inner = item.values() if type(item) is dict else item
            pending.extend((x, level + 1) for x in inner)
    return deepest


def _client_data(raw: bytes) -> tuple[dict, bool] | None:
    """The client data as one JSON object, and whether a top-level key repeats.

    None when it is not UTF-8 JSON holding one object, or when a string holds half of a
    surrogate pair, which Python's parser accepts and OpenProof's does not. A nesting
    so deep that Python's parser gives up is refused too. `json.loads` keeps the last of
    two equal keys, so the repeat is recorded during the parse: the hook runs for an
    inner object before the one that holds it, and the top-level object last.
    """
    top = {"repeats": False}

    def pairs(items: list[tuple[str, object]]) -> dict:
        keys = [key for key, _ in items]
        top["repeats"] = len(set(keys)) != len(keys)
        return dict(items)

    def constant(name: str) -> None:
        raise ValueError(f"{name} is not JSON")

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if type(data) is not dict:
            return None
        # A lone surrogate cannot be written as UTF-8.
        json.dumps(data, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):
        return None
    return data, top["repeats"]


def _passkey_signed(request: dict, passkey: dict, digest_hex: str, ok) -> bool:
    """A WebAuthn ES256 assertion whose challenge is the approval digest, made with user
    presence and user verification for the relying party and origin the owner's trust
    names. The checks are those of `verify_assertion` in OpenProof's passkey.rs."""
    try:
        assertion = request["owner_assertion"]
        if not ok(
            "assertion-fields",
            type(assertion) is dict and set(assertion) == set(ASSERTION_FIELDS),
        ):
            return False
        auth, client, der = (_unb64u(assertion[field]) for field in ASSERTION_FIELDS)
        decoded = zip(ASSERTION_FIELDS, (auth, client, der), strict=True)
        if not ok(
            "assertion-encoding",
            all(_strict_b64u(assertion[field], raw) for field, raw in decoded),
        ):
            return False
        if not ok(
            "assertion-size",
            0 < len(auth) <= MAX_AUTHENTICATOR_DATA
            and 0 < len(client) <= MAX_CLIENT_DATA_JSON
            and 0 < len(der) <= MAX_ASSERTION_SIGNATURE,
        ):
            return False
        parsed = _client_data(client)
        if parsed is None:
            return False
        data, repeats = parsed
        challenge = _b64u(bytes.fromhex(digest_hex))
        rp_id_hash = hashlib.sha256(passkey["rp_id"].encode("utf-8")).digest()
        flags = auth[32] if len(auth) > 32 else 0
        if not (
            ok("client-data-duplicate-key", not repeats)
            and ok("client-data-depth", _depth(data) <= MAX_CLIENT_DATA_DEPTH)
            and ok("client-data-type", data.get("type") == "webauthn.get")
            and ok("client-data-challenge", data.get("challenge") == challenge)
            and ok("client-data-origin", data.get("origin") == passkey["origin"])
            and ok("client-data-cross-origin", data.get("crossOrigin", False) is False)
            and ok("authenticator-data-length", len(auth) >= 37)
            and ok("authenticator-data-rp-id", auth[:32] == rp_id_hash)
            and ok("authenticator-data-user-present", flags & 0x01)
            and ok("authenticator-data-user-verified", flags & 0x04)
        ):
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(passkey["public_key"])
        )
        try:
            key.verify(der, auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
            verified = True
        except InvalidSignature:
            verified = False
        return ok("assertion-signature", verified)
    except (ValueError, KeyError, TypeError):
        return False


def _owner_passkey_rule(
    request: dict, trust: dict, digest_hex: str, sequence: int | None, ok
) -> bool:
    """OpenProof's history rule, `check_owner_assertion` in passkey.rs.

    When the trust names a passkey and the receipt's sequence number is at or after its
    `from_sequence`, the request must carry a valid assertion. Before `from_sequence`,
    or when the trust names no passkey, the request must carry none.

    `sequence` is None when the entry has no receipt, or has one that the trust's
    receiver did not sign. Nothing then says where the request sits in the history. The
    receiver admits a new request under a passkey only with an assertion, so one is
    required.
    """
    passkey = trust.get("owner_passkey")
    present = request.get("owner_assertion") is not None
    required = passkey is not None and (
        sequence is None
        or (_is_int(passkey.get("from_sequence")) and sequence >= passkey["from_sequence"])
    )
    if not required:
        return ok("assertion-unexpected", not present)
    if not ok("assertion-required", present):
        return False
    return not present or _passkey_signed(request, passkey, digest_hex, ok)


def _assess(
    record: dict, store: dict, root_key: str = ROOT_KEY, skip: frozenset[str] = frozenset()
) -> dict:
    """What a relying party concludes about the approval a record points at.

    The steps are those of docs/crosswalks/openproof-approvals.md, in order, and each
    later finding is None when an earlier one already decided the verdict. `skip` turns
    named checks off, for the tests that show what each check is for.
    """
    ok = _checker(frozenset(skip))
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
    # Step 2.
    entry = store["entries"].get(reference["id"])
    if entry is None:
        return done("approval-unconfirmed")
    out["reference_resolves"] = True
    # Step 3.
    request = entry["request"]
    out["digest_matches"] = ok("reference-digest", _jcs_sha256(request) == reference["digest"])
    if not out["digest_matches"]:
        return done("approval-contradicted")
    # Step 4.
    if not ok("trust-signature", _signed_by(store["signed_trust"], "witness-trust/1", root_key)):
        out["approval_attributable"] = False
        return done("trust-unverified")
    trust = store["signed_trust"]["payload"]
    digest_hex = _approval_digest(request)
    approval = request["approval"]["payload"]
    # The passkey rule needs the receipt's sequence number, and takes it only from a
    # receipt the trust's receiver signed.
    receipt = entry.get("receipt")
    receipt_signed = receipt is not None and ok(
        "receipt-signature", _signed_by(receipt, "receiver-receipt/1", trust["receiver"])
    )
    sequence = receipt["payload"].get("sequence") if receipt_signed else None
    attributable = (
        ok("id-is-approval-digest", reference["id"] == ID_PREFIX + digest_hex)
        and ok("authority-not-revoked", approval["authority"] not in trust["revoked_authorities"])
        and ok(
            "authority-named",
            approval["authority"] in [trust["authority"], *trust["previous_authorities"]],
        )
        and ok(
            "approval-signature",
            _signed_by(request["approval"], "document-approval/1", approval["authority"]),
        )
        and ok(
            "content-hash",
            approval["content_sha256"]
            == hashlib.sha256(request["content"].encode("utf-8")).hexdigest(),
        )
        and ok("approval-receiver", approval["receiver"] == trust["receiver"])
        and _owner_passkey_rule(
            request, trust, digest_hex, sequence if _is_int(sequence) else None, ok
        )
    )
    out["approval_attributable"] = attributable
    if not attributable:
        return done("approval-not-attributable")
    # Step 5.
    if receipt is None:
        out["executed_as_approved"] = False
        return done("approved-not-executed")
    r = receipt["payload"]
    out["executed_as_approved"] = (
        receipt_signed
        and ok("receipt-kind", r["kind"] == "update")
        and ok("receipt-approval", r["approval_sha256"] == digest_hex)
        and ok("receipt-content", r["content_sha256"] == approval["content_sha256"])
        and ok("receipt-document", r["document"] == approval["document"])
        and ok(
            "receipt-version",
            _is_int(r["document_version"])
            and _is_int(approval["expected_version"])
            and r["document_version"] == approval["expected_version"] + 1,
        )
    )
    if not out["executed_as_approved"]:
        return done("execution-contradicted")
    # Step 6, reached only with a receipt. The checkpoint must be the one the witness
    # signed at this receipt: the same count, and a head that is this receipt's digest.
    checkpoint = entry.get("checkpoint")
    c = checkpoint["payload"] if type(checkpoint) is dict else {}
    receipt_digest = hashlib.sha256(_preimage("receiver-receipt/1", r)).hexdigest()
    out["witnessed"] = (
        ok(
            "checkpoint-signature",
            _signed_by(checkpoint, "witness-checkpoint/1", trust["witness"]),
        )
        and ok("checkpoint-receiver", c.get("receiver") == trust["receiver"])
        and ok(
            "checkpoint-count",
            _is_int(c.get("count")) and _is_int(sequence) and c["count"] == sequence,
        )
        and ok("checkpoint-head", c.get("head") == receipt_digest)
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


# A second store, signed at test time by keys generated here, so that each check in
# `_assess` can be seen failing on its own. The committed fixtures hold no private
# keys, so changing a signed field there also breaks its signature, and a check
# behind that signature is never reached. Here every object is signed after the
# change, and only the one check under test fails.
#
# What this shows, and what it does not. These cases run `_assess` in this file. They
# do not run OpenProof's Rust or Go verifier: this file does not import OpenProof, and
# `_assess` was written by the author of the cross-walk. They show that this file's
# checks do what the cross-walk says. That this file agrees with OpenProof rests on
# reading passkey.rs and lib.rs at the pinned commit, and on the five committed cases
# whose OpenProof objects came from the OpenProof binary.


def _ed25519() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    return key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sign(key: Ed25519PrivateKey, domain: str, payload: dict) -> dict:
    return {"payload": payload, "signature": key.sign(_preimage(domain, payload)).hex()}


def _no_change(stage: str, value: object) -> None:
    return None


def _test_store(tweak=_no_change, signers=None):
    """The executed case 01 rebuilt under test keys. `tweak(stage, value)` changes a
    value in place just before it is signed, encoded or stored; `signers` swaps a
    signing key. Returns the unsigned record, the store and the test root's public key.

    Stages, in order: trust, approval, content, client, client_bytes, auth, request,
    receipt, checkpoint, entry, filed, reference. `client_bytes` and `filed` are
    one-item lists, so that a tweak can replace the bytes or the id.
    """
    store = _load("openproof-approvals.json")
    record = _load("01-approval-executed.json")
    entry = store["entries"][record["references"][0]["id"]]
    root, root_pub = _ed25519()
    authority, authority_pub = _ed25519()
    receiver, receiver_pub = _ed25519()
    witness, witness_pub = _ed25519()
    keys = {
        "root": root,
        "authority": authority,
        "receiver": receiver,
        "witness": witness,
        "owner": ec.generate_private_key(ec.SECP256R1()),
    }
    owner_pub = keys["owner"].public_key()
    keys.update(signers or {})

    trust = copy.deepcopy(store["signed_trust"]["payload"])
    trust.update(
        authority=authority_pub,
        previous_authorities=[],
        revoked_authorities=[],
        receiver=receiver_pub,
        witness=witness_pub,
    )
    trust["owner_passkey"]["public_key"] = owner_pub.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ).hex()
    # The assertion below is made for this passkey even when a tweak takes it out of
    # the trust.
    passkey = copy.deepcopy(trust["owner_passkey"])
    tweak("trust", trust)
    signed_trust = _sign(keys["root"], "witness-trust/1", trust)

    approval = copy.deepcopy(entry["request"]["approval"]["payload"])
    approval.update(authority=authority_pub, receiver=receiver_pub)
    tweak("approval", approval)
    request = {
        "approval": _sign(keys["authority"], "document-approval/1", approval),
        "content": entry["request"]["content"],
    }
    tweak("content", request)
    digest = _approval_digest(request)

    client = {
        "type": "webauthn.get",
        "challenge": _b64u(bytes.fromhex(digest)),
        "origin": passkey["origin"],
    }
    tweak("client", client)
    client_bytes = [json.dumps(client, separators=(",", ":")).encode()]
    tweak("client_bytes", client_bytes)
    auth = bytearray(hashlib.sha256(passkey["rp_id"].encode()).digest() + b"\x05" + bytes(4))
    tweak("auth", auth)
    signature = keys["owner"].sign(
        bytes(auth) + hashlib.sha256(client_bytes[0]).digest(), ec.ECDSA(hashes.SHA256())
    )
    request["owner_assertion"] = {
        "authenticator_data": _b64u(bytes(auth)),
        "client_data_json": _b64u(client_bytes[0]),
        "signature": _b64u(signature),
    }
    tweak("request", request)

    receipt = copy.deepcopy(entry["receipt"]["payload"])
    receipt["approval_sha256"] = digest
    tweak("receipt", receipt)
    # The checkpoint the witness signs at this receipt.
    checkpoint = copy.deepcopy(entry["checkpoint"]["payload"])
    checkpoint.update(
        receiver=receiver_pub,
        count=receipt["sequence"],
        head=hashlib.sha256(_preimage("receiver-receipt/1", receipt)).hexdigest(),
    )
    tweak("checkpoint", checkpoint)

    built_entry = {
        "request": request,
        "receipt": _sign(keys["receiver"], "receiver-receipt/1", receipt),
        "checkpoint": _sign(keys["witness"], "witness-checkpoint/1", checkpoint),
    }
    tweak("entry", built_entry)
    filed = [ID_PREFIX + digest]
    tweak("filed", filed)
    built = {
        "resolver": store["resolver"],
        "signed_trust": signed_trust,
        "entries": {filed[0]: built_entry},
    }
    record = copy.deepcopy(record)
    record["references"][0].update(id=filed[0], digest=_jcs_sha256(request))
    tweak("reference", record["references"][0])
    return record, built, root_pub


def _set(**fields):
    return lambda value: value.update(fields)


def _at(stage: str, change):
    return lambda s, value: change(value) if s == stage else None


def _all(*tweaks):
    def tweak(stage: str, value: object) -> None:
        for one in tweaks:
            one(stage, value)

    return tweak


def test_the_store_rebuilt_under_test_keys_is_confirmed() -> None:
    """The baseline for the cases below: without a change, every check passes."""
    record, store, root = _test_store()
    assert _assess(record, store, root)["verdict"] == "approval-confirmed-and-executed"


# A valid Ed25519 public key that plays no role in the rebuilt store.
OTHER_KEY = _ed25519()[1]


def _revoke_authority(trust: dict) -> None:
    # The approval's signer becomes an earlier authority that the trust has revoked.
    # OpenProof refuses a trust that lists its current authority as revoked.
    earlier = trust["authority"]
    trust.update(authority=OTHER_KEY, previous_authorities=[earlier], revoked_authorities=[earlier])


def _nested(levels: int) -> list:
    value: list = []
    for _ in range(levels - 1):
        value = [value]
    return value


def _flags(value: int):
    return lambda auth: auth.__setitem__(32, value)


def _repeat_origin(client_bytes: list) -> None:
    # Two `origin` members. The last one is the trusted origin, so a parser that keeps
    # the last value reads a client data that looks right.
    client = json.loads(client_bytes[0])
    members = [
        '"type":"webauthn.get"',
        '"challenge":"' + client["challenge"] + '"',
        '"origin":"http://localhost:1"',
        '"origin":"' + client["origin"] + '"',
    ]
    client_bytes[0] = ("{" + ",".join(members) + "}").encode()


def _pad_authenticator_data(request: dict) -> None:
    # 37 bytes encode to 50 characters, which standard Base64 pads with two more.
    text = request["owner_assertion"]["authenticator_data"]
    assert len(text) % 4 == 2
    request["owner_assertion"]["authenticator_data"] = text + "=="


def _set_unused_bits(request: dict) -> None:
    # 37 bytes of authenticator data leave four unused bits in the last character.
    # Setting one gives a second spelling of the same bytes.
    text = request["owner_assertion"]["authenticator_data"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert len(text) % 4 == 2
    respelled = text[:-1] + alphabet[alphabet.index(text[-1]) | 0x01]
    assert respelled != text and _unb64u(respelled) == _unb64u(text)
    request["owner_assertion"]["authenticator_data"] = respelled


def _remove_assertion(request: dict) -> None:
    del request["owner_assertion"]


def _remove_passkey(trust: dict) -> None:
    del trust["owner_passkey"]


def _from_sequence(value: int):
    return _at("trust", lambda trust: trust["owner_passkey"].update(from_sequence=value))


def _receipt_sequence(value: int):
    return _at("receipt", _set(sequence=value))


def _not_executed(entry: dict) -> None:
    entry.update(receipt=None, checkpoint=None)


def _file_under_another_id(filed: list) -> None:
    filed[0] = ID_PREFIX + "00" * 32


CONFIRMED = "approval-confirmed-and-executed"
NOT_ATTRIBUTABLE = "approval-not-attributable"
CONTRADICTED = "execution-contradicted"
UNWITNESSED = "executed-unwitnessed"


def _defect(name, check, verdict, tweak=None, signers=None, check_off=CONFIRMED):
    """One thing wrong, the check that catches it, the verdict, and the verdict once
    that check is turned off: the defect passes."""
    return (name, check, tweak, signers, verdict, check_off)


def _other_ed25519(role: str) -> dict:
    return {role: Ed25519PrivateKey.generate()}


def _longer(content: dict) -> None:
    content["content"] += " "


def _oversize(auth: bytearray) -> None:
    auth.extend(bytes(MAX_AUTHENTICATOR_DATA + 1 - len(auth)))


def _truncate(auth: bytearray) -> None:
    del auth[36:]


def _zero_rp_id(auth: bytearray) -> None:
    auth[:32] = bytes(32)


def _fourth_field(request: dict) -> None:
    request["owner_assertion"]["extra"] = ""


def _next_version(receipt: dict) -> None:
    receipt["document_version"] += 1


def _next_count(checkpoint: dict) -> None:
    checkpoint["count"] += 1


ZEROS = "00" * 32
NO_ASSERTION = _at("request", _remove_assertion)
SINGLE_DEFECTS = [
    # Step 3: the record's digest of the request.
    _defect(
        "record cites another digest",
        "reference-digest",
        "approval-contradicted",
        _at("reference", _set(digest="sha256:" + ZEROS)),
    ),
    # Step 4: the trust and the approval.
    _defect(
        "trust signed by another root",
        "trust-signature",
        "trust-unverified",
        signers=_other_ed25519("root"),
    ),
    _defect(
        "entry filed under another id",
        "id-is-approval-digest",
        NOT_ATTRIBUTABLE,
        _at("filed", _file_under_another_id),
    ),
    _defect(
        "authority revoked",
        "authority-not-revoked",
        NOT_ATTRIBUTABLE,
        _at("trust", _revoke_authority),
    ),
    _defect(
        "authority not named",
        "authority-named",
        NOT_ATTRIBUTABLE,
        _at("trust", _set(authority=OTHER_KEY)),
    ),
    _defect(
        "approval signed by another key",
        "approval-signature",
        NOT_ATTRIBUTABLE,
        signers=_other_ed25519("authority"),
    ),
    _defect(
        "content does not hash to the approval",
        "content-hash",
        NOT_ATTRIBUTABLE,
        _at("content", _longer),
    ),
    _defect(
        "approval names another receiver",
        "approval-receiver",
        NOT_ATTRIBUTABLE,
        _at("approval", _set(receiver=OTHER_KEY)),
    ),
    # Step 4: when the owner's passkey assertion is required.
    _defect(
        "no assertion at from_sequence",
        "assertion-required",
        NOT_ATTRIBUTABLE,
        _all(_from_sequence(5), _receipt_sequence(5), NO_ASSERTION),
    ),
    _defect(
        "no assertion and no receipt",
        "assertion-required",
        NOT_ATTRIBUTABLE,
        _all(NO_ASSERTION, _at("entry", _not_executed)),
        check_off="approved-not-executed",
    ),
    _defect(
        "assertion before from_sequence",
        "assertion-unexpected",
        NOT_ATTRIBUTABLE,
        _all(_from_sequence(5), _receipt_sequence(4)),
    ),
    _defect(
        "assertion and no passkey in the trust",
        "assertion-unexpected",
        NOT_ATTRIBUTABLE,
        _at("trust", _remove_passkey),
    ),
    # Step 4: the assertion as stored.
    _defect(
        "assertion with a fourth field",
        "assertion-fields",
        NOT_ATTRIBUTABLE,
        _at("request", _fourth_field),
    ),
    _defect(
        "authenticator data padded",
        "assertion-encoding",
        NOT_ATTRIBUTABLE,
        _at("request", _pad_authenticator_data),
    ),
    _defect(
        "authenticator data with an unused bit set",
        "assertion-encoding",
        NOT_ATTRIBUTABLE,
        _at("request", _set_unused_bits),
    ),
    _defect(
        "authenticator data over 1024 bytes",
        "assertion-size",
        NOT_ATTRIBUTABLE,
        _at("auth", _oversize),
    ),
    _defect(
        "client data over 2048 bytes",
        "assertion-size",
        NOT_ATTRIBUTABLE,
        _at("client", _set(other="x" * MAX_CLIENT_DATA_JSON)),
    ),
    # Step 4: the client data.
    _defect(
        "client data with two origins",
        "client-data-duplicate-key",
        NOT_ATTRIBUTABLE,
        _at("client_bytes", _repeat_origin),
    ),
    _defect(
        "client data nested past the depth limit",
        "client-data-depth",
        NOT_ATTRIBUTABLE,
        _at("client", _set(other=_nested(MAX_CLIENT_DATA_DEPTH))),
    ),
    _defect(
        "assertion type",
        "client-data-type",
        NOT_ATTRIBUTABLE,
        _at("client", _set(type="webauthn.create")),
    ),
    _defect(
        "assertion challenge",
        "client-data-challenge",
        NOT_ATTRIBUTABLE,
        _at("client", _set(challenge=_b64u(bytes(32)))),
    ),
    _defect(
        "assertion origin",
        "client-data-origin",
        NOT_ATTRIBUTABLE,
        _at("client", _set(origin="http://localhost:1")),
    ),
    _defect(
        "assertion cross-origin",
        "client-data-cross-origin",
        NOT_ATTRIBUTABLE,
        _at("client", _set(crossOrigin=True)),
    ),
    # Step 4: the authenticator data and the assertion signature.
    _defect(
        "authenticator data of 36 bytes",
        "authenticator-data-length",
        NOT_ATTRIBUTABLE,
        _at("auth", _truncate),
    ),
    _defect(
        "assertion relying party",
        "authenticator-data-rp-id",
        NOT_ATTRIBUTABLE,
        _at("auth", _zero_rp_id),
    ),
    _defect(
        "assertion without user presence",
        "authenticator-data-user-present",
        NOT_ATTRIBUTABLE,
        _at("auth", _flags(0x04)),
    ),
    _defect(
        "assertion without user verification",
        "authenticator-data-user-verified",
        NOT_ATTRIBUTABLE,
        _at("auth", _flags(0x01)),
    ),
    _defect(
        "assertion signed by another passkey",
        "assertion-signature",
        NOT_ATTRIBUTABLE,
        signers={"owner": ec.generate_private_key(ec.SECP256R1())},
    ),
    # Step 5: the receipt.
    _defect(
        "receipt signed by another key",
        "receipt-signature",
        CONTRADICTED,
        signers=_other_ed25519("receiver"),
    ),
    _defect("receipt kind", "receipt-kind", CONTRADICTED, _at("receipt", _set(kind="create"))),
    _defect(
        "receipt names another approval",
        "receipt-approval",
        CONTRADICTED,
        _at("receipt", _set(approval_sha256=ZEROS)),
    ),
    _defect(
        "receipt content hash",
        "receipt-content",
        CONTRADICTED,
        _at("receipt", _set(content_sha256=ZEROS)),
    ),
    _defect(
        "receipt document",
        "receipt-document",
        CONTRADICTED,
        _at("receipt", _set(document="other")),
    ),
    _defect("receipt version", "receipt-version", CONTRADICTED, _at("receipt", _next_version)),
    # Step 6: the checkpoint.
    _defect(
        "checkpoint signed by another key",
        "checkpoint-signature",
        UNWITNESSED,
        signers=_other_ed25519("witness"),
    ),
    _defect(
        "checkpoint names another receiver",
        "checkpoint-receiver",
        UNWITNESSED,
        _at("checkpoint", _set(receiver=OTHER_KEY)),
    ),
    _defect(
        "checkpoint short of the receipt",
        "checkpoint-count",
        UNWITNESSED,
        _at("checkpoint", _set(count=0)),
    ),
    _defect(
        "checkpoint later than the receipt",
        "checkpoint-count",
        UNWITNESSED,
        _at("checkpoint", _next_count),
    ),
    _defect(
        "checkpoint head is not this receipt",
        "checkpoint-head",
        UNWITNESSED,
        _at("checkpoint", _set(head=ZEROS)),
    ),
]
DEFECT_IDS = [case[0] for case in SINGLE_DEFECTS]


@pytest.mark.parametrize(
    ("tweak", "signers", "verdict"),
    [case[2:5] for case in SINGLE_DEFECTS],
    ids=DEFECT_IDS,
)
def test_each_check_fails_on_its_own_defect(tweak, signers, verdict) -> None:
    record, store, root = _test_store(tweak or _no_change, signers)
    assert _assess(record, store, root)["verdict"] == verdict


@pytest.mark.parametrize(
    ("check", "tweak", "signers", "verdict", "verdict_with_check_off"),
    [case[1:] for case in SINGLE_DEFECTS],
    ids=DEFECT_IDS,
)
def test_each_defect_passes_once_its_check_is_off(
    check, tweak, signers, verdict, verdict_with_check_off
) -> None:
    """The named check is the one that catches the defect: with it off, and every other
    check on, the defect is no longer reported."""
    record, store, root = _test_store(tweak or _no_change, signers)
    assert verdict != verdict_with_check_off
    assert _assess(record, store, root, skip=frozenset({check}))["verdict"] == (
        verdict_with_check_off
    )


def test_every_check_has_a_defect_that_only_it_catches() -> None:
    assert {case[1] for case in SINGLE_DEFECTS} == set(CHECKS)
    assert len(set(CHECKS)) == len(CHECKS)


def test_the_reference_digest_check_is_the_one_that_catches_an_altered_store() -> None:
    """Step 3 on the committed case 02, where no test key is needed: with the digest
    check off, the next check to fail is the content hash."""
    record = _load("02-approval-altered-after-issue.json")
    store = _load("openproof-approvals-altered.json")
    assert _assess(record, store)["verdict"] == "approval-contradicted"
    verdict = _assess(record, store, skip=frozenset({"reference-digest"}))["verdict"]
    assert verdict == NOT_ATTRIBUTABLE
    both = frozenset({"reference-digest", "content-hash"})
    assert _assess(record, store, skip=both)["verdict"] == CONFIRMED


# The owner-passkey rule at its boundary. These are not defects: each is a history
# OpenProof accepts, and `_assess` confirms it.
ACCEPTED_HISTORIES = [
    (
        "assertion at from_sequence",
        _all(_from_sequence(5), _receipt_sequence(5)),
    ),
    (
        "assertion after from_sequence",
        _all(_from_sequence(5), _receipt_sequence(6)),
    ),
    (
        "no assertion before from_sequence",
        _all(_from_sequence(5), _receipt_sequence(4), _at("request", _remove_assertion)),
    ),
    (
        "no assertion and no passkey in the trust",
        _all(_at("trust", _remove_passkey), _at("request", _remove_assertion)),
    ),
]


@pytest.mark.parametrize(
    "tweak", [case[1] for case in ACCEPTED_HISTORIES], ids=[c[0] for c in ACCEPTED_HISTORIES]
)
def test_the_passkey_rule_accepts_what_openproof_accepts(tweak) -> None:
    record, store, root = _test_store(tweak)
    assert _assess(record, store, root)["verdict"] == CONFIRMED


def test_a_receipt_the_receiver_did_not_sign_gives_no_sequence_number() -> None:
    """What `_assess` reports when it cannot place a request in the history. The request
    was approved before the passkey and carries no assertion, which OpenProof accepts
    at sequence 4. With a receipt signed by another key, nothing says it is at sequence
    4, so an assertion is required and the approval is reported as not attributable.
    The same request with an assertion gets as far as the receipt and fails there."""
    before_passkey = _all(_from_sequence(5), _receipt_sequence(4))
    other_receiver = {"receiver": Ed25519PrivateKey.generate()}
    record, store, root = _test_store(
        _all(before_passkey, _at("request", _remove_assertion)), other_receiver
    )
    assert _assess(record, store, root)["verdict"] == NOT_ATTRIBUTABLE
    record, store, root = _test_store(before_passkey, other_receiver)
    assert _assess(record, store, root)["verdict"] == CONTRADICTED


MALFORMED_CLIENT_DATA = [
    ("not JSON", b"{"),
    ("a JSON array", b"[]"),
    ("not UTF-8", b'{"type":"webauthn.get","origin":"\xff"}'),
    ("a number that is not JSON", b'{"type":"webauthn.get","other":NaN}'),
    ("half of a surrogate pair", b'{"type":"webauthn.get","other":"\\ud800"}'),
]


@pytest.mark.parametrize(
    "client_data",
    [case[1] for case in MALFORMED_CLIENT_DATA],
    ids=[case[0] for case in MALFORMED_CLIENT_DATA],
)
def test_client_data_that_is_not_one_json_object_is_not_attributable(client_data) -> None:
    """These fail closed in the parse, before any named check, so no check can be turned
    off to let them pass. The assertion signature is made over the bytes as given."""
    record, store, root = _test_store(
        _at("client_bytes", lambda holder: holder.__setitem__(0, client_data))
    )
    assert _assess(record, store, root)["verdict"] == NOT_ATTRIBUTABLE
    assert _assess(record, store, root, skip=frozenset(CHECKS))["verdict"] == NOT_ATTRIBUTABLE
