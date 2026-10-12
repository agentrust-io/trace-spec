#!/usr/bin/python3
"""Fuzz TR-SIG for acceptance of anything but the record that was signed.

A crash-only target would miss the defect class that matters here, which is a
verifier that says PASS too often. So the target signs one record with a fixed
key, lets the fuzzer mutate it (the signature string, the key, a field of the
body, a new field), and asserts that TR-SIG never passes a record whose
signature string or RFC 8785 body differs from the original. Ed25519 as
``cryptography`` implements it rejects non-canonical signatures, so any PASS on
a changed record is a defect in this suite: an encoding it decodes too
leniently, or bytes it canonicalizes differently from the signer.

Both signed formats are covered: a plain record, whose key lives in the record,
and a cmcp RuntimeClaim envelope, whose key lives under ``trace``.
"""
import base64
import sys

import atheris

with atheris.instrument_imports():
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from trace_tests.modules import tr_sig

_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWK = {"kty": "OKP", "crv": "Ed25519", "x": _b64(_KEY.public_key().public_bytes_raw())}


def _sign(body: dict) -> dict:
    return {**body, "signature": _b64(_KEY.sign(rfc8785.dumps(body)))}


_PLAIN = _sign({
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1_760_000_000,
    "subject": "spiffe://example.org/agent/é",
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "cnf": {"jwk": dict(_JWK)},
})
_CMCP = _sign({"cmcp_version": "0.1", "trace": {"cnf": {"jwk": dict(_JWK)}}})


def _value(fdp: atheris.FuzzedDataProvider) -> object:
    kind = fdp.ConsumeIntInRange(0, 5)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        return fdp.ConsumeIntInRange(-(2**54), 2**54)
    if kind == 3:
        return fdp.ConsumeFloat()
    if kind == 4:
        return fdp.ConsumeUnicode(32)
    return [fdp.ConsumeUnicode(8)]


def _mutate(fdp: atheris.FuzzedDataProvider, original: dict) -> dict:
    record = dict(original)
    sig = record["signature"]
    op = fdp.ConsumeIntInRange(0, 5)
    if op == 0:
        record["signature"] = fdp.ConsumeUnicode(128)
    elif op == 1:
        i = fdp.ConsumeIntInRange(0, len(sig))
        record["signature"] = sig[:i] + fdp.ConsumeUnicode(4) + sig[i:]
    elif op == 2:
        i = fdp.ConsumeIntInRange(0, len(sig) - 1)
        record["signature"] = sig[:i] + fdp.ConsumeUnicode(1) + sig[i + 1 :]
    elif op == 3:
        # The key, wherever this format keeps it.
        jwk = {**_JWK, "x": fdp.ConsumeUnicode(64)}
        if "trace" in record:
            record["trace"] = {**record["trace"], "cnf": {"jwk": jwk}}
        else:
            record["cnf"] = {"jwk": jwk}
    elif op == 4:
        keys = sorted(k for k in record if k != "signature")
        record[keys[fdp.ConsumeIntInRange(0, len(keys) - 1)]] = _value(fdp)
    else:
        record[fdp.ConsumeUnicode(8)] = _value(fdp)
    return record


def _body(record: dict) -> bytes | None:
    try:
        return rfc8785.dumps({k: v for k, v in record.items() if k != "signature"})
    except rfc8785.CanonicalizationError:
        return None


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    cmcp = fdp.ConsumeBool()
    original = _CMCP if cmcp else _PLAIN
    record = _mutate(fdp, original)

    if cmcp:
        findings = tr_sig.check_cmcp_runtime(record)
        code = "TR-SIG-001"
    else:
        findings = tr_sig.check(record, record, "trace", 1)
        code = "TR-SIG-005"

    if not any(f.code == code and f.passed() for f in findings):
        return
    assert record.get("signature") == original["signature"], (
        f"{code} passed a respelled signature: {record.get('signature')!r}"
    )
    assert _body(record) == _body(original), f"{code} passed a changed body: {record!r}"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
