#!/usr/bin/env python3
"""Verify an xChk receipt bundle with no network. Standard library only (post-quantum half optional, see below).

MIT License. Copyright (c) 2026 Sean MacGuire. Permission is hereby granted, free of charge, to any person
obtaining a copy of this file, to deal in it without restriction, subject to this notice being included.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Usage:  python3 verify_receipt.py xchk-receipt-<hash>.json [file]
Exit:   0 = every offline check passed; 1 = a check failed; 2 = could not read the bundle.

With a second argument (5 Oct 2026), also checks that FILE is the one this receipt's action wrote: sha256 of its
bytes equals the record's artifactHash, which check 1 has already tied to the record hash. That proves which plate
and run left those bytes on the host, as the host reported it; it does not prove the content is true.

Checks (each reproduces the rule the registry used to write the bytes; bundle formats /1 and /2):
  1. record hash   = sha256(canonical(record))           canonical = sorted keys, no whitespace, JSON scalars, UTF-8
  2. Merkle path   from the record hash to the seal root  node = sha256(left_hex + right_hex); odd node promoted unhashed
  3. seal hash     = sha256(canonical(seal fields))
  4. registry sig  EVERY signature the seal carries, over the seal-hash bytes, each with the pinned key of its alg and
                   keyId: Ed25519 (pure Python, below) and — since 24 Sep 2026 — ML-DSA-65 (FIPS 204). A hybrid must
                   pass both. Unknown algs fail. Key ids are recomputed from the pinned keys.
                   The ML-DSA half needs `pip install dilithium-py` (pure Python, MIT); without it that half is
                   reported as WAIT, never as a pass, and the exit code is 1 only if something actually failed.
  4b. root         the SLH-DSA-SHA2-128s (FIPS 205) key statement, when the bundle carries one: shown, and checked that
                   every pinned key is listed in it; the SLH-DSA signature itself needs a library this script does not
                   ship (WAIT) — pin the root's public key once and check it with any FIPS 205 implementation.
  5. approver      the passkey assertion that answered: ECDSA P-256 over authenticatorData || sha256(clientDataJSON),
                   user-verified flag set; then the registry's identity binding (same rules as 4) tying that credential
                   to this person for THIS record hash
  6. anchor        the raw Ravencoin transaction carries the seal hash in OP_RETURN; sha256d(tx) is the txid; the
                   merkleblock's partial Merkle tree reproduces its header's Merkle root and includes the txid.
                   Left for you to confirm on any explorer: that block hash + Merkle root are on the chain
                   (Ravencoin's block hash is a KAWPOW hash, which this script does not compute).
"""
import base64
import hashlib
import json
import sys
from typing import Optional

try:  # optional post-quantum half: https://pypi.org/project/dilithium-py (pure Python)
    from dilithium_py.ml_dsa import ML_DSA_65 as _ML_DSA_65
except Exception:  # noqa: BLE001
    _ML_DSA_65 = None

# ----------------------------------------------------------------------------------------------------- canonical

SEAL_KEYS = ["v", "agentId", "plate", "sealSeq", "windowStart", "windowEnd", "count", "issuedCount",
             "seqStart", "seqEnd", "merkleRoot", "deskCondition", "prevSealHash", "rvnBlock", "profileHash"]
# rvnBlock and profileHash (6 Oct 2026) enter the hash only when the seal carries them


def canonical(value):
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, float):
        raise ValueError(f"non-integer number {value} is outside the sealed value profile")
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canonical(value[k])
                              for k in sorted(value.keys())) + "}"
    raise ValueError(f"unsupported value type {type(value).__name__}")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b64d(s) -> bytes:
    if isinstance(s, dict):
        s = s.get("signature", "")
    s = str(s).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))

# ------------------------------------------------------------------------------------------------------- Ed25519
# Reference algorithm (Bernstein et al.), affine arithmetic; a few hundred ms per signature, no dependencies.

_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_B = (_xrecover(_By), _By)


def _add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _mul(P, e):
    Q = (0, 1)
    while e:
        if e & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        e >>= 1
    return Q


def _decodepoint(b: bytes):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (b[31] >> 7):
        x = _q - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
        raise ValueError("point not on curve")
    return (x, y)


def ed25519_verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pub_raw) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pub_raw)
    except ValueError:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _l:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub_raw + msg).digest(), "little") % _l
    return _mul(_B, S) == _add(R, _mul(A, h))

# ---------------------------------------------------------------------------------------- key ids + registry sigs

ED_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def key_id_for(alg: str, pub_raw: bytes) -> str:
    """Ed25519 ids hash the SPKI DER; post-quantum ids hash the raw public key. 16 hex chars."""
    data = ED_SPKI_PREFIX + pub_raw if alg == "ed25519" else pub_raw
    return hashlib.sha256(data).hexdigest()[:16]


def ml_dsa_65_verify(pub_raw: bytes, msg: bytes, sig: bytes):
    """True/False, or None when dilithium-py is not installed."""
    if _ML_DSA_65 is None:
        return None
    try:
        return bool(_ML_DSA_65.verify(pub_raw, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def pinned_keys(rs: dict) -> list:
    keys = rs.get("keys")
    if isinstance(keys, list) and keys:
        return keys
    if rs.get("publicKeyRaw"):   # pre-hybrid bundle: one Ed25519 key
        alg = rs.get("alg") if rs.get("alg") and rs.get("alg") != "ed25519+ml-dsa-65" else "ed25519"
        return [{"alg": alg, "keyId": rs.get("keyId"), "publicKeyRaw": rs["publicKeyRaw"]}]
    return []


def registry_verify(ok, sig_obj: dict, msg: bytes, keys: list, what: str) -> int:
    """Verify every signature the object lists. Returns the number of WAITs (unverifiable halves); FAILs go through ok()."""
    sigs = sig_obj.get("signatures") if isinstance(sig_obj.get("signatures"), list) and sig_obj.get("signatures") else None
    if not sigs and sig_obj.get("signature"):
        alg = sig_obj.get("alg") if sig_obj.get("alg") and sig_obj.get("alg") != "ed25519+ml-dsa-65" else "ed25519"
        sigs = [{"alg": alg, "keyId": sig_obj.get("keyId"), "signature": sig_obj["signature"]}]
    if not sigs:
        ok(False, f"{what}: no signature to check")
        return 0
    waits = 0
    for sig in sigs:
        alg = sig.get("alg")
        key = next((k for k in keys if k.get("alg") == alg and (not sig.get("keyId") or not k.get("keyId") or k.get("keyId") == sig.get("keyId"))), None)
        if not key:
            ok(False, f"{what}: no pinned key for alg {alg!r} keyId {sig.get('keyId')!r}")
            continue
        pub = b64d(key["publicKeyRaw"])
        kid = key_id_for(alg, pub)
        if key.get("keyId") and kid != key.get("keyId"):
            ok(False, f"{what}: pinned {alg} key's id recomputes to {kid}, not {key.get('keyId')}")
            continue
        if alg == "ed25519":
            r = ed25519_verify(pub, msg, b64d(sig["signature"]))
        elif alg == "ml-dsa-65":
            r = ml_dsa_65_verify(pub, msg, b64d(sig["signature"]))
        else:
            r = False
        if r is None:
            waits += 1
            print(f"  WAIT {what}: {alg} signature present (keyId {kid}) — install dilithium-py to verify the post-quantum half")
        else:
            ok(r, f"{what}: {alg} signature verifies with pinned key {kid}" + (" (FIPS 204, post-quantum)" if alg == "ml-dsa-65" else ""))
    if len(sigs) > 1 and waits == 0:
        print(f"  ..   {what}: HYBRID — {' + '.join(s.get('alg', '?') for s in sigs)}, every half checked")
    return waits

# --------------------------------------------------------------------------------------------------- ECDSA P-256

_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b


def _p256_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, _p - 2, _p) % _p
    else:
        lam = (y2 - y1) * pow(x2 - x1, _p - 2, _p) % _p
    x3 = (lam * lam - x1 - x2) % _p
    return (x3, (lam * (x1 - x3) - y1) % _p)


def _p256_mul(P, e):
    Q = None
    while e:
        if e & 1:
            Q = _p256_add(Q, P)
        P = _p256_add(P, P)
        e >>= 1
    return Q


def _der_sig(sig: bytes):
    if len(sig) < 8 or sig[0] != 0x30 or sig[2] != 0x02:
        raise ValueError("not a DER ECDSA signature")
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    if sig[4 + rl] != 0x02:
        raise ValueError("not a DER ECDSA signature")
    sl = sig[5 + rl]
    s = int.from_bytes(sig[6 + rl:6 + rl + sl], "big")
    return r, s


def p256_verify(pub_uncompressed: bytes, msg: bytes, der_sig: bytes) -> bool:
    if len(pub_uncompressed) != 65 or pub_uncompressed[0] != 4:
        return False
    Qx = int.from_bytes(pub_uncompressed[1:33], "big")
    Qy = int.from_bytes(pub_uncompressed[33:65], "big")
    if (Qy * Qy - (Qx ** 3 - 3 * Qx + _b)) % _p != 0:
        return False
    try:
        r, s = _der_sig(der_sig)
    except ValueError:
        return False
    if not (1 <= r < _n and 1 <= s < _n):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, _n - 2, _n)
    u1 = (e * w) % _n
    u2 = (r * w) % _n
    X = _p256_add(_p256_mul((_Gx, _Gy), u1), _p256_mul((Qx, Qy), u2))
    return X is not None and X[0] % _n == r

# ------------------------------------------------------------------------------------------------- anchor proof


def _varint(b: bytes, i: int):
    v = b[i]
    if v < 0xfd:
        return v, i + 1
    if v == 0xfd:
        return int.from_bytes(b[i + 1:i + 3], "little"), i + 3
    if v == 0xfe:
        return int.from_bytes(b[i + 1:i + 5], "little"), i + 5
    return int.from_bytes(b[i + 1:i + 9], "little"), i + 9


def tx_op_return_payloads(tx: bytes):
    """Every OP_RETURN payload in a legacy (non-witness) transaction."""
    i = 4
    n_in, i = _varint(tx, i)
    for _ in range(n_in):
        i += 36
        sl, i = _varint(tx, i)
        i += sl + 4
    n_out, i = _varint(tx, i)
    out = []
    for _ in range(n_out):
        i += 8
        sl, i = _varint(tx, i)
        script = tx[i:i + sl]
        i += sl
        if script and script[0] == 0x6a:
            j = 1
            if j < len(script):
                op = script[j]
                if op <= 0x4b:
                    out.append(script[j + 1:j + 1 + op])
                elif op == 0x4c:
                    out.append(script[j + 2:j + 2 + script[j + 1]])
                elif op == 0x4d:
                    ln = int.from_bytes(script[j + 1:j + 3], "little")
                    out.append(script[j + 3:j + 3 + ln])
    return out


def merkleblock_check(mb: bytes, header_len: int, txid_hex: str):
    """Parse a Bitcoin-style merkleblock; return (merkle_root_hex, txid_included, computed_root_matches_header)."""
    header = mb[:header_len]
    root_in_header = header[36:68][::-1].hex()
    i = header_len
    ntx = int.from_bytes(mb[i:i + 4], "little")
    i += 4
    nh, i = _varint(mb, i)
    hashes = [mb[i + 32 * k:i + 32 * (k + 1)] for k in range(nh)]
    i += 32 * nh
    nf, i = _varint(mb, i)
    flags = mb[i:i + nf]
    bits = []
    for byte in flags:
        for k in range(8):
            bits.append((byte >> k) & 1)
    height = 0
    while (1 << height) < ntx:
        height += 1
    state = {"h": 0, "b": 0, "matched": []}

    def width(h):
        return (ntx + (1 << h) - 1) >> h

    def walk(h, pos):
        flag = bits[state["b"]]
        state["b"] += 1
        if h == 0 or flag == 0:
            hsh = hashes[state["h"]]
            state["h"] += 1
            if h == 0 and flag:
                state["matched"].append(hsh)
            return hsh
        left = walk(h - 1, pos * 2)
        right = walk(h - 1, pos * 2 + 1) if pos * 2 + 1 < width(h - 1) else left
        return sha256d(left + right)

    computed = walk(height, 0)[::-1].hex()
    included = any(m[::-1].hex() == txid_hex for m in state["matched"])
    return root_in_header, included, computed == root_in_header

# --------------------------------------------------------------------------------------------------------- main


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------------------------------------ OpenTimestamps (6 Oct 2026)
# A second, independent anchor: the seal hash was submitted to an OpenTimestamps calendar, which commits it to Bitcoin.
# Wire format of python-opentimestamps (core/op.py, notary.py, timestamp.py), dependency-free here:
#   timestamp := (0xff op timestamp)* (0x00 attestation | op timestamp);  op := tag [varbytes arg]
#   0xf0 append · 0xf1 prepend · 0xf2 reverse · 0xf3 hexlify · 0x02 sha1 · 0x03 ripemd160 · 0x08 sha256
#   attestation := 8-byte tag, varbytes payload; 83dfe30d2ef90c8e pending (varbytes uri) · 0588960d73d71901 bitcoin (varuint height)
# The message at a Bitcoin attestation is the block's Merkle root in header byte order: the one fact left to the reader.
OTS_OPS = {0xF0: "append", 0xF1: "prepend", 0xF2: "reverse", 0xF3: "hexlify", 0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256"}
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")


class _OtsReader:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def byte(self) -> int:
        if self.i >= len(self.b):
            raise ValueError("ots: truncated")
        v = self.b[self.i]
        self.i += 1
        return v

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise ValueError("ots: truncated")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def varuint(self) -> int:
        v, shift = 0, 0
        while True:
            c = self.byte()
            v |= (c & 0x7F) << shift
            if not c & 0x80:
                return v
            shift += 7
            if shift > 56:
                raise ValueError("ots: varuint too long")

    def varbytes(self, mx: int = 4096) -> bytes:
        n = self.varuint()
        if n > mx:
            raise ValueError("ots: varbytes too long")
        return self.take(n)


def _ots_apply(op: str, arg, msg: bytes) -> bytes:
    if op == "append":
        return msg + arg
    if op == "prepend":
        return arg + msg
    if op == "reverse":
        return msg[::-1]
    if op == "hexlify":
        return msg.hex().encode("ascii")
    if op == "sha1":
        return hashlib.sha1(msg).digest()
    if op == "ripemd160":
        return hashlib.new("ripemd160", msg).digest()
    if op == "sha256":
        return hashlib.sha256(msg).digest()
    raise ValueError(f"ots: unsupported op {op}")


def ots_attestations(proof: bytes, digest: bytes) -> list:
    """Replay a calendar proof from the digest: [(kind, value, msg)] with kind 'pending' (value = uri) or 'bitcoin' (value = height)."""
    r = _OtsReader(proof)
    out = []

    def timestamp(msg: bytes, depth: int):
        if depth > 256:
            raise ValueError("ots: too deep")
        tag = r.byte()
        while tag == 0xFF:
            node(msg, r.byte(), depth)
            tag = r.byte()
        node(msg, tag, depth)

    def node(msg: bytes, tag: int, depth: int):
        if tag == 0x00:
            att = r.take(8)
            payload = r.varbytes(8192)
            if att == OTS_PENDING:
                out.append(("pending", _OtsReader(payload).varbytes(1000).decode("utf-8", "replace"), msg))
            elif att == OTS_BITCOIN:
                out.append(("bitcoin", _OtsReader(payload).varuint(), msg))
            else:
                out.append(("unknown", att.hex(), msg))
            return
        op = OTS_OPS.get(tag)
        if not op:
            raise ValueError(f"ots: unknown op tag 0x{tag:02x}")
        arg = r.varbytes() if op in ("append", "prepend") else None
        timestamp(_ots_apply(op, arg, msg), depth + 1)

    timestamp(digest, 0)
    if r.i != len(proof):
        raise ValueError("ots: trailing bytes")
    return out


def main(path: str, artifact_path: Optional[str] = None) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            b = json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"could not read bundle: {exc}")
        return 2
    if b.get("format") not in ("xchk-receipt-bundle/1", "xchk-receipt-bundle/2"):
        print(f"not an xChk receipt bundle (format={b.get('format')!r})")
        return 2

    failed = 0
    pending = 0

    def ok(cond, text):
        nonlocal failed
        print(("  OK   " if cond else "  FAIL ") + text)
        if not cond:
            failed += 1

    rec = b.get("record") or {}
    print(f"xChk receipt {b.get('recordHash')}  ({b.get('format')})")
    print(f"  {b.get('issuer', {}).get('headline', '')}")

    # 1. record hash
    mine = sha256_hex(canonical(rec))
    ok(mine == b.get("recordHash"), f"record hash recomputed: {mine}")
    print(f"  ..   {'chained to previous record ' + rec['prevHash'] if rec.get('prevHash') else 'first record on its chain'}")

    # 1b. the file, when one was given: its bytes against the digest sealed in the record
    if artifact_path:
        want = rec.get("artifactHash")
        if not want:
            ok(False, "this record carries no artifactHash: it is not the outcome record of a file write")
        else:
            try:
                got = file_sha256(artifact_path)
                ok(got == want, f"file {artifact_path} is the one this action wrote: sha256 {got}" if got == want
                   else f"file {artifact_path} is NOT the one this action wrote: sha256 {got}, record says {want}")
            except OSError as exc:
                ok(False, f"could not read {artifact_path}: {exc}")
        if rec.get("outcomeOf"):
            print(f"  ..   written under decision {rec['outcomeOf']} by {rec.get('plate')}, run {rec.get('runRef') or rec.get('runSeq')}")

    # 2. merkle
    seal = b.get("seal")
    merkle = b.get("merkle")
    if seal and merkle and isinstance(merkle.get("proof"), list):
        cur = b["recordHash"]
        for step in merkle["proof"]:
            cur = sha256_hex(step["hash"] + cur) if step.get("side") == "L" else sha256_hex(cur + step["hash"])
        ok(cur == seal.get("merkleRoot"), f"Merkle path ({len(merkle['proof'])} steps) reaches seal root {seal.get('merkleRoot')}")
    else:
        pending += 1
        print("  WAIT not sealed when the bundle was made — download it again later")

    # 3. seal hash
    if seal:
        fields = {k: seal[k] for k in SEAL_KEYS if k in seal and not (k in ("rvnBlock", "profileHash") and seal[k] is None)}
        sh = sha256_hex(canonical(fields))
        ok(sh == seal.get("sealHash"), f"seal #{seal.get('sealSeq')} hash recomputed: {sh}")

        # 3b. the node profile the seal names (6 Oct 2026): which rules produced this record, checkable here, offline
        ph = seal.get("profileHash")
        if ph:
            prof = b.get("profile") or {}
            doc = prof.get("document")
            if not isinstance(doc, dict):
                ok(False, f"seal names profile {ph[:12]}… but the bundle does not carry it ({prof.get('note') or 'missing'})")
            else:
                dh = sha256_hex(canonical(doc))
                ok(dh == ph, f"profile document hashes to the seal's profileHash: {dh}" if dh == ph
                   else f"profile document does NOT hash to the seal's profileHash: {dh}, seal says {ph}")
                psig = prof.get("signature") or {}
                pkeys = pinned_keys(b.get("registrySignature") or {})
                if (psig.get("signature") or psig.get("signatures")) and pkeys:
                    pending += registry_verify(ok, psig, ph.encode("utf-8"), pkeys, "registry signature over the profile hash")
                else:
                    ok(False, "profile carries no registry signature")
                print(f"  ..   sealed under profile \"{doc.get('name')}\" of {doc.get('registry')} ({ph[:12]}…): "
                      + ", ".join(f"{k}={json.dumps(v, separators=(',', ':'))}" for k, v in sorted((doc.get("dials") or {}).items())))
        else:
            print("  ..   sealed before profiles (no profileHash in the seal)")

    # 4. registry signature(s) — Ed25519, or hybrid Ed25519 + ML-DSA-65
    rs = b.get("registrySignature") or {}
    keys = pinned_keys(rs)
    if seal and (rs.get("signature") or rs.get("signatures")) and keys:
        pending += registry_verify(ok, rs, seal["sealHash"].encode("utf-8"), keys, "registry signature over the seal hash")
        pinned = ", ".join(f"{k.get('alg')}/{k.get('keyId')}" for k in keys)  # 18 Oct 2026: no nested same-quote f-string (3.12-only syntax)
        print(f"  ..   keys pinned in the bundle: {pinned}; confirm at {rs.get('wellKnown')} when online")
    elif seal:
        pending += 1
        print(f"  WAIT no registry signature in this bundle ({rs.get('note') or 'unsigned'})")

    # 4b. root key statement (SLH-DSA-SHA2-128s)
    root = rs.get("root")
    if isinstance(root, dict) and root.get("statement") and root.get("signature"):
        stated = root["statement"].get("keys") or []
        listed = all(any(x.get("alg") == k.get("alg") and x.get("keyId") == k.get("keyId") and x.get("publicKeyRaw") == k.get("publicKeyRaw") for x in stated) for k in keys)
        ok(listed, "every key pinned in this bundle is listed in the root's key statement")
        rid = key_id_for(root.get("alg", ""), b64d(root.get("publicKeyRaw", "")))
        pending += 1
        print(f"  WAIT root {root.get('alg')} signature over canonical(statement) — pin root keyId {rid} and verify with any FIPS 205 implementation (not shipped in this script)")

    # 5. approver
    ap = b.get("approver")
    if ap:
        a = ap.get("assertion") or {}
        pk = ap.get("publicKey") or {}
        if a.get("signature") and a.get("authenticatorData") and a.get("clientDataJSON") and pk.get("format") == "ec-p256-uncompressed":
            auth = b64d(a["authenticatorData"])
            cdj = b64d(a["clientDataJSON"])
            try:
                cd = json.loads(cdj.decode("utf-8"))
            except Exception:  # noqa: BLE001
                cd = {}
            uv = len(auth) > 32 and bool(auth[32] & 0x04)
            sig_ok = p256_verify(b64d(pk["raw"]), auth + hashlib.sha256(cdj).digest(), b64d(a["signature"]))
            ok(sig_ok, f"passkey assertion signature verifies with the enrolled credential {str(ap.get('credentialId'))[:16]}…")
            ok(cd.get("type") == "webauthn.get", f"assertion is a WebAuthn 'get' ceremony (type={cd.get('type')!r})")
            ok(uv, "authenticator reports USER VERIFIED (biometric/PIN) for that ceremony")
        else:
            pending += 1
            print("  WAIT approver assertion or an ES256 public key not present in this bundle — the ceremony cannot be re-run here")
        bd = ap.get("binding") or {}
        if (bd.get("signature") or bd.get("signatures")) and keys and bd.get("fields"):
            f = bd["fields"]
            pending += registry_verify(ok, bd, canonical(f).encode("utf-8"), keys, f"identity binding: credential ↔ {f.get('approverEmail')} (level {f.get('authLevel')})")
            ok(f.get("recordHash") == b.get("recordHash"), "binding names this record hash")
            ok(f.get("credentialId") == ap.get("credentialId"), "binding names the credential that signed the assertion")
            # 17 Oct 2026: the key the assertion was checked with must be the key the registry bound to that credential,
            # or an attacker who swaps both the key and the assertion for their own passes check 5 with every registry
            # signature intact (TRACE fixture 06-assertion-from-another-credential).
            ok(f.get("publicKey") == pk.get("raw"), "binding names the public key the assertion was checked with")
        else:
            pending += 1
            print("  WAIT no signed identity binding (registry signing not configured when the bundle was made)")
        # 18 Oct 2026 (AB-1): what the device signed over. With rule ask-v1 the challenge is sha256 over the ask as
        # issued (attestation id, the prompt the person saw, the digest of the action's parameters), so the assertion
        # itself names the act it answered; recompute it from the bundle's own decision block, never from `expected`.
        # Without it the challenge was a nonce and only the registry's binding pairs the assertion with the record:
        # an assertion by the same credential over another ask passes every other check.
        ch = ap.get("challenge") or {}
        if ch.get("rule") == "ask-v1" and isinstance(ch.get("fields"), dict) and a.get("clientDataJSON"):
            f = ch["fields"]
            dec = b.get("decision") or {}
            try:
                cd = json.loads(b64d(a["clientDataJSON"]).decode("utf-8"))
            except Exception:  # noqa: BLE001
                cd = {}
            recomputed = base64.urlsafe_b64encode(hashlib.sha256(canonical(f).encode("utf-8")).digest()).decode("ascii").rstrip("=")
            ok(cd.get("challenge") == recomputed, "the challenge the device signed is sha256 over the ask (rule ask-v1)")
            ok(f.get("attestationId") == ap.get("attestationId"), "the signed ask names this ceremony")
            ok(f.get("prompt") == dec.get("prompt"), "the signed ask carries the prompt the person saw")
            ok(f.get("actionParamsHash") == dec.get("actionParamsHash"), "the signed ask carries the digest of the action's parameters")
        else:
            pending += 1
            print("  WAIT challenge not derived from the ask (ceremony before 18 Oct 2026): the binding alone pairs this assertion with the record")

    # 6. anchor
    anchor = b.get("anchor") or {}
    proof = anchor.get("proof")
    if proof and proof.get("txHex") and seal:
        tx = bytes.fromhex(proof["txHex"])
        payloads = tx_op_return_payloads(tx)
        carries = any(p[:3] == b"xCk" and p[9:41].hex() == seal["sealHash"] for p in payloads)
        ok(carries, "the raw anchor transaction's OP_RETURN carries this seal hash")
        ok(sha256d(tx)[::-1].hex() == proof.get("txid"), f"sha256d(transaction) = txid {proof.get('txid')}")
        hdr = bytes.fromhex(proof["headerHex"]) if proof.get("headerHex") else b""
        mb = bytes.fromhex(proof["merkleBlockHex"]) if proof.get("merkleBlockHex") else b""
        if hdr and mb:
            root_hdr, included, root_ok = merkleblock_check(mb, len(hdr), proof["txid"])
            ok(mb[:len(hdr)] == hdr, "merkleblock header is the block header shipped with the bundle")
            ok(root_ok and included, f"partial Merkle tree reproduces the header's Merkle root {root_hdr} and includes the txid")
            print(f"  WAIT one outside fact left: Ravencoin block {proof.get('blockHash')} (height {proof.get('blockHeight')}) has Merkle root {root_hdr}. Any explorer confirms it; the block hash itself is a KAWPOW hash this script does not compute.")
        else:
            pending += 1
            print("  WAIT anchor proof lacks header/merkleblock")
    elif anchor.get("rvnTxId"):
        pending += 1
        print(f"  WAIT anchor: Ravencoin tx {anchor['rvnTxId']} — raw bytes not yet captured in this bundle (download again after a confirmation), or confirm its OP_RETURN on an explorer:")
        print(f"       {anchor.get('explorer') or 'https://ravencoin.network/tx/' + anchor['rvnTxId']}")
    elif seal:
        pending += 1
        print("  WAIT seal not yet anchored when the bundle was made")

    # 3c. legal holds (7 Oct 2026): existence and scope only; the reason and the names are not on a public receipt
    for h in (b.get("legalHolds") or []):
        print(f"  ..   under a legal hold on the {h.get('scope')} since {h.get('placedAt')}"
              + (f", until {h.get('until')}" if h.get("until") else ", until released") + f" (hold {str(h.get('id'))[:8]}…)")

    # 6b. OpenTimestamps (6 Oct 2026): the second anchor, replayed from the seal hash to its attestations
    if seal and anchor.get("otsProof"):
        try:
            atts = ots_attestations(base64.b64decode(anchor["otsProof"]), bytes.fromhex(seal["sealHash"]))
            btc = [a for a in atts if a[0] == "bitcoin"]
            pend = [a for a in atts if a[0] == "pending"]
            if btc:
                for _, height, root in btc:
                    ok(len(root) == 32, f"OpenTimestamps proof replays from the seal hash to a 32-byte Merkle root at Bitcoin block {height}")
                    pending += 1
                    print(f"  WAIT one outside fact left: Bitcoin block {height} has Merkle root {root[::-1].hex()}. Any Bitcoin explorer confirms it.")
            elif pend:
                pending += 1
                print(f"  WAIT OpenTimestamps: the seal hash is committed at {', '.join(sorted({a[1] for a in pend}))}, not yet in a Bitcoin block when the bundle was made — download again later")
            else:
                ok(False, "OpenTimestamps proof carries no attestation this script knows")
        except Exception as exc:  # noqa: BLE001 — a proof that does not replay is a failed check, not a crash
            ok(False, f"OpenTimestamps proof does not replay: {exc}")

    if failed:
        print(f"\nRESULT: does NOT verify ({failed} check(s) failed)")
        return 1
    print("\nRESULT: verifies offline" + (f" — {pending} step(s) pending (see WAIT)" if pending else "") + "; only the block's presence on the chain is left to you")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
