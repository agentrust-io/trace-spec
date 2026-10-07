# ruff: noqa: E501, E731 (literal vector catalog: long descriptions, small named mutators)
"""Independent portable conformance corpus for the RFC-0001/0002 verifier token.

No reference-verifier imports. Envelopes, digests, binding digests and composite
results are built here from cbor2, rfc8785 and Ed25519 primitives and the literal
wire definitions in docs/verifier-token-experimental.md. Test-only keys; all
component appraisals are synthetic software observations.

Each counterexample isolates one defect. Where two checks necessarily detect the
same defect, the description names the construction choice.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cbor2
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).parent
OUT = HERE / "vectors"
LEGACY = HERE.parent / "verifier-token-profile"

PROFILE = "urn:agentrust:trace:verifier-token:experimental-v1"
PROOF_PROFILE = "urn:agentrust:trace:holder-proof:experimental-v1"
APPRAISAL_PROFILE = "urn:agentrust:trace:component-appraisal:experimental-v1"
TOKEN_MEDIA = "application/trace-verifier-token+json"
PROOF_MEDIA = "application/trace-holder-proof+json"
APPRAISAL_MEDIA = "application/trace-component-appraisal+json"
HEADER = "trace-profile"
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
HOLDER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ROGUE = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
APPRAISER = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
APPRAISER_ISS = "https://appraiser.example.test"
NOW = 1790683200
ISS = "https://verifier.example.test"
AUD = "spiffe://example.test/gateway/one"
SUB = "spiffe://example.test/agent/one"
EVIDENCE_PROFILE = "urn:example:software-evidence:v1"
POLICY = {
    "id": "https://verifier.example.test/policy",
    "version": "1",
    "digest": "sha256:" + "c" * 64,
}
ACTION = {"tool": "read", "args": {"id": "1"}}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def kid(key: Ed25519PrivateKey) -> bytes:
    return hashlib.sha256(public(key)).digest()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_digest(value: object) -> str:
    return digest(rfc8785.dumps(value))


NONCE = b64url(bytes(range(32)))
ACTION_DIGEST = canonical_digest(ACTION)


def headers_for(profile: str, media: str, key: Ed25519PrivateKey) -> dict:
    return {1: -19, 2: [HEADER], 3: media, 4: kid(key), HEADER: profile}


def envelope(
    payload: Any,
    key: Ed25519PrivateKey,
    *,
    headers: dict | None = None,
    unprotected: dict | None = None,
    carried: bytes | None = None,
    flip_signature: bool = False,
) -> bytes:
    """COSE_Sign1 (tag 18), Ed25519 -19, JCS payload, detached-free."""
    routes = {PROOF_PROFILE: PROOF_MEDIA, APPRAISAL_PROFILE: APPRAISAL_MEDIA}
    named = payload.get("profile") if isinstance(payload, dict) else None
    profile = named if named in routes else PROFILE
    media = routes.get(profile, TOKEN_MEDIA)
    protected = cbor2.dumps(
        headers if headers is not None else headers_for(profile, media, key), canonical=True
    )
    signed = rfc8785.dumps(payload)
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", signed], canonical=True))
    if flip_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    body = [protected, unprotected or {}, signed if carried is None else carried, signature]
    return cbor2.dumps(cbor2.CBORTag(18, body), canonical=True)


def manifest_parts() -> tuple[bytes, dict, bytes, bytes]:
    """Exact signed Agent Manifest COSE bytes, the same as the legacy fixture."""
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": SUB,
        "version": "0.2",
        "issuer": "spiffe://example.test/manifest-issuer",
        "issued_at": "2026-09-29T11:00:00Z",
        "expires_at": "2026-09-30T12:00:00Z",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {"version": "test-model", "deployment_type": "api"},
        },
    }
    raw = rfc8785.dumps(manifest)
    protected = cbor2.dumps(
        {
            1: -19,
            3: "application/agent-manifest+json",
            4: kid(ROGUE),
            16: "application/agent-manifest+cose",
        },
        canonical=True,
    )
    signature = ROGUE.sign(cbor2.dumps(["Signature1", protected, b"", raw], canonical=True))
    exact = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, raw, signature]), canonical=True)
    return exact, manifest, protected, signature


MANIFEST, MANIFEST_JSON, MANIFEST_PROTECTED, MANIFEST_SIGNATURE = manifest_parts()


def requirement(cid: str, typ: str, *, required: bool = True, age: int = 120, **extra) -> dict:
    value = {
        "component_id": cid,
        "component_type": typ,
        "required": required,
        "accepted_profiles": [EVIDENCE_PROFILE],
        "accepted_authorities": [ISS],
        "maximum_age_seconds": age,
        "expected_observed_digest": None,
    }
    value.update(extra)
    return value


def component(cid: str, typ: str, *, fresh: int = 120, observed: str = "d", **extra) -> dict:
    value = {
        "component_id": cid,
        "component_type": typ,
        "profile": EVIDENCE_PROFILE,
        "authority": ISS,
        "instance": "instance-1",
        "status": "affirming",
        "appraised_at": NOW,
        "fresh_until": NOW + fresh,
        "observed_digest": "sha256:" + observed * 64,
        "reasons": [],
        "evidence_refs": [
            {
                "profile": EVIDENCE_PROFILE,
                "media_type": "application/example-software-evidence+json",
                "digest": "sha256:" + "e" * 64,
                "resolver": None,
            }
        ],
    }
    value.update(extra)
    return value


def question(
    requirements: dict, *, purpose: str = "protected-action", audience: bool = True
) -> str:
    """The legacy fixture's verification question; opaque to the verifier."""
    # The legacy question hashed requirements without the explicit null pin.
    reqs = copy.deepcopy(requirements)
    for r in reqs["components"]:
        if r.get("expected_observed_digest") is None:
            r.pop("expected_observed_digest", None)
    value = {"purpose": purpose, "policy": POLICY, "requirements": reqs}
    if audience:
        value["audience"] = AUD
    return canonical_digest(value)


def binding_digest(source: dict, target: dict, method: str = "same-instance-v1") -> str:
    return canonical_digest(
        {"method": method, "source": source, "target": target}  # exactly as signed
    )


def derive(
    token: dict, requirements: dict, delegated: frozenset[str] = frozenset()
) -> tuple[str, int, list[str]]:
    """Independent composite derivation from the written combination rule.

    `delegated` names components whose appraisal the construction made valid,
    trusted and in grant; any other non-issuer authority is unverifiable.
    """
    comps = {c["component_id"]: c for c in token["components"]}
    ends = {b["source"] for b in requirements["bindings"]} | {
        b["target"] for b in requirements["bindings"]
    }
    required = sorted(
        {r["component_id"] for r in requirements["components"] if r["required"]} | ends
    )
    statuses: list[str] = []
    bounds = [token["exp"]]
    for r in requirements["components"]:
        c = comps.get(r["component_id"])
        if c is None:
            if r["component_id"] in required:
                statuses.append("missing")
            continue
        status = c["status"]
        if (
            c["profile"] not in r["accepted_profiles"]
            or c["authority"] not in r["accepted_authorities"]
            or (c["authority"] != token["iss"] and c["component_id"] not in delegated)
        ):
            status = "unverifiable"
        if r["component_id"] in required:
            bounds.append(c["fresh_until"])
            statuses.append(status)
    present = {
        (b["source"], b["target"], b["relationship"], b["method"]): b for b in token["bindings"]
    }
    for br in requirements["bindings"]:
        b = present.get((br["source"], br["target"], br["relationship"], br["method"]))
        if b is None or br["source"] not in comps or br["target"] not in comps:
            statuses.append("missing")
            continue
        bounds.append(b["fresh_until"])
        statuses.append(b["status"])
    overall = next(
        (
            s
            for s in ("contraindicated", "missing", "unverifiable", "not-appraised")
            if s in statuses
        ),
        "affirming",
    )
    if overall == "affirming" and "warning" in statuses:
        overall = "warning" if requirements["allow_warnings"] else "contraindicated"
    return overall, min(bounds), required


def rebind(token: dict) -> None:
    comps = {c["component_id"]: c for c in token["components"]}
    for b in token["bindings"]:
        if b["source"] in comps and b["target"] in comps:
            b["digest"] = binding_digest(comps[b["source"]], comps[b["target"]], b["method"])


def recompose(token: dict, requirements: dict, delegated: frozenset[str] = frozenset()) -> None:
    status, fresh, required = derive(token, requirements, delegated)
    token["composite_appraisal"].update(
        status=status, fresh_until=fresh, required_components=required
    )


# Tool-catalog observed digest, recomputed here from the pinned tools/list files
# under catalog/ (docs/rfcs/tool-catalog-observed-digest.md). The label is part of
# every per-tool preimage; it names the derivation that document defines and is
# carried literally. tests/test_tool_catalog_digest.py recomputes the same values
# from the same bytes without this code.
CATALOG = HERE / "catalog"
TOOL_LABEL = "trace.mcp-tool-definition.v1"
TOOL_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
TOOL_KEY_UNSAFE = re.compile(r"[^\x21-\x7e]|[%=]")


def tool_definition_digest(definition: dict) -> str:
    body = {f: definition[f] for f in TOOL_FIELDS if definition.get(f) is not None}
    return canonical_digest({"profile": TOOL_LABEL, "tool": body})


def tool_key(name: str) -> str:
    encoded = TOOL_KEY_UNSAFE.sub(
        lambda m: "".join(f"%{b:02X}" for b in m.group().encode("utf-8", "surrogatepass")), name
    )
    if len(encoded) > 128:
        tail = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        encoded = encoded[:96] + "~" + tail
    return "tool:" + encoded


def catalog_manifest_digest(filename: str) -> str:
    tools = json.loads((CATALOG / filename).read_text(encoding="utf-8"))["tools"]
    per_tool = {tool_key(str(t.get("name", "") or "unnamed")): tool_definition_digest(t) for t in tools}
    assert len(per_tool) == len(tools), "the pinned catalogs carry no duplicate names"
    lines = "\n".join(f"{key}={per_tool[key]}" for key in sorted(per_tool))
    return digest(lines.encode("utf-8"))


def base(variant: str = "pair") -> tuple[dict, dict]:
    if variant in ("mcp", "mcp-catalog"):
        pinned = (
            catalog_manifest_digest("deepwiki-tools-list.json")
            if variant == "mcp-catalog"
            else "sha256:" + "1" * 64
        )
        reqs = {
            "components": [
                requirement("mcp.server", "mcp-server"),
                requirement("tools.catalog", "tool-catalog", expected_observed_digest=pinned),
            ],
            "bindings": [],
            "allow_warnings": False,
        }
        comps = [
            component("mcp.server", "mcp-server", observed="2"),
            component("tools.catalog", "tool-catalog", observed="1", observed_digest=pinned),
        ]
    else:
        reqs = {
            "components": [
                requirement("runtime.cpu", "runtime"),
                requirement("runtime.accelerator.0", "accelerator"),
            ],
            "bindings": [
                {
                    "source": "runtime.cpu",
                    "target": "runtime.accelerator.0",
                    "relationship": "same-workload",
                    "method": "same-instance-v1",
                }
            ],
            "allow_warnings": False,
        }
        comps = [
            component("runtime.cpu", "runtime"),
            component("runtime.accelerator.0", "accelerator"),
        ]
        if variant == "single":
            reqs["components"].pop()
            reqs["bindings"] = []
            comps.pop()
    bindings = [
        dict(br, status="affirming", fresh_until=NOW + 120, digest="") for br in reqs["bindings"]
    ]
    token = {
        "profile": PROFILE,
        "iss": ISS,
        "sub": SUB,
        "instance": "instance-1",
        "iat": NOW,
        "exp": NOW + 120,
        "jti": "test-token-1",
        "aud": AUD,
        "cnf": {"kty": "OKP", "crv": "Ed25519", "x": b64url(public(HOLDER))},
        "manifest": {
            "id": MANIFEST_JSON["manifest_id"],
            "media_type": "application/agent-manifest+cose",
            "version": "0.2",
            "digest": digest(MANIFEST),
        },
        "verification_context_hash": question(reqs),
        "appraisal_policy": copy.deepcopy(POLICY),
        "components": comps,
        "bindings": bindings,
        "composite_appraisal": {
            "status": "affirming",
            "required_components": [],
            "policy": copy.deepcopy(POLICY),
            "fresh_until": NOW + 120,
        },
    }
    rebind(token)
    recompose(token, reqs)
    return token, reqs


def issuer_entry(
    key: Ed25519PrivateKey, issuer: str = ISS, start: int = NOW - 1, end: int = NOW + 300
) -> dict:
    return {
        "issuer": issuer,
        "public_b64url": b64url(public(key)),
        "valid_from": start,
        "valid_until": end,
    }


def appraisal(
    comp: dict,
    *,
    key: Ed25519PrivateKey = APPRAISER,
    iss: str = APPRAISER_ISS,
    headers: dict | None = None,
    flip_signature: bool = False,
    change: Callable[[dict], None] | None = None,
) -> str:
    """Delegated appraisal: {profile, iss, component minus appraisal}, unpadded base64url."""
    signed = copy.deepcopy(comp)
    signed.pop("appraisal", None)
    if change:
        change(signed)
    payload = {"profile": APPRAISAL_PROFILE, "iss": iss, "component": signed}
    return b64url(envelope(payload, key, headers=headers, flip_signature=flip_signature))


def appraiser_entry(
    key: Ed25519PrivateKey = APPRAISER,
    authority: str = APPRAISER_ISS,
    profiles: tuple[str, ...] = (EVIDENCE_PROFILE,),
    types: tuple[str, ...] = ("runtime",),
    start: int = NOW - 1,
    end: int = NOW + 300,
) -> dict:
    return {
        "authority": authority,
        "public_b64url": b64url(public(key)),
        "profiles": sorted(profiles),
        "component_types": sorted(types),
        "valid_from": start,
        "valid_until": end,
    }


def context(reqs: dict, question_digest: str | None = None) -> dict:
    return {
        "audience": AUD,
        "subject": SUB,
        "instance": "instance-1",
        "manifest_b64": b64(MANIFEST),
        "manifest_id": MANIFEST_JSON["manifest_id"],
        "manifest_valid_until": NOW + 300,
        "question_digest": question_digest or question(reqs),
        "policy": copy.deepcopy(POLICY),
        "requirements": copy.deepcopy(reqs),
        "trusted_issuers": [issuer_entry(ISSUER)],
        "status": "active",
        "maximum_lifetime": 300,
    }


def holder_proof(
    token_bytes: bytes,
    jti: str = "test-token-1",
    *,
    key: Ed25519PrivateKey = HOLDER,
    headers: dict | None = None,
    issued: int = NOW,
    expires: int = NOW + 30,
    change: dict | None = None,
    expect: dict | None = None,
) -> dict:
    payload = {
        "profile": PROOF_PROFILE,
        "nonce": NONCE,
        "token_digest": digest(token_bytes),
        "token_id": jti,
        "audience": AUD,
        "session_id": "session-1",
        "action_digest": ACTION_DIGEST,
        "issued_at": issued,
        "expires_at": expires,
    }
    payload.update(change or {})
    block = {
        "proof_b64": b64(envelope(payload, key, headers=headers)),
        "nonce": NONCE,
        "audience": AUD,
        "session_id": "session-1",
        "action_digest": ACTION_DIGEST,
        "challenge_issued_at": issued,
        "challenge_expires_at": expires,
    }
    block.update(expect or {})
    return block


VECTORS: list[dict] = []


def emit(
    vid: str,
    requirements: list[str],
    kind: str,
    description: str,
    *,
    token: dict | None = None,
    reqs: dict | None = None,
    ctx: dict | None = None,
    raw: bytes | None = None,
    now: int = NOW,
    token_code: str = "valid",
    composite: str | None = None,
    proof: dict | None = None,
    proof_code: str | None = None,
) -> None:
    if token is None or reqs is None:
        default_token, default_reqs = base()
        token = default_token if token is None else token
        reqs = default_reqs if reqs is None else reqs
    if ctx is None:
        ctx = context(reqs)
    if raw is None:
        raw = envelope(token, ISSUER)
    if token_code == "valid" and composite is None:
        composite = "affirming"
    assert kind in ("positive", "counterexample")
    VECTORS.append(
        {
            "id": vid,
            "requirements": requirements,
            "kind": kind,
            "description": description,
            "context": ctx,
            "now": now,
            "envelope_b64": b64(raw),
            "proof": proof,
            "expected": {
                "token": token_code,
                "composite_status": composite if token_code == "valid" else None,
                "proof": proof_code if proof is not None else None,
            },
        }
    )


def variant(
    change: Callable[[dict], None],
    *,
    kind: str = "pair",
    rebinding: bool = True,
    recomposing: bool = False,
    reqs_change: Callable[[dict], None] | None = None,
) -> tuple[dict, dict]:
    token, reqs = base(kind)
    if reqs_change:
        reqs_change(reqs)
    change(token)
    if rebinding:
        rebind(token)
    if recomposing:
        recompose(token, reqs)
    return token, reqs


def ctx_with(change: Callable[[dict], None], kind: str = "pair") -> dict:
    token, reqs = base(kind)
    value = context(reqs, token["verification_context_hash"])
    change(value)
    return value


def set_(path: list, value: Any) -> Callable[[dict], None]:
    def apply(obj: dict) -> None:
        for key in path[:-1]:
            obj = obj[key]
        obj[path[-1]] = value

    return apply


def drop(path: list) -> Callable[[dict], None]:
    def apply(obj: dict) -> None:
        for key in path[:-1]:
            obj = obj[key]
        del obj[path[-1]]

    return apply


def optional_model(fresh: int = 60, **extra) -> dict:
    return component("model.optional", "model", fresh=fresh, **extra)


def add_optional(reqs: dict) -> None:
    reqs["components"].append(requirement("model.optional", "model", required=False, age=60))


def build() -> None:
    B, R = base()
    good = envelope(B, ISSUER)
    hdr = headers_for(PROFILE, TOKEN_MEDIA, ISSUER)

    # TR-VT-PROFILE-001 / 002
    P1, P2 = ["TR-VT-PROFILE-001"], ["TR-VT-PROFILE-002"]
    emit(
        "VT-PROFILE-001",
        P1,
        "positive",
        "Exact supported profile in the protected trace-profile header and payload.",
    )
    h = dict(hdr)
    del h[HEADER]
    emit(
        "VT-PROFILE-002",
        P1,
        "counterexample",
        "Protected trace-profile header is absent while crit still names it.",
        raw=envelope(B, ISSUER, headers=h),
        token_code="protected_headers",
    )
    emit(
        "VT-PROFILE-003",
        P1,
        "counterexample",
        "A copy of the profile label also appears in the unprotected map; protected headers stay complete so the only defect is unprotected content.",
        raw=envelope(B, ISSUER, unprotected={HEADER: PROFILE}),
        token_code="envelope_structure",
    )
    emit(
        "VT-PROFILE-004",
        P1,
        "counterexample",
        "Protected trace-profile header names an unknown profile; payload and media type unchanged.",
        raw=envelope(B, ISSUER, headers=dict(hdr, **{HEADER: "urn:example:unknown-profile"})),
        token_code="protected_headers",
    )
    t = copy.deepcopy(B)
    t["profile"] = "tag:agentrust-io.com,2026:trace-v0.2"
    emit(
        "VT-PROFILE-005",
        P1,
        "counterexample",
        "A v0.2 profile payload carried inside a correctly headed verifier-token envelope.",
        raw=envelope(t, ISSUER, headers=hdr),
        token_code="malformed_payload",
    )
    emit("VT-PROFILE-006", P2, "positive", "Supported experimental-v1 profile is accepted.")
    t = copy.deepcopy(B)
    t["profile"] = "urn:agentrust:trace:verifier-token:experimental-v2"
    emit(
        "VT-PROFILE-007",
        P2,
        "counterexample",
        "Future experimental-v2 payload profile under a v1 protected header; never best-effort valid.",
        raw=envelope(t, ISSUER, headers=hdr),
        token_code="malformed_payload",
    )
    emit(
        "VT-PROFILE-008",
        P2,
        "counterexample",
        "Cross-profile routing: holder-proof profile and media type in the protected header of a verifier-token payload.",
        raw=envelope(B, ISSUER, headers=headers_for(PROOF_PROFILE, PROOF_MEDIA, ISSUER)),
        token_code="protected_headers",
    )

    # TR-VT-ENV-001
    E = ["TR-VT-ENV-001"]
    emit("VT-ENV-001", E, "positive", "Profile, content type, algorithm and key ID all protected.")
    emit(
        "VT-ENV-002",
        E,
        "counterexample",
        "Algorithm label duplicated into the unprotected map; the protected alg stays so the only defect is unprotected content.",
        raw=envelope(B, ISSUER, unprotected={1: -19}),
        token_code="envelope_structure",
    )
    emit(
        "VT-ENV-003",
        E,
        "counterexample",
        "Protected key ID altered to another key's SHA-256; trust is looked up by (iss, kid) so no trusted key exists for it.",
        raw=envelope(B, ISSUER, headers={**hdr, 4: kid(ROGUE)}),
        token_code="issuer_untrusted",
    )
    h = dict(hdr)
    del h[3]
    emit(
        "VT-ENV-004",
        E,
        "counterexample",
        "Protected content type header missing.",
        raw=envelope(B, ISSUER, headers=h),
        token_code="protected_headers",
    )
    emit(
        "VT-ENV-005",
        E,
        "counterexample",
        "Protected alg is the polymorphic EdDSA alias -8 instead of fully specified Ed25519 -19.",
        raw=envelope(B, ISSUER, headers={**hdr, 1: -8}),
        token_code="protected_headers",
    )
    emit(
        "VT-ENV-006",
        E,
        "counterexample",
        "One bit of the signature flipped.",
        raw=envelope(B, ISSUER, flip_signature=True),
        token_code="signature_invalid",
    )

    # TR-VT-ISS-001 / 002
    I1, I2 = ["TR-VT-ISS-001"], ["TR-VT-ISS-002"]
    emit("VT-ISS-001", I1, "positive", "Verifier key resolved from configured trust by (iss, kid).")
    t = copy.deepcopy(B)
    t["cnf"]["x"] = b64url(public(ROGUE))
    emit(
        "VT-ISS-002",
        I1,
        "counterexample",
        "Token signed by the key it embeds in cnf; token-supplied key material is not a trust anchor.",
        raw=envelope(t, ROGUE),
        token_code="issuer_untrusted",
    )
    emit(
        "VT-ISS-003",
        I1,
        "counterexample",
        "Token signed by an unknown key.",
        raw=envelope(B, ROGUE),
        token_code="issuer_untrusted",
    )
    emit(
        "VT-ISS-004",
        I1,
        "counterexample",
        "Signing key is trusted, but only for a different issuer name.",
        raw=envelope(B, ROGUE),
        ctx=ctx_with(
            lambda c: c["trusted_issuers"].append(
                issuer_entry(ROGUE, "https://other-verifier.example.test")
            )
        ),
        token_code="issuer_untrusted",
    )
    emit(
        "VT-ISS-009",
        I1,
        "counterexample",
        "Configured issuer entry is not yet valid at now (valid_from is now + 1).",
        ctx=ctx_with(
            lambda c: c["trusted_issuers"].__setitem__(0, issuer_entry(ISSUER, start=NOW + 1))
        ),
        token_code="issuer_expired",
    )
    emit("VT-ISS-005", I2, "positive", "iss names the configured authorized verifier.")
    t = copy.deepcopy(B)
    del t["iss"]
    emit(
        "VT-ISS-006",
        I2,
        "counterexample",
        "iss claim missing.",
        raw=envelope(t, ISSUER),
        token_code="malformed_payload",
    )
    for vid, iss, why in [
        (
            "VT-ISS-007",
            "https://other-verifier.example.test",
            "iss names a different verifier than the one the signing key is trusted for",
        ),
        (
            "VT-ISS-008",
            "https://Verifier.example.test",
            "iss is a case variant of the trusted issuer name",
        ),
    ]:
        t, _ = variant(set_(["iss"], iss), recomposing=True)
        emit(
            vid,
            I2,
            "counterexample",
            why.capitalize()
            + "; composite is recomputed so the issuer binding is the only defect.",
            raw=envelope(t, ISSUER),
            token_code="issuer_untrusted",
        )

    # TR-VT-CNF-001 / 002
    C1, C2 = ["TR-VT-CNF-001"], ["TR-VT-CNF-002"]
    emit(
        "VT-CNF-001",
        C1,
        "positive",
        "Distinct issuer and holder keys; holder proof valid.",
        proof=holder_proof(good),
        proof_code="valid",
    )
    t = copy.deepcopy(B)
    t["cnf"]["x"] = b64url(public(ROGUE))
    sub_raw = envelope(t, ISSUER)
    emit(
        "VT-CNF-002",
        C1,
        "counterexample",
        "Holder substituted: token binds another key, the presenter signs with the original holder key and names the bound key's kid, so only the signature fails.",
        token=t,
        raw=sub_raw,
        proof=holder_proof(
            sub_raw, key=HOLDER, headers=headers_for(PROOF_PROFILE, PROOF_MEDIA, ROGUE)
        ),
        proof_code="signature_invalid",
    )
    t = copy.deepcopy(B)
    t["cnf"]["x"] = b64url(public(ISSUER))
    emit(
        "VT-CNF-003",
        C1,
        "counterexample",
        "cnf reuses the verifier signing key.",
        raw=envelope(t, ISSUER),
        token_code="issuer_holder_same_key",
    )
    x = B["cnf"]["x"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    t = copy.deepcopy(B)
    t["cnf"]["x"] = x[:-1] + alphabet[alphabet.index(x[-1]) ^ 1]
    emit(
        "VT-CNF-009",
        C1,
        "counterexample",
        "cnf.x has nonzero base64url padding bits, so it is not the canonical encoding of a 32-byte key.",
        raw=envelope(t, ISSUER),
        token_code="holder_key_invalid",
    )
    emit(
        "VT-CNF-004",
        C2,
        "positive",
        "Valid one-use challenge proof by the cnf key.",
        proof=holder_proof(good),
        proof_code="valid",
    )
    emit(
        "VT-CNF-006",
        C2,
        "counterexample",
        "Proof signed by a different key while naming the holder kid; only the signature fails.",
        proof=holder_proof(
            good, key=ROGUE, headers=headers_for(PROOF_PROFILE, PROOF_MEDIA, HOLDER)
        ),
        proof_code="signature_invalid",
    )
    emit(
        "VT-CNF-010",
        C2,
        "counterexample",
        "Proof correctly signed by the holder key but its protected kid names another key.",
        proof=holder_proof(
            good, key=HOLDER, headers=headers_for(PROOF_PROFILE, PROOF_MEDIA, ROGUE)
        ),
        proof_code="key_id_mismatch",
    )
    t2 = copy.deepcopy(B)
    t2["jti"] = "test-token-2"
    raw2 = envelope(t2, ISSUER)
    emit(
        "VT-CNF-007",
        C2,
        "counterexample",
        "Proof made for another token (digest and jti) replayed with this valid token.",
        token=t2,
        raw=raw2,
        proof=holder_proof(good, "test-token-1"),
        proof_code="holder_proof_binding",
    )
    emit(
        "VT-CNF-008",
        C2,
        "counterexample",
        "Proof for session-1 replayed into session-2.",
        proof=holder_proof(good, expect={"session_id": "session-2"}),
        proof_code="holder_proof_binding",
    )
    emit(
        "VT-CNF-011",
        C2,
        "counterexample",
        "Proof presented exactly at the exclusive challenge expiry.",
        now=NOW + 30,
        proof=holder_proof(good),
        proof_code="holder_proof_expired",
    )
    emit(
        "VT-CNF-012",
        C2,
        "counterexample",
        "Challenge window outlives the token: proof expires_at is after token exp.",
        now=NOW + 100,
        proof=holder_proof(good, issued=NOW + 100, expires=NOW + 130),
        proof_code="holder_proof_expired",
    )

    # TR-VT-TIME-001 / 002 / 003
    T1, T2, T3 = ["TR-VT-TIME-001"], ["TR-VT-TIME-002"], ["TR-VT-TIME-003"]
    ORDER = (
        " The composite freshness boundary includes exp by definition, so component_expired "
        "restates the same defect; the signed [iat, exp) window check is the primary gate and "
        "must precede composite derivation."
    )
    emit("VT-TIME-001", T1, "positive", "now strictly inside [iat, exp).", now=NOW + 60)
    emit("VT-TIME-002", T1, "positive", "now exactly at iat (inclusive lower bound).", now=NOW)
    emit(
        "VT-TIME-003",
        T1,
        "counterexample",
        "now exactly at exp (exclusive upper bound)." + ORDER,
        now=NOW + 120,
        token_code="token_expired_or_future",
    )
    emit(
        "VT-TIME-004",
        T1,
        "counterexample",
        "iat is one second in the future.",
        now=NOW - 1,
        token_code="token_expired_or_future",
    )
    t = copy.deepcopy(B)
    t["iat"] = True
    emit(
        "VT-TIME-005",
        T1,
        "counterexample",
        "iat is a boolean, not an integer.",
        raw=envelope(t, ISSUER),
        token_code="malformed_payload",
    )
    t = copy.deepcopy(B)
    t["exp"] = str(NOW + 120)
    emit(
        "VT-TIME-011",
        T1,
        "counterexample",
        "exp is a decimal string, not an integer.",
        raw=envelope(t, ISSUER),
        token_code="malformed_payload",
    )
    emit(
        "VT-TIME-006",
        T2,
        "positive",
        "Local maximum lifetime equal to the signed lifetime, used one second before exp.",
        now=NOW + 119,
        ctx=ctx_with(set_(["maximum_lifetime"], 120)),
    )
    long_ctx = ctx_with(set_(["maximum_lifetime"], 86400))
    emit(
        "VT-TIME-007",
        T2,
        "counterexample",
        "Cached token used at exp although the local lifetime cap is one day." + ORDER,
        now=NOW + 120,
        ctx=long_ctx,
        token_code="token_expired_or_future",
    )
    emit(
        "VT-TIME-012",
        T2,
        "counterexample",
        "Cached token used 80 seconds after exp with a one-day local cap." + ORDER,
        now=NOW + 200,
        ctx=long_ctx,
        token_code="token_expired_or_future",
    )
    emit(
        "VT-TIME-015",
        T2,
        "counterexample",
        "Local cap shorter than the signed lifetime rejects rather than truncates.",
        ctx=ctx_with(set_(["maximum_lifetime"], 119)),
        token_code="token_lifetime",
    )
    emit("VT-TIME-008", T3, "positive", "exp equals the earliest required freshness boundary.")
    t = copy.deepcopy(B)
    t["exp"] = NOW + 121
    emit(
        "VT-TIME-009",
        T3,
        "counterexample",
        "exp one second after the earliest component boundary; composite fresh_until unchanged.",
        raw=envelope(t, ISSUER),
        token_code="expiry_exceeds_evidence",
    )

    def stale(tok: dict) -> None:
        tok["components"][0].update(appraised_at=NOW - 100, fresh_until=NOW + 20)
        tok["bindings"][0]["fresh_until"] = NOW + 20
        tok["composite_appraisal"]["fresh_until"] = NOW + 20

    t, _ = variant(stale)
    emit(
        "VT-TIME-010",
        T3,
        "counterexample",
        "Older component (fresh until now + 20) hidden behind a fresh iat and exp now + 120.",
        raw=envelope(t, ISSUER),
        token_code="expiry_exceeds_evidence",
    )
    emit(
        "VT-TIME-013",
        T3,
        "counterexample",
        "exp is one second after the manifest validity.",
        ctx=ctx_with(set_(["manifest_valid_until"], NOW + 119)),
        token_code="expiry_exceeds_credential",
    )
    emit(
        "VT-TIME-014",
        T3,
        "counterexample",
        "exp is one second after the configured issuer credential validity.",
        ctx=ctx_with(
            lambda c: c["trusted_issuers"].__setitem__(0, issuer_entry(ISSUER, end=NOW + 119))
        ),
        token_code="expiry_exceeds_credential",
    )

    # Simple claim families: (id, reqs, desc, mutate, code)
    simple = [
        ("VT-AUD-002", ["TR-VT-AUD-001"], "aud claim missing.", drop(["aud"]), "malformed_payload"),
        (
            "VT-AUD-003",
            ["TR-VT-AUD-001"],
            "aud names a different gateway.",
            set_(["aud"], "spiffe://example.test/gateway/two"),
            "audience_mismatch",
        ),
        (
            "VT-AUD-004",
            ["TR-VT-AUD-001"],
            "aud is a case variant of the relying party.",
            set_(["aud"], "spiffe://example.test/Gateway/one"),
            "audience_mismatch",
        ),
        (
            "VT-AUD-005",
            ["TR-VT-AUD-001"],
            "aud uses a wildcard; the profile has no wildcard syntax.",
            set_(["aud"], "spiffe://example.test/gateway/*"),
            "malformed_payload",
        ),
        ("VT-ID-002", ["TR-VT-ID-001"], "jti claim missing.", drop(["jti"]), "malformed_payload"),
        (
            "VT-ID-004",
            ["TR-VT-ID-001"],
            "jti is the empty string.",
            set_(["jti"], ""),
            "malformed_payload",
        ),
        (
            "VT-SUB-002",
            ["TR-VT-SUB-001"],
            "sub names another agent.",
            set_(["sub"], "spiffe://example.test/agent/two"),
            "subject_or_instance_mismatch",
        ),
        (
            "VT-SUB-003",
            ["TR-VT-SUB-001"],
            "sub is a case variant of the authenticated agent.",
            set_(["sub"], "spiffe://example.test/Agent/one"),
            "subject_or_instance_mismatch",
        ),
        (
            "VT-SUB-007",
            ["TR-VT-SUB-002"],
            "instance claim missing.",
            drop(["instance"]),
            "malformed_payload",
        ),
        (
            "VT-MAN-002",
            ["TR-VT-MAN-001"],
            "Manifest digest is of the exact bytes with the final byte changed.",
            set_(["manifest", "digest"], digest(MANIFEST[:-1] + bytes([MANIFEST[-1] ^ 1]))),
            "manifest_mismatch",
        ),
        (
            "VT-MAN-003",
            ["TR-VT-MAN-001"],
            "Manifest digest is of the decoded JCS payload, not the COSE envelope.",
            set_(["manifest", "digest"], digest(rfc8785.dumps(MANIFEST_JSON))),
            "manifest_mismatch",
        ),
        (
            "VT-MAN-004",
            ["TR-VT-MAN-001"],
            "Manifest media type is legacy JSON; this profile binds COSE manifests only.",
            set_(["manifest", "media_type"], "application/agent-manifest+json"),
            "malformed_payload",
        ),
        (
            "VT-MAN-011",
            ["TR-VT-MAN-001"],
            "Manifest ID differs from the verified manifest while the digest matches.",
            set_(["manifest", "id"], "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5d"),
            "manifest_mismatch",
        ),
        (
            "VT-CTX-002",
            ["TR-VT-CTX-001"],
            "Verification question with a different purpose.",
            set_(["verification_context_hash"], question(R, purpose="other-action")),
            "context_mismatch",
        ),
        (
            "VT-CTX-004",
            ["TR-VT-CTX-001"],
            "Verification question hashed without the audience.",
            set_(["verification_context_hash"], question(R, audience=False)),
            "context_mismatch",
        ),
        (
            "VT-POL-002",
            ["TR-VT-POL-001"],
            "appraisal_policy digest missing.",
            drop(["appraisal_policy", "digest"]),
            "malformed_payload",
        ),
        (
            "VT-POL-003",
            ["TR-VT-POL-001"],
            "Stale appraisal policy version and digest.",
            set_(
                ["appraisal_policy"],
                {"id": POLICY["id"], "version": "0", "digest": "sha256:" + "9" * 64},
            ),
            "policy_mismatch",
        ),
        (
            "VT-POL-004",
            ["TR-VT-POL-001"],
            "Policy ID and version current but digest disagrees.",
            set_(["appraisal_policy", "digest"], "sha256:" + "9" * 64),
            "policy_mismatch",
        ),
        (
            "VT-PRIV-002",
            ["TR-VT-PRIV-001"],
            "cnf carries the JWK private member d.",
            set_(["cnf", "d"], b64url(bytes(range(32, 64)))),
            "malformed_payload",
        ),
        (
            "VT-PRIV-003",
            ["TR-VT-PRIV-001"],
            "Token carries a raw prompt member.",
            set_(["prompt"], "You are a helpful agent with access to the ledger."),
            "malformed_payload",
        ),
        (
            "VT-EXT-003",
            ["TR-VT-EXT-001"],
            "Gateway decision member copied into the payload and re-signed by the issuer.",
            set_(["gateway_decision"], "allow"),
            "malformed_payload",
        ),
    ]
    for vid, reqs_, desc, change, code in simple:
        t = copy.deepcopy(B)
        change(t)
        emit(vid, reqs_, "counterexample", desc, raw=envelope(t, ISSUER), token_code=code)
    for vid, req in [
        ("VT-AUD-001", "TR-VT-AUD-001"),
        ("VT-ID-001", "TR-VT-ID-001"),
        ("VT-SUB-001", "TR-VT-SUB-001"),
        ("VT-SUB-005", "TR-VT-SUB-002"),
        ("VT-MAN-001", "TR-VT-MAN-001"),
        ("VT-MAN-005", "TR-VT-MAN-002"),
        ("VT-CTX-001", "TR-VT-CTX-001"),
        ("VT-POL-001", "TR-VT-POL-001"),
        ("VT-REV-001", "TR-VT-REV-001"),
        ("VT-PRIV-001", "TR-VT-PRIV-001"),
        ("VT-PRIV-005", "TR-VT-PRIV-002"),
        ("VT-EXT-001", "TR-VT-EXT-001"),
    ]:
        emit(
            vid,
            [req],
            "positive",
            "Base token satisfies "
            + req
            + " (exact claim, exact bytes, signed separately from any gateway field).",
        )

    def other_instance(tok: dict) -> None:
        tok["instance"] = "instance-2"
        for c in tok["components"]:
            c["instance"] = "instance-2"

    t, _ = variant(other_instance)
    emit(
        "VT-SUB-006",
        ["TR-VT-SUB-002"],
        "counterexample",
        "Correct subject, token and all components consistently on another instance.",
        raw=envelope(t, ISSUER),
        token_code="subject_or_instance_mismatch",
    )

    reencoded = (
        b"\xd2\x9f"
        + b"".join(
            cbor2.dumps(x, canonical=True)
            for x in [MANIFEST_PROTECTED, {}, rfc8785.dumps(MANIFEST_JSON), MANIFEST_SIGNATURE]
        )
        + b"\xff"
    )
    headered = cbor2.dumps(
        cbor2.CBORTag(
            18,
            [MANIFEST_PROTECTED, {"note": "x"}, rfc8785.dumps(MANIFEST_JSON), MANIFEST_SIGNATURE],
        ),
        canonical=True,
    )
    for vid, data, desc in [
        (
            "VT-MAN-006",
            reencoded,
            "Digest over a semantically equal indefinite-length re-encoding of the manifest COSE bytes.",
        ),
        (
            "VT-MAN-008",
            headered,
            "Digest over the manifest envelope with an added unprotected header.",
        ),
    ]:
        t = copy.deepcopy(B)
        t["manifest"]["digest"] = digest(data)
        emit(
            vid,
            ["TR-VT-MAN-002"],
            "counterexample",
            desc + " The only construction is sha256 of the exact COSE bytes.",
            raw=envelope(t, ISSUER),
            token_code="manifest_mismatch",
        )
    changed = copy.deepcopy(R)
    changed["components"][0]["accepted_profiles"] = ["urn:example:other-evidence:v1"]
    t = copy.deepcopy(B)
    t["verification_context_hash"] = question(changed)
    emit(
        "VT-CTX-003",
        ["TR-VT-CTX-001"],
        "counterexample",
        "Verification question hashed with a different required evidence profile.",
        raw=envelope(t, ISSUER),
        token_code="context_mismatch",
    )

    REV = ["TR-VT-REV-001"]
    emit(
        "VT-REV-002",
        REV,
        "counterexample",
        "Status check reports the token or its issuer revoked.",
        ctx=ctx_with(set_(["status"], "inactive")),
        token_code="status_not_active",
    )
    emit(
        "VT-REV-003",
        REV,
        "counterexample",
        "Status service unavailable; fail closed.",
        ctx=ctx_with(set_(["status"], "unavailable")),
        token_code="status_unavailable",
    )
    emit(
        "VT-REV-004",
        REV,
        "counterexample",
        "Verifier key revoked: configured trust now holds only a replacement key for the same issuer.",
        ctx=ctx_with(set_(["trusted_issuers"], [issuer_entry(ROGUE)])),
        token_code="issuer_untrusted",
    )

    t, _ = variant(
        lambda tok: tok["components"][0]["evidence_refs"][0].update(
            private_key=b64url(bytes(range(32)))
        ),
        rebinding=False,
    )
    emit(
        "VT-PRIV-004",
        ["TR-VT-PRIV-001"],
        "counterexample",
        "Evidence reference carries a private key member.",
        raw=envelope(t, ISSUER),
        token_code="malformed_payload",
    )
    t, _ = variant(
        lambda tok: tok["components"][0]["evidence_refs"][0].update(digest="sha256:" + "7" * 64),
        rebinding=False,
    )
    emit(
        "VT-PRIV-006",
        ["TR-VT-PRIV-002"],
        "counterexample",
        "Evidence digest swapped after the binding digest committed the original reference.",
        raw=envelope(t, ISSUER),
        token_code="binding_digest_mismatch",
    )
    t, _ = variant(lambda tok: tok["components"][0]["evidence_refs"][0].pop("digest"))
    emit(
        "VT-PRIV-007",
        ["TR-VT-PRIV-002"],
        "counterexample",
        "Evidence reference without a digest although evidence was held at issue.",
        raw=envelope(t, ISSUER),
        token_code="malformed_payload",
    )

    X = ["TR-VT-EXT-001"]
    emit(
        "VT-EXT-002",
        X,
        "counterexample",
        "Gateway decision appended in the unprotected header after signing.",
        raw=envelope(B, ISSUER, unprotected={"gateway_decision": "allow"}),
        token_code="envelope_structure",
    )
    t = copy.deepcopy(B)
    t["jti"] = "test-token-appended"
    emit(
        "VT-EXT-004",
        X,
        "counterexample",
        "In-schema claim value altered after the verifier signed the original payload.",
        raw=envelope(B, ISSUER, carried=rfc8785.dumps(t)),
        token_code="signature_invalid",
    )

    # RFC-0002
    def comp_vector(
        vid,
        reqs_,
        kind,
        desc,
        change=lambda tok: None,
        *,
        rebinding=True,
        recomposing=False,
        reqs_change=None,
        variant_kind="pair",
        code="valid",
        composite=None,
        ctx=None,
    ):
        tok, rq = variant(
            change,
            kind=variant_kind,
            rebinding=rebinding,
            recomposing=recomposing,
            reqs_change=reqs_change,
        )
        emit(
            vid,
            reqs_,
            kind,
            desc,
            token=tok,
            reqs=rq,
            ctx=ctx if ctx is not None else _ctx(rq, tok),
            token_code=code,
            composite=composite,
        )

    def _ctx(rq, tok):
        return context(rq, tok["verification_context_hash"])

    ID1, ID2 = ["TR-COMP-ID-001"], ["TR-COMP-ID-002"]
    comp_vector("COMP-ID-001", ID1, "positive", "Unique non-empty component IDs.")
    comp_vector(
        "COMP-ID-002",
        ID1,
        "counterexample",
        "Byte-identical duplicate component entry.",
        lambda tok: tok["components"].append(copy.deepcopy(tok["components"][0])),
        code="duplicate_component",
    )
    comp_vector(
        "COMP-ID-003",
        ID1,
        "counterexample",
        "Case-variant twin Runtime.cpu added beside runtime.cpu; IDs are exact bytes so it is a distinct, undeclared component.",
        lambda tok: tok["components"].append(
            dict(copy.deepcopy(tok["components"][0]), component_id="Runtime.cpu")
        ),
        code="undeclared_component",
    )
    comp_vector(
        "COMP-ID-004",
        ID1,
        "counterexample",
        "Empty component_id.",
        lambda tok: tok["components"][0].update(component_id=""),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-ID-005",
        ID1,
        "counterexample",
        "Unicode-confusable ID (Cyrillic es) outside the ASCII identifier grammar.",
        lambda tok: tok["components"][0].update(component_id="runtime.сpu"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-ID-006", ID2, "positive", "Exact-case lookup of runtime.cpu.", variant_kind="single"
    )
    comp_vector(
        "COMP-ID-007",
        ID2,
        "counterexample",
        "Token reports Runtime.cpu for required runtime.cpu; composite honestly missing so the only defect is the undeclared ID a case-folding verifier would accept.",
        lambda tok: tok["components"][0].update(component_id="Runtime.cpu"),
        variant_kind="single",
        recomposing=True,
        code="undeclared_component",
    )
    comp_vector(
        "COMP-ID-008",
        ID2,
        "counterexample",
        "Token reports runtime.cpu.primary, inferring a match from the runtime.cpu prefix; composite honestly missing.",
        lambda tok: tok["components"][0].update(component_id="runtime.cpu.primary"),
        variant_kind="single",
        recomposing=True,
        code="undeclared_component",
    )

    TY = ["TR-COMP-TYPE-001"]
    comp_vector(
        "COMP-TYPE-001", TY, "positive", "Registered core categories runtime and accelerator."
    )
    comp_vector(
        "COMP-TYPE-002",
        TY,
        "counterexample",
        "Unknown category tpm on a required component.",
        lambda tok: tok["components"][0].update(component_type="tpm"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-TYPE-003",
        TY,
        "counterexample",
        "Unknown category on an optional component; the experimental category set is closed.",
        lambda tok: tok["components"].append(optional_model(component_type="tokenizer")),
        reqs_change=add_optional,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-TYPE-004",
        TY,
        "counterexample",
        "Registered category model where the requirement declares runtime.",
        lambda tok: tok["components"][0].update(component_type="model"),
        code="component_type_mismatch",
    )

    RQ1, RQ2 = ["TR-COMP-REQ-001"], ["TR-COMP-REQ-002"]
    comp_vector("COMP-REQ-001", RQ1, "positive", "All required components and the binding present.")

    def omit_accel(tok):
        tok["components"].pop()
        tok["bindings"] = []

    comp_vector(
        "COMP-REQ-002",
        RQ1,
        "counterexample",
        "Required accelerator and its binding absent; honest composite reports missing.",
        omit_accel,
        recomposing=True,
        composite="missing",
    )
    comp_vector(
        "COMP-REQ-003",
        RQ1,
        "counterexample",
        "Relying-party requirements add required model.primary that the token ignores while claiming affirming.",
        ctx=ctx_with(
            lambda c: c["requirements"]["components"].append(requirement("model.primary", "model"))
        ),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-REQ-004",
        RQ1,
        "counterexample",
        "Composite silently drops runtime.accelerator.0 from required_components.",
        lambda tok: tok["composite_appraisal"].update(required_components=["runtime.cpu"]),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-REQ-005",
        RQ2,
        "positive",
        "Declared optional model.optional absent; composite affirming.",
        reqs_change=add_optional,
    )
    comp_vector(
        "COMP-REQ-006",
        RQ2,
        "counterexample",
        "Optional absence elevated to an overall missing status.",
        lambda tok: tok["composite_appraisal"].update(status="missing"),
        reqs_change=add_optional,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-REQ-007",
        RQ2,
        "counterexample",
        "Absent optional component listed in required_components.",
        lambda tok: tok["composite_appraisal"].update(
            required_components=["model.optional", "runtime.accelerator.0", "runtime.cpu"]
        ),
        reqs_change=add_optional,
        code="composite_inconsistent",
    )

    def optional_bad(tok):
        tok["components"].append(optional_model(status="contraindicated"))
        tok["composite_appraisal"]["status"] = "contraindicated"

    comp_vector(
        "COMP-REQ-008",
        RQ2,
        "counterexample",
        "A contraindicated optional component elevates the overall status.",
        optional_bad,
        reqs_change=add_optional,
        code="composite_inconsistent",
    )

    S1, S2 = ["TR-COMP-STAT-001"], ["TR-COMP-STAT-002"]
    for status in [
        "affirming",
        "warning",
        "contraindicated",
        "unverifiable",
        "missing",
        "not-appraised",
    ]:
        comp_vector(
            "COMP-STAT-001-" + status,
            S1,
            "positive",
            "Required accelerator reports "
            + status
            + "; composite reports exactly "
            + status
            + ".",
            lambda tok, s=status: tok["components"][1].update(status=s),
            recomposing=True,
            reqs_change=(lambda rq: rq.update(allow_warnings=True))
            if status == "warning"
            else None,
            composite=status,
        )
    comp_vector(
        "COMP-STAT-002",
        S1,
        "counterexample",
        "Status outside the six-value enum.",
        lambda tok: tok["components"][1].update(status="unknown"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-STAT-003",
        S1,
        "counterexample",
        "Required component missing but composite claims affirming.",
        lambda tok: tok["components"][1].update(status="missing"),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-STAT-004",
        S1,
        "counterexample",
        "Required component unverifiable but composite claims contraindicated.",
        lambda tok: (
            tok["components"][1].update(status="unverifiable"),
            tok["composite_appraisal"].update(status="contraindicated"),
        ),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-STAT-005",
        S2,
        "positive",
        "Optional component not-appraised with no evidence; composite affirming.",
        lambda tok: tok["components"].append(
            optional_model(status="not-appraised", evidence_refs=[])
        ),
        reqs_change=add_optional,
    )
    comp_vector(
        "COMP-STAT-006",
        S2,
        "counterexample",
        "Required unverifiable component inflated to affirming.",
        lambda tok: tok["components"][1].update(status="unverifiable"),
        code="composite_inconsistent",
    )

    def drop_required(tok):
        tok["components"].pop()

    comp_vector(
        "COMP-STAT-007",
        S2,
        "counterexample",
        "Required accelerator absent (binding kept) while composite claims affirming.",
        drop_required,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-STAT-008",
        S2,
        "counterexample",
        "Required unverifiable component, honest composite is unverifiable, never affirming.",
        lambda tok: tok["components"][1].update(status="unverifiable"),
        recomposing=True,
        composite="unverifiable",
    )
    comp_vector(
        "COMP-STAT-009",
        S2,
        "counterexample",
        "Component self-reports affirming from an unaccepted authority; the verifier demotes it to unverifiable, so affirming is inconsistent.",
        lambda tok: tok["components"][1].update(authority="https://untrusted.example"),
        code="composite_inconsistent",
    )

    W = ["TR-COMP-WARN-001"]
    warn = lambda tok: tok["components"][0].update(status="warning")
    comp_vector(
        "COMP-WARN-001",
        W,
        "positive",
        "Combination policy allows warnings; composite warning.",
        warn,
        recomposing=True,
        reqs_change=lambda rq: rq.update(allow_warnings=True),
        composite="warning",
    )
    comp_vector(
        "COMP-WARN-002",
        W,
        "counterexample",
        "Warnings forbidden but composite reports warning.",
        lambda tok: (warn(tok), tok["composite_appraisal"].update(status="warning")),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-WARN-003",
        W,
        "counterexample",
        "Warnings forbidden; honest composite is contraindicated.",
        warn,
        recomposing=True,
        composite="contraindicated",
    )
    comp_vector(
        "COMP-WARN-004",
        W,
        "counterexample",
        "Warnings allowed, but a warning component is reported as plain affirming.",
        warn,
        reqs_change=lambda rq: rq.update(allow_warnings=True),
        code="composite_inconsistent",
    )

    EV1, EV2 = ["TR-COMP-EVID-001"], ["TR-COMP-EVID-002"]
    comp_vector(
        "COMP-EVID-001",
        EV1,
        "positive",
        "Evidence reference with profile, media type, digest and a null resolver hint.",
    )
    comp_vector(
        "COMP-EVID-002",
        EV1,
        "counterexample",
        "Evidence reference media_type missing.",
        lambda tok: tok["components"][0]["evidence_refs"][0].pop("media_type"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-EVID-003",
        EV1,
        "positive",
        "Resolver member omitted: accepted because this experimental profile makes resolver optional (the requirements as first written expected rejection; recorded divergence). The binding digest preimage is the component as signed, without the member.",
        lambda tok: tok["components"][0]["evidence_refs"][0].pop("resolver"),
    )
    comp_vector(
        "COMP-EVID-004",
        EV1,
        "counterexample",
        "Evidence digest is not a sha256 digest.",
        lambda tok: tok["components"][0]["evidence_refs"][0].update(digest="sha1:" + "e" * 40),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-EVID-009",
        EV1,
        "counterexample",
        "Evidence reference profile differs from its component profile.",
        lambda tok: tok["components"][0]["evidence_refs"][0].update(
            profile="urn:example:other-evidence:v1"
        ),
        code="evidence_profile_mismatch",
    )
    comp_vector(
        "COMP-EVID-005",
        EV2,
        "positive",
        "Affirming component carries digest-bound evidence references.",
    )
    comp_vector(
        "COMP-EVID-006",
        EV2,
        "counterexample",
        "Affirming component with no evidence reference at all.",
        lambda tok: tok["components"][0].update(evidence_refs=[]),
        code="evidence_missing",
    )
    self_asserted = lambda tok: (
        tok["components"][0].update(profile="urn:example:self-asserted:v1"),
        tok["components"][0]["evidence_refs"][0].update(profile="urn:example:self-asserted:v1"),
    )
    comp_vector(
        "COMP-EVID-007",
        EV2,
        "counterexample",
        "Self-asserted evidence profile not accepted by requirements, yet composite claims affirming.",
        self_asserted,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-EVID-010",
        EV2,
        "counterexample",
        "Self-asserted evidence profile; honest composite is unverifiable.",
        self_asserted,
        recomposing=True,
        composite="unverifiable",
    )

    AU = ["TR-COMP-AUTH-001"]
    comp_vector(
        "COMP-AUTH-001",
        AU,
        "positive",
        "Component authority is the token issuer and accepted for the profile.",
    )
    comp_vector(
        "COMP-AUTH-002",
        AU,
        "counterexample",
        "Unknown component authority while composite claims affirming.",
        lambda tok: tok["components"][0].update(authority="https://untrusted.example"),
        code="composite_inconsistent",
    )
    other_profile = lambda tok: (
        tok["components"][0].update(profile="urn:example:other-evidence:v1"),
        tok["components"][0]["evidence_refs"][0].update(profile="urn:example:other-evidence:v1"),
    )
    comp_vector(
        "COMP-AUTH-003",
        AU,
        "counterexample",
        "Trusted authority appraising a profile it is not accepted for, composite affirming.",
        other_profile,
        code="composite_inconsistent",
    )
    extra_authority = lambda rq: rq["components"][0]["accepted_authorities"].append(
        "https://other-appraiser.example.test"
    )
    other_appraiser = lambda tok: tok["components"][0].update(
        authority="https://other-appraiser.example.test"
    )
    comp_vector(
        "COMP-AUTH-004",
        AU,
        "counterexample",
        "Accepted appraiser differs from the token issuer; no delegation exists, yet composite affirming.",
        other_appraiser,
        reqs_change=extra_authority,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-AUTH-005",
        AU,
        "counterexample",
        "Accepted appraiser differs from the token issuer; honest composite unverifiable.",
        other_appraiser,
        reqs_change=extra_authority,
        recomposing=True,
        composite="unverifiable",
    )

    F1, F2 = ["TR-COMP-FRESH-001"], ["TR-COMP-FRESH-002"]
    comp_vector(
        "COMP-FRESH-001",
        F1,
        "positive",
        "Component carries appraised_at and fresh_until within the age bound.",
    )
    comp_vector(
        "COMP-FRESH-002",
        F1,
        "counterexample",
        "Component freshness one second beyond its maximum age.",
        lambda tok: tok["components"][0].update(fresh_until=NOW + 121),
        code="component_age_bound",
    )
    comp_vector(
        "COMP-FRESH-003",
        F1,
        "counterexample",
        "Component appraised one second after token iat.",
        lambda tok: tok["components"][0].update(appraised_at=NOW + 1),
        code="component_interval",
    )
    comp_vector(
        "COMP-FRESH-004",
        F1,
        "counterexample",
        "Required component without fresh_until.",
        lambda tok: tok["components"][0].pop("fresh_until"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-FRESH-005",
        F2,
        "positive",
        "Composite fresh_until equals the earliest required boundary.",
    )
    comp_vector(
        "COMP-FRESH-006",
        F2,
        "counterexample",
        "Composite fresh_until one second later than the earliest required boundary.",
        lambda tok: tok["composite_appraisal"].update(fresh_until=NOW + 121),
        code="composite_inconsistent",
    )
    early_optional = lambda tok: tok["components"].append(optional_model(fresh=30))
    comp_vector(
        "COMP-FRESH-007",
        F2,
        "counterexample",
        "Earlier optional component wrongly bounds composite freshness.",
        lambda tok: (early_optional(tok), tok["composite_appraisal"].update(fresh_until=NOW + 30)),
        reqs_change=add_optional,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-FRESH-008",
        F2,
        "positive",
        "Earlier optional component does not bound composite freshness.",
        early_optional,
        reqs_change=add_optional,
    )
    short_exp = lambda tok: tok.update(exp=NOW + 60)
    comp_vector(
        "COMP-FRESH-009",
        F2,
        "positive",
        "Token exp earlier than every evidence boundary: composite fresh_until is exp.",
        lambda tok: (short_exp(tok), tok["composite_appraisal"].update(fresh_until=NOW + 60)),
    )
    comp_vector(
        "COMP-FRESH-010",
        F2,
        "counterexample",
        "Token exp earlier than every evidence boundary, composite fresh_until left at the evidence boundary.",
        short_exp,
        code="composite_inconsistent",
    )

    def missing_and_unverifiable(tok: dict) -> None:
        tok["components"] = [c for c in tok["components"] if c["component_id"] != "runtime.cpu"]
        other = tok["components"][0]
        other["profile"] = "urn:example:unaccepted-evidence:v1"
        for ref in other["evidence_refs"]:
            ref["profile"] = other["profile"]

    comp_vector(
        "COMP-COMP-008",
        ["TR-COMP-COMP-002"],
        "positive",
        "One required component missing and another unverifiable: the composite is missing, which outranks unverifiable.",
        missing_and_unverifiable,
        recomposing=True,
        code="valid",
        composite="missing",
    )
    comp_vector(
        "COMP-COMP-009",
        ["TR-COMP-COMP-002"],
        "counterexample",
        "One required component missing and another unverifiable, composite asserted as unverifiable.",
        lambda tok: (
            missing_and_unverifiable(tok),
            tok["composite_appraisal"].update(status="unverifiable"),
        ),
        recomposing=False,
        code="composite_inconsistent",
    )

    BD1, BD2, BD3, BD4 = (
        ["TR-COMP-BIND-001"],
        ["TR-COMP-BIND-002"],
        ["TR-COMP-BIND-003"],
        ["TR-COMP-BIND-004"],
    )
    comp_vector("COMP-BIND-001", BD1, "positive", "Binding names two present, declared components.")
    both_optional = lambda rq: [r.update(required=False) for r in rq["components"]]
    comp_vector(
        "COMP-BIND-002",
        BD1,
        "counterexample",
        "Binding source component absent; endpoints are otherwise optional, composite claims affirming.",
        lambda tok: tok["components"].pop(0),
        reqs_change=both_optional,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-BIND-003",
        BD1,
        "counterexample",
        "Binding target component absent; endpoints are otherwise optional, composite claims affirming.",
        lambda tok: tok["components"].pop(1),
        reqs_change=both_optional,
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-BIND-004",
        BD1,
        "counterexample",
        "Binding source is the case variant Runtime.cpu; composite honestly missing, so the undeclared binding is the only defect.",
        lambda tok: tok["bindings"][0].update(source="Runtime.cpu"),
        recomposing=True,
        code="undeclared_binding",
    )
    comp_vector(
        "COMP-BIND-005", BD2, "positive", "same-instance-v1 method with a recomputable digest."
    )
    comp_vector(
        "COMP-BIND-006",
        BD2,
        "counterexample",
        "Unregistered method same-instance-v2.",
        lambda tok: tok["bindings"][0].update(method="same-instance-v2"),
        rebinding=False,
        code="malformed_payload",
    )
    comp_vector(
        "COMP-BIND-007",
        BD2,
        "counterexample",
        "Binding digest does not recompute.",
        lambda tok: tok["bindings"][0].update(digest="sha256:" + "0" * 64),
        rebinding=False,
        code="binding_digest_mismatch",
    )
    comp_vector(
        "COMP-BIND-008",
        BD2,
        "counterexample",
        "Binding result unverifiable while composite claims affirming.",
        lambda tok: tok["bindings"][0].update(status="unverifiable"),
        code="composite_inconsistent",
    )
    comp_vector("COMP-BIND-009", BD3, "positive", "Relationship verified by recomputation.")

    def swapped(tok):
        c = {x["component_id"]: x for x in tok["components"]}
        tok["bindings"][0]["digest"] = binding_digest(c["runtime.accelerator.0"], c["runtime.cpu"])

    comp_vector(
        "COMP-BIND-010",
        BD3,
        "counterexample",
        "Asserted relationship digest computed with source and target swapped.",
        swapped,
        rebinding=False,
        code="binding_digest_mismatch",
    )
    comp_vector(
        "COMP-BIND-013",
        BD3,
        "counterexample",
        "Asserted relationship fresher than its endpoints.",
        lambda tok: tok["bindings"][0].update(fresh_until=NOW + 121),
        code="binding_interval",
    )
    comp_vector("COMP-BIND-011", BD4, "positive", "Both endpoints on the token instance.")
    comp_vector(
        "COMP-BIND-012",
        BD4,
        "counterexample",
        "Accelerator evidence from instance-2 with individually valid, rebound evidence.",
        lambda tok: tok["components"][1].update(instance="instance-2"),
        code="mixed_instance",
    )
    comp_vector(
        "COMP-BIND-014",
        BD4,
        "counterexample",
        "Both endpoints on instance-2 while the token names instance-1.",
        lambda tok: [c.update(instance="instance-2") for c in tok["components"]],
        code="mixed_instance",
    )

    CC1, CC2 = ["TR-COMP-COMP-001"], ["TR-COMP-COMP-002"]
    comp_vector(
        "COMP-COMP-001",
        CC1,
        "positive",
        "Composite lists required components and binds the policy.",
    )
    comp_vector(
        "COMP-COMP-002",
        CC1,
        "counterexample",
        "Composite required_components emptied.",
        lambda tok: tok["composite_appraisal"].update(required_components=[]),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-COMP-003",
        CC1,
        "counterexample",
        "Composite policy digest missing.",
        lambda tok: tok["composite_appraisal"]["policy"].pop("digest"),
        code="malformed_payload",
    )
    comp_vector(
        "COMP-COMP-004",
        CC1,
        "counterexample",
        "Composite policy version changed while appraisal_policy is current.",
        lambda tok: tok["composite_appraisal"]["policy"].update(version="0"),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-COMP-005",
        CC2,
        "positive",
        "Overall affirming consistent with components and binding.",
    )
    comp_vector(
        "COMP-COMP-006",
        CC2,
        "counterexample",
        "Overall affirming with a contraindicated required component.",
        lambda tok: tok["components"][0].update(status="contraindicated"),
        code="composite_inconsistent",
    )
    comp_vector(
        "COMP-COMP-007",
        CC2,
        "counterexample",
        "Overall affirming with the required binding removed.",
        lambda tok: tok.update(bindings=[]),
        code="composite_inconsistent",
    )

    M = ["TR-COMP-MCP-001"]
    comp_vector(
        "COMP-MCP-001",
        M,
        "positive",
        "Separate mcp-server and tool-catalog results, catalog pinned to its expected digest.",
        variant_kind="mcp",
    )
    comp_vector(
        "COMP-MCP-002",
        M,
        "counterexample",
        "Server valid, catalog observed digest altered from the pinned value.",
        lambda tok: tok["components"][1].update(observed_digest="sha256:" + "f" * 64),
        variant_kind="mcp",
        code="component_observation_mismatch",
    )
    untrusted_server = lambda tok: tok["components"][0].update(
        authority="https://untrusted.example"
    )
    comp_vector(
        "COMP-MCP-003",
        M,
        "counterexample",
        "Catalog valid, server appraisal from an untrusted authority; honest composite unverifiable.",
        untrusted_server,
        variant_kind="mcp",
        recomposing=True,
        composite="unverifiable",
    )
    comp_vector(
        "COMP-MCP-007",
        M,
        "counterexample",
        "Catalog valid, server untrusted, composite still claims affirming.",
        untrusted_server,
        variant_kind="mcp",
        code="composite_inconsistent",
    )

    # The catalog pin recomputed from pinned tools/list bytes (catalog/, #443).
    # The pin is the deepwiki catalog in all three; what the token presents differs.
    def present_catalog(filename):
        return lambda tok: tok["components"][1].update(
            observed_digest=catalog_manifest_digest(filename)
        )

    comp_vector(
        "COMP-MCP-004",
        M,
        "positive",
        "Catalog pinned to the digest recomputed from a served tools/list (catalog/deepwiki-tools-list.json); the token carries the same digest.",
        variant_kind="mcp-catalog",
    )
    comp_vector(
        "COMP-MCP-005",
        M,
        "counterexample",
        "Digest mismatch: the token carries the digest of catalog/deepwiki-tools-list-drifted.json, one description changed after appraisal, against the pin from the served catalog.",
        present_catalog("deepwiki-tools-list-drifted.json"),
        variant_kind="mcp-catalog",
        code="component_observation_mismatch",
    )
    comp_vector(
        "COMP-MCP-006",
        M,
        "counterexample",
        "Wrong subject: the token carries the digest of catalog/cloudflare-docs-tools-list.json, a catalog another server served, against the pin for the deepwiki catalog.",
        present_catalog("cloudflare-docs-tools-list.json"),
        variant_kind="mcp-catalog",
        code="component_observation_mismatch",
    )

    # RFC-0002 stage 4: authenticated appraiser delegation (TR-COMP-AUTH-001).
    def delegate(**kwargs):
        def apply(tok):
            cpu = tok["components"][0]
            cpu["authority"] = APPRAISER_ISS
            cpu["appraisal"] = appraisal(cpu, **kwargs)

        return apply

    def accept_appraiser(rq):
        rq["components"][0]["accepted_authorities"].append(APPRAISER_ISS)

    def auth_vector(
        vid,
        kind,
        desc,
        change,
        *,
        appraisers=None,
        code="valid",
        composite=None,
        recomposing=False,
        delegated=frozenset(),
    ):
        tok, rq = variant(change, reqs_change=accept_appraiser)
        if recomposing:
            recompose(tok, rq, delegated)
        ctx = _ctx(rq, tok)
        ctx["trusted_appraisers"] = [appraiser_entry()] if appraisers is None else appraisers
        emit(vid, AU, kind, desc, token=tok, reqs=rq, ctx=ctx, token_code=code, composite=composite)

    auth_vector(
        "COMP-AUTH-006",
        "positive",
        "runtime.cpu appraised by a configured delegated appraiser: the token issuer carries the appraiser's signed appraisal, the grant covers its profile and type, composite affirming.",
        delegate(),
        recomposing=True,
        delegated=frozenset({"runtime.cpu"}),
    )
    auth_vector(
        "COMP-AUTH-007",
        "counterexample",
        "Delegated appraisal with one signature bit flipped under the configured appraiser key.",
        delegate(flip_signature=True),
        code="component_appraisal_signature_invalid",
    )
    auth_vector(
        "COMP-AUTH-008",
        "counterexample",
        "Appraiser signed fresh_until now + 60; the issuer carries now + 120. Signed and carried components differ.",
        delegate(change=lambda signed: signed.update(fresh_until=NOW + 60)),
        code="component_appraisal_mismatch",
    )
    auth_vector(
        "COMP-AUTH-009",
        "counterexample",
        "Signed component matches, but the signed iss names another appraiser than the carried authority.",
        delegate(iss="https://other-appraiser.example.test"),
        code="component_appraisal_mismatch",
    )
    accelerator_only = [appraiser_entry(types=("accelerator",))]
    auth_vector(
        "COMP-AUTH-010",
        "counterexample",
        "Configured appraiser is granted only accelerator components; it appraised a runtime component and composite claims affirming.",
        delegate(),
        appraisers=accelerator_only,
        code="composite_inconsistent",
    )
    auth_vector(
        "COMP-AUTH-011",
        "counterexample",
        "Configured appraiser is granted only accelerator components; honest composite unverifiable.",
        delegate(),
        appraisers=accelerator_only,
        recomposing=True,
        composite="unverifiable",
    )
    auth_vector(
        "COMP-AUTH-012",
        "counterexample",
        "Configured appraiser entry is not yet valid at now (valid_from is now + 1); composite claims affirming.",
        delegate(),
        appraisers=[appraiser_entry(start=NOW + 1)],
        code="composite_inconsistent",
    )
    auth_vector(
        "COMP-AUTH-013",
        "counterexample",
        "Appraiser configured and accepted, but the component carries no appraisal; composite claims affirming.",
        lambda tok: tok["components"][0].update(authority=APPRAISER_ISS),
        code="composite_inconsistent",
    )
    auth_vector(
        "COMP-AUTH-014",
        "counterexample",
        "Appraisal signed by an unconfigured key under its own key ID for the appraiser's name; composite claims affirming.",
        delegate(key=ROGUE),
        code="composite_inconsistent",
    )
    auth_vector(
        "COMP-AUTH-015",
        "counterexample",
        "Configured appraiser granted only another evidence profile; composite claims affirming.",
        delegate(),
        appraisers=[appraiser_entry(profiles=("urn:example:other-evidence:v1",))],
        code="composite_inconsistent",
    )

    def issuer_appraisal(tok):
        cpu = tok["components"][0]
        cpu["appraisal"] = appraisal(cpu, iss=ISS)

    auth_vector(
        "COMP-AUTH-016",
        "counterexample",
        "Component appraised by the token issuer also carries an appraisal member.",
        issuer_appraisal,
        code="component_appraisal_unexpected",
    )
    auth_vector(
        "COMP-AUTH-017",
        "counterexample",
        "Appraisal envelope carries the verifier-token profile and media type in its protected header.",
        delegate(headers=headers_for(PROFILE, TOKEN_MEDIA, APPRAISER)),
        code="component_appraisal_malformed",
    )

    # RFC-0002 stage 4: same-evidence-v1 relationships (TR-COMP-BIND-002 / 003).
    def evidence_method(rq):
        rq["bindings"][0]["method"] = "same-evidence-v1"

    def evidence_binding(tok):
        tok["bindings"][0]["method"] = "same-evidence-v1"

    def evidence_vector(vid, reqs_, kind, desc, change=lambda tok: None, **kwargs):
        comp_vector(
            vid,
            reqs_,
            kind,
            desc,
            lambda tok: (evidence_binding(tok), change(tok)),
            reqs_change=evidence_method,
            **kwargs,
        )

    other_ref = {
        "profile": EVIDENCE_PROFILE,
        "media_type": "application/example-software-evidence+json",
        "digest": "sha256:" + "f" * 64,
        "resolver": None,
    }
    evidence_vector(
        "COMP-BIND-015",
        BD2,
        "positive",
        "same-evidence-v1 with a recomputable digest; both endpoints cite one evidence digest.",
    )
    evidence_vector(
        "COMP-BIND-016",
        BD3,
        "positive",
        "same-evidence-v1 where the accelerator cites two evidence objects, one of them the CPU's.",
        lambda tok: tok["components"][1]["evidence_refs"].insert(0, copy.deepcopy(other_ref)),
    )
    evidence_vector(
        "COMP-BIND-017",
        BD3,
        "counterexample",
        "same-evidence-v1 whose accelerator evidence is a different object than the CPU's.",
        lambda tok: tok["components"][1].update(evidence_refs=[copy.deepcopy(other_ref)]),
        code="binding_evidence_disjoint",
    )
    evidence_vector(
        "COMP-BIND-018",
        BD3,
        "counterexample",
        "same-evidence-v1 whose accelerator is not-appraised and cites no evidence; composite honest.",
        lambda tok: tok["components"][1].update(status="not-appraised", evidence_refs=[]),
        recomposing=True,
        code="binding_evidence_disjoint",
    )
    evidence_vector(
        "COMP-BIND-019",
        BD2,
        "counterexample",
        "same-evidence-v1 is required; the token carries only a same-instance-v1 binding and an honest missing composite.",
        lambda tok: tok["bindings"][0].update(method="same-instance-v1"),
        recomposing=True,
        code="undeclared_binding",
    )

    def instance_preimage(tok):
        c = {x["component_id"]: x for x in tok["components"]}
        tok["bindings"][0]["digest"] = binding_digest(
            c["runtime.cpu"], c["runtime.accelerator.0"], "same-instance-v1"
        )

    evidence_vector(
        "COMP-BIND-020",
        BD2,
        "counterexample",
        "same-evidence-v1 binding whose digest preimage names same-instance-v1.",
        instance_preimage,
        rebinding=False,
        code="binding_digest_mismatch",
    )

    legacy()


LEGACY_MAP = {
    "01-valid": ("TR-VT-PROFILE-001", "Legacy valid token."),
    "02-wrong-audience": ("TR-VT-AUD-001", "Legacy wrong audience."),
    "03-wrong-subject": ("TR-VT-SUB-001", "Legacy wrong subject."),
    "04-manifest-substitution": ("TR-VT-MAN-001", "Legacy manifest digest substitution."),
    "05-component-omitted": (
        "TR-COMP-REQ-001",
        "Legacy required component omitted while composite claims affirming.",
    ),
    "06-failed-as-affirming": (
        "TR-COMP-STAT-002",
        "Legacy status change without rebinding: binding digest checks run during composite derivation, before the composite comparison.",
    ),
    "07-mixed-instance": (
        "TR-COMP-BIND-004",
        "Legacy instance change without rebinding: also breaks the binding digest; the reference reports component checks before binding checks.",
    ),
    "08-expiry-exceeds-evidence": ("TR-VT-TIME-003", "Legacy exp beyond evidence freshness."),
    "09-context-substitution": ("TR-VT-CTX-001", "Legacy verification context substitution."),
    "10-duplicate-component": ("TR-COMP-ID-001", "Legacy duplicate component."),
    "11-binding-substitution": ("TR-COMP-BIND-002", "Legacy binding digest substitution."),
    "12-signature-extension": ("TR-VT-EXT-001", "Legacy gateway field inside the signed payload."),
    "13-untrusted-self-signer": ("TR-VT-ISS-001", "Legacy untrusted signer."),
    "14-v02-as-verifier-token": (
        "TR-VT-PROFILE-001",
        "Legacy v0.2 profile in header and payload: the envelope header check precedes payload parsing.",
    ),
}


def legacy() -> None:
    token, reqs = base()
    for number, (stem, (req, desc)) in enumerate(sorted(LEGACY_MAP.items()), start=1):
        old = json.loads((LEGACY / (stem + ".json")).read_text())
        text = old["envelope_b64"]
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        code = old["expected"]
        emit(
            f"LEGACY-{number:02d}",
            [req],
            "positive" if code == "valid" else "counterexample",
            desc + " Exact bytes from examples/verifier-token-profile/" + stem + ".json.",
            token=token,
            reqs=reqs,
            ctx=context(reqs, token["verification_context_hash"]),
            raw=raw,
            token_code=code,
        )


def main() -> None:
    build()
    OUT.mkdir(exist_ok=True)
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate vector id"
    for existing in OUT.glob("*.json"):
        if existing.stem not in ids:
            raise SystemExit("stale vector file present: " + existing.name)
    for vector in VECTORS:
        text = json.dumps(vector, indent=1, ensure_ascii=True) + "\n"
        (OUT / (vector["id"] + ".json")).write_bytes(text.encode())
    print(len(VECTORS), "vectors")


if __name__ == "__main__":
    main()
