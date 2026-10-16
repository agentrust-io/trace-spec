"""Adversarial contract tests for the unreleased RFC-0001/0002 prototype."""

from __future__ import annotations
import base64
import copy
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

import cbor2
import jsonschema
import pytest
import rfc8785

from prototype import verifier_token as v

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples/verifier-token-profile"
SPEC = importlib.util.spec_from_file_location("independent_vectors", VECTORS / "gen_vectors.py")
assert SPEC is not None and SPEC.loader is not None
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.fixture
def fixture():
    return json.loads((VECTORS / "01-valid.json").read_text())


def context(f):
    token = f["token"]
    issuer = v.TrustedIssuer(token["iss"], g.ISSUER.public_key(), g.NOW - 1, g.NOW + 300)
    return v.VerificationContext(
        audience=token["aud"],
        subject=token["sub"],
        instance=token["instance"],
        manifest_bytes=unb64(f["manifest_b64"]),
        manifest_id=token["manifest"]["id"],
        manifest_valid_until=g.NOW + 300,
        question_digest=token["verification_context_hash"],
        policy=v.Policy.model_validate(token["appraisal_policy"]),
        requirements=v.Requirements.model_validate(f["requirements"]),
        trusted_issuers={(issuer.issuer, v.key_id(issuer.key)): issuer},
        status_check=lambda token, now: True,
    )


def rebind(token):
    """Independent fixture repair isolates semantic gates after signature verification."""
    for binding in token["bindings"]:
        components = {c["component_id"]: c for c in token["components"]}
        if binding["source"] in components and binding["target"] in components:
            binding["digest"] = g.canonical_digest(
                {
                    "method": binding["method"],
                    "source": components[binding["source"]],
                    "target": components[binding["target"]],
                }
            )


def expect_code(code, fn):
    with pytest.raises(v.ProfileError, match="^" + code + "$"):
        fn()


def test_independent_positive_signature_and_payload(fixture):
    raw = unb64(fixture["envelope_b64"])
    token = v.verify_token(raw, context(fixture), g.NOW)
    assert token.iss != token.sub
    assert v.public_bytes(g.ISSUER) != v.public_bytes(v.holder_public(token.cnf))
    assert v.sign_payload(token, g.ISSUER) == raw
    assert rfc8785.dumps(token.model_dump(mode="json")) == unb64(fixture["canonical_payload_b64"])


@pytest.mark.parametrize("path", sorted(VECTORS.glob("*.json")), ids=lambda p: p.stem)
def test_portable_vectors(path, fixture):
    f = json.loads(path.read_text())
    raw = unb64(f["envelope_b64"])
    if f["expected"] == "valid":
        v.verify_token(raw, context(fixture), g.NOW)
    else:
        expect_code(f["expected"], lambda: v.verify_token(raw, context(fixture), g.NOW))


@pytest.mark.parametrize(
    "now,valid", [(g.NOW, True), (g.NOW + 119, True), (g.NOW - 1, False), (g.NOW + 120, False)]
)
def test_exclusive_signed_time_boundaries(fixture, now, valid):
    if valid:
        v.verify_token(unb64(fixture["envelope_b64"]), context(fixture), now)
    else:
        expect_code(
            "token_expired_or_future",
            lambda: v.verify_token(unb64(fixture["envelope_b64"]), context(fixture), now),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("iat", True),
        ("exp", 1.0),
        ("aud", []),
        ("jti", ""),
        ("profile", v.PROOF_PROFILE),
        ("sub", ""),
        ("instance", ""),
    ],
)
def test_no_coercion_or_cross_profile(fixture, field, value):
    token = copy.deepcopy(fixture["token"])
    token[field] = value
    expected = "protected_headers" if field == "profile" else "malformed_payload"
    if isinstance(value, float):
        raw = g.envelope(token, g.ISSUER, raw=json.dumps(token).encode())
        expected = "noncanonical_payload"
    else:
        raw = g.envelope(token, g.ISSUER)
    expect_code(expected, lambda: v.verify_token(raw, context(fixture), g.NOW))


@pytest.mark.parametrize(
    "field",
    [
        "profile",
        "iss",
        "sub",
        "instance",
        "iat",
        "exp",
        "jti",
        "aud",
        "cnf",
        "manifest",
        "verification_context_hash",
        "appraisal_policy",
        "components",
        "bindings",
        "composite_appraisal",
    ],
)
def test_every_required_claim_is_required(fixture, field):
    token = copy.deepcopy(fixture["token"])
    del token[field]
    if field == "profile":
        headers = {
            1: -19,
            2: [v.PROFILE_HEADER],
            3: v.CONTENT_TYPE,
            4: v.key_id(g.ISSUER),
            v.PROFILE_HEADER: v.PROFILE,
        }
        raw = g.envelope(token, g.ISSUER, headers=headers)
    else:
        raw = g.envelope(token, g.ISSUER)
    expect_code("malformed_payload", lambda: v.verify_token(raw, context(fixture), g.NOW))


@pytest.mark.parametrize("status", ["contraindicated", "missing", "unverifiable", "not-appraised"])
def test_no_status_inflation_even_with_binding_repaired(fixture, status):
    token = copy.deepcopy(fixture["token"])
    token["components"][1]["status"] = status
    rebind(token)
    expect_code(
        "composite_inconsistent",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW),
    )
    token["composite_appraisal"]["status"] = status
    assert (
        v.verify_token(
            g.envelope(token, g.ISSUER), context(fixture), g.NOW
        ).composite_appraisal.status
        == status
    )


@pytest.mark.parametrize("allowed,expected", [(False, "contraindicated"), (True, "warning")])
def test_warning_policy_is_explicit(fixture, allowed, expected):
    token = copy.deepcopy(fixture["token"])
    token["components"][0]["status"] = "warning"
    token["composite_appraisal"]["status"] = expected
    rebind(token)
    ctx = context(fixture)
    ctx = replace(ctx, requirements=ctx.requirements.model_copy(update={"allow_warnings": allowed}))
    assert (
        v.verify_token(g.envelope(token, g.ISSUER), ctx, g.NOW).composite_appraisal.status
        == expected
    )


@pytest.mark.parametrize("which", [0, 1])
def test_required_component_position_does_not_matter(fixture, which):
    token = copy.deepcopy(fixture["token"])
    token["components"].pop(which)
    expect_code(
        "composite_inconsistent",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW),
    )


def test_optional_absence_is_not_required_failure(fixture):
    ctx = context(fixture)
    optional = v.Requirement(
        component_id="model.optional",
        component_type="model",
        required=False,
        accepted_profiles=["urn:example:optional"],
        accepted_authorities=[fixture["token"]["iss"]],
        maximum_age_seconds=60,
    )
    req = ctx.requirements.model_copy(
        update={"components": [*ctx.requirements.components, optional]}
    )
    assert v.verify_token(unb64(fixture["envelope_b64"]), replace(ctx, requirements=req), g.NOW)


@pytest.mark.parametrize("which", [0, 1])
def test_required_binding_makes_its_optional_endpoints_required(fixture, which):
    ctx = context(fixture)
    components = [r.model_copy(update={"required": False}) for r in ctx.requirements.components]
    req = ctx.requirements.model_copy(update={"components": components})
    token = copy.deepcopy(fixture["token"])
    token["components"].pop(which)
    expect_code(
        "composite_inconsistent",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), replace(ctx, requirements=req), g.NOW),
    )


@pytest.mark.parametrize(
    "change,code",
    [
        (lambda c: c.update(component_id="Runtime.cpu"), "undeclared_component"),
        (lambda c: c.update(component_type="model"), "component_type_mismatch"),
        (lambda c: c.update(appraised_at=g.NOW + 1), "component_interval"),
        (lambda c: c.update(fresh_until=g.NOW + 121), "component_age_bound"),
        (lambda c: c.update(evidence_refs=[]), "evidence_missing"),
        (lambda c: c["evidence_refs"][0].update(profile="wrong"), "evidence_profile_mismatch"),
    ],
)
def test_component_semantics_after_resigning(fixture, change, code):
    token = copy.deepcopy(fixture["token"])
    change(token["components"][0])
    rebind(token)
    expect_code(code, lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW))


@pytest.mark.parametrize(
    "field,value", [("authority", "https://untrusted.example"), ("profile", "urn:unknown:profile")]
)
def test_unknown_authority_or_profile_cannot_affirm(fixture, field, value):
    token = copy.deepcopy(fixture["token"])
    token["components"][0][field] = value
    if field == "profile":
        token["components"][0]["evidence_refs"][0]["profile"] = value
    rebind(token)
    expect_code(
        "composite_inconsistent",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW),
    )


def test_expiry_cannot_extend_manifest_or_issuer(fixture):
    ctx = context(fixture)
    expect_code(
        "expiry_exceeds_credential",
        lambda: v.verify_token(
            unb64(fixture["envelope_b64"]), replace(ctx, manifest_valid_until=g.NOW + 119), g.NOW
        ),
    )
    issuer = next(iter(ctx.trusted_issuers.values()))
    shorter = replace(issuer, valid_until=g.NOW + 119)
    expect_code(
        "expiry_exceeds_credential",
        lambda: v.verify_token(
            unb64(fixture["envelope_b64"]),
            replace(ctx, trusted_issuers={(issuer.issuer, v.key_id(issuer.key)): shorter}),
            g.NOW,
        ),
    )


@pytest.mark.parametrize("status", [False, None, "active"])
def test_status_fails_closed_without_exact_true(fixture, status):
    ctx = replace(context(fixture), status_check=lambda token, now: status)
    expect_code(
        "status_not_active", lambda: v.verify_token(unb64(fixture["envelope_b64"]), ctx, g.NOW)
    )


def test_status_outage_is_distinct(fixture):
    def unavailable(token, now):
        raise OSError("private endpoint")

    expect_code(
        "status_unavailable",
        lambda: v.verify_token(
            unb64(fixture["envelope_b64"]),
            replace(context(fixture), status_check=unavailable),
            g.NOW,
        ),
    )


def test_holder_is_not_issuer(fixture):
    token = copy.deepcopy(fixture["token"])
    token["cnf"]["x"] = g.b64(g.public(g.ISSUER))
    expect_code(
        "issuer_holder_same_key",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW),
    )


def proof(fixture, *, holder=None, change=None):
    payload = {
        "profile": v.PROOF_PROFILE,
        "nonce": g.b64(bytes(range(32))),
        "token_digest": v.digest(unb64(fixture["envelope_b64"])),
        "token_id": "test-token-1",
        "audience": fixture["token"]["aud"],
        "session_id": "session-1",
        "action_digest": g.canonical_digest({"tool": "read", "args": {"id": "1"}}),
        "issued_at": g.NOW,
        "expires_at": g.NOW + 30,
    }
    if change:
        payload.update(change)
    return payload, g.envelope(payload, holder or g.HOLDER)


def verify_holder(fixture, p):
    token_bytes = unb64(fixture["envelope_b64"])
    token = v.verify_token(token_bytes, context(fixture), g.NOW)
    return v.verify_proof(
        p,
        token_bytes,
        token,
        nonce=g.b64(bytes(range(32))),
        audience=token.aud,
        session_id="session-1",
        action_digest=g.canonical_digest({"tool": "read", "args": {"id": "1"}}),
        challenge_issued_at=g.NOW,
        challenge_expires_at=g.NOW + 30,
        now=g.NOW,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("nonce", g.b64(bytes(range(1, 33)))),
        ("token_id", "other"),
        ("audience", "other"),
        ("session_id", "other"),
        ("action_digest", "sha256:" + "0" * 64),
        ("token_digest", "sha256:" + "0" * 64),
    ],
)
def test_holder_proof_cross_context_replay(fixture, field, value):
    _, p = proof(fixture, change={field: value})
    expect_code("holder_proof_binding", lambda: verify_holder(fixture, p))


@pytest.mark.parametrize("key", [g.ISSUER, g.ROGUE])
def test_wrong_holder_key_even_with_valid_signature(fixture, key):
    _, p = proof(fixture, holder=key)
    expect_code("key_id_mismatch", lambda: verify_holder(fixture, p))


def test_one_use_challenge_and_policy_deny(fixture):
    rp = v.RelyingParty(context(fixture))
    body, signed = proof(fixture)
    rp.challenge(
        nonce=body["nonce"],
        session_id="session-1",
        action_digest=body["action_digest"],
        issued_at=g.NOW,
        expires_at=g.NOW + 30,
    )
    _, decision = rp.authorize(
        unb64(fixture["envelope_b64"]),
        signed,
        nonce=body["nonce"],
        action={"tool": "read", "args": {"id": "1"}},
        session_id="session-1",
        now=g.NOW,
        policy=lambda token, action: False,
    )
    assert decision is False
    expect_code(
        "challenge_missing_or_consumed",
        lambda: rp.authorize(
            unb64(fixture["envelope_b64"]),
            signed,
            nonce=body["nonce"],
            action={"tool": "read", "args": {"id": "1"}},
            session_id="session-1",
            now=g.NOW,
            policy=lambda token, action: True,
        ),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "tampered_sig",
        "trailing",
        "unprotected",
        "untagged",
        "alg_alias",
        "profile_unprotected",
        "float_label",
        "duplicate_payload",
    ],
)
def test_envelope_parser_boundaries(fixture, mutation):
    raw = unb64(fixture["envelope_b64"])
    tag = cbor2.loads(raw)
    body = list(tag.value)
    if mutation == "tampered_sig":
        body[3] = bytes([body[3][0] ^ 1]) + body[3][1:]
    elif mutation == "trailing":
        raw += b"\x00"
    elif mutation == "unprotected":
        body[1] = {"gateway": "allow"}
    elif mutation == "untagged":
        raw = cbor2.dumps(body, canonical=True)
    elif mutation == "duplicate_payload":
        dup = b'{"iat":1,"iat":2}'
        raw = g.envelope(fixture["token"], g.ISSUER, raw=dup)
    else:
        headers = dict(cbor2.loads(body[0]))
        if mutation == "alg_alias":
            headers[1] = -8
        elif mutation == "profile_unprotected":
            body[1] = {v.PROFILE_HEADER: headers.pop(v.PROFILE_HEADER)}
        elif mutation == "float_label":
            headers[1.0] = headers.pop(1)
        body[0] = cbor2.dumps(headers, canonical=True)
    if mutation not in ("trailing", "untagged", "duplicate_payload"):
        raw = cbor2.dumps(cbor2.CBORTag(18, body), canonical=True)
    with pytest.raises(v.ProfileError):
        v.verify_token(raw, context(fixture), g.NOW)


def test_private_key_or_unknown_fields_rejected(fixture):
    token = copy.deepcopy(fixture["token"])
    token["cnf"]["d"] = "secret"
    expect_code(
        "malformed_payload",
        lambda: v.verify_token(g.envelope(token, g.ISSUER), context(fixture), g.NOW),
    )


def test_schema_contracts_reproduce_models(fixture):
    for name, model in [
        ("token", v.Token),
        ("requirements", v.Requirements),
        ("holder-proof", v.Proof),
        ("decision-receipt", v.Receipt),
    ]:
        schema = json.loads(
            (ROOT / "schema" / ("trace-" + name + "-experimental-v1.json")).read_text()
        )
        assert schema == model.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(schema)
        if name in ("token", "requirements"):
            value = fixture["token"] if name == "token" else fixture["requirements"]
            jsonschema.Draft202012Validator(schema).validate(value)


def test_consumed_nonce_cannot_be_registered_again(fixture):
    rp = v.RelyingParty(context(fixture))
    body, signed = proof(fixture)
    kwargs = {
        "nonce": body["nonce"],
        "session_id": "session-1",
        "action_digest": body["action_digest"],
        "issued_at": g.NOW,
        "expires_at": g.NOW + 30,
    }
    rp.challenge(**kwargs)
    rp.authorize(
        unb64(fixture["envelope_b64"]),
        signed,
        nonce=body["nonce"],
        action={"tool": "read", "args": {"id": "1"}},
        session_id="session-1",
        now=g.NOW,
        policy=lambda token, action: True,
    )
    expect_code("challenge_reused", lambda: rp.challenge(**kwargs))


def test_concurrent_proof_has_one_winner(fixture):
    from concurrent.futures import ThreadPoolExecutor

    rp = v.RelyingParty(context(fixture))
    body, signed = proof(fixture)
    rp.challenge(
        nonce=body["nonce"],
        session_id="session-1",
        action_digest=body["action_digest"],
        issued_at=g.NOW,
        expires_at=g.NOW + 30,
    )

    def call(_):
        try:
            _, decision = rp.authorize(
                unb64(fixture["envelope_b64"]),
                signed,
                nonce=body["nonce"],
                action={"tool": "read", "args": {"id": "1"}},
                session_id="session-1",
                now=g.NOW,
                policy=lambda token, action: True,
            )
            return decision
        except v.ProfileError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(call, range(8)))
    assert outcomes.count(True) == 1
    assert outcomes.count("challenge_missing_or_consumed") == 7


@pytest.mark.parametrize(
    "field,value",
    [
        ("iat", True),
        ("exp", "1790683320"),
        ("aud", []),
        ("cnf", {"kty": "OKP", "crv": "Ed25519", "x": "a" * 43, "d": "secret"}),
    ],
)
def test_schema_rejects_without_model_gate(fixture, field, value):
    schema = json.loads((ROOT / "schema/trace-token-experimental-v1.json").read_text())
    token = copy.deepcopy(fixture["token"])
    token[field] = value
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(token)
