"""Precedence of disallowed warnings in verifier-token composite appraisal."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from prototype import verifier_token as v

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples" / "verifier-token-profile"
VERIFIER_MJS = ROOT / "tools" / "independent-verifier" / "verifier.mjs"
ERRORS_MJS = ROOT / "tools" / "independent-verifier" / "errors.mjs"
NODE = shutil.which("node")

SPEC = importlib.util.spec_from_file_location("independent_vectors", VECTORS / "gen_vectors.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load independent_vectors generator")
g: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _base_fixture() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads((VECTORS / "01-valid.json").read_text(encoding="utf-8"))
    return raw


def _context(
    fixture: dict[str, Any],
    requirements_dict: dict[str, Any],
    *,
    allow_warnings: bool,
) -> v.VerificationContext:
    token = fixture["token"]
    req_data = copy.deepcopy(requirements_dict)
    req_data["allow_warnings"] = allow_warnings
    issuer = v.TrustedIssuer(token["iss"], g.ISSUER.public_key(), g.NOW - 1, g.NOW + 300)
    return v.VerificationContext(
        audience=token["aud"],
        subject=token["sub"],
        instance=token["instance"],
        manifest_bytes=_unb64(fixture["manifest_b64"]),
        manifest_id=token["manifest"]["id"],
        manifest_valid_until=g.NOW + 300,
        question_digest=token["verification_context_hash"],
        policy=v.Policy.model_validate(token["appraisal_policy"]),
        requirements=v.Requirements.model_validate(req_data),
        trusted_issuers={(issuer.issuer, v.key_id(issuer.key)): issuer},
        status_check=lambda _token, _now: True,
    )


def _rebind(token: dict[str, Any]) -> None:
    components = {c["component_id"]: c for c in token["components"]}
    for binding in token["bindings"]:
        if binding["source"] in components and binding["target"] in components:
            binding["digest"] = g.canonical_digest(
                {
                    "method": binding["method"],
                    "source": components[binding["source"]],
                    "target": components[binding["target"]],
                }
            )


def _build_scenario(
    fixture: dict[str, Any],
    surface: str,
    other_status: v.Status,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    token: dict[str, Any] = copy.deepcopy(fixture["token"])
    requirements: dict[str, Any] = copy.deepcopy(fixture["requirements"])

    if surface == "components_warning_first":
        requirements["bindings"] = []
        token["bindings"] = []
        token["components"][0]["status"] = "warning"
        if other_status == "missing":
            token["components"].pop(1)
        else:
            token["components"][1]["status"] = other_status
        required = ["runtime.accelerator.0", "runtime.cpu"]
    elif surface == "components_other_first":
        requirements["bindings"] = []
        token["bindings"] = []
        token["components"][1]["status"] = "warning"
        if other_status == "missing":
            token["components"].pop(0)
        else:
            token["components"][0]["status"] = other_status
        required = ["runtime.accelerator.0", "runtime.cpu"]
    elif surface == "binding_other_with_warning_component":
        token["components"][0]["status"] = "warning"
        token["components"][1]["status"] = "affirming"
        if other_status == "missing":
            token["bindings"] = []
        else:
            token["bindings"][0]["status"] = other_status
        required = ["runtime.accelerator.0", "runtime.cpu"]
    elif surface == "warning_binding_with_other_component":
        token["components"][0]["status"] = "affirming"
        token["bindings"][0]["status"] = "warning"
        if other_status == "missing":
            requirements["components"].append(
                {
                    "component_id": "model.weights",
                    "component_type": "model",
                    "required": True,
                    "accepted_profiles": ["urn:example:software-evidence:v1"],
                    "accepted_authorities": [token["iss"]],
                    "maximum_age_seconds": 120,
                }
            )
            required = ["model.weights", "runtime.accelerator.0", "runtime.cpu"]
        else:
            token["components"][1]["status"] = other_status
            required = ["runtime.accelerator.0", "runtime.cpu"]
    else:
        raise ValueError(f"unknown surface: {surface}")

    token["composite_appraisal"]["required_components"] = required
    _rebind(token)
    return token, requirements, required


def _js_check(
    fixture: dict[str, Any],
    token: dict[str, Any],
    requirements: dict[str, Any],
    *,
    allow_warnings: bool,
    envelope_bytes: bytes,
) -> dict[str, Any]:
    if NODE is None:
        raise RuntimeError("node is required for independent verifier check")
    req_copy = copy.deepcopy(requirements)
    req_copy["allow_warnings"] = allow_warnings
    pub_b64url = (
        fixture["issuer_public_b64"].rstrip("=").replace("+", "-").replace("/", "_")
    )
    payload = {
        "verifierUrl": VERIFIER_MJS.as_uri(),
        "errorsUrl": ERRORS_MJS.as_uri(),
        "now": g.NOW,
        "token": token,
        "envelopeB64": base64.b64encode(envelope_bytes).decode("ascii"),
        "context": {
            "audience": token["aud"],
            "subject": token["sub"],
            "instance": token["instance"],
            "manifest_b64": fixture["manifest_b64"],
            "manifest_id": token["manifest"]["id"],
            "manifest_valid_until": g.NOW + 300,
            "question_digest": token["verification_context_hash"],
            "policy": token["appraisal_policy"],
            "requirements": req_copy,
            "trusted_issuers": [
                {
                    "issuer": token["iss"],
                    "public_b64url": pub_b64url,
                    "valid_from": g.NOW - 1,
                    "valid_until": g.NOW + 300,
                }
            ],
            "status": "active",
            "maximum_lifetime": 300,
        },
    }
    script = (
        "import fs from 'node:fs';"
        "const input = JSON.parse(fs.readFileSync(0, 'utf8'));"
        "const { makeContext, deriveComposite, verifyToken } = await import(input.verifierUrl);"
        "const { VerifyError } = await import(input.errorsUrl);"
        "const ctx = makeContext(input.context);"
        "const derived = deriveComposite(input.token, ctx);"
        "let tokenOutcome = 'valid';"
        "let verifiedStatus = null;"
        "try {"
        "  const env = new Uint8Array(Buffer.from(input.envelopeB64, 'base64'));"
        "  const res = verifyToken(env, ctx, input.now);"
        "  verifiedStatus = res.composite_status;"
        "} catch (e) {"
        "  tokenOutcome = e instanceof VerifyError ? e.code : 'input_invalid';"
        "}"
        "process.stdout.write(JSON.stringify({"
        "  derived_status: derived.status,"
        "  token: tokenOutcome,"
        "  composite_status: verifiedStatus"
        "}));"
    )
    proc = subprocess.run(
        [NODE, "--input-type=module", "-e", script],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    result: dict[str, Any] = json.loads(proc.stdout)
    return result


@pytest.mark.parametrize("other_status", ["missing", "unverifiable", "not-appraised"])
@pytest.mark.parametrize(
    "surface",
    [
        "components_warning_first",
        "components_other_first",
        "binding_other_with_warning_component",
        "warning_binding_with_other_component",
    ],
)
def test_disallowed_warning_outranks_non_contraindicated_statuses(
    surface: str,
    other_status: v.Status,
) -> None:
    fixture = _base_fixture()
    token_dict, requirements_dict, required = _build_scenario(fixture, surface, other_status)

    # 1. When allow_warnings=False, disallowed warning maps to contraindicated
    # before composite precedence selection.
    strict_ctx = _context(fixture, requirements_dict, allow_warnings=False)
    strict_token = copy.deepcopy(token_dict)
    strict_token["composite_appraisal"]["status"] = "contraindicated"
    strict_envelope = g.envelope(strict_token, g.ISSUER)

    overall, fresh_until, derived_required = v.derive_composite(
        v.Token.model_validate(strict_token),
        strict_ctx.requirements,
        strict_ctx.policy,
        g.NOW,
    )
    assert overall == "contraindicated"
    assert fresh_until == g.NOW + 120
    assert derived_required == required

    verified = v.verify_token(strict_envelope, strict_ctx, g.NOW)
    assert verified.composite_appraisal.status == "contraindicated"

    # Claiming the weaker status (missing, unverifiable, or not-appraised) when a
    # disallowed warning is present must be rejected with composite_inconsistent.
    understated_token = copy.deepcopy(token_dict)
    understated_token["composite_appraisal"]["status"] = other_status
    understated_envelope = g.envelope(understated_token, g.ISSUER)
    with pytest.raises(v.ProfileError, match="^composite_inconsistent$"):
        v.derive_composite(
            v.Token.model_validate(understated_token),
            strict_ctx.requirements,
            strict_ctx.policy,
            g.NOW,
        )
    with pytest.raises(v.ProfileError, match="^composite_inconsistent$"):
        v.verify_token(understated_envelope, strict_ctx, g.NOW)

    # 2. Paired positive control: when allow_warnings=True, absence of evidence
    # (missing, unverifiable, not-appraised) still outranks an allowed warning.
    permissive_ctx = replace(
        strict_ctx,
        requirements=strict_ctx.requirements.model_copy(update={"allow_warnings": True}),
    )
    permissive_token = copy.deepcopy(token_dict)
    permissive_token["composite_appraisal"]["status"] = other_status
    permissive_envelope = g.envelope(permissive_token, g.ISSUER)

    perm_overall, perm_fresh, perm_required = v.derive_composite(
        v.Token.model_validate(permissive_token),
        permissive_ctx.requirements,
        permissive_ctx.policy,
        g.NOW,
    )
    assert perm_overall == other_status
    assert perm_fresh == g.NOW + 120
    assert perm_required == required

    perm_verified = v.verify_token(permissive_envelope, permissive_ctx, g.NOW)
    assert perm_verified.composite_appraisal.status == other_status

    # 3. Differential agreement with tools/independent-verifier/verifier.mjs.
    if NODE is not None:
        js_strict_valid = _js_check(
            fixture,
            strict_token,
            requirements_dict,
            allow_warnings=False,
            envelope_bytes=strict_envelope,
        )
        assert js_strict_valid == {
            "derived_status": "contraindicated",
            "token": "valid",
            "composite_status": "contraindicated",
        }

        js_strict_understated = _js_check(
            fixture,
            understated_token,
            requirements_dict,
            allow_warnings=False,
            envelope_bytes=understated_envelope,
        )
        assert js_strict_understated == {
            "derived_status": "contraindicated",
            "token": "composite_inconsistent",
            "composite_status": None,
        }

        js_permissive = _js_check(
            fixture,
            permissive_token,
            requirements_dict,
            allow_warnings=True,
            envelope_bytes=permissive_envelope,
        )
        assert js_permissive == {
            "derived_status": other_status,
            "token": "valid",
            "composite_status": other_status,
        }
