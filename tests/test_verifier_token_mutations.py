"""Causal checks: disabling a security rule admits its mapped counterexample.

Each counterexample must first be rejected by the unmodified implementation.
The mutated module is loaded only in memory; the working source is untouched.
These are selected gate tests, not a complete mutation-coverage claim.
"""

from __future__ import annotations
import ast
import copy
import sys
import types
from dataclasses import replace

import pytest

from prototype import verifier_token as v
from tests.test_verifier_token_profile import context, fixture, g, rebind

# pytest discovers the imported fixture; keep the import explicit for lint.
__all__ = ["fixture"]


def load_mutant(changes):
    source = __import__("pathlib").Path(v.__file__).read_text()
    for before, after in changes:
        assert source.count(before) == 1, before
        source = source.replace(before, after)
    module = types.ModuleType("verifier_token_mutant")
    sys.modules[module.__name__] = module
    exec(compile(source, "<mutated-verifier-token>", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize(
    "rule",
    [
        "audience",
        "subject",
        "time",
        "manifest",
        "context",
        "policy",
        "issuer-holder-separation",
        "composite",
        "mixed-instance",
        "evidence",
        "signature",
        "protected-profile",
        "observation",
    ],
)
def test_disabling_mapped_gate_admits_counterexample(fixture, rule):
    token = copy.deepcopy(fixture["token"])
    ctx = context(fixture)
    now = g.NOW
    headers = None
    if rule == "observation":
        requirements = ctx.requirements.model_copy(deep=True)
        requirements.components[0] = requirements.components[0].model_copy(
            update={"expected_observed_digest": token["components"][0]["observed_digest"]}
        )
        ctx = replace(ctx, requirements=requirements)
        token["components"][0]["observed_digest"] = "sha256:" + "f" * 64
        rebind(token)
        changes = [('raise ProfileError("component_observation_mismatch")', "pass")]
    elif rule == "audience":
        token["aud"] = "wrong"
        changes = [("if token.aud != context.audience:", "if False:")]
    elif rule == "subject":
        token["sub"] = "wrong"
        changes = [
            ("if token.sub != context.subject or token.instance != context.instance:", "if False:")
        ]
    elif rule == "time":
        now -= 1
        changes = [("if type(now) is not int or not token.iat <= now < token.exp:", "if False:")]
    elif rule == "manifest":
        token["manifest"]["digest"] = "sha256:" + "0" * 64
        changes = [("token.manifest.digest != digest(context.manifest_bytes)", "False")]
    elif rule == "context":
        token["verification_context_hash"] = "sha256:" + "0" * 64
        changes = [("if token.verification_context_hash != context.question_digest:", "if False:")]
    elif rule == "policy":
        token["appraisal_policy"]["version"] = "other"
        changes = [("if token.appraisal_policy != context.policy:", "if False:")]
    elif rule == "issuer-holder-separation":
        token["cnf"]["x"] = g.b64(g.public(g.ISSUER))
        changes = [
            ("if public_bytes(holder_public(token.cnf)) == public_bytes(trusted.key):", "if False:")
        ]
    elif rule == "composite":
        token["composite_appraisal"]["status"] = "missing"
        changes = [("composite.status != overall", "False")]
    elif rule == "mixed-instance":
        # A single required component isolates the instance gate from relationship checks.
        token["components"].pop()
        token["bindings"] = []
        token["composite_appraisal"]["required_components"] = ["runtime.cpu"]
        token["components"][0]["instance"] = "other-instance"
        ctx = replace(
            ctx,
            requirements=ctx.requirements.model_copy(
                update={"components": [ctx.requirements.components[0]], "bindings": []}
            ),
        )
        changes = [("if component.instance != token.instance:", "if False:")]
    elif rule == "evidence":
        token["components"].pop()
        token["bindings"] = []
        token["composite_appraisal"]["required_components"] = ["runtime.cpu"]
        token["components"][0]["evidence_refs"] = []
        ctx = replace(
            ctx,
            requirements=ctx.requirements.model_copy(
                update={"components": [ctx.requirements.components[0]], "bindings": []}
            ),
        )
        changes = [
            (
                'if component.status in ("affirming", "warning") and not component.evidence_refs:',
                "if False:",
            )
        ]
    elif rule == "protected-profile":
        headers = {
            1: -19,
            2: [v.PROFILE_HEADER],
            3: v.CONTENT_TYPE,
            4: v.key_id(g.ISSUER),
            v.PROFILE_HEADER: "urn:unknown:profile",
        }
        changes = [("or headers[PROFILE_HEADER] != profile", "or False")]
    else:
        changes = [("trusted.key.verify(signature,", "signature_verification_disabled(signature,")]
        # The formatted call spans lines; AST removes only verify_token's crypto operation.
    raw = g.envelope(token, g.ISSUER, headers=headers)
    if rule == "signature":
        body = list(__import__("cbor2").loads(raw).value)
        body[3] = bytes([body[3][0] ^ 1]) + body[3][1:]
        raw = __import__("cbor2").dumps(__import__("cbor2").CBORTag(18, body), canonical=True)
        source = __import__("pathlib").Path(v.__file__).read_text()
        tree = ast.parse(source)
        function = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verify_token"
        )
        gate = next(n for n in function.body if isinstance(n, ast.Try))
        gate.body = [ast.Pass()]
        module = types.ModuleType("verifier_token_mutant")
        sys.modules[module.__name__] = module
        exec(compile(ast.fix_missing_locations(tree), "<mutant>", "exec"), module.__dict__)
    else:
        module = load_mutant(changes)
    with pytest.raises(v.ProfileError):
        v.verify_token(raw, ctx, now)
    # Reconstructed modules have distinct Pydantic classes. Preserve the same
    # trusted values while constructing models in the mutated module's types.
    ctx = module.VerificationContext(
        **{key: value for key, value in vars(ctx).items() if key not in ("policy", "requirements")},
        policy=module.Policy.model_validate(ctx.policy.model_dump()),
        requirements=module.Requirements.model_validate(ctx.requirements.model_dump()),
    )
    # The same expectation would turn red against this disabled implementation.
    assert module.verify_token(raw, ctx, now) is not None
