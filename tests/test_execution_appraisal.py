"""Independent signed counterexamples for experimental launch admission."""

import ast
import base64
import copy
import hashlib
import inspect
import json
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from prototype import execution_appraisal as a
from prototype import verifier_token as v

NOW = 1000
CHALLENGE = "ab" * 32
DIGEST = "sha256:" + "11" * 32
SUBJECT = "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/approved"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@pytest.fixture
def case():
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    holder = ed25519.Ed25519PrivateKey.generate()
    public = holder.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    numbers = signer.public_key().public_numbers()
    keys = {
        "keys": [
            {
                "kid": "laboratory",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": b64(numbers.n.to_bytes(256, "big")),
                "e": b64(b"\x01\x00\x01"),
            }
        ]
    }
    # Literal wire construction independent of the subject's nonce helpers.
    nonce = hashlib.sha256(
        b"trace-execution-binding-v1\x00" + bytes.fromhex(CHALLENGE) + public
    ).hexdigest()
    claims = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": "urn:test:launch",
        "sub": SUBJECT,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 3600,
        "eat_nonce": [nonce],
        "hwmodel": "GCP_INTEL_TDX",
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": True,
        "dbgstat": "disabled-since-boot",
        "submods": {
            "gce": {"instance_id": "1234"},
            "confidential_space": {
                "support_attributes": ["STABLE", "USABLE"],
                "monitoring_enabled": {"memory": False},
            },
            "container": {
                "image_digest": DIGEST,
                "args": ["python", "/approved.py"],
                "env": {"TRACE_CHALLENGE": CHALLENGE},
                "env_override": {"TRACE_CHALLENGE": CHALLENGE},
                "restart_policy": "Never",
            },
        },
    }
    policy = a.LaunchPolicy("urn:test:launch", DIGEST, ("python", "/approved.py"), SUBJECT, "1234")

    def packet(claims_=None, header=None):
        signed = (
            b64(json.dumps(header or {"alg": "RS256", "kid": "laboratory"}).encode())
            + "."
            + b64(json.dumps(claims_ or claims).encode())
        )
        token = (
            signed + "." + b64(signer.sign(signed.encode(), padding.PKCS1v15(), hashes.SHA256()))
        )
        proof = (
            b"trace-execution-binding-v1\x00"
            + hashlib.sha256(token.encode()).digest()
            + bytes.fromhex(CHALLENGE)
        )
        return {
            "token": token,
            "challenge": CHALLENGE,
            "holder_public_hex": public.hex(),
            "holder_signature_b64": base64.b64encode(holder.sign(proof)).decode(),
        }

    return claims, keys, policy, packet, public


def appraise(case, claims=None, **kwargs):
    original, keys, policy, packet, _ = case
    return a.appraise_launch(
        packet(claims), keys, policy, expected_challenge=CHALLENGE, now=NOW, **kwargs
    )


def test_approved_launch_and_issuer_holder_binding(case):
    _, keys, policy, packet, public = case
    result = appraise(case)
    assert result["observed_digest"] == DIGEST and result["expires_at"] == NOW + 300
    component = a.launch_component(
        packet(),
        keys,
        policy,
        expected_challenge=CHALLENGE,
        expected_holder=public,
        authority="urn:test:issuer",
        now=NOW,
    )
    assert component.component_type == "code" and component.status == "affirming"
    assert component.profile == a.PROFILE
    with pytest.raises(a.ExecutionDenied, match="^token_holder_mismatch$"):
        a.launch_component(
            packet(),
            keys,
            policy,
            expected_challenge=CHALLENGE,
            expected_holder=bytes(32),
            authority="urn:test:issuer",
            now=NOW,
        )


@pytest.mark.parametrize(
    "path,value,reason",
    [
        (("submods", "gce", "instance_id"), "5678", "instance_uid"),
        (("submods", "gce", "instance_id"), None, "instance_uid"),
        (("submods", "container", "image_digest"), "sha256:" + "22" * 32, "workload_substitution"),
        (("submods", "container", "image_digest"), None, "workload_substitution"),
        (("submods", "container", "args"), ["python", "/substituted.py"], "command_substitution"),
        (("submods", "container", "cmd_override"), ["-c", "substituted"], "command_substitution"),
        (
            ("submods", "container", "env_override"),
            {"TRACE_CHALLENGE": CHALLENGE, "PYTHONPATH": "/evil"},
            "environment_substitution",
        ),
        (("submods", "container", "env"), {}, "environment_binding"),
        (("submods", "container", "restart_policy"), "Always", "restart_policy"),
        (("dbgstat",), "enabled", "boot_or_debug"),
        (("secboot",), 1, "boot_or_debug"),
        (("swname",), "GCE", "platform_or_launcher"),
        (("hwmodel",), "GCP_SHIELDED_VM", "platform_or_launcher"),
        (("submods", "confidential_space", "support_attributes"), ["USABLE"], "launcher_support"),
        (
            ("submods", "confidential_space", "monitoring_enabled"),
            {"memory": True},
            "memory_monitoring",
        ),
        (("sub",), SUBJECT + "-other", "instance"),
        (("eat_nonce",), ["00" * 32], "holder_nonce"),
        (("iss",), "https://untrusted.test", "issuer_or_audience"),
        (("aud",), ["urn:test:launch"], "issuer_or_audience"),
        (("iat",), True, "time_type"),
        (("iat",), NOW + 1, "time_bounds"),
        (("nbf",), NOW + 1, "time_bounds"),
        (("exp",), NOW, "time_bounds"),
    ],
)
def test_signed_counterexamples_reach_semantic_gate(case, path, value, reason):
    claims = copy.deepcopy(case[0])
    parent = claims
    for field in path[:-1]:
        parent = parent[field]
    parent[path[-1]] = value
    with pytest.raises(a.ExecutionDenied, match="^" + reason + "$"):
        appraise(case, claims)


def test_exclusive_age_and_unknown_signer(case):
    _, keys, policy, packet, _ = case
    with pytest.raises(a.ExecutionDenied, match="^stale$"):
        a.appraise_launch(packet(), keys, policy, expected_challenge=CHALLENGE, now=NOW + 300)
    for bad_keys in ({"keys": []}, {"keys": keys["keys"] * 2}):
        with pytest.raises(a.ExecutionDenied, match="^unknown_or_ambiguous_signer$"):
            a.appraise_launch(packet(), bad_keys, policy, expected_challenge=CHALLENGE, now=NOW)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": "laboratory"},
        {"alg": "HS256", "kid": "laboratory"},
        {"alg": "RS256"},
        {"alg": "RS256", "kid": "laboratory", "jku": "https://evil.test"},
        {"alg": "RS256", "kid": "laboratory", "crit": ["evil"]},
    ],
)
def test_untrusted_envelope_headers(case, header):
    _, keys, policy, packet, _ = case
    with pytest.raises(a.ExecutionDenied):
        a.appraise_launch(
            packet(header=header), keys, policy, expected_challenge=CHALLENGE, now=NOW
        )


def test_missing_tcb_component_cannot_become_complete_agent(case):
    _, keys, launch_policy, packet, public = case
    authority = "urn:test:issuer"
    code = a.launch_component(
        packet(),
        keys,
        launch_policy,
        expected_challenge=CHALLENGE,
        expected_holder=public,
        authority=authority,
        now=NOW,
    )
    policy = v.Policy(id="urn:test:policy", version="1", digest="sha256:" + "33" * 32)
    requirements = v.Requirements(
        components=[
            v.Requirement(
                component_id="application.code",
                component_type="code",
                required=True,
                accepted_profiles=[a.PROFILE],
                accepted_authorities=[authority],
                maximum_age_seconds=300,
                expected_observed_digest=DIGEST,
            ),
            v.Requirement(
                component_id="platform.tcb",
                component_type="runtime",
                required=True,
                accepted_profiles=["dcap-full-appraisal-v1"],
                accepted_authorities=[authority],
                maximum_age_seconds=300,
            ),
        ],
        bindings=[],
        allow_warnings=False,
    )
    token = v.Token(
        profile=v.PROFILE,
        iss=authority,
        sub="agent.test",
        instance="gcp-instance/1234",
        iat=NOW,
        exp=NOW + 200,
        jti="token.test",
        aud="urn:test:launch",
        cnf=v.HolderKey(kty="OKP", crv="Ed25519", x=b64(public)),
        manifest=v.ManifestRef(
            id="manifest.test",
            media_type="application/agent-manifest+cose",
            version="0.2",
            digest="sha256:" + "44" * 32,
        ),
        verification_context_hash="sha256:" + "55" * 32,
        appraisal_policy=policy,
        components=[code],
        bindings=[],
        composite_appraisal=v.Composite(
            status="missing",
            required_components=["application.code", "platform.tcb"],
            policy=policy,
            fresh_until=NOW + 200,
        ),
    )
    assert v.derive_composite(token, requirements, policy, NOW)[0] == "missing"
    with pytest.raises(v.ProfileError, match="^composite_inconsistent$"):
        v.derive_composite(
            token.model_copy(
                update={
                    "composite_appraisal": token.composite_appraisal.model_copy(
                        update={"status": "affirming"}
                    )
                }
            ),
            requirements,
            policy,
            NOW,
        )


def test_removing_image_gate_admits_signed_substitution(case):
    claims = copy.deepcopy(case[0])
    claims["submods"]["container"]["image_digest"] = "sha256:" + "22" * 32
    with pytest.raises(a.ExecutionDenied, match="^workload_substitution$"):
        appraise(case, claims)

    class RemoveImageGate(ast.NodeTransformer):
        removed = 0

        def visit_If(self, node):
            if any(
                isinstance(item, ast.Raise)
                and isinstance(item.exc, ast.Call)
                and any(
                    isinstance(arg, ast.Constant) and arg.value == "workload_substitution"
                    for arg in item.exc.args
                )
                for item in node.body
            ):
                self.removed += 1
                return None
            return self.generic_visit(node)

    mutation = RemoveImageGate()
    tree = mutation.visit(ast.parse(inspect.getsource(a)))
    assert mutation.removed == 1
    mutant = ModuleType("prototype.mutated_launch")
    mutant.__package__ = "prototype"
    # Dataclass resolution needs the module registered during its execution.
    import sys

    sys.modules[mutant.__name__] = mutant
    try:
        exec(compile(ast.fix_missing_locations(tree), "<mutated-launch>", "exec"), mutant.__dict__)
        _, keys, policy, packet, _ = case
        result = mutant.appraise_launch(
            packet(claims), keys, policy, expected_challenge=CHALLENGE, now=NOW
        )
        assert result["observed_digest"] == "sha256:" + "22" * 32
    finally:
        del sys.modules[mutant.__name__]
