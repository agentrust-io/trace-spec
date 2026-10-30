"""Experimental GCA launch appraisal, separate from raw TDX collateral appraisal.

Trust keys must come from an operator-pinned GCA JWKS snapshot, never the packet.
This checks launch identity and holder possession, not application correctness.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .verifier_token import Component

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

ISSUER = "https://confidentialcomputing.googleapis.com"
DOMAIN = b"trace-execution-binding-v1\x00"
PROFILE = "gca-confidential-space-launch-experimental-v1"
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class ExecutionDenied(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionDenied("duplicate_json_key")
        result[key] = value
    return result


def _no_nonfinite(_token: str) -> Any:
    raise ExecutionDenied("jwt_framing")


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ExecutionDenied("invalid_base64url")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ExecutionDenied("noncanonical_base64url")
    return decoded


@dataclass(frozen=True)
class LaunchPolicy:
    audience: str
    image_digest: str
    args: tuple[str, ...]
    subject: str
    instance_id: str
    max_age: int = 300

    def __post_init__(self) -> None:
        if not isinstance(self.instance_id, str) or not re.fullmatch(
            r"[0-9]{1,20}", self.instance_id
        ):
            raise ExecutionDenied("policy_instance_id")
        if not isinstance(self.audience, str) or not 1 <= len(self.audience) <= 255:
            raise ExecutionDenied("policy_audience")
        if not isinstance(self.image_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.image_digest
        ):
            raise ExecutionDenied("policy_digest")
        if (
            not isinstance(self.args, tuple)
            or not self.args
            or any(not isinstance(a, str) or not a for a in self.args)
        ):
            raise ExecutionDenied("policy_command")
        if not isinstance(self.subject, str) or not re.fullmatch(
            r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]+/zones/[a-z0-9-]+/instances/[a-z][a-z0-9-]+",
            self.subject,
        ):
            raise ExecutionDenied("policy_subject")
        if type(self.max_age) is not int or not 1 <= self.max_age <= 86400:
            raise ExecutionDenied("policy_age")


def authenticate_token(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 65536:
        raise ExecutionDenied("token_size")
    if (
        not isinstance(jwks, dict)
        or not isinstance(jwks.get("keys"), list)
        or any(not isinstance(k, dict) for k in jwks["keys"])
    ):
        raise ExecutionDenied("jwks_format")
    parts = token.split(".")
    if len(parts) != 3:
        raise ExecutionDenied("jwt_framing")
    try:
        header = json.loads(
            _decode(parts[0]), object_pairs_hook=_pairs, parse_constant=_no_nonfinite
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutionDenied("jwt_framing") from error
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise ExecutionDenied("algorithm")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise ExecutionDenied("missing_signer")
    if header.get("crit") or any(key in header for key in ("jku", "jwk", "x5u", "x5c")):
        raise ExecutionDenied("untrusted_header")
    matches = [key for key in jwks["keys"] if key.get("kid") == header.get("kid")]
    if len(matches) != 1:
        raise ExecutionDenied("unknown_or_ambiguous_signer")
    key = matches[0]
    if _JWK_PRIVATE_PARAMS.intersection(key):
        raise ExecutionDenied("private_jwk_material")
    if (
        key.get("kty") != "RSA"
        or key.get("alg", "RS256") != "RS256"
        or key.get("use", "sig") != "sig"
    ):
        raise ExecutionDenied("key_type")
    n_bytes, e_bytes = _decode(key.get("n")), _decode(key.get("e"))
    if not n_bytes or not e_bytes or n_bytes[0] == 0 or e_bytes[0] == 0:
        raise ExecutionDenied("key_encoding")
    n, e = int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")
    if n.bit_length() < 2048 or e != 65537:
        raise ExecutionDenied("weak_key")
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            _decode(parts[2]),
            (parts[0] + "." + parts[1]).encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as error:
        raise ExecutionDenied("signature") from error
    try:
        claims = json.loads(
            _decode(parts[1]), object_pairs_hook=_pairs, parse_constant=_no_nonfinite
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutionDenied("jwt_framing") from error
    if not isinstance(claims, dict):
        raise ExecutionDenied("claims_type")
    return claims


def appraise_launch(
    packet: dict[str, Any],
    jwks: dict[str, Any],
    policy: LaunchPolicy,
    *,
    expected_challenge: str,
    now: int,
) -> dict[str, Any]:
    """Fail closed; returns only authenticated observations on success.

    The relying party supplies a fresh challenge and consumes it on admission.
    This pure appraisal function does not implement replay storage.
    """
    try:
        if not isinstance(packet, dict):
            raise ExecutionDenied("malformed_or_unauthenticated_evidence")
        if (
            type(now) is not int
            or not 0 <= now <= 9007199254740991
            or type(policy.max_age) is not int
            or policy.max_age < 1
        ):
            raise ExecutionDenied("clock_or_policy")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", policy.image_digest):
            raise ExecutionDenied("policy_digest")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_challenge):
            raise ExecutionDenied("challenge_format")
        if packet.get("challenge") != expected_challenge:
            raise ExecutionDenied("challenge")
        public_hex = packet["holder_public_hex"]
        if not isinstance(public_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", public_hex):
            raise ExecutionDenied("holder_key")
        public = bytes.fromhex(public_hex)
        token = packet["token"]
        claims = authenticate_token(token, jwks)
        if claims.get("iss") != ISSUER or claims.get("aud") != policy.audience:
            raise ExecutionDenied("issuer_or_audience")
        if claims.get("sub") != policy.subject:
            raise ExecutionDenied("instance")
        times = [claims.get(name) for name in ("iat", "nbf", "exp")]
        if any(type(value) is not int for value in times):
            raise ExecutionDenied("time_type")
        issued, not_before, expiry = (cast(int, value) for value in times)
        if any(not 0 <= t <= 9007199254740991 for t in (issued, not_before, expiry)):
            raise ExecutionDenied("time_bounds")
        if not (issued <= now < expiry and not_before <= now and issued <= expiry):
            raise ExecutionDenied("time_bounds")
        if now - issued >= policy.max_age:
            raise ExecutionDenied("stale")
        expected_nonce = hashlib.sha256(
            DOMAIN + bytes.fromhex(expected_challenge) + public
        ).hexdigest()
        if claims.get("eat_nonce") not in (expected_nonce, [expected_nonce]):
            raise ExecutionDenied("holder_nonce")
        if claims.get("hwmodel") != "GCP_INTEL_TDX" or claims.get("swname") != "CONFIDENTIAL_SPACE":
            raise ExecutionDenied("platform_or_launcher")
        if claims.get("secboot") is not True or claims.get("dbgstat") != "disabled-since-boot":
            raise ExecutionDenied("boot_or_debug")
        submods = claims["submods"]
        if submods.get("gce", {}).get("instance_id") != policy.instance_id:
            raise ExecutionDenied("instance_uid")
        support = submods["confidential_space"]["support_attributes"]
        if not isinstance(support, list) or not {"STABLE", "USABLE"}.issubset(support):
            raise ExecutionDenied("launcher_support")
        if submods["confidential_space"].get("monitoring_enabled", {}).get("memory") is not False:
            raise ExecutionDenied("memory_monitoring")
        container = submods["container"]
        if container.get("image_digest") != policy.image_digest:
            raise ExecutionDenied("workload_substitution")
        if container.get("args") != list(policy.args) or container.get("cmd_override", []) != []:
            raise ExecutionDenied("command_substitution")
        if container.get("env_override", {}) != {"TRACE_CHALLENGE": expected_challenge}:
            raise ExecutionDenied("environment_substitution")
        if container.get("env", {}).get("TRACE_CHALLENGE") != expected_challenge:
            raise ExecutionDenied("environment_binding")
        if container.get("restart_policy") != "Never":
            raise ExecutionDenied("restart_policy")
        signed = (
            DOMAIN + hashlib.sha256(token.encode()).digest() + bytes.fromhex(expected_challenge)
        )
        sig_b64 = packet.get("holder_signature_b64")
        if not isinstance(sig_b64, str):
            raise ExecutionDenied("holder_signature")
        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except ValueError as error:
            raise ExecutionDenied("holder_signature") from error
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != sig_b64:
            raise ExecutionDenied("holder_signature")
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, signed)
        return {
            "profile": PROFILE,
            "instance": "gcp-instance/" + policy.instance_id,
            "observed_digest": container["image_digest"],
            "evidence_digest": "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
            "holder_public_hex": public.hex(),
            "issued_at": issued,
            "expires_at": min(expiry, issued + policy.max_age),
            "appraiser": ISSUER,
            "limits": [
                "Google-delegated appraisal; raw TCB/revocation/QE appraisal is separate.",
                "Point-in-time launch and holder possession; no proof of task completion.",
                "Challenge consumption belongs to the relying party replay store.",
            ],
        }
    except ExecutionDenied:
        raise
    except Exception as error:
        raise ExecutionDenied("malformed_or_unauthenticated_evidence") from error


def launch_component(
    packet: dict[str, Any],
    jwks: dict[str, Any],
    policy: LaunchPolicy,
    *,
    expected_challenge: str,
    expected_holder: bytes,
    authority: str,
    now: int,
) -> Component:
    """Issuer-side adapter; the component authority is the TRACE token issuer.

    It must be explicitly accepted by independently configured requirements.
    The evidence profile records the GCA delegation; no direct DCAP claim is made.
    Only code launch is appraised. Required runtime/TCB/relationship components
    must be appraised separately before any complete-agent composite can affirm.
    """
    from .verifier_token import Component, EvidenceRef

    observation = appraise_launch(
        packet, jwks, policy, expected_challenge=expected_challenge, now=now
    )
    if (
        type(expected_holder) is not bytes
        or bytes.fromhex(observation["holder_public_hex"]) != expected_holder
    ):
        raise ExecutionDenied("token_holder_mismatch")
    return Component(
        component_id="application.code",
        component_type="code",
        profile=PROFILE,
        authority=authority,
        instance=observation["instance"],
        status="affirming",
        appraised_at=now,
        fresh_until=observation["expires_at"],
        evidence_refs=[
            EvidenceRef(
                profile=PROFILE,
                media_type="application/eat+jwt",
                digest=observation["evidence_digest"],
            )
        ],
        observed_digest=observation["observed_digest"],
        reasons=[],
    )
