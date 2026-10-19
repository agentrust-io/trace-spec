"""Boundary and fail-closed tests for launch and Azure execution appraisal."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from types import ModuleType
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from prototype import azure_execution_binding as x
from prototype import execution_appraisal as a

NOW = 1000
CHALLENGE = "ab" * 32
DIGEST = "sha256:" + "11" * 32
SUBJECT = (
    "https://www.googleapis.com/compute/v1/projects/test-project"
    "/zones/us-central1-a/instances/approved"
)
SHIM = "a1" * 32
UKI = "b2" * 32
APP = "11" * 32
SYSTEMD = "33" * 32
SUDO = "44" * 32

SIGNER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
HOLDER = ed25519.Ed25519PrivateKey.generate()
PUBLIC = HOLDER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
AK = rsa.generate_private_key(public_exponent=65537, key_size=2048)

LAUNCH_POLICY = a.LaunchPolicy(
    "urn:test:launch",
    DIGEST,
    ("python", "/approved.py"),
    SUBJECT,
    "1234",
)

EXECUTION_POLICY = x.ExecutionPolicy(
    required_boot_application=UKI,
    approved_boot_applications=frozenset({SHIM, UKI}),
    required_application=APP,
    approved_executables=frozenset({APP, SYSTEMD}),
    denied_executables=frozenset({SUDO}),
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _valid_jwks() -> dict[str, Any]:
    numbers = SIGNER.public_key().public_numbers()
    return {
        "keys": [
            {
                "kid": "laboratory",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": _b64url(numbers.n.to_bytes(256, "big")),
                "e": _b64url(b"\x01\x00\x01"),
            }
        ]
    }


def _valid_claims() -> dict[str, Any]:
    nonce = hashlib.sha256(
        b"trace-execution-binding-v1\x00" + bytes.fromhex(CHALLENGE) + PUBLIC
    ).hexdigest()
    return {
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


def _sign_parts(header_part: str, payload_part: str) -> str:
    signing_input = f"{header_part}.{payload_part}"
    sig = SIGNER.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(sig)}"


def _valid_launch_packet() -> dict[str, Any]:
    header_part = _b64url(json.dumps({"alg": "RS256", "kid": "laboratory"}).encode("utf-8"))
    payload_part = _b64url(json.dumps(_valid_claims()).encode("utf-8"))
    token = _sign_parts(header_part, payload_part)
    proof = (
        b"trace-execution-binding-v1\x00"
        + hashlib.sha256(token.encode("ascii")).digest()
        + bytes.fromhex(CHALLENGE)
    )
    return {
        "token": token,
        "challenge": CHALLENGE,
        "holder_public_hex": PUBLIC.hex(),
        "holder_signature_b64": _b64(HOLDER.sign(proof)),
    }


def _uefi_event(pcr: int, etype: int, digest: bytes, data: bytes = b"") -> bytes:
    return (
        struct.pack("<III", pcr, etype, 1)
        + struct.pack("<H", 0x000B)
        + digest
        + struct.pack("<I", len(data))
        + data
    )


def _valid_uefi_log() -> bytes:
    header = (
        b"Spec ID Event03\x00"
        + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1)
        + struct.pack("<HH", 0x000B, 32)
        + b"\x00"
    )
    log = (
        struct.pack("<II", 0, x.EV_NO_ACTION)
        + bytes(20)
        + struct.pack("<I", len(header))
        + header
    )
    name = "SecureBoot".encode("utf-16-le")
    variable = bytes(16) + struct.pack("<QQ", 10, 1) + name + b"\x01"
    log += _uefi_event(7, x.EV_EFI_VARIABLE_DRIVER_CONFIG, _sha256(variable), variable)
    for pcr in range(10):
        log += _uefi_event(pcr, 0x4, _sha256(b"separator"))
    for app in (SHIM, UKI):
        log += _uefi_event(
            4, x.EV_EFI_BOOT_SERVICES_APPLICATION, bytes.fromhex(app), b"devicepath"
        )
    return log


def _ima_entry(file_digest: bytes, path: str) -> bytes:
    digest_field = b"sha256:\x00" + file_digest
    path_field = path.encode("utf-8") + b"\x00"
    data = (
        struct.pack("<I", len(digest_field))
        + digest_field
        + struct.pack("<I", len(path_field))
        + path_field
    )
    return (
        struct.pack("<I", 10)
        + _sha256(data)
        + struct.pack("<I", 6)
        + b"ima-ng"
        + struct.pack("<I", len(data))
        + data
    )


def _valid_azure_packet() -> tuple[dict[str, Any], bytes, bytes, bytes, bytes]:
    uefi = _valid_uefi_log()
    replayed = x.replay_uefi(x.parse_uefi_log(uefi))
    aggregate = _sha256(b"".join(replayed[i] for i in range(10)))
    entries = [
        _ima_entry(aggregate, "boot_aggregate"),
        _ima_entry(bytes.fromhex(SYSTEMD), "/bin/0"),
        _ima_entry(bytes.fromhex(APP), "/bin/1"),
    ]
    pcr10 = bytes(32)
    for entry in entries:
        pcr10 = _sha256(pcr10 + entry[4:36])
    values = {**replayed, 10: pcr10}
    composite = _sha256(b"".join(values[i] for i in x.QUOTED_PCRS))
    bitmap = bytearray(3)
    for i in x.QUOTED_PCRS:
        bitmap[i // 8] |= 1 << (i % 8)
    qualifying = _sha256(x.DOMAIN + bytes.fromhex(CHALLENGE) + PUBLIC)
    quote = (
        b"\xffTCG\x80\x18"
        + struct.pack(">H", 4)
        + b"name"
        + struct.pack(">H", len(qualifying))
        + qualifying
        + bytes(25)
        + struct.pack(">I", 1)
        + struct.pack(">HB", 0x000B, 3)
        + bytes(bitmap)
        + struct.pack(">H", 32)
        + composite
    )
    raw_sig = AK.sign(quote, padding.PKCS1v15(), hashes.SHA256())
    tpm_sig = b"\x00\x14\x00\x0b" + struct.pack(">H", len(raw_sig)) + raw_sig
    ima = b"".join(entries)
    packet = {
        "challenge": CHALLENGE,
        "holder_public_hex": PUBLIC.hex(),
        "tpm_quote_b64": _b64(quote),
        "tpm_signature_b64": _b64(tpm_sig),
        "holder_signature_b64": _b64(
            HOLDER.sign(x.DOMAIN + _sha256(quote) + bytes.fromhex(CHALLENGE))
        ),
        "uefi_event_log_b64": _b64(uefi),
        "ima_log_sha256_b64": _b64(ima),
    }
    return packet, quote, tpm_sig, uefi, ima


def test_authenticate_token_rejects_malformed_jwt_json_and_bad_signature() -> None:
    jwks = _valid_jwks()
    good_packet = _valid_launch_packet()
    claims = a.authenticate_token(good_packet["token"], jwks)
    assert claims["sub"] == SUBJECT

    valid_header = _b64url(json.dumps({"alg": "RS256", "kid": "laboratory"}).encode("utf-8"))
    valid_payload = _b64url(json.dumps(_valid_claims()).encode("utf-8"))

    for bad_header in (_b64url(b"\xff"), _b64url(b"{not-json")):
        token = _sign_parts(bad_header, valid_payload)
        with pytest.raises(a.ExecutionDenied, match="^jwt_framing$"):
            a.authenticate_token(token, jwks)

    for bad_payload in (_b64url(b"\xff"), _b64url(b"{not-json")):
        token = _sign_parts(valid_header, bad_payload)
        with pytest.raises(a.ExecutionDenied, match="^jwt_framing$"):
            a.authenticate_token(token, jwks)

    parts = good_packet["token"].split(".")
    corrupted_sig = _b64url(bytes(256))
    with pytest.raises(a.ExecutionDenied, match="^signature$"):
        a.authenticate_token(f"{parts[0]}.{parts[1]}.{corrupted_sig}", jwks)


def test_authenticate_token_rejects_malformed_jwks() -> None:
    jwks = _valid_jwks()
    token = _valid_launch_packet()["token"]
    assert a.authenticate_token(token, jwks)["aud"] == "urn:test:launch"

    for bad_jwks in (None, {}, {"keys": None}, {"keys": [None]}, {"keys": ["bad"]}):
        with pytest.raises(a.ExecutionDenied, match="^jwks_format$"):
            a.authenticate_token(token, cast(Any, bad_jwks))


def test_authenticate_token_rejects_private_jwk_parameters() -> None:
    jwks = _valid_jwks()
    token = _valid_launch_packet()["token"]
    assert a.authenticate_token(token, jwks)["iss"] == a.ISSUER

    for private_param in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
        leaked = copy.deepcopy(jwks)
        leaked["keys"][0][private_param] = "AA"
        with pytest.raises(a.ExecutionDenied, match="^private_jwk_material$"):
            a.authenticate_token(token, leaked)


def test_authenticate_token_rejects_non_minimal_base64url_uint() -> None:
    jwks = _valid_jwks()
    token = _valid_launch_packet()["token"]
    assert a.authenticate_token(token, jwks)["sub"] == SUBJECT

    numbers = SIGNER.public_key().public_numbers()
    padded_n = copy.deepcopy(jwks)
    padded_n["keys"][0]["n"] = _b64url(b"\x00" + numbers.n.to_bytes(256, "big"))
    with pytest.raises(a.ExecutionDenied, match="^key_encoding$"):
        a.authenticate_token(token, padded_n)

    padded_e = copy.deepcopy(jwks)
    padded_e["keys"][0]["e"] = _b64url(b"\x00\x01\x00\x01")
    with pytest.raises(a.ExecutionDenied, match="^key_encoding$"):
        a.authenticate_token(token, padded_e)


def test_appraise_launch_rejects_noncanonical_holder_signature_and_non_dict_inputs() -> None:
    jwks = _valid_jwks()
    packet = _valid_launch_packet()
    result = a.appraise_launch(
        packet, jwks, LAUNCH_POLICY, expected_challenge=CHALLENGE, now=NOW
    )
    assert result["observed_digest"] == DIGEST

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    sig_b64 = packet["holder_signature_b64"]
    assert sig_b64.endswith("==")
    idx = alphabet.index(sig_b64[-3])
    noncanonical_sig_b64 = sig_b64[:-3] + alphabet[idx ^ 1] + "=="
    assert base64.b64decode(noncanonical_sig_b64, validate=True) == base64.b64decode(sig_b64)

    noncanonical_packet = {**packet, "holder_signature_b64": noncanonical_sig_b64}
    with pytest.raises(a.ExecutionDenied, match="^holder_signature$"):
        a.appraise_launch(
            noncanonical_packet, jwks, LAUNCH_POLICY, expected_challenge=CHALLENGE, now=NOW
        )

    bytes_sig_packet = {**packet, "holder_signature_b64": sig_b64.encode("ascii")}
    with pytest.raises(a.ExecutionDenied, match="^holder_signature$"):
        a.appraise_launch(
            bytes_sig_packet, jwks, LAUNCH_POLICY, expected_challenge=CHALLENGE, now=NOW
        )

    short_sig_packet = {**packet, "holder_signature_b64": _b64(bytes(63))}
    with pytest.raises(a.ExecutionDenied, match="^holder_signature$"):
        a.appraise_launch(
            short_sig_packet, jwks, LAUNCH_POLICY, expected_challenge=CHALLENGE, now=NOW
        )

    with pytest.raises(a.ExecutionDenied, match="^malformed_or_unauthenticated_evidence$"):
        a.appraise_launch(
            cast(Any, None), jwks, LAUNCH_POLICY, expected_challenge=CHALLENGE, now=NOW
        )
    with pytest.raises(a.ExecutionDenied, match="^malformed_or_unauthenticated_evidence$"):
        a.appraise_launch(
            packet, jwks, cast(Any, None), expected_challenge=CHALLENGE, now=NOW
        )


def test_quote_and_signature_type_boundaries() -> None:
    _, quote, tpm_sig, _, _ = _valid_azure_packet()
    parsed = x.parse_quote(quote)
    assert parsed.pcrs == x.QUOTED_PCRS
    x.verify_quote_signature(quote, tpm_sig, AK.public_key())

    for bad_quote in (None, "not-bytes", bytearray(quote)):
        with pytest.raises(x.ExecutionDenied, match="^quote_type$"):
            x.parse_quote(cast(Any, bad_quote))

    with pytest.raises(x.ExecutionDenied, match="^quote_signature$"):
        x.verify_quote_signature(cast(Any, None), tpm_sig, AK.public_key())
    with pytest.raises(x.ExecutionDenied, match="^quote_signature$"):
        x.verify_quote_signature(quote, cast(Any, None), AK.public_key())
    with pytest.raises(x.ExecutionDenied, match="^quote_signature$"):
        x.verify_quote_signature(quote, tpm_sig, cast(Any, None))


def test_parse_uefi_log_rejects_non_bytes_and_truncated_headers() -> None:
    _, _, _, uefi, _ = _valid_azure_packet()
    events = x.parse_uefi_log(uefi)
    assert len(events) > 0

    spec_size = struct.unpack_from("<I", uefi, 28)[0]
    spec_only = uefi[: 32 + spec_size]
    oversized_spec = spec_only[:28] + struct.pack("<I", spec_size + 64) + spec_only[32:]
    truncated_event_header = spec_only + uefi[32 + spec_size : 32 + spec_size + 8]
    truncated_event_data = uefi[:-1]

    for bad_log in (
        None,
        "not-bytes",
        uefi[:16],
        oversized_spec,
        truncated_event_header,
        truncated_event_data,
    ):
        with pytest.raises(x.ExecutionDenied, match="^uefi_log_truncated$"):
            x.parse_uefi_log(cast(Any, bad_log))


def test_parse_ima_log_rejects_non_bytes_and_truncated_entries() -> None:
    _, _, _, _, ima = _valid_azure_packet()
    entries = x.parse_ima_log(ima)
    assert len(entries) == 3

    first_entry = _ima_entry(bytes.fromhex(APP), "/bin/app")
    for bad_ima in (
        None,
        "not-bytes",
        first_entry[:20],
        first_entry[:42],
        first_entry[:-2],
    ):
        with pytest.raises(x.ExecutionDenied, match="^ima_log_truncated$"):
            x.parse_ima_log(cast(Any, bad_ima))


def test_appraise_execution_rejects_non_dict_and_bad_argument_types() -> None:
    packet, _, _, _, _ = _valid_azure_packet()
    result = x.appraise_execution(
        packet, AK.public_key(), EXECUTION_POLICY, expected_challenge=CHALLENGE
    )
    assert result["observed_application"] == "sha256:" + APP

    with pytest.raises(x.ExecutionDenied, match="^packet_format$"):
        x.appraise_execution(
            cast(Any, None), AK.public_key(), EXECUTION_POLICY, expected_challenge=CHALLENGE
        )
    with pytest.raises(x.ExecutionDenied, match="^packet_format$"):
        x.appraise_execution(
            packet, cast(Any, None), EXECUTION_POLICY, expected_challenge=CHALLENGE
        )
    with pytest.raises(x.ExecutionDenied, match="^packet_format$"):
        x.appraise_execution(
            packet, AK.public_key(), cast(Any, None), expected_challenge=CHALLENGE
        )
    with pytest.raises(x.ExecutionDenied, match="^packet_format$"):
        x.appraise_execution(
            packet, AK.public_key(), EXECUTION_POLICY, expected_challenge=cast(Any, None)
        )


def test_authenticate_ak_rejects_non_dict_private_jwk_and_non_minimal_modulus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass
    class _ParsedReport:
        policy: int
        vmpl: int
        report_data: bytes

    wcm_mod = ModuleType("wcm")
    certs_mod = ModuleType("wcm._certificates")
    quote_mod = ModuleType("wcm._quote_verify")
    snp_mod = ModuleType("wcm.snp")

    cast(Any, certs_mod).load_pem_certificate = lambda pem, **kw: pem
    cast(Any, quote_mod).verify_cert_chain = lambda vcek, inter, trust, now: []
    cast(Any, snp_mod).extract_snp_report_from_hcl = lambda hcl: hcl
    cast(Any, snp_mod).verify_snp_report_signature = lambda report, vcek: True

    def _parse_snp_report(hcl: bytes) -> _ParsedReport:
        runtime = hcl[32 + 1184 :]
        json_len = int.from_bytes(runtime[16:20], "little")
        runtime_json = runtime[20 : 20 + json_len]
        return _ParsedReport(
            policy=0,
            vmpl=0,
            report_data=hashlib.sha256(runtime_json).digest() + bytes(32),
        )

    cast(Any, snp_mod).parse_snp_report = _parse_snp_report
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm._quote_verify", quote_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)

    ak_pem = (
        AK.public_key()
        .public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    n_bytes = AK.public_key().public_numbers().n.to_bytes(256, "big")

    def _hcl_packet(jwk_overrides: dict[str, Any]) -> dict[str, Any]:
        jwk: dict[str, Any] = {
            "kid": "HCLAkPub",
            "kty": "RSA",
            "e": "AQAB",
            "n": _b64url(n_bytes),
            **jwk_overrides,
        }
        runtime_bytes = json.dumps({"keys": [jwk]}).encode("utf-8")
        hcl = (
            bytes(32 + 1184)
            + bytes(16)
            + len(runtime_bytes).to_bytes(4, "little")
            + runtime_bytes
        )
        return {
            "hcl_b64": _b64(hcl),
            "vcek_pem": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            "intermediates_pem": [],
            "ak_pem": ak_pem,
        }

    authenticated = x.authenticate_ak(_hcl_packet({}), object())
    assert authenticated.public_numbers().n == AK.public_key().public_numbers().n

    for private_param in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
        with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
            x.authenticate_ak(_hcl_packet({private_param: "AA"}), object())

    with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
        x.authenticate_ak(_hcl_packet({"n": _b64url(b"\x00" + n_bytes)}), object())

    with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
        x.authenticate_ak(_hcl_packet({"n": _b64url(n_bytes) + "="}), object())

    with pytest.raises(x.ExecutionDenied, match="^platform_evidence_format$"):
        x.authenticate_ak(cast(Any, None), object())
