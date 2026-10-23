"""Regression and boundary tests for Azure SEV-SNP/vTPM execution binding (#613)."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from prototype import azure_execution_binding as x

FIXTURES = Path(__file__).parent / "fixtures" / "azure-execution-20260929"
AK = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _install_wcm_stub(monkeypatch: pytest.MonkeyPatch) -> None:
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
    cast(Any, snp_mod).extract_snp_report_from_hcl = lambda hcl: hcl[32 : 32 + 1184]
    cast(Any, snp_mod).verify_snp_report_signature = lambda report, vcek: True
    cast(Any, snp_mod).parse_snp_report = lambda report: _ParsedReport(
        policy=int.from_bytes(report[8:16], "little"),
        vmpl=report[0x30],
        report_data=report[0x50:0x90],
    )
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm._quote_verify", quote_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)


def _hcl_blob(runtime_json: bytes) -> bytes:
    report = bytearray(1184)
    report[0x50:0x90] = hashlib.sha256(runtime_json).digest() + bytes(32)
    return (
        bytes(32)
        + bytes(report)
        + bytes(16)
        + len(runtime_json).to_bytes(4, "little")
        + runtime_json
    )


def _ak_pem(public_key: rsa.RSAPublicKey | None = None) -> str:
    key = public_key or AK.public_key()
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _hcl_packet(
    runtime_json: bytes | None = None,
    *,
    jwk: dict[str, Any] | None = None,
    ak_pem: str | None = None,
) -> dict[str, Any]:
    n_bytes = AK.public_key().public_numbers().n.to_bytes(256, "big")
    key_obj: dict[str, Any] = (
        jwk
        if jwk is not None
        else {
            "kid": "HCLAkPub",
            "kty": "RSA",
            "e": "AQAB",
            "n": _b64url(n_bytes),
        }
    )
    raw_json = (
        runtime_json
        if runtime_json is not None
        else json.dumps(
            {
                "keys": [key_obj],
                "vm-configuration": {
                    "vmUniqueId": "ca2e2e97-d879-49b7-ab25-f10ac9bd8667",
                    "secure-boot": False,
                },
            }
        ).encode("utf-8")
    )
    return {
        "hcl_b64": _b64(_hcl_blob(raw_json)),
        "vcek_pem": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        "intermediates_pem": [],
        "ak_pem": ak_pem if ak_pem is not None else _ak_pem(),
    }


def _real_b1() -> tuple[dict[str, Any], x.ExecutionPolicy, str]:
    packet = json.loads((FIXTURES / "b1-approved-packet.json").read_text(encoding="utf-8"))
    challenge = (FIXTURES / "b1-approved.challenge").read_text(encoding="utf-8").strip()
    raw_policy = json.loads((FIXTURES / "execution-policy.json").read_text(encoding="utf-8"))
    policy = x.ExecutionPolicy(
        required_boot_application=raw_policy["required_boot_application"],
        approved_boot_applications=frozenset(raw_policy["approved_boot_applications"]),
        required_application=raw_policy["required_application"],
        approved_executables=frozenset(raw_policy["approved_executables"]),
        denied_executables=frozenset(raw_policy["denied_executables"]),
        secure_boot=raw_policy["secure_boot"],
    )
    return packet, policy, challenge


def _build_pe_image(
    *,
    magic: int = 0x20B,
    section_data: bytes = b"\x90" * 64,
    cert_bytes: bytes = b"",
) -> tuple[bytes, str]:
    pe = 0x40
    opt = pe + 24
    optional_size = 240 if magic == 0x20B else 224
    datadir = opt + (112 if magic == 0x20B else 96)
    checksum = opt + 64
    cert_entry = datadir + 8 * 4
    table = opt + optional_size
    headers_size = 512
    section_offset = headers_size
    section_size = len(section_data)
    cert_offset = section_offset + section_size if cert_bytes else 0
    cert_size = len(cert_bytes)
    total_size = section_offset + section_size + cert_size

    buf = bytearray(total_size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe)
    buf[pe : pe + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe + 6, 1)  # NumberOfSections = 1
    struct.pack_into("<H", buf, pe + 20, optional_size)
    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into("<I", buf, opt + 60, headers_size)
    struct.pack_into("<I", buf, checksum, 0xDEADBEEF)
    struct.pack_into("<II", buf, cert_entry, cert_offset, cert_size)
    buf[table : table + 6] = b".text\x00"
    struct.pack_into("<II", buf, table + 16, section_size, section_offset)
    buf[section_offset : section_offset + section_size] = section_data
    if cert_bytes:
        buf[cert_offset : cert_offset + cert_size] = cert_bytes

    expected = hashlib.sha256()
    expected.update(buf[:checksum])
    expected.update(buf[checksum + 4 : cert_entry])
    expected.update(buf[cert_entry + 8 : headers_size])
    expected.update(section_data)
    return bytes(buf), expected.hexdigest()


def test_authenticate_ak_rejects_duplicate_json_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_wcm_stub(monkeypatch)
    b1_packet, b1_policy, b1_challenge = _real_b1()
    appraised = x.appraise(
        b1_packet, object(), b1_policy, expected_challenge=b1_challenge
    )
    assert appraised["observed_application"] == "sha256:" + b1_policy.required_application

    n_b64 = _b64url(AK.public_key().public_numbers().n.to_bytes(256, "big"))
    other_n_b64 = _b64url(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_numbers()
        .n.to_bytes(256, "big")
    )
    dup_top_level = (
        b'{"keys":[{"kid":"other","kty":"RSA","e":"AQAB","n":"'
        + other_n_b64.encode("ascii")
        + b'"}],"keys":[{"kid":"HCLAkPub","kty":"RSA","e":"AQAB","n":"'
        + n_b64.encode("ascii")
        + b'"}]}'
    )
    with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
        x.authenticate_ak(_hcl_packet(dup_top_level), object())

    dup_jwk_key = (
        b'{"keys":[{"kid":"HCLAkPub","kty":"RSA","e":"AQAB","n":"'
        + other_n_b64.encode("ascii")
        + b'","n":"'
        + n_b64.encode("ascii")
        + b'"}]}'
    )
    with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
        x.authenticate_ak(_hcl_packet(dup_jwk_key), object())


def test_runtime_claims_rejects_duplicate_json_keys() -> None:
    b1_packet, _, _ = _real_b1()
    assert x._runtime_claims(b1_packet) == {
        "vm_id": "ca2e2e97-d879-49b7-ab25-f10ac9bd8667",
        "secure_boot": False,
    }

    dup_vm_id = (
        b'{"vm-configuration":{"vmUniqueId":"not-a-uuid",'
        b'"vmUniqueId":"ca2e2e97-d879-49b7-ab25-f10ac9bd8667","secure-boot":false}}'
    )
    with pytest.raises(x.ExecutionDenied, match="^hcl_vm_configuration$"):
        x._runtime_claims(_hcl_packet(dup_vm_id))

    dup_secboot = (
        b'{"vm-configuration":{"vmUniqueId":"ca2e2e97-d879-49b7-ab25-f10ac9bd8667",'
        b'"secure-boot":true,"secure-boot":false}}'
    )
    with pytest.raises(x.ExecutionDenied, match="^hcl_vm_configuration$"):
        x._runtime_claims(_hcl_packet(dup_secboot))


def test_authenticate_ak_rejects_non_rsa_kty(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_wcm_stub(monkeypatch)
    b1_packet, _, _ = _real_b1()
    assert x.authenticate_ak(b1_packet, object()).public_numbers().e == 65537

    valid_n = _b64url(AK.public_key().public_numbers().n.to_bytes(256, "big"))
    for bad_jwk in (
        {"kid": "HCLAkPub", "e": "AQAB", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "EC", "e": "AQAB", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "OKP", "e": "AQAB", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "oct", "e": "AQAB", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "rsa", "e": "AQAB", "n": valid_n},
    ):
        with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
            x.authenticate_ak(_hcl_packet(jwk=bad_jwk), object())


def test_authenticate_ak_rejects_invalid_or_noncanonical_exponent_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_wcm_stub(monkeypatch)
    assert x.authenticate_ak(_hcl_packet(), object()).public_numbers().e == 65537

    valid_n = _b64url(AK.public_key().public_numbers().n.to_bytes(256, "big"))
    for bad_jwk in (
        {"kid": "HCLAkPub", "kty": "RSA", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": 65537, "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": None, "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "A", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB=", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB$", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": _b64url(b"\x00\x01\x00\x01"), "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "AQB", "n": valid_n},
        {"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB", "n": "A" * 341},
    ):
        with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
            x.authenticate_ak(_hcl_packet(jwk=bad_jwk), object())


def test_authenticate_ak_rejects_sub_2048_bit_modulus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_wcm_stub(monkeypatch)
    assert x.authenticate_ak(_hcl_packet(), object()).public_numbers().n.bit_length() == 2048

    for small_int, byte_len in (((1 << 1023) | 1, 128), ((1 << 2047) - 1, 256)):
        small_n = _b64url(small_int.to_bytes(byte_len, "big"))
        small_key = rsa.RSAPublicNumbers(65537, small_int).public_key()
        bad_jwk = {"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB", "n": small_n}
        with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
            x.authenticate_ak(_hcl_packet(jwk=bad_jwk, ak_pem=_ak_pem(small_key)), object())


def test_authenticate_ak_rejects_non_65537_exponent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_wcm_stub(monkeypatch)
    assert x.authenticate_ak(_hcl_packet(), object()).public_numbers().e == 65537

    valid_n = _b64url(AK.public_key().public_numbers().n.to_bytes(256, "big"))
    for bad_e in (
        _b64url((3).to_bytes(1, "big")),
        _b64url((17).to_bytes(1, "big")),
        _b64url((65539).to_bytes(3, "big")),
    ):
        bad_jwk = {"kid": "HCLAkPub", "kty": "RSA", "e": bad_e, "n": valid_n}
        with pytest.raises(x.ExecutionDenied, match="^hcl_ak$"):
            x.authenticate_ak(_hcl_packet(jwk=bad_jwk), object())


def test_authenticate_ak_rejects_mismatched_ak_pem_exponent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_wcm_stub(monkeypatch)
    good_ak = x.authenticate_ak(_hcl_packet(), object())
    assert (good_ak.public_numbers().n, good_ak.public_numbers().e) == (
        AK.public_key().public_numbers().n,
        65537,
    )

    mismatched_e_key = rsa.RSAPublicNumbers(3, AK.public_key().public_numbers().n).public_key()
    with pytest.raises(x.ExecutionDenied, match="^ak_not_hcl_bound$"):
        x.authenticate_ak(_hcl_packet(ak_pem=_ak_pem(mismatched_e_key)), object())


def test_secure_boot_state_rejects_non_bytes_and_short_event_data() -> None:
    b1_packet, _, _ = _real_b1()
    b1_events = x.parse_uefi_log(base64.b64decode(b1_packet["uefi_event_log_b64"]))
    assert x._secure_boot_state(b1_events) is False

    short_data = bytes(20)
    short_ev = x.UefiEvent(
        pcr=7,
        event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256=hashlib.sha256(short_data).digest(),
        data=short_data,
    )
    with pytest.raises(x.ExecutionDenied, match="^secure_boot_state$"):
        x._secure_boot_state([short_ev])

    non_bytes_ev = x.UefiEvent(
        pcr=7,
        event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256=bytes(32),
        data=cast(Any, None),
    )
    with pytest.raises(x.ExecutionDenied, match="^secure_boot_state$"):
        x._secure_boot_state([non_bytes_ev])


def test_secure_boot_state_rejects_mismatched_variable_payload_length() -> None:
    name_utf16 = "SecureBoot".encode("utf-16-le")
    valid_data = bytes(16) + struct.pack("<QQ", len("SecureBoot"), 1) + name_utf16 + b"\x01"
    valid_ev = x.UefiEvent(
        pcr=7,
        event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256=hashlib.sha256(valid_data).digest(),
        data=valid_data,
    )
    assert x._secure_boot_state([valid_ev]) is True

    truncated_data = bytes(16) + struct.pack("<QQ", len("SecureBoot"), 9999) + name_utf16 + b"\x01"
    truncated_name = bytes(16) + struct.pack("<QQ", 10, 1) + name_utf16[:6] + b"\x01"
    trailing_bytes = (
        bytes(16) + struct.pack("<QQ", len("SecureBoot"), 1) + name_utf16 + b"\x01\x00"
    )
    for bad_payload in (truncated_data, truncated_name, trailing_bytes):
        ev = x.UefiEvent(
            pcr=7,
            event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
            sha256=hashlib.sha256(bad_payload).digest(),
            data=bad_payload,
        )
        with pytest.raises(x.ExecutionDenied, match="^secure_boot_state$"):
            x._secure_boot_state([ev])


def test_secure_boot_state_rejects_invalid_utf16_variable_name() -> None:
    name_utf16 = "SecureBoot".encode("utf-16-le")
    valid_data = bytes(16) + struct.pack("<QQ", len("SecureBoot"), 1) + name_utf16 + b"\x01"
    valid_ev = x.UefiEvent(
        pcr=7,
        event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256=hashlib.sha256(valid_data).digest(),
        data=valid_data,
    )
    assert x._secure_boot_state([valid_ev]) is True

    surrogate_name = bytes(16) + struct.pack("<QQ", 1, 1) + b"\x00\xd8" + b"\x01"
    ev = x.UefiEvent(
        pcr=7,
        event_type=x.EV_EFI_VARIABLE_DRIVER_CONFIG,
        sha256=hashlib.sha256(surrogate_name).digest(),
        data=surrogate_name,
    )
    with pytest.raises(x.ExecutionDenied, match="^secure_boot_state$"):
        x._secure_boot_state([ev])


def test_authenticode_sha256_rejects_non_bytes_and_truncated_pe_headers() -> None:
    pe64, expected64 = _build_pe_image(magic=0x20B, cert_bytes=b"CERT" * 8)
    assert x.authenticode_sha256(pe64) == expected64

    pe32, expected32 = _build_pe_image(magic=0x10B, cert_bytes=b"")
    assert x.authenticode_sha256(pe32) == expected32

    for non_pe in (
        cast(Any, None),
        cast(Any, "MZ"),
        cast(Any, bytearray(pe64)),
        b"MZ" + bytes(20),
        b"MZ" + bytes(0x3A) + struct.pack("<I", 0x200) + bytes(64),
        b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\x00\x00" + bytes(16),
    ):
        with pytest.raises(ValueError, match="^not a PE image$"):
            x.authenticode_sha256(non_pe)

    truncated_optional = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\x00\x00" + bytes(20)
    with pytest.raises(ValueError, match="^malformed PE image$"):
        x.authenticode_sha256(truncated_optional)


def test_authenticode_sha256_rejects_unknown_optional_header_magic() -> None:
    pe64, expected64 = _build_pe_image(magic=0x20B)
    assert x.authenticode_sha256(pe64) == expected64

    bad_magic = bytearray(pe64)
    struct.pack_into("<H", bad_magic, 0x40 + 24, 0x999)
    with pytest.raises(ValueError, match="^malformed PE image$"):
        x.authenticode_sha256(bytes(bad_magic))


def test_authenticode_sha256_rejects_out_of_bounds_header_and_section_table_sizes() -> None:
    pe64, expected64 = _build_pe_image(magic=0x20B)
    assert x.authenticode_sha256(pe64) == expected64

    small_opt = bytearray(pe64)
    struct.pack_into("<H", small_opt, 0x40 + 20, 32)

    oversized_headers = bytearray(pe64)
    struct.pack_into("<I", oversized_headers, 0x40 + 24 + 60, len(pe64) + 64)

    too_many_sections = bytearray(pe64)
    struct.pack_into("<H", too_many_sections, 0x40 + 6, 20)

    for malformed in (bytes(small_opt), bytes(oversized_headers), bytes(too_many_sections)):
        with pytest.raises(ValueError, match="^malformed PE image$"):
            x.authenticode_sha256(malformed)


def test_authenticode_sha256_rejects_invalid_certificate_table_bounds() -> None:
    pe64, expected64 = _build_pe_image(magic=0x20B, cert_bytes=b"CERT" * 8)
    assert x.authenticode_sha256(pe64) == expected64

    cert_entry = 0x40 + 24 + 112 + 32

    oob_cert = bytearray(pe64)
    struct.pack_into("<II", oob_cert, cert_entry, 512, 4096)

    cert_in_headers = bytearray(pe64)
    struct.pack_into("<II", cert_in_headers, cert_entry, 256, 32)

    zero_offset_nonzero_cert = bytearray(pe64)
    struct.pack_into("<II", zero_offset_nonzero_cert, cert_entry, 0, 32)

    for malformed in (bytes(oob_cert), bytes(cert_in_headers), bytes(zero_offset_nonzero_cert)):
        with pytest.raises(ValueError, match="^malformed PE image$"):
            x.authenticode_sha256(malformed)


def test_authenticode_sha256_rejects_overlapping_or_out_of_bounds_sections() -> None:
    pe64, expected64 = _build_pe_image(magic=0x20B, cert_bytes=b"CERT" * 8)
    assert x.authenticode_sha256(pe64) == expected64

    table = 0x40 + 24 + 240

    oob_section = bytearray(pe64)
    struct.pack_into("<II", oob_section, table + 16, 4096, 512)

    header_overlapping_section = bytearray(pe64)
    struct.pack_into("<II", header_overlapping_section, table + 16, 64, 256)

    for malformed in (bytes(oob_section), bytes(header_overlapping_section)):
        with pytest.raises(ValueError, match="^malformed PE image$"):
            x.authenticode_sha256(malformed)
