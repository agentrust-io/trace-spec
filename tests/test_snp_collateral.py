"""SEV-SNP collateral appraisal against real Azure packets and AMD KDS CRLs (30 Sept 2026)."""

import base64
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509

from prototype import snp_collateral as s
from tests.test_azure_execution_binding import FIXTURES as EXEC, _wcm

FIXTURES = Path(__file__).parent / "fixtures" / "snp-collateral-20260930"
NOW = datetime(2026, 9, 30, 5, 0, tzinfo=UTC)  # inside both CRL windows
SB_3016 = "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html"
# AMD-SB-3016 (2026-04-14): TCB[SNP] >= 0x1B for Milan and Genoa, plus an OS
# update signalled by SEV mitigation vector bit 2.
FLOOR = s.TcbFloor(snp=0x1B, source=SB_3016, os_mitigation_bit=2)


def packets():
    milan = json.loads((FIXTURES / "live-milan-packet.json").read_text(encoding="utf-8"))
    genoa = json.loads((EXEC / "b1-approved-packet.json").read_text(encoding="utf-8"))
    return milan, genoa


def arks():
    _, _ = _wcm()  # asserts the pinned AMD root hash
    root = Path(__file__).resolve().parents[2] / "cloud-20260929" / "amd-root.pem"
    return {
        "Milan": x509.load_pem_x509_certificate(root.read_bytes()),
        "Genoa": x509.load_pem_x509_certificate((EXEC / "ark-genoa.pem").read_bytes()),
    }


def policy(**changes):
    base = s.CollateralPolicy(
        floors={"Milan": FLOOR, "Genoa": FLOOR},
        arks=arks(),
        crls={p: (FIXTURES / f"amd-{p}.crl").read_bytes() for p in ("Milan", "Genoa")},
    )
    return dataclasses.replace(base, **changes)


def denied(packet, pol=None, now=NOW):
    with pytest.raises(s.CollateralDenied) as caught:
        s.appraise_collateral(packet, pol or policy(), now=now)
    return str(caught.value)


def test_live_milan_platform_is_genuine_but_below_the_sb3016_floor():
    milan, _ = packets()
    result = s.appraise_collateral(milan, policy(), now=NOW)
    assert result["product"] == "Milan" and result["report_version"] == 3
    assert result["reported_tcb"] == {"bootloader": 4, "tee": 0, "snp": 24, "microcode": 219}
    assert result["reported_tcb"] == result["committed_tcb"] == result["launch_tcb"]
    assert result["firmware"] == "1.55.29"
    assert result["status"] == "contraindicated"
    assert result["reasons"] == ["tcb_snp_below_floor"]
    assert result["os_mitigation"] == "unproven_report_version"
    assert result["crl"]["revoked"] == 0 and result["vcek_serial_zero"]


def test_genoa_platform_from_the_earlier_run_is_also_below_the_floor():
    _, genoa = packets()
    result = s.appraise_collateral(genoa, policy(), now=NOW)
    assert result["product"] == "Genoa"
    assert result["reported_tcb"]["snp"] == 23
    assert (result["status"], result["reasons"]) == ("contraindicated", ["tcb_snp_below_floor"])
    assert result["crl"]["revoked"] == 1  # the Genoa CRL is not empty; the ASK is not on it


def test_floor_and_os_mitigation_are_each_causal():
    milan, _ = packets()
    lowered = dataclasses.replace(FLOOR, snp=24)
    pol = policy(floors={"Milan": lowered})
    result = s.appraise_collateral(milan, pol, now=NOW)
    # Firmware floor met; a version 3 report cannot prove the OS half of SB-3016.
    assert (result["status"], result["reasons"]) == ("contraindicated", ["os_mitigation_unproven"])
    accepted = dataclasses.replace(pol, accept_unproven_os_mitigation=True)
    assert s.appraise_collateral(milan, accepted, now=NOW)["status"] == "warning"
    firmware_only = dataclasses.replace(lowered, os_mitigation_bit=None)
    result = s.appraise_collateral(milan, policy(floors={"Milan": firmware_only}), now=NOW)
    assert (result["status"], result["reasons"]) == ("affirming", [])
    raised = dataclasses.replace(firmware_only, microcode=220)
    result = s.appraise_collateral(milan, policy(floors={"Milan": raised}), now=NOW)
    assert result["reasons"] == ["tcb_microcode_below_floor"]


def test_product_line_must_be_accepted_and_pinned():
    milan, genoa = packets()
    assert denied(milan, policy(floors={"Genoa": FLOOR})) == "product_not_accepted"
    swapped = arks()
    swapped["Milan"] = swapped["Genoa"]
    assert denied(milan, policy(arks=swapped)) == "product_chain"
    assert denied(genoa, policy(arks={"Milan": arks()["Milan"]})) == "product_chain"


def test_crl_must_be_present_signed_by_the_product_ark_and_current():
    milan, _ = packets()
    assert denied(milan, policy(crls={})) == "crl_missing"
    genoa_crl = (FIXTURES / "amd-Genoa.crl").read_bytes()
    assert denied(milan, policy(crls={"Milan": genoa_crl})) == "crl_signature"
    assert denied(milan, policy(crls={"Milan": b"\x30\x00"})) == "crl_format"
    assert denied(milan, now=datetime(2026, 11, 9, 1, 0, tzinfo=UTC)) == "crl_stale"
    assert denied(milan, now=datetime(2026, 9, 22, 7, 35, tzinfo=UTC)) == "crl_stale"
    assert s.appraise_collateral(milan, policy(), now=NOW + timedelta(days=39))


def test_revoked_ask_is_denied(monkeypatch):
    """The real Genoa CRL revokes serial 131073; an ASK carrying it must fail."""
    _wcm()  # skips when the pinned WCM verifier snapshot is absent
    _, genoa = packets()
    crl = x509.load_der_x509_crl((FIXTURES / "amd-Genoa.crl").read_bytes())
    assert [c.serial_number for c in crl] == [131073]
    from wcm import _certificates

    original = _certificates.load_pem_certificate

    class Revoked:
        def __init__(self, cert):
            self._cert = cert

        def __getattr__(self, name):
            return getattr(self._cert, name)

        serial_number = 131073

    def load(data, **kwargs):
        cert = original(data, **kwargs)
        return Revoked(cert) if s._cn(cert.subject) == "SEV-Genoa" else cert

    monkeypatch.setattr(_certificates, "load_pem_certificate", load)
    assert denied(genoa) == "ask_revoked"


def _with_report(packet, offset, value):
    hcl = bytearray(base64.b64decode(packet["hcl_b64"]))
    start = 32 + offset  # HCL header precedes the report
    hcl[start : start + len(value)] = value
    return dict(packet, hcl_b64=base64.b64encode(bytes(hcl)).decode())


def test_report_must_state_the_certified_tcb_chip_and_product():
    """authenticate_ak rejects these edits by signature; this checks the collateral gate itself."""
    milan, _ = packets()
    assert denied(_with_report(milan, s._REPORTED_TCB + 6, b"\x1b")) == "vcek_tcb_mismatch"
    assert denied(_with_report(milan, s._CHIP_ID, b"\x00")) == "vcek_chip_mismatch"
    assert denied(_with_report(milan, s._CPUID + 1, b"\x11")) == "cpuid_product_mismatch"


def test_policy_rejects_malformed_floors():
    with pytest.raises(s.CollateralDenied, match="policy_floor"):
        s.TcbFloor(snp=256, source=SB_3016)
    with pytest.raises(s.CollateralDenied, match="policy_floor"):
        s.TcbFloor(snp=27)
    with pytest.raises(s.CollateralDenied, match="policy_products"):
        s.CollateralPolicy(floors={"Turin": FLOOR}, arks={}, crls={})


def test_negative_verdict_becomes_an_honest_runtime_component():
    from prototype.verifier_token import canonical_digest

    milan, _ = packets()
    result = s.appraise_collateral(milan, policy(), now=NOW)
    now = int(NOW.timestamp())
    c = s.tcb_component(
        result,
        milan,
        instance="azure-vm/30dbc542-3653-43ce-b482-885a3eedfc23",
        authority="https://verifier.example.test",
        now=now,
    )
    assert (c.component_id, c.component_type, c.status) == (
        "runtime.cpu",
        "runtime",
        "contraindicated",
    )
    assert c.reasons == ["tcb_snp_below_floor"]
    assert c.evidence_refs[0].digest == canonical_digest(milan)


def test_der_uint_rejects_negative_non_minimal_and_out_of_range_integers():
    assert s._der_uint(b"\x02\x01\x00") == 0
    assert s._der_uint(b"\x02\x01\x7f") == 127
    assert s._der_uint(b"\x02\x02\x00\x80") == 128
    assert s._der_uint(b"\x02\x02\x00\xdb") == 219
    assert s._der_uint(b"\x02\x02\x00\xff") == 255

    for bad in (
        b"\x02\x01\x80",
        b"\x02\x01\xff",
        b"\x02\x02\xff\x00",
        b"\x02\x02\x00\x00",
        b"\x02\x02\x00\x05",
        b"\x02\x02\x00\x7f",
        b"\x02\x03\x00\x00\x80",
        b"\x02\x02\x01\x00",
        b"\x02\x03\x00\x80\x00",
        None,
        "020105",
        bytearray(b"\x02\x01\x05"),
        b"\x02\x00",
        b"\x04\x01\x05",
        b"\x02\x02\x05",
    ):
        with pytest.raises(s.CollateralDenied, match="^vcek_extension_encoding$"):
            s._der_uint(bad)  # type: ignore[arg-type]


def test_tcb_floor_rejects_non_string_source_and_non_int_os_mitigation_bit():
    floor = s.TcbFloor(
        bootloader=4, tee=0, snp=27, microcode=219, source=SB_3016, os_mitigation_bit=2
    )
    assert floor.os_mitigation_bit == 2 and floor.source == SB_3016

    for bad_source in ("", None, [1], 123, {"url": SB_3016}):
        with pytest.raises(s.CollateralDenied, match="^policy_floor$"):
            s.TcbFloor(snp=27, source=bad_source)  # type: ignore[arg-type]

    for bad_bit in (True, False, 1.5, "2", -1, 64, [2]):
        with pytest.raises(s.CollateralDenied, match="^policy_floor$"):
            s.TcbFloor(snp=27, source=SB_3016, os_mitigation_bit=bad_bit)  # type: ignore[arg-type]


def test_collateral_policy_validates_floors_arks_crls_and_limits_types():
    valid = s.CollateralPolicy(floors={"Milan": FLOOR}, arks={}, crls={}, limits=["note"])
    assert valid.limits == ["note"]

    for bad_floors in (None, [], "Milan", {1: FLOOR}):
        with pytest.raises(s.CollateralDenied, match="^policy_products$"):
            s.CollateralPolicy(floors=bad_floors, arks={}, crls={})  # type: ignore[arg-type]

    for bad_floor_val in (None, {"snp": 27}, "floor", 27):
        with pytest.raises(s.CollateralDenied, match="^policy_floor$"):
            s.CollateralPolicy(
                floors={"Milan": bad_floor_val},  # type: ignore[dict-item]
                arks={},
                crls={},
            )

    for bad_arks in (None, [], {"Milan": "not-a-cert"}, {1: None}):
        with pytest.raises(s.CollateralDenied, match="^policy_arks$"):
            s.CollateralPolicy(
                floors={"Milan": FLOOR},
                arks=bad_arks,  # type: ignore[arg-type]
                crls={},
            )

    for bad_crls in (None, [], {"Milan": "not-bytes"}, {"Milan": bytearray(b"x")}, {1: b"x"}):
        with pytest.raises(s.CollateralDenied, match="^policy_crls$"):
            s.CollateralPolicy(
                floors={"Milan": FLOOR},
                arks={},
                crls=bad_crls,  # type: ignore[arg-type]
            )

    for bad_limits in (None, ("note",), "note", [1], ["ok", None]):
        with pytest.raises(s.CollateralDenied, match="^policy_limits$"):
            s.CollateralPolicy(
                floors={"Milan": FLOOR},
                arks={},
                crls={},
                limits=bad_limits,  # type: ignore[arg-type]
            )


def test_appraise_collateral_validates_packet_policy_and_timezone_aware_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    from types import ModuleType

    wcm_mod = ModuleType("wcm")
    certs_mod = ModuleType("wcm._certificates")
    snp_mod = ModuleType("wcm.snp")
    certs_mod.load_pem_certificate = (  # type: ignore[attr-defined]
        lambda pem, **kw: x509.load_pem_x509_certificate(pem)
    )
    snp_mod.extract_snp_report_from_hcl = (  # type: ignore[attr-defined]
        lambda hcl: hcl[32 : 32 + 1184]
    )
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)

    milan, _ = packets()
    valid_policy = s.CollateralPolicy(floors={"Milan": FLOOR}, arks={}, crls={})

    for bad_policy in (None, {}, "policy"):
        with pytest.raises(s.CollateralDenied, match="^policy_inputs$"):
            s.appraise_collateral(milan, bad_policy, now=NOW)  # type: ignore[arg-type]

    for bad_now in (None, 1790683200, "2026-09-30T05:00:00Z", datetime(2026, 9, 30, 5, 0)):
        with pytest.raises(s.CollateralDenied, match="^clock_or_age$"):
            s.appraise_collateral(milan, valid_policy, now=bad_now)  # type: ignore[arg-type]

    for bad_packet in (
        None,
        [],
        "packet",
        {},
        {**milan, "hcl_b64": b"bytes"},
        {**milan, "vcek_pem": b"bytes"},
        {**milan, "intermediates_pem": "not-a-list"},
        {**milan, "intermediates_pem": [b"bytes"]},
        {**milan, "intermediates_pem": [None]},
    ):
        with pytest.raises(s.CollateralDenied, match="^platform_evidence_format$"):
            s.appraise_collateral(bad_packet, valid_policy, now=NOW)  # type: ignore[arg-type]


def test_appraise_collateral_rejects_vcek_with_negative_or_non_minimal_der_tcb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    from types import ModuleType

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    milan, _ = packets()
    hcl_raw = base64.b64decode(milan["hcl_b64"])
    report_raw = bytearray(hcl_raw[32 : 32 + 1184])
    hwid = bytes(report_raw[s._CHIP_ID : s._CHIP_ID + 64])

    wcm_mod = ModuleType("wcm")
    certs_mod = ModuleType("wcm._certificates")
    snp_mod = ModuleType("wcm.snp")
    certs_mod.load_pem_certificate = (  # type: ignore[attr-defined]
        lambda pem, **kw: x509.load_pem_x509_certificate(pem)
    )
    snp_mod.extract_snp_report_from_hcl = (  # type: ignore[attr-defined]
        lambda hcl: hcl[32 : 32 + 1184]
    )
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)

    ark_key = ec.generate_private_key(ec.SECP384R1())
    ask_key = ec.generate_private_key(ec.SECP384R1())
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ARK-Milan")])
    ask_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-Milan")])
    vcek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-VCEK")])

    ark_cert = (
        x509.CertificateBuilder()
        .subject_name(ark_name)
        .issuer_name(ark_name)
        .public_key(ark_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(ark_key, hashes.SHA384())
    )
    ask_cert = (
        x509.CertificateBuilder()
        .subject_name(ask_name)
        .issuer_name(ark_name)
        .public_key(ask_key.public_key())
        .serial_number(2)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(ark_key, hashes.SHA384())
    )
    crl_der = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ark_name)
        .last_update(NOW - timedelta(hours=1))
        .next_update(NOW + timedelta(days=7))
        .sign(ark_key, hashes.SHA384())
        .public_bytes(serialization.Encoding.DER)
    )
    ask_pem = ask_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pol = s.CollateralPolicy(
        floors={"Milan": FLOOR},
        arks={"Milan": ark_cert},
        crls={"Milan": crl_der},
    )

    def _pkt(snp_der: bytes, snp_report_byte: int = 24) -> dict[str, object]:
        mut_hcl = bytearray(hcl_raw)
        mut_hcl[32 + s._REPORTED_TCB + 6] = snp_report_byte
        builder = (
            x509.CertificateBuilder()
            .subject_name(vcek_name)
            .issuer_name(ask_name)
            .public_key(vcek_key.public_key())
            .serial_number(3)
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(s._VCEK_OIDS["bootloader"]), b"\x02\x01\x04"
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._VCEK_OIDS["tee"]), b"\x02\x01\x00"),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._VCEK_OIDS["snp"]), snp_der),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(s._VCEK_OIDS["microcode"]), b"\x02\x02\x00\xdb"
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._HWID_OID), hwid),
                critical=False,
            )
        )
        vcek_pem = (
            builder.sign(ask_key, hashes.SHA384())
            .public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
        )
        return {
            "hcl_b64": base64.b64encode(bytes(mut_hcl)).decode("ascii"),
            "vcek_pem": vcek_pem,
            "intermediates_pem": [ask_pem],
        }

    ok = s.appraise_collateral(_pkt(b"\x02\x01\x18", 24), pol, now=NOW)
    assert ok["reported_tcb"]["snp"] == 24

    # Non-minimal leading zero for 24 (0x00 0x18) must be rejected.
    with pytest.raises(s.CollateralDenied, match="^vcek_extension_encoding$"):
        s.appraise_collateral(_pkt(b"\x02\x02\x00\x18", 24), pol, now=NOW)

    # Negative DER integer -128 (0x80) must not be accepted as +128.
    with pytest.raises(s.CollateralDenied, match="^vcek_extension_encoding$"):
        s.appraise_collateral(_pkt(b"\x02\x01\x80", 128), pol, now=NOW)


def test_tcb_component_validates_appraisal_packet_and_identifiers():
    milan, _ = packets()
    valid_appraisal = {
        "profile": s.PROFILE,
        "status": "contraindicated",
        "reasons": ["tcb_snp_below_floor"],
    }
    now = int(NOW.timestamp())
    comp = s.tcb_component(
        valid_appraisal,
        milan,
        instance="azure-vm/test",
        authority="https://verifier.example.test",
        now=now,
    )
    assert comp.status == "contraindicated"

    for bad_appraisal in (
        None,
        [],
        {},
        {"status": "affirming", "reasons": []},
        {"profile": s.PROFILE, "status": 123, "reasons": []},
        {"profile": s.PROFILE, "status": "affirming", "reasons": "not-a-list"},
        {"profile": s.PROFILE, "status": "affirming", "reasons": [123]},
        {"profile": s.PROFILE, "status": "not-a-valid-status", "reasons": []},
    ):
        with pytest.raises(s.CollateralDenied, match="^component_inputs$"):
            s.tcb_component(
                bad_appraisal,  # type: ignore[arg-type]
                milan,
                instance="azure-vm/test",
                authority="https://verifier.example.test",
                now=now,
            )

    for bad_packet in (None, [], "packet"):
        with pytest.raises(s.CollateralDenied, match="^component_inputs$"):
            s.tcb_component(
                valid_appraisal,
                bad_packet,  # type: ignore[arg-type]
                instance="azure-vm/test",
                authority="https://verifier.example.test",
                now=now,
            )

    for bad_id in ("", None, 123):
        with pytest.raises(s.CollateralDenied, match="^component_inputs$"):
            s.tcb_component(
                valid_appraisal,
                milan,
                instance=bad_id,  # type: ignore[arg-type]
                authority="https://verifier.example.test",
                now=now,
            )
        with pytest.raises(s.CollateralDenied, match="^component_inputs$"):
            s.tcb_component(
                valid_appraisal,
                milan,
                instance="azure-vm/test",
                authority=bad_id,  # type: ignore[arg-type]
                now=now,
            )


@pytest.mark.parametrize(
    ("case", "expected_reason"),
    [
        ("wrong_signer", "product_chain"),
        ("extra_issuer_rdn", "product_chain"),
        ("non_canonical_hcl_b64", "platform_evidence_format"),
        ("version_1", "platform_evidence_format"),
    ],
)
def test_appraise_collateral_verifies_vcek_issuer_and_signature_and_report_bounds(
    monkeypatch: pytest.MonkeyPatch, case: str, expected_reason: str
) -> None:
    import sys
    from types import ModuleType

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    milan, _ = packets()
    hcl_raw = base64.b64decode(milan["hcl_b64"])
    report_raw = bytearray(hcl_raw[32 : 32 + 1184])
    hwid = bytes(report_raw[s._CHIP_ID : s._CHIP_ID + 64])

    wcm_mod = ModuleType("wcm")
    certs_mod = ModuleType("wcm._certificates")
    snp_mod = ModuleType("wcm.snp")
    certs_mod.load_pem_certificate = (  # type: ignore[attr-defined]
        lambda pem, **kw: x509.load_pem_x509_certificate(pem)
    )
    snp_mod.extract_snp_report_from_hcl = (  # type: ignore[attr-defined]
        lambda hcl: hcl[32 : 32 + 1184]
    )
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)

    ark_key = ec.generate_private_key(ec.SECP384R1())
    ask_key = ec.generate_private_key(ec.SECP384R1())
    wrong_ask_key = ec.generate_private_key(ec.SECP384R1())
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ARK-Milan")])
    ask_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-Milan")])
    extra_issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SEV-Milan"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Other"),
        ]
    )
    vcek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-VCEK")])

    ark_cert = (
        x509.CertificateBuilder()
        .subject_name(ark_name)
        .issuer_name(ark_name)
        .public_key(ark_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(ark_key, hashes.SHA384())
    )
    ask_cert = (
        x509.CertificateBuilder()
        .subject_name(ask_name)
        .issuer_name(ark_name)
        .public_key(ask_key.public_key())
        .serial_number(2)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(ark_key, hashes.SHA384())
    )
    crl_der = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ark_name)
        .last_update(NOW - timedelta(hours=1))
        .next_update(NOW + timedelta(days=7))
        .sign(ark_key, hashes.SHA384())
        .public_bytes(serialization.Encoding.DER)
    )
    ask_pem = ask_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pol = s.CollateralPolicy(
        floors={"Milan": FLOOR},
        arks={"Milan": ark_cert},
        crls={"Milan": crl_der},
    )

    def _build_vcek(issuer: x509.Name, signer: ec.EllipticCurvePrivateKey) -> str:
        return (
            x509.CertificateBuilder()
            .subject_name(vcek_name)
            .issuer_name(issuer)
            .public_key(vcek_key.public_key())
            .serial_number(3)
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(s._VCEK_OIDS["bootloader"]), b"\x02\x01\x04"
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._VCEK_OIDS["tee"]), b"\x02\x01\x00"),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._VCEK_OIDS["snp"]), b"\x02\x01\x18"),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier(s._VCEK_OIDS["microcode"]), b"\x02\x02\x00\xdb"
                ),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(s._HWID_OID), hwid),
                critical=False,
            )
            .sign(signer, hashes.SHA384())
            .public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
        )

    valid_pkt = {
        "hcl_b64": milan["hcl_b64"],
        "vcek_pem": _build_vcek(ask_name, ask_key),
        "intermediates_pem": [ask_pem],
    }
    assert s.appraise_collateral(valid_pkt, pol, now=NOW)["product"] == "Milan"

    if case == "wrong_signer":
        bad_pkt = {**valid_pkt, "vcek_pem": _build_vcek(ask_name, wrong_ask_key)}
    elif case == "extra_issuer_rdn":
        bad_pkt = {**valid_pkt, "vcek_pem": _build_vcek(extra_issuer_name, ask_key)}
    elif case == "non_canonical_hcl_b64":
        bad_pkt = {**valid_pkt, "hcl_b64": milan["hcl_b64"][:-2] + "B="}
    else:
        v1_hcl = bytearray(hcl_raw)
        v1_hcl[32 + s._VERSION : 32 + s._VERSION + 4] = (1).to_bytes(4, "little")
        bad_pkt = {
            **valid_pkt,
            "hcl_b64": base64.b64encode(bytes(v1_hcl)).decode("ascii"),
        }
    with pytest.raises(s.CollateralDenied, match=f"^{expected_reason}$"):
        s.appraise_collateral(bad_pkt, pol, now=NOW)


@pytest.mark.parametrize(
    ("bad_now", "bad_appraisal", "expected_reason"),
    [
        (0, {"profile": s.PROFILE, "status": "affirming", "reasons": []}, "clock_or_age"),
        (
            9_007_199_254_740_991,
            {"profile": s.PROFILE, "status": "affirming", "reasons": []},
            "clock_or_age",
        ),
        (
            1790683200,
            {"status": "affirming", "reasons": []},
            "component_inputs",
        ),
        (
            1790683200,
            {"profile": "other-profile", "status": "affirming", "reasons": []},
            "component_inputs",
        ),
    ],
)
def test_tcb_component_rejects_zero_or_overflow_now_and_wrong_profile(
    bad_now: int, bad_appraisal: dict[str, object], expected_reason: str
) -> None:
    milan, _ = packets()
    with pytest.raises(s.CollateralDenied, match=f"^{expected_reason}$"):
        s.tcb_component(
            bad_appraisal,
            milan,
            instance="azure-vm/test",
            authority="https://verifier.example.test",
            now=bad_now,
        )


# What the signature check cannot verify, as (issuer key kind, part of the chain, defect, reason).
# A signature defect names the certificate or CRL that carries the signature. A key defect names
# the issuer certificate whose own key it is: the ASK for the VCEK, the ARK for the ASK.
_SIGNED_PARTS = (("vcek", "product_chain"), ("ask", "product_chain"), ("crl", "crl_signature"))
_UNVERIFIABLE = (
    [
        (issuer_keys, part, defect, reason)
        for issuer_keys in ("ec", "rsa")
        for part, reason in _SIGNED_PARTS
        for defect in (
            "ed25519_signature",
            "ed448_signature",
            "unknown_signature_algorithm",
            "id_alg_unsigned_identifier",
        )
    ]
    + [
        ("rsa", part, defect, reason)
        for part, reason in _SIGNED_PARTS
        for defect in ("pss_unknown_mask_function", "pss_unknown_mask_hash")
    ]
    + [("rsa", part, "pss_outer_parameters_absent", "product_chain") for part in ("vcek", "ask")]
    + [
        (issuer_keys, part, "outer_identifier_id_alg_unsigned", "product_chain")
        for issuer_keys in ("ec", "rsa")
        for part in ("vcek", "ask")
    ]
    + [
        ("ec", part, defect, "product_chain")
        for part in ("ask", "ark")
        for defect in (
            "key_of_unknown_algorithm",
            "key_point_off_the_curve",
            "key_neither_rsa_nor_ec",
        )
    ]
    + [
        ("rsa", part, "rsa_key_too_small_for_the_pss_digest", "product_chain")
        for part in ("ask", "ark")
    ]
)


@pytest.mark.parametrize(("issuer_keys", "part", "defect", "expected_reason"), _UNVERIFIABLE)
def test_appraise_collateral_denies_what_its_signature_check_cannot_verify(
    monkeypatch: pytest.MonkeyPatch,
    issuer_keys: str,
    part: str,
    defect: str,
    expected_reason: str,
) -> None:
    """One part of an otherwise valid chain leaves a signature that cannot be verified.

    The VCEK, the ASK or the CRL carries an Ed25519 or an Ed448 signature; or a signature whose
    algorithm identifier was changed after signing, to one the library does not know or to
    id-alg-unsigned, which it maps to no hash; or an RSASSA-PSS signature whose mask generation
    function, or the hash that function uses, was changed after signing to one the library does
    not know. Or the VCEK or the ASK carries its issuer's own signature under an outer identifier
    changed after signing: to id-alg-unsigned, under an EC and under an RSA issuer, or to
    RSASSA-PSS without its parameters, under an RSA issuer. Or the ASK or the ARK carries an EC
    key relabelled as an unknown algorithm, an EC point that is not on its curve, an RSA key too
    small for the digest of an RSASSA-PSS signature, or a key that is neither RSA nor EC. Each
    is denied with the reason a forged signature gets, and no other exception leaves
    appraise_collateral.
    """
    import sys
    from types import ModuleType

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    milan, _ = packets()
    report = base64.b64decode(milan["hcl_b64"])[32 : 32 + 1184]
    reported = s._tcb(report[s._REPORTED_TCB : s._REPORTED_TCB + 8])

    wcm_mod = ModuleType("wcm")
    certs_mod = ModuleType("wcm._certificates")
    snp_mod = ModuleType("wcm.snp")
    certs_mod.load_pem_certificate = (  # type: ignore[attr-defined]
        lambda pem, **kw: x509.load_pem_x509_certificate(pem)
    )
    snp_mod.extract_snp_report_from_hcl = (  # type: ignore[attr-defined]
        lambda hcl: hcl[32 : 32 + 1184]
    )
    monkeypatch.setitem(sys.modules, "wcm", wcm_mod)
    monkeypatch.setitem(sys.modules, "wcm._certificates", certs_mod)
    monkeypatch.setitem(sys.modules, "wcm.snp", snp_mod)

    IssuerKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    Builder = x509.CertificateBuilder | x509.CertificateRevocationListBuilder
    der_encoding = serialization.Encoding.DER
    # DER object identifiers: ecdsa-with-SHA384, sha384WithRSAEncryption, id-RSASSA-PSS, id-mgf1,
    # id-sha384, id-ecPublicKey and id-alg-unsigned.
    ecdsa_with_sha384 = bytes.fromhex("06082a8648ce3d040303")
    sha384_with_rsa = bytes.fromhex("06092a864886f70d01010c")
    rsassa_pss = bytes.fromhex("06092a864886f70d01010a")
    mgf1 = bytes.fromhex("06092a864886f70d010108")
    sha384 = bytes.fromhex("0609608648016503040202")
    ec_public_key = bytes.fromhex("06072a8648ce3d0201")
    id_alg_unsigned = bytes.fromhex("06082b06010505070624")

    def issuer_key() -> IssuerKey:
        if issuer_keys == "ec":
            return ec.generate_private_key(ec.SECP384R1())
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ark_key, ask_key = issuer_key(), issuer_key()
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    another_key = ec.generate_private_key(ec.SECP384R1())
    # 256 bits, fewer than the 400 an RSASSA-PSS signature needs for a SHA-384 digest: verifying
    # one under it raises.
    small_rsa_key = rsa.RSAPublicNumbers(65537, (1 << 255) + 1).public_key()
    ed25519_key = ed25519.Ed25519PrivateKey.generate()
    hashless = {
        "ed25519_signature": ed25519_key,
        "ed448_signature": ed448.Ed448PrivateKey.generate(),
    }
    ark_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ARK-Milan")])
    ask_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-Milan")])
    vcek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-VCEK")])

    def renamed(
        der: bytes,
        identifier: bytes,
        times: int,
        to: bytes | None = None,
        only: tuple[int, ...] = (),
    ) -> bytes:
        """The same DER with one object identifier changed wherever it stands.

        Or, with `only`, at those of the places it stands, counted from 1. To `to`, of the same
        length, or else to itself with 127 as its last arc. The change is made after signing, so
        the signature no longer covers the bytes it stands on.
        """
        assert der.count(identifier) == times, (defect, der.count(identifier))
        new = to or identifier[:-1] + b"\x7f"
        pieces = der.split(identifier)
        return pieces[0] + b"".join(
            (new if not only or place in only else identifier) + piece
            for place, piece in enumerate(pieces[1:], 1)
        )

    def with_outer_algorithm(der: bytes, identifier: bytes, to: bytes) -> bytes:
        """The same certificate with its outer signature algorithm replaced by `to` alone.

        The outer algorithm is the last place `identifier` stands, and the signature does not
        cover it, so the signature stays the issuer's own. The one length written again is the
        outermost. Not for a CRL: the library does not load one whose two signature algorithms
        differ.
        """
        start = der.rindex(identifier) - 2
        end = start + 2 + der[start + 1]
        rest = der[4:start] + bytes([0x30, len(to)]) + to + der[end:]
        assert der[:2] == b"\x30\x82" and der[start] == 0x30 and len(rest) > 0xFF, defect
        return der[:2] + len(rest).to_bytes(2, "big") + rest

    def signed(builder: Builder, issuer: IssuerKey, how: str) -> bytes:
        """Sign as `issuer` does, unless `how` names a signature defect. Returns DER."""
        if how in hashless:
            return builder.sign(hashless[how], None).public_bytes(der_encoding)
        if how == "id_alg_unsigned_identifier":
            der = builder.sign(another_key, hashes.SHA384()).public_bytes(der_encoding)
            return renamed(der, ecdsa_with_sha384, 2, id_alg_unsigned)
        if how == "outer_identifier_id_alg_unsigned":
            # ECDSA, or PKCS #1 v1.5 under an RSA issuer: a signature that verifies with SHA-384
            # once the outer identifier is ignored.
            der = builder.sign(issuer, hashes.SHA384()).public_bytes(der_encoding)
            label = sha384_with_rsa if isinstance(issuer, rsa.RSAPrivateKey) else ecdsa_with_sha384
            return with_outer_algorithm(der, label, id_alg_unsigned)
        if isinstance(issuer, rsa.RSAPrivateKey):
            pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
            der = builder.sign(issuer, hashes.SHA384(), rsa_padding=pss).public_bytes(der_encoding)
            algorithm = rsassa_pss
        else:
            der = builder.sign(issuer, hashes.SHA384()).public_bytes(der_encoding)
            algorithm = ecdsa_with_sha384
        # A certificate and a CRL each name their signature algorithm in two places.
        if how == "unknown_signature_algorithm":
            return renamed(der, algorithm, 2)
        if how == "pss_unknown_mask_function":
            return renamed(der, mgf1, 2)
        if how == "pss_unknown_mask_hash":
            # id-sha384 stands four times: the hash and the mask function's hash, in two places.
            return renamed(der, sha384, 4, only=(2, 4))
        if how == "pss_outer_parameters_absent":
            return with_outer_algorithm(der, rsassa_pss, rsassa_pss)
        return der

    def with_own_key(der: bytes, how: str) -> bytes:
        """The certificate as it is, unless `how` names a defect of the key it carries."""
        if how == "key_of_unknown_algorithm":
            return renamed(der, ec_public_key, 1)
        if how == "key_point_off_the_curve":
            # The uncompressed P-384 point follows 03 62 00 04; change the first byte of x.
            at = der.index(bytes.fromhex("03620004"), der.index(ec_public_key)) + 4
            return der[:at] + bytes([der[at] ^ 0xFF]) + der[at + 1 :]
        return der

    def certificate(
        subject: x509.Name,
        issuer_name: x509.Name,
        public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey,
        issuer: IssuerKey,
        how: str,
        extensions: list[tuple[str, bytes]] | None = None,
    ) -> bytes:
        if how == "rsa_key_too_small_for_the_pss_digest":
            public_key = small_rsa_key
        if how == "key_neither_rsa_nor_ec":
            public_key = ed25519_key.public_key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(public_key)
            .serial_number(2)
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
        )
        for oid, value in extensions or []:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(ObjectIdentifier(oid), value), critical=False
            )
        return with_own_key(signed(builder, issuer, how), how)

    def pem(der: bytes) -> str:
        body = base64.encodebytes(der).decode("ascii")
        return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"

    def der_small_uint(value: int) -> bytes:
        return b"\x02\x01" + bytes([value]) if value < 0x80 else b"\x02\x02\x00" + bytes([value])

    vcek_extensions = [(oid, der_small_uint(reported[name])) for name, oid in s._VCEK_OIDS.items()]
    vcek_extensions.append((s._HWID_OID, report[s._CHIP_ID : s._CHIP_ID + 64]))

    def chain(bad: str | None) -> tuple[dict[str, object], s.CollateralPolicy]:
        """A valid packet and policy, or the same with the defect in the part named."""

        def how(name: str) -> str:
            return defect if name == bad else "as the issuer signs"

        ark = certificate(ark_name, ark_name, ark_key.public_key(), ark_key, how("ark"))
        ask = certificate(ask_name, ark_name, ask_key.public_key(), ark_key, how("ask"))
        vcek = certificate(
            vcek_name, ask_name, vcek_key.public_key(), ask_key, how("vcek"), vcek_extensions
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ark_name)
            .last_update(NOW - timedelta(hours=1))
            .next_update(NOW + timedelta(days=7))
        )
        packet: dict[str, object] = {
            "hcl_b64": milan["hcl_b64"],
            "vcek_pem": pem(vcek),
            "intermediates_pem": [pem(ask)],
        }
        pol = s.CollateralPolicy(
            floors={"Milan": FLOOR},
            arks={"Milan": x509.load_der_x509_certificate(ark)},
            crls={"Milan": signed(crl, ark_key, how("crl"))},
        )
        return packet, pol

    packet, pol = chain(None)
    assert s.appraise_collateral(packet, pol, now=NOW)["product"] == "Milan"

    packet, pol = chain(part)
    with pytest.raises(s.CollateralDenied, match=f"^{expected_reason}$"):
        s.appraise_collateral(packet, pol, now=NOW)
