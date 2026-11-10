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
    valid_appraisal = {"status": "contraindicated", "reasons": ["tcb_snp_below_floor"]}
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
        {"status": 123, "reasons": []},
        {"status": "affirming", "reasons": "not-a-list"},
        {"status": "affirming", "reasons": [123]},
        {"status": "not-a-valid-status", "reasons": []},
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
        (0, {"status": "affirming", "reasons": []}, "clock_or_age"),
        (9_007_199_254_740_991, {"status": "affirming", "reasons": []}, "clock_or_age"),
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

