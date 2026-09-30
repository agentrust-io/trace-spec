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
    milan = json.loads((FIXTURES / "live-milan-packet.json").read_text())
    genoa = json.loads((EXEC / "b1-approved-packet.json").read_text())
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
