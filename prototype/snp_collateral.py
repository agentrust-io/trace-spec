"""Experimental SEV-SNP platform collateral appraisal: TCB floors, revocation, product.

Runs after azure_execution_binding.authenticate_ak has authenticated the report
(AMD root, VCEK, report signature, debug bit, VMPL). This module enforces what
that chain alone does not: the VCEK's certified TCB equals the signed reported
TCB, the chip and CPUID agree with the certifying product line, the reported
TCB meets the relying party's published floors, the ASK is not on AMD's current
ARK-signed CRL, and a mitigation that also needs a guest OS change is proved by
the report's mitigation vector or reported as unproved.

AMD publishes no VCEK leaf revocation list: a VCEK is superseded through TCB
floors, which is why the floor check is the leaf-level control.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

PROFILE = "amd-snp-collateral-experimental-v1"
# SEV-SNP ABI (AMD 56860) ATTESTATION_REPORT offsets.
_VERSION, _REPORTED_TCB, _CPUID, _CHIP_ID = 0x00, 0x180, 0x188, 0x1A0
_COMMITTED_TCB, _BUILD, _LAUNCH_TCB, _CURRENT_MIT = 0x1E0, 0x1E8, 0x1F0, 0x200
# Milan and Genoa TCB_VERSION byte positions; Turin uses a different layout.
_TCB_BYTES = {"bootloader": 0, "tee": 1, "snp": 6, "microcode": 7}
_VCEK_OIDS = {
    "bootloader": "1.3.6.1.4.1.3704.1.3.1",
    "tee": "1.3.6.1.4.1.3704.1.3.2",
    "snp": "1.3.6.1.4.1.3704.1.3.3",
    "microcode": "1.3.6.1.4.1.3704.1.3.8",
}
_HWID_OID = "1.3.6.1.4.1.3704.1.4"
# CPUID (family, model) per product line, from the report's CPUID fields.
PRODUCTS = {"Milan": (0x19, 0x01), "Genoa": (0x19, 0x11)}


class CollateralDenied(ValueError):
    pass


@dataclass(frozen=True)
class TcbFloor:
    """Minimum reported TCB for one product line, from a named vendor bulletin."""

    bootloader: int = 0
    tee: int = 0
    snp: int = 0
    microcode: int = 0
    source: str = ""
    os_mitigation_bit: int | None = None  # mitigation vector bit when an OS change is also required

    def __post_init__(self) -> None:
        values = (self.bootloader, self.tee, self.snp, self.microcode)
        if any(type(v) is not int or not 0 <= v <= 255 for v in values) or not self.source:
            raise CollateralDenied("policy_floor")
        if self.os_mitigation_bit is not None and not 0 <= self.os_mitigation_bit < 64:
            raise CollateralDenied("policy_floor")


@dataclass(frozen=True)
class CollateralPolicy:
    """Relying-party inputs, never taken from the evidence.

    `arks` are operator-pinned ARK certificates and `crls` DER CRLs fetched
    from AMD KDS, both keyed by product line.
    """

    floors: dict[str, TcbFloor]
    arks: dict[str, x509.Certificate]
    crls: dict[str, bytes]
    accept_unproven_os_mitigation: bool = False
    limits: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.floors or set(self.floors) - set(PRODUCTS):
            raise CollateralDenied("policy_products")
        if type(self.accept_unproven_os_mitigation) is not bool:
            raise CollateralDenied("policy_os_mitigation")


def _tcb(value: bytes) -> dict[str, int]:
    return {name: value[i] for name, i in _TCB_BYTES.items()}


def _der_uint(der: bytes) -> int:
    if len(der) < 3 or der[0] != 0x02 or der[1] != len(der) - 2:
        raise CollateralDenied("vcek_extension_encoding")
    return int.from_bytes(der[2:], "big")


def _cn(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(values) != 1:
        raise CollateralDenied("certificate_common_name")
    return str(values[0].value)


def _verify_signed_by(cert_or_crl: Any, issuer: x509.Certificate) -> bool:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            params = cert_or_crl.signature_algorithm_parameters
            key.verify(
                cert_or_crl.signature,
                cert_or_crl.tbs_certlist_bytes
                if isinstance(cert_or_crl, x509.CertificateRevocationList)
                else cert_or_crl.tbs_certificate_bytes,
                params if isinstance(params, padding.PSS) else padding.PKCS1v15(),
                cert_or_crl.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                cert_or_crl.signature,
                cert_or_crl.tbs_certlist_bytes
                if isinstance(cert_or_crl, x509.CertificateRevocationList)
                else cert_or_crl.tbs_certificate_bytes,
                ec.ECDSA(cert_or_crl.signature_hash_algorithm),
            )
        else:
            return False
    except InvalidSignature:
        return False
    return True


def appraise_collateral(
    packet: dict[str, Any], policy: CollateralPolicy, *, now: datetime
) -> dict[str, Any]:
    """Appraise an already-authenticated packet's platform collateral.

    Structural and authenticity failures raise CollateralDenied. A genuine
    platform below a floor returns status "contraindicated" with reasons, so an
    issuer can state it honestly rather than omit it.
    """
    from wcm._certificates import load_pem_certificate
    from wcm.snp import extract_snp_report_from_hcl

    try:
        report = extract_snp_report_from_hcl(base64.b64decode(packet["hcl_b64"], validate=True))
        vcek = load_pem_certificate(packet["vcek_pem"].encode(), allow_non_positive_serial=True)
        asks = [load_pem_certificate(p.encode()) for p in packet["intermediates_pem"]]
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise CollateralDenied("platform_evidence_format") from exc
    if len(report) < _CURRENT_MIT + 8 or len(asks) != 1:
        raise CollateralDenied("platform_evidence_format")
    ask = asks[0]
    version = int.from_bytes(report[_VERSION : _VERSION + 4], "little")

    # Product line: VCEK issuer, ASK subject and issuer, pinned ARK and CPUID must agree.
    issuer = _cn(vcek.issuer)
    if not issuer.startswith("SEV-") or issuer[4:] not in PRODUCTS:
        raise CollateralDenied("vcek_product")
    product = issuer[4:]
    ark = policy.arks.get(product)
    if (
        ark is None
        or _cn(ask.subject) != issuer
        or _cn(ask.issuer) != "ARK-" + product
        or ask.issuer != ark.subject
        or not _verify_signed_by(ask, ark)
    ):
        raise CollateralDenied("product_chain")
    if version >= 3 and tuple(report[_CPUID : _CPUID + 2]) != PRODUCTS[product]:
        raise CollateralDenied("cpuid_product_mismatch")
    floor = policy.floors.get(product)
    if floor is None:
        raise CollateralDenied("product_not_accepted")

    # The VCEK certifies one TCB; the report must state exactly that TCB.
    reported = _tcb(report[_REPORTED_TCB : _REPORTED_TCB + 8])
    try:
        certified = {
            name: _der_uint(
                vcek.extensions.get_extension_for_oid(ObjectIdentifier(oid)).value.value
            )
            for name, oid in _VCEK_OIDS.items()
        }
        hwid = vcek.extensions.get_extension_for_oid(ObjectIdentifier(_HWID_OID)).value.value
    except x509.ExtensionNotFound as exc:
        raise CollateralDenied("vcek_extension_missing") from exc
    if certified != reported:
        raise CollateralDenied("vcek_tcb_mismatch")
    if hwid != report[_CHIP_ID : _CHIP_ID + 64]:
        raise CollateralDenied("vcek_chip_mismatch")

    # Revocation: the ARK-signed CRL covers ARK-issued certificates, i.e. the ASK.
    der = policy.crls.get(product)
    if der is None:
        raise CollateralDenied("crl_missing")
    try:
        crl = x509.load_der_x509_crl(der)
    except ValueError as exc:
        raise CollateralDenied("crl_format") from exc
    if crl.issuer != ark.subject or not _verify_signed_by(crl, ark):
        raise CollateralDenied("crl_signature")
    if crl.next_update_utc is None or not crl.last_update_utc <= now < crl.next_update_utc:
        raise CollateralDenied("crl_stale")
    if crl.get_revoked_certificate_by_serial_number(ask.serial_number) is not None:
        raise CollateralDenied("ask_revoked")

    reasons = [
        f"tcb_{name}_below_floor" for name in _TCB_BYTES if reported[name] < getattr(floor, name)
    ]
    mitigation = "not_required"
    if floor.os_mitigation_bit is not None:
        if version < 5:
            mitigation = "unproven_report_version"
        else:
            vector = int.from_bytes(report[_CURRENT_MIT : _CURRENT_MIT + 8], "little")
            mitigation = "proved" if vector >> floor.os_mitigation_bit & 1 else "absent"
        if mitigation == "absent":
            reasons.append("os_mitigation_absent")
    if reasons:
        status = "contraindicated"
    elif mitigation == "unproven_report_version":
        status = "warning" if policy.accept_unproven_os_mitigation else "contraindicated"
        reasons.append("os_mitigation_unproven")
    else:
        status = "affirming"
    build = report[_BUILD : _BUILD + 3]
    return {
        "profile": PROFILE,
        "status": status,
        "reasons": reasons,
        "product": product,
        "report_version": version,
        "reported_tcb": reported,
        "committed_tcb": _tcb(report[_COMMITTED_TCB : _COMMITTED_TCB + 8]),
        "launch_tcb": _tcb(report[_LAUNCH_TCB : _LAUNCH_TCB + 8]),
        "firmware": f"{build[2]}.{build[1]}.{build[0]}",
        "floor": {name: getattr(floor, name) for name in _TCB_BYTES} | {"source": floor.source},
        "os_mitigation": mitigation,
        "crl": {
            "issuer": crl.issuer.rfc4514_string(),
            "this_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat(),
            "revoked": len(list(crl)),
        },
        "vcek_serial_zero": vcek.serial_number == 0,
        "limits": [
            "Floors are the relying party's published policy, not a live vendor feed.",
            "AMD publishes no VCEK leaf CRL; leaf supersession is enforced through the floor.",
            "A zero VCEK serial is accepted only through the existing compatibility exception.",
            *policy.limits,
        ],
    }


def tcb_component(
    appraisal: dict[str, Any],
    packet: dict[str, Any],
    *,
    instance: str,
    authority: str,
    now: int,
    max_age: int = 300,
) -> Any:
    """TRACE runtime component for the appraised platform, including a negative verdict."""
    from .verifier_token import Component, EvidenceRef, canonical_digest

    if type(now) is not int or now < 0 or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise CollateralDenied("clock_or_age")
    return Component(
        component_id="runtime.cpu",
        component_type="runtime",
        profile=PROFILE,
        authority=authority,
        instance=instance,
        status=appraisal["status"],
        appraised_at=now,
        fresh_until=now + max_age,
        evidence_refs=[
            EvidenceRef(
                profile=PROFILE,
                media_type="application/vnd.agentrust.azure-snp-execution+json",
                digest=canonical_digest(packet),
            )
        ],
        reasons=appraisal["reasons"],
    )
