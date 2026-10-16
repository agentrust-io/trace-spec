"""Experimental Azure SEV-SNP/vTPM execution binding through a UKI-anchored IMA log.

The chain is: AMD root -> VCEK -> SNP report -> HCL runtime JSON -> vTPM AK ->
quote over SHA-256 PCRs 0-10. PCRs 0-9 are replayed from the UEFI event log and
PCR 10 from the IMA log. PCR 4 must contain the approved UKI, whose initrd loads
the IMA policy before other userspace runs; that makes the policy part of the
measured boot rather than something a guest process asserts afterwards.

Guest-resettable PCR 23 plays no part. The evidence establishes which files were
executed or mapped executable since boot, up to the quote. It does not cover
code an approved interpreter reads without exec, runtime compromise of an
approved process, or complete TCB/revocation appraisal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

DOMAIN = b"trace-execution-binding-azure-snp-v1\x00"
PROFILE = "azure-snp-vtpm-ima-execution-experimental-v1"
QUOTED_PCRS = tuple(range(11))
SHA256 = 0x000B
EV_NO_ACTION = 0x00000003
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
SNP_POLICY_DEBUG = 1 << 19
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ExecutionDenied(ValueError):
    pass


def _digest_set(values: frozenset[str], name: str) -> None:
    if not isinstance(values, frozenset) or any(
        not isinstance(v, str) or not _HEX64.fullmatch(v) for v in values
    ):
        raise ExecutionDenied(f"policy_{name}")


@dataclass(frozen=True)
class ExecutionPolicy:
    """Relying-party expectations, supplied independently of the evidence.

    Digests are lowercase SHA-256 hex. Boot applications are PE Authenticode
    digests as firmware logs them; executables are file-content digests as IMA
    logs them.
    """

    required_boot_application: str
    approved_boot_applications: frozenset[str]
    required_application: str
    approved_executables: frozenset[str]
    denied_executables: frozenset[str] = field(default_factory=frozenset)
    secure_boot: bool = True

    def __post_init__(self) -> None:
        _digest_set(self.approved_boot_applications, "boot_applications")
        _digest_set(self.approved_executables, "executables")
        _digest_set(self.denied_executables, "denied_executables")
        if self.required_boot_application not in self.approved_boot_applications:
            raise ExecutionDenied("policy_required_boot_application")
        if self.required_application not in self.approved_executables:
            raise ExecutionDenied("policy_required_application")
        if self.denied_executables & self.approved_executables:
            raise ExecutionDenied("policy_denied_overlaps_approved")
        if type(self.secure_boot) is not bool:
            raise ExecutionDenied("policy_secure_boot")


# ---------------------------------------------------------------- TPM quote


@dataclass(frozen=True)
class Quote:
    extra_data: bytes
    pcrs: tuple[int, ...]
    pcr_digest: bytes


def _tpm2b(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(blob):
        raise ExecutionDenied("quote_truncated")
    size = int.from_bytes(blob[offset : offset + 2], "big")
    end = offset + 2 + size
    if end > len(blob):
        raise ExecutionDenied("quote_truncated")
    return blob[offset + 2 : end], end


def parse_quote(quote: bytes) -> Quote:
    if quote[:6] != b"\xffTCG\x80\x18":
        raise ExecutionDenied("quote_type")
    _, offset = _tpm2b(quote, 6)  # qualified signer
    extra, offset = _tpm2b(quote, offset)
    offset += 17 + 8  # TPMS_CLOCK_INFO, firmwareVersion
    if offset + 4 > len(quote):
        raise ExecutionDenied("quote_truncated")
    if int.from_bytes(quote[offset : offset + 4], "big") != 1:
        raise ExecutionDenied("quote_selection_banks")
    offset += 4
    if offset + 3 > len(quote):
        raise ExecutionDenied("quote_truncated")
    algorithm = int.from_bytes(quote[offset : offset + 2], "big")
    size = quote[offset + 2]
    bitmap = quote[offset + 3 : offset + 3 + size]
    if algorithm != SHA256 or len(bitmap) != size:
        raise ExecutionDenied("quote_selection_bank")
    pcrs = tuple(i for i in range(size * 8) if bitmap[i // 8] >> (i % 8) & 1)
    digest, end = _tpm2b(quote, offset + 3 + size)
    if end != len(quote) or len(digest) != 32:
        raise ExecutionDenied("quote_trailing_or_digest")
    return Quote(extra, pcrs, digest)


def verify_quote_signature(quote: bytes, signature: bytes, ak: rsa.RSAPublicKey) -> None:
    if signature[:4] != b"\x00\x14\x00\x0b":
        raise ExecutionDenied("quote_signature_scheme")
    raw, end = _tpm2b(signature, 4)
    if end != len(signature):
        raise ExecutionDenied("quote_signature_trailing")
    try:
        ak.verify(raw, quote, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise ExecutionDenied("quote_signature") from exc


# ---------------------------------------------------------- UEFI event log


@dataclass(frozen=True)
class UefiEvent:
    pcr: int
    event_type: int
    sha256: bytes
    data: bytes


def parse_uefi_log(log: bytes) -> list[UefiEvent]:
    """Parse a TCG2 crypto-agile log (SHA-1 format Spec ID header first)."""
    try:
        pcr, etype = struct.unpack_from("<II", log, 0)
        (size,) = struct.unpack_from("<I", log, 28)
        header = log[32 : 32 + size]
        if etype != EV_NO_ACTION or not header.startswith(b"Spec ID Event03\x00"):
            raise ExecutionDenied("uefi_log_header")
        (count,) = struct.unpack_from("<I", header, 24)
        sizes = {}
        for i in range(count):
            alg, dsize = struct.unpack_from("<HH", header, 28 + 4 * i)
            sizes[alg] = dsize
        if sizes.get(SHA256) != 32:
            raise ExecutionDenied("uefi_log_no_sha256")
        offset = 32 + size
        events = []
        while offset < len(log):
            pcr, etype, ndigests = struct.unpack_from("<III", log, offset)
            offset += 12
            sha = None
            for _ in range(ndigests):
                (alg,) = struct.unpack_from("<H", log, offset)
                if alg not in sizes:
                    raise ExecutionDenied("uefi_log_unknown_algorithm")
                value = log[offset + 2 : offset + 2 + sizes[alg]]
                if alg == SHA256:
                    sha = value
                offset += 2 + sizes[alg]
            (esize,) = struct.unpack_from("<I", log, offset)
            data = log[offset + 4 : offset + 4 + esize]
            if len(data) != esize or sha is None or len(sha) != 32:
                raise ExecutionDenied("uefi_log_truncated")
            offset += 4 + esize
            events.append(UefiEvent(pcr, etype, sha, data))
        return events
    except struct.error as exc:
        raise ExecutionDenied("uefi_log_truncated") from exc


def replay_uefi(events: list[UefiEvent]) -> dict[int, bytes]:
    pcrs = {i: bytes(32) for i in range(10)}
    for event in events:
        if event.event_type == EV_NO_ACTION:
            if event.pcr == 0 and event.data.startswith(b"StartupLocality\x00"):
                pcrs[0] = bytes(31) + event.data[16:17]
            continue
        if event.pcr in pcrs:
            pcrs[event.pcr] = hashlib.sha256(pcrs[event.pcr] + event.sha256).digest()
    return pcrs


def _secure_boot_state(events: list[UefiEvent]) -> bool:
    found = []
    for event in events:
        if event.pcr != 7 or event.event_type != EV_EFI_VARIABLE_DRIVER_CONFIG:
            continue
        if hashlib.sha256(event.data).digest() != event.sha256:
            raise ExecutionDenied("uefi_variable_digest")
        name_len, data_len = struct.unpack_from("<QQ", event.data, 16)
        name = event.data[32 : 32 + 2 * name_len].decode("utf-16-le")
        if name == "SecureBoot":
            found.append(event.data[32 + 2 * name_len : 32 + 2 * name_len + data_len])
    if len(found) != 1 or found[0] not in (b"\x00", b"\x01"):
        raise ExecutionDenied("secure_boot_state")
    return found[0] == b"\x01"


# ---------------------------------------------------------------- IMA log


@dataclass(frozen=True)
class ImaEntry:
    pcr: int
    template_digest: bytes
    file_digest: str
    path: str


def parse_ima_log(log: bytes) -> list[ImaEntry]:
    """Parse binary_runtime_measurements_sha256 (x86 little-endian, ima-ng)."""
    entries = []
    offset = 0
    try:
        while offset < len(log):
            (pcr,) = struct.unpack_from("<I", log, offset)
            template_digest = log[offset + 4 : offset + 36]
            (name_len,) = struct.unpack_from("<I", log, offset + 36)
            name = log[offset + 40 : offset + 40 + name_len]
            offset += 40 + name_len
            (data_len,) = struct.unpack_from("<I", log, offset)
            data = log[offset + 4 : offset + 4 + data_len]
            offset += 4 + data_len
            if name != b"ima-ng" or len(data) != data_len:
                raise ExecutionDenied("ima_template")
            if template_digest == bytes(32):
                raise ExecutionDenied("ima_violation")
            if hashlib.sha256(data).digest() != template_digest:
                raise ExecutionDenied("ima_template_digest")
            (dlen,) = struct.unpack_from("<I", data, 0)
            digest_field = data[4 : 4 + dlen]
            (plen,) = struct.unpack_from("<I", data, 4 + dlen)
            path = data[8 + dlen : 8 + dlen + plen]
            if 8 + dlen + plen != len(data) or not digest_field.startswith(b"sha256:\x00"):
                raise ExecutionDenied("ima_template_fields")
            file_digest = digest_field[8:]
            if len(file_digest) != 32 or not path.endswith(b"\x00"):
                raise ExecutionDenied("ima_template_fields")
            entries.append(
                ImaEntry(
                    pcr, template_digest, file_digest.hex(), path[:-1].decode("utf-8", "replace")
                )
            )
    except struct.error as exc:
        raise ExecutionDenied("ima_log_truncated") from exc
    return entries


def _quoted_ima_prefix(
    uefi_pcrs: dict[int, bytes], entries: list[ImaEntry], quoted: bytes
) -> list[ImaEntry]:
    """Return the IMA prefix whose replay reproduces the quoted composite.

    The log is read just after the quote, so later measurements may follow the
    quoted prefix. Only the authenticated prefix is appraised.
    """
    base = b"".join(uefi_pcrs[i] for i in range(10))
    pcr10 = bytes(32)
    for count in range(len(entries) + 1):
        if hashlib.sha256(base + pcr10).digest() == quoted:
            return entries[:count]
        if count < len(entries):
            if entries[count].pcr != 10:
                raise ExecutionDenied("ima_unexpected_pcr")
            pcr10 = hashlib.sha256(pcr10 + entries[count].template_digest).digest()
    raise ExecutionDenied("pcr_replay_mismatch")


# ------------------------------------------------------------- appraisal


def _b64(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise ExecutionDenied(f"packet_{name}")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ExecutionDenied(f"packet_{name}") from exc


def appraise_execution(
    packet: dict[str, Any],
    ak: rsa.RSAPublicKey,
    policy: ExecutionPolicy,
    *,
    expected_challenge: str,
) -> dict[str, Any]:
    """Appraise a packet whose AK the caller has already authenticated.

    Fails closed with ExecutionDenied. The relying party issues the challenge
    and consumes it on admission; this function keeps no replay state.
    """
    if not _HEX64.fullmatch(expected_challenge) or packet.get("challenge") != expected_challenge:
        raise ExecutionDenied("challenge")
    holder_hex = packet.get("holder_public_hex")
    if not isinstance(holder_hex, str) or not _HEX64.fullmatch(holder_hex):
        raise ExecutionDenied("holder_key")
    challenge, holder = bytes.fromhex(expected_challenge), bytes.fromhex(holder_hex)
    quote_bytes = _b64(packet.get("tpm_quote_b64"), "quote")
    verify_quote_signature(quote_bytes, _b64(packet.get("tpm_signature_b64"), "signature"), ak)
    quote = parse_quote(quote_bytes)
    if quote.pcrs != QUOTED_PCRS:
        raise ExecutionDenied("quote_pcr_selection")
    if quote.extra_data != hashlib.sha256(DOMAIN + challenge + holder).digest():
        raise ExecutionDenied("holder_binding")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(holder).verify(
            _b64(packet.get("holder_signature_b64"), "holder_signature"),
            DOMAIN + hashlib.sha256(quote_bytes).digest() + challenge,
        )
    except InvalidSignature as exc:
        raise ExecutionDenied("holder_possession") from exc

    events = parse_uefi_log(_b64(packet.get("uefi_event_log_b64"), "uefi_log"))
    uefi_pcrs = replay_uefi(events)
    log = parse_ima_log(_b64(packet.get("ima_log_sha256_b64"), "ima_log"))
    entries = _quoted_ima_prefix(uefi_pcrs, log, quote.pcr_digest)
    # Entries after the quoted prefix are unauthenticated, so they can only deny.
    trailing = log[len(entries) :]
    if any(e.pcr != 10 for e in trailing):
        raise ExecutionDenied("ima_unexpected_pcr")

    boot_apps = [e.sha256.hex() for e in events if e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION]
    if any(app not in policy.approved_boot_applications for app in boot_apps):
        raise ExecutionDenied("unapproved_boot_application")
    if policy.required_boot_application not in boot_apps:
        raise ExecutionDenied("boot_policy_not_measured")
    if _secure_boot_state(events) != policy.secure_boot:
        raise ExecutionDenied("secure_boot_state")

    if not entries or entries[0].path != "boot_aggregate":
        raise ExecutionDenied("ima_boot_aggregate_missing")
    aggregate = hashlib.sha256(b"".join(uefi_pcrs[i] for i in range(10))).hexdigest()
    if entries[0].file_digest != aggregate:
        raise ExecutionDenied("ima_boot_aggregate")
    executed = entries[1:]
    observed = executed + trailing
    if any(e.file_digest in policy.denied_executables for e in observed):
        raise ExecutionDenied("interactive_access")
    if any(e.file_digest not in policy.approved_executables for e in observed):
        raise ExecutionDenied("unapproved_execution")
    if not any(e.file_digest == policy.required_application for e in executed):
        raise ExecutionDenied("application_not_executed")
    return {
        "profile": PROFILE,
        "observed_application": "sha256:" + policy.required_application,
        "boot_application": "sha256:" + policy.required_boot_application,
        "secure_boot": policy.secure_boot,
        "quoted_executions": len(executed),
        "evidence_digest": "sha256:" + hashlib.sha256(quote_bytes).hexdigest(),
        "holder_public_hex": holder_hex,
        "limits": [
            "Executions and executable mappings since boot, up to the quote.",
            "Later executions need a new quote.",
            "Code read by an approved interpreter without exec is not measured.",
            "Runtime compromise of an approved process is not detected.",
            "No complete TCB, revocation or collateral appraisal.",
        ],
    }


def unapproved_executions(packet: dict[str, Any], policy: ExecutionPolicy) -> list[dict[str, str]]:
    """Diagnostic listing for denial reports; never an authorization input."""
    entries = parse_ima_log(_b64(packet.get("ima_log_sha256_b64"), "ima_log"))[1:]
    return [
        {"path": e.path, "sha256": e.file_digest}
        for e in entries
        if e.file_digest not in policy.approved_executables
    ]


def authenticate_ak(
    packet: dict[str, Any], trust_store: Any, *, now: datetime | None = None
) -> rsa.RSAPublicKey:
    """Authenticate the vTPM AK through the SNP report, using WCM's SNP parsers.

    ``trust_store`` must hold an operator-pinned AMD root, never one from the packet.
    """
    from wcm._certificates import load_pem_certificate
    from wcm._quote_verify import verify_cert_chain
    from wcm.snp import extract_snp_report_from_hcl, parse_snp_report, verify_snp_report_signature

    hcl = _b64(packet.get("hcl_b64"), "hcl")
    try:
        vcek = load_pem_certificate(packet["vcek_pem"].encode(), allow_non_positive_serial=True)
        intermediates = [load_pem_certificate(p.encode()) for p in packet["intermediates_pem"]]
        ak = serialization.load_pem_public_key(packet["ak_pem"].encode())
        report = extract_snp_report_from_hcl(hcl)
        parsed = parse_snp_report(report)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ExecutionDenied("platform_evidence_format") from exc
    if not isinstance(ak, rsa.RSAPublicKey):
        raise ExecutionDenied("ak_type")
    if verify_cert_chain(vcek, intermediates, trust_store, now or datetime.now(UTC)):
        raise ExecutionDenied("vcek_chain")
    if not verify_snp_report_signature(report, vcek):
        raise ExecutionDenied("snp_report_signature")
    if parsed.policy & SNP_POLICY_DEBUG:
        raise ExecutionDenied("snp_debug_enabled")
    if parsed.vmpl != 0:
        raise ExecutionDenied("snp_vmpl")
    runtime = hcl[32 + 1184 :]
    if len(runtime) < 20:
        raise ExecutionDenied("hcl_runtime_truncated")
    json_len = int.from_bytes(runtime[16:20], "little")
    runtime_json = runtime[20 : 20 + json_len]
    if len(runtime_json) != json_len:
        raise ExecutionDenied("hcl_runtime_truncated")
    if parsed.report_data != hashlib.sha256(runtime_json).digest() + bytes(32):
        raise ExecutionDenied("hcl_runtime_binding")
    try:
        doc = json.loads(runtime_json)
        keys = [k for k in doc["keys"] if k.get("kid") == "HCLAkPub"]
        if len(keys) != 1:
            raise ValueError("HCLAkPub count")
        n = keys[0]["n"]
        modulus = int.from_bytes(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4)), "big")
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ExecutionDenied("hcl_ak") from exc
    if modulus != ak.public_numbers().n:
        raise ExecutionDenied("ak_not_hcl_bound")
    return ak


def appraise(
    packet: dict[str, Any],
    trust_store: Any,
    policy: ExecutionPolicy,
    *,
    expected_challenge: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    ak = authenticate_ak(packet, trust_store, now=now)
    return appraise_execution(packet, ak, policy, expected_challenge=expected_challenge)


def _runtime_claims(packet: dict[str, Any]) -> dict[str, Any]:
    """HCL runtime JSON; authenticated only after authenticate_ak has passed."""
    runtime = _b64(packet.get("hcl_b64"), "hcl")[32 + 1184 :]
    json_len = int.from_bytes(runtime[16:20], "little")
    try:
        claims = json.loads(runtime[20 : 20 + json_len])
        vm_id = claims["vm-configuration"]["vmUniqueId"]
        secure_boot = claims["vm-configuration"]["secure-boot"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ExecutionDenied("hcl_vm_configuration") from exc
    if not isinstance(vm_id, str) or not re.fullmatch(
        r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", vm_id
    ):
        raise ExecutionDenied("hcl_vm_id")
    if type(secure_boot) is not bool:
        raise ExecutionDenied("hcl_secure_boot")
    return {"vm_id": vm_id.lower(), "secure_boot": secure_boot}


def execution_component(
    packet: dict[str, Any],
    trust_store: Any,
    policy: ExecutionPolicy,
    *,
    expected_challenge: str,
    expected_holder: bytes,
    authority: str,
    now: int,
    max_age: int = 300,
) -> Any:
    """Issuer-side adapter from an appraised packet to a TRACE code component.

    The issuer runs this at the time it receives the packet in reply to its own
    challenge; the packet carries no wall-clock time, so `now` is the issuer's.
    The instance is the SNP-authenticated vmUniqueId. Only code execution is
    appraised: required TCB and relationship components stay separate.
    """
    from .verifier_token import Component, EvidenceRef, canonical_digest

    if type(now) is not int or now < 0 or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise ExecutionDenied("clock_or_age")
    observation = appraise(
        packet,
        trust_store,
        policy,
        expected_challenge=expected_challenge,
        now=datetime.fromtimestamp(now, UTC),
    )
    if (
        type(expected_holder) is not bytes
        or bytes.fromhex(observation["holder_public_hex"]) != expected_holder
    ):
        raise ExecutionDenied("token_holder_mismatch")
    claims = _runtime_claims(packet)
    # The HCL's own view of Secure Boot must agree with the replayed PCR 7 state.
    if claims["secure_boot"] != policy.secure_boot:
        raise ExecutionDenied("hcl_secure_boot_mismatch")
    return Component(
        component_id="application.code",
        component_type="code",
        profile=PROFILE,
        authority=authority,
        instance="azure-vm/" + claims["vm_id"],
        status="affirming",
        appraised_at=now,
        fresh_until=now + max_age,
        evidence_refs=[
            EvidenceRef(
                profile=PROFILE,
                media_type="application/vnd.agentrust.azure-snp-execution+json",
                digest=canonical_digest(packet),
            )
        ],
        observed_digest=observation["observed_application"],
        reasons=[],
    )


def authenticode_sha256(image: bytes) -> str:
    """PE Authenticode SHA-256, the digest firmware logs for boot applications."""
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe : pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image")
    sections = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", image, opt)[0]
    datadir = opt + (112 if magic == 0x20B else 96)
    checksum = opt + 64
    cert_entry = datadir + 8 * 4
    headers_size = struct.unpack_from("<I", image, opt + 60)[0]
    cert_offset, cert_size = struct.unpack_from("<II", image, cert_entry)
    digest = hashlib.sha256()
    digest.update(image[:checksum])
    digest.update(image[checksum + 4 : cert_entry])
    digest.update(image[cert_entry + 8 : headers_size])
    table = opt + optional_size
    raw = []
    for i in range(sections):
        size, pointer = struct.unpack_from("<II", image, table + 40 * i + 16)
        if size:
            raw.append((pointer, size))
    hashed = headers_size
    for pointer, size in sorted(raw):
        digest.update(image[pointer : pointer + size])
        hashed = max(hashed, pointer + size)
    end = len(image) - (cert_size if cert_offset else 0)
    if end > hashed:
        digest.update(image[hashed:end])
    return digest.hexdigest()
