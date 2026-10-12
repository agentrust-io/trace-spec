"""Experimental Intel TDX collateral appraisal: relying-party policy over a native QVL record.

Native Intel QVL (libsgx-dcap-quote-verify) appraises a TDX quote against Intel
PCS collateral and reports three numbers: the API status, the quote
verification result and the collateral expiration status. This module does not
run QVL. It turns a saved QVL record into an enforced verdict:

- the caller selects the Intel update policy (standard or early) and the TCB
  evaluation data number; the run configuration and the Intel-signed collateral
  must state the same, and the verdict records both;
- only QV result OK is affirming; other non-terminal results deny unless the
  caller allowlists that exact code, which then yields a warning;
- expired collateral, a nonzero API or retrieval status, a record for other
  quote bytes, or a record outside the caller's window deny;
- the saved collateral is re-verified offline against a caller-pinned Intel SGX
  Root CA (signatures, chains, CRLs, validity at the appraisal time), and the
  TCB level, TDX module identity and QE identity are re-derived from the quote.
  The re-derived QV result must equal the record's, so a record that claims OK
  for an out-of-date platform is denied by the evidence, not by the record.

The record is unsigned and no QvE was used, so the QVL run itself is trusted
local verifier output. TD measurements (MRTD, RTMRs), REPORT_DATA freshness and
workload binding are outside this adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

PROFILE = "intel-tdx-qvl-collateral-experimental-v1"
RECORD_KIND = "trace-intel-qvl-appraisal/v1"
REPLAY_KIND = "trace-intel-qvl-offline-replay/v1"
RECORD_MEDIA_TYPE = "application/vnd.agentrust.intel-qvl-appraisal+json"
COLLATERAL_MEDIA_TYPE = "application/vnd.agentrust.intel-tdx-collateral+json"
QUOTE_MEDIA_TYPE = "application/vnd.agentrust.intel-tdx-quote"
UPDATE_POLICIES = ("standard", "early")
# The native QVL build the saved records came from; the relying party pins it.
QVL_PACKAGES = (
    "libsgx-dcap-default-qpl\t1.27.101.1-noble1\nlibsgx-dcap-quote-verify\t1.27.101.1-noble1"
)
INTEL_PCS = "https://api.trustedservices.intel.com/"
REPLAY_EXPIRY_SHIFT = 10 * 366 * 86400  # qvl_capture.py / qvl_replay.py expired case
LIMIT = 8 * 1024 * 1024

# sgx_ql_qv_result_t, Intel DCAP
# QuoteGeneration/quote_wrapper/common/inc/sgx_qve_header.h (SGX_QL_QV_RESULT_*).
QV_OK = 0x0000
QV_RESULTS = {
    0x0000: "ok",
    0xA001: "config_needed",
    0xA002: "out_of_date",
    0xA003: "out_of_date_config_needed",
    0xA004: "invalid_signature",
    0xA005: "revoked",
    0xA006: "unspecified",
    0xA007: "sw_hardening_needed",
    0xA008: "config_and_sw_hardening_needed",
    0xA009: "td_relaunch_advised",
    0xA00A: "td_relaunch_advised_config_needed",
}
# A caller may accept these as warnings. Signature, revocation and unspecified
# failures are never allowlistable.
ALLOWLISTABLE = frozenset({0xA001, 0xA002, 0xA003, 0xA007, 0xA008, 0xA009, 0xA00A})

# Intel TCB status strings (TCB Info v3 / Enclave Identity v2) to the QV result
# QVL reports for them.
_STATUS_TO_QV = {
    "UpToDate": 0x0000,
    "ConfigurationNeeded": 0xA001,
    "OutOfDate": 0xA002,
    "OutOfDateConfigurationNeeded": 0xA003,
    "Revoked": 0xA005,
    "SWHardeningNeeded": 0xA007,
    "ConfigurationAndSWHardeningNeeded": 0xA008,
}

FIELDS = (
    "pck_crl_issuer_chain",
    "root_ca_crl",
    "pck_crl",
    "tcb_info_issuer_chain",
    "tcb_info",
    "qe_identity_issuer_chain",
    "qe_identity",
)
_RECORD_KEYS = frozenset(
    {
        "kind",
        "verified_at",
        "quote_sha256",
        "retrieval_status",
        "qve_used",
        "freshness_scope",
        "packages",
        "cases",
        "limits",
        "collateral_sha256",
        "negative_controls_rejected",
        "collateral_free_status",
        "full_appraisal_accepted",
    }
)
_CASE_KEYS = frozenset(
    {"api_status", "qv_result", "collateral_expiration_status", "strict_accepted"}
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_STATUS = re.compile(r"0x[0-9a-f]{1,8}")
_SGX_EXTENSION = x509.ObjectIdentifier("1.2.840.113741.1.13.1")
_TCB_SIGNER = "Intel SGX TCB Signing"
_PCK_CAS = ("Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA")

LIMITS = (
    "QVL ran without a QvE; its record is trusted local verifier output, not an "
    "authenticated QvE report.",
    "The record is unsigned; integrity rests on the quote and collateral SHA-256 bindings.",
    "The update policy is stated by the QCNL run configuration, which Intel does not sign; "
    "the TCB evaluation data number is Intel-signed.",
    "TD relaunch advised results are not re-derived offline and deny by disagreement.",
    "TD measurements, REPORT_DATA freshness and workload binding are not appraised.",
    "Revocation uses the saved CRLs, bounded by their nextUpdate.",
)


class CollateralDenied(ValueError):
    pass


@dataclass(frozen=True)
class CollateralPolicy:
    """Relying-party expectations, supplied independently of the record."""

    update_policy: str
    tcb_evaluation_data_number: int
    allowed_qv_results: frozenset[int] = field(default_factory=frozenset)
    verifier_packages: str = QVL_PACKAGES

    def __post_init__(self) -> None:
        if self.update_policy not in UPDATE_POLICIES:
            raise CollateralDenied("policy_update_policy")
        number = self.tcb_evaluation_data_number
        if type(number) is not int or not 1 <= number <= 0xFFFFFFFF:
            raise CollateralDenied("policy_tcb_evaluation_data_number")
        if not isinstance(self.allowed_qv_results, frozenset) or any(
            type(code) is not int or code not in ALLOWLISTABLE for code in self.allowed_qv_results
        ):
            raise CollateralDenied("policy_allowed_qv_results")
        if not isinstance(self.verifier_packages, str) or not self.verifier_packages:
            raise CollateralDenied("policy_verifier_packages")


@dataclass(frozen=True)
class Packet:
    """One QVL run: its record, the exact collateral bytes it saved, and its QCNL config."""

    record: dict[str, Any]
    collateral: bytes
    qcnl_config: bytes


# ------------------------------------------------------------------ loading


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CollateralDenied("json_duplicate_key")
        value[key] = item
    return value


def _json(raw: bytes, name: str) -> Any:
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise CollateralDenied(f"{name}_format")
    try:
        return json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CollateralDenied):
            raise
        raise CollateralDenied(f"{name}_format") from exc


def _read(path: Any) -> bytes:
    with open(path, "rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise CollateralDenied("input_oversized")
    return raw


def load_packet(directory: Any) -> Packet:
    """Load qvl-appraisal.json, intel-collateral.json and sgx_default_qcnl.conf."""
    root = Path(directory)
    record = _json(_read(root / "qvl-appraisal.json"), "record")
    if not isinstance(record, dict):
        raise CollateralDenied("record_format")
    return Packet(
        record, _read(root / "intel-collateral.json"), _read(root / "sgx_default_qcnl.conf")
    )


def replay_record(
    replay: dict[str, Any], base: dict[str, Any], update_policy: str, case: str
) -> dict[str, Any]:
    """A QVL record for one offline replay case, reusing the replayed run's record.

    qvl_replay.py re-ran native QVL on the base record's saved collateral at its
    verified_at ("historical") and ten years later ("expired"). The replay file
    carries neither time nor quote hash, so both come from the base record, and
    the historical result must equal the base record's own.
    """
    if (
        not isinstance(replay, dict)
        or replay.get("kind") != REPLAY_KIND
        or replay.get("passed") is not True
        or replay.get("current_admission") is not False
        or update_policy not in UPDATE_POLICIES
        or case not in ("historical", "expired")
    ):
        raise CollateralDenied("replay_format")
    try:
        cases = replay["results"][update_policy]
        chosen = dict(cases[case])
        if cases["historical"] != base["cases"]["current_collateral"]:
            raise CollateralDenied("replay_inconsistent")
        record = json.loads(json.dumps(base))
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CollateralDenied):
            raise
        raise CollateralDenied("replay_format") from exc
    if type(record.get("verified_at")) is not int:
        raise CollateralDenied("record_time")
    record["verified_at"] += 0 if case == "historical" else REPLAY_EXPIRY_SHIFT
    record["cases"]["current_collateral"] = chosen
    record["full_appraisal_accepted"] = chosen.get("strict_accepted")
    record["limits"] = list(record.get("limits", [])) + list(replay.get("limits", []))
    return record


# ------------------------------------------------------------------ record


def _status(value: Any, name: str) -> int:
    if not isinstance(value, str) or not _STATUS.fullmatch(value):
        raise CollateralDenied(f"record_{name}")
    return int(value, 16)


def _case(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _CASE_KEYS:
        raise CollateralDenied("record_case_fields")
    api = _status(value["api_status"], "api_status")
    qv = _status(value["qv_result"], "qv_result")
    expiry = value["collateral_expiration_status"]
    strict = value["strict_accepted"]
    if type(expiry) is not int or type(strict) is not bool:
        raise CollateralDenied("record_case_fields")
    if strict != (api == 0 and qv == 0 and expiry == 0):
        raise CollateralDenied("record_inconsistent")
    return {"api": api, "qv": qv, "expiry": expiry, "strict": strict}


def _check_record(record: Any, quote: bytes, policy: CollateralPolicy) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise CollateralDenied("record_fields")
    if record["kind"] != RECORD_KIND:
        raise CollateralDenied("record_kind")
    if type(quote) is not bytes or hashlib.sha256(quote).hexdigest() != record["quote_sha256"]:
        raise CollateralDenied("quote_mismatch")
    if type(record["verified_at"]) is not int or record["verified_at"] <= 0:
        raise CollateralDenied("record_time")
    if record["packages"] != policy.verifier_packages:
        raise CollateralDenied("verifier_packages")
    if record["qve_used"] is not False:
        # A QvE report would need its own authentication, which this adapter lacks.
        raise CollateralDenied("qve_unsupported")
    if _status(record["retrieval_status"], "retrieval_status") != 0:
        raise CollateralDenied("collateral_retrieval")
    if not isinstance(record["collateral_sha256"], str) or not _HEX64.fullmatch(
        record["collateral_sha256"]
    ):
        raise CollateralDenied("record_collateral_sha256")
    if not isinstance(record["limits"], list) or any(
        not isinstance(item, str) for item in record["limits"]
    ):
        raise CollateralDenied("record_limits")
    cases = record["cases"]
    if not isinstance(cases, dict) or "current_collateral" not in cases:
        raise CollateralDenied("record_cases")
    parsed = {name: _case(value) for name, value in cases.items()}
    current = parsed.pop("current_collateral")
    if record["full_appraisal_accepted"] is not current["strict"]:
        raise CollateralDenied("record_inconsistent")
    # The run's own negative controls (tampered quote/collateral, expired date)
    # must all have been rejected, or the run did not distinguish anything.
    if record["negative_controls_rejected"] is not True or any(
        case["strict"] for case in parsed.values()
    ):
        raise CollateralDenied("negative_controls")
    return current


def _check_qcnl(raw: bytes, policy: CollateralPolicy) -> None:
    config = _json(raw, "qcnl")
    if not isinstance(config, dict):
        raise CollateralDenied("qcnl_format")
    if config.get("tcb_update_type") != policy.update_policy:
        raise CollateralDenied("update_policy_mismatch")
    for key in ("pccs_url", "collateral_service"):
        value = config.get(key)
        if not isinstance(value, str) or not value.startswith(INTEL_PCS):
            raise CollateralDenied("qcnl_collateral_source")
    if config.get("use_secure_cert") is not True:
        raise CollateralDenied("qcnl_insecure")
    if (
        config.get("pck_cache_expire_hours") != 0
        or config.get("verify_collateral_cache_expire_hours") != 0
    ):
        raise CollateralDenied("qcnl_cache")


# --------------------------------------------------------------- collateral


def _time(value: Any, name: str) -> int:
    if not isinstance(value, str):
        raise CollateralDenied(f"{name}_format")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CollateralDenied(f"{name}_format") from exc
    return int(parsed.timestamp())


def _cn(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if len(names) == 1 else ""


def _chain(raw: bytes, root: x509.Certificate, at: datetime, name: str) -> list[x509.Certificate]:
    from wcm._quote_verify import TrustStore, verify_cert_chain

    try:
        certs = x509.load_pem_x509_certificates(raw)
    except ValueError as exc:
        raise CollateralDenied(f"{name}_format") from exc
    for cert in certs[1:]:
        try:
            ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            ca = False
        if not ca:
            raise CollateralDenied(f"{name}_not_ca")
    store = TrustStore()
    store.add_root(root)
    if len(certs) < 2 or verify_cert_chain(certs[0], certs[1:], store, at) is not None:
        raise CollateralDenied(f"{name}_chain")
    return certs


def _raw_signature(pub: Any, signature_hex: Any, message: bytes, name: str) -> None:
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise CollateralDenied(f"{name}_key")
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", signature_hex):
        raise CollateralDenied(f"{name}_signature")
    raw = bytes.fromhex(signature_hex)
    der = utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    try:
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise CollateralDenied(f"{name}_signature") from exc


def _signed_json(raw: bytes, key: str, signer: x509.Certificate, name: str) -> dict[str, Any]:
    """Intel signs the exact bytes of the body's first member value."""
    prefix, marker = b'{"' + key.encode() + b'":', b',"signature":"'
    at = raw.rfind(marker)
    if not raw.startswith(prefix) or at < 0 or not raw.endswith(b'"}'):
        raise CollateralDenied(f"{name}_format")
    signed = raw[len(prefix) : at]
    body = _json(raw, name)
    inner = _json(signed, name)
    if (
        not isinstance(body, dict)
        or not isinstance(inner, dict)
        or set(body) != {key, "signature"}
        or body[key] != inner
    ):
        raise CollateralDenied(f"{name}_format")
    _raw_signature(signer.public_key(), body["signature"], signed, name)
    return inner


def _crl(
    raw: bytes, issuer: x509.Certificate, at: int, name: str
) -> x509.CertificateRevocationList:
    try:
        crl = x509.load_der_x509_crl(raw)
    except ValueError as exc:
        raise CollateralDenied(f"{name}_format") from exc
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise CollateralDenied(f"{name}_signature")
    if crl.next_update_utc is None or not (
        crl.last_update_utc.timestamp() <= at < crl.next_update_utc.timestamp()
    ):
        raise CollateralDenied(f"{name}_expired")
    return crl


def _window(document: dict[str, Any], at: int, name: str) -> int:
    issued = _time(document.get("issueDate"), name)
    next_update = _time(document.get("nextUpdate"), name)
    if not issued <= at < next_update:
        raise CollateralDenied(f"{name}_expired")
    return next_update


def _der(blob: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(blob):
        raise CollateralDenied("pck_extension")
    tag, length, offset = blob[offset], blob[offset + 1], offset + 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 3 or offset + count > len(blob):
            raise CollateralDenied("pck_extension")
        length, offset = int.from_bytes(blob[offset : offset + count], "big"), offset + count
    end = offset + length
    if end > len(blob):
        raise CollateralDenied("pck_extension")
    return tag, blob[offset:end], end


def _sequence(blob: bytes) -> list[tuple[int, bytes]]:
    items, offset = [], 0
    while offset < len(blob):
        tag, value, offset = _der(blob, offset)
        items.append((tag, value))
    return items


def _oid(value: bytes) -> str:
    if not value:
        raise CollateralDenied("pck_extension")
    parts, number = [min(value[0] // 40, 2), value[0] - 40 * min(value[0] // 40, 2)], 0
    for byte in value[1:]:
        number = number << 7 | byte & 0x7F
        if not byte & 0x80:
            parts.append(number)
            number = 0
    return ".".join(map(str, parts))


def _pck_extension(cert: x509.Certificate) -> dict[str, Any]:
    """FMSPC, PCE-ID, the 16 SGX TCB component SVNs and PCESVN from the PCK leaf."""
    try:
        ext = cert.extensions.get_extension_for_oid(_SGX_EXTENSION).value
    except x509.ExtensionNotFound as exc:
        raise CollateralDenied("pck_extension") from exc
    if not isinstance(ext, x509.UnrecognizedExtension):
        raise CollateralDenied("pck_extension")
    tag, body, end = _der(ext.value, 0)
    if tag != 0x30 or end != len(ext.value):
        raise CollateralDenied("pck_extension")
    base = _SGX_EXTENSION.dotted_string
    values: dict[str, tuple[int, bytes]] = {}
    for tag, item in _sequence(body):
        pair = _sequence(item) if tag == 0x30 else []
        if len(pair) != 2 or pair[0][0] != 0x06:
            raise CollateralDenied("pck_extension")
        name = _oid(pair[0][1])
        if name == base + ".2":
            for inner_tag, inner in _sequence(pair[1][1]):
                sub = _sequence(inner) if inner_tag == 0x30 else []
                if len(sub) != 2 or sub[0][0] != 0x06:
                    raise CollateralDenied("pck_extension")
                values[_oid(sub[0][1])] = sub[1]
        else:
            values[name] = pair[1]

    def integer(oid: str) -> int:
        tag, raw = values.get(oid, (0, b""))
        if tag != 0x02 or not raw or raw[0] & 0x80 or len(raw) > 3:
            raise CollateralDenied("pck_extension")
        return int.from_bytes(raw, "big")

    def octets(oid: str, size: int) -> bytes:
        tag, raw = values.get(oid, (0, b""))
        if tag != 0x04 or len(raw) != size:
            raise CollateralDenied("pck_extension")
        return raw

    return {
        "fmspc": octets(base + ".4", 6).hex(),
        "pceid": octets(base + ".3", 2).hex(),
        "sgx_svns": [integer(f"{base}.2.{i}") for i in range(1, 17)],
        "pcesvn": integer(base + ".2.17"),
    }


def _svns(components: Any) -> list[int]:
    if not isinstance(components, list) or len(components) != 16:
        raise CollateralDenied("tcb_info_levels")
    out = []
    for component in components:
        svn = component.get("svn") if isinstance(component, dict) else None
        if type(svn) is not int or not 0 <= svn <= 255:
            raise CollateralDenied("tcb_info_levels")
        out.append(svn)
    return out


def _masked(value: bytes, expected: Any, mask: Any, name: str) -> bool:
    try:
        want, bits = bytes.fromhex(expected), bytes.fromhex(mask)
    except (TypeError, ValueError) as exc:
        raise CollateralDenied(f"{name}_format") from exc
    if len(want) != len(value) or len(bits) != len(value):
        raise CollateralDenied(f"{name}_format")
    return all(v & m == w & m for v, w, m in zip(value, want, bits, strict=True))


def _isvsvn_status(levels: Any, isvsvn: int, name: str) -> dict[str, Any]:
    if not isinstance(levels, list):
        raise CollateralDenied(f"{name}_format")
    for level in levels:
        try:
            floor = level["tcb"]["isvsvn"]
        except (KeyError, TypeError) as exc:
            raise CollateralDenied(f"{name}_format") from exc
        if type(floor) is not int:
            raise CollateralDenied(f"{name}_format")
        if isvsvn >= floor:
            return level
    raise CollateralDenied(f"{name}_tcb_unsupported")


def _converge(platform: str, other: str) -> str:
    """Fold a QE or TDX module status into the platform status, as QVL does."""
    if other == "Revoked":
        return "Revoked"
    if other == "OutOfDate":
        if platform in ("UpToDate", "SWHardeningNeeded"):
            return "OutOfDate"
        if platform in ("ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
            return "OutOfDateConfigurationNeeded"
    if other != "UpToDate" and other not in _STATUS_TO_QV:
        raise CollateralDenied("tcb_status_unknown")
    return platform


def appraise_collateral(
    collateral: bytes, quote: bytes, trust_root: x509.Certificate, *, at: int
) -> dict[str, Any]:
    """Re-verify saved Intel collateral offline and re-derive the TDX TCB status at `at`.

    `trust_root` must be the operator-pinned Intel SGX Root CA, never one taken
    from the collateral or the quote.
    """
    from wcm.tdx import parse_tdx_quote, verify_tdx_quote

    from wcm._quote_verify import QuoteFormatError, TrustStore

    if type(at) is not int or at <= 0 or not isinstance(trust_root, x509.Certificate):
        raise CollateralDenied("collateral_inputs")
    when = datetime.fromtimestamp(at, UTC)
    snapshot = _json(collateral, "collateral")
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"version", "tee_type", "fields"}
        or snapshot["version"] != 3
        or snapshot["tee_type"] != 0x81
        or not isinstance(snapshot["fields"], dict)
        or set(snapshot["fields"]) != set(FIELDS)
    ):
        raise CollateralDenied("collateral_structure")
    fields: dict[str, bytes] = {}
    for name in FIELDS:
        encoded = snapshot["fields"][name]
        try:
            value = base64.b64decode(encoded, validate=True)
        except (TypeError, ValueError) as exc:
            raise CollateralDenied("collateral_field") from exc
        # QVL sizes every collateral buffer to include one terminating NUL.
        if len(value) < 2 or value[-1] != 0 or base64.b64encode(value).decode() != encoded:
            raise CollateralDenied("collateral_field")
        fields[name] = value[:-1]

    tcb_chain = _chain(fields["tcb_info_issuer_chain"], trust_root, when, "tcb_info")
    qe_chain = _chain(fields["qe_identity_issuer_chain"], trust_root, when, "qe_identity")
    crl_chain = _chain(fields["pck_crl_issuer_chain"], trust_root, when, "pck_crl")
    if _cn(tcb_chain[0]) != _TCB_SIGNER or _cn(qe_chain[0]) != _TCB_SIGNER:
        raise CollateralDenied("tcb_signer")
    if _cn(crl_chain[0]) not in _PCK_CAS:
        raise CollateralDenied("pck_crl_issuer")
    root_crl = _crl(fields["root_ca_crl"], trust_root, at, "root_ca_crl")
    pck_crl = _crl(fields["pck_crl"], crl_chain[0], at, "pck_crl")
    for cert in (tcb_chain[0], qe_chain[0], crl_chain[0]):
        if root_crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            raise CollateralDenied("intermediate_revoked")

    tcb_info = _signed_json(fields["tcb_info"], "tcbInfo", tcb_chain[0], "tcb_info")
    qe_identity = _signed_json(fields["qe_identity"], "enclaveIdentity", qe_chain[0], "qe_identity")
    if tcb_info.get("id") != "TDX" or tcb_info.get("version") != 3 or tcb_info.get("tcbType") != 0:
        raise CollateralDenied("tcb_info_kind")
    if qe_identity.get("id") != "TD_QE" or qe_identity.get("version") != 2:
        raise CollateralDenied("qe_identity_kind")
    fresh_until = min(
        _window(tcb_info, at, "tcb_info"),
        _window(qe_identity, at, "qe_identity"),
        int(root_crl.next_update_utc.timestamp()),  # type: ignore[union-attr]
        int(pck_crl.next_update_utc.timestamp()),  # type: ignore[union-attr]
    )

    # Quote: attestation key, QE report binding, PCK signature, PCK chain.
    store = TrustStore()
    store.add_root(trust_root)
    if not verify_tdx_quote(quote, store, now=when).verified:
        raise CollateralDenied("quote_verification")
    try:
        parsed = parse_tdx_quote(quote)
    except QuoteFormatError as exc:
        raise CollateralDenied("quote_format") from exc
    if parsed.version != 4:
        raise CollateralDenied("quote_version")
    pck = parsed.pck_leaf
    if (
        pck.issuer != crl_chain[0].subject
        or not parsed.pck_intermediates
        or (parsed.pck_intermediates[0] != crl_chain[0])
    ):
        raise CollateralDenied("pck_crl_scope")
    if pck_crl.get_revoked_certificate_by_serial_number(pck.serial_number) is not None:
        raise CollateralDenied("pck_revoked")
    platform = _pck_extension(pck)
    if (
        str(tcb_info.get("fmspc", "")).lower() != platform["fmspc"]
        or str(tcb_info.get("pceId", "")).lower() != platform["pceid"]
    ):
        raise CollateralDenied("tcb_info_platform")

    # QE identity (SGX report body layout).
    qe = parsed.qe_report
    if (
        not _masked(
            qe[16:20],
            qe_identity.get("miscselect"),
            qe_identity.get("miscselectMask"),
            "qe_identity",
        )
        or not _masked(
            qe[48:64],
            qe_identity.get("attributes"),
            qe_identity.get("attributesMask"),
            "qe_identity",
        )
        or str(qe_identity.get("mrsigner", "")).lower() != qe[128:160].hex()
        or qe_identity.get("isvprodid") != int.from_bytes(qe[256:258], "little")
    ):
        raise CollateralDenied("qe_identity_mismatch")
    qe_level = _isvsvn_status(
        qe_identity.get("tcbLevels"), int.from_bytes(qe[258:260], "little"), "qe_identity"
    )

    # TCB level: first level whose SGX components, PCESVN and TDX components
    # (from TEE_TCB_SVN, skipping the module bytes when a module identity applies)
    # are all at or below the platform's.
    tee_tcb_svn = parsed.report.raw[0:16]
    start = 2 if tee_tcb_svn[1] > 0 else 0
    levels = tcb_info.get("tcbLevels")
    if not isinstance(levels, list):
        raise CollateralDenied("tcb_info_levels")
    level = None
    for candidate in levels:
        try:
            tcb = candidate["tcb"]
            sgx, pcesvn, tdx = (
                _svns(tcb["sgxtcbcomponents"]),
                tcb["pcesvn"],
                _svns(tcb["tdxtcbcomponents"]),
            )
        except (KeyError, TypeError) as exc:
            raise CollateralDenied("tcb_info_levels") from exc
        if type(pcesvn) is not int:
            raise CollateralDenied("tcb_info_levels")
        if (
            all(p >= s for p, s in zip(platform["sgx_svns"], sgx, strict=True))
            and platform["pcesvn"] >= pcesvn
            and all(tee_tcb_svn[i] >= tdx[i] for i in range(start, 16))
        ):
            level = candidate
            break
    if level is None:
        raise CollateralDenied("tcb_level_unsupported")
    status = level.get("tcbStatus")
    if status not in _STATUS_TO_QV:
        raise CollateralDenied("tcb_status_unknown")

    module_status = None
    if tee_tcb_svn[1] > 0:
        identity_id = f"TDX_{tee_tcb_svn[1]:02X}"
        identities = [
            i
            for i in tcb_info.get("tdxModuleIdentities") or []
            if isinstance(i, dict) and i.get("id") == identity_id
        ]
        if len(identities) != 1:
            raise CollateralDenied("tdx_module_identity_missing")
        identity = identities[0]
        report = parsed.report.raw
        if str(identity.get("mrsigner", "")).lower() != report[64:112].hex() or not _masked(
            report[112:120],
            identity.get("attributes"),
            identity.get("attributesMask"),
            "tdx_module",
        ):
            raise CollateralDenied("tdx_module_identity_mismatch")
        module_level = _isvsvn_status(identity.get("tcbLevels"), tee_tcb_svn[0], "tdx_module")
        module_status = module_level.get("tcbStatus")
        status = _converge(status, module_status)
    else:
        module = tcb_info.get("tdxModule")
        report = parsed.report.raw
        if (
            not isinstance(module, dict)
            or str(module.get("mrsigner", "")).lower() != report[64:112].hex()
            or not _masked(
                report[112:120],
                module.get("attributes"),
                module.get("attributesMask"),
                "tdx_module",
            )
        ):
            raise CollateralDenied("tdx_module_identity_mismatch")
    status = _converge(status, qe_level.get("tcbStatus"))

    return {
        "tcb_evaluation_data_number": tcb_info.get("tcbEvaluationDataNumber"),
        "qe_tcb_evaluation_data_number": qe_identity.get("tcbEvaluationDataNumber"),
        "tcb_status": status,
        "platform_tcb_status": level["tcbStatus"],
        "tdx_module_tcb_status": module_status,
        "qe_tcb_status": qe_level.get("tcbStatus"),
        "tcb_date": level.get("tcbDate"),
        "advisory_ids": sorted(level.get("advisoryIDs") or []),
        "qv_result": _STATUS_TO_QV[status],
        "fmspc": platform["fmspc"],
        "fresh_until": fresh_until,
    }


# ---------------------------------------------------------------- appraisal


def appraise(
    packet: Packet,
    quote: bytes,
    policy: CollateralPolicy,
    *,
    trust_root: x509.Certificate,
    not_before: int,
    not_after: int,
) -> dict[str, Any]:
    """Enforced verdict for one QVL run over exactly `quote`, or CollateralDenied.

    The record must have been produced inside [not_before, not_after]. The
    returned status is "affirming", or "warning" only for an allowlisted code.
    """
    if not isinstance(policy, CollateralPolicy) or not isinstance(packet, Packet):
        raise CollateralDenied("inputs")
    if type(not_before) is not int or type(not_after) is not int or not 0 < not_before <= not_after:
        raise CollateralDenied("window")
    current = _check_record(packet.record, quote, policy)
    record = packet.record
    verified_at = record["verified_at"]
    if verified_at < not_before:
        raise CollateralDenied("record_stale")
    if verified_at > not_after:
        raise CollateralDenied("record_future")
    if type(packet.collateral) is not bytes or (
        hashlib.sha256(packet.collateral).hexdigest() != record["collateral_sha256"]
    ):
        raise CollateralDenied("collateral_mismatch")
    _check_qcnl(packet.qcnl_config, policy)
    if current["api"] != 0:
        raise CollateralDenied("qvl_api_status")
    if current["expiry"] != 0:
        raise CollateralDenied("collateral_expired")
    code = current["qv"]
    name = QV_RESULTS.get(code)
    if name is None:
        raise CollateralDenied("qv_result_unknown")
    if code != QV_OK and code not in policy.allowed_qv_results:
        raise CollateralDenied("qv_" + name)

    offline = appraise_collateral(packet.collateral, quote, trust_root, at=verified_at)
    number = policy.tcb_evaluation_data_number
    if (
        offline["tcb_evaluation_data_number"] != number
        or offline["qe_tcb_evaluation_data_number"] != number
    ):
        raise CollateralDenied("tcb_evaluation_data_number")
    if offline["qv_result"] != code:
        raise CollateralDenied("offline_tcb_disagrees")
    return {
        "profile": PROFILE,
        "status": "affirming" if code == QV_OK else "warning",
        "reasons": [] if code == QV_OK else ["qv_" + name],
        "update_policy": policy.update_policy,
        "tcb_evaluation_data_number": number,
        "qv_result": f"{code:#x}",
        "tcb_status": offline["tcb_status"],
        "tcb_date": offline["tcb_date"],
        "advisory_ids": offline["advisory_ids"],
        "fmspc": offline["fmspc"],
        "quote_sha256": record["quote_sha256"],
        "collateral_sha256": record["collateral_sha256"],
        "verified_at": verified_at,
        "collateral_fresh_until": offline["fresh_until"],
        "limits": list(LIMITS) + list(record["limits"]),
    }


def runtime_component(
    packet: Packet,
    quote: bytes,
    policy: CollateralPolicy,
    *,
    trust_root: x509.Certificate,
    authority: str,
    now: int,
    max_age: int = 300,
) -> Any:
    """Issuer-side adapter from an appraised QVL run to a TRACE runtime component.

    The record must be at most `max_age` seconds old at the issuer's `now`, and
    freshness never outlives the collateral. The instance names the quote, not
    a workload: a same-instance binding needs separate launch evidence.
    """
    from .verifier_token import Component, EvidenceRef, canonical_digest, digest

    if type(now) is not int or now <= 0 or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise CollateralDenied("clock_or_age")
    verdict = appraise(
        packet, quote, policy, trust_root=trust_root, not_before=now - max_age, not_after=now
    )
    fresh_until = min(verdict["verified_at"] + max_age, verdict["collateral_fresh_until"])
    if fresh_until <= now:
        raise CollateralDenied("record_stale")
    profile = f"{PROFILE}/{policy.update_policy}"
    refs = [
        (RECORD_MEDIA_TYPE, canonical_digest(packet.record)),
        (COLLATERAL_MEDIA_TYPE, digest(packet.collateral)),
        (QUOTE_MEDIA_TYPE, digest(quote)),
    ]
    return Component(
        component_id="runtime.cpu",
        component_type="runtime",
        profile=profile,
        authority=authority,
        instance="tdx-quote/" + verdict["quote_sha256"],
        status=verdict["status"],
        appraised_at=verdict["verified_at"],
        fresh_until=fresh_until,
        evidence_refs=[EvidenceRef(profile=profile, media_type=m, digest=d) for m, d in refs],
        observed_digest=None,
        reasons=verdict["reasons"],
    )
