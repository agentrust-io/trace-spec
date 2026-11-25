"""Enforced verdicts over the saved native Intel QVL records for the GCP TDX quote.

Every positive and most negative cases start from the real stage 2 artifacts in
cloud-20260929/collateral-appraisal and the pinned Intel SGX Root CA.
"""

import base64
import copy
import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from prototype import tdx_collateral as t

CLOUD = Path(__file__).resolve().parents[2] / "cloud-20260929"
_HAS_CLOUD = (CLOUD / "gcp-platform-run" / "evidence.bin").is_file()
APPRAISAL = CLOUD / "collateral-appraisal"
QUOTE = (CLOUD / "gcp-platform-run" / "evidence.bin").read_bytes() if _HAS_CLOUD else b""
ROOT = (
    x509.load_pem_x509_certificate((CLOUD / "intel-root.pem").read_bytes())
    if _HAS_CLOUD
    else None
)
STANDARD = t.CollateralPolicy("standard", 20)
EARLY = t.CollateralPolicy("early", 22)
AUTHORITY = "spiffe://example.test/tdx-appraiser"


def _require_cloud():
    if not _HAS_CLOUD:
        pytest.skip("saved TDX quote and collateral are absent")


def packet(name):
    _require_cloud()
    return t.load_packet(APPRAISAL / name)


def at(p):
    return p.record["verified_at"]


def run(p, policy, quote=QUOTE, root=ROOT, window=None):
    when = at(p) if window is None else window
    lo, hi = when if isinstance(when, tuple) else (when, when)
    return t.appraise(p, quote, policy, trust_root=root, not_before=lo, not_after=hi)


def denied(reason, fn, *args, **kwargs):
    with pytest.raises(t.CollateralDenied, match=f"^{reason}$"):
        fn(*args, **kwargs)


def with_record(p, mutate):
    record = copy.deepcopy(p.record)
    mutate(record)
    return dataclasses.replace(p, record=record)


def fields(p):
    return json.loads(p.collateral)


def collateral_with(p, name, change):
    snapshot = fields(p)
    value = base64.b64decode(snapshot["fields"][name])[:-1]
    snapshot["fields"][name] = base64.b64encode(change(value) + b"\x00").decode()
    return json.dumps(snapshot, indent=2).encode()


def test_intel_root_is_the_independently_downloaded_pin():
    _require_cloud()
    pin = json.loads((CLOUD / "trust-root.json").read_text(encoding="utf-8"))["intel"]
    der = ROOT.public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == pin["der_sha256"]
    assert hashlib.sha256(QUOTE).hexdigest() == packet("standard").record["quote_sha256"]


# ------------------------------------------------------------- positive


def test_standard_record_is_affirming_under_standard_policy():
    verdict = run(packet("standard"), STANDARD)
    assert verdict["status"] == "affirming" and verdict["reasons"] == []
    assert verdict["update_policy"] == "standard"
    assert verdict["tcb_evaluation_data_number"] == 20
    assert verdict["qv_result"] == "0x0" and verdict["tcb_status"] == "UpToDate"
    assert verdict["fmspc"] == "00806f050000"
    assert any("QvE" in limit for limit in verdict["limits"])
    assert any("Intel does not sign" in limit for limit in verdict["limits"])


def test_offline_rederivation_matches_native_qvl_for_both_policies():
    s, e = packet("standard"), packet("early")
    standard = t.appraise_collateral(s.collateral, QUOTE, ROOT, at=at(s))
    early = t.appraise_collateral(e.collateral, QUOTE, ROOT, at=at(e))
    assert (standard["tcb_status"], standard["qv_result"]) == ("UpToDate", 0x0)
    assert standard["tcb_evaluation_data_number"] == 20
    assert (early["tcb_status"], early["qv_result"]) == ("OutOfDate", 0xA002)
    assert early["tcb_evaluation_data_number"] == 22
    # The early baseline's platform level is the cause; module and QE are current.
    assert early["platform_tcb_status"] == "OutOfDate"
    assert early["tdx_module_tcb_status"] == early["qe_tcb_status"] == "UpToDate"
    assert "INTEL-SA-01439" in early["advisory_ids"]
    for p, offline in ((s, standard), (e, early)):
        assert int(p.record["cases"]["current_collateral"]["qv_result"], 16) == offline["qv_result"]


# ------------------------------------------------------ policy selection


def test_early_record_denies_under_early_policy():
    assert packet("early").record["cases"]["current_collateral"]["qv_result"] == "0xa002"
    denied("qv_out_of_date", run, packet("early"), EARLY)


def test_early_record_presented_as_standard_denies():
    denied("update_policy_mismatch", run, packet("early"), STANDARD)


def test_relabelled_run_configuration_is_caught_by_the_signed_evaluation_number():
    s, e = packet("standard"), packet("early")
    relabelled = dataclasses.replace(e, qcnl_config=s.qcnl_config)
    denied(
        "tcb_evaluation_data_number",
        run,
        relabelled,
        t.CollateralPolicy("standard", 20, frozenset({0xA002})),
    )
    as_early = dataclasses.replace(s, qcnl_config=e.qcnl_config)
    denied("tcb_evaluation_data_number", run, as_early, EARLY)
    denied("tcb_evaluation_data_number", run, s, t.CollateralPolicy("standard", 19))


def test_record_claiming_ok_for_the_early_run_is_denied_by_the_evidence():
    def forge(record):
        record["cases"]["current_collateral"].update(qv_result="0x0", strict_accepted=True)
        record["full_appraisal_accepted"] = True

    denied("offline_tcb_disagrees", run, with_record(packet("early"), forge), EARLY)


def test_allowlisting_out_of_date_is_causal():
    e = packet("early")
    denied("qv_out_of_date", run, e, EARLY)
    denied("qv_out_of_date", run, e, t.CollateralPolicy("early", 22, frozenset({0xA007})))
    verdict = run(e, t.CollateralPolicy("early", 22, frozenset({0xA002})))
    assert verdict["status"] == "warning" and verdict["reasons"] == ["qv_out_of_date"]
    assert verdict["update_policy"] == "early" and verdict["qv_result"] == "0xa002"
    # The allowlist changes nothing for a record that is already OK.
    standard = run(packet("standard"), t.CollateralPolicy("standard", 20, frozenset({0xA002})))
    assert standard["status"] == "affirming"


@pytest.mark.parametrize("code", [0xA004, 0xA005, 0xA006, 0xA0FF, 0x0])
def test_signature_revocation_and_unknown_codes_are_not_allowlistable(code):
    denied("policy_allowed_qv_results", t.CollateralPolicy, "early", 22, frozenset({code}))


@pytest.mark.parametrize(
    ("args", "reason"),
    [
        (("preview", 20), "policy_update_policy"),
        (("standard", 0), "policy_tcb_evaluation_data_number"),
        (("standard", True), "policy_tcb_evaluation_data_number"),
        (("standard", 20, {0xA002}), "policy_allowed_qv_results"),
    ],
)
def test_policy_is_validated(args, reason):
    denied(reason, t.CollateralPolicy, *args)


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        ("0xa007", "qv_sw_hardening_needed"),
        ("0xa001", "qv_config_needed"),
        ("0xa003", "qv_out_of_date_config_needed"),
        ("0xa005", "qv_revoked"),
        ("0xa004", "qv_invalid_signature"),
        ("0xa0ff", "qv_result_unknown"),
    ],
)
def test_non_ok_results_deny_by_default(code, reason):
    def change(record):
        record["cases"]["current_collateral"].update(qv_result=code, strict_accepted=False)
        record["full_appraisal_accepted"] = False

    denied(reason, run, with_record(packet("standard"), change), STANDARD)


# ------------------------------------------------------------- expiry


def test_ten_year_expired_offline_replay_denies():
    _require_cloud()
    replay = json.loads(
        (APPRAISAL / "offline" / "offline-replay.json").read_text(encoding="utf-8")
    )
    for name, policy in (
        ("standard", STANDARD),
        ("early", t.CollateralPolicy("early", 22, frozenset({0xA002}))),
    ):
        base = packet(name)
        expired = dataclasses.replace(
            base, record=t.replay_record(replay, base.record, name, "expired")
        )
        assert expired.record["cases"]["current_collateral"]["collateral_expiration_status"] == 1
        denied("collateral_expired", run, expired, policy)
        # The ordinary window already rejects a record ten years out.
        denied("record_future", run, expired, policy, window=at(base))


def test_historical_offline_replay_reproduces_the_saved_verdict():
    _require_cloud()
    replay = json.loads(
        (APPRAISAL / "offline" / "offline-replay.json").read_text(encoding="utf-8")
    )
    base = packet("standard")
    historical = dataclasses.replace(
        base, record=t.replay_record(replay, base.record, "standard", "historical")
    )
    assert run(historical, STANDARD)["status"] == "affirming"
    denied("replay_inconsistent", t.replay_record, replay, base.record, "early", "historical")


def test_offline_collateral_check_independently_rejects_expiry():
    s = packet("standard")
    crl = base64.b64decode(fields(s)["fields"]["pck_crl"])[:-1]
    next_update = int(x509.load_der_x509_crl(crl).next_update_utc.timestamp())
    denied("pck_crl_expired", t.appraise_collateral, s.collateral, QUOTE, ROOT, at=next_update)
    with pytest.raises(t.CollateralDenied):
        t.appraise_collateral(s.collateral, QUOTE, ROOT, at=at(s) + t.REPLAY_EXPIRY_SHIFT)


def test_saved_future_expired_case_is_the_same_signal():
    case = packet("standard").record["cases"]["future_expired_collateral"]

    def change(record):
        record["cases"]["current_collateral"] = dict(case)
        record["full_appraisal_accepted"] = False

    assert case["qv_result"] == "0x0" and case["collateral_expiration_status"] == 1
    denied("collateral_expired", run, with_record(packet("standard"), change), STANDARD)


# ------------------------------------------------------ binding and time


def test_other_quote_bytes_deny():
    _require_cloud()
    changed = bytearray(QUOTE)
    changed[100] ^= 1  # the byte qvl_capture.py flips for its tampered_quote case
    denied("quote_mismatch", run, packet("standard"), STANDARD, quote=bytes(changed))
    denied(
        "quote_verification",
        t.appraise_collateral,
        packet("standard").collateral,
        bytes(changed),
        ROOT,
        at=at(packet("standard")),
    )


def test_stale_and_future_records_deny():
    s = packet("standard")
    denied("record_stale", run, s, STANDARD, window=(at(s) + 1, at(s) + 300))
    denied("record_future", run, s, STANDARD, window=(at(s) - 300, at(s) - 1))
    denied("window", run, s, STANDARD, window=(at(s), at(s) - 1))


# ----------------------------------------------------- tampered records


def _set(path, value):
    def mutate(record):
        target = record
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return mutate


CURRENT = ("cases", "current_collateral")


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (_set(("kind",), "trace-intel-qvl-appraisal/v2"), "record_kind"),
        (_set(("quote_sha256",), "00" * 32), "quote_mismatch"),
        (_set(("collateral_sha256",), "00" * 32), "collateral_mismatch"),
        (_set(("verified_at",), True), "record_time"),
        (_set(("verified_at",), "1790727972"), "record_time"),
        (_set(("packages",), "libsgx-dcap-quote-verify\t1.26.0"), "verifier_packages"),
        (_set(("qve_used",), True), "qve_unsupported"),
        (_set(("retrieval_status",), "0xe011"), "collateral_retrieval"),
        (_set(("retrieval_status",), "0"), "record_retrieval_status"),
        (_set(("negative_controls_rejected",), False), "negative_controls"),
        (_set(("cases", "tampered_tcb_info", "strict_accepted"), True), "record_inconsistent"),
        (_set(("full_appraisal_accepted",), False), "record_inconsistent"),
        (_set((*CURRENT, "api_status"), "0xe068"), "record_inconsistent"),
        (_set((*CURRENT, "collateral_expiration_status"), 1), "record_inconsistent"),
        (_set((*CURRENT, "collateral_expiration_status"), False), "record_case_fields"),
        (_set((*CURRENT, "extra"), 1), "record_case_fields"),
        (_set(("signed",), True), "record_fields"),
        (lambda r: r.pop("limits"), "record_fields"),
    ],
)
def test_tampered_record_fields_deny(mutate, reason):
    s = packet("standard")
    denied(reason, run, with_record(s, mutate), STANDARD, window=at(s))


def test_nonzero_status_with_consistent_strict_flag_denies():
    def api(record):
        record["cases"]["current_collateral"].update(api_status="0xe068", strict_accepted=False)
        record["full_appraisal_accepted"] = False

    def expiry(record):
        record["cases"]["current_collateral"].update(
            collateral_expiration_status=1, strict_accepted=False
        )
        record["full_appraisal_accepted"] = False

    denied("qvl_api_status", run, with_record(packet("standard"), api), STANDARD)
    denied("collateral_expired", run, with_record(packet("standard"), expiry), STANDARD)


def test_duplicate_json_keys_deny(tmp_path):
    _require_cloud()
    for name in ("qvl-appraisal.json", "intel-collateral.json", "sgx_default_qcnl.conf"):
        (tmp_path / name).write_bytes((APPRAISAL / "standard" / name).read_bytes())
    raw = (tmp_path / "qvl-appraisal.json").read_text(encoding="utf-8")
    (tmp_path / "qvl-appraisal.json").write_text(
        raw.replace('"qve_used": false,', '"qve_used": false, "qve_used": false,'),
        encoding="utf-8",
    )
    denied("json_duplicate_key", t.load_packet, tmp_path)


# --------------------------------------------------- run configuration


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"use_secure_cert": False}, "qcnl_insecure"),
        (
            {"collateral_service": "https://pccs.example.test/sgx/certification/v4/"},
            "qcnl_collateral_source",
        ),
        ({"verify_collateral_cache_expire_hours": 24}, "qcnl_cache"),
        ({"tcb_update_type": None}, "update_policy_mismatch"),
    ],
)
def test_run_configuration_fields_are_enforced(change, reason):
    s = packet("standard")
    config = {**json.loads(s.qcnl_config), **change}
    denied(reason, run, dataclasses.replace(s, qcnl_config=json.dumps(config).encode()), STANDARD)


# ----------------------------------------------- collateral cryptography


def test_tampered_collateral_fails_offline_verification():
    s = packet("standard")

    def status(value):
        changed = value.replace(b'"tcbStatus":"UpToDate"', b'"tcbStatus":"UpToDaTe"', 1)
        assert changed != value
        return changed

    def qe_svn(value):
        changed = value.replace(b'"isvprodid":2', b'"isvprodid":3', 1)
        assert changed != value
        return changed

    def flip_last(value):
        return value[:-1] + bytes([value[-1] ^ 1])

    denied(
        "tcb_info_signature",
        t.appraise_collateral,
        collateral_with(s, "tcb_info", status),
        QUOTE,
        ROOT,
        at=at(s),
    )
    denied(
        "qe_identity_signature",
        t.appraise_collateral,
        collateral_with(s, "qe_identity", qe_svn),
        QUOTE,
        ROOT,
        at=at(s),
    )
    denied(
        "pck_crl_signature",
        t.appraise_collateral,
        collateral_with(s, "pck_crl", flip_last),
        QUOTE,
        ROOT,
        at=at(s),
    )
    denied(
        "root_ca_crl_signature",
        t.appraise_collateral,
        collateral_with(s, "root_ca_crl", flip_last),
        QUOTE,
        ROOT,
        at=at(s),
    )
    # The QVL record binds the collateral bytes, so tampering there is caught first.
    tampered = dataclasses.replace(s, collateral=collateral_with(s, "tcb_info", status))
    denied("collateral_mismatch", run, tampered, STANDARD)


def test_collateral_terminator_and_structure_are_enforced():
    s = packet("standard")
    snapshot = fields(s)
    snapshot["fields"]["tcb_info"] = base64.b64encode(
        base64.b64decode(snapshot["fields"]["tcb_info"])[:-1]
    ).decode()
    denied(
        "collateral_field",
        t.appraise_collateral,
        json.dumps(snapshot).encode(),
        QUOTE,
        ROOT,
        at=at(s),
    )
    snapshot = fields(s)
    snapshot["tee_type"] = 0
    denied(
        "collateral_structure",
        t.appraise_collateral,
        json.dumps(snapshot).encode(),
        QUOTE,
        ROOT,
        at=at(s),
    )


def test_unpinned_root_is_rejected():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intel SGX Root CA")])
    start = datetime(2018, 1, 1, tzinfo=UTC)
    other = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(datetime(2049, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    s = packet("standard")
    denied("tcb_info_chain", t.appraise_collateral, s.collateral, QUOTE, other, at=at(s))
    denied("tcb_info_chain", run, s, STANDARD, root=other)


@pytest.mark.parametrize("name", ["pck_crl", "root_ca_crl"])
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("crl_version_0", "format"),
        ("crl_version_2", "format"),
        ("crl_issuer_as_integer", "format"),
        ("crl_issuer_as_bit_string", "format"),
        ("crl_this_update_in_year_0", "format"),
        ("crl_next_update_in_year_0", "format"),
        ("issuer_subject_as_integer", "signature"),
        ("issuer_subject_as_bit_string", "signature"),
        ("issuer_key_off_the_curve", "signature"),
        ("issuer_key_of_unknown_algorithm", "signature"),
        ("issuer_key_x25519", "signature"),
        ("issuer_key_x448", "signature"),
        # Denied at the parent commit as well. Held here because the lines that deny them changed.
        ("crl_not_der", "format"),
        ("crl_signed_by_another_key", "signature"),
        ("crl_under_another_issuer_name", "signature"),
        ("crl_next_update_in_year_0_signed_by_another_key", "signature"),
        ("crl_this_update_in_year_0_signed_by_another_key", "signature"),
        ("crl_without_next_update", "expired"),
        ("crl_without_next_update_signed_by_another_key", "signature"),
        ("crl_this_update_in_year_0_without_next_update", "expired"),
        ("at_one_second_before_this_update", "expired"),
        ("at_next_update", "expired"),
        ("crl_signed_by_another_key_at_one_second_before_this_update", "signature"),
        ("crl_signed_by_another_key_at_next_update", "signature"),
    ],
)
def test_crl_denies_a_crl_or_an_issuer_the_library_cannot_read(
    change: str, reason: str, name: str
) -> None:
    """A CRL, its issuer certificate or the time it is checked at is changed: deny, do not raise.

    The library refuses a CRL version next to the valid one on load, with x509.InvalidVersion and
    not a ValueError. It reads a name only when asked: with the tag of the common name's value
    changed to INTEGER or to BIT STRING the CRL or the certificate still loads, and reading the
    name raises ValueError or TypeError. It loads an update time in year 0000 and raises
    ValueError when asked for it. Reading a key raises ValueError for a point off its curve and
    UnsupportedAlgorithm for an algorithm the library does not know, and verifying under an
    X25519 or an X448 key, which sign nothing, raises TypeError.

    The changes after the comment are denied at the parent commit as well, each with the reason
    it has here. They are here so that the reason does not move.
    """
    from datetime import timedelta

    from cryptography.hazmat.primitives.asymmetric import x448, x25519

    now = datetime(2026, 9, 30, 5, 0, tzinfo=UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic PCK CA")])
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other CA")])

    def certificate(public_key: object) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Root")]))
            .public_key(public_key)  # type: ignore[arg-type]
            .serial_number(2)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(root_key, hashes.SHA256())
        )

    def revocation_list(
        issuer_name: x509.Name = ca_name,
        signer: ec.EllipticCurvePrivateKey = ca_key,
        this_update: datetime = now - timedelta(hours=1),
        next_update: datetime = now + timedelta(days=7),
    ) -> x509.CertificateRevocationList:
        return (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_name)
            .last_update(this_update)
            .next_update(next_update)
            .sign(signer, hashes.SHA256())
        )

    def with_byte(der: bytes, index: int, value: int) -> bytes:
        return der[:index] + bytes([value]) + der[index + 1 :]

    def signed_again(
        made: x509.CertificateRevocationList,
        old: bytes,
        new: bytes,
        signer: ec.EllipticCurvePrivateKey = ca_key,
    ) -> bytes:
        """The CRL with `old` replaced by `new` in its signed part, then signed again."""
        der = made.public_bytes(serialization.Encoding.DER)
        signed = made.tbs_certlist_bytes
        assert signed.count(old) == 1
        header = 2 if signed[1] < 0x80 else 2 + (signed[1] & 0x7F)
        changed = _der_tlv(0x30, signed[header:].replace(old, new))
        rest = der[der.index(signed) + len(signed) :]
        algorithm = rest[: 2 + rest[1]]
        signature = signer.sign(changed, ec.ECDSA(hashes.SHA256()))
        return _der_tlv(0x30, changed + algorithm + _der_tlv(0x03, b"\x00" + signature))

    issuer = certificate(ca_key.public_key())
    crl = revocation_list()
    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    this_update = int(crl.last_update_utc.timestamp())
    next_update = int(crl.next_update_utc.timestamp())  # type: ignore[union-attr]
    at = int(now.timestamp())
    for inside in (this_update, at, next_update - 1):
        assert t._crl(crl_der, issuer, inside, name).issuer == ca_name

    # The common name's value is a UTF8String, tag 0x0c.
    name_tag = {"as_integer": 0x02, "as_bit_string": 0x03}
    in_2050 = datetime(2050, 1, 1, tzinfo=UTC)
    # From 2050 on the library writes a time as GeneralizedTime, tag 0x18, year in four digits.
    year_2050, year_0 = b"\x18\x0f2050", b"\x18\x0f0000"
    common_name = b"\x0c\x10Synthetic PCK CA"
    assert crl_der.count(common_name) == 1 and issuer_der.count(common_name) == 1
    if change.startswith("crl_version_"):
        # The version is the first field of the signed part.
        signed = crl.tbs_certlist_bytes
        start = crl_der.index(signed) + (2 if signed[1] < 0x80 else 2 + (signed[1] & 0x7F))
        assert crl_der[start : start + 3] == b"\x02\x01\x01"
        crl_der = with_byte(crl_der, start + 2, int(change.removeprefix("crl_version_")))
    elif change.startswith("crl_issuer_"):
        tag = name_tag[change.removeprefix("crl_issuer_")]
        crl_der = with_byte(crl_der, crl_der.index(common_name), tag)
    elif change == "crl_this_update_in_year_0_without_next_update":
        made = revocation_list(this_update=in_2050, next_update=in_2050.replace(2051))
        both = year_2050 + b"0101000000Z" + b"\x18\x0f2051" + b"0101000000Z"
        crl_der = signed_again(made, both, year_0 + b"0101000000Z")
    elif change.startswith("crl_this_update_in_year_0"):
        signer = root_key if change.endswith("_signed_by_another_key") else ca_key
        made = revocation_list(this_update=in_2050, next_update=in_2050.replace(2051))
        crl_der = signed_again(made, year_2050, year_0, signer)
    elif change.startswith("crl_next_update_in_year_0"):
        signer = root_key if change.endswith("_signed_by_another_key") else ca_key
        crl_der = signed_again(revocation_list(next_update=in_2050), year_2050, year_0, signer)
    elif change.startswith("crl_without_next_update"):
        # The library's builder writes no CRL without one: the field is cut out of a CRL it wrote.
        signer = root_key if change.endswith("_signed_by_another_key") else ca_key
        made = revocation_list(next_update=in_2050)
        crl_der = signed_again(made, year_2050 + b"0101000000Z", b"", signer)
    elif change == "crl_not_der":
        crl_der = b"not a CRL"
    elif change.startswith("crl_signed_by_another_key"):
        crl_der = revocation_list(signer=root_key).public_bytes(serialization.Encoding.DER)
        if change.endswith("_at_one_second_before_this_update"):
            at = this_update - 1
        elif change.endswith("_at_next_update"):
            at = next_update
    elif change == "crl_under_another_issuer_name":
        crl_der = revocation_list(issuer_name=other_name).public_bytes(serialization.Encoding.DER)
    elif change == "at_one_second_before_this_update":
        at = this_update - 1
    elif change == "at_next_update":
        at = next_update
    elif change.startswith("issuer_subject_"):
        tag = name_tag[change.removeprefix("issuer_subject_")]
        issuer_der = with_byte(issuer_der, issuer_der.index(common_name), tag)
    elif change == "issuer_key_off_the_curve":
        point = ca_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        last = issuer_der.index(point) + len(point) - 1
        issuer_der = with_byte(issuer_der, last, issuer_der[last] ^ 0x01)
    elif change == "issuer_key_of_unknown_algorithm":
        ec_public_key = bytes.fromhex("06072a8648ce3d0201")  # id-ecPublicKey, 1.2.840.10045.2.1
        assert issuer_der.count(ec_public_key) == 1
        issuer_der = with_byte(issuer_der, issuer_der.index(ec_public_key) + 8, 0x7F)
    else:
        kind = {
            "issuer_key_x25519": x25519.X25519PrivateKey,
            "issuer_key_x448": x448.X448PrivateKey,
        }
        issuer_der = certificate(kind[change].generate().public_key()).public_bytes(
            serialization.Encoding.DER
        )

    denied(
        f"{name}_{reason}", t._crl, crl_der, x509.load_der_x509_certificate(issuer_der), at, name
    )


@pytest.mark.parametrize(
    ("tag", "common_name"),
    [
        pytest.param(0x0C, "Synthetic PCK CA", id="as_built"),
        pytest.param(0x02, "", id="as_integer"),
        pytest.param(0x03, "", id="as_bit_string"),
    ],
)
def test_cn_is_empty_for_a_subject_the_library_cannot_read(tag: int, common_name: str) -> None:
    """A certificate whose subject raises when read has no common name; _cn must not raise.

    The tag of the common name's value: UTF8String as built, then INTEGER, which reading the
    subject answers with ValueError, and BIT STRING, which it answers with TypeError.
    """
    from datetime import timedelta

    now = datetime(2026, 9, 30, 5, 0, tzinfo=UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic PCK CA")])
    der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Root")]))
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    value = b"\x0c\x10Synthetic PCK CA"
    assert der.count(value) == 1
    at = der.index(value)
    changed = x509.load_der_x509_certificate(der[:at] + bytes([tag]) + der[at + 1 :])
    assert t._cn(changed) == common_name


def test_collateral_for_another_platform_is_rejected():
    s = packet("standard")

    def fmspc(value):
        return value.replace(b'"fmspc":"00806F050000"', b'"fmspc":"00906F050000"', 1)

    # The signature check fires before the platform check, so a changed FMSPC
    # cannot be smuggled in; this is what makes the FMSPC comparison meaningful.
    denied(
        "tcb_info_signature",
        t.appraise_collateral,
        collateral_with(s, "tcb_info", fmspc),
        QUOTE,
        ROOT,
        at=at(s),
    )


# ------------------------------------------------------------ component


def test_runtime_component_from_the_standard_record():
    s = packet("standard")
    component = t.runtime_component(
        s, QUOTE, STANDARD, trust_root=ROOT, authority=AUTHORITY, now=at(s) + 60
    )
    assert component.component_id == "runtime.cpu" and component.component_type == "runtime"
    assert component.status == "affirming" and component.reasons == []
    assert component.profile == t.PROFILE + "/standard"
    assert component.appraised_at == at(s) and component.fresh_until == at(s) + 300
    assert component.instance == "tdx-quote/" + s.record["quote_sha256"]
    digests = {ref.media_type: ref.digest for ref in component.evidence_refs}
    assert digests[t.QUOTE_MEDIA_TYPE] == "sha256:" + s.record["quote_sha256"]
    assert digests[t.COLLATERAL_MEDIA_TYPE] == "sha256:" + s.record["collateral_sha256"]
    assert all(ref.profile == component.profile for ref in component.evidence_refs)


def test_runtime_component_for_the_early_record():
    e = packet("early")
    kwargs = {"trust_root": ROOT, "authority": AUTHORITY, "now": at(e) + 60}
    denied("qv_out_of_date", t.runtime_component, e, QUOTE, EARLY, **kwargs)
    warned = t.runtime_component(
        e, QUOTE, t.CollateralPolicy("early", 22, frozenset({0xA002})), **kwargs
    )
    assert warned.status == "warning" and warned.reasons == ["qv_out_of_date"]
    assert warned.profile == t.PROFILE + "/early"


def test_runtime_component_rejects_an_old_record():
    s = packet("standard")
    denied(
        "record_stale",
        t.runtime_component,
        s,
        QUOTE,
        STANDARD,
        trust_root=ROOT,
        authority=AUTHORITY,
        now=at(s) + 301,
    )
    denied(
        "clock_or_age",
        t.runtime_component,
        s,
        QUOTE,
        STANDARD,
        trust_root=ROOT,
        authority=AUTHORITY,
        now=at(s),
        max_age=0,
    )


# ------------------------------------ TCB convergence and DER boundaries


def _der_tlv(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        header = bytes([tag, length])
    elif length <= 0xFF:
        header = bytes([tag, 0x81, length])
    else:
        header = bytes([tag, 0x82, length >> 8, length & 0xFF])
    return header + body


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        if part == 0:
            out.append(0)
            continue
        chunks: list[int] = []
        while part:
            chunks.append(part & 0x7F)
            part >>= 7
        chunks.reverse()
        for idx, chunk in enumerate(chunks):
            out.append(chunk | (0x80 if idx < len(chunks) - 1 else 0))
    return _der_tlv(0x06, bytes(out))


def _build_pck_cert_with_sgx_ext(
    *,
    svn1_bytes: bytes = b"\x01",
    pcesvn_bytes: bytes = b"\x0b",
    fmspc: bytes = bytes.fromhex("00806f050000"),
    pceid: bytes = b"\x00\x00",
) -> x509.Certificate:
    base = t._SGX_EXTENSION.dotted_string
    tcb_entries = [_der_tlv(0x30, _der_oid(f"{base}.2.1") + _der_tlv(0x02, svn1_bytes))]
    for i in range(2, 17):
        tcb_entries.append(_der_tlv(0x30, _der_oid(f"{base}.2.{i}") + _der_tlv(0x02, b"\x01")))
    tcb_entries.append(_der_tlv(0x30, _der_oid(f"{base}.2.17") + _der_tlv(0x02, pcesvn_bytes)))
    tcb_seq = _der_tlv(0x30, b"".join(tcb_entries))
    top_seq = _der_tlv(
        0x30,
        _der_tlv(0x30, _der_oid(f"{base}.2") + tcb_seq)
        + _der_tlv(0x30, _der_oid(f"{base}.3") + _der_tlv(0x04, pceid))
        + _der_tlv(0x30, _der_oid(f"{base}.4") + _der_tlv(0x04, fmspc)),
    )
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intel SGX PCK Certificate")])
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.UnrecognizedExtension(t._SGX_EXTENSION, top_seq),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def _intel_qvl_converge_tcb_statuses(
    tcb_level_status: str, status_vec: list[str]
) -> str:
    """Transcription of Intel DCAP QVL convergeTcbStatuses.

    Source: confidential-computing.tee.dcap.qvl
    d12717e3f1f2ab81313f88001fd902b5ef5f9c8c,
    Src/AttestationLibrary/src/Verifiers/Checks/EvaluateTcb.cpp:187-225
    (pinned by DCAP 72f800e9696f382464bc8ef243311edf8bd7dc13).
    """
    effective = tcb_level_status
    if any(status == "OutOfDate" for status in status_vec):
        if effective in ("UpToDate", "SWHardeningNeeded"):
            effective = "OutOfDate"
        if effective in ("ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
            effective = "OutOfDateConfigurationNeeded"
    if any(status == "Revoked" for status in status_vec):
        effective = "Revoked"
    return effective


def test_converge_matches_intel_qvl_converge_tcb_statuses_across_all_pairs_and_triples():
    statuses = tuple(t._STATUS_TO_QV)
    assert len(statuses) == 7
    pairs = [(p, o) for p in statuses for o in statuses]
    assert len(pairs) == 49
    for platform, other in pairs:
        assert t._converge(platform, other) == _intel_qvl_converge_tcb_statuses(
            platform, [other]
        )

    triples = [(p, m, q) for p in statuses for m in statuses for q in statuses]
    assert len(triples) == 343
    for platform, module_status, qe_status in triples:
        folded = t._converge(t._converge(platform, module_status), qe_status)
        assert folded == _intel_qvl_converge_tcb_statuses(
            platform, [module_status, qe_status]
        )


def test_converge_rejects_unknown_or_non_string_status():
    assert t._converge("UpToDate", "UpToDate") == "UpToDate"
    for valid in ("UpToDate", "OutOfDate", "Revoked", "ConfigurationNeeded"):
        for bad in ("Unknown", "", None, 0, ["UpToDate"], {"status": "UpToDate"}):
            denied("tcb_status_unknown", t._converge, bad, valid)
            denied("tcb_status_unknown", t._converge, valid, bad)


def test_der_rejects_non_minimal_length_encodings():
    assert t._der(b"\x04\x05hello", 0) == (0x04, b"hello", 7)
    long_128 = b"\x04\x81\x80" + b"a" * 0x80
    assert t._der(long_128, 0) == (0x04, b"a" * 0x80, 3 + 0x80)
    long_256 = b"\x04\x82\x01\x00" + b"a" * 0x100
    assert t._der(long_256, 0) == (0x04, b"a" * 0x100, 4 + 0x100)

    for bad_blob in (
        b"\x04\x81\x00",
        b"\x04\x81\x05hello",
        b"\x04\x81\x7f" + b"a" * 0x7F,
        b"\x04\x82\x00\x80" + b"a" * 0x80,
        b"\x04\x83\x00\x01\x00" + b"a" * 0x100,
    ):
        denied("pck_extension", t._der, bad_blob, 0)


def test_pck_extension_rejects_non_minimal_and_negative_der_integers():
    valid_cert = _build_pck_cert_with_sgx_ext(svn1_bytes=b"\x00\x80", pcesvn_bytes=b"\x01\x00")
    parsed = t._pck_extension(valid_cert)
    assert parsed["sgx_svns"][0] == 128 and parsed["pcesvn"] == 256

    for bad_int in (b"\x00\x05", b"\x00\x00", b"\x00\x7f", b"\x00\x00\x80", b"\x80"):
        denied(
            "pck_extension",
            t._pck_extension,
            _build_pck_cert_with_sgx_ext(svn1_bytes=bad_int),
        )
        denied(
            "pck_extension",
            t._pck_extension,
            _build_pck_cert_with_sgx_ext(pcesvn_bytes=bad_int),
        )
