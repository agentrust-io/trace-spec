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
if not (CLOUD / "gcp-platform-run" / "evidence.bin").is_file():
    pytest.skip("saved TDX quote and collateral are absent", allow_module_level=True)
APPRAISAL = CLOUD / "collateral-appraisal"
QUOTE = (CLOUD / "gcp-platform-run" / "evidence.bin").read_bytes()
ROOT = x509.load_pem_x509_certificate((CLOUD / "intel-root.pem").read_bytes())
STANDARD = t.CollateralPolicy("standard", 20)
EARLY = t.CollateralPolicy("early", 22)
AUTHORITY = "spiffe://example.test/tdx-appraiser"


def packet(name):
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
    pin = json.loads((CLOUD / "trust-root.json").read_text())["intel"]
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
    replay = json.loads((APPRAISAL / "offline" / "offline-replay.json").read_text())
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
    replay = json.loads((APPRAISAL / "offline" / "offline-replay.json").read_text())
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
    for name in ("qvl-appraisal.json", "intel-collateral.json", "sgx_default_qcnl.conf"):
        (tmp_path / name).write_bytes((APPRAISAL / "standard" / name).read_bytes())
    raw = (tmp_path / "qvl-appraisal.json").read_text()
    (tmp_path / "qvl-appraisal.json").write_text(
        raw.replace('"qve_used": false,', '"qve_used": false, "qve_used": false,')
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
