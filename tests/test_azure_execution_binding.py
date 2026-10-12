"""Signed counterexamples for the Azure SNP/vTPM UKI-anchored IMA execution binding."""

import base64
import dataclasses
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from prototype import azure_execution_binding as x

CHALLENGE = "ab" * 32
SHIM, UKI, STOCK_UKI = "a1" * 32, "b2" * 32, "c3" * 32
APP, SUBSTITUTE, SYSTEMD, SUDO = "11" * 32, "22" * 32, "33" * 32, "44" * 32
FIXTURES = Path(__file__).parent / "fixtures" / "azure-execution-20260929"
AK = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(data):
    return base64.b64encode(data).decode()


def sha(data):
    return hashlib.sha256(data).digest()


def uefi_event(pcr, etype, digest, data=b""):
    return (
        struct.pack("<III", pcr, etype, 1)
        + struct.pack("<H", 0x000B)
        + digest
        + struct.pack("<I", len(data))
        + data
    )


def uefi_log(boot_apps, secure_boot=True):
    header = (
        b"Spec ID Event03\x00"
        + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1)
        + struct.pack("<HH", 0x000B, 32)
        + b"\x00"
    )
    log = (
        struct.pack("<II", 0, x.EV_NO_ACTION) + bytes(20) + struct.pack("<I", len(header)) + header
    )
    name = "SecureBoot".encode("utf-16-le")
    variable = bytes(16) + struct.pack("<QQ", 10, 1) + name + (b"\x01" if secure_boot else b"\x00")
    log += uefi_event(7, x.EV_EFI_VARIABLE_DRIVER_CONFIG, sha(variable), variable)
    for pcr in range(10):
        log += uefi_event(pcr, 0x4, sha(b"separator"))
    for app in boot_apps:
        log += uefi_event(4, x.EV_EFI_BOOT_SERVICES_APPLICATION, bytes.fromhex(app), b"devicepath")
    return log


def ima_entry(file_digest, path):
    digest_field = b"sha256:\x00" + file_digest
    path_field = path.encode() + b"\x00"
    data = (
        struct.pack("<I", len(digest_field))
        + digest_field
        + struct.pack("<I", len(path_field))
        + path_field
    )
    return (
        struct.pack("<I", 10)
        + sha(data)
        + struct.pack("<I", 6)
        + b"ima-ng"
        + struct.pack("<I", len(data))
        + data
    )


def build(
    boot_apps=(SHIM, UKI),
    executed=(SYSTEMD, APP),
    trailing=(),
    secure_boot=True,
    holder=None,
    pcrs=x.QUOTED_PCRS,
    qualifying=None,
    signer=AK,
    tamper_ima=None,
):
    holder = holder or ed25519.Ed25519PrivateKey.generate()
    public = holder.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    uefi = uefi_log(boot_apps, secure_boot)
    replayed = x.replay_uefi(x.parse_uefi_log(uefi))
    aggregate = sha(b"".join(replayed[i] for i in range(10)))
    entries = [ima_entry(aggregate, "boot_aggregate")] + [
        ima_entry(bytes.fromhex(d), f"/bin/{i}") for i, d in enumerate(executed)
    ]
    pcr10 = bytes(32)
    for entry in entries:
        pcr10 = sha(pcr10 + entry[4:36])
    values = {**replayed, 10: pcr10, 23: bytes(32)}
    composite = sha(b"".join(values[i] for i in pcrs))
    bitmap = bytearray(3)
    for i in pcrs:
        bitmap[i // 8] |= 1 << (i % 8)
    qualifying = (
        qualifying if qualifying is not None else sha(x.DOMAIN + bytes.fromhex(CHALLENGE) + public)
    )
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
    signature = signer.sign(quote, padding.PKCS1v15(), hashes.SHA256())
    ima = b"".join(entries) + b"".join(ima_entry(bytes.fromhex(d), "/late") for d in trailing)
    if tamper_ima:
        ima = tamper_ima(entries)
    return {
        "challenge": CHALLENGE,
        "holder_public_hex": public.hex(),
        "tpm_quote_b64": b64(quote),
        "tpm_signature_b64": b64(
            b"\x00\x14\x00\x0b" + struct.pack(">H", len(signature)) + signature
        ),
        "holder_signature_b64": b64(holder.sign(x.DOMAIN + sha(quote) + bytes.fromhex(CHALLENGE))),
        "uefi_event_log_b64": b64(uefi),
        "ima_log_sha256_b64": b64(ima),
    }


POLICY = x.ExecutionPolicy(
    required_boot_application=UKI,
    approved_boot_applications=frozenset({SHIM, UKI}),
    required_application=APP,
    approved_executables=frozenset({APP, SYSTEMD}),
    denied_executables=frozenset({SUDO}),
)


def appraise(packet, policy=POLICY):
    return x.appraise_execution(packet, AK.public_key(), policy, expected_challenge=CHALLENGE)


def denied(packet, policy=POLICY):
    with pytest.raises(x.ExecutionDenied) as caught:
        appraise(packet, policy)
    return str(caught.value)


def test_approved_boot_and_application_are_accepted():
    result = appraise(build())
    assert result["observed_application"] == "sha256:" + APP
    assert result["quoted_executions"] == 2


def test_substituted_application_is_denied_and_the_allowlist_is_causal():
    packet = build(executed=(SYSTEMD, SUBSTITUTE))
    assert denied(packet) == "unapproved_execution"
    widened = dataclasses.replace(
        POLICY, approved_executables=POLICY.approved_executables | {SUBSTITUTE}
    )
    assert denied(packet, widened) == "application_not_executed"


def test_substitute_run_beside_the_approved_application_is_denied():
    assert denied(build(executed=(SYSTEMD, APP, SUBSTITUTE))) == "unapproved_execution"


def test_unapproved_execution_after_the_quote_still_denies():
    assert denied(build(trailing=(SUBSTITUTE,))) == "unapproved_execution"
    assert appraise(build(trailing=(SYSTEMD,)))["quoted_executions"] == 2


def test_application_must_be_inside_the_quoted_prefix():
    assert denied(build(executed=(SYSTEMD,), trailing=(APP,))) == "application_not_executed"


def test_interactive_root_access_is_denied():
    assert denied(build(executed=(SYSTEMD, APP, SUDO))) == "interactive_access"


def test_boot_chain_must_carry_the_policy_bearing_uki():
    assert denied(build(boot_apps=(SHIM, STOCK_UKI))) == "unapproved_boot_application"
    assert denied(build(boot_apps=(SHIM,))) == "boot_policy_not_measured"


def test_secure_boot_state_is_pinned():
    assert denied(build(secure_boot=False)) == "secure_boot_state"
    assert appraise(build(secure_boot=False), dataclasses.replace(POLICY, secure_boot=False))


def test_dropping_an_ima_entry_breaks_replay():
    packet = build(tamper_ima=lambda entries: entries[0] + b"".join(entries[2:]))
    assert denied(packet) == "pcr_replay_mismatch"


def test_rewriting_an_ima_path_breaks_the_template_digest():
    def rewrite(entries):
        return b"".join(entries[:-1]) + entries[-1][:-3] + b"X\x00" + entries[-1][-1:]

    assert denied(build(tamper_ima=rewrite)) in {"ima_template_digest", "ima_template_fields"}


def test_pcr23_only_quote_is_rejected():
    assert denied(build(pcrs=(23,))) == "quote_pcr_selection"


def test_holder_key_and_challenge_bindings():
    assert denied(build(qualifying=sha(b"other"))) == "holder_binding"
    packet = build()
    packet["holder_signature_b64"] = b64(ed25519.Ed25519PrivateKey.generate().sign(b"x"))
    assert denied(packet) == "holder_possession"
    packet = build()
    packet["challenge"] = "cd" * 32
    assert denied(packet) == "challenge"


def test_quote_signed_by_another_key_is_rejected():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert denied(build(signer=other)) == "quote_signature"


def test_policy_rejects_inconsistent_expectations():
    with pytest.raises(x.ExecutionDenied):
        dataclasses.replace(POLICY, required_application=SUBSTITUTE)
    with pytest.raises(x.ExecutionDenied):
        dataclasses.replace(POLICY, denied_executables=frozenset({APP}))


# ------------------------------------------------ real Azure hardware packet


def _wcm():
    root = Path(__file__).resolve().parents[2] / "cloud-20260929"
    if not (root / "wcm").is_dir():
        pytest.skip("pinned WCM verifier snapshot not present")
    sys.path.insert(0, str(root))
    import wcm

    pem = (root / "amd-root.pem").read_bytes()
    pinned = json.loads((root / "trust-root.json").read_text())["amd"]["pem_sha256"]
    assert hashlib.sha256(pem).hexdigest() == pinned
    trust = wcm.TrustStore()
    trust.add_root_pem(pem.decode())
    return wcm, trust


def test_real_stock_boot_packet_replays_and_is_denied():
    wcm, trust = _wcm()
    packet = json.loads((FIXTURES / "stock-relabel-packet.json").read_text())
    meta = json.loads((FIXTURES / "stock-relabel-meta.json").read_text())
    ak = x.authenticate_ak(packet, trust)
    quote = x.parse_quote(base64.b64decode(packet["tpm_quote_b64"]))
    events = x.parse_uefi_log(base64.b64decode(packet["uefi_event_log_b64"]))
    ima = x.parse_ima_log(base64.b64decode(packet["ima_log_sha256_b64"]))
    assert x._quoted_ima_prefix(x.replay_uefi(events), ima, quote.pcr_digest)
    logged = {e.sha256.hex() for e in events if e.event_type == x.EV_EFI_BOOT_SERVICES_APPLICATION}
    assert logged == {meta["authenticode"]["shimx64.efi"], meta["authenticode"]["canonical-uki"]}
    app = meta["legacy_pcr23_measurement"].removeprefix("sha256:")
    policy = x.ExecutionPolicy(
        required_boot_application=meta["authenticode"]["trace-uki"],
        approved_boot_applications=frozenset(
            {meta["authenticode"]["shimx64.efi"], meta["authenticode"]["trace-uki"]}
        ),
        required_application=app,
        approved_executables=frozenset({app} | {e.file_digest for e in ima[1:]}),
    )
    with pytest.raises(x.ExecutionDenied, match="unapproved_boot_application"):
        x.appraise_execution(packet, ak, policy, expected_challenge=meta["challenge"])
    canonical = dataclasses.replace(
        policy,
        required_boot_application=meta["authenticode"]["canonical-uki"],
        approved_boot_applications=policy.approved_boot_applications
        | {meta["authenticode"]["canonical-uki"]},
    )
    # Even trusting Canonical's UKI, the stock policy never measured the agent.
    with pytest.raises(x.ExecutionDenied, match="application_not_executed"):
        x.appraise_execution(packet, ak, canonical, expected_challenge=meta["challenge"])


def test_legacy_pcr23_binding_accepts_the_same_unexecuted_agent():
    wcm, trust = _wcm()
    packet = json.loads((FIXTURES / "stock-relabel-packet.json").read_text())
    meta = json.loads((FIXTURES / "stock-relabel-meta.json").read_text())
    legacy = wcm.AzureSnpVtpmVerifier(trust).verify(
        packet["legacy_wcm_pcr23_bundle_b64"],
        expected_nonce=meta["challenge"],
        channel_binding=bytes.fromhex(packet["holder_public_hex"]),
        expected_workload_measurement=meta["legacy_pcr23_measurement"],
    )
    assert legacy.verified  # the gap this profile closes


# ------------------------------------ execution_component on real packets

AUTHORITY = "https://verifier.example.test"
ISSUED = 1790683200  # issuer clock; inside the VCEK and ARK validity windows


def real(name):
    packet = json.loads((FIXTURES / f"{name}-packet.json").read_text())
    return packet, (FIXTURES / f"{name}.challenge").read_text().strip()


def real_policy(**changes):
    p = json.loads((FIXTURES / "execution-policy.json").read_text())
    policy = x.ExecutionPolicy(
        required_boot_application=p["required_boot_application"],
        approved_boot_applications=frozenset(p["approved_boot_applications"]),
        required_application=p["required_application"],
        approved_executables=frozenset(p["approved_executables"]),
        denied_executables=frozenset(p["denied_executables"]),
        secure_boot=p["secure_boot"],
    )
    return dataclasses.replace(policy, **changes)


def genoa_trust():
    wcm, trust = _wcm()
    pem = (FIXTURES / "ark-genoa.pem").read_bytes()
    pinned = json.loads((FIXTURES / "execution-policy.json").read_text())["ark_genoa_sha256"]
    assert hashlib.sha256(pem).hexdigest() == pinned
    trust.add_root_pem(pem.decode())
    return trust


def component(name, trust=None, policy=None, **overrides):
    packet, challenge = real(name)
    args = {
        "expected_challenge": challenge,
        "expected_holder": bytes.fromhex(packet["holder_public_hex"]),
        "authority": AUTHORITY,
        "now": ISSUED,
    } | overrides
    return x.execution_component(packet, trust or genoa_trust(), policy or real_policy(), **args)


def component_denied(name, **kwargs):
    with pytest.raises(x.ExecutionDenied) as caught:
        component(name, **kwargs)
    return str(caught.value)


def test_real_approved_packet_yields_an_affirming_code_component():
    from prototype.verifier_token import canonical_digest

    packet, _ = real("b1-approved")
    c = component("b1-approved")
    assert (c.component_id, c.component_type, c.status) == ("application.code", "code", "affirming")
    assert c.profile == x.PROFILE and c.authority == AUTHORITY
    assert c.instance == "azure-vm/ca2e2e97-d879-49b7-ab25-f10ac9bd8667"
    assert c.observed_digest == "sha256:" + real_policy().required_application
    assert (c.appraised_at, c.fresh_until) == (ISSUED, ISSUED + 300)
    assert [e.digest for e in c.evidence_refs] == [canonical_digest(packet)]
    assert all(e.profile == c.profile for e in c.evidence_refs)
    assert component("b1-approved", max_age=60).fresh_until == ISSUED + 60


def test_real_substituted_packet_yields_no_component_and_the_allowlist_is_causal():
    assert component_denied("b2-substituted-relabel") == "unapproved_execution"
    # The relabeled substitute is the only unapproved file in the quoted log.
    substitute = "e70ef2d509af7ed9702002a3ba72c42883e17bd330dd2ef6d44ac22e49ac537d"
    policy = real_policy(approved_executables=real_policy().approved_executables | {substitute})
    assert component_denied("b2-substituted-relabel", policy=policy) == "application_not_executed"


def test_real_packet_after_sudo_yields_no_component():
    assert component_denied("b4b-after-sudo") == "interactive_access"


def test_component_is_bound_to_the_token_holder():
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    holder = other.public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert component_denied("b1-approved", expected_holder=holder) == "token_holder_mismatch"
    packet, _ = real("b1-approved")
    text = packet["holder_public_hex"]
    assert component_denied("b1-approved", expected_holder=text) == "token_holder_mismatch"


def test_component_needs_the_issuer_challenge():
    assert component_denied("b1-approved", expected_challenge="cd" * 32) == "challenge"
    _, other = real("b2-substituted-relabel")
    assert component_denied("b1-approved", expected_challenge=other) == "challenge"


def test_component_needs_the_pinned_root_for_the_host_generation():
    _, milan_only = _wcm()
    assert component_denied("b1-approved", trust=milan_only) == "vcek_chain"


def test_component_pins_secure_boot_twice(monkeypatch):
    policy = real_policy(secure_boot=True)
    assert component_denied("b1-approved", policy=policy) == "secure_boot_state"
    # PCR 7 replay and the SNP-authenticated HCL claim must agree.
    runtime = x._runtime_claims
    monkeypatch.setattr(x, "_runtime_claims", lambda p: runtime(p) | {"secure_boot": True})
    assert component_denied("b1-approved") == "hcl_secure_boot_mismatch"


@pytest.mark.parametrize(
    "overrides",
    [{"now": True}, {"now": -1}, {"now": 1.0}, {"max_age": 0}, {"max_age": 86401}],
)
def test_component_rejects_bad_clock_or_age(overrides):
    assert component_denied("b1-approved", **overrides) == "clock_or_age"
