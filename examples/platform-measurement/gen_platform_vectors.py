"""Generate the platform-measurement conformance vectors (#279, platform-measurement row).

`agentrust_trace.platform_measurement` records what a caller-supplied appraiser
reported about `runtime.measurement`, per layer. These vectors pin that record. No
vector asserts that a reported layer is true of the platform; the appraiser's report is
the input, carried as given.

**Pairs.** Every cause appears in a vector that produces it and in a twin, `twin_of`
that vector, which carries the same signed record and the same context except the
appraisal table, and differs only in the one condition that produces the cause. A
cause that only appears cannot show the consumer keyed it to the right condition; the
twin can. Every vector whose measurement is not from published evidence carries
`"synthetic": true`.

**Reports in hand.** `context.appraisals` maps each measurement the harness appraiser
knows to the report it returns: `measurement` and `layers`, exactly the shape the
consumer accepts. The harness lives in `tests/`; a measurement the table lacks makes the
harness raise `KeyError`, which is the vectors' `appraiser_raised`. A report whose
`measurement` member differs from the table key is how a vector expresses an appraiser
that appraised other evidence.

**Where the reports come from.** Two vectors carry reports derived from published
evidence on a physical board with a discrete TPM (TactiQ OS on Rock 5A, Infineon
SLB9670), and say so in `source`:

- `15` uses the measurement of the v2.1.0-rc13 release reference (`pcrDigest` over PCR
  0 to 9). PCR 2, 3, 5 and 7 in that reference hold a single separator and nothing
  else, and PCR 10 is outside the quote's selection: `layer_not_measured`.
- `16` uses the cold-start quote of 2026-10-02 (PCR 0 to 12). Four IMA entries in PCR 11
  and 12 replay to the quoted values, and the IMA policy that leaves them unappraised is
  not measured into the log: `measured_not_appraised`.

The evidence and an offline checker for both are published at the URLs in `source`;
nothing here reads them, and the consumer would not either. The two-boot cause exists
only in the synthetic pair `13` and `14`: that board resets its TPM in SPL before
measuring, so it does not produce the case.

The key derives from one published seed so the set regenerates byte-for-byte. Files are
written as bytes with LF line endings, so the set regenerates identically everywhere.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace.sign import key_to_jwk, sign_record

OUT = Path("examples/platform-measurement")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SPEC = "https://github.com/agentrust-io/trace-spec/issues/279"

SEED = hashlib.sha256(b"trace-spec platform-measurement fixture key").digest()

#: Fixed verification moment; the record is issued one hour before it.
NOW = 1785000000
IAT = NOW - 3600
MAX_AGE = 86400
SKEW = 300

#: Measurements. The two real ones are the `pcrDigest` values of published quotes.
RC13 = "sha256:2ee6f2d22d3b8e704d1ee8119220aed62a5caff4624c5804b8185debdff1f745"
DEV_COLD = "sha256:266c3432e78cde16a9e9e63c479c4d07aad80ac049b25d655bfd897fb3b19746"
SYNTHETIC = "sha256:" + "5a" * 32
OTHER = "sha256:" + "0e" * 32

SOURCE_RC13 = (
    "https://github.com/revenue7-eng/tactiq-os/releases/tag/v2.1.0-rc13 "
    "(VERIFY-L3-rc13.md and l3-evidence-rc13.tar.gz)"
)
SOURCE_DEV = (
    "https://github.com/revenue7-eng/tactiq-os/blob/main/measurements/"
    "tpm-quotes-dev-20261002.md (cold.* files and check.py beside it)"
)

PCRS_0_9 = [f"pcr:{i}" for i in range(10)]


def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEED)


def record_with(measurement: str, platform: str = "tpm2") -> dict[str, Any]:
    """A schema-valid, signed v0.2 record carrying `measurement` under `platform`."""
    body = {
        "eat_profile": V0_2,
        "iat": IAT,
        "subject": "spiffe://acme.example/agent/measured",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": platform, "measurement": measurement},
        "policy": {"bundle_hash": "sha256:" + "aa" * 32, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "bb" * 32},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    }
    return sign_record(body, key())


def report(measurement: str, layers: dict[str, str]) -> dict[str, Any]:
    return {"measurement": measurement, "layers": layers}


def expected_for(record: dict[str, Any], appraisals: dict[str, Any] | None) -> dict[str, Any]:
    """The consumer's decision procedure, restated here so `expected` cannot drift."""
    measurement = record["runtime"]["measurement"]
    if appraisals is None:
        row: dict[str, Any] = {
            "outcome": "not_attempted", "cause": "no_appraiser", "evidence": {}, "layers": {},
        }
    elif measurement not in appraisals:
        row = {
            "outcome": "appraisal_rejected", "cause": "appraiser_raised",
            "evidence": {"measurement": measurement, "exception": "KeyError"}, "layers": {},
        }
    elif set(appraisals[measurement]) != {"measurement", "layers"}:
        row = {
            "outcome": "appraisal_rejected", "cause": "appraiser_returned_invalid",
            "evidence": {
                "measurement": measurement, "member": "report",
                "members": sorted(appraisals[measurement]),
            },
            "layers": {},
        }
    elif appraisals[measurement]["measurement"] != measurement:
        row = {
            "outcome": "appraisal_rejected", "cause": "measurement_mismatch",
            "evidence": {
                "measurement": measurement,
                "appraised": appraisals[measurement]["measurement"],
            },
            "layers": {},
        }
    else:
        layers = appraisals[measurement]["layers"]
        row = {
            "outcome": "appraised", "cause": None,
            "evidence": {"measurement": measurement, "layers": len(layers)},
            "layers": {
                name: (
                    {"outcome": "established", "cause": None}
                    if status == "established"
                    else {"outcome": "not_established", "cause": status}
                )
                for name, status in layers.items()
            },
        }
    return {"rejected": False, "codes": [], "platform_measurement": row}


def vector(
    n: int, name: str, description: str, *, record: dict[str, Any],
    appraisals: dict[str, Any] | None, source: str | None = None, twin_of: int | None = None,
) -> tuple[str, dict[str, Any]]:
    context: dict[str, Any] = {
        "now": NOW,
        "max_age_seconds": MAX_AGE,
        "max_future_skew_seconds": SKEW,
        "trusted_key": key_to_jwk(key()),
    }
    if appraisals is not None:
        context["appraisals"] = appraisals
    doc: dict[str, Any] = {
        "id": f"TRACE-PMEAS-{n:03d}",
        "name": name,
        "description": description,
        "spec": SPEC,
    }
    if source is not None:
        doc["source"] = source
    else:
        doc["synthetic"] = True
    if twin_of is not None:
        doc["twin_of"] = f"TRACE-PMEAS-{twin_of:03d}"
    doc.update(
        {"context": context, "records": [record], "expected": expected_for(record, appraisals)}
    )
    return f"{n:02d}-{name}.json", doc


def vectors() -> list[tuple[str, dict[str, Any]]]:
    """Pairs first: each cause, then its twin, which carries the same signed record and
    differs only in the one condition that produces the cause. Then the two vectors
    whose measurements come from published evidence."""
    out = []
    rec = record_with(SYNTHETIC)
    good = {SYNTHETIC: report(SYNTHETIC, dict.fromkeys(PCRS_0_9, "established"))}

    def one_layer(status: str) -> dict[str, Any]:
        layers = dict.fromkeys(PCRS_0_9, "established")
        layers["pcr:2"] = status
        return {SYNTHETIC: report(SYNTHETIC, layers)}

    out.append(vector(
        1, "no-appraiser",
        "The harness supplies no appraiser: not_attempted with cause no_appraiser and no "
        "layers. not_attempted is not a pass and is never summarised as one.",
        record=rec, appraisals=None,
    ))
    out.append(vector(
        2, "no-appraiser-twin",
        "Twin of 001: the same record, with an appraiser that reports every layer "
        "established. The only difference is that an appraiser was supplied.",
        record=rec, appraisals=good, twin_of=1,
    ))
    out.append(vector(
        3, "appraiser-raised",
        "The appraiser knows other measurements but not this one and raises: "
        "appraisal_rejected with cause appraiser_raised and the exception's class name. "
        "The record still verifies.",
        record=rec, appraisals={OTHER: report(OTHER, {"pcr:0": "established"})},
    ))
    out.append(vector(
        4, "appraiser-raised-twin",
        "Twin of 003: the appraiser's table also holds this measurement, so it does not "
        "raise. The only difference is the table entry for this measurement.",
        record=rec,
        appraisals={OTHER: report(OTHER, {"pcr:0": "established"}), **good}, twin_of=3,
    ))
    out.append(vector(
        5, "appraiser-returned-invalid",
        "The appraiser returns a report without its layers member: appraisal_rejected with "
        "cause appraiser_returned_invalid, naming the member at fault.",
        record=rec, appraisals={SYNTHETIC: {"measurement": SYNTHETIC}},
    ))
    out.append(vector(
        6, "appraiser-returned-invalid-twin",
        "Twin of 005: the same report with its layers member present.",
        record=rec, appraisals=good, twin_of=5,
    ))
    out.append(vector(
        7, "measurement-mismatch",
        "The appraiser returns a report about a different measurement. A correct appraisal "
        "of other evidence is not attached to this record: appraisal_rejected with cause "
        "measurement_mismatch and both values.",
        record=rec,
        appraisals={SYNTHETIC: report(OTHER, dict.fromkeys(PCRS_0_9, "established"))},
    ))
    out.append(vector(
        8, "measurement-mismatch-twin",
        "Twin of 007: the same report, naming this record's measurement.",
        record=rec, appraisals=good, twin_of=7,
    ))
    for n, cause, what in (
        (9, "layer_not_measured", "the layer was not measured"),
        (11, "measured_not_appraised", "the layer was measured and nothing shows it was "
                                       "appraised"),
        (13, "evidence_spans_multiple_boots", "the evidence does not describe a single boot"),
    ):
        stem = cause.replace("_", "-")
        out.append(vector(
            n, stem,
            f"Synthetic. The appraiser reports pcr:2 as {cause} ({what}) and every other "
            "layer established. The layer is not_established with that cause; the "
            "measurement as a whole is still appraised, and nothing is upgraded.",
            record=rec, appraisals=one_layer(cause),
        ))
        out.append(vector(
            n + 1, f"{stem}-twin",
            f"Twin of {n:03d}: the same report with pcr:2 established. The only difference "
            "is that one layer's status.",
            record=rec, appraisals=good, twin_of=n,
        ))

    layers_rc13 = {
        p: ("layer_not_measured" if p in ("pcr:2", "pcr:3", "pcr:5", "pcr:7") else "established")
        for p in PCRS_0_9
    }
    layers_rc13["pcr:10"] = "layer_not_measured"
    rec_rc13 = record_with(RC13)
    out.append(vector(
        15, "rc13-layer-not-measured",
        "Real measurement: the v2.1.0-rc13 reference composite over PCR 0 to 9. PCR 2, 3, 5 "
        "and 7 hold a single separator and nothing else, and PCR 10 is outside the quote's "
        "selection, so the appraiser reports them layer_not_measured. A digest comparison "
        "alone passes all of them.",
        record=rec_rc13, appraisals={RC13: report(RC13, layers_rc13)}, source=SOURCE_RC13,
    ))

    layers_dev = dict.fromkeys(("pcr:2", "pcr:3", "pcr:5", "pcr:7"), "layer_not_measured")
    layers_dev.update({"pcr:11": "measured_not_appraised", "pcr:12": "measured_not_appraised"})
    rec_dev = record_with(DEV_COLD)
    out.append(vector(
        16, "dev-measured-not-appraised",
        "Real measurement: a cold-start quote over PCR 0 to 12 from a development image. "
        "Four IMA entries in PCR 11 and 12 replay to the quoted values; the IMA policy that "
        "leaves them unappraised is not measured into the log, so the appraiser reports "
        "measured_not_appraised. Only layers the appraiser reported are carried. The "
        "board resets its TPM before measuring, so it does not produce "
        "evidence_spans_multiple_boots; that cause is exercised by the synthetic 013.",
        record=rec_dev, appraisals={DEV_COLD: report(DEV_COLD, layers_dev)}, source=SOURCE_DEV,
    ))
    return out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in vectors():
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        (OUT / name).write_bytes(text.encode("utf-8"))


if __name__ == "__main__":
    main()
