"""Generate the platform-measurement appraisal vectors (spec section 3.1.5, #279).

Each vector is one signed Trust Record whose `appraisal.platform_measurement` says, layer
by layer, what a matching `runtime.measurement` covers. Two things are pinned.

**The shape rules the schema and the reference model hold.** An accepting vector is a
record both validators take; a rejecting vector carries the one code of the rule it
breaks. One rule is held by the reference model only, because it compares two members
of the record and a JSON Schema cannot: `measurement_mismatch`, where the result is
about a measurement other than `runtime.measurement`. Those vectors say so with
`"schema_sees": false`.

**What a relying party reads off an accepting record.** `expected.reading` names, for
each layer the vector asks about, the outcome a relying party must take from the record,
and the reason when the layer is not established. A layer the result does not list is
read as `not-established` with the reason `not-listed`, which is not one of the record's
three reasons: it is the reader's own finding, rule 1 of the section.

**Pairs.** Every case appears in a vector that produces it and in a twin, `twin_of` that
vector, which carries the same record except the one condition: a single-boot log, an
appraised layer, a measured layer, a listed layer, a result at all. A reader that refuses everything
reads `not-established` everywhere and fails every twin; a reader that takes
`appraisal.status` at its word, or that reads an unlisted layer as established, fails
the cases. Every pair is synthetic, `"synthetic": true`: its measurement and its
per-layer result are made up to exercise one case, not taken from a platform.

**Where real measurements come from.** Two accepting vectors carry the `pcrDigest` of
published quotes on a physical board with a discrete TPM (TactiQ OS on Rock 5A, Infineon
SLB9670), and say so in `source`; neither has a twin, because a twin would have to state
something untrue about that evidence:

- `09` is the v2.1.0-rc13 release reference over PCR 0 to 9, in which PCR 2, 3, 5 and 7
  hold a single separator and nothing else: `layer-not-measured`.
- `10` is the cold-start quote of 2026-10-02 over PCR 0 to 12, in which four IMA entries
  in PCR 11 and 12 replay to the quoted values and the policy that leaves them
  unappraised is not in the log: `measured-not-appraised`. The quote was taken by hand
  with `tpm2_quote` under the board's registered attestation key; the image's attestation
  agent quotes PCR 0 to 9 only.

The two-boot case exists only in the synthetic pair: the development loader on that board
resets the TPM before measuring, so the board did not produce the case. These are the
measurements the platform-measurement vectors of #457 carry, now written into the record
as section 3.1.5 names them.

The key derives from one published seed so the set regenerates byte-for-byte. Files are
written as bytes with LF line endings.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/platform-measurement-appraisal")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
SPEC = "spec/trace-v0.2.md#315-appraisalplatform_measurement-what-a-matching-measurement-covers"

SEED = hashlib.sha256(b"trace-spec platform-measurement-appraisal fixture key").digest()

#: Fixed issue time. Nothing in this set turns on the clock.
IAT = 1785000000

SUBJECT = "spiffe://edge.example/device/bench-001"
VERIFIER = "https://verifier.example/platform-measurement"

#: The two real measurements: `pcrDigest` of published quotes.
RC13 = "sha256:2ee6f2d22d3b8e704d1ee8119220aed62a5caff4624c5804b8185debdff1f745"
DEV_COLD = "sha256:266c3432e78cde16a9e9e63c479c4d07aad80ac049b25d655bfd897fb3b19746"
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
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED + b"|producer").digest())


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk() -> dict[str, str]:
    raw = key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def synthetic(label: str) -> str:
    """A measurement with no platform behind it, derived from the seed by label."""
    return "sha256:" + hashlib.sha256(SEED + b"|" + label.encode()).hexdigest()


def established() -> dict[str, str]:
    return {"outcome": "established"}


def not_established(reason: str) -> dict[str, str]:
    return {"outcome": "not-established", "reason": reason}


def record(*, measurement: str, status: str, layers: dict[str, Any] | None,
           result_measurement: str | None = None, platform: str = "tpm2") -> dict[str, Any]:
    """A schema-valid record carrying the appraisal given. Minimal otherwise.

    ``layers=None`` writes no ``appraisal.platform_measurement`` at all.
    """
    body: dict[str, Any] = {
        "eat_profile": V0_2,
        "iat": IAT,
        "subject": SUBJECT,
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": platform, "measurement": measurement},
        "policy": {"bundle_hash": "sha256:" + "aa" * 32, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": synthetic("build")},
        "appraisal": {
            "status": status,
            "verifier": VERIFIER,
            "platform_measurement": {
                "measurement": result_measurement or measurement,
                "layers": layers,
            },
        },
        "cnf": {"jwk": jwk()},
    }
    if layers is None:
        del body["appraisal"]["platform_measurement"]
    return sign(body)


def sign(body: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in body.items() if k != "signature"}
    body["signature"] = b64u(key().sign(rfc8785.dumps(body)))
    return body


def vector(n: int, name: str, description: str, *, rec: dict[str, Any],
           codes: list[str] | None = None, reading: dict[str, Any] | None = None,
           twin_of: int | None = None, source: str | None = None,
           schema_sees: bool = True) -> tuple[str, dict[str, Any]]:
    codes = codes or []
    expected: dict[str, Any] = {"outcome": "reject" if codes else "accept", "codes": codes}
    if reading is not None:
        expected["reading"] = reading
    if not schema_sees:
        expected["schema_sees"] = False
    doc: dict[str, Any] = {"name": name, "description": description, "spec": SPEC}
    if source is not None:
        doc["source"] = source
    else:
        doc["synthetic"] = True
    if twin_of is not None:
        doc["twin_of"] = f"{twin_of:02d}"
    doc["record"] = rec
    doc["expected"] = expected
    return f"{n:02d}-{name}.json", doc


def read(outcome: str, reason: str | None = None) -> dict[str, str]:
    return {"outcome": outcome} if reason is None else {"outcome": outcome, "reason": reason}


def with_layer(layers: dict[str, Any], name: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(layers)
    out[name] = value
    return out


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []
    base = {p: established() for p in PCRS_0_9}

    # Pairs. Each case on pcr:2 with every other layer established, then its twin.
    pairs = [
        ("layer-not-measured", "a measured layer",
         "pcr:2 holds no measurement, so a match there confirms only that nothing was "
         "recorded. A reader that takes the matching composite as a pass reads it as "
         "established; it is not."),
        ("measured-not-appraised", "an appraised layer",
         "pcr:2's measurements replay to the quoted value and nothing in the evidence "
         "shows they were appraised before they ran. Not a finding that appraisal was off."),
        ("evidence-spans-multiple-boots", "a single-boot log",
         "the log does not replay to the quoted value and the evidence does not establish "
         "one boot. Reported as not established, not as tampering: appraisal.status is "
         "warning, not contraindicated, under rule 3."),
    ]
    n = 1
    for reason, twin_condition, what in pairs:
        m = synthetic(reason)
        out.append(vector(n, reason, f"Synthetic. {what}",
            rec=record(measurement=m, status="warning",
                       layers=with_layer(base, "pcr:2", not_established(reason))),
            reading={"pcr:2": read("not-established", reason)}))
        out.append(vector(n + 1, f"{reason}-twin",
            f"Twin of {n:02d}: the same record with {twin_condition} at pcr:2, so the "
            "layer is established. The only difference is that one condition.",
            rec=record(measurement=m, status="warning", layers=base),
            reading={"pcr:2": read("established")}, twin_of=n))
        n += 2

    # Unlisted layer, rule 1: absence is not a pass.
    m = synthetic("not-listed")
    out.append(vector(7, "layer-not-listed",
        "Synthetic. The result lists pcr:0 and pcr:4 only. A reader asking about pcr:2 "
        "reads not-established with the reader's own reason not-listed: a layer the "
        "result does not list is not established either.",
        rec=record(measurement=m, status="warning",
                   layers={"pcr:0": established(), "pcr:4": established()}),
        reading={"pcr:2": read("not-established", "not-listed")}))
    out.append(vector(8, "layer-not-listed-twin",
        "Twin of 07: the same record with pcr:2 listed and established. The only "
        "difference is that one layer.",
        rec=record(measurement=m, status="warning",
                   layers={"pcr:0": established(), "pcr:2": established(),
                           "pcr:4": established()}),
        reading={"pcr:2": read("established")}, twin_of=7))

    # Real measurements, unpaired.
    rc13 = {p: (not_established("layer-not-measured")
                if p in ("pcr:2", "pcr:3", "pcr:5", "pcr:7") else established())
            for p in PCRS_0_9}
    out.append(vector(9, "rc13-layer-not-measured",
        "Real measurement: the v2.1.0-rc13 release reference over PCR 0 to 9. PCR 2, 3, "
        "5 and 7 hold a single separator and nothing else, so a digest comparison passes "
        "them while nothing was measured there. PCR 10 is outside the quote's selection "
        "and is not listed, so a reader asking about it reads not-listed.",
        rec=record(measurement=RC13, status="warning", layers=rc13),
        reading={"pcr:2": read("not-established", "layer-not-measured"),
                 "pcr:4": read("established"),
                 "pcr:10": read("not-established", "not-listed")},
        source=SOURCE_RC13))
    dev = {"pcr:11": not_established("measured-not-appraised"),
           "pcr:12": not_established("measured-not-appraised")}
    out.append(vector(10, "dev-measured-not-appraised",
        "Real measurement: a cold-start quote over PCR 0 to 12 from a development image. "
        "Four IMA entries in PCR 11 and 12 replay to the quoted values; the policy that "
        "leaves them unappraised is not in the log. Only the layers the appraiser "
        "reported are carried. The quote was taken by hand with tpm2_quote under the "
        "board's registered attestation key; the image's attestation agent quotes PCR 0 "
        "to 9 only, so PCR 11 and 12 are not in its envelope.",
        rec=record(measurement=DEV_COLD, status="warning", layers=dev),
        reading={"pcr:11": read("not-established", "measured-not-appraised"),
                 "pcr:12": read("not-established", "measured-not-appraised")},
        source=SOURCE_DEV))

    # Rejections: one code per rule, at least two vectors per code. Each rejection has an
    # accepting twin, written after all of them, that differs from it only in the rule the
    # rejection tests: the same record with the one member that breaks the rule put right.
    m = synthetic("rejections")
    twins: list[tuple[int, str, str, dict[str, Any], dict[str, Any]]] = []

    def reject(n: int, name: str, description: str, code: str, *, layers: Any,
               fixed: dict[str, Any], twin_reading: dict[str, Any],
               platform: str = "tpm2", status: str = "warning",
               result_measurement: str | None = None, schema_sees: bool = True) -> None:
        out.append(vector(n, name, description,
            rec=record(measurement=m, status=status, layers=layers, platform=platform,
                       result_measurement=result_measurement),
            codes=[code], schema_sees=schema_sees))
        twin = {"measurement": m, "status": status, "layers": layers,
                "platform": platform, "result_measurement": result_measurement}
        twin.update(fixed)
        twins.append((n, name, code, twin, twin_reading))

    reject(11, "not-established-without-reason",
        "pcr:2 is not-established and names no reason. The three reasons are different "
        "findings; one without its reason is a generic absence.",
        "not_established_without_reason",
        layers={"pcr:2": {"outcome": "not-established"}},
        fixed={"layers": {"pcr:2": not_established("layer-not-measured")}},
        twin_reading={"pcr:2": read("not-established", "layer-not-measured")})
    reject(12, "not-established-without-reason-among-established",
        "pcr:5 is not-established with no reason, among layers that are established.",
        "not_established_without_reason",
        layers={"pcr:0": established(), "pcr:5": {"outcome": "not-established"},
                "pcr:9": established()},
        fixed={"layers": {"pcr:0": established(),
                          "pcr:5": not_established("measured-not-appraised"),
                          "pcr:9": established()}},
        twin_reading={"pcr:5": read("not-established", "measured-not-appraised")})
    reject(13, "established-with-a-reason",
        "pcr:2 is established and carries a reason. An established layer has none.",
        "established_with_reason",
        layers={"pcr:2": {"outcome": "established", "reason": "layer-not-measured"}},
        fixed={"layers": {"pcr:2": established()}},
        twin_reading={"pcr:2": read("established")})
    reject(14, "established-with-a-multiple-boots-reason",
        "pcr:0 is established and carries evidence-spans-multiple-boots.",
        "established_with_reason",
        layers={"pcr:0": {"outcome": "established",
                          "reason": "evidence-spans-multiple-boots"}},
        fixed={"layers": {"pcr:0": established()}},
        twin_reading={"pcr:0": read("established")})
    reject(15, "layers-empty",
        "layers is an empty object. A result naming no layer establishes nothing.",
        "layers_empty",
        layers={}, fixed={"layers": {"pcr:0": established()}},
        twin_reading={"pcr:0": read("established")})
    reject(16, "reason-outside-the-closed-set",
        "pcr:2 names the reason not-listed, which is the reader's finding about an unlisted "
        "layer and not a reason a record carries.",
        "unknown_reason",
        layers={"pcr:2": not_established("not-listed")},
        fixed={"layers": {"pcr:2": not_established("layer-not-measured")}},
        twin_reading={"pcr:2": read("not-established", "layer-not-measured")})
    reject(17, "reason-spelled-with-underscores",
        "pcr:2 names layer_not_measured, the library's spelling from #457. The record's "
        "reasons are hyphenated.",
        "unknown_reason",
        layers={"pcr:2": not_established("layer_not_measured")},
        fixed={"layers": {"pcr:2": not_established("layer-not-measured")}},
        twin_reading={"pcr:2": read("not-established", "layer-not-measured")})
    reject(18, "tpm-layer-with-a-leading-zero",
        "On tpm2 the layer pcr:02 has a leading zero; two verifiers would name one register "
        "two ways.",
        "tpm_layer_name",
        layers={"pcr:02": established()}, fixed={"layers": {"pcr:2": established()}},
        twin_reading={"pcr:2": read("established")})
    reject(19, "tpm-layer-in-another-spelling",
        "On tpm2 the layer is named PCR2.",
        "tpm_layer_name",
        layers={"PCR2": established()}, fixed={"layers": {"pcr:2": established()}},
        twin_reading={"pcr:2": read("established")})
    reject(20, "layers-empty-off-tpm",
        "layers is an empty object on a non-TPM platform. The rule does not depend on the "
        "platform.",
        "layers_empty",
        layers={}, platform="intel-tdx",
        fixed={"layers": {"rtmr:0": established()}},
        twin_reading={"rtmr:0": read("established")})
    for n, (name, description, other) in enumerate([
        ("result-about-another-measurement",
         "platform_measurement.measurement differs from runtime.measurement: the result is "
         "about other evidence, not this record.", synthetic("other")),
        ("result-about-a-measurement-one-byte-off",
         "platform_measurement.measurement differs from runtime.measurement in its last "
         "byte.", m[:-2] + ("00" if m[-2:] != "00" else "01")),
    ], start=21):
        reject(n, name, description + " Held by the reference model only: the schema "
               "cannot compare two members of the record.",
               "measurement_mismatch",
               layers={"pcr:0": established()}, result_measurement=other,
               fixed={"result_measurement": None},
               twin_reading={"pcr:0": read("established")}, schema_sees=False)

    # No result at all, rule 1: a record without the block establishes no layer.
    nr = synthetic("no-result")
    out.append(vector(23, "no-result",
        "Synthetic. The record carries no appraisal.platform_measurement at all. A reader "
        "asking about pcr:2 reads not-established with the reader's reason not-listed: a "
        "record without the block establishes no layer, whatever its status says.",
        rec=record(measurement=nr, status="warning", layers=None),
        reading={"pcr:2": read("not-established", "not-listed")}))
    out.append(vector(24, "no-result-twin",
        "Twin of 23: the same record with a result that lists pcr:2 as established. "
        "The only difference is the result.",
        rec=record(measurement=nr, status="warning", layers={"pcr:2": established()}),
        reading={"pcr:2": read("established")}, twin_of=23))

    # Rule 5: a written result is an appraisal, so status is not none.
    reject(25, "status-none-with-a-result",
        "appraisal.status is none while the record carries a per-layer result. A verifier "
        "that wrote the result performed an appraisal.",
        "status_none_with_result",
        layers={"pcr:0": established()}, status="none", fixed={"status": "warning"},
        twin_reading={"pcr:0": read("established")})
    reject(26, "status-none-with-a-not-established-result",
        "appraisal.status is none while the result reports pcr:2 not-established. A finding "
        "per layer is a finding, not the absence of one.",
        "status_none_with_result",
        layers={"pcr:2": not_established("layer-not-measured")}, status="none",
        fixed={"status": "warning"},
        twin_reading={"pcr:2": read("not-established", "layer-not-measured")})
    reject(27, "reason-null",
        "pcr:0 is established and carries reason null. A null reason is neither absent nor "
        "one of the three reasons.",
        "unknown_reason",
        layers={"pcr:0": {"outcome": "established", "reason": None}},
        fixed={"layers": {"pcr:0": established()}},
        twin_reading={"pcr:0": read("established")})
    reject(28, "tpm-layer-past-the-last-register",
        "On tpm2 the layer pcr:24 names a register past pcr:23, the last a TPM 2.0 PC "
        "Client platform defines.",
        "tpm_layer_name",
        layers={"pcr:24": established()}, fixed={"layers": {"pcr:23": established()}},
        twin_reading={"pcr:23": read("established")})

    # The accepting twin of every rejection, in the order the rejections were written.
    for i, (n, name, code, twin, twin_reading) in enumerate(twins, start=29):
        out.append(vector(i, f"{name}-twin",
            f"Twin of {n:02d}: the same record with the member that breaks {code} put "
            "right. The only difference is that member.",
            rec=record(**twin), reading=twin_reading, twin_of=n))
    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in out:
        (OUT / name).write_bytes((json.dumps(doc, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
