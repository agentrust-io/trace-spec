"""Generate delegation-link conformance vectors for the proposed A2A profile.

The `delegation` block is normative in v0.2: `schema/trace-claim.json` requires
`parent_record_hash` and `credential_id`, and pins the first to a sha256/sha384
digest string. What a verifier is supposed to *do* with a chain of them is not
normative anywhere. `spec/trace-v0.2.md` never mentions either field; the only
prose is `docs/schema.md`, which says a verifier "walks `parent_record_hash` from
a leaf record back to the root and confirms each hop acted under a credential in
the delegation chain" — one sentence, no rules. `ROADMAP.md` targets the normative
A2A profile at v0.3.

These vectors encode the rules proposed in `docs/rfcs/a2a-delegation-profile.md`,
so that the proposal can be argued against executable material rather than in the
abstract. Each vector is a complete record set plus the verifier context it must
be judged under, and carries its own expected classification and codes. Nothing
here is normative until the proposal is.

Three things were settled while building this set, each because a vector could not
be written without settling it. They are the reason the corpus exists at this
stage rather than after the profile is written:

**The digest preimage.** "Digest of the parent hop's Trust Record" does not say
which bytes. Over the RFC 8785 encoding of the complete record, signature
included, or over the signed body only? The two readings are both natural and
they are not interoperable — a chain built under one is a chain of dangling links
under the other. The profile takes the complete record, because under the other
reading a child's commitment does not bind the parent's *signer*: anyone may
re-sign identical body bytes under a different key and produce a record the child
still points at. Vector 05 is that difference and nothing else.

**Cycles cannot be built.** A cycle would need A's block to carry a digest of B
while B's carries a digest of A, and each digest covers the block holding the
other, so constructing one is a hash collision. The profile therefore has no
cycle rule and says why; what it does need is a depth bound, because an
*unbounded* chain is constructible and a walk without a limit is a denial of
service. That is `depth_exceeded`, and it is the only reason the bound exists.

**Only the leaf's signature is independently attackable.** Every ancestor's bytes
are already committed to by its child, so a record cannot be altered in place
without breaking the link that names it. An ancestor with an invalid signature is
still reachable — it just has to be built that way from the start rather than
tampered with afterwards — which is why `sign_key` is a build-time parameter here
and no vector is produced by mutating a finished chain.

Keys derive from one published seed, per role, so the whole set regenerates
byte-for-byte and a third party can reissue any of it. Public test material with
no secret in it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/delegation-link")
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
PROFILE = "trace.a2a.delegation-link.v0"
SPEC = "docs/rfcs/a2a-delegation-profile.md"

#: One published seed; every role key is a labelled derivation from it, so the
#: corpus needs a single secret-free constant to be fully reissuable. The label is
#: part of the preimage rather than a counter, so adding a role later cannot shift
#: an existing role's key.
SEED = hashlib.sha256(b"trace-spec delegation-link fixture key").digest()

ROLES = ("orchestrator", "planner", "executor", "courier", "auditor", "stranger")

#: Least sensitive first. `data_class` is an open string in the schema, so an
#: ordering cannot be inferred from a record; it is verifier context, supplied
#: per vector exactly like the trusted key set.
LATTICE = ("public", "internal", "confidential", "restricted")

#: Delegation hops beyond the root that a verifier will follow. Vector 02 sits
#: exactly on it and must verify; 21 sits one past it.
MAX_DEPTH = 4

#: Fixed, so every fixture regenerates identically. Vectors that turn on time
#: move the credential window, never the clock.
NOW = 1785000000


def key_for(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SEED + b"|" + role.encode()).digest()
    )


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(role: str) -> dict[str, str]:
    raw = key_for(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def subject_for(role: str) -> str:
    return f"spiffe://acme.example/agent/{role}"


def base_record(role: str, *, iat: int, data_class: str) -> dict[str, Any]:
    """A schema-valid v0.2 record for `role`, with no delegation block yet.

    Deliberately minimal: every field here is required by the schema, and nothing
    optional is present except what a vector adds. A record that carries more than
    the rules under test can read is a record whose failures are harder to place.
    """
    return {
        "eat_profile": V0_2,
        "iat": iat,
        "subject": subject_for(role),
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "00" * 32},
        "policy": {
            "bundle_hash": "sha256:" + "aa" * 32,
            "enforcement_mode": "enforce",
        },
        "data_class": data_class,
        "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "bb" * 32},
        "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    }


def signed(body: dict[str, Any], *, sign_key: str) -> dict[str, Any]:
    """Seal `body` under `sign_key`'s private half, declaring `cnf.jwk` separately.

    `cnf.jwk` is set by the caller before this runs when a vector needs the record
    to *claim* one key and be signed by another; when it is absent the claimed key
    is the signing key, which is the honest case.
    """
    record = dict(body)
    record.setdefault("cnf", {"jwk": jwk_for(sign_key)})
    record["signature"] = b64u(key_for(sign_key).sign(rfc8785.dumps(record)))
    return record


def digest(record: dict[str, Any], alg: str = "sha256") -> str:
    """The profile's preimage: RFC 8785 bytes of the complete record."""
    return f"{alg}:" + hashlib.new(alg, rfc8785.dumps(record)).hexdigest()


def body_digest(record: dict[str, Any], alg: str = "sha256") -> str:
    """The rejected reading: the same record with `signature` removed.

    Present only so vector 05 can be built. Nothing in the profile computes this.
    """
    body = {k: v for k, v in record.items() if k != "signature"}
    return f"{alg}:" + hashlib.new(alg, rfc8785.dumps(body)).hexdigest()


def credential(
    cid: str,
    *,
    issuer: str,
    holder: str,
    not_before: int = NOW - 86400,
    not_after: int = NOW + 86400,
) -> tuple[str, dict[str, Any]]:
    return cid, {
        "issuer": subject_for(issuer),
        "holder": subject_for(holder),
        "not_before": not_before,
        "not_after": not_after,
    }


def build_chain(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a chain root-first, returning the records in root-to-leaf order.

    `hops[0]` is the root and takes no delegation block. Each later hop reads:

      role, data_class, iat      — the record's own content
      credential_id              — what its delegation block names
      parent_alg                 — digest algorithm for the link (default sha256)
      sign_key                   — signer, when it must differ from `role`
      claimed_key                — what `cnf.jwk` advertises, when it must differ
                                   from the signer
      link_over_body             — link to the parent's signed body rather than
                                   the complete record (vector 05 only)

    Built rather than mutated: a finished chain cannot be edited anywhere but the
    leaf without breaking the link that commits to the edited record, so every
    defect involving an ancestor has to exist before its child is signed.
    """
    records: list[dict[str, Any]] = []
    for index, hop in enumerate(hops):
        body = base_record(
            hop["role"], iat=hop.get("iat", NOW), data_class=hop["data_class"]
        )
        if index:
            parent = records[-1]
            alg = hop.get("parent_alg", "sha256")
            link = body_digest if hop.get("link_over_body") else digest
            body["delegation"] = {
                "parent_record_hash": link(parent, alg),
                "credential_id": hop["credential_id"],
            }
        if "claimed_key" in hop:
            body["cnf"] = {"jwk": jwk_for(hop["claimed_key"])}
        records.append(signed(body, sign_key=hop.get("sign_key", hop["role"])))
    return records


def vector(
    vid: str,
    name: str,
    description: str,
    records: list[dict[str, Any]],
    *,
    classification: str,
    codes: list[str],
    credentials: dict[str, Any],
    trusted_roots: tuple[str, ...] = ("orchestrator",),
    supported_algorithms: tuple[str, ...] = ("sha256",),
    leaf: dict[str, Any] | None = None,
    emit: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """One scenario, with everything a third party needs to judge it offline.

    `records` is emitted last-to-first. A verifier that assumes the set arrives in
    chain order, or that treats `records[0]` as the root, fails every vector here
    rather than passing until the first shuffled input reaches production.
    """
    under_appraisal = leaf if leaf is not None else records[-1]
    emitted = emit if emit is not None else records
    return {
        "id": vid,
        "name": name,
        "description": description,
        "spec": SPEC,
        "profile": PROFILE,
        "context": {
            "leaf": digest(under_appraisal),
            "now": NOW,
            "max_depth": MAX_DEPTH,
            "supported_digest_algorithms": supported_algorithms,
            "data_class_lattice": list(LATTICE),
            "trusted_root_keys": [jwk_for(role) for role in trusted_roots],
            "credentials": credentials,
        },
        "records": list(reversed(emitted)),
        "expected": {"classification": classification, "codes": codes},
    }


# --- the credential registry the well-formed chains draw on --------------------

CRED_PLANNER = credential("cred:orchestrator-to-planner", issuer="orchestrator", holder="planner")
CRED_EXECUTOR = credential("cred:planner-to-executor", issuer="planner", holder="executor")
CRED_COURIER = credential("cred:executor-to-courier", issuer="executor", holder="courier")
CRED_AUDITOR = credential("cred:courier-to-auditor", issuer="courier", holder="auditor")

WELL_FORMED = dict([CRED_PLANNER, CRED_EXECUTOR, CRED_COURIER, CRED_AUDITOR])

#: Root to leaf, narrowing at every hop, exactly `MAX_DEPTH` delegations deep.
FULL_DEPTH_HOPS = [
    {"role": "orchestrator", "data_class": "restricted"},
    {"role": "planner", "data_class": "restricted", "credential_id": CRED_PLANNER[0]},
    {"role": "executor", "data_class": "confidential", "credential_id": CRED_EXECUTOR[0]},
    {"role": "courier", "data_class": "internal", "credential_id": CRED_COURIER[0]},
    {"role": "auditor", "data_class": "public", "credential_id": CRED_AUDITOR[0]},
]

SINGLE_HOP = [
    {"role": "orchestrator", "data_class": "restricted"},
    {"role": "planner", "data_class": "confidential", "credential_id": CRED_PLANNER[0]},
]


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    def add(filename: str, doc: dict[str, Any]) -> None:
        out.append((filename, doc))

    # -- verified ---------------------------------------------------------------

    add("01-valid-single-hop.json", vector(
        "TRACE-DELEG-001", "valid-single-hop",
        "One delegation from a trusted root. The shortest chain the profile has "
        "anything to say about, and the case every rule below is a departure from.",
        build_chain(SINGLE_HOP),
        classification="verified", codes=[], credentials=WELL_FORMED,
    ))

    add("02-valid-full-depth-out-of-order.json", vector(
        "TRACE-DELEG-002", "valid-full-depth-out-of-order",
        "Four delegations, exactly on `max_depth`, narrowing at every hop, with "
        "the record set emitted leaf-first. Verifies. A verifier whose bound is "
        "off by one rejects this, which is the other half of vector 21.",
        build_chain(FULL_DEPTH_HOPS),
        classification="verified", codes=[], credentials=WELL_FORMED,
    ))

    add("03-valid-root-only.json", vector(
        "TRACE-DELEG-003", "valid-root-only",
        "A record with no delegation block at all. Not a degenerate chain: a root "
        "execution is the ordinary case, and a verifier that requires the block to "
        "be present has broken every non-delegated record.",
        build_chain([FULL_DEPTH_HOPS[0]]),
        classification="verified", codes=[], credentials=WELL_FORMED,
    ))

    # -- parent_not_found -------------------------------------------------------

    full = build_chain(FULL_DEPTH_HOPS)
    add("04-parent-record-absent.json", vector(
        "TRACE-DELEG-004", "parent-record-absent",
        "The chain is sound, and the record the third hop names is simply not in "
        "the set. Presenting a leaf without the hops that authorise it is the "
        "cheapest attack on a chain nobody walks to the end.",
        full,
        classification="provenance-invalid", codes=["parent_not_found"],
        credentials=WELL_FORMED,
        emit=[r for i, r in enumerate(full) if i != 2],
    ))

    add("05-link-over-signed-body.json", vector(
        "TRACE-DELEG-005", "link-over-signed-body",
        "Every record is present and correctly signed; the leaf's "
        "`parent_record_hash` is a digest of its parent's signed body with "
        "`signature` removed, rather than of the complete record. This is the one "
        "vector that separates the two readings of \"digest of the parent hop's "
        "Trust Record\": under the profile's reading the link resolves to nothing, "
        "under the rejected reading the whole chain verifies.",
        build_chain([
            SINGLE_HOP[0],
            {**SINGLE_HOP[1], "link_over_body": True},
        ]),
        classification="provenance-invalid", codes=["parent_not_found"],
        credentials=WELL_FORMED,
    ))

    # -- record_signature_invalid -----------------------------------------------

    add("06-leaf-signed-by-other-key.json", vector(
        "TRACE-DELEG-006", "leaf-signed-by-other-key",
        "The leaf advertises the executor's key in `cnf.jwk` and is signed by the "
        "stranger's. The leaf is the only record in a chain whose bytes nothing "
        "else commits to, so it is the only one an attacker can reach in place.",
        build_chain([
            SINGLE_HOP[0],
            {**SINGLE_HOP[1], "sign_key": "stranger", "claimed_key": "planner"},
        ]),
        classification="provenance-invalid", codes=["record_signature_invalid"],
        credentials=WELL_FORMED,
    ))

    add("07-intermediate-signed-by-other-key.json", vector(
        "TRACE-DELEG-007", "intermediate-signed-by-other-key",
        "The same defect one hop up, built in before the child committed to it, so "
        "the link still resolves and only the signature is wrong. A verifier that "
        "checks the leaf and trusts the rest of the chain because 'the hashes "
        "match' passes this and fails vector 06.",
        build_chain([
            FULL_DEPTH_HOPS[0],
            {**FULL_DEPTH_HOPS[1], "sign_key": "stranger", "claimed_key": "planner"},
            FULL_DEPTH_HOPS[2],
        ]),
        classification="provenance-invalid", codes=["record_signature_invalid"],
        credentials=WELL_FORMED,
    ))

    # -- root_key_untrusted -----------------------------------------------------

    add("08-root-key-untrusted.json", vector(
        "TRACE-DELEG-008", "root-key-untrusted",
        "A correctly signed, internally consistent single-hop chain whose root is "
        "held by a key the verifier was never given. Every hash matches and every "
        "signature verifies; the chain is anchored to nothing.",
        build_chain([
            {"role": "stranger", "data_class": "restricted"},
            {"role": "planner", "data_class": "confidential",
             "credential_id": "cred:stranger-to-planner"},
        ]),
        classification="provenance-invalid", codes=["root_key_untrusted"],
        credentials=dict([
            credential("cred:stranger-to-planner", issuer="stranger", holder="planner"),
        ]),
    ))

    add("09-trusted-key-below-the-root.json", vector(
        "TRACE-DELEG-009", "trusted-key-below-the-root",
        "The root is the stranger again, but this time the *second* record on the "
        "chain is held by the trusted orchestrator key. Every hop is sound and the "
        "chain is still anchored to nobody: authority does not begin partway up. A "
        "verifier that anchors on the highest trusted key it finds, rather than on "
        "the record with no delegation block, reports this chain verified — and "
        "still fails vector 08, where no record carries a trusted key at all.",
        build_chain([
            {"role": "stranger", "data_class": "restricted"},
            {"role": "orchestrator", "data_class": "restricted",
             "credential_id": "cred:stranger-to-orchestrator"},
            {"role": "planner", "data_class": "confidential",
             "credential_id": CRED_PLANNER[0]},
        ]),
        classification="provenance-invalid", codes=["root_key_untrusted"],
        credentials=dict([
            credential("cred:stranger-to-orchestrator", issuer="stranger",
                       holder="orchestrator"),
            CRED_PLANNER,
        ]),
    ))

    # -- credential_unknown -----------------------------------------------------

    add("10-credential-not-registered.json", vector(
        "TRACE-DELEG-010", "credential-not-registered",
        "The hop names a credential the verifier holds nothing for. The chain is "
        "structurally sound; the authority it claims cannot be looked up.",
        build_chain([
            SINGLE_HOP[0],
            {**SINGLE_HOP[1], "credential_id": "cred:never-issued"},
        ]),
        classification="authorization-invalid", codes=["credential_unknown"],
        credentials=WELL_FORMED,
    ))

    add("11-credential-id-case-differs.json", vector(
        "TRACE-DELEG-011", "credential-id-case-differs",
        "The hop names `CRED:Orchestrator-To-Planner`, differing from the "
        "registered id only in case. `credential_id` is an opaque octet string "
        "with no case-folding rule, so this is an unknown credential — and a "
        "verifier that lowercases before lookup accepts an identifier nobody "
        "issued.",
        build_chain([
            SINGLE_HOP[0],
            {**SINGLE_HOP[1], "credential_id": "CRED:Orchestrator-To-Planner"},
        ]),
        classification="authorization-invalid", codes=["credential_unknown"],
        credentials=WELL_FORMED,
    ))

    # -- credential_issuer_mismatch ---------------------------------------------

    add("12-credential-issued-by-third-party.json", vector(
        "TRACE-DELEG-012", "credential-issued-by-third-party",
        "A registered, in-window credential naming the courier as issuer, used on "
        "a hop whose parent is the orchestrator. Authority that did not come from "
        "the delegating hop is not delegation.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_issuer_mismatch"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="courier", holder="planner"),
        ]),
    ))

    add("13-credential-self-issued.json", vector(
        "TRACE-DELEG-013", "credential-self-issued",
        "The credential names the *holder* as its own issuer. A verifier "
        "comparing the issuer against the record under appraisal rather than "
        "against its parent reads this as consistent, and grants an agent whatever "
        "it wrote down for itself.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_issuer_mismatch"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="planner", holder="planner"),
        ]),
    ))

    # -- credential_holder_mismatch ---------------------------------------------

    add("14-credential-held-by-third-party.json", vector(
        "TRACE-DELEG-014", "credential-held-by-third-party",
        "The credential was issued by the right party to somebody else. Replaying "
        "a valid credential issued to a different agent is the attack a holder "
        "check exists for.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_holder_mismatch"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="orchestrator", holder="courier"),
        ]),
    ))

    add("15-credential-holder-is-the-parent.json", vector(
        "TRACE-DELEG-015", "credential-holder-is-the-parent",
        "Issuer and holder both name the parent. A verifier that has the two "
        "comparisons the wrong way round finds the holder where it expects the "
        "issuer, reports agreement, and passes this while failing 14.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_holder_mismatch"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="orchestrator",
                       holder="orchestrator"),
        ]),
    ))

    # -- credential_window ------------------------------------------------------

    add("16-credential-expired-at-hop.json", vector(
        "TRACE-DELEG-016", "credential-expired-at-hop",
        "The hop executed after its credential's `not_after`. Judged against the "
        "hop's own `iat`, not against the verifier's clock: a chain does not "
        "become invalid because it is being read late.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_window"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="orchestrator",
                       holder="planner", not_before=NOW - 7200, not_after=NOW - 3600),
        ]),
    ))

    add("17-credential-not-yet-valid-at-hop.json", vector(
        "TRACE-DELEG-017", "credential-not-yet-valid-at-hop",
        "The hop executed before its credential's `not_before`. The other side of "
        "the window, and the side an implementation reaches for expiry alone "
        "leaves open — a credential dated into the future authorises everything "
        "done before it existed.",
        build_chain(SINGLE_HOP),
        classification="authorization-invalid", codes=["credential_window"],
        credentials=dict([
            credential("cred:orchestrator-to-planner", issuer="orchestrator",
                       holder="planner", not_before=NOW + 3600, not_after=NOW + 7200),
        ]),
    ))

    # -- data_class_widened -----------------------------------------------------

    add("18-data-class-widened-at-leaf.json", vector(
        "TRACE-DELEG-018", "data-class-widened-at-leaf",
        "A hop delegated from an `internal` parent declares `restricted`. "
        "Delegation cannot manufacture reach the delegator did not have.",
        build_chain([
            {"role": "orchestrator", "data_class": "internal"},
            {"role": "planner", "data_class": "restricted",
             "credential_id": CRED_PLANNER[0]},
        ]),
        classification="authorization-invalid", codes=["data_class_widened"],
        credentials=WELL_FORMED,
    ))

    add("19-data-class-widened-mid-chain.json", vector(
        "TRACE-DELEG-019", "data-class-widened-mid-chain",
        "Widening at the first hop, inside a chain whose leaf is narrower than its "
        "root. Comparing the leaf against the root shows narrowing and reports "
        "nothing; the rule is per hop, and this is the vector that says so.",
        build_chain([
            {"role": "orchestrator", "data_class": "confidential"},
            {"role": "planner", "data_class": "restricted",
             "credential_id": CRED_PLANNER[0]},
            {"role": "executor", "data_class": "internal",
             "credential_id": CRED_EXECUTOR[0]},
            {"role": "courier", "data_class": "public",
             "credential_id": CRED_COURIER[0]},
        ]),
        classification="authorization-invalid", codes=["data_class_widened"],
        credentials=WELL_FORMED,
    ))

    # -- depth_exceeded ---------------------------------------------------------

    deep_hops = FULL_DEPTH_HOPS + [
        {"role": "stranger", "data_class": "public",
         "credential_id": "cred:auditor-to-stranger"},
    ]
    add("21-depth-one-past-the-bound.json", vector(
        "TRACE-DELEG-021", "depth-one-past-the-bound",
        "Five delegations against a bound of four. One past, so a verifier "
        "comparing with the wrong operator accepts it — and vector 02 sits exactly "
        "on the bound and must not be rejected, which pins the comparison from "
        "both sides.",
        build_chain(deep_hops),
        classification="authorization-invalid", codes=["depth_exceeded"],
        credentials=dict(list(WELL_FORMED.items()) + [
            credential("cred:auditor-to-stranger", issuer="auditor", holder="stranger"),
        ]),
    ))

    deeper_hops = deep_hops + [
        {"role": "planner", "data_class": "public",
         "credential_id": "cred:stranger-to-planner-deep"},
    ]
    add("20-depth-far-past-the-bound.json", vector(
        "TRACE-DELEG-020", "depth-far-past-the-bound",
        "Six delegations against a bound of four. An implementation whose bound is "
        "off by one — or absent, walking until the records run out — is separated "
        "from a correct one by 21, not by this; this one is what an unbounded walk "
        "looks like when nobody is counting at all.",
        build_chain(deeper_hops),
        classification="authorization-invalid", codes=["depth_exceeded"],
        credentials=dict(list(WELL_FORMED.items()) + [
            credential("cred:auditor-to-stranger", issuer="auditor", holder="stranger"),
            credential("cred:stranger-to-planner-deep", issuer="stranger", holder="planner"),
        ]),
    ))

    # -- digest_algorithm_unsupported -------------------------------------------

    add("22-leaf-link-uses-sha384.json", vector(
        "TRACE-DELEG-022", "leaf-link-uses-sha384",
        "The leaf links to its parent by a sha384 digest, which the schema permits "
        "and this verifier does not implement. The digest is correct: a verifier "
        "that supports sha384 resolves the link and verifies the chain. The "
        "outcome is unverifiable, not invalid — nothing here contradicts, it just "
        "cannot be read.",
        build_chain([
            SINGLE_HOP[0],
            {**SINGLE_HOP[1], "parent_alg": "sha384"},
        ]),
        classification="unverifiable", codes=["digest_algorithm_unsupported"],
        credentials=WELL_FORMED,
    ))

    add("23-deep-link-uses-sha384.json", vector(
        "TRACE-DELEG-023", "deep-link-uses-sha384",
        "The same unreadable link two hops up, with a sha256 link at the leaf. A "
        "verifier that inspects the algorithm of the first link and assumes the "
        "rest of the chain matches reports this chain verified, having never "
        "resolved half of it.",
        build_chain([
            FULL_DEPTH_HOPS[0],
            {**FULL_DEPTH_HOPS[1], "parent_alg": "sha384"},
            FULL_DEPTH_HOPS[2],
            FULL_DEPTH_HOPS[3],
        ]),
        classification="unverifiable", codes=["digest_algorithm_unsupported"],
        credentials=WELL_FORMED,
    ))

    for name, doc in sorted(out):
        (OUT / name).write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print("wrote", name)


if __name__ == "__main__":
    main()
