# Verifier-issued, holder-bound TRACE: experimental reference

This prototype implements the proposals in `docs/rfcs/verifier-issued-trace-profile.md`
and `docs/rfcs/composite-component-appraisal.md`.
It is a proposal, not an adopted TRACE profile. Existing v0.2 records, signatures,
schemas and verification behavior retain their current meaning.

## Three separate objects

An Agent Manifest describes the issuer's intended component and requirements.
Evidence describes observations of an instantiated workload. A verifier-issued
TRACE token reports the verifier's appraisal of those observations under a
specific policy and verification context. Acceptance of that token does not
authorize an action: the relying party also verifies possession of the holder
key, current status, exact call binding and its own action policy.

The reference implementation lives in
`prototype.verifier_token`, outside the installed SDK package. Public functions
normalize malformed direct inputs to ProfileError; configured context and issuer
values are validated separately. The argument sweep inventories all fourteen
public functions and their parameters. This does not prove every nested boundary.
Four JSON schemas cover the token, locally configured requirements, holder proof
and separate gateway decision receipt. Fourteen independently constructed vectors
pin the wire bytes. The vector generator uses cryptographic primitives and literal
wire definitions rather than the implementation's signing or validation functions.

## Experimental wire choices

The token profile is `urn:agentrust:trace:verifier-token:experimental-v1`.
COSE_Sign1 carries a JCS JSON payload, fully specified Ed25519 (`-19`), a key ID
derived from the trusted public key, a profile-specific content type and a private
critical `trace-profile` protected header. It is not a CWT claim encoding or an
IANA-registered profile. These wire choices still need public review.

The parser requires bounded, canonical CBOR and canonical JSON; duplicate keys,
unsigned headers, algorithm aliases, unexpected fields and cross-profile envelopes
are rejected. The token signs issuer, holder confirmation key, authenticated
subject and instance, audience, issuance and exclusive expiry, token ID, exact
signed Agent Manifest bytes digest, verification-context digest and policy binding.
The verifier signing key must differ from the holder key. Issuer trust comes from
the relying party's configured key store, never the token itself.

Required components are determined by local trusted requirements, including both
ends of required relationships. Composite appraisal is recomputed from component
statuses, accepted evidence profiles and authorities, instance consistency,
freshness and required bindings. Unknown, missing and unverifiable results cannot
silently become affirming. Expiry is bounded by issuer validity, manifest validity,
component evidence and relationship freshness. By default the token issuer is the
only appraisal authority. A relying party may also configure delegated component
appraisers, described next.

## Delegated component appraisal

The relying party may configure trusted appraisers next to its trusted issuers.
Each entry is keyed by `(authority, kid)`, where kid is SHA-256 of the raw 32-byte
Ed25519 public key, and grants a non-empty set of evidence profiles, a non-empty
set of component types and a validity interval `[valid_from, valid_until)`. With no
entries, behavior is unchanged.

A component whose `authority` differs from the token `iss` may carry an optional
`appraisal` member: canonical unpadded base64url (1 to 16384 characters, never
`null`) of a COSE_Sign1 envelope with profile
`urn:agentrust:trace:component-appraisal:experimental-v1` and content type
`application/trace-component-appraisal+json`. The envelope rules are those of the
token and holder proof: canonical CBOR, tag 18, empty unprotected map, protected
header exactly `{1: -19, 2: ["trace-profile"], 3: content type, 4: kid,
"trace-profile": profile}`, 64-byte Ed25519 signature over
`["Signature1", protected, h'', payload]`, and a canonical JCS payload without
duplicate members. The payload is closed:

```json
{"profile": "urn:agentrust:trace:component-appraisal:experimental-v1",
 "iss": "<appraiser authority>",
 "component": {"<the component exactly as carried, without appraisal>": "..."}}
```

The component is nested, not merged, because a component already has its own
`profile` member (its evidence profile). `component` is the carried component
object with only the `appraisal` member removed; no defaults are added. The payload
has no separate instance, subject or audience claim. The signed component's
`instance` must already equal the token `instance`, so an appraisal cannot move to
another workload instance. It is deliberately not bound to the carrying issuer:
any trusted token issuer may carry it, and the appraiser, not the carrier, is the
party that signed the component result.

Each present component is evaluated after its type, observation, instance,
interval, age-bound and evidence checks:

1. No `appraisal`: nothing further. A component whose authority is not `iss` is
   `unverifiable`, as before.
2. `appraisal` present and authority equal to `iss`: reject
   `component_appraisal_unexpected`.
3. Decode the base64url strictly (it must re-encode to the same text), then apply
   the envelope and closed-payload rules for the appraisal profile. Any failure:
   `component_appraisal_malformed`.
4. Find the configured appraiser by (component `authority`, protected kid). If
   there is none, or `now` is outside its `[valid_from, valid_until)`, the
   component is `unverifiable`; this is not a rejection.
5. Verify the signature under that key. Failure: `component_appraisal_signature_invalid`.
6. The signed `iss` must equal the carried `authority`, and the signed `component`
   must equal the carried component without `appraisal` as a JSON value. Otherwise
   `component_appraisal_mismatch`.
7. The component `profile` must be in the grant's profiles and its
   `component_type` in the grant's component types; otherwise `unverifiable`.

A component that passes all seven steps counts as appraised by an accepted
authority. It is still subject to the requirement's `accepted_profiles` and
`accepted_authorities`, and a delegated appraisal never overrides them. Binding
digests cover each component exactly as signed in the token, `appraisal` included.

This proves that the configured appraiser signed this exact component result and
that the token issuer only carried it. It does not reappraise the appraiser's
evidence: the relying party trusts the appraiser for its grant as it trusts an
issuer. Freshness remains the signed `appraised_at` and `fresh_until`, bounded as
for any component.

## Relationship methods

`same-instance-v1` checks consistency and a signed digest of the two component
appraisal objects. It authenticates the issuer's relationship assertion; it does
not independently prove a CPU/GPU hardware relationship or appraise a quote.
Evidence digests are required; resolver hints are optional and untrusted.

`same-evidence-v1` is an additive method with the same relationship
(`same-workload`), the same digest preimage form (with `"method":
"same-evidence-v1"`) and the same instance and freshness checks. After those
checks, the source and target must each list an `evidence_refs` entry with the
same `digest`: the two digest sets must intersect. Otherwise the token is rejected
with `binding_evidence_disjoint`. Only the digest is compared; the two entries may
name different evidence profiles and media types, because two appraisal profiles
can appraise one evidence object. The binding identity includes the method, so a
requirement for `same-evidence-v1` is not met by a `same-instance-v1` binding.

This proves that the issuer digest-bound both component appraisals to one evidence
object, so the relationship rests on shared evidence rather than on the issuer's
assertion alone, and a relying party that retrieves that object can check it. It
does not reappraise or resolve the evidence, does not show that each appraisal
read the part of the object it claims, and proves no more about a physical
relationship than that one evidence object attests.

On real data: for the saved Azure packet
`tests/fixtures/azure-execution-20260929/b1-approved-packet.json`, the
`application.code` component from `azure_execution_binding.execution_component`
and the `runtime.cpu` component from `snp_collateral.tcb_component` both cite
`canonical_digest(packet)`, so a `same-evidence-v1` binding holds. A `runtime.cpu`
built from another packet (the b2 packet or the live Milan packet) is rejected
with `binding_evidence_disjoint` (`tests/test_stage4_relationships.py`).

The binding digest is SHA-256 over the JCS form of
`{"method", "source", "target"}`, where `source` and `target` are the two component
objects exactly as they appear in the signed payload. A verifier adds no defaults:
an optional member absent from the wire stays absent from the preimage. A required
binding whose source or target component is absent from the token evaluates as
`missing` and its digest is not evaluated; the token stays well formed and its
composite cannot be affirming. The composite `fresh_until` is the earliest of the
token `exp` and every required component and binding boundary, so a composite never
outlives its token. When required results differ, the overall status is the first
present in this order: contraindicated, missing, unverifiable, not-appraised; then
warning, which counts as contraindicated unless the requirements allow warnings.
The last two rules were settled after vectors COMP-FRESH-009/010 and COMP-COMP-008/009
showed the two implementations reading them differently. The first two rules were settled by the first independent
implementation (`tools/independent-verifier/`), which found the reference hashing a
normalized model instead of the signed objects.

## Holder proof and decision receipt

Holder proofs use a separate profile and bind a one-use challenge to the exact
token, audience, session, action digest and validity interval. The local harness
consumes challenges atomically and retains consumed nonces until expiry. Its
in-memory replay store is a single-process demonstration, not a distributed store.
The cMCP gate keeps its replay state behind `prototype.gate_store.GateStore`: SQLite
for one host, or one `GateStoreServer` process shared by gateway replicas over TCP.
`tests/test_multihost_replay.py` runs two replicas as separate processes and refuses
cross-replica proof replay, a second concurrent consume, token-ID reuse and receipt
chain forks; per-replica stores are the counterexample. The prototype store server
is not itself replicated, so replicas fail closed while it is unreachable.
Callers must supply trusted clock values and unpredictable, server-generated nonces.

The gateway's separately signed allow/deny receipt binds token digest, token ID,
session, call, action and gateway policy. It does not modify the verifier token.
An allow receipt reports authorization, not execution or physical completion.

## Signed intent and cMCP enforcement

The sibling Agent Manifest proposal implements
`evidence-requirements-experimental-v1` for v0.2 COSE. Its normal SDK verifies the
manifest before exporting signed requirements, exact artifact digest, identity,
expiry and whitelisted artifact outcomes. The TRACE bridge intersects accepted
profiles/authorities with independent local trust, retains both required sets,
and uses the tighter age limit. A signed declaration cannot introduce trust.
Expected observation digests add a constraint and cannot replace a different
local pin. cMCP signs its sealed catalog-file digest in the required catalog
component declaration; its tool_manifest retains the distinct Merkle root.
The adapter recomputes that root from actual approved schemas/descriptions and
checks both. Output schemas and endpoint metadata remain covered by the sealed
catalog digest. The projection and expectation field require public review.

`prototype.cmcp_bootstrap.build_protected_server` verifies this intent and wires
`CMCPTraceGate` through cMCP's normal server builder. The operator supplies
configured identity, issuer trust, status callback, clock, database and a distinct
gateway signing key. Clients supply no trust anchors. cMCP default startup remains
unchanged; the experimental path requires explicit operator composition.
The token's appraisal-policy digest and gateway's action-policy digest are
independent inputs. A receipt binds the actual loaded gateway policy. The signed
manifest's policy artifact is checked against that actual runtime policy.

Bearer-protected `/trace/challenge` and `/trace/admit` endpoints bind holder proofs
to the actual server session. The server generates call IDs and reconstructs the
action from its catalog. Each `tools/call` carries `_cmcp.trace.call_id` and
`_cmcp.trace.credentials`. Missing, replayed or mismatched proofs fail closed.

SQLite atomically consumes challenges, persists session admission generations,
reserves call IDs and records issuer/token-ID collisions across workers and
restarts. Several gateway replicas share this state through the `GateStore`
interface (`prototype/gate_store.py`); the tested shared store is one server
process, so production needs a replicated linearizable database behind the same
interface, mutual TLS on the store channel and bounded clock skew between
replicas. Receipts commit before
transport and sign the preceding receipt hash. Retention/rotation of these tables,
protected database storage and separately retained checkpoints require an operator
policy. A chain alone cannot detect a complete rewrite without an external anchor.

The proxy freezes the accepted action, applies Cedar independently, and rechecks
identity/action, policy, status and expiry after asynchronous provenance work,
immediately before transport, and after durable receipt creation. Refreshing the
admission generation invalidates pending calls. Storage failure prevents transport.
An allow receipt may precede a later refusal; the terminal cMCP audit records the
actual outcome. Receipt authorization must not be interpreted as completed work.

The cross-repository checks execute the real cMCP proxy, Cedar, server routes and
production builder. The upstream transport is controlled HTTPX, and appraisals,
status and clocks are test inputs. A causal check admits an expired call only when
the recheck is disabled. A second, clean-room verifier in JavaScript
(`tools/independent-verifier/`) agrees with the reference on every portable vector;
its stage 4 additions were written by the same author as the reference change, so
only the stage 1 to 3 surface is independent in authorship.

## Reproduction

From this checkout in PowerShell, with prototype dependencies installed:

```powershell
$env:PYTHONPATH="$PWD;$PWD/src"
python -m pip install -e '.[dev,prototype]'
python tools/gen_verifier_token_schemas.py
python examples/verifier-token-profile/gen_vectors.py
python -m pytest -q tests/test_verifier_token_profile.py tests/test_verifier_token_mutations.py
```

The causal tests first require the unchanged implementation to reject each bad
input, then disable one mapped verification rule in memory and require that input
to be admitted. `tests/test_conformance_causal.py` does this for every portable
requirement in `examples/verifier-token-conformance/coverage.json` and every refusal
code added since.

For the cross-repository demonstration, use sibling Agent Manifest and cMCP
checkouts with their runtime dependencies installed:

```powershell
$env:PYTHONPATH="$PWD;$PWD/src;$PWD/../agent-manifest/python/src;$PWD/../cmcp/src"
python tools/run_verifier_token_poc.py
```

The demonstration validates a real signed Agent Manifest with its Python SDK and
evaluates action policy through cMCP's real Cedar adapter. It asserts that only
the valid allow case reaches a local upstream-call collector. Policy denial,
expiry, wrong holder, manifest substitution, missing components, revocation and
status-service outage produce zero calls. Allow and deny receipts are checked
offline with a separate gateway key.

## Work still required

Since 29 September 2026 the prototype has run execution binding live on Azure
SEV-SNP through this gateway, gained SNP and TDX collateral adapters, and been
checked by the portable conformance corpus and a second verifier. What remains:

- An accepted current platform. The Azure SNP hosts tested are below the
  AMD-SB-3016 floor, and the TDX quote with signed collateral is historical and from
  another instance.
- Evidence resolution. Evidence references are digest-bound but never fetched and
  re-appraised by the relying party.
- Delegation chains and revocation of delegated appraisers; `same-evidence-v1` is the
  strongest relationship method, and it does not re-appraise the shared evidence.
- MCP server components and a server-to-catalog relationship profile.
- A replicated store for multi-host replay state, and the protections that store needs.
- Public review before normative adoption or stable SDK promotion. The wire format,
  relationship methods and catalog projection remain experimental choices.
