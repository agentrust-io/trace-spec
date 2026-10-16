// Independent verifier for the experimental TRACE verifier token and holder
// proof, written from docs/verifier-token-experimental.md, the JSON schemas
// and the code list in examples/verifier-token-conformance/codes.json.

import { fail, VerifyError } from './errors.mjs';
import { canonicalize } from './json.mjs';
import {
  validateToken, validateProof, validateAppraisal, TOKEN_PROFILE, PROOF_PROFILE, APPRAISAL_PROFILE,
} from './schema.mjs';
import {
  unpack, sigStructure, ed25519Verify, isCanonicalEd25519, b64uStrict,
  sha256, sha256Hex, bytesEqual,
} from './cose.mjs';

export const TOKEN_MEDIA_TYPE = 'application/trace-verifier-token+json';
export const PROOF_MEDIA_TYPE = 'application/trace-holder-proof+json';
export const APPRAISAL_MEDIA_TYPE = 'application/trace-component-appraisal+json';
const COMPONENT_TYPES = ['identity', 'code', 'model', 'policy', 'runtime', 'accelerator', 'mcp-server', 'tool-catalog', 'guardrail', 'data-state'];

// Composite precedence, worst first. Positive evidence of a problem
// (contraindicated) outranks absence of evidence; absence outranks a warning.
// Settled rule: missing outranks unverifiable (COMP-COMP-008/009).
export const STATUS_PRECEDENCE = ['contraindicated', 'missing', 'unverifiable', 'not-appraised', 'warning', 'affirming'];

const isNonNegInt = (n) => typeof n === 'number' && Number.isInteger(n) && n >= 0;
const policyEqual = (a, b) => a.id === b.id && a.version === b.version && a.digest === b.digest;
const bindingKey = (b) => JSON.stringify([b.source, b.target, b.relationship, b.method]);
const byCodeUnits = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function worst(statuses) {
  let best = STATUS_PRECEDENCE.length - 1;
  for (const s of statuses) best = Math.min(best, STATUS_PRECEDENCE.indexOf(s));
  return STATUS_PRECEDENCE[best];
}

// Validates the locally configured context. Vectors never expect these codes.
export function makeContext(c) {
  const bad = (m) => fail('context_configuration_invalid', m);
  if (!c || typeof c !== 'object') bad('context');
  for (const k of ['audience', 'subject', 'instance', 'manifest_id', 'question_digest']) {
    if (typeof c[k] !== 'string' || c[k] === '') bad(k);
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(c.question_digest)) bad('question_digest');
  if (!isNonNegInt(c.manifest_valid_until)) bad('manifest_valid_until');
  if (!isNonNegInt(c.maximum_lifetime) || c.maximum_lifetime < 1) bad('maximum_lifetime');
  if (!['active', 'inactive', 'unavailable'].includes(c.status)) bad('status');
  const p = c.policy;
  if (!p || typeof p.id !== 'string' || typeof p.version !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(p.digest)) bad('policy');
  const r = c.requirements;
  if (!r || !Array.isArray(r.components) || r.components.length < 1 || !Array.isArray(r.bindings) || typeof r.allow_warnings !== 'boolean') bad('requirements');
  const reqIds = new Set();
  for (const q of r.components) {
    if (reqIds.has(q.component_id)) bad('duplicate requirement');
    reqIds.add(q.component_id);
    if (!Array.isArray(q.accepted_profiles) || !Array.isArray(q.accepted_authorities) || !isNonNegInt(q.maximum_age_seconds)) bad('requirement');
  }
  const trusted = (c.trusted_issuers || []).map((t) => {
    const pub = b64uStrict(t.public_b64url);
    if (typeof t.issuer !== 'string' || t.issuer === '') fail('issuer_configuration_invalid', 'issuer');
    if (!pub || pub.length !== 32) fail('issuer_configuration_invalid', 'key');
    if (!isNonNegInt(t.valid_from) || !isNonNegInt(t.valid_until) || t.valid_until <= t.valid_from) fail('issuer_configuration_invalid', 'interval');
    return { issuer: t.issuer, publicRaw: pub, kid: sha256(pub), validFrom: t.valid_from, validUntil: t.valid_until };
  });
  // Delegated component appraisers, keyed by (authority, kid). Optional; absent
  // means only the token issuer appraises.
  const appraisers = (c.trusted_appraisers ?? []).map((a) => {
    const badA = (m) => fail('appraiser_configuration_invalid', m);
    const pub = b64uStrict(a.public_b64url);
    if (typeof a.authority !== 'string' || a.authority === '') badA('authority');
    if (!pub || pub.length !== 32) badA('key');
    if (!Array.isArray(a.profiles) || a.profiles.length === 0 || a.profiles.some((x) => typeof x !== 'string' || x === '')) badA('profiles');
    if (!Array.isArray(a.component_types) || a.component_types.length === 0 || a.component_types.some((x) => !COMPONENT_TYPES.includes(x))) badA('component_types');
    if (!isNonNegInt(a.valid_from) || !isNonNegInt(a.valid_until) || a.valid_until <= a.valid_from) badA('interval');
    return {
      authority: a.authority, publicRaw: pub, kid: sha256(pub),
      profiles: new Set(a.profiles), componentTypes: new Set(a.component_types),
      validFrom: a.valid_from, validUntil: a.valid_until,
    };
  });
  let manifestBytes = c.manifest_bytes;
  if (!manifestBytes) manifestBytes = new Uint8Array(Buffer.from(c.manifest_b64, 'base64'));
  return {
    audience: c.audience, subject: c.subject, instance: c.instance,
    manifestBytes, manifestId: c.manifest_id, manifestValidUntil: c.manifest_valid_until,
    questionDigest: c.question_digest, policy: p, requirements: r, trusted, appraisers,
    status: c.status, maximumLifetime: c.maximum_lifetime,
  };
}

// Recomputes the composite appraisal from the components, bindings and the
// local requirements. Returns {status, required_components, policy, fresh_until}.
export function deriveComposite(token, ctx, delegated = new Set()) {
  const req = ctx.requirements;
  const reqById = new Map(req.components.map((q) => [q.component_id, q]));
  const compById = new Map(token.components.map((c) => [c.component_id, c]));
  const bindByKey = new Map(token.bindings.map((b) => [bindingKey(b), b]));

  const required = new Set();
  for (const q of req.components) if (q.required === true) required.add(q.component_id);
  for (const br of req.bindings) { required.add(br.source); required.add(br.target); }
  const requiredList = [...required].sort(byCodeUnits);

  const effective = (s) => (s === 'warning' && !req.allow_warnings ? 'contraindicated' : s);
  const statuses = [];
  const freshness = [];
  for (const cid of requiredList) {
    const c = compById.get(cid);
    const q = reqById.get(cid);
    if (!c) { statuses.push('missing'); continue; }
    freshness.push(c.fresh_until);
    // A component from another authority counts only with a valid delegated appraisal.
    const authorityOk = c.authority === token.iss || delegated.has(cid);
    if (!q || !q.accepted_profiles.includes(c.profile) || !q.accepted_authorities.includes(c.authority) || !authorityOk) {
      statuses.push('unverifiable');
      continue;
    }
    statuses.push(effective(c.status));
  }
  for (const br of req.bindings) {
    const b = bindByKey.get(bindingKey(br));
    // Clarified rule: a binding whose endpoint is absent from the token is missing.
    if (!b || !compById.has(br.source) || !compById.has(br.target)) { statuses.push('missing'); continue; }
    freshness.push(b.fresh_until);
    statuses.push(effective(b.status));
  }
  return {
    status: statuses.length ? worst(statuses) : 'missing',
    required_components: requiredList,
    policy: { id: ctx.policy.id, version: ctx.policy.version, digest: ctx.policy.digest },
    // Settled rule: the composite never outlives the token (COMP-FRESH-009/010).
    fresh_until: Math.min(token.exp, ...freshness),
  };
}

// Delegated component appraisal, following the numbered steps in the profile
// document. Returns true when the component counts as appraised by an accepted
// authority, false when it stays unverifiable; throws on a hard rejection.
export function appraisalAccepted(c, t, ctx, now) {
  if (!('appraisal' in c)) return false;
  if (c.authority === t.iss) fail('component_appraisal_unexpected', c.component_id);
  let parts;
  try {
    const bytes = b64uStrict(c.appraisal);
    if (!bytes) fail('component_appraisal_malformed', 'base64url');
    parts = unpack(bytes, APPRAISAL_PROFILE, APPRAISAL_MEDIA_TYPE);
    validateAppraisal(parts.payload);
  } catch (e) {
    if (e instanceof VerifyError && e.code === 'component_appraisal_malformed') throw e;
    fail('component_appraisal_malformed', e instanceof Error ? e.message : String(e));
  }
  const a = ctx.appraisers.find((x) => x.authority === c.authority && bytesEqual(x.kid, parts.kid));
  if (!a || now < a.validFrom || now >= a.validUntil) return false;
  if (!ed25519Verify(a.publicRaw, sigStructure(parts.protBytes, parts.payloadBytes), parts.signature)) {
    fail('component_appraisal_signature_invalid', c.component_id);
  }
  const carried = { ...c };
  delete carried.appraisal;
  if (parts.payload.iss !== c.authority || canonicalize(parts.payload.component) !== canonicalize(carried)) {
    fail('component_appraisal_mismatch', c.component_id);
  }
  return a.profiles.has(c.profile) && a.componentTypes.has(c.component_type);
}

export function bindingDigest(method, source, target) {
  return sha256Hex(Buffer.from(canonicalize({ method, source, target }), 'utf8'));
}

// Returns {token, composite_status}. Throws VerifyError on rejection.
export function verifyToken(envelope, ctx, now) {
  if (!isNonNegInt(now) || !ctx) fail('verification_inputs_invalid');

  // 1. Envelope, protected header, payload encoding, closed schema.
  const { protBytes, payloadBytes, signature, kid, payload } = unpack(envelope, TOKEN_PROFILE, TOKEN_MEDIA_TYPE);
  validateToken(payload);
  const t = payload;

  // 2. Issuer trust comes only from configuration, keyed by (iss, kid).
  const issuer = ctx.trusted.find((e) => e.issuer === t.iss && bytesEqual(e.kid, kid));
  if (!issuer) fail('issuer_untrusted');
  if (now < issuer.validFrom || now >= issuer.validUntil) fail('issuer_expired');
  if (!ed25519Verify(issuer.publicRaw, sigStructure(protBytes, payloadBytes), signature)) fail('signature_invalid');

  // 3. Holder confirmation key.
  const holderRaw = b64uStrict(t.cnf.x);
  if (!holderRaw || !isCanonicalEd25519(holderRaw)) fail('holder_key_invalid');
  if (bytesEqual(holderRaw, issuer.publicRaw)) fail('issuer_holder_same_key');

  // 4. Time and lifetime. A token whose own interval is empty or too long is
  // rejected as such before it is compared with the clock.
  if (t.exp <= t.iat || t.exp - t.iat > ctx.maximumLifetime) fail('token_lifetime');
  if (now < t.iat || now >= t.exp) fail('token_expired_or_future');
  if (t.exp > issuer.validUntil || t.exp > ctx.manifestValidUntil) fail('expiry_exceeds_credential');

  // 5. Relying-party context.
  if (t.aud !== ctx.audience) fail('audience_mismatch');
  if (t.sub !== ctx.subject || t.instance !== ctx.instance) fail('subject_or_instance_mismatch');
  if (t.manifest.digest !== sha256Hex(ctx.manifestBytes) || t.manifest.id !== ctx.manifestId) fail('manifest_mismatch');
  if (t.verification_context_hash !== ctx.questionDigest) fail('context_mismatch');
  if (!policyEqual(t.appraisal_policy, ctx.policy)) fail('policy_mismatch');

  // 6. Current status, fail closed.
  if (ctx.status === 'unavailable') fail('status_unavailable');
  if (ctx.status !== 'active') fail('status_not_active');

  // 7. Component and binding structure against local requirements.
  const req = ctx.requirements;
  const reqById = new Map(req.components.map((q) => [q.component_id, q]));
  const compById = new Map();
  for (const c of t.components) {
    if (compById.has(c.component_id)) fail('duplicate_component', c.component_id);
    compById.set(c.component_id, c);
  }
  for (const c of t.components) if (!reqById.has(c.component_id)) fail('undeclared_component', c.component_id);
  const declaredBindings = new Set(req.bindings.map(bindingKey));
  const seenBindings = new Set();
  for (const b of t.bindings) {
    const k = bindingKey(b);
    if (seenBindings.has(k)) fail('duplicate_binding');
    seenBindings.add(k);
  }
  for (const b of t.bindings) if (!declaredBindings.has(bindingKey(b))) fail('undeclared_binding');

  const delegated = new Set();
  for (const c of t.components) {
    const q = reqById.get(c.component_id);
    if (c.component_type !== q.component_type) fail('component_type_mismatch', c.component_id);
    const pin = q.expected_observed_digest ?? null;
    if (pin !== null && (c.observed_digest ?? null) !== pin) fail('component_observation_mismatch', c.component_id);
    if (c.instance !== t.instance) fail('mixed_instance', c.component_id);
    if (c.appraised_at > t.iat || c.fresh_until <= c.appraised_at) fail('component_interval', c.component_id);
    if (c.fresh_until > c.appraised_at + q.maximum_age_seconds) fail('component_age_bound', c.component_id);
    if ((c.status === 'affirming' || c.status === 'warning') && c.evidence_refs.length === 0) fail('evidence_missing', c.component_id);
    for (const e of c.evidence_refs) if (e.profile !== c.profile) fail('evidence_profile_mismatch', c.component_id);
    if (appraisalAccepted(c, t, ctx, now)) delegated.add(c.component_id);
  }

  // 8. Bindings: endpoints, instance, signed digest, freshness.
  for (const b of t.bindings) {
    const s = compById.get(b.source);
    const g = compById.get(b.target);
    if (!s || !g) continue; // evaluated as missing in the composite (clarified rule)
    if (s.instance !== t.instance || g.instance !== t.instance) fail('mixed_instance', 'binding');
    if (b.digest !== bindingDigest(b.method, s, g)) fail('binding_digest_mismatch');
    if (b.fresh_until > Math.min(s.fresh_until, g.fresh_until)) fail('binding_interval');
    // same-evidence-v1: both endpoints cite one evidence object by digest.
    if (b.method === 'same-evidence-v1') {
      const sourceDigests = new Set(s.evidence_refs.map((e) => e.digest));
      if (!g.evidence_refs.some((e) => sourceDigests.has(e.digest))) fail('binding_evidence_disjoint');
    }
  }

  // 9. Expiry bounded by evidence freshness of required elements.
  const derived = deriveComposite(t, ctx, delegated);
  const requiredSet = new Set(derived.required_components);
  const bounds = [];
  for (const c of t.components) if (requiredSet.has(c.component_id)) bounds.push(c.fresh_until);
  for (const b of t.bindings) bounds.push(b.fresh_until); // every declared binding is required
  if (bounds.length) {
    const minFresh = Math.min(...bounds);
    if (t.exp > minFresh) fail('expiry_exceeds_evidence');
    if (now >= minFresh) fail('component_expired');
  }

  // 10. Composite consistency.
  const ca = t.composite_appraisal;
  if (
    ca.status !== derived.status ||
    ca.fresh_until !== derived.fresh_until ||
    !policyEqual(ca.policy, derived.policy) ||
    ca.required_components.length !== derived.required_components.length ||
    ca.required_components.some((r, i) => r !== derived.required_components[i])
  ) fail('composite_inconsistent');

  return { token: t, holderRaw, composite_status: derived.status, envelope };
}

// proofInput: {proof_b64 | proof_bytes, nonce, audience, session_id,
// action_digest, challenge_issued_at, challenge_expires_at}
export function verifyProof(verified, proofInput, ctx, now) {
  if (!isNonNegInt(now)) fail('verification_inputs_invalid');
  let proofBytes = proofInput.proof_bytes;
  if (!proofBytes) {
    if (typeof proofInput.proof_b64 !== 'string') fail('input_invalid');
    proofBytes = new Uint8Array(Buffer.from(proofInput.proof_b64, 'base64'));
  }
  const { protBytes, payloadBytes, signature, kid, payload } = unpack(proofBytes, PROOF_PROFILE, PROOF_MEDIA_TYPE);
  validateProof(payload);
  const p = payload;
  const t = verified.token;
  const holderRaw = verified.holderRaw;
  if (!holderRaw || !isCanonicalEd25519(holderRaw)) fail('holder_key_invalid');
  if (!bytesEqual(kid, sha256(holderRaw))) fail('key_id_mismatch');
  if (!ed25519Verify(holderRaw, sigStructure(protBytes, payloadBytes), signature)) fail('signature_invalid');

  if (
    p.nonce !== proofInput.nonce ||
    p.token_digest !== sha256Hex(verified.envelope) ||
    p.token_id !== t.jti ||
    p.audience !== proofInput.audience ||
    p.audience !== t.aud ||
    p.session_id !== proofInput.session_id ||
    p.action_digest !== proofInput.action_digest
  ) fail('holder_proof_binding');

  const ci = proofInput.challenge_issued_at;
  const ce = proofInput.challenge_expires_at;
  if (now < ci || now >= ce || p.issued_at !== ci || p.expires_at !== ce || p.expires_at > t.exp) fail('holder_proof_expired');
  return 'valid';
}

export { VerifyError };
