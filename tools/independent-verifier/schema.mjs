// Closed-schema validation for the token and holder-proof payloads,
// hand-written from schema/trace-token-experimental-v1.json and
// schema/trace-holder-proof-experimental-v1.json. Any violation is
// malformed_payload.

import { fail } from './errors.mjs';

export const TOKEN_PROFILE = 'urn:agentrust:trace:verifier-token:experimental-v1';
export const PROOF_PROFILE = 'urn:agentrust:trace:holder-proof:experimental-v1';
export const APPRAISAL_PROFILE = 'urn:agentrust:trace:component-appraisal:experimental-v1';
export const BINDING_METHODS = ['same-instance-v1', 'same-evidence-v1'];

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64U43_RE = /^[A-Za-z0-9_-]{43}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const MAX_INT = 9007199254740991;
export const STATUSES = ['affirming', 'warning', 'contraindicated', 'unverifiable', 'missing', 'not-appraised'];
const COMPONENT_TYPES = ['identity', 'code', 'model', 'policy', 'runtime', 'accelerator', 'mcp-server', 'tool-catalog', 'guardrail', 'data-state'];

const bad = (where) => fail('malformed_payload', where);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// JSON Schema maxLength counts code points, not UTF-16 units.
const cpLen = (s) => [...s].length;

function closed(o, where, required, optional = []) {
  if (!isObj(o)) bad(`${where} not an object`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(o)) if (!allowed.has(k)) bad(`${where}.${k} unexpected`);
  for (const k of required) if (!(k in o)) bad(`${where}.${k} missing`);
}
function str(v, where) { if (typeof v !== 'string') bad(`${where} not a string`); }
function id(v, where) { str(v, where); if (!ID_RE.test(v)) bad(`${where} pattern`); }
function digest(v, where) { str(v, where); if (!DIGEST_RE.test(v)) bad(`${where} pattern`); }
function text255(v, where) { str(v, where); const n = cpLen(v); if (n < 1 || n > 255) bad(`${where} length`); }
function int(v, where) { if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > MAX_INT) bad(`${where} integer range`); }
function oneOf(v, list, where) { str(v, where); if (!list.includes(v)) bad(`${where} enum`); }
function konst(v, c, where) { if (v !== c) bad(`${where} const`); }
function arr(v, where, max) { if (!Array.isArray(v)) bad(`${where} not an array`); if (v.length > max) bad(`${where} maxItems`); }

function policy(p, where) {
  closed(p, where, ['id', 'version', 'digest']);
  text255(p.id, `${where}.id`); text255(p.version, `${where}.version`); digest(p.digest, `${where}.digest`);
}

function evidenceRef(e, where) {
  closed(e, where, ['profile', 'media_type', 'digest'], ['resolver']);
  text255(e.profile, `${where}.profile`); text255(e.media_type, `${where}.media_type`); digest(e.digest, `${where}.digest`);
  if ('resolver' in e && e.resolver !== null) text255(e.resolver, `${where}.resolver`);
}

function component(c, where) {
  closed(c, where, ['component_id', 'component_type', 'profile', 'authority', 'instance', 'status', 'appraised_at', 'fresh_until', 'evidence_refs', 'reasons'], ['observed_digest', 'appraisal']);
  // Delegated appraisal: unpadded base64url text, 1 to 16384 characters, never null.
  if ('appraisal' in c) {
    str(c.appraisal, `${where}.appraisal`);
    if (c.appraisal.length < 1 || c.appraisal.length > 16384 || !B64U_RE.test(c.appraisal)) bad(`${where}.appraisal`);
  }
  id(c.component_id, `${where}.component_id`);
  oneOf(c.component_type, COMPONENT_TYPES, `${where}.component_type`);
  text255(c.profile, `${where}.profile`); text255(c.authority, `${where}.authority`);
  id(c.instance, `${where}.instance`);
  oneOf(c.status, STATUSES, `${where}.status`);
  int(c.appraised_at, `${where}.appraised_at`); int(c.fresh_until, `${where}.fresh_until`);
  arr(c.evidence_refs, `${where}.evidence_refs`, 16);
  c.evidence_refs.forEach((e, i) => evidenceRef(e, `${where}.evidence_refs[${i}]`));
  if ('observed_digest' in c && c.observed_digest !== null) digest(c.observed_digest, `${where}.observed_digest`);
  arr(c.reasons, `${where}.reasons`, 16);
  c.reasons.forEach((r, i) => id(r, `${where}.reasons[${i}]`));
}

function binding(b, where) {
  closed(b, where, ['source', 'target', 'relationship', 'method', 'status', 'digest', 'fresh_until']);
  id(b.source, `${where}.source`); id(b.target, `${where}.target`);
  konst(b.relationship, 'same-workload', `${where}.relationship`);
  oneOf(b.method, BINDING_METHODS, `${where}.method`);
  oneOf(b.status, STATUSES, `${where}.status`);
  digest(b.digest, `${where}.digest`);
  int(b.fresh_until, `${where}.fresh_until`);
}

export function validateToken(t) {
  closed(t, 'token', ['profile', 'iss', 'sub', 'instance', 'iat', 'exp', 'jti', 'aud', 'cnf', 'manifest', 'verification_context_hash', 'appraisal_policy', 'components', 'bindings', 'composite_appraisal']);
  konst(t.profile, TOKEN_PROFILE, 'profile');
  text255(t.iss, 'iss'); id(t.sub, 'sub'); id(t.instance, 'instance');
  int(t.iat, 'iat'); int(t.exp, 'exp'); id(t.jti, 'jti'); id(t.aud, 'aud');
  closed(t.cnf, 'cnf', ['kty', 'crv', 'x']);
  konst(t.cnf.kty, 'OKP', 'cnf.kty'); konst(t.cnf.crv, 'Ed25519', 'cnf.crv');
  str(t.cnf.x, 'cnf.x'); if (!B64U43_RE.test(t.cnf.x)) bad('cnf.x pattern');
  closed(t.manifest, 'manifest', ['id', 'media_type', 'version', 'digest']);
  text255(t.manifest.id, 'manifest.id');
  konst(t.manifest.media_type, 'application/agent-manifest+cose', 'manifest.media_type');
  konst(t.manifest.version, '0.2', 'manifest.version');
  digest(t.manifest.digest, 'manifest.digest');
  digest(t.verification_context_hash, 'verification_context_hash');
  policy(t.appraisal_policy, 'appraisal_policy');
  arr(t.components, 'components', 64);
  t.components.forEach((c, i) => component(c, `components[${i}]`));
  arr(t.bindings, 'bindings', 128);
  t.bindings.forEach((b, i) => binding(b, `bindings[${i}]`));
  const ca = t.composite_appraisal;
  closed(ca, 'composite_appraisal', ['status', 'required_components', 'policy', 'fresh_until']);
  oneOf(ca.status, STATUSES, 'composite_appraisal.status');
  arr(ca.required_components, 'composite_appraisal.required_components', 64);
  ca.required_components.forEach((r, i) => id(r, `composite_appraisal.required_components[${i}]`));
  policy(ca.policy, 'composite_appraisal.policy');
  int(ca.fresh_until, 'composite_appraisal.fresh_until');
}

// Closed component-appraisal payload: {profile, iss, component}.
export function validateAppraisal(p) {
  closed(p, 'appraisal', ['profile', 'iss', 'component']);
  konst(p.profile, APPRAISAL_PROFILE, 'appraisal.profile');
  text255(p.iss, 'appraisal.iss');
  component(p.component, 'appraisal.component');
}

export function validateProof(p) {
  closed(p, 'proof', ['profile', 'nonce', 'token_digest', 'token_id', 'audience', 'session_id', 'action_digest', 'issued_at', 'expires_at']);
  konst(p.profile, PROOF_PROFILE, 'profile');
  str(p.nonce, 'nonce'); if (!B64U43_RE.test(p.nonce)) bad('nonce pattern');
  digest(p.token_digest, 'token_digest'); id(p.token_id, 'token_id'); id(p.audience, 'audience');
  id(p.session_id, 'session_id'); digest(p.action_digest, 'action_digest');
  int(p.issued_at, 'issued_at'); int(p.expires_at, 'expires_at');
}
