// Generates REAL Acta decision-receipt fixtures (Ed25519 over JCS canonical
// bytes, same envelope shape protect-mcp/@veritasacta ship) for the TRACE
// action-receipts crosswalk. Every "invalid" fixture is produced by actually
// breaking a valid one and re-verified to fail for the stated reason, not
// hand-typed.
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { writeFileSync, mkdirSync } from 'node:fs';

const bytesToHex = (b) => Buffer.from(b).toString('hex');
const hexToBytes = (h) => new Uint8Array(Buffer.from(h, 'hex'));

// Minimal JCS (RFC 8785): sort object keys recursively, compact separators.
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}
function canonicalBytes(obj) { return new TextEncoder().encode(canonicalize(obj)); }
function sha256hex(bytes) { return bytesToHex(sha256(bytes)); }

function sign(payloadObj, privKeyHex) {
  const priv = hexToBytes(privKeyHex);
  const pub = ed25519.getPublicKey(priv);
  const digest = canonicalBytes(payloadObj);
  const sig = ed25519.sign(digest, priv);
  return { publicKeyHex: bytesToHex(pub), signatureHex: bytesToHex(sig), digestHex: sha256hex(digest) };
}

// --- Fixed demo keypair (deterministic, published as the fixture signer) ---
const PRIV = '4c9c9f6a5b2e7d3f1a8b6c4d2e9f7a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e1f';
const pub = ed25519.getPublicKey(hexToBytes(PRIV));
const PUB_HEX = bytesToHex(pub);

const ISSUER = 'did:web:legate.scopeblind.com';
const KID = 'acta-demo-2026q3';

// Real digests over actual (illustrative) policy bundle bytes, not placeholders.
const POLICY_V1_DIGEST = `sha256:${sha256hex(canonicalBytes({ policy: 'permit read-only; forbid destructive', rev: 1 }))}`;
const POLICY_V2_DIGEST = `sha256:${sha256hex(canonicalBytes({ policy: 'permit read-only; forbid destructive; forbid network-egress', rev: 2 }))}`;

function makeReceipt({ callId, sessionId, tool, decision, reasonCode, issuedAt, prevHash, policyDigest }) {
  const payload = {
    tool,
    decision,
    reason_code: reasonCode,
    policy_digest: policyDigest,
    scope: callId,
    session_id: sessionId,
    request_id: callId,
    spec: 'draft-farley-acta-signed-receipts-02',
    parent_receipt_hash: prevHash,
  };
  const env = {
    v: 2,
    type: 'decision_receipt',
    algorithm: 'ed25519',
    kid: KID,
    issuer: ISSUER,
    issued_at: issuedAt,
    payload,
  };
  const { signatureHex, digestHex } = sign(payload, PRIV);
  env.signature = signatureHex;
  return { env, digestHex };
}

function verify(env, pubHex) {
  try {
    const { signature, ...unsigned } = env;
    const digest = canonicalBytes(unsigned.payload);
    const ok = ed25519.verify(hexToBytes(signature), digest, hexToBytes(pubHex));
    return ok;
  } catch (e) { return false; }
}

mkdirSync('out', { recursive: true });
const results = {};

// 1. Valid accepted (allow)
const r1 = makeReceipt({
  callId: 'call-7f31', sessionId: 'trace-session-2026-07-08T09:00:00Z', tool: 'run_shell',
  decision: 'allow', reasonCode: 'policy_permit', issuedAt: '2026-07-08T09:00:01.000Z',
  prevHash: null, policyDigest: POLICY_V1_DIGEST,
});
results['01-valid-accepted.json'] = r1.env;
console.log('01 valid, expect true ->', verify(r1.env, PUB_HEX));

// 2. Valid denied (Acta's differentiator: denials verify too, not just allows)
const r2 = makeReceipt({
  callId: 'call-7f32', sessionId: 'trace-session-2026-07-08T09:00:00Z', tool: 'delete_database',
  decision: 'deny', reasonCode: 'policy_forbid:destructive_action', issuedAt: '2026-07-08T09:00:05.000Z',
  prevHash: `sha256:${sha256hex(canonicalBytes(r1.env.payload))}`, policyDigest: POLICY_V1_DIGEST,
});
results['02-valid-denied.json'] = r2.env;
console.log('02 valid denial, expect true ->', verify(r2.env, PUB_HEX));

// 3. Signature/key mismatch: verify against a DIFFERENT real keypair
const otherPriv = bytesToHex(ed25519.utils.randomSecretKey());
const otherPub = bytesToHex(ed25519.getPublicKey(hexToBytes(otherPriv)));
results['03-signature-key-mismatch.json'] = r1.env; // same envelope, wrong key on verify
console.log('03 wrong key, expect false ->', verify(r1.env, otherPub));

// 4. Broken chain: tamper parent_receipt_hash after signing (invalidates signature)
const r4tampered = JSON.parse(JSON.stringify(r2.env));
r4tampered.payload.parent_receipt_hash = `sha256:${'0'.repeat(64)}`; // tampered: does not match r1's real hash
results['04-broken-chain.json'] = r4tampered;
console.log('04 broken chain (tampered payload, stale sig), expect false ->', verify(r4tampered, PUB_HEX));

// 5. Stale policy_digest: policy changed after signing; signature is still valid,
// so this is NOT a signature-verification failure -- it fails a freshness check
// a verifier must run separately (policy_digest != current bundle digest).
results['05-stale-policy-digest.json'] = r1.env;
const CURRENT_POLICY_DIGEST = POLICY_V2_DIGEST; // policy rotated (real digest) after r1 was issued
console.log('05 stale policy_digest, signature still valid ->', verify(r1.env, PUB_HEX),
  '| digest matches current policy? ->', r1.env.payload.policy_digest === CURRENT_POLICY_DIGEST);

// 6. Mismatched session/call binding: a validly signed receipt whose
// session_id belongs to a DIFFERENT session than the one it is presented
// under. Like 05, this passes signature verification (the receipt is not
// forged or tampered); it fails the binding check a verifier runs against
// the session/call identifiers the surrounding TRACE/cMCP layer assigned.
const r6 = makeReceipt({
  callId: 'call-9a10', sessionId: 'trace-session-2026-07-07T14:30:00Z', tool: 'run_shell',
  decision: 'allow', reasonCode: 'policy_permit', issuedAt: '2026-07-07T14:30:02.000Z',
  prevHash: null, policyDigest: POLICY_V1_DIGEST,
});
results['06-session-binding-mismatch.json'] = r6.env;
const EXPECTED_SESSION = 'trace-session-2026-07-08T09:00:00Z'; // the session 01/02 belong to
console.log('06 session mismatch, signature still valid ->', verify(r6.env, PUB_HEX),
  '| session binding matches? ->', r6.env.payload.session_id === EXPECTED_SESSION);

// Chain head over the fixture chain (01 -> 02), for the Trust Record
// reference example in the crosswalk doc: same digest construction the
// chain links themselves use (SHA-256 over the JCS bytes of the payload).
const CHAIN_HEAD = `sha256:${sha256hex(canonicalBytes(r2.env.payload))}`;
console.log('chain head (02):', CHAIN_HEAD);

for (const [name, obj] of Object.entries(results)) {
  writeFileSync(`out/${name}`, JSON.stringify(obj, null, 2) + '\n');
}
writeFileSync('out/signer-public-key.txt', PUB_HEX + '\n');
console.log('\nwrote', Object.keys(results).length, 'fixtures + public key to out/');
