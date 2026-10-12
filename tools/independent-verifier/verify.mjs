#!/usr/bin/env node
// Usage: node verify.mjs VECTOR.json [VECTOR.json ...]
// Prints one JSON line per vector:
//   {"id", "token": "valid"|code, "composite_status": status|null, "proof": null|"valid"|code}

import fs from 'node:fs';
import path from 'node:path';
import { VerifyError } from './errors.mjs';
import { makeContext, verifyToken, verifyProof } from './verifier.mjs';

function code(e) {
  // Anything that is not a classified rejection is a malformed direct input.
  return e instanceof VerifyError ? e.code : 'input_invalid';
}

// Legacy vectors (examples/verifier-token-profile) carry only the envelope,
// except 01-valid.json, which supplies the context for the whole set.
const legacyBaseCache = new Map();
function legacyContext(file, vec) {
  const base = path.join(path.dirname(file), '01-valid.json');
  let b = legacyBaseCache.get(base);
  if (!b) { b = JSON.parse(fs.readFileSync(base, 'utf8')); legacyBaseCache.set(base, b); }
  const t = b.token;
  const now = vec.now ?? b.now;
  return {
    now,
    context: {
      audience: t.aud,
      subject: t.sub,
      instance: t.instance,
      manifest_b64: vec.manifest_b64 ?? b.manifest_b64,
      manifest_id: t.manifest.id,
      manifest_valid_until: b.now + 300,
      question_digest: t.verification_context_hash,
      policy: t.appraisal_policy,
      requirements: vec.requirements ?? b.requirements,
      trusted_issuers: [{
        issuer: t.iss,
        public_b64url: (vec.issuer_public_b64 ?? b.issuer_public_b64).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
        valid_from: b.now - 1,
        valid_until: b.now + 300,
      }],
      status: 'active',
      maximum_lifetime: 300,
    },
    proof: null,
  };
}

export function runVector(file) {
  const vec = JSON.parse(fs.readFileSync(file, 'utf8'));
  const id = vec.id ?? path.basename(file, '.json');
  const out = { id, token: null, composite_status: null, proof: null };
  let setup;
  try {
    setup = vec.context ? { now: vec.now, context: vec.context, proof: vec.proof ?? null } : legacyContext(file, vec);
  } catch (e) {
    out.token = code(e);
    return out;
  }
  let verified;
  try {
    const ctx = makeContext(setup.context);
    const envelope = new Uint8Array(Buffer.from(vec.envelope_b64, 'base64'));
    verified = verifyToken(envelope, ctx, setup.now);
    out.token = 'valid';
    out.composite_status = verified.composite_status;
    if (setup.proof) {
      try {
        out.proof = verifyProof(verified, setup.proof, ctx, setup.now);
      } catch (e) {
        out.proof = code(e);
      }
    }
  } catch (e) {
    out.token = code(e);
  }
  return out;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
if (isMain) {
  const files = process.argv.slice(2);
  if (!files.length) {
    process.stderr.write('usage: node verify.mjs VECTOR.json [...]\n');
    process.exit(2);
  }
  for (const f of files) process.stdout.write(JSON.stringify(runVector(f)) + '\n');
}
