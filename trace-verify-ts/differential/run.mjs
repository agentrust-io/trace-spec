// Run the differential corpus through this implementation and record verdicts.
//
// The verdict shape is the one `oracle.py` writes, so `compare.py` reads two
// files of the same kind. Each case is parsed here with this runtime's own JSON
// parser, from the same text the Python side parses with its own: where the two
// parsers differ, that is a difference the corpus is meant to surface.
//
//   node differential/run.mjs [--cases build/cases.json] [--out build/typescript.jsonl]

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  jwkThumbprint,
  parentRecordHash,
  TraceVerificationError,
  verifyRecord,
} from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function argument(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function scrub(evidence) {
  return Object.fromEntries(Object.entries(evidence).filter(([name]) => name !== "error" && name !== "key"));
}

function rejection(error) {
  if (error instanceof TraceVerificationError) {
    const out = { verdict: "rejected", code: error.code };
    if (error.code === "schema_invalid") {
      out.path = error.path ?? null;
    }
    return out;
  }
  return { verdict: "rejected", code: "unclassified", detail: `${error?.name}: ${error?.message}` };
}

function store(spec) {
  if (spec === undefined || spec === null) {
    return undefined;
  }
  if (spec.kind === "list") {
    return spec.ids;
  }
  if (spec.kind === "raises") {
    return () => {
      throw new Error("the revocation source is unreachable");
    };
  }
  if (spec.kind === "non_bool") {
    return () => undefined;
  }
  throw new Error(`unknown revocation store kind ${spec.kind}`);
}

async function runVerify(item) {
  const options = item.options;
  let record;
  try {
    record = JSON.parse(item.record_json);
  } catch (error) {
    return { verdict: "parse_error", detail: String(error?.message) };
  }
  const settings = {
    trustedKey: options.trusted_key,
    allowEmbeddedKey: options.allow_embedded_key ?? false,
    now: options.now,
    maxFutureSkewSeconds: options.max_future_skew_seconds ?? 300,
    maxBundleAgeSeconds: options.max_bundle_age_seconds ?? 86400,
    expectedNonce: options.expected_nonce ?? undefined,
    revocation: store(options.revocation),
    trustedBundleKeys: options.trusted_bundle_keys ?? [],
  };
  if (Object.hasOwn(options, "max_age_seconds")) {
    settings.maxAgeSeconds = options.max_age_seconds;
  }
  if (options.revocation_bundle_json !== undefined && options.revocation_bundle_json !== null) {
    try {
      settings.revocationBundle = JSON.parse(options.revocation_bundle_json);
    } catch (error) {
      return { verdict: "parse_error", detail: `bundle: ${String(error?.message)}` };
    }
  }
  try {
    const result = await verifyRecord(record, settings);
    return {
      verdict: "verified",
      thumbprint: result.trustedKeyThumbprint,
      revocation: {
        outcome: result.revocation.outcome,
        cause: result.revocation.cause,
        evidence: scrub(result.revocation.evidence),
      },
    };
  } catch (error) {
    return rejection(error);
  }
}

async function runJcs(item) {
  let value;
  try {
    value = JSON.parse(item.value_json);
  } catch (error) {
    return { verdict: "parse_error", detail: String(error?.message) };
  }
  try {
    return { verdict: "canonical", bytes: canonicalJson(value) };
  } catch (error) {
    return rejection(error);
  }
}

async function runThumbprint(item) {
  let value;
  try {
    value = JSON.parse(item.value_json);
  } catch (error) {
    return { verdict: "parse_error", detail: String(error?.message) };
  }
  try {
    return { verdict: "thumbprint", value: await jwkThumbprint(value) };
  } catch (error) {
    return rejection(error);
  }
}

async function runChainDigest(item) {
  let value;
  try {
    value = JSON.parse(item.value_json);
  } catch (error) {
    return { verdict: "parse_error", detail: String(error?.message) };
  }
  try {
    return { verdict: "digest", value: await parentRecordHash(value, item.algorithm) };
  } catch (error) {
    return rejection(error);
  }
}

const RUNNERS = {
  verify: runVerify,
  jcs: runJcs,
  thumbprint: runThumbprint,
  chain_digest: runChainDigest,
};

const casesPath = argument("cases", join(HERE, "build", "cases.json"));
const outPath = argument("out", join(HERE, "build", "typescript.jsonl"));
const corpus = JSON.parse(readFileSync(casesPath, "utf8"));
const lines = [];
for (const item of corpus.cases) {
  const verdict = await RUNNERS[item.kind](item);
  lines.push(JSON.stringify({ id: item.id, group: item.group, ...verdict }));
}
writeFileSync(outPath, `${lines.join("\n")}\n`, "utf8");
console.log(`${corpus.cases.length} verdicts written to ${outPath}`);
