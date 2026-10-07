// A verification failure carrying exactly one reason code from
// examples/verifier-token-conformance/codes.json.
export class VerifyError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

export function fail(code, detail) {
  throw new VerifyError(code, detail);
}
