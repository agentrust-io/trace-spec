# TR-SCA — Provenance

Tests SLSA build provenance.

## Required at Level 1+

| Test ID    | Description                                           | Positive Case                      | Negative Case                       |
| ---------- | ----------------------------------------------------- | ---------------------------------- | ----------------------------------- |
| TR-SCA-001 | `build_provenance.slsa_level` is 0–3                  | `0`, `1`, `2`, `3`                 | `4`, `5`, `-1`, `"high"`, absent    |
| TR-SCA-002 | `build_provenance.digest` is a valid `sha256:` digest | `sha256:` followed by 64 hex chars | missing, wrong prefix, wrong length |
