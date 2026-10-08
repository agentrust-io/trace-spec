# TR-SCA: Provenance

Checks the record's statement about how the agent's software was built: the SLSA level (a public scale, 0 to 3, for how trustworthy a build process is) and the digest of what was built. These checks apply from Level 1 and cover the format of the claim only.

## Required at Level 1+

| Test ID    | Description                                           | Positive Case                      | Negative Case                       |
| ---------- | ----------------------------------------------------- | ---------------------------------- | ----------------------------------- |
| TR-SCA-001 | `build_provenance.slsa_level` is 0 to 3               | `0`, `1`, `2`, `3`                 | `4`, `5`, `-1`, `"high"`, absent    |
| TR-SCA-002 | `build_provenance.digest` is a valid `sha256:` digest | `sha256:` followed by 64 hex chars | missing, wrong prefix, wrong length |
