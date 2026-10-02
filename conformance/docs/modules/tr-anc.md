# TR-ANC — Transparency

Tests transparency anchoring via SCITT.

## Required at Level 2+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-ANC-001 | `transparency` is an `https://` URI with a host. Not resolved | `https://transparency.example/entries/abc123` | missing field, empty string, non-string, `http://`, bare path, `ipfs://` |
| TR-ANC-002 | The record's inclusion proof replays to the committed `merkle_root`, per RFC 9162 over an RFC 6962 tree. Offline, no network | a receipt whose `audit_path` reproduces `merkle_root` from the record's leaf | no receipt supplied, missing `leaf_index`/`audit_path`/`leaf_count`/`merkle_root`, non-hex audit node, out-of-range `leaf_index`, proof for a different record, record modified after anchoring |
