# TR-ANC: Transparency

Checks that the record was entered in a public, append-only log, so it cannot be quietly replaced later. TR-ANC-001 checks the link to the log entry. TR-ANC-002 uses a receipt you supply to prove, offline, that this exact record is in the log the receipt describes. Both apply from Level 2.

Technical detail: what the receipt proof covers

The log follows SCITT, the IETF format for transparency services. The receipt carries an inclusion proof (a short list of hashes linking the record to a Merkle root, the single hash that commits to the whole log). The proof is checked against the root in that receipt; whether a public log really published that root is outside this module, as [Known limitations](https://trace.agentrust-io.com/conformance/LIMITATIONS/index.md) explains.

## Required at Level 2+

| Test ID    | Description                                                                                                                  | Positive Case                                                                | Negative Case                                                                                                                                                                                   |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TR-ANC-001 | `transparency` is an `https://` URI with a host. Not resolved                                                                | `https://transparency.example/entries/abc123`                                | missing field, empty string, non-string, `http://`, bare path, `ipfs://`                                                                                                                        |
| TR-ANC-002 | The record's inclusion proof replays to the committed `merkle_root`, per RFC 9162 over an RFC 6962 tree. Offline, no network | a receipt whose `audit_path` reproduces `merkle_root` from the record's leaf | no receipt supplied, missing `leaf_index`/`audit_path`/`leaf_count`/`merkle_root`, non-hex audit node, out-of-range `leaf_index`, proof for a different record, record modified after anchoring |
