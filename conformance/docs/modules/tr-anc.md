# TR-ANC: Transparency

Checks that the record was entered in a public, append-only log, so it cannot be quietly replaced later. TR-ANC-001 checks the link to the log entry. TR-ANC-002 uses a receipt and the registry entry you supply to prove, offline, that this exact record is in that entry. Both apply from Level 2.

??? info "Technical detail: what the receipt proof covers"
    The log follows SCITT, the IETF format for transparency services. The receipt carries an
    inclusion proof (a short list of hashes linking the record to a Merkle root, the single
    hash that commits to the whole log). The receipt's `merkle_root` and `leaf_count` must
    equal those of the registry entry you pass with `--entry` (one line in the shape of
    Anchor Format §4), and the proof is then replayed against that root. Nothing yet
    identifies an entry from the `transparency` URI, so the check does not establish that
    the entry is the one the record names, and the pass message says so (trace-spec#448
    finding 21). Whether a public log really published the entry is also outside this
    module, as [Known limitations](../../LIMITATIONS.md) explains.

## Required at Level 2+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-ANC-001 | `transparency` is an `https://` URI with a host. Not resolved | `https://transparency.example/entries/abc123` | missing field, empty string, non-string, `http://`, bare path, `ipfs://` |
| TR-ANC-002 | The receipt's `merkle_root` and `leaf_count` equal the supplied registry entry's, the entry's `ts` is an ISO-8601 UTC timestamp ending in `Z`, and the inclusion proof replays to that `merkle_root` from the leaf of the complete signed claim, signature included (Anchor Format §1; for `cmcp-runtime` that is the whole envelope, not the nested `trace`), per RFC 9162 over an RFC 6962 tree. Offline, no network. The link from the `transparency` URI to the entry is not checked | a receipt whose `audit_path` reproduces `merkle_root` from the record's leaf, with the entry sealed alongside it | no receipt supplied, no entry supplied, malformed entry or `ts`, receipt `merkle_root` or `leaf_count` differing from the entry's, missing `leaf_index`/`audit_path`/`leaf_count`/`merkle_root`, non-hex audit node, out-of-range `leaf_index`, proof for a different record, record modified after anchoring, a `cmcp-runtime` proof over the nested `trace` only, an envelope re-signed or with a changed signature after anchoring |
