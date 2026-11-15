# TR-ANC: Transparency

Checks whether the record was entered in the log entry its signed `transparency` value names. TR-ANC-001 checks URI shape. TR-ANC-002 compares the resolved entry's canonical identity and proves inclusion; a Level 2 pass additionally requires the caller to authenticate the entry source independently. Both apply from Level 2.

??? info "Technical detail: what the receipt proof covers"
    The log follows SCITT, the IETF format for transparency services. The receipt carries an
    inclusion proof (a short list of hashes linking the record to a Merkle root, the single
    hash that commits to the whole log). The receipt's `merkle_root` and `leaf_count` must
    equal those of the resolved registry entry (one line in the shape of Anchor Format §4),
    and the proof is then replayed against that root. `--entry-dir` supplies an
    `entries.json` map from each exact signed URI to a local snapshot. The map alone
    cannot establish that the named log published it; the command-line interface
    reports a matching entry and proof as unverified. The library API can record
    a pass only when its caller separately authenticates the resolver's source,
    as [Known limitations](../../LIMITATIONS.md) explains.

## Required at Level 2+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-ANC-001 | `transparency` is an `https://` URI with a host. Not resolved | `https://transparency.example/entries/abc123` | missing field, empty string, non-string, `http://`, bare path, `ipfs://` |
| TR-ANC-002 | The exact signed `transparency` URI resolves to an independently authenticated entry whose canonical `log_id`/`entry_id` URI matches byte for byte; the record's inclusion proof (`leaf_index` and `audit_path`) then replays to that entry's `merkle_root` and `leaf_count` from the complete signed claim, signature included (Anchor Format §§1, 4, and 6; for `cmcp-runtime` that is the whole envelope, not the nested `trace`). Offline, no network | a caller-authenticated resolver for the named entry and a receipt whose `audit_path` reproduces that entry's `merkle_root` | unresolved URI, unauthenticated local map, presenter-supplied entry only, identity from another log or checkpoint, malformed entry, mismatched root/count, malformed proof, proof for a different record, or modified signed claim |
