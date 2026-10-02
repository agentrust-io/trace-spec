# TR-TXN — Transcript

Tests tool-call transcript binding.

## Required at Level 2+

| Test ID | Description | Positive Case | Negative Case |
|---------|-------------|---------------|---------------|
| TR-TXN-001 | `tool_transcript.hash` is a valid `sha256:` digest | `sha256:` followed by 64 hex chars | missing, wrong prefix, wrong length |
| TR-TXN-002 | `tool_transcript.call_count` is a non-negative integer | `0`, `1`, `42` | `-1`, `"three"`, absent |
