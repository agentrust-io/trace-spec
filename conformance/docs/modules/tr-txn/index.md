# TR-TXN: Transcript

Checks the record's summary of the tool calls the agent made: a fingerprint of the full call log and the number of calls. These checks apply from Level 2. They check that the fields are well formed; the suite does not have the log itself to compare against.

## Required at Level 2+

| Test ID    | Description                                            | Positive Case                      | Negative Case                       |
| ---------- | ------------------------------------------------------ | ---------------------------------- | ----------------------------------- |
| TR-TXN-001 | `tool_transcript.hash` is a valid `sha256:` digest     | `sha256:` followed by 64 hex chars | missing, wrong prefix, wrong length |
| TR-TXN-002 | `tool_transcript.call_count` is a non-negative integer | `0`, `1`, `42`                     | `-1`, `"three"`, absent             |
