# Privacy

The TRACE test suite reads the record and optional evidence you supply. CLI options can also load policy bundles, receipts, and related local files. Findings and exported reports may reproduce identifiers, artifact locations, and error details from those inputs; review reports before sharing them.

The CLI does not send project telemetry or analytics and does not fetch arbitrary record URLs. Its policy-directory resolver uses local files. Library callers can supply their own resolver callbacks, whose network and data handling behavior belongs to the calling application.

Uninstalling the package does not delete input records, evidence files, exported reports, badges, logs, or backups. Manage those artifacts through your application's retention and deletion procedures.

[Report a correction](https://github.com/agentrust-io/trace-tests/issues).
