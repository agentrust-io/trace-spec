# Privacy

The TRACE SDK processes the records, keys, and evidence supplied by the calling application. Records can contain identifiers, artifact locations, or other sensitive metadata chosen by the producer; review those fields before sharing them.

Core signing and signature verification run locally. The SDK does not send project telemetry or analytics. Application-provided callbacks, evidence retrieval, and registry submission can involve network services chosen by that application; their handling of data is separate from the local signature operation.

Uninstalling the package does not delete generated records, exported keys, logs, caches, backups, or records already shared with a registry or recipient. Manage those artifacts through your application's retention and deletion procedures.

[Report a correction](https://github.com/agentrust-io/trace-spec/issues).
