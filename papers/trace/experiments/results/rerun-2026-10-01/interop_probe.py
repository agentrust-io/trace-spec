"""Probe: does a record signed by agentrust-trace verify under trace-tests TR-SIG at the same pins?"""
import json, time
from agentrust_trace.sign import generate_key, sign_record, verify_record
from trace_tests.runner import run

def base(subject, extra=None):
    r = {"eat_profile": "tag:agentrust.io,2026:trace-v0.1", "iat": int(time.time()),
         "subject": subject,
         "runtime": {"platform": "software-only", "measurement": "sha256:" + "0"*64},
         "policy": {"bundle_hash": "sha256:" + "1"*64, "enforcement_mode": "enforce"},
         "data_class": "public"}
    if extra: r.update(extra)
    return r

out = {}
k = generate_key(); pub = k.public_key()
for label, rec in [("ascii", base("spiffe://example.org/agent")),
                   ("non_ascii_subject", base("spiffe://example.org/agent/caf\u00e9")),
                   ("float_value", base("spiffe://example.org/agent", {"x_score": 1e21}))]:
    s = sign_record(rec, k)
    sdk_ok = True
    try: verify_record(s, pub, max_age_seconds=None)
    except Exception as e: sdk_ok = f"error: {e}"
    res = run(s, "trace", 0, max_age_seconds=86400)
    sig = [ (f.rule if hasattr(f,'rule') else f.code, f.status.value) for m, fs in res.items() for f in fs if (getattr(f,'rule',None) or getattr(f,'code','')).startswith("TR-SIG-005")]
    out[label] = {"sdk_verify": sdk_ok, "trace_tests_TR_SIG_005": sig}
print(json.dumps(out, indent=2))
