# TRACE: Trust, Runtime Attestation, and Compliance Evidence (A Portable Attestation Format for AI Agent Runtime Governance)

Technical report, version 3, October 1, 2026. Not peer reviewed.
Version 3 corrects the identification of the evaluated SDK (trace-spec revision 523f8cc, whose
signing code is release 0.3.0), five bibliography entries and several conformance descriptions.
The recorded numbers are unchanged.

Build: `tectonic paper.tex` (prepared with Tectonic 0.16.9; set SOURCE_DATE_EPOCH=1790812800
to reproduce the published PDF byte for byte).

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/trace-spec.

This package contains the manuscript source, figures, the recorded experiment results and the
October 1, 2026 rerun in `experiments/results/rerun-2026-10-01/`, which identifies the revisions
the July 1 run measured and repeats the benchmark there and on current main. It is not an
independently replicated or fully pinned reproduction package.
Current implementation guidance: https://trace.agentrust-io.com/

Historical revisions: trace-spec 523f8cc and trace-tests 661c177 (identical to tag v0.2.0).
Set TRACE_VECTORS_DIR to that trace-tests checkout. Do not run against current vectors and label
the output a reproduction of the saved run.
