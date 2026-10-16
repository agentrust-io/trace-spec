#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# Third-party dependencies come from the same hash-pinned lock CI uses; the
# suite itself then goes in with --no-deps and is installed rather than put on
# the path, so the targets exercise the import surface a consumer gets.

cd "$SRC/trace-spec/conformance"
pip3 install --no-cache-dir --require-hashes -r requirements/test.txt
pip3 install --no-cache-dir --no-deps .

PYI_ARGS=(
  # Lazy stdlib import from the cryptography stack; without it the bundled
  # target dies with "No module named 'email.mime'" and libFuzzer reports that
  # as a crash in the target.
  --collect-submodules=email
  # accounting.py hashes the checker modules' own .py source at import time to
  # bind each obligation to the code that decides it. PyInstaller bundles
  # bytecode, not source, so the .py files are added as data at the path
  # accounting.py reads them from.
  --add-data="$SRC/trace-spec/conformance/src/trace_tests/modules:trace_tests/modules"
)

for target in "$SRC"/trace-spec/conformance/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
