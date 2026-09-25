#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# Third-party dependencies come from the same hash-pinned lock CI uses, and the
# package then goes in with --no-deps, so the targets run against the versions
# the test suite runs against rather than whatever resolves on the day.

cd "$SRC/trace-spec"
pip3 install --no-cache-dir --require-hashes -r requirements/dev.txt
pip3 install --no-cache-dir --no-deps .

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only. The cryptography and pydantic stacks reach email.mime
# lazily, so without this the bundled target dies at runtime with
# "ModuleNotFoundError: No module named 'email.mime'" and libFuzzer reports it
# as a crash in the target. The package schemas are data files PyInstaller does
# not see through importlib.resources, and neither are the metaschemas jsonschema
# loads the same way, so both are collected explicitly.
PYI_ARGS=(
  --collect-submodules=email
  --collect-data=agentrust_trace
  --collect-data=jsonschema_specifications
)

for target in "$SRC"/trace-spec/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done

# Seed corpora: the committed example records and bundles, plus one valid input
# per target built with the library itself, so the fuzzer starts past the
# schema instead of spending its budget discovering JSON.
python3 .clusterfuzzlite/make_seeds.py "$OUT"
