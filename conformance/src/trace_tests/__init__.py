"""TRACE conformance test suite."""

from importlib.metadata import PackageNotFoundError, version

# Read the version from installed distribution metadata rather than restating it
# here. `pyproject.toml` is what the build and PyPI publish, so a second literal
# in this file is a copy that can fall behind silently: it sat at "0.2.0" through
# both the 0.3.0 and 0.4.0 releases, so `trace-tests --version` reported 0.2.0
# from a 0.4.0 install. That is worse than cosmetic, because the v0.2 profile
# cutover landed in 0.4.0 and `--version` is the command someone runs to find out
# whether they have a suite that accepts v0.2 records.
try:
    __version__ = version("agentrust-trace-tests")
except PackageNotFoundError:  # pragma: no cover - source tree with no install
    # Importable without being installed (e.g. PYTHONPATH against a checkout).
    # There is no metadata to read here, and guessing a number would reintroduce
    # the drift this exists to prevent.
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
