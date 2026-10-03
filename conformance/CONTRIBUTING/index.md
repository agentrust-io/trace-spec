# Contributing

Thank you for your interest in contributing to the TRACE test suite.

## How to Contribute

1. Fork the repository and create a feature branch
1. Add or update conformance tests following the patterns in existing test files
1. Commit using [Conventional Commits](https://www.conventionalcommits.org)
1. Open a pull request against `main`

## Running tests locally

From the repository root, use Python 3.11 or later in a virtual environment:

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in PowerShell instead. To run the same subsets as CI, use `pytest -m "level0 or negative"` and `pytest tests/unit/`.

## Using AI to contribute

Use agents. A lot of this was built with them and saying otherwise would be dishonest.

The rule is that you have to understand what you submit. If you cannot explain what your change does and how it interacts with the rest of the system, with the agent closed, do not open the pull request. Reviewing a change nobody can explain costs more than writing it did, and it becomes someone else's problem the moment it merges.

That is a rule about understanding, not about tooling.

## Reporting Security Issues

Use [GitHub Security Advisories](https://github.com/agentrust-io/trace-tests/security/advisories/new) rather than public issues.

## Code of Conduct

See [CODE_OF_CONDUCT.md](https://trace.agentrust-io.com/conformance/CODE_OF_CONDUCT/index.md).
