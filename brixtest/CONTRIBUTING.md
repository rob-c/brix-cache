# Contributing to BriXTest

BriXTest is developed and tested as a standalone pytest plugin. Changes must
not import code, tests, or configuration from outside this directory.

Create an isolated environment, install the project, and run its contract
suite:

```console
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[dev]'
pytest
```

Public API changes must update `_api.py`, the API reference, examples, and the
compatibility contract in the same change. Runtime extension changes require a
black-box conformance case. Every boundary change needs a successful case, an
operational-error case, and a security-negative case.

Use shell-free argv throughout. Keep secrets out of reports, process arguments,
and exported replay records. Do not weaken helper-process isolation to support
a plugin; trusted pytest integrations must be explicitly selected for helpers.

Use `tox` to validate the built wheel against the supported Python/pytest
matrix. Set `BRIXTEST_MINIKUBE=1` only in an environment where the dedicated
Minikube profile may create and delete BriXTest-owned namespaces.

The quality contract scans all Python source, tests, examples, compatibility
tests, and tools. Functions are limited to CCN 10, cognitive complexity 25,
NPath 512, Halstead effort 3000, and lexical control-flow nesting depth 5;
files must remain below 500 lines. Run it directly with:

```console
pytest tests/test_code_quality.py -q --no-brixtest-fail-fast
```
