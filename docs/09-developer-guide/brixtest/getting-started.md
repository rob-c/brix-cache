# Getting started

From the standalone `BriXTest` directory:

```console
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

Run the public API example and framework contract tests:

```console
pytest tests/test_pythonic_case.py -v
pytest tests -v
```

Managed tests are ordinary pytest items decorated with `@case`. Install-time
pytest entry-point discovery loads BriXTest automatically; source-tree runs may
load it explicitly with `-p brixtest.pytest_plugin`.

Run any suite and choose a backend without changing the test:

```console
pytest tests/ --brixtest-backend=local
pytest tests/ --brixtest-backend=kubernetes
```

For a reproducible local Kubernetes target, use the dedicated Docker-backed
Minikube profile:

```console
brixtest minikube start
brixtest --json minikube status
pytest tests/ --brixtest-backend=minikube
```

The local backend needs loopback socket and child-process access. A restricted
sandbox that denies either capability cannot run the live server tests.

The CLI is intentionally pytest-shaped:

```console
brixtest run tests/test_transfer.py -vv
brixtest design tests/test_transfer.py
brixtest summary list
brixtest --json summary latest
```

Every case receives a unique run directory. Set `BRIXTEST_RUNS` or pass
`--brixtest-runs PATH` to choose its parent directory. Failed and timed-out
runs are retained by default for inspection.
