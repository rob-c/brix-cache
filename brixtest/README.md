# BriXTest

BriXTest is a standalone, installable pytest extension for server/client tests.
A test declares its servers, clients, configs, captured binaries, and input
artifacts in Python. BriXTest materializes those resources in an isolated run,
then executes the entire test lifecycle in a supervised helper process.

```console
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
pytest
```

The public surface is intentionally regular: `Execution` describes how
something runs, `Server`, `Client`, and `Tool` describe who owns it, and `@case(...)`
infers the resource graph:

```python
from brixtest import (
    binary, case, docker, execution, load_template, noise, server,
    tcp, tool,
)

origin_binary = binary("origin", "/build/bin/origin")
origin = server(
    "origin",
    binary=origin_binary,
    args=["--config", "{config}"],
    config=load_template("configs/origin.json.in").fill(
        filename="origin.json", response_text="hello",
    ),
    ports=["http"],
    readiness=tcp("http"),
)

curl = tool("curl", execution=execution("curl", "--fail", origin.url("http")))


payload = noise("payload", size=100_000_000, seed=7)


@case(origin, curl, payload,
      isolation=docker("registry.example/brixtest@sha256:<digest>"))
def test_origin(run):
    with run.metrics.timer("download.latency"):
        result = run.tool(curl).run()
    run.metrics.gauge("download.bytes", len(result.stdout), unit="bytes")
    assert result.returncode == 0
    assert run.artifact("payload").size == 100_000_000
```

Native programs are first-class pytest items too. `native_test(...)` compiles
one declared C or C++ program, runs it in the normal supervised helper, checks
its exit code and text streams, and archives exact build provenance. See the
[native-test guide](docs/native-tests.md).

The same declaration can run locally or on Kubernetes; select the backend with
`--brixtest-backend` or `BRIXTEST_BACKEND`. Test code continues to consume the
same `run.server()`, `run.client()`, `run.artifact()`, and `run.binary()` API.
Enhanced evidence is equally backend-neutral: pytest records metrics, process
and cgroup resources, spans, logs, attachments, provenance, and deterministic
findings in a crash-recoverable, versioned model. Each session has searchable
HTML and JSON plus normalized SQLite, with optional Parquet/DuckDB, OTLP,
OpenSearch, and S3 export. See [the metrics guide](docs/metrics.md) and
[the evidence and analytics guide](docs/evidence-and-analytics.md).
The complete stable import and fixture surface is listed in the
[public API reference](docs/api-reference.md) and enforced by BriXTest's own
contract suite.

`run.tool(name)` always resolves a bound tool and `.run(...)` invokes it.
`run.execute(execution(...))` is the explicit reusable-execution path, while
`run.command(...)` remains the compact path for immediate argv. Lookup and
execution therefore remain unambiguous in IDEs and type checkers.

Use `brixtest api` to browse that supported contract, `brixtest api Run` to
inspect one symbol, or `brixtest api --json` for an immutable machine-readable
manifest suitable for editor integrations and compatibility checks. The
versioned schema includes constructors, readable attributes, methods,
properties, signatures, and the complete pytest integration surface.

Start a test from a checked, runnable skeleton with `brixtest new
tests/test_feature.py`. Add `--nginx` to generate an on-disk nginx template and
a live HTTP assertion as well.

Server topology is derived from the collected tests. The default
`scope="case"` gives every attempt a fresh server; class, module, package, and
session scopes fingerprint identical server graphs and share monitored
instances in their pytest-familiar domains, including across xdist workers.
Use `scope="worker"` only for intentional worker-local duplication. Each
attempt stores stable server-instance links, while
the shared physical log is archived once with its SHA-256. See
[the dynamic topology guide](docs/dynamic-topology.md).

Credentials and authentication infrastructure are declarations too. BriXTest
can generate role-scoped custom/checksum/signed credentials, bearer tokens, a
fresh TLS CA/CRL/host identity, a complete VOMS/GSI test PKI and proxy, and an
isolated MIT Kerberos realm with keytab and ticket cache. Declared host mappings
provide container/Kubernetes forward and reverse DNS without editing the host.
See [the authentication guide](docs/authentication.md).

Helper isolation is independent of server placement. Select `process`,
`nsenter`, Docker, Podman, runc, or a bundled Kubernetes Job in
`@case(isolation=...)`, or override the whole suite from the command line.
Container and Kubernetes runtime images are digest-pinned by default; remote
helpers retain normal pytest fixtures/reporting through a supervised framed
transport and content-addressed source/dependency bundle.

Tool placement is independently selectable with `Placement(backend=...)`.
Built-in executors cover local processes, digest-pinned Docker/Podman
containers, and Kubernetes Pods; packaged executors use the same versioned
contract. Kubernetes tools receive in-cluster service DNS, declared
credentials, mounts, limits, and structured output capture without changing
the test body.

Server placement is independently selectable per declaration too. Process,
Docker, and Podman launchers feed the same supervisor, so one local case may
mix native and containerized servers while keeping readiness, metrics, logs,
and teardown uniform. A running `Service` exposes bounded health, log-tail,
log-follow, signal, restart, wait, and in-environment command controls.

Docker-backed Minikube is the supported local Kubernetes target. It uses the
dedicated `brixtest` profile and an explicit kubectl context:

```console
brixtest minikube start
brixtest --json minikube status
brixtest minikube test
pytest tests --brixtest-backend=minikube
```

For an ASan or freshly linked nginx validation, declare the executable once as
`binary("nginx", ...)`, then replace it for an entire run without editing tests:

```console
brixtest run tests --brixtest-binary nginx=/build/asan/objs/nginx \
  --brixtest-sanitizer asan
```

The same complete-suite override can be retained as a JSON profile and replayed
with `pytest --brixtest-profile profiles/asan.json`; command-line values take
precedence over profile values.

The selected executable and its dynamic libraries are copied into each unique
run before any server starts, so a concurrent rebuild cannot replace the binary
mid-suite. Discovery follows transitive dependencies of the executable and
explicit dynamic modules; every captured library has its own retained SHA-256
and `run.binary(...).verify()` checks the complete snapshot. BriXTest stops on
the first failure by default and prints
`brixtest rerun <session>` for exact replay. Use `--no-brixtest-fail-fast` only
when a complete failure inventory is preferable.

## Layout

```text
brixtest/
├── configs/          reusable on-disk server configs and templates
├── compat_tests/     lower-level core compatibility tests
├── docs/             framework and author documentation
├── examples/         executable core and authentication API examples
├── k8s/minikube/     dedicated Docker-Minikube validation profile
├── src/brixtest/     standalone framework package
├── tests/            framework self-tests and executable examples
├── requirements.txt  bounded runtime requirements
├── tox.ini            installed-wheel Python/pytest compatibility matrix
└── pyproject.toml     package, CLI, and pytest plugin metadata
```

BriXTest imports no nginx-xrootd repository modules. The repository-specific
adapter lives outside this sub-project at `tests/brix_suite`.

## License

BriXTest is licensed under the GNU Affero General Public License version 3
only (`AGPL-3.0-only`). See [LICENSE](LICENSE) for the complete license text.
