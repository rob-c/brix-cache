# Architecture and compatibility contract

BriXTest is a pytest plugin, not a second test framework. Pytest owns
collection, parametrization, fixture setup/yield teardown, call adapters,
skip/xfail semantics, reporting hooks, selection, and xdist scheduling.
BriXTest adds an immutable resource graph and executes each complete managed
item in a supervised helper process.

```text
pytest controller
  ├─ collection: @case declarations → validated, content-addressed plans
  ├─ scoped supervisors: class/module/package/session server pools
  └─ attempt helper process
       ├─ normal pytest fixture lifecycle
       ├─ dedicated Python worker thread for the call hook
       ├─ case backend → servers/configs/mounts/credentials
       └─ Run facade → client/tool executors/metrics/evidence
```

The controller never imports optional native libraries from a managed test
body, never owns a server subprocess, and never waits on test code in its own
interpreter. A hung worker can consume only its helper; the controller enforces
the case timeout and terminates the process tree.

Declarations are inert frozen values. Collection may validate and fingerprint
them but cannot read mutable executables into a running service, allocate
ports, create credentials, or launch processes. Materialization happens only
after a unique run directory exists. Effective config content, captured binary
and library bytes, credentials, artifacts, logs, metrics, timestamps, process
identity, and server/test relationships are checksummed and correlated in the
evidence model.

Backends implement one `validate → plan → prepare → start → stop → collect`
contract against the public `BackendContext`. Tool executors independently own
one resolved client invocation. Per-server launchers translate process,
Docker, Podman, or installed placement into one supervised process plan.
Providers materialize custom inputs, probes own readiness, and
collector/analyzer/exporter callables own evidence extensions. The built-in
local, Kubernetes, and Docker-backed Minikube implementations use the same
`Service` and `Run` values. Unsupported combinations fail validation; fields
are never silently ignored. All runtime seams use the versioned registry
described in [Extensions](extensions.md).

Output paths are bounded while processes are running, not after an unbounded
capture completes. Command pipes are drained concurrently into head/tail byte
budgets; server pipes are continuously drained into capped logs. Timeouts kill
the full process group, then archive the partial decoded output and provenance.

Compatibility is enforced from one machine-readable API manifest. It locks
top-level imports, constructors, methods, properties, readable attributes,
pytest options, ini keys, fixtures, markers, and cooperative hooks. Third-party
code should use that public surface and `brixtest.testing` conformance helpers,
not orchestration internals.
