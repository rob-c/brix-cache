# Architecture and compatibility contract

BriXTest is a pytest plugin, not a second test framework. Pytest owns
collection, parametrization, fixture setup/yield teardown, call adapters,
skip/xfail semantics, reporting hooks, selection, and xdist scheduling.
BriXTest adds an immutable resource graph and executes each complete managed
item in a supervised helper process.

```text
pytest controller
  ├─ collection: @case declarations → validated, content-addressed plans
  ├─ authenticated topology broker: global class/module/package/session pools
  │    └─ explicit worker-scoped pools when requested
  └─ attempt helper process
       ├─ normal pytest fixture lifecycle
       ├─ dedicated Python worker thread for the call hook
       ├─ independent heartbeat/cancellation control thread
       ├─ case backend → servers/configs/mounts/credentials
       └─ Run facade → client/tool executors/metrics/evidence

Kubernetes-isolated attempt
  ├─ deterministic test/BriXTest/dependency bundle
  ├─ controller-owned framed transport bridge
  └─ non-retrying Job → normal pytest helper lifecycle in the selected pod
```

With xdist, workers submit their complete immutable topology plans before the
scheduler releases tests. The controller-owned broker merges identical pools,
supervises their process trees independently of attempt helpers, and returns
only resolved service records over size-bounded, authenticated Unix IPC. A
worker exit cannot orphan its pools; explicit `scope="worker"` pools remain
broker-owned and are reaped with the session. On Linux, a parent-death signal
also unwinds the broker and lets every pool perform its normal transactional
teardown if the pytest controller itself disappears.

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

Authentication follows the same graph contract. Each declared authority owns
role-scoped issued-material nodes for the test helper, servers, and clients;
typed `issues`, `refreshes`, `revokes`, and `consumes` edges describe lifecycle
and distribution before any key or credential exists. Graph serialization
redacts secret/password fields, while runtime evidence resolves those planned
nodes to public metadata, retained checksums, and consumer relationships.

The controller initializes a per-attempt control channel before launch. The
helper publishes liveness independently of the Python test worker; a missing
heartbeat therefore detects a native call that wedges the helper interpreter,
not merely a slow assertion. On heartbeat loss or the absolute case deadline,
the controller writes a cancellation reason, terminates the complete process
tree, and reports the retained partial logs and resource tails. Container and
runc isolation mount the same private channel without exposing it to tests.
Kubernetes isolation projects the protocol onto a framed byte stream, while a
supervised local bridge applies the same heartbeat/result files and recovers
the remote run tree. The bridge never evaluates test code and owns forceful Pod,
Job, and Secret cleanup on cancellation or deadline.

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
