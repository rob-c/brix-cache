# Isolation, resources, and summaries

Collection sees only immutable Python declarations. For each managed item the
pytest controller starts a fresh supervised pytest helper. Fixture setup, resource
materialization, server startup, the test body, client calls, and teardown all
occur there. The `case(timeout=...)` deadline covers that entire lifecycle.

Inside the helper, the managed function body runs on a dedicated daemon worker
thread. This makes the execution boundary explicit to test code while retaining
process-level containment: a hung C extension can stall an interpreter despite
threads, but it cannot stall the separate controller process.

If the deadline expires, the controller snapshots and terminates the helper's
descendant processes, then reports a normal failed pytest item. A blocked test
therefore cannot block the controller indefinitely.

Before importing a managed test module, BriXTest applies an AST policy that
keeps module scope declarative. Untrusted imports, subprocess/network
operations, sleeps, loops, and dynamic execution are rejected there. Trusted
pure-Python declaration/plugin roots can be explicitly allowed; executable or
native operations belong inside the test function so they execute only in its
worker. In particular, a module-level `import XRootD` is always refused before
Python loads the module; a function-local import remains supported.

## Isolation declarations

Isolation belongs to the case, while a suite-wide CLI override makes validation
against a different runtime mechanical:

```python
from brixtest import case, docker, kubernetes, process

@case(isolation=process())
def test_local_helper(run): ...

@case(isolation=docker("registry.example/test@sha256:<64-hex-digest>"))
def test_container_helper(run): ...

@case(isolation=kubernetes(
    "registry.example/python-runtime@sha256:<64-hex-digest>",
    context="brixtest", namespace="default", service_account="test-runner",
))
def test_remote_helper(run): ...
```

```console
pytest --brixtest-isolation process
pytest --brixtest-isolation nsenter --brixtest-nsenter-target 1234
pytest --brixtest-isolation docker --brixtest-isolation-image IMAGE@sha256:DIGEST
pytest --brixtest-isolation podman --brixtest-isolation-image IMAGE@sha256:DIGEST
pytest --brixtest-isolation runc --brixtest-runc-bundle ./oci-bundle
pytest --brixtest-isolation kubernetes \
  --brixtest-isolation-image IMAGE@sha256:DIGEST \
  --brixtest-kubernetes-context brixtest \
  --brixtest-kubernetes-namespace default \
  --brixtest-kubernetes-service-account test-runner
```

`nsenter()` names the namespaces to join and requires a positive target PID.
Docker and Podman use host networking so backend-neutral forwarded endpoints
remain reachable; project paths are read-only and only the run root is
writable. Ambient credentials are not copied into containers. runc derives a
private `config.json` from the declared OCI bundle and leaves the original
bundle unchanged. All commands are argv vectors and never pass through a shell.

Mutable image tags require the conspicuous `allow_mutable=True` opt-out. Extra
runtime arguments cannot replace BriXTest's mounts, environment file, network,
work directory, or container identity.

Kubernetes isolation builds a deterministic content-addressed bundle containing
the selected test subtree, portable project Python/config assets, ancestor
`conftest.py` files, project pytest config, the BriXTest package, trusted helper
plugins, and pytest's environment-marker-aware dependency closure. Dependency
files come from installed distribution metadata rather than a brittle module
allowlist. Individual inputs are limited to 64 MiB and the complete
uncompressed bundle to 256 MiB. Symlinks are excluded. The declared image is a
digest-pinned Python runtime; it does not need a BriXTest installation. The
bundle itself is retained once in the session object store with both its input
fingerprint and archive SHA-256.

The controller creates a non-retrying Job and a private environment Secret in
the selected existing namespace. The Job uses the declared ServiceAccount,
drops Linux capabilities, disables privilege escalation, and keeps its root
filesystem read-only. The bundle is streamed into writable `emptyDir` volumes,
then the normal pytest helper executes inside the pod. Remote test collection,
fixtures, the dedicated test worker, resources, and teardown therefore retain
the same semantics as process/container helpers.

Heartbeat, report, traceback, and result messages use versioned framed JSON;
ordinary stdout/stderr remains a bounded byte stream. Run and session evidence
is copied back with link-rejecting, path-confined archive extraction. The
absolute case deadline covers provisioning, execution, and recovery. Timeout
cleanup force-deletes the helper pod before deleting its Job and Secret, so a
hung remote interpreter cannot block the pytest controller.

For a remote cluster, Kubernetes pulls the declared digest normally. If
`context` names a running Minikube profile and the exact digest is already in
the local Docker store, BriXTest verifies the image ID, loads a checksum-tagged
alias into Minikube, and sets `imagePullPolicy: Never`. This makes the standard
Docker-backed `brixtest` profile an offline-capable reference target without
weakening image identity. Native function-local dependencies must either be in
the runtime image or be modeled as normal BriXTest binaries/artifacts.

Each helper owns a unique path containing:

```text
<run>/
├── inputs/
│   ├── artifacts/     generated/copied data and manifest
│   ├── binaries/      executable/library snapshots and manifest
│   └── configs/       source snapshots and rendered configs
├── runtime/               process workdirs and logs
├── workspace/             test-owned mutable files
└── summary.json           outcome and resource inventory
```

Regardless of `keep`, all server logs, every configured-client stdout/stderr
pair, client invocation metadata, the helper's complete pytest output, and the
case summary are copied into:

```text
<runs>/metrics/<session>/logs/<nodeid-sha256>/
```

Symlinks are not followed. This structured log tree survives passing-test
cleanup and is embedded (compressed) in the session SQLite archive.
Session-scoped server logs are stored once under
`logs/instances/<instance-id>/` and checksum-linked from every consuming test;
see [Dynamic topology](dynamic-topology.md).

Capture checks hashes and source metadata before and after copying. A concurrent
rebuild or input rewrite fails setup instead of silently mixing versions.

`keep="failed"` retains failures and timeouts, `always` retains every run, and
`never` cleans all completed runs. Inspect retained records with:

```console
brixtest summary list
brixtest summary latest
brixtest --json summary <run-id>
```

Set `BRIXTEST_RUNS` or `--brixtest-runs` to control the runs directory.

Metric records are retained independently of `keep`. Passing cases may safely
remove their large run inputs while their compact measurements remain under
`<runs>/metrics/<session>/`. See [Metrics and performance budgets](metrics.md).

The first failure stops execution by default and retains a full trace. Replay
it with `brixtest rerun latest`; use `--test <exact-nodeid>` to select a case or
`--all` to replay every failed case in order.
