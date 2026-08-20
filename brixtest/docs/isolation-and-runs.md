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
from brixtest import case, docker, process

@case(isolation=process())
def test_local_helper(run): ...

@case(isolation=docker("registry.example/test@sha256:<64-hex-digest>"))
def test_container_helper(run): ...
```

```console
pytest --brixtest-isolation process
pytest --brixtest-isolation nsenter --brixtest-nsenter-target 1234
pytest --brixtest-isolation docker --brixtest-isolation-image IMAGE@sha256:DIGEST
pytest --brixtest-isolation podman --brixtest-isolation-image IMAGE@sha256:DIGEST
pytest --brixtest-isolation runc --brixtest-runc-bundle ./oci-bundle
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
