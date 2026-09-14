# Extending BriXTest

BriXTest has one versioned, lazy extension registry. Every advertised kind has
an executable runtime path and a reusable black-box conformance helper.

| Kind | Entry-point group | Runtime contract |
|---|---|---|
| backend | `brixtest.backends` | `validate`, `plan`, `prepare`, `start`, `stop`, `collect` |
| executor | `brixtest.executors` | `validate`, `execute` |
| probe | `brixtest.probes` | `validate`, `wait` |
| provider | `brixtest.providers` | `validate`, `materialize` |
| collector | `brixtest.collectors` | callable collector |
| analyzer | `brixtest.analyzers` | callable analyzer |
| exporter | `brixtest.exporters` | callable exporter |
| launcher | `brixtest.launchers` | `validate`, `prepare`, `cleanup` |
| resource | `brixtest.resources` | `validate`, `plan`, `create`, `ready`, `collect`, `destroy` |
| volume | `brixtest.volumes` | managed lifecycle used by provider-backed volumes |
| identity | `brixtest.identities` | managed lifecycle used by external identities |
| transport | `brixtest.transports` | binary-safe filesystem operations |
| image | `brixtest.images` | immutable image build contract |

Import the typed protocols from `brixtest.extensions`. Backends receive a
public `BackendContext`; executors receive `ToolExecutionContext` and
`ToolExecutionRequest`; artifact providers receive `ArtifactProviderContext`.
Per-server launchers receive `ServerLaunchContext` and `ServerLaunchRequest`
and return a `ServerLaunchPlan` that the normal supervisor owns.
Managed-resource providers receive `ProviderContext`, return a `ProviderPlan`
without mutating external state, and return an owned `ProviderInstance` from
`create`. BriXTest publishes only named outputs, waits for readiness, archives
collection data, and calls `destroy` in reverse order even when collection
fails.
On a Kubernetes backend, `context.kubernetes()` becomes available only after
side-effect-free planning. Its exclusive-create `apply(owner, documents)`,
`get(identity)`, `observe(identity)`, `delete(identity)`, `orphans()`, and
`cleanup_orphans()` operations confine provider implementations to the owned
case namespace, attach run-specific ownership labels, retain an atomic UID
journal, reject cluster-scoped objects, and refuse deletion after UID
replacement. `observe()` correlates UID-scoped events and optional exact-label
Pod status, logs, and metrics. Raw custom
resource documents therefore remain private to an extension; the ordinary
test contains only a typed `resource("store", "rook-ceph", ...)` declaration.
Kubernetes teardown stops workloads first, then collects and destroys provider
objects, and deletes the namespace last.
These values expose stable capabilities without requiring private manager
attributes.
`VolumeProvider` and `IdentityProvider` refine that managed lifecycle;
`FilesystemTransport` and `ImageProvider` define the narrow data-plane and
image-build seams. Their registry kinds are available now so extensions can be
versioned without placing backend dictionaries in tests; backend integration
is enabled only where its declared capabilities are supported.

Server- and tool-specific author conveniences do not require entry points. A
package such as `brixtest-nginx` should normally expose an ordinary factory
that returns a generic `Server`, `Tool`, `Probe`, and config declaration. Use a
runtime extension only when the package introduces genuinely new placement,
execution, readiness, materialization, observation, analysis, or export
behaviour.

## Registration and packaging

Programmatic registration is useful for a project-local adapter:

```python
from brixtest import register_extension

register_extension(
    "backend", "remote-lab", remote_lab_backend,
    api_version=1, capabilities=("logs", "metrics", "provenance"),
)
```

A packaged executor uses standard Python entry-point metadata:

```toml
[project.entry-points."brixtest.executors"]
remote-lab = "brixtest_remote_lab:executor"
```

A packaged per-server launcher uses the corresponding group:

```toml
[project.entry-points."brixtest.launchers"]
remote-host = "brixtest_remote_host:launcher"
```

Discovery records metadata without importing extension code. `get_extension`
performs the first load and validates the contract. Extension objects may
publish `brixtest_api_version` and `brixtest_capabilities`; incompatible API
versions are rejected before execution. `brixtest plugins` lists installed
implementations and `brixtest plugins --load` verifies imports and contracts.

Programmatic registrations derive `brixtest_capabilities` from the extension
object unless an explicit capability sequence is supplied. Every built-in
backend, launcher, executor, artifact provider, filesystem transport, and
image pipeline publishes the same stable, kind-specific vocabulary used by
`brixtest design`; an executor advertises PTY and stdin only when its own
transport implements them. Adapter suites can call
`check_extension_capabilities(kind, target, required)` to verify API version,
declaration shape, and required semantics before running lifecycle checks.

## Runtime examples

A provider can return bytes, text, a confined `Path`, or write the supplied
destination and return `None`:

```python
from brixtest import artifact, case

payload = artifact("dataset", "site-dataset", filename="input.bin", rows=1000)

@case(payload)
def test_dataset(run):
    assert run.artifact(payload).verify()
```

An executor is selected without changing test logic:

```python
from brixtest import Placement, execution, tool

client = tool(
    "client",
    execution=execution("/opt/client", "--version"),
    placement=Placement(backend="remote-lab"),
)
```

Analyzers and exporters run through the evidence CLI:

```console
brixtest metrics analyze latest --plugin latency-model --option confidence=0.99
brixtest metrics export latest --format plugin --plugin lab-archive -o result.bundle
```

Third-party suites should call `assert_extension_contract` plus the relevant
`check_case_backend_contract`, `check_executor_contract`, or
`check_provider_contract`, `check_managed_resource_provider_contract`, or
`check_launcher_contract` helper from `brixtest.testing`.

## Pytest cooperation

Cooperating pytest plugins have these stable hooks:

- `pytest_brixtest_plan(item, definition)` observes validated collection plans.
- `pytest_brixtest_helper_plugins(config, item)` selects trusted helper plugins.
- `pytest_brixtest_server_ready(run, server)` observes successful readiness.
- `pytest_brixtest_server_stopped(run, server, error)` observes teardown.
- `pytest_brixtest_tool_result(run, tool, result)` observes completed invocations.
- `pytest_brixtest_artifact_materialized(run, artifact)` observes captured inputs.
- `pytest_brixtest_result(item, record)` observes the secret-free final result.

Helper plugin auto-loading is disabled. Opt in with repeated
`--brixtest-helper-plugin module.name` or the `brixtest_helper_plugins` ini
setting. This keeps native or blocking plugin code outside the controller while
preserving pytest's normal fixture and call-hook semantics inside the helper.

Extensions must use shell-free argv, confined paths, bounded output, and the
supplied evidence interfaces. Secrets must never be placed in result metadata,
replay commands, or exported extension diagnostics.

The built-in container executors pass declared environment through temporary
mode-`0600` env files and remove them after execution. The Kubernetes executor
uses mounted Secrets and `SecretKeyRef` for content-valued credentials; custom
executors are responsible for an equivalent secret-transport boundary.
