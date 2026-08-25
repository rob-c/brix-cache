# Writing tests

Put tests in your project's `tests/` folder. Define reusable declarations at
module scope, decorate a function with `@case`, and accept one `run` fixture.
Declarations are inert: importing and collecting the module starts nothing.

`Execution` is the common shell-free invocation policy. A `Tool` is an
invocable executable; a `Client` is a named client actor retained for suites
that prefer server/client vocabulary. `command()` remains a compatibility
spelling for `execution()`. Declarations create their own typed references
(`origin.url("http")`, `payload.ref()`, `credential.ref()`), while
`param("name")`, `workspace_ref()`, and `run_root_ref()` cover values without
an owner object. Explicit `*_ref()` factories remain for migrations and
generic tooling.

References describe intent, not a pre-rendered string. For example,
`origin.url("http")` resolves to an in-cluster Service address when consumed by
a Kubernetes server or tool and to the supervised forwarded address when
consumed by the helper. Likewise, `payload.ref()` and `program.ref()` resolve
to projected pod/image paths remotely and retained run paths locally. If a
backend cannot provide a safe representation, planning reports the consuming
resource instead of allowing a host path to escape into it.

```python
from brixtest import (
    case, execution, http_endpoint, http_probe, noise, server,
    template_config, tool,
)

origin = server(
    "origin",
    command=["./origin", "--config", "{config}"],
    config=template_config("configs/origin.conf.in"),
    endpoints=[http_endpoint()],
    probe=http_probe(),
)
curl = tool("curl", execution=execution("curl", "--fail", origin.url("http")))
object_input = noise("object", size=100_000_000, seed=4)


@case(origin, curl, object_input)
def test_download(run):
    assert run.tool(curl).run().returncode == 0
    assert run.artifact("object").size == 100_000_000
```

## The `run` fixture

| Need | Call |
|---|---|
| Resolve a server | `run.server(origin)` or `run.server("origin")` |
| Build a backend-neutral URL | `run.server(origin).url(role="http", path="/x")` |
| Correlate a server instance | `run.server(origin).instance_id` and `.scope` |
| Run a named client | `run.client(curl).run("--verbose")` |
| Resolve an input artifact | `run.artifact("object").path` |
| Read artifact text | `run.artifact_text("object")` |
| Read artifact bytes | `run.artifact_bytes("object")` |
| Read artifact JSON | `run.artifact_json("object")` |
| Get the raw artifact path | `run.artifact_path("object")` |
| Open an artifact | `run.open_artifact("object", "rb")` |
| Run arbitrary argv | `run.command("tool", "--option")` |
| Run reusable execution defaults | `run.execute(execution, "--operation")` |
| Resolve and run a named tool | `run.tool(tool).run("--operation")` |
| Resolve an immutable binary | `run.binary("origin").path` |
| Resolve a custom credential | `run.credential("proof").path` |
| Resolve an authentication stack | `run.auth("tls").path("host_cert")` |
| Resolve a declared hostname | `run.resolve("origin.test")` |
| Perform declared reverse lookup | `run.reverse("127.0.0.8")` |
| Record a metric | `run.metrics.gauge("transfer.rate", 42, unit="MiB/s")` |
| Time a block | `with run.metrics.timer("transfer.latency"):` |
| Correlate a test action | `with run.step("upload", bytes=100_000_000):` |
| Archive a produced file | `run.attach(run.workspace / "profile.svg")` |
| Archive structured output | `run.attach_json("result.json", value)` |
| Get test-owned scratch space | `run.workspace` |
| Inspect retained inputs/logs | `run.root` |
| Check server health | `run.server(origin).is_ready()` / `.wait_ready()` |
| Read bounded server diagnostics | `.tail_log()` / `.follow_log(timeout=...)` |
| Control a running server | `.signal()`, `.restart()`, `.wait(timeout=...)` |
| Run a server-side diagnostic | `.command("tool", "--check")` |

Clients return BriXTest's immutable `CommandResult`, capture text output, use
no shell, and raise on non-zero status by default. Pass `check=False`,
`timeout=...`, `input=...`, or extra environment values to `run()` as needed.
Set `mode="pty"` on `client()`, `tool()`, `execution()`, or `run.command()` when
the program requires a real terminal. BriXTest attaches stdin/stdout/stderr to
one resized PTY, streams terminal output while retaining a bounded transcript,
and applies the same deadline and process-tree termination locally, through
Docker/Podman, and in Kubernetes. Declared `input=` remains deterministic and
portable; use `mode="capture"` for binary-safe, non-terminal stdin.

`run.command()` provides the same result and shell-free behavior for one-off
commands. `CommandResult` has decoded string `stdout`/`stderr`, `returncode`,
`elapsed_seconds`, `ok`, line helpers, `check()`, and `check_returncode()`.
Use `.json()` when stdout contains JSON. Materialized artifacts, captured
binaries, and credentials expose `.verify()` for concise checksum assertions.
Every call archives its two
streams and invocation metadata even when it succeeds or raises.

Both `server()` and `client()` accept either a complete `execution=...` value,
a compatibility `command=[...]` vector,
or the concise `binary=tool, args=[...]` form. Mixing the two is rejected at
declaration time.

Use `execution(...)` when argv, environment, cwd, input, timeout, accepted exit
codes, output bound, retry count, or capture mode should be reusable. Servers
also accept named `Endpoint` values, TCP/HTTP/HTTPS/exec/log `Probe` values,
`Lifecycle`, `LogPolicy`, `Placement`, and confined `Mount` projections. A
mount can source a declared artifact, credential, one of that server's config
files, a path, or a fresh temporary directory. Its run-local path is available
as `{mount_<target>}` (non-alphanumeric characters become underscores) and as
the corresponding uppercase environment variable.

Multi-file servers use `configs(...)`; `{config}` remains the selected primary
and each file also has a `{config_<destination>}` placeholder. The complete
rendered set and SHA-256 provenance are retained on every result.
Servers that do not consume a config may omit `config=`; BriXTest retains a
checksummed empty config so the provenance schema remains uniform.

Servers may depend on other declared servers with `depends_on=[auth]`. BriXTest
starts dependency levels in order and tears them down in reverse order.
Servers are case-scoped by default. `function`, `class`, `module`, `package`,
and `session` lifetimes follow pytest's familiar vocabulary. `worker` is an
explicit xdist-local lifetime. Collection derives
immutable shared pools for class/module/package/session resources;
`run.server()` is unchanged, and every attempt records the exact instance ID
it consumed. See [Dynamic topology](dynamic-topology.md).

## Safe imports and execution

Keep module scope declarative. Standard-library, pytest, and BriXTest imports
are allowed there; optional or native libraries such as `XRootD` must be
imported inside the managed test function:

```python
@case()
def test_native_client(run):
    import XRootD
    # Native calls happen only in this case's isolated worker.
```

BriXTest parses managed modules before pytest imports them and rejects unsafe
module-scope native imports, process/network calls, sleeps, loops, and dynamic
execution. The function body runs on a dedicated worker thread inside the
per-attempt helper process. If native code blocks the worker or its interpreter,
an independent helper heartbeat expires and the controller terminates the
whole helper process tree. `BRIXTEST_HEARTBEAT_TIMEOUT` may shorten or lengthen
that liveness bound for unusually long native calls; the absolute `case`
timeout remains authoritative and is enforced by the separate controller
process.

## Inputs and binaries

- `noise(name, size=..., seed=...)` produces deterministic SHAKE-256 XOF bytes
  in chunks. The content is high entropy and practically incompressible; it is
  reproducible, not a secret random-number source.
- `file_artifact(name, path)` copies and hashes an existing file while checking
  that its source did not change during capture.
- `text_artifact(name, text)` publishes a small text input.
- `binary(name, path)` copies an executable and, by default, its `ldd`-resolved
  shared libraries into the unique run before any server starts. Use the
  `Binary` object directly in server/client argv.
- `credential()`, `checksum_credential()`, and `signed_credential()` create
  confined, role-scoped credentials. See [Authentication recipes](authentication.md).

## Test shape

Each behavior change should cover three cases:

1. the intended success path;
2. a malformed input or operational error;
3. a security-negative case showing that the boundary refuses unsafe input.

Prefer endpoints over hand-built host/port strings, named clients over repeated
subprocess setup, `run.workspace` over global temporary paths, and declared
artifacts/binaries over files that can change underneath a running suite.

Run a single file while authoring:

```console
pytest tests/test_<feature>.py -v
```

Inspect the fully collected declarations without creating inputs or processes:

```console
brixtest design tests/test_<feature>.py
```

`pytest-xdist` may distribute managed controller items with `-n auto`. Every
worker publishes its immutable plans before execution; an authenticated,
controller-owned topology broker merges them and owns class/module/package/
session pools once for the whole pytest session. Each attempt still runs in a
separate supervised helper. Choose `scope="worker"` when duplication per xdist
worker is intentional; that decision is recorded in topology provenance.

Each managed item is deliberately a separate pytest helper session. Ordinary
fixtures retain normal setup/yield-teardown behavior inside that item; do not
use a session/module fixture as cross-item mutable state. Declare shared
servers with `scope="module"`, `"package"`, or `"session"` instead: BriXTest
derives and supervises those pools in the controller and records every
test-to-instance edge without importing the test body there.

See [Metrics and performance budgets](metrics.md) for the `metrics` fixture,
automatic resource/client measurements, pytest budget markers, terminal
summaries, and JSON/CSV/HTML output.

Use `@case(warmup=1, trials=5)` for independent repeated attempts, and declare
automatic collectors with `observe=[process_tree(), prometheus(...)]`. See
[Evidence, trials, analytics, and extensions](evidence-and-analytics.md).
