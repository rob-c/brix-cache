# Server and tool placement backends

Case placement (`local`, `kubernetes`, or `minikube`) and test-helper isolation
(`process`, `nsenter`, `docker`, `podman`, or `runc`) are independent axes. A
test can, for example, execute in a Podman container while its declared servers
run in Kubernetes. Test code sees the same `Run` object in every combination.

Tests consume one API on both backends. A server's `Service.host`, named ports,
and `url()` are reachable from the test helper: direct loopback endpoints
locally and supervised `kubectl port-forward` endpoints on Kubernetes.

Client/tool placement is a third independent axis. `inherit` and `local` run
inside the isolated helper; `docker` and `podman` run a digest-pinned one-shot
container; `kubernetes` creates a one-shot Pod in the case namespace. Installed
executor names are accepted by the same `Placement` declaration.

Select a backend in descending precedence:

1. `--brixtest-backend=local|kubernetes|minikube|<installed-name>`;
2. `BRIXTEST_BACKEND`;
3. `@case(backend=...)`;
4. `auto`, which currently selects local.

## Local

BriXTest reserves auto-selected loopback ports before spawn, snapshots every
input, starts dependency levels, waits for readiness, and terminates each
server process group during teardown. Logs live under the case run path.
Each local-case server independently selects `inherit`/`local`/`process`,
`docker`, `podman`, or an installed launcher through `Placement(backend=...)`.
All variants remain attached to the same supervisor. Docker/Podman use host
networking by default, mount the immutable run tree at identical absolute
paths, pass environment through a mode-0600 file, and translate CPU, memory,
PID, and label declarations. Images are digest-pinned unless the declaration
explicitly opts into a mutable local-development image. Kubernetes-only
namespace, scheduling, and security fields fail during setup instead of being
silently ignored.

```python
native = server("native", execution=execution("./server", "{port}"))
boxed = server(
    "boxed",
    execution=execution("/opt/server", "{port}"),
    placement=Placement(
        backend="docker",
        image="registry.example/server@sha256:<digest>",
        resources=ResourceLimits(cpu=1, memory_bytes=512 * MiB),
    ),
)
```

## Kubernetes

For each server, BriXTest creates a ConfigMap, Deployment, and Service in a
unique temporary namespace, waits for rollout, and opens local port forwards.
Teardown captures deployment logs and deletes the namespace.
`Placement` image, labels, node selector, security context, CPU/memory limits,
and namespace prefix are translated into the generated resources. BriXTest
adds a unique run suffix and continues to own namespace teardown. Named
TCP/HTTP(S)/exec probes become native readiness probes.

Declared server credentials and authentication files are projected from a
namespace-scoped Secret at mode `0400`; client/test-only files are excluded.
Declared test host mappings become Pod `hostAliases`. The Docker-Minikube
validation profile is documented in `k8s/minikube/README.md`.

## Docker-backed Minikube

`backend="minikube"` is the first-class local Kubernetes target. It requires
the dedicated profile to use the Docker driver and passes `--context
brixtest` (or `BRIXTEST_MINIKUBE_PROFILE`) to every kubectl command; it does
not mutate the caller's active context. The CLI owns the reproducible profile
workflow:

```console
brixtest minikube start       # Docker driver/runtime, 2 CPUs, 4096 MiB
brixtest --json minikube status
brixtest minikube test
```

The backend verifies the profile exists, uses the Docker driver, and has a
running host, kubelet, and API server before it creates a namespace. `test`
performs the same preflight before loading the pinned validation image.

CPU and memory defaults can be changed with CLI options or
`BRIXTEST_MINIKUBE_CPUS` / `BRIXTEST_MINIKUBE_MEMORY_MB`. Cluster deletion is
intentionally not automated; it remains an explicit Minikube operator action.

Declared read-only file mounts are projected at the same logical
`/brixtest/mounts/<target>` paths used by template values; writable `tmp`
mounts become `emptyDir` volumes. Embedded files are intentionally capped at
768 KiB to stay below Kubernetes object limits. Larger server inputs should be
baked into an immutable image, supplied by a PVC, or handled by an installed
backend extension; BriXTest fails the plan instead of creating a fragile giant
Secret. Kubernetes rejects UDP endpoints because `kubectl port-forward` cannot
publish them.

Kubernetes images must be digest pinned (`image@sha256:...`). A `Binary` used in
a server command needs `image` and `image_path`; local `path` may also be given
when the same declaration is used on both backends. This makes the image's
executable identity the Kubernetes equivalent of the local captured copy.

```python
origin_bin = binary(
    "origin",
    path="build/origin",
    image="registry.example/origin@sha256:<digest>",
    image_path="/opt/origin/bin/origin",
)
```

Set `BRIXTEST_KUBECTL` to use a non-default kubectl executable. The active
kubectl context and credentials determine the target cluster. BriXTest invokes
kubectl with argv and JSON stdin, never through a shell.

Tools declared with `Placement(backend="kubernetes")` use the same namespace
and in-cluster Service DNS. Each invocation creates a uniquely named Pod,
captures its container log and exit status, applies CPU/memory limits, projects
role-approved client credentials and declared mounts, and deletes the Pod in a
`finally` path. Input projections remain limited to 768 KiB; larger inputs need
an immutable image, PVC-aware executor, or another installed executor.
Interactive PTY and stdin transport are rejected explicitly.
Content-valued credentials (including bearer tokens) use `SecretKeyRef`, while
file-valued credentials use read-only Secret mounts. Neither is written as a
plaintext `env.value` in the tool Pod manifest.

## Runtime service controls

`run.server(...)` returns a `Service` with the same bounded controls on every
supported target: `is_ready()`, `wait_ready()`, `tail_log()`, `follow_log()`,
`signal()`, `restart()`, and `command()`. Process exit `wait()` is available
for process/Docker/Podman servers. Every command has a deadline and bounded
capture; detached `Service` records fail clearly instead of pretending to be
controllable.

## Container tool execution

`Placement(backend="docker"|"podman", image="...@sha256:...")` executes a
tool in a disposable container with host networking and the confined run tree
mounted at identical absolute paths. Environment values travel through a
mode-0600 environment file rather than process arguments. CPU, memory, and PID
limits map to the runtime's native flags. Kubernetes scheduling fields and PTY
mode fail validation instead of being ignored.
