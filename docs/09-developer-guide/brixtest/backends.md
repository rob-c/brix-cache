# Server and tool placement backends

Case placement (`local`, `kubernetes`, or `minikube`) and test-helper isolation
(`process`, `nsenter`, `docker`, `podman`, `runc`, or `kubernetes`) are
independent axes. A
test can, for example, execute in a Podman container while its declared servers
run in Kubernetes. Test code sees the same `Run` object in every combination.

`kubernetes()` helper isolation streams a content-addressed test/runtime bundle
into a digest-pinned, non-retrying Job and runs pytest through the declared
ServiceAccount. It is distinct from server/tool placement: a remote helper may
run local processes inside its pod or use the Kubernetes case backend through
the bundled `kubectl`. The Docker-backed `brixtest` Minikube context supports
verified offline loading of a locally cached digest.

Tests consume one API on both backends. A server's `Service.host`, named ports,
and `url()` are reachable from the test helper: direct loopback endpoints
locally and supervised `kubectl port-forward` endpoints on Kubernetes.
Typed server references are consumer-aware: server configs and tools running
inside the case namespace receive stable Service DNS and cluster ports, while
local tools and the test helper receive the forwarded loopback endpoint. This
also applies independently to every named endpoint role.

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

Servers sharing `Placement(group="stack")` use one local isolation realm.
For Docker and Podman, the first declaration owns the digest-pinned container
and later members are foreground, separately logged `exec` processes inside
it. Each member retains independent readiness and its exact shutdown command;
reverse-order teardown stops those members before the anchor container is
removed. Container-level image, identity, resource limits, labels, options,
device mounts, and propagation must match across the group and are validated
before any runtime command executes.

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

For ordinary cases BriXTest creates a ConfigMap, Deployment, and Service in one
unique temporary namespace and waits for rollout. Named `Environment`
declarations may select additional owned namespaces and explicit kubeconfig
contexts without changing server, task, or tool APIs. Resources inherit the
case context when `Environment.context` is empty. In-cluster consumers use
Service DNS directly; cross-namespace references use the fully qualified
`service.namespace.svc.<dns-domain>` name. Dependencies between different
contexts are rejected before mutation unless an installed transport can own
that connection. Controller-side TCP uses supervised port forwards; UDP
uses a bounded binary datagram gateway in the service Pod's network namespace.
Tests continue to call `Service.address()` and never invoke transport commands.
Teardown captures deployment and gateway logs and deletes every owned
namespace only after its captured UID still matches.
`Service.read_log()` and `follow_log()` fetch current server-container output
before that archive exists, including replica prefixes.
`Placement` image, labels, node selector, security context, CPU/memory limits,
and namespace prefix are translated into the generated resources. BriXTest
adds a unique run suffix and continues to own namespace teardown. Named
TCP/HTTP(S)/exec probes become native readiness probes.

Declared server credentials and authentication files are projected from a
namespace-scoped Secret at mode `0400`; client/test-only files are excluded.
Host mappings declared with `libc=True` become Pod `hostAliases` for their
selected server/client/test consumers. Framework-only mappings remain
available through `run.resolve()` and `run.reverse()` without changing a
workload's resolver. The Docker-Minikube validation profile is documented in
`k8s/minikube/README.md`.

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

Local-only `Binary` declarations are converted into unique run-owned OCI
images before namespace creation. BriXTest builds without network access,
loads the image into the selected profile, and archives the image ID, layer
digests, generated command paths, base/build inputs, Docker and Minikube
versions, and a file-level checksum SBOM. Normal tests
continue to use the same `binary(..., path=...)` and `server(...)` declarations.

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
Secret. Controller-side UDP endpoints use BriXTest's supervised binary gateway
because `kubectl port-forward` only transports TCP.

Every managed server Pod includes a small restricted filesystem sidecar using
the digest-pinned `BRIXTEST_KUBERNETES_FILESYSTEM_IMAGE` (the maintained Python
runtime by default). It shares only the server's declared volumes and powers
the ordinary `service.fs` facade through a raw-byte framed protocol. The
sidecar has a read-only root filesystem, drops all Linux capabilities unless
the declared service identity explicitly adds one, and has fixed resource
limits. No shell, quoting, or base64 code is required in a test.

Stateless servers render as Deployments. A server with a persistent, shared,
or provider-backed mounted volume renders as a StatefulSet plus a headless
identity Service; its ordinary Service remains the stable load-balanced test
endpoint. `Lifecycle.shutdown_command` is rendered as a shell-free `preStop`
exec hook. Runtime controls and teardown address the realized workload kind,
not an assumed Deployment.
After a restart, BriXTest reads the new Pod list and returns a refreshed
`Service` value. Stable service ports and claim names are preserved while
`Service.replicas` exposes the replacement Pod UIDs, restart state, and image
identities; callers never receive a stale pre-rollout replica snapshot.

Every object applied by the built-in backend receives
`brixtest.io/graph-node` and `brixtest.io/test-instance` labels. The same values
are written to the evidence journal, so manifests, logs, events, and consuming
tests can be joined without relying on a resource name alone.

`Placement(group="stack")` co-locates servers as named containers in one Pod
without introducing a sidecar-specific declaration. Each member keeps its own
Service, port-forward, readiness, lifecycle, `Service.command()`, log archive,
container status, and metrics. A `phase="init"` task using the same group is
rendered before those server containers as an ordered init container; an
ungrouped task remains a non-retrying Job. Group members must share replica,
identity, and node-selection policy because those are Pod properties. They may
not declare ordering between one another because Kubernetes starts ordinary
containers together. These constraints are checked before namespace creation.

A typed artifact reference used by a server or Kubernetes tool automatically
projects that artifact and resolves to its pod path. Binary references resolve
to the declared `image_path`, or to the content-addressed path generated for a
local binary on Minikube. BriXTest rejects host-only binary paths and
unprojected Kubernetes task inputs during pre-mutation validation; it never
passes a controller filesystem path into a pod.

Legacy template placeholders such as `{artifact_payload}` and
`{artifact_payload_dir}` receive the same consumer-specific treatment. Only
the named artifact is projected into the consuming Pod, the captured config
contains the in-Pod path, and its checksum/projection relationship is retained.

Backend validation is exhaustive rather than best-effort. A public placement,
networking, identity, storage, terminal, or lifecycle field that has no exact
translation is rejected before the attempt root is created, with the resource,
missing capability, selected backend, and available alternatives. For example,
native process placement rejects mutable-image policy because no image exists
in that execution model.

Kubernetes images must be digest pinned (`image@sha256:...`). A `Binary` used in
a server command needs `image` and `image_path`; local `path` may also be given
when the same declaration is used on both backends. This makes the image's
executable identity the Kubernetes equivalent of the local captured copy.
Digest-pinned supplied images remain unchanged. A locally captured binary is
instead packaged into a checksum-tagged image: Minikube loads it directly,
while remote Kubernetes pushes it to the registry configured by the suite
profile or `brixtest_registry` project setting. The optional generated-image
base is independently digest pinned.

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
selected by their `Environment` and use in-cluster Service DNS. Each invocation
creates a uniquely named Pod,
captures its container log and exit status, applies CPU/memory limits, projects
role-approved client credentials and declared mounts, and deletes the Pod in a
`finally` path. Input projections remain limited to 768 KiB; larger inputs need
an immutable image, PVC-aware executor, or another installed executor.
Text and raw-byte stdin use the Pod attach channel and preserve the same
bounded capture/result contract as local and container tools. Interactive PTY
mode allocates a TTY in the Pod, attaches through a controller-side PTY, tracks
terminal-size changes, streams combined terminal output, preserves a bounded
durable transcript, and terminates the attach and Pod on deadline.
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
limits map to the runtime's native flags. PTY tools translate to the runtime's
interactive/TTY flags and use the same bounded controller-side terminal
transport as local commands. Kubernetes-only scheduling fields still fail
validation instead of being ignored.
