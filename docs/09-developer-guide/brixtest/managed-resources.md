# Managed resources and lifecycle tasks

BriXTest compiles every case into an immutable resource graph before creating
files, reserving ports, or starting processes. Most tests still need only
`server()`, `tool()`, and `artifact()`. Use the general resource declarations
when the behavior under test depends on execution realms, storage, identity,
finite setup work, or provider-managed infrastructure.

## Finite tasks and volumes

Tasks are shell-free, bounded commands. `prepare` and `init` tasks complete
before servers start; `finalize` tasks run while servers are still available
and before reverse-order teardown.

```python
import sys

from brixtest import case, mount, task, volume

data = volume("data", kind="shared")

seed = task(
    "seed",
    command=(
        sys.executable,
        "-c",
        "import os,pathlib; pathlib.Path(os.environ['MOUNT_DATA'], 'ready').write_text('yes')",
    ),
    mounts=(mount(data, "data", read_only=False),),
)

@case(data, seed)
def test_seeded_volume(run):
    assert (run.volume(data) / "ready").read_text() == "yes"
    assert run.task(seed).ok
```

Declared task outputs must be regular non-symlink files in the task work
directory. BriXTest verifies and archives them before publishing their typed
references to later tasks, server configs, commands, or environments.

```python
build = task(
    "build",
    command=(sys.executable, "-c", "open('result.txt', 'w').write('ready')"),
    outputs={"result": "result.txt"},
)

consume = task(
    "consume",
    depends_on=(build,),
    command=(sys.executable, "-c", "import sys; print(open(sys.argv[1]).read())",
             build.output("result")),
)
```

A preparation task can also publish the executable or file captured for later
workloads. The source is verified only after the producer completes and is then
copied into the immutable run input store before any dependent server starts:

```python
from brixtest import binary, file_artifact

build = task(
    "build",
    command=("./build-server",),
    outputs={"server": "server", "fixture": "fixture.json"},
)
built_server = binary("server", path=build.output("server"))
built_fixture = file_artifact("fixture", build.output("fixture"))
```

Changing or rebuilding the producer path after capture cannot change the
executable or artifact used by the active run. Finalization outputs and
task-output-backed credential sources are rejected because their lifetimes are
too late for safe capture.

Set `Placement(backend="docker"|"podman", image="...@sha256:...")` on a task
to run the same finite declaration in a disposable one-shot container. CPU,
memory, PID, environment, cwd, timeout, and dependency semantics use the
normal tool-executor translation. Stdout and stderr are retained separately
under the task record on success or failure. Mutable images and placement
features the selected runtime cannot honor fail during planning.

The local backend supports temporary, shared, persistent-for-the-case, and
explicit host volumes. Docker and Podman additionally translate an explicitly
declared device volume into a validated runtime device mapping; regular files
cannot masquerade as devices. They translate `host-to-container` and
`bidirectional` propagation into `rslave` and `rshared` bind mounts and retain
the container cleanup command with the server lifecycle. Kubernetes represents
device volumes as typed `hostPath` devices (including `/dev/fuse`) and uses its
native mount-propagation field. Tests continue to consume the ordinary mount
reference and contain no runtime-specific arguments.

A non-zero size is a quota request, not a hint; a
backend that cannot enforce it rejects the plan before creating the run root.
Provider and user-namespace declarations are likewise rejected until their
selected backend advertises and implements the required capability. Kubernetes
implements isolated named environments as run-owned namespace/context targets;
placing a resource needs only `Placement(environment=realm)`. Same-context
references use managed Service DNS and dependency-derived NetworkPolicy, while
cross-context dependencies require an installed transport and otherwise fail
before mutation. Kubernetes renders temporary volumes as bounded
`emptyDir` volumes, persistent/shared volumes as PVCs, absolute host volumes
as `hostPath` volumes, and replica counts directly into Deployments.
After rollout, `run.server(name).replicas` exposes the live Pod identities,
direct Pod addresses, readiness, restart counts, node placement, and immutable
container image identities. The parent `Service` continues to expose the
stable load-balanced/forwarded endpoint, so tests need no Kubernetes branches.
Before namespace teardown, BriXTest archives each container's timestamped log,
the previous log when Kubernetes reports a restart, sanitized status and exit
details, namespace Pod events, and an optional `kubectl top --containers`
snapshot. These files live below `runtime/logs/<server>/`, so the normal
content-checksummed case archive and SQLite/search exporters retain them on
successful and failed runs alike.

An `Identity` selected through `Placement(identity=...)` becomes an owned
Kubernetes ServiceAccount. Declared permissions become a namespaced Role and
RoleBinding; UID, GID, supplementary groups, and portable Linux capabilities
become pod/container security contexts. Kubernetes user namespace maps fail
during capability planning because that backend cannot honor them portably.

The same declaration enforces numeric UID/GID, supplementary groups, and an
explicit capability allow-list for process, Docker, and Podman servers,
clients/tools, and finite tasks. Direct execution is wrapped by `setpriv` with
no-new-privileges and a capability bounding set while the returned
`CommandResult.argv` remains the test author's command. Process placement uses
a supervised, shell-free user-namespace helper plus `newuidmap`/`newgidmap` for
declared maps. Podman translates the same `user_namespace=True`, `uid_map`, and
`gid_map` declaration to native runtime flags. Docker rejects those maps
because it cannot express per-container arbitrary mappings.
ServiceAccount/RBAC fields remain Kubernetes-only and are never silently
discarded by an OCI launcher.

```python
runner = identity(
    "mapped", uid=0, gid=0, user_namespace=True,
    uid_map=((0, 100000, 65536),),
    gid_map=((0, 200000, 65536),),
)
origin = server("origin", command=("id",), placement=Placement(identity=runner))
```

Map rows are `(inside_id, outside_id, count)`. Overlapping ranges and target
UIDs/groups not covered by their declared maps fail during declaration;
missing host mapping helpers fail before the workload command is invoked.

`host_mapping(..., libc=True)` makes DNS requirements explicit. Its `targets`
select server, client, and/or test consumers. Kubernetes renders only the
selected Pod aliases; managed Docker/Podman servers use `--add-host`; helper
containers receive test-targeted aliases. Unsupported test-process mappings
fail before execution instead of modifying the machine-wide hosts file.

When both a UID and primary GID are declared, Docker, Podman, and Kubernetes
also receive run-owned passwd/group projections. The records contain only the
root, test identity, supplementary groups, and nobody entries, are immutable
inside the workload, and make `getpwuid()`/`getgrgid()` behavior deterministic
without changing the host account database. Kubernetes owns the corresponding
ConfigMap; OCI launchers bind mode-0644 files from the retained launcher state.

Kubernetes converts `Placement(network_policy="declared")` into a
default-deny NetworkPolicy with declared ingress ports, DNS egress, and egress
to declared service dependencies. Per-endpoint exposure drives ingress:
`case` is limited to Pods bearing the case identity, `environment` accepts the
case namespace, and `host`/`external` permits the explicitly exposed port.
`network_policy="isolated"` is strict deny-all; `"open"` opts out explicitly.

TCP and UDP endpoints use the same declaration and `Service.address()` API.
Consumers inside Kubernetes receive direct Service DNS. Controller-side TCP
uses a supervised `kubectl port-forward`; UDP uses a supervised shell-free
gateway that attaches each raw datagram to the restricted filesystem sidecar,
which sends and receives it in the Pod network namespace. Gateway processes
share normal teardown and their individual logs and checksums are archived.
The same binary UDP test source is part of the local and Docker-backed
Minikube conformance paths.

Dependencies can also point back toward a managed listener. Server references
resolve to loopback locally and Service DNS inside Kubernetes, so the same
declaration supports reverse callbacks without a test-owned socket or manual
gateway. `Service.read_log()` and `follow_log()` read active Kubernetes
container output through the backend until the final checksummed archive is
written during teardown.

The Kubernetes backend records every created environment namespace UID and
reads each back immediately before teardown. If a name now resolves to a
different UID, BriXTest refuses that deletion and reports the ownership
mismatch instead of touching the replacement namespace.

## Provider-backed Rook/Ceph storage

Rook/Ceph is a built-in managed-resource provider, while the test remains free
of Kubernetes and Rook objects:

```python
ceph = resource("ceph", "rook-ceph", storage_class="rook-cephfs")
data = volume("data", kind="provider", provider=ceph.name, size=1 << 30)
origin = server("origin", command=("/server",), mounts=(mount(data, "data"),))

@case(ceph, data, origin, backend="kubernetes")
def test_storage(run):
    run.server(origin).fs.write_text("data/result", "durable")
```

The safe default discovers the Rook operator and an existing StorageClass.
`managed=True` additionally owns a case-scoped `CephCluster`, `CephBlockPool`,
and `CephFilesystem`; it requires a digest-pinned Ceph image and never opts
into all-device consumption. The provider waits on typed health status,
records external/operator and owned-object UIDs, feeds its StorageClass output
into the ordinary PVC renderer, collects final object status, UID-scoped
events, Rook Pod/container status, bounded current/previous logs, and resource
metrics, then destroys only matching owned objects in reverse order. Every
provider object is created exclusively: BriXTest refuses a same-name object
instead of modifying it. An atomic run-owned UID journal permits
`KubernetesProviderObjects.orphans()` and `cleanup_orphans()` to recover after
an interrupted provider lifecycle; cleanup requires the original namespace,
provider, test-instance label, and object UID to match, so replacements and
unrelated objects are never reaped.

Finite Kubernetes tasks render as non-retrying Jobs with an active deadline,
declared environment, identity, RBAC, and secure credential projection. Their
phase and dependency ordering is the same as local tasks. BriXTest rejects
task outputs and mounts that cannot yet be transported back from the cluster
before creating the run root, instead of silently dropping those semantics.

An init task and long-lived servers can share a normal execution group:

```python
pod = Placement(backend="kubernetes", image=IMAGE, group="origin_stack")
seed = task("seed", command=("/seed",), phase="init", placement=pod)
origin = server("origin", command=("/origin",), placement=pod)
monitor = server("monitor", command=("/monitor",), placement=pod)
```

This produces one ordered init container followed by independently observed
`origin` and `monitor` containers. Their public `Service` objects still expose
separate endpoints, logs, commands, readiness, and evidence, while replica
records share the physical Pod UID. The equivalent local init task runs in the
normal dependency-ordered setup phase before its grouped servers start.

## Provider-managed infrastructure

`resource()` is the generic escape hatch for infrastructure with a lifecycle
that is not itself a server, task, volume, identity, or endpoint:

```python
from brixtest import case, resource

store = resource("store", "site-object-store", capacity="1Gi")

@case(store)
def test_store(run):
    endpoint = run.resource(store).outputs["endpoint"]
    assert endpoint.startswith("https://")
```

A `brixtest.resources` extension validates the declaration and returns a
side-effect-free `ProviderPlan`. Its `create` operation returns a
`ProviderInstance` with explicit ownership metadata, named outputs, and
secret-free provenance. BriXTest waits for readiness, makes typed
`store.ref("endpoint")` values available to consumers, archives provider
collection data, and destroys owned instances in reverse order. Readiness
failure rolls back the newly created instance; collection failure is reported
but cannot suppress destruction. Providers can verify the whole lifecycle
with `brixtest.testing.check_managed_resource_provider_contract`.

On Kubernetes, `context.kubernetes()` exposes only namespace-confined,
ownership-checked operations: `apply()` (with exclusive-create semantics),
`get()`, `discover()`, `observe()`, `delete()`, `orphans()`, and
`cleanup_orphans()`. `observe()` is the standard path for correlating an
object UID with events and, when given an exact Pod label selector, container
status, logs, and `kubectl top` output. These records enter the same
content-addressed evidence archive as workload evidence.

## Service filesystem operations

`Service.fs` removes transport and encoding boilerplate from server
filesystem assertions:

```python
service = run.server("origin")
service.fs.mkdir("state", exist_ok=True)
service.fs.write_bytes("state/payload", b"\x00\xff")
assert service.fs.read_bytes("state/payload") == b"\x00\xff"
assert service.fs.stat("state/payload")["size"] == 2
```

The facade supports `stat`, `list`, text and byte reads/writes, `mkdir`,
`remove`, `chmod`, `chown`, confined symlinks, and `user.*` xattrs. Local and
OCI services use native operations over the service work directory and
declared mount roots. Kubernetes uses a restricted, digest-pinned Python
sidecar sharing those same declared volumes; a framed raw-byte protocol keeps
binary data out of shell arguments and removes base64 workarounds from tests.
Traversal, root removal, and symlinks escaping the declared roots are rejected.
Mutations and resulting SHA-256 values are written to the case evidence
journal on every backend.

## Planning and evidence

The normalized plan contains versioned nodes and explicit ordering, readiness,
co-location, connectivity, consumption, production, placement, identity,
mount, and reverse-teardown edges. It also records effective declarations,
capability requirements, and stable fingerprints. It is archived as
`resource-plan.json`. Task results, individual
stdout/stderr logs, task-output checksums, volume records, filesystem
operations, selected backend, and the graph are correlated by attempt ID in
`summary.json` and the evidence journal.

Planning is deliberately strict. Cycles, a setup task depending on a running
server, a server depending on a finalizer, conflicting execution groups, or a
resource/backend capability mismatch fail before mutation. The diagnostic
names the resource, missing capability, selected backend, and the capabilities
that backend provides.

Runtime realization is transactional. If preparation or startup fails after
some servers or provider resources exist, BriXTest runs finalizers, stops the
backend in reverse order, collects the partial state, destroys providers in
reverse order, closes credentials, and reaps every supervised process before
returning the complete setup error.

`brixtest design tests/` performs pytest collection only and prints each
effective graph fingerprint, node backend, inferred requirements, missing
capabilities, and typed edge. It does not create any planned resource.

## Address families

Local endpoints with `family="ipv6"` reserve and probe a real IPv6 loopback
socket. `family="dual"` reserves one IPv6 socket with dual-stack behavior and
verifies that IPv4 and IPv6 use the same port. `Service.address()`,
`Service.endpoint()`, typed role host references, URLs, plans, and evidence all
retain the effective per-role host; IPv6 URLs are bracketed automatically.
Docker and Podman preserve these semantics through their required host network.
Kubernetes renders IPv4/IPv6 `SingleStack` or `RequireDualStack` Service policy
and supplies per-role wildcard bind addresses inside the Pod; `family="any"`
deliberately leaves Service family selection to the target cluster.
