# BriXTest capability expansion plan

Status: implemented and validated
Scope: BriXTest only  
Compatibility target: existing public API remains source-compatible

Landed slices: typed plans and capability diagnostics; supervised local tasks
and volumes; confined `Service.fs`; real local IPv6/dual-stack endpoints;
Kubernetes replicas, PVC/emptyDir/host volumes, ServiceAccount/RBAC/POSIX
identity rendering, dependency-derived NetworkPolicy rendering, bounded
Kubernetes task Jobs, task-output binary capture, and transactional typed
resource providers. Services now expose immutable local/Kubernetes replica
records while preserving their stable load-balanced endpoint; Kubernetes
teardown captures per-container current/previous logs, status, restarts,
exits, events, and available resource metrics. Local binary captures and
command-line overrides can now become content-addressed run-owned OCI images
that are loaded into Docker-backed Minikube or pushed to a configured remote
registry with manifest/layer/SBOM and delivery evidence. Project configuration
and suite profiles can provide digest-pinned base images and registry prefixes
without changing test declarations. Every milestone and acceptance box below
is backed by executable contracts, public examples, retained evidence, or live
Docker-backed Minikube validation.

Helper supervision now also uses an explicit liveness/cancellation channel.
The controller reaps a helper process tree on either its case deadline or a
stale heartbeat, retaining the termination reason and all partial output.

Typed references are now projected for their actual consumer. In-cluster
servers, tasks, and tools receive Service DNS, container paths, and projected
artifact paths; controller-side consumers receive loopback/forwarded endpoints
and retained host paths. A missing safe representation fails before execution
instead of leaking a controller path into a container or pod.

Capability publication is now component-specific across every built-in case
backend, server launcher, tool executor, artifact provider, native filesystem
transport, and OCI image pipeline. The extension registry also reserves
versioned volume, identity, transport, and image contracts, so a component
cannot inherit unrelated capabilities from a same-named backend.

Rerun records now retain content-addressed copies of every captured executable
and selected library. Binary declarations may also map dynamically loaded
runtime data to exact absolute image paths; those files are captured before
startup, checksummed in the binary manifest/SBOM, placed in generated OCI
rootfs layers without allowing path conflicts, and archived for exact reruns.
`brixtest rerun` transports those immutable identities to the helper, verifies
every checksum while recapturing, and rejects a changed resource-graph
fingerprint before creating the run root.

Kubernetes helper isolation is now a first-class pytest execution boundary.
The controller produces a content-addressed selected-test/BriXTest/dependency
bundle, streams it into a locked-down non-retrying Job, applies the declared
ServiceAccount and Secret-backed environment, and restores reports, tracebacks,
logs, run evidence, and metrics through a versioned framed transport. Absolute
deadlines force-delete the Pod/Job/Secret; the Docker-backed Minikube reference
target can verify and load an already cached digest without a registry pull.
The bundle follows installed distribution metadata transitively, includes
portable project config assets, and is retained as a checksummed session object.

`Service.fs` now uses the same public facade on process, OCI, and Kubernetes
servers. Docker and Podman share only the run-owned work directory and declared
mount roots at identical paths; Kubernetes injects a restricted digest-pinned
Python sidecar sharing only the server volumes. The sidecar protocol frames raw
bytes and structured metadata directly, so tests never need shell quoting or
base64. Local contracts and the live Docker-backed Minikube case run identical
binary read/write/stat/list assertions, and every mutation remains correlated
with its resulting checksum in the evidence journal.

The normalized evidence layer now promotes every effective resource-graph node
and typed edge from retained provenance into independently queryable entities.
SQLite has dedicated node, edge, and test-to-resource tables; Parquet,
OpenSearch/Elasticsearch bulk data, OTLP JSON, and the self-contained HTML
report expose the same records. Existing schema-v2 readers remain compatible
because this is an additive entity/table expansion.

Interactive tools now use one real, resized controller PTY with combined live
streaming, bounded durable capture, declared input, and process-group deadline
termination. Docker and Podman receive native interactive/TTY flags;
Kubernetes tool Pods declare stdin/TTY and are attached through the same PTY
transport before their logs and exit status are archived.

Declared device volumes and propagated mounts now have strict native
translations. Docker and Podman validate character/block devices and emit
least-scope device plus `rslave`/`rshared` bind options; Kubernetes emits typed
device `hostPath` and native mount-propagation fields. Unsupported process
plans fail capability negotiation, and container teardown owns the propagated
mount lifetime.

Server identity declarations now reach every built-in server launcher. Direct
processes use `setpriv` with no-new-privileges and bounded capabilities;
Docker/Podman drop all capabilities before adding the declared allow-list and
translate numeric IDs/groups. Podman additionally renders arbitrary UID/GID
maps, while Docker, process, and Kubernetes paths reject unsupported user-map
semantics before spawning the workload.

Fully specified OCI/Kubernetes numeric identities now receive deterministic
run-owned passwd and group projections as well. This makes libc NSS lookup
agree with the enforced UID/GID and supplementary groups without modifying the
host account database; the generated records and their owning ConfigMap or
launcher paths are retained with the case.

The identical identity translation now covers declared clients/tools and
finite tasks as well as servers. A typed immutable identity catalog crosses the
versioned executor boundary, missing identities fail before invocation, and
results retain the author's argv rather than exposing the internal privilege
wrapper.

Materialized token authorities now issue from current state and rotate
HS256/ES256/RS256 signing versions in place, including public JWKS updates.
TLS and VOMS/GSI authorities revoke only named leaf identities and atomically
republish their CRLs. A redacted JSONL authority journal retains issuance,
rotation, revocation, version, and checksum evidence under the case archive.
Managed service authorities also expose bounded `available()`, `stop()`, and
`start()` operations. Kerberos restarts from its retained realm database and
endpoint, permitting explicit outage/recovery tests without an unmanaged
process.

Token recipes can now select a supervised managed authority and deterministic
key rotation on restart. The helper keeps one stable allocated endpoint, serves
live OIDC discovery and public-only JWKS through exact read-only routes, records
its request log, and never exposes private keys, shared secrets, or mutation
operations over HTTP.

Authentication is now normalized into the same pre-mutation resource graph as
workloads and storage. Role-scoped issued-material nodes carry refresh and
revocation policy; typed issue/refresh/revoke/consume edges link them to their
authority and exact server/client consumers without serializing passwords or
shared secrets.

Process servers, clients, and tasks now honor the same arbitrary UID/GID map
declarations as Podman through a supervised shell-free user-namespace helper.
Map ranges and target coverage are validated before planning; the helper
unshares first, applies only `newuidmap`/`newgidmap`, then releases the child
through the normal process-group supervisor. Docker and Kubernetes continue to
reject mappings they cannot faithfully express.

Kubernetes default-deny ingress is now derived per endpoint from `case`,
`environment`, `host`, or `external` exposure, while egress remains limited to
declared dependencies and DNS. Completed summaries also contain one normalized,
checksummed network realization spanning environments, DNS/rDNS records,
dependency routes, policies, replica/internal/external addresses, gateways,
protocols, families, and allocations.

Endpoint address families now translate through every server runtime. Process
servers use real loopback sockets, Docker and Podman preserve them through host
networking, and Kubernetes renders native single-stack or required dual-stack
Service fields plus per-role Pod bind addresses. Unspecified families retain
the cluster default rather than imposing an accidental address policy.

UDP now follows the same endpoint and `Service.address()` surface as TCP.
Local and host-networked OCI servers are reached directly; Kubernetes
consumers receive Service DNS and controller consumers use a supervised,
shell-free binary datagram gateway through the restricted Pod sidecar. The
identical captured-Python UDP declaration passes locally and on the dedicated
Docker-backed Minikube profile, with gateway logs archived and checksummed.

Host mappings now distinguish deterministic framework lookups from explicit
physical libc/NSS requirements. Role-scoped mappings render as Docker/Podman
`--add-host` entries or Kubernetes `hostAliases` for servers, clients, and
remote helpers; impossible process-helper requests and forward-only hosts-file
policies fail before launch. The live Minikube case proves forward and reverse
`getent` lookups from both managed server and client Pods.

Kubernetes managed-resource providers now participate in the same interleaved
task/provider lifecycle as local runs. Provider implementations receive a
post-plan, namespace-confined object adapter with automatic ownership labels,
UID capture, replacement-safe deletion checks, and evidence events. Workloads
are quiesced before provider collection/destruction, and the namespace is
deleted last, so custom-resource providers do not depend on raw manifest data
in normal test declarations or lose their evidence during teardown.

Provider object creation is now exclusive rather than replacement-capable.
An atomic intent/UID journal permits crash-time orphan discovery and cleanup,
but deletion proceeds only when the namespace, provider owner, test-instance
label, and live Kubernetes UID all match. The same adapter collects UID-scoped
events plus selector-scoped Pod status, current/previous logs, and resource
metrics; the Rook/Ceph provider correlates these records with its operator,
StorageClass, custom-resource, and consuming-storage identities.

Realized network and infrastructure state is now promoted into normalized
evidence entities. Internal/external endpoints, gateways, DNS, routes,
policies, environments, replicas, provider objects, and storage identities
remain individually queryable in SQLite and every streaming/columnar/search
export, while typed graph nodes retain identities, RBAC, images, volumes,
tasks, and authorities.

The built-in `rook-ceph` provider now offers safe external discovery and an
explicit managed mode for case-owned CephCluster, block-pool, and CephFS custom
resources. Provider-backed `Volume` declarations consume its StorageClass
output through the normal PVC/mount renderer. Operator, StorageClass, custom
resource, and health identities are collected without Kubernetes objects in
test declarations; managed Ceph images must be digest pinned and device use is
opt-in.

Kerberos authorities now retain one local realm database while projecting a
separate Kubernetes client profile and a case-owned KDC Deployment/Service.
BriXTest snapshots the KDC, loader, libraries, KDB/event plugins, and realm
seed; builds and loads a content-addressed minimal image; exposes the allocated
port over TCP and UDP; derives server egress policy; coordinates local/remote
stop and restart; and archives KDC logs, Pod status, events, object UIDs, and
image evidence before namespace teardown. KDC seed Secrets exclude ticket
caches and service keytabs, while server/client Secrets continue to receive
only their declared role material.

pytest-xdist workers now publish their complete immutable topology plans to a
controller-owned broker before execution. The broker merges global
class/module/package/session pools, supervises them independently of attempt
helpers, and returns resolved services through authenticated size-bounded Unix
IPC. Two workers consume one physical session server and one correlated log;
`scope="worker"` is the explicit opt-in for per-worker instances. Worker exit
does not transfer ownership, and Linux parent-death handling unwinds broker
pools if the pytest controller disappears. Pool fingerprints now include
captured binary runtime-data contents as well as executables and libraries.

Kubernetes rendering now completes the typed workload set without exposing
manifest dictionaries in tests. Persistent mounted services become
StatefulSets with a dedicated headless identity service while retaining the
normal load-balanced `Service`; stateless services remain Deployments, finite
tasks remain Jobs, and client tools remain Pods. `Lifecycle.shutdown_command`
becomes an exact-argv `preStop` exec hook, and restart, signal, rollout, and
teardown target the realized workload kind. Every applied object is labelled
and journalled with its resource-graph node and unique test-instance identity.

Shared-service health loss before helper launch is now converted into a normal
failed attempt instead of a pytest internal error. The attempt, shared pool,
physical server instance, single log object, exit status, and controller trace
remain linked, while unrelated consumers are never launched against a known
dead service.

The pre-mutation capability contract now exercises unsupported external
networking, IPv6, PTY execution, devices, user namespaces, storage quota, and
every process-placement policy as one matrix. Controller construction leaves
no run root behind on rejection. This also found and removed the last ignored
process field: mutable-image policy is now rejected because a native process
does not consume an image.

Kubernetes execution groups now compile from the existing
`Placement(group=...)` field into one multi-container Deployment or
StatefulSet. Each server retains its own Service, readiness probe, lifecycle
hook, command surface, bounded log stream, status, metrics, and evidence links,
while all members resolve to the same Pod identity. Grouped init tasks become
dependency-ordered init containers; ordinary finite tasks remain Jobs.
Incompatible replicas, identities, scheduling, client grouping, and impossible
in-group startup ordering fail before the run root exists. Local grouped init
tasks use the normal ordered pre-server phase. The advanced examples cover the
init-container, sidecar, Job, three-replica, RBAC, NetworkPolicy, and PVC
surface without importing Kubernetes APIs.

The same group declaration now has native local and OCI translations. Process
members share the helper's supervised host isolation realm. Docker and Podman
create one digest-pinned anchor container, then start each additional member
as a separately supervised foreground `exec` with its own environment file,
readiness probe, bounded log, shutdown hook, and evidence identity. Teardown
stops member executions before removing the one owned container. Conflicting
image, identity, limits, labels, options, device, or propagation policy is
rejected during controller construction.

The opt-in privileged examples now exercise the physical behavior rather than
only declaration shape. The FUSE case waits for the propagated mount, performs
a binary-safe round trip through `Service.fs`, and relies on the declared
in-container unmount hook. The user-namespace red-team case changes `fsuid` to
a second mapped identity, proves a private owner file is denied, and proves a
supplementary-group-only file remains readable.

Persistent-service restart now refreshes public replica records after the
rollout instead of returning stale Pod UIDs. The Rook/Ceph example snapshots
the stored content checksum, rolls a three-replica StatefulSet, proves every
Pod identity was replaced, and verifies both bytes and checksum survived on
the stable claim. Unit contracts separately pin claim/headless identities and
the distinction between a stable Service port and a rescheduled Pod UID.

Named `Environment` declarations now resolve to immutable Kubernetes
context/namespace/DNS targets. Servers, grouped workloads, Jobs, tool Pods,
identity and credential projections, observations, commands, filesystems,
TCP/UDP gateways, and teardown all use the owning target. Same-context
cross-namespace references become fully qualified Service DNS plus
test-instance-scoped NetworkPolicy; cross-context dependencies fail before
mutation because no implicit inter-cluster transport is installed. Every
namespace has its own captured UID and ownership record, and teardown verifies
each live UID before deletion. The opt-in Docker-backed Minikube example needs
only two environment declarations to exercise a cross-namespace HTTP chain.

Validation on 2026-08-23 completed the standalone unit, contract, API,
documentation, evidence, and five-metric complexity suite (1,202 passed, 9
environment-dependent skips). The healthy Docker-backed `brixtest` Minikube
profile passed the live auth/DNS/PTY/filesystem cases, the captured dynamic
nginx case, and the same-context two-namespace environment case; the
managed-namespace and managed-Pod audits were empty afterward. The dynamic
nginx candidate passed the unchanged 20-example local suite. A separately
built ASan nginx executed those same 20 test bodies and correctly made the run
fail during evidence finalization on genuine symbolized LeakSanitizer findings;
the framework retained the logs, SQLite archive, report, and exact rerun record
instead of hiding the candidate defect.

Shared-pool identity now includes every server-effective environment, image,
identity, volume, auth stack, host mapping, binary, credential, parameter, and
rendered configuration input. Changing one of those inputs creates a distinct
pool; unrelated client-only resources remain excluded.

This document tracks the work required to make BriXTest capable of expressing
the privileged, distributed, authentication, storage, networking, and
Kubernetes tests currently found in the raw Python and prototype Kubernetes
suites. A checked item must meet its stated acceptance criteria; partial or
experimental implementations remain unchecked.

## Architectural constraints

- [x] **BXP-001** Keep pytest responsible for collection, parametrization,
  fixtures, selection, reporting, skip/xfail semantics, and xdist scheduling.
- [x] **BXP-002** Keep every managed test body in a supervised helper, never in
  the controller interpreter.
- [x] **BXP-003** Keep declarations immutable, import-safe, and side-effect-free
  during collection.
- [x] **BXP-004** Compile all declarations into one typed, backend-neutral
  resource graph before any backend creates resources.
- [x] **BXP-005** Reject unsupported semantics during planning; no backend may
  silently ignore a declaration.
- [x] **BXP-006** Keep ordinary tests free of Docker, Podman, runc, Helm,
  Kubernetes, or transport orchestration.
- [x] **BXP-007** Keep BriXTest standalone: production code, tests, templates,
  images, and documentation must not import files outside `brixtest/`.
- [x] **BXP-008** Preserve existing declarations and defaults. New declarations
  must be optional and positional resource inference must remain available.
- [x] **BXP-009** Record every planned and realized resource in the evidence
  model without exposing secret contents.
- [x] **BXP-010** Keep Python files below 500 lines and within the repository's
  CCN, Cognitive, NPath, Halstead, and nesting limits.

## Intended public surface

The normal path remains `@case`, `server`, `tool`, `artifact`, `binary`, and
`run`. Add only the following general resources:

- [x] **BXP-020** Add `Environment` and `environment()` for explicit execution
  realms, namespaces, clusters, DNS domains, and network isolation.
- [x] **BXP-021** Add `Volume` and `volume()` for temporary, persistent, shared,
  host, device, and provider-backed storage.
- [x] **BXP-022** Add `Identity` and `identity()` for UID/GID/groups, user
  namespaces, capabilities, ServiceAccounts, and abstract permissions.
- [x] **BXP-023** Add `Task` and `task()` for supervised build, preparation,
  init, bootstrap, and finalization actions.
- [x] **BXP-024** Add `Resource` and `resource()` as the versioned provider path
  for infrastructure that is not a process, identity, network, or volume.
- [x] **BXP-025** Add `kubernetes()` helper isolation beside `process()`,
  `docker()`, `podman()`, `runc()`, and `nsenter()`.
- [x] **BXP-026** Extend `Endpoint` with address family and exposure policy.
- [x] **BXP-027** Extend `Placement` with environment, execution-group, identity,
  and typed scheduling/network policy.
- [x] **BXP-028** Extend `Mount` with `Volume` sources and mount propagation.
- [x] **BXP-029** Extend `Server` with replica count while keeping one replica as
  the default.
- [x] **BXP-030** Extend `Binary` so a local capture can be materialized into an
  immutable OCI image without changing its declaration.
- [x] **BXP-031** Add managed-authority and rotation options to authentication
  recipes.
- [x] **BXP-032** Add `Service.fs` and replica inspection without changing the
  existing endpoint, log, signal, restart, or command methods.
- [x] **BXP-033** Add issuance, revocation, rotation, and availability controls
  to materialized authentication stacks.
- [x] **BXP-034** Update the machine-readable API manifest, stubs, API reference,
  introspection contract, and compatibility tests for every public addition.

## Normative design target

This section is the architectural source of truth behind the milestone list.
It records how the capabilities compose, which public declaration owns each
choice, and where backend-specific behavior must remain hidden. The objective
is not to make every internal mechanism public. It is to make every useful
test intent expressible through a small, regular vocabulary.

A BriXTest case has two deliberately different layers:

1. **Declaration layer:** immutable values describing desired servers,
   clients, tools, tasks, inputs, identities, networks, storage, credentials,
   authorities, observations, and execution policy.
2. **Runtime layer:** the single `run` fixture exposing resolved services,
   commands, files, metrics, spans, attachments, and managed-authority
   controls after the selected backend has realized the declaration.

Backend handles, subprocess objects, container IDs, Kubernetes dictionaries,
temporary port reservations, credential-generation commands, and cleanup
callbacks are implementation details. They may appear in retained evidence,
but they must not be required in an ordinary test body.

### Test-author experience target

The common HTTP-server case should require only a server declaration, a client
declaration, and the behavior assertion:

```python
from brixtest import case, execution, http_endpoint, http_probe, server, tool

origin = server(
    "origin",
    command=("python", "-m", "http.server", "{http_port}"),
    endpoints=(http_endpoint(),),
    probe=http_probe(),
)
get = tool("get", execution=execution("curl", "--fail", origin.url("http")))


@case(origin, get)
def test_origin(run):
    assert run.tool(get).run().returncode == 0
```

The snippet shows the minimum local authoring shape. Once a declaration also
names a captured binary or digest-pinned image valid on its selected targets,
changing the profile from local execution to Docker-backed Minikube must not
require a conditional, a rewritten URL, a Kubernetes object, or a different
assertion. A test should grow only when the behavior being tested grows: TLS
adds an authority declaration, persistence adds a volume, a callback adds an
endpoint or dependency, and a privileged filesystem test adds an
identity/device/mount policy.

### Rules for minimizing the public surface

- Prefer adding an optional keyword to an existing immutable value over adding
  a new top-level constructor.
- Prefer a typed reference returned by the declaration that owns the value over
  a new free-standing placeholder syntax.
- Prefer `execution()` for reusable command policy; retain `command()` only as
  its compatibility spelling.
- Prefer `tool()` for reusable invocations. `client()` remains the equivalent
  server/client vocabulary where naming the actor helps the test read clearly.
- Prefer `resource()` only for infrastructure that is not naturally a server,
  task, volume, identity, endpoint, artifact, binary, credential, or authority.
- Prefer project profiles for site policy, image registries, cluster contexts,
  and binary overrides. Do not repeat those choices in every test.
- Prefer extension factories that return built-in declarations. A runtime
  extension is justified only by genuinely new planning, placement, execution,
  observation, materialization, or export behavior.
- Never add a `docker_*`, `podman_*`, `kubernetes_*`, or `minikube_*` variant of
  a general server/client capability. Extend the graph and translators instead.
- Never accept a raw manifest dictionary, shell fragment, implicit host path,
  or unowned cleanup callback as a shortcut around the resource model.

## Complete declaration option catalogue

The catalogue below describes the intended use of every major public option.
Constructor signatures remain enforced by `api_contract()` and the public API
tests; this section explains how those options compose.

### Case options

| Option | Meaning | Design rule |
|---|---|---|
| positional resources | Infer and register declarations by type | Preferred concise form |
| `resources=` | Explicit mixed resource sequence | Useful for generated catalogues |
| `servers=` | Long-lived managed services | Equivalent to positional servers |
| `clients=` | Named client actors and tools | Equivalent to positional clients |
| `artifacts=` | Generated, copied, or provider-produced inputs | Captured before consumers start |
| `binaries=` | Immutable executable/library captures | Overrides apply before capture |
| `credentials=` | Custom role-scoped secret material | Never serialized in clear text |
| `auth=` | Token, TLS, VOMS/GSI, or Kerberos recipes | Authorities own issuance lifecycle |
| `hosts=` | Declared forward/reverse hostname mappings | Physical NSS is explicit |
| `environments=` | Named execution realms | Test resources refer by name |
| `volumes=` | Managed storage declarations | Ownership follows the case graph |
| `identities=` | POSIX, namespace, capability, or RBAC identities | Enforcement is backend translated |
| `tasks=` | Build/preparation, grouped init, or finalization tasks | Always supervised and bounded |
| `managed_resources=` | Provider-managed infrastructure | Uses versioned lifecycle contracts |
| `observe=` | Automatic collector declarations | Empty disables default collection |
| `parameters=` | Immutable case parameters | Available through typed references |
| `warmup=` | Independent non-analytical attempts | Retained but excluded from decisions |
| `trials=` | Independent measured attempts | Stop at first failed attempt |
| `timeout=` | Whole-attempt absolute deadline | Includes setup, body, and teardown |
| `backend=` | Case-resource placement default | Independent of helper isolation |
| `isolation=` | Test-helper isolation | Process, nsenter, OCI, or Kubernetes |
| `keep=` | Run-root retention policy | Compact evidence survives regardless |

The positional form is canonical for hand-written tests because it keeps the
topology visually close to the assertion. Keyword collections remain valuable
for migrations, generated suites, and code that assembles a case definition.

### Execution options shared by clients and tools

`Execution` is the common shell-free invocation policy. `Client`, `Tool`, and
`run.command()` must converge on the same result and capture semantics.

| Option | Meaning | Required behavior |
|---|---|---|
| `argv` | Exact argument vector, including typed references | Never evaluated by a shell |
| `env` | Per-invocation environment overlay | Merged deterministically and archived by presence/hash |
| `cwd` | Declared working directory/reference | Confined to a projected run location |
| `input` | Text or binary stdin | Preserved without lossy conversion |
| `encoding` | Text decoding policy | Returned strings use the declared codec |
| `timeout` | Per-call deadline | Kills the complete invocation process group |
| `expected_exit_codes` | Accepted status set | Unexpected values fail with retained output |
| `output_limit` | Bounded stdout/stderr capture | Enforced while draining, not afterward |
| `mode` | `capture` or `pty` | PTY uses one real resized terminal |
| `retries` | Bounded repeat policy | Every attempt is retained and correlated |

`client()` and `tool()` additionally accept `mounts`, `logs`, `placement`,
named binary dependencies, metadata, and either `execution=...`,
`command=...`, or the concise `binary=..., args=...` form. Mixing command forms
is a declaration error rather than a precedence rule.

### Server options

| Option | Meaning | Backend-neutral contract |
|---|---|---|
| `command` / `execution` / `binary` + `args` | How to launch the server | Exact argv with typed projections |
| `config` / `configs` | Inline, static, or template-derived files | Rendered contents and checksums retained |
| `ports` | Compatibility role names | Normalize into endpoint records |
| `endpoints` | Protocol, scheme, family, exposure, and port intent | Resolve per consumer/environment |
| `env` | Server-only environment overlay | Applied before the first instruction runs |
| `readiness` / `probe` | Startup acceptance behavior | Bounded, logged, and independent per server |
| `depends_on` | Startup/connectivity dependencies | Drives ordering, references, and policy |
| `binaries` | Additional captured executables | Immutable for the instance lifetime |
| `image` | Explicit workload image | Digest pinned unless opt-out is explicit |
| `scope` | `case`, `function`, `class`, `module`, `package`, `session`, or `worker` | Controls broker ownership and pooling |
| `mounts` | Config, artifact, credential, volume, device, or temporary projections | Least-scope and read-only by default |
| `lifecycle` | Backgrounding, shutdown, timeout, expected exit | Backend-specific control, same semantics |
| `placement` | Backend, environment, image, group, identity, scheduling, policy | Compiled before mutation |
| `logs` | Capture, bound, tail, and redaction policy | Stored for passing and failing cases |
| `cwd` | Working directory | Resolved in the server's environment |
| `metadata` | Bounded secret-free descriptive values | Evidence only; never changes hidden behavior |
| `replicas` | Desired service replica count | One stable service plus replica records |

Servers that omit configuration still receive a uniform empty-config evidence
record. Multi-file configurations identify one primary `{config}` and expose
every destination through a typed/config placeholder. The exact completed
content, destination filename, source identity, and SHA-256 participate in
pooling and reruns.

### Configuration options

| Declaration | Use | Contract |
|---|---|---|
| `server_config(content, filename=...)` | Test-completed text held in memory | Content is the authority |
| `static_config(path, destination=...)` | Checked-in file used unchanged | Source is copied and verified |
| `template_config(path, destination=..., values=...)` | Checked-in template with declared substitutions | Missing/unknown values fail before launch |
| `configs(*files, primary=...)` | Multi-file server configuration | All files share one captured identity set |
| `load_template(path)` | Let test code complete a template explicitly | Returned text can feed `server_config()` |

Templates must remain plain data. Rendering may use parameters and typed
references, but it may not execute Python, invoke a shell, read undeclared host
state, or allocate resources. Equivalent final content must yield equivalent
config identity even when loaded from different source paths.

### Artifact and binary options

| Declaration | Purpose | Important options |
|---|---|---|
| `noise()` | Reproducible high-entropy input | byte size, seed, filename |
| `file_artifact()` | Immutable capture of an existing file | source path, filename |
| `text_artifact()` | Small text input | text, filename |
| `artifact()` | Versioned provider-produced input | kind, filename, provider options |
| `binary()` | Executable/image declaration | path, libraries, discovery, image path, runtime files |

Noise generation must be streaming, deterministic, and practically
incompressible without pretending to be a secret random source. File and
binary capture must compare source metadata and checksums around the copy so a
concurrent rebuild cannot produce a mixed input.

`Binary.runtime_files` maps declared host inputs to exact runtime destinations.
It covers dynamic loader/NSS data, daemon account databases, configuration
fragments, or other immutable files required by a captured executable. Runtime
files are checksummed, placed in generated OCI layers when required, included
in the SBOM/manifest, and rejected on destination conflicts.

### Task options

| Option | Meaning | Translation |
|---|---|---|
| `command` | Exact finite argv | Process, one-shot container, or Job/init container |
| `phase` | `prepare`, grouped `init`, or `finalize` phase | Determines legal dependencies and lifecycle order |
| `depends_on` | Required resources/tasks | Topologically ordered |
| `env` | Task-specific environment | Applied before invocation |
| `outputs` | Named files produced for later consumers | Captured and checksum verified |
| `timeout` | Absolute task deadline | Terminate complete task process/container |
| `binaries` | Immutable executable inputs | Projected before execution |
| `mounts` | Declared inputs/storage | Same mount semantics as workloads |
| `placement` | Environment, image, identity, execution group | Capability checked before creation |
| `metadata` | Secret-free annotations | Retained with task evidence |

Task outputs may feed later artifact, binary, image, server, or client nodes.
The graph must make this production edge explicit; a consumer cannot guess a
task-local filesystem path.

### Endpoint and probe options

Endpoints carry a role/name, protocol, optional requested port, URL scheme,
address family, exposure policy, and bounded metadata.

Supported protocol intent includes TCP and UDP. HTTP and HTTPS are schemes over
TCP, not separate transport implementations. Address-family intent is `any`,
IPv4, IPv6, or required dual stack. Exposure distinguishes case-only,
environment, host, and external reachability. The same role may therefore
resolve to different internal and external address records without losing its
identity.

Probes cover disabled/immediate-equivalent readiness, TCP connection,
HTTP/HTTPS response, exact argv execution, and bounded log-pattern observation. Probe options include the
endpoint role, path/command/pattern, accepted HTTP statuses, timeout, and
interval. Readiness success never proves continued health: long-lived server
monitoring remains active after startup.

### Placement and environment options

`Environment` names an execution realm with backend, Kubernetes context,
namespace, address family, DNS domain, isolation policy, and provider-specific
options. `Placement` selects an environment and refines workload behavior with
backend, image, labels, node selector, security context, resource limits,
provider options, mutable-image policy, execution group, identity, and network
policy.

Environment declarations answer **where a resource exists**. Helper isolation
answers **where untrusted Python test code executes**. These axes must remain
independent. For example, a Podman-isolated helper may operate a Kubernetes
server, and a Kubernetes-isolated helper may consume a controller-supervised
session service.

An execution group describes required co-location, not a Kubernetes Pod. It
translates into a shared local isolation realm, one OCI container realm, or one
multi-container Kubernetes workload. The planner rejects conflicting images,
replica counts, identities, limits, scheduling, devices, propagation, or
startup ordering before realizing the group.

### Volume, mount, and identity options

Volumes cover temporary, persistent, shared, host-backed, device, and
provider-backed storage. Their declaration includes size, source, access mode,
persistence, provider, and bounded provider options. A mount selects the
source, target, read-only policy, kind, and propagation.

Identity covers numeric UID/GID, supplementary groups, user-namespace policy,
UID/GID maps, Linux capabilities, abstract permissions, and Kubernetes
ServiceAccount identity. Fully specified numeric identities also generate
deterministic run-owned passwd/group projections where the backend can enforce
them.

The following rules are mandatory:

- A mount target is a confined relative logical path. Each backend projects it
  beneath a run-owned absolute root inside the process, container, or Pod.
- Host paths and devices require explicit declarations; they are never inferred
  from an argv string.
- Character/block devices and propagation require backend capabilities and
  least-scope translation.
- Linux capabilities start from drop-all and add only the declared allow-list.
- User maps must cover every requested runtime identity and be validated before
  any namespace helper starts.
- ServiceAccount permissions become namespaced RBAC objects derived from typed
  abstract permissions, not arbitrary role manifests in tests.

### Custom credentials and managed authentication

Custom credentials cover literal/source content, checksums over declared
artifacts, and signed payloads. Every credential declares its destination,
environment variable behavior, target roles, and mode. Destinations are
confined; unsafe modes and ambiguous standard environment variables are
rejected.

Authentication recipes remain specialized factories because they describe
coherent authorities rather than loose files:

| Recipe | Managed material and behavior |
|---|---|
| `token_auth()` | HS256/ES256/RS256 issuance, public verification material, optional OIDC/JWKS service, rotation |
| `tls_auth()` | Disposable CA, trust directory, SAN host/client identities, CRL and revocation |
| `voms_auth()` | CA/CRL, host/user/VOMS identities, proxy, FQANs, LSC and vomses material |
| `kerberos_auth()` | Realm database, KDC, principals, keytab, cache, TCP/UDP service, stop/start |

Authority material is distributed by consumer role. Servers receive only the
verification or service identity needed to authenticate clients; clients and
the test helper receive only their declared credentials. Private keys, shared
secrets, bearer tokens, ticket caches, and passwords must not appear in the
resource plan, replay command, remote index, or secret-free summary.

### Observation options

Built-in collectors are `process_tree()`, `prometheus()`,
`structured_logs()`, and `kubernetes_events()`. A generic `collector()` names a
versioned extension. Collector declarations specify a bounded interval and
kind-specific options; they must remain inert during collection.

The metric surface intentionally stays small:

- `gauge()` for a point or final value;
- `count()` for an increment or amount;
- `observe()` for distribution members;
- `timer()` for a timed context;
- `tag()` for bounded non-numeric context;
- `record()` for the underlying extensible numeric form.

Names are stable dotted identifiers, values are finite, units are explicit,
and labels are bounded low-cardinality scalars. Metric budgets use pytest
markers and `last`, `min`, `mean`, `p95`, `max`, or `sum` aggregation.

## Runtime interaction surface

The `run` fixture is the resolved view of the effective resource graph. Test
authors should not need a backend context or manager object.

| Intent | Runtime operation |
|---|---|
| Resolve a service | `run.server(name_or_declaration)` |
| Resolve a named client/tool | `run.client(...)` / `run.tool(...)` |
| Execute shell-free argv | `run.command(...)` / `run.execute(...)` |
| Read input content | `run.artifact_text/bytes/json/path(...)` |
| Open an input | `run.open_artifact(...)` |
| Inspect immutable executable | `run.binary(...)` and `.verify()` |
| Inspect a credential | `run.credential(...)` and `.verify()` |
| Control an authority | `run.auth(...).issue/rotate/revoke/start/stop/available` |
| Inspect a task/output | `run.task(...)` / `run.task_output(...)` |
| Resolve managed storage | `run.volume(...)` |
| Resolve provider output | `run.resource(...).outputs` |
| Resolve declared names | `run.resolve(...)` / `run.reverse(...)` |
| Record measurements | `run.metrics` |
| Correlate an action | `run.step(...)` |
| Retain output | `run.attach*()` |
| Use test-owned scratch space | `run.workspace` |

`Service` keeps the same interface on every backend. It exposes stable and
per-replica endpoints, URL construction, captured configuration, physical log
identity, readiness/health, signal/restart/wait operations, bounded log reads,
server-side commands, and confined binary-safe filesystem operations.

`CommandResult` always contains author-visible argv, decoded stdout/stderr,
return code, elapsed time, attempt count, truncation flags, convenience line
and JSON helpers, and fluent/standard-library-style status checks. Internal
identity wrappers, namespace helpers, runtime commands, or secret env files
must not leak into its argv.

## Typed resource graph

The graph is the architectural seam that prevents these capabilities becoming
independent bolt-ons. All declarations enter the same compiler before a
backend mutates external state.

### Node kinds

The versioned graph must represent at least:

- case, attempt, environment, and helper isolation;
- server, client/tool, task, execution group, and replica intent;
- endpoint, DNS/host mapping, route, gateway, and network policy;
- configuration file/set and rendered configuration;
- artifact, binary, library, runtime file, image, layer, and task output;
- volume, mount, claim, device, and storage provider identity;
- identity, NSS projection, ServiceAccount, role, and binding;
- custom credential, authority, issued material, refresh/revocation policy;
- collector, metric stream, span, attachment, and log stream;
- managed provider resource and each returned named output.

Runtime realization adds typed entities for physical processes, containers,
Pods, Kubernetes objects, forwarded endpoints, provider objects, storage
identities, and shared server instances without replacing the declared nodes.

### Edge kinds

Edges must make behavior explicit rather than relying on list order or string
inspection. Required relationships include:

- `depends-on` and `starts-before`;
- `waits-for-readiness` and `monitors`;
- `co-located-with` and `member-of-group`;
- `connects-to`, `exposes`, `routes-through`, and `resolves-as`;
- `consumes`, `produces`, `mounts`, and `projects`;
- `runs-as`, `authorized-by`, and `bound-to`;
- `issued-by`, `refreshes-from`, `revokes`, and `distributed-to`;
- `realizes`, `owns`, `observed-by`, and `logged-by`;
- `shared-by` and exact test-to-resource consumer links;
- explicit reverse-order destruction dependencies.

Every edge is independently queryable in evidence. Backends may add realization
records, but they may not invent undeclared dependency or secret-distribution
edges at launch time.

### Fingerprints and identities

Stable graph fingerprints cover all effective behavior: rendered config
content, executable/runtime-file/library checksums, images, server environment,
identity, auth, hosts, volumes, placement, endpoint policy, dependencies,
parameters, and provider plans. Client-only inputs are excluded from a shared
server fingerprint unless the server actually consumes them.

Fingerprints serve four different purposes and must not be conflated:

1. declaration/effective-plan identity;
2. shared-pool equivalence;
3. content-addressed object identity;
4. exact rerun verification.

Each identity has an explicit schema version so future additions cannot
silently merge resources created under older semantics.

## Reference projection model

Typed references are resolved for the consuming graph node, not globally.

| Reference | Controller/process consumer | OCI consumer | Kubernetes consumer |
|---|---|---|---|
| server endpoint | loopback/direct or supervised forward | reachable host/direct address | Service DNS/internal address |
| artifact file | retained host path | declared bind path | projected volume path |
| artifact directory | retained artifact directory | declared directory bind | projected directory root |
| binary executable | captured host path | captured image/bind destination | immutable image destination |
| config file | rendered run path | declared config mount | ConfigMap/volume path |
| credential file | confined role path | read-only secret bind | Secret projection |
| credential content env | mode-0600 environment transport | mode-0600 env file | SecretKeyRef |
| workspace | test-owned host directory | writable run-root mount | helper writable volume |
| task output | checksum-verified captured path | projected captured output | transported/projected output |
| provider output | typed local/provider value | provider translation | namespaced provider output |

Legacy `{artifact_name}` and `{artifact_name_dir}` placeholders may project
through the same resolver for compatibility. New declarations should prefer
owner-returned typed references because they retain kind, role, and consumer
intent without parsing strings.

## Backend and isolation model

Placement and isolation form an explicit matrix rather than one overloaded
backend flag.

### Case and workload placement backends

The built-in case backends are `local`, `kubernetes`, and `minikube`. Installed
case backends may extend that set through the versioned registry. Within a
local case, individual servers and tools may select native, Docker, Podman, or
an installed launcher/executor through `Placement`. runc and nsenter are helper
isolation boundaries; they are not implied to be general built-in server
launchers.

| Placement | Long-lived servers | Tasks/tools | Primary purpose |
|---|---|---|---|
| local/process | Supervised process groups | Native supervised argv | Fast development and host integration |
| local plus Docker placement | Foreground container/exec members | One-shot containers or exec | OCI behavior with Docker engine |
| local plus Podman placement | Foreground container/exec members | One-shot containers or exec | Rootless/user-map-oriented OCI behavior |
| Kubernetes | Deployment/StatefulSet and Services | Jobs, init containers, tool Pods | Cluster-native behavior |
| Minikube | Kubernetes semantics plus local image loading/profile defaults | Same as Kubernetes | Mandatory reference conformance target |
| installed backend/launcher/executor | Contract-defined realization | Contract-defined realization | Site or product integration without test API changes |

### Helper isolation

| Isolation | Boundary | Required guarantees |
|---|---|---|
| `process()` | Fresh supervised pytest helper process | Process-tree reap and independent heartbeat |
| `nsenter()` | Helper joins declared namespaces of a target PID | Positive PID, explicit namespace allow-list |
| `docker()` | Helper in a Docker container | Digest policy, confined mounts, host reachability |
| `podman()` | Helper in a Podman container | Same transport contract, rootless compatibility |
| `runc()` | Helper in a derived OCI bundle | Original bundle unchanged, confined runtime state |
| `kubernetes()` | Helper in a non-retrying Job | Content-addressed bundle, framed transport, forced cleanup |

Unsupported combinations must be rejected during capability negotiation. A
backend is not conformant merely because it starts a process: it must preserve
input projection, stdin/PTY behavior, bounded output, cancellation, logs,
identity, evidence, and teardown semantics for every accepted field.

## Transactional lifecycle and failure model

Every case and shared topology follows one explicit state machine:

```text
declare -> validate -> plan -> allocate -> prepare -> start -> ready
        -> execute/observe -> quiesce -> collect -> destroy -> finalize
```

Planning remains side-effect free. Allocation may reserve run-owned names,
ports, paths, and ownership IDs but cannot start user workloads. Each mutating
stage appends an intent and completion event so an interrupted run can discover
which resources may require recovery.

Failure policy is uniform:

- Validation or capability failure creates no run root and mutates nothing.
- Allocation/preparation failure rolls back only completed owned allocations.
- Startup failure preserves partial logs, status, and readiness diagnostics,
  then tears down started resources in reverse order.
- Test/client failure stops the remaining trial sequence immediately, captures
  the complete traceback and streams, and proceeds through normal collection.
- Heartbeat loss or timeout snapshots descendants and forcefully terminates the
  helper/process tree or remote Pod/Job before final recovery.
- Collection failure is reported but cannot suppress resource destruction.
- Destruction failure is retained as a teardown error with ownership evidence;
  it cannot silently turn a broken cleanup into a passing test.
- Archive/export failure is visible during session finalization when the user
  explicitly selected that durable sink.

All individual tests fail fast by default. The suite-level fail-fast switch
stops scheduling after the first error while retaining the exact failed node ID
and a complete rerun record.

## Dynamic topology and pooling contract

The collected tests are the fleet inventory. There is no separate server list.
Pool derivation happens from immutable plans after collection and before shared
resource startup.

`scope="case"` and `scope="function"` create attempt-owned instances. Class,
module, package, and session scopes are controller-broker-owned pools.
`scope="worker"` is the explicit xdist-local variant. The broker owns shared
processes independently of any test helper, continuously monitors them, and
publishes only resolved `Service` records through bounded authenticated IPC.

Pooling requirements:

- Identical final template-derived content can share even when source template
  paths differ.
- Any server-effective config, binary, library/runtime file, env, identity,
  volume, auth, host mapping, image, placement, endpoint, parameter, or provider
  change creates a distinct pool.
- Multiple tests using one physical instance link to one instance record and
  one log object instead of copying the same bytes.
- A known-dead shared service fails future consumers before helper launch and
  links each failure to the same exit trace.
- The final actual consumer, not merely the final scheduled node, determines
  normal shared teardown.
- Worker/controller failure cannot transfer ownership to an unmanaged child;
  broker recovery reaps or reports every pool.

## Networking realization contract

Networking is derived from endpoints, environments, dependencies, exposure,
host mappings, and consumer placement.

The realized network record must retain:

- declared and effective address family;
- protocol, scheme, role, and allocated port;
- internal and controller-visible host/address;
- direct, forwarded, gateway, or external transport;
- namespace, context, DNS domain, Pod/replica identity;
- forward and reverse DNS/NSS records;
- dependency routes and allowed peers;
- generated NetworkPolicy identity and checksum;
- gateway/port-forward lifecycle and log identity.

Local IPv6 uses real IPv6 sockets; required dual stack verifies both families
share the intended port. Docker and Podman preserve compatible semantics
through their network translation. Kubernetes renders native Service family
policy. UDP uses the same endpoint API; when controller access needs a bridge,
BriXTest owns a supervised binary-safe datagram gateway rather than asking the
test to invoke shell/base64 plumbing.

Same-context cross-namespace dependencies resolve to fully qualified Service
DNS and derived policy. Cross-context dependencies fail before mutation unless
a versioned transport provider explicitly supplies the requested semantics.

## Workload translation contract

The graph describes workload intent; translators choose native runtime kinds:

| Intent | Local/OCI translation | Kubernetes translation |
|---|---|---|
| stateless server | Process/container member | Deployment |
| persistent server | Supervised member with persistent volume | StatefulSet plus headless identity Service |
| load-balanced replicas | Multiple supervised members/endpoints | Replica workload plus normal Service |
| init task | Ordered pre-server execution | Init container in its group |
| ungrouped finite task | Supervised process/one-shot container | Non-retrying Job |
| grouped sidecar | Shared isolation/container realm | Additional Pod container |
| interactive client | Real local/container PTY | TTY/stdin Pod attached through transport |

Every server/container member retains independent readiness, command surface,
logs, metrics, lifecycle hooks, exit status, and graph identity even when
co-located. Kubernetes objects receive graph-node, test-instance, ownership,
and provider labels. UID-aware teardown refuses to delete a replacement object
that happens to reuse a name.

## Filesystem contract

`Service.fs` is the sole test-author facade for inspecting or mutating a
server's declared filesystem roots. It supports binary/text read and write,
stat, list, mkdir, remove, chmod, chown, confined symlink, and `user.*` xattr
operations.

The implementation may use native confined operations locally, declared shared
mounts for OCI, or a restricted digest-pinned sidecar for Kubernetes. The
protocol carries raw bytes and structured metadata; tests must not need shell
quoting or base64. Traversal, root deletion, symlink escape, undeclared host
access, and unsupported privilege changes fail before mutation. Every mutation
and resulting checksum enters the evidence journal.

## Binary, image, and build pipeline contract

The binary pipeline separates author intent from immutable realization:

1. Resolve the selected declaration/profile/CLI override.
2. Capture the executable without following an unsafe replacement.
3. Capture the interpreter/loader, selected libraries, and runtime files.
4. Verify source metadata and all SHA-256 values.
5. Store content-addressed copies in the session object store.
6. Use host paths for local consumers or construct deterministic OCI layers.
7. Record manifest, layer digests, image identity, build inputs, tool versions,
   and SBOM.
8. Load the exact image into Docker-backed Minikube or push it to a configured
   content-addressed registry.
9. Verify the same identities before an exact rerun.

Build/RPM tasks may produce a new binary node, but active consumers use only
the already captured bytes. ASan, LeakSanitizer, and UBSan findings in any
managed stream become failed evidence even when the Python assertion passes.

## Evidence, metrics, analytics, and archival contract

Evidence is an append-first system of record, not a report assembled only from
successful teardown. Each attempt writes crash-resilient journal events before
the completed compact records are generated.

Required retained entities include:

- session, collected case, warmup/trial attempt, phase, and outcome;
- declared/effective resource nodes and typed edges;
- physical server pool/instance/replica and exact consumers;
- helper, process, container, Pod, Job, gateway, and provider object;
- config, artifact, binary, library, runtime file, image, layer, and SBOM;
- credential/authority public identity and redacted lifecycle events;
- endpoint, port, DNS/rDNS, route, policy, environment, and allocation;
- task/client/server stdout, stderr, log, exit, retry, and truncation metadata;
- metrics, resource samples, spans, attachments, findings, and checksums;
- start/stop/readiness/restart/rollout/cleanup timestamps and errors.

The normalized semantics remain identical across JSON, SQLite, Parquet, HTML,
OpenSearch/Elasticsearch bulk documents, OTLP JSON, S3-compatible packages, and
plugin exporters. Local original log bytes are mode-0600 and checksummed;
remote documents are recursively redacted. An explicitly requested exporter
must report item-level errors rather than silently dropping records.

Analytics include descriptive distributions, confidence intervals, relative
change, Cliff's delta, trends, Pearson/Spearman correlations, robust MAD
outliers, resource correlations, and checksum coverage. Statistical output is
evidence for investigation, never an unsupported causal claim. Performance
regression decisions require both magnitude and effect thresholds.

## Exact rerun contract

Every failure records enough information to reconstruct the experiment:

- exact pytest node ID and parameters;
- warmup/trial/attempt identity and failure phase;
- backend, helper isolation, profile, context, and namespace choices;
- effective resource graph and schema version;
- server-pool and consumer identities;
- captured executable, library, runtime-file, image, layer, and config hashes;
- non-secret environment presence/value hashes and explicit safe overrides;
- artifact, provider-plan, authority-public-state, and network fingerprints;
- seeds, deadlines, output bounds, and selected collectors;
- source/provenance identity and retained object-store references.

`brixtest rerun latest` and exact run IDs must use archived immutable bytes,
verify all checksums and the resource-graph fingerprint before mutation, and
refuse drift. A convenient rerun is not an excuse to silently use the newest
build, image tag, config file, or credential recipe.

## Configuration precedence and suite profiles

Configuration uses deterministic, setting-specific precedence because suite
policy and declaration behavior are not interchangeable:

| Setting | Highest to lowest precedence |
|---|---|
| case backend | CLI, selected profile, pytest ini, `BRIXTEST_BACKEND`, declaration, `auto`/local |
| helper isolation | explicit CLI/pytest ini, selected profile, case declaration, process default |
| binary candidate | CLI named override, selected profile mapping, binary declaration |
| test/server/client environment overlay | CLI named values over selected profile mapping, then normal declared/inherited environment rules |
| generated-image base/registry | selected profile image settings, pytest ini/project default, existing validated runtime setting |
| run root | CLI, pytest ini, `BRIXTEST_RUNS`, framework default |
| evidence/report sinks | explicit CLI option, framework default archive behavior |

Only settings designed as suite-wide policy may override declarations: backend
selection, helper isolation, run/archive locations, binary candidates, safe
environment overlays, image/registry choices, sanitizer mode, reporting sinks,
and retention/display settings. CLI options must not mutate arbitrary
declaration fields or weaken security silently. Every effective override is
recorded without exposing its secret value.

Profiles are the correct place for local-vs-CI-vs-Minikube site concerns. The
checked-in Docker-backed `brixtest` Minikube profile is the reference Kubernetes
target and must remain usable without editing test declarations.

## Extension architecture

One lazy, versioned registry covers backends, executors, probes, artifact
providers, launchers, managed resources, volumes, identities, transports,
images, collectors, analyzers, and exporters.

Extensions must provide:

- a stable kind-specific API version and capabilities;
- side-effect-free validation/planning;
- typed inputs and outputs;
- explicit ownership and conservative rollback;
- bounded readiness, execution, collection, and teardown;
- secret-safe metadata and standard evidence events;
- a black-box conformance suite covering success, failure, and security denial.

A resource provider returns a typed plan before mutation and an owned instance
with named outputs after creation. Kubernetes providers receive only
namespace-confined, label/UID-checked object operations. Raw custom resources
remain inside the provider; normal tests request an abstract resource such as
`resource("ceph", "rook-ceph", ...)` and consume typed outputs.

## Pytest cooperation contract

Pytest remains responsible for collection, parametrization, fixtures,
setup/call/teardown reporting, skip/xfail, selection, markers, xdist scheduling,
terminal reporting, and exit status. BriXTest transports those semantics across
the helper boundary instead of replacing them.

The stable plugin surface consists of the `run`, `metrics`, and
`brixtest_metrics` fixtures; BriXTest options/ini keys; `brixtest` and
`brixtest_budget` markers; and cooperative plan, helper-plugin, server,
artifact, tool-result, and final-result hooks. Helper plugin auto-loading is
disabled. Explicit helper plugins run inside the helper boundary so native or
blocking plugin imports never enter the controller.

## Security and containment invariants

- The controller never imports managed test bodies or optional native client
  libraries into its interpreter.
- Managed module scope is declarative and AST checked; executable/native work
  belongs inside the isolated function body.
- All external commands use exact argv and never a shell.
- Output is bounded while being captured; stdin remains binary safe.
- Every helper, process, container, gateway, Job, authority, and provider has a
  supervisor, deadline, owner, and teardown path.
- Paths are confined, symlinks are rejected or safely resolved, archives cannot
  escape their destination, and secret files use restrictive modes.
- Mutable image tags, devices, host mounts, privilege, external exposure, and
  physical NSS changes require explicit policy and capability support.
- Plans, summaries, remote archives, replay commands, and errors never contain
  private credential content.
- Kubernetes deletion validates namespace, labels, test instance, provider
  owner, and live UID.
- Unsupported or ambiguous semantics fail closed before resource creation.

## Migration strategy for raw and prototype suites

Migration should remove orchestration rather than transliterate it line by
line:

| Legacy/prototype pattern | BriXTest representation |
|---|---|
| handwritten subprocess wrapper | `tool()`/`client()` plus `Execution` |
| daemon `Popen` and polling loop | `server()` plus `Probe`/`Lifecycle` |
| temporary config rewrite | `server_config()` or `template_config()` |
| manual port allocation/string formatting | `Endpoint` and typed server references |
| setup-generated data file | `artifact()`, `noise()`, or task output |
| mutable build-tree executable | captured `binary()` and CLI/profile override |
| Docker/Podman command assembly | placement/profile selection |
| Kubernetes YAML/Helm in test | generic declarations or a provider extension |
| init container or sidecar manifest | task/server execution group |
| PVC/Rook manifest | `volume()` plus provider-backed `resource()` |
| ad-hoc CA/token/KDC scripts | managed authentication recipe |
| `/etc/hosts` edits | `host_mapping()` with explicit libc requirement |
| `kubectl exec` filesystem/base64 | `Service.fs` |
| local performance CSV | `run.metrics` and normalized exporters |
| copied logs per test | one content-addressed log plus consumer links |
| manual retry/reproduction instructions | retained exact rerun record |

Each migrated scenario should first identify the behavior under test, then
declare only resources that behavior requires. Backend mechanics move into the
compiler, runtime adapter, or a reusable extension. A migration is incomplete
while the example still imports a container/Kubernetes SDK, starts an unmanaged
process, parses runtime CLI output, sleeps for readiness, writes outside the
run root, or branches on the selected backend.

## Delivery and review gates

Every capability slice must cross all applicable layers in one change:

1. public immutable declaration or reuse of an existing declaration;
2. graph node/edge and fingerprint semantics;
3. reference projection and capability inference;
4. each accepting backend translator plus explicit rejection elsewhere;
5. transactional lifecycle, ownership, cancellation, and cleanup;
6. logs, metrics, provenance, normalized evidence, and rerun identity;
7. public typing/API manifest and compatibility behavior;
8. concise example and normative documentation;
9. success, operational error, and security-negative tests;
10. backend/extension conformance and live Minikube validation where relevant.

This vertical-slice rule is the primary defense against bolt-ons. A feature is
not complete if it has a constructor but no graph identity, a Kubernetes
renderer but no local/rejection semantics, execution without cancellation,
output without archival, or documentation without a minimal executable
example.

## Milestone 1: typed resource plan

Dependencies: BXP-001 through BXP-010.

- [x] **BXP-100** Define versioned immutable graph nodes for environments,
  workloads, tasks, identities, volumes, endpoints, authorities, and provider
  resources.
- [x] **BXP-101** Define typed edges for ordering, readiness, co-location,
  connectivity, consumption, and reverse-order teardown.
- [x] **BXP-102** Expand existing `CaseDefinition` resources into the graph
  without changing their behavior.
- [x] **BXP-103** Resolve typed references according to the consuming resource,
  rather than using one address/path representation globally.
- [x] **BXP-104** Fingerprint graph nodes and their effective inputs for pooling,
  caching, provenance, and reproducible reruns.
- [x] **BXP-105** Implement transactional prepare/start/stop/collect processing
  with reverse-order rollback after partial failure.
- [x] **BXP-106** Persist the declared graph, effective plan, allocation choices,
  and checksums in case evidence.
- [x] **BXP-107** Preserve exact config-content-based server merging across the
  new graph.
- [x] **BXP-108** Add graph validation for cycles, invalid lifetimes, ambiguous
  outputs, unsafe cross-environment references, and conflicting groups.

Acceptance:

- [x] Existing BriXTest examples generate equivalent effective plans.
- [x] Plan creation performs no process, port, credential, image, or cluster
  mutation.
- [x] A partial-start failure leaves no owned resource running.

## Milestone 2: capability negotiation

Dependencies: milestone 1.

- [x] **BXP-120** Define stable capability names for networking, execution,
  workload shape, storage, identity, security, and transport.
- [x] **BXP-121** Infer required capabilities from the graph.
- [x] **BXP-122** Publish capabilities from every built-in backend, launcher,
  executor, provider, and transport.
- [x] **BXP-123** Produce one diagnostic containing the resource, requirement,
  selected backend, and available alternatives when planning fails.
- [x] **BXP-124** Extend `brixtest design` with effective-plan and capability
  explanations.
- [x] **BXP-125** Add capability declarations and conformance checks to the
  extension API.

Acceptance:

- [x] Unsupported UDP, IPv6, PTY, device, identity, and storage requests fail
  before resource creation.
- [x] No built-in backend ignores a public declaration field.

## Milestone 3: environments and networking

Dependencies: milestones 1 and 2.

- [x] **BXP-200** Support multiple environments, namespaces, and Kubernetes
  contexts in one case.
- [x] **BXP-201** Add IPv4, IPv6, IPv6-only, and dual-stack port allocation.
- [x] **BXP-202** Make local, OCI, and Kubernetes endpoints address-family aware.
- [x] **BXP-203** Support UDP service discovery and reachability in every capable
  environment.
- [x] **BXP-204** Use direct in-environment endpoints where possible and
  supervised TCP/UDP gateways where crossing an environment boundary.
- [x] **BXP-205** Support server-to-helper callbacks and reverse connections.
- [x] **BXP-206** Resolve server references to internal or external addresses
  according to their consumer.
- [x] **BXP-207** Materialize declared host mappings as real forward and reverse
  DNS/NSS behavior for helpers, containers, and pods.
- [x] **BXP-208** Derive default-deny network policy from declared dependencies
  and endpoint exposure.
- [x] **BXP-209** Archive addresses, routes, gateways, DNS records, policies, and
  allocation checksums.

Acceptance:

- [x] The same UDP test runs locally and in Docker-backed Minikube.
- [x] IPv6-only and dual-stack fallback tests exercise real IPv6 sockets.
- [x] TLS/GSI reverse-DNS tests use libc/NSS rather than only `run.reverse()`.
- [x] A Kubernetes server can connect to a managed callback listener.

## Milestone 4: workloads, tasks, and Kubernetes rendering

Dependencies: milestones 1 through 3.

- [x] **BXP-300** Compile grouped servers into one local/OCI isolation unit or
  Kubernetes Pod template.
- [x] **BXP-301** Compile grouped init tasks into ordered local setup operations
  or Kubernetes init containers.
- [x] **BXP-302** Compile standalone tasks into supervised processes, one-shot
  containers, or Kubernetes Jobs.
- [x] **BXP-303** Support sidecars with independent readiness, logs, metrics,
  health monitoring, and teardown.
- [x] **BXP-304** Support replicated services and expose both the load-balanced
  service and individual replica records.
- [x] **BXP-305** Render identity, RBAC, networking, scheduling, volumes, probes,
  lifecycle, and security from typed graph nodes.
- [x] **BXP-306** Add Deployments, StatefulSets, Jobs, Pods, Services,
  ServiceAccounts, Roles, RoleBindings, NetworkPolicies, PVCs, and associated
  cleanup to the Kubernetes backend.
- [x] **BXP-307** Support provider-owned CRDs through a lifecycle contract; do
  not add raw manifest dictionaries to normal test declarations.
- [x] **BXP-308** Collect per-container logs, events, status, restarts, exits, and
  resource metrics.
- [x] **BXP-309** Make Kubernetes teardown UID-aware so BriXTest cannot delete a
  similarly named object that it did not create.

Acceptance:

- [x] Minimal examples cover init container, sidecar, Job, three replicas,
  ServiceAccount/RBAC, NetworkPolicy, and PVC behavior.
- [x] All rendered Kubernetes resources have graph-node and test-instance
  provenance links.

## Milestone 5: helper isolation and command transport

Dependencies: milestones 1 through 4.

- [x] **BXP-400** Define a transport-neutral helper protocol for heartbeats,
  pytest reports, tracebacks, attachments, logs, and cancellation.
- [x] **BXP-401** Produce a content-addressed bundle containing the selected test,
  BriXTest installation, required pure-Python files, and dependency identity.
- [x] **BXP-402** Launch the helper as a Kubernetes Job with its declared
  environment and identity.
- [x] **BXP-403** Keep fixture and test execution inside the remote helper while
  pytest reporting remains controller-owned.
- [x] **BXP-404** Enforce deadlines and terminate the remote Job/process tree
  when heartbeats stop.
- [x] **BXP-405** Support text and binary stdin in the Kubernetes tool executor.
- [x] **BXP-406** Support PTY allocation, resize, streaming, and termination.
- [x] **BXP-407** Apply the same bounded capture, retry, cancellation, and durable
  log semantics on every executor.
- [x] **BXP-408** Preserve complete remote tracebacks and partial output on error.

Acceptance:

- [x] A test proves its Kubernetes ServiceAccount identity and RBAC permissions.
- [x] Interactive and binary-stdin clients behave consistently locally and in
  Kubernetes.
- [x] A deliberately hung remote test is killed without blocking the controller.

## Milestone 6: identity, user namespaces, devices, and filesystems

Dependencies: milestones 1, 2, and 4.

- [x] **BXP-500** Implement UID, GID, supplementary-group, and NSS materialization.
- [x] **BXP-501** Implement user-namespace UID/GID mappings for capable local and
  OCI runtimes.
- [x] **BXP-502** Implement least-privilege Linux capability translation.
- [x] **BXP-503** Implement explicit host/device volumes, including `/dev/fuse`.
- [x] **BXP-504** Implement mount propagation and mount lifecycle supervision.
- [x] **BXP-505** Implement `Service.fs` using confined native operations locally.
- [x] **BXP-506** Implement binary-safe OCI filesystem transport.
- [x] **BXP-507** Implement binary-safe Kubernetes filesystem transport without
  shell/base64 helpers in test code.
- [x] **BXP-508** Support stat, list, read, write, mkdir, remove, chmod, chown,
  symlink, and xattr operations.
- [x] **BXP-509** Prevent traversal, symlink escapes, undeclared host access, and
  implicit privilege escalation.
- [x] **BXP-510** Journal filesystem mutations and resulting checksums.

Acceptance:

- [x] Port the real FUSE mount lifecycle test to the public API.
- [x] Port the user-namespace setfsuid/supplementary-group red-team test.
- [x] Run the same server filesystem assertions locally and in Kubernetes.

## Milestone 7: managed authentication authorities

Dependencies: milestones 1 through 6.

- [x] **BXP-600** Model authorities, issued material, consumers, refresh behavior,
  and revocation as graph resources.
- [x] **BXP-601** Provide HS256, ES256, and RSA token issuance.
- [x] **BXP-602** Provide managed JWKS and OIDC discovery endpoints.
- [x] **BXP-603** Support signing-key rotation and observable JWKS refresh.
- [x] **BXP-604** Manage TLS CA, host/client identities, CRLs, revocation, and CRL
  publication.
- [x] **BXP-605** Manage VOMS/GSI authority, trust roots, LSC data, proxy issuance,
  FQANs, and revocation.
- [x] **BXP-606** Run Kerberos KDCs as reachable managed services with TCP and UDP
  endpoints and generated realm/domain configuration.
- [x] **BXP-607** Support authority stop/start and failure injection for refresh
  and recovery tests.
- [x] **BXP-608** Distribute credentials by declared role and environment only.
- [x] **BXP-609** Archive public material, versions, checksums, issuance events,
  rotations, and revocations while redacting private material.

Acceptance:

- [x] Minimal examples cover token, JWKS rotation, TLS CRL reload, VOMS/GSI, and
  Kerberos on local and Minikube backends.
- [x] A server pod never receives client-only credentials.

## Milestone 8: binary, build, and image pipeline

Dependencies: milestones 1, 2, 4, and 5.

- [x] **BXP-700** Permit task outputs to become artifact or binary inputs for
  later graph nodes.
- [x] **BXP-701** Snapshot a binary, interpreter/loader, selected libraries, and
  runtime data before any dependent server starts.
- [x] **BXP-702** Construct deterministic minimal OCI layers from captured
  binaries.
- [x] **BXP-703** Record image manifests, layer digests, file checksums, build
  inputs, tool versions, and an SBOM.
- [x] **BXP-704** Load generated images into the Docker-backed Minikube profile.
- [x] **BXP-705** Push generated images to a configured content-addressed registry
  for remote clusters.
- [x] **BXP-706** Preserve support for explicitly supplied digest-pinned images.
- [x] **BXP-707** Add project/profile configuration for base images and registries
  without requiring per-test settings.
- [x] **BXP-708** Verify ASan and dynamically linked nginx substitutions through a
  complete suite rerun.
- [x] **BXP-709** Support build/RPM tasks without allowing a rebuild to replace a
  captured executable used by an active run.

Acceptance:

- [x] `binary("nginx", path="...", runtime_files={...})` uses the same declaration
  on local and Minikube, including immutable daemon NSS/runtime inputs.
- [x] A build modified after capture cannot alter the running suite.

## Milestone 9: provider-managed storage and infrastructure

Dependencies: milestones 1, 2, 4, and 6.

- [x] **BXP-800** Add versioned resource, volume, identity, transport, and image
  provider contracts with reusable conformance suites.
- [x] **BXP-801** Require providers to return typed plan fragments, ownership
  metadata, readiness, outputs, and teardown operations.
- [x] **BXP-802** Implement a Rook/Ceph provider covering operator discovery,
  CephCluster, pools, CephFS, PVCs, credentials, and health.
- [x] **BXP-803** Add persistence, restart, rescheduling, and snapshot tests.
- [x] **BXP-804** Add orphan discovery and conservative cleanup for provider
  resources.
- [x] **BXP-805** Correlate provider logs, events, metrics, object UIDs, and storage
  identities with consuming tests.

Acceptance:

- [x] A test requests a Ceph-backed volume without importing Kubernetes or Rook
  APIs.
- [x] Provider failure rolls back all resources BriXTest owns and nothing else.

## Milestone 10: global shared topology

Dependencies: milestones 1 through 5.

- [x] **BXP-900** Move session-scoped pool ownership to a controller-supervised
  topology broker shared by xdist workers.
- [x] **BXP-901** Merge collected worker plans before starting shared resources.
- [x] **BXP-902** Publish resolved services to workers through bounded authenticated
  IPC.
- [x] **BXP-903** Monitor shared servers, gateways, authorities, and port-forwards
  independently of test helpers.
- [x] **BXP-904** Add explicit `scope="worker"` for intentionally worker-local
  instances.
- [x] **BXP-905** Include environment, image, identity, network, volume, auth, and
  config identity in shared-pool fingerprints.
- [x] **BXP-906** Link all consumers to one instance/log record and tear it down
  after the final actual consumer.
- [x] **BXP-907** Recover or safely reap broker resources after worker or
  controller failure.

Acceptance:

- [x] Two xdist workers consume one session-scoped server instance.
- [x] A shared server crash fails consumers quickly with one correlated trace.

## Milestone 11: evidence, migration, and release readiness

Dependencies: all preceding milestones.

- [x] **BXP-1000** Extend JSON, SQLite, Parquet, HTML, OpenSearch, and Elasticsearch
  schemas for the complete resource graph.
- [x] **BXP-1001** Store internal/external endpoints, routes, DNS, identities,
  RBAC, policies, images, volumes, tasks, authorities, replicas, and provider
  objects.
- [x] **BXP-1002** Store individual stdout/stderr/log streams and checksums for
  every task, container, server, client, helper, and authority.
- [x] **BXP-1003** Retain exact test-to-resource and shared-resource relationships.
- [x] **BXP-1004** Add one-command rerun for failures using the recorded backend,
  parameters, binaries, images, and resource plan.
- [x] **BXP-1005** Port representative IPv6, UDP, callback/TPC, FUSE, userns,
  filesystem, RBAC, JWKS, CRL, Kerberos, VOMS/GSI, Ceph, interactive, and xdist
  tests into self-contained BriXTest examples.
- [x] **BXP-1006** Add concise examples for every new public declaration and
  runtime method.
- [x] **BXP-1007** Update architecture, API, backend, isolation, authentication,
  extension, migration, and evidence documentation.
- [x] **BXP-1008** Make Docker-backed Minikube the mandatory Kubernetes
  conformance target in CI and the documented reference profile.
- [x] **BXP-1009** Run the complete unit, contract, integration, live Minikube,
  complexity, API compatibility, and documentation suites.
- [x] **BXP-1010** Confirm BriXTest imports and packages successfully when copied
  out of the parent repository.

## Required validation for every action

Every implementation action above requires all applicable boxes:

- [x] Public success-path unit test.
- [x] Validation/error-path unit test.
- [x] Security-negative unit test.
- [x] Backend contract test.
- [x] Provenance/evidence assertion.
- [x] Public API manifest and type-stub update.
- [x] User-facing documentation or example.
- [x] File-size and complexity checks.
- [x] Full BriXTest suite remains green.

## Final definition of done

- [x] Existing BriXTest tests run without source changes.
- [x] Advanced examples contain no direct runtime or cluster orchestration.
- [x] Local and Minikube use the same test source wherever physical capabilities
  permit equivalent behavior.
- [x] Unsupported physical capabilities fail during planning with an actionable
  diagnostic.
- [x] FUSE, userns, IPv6, UDP, reverse callback, live authority rotation, Ceph,
  and in-cluster identity tests are first-class examples.
- [x] All processes, containers, Jobs, volumes, gateways, and authorities are
  supervised and transactionally torn down.
- [x] Every resource, operation, log, metric, checksum, and consumer relationship
  is queryable from the evidence archive.
- [x] A failing test can be rerun with the exact captured plan and executable
  identities.
- [x] BriXTest remains standalone and AGPLv3-licensed.
- [x] No raw manifest, shell/base64 filesystem workaround, backend conditional,
  unmanaged side process, compatibility exception, or complexity backlog is
  required by the shipped examples.
