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

The local backend supports temporary, shared, persistent-for-the-case, and
explicit host volumes. A non-zero size is a quota request, not a hint; a
backend that cannot enforce it rejects the plan before creating the run root.
Device, provider, mount-propagation, isolated-environment, identity, replica,
and Kubernetes-managed-volume declarations are likewise rejected until their
selected backend advertises and implements the required capability.

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
declared mount roots. Traversal, root removal, and symlinks escaping those
roots are rejected. Mutations and resulting SHA-256 values are written to the
case evidence journal. Kubernetes currently reports the missing binary-safe
filesystem-transport capability instead of falling back to shell or base64
workarounds.

## Planning and evidence

The normalized plan contains versioned nodes, typed dependency and placement
edges, effective declarations, capability requirements, and stable
fingerprints. It is archived as `resource-plan.json`. Task results, individual
stdout/stderr logs, task-output checksums, volume records, filesystem
operations, selected backend, and the graph are correlated by attempt ID in
`summary.json` and the evidence journal.

Planning is deliberately strict. Cycles, a setup task depending on a running
server, a server depending on a finalizer, conflicting execution groups, or a
resource/backend capability mismatch fail before mutation. The diagnostic
names the resource, missing capability, selected backend, and the capabilities
that backend provides.

`brixtest design tests/` performs pytest collection only and prints each
effective graph fingerprint, node backend, inferred requirements, missing
capabilities, and typed edge. It does not create any planned resource.

## Address families

Local endpoints with `family="ipv6"` reserve and probe a real IPv6 loopback
socket. `family="dual"` reserves one IPv6 socket with dual-stack behavior and
verifies that IPv4 and IPv6 use the same port. `Service.address()`,
`Service.endpoint()`, typed role host references, URLs, plans, and evidence all
retain the effective per-role host; IPv6 URLs are bracketed automatically.
