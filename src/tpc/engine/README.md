# engine — native-TPC control plane (destination side)

## Overview

Native third-party copy lets a client orchestrate a direct
server-to-server transfer: the destination server pulls from the source
server without the bytes touching the client. This directory is the
destination-side control plane. `brix_tpc_prepare_pull()` (`launch.c`) is
the entry point, invoked from `root/read/open_request.c` when a `kXR_open`
carries TPC opaque parameters (parsed by `parse.c`).

The rendezvous between the client's two opens (source-side key
registration, destination-side pull) happens through a shared-memory key
table (`key_registry.c`) — cross-process and zero-copy, so any worker can
serve either leg. The actual pull runs on a blocking thread-pool worker
([../outbound/](../outbound/)); `done.c` hands completion back from the
thread pool to the nginx event loop.

## Files

| File | Responsibility |
|---|---|
| `launch.c` | TPC pull entry point; destination-side preparation (event-loop side) |
| `parse.c` | parse the TPC opaque query string from kXR_open into structures |
| `done.c` | thread-pool → event-loop completion handoff |
| `key_registry.c` / `key_registry.h` | SHM TPC key table: entry structure, registration, expiry |
| `noop.c` | refusing stand-ins when native TPC is compiled out |
| `tpc_internal.h` | shared types, constants, and declarations for the TPC cluster |

## Invariants, security & gotchas

1. The SHM key table mutex MUST be spin+yield via `brix_shm_table_alloc()`
   — never POSIX-semaphore mode (CLAUDE.md INVARIANT 10).
2. Keys expire; a pull presenting an expired or unknown key is refused —
   never "best-effort" matched.
3. Native TPC (this engine) and WebDAV TPC
   (`src/protocols/webdav/tpc.c`, curl COPY with Source/Credential
   headers) are separate mechanisms — do not share state or auth logic
   between them.

## See also

- [../outbound/README.md](../outbound/README.md) — the blocking source-session client
- [../gsi/README.md](../gsi/README.md) — outbound GSI auth for the pull socket
- [../../protocols/root/read/](../../protocols/root/read/) — `open_request.c`, the caller
