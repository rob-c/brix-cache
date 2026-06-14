# Full Hierarchical CMS Cluster

The XRootD CMS cluster protocol from first principles: what it is, where it appears in HEP deployments, what nginx-xrootd already implements, and what remains.
what the remaining gap is, and a detailed implementation plan for completing
full hierarchical support.

See [cluster-mode.md](cluster-management.md) for the existing two-tier configuration
reference and [manager-mode.md](manager-mode.md) for the static
`xrootd_manager_map` alternative. For the byte-by-byte CMS wire protocol —
framing, the `kYR_*` opcode catalogue, and the field-by-field login / load /
state→have / select negotiation — see
[The CMS Cluster Protocol (`cms://`)](../04-protocols/cms-protocol.md).

---

## Background and terminology

The XRootD **Cluster Management System (CMS)** is a separate TCP management
channel that runs alongside the XRootD data channel. Data servers open an
outbound connection to a manager and send periodic registration and heartbeat
frames. The manager uses those registrations to build a real-time map of which
server holds which files, then redirects incoming client `kXR_locate` and
`kXR_open` requests to the best available server rather than serving the data
itself.

### Roles

| Role | Description |
|---|---|
| **Data server** | Holds files on local storage; registers exported paths and reports free space / utilisation over CMS. Redirected to by the manager for reads and writes. |
| **Manager / redirector** | Receives client locate and open requests; consults the registry; returns `kXR_redirect`. Runs a CMS listener so data servers can register. |
| **Sub-manager / supervisor** | Acts as both a data server (outbound CMS client connecting upward) and a manager (inbound CMS listener accepting children). Aggregates child capacity and reports it to the parent manager. |
| **Meta-manager** | Top of a three-tier or deeper hierarchy. Clients contact the meta-manager first; it redirects to a sub-manager; the sub-manager redirects to a leaf. |
| **Cache node** | A read-cache server that self-registers each file it caches and deregisters on eviction. Clients are redirected to the cache when it holds the file. |

### CMS wire framing

All CMS frames share an 8-byte fixed header:

```
[streamid : 4 bytes big-endian]
[rrCode   : 1 byte            ]   opcode
[modifier : 1 byte            ]   opcode-specific flags
[dlen     : 2 bytes big-endian]   payload length in bytes
```

Variable-length fields in the payload use a type-tagged encoding: a leading
type byte (`0x80` for a 2-byte value, `0xa0` for a 4-byte value) followed by
the big-endian value. Strings are null-terminated and appear at the end of the
payload.

The CMS channel is completely separate from the XRootD data channel
(`root://`). A data server maintains two long-lived TCP connections to its
parent manager: one for the XRootD data protocol (for incoming client requests
it handles itself) and one for the CMS management protocol (to report space
and receive manager directives).

---

## HEP use-cases

### WLCG Tier-0 / Tier-1 / Tier-2 topology

The Worldwide LHC Computing Grid (WLCG) is the primary consumer of hierarchical
CMS clusters. Each LHC experiment (CMS, ATLAS, LHCb, ALICE) runs a tiered
storage infrastructure:

- **Tier-0 (CERN)**: A meta-manager at CERN coordinates storage across the
  experiment. CERN's EOS storage system alone has over 1 000 storage nodes —
  far more than a single 128-slot redirector can represent directly.
- **Tier-1 sites** (~10 globally): Each runs a sub-manager that aggregates
  10–60 local storage nodes and reports aggregate capacity to the Tier-0
  meta-manager. Clients contacting the Tier-1 sub-manager are redirected to a
  local storage node.
- **Tier-2 sites** (~40 per experiment, ~200 globally): Each runs a site-local
  redirector pointing to 5–20 storage nodes. The Tier-2 redirector registers as
  a sub-manager with the nearest Tier-1.

A client running `xrdcp` to fetch a file contacts the closest sub-manager. If
the file is locally available the sub-manager redirects immediately. If not, it
must escalate the query to its parent — this is the `kYR_locate` → `kYR_select`
exchange that the current implementation is missing.

### XCache / StashCache / OSDF

The Open Science Data Federation (OSDF) uses a global redirector at the top,
regional sub-managers at each resource provider, and per-site XCache instances
at the leaves. A cache miss at a regional sub-manager must be escalated upward
to ask the global redirector where the file's authoritative copy is. Without
the escalation mechanism, a cache miss terminates in a `kXR_notFound` rather
than a redirect to the origin.

### OSG / DOMA federations

The Open Science Grid (DOMA storage task force) federates over 100 sites under
a common namespace. No single redirector can hold registry entries for every
storage node at every site — the hierarchy is essential for scale. Sites running
nginx-xrootd as a sub-manager today rely on the static `xrootd_manager_map`
fallback, which means redirect decisions are pre-configured at deploy time
rather than derived from live availability data.

### Rucio + XRootD storage element lookup

Rucio (the ATLAS / CMS / DUNE distributed data management system) issues
`kXR_locate` against an XRootD storage element to discover where a replica
actually lives before scheduling a transfer. A multi-tier locate chain is
central to Rucio's file-location algorithm. A sub-manager that cannot escalate
to its parent returns an incorrect "not found" response, causing Rucio to
classify the replica as unavailable.

### dCache and EOS XRootD doors

Both dCache and EOS expose an XRootD door that registers each storage pool as
a data server. They interoperate with an external redirector that acts as the
sub-manager for a site. When nginx-xrootd is that external redirector, it
needs to accept registrations from dCache / EOS pool managers and in turn
report to a site-level or experiment-level parent.

### Summary by site type

| Site type | Works today | Blocked by M6 gap |
|---|---|---|
| Single-site disk-only (≤ 128 nodes) | ✅ Two-tier sufficient | — |
| Single-site disk-only (> 128 nodes) | ✅ Configurable via `xrootd_registry_slots` | — |
| Multi-site federation (WLCG Tier-2) | ⚠️ Static map only | `kYR_locate` escalation |
| OSDF / XCache deployment | ❌ Cache miss cannot escalate | `kYR_locate` + `kYR_select` |
| CERN-scale EOS (1 000+ nodes) | ⚠️ Configurable slots; no fanout yet | Hierarchical fanout |
| Rucio storage element with parent | ⚠️ Locate fails at miss | `kYR_locate` escalation |

---

## What is already implemented

All five phases documented in [cluster-mode.md](cluster-management.md) are complete
and tested.

### M1 — Server registry (`src/manager/`)

A shared-memory table, spinlock-protected, maps each registered data server to
its host, port, colon-delimited export path list, free space, and utilisation.
The table persists across nginx worker restarts because it lives in a dedicated
`ngx_shm_zone_t`. The capacity defaults to 128 slots and is configurable at
runtime via the `xrootd_registry_slots` directive (Step 1b — implemented).

`xrootd_srv_select()` performs longest-prefix matching over each server's path
list. For reads it picks the server with the lowest `util_pct`; for writes the
server with the most `free_mb`. When multiple servers tie on the scoring
criterion the first matching slot is used (deterministic for a given registry
state).

If the table is full when a new registration arrives, a `NGX_LOG_WARN` message
is written to the error log and the `xrootd_registry_full_total` Prometheus
counter is incremented.

Key files: `src/manager/registry.h`, `src/manager/registry.c`.

### M2 — CMS server listener (`src/cms/server_*.c`)

A dedicated nginx stream server block (`xrootd_cms_server on`) accepts inbound
TCP connections from data servers. It parses CMS frames and maintains the
registry:

| Frame received | Action |
|---|---|
| `kYR_login` | Calls `xrootd_srv_register()` with host, port, paths, and initial space metrics |
| `kYR_load` / `kYR_avail` / `kYR_space` | Calls `xrootd_srv_update_load()` to refresh `free_mb` and `util_pct` |
| `kYR_pong` | Updates `last_seen` timestamp |
| `kYR_ping` | Sends `kYR_pong` back |
| `kYR_gone` | Calls `xrootd_srv_unregister_path()` for the path named in the payload (Step 1a — implemented) |
| Disconnect | Calls `xrootd_srv_unregister()` to free the slot |

Key files: `src/cms/server_handler.c`, `src/cms/server_recv.c`,
`src/cms/server_send.c`, `src/cms/server_module.c`.

### M3 — Dynamic redirect in `kXR_locate` and `kXR_open`

When `xrootd_manager_mode on` is set, the redirect lookup sequence is:

1. Query the live registry via `xrootd_srv_select()`.
2. If no registry match, fall back to the static `xrootd_manager_map` table.
3. If still no match and `xrootd_upstream` is configured, forward the whole
   request to the upstream redirector.
4. Otherwise, attempt to serve locally.

The `kXR_isManager` capability flag is set in the `kXR_protocol` response so
clients know this server can issue redirects.

Key files: `src/read/locate.c`, `src/read/open.c`, `src/session/protocol.c`.

### M4 — Sub-manager / hierarchical mode (partial)

A node configured with both `xrootd_cms_manager` (outbound CMS client) and
`xrootd_cms_server on` (inbound CMS listener) acts as a sub-manager. It
accepts registrations from its children and aggregates their capacity to report
upward.

What works:

- `CMS_LOGIN_MODE_MANAGER` bit is set in the `kYR_login` frame sent upward, so
  the parent recognises this node as a sub-manager rather than a leaf.
- `xrootd_srv_aggregate_space()` sums `free_mb` and averages `util_pct` across
  all registered children; the aggregated value is used in `kYR_load` heartbeats
  sent upward (`src/cms/send.c`).
- `CMS_RR_STATUS` (suspend / resume) from the parent manager is handled;
  `cms_suspended` gates new `kXR_login` attempts.

What does not work: when the parent manager responds to a child query with
`kYR_select` (telling the sub-manager which server to redirect a client to),
the sub-manager has no mechanism to correlate that CMS response with the
pending XRootD client session and emit a `kXR_redirect`. This is the M6 gap.

### M5 — Cache node auto-registration

When `xrootd_manager_mode on` is combined with `xrootd_cache`, the cache
module calls `xrootd_srv_register()` after each successful cache fill and
`xrootd_srv_unregister_path()` on each eviction. The registry reflects the
exact current contents of the cache, and clients are redirected to the cache
for files it holds.

Key files: `src/cache/thread.c`, `src/cache/evict.c`.

---

## What is missing — the M6 gap

The current implementation works correctly for two-tier deployments (one
redirector, any number of data servers up to 128). The gap is entirely in the
sub-manager path: a sub-manager that receives a `kXR_locate` or `kXR_open` for
a path not in its local registry has no way to escalate the query to its parent
and relay the parent's answer back to the client.

### Missing CMS opcodes

The following opcodes appear in the XRootD CMS wire protocol but are not yet
handled. Values are verified against `YProtocol.hh` in the XRootD reference
source tree at `/tmp/xrootd-src/src/XProtocol/YProtocol.hh`.

| Opcode | Value | Direction | Purpose |
|---|---|---|---|
| `kYR_locate` | 2 | Sub-manager → parent | "Where is this file?" — asks the parent manager for a redirect target |
| `kYR_select` | 10 | Parent → sub-manager | "Send the client to this server" — the parent's answer to `kYR_locate` |
| `kYR_try` | 24 | Parent → sub-manager | Like `kYR_select` but with an ordered list of alternatives |

`kYR_gone` (value 14, data server → manager) is **implemented** — see Step 1a below.

### The pending-locate bridge problem

The fundamental architectural challenge is that a `kXR_locate` client request
arrives on an XRootD data channel connection (managed by any nginx worker) and
the parent manager's `kYR_select` reply arrives on the CMS management channel
(currently worker 0 only). There is no mechanism to hold the XRootD session
open while the CMS exchange completes, and no way to route the CMS response
back to the correct worker and connection.

### Registry capacity

The registry capacity defaults to 128 slots and is now configurable via
`xrootd_registry_slots N` (Step 1b — implemented). When the table is full,
new registrations are dropped with a `WARN`-level log message and a
`xrootd_registry_full_total` Prometheus counter increment. Without hierarchical
fanout, a single redirector still cannot serve sites at CERN scale regardless
of the slot count.

---

## Implementation plan — M6

Each step below is independently reviewable. Steps 1a and 1b are independent of
each other and can proceed in any order. Step 3 depends on 1b. Steps 4 and 5
depend on steps 2 and 3. Step 6 depends on steps 3, 4, and 5.

### Step 1a — `kYR_gone` ✅ Implemented

`CMS_RR_GONE` (value 14) is handled in `cms_srv_process_frame()` in
`src/cms/server_recv.c` (the CMS server receive path, which handles frames
arriving from data servers — the correct direction for `kYR_gone`).

When a `CMS_RR_GONE` frame arrives, the handler copies the NUL-terminated path
from the payload and calls `xrootd_srv_unregister_path(ctx->host, ctx->port,
path)` using the data server's login-time host and port.

`#define CMS_RR_GONE 14` is in `src/cms/cms_internal.h`.

Note: the plan originally placed this in `src/cms/recv.c` (the CMS client
receive path). `kYR_gone` flows data-server → manager, so the correct file is
`src/cms/server_recv.c`.

Files changed: `src/cms/cms_internal.h`, `src/cms/server_recv.c`.

---

### Step 1b — Configurable registry slots ✅ Implemented

The `xrootd_registry_slots N` directive (default `128`) is implemented.

`xrootd_srv_table_t` now uses a C99 flexible array member with a `capacity`
field in the shared-memory header. The zone size is computed at postconfiguration
time by scanning all enabled server blocks for the largest `registry_slots`
value:

```c
size = sizeof(xrootd_srv_table_t)
     + (size_t) slots * sizeof(xrootd_srv_entry_t)
     + ngx_pagesize;
```

All loop bounds in `registry.c` use `tbl->capacity` instead of the former
compile-time constant. When the table is full, a `NGX_LOG_WARN` message is
emitted and `m->registry_full_total` is incremented atomically. The counter is
exported as the `xrootd_registry_full_total` Prometheus counter.

Files changed: `src/manager/registry.h`, `src/manager/registry.c`,
`src/config/config.h`, `src/config/server_conf.c`,
`src/config/postconfiguration.c`, `src/stream/module.c`,
`src/types/config.h`, `src/metrics/metrics.h`, `src/metrics/stream.c`.

---

### Step 2 — Per-worker CMS connections ✅ Implemented

Each nginx worker process opens its own independent CMS connection to the parent
manager. Workers are forked from the master process; each inherits
`conf->cms_ctx = NULL` (the master never calls `ngx_xrootd_cms_start`). Each
worker's `init_process` hook independently calls `ngx_xrootd_cms_start`, which
allocates a private `ngx_xrootd_cms_ctx_t` from that worker's pool and
schedules the initial connection timer.

This means the parent manager receives one connection per nginx worker. When a
worker sends `kYR_locate`, the `kYR_select` reply arrives on that same worker's
event loop — the same loop that holds the suspended `kXR_locate` client session.
No cross-worker IPC is required for the pending-locate bridge in Step 5.

Note: the plan described removing a `ngx_process.slot == 0` guard, but that
guard was not present in the codebase. The per-worker behavior was already
correct. The actual changes in this step were:

- Fixed a bug in `src/manager/registry.c`: the sentinel value for "no free slot
  found" was `XROOTD_SRV_REGISTRY_SLOTS` (hardcoded to 128) instead of
  `tbl->capacity`. This broke `xrootd_srv_register()` whenever `registry_slots`
  was configured to any value other than 128.
- Updated the stale struct comment in `src/cms/cms_internal.h` that incorrectly
  stated "Only one worker manages the CMS connection per server block (worker
  index 0)".
- Added `TestPerWorkerCMS` (Part 3) in `tests/test_manager_mode.py`: starts
  nginx with `worker_processes 2` and a mock TCP CMS listener; asserts the mock
  receives at least 2 connections.

Files changed: `src/manager/registry.c`, `src/cms/cms_internal.h`,
`tests/test_manager_mode.py`.

---

### Step 3 — Pending-locate table ✅ Implemented

A new shared-memory zone bridges a waiting XRootD session to its in-flight CMS
locate query. The implementation follows the same pattern as
`src/manager/registry.c`: a fixed `ngx_shm_zone_t` zone, an `ngx_shmtx_t`
spinlock embedded in the zone header, and a linear scan over a fixed-size slot
array.

The struct signatures deviate slightly from the plan sketch: `worker_pid` was
added to both `xrootd_pending_insert` and `xrootd_pending_lookup`/
`xrootd_pending_remove` so that two workers can recycle the same `streamid`
value concurrently without aliasing. A separate `xrootd_pending_unlock()` was
split out so that `xrootd_pending_lookup()` can return a pointer into shared
memory while still holding the lock, allowing the caller to copy `redir_host`
and `redir_port` atomically before releasing.

Expired entries are reaped lazily during the next insert pass rather than
via a background timer.

New `xrootd_cms_locate_timeout` directive (default `5000 ms`). Accepts nginx
time strings (`5s`, `500ms`, etc.). Stored as `ngx_msec_t cms_locate_timeout`
in `ngx_stream_xrootd_srv_conf_t`.

Files added: `src/manager/pending.h`, `src/manager/pending.c`.
Files changed: `src/config/config.h`, `src/config/postconfiguration.c`,
`src/config/server_conf.c`, `src/stream/module.c`, `src/types/config.h`,
`config`.

---

### Step 4 — `ngx_xrootd_cms_send_locate()` in `src/cms/send.c` ✅ Implemented

`ngx_xrootd_cms_send_locate()` builds a `kYR_locate` frame containing the
NUL-terminated path (payload up to `XROOTD_SRV_MAX_PATHS` = 1024 bytes) and
sends it via `ngx_xrootd_cms_send_frame()`.

`ngx_xrootd_cms_next_streamid()` increments and returns the per-worker
`uint32_t next_streamid` counter stored in `ngx_xrootd_cms_ctx_t`. The counter
starts at 0 and wraps safely (skipping 0 would require special casing; wrapping
through UINT32_MAX resets to 1 instead). Because each nginx worker has its own
independent CMS connection to the manager, streamids are per-worker and do not
need to be coordinated across workers.

`#define CMS_RR_LOCATE 2` and the two new function declarations were added to
`src/cms/cms_internal.h`. The `next_streamid` field was added to
`ngx_xrootd_cms_ctx_s`.

Files changed: `src/cms/send.c`, `src/cms/cms_internal.h`.

---

### Step 5 — XRootD session suspension ✅ Implemented

Added `XRD_ST_WAITING_CMS` to the state enum in `src/types/state.h` and
`cms_wait_streamid` to `xrootd_ctx_t` in `src/types/context.h`.

In `src/read/locate.c`, inside the `conf->manager_mode && !is_wildcard` block,
after a registry miss: call `ngx_xrootd_cms_next_streamid()`, send a
`kYR_locate` frame via `ngx_xrootd_cms_send_locate()`, insert into the pending
table via `xrootd_pending_insert()`, set `ctx->state = XRD_ST_WAITING_CMS`,
arm `ngx_add_timer(c->read, conf->cms_locate_timeout)`, and return
`NGX_AGAIN`. On failure of either send or insert the code falls through to
the static-map / `kXR_notFound` path unchanged.

The same pattern was applied to the registry-miss path in `src/read/open.c`.

In `src/connection/recv.c`:
- Added `#include "../manager/pending.h"`
- Added a `XRD_ST_WAITING_CMS` guard in the inner recv loop (same re-arm +
  return pattern as `XRD_ST_UPSTREAM`).
- Added an early-return in the `rev->timedout` block: when the state is
  `XRD_ST_WAITING_CMS`, clear the timedout flag, call
  `xrootd_pending_remove()`, reset state to `XRD_ST_REQ_HEADER`, send
  `kXR_wait 5` (ask client to retry in 5 seconds), and schedule a read
  resume. The existing connection-close path is unaffected for all other
  states.

Files changed: `src/types/state.h`, `src/types/context.h`,
`src/connection/recv.c`, `src/read/locate.c`, `src/read/open.c`.

---

### Step 6 — `kYR_select` and `kYR_try` in `src/cms/recv.c` ✅ Implemented

Added `CMS_RR_SELECT 10` and `CMS_RR_TRY 24` to `src/cms/cms_internal.h`.

Added `#include "../manager/pending.h"` to `src/cms/recv.c` and factored the
wake logic into a static helper `cms_wake_pending_session(ctx, streamid, host,
port)`. The helper:

1. Calls `xrootd_pending_lookup(streamid, ngx_pid)` — returns `NULL` if the
   session already timed out (pending_remove was called by the recv.c
   timedout handler).
2. Reads `conn_fd` from the entry, then calls `xrootd_pending_unlock()`
   before any nginx operations.
3. Calls `xrootd_pending_remove()` to free the slot.
4. Validates the fd index against `ngx_cycle->connection_n` and checks
   `client_conn->fd == conn_fd` to detect fd reuse after the client closed.
5. Walks `client_conn->data` → `ngx_stream_get_module_ctx(session, ...)` to
   get `xrootd_ctx_t *` and confirms `state == XRD_ST_WAITING_CMS`.
6. Calls `ngx_del_timer(client_conn->read)`, resets state to
   `XRD_ST_REQ_HEADER`, and calls `xrootd_send_redirect()` +
   `xrootd_schedule_read_resume()`.

Both `CMS_RR_SELECT` and `CMS_RR_TRY` parse `payload[0..]` as a
NUL-terminated hostname + 2-byte big-endian port (first entry in the case
of `kYR_try`), with a minimum-length guard before accessing the port bytes.
Both call `cms_wake_pending_session()`.

Files changed: `src/cms/recv.c`, `src/cms/cms_internal.h`.

---

## Nginx infrastructure leveraged

The implementation borrows from nginx building blocks already in the codebase.
No new external dependencies are introduced.

| nginx feature | Used by M6 |
|---|---|
| `ngx_shm_zone_t` | Pending-locate table; same zone lifecycle as the server registry |
| `ngx_shmtx_t` spinlock | Pending-locate table concurrency control |
| `ngx_event_t` + timer | Locate timeout; fires if `kYR_select` does not arrive within `xrootd_cms_locate_timeout` |
| `ngx_cycle->connections[fd]` | Looks up the waiting client connection by file descriptor within the same worker |
| `ngx_post_event` | Optionally defers `xrootd_send_redirect()` to the next event loop tick |
| Per-worker CMS connection (step 2) | Eliminates cross-worker IPC entirely |
| `XRD_ST_UPSTREAM` state machine | Template for `XRD_ST_WAITING_CMS`; suspend / wake / timeout pattern is identical |
| `ngx_conf_set_num_slot` | Parses `xrootd_registry_slots` directive |
| `ngx_conf_set_msec_slot` | Parses `xrootd_cms_locate_timeout` directive |

---

## Configuration reference

### New directives

`xrootd_registry_slots N`

Maximum number of data server entries in the shared-memory registry. Default
`128`. Increase at sites with more than 128 storage nodes. Applied at the next
`nginx -s reload`.

`xrootd_cms_locate_timeout time`

How long to hold a client `kXR_locate` or `kXR_open` open while waiting for a
`kYR_select` response from the parent manager. Default `5s`. If the parent does
not respond within this window the client receives `kXR_wait` and may retry.

### Three-tier example

```nginx
# Meta-manager — clients contact this first
stream {
    server {
        listen 2213;
        xrootd_cms_server on;      # accepts sub-manager registrations
    }
    server {
        listen 2094;
        xrootd on;
        xrootd_root /dev/null;
        xrootd_manager_mode on;
        xrootd_registry_slots 256;
    }
}

# Sub-manager — registers to meta-manager; accepts data servers below
stream {
    server {
        listen 1213;
        xrootd_cms_server on;      # accepts data server registrations
    }
    server {
        listen 1094;
        xrootd on;
        xrootd_root /dev/null;
        xrootd_manager_mode on;
        xrootd_cms_manager meta-manager.example.org:2213;
        xrootd_cms_locate_timeout 5s;
        xrootd_registry_slots 128;
    }
}

# Leaf data server — registers to sub-manager
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_cms_manager sub-manager.example.org:1213;
        xrootd_cms_paths /data;
    }
}
```

Client flow: `xrdcp` contacts the meta-manager on port 2094. The meta-manager
queries its registry and redirects the client to the sub-manager on port 1094.
The client contacts the sub-manager, which queries its local registry. On a
miss (after M6 is implemented), the sub-manager sends `kYR_locate` upward to
the meta-manager, which responds with `kYR_select` naming a specific leaf. The
sub-manager issues `kXR_redirect` to the client naming that leaf, and the
client connects directly to the leaf for the data transfer.

---

## Implementation sequencing

| Step | What | Depends on | Status |
|---|---|---|---|
| 1a | `kYR_gone` + `CMS_RR_GONE` in `server_recv.c` | — | ✅ Done |
| 1b | Configurable `xrootd_registry_slots` + full-table warning + Prometheus counter | — | ✅ Done |
| 2 | Per-worker CMS connections; fix registry sentinel bug; add multi-worker test | — | ✅ Done |
| 3 | Pending-locate table (`src/manager/pending.c`) | 1b | ✅ Done |
| 4 | `ngx_xrootd_cms_send_locate()` + streamid counter | 2 | ✅ Done |
| 5 | `XRD_ST_WAITING_CMS` + session suspension in `locate.c` / `open.c` | 3, 4 | ✅ Done |
| 6 | `kYR_select` / `kYR_try` in `recv.c` + session wake | 3, 4, 5 | ✅ Done |
| 7 | Three-tier integration tests (Parts 5–8) | 2–6 | Not started |

---

## Tests

Add to `tests/test_manager_mode.py`. All tests must be deterministic — no
timing-dependent assertions. Use the mock CMS fixture pattern from
`tests/test_cms.py` wherever a real manager response would introduce timing
uncertainty.

**Part 3 — Per-worker CMS connections**

Start nginx with `worker_processes 2` and a mock TCP CMS listener. Assert the
mock receives at least 2 incoming connections — one per worker. This test is in
`TestPerWorkerCMS` in `tests/test_manager_mode.py` and is already implemented.

**Part 5 — Three-tier topology**

Stand up a meta-manager (port 12094 + CMS server 12213), a sub-manager (port
11094 + CMS server 11213 + CMS client to 12213), and a leaf data server (CMS
client to 11213). Issue `kXR_locate` to the meta-manager for a file held by
the leaf. Assert the client ultimately receives `kXR_redirect` to the leaf's
host:port.

**Part 6 — `kYR_select` mock flow**

Use the mock CMS manager fixture. Configure the sub-manager with a CMS client
pointing to the mock. Send `kXR_locate` for a path not in the local registry.
Assert the mock receives a `kYR_locate` frame with the correct streamid and
path. Send back a `kYR_select` frame from the mock. Assert the sub-manager
emits `kXR_redirect` to the client naming the host:port from the select frame.

**Part 7 — Registry-full counter**

Configure `xrootd_registry_slots 4`. Connect five data servers via CMS. Assert
the `xrootd_registry_full_total` Prometheus counter increments for the fifth
registration, that a warning appears in the error log, and that the fifth
server is not returned by subsequent `kXR_locate` requests.

**Part 8 — `kYR_gone`**

Register a data server and assert `kXR_locate` redirects to it. Send a
`CMS_RR_GONE` frame for the registered path. Assert the path is removed from
the registry and that a subsequent `kXR_locate` for that path no longer
redirects to that server.

---

## Files changed

| File | Change | Status |
|---|---|---|
| `src/cms/cms_internal.h` | Added `CMS_RR_GONE 14`, `CMS_RR_LOCATE 2`, `CMS_RR_SELECT 10`, `CMS_RR_TRY 24`; `next_streamid` field | ✅ Steps 1a, 2, 4, 6 done |
| `src/cms/server_recv.c` | Added `CMS_RR_GONE` case calling `xrootd_srv_unregister_path()` | ✅ Step 1a done |
| `src/cms/recv.c` | Added `cms_wake_pending_session()` helper; `CMS_RR_SELECT` and `CMS_RR_TRY` cases | ✅ Step 6 done |
| `src/cms/send.c` | Added `ngx_xrootd_cms_send_locate()` and `ngx_xrootd_cms_next_streamid()` | ✅ Step 4 done |
| `src/manager/registry.h` | C99 flexible array member; `capacity` field; updated `xrootd_srv_configure_registry` signature | ✅ Step 1b done |
| `src/manager/registry.c` | Runtime zone size; `tbl->capacity` loop bounds and sentinel; full-table log and counter | ✅ Steps 1b, 2 done |
| `src/manager/pending.h` | New: `xrootd_pending_locate_t`, `xrootd_pending_table_t`, API declarations | ✅ Step 3 done |
| `src/manager/pending.c` | New: shm zone init, insert/lookup/remove with lock, lazy expiry reaping | ✅ Step 3 done |
| `src/read/locate.c` | CMS-suspend path when no registry match | ✅ Step 5 done |
| `src/read/open.c` | Same | ✅ Step 5 done |
| `src/config/config.h` | Updated `xrootd_srv_configure_registry` declaration; added `xrootd_pending_configure` declaration | ✅ Steps 1b, 3 done |
| `src/config/server_conf.c` | `registry_slots` UNSET + default-128 merge; `cms_locate_timeout` UNSET_MSEC + 5000 ms merge | ✅ Steps 1b, 3 done |
| `src/connection/recv.c` | Added `XRD_ST_WAITING_CMS` loop guard and timedout handler | ✅ Step 5 done |
| `src/stream/module.c` | Added `xrootd_registry_slots` and `xrootd_cms_locate_timeout` directive entries | ✅ Steps 1b, 3 done |
| `src/types/state.h` | Added `XRD_ST_WAITING_CMS` | ✅ Step 5 done |
| `config` | Added `pending.c` to `ngx_module_srcs` | ✅ Step 3 done |
| `src/metrics/metrics.h` | Added `registry_full_total` counter to `ngx_xrootd_metrics_t` | ✅ Step 1b done |
| `src/metrics/stream.c` | Added `xrootd_registry_full_total` Prometheus export | ✅ Step 1b done |
| `tests/test_manager_mode.py` | Part 3 (per-worker CMS) added; Parts 5–8 | Steps 2, 3–6 |

---

## Remaining work

The following items are needed before the hierarchical CMS implementation can
be considered production-complete.

### R1 — `kYR_try` test coverage

**Implemented:** `TestCmsKyrTry` in `tests/test_manager_mode.py` exercises
`kYR_try` (opcode 24). `cms_wake_pending_session()` parses the first
host:port entry from the ordered alternative list and wakes the suspended
client session exactly as `kYR_select` does.

The test fixture sends `CMS_RR_TRY` (opcode 24) with this payload format:

```
[hostname NUL-terminated]
[port 2 bytes big-endian]   ← first entry: this is what nginx should pick
[hostname NUL-terminated]   ← second entry: should be ignored
[port 2 bytes big-endian]
```

The assertions confirm the client receives `kXR_redirect` to the *first*
entry's port, not the second.

### R2 — True CMS-escalation three-tier test

**Implemented:** `TestCmsEscalation` in `tests/test_manager_mode.py` validates
the true **CMS escalation** path in addition to the static registry-hit path
covered by `TestThreeTierTopology`.

The escalation path — which is the entire purpose of `XRD_ST_WAITING_CMS` —
triggers when the sub-manager's local registry has *no* entry for the requested
path. The sub-manager must then:

1. Send `kYR_locate` to the meta-manager.
2. Suspend the client session (`XRD_ST_WAITING_CMS`).
3. Receive `kYR_select` from the meta-manager naming the correct leaf.
4. Wake the suspended session and emit `kXR_redirect` to the leaf.

The test stands up a sub-manager, a leaf data-server, and one mock CMS
meta-manager (Python thread):

```
Client
  └─ kXR_locate /escalate/file.dat
       │
       ▼
Sub-manager  (port S, registry_slots=0 or path not in registry)
  │  kYR_locate /escalate/file.dat
  │    (XRD_ST_WAITING_CMS)
  ▼
Mock meta-manager  (Python thread, CMS port M)
  │  kYR_select reply → leaf_host:leaf_port
  │
  └─ wakes sub-manager session
         │
         ▼
       kXR_redirect → leaf_port  (sent to Client)
```

The sub-manager must have `xrootd_cms_manager 127.0.0.1:{M}` pointing at the
mock meta CMS. The path `/escalate/file.dat` must **not** be registered in the
sub-manager's local registry (either use a fresh registry or a path that no
data server has registered). On receiving `kXR_locate` for that path the
sub-manager will miss locally and escalate.

This test is the most important one for production confidence because it is the
only test that exercises the full `kYR_locate` → suspend → `kYR_select` → wake
→ `kXR_redirect` pipeline under realistic conditions.

**Files:** add to `tests/test_manager_mode.py` as `TestCmsEscalation`.

---

## Proxy/gateway integration

The pending-locate infrastructure built for M6 has a natural extension that
enables a more powerful deployment mode: instead of *redirecting* a client to
a CMS-selected backend, nginx *proxies* the request on the client's behalf.

This matters in two common scenarios:

1. **NAT / firewall:** Clients are on a network that cannot reach data servers
   directly. A redirect to `storage-node-47.internal:1094` is useless because
   the client cannot connect. The gateway must proxy.

2. **Auth bridging:** The client presents a WLCG JWT to the gateway; the
   backend speaks GSI only. The gateway authenticates the client with the token,
   then connects to the backend with its own GSI credential — a protocol/auth
   translation that a redirect cannot do.

### Architecture: select-then-proxy

```
Client               Gateway (nginx-xrootd)              Backend
  │                        │                                │
  │── kXR_open /data ─────►│                                │
  │                        │  1. local registry miss        │
  │                        │  2. kYR_locate → parent CMS    │
  │                        │  (XRD_ST_WAITING_CMS)          │
  │                        │◄─ kYR_select host:port ────────│ (CMS channel)
  │                        │                                │
  │                        │  3. instead of kXR_redirect:   │
  │                        │     enter proxy mode to        │
  │                        │     the CMS-selected host:port │
  │                        │── handshake + kXR_login ──────►│
  │                        │── kXR_open /data ─────────────►│
  │◄─ ok (fh=N) ───────────│◄─ ok (upstream fh) ────────────│
  │                        │  fh_map[N] = upstream_fh       │
  │── kXR_read fh=N ──────►│── kXR_read fh=upstream ───────►│
  │◄─ data ────────────────│◄─ data ─────────────────────────│
```

The critical observation is that steps 1–2 are already implemented and tested.
The pivot point is step 3: instead of calling `xrootd_send_redirect()` in
`cms_wake_pending_session()`, call a new `xrootd_proxy_cms_selected()` that
bootstraps an upstream proxy connection to the CMS-nominated host:port.

### What needs to be built

#### G1 — Policy directive: `xrootd_cms_response redirect|proxy`

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_manager_mode on;
        xrootd_cms_manager parent.example.org:1213;
        xrootd_cms_response proxy;   # NEW: proxy instead of redirect
    }
}
```

Default `redirect` preserves current behaviour. `proxy` switches the wake
action in `cms_wake_pending_session()` from `xrootd_send_redirect()` to
`xrootd_proxy_cms_selected()`.

**File:** `src/config/config.h` + `src/config/server_conf.c` + directive entry
in `src/stream/module.c`.

#### G2 — `xrootd_proxy_cms_selected()` in `src/upstream/start.c`

When `cms_response == PROXY` the wake function, rather than redirecting,
allocates an upstream context (`xrootd_upstream_ctx_t`) and initiates a TCP
connect to the CMS-selected host:port. This is exactly what
`xrootd_upstream_start()` does today for the static `xrootd_upstream`
directive, with two differences:

- The target host:port comes from the `kYR_select` payload rather than static
  config.
- The in-flight `kXR_open` / `kXR_locate` request is already buffered in the
  connection (saved by `XRD_ST_WAITING_CMS`); it must be replayed once
  bootstrap completes, just as the existing proxy mode replays a request saved
  during bootstrap.

The file-handle translation table (`fh_map[16]`) and the `kXR_oksofar`
streaming relay from `src/upstream/response.c` apply unchanged.

**Files:** `src/upstream/start.c` (new path in `xrootd_proxy_cms_selected`),
`src/upstream/bootstrap.c` (reuse), `src/cms/recv.c` (call site change when
`cms_response == PROXY`).

#### G3 — Auth bridging for CMS-selected upstreams

When `xrootd_cms_response proxy` is set, the upstream auth mode is controlled
by the existing `xrootd_proxy_auth` directive:

- `anonymous` (default) — anonymous login to the backend. Sufficient when the
  backend grants access by path ACL or trusts the gateway's IP.
- `forward` — replay the client's bearer token as-is. Works when both
  gateway and backend trust the same WLCG issuer.
- `sss` — generate an SSS credential from a shared key. Works for gateways
  serving xrootd daemons at the same site.
- `gsi` (future, tracked in proxy-mode-guide.md §Still needed) — present
  a service certificate. Required when the backend enforces GSI.

No new directives needed for G3; it reuses the existing proxy-auth enum.

#### G4 — CMS-driven upstream pool (optional, larger scope)

A further extension replaces the static `xrootd_proxy_upstream host:port` list
with a pool populated dynamically from CMS registrations. When the gateway also
runs `xrootd_cms_server on`, data servers that register with it are added to
the proxy upstream pool. Load-aware selection (lowest `util_pct` / highest
`free_mb` from `kYR_load` frames) replaces the current round-robin.

This gives a single nginx instance the ability to:
- Accept client connections.
- Accept data-server CMS registrations.
- Route and proxy client requests to the least-loaded registered server.
- Report aggregate capacity upward to a parent manager via its own CMS
  outbound connection.

In effect, the gateway becomes a **transparent aggregating proxy** rather than
a redirector — clients see a stable endpoint, backend topology changes are
invisible, and load balancing is CMS-driven.

**Approximate scope:** `src/upstream/pool.c` (new CMS-backed pool implementation
replacing `upstream_ctx->round_robin_idx`), `src/cms/server_handler.c` (call
`xrootd_pool_register()` on `kYR_login`, `xrootd_pool_update_load()` on
`kYR_load`, `xrootd_pool_unregister()` on disconnect / `kYR_gone`).

### Implementation sequencing for G1–G4

| Step | What | Depends on | Estimated effort |
|---|---|---|---|
| G1 | `xrootd_cms_response` directive | — | 1 day |
| G2 | `xrootd_proxy_cms_selected()` — redirect pivot | G1 | 2–3 days |
| G3 | Auth bridging reuse | G2 (uses existing proxy-auth enum) | — (already works) |
| G4 | CMS-driven pool | G2, existing `xrootd_cms_server` | 3–5 days |

G1+G2 are a self-contained unit that makes the select-then-proxy topology
work end-to-end. G4 is an independent quality improvement that can follow
later. G3 requires no new code beyond what GSI credential bridging already
needs (tracked separately in proxy-mode-guide.md).
