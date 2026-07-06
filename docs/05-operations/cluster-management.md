# Cluster Mode: Redirector / Manager / Cache

BriX-Cache as a full XRootD cluster participant — redirector, sub-manager, or data server behind a redirector. This page covers the architecture, configuration, and the CMS protocol interactions that hold it together.
cache node, not just a leaf data server.

The static `brix_manager_map` (see [manager-mode.md](manager-mode.md)) provides
a fixed path-to-backend mapping useful for small deployments. Cluster mode
replaces that with a **dynamic server registry** populated at runtime by data
servers that connect via the standard CMS management protocol.

> **Wire-level detail:** for the byte-by-byte CMS framing, the manager↔server↔client
> negotiation in both directions, and the cmsd-compliance gotchas, see
> [The CMS Cluster Protocol (`cms://`)](../04-protocols/cms-protocol.md).

## Implementation status

All five phases are fully implemented and tested.

| Phase | Description | Status |
|---|---|---|
| M1 | Server registry (`src/net/manager/registry.c`) | ✅ Complete |
| M2 | CMS server listener (`src/net/cms/server_*.c`) | ✅ Complete |
| M3 | Dynamic redirect in `kXR_locate` and `kXR_open` | ✅ Complete |
| M4 | Sub-manager / hierarchical mode | ✅ Complete |
| M5 | Cache node auto-registration / eviction unregister | ✅ Complete |

Test suite: `tests/test_manager_mode.py` (Part 1: static map; Part 2: live two-tier cluster).

---

## Cluster topology

```
  Clients
     │
     ▼
  Redirector  :1094              nginx-xrootd, brix_manager_mode on
     │   ▲
     │   │ kXR_redirect
     │   │
     │   │ CMS login/heartbeat
     │   ▼
  Data servers :1094             nginx-xrootd (existing leaf role)
                                   → CMS client reports to redirector :1213
     ↑
  CMS Server :1213               nginx-xrootd, brix_cms_server on
```

A **two-tier cluster** (redirector + data servers) needs M1 + M2 + M3 below.
A **three-tier cluster** (meta-manager → sub-manager → data servers) adds M4.
A **cache node** that advertises newly cached files to the redirector adds M5.

---

## What each phase adds

### M1 — Server Registry (`src/net/manager/`)

A shared-memory table (128 slots, spinlock-protected) maps each registered
data server to its host, port, exported path list, free space, and utilisation.
It is the source of truth read by the redirect logic.

**New files**: `src/net/manager/registry.h`, `src/net/manager/registry.c`

**API**:
```c
void brix_srv_register(const char *host, uint16_t port,
    const char *paths, uint32_t free_mb, uint32_t util_pct);

void brix_srv_update_load(const char *host, uint16_t port,
    uint32_t free_mb, uint32_t util_pct);

void brix_srv_unregister(const char *host, uint16_t port);

/* Returns 1 and fills host_out/port_out if a match is found. */
int brix_srv_select(const char *path, int for_write,
    char *host_out, size_t host_size, uint16_t *port_out);
```

`select()` uses longest-prefix matching over each server's colon-delimited path
list. For reads it picks the server with lowest `util_pct`; for writes the server
with the most `free_mb`.

**Implementation note**: follows the exact pattern in `src/protocols/root/session/registry.c`
(shm zone init, `ngx_shmtx_lock`/`unlock`, linear scan, `ngx_cpystrn` copies).

**Wiring**: call `brix_srv_configure_registry(cf)` from
`src/core/config/postconfiguration.c` (after the metrics zone, same pattern).
Add `src/net/manager/registry.c` to `ngx_module_srcs` in `config`.

---

### M2 — CMS Server Stream Module (`src/net/cms/server_*.c`)

Accepts incoming TCP connections from data servers on the CMS management port
(default 1213). Parses CMS login and heartbeat frames and writes to the M1
registry.

**New files**:

| File | Purpose |
|---|---|
| `src/net/cms/server_handler.c` | nginx stream handler: allocates `brix_cms_server_ctx_t`, wires read handler. Mirrors `src/protocols/root/connection/handler.c`. |
| `src/net/cms/server_recv.c` | Frame reader: accumulates 8-byte header + payload, dispatches on `rrCode`. Mirrors `src/net/cms/recv.c`. |
| `src/net/cms/server_send.c` | `cms_server_send_ping()` and `cms_server_send_status()`. Reuses `src/net/cms/wire.c` helpers. |
| `src/net/cms/server_timer.c` | Per-worker timer: pings each active CMS connection every `cms_server_interval` seconds (default 60); marks stale connections for disconnect. |
| `src/net/cms/server_module.c` | nginx stream module glue. Directive: `brix_cms_server on;`. |

**CMS opcodes handled**:

| `rrCode` | Action |
|---|---|
| `CMS_RR_LOGIN (0)` | Parse host/port/paths/free_mb/util_pct → `brix_srv_register()` |
| `CMS_RR_LOAD (16)` | Update load metrics → `brix_srv_update_load()` |
| `CMS_RR_AVAIL (12)` | Same as LOAD |
| `CMS_RR_SPACE (19)` | Same as LOAD |
| `CMS_RR_PONG (18)` | Update `ctx->last_seen` timestamp |
| Unknown | Ignore (log at `NGX_LOG_DEBUG`) |

On disconnect: if the connection logged in, call `brix_srv_unregister()`.

---

### M3 — Dynamic Redirect in XRootD Protocol

Inserts a registry query before the static `manager_map` fallback in the two
redirect-capable handlers.

**Changes to `src/protocols/root/read/locate.c`**:
```c
if (conf->manager_mode && !is_wildcard) {
    char     redir_host[256];
    uint16_t redir_port;
    if (brix_srv_select(reqpath_buf, 0, redir_host,
                          sizeof(redir_host), &redir_port)) {
        brix_log_access(ctx, c, "LOCATE", reqpath_buf, "registry", 1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_LOCATE);
        return brix_send_redirect(ctx, c, redir_host, redir_port);
    }
}
/* static manager_map fallback follows unchanged */
```

**Changes to `src/protocols/root/read/open.c`**: same registry-then-fallback pattern before
the local open path.

**Changes to `src/protocols/root/session/protocol.c`**: set `kXR_isManager` flag when
`conf->manager_mode` is on (extends the existing `manager_map` condition).

**New config directive**: `brix_manager_mode on|off` (default off).
Add `ngx_flag_t manager_mode` to `ngx_stream_brix_srv_conf_t` in
`src/core/types/config.h`. Register in `src/protocols/root/stream/module.c`, initialise/merge in
`src/core/config/server_conf.c`.

---

### M4 — Sub-manager / Hierarchical Mode

No new files. A sub-manager runs both the CMS client (reports upward) and the
CMS server listener (accepts downward), with `brix_manager_mode on`.

One change in `src/net/cms/send.c:ngx_brix_cms_send_login()`: when `manager_mode`
is on, set `CMS_LOGIN_MODE_MANAGER` in the mode field so the parent manager
recognises this node as a sub-manager rather than a leaf data server.

---

### M5 — Cache Node Integration

After a cache fill completes (`src/fs/cache/thread.c`), if `manager_mode` is on,
call `brix_srv_register(self_host, self_port, cached_path, ...)` so the
registry reflects this cache node as a valid source for the file.

When a file is evicted (`src/fs/cache/evict.c`), call `brix_srv_unregister_path()`
(a new single-path variant of unregister) to remove only that path from the
cache node's entry.

---

## Minimum viable configuration (two-tier cluster)

```nginx
# Redirector instance (nginx-redirector.conf)
stream {

    # CMS management port — data servers connect here
    server {
        listen 1213;
        brix_cms_server on;
    }

    # XRootD protocol port — clients connect here
    server {
        listen 1094;
        brix_root on;
        brix_export /dev/null;     # redirector has no local storage
        brix_manager_mode on;    # enables registry-based kXR_redirect
    }
}
```

```nginx
# Data server instance (nginx-dataserver.conf)
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;
        brix_cms_manager redirector.example.org:1213;  # existing directive
    }
}
```

---

## Source layout

| Phase | New files | Changed files |
|---|---|---|
| M1 registry | `src/net/manager/registry.h`, `registry.c` | `src/core/config/postconfiguration.c`, `config` |
| M2 CMS server | `src/net/cms/server_handler.c`, `server_recv.c`, `server_send.c`, `server_timer.c`, `server_module.c` | `config` |
| M3 dynamic redirect | — | `src/protocols/root/read/locate.c`, `src/protocols/root/read/open.c`, `src/protocols/root/session/protocol.c`, `src/core/types/config.h`, `src/protocols/root/stream/module.c`, `src/core/config/server_conf.c` |
| M4 sub-manager | — | `src/net/cms/send.c` |
| M5 cache integration | — | `src/fs/cache/thread.c`, `src/fs/cache/evict.c`, `src/net/manager/registry.c` |

---

## Existing code to reuse

| Component | Reuse |
|---|---|
| `src/protocols/root/session/registry.c` | shm zone + spinlock + fixed-slot array pattern for M1 |
| `src/net/cms/recv.c`, `send.c`, `wire.c` | CMS frame parser, encoder, byte-order helpers for M2 |
| `src/net/cms/connect.c` | timer and backoff pattern for `server_timer.c` |
| `src/core/config/manager_map.c` | longest-prefix matching algorithm (static fallback stays) |
| `src/protocols/root/connection/handler.c` | per-connection context init pattern for `server_handler.c` |
| `src/observability/metrics/config.c` | shm zone creation pattern for `src/core/config/postconfiguration.c` |

---

## Verification

```bash
# Two-tier smoke test

# 1. Start redirector
nginx -c tests/nginx-redirector.conf    # brix_manager_mode on :1094, cms :1213

# 2. Start data server (CMS client connects to redirector on startup)
nginx -c tests/nginx-dataserver.conf    # xrootd on :1095, cms_manager redirector:1213

# 3. Client hits redirector — should receive kXR_redirect to data server
xrdcp root://localhost:1094//data/file.txt /tmp/out.txt

# 4. Full test suite
pytest tests/test_manager_mode.py tests/test_conformance.py -x -q
```

For a three-tier test (M4): run three nginx instances — meta-manager, sub-manager,
data server — and verify that a client connecting to the meta-manager is ultimately
redirected to the correct data server through the sub-manager layer.
