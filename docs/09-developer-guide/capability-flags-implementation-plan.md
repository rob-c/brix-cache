# Server Capability Flags — Implementation Plan

**Status**: Draft  
**Scope**: All `ServerProtocolBody.flags` capability bits not yet advertised by nginx-xrootd  
**Wire spec**: `/tmp/xrootd-src/src/XProtocol/XProtocol.hh` lines 1198–1217  
**Primary files**: `src/protocol/flags.h`, `src/session/protocol.c`

---

## Background

Every `kXR_protocol` response carries a 32-bit `flags` field that tells the client what this server node is and what optional features it supports. Clients use this to choose paths, optimise transfers, and avoid sending unsupported opcodes.

Current nginx-xrootd advertisement (lines 112–114 of `src/session/protocol.c`):

```c
body.flags = htonl(kXR_isServer
                   | ((conf->manager_map || conf->manager_mode) ? kXR_isManager : 0)
                   | (offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0));
```

This is severely under-reporting. The server silently omits flags for features it already supports (pgread/pgwrite, POSC, cache, proxy), causing clients to miss optimisation opportunities and federation tools to misclassify nodes.

---

## Complete Flag Inventory

| Flag | Hex | Status | Action |
|------|-----|--------|--------|
| `kXR_isServer` | `0x00000001` | ✅ set | No change |
| `kXR_isManager` | `0x00000002` | ✅ set | No change |
| `kXR_attrCache` (protocol) | `0x00000080` | ❌ missing | Phase 1 |
| `kXR_attrMeta` | `0x00000100` | ❌ missing | Phase 2 |
| `kXR_attrProxy` | `0x00000200` | ⚠️ partial | Phase 1 |
| `kXR_attrSuper` | `0x00000400` | ❌ missing | Phase 2 |
| `kXR_attrVirtRdr` | `0x00000800` | ❌ missing | Phase 2 |
| `kXR_recoverWrts` | `0x00001000` | ❌ missing | Phase 3 |
| `kXR_collapseRedir` | `0x00002000` | ❌ missing | Phase 3 |
| `kXR_ecRedir` | `0x00004000` | ❌ out of scope | See §9 |
| `kXR_supposc` | `0x00100000` | ⚠️ unset | Phase 1 |
| `kXR_suppgrw` | `0x00200000` | ⚠️ unset | Phase 1 |
| `kXR_supgpf` | `0x00400000` | ❌ missing | Phase 4 |
| `kXR_anongpf` | `0x00800000` | ❌ missing | Phase 4 |
| `kXR_tlsLogin` | `0x04000000` | ✅ set | No change |
| `kXR_gotoTLS` | `0x40000000` | ✅ set | No change |
| `kXR_haveTLS` | `0x80000000` | ✅ set | No change |

---

## Naming Collision — `kXR_attrCache`

**Critical issue that must be resolved first.**

Our `src/protocol/flags.h` currently defines `kXR_attrCache = 256` (0x100) under the *stat response* flags section. This is a local extension used in per-file `kXR_stat` responses to indicate cached xattr metadata.

The upstream spec defines `kXR_attrCache = 0x00000080` (0x80) under *protocol response* flags to indicate the server is a cache node.

These are different values for different wire fields, but the shared name will cause include-order bugs and reader confusion the moment both sections are used in the same translation unit.

**Resolution (prerequisite to all other work):**

In `src/protocol/flags.h`, rename the stat-level definition:

```c
/* Before — in "Stat response flags" section */
#define kXR_attrCache   256   /* extended attribute metadata is locally cached */

/* After */
#define kXR_statAttrCache  256  /* per-file: xattr metadata is cached; server can
                                    satisfy kXR_fattr without a round-trip to origin.
                                    Local extension — not part of upstream protocol. */
```

Then update every callsite that references `kXR_attrCache` in a stat context:

```bash
grep -rn "kXR_attrCache" src/
```

Affected files are in `src/read/stat.c`, `src/read/statx.c`, and `src/fattr/`.

After the rename, add the protocol-level constant to the "Protocol response flags" section (see Phase 1).

---

## Phase 1 — Zero-Cost / Config-Derivable Flags

These flags require no new features. They either unconditionally apply or are derivable from existing config fields. All can land in a single commit.

### 1.1 `kXR_suppgrw` — pgread/pgwrite supported

**Meaning**: server implements paged read (`kXR_pgread`) and paged write (`kXR_pgwrite`) with per-page CRC32c checksums. Clients use this to know whether to use the faster paged path.

**Current state**: Features fully implemented (`src/read/pgread.c`, `src/write/pgwrite.c`) but flag never set. Clients that check the flag before attempting pgread will fall back to plain `kXR_read`.

**Implementation**:

In `src/protocol/flags.h`, add to the "Protocol response flags" section:
```c
#define kXR_suppgrw     0x00200000u  /* server supports kXR_pgread and kXR_pgwrite
                                        with per-page CRC32c integrity */
```

In `src/session/protocol.c`, add unconditionally to the flags expression:
```c
body.flags = htonl(kXR_isServer
                   | kXR_suppgrw   /* always: pgread/pgwrite implemented */
                   | kXR_supposc   /* always: POSC implemented */
                   | ...);
```

**Test**: `xrdfs root://localhost:11094/ query config suppgrw` should return `1`. Alternatively, inspect the raw `kXR_protocol` response flags in `test_manager_mode.py` with an assertion on `flags & 0x00200000`.

---

### 1.2 `kXR_supposc` — POSC supported

**Meaning**: server supports persist-on-successful-close (`kXR_posc` open flag). Files opened with POSC are held as temporary; abandoned opens are cleaned up automatically.

**Current state**: POSC is implemented in `src/read/open_request.c` and `src/read/close.c`, but flag never advertised.

**Implementation**: Same as 1.1 — add `kXR_supposc = 0x00100000u` to `flags.h` and include unconditionally in the flags expression.

```c
#define kXR_supposc     0x00100000u  /* server supports persist-on-successful-close */
```

---

### 1.3 `kXR_attrProxy` — proxy mode

**Meaning**: this node is an XRootD proxy — it forwards requests to a backend server rather than serving files locally. CMS and monitoring tools use this to distinguish proxy hops from data servers in topology maps.

**Current state**: Proxy mode is implemented (`src/upstream/`, `conf->proxy_enable`, `conf->proxy_upstreams`). Flag defined in `XProtocol.hh` but not in our `flags.h` and not set.

**Implementation**:

`src/protocol/flags.h`:
```c
#define kXR_attrProxy   0x00000200u  /* this node is a proxy; all file I/O is
                                        forwarded to a backend XRootD server */
```

`src/session/protocol.c` — add to the flags expression:
```c
| (conf->proxy_enable || conf->proxy_upstreams != NULL ? kXR_attrProxy : 0)
```

**Edge case**: A node can be simultaneously `kXR_isManager` and `kXR_attrProxy` (a proxying manager). Both flags must be set together in that topology. The spec allows this combination.

**Test**: Start the proxy-mode test server and assert `flags & kXR_attrProxy` is set. Add a negative test asserting the plain data server does *not* set this flag.

---

### 1.4 `kXR_attrCache` (protocol) — cache node

**Meaning**: this node is a read-through cache server (XCache-compatible). Clients may use this to understand why responses include `kXR_cachersp` stat bits, and federation tools route accordingly.

**Current state**: Cache is implemented (`conf->cache_root`, `conf->cache_origin_host`, `src/cache/`). Flag exists in upstream spec but missing from our `flags.h` and not set.

**Implementation**:

`src/protocol/flags.h` — add to "Protocol response flags" section:
```c
#define kXR_attrCache   0x00000080u  /* this node is a read-through cache (XCache);
                                        file data may be served from local cache_root */
```

**Note**: This is distinct from the stat-level `kXR_statAttrCache = 256` (renamed above). One is a server-level advertisement; the other is a per-file response hint.

`src/session/protocol.c`:
```c
| (conf->cache_root.len > 0 || conf->cache_origin_host.len > 0 ? kXR_attrCache : 0)
```

**Test**: Start the cache-mode test server (must have `xrootd_cache_root` set) and assert the protocol flag is present. Assert it is absent from a plain data server config.

---

## Phase 2 — New Config Directives for Node Roles

These flags represent topology roles that have no existing config directive. Each requires a new directive, a new `ngx_flag_t` field in the server config struct, and wiring into the protocol handler. They do not require new operational features — they are self-declarations used by the CMS topology layer.

### 2.1 `kXR_attrMeta` — metadata-only server

**Meaning**: this node serves namespace operations (stat, dirlist, locate, mkdir, rm, mv, chmod) but holds no file data. Clients and the CMS will not attempt open/read on this node. Used in large federations to separate namespace servers from data servers.

**XRootD use**: The upstream CMS uses this flag to exclude the node from file-availability lookups while still routing namespace queries to it.

**New directive**: `xrootd_metadata_only on|off` (default `off`)

**Config struct** (`src/config/server_conf.h`):
```c
ngx_flag_t  metadata_only;   /* advertise kXR_attrMeta; reject open/read */
```

**Merge** (`src/config/server_conf.c`):
```c
ngx_conf_merge_value(conf->metadata_only, prev->metadata_only, 0);
```

**Protocol flag** (`src/session/protocol.c`):
```c
| (conf->metadata_only ? kXR_attrMeta : 0)
```

**Behavioral enforcement**: When `metadata_only` is set, the open handler (`src/read/open_request.c`) must reject `kXR_open` with `kXR_Unsupported` or redirect to a CMS-selected data server if a manager map is configured. A metadata-only node with a manager map is valid (it namespace-serves and redirects I/O).

**Test cases**:
1. Protocol response has `kXR_attrMeta` set when directive is on.
2. `kXR_open` returns `kXR_Unsupported` on a pure metadata-only node (no manager map).
3. `kXR_stat` and `kXR_dirlist` succeed normally.
4. With a manager map configured, `kXR_open` redirects rather than failing.

`src/protocol/flags.h`:
```c
#define kXR_attrMeta    0x00000100u  /* metadata-only: serves namespace ops but
                                        holds no file data; kXR_open redirected */
```

---

### 2.2 `kXR_attrSuper` — supervisor (manager-of-managers)

**Meaning**: this node is a supervisor — a manager that coordinates other managers in a multi-tier hierarchy. The CMS uses this to build a three-level topology: supervisor → sub-manager → data server. The supervisor receives CMS space/availability reports from sub-managers and makes routing decisions at the top tier.

**XRootD use**: Sub-managers report to the supervisor node; clients are redirected through sub-managers rather than directly to data servers.

**Current state**: Two-tier manager→DS is fully implemented. Three-tier (meta→sub→DS) works but the meta node does not advertise `kXR_attrSuper`, which causes some topology-aware clients to misclassify it.

**New directive**: `xrootd_supervisor on|off` (default `off`; implies `manager_mode on`)

**Config struct**:
```c
ngx_flag_t  supervisor;   /* advertise kXR_attrSuper; top-tier manager role */
```

**Protocol flag**:
```c
| (conf->supervisor ? (kXR_isManager | kXR_attrSuper) : 0)
```

Note: `kXR_attrSuper` is only meaningful when `kXR_isManager` is also set. Enforce this in postconfiguration.

**Test cases**:
1. Three-tier cluster: meta node advertises `kXR_isManager | kXR_attrSuper`.
2. Sub-manager advertises `kXR_isManager` but not `kXR_attrSuper`.
3. Data server advertises only `kXR_isServer`.

`src/protocol/flags.h`:
```c
#define kXR_attrSuper   0x00000400u  /* supervisor role: top-tier manager in a
                                        three-level CMS hierarchy; implies kXR_isManager */
```

---

### 2.3 `kXR_attrVirtRdr` — virtual redirector

**Meaning**: this node is a virtual redirector — it translates logical path names into physical paths or alternate server endpoints without the CMS protocol. Unlike a CMS manager, a virtual redirector uses a static or plugin-driven mapping rather than dynamic server registration. Used in namespace virtualisation and path aliasing.

**XRootD use**: Clients that receive a redirect from a virtual redirector know not to cache the server's path mapping as authoritative for future requests.

**Current state**: A partial form exists via the manager map (`xrootd_cms_paths` / `manager_map`). A pure virtual redirector that maps paths without CMS involvement is not formally declared.

**New directive**: `xrootd_virtual_redirector on|off` (default `off`)

This flag is appropriate when:
- `manager_map` is configured but `cms_addr` is absent (no live CMS — purely static routing)
- Operator explicitly marks the node as a namespace-mapping gateway

**Config struct**:
```c
ngx_flag_t  virtual_redirector;  /* advertise kXR_attrVirtRdr */
```

**Protocol flag**:
```c
| (conf->virtual_redirector ? (kXR_isManager | kXR_attrVirtRdr) : 0)
```

**Auto-detection** (optional enhancement): set `kXR_attrVirtRdr` automatically when `manager_map != NULL && cms_addr.len == 0`. This avoids requiring the operator to set two directives for what is implicitly a static redirector.

**Test cases**:
1. Static manager-map-only config advertises `kXR_attrVirtRdr`.
2. CMS-backed manager does not set `kXR_attrVirtRdr`.
3. Explicit `xrootd_virtual_redirector on` sets the flag regardless.

`src/protocol/flags.h`:
```c
#define kXR_attrVirtRdr 0x00000800u  /* virtual redirector: translates logical
                                        paths via static map, not CMS protocol */
```

---

## Phase 3 — Behavioral Features

These flags require new server-side behaviour, not just self-declaration. They must only be set when the behaviour is actually implemented and active.

### 3.1 `kXR_recoverWrts` — write recovery

**Meaning**: the server can recover from partial or failed writes. If a connection drops mid-write, the server can detect the incomplete write, roll it back, or replay it from a client-provided journal. Clients use this to decide whether to retry writes without truncation risk.

**XRootD upstream**: Implemented via the POSC mechanism plus an optional write journal. The server keeps a per-file journal of in-progress writes; on reconnect it sends the client a `kXR_attn` with the resume offset.

**Scope and prerequisites**:
- Requires `kXR_attn` async notification (currently partial — see gap doc Section 12)
- Requires per-session write journalling: open → journal entry → write → close → discard journal; on disconnect without close → retain journal
- Requires new opcode support path: client reconnects, server matches sessid to journal, returns `kXR_oksofar` or `kXR_wait` with resume position

**Assessment**: Do not set `kXR_recoverWrts` until the write journal and `kXR_attn` resume-notification path are implemented. Setting it prematurely causes clients to retry writes they believe are safe, potentially creating double-write corruption.

**Implementation steps** (ordered):
1. Implement `kXR_attn` async server-push channel (`src/session/attn.c`)
2. Add per-session write journal (`src/write/journal.c`): open file → allocate journal entry in connection pool; on `kXR_close` → discard; on `ngx_stream_session_t` cleanup without close → persist journal file alongside the data file
3. On new session login: scan journal directory for matching `sessid`, if found send `kXR_attn` with resume offset
4. Only after steps 1–3 pass integration tests: add `kXR_recoverWrts = 0x00001000u` to `flags.h` and set it when `conf->allow_write` is true

**Config directive** (for explicit opt-in): `xrootd_recover_writes on|off` (default `off`; must not be auto-enabled)

`src/protocol/flags.h`:
```c
#define kXR_recoverWrts 0x00001000u  /* server can recover partial writes;
                                        requires kXR_attn async notification */
```

---

### 3.2 `kXR_collapseRedir` — collapse redirect chains

**Meaning**: when a client follows a chain of redirects (manager → sub-manager → DS), and then re-requests the same file, a collapse-redir server will respond with the final DS address directly, eliminating the intermediate hops. The server keeps a short-lived cache mapping `(client-ip, logical-path)` → `(DS-host, DS-port)` from recent resolved redirects.

**XRootD upstream**: Implemented in the CMS layer as a "recent redirect" table. When the same client requests the same path within a TTL window, the manager returns the DS address from its cache instead of querying CMS again.

**Scope**: Medium effort. Requires:
1. A small LRU map in shared memory (indexed by `(client_ip_prefix, canonical_path)`, value is `(host, port, expiry)`)
2. Integration point in `src/read/locate.c` and `src/read/open_request.c`: before querying CMS, check the LRU map; on CMS response, insert into map
3. Map eviction on configurable TTL (default 30 s)

**Implementation steps**:
1. Add `src/manager/redir_cache.c` — shared-memory LRU map, 512 slots, configurable TTL
2. In `xrootd_srv_select()` (`src/manager/registry.c`): check redir cache before normal registry scan; on miss, continue to CMS query; on hit, return cached entry
3. On CMS response delivering a DS address, insert into redir cache
4. New directive: `xrootd_collapse_redir on|off` (default `off`) and TTL: `xrootd_collapse_redir_ttl 30s`
5. Set flag only when `conf->collapse_redir` is true

**Config struct**:
```c
ngx_flag_t  collapse_redir;     /* enable redirect collapse cache */
ngx_msec_t  collapse_redir_ttl; /* cache entry TTL, default 30000 ms */
```

**Protocol flag**:
```c
| (conf->collapse_redir ? kXR_collapseRedir : 0)
```

**Test cases**:
1. First request through manager: takes CMS path, is redirected to DS.
2. Second identical request within TTL: manager responds immediately from cache, no CMS round-trip (observable via CMS log silence).
3. After TTL expires: cache miss, CMS consulted again.
4. Flag absent when directive is off.

`src/protocol/flags.h`:
```c
#define kXR_collapseRedir 0x00002000u /* server caches recent redirect targets;
                                          subsequent identical requests skip CMS */
```

---

## Phase 4 — GPF (Grouped Parallel Fetch) Flags

Grouped Parallel Fetch is a protocol extension that allows a manager to collect and batch multiple client read requests, dispatch them to data servers in parallel, and stream the results back to the client through the manager node (rather than redirecting each request). This is primarily used by ROOT batch processing where many small reads to the same files benefit from batching.

### 4.1 `kXR_supgpf` — server supports GPF

**Meaning**: this node can act as a GPF aggregator — it accepts `kXR_gpfile` (opcode 3005, retired from active use but still used by GPF clients) or the v5 equivalent, and coordinates parallel fetches from DS nodes.

### 4.2 `kXR_anongpf` — anonymous GPF

**Meaning**: this node will serve GPF requests from anonymous (unauthenticated) clients. Without this flag, GPF requests require auth credentials.

**Assessment**: GPF is a legacy feature primarily used by ROOT's `TXNetFile` and older clients. The `kXR_gpfile` opcode (3005) is retired in v5 protocol. Modern clients (ROOT 6.28+, xrdcp 5.x) use `kXR_readv` instead, which achieves similar batching.

Setting `kXR_supgpf` without implementing GPF aggregation would cause clients to send batched reads that the server cannot service, resulting in `kXR_Unsupported` errors or hangs.

**Recommendation**: Defer. If a concrete use case requires GPF (e.g., ROOT <6.28 compat), implement as a separate phase:
1. Re-activate `kXR_gpfile` dispatch in `src/handshake/dispatch_ops.c`
2. Implement `src/query/gpfile.c`: accept batch request, open N file handles, issue parallel `kXR_read` dispatches via thread pool, stream responses
3. Only then set `kXR_supgpf`; set `kXR_anongpf` additionally when `conf->auth == XROOTD_AUTH_NONE`

`src/protocol/flags.h`:
```c
#define kXR_supgpf      0x00400000u  /* server supports Grouped Parallel Fetch */
#define kXR_anongpf     0x00800000u  /* GPF available to anonymous clients */
```

---

## Out of Scope — `kXR_ecRedir`

`kXR_ecRedir = 0x00004000` indicates the server can redirect to erasure-coded storage segments. This requires an erasure-coding storage backend (Reed-Solomon stripe layout, parity servers, reconstruction protocol). nginx-xrootd is POSIX-backed only. This flag must not be set and is explicitly out of scope.

`src/protocol/flags.h`:
```c
#define kXR_ecRedir     0x00004000u  /* redirect to erasure-coded storage shards;
                                        out of scope — requires EC storage backend */
```

Define for documentation and grep completeness; never set.

---

## Implementation Sequence

```
Phase 0  (prerequisite):  rename kXR_attrCache stat flag → kXR_statAttrCache
Phase 1  (single commit): add kXR_attrCache/Proxy/suppgrw/supposc to flags.h;
                          wire all four into protocol.c flags expression
Phase 2a (new directive): kXR_attrMeta + metadata_only directive + open rejection
Phase 2b (new directive): kXR_attrSuper + supervisor directive
Phase 2c (new directive): kXR_attrVirtRdr + virtual_redirector directive
Phase 3a (feature):       kXR_collapseRedir + redir_cache.c (medium effort)
Phase 3b (feature):       kXR_recoverWrts — blocked on kXR_attn (high effort)
Phase 4  (deferred):      kXR_supgpf / kXR_anongpf — only if GPF use case emerges
```

Phases 0 and 1 are the highest-value items: they fix silent misreporting of already-implemented features (pgread, POSC, cache, proxy) and cost roughly 40 lines of code across two files.

---

## Changes Per File

### `src/protocol/flags.h`

1. Rename `kXR_attrCache = 256` → `kXR_statAttrCache = 256` (stat section)
2. Add to "Protocol response flags" section:
   ```c
   #define kXR_attrCache     0x00000080u
   #define kXR_attrMeta      0x00000100u
   #define kXR_attrProxy     0x00000200u
   #define kXR_attrSuper     0x00000400u
   #define kXR_attrVirtRdr   0x00000800u
   #define kXR_recoverWrts   0x00001000u
   #define kXR_collapseRedir 0x00002000u
   #define kXR_ecRedir       0x00004000u  /* out of scope — never set */
   #define kXR_supposc       0x00100000u
   #define kXR_suppgrw       0x00200000u
   #define kXR_supgpf        0x00400000u
   #define kXR_anongpf       0x00800000u
   ```

### `src/session/protocol.c`

Replace lines 112–114 with a factored expression:

```c
uint32_t caps = kXR_isServer
              | kXR_suppgrw
              | kXR_supposc
              | ((conf->manager_map || conf->manager_mode) ? kXR_isManager : 0)
              | (conf->supervisor         ? (kXR_isManager | kXR_attrSuper)   : 0)
              | (conf->virtual_redirector ? (kXR_isManager | kXR_attrVirtRdr) : 0)
              | (conf->metadata_only      ? kXR_attrMeta   : 0)
              | (conf->proxy_enable || conf->proxy_upstreams != NULL
                                         ? kXR_attrProxy   : 0)
              | (conf->cache_root.len > 0 || conf->cache_origin_host.len > 0
                                         ? kXR_attrCache   : 0)
              | (conf->collapse_redir     ? kXR_collapseRedir : 0)
              | (offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0);

body.flags = htonl(caps);
```

### `src/config/server_conf.h` (new fields for Phase 2 directives)

```c
ngx_flag_t  metadata_only;
ngx_flag_t  supervisor;
ngx_flag_t  virtual_redirector;
ngx_flag_t  collapse_redir;
ngx_msec_t  collapse_redir_ttl;
```

### `src/config/server_conf.c` (merge for new fields)

```c
ngx_conf_merge_value(conf->metadata_only,      prev->metadata_only,      0);
ngx_conf_merge_value(conf->supervisor,          prev->supervisor,          0);
ngx_conf_merge_value(conf->virtual_redirector,  prev->virtual_redirector,  0);
ngx_conf_merge_value(conf->collapse_redir,      prev->collapse_redir,      0);
ngx_conf_merge_msec_value(conf->collapse_redir_ttl, prev->collapse_redir_ttl, 30000);
```

### `src/config/directives.c` (new ngx_command_t entries)

```c
{ ngx_string("xrootd_metadata_only"),
  NGX_STREAM_SRV_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, metadata_only), NULL },

{ ngx_string("xrootd_supervisor"),
  NGX_STREAM_SRV_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, supervisor), NULL },

{ ngx_string("xrootd_virtual_redirector"),
  NGX_STREAM_SRV_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, virtual_redirector), NULL },

{ ngx_string("xrootd_collapse_redir"),
  NGX_STREAM_SRV_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, collapse_redir), NULL },
```

### `src/read/open_request.c` (Phase 2a enforcement)

After the existing manager-mode redirect block, add:

```c
if (conf->metadata_only && !conf->manager_map) {
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "open not available on metadata-only server");
}
```

When `manager_map` is configured, the existing redirect path handles it; the error path only fires for pure metadata-only nodes with no redirect target.

### `src/manager/redir_cache.c` (Phase 3a new file)

New source file for the collapse-redir LRU. Must be registered in `src/config/config.h` under `NGX_ADDON_SRCS` and will require a `./configure` run.

---

## Test Requirements

Each phase requires three tests: success path, error/negative path, and security/boundary.

### Phase 1 tests (`tests/test_protocol_flags.py`, new file)

```python
class TestCapabilityFlags:
    def test_suppgrw_always_set(self, server):
        flags = _get_protocol_flags(server["port"])
        assert flags & 0x00200000, "kXR_suppgrw must always be set"

    def test_supposc_always_set(self, server):
        flags = _get_protocol_flags(server["port"])
        assert flags & 0x00100000, "kXR_supposc must always be set"

    def test_cache_flag_set_for_cache_server(self, cache_server):
        flags = _get_protocol_flags(cache_server["port"])
        assert flags & 0x00000080, "kXR_attrCache must be set for cache server"

    def test_cache_flag_absent_for_plain_server(self, server):
        flags = _get_protocol_flags(server["port"])
        assert not (flags & 0x00000080), "kXR_attrCache must not be set for plain data server"

    def test_proxy_flag_set_for_proxy_server(self, proxy_server):
        flags = _get_protocol_flags(proxy_server["port"])
        assert flags & 0x00000200, "kXR_attrProxy must be set for proxy server"
```

### Phase 2 tests

```python
    def test_metadata_only_rejects_open(self, meta_server):
        with _xrd_session(meta_server["host"], meta_server["port"]) as s:
            status, _ = _open(s, "/any/path.txt", kXR_open_read)
            assert status == kXR_Unsupported

    def test_metadata_only_allows_stat(self, meta_server):
        with _xrd_session(meta_server["host"], meta_server["port"]) as s:
            status, _ = _stat(s, "/")
            assert status == kXR_ok

    def test_supervisor_flag_set(self, supervisor_server):
        flags = _get_protocol_flags(supervisor_server["port"])
        assert flags & 0x00000400
        assert flags & 0x00000002  # kXR_isManager also set

    def test_virtual_redirector_flag_set(self, static_redir_server):
        flags = _get_protocol_flags(static_redir_server["port"])
        assert flags & 0x00000800
```

### Phase 3 tests

```python
    def test_collapse_redir_flag_set(self, cluster):
        flags = _get_protocol_flags(cluster["redir_port"])
        assert flags & 0x00002000

    def test_collapse_redir_second_request_faster(self, cluster):
        # warm the cache
        t0 = time.monotonic()
        _open_through_redirector(cluster, "/test/file.txt")
        t1 = time.monotonic()
        # second request should not hit CMS
        _open_through_redirector(cluster, "/test/file.txt")
        t2 = time.monotonic()
        assert (t2 - t1) < (t1 - t0) * 0.5, "collapsed redirect should be faster"
```

---

## Callsite Rename Sweep (Phase 0 prerequisite)

After renaming `kXR_attrCache → kXR_statAttrCache` in `flags.h`, update all callsites:

```bash
# Find all affected callsites
grep -rn "kXR_attrCache" src/ tests/

# Expected callsites (stat context, should become kXR_statAttrCache):
#   src/read/stat.c         — stat response flag assembly
#   src/read/statx.c        — statx response flag assembly
#   src/fattr/dispatch.c    — fattr cache hint
```

Scope is small (3–5 callsites). Do the rename and verify build before any other Phase 1 changes.

---

## Wire Protocol Correctness

The `ServerProtocolBody.flags` field is a big-endian `uint32_t` sent in the response body immediately after the 8-byte response header. All values above are expressed as host-byte-order constants; `htonl()` is already applied at line 111 of `protocol.c`. No wire format changes are needed — only the bitmask value changes.

The response body size (`sizeof(ServerProtocolBody) = 8 bytes`) does not change regardless of which flags are set.

---

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| 0 — rename | Rename causes build error at callsites | Sweep all callers before build; compiler catches misses |
| 1 — always-on | Clients that haven't seen `suppgrw` flag may behave differently | All XRootD clients ≥3.0 handle unknown flags gracefully per spec |
| 1 — proxy/cache | Config detection logic incorrect | Test both positive (flag set) and negative (flag absent) cases |
| 2 — new directives | `metadata_only` enforcement in open handler too broad | Guard: only reject when no manager_map configured |
| 2 — supervisor | `kXR_isManager` also required alongside `kXR_attrSuper` | Assert both bits in test |
| 3a — collapse redir | Shared memory race in LRU update | Use atomic exchange on the slot; accept occasional stale hit |
| 3b — recoverWrts | Premature flag set causes client double-write | Hard constraint: blocked until `kXR_attn` lands |
| 4 — GPF | `kXR_gpfile` opcode (3005) is retired | Deferred indefinitely; `kXR_readv` is the modern replacement |
