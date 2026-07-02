> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

# Architecture & Process Model — Official XRootD vs. nginx-xrootd

This document compares the **official XRootD C++** server with the **nginx-xrootd**
module on five axes: overall architecture, the process/concurrency model, the
per-request lifecycle, the memory model, and the build/config model. Every claim
is grounded in source read on both sides. Where a fact could not be verified from
source it is marked "not verified" rather than guessed.

Source roots:

- Official XRootD: `/tmp/xrootd-src/src` (directories `Xrd/`, `XrdXrootd/`,
  `XrdOuc/`, `XrdSys/`, `XrdSfs/`, `XrdOss/`, `XrdCms/`, `XrdFrm/`).
- This module: `/home/rcurrie/HEP-x/nginx-xrootd/src` (plus the top-level
  `config` build script).

For the wire-protocol-level comparison, see
[02-rootd-protocol.md](./02-rootd-protocol.md); for the multi-implementation
survey see
[../xrootd-implementations.md](../xrootd-implementations.md); for the
feature-by-feature parity matrix see
[../../source-verified-xrootd-comparison.md](../../source-verified-xrootd-comparison.md).

---

## Scope

The two systems solve the same problem — serve the XRootD `root://` wire protocol
(and HTTP/WebDAV) over a POSIX namespace — but from opposite architectural
starting points:

- **Official XRootD** is a **standalone, single-process, multi-threaded C++
  daemon** (`xrootd`). It owns its own `main()`, its own listener/scheduler/poller
  layer (the `Xrd/` framework), and loads the actual protocol, security, and
  storage behavior as **`.so` plugins** selected by `xrootd.cfg` directives.
  Clustering and tape staging are **separate companion daemons** (`cmsd`, `frmd`).

- **nginx-xrootd** is **not a daemon at all** — it is an **nginx module**. nginx
  owns `main()`, the listening sockets, the worker-process model, and the
  per-worker **event loop**; the module contributes a **stream handler** (for
  `root://`) and an **HTTP handler** (for WebDAV/S3/metrics) plus a thread pool
  detour for blocking I/O. There are no companion daemons: clustering (manager
  mode/CMS), tape staging (FRM), metrics, and the dashboard all run inside the
  same nginx worker processes.

This page deliberately stays at the architecture/process/memory/build layer. It
does not re-litigate wire bytes, auth dialects, or feature parity — those are
covered in the sibling documents linked above.

---

## In official XRootD

### Process / daemon model

The daemon entry point is `Xrd/XrdMain.cc` (`main()`). It is a **single process,
multi-threaded** model — there is no per-connection process fork and no worker
process pool. `main()`:

1. Sets up signal handling, timezone, and stack size, then calls
   `XrdConfig::Configure()` (`Xrd/XrdConfig.cc`) to parse the config file and load
   plugins.
2. Spawns one **accept thread** per configured listening port via
   `XrdSysThread::Run(... mainAccept ...)` (the last port is handled inline on the
   main thread), plus a separate admin thread (`mainAdmin`).
3. From there, all request work runs on a **central thread pool** owned by
   `XrdScheduler`, not on the accept threads.

Two **separate companion daemons** provide cluster and tape functionality and are
not part of the `xrootd` data-server process:

- **`cmsd`** (`XrdCms/`) — the Cluster Management System daemon. Provides
  distributed file location / redirection for a federation of data servers.
- **`frmd` / FRM** (`XrdFrm/`) — the File Residency/Replication Manager: a full
  daemon + admin/migrate/purge tool ecosystem (`frm_admin`, `frm_purged`,
  `frm_xfrd`, `frm_xfragent`) for disk↔tape staging.

### Network / scheduler layer (the `Xrd/` framework)

This is XRootD's own async server framework, independent of the protocol:

- **`XrdScheduler`** (`Xrd/XrdScheduler.hh/.cc`) — the worker **thread pool**.
  `class XrdScheduler : public XrdJob`. Its constructor takes `minw` (min workers,
  default **8**), `maxw` (max workers, default **8192**, hard-capped at
  `MAX_SCHED_PROCS 30000`), and `maxi` (max idle seconds, default **780**). Jobs
  are enqueued via `Schedule(XrdJob*)`; worker threads block on a `WorkAvail`
  semaphore; `DoIt()` periodically reaps idle threads above `min_Workers`. Threads
  are **spawned and reaped dynamically** with demand.
- **`XrdLink`** (`Xrd/XrdLink.hh`) — represents one client connection.
  `class XrdLink : public XrdJob`, so a connection *is* a schedulable work unit:
  when a link becomes readable, it is scheduled, a pool thread runs its protocol's
  `Process()`, and the link is returned to the poller.
- **`XrdPoll`** (`Xrd/XrdPoll.hh/.cc`) — the readiness layer. There are
  **`XRD_NUMPOLLERS 3`** poller threads; on Linux they use **epoll**
  (`XrdPollE.hh`), elsewhere `poll()` (`XrdPollPoll.hh`). Pollers communicate via
  a control pipe (`PipeData`, enum `{EnFD, DiFD, RmFD, Post}`). The pollers detect
  readiness; the scheduler thread pool does the work.
- **`XrdProtocol`** (`Xrd/XrdProtocol.hh`) — the protocol **plugin interface**.
  `class XrdProtocol : public XrdJob` with the pure-virtual triad
  `Match(XrdLink*)` / `Process(XrdLink*)` / `Recycle(...)` plus `Stats(...)`.
  Protocol objects are pooled and reused (`Recycle`).
- **`XrdProtLoad`** (`Xrd/XrdProtLoad.hh/.cc`) — `class XrdProtLoad : public
  XrdProtocol`, the protocol **router**. It maps listening ports to loaded
  protocol plugins (`portVec` of `portMap`), and `Load(...)` dlopens each plugin
  through `XrdOucPinLoader`.

The key implication: in XRootD, **a connection is a job and a request is run on a
borrowed pool thread**. Concurrency is bounded by the thread pool size, not by a
fixed worker count.

### Protocol plugins

The wire behavior lives in dynamically loaded `.so` protocol plugins, not in the
`Xrd/` core:

- **`XrdXrootd/`** — the `root://` protocol plugin. `class XrdXrootdProtocol :
  public XrdProtocol, public XrdXrootd::gdCallBack, public XrdSfsDio, public
  XrdSfsXio` (`XrdXrootdProtocol.hh`). It overrides `Match` / `Process` /
  `Recycle`. Request dispatch is the `do_*` handler family
  (`do_Auth`, `do_Open`, `do_Read`, `do_Write`, `do_Close`, `do_Locate`, …)
  selected from `Process2()` (`XrdXrootdXeq.cc`). Pre-login gating restricts a
  fresh connection to protocol/login/bind until `XRD_LOGGEDIN`/`XRD_NEED_AUTH`
  state allows more.
- **The "Resume" continuation pattern.** Rather than block a pool thread inside a
  partial read, `XrdXrootdProtocol` carries a member-function pointer
  `int (XrdXrootdProtocol::*Resume)()` (`XrdXrootdProtocol.hh:589`). A handler that
  cannot finish (short read, offloaded I/O) stashes a continuation in `Resume` and
  returns; `DoIt()` re-invokes `(*this.*Resume)()` when rescheduled. This is
  XRootD's hand-rolled coroutine — conceptually the same trick nginx-xrootd uses
  with `NGX_AGAIN` + `XRD_ST_*` suspend states (see below).
- **`XrdHttp/`** — the HTTP/WebDAV protocol plugin (`XrdHttpProtocol`), another
  `XrdProtocol` implementation, loaded on its own port.

Plugins are loaded as `.so` files through a versioned ABI:

- **`XrdSys/XrdSysPlugin.hh`** — the low-level `dlopen` wrapper
  (`getPlugin(...)`, `VerCmp(...)`).
- **`XrdOuc/XrdOucPinLoader`** — the higher-level loader with version checking and
  symbol resolution.
- **`XrdVersionPlugin.hh`** — the ABI version rules. Each plugin exposes a C
  entry point (e.g. `XrdgetProtocol`, `XrdSfsGetFileSystem2`,
  `XrdOssGetStorageSystem2`, `XrdSecGetProtocol`) plus a `…Version` symbol that the
  loader version-checks (`Required` / `Optional` / `DoNotChk`).

### Storage / filesystem abstraction

`XrdXrootdProtocol` does not touch the disk directly — it calls a **virtual
filesystem plugin**:

- **`XrdSfs/XrdSfsInterface.hh`** — `XrdSfsFileSystem` / `XrdSfsFile` /
  `XrdSfsDirectory`. Return codes are `SFS_OK` / `SFS_ERROR` / `SFS_REDIRECT`
  (-256) / `SFS_STALL` / `SFS_STARTED`. The `SFS_REDIRECT` return is how a
  manager/redirector (or EOS MGM) bounces a client to another server.
- **`XrdOss/XrdOss.hh`** — the lower `XrdOssDF` storage-system interface that the
  default OFS layer (`XrdOfs`) calls into.

Sites select which filesystem/storage plugin to load with `xrootd.fslib` /
`ofs.osslib`. The default OFS+OSS stack serves a local POSIX namespace; EOS,
XrdPss, XrdCeph, XrdPfc, etc. are alternative plugins that satisfy the same
interfaces.

### Memory model

XRootD is C++ with explicit `new`/`delete`, but the hot request/response path is
served from a **pooled buffer manager**, not raw allocation:

- **`Xrd/XrdBuffer.hh`** — `XrdBuffer` wraps a `char *buff` of `bsize`, allocated
  with libc `malloc`/`free` (destructor `free(buff)`), with a `next` pointer for
  free-listing.
- **`XrdBuffManager`** — a process-wide singleton pool (`extern XrdBuffManager
  BuffPool`). It keeps **`XRD_BUCKETS 12`** power-of-two size classes. `Obtain(sz)`
  hands out a buffer of the nearest class; `Release(bp)` returns it to the
  free-list; `Reshape()` periodically rebalances under a `XrdSysCondVar`. So a
  request's data buffer is **recycled across requests**, amortizing allocation.

Object lifetimes (protocol objects, links) are managed by **explicit
recycle/destroy** (`XrdProtocol::Recycle`, link pooling). There is no arena: each
object owns its own memory and is responsible for releasing it.

### Config model

- **One config file** (`xrootd.cfg`, default `/etc/xrootd/xrootd.cfg`,
  overridable via `XrdCONFIGFN`), parsed by `XrdConfig::Configure()` using the
  `XrdOucStream` tokenizer. The parser natively understands **host-conditional
  `if … fi` blocks** so one file can configure a whole cluster.
- **Scoped directive prefixes** select and configure each subsystem/plugin:
  `xrd.` (core daemon: `xrd.protocol`, `xrd.port`, `xrd.sched`),
  `all.` (global, e.g. `all.manager`, `all.export`),
  `ofs.` (`ofs.osslib`, `ofs.authlib`, `ofs.ckslib`),
  `oss.` (`oss.namelib`, …),
  `xrootd.` (`xrootd.fslib`, `xrootd.async`, `xrootd.seclib`),
  `sec.` (`sec.protocol`, `sec.protbind`),
  `acc.` (XrdAcc authorization),
  `cms.` (cluster), `http.` (`http.secxtractor`, `http.exthandler`),
  `pfc.` (cache), `frm.` (residency manager).
- The model is **plugin-selection-by-directive**: `xrd.protocol`, `ofs.osslib`,
  `sec.protocol`, etc. each name a `.so` to dlopen at startup.
- **Reload model**: configuration is read at process start; the standard
  operational pattern is to restart the daemon (or send signals to companion
  daemons). There is no nginx-style binary-upgrade/SIGHUP graceful worker
  reload built into the `Xrd/` core (not verified that a graceful in-place reload
  exists).

---

## In nginx-xrootd

### Architecture: a module, not a daemon

nginx-xrootd ships as an nginx **add-on module** (`ngx_addon_name =
ngx_stream_xrootd_module`, top-level `config`). It plugs into nginx's existing
machinery:

- The `root://` binary protocol is an **`NGX_STREAM_MODULE`** stream handler
  (`src/stream/module_definition.c`).
- WebDAV/XrdHttp, S3, and the dashboard/admin are **HTTP** handlers
  (`src/webdav/`, `src/s3/`, `src/dashboard/`), and `/metrics` is a second HTTP
  module (`ngx_http_xrootd_metrics_module`, registered in `config`).

The module descriptor (`src/stream/module_definition.c`) wires nginx's lifecycle
hooks:

```c
static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    NULL,                                 /* preconfiguration  */
    ngx_stream_xrootd_postconfiguration,  /* postconfiguration */
    NULL, NULL,                           /* (no) main conf    */
    ngx_stream_xrootd_create_srv_conf,    /* create srv conf   */
    ngx_stream_xrootd_merge_srv_conf,     /* merge srv conf    */
};
ngx_module_t ngx_stream_xrootd_module = {
    ...
    NULL,                            /* init master  */
    xrootd_imp_init_module,          /* init module  */
    ngx_stream_xrootd_init_process,  /* init process */
    NULL, NULL, xrootd_exit_process, NULL,
    ...
};
```

There are **no companion daemons**. Manager/redirector mode (`src/manager/`,
`src/cms/`), FRM tape staging (`src/frm/`), metrics, SRR, and the dashboard all
run **inside the nginx workers**.

### Process / concurrency model: one event loop per worker

nginx runs a master process plus **N worker processes** (one per
`worker_processes`). Each worker is **single-threaded with one epoll/kqueue event
loop**. The module's protocol logic therefore runs **single-threaded per worker**;
there is no per-connection thread or per-request job (contrast XRootD's thread
pool).

Consequences, made explicit in the codebase conventions
([nginx-idioms-for-cpp-reviewers.md](../../../09-developer-guide/nginx-idioms-for-cpp-reviewers.md)
and CLAUDE.md):

- **Protocol handlers must never block.** A blocked handler freezes *every*
  connection on that worker. No `sleep`, no blocking `read`, no long CPU.
- **Blocking I/O is exiled to a thread pool.** `pread`/`pwrite`/`fsync`/`readdir`
  + per-page CRC are offloaded via `ngx_thread_pool_run` (`src/core/aio/`), with an
  optional io_uring tier above the pool (`src/core/aio/uring.c`, Phase 44, off by
  default). The worker thread does *only* the syscall and posts a `_done`
  callback back onto the event loop; while in flight the connection sits in
  `XRD_ST_AIO` with read/write events disarmed and `ctx->destroyed` checked in
  every callback.
- **Other potentially-blocking work is cached or pooled** so it never stalls the
  loop: a per-worker DH keypool (so `ffdhe2048` keygen never runs inline), an
  in-flight GSI-handshake gauge that sheds with `kXR_wait`
  (`xrootd_gsi_max_inflight_handshakes`), and always-on per-worker token L1 +
  optional SHM L2 validation caches (so RSA/ECDSA verify never re-runs on the
  loop).

Cross-worker state lives in **shared memory (SHM)**, since workers are separate
processes and share nothing by default:

- SHM tables are allocated through `xrootd_shm_table_alloc()` /
  `xrootd_shm_table_mutex_create()` (`src/core/compat/shm_slots.c`), which allocate the
  table *from the slab pool* so nginx's `ngx_unlock_mutexes()` (run on every child
  death) does not crash the master.
- Those table mutexes are deliberately created in **spin+yield-only mode**
  (`mtx->semaphore = 0`), not nginx's default POSIX-semaphore mode, because the
  semaphore wakeup path is lost-wakeup-prone under heavy cross-worker contention
  (postmortem: 60–450 s multi-worker `kXR_open` stalls). The critical sections are
  microsecond fixed-slot scans, so spinning is correct and cheaper. See INVARIANT
  #10 in CLAUDE.md and
  `docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`.
- SHM-backed state includes per-server metrics (`ngx_xrootd_metrics_t`,
  `src/connection/handler.c`), the session/handle/manager registries
  (`src/manager/registry.c`), the redirect-collapse cache
  (`src/manager/redir_cache.c`), the native-TPC key registry
  (`src/tpc/key_registry.c`), the FRM durable queue, and rate-limit/KV zones.

### Per-connection state: `xrootd_ctx_t`

Each accepted TCP connection gets one `xrootd_ctx_t` (`src/core/types/context.h`),
allocated from the connection pool at connect time
(`ngx_stream_xrootd_handler()`, `src/connection/handler.c`):

```c
ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
ctx->session = s;
ctx->state   = XRD_ST_HANDSHAKE;
ctx->identity = xrootd_identity_alloc(c->pool);
...
ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);
c->read->handler  = ngx_stream_xrootd_recv;
c->write->handler = ngx_stream_xrootd_send;
ngx_stream_xrootd_recv(c->read);          /* fire the first read */
```

`xrootd_ctx_t` is the module's `this`: it carries the protocol state machine
(`XRD_ST_*`), the file-handle slot table (`files[XROOTD_MAX_FILES]`, `fd = -1`
sentinel), a 16-byte opaque session id (built from time/pid/pointer/random —
explicitly *not* crypto-grade), the per-connection **pipeline rings** (`out_ring`
+ `rd_pool`, sized by `xrootd_pipeline_depth`), the cached network-fault
deadlines, and the metrics slot pointer. It is fetched at the top of every handler
via `ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module)`.

### The recv state machine (the "Resume" equivalent)

`src/connection/recv.c` (`ngx_stream_xrootd_recv`) is a byte-accumulating state
machine that replaces XRootD's `Resume` member-pointer with explicit
`XRD_ST_*` states and the `NGX_AGAIN` yield convention:

```
HANDSHAKE(20B) → REQ_HEADER(24B) → REQ_PAYLOAD(dlen) → dispatch
```

plus suspend states (`XRD_ST_SENDING`, `XRD_ST_AIO`, `XRD_ST_UPSTREAM`,
`XRD_ST_WAITING_CMS`, `XRD_ST_TLS_HANDSHAKE`, …) that return to the loop
immediately without reading. A critical **security invariant** is enforced here:
`dlen` is validated against `xrootd_max_payload_for_request(reqid)` **before any
allocation** — per-opcode caps (write/pgwrite → `XROOTD_MAX_WRITE_PAYLOAD`, auth →
16 KiB, everything else → path + 64 B) — so an oversized frame is rejected, not
allocated.

### Dispatch

When a full request is framed, `xrootd_dispatch()` (`src/handshake/dispatch.c`)
runs a **cascade of single-purpose dispatchers**, each returning
`XROOTD_DISPATCH_CONTINUE` if the opcode is not its own:

1. `xrootd_verify_pending_sigver` + `xrootd_signing_enforce_level` (signing gate,
   fail-closed before any handler).
2. `xrootd_dispatch_session_opcode` (protocol/login/auth/bind/endsess/ping/set).
3. proxy mode → `xrootd_proxy_dispatch` (gated on `ctx->auth_done`, not merely
   `logged_in` — a fail-open lesson).
4. rate-limit gate (`xrootd_rl_stream_gate`).
5. `xrootd_dispatch_read_opcode` / `xrootd_dispatch_write_opcode`, optionally
   bracketed by impersonation begin/end.
6. `xrootd_dispatch_signing_opcode` last.

This is functionally the same role as XRootD's `Process2()` `switch` over `do_*`
handlers, but realized as a table/cascade rather than a hand-split `switch`, with
auth gates encoded as macros (`require_auth`, `require_write`) and **no `goto`**
anywhere (hard rule; cleanup is early-return + helper decomposition).

### Memory model: nginx pools + arena lifetimes

There is no RAII and no `new`/`delete`; memory is **arena-allocated from nginx
pools** whose lifetimes nginx owns:

- `ngx_palloc(pool, n)` / `ngx_pcalloc(pool, n)` for pool-scoped allocations;
  `r->pool` (HTTP, freed at request end) or `c->pool` (stream, freed at connection
  close). Every pool allocation is conceptually a `unique_ptr` owned by the pool,
  all released together.
- `ngx_alloc` / `ngx_free` is the sanctioned **raw heap** path for stream buffers
  with explicit lifetime that must survive across requests on a persistent
  connection. For example the recv payload buffer
  (`xrootd_ensure_payload_buffer`, `recv.c`) and the AIO scratch slots
  (`read_scratch`/`write_scratch`, `src/core/aio/`) are grow-only raw-heap buffers
  reused across requests and freed once at disconnect — pool allocation there
  caused a use-after-free in nginx's large-allocation list (documented in
  `src/core/aio/README.md`).
- Deterministic cleanup (OpenSSL objects, fds, temp files) uses
  `ngx_pool_cleanup_add(pool, …)` — the manual destructor equivalent
  (`src/crypto/scoped.h`).
- The output path is buffer/chain assembly: an `ngx_chain_t` of `ngx_buf_t`
  (memory-backed `b->memory=1` for TLS; file-backed `b->in_file=1` for cleartext
  `sendfile`) — never raw `write`/`send`. The shared chain builders live in
  `src/core/aio/buffers.c` so sync and async paths produce byte-identical wire output.

So where XRootD recycles fixed-size buffers from a global `XrdBuffManager`,
nginx-xrootd uses **per-request/per-connection arenas plus a few long-lived
grow-only scratch buffers** owned by the ctx.

### Build / config model

The build is governed by exactly two things (CLAUDE.md "BUILD GOVERNANCE"):

1. **The top-level `config` script** (an nginx add-on `config`). It sets
   `ngx_addon_name`, builds `ngx_module_srcs` (the source list — the nginx
   equivalent of `NGX_ADDON_SRCS`), `ngx_module_deps`, `ngx_module_incs`, and
   per-module `ngx_module_libs` via repeated `. auto/module` blocks (so a dynamic
   `.so` build links its own libs, e.g. xml2/jansson/curl/krb5 — putting them only
   in `CORE_LIBS` would break `dlopen`). It also probes external deps
   (libxml2/jansson/libcurl mandatory; krb5/liburing optional) and sets the
   performance/hardening CFLAGS (default `-O3 -march=x86-64-v2`, FORTIFY,
   stack-protector, CET).
2. **nginx's own `./configure`**, invoked with `--add-module=$REPO`, which picks up
   that `config` and regenerates the build tree.

```bash
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-threads --add-module=$REPO
make -j$(nproc)
```

`--with-threads` is **required** (enforced in `config`) because async I/O, TPC,
and S3 PUT depend on the thread pool. A new `.c` file must be added to the source
list in `config` or `./configure` will not compile it; generated Makefiles and
nginx's own `src/core|event|http` are never edited.

Runtime configuration is **nginx config**, not a separate `xrootd.cfg`. Directives
live inside nginx `stream { server { … } }` (for `root://`) and `http { server {
location { … } } }` (for WebDAV/S3/metrics) blocks. The directive table is
`ngx_stream_xrootd_commands[]` (`src/stream/module.c`): `xrootd on;` enables the
handler, `xrootd_root`, `xrootd_auth`, `xrootd_allow_write`, `xrootd_tls`,
`xrootd_token_jwks`, `xrootd_manager_mode`, `xrootd_frm`, etc. Almost every
directive is `NGX_STREAM_SRV_CONF` (per-server, stored at an `offsetof` into
`ngx_stream_xrootd_srv_conf_t`); a few SHM-zone directives
(`xrootd_rate_limit_zone`, `xrootd_kv_zone`) are `NGX_STREAM_MAIN_CONF`. Config
objects follow nginx's `create_srv_conf` → `merge_srv_conf` (main→srv→loc) merge
discipline with `NGX_CONF_UNSET` sentinels, validated in
`ngx_stream_xrootd_postconfiguration` (`src/core/config/postconfiguration.c`) where
`nginx -t` catches misconfigured paths before traffic.

The deployment unit is therefore **one nginx instance**: start/stop/reload uses
the standard nginx lifecycle (`nginx -s reload` does a graceful worker reload;
`nginx -t` validates config), and all module state lives in the workers + SHM
zones.

---

## Request lifecycle side-by-side

Both sides implement the same logical sequence — accept → frame → handshake →
login/auth → dispatch → handler → response — but on different execution
substrates. The "Resume continuation" (official) and the `XRD_ST_*` + `NGX_AGAIN`
suspend states (nginx) are the same idea: survive a partial read without holding a
thread.

| Stage | Official XRootD | nginx-xrootd |
|---|---|---|
| Accept | accept thread (`mainAccept`) hands the fd to a poller; an `XrdLink` is created | nginx core accepts; `ngx_stream_xrootd_handler()` runs, allocates `xrootd_ctx_t`, arms read/write handlers |
| Readiness | one of 3 `XrdPoll` epoll threads marks the link readable, schedules it | the worker's single epoll loop calls `ngx_stream_xrootd_recv` |
| Run context | a **borrowed `XrdScheduler` pool thread** runs the protocol | the **worker's own event-loop thread** runs the handler — never blocks |
| Framing | `XrdXrootdProtocol::Process2()` reads header/body; short read → stash `Resume`, return | `recv.c` accumulates 20B/24B/dlen; incomplete → `NGX_AGAIN`, return to loop |
| Handshake/login/auth | `do_Login` / `do_Auth`, gated by `XRD_LOGGEDIN`/`XRD_NEED_AUTH` | `xrootd_dispatch_session_opcode`, gated by `ctx->auth_done` |
| Dispatch | `switch` over opcode → `do_Open`/`do_Read`/… | cascade `xrootd_dispatch_{session,read,write,signing}_opcode` |
| Storage call | virtual `XrdSfsFile`/`XrdOss` plugin method | confined `openat2(RESOLVE_BENEATH)` helpers (`src/path/`) |
| Blocking I/O | runs on the pool thread (the thread *is* allowed to block) | **offloaded** to `ngx_thread_pool_run` / io_uring; conn → `XRD_ST_AIO` |
| Response | `XrdXrootdResponse` from a pooled `XrdBuffer` | `ngx_chain_t` of `ngx_buf_t` (memory or sendfile), shared builders in `aio/buffers.c` |
| Cleanup | `XrdProtocol::Recycle` returns the protocol object to its pool | pool freed at request/conn end; raw scratch/SSL freed via `cleanup_add` / disconnect |

**Threading vs event-loop implications.** Because XRootD runs each request on a
pool thread, a slow disk read blocks only that one thread, and concurrency scales
by spawning more threads (up to 8192). Because nginx-xrootd runs on a shared event
loop, a slow disk read *must* be offloaded or it blocks every connection on the
worker — which is exactly why the module's hard rules are "no `goto` / no blocking
/ pool the crypto / cache the validation." The two models trade
**thread-scheduling overhead + locking** (XRootD) against **callback discipline +
no-blocking constraint** (nginx).

---

## Admin & operator view

### Official XRootD deployment

A typical site runs **multiple cooperating daemons**:

- one or more **`xrootd`** data-server processes (each a single multi-threaded
  process loading OFS/OSS + Sec + (optionally) Http plugins);
- a **`cmsd`** per node for clustering/redirection;
- optionally **`frmd`** + the FRM tool suite for tape staging.

Everything is driven by `xrootd.cfg` (often one shared file with `if/fi`
host-conditionals). Plugins are chosen by `xrd.protocol` / `xrootd.fslib` /
`ofs.osslib` / `sec.protocol` directives and dlopened at startup. Operators
manage it via the daemons' own start/stop (systemd units `xrootd@`, `cmsd@`,
`frmd@`) and signals; config changes generally mean a daemon restart.
Observability is historically **UDP XrdMon** streams plus per-daemon logs.

### nginx-xrootd deployment

The deployment is **one nginx instance with the module loaded**. A single
`nginx.conf` configures `root://` (stream block), WebDAV/S3 (http blocks),
`/metrics`, the dashboard, TLS, rate limiting, and reverse proxying — reusing the
operator's existing nginx practices. Lifecycle is the standard nginx one:

- `nginx -t -c …` validate;
- `nginx` start (master forks workers);
- `nginx -s reload` graceful reload (new workers, old workers drain);
- `nginx -s stop` / `quit`.

State lives in the **worker processes** (per-connection `xrootd_ctx_t`, open
handles) and in **SHM zones** (metrics, session/handle/manager registries,
redirect cache, TPC key registry, FRM durable queue, rate-limit/KV zones).
Clustering, tape staging, metrics, and the dashboard are features of the same
process tree, not separate daemons. Observability is **HTTP-native**: Prometheus
`/metrics`, WLCG SRR (`src/srr/`), the dashboard/admin API (`src/dashboard/`), and
nginx access/error logs — UDP XrdMon is an explicit non-goal.

---

## Parity, divergences, and trade-offs

| Aspect | Official XRootD | nginx-xrootd | Notes |
|---|---|---|---|
| Deployment unit | standalone `xrootd` daemon + plugins (+ `cmsd`, `frmd`) | one nginx instance with a stream + HTTP module | nginx folds cluster/tape/metrics into the workers; no companion daemons |
| Process model | single process, multi-threaded | nginx master + N single-threaded worker processes | XRootD = threads share memory; nginx = processes share via SHM |
| Concurrency unit | a request = an `XrdJob` on a `XrdScheduler` pool thread (min 8 / max 8192) | a request = a callback on the worker's epoll loop | XRootD scales by thread count; nginx by worker count + non-blocking discipline |
| Readiness layer | `XrdPoll`, 3 epoll/poll threads, separate from workers | nginx core epoll, one loop per worker (no separate poller threads) | distinct designs; both epoll on Linux |
| Connection object | `XrdLink : XrdJob` | `ngx_connection_t` + `xrootd_ctx_t` | ctx is the module's per-connection `this` |
| Partial-read survival | `Resume` member-fn-pointer continuation | `XRD_ST_*` suspend states + `NGX_AGAIN` | same idea, different mechanism |
| Blocking I/O | done on the (blockable) pool thread | offloaded to `ngx_thread_pool` / io_uring; conn parked in `XRD_ST_AIO` | nginx *must* offload or it stalls the worker |
| Crypto on the hot path | runs on a pool thread, fine to block | pooled/cached (DH keypool, GSI in-flight cap, token L1/L2) | a consequence of the shared event loop |
| Protocol code | `.so` plugin (`XrdXrootdProtocol`), ABI-versioned, dlopened | compiled into the module; dispatch cascade in `src/handshake/` | XRootD = pluggable ABI; nginx = static module |
| Storage abstraction | `XrdSfs`/`XrdOss` virtual plugins | confined `openat2(RESOLVE_BENEATH)` POSIX helpers (`src/path/`) | nginx is POSIX-focused; no plugin ABI for Ceph/PSS/PFC |
| Cross-process state | shared in-process memory (threads) | SHM slab tables via `shm_slots.c`, spin+yield mutexes | nginx needs SHM because workers are processes |
| Memory model | C++ `new`/`delete` + `XrdBuffManager` bucketed buffer pool | nginx arenas (`ngx_palloc`) + raw grow-only scratch + `cleanup_add` | recycle vs arena; both avoid per-request malloc on the hot path |
| Config | `xrootd.cfg`, scoped prefixes, `if/fi`, plugin-by-directive | nginx `stream{}`/`http{}` blocks, `xrootd_*` directives, `create/merge_srv_conf` | one nginx.conf spans root/WebDAV/S3/metrics |
| Build | CMake C++ build of daemon + plugins | nginx `--add-module` add-on; src list in top-level `config` | new `.c` must be registered in `config`, then `./configure` |
| Reload | typically daemon restart (graceful in-place reload not verified) | nginx `-s reload` graceful worker reload | nginx reload model is a clear operational win |
| Observability | UDP XrdMon + logs | Prometheus `/metrics`, SRR, dashboard, access logs | nginx-xrootd makes UDP XrdMon an explicit non-goal |
| Hard coding rules | C++ conventions | no `goto`, no blocking, helpers-first, functional/modular (CLAUDE.md) | enforced because everything shares the loop |

**Net trade-off.** XRootD's thread-per-job model is conceptually simpler for the
handler author (a handler may block) and scales with thread count, at the cost of
thread-scheduling overhead and lock contention. nginx-xrootd's event-loop model
removes per-request thread overhead and inherits nginx's mature
process/reload/TLS/HTTP machinery, but forces a strict no-blocking discipline:
every disk syscall is offloaded and every blocking crypto primitive is pooled or
cached. Both achieve the same wire semantics; they differ in *where the work runs*
and *what the author must never do*.

---

## Source references

### Official XRootD (`/tmp/xrootd-src/src`)

| Concern | Files / symbols |
|---|---|
| Daemon bootstrap | `Xrd/XrdMain.cc` (`main`, `mainAccept`, `mainAdmin`) |
| Config parse / plugin load | `Xrd/XrdConfig.cc/.hh` (`Configure`, `xprot`, `xsched`, `xbuf`), `XrdOuc/XrdOucStream` |
| Thread pool | `Xrd/XrdScheduler.hh/.cc` (`XrdScheduler`, `Schedule`, `minw/maxw/maxi`) |
| Connection | `Xrd/XrdLink.hh` (`XrdLink : XrdJob`) |
| Poller | `Xrd/XrdPoll.hh/.cc` (`XRD_NUMPOLLERS 3`, `XrdPollE`/`XrdPollPoll`) |
| Protocol iface | `Xrd/XrdProtocol.hh` (`Match`/`Process`/`Recycle`), `Xrd/XrdProtLoad.hh/.cc` |
| `root://` plugin | `XrdXrootd/XrdXrootdProtocol.hh` (`Resume`, `Process2`), `XrdXrootd/XrdXrootdXeq.cc` (`do_*`) |
| HTTP plugin | `XrdHttp/XrdHttpProtocol.hh/.cc` |
| Plugin ABI | `XrdVersionPlugin.hh`, `XrdSys/XrdSysPlugin.hh`, `XrdOuc/XrdOucPinLoader` |
| Buffer pool | `Xrd/XrdBuffer.hh` (`XrdBuffer`, `XrdBuffManager`, `XRD_BUCKETS 12`, `BuffPool`) |
| Storage abstraction | `XrdSfs/XrdSfsInterface.hh` (`SFS_OK/ERROR/REDIRECT`), `XrdOss/XrdOss.hh` (`XrdOssDF`) |
| Companion daemons | `XrdCms/` (cmsd), `XrdFrm/` (frmd + frm_* tools) |

### nginx-xrootd (`/home/rcurrie/HEP-x/nginx-xrootd`)

| Concern | Files / symbols |
|---|---|
| Module descriptor / hooks | `src/stream/module_definition.c` (`ngx_stream_xrootd_module`, postconfiguration, create/merge srv conf, init/exit process) |
| Connection entry | `src/connection/handler.c` (`ngx_stream_xrootd_handler`, `xrootd_ctx_t` init, metrics slot, `max_connections` gate) |
| Recv state machine | `src/connection/recv.c` (`ngx_stream_xrootd_recv`, `XRD_ST_*`, `xrootd_max_payload_for_request`, `xrootd_ensure_payload_buffer`) |
| Dispatch | `src/handshake/dispatch.c` (`xrootd_dispatch`), `dispatch_{session,read,write,signing}.c` |
| Directive table / config | `src/stream/module.c` (`ngx_stream_xrootd_commands[]`), `src/core/types/config.h` (`ngx_stream_xrootd_srv_conf_t`), `src/core/config/postconfiguration.c`, `src/core/config/config.h`, `src/core/types/tunables.h` |
| Per-connection state | `src/core/types/context.h` (`xrootd_ctx_t`, `files[]`, `out_ring`/`rd_pool`, `XRD_ST_*`) |
| Thread-pool / io_uring offload | `src/core/aio/README.md`, `src/core/aio/resume.c` (`xrootd_aio_post_task`), `src/core/aio/buffers.c`, `src/core/aio/uring.c` |
| SHM cross-worker state | `src/core/compat/shm_slots.c` (`xrootd_shm_table_alloc`, spin+yield mutex), `src/manager/registry.c`, `src/manager/redir_cache.c`, `src/tpc/key_registry.c` |
| Build governance | top-level `config` (`ngx_addon_name`, `ngx_module_srcs`, `ngx_module_libs`, CFLAGS), `src/core/config/config.h` |
| Cluster / tape / observability (in-process) | `src/manager/`, `src/cms/`, `src/frm/`, `src/metrics/`, `src/srr/`, `src/dashboard/` |
