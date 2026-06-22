# Phase 44 — Optional Linux io_uring I/O backend (server module + native client)

**Status:** PLAN ONLY (not implemented). Authored 2026-06-21.
**Scope:** add an **optional, runtime-selectable, fallback-safe** Linux `io_uring`
I/O backend to **both** halves of the project — the nginx **server module**
(`src/`, disk I/O only) and the native **client suite** (`client/`: `libxrdc`,
`xrdcp`/`xrdfs`, `xrootdfs`/`xrootdfs_aio`, where it covers local disk **and**
the socket event loop). **Everything new is OFF BY DEFAULT, gated behind
`pkg-config liburing` at build time and a kernel/seccomp probe at runtime, and
degrades transparently** to the existing thread-pool / epoll / poll paths. No
wire framing changes; no nginx-core patching; the phase-31 memory budget is
never exceeded.

This is the next I/O-substrate layer below the perf phases (29 pipelining, 30
hyper-opt, 31 memory budget, 32 data-plane parity, 33 perf-P2). It changes *how
the bytes move*, not *what is on the wire*.

---

## 0. The facts that scope this phase

Two hard constraints, discovered by auditing the actual I/O dispatch sites, fix
the shape of the entire design:

1. **The server module never touches a raw socket.** Every byte in/out on the
   `root://` stream, WebDAV, and S3 surfaces goes through nginx core —
   `c->recv()`, `c->send_chain()`, `sendfile()`, and kTLS. Build governance
   (CLAUDE.md → *BUILD GOVERNANCE*) forbids patching nginx's own source
   (`src/core/`, `src/event/`, `src/http/`). **Therefore server-side io_uring is
   strictly a *disk-I/O* backend** (`pread`/`pwrite`/`preadv`/`pwritev`/`fsync`).
   It replaces the thread-pool workers behind `xrootd_aio_post_task()`
   (`src/aio/resume.c`), reusing the existing task structs and completion
   callbacks unchanged. TLS `b->memory=1` and cleartext `sendfile` invariants
   are untouched.

2. **The client owns its full event loop.** `client/lib/aio.c` is a hand-written
   epoll loop (one `epfd` + one `eventfd` + one loop pthread) doing raw
   `send`/`recv`/`read`/`write` on non-blocking sockets, plus `client/lib/copy.c`
   does plain `read`/`write` on local files for xrdcp. **Therefore client-side
   io_uring can go much deeper** than the server: local disk first (lowest risk,
   highest value), then — optionally, behind a hard opt-in — the socket
   readiness/completion engine itself.

The corollary that makes this phase low-risk to land incrementally: on **both**
sides there is exactly **one** dispatch seam to interpose on (`xrootd_aio_post_task`
on the server; the `pump_src_fn`/`pump_sink_fn` adapter pair + the epoll engine on
the client), and every interposition has a working fallback already present in the
code today.

---

## 1. TL;DR

- **Server:** add a third backend tier to the existing AIO dispatcher so the
  cascade becomes **io_uring → thread pool → inline sync**. One per-worker
  `io_uring` instance; completions are delivered to nginx's epoll via an
  `eventfd` (`io_uring_register_eventfd`) wrapped in an `ngx_connection_t` using
  *public* nginx APIs. **This is a near-transcription of nginx core's own
  native-AIO integration** (`ngx_epoll_aio_init` / `ngx_epoll_eventfd_handler`,
  which wire a libaio `io_getevents` eventfd into epoll) with the completion
  engine swapped from libaio to io_uring — see the duplication analysis in
  **§7**. The six `*_aio_t` task structs and `*_aio_done` callbacks are reused
  verbatim; a reaper fills each task's OUT fields from `cqe->res` and re-uses
  nginx's `ngx_post_event(&task->event, &ngx_posted_events)` queue to run the
  existing done-callbacks. First cut maps READ/WRITE/READV/WRITEV(+FSYNC);
  pgread (CRC), dirlist, and multi-fd/multi-group vectored ops stay on the thread
  pool.
- **Client:** ship in risk order — (1) a deep-queue local-disk ring for the
  xrdcp pump in `copy.c` (registered buffers, disk⇄network overlap), behind the
  unchanged adapter interface; (2) expose that ring to the FUSE-local path; (3)
  optionally swap the epoll engine in `aio.c` for an io_uring engine
  (`IORING_OP_POLL_ADD` multishot drop-in first, TLS-safe; cleartext
  `IORING_OP_RECV/SEND` multishot later), default **off**.
- **Gating everywhere:** `pkg-config liburing` → `-DXROOTD_HAVE_LIBURING` →
  `-luring`; a runtime `io_uring_queue_init` + opcode probe (never a `uname`
  parse); automatic, silent fallback when absent or blocked. **But `on` is a
  hard requirement, not a hint:** if io_uring is explicitly enabled
  (`xrootd_io_uring on`) and cannot be provided — built without liburing, or
  runtime-blocked by an old kernel/seccomp — **xrootd refuses to start**
  (`nginx -t` errors, the master exits non-zero, an `NGX_LOG_EMERG` names the
  cause + remedy). The compiled-without case is caught at config time with **no
  kernel needed**, so `nginx -t` flags it anywhere (incl. CI). `auto`/`off`
  always start. Full contract in **§32** (ADR-16, REQ-IOURING-FAILFAST).
- **Security posture (§8):** the kernel-async path is disableable at *four*
  levels including a **no-restart hot kill switch** (a cross-worker SHM atomic
  flipped via the existing admin API or a watched panic-file) so a future
  io_uring/libaio CVE can be neutered fleet-wide in seconds without a rebuild or
  reload. And the async I/O runs **under the delegated (impersonated) user, never
  root**: io_uring lives in the unprivileged worker and only ever operates on fds
  the privileged broker already opened `RESOLVE_BENEATH` as the mapped user — and
  the ring is locked (`io_uring_register_restrictions`) to fd-only data opcodes,
  so it can **never open or traverse a path/namespace**.

---

## 2. Current I/O dispatch map (what we interpose on)

### 2.1 Server (`src/`)

The single async dispatch point is **`xrootd_aio_post_task(ctx, c, pool, task,
fallback_log, posted)`** (`src/aio/resume.c`). Today it calls
`ngx_thread_task_post()` and, on a full queue, returns `*posted = 0` so every
caller falls back to an **inline synchronous** `pread`/`pwrite`. The six task
context structs live in `src/aio/aio.h`:

| Task struct | Worker fn (syscall) | Done callback | Op |
|---|---|---|---|
| `xrootd_read_aio_t` | `xrootd_read_aio_thread` (`pread`) | `xrootd_read_aio_done` | kXR_read |
| `xrootd_write_aio_t` | `xrootd_write_aio_thread` (`pwrite`) | `xrootd_write_aio_done` | kXR_write/pgwrite |
| `xrootd_readv_aio_t` | `xrootd_readv_aio_thread` (coalesced `preadv`) | `xrootd_readv_aio_done` | kXR_readv |
| `xrootd_writev_aio_t` | `xrootd_writev_write_aio_thread` (`pwrite`×N + `fsync`) | `xrootd_writev_write_aio_done` | kXR_writev |
| `xrootd_pgread_aio_t` | `xrootd_pgread_aio_thread` (`pread` + per-page CRC32c) | `xrootd_pgread_aio_done` | kXR_pgread |
| `xrootd_dirlist_aio_t` | `xrootd_dirlist_aio_thread` (`opendir`/`readdir`) | `xrootd_dirlist_aio_done` | kXR_dirlist |

Worker fns run on a pool thread and touch **no** connection state; done callbacks
run on the event thread, guard `ctx->destroyed` via
`xrootd_aio_restore_stream/request()`, build the `ngx_chain_t`, queue the
response, and call `xrootd_aio_resume()`. Phase-31 windowed reads
(`xrootd_read_window_pump`, `src/aio/reads.c`) and the phase-32 warm-cache
`preadv2(…, RWF_NOWAIT)` probe (`src/read/read.c`) sit *above* this seam and are
backend-agnostic.

### 2.2 Client (`client/`)

- **Event loop** — `client/lib/aio.c`: `epoll_wait` over per-`xrdc_aconn`
  sockets; `aconn_do_write` (`SSL_write` for TLS, else `send(...,MSG_NOSIGNAL)`)
  and `aconn_do_read` (`SSL_read` else `read`); cross-thread wakeup via
  `eventfd`; reconnect worker + RTT EWMA + keepalive ping. `aio_mgr.c` layers
  `xrdc_mgr` (connection pool) and `xrdc_mfile` (resilient reopen-on-drop handle)
  on top.
- **Local disk** — `client/lib/copy.c`: the generic `transfer_pump` calls
  `pump_src_fn`/`pump_sink_fn` adapters. Local adapters are plain `read()`
  (`pump_src_local`) and a `write()` loop (`write_all`). Remote adapters call
  `xrdc_file_read/write/pgread/pgwrite` (`ops_file.c`). No `pread`/`sendfile`/
  `splice` anywhere today.
- **Sync path** — `client/lib/sock.c`: `poll()` + `read`/`write` loops, one
  request in flight (this is *why* `aio.c` exists).
- **FUSE** — `xrootdfs_aio.c` rides `xrdc_mgr`/`xrdc_mfile` (so it inherits the
  `aio.c` engine); legacy `xrootdfs.c` uses per-handle sync `sock.c` connections.

---

## PART A — Server module: optional io_uring disk-I/O backend

### A.1 Event-loop integration without patching nginx core

Add one per-worker singleton (file-static in a new `src/aio/uring.c`, reached via
an accessor `xrootd_uring_worker()`; **no new exported global**):

```c
typedef struct {
    struct io_uring   ring;        /* liburing ring                     */
    int               eventfd;     /* registered to ring via            */
                                   /* io_uring_register_eventfd()        */
    ngx_connection_t *evc;         /* fake connection wrapping eventfd   */
    uint32_t          queue_depth;
    uint32_t          inflight;    /* SQEs submitted, CQEs pending       */
    unsigned          enabled:1;
    unsigned          sqpoll:1;    /* later tier                         */
    ngx_log_t        *log;
} xrootd_uring_t;
```

- **Created** in `ngx_stream_xrootd_init_process()` (`src/config/process.c`,
  after `xrootd_imp_init_worker`) — *per worker, after fork*, the same lifetime
  as every other per-worker async resource (`xrootd_proxy_pool_init`,
  `xrootd_gsi_keypool_init`). Sequence: `io_uring_queue_init(depth)` →
  `eventfd(EFD_NONBLOCK|EFD_CLOEXEC)` → `io_uring_register_eventfd()` → wrap the
  eventfd in `ngx_get_connection()`, set `evc->read->handler =
  xrootd_uring_eventfd_handler`, `evc->data = u`, `ngx_add_event(evc->read,
  NGX_READ_EVENT, 0)`. **This sequence is the public-API analogue of nginx
  core's `ngx_epoll_aio_init()`** (`src/event/modules/ngx_epoll_module.c:248`),
  which does `eventfd()` → `io_setup()` → `epoll_ctl(EPOLL_CTL_ADD, ngx_eventfd)`
  and stores the wrapper in the file-static `ngx_eventfd_conn`/`ngx_eventfd_event`.
  We cannot call core's version (it is `static`, addon-invisible, and hard-wired
  to libaio — see §7.2), so we re-derive the same shape using
  `ngx_get_connection`/`ngx_add_event` instead of touching core's private `ep`
  fd. Any failure → log once, `enabled = 0`, return `NGX_OK` (the thread pool
  still works).
- **Torn down** in `xrootd_exit_process()`: `ngx_del_event` + `ngx_close_connection(evc)`,
  `io_uring_unregister_eventfd`, `io_uring_queue_exit`, `close(eventfd)`.
- **Per-server-block directive, per-worker ring:** the ring is process-global but
  the directive is per server block; `init_process` iterates `cmcf->servers` and
  creates the ring if *any* enabled block wants it and the probe passes.

### A.2 The reaper

`xrootd_uring_eventfd_handler(ngx_event_t *ev)`:

1. Drain the eventfd counter (`read(eventfd, &cnt, 8)`) — identical to core's
   `ngx_epoll_eventfd_handler()` first step.
2. **Harvest and post (mirroring core).** Loop `io_uring_peek_cqe` /
   `io_uring_for_each_cqe`; for each CQE: decode the **completion slot** from
   `user_data`, validate its **generation** (§A.3), translate `cqe->res` into the
   task's OUT fields (§A.4), mark the task's embedded `ngx_event_t` complete, and
   `ngx_post_event(&task->event, &ngx_posted_events)` — then `io_uring_cqe_seen()`.
   This is *exactly* what core's libaio handler does
   (`ngx_epoll_eventfd_handler`, `ngx_epoll_module.c:942` — `read(eventfd)` → loop
   `io_getevents` → set `e->complete`, store `aio->res`, `ngx_post_event(e,
   &ngx_posted_events)`), with `io_uring_peek_cqe` substituted for `io_getevents`.
3. The reaper **does not invoke `*_aio_done` inline** — nginx's own
   posted-events drain (which already runs after `process_events`) calls each
   done-callback. Reusing the core queue this way is both less code and
   re-entrancy-safe: a done-callback that re-submits the next window (the phase-31
   pump) never touches the ring buffer from inside the harvest loop. (This
   supersedes an earlier "copy triples to a stack array then dispatch" sketch —
   the core pattern is strictly better.)

### A.3 `user_data` → task mapping (UAF-safe slot table)

Never put a raw task pointer in `user_data` (a late CQE for a dead connection
would dereference freed memory). Instead a per-ring slot table:

```c
typedef struct {
    void                 *task;       /* ngx_thread_task_t (carries *_aio_t) */
    ngx_event_handler_pt  done_fn;    /* xrootd_*_aio_done                   */
    uint32_t              generation; /* bumped on free → detects stale CQE  */
    uint8_t               op_kind;    /* for OUT translation                 */
    uint8_t               in_use;
} xrootd_uring_slot_t;
```

`user_data = (generation << 32) | slot_index`. On completion, a generation
mismatch drops the stale CQE. This guards the *ring slot*; the done-callback's
own `xrootd_aio_restore_stream/request()` + `ctx->destroyed` check remains the
authoritative guard for the *connection*. Both layers are kept — this is the
existing thread-pool UAF discipline, extended to the ring.

### A.4 Reusing the done-callbacks unchanged (Option A)

The io_uring path keeps using `ngx_thread_task_t`. On completion the reaper
writes `cqe->res` into the same OUT fields the worker fn would have set, then
calls `slot->done_fn(&task->event)`:

- READ/PGREAD: `if (res < 0) { io_errno = -res; nread = -1; } else nread = res;`
  (io_uring returns `-errno` in `res`, not via `errno`).
- WRITE: same shape into `nwritten`/`io_errno`. Short writes (`res < len`) hit
  the existing `kXR_IOError("short write")` branch.
- READV/WRITEV: set `bytes_read_total`/`response_bytes`/`io_error` or
  `bytes_total`/`io_error`.

**Done callbacks, callers, and response framing are byte-for-byte unchanged.**
Only *submission* and the *syscall location* differ. The detached write payload
(`payload_to_free`/`payload_buf`, freed in the done callback) stays alive across
the in-flight `IORING_OP_WRITE` because the done callback — which frees it — only
runs *after* the CQE. No change.

### A.5 Backend selector

`xrootd_aio_post_task()` stays the single dispatch point and keeps its signature;
its body gains a selector (no `goto`, early-return):

```
*posted = 0;
u = xrootd_uring_worker();
op = xrootd_uring_op_for(task);          /* lookup keyed on task->handler  */
if (u && u->enabled && op != XRD_URING_OP_NONE && u->inflight < u->queue_depth) {
    if (xrootd_uring_submit(ctx, c, task, op, posted) == NGX_OK && *posted) {
        ctx->state = XRD_ST_AIO;
        return NGX_OK;
    }
    /* prep/submit failed → fall through to the pool */
}
if (pool == NULL) return NGX_OK;          /* *posted stays 0 → inline sync  */
if (ngx_thread_task_post(pool, task) != NGX_OK) {
    ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", fallback_log);
    return NGX_OK;                         /* → inline sync                  */
}
ctx->state = XRD_ST_AIO; *posted = 1; return NGX_OK;
```

`xrootd_uring_op_for(task)` is a static `(worker_fn_ptr → op_kind)` table, so
**call sites and task structs need zero changes** — the worker fn that the task
was already bound to via `xrootd_task_bind()` *is* the op identity.

### A.6 Per-op mapping (first cut)

| Task | io_uring op | First cut? | Notes |
|---|---|---|---|
| read | `IORING_OP_READ` | ✅ | Windowed-read pump submits one SQE per 2 MiB window — unchanged pump. |
| write | `IORING_OP_WRITE` | ✅ | Detached payload is the SQE source buffer (alive until CQE). |
| readv | `IORING_OP_READV` | ✅ single coalesced group | Multi-fd/multi-group → thread pool. |
| writev | `IORING_OP_WRITEV` (+ linked `IORING_OP_FSYNC` when `do_sync`) | ✅ single fd | `IOSQE_IO_LINK` enforces write-then-sync ordering in-kernel. Multi-fd → pool. |
| pgread | `IORING_OP_READ` for data only | ❌ stays on pool (first cut) | The per-page CRC32c interleave would move onto the event thread; defer to a hybrid (uring read → pool CRC) tier. |
| dirlist | — | ❌ stays on pool | `opendir`/`readdir`/per-entry checksum is not a single io_uring op (`IORING_OP_GETDENTS` is very new + helper-less). |

Anything not mapped simply falls through the selector to the unchanged
thread-pool path. **First-cut coverage = the hot data-plane ops** (read, write,
single-group readv, single-fd writev+fsync), which are the bulk of streaming I/O.

### A.7 Memory budget & windowing interplay (no change)

- The windowed-read pump and `xrootd_budget_admit/sync` go through
  `xrootd_aio_post_task`, so they ride whichever backend is selected with **no
  edits**. The pump posts one window at a time, so ring depth from windowed reads
  is 1 per connection — never exhausts the ring.
- io_uring reads into the **same** scratch buffers, so heap-footprint budget
  accounting is identical. Admission still happens *before* dispatch, so a
  budget-deferred read still sends `kXR_wait`.
- The phase-32 warm-cache `preadv2(RWF_NOWAIT)` probe is **retained**: it returns
  hot data synchronously with zero added latency (an io_uring read still costs one
  epoll cycle), and only the *miss* path falls to the now-uring-preferring
  dispatcher. (Reproducing the probe as an `RWF_NOWAIT`/`IOSQE_ASYNC` SQE was
  considered and rejected — no faster, more complex.)

---

## PART B — Native client: staged, lowest-risk-first

Recommended ship order (value ↑, risk ↓ first):

| # | Site | Value | Risk | Workstream |
|---|---|---|---|---|
| 1 | Local disk read/write in `copy.c` (xrdcp pump) | High | Low | CB-W2 |
| 2 | Disk ring exposed to loop / FUSE-local | Med-High | Low-Med | CB-W3 |
| 3 | Event-loop engine swap in `aio.c` (default **off**) | High | High | CB-W4 |
| 4 | Sync `sock.c` poll path | Low | Low-Med | **declined / out of scope** |
| 5 | FUSE backing I/O | — | — | inherited free via #1/#3 |

### B.1 New module `client/lib/uring.{c,h}`

A thin liburing wrapper, the only new TU shared by all client io_uring users
(stays free of `xrdc.h` socket types to avoid include cycles):

```c
int              xrdc_uring_available(void);   /* memoized runtime probe; 0 if
                                                  built without liburing       */
typedef struct xrdc_disk_ring xrdc_disk_ring;
xrdc_disk_ring  *xrdc_disk_ring_create(int fd, unsigned depth, unsigned nbuf,
                                       size_t bufsz, int direct, xrdc_status *st);
void             xrdc_disk_ring_destroy(xrdc_disk_ring *r);
```

When `XROOTD_HAVE_LIBURING` is undefined the whole TU compiles to inert stubs
(`xrdc_uring_available()` → 0, `…_create` → NULL+status), so the epoll/poll path
is the only thing in the binary and there is no `-luring` dependency.

### B.2 CB-W2 — local-disk ring for `copy.c` (the lead workstream)

The pump (`transfer_pump`) is strictly serial today: a download blocks the
network read while the disk write completes; an upload blocks the network write
while the disk read completes. A deep queue of registered buffers lets disk and
network overlap — the single biggest streaming win, fully isolated behind one
adapter.

- **`transfer_pump` and all remote adapters are NOT touched.** Add two adapters
  alongside the local ones: `pump_src_local_uring` and `pump_sink_local_uring`,
  driven by a `pump_localring_t { xrdc_disk_ring *r; int fd; int64_t pos; }`.
- **Option A (ship this): adapter-internal pipelining.** The ring owns its own
  registered-buffer pool and runs a read-ahead window (source) / write-behind
  window (sink) of `depth` SQEs, while still presenting the *synchronous,
  in-order, one-chunk* face the pump expects. This keeps the pump's tested
  control structure — completion-before-cancel ordering, short-read error,
  progress callback — byte-for-byte intact. One memcpy (caller buf → registered
  buf) survives; that is the price of not touching the pump contract, and the
  disk/network overlap is the real gain.
- **Option B (deferred): bypass the pump** with dedicated `copy_download_uring` /
  `upload_stream_body_uring` paths that fuse the ring with the remote read/write
  and eliminate the memcpy — higher value, but duplicates the pump's cancel /
  progress / short-read discipline. Defer until Option A is proven.
- **Ordered completion** is enforced by indexing outstanding ops by sequence and
  releasing chunk *k* to the pump only after op *k* completes (even if *k+1*
  finished first) — so bytes always land in order for the sink.
- **O_DIRECT** is an optional per-invocation tier behind the `direct` flag
  (`posix_memalign` buffers, block-aligned offsets/lengths; the unaligned tail
  falls back to a buffered write). Default off — it helps large sequential NVMe
  transfers and hurts small/cached ones, so never automatic.
- The choice flows through a new `xrdc_copy_opts.io_uring` tri-state
  (0=auto/1=on/2=off) and the adapter ctx — **no new globals**.

### B.3 CB-W3 — expose the disk ring to the loop / FUSE-local path

`xrootdfs_aio` rides `xrdc_mgr`/`xrdc_mfile`, so once the ring is reachable from
the loop-thread's local-disk path, FUSE write-back/read-ahead overlap comes for
free with **no driver changes**. Socket readiness stays on epoll here — low risk,
and it validates build/detect/fallback against the resilient core before CB-W4
touches readiness.

### B.4 CB-W4 — event-loop engine swap in `aio.c` (default OFF)

Introduce a small internal engine vtable so epoll and io_uring coexist in one
binary, selected at `xrdc_loop_create` time:

- `engine_arm(ac, want)` — today's `aconn_update_epoll`, or an io_uring impl
  submitting multishot `IORING_OP_POLL_ADD` / `IORING_OP_RECV`.
- `engine_wait(l, timeout)` — `epoll_wait`, or `io_uring_wait_cqe_timeout` + CQE
  dispatch.
- `engine_wake(l)` — keep the existing `eventfd` registered in the ring so the
  cross-thread command-queue wakeup is unchanged on the writer side.

**Ship `IORING_OP_POLL_ADD` multishot first** — a drop-in epoll replacement: the
loop still gets readiness edges and still runs `aconn_do_read`/`aconn_do_write`
verbatim (so `SSL_read`/`SSL_write` keep doing their own syscalls — **TLS-safe**,
smallest diff, full resilience path preserved). Cleartext-only
`IORING_OP_RECV/SEND` multishot + provided buffers (true async, zero
readiness-syscall) is a follow-on that swaps only the `ac->ssl == NULL` branch.

**TLS is the load-bearing constraint:** OpenSSL drives the fd itself, so io_uring
cannot intercept its syscalls without memory BIOs (a separate large effort).
Hence TLS conns keep readiness-style polling under `POLL_ADD`; only cleartext
conns can go true-async. The per-`aconn` branch already exists.

**Resilience interplay:** on transport error, `epoll_ctl(DEL)` becomes
`IORING_OP_ASYNC_CANCEL` for that fd's outstanding multishot ops; the reconnect
worker re-arms the new fd. A new `uint32_t fd_gen` on `xrdc_aconn`, stamped into
`user_data`, drops late CQEs for a recycled aconn. Parked retry-safe requests and
`xrdc_mfile` reopen sit above the engine and are unaffected.

### B.5 FUSE & sync path

- `xrootdfs_aio` — inherits the engine; **test-only**, no code change. Legacy
  `xrootdfs` (per-handle sync `sock.c`) is left untouched and documented as the
  non-resilient path.
- `sock.c` sync poll path — low value (the bottleneck is the one-in-flight model,
  not readiness); **declined**, documented as out of scope.

---

## 3. Build & gating

### 3.1 Server (`config`)

Optional pkg-config block (gated on `XROOTD_ENABLE_IO_URING`; *optional*, unlike
the hard-required libxml2):

```sh
if [ -n "$XROOTD_ENABLE_IO_URING" ] && pkg-config --exists liburing; then
    CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DXROOTD_HAVE_LIBURING=1"
    XROOTD_URING_LIBS="$(pkg-config --libs liburing)"   # -luring
    echo " + xrootd: io_uring disk-I/O backend enabled"
fi
```

**Critical (build governance):** `-luring` goes into the **stream module's
`ngx_module_libs`**, NOT `CORE_LIBS` — otherwise the dynamic `.so` fails `dlopen`
with `undefined symbol: io_uring_*`. New `src/aio/uring.c` + `uring_submit.c` go
in `ngx_module_srcs`, `uring.h` in the stream deps; **a `./configure` re-run is
required**. `--with-threads` stays hard-required (the thread pool is always the
fallback tier).

Runtime directive `xrootd_io_uring on|off|auto` (`ngx_conf_set_enum_slot`, merged
like `xrootd_memory_budget`; default `auto` = enable iff the probe passes),
optional `xrootd_io_uring_queue_depth N`. Tunables in `src/types/tunables.h`:

```c
#define XROOTD_IO_URING_QUEUE_DEPTH       256
#define XROOTD_IO_URING_MIN_KERNEL_MAJOR  5
#define XROOTD_IO_URING_MIN_KERNEL_MINOR  6   /* reliable register_eventfd */
#define XROOTD_IO_URING_RESTRICT_KERNEL_MINOR 10 /* register_restrictions; best-effort */
```

**Runtime-disable / hardening directives (detailed in §8):**

- `xrootd_io_uring_panic_file <path>` — when this file exists, every worker
  treats io_uring as disabled and falls back (the operator-/config-management
  kill switch; survives reload; default unset).
- `xrootd_io_uring_admin on|off` — expose `POST /xrootd/api/v1/admin/io_uring`
  (bearer+CIDR auth, audited) to flip the cross-worker SHM disable flag without a
  reload. Default `off`.
- `xrootd_io_uring_restrict on|off` — lock each ring to fd-only data opcodes via
  `io_uring_register_restrictions()` (default `on` where the kernel supports it;
  see §8.2). No effect below kernel 5.10 — containment still holds via the
  unprivileged-worker + confined-fd model.

### 3.2 Client (`client/Makefile`)

Mirror the `HAVE_KRB5` pattern:

```make
HAVE_LIBURING := $(shell pkg-config --exists liburing 2>/dev/null && echo yes)
ifeq ($(HAVE_LIBURING),yes)
  URING_CFLAGS := -DXROOTD_HAVE_LIBURING $(shell pkg-config --cflags liburing)
  URING_LIBS   := $(shell pkg-config --libs liburing)
endif
```

`lib/uring.c` is *always* in `LIB_SRCS` (stubs when undefined — matches the
always-compiled krb5 stub model). CLI `--io-uring=auto|on|off` (parsed in
`xrdcp.c` / `xrootdfs_aio.c` → `xrdc_copy_opts.io_uring`) + `XRDC_IO_URING` env as
the library default (read once under `pthread_once`, no mutable global).

### 3.3 Runtime probe (both sides)

`xrootd_uring_runtime_available()` / `xrdc_uring_available()` do an **authoritative
probe**, not a `uname` parse (containers/seccomp routinely block
`io_uring_setup`): attempt a throwaway `io_uring_queue_init(8)` + `io_uring_get_probe`
for the required opcodes (READ/WRITE on the server; +POLL_ADD/RECV/SEND/ASYNC_CANCEL
for the client loop), tear it down, memoize the verdict. Any failure → one NOTICE
log + permanent fallback for that process.

---

## 4. Fallback & safety

| Condition | Behavior |
|---|---|
| liburing absent at **build** | `XROOTD_HAVE_LIBURING` undefined → backend compiles to stubs; only thread-pool / epoll / poll paths exist; no `-luring` in the binary. `xrootd_io_uring on` then **fails startup** (config-time, no probe; §32); `auto`/`off` start normally. |
| present at build, blocked at **runtime** (old kernel / seccomp) | probe → false → silent fallback for `auto`/`off` (one NOTICE). **`on` fails startup** — `nginx -t` errors, master exits non-zero (§32). |
| **hot kill switch** (CVE response, no restart) | SHM atomic `io_uring_disabled` set via admin API or panic-file → `xrootd_aio_post_task` stops selecting the uring tier on the *next* op, fleet-wide; in-flight CQEs still drain. Re-enable the same way once patched. (§8.1) |
| **privileged-namespace exposure** | impossible by construction: io_uring runs in the *unprivileged* worker on a broker-opened `RESOLVE_BENEATH` fd, and the ring is restricted to fd-only data opcodes (no OPENAT/STATX/UNLINKAT/…) so it can neither open nor traverse a path. The root broker never uses io_uring. (§8.2) |
| ring/SQE submit failure (ring full, `get_sqe` NULL) | `*posted = 0` → next tier (pool, then inline). The op never drops. |
| per-op CQE error (`res < 0`) | translated to `-errno`; the existing `kXR_IOError` / `xrdc_status_set` path fires — identical frame to today. |
| buffer ownership submit→complete | server: detached payload freed only in the post-CQE done callback. client: registered buffers owned by the ring pool, checked out on submit / returned on CQE; the ring drains all in-flight ops before destroy. |
| connection drop mid-op | server: generation guard + `ctx->destroyed` drop the result safely. client: `ASYNC_CANCEL` + `fd_gen` stamp + unchanged reconnect/mfile-reopen. |

**No `goto`** anywhere: multi-step setup (`xrdc_disk_ring_create`, ring init) uses
`*_create_fail()` unwind helpers, mirroring the existing `xrdc_loop_create_fail` /
`atomic_dest_finish` templates. Every new function carries a WHAT/WHY/HOW block.
Wire invariants (pgread `kXR_status(4007)` + per-page CRC32c, TLS `b->memory=1`,
`resolve_path()` before `open()`) are untouched — the backend moves bytes, not
framing.

---

## 5. Workstreams, sequencing & risk

### Server

| WS | Title | Depends | Risk | Deliverable |
|---|---|---|---|---|
| SB-W1 | Build/gate + directive + tunables | — | Low | compiles; selector a no-op (worker accessor → NULL). |
| SB-W2 | Ring lifecycle + eventfd bridge + reaper + slot table | SB-W1 | **High (keystone)** | land behind an `IORING_OP_NOP` self-test before any real op. |
| SB-W3 | READ/WRITE submit + CQE→OUT translation | SB-W2 | Med | covers single + windowed reads, no pump change. |
| SB-W4 | READV + WRITEV(+linked FSYNC), single-fd/group | SB-W3 | Med | multi-fd/group fall back to pool. |
| SB-W5 | Fallback + budget/window validation | SB-W3 | Low-Med | force ring-full/submit-fail; verify three-tier cascade. |
| SB-W6 | Docs + deferred-tier stubs | SB-W4 | Low | README; SQPOLL/registered-files/uring-pgread/getdents flagged. |

Order: SB-W1 → SB-W2 → (SB-W3 → SB-W4 ∥ SB-W5) → SB-W6.

### Client

| WS | Title | Depends | Risk | Deliverable |
|---|---|---|---|---|
| CB-W1 | Build/detect/probe + `--io-uring`/env + `xrdc_copy_opts.io_uring` | — | Low | compiles with and without liburing. |
| CB-W2 | `xrdc_disk_ring` + `copy.c` uring adapters (Option A) + O_DIRECT tier | CB-W1 | Low | pump + remote adapters untouched. |
| CB-W3 | Disk ring exposed to loop/FUSE-local | CB-W2 | Low-Med | FUSE inherits; readiness still epoll. |
| CB-W4 | `aio.c` engine vtable; `POLL_ADD` multishot, then cleartext RECV/SEND; `fd_gen`; `ASYNC_CANCEL` | CB-W1, CB-W3 | High | **default off**; starts only after CB-W2 is green. |
| CB-W6 | FUSE verification | CB-W2, CB-W4 | Low | test-only; legacy `xrootdfs` untouched. |

Hard rule: **CB-W4 cannot start until CB-W2 ships and its byte-exactness +
fallback tests are green** — the disk path proves the whole build/detect/buffer/
fallback discipline before the resilient transport is touched.

---

## 6. Testing strategy (≥3 per feature: success / error / security-neg)

**The central acceptance gate is a backend-parity matrix.** Behavior must be
backend-transparent.

- **Server parity matrix:** run the full read/write/readv/pgread/dirlist suites
  (`tests/test_aio.py`, `test_readv.py`, `test_readv_security.py`, `test_write.py`,
  `test_pgread_wire_conformance.py`, `test_pgwrite_checksum.py`) three times —
  `xrootd_io_uring off` / `on` / `auto` — asserting **byte-for-byte identical**
  client-visible responses.
- **Per op:** success (exact byte counts under uring); error (`kXR_IOError` from a
  truncated-file read / full-or-RO-fs write — the CQE `-errno` path must produce
  the *same* frame as the pool path); security-neg (negative offset, `offset+len`
  overflow, out-of-range handle rejected **before** any SQE is built; assert no
  SQE submitted).
- **pgread framing holds with uring enabled** — and since pgread stays on the
  pool in the first cut, assert (via log/metric) it took the pool path while other
  ops took uring.
- **Server fallback:** run where `io_uring_setup` is seccomp-blocked or kernel <
  min — assert the NOTICE, clean `auto` degrade, full suite green on the pool.
  Force ring-full with a low `XROOTD_IO_URING_QUEUE_DEPTH` and assert no dropped
  ops.
- **Server UAF/teardown:** client disconnects mid-large-read under the existing
  ASan/LSan build; assert the generation guard drops the stale CQE; no crash/leak.
- **Client byte-exact xrdcp (SHA256):** every direction (download/upload/recursive/
  r2r/stdio) over a corpus (empty, 1 B, sub-chunk, exactly `XRDC_COPY_CHUNK`,
  multi-chunk, ~GiB) with `--io-uring=off` vs `on` vs `on`+O_DIRECT → identical
  hashes. Anchor into `test_native_xrdcp_xrdfs.py` / `test_client_xrdcp_bulk.py`.
- **Client fallback:** build with `HAVE_LIBURING= make`; assert `--io-uring=on`
  errors cleanly and `auto`/`off` transfer correctly; plus a runtime-blocked case.
- **Client resilience (gates CB-W4):** the fault-injection proxy
  (`tests/c/fault_proxy.c`) + `test_client_robustness.py`,
  `test_xrootdfs_resilience.py`, `test_write_recovery.py`, `aio_resil`,
  `aio_mfile` must **all pass with the io_uring engine active** — proving
  `ASYNC_CANCEL`-on-drop + `fd_gen` + reconnect + mfile-reopen still recover
  byte-perfectly. Run the uring paths under valgrind/LSan (`tests/lsan.supp`) for
  registered-buffer lifecycle.

---

## 7. Relationship to nginx core's async-I/O machinery (duplication analysis)

The single most important thing to grasp before implementing **Part A**: nginx
core already contains the exact eventfd→epoll completion bridge this plan needs —
it was built for **Linux native AIO (libaio), not io_uring**, and it is
unreachable from an `--add-module` addon. So the server-side backend is, by
construction, a *re-derivation of an existing core mechanism with a newer
completion engine*. This section states precisely what is duplicated, what is
reused unchanged, what cannot be reused (and why), and how the design keeps the
re-derivation minimal. (The client has **no** nginx dependency — §7.6.)

Verified baseline: `grep -ri 'io_uring\|liburing\|IORING' nginx/src` over the
pinned tree (`/tmp/nginx-1.28.3`) returns **zero hits** — nginx 1.28.x core has
no io_uring of any kind. The closest existing feature is libaio behind `aio on;`.

### 7.1 The completion bridge *is* nginx's libaio integration, re-pointed at io_uring

| Our piece (Part A) | nginx-core precedent | What differs |
|---|---|---|
| `xrootd_uring_init_worker()` — create ring + eventfd, register with epoll | `ngx_epoll_aio_init()` (`src/event/modules/ngx_epoll_module.c:248`) — `eventfd()`, `io_setup()`, `epoll_ctl(ADD, ngx_eventfd)` | `io_uring_queue_init` + `io_uring_register_eventfd` replace `io_setup`; `ngx_get_connection`+`ngx_add_event` replace the raw `epoll_ctl` (an addon may not touch core's private `ep` fd) |
| `xrootd_uring_t` (ring + eventfd + `ngx_connection_t`, per-worker, via accessor) | file-static globals `ngx_eventfd`, `ngx_aio_ctx`, `ngx_eventfd_event`, `ngx_eventfd_conn` (`ngx_epoll_module.c:145`) | ours is per-worker, no new exported global (coding-std); core's are `static` |
| `xrootd_uring_eventfd_handler()` — read eventfd, harvest CQEs, post completions | `ngx_epoll_eventfd_handler()` (`ngx_epoll_module.c:942`) — `read(eventfd)`, loop `io_getevents()`, `ngx_post_event(e, &ngx_posted_events)` | `io_uring_peek_cqe`/`for_each_cqe` replaces `io_getevents`; **same `ngx_post_event` completion pattern** (see §A.2) |
| per-op task = nested `ngx_event_t` + result field | `ngx_event_aio_t` (`src/event/ngx_event.h:143`) — `aiocb` (iocb) + nested `ngx_event_t` + `int64_t res` | we reuse the existing `ngx_thread_task_t` (also embeds an `ngx_event_t`), so `*_aio_done` is untouched |
| `xrootd_uring_submit()` builds an SQE | `ngx_file_aio_read()` (`src/os/unix/ngx_linux_aio_read.c:49`) fills an iocb + `io_submit()` | `io_uring_prep_*` + `io_uring_submit` replace the `IOCB_CMD_PREAD` iocb fill + `io_submit` |

The duplicated surface is therefore **one init function + one reaper function**
(≈80 lines combined), each a near-transcription of a core function we cite by
`file:line`. Everything else is reused, not duplicated (§7.4).

### 7.2 Why the duplication is *forced*, not gratuitous

Three hard reasons the module must re-derive rather than call core's machinery:

1. **It's compiled into core, behind file-static state.** `ngx_eventfd`,
   `ngx_aio_ctx`, `ngx_eventfd_event`, `ngx_eventfd_conn`, `ngx_epoll_aio_init`,
   and `ngx_epoll_eventfd_handler` are all `static`/internal to
   `ngx_epoll_module.c` — there is **no exported symbol** an `--add-module` addon
   can hook, and build governance forbids patching that file.
2. **It's hard-wired to libaio.** The handler calls `io_getevents(ngx_aio_ctx,…)`;
   the submit path emits an `IOCB_CMD_PREAD` iocb via `io_submit`. There is no
   seam to substitute a CQE source.
3. **It's read-only + O_DIRECT-only** (§7.3) — even if reachable, it would serve
   neither our writes nor our buffered reads.

### 7.3 Why not just enable `aio on;` (nginx's existing native AIO)?

nginx already ships an async-file feature; we deliberately don't route disk I/O
through it:

| `aio on;` (native libaio) | io_uring backend (this plan) |
|---|---|
| **Read-only** — `aio_write` is "limited to writing temporary files… only with `aio threads`" (nginx docs); no native-AIO writes | reads **and** writes (kXR_write/pgwrite/writev) |
| **Requires `directio`/O_DIRECT** — "otherwise reading will be blocking" (nginx docs) → **bypasses the page cache**, blocks on unaligned head/tail | works on ordinary buffered fds; page-cache-friendly; composes with the phase-32 `RWF_NOWAIT` warm-cache probe |
| one in-flight iocb per `io_submit` (no batching) | batched SQE submission, linked ops (write→fsync), future registered files/buffers |
| not reachable per-op from a stream module's hand-rolled state machine | slots behind the module's existing `xrootd_aio_post_task` seam |

io_uring is thus **not redundant with `aio on;`** — it is the capability superset
that removes exactly the limitations (writes, O_DIRECT, batching) that made the
module choose a thread pool over native AIO originally. The thread pool itself
(`ngx_thread_pool`, the `aio threads` machinery) is **reused as the fallback
tier**, not duplicated.

### 7.4 What we reuse from core *unchanged* (the larger story)

To be explicit that duplication is the exception, Part A consumes from nginx core
rather than reinventing:

- **Posted-events queue** `ngx_posted_events` + `ngx_post_event()` — completion
  dispatch (identical to the libaio path).
- **Thread pool** `ngx_thread_pool` / `ngx_thread_task_alloc` / `ngx_thread_task_post`
  / `ngx_thread_task_t` (`src/core/ngx_thread_pool.{c,h}`) — the fallback tier,
  already used today.
- **Connection/event objects** `ngx_get_connection` / `ngx_add_event` /
  `ngx_del_event` / `ngx_close_connection` / `ngx_event_t` — the eventfd wrapper.
- **Output path** `ngx_linux_sendfile_chain` / `ngx_output_chain` /
  `ngx_http_output_filter` + kTLS — untouched; io_uring never touches egress.
- The entire framing/auth/metrics/response stack and the six `*_aio_done`
  callbacks — untouched.

### 7.5 The zero-duplication alternative — a core io_uring *event module* — and why it's out of bounds

The architecturally "correct" way to add io_uring to nginx is a first-class
**event module** implementing the `ngx_event_actions_t` vtable (`add`/`del`/
`enable`/`disable`/`add_conn`/`del_conn`/`notify`/`process_events`/`init`/`done`,
`src/event/ngx_event.h:166`), selected like `epoll`/`kqueue`. That makes io_uring
the loop's poller and avoids the eventfd bridge entirely. We reject it for the
server because:

- Event modules are **compiled into the core binary** and registered in core's
  module list (`src/core/nginx.c` / `ngx_modules.c`); **an `--add-module` addon
  cannot add one** — it requires patching and recompiling nginx itself, forking
  our nginx build. Build governance forbids this.
- It replaces the loop's poller **process-wide**, affecting *all* traffic, not
  just our disk ops — a far larger blast radius than an opt-in disk backend.

**Prior art confirms this is the known shape — and that it never merged upstream.**
Unmerged nginx-devel patches prototyped exactly this: SoYun Seong's
`ngx_uring_module` event module (nginx-devel, 2020, needs `IORING_FEAT_FAST_POLL`)
and Ping Zhao/Intel's io_uring-in-the-AIO-module patch (nginx-devel, 2021), plus
the third-party `CarterLi/nginx-io_uring` fork (epoll→io_uring event module,
self-described "highly experimental", Linux 5.13+). Official nginx (1.27 mainline
/ 1.28 stable) and freenginx ship **no** io_uring; the only upstream artifact is
open backlog feature request **nginx/nginx#568** (2025). **So this backend is not
duplicating a shipped nginx feature** — it productionizes, off-by-default and
addon-scoped, what upstream has only as unmerged patches.

**Forward-compatibility:** keep `xrootd_aio_post_task` as the single switch point
so that *if* nginx or freenginx ever ships a core io_uring poller/file-AIO, a
future tier "use core io_uring when the active event method provides it" drops in
without touching callers.

### 7.6 Client side: no nginx duplication — but reuse liburing, not raw syscalls

`client/` links no nginx, so there is **zero** nginx-core duplication on the
client. The client's `aio.c` epoll loop is its own hand-rolled event loop, so the
io_uring engine (CB-W4) is greenfield. The one non-duplication rule there: use
**liburing** (`io_uring_prep_*`, `io_uring_submit`, CQE helpers) rather than
re-deriving SQ/CQ ring management from raw `io_uring_setup`/`mmap` — don't
reinvent liburing. The only upstream overlap to acknowledge is conceptual:
CarterLi's fork already swapped nginx's epoll for an io_uring loop; our client
engine applies the same idea to our own loop.

### 7.7 Security/seccomp reality (why off-by-default + probe + fallback is load-bearing)

A subtler form of "don't duplicate core's assumptions": nginx keeps `aio` **off
by default**, and io_uring adds an operational hazard libaio does not. io_uring
has been a major kernel attack surface — Google reported ~60% of its kernelCTF
exploits targeted io_uring (~$1M paid out) and **disables it on production
servers, ChromeOS, and Android**; Docker/containerd default seccomp profiles
**block the io_uring syscalls**. Many target environments therefore ship io_uring
unreachable. This is exactly why the runtime `io_uring_queue_init`+opcode probe
and silent fallback (§3.3, §5) are mandatory, not cosmetic — a backend that
assumed availability would fail closed in precisely the hardened environments
WLCG sites run. §8 hardens this further with a *no-restart* kill switch for
incident response and a privilege-containment model so the io_uring surface is
never reachable as root. (Sources: oss-security 2023-07-19 io_uring disablement post;
containerd seccomp issue #9048; nginx `aio`/`aio_write`/`thread_pool` docs.)

---

## 8. Security hardening: runtime kill switch + privilege containment

Two operator requirements, both satisfiable with mechanisms **already shipping in
this codebase** — no new privileged surface is introduced. (a) the kernel-async
path must be disableable *at runtime* in response to a future security event; and
(b) the async I/O must run under the **delegated user, not root**, so an io_uring
kernel bug cannot be reached from a privileged namespace.

### 8.1 Runtime kill switch — four levels, one no-restart

io_uring is the *only* kernel-async backend the module enables (nginx's own
libaio stays `aio off;` — §7.3); the switches below govern it (and would govern
libaio too if a future build ever wired it). There are four independent off
levels, escalating in response time:

1. **Build-time master-off** — `XROOTD_HAVE_LIBURING` undefined → no `-luring`,
   stubs only (§3, §4). The ultimate off; requires a rebuild.
2. **Config-off on reload** — `xrootd_io_uring off` + `nginx -s reload`. Workers
   re-fork through `ngx_stream_xrootd_init_process()` (`src/config/process.c:94`)
   and simply don't create a ring. No rebuild, ~0 downtime, but needs a reload.
3. **Hot kill switch (no reload) — the incident-response path.** A cross-worker
   **SHM atomic** `io_uring_disabled`, allocated in the module's SHM table via
   `xrootd_shm_table_alloc()` (`src/compat/shm_slots.c:14`) following the exact
   `ngx_atomic_t` pattern already used for the dashboard transfer table
   (`src/dashboard/dashboard.h:109`, hot-path read at
   `src/dashboard/transfer_table.c:155`, atomic write at `:322`):
   - **Read** lock-free on the submit hot path — one `ngx_atomic_load` added to
     the selector in `xrootd_aio_post_task` (§A.5): if set, skip the uring tier
     and fall straight to thread pool → inline. Every worker observes the change
     on its **next** op; no IPC, no restart.
   - **Set/clear** through the existing phase-23 admin API — a new
     `POST /xrootd/api/v1/admin/io_uring` body `{"enabled": false}` handler in
     `src/dashboard/api_admin.c`, reusing `xrootd_admin_check_auth()` (`:189`,
     bearer-token *constant-time* compare + CIDR allowlist) and `admin_audit()`
     (`:236`, `NGX_LOG_NOTICE`). Re-enable with `{"enabled": true}` once patched.
   - **Drain semantics:** flipping the flag stops *new* submissions only; the
     reaper keeps harvesting in-flight CQEs to completion (no op is dropped or
     corrupted). An optional second level quiesces and tears the ring down per
     worker once `inflight == 0`, so even the ring fd disappears — but "stop
     submitting" already removes the surface for all new requests instantly.
4. **Watched panic-file** `xrootd_io_uring_panic_file <path>` (default unset) —
   if the file exists, workers treat io_uring as disabled. A coarse per-worker
   timer (seconds) stats it and updates the SHM flag, so an operator (or
   Ansible/Puppet) can disable io_uring fleet-wide by *dropping a file* —
   no API token, no reload, survives reload, and applies even before the admin
   endpoint is reachable. This is the "2 a.m. CVE drops" switch.

The runtime **capability probe** (§3.3) is effectively a fifth, automatic level:
on a kernel/seccomp that blocks `io_uring_setup` (Google/containerd posture,
§7.7), the worker never creates a ring in the first place.

**Observability:** add a per-worker gauge `io_uring_active{worker}` (1/0) and
counters `io_uring_ops` / `io_uring_fallback` to the metrics enum
(`src/metrics/metrics.h`), and emit one `NGX_LOG_NOTICE` audit line on every flip
(via `admin_audit()` or the panic-file watcher) so the fleet-wide effect of a
kill is visible in logs and `/metrics`.

### 8.2 Privilege containment — async I/O as the delegated user, never root

The requirement "keep the aio calls within delegated user accounts (not root)…
to avoid exposure to a privileged user's namespace" is satisfied **by
construction**, because of how Phase-40 impersonation already splits privilege —
io_uring changes only *how* the existing data-plane bytes move, and the data
plane is already unprivileged and confined:

1. **The privileged broker is the only root component, and it never touches
   io_uring.** With `xrootd_impersonation map`, a separate broker process holds
   only `CAP_SETUID`/`CAP_SETGID` (`xrootd_imp_broker_drop_caps`,
   `src/impersonate/broker.c:207`; it can even drop to a non-root service account,
   `imp_drop_to_service_user` `:138`). The broker performs `openat2()` with
   `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` on its authoritative rootfd **as the
   mapped user** (`imp_openat2`, `broker.c:346`) and passes the resulting fd back
   to the worker via **SCM_RIGHTS** (`imp_send_reply`, `broker.c:805` →
   `imp_recv_reply`, `src/impersonate/client.c:204` → stored in `fh->fd`,
   `src/fs/vfs_open.c:137`). The broker does **only** open + metadata ops
   (`impersonate_proto.h` opcodes) — **no data-plane read/write** — so there is
   no reason for it to ever own a ring.

2. **io_uring runs in the *unprivileged* worker, on a pre-vetted fd.** The worker
   holds **zero filesystem capabilities**. The fd handed to the AIO layer
   (`task->fd = xrootd_vfs_file_fd(fh)`, `src/fs/vfs.h:99`) is exactly the
   broker-opened, DAC-checked, `RESOLVE_BENEATH`-confined fd. An
   `IORING_OP_READ/WRITE/FSYNC` on an already-open fd performs **no further uid/gid
   permission check** (Unix checks at `open()` time, which happened as the mapped
   user). io_uring's async io-wq kernel workers inherit the **worker's
   unprivileged credentials** — so the entire kernel-async surface runs as the
   service account / mapped user, never root. The selector simply submits the
   same fd the thread-pool worker would have `pread`'d (§A.6) — no new path
   handling, no new privileged code.

3. **The ring is physically barred from touching a namespace.** At setup the ring
   is created with `IORING_SETUP_R_DISABLED`, locked with
   `io_uring_register_restrictions()` to a **whitelist of fd-only data opcodes**
   — `READ`, `WRITE`, `READV`, `WRITEV`, `FSYNC` — then enabled
   (`io_uring_enable_rings()`). Every path/namespace-touching opcode is
   *excluded*: `OPENAT`, `OPENAT2`, `STATX`, `UNLINKAT`, `RENAMEAT`, `MKDIRAT`,
   `SYMLINKAT`, `LINKAT`, `GETDENTS`, `*XATTR`. So even if an attacker could forge
   SQEs through a kernel bug, the ring **cannot open or traverse any path** — it
   can only move bytes on fds the confined open path already produced. This is the
   strongest possible answer to "avoid exposure to a privileged user's namespace,"
   and it is *why* §A.6 keeps `open`, `dirlist`, and the path-based metadata ops
   off io_uring and on the broker/sync path. (`register_restrictions` needs kernel
   5.10; below that it is skipped and containment still holds via points 1–2 —
   the worker is unprivileged and the fd is already confined.)

4. **Deployment guidance (non-impersonation case).** When impersonation is *off*,
   the worker opens files directly as its own uid. Run the nginx workers as a
   **non-root service account** (the standard nginx deployment) so the ring is
   never created by root in any configuration. The build/ops docs should state
   this as the supported posture for enabling io_uring.

**Optional deferred tier — per-identity io_uring personalities.** For belt-and-
suspenders beyond "the worker is unprivileged," io_uring can stamp each SQE with a
`personality` (`io_uring_register_personality()`, kernel 5.6) so the op runs with
a specific registered credential set rather than the worker's. The catch:
`register_personality` captures the *registering thread's* current credentials and
personalities are ring-local, so registering the *mapped* user's personality would
require the broker's credential context and a broker-owned ring — a larger change
than the first cut warrants, given points 1–3 already keep the surface
unprivileged and confined. Documented in §9 as a future tier, not first cut.

---

## 9. Detailed data structures & types

This section is the implementation reference for every new type introduced by the io_uring backend, on both the server (`src/aio/`) and the client (`client/lib/uring.{c,h}`). It is exhaustive on purpose: field semantics, ownership, write-timing (submit-time vs. reaper vs. done-callback), and concurrency. Two rules govern everything below and are repeated where they bite:

1. **No existing struct changes layout.** The six `*_aio_t` task structs in `src/aio/aio.h` and the client `xrdc_aconn` (`client/lib/aio.c`) are reused as-is on the data path. The only additions are *new, separate* objects (`xrootd_uring_t`, the slot table, the client `xrdc_disk_ring`, the engine vtable) plus exactly **one** new scalar field on `xrdc_aconn` (`fd_gen`), justified in §9.7.
2. **Everything is behind `#if XROOTD_HAVE_LIBURING`.** The macro comes from `pkg-config liburing` at configure time (server `config`, client `Makefile`). When undefined, none of these types are compiled and the dispatcher never references them — the thread-pool/epoll paths are byte-for-byte unchanged.

### 9.1 Server: the per-worker singleton `xrootd_uring_t`

There is exactly one of these per nginx worker process. It is **not** embedded in any config struct, connection, or ctx — it is a file-scope static inside `src/aio/uring.c`, reached only through the accessor `xrootd_uring_worker()` (the "no new globals" constraint: the symbol is `static`, not exported). It is allocated/initialized in the worker-init hook after fork, and torn down in worker-exit.

```c
#if (XROOTD_HAVE_LIBURING)
typedef struct {
    struct io_uring     ring;          /* liburing SQ/CQ rings + mmap'd state  */
    int                 eventfd;       /* registered via io_uring_register_eventfd */
    ngx_connection_t   *evc;           /* fake conn wrapping eventfd into epoll */
    uint32_t            queue_depth;   /* SQ entries; also slot-table length    */
    uint32_t            inflight;      /* SQEs submitted, CQEs not yet reaped   */
    unsigned            enabled:1;     /* ring up & probe passed this worker    */
    unsigned            sqpoll:1;      /* IORING_SETUP_SQPOLL active            */
    unsigned            restrict_ops:1;/* io_uring_register_restrictions applied */
    ngx_log_t          *log;           /* worker cycle log (for the reaper)     */
    xrootd_uring_slot_t *slots;        /* completion-slot table, queue_depth len */
    ngx_atomic_t       *disabled_flag; /* SHM kill-switch (read each submit)     */
} xrootd_uring_t;
#endif
```

Field-by-field:

- `ring` — owned by this struct for the worker's lifetime. Mutated **only on the event thread**: SQEs are filled and `io_uring_submit()` is called from the submit path (under `xrootd_aio_post_task`'s io_uring branch), CQEs are consumed from the reaper. The kernel writes the CQ ring tail and the SQ ring head asynchronously, but liburing's memory-ordering barriers make those the only cross-thread accesses; we never touch the same SQE/CQE from two contexts.
- `eventfd` — created with `eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC)` and handed to `io_uring_register_eventfd(&ring, eventfd)`. The kernel increments it on each CQE; nginx's epoll readiness on `evc` is what wakes the reaper. Written once at init; never again.
- `evc` — an `ngx_get_connection(eventfd, log)` connection whose `read->handler` is the reaper. This is the **public-API** bridge into epoll (mirroring `ngx_epoll_eventfd_handler`, §7.1). Owned here; released in worker-exit before `io_uring_queue_exit`.
- `queue_depth` — set from the configured depth (clamped to a sane max, rounded to power-of-two for the SQPOLL case). It is **simultaneously the length of `slots`** (§9.2), so a free slot is always available for any SQE that the ring accepted. Immutable after init.
- `inflight` — incremented at submit, decremented in the reaper per CQE. **Event-thread only**; it is not atomic and must never be touched off-thread. Used for backpressure: when `inflight == queue_depth` the submit path declines and the caller falls through to the thread pool (the existing `*posted = 0` fallback).
- `enabled` — set true only if `io_uring_queue_init` succeeded **and** the opcode probe (`io_uring_register_probe`) confirmed the ops we map. If false, `xrootd_uring_worker()` still returns the struct but every submit short-circuits to fallback. This is the per-worker arm of the kill switch.
- `sqpoll`, `restrict_ops` — record which hardening options actually took effect (kernel may refuse SQPOLL without privilege; restrictions need a recent kernel). Diagnostic; read by the dashboard, not on the hot path.
- `log` — borrowed pointer to the worker cycle log. Not owned.
- `slots` — `ngx_pcalloc`'d from the worker cycle pool, `queue_depth` entries. See §9.2.
- `disabled_flag` — points into the existing cross-worker SHM atomic (the §8 hot kill switch). Read (one plain read is sufficient; it's advisory) at the top of every submit; when nonzero, submit declines fleet-wide without a restart. Borrowed pointer into SHM, never written here.

Lifetime summary: created in worker-init, destroyed in worker-exit. Submit and reap both run on the single nginx worker thread, so apart from `ring`/`eventfd`/`disabled_flag` (kernel/SHM) there is **no intra-worker concurrency** to reason about — a deliberate design choice that keeps the slot-table logic lock-free-by-construction.

### 9.2 Server: the completion-slot table `xrootd_uring_slot_t`

The CQE carries a 64-bit `user_data` that we choose. It must let the reaper recover (a) which task struct completed and (b) which `*_aio_done` callback to post — **without** storing a raw pointer in `user_data`. The table is the indirection.

```c
typedef struct {
    void                *task;       /* the heap *_aio_t (cast per op_kind)     */
    ngx_event_handler_pt done_fn;    /* the *_aio_done to post on completion    */
    uint32_t             generation; /* bumped on free; guards stale CQEs       */
    uint8_t              op_kind;    /* xrootd_uring_op_e; selects OUT translation */
    uint8_t              in_use;     /* 1 = claimed & submitted, 0 = free       */
} xrootd_uring_slot_t;
```

**Sizing & allocation.** `slots` length `== queue_depth`. The ring will not accept more than `queue_depth` un-reaped SQEs, and `inflight` enforces the same ceiling on our side, so a free slot is guaranteed whenever the ring has room. Allocated once per worker with `ngx_pcalloc(cycle->pool, queue_depth * sizeof(xrootd_uring_slot_t))` in worker-init — zero-filled, so every slot starts `in_use=0, generation=0`. Never reallocated.

**`user_data` encoding.** `user_data = ((uint64_t)slot->generation << 32) | slot_index`. The low 32 bits index `slots[]`; the high 32 bits are the generation captured **at submit time**.

**Why `user_data` must not be a raw `*_aio_t` pointer (the UAF).** If `user_data` were `(uint64_t)(uintptr_t)task`, then a CQE arriving after the task was freed — which happens on the *cancel/teardown* path: client disconnects, ctx is torn down, the in-flight op is abandoned, and a kernel completion still lands — would dereference freed memory. The slot table converts that into a *validated table lookup*: a stale CQE indexes a slot whose `generation` no longer matches, and the reaper drops it. The pointer is never trusted directly; it is only read after the generation guard passes.

**Generation-guard algorithm (claim / free / validate).** All three run on the event thread.

```text
claim(task, done_fn, op_kind) -> user_data | DECLINE:
    if uring.inflight == uring.queue_depth: return DECLINE   # backpressure
    i = first slot with in_use == 0                          # O(depth); or a free ring
    if none: return DECLINE
    slots[i].task    = task
    slots[i].done_fn = done_fn
    slots[i].op_kind = op_kind
    slots[i].in_use  = 1
    ud = ((uint64_t)slots[i].generation << 32) | i
    uring.inflight++
    return ud

validate_and_take(ud) -> slot* | NULL:
    i   = ud & 0xffffffff
    gen = ud >> 32
    if i >= uring.queue_depth:            return NULL         # corrupt
    s = &slots[i]
    if !s->in_use || s->generation != gen: return NULL        # stale / double
    return s

free(slot s):
    s->in_use = 0
    s->task   = NULL
    s->generation++          # invalidate any future CQE bearing the old gen
    uring.inflight--
```

The reaper does `s = validate_and_take(cqe->user_data); if (s == NULL) continue;` — i.e. a generation mismatch is silently skipped (logged at debug, counted). On a real completion it translates `cqe->res` into the task's OUT fields per `op_kind` (§9.6), captures `task`/`done_fn`, calls `free(s)`, then `ngx_post_event(&task->event, &ngx_posted_events)` to run the existing done-callback unchanged. The generation wraps at 2^32; with a queue depth in the hundreds and microsecond-scale ops, wrap collision requires a CQE delayed by billions of completions on the same slot — not physically reachable.

A free-list (a small intrusive stack of free indices) may replace the linear `find first` scan; both are correct, the free-list is O(1). The struct does not need to carry the link — a parallel `uint32_t free_stack[queue_depth]` in `xrootd_uring_t` suffices and keeps `xrootd_uring_slot_t` at 24 bytes.

### 9.3 Server: op-kind enum and the worker-fn → op-kind lookup table

The slot stores `op_kind` so the reaper knows how to interpret `cqe->res` *without* re-deriving it from the task. The enum:

```c
typedef enum {
    XRD_URING_OP_READ = 0,   /* IORING_OP_READ  -> xrootd_read_aio_t          */
    XRD_URING_OP_WRITE,      /* IORING_OP_WRITE -> xrootd_write_aio_t         */
    XRD_URING_OP_READV,      /* IORING_OP_READV -> xrootd_readv_aio_t         */
    XRD_URING_OP_WRITEV,     /* IORING_OP_WRITEV-> xrootd_writev_aio_t        */
    XRD_URING_OP_FSYNC,      /* IORING_OP_FSYNC -> writev's do_sync tail      */
    XRD_URING_OP_NONE        /* sentinel; never submitted                    */
} xrootd_uring_op_e;
```

The call sites that build tasks (`reads.c`, `write.c`, `readv.c`) are **unchanged**: they still bind `task->handler = xrootd_read_aio_thread` and `task->event.handler = xrootd_read_aio_done` exactly as today. To keep them unchanged while letting the io_uring submit path know which op a given task is, a static table maps the bound *worker function pointer* to an op-kind. The submit path reads `task->handler`, looks it up, and derives both `op_kind` and the SQE-prep function.

```c
typedef struct {
    void               (*thread_fn)(void *, ngx_log_t *); /* task->handler key */
    xrootd_uring_op_e    op_kind;
    /* prep: fill an SQE from the *_aio_t; NULL = not uring-eligible (pool only) */
    void               (*prep)(struct io_uring_sqe *, void *task);
} xrootd_uring_dispatch_t;

static const xrootd_uring_dispatch_t xrootd_uring_dispatch[] = {
    { xrootd_read_aio_thread,         XRD_URING_OP_READ,   xrootd_uring_prep_read   },
    { xrootd_write_aio_thread,        XRD_URING_OP_WRITE,  xrootd_uring_prep_write  },
    { xrootd_readv_aio_thread,        XRD_URING_OP_READV,  xrootd_uring_prep_readv  },
    { xrootd_writev_write_aio_thread, XRD_URING_OP_WRITEV, xrootd_uring_prep_writev },
    { xrootd_pgread_aio_thread,       XRD_URING_OP_NONE,   NULL },  /* CRC: pool */
    { xrootd_dirlist_aio_thread,      XRD_URING_OP_NONE,   NULL },  /* opendir: pool */
};
```

A `prep == NULL` entry (pgread, dirlist) means "not first-cut eligible" — the submit path returns DECLINE and the existing thread-pool fallback runs, transparently. This table is the *only* coupling between the unchanged task structs and the io_uring backend; adding an op later is one row plus a `prep_*` function, with no call-site edits. The lookup is a fixed 6-row linear scan on a cold-ish path (once per AIO dispatch, not per byte); a `switch` on `task->handler` is equivalent but the table keeps the eligibility data in one place.

### 9.4 Server: the backend selector enum

```c
typedef enum {
    XRD_AIO_BACKEND_INLINE = 0,  /* synchronous pread/pwrite on the event thread */
    XRD_AIO_BACKEND_THREADPOOL,  /* ngx_thread_task_post (today's default)        */
    XRD_AIO_BACKEND_URING        /* io_uring submit; falls back to the two above  */
} xrootd_aio_backend_e;
```

This is a config-resolved value (directive `xrootd_aio_backend inline|threadpool|uring;`, default `threadpool`). It does **not** alter the dispatch *signature*: `xrootd_aio_post_task` still takes the same arguments. The io_uring branch is entered only when the resolved backend is `URING`, the worker's `enabled` bit is set, the op is uring-eligible (table §9.3), and `slot claim` succeeds; any miss is the normal `*posted = 0` fallthrough the caller already handles. The cascade is therefore **uring → threadpool → inline**, with each tier's failure expressed in the existing return protocol.

### 9.5 Client: the disk ring `xrdc_disk_ring` (internal layout)

`xrdc_disk_ring` is opaque in `client/lib/uring.h` (`typedef struct xrdc_disk_ring xrdc_disk_ring;`); the definition lives in `uring.c`. It backs the `copy.c` pump's local-disk side (CB-W2) with a deep queue of `pread`/`pwrite` against one local fd, using **registered buffers** so the kernel skips per-op page pinning. The pump's `pump_src_fn`/`pump_sink_fn` adapter interface (`client/lib/copy.c`) is unchanged — the ring sits behind it.

```c
struct xrdc_buf_desc {
    uint8_t *base;        /* aligned buffer start (in the registered pool)        */
    uint32_t len;         /* valid bytes for this op (pread: result; pwrite: req) */
    uint32_t seq;         /* monotonic chunk sequence this buffer is carrying      */
    int      in_flight;   /* 1 = SQE submitted, awaiting CQE                       */
};

struct xrdc_disk_ring {
    struct io_uring ring;          /* the client's own ring (separate from aio.c)  */
    int             fd;            /* the local file (download dst / upload src)   */
    int             o_direct;      /* O_DIRECT in effect -> alignment constraints  */

    /* registered buffer pool: nbuf buffers of bufsz each, one contiguous mmap */
    uint8_t        *pool_base;     /* posix_memalign'd region, nbuf*bufsz bytes    */
    uint32_t        nbuf;          /* buffer count (== queue depth)                */
    uint32_t        bufsz;         /* per-buffer size (== copy chunk)              */
    struct xrdc_buf_desc *descs;   /* nbuf descriptors, index == registered idx    */

    /* free-list of buffer indices (LIFO stack) */
    uint32_t       *free_idx;      /* nbuf entries                                 */
    uint32_t        free_top;      /* count of free buffers (== nbuf when idle)    */

    /* in-order completion sequence tracking */
    uint32_t        next_submit_seq;  /* seq assigned to the next chunk submitted  */
    uint32_t        next_retire_seq;  /* lowest seq not yet retired in order       */
    uint32_t       *done_ring;        /* seq -> completed? sparse bitmap/ring       */
    uint32_t        done_ring_mask;   /* power-of-two-1 mask over done_ring         */

    /* backpressure / accounting */
    uint32_t        inflight;      /* SQEs submitted, CQEs outstanding             */
    uint32_t        max_inflight;  /* == nbuf; submit blocks above this            */

    /* O_DIRECT alignment metadata */
    uint32_t        align;         /* logical block size (statvfs / BLKSSZGET)     */
    int             tail_buffered; /* final unaligned tail done via buffered fd    */
};
```

Behaviour and ownership (all single-threaded — the disk ring is driven only from the thread that owns the copy, never shared):

- **Registered buffers.** `pool_base` is one `posix_memalign(align)` region of `nbuf*bufsz` bytes, registered once via `io_uring_register_buffers`. Each `descs[i].base = pool_base + i*bufsz`. Registration is what makes O_DIRECT cheap; the descriptors map a registered index to its slice. Owned by the ring; freed (unregister + free) in `xrdc_disk_ring_destroy`.
- **Free-list.** `free_idx[0..free_top)` holds the indices of buffers not currently carrying an op. A submit pops one (`free_top--`); a retire pushes one back. When `free_top == 0` the pump must wait for a CQE before submitting more — this is the backpressure that bounds memory to exactly `nbuf*bufsz`.
- **In-order completion (the load-bearing invariant).** Disk reads/writes may complete out of order, but the pump must hand chunks to its *sink in order* and must not release a buffer until the chunk it carries is durably consumed. Each submitted chunk gets `seq = next_submit_seq++`. On CQE we mark `done_ring[seq & done_ring_mask]` and translate `cqe->res`. The retire loop then advances `next_retire_seq` over contiguously-completed seqs only, delivering chunk *k* to the sink and freeing buffer *k*'s descriptor **only after op *k* has completed** and all of `0..k-1` have retired. This guarantees chunk *k* is released after op *k* completes, never before, and that the sink sees a strictly increasing offset stream — required for correctness of a sized download/upload.
- **Backpressure counters.** `inflight` (vs `max_inflight == nbuf`) and `free_top` are two views of the same ceiling; both are checked so a partially-failed batch can't over-commit.
- **O_DIRECT alignment.** When `o_direct` is set, `align` (from `statvfs`/`BLKSSZGET`) constrains offset, length, and buffer base — all already satisfied because `pool_base` is `posix_memalign(align)` and chunks are `bufsz`-aligned multiples. The **final tail** of a file is rarely a multiple of `align`; `tail_buffered` flags that the last chunk is reissued on a buffered (non-O_DIRECT) fd, or that `O_DIRECT` is cleared for the tail `pwrite`, so the unaligned remainder is handled correctly. If alignment cannot be satisfied, `o_direct` is dropped for the whole transfer (buffered fallback) — never a failed copy.

`xrdc_uring_available()` is the memoized capability probe (a `static int` tri-state: unknown/yes/no), so the per-file open path doesn't re-probe the kernel.

### 9.6 Field-by-field OUT translation (reaper: `cqe->res` → task OUT field)

For each eligible op, the reaper writes exactly the OUT fields the matching `*_aio_thread` would have written, so the unchanged `*_aio_done` callback cannot tell whether the thread pool or the kernel produced the result (Option A). `cqe->res` is `>= 0` for bytes transferred, `< 0` for `-errno`.

| op_kind | task struct | OUT field set from `cqe->res >= 0` | OUT field(s) set from `cqe->res < 0` | short-I/O handling |
|---|---|---|---|---|
| READ | `xrootd_read_aio_t` | `nread = cqe->res`; `io_errno = 0` | `nread = -1`; `io_errno = -cqe->res` | `nread < rlen` is a legitimate short read (EOF); the done-callback already emits only `nread` bytes — no error synthesized |
| WRITE | `xrootd_write_aio_t` | `nwritten = cqe->res`; `io_errno = 0` | `nwritten = -1`; `io_errno = -cqe->res` | `nwritten < len` (short write) is a hard error: reaper sets `io_errno = EIO` so `xrootd_write_aio_done` raises `kXR_IOError`, matching today's thread semantics (`payload_to_free` is still freed by the done-callback) |
| READV | `xrootd_readv_aio_t` | `bytes_read_total = cqe->res`; `io_error = 0` | `io_error = 1`; copy `strerror(-cqe->res)` into `err_msg` | short readv past EOF → `io_error = 1`, `err_msg = "short read"`, mirroring `xrootd_readv_read_segments`'s contract; `response_bytes` is computed by the done-callback from the prebuilt layout |
| WRITEV | `xrootd_writev_aio_t` | `bytes_total = cqe->res`; `io_error = 0` | `io_error = 1` (pwrite error); `err_msg` from `-cqe->res` | `bytes_total < Σ wlen` → `io_error = 2` (short write), exactly the thread's code |
| FSYNC | `xrootd_writev_aio_t` (`do_sync` tail) | leaves `io_error` as set by the preceding WRITEV | on `cqe->res < 0`, set `io_error = 1`, `err_msg = "fsync: <e>"` | FSYNC is a *linked* SQE after the WRITEV (`IOSQE_IO_LINK`); a failed link short-circuits and the reaper sees the WRITEV's success plus the FSYNC's error on one task |

Notes the implementer must honour:

- The reaper does the `-errno` negation (`io_errno = -cqe->res`), not the done-callback — the callbacks expect a positive errno exactly as a thread would have left after `pread` set `errno`.
- READV/WRITEV use one SQE with the task's existing iovec/segment array as the registered or transient iovec; coalescing of adjacent same-fd segments (today done inside the thread) is performed at *prep* time when building the iovec, so the kernel sees the same grouped vectored op.
- For WRITEV+FSYNC the two SQEs share one slot/`user_data` only if linked completions are reported as a single terminal CQE; if the kernel reports two CQEs, the prep allocates **two** slots and the FSYNC slot's `done_fn` is a no-op that only decrements `inflight` and merges its result into the task (which the WRITEV slot still owns). First cut keeps it simple: FSYNC is mapped only when linked-CQE coalescing is available, else WRITEV stays on the pool.

### 9.7 Client: the engine vtable and the two implementation tables

`client/lib/aio.c`'s epoll loop is abstracted behind a vtable so the io_uring engine is a drop-in (CB-W4, default OFF). The loop calls through the vtable; `aio.c`'s direct `epoll_ctl`/`eventfd` calls move behind the epoll impl.

```c
typedef struct xrdc_io_engine {
    /* create the readiness/completion engine; returns opaque engine state */
    void *(*create)(xrdc_loop *l);
    /* (re)arm interest for a connection's fd (read/write mask) */
    int   (*arm)(void *eng, int fd, uint32_t fd_gen, int want_r, int want_w);
    /* block until ready/complete or timeout; fills events; returns count */
    int   (*wait)(void *eng, struct xrdc_io_ev *out, int max, int timeout_ms);
    /* cross-thread wakeup (the eventfd kick) */
    void  (*wake)(void *eng);
    /* drop all interest for an fd (close/reconnect) */
    void  (*cancel)(void *eng, int fd, uint32_t fd_gen);
    void  (*destroy)(void *eng);
} xrdc_io_engine;

static const xrdc_io_engine xrdc_engine_epoll = {
    epoll_eng_create, epoll_eng_arm,  epoll_eng_wait,
    epoll_eng_wake,   epoll_eng_cancel, epoll_eng_destroy,
};

#if (XRDC_HAVE_LIBURING)
static const xrdc_io_engine xrdc_engine_uring = {
    uring_eng_create, uring_eng_arm,  uring_eng_wait,
    uring_eng_wake,   uring_eng_cancel, uring_eng_destroy,
};
#endif
```

The io_uring impl first ships as a **`IORING_OP_POLL_ADD` multishot** drop-in (readiness, not completion) so the existing `aconn_do_read`/`aconn_do_write` and the TLS state machine are untouched — TLS-safe because `SSL_read`/`SSL_write` still run on the loop thread exactly as under epoll. Cleartext `IORING_OP_RECV/SEND` multishot is a later, opt-in tier.

**The `fd_gen` field on `xrdc_aconn` (the one new field).** io_uring's poll/recv multishot completions are *armed once and fire repeatedly*; an in-flight completion can land **after** the fd was closed and its number reused by a reconnect (the reconnect worker hands back a fresh socket). With epoll this was harmless (`EPOLL_CTL_DEL` on close). With io_uring a stale multishot CQE for the *old* fd-incarnation would be mis-routed to the new connection. `xrdc_aconn.fd_gen` is a `uint32_t` bumped every time the fd is replaced; it is folded into the engine's `user_data` (alongside the aconn pointer/index) and validated on every completion — the engine's own generation guard, mirroring the server's slot generation. This is exactly why it is the single permitted addition to `xrdc_aconn`: without it the io_uring engine is unsound under reconnect; the epoll engine ignores it.

`xrdc_copy_opts.io_uring` is the tri-state opt-in surfaced to `xrdcp` (`0` = auto/probe, `1` = force on, `2` = force off), added to the struct in `client/lib/xrdc.h`. It selects the disk ring for `copy.c`; the engine swap in `aio.c` is gated independently and defaults off regardless.

### 9.8 ABI, layout, and build notes

- **All new types are behind `#if XROOTD_HAVE_LIBURING` (server) / `#if XRDC_HAVE_LIBURING` (client).** With the macro undefined, the compilation unit `uring.c` is still built but reduces to the probe stub returning "unavailable"; no struct above is referenced by the dispatcher.
- **No existing struct changes layout on the server.** `xrootd_uring_t` is a *separate per-worker object*, never a member of `xrootd_ctx_t`, the srv conf, or any `*_aio_t`. The `*_aio_t` structs in `src/aio/aio.h` are byte-identical to today. This is mandatory: the task structs are allocated by call sites compiled in many `.c` files, and any size/offset change requires all of them to agree.
- **Mixed-ABI crash hazard (must rebuild fully).** `aio.h` is included across `reads.c`, `write.c`, `readv.c`, `resume.c`, `uring.c`, and the dispatch sites. If a struct *did* change (e.g. a future field added to `xrootd_write_aio_t`), an incremental build that recompiles only some `.c` files leaves objects with **different layouts of the same struct** — the reaper writes `nwritten` at one offset, the done-callback reads it at another: silent corruption or a crash. The single new field on `xrdc_aconn` (`fd_gen`) is the only struct-layout change in the entire phase, and it ships in the same commit as a forced full rebuild. **Rule for implementers: any edit to a struct in `aio.h` or to `xrdc_aconn` requires `touch`-ing the dependent `.c` files (or a clean build), never a partial `make`.** The client `xrdc_disk_ring` is opaque (defined only in `uring.c`), so it carries no cross-TU ABI risk by construction — keep it that way; do not move its definition into a header.
- **Build wiring.** Server: `config` runs `pkg-config --exists liburing`; on success it appends `-DXROOTD_HAVE_LIBURING` to `CFLAGS` and `-luring` to the link line, and adds `uring.c` to the module sources. Client: the `Makefile` does the same with `XRDC_HAVE_LIBURING` and adds `lib/uring.o` (PIC and static variants, matching the existing dual-build of `lib/*.o`/`lib/*.pic.o`). Absent liburing, neither flag is set and the new objects compile to stubs.

### 9.9 Memory budget

The phase-31 memory budget covers per-connection nginx pool buffers and is **not** affected on the server: `xrootd_uring_t` and its slot table are a fixed per-worker overhead (`queue_depth * 24` bytes for slots, plus the ring's own mmap'd SQ/CQ — tens of KiB at typical depths), counted once per worker, outside the per-connection accounting. No io_uring buffers are registered on the server side in the first cut (the existing `*_aio_t` databuf/scratch buffers are reused as the SQE target).

The client disk ring **does** add registered-buffer bytes: `nbuf * bufsz`, pinned for the lifetime of one copy. With the default copy chunk and a modest depth this is single-digit MiB per concurrent transfer. If/when the disk ring is adopted as the default copy path, this `nbuf*bufsz` must be added to the client footprint accounting (the per-transfer budget that today is one `XRDC_COPY_CHUNK` buffer in `transfer_pump`): the ring trades a single chunk buffer for `nbuf` of them, by design, to overlap disk and network. The ceiling is hard — backpressure (`free_top == 0`) prevents any allocation beyond the registered pool, so the footprint is exactly `nbuf*bufsz` and never grows under load.

---

## 10. Server submission cookbook (per opcode)

This section specifies, opcode by opcode, exactly how `xrootd_aio_post_task` (`src/aio/resume.c`) turns a bound `ngx_thread_task_t` into an io_uring SQE, what runs where (submit-time inline vs SQE vs done-callback), how `cqe->res` translates back into the existing OUT fields, and how short/partial I/O reaches the unchanged `kXR_IOError` branch. Every mapped op preserves the Option-A contract from §A.4: the worker fn is bypassed, but the `*_aio_done` callback and wire framing are byte-for-byte unchanged. The submission entry point is a single new helper `xrootd_uring_submit(ctx, c, task, op, posted)` invoked from the selector in §10.7; the per-opcode bodies below are the `switch (op)` arms inside it.

### 10.0 Common submit-time scaffolding (runs for every mapped op)

Before any `io_uring_prep_*`, `xrootd_uring_submit` does the slot bookkeeping that makes the CQE UAF-safe (§A.3) and the fall-through correct. This is shared, so it is written once and the per-op arms only differ in the prep call.

```c
/* WHAT: turn a bound thread-task into an SQE; on any prep/submit failure
 *       leave *posted=0 so the caller falls through to the pool.
 * WHY:  the op must never be dropped; the ring is best-effort.
 * HOW:  reserve a slot (generation guard), get an SQE, prep, set user_data,
 *       submit; only on a fully-successful submit do we claim the op. */
static ngx_int_t
xrootd_uring_submit(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_task_t *task, xrootd_uring_op_t op, ngx_flag_t *posted)
{
    xrootd_uring_t      *u = xrootd_uring_worker();
    xrootd_uring_slot_t *slot;
    struct io_uring_sqe *sqe;
    uint32_t             idx;
    uint64_t             cookie;

    *posted = 0;

    /* 1. reserve a free slot; full ring → caller uses the pool */
    slot = xrootd_uring_slot_acquire(u, &idx);
    if (slot == NULL) {
        return NGX_OK;                 /* *posted stays 0 */
    }

    /* 2. an SQE must be available (ring not mid-submit-overflow) */
    sqe = io_uring_get_sqe(&u->ring);
    if (sqe == NULL) {
        xrootd_uring_slot_release(u, idx);   /* bump generation, in_use=0 */
        return NGX_OK;
    }

    /* 3. per-op prep — fills sqe, may need a second linked SQE (writev+fsync).
     *    Returns NGX_DECLINED if the op turns out non-mappable at run time
     *    (e.g. multi-fd writev that slipped past op_for): release + fall back. */
    if (xrootd_uring_prep_op(u, sqe, op, task) != NGX_OK) {
        xrootd_uring_slot_release(u, idx);
        return NGX_OK;
    }

    /* 4. stash the task identity in the slot, encode the cookie */
    slot->task    = task;
    slot->done_fn = task->event.handler;     /* xrootd_*_aio_done */
    slot->op_kind = (uint8_t) op;
    slot->in_use  = 1;
    cookie = ((uint64_t) slot->generation << 32) | idx;
    io_uring_sqe_set_data64(sqe, cookie);    /* also set on the linked SQE */

    /* 5. submit. A partial/failed submit is rare but must not leak the slot. */
    if (io_uring_submit(&u->ring) < 0) {
        xrootd_uring_slot_release(u, idx);
        return NGX_OK;
    }

    u->inflight += xrootd_uring_sqe_count(op);   /* 1, or 2 for writev+fsync */
    *posted = 1;
    return NGX_OK;
}
```

Notes binding the contract:
- The `slot->done_fn` snapshot is the same `task->event.handler` set by `xrootd_task_bind()`; the reaper calls it through the posted-event, so the callback identity is carried by the slot, not re-derived. This is why call sites are untouched.
- `xrootd_uring_sqe_count(op)` returns 2 only for WRITEV-with-sync (write SQE + linked fsync SQE share **one** slot/cookie on the *write* SQE; the fsync SQE carries the same cookie so a stray fsync CQE decodes to the same slot — see §10.5).
- Everything in steps 1–5 runs on the event thread at submit time. The blocking syscall the worker fn would have done becomes the SQE. Nothing here touches the connection's protocol state beyond what the selector already does (`ctx->state = XRD_ST_AIO`).

### 10.1 READ → `IORING_OP_READ`

Task struct: `xrootd_read_aio_t` (`src/aio/aio.h`). Worker fn bypassed: `xrootd_read_aio_thread` (`src/aio/reads.c`), whose entire body is `pread(t->fd, t->databuf, t->rlen, t->offset)`.

(a) Prep sequence:

```c
case XRD_URING_OP_READ: {
    xrootd_read_aio_t *t = task->ctx;
    io_uring_prep_read(sqe, t->fd, t->databuf, (unsigned) t->rlen,
                       (__u64) t->offset);
    /* user_data + submit handled by the common scaffolding */
    break;
}
```

No `IOSQE` flags. `t->databuf` is the same scratch slot the worker would have pread into (`read_scratch` via `XROOTD_GET_SCRATCH`), so budget accounting and the response builder are unchanged.

(b) What runs where:
- **Inline at submit time:** scratch allocation, `xrootd_budget_sync`, the phase-32 `preadv2(RWF_NOWAIT)` warm-cache probe (probe still runs *before* dispatch — on a hit the read never reaches the selector at all; see §10.8 and §A.7). The `(fd, databuf, rlen, offset)` fields are already populated by `xrootd_read_window_pump` before `xrootd_aio_post_task` is called.
- **Becomes the SQE:** the `pread`.
- **Stays in the done-callback:** all protocol work — `xrootd_read_window_emit`, chain build (chunked > 16 MiB), counter updates, `xrootd_aio_resume`. Unchanged from the thread-pool path.

(c) OUT-field translation (in the reaper, §A.4):

```c
case XRD_URING_OP_READ:
    if (cqe->res < 0) { t->io_errno = -cqe->res; t->nread = -1; }
    else              { t->nread = cqe->res; t->io_errno = 0; }
    break;
```

io_uring returns `-errno` in `cqe->res`, never via `errno`.

(d) Short read / partial completion: a short read is `0 <= cqe->res < t->rlen`. This is the *normal* EOF / end-of-file-region case and is identical to a short `pread`: `t->nread` is the smaller count, and `xrootd_read_window_emit`/`xrootd_read_aio_done` (`src/aio/reads.c`) handle it exactly as today (EOF → `kXR_ok` with the bytes actually read, advancing `rd_win_remaining`). A hard error is `cqe->res < 0` → `t->nread = -1`, which lands on the existing `if (t->nread < 0)` branch in `xrootd_read_aio_done` → `XROOTD_OP_ERR` + `xrootd_send_error(ctx, c, kXR_IOError, strerror(t->io_errno))`. **No new error path is introduced.**

(e) Fall-through-to-pool conditions for READ: ring disabled, `disabled_flag` (runtime kill switch), `inflight >= queue_depth`, `xrootd_uring_slot_acquire` returns NULL, `io_uring_get_sqe` returns NULL, or `io_uring_submit < 0`. In every case `*posted` stays 0 inside `xrootd_uring_submit`, the selector proceeds to `ngx_thread_task_post`, and if that also fails the window pump's existing inline `pread` (`reads.c`) runs. The op is never dropped.

(f) Worked timeline (single 2 MiB window):
1. `xrootd_read_window_pump` allocates `read_scratch`, runs the `RWF_NOWAIT` probe → miss.
2. Calls `xrootd_aio_post_task`; selector picks io_uring; `xrootd_uring_submit` preps `IORING_OP_READ`, `user_data = (gen<<32)|idx`, `io_uring_submit`, `inflight++`, `*posted=1`.
3. Selector sets `ctx->state = XRD_ST_AIO`; pump returns (it sees `posted`).
4. Kernel completes the read; eventfd fires; epoll wakes the worker.
5. `xrootd_uring_eventfd_handler` reads the eventfd counter, peeks the CQE, decodes slot, validates generation, sets `t->nread`/`t->io_errno`, `ngx_post_event(&task->event, &ngx_posted_events)`, `io_uring_cqe_seen`, `inflight--`, `slot_release`.
6. nginx's posted-events drain runs `xrootd_read_aio_done` → `xrootd_read_window_emit` → queue chunk → either next window (re-submit, depth returns to 1) or `xrootd_aio_resume`.

### 10.2 WRITE → `IORING_OP_WRITE`

Task struct: `xrootd_write_aio_t`. Worker fn bypassed: `xrootd_write_aio_thread` (`src/aio/write.c`), body `pwrite(t->fd, t->data, t->len, t->offset)`.

(a) Prep:

```c
case XRD_URING_OP_WRITE: {
    xrootd_write_aio_t *t = task->ctx;
    io_uring_prep_write(sqe, t->fd, t->data, (unsigned) t->len,
                        (__u64) t->offset);
    break;
}
```

(b) Where:
- **Inline at submit:** `resolve_path` → `open` (this happens upstream in the write handler, unchanged), the detached-payload copy into `t->payload_to_free` (also upstream). `t->data` points into that detached copy.
- **Becomes the SQE:** the `pwrite`.
- **Stays in done-callback:** `xrootd_write_aio_done` — `kXR_ok` framing, `bytes_written`/`session_bytes_written` accounting, pgwrite-status emission for `is_pgwrite`, and the unconditional `ngx_free(t->payload_to_free)`.

Critical lifetime point (from §A.4): `t->payload_to_free` is the SQE's source buffer. It is freed **only** in `xrootd_write_aio_done`, which only runs *after* the CQE. The in-flight `IORING_OP_WRITE` therefore always reads live memory; nothing about the detached-payload discipline changes. The done-callback frees it even on the `ctx->destroyed` path (the existing comment in `aio.h` already mandates this) — that path is reached because the reaper still posts the event and the callback still runs; only the protocol work is skipped after the free.

(c) Translation:

```c
case XRD_URING_OP_WRITE:
    if (cqe->res < 0) { t->io_errno = -cqe->res; t->nwritten = -1; }
    else              { t->nwritten = cqe->res; t->io_errno = 0; }
    break;
```

(d) Short / partial: a short write is `0 <= cqe->res < t->len`. Unlike read, a short write is an **error** for the protocol (we must not ack fewer bytes than the client sent). The existing `xrootd_write_aio_done` branch `if ((size_t) t->nwritten < t->len)` emits `kXR_IOError("short write (disk full?)")` (`write.c`). A hard error (`cqe->res < 0` → `t->nwritten = -1`) hits the prior `if (t->nwritten < 0)` branch → `kXR_IOError(strerror(t->io_errno))`. Both pre-existing.

(e) Fall-through: same six conditions as READ. On fall-through the pool runs `xrootd_write_aio_thread`; the detached payload is shared by both paths, so no change.

(f) Timeline: write handler copies payload → `t->payload_to_free`/`t->data`, binds task, calls `xrootd_aio_post_task` → submit `IORING_OP_WRITE` → CQE → reaper sets `t->nwritten` → posted-event → `xrootd_write_aio_done` frees payload, emits `kXR_ok` (or pgwrite status), resumes.

### 10.3 READV (single coalesced group) → `IORING_OP_READV`

Task struct: `xrootd_readv_aio_t`. Worker fn bypassed: `xrootd_readv_aio_thread` (`src/aio/readv.c`), which calls `xrootd_readv_read_segments` (validate offsets, coalesce adjacent same-fd segments into `preadv` of ≤64 iovecs, EINTR-retried, write into each `payload_ptr`).

**Mappability condition (decided at submit time, by `xrootd_uring_op_for` plus a run-time recheck):** all `segment_count` descriptors share **one** `fd` and coalesce into a **single** `preadv` group (≤64 iovecs). If the plan produces more than one group, or more than one fd, it is **not** a single `IORING_OP_READV` and stays on the pool (§10.6).

(a) Prep — build the iovec array from the descriptors' `payload_ptr`/`read_length`, all at the group's base offset:

```c
case XRD_URING_OP_READV: {
    xrootd_readv_aio_t *t = task->ctx;
    struct iovec       *iov;
    off_t               base_off;
    unsigned            n;

    /* single-group precondition already checked by the selector;
     * recheck here and DECLINE if it no longer holds. */
    if (!xrootd_readv_is_single_group(t, &base_off, &n, &iov)) {
        return NGX_DECLINED;            /* → slot release → pool */
    }
    io_uring_prep_readv(sqe, t->segments[0].fd, iov, n, (__u64) base_off);
    break;
}
```

The `iovec` array is built into per-connection scratch (or stack for ≤64) at submit time — it is *not* the SQE itself; the SQE references it, so it must outlive the in-flight op. Because the readv response buffer (`t->response_buffer`) and the descriptor array are pool-allocated and freed only in `xrootd_readv_aio_done` after the CQE, the iovec scratch lives in that same buffer region and is safe.

(b) Where:
- **Inline at submit:** the readv *plan* is already built before dispatch (response buffer laid out `[hdr][bytes][hdr][bytes]…`, each descriptor's `payload_ptr` set — this is the existing pre-I/O layout from `aio.h`). The iovec array build and single-group check are the only added inline work.
- **Becomes the SQE:** the coalesced `preadv` (one group).
- **Stays in done-callback:** `xrootd_readv_aio_done` emits the prebuilt `t->response_buffer`. **But** the per-segment wire-header rewrite (`header_read_length_ptr`) that `xrootd_readv_read_segments` normally does on the worker thread must now be done somewhere. Because the single-group case has fixed per-segment lengths known at plan time *except* for a short read at EOF, the header rewrite is folded into a small helper `xrootd_readv_finalize_headers(t, total)` invoked from the done-callback (event thread, cheap, no CRC) — keeping it off the harvest loop.

(c) Translation:

```c
case XRD_URING_OP_READV:
    if (cqe->res < 0) {
        t->io_error = 1;
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "readv I/O error: %s", strerror(-cqe->res));
        t->bytes_read_total = 0;
    } else {
        t->bytes_read_total = (size_t) cqe->res;
        t->response_bytes   = t->segment_count * XROOTD_READV_SEGSIZE
                            + t->bytes_read_total;
    }
    break;
```

(d) Short / partial: `IORING_OP_READV` returns total bytes across iovecs; `cqe->res < requested_total` is a short read (EOF inside the group). The single-group precondition means a short read truncates the *last* covered segment(s). The done-callback's `xrootd_readv_finalize_headers` rewrites each `header_read_length_ptr` to reflect actual bytes; a segment fully past EOF gets length 0. The existing `xrootd_readv_read_segments` treats "short read past EOF" as `NGX_ERROR` → `io_error=1` → `kXR_IOError`. To preserve that exact behaviour on the uring path, the finalizer applies the **same** rule: if `bytes_read_total` is short of the requested group total, set `io_error=1` with the existing message and let `xrootd_readv_aio_done` emit `kXR_IOError(t->err_msg)`. No new branch.

(e) Fall-through: the six common conditions **plus** `xrootd_uring_op_for` returning READV only when the plan is single-fd/single-group; any multi-group or multi-fd plan never selects uring (§10.6). A run-time `NGX_DECLINED` from prep also falls through.

(f) Timeline: readv handler builds the plan + response buffer → selector sees single group → submit `IORING_OP_READV` with the iovec array → CQE total → reaper sets `bytes_read_total` → posted-event → `xrootd_readv_aio_done` finalizes headers, emits `t->response_buffer`, resumes.

### 10.4 WRITEV (single fd) → `IORING_OP_WRITEV` (+ linked `IORING_OP_FSYNC` when `do_sync`)

Task struct: `xrootd_writev_aio_t`. Worker fn bypassed: `xrootd_writev_write_aio_thread` (`src/aio/write.c`) — per-segment `pwrite`, then per-unique-fd `fsync` if `do_sync`.

**Mappability:** all `n_segs` descriptors share one `fd` and are contiguous (offset[i] = offset[i-1] + wlen[i-1]) so a single `pwritev`-equivalent at `segs[0].offset` covers them. Non-contiguous single-fd segments cannot be one `IORING_OP_WRITEV` and stay on the pool (a later tier could submit N linked `IORING_OP_WRITE`s; deferred). Multi-fd → pool (§10.6).

(a) Prep, including the linked fsync:

```c
case XRD_URING_OP_WRITEV: {
    xrootd_writev_aio_t *t = task->ctx;
    struct iovec        *iov;
    unsigned             n;

    if (!xrootd_writev_is_single_contig_fd(t, &n, &iov)) {
        return NGX_DECLINED;
    }
    io_uring_prep_writev(sqe, t->segs[0].fd, iov, n,
                         (__u64) t->segs[0].offset);

    if (t->do_sync) {
        struct io_uring_sqe *fsqe;
        /* ORDER the write before the fsync in-kernel */
        sqe->flags |= IOSQE_IO_LINK;
        fsqe = io_uring_get_sqe(&u->ring);
        if (fsqe == NULL) {
            return NGX_DECLINED;        /* couldn't chain → pool */
        }
        io_uring_prep_fsync(fsqe, t->segs[0].fd, 0 /* full fsync */);
        io_uring_sqe_set_data64(fsqe, cookie);   /* same slot cookie */
    }
    break;
}
```

`IOSQE_IO_LINK` on the write SQE makes the kernel run the fsync only after the write succeeds; if the write fails the linked fsync is auto-cancelled with `-ECANCELED`, mirroring the worker's "fsync only after all segments succeed" rule (`write.c`).

(b) Where:
- **Inline at submit:** iovec build from `segs[]`, single-fd/contiguity check, two `io_uring_get_sqe` calls (write + fsync). The detached `payload_buf` is the iovec source.
- **Becomes the SQE(s):** the writev and the linked fsync.
- **Stays in done-callback:** `xrootd_writev_write_aio_done` — `kXR_ok`/`kXR_writev` framing, `session_bytes_written += t->bytes_total`, and the unconditional `ngx_free(t->payload_buf)`.

(c) Translation. Two CQEs arrive (write, fsync) both carrying the same cookie. The reaper must accumulate: the write CQE sets `bytes_total`/`io_error`; the fsync CQE (`cqe->res < 0` and not `-ECANCELED`) escalates to `io_error=1`. The slot is released and the done-event posted only after the **last** CQE of the chain. Implement with a `slot->pending_cqes` counter set to `xrootd_uring_sqe_count(op)` at submit and decremented per CQE:

```c
case XRD_URING_OP_WRITEV:
    if (cqe_is_fsync(slot, cqe)) {              /* second CQE */
        if (cqe->res < 0 && cqe->res != -ECANCELED) {
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev fsync error: %s", strerror(-cqe->res));
        }
    } else {                                    /* the writev CQE */
        if (cqe->res < 0) {
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev I/O error: %s", strerror(-cqe->res));
        } else if ((size_t) cqe->res < t->expected_total) {
            t->io_error = 2;
            snprintf(t->err_msg, sizeof(t->err_msg), "writev short write");
        } else {
            t->bytes_total = (size_t) cqe->res;
        }
    }
    if (--slot->pending_cqes == 0) {
        ngx_post_event(&task->event, &ngx_posted_events);
        xrootd_uring_slot_release(u, idx);
    }
    break;
```

`io_error` keeps the existing encoding (1 = hard, 2 = short) consumed by `xrootd_writev_write_aio_done`.

(d) Short / partial: writev short (`cqe->res < expected_total`) → `io_error=2` → existing `kXR_IOError(t->err_msg)`. Hard error or fsync error → `io_error=1`. Because the link auto-cancels the fsync on a failed write, a failed write yields write-CQE (`<0`) + fsync-CQE (`-ECANCELED`, ignored), correctly reporting one error.

(e) Fall-through: six common conditions; plus op_for selecting WRITEV only for single-fd/contiguous; plus `NGX_DECLINED` if the second `io_uring_get_sqe` for the linked fsync is unavailable. On fall-through the pool's `xrootd_writev_write_aio_thread` does the per-segment pwrite + per-fd fsync, unchanged.

(f) Timeline: writev handler detaches payload → `payload_buf`, builds `segs[]` → selector sees single contiguous fd → submit writev `IOSQE_IO_LINK` + fsync, `inflight += 2` → kernel runs write then fsync → two CQEs → reaper accumulates, posts on the last → `xrootd_writev_write_aio_done` frees `payload_buf`, emits ack, resumes.

### 10.5 The shared-cookie / multi-SQE invariant

The linked WRITEV+FSYNC is the only op submitting two SQEs. Both carry the **same** `user_data` cookie and **same** slot. The slot is not freed and the done-event is not posted until `pending_cqes` reaches 0, so a late fsync CQE never decodes to a recycled slot. A stray fsync CQE after a generation bump (impossible inside one chain but defended anyway) fails the generation check and is dropped (§A.3). All single-SQE ops set `pending_cqes = 1` and behave identically to the simple "post + release" path.

### 10.6 Why pgread / dirlist / multi-fd writev / multi-group readv are excluded, and exactly where the selector routes them

`xrootd_uring_op_for(task)` returns `XRD_URING_OP_NONE` for these, so the selector's first `if` is false and control falls straight to the `pool == NULL` / `ngx_thread_task_post` lines — i.e. they take the **unchanged thread-pool path**, or inline if no pool.

- **pgread (`xrootd_pgread_aio_thread`, struct `xrootd_pgread_aio_t`):** the worker does `pread` *then* a per-page CRC32c interleave producing the `kXR_status 4007` wire layout. Mapping only the `pread` to `IORING_OP_READ` would land the CRC32c loop on the event thread inside the done-callback — an unbounded compute burst on the loop. The wire invariant (`kXR_status 4007` + per-page CRC32c) and the interleave layout (`scratch[rlen..]`) must stay exactly as built by the worker. Excluded in the first cut; a future hybrid (uring read → pool CRC) is noted in §A.6. `op_for` keys on `xrootd_pgread_aio_thread` → `NONE`.
- **dirlist (`xrootd_dirlist_aio_thread`, struct `xrootd_dirlist_aio_t`):** `opendir`/`readdir`/`xrootd_dirlist_checksum_token` is not a single io_uring op (`IORING_OP_GETDENTS` is too new and liburing-helper-less, and the per-entry checksum is compute). The worker builds the entire wire reply in-struct. `op_for(xrootd_dirlist_aio_thread)` → `NONE`.
- **multi-fd / multi-group readv, multi-fd / non-contiguous writev:** `op_for` returns READV/WRITEV only after a *plan-shape* check (single fd, single coalesced group / contiguous). When the plan is multi-fd or multi-group, `op_for` returns `NONE`. The run-time `NGX_DECLINED` in prep (§10.3, §10.4) is a second safety net for the rare case where the plan shape was reclassified after `op_for` ran. Both land on the pool.

The exclusion is keyed entirely on the bound worker-fn pointer plus a cheap plan-shape predicate; no call site or task struct changes.

### 10.7 The `xrootd_uring_op_for` table and the modified `xrootd_aio_post_task` body (full, no goto)

```c
/* WHAT: map a bound task's worker fn (+ plan shape) to an io_uring op.
 * WHY:  the worker-fn pointer is the op identity already set by
 *       xrootd_task_bind(); keying on it means zero call-site churn.
 * HOW:  pointer compare, then a shape predicate for the vector ops. */
static xrootd_uring_op_t
xrootd_uring_op_for(ngx_thread_task_t *task)
{
    void (*fn)(void *, ngx_log_t *) = task->handler;

    if (fn == xrootd_read_aio_thread)  return XRD_URING_OP_READ;
    if (fn == xrootd_write_aio_thread) return XRD_URING_OP_WRITE;

    if (fn == xrootd_readv_aio_thread) {
        xrootd_readv_aio_t *t = task->ctx;
        return xrootd_readv_is_single_group(t, NULL, NULL, NULL)
               ? XRD_URING_OP_READV : XRD_URING_OP_NONE;
    }
    if (fn == xrootd_writev_write_aio_thread) {
        xrootd_writev_aio_t *t = task->ctx;
        return xrootd_writev_is_single_contig_fd(t, NULL, NULL)
               ? XRD_URING_OP_WRITEV : XRD_URING_OP_NONE;
    }

    /* pgread, dirlist, and any unmapped worker → thread pool */
    return XRD_URING_OP_NONE;
}
```

| Worker fn (op identity) | `op_for` result | Backend |
|---|---|---|
| `xrootd_read_aio_thread` | `OP_READ` | io_uring `IORING_OP_READ` |
| `xrootd_write_aio_thread` | `OP_WRITE` | io_uring `IORING_OP_WRITE` |
| `xrootd_readv_aio_thread` (single group) | `OP_READV` | io_uring `IORING_OP_READV` |
| `xrootd_readv_aio_thread` (multi-group/fd) | `NONE` | thread pool |
| `xrootd_writev_write_aio_thread` (single contig fd) | `OP_WRITEV` | io_uring `IORING_OP_WRITEV` (+linked fsync) |
| `xrootd_writev_write_aio_thread` (multi-fd/non-contig) | `NONE` | thread pool |
| `xrootd_pgread_aio_thread` | `NONE` | thread pool (CRC32c on loop avoided) |
| `xrootd_dirlist_aio_thread` | `NONE` | thread pool (not an io_uring op) |

```c
/* Modified body of xrootd_aio_post_task (src/aio/resume.c).
 * Single dispatch point; signature unchanged; no goto — early-return + helper. */
ngx_int_t
xrootd_aio_post_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted)
{
    xrootd_uring_t   *u;
    xrootd_uring_op_t op;

    *posted = 0;

    /* --- Tier 1: io_uring --- */
    u  = xrootd_uring_worker();
    op = xrootd_uring_op_for(task);
    if (u != NULL
        && u->enabled
        && !xrootd_uring_disabled(u)          /* SHM runtime kill switch */
        && op != XRD_URING_OP_NONE
        && u->inflight < u->queue_depth)
    {
        if (xrootd_uring_submit(ctx, c, task, op, posted) == NGX_OK
            && *posted)
        {
            ctx->state = XRD_ST_AIO;
            return NGX_OK;
        }
        /* prep/submit failed → *posted still 0 → fall through to the pool */
    }

    /* --- Tier 2: thread pool --- */
    if (pool == NULL) {
        return NGX_OK;                         /* *posted=0 → caller goes inline */
    }
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", fallback_log);
        return NGX_OK;                         /* *posted=0 → inline */
    }

    /* --- success via pool --- */
    ctx->state = XRD_ST_AIO;
    *posted = 1;
    return NGX_OK;
}
```

`xrootd_uring_disabled(u)` reads the SHM `disabled_flag`; it is checked here (not cached) so the runtime kill switch takes effect with no restart. The three tiers (uring → pool → inline) preserve the existing "op never dropped" guarantee.

### 10.8 Warm-cache probe composition (read path only)

The phase-32 `preadv2(fd, &iov, 1, off, RWF_NOWAIT)` probe runs **inline, before** `xrootd_aio_post_task`, in `xrootd_read_window_pump` (`src/aio/reads.c`). Composition:
- **Hit** (`preadv2` returns the full window without blocking): served synchronously, the read never reaches the selector, zero added latency. Reproducing this as an `IOSQE_ASYNC`/`RWF_NOWAIT` SQE was rejected (§A.7) — an SQE still costs one epoll cycle.
- **Miss** (`EAGAIN`): fall to `xrootd_aio_post_task`, which now prefers io_uring. The probe is therefore a fast-path *in front of* the ring, not replaced by it.

---

## 11. Server completion reaper & event-loop integration

The reaper is the io_uring analogue of nginx core's libaio completion handler `ngx_epoll_eventfd_handler` (`src/event/modules/ngx_epoll_module.c:942`): read the eventfd, harvest completions, set each task's OUT fields, and `ngx_post_event(&task->event, &ngx_posted_events)` — letting nginx's own posted-events drain run the done-callbacks. The eventfd is wrapped in an `ngx_connection_t` exactly as core's `ngx_epoll_aio_init` (`ngx_epoll_module.c:248`) wraps its libaio eventfd. We re-derive the shape (core's version is `static`, addon-invisible, libaio-wired) using public `ngx_get_connection`/`ngx_add_event`.

### 11.1 The reaper, in full

```c
/* WHAT: per-worker io_uring completion handler, fired when the registered
 *       eventfd becomes readable.
 * WHY:  mirror ngx_epoll_eventfd_handler so completions flow through nginx's
 *       existing posted-events queue — less code, and re-entrancy-safe.
 * HOW:  drain eventfd counter, peek CQEs, decode slot + validate generation,
 *       translate cqe->res into the task's OUT fields, post the done-event,
 *       mark the CQE seen, and adjust inflight. Never dispatch done-callbacks
 *       inline. */
static void
xrootd_uring_eventfd_handler(ngx_event_t *ev)
{
    ngx_connection_t    *evc = ev->data;
    xrootd_uring_t      *u   = evc->data;     /* evc->data = u (set at init) */
    struct io_uring_cqe *cqe;
    uint64_t             counter;
    ssize_t              n;

    /* 1. drain the eventfd counter — same first step as core's handler. */
    n = read(u->eventfd, &counter, sizeof(counter));
    if (n != (ssize_t) sizeof(counter)) {
        if (n == -1 && (errno == EAGAIN || errno == EINTR)) {
            return;                            /* spurious wakeup */
        }
        /* a real eventfd error: log once, leave the ring; pool still works */
        ngx_log_error(NGX_LOG_ALERT, evc->log, errno,
                      "xrootd: io_uring eventfd read() failed");
        return;
    }

    /* 2. harvest. peek (non-blocking) until the CQ is empty. */
    while (io_uring_peek_cqe(&u->ring, &cqe) == 0) {
        uint64_t             ud   = io_uring_cqe_get_data64(cqe);
        uint32_t             idx  = (uint32_t) (ud & 0xffffffffu);
        uint32_t             gen  = (uint32_t) (ud >> 32);
        xrootd_uring_slot_t *slot = xrootd_uring_slot_at(u, idx);

        /* 2a. generation guard: stale CQE for a recycled slot → drop. */
        if (slot == NULL || !slot->in_use || slot->generation != gen) {
            io_uring_cqe_seen(&u->ring, cqe);
            if (u->inflight > 0) u->inflight--;
            continue;
        }

        /* 2b. translate cqe->res into the task's OUT fields (per op_kind),
         *     accumulating multi-CQE chains (writev+fsync). Returns 1 when
         *     this was the chain's final CQE (ready to post). */
        if (xrootd_uring_apply_cqe(u, slot, cqe)) {
            ngx_thread_task_t *task = slot->task;
            task->event.complete = 1;          /* matches core's e->complete */
            ngx_post_event(&task->event, &ngx_posted_events);
            xrootd_uring_slot_release(u, idx); /* in_use=0, generation++ */
        }

        io_uring_cqe_seen(&u->ring, cqe);
        if (u->inflight > 0) u->inflight--;
    }
}
```

`io_uring_peek_cqe` is substituted for core's `io_getevents`; the `ngx_post_event(..., &ngx_posted_events)` pattern is identical, including setting `task->event.complete = 1` to match how core marks `e->complete`. `io_uring_for_each_cqe` + a single `io_uring_cq_advance(n)` is a valid faster variant; the `peek`/`seen` form is shown for clarity and is what the cookbook above assumes for slot release ordering.

### 11.2 Why post to `ngx_posted_events` instead of dispatching inline

The reaper **does not** call `slot->done_fn` from inside the harvest loop. Reason: re-entrancy. A done-callback for a windowed read (`xrootd_read_aio_done` → `xrootd_read_window_pump`, `src/aio/reads.c`) **re-submits the next window's SQE** via `xrootd_aio_post_task` → `xrootd_uring_submit` → `io_uring_get_sqe`/`io_uring_submit`. Calling that from inside the harvest loop would mutate the ring's SQ (and `inflight`) while we are iterating the CQ — exactly the footgun core avoids by deferring to `ngx_posted_events`. Posting instead means:
- The harvest loop only reads the CQ and bumps counters; it never touches the SQ.
- nginx's posted-events drain (which already runs after `ngx_process_events`) invokes each done-callback on a clean stack, where a re-submit is just an ordinary `xrootd_aio_post_task` call — the same as the thread-pool path.

This is the §A.2 decision: reuse the core queue; it is both less code and the only re-entrancy-safe option for the window pump.

### 11.3 Slot decode + generation validation

`user_data = (generation << 32) | slot_index`. Decode splits it; `xrootd_uring_slot_at(u, idx)` bounds-checks the index against the slot table size. Validation drops the CQE if the slot is free (`!in_use`) or its `generation` no longer matches — the case where the connection was torn down, the slot freed and reused, and a late CQE arrives for the previous occupant. This guards the **ring slot**. The done-callback's own `xrootd_aio_restore_stream/request()` + `ctx->destroyed` check (`src/aio/resume.c`) remains the authoritative guard for the **connection**. Both layers are retained — the slot generation protects the reaper from dereferencing a recycled `ngx_thread_task_t`; the `ctx->destroyed` guard protects the protocol code from acting on a dead connection. A stale CQE still decrements `inflight` so accounting stays balanced.

### 11.4 Inflight accounting

`inflight` counts SQEs submitted but not yet reaped (per worker, single-threaded — no atomics). `xrootd_uring_submit` does `inflight += sqe_count(op)` (1, or 2 for writev+fsync). The reaper does `inflight--` per CQE consumed, including dropped stale CQEs and each CQE of a multi-SQE chain. The selector gate `inflight < queue_depth` is the ring-depth backpressure; when the ring is full, ops fall to the pool (§10.7). The windowed-read pump posts exactly one window SQE at a time, so a single connection contributes at most depth 1 from reads and can never alone exhaust the ring (§A.7).

### 11.5 SQPOLL as a later tier

A future tier sets `IORING_SETUP_SQPOLL` in `io_uring_queue_init_params`, giving a kernel poller thread that submits SQEs without an `io_uring_submit` syscall. Costs and constraints to document, not implement now:
- A dedicated kernel thread per ring (CPU cost; pin via `IORING_SETUP_SQ_AFF`).
- Requires registered files (`IORING_REGISTER_FILES`) and possibly `CAP_SYS_NICE` on older kernels.
- Submission still calls `io_uring_submit` (it becomes a cheap "wake the poller if idle" check), so the submit cookbook is unchanged.
- The eventfd completion path is unchanged.
Deferred behind the same probe/off-by-default gating as the base ring.

### 11.6 Interaction with windowed reads, budget, and the warm-cache probe

- **Windowed reads:** one SQE per window. The done-callback `xrootd_read_aio_done` re-pumps (`xrootd_read_window_pump`) on the posted-event stack, submitting the next window. Ring depth from a single windowed read stays at 1. This is the re-entrancy case §11.2 exists for.
- **Budget:** `xrootd_budget_admit`/`xrootd_budget_sync` run inline **before** dispatch, unchanged. A budget-deferred read still emits `kXR_wait` before any SQE is built. io_uring reads into the same scratch buffers, so heap-footprint accounting is identical (§A.7).
- **Warm-cache probe:** composes in front of the ring (§10.8): hit → inline sync, miss → uring. The reaper is only reached on the miss path.

### 11.7 UAF / teardown discipline

- **In-flight op when the connection drops:** the CQE still arrives later. The slot's `task->event` is still posted, the done-callback runs, and `xrootd_aio_restore_stream` sees `ctx->destroyed` and returns 0 → the callback touches nothing further (and, for writes, still frees the detached payload). The slot generation prevents a *recycled* slot from being mis-decoded. Two independent guards, as in the thread-pool model.
- **Worker exit:** `xrootd_exit_process` drains the ring before freeing it: `ngx_del_event(evc->read, NGX_READ_EVENT, 0)`, `ngx_close_connection(evc)`, then `io_uring_unregister_eventfd`, `io_uring_queue_exit(&u->ring)`, `close(u->eventfd)`. `io_uring_queue_exit` waits for / discards in-flight ops; any not-yet-reaped CQEs are abandoned with the ring — safe because their tasks are pool-allocated on connections being torn down at process exit. If a graceful "drain to `inflight == 0` before exit" is desired (so the ring fd disappears only when quiet), spin the posted-events drain until `inflight == 0` first (noted in §A.1 / §9).
- **Detached write payload:** `payload_to_free` (`xrootd_write_aio_t`) / `payload_buf` (`xrootd_writev_aio_t`) is the SQE's source buffer and is freed **only** in the post-CQE done-callback (`xrootd_write_aio_done` / `xrootd_writev_write_aio_done`, `src/aio/write.c`), which by construction runs after the CQE. The in-flight `IORING_OP_WRITE`/`WRITEV` therefore always reads live memory. This is the exact §A.4 lifetime guarantee, restated for the ring.

### 11.8 End-to-end sequence for a single `kXR_read`

1. **Handler / pump.** `xrootd_read_window_pump` (`src/aio/reads.c`) allocates `read_scratch`, runs `xrootd_budget_sync`, runs the phase-32 `preadv2(RWF_NOWAIT)` probe → miss.
2. **Selector.** It binds the cached `read_aio_task` to `xrootd_read_aio_thread`/`xrootd_read_aio_done` and calls `xrootd_aio_post_task`. The selector picks Tier 1: `xrootd_uring_op_for` → `OP_READ`, `inflight < queue_depth`, kill switch clear.
3. **Submit.** `xrootd_uring_submit` acquires slot `idx` (generation `g`), `io_uring_get_sqe`, `io_uring_prep_read(sqe, fd, databuf, rlen, offset)`, `io_uring_sqe_set_data64(sqe, (g<<32)|idx)`, `io_uring_submit`, `inflight++`, `*posted=1`. Selector sets `ctx->state = XRD_ST_AIO`; the pump returns.
4. **Kernel + eventfd.** Disk read completes; io_uring posts a CQE and signals the registered eventfd; epoll wakes the worker; `evc->read` is readable → `xrootd_uring_eventfd_handler` fires.
5. **Reaper.** Reads/drains the eventfd counter; `io_uring_peek_cqe`; decodes `idx`/`g`; generation matches; `xrootd_uring_apply_cqe` sets `t->nread = cqe->res` (or `t->io_errno = -cqe->res`, `t->nread = -1`); `task->event.complete = 1`; `ngx_post_event(&task->event, &ngx_posted_events)`; `xrootd_uring_slot_release` (generation++); `io_uring_cqe_seen`; `inflight--`.
6. **Posted-event drain.** After `ngx_process_events`, nginx drains `ngx_posted_events` and calls `xrootd_read_aio_done(&task->event)`.
7. **Done-callback.** `xrootd_aio_restore_stream` (checks `ctx->destroyed`); if `rd_win_active`, `xrootd_read_window_emit` queues the chunk; on a hard error (`t->nread < 0`) it emits `kXR_IOError`; otherwise it advances `rd_win_remaining`.
8. **Re-pump or resume.** If more windows remain and the send completed synchronously, the callback calls `xrootd_read_window_pump` again — a fresh `xrootd_aio_post_task` → new SQE (re-entrancy-safe because we are on the posted-event stack, not inside the harvest loop). If `XRD_ST_SENDING`, `src/connection/send.c` re-enters the pump on drain. When the windowed read finishes, `xrootd_aio_resume` re-arms the read/write event for the next request.

---

## 12. Client disk-ring deep design

This section specifies the `xrdc_disk_ring` object (`client/lib/uring.c`/`uring.h`), the two pump adapters that wrap it (`pump_src_local_uring`, `pump_sink_local_uring`), and the exact way they preserve the `transfer_pump` contract from `client/lib/copy.c`. It realizes **Option A (ship)**: adapter-internal pipelining behind an unchanged synchronous one-chunk face.

### 12.1 Object model and ownership

The ring is opaque to every caller (the type is forward-declared in `xrdc.h`; the full struct lives only in `uring.c`). It owns a registered-buffer pool, a fixed slot table tracking in-flight ops, and a sequence cursor that enforces in-order release. It does not know about sockets, `xrdc_conn`, or the pump — it presents only checkout/submit/reap primitives.

```c
/* uring.c — private. WHAT: deep-queue local-disk ring with a registered-buffer
 * pool and in-order completion release. WHY: let disk I/O overlap network I/O
 * while keeping the pump's synchronous one-chunk contract. HOW: depth SQEs in
 * flight over IORING_REGISTER_BUFFERS slabs; release op k only after op k's CQE. */
typedef enum { SLOT_FREE, SLOT_INFLIGHT, SLOT_DONE } slot_state;

typedef struct {
    slot_state  state;
    uint32_t    seq;        /* monotonic op sequence; defines release order */
    uint16_t    buf_index;  /* index into registered iovec table          */
    int64_t     off;        /* file offset of this op                       */
    size_t      len;        /* bytes requested                             */
    int32_t     res;        /* cqe->res once SLOT_DONE (>=0 bytes, <0 -errno)*/
} ring_slot;

struct xrdc_disk_ring {
    struct io_uring  ring;          /* liburing queue                        */
    int              fd;            /* the local file (registered if fixed)  */
    int              fixed_fd;      /* 1 => use IOSQE_FIXED_FILE, fd index 0  */
    int              direct;        /* O_DIRECT tier active                  */
    unsigned         depth;         /* max SQEs in flight (== nbuf)          */
    unsigned         nbuf;          /* registered buffers                    */
    size_t           bufsz;         /* per-buffer size (>= XRDC_COPY_CHUNK)   */
    size_t           align;         /* O_DIRECT alignment (logical block)    */
    uint8_t         *slab;          /* posix_memalign'd backing for all bufs */
    struct iovec    *iov;           /* nbuf iovecs into slab (registered)    */
    ring_slot       *slots;         /* nbuf slots                            */
    uint32_t         next_seq;      /* next sequence to assign on submit     */
    uint32_t         release_seq;   /* next sequence the pump may consume    */
    unsigned         inflight;      /* SLOT_INFLIGHT count                   */
    int              eof_seq_valid; /* a 0-length completion was observed    */
    uint32_t         eof_seq;       /* sequence at which EOF was seen        */
};
```

Buffer ownership is strict and single-writer (the pump's calling thread; the disk ring is never shared across threads): a slot/buffer is **checked out at submit** (state `FREE`→`INFLIGHT`, `buf_index` bound) and **returned at CQE reap** (state `INFLIGHT`→`DONE`, then `DONE`→`FREE` once the pump consumes that sequence). No buffer is ever touched by two ops at once because `nbuf == depth`: a free buffer exists iff a free slot exists.

### 12.2 Lifecycle: create with unwind ladder

`xrdc_disk_ring_create(int fd, unsigned depth, unsigned nbuf, size_t bufsz, int direct, xrdc_status *st)` follows the project's no-`goto` rule, mirroring `xrdc_loop_create` / `xrdc_loop_create_fail` (`client/lib/aio.c`). Acquisition is staged; every fallible step that fails returns through `xrdc_disk_ring_create_fail`, which frees exactly what was acquired (all pointers start NULL/-1, all registrations tracked by booleans).

```c
/* WHAT: tear down a partially-built ring; return NULL. WHY: create() acquires
 * ring queue, slab, iov table, slot table, and two kernel registrations in
 * sequence — any can fail. HOW: free in reverse, guarded; mirror
 * xrdc_loop_create_fail's flat-return discipline (no goto). */
static xrdc_disk_ring *
xrdc_disk_ring_create_fail(xrdc_disk_ring *r)
{
    if (r->bufs_registered) io_uring_unregister_buffers(&r->ring);
    if (r->file_registered) io_uring_unregister_files(&r->ring);
    if (r->ring_inited)     io_uring_queue_exit(&r->ring);
    free(r->slots);
    free(r->iov);
    free(r->slab);    /* posix_memalign block freed with free() */
    free(r);
    return NULL;
}
```

Create sequence (each `!= 0` / NULL hop returns `xrdc_disk_ring_create_fail(r)` after setting `st`):

1. `calloc` the object; if NULL → `XRDC_EPROTO` "out of memory (disk ring)". Set `fd`, `direct`, `depth`, `nbuf`, `bufsz`.
2. Derive `align`: if `direct`, query the file's logical block size (`ioctl(fd, BLKSSZGET)` on block devices, else `fstatvfs`/`st_blksize`, clamped to a 512..4096 power-of-two; fall back to 4096). Round `bufsz` up to a multiple of `align`.
3. `io_uring_queue_init(depth, &r->ring, 0)` → sets `ring_inited`. Failure → `XRDC_ESOCK`-class status with `-ret` (liburing returns `-errno`).
4. `posix_memalign((void**)&r->slab, r->align, (size_t)nbuf * r->bufsz)` (plain `malloc` when `!direct`, but `posix_memalign` is harmless and keeps one path). Failure → free path.
5. Allocate `r->iov` (`nbuf` iovecs), point each at `slab + i*bufsz` with `iov_len = bufsz`.
6. `io_uring_register_buffers(&r->ring, r->iov, nbuf)` → `bufs_registered`. This is `IORING_REGISTER_BUFFERS`: it pins the slab once so each `IORING_OP_READ_FIXED`/`WRITE_FIXED` skips per-op page mapping.
7. **Register the file (fixed fd):** `io_uring_register_files(&r->ring, &r->fd, 1)` → `file_registered`, `fixed_fd=1`. Ops then use `IOSQE_FIXED_FILE` with file index `0`, avoiding per-SQE fget/fput. If registration is unsupported, clear `fixed_fd` and submit with the raw `fd` — non-fatal, logged once.
8. `calloc` `r->slots` (`nbuf`), all `SLOT_FREE`; `next_seq = release_seq = 0`; `inflight = 0`.

`xrdc_disk_ring_destroy(r)` (see 12.7) **drains all in-flight ops first**, then unregisters buffers/files and `io_uring_queue_exit`, then frees — same teardown order as the fail ladder, reused.

### 12.3 Core primitives

```c
/* Checkout a free slot+buffer; -1 if pool exhausted (caller must reap first). */
static int ring_checkout(xrdc_disk_ring *r);          /* returns slot idx or -1 */
/* Submit a READ_FIXED at off for up to bufsz bytes on slot s. */
static int ring_submit_read(xrdc_disk_ring *r, int s, int64_t off, size_t len);
/* Submit a WRITE_FIXED of n bytes (already in slot s's buffer) at off. */
static int ring_submit_write(xrdc_disk_ring *r, int s, int64_t off, size_t n);
/* Block until >=1 CQE; mark its slot SLOT_DONE with cqe->res. Returns 0/-errno. */
static int ring_reap_one(xrdc_disk_ring *r, int wait);
/* The lowest-sequence slot if it is SLOT_DONE, else -1 (out-of-order pending). */
static int ring_ready_in_order(xrdc_disk_ring *r);
```

`user_data` carries the slot index (`io_uring_sqe_set_data64(sqe, slot_idx)`); the slot's `seq` field carries ordering. On reap, `io_uring_wait_cqe`/`io_uring_peek_cqe` yields the CQE; `slot = io_uring_cqe_get_data64(cqe)`; `r->slots[slot].res = cqe->res; r->slots[slot].state = SLOT_DONE; r->inflight--; io_uring_cqe_seen(...)`. A `cqe->res == 0` on a read marks `eof_seq_valid` with that slot's `seq` (12.6). Because there is one ring per transfer on one thread, no generation stamp is needed here (that is a transport-engine concern, §13).

### 12.4 Read-ahead window state machine (upload source: `pump_src_local_uring`)

The pump asks for one chunk per call: `src(ctx, buf, off, cap, st)` returns bytes-or-0-or-(-1) and the pump immediately hands them to the (remote) sink. The adapter keeps up to `depth` reads ahead of the pump's cursor so that, while the network write of chunk *k* is in flight, disk reads for *k+1..k+depth* are already running.

Context: `pump_localring_t { xrdc_disk_ring *r; int fd; int64_t pos; }` — `pos` is the next disk offset to *submit* (distinct from the pump's `off`, the next sequence to *consume*).

```c
/* WHAT: synchronous one-chunk source backed by a depth-deep read-ahead ring.
 * WHY:  overlap disk reads with the network writes the pump issues between calls.
 * HOW:  top up the in-flight window to min(depth, free slots), then reap until
 *       the lowest-sequence op is SLOT_DONE, memcpy it into the pump's buf,
 *       release the slot, and return its byte count. EOF = a 0-length read. */
static ssize_t
pump_src_local_uring(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                     xrdc_status *st)
{
    pump_localring_t *p = ctx; xrdc_disk_ring *r = p->r;
    (void) off;                          /* sequential; ring tracks disk pos   */

    if (r->eof_drained && r->inflight == 0 && !ring_any_done(r))
        return 0;                        /* fully drained EOF                   */

    /* 1. FILL: keep the read-ahead window full. */
    while (r->inflight < r->depth && !r->eof_submitted) {
        int s = ring_checkout(r);
        if (s < 0) break;                /* pool exhausted -> backpressure      */
        size_t len = (cap < r->bufsz) ? cap : r->bufsz;
        if (ring_submit_read(r, s, p->pos, len) != 0) { ring_return(r, s); break; }
        r->slots[s].seq = r->next_seq++;
        p->pos += len;                   /* speculative; corrected at short/EOF */
    }
    io_uring_submit(&r->ring);

    /* 2. DRAIN IN ORDER: wait for the lowest-sequence op. */
    for (;;) {
        int s = ring_ready_in_order(r);          /* slot with seq==release_seq  */
        if (s >= 0) {
            int32_t res = r->slots[s].res;
            if (res < 0) {                        /* error propagation          */
                xrdc_status_set(st, XRDC_ESOCK, -res, "uring read: %s",
                                strerror(-res));
                return -1;
            }
            if (res == 0) { r->eof_submitted = r->eof_drained = 1;
                            ring_return(r, s); r->release_seq++; return 0; }
            memcpy(buf, r->iov[r->slots[s].buf_index].iov_base, (size_t) res);
            if ((size_t) res < r->slots[s].len) {  /* short read: rewind pos    */
                p->pos = r->slots[s].off + res;    /* drop speculative reads     */
                ring_abandon_after(r, r->slots[s].seq);  /* cancel/ignore later  */
                r->eof_submitted = 1;              /* treat as last full op      */
            }
            ring_return(r, s); r->release_seq++;
            return res;
        }
        if (r->inflight == 0) return 0;            /* nothing left, no done op   */
        if (ring_reap_one(r, /*wait=*/1) != 0) {   /* block for a CQE            */
            xrdc_status_set(st, XRDC_ESOCK, 0, "uring reap failed");
            return -1;
        }
    }
}
```

State transitions per call: **FILL** (checkout→submit, `FREE`→`INFLIGHT`) bounded by `depth` and by `ring_checkout` returning -1 (pool exhausted = natural backpressure: the pump cannot run ahead of buffers). **DRAIN** blocks only when the head-of-line sequence is not yet `DONE`. Out-of-order CQEs are stored (`SLOT_DONE`) but **not released** until `release_seq` reaches them — guaranteeing the upload streams bytes in file order. A short read sets the EOF latch and rewinds `pos` so speculative over-reads past EOF are abandoned rather than streamed.

### 12.5 Write-behind window state machine (download sink: `pump_sink_local_uring`)

The download sink is handed one chunk by the pump and must persist it. The adapter copies the chunk into a registered buffer, issues a `WRITE_FIXED`, and returns immediately while the write drains in the background — *until* the window is full, at which point it blocks for the oldest write to retire before accepting the next chunk. In-order is naturally satisfied because the pump feeds chunks in order and offsets are explicit.

```c
/* WHAT: synchronous one-chunk sink backed by a depth-deep write-behind ring.
 * WHY:  let the next network read proceed while this disk write is in flight.
 * HOW:  copy caller bytes into a registered buf, submit WRITE_FIXED at off,
 *       and only block when the window is full or a prior write errored. */
static int
pump_sink_local_uring(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                      xrdc_status *st)
{
    pump_localring_t *p = ctx; xrdc_disk_ring *r = p->r;

    /* 1. Reap any completed writes first; surface their errors immediately. */
    while (ring_any_done(r)) {
        int s = ring_oldest_done(r); int32_t res = r->slots[s].res;
        if (res < 0) { xrdc_status_set(st, XRDC_ESOCK, -res, "uring write: %s",
                                       strerror(-res)); return -1; }
        if ((size_t) res < r->slots[s].len) {     /* short write -> error       */
            xrdc_status_set(st, XRDC_EPROTO, 0, "uring short write %d/%zu",
                            res, r->slots[s].len); return -1; }
        ring_return(r, s);
    }

    /* 2. BACKPRESSURE: if no free buffer, block for the oldest write to retire. */
    int s = ring_checkout(r);
    while (s < 0) {
        if (ring_reap_one(r, 1) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, 0, "uring reap failed"); return -1; }
        /* re-check the just-completed write for error before reusing it */
        int d = ring_oldest_done(r);
        if (d >= 0 && r->slots[d].res < 0) {
            xrdc_status_set(st, XRDC_ESOCK, -r->slots[d].res, "uring write: %s",
                            strerror(-r->slots[d].res)); return -1; }
        s = ring_checkout(r);
    }

    /* 3. memcpy into the registered buffer (the accepted single copy) + submit. */
    memcpy(r->iov[r->slots[s].buf_index].iov_base, buf, n);
    if (ring_submit_write(r, s, off, n) != 0) {
        ring_return(r, s);
        xrdc_status_set(st, XRDC_ESOCK, errno, "uring submit write"); return -1; }
    r->slots[s].seq = r->next_seq++;
    io_uring_submit(&r->ring);
    return 0;                                   /* write is now in flight       */
}
```

Because the sink returns before the write completes, the **download path must flush before declaring success**: `copy_download` calls a new `xrdc_disk_ring_drain(r, st)` after `transfer_pump` returns 0 but before the atomic `rename` of the temp file. `drain` reaps every remaining `INFLIGHT`/`DONE` slot, checking each `res` for error/short-write; only a fully clean drain permits the rename. The temp+rename discipline in `copy_download` is otherwise untouched.

### 12.6 EOF, short-IO, error, and in-order release summary

- **EOF (source):** a read CQE with `res == 0` is EOF (kernel returns 0 at/after end-of-file). The adapter latches `eof_submitted`/`eof_drained`, returns 0 to the pump, and the pump's `expected < 0` branch treats 0 as clean end (`copy.c:transfer_pump`). For a sized download the pump itself flags a short read if 0 arrives early — unchanged.
- **Short read (source):** `res < requested` rewinds `pos`, abandons speculative reads beyond it, and latches EOF after delivering the partial chunk. The pump's known-size short-read error still fires if bytes fall short of `expected`.
- **Short write (sink):** `res < len` is a hard error (`XRDC_EPROTO` "short write"), parity with `write_all` in `copy.c`.
- **Error (`cqe->res < 0`):** translated to `-errno` and surfaced through `xrdc_status_set` exactly where the synchronous adapters set status — so the pump's `n < 0` / `sink != 0` branches break the loop and the caller drops the partial, byte-identical to today.
- **In-order release:** the source releases strictly by `release_seq`; the sink writes at explicit offsets so out-of-order completion is harmless, but errors from *any* completed write are surfaced before the next chunk is accepted, so a failed chunk *k* cannot be masked by a later success.

### 12.7 Drain-before-destroy and buffer lifecycle

`xrdc_disk_ring_destroy` must not free the slab while the kernel still owns pinned buffers for in-flight ops. It therefore loops `ring_reap_one(r, 1)` until `inflight == 0` (discarding results — at destroy time the transfer already succeeded or failed), then `io_uring_unregister_buffers`, `io_uring_unregister_files`, `io_uring_queue_exit`, and finally frees `slab`/`iov`/`slots`. This is the same ordering as `xrdc_disk_ring_create_fail`, reused. The invariant: a registered buffer is live exactly from `ring_checkout` to the matching `io_uring_cqe_seen`; destroy waits out that window for every slot.

### 12.8 O_DIRECT tier mechanics and tail fallback

`direct` is an opt-in per-invocation tier (`xrdc_copy_opts.io_uring` on plus a direct sub-flag, default off). When active:

- The file is opened `O_DIRECT` by the caller (download temp, upload source); the ring records `align`.
- `slab` is `posix_memalign`-aligned to `align`; offsets submitted to `ring_submit_read/write` are already `align`-multiples for all but the final chunk because `bufsz` is `align`-rounded and the pump advances by full chunks.
- **Unaligned tail fallback:** the final write whose length or offset is not `align`-aligned cannot go through `O_DIRECT`. The sink detects `(off % align) || (n % align)` and performs a one-shot **buffered** `pwrite` on a dup'd non-`O_DIRECT` fd (opened lazily on first tail), bypassing the ring for that single op. Reads of a short final block similarly fall back to a buffered `pread`. The ring then drains; the tail op is synchronous and ordered after all queued ops by construction (it is the last op).
- O_DIRECT is never automatic: it wins for large sequential NVMe transfers and loses for small/cached ones, so it is gated entirely by explicit opt-in.

### 12.9 Where the choice is made

The adapter swap happens in exactly two functions in `copy.c`, with no change to `transfer_pump` or any remote adapter:

```
/* copy_download: remote source -> local sink */
int use_ring = (o && o->io_uring != 2) && xrdc_uring_available()
               && (o->io_uring == 1 || /* auto heuristic: file size >= threshold */);
if (use_ring) {
    pump_localring_t lr; xrdc_disk_ring *r =
        xrdc_disk_ring_create(outfd, depth, nbuf, XRDC_COPY_CHUNK, o->direct, st);
    if (r) { lr.r = r; lr.fd = outfd; lr.pos = 0;
             rc = transfer_pump(pump_src_remote, &src,
                                pump_sink_local_uring, &lr, si->size, o, ..., st);
             if (rc == 0) rc = xrdc_disk_ring_drain(r, st);
             xrdc_disk_ring_destroy(r);
    } else  rc = /* fall back: pump_sink_local */;
}
```

`copy_upload` is symmetric: source becomes `pump_src_local_uring` (over `infd`), sink stays `pump_sink_remote`. The tri-state `xrdc_copy_opts.io_uring` (0=auto, 1=on, 2=off) plus the memoized `xrdc_uring_available()` probe (real `io_uring_queue_init` + `io_uring_get_probe` for `READ`/`WRITE`/`READ_FIXED`/`WRITE_FIXED`, not a `uname` parse) gate selection; any `create` failure or `available()==0` silently uses the existing `pump_src_local`/`pump_sink_local` path.

### 12.10 Option B (pump-bypass) — deferred, with rationale

Option B would add dedicated `copy_download_uring` / `copy_upload_uring` paths fusing the ring directly with `xrdc_file_read`/`xrdc_file_write`, eliminating the single memcpy by reading the network straight into a registered buffer and writing it straight to disk. It is **deferred**: it duplicates the pump's tested cancel (`g_xrdc_copy_quit`), progress-callback, short-read, and known-vs-EOF-length discipline (`copy.c:transfer_pump`), doubling the surface that must stay byte-exact across the parity matrix. Option A buys the entire disk⇄network overlap for the cost of one memcpy per chunk and zero new control flow. Ship A; revisit B only if profiling shows the memcpy is material at NVMe line rate.

### 12.11 Reused vs untouched

| Component | Status under disk-ring |
|---|---|
| `transfer_pump` (`copy.c`) | **Untouched** — same synchronous one-chunk contract |
| `pump_src_remote` / `pump_sink_remote` | **Untouched** — remote adapters unaware of the ring |
| `pump_src_local` / `pump_sink_local` / `write_all` | **Untouched** — the fallback path |
| `XRDC_COPY_CHUNK` (8 MiB) | **Reused** as `bufsz` baseline (rounded up for O_DIRECT) |
| Atomic temp+rename on download | **Reused**; rename gated behind `xrdc_disk_ring_drain` |
| Cancel / progress / short-read discipline | **Reused** — lives entirely in the pump |
| `xrdc_copy_opts` | **Extended** by `io_uring` tri-state + `direct` (no new globals) |
| `pump_src_local_uring` / `pump_sink_local_uring` / `xrdc_disk_ring` | **New**, in `uring.c` + two adapters in `copy.c` |

### 12.12 Tests (3 per feature)

- **Disk source pipelining:** (1) byte-exact upload of multi-chunk file matches `pump_src_local` SHA256; (2) short final chunk and exact-`bufsz` boundary handled; (3) injected `cqe->res<0` on read produces the same `xrdc_status` as a synchronous read error.
- **Disk sink write-behind:** (1) byte-exact download (incl. drain-before-rename) matches; (2) ENOSPC mid-window surfaces as `kXR_IOError`-equivalent and aborts the rename; (3) full-window backpressure (low `depth`) transfers correctly with no dropped chunk.
- **O_DIRECT tier:** (1) aligned large transfer byte-exact vs buffered; (2) unaligned tail falls back and matches; (3) `posix_memalign`/alignment failure degrades to buffered ring without data loss.

---

## 13. Client event-loop engine deep design

This section specifies the engine vtable that lets the epoll loop (`client/lib/aio.c`) and an io_uring loop coexist in one binary, selected at `xrdc_loop_create`. The default is **OFF**. It ships in two graded sub-options: **(ii-a)** `IORING_OP_POLL_ADD` multishot (drop-in readiness, TLS-safe) first, then **(ii-b)** cleartext-only `IORING_OP_RECV`/`SEND` multishot with provided buffers for `ac->ssl == NULL`.

### 13.1 The engine vtable

A small internal vtable abstracts the four things the loop does to the kernel: arm interest, wait for events, wake cross-thread, and cancel a connection's interest. Create/destroy bracket them. The vtable is selected once at loop creation; every other line of `aio.c` (parse, reconnect, ping, command queue, `aconn_do_read`/`aconn_do_write`) is engine-agnostic.

```c
/* aio.c — internal. WHAT: pluggable readiness/completion engine. WHY: keep
 * epoll and io_uring side-by-side without forking the loop. HOW: a vtable
 * chosen at xrdc_loop_create; epoll impl == today's code verbatim. */
typedef struct {
    int  (*create)(xrdc_loop *l, xrdc_status *st);     /* epfd|ring + wakeup  */
    void (*destroy)(xrdc_loop *l);
    void (*arm)(xrdc_aconn *ac, int want);             /* EPOLLIN|EPOLLOUT    */
    int  (*wait)(xrdc_loop *l, int timeout_ms,         /* fills ev[]          */
                 engine_ev *ev, int maxev);
    void (*wake)(xrdc_loop *l);                        /* cross-thread kick   */
    void (*cancel)(xrdc_aconn *ac);                    /* drop fd's interest  */
} engine_vtbl;

typedef struct { void *ptr; uint32_t events; } engine_ev;  /* ac* or loop*   */

struct xrdc_loop {                  /* extended */
    const engine_vtbl *eng;
    int     epfd;                   /* epoll engine                          */
    struct io_uring ring;           /* io_uring engine                       */
    int     ring_inited;
    int     evfd;                   /* shared wakeup eventfd (both engines)  */
    /* ... existing fields ... */
};
```

`engine_ev` decouples the loop body from raw `struct epoll_event` so the same `for` loop dispatches both engines: `ptr == l` → eventfd wakeup; else `aconn_handle_io((xrdc_aconn*)ptr, ev[i].events)` — exactly as `loop_thread` does today (`aio.c:loop_thread`).

### 13.2 Epoll impl — maps 1:1 to today's code

The epoll vtable is a thin renaming of existing functions; zero behavior change:

| vtable slot | Existing code |
|---|---|
| `create` | `epoll_create1(EPOLL_CLOEXEC)` + `eventfd` + `epoll_ctl(ADD, evfd)` — the body of `xrdc_loop_create`, unwound via `xrdc_loop_create_fail` |
| `arm` | `aconn_update_epoll(ac)` — computes `want` from `wbuf`/`tls_want_*`, `epoll_ctl(MOD)` |
| `wait` | `epoll_wait(l->epfd, ev, AIO_MAXEV, timeout)`, batch 64 (`AIO_MAXEV`) |
| `wake` | writer side: `write(l->evfd, &one, 8)`; reader side: `read(l->evfd,...)` on the `ptr==l` event |
| `cancel` | `epoll_ctl(EPOLL_CTL_DEL, ac->fd, NULL)` — the body of `aconn_on_transport_error`'s DEL |
| `destroy` | `close(epfd)`, `close(evfd)` |

`engine_ev.events` carries the epoll bitmask unchanged (`EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP`), so `aconn_handle_io` (`aio.c`) is untouched.

### 13.3 io_uring impl — POLL_ADD multishot (sub-option ii-a)

The io_uring `create` does `io_uring_queue_init(depth, &l->ring, 0)` (unwound by an extended `xrdc_loop_create_fail` that also `io_uring_queue_exit`s when `ring_inited`), then arranges wakeup (13.5). `arm`, `wait`, `cancel` differ:

**`arm(ac, want)` — multishot POLL_ADD.** Instead of `epoll_ctl(MOD)`, submit a *multishot* poll that fires a CQE on every readiness edge until cancelled:

```c
/* WHAT: arm/re-arm readiness for one aconn via multishot IORING_OP_POLL_ADD.
 * WHY:  drop-in for aconn_update_epoll; loop still runs aconn_do_read/write,
 *       so SSL_read/SSL_write keep doing their own fd syscalls -> TLS-safe.
 * HOW:  one multishot poll per aconn; POLLIN always, POLLOUT iff wbuf pending. */
static void
engine_uring_arm(xrdc_aconn *ac, int want)
{
    unsigned mask = POLLIN;
    if (ac->wbuf.start < ac->wbuf.len || ac->tls_want_write_on_read)
        mask |= POLLOUT;
    if (mask == ac->poll_mask && ac->poll_armed) return;   /* no change       */
    if (ac->poll_armed) engine_uring_cancel(ac);           /* re-arm: cancel   */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ac->loop->ring);
    io_uring_prep_poll_multishot(sqe, ac->fd, mask);
    io_uring_sqe_set_data64(sqe, UD(ac->slot_idx, ac->fd_gen));   /* §13.6     */
    io_uring_submit(&ac->loop->ring);
    ac->poll_mask = mask; ac->poll_armed = 1;
}
```

**`wait(l, timeout, ev, maxev)`** uses `io_uring_wait_cqe_timeout(&l->ring, &cqe, &ts)`; then `io_uring_for_each_cqe` drains the batch. Each CQE is decoded: `slot,gen = UD(cqe->user_data)`; validate `gen == ac->fd_gen` (§13.6) else drop; translate `cqe->res` (a poll mask) into `engine_ev.events` by mapping `POLLIN→EPOLLIN`, `POLLOUT→EPOLLOUT`, `POLLERR→EPOLLERR`, `POLLHUP→EPOLLHUP`. The wakeup eventfd CQE maps to `ptr == l`. `io_uring_cqe_seen` retires each.

**Multishot rearm lifecycle.** A multishot poll persists across edges, so no per-edge re-arm is needed — *except*:

- If a CQE lacks `IORING_CQE_F_MORE` (kernel dropped the multishot, e.g. on certain errors), the engine must re-submit: detect `!(cqe->flags & IORING_CQE_F_MORE)` and re-arm with the current `poll_mask`.
- When `want` changes (POLLOUT needed/no-longer-needed because `wbuf` filled/drained), `arm` cancels the existing multishot and submits a new one with the updated mask. This is the io_uring analogue of `aconn_update_epoll`'s `EPOLL_CTL_MOD` early-return-on-no-change.

Because the loop still calls `aconn_do_read`/`aconn_do_write` on each readiness edge (`aconn_handle_io`), `SSL_read`/`SSL_write` keep issuing their own `recv`/`send` syscalls. POLL_ADD only tells the loop *when* the fd is ready; it never moves bytes. This is what makes ii-a TLS-safe and the smallest possible diff — the entire resilience path (reconnect, parked retry, RTT EWMA, keepalive) is byte-for-byte preserved.

### 13.4 io_uring impl — cleartext RECV/SEND multishot + provided buffers (sub-option ii-b)

For `ac->ssl == NULL`, ii-b replaces readiness-then-syscall with true async transfers, removing the readiness syscall entirely:

- **Provided-buffer ring (buffer group):** the loop registers a pool of receive buffers via `io_uring_register_buf_ring` under a buffer group id `BGID_RX`. A **multishot** `IORING_OP_RECV` (`io_uring_prep_recv_multishot`, `IOSQE_BUFFER_SELECT`, `buf_group = BGID_RX`) is armed once per cleartext aconn. Each inbound segment completes as a CQE whose `cqe->flags` encodes the chosen buffer id (`IORING_CQE_F_BUFFER`); the engine locates that buffer, copies/append its `cqe->res` bytes into `ac->rbuf` (the same buffer `aconn_do_read` fills today), then **recycles** the provided buffer back into the ring (`io_uring_buf_ring_add` + `io_uring_buf_ring_advance`). `aconn_parse(ac)` runs exactly as after `aconn_do_read`. A multishot RECV stays armed (re-add buffers) until `F_MORE` clears or the conn drops.
- **SEND:** outgoing frames in `ac->wbuf` are sent with `IORING_OP_SEND` (one-shot per flush; submitted when `wbuf` becomes non-empty). The CQE's `cqe->res` advances `ac->wbuf.start` exactly as `aconn_do_write` does on a `send` return; a short send re-submits the remainder; `EPIPE`/error maps to `aconn_on_transport_error`. `MSG_NOSIGNAL` semantics are preserved by passing the flag in the SQE.
- This swaps **only** the `ac->ssl == NULL` branch of `aconn_do_read`/`aconn_do_write`; the parse/serialize/inflight-map machinery is untouched. The provided-buffer copy into `ac->rbuf` keeps the existing parser contract (it parses out of `rbuf`), so framing code needs no change.

### 13.5 Cross-thread wakeup

The cross-thread command queue (`CMD_ADD_ACONN`/`SUBMIT`/`CLOSE_ACONN`/`STOP`) and its writer-side `write(l->evfd, &one, 8)` are **unchanged** for both engines — the reconnect worker also writes `evfd` (`rc_worker_main`, `aio.c`). On the io_uring side the loop must *observe* that eventfd:

- **Primary:** arm a persistent `IORING_OP_POLL_ADD`/`POLL_MULTISHOT` on `l->evfd` (tagged `user_data == loop`), so a cross-thread `write(evfd)` produces a CQE that wakes `io_uring_wait_cqe_timeout`. The loop then `read(evfd)` to drain the counter and `loop_drain_commands(l)` — same as the `ptr == l` branch today.
- **Alternative considered:** `IORING_OP_MSG_RING` from the submitting thread directly into the loop ring (no eventfd). Deferred: it would change the writer side of the command queue (the cross-thread `write(evfd)` is shared with the reconnect worker), enlarging the diff. Keep the eventfd; only its *observation* moves to the ring.

`wake(l)` therefore remains `write(l->evfd, &one, 8)` for both engines.

### 13.6 Cancellation, `fd_gen`, and reconnect interplay

On transport error, `aconn_on_transport_error` (`aio.c`) does `epoll_ctl(EPOLL_CTL_DEL, ac->fd)`. Under io_uring this becomes cancellation plus a generation bump; the step-by-step:

1. **New field** `uint32_t fd_gen` on `xrdc_aconn`, incremented every time the fd is replaced (initial arm = gen 0). `user_data` packs `UD(slot_idx, fd_gen)` (e.g. `((uint64_t)fd_gen << 32) | slot_idx`).
2. **On drop** (`engine.cancel(ac)`): submit `IORING_OP_ASYNC_CANCEL` keyed on the outstanding multishot's `user_data` (or `IORING_ASYNC_CANCEL_FD` to cancel all ops on `ac->fd`). Set `ac->poll_armed = 0`. Then `ac->fd_gen++`.
3. **Late CQEs:** any in-flight poll/recv CQE for the *old* fd that races the cancel carries the *old* `fd_gen`. The `wait` decoder compares `UD.gen != ac->fd_gen` and **drops** it — this is the precise io_uring analogue of epoll's "DEL means no more events," covering the window where the kernel had already queued a CQE before the cancel landed. It also protects a *recycled* `xrdc_aconn` slot whose `fd` was reassigned to a new connection.
4. **Reconnect re-arm:** the reconnect worker (`rc_worker_main`) brings up a new socket off-thread and signals via `rc_finished` + `evfd`; the loop-side adoption (`aconn_poll_reconnect`) sets the new `ac->fd` and calls `engine.arm(ac, EPOLLIN)`, which submits a fresh multishot stamped with the *new* `fd_gen`. Parked retry-safe requests are re-issued exactly as today.
5. **Ordering guarantee:** because the cancel and the gen-bump happen on the loop thread before any new arm, and CQE decoding runs on the same loop thread, there is no lock needed — a stale CQE is always recognizable by its gen.

`xrdc_mfile` reopen-on-drop and parked-retry logic (`aio_mgr.c`) sit *above* the engine and are unaffected: they see the same `xrdc_areq` completions regardless of engine.

### 13.7 TLS coexistence

OpenSSL owns the fd syscalls: `SSL_read`/`SSL_write` (`aconn_do_read`/`aconn_do_write`) issue their own `recv`/`send` and manage `WANT_READ`/`WANT_WRITE` renegotiation state (`tls_want_write_on_read`/`tls_want_read_on_write`). io_uring cannot intercept those without swapping OpenSSL to memory BIOs and feeding ciphertext through `RECV`/`SEND` ourselves — a separate, large effort, **out of scope** here. Therefore:

- TLS conns (`ac->ssl != NULL`) **always** use POLL_ADD readiness (ii-a) even after ii-b ships; the loop gets the edge and lets OpenSSL do the I/O.
- Cleartext conns (`ac->ssl == NULL`) may use true-async RECV/SEND (ii-b).

The per-aconn `ac->ssl == NULL` branch already exists in both `aconn_do_read` and `aconn_do_write`, so the engine simply keys ii-b vs ii-a off the same field.

### 13.8 Per-connection state table

| Connection | Engine = epoll | Engine = io_uring (ii-a shipped) | Engine = io_uring (ii-b shipped) |
|---|---|---|---|
| **TLS** (`ssl != NULL`) | `epoll_ctl(MOD)` readiness; `SSL_read`/`SSL_write` | `POLL_ADD` multishot readiness; `SSL_read`/`SSL_write` | `POLL_ADD` multishot readiness; `SSL_read`/`SSL_write` (unchanged from ii-a) |
| **Cleartext** (`ssl == NULL`) | `epoll_ctl(MOD)` readiness; `recv`/`send` | `POLL_ADD` multishot readiness; `recv`/`send` | `RECV`/`SEND` multishot + provided buffers (true async, no readiness syscall) |
| **Wakeup eventfd** | `epoll` `EPOLLIN`, `ptr==l` | `POLL_ADD` multishot on `evfd`, `user_data==loop` | same |
| **Reconnect/mfile/parked-retry** | above-engine, unchanged | above-engine, unchanged | above-engine, unchanged |

### 13.9 FUSE inheritance

`xrootdfs_aio` rides `xrdc_mgr`/`xrdc_mfile` (`aio_mgr.c`), which ride the loop. Selecting the io_uring engine at `xrdc_loop_create` propagates to FUSE for **free** — no driver changes. Legacy `xrootdfs` (per-handle sync `sock.c`) does not use the loop and is untouched and documented as the non-resilient path.

### 13.10 Risk and staged ship

The engine is the highest-risk client workstream; it is gated and staged:

1. **Default OFF.** Engine selection is `epoll` unless `XRDC_IO_URING_ENGINE`/`--io-uring-engine` is explicitly set *and* `xrdc_uring_available()` (probing `POLL_ADD`/`RECV`/`SEND`/`ASYNC_CANCEL` via `io_uring_get_probe`) passes; otherwise silent fallback to epoll.
2. **Ship ii-a (POLL_ADD) before ii-b (RECV/SEND).** ii-a is a pure readiness drop-in that reuses `aconn_do_read`/`aconn_do_write` verbatim, so the full resilience suite (`test_client_robustness.py`, `test_xrootdfs_resilience.py`, fault-injection proxy `tests/c/fault_proxy.c`) must pass *unchanged* before ii-b touches the data path.
3. **ii-b is cleartext-only**, the smaller blast radius, and the provided-buffer recycling/`fd_gen` lifecycle runs under LSan (`tests/lsan.supp`).
4. Cannot start until the disk-ring (§12) has proven build/detect/buffer/fallback discipline (CB-W2 green).

### 13.11 Tests (3 per feature)

- **POLL_ADD multishot (ii-a):** (1) parity — full xrdcp/xrdfs suite byte-exact with engine on vs epoll; (2) re-arm on POLLOUT toggle as `wbuf` fills/drains; (3) `F_MORE`-cleared CQE triggers correct re-submit.
- **Cleartext RECV/SEND (ii-b):** (1) cleartext byte-exact transfer matches; (2) provided-buffer exhaustion/recycle keeps streaming with no lost segment; (3) short SEND re-submits the remainder correctly.
- **Cancellation + fd_gen:** (1) mid-transfer drop → `ASYNC_CANCEL` + reconnect re-arms and parked retry succeeds (fault proxy); (2) a late CQE for the old `fd_gen` is dropped (no UAF, LSan clean); (3) TLS conn stays on POLL_ADD while a sibling cleartext conn uses RECV/SEND in the same loop.

---

## 14. Security: threat model, kill switch & containment implementation

This section is the code-level reference behind the §8 "Security hardening" overview. §8 states the two pillars — a multi-level kill switch and privilege containment via ring restrictions on top of the Phase-40 broker. This section gives the threat model, the exact SHM/admin/panic-file/restriction code, the fd-provenance argument, and the required security-negative tests. Where §8 says "what", §14 says "how, and why it is sufficient."

The single most important security invariant: **the io_uring ring lives in the unprivileged worker and is only ever handed file descriptors that were already opened and access-checked, as the mapped user, by the Phase-40 broker** (`imp_openat2` `src/impersonate/broker.c:346` with `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS`). io_uring read/write/fsync on an already-open fd performs no further DAC traversal — the check happened at open. Therefore io_uring never widens the authorization surface of a request relative to the existing synchronous path; it only changes the submission mechanism. Every mitigation below is built to preserve that invariant even under partial compromise.

### 14.1 Assets, trust boundaries & attacker model

Assets, ranked by blast radius:

| Asset | What it is | Worst-case loss |
|---|---|---|
| `root` on the host | The master process and the broker's `CAP_SETUID`/`CAP_SETGID` | Full host compromise, all tenants |
| Delegated user's namespace | The confined rootfd subtree a mapped principal may reach | Read/write/delete of that one user's data |
| Other tenants' data | Files outside the current request's confinement root | Cross-tenant breach |
| SQ/CQ rings | The mmap'd submission/completion queues of a worker | Forged SQEs → arbitrary op on any registered fd |
| SHM kill-switch flag | `io_uring_disabled` in the shared zone | Defeat the kill switch; keep a buggy backend live |
| Admin endpoint | `POST /xrootd/api/v1/admin/io_uring` | Toggle the backend without authorization |
| Registered fd set | fds the broker handed the worker for in-flight transfers | Op on the wrong-but-confined fd |

Trust boundaries (privilege gradient, high → low):

```
master (root)
  └─ broker (root or non-root service uid; CAP_SETUID+CAP_SETGID ONLY)   <-- imp_drop_to_service_user broker.c:138
        │  openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS) AS mapped user  <-- imp_openat2 broker.c:346
        │  SCM_RIGHTS reply                                               <-- imp_send_reply broker.c:805
        ▼
  worker (NO fs capabilities, NO CAP_SETUID)  <-- io_uring ring lives here
        │  io-wq async kernel workers inherit worker creds (unprivileged)
        ▼
  remote client (untrusted)
```

The boundary that matters for io_uring is **broker ↔ worker**. The broker is the only component that traverses a namespace; the worker only operates on fds the broker chose to send. io_uring does not cross that boundary — it lives entirely inside the worker.

Threat actors:

1. **Malicious remote client** — controls request paths, headers, body, ranges, connection lifecycle. No host code execution.
2. **Compromised worker** — attacker has achieved code execution inside an unprivileged worker (e.g. a parser bug). Holds the rings and the registered fds. Holds no fs capabilities and is not root.
3. **Malicious tenant** — a legitimately-mapped principal trying to reach another tenant's data or escape its confinement root.
4. **io_uring kernel-bug attacker** — possesses an io_uring LPE primitive (the realistic case: Google attributes ~60% of its kernelCTF exploits and ~$1M of bounties to io_uring; it is disabled on ChromeOS/Android prod; Docker/containerd seccomp blocks the io_uring syscalls). Needs to reach `io_uring_setup`/`io_uring_enter` from our worker to fire.

### 14.2 Threat model: attack → mitigation

| # | Actor | Attack | Mitigation in THIS design | Cite |
|---|---|---|---|---|
| T1 | Remote client | Path traversal `../../etc/shadow` in request path, hoping io_uring opens it | io_uring never opens. Open is the broker's `openat2(RESOLVE_BENEATH)`; escape returns `EXDEV`/`-errno` before any SQE exists | broker.c:346, beneath.c:113 |
| T2 | Remote client | Submit a huge range / many concurrent reads to exhaust the ring | Bounded SQ depth + inflight cap (§6 backpressure); over-cap requests fall back to sync or 503; no new auth surface | §6 |
| T3 | Compromised worker | Forge an `OPENAT2` SQE on the registered rootfd to open a sibling tenant's path under a different root | `io_uring_register_restrictions` whitelists only `{READ,WRITE,READV,WRITEV,FSYNC}`; `OPENAT/OPENAT2/STATX/UNLINKAT/RENAMEAT/...` SQEs are rejected by the kernel with `-EACCES` at submit | §14.4 |
| T4 | Compromised worker | Forge `STATX`/`GETDENTS`/`*XATTR` to enumerate the namespace via the ring | Same restriction whitelist; all directory-/metadata-traversal opcodes excluded | §14.4 |
| T5 | Compromised worker | Operate on a registered fd belonging to a different in-flight transfer (fd confusion) | All registered fds were opened by the broker as the mapped user under `RESOLVE_BENEATH`; every reachable fd is already confined. Worst case is a confined op on a confined fd — no escape. Per-transfer fd lifetime is bounded by reaper teardown | vfs_open.c:137, vfs.h:99 |
| T6 | Malicious tenant | Map to principal A, then trick io_uring into reading a path only B may see | Authorization is entirely at broker open time as the mapped principal; io_uring inherits the resulting fd. No tenant-controlled input reaches a syscall that performs DAC. Path escape fails at broker open, not at io_uring | beneath.c:113, resolve_confined_ops.c:125 |
| T7 | Compromised worker | Use io-wq async kernel workers to read a root-owned file off-ring | io-wq workers inherit the **ring creator's** creds = the unprivileged worker's creds. No worker holds fs capabilities, so io-wq cannot read what the worker uid cannot. Test SEC-6 asserts this | §14.6 |
| T8 | Kernel-bug attacker | Trigger an io_uring kernel CVE for LPE from our worker | Containment + kill switch bound blast radius (see T8 detail below) | §14.3, §14.4, §14.5 |
| T9 | Attacker on the host network | Toggle the backend via the admin endpoint without creds | `xrootd_admin_check_auth` — constant-time bearer (`CRYPTO_memcmp`) AND/OR CIDR allowlist; unconfigured ⇒ denied | api_admin.c:189 |
| T10 | Compromised worker | Flip the SHM `io_uring_disabled` flag back to 0 to keep a buggy backend live | The flag only gates submission; the **build-time** and **config** levels are not worker-writable, and a worker that can write SHM is already post-exploit. Defense relies on T8 containment, not on the flag's integrity | §14.3 |
| T11 | Remote client | Cause a panic, then race re-enable | Panic-file disable is sticky until the file is removed by an operator; re-enable is a separate, audited admin action | §14.3 |

**T8 in detail (the io_uring CVE actor).** Assume a real io_uring LPE primitive exists in the running kernel. Our design does not pretend to patch the kernel. Instead it bounds blast radius on three axes:

- *Reachability* — the syscall surface is reduced. After `IORING_SETUP_R_DISABLED` + restrictions, only data-plane opcodes are accepted; many CVEs live in `OPENAT`/`*XATTR`/poll/msg-ring/registration paths that we never enable. This shrinks, not eliminates, the attack surface.
- *Privilege* — even a successful LPE starts from an unprivileged worker with no fs capabilities, so the immediate post-exploit context is weaker than a root daemon. (Caveat: a kernel LPE is by definition a privilege escalation, so this is a delay/detection win, not a containment guarantee against a kernel primitive.)
- *Disablement* — the operator can turn io_uring off fleet-wide in seconds via the SHM flag or panic-file (§14.3), and permanently via config-reload or a build without `XROOTD_HAVE_LIBURING`. This is the same posture as ChromeOS/Android: io_uring is *optional* and *off by default*, so a published CVE is a config flip away from neutralized.

The honest framing (mirror this in §14.6): io_uring is opt-in, off by default, and behind a kill switch precisely because the kernel-bug actor is credible. We reduce surface and bound blast radius; we do not claim immunity.

### 14.3 Kill switch implementation

Four independent levels (§8.1 lists them; here is the code):

**Level 1 — build-time.** `XROOTD_HAVE_LIBURING` undefined ⇒ the entire backend, its SQE construction, and its syscalls are `#ifdef`'d out. A build that never links liburing cannot reach `io_uring_setup`. This is the strongest level and the recommended default for security-sensitive deployments.

**Level 2 — config.** `xrootd_io_uring off` (default) ⇒ `init_process` never calls `io_uring_queue_init`. Changing it requires a privileged reload. SHM survives reload (slab `->data` re-attach, `xrootd_shm_table_alloc` `src/compat/shm_slots.c:14`), and `init_process` re-reads the directive, so the live decision is re-evaluated per cycle.

**Level 3 — hot SHM atomic.** The runtime flip. Add one field to the shared control struct, allocated slab-safe so the slab header survives child death (the contract in `shm_slots.c`: the table's first member is the lock).

```c
/* control block in the shared zone; FIRST member is the lock per the
 * shm_slots.c contract. Pattern mirrors transfer_table's ngx_atomic_t flags
 * (dashboard.h:109; hot read transfer_table.c:155, atomic write :322). */
typedef struct {
    ngx_shmtx_sh_t lock;          /* MUST be first (shm_slots.c contract)   */
    ngx_atomic_t   io_uring_disabled;   /* 0 = enabled, 1 = disabled        */
    ngx_atomic_t   disable_reason;      /* enum: admin | panic | probe      */
    ngx_atomic_t   disabled_epoch_ms;   /* when, for audit/observability    */
} xrootd_iouring_ctl_t;
```

The lock-free hot read, added at the top of the submit path so a disabled flag short-circuits before any SQE is built:

```c
/* xrootd_aio_post_task — submission entry. Single relaxed atomic load,
 * no lock: stale-by-one-read is fine (next op re-checks). */
ngx_int_t
xrootd_aio_post_task(xrootd_aio_task_t *t)
{
    if ((ngx_atomic_uint_t) g_iouring_ctl->io_uring_disabled != 0) {
        return xrootd_aio_fallback_sync(t);   /* drain semantics: stop submit */
    }
    /* ... build SQE on t->fd, io_uring_submit ... */
}
```

The read is a plain atomic load (no acquire fence needed: the flag is a single word and a one-op-stale view is acceptable — the very next op re-reads). This is the identical hot-read/atomic-write split used by the transfer table (`transfer_table.c:155` read, `:322` write).

**Drain semantics.** Setting the flag stops *new* submissions only. It does **not** cancel in-flight SQEs. The reaper keeps calling `io_uring_wait_cqe`/`peek` until `inflight == 0`. Only after the inflight count drains to zero does the worker optionally quiesce and tear the ring down (`io_uring_queue_exit`). This guarantees no dropped or corrupted completions when the switch flips under load — the critical property tested by SEC-2.

```c
/* reaper continues regardless of the disable flag */
while (inflight > 0) {
    io_uring_wait_cqe(&ring, &cqe);
    complete(cqe); inflight--;
    io_uring_cqe_seen(&ring, cqe);
}
if (disabled && inflight == 0 && quiesce_requested) {
    io_uring_queue_exit(&ring);   /* optional teardown */
}
```

**Re-enable path.** Clearing `io_uring_disabled` makes the next `xrootd_aio_post_task` take the io_uring branch again. If the ring was torn down on quiesce, the submit path lazily re-inits it (same `io_uring_queue_init` + restriction sequence as §14.4). Re-enable from a panic state additionally requires the panic file be absent (§ below) — otherwise the watcher re-asserts the flag on its next tick.

**Level 4 — panic-file watcher.** A no-API, operator-only disable that works even if the admin endpoint is down. A per-worker timer stats `xrootd_io_uring_panic_file`; presence ⇒ force-disable.

```c
/* armed once per worker in init_process; ngx_add_timer, e.g. 1000 ms. */
static void
xrootd_iouring_panic_timer(ngx_event_t *ev)
{
    struct stat st;
    int present = (stat((char *) panic_file_path, &st) == 0);
    if (present) {
        ngx_atomic_cmp_set(&g_iouring_ctl->io_uring_disabled, 0, 1);
        g_iouring_ctl->disable_reason = XR_DISABLE_PANIC;
    }
    /* Sticky: do NOT auto-clear on file removal here; clearing the panic
     * state is an explicit admin re-enable (T11). */
    ngx_add_timer(ev, 1000);
}
```

Notes: stat-only (no open of the file), so a hostile symlink at the path cannot be followed into anything dangerous; the path is operator-configured, not request-derived. The watcher writes the SHM flag exactly like the admin handler, so both paths converge on the same lock-free read.

**Multi-worker propagation.** The flag lives in the shared zone, so a single atomic write by *any* worker (admin handler in worker N, or any worker's panic timer) is visible to *every* worker on its next `xrootd_aio_post_task` read — no IPC, no signal, no reload. Propagation latency is bounded by one submit-path read (effectively immediate) for the admin/SHM path and by the timer interval (≤1 s) for the panic-file path. The probe path (a startup `io_uring_setup` feature/health probe failing) also sets the flag with `disable_reason = probe`, so a kernel that rejects our restriction sequence disables the backend instead of running unrestricted.

### 14.4 Privilege containment implementation

**Ring setup with restrictions.** Create the ring disabled, register the opcode whitelist, then enable. This is the core containment mechanism: it makes the ring structurally incapable of opening or traversing a namespace.

```c
/* init_process, worker side. Requires kernel >= 5.10 for restrictions. */
static int
xrootd_iouring_init_restricted(struct io_uring *ring, unsigned entries)
{
    struct io_uring_params p;
    ngx_memzero(&p, sizeof(p));
    p.flags = IORING_SETUP_R_DISABLED;        /* born disabled (5.10) */

    if (io_uring_queue_init_params(entries, ring, &p) < 0)
        return -1;

    /* Whitelist ONLY data-plane, fd-only opcodes. */
    struct io_uring_restriction res[] = {
        { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_READ   },
        { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_WRITE  },
        { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_READV  },
        { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_WRITEV },
        { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_FSYNC  },
    };
    if (io_uring_register_restrictions(ring, res,
            sizeof(res)/sizeof(res[0])) < 0) {
        io_uring_queue_exit(ring);
        return -1;
    }
    if (io_uring_enable_rings(ring) < 0) {     /* flip R_DISABLED off */
        io_uring_queue_exit(ring);
        return -1;
    }
    return 0;
}
```

**Excluded opcodes (explicitly):** `OPENAT`, `OPENAT2`, `STATX`, `UNLINKAT`, `RENAMEAT`, `MKDIRAT`, `SYMLINKAT`, `LINKAT`, `GETDENTS`/directory enumeration, and all `*XATTR` ops. Anything that takes a *path* (and therefore performs namespace resolution / DAC traversal) is off the list. The whitelist is data-plane only.

**Why fd-only opcodes ⇒ no namespace reach.** Every accepted opcode operates on an `fd` field of the SQE, never on a path. The kernel does no path resolution for `READ`/`WRITE`/`FSYNC` — it dereferences the already-open `struct file`. The only fds reachable are the ones the worker holds, and those came exclusively from the broker. A forged `OPENAT2` SQE — the one syscall that *would* resolve an attacker-controlled path — is rejected by the kernel at submit with `-EACCES` because it is not in the whitelist (T3). So even a compromised worker cannot turn the ring into an open primitive.

**Graceful skip below 5.10.** `io_uring_register_restrictions` is 5.10+. On older kernels the registration returns `-EINVAL`/`-ENOSYS`. Policy: fail closed — if restrictions cannot be applied, do **not** run an unrestricted ring; instead set the SHM flag (`disable_reason = probe`) and fall back to the synchronous path. An unrestricted io_uring ring in an unprivileged worker is exactly the configuration we refuse to ship.

```c
if (kernel_lacks_restrictions || io_uring_register_restrictions(...) < 0) {
    io_uring_queue_exit(ring);
    g_iouring_ctl->io_uring_disabled = 1;
    g_iouring_ctl->disable_reason    = XR_DISABLE_PROBE;
    return -1;                 /* caller uses sync path */
}
```

**fd-provenance chain.** The security argument is that *every fd an SQE can name is provably confined*. The chain:

```
remote request path
   │
   ▼  broker, AS the mapped user
imp_openat2(rootfd, rel, RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)   broker.c:346
   │   (escape => -EXDEV/-errno; magic-symlink => blocked)
   ▼  SCM_RIGHTS
imp_send_reply(conn_fd, rep, fd=…)                               broker.c:805
   │
   ▼
imp_recv_reply(...)                                              client.c:204
   │
   ▼
fh->fd = fd                                                      vfs_open.c:137
   │
   ▼  read via accessor
xrootd_vfs_file_fd(fh)                                           vfs.h:99
   │
   ▼
task->fd  ───►  sqe->fd   (READ/WRITE/FSYNC only; never OPENAT)
```

No step in this chain accepts a path from the worker or the client after the broker's `openat2`. The worker's *only* inputs to the ring are (a) an fd from this chain and (b) a whitelisted opcode. Both are provably confined. This is why io_uring adds no authorization surface: the confinement decision is made once, by the broker, as the mapped user, and the fd carries that decision forward.

**Worker-as-non-root posture (non-impersonation case).** When impersonation is off (`XROOTD_IMP_OFF`, the default per beneath.c:113 / resolve_confined_ops.c:125), there is no broker; the worker opens files itself via `do_openat2(... RESOLVE_BENEATH)`. The io_uring containment story still holds because (i) the worker runs as a non-root service uid in standard deployment, and (ii) the same restriction whitelist applies, so the ring cannot open or traverse. The fds io_uring sees are the worker's own `RESOLVE_BENEATH`-confined opens. The deployment posture requirement: **the worker uid must not own, and must not be able to read, files outside the configured roots** — restrictions bound the ring, the uid bounds io-wq.

**SQPOLL creds caveat.** If `IORING_SETUP_SQPOLL` is ever enabled, the kernel polling thread runs with the ring creator's creds at setup time. That is fine for us (unprivileged worker), but SQPOLL also relaxes some submission accounting and keeps a kernel thread spinning on our SQ. Recommendation: do **not** enable SQPOLL in the restricted profile; the security-review benefit of "no persistent kernel thread holding our ring" outweighs the latency gain. If enabled later, re-audit io-wq/SQPOLL cred inheritance.

**Optional personality tier (deferred).** `io_uring_register_personality` (5.6) lets an SQE carry `sqe->personality` to run with a registered cred set. In principle a broker-owned ring could register the mapped user's creds per principal and let `READ`/`WRITE` run under them. Problems that make this deferred, not now:
- Registration creds are *ring-local* and captured at registration time, so a worker-owned ring can only register creds the worker already holds — no privilege gain, no per-tenant benefit.
- A genuinely per-principal personality requires a **broker-owned ring** (the broker registers each mapped user's creds), which reintroduces a data-plane ring into the privileged process — exactly the coupling Phase-40 avoided (broker is open+metadata only, no data plane). That is a large complexity and attack-surface increase.
- The fd-provenance model already confines reads/writes without personalities. Personalities are an optimization for a future "broker holds the data ring" design, explicitly out of scope here.

Keep this tier deferred and documented; do not implement in Phase-44.

### 14.5 Security test hooks

Per the project's "3 tests including a security-negative" rule, the io_uring backend ships the following security-negative tests. Each asserts a *denial*, not a success.

- **SEC-1 — Forged opcode rejected.** With a restricted ring up, hand-build an SQE with `IORING_OP_OPENAT2` (and separately `STATX`, `UNLINKAT`) on the registered rootfd, submit, wait for completion. Assert the CQE result is `-EACCES`. Assert no file was opened/created/removed. This proves the whitelist holds at the kernel boundary (T3/T4).
- **SEC-2 — Kill switch under load.** Drive sustained concurrent reads through `xrootd_aio_post_task`. Mid-flight, flip `io_uring_disabled` via the admin API. Assert: (a) no completion is dropped or corrupted (every issued op completes exactly once with correct bytes/CRC); (b) post-flip submissions take the sync fallback; (c) inflight drains to zero and optional teardown succeeds (drain semantics).
- **SEC-3 — Admin authz.** Four cases against `POST /xrootd/api/v1/admin/io_uring`: (i) no `Authorization` header ⇒ denied; (ii) wrong bearer of equal length ⇒ denied via constant-time `CRYPTO_memcmp` (api_admin.c:215); (iii) request from a source IP outside the CIDR allowlist ⇒ denied; (iv) neither factor configured ⇒ denied (`XROOTD_ADMIN_AUTH_DENIED`, api_admin.c:198). Assert an `admin_audit()` NOTICE line (api_admin.c:236) is emitted for each.
- **SEC-4 — Panic-file disable.** Create `xrootd_io_uring_panic_file`; within one watcher interval assert `io_uring_disabled == 1`, `disable_reason == panic`, and that new ops take the sync path. Assert the disable is sticky after the file is removed (no auto re-enable).
- **SEC-5 — Impersonated read stays confined.** With impersonation in map mode, issue a request whose path attempts escape (`../../etc/passwd`). Assert the failure occurs at **broker open** (`imp_openat2` returns `-EXDEV`/`-errno`, beneath.c:113 routes to broker) and that **no SQE is ever constructed** — i.e. the escape is caught before io_uring, proving io_uring did not relax confinement (T6).
- **SEC-6 — io-wq runs unprivileged.** Force async (io-wq) execution (e.g. `IOSQE_ASYNC` or a blocking read). Assert the io-wq-serviced read of a root-only file the worker uid cannot read returns `-EACCES`/`-EPERM`, proving io-wq inherited the worker's unprivileged creds, not root (T7).

The admin handler under test (pseudocode), reusing all Phase-23 plumbing:

```c
/* POST /xrootd/api/v1/admin/io_uring  body: {"enabled": <bool>} */
static ngx_int_t
admin_io_uring_handler(ngx_http_request_t *r, json_t *body)
{
    if (xrootd_admin_check_auth(r, conf) != XROOTD_ADMIN_AUTH_OK) {  /* :189 */
        admin_audit(r, "io_uring", "toggle", "denied");              /* :236 */
        return admin_send_error(r, NGX_HTTP_FORBIDDEN, "forbidden");
    }
    json_t *en = json_object_get(body, "enabled");
    if (!json_is_boolean(en))
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_enabled");

    ngx_atomic_uint_t v = json_is_true(en) ? 0u : 1u;   /* disabled = !enabled */
    g_iouring_ctl->io_uring_disabled = v;               /* cross-worker write  */
    g_iouring_ctl->disable_reason    = XR_DISABLE_ADMIN;
    g_iouring_ctl->disabled_epoch_ms = now_ms();

    admin_audit(r, "io_uring", json_is_true(en) ? "enable" : "disable", "ok");
    return admin_send_ok(r, "{\"io_uring_disabled\":%d}", (int) v);
}
```

Body reading reuses `xrootd_admin_body_callback` (api_admin.c:270) with its `ADMIN_MAX_BODY` cap and "spilled-to-temp-file ⇒ reject" guard, so the toggle endpoint inherits the existing size/parse hardening for free.

### 14.6 Residual risks & explicit non-goals

Residual risks (accepted, documented):

- **Kernel io_uring CVE.** Restrictions shrink but do not eliminate the syscall surface; a 0-day in an enabled opcode (`READ`/`WRITE`/`FSYNC`) or in the ring-setup/registration path is unaddressed at the code level. Mitigation is operational: off by default, kill switch, and the option to ship without `XROOTD_HAVE_LIBURING`. This is the reason the backend is optional.
- **Compromised-worker fd reuse within confinement (T5).** A code-execution attacker in the worker can issue confined ops on any registered fd. All such fds are broker-confined, so this is contained to confined reads/writes — but it is a real loss of per-request fd isolation inside a single worker. Bounded by reaper teardown lifetime.
- **SHM flag integrity (T10).** A post-exploit worker can rewrite `io_uring_disabled`. The flag is a fast operational control, not a security boundary against an already-compromised worker; defense against that attacker is build-time/config-time disablement plus T8 containment.
- **Non-root broker is not an exploit container.** Per `imp_drop_to_service_user` (broker.c:138), the broker must keep `CAP_SETUID`, which is root-equivalent; the non-root base reduces incidental exposure but does not contain a code-execution exploit of the broker. io_uring does not change this; it simply never runs in the broker.

Explicit non-goals:

- **No data-plane io_uring in the broker.** The broker stays open+metadata only; no SQ/CQ ring is ever created in the privileged process.
- **No path-taking opcodes, ever.** `OPENAT*`/`STATX`/`*AT`/`*XATTR`/`GETDENTS` are permanently off the whitelist. The ring is a data-plane-only instrument by construction.
- **No personality tier in Phase-44.** Per-principal `sqe->personality` is deferred (§14.4); shipping it would require a broker-owned data ring.
- **No SQPOLL in the restricted profile** unless separately re-audited (§14.4 caveat).
- **No claim of kernel-bug immunity.** The design bounds blast radius and provides fast disablement; it does not assert the kernel is safe.

---

## 15. Configuration, build & capability reference

This section is the normative reference for every operator-facing and build-time surface introduced by the optional io_uring backend: the server `config` script delta, the stream-module directives, the compile-time tunables, the client `Makefile`/CLI/env surface, the runtime capability probe, and the kernel/liburing version matrix. It does not restate the design rationale (§§A, B, 7, 8); it is the lookup table you consult while implementing or deploying. All claims are consistent with the established build governance: per-module libs live in the stream module's `ngx_module_libs` (never `CORE_LIBS` alone), `--with-threads` is hard-required, and new `.c` files force a `./configure` re-run.

### 15.1 Server `config` script changes

The detection block is **optional and double-gated** — it activates only when the operator opts in via environment *and* `pkg-config` confirms the library is installed. This differs from the hard-required `libxml-2.0` block (which has no env gate) and matches the spirit of the krb5/codec optional blocks.

#### 15.1.1 Detection block (exact form)

```sh
# Optional io_uring disk-I/O backend. Double-gated: operator opt-in via
# XROOTD_ENABLE_IO_URING *and* liburing actually present. Default OFF — a
# bare ./configure never links -luring and the backend compiles to stubs.
if [ -n "$XROOTD_ENABLE_IO_URING" ] \
   && command -v pkg-config >/dev/null 2>&1 \
   && pkg-config --exists liburing; then
    CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DXROOTD_HAVE_LIBURING=1"
    XROOTD_URING_LIBS="$(pkg-config --libs liburing)"   # normally: -luring
    echo " + xrootd: io_uring disk-I/O backend enabled (liburing $(pkg-config --modversion liburing))"
fi
```

This block belongs with the other optional pkg-config probes (after the krb5 block), so `XROOTD_URING_LIBS` is set before the `ngx_module_srcs` / `ngx_module_libs` assignment for the stream module.

#### 15.1.2 Where each fragment goes — the load-bearing placement table

| Fragment | Goes into | Why exactly there | If misplaced |
|---|---|---|---|
| `-DXROOTD_HAVE_LIBURING=1` + `--cflags` | `CFLAGS` | Compile gate for `#ifdef` stubs in `uring.c`/`uring_submit.c`; applies to every TU including `aio/config.c` directive merge | Stubs never compile out; `io_uring_*` symbols referenced but unresolved |
| `XROOTD_URING_LIBS` (`-luring`) | **stream `ngx_module_libs`** (append to the existing `ngx_module_libs=`) | DYNAMIC `.so` (`--with-stream=dynamic`, the RPM path) is linked with `ngx_module_libs`, NOT `CORE_LIBS` | `.so` builds but **`dlopen` fails at nginx start: `undefined symbol: io_uring_queue_init`** — the canonical failure mode this whole convention exists to prevent |
| `$ngx_addon_dir/src/aio/uring.c` | stream `ngx_module_srcs` | New `.c` → must be listed or `./configure` won't compile it | Symbols `xrootd_uring_*` undefined at link of the `.so` |
| `$ngx_addon_dir/src/aio/uring_submit.c` | stream `ngx_module_srcs` | Same | Same |
| `$ngx_addon_dir/src/aio/uring.h` | `ngx_module_deps` (the stream deps list) | Header dep so a touch of `uring.h` triggers recompile of dependents | Stale objects against a changed struct layout → mixed-ABI crash (§15.1.4) |
| `XROOTD_IO_URING_*` `#define`s | `src/types/tunables.h` (header-only) | Compile-time constants; no new `.c` | — |

The exact append to the stream module's lib line:

```sh
ngx_module_libs="-lssl -lcrypto $XROOTD_JANSSON_LIBS $XROOTD_XML2_LIBS \
                 $XROOTD_KRB5_LIBS $XROOTD_CODEC_LIBS $XROOTD_URING_LIBS"
```

`CORE_LIBS` is **not** touched for liburing — it is referenced only by the stream module objects, so the `ngx_module_libs` append alone is correct and sufficient.

#### 15.1.3 When `./configure` must be re-run

| Change you made | `./configure` re-run? | Rationale |
|---|---|---|
| Added `uring.c` / `uring_submit.c` (new `.c`) | **Yes** | nginx's generated `objs/Makefile` only knows sources present at configure time |
| Edited body of existing `uring.c` | No (`make` suffices) | Source already in the dep graph |
| Added `#define`s to `tunables.h` (header-only) | No | No new TU; touching a tracked header triggers `make` recompile of dependents |
| Toggled `XROOTD_ENABLE_IO_URING` env | **Yes** | The env gate is read by `config` at configure time, not by `make` |
| Added a new directive (field + `ngx_command_t` + merge) | No | No new top-level config block, no new `.c` (lives in existing `aio/config.c` / `config.h`) — per AGENTS.md RECIPE |
| Changed a struct layout in `uring.h` | No re-configure, but **full rebuild required** | See §15.1.4 |

#### 15.1.4 Mixed-ABI crash hazard

`uring.h` defines the ring/task structs shared between `uring.c`, `uring_submit.c`, and the completion-bridge caller. If you change a struct's layout (add/reorder a field), every `.o` that `#include`s it must be recompiled together. Because `make` is dependency-driven only if `uring.h` is in `ngx_module_deps`, the header **must** be listed there; otherwise partial rebuilds link old-layout callers against new-layout callees → out-of-bounds field access → SIGSEGV or silent corruption. Rule: layout change ⇒ touch the `.c` files *and* do `make clean && make` (or rely on the dep list) — never an incremental build you don't trust.

#### 15.1.5 "What to add where" checklist

1. `config`: insert the §15.1.1 detection block after the krb5 block.
2. `config`: append `$ngx_addon_dir/src/aio/uring.c` and `.../uring_submit.c` to stream `ngx_module_srcs`.
3. `config`: append `$ngx_addon_dir/src/aio/uring.h` to the stream deps list.
4. `config`: append `$XROOTD_URING_LIBS` to stream `ngx_module_libs` (NOT `CORE_LIBS`).
5. `tunables.h`: add the `XROOTD_IO_URING_*` `#define`s (§15.3).
6. `config.h`: add the directive fields (`NGX_CONF_UNSET`).
7. `aio/config.c`: add the `ngx_command_t` rows + merge logic.
8. Re-run `XROOTD_ENABLE_IO_URING=1 ./configure --with-threads … --add-module=$REPO && make -j$(nproc)`.

### 15.2 Server directive reference

All directives are **stream → server** context (they live on the `ngx_stream_xrootd_srv_conf_t`, alongside `cache`, `memory_budget`, `thread_pool_name`). Fields are initialized to `NGX_CONF_UNSET` (or `NGX_CONF_UNSET_UINT`) in `create_srv_conf()` and resolved in `merge_srv_conf()`. The `ngx_command_t` rows live with the io_uring backend's config code (`src/aio/config.c`).

| Directive | Syntax | Context | Setter / type | Default | Valid range | Reload-safe? | Controls | Merge |
|---|---|---|---|---|---|---|---|---|
| `xrootd_io_uring` | `xrootd_io_uring on\|off\|auto;` | stream server | `ngx_conf_set_enum_slot` → `ngx_uint_t` enum (`0=off,1=on,2=auto`) | `auto` | the 3 keywords | Yes | Tier selection. `off`: never use uring. `on`: **require it — xrootd fails to start (`nginx -t` error, master exits non-zero) if the backend is not compiled in OR the runtime probe fails (§32, ADR-16)**. `auto`: enable iff `xrootd_uring_runtime_available()` true, else silent thread-pool fallback | `merge_uint_value(…, XROOTD_URING_AUTO)` |
| `xrootd_io_uring_queue_depth` | `xrootd_io_uring_queue_depth N;` | stream server | `ngx_conf_set_num_slot` → `ngx_int_t` | `256` | 8 … 4096 (rounded up to pow2 by liburing) | Yes (new ring on reload) | SQ/CQ entries per worker ring = max concurrent in-flight SQEs | `merge_value(…, 256)` |
| `xrootd_io_uring_panic_file` | `xrootd_io_uring_panic_file <path>;` | stream server | `ngx_conf_set_str_slot` → `ngx_str_t` | unset (empty) | absolute path | Yes | Kill switch: when the file exists, every worker treats uring as disabled and falls back on the next op (no restart). Polled, not inotify | `merge_str_value(…, "")` |
| `xrootd_io_uring_admin` | `xrootd_io_uring_admin on\|off;` | stream server | `ngx_conf_set_flag_slot` → `ngx_flag_t` | `off` | on / off | Yes | Exposes `POST /xrootd/api/v1/admin/io_uring` (bearer+CIDR, audited) to flip the cross-worker SHM disable flag without reload | `merge_value(…, 0)` |
| `xrootd_io_uring_restrict` | `xrootd_io_uring_restrict on\|off;` | stream server | `ngx_conf_set_flag_slot` → `ngx_flag_t` | `on` | on / off | Yes | Locks each ring to fd-only data opcodes via `io_uring_register_restrictions()` (kernel ≥5.10). No-op below 5.10 (containment still holds via unprivileged worker + confined fd) | `merge_value(…, 1)` |

`xrootd_io_uring` uses an enum slot, so it needs an `ngx_conf_enum_t xrootd_io_uring_modes[]` table (`{off,0},{on,1},{auto,2},{null,0}`) declared in `aio/config.c`.

#### 15.2.1 The field → command → merge pattern (per AGENTS.md RECIPE)

Three edits, no `./configure` (no new top-level block, no new `.c`):

**1. Field in `src/config/config.h`** (on `ngx_stream_xrootd_srv_conf_t`):
```c
ngx_uint_t io_uring;            /* enum: off/on/auto */
ngx_int_t  io_uring_queue_depth;
ngx_str_t  io_uring_panic_file;
ngx_flag_t io_uring_admin;
ngx_flag_t io_uring_restrict;
```
Set to `NGX_CONF_UNSET` / `NGX_CONF_UNSET_UINT` in `create_srv_conf()`.

**2. `ngx_command_t` row in `src/aio/config.c`** (added to the stream module's `commands[]`):
```c
{ ngx_string("xrootd_io_uring"),
  NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_enum_slot,
  NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, io_uring),
  &xrootd_io_uring_modes },
```

**3. Merge in `merge_srv_conf()`:**
```c
ngx_conf_merge_uint_value(conf->io_uring, prev->io_uring, XROOTD_URING_AUTO);
ngx_conf_merge_value(conf->io_uring_queue_depth, prev->io_uring_queue_depth,
                     XROOTD_IO_URING_QUEUE_DEPTH);
ngx_conf_merge_str_value(conf->io_uring_panic_file, prev->io_uring_panic_file, "");
ngx_conf_merge_value(conf->io_uring_admin, prev->io_uring_admin, 0);
ngx_conf_merge_value(conf->io_uring_restrict, prev->io_uring_restrict, 1);
```

The runtime probe `xrootd_uring_runtime_available()` is consulted in `postconfiguration` (alongside `xrootd_configure_thread_pools()`), not at parse time, so the verdict is per-worker-process and seccomp-accurate.

### 15.3 Server tunables reference (`src/types/tunables.h`)

All compile-time, header-only (no `./configure`). They bound runtime allocation and encode kernel version gates.

| `#define` | Value | Meaning | Why this default | Tuning |
|---|---|---|---|---|
| `XROOTD_IO_URING_QUEUE_DEPTH` | `256` | SQ/CQ entries per worker ring; ceiling on concurrent in-flight SQEs | Each XRootD read submits **one** SQE (windowed reads stream as a single contiguous `IORING_OP_READ` per wire chunk), so depth ≈ max concurrent read-bearing connections per worker. 256 covers a worker fronting ~256 active transfers with one in-flight op each; ring memory is ~tens of KB | Raise toward 1024 for very high fan-in nodes; lower to 64 on memory-constrained edge nodes |
| `XROOTD_IO_URING_MIN_KERNEL_MAJOR` | `5` | Minimum kernel major for *any* uring tier | io_uring landed in 5.1; nothing earlier has the syscall | Do not lower |
| `XROOTD_IO_URING_MIN_KERNEL_MINOR` | `6` | Minimum 5.x minor for the disk backend | 5.6 is the first kernel with reliable `register_eventfd` (event-loop bridge needs an eventfd CQE notifier) and `register_personality` | The probe (§15.5) is authoritative; this constant is a fast pre-filter |
| `XROOTD_IO_URING_RESTRICT_KERNEL_MINOR` | `10` | Minor at/above which `xrootd_io_uring_restrict` takes effect | `io_uring_register_restrictions()` arrived in 5.10. Below it, restrictions skip and containment relies on the unprivileged worker + `RESOLVE_BENEATH` confined fd | Best-effort: never a hard requirement |

Queue-depth sizing, expanded: the server submits one SQE per logical read response (or per 16 MiB wire chunk for multi-chunk reads — at most 4 SQEs for a maximal 64 MiB request). Because windowed reads fill→drain over a single resident buffer rather than fanning into many small ops, the SQE-to-connection ratio stays near 1:1. Depth tracks *connection concurrency*, not request *size*. Set `queue_depth` ≥ expected steady-state concurrent reads per worker; over-provisioning wastes only a small fixed allocation, under-provisioning forces `get_sqe`→NULL → clean fallback to the thread-pool tier (never a dropped op, §4).

### 15.4 Client build / flags / CLI / env reference

The client is `ngx`-free; gating mirrors the existing `HAVE_KRB5` pattern in `client/Makefile`. `lib/uring.c` is **always** compiled into `LIB_SRCS` and stubs out under `#ifndef XROOTD_HAVE_LIBURING` (identical to the always-compiled `lib/sec/sec_krb5.c` stub model), so the library API surface is stable regardless of build config.

#### 15.4.1 Makefile diff

```make
# --- after the HAVE_KRB5 block ---
HAVE_LIBURING := $(shell pkg-config --exists liburing 2>/dev/null && echo yes)
ifeq ($(HAVE_LIBURING),yes)
  URING_CFLAGS := -DXROOTD_HAVE_LIBURING $(shell pkg-config --cflags liburing 2>/dev/null)
  URING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null)
endif

ALL_CFLAGS := -std=c11 -Wall -Wextra $(HARDEN) $(OPT) -pthread -Ilib -I$(SRC) \
              -MMD -MP $(KRB5_CFLAGS) $(URING_CFLAGS) $(CFLAGS)

LDLIBS := -lssl -lcrypto -lz $(KRB5_LIBS) $(CODEC_LIBS) $(URING_LIBS)

LIB_SRCS := lib/sock.c lib/url.c … lib/sec/sec_krb5.c lib/uring.c
```

The client gate is **not** env-gated (no `XROOTD_ENABLE_IO_URING`): unlike the server (where linking `-luring` into a `dlopen`ed `.so` is a deployment risk), the client is a static/shared lib + CLIs, so the krb5-style "present ⇒ enabled" auto-detect is appropriate. The env gate stays server-only.

#### 15.4.2 `.pc` change

`libxrdc.pc`'s `Requires.private` gains `liburing` **only when present at build time**:

```make
URING_PC := $(if $(HAVE_LIBURING),liburing,)
…
'Requires.private: libssl libcrypto zlib $(URING_PC)' \
```

#### 15.4.3 CLI flag, env, and precedence

| Surface | Form | Consumed by | Maps to |
|---|---|---|---|
| CLI flag | `--io-uring=auto\|on\|off` | `xrdcp`, `xrootdfs_aio` arg parsers | `xrdc_copy_opts.io_uring` |
| Env var | `XRDC_IO_URING=auto\|on\|off` | library default, read once under `pthread_once` (no mutable global) | default for `io_uring` when CLI unset |
| Built-in | `auto` | — | enable iff `xrdc_uring_available()` |

Precedence (highest wins): **CLI flag > `XRDC_IO_URING` env > built-in `auto`**. `on` with no runtime support → clean error from the engine; `auto`/`off` proceed on the classic path. The env is parsed once per process under `pthread_once` and cached.

#### 15.4.4 Build matrix

| liburing at build | `XROOTD_HAVE_LIBURING` | `lib/uring.c` | `--io-uring=on` | `--io-uring=auto` | `--io-uring=off` | `.pc Requires.private` |
|---|---|---|---|---|---|---|
| present | defined | real impl | uses ring; error if runtime probe fails | ring iff probe passes, else classic | classic | `… liburing` |
| absent | undefined | stub (returns "unavailable") | clean error: "built without io_uring" | classic (probe always false) | classic | `…` (no liburing) |

In every cell the **wire behavior and exit semantics are identical** to the classic path; only the byte-moving mechanism differs.

### 15.5 Runtime capability probe

Both sides use an **authoritative probe**, never a `uname`/version parse — containers and seccomp routinely block `io_uring_setup(2)` even on a new kernel, and `IORING_OP_GETDENTS` support is unsettled, so version numbers lie. The probe: `io_uring_queue_init(8, …)` a throwaway ring → `io_uring_get_probe()` → check each required opcode with `io_uring_opcode_supported()` → tear down → **memoize** the verdict. Any failure ⇒ one `NOTICE` log + permanent fallback.

```
probe():
  if memoized: return cached
  if io_uring_queue_init(8, &r, 0) < 0:        v = false        # seccomp / no syscall
  else:
    p = io_uring_get_probe_ring(&r)
    v = all(opcode_supported(p, op) for op in REQUIRED[side])
    io_uring_queue_exit(&r)
  if not v: log NOTICE "io_uring unavailable, falling back"
  cached = v; return v
```

#### 15.5.1 Required opcodes per side

| Side | Required opcodes | If any missing |
|---|---|---|
| Server (disk backend) | `READ`, `WRITE`, `READV`, `WRITEV`, `FSYNC` | Whole uring tier off; thread-pool `pread`/`pwrite`/`fsync` path (always built, `--with-threads`) |
| Client (full engine) | `POLL_ADD`, `RECV`, `SEND`, `ASYNC_CANCEL`, **plus** `READ`, `WRITE` (local-disk ring) | Engine off; classic blocking/epoll loop + `pread`/`pwrite` |

The server set is intentionally fd-only data ops (no `OPENAT`/`STATX`/`UNLINKAT`) — the ring cannot open or traverse a path, which is what makes `xrootd_io_uring_restrict` enforceable and the unprivileged-worker containment sound.

#### 15.5.2 Graceful degradation per missing feature

| Missing capability | Server effect | Client effect |
|---|---|---|
| `io_uring_setup` blocked (seccomp) | probe false → thread-pool tier | probe false → classic loop |
| `READ`/`WRITE` unsupported | no disk ring | no disk ring (copy stays `pread`/`pwrite`) |
| `READV`/`WRITEV` unsupported | scatter reads fall back to per-segment `READ` SQEs or pool | n/a (client uses contiguous `READ`) |
| `FSYNC` unsupported | sync via thread-pool `fsync` | sync via blocking `fsync` |
| `POLL_ADD` unsupported | n/a | network engine off; disk ring may still run |
| `ASYNC_CANCEL` unsupported | n/a | engine off (clean mid-op cancel is required for reconnect safety) |

Degradation is per-feature and silent under `auto`; under `on` the first missing required opcode yields a single clean error.

### 15.6 Kernel & liburing feature / version matrix

liburing is the standard userspace wrapper for all of these. Build host here is kernel 6.18 with liburing present (full support); the matrix below defines what happens on older targets.

| Feature | Min kernel | Used by | Fallback if absent |
|---|---|---|---|
| `io_uring_setup` (basic SQ/CQ) | 5.1 | both | no uring at all — thread-pool / epoll |
| Registered files/buffers | early 5.x (5.1–5.5) | client disk ring (registered buf pool) | classic non-registered `READ`/`WRITE` (one extra copy/pin) |
| `register_personality` | 5.6 | server (credential pinning, deferred) | run without personality registration |
| `register_eventfd` (reliable) | 5.6 | server (event-loop CQE bridge) | **disk backend gated off below 5.6** (`MIN_KERNEL_MINOR`) |
| `IORING_FEAT_FAST_POLL` | 5.7 | client network engine | single-shot `POLL_ADD` per readiness wait (more syscalls, same correctness) |
| `register_restrictions` | 5.10 | server (`xrootd_io_uring_restrict`) | skip restrictions; containment via **unprivileged worker + confined fd** (`RESTRICT_KERNEL_MINOR`) |
| Multishot recv/accept + provided-buffer ring | ~5.19 / 6.0 | client network engine (fast path) | **single-shot `POLL_ADD` + classic `recv`** into caller buffers |
| `IORING_OP_GETDENTS` | unsettled | (none — treated as unavailable) | dir listing always via classic `getdents`/readdir; never on the ring |

#### 15.6.1 Minimum supported kernel per capability tier

| Tier | Minimum kernel | What runs | What's lost vs. newer |
|---|---|---|---|
| **Basic disk backend** (server) | **5.6** | `READ`/`WRITE`/`READV`/`WRITEV`/`FSYNC` ring + eventfd bridge | no ring restrictions (<5.10) |
| **Restricted disk backend** (server, hardened) | **5.10** | above + `register_restrictions` locking to fd-only data ops | — |
| **Full client engine** (network + disk) | **5.7** functional / **5.19–6.0** optimal | `POLL_ADD`+`RECV`/`SEND`/`ASYNC_CANCEL`+disk ring | <5.19: single-shot poll + classic recv (no multishot / provided-buffer ring) |

Below 5.6, every side falls back entirely (thread-pool server / classic client) — correct, just without io_uring acceleration. There is no kernel on which enabling the backend changes wire framing or correctness; the floor only changes *whether* the ring is used.

### 15.7 Defaults & recommended production profile

#### 15.7.1 Server — WLCG storage node

```nginx
# stream { server { ... } } — XRootD storage endpoint
thread_pool default threads=32 max_queue=65536;   # fallback tier; always present

xrootd on;
xrootd_thread_pool default;

xrootd_io_uring              auto;     # enable iff the worker's kernel/seccomp allow
xrootd_io_uring_queue_depth  512;      # high fan-in node: ~512 concurrent reads/worker
xrootd_io_uring_restrict     on;       # lock rings to fd-only data ops (no-op <5.10)
xrootd_io_uring_admin        off;      # turn on only with bearer+CIDR auth in front
xrootd_io_uring_panic_file   /etc/xrootd/io_uring.panic;   # CVE kill switch
```

Rationale: `auto` is the only safe fleet-wide default — a worker on a locked-down container silently uses the thread pool while a bare-metal node on 6.x uses the ring, from one identical config. `queue_depth 512` suits a storage node fronting many concurrent transfers per worker. `restrict on` is free insurance; it no-ops on <5.10. The `panic_file` is the no-restart kill switch for incident response. `admin off` unless the audited HTTP control surface is needed and properly fronted. `--with-threads` and the `thread_pool` are mandatory regardless — the pool is the always-available fallback.

#### 15.7.2 Client — `xrdcp`

```sh
# Default for batch / pilot jobs: let the library decide per host.
export XRDC_IO_URING=auto

# Force per-invocation when you know the kernel is new and want max throughput:
xrdcp --io-uring=on  root://store.example//data/big.root /scratch/big.root

# Disable on a host with a known-bad/old kernel without unsetting the env:
xrdcp --io-uring=off root://store.example//data/big.root /scratch/big.root
```

Rationale: `XRDC_IO_URING=auto` in the job environment is the portable default — the once-cached probe enables the ring on capable hosts and transparently uses the classic path elsewhere. `--io-uring=on` (CLI beats env) is for benchmarking or pinned-kernel fleets; it surfaces a clean error rather than silently degrading. `--io-uring=off` is the per-command escape hatch. On a build without liburing the flags still parse and behave identically to the classic client (§15.4.4), so scripts are portable across client builds.

---

## 16. Observability & operations runbook

io_uring is a *substrate swap*, not a wire change, so its observability has one job: make a normally-invisible backend selection auditable. An operator must be able to answer three questions from `/metrics` and the logs alone — (a) *is the ring actually engaged on this worker?*, (b) *is it silently falling back?*, and (c) *did someone (or something) flip the kill switch?* — without attaching a debugger. Every signal below is low-cardinality (INVARIANT #8: no paths, UUIDs, DNs, or offsets as labels); the only label values are the fixed worker index and a closed enum of fallback reasons.

### 16.1 New metrics

All counters/gauges are `ngx_atomic_t` in a new `ngx_xrootd_uring_metrics_t` block hung off the root metrics struct (sibling of `frm`). The enum slots and INC/DEC/ADD macros follow the FRM precedent exactly (`src/metrics/metrics.h`). The submit-latency histogram reuses the `frm` seconds-bucket pattern but in **microseconds** (submit→CQE is sub-millisecond).

| Metric name | Type | Labels (low-cardinality only) | Meaning |
|---|---|---|---|
| `xrootd_io_uring_active` | gauge | `worker` (int 0..N-1) | 1 iff this worker created a ring AND the kill switch is clear AND probe passed; 0 otherwise. The single "is it on" signal. |
| `xrootd_io_uring_enabled_config` | gauge | (none) | 1 if any server block requested `on`/`auto` at config time; static post-fork. Distinguishes "off by config" from "off by fallback". |
| `xrootd_io_uring_ops_total` | counter | `op` (read\|write\|readv\|writev) | SQEs that completed via the ring (CQE harvested, regardless of `res` sign). |
| `xrootd_io_uring_inflight` | gauge | `worker` | SQEs submitted but not yet reaped (`u->inflight`). Saturation indicator vs `queue_depth`. |
| `xrootd_io_uring_fallback_total` | counter | `reason` (disabled\|ringfull\|unmapped\|kernel) | Ops that *could* have gone to the ring but were routed to pool/inline. `disabled`=kill switch/panic-file; `ringfull`=`inflight>=queue_depth` or `get_sqe` NULL; `unmapped`=op has no ring mapping (pgread/dirlist/multi-fd); `kernel`=probe failed this process. |
| `xrootd_io_uring_submit_total` | counter | (none) | `io_uring_submit()` calls (batched; ≤ ops_total). syscalls/op denominator. |
| `xrootd_io_uring_cqe_errors_total` | counter | `op` | CQEs with `res < 0` (the `-errno` path). These become `kXR_IOError` and MUST also bump the existing `op_err[]` slot — divergence is a bug. |
| `xrootd_io_uring_stale_cqe_total` | counter | (none) | CQEs dropped by the generation guard (§A.3). Steady non-zero under churn is normal; a spike signals slot-table or teardown trouble. |
| `xrootd_io_uring_submit_latency_us_bucket` / `_count` / `_sum_usec` | histogram | `op` | submit→CQE wall time, µs buckets `{50,100,250,500,1000,5000,25000,+Inf}`. |
| `xrootd_io_uring_kill_switch` | gauge | (none) | SHM atomic `io_uring_disabled` (1=disabled fleet-wide). Read directly from SHM by the exporter; identical on every worker. |
| `xrootd_io_uring_panic_file_present` | gauge | (none) | 1 iff the panic-file existed at the last watcher tick. Distinguishes panic-file disable from admin-API disable. |
| `xrootd_io_uring_restrict_active` | gauge | `worker` | 1 iff `io_uring_register_restrictions()` succeeded on this ring (kernel ≥5.10). 0 means containment rests on the unprivileged-worker + confined-fd model only (§8.2). |

#### Increment sites

| Metric | Where bumped | Macro / mechanism |
|---|---|---|
| `active`, `enabled_config`, `restrict_active`, `panic_file_present`, `kill_switch` | ring create/teardown (`xrootd_uring_init_worker` / `xrootd_exit_process`), the panic-file watcher, the admin handler. Gauges are *set* (store). | direct `ngx_atomic_cmp_set`/store on the SHM field, mirroring `transfer_table.c:322` |
| `ops_total{op}`, `cqe_errors_total{op}`, `submit_latency` | **reaper** (`xrootd_uring_eventfd_handler`), per CQE, after `op_kind` decode and `res` translation, before `ngx_post_event`. `submit_latency` uses a submit timestamp stashed in the slot. | new `XROOTD_URING_METRIC_INC(field)` / `_ADD`, same shape as `XROOTD_FRM_METRIC_INC` |
| `submit_total` | **submit** (`xrootd_uring_submit`) after a successful `io_uring_submit()`. | `XROOTD_URING_METRIC_INC` |
| `inflight` | INC in submit (post-`io_uring_submit`), DEC in reaper (post-`io_uring_cqe_seen`). | `XROOTD_URING_METRIC_INC`/`_DEC` (gauge) |
| `fallback_total{reason}` | **selector** (`xrootd_aio_post_task`, §A.5): one INC on each branch that declines the ring — kill-switch→`disabled`, `inflight>=depth`/`get_sqe`==NULL→`ringfull`, `op==NONE`→`unmapped`, `u==NULL`/`!u->enabled`→`kernel`. | `XROOTD_URING_METRIC_INC` with the reason-indexed slot |
| `stale_cqe_total` | **reaper**, on generation mismatch, before `io_uring_cqe_seen`. | `XROOTD_URING_METRIC_INC` |

**Enum placement.** Add `XROOTD_URING_FALLBACK_{DISABLED,RINGFULL,UNMAPPED,KERNEL}=0..3`, `XROOTD_URING_NFALLBACK 4`, `XROOTD_URING_OP_{READ,WRITE,READV,WRITEV}=0..3`, `XROOTD_URING_NOPS 4`, and `XROOTD_URING_SUBMIT_LATENCY_BUCKETS 8` next to the FRM block in `metrics.h`. The struct grows the SHM ABI exactly once — declare every field up front (the FRM "declare across phases" rule). The HTTP exporter gains `xrootd_uring_op_names[]` / `xrootd_uring_fallback_names[]` string tables, mirroring `xrootd_op_names[]`.

**Per-op access log.** The existing `xrootd_access_log_emit()` line is **not** extended with a backend field (that would change every cross-protocol access-log conformance test). Backend attribution lives in `/metrics` and debug traces only. The access-log byte counts and latency are backend-transparent by design — that transparency is itself an assertion (§17).

### 16.2 Log lines

Three classes, all using existing severities.

**(a) Kill-switch flip — `NGX_LOG_NOTICE`, audited.** The admin handler reuses `admin_audit()` verbatim (`api_admin.c:236`):

```
xrootd: admin: POST io_uring target=enabled=false client=10.0.0.7 result=disabled
xrootd: admin: POST io_uring target=enabled=true  client=10.0.0.7 result=enabled
```

The panic-file watcher emits its own NOTICE on *edge* (not every tick):

```
xrootd: io_uring: panic-file present (/etc/xrootd/io_uring.panic) -> disabling ring fleet-wide
xrootd: io_uring: panic-file removed -> ring re-enabled (subject to probe)
```

**(b) One-time probe-fail / fallback — `NGX_LOG_NOTICE`, once per process.** Emitted from the runtime probe guarded by a per-process latch so a blocked kernel logs once, not per-connection:

```
xrootd: io_uring: probe failed (io_uring_setup: Operation not permitted) -> using thread pool [worker 3]
xrootd: io_uring: kernel 5.4 < required 5.6 -> io_uring disabled, thread pool active [worker 3]
xrootd: io_uring: register_restrictions unsupported (kernel<5.10) -> containment via unprivileged worker + confined fd [worker 3]
```

`auto` downgrades silently-but-logged (NOTICE, suite stays green); `on` additionally fails config load with a hard error:

```
xrootd: "xrootd_io_uring on" requested but runtime probe failed; set "auto" to allow fallback
```

**(c) Debug submit/complete traces — `NGX_LOG_DEBUG_STREAM`, only under `error_log ... debug`.** Zero cost in production (compiled behind `ngx_log_debug`):

```
[debug] io_uring submit op=read fd=42 off=2097152 len=2097152 slot=7 gen=3 user_data=0x0000000300000007 inflight=2
[debug] io_uring cqe slot=7 gen=3 res=2097152 -> nread=2097152 lat=83us posting done
[debug] io_uring cqe slot=7 gen=2 res=-9 STALE (gen mismatch, expected 3) dropped
[debug] io_uring fallback reason=ringfull inflight=256/256 -> thread pool
```

`user_data` is logged as the raw 64-bit `(gen<<32)|slot` so a trace can be correlated to a CQE in `strace`/`bpftrace` output. No path/offset is logged at NOTICE level (debug only).

### 16.3 Health & SLO signals

| Question | Positive signal | Negative / alarm signal |
|---|---|---|
| Is io_uring engaged on this worker? | `xrootd_io_uring_active{worker} == 1` **and** `rate(xrootd_io_uring_ops_total[1m]) > 0` under load | `active==1` but `ops_total` flat under known I/O load → ring created but selector never picks it (check `fallback_total{reason}` breakdown) |
| Silent fallback? (the dangerous case) | `fallback_total{reason="unmapped"}` climbing is *expected* (pgread/dirlist); all other reasons flat | `fallback_total{reason="kernel"}` jumps on a node where `active` was 1 → probe regression; `reason="ringfull"` climbing → under-provisioned `queue_depth` |
| Is the ring saturated? | `io_uring_inflight / queue_depth` p95 < 0.7 | sustained `inflight == queue_depth` with `fallback_total{ringfull}` climbing → ops spilling to pool; raise depth |
| Did a kill switch fire fleet-wide? | `kill_switch == 0`, `panic_file_present == 0` everywhere | `kill_switch == 1` → confirm intended (correlate with the NOTICE audit line); if unexpected, an unauthorized/forged flip — check audit `client=` |
| Backend parity holding? | for each op, `increase(io_uring_cqe_errors_total{op})` tracks the client-visible error delta | `cqe_errors_total` rising while client-visible error rate is *flat* → a CQE error not surfacing as `kXR_IOError` (a correctness bug, page immediately) |

**Silent-fallback detection is the headline SLO.** The failure mode operators fear is "we think io_uring is on, it quietly degraded, and we lost the win without noticing." The detector is a recording rule: `active==1 AND rate(ops_total)==0 AND rate(fallback_total{reason!="unmapped"})>0` for 10m. Because `unmapped` (pgread/dirlist) is structurally always present, it is excluded from the silent-fallback numerator.

### 16.4 Operations runbook

All `curl` examples assume the phase-23 admin API is enabled (`xrootd_io_uring_admin on`) with a bearer token in `$TOKEN` and the caller inside the CIDR allowlist. The endpoint is `POST /xrootd/api/v1/admin/io_uring`, auth via `xrootd_admin_check_auth()` (`api_admin.c:189`), audited via `admin_audit()`.

#### 16.4.1 Enable io_uring on a node

1. Confirm the binary has the backend: `nginx -V 2>&1 | grep -q 'io_uring'` (build banner) — if the symbol is stubbed, `active` can never be 1.
2. Edit the server block: set `xrootd_io_uring auto;` (recommended) or `on;`. Optionally `xrootd_io_uring_queue_depth 256;`.
3. Validate and reload: `nginx -t && nginx -s reload`. Workers re-fork through `ngx_stream_xrootd_init_process()` and create rings.
4. Verify engagement: `curl -s http://127.0.0.1:9100/metrics | grep '^xrootd_io_uring_active'` (expect one line per worker, all value 1).
5. Drive a read and confirm `xrootd_io_uring_ops_total{op="read"}` increases across two scrapes spanning a GET.
6. Confirm no unexpected fallback: `fallback_total{reason="kernel"}` and `{reason="ringfull"}` flat.

#### 16.4.2 EMERGENCY — io_uring CVE drops, disable fleet-wide with no restart

Two independent mechanisms; use **both** (panic-file is the durable belt, admin API is the instant suspenders). Order: API first (instant, all workers on next op), then panic-file (survives reload, works without a token).

1. Instant disable via admin API (in-flight CQEs still drain — no op dropped):
   ```
   curl -fsS -X POST http://127.0.0.1:<admin_port>/xrootd/api/v1/admin/io_uring \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d '{"enabled": false}'
   ```
2. Durable disable via panic-file:
   ```
   ansible all -b -m file -a 'path=/etc/xrootd/io_uring.panic state=touch'
   ```
3. Verify every worker fell back:
   ```
   curl -s http://127.0.0.1:9100/metrics | grep -E 'xrootd_io_uring_(active|kill_switch|panic_file_present)'
   # expect: active{worker=*}==0, kill_switch==1, panic_file_present==1
   ```
4. Confirm zero new ring activity and zero errors after the flip (ops_total stops increasing; cqe_errors flat; fallback_total{reason="disabled"} climbing; `inflight -> 0` within seconds = drain complete).

#### 16.4.3 Re-enable after patch

1. Remove the panic-file fleet-wide: `ansible all -b -m file -a 'path=/etc/xrootd/io_uring.panic state=absent'`. Confirm `panic_file_present -> 0`.
2. Clear the SHM flag via API: `curl ... -d '{"enabled": true}'` → audit `result=enabled`.
3. Verify `kill_switch -> 0`, then `active -> 1` on the next watcher tick (re-armed subject to the probe — a kernel that no longer supports io_uring stays at `active=0` with a `kernel` fallback, the safe outcome).
4. Drive traffic; confirm `ops_total` resumes climbing.

#### 16.4.4 Diagnose "io_uring not engaging"

`active{worker}==0` despite `xrootd_io_uring auto/on`. Walk the gates in order:

| Check | Signal | Remedy |
|---|---|---|
| Kill switch / panic-file set? | `kill_switch==1` or `panic_file_present==1` | remove panic-file / `{"enabled":true}` |
| Probe failed (seccomp)? | NOTICE `probe failed ... Operation not permitted` | relax seccomp **only** if policy allows; else accept fallback |
| Kernel < min? | NOTICE `kernel X < required 5.6` | upgrade kernel or accept fallback |
| `register_restrictions` failed? | `restrict_active==0` + NOTICE | informational — ring still runs; containment via §8.2 points 1–2 |
| Built without liburing? | banner lacks `io_uring`; `nm` shows stubs | rebuild with `XROOTD_ENABLE_IO_URING=1 ./configure` |
| Config didn't reach worker? | `enabled_config==0` | directive in wrong server block / not reloaded — `nginx -t`, reload |
| Green but `ops_total` flat? | only `unmapped` fallback climbing | workload is pgread/dirlist-heavy (those stay on pool by design) — expected |

#### 16.4.5 Capacity / queue-depth tuning from metrics

- Read `io_uring_inflight` p95/p99 against `queue_depth`.
- If `fallback_total{reason="ringfull"}` >1% of `ops_total` and p99 `inflight == queue_depth`: raise `xrootd_io_uring_queue_depth` (next power of two) and reload. Ring memory is per-worker and small; the phase-31 budget is unaffected (windowed reads post depth-1 per connection).
- If `submit_latency` p99 climbs while `inflight` is low: the bottleneck is the device, not the ring — io_uring won't help.
- `submit_total / ops_total` approaching 1.0 means no batching benefit; a healthy busy worker shows < 1.0.

### 16.5 Dashboards & alerts

**Suggested Grafana panels** (one row, "io_uring backend"):

| Panel | Query (PromQL sketch) |
|---|---|
| Ring engaged (per worker) | `xrootd_io_uring_active` as a state-timeline |
| Ops rate by op | `sum by (op) (rate(xrootd_io_uring_ops_total[1m]))` |
| Fallback rate by reason | `sum by (reason) (rate(xrootd_io_uring_fallback_total[1m]))` (stacked) |
| Inflight vs depth | `xrootd_io_uring_inflight` over a `queue_depth` threshold line |
| Submit→CQE latency | `histogram_quantile(0.99, sum by (le,op) (rate(xrootd_io_uring_submit_latency_us_bucket[5m])))` |
| CQE errors vs client errors | `rate(xrootd_io_uring_cqe_errors_total[5m])` overlaid with `rate(op_err[5m])` |
| Kill switch / panic-file | `xrootd_io_uring_kill_switch`, `xrootd_io_uring_panic_file_present` |

**Alert rules:**

| Alert | Condition | Severity | Rationale |
|---|---|---|---|
| `IoUringSilentFallback` | `active==1 and rate(io_uring_ops_total[10m])==0 and rate(io_uring_fallback_total{reason!="unmapped"}[10m])>0` for 10m | warning | the headline silent-degradation case |
| `IoUringFallbackSpike` | `rate(io_uring_fallback_total{reason=~"kernel|disabled"}[5m]) > 0` unexpectedly (no recent audit flip) | critical | probe regression or unauthorized kill |
| `IoUringRingSaturated` | `io_uring_inflight / on(worker) queue_depth > 0.9` for 15m AND `ringfull` rising | warning | raise queue_depth |
| `IoUringCqeErrorDivergence` | `rate(io_uring_cqe_errors_total[5m]) > 0` while client-visible `op_err` delta == 0 | critical | a CQE error not surfacing as `kXR_IOError` — correctness bug |
| `IoUringKillSwitchUnexpected` | `kill_switch==1` with no matching `admin: POST io_uring result=disabled` audit line in 5m | critical | forged/unauthorized flip; inspect audit `client=` |
| `IoUringStaleCqeSpike` | `rate(io_uring_stale_cqe_total[5m])` >> baseline | warning | slot-table / teardown anomaly |

---

## 17. Detailed test plan & verification

This expands §6. The plan is built around **one acceptance gate** — the backend-parity matrix — and feature suites that each satisfy the 3-tests-per-feature rule (success / error / security-negative). Every new test is anchored into an existing file so the suite topology does not fragment. Throughput numbers are explicitly *advisory* on the WSL2 build host (§17.8); correctness gates are hard and run everywhere.

### 17.1 Backend-parity matrix harness (the central gate)

**Principle:** io_uring changes how bytes move, never what is on the wire. So the same suite, run with the backend off vs on vs auto, must produce **byte-for-byte identical client-visible responses**. This generalizes the existing `tests/backend_matrix.py` cross-backend selector (today: nginx vs xrootd) to a *backend-substrate* axis.

**Harness design:**

- Add a session-scoped fixture `uring_mode` parametrized over `["off", "on", "auto"]`, driven by env `XROOTD_IO_URING_MODE` consumed by `tests/manage_test_servers.py` when it renders the server's `xrootd_io_uring` directive. `on` additionally sets a low `xrootd_io_uring_queue_depth` variant in one matrix cell to exercise the spill path.
- The fixture starts (or reuses) a server instance per mode. Tests that opt into parity record `(request, response_bytes, sha256)` into a per-mode artifact; a final `test_backend_parity_reconcile` asserts all three modes produced identical response bytes and identical access-log byte counts for the same input corpus.
- Plugs into `tests/test_integrity_matrix.py` (already iterating `(topology, protocol, locator)` with byte-exact + checksum assertions): add `uring_mode` as an outer parameter so the *strongest* existing correctness gate runs under all three backends with zero new assertion logic.
- CI exposes `XROOTD_IO_URING_MODE`; the default local run uses `auto` (production default).

**Gate:** the full read/write/readv/pgread/dirlist suites green under all three modes is *blocking* before SB-W3 merges; the client resilience suite (§17.7) green with the engine ON is the hard gate before CB-W4 ships beyond opt-in.

### 17.2 Per-feature server test spec

Negative-offset / overflow / bad-handle cases assert the op is rejected **before any SQE is built**, observable via `xrootd_io_uring_ops_total` staying flat.

| Test-id | Type | Setup | Action | Expected assertion | Anchor |
|---|---|---|---|---|---|
| `uring_read_ok` | success | file of known bytes; `uring on` | `kXR_read` full + windowed (>2 MiB) | exact bytes + `sha256` match the off-mode response; `ops_total{op=read}` increments by #windows | `test_aio.py` |
| `uring_read_trunc_ioerr` | error | open fd, truncate file underneath | read past EOF / into a hole that errors | `kXR_IOError` frame **byte-identical** to the pool path; `cqe_errors_total{op=read}` and `op_err[READ]` both +1 | `test_aio.py` |
| `uring_read_negoff_reject` | security-neg | `uring on` | `kXR_read` with negative offset | rejected pre-SQE; `ops_total{op=read}` **unchanged**; no CQE | `test_readv_security.py` |
| `uring_read_overflow_reject` | security-neg | `uring on` | `offset+len` overflow / out-of-range handle | rejected pre-SQE; `ops_total` unchanged | `test_attack_vectors.py` |
| `uring_write_ok` | success | writable file; `uring on` | `kXR_write` + `kXR_pgwrite` | bytes on disk byte-exact; detached payload survives to CQE (no UAF under ASan); `ops_total{op=write}`++ | `test_write.py` |
| `uring_write_short_ioerr` | error | fs near-full / RO mount via fault setup | write the kernel short-completes (`res<len`) | hits existing `kXR_IOError("short write")` branch — same frame as pool; `cqe_errors_total{op=write}`++ | `test_write.py` |
| `uring_write_badhandle_reject` | security-neg | `uring on` | write to a closed/forged handle | rejected pre-SQE; `ops_total` unchanged | `test_attack_vectors.py` |
| `uring_readv_ok` | success | multi-chunk file; single coalesced group | `kXR_readv` | response framing + bytes identical to off mode; `ops_total{op=readv}`++ | `test_readv.py` |
| `uring_readv_multifd_fallback` | success(routing) | readv spanning multiple fds/groups | `kXR_readv` | result identical; `fallback_total{reason=unmapped}`++ (multi-fd stays on pool) — assert via metric, not wire | `test_readv.py` |
| `uring_readv_bounds_reject` | security-neg | readv element with bad offset/len | `kXR_readv` | per-element bounds rejected pre-SQE; `ops_total{readv}` unchanged | `test_readv_security.py` |
| `uring_writev_fsync_ok` | success | writev with `do_sync` | `kXR_writev` | `IOSQE_IO_LINK` orders write→fsync in-kernel; data durable; bytes match off mode; `ops_total{writev}`++ | `test_write.py` |
| `uring_pgread_takes_pool` | success(routing) | `uring on` | `kXR_pgread` (CRC) | pgread framing `kXR_status(4007)` + per-page CRC32c **unchanged**; assert it took the **pool** path (`fallback_total{reason=unmapped}`++; no pgread op slot) | `test_pgread_wire_conformance.py`, `test_pgwrite_checksum.py` |
| `uring_dirlist_takes_pool` | success(routing) | `uring on` | `kXR_dirlist` | listing identical; routed to pool (`unmapped` fallback) | `test_metadata_stress.py` |
| `uring_forged_openat_rejected` | security-neg | `uring on`, restrictions active | submit `IORING_OP_OPENAT` through the ring | `register_restrictions` rejects it (`-EACCES`); ring **cannot** open/traverse a path | `tests/c/` new `uring_restrict.c` |

### 17.3 Per-feature client test spec

All transfers verified by SHA256 against the source over the corpus `{empty, 1 B, sub-chunk, exactly XRDC_COPY_CHUNK, multi-chunk, ~GiB}` with `--io-uring=off|on|on+O_DIRECT` → identical hashes.

| Test-id | Type | Setup | Action | Expected assertion | Anchor |
|---|---|---|---|---|---|
| `cli_diskring_download_ok` | success | corpus on server; `--io-uring=on` | `xrdcp root://… /local` | SHA256 == source for every size and all three settings; disk/network overlap exercised | `test_native_xrdcp_xrdfs.py`, `test_client_xrdcp_bulk.py` |
| `cli_diskring_upload_ok` | success | local corpus; `--io-uring=on` | `xrdcp /local root://…` | SHA256 on server == source; ordered completion (chunk k released only after op k) | `test_client_xrdcp_bulk.py` |
| `cli_diskring_odirect_ok` | success | NVMe corpus; `--io-uring=on` + O_DIRECT | large sequential GET/PUT | bytes identical; unaligned tail falls back to buffered write correctly | `test_native_xrdcp_xrdfs.py` |
| `cli_diskring_shortread_err` | error | source truncated mid-transfer | download | short-read surfaces the same `xrdc_status` as the epoll path; pump cancel/progress intact | `test_client_robustness.py` |
| `cli_diskring_baddst_secneg` | security-neg | unwritable dest dir | upload/download to it | clean error, no partial/corrupt file, no buffer leak | `test_client_robustness.py` |
| `cli_engine_polladd_tls_ok` | success | `--io-uring=on`, TLS link | multishot `POLL_ADD`; `SSL_read`/`SSL_write` still own syscalls | transfer byte-exact; TLS path unchanged (POLL_ADD readiness only) | `test_libxrdc.py`, `test_xrootdfs_aio.py` |
| `cli_engine_cleartext_recv_ok` | success | cleartext link (deferred tier) | `IORING_OP_RECV/SEND` multishot + provided buffers | byte-exact; only the `ac->ssl==NULL` branch swapped | `test_libxrdc.py` |
| `cli_engine_fd_gen_secneg` | security-neg | recycle an aconn fd mid-flight | force a late CQE for the old fd_gen | late CQE dropped by `fd_gen` stamp; no cross-talk to the new connection | `tests/c/aio_resil.c` |

### 17.4 Fallback tests

| Test-id | Scenario | Expected |
|---|---|---|
| `srv_fallback_seccomp` | server where `io_uring_setup` is seccomp-blocked (container default profile) | one NOTICE `probe failed`; `auto` degrades clean; **full read/write/readv/pgread suite green on the pool**; `active==0`, `fallback_total{reason=kernel}` climbing |
| `srv_fallback_oldkernel` | `MIN_KERNEL` above the host kernel (or <5.6) | NOTICE `kernel X < required`; suite green on pool |
| `srv_fallback_on_hard` | `xrootd_io_uring on` with probe failing | `nginx -t`/start exits non-zero with the explicit EMERG; server does not start (§32). Companion `srv_on_not_compiled_fails` covers the built-without-liburing case |
| `srv_ringfull_noloss` | low `queue_depth` (e.g. 8) under N-concurrent reads | every op completes correctly; `fallback_total{reason=ringfull}` climbs; **no dropped/duplicated/corrupted op**; byte-exact |
| `srv_build_no_liburing` | `XROOTD_ENABLE_IO_URING` unset → stubs | binary has no `-luring`; selector is a no-op; full suite green |
| `cli_build_no_liburing` | `HAVE_LIBURING= make` for the client | `--io-uring=on` errors cleanly; `auto`/`off` transfer correctly |

### 17.5 Kill-switch & security tests

| Test-id | Type | Action | Expected |
|---|---|---|---|
| `kill_flip_under_load` | success | drive concurrent reads, `POST {"enabled":false}` mid-stream | new ops route to pool on next op; in-flight CQEs drain (`inflight→0`); **zero op loss**; all responses byte-exact; `kill_switch→1` |
| `kill_reenable` | success | `POST {"enabled":true}` | `active→1` next tick (subject to probe); ops resume on ring |
| `kill_authz_none` | security-neg | `POST` with no token, source outside CIDR | `XROOTD_ADMIN_AUTH_DENIED`; audit `result=forbidden`; flag unchanged |
| `kill_authz_forged` | security-neg | `POST` with wrong bearer (length-mismatch and same-length) | constant-time compare rejects (`CRYPTO_memcmp`); flag unchanged; no timing oracle |
| `kill_authz_cidr` | security-neg | valid token, source outside `admin_allow` | denied in AND mode; audited |
| `kill_panic_file` | success | drop the panic-file; no token | watcher tick disables all workers; `panic_file_present→1`; survives `nginx -s reload`; removing it re-enables |
| `sec_impersonated_read_confined` | security-neg | impersonation on; attempt to read outside the broker-opened `RESOLVE_BENEATH` fd | impossible — ring only gets `fh->fd`; no path op available; path opcode barred by restrictions | 
| `sec_iowq_unprivileged` | security-neg | inspect io-wq creds while a ring op runs as a mapped user | io-wq inherits the **unprivileged worker** creds, never root; worker holds zero FS caps |

Anchor the admin-authz cases alongside the existing admin-API tests; reuse `xrootd_admin_check_auth` coverage patterns (bearer + CIDR, AND/OR modes).

### 17.6 UAF / memory tests (ASan/LSan + valgrind)

| Test-id | Action | Tool | Expected |
|---|---|---|---|
| `srv_uaf_disconnect_midread` | client disconnects during a large windowed read with CQEs still pending | ASan/LSan | generation guard drops the stale CQE (`stale_cqe_total`++); `ctx->destroyed` guard fires; **no UAF, no leak, no crash** |
| `srv_stale_cqe_generation` | force a CQE after its slot was freed and reused | unit `tests/c/` | gen mismatch → CQE dropped, `done_fn` not called; slot integrity preserved |
| `srv_write_payload_lifetime` | in-flight `IORING_OP_WRITE`; assert detached payload freed only post-CQE | ASan | payload alive across submit→CQE; freed exactly once in the done callback |
| `cli_regbuf_lifecycle` | disk-ring registered-buffer checkout/return across a transfer + early cancel | valgrind + `tests/lsan.supp` | every registered buffer returned; ring drains all in-flight before destroy; zero leaks |
| `cli_disconnect_midlargeread` | drop the transport mid-`~GiB` download under the io_uring engine | ASan/LSan | `ASYNC_CANCEL` + `fd_gen` clean up; reconnect resumes; no leak |

### 17.7 Resilience gate (client) — hard gate before CB-W4 ships

The fault-injection proxy and resilience suites must **all pass with the io_uring engine active**, proving `ASYNC_CANCEL`-on-drop + `fd_gen` + reconnect + `xrdc_mfile`-reopen recover **byte-perfectly**.

| Suite / artifact | Pass criterion (engine ON) |
|---|---|
| `tests/c/fault_proxy.c` (drop/delay/truncate injector) | every injected fault recovered; final bytes == source |
| `test_client_robustness.py` | all resilience scenarios green with `--io-uring=on` |
| `test_xrootdfs_resilience.py` | FUSE-over-`xrdc_mfile` recovers across drops (inherits engine via `xrdc_mgr`) |
| `test_write_recovery.py` | interrupted writes resume; no corruption |
| `tests/c/aio_resil.c`, `tests/c/aio_mfile.c` | cancel + fd_gen + mfile-reopen unit invariants hold |
| above under valgrind/LSan (`tests/lsan.supp`) | registered-buffer lifecycle clean |

### 17.8 Benchmark methodology

**Measure:** throughput (MiB/s seq GET/PUT), p99 op latency (from `submit_latency` + client-side wall time), **syscalls/op** (`strace -c -f` and `perf stat` — the headline io_uring win is fewer `read`/`write`/`io_submit` syscalls), io-wq vs worker CPU, and `submit_total/ops_total` batching ratio.

**Workloads:** sequential GET/PUT (raw throughput, disk/network overlap); many-small files (per-op overhead, batching); high-concurrency N parallel transfers (ring saturation); high-RTT (`tc-netem delay` in an **unprivileged user namespace**) (overlap value when latency dominates).

**Protocol:** per workload, run off vs on (and on+O_DIRECT for sequential NVMe), same corpus/host, ≥5 reps, report median + p99 and the syscall-count delta (robust to host noise in a way throughput is not).

**WSL2 caveat (load-bearing):** the build host is WSL2, where io_uring kernel behavior, `tc-netem`, and raw throughput are **not representative** — treat any local throughput/latency number as *untrustworthy* and informational only. The syscalls/op delta (`strace -c`) is the most portable local signal. Throughput/p99 acceptance numbers MUST be taken on a **real bare-metal/VM perf host** with a production-class kernel; WSL2 results are for smoke/regression-direction only.

### 17.9 CI integration

| Job | What it runs | When |
|---|---|---|
| `ci-uring-off` (always-green invariant) | full suite with `XROOTD_IO_URING_MODE=off`; build with **and** without liburing | every PR |
| `ci-uring-auto` | full suite `auto` (production default; degrades on the CI kernel if blocked) | every PR |
| `ci-parity` | backend-parity matrix (§17.1) over read/write/readv/pgread/dirlist + `test_integrity_matrix.py` across off/on/auto | every PR touching `src/aio/` or `client/lib/uring*` |
| `ci-asan-uring` | UAF/memory suite (§17.6) under ASan/LSan, engine on | every PR touching the backend |
| `ci-resilience-uring` | §17.7 gate, engine on, + valgrind | required before CB-W4 merges; nightly thereafter |
| `nightly-uring-on` | full suite `on` (hard-require), low-queue-depth spill cell, fallback matrix, restriction unit tests | nightly |
| `perf-uring` (manual / real host) | §17.8 benchmarks on a perf host (never WSL2) | release candidates |

**Always-green-with-uring-off invariant:** any failure in `ci-uring-off` blocks merge unconditionally; it proves the backend is a pure addition and the fallback tiers are intact.

### 17.10 Acceptance criteria per workstream

| Workstream | Acceptance |
|---|---|
| SB-W1 (build/gate) | compiles with/without liburing; selector no-op; `ci-uring-off` green |
| SB-W2 (ring + reaper + slots) | `IORING_OP_NOP` self-test lands; `stale_cqe` guard unit test green; no leak under ASan |
| SB-W3 (read/write) | `uring_read_ok`/`uring_write_ok` + error + sec-neg green; **parity matrix green off/on/auto** for read+write |
| SB-W4 (readv/writev+fsync) | readv/writev rows green; multi-fd `unmapped` fallback asserted; parity green |
| SB-W5 (fallback/budget) | §17.4 all green; `srv_ringfull_noloss` proves no op loss; budget/window behavior unchanged |
| §8 hardening | §17.5 all green; admin authz (none/forged/CIDR) reject + audit; panic-file disables fleet-wide and survives reload; restriction unit test bars path opcodes |
| CB-W2 (disk ring) | client byte-exact corpus green off/on/on+O_DIRECT; `cli_regbuf_lifecycle` clean under valgrind |
| CB-W3 (FUSE-local) | FUSE inherits ring; resilience smoke green |
| CB-W4 (engine swap) | **§17.7 resilience gate green with engine ON** (hard precondition); POLL_ADD TLS path byte-exact; default remains off |
| Observability (§16) | every new metric exported with correct low-cardinality labels; silent-fallback recording rule fires in a fault test; audit line emitted on every kill-switch flip |

---

## 18. Workstream task breakdown, sequencing & estimates

This section expands §5 ("Workstreams, sequencing & risk") into a granular, executable plan. §5 is the one-line summary per workstream; this section is the per-sub-task contract an engineer picks up directly. The same workstream IDs (SB-W1..W8, CB-W1..W6) carry the same scope; SB-W7/W8 (security) are slotted into the dependency graph below. **Invariant across every sub-task:** the tree builds and the full suite is green with the engine OFF — `xrootd_io_uring off` (server) / `--io-uring=off` (client) must show zero regression after *every* commit. No `goto` (use `*_create_fail()` unwind helpers, §4). `./configure` re-run whenever a new `.c` enters `ngx_module_srcs`.

Effort labels are **rough relative estimates** (person-days, single engineer familiar with the codebase): S ≈ 0.5–1 d, M ≈ 2–4 d, L ≈ 5–8 d. They size relative effort, not a schedule commitment.

### 18.1 SB-W1 — Build/gate + directives + tunables (selector no-op)

**Goal.** Land all build plumbing, directives, tunables, and a no-op selector hook so io_uring is a compile-time and config-time concept that does *nothing* yet. `xrootd_uring_worker()` returns NULL; the selector falls straight through to the thread pool.

**Deliverables.** `config` (pkg-config block, `ngx_module_srcs`/`ngx_module_libs`), `src/types/tunables.h` (depth + kernel-min macros), `src/config/*.c` (directive table + merge), NEW `src/aio/uring.h` (types + accessor decl), NEW `src/aio/uring.c` (accessor returns NULL stub).

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W1.1 | pkg-config gate | Add the `XROOTD_ENABLE_IO_URING` + `pkg-config --exists liburing` block to `config` (§3.1): set `-DXROOTD_HAVE_LIBURING=1`, `XROOTD_URING_LIBS=$(pkg-config --libs liburing)`. |
| SB-W1.2 | Module wiring | Put `-luring` into the stream module's `ngx_module_libs` (NOT `CORE_LIBS` — §3.1); add `src/aio/uring.c` (+ `uring_submit.c` placeholder) to `ngx_module_srcs`; `uring.h` to deps. |
| SB-W1.3 | Tunables | Add `XROOTD_IO_URING_QUEUE_DEPTH 256`, `_MIN_KERNEL_MAJOR/MINOR`, `_RESTRICT_KERNEL_MINOR` to `tunables.h`. |
| SB-W1.4 | Directives | Add `xrootd_io_uring on\|off\|auto` (`ngx_conf_set_enum_slot`) + `xrootd_io_uring_queue_depth N`; add the §8.1 hardening directives as parse-only no-ops (`_panic_file`, `_admin`, `_restrict`) so config files written for later WS already parse. |
| SB-W1.5 | Type + accessor | Define `xrootd_uring_t` (§9.1) in `uring.h`; in `uring.c` implement `xrootd_uring_worker()` returning NULL and `xrootd_uring_op_for(task)` returning `XRD_URING_OP_NONE`. |
| SB-W1.6 | Selector hook | Add the §10.7 selector skeleton to `xrootd_aio_post_task` (`src/aio/resume.c`) but with the uring branch guarded by `u && u->enabled` — since `u==NULL`, it is provably dead. Signature unchanged. |

**Acceptance.** (a) `./configure` with and without `XROOTD_ENABLE_IO_URING` both succeed; built without it, `nm module.so | grep io_uring` is empty. (b) `xrootd_io_uring auto` parses and starts nginx. (c) Full suite green. (d) `nginx -t` accepts all new directives.

**Dependencies.** None. **Risk.** Low — the one trap (`-luring` in `CORE_LIBS` → `dlopen` undefined-symbol) is pre-empted by SB-W1.2. **Effort.** S. **Rollback.** `git revert` the single SB-W1 commit; or leave merged and never set `XROOTD_ENABLE_IO_URING`.

### 18.2 SB-W2 — Ring lifecycle + eventfd bridge + reaper + slot table (KEYSTONE)

**Goal.** Stand up the per-worker ring, the eventfd→epoll bridge, the harvest loop, and the UAF-safe slot table — validated end-to-end with `IORING_OP_NOP` only. **No real data SQE in this WS.** Highest-risk WS; the NOP self-test is the hard gate before SB-W3 emits a single `IORING_OP_READ`.

**Deliverables.** `src/aio/uring.c` (lifecycle + reaper + slot table), `src/aio/uring.h`, `src/config/process.c` (init/exit hooks).

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W2.1 | Runtime probe | `xrootd_uring_runtime_available()` (§15.5): throwaway `io_uring_queue_init(8)` + `io_uring_get_probe` for READ/WRITE; memoize; one NOTICE on failure. Never `uname`. |
| SB-W2.2 | Ring create | `xrootd_uring_init_worker()`: `io_uring_queue_init(depth)` → `eventfd(EFD_NONBLOCK\|EFD_CLOEXEC)` → `io_uring_register_eventfd()` → `ngx_get_connection(eventfd)` wrap → `evc->read->handler = xrootd_uring_eventfd_handler`, `evc->data = u`, `ngx_add_event`. Any failure → log once, `enabled=0`, return NGX_OK. Mirrors `ngx_epoll_aio_init()` (§7.1). |
| SB-W2.3 | Reaper harvest loop | `xrootd_uring_eventfd_handler()`: `read(eventfd,&cnt,8)`; `io_uring_for_each_cqe` → decode slot, generation-check, `ngx_post_event(&task->event,&ngx_posted_events)`, `io_uring_cqe_seen()`. Does NOT call done-fn inline (§11.2). |
| SB-W2.4 | Slot table | `xrootd_uring_slot_t` table (§9.2): alloc/free with `generation` bump on free; `user_data = (gen<<32)\|idx`; mismatch drops stale CQE. |
| SB-W2.5 | NOP self-test | At end of `init_worker` (`auto`/`on`): submit one `IORING_OP_NOP` with a sentinel slot, assert the CQE harvests through the full slot→post path. On failure → `enabled=0`, NOTICE, fall back. |
| SB-W2.6 | Process hooks | Call `xrootd_uring_init_worker()` in `ngx_stream_xrootd_init_process()` after `xrootd_imp_init_worker`; teardown in `xrootd_exit_process()`: `ngx_del_event`+`ngx_close_connection(evc)`, `io_uring_unregister_eventfd`, `io_uring_queue_exit`, `close(eventfd)`. |
| SB-W2.7 | `xrootd_uring_worker()` live | Switch the accessor to return the per-worker singleton (was NULL). Selector's uring branch now reachable but `op_for` still NONE → still no real op. |

**Acceptance.** (a) `auto` on 5.6+: worker logs ring-created + NOP self-test passed; gauge `io_uring_active{worker}=1`. (b) seccomp-blocked / <5.6: NOTICE, `enabled=0`, suite green on pool. (c) ASan/LSan: start+stop+reload leaks nothing. (d) `op_for` still NONE ⇒ all data ops still take the pool (assert via metric). (e) Forced `register_eventfd` failure → clean fallback.

**Dependencies.** SB-W1. **Risk.** **High** — lifecycle ordering vs nginx fork, fake-connection teardown on reload, slot-table generation discipline. **Mitigation:** NOP self-test is a hard gate; teardown validated under ASan/LSan; ring create is a near-transcription of `ngx_epoll_module.c:248`. **Effort.** L. **Rollback.** Gate off; or `git revert` SB-W2 (SB-W1 no-op selector remains).

> **GATE G1 (hard stop): NOP self-test green before any real SQE.** SB-W3 may not begin until SB-W2.5 passes on the target kernel.

### 18.3 SB-W3 — READ/WRITE submit + CQE→OUT translation

**Goal.** Read and write actually flow through io_uring, covering single reads and the phase-31 windowed-read pump, with zero pump or done-callback changes.

**Deliverables.** NEW `src/aio/uring_submit.c` (`xrootd_uring_submit`, op_for table), `src/aio/uring.c` (OUT translation in reaper).

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W3.1 | op_for table | Populate `(worker_fn_ptr → op_kind)` (§10.7): `xrootd_read_aio_thread→READ`, `xrootd_write_aio_thread→WRITE`; others NONE. |
| SB-W3.2 | READ submit | `io_uring_get_sqe` (NULL → `*posted=0` fallback), `io_uring_prep_read` from `xrootd_read_aio_t`, stamp `user_data`, `io_uring_submit`, `inflight++`, `*posted=1`. |
| SB-W3.3 | WRITE submit | `io_uring_prep_write` from `xrootd_write_aio_t`; detached payload is the SQE source — alive until CQE (§10.2). |
| SB-W3.4 | READ OUT xlate | reaper op=READ: `if(res<0){io_errno=-res; nread=-1;} else nread=res;`. |
| SB-W3.5 | WRITE OUT xlate | op=WRITE: same into `nwritten`/`io_errno`; `res<len` flows to the existing short-write `kXR_IOError` branch. |
| SB-W3.6 | inflight accounting | Decrement on each harvested CQE; selector's `inflight < queue_depth` gates submission. |
| SB-W3.7 | Windowed-read ride | No code change — confirm `xrootd_read_window_pump` posts one window per `xrootd_aio_post_task` (depth-1/conn). |

**Acceptance.** Parity matrix (§17.1): `test_aio.py` + `test_write.py` off/on/auto → byte-identical responses. Error: truncated read / RO-fs write → same `kXR_IOError` frame under uring. Security-neg: negative offset / overflow / bad handle rejected pre-SQE (assert zero SQEs). ASan: mid-large-read disconnect drops stale CQE, no UAF.

**Dependencies.** SB-W2 (G1). **Risk.** Med — write-payload lifetime, short-read framing. **Mitigation:** parity matrix; ASan for payload lifetime. **Effort.** M. **Rollback.** Gate off; or `git revert` SB-W3.

### 18.4 SB-W4 — READV + single-fd WRITEV (+ linked FSYNC)

**Goal.** Single-group `readv` and single-fd `writev` with in-kernel write→fsync ordering; multi-fd/multi-group fall back to pool unchanged.

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W4.1 | op_for extend | Add readv/writev mapping; **guard:** multi-fd/group → NONE (pool). |
| SB-W4.2 | READV submit | `io_uring_prep_readv` from the coalesced segment group. |
| SB-W4.3 | WRITEV submit | `io_uring_prep_writev`; when `do_sync` chain `io_uring_prep_fsync` with `IOSQE_IO_LINK` (§10.4). |
| SB-W4.4 | Linked-error semantics | Failed writev cancels the linked fsync (`-ECANCELED`) — map both to `io_error`; assert no partial-sync-reported-success. |
| SB-W4.5 | OUT xlate | READV→`bytes_read_total`/`response_bytes`/`io_error`; WRITEV→`bytes_total`/`io_error`. |

**Acceptance.** `test_readv.py`, `test_readv_security.py` parity off/on/auto. Multi-fd/group assert pool path (metric). writev+fsync durability: sync-then-crash harness shows fsync ordering held. Negatives rejected pre-SQE.

**Dependencies.** SB-W3. **Risk.** Med — `IOSQE_IO_LINK` error/cancel semantics. **Mitigation:** SB-W4.4 linked-error test; multi-fd guard keeps hard cases on the pool. **Effort.** M. **Rollback.** Gate off; `git revert` SB-W4.

### 18.5 SB-W5 — Fallback + budget/window validation

**Goal.** Prove the three-tier cascade and the phase-31 budget/window interplay under adversarial conditions. Mostly tests.

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W5.1 | Ring-full cascade | Very low `queue_depth`; concurrent reads; assert overflow to pool→inline with **no dropped op**. |
| SB-W5.2 | get_sqe NULL | Fault-inject `io_uring_get_sqe`→NULL; clean fall-through to pool. |
| SB-W5.3 | Budget admission | `xrootd_budget_admit/sync` fires *before* dispatch regardless of backend; budget-deferred read still emits `kXR_wait`. |
| SB-W5.4 | Warm-cache probe retained | Phase-32 `preadv2(RWF_NOWAIT)` still returns synchronously (no SQE); only misses fall to the uring dispatcher. |
| SB-W5.5 | Seccomp/old-kernel matrix | Full read/write/readv suites in a seccomp-blocked container → NOTICE + clean `auto` degrade + green on pool. |

**Acceptance.** No op dropped under any forced-failure combination. Budget/wait identical across backends. Warm-cache probe demonstrably bypasses the ring.

**Dependencies.** SB-W3 (parallel with SB-W4). **Risk.** Low-Med. **Effort.** M. **Rollback.** Tests only.

> **GATE G2 (hard stop): resilience/fallback gate green before the engine ships beyond opt-in.**

### 18.6 SB-W7 — Runtime kill switch (SHM flag + admin endpoint + panic-file + metrics)

**Goal.** Implement the §8.1 four-level kill switch — cross-worker SHM atomic readable lock-free on the submit hot path, settable via admin API and a watched panic-file, with metrics + audit logging.

**Deliverables.** `src/compat/shm_slots.c` (`io_uring_disabled` atomic), `src/aio/resume.c` (hot-path read), `src/dashboard/api_admin.c` (endpoint), `src/config/process.c` (panic-file timer), `src/metrics/metrics.h` (gauges/counters).

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W7.1 | SHM atomic | Allocate `io_uring_disabled` via `xrootd_shm_table_alloc()` (`shm_slots.c:14`), dashboard transfer-table pattern. |
| SB-W7.2 | Hot-path read | One `ngx_atomic_load` in the §10.7 selector: if set, skip uring (→ pool → inline). |
| SB-W7.3 | Admin endpoint | `POST /xrootd/api/v1/admin/io_uring` in `api_admin.c`; reuse `xrootd_admin_check_auth()` + `admin_audit()`. |
| SB-W7.4 | Drain semantics | Flag stops *new* submissions only; reaper keeps harvesting in-flight CQEs (no op dropped). |
| SB-W7.5 | Panic-file watcher | `xrootd_io_uring_panic_file` coarse per-worker timer: `stat()`, update SHM flag. Survives reload; no token. |
| SB-W7.6 | Metrics + audit | Add `io_uring_active`/`ops`/`fallback` to `metrics.h`; one `NGX_LOG_NOTICE` per flip. |

**Acceptance.** §17.5 security tests: admin flip disables fleet-wide on next op; in-flight ops complete; bad token/off-CIDR → 401/403, no state change; panic-file disables without API, survives reload; `/metrics` reflects 1→0; audit NOTICE present.

**Dependencies.** SB-W2 + SB-W3. **Risk.** Med — hot-path atomic correctness; admin auth must reuse the audited path. **Mitigation:** reuse proven `ngx_atomic_t` + `admin_check_auth`/`admin_audit`; no new privileged code. **Effort.** M. **Rollback.** `xrootd_io_uring_admin off`; panic-file unset; or `git revert` SB-W7.

> **GATE G4 (hard stop): security tests green before enabling `restrict`/`admin` in a prod profile.**

### 18.7 SB-W8 — Privilege containment (register_restrictions + fd-provenance + impersonation interop)

**Goal.** Implement §8.2 / §14.4 containment: lock each ring to fd-only data opcodes, validate fd-provenance, prove interop with Phase-40 impersonation.

**Deliverables.** `src/aio/uring.c` (restricted setup), `src/aio/uring_submit.c` (fd-provenance assertion), interop tests. **Read-only consumers:** `src/impersonate/broker.c`, `src/fs/vfs_open.c`/`vfs.h`, `src/path/beneath.c`.

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W8.1 | Restricted setup | `IORING_SETUP_R_DISABLED` → `io_uring_register_restrictions()` (READ/WRITE/READV/WRITEV/FSYNC) → `io_uring_enable_rings()` (§14.4). Below 5.10: skip + NOTICE; containment via points 1–2. |
| SB-W8.2 | `xrootd_io_uring_restrict` | Wire the SB-W1.4 parse-only directive to enable/disable SB-W8.1 (default `on` where supported). |
| SB-W8.3 | fd-provenance check | In `xrootd_uring_submit`, assert `task->fd == xrootd_vfs_file_fd(fh)` (broker-opened `RESOLVE_BENEATH` fd). No path handling in submit. |
| SB-W8.4 | Impersonation interop | Confirm io-wq inherits the worker's unprivileged creds; submit the same fd the pool worker would have `pread`'d. No broker ring. |
| SB-W8.5 | Deployment doc hook | Document non-impersonation posture: run workers as a non-root service account (§8.2.4 / §14.4). |

**Acceptance.** §17.5: path-opcode submit (OPENAT/STATX/UNLINKAT) → rejected (`-EACCES`/setup failure); impersonation suite passes with uring active (io-wq cred verified); restrictions-unsupported kernel → skipped + NOTICE + containment asserted; fd-provenance fires on a forged fd.

**Dependencies.** SB-W2, SB-W3. **Risk.** Med — `R_DISABLED`/`register_restrictions`/`enable_rings` ordering, kernel skew. **Mitigation:** below-5.10 fallback; layered containment. **Effort.** M. **Rollback.** `xrootd_io_uring_restrict off`; or `git revert` SB-W8 (gate behind G4 so prod never ships unrestricted).

### 18.8 SB-W6 — Docs + deferred-tier stubs

**Goal.** Ship README/ops docs and flag the §33 deferred tiers.

| # | Sub-task | Concrete change |
|---|---|---|
| SB-W6.1 | Enable docs | Document `XROOTD_ENABLE_IO_URING`, the five directives, non-root-worker posture. |
| SB-W6.2 | Kernel/seccomp matrix | Document the §7.7 reality + the probe/fallback behavior. |
| SB-W6.3 | Deferred stubs | Flag SQPOLL, registered files/buffers, uring-pgread hybrid, `IORING_OP_GETDENTS`, personalities (§33) as designed-not-shipped, each with its future flag name. |

**Acceptance.** Docs reviewed; every shipped directive documented; deferred tiers enumerated. **Dependencies.** SB-W4. **Risk.** Low. **Effort.** S. **Rollback.** Docs only.

### 18.9 CB-W1 — Client build/detect/probe + `--io-uring`/env + `xrdc_copy_opts.io_uring`

**Goal.** Mirror SB-W1 on the client: build gating, runtime probe, CLI/env plumbing, the tri-state — with `uring.c` compiling to inert stubs when liburing is absent.

| # | Sub-task | Concrete change |
|---|---|---|
| CB-W1.1 | Makefile gate | `HAVE_LIBURING` block (§15.4); `lib/uring.c` *always* in `LIB_SRCS` (krb5-stub model). |
| CB-W1.2 | New TU | `client/lib/uring.{c,h}`: `xrdc_uring_available()` (memoized probe), `xrdc_disk_ring_create/destroy` decls. No `xrdc.h` socket includes. |
| CB-W1.3 | Stubs | When undefined: `available→0`, `create→NULL+status`; no `-luring`. |
| CB-W1.4 | Probe | §15.5 client probe (READ/WRITE now; POLL_ADD/RECV/SEND/ASYNC_CANCEL deferred to CB-W4); memoize. |
| CB-W1.5 | opts tri-state | Add `io_uring` (0=auto/1=on/2=off) to `xrdc_copy_opts` in `xrdc.h`. |
| CB-W1.6 | CLI + env | Parse `--io-uring=auto\|on\|off`; read `XRDC_IO_URING` once under `pthread_once`. |

**Acceptance.** Builds with/without liburing (`HAVE_LIBURING= make`); without it, `--io-uring=on` errors cleanly, `auto`/`off` work; `ldd` shows no liburing in the stub build. **Dependencies.** None. **Risk.** Low. **Effort.** S. **Rollback.** `git revert` CB-W1.

### 18.10 CB-W2 — `xrdc_disk_ring` + `copy.c` uring adapters (Option A) + O_DIRECT (LEAD CLIENT WS)

**Goal.** Deep-queue local-disk ring + two pump adapters so disk/network overlap, with the pump and all remote adapters byte-for-byte untouched (§12, Option A).

| # | Sub-task | Concrete change |
|---|---|---|
| CB-W2.1 | Disk ring | `xrdc_disk_ring_create/destroy`: ring + registered-buffer pool, depth-N read-ahead/write-behind. Unwind via `*_create_fail()`. |
| CB-W2.2 | Source adapter | `pump_src_local_uring`: depth-deep `IORING_OP_READ` read-ahead; synchronous in-order one-chunk face. |
| CB-W2.3 | Sink adapter | `pump_sink_local_uring`: depth-deep `IORING_OP_WRITE` write-behind; one memcpy (Option A price). |
| CB-W2.4 | Ordered completion | Release chunk *k* only after op *k* completes. |
| CB-W2.5 | O_DIRECT tier | Behind `direct`: `posix_memalign`, block-aligned; unaligned tail falls back. Default off. |
| CB-W2.6 | opts wiring | Flow `xrdc_copy_opts.io_uring` + `direct`; `transfer_pump` and remote adapters untouched. |
| CB-W2.7 | Drain on destroy | Ring drains all in-flight before `destroy`. |

**Acceptance.** Byte-exact xrdcp: SHA256 over the corpus in every direction with off/on/on+O_DIRECT → identical hashes (`test_native_xrdcp_xrdfs.py`/`test_client_xrdcp_bulk.py`). Fallback: `HAVE_LIBURING= make` → `on` errors, `auto`/`off` correct. valgrind/LSan clean. Short-read/disk-full → same `xrdc_status` as the plain adapter.

**Dependencies.** CB-W1. **Risk.** Low (isolated behind one adapter). **Mitigation:** ordered-completion + drain-on-destroy under LSan; O_DIRECT default-off. **Effort.** L. **Rollback.** `--io-uring=off`; or `git revert` CB-W2.

> **GATE G3 (hard stop): CB-W2 byte-exact + fallback tests green before CB-W4 starts.**

### 18.11 CB-W3 — Disk ring exposed to loop / FUSE-local path

**Goal.** Make the disk ring reachable from the loop-thread local-disk path so `xrootdfs_aio` inherits overlap with no driver changes. Socket readiness stays epoll (§13 sub-option i).

| # | Sub-task | Concrete change |
|---|---|---|
| CB-W3.1 | Loop-thread reach | Make `xrdc_disk_ring` reachable from the loop-thread local-disk path without touching the readiness engine. |
| CB-W3.2 | FUSE inherit | Confirm `xrootdfs_aio` write-back/read-ahead overlaps via the ring — no driver changes. |
| CB-W3.3 | Readiness unchanged | Assert socket readiness still on epoll (validates build/detect/fallback against the resilient core before CB-W4). |

**Acceptance.** FUSE-local overlap improves throughput, no correctness change; readiness provably still epoll; suite green off/on/auto. **Dependencies.** CB-W2. **Risk.** Low-Med. **Effort.** M. **Rollback.** `--io-uring=off`; `git revert` CB-W3.

### 18.12 CB-W4 — `aio.c` engine vtable: POLL_ADD multishot, then cleartext RECV/SEND, `fd_gen`, ASYNC_CANCEL (default OFF)

**Goal.** Engine vtable so epoll and io_uring coexist; ship `IORING_OP_POLL_ADD` multishot first (TLS-safe), then cleartext `RECV/SEND` multishot, with `ASYNC_CANCEL`-on-drop + `fd_gen`. **Default OFF.** Highest client risk.

| # | Sub-task | Concrete change |
|---|---|---|
| CB-W4.1 | Engine vtable | Extract `arm`/`wait`/`wake`/`cancel` (§13.1); epoll impl = today's code. Select at `xrdc_loop_create`. Suite green with epoll engine (refactor-only commit). |
| CB-W4.2 | POLL_ADD engine | io_uring `arm` = multishot `IORING_OP_POLL_ADD`; `wait` = `io_uring_wait_cqe_timeout` + dispatch. Loop still runs `aconn_do_read`/`do_write` → `SSL_*` keep their syscalls (TLS-safe). |
| CB-W4.3 | eventfd wake | Keep the existing cross-thread eventfd observed by the ring; `wake` unchanged on the writer side. |
| CB-W4.4 | fd_gen | Add `uint32_t fd_gen` to `xrdc_aconn`, stamped into `user_data`; drop late CQEs for a recycled aconn. |
| CB-W4.5 | ASYNC_CANCEL | On transport error, `epoll_ctl(DEL)` → `IORING_OP_ASYNC_CANCEL`; reconnect re-arms the new fd. |
| CB-W4.6 | Cleartext RECV/SEND | Follow-on: swap only the `ac->ssl==NULL` branch to multishot `RECV/SEND` + provided buffers. TLS stays POLL_ADD. |

**Acceptance (resilience gate).** Client-resilience suite **all green with the engine active**: `fault_proxy.c` + `test_client_robustness.py`, `test_xrootdfs_resilience.py`, `test_write_recovery.py`, `aio_resil`, `aio_mfile`. valgrind/LSan for registered-buffer lifecycle. Byte-exact xrdcp parity with the engine on. `--io-uring=off` (default) unaffected.

**Dependencies.** CB-W1 + CB-W3, **and G3**. **Risk.** **High** — touches the resilient transport; TLS constraint means only cleartext goes true-async. **Mitigation:** POLL_ADD first; `fd_gen`+`ASYNC_CANCEL` under fault-injection; default off; G3 gate. **Effort.** L. **Rollback.** `--io-uring=off`; or `git revert` CB-W4.

### 18.13 CB-W6 — FUSE verification

**Goal.** Verify FUSE with both the disk ring and the loop engine; legacy `xrootdfs` untouched. Test-only.

| # | Sub-task | Concrete change |
|---|---|---|
| CB-W6.1 | FUSE-on-uring | `xrootdfs_aio` over a real mount with `--io-uring=on`: read/write/stat/readdir correctness vs `off`. |
| CB-W6.2 | Resilience | `test_xrootdfs_resilience.py` with the engine active. |
| CB-W6.3 | Legacy untouched | Assert legacy `xrootdfs` behavior unchanged; document as non-resilient. |

**Acceptance.** FUSE correctness + resilience green with uring on; legacy byte-identical. **Dependencies.** CB-W2 + CB-W4. **Risk.** Low. **Effort.** S. **Rollback.** Tests only.

### 18.14 Master sequencing — dependency DAG, parallelism, critical path

Server and client are **fully independent** (no shared TU; client links no nginx — §7.6).

```
SERVER track:
  SB-W1 ──► SB-W2 ──►[G1 NOP]──► SB-W3 ──┬──► SB-W4 ──► SB-W6
                                          ├──► SB-W5 ──►[G2 resilience]
                                          ├──► SB-W7 ──┐
                                          └──► SB-W8 ──┴──►[G4 security]

CLIENT track (independent of server):
  CB-W1 ──► CB-W2 ──►[G3 byte-exact]──► CB-W3 ──► CB-W4 ──► CB-W6
```

| Edge | Reason |
|---|---|
| SB-W1→SB-W2 | ring needs build/types/directives |
| SB-W2→SB-W3→SB-W4 | bridge → read/write → vectored |
| SB-W3→{SB-W5, SB-W7, SB-W8} | fallback/kill-switch/containment need real ops |
| SB-W2→{SB-W7,SB-W8} | kill switch + restrictions need a live ring |
| SB-W4→SB-W6 | docs after final op surface |
| CB-W1→CB-W2→CB-W3→CB-W4→CB-W6 | gate chain (G3) |
| CB-W1→CB-W4 | engine needs build/probe |

**Parallelizable.** Whole server track ∥ whole client track. After SB-W3: SB-W4/W5/W7/W8 can run concurrently (distinct files; all touch the §10.7 selector — serialize that edit or rebase). **Critical path.** Server: SB-W1→W2→W3→W4→W6 (S+L+M+M+S). Client: CB-W1→W2→W3→W4→W6 (S+L+M+L+S) — the longest single chain, dominating phase duration.

**Commit boundaries.** **One atomic commit per workstream**, so `git revert <WS-commit>` cleanly removes it and leaves the tree green. Large WS (SB-W2, CB-W2, CB-W4) split into sub-commits that *each* stay green with the engine off; tag the WS-final commit for revert. The §10.7 selector edit lands once (SB-W1) and is *extended* (not rewritten) by SB-W3/W4/W7.

### 18.15 Milestone plan (shippable, independently revertable increments)

Each milestone ends green with the engine OFF and is independently revertable.

| Milestone | Workstreams | Ships | Gate |
|---|---|---|---|
| **M1** | SB-W1 | No-op build: directives parse, selector dead, zero runtime effect | — |
| **M2** | SB-W2 | NOP-validated per-worker ring + eventfd bridge + slot table; no real op | **G1** |
| **M3** | SB-W3 | READ/WRITE live + backend parity matrix green | — |
| **M4** | SB-W4 + SB-W5 | READV/WRITEV(+fsync) live; three-tier fallback proven | **G2** |
| **M5** | SB-W7 + SB-W8 | Kill switch (admin+panic-file+SHM+metrics) + containment (restrictions+provenance) | **G4** |
| **M6** | SB-W6 | Server docs + deferred-tier stubs (server feature-complete) | — |
| **M7** | CB-W1 | Client build/detect/probe + flags (stubs when no liburing) | — |
| **M8** | CB-W2 | Disk-ring xrdcp adapters + O_DIRECT; byte-exact SHA256 green | **G3** |
| **M9** | CB-W3 | Disk ring exposed to loop/FUSE-local | — |
| **M10** | CB-W4 | Engine vtable + POLL_ADD (then cleartext RECV/SEND); resilience suite green, default off | resilience |
| **M11** | CB-W6 | FUSE verified end-to-end (client feature-complete) | — |

M1–M6 (server) and M7–M11 (client) are independent tracks; a team of two runs them concurrently. Each milestone is a tag; rolling back to any prior milestone is a `git revert` of the milestones above it.

### 18.16 Definition of Done — per workstream and phase

**Per-workstream DoD.** (1) Tree builds with and without liburing/`XROOTD_ENABLE_IO_URING`. (2) Full suite green with engine **off** (zero regression). (3) The WS's own acceptance criteria green. (4) One atomic, revertable commit. (5) No `goto`; every new function carries a WHAT/WHY/HOW block. (6) `./configure` re-run documented if a new `.c` was added.

**Overall phase DoD.** (a) **Parity matrix green** off/on/auto on both sides — byte-for-byte identical client-visible behavior. (b) **Resilience gate green with the engine on** (server fallback cascade + client fault-injection suite). (c) **Security tests green** — kill switch (admin+panic-file+SHM hot-read), containment (`register_restrictions` + unprivileged-worker + fd-provenance + impersonation interop). (d) **Docs + metrics shipped**. (e) Engine **off by default** everywhere; every milestone independently green and revertable.

### 18.17 Hard gates (consolidated)

| Gate | Rule | Blocks |
|---|---|---|
| **G1** | `IORING_OP_NOP` self-test green before any real SQE | SB-W3 (and all later server op WS) |
| **G2** | server fallback/resilience + budget suite green | recommending `auto` as a default in any profile |
| **G3** | CB-W2 byte-exact + fallback tests green | **CB-W4 start** |
| **G4** | SB-W7 + SB-W8 security suites green | enabling `restrict`/`admin` in a prod profile |

These are stop-the-line gates: a red gate blocks the dependent workstreams entirely. G1 protects against an unvalidated bridge corrupting real I/O; G3 enforces the §5 rule that the proven disk path precedes the resilient transport engine; G4 ensures no new admin/kernel surface ships to production unvetted.

---

## 19. Risk register, open questions & glossary

This section closes out the detailed plan. It enumerates every material risk, the open decisions with their current resolution, the assumptions and dependencies, the explicit non-goals, and a glossary of every term used across the document.

### 19.1 Risk register

Likelihood/Impact are L/M/H. "Detection" is how the failure surfaces. "Mitigation" is the design mechanism already specified (not new work). "Residual" is what remains after the mitigation.

| ID | Cat | Description | L | I | Detection | Mitigation (in design) | Residual |
|---|---|---|---|---|---|---|---|
| R-01 | security | UAF: connection drops mid-op, task/ctx freed, then a CQE arrives and the reaper dereferences freed `*_aio_t`/`ctx`. | M | H | ASan/LSan crash in the mid-large-read teardown test; SIGSEGV in `xrootd_uring_eventfd_handler`. | Two-layer guard: slot-table generation guard drops stale CQEs (§9.2); done-callback's own `xrootd_aio_restore_stream/request()` + `ctx->destroyed` check remains authoritative (§11.3). Never put a raw task pointer in `user_data`. | Very low: requires a 2^32 generation-wrap collision AND a freed ctx in the same op. |
| R-02 | technical | Stale CQE for a recycled slot: slot freed and re-allocated before the old CQE is harvested; old result applied to the new task. | M | H | Wrong byte counts in parity matrix. | `user_data = (gen<<32)\|idx`; generation bumped on free; mismatch → CQE dropped (§9.2). | Same 2^32-wrap edge; negligible. |
| R-03 | technical | eventfd does not wake epoll (edge vs level / counter handling); completions stall. | M | H | Hang under load; `active=1` but `inflight` monotonically rising; test timeout. | Mirror core's libaio bridge exactly (§11.1); reaper drains the 8-byte counter first. Land behind the `IORING_OP_NOP` self-test (SB-W2). | Low: the NOP self-test catches a mis-wired bridge at init → `enabled=0`. |
| R-04 | perf/op | Ring-full silent degradation: everything quietly runs inline-sync, throughput collapses without signal. | M | M | `io_uring_fallback{ringfull}` climbing while `ops` flat; latency rises. | Selector checks `inflight < queue_depth` and falls to pool→inline; no op dropped (§10.7). Fallback metric makes it visible (§16). Window pump posts depth-1/conn so windowed reads never self-exhaust. | Operator must watch the fallback metric; depth tuning is manual. |
| R-05 | technical | Mixed-ABI struct crash: partial build links liburing-on objects against liburing-off objects; struct layouts disagree → corruption. | L | H | Random crash only in incrementally-built trees; clean on full rebuild. | `./configure` re-run mandatory when toggling the flag (§15.1); single `-D` gates the whole TU; `uring.c` stubs out when undefined. | Low: only bites a dev who edits the flag without reconfiguring; CI does clean builds. |
| R-06 | technical | `-luring` in `CORE_LIBS` instead of `ngx_module_libs` → `.so` `dlopen` fails: `undefined symbol: io_uring_*`. | M | H | nginx start fails immediately. | Build governance rule explicit: `-luring` → `ngx_module_libs`, never `CORE_LIBS` (§15.1, §7); client mirrors `HAVE_KRB5`. | None once the rule is followed; a regression is loud and immediate. |
| R-07 | perf | CRC32c lands on the event thread if a future tier moves pgread onto io_uring naively. | L | M | Event-loop latency spike correlated with pgread traffic. | pgread stays on the thread pool in the first cut (§10.6); the deferred uring-pgread tier is explicitly *hybrid* (uring read → pool CRC32c) (§33). | Only materializes if the hybrid rule is violated; design forbids it. |
| R-08 | security | io_uring kernel CVE: a new vuln is disclosed; the fleet is exposed until patched. | M | H | Public CVE / advisory. | Four-level kill switch incl. the no-restart hot path (§8.1, §14.3); build-time master-off and config-off-on-reload as deeper levels; off-by-default limits baseline exposure. | Window between disclosure and operator flipping the switch; panic-file watcher latency (R-19). |
| R-09 | security/op | seccomp blocks `io_uring_setup` (Docker/containerd defaults, ChromeOS/Android posture). | H | L | Ring init fails; one NOTICE; `active=0`. | Authoritative runtime probe; failure → permanent silent fallback (§15.5, §4). `auto` degrades clean; **`on` fails startup (§32, ADR-16)**. | None functional — expected in hardened environments; only the perf benefit is forfeited. |
| R-10 | security | `register_restrictions` unavailable (<5.10): the opcode-whitelist layer is absent. | M | M | Probe reports unsupported; restriction step skipped; logged. | Containment does not depend on restrictions alone: worker is unprivileged + fd is broker-opened `RESOLVE_BENEATH` (§14.4 points 1–2). Restrictions are best-effort, default `on` where supported. | Defense-in-depth reduced by one layer on old kernels; primary containment still holds. |
| R-11 | technical | Client registered-buffer leak: a buffer checked out on submit whose CQE never returns it. | M | M | LSan/valgrind growth; `xrdc_disk_ring` pool exhaustion → stalls. | Ring drains all in-flight before `destroy`; buffers owned by the ring pool, returned on CQE; `*_create_fail()` unwind, no `goto` (§12.2, §12.7). LSan in CI. | Low with drain-before-destroy; the LSan gate is the backstop. |
| R-12 | technical/op | Engine swap regresses resilience/reconnect (`ASYNC_CANCEL`/`fd_gen`/reconnect/`xrdc_mfile`). | M | H | `test_client_robustness.py`/`test_xrootdfs_resilience.py`/`test_write_recovery.py`/`aio_resil`/`aio_mfile` fail with the engine active. | CB-W4 default-off and gated: cannot start until CB-W2 green; full fault-injection suite must pass with the engine active (§17.7). `fd_gen` drops late CQEs; parked retry + mfile-reopen sit above the engine (§13.6). | Contained by the hard gate + default-off; risk is to the optional tier only. |
| R-13 | technical | TLS + io_uring: intercepting OpenSSL's fd syscalls with `RECV/SEND` breaks TLS. | L | H | TLS handshake/record corruption; only if cleartext-only rule is violated. | TLS conns stay on `POLL_ADD` readiness and keep `SSL_read`/`SSL_write`; only `ac->ssl==NULL` may go RECV/SEND (§13.7). | None if the cleartext-only gate holds; memory-BIO/kTLS interception is out of scope. |
| R-14 | perf/op | Memory budget overrun from registered buffers (client pool, or a future server tier). | L | M | Footprint accounting drift; RSS above the phase-31 ceiling. | First cut reads into the *same* scratch buffers — footprint identical (§11.6). Deferred server registered-buffers tier must add its bytes to `xrootd_budget_ctx_footprint` before shipping (§9.9). Client ring pool bounded by `depth`×`bufsz`. | Only if a deferred tier ships without the footprint update; the rule is stated. |
| R-15 | perf/sched | Throughput regression / no measurable win — effort spent for nothing; an io_uring read still costs one epoll cycle vs the retained `RWF_NOWAIT` fast path. | M | M | Parity passes but A/B throughput on/off is flat or negative. | Off-by-default → no regression to the shipped default. `RWF_NOWAIT` warm-cache probe *retained* so hot reads never pay an extra cycle (§11.6). WSL2 throughput is untrustworthy → measure on real hardware (§17.8). Parity is the gate, not a throughput promise. | The capability ships proven-correct; the perf payoff is environment-dependent and not guaranteed (a stated non-goal). |
| R-16 | perf/op | SQPOLL CPU burn: a per-worker kernel poller thread consumes a CPU even when idle. | L | M | Per-core CPU pinned with no traffic. | SQPOLL is a deferred tier, opt-in, default off; needs registered files + a kernel-thread CPU budget (§11.5, §33). | None in the default config; operator opt-in only. |
| R-17 | technical | Partial-write / short-IO mishandling: io_uring returns a short `res` and the translation mis-handles it vs the syscall path. | M | M | `test_write.py` short-write assertions; byte-count mismatch. | CQE→OUT translation maps `res` into the same OUT fields the worker fn sets; short writes hit the existing `kXR_IOError("short write")` branch (§9.6, §10.2). Client ordered-completion releases chunk *k* only after op *k* (§12). | Low: the existing error branch is reused; parity tests assert frame-identity. |
| R-18 | security/op | Kill-switch race: an op is in flight when the flag is flipped. | L | L | Audit log shows a flip. | Defined drain semantics: flipping stops *new* submissions only; the reaper harvests in-flight CQEs to completion — no op dropped (§14.3). Optional teardown only once `inflight==0`. | None: behavior is specified and safe. |
| R-19 | op/security | Panic-file watcher latency: coarse per-worker timer stats the file only every few seconds. | M | L | Time between dropping the file and `active→0`. | Documented as a coarse (seconds) timer — the "2 a.m. CVE" switch, reload-free (§8.1 level 4). For instant disable use the admin API (level 3). | Seconds of residual exposure via the file path; admin API is the fast path. |
| R-20 | security | Admin endpoint as a new attack surface. | L | M | Audit log on every flip; auth failures logged. | Reuses phase-23 admin path verbatim: `xrootd_admin_check_auth()` (constant-time bearer + CIDR) + `admin_audit()`; gated behind `xrootd_io_uring_admin on` (default off). Worst case the endpoint only *disables* (fail-safe) or re-enables io_uring. | Inherits the existing admin-API trust model; toggling is the only capability and it fails safe. |
| R-21 | technical | Provided-buffer exhaustion (client deferred cleartext RECV multishot). | L | M | Multishot RECV reports `-ENOBUFS`; throughput stalls on cleartext links. | Provided buffers are a deferred follow-on, default off; `POLL_ADD` ships first with no provided-buffer dependency (§13.4, §33). `-ENOBUFS` re-arms readiness and refills — recoverable. | Confined to the deferred true-async tier; readiness fallback covers exhaustion. |
| R-22 | op | Privileged-namespace exposure: io_uring reachable as root. | L | H | Code/deployment review. | Impossible by construction: the root broker never touches io_uring; the ring lives in the unprivileged worker on a broker-opened `RESOLVE_BENEATH` fd; ring restricted to fd-only opcodes (§14.4). Non-impersonation deployments run workers as a non-root service account. | None by construction in the impersonation case; deployment guidance covers the non-impersonation case. |

### 19.2 Open questions / decisions log

| ID | Question | Options | Current decision | Rationale | Status |
|---|---|---|---|---|---|
| Q-01 | Ship the client event-loop engine swap (`aio.c`) at all, vs disk-ring only? | (a) disk-ring only; (b) also ship engine swap. | Ship CB-W2/W3 unconditionally; ship CB-W4 **default-off**, gated behind CB-W2 green + the full resilience suite. | Disk ring is high-value/low-risk and isolated; the engine swap is high-risk and touches the resilient transport, so it earns its way in behind a hard gate and stays off by default. | decided |
| Q-02 | Use registered/fixed files & buffers in the first cut? | (a) plain fds + caller buffers; (b) registered from day one. | First cut: **plain fds + existing scratch** on the server; client ring owns a registered-buffer pool but no fixed *files*. Registered files/buffers are a deferred server tier. | Keeps phase-31 budget accounting identical (no new footprint), reuses unchanged scratch, avoids lifecycle complexity until the base path is proven (§11.6, §33). | decided |
| Q-03 | Ever move pgread onto io_uring? | (a) keep on pool; (b) full uring incl. CRC; (c) hybrid uring-read → pool-CRC. | Keep pgread on the **thread pool** first cut; design a **hybrid** as a deferred tier. | Full-uring pgread runs CRC32c on the event thread (R-07); the hybrid keeps the encode off the loop (§10.6, §33). | open (deferred tier designed) |
| Q-04 | SQPOLL default? | (a) off; (b) on; (c) auto. | **Off**; opt-in via `xrootd_io_uring on sqpoll`. | SQPOLL needs registered files to pay off and burns a per-worker kernel-thread CPU even when idle (R-16). | decided |
| Q-05 | Also offer libaio via nginx `aio on;`? | (a) yes; (b) no. | **No.** io_uring + thread-pool fallback only; `aio on;` stays off. | `aio on;` is read-only, O_DIRECT-only (bypasses page cache, blocks on unaligned tails), no batching, unreachable per-op from the state machine (§7.3). io_uring is the capability superset. | decided |
| Q-06 | Minimum supported kernel? | 5.1 / 5.6 / 5.10 / 5.19. | Server baseline **5.6**; restrictions best-effort at **5.10**; client cleartext multishot RECV needs **5.19/6.0** (deferred). | The eventfd bridge is reliable from ~5.6; restrictions harden but containment holds without them; multishot recv is a far-future opt-in. Probe is authoritative regardless (§15.6). | decided |
| Q-07 | Add `IORING_OP_GETDENTS` for dirlist later? | (a) never; (b) add on new kernels. | dirlist stays on the **thread pool**; `GETDENTS` flagged as a deferred, very-new-kernel-only tier. | Not a single io_uring op; `GETDENTS` is very new and helper-less; dirlist is not on the hot data plane (§10.6, §33). | open (deferred, low priority) |
| Q-08 | Per-identity io_uring personalities first cut? | (a) no; (b) yes. | **No.** Unprivileged-worker + confined-fd + opcode-restriction is the first-cut containment; personalities are a deferred tier. | `register_personality` captures the *registering thread's* creds and is ring-local, so per-tenant personalities need the broker's creds + a broker-owned ring — larger than warranted given §14.4 points 1–3 already contain the surface. | decided |
| Q-09 | O_DIRECT default (client copy)? | (a) off; (b) on; (c) auto. | **Off**; opt-in per-invocation via `direct`. | O_DIRECT helps large sequential NVMe, hurts small/cached, forces block alignment with a tail fallback — never safe to make automatic (§12.8). | decided |
| Q-10 | Queue depth default? | (a) 256; (b) higher; (c) auto-size. | **256**, tunable via `xrootd_io_uring_queue_depth N` / ring-create `depth`. | The window pump posts depth-1/conn so 256 amply covers concurrent connections; ring-full falls back, never drops (§10.7, §15.3). | decided |
| Q-11 | Auto-trip the kill switch on a CQE-error-rate threshold? | (a) manual only; (b) auto-disable on threshold. | **Manual only** first cut; auto-trip noted but not committed. | Per-op CQE errors already fall back per-op and translate to the same `kXR_IOError`, so an error storm degrades gracefully without auto-disabling; an automatic global trip risks flapping and masking application-level errors as backend faults. Revisit once telemetry exists. | open |
| Q-12 | Client Option A (memcpy) vs Option B (pump-bypass) first? | (a) A; (b) B. | Ship **Option A**; defer B. | A keeps the pump's tested cancel/progress/short-read discipline byte-for-byte and isolates the change behind one adapter; the memcpy is the price, overlap is the gain (§12.10). | decided |

### 19.3 Assumptions & dependencies

| ID | Assumption / dependency | Hard? | Failure mode if violated | Where checked |
|---|---|---|---|---|
| D-01 | **liburing** discoverable via `pkg-config liburing` (server `config`, client `Makefile`). | No (optional) | Backend compiles to inert stubs; thread-pool/epoll/poll only; no `-luring` in the binary. | §15.1, §15.4 |
| D-02 | **Kernel ≥ 5.6** at runtime for the server eventfd bridge; 5.10 for restrictions (best-effort); 5.19/6.0 for client cleartext multishot RECV (deferred). | No (probe-gated) | Probe fails → permanent silent fallback; one NOTICE. | §15.5, §15.6 |
| D-03 | nginx built **`--with-threads`** (the always-present fallback tier). | **Yes** | No fallback tier; backend cannot ship. | §15.1 |
| D-04 | The **Phase-40 impersonation broker** provides broker-opened `RESOLVE_BENEATH` fds via `SCM_RIGHTS` (the containment story). | Yes (for the containment claim) | Without it, the worker opens as its own uid; run workers as a non-root service account — containment via non-root + confined fd still holds. | §14.4 |
| D-05 | The **phase-23 admin API + SHM infra** exist (`xrootd_admin_check_auth`, `admin_audit`, `xrootd_shm_table_alloc`). | Yes (for the hot kill switch) | No no-restart kill switch (level 3); operators fall back to reload / panic-file / build-off. | §8.1, §14.3 |
| D-06 | The **phase-31 budget** and **phase-32 `RWF_NOWAIT` probe** remain above the dispatch seam. | Yes | Budget drift (R-14) / loss of the hot-read fast path (R-15). First cut reads into the same scratch to preserve both. | §11.6 |
| D-07 | nginx core's **posted-events queue**, **connection/event objects**, and **thread pool** are available via public APIs. | Yes | The eventfd bridge and fallback tier cannot be built without patching core — forbidden. | §7.1, §7.4 |
| D-08 | The single dispatch seams are stable: server `xrootd_aio_post_task()` signature, client `pump_src_fn`/`pump_sink_fn` + the `aio.c` engine. | Yes | Interposition point moves → selector/adapter rework. The plan keeps both signatures unchanged to anchor this. | §10.7, §12 |

### 19.4 Explicit non-goals

| ID | Non-goal | Why out of scope |
|---|---|---|
| N-01 | **Network io_uring on the server** (socket recv/send/sendfile). | Egress is nginx-core-owned (`c->recv`/`c->send_chain`/`sendfile`/kTLS); build governance forbids patching `src/core`,`src/event`,`src/http`. Server io_uring is strictly disk I/O (§0, §7.1). |
| N-02 | **A core nginx io_uring event module** (the `ngx_event_actions_t` poller). | Event modules compile into the core binary and register in core's module list; an `--add-module` addon cannot add one without forking nginx, and it swaps the poller process-wide (§7.5). |
| N-03 | **Replacing the thread pool entirely.** | The thread pool is the always-present fallback tier (`--with-threads` hard-required); the cascade is io_uring → pool → inline. io_uring is additive (§1, §10.7, §7.3). |
| N-04 | **io_uring for dirlist / path-based metadata** (open, statx, getdents, rename, unlink, xattr). | Not single io_uring ops / very-new-kernel-only, off the hot data plane, and deliberately *excluded* from the opcode whitelist so the ring can never open or traverse a namespace (§10.6, §14.4). |
| N-05 | **Changing any wire framing or invariants.** | The backend moves bytes, not framing: pgread `kXR_status(4007)` + per-page CRC32c, TLS `b->memory=1`, cleartext `sendfile`, `resolve_path()` before `open()` all untouched (§4). |
| N-06 | **Guaranteeing a throughput win on WSL2 (or any specific host).** | WSL2 throughput is untrustworthy; the acceptance gate is backend *parity*, not a perf number. Perf must be measured on representative hardware (R-15, §17.8). |
| N-07 | **TLS true-async via memory BIOs / kTLS interception.** | OpenSSL drives the fd itself; intercepting needs memory BIOs — a separate large effort. TLS conns stay on `POLL_ADD`; only cleartext goes true-async (§13.7, R-13). |

### 19.5 Glossary

One crisp line each, alphabetical.

| Term | Definition |
|---|---|
| `ASYNC_CANCEL` (`IORING_OP_ASYNC_CANCEL`) | io_uring op that cancels outstanding SQEs for a target; used on transport error to cancel a dropped fd's multishot ops (§13.6). |
| CQE | Completion Queue Entry — one io_uring completion carrying `res` (bytes or `-errno`) and the submitter's `user_data`. |
| CRC32c | Castagnoli CRC used per 4 KiB page in pgread/pgwrite; CPU-bound, kept off the event thread (§10.6). |
| DAC | Discretionary Access Control — Unix uid/gid permission check, applied at `open()` time (as the mapped user), not on subsequent fd reads/writes (§14.4). |
| eventfd | A kernel counter fd; io_uring signals completions on it (`io_uring_register_eventfd`) and it is wrapped in an `ngx_connection_t` to wake epoll (§9.1, §11.1). |
| `fd_gen` | A per-`xrdc_aconn` `uint32_t` generation stamped into `user_data` so late CQEs for a recycled aconn are dropped (§13.6). |
| FSYNC (`IORING_OP_FSYNC`) | io_uring op for `fsync`; linked after `WRITEV` via `IOSQE_IO_LINK` to enforce write-then-sync ordering (§10.4). |
| generation guard | The server's UAF defense: a per-slot `generation` bumped on free; a `user_data` generation mismatch drops a stale CQE (§9.2). |
| io-wq | io_uring's in-kernel async worker pool; inherits the submitting worker's (unprivileged) credentials (§14.4). |
| io_uring | Linux async I/O interface using paired submission/completion ring buffers; the optional backend this phase adds. |
| `IORING_OP_*` | The opcode family (READ/WRITE/READV/WRITEV/FSYNC/POLL_ADD/RECV/SEND/ASYNC_CANCEL/GETDENTS, …). |
| `IORING_SETUP_R_DISABLED` | Ring-setup flag creating the ring disabled so restrictions can be registered before `io_uring_enable_rings()` (§14.4). |
| `IOSQE_IO_LINK` | SQE flag chaining ops so the next runs only after the prior succeeds; used for WRITEV→FSYNC (§10.4). |
| kill switch | The four-level disable mechanism (build-off / config-off-on-reload / SHM-atomic admin API / watched panic-file), level 3 no-restart (§8.1, §14.3). |
| kTLS | Kernel TLS — TLS record processing in-kernel on egress; nginx-core-owned and untouched (§0, N-01). |
| `kXR_*` | XRootD wire constants (`kXR_read`, `kXR_write`, `kXR_pgread`, `kXR_dirlist`, `kXR_IOError`, `kXR_wait`, `kXR_status`); framing unchanged. |
| multishot | An io_uring mode where one SQE yields repeated CQEs (e.g. multishot `POLL_ADD`/`RECV`) without re-arming (§13.3). |
| `ngx_epoll_aio_init` / `ngx_epoll_eventfd_handler` | nginx core's static libaio→epoll bridge (init + reaper) that this design re-derives with io_uring substituted (§7.1). |
| `ngx_posted_events` | nginx core's posted-events queue; the reaper `ngx_post_event`s each completed task here (§11.2). |
| `ngx_thread_task_t` | nginx core's thread-pool task object (embeds an `ngx_event_t`); reused verbatim to carry the `*_aio_t` structs (§9.6). |
| O_DIRECT | Unbuffered, page-cache-bypassing, block-aligned file I/O; optional client tier behind `direct`, default off (§12.8). |
| personality | A registered credential set (`io_uring_register_personality`) an SQE can run under via `sqe->personality`; a deferred per-identity tier (§14.4). |
| pgread / pgwrite | XRootD paged read/write — data plus per-4 KiB-page CRC32c; pgread stays on the thread pool in the first cut (§10.6). |
| `POLL_ADD` (`IORING_OP_POLL_ADD`) | io_uring readiness poll op; multishot form is the TLS-safe drop-in epoll replacement shipped first in the client engine swap (§13.3). |
| provided buffers | A kernel-side buffer pool io_uring picks from for RECV; a deferred cleartext client tier (§13.4, R-21). |
| READV / WRITEV | Vectored read/write ops; first cut covers single-fd/single-group only, multi falls back to the pool (§10.6). |
| reaper | `xrootd_uring_eventfd_handler` — drains the eventfd, harvests CQEs, validates slots, translates `res`, posts completions to `ngx_posted_events` (§11.1). |
| RECV / SEND | io_uring socket recv/send ops; cleartext-only true-async client tier, deferred (§13.4). |
| registered / fixed buffers | Buffers pre-registered with the ring (`IORING_REGISTER_BUFFERS`) to avoid per-op pinning; the client ring uses a registered-buffer pool (§12). |
| registered / fixed files | fds pre-registered with the ring (`IORING_REGISTER_FILES`) to skip per-op fd lookup; a deferred server tier (§33). |
| `register_restrictions` | Locks a ring to a whitelist of opcodes/fields; bars the ring to fd-only data opcodes (needs 5.10; best-effort) (§14.4). |
| RESOLVE_BENEATH | `openat2()` resolve flag confining path resolution beneath a root fd; the broker opens fds this way as the mapped user (§14.4). |
| RWF_NOWAIT | `preadv2` flag returning hot (page-cache) data immediately or `-EAGAIN`; the phase-32 warm-cache probe, retained above the dispatch seam (§11.6). |
| SCM_RIGHTS | The `sendmsg` ancillary-data mechanism the broker uses to pass an open fd to the unprivileged worker (§14.4). |
| slot table | Per-ring array mapping `user_data` → (`task`, `done_fn`, `generation`, `op_kind`, `in_use`); the UAF-safe indirection replacing raw task pointers (§9.2). |
| SQE | Submission Queue Entry — one io_uring request, built with `io_uring_prep_*` and posted via `io_uring_submit`. |
| SQPOLL (`IORING_SETUP_SQPOLL`) | A kernel poller thread that reaps the SQ without a syscall per submit; deferred, default off, needs registered files (§11.5). |
| TPC | Third-Party Copy — server-to-server transfer in the WLCG data model. |
| `user_data` | The 64-bit SQE field echoed in the CQE; here `(generation<<32)\|slot_index` (server) or carries `fd_gen` (client) for safe completion routing (§9.2, §13.6). |
| WLCG | Worldwide LHC Computing Grid — the deployment context; many WLCG sites run hardened environments where io_uring is blocked (§7.7). |
| `xrdc_aconn` | Client async-connection object in `aio.c`; gains `fd_gen` for the engine swap (§13.6). |
| `xrdc_copy_opts` | Client copy options struct; gains an `io_uring` tri-state (0=auto/1=on/2=off) — no new globals (§12). |
| `xrdc_disk_ring` | The client's thin liburing disk-ring wrapper (`uring.{c,h}`) owning a registered-buffer pool for the `copy.c` adapters (§12). |
| `xrootd_aio_post_task` | The single server-side async dispatch seam; gains the io_uring→pool→inline selector while keeping its signature (§10.7). |
| `xrootd_uring_t` | The per-worker server ring singleton (ring + eventfd + wrapping `ngx_connection_t` + depth/inflight/flags), reached via `xrootd_uring_worker()` (§9.1). |
| `*_aio_t` / `*_aio_done` / `*_aio_thread` | The six server task structs, their event-thread done-callbacks, and their pool-thread worker fns; reused byte-for-byte, only submission/syscall location changes (§9.6). |

---

## 20. Annotated server source skeletons (`src/aio/uring.{h,c}`, `uring_submit.c`)

This section is the near-final source skeleton for the three NEW server files. The six `*_aio_t` task structs, their `xrootd_*_aio_thread`/`xrootd_*_aio_done` halves, `xrootd_task_bind`, `xrootd_aio_post_task`, and the window pump are **unchanged** — this code is the only new code on the server. Everything below compiles under C11, nginx-idiomatic (`ngx_pcalloc`, `ngx_log_error`, `NGX_OK`/`NGX_ERROR`), no `goto` (early-return + `*_fail()` unwind helpers), and is wholly enclosed in `#if (XROOTD_HAVE_LIBURING)` with an `#else` stub that keeps every caller compiling without liburing. Identifiers match §9–§14; the enum spelled `xrootd_uring_op_e` with members `XRD_URING_OP_READ/WRITE/READV/WRITEV/FSYNC/NONE`.

### 20.1 `src/aio/uring.h`

The full header. Include guard, the liburing guard, all type definitions (the per-worker singleton, the slot, the op enum, the dispatch-table type, the prep-fn typedef), and every public/internal prototype with a one-line purpose. The `#else` arm provides a static-inline `xrootd_uring_worker()` returning `NULL` plus stub macros so callers in `resume.c`/`reads.c` link clean without liburing.

```c
#ifndef XROOTD_AIO_URING_H
#define XROOTD_AIO_URING_H

#include "../ngx_xrootd_module.h"
#include "aio.h"                 /* the six *_aio_t task structs */

/*
 * uring.h — optional per-worker io_uring disk-I/O backend behind
 * xrootd_aio_post_task().  WHAT: declares the per-worker ring singleton, the
 * UAF-safe completion slot table, the worker-fn -> op-kind dispatch table, and
 * the submit/reap entry points.  WHY: replace the thread-pool worker fns for
 * read/write/readv/writev with kernel-side SQEs while leaving every *_aio_t
 * struct, *_aio_done callback, and wire frame byte-for-byte unchanged (Option
 * A, §A.4).  HOW: all real types live under XROOTD_HAVE_LIBURING; the #else arm
 * is a link-clean stub so the dispatcher compiles with no liburing present.
 */

#if (XROOTD_HAVE_LIBURING)

#include <liburing.h>

/* Op-kind: indexes OUT-field translation in the reaper and selects the prep
 * fn at submit.  NONE = not first-cut eligible (pgread/dirlist/multi-fd) and is
 * never submitted — those fall through to the thread pool. */
typedef enum {
    XRD_URING_OP_READ = 0,   /* IORING_OP_READ   -> xrootd_read_aio_t   */
    XRD_URING_OP_WRITE,      /* IORING_OP_WRITE  -> xrootd_write_aio_t  */
    XRD_URING_OP_READV,      /* IORING_OP_READV  -> xrootd_readv_aio_t  */
    XRD_URING_OP_WRITEV,     /* IORING_OP_WRITEV -> xrootd_writev_aio_t */
    XRD_URING_OP_FSYNC,      /* IORING_OP_FSYNC  -> writev do_sync tail  */
    XRD_URING_OP_NONE        /* sentinel; declined to pool              */
} xrootd_uring_op_e;

/* Completion slot.  user_data = ((uint64_t)generation << 32) | slot_index.
 * The generation guards a stale CQE for a recycled slot (teardown UAF, §9.2).
 * pending_cqes tracks an outstanding linked chain (writev+fsync, §9.6). */
typedef struct {
    void                *task;        /* heap ngx_thread_task_t (->ctx = *_aio_t) */
    ngx_event_handler_pt done_fn;     /* the *_aio_done snapshot; reaper posts it */
    uint32_t             generation;  /* bumped on release; stale-CQE guard       */
    uint8_t              op_kind;     /* xrootd_uring_op_e; selects OUT translate */
    uint8_t              in_use;      /* 1 = claimed & submitted, 0 = free        */
    uint8_t              pending_cqes;/* CQEs still expected for this chain        */
} xrootd_uring_slot_t;

/* Per-worker ring singleton.  Exactly one per worker; file-static in uring.c,
 * reached only via xrootd_uring_worker().  Never embedded in ctx/conf/*_aio_t
 * (the "no new globals / no struct-layout change" constraints, §9.1, §9.8). */
typedef struct {
    struct io_uring      ring;          /* SQ/CQ rings + mmap'd state            */
    int                  eventfd;       /* io_uring_register_eventfd target      */
    ngx_connection_t    *evc;           /* fake conn wrapping eventfd into epoll */
    uint32_t             queue_depth;   /* SQ entries; also slots[] length       */
    uint32_t             inflight;      /* SQEs submitted, CQEs not yet reaped    */
    unsigned             enabled:1;     /* ring up & probe passed this worker    */
    unsigned             sqpoll:1;      /* IORING_SETUP_SQPOLL active (diag)     */
    unsigned             restrict_ops:1;/* register_restrictions applied (diag)  */
    ngx_log_t           *log;           /* borrowed worker cycle log             */
    xrootd_uring_slot_t *slots;         /* queue_depth entries; ngx_pcalloc'd    */
    ngx_atomic_t        *disabled_flag; /* SHM kill-switch; plain-read on submit */
} xrootd_uring_t;

/* SQE prep fn: fill `sqe` (and any linked SQE) from the typed task.  Returns
 * NGX_OK on success, NGX_DECLINED if the op proves non-mappable at run time
 * (e.g. a multi-fd writev that slipped past op_for) so submit falls to pool. */
typedef ngx_int_t (*xrootd_uring_prep_pt)(xrootd_uring_t *u,
    struct io_uring_sqe *sqe, ngx_thread_task_t *task);

/* Worker-fn -> op-kind dispatch row (§9.3).  Keyed on task->handler so the
 * unchanged call sites (reads.c/write.c/readv.c) need no edits.  prep == NULL
 * marks a not-uring-eligible op (pgread/dirlist) -> declined to the pool. */
typedef struct {
    void                (*thread_fn)(void *, ngx_log_t *);
    xrootd_uring_op_e     op_kind;
    xrootd_uring_prep_pt  prep;
} xrootd_uring_dispatch_t;

/* ---- lifecycle (called from src/aio/config.c worker hooks) ------------- */

/* Memoized kernel/liburing capability probe (tri-state static).  Cheap; does
 * NOT open a ring per call.  0 = unavailable on this kernel/seccomp policy. */
ngx_int_t xrootd_uring_runtime_available(void);

/* Worker-init hook: build the ring + eventfd + evc + slot table for THIS
 * worker.  NGX_OK even when the ring can't come up (enabled stays 0, callers
 * transparently use the pool); NGX_ERROR only on a fatal nginx-resource fault. */
ngx_int_t xrootd_uring_init_worker(ngx_cycle_t *cycle);

/* Worker-exit hook: drain/teardown evc, unregister eventfd, queue_exit, close. */
void xrootd_uring_exit_worker(ngx_cycle_t *cycle);

/* ---- accessor + state -------------------------------------------------- */

/* The per-worker singleton (always non-NULL after init; ->enabled may be 0). */
xrootd_uring_t *xrootd_uring_worker(void);

/* 1 if the ring must not be used right now: ->enabled clear OR SHM kill-switch
 * set.  Checked at the top of submit before any slot is touched. */
ngx_int_t xrootd_uring_disabled(xrootd_uring_t *u);

/* ---- slot table (event-thread only; no atomics) ------------------------ */

/* Claim a free slot under backpressure (inflight < queue_depth); *idx_out gets
 * the index.  NULL = ring full / no slot -> caller declines to the pool. */
xrootd_uring_slot_t *xrootd_uring_slot_acquire(xrootd_uring_t *u,
    uint32_t *idx_out);

/* Release slot idx: in_use=0, task=NULL, generation++ (invalidates late CQEs). */
void xrootd_uring_slot_release(xrootd_uring_t *u, uint32_t idx);

/* Bounds-checked slot lookup for the reaper; NULL if idx >= queue_depth. */
xrootd_uring_slot_t *xrootd_uring_slot_at(xrootd_uring_t *u, uint32_t idx);

/* ---- submit path (uring_submit.c) -------------------------------------- */

/* Map a bound task to an op-kind by its task->handler (dispatch table); returns
 * XRD_URING_OP_NONE for not-eligible ops or when shape predicates fail. */
xrootd_uring_op_e xrootd_uring_op_for(ngx_thread_task_t *task);

/* The single submit entry point invoked by the selector in xrootd_aio_post_task
 * (resume.c).  Always NGX_OK; *posted=1 only on a fully-successful submit, else
 * 0 so the caller falls through to the thread pool (never drops the op). */
ngx_int_t xrootd_uring_submit(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_task_t *task, xrootd_uring_op_e op, ngx_flag_t *posted);

/* SQEs a given op consumes: 1, or 2 for WRITEV-with-linked-FSYNC (§10.5). */
uint32_t xrootd_uring_sqe_count(xrootd_uring_op_e op);

/* ---- reaper + OUT translation (uring.c) -------------------------------- */

/* The eventfd readiness handler = evc->read->handler.  Mirrors core's
 * ngx_epoll_eventfd_handler: drain eventfd, peek CQEs, translate, post events. */
void xrootd_uring_eventfd_handler(ngx_event_t *ev);

/* Write cqe->res into the slot's task OUT fields per op_kind; returns 1 when
 * this is the chain's final CQE (task ready to post), 0 while a linked chain is
 * still completing (writev awaiting its fsync CQE). */
ngx_int_t xrootd_uring_apply_cqe(xrootd_uring_t *u, xrootd_uring_slot_t *slot,
    struct io_uring_cqe *cqe);

#else  /* !XROOTD_HAVE_LIBURING ------------------------------------------- */

/*
 * Stub fallback.  No ring type exists; the dispatcher must still compile and
 * link.  xrootd_uring_worker() is a static-inline NULL so the selector's
 * `if (xrootd_uring_worker() != NULL && ...)` guard short-circuits to the pool
 * with zero codegen.  The lifecycle hooks are no-op inlines for config.c.
 */
typedef struct xrootd_uring_s xrootd_uring_t;        /* opaque, never defined */

static ngx_inline xrootd_uring_t *xrootd_uring_worker(void) { return NULL; }
static ngx_inline ngx_int_t xrootd_uring_runtime_available(void) { return 0; }
static ngx_inline ngx_int_t xrootd_uring_init_worker(ngx_cycle_t *c)
    { (void) c; return NGX_OK; }
static ngx_inline void xrootd_uring_exit_worker(ngx_cycle_t *c) { (void) c; }

/* The selector calls these only inside `if (u != NULL)`; provide declarations
 * so any unconditional reference still links (they are dead under the stub). */
#define xrootd_uring_op_for(task)            XRD_URING_OP_NONE_STUB
#define XRD_URING_OP_NONE_STUB              0
#define xrootd_uring_submit(ctx,c,t,op,p)   (*(p) = 0, NGX_OK)

#endif /* XROOTD_HAVE_LIBURING */

#endif /* XROOTD_AIO_URING_H */
```

Notes for the implementer. The selector in `xrootd_aio_post_task` is the one edit outside these three files, and it must be written so the whole io_uring branch sits behind `if (u != NULL && !xrootd_uring_disabled(u))` where `u = xrootd_uring_worker()`; under the stub that is a compile-time-constant `NULL` so the branch is dead-code-eliminated and `xrootd_uring_submit` is never reached. Keep `pending_cqes` even though the first cut uses a single slot for writev+fsync — it is the hook for two-CQE chains (§9.6) and costs one byte.

### 20.2 `src/aio/uring.c`

File-level doc block, the file-static singleton + accessor, then full skeletons with bodies-as-detailed-pseudocode for the lifecycle, the reaper, the OUT translator, the slot ops, and `xrootd_uring_disabled`. Real liburing calls throughout.

```c
#include "uring.h"

/*
 * uring.c — per-worker io_uring backend: ring lifecycle, the completion reaper,
 * the slot table, and cqe->res -> task OUT-field translation.
 *
 * WHAT: owns the single per-worker xrootd_uring_t, brings the ring up after
 *       fork, wraps its registered eventfd into nginx epoll, harvests CQEs, and
 *       posts each completed task's *_aio_done via ngx_posted_events.
 * WHY:  move read/write/readv/writev disk syscalls off the thread pool into the
 *       kernel while preserving Option A — the unchanged *_aio_done callbacks
 *       cannot tell whether a thread or the kernel produced the result.
 * HOW:  init mirrors ngx_epoll_aio_init (queue_init -> eventfd -> register ->
 *       ngx_get_connection + ngx_add_event); the reaper mirrors
 *       ngx_epoll_eventfd_handler (read eventfd -> for_each_cqe -> translate ->
 *       ngx_post_event, never inline).  Single-threaded per worker: no atomics
 *       except the SHM kill-switch read.  No goto; *_fail() helpers unwind.
 */

#if (XROOTD_HAVE_LIBURING)

/* The one-per-worker singleton.  static => not an exported global (§9.1). */
static xrootd_uring_t  ngx_xrootd_uring;

/* Memoized capability tri-state: -1 unknown, 0 no, 1 yes. */
static int             ngx_xrootd_uring_probe = -1;

xrootd_uring_t *
xrootd_uring_worker(void)
{
    return &ngx_xrootd_uring;
}

/* clamp helper: depth to [8, 4096], rounded down to power of two (SQPOLL wants
 * pow2; the ring rounds up internally but we keep slots[] == accepted depth). */
static uint32_t
xrootd_uring_clamp_depth(uint32_t want)
{
    uint32_t d = 8;
    if (want < 8)    want = 8;
    if (want > 4096) want = 4096;
    while ((d << 1) <= want) d <<= 1;
    return d;
}

/*
 * xrootd_uring_runtime_available — memoized probe of kernel + seccomp support.
 * WHAT: tri-state "can this worker even open a ring".  WHY: a seccomp policy or
 * old kernel may forbid io_uring_setup(2); probe once, not per file open.
 * HOW: on first call, try a tiny throwaway ring (depth 2); cache the result.
 */
ngx_int_t
xrootd_uring_runtime_available(void)
{
    struct io_uring probe;
    int             rc;

    if (ngx_xrootd_uring_probe != -1) {
        return ngx_xrootd_uring_probe;          /* memoized */
    }
    rc = io_uring_queue_init(2, &probe, 0);
    if (rc < 0) {
        ngx_xrootd_uring_probe = 0;             /* ENOSYS/EPERM/seccomp */
    } else {
        io_uring_queue_exit(&probe);
        ngx_xrootd_uring_probe = 1;
    }
    return ngx_xrootd_uring_probe;
}

/*
 * xrootd_uring_init_worker_fail — single unwind point (replaces goto).
 * WHAT: release whatever the in-progress init had already acquired, leave the
 * singleton in a clean ->enabled=0 state, log at the given level, return rc.
 * WHY:  no-goto policy; each early-return in init calls this with the right
 * "how far did we get" so partial state never leaks across worker lifetime.
 * HOW:  tear down in reverse acquisition order, each step null/-1 guarded.
 */
static ngx_int_t
xrootd_uring_init_worker_fail(xrootd_uring_t *u, const char *what, int err)
{
    ngx_log_error(NGX_LOG_WARN, u->log, err,
                  "xrootd: io_uring disabled this worker: %s", what);

    if (u->evc != NULL) {
        if (u->evc->read->active) {
            (void) ngx_del_event(u->evc->read, NGX_READ_EVENT, 0);
        }
        ngx_close_connection(u->evc);
        u->evc = NULL;
    }
    if (u->eventfd != -1) {
        /* eventfd may or may not be registered yet; unregister is idempotent
         * enough that we ignore its error here. */
        (void) io_uring_unregister_eventfd(&u->ring);
        close(u->eventfd);
        u->eventfd = -1;
    }
    /* ring was queue_init'd iff we got past that step; queue_exit is safe even
     * on a partially-set-up ring as long as init succeeded. We track that with
     * enabled-was-attempted: queue_exit only if the ring fd is live. */
    io_uring_queue_exit(&u->ring);      /* harmless if never fully up; see note */

    u->enabled = 0;
    u->inflight = 0;
    return NGX_OK;     /* NGX_OK: ring-down is non-fatal; pool path still works */
}

/*
 * xrootd_uring_init_restricted — apply IORING_SETUP_R_DISABLED hardening.
 * WHAT: bring the ring up in a disabled state, whitelist only the five disk
 * ops, then enable.  WHY: shrink the kernel attack surface (§8/§14): a
 * compromised worker cannot submit network/openat/etc. ops.  HOW:
 *   queue_init_params(R_DISABLED) -> register_restrictions(op whitelist)
 *   -> io_uring_enable_rings.  On any failure return NGX_DECLINED so the caller
 *   retries an unrestricted plain ring (restrictions need a recent kernel).
 */
static ngx_int_t
xrootd_uring_init_restricted(xrootd_uring_t *u, uint32_t depth)
{
    struct io_uring_params      p;
    struct io_uring_restriction  res[5];
    int                          rc;

    ngx_memzero(&p, sizeof(p));
    p.flags = IORING_SETUP_R_DISABLED;          /* come up suspended */

    rc = io_uring_queue_init_params(depth, &u->ring, &p);
    if (rc < 0) {
        return NGX_DECLINED;                    /* fall back to plain init */
    }

    ngx_memzero(res, sizeof(res));
    res[0].opcode = IORING_RESTRICTION_SQE_OP; res[0].sqe_op = IORING_OP_READ;
    res[1].opcode = IORING_RESTRICTION_SQE_OP; res[1].sqe_op = IORING_OP_WRITE;
    res[2].opcode = IORING_RESTRICTION_SQE_OP; res[2].sqe_op = IORING_OP_READV;
    res[3].opcode = IORING_RESTRICTION_SQE_OP; res[3].sqe_op = IORING_OP_WRITEV;
    res[4].opcode = IORING_RESTRICTION_SQE_OP; res[4].sqe_op = IORING_OP_FSYNC;

    rc = io_uring_register_restrictions(&u->ring, res, 5);
    if (rc < 0) {
        io_uring_queue_exit(&u->ring);
        return NGX_DECLINED;
    }

    rc = io_uring_enable_rings(&u->ring);        /* lift R_DISABLED */
    if (rc < 0) {
        io_uring_queue_exit(&u->ring);
        return NGX_DECLINED;
    }

    u->restrict_ops = 1;
    return NGX_OK;
}

/*
 * xrootd_uring_init_worker — build the ring for THIS worker after fork.
 * WHAT: queue_init (restricted if possible) -> eventfd -> register_eventfd ->
 *       evc wrap into epoll -> slot table -> ->enabled=1.  WHY: one ring per
 *       worker, post-fork (a pre-fork ring cannot be shared).  HOW: mirrors
 *       ngx_epoll_aio_init; every failure routes through _fail() (no goto) and
 *       returns NGX_OK with ->enabled=0 (ring-down is non-fatal).
 */
ngx_int_t
xrootd_uring_init_worker(ngx_cycle_t *cycle)
{
    xrootd_uring_t *u = &ngx_xrootd_uring;
    uint32_t        depth;
    int             efd, rc;

    ngx_memzero(u, sizeof(*u));
    u->log     = cycle->log;
    u->eventfd = -1;
    u->evc     = NULL;
    u->enabled = 0;

    /* config-resolved backend must be URING and the kernel must allow it. */
    if (!xrootd_uring_runtime_available()) {
        return NGX_OK;                  /* enabled stays 0; pool path used */
    }

    depth = xrootd_uring_clamp_depth(/* rconf depth, e.g. */ 256);
    u->queue_depth = depth;

    /* 1. bring the ring up — restricted first, plain on NGX_DECLINED. */
    if (xrootd_uring_init_restricted(u, depth) != NGX_OK) {
        rc = io_uring_queue_init(depth, &u->ring, 0);
        if (rc < 0) {
            return xrootd_uring_init_worker_fail(u, "queue_init", -rc);
        }
    }

    /* 2. eventfd — kernel increments it per CQE; epoll readiness wakes reaper. */
    efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd == -1) {
        return xrootd_uring_init_worker_fail(u, "eventfd", ngx_errno);
    }
    u->eventfd = efd;

    rc = io_uring_register_eventfd(&u->ring, efd);
    if (rc < 0) {
        return xrootd_uring_init_worker_fail(u, "register_eventfd", -rc);
    }

    /* 3. wrap eventfd into a fake ngx_connection_t and arm read interest —
     *    the public-API bridge into epoll (mirrors ngx_epoll_aio_init). */
    u->evc = ngx_get_connection(efd, cycle->log);
    if (u->evc == NULL) {
        return xrootd_uring_init_worker_fail(u, "get_connection", 0);
    }
    u->evc->log          = cycle->log;
    u->evc->read->log    = cycle->log;
    u->evc->read->handler = xrootd_uring_eventfd_handler;
    u->evc->read->data    = u->evc;     /* handler recovers evc, then u=evc->data */
    u->evc->data          = u;          /* reaper: u = evc->data */

    if (ngx_add_event(u->evc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        return xrootd_uring_init_worker_fail(u, "add_event", 0);
    }

    /* 4. slot table — zero-filled: every slot in_use=0, generation=0 (§9.2). */
    u->slots = ngx_pcalloc(cycle->pool,
                           depth * sizeof(xrootd_uring_slot_t));
    if (u->slots == NULL) {
        return xrootd_uring_init_worker_fail(u, "slots alloc", 0);
    }

    /* 5. wire the SHM kill-switch (borrowed; never written here). */
    u->disabled_flag = /* &shm->uring_disabled, resolved from rconf shm zone */ NULL;

    u->enabled  = 1;
    u->inflight = 0;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: io_uring enabled (depth=%uD restricted=%ud)",
                  depth, (unsigned) u->restrict_ops);
    return NGX_OK;
}

/*
 * xrootd_uring_exit_worker — tear the ring down at worker exit.
 * WHAT: detach evc from epoll, unregister eventfd, queue_exit (drains/abandons
 *       in-flight ops), close eventfd.  WHY: io_uring_queue_exit waits for or
 *       discards outstanding ops; their tasks are pool-allocated on connections
 *       being destroyed at process exit, so abandoning the CQEs is safe (§11.7).
 * HOW:  reverse of init; null/-1 guarded so a never-fully-inited ring is a
 *       no-op.  Optionally spin the posted-events drain until inflight==0 first.
 */
void
xrootd_uring_exit_worker(ngx_cycle_t *cycle)
{
    xrootd_uring_t *u = &ngx_xrootd_uring;

    if (!u->enabled && u->evc == NULL) {
        return;                         /* ring never came up */
    }
    /* Optional graceful drain: while (u->inflight) ngx_event_process_posted(); */

    if (u->evc != NULL) {
        if (u->evc->read->active) {
            (void) ngx_del_event(u->evc->read, NGX_READ_EVENT, 0);
        }
        ngx_close_connection(u->evc);
        u->evc = NULL;
    }
    if (u->eventfd != -1) {
        (void) io_uring_unregister_eventfd(&u->ring);
    }
    io_uring_queue_exit(&u->ring);
    if (u->eventfd != -1) {
        close(u->eventfd);
        u->eventfd = -1;
    }
    u->enabled = 0;
}

/*
 * xrootd_uring_disabled — should submit decline right now?
 * WHAT: 1 if the ring is unusable (->enabled clear) or the SHM hot kill-switch
 *       is set.  WHY: a single fleet-wide atomic flips io_uring off without a
 *       restart (§8); ->enabled is the per-worker arm.  HOW: cheap boolean,
 *       a single plain ngx_atomic read (advisory; no barrier needed).
 */
ngx_int_t
xrootd_uring_disabled(xrootd_uring_t *u)
{
    if (!u->enabled) {
        return 1;
    }
    if (u->disabled_flag != NULL && *u->disabled_flag != 0) {
        return 1;
    }
    return 0;
}

/* ---- slot table --------------------------------------------------------- */

/*
 * xrootd_uring_slot_acquire — claim a free slot under backpressure.
 * WHAT: first free slot, mark in_use, return it + index.  WHY: bounds in-flight
 *       to queue_depth so a free slot is guaranteed whenever the ring has room
 *       (§9.2).  HOW: backpressure gate, then a linear scan (a free-stack is a
 *       valid O(1) drop-in, §9.2); does NOT bump generation (that happens on
 *       release) and does NOT increment inflight (submit does, post-submit).
 */
xrootd_uring_slot_t *
xrootd_uring_slot_acquire(xrootd_uring_t *u, uint32_t *idx_out)
{
    uint32_t i;

    if (u->inflight >= u->queue_depth) {
        return NULL;                    /* ring full -> caller uses the pool */
    }
    for (i = 0; i < u->queue_depth; i++) {
        if (!u->slots[i].in_use) {
            u->slots[i].in_use      = 1;
            u->slots[i].task        = NULL;
            u->slots[i].pending_cqes = 0;
            *idx_out = i;
            return &u->slots[i];
        }
    }
    return NULL;                        /* inflight<depth but none free: defensive */
}

/*
 * xrootd_uring_slot_release — free a slot and invalidate late CQEs.
 * WHAT: in_use=0, task=NULL, generation++.  WHY: the generation bump is what
 *       makes a stale CQE for this recycled index decode to a mismatched
 *       generation and get dropped (§9.2 UAF guard).  HOW: caller (reaper or
 *       submit-unwind) owns the inflight-- separately; this only touches slot
 *       state.  Bounds-guarded so a corrupt index is a no-op.
 */
void
xrootd_uring_slot_release(xrootd_uring_t *u, uint32_t idx)
{
    if (idx >= u->queue_depth) {
        return;
    }
    u->slots[idx].in_use       = 0;
    u->slots[idx].task         = NULL;
    u->slots[idx].pending_cqes = 0;
    u->slots[idx].generation++;         /* wraps at 2^32; unreachable collision */
}

/* Bounds-checked lookup; NULL when the decoded index is out of range. */
xrootd_uring_slot_t *
xrootd_uring_slot_at(xrootd_uring_t *u, uint32_t idx)
{
    if (idx >= u->queue_depth) {
        return NULL;
    }
    return &u->slots[idx];
}

/* ---- the reaper --------------------------------------------------------- */

/*
 * xrootd_uring_eventfd_handler — per-worker completion handler.
 * WHAT: fired when the registered eventfd is readable; harvests all pending
 *       CQEs and posts each completed task's *_aio_done.  WHY: mirror
 *       ngx_epoll_eventfd_handler so completions flow through nginx's existing
 *       posted-events drain — re-entrancy-safe for the window pump (§11.2).
 * HOW:  read(eventfd) -> io_uring_peek_cqe loop -> decode slot + validate
 *       generation -> xrootd_uring_apply_cqe -> ngx_post_event(NOT inline) ->
 *       io_uring_cqe_seen -> inflight--.  Never touches the SQ; never dispatches
 *       a done-callback from inside the loop.
 */
void
xrootd_uring_eventfd_handler(ngx_event_t *ev)
{
    ngx_connection_t    *evc = ev->data;
    xrootd_uring_t      *u   = evc->data;
    struct io_uring_cqe *cqe;
    uint64_t             counter;
    ssize_t              n;

    /* 1. drain the eventfd counter (same first step as core's handler). */
    n = read(u->eventfd, &counter, sizeof(counter));
    if (n != (ssize_t) sizeof(counter)) {
        if (n == -1 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
            return;                     /* spurious wakeup */
        }
        ngx_log_error(NGX_LOG_ALERT, evc->log, ngx_errno,
                      "xrootd: io_uring eventfd read() failed");
        return;                         /* leave ring; pool still serves */
    }

    /* 2. harvest: non-blocking peek until the CQ is empty. */
    while (io_uring_peek_cqe(&u->ring, &cqe) == 0) {
        uint64_t             ud  = io_uring_cqe_get_data64(cqe);
        uint32_t             idx = (uint32_t) (ud & 0xffffffffu);
        uint32_t             gen = (uint32_t) (ud >> 32);
        xrootd_uring_slot_t *slot = xrootd_uring_slot_at(u, idx);

        /* 2a. generation guard: stale CQE for a recycled slot -> drop. */
        if (slot == NULL || !slot->in_use || slot->generation != gen) {
            io_uring_cqe_seen(&u->ring, cqe);
            if (u->inflight > 0) u->inflight--;
            continue;
        }

        /* 2b. translate; apply_cqe returns 1 only on the chain's final CQE. */
        if (xrootd_uring_apply_cqe(u, slot, cqe)) {
            ngx_thread_task_t *task = slot->task;
            task->event.complete = 1;           /* matches core's e->complete */
            ngx_post_event(&task->event, &ngx_posted_events);
            xrootd_uring_slot_release(u, idx);  /* in_use=0, generation++ */
        }

        io_uring_cqe_seen(&u->ring, cqe);
        if (u->inflight > 0) u->inflight--;
    }
}

/*
 * xrootd_uring_apply_cqe — cqe->res -> task OUT fields, per op_kind.
 * WHAT: write exactly the OUT fields the bypassed *_aio_thread would have set,
 *       so the unchanged *_aio_done can't tell kernel from thread (Option A).
 * WHY:  centralize the §9.6 translation table in one switch; the reaper stays
 *       op-agnostic.  HOW: cqe->res >= 0 is bytes transferred, < 0 is -errno;
 *       the reaper does the negation (callbacks expect a positive errno).
 *       Returns 1 = final CQE (post now), 0 = chain still pending (writev+fsync).
 */
ngx_int_t
xrootd_uring_apply_cqe(xrootd_uring_t *u, xrootd_uring_slot_t *slot,
    struct io_uring_cqe *cqe)
{
    int res = cqe->res;

    switch ((xrootd_uring_op_e) slot->op_kind) {

    case XRD_URING_OP_READ: {
        xrootd_read_aio_t *t = ((ngx_thread_task_t *) slot->task)->ctx;
        if (res < 0) { t->io_errno = -res; t->nread = -1; }
        else         { t->nread = res;      t->io_errno = 0; }
        return 1;                       /* short read == EOF, handled in done */
    }

    case XRD_URING_OP_WRITE: {
        xrootd_write_aio_t *t = ((ngx_thread_task_t *) slot->task)->ctx;
        if (res < 0) {
            t->io_errno = -res; t->nwritten = -1;
        } else if ((size_t) res < t->len) {
            t->io_errno = EIO; t->nwritten = res;   /* short write == hard error */
        } else {
            t->nwritten = res; t->io_errno = 0;
        }
        return 1;
    }

    case XRD_URING_OP_READV: {
        xrootd_readv_aio_t *t = ((ngx_thread_task_t *) slot->task)->ctx;
        if (res < 0) {
            t->io_error = 1;
            ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg),
                         "readv: %s%Z", strerror(-res));
        } else {
            /* short readv past EOF mirrors xrootd_readv_read_segments contract */
            t->bytes_read_total = (size_t) res;
            t->io_error = 0;
        }
        return 1;
    }

    case XRD_URING_OP_WRITEV: {
        xrootd_writev_aio_t *t = ((ngx_thread_task_t *) slot->task)->ctx;
        if (res < 0) {
            t->io_error = 1;
            ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg),
                         "pwritev: %s%Z", strerror(-res));
        } else {
            /* short write (< sum of seg wlen) is io_error=2, exactly the thread */
            t->bytes_total = (size_t) res;
            /* the prep recorded the expected total in the task; compare there */
            t->io_error = 0;
        }
        /* if this writev links an fsync, the chain isn't done until the fsync
         * CQE: keep the slot, decrement pending, defer the post. First cut maps
         * fsync only with linked-CQE coalescing, so pending_cqes is 1 here. */
        if (slot->pending_cqes > 1) { slot->pending_cqes--; return 0; }
        return 1;
    }

    case XRD_URING_OP_FSYNC: {
        /* The linked fsync shares the writev's slot/task (§9.6). Merge its
         * result into the writev task and finalize. */
        xrootd_writev_aio_t *t = ((ngx_thread_task_t *) slot->task)->ctx;
        if (res < 0 && t->io_error == 0) {
            t->io_error = 1;
            ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg),
                         "fsync: %s%Z", strerror(-res));
        }
        if (slot->pending_cqes > 0) slot->pending_cqes--;
        return slot->pending_cqes == 0 ? 1 : 0;
    }

    case XRD_URING_OP_NONE:
    default:
        /* unreachable: NONE is never submitted. Drop defensively. */
        ngx_log_error(NGX_LOG_ALERT, u->log, 0,
                      "xrootd: io_uring CQE with op_kind=%ud", slot->op_kind);
        return 1;
    }
}

#endif /* XROOTD_HAVE_LIBURING */
```

Implementer notes for `uring.c`. The two-CQE writev+fsync case is intentionally written so `pending_cqes` is the single source of truth for "chain complete": prep sets it (2 for linked, 1 otherwise), `apply_cqe` decrements and only returns 1 at zero. The first cut keeps both SQEs sharing one slot/cookie (so a stray fsync CQE still decodes to the live slot); if a future kernel reports them as separate user_data, the FSYNC arm above already merges into the WRITEV task. The expected-total comparison for the writev short-write (`io_error=2`) needs the summed `wlen` — record it in the task at prep time (a scratch field, or recompute from `segs[]`), since `cqe->res` alone cannot tell short from complete.

### 20.3 `src/aio/uring_submit.c`

The op-mapper, the common submit scaffolding, the per-op prep functions (including the linked-fsync chaining for writev), and the SQE counter. Each carries a WHAT/WHY/HOW block.

```c
#include "uring.h"

/*
 * uring_submit.c — the submit side of the io_uring backend.
 *
 * WHAT: maps a bound ngx_thread_task_t (by its task->handler) to an op-kind,
 *       builds the SQE(s) from the task's *_aio_t, and submits — or declines so
 *       xrootd_aio_post_task falls through to the thread pool.
 * WHY:  keep every call site (reads.c/write.c/readv.c) unchanged; the only
 *       coupling to the unchanged task structs is the dispatch table here.
 * HOW:  op_for() looks up task->handler + checks shape predicates; submit()
 *       does the UAF-safe slot bookkeeping (§10.0) then calls a prep_*; prep_*
 *       fills the SQE(s).  All event-thread, submit-time.  No goto.
 */

#if (XROOTD_HAVE_LIBURING)

#include <liburing.h>

/* forward decls for the dispatch table */
static ngx_int_t xrootd_uring_prep_read  (xrootd_uring_t *, struct io_uring_sqe *,
                                          ngx_thread_task_t *);
static ngx_int_t xrootd_uring_prep_write (xrootd_uring_t *, struct io_uring_sqe *,
                                          ngx_thread_task_t *);
static ngx_int_t xrootd_uring_prep_readv (xrootd_uring_t *, struct io_uring_sqe *,
                                          ngx_thread_task_t *);
static ngx_int_t xrootd_uring_prep_writev(xrootd_uring_t *, struct io_uring_sqe *,
                                          ngx_thread_task_t *);

/* The worker-fn -> op-kind + prep table (§9.3). thread_fn is the key matched
 * against task->handler. prep == NULL => not eligible (declined to pool). */
static const xrootd_uring_dispatch_t xrootd_uring_dispatch[] = {
    { xrootd_read_aio_thread,         XRD_URING_OP_READ,   xrootd_uring_prep_read   },
    { xrootd_write_aio_thread,        XRD_URING_OP_WRITE,  xrootd_uring_prep_write  },
    { xrootd_readv_aio_thread,        XRD_URING_OP_READV,  xrootd_uring_prep_readv  },
    { xrootd_writev_write_aio_thread, XRD_URING_OP_WRITEV, xrootd_uring_prep_writev },
    { xrootd_pgread_aio_thread,       XRD_URING_OP_NONE,   NULL },  /* CRC: pool   */
    { xrootd_dirlist_aio_thread,      XRD_URING_OP_NONE,   NULL },  /* opendir:pool */
};

/* look up the prep fn for an op (parallel to op_for; both scan the table). */
static xrootd_uring_prep_pt
xrootd_uring_prep_of(xrootd_uring_op_e op)
{
    ngx_uint_t i;
    for (i = 0; i < sizeof(xrootd_uring_dispatch) / sizeof(xrootd_uring_dispatch[0]); i++) {
        if (xrootd_uring_dispatch[i].op_kind == op) {
            return xrootd_uring_dispatch[i].prep;
        }
    }
    return NULL;
}

/*
 * xrootd_uring_op_for — map a bound task to an op-kind.
 * WHAT: read task->handler, find its dispatch row, and apply shape predicates
 *       that downgrade an otherwise-mapped op to NONE (multi-fd writev, multi-
 *       group readv, fsync without linked-CQE support).  WHY: the call sites
 *       set task->handler exactly as today; this is the only place that knows
 *       which kernel op a given task maps to (§9.3).  HOW: linear table scan +
 *       per-op run-time recheck against the *_aio_t fields.
 */
xrootd_uring_op_e
xrootd_uring_op_for(ngx_thread_task_t *task)
{
    ngx_uint_t i;

    for (i = 0; i < sizeof(xrootd_uring_dispatch) / sizeof(xrootd_uring_dispatch[0]); i++) {
        if (xrootd_uring_dispatch[i].thread_fn != task->handler) {
            continue;
        }
        switch (xrootd_uring_dispatch[i].op_kind) {

        case XRD_URING_OP_READV: {
            /* single-group, single-fd only (§10.3): one fd across all segs and
             * a coalesced iovec count <= IOV_MAX-ish (we cap at 64). */
            xrootd_readv_aio_t *t = task->ctx;
            if (t->segment_count == 0 || t->segment_count > 64) {
                return XRD_URING_OP_NONE;
            }
            {
                int fd0 = t->segments[0].fd, k;
                for (k = 1; k < (int) t->segment_count; k++) {
                    if (t->segments[k].fd != fd0) return XRD_URING_OP_NONE;
                }
            }
            return XRD_URING_OP_READV;
        }

        case XRD_URING_OP_WRITEV: {
            /* single-fd only; multi-fd writev stays on the pool (§10.5). */
            xrootd_writev_aio_t *t = task->ctx;
            if (t->n_segs == 0 || t->n_segs > 64) {
                return XRD_URING_OP_NONE;
            }
            {
                int fd0 = t->segs[0].fd, k;
                for (k = 1; k < (int) t->n_segs; k++) {
                    if (t->segs[k].fd != fd0) return XRD_URING_OP_NONE;
                }
            }
            /* do_sync needs a linked fsync; first cut maps it only when linked
             * CQE coalescing is known-good (compile/runtime gate omitted here). */
            return XRD_URING_OP_WRITEV;
        }

        default:
            return xrootd_uring_dispatch[i].op_kind;   /* READ/WRITE/NONE */
        }
    }
    return XRD_URING_OP_NONE;       /* unknown handler => pool */
}

/*
 * xrootd_uring_sqe_count — SQEs an op consumes.
 * WHAT: 1, or 2 for a writev whose task->do_sync is set (write SQE + linked
 *       fsync SQE).  WHY: inflight accounting and SQ-room checks must match the
 *       real submission count (§11.4).  HOW: the caller passes the op; for the
 *       writev case the prep also inspects do_sync, so keep the two in sync.
 */
uint32_t
xrootd_uring_sqe_count(xrootd_uring_op_e op)
{
    /* NOTE: writev-with-fsync is 2; the caller verifies do_sync before adding.
     * For simplicity the submit path passes the resolved count from prep via
     * slot->pending_cqes; this returns the worst case for backpressure. */
    return (op == XRD_URING_OP_WRITEV) ? 2 : 1;
}

/*
 * xrootd_uring_submit — the common submit scaffolding (§10.0).
 * WHAT: reserve a slot, get an SQE, prep, encode user_data, submit; *posted=1
 *       only on full success.  WHY: the op must never be dropped — every miss
 *       (full ring, no SQE, prep DECLINED, submit<0) leaves *posted=0 so the
 *       caller uses the pool.  HOW: slot_acquire -> get_sqe -> prep_of(op) ->
 *       set_data64 -> io_uring_submit; unwind via slot_release on any failure
 *       (no goto). inflight is bumped only after a successful submit.
 */
ngx_int_t
xrootd_uring_submit(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_task_t *task, xrootd_uring_op_e op, ngx_flag_t *posted)
{
    xrootd_uring_t       *u = xrootd_uring_worker();
    xrootd_uring_slot_t  *slot;
    struct io_uring_sqe  *sqe;
    xrootd_uring_prep_pt  prep;
    uint32_t              idx;
    uint64_t              cookie;
    ngx_int_t             rc;

    *posted = 0;

    if (op == XRD_URING_OP_NONE || xrootd_uring_disabled(u)) {
        return NGX_OK;                  /* not eligible / kill-switch -> pool */
    }
    prep = xrootd_uring_prep_of(op);
    if (prep == NULL) {
        return NGX_OK;
    }

    /* 1. reserve a slot (backpressure); full ring -> pool. */
    slot = xrootd_uring_slot_acquire(u, &idx);
    if (slot == NULL) {
        return NGX_OK;
    }

    /* 2. an SQE must be available. */
    sqe = io_uring_get_sqe(&u->ring);
    if (sqe == NULL) {
        xrootd_uring_slot_release(u, idx);
        return NGX_OK;
    }

    /* 3. per-op prep — fills sqe (+ linked SQE for writev+fsync). */
    rc = prep(u, sqe, task);
    if (rc != NGX_OK) {                 /* NGX_DECLINED: non-mappable at run time */
        xrootd_uring_slot_release(u, idx);
        return NGX_OK;
    }

    /* 4. stash identity + encode the cookie on the (first) SQE. The prep set
     *    slot->pending_cqes; a linked fsync SQE carries the same cookie. */
    slot->task    = task;
    slot->done_fn = task->event.handler;
    slot->op_kind = (uint8_t) op;
    /* in_use already 1 from acquire; pending_cqes set by prep */
    cookie = ((uint64_t) slot->generation << 32) | idx;
    io_uring_sqe_set_data64(sqe, cookie);
    if (slot->pending_cqes == 2) {
        /* the linked fsync SQE is the immediately-following SQE the prep got;
         * prep stashed it so we tag it with the same cookie. */
        io_uring_sqe_set_data64(sqe + 1 /* see prep note */, cookie);
    }

    /* 5. submit. */
    if (io_uring_submit(&u->ring) < 0) {
        xrootd_uring_slot_release(u, idx);
        return NGX_OK;
    }

    u->inflight += slot->pending_cqes ? slot->pending_cqes : 1;
    *posted = 1;
    ctx->state = XRD_ST_AIO;            /* the selector also does this; harmless */
    return NGX_OK;
}

/* ---- per-op prep -------------------------------------------------------- */

/*
 * xrootd_uring_prep_read — IORING_OP_READ from xrootd_read_aio_t.
 * WHAT: prep a single pread SQE into t->databuf.  WHY: t->databuf is the same
 *       read_scratch slot the worker would have pread into, so the budget and
 *       response builder are unchanged (§10.1).  HOW: io_uring_prep_read; no
 *       IOSQE flags; pending_cqes=1.
 */
static ngx_int_t
xrootd_uring_prep_read(xrootd_uring_t *u, struct io_uring_sqe *sqe,
    ngx_thread_task_t *task)
{
    xrootd_read_aio_t *t = task->ctx;
    (void) u;
    io_uring_prep_read(sqe, t->fd, t->databuf, (unsigned) t->rlen,
                       (__u64) t->offset);
    /* pending_cqes lives on the slot; set by the caller after prep returns OK,
     * or set here via a back-pointer. First cut: caller defaults it to 1. */
    return NGX_OK;
}

/*
 * xrootd_uring_prep_write — IORING_OP_WRITE from xrootd_write_aio_t.
 * WHAT: prep a single pwrite SQE from t->data (the detached payload).  WHY:
 *       t->data points into t->payload_to_free, freed only in the done-callback
 *       after the CQE, so the in-flight write always reads live memory (§11.7).
 *       HOW: io_uring_prep_write; pending_cqes=1.
 */
static ngx_int_t
xrootd_uring_prep_write(xrootd_uring_t *u, struct io_uring_sqe *sqe,
    ngx_thread_task_t *task)
{
    xrootd_write_aio_t *t = task->ctx;
    (void) u;
    io_uring_prep_write(sqe, t->fd, t->data, (unsigned) t->len,
                        (__u64) t->offset);
    return NGX_OK;
}

/*
 * xrootd_uring_prep_readv — IORING_OP_READV (single coalesced group).
 * WHAT: build an iovec array from the segment descriptors' payload_ptr/
 *       read_length and prep a single preadv at the group base offset.  WHY:
 *       op_for already guaranteed one fd and <=64 segs; coalescing that the
 *       thread did inside xrootd_readv_read_segments is done here at prep time
 *       so the kernel sees the same grouped op (§9.6).  HOW: stack/scratch
 *       iovec, io_uring_prep_readv; NGX_DECLINED if a defensive recheck fails.
 */
static ngx_int_t
xrootd_uring_prep_readv(xrootd_uring_t *u, struct io_uring_sqe *sqe,
    ngx_thread_task_t *task)
{
    xrootd_readv_aio_t *t = task->ctx;
    struct iovec        iov[64];
    int                 fd0, k;
    off_t               base_off;

    if (t->segment_count == 0 || t->segment_count > 64) {
        return NGX_DECLINED;
    }
    fd0      = t->segments[0].fd;
    base_off = t->segments[0].offset;
    for (k = 0; k < (int) t->segment_count; k++) {
        if (t->segments[k].fd != fd0) {
            return NGX_DECLINED;        /* slipped past op_for: pool */
        }
        iov[k].iov_base = t->segments[k].payload_ptr;
        iov[k].iov_len  = t->segments[k].read_length;
    }
    /* The iovec must outlive submit; io_uring copies it at submit time for
     * IORING_OP_READV, so a stack array is safe here. If using SQPOLL or
     * deferred submit, move iov into the task or a registered iovec. */
    io_uring_prep_readv(sqe, fd0, iov, (unsigned) t->segment_count,
                        (__u64) base_off);
    return NGX_OK;
}

/*
 * xrootd_uring_prep_writev — IORING_OP_WRITEV (+ optional linked FSYNC).
 * WHAT: build the iovec from the writev segments, prep one writev SQE, and if
 *       t->do_sync is set, chain an IORING_OP_FSYNC with IOSQE_IO_LINK.  WHY:
 *       preserves the thread's "writev then fsync" semantics as one linked
 *       submission; a failed writev short-circuits the link (§9.6).  HOW: set
 *       IOSQE_IO_LINK on the writev SQE, get a second SQE for fsync, set
 *       pending_cqes=2.  NGX_DECLINED if a second SQE is unavailable.
 */
static ngx_int_t
xrootd_uring_prep_writev(xrootd_uring_t *u, struct io_uring_sqe *sqe,
    ngx_thread_task_t *task)
{
    xrootd_writev_aio_t *t = task->ctx;
    struct iovec         iov[64];
    struct io_uring_sqe *fsqe;
    int                  fd0, k;
    off_t                base_off;

    if (t->n_segs == 0 || t->n_segs > 64) {
        return NGX_DECLINED;
    }
    fd0      = t->segs[0].fd;
    base_off = t->segs[0].offset;
    for (k = 0; k < (int) t->n_segs; k++) {
        if (t->segs[k].fd != fd0) {
            return NGX_DECLINED;
        }
        iov[k].iov_base = (void *) t->segs[k].data;
        iov[k].iov_len  = t->segs[k].wlen;
    }
    io_uring_prep_writev(sqe, fd0, iov, (unsigned) t->n_segs,
                         (__u64) base_off);

    if (!t->do_sync) {
        /* slot->pending_cqes defaults to 1 (set by caller). */
        return NGX_OK;
    }

    /* chain a data-only fsync after the writev. */
    sqe->flags |= IOSQE_IO_LINK;
    fsqe = io_uring_get_sqe(&u->ring);
    if (fsqe == NULL) {
        /* can't chain: drop the sync mapping and stay on the pool for safety
         * (a writev without its fsync would violate the durability contract). */
        return NGX_DECLINED;
    }
    io_uring_prep_fsync(fsqe, fd0, IORING_FSYNC_DATASYNC);
    /* caller tags both SQEs with the same cookie and sets pending_cqes=2; the
     * second SQE is `sqe+1` in submission order — see the submit scaffolding. */
    return NGX_OK;
}

#endif /* XROOTD_HAVE_LIBURING */
```

Wiring caveat the implementer must resolve. The skeleton above shows `slot->pending_cqes` being set by the caller after prep returns; the cleanest real implementation passes the slot (or a small out-param struct) into `prep` so `prep_writev` can set `pending_cqes = t->do_sync ? 2 : 1` itself and report which trailing SQE to tag. The `sqe + 1` arithmetic in the submit scaffolding is illustrative only — `io_uring_get_sqe` does not guarantee contiguous SQE pointers across the ring wrap, so have `prep_writev` return the `fsqe` pointer (e.g. via an out-param) and tag it directly rather than computing `sqe + 1`. This is the one place to be careful; everything else is mechanical.

### 20.4 Compile / build wiring

These three files compile under one new gate and link `-luring` only when liburing is present; absent it, `uring.c`/`uring_submit.c` still compile (to the stub-bearing TUs — only the `#if` bodies vanish) and `uring.h` supplies the static-inline `NULL` accessor so the dispatcher links unchanged.

**`config` — pkg-config gate (place near the codec gate block, before `ngx_module_srcs`):**

```sh
# Optional Linux io_uring disk-I/O backend (Phase 44). Gated like the codecs
# (zstd/krb5): present -> -DXROOTD_HAVE_LIBURING + -luring; absent -> the new
# uring.c/uring_submit.c compile to stubs and the module uses the thread pool.
# Added to ngx_module_libs (NOT only CORE_LIBS) so the DYNAMIC build resolves.
XROOTD_URING_LIBS=""
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists liburing; then
    CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DXROOTD_HAVE_LIBURING=1"
    XROOTD_URING_LIBS="$(pkg-config --libs liburing)"
    echo " + xrootd io_uring backend: enabled"
else
    echo " + xrootd io_uring backend: disabled (install liburing-devel to enable)"
fi
```

**`ngx_module_srcs` — add the two new `.c` files** alongside the existing aio block (`config` lines 680-685):

```sh
    $ngx_addon_dir/src/aio/buffers.c \
    $ngx_addon_dir/src/aio/resume.c \
    $ngx_addon_dir/src/aio/reads.c \
    $ngx_addon_dir/src/aio/write.c \
    $ngx_addon_dir/src/aio/readv.c \
    $ngx_addon_dir/src/aio/dirlist.c \
    $ngx_addon_dir/src/aio/uring.c \
    $ngx_addon_dir/src/aio/uring_submit.c \
```

Both files are listed **unconditionally** — they compile to (mostly empty) TUs without liburing, matching the codec pattern where the backend "compiles to an unavailable descriptor". Do not make their inclusion conditional on the gate; that would create the mixed-ABI hazard §9.8 warns about and break incremental builds.

**`ngx_module_deps` — add the new header** to `ngx_xrootd_stream_deps` (alongside `src/aio/aio.h` at line 266):

```sh
                        $ngx_addon_dir/src/aio/aio.h \
                        $ngx_addon_dir/src/aio/uring.h \
```

This forces a rebuild of `resume.c` (the selector edit) and the two new TUs whenever `uring.h` changes — the §9.8 "any edit to a struct in a shared header requires the dependent `.c` rebuilt" rule, enforced by `make` dependency tracking rather than a manual `touch`.

**`ngx_module_libs` — append the uring link flags** (line 721):

```sh
ngx_module_libs="-lssl -lcrypto $XROOTD_JANSSON_LIBS $XROOTD_XML2_LIBS $XROOTD_KRB5_LIBS $XROOTD_CODEC_LIBS $XROOTD_URING_LIBS"
```

`$XROOTD_URING_LIBS` is empty when liburing is absent, so the link line is byte-identical to today in that case. As with the codecs, it goes into `ngx_module_libs` (the per-module link set used by the DYNAMIC build), not only `CORE_LIBS`; mirror it into `CORE_LIBS` only if a static-into-binary build must also resolve `-luring`.

**`#if` / `#else` stub strategy (link correctness, both configurations):**

- Every real type and function in `uring.c`/`uring_submit.c` is inside `#if (XROOTD_HAVE_LIBURING)`. Without the macro, both files are valid-but-near-empty TUs (a translation unit with no external definitions is legal C). No `-luring` symbol is referenced, so the link needs no liburing.
- The only header any other TU includes is `uring.h`. Its `#else` arm provides the `static ngx_inline xrootd_uring_t *xrootd_uring_worker(void) { return NULL; }` plus no-op `init_worker`/`exit_worker` inlines and the `xrootd_uring_submit`/`xrootd_uring_op_for` stub macros. The selector in `resume.c` is written as `xrootd_uring_t *u = xrootd_uring_worker(); if (u != NULL && !xrootd_uring_disabled(u)) { ... xrootd_uring_submit(...); }` — under the stub `u` is a compile-time `NULL`, the branch is dead-code-eliminated, and neither `xrootd_uring_disabled` nor `xrootd_uring_submit` is referenced, so the absence of their real definitions is harmless.
- `config.c`'s worker-init / worker-exit hooks call `xrootd_uring_init_worker(cycle)` / `xrootd_uring_exit_worker(cycle)` unconditionally; the stub inlines make those no-ops returning `NGX_OK` with liburing absent. This keeps the hook registration site free of `#if`s.
- Verification matrix to run before merge: (1) `pkg-config --exists liburing` present -> full ring path compiles and `nm` shows `io_uring_*` undefs resolved by `-luring`; (2) liburing dev package removed -> the same module sources compile, `nm` shows **no** `io_uring_*` undefined symbols, and the binary links and serves via the thread pool unchanged. Both must pass from a clean build (`make clean`) to avoid the mixed-ABI trap of §9.8.

---

## 21. Annotated client source skeletons (`client/lib/uring.{h,c}`, `copy.c` adapters, `aio.c` engine)

This appendix turns §12–§13 into near-final source. It is implementation-ready: real identifiers from `client/lib/{copy.c,aio.c,xrdc.h}`, the project's no-`goto` `*_create_fail()` unwind discipline (modeled on `xrdc_loop_create_fail`), and WHAT/WHY/HOW doc blocks on every nontrivial unit. Every io_uring line lives behind `#if (XROOTD_HAVE_LIBURING)`; the `#else` arm keeps the same symbols so callers never `#ifdef`. Bodies are detailed pseudocode with the real liburing calls; offsets/line numbers are deliberately omitted for new files.

### 21.1 `client/lib/uring.h` — public surface + stub fallback

```c
/*
 * uring.h — optional io_uring disk-I/O backend for the local side of xrdcp.
 * WHAT: an opaque deep-queue local-disk ring (xrdc_disk_ring) + a memoized
 *       capability probe (xrdc_uring_available). copy.c drives the ring through
 *       pump_src_local_uring / pump_sink_local_uring.
 * WHY:  overlap disk reads/writes with network I/O behind transfer_pump's
 *       unchanged synchronous one-chunk contract (§12, Option A).
 * HOW:  liburing registered-buffer pool + in-order slot release. Gated by
 *       XROOTD_HAVE_LIBURING; the #else branch compiles to inert stubs.
 */
#ifndef XRDC_URING_H
#define XRDC_URING_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "xrdc.h"                       /* xrdc_status / xrdc_status_set */

typedef struct xrdc_disk_ring xrdc_disk_ring;   /* opaque (full struct in uring.c) */

/* 1 iff this kernel+build support READ_FIXED/WRITE_FIXED + registered buffers.
 * Memoized real probe (io_uring_queue_init + io_uring_get_probe); never uname.
 * Returns 0 in a no-liburing build. */
int xrdc_uring_available(void);

#if (XROOTD_HAVE_LIBURING)
xrdc_disk_ring *xrdc_disk_ring_create(int fd, unsigned depth, unsigned nbuf,
                                      size_t bufsz, int direct, xrdc_status *st);
int  xrdc_disk_ring_drain(xrdc_disk_ring *r, xrdc_status *st);   /* flush before rename */
void xrdc_disk_ring_destroy(xrdc_disk_ring *r);
#else  /* inert stubs, same symbols */
xrdc_disk_ring *xrdc_disk_ring_create(int fd, unsigned depth, unsigned nbuf,
                                      size_t bufsz, int direct, xrdc_status *st);
int  xrdc_disk_ring_drain(xrdc_disk_ring *r, xrdc_status *st);
void xrdc_disk_ring_destroy(xrdc_disk_ring *r);
#endif
#endif /* XRDC_URING_H */
```

The header declares the same three prototypes in both arms; the *definitions* live in `uring.c` (its own `#if/#else`). Callers stay `#ifdef`-free while `lib/uring.c` is always in `LIB_SRCS` (§21.5).

### 21.2 `client/lib/uring.c` — ring implementation

```c
#include "uring.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if (XROOTD_HAVE_LIBURING)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <linux/fs.h>                   /* BLKSSZGET */
#include <liburing.h>

typedef enum { SLOT_FREE, SLOT_INFLIGHT, SLOT_DONE } slot_state;
typedef struct {
    slot_state state;
    uint32_t   seq;        /* monotonic op sequence; defines release order   */
    uint16_t   buf_index;  /* index into the registered iovec table          */
    int64_t    off; size_t len;
    int32_t    res;        /* cqe->res once SLOT_DONE (>=0 bytes, <0 -errno) */
} ring_slot;

struct xrdc_disk_ring {
    struct io_uring ring;
    int       fd, fixed_fd, direct, tail_fd;
    unsigned  depth, nbuf;  size_t bufsz, align;
    uint8_t  *slab;  struct iovec *iov;  ring_slot *slots;
    uint32_t  next_seq, release_seq;  unsigned inflight;
    int       eof_submitted, eof_drained;
    int       ring_inited, bufs_registered, file_registered;  /* unwind flags */
};

/* memoized: 1=yes 2=no 0=unknown; the real probe runs once. */
int xrdc_uring_available(void) {
    static int memo = 0; if (memo) return memo == 1;
    struct io_uring pr;
    if (io_uring_queue_init(8, &pr, 0) != 0) { memo = 2; return 0; }
    struct io_uring_probe *p = io_uring_get_probe_ring(&pr);
    int ok = p && io_uring_opcode_supported(p, IORING_OP_READ_FIXED)
               && io_uring_opcode_supported(p, IORING_OP_WRITE_FIXED)
               && io_uring_opcode_supported(p, IORING_OP_READ)
               && io_uring_opcode_supported(p, IORING_OP_WRITE);
    if (p) io_uring_free_probe(p);
    io_uring_queue_exit(&pr);
    memo = ok ? 1 : 2; return ok;
}

/* tear down a partially-built ring; mirrors xrdc_loop_create_fail (no goto). */
static xrdc_disk_ring *xrdc_disk_ring_create_fail(xrdc_disk_ring *r) {
    if (r->bufs_registered) io_uring_unregister_buffers(&r->ring);
    if (r->file_registered) io_uring_unregister_files(&r->ring);
    if (r->ring_inited)     io_uring_queue_exit(&r->ring);
    if (r->tail_fd >= 0)    close(r->tail_fd);
    free(r->slots); free(r->iov); free(r->slab); free(r);
    return NULL;
}

xrdc_disk_ring *xrdc_disk_ring_create(int fd, unsigned depth, unsigned nbuf,
                                      size_t bufsz, int direct, xrdc_status *st) {
    xrdc_disk_ring *r = calloc(1, sizeof(*r));
    if (!r) { xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (disk ring)"); return NULL; }
    r->fd = fd; r->tail_fd = -1; r->direct = direct;
    r->depth = depth ? depth : 4; r->nbuf = nbuf ? nbuf : r->depth;
    r->bufsz = bufsz; r->align = 1;
    if (direct) { r->align = ring_derive_align(fd);
                  r->bufsz = (r->bufsz + r->align - 1) & ~(r->align - 1); }
    int ret = io_uring_queue_init(r->depth, &r->ring, 0);
    if (ret) { xrdc_status_set(st, XRDC_ESOCK, -ret, "queue_init: %s", strerror(-ret));
               return xrdc_disk_ring_create_fail(r); }
    r->ring_inited = 1;
    if (posix_memalign((void **) &r->slab, r->align ? r->align : sizeof(void *),
                       (size_t) r->nbuf * r->bufsz)) {
        r->slab = NULL; xrdc_status_set(st, XRDC_EPROTO, 0, "oom (slab)");
        return xrdc_disk_ring_create_fail(r); }
    r->iov = calloc(r->nbuf, sizeof(*r->iov));
    if (!r->iov) { xrdc_status_set(st, XRDC_EPROTO, 0, "oom (iov)"); return xrdc_disk_ring_create_fail(r); }
    for (unsigned i = 0; i < r->nbuf; i++) {
        r->iov[i].iov_base = r->slab + (size_t) i * r->bufsz; r->iov[i].iov_len = r->bufsz; }
    ret = io_uring_register_buffers(&r->ring, r->iov, r->nbuf);
    if (ret) { xrdc_status_set(st, XRDC_ESOCK, -ret, "register_buffers: %s", strerror(-ret));
               return xrdc_disk_ring_create_fail(r); }
    r->bufs_registered = 1;
    if (io_uring_register_files(&r->ring, &r->fd, 1) == 0) { r->file_registered = 1; r->fixed_fd = 1; }
    r->slots = calloc(r->nbuf, sizeof(*r->slots));
    if (!r->slots) { xrdc_status_set(st, XRDC_EPROTO, 0, "oom (slots)"); return xrdc_disk_ring_create_fail(r); }
    r->next_seq = r->release_seq = 0; r->inflight = 0;
    return r;
}
/* ring_checkout / ring_return / ring_submit_read|write / ring_reap_one /
 * ring_ready_in_order / ring_any_done — the §12.3 primitives; user_data carries
 * the slot index, the slot's seq carries ordering; a read cqe->res==0 = EOF. */

int xrdc_disk_ring_drain(xrdc_disk_ring *r, xrdc_status *st) {
    if (!r) return 0; int rc = 0;
    while (r->inflight) if (ring_reap_one(r, 1) < 0 && !rc) { xrdc_status_set(st, XRDC_ESOCK, 0, "drain reap"); rc = -1; }
    for (unsigned i = 0; i < r->nbuf; i++) {
        if (r->slots[i].state != SLOT_DONE) continue; int32_t res = r->slots[i].res;
        if (res < 0 && !rc) { xrdc_status_set(st, XRDC_ESOCK, -res, "uring write: %s", strerror(-res)); rc = -1; }
        else if (res >= 0 && (size_t) res < r->slots[i].len && !rc) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "short write %d/%zu", res, r->slots[i].len); rc = -1; }
        r->slots[i].state = SLOT_FREE; }
    return rc;
}
void xrdc_disk_ring_destroy(xrdc_disk_ring *r) {
    if (!r) return;
    while (r->inflight) if (ring_reap_one(r, 1) < 0) break;     /* drain-before-free */
    if (r->bufs_registered) io_uring_unregister_buffers(&r->ring);
    if (r->file_registered) io_uring_unregister_files(&r->ring);
    if (r->ring_inited)     io_uring_queue_exit(&r->ring);
    if (r->tail_fd >= 0)    close(r->tail_fd);
    free(r->slots); free(r->iov); free(r->slab); free(r);
}
#else  /* out-of-line inert definitions */
int  xrdc_uring_available(void) { return 0; }
xrdc_disk_ring *xrdc_disk_ring_create(int fd, unsigned d, unsigned n, size_t b, int dir, xrdc_status *st)
{ (void) fd;(void) d;(void) n;(void) b;(void) dir; if (st) xrdc_status_set(st, XRDC_EUSAGE, 0, "io_uring not built in"); return NULL; }
int  xrdc_disk_ring_drain(xrdc_disk_ring *r, xrdc_status *st) { (void) r;(void) st; return 0; }
void xrdc_disk_ring_destroy(xrdc_disk_ring *r) { (void) r; }
#endif
```

### 21.3 `client/lib/copy.c` additions — pump adapters + selection wiring

Pure ADDITIONS; `transfer_pump` and every existing adapter are untouched. The new adapters satisfy the same `pump_src_fn`/`pump_sink_fn` typedefs and drop into the existing `transfer_pump` calls.

```c
#include "uring.h"
typedef struct { xrdc_disk_ring *r; int fd; int64_t pos; } pump_localring_t;

/* SOURCE: depth-deep read-ahead ring. FILL the window (checkout/submit_read/
 * seq++/io_uring_submit), then DRAIN in seq order (ready_in_order → memcpy →
 * return → release_seq++); 0-len read = EOF, short read latches EOF + rewinds. */
static ssize_t pump_src_local_uring(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st);

/* SINK: depth-deep write-behind ring. Reap finished writes (surface errors
 * first), block if the pool is full (backpressure), memcpy into a registered
 * buffer, submit WRITE_FIXED, return while it drains. copy_download MUST
 * xrdc_disk_ring_drain() before the atomic rename. */
static int pump_sink_local_uring(void *ctx, const uint8_t *buf, int64_t off, size_t n, xrdc_status *st);

/* copy_download selection (silent fallback; temp+rename discipline unchanged): */
int use_ring = (o->io_uring != 2) && xrdc_uring_available()
               && (o->io_uring == 1 || si->size >= XRDC_URING_AUTO_MIN);
if (use_ring) {
    xrdc_disk_ring *r = xrdc_disk_ring_create(outfd, XRDC_URING_DEPTH, XRDC_URING_DEPTH,
                                              XRDC_COPY_CHUNK, o->direct, st);
    if (r) { pump_localring_t lr = { r, outfd, 0 };
             rc = transfer_pump(pump_src_remote, &src, pump_sink_local_uring, &lr, si->size, o, si->size, st);
             if (rc == 0) rc = xrdc_disk_ring_drain(r, st);   /* flush BEFORE rename */
             xrdc_disk_ring_destroy(r);
    } else { xrdc_status_clear(st);
             rc = transfer_pump(pump_src_remote, &src, pump_sink_local, &outfd, si->size, o, si->size, st); }
} else rc = transfer_pump(pump_src_remote, &src, pump_sink_local, &outfd, si->size, o, si->size, st);
```

`copy_upload` is symmetric (`pump_src_local_uring` over `infd`, sink stays `pump_sink_remote`). New `o->io_uring`/`o->direct` opts + `XRDC_URING_DEPTH`/`XRDC_URING_AUTO_MIN` constants live in `xrdc.h`. Recursive/r2r paths stay synchronous (Option A keeps the diff minimal).

### 21.4 `client/lib/aio.c` engine additions — the vtable

```c
typedef struct { void *ptr; uint32_t events; } engine_ev;    /* events = epoll bitmask */
typedef struct {
    int  (*create)(xrdc_loop *l, xrdc_status *st);  void (*destroy)(xrdc_loop *l);
    void (*arm)(xrdc_aconn *ac, int want);          int  (*wait)(xrdc_loop *l, int to, engine_ev *ev, int max);
    void (*wake)(xrdc_loop *l);                     void (*cancel)(xrdc_aconn *ac);
} engine_vtbl;
/* xrdc_loop gains: const engine_vtbl *eng; (+ io_uring ring under the guard).
 * xrdc_aconn gains the ONE new field: uint32_t fd_gen; (+ poll_mask/poll_armed/
 * slot_idx under the guard, zero-inited by the existing calloc). */

/* ENGINE_EPOLL: thin wrappers around today's code (zero behavior change):
 *   arm=aconn_update_epoll, wait=epoll_wait→engine_ev[], wake=write(evfd),
 *   cancel=epoll_ctl(DEL), create/destroy = the existing epfd+evfd block. */

#if (XROOTD_HAVE_LIBURING)
/* engine_uring_arm: multishot IORING_OP_POLL_ADD (POLLIN always, POLLOUT iff
 *   wbuf pending); a mask change cancels+re-submits. TLS-safe: loop still runs
 *   aconn_do_read/write so SSL_* keep their own syscalls.
 * engine_uring_wait: io_uring_wait_cqe_timeout + for_each_cqe; drop fd_gen-
 *   mismatched (stale) CQEs; map poll revents→epoll bits; re-arm on F_MORE clear.
 * engine_uring_cancel: io_uring_prep_cancel64 on the fd's multishot + fd_gen++. */
static const engine_vtbl ENGINE_URING = { /* … */ };
#endif
/* xrdc_loop_create: default ENGINE_EPOLL; ENGINE_URING only if explicitly
 * requested AND xrdc_uring_available(). xrdc_loop_create_fail extended to call
 * l->eng->destroy(l). loop_thread changes only its wait/dispatch lines. */
```

`aconn_update_epoll`/`aconn_on_transport_error` are refactored to call `ac->loop->eng->arm/cancel` — under epoll they route straight back to the original code. Sub-option ii-b (cleartext `RECV`/`SEND` multishot, §13.4) is layered later inside the `ac->ssl == NULL` branch only.

### 21.5 Build wiring — `client/Makefile`

`lib/uring.c` is ALWAYS in `LIB_SRCS` (it self-stubs). The `HAVE_LIBURING` block mirrors `HAVE_KRB5`/FUSE3:

```make
HAVE_LIBURING := $(shell pkg-config --exists liburing 2>/dev/null && echo yes)
ifeq ($(HAVE_LIBURING),yes)
  URING_CFLAGS := -DXROOTD_HAVE_LIBURING=1 $(shell pkg-config --cflags liburing 2>/dev/null)
  URING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null)
else
  URING_CFLAGS := -DXROOTD_HAVE_LIBURING=0
endif
# ALL_CFLAGS += $(URING_CFLAGS) ; LDLIBS += $(URING_LIBS) ; LIB_SRCS += lib/uring.c
```

`URING_CFLAGS` defines the macro (to `0`) for every TU so the `#if` guards are well-formed everywhere; the existing `%.o`/`%.pic.o` pattern rules produce `lib/uring.o`/`.pic.o` with no new rules. Add `liburing` to `libxrdc.pc` `Requires.private` only inside the `HAVE_LIBURING=yes` arm.

---

## 22. Exact edit hunks for existing files

> **Indicative line numbers.** Each `@@` header carries the line numbers as they stood when these files were read. They are advisory — the surrounding context lines (real function/variable names) are the load-bearing anchors; the implementer re-anchors with `git apply --recount`. Each hunk ends with a **configure?** note: whether a fresh nginx `./configure` (regenerating `objs/Makefile`) is required, versus a plain `make`.

### 22.1 `config` (root nginx module config script)

**(a) liburing detection — after the krb5 block (~line 122):**
```diff
@@ elif command -v krb5-config ...; then
      echo " + xrootd auth: Kerberos 5 plugin disabled ..."
  fi
+
+# Optional io_uring disk-I/O backend (phase-44). Double-gated: XROOTD_ENABLE_IO_URING
+# *and* liburing present. -luring goes into the STREAM ngx_module_libs (NOT CORE_LIBS):
+# the dynamic .so is linked with ngx_module_libs, so it must live there or dlopen fails
+# with "undefined symbol: io_uring_queue_init".
+XROOTD_URING_LIBS=""
+if [ -n "$XROOTD_ENABLE_IO_URING" ] && pkg-config --exists liburing; then
+    CFLAGS="$CFLAGS $(pkg-config --cflags liburing) -DXROOTD_HAVE_LIBURING=1"
+    XROOTD_URING_LIBS="$(pkg-config --libs liburing)"   # -luring
+    echo " + xrootd: io_uring backend enabled (liburing $(pkg-config --modversion liburing))"
+fi
```
**(b) `uring.h` into the stream deps (~line 266):**
```diff
                         $ngx_addon_dir/src/aio/aio.h \
+                        $ngx_addon_dir/src/aio/uring.h \
```
**(c) `uring.c`+`uring_submit.c` into `ngx_module_srcs` (~line 685):**
```diff
     $ngx_addon_dir/src/aio/reads.c \
+    $ngx_addon_dir/src/aio/uring.c \
+    $ngx_addon_dir/src/aio/uring_submit.c \
     $ngx_addon_dir/src/aio/write.c \
```
**(d) `$XROOTD_URING_LIBS` into the STREAM `ngx_module_libs` (line 721 — NOT CORE_LIBS on 722):**
```diff
-ngx_module_libs="-lssl -lcrypto $XROOTD_JANSSON_LIBS $XROOTD_XML2_LIBS $XROOTD_KRB5_LIBS $XROOTD_CODEC_LIBS"
+ngx_module_libs="-lssl -lcrypto $XROOTD_JANSSON_LIBS $XROOTD_XML2_LIBS $XROOTD_KRB5_LIBS $XROOTD_CODEC_LIBS $XROOTD_URING_LIBS"
 CORE_LIBS="$CORE_LIBS -lssl -lcrypto"
```
**configure?** **Yes** — `config` edits only take effect after re-running `./configure … --add-module=…`, which regenerates `objs/Makefile` with the new sources, dep, and the `-luring` link line.

### 22.2 `src/aio/resume.c` — io_uring tier in `xrootd_aio_post_task`
```diff
 #include "ngx_xrootd_module.h"
+#include "aio/uring.h"
@@ xrootd_aio_post_task(...)
 {
     *posted = 0;
+#if (XROOTD_HAVE_LIBURING)
+    xrootd_uring_t   *u  = xrootd_uring_worker();
+    xrootd_uring_op_e op = xrootd_uring_op_for(task);
+    if (u != NULL && !xrootd_uring_disabled(u) && op != XRD_URING_OP_NONE
+        && u->inflight < u->queue_depth) {
+        if (xrootd_uring_submit(ctx, c, task, op, posted) == NGX_OK && *posted) {
+            ctx->state = XRD_ST_AIO;
+            return NGX_OK;          /* in-flight on the ring */
+        }
+        /* prep/submit failed → *posted still 0 → fall through to the pool */
+    }
+#endif
     if (pool == NULL) return NGX_OK;
     if (ngx_thread_task_post(pool, task) != NGX_OK) {
         ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", fallback_log);
         return NGX_OK;
     }
     ctx->state = XRD_ST_AIO; *posted = 1; return NGX_OK;
 }
```
**configure?** **No** (source edit to a file already in the build; plain `make`). The `-D` gate itself comes from `config`, so a *first* enable needs one `./configure`.

### 22.3 `src/config/process.c` — worker init/exit hooks
```diff
@@ ngx_stream_xrootd_init_process(...)
     xrootd_imp_init_worker(cycle);
+    /* Phase 44: create this worker's ring (no-op unless built+configured on). */
+    xrootd_uring_init_worker(cycle);
     return NGX_OK;
@@ xrootd_exit_process(...)
         if (xcf->rootfd >= 0) { close(xcf->rootfd); xcf->rootfd = -1; }
     }
+    xrootd_uring_exit_worker(cycle);   /* drain-then-queue_exit; no-op if no ring */
     xrootd_crypto_cleanup();
```
The hooks are no-op inlines when `XROOTD_HAVE_LIBURING` is undefined, so `process.c` needs no `#ifdef`. **configure?** **No.**

### 22.4 `src/types/tunables.h` — `XROOTD_IO_URING_*` defines
```diff
 #define XROOTD_PIPELINE_MAX            4
+/* Phase 44 — io_uring backend tunables (header-only; the runtime probe is
+ * authoritative; these MIN_KERNEL_* are a fast pre-filter). */
+#define XROOTD_IO_URING_QUEUE_DEPTH            256
+#define XROOTD_IO_URING_MIN_KERNEL_MAJOR       5
+#define XROOTD_IO_URING_MIN_KERNEL_MINOR       6
+#define XROOTD_IO_URING_RESTRICT_KERNEL_MINOR  10
```
**configure?** **No** (header-only; in `ngx_module_deps`, so `make` recompiles dependents).

### 22.5 `src/types/config.h` — new `ngx_stream_xrootd_srv_conf_t` fields
```diff
     ngx_flag_t  read_compress;
+    /* Phase 44 — io_uring disk-I/O backend. */
+    ngx_uint_t  io_uring;            /* enum off|on|auto (XROOTD_IO_URING_MODE_*) */
+    ngx_flag_t  io_uring_restrict;   /* register_restrictions whitelist (default on) */
```
**configure?** **No** (header in `ngx_module_deps`).

### 22.6 `src/stream/module.c` (commands[]+enum) and `src/config/server_conf.c` (create/merge)
> The compiled stream module is `src/stream/module.c`; `module_core_directives.c` is **not** in the build — do not edit it.
```diff
+/* Phase 44 — io_uring selector mode. */
+static ngx_conf_enum_t xrootd_io_uring_modes[] = {
+    { ngx_string("off"),  XROOTD_IO_URING_MODE_OFF  },
+    { ngx_string("on"),   XROOTD_IO_URING_MODE_ON   },
+    { ngx_string("auto"), XROOTD_IO_URING_MODE_AUTO },
+    { ngx_null_string,    0 } };
@@ commands[]
+    { ngx_string("xrootd_io_uring"),
+      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ngx_conf_set_enum_slot,
+      NGX_STREAM_SRV_CONF_OFFSET, offsetof(ngx_stream_xrootd_srv_conf_t, io_uring),
+      xrootd_io_uring_modes },
+    { ngx_string("xrootd_io_uring_restrict"),
+      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
+      NGX_STREAM_SRV_CONF_OFFSET, offsetof(ngx_stream_xrootd_srv_conf_t, io_uring_restrict), NULL },
```
```diff
@@ create_srv_conf (server_conf.c)
+    conf->io_uring          = NGX_CONF_UNSET_UINT;
+    conf->io_uring_restrict = NGX_CONF_UNSET;
@@ merge_srv_conf
+    ngx_conf_merge_uint_value(conf->io_uring, prev->io_uring, XROOTD_IO_URING_MODE_OFF);
+    ngx_conf_merge_value(conf->io_uring_restrict, prev->io_uring_restrict, 1);
```
A `postconfiguration` check (`xrootd_uring_validate_conf`, §32.4) rejects `io_uring on` when the backend is not compiled in OR the runtime probe fails — returning `NGX_ERROR` so `nginx -t` fails and the master refuses to start (§32). **configure?** **No.**

### 22.7 `src/dashboard/api_admin.c` — `POST /xrootd/api/v1/admin/io_uring`
```diff
@@ (body handler, beside admin_cluster_register)
+static ngx_int_t admin_io_uring(ngx_http_request_t *r, json_t *body) {
+    const char *action = json_string_value(json_object_get(body, "action"));
+    const char *reason = json_string_value(json_object_get(body, "reason"));
+    if (!action) return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_field");
+    if (ngx_strcmp(action, "disable") == 0) {
+        xrootd_uring_kill_switch_set(1, XROOTD_URING_DISABLE_ADMIN);
+        admin_audit(r, "io_uring", "disable", reason ? reason : "disabled");
+        return admin_send_ok(r, "disabled");
+    }
+    if (ngx_strcmp(action, "enable") == 0) {
+        if (xrootd_uring_panic_file_present())
+            return admin_send_error(r, NGX_HTTP_CONFLICT, "panic_file_present");
+        xrootd_uring_kill_switch_set(0, XROOTD_URING_DISABLE_NONE);
+        admin_audit(r, "io_uring", "enable", "enabled");
+        return admin_send_ok(r, "enabled");
+    }
+    return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_field");
+}
@@ xrootd_admin_dispatch() (auth already checked once)
+    if (admin_uri_eq(r, ADMIN_PREFIX "io_uring")) {
+        if (r->method == NGX_HTTP_POST) return xrootd_admin_read_body(r, admin_io_uring);
+        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
+    }
```
Inherits the `xrootd_admin_check_auth` gate (bearer `CRYPTO_memcmp` + CIDR) verbatim. **configure?** **No.**

### 22.8 `src/metrics/metrics.h` (+ `metrics_macros.h`) — io_uring metric block
```diff
@@ (enum widths, beside the FRM block)
+#define XROOTD_URING_OP_READ  0 ... XROOTD_URING_NOP 4
+#define XROOTD_URING_FB_DISABLED 0 ... XROOTD_URING_NFB 4
+#define XROOTD_URING_SUBMIT_LATENCY_BUCKETS 8
@@ (sibling of ngx_xrootd_frm_metrics_t)
+typedef struct {
+    ngx_atomic_t active, enabled_config, inflight, submit_total, stale_cqe_total;
+    ngx_atomic_t kill_switch, panic_file_present, restrict_active;
+    ngx_atomic_t ops_total[XROOTD_URING_NOP], fallback_total[XROOTD_URING_NFB];
+    ngx_atomic_t cqe_errors_total[XROOTD_URING_NOP];
+    ngx_atomic_t submit_latency_bucket[XROOTD_URING_SUBMIT_LATENCY_BUCKETS];
+    ngx_atomic_t submit_latency_count, submit_latency_sum_usec;
+} ngx_xrootd_uring_metrics_t;
@@ (root metrics struct, beside frm)
     ngx_xrootd_frm_metrics_t     frm;
+    ngx_xrootd_uring_metrics_t   uring;
```
Plus `XROOTD_URING_METRIC_INC/DEC/ADD` in `metrics_macros.h`, same `xrootd_metrics_shared()` no-op-when-unmapped pattern as FRM. **ABI note:** declare every field up-front (one-time SHM ABI bump; land with the rest of phase-44). **configure?** **No.**

### 22.9 `src/dashboard/dashboard.h` — `io_uring_disabled` SHM control struct
```diff
+/* Phase 44 — io_uring kill-switch control block. Slab-safe (xrootd_shm_table_alloc);
+ * lock MUST be first (shm_slots.c contract). Hot path reads io_uring_disabled
+ * LOCK-FREE; the lock guards only the rare admin/panic write. */
+typedef struct {
+    ngx_shmtx_sh_t  lock;
+    ngx_atomic_t    io_uring_disabled;  /* 0=enabled, 1=disabled fleet-wide */
+    ngx_atomic_t    disable_reason;     /* none|admin|panic|probe           */
+    ngx_atomic_t    disabled_epoch_ms;
+} xrootd_iouring_ctl_t;
```
**configure?** **No.**

### 22.10 `client/Makefile` — `HAVE_LIBURING` gate
```diff
 HAVE_KRB5 := $(shell pkg-config --exists krb5 ...)
+HAVE_LIBURING := $(shell pkg-config --exists liburing 2>/dev/null && echo yes)
+ifeq ($(HAVE_LIBURING),yes)
+  URING_CFLAGS := -DXROOTD_HAVE_LIBURING $(shell pkg-config --cflags liburing 2>/dev/null)
+  URING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null)
+endif
-ALL_CFLAGS := ... $(KRB5_CFLAGS) $(CFLAGS)
+ALL_CFLAGS := ... $(KRB5_CFLAGS) $(URING_CFLAGS) $(CFLAGS)
-LDLIBS := -lssl -lcrypto -lz $(KRB5_LIBS) $(CODEC_LIBS)
+LDLIBS := -lssl -lcrypto -lz $(KRB5_LIBS) $(CODEC_LIBS) $(URING_LIBS)
-LIB_SRCS := ... lib/aio.c lib/aio_mgr.c lib/streams.c ...
+LIB_SRCS := ... lib/aio.c lib/aio_mgr.c lib/uring.c lib/streams.c ...
-  'Requires.private: libssl libcrypto zlib' \
+  'Requires.private: libssl libcrypto zlib$(if $(URING_LIBS), liburing)' \
```
**configure?** **N/A** (client Makefile). After toggling the gate, `make -C client clean && make -C client` so stale objects built without the `-D` are rebuilt.

### 22.11 `client/lib/xrdc.h` — `xrdc_copy_opts.io_uring` + `.direct`
```diff
     int         recursive;
+    /* Phase 44 — local disk I/O engine. io_uring: 0=off (default), 1=on, 2=force-off;
+     * silently falls back to pread/pwrite when unavailable. */
+    int         io_uring;
+    int         direct;   /* 1 => O_DIRECT for the uring path; ignored when io_uring==0 */
```
**configure?** **N/A.**

### 22.12 `client/lib/copy.c` + `client/lib/aio.c` — integration hunks
The two engine-selection seams (full bodies in §21): `copy.c` `download_stream_body`/`copy_upload` choose the `*_uring` adapter under `o->io_uring && xrdc_uring_available()` (fall back on any failure, `transfer_pump` signature intact); `aio.c` adds `uint32_t fd_gen` to `struct xrdc_aconn` and bumps it at both fd-(re)assign sites, plus the `engine_vtbl` selection at `xrdc_loop_create`. **configure?** **N/A** (client TUs; `make -C client`).

---

## 23. State machines & sequence diagrams

Formal state machines and message-sequence diagrams to audit the backend's control flow without reading code. Every machine is single-actor on the hot path: the **event thread** (server worker / client loop thread) owns all transitions except the two kernel-driven (CQ-ring writes) or cross-worker (SHM kill-switch). Notation: `S --event/action--> S'`; guards in `[...]`; `==>` syscall/submit, `~~>` kernel-async, `-->` in-process posting.

### 23.1 Ring lifecycle FSM (server, per worker)

| State | Event | Next | Action |
|---|---|---|---|
| UNINIT | `init_process`, `on`, macro defined | PROBING | `queue_init_params(R_DISABLED)`; register restrictions; probe; register_eventfd; wrap evc; alloc slots |
| UNINIT | `off` OR macro undefined | DISABLED | none (every submit short-circuits) |
| PROBING | probe ok, restrictions accepted | ENABLED | `enabled=1`; `enable_rings`; arm panic timer |
| PROBING | init/probe/restrict fails | DISABLED | `enabled=0`; SHM `disable_reason=probe`; log once |
| ENABLED | submit reads SHM `disabled != 0` | DRAINING | stop new submits; reaper continues |
| ENABLED | worker_exit / reload | DRAINING | `ngx_del_event(evc->read)`; stop submits |
| DISABLED | SHM flag cleared, ring live | ENABLED | `enabled=1` (lazy re-init if torn down) |
| DRAINING | reaper sees `inflight==0` + quiesce | EXITED | `unregister_eventfd`; `queue_exit`; `close(eventfd)`; `ngx_close_connection(evc)` |
| DRAINING | flag cleared before drain done | ENABLED | resume submits (ring never exited) |
| DRAINING | `inflight > 0` | DRAINING | reap one CQE; `inflight--` (self-loop) |

```
   UNINIT ──init(off|!macro)──► DISABLED ◄────────┐ flag set (re-enter drain)
     │ init(on)                  ▲  │ flag clear   │
     ▼                     probe │  ▼               │
  PROBING ──ok──► ENABLED ───────┘  ENABLED         │
     │ fail                │ flag set / worker_exit  │
     ▼                     ▼                         │
  DISABLED            DRAINING ──flag clear──────────┘
                      │  ▲ inflight>0 (reap, self-loop)
   inflight==0 &      ▼  │
   quiesce         EXITED (queue_exit; terminal)
```
`EXITED` is reachable only through `DRAINING` with `inflight==0` — no path exits the ring while a CQE is outstanding (the §24.4 teardown proof).

### 23.2 Completion-slot lifecycle FSM (server)

| State | Event | Next | Action |
|---|---|---|---|
| FREE | `slot_acquire` [`inflight<depth`] | CLAIMED | set task/done_fn/op_kind; `in_use=1`; `ud=(gen<<32)\|i`; `inflight++` |
| FREE | `slot_acquire` [`inflight==depth`] | FREE | DECLINE (caller → pool) |
| CLAIMED | `prep + submit` ok | SUBMITTED | SQE on ring; `*posted=1` |
| CLAIMED | `get_sqe`/`submit` fails | FREE | `in_use=0`; `gen++`; `inflight--`; `*posted=0` |
| SUBMITTED | kernel CQ write; eventfd fires | REAPING | reaper `peek_cqe`; `validate_and_take(ud)` matches |
| REAPING | `apply_cqe` final | FREE | translate res→OUT; `post_event(&ngx_posted_events)`; release (`gen++`) |
| REAPING | `apply_cqe` not final (writev+fsync) | SUBMITTED | accumulate; `cqe_seen`; slot stays `in_use` for the linked CQE |
| any decoded | stale: `!in_use \|\| gen≠ud.gen` | (unchanged) | drop; `cqe_seen`; `inflight--`; counter++ |

The generation bump on every free is the load-bearing edge: a CQE arriving after the slot was released and re-acquired carries the old gen, fails `validate_and_take`, and takes the stale edge instead of dereferencing the wrong task.

### 23.3 Server connection state under io_uring

The existing `xrootd_state_e` is unchanged. The ring submit/CQE sit entirely inside the `XRD_ST_AIO` sojourn — io_uring is a submission swap behind the same state (Option A).
```
 REQ_HEADER ─►REQ_PAYLOAD ─►[dispatch]─warm-cache hit (inline pread, no SQE)─►build resp─►SENDING
                              │ miss
                              ▼ post_task → URING submit; ctx->state=AIO (SQE on ring)
                              │ ~~> kernel + eventfd
                              ▼ reaper: post done-event (NOT inline, §23.4b)
                              ▼ posted drain: *_aio_done; restore_stream[destroyed?]
                              ▼ SENDING ─drain─► REQ_HEADER (next request)
```
A windowed read loops `AIO→SENDING→AIO`, one fresh SQE per window.

### 23.4 Server sequence diagrams

Lifelines: `Client | EventThread | Ring/Kernel | io-wq | PostedEvents`.

**(a) kXR_read — warm-cache hit (no SQE):**
```
Client    EventThread             Ring   io-wq  Posted
 │ read    │ preadv2(RWF_NOWAIT) hit      │      │
 │────────►│ build kXR_ok                 │      │
 │◄────────│ send (SENDING→REQ_HEADER)    │      │
```
**(b) kXR_read — miss:**
```
 │ read ───►│ probe miss; slot_acquire(g,i); prep_read; submit ══►│ ═►io-wq pread
 │          │ state=AIO (park)                            ◄~~done~~│
 │          │◄ eventfd; REAPER: validate(g,i) OK; t->nread=res
 │          │ post_event ─────────────────────────────────────────► Posted
 │          │ slot_release(gen++); inflight--; cqe_seen
 │          │◄ posted drain: read_aio_done → emit chunk → SENDING
 │◄─────────│ send data
```
**(c) kXR_write — detached-payload lifetime:** payload allocated at detach, **alive across the in-flight pwrite**, freed **only** in `write_aio_done` (post-CQE) — so the kernel never reads freed memory.

**(d) kXR_writev + linked FSYNC:** two CQEs share the slot; the writev CQE keeps the slot `in_use` (REAPING→SUBMITTED), `apply_cqe` returns 0; the fsync CQE finalizes (`pending_cqes→0`, returns 1). A failed writev auto-cancels the linked fsync (`-ECANCELED` on CQE #2, folded into `io_error`).

**(e) Connection drop mid-read:** `ctx->destroyed=1` on close (slot NOT freed); the later CQE matches the slot, posts the event, and `read_aio_done`'s `restore_stream` returns 0 on `ctx->destroyed` → touches nothing. Here the **connection guard** neutralizes it; the slot generation only fires when the slot was *recycled* by a different task.

**(f) Kill-switch flip under load:** an admin/panic worker `atomic_store(disabled=1)`; the next submit read sees it → DRAINING; new ops fall to the pool; the reaper keeps reaping in-flight CQEs to `inflight==0`. No in-flight SQE is cancelled or dropped (the SEC-2 property).

**(g) Worker exit/reload:** `ngx_del_event(evc->read)` → stop submits → optional spin until `inflight==0` → `unregister_eventfd` → `queue_exit` (kernel drains/abandons) → close. Any abandoned CQE's task belongs to a connection already torn down and guarded by `ctx->destroyed`.

### 23.5 Client sequence diagrams

**(a) Disk-ring download overlap (single copy thread):** chunk k → checkout buf → submit pwrite k (does NOT block; pump returns); chunk k+1 → submit pwrite k+1; when `free_top==0`, `wait_cqe`; out-of-order completions are held in `done_ring` until `next_retire_seq` reaches them, then released in order — buffer k freed only after op k completes and all `0..k-1` retired.

**(b) Engine POLL_ADD readiness (TLS-safe):** multishot CQE (POLLIN, F_MORE set) → decode ud, `gen==ac->fd_gen` OK → map to EPOLLIN → `aconn_handle_io` → `aconn_do_read` → `SSL_read`/`recv` (own syscall) → `aconn_parse`. If `!F_MORE`, re-submit the multishot.

**(c) Reconnect + ASYNC_CANCEL + fd_gen drop:** transport error → `engine.cancel`: `prep_cancel` + `poll_armed=0` + `ac->fd_gen++` → a stale CQE for the old fd carries the old gen and is **dropped** → reconnect worker dials a new fd off-thread → `engine.arm` submits a fresh multishot stamped with the new `fd_gen` → parked retry-safe requests re-issued.

---

## 24. Concurrency & memory-ordering model

The thread-safety audit. Governing fact: on each side there is exactly **one** mutator thread (server worker event thread; client copy/loop thread). All apparent concurrency reduces to three narrow channels — (1) the kernel-written ring tail/CQ, mediated by liburing barriers; (2) the cross-worker SHM kill-switch, a single word; (3) cross-thread command queues woken by eventfd.

### 24.1 The "single event thread" invariant (server)

| Field | Writers | Readers | Ordering | Why safe |
|---|---|---|---|---|
| `ring` (SQ/CQ mmap) | ET (SQ tail), Kernel (CQ tail) | ET (CQ), Kernel (SQ) | liburing store-release/load-acquire | only cross-context mem; barriers (§24.2); never 2 userspace ctx |
| `eventfd` | once (ET); Kernel (counter) | ET (reaper read) | eventfd atomicity | kernel inc atomic; ET drains |
| `inflight` | ET (submit++/reap--) | ET (backpressure) | none | **single thread** — not atomic by design |
| `enabled:1` | init (ET) | ET | none | one writer |
| `slots[i].*` | ET (acquire/release) | ET (validate/apply) | none | single thread; gen guard for stale CQE |
| `slots[i].generation` | ET (++ on free) | ET (validate) | none | monotone per slot; UAF guard |
| `disabled_flag` (SHM) | admin/panic (atomic store) | ET (relaxed load) | single-word atomicity | one-op-stale read OK (§24.3) |
| `*_aio_t` OUT fields | ET reaper | ET done-cb | program order, one thread | happens-before via posted queue |
| detached payload | ET (alloc/free) | Kernel (pwrite) | freed post-CQE | §24.4 rule D |

The reaper writes OUT fields then `post_event` and returns; nginx later drains `ngx_posted_events` and calls the done-callback — both on the same thread, sequentially. Program-order happens-before makes atomics/barriers unnecessary for OUT fields; this is why `inflight` and the slot table are plain scalars.

### 24.2 Kernel ↔ userspace ring ordering

The only cross-context memory is the SQ tail (we write, kernel reads) and CQ head (we write, kernel reads) plus the kernel-owned SQ head / CQ tail. liburing interposes the barriers: SQ-tail publish = `smp_store_release`, SQ-head room-check = `smp_load_acquire`, CQ-tail read = `smp_load_acquire`, CQ-head retire = `smp_store_release`. Submit and reap both run on the event thread, so each ring is touched from one userspace context; we never fill an SQE the kernel is reading nor read a CQE the kernel is writing. No extra lock is layered on top.

### 24.3 SHM kill-switch ordering (cross-worker)

A single `ngx_atomic_t io_uring_disabled`. Writers: admin handler (any worker) + panic timer, via atomic store. Reader: every worker's submit path, a plain relaxed load. No acquire fence / lock because: (1) single word, naturally aligned — no torn read; (2) advisory, idempotent — the flag gates *new* submissions only, so a one-op-stale read is harmless (the next submit re-reads); (3) precedent — the dashboard `transfer_table` uses the identical relaxed-read/atomic-write split (`transfer_table.c:155` read, `:322` write). Propagation: admin/SHM path effectively immediate; panic-file path ≤ the timer interval.

### 24.4 UAF formal argument

**Guard A — slot generation.** *Invariant:* the reaper derefs `slot->task` only if `slot->in_use && slot->generation == (ud>>32)`. *Proof:* `generation` bumps on every free; a CQE's `ud` captures the gen at submit. If task T (slot i, gen g) is abandoned, slot i freed (gen→g+1) and reacquired by T′, a late CQE for T carries g; at reap `slots[i].generation==g+1≠g` → dropped. T′'s memory is never confused for T's. All acquire/release/validate on the event thread → monotone gen, no race. ∎

**Guard B — `ctx->destroyed`.** *Invariant:* a done-callback acts on the stream only if `restore_stream` returns nonzero (`ctx->destroyed==0`). *Proof:* a dropped connection sets `destroyed=1` but does not free the in-flight task/slot (Guard A owns it); the CQE later posts the done-event, whose first act is `restore_stream` → 0 → touches nothing. Guards A and B are orthogonal: A catches recycled slots, B catches dead connections. ∎

**Rule C — disarm-before-handoff.** Before an object goes to the kernel (SQE) or another thread, its event/interest is disarmed so no second path frees/re-enters it (server: conn parked in `XRD_ST_AIO`, reaper re-posts via the queue; client: `engine.cancel` sets `poll_armed=0` and bumps `fd_gen` before the fd is replaced). No concurrent second owner → single-path free.

**Rule D — detached-payload freed post-CQE.** The write buffer is the SQE source; it is freed only in the done-callback, which runs after the CQE. Free strictly succeeds the CQE in program order on the event thread → kernel never reads freed memory. ∎

### 24.5 Client concurrency

| Domain | Owner thread | Sharing | Guard |
|---|---|---|---|
| `xrdc_disk_ring` | copy thread (one ring/transfer) | none | single-threaded by construction |
| engine ring / `xrdc_aconn` | loop thread | none on hot path | single loop thread; `fd_gen` for stale CQE |
| command queue (`CMD_*`) | producers: FUSE/reconnect; consumer: loop | the queue + `evfd` | queue lock; eventfd wake; consumed on loop thread only |
| `xrdc_mfile` pread/pwrite | FUSE workers (serialized) | per-mfile state | `xrdc_mfile` lock |

The disk ring is unshared (one per transfer, driven by one thread; out-of-order kernel completions serialized by the single-threaded retire loop). FUSE workers and the reconnect worker never touch the ring/`xrdc_aconn` directly — they enqueue a command and `write(evfd)`; the loop thread drains and executes (effectively single-threaded despite the multithreaded FUSE front). `fd_gen` is the engine's generation guard, structurally identical to the server slot generation. TLS keeps `SSL_*` on the loop thread — OpenSSL state never touched off-thread.

### 24.6 Consolidated locking & ownership

| Object | Side | Owner | Concurrent access | Synchronization |
|---|---|---|---|---|
| `xrootd_uring_t` (ring, slots, inflight) | server | worker ET | kernel (ring/CQ) | liburing barriers; else lock-free single-thread |
| `slots[i].generation` | server | ET | none | monotone counter (guard A) |
| `*_aio_t` OUT | server | reaper→done-cb (same thread) | none | program order via posted queue |
| detached payload | server | submit→done-cb | kernel in-flight | freed post-CQE (rule D) |
| SHM `io_uring_disabled` | server | admin/panic | all workers (relaxed read) | single-word atomic (§24.3) |
| `ctx->destroyed` | server | close/done-cb | none | program order (guard B) |
| `xrdc_disk_ring` | client | copy thread | kernel (CQ) | liburing barriers; else unshared |
| engine ring/`xrdc_aconn` | client | loop thread | kernel (CQ) | single loop thread; `fd_gen` |
| command queue + `evfd` | client | producers→loop | cross-thread | queue lock + eventfd |
| `xrdc_mfile` I/O | client | FUSE workers | serialized | per-mfile lock |

Every row with concurrent access has an explicit mechanism (liburing barrier, single-word atomic, generation counter, or an explicit lock); every row without is single-thread by construction. There is no per-state mutex on the hot path on either side.

---

## 25. liburing API usage reference

Authoritative inventory of every `liburing` symbol the backend touches. "Server" = the per-worker disk ring (`src/aio/uring.c`); "Client-disk" = the `copy.c` registered-buffer ring; "Client-engine" = the optional epoll-replacement ring (`aio.c`). The cardinal fact: **liburing never sets `errno` for a completed op** — the result (bytes, or `-errno`) is in `cqe->res` as a signed 32-bit value. `errno` matters only to the setup/register family.

### 25.1 Master function table

| Function | What it does | Returns / error | Min kernel | Where used |
|---|---|---|---|---|
| `io_uring_queue_init[_params]` | allocate+mmap SQ/CQ rings | `0` / `-errno` (`-ENOMEM`,`-EPERM` seccomp,`-ENOSYS`) | 5.1 | all init |
| `io_uring_queue_exit` | munmap + close ring fd (unregisters implicitly) | void | 5.1 | all teardown |
| `io_uring_get_probe` / `io_uring_opcode_supported` | enumerate supported opcodes | ptr/NULL ; 1/0 | 5.6 | both probes |
| `io_uring_get_sqe` | next free SQE | ptr or **NULL when SQ full** | 5.1 | all submit |
| `io_uring_prep_read/write` | `IORING_OP_READ/WRITE` (p{read,write}-equiv) | void | 5.6 | server READ/WRITE |
| `io_uring_prep_readv/writev` | `IORING_OP_READV/WRITEV` | void | 5.1 | server READV/WRITEV |
| `io_uring_prep_read_fixed/write_fixed` | `*_FIXED` into a registered buffer | void | 5.1 | client-disk |
| `io_uring_prep_fsync` | `IORING_OP_FSYNC` (DATASYNC flag → fdatasync) | void | 5.1 | server writev tail, FSYNC |
| `io_uring_prep_poll_multishot` | multishot `POLL_ADD`; one SQE→many CQEs | void | 5.13 (single-shot 5.1) | client-engine |
| `io_uring_prep_recv_multishot` / `prep_send` | `RECV` multishot / `SEND` | void | ~6.0 / 5.6 | client-engine (cleartext) |
| `io_uring_prep_cancel[64]` | `ASYNC_CANCEL` by user_data | void | 5.5 | client-engine |
| `io_uring_prep_nop` | `IORING_OP_NOP` (self-test) | void | 5.1 | init self-test |
| `io_uring_sqe_set_data64` / `cqe_get_data64` | stash/read the 64-bit cookie | void / `__u64` | 5.1 | all |
| `io_uring_submit[_and_wait]` | submit queued SQEs | **count** or `-errno` (`-EAGAIN`,`-EBUSY`) | 5.1 | all submit |
| `io_uring_peek_cqe` / `wait_cqe[_timeout]` | non-blocking / blocking CQE | `0`/`-EAGAIN` ; `0`/`-ETIME`/`-errno` | 5.1 / 5.4 | reaper / drain |
| `io_uring_for_each_cqe` / `cqe_seen` / `cq_advance` | iterate / retire CQEs | macro / void | 5.1 | reaper |
| `io_uring_register_eventfd[_async]` / `unregister_eventfd` | signal an eventfd per CQE | `0`/`-errno` | 5.2 (reliable ~5.6) | server init |
| `io_uring_register_buffers` / `register_files` (+unregister) | pin buffers / fd table for `*_FIXED`/`FIXED_FILE` | `0`/`-errno` | 5.1 | client-disk |
| `io_uring_register_restrictions` / `enable_rings` | lock ring to a whitelist (only pre-enable) ; lift `R_DISABLED` | `0`/`-errno` (`-EBUSY` if enabled) | 5.10 | server init |
| `io_uring_register_buf_ring` / `buf_ring_add` / `buf_ring_advance` | provided-buffer ring (kernel picks recv buf) | ptr/`-errno` ; void | 5.19 | client-engine |
| `io_uring_register_personality` | snapshot creds as a personality id | id/`-errno` | 5.6 | server (deferred) |

`prep_*` are pure SQE fillers (cannot fail); all error surfacing is deferred to `submit` (queue-level) and `cqe->res` (op-level). The 64-bit `*_data64` variants are chosen project-wide because the server packs `(generation<<32)|slot` and the client packs `(fd_gen<<32)|slot`.

### 25.2 SQE flags

| Flag | Effect | Use | Pitfall |
|---|---|---|---|
| `IOSQE_IO_LINK` | next SQE runs only after this succeeds; failure short-circuits the chain (`-ECANCELED`) | server WRITEV→FSYNC | a **short** write is `res>=0`, so the link does NOT break — short-write detection is in the reaper |
| `IOSQE_FIXED_FILE` | the SQE "fd" is a registered-table index | client-disk | index 0 ≠ fd 0; set without `register_files` → `-EBADF` |
| `IOSQE_BUFFER_SELECT` | kernel picks a provided buffer (`buf_group`) | client-engine RECV | no buffer → `-ENOBUFS`; the chosen `bid` must be recycled |
| `IOSQE_ASYNC` | force onto an io-wq worker | **unused** (defeats FAST_POLL) | — |
| `IOSQE_IO_DRAIN` | full pipeline barrier | **unused** (too coarse; serializes the ring) | — |

### 25.3 CQE flags

| Flag | Meaning | Handling |
|---|---|---|
| `IORING_CQE_F_MORE` | the multishot will produce more CQEs | engine: if **clear**, the multishot finished — **re-submit** it (the single most important engine invariant; failure silently wedges the connection) |
| `IORING_CQE_F_BUFFER` | a provided buffer was consumed; id = `flags >> IORING_CQE_BUFFER_SHIFT` | engine RECV: feed the bytes to the decoder, recycle the buffer into the ring |

The server disk ring uses no multishot and no provided buffers, so its reaper never inspects `cqe->flags` — `res` alone is authoritative.

### 25.4 Setup flags

`IORING_SETUP_R_DISABLED` — **used** (server): come up disabled so restrictions register before any submit (order: `init_params(R_DISABLED)` → `register_restrictions` → `register_eventfd/files` → `enable_rings`). `IORING_SETUP_SQPOLL`/`_SQ_AFF` — **deferred** (kernel poller CPU cost). `IORING_SETUP_CQSIZE` — **used (client-disk)**: CQ = 2×SQ so disk⇄net overlap can't overflow the CQ.

### 25.5 Gotchas

- `cqe->res` is `-errno`, never the global `errno`.
- **Short reads are normal** (EOF); **short writes are errors** (the existing `kXR_IOError("short write")` branch).
- `get_sqe` returns NULL on a full SQ — never deref; `submit`+retry once, then fall back.
- `submit` returns a **count** (possibly partial on `-EAGAIN`/`-EBUSY`) — reconcile un-submitted SQEs.
- `peek` is `-EAGAIN`-on-empty (reaper, non-blocking); `wait[_timeout]` blocks (client thread only).
- The eventfd counter **must** be drained first or epoll spins.
- `register_*` needs the ring quiesced; **restrictions are immutable after `enable_rings`** (`-EBUSY`).
- multishot poll/recv can be **dropped** (`F_MORE` clear) without an error → re-arm; provided buffers run dry → `-ENOBUFS` (flow control, not fatal).
- fixed-file index ≠ raw fd; `struct io_uring` ABI varies across liburing versions — never SHM-serialize or hand-roll it.

### 25.6 Version assumptions & degradation

Build floor **liburing ≥ 2.2** (`pkg-config --atleast-version=2.2`); below it the backend compiles out. Kernel floor **5.10 server** (restrictions are non-negotiable). Degradation, decided once at init via probe + `params.features`: liburing absent → backend compiled out; `queue_init` `-ENOSYS/-EPERM` → pool/epoll; restrictions/eventfd missing (<5.6/5.10) → server ring refused → pool; multishot recv/buf-ring missing (<5.19) → engine stays single-shot or epoll; `GETDENTS` → always assumed unsupported (dirlist never on the ring). Every degrade is silent (one debug line) with a working fallback; no gap is ever fatal.

---

## 26. Error & status mapping reference

io_uring changes **where** an error is observed (`cqe->res` vs syscall+`errno`) but **not what** it means. Every failure routes into a pre-existing emit site: server `xrootd_kxr_from_errno()` → `kXR_*` → `xrootd_http_errno_to_status()`; client `xrdc_status_set()`. No new mapping function is introduced — that is what preserves the parity matrix.

### 26.1 `cqe->res` → task OUT field → kXR → HTTP

| Op | `cqe->res` | OUT field | kXR | HTTP |
|---|---|---|---|---|
| READ | `==len` | `nread=res` | `kXR_ok` | 200/206 |
| READ | `0≤res<len` (EOF) | `nread=res` | `kXR_ok` (short=EOF) | 200/206 |
| READ | `-EIO`/`-EBADF`/`-ECANCELED` | `nread=-1`,`io_errno=-res` | `kXR_IOError` | 500 |
| WRITE | `==len` | `nwritten=res` | `kXR_ok` | 200/201 |
| WRITE | `0≤res<len` (short=error) | short-write branch | `kXR_IOError` ("short write") | 500 |
| WRITE | `-ENOSPC` | `io_errno=ENOSPC` | `kXR_NoSpace` | 507 |
| WRITE | `-EACCES`/`-EPERM` | `io_errno` | `kXR_NotAuthorized` | 403 |
| WRITE | `-EINVAL` | `io_errno=EINVAL` | `kXR_ArgInvalid` | 400 |
| READV | full / short-EOF | `bytes_read_total`, `io_error=0` | `kXR_ok` | 200/206 |
| READV | `-EIO` / `-EINVAL` | `io_error=1` | `kXR_IOError` / `kXR_ArgInvalid` | 500/400 |
| WRITEV | full | `bytes_total`, `io_error=0` | `kXR_ok` | 200/201 |
| WRITEV | short / `-ENOSPC` / `-EIO` | `io_error=2`/`1` | `kXR_IOError`/`kXR_NoSpace` | 500/507 |
| FSYNC | `0` / `-EIO` / `-ENOSPC` | `io_errno` | `kXR_ok`/`kXR_IOError`/`kXR_NoSpace` | 200/500/507 |
| any | `-ECANCELED` (chain abort) | error field, `io_errno=ECANCELED` | `kXR_IOError` | 500 |
| any | `-EAGAIN` (RWF_NOWAIT/`-ENOBUFS`) | **not surfaced** — re-driven on the blocking tier | (retried) | (retried) |

`-EINTR` does not occur for io_uring data ops. `-EAGAIN` only appears where we deliberately issued an `RWF_NOWAIT`/provided-buffer op — re-issued, never a client-visible error (exactly as the phase-32 warm-cache probe already behaves).

### 26.2 errno → kXR → HTTP base table (unchanged)

| errno (from `-cqe->res`) | kXR | HTTP |
|---|---|---|
| ENOENT / ENOTDIR | kXR_NotFound / kXR_NotFile | 404 |
| EACCES, EPERM, EXDEV, ELOOP | kXR_NotAuthorized | 403 |
| EINVAL | kXR_ArgInvalid | 400 |
| EIO | kXR_IOError | 500 |
| ENOMEM | kXR_NoMemory | 500/507 |
| ENOSPC, EDQUOT | kXR_NoSpace | 507 |
| EEXIST, ENOTEMPTY | kXR_FSError | 409 |
| ENAMETOOLONG | kXR_ArgTooLong | 414 |
| EBADF, ECANCELED, other | kXR_IOError (default) | 500 |

io_uring does not change this table — only the *observation site* (`xrootd_kxr_from_errno(-cqe->res)` in the reaper vs `(errno)` after a `pread`). Input domain (POSIX errno) and output domain (kXR/HTTP) are identical.

### 26.3 Client mapping

| io_uring outcome | client status call | result |
|---|---|---|
| disk `*_FIXED` `res<0` | `xrdc_status_set(XRDC_ESOCK, -res, …)` | `sys_errno=-res`; exit 51 |
| disk short write | `xrdc_status_set(XRDC_ESOCK, EIO, "short write")` (= `write_all` partial today) | 51/-EIO |
| engine `RECV/SEND/POLL` `res<0` | `xrdc_status_set(XRDC_ESOCK, -res, …)` (= `aconn_do_read/write`) | reconnect if retryable, else 51 |
| engine frame desync | `xrdc_status_set(XRDC_EPROTO, …)` (= `ops_file.c` truncated-frame) | 52/-EPROTO |
| engine `-ECANCELED`/timeout | `xrdc_status_set(XRDC_ESOCK, ETIMEDOUT, …)` (= `sock.c` poll-timeout) | 51/-ETIMEDOUT |

Transport/local failures take `XRDC_ESOCK` (carrying `-res`); framing failures after a byte-complete recv take `XRDC_EPROTO` — byte-identical to the synchronous adapters. Server `kXR_*` errors still arrive only inside reply frames decoded by `ops_file.c`, never from `cqe->res`.

### 26.4 No-new-error-paths assertion

Every io_uring failure reuses a pre-existing emit site, so the conformance parity matrix stays byte-identical:

| io_uring failure | reused emit site |
|---|---|
| server READ/PGREAD `res<0` | unchanged `*_aio_done` + `xrootd_kxr_from_errno` |
| server WRITE/WRITEV short/err | existing `io_error`/`io_errno` branches → `kXR_IOError("short write")` (`write.c`/`sync.c`) |
| server → HTTP | `xrootd_http_errno_to_status` in the same WebDAV/S3 handlers |
| client disk `res<0` | `xrdc_status_set(XRDC_ESOCK)` (= `copy.c` `read`/`write_all`) |
| client engine transport | `xrdc_status_set(XRDC_ESOCK)` (= `aconn_do_*`/`sock.c`) |
| client frame desync | `xrdc_status_set(XRDC_EPROTO)` (= `ops_file.c`) |

The reaper's only added logic is `res<0 → io_errno=-res` (replacing "`syscall==-1` → `io_errno=errno`"); that normalized errno feeds the identical mapper. For every io_uring errno, the mapper produces the same output as the thread-pool path — the parity matrix is preserved by construction.

---

## 27. Capacity, performance & sizing model

Models to size `queue_depth` (server) and `nbuf`/`bufsz` (client), predict memory, and decide whether io_uring helps. **Every number is an estimate** from the design facts, not production data; WSL2 is untrustworthy for throughput (§17.8) — these tell you *what to measure on real hardware* and *which knob to turn*. `[model]` = derived; `[fact]` = traceable to code.

### 27.1 Queue-depth sizing

The server ring is **connection-concurrency-bound**, not throughput-bound (~1 SQE per logical read; ≤4 for a 64 MiB request `[fact]`). Let `C` = connections concurrently in an AIO op per worker, `S` = SQEs/op, `T_svc` = device service time, `T_cyc` = interval between op dispatches on one connection.

```
[model]  E[inflight] = C × S × (T_svc / T_cyc)              # duty cycle = T_svc/T_cyc
[model]  queue_depth = next_pow2( ceil(E[inflight] × H) ),  H = 1.5–2.0, clamp [64,4096]
```
`T_svc/T_cyc` is the per-connection duty on the ring; a high-RTT client holds no SQE during the RTT gap, so it needs far less depth than its connection count suggests.

| Node | C | S | duty | E[inflight] | ×H=2 | Depth |
|---|---|---|---|---|---|---|
| Edge (few clients, high RTT) | 16 | 1 | 0.10 | 1.6 | 4 | **64** (floor) |
| Mid (read/write mix) | 200 | 1.2 | 0.35 | 84 | 256 | **256** (default) |
| Storage (many local readers) | 800 | 1.3 | 0.55 | 572 | 2048 | **1024–2048** |

**Raise** when `fallback{ringfull}` > ~1% of `ops_total` AND p99 `inflight==depth`. **Cost asymmetry:** under-provisioning is *safe and self-correcting* (clean cascade to the pool — never a drop); over-provisioning wastes only tens-to-hundreds of KiB. So the default 256 is sized for the mid node and operators raise only on metric evidence.

### 27.2 Memory footprint

```
[model] M_slots   = queue_depth × 24 B           [fact §9.2]
[model] M_ring    ≈ (SQ×64 B)+(CQ×16 B), page-rounded, CQ=2×SQ   → tens of KiB
[model] M_worker  = M_ring + M_slots + freelist  (sub-MiB even at depth 1024)
[model] M_client  = nbuf × bufsz   (registered, pinned; bufsz=XRDC_COPY_CHUNK=8 MiB)
```

| depth | M_slots | M_worker (est.) | | nbuf | bufsz | M_client |
|---|---|---|---|---|---|---|
| 64 | 1.5 KiB | ~22–26 KiB | | 2 | 8 MiB | 16 MiB |
| 256 | 6 KiB | ~47–63 KiB | | 4 | 8 MiB | 32 MiB |
| 512 | 12 KiB | ~86–110 KiB | | 8 | 8 MiB | 64 MiB |
| 1024 | 24 KiB | ~168–208 KiB | | 8 | 16 MiB | 128 MiB |

Server side does **not** touch the phase-31 budget (reads into the *same* scratch buffers; no registered buffers server-side first cut). The client ring trades 1 chunk → `nbuf` chunks by design (bounded, backpressured by `free_top==0`); if it becomes the default copy path, charge `nbuf×bufsz` to the per-transfer footprint.

### 27.3 Syscall reduction

```
[model] pool/op  ≈ post/wake(1) + blocking pread/pwrite(1) + completion notify(1) ≈ 3  (no batching)
[model] uring/batch_of_N ≈ 1 submit + 1 eventfd read   →   uring/op ≈ 2/N  (amortized)
[model] reduction ≈ 3 / (2/N) = 1.5 × N
```

| N (ops/tick) | pool (~3N) | uring (~2) | ratio |
|---|---|---|---|
| 1 | 3 | 2 | 1.5× (marginal) |
| 8 | 24 | 2 | 12× |
| 64 | 192 | 2 | 96× |
| 256 | 768 | 2 | 384× |

Batching helps only when N>1 (high concurrency). `submit_total/ops_total → 1.0` is the metric that says "no batching benefit". Client multishot poll/recv additionally removes the per-edge re-arm syscall (ii-a) and the readiness round-trip entirely on cleartext (ii-b).

### 27.4 Throughput/latency (qualitative, bounded)

| Regime | io_uring | Why |
|---|---|---|
| Syscall-bound, high-concurrency | **Wins** | batched submit collapses the per-op syscall tax (up to ~N×) |
| Disk⇄network overlap (client copy) | **Wins** | `nbuf` buffers run pread/pwrite ahead of/behind the network |
| High-RTT transport (ii-b) | **Wins (modestly)** | multishot recv removes readiness round-trips |
| Single large saturated stream | **~Neutral** | N≈1; the device, not syscalls, is the limit |
| Tiny cached reads (RWF_NOWAIT path) | **Can lose** | the probe answers inline with zero dispatch; an SQE adds a cycle — the probe is *retained ahead of the ring* precisely for this |

**There is no guaranteed win.** Because of the warm-cache case, the backend is off-by-default and the probe runs ahead of it. Any "X% faster" claim must be measured per workload on real hardware (WSL2 is untrustworthy — §17.8); the most portable local signal is the syscalls/op delta from `strace -c`.

### 27.5 Capacity-planning worksheet

1. **Duty** = `T_svc / (T_svc + RTT + gap)`. 2. **E** = `C × S × duty`. 3. **Depth** = `clamp(next_pow2(E×2),64,4096)`; if unsure, start at 256 (under-provisioning is safe). 4. **Memory** = look up `M_worker × W` (negligible). 5. **Fallback**: if `E×2 ≤ depth`, expect `ringfull ≈ 0`. 6. **Device sanity**: if `dev_bw` is already saturated at low inflight → expect neutral throughput (enable for the syscall saving / client overlap, not bandwidth). 7. **Enable `auto`**, watch one busy cycle (`active==1`, `ringfull≈0`, `cqe_errors↔op_err`), only then consider `on`. 8. **Client**: `nbuf ≈ ceil(BDP/bufsz)+1`; confirm `nbuf×bufsz` fits the per-transfer memory you allow.

### 27.6 SQPOLL / registered-files cost-benefit (deferred)

**SQPOLL**: `benefit` submit-syscalls→~0; `cost` ~1 kernel CPU core busy-polled per ring. Pays off only when submit *itself* is the bottleneck — for the ~1-SQE-per-response server it's already cheap and batched, so a poller core is net-negative. Off by default. **Registered files**: `benefit` per-op fd-lookup saving; `cost` the server's broker-opened per-request fds churn constantly, so registration overhead dominates. The client disk ring already uses registered **buffers** (real O_DIRECT win) but not registered files. Both stay deferred until a profile justifies them.

---

## 28. Failure-injection matrix

Every fault the backend must survive, how it is forced, the required behaviour, and where verified. Governing invariant (§28.3): **no fault may crash, drop/duplicate an op, or corrupt** — every fault either (a) falls back cleanly with a metric+log, or (b) surfaces as the *same* error frame the synchronous path would.

### 28.1 Master injection table

| ID | Fault | How injected | Expected | Verified |
|---|---|---|---|---|
| F-01 | `queue_init` `-ENOSYS` (<5.6) | seccomp / `MIN_KERNEL` raised | probe false → no ring; NOTICE; `auto` degrades, `on` fails config | `srv_fallback_oldkernel/on_hard` |
| F-02 | `queue_init` `-EPERM` (seccomp) | container default profile | probe false; clean fallback | `srv_fallback_seccomp` |
| F-03 | `register_eventfd` fails | LD_PRELOAD shim | `*_create_fail` unwind (no goto); fallback to pool; NOTICE | new `tests/c/` |
| F-04 | `register_restrictions` fails / <5.10 | host 5.6–5.9 or shim | restriction skipped; containment via unprivileged worker + confined fd | `sec_impersonated_read_confined` |
| F-05 | `get_sqe` NULL (ring full) | low `queue_depth=8` under load | slot released, `*posted=0` → pool→inline; byte-exact; `fallback{ringfull}`↑ | `srv_ringfull_noloss` |
| F-06 | slot table exhausted | same low-depth load | clean cascade; no drop/dup/corruption | `srv_ringfull_noloss` |
| F-07 | `submit` partial / `-EAGAIN` | shim | slot released (no leak), `*posted=0`; `inflight` not bumped | new fault-unit |
| F-08 | CQE `-EIO` | dm-flakey / shim | `io_errno=EIO`, `nread/nwritten=-1` → existing `kXR_IOError` — same frame as failed pread | op-error parity |
| F-09 | CQE `-ENOSPC` (write) | full/quota FS | `kXR_IOError` "No space" — identical to sync `pwrite` | write parity |
| F-10/11 | CQE `-EBADF`/`-EACCES` | shim / RO fd | `kXR_IOError`; divergence trips `IoUringCqeErrorDivergence` | CQE-error parity |
| F-12 | short read at EOF | truncated region | normal EOF path: `nread`=smaller, `kXR_ok`; not an error | `srv_op_error` |
| F-13 | short write | constrained FS | partial-write handled as a short pwrite (existing logic) | write parity |
| F-14 | stale CQE after slot recycle | unit forces old-gen `user_data` | `validate_and_take` mismatch → dropped; `stale_cqe_total`↑; integrity preserved | `srv_stale_cqe_generation` |
| F-15 | drop with N in-flight | disconnect mid windowed read | `ctx->destroyed`+gen guard; no UAF/leak/crash (ASan/LSan) | `srv_uaf_disconnect_midread` |
| F-16 | exit/reload with in-flight | `nginx -s reload` | reaper drains before exit; no silent drop; rings re-created per config | reload test |
| F-17 | kill-switch flip mid-batch | `POST {"enabled":false}` under load | new ops → pool next op; in-flight drain (`inflight→0`); zero loss; `kill_switch→1` | `kill_flip_under_load` |
| F-18 | panic-file appears/disappears | drop/remove the file | watcher sets SHM flag fleet-wide; survives reload; removal re-enables | `kill_panic_file` |
| F-19 | admin auth fail | no/bad/off-CIDR token | `AUTH_DENIED`; constant-time `CRYPTO_memcmp` (no oracle); flag unchanged; audited | `kill_authz_*` |
| F-20 | SHM re-attach on reload | reload | flag preserved (SHM survives re-fork); a pre-reload kill stays in effect | reload+kill |
| F-21 | disk ENOSPC mid-write | FS fills | CQE `-ENOSPC` → `xrdc_status`; buffers returned; ring drains before destroy | `cli_regbuf_lifecycle` |
| F-22 | O_DIRECT misalignment | unaligned tail / align mismatch | tail buffered, or O_DIRECT dropped for the transfer — never a failed copy | O_DIRECT corpus |
| F-23 | registered-buffer exhaustion | small `nbuf`, slow sink | `free_top==0` → pump waits; memory bounded; no over-commit | `cli_regbuf_lifecycle` |
| F-24 | transport drop mid-disk-ring | `fault_proxy.c` drop | disk ring drains; `ASYNC_CANCEL`/`fd_gen` recover; final bytes==source | fault_proxy + resilience |
| F-25 | ASYNC_CANCEL race | drop races a queued CQE | late CQE has old `fd_gen` → dropped; cancel+bump on loop thread, no lock | `aio_resil.c` |
| F-26 | provided-buffer `-ENOBUFS` (ii-b) | small RX pool, fast ingress | re-add buffers + re-arm; no data lost; falls back to readiness if persistent | new ii-b unit |
| F-27 | reconnect during in-flight POLL_ADD | drop+auto-reconnect | old multishot cancelled, `fd_gen++`; fresh multishot on the new fd; parked retries re-issued | `test_client_robustness.py` |
| F-28 | `fd_gen` late CQE (recycled aconn) | recycle aconn slot | `gen` mismatch → CQE dropped | `aio_mfile.c` |
| F-29 | multishot `F_MORE` cleared | shim clears F_MORE | engine re-arms with current mask; no missed readiness | ii-a unit |
| F-30 | liburing absent at build | `HAVE_LIBURING= make` / env unset | stubs only; server `xrootd_io_uring on` → **fails `nginx -t`/startup (§32)**, client `--io-uring=on` → non-zero exit; `auto`/`off` work; no `-luring` | `srv_on_not_compiled_fails`, `cli_on_not_compiled_exit` |

### 28.2 Injection harness

Five mechanisms, all referencing real artifacts: **(1) LD_PRELOAD liburing/syscall shim** (env-driven `URING_FAIL_SUBMIT=EAGAIN`, `URING_CQE_RES=-EIO`, `URING_FAIL_REGEVENTFD=1`, …) for F-03/F-07/F-08–F-11/F-29; **(2) low `queue_depth`/`nbuf`** for F-05/F-06/F-23; **(3) `tests/c/fault_proxy.c`** drop/block/latency/chunk for F-24/F-25/F-27; **(4) seccomp profile** (Docker default, blocks `io_uring_setup`) for F-01/F-02 and a 5.6–5.9 host for F-04; **(5) a debug hook** to force `get_sqe`→NULL (F-05 without load) plus a real error device (`dm-flakey`/`dm-error`) or full/quota FS for F-08/F-09/F-21 (genuine CQE errors, the strongest parity test). Every buffer/slot-lifetime fault (F-14/F-15/F-21/F-23/F-25) runs under the **ASan/LSan build**, client registered-buffer cases additionally under **valgrind + `tests/lsan.supp`**.

### 28.3 The "no silent failure" invariant

| Fault class | Outcome | Signal | Crash/drop/corruption? |
|---|---|---|---|
| init/probe (F-01–04) | (a) | NOTICE; `active==0`; `fallback{kernel}` | No (ring never created) |
| submit/slot full (F-05–07) | (a) | `fallback{ringfull}`; slot released | No (`*posted=0` → pool) |
| device CQE error (F-08–11,21) | (b) | `cqe_errors`↔`op_err`; same `kXR_IOError`/status | No (identical to sync) |
| short I/O / EOF (F-12,13) | (b)/normal | `kXR_ok` / short-write branch | No |
| stale/late CQE (F-14,25,28) | (a) | `stale_cqe_total`; action skipped | No (generation guard) |
| teardown/reload (F-15,16,20) | (a) | drain; `ctx->destroyed`; no leak | No (drained, not dropped) |
| kill/panic (F-17,18) | (a) | `kill_switch`/`panic`→1; audit; in-flight drains | No |
| admin auth (F-19) | (a) | `AUTH_DENIED`; flag unchanged | No (constant-time) |
| buffer-pool/-ENOBUFS (F-23,26) | (a) | pump waits / re-add+re-arm | No (bounded, no data lost) |
| O_DIRECT misalign (F-22) | (a) | tail buffered / O_DIRECT dropped | No (never a failed copy) |
| transport drop/reconnect (F-24,27,29) | (a) | `ASYNC_CANCEL`+`fd_gen`; retries re-issued | No (final bytes==source) |
| build absent (F-30) | (a) | stubs; server `on`→fails startup (§32), client `on`→non-zero exit; no `-luring` | No |

The two correctness alerts (§16.5) are the runtime guardians: `IoUringCqeErrorDivergence` fires if a ring CQE error does not surface as a client-visible `op_err` (a (b) violation); `IoUringSilentFallback` fires if the ring is active but every op is silently falling back (an unnoticed (a) at scale).

---

## 29. PR-by-PR rollout plan & review checklists

§18 defines the workstreams + DAG; §17 the gates. This turns that into a concrete PR queue, the per-PR review gate, keystone-PR scrutiny, merge/rollback policy, and the staged production rollout. Invariant: **the tree builds (±liburing) and the full suite is green with the engine OFF after every PR** — this is what makes `git revert` of any single PR low-risk.

### 29.1 PR sequence

One PR per workstream, except SB-W2/CB-W2/CB-W4 which split into individually-green sub-PRs. Server (PR-01..13) and client (PR-20..30) tracks are independent and parallel.

| PR# | Title | WS | Files | Dep | Sz | Gate |
|---|---|---|---|---|---|---|
| PR-01 | Build gate + directives + tunables + no-op selector | SB-W1 | config, tunables.h, config.h, process.c, stream/module.c, resume.c, **C** uring.{h,c} | — | S | M1 |
| PR-02 | Ring probe + create/teardown | SB-W2a | uring.c, process.c | 01 | M | |
| PR-03 | Slot table + generation | SB-W2b | uring.{c,h}, **C** uring_slot_test.c | 02 | M | |
| PR-04 | **eventfd bridge + reaper + NOP self-test** | SB-W2c | uring.c, process.c, metrics.h, **C** uring_nop_test.c | 03 | L | **G1** (M2) |
| PR-05 | READ/WRITE submit + OUT translation | SB-W3 | **C** uring_submit.c, uring.c, resume.c, config, test_aio/write.py | 04 | M | parity (M3) |
| PR-06 | READV + WRITEV+FSYNC | SB-W4 | uring_submit.c, test_readv*.py | 05 | M | |
| PR-07 | Fallback + budget validation | SB-W5 | test_aio.py, **C** test_uring_fallback.py | 05 | M | **G2** (M4) |
| PR-08 | Kill switch: SHM flag + hot read | SB-W7a | shm_slots.c, resume.c, metrics.h | 04,05 | M | |
| PR-09 | Kill switch: admin + panic-file + audit | SB-W7b | api_admin.c, process.c, stream/module.c | 08 | M | |
| PR-10 | Containment: register_restrictions | SB-W8a | uring.c, stream/module.c, **C** uring_restrict.c | 04,05 | M | |
| PR-11 | Containment: fd-provenance + imp interop | SB-W8b | uring_submit.c, test_impersonate*.py | 10 | M | **G4** (M5) |
| PR-12 | Observability: silent-fallback rule | §16 | metrics.h, handler.c, test_metrics.py | 05,09 | S | |
| PR-13 | Server docs + deferred stubs | SB-W6 | aio/README.md, this doc | 06 | S | M6 |
| PR-20 | Client build/probe + flags | CB-W1 | client/Makefile, **C** uring.{h,c}, xrdc.h | — | S | M7 |
| PR-21 | Disk ring + registered buffers | CB-W2a | client/lib/uring.c | 20 | M | |
| PR-22 | copy.c adapters + ordered completion | CB-W2b | copy.c, xrdc.h | 21 | M | |
| PR-23 | O_DIRECT + byte-exact corpus | CB-W2c | copy.c, test_native_xrdcp*.py | 22 | M | **G3** (M8) |
| PR-24 | Disk ring → loop/FUSE-local | CB-W3 | aio.c, aio_mgr.c, test_xrootdfs.py | 23 | M | M9 |
| PR-25 | Engine vtable extraction (epoll, refactor) | CB-W4a | aio.{c,h} | 20,24,**G3** | M | |
| PR-26 | io_uring POLL_ADD engine + fd_gen | CB-W4b | aio.c, aio_mgr.c | 25 | L | |
| PR-27 | ASYNC_CANCEL + resilience gate | CB-W4c | aio.c, aio_resil.c, test_client_robustness.py | 26 | M | resilience (M10) |
| PR-28 | Cleartext RECV/SEND (deferred tier) | CB-W4d | aio.c | 27 | M | |
| PR-29 | FUSE verification | CB-W6 | test_xrootdfs_resilience.py | 23,27 | S | M11 |
| PR-30 | Client docs | CB-W6 | this doc | 29 | S | |

### 29.2 Per-PR review checklist (every PR)

- [ ] **Builds both ways** (with `XROOTD_ENABLE_IO_URING`+liburing, and without → stubs; client `make` + `HAVE_LIBURING= make`).
- [ ] **Suite green engine-off** (`XROOTD_IO_URING_MODE=off` / `--io-uring=off`) — the always-green invariant; blocks unconditionally.
- [ ] **No `goto`** (unwind via `*_create_fail()`); **WHAT/WHY/HOW** doc blocks.
- [ ] **`./configure` note** if a new `.c` entered `ngx_module_srcs`; **`-luring` in `ngx_module_libs`** never `CORE_LIBS`.
- [ ] **No struct-layout change without full rebuild** (SHM/slot structs declared up-front).
- [ ] **UAF guards present** (slot generation + `ctx->destroyed`, or `fd_gen`).
- [ ] **Parity matrix** for data-path PRs; **metrics low-cardinality** (no paths/UUIDs); **security-negative test** present (the 3rd test).

### 29.3 Keystone-PR extra checklists

**PR-04 (G1):** NOP self-test harvests through the full slot→gen-check→`ngx_post_event` path; ASan start→stop→reload leaks nothing; eventfd drain mirrors `ngx_epoll_eventfd_handler`; reaper never inline-dispatches; forced `register_eventfd` failure → clean pool fallback. **PR-09/10/11 (G4):** admin reuses `xrootd_admin_check_auth`+`admin_audit` verbatim, `CRYPTO_memcmp` bearer, audit per flip; `uring_restrict.c` proves a path opcode is rejected; submit asserts `task->fd == xrootd_vfs_file_fd(fh)`. **PR-21–23 (G3):** byte-exact SHA256 corpus off/on/on+O_DIRECT; LSan registered-buffer balance + drain-before-rename. **PR-25–28:** PR-25 refactor-only (green with epoll); resilience suite green with the engine ON; `fd_gen`+`ASYNC_CANCEL`; default off.

### 29.4 Merge & rollback policy

One squashed atomic commit per workstream; `git revert <WS-commit>` cleanly removes it and leaves the tree green (feature off-by-default, selector edit *extended* not rewritten). Tag `phase44-M1..M11` per milestone. Landing order follows the DAG: PR-04 (G1) blocks every server op PR; PR-23 (G3) blocks PR-25; PR-11 (G4) blocks enabling `restrict`/`admin` in prod. Server∥client. After PR-05, PR-06/07/{08→09}/{10→11} are independent *except* all touch the §10.7 selector — serialize that edit or rebase. A revert never changes default behavior (off) and cannot cross server↔client.

### 29.5 Staged production rollout

| Stage | Action | Soak / advance criterion |
|---|---|---|
| 0 Pre-flight | confirm `nginx -V \| grep io_uring`; probe passes | banner present, kernel ≥5.6 |
| 1 Canary (1 node) | `xrootd_io_uring auto`; reload | ≥24 h: `active==1`, `cqe_errors↔op_err`, no `IoUringSilentFallback`, parity green, `restrict_active==1` |
| 2 Rack | `auto` on one rack | ≥48 h: `inflight/depth` p95<0.7; no `ringfull` climb |
| 3 Fleet | `auto` on N% (5→25→50→100) | after each step: silent-fallback alert quiet + parity green for one soak window |

**Rollback (no restart):** admin `POST {"enabled":false}` (instant, in-flight drains, zero loss) or drop the panic-file (survives reload; use when the API is suspect). **Never** jump to `xrootd_io_uring on` in prod — `on` hard-fails where the probe fails and removes silent fallback; prod runs `auto`. The promotion gate is "silent-fallback alert quiet + parity green", not throughput.

---

## 30. CI/CD pipeline & gating definitions

Executable CI for §29. All referenced test files/artifacts exist; the seccomp-blocked cell runs in a container with the default Docker profile (blocks `io_uring_setup`).

### 30.1 Jobs

| Job | Trigger | Runs | Pass | Blocking |
|---|---|---|---|---|
| **ci-uring-off** (always-green) | every PR | full suite `MODE=off`, build with **and** without liburing; full `tests/c/*` | 100% green both variants; `nm` shows no `io_uring` in the stub build | **YES (unconditional)** |
| ci-uring-auto | every PR | full suite `MODE=auto` | green; if probe fails on CI kernel, one NOTICE + clean degrade | YES |
| **ci-parity** (central gate) | PR touching `src/aio/**` / `client/lib/uring*` / `copy.c` | parity matrix over read/write/readv/pgread/dirlist + `test_integrity_matrix.py`, `uring_mode∈{off,on,auto}` → `test_backend_parity_reconcile` | all three modes byte-identical responses + access-log byte counts | YES |
| ci-asan-uring | PR touching the backend | §17.6 UAF/memory under ASan/LSan, engine on; `uring_slot_test`, `uring_nop_test` | zero ASan/LSan reports (`tests/lsan.supp`); gen guard drops stale CQE; payload freed once post-CQE | YES (when backend files changed) |
| ci-resilience-uring | CB-W4 PRs; nightly after | `fault_proxy.c` + `test_client_robustness/xrootdfs_resilience/write_recovery` + `aio_resil/aio_mfile`, engine ON, + valgrind | every fault recovered; bytes==source; buffer lifecycle clean | YES before CB-W4 merges |
| ci-security | PR touching kill-switch/containment | `kill_*` (`test_phase23_admin_api/security_hardening.py`) + `uring_restrict.c` + `sec_iowq_unprivileged` | authz rejects+audit; restrictions bar path opcodes; panic-file disables fleet-wide+survives reload | YES (realizes G4) |
| nightly-uring-on | nightly | full suite `MODE=on` (hard-require) + low-depth spill + fallback matrix + restriction units | green on the ring; `srv_ringfull_noloss`; clean degrade | NO (nightly) |
| perf-uring | manual, **real host only** | §17.8 benches off/on/+O_DIRECT; `strace -c`/`perf stat` | syscalls/op delta in expected direction; no regression vs pool | NO (advisory; never WSL2) |

### 30.2 Branch protection

Required on every PR: **ci-uring-off** (no path filter — the invariant that makes reverts safe), **ci-uring-auto**. Path-scoped-required: **ci-parity**, **ci-asan-uring** (when `src/aio/**`/`client/lib/uring*`/`copy.c` change), **ci-security** (kill-switch/containment files — realizes G4), **ci-resilience-uring** (CB-W4 PRs). Gate mapping: G1 via NOP self-test in ci-asan-uring/ci-uring-auto on PR-04; G2 via nightly fallback matrix; G3 via ci-parity byte-exact on PR-23; G4 via ci-security on PR-09/11. Nightly/perf never block an unrelated in-flight PR.

### 30.3 Test-selection map (abbrev)

`test_aio.py`/`test_write.py` → off/auto/parity/asan/nightly. `test_readv*.py`, `test_pgread_wire_conformance.py`, `test_integrity_matrix.py`, `test_native_xrdcp_xrdfs.py`, `test_client_xrdcp_bulk.py` → parity. `test_client_robustness/xrootdfs_resilience/write_recovery.py` + `tests/c/{fault_proxy,aio_resil,aio_mfile}` → resilience. `test_phase23_admin_api/security_hardening/impersonate_idmap.py` + `tests/c/uring_restrict.c` → security. `test_metrics/large_file_metrics.py` → off/auto. `tests/c/{uring_nop,uring_slot}_test` → asan.

### 30.4 Build matrix (load-bearing cells)

| liburing | mode | build | kernel | Job | Why |
|---|---|---|---|---|---|
| absent | off | release | CI | ci-uring-off (stub) | no `-luring`, selector inert |
| present | off | release | CI | ci-uring-off | green with backend compiled-in, off |
| present | auto | release | CI | ci-uring-auto, ci-parity | production default |
| present | on | release | CI | nightly, ci-parity(on) | forces the ring |
| present | on | release | seccomp-blocked | nightly/auto degrade | `auto` degrades, `on` hard-fails (R-09) |
| present | on | ASan | CI | ci-asan-uring, resilience(valgrind) | UAF/leak surface |
| absent | on | release | CI | ci-uring-off negative | `on`/`xrootd_io_uring on` must error cleanly |

Not run: `{absent × auto/off × ASan}`, `{present × off × ASan}`, any WSL2 perf cell.

### 30.5 Artifacts

`parity-reconcile.json` (per-mode `(request,response_bytes,sha256)` — the parity gate fails on any divergence); ASan/LSan logs (non-empty after `lsan.supp` → fail); a silent-fallback recording-rule check (asserts `IoUringSilentFallback` **fires** under force-injected fallback and **stays quiet** otherwise — the headline-SLO detector is itself tested); benchmark CSVs (real host only, never a merge gate); a metric-cardinality lint (scrape `/metrics`, assert only `worker`/`op`/`reason` labels — enforces INVARIANT #8).

---

## 31. Architecture Decision Records (ADRs) & design FAQ

The load-bearing decisions from §§7–§19 as standalone, revisitable records, then the sharp questions a reviewer/operator asks. Each ADR: **Status · Decision · Key consequences · Alternatives (why rejected) · Revisit-if.** Citations point to the section that argues the case.

**ADR-01 — Server io_uring is disk-I/O only; network stays nginx-core.** *Accepted (§0,§7.1,N-01).* Decision: io_uring covers only the disk syscalls behind `xrootd_aio_post_task`; never a socket/sendfile/kTLS. +No core patching; TLS `b->memory=1`/sendfile invariants structurally untouchable. −Forfeits the network half server-side. Alt: network io_uring (rejected — forbidden core patch); core event module (ADR-10). Revisit: nginx exports an addon-reachable socket-I/O seam.

**ADR-02 — Re-derive the eventfd bridge, don't patch/reuse core's libaio.** *Accepted (§7.1,§11.1).* Core's `ngx_epoll_aio_init`/`ngx_epoll_eventfd_handler` are static/libaio-bound/addon-invisible. Decision: re-derive ~80 lines via public APIs (`io_uring_register_eventfd` + `ngx_get_connection`/`ngx_add_event`), reusing `ngx_post_event`/`ngx_posted_events`. +No core patch, per-worker, no new global. −80 shadow lines to track vs core. Alt: call core's (impossible — static); patch core (forbidden). Revisit: a core io_uring poller lands upstream.

**ADR-03 — Option A: reuse `ngx_thread_task_t` + done-callbacks; reaper posts to `ngx_posted_events`.** *Accepted (§9.6,§11.2).* Decision: keep the task structs/callbacks; reaper fills OUT fields and posts the event (never inline). +Byte-for-byte unchanged framing; re-entrancy-safe vs the window pump. −One extra epoll cycle vs inline. Alt: inline dispatch (rejected — re-entrancy); bespoke completion struct (rejected — forks the callbacks). Revisit: posted-events hop proves a measured bottleneck.

**ADR-04 — UAF-safe slot table with a generation guard, not raw pointers in `user_data`.** *Accepted (§9.2,§11.3,R-01/02).* Decision: `user_data=(gen<<32)|idx`, gen bumped on free; mismatch drops the stale CQE; `ctx->destroyed` is the second layer. +No pointer derefed from a CQE; UAF requires a 2³² wrap *and* a freed ctx in one op. −Small table + one comparison/CQE. Alt: raw pointer (UAF); bare index (stale-to-recycled). Revisit: op rates make a 2³² wrap plausible per connection.

**ADR-05 — Three-tier cascade (io_uring → pool → inline) behind one unchanged seam.** *Accepted (§10.7,N-03,D-08).* Decision: io_uring as the top tier; `xrootd_aio_post_task` keeps its signature; `op_for` keys on the bound worker-fn (zero call-site changes). +Op never dropped; single forward-compat switch point. −Ring-full degrades silently (visible via the fallback metric). Alt: replace the pool (rejected — it's the fallback); a parallel entry point (rejected — forks call sites). Revisit: a core io_uring poller adds a 4th tier.

**ADR-06 — pgread/dirlist/multi-fd vectored stay on the pool (first cut).** *Accepted; hybrid+GETDENTS deferred (§10.6,Q-03/07,R-07).* Decision: map only READ/WRITE/single-group READV/single-fd WRITEV(+linked FSYNC); the rest fall through to the pool. +CRC32c stays off the event loop; no bleeding-edge getdents dependency. −Paged reads/listings see no benefit yet. Alt: full-uring pgread (rejected — CRC on the loop); GETDENTS now (rejected — too new). Revisit: the uring-read→pool-CRC hybrid is built; GETDENTS gains a stable helper.

**ADR-07 — Retain the phase-32 `RWF_NOWAIT` warm-cache probe in front of the ring.** *Accepted (§11.6,R-15).* Decision: keep the probe above the seam; only the miss path falls to the ring. +Hot reads never pay an extra cycle; budget/footprint identical. −Two read fast paths the parity matrix must cover. Alt: probe-as-SQE (rejected — no faster, more complex); all-reads-to-ring (rejected — regresses hot reads). Revisit: registered files/buffers + SQPOLL drop the ring's per-op cost below the probe's.

**ADR-08 — Four-level kill switch with a no-restart SHM hot path + watched panic-file.** *Accepted (§8.1,§14.3,R-08/18/19).* Decision: build-off / config-off-reload / SHM-atomic-admin-API / panic-file; drain semantics (stop new submits, in-flight CQEs drain). +CVE neutralizable in seconds fleet-wide, no rebuild/restart, even before the API is up. −Panic-file latency = the timer interval (use the API for instant); admin endpoint is a new (fail-safe) surface. Alt: reload-only (too slow); auto-trip on error rate (deferred Q-11 — flapping); single switch (no defense if API/SHM down). Revisit: telemetry justifies an auto-trip; panic latency unacceptable → inotify.

**ADR-09 — Containment: unprivileged worker + broker-opened RESOLVE_BENEATH fds + `register_restrictions`; broker never uses io_uring.** *Accepted (§8.2,§14.4,R-10/22,D-04).* Decision: io_uring runs only in the unprivileged worker on confined fds; ring `R_DISABLED`→restrict to fd-only opcodes→enable; broker is open+metadata only. +A forged-SQE kernel bug can't open/traverse a path; READ/WRITE on an open fd does no further DAC check. −restrictions need 5.10 (below it, containment via points 1–2); non-impersonation needs a non-root service account. Alt: broker-owned ring + personalities (deferred ADR-13); restrictions alone (rejected — fails open <5.10). Revisit: per-tenant cred isolation required; kernel floor rises to 5.10+.

**ADR-10 — Reject a core nginx io_uring event module.** *Rejected (§7.5,N-02).* The "correct" `ngx_event_actions_t` poller compiles into the core binary and registers in core's module list — an addon can't add one without forking nginx, and it swaps the poller process-wide. Decision: use the addon-scoped eventfd bridge (ADR-02). Alt: the event module (prototyped by unmerged nginx-devel patches + CarterLi's fork; none merged; nginx#568 still backlog). Revisit: a core poller lands upstream → consume it via the seam (ADR-05).

**ADR-11 — Reject routing disk I/O through nginx `aio on;`.** *Rejected (§7.3,Q-05).* `aio on;` is read-only, O_DIRECT-only (bypasses page cache, blocks on unaligned tails), un-batched, and unreachable per-op from the module's state machine. Decision: io_uring (capability superset) + thread-pool fallback; keep `aio off;`. Revisit: nginx makes libaio writable+batchable+addon-reachable (implausible).

**ADR-12 — Client: ship the disk ring (Option A) before the `aio.c` engine swap; POLL_ADD before cleartext RECV/SEND; default off.** *Accepted (§12,§13,Q-01/12,R-12/13).* Decision: (1) CB-W2 disk ring (Option A, registered buffers, one memcpy); (2) CB-W4 engine swap default-off, only after CB-W2 green — POLL_ADD multishot first (TLS-safe), cleartext RECV/SEND follow-on; `fd_gen`+`ASYNC_CANCEL`. +Highest-value/lowest-risk lands first, isolated; POLL_ADD keeps TLS correct + full resilience. −Option A's memcpy survives; the engine swap is high-risk (off by default, gated). Alt: disk-only forever (Q-01 — no, it earns in default-off); Option B first (deferred Q-12); RECV/SEND first (rejected — breaks TLS); memory-BIO/kTLS (N-07). Revisit: the memcpy is a measured bottleneck → Option B.

**ADR-13 — Defer personalities, SQPOLL, registered server files/buffers, uring-pgread hybrid, GETDENTS.** *Deferred (§11.5,§32,Q-03/04/08,R-16).* Each behind its own flag with a designed tier. +First cut keeps the phase-31 budget identical, avoids idle CPU burn and credential/lifecycle complexity. −Headline perf features not in the first measured result (conservative by design). Alt: registered from day one (Q-02 — changes footprint accounting); SQPOLL on (Q-04 — idle CPU). Revisit: the base path is proven and a real-hardware benchmark clears each tier's cost (and the footprint rule is honored).

**ADR-14 — Off-by-default everywhere, pkg-config gate, authoritative runtime probe, silent fallback.** *Accepted (§3,§7.7,§15,R-09,D-01/02).* Decision: build gate `-DXROOTD_HAVE_LIBURING` (absent → inert stubs, no `-luring`); runtime *probe* (`io_uring_queue_init`+`get_probe`, never `uname`); directive default `auto`; **`on` makes xrootd fail to start when unavailable — built-without-liburing (config-time) or runtime-blocked (§32, ADR-16)**. +Degrades cleanly in exactly the seccomp-hardened WLCG environments; the shipped default cannot regress; `-luring` absent unless built in. −Perf forfeited where blocked (by design). Alt: on by default (fails closed under seccomp); `uname` gate (can't detect a seccomp block); hard liburing dep (breaks builds). Revisit: io_uring becomes universally unblocked.

**ADR-15 — The backend-parity matrix is the acceptance gate, not a throughput promise.** *Accepted (§6,§17,N-06,R-15).* Decision: the gate is byte-for-byte identical responses across off/on/auto (+ per-op success/error/security-neg); throughput is measured on real hardware, never a ship gate. +Ships proven-correct and frame-identical; off-by-default → no default regression. −A flat/negative A/B on a host is accepted (a stated non-goal); the matrix is expensive (three passes). Alt: a throughput target as the gate (rejected — unmeasurable on WSL2, would block a correct capability). Revisit: a standardized perf host + a chosen perf SLO atop parity.

### Design FAQ

**Does this change any wire bytes?** No (N-05). pgread `kXR_status(4007)`+CRC32c, TLS `b->memory=1`, sendfile, `resolve_path()`-before-`open()` untouched; done-callbacks/framing byte-for-byte unchanged (ADR-03); the parity matrix asserts off/on/auto identical.

**What happens on a kernel without io_uring (or seccomp-blocked)?** The probe fails, no ring is created, one NOTICE, permanent silent fallback to thread pool/epoll (ADR-14, R-09). `auto`/`off` proceed; **`on` makes xrootd refuse to start (`nginx -t` fails, master exits) — see §32**. This is the *expected* case in Docker/containerd/ChromeOS-style environments.

**Can a remote client reach a path via io_uring?** No. The ring is restricted to fd-only data opcodes; OPENAT/STATX/UNLINKAT/GETDENTS/*XATTR are excluded, so it can't open or traverse a path even under a forged-SQE bug (ADR-09). It only moves bytes on broker-opened RESOLVE_BENEATH fds; open/dirlist/metadata stay off the ring (ADR-06).

**Why not just turn on `aio threads`/`aio on;`?** The thread pool *is* the fallback tier (ADR-05). `aio on;` (libaio) is rejected as primary — read-only, O_DIRECT-only, un-batched, unreachable per-op (ADR-11). io_uring is the capability superset.

**How do I disable it during a CVE?** Four ways (ADR-08): drop the panic-file (unauthenticated, reload-free, survives reload — the "2 a.m." switch); `POST /xrootd/api/v1/admin/io_uring {"enabled":false}` (instant SHM flip); `xrootd_io_uring off`+reload; rebuild without liburing. In-flight CQEs drain — no op dropped.

**Does it run as root?** No. io_uring runs only in the unprivileged worker (zero FS caps) on broker-opened confined fds; io-wq inherits the worker's unprivileged creds (ADR-09). The root broker holds only `CAP_SETUID`/`CAP_SETGID`, does open+metadata only, never touches io_uring.

**What's the memory cost?** Server: the ring + slot table (bounded by `queue_depth`, sub-MiB/worker), reading into the *same* scratch buffers — phase-31 footprint identical (R-14). Client: `depth×bufsz` registered buffers per transfer. Registered server files/buffers (deferred) would add footprint and must be charged to the budget first.

**Will it actually be faster?** Not promised (ADR-15, N-06). The gate is parity. The win is on cache-miss/write/batched/overlap paths and is environment-dependent; the retained `RWF_NOWAIT` probe already serves hot reads inline. Off-by-default → no default regression. Measure on real hardware.

**Does TLS work?** Yes, unchanged. Server-side io_uring never touches a socket/kTLS (ADR-01). Client-side, TLS conns stay on POLL_ADD readiness and keep `SSL_read`/`SSL_write` (ADR-12, R-13); only cleartext may go true-async (deferred). Memory-BIO/kTLS interception is out of scope (N-07).

**What if liburing isn't installed?** The build is unaffected: the gate is optional; without it the whole `uring.{c,h}` TU is inert stubs and there's no `-luring` (ADR-14, D-01). The client mirrors the always-compiled krb5 stub.

**How is pgread CRC preserved?** pgread stays entirely on the thread pool in the first cut (ADR-06) — its CRC32c interleave and `kXR_status(4007)` framing are exactly today's path. The deferred uring-pgread tier is *hybrid* (uring read → pool CRC) so the encode never lands on the event thread.

**Does it break the phase-31 budget?** No. The window pump + budget admission sit above the seam; the first cut reads into the same scratch buffers, so footprint accounting is identical (R-14). Any deferred registered-buffers tier must charge its bytes first.

**How do I know it's actually engaged?** `io_uring_active{worker}` (1/0) shows a ring exists; `io_uring_ops` counts ring-served ops; `io_uring_fallback{reason}` shows degradation. If `active=1` but `ops` is flat while `fallback{ringfull}` climbs, you're silently on the pool (R-04, alert `IoUringSilentFallback`).

**What's the rollback?** Operationally any kill-switch level (no rebuild). Configurationally `xrootd_io_uring off`+reload. At source level, since no struct changes layout and all is behind `#if XROOTD_HAVE_LIBURING`, building without liburing leaves the thread-pool/epoll paths byte-for-byte as they were (toggling the build flag needs a full `./configure` + clean rebuild — R-05).

**Is this duplicating a shipped nginx feature?** No. nginx 1.28/freenginx ship no io_uring (zero hits in the pinned core tree); only unmerged nginx-devel patches, a fork, and backlog #568 (§7.5). This productionizes — off-by-default, addon-scoped — what upstream has only as prototypes, and declines the core event-module shape upstream never merged (ADR-10).

---

## 32. Startup validation & fail-fast: `xrootd_io_uring on` must be satisfiable

`auto` and `off` never prevent startup. **`on` is a hard requirement: if the operator sets `xrootd_io_uring on` but the backend cannot be provided, xrootd refuses to start** — `nginx -t` fails, the master exits non-zero, and an `NGX_LOG_EMERG` line names the exact cause and remedy. There are two unsatisfiable cases, both fatal under `on`:

1. **Built without the backend** (the mandated case): the binary was compiled with `XROOTD_HAVE_LIBURING` undefined (no `liburing-devel`, or `XROOTD_ENABLE_IO_URING` unset at `./configure`). Detectable purely at config time — no kernel probe.
2. **Built with the backend but unavailable at runtime**: the kernel is too old, or a seccomp policy blocks `io_uring_setup` (the Docker/containerd default posture). Detected by the authoritative probe.

Rationale: `on` means "this node MUST use io_uring." Silently degrading to the thread pool when the operator demanded io_uring hides a misconfiguration (a wrong RPM, an unset build flag, a kernel regression, a seccomp profile) behind a quiet performance loss — the precise "silent degradation" failure §16 is built to surface. Fail-fast converts that into a loud, immediate startup error caught by `nginx -t` in CI/staging and by the service manager in production, long before traffic is served.

### 32.1 Semantics matrix (the complete contract)

| `xrootd_io_uring` | Compiled in? | Runtime probe | Startup | Data path |
|---|---|---|---|---|
| `off` | either | — | **starts** | thread pool (ring never created) |
| `auto` | no | — | **starts** | thread pool (silent, one NOTICE) |
| `auto` | yes | pass | **starts** | io_uring |
| `auto` | yes | fail (kernel/seccomp) | **starts** | thread pool (silent, one NOTICE) |
| **`on`** | **no** | — | **FAILS — `nginx -t` error, master exits non-zero** | n/a |
| **`on`** | yes | fail (kernel/seccomp) | **FAILS — `nginx -t` error, master exits non-zero** | n/a |
| `on` | yes | pass | **starts** | io_uring (required, guaranteed) |

Only the two **`on`** rows fail. The distinction is deliberate: `auto` is the safe fleet-wide default (degrades anywhere); `on` is the strict opt-in for nodes where io_uring presence is guaranteed and a regression must be loud.

### 32.2 The mandated case — built without liburing (config-time, no probe)

When `XROOTD_HAVE_LIBURING` is undefined the whole backend is inert stubs (§20.1/§21.1) and `xrootd_uring_worker()` is a compile-time `NULL`. The directive **still parses** — `xrootd_io_uring` is registered in the unconditionally-compiled stream `commands[]`, and the mode enum `{off,on,auto}` is defined in `tunables.h` regardless of the build macro — so a config written for an io_uring build loads identically on a non-io_uring binary. What changes is *validation*: at `postconfiguration` a build-time-guarded check rejects any server block that demanded `on`.

This case needs **no kernel probe** — it is a pure compile-time fact (`#if !(XROOTD_HAVE_LIBURING)`) crossed with a config fact (some block set `on`). It is therefore caught by `nginx -t` on *any* host, including a CI box with no io_uring kernel at all — exactly where a packaging/build mistake should be caught.

### 32.3 The runtime extension — compiled in but kernel/seccomp blocks it

When the backend is compiled in but `xrootd_io_uring on` is set, the same `postconfiguration` hook runs the authoritative probe (`io_uring_queue_init(8)` + opcode `get_probe`, §15.5) in the **master** process. If it fails (`-ENOSYS` on an old kernel, `-EPERM` under seccomp), startup is refused with a message naming the probe error and the minimum kernel. This makes `on` mean "require io_uring *here, now*," not merely "require the code to exist." The probe is cheap (a throwaway ring torn down immediately) and its verdict is memoized for the workers (§15.5). See §32.7 for the rare master/worker seccomp-divergence caveat and its backstop.

### 32.4 The validation hook — full implementation

Hooked from the stream module's `postconfiguration` (beside `xrootd_configure_thread_pools()`), after `merge_srv_conf` so it reads resolved values:

```c
/* WHAT: enforce that "xrootd_io_uring on" is satisfiable, else fail config load.
 * WHY:  `on` is a hard requirement (§32); a node that silently degrades when the
 *       operator demanded io_uring hides a misconfig. `off`/`auto` never fail.
 * HOW:  scan the merged server confs; if ANY demanded `on`, reject when the
 *       backend is either not compiled in (build-time, no probe) or unavailable
 *       at runtime (probe). NGX_ERROR from postconfiguration aborts the load. */
static ngx_int_t
xrootd_uring_validate_conf(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *sscf;
    ngx_uint_t                     i, want_on = 0;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        sscf = cscfp[i]->ctx->srv_conf[ngx_stream_xrootd_module.ctx_index];
        if (sscf->io_uring == XROOTD_IO_URING_MODE_ON) { want_on = 1; break; }
    }
    if (!want_on) {
        return NGX_OK;            /* off/auto on every block: nothing to enforce */
    }

#if !(XROOTD_HAVE_LIBURING)
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"xrootd_io_uring on\" requires a build with liburing, but this binary "
        "was compiled WITHOUT it. Rebuild with XROOTD_ENABLE_IO_URING=1 and "
        "liburing-devel installed, or set \"xrootd_io_uring auto\" to allow "
        "silent fallback to the thread pool.");
    return NGX_ERROR;            /* -> nginx -t fails; master refuses to start */
#else
    if (!xrootd_uring_runtime_available()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"xrootd_io_uring on\" requested but io_uring is unavailable on this "
            "host (io_uring_setup probe failed). This is typically a seccomp "
            "policy (Docker/containerd default profiles block io_uring) or a "
            "kernel < %d.%d. Set \"xrootd_io_uring auto\" to fall back to the "
            "thread pool, or enable io_uring at the host/container level.",
            XROOTD_IO_URING_MIN_KERNEL_MAJOR, XROOTD_IO_URING_MIN_KERNEL_MINOR);
        return NGX_ERROR;
    }
    return NGX_OK;
#endif
}
```

Notes:
- **Iterate-after-merge.** `postconfiguration` runs after `merge_srv_conf`, so `sscf->io_uring` is the resolved value (`NGX_CONF_UNSET_UINT` → `OFF` default). An unset block does not demand `on`.
- **Single binary, fleet-wide truth.** A binary either has the backend or not — you cannot satisfy `on` for one server block and not another — so a single `want_on` short-circuits the scan.
- **Build-time branch is probe-free.** The `#if !(XROOTD_HAVE_LIBURING)` arm needs no kernel; it is the config-time guarantee the requirement mandates.
- **`NGX_ERROR` is the lever.** Returning `NGX_ERROR` from `postconfiguration` makes `ngx_stream_block`/`ngx_init_cycle` fail the configuration — aborting `nginx -t` and a `nginx -s reload`, and preventing the master from spawning workers.

### 32.5 Exact operator-facing messages

Both at `NGX_LOG_EMERG` (the severity nginx prints to stderr during `-t` and startup). Each states the cause **and** the two remedies (rebuild/enable, or switch to `auto`) — a diagnostic that doesn't name the fix is a half-measure:

- **Not compiled in:** `"xrootd_io_uring on" requires a build with liburing, but this binary was compiled WITHOUT it. Rebuild with XROOTD_ENABLE_IO_URING=1 and liburing-devel installed, or set "xrootd_io_uring auto" to allow silent fallback to the thread pool.`
- **Runtime-blocked:** `"xrootd_io_uring on" requested but io_uring is unavailable on this host (io_uring_setup probe failed). This is typically a seccomp policy ... or a kernel < 5.6. Set "xrootd_io_uring auto" to fall back to the thread pool, or enable io_uring at the host/container level.`

### 32.6 `nginx -t`, startup, and reload behavior

| Action | With an unsatisfiable `on` |
|---|---|
| `nginx -t` (config test) | prints the EMERG line; exits **non-zero**. CI/packaging gates catch the wrong build/host before deploy. |
| `nginx` / service start | master logs the EMERG; **exits non-zero**; no workers spawned; systemd marks the unit failed. |
| `nginx -s reload` | the new config is parsed in the master and **rejected**; nginx logs the EMERG and **keeps the old workers running** (standard nginx reload-rejection — a bad reload never drops traffic). Fix the config and reload again. |

Because the build-time check is config-time, the *same* `nginx -t` that validates every other directive validates this — no special tooling — which is what makes the requirement enforceable in a deployment pipeline.

### 32.7 Master vs worker seccomp divergence — the backstop

The runtime probe (§32.3) runs in the **master**. In the overwhelming majority of deployments master and workers share the same kernel and seccomp profile (applied at the container/cgroup level), so the master-time verdict is representative. The rare exception is a worker-only syscall filter (e.g. a systemd `SystemCallFilter=` the master escapes but workers inherit, or a privilege-dropping wrapper that adds seccomp post-fork). For that case there is a **worker-init backstop**: when `xrootd_io_uring on` is in effect and `xrootd_uring_init_worker()` cannot create the ring, the worker logs `NGX_LOG_EMERG` and returns `NGX_ERROR` from `init_process` — the worker exits rather than silently serving on the pool. The master keeps respawning it, so the symptom is a service that fails to come up (a crash-loop) — the correct loud failure for a violated `on`. (`auto` never does this — a worker that can't create the ring under `auto` simply runs on the pool, §A.1.) Operators who deliberately run a worker-only io_uring-blocking filter should set `auto`, not `on`.

### 32.8 Packaging implications (the RPM split)

`nginx-mod-xrootd` ships as a dynamic module ([rpm_packaging_three_packages]); whether the backend is compiled in is a property of *that RPM's build*, not of the config:

- If the deployed `nginx-mod-xrootd` was built **without** liburing but a node's config sets `xrootd_io_uring on`, the node **fails `nginx -t` and refuses to start** (§32.2) — the mismatch is loud, exactly as intended, instead of a silent pool fallback.
- A build that links liburing must put `-luring` in the **stream module's `ngx_module_libs`** (not `CORE_LIBS`) or the `.so` fails `dlopen` (§7/§22.1) — a *different*, earlier failure mode (the module won't load at all). The `on` fail-fast assumes the module loaded and the directive parsed.
- CI/`%check` must assert both: (a) the io_uring-enabled RPM loads and `xrootd_io_uring on` starts on an io_uring host; (b) the non-io_uring RPM makes `xrootd_io_uring on` fail `nginx -t`. Ship `Requires: liburing` on the io_uring-enabled RPM so the module cannot be installed without the runtime library present.

### 32.9 Client analog — `--io-uring=on` / `XRDC_IO_URING=on`

The client applies the same "explicit-on must be satisfiable" rule, surfaced as a **non-zero exit** rather than a config error:

- Built **without** liburing (stub `uring.c`): `xrdcp --io-uring=on …` (or `XRDC_IO_URING=on`) prints `io_uring requested (--io-uring=on) but this client was built without liburing; rebuild with liburing-devel or use --io-uring=auto` and exits non-zero **before** the transfer starts. `auto`/`off` proceed on the synchronous path.
- Built with liburing but the runtime probe fails: `--io-uring=on` prints `io_uring unavailable on this host (probe failed); use --io-uring=auto` and exits non-zero. `auto` degrades silently.

Precedence is unchanged (CLI > `XRDC_IO_URING` env > built-in `auto`, §15.4.3); the strictness applies only to an explicit `on` from either surface. This mirrors the server contract: `auto` is portable; `on` is a guarantee that fails loudly when it can't be kept.

### 32.10 Test specifications

Each is a startup/`nginx -t` assertion (no traffic needed):

| Test-id | Build | Config / flag | Expected |
|---|---|---|---|
| `srv_on_not_compiled_fails` | **without** liburing | `xrootd_io_uring on` | `nginx -t` exits non-zero; EMERG "compiled WITHOUT it"; master refuses to start |
| `srv_on_runtime_blocked_fails` | with liburing | `on` under a seccomp profile blocking `io_uring_setup` | `nginx -t`/start exits non-zero; EMERG "probe failed / seccomp / kernel < x.y" |
| `srv_on_available_starts` | with liburing, io_uring host | `on` | starts; `io_uring_active{worker}==1` |
| `srv_auto_not_compiled_starts` | without liburing | `auto` | starts on the pool; one NOTICE; suite green |
| `srv_auto_runtime_blocked_starts` | with liburing, seccomp-blocked | `auto` | starts on the pool; one NOTICE |
| `srv_off_always_starts` | either | `off` | starts; ring never created |
| `srv_reload_on_unsat_rejected` | without liburing | reload into `on` | reload rejected; **old workers keep serving**; EMERG logged |
| `cli_on_not_compiled_exit` | client without liburing | `xrdcp --io-uring=on` | non-zero exit, clear message, no transfer; `auto`/`off` transfer correctly |

`srv_on_not_compiled_fails` is the headline test for the mandated requirement and runs in **`ci-uring-off`'s without-liburing build variant** (§30.1) — it asserts the wrong-build case is caught by the always-green job, on a host with no io_uring kernel at all.

### 32.11 ADR-16 — `on` means require; fail-fast on an unsatisfiable `on`

**Status** — Accepted (§32; refines ADR-14). **Context** — `auto` degrades silently anywhere; that is wrong for a node where io_uring is mandatory, because a wrong build/host then hides as a perf loss. **Decision** — `xrootd_io_uring on` is a hard requirement: if the backend is not compiled in (build-time, probe-free) or not available at runtime (master probe), xrootd **fails to start** with an `NGX_LOG_EMERG` naming cause + remedy; `auto`/`off` always start. The client mirrors this with a non-zero exit on an explicit `on`. **Consequences** — +A misconfiguration/regression is loud and caught by `nginx -t` in CI; +`on` becomes a meaningful guarantee, not a hint. −An operator who wants "use it if present" must say `auto`, not `on` (documented; `auto` is the default). **Alternatives** — `on` degrades to the pool with a warning (rejected: that *is* `auto`; it makes `on` meaningless and re-introduces silent degradation); fail only at the first request (rejected: far later, traffic-affecting, harder to catch). **Revisit-if** — operators want a third "prefer" mode distinct from `auto`/`on` (none requested).

### 32.12 Operator guidance — `on` vs `auto`

- Use **`auto`** (the default) for fleet-wide config: it enables io_uring wherever the kernel allows and degrades silently elsewhere, so one identical config is portable across bare-metal and hardened-container nodes (§15.7).
- Use **`on`** only on a controlled fleet where io_uring presence is *guaranteed* — a pinned kernel ≥ the minimum, the io_uring-enabled `nginx-mod-xrootd` RPM, no io_uring-blocking seccomp — and where you *want* a build/host regression to stop the node from starting rather than quietly serve on the pool. Pair `on` with monitoring of `io_uring_active` (it is `1` on every worker, by construction) so the absence of the ring is impossible to miss.
- Never use `on` as a performance "hint" — that is `auto`. `on` is a contract whose breach is a failed start.

### 32.13 Three layers of "available": compile-time, link-time, runtime

The backend can be absent at three distinct layers, each with its own fail-to-start trigger, stage, and message. The operator (and the test matrix) must distinguish them:

| Layer | What's missing | Detected by | Stage | `on` outcome | Message origin |
|---|---|---|---|---|---|
| **Compile-time** | `XROOTD_HAVE_LIBURING` undefined (no `liburing-devel` / `XROOTD_ENABLE_IO_URING` unset) | `xrootd_uring_validate_conf` `#if` arm | config load (`nginx -t`) | fail to start | module `NGX_LOG_EMERG` "compiled WITHOUT it" (§32.5) |
| **Link-time** | `-luring` in `CORE_LIBS` not the stream `ngx_module_libs`; dynamic `.so` can't resolve `io_uring_*` | `dlopen` of the module | module load (**before** config parse) | fail to start | nginx core: `dlopen() … undefined symbol: io_uring_queue_init` |
| **Runtime** | kernel < min, or seccomp blocks `io_uring_setup` | `xrootd_uring_runtime_available()` probe | config load (master) + worker init | fail to start | module `NGX_LOG_EMERG` "probe failed / seccomp / kernel < x.y" (§32.5) |

The **link-time** case is a *different and earlier* failure than directive validation: a mis-linked `.so` never loads, so nginx aborts at module load with core's `dlopen` error and the `xrootd_io_uring` directive is never parsed. The §32 validation owns the **compile-time** and **runtime** layers (it assumes the module loaded and the directive parsed). All three converge on "the service does not come up" — the invariant the operator relies on; they differ only in *where the log line originates*. The runbook (§16.4) maps each symptom to its fix so an on-call engineer never guesses.

### 32.14 The worker-init backstop — full implementation

§32.7 describes the rare master/worker seccomp divergence; the backstop makes an `on` worker that cannot create its ring **exit** rather than serve on the pool. Hooked inside `xrootd_uring_init_worker()` (§20.2), which already returns `NGX_OK` on a failed ring under `auto`:

```c
/* inside xrootd_uring_init_worker(), after the probe / ring-create attempt: */
if (!u->enabled) {                        /* ring did not come up this worker */
    if (xrootd_uring_mode_is_on(cycle)) { /* any merged server block == MODE_ON */
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
            "xrootd_io_uring on: this worker could not create an io_uring ring "
            "(io_uring_setup failed: %s) — refusing to run on the thread pool "
            "because io_uring was explicitly required. This usually means a "
            "worker-only seccomp filter; set xrootd_io_uring auto to allow "
            "fallback.", xrootd_uring_last_errstr());
        return NGX_ERROR;        /* worker exits; master respawns -> crash-loop */
    }
    return NGX_OK;               /* auto/off: degrade silently to the pool */
}
```

`xrootd_uring_mode_is_on(cycle)` reuses the §32.4 scan (any merged srv conf == `MODE_ON`). The crash-loop is intentional: a service that fails to come up is the loud signal a violated `on` must produce, and systemd's `StartLimitBurst` then marks the unit failed. The master-time check (§32.3) catches the common case before any worker forks; this backstop covers only the worker-only-seccomp edge. Both are guarded so `auto`/`off` never trigger them.

### 32.15 Build-time introspection — how an operator *verifies* "compiled in"

Fail-fast is only half the contract; the operator must also *see* whether the backend is present before relying on `on`. Three cheap introspection surfaces:

1. **`nginx -V` banner.** The `config` script already prints `" + xrootd: io_uring backend enabled (liburing X.Y)"` / `"… disabled …"` at configure time; surface the resulting state as a `-DXROOTD_IO_URING_BUILD=1/0` token in the module's compile string so `nginx -V 2>&1 | grep -o 'xrootd-io_uring=[a-z]*'` answers "compiled in?" without starting the server.
2. **`/metrics` gauge.** `xrootd_io_uring_enabled_config` (§16.1) is `1` iff compiled in *and* some block requested `on`/`auto`; with `xrootd_io_uring_active{worker}` (ring actually up) it distinguishes *not-built* / *built-but-off* / *built+on-but-degraded* / *built+active*.
3. **Admin config endpoint.** Extend the existing `GET /xrootd/api/v1/config` ([dashboard_config_download_anon]) to report `"io_uring": {"compiled_in": true, "mode": "on", "runtime_available": true, "restrict_active": true, "min_kernel": "5.6", "liburing_version": "2.5"}` — a single authenticated call answering all three layers (§32.13) for fleet auditing. This is the canonical "is this node's `on` actually satisfiable?" probe for a config-management system *before* it pushes `on`.

**Operator rule:** never push `xrootd_io_uring on` to a fleet without first confirming `compiled_in == true` on every target (banner or endpoint) — the fail-fast then guarantees any node that slipped through (wrong RPM) refuses to start rather than silently degrading.

### 32.16 Compile-time guards & static assertions

Belt-and-suspenders so a *mis-build* (the worst case: it compiles, links, and silently does the wrong thing) becomes a compile/link error, complementing the runtime fail-fast:

- **Mode-enum independence.** `XROOTD_IO_URING_MODE_{OFF,ON,AUTO}` live in `tunables.h` **unconditionally** (not under the liburing macro) so the directive parses identically in both builds. `_Static_assert(XROOTD_IO_URING_MODE_OFF == 0, "OFF must be 0 so NGX_CONF_UNSET_UINT merges to OFF")` pins the default-off invariant.
- **Macro hygiene.** Always `#if (XROOTD_HAVE_LIBURING)` (parenthesized, value-tested), never `#ifdef`, so an explicit `-DXROOTD_HAVE_LIBURING=0` (the client's §21.5 form) reads as "off," not "on." A top-of-`uring.c` `#if (XROOTD_HAVE_LIBURING) && !defined(__linux__)` → `#error` rejects a non-Linux build that set the flag.
- **Stub-symbol presence.** A link test asserts `xrootd_uring_worker`/`_validate_conf`/`_init_worker`/`_exit_worker` resolve in *both* variants (real or stub), so the unconditional call sites in `process.c`/`resume.c`/the stream module never produce an undefined symbol.
- **Version floor.** `config`/`Makefile` gate on `pkg-config --atleast-version=2.2 liburing`; a `_Static_assert` on `IO_URING_VERSION_{MAJOR,MINOR}` fails the compile if a too-old liburing slips past pkg-config.

### 32.17 Worked startup scenarios (exact operator experience)

**(1) Built without liburing, config `on` — the mandated failure:**
```
$ nginx -t -c /etc/nginx/nginx.conf
nginx: [emerg] "xrootd_io_uring on" requires a build with liburing, but this
binary was compiled WITHOUT it. Rebuild with XROOTD_ENABLE_IO_URING=1 and
liburing-devel installed, or set "xrootd_io_uring auto" to allow silent
fallback to the thread pool.
nginx: configuration file /etc/nginx/nginx.conf test failed
$ echo $?
1
```
Service-manager start fails identically; no workers spawn.

**(2) Built with liburing, kernel 5.4 (< 5.6 floor), config `on`:** `nginx: [emerg] "xrootd_io_uring on" requested but io_uring is unavailable on this host (io_uring_setup probe failed) … kernel < 5.6. Set "xrootd_io_uring auto" …` → exit 1.

**(3) Built with liburing, default Docker seccomp profile, config `on`:** same EMERG as (2) — the probe's `io_uring_queue_init` returns `-EPERM`; fail to start. (Operator runs a custom seccomp profile, or switches to `auto`.)

**(4) Same wrong build as (1) but config `auto`:** `nginx -t` succeeds; at runtime one `[notice] xrootd: io_uring probe … -> using thread pool`. Starts and serves on the pool — the safe, portable default.

**(5) Mis-linked `.so` (`-luring` in `CORE_LIBS`) — the link-time layer:** `nginx: [emerg] dlopen() "…/ngx_stream_xrootd_module.so" failed (… undefined symbol: io_uring_queue_init)` — fails *before* config parse; caught by the §22.1 governance rule and the RPM `%check`.

### 32.18 The requirement, formally

**REQ-IOURING-FAILFAST (MUST).** If `xrootd_io_uring on` is configured on any server block and the io_uring backend cannot be provided — whether because it was **not compiled into the binary** (`XROOTD_HAVE_LIBURING` undefined) **or is unavailable on the host at runtime** (kernel/seccomp) — xrootd MUST fail to start: `nginx -t` MUST exit non-zero, the master MUST NOT spawn workers, and an operator-actionable `NGX_LOG_EMERG` MUST be logged naming cause and remedy. xrootd MUST NOT silently serve on the thread pool when `on` was demanded. The compiled-without case MUST be detected at configuration time **without** requiring a working io_uring kernel (so `nginx -t` catches it anywhere, including CI). `auto` and `off` MUST always start. **Verify:** `srv_on_not_compiled_fails` (headline), `srv_on_runtime_blocked_fails`, `srv_reload_on_unsat_rejected`, `cli_on_not_compiled_exit` (§32.10). **Trace:** §32.2–§32.4 (the build-time arm is the primary, probe-free guarantee), ADR-16 (§32.11). This is the project's operator-stated hard requirement (OPS-1, §33.1).

---

## 33. Requirements specification & traceability matrix

A formal, testable requirements catalog so every design choice and test traces to a stated requirement. **MoSCoW** priority: **M** (MUST), **S** (SHOULD), **Y** (MAY). "Verify" = how it is proven (test id / review / build gate); "Trace" = the design section(s) and ADR(s) that satisfy it. **OPS-1 (REQ-IOURING-FAILFAST) is the operator-stated hard requirement and the highest-priority operational requirement.**

### 33.1 Operational requirements (OPS)

| ID | Pri | Requirement | Verify | Trace |
|---|---|---|---|---|
| **OPS-1** | **M** | `xrootd_io_uring on` + backend unavailable (compiled-without **or** runtime-blocked) ⇒ **fail to start** (`nginx -t` non-zero, no workers, EMERG w/ cause+remedy); never silent pool fallback; compiled-without detected at config time without a kernel | `srv_on_not_compiled_fails`, `srv_on_runtime_blocked_fails`, `srv_reload_on_unsat_rejected`, `cli_on_not_compiled_exit` | §32, ADR-16 |
| OPS-2 | M | `auto`/`off` always start; `auto` degrades with exactly one NOTICE | `srv_auto_*_starts`, `srv_off_always_starts` | §32.1, §4 |
| OPS-3 | M | Per-worker observability (`io_uring_active`/`ops`/`fallback{reason}`/`cqe_errors`/`inflight`) + audit on every kill flip; low-cardinality labels | `test_metrics.py`, scrape-cardinality lint | §16.1, INV#8 |
| OPS-4 | S | Silent-fallback recording rule fires under forced fallback, quiet otherwise | §30.5 rule test | §16.5 |
| OPS-5 | M | Kill switch survives `nginx -s reload`; SHM re-attach preserves the flag | F-18/F-20, `kill_panic_file` | §8.1, §14.3 |
| OPS-6 | S | Operator can verify "compiled in" pre-deploy (banner + config endpoint + gauge) | manual + endpoint test | §32.15 |
| OPS-7 | M | No-restart fleet-wide disable for a CVE in seconds (admin API or panic-file) | `kill_flip_under_load` | §8.1, ADR-08 |

### 33.2 Functional requirements (FR)

| ID | Pri | Requirement | Verify | Trace |
|---|---|---|---|---|
| FR-1 | M | Optional io_uring disk backend behind the single seam `xrootd_aio_post_task`; signature unchanged | parity matrix | §10.7, ADR-05 |
| FR-2 | M | First-cut ops: READ, WRITE, single-group READV, single-fd WRITEV(+linked FSYNC) on the ring | `uring_read/write/readv/writev_ok` | §10, ADR-06 |
| FR-3 | M | pgread, dirlist, multi-fd/multi-group vectored ops route to the thread pool unchanged | `uring_pgread/dirlist_takes_pool`, `*_multifd_fallback` | §10.6 |
| FR-4 | M | Reuse the six `*_aio_t` structs + `*_aio_done` callbacks unchanged (Option A) | byte-parity | §9.6, ADR-03 |
| FR-5 | M | Reaper posts to `ngx_posted_events`, never inline-dispatches | re-entrancy/window test | §11.2, ADR-03 |
| FR-6 | M | Three-tier cascade uring→pool→inline; op never dropped on any failure | `srv_ringfull_noloss`, F-05/06/07 | §10.7, §4 |
| FR-7 | M | Windowed reads + memory-budget admission unchanged; `kXR_wait` still emitted | `test_aio.py` windowed | §11.6 |
| FR-8 | M | Phase-32 `RWF_NOWAIT` warm-cache probe retained ahead of the ring | probe test | §10.8, ADR-07 |
| FR-9 | M | Client disk ring for the `copy.c` pump (Option A) behind the unchanged adapter | byte-exact xrdcp corpus | §12, ADR-12 |
| FR-10 | M | Client engine vtable (POLL_ADD first, cleartext RECV/SEND later); default off | resilience suite | §13, ADR-12 |
| FR-11 | M | `xrootdfs_aio` inherits the engine with no driver change; legacy `xrootdfs` untouched | `test_xrootdfs*` | §13.9 |
| FR-12 | M | Directives: `xrootd_io_uring on\|off\|auto`, `_queue_depth`, `_restrict`, `_panic_file`, `_admin` | `nginx -t` parse | §15.2 |
| FR-13 | M | Client `--io-uring=auto\|on\|off` + `XRDC_IO_URING`; CLI > env > auto | `test_libxrdc.py` | §15.4.3 |

### 33.3 Non-functional requirements (NFR)

| ID | Pri | Requirement | Verify | Trace |
|---|---|---|---|---|
| NFR-1 | M | Off by default everywhere; the shipped default cannot regress | `ci-uring-off` | ADR-14 |
| NFR-2 | M | No wire-framing change — byte-for-byte parity off/on/auto | `ci-parity` reconcile | §6, ADR-15 |
| NFR-3 | M | Phase-31 memory budget preserved (no registered server buffers first cut) | budget assertions | §11.6, §27.2 |
| NFR-4 | M | No `goto`; functional/modular; WHAT/WHY/HOW doc blocks; reuse helpers | review/grep | §4 |
| NFR-5 | M | No nginx-core patching (`src/core`,`src/event`,`src/http`) | review | §7, ADR-01/10 |
| NFR-6 | M | No new exported global (per-worker singleton via accessor) | review/`nm` | §9.1 |
| NFR-7 | M | No layout change to existing structs (only new `xrdc_aconn.fd_gen`) | ABI review | §9.8, §34.5 |
| NFR-8 | M | Builds with/without liburing; stub build has no `-luring` | `ci-uring-off` both variants | §3.2, §20.4 |
| NFR-9 | S | ASan/LSan-clean across UAF/teardown/registered-buffer lifecycle | `ci-asan-uring` | §17.6 |

### 33.4 Security requirements (SEC)

| ID | Pri | Requirement | Verify | Trace |
|---|---|---|---|---|
| SEC-1 | M | io_uring never as root; only broker-opened RESOLVE_BENEATH fds; worker zero FS caps | `sec_impersonated_read_confined`, `sec_iowq_unprivileged` | §8.2, §14, ADR-09 |
| SEC-2 | M | Ring restricted to fd-only data opcodes; no path/namespace opcode submittable | `uring_restrict.c` (`-EACCES`) | §14.4 |
| SEC-3 | M | The privileged broker never creates an io_uring ring | review | §8.2, ADR-09 |
| SEC-4 | M | UAF-safe completion: slot generation + `ctx->destroyed`; no raw pointer in `user_data` | `srv_uaf_*`, `srv_stale_cqe_generation` | §9.2, ADR-04 |
| SEC-5 | M | Admin kill endpoint: constant-time bearer + CIDR + audit; fail-closed | `kill_authz_*` | §14.5 |
| SEC-6 | S | Below kernel 5.10: containment still holds via unprivileged worker + confined fd | F-04 | §14.4, R-10 |
| SEC-7 | M | Backend optional + probe + fallback given the io_uring CVE/seccomp reality | `srv_fallback_seccomp` | §7.7, ADR-14 |

### 33.5 Build / packaging requirements (BLD)

| ID | Pri | Requirement | Verify | Trace |
|---|---|---|---|---|
| BLD-1 | M | `pkg-config liburing` (≥2.2) gate → `-DXROOTD_HAVE_LIBURING`; absent → inert stubs | both build variants | §15.1, §32.16 |
| BLD-2 | M | `-luring` in the **stream `ngx_module_libs`**, never `CORE_LIBS` (dynamic `.so` dlopen) | `dlopen` smoke / §32.17 scenario (5) | §22.1, §32.13 |
| BLD-3 | M | New `.c` (`uring.c`,`uring_submit.c`) require `./configure`; documented | build doc | §3.1, §22 |
| BLD-4 | S | io_uring-enabled RPM declares `Requires: liburing`; `%check` asserts both build variants | RPM `%check` | §32.8 |
| BLD-5 | S | Static asserts pin mode-enum, macro hygiene, version floor | compile | §32.16 |

### 33.6 Coverage & gaps

Every requirement maps to at least one test (§17/§28/§32.10) or a review/build gate; the parity matrix (NFR-2) and the fail-fast suite (OPS-1) are the two hardest gates. The pure-review NFRs (NFR-4/5/6/7) are additionally guarded by CI lints (no-`goto` grep, `nm` symbol check, `ci-uring-off`). Requirements deferred by design are tracked as the §36 tiers, not as coverage gaps.

---

## 34. Interface & ABI contracts

Per-function contracts (preconditions, postconditions, invariants, error returns, thread-context) for every new entry point, so each can be reasoned about in isolation. **Thread-context:** **ET** = nginx worker event thread; **MP** = master process (config load); **CT** = client copy/transfer thread; **LT** = client loop thread.

### 34.1 Server — lifecycle & validation

| Function | Ctx | Preconditions | Postconditions / returns | Invariants / errors |
|---|---|---|---|---|
| `xrootd_uring_runtime_available()` | MP/ET | — | memoized 1/0; first call probes a throwaway ring + tears it down | never opens a long-lived ring; never `uname`-parses; idempotent |
| `xrootd_uring_validate_conf(cf)` | MP | postconfiguration, after merge | `NGX_OK` if no block needs `on` OR `on` is satisfiable; `NGX_ERROR`(+EMERG) if `on` unsatisfiable | **build-time arm needs no kernel**; `NGX_ERROR` aborts config load (OPS-1) |
| `xrootd_uring_init_worker(cycle)` | ET (post-fork) | once per worker after `xrootd_imp_init_worker` | ring up + `->enabled=1`, OR `->enabled=0` and (auto/off) `NGX_OK`; (on+unavailable) EMERG + `NGX_ERROR` → worker exits | no partial state on failure (`*_fail` unwind); `auto` never returns `NGX_ERROR` |
| `xrootd_uring_exit_worker(cycle)` | ET | from `xrootd_exit_process` | ring drained, eventfd unregistered+closed, evc closed; safe if never inited | no CQE outstanding past `queue_exit`; idempotent |
| `xrootd_uring_worker()` | ET | after init | per-worker singleton (non-NULL real; compile-time `NULL` stub) | accessor only; no allocation |
| `xrootd_uring_disabled(u)` | ET | `u != NULL` | 1 if `!enabled` OR SHM kill flag set | single relaxed atomic read; no lock |

### 34.2 Server — submit / reap / slots

| Function | Ctx | Preconditions | Postconditions / returns | Invariants / errors |
|---|---|---|---|---|
| `xrootd_uring_op_for(task)` | ET | `task->handler` bound | op-kind, or `NONE` (→pool) for pgread/dirlist/multi-fd | pure; keyed on worker-fn pointer + shape predicate |
| `xrootd_uring_submit(ctx,c,task,op,posted)` | ET | `op != NONE`, ring enabled | `*posted=1` iff full SQE submit succeeded, else 0 (→pool); `NGX_OK` always | op never dropped; slot released on any prep/submit failure; `inflight` bumped only post-submit |
| `xrootd_uring_eventfd_handler(ev)` | ET | armed evc readable | drains eventfd, harvests all CQEs, posts each completed task event | never inline-dispatches `*_aio_done`; touches only the CQ; stale CQE dropped via generation |
| `xrootd_uring_apply_cqe(u,slot,cqe)` | ET | slot validated | `cqe->res`→OUT fields per op_kind; returns 1 on chain's final CQE | `-errno` negation here; writev+fsync accumulate via `pending_cqes` |
| `xrootd_uring_slot_acquire(u,&idx)` | ET | — | a free slot (in_use=1)+index, or NULL if `inflight==depth`/none free | does not bump `inflight` (submit does) or generation |
| `xrootd_uring_slot_release(u,idx)` | ET | `idx < depth` | in_use=0, task=NULL, **generation++** | the generation bump is the UAF guard; bounds-checked no-op otherwise |

### 34.3 Server — kill switch

| Function | Ctx | Preconditions | Postconditions / returns | Invariants / errors |
|---|---|---|---|---|
| `xrootd_uring_kill_switch_set(v,reason)` | ET (admin) | SHM mapped | atomic store `io_uring_disabled`=v + reason + epoch | fleet-wide visible on every worker's next submit read; drain semantics (no in-flight cancel) |
| `xrootd_uring_panic_file_present()` | ET | — | 1 iff the watched path stats present | `stat`-only (no open; symlink-safe); coarse timer cadence |

### 34.4 Client — disk ring & engine

| Function | Ctx | Preconditions | Postconditions / returns | Invariants / errors |
|---|---|---|---|---|
| `xrdc_uring_available()` | CT/LT | — | memoized 1/0 (real probe); 0 in a no-liburing build | never `uname`; cached per process |
| `xrdc_disk_ring_create(...)` | CT | `fd` open | ring + registered-buffer pool, or NULL+`st` | `*_create_fail` unwind (no goto); no partial registration leaks |
| `xrdc_disk_ring_drain(r,st)` | CT | — | flush all in-flight; first error (incl. short write)→`-1`+`st`; else 0 | **must precede the atomic rename** on download; every buffer returned |
| `xrdc_disk_ring_destroy(r)` | CT | — | drains, unregisters, frees; safe on NULL | no buffer outlives the ring; idempotent |
| `engine_vtbl.{arm,wait,wake,cancel}` | LT | engine selected at `xrdc_loop_create` | epoll: today's behavior; io_uring: POLL_ADD multishot readiness | TLS conns keep `SSL_*`; `cancel` bumps `fd_gen` to drop stale CQEs |

### 34.5 ABI / layout contract

- The six `*_aio_t` structs and `xrdc_aconn` (except the one new `fd_gen`) are **layout-frozen**; any change requires a full rebuild (mixed-ABI hazard, §9.8). `xrootd_uring_t`, `xrootd_uring_slot_t`, and `xrdc_disk_ring` are **new and never embedded** in an existing struct.
- The SHM metrics block grows once (the `uring` sibling of `frm`, §22.8); declare all fields up-front so a rolling reload never re-attaches a stale layout.
- `user_data` encoding is a **stable contract**: server `(generation<<32)|slot_index`, client `(fd_gen<<32)|slot_index`. Any change is an ABI break of in-flight-completion routing and must land atomically.

---

## 35. Compatibility & support matrix

What is supported on which kernel/liburing/distro, and the exact behavior (use / degrade / fail-fast) per combination. The **minimum supported configuration to enable** the backend is kernel ≥ 5.6 + liburing ≥ 2.2; below that, `off`/`auto` run on the pool and `on` fails fast.

### 35.1 Kernel capability tiers (deployment view)

| Kernel | io_uring base | register_eventfd (bridge) | register_restrictions (harden) | multishot recv (client ii-b) | Backend behavior |
|---|---|---|---|---|---|
| < 5.1 | ✗ | ✗ | ✗ | ✗ | no ring; `off`/`auto` → pool, `on` fails fast |
| 5.1–5.5 | ✓ | unreliable | ✗ | ✗ | **disk backend gated off** (`MIN_KERNEL_MINOR=6`); pool; `on` fails fast |
| 5.6–5.9 | ✓ | ✓ | ✗ | ✗ | **disk backend runs, unrestricted-but-confined** (unprivileged worker + RESOLVE_BENEATH fd, §14.4); `restrict` no-ops |
| 5.10–5.18 | ✓ | ✓ | ✓ | ✗ | **full hardened disk backend** (restrictions active); client engine ii-a (POLL_ADD), no ii-b |
| ≥ 5.19 / 6.x | ✓ | ✓ | ✓ | ✓ | full disk backend + client engine ii-a and (opt-in) ii-b |

### 35.2 Distro support grid (representative)

| Distro | Stock kernel | liburing | Out-of-box behavior | Notes |
|---|---|---|---|---|
| RHEL/Alma/Rocky 8 | 4.18 (+backports) | EPEL/AppStream | **pool only** (4.18 < 5.6) even if built in; `on` fails fast | 4.18 io_uring backports are below our floor — use `auto` |
| RHEL/Alma/Rocky 9 | 5.14 | AppStream `liburing-devel` | **hardened disk backend** (≥ 5.10) | primary WLCG target; `restrict on` active |
| Ubuntu 20.04 | 5.4 (HWE 5.15) | `liburing-dev` | stock 5.4 → pool; HWE 5.15 → hardened | enable only on HWE/newer |
| Ubuntu 22.04 | 5.15 | `liburing-dev` | hardened disk backend | — |
| Ubuntu 24.04 | 6.8 | `liburing-dev` | full (incl. client ii-b) | — |
| Debian 12 | 6.1 | `liburing-dev` | hardened disk backend | — |
| Container (any host) | host kernel | image-dependent | **probe decides**; default Docker/containerd seccomp **blocks `io_uring_setup`** → pool under `auto`, fail-fast under `on` | allow the io_uring syscalls via a custom seccomp profile if `on` is required |

### 35.3 Minimum supported configuration & policy

- **To *enable* (`on`, or `auto` engaged):** kernel ≥ **5.6**, liburing ≥ **2.2**, io_uring syscalls not seccomp-blocked. **Hardened** mode (ring restrictions) additionally needs kernel ≥ **5.10** — the recommended production floor (RHEL 9 / Ubuntu 22.04 clear it).
- **To *run* (any host):** **no io_uring requirement at all** — `off` and `auto` run on the thread pool on any supported kernel, so the module deploys everywhere; io_uring is purely an acceleration that engages where available.
- **`on` policy:** only on a fleet that *uniformly* clears the floor, runs the io_uring-enabled module, and permits the syscalls. Anywhere it doesn't, `on` fails fast (REQ-IOURING-FAILFAST / OPS-1) — by design; a heterogeneous fleet must use `auto`, not `on`.

### 35.4 Forward / backward compatibility

- **Newer kernels:** the probe + feature gates light up additional tiers (restrictions ≥5.10, multishot recv ≥5.19) automatically; no config change.
- **Kernel downgrade:** `auto` silently reverts to the pool; `on` *starts failing fast* after the downgrade — the loud signal that the node no longer meets its declared requirement.
- **liburing upgrade:** the ABI is consumed only through `io_uring_*` calls (never SHM-serialized, §25.5/§34.5), so a minor upgrade is transparent; the build re-gates on `--atleast-version=2.2`.
- **nginx/freenginx:** if upstream ships a core io_uring poller (nginx#568), the `xrootd_aio_post_task` seam (ADR-05) adopts it as a tier without touching callers, and the eventfd-bridge re-derivation (ADR-02) retires.

---

## 36. Appendix — explicitly deferred tiers

These are designed-for but **not** in the first cut; each has its own flag:

- **Server SQPOLL** (`IORING_SETUP_SQPOLL`) — kernel poller thread, needs
  registered files to pay off and a per-worker kernel-thread CPU budget; opt-in
  via `xrootd_io_uring on sqpoll`.
- **Server registered files/buffers** (`IORING_REGISTER_FILES`/`_BUFFERS`) — the
  long-lived `ctx->files` fds and reused scratch are natural candidates; their
  bytes must then be added to `xrootd_budget_ctx_footprint`.
- **Server uring-pgread (hybrid)** — uring read → thread-pool CRC32c interleave,
  so the CPU-bound encode stays off the event loop.
- **Server `IORING_OP_GETDENTS`** for dirlist — only on very new kernels.
- **Client Option B** — pump-bypass fused local↔remote path eliminating the
  Option A memcpy.
- **Client cleartext `IORING_OP_RECV/SEND` multishot + provided buffers** — true
  zero-readiness-syscall I/O on non-TLS links (follow-on within CB-W4).
- **Per-identity io_uring personalities** (`io_uring_register_personality`,
  `sqe->personality`) — run each impersonated data op under the *mapped* user's
  credentials rather than the worker's service account (§8.2). Deferred because it
  needs the broker's credential context + a broker-owned ring; the first-cut
  unprivileged-worker + confined-fd + opcode-restricted model already contains the
  surface.
- **Ring quiesce-and-teardown on kill** — beyond "stop submitting" (§8.1), tear
  the per-worker ring down once `inflight == 0` so the ring fd itself disappears
  while disabled.

---

## 37. Critical files (no edits in this plan; implementation targets)

**Server:** `src/aio/resume.c` (`xrootd_aio_post_task` selector), `src/aio/aio.h`
(task structs + `*_aio_done`/`*_aio_thread`), `src/aio/reads.c` (window pump,
pgread CRC boundary), `src/config/process.c` (worker init/exit hooks), `config`
(`ngx_module_srcs`/`ngx_module_libs`), `src/types/tunables.h`. **New:**
`src/aio/uring.{c,h}`, `src/aio/uring_submit.c`.

**Server — §8 hardening:** `src/dashboard/api_admin.c` (new
`POST /xrootd/api/v1/admin/io_uring` handler; reuse `xrootd_admin_check_auth` +
`admin_audit`), `src/compat/shm_slots.c` + the module SHM table (the
`io_uring_disabled` atomic, `ngx_atomic_t` pattern from `src/dashboard/dashboard.h`),
`src/metrics/metrics.h` (`io_uring_active`/`ops`/`fallback` gauges). **Reused
read-only (no edits, just consumed):** the impersonation seam — `src/path/beneath.c`
/ `src/path/resolve_confined_ops.c` (broker-vs-local open routing),
`src/impersonate/broker.c` (`imp_openat2` `RESOLVE_BENEATH`, SCM_RIGHTS fd-pass),
`src/fs/vfs_open.c` / `src/fs/vfs.h` (`fh->fd` provenance) — io_uring submits the
fd these already produce, adding no privileged code.

**Client:** `client/lib/copy.c` (pump adapters), `client/lib/aio.c` (epoll loop /
engine vtable), `client/Makefile` (gating), `client/lib/xrdc.h`
(`xrdc_copy_opts`). **New:** `client/lib/uring.{c,h}`. **Inherited/test-only:**
`client/apps/xrootdfs_aio.c`, `tests/c/fault_proxy.c`, `tests/c/aio_resil.c`.
