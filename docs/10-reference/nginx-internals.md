# nginx internals used by this module

> ⚠️ **Reference tier — advanced.** Internal nginx C implementation details. Only useful if you're contributing to the module or debugging deep issues. Running a server? Skip this entirely.
>
> Prerequisites: [XRootD Basics](../02-concepts/brix-basics.md), basic understanding of C and event-driven programming.

[← nginx concepts overview](nginx-overview.md)

## 5. The nginx event loop and why blocking is prohibited

nginx's worker processes run an `epoll`-based event loop:

```c
/* simplified nginx event loop — ngx_event.c */
for (;;) {
    events = epoll_wait(epfd, event_list, MAX_EVENTS, timer_delay_ms);
    for (i = 0; i < events; i++) {
        ev = event_list[i].data.ptr;
        ev->handler(ev);    /* your module's read/write callback */
    }
    ngx_event_expire_timers();
}
```

Each `ev->handler` call runs to completion — there is no preemption, no
cooperative yield, no async/await. If `ev->handler` calls `read(2)` and the
disk is slow, the entire worker is stuck. Every other connection on that
worker — potentially thousands — waits.

This is why the module never calls blocking syscalls from an event handler
directly. Any `pread()`, `pwrite()`, `fsync()`, or `stat()` that might block
goes to the thread pool:

```c
/* src/core/aio/read.c — kXR_read AIO path */

/* Thread function: runs in thread pool, must not call nginx APIs */
void
brix_read_aio_thread(void *data, ngx_log_t *log)
{
    brix_read_aio_t *t = data;

    /* Only the blocking syscall is here */
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

/* Done callback: runs on the event loop thread after pread completes */
void
brix_read_aio_done(ngx_event_t *ev)
{
    brix_read_aio_t *t = ev->data;
    brix_ctx_t      *ctx = t->ctx;

    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        return;   /* connection was closed while we were in the thread */
    }

    /* Build the response chain and send it — nginx APIs are safe here */
    rsp_chain = brix_build_chunked_chain(ctx, c, t->databuf, t->nread);
    c->send_chain(c, rsp_chain, 0);
    brix_aio_resume(c);
}
```

nginx's thread pool posts the task and immediately returns the event loop to
serve other connections. When `pread` completes, the thread posts an event
back to the event loop, which calls `brix_read_aio_done`.

**Contrast with XRootD's threading model:** XRootD uses a thread-per-connection
model (via `XrdScheduler`). Every connection gets its own OS thread. This works
but has significant overhead:
- Each thread consumes ~8 MiB of stack by default
- 10,000 concurrent connections = 80 GiB of virtual address space just for stacks
- OS scheduler context-switches between threads even when they are all waiting on I/O

nginx's event-loop + thread-pool model handles the same 10,000 connections with
a handful of workers (typically 1 per CPU core) plus a small thread pool (8–32
threads). Stack and scheduling overhead is a rounding error.

---

## 6. Buffer chains and zero-copy I/O

nginx represents data to send as a linked list of `ngx_chain_t` nodes, each
pointing to an `ngx_buf_t`:

```c
struct ngx_buf_s {
    u_char    *pos;       /* start of data to send */
    u_char    *last;      /* end of data to send */
    off_t      file_pos;  /* file offset (if file-backed) */
    off_t      file_last; /* file end (if file-backed) */
    ngx_file_t *file;     /* the open file (if file-backed) */

    unsigned   in_file:1;    /* use file_pos..file_last, not pos..last */
    unsigned   last_buf:1;   /* this is the last buffer in the response */
    unsigned   flush:1;      /* flush after sending this buffer */
    unsigned   memory:1;     /* pos..last is a read-only memory mapping */
    unsigned   temp_file:1;  /* from a temp file, writable */
};
```

A file-backed buffer (`in_file = 1`) lets nginx call `sendfile(2)` internally —
the kernel copies data from the file's page cache directly to the socket without
going through userspace. No `malloc`, no `memcpy`, no userspace copy at all.

The module uses this for cleartext reads:

```c
/* src/core/aio/buffers.c — build a file-backed chain for kXR_read */
buf->in_file  = 1;
buf->file     = &ctx->files[handle_idx].ngx_file;
buf->file_pos = offset;
buf->file_last = offset + rlen;
```

When this chain reaches `c->send_chain()`, nginx calls `sendfile(2)`. For a
4 MiB read, the data path is:

```
disk → kernel page cache → socket send buffer
```

There is no intermediate copy in userspace. The module's C code only builds
the chain descriptor — nginx and the kernel do the actual data movement.

The official XRootD daemon implements its own equivalent in `XrdOucIOVec` and
`XrdSfsInterface::Read()`. Every read goes through at least one userspace
buffer copy. For high-throughput workloads this is measurable.

---

## 7. The HTTP header filter chain — and a critical pitfall for add-on modules

### How the chain works

nginx processes HTTP response headers through a linked list of filter functions.
Each filter can add, remove, or rewrite headers before passing control to the
next filter in the chain:

```c
/* Canonical registration pattern used by every nginx filter module */
static ngx_http_output_header_filter_pt  ngx_http_next_my_filter;

static ngx_int_t
my_header_filter(ngx_http_request_t *r)
{
    /* add/modify headers here */
    ngx_list_push(&r->headers_out.headers, ...);
    return ngx_http_next_my_filter(r);   /* call next in chain */
}

static ngx_int_t
my_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_next_my_filter  = ngx_http_top_header_filter;
    ngx_http_top_header_filter = my_header_filter;
    return NGX_OK;
}
```

This is **LIFO**: the last module to register becomes the first filter called.
`ngx_http_send_header(r)` invokes `ngx_http_top_header_filter(r)`, which
chains down to the built-in `ngx_http_header_filter` (the actual header writer)
at the bottom.

### The module-order trap

`ngx_http_header_filter_module` (the built-in header writer) does **not** use
the save-and-replace pattern. It sets the global with a **direct assignment**:

```c
/* nginx src/http/ngx_http_header_filter_module.c */
static ngx_int_t
ngx_http_header_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_header_filter = ngx_http_header_filter;   /* ← direct, not chained */
    return NGX_OK;
}
```

nginx calls `postconfiguration` for all modules in **module-list order**
(`objs/ngx_modules.c`). Add-on modules compiled with `--add-module=` are
inserted **before** the built-in HTTP filter modules in that list:

```
# objs/ngx_modules.c (excerpt — add-on modules come first)
&ngx_http_brix_webdav_module,   /* ← add-on: postconfiguration runs first */
...
&ngx_http_header_filter_module,   /* ← built-in: postconfiguration runs second */
&ngx_http_chunked_filter_module,
...
```

Consequence: if an add-on module's `postconfiguration` registers a header
filter, at that moment `ngx_http_top_header_filter` is still `NULL` (no
built-in filter has registered yet). The add-on saves `next = NULL` and sets
`top = add_on_filter`. Then `ngx_http_header_filter_module` runs and does
`top = ngx_http_header_filter` — **overwriting the add-on registration
entirely**. The add-on filter is orphaned and never called.

You can confirm this with a `ngx_log_stderr` in the registration function:

```
nginx: xrdhttp_register_header_filter: top=0000000000000000 registering=0x51478A
#                                           ^^^^^^^^^^^^^^^^
#                                           NULL → chain is empty → we'll be overwritten
```

### Correct approaches for add-on modules that need to inject response headers

**Option A — Inject directly before returning (preferred for content handlers)**

For handlers that own the entire response path, add headers to
`r->headers_out.headers` immediately before `ngx_http_send_header(r)`:

```c
xrdhttp_add_response_headers(r, r->headers_out.status);
rc = ngx_http_send_header(r);
```

For **error returns** (`return NGX_HTTP_NOT_FOUND`), inject before the return
statement. nginx's `ngx_http_send_special_response` does **not** clear
`r->headers_out.headers` (only `ngx_http_filter_finalize_request` does, via
`ngx_http_clean_header` — a separate code path used only by filter error
recovery). The list survives intact into the error response:

```c
if (fd == NGX_INVALID_FILE) {
    if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
        xrdhttp_add_response_headers(r, NGX_HTTP_NOT_FOUND);   /* survives */
        return NGX_HTTP_NOT_FOUND;
    }
}
```

**Option B — Separate filter module (for true cross-cutting injection)**

If headers must be injected into responses from *other* modules (proxy, static
files, etc.), implement a **separate** `NGX_HTTP_MODULE` whose sole job is
filter registration, and list it **after** the built-in filter modules in the
nginx `config` file's `HTTP_MODULES` list. This ensures its `postconfiguration`
runs last (highest in the LIFO chain, called first):

```
# module config file
ngx_addon_name=ngx_http_myfilter_module
HTTP_MODULES="$HTTP_MODULES ngx_http_myfilter_module"
NGX_ADDON_SRCS="$NGX_ADDON_SRCS $ngx_addon_dir/myfilter.c"
```

This module is distinct from the content handler module and has no directives —
only a `postconfiguration` that registers the filter.

### Summary

| Scenario | Works? | Reason |
|---|---|---|
| Add-on registers filter in its `postconfiguration` | ✗ | Built-in header writer overwrites `top` afterward |
| Inject into `r->headers_out.headers` before `ngx_http_send_header` | ✓ | Directly in the list; built-in writer iterates it |
| Inject before `return NGX_HTTP_NOT_FOUND` | ✓ | `ngx_http_send_special_response` preserves the list |
| Inject before `return NGX_HTTP_NOT_FOUND` after a filter error | ✗ | `ngx_http_filter_finalize_request` calls `ngx_http_clean_header` |
| Separate filter module listed after built-in modules | ✓ | Runs after built-in registration; correctly at top of chain |

---

## 8. TLS: one function call vs thousands of lines

Starting a TLS handshake in the stream module (for the `kXR_haveTLS` in-protocol
upgrade path) is one nginx API call:

```c
/* src/protocols/root/connection/tls.c */
if (ngx_ssl_create_connection(conf->tls_ctx, c, NGX_SSL_BUFFER) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "xrootd: ngx_ssl_create_connection failed");
    /* ... */
}
rc = ngx_ssl_handshake(c);
```

nginx's `ngx_ssl_handshake` drives the OpenSSL state machine non-blockingly,
re-arming the read/write event until the handshake completes, then calling
the module's callback. The module never touches `SSL_CTX`, `SSL_read`, or
`SSL_write` for the transport layer — nginx wraps them transparently.

After the handshake, `c->recv` and `c->send` automatically use the TLS codepath.
The rest of the module is identical whether TLS is active or not.

For the HTTP module (`davs://`), TLS is handled entirely by the nginx
`ngx_http_ssl_module`. The module does not write a single line of TLS code for
the transport — it only interacts with the peer certificate (via OpenSSL APIs
for x509 proxy chain validation, in `src/auth/crypto/pki_check.c`).

Compare: the XRootD daemon's `XrdTls` subsystem is ~3,000 lines of C++ that
wires OpenSSL, manages session caches, implements non-blocking handshake
retries, and handles certificate reload. BriX-Cache has zero equivalent code.

---

## 9. Shared memory for cross-worker metrics

nginx workers are separate processes — they share no address space by default.
When 8 workers each serve connections, Prometheus metrics need to sum across
all 8. nginx provides a named shared-memory zone for this:

```c
/* src/observability/metrics/config.c */
ngx_brix_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                              sizeof(ngx_brix_metrics_t),
                                              &ngx_stream_brix_module);
ngx_brix_shm_zone->init = ngx_brix_metrics_shm_init;
```

The shared memory is an `mmap(MAP_SHARED)` region that all worker processes
can read and write. The module declares all counters as `ngx_atomic_t`:

```c
/* src/observability/metrics/metrics.h */
typedef struct {
    ngx_atomic_t  connections_total;   /* connections accepted (lifetime) */
    ngx_atomic_t  connections_active;  /* currently open connections      */
    ngx_atomic_t  bytes_rx_total;      /* bytes received from clients     */
    ngx_atomic_t  bytes_tx_total;      /* bytes sent to clients           */
    ngx_atomic_t  op_ok[BRIX_OP_COUNT];
    ngx_atomic_t  op_err[BRIX_OP_COUNT];
    …
} ngx_brix_metrics_t;
```

`ngx_atomic_t` uses processor-native compare-and-swap or locked increments
depending on the platform. Workers update counters with `ngx_atomic_fetch_add()`
without any mutex. The Prometheus scrape endpoint (an HTTP location handler
in the HTTP module) reads the same shared memory and serializes it.

The official XRootD daemon implements its own stats system (`XrdStats`,
`XrdXrootdMonitor`), with its own shared-memory layout, its own inter-process
communication for the monitor stream, and its own Prometheus exporter plugin.

---

## 10. Configuration: parsing, inheritance, and validation

nginx's config system provides:

- **Directive table**: each module declares a `ngx_command_t[]` array listing
  every directive it accepts, its argument count and types, and its handler
  function. nginx core validates arguments before calling the handler.

- **Config structs per scope**: nginx allocates a fresh config struct for every
  `server {}` block. The module declares `create_srv_conf` and `merge_srv_conf`
  callbacks. `merge_srv_conf` applies `http {}` or `stream {}` defaults to
  `server {}` settings:

```c
/* src/core/config/server_conf.c */
static char *
ngx_stream_brix_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_brix_srv_conf_t *prev = parent;
    ngx_stream_brix_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_str_value(conf->root,    prev->root,        "/");
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_msec_value(conf->tpc_key_ttl_ms,
                              prev->tpc_key_ttl_ms, 300000);
    …
    return NGX_CONF_OK;
}
```

  `NGX_CONF_UNSET` sentinel values tell `ngx_conf_merge_*` macros whether a
  child setting was explicitly configured or should inherit the parent value.

- **Post-configuration hooks**: after all directives are parsed, the module's
  `postconfiguration` callback runs to resolve paths, validate consistency, and
  install any per-phase handlers. This is where PKI consistency checks and
  authdb rule path resolution happen (`src/core/config/postconfiguration.c`).

- **Type-checked directive setters**: `ngx_conf_set_flag_slot` (for `on`/`off`),
  `ngx_conf_set_str_slot` (for strings), `ngx_conf_set_num_slot` (for integers)
  — each validates the argument type and sets the field. The module only writes
  custom handlers for semantically complex directives (like `brix_manager_map`
  or `brix_authdb`).

The XRootD daemon's config is a single large file (`xrootd.cfg`) parsed by
`XrdConfig::Configure()` — a ~2,000 line function that manually tokenises each
line and dispatches to per-subsystem handlers. Inheritance between config
contexts requires manual passing of parent-scope pointers. There is no
type-checking layer — a wrong argument silently uses a default.

---

## 11. Hot reload without dropping connections

nginx's hot-reload sequence (`nginx -s reload` or `kill -HUP <masterpid>`):

```
1. Master receives SIGHUP
2. Master re-reads nginx.conf; validates syntax
3. Master forks new worker processes (with new config, new module state)
4. New workers begin accepting connections immediately
5. Master sends SIGQUIT to old workers
6. Old workers: stop accepting new connections, finish in-progress requests
7. Old workers exit when their connection count reaches zero
8. Reload complete — no connection was dropped
```

From the module's perspective, hot reload is transparent. The module's
`init_process` callback initialises fresh state in each new worker. Old workers
drain naturally. No connection drops, no downtime, no restart.

For the official XRootD daemon, a config change requires a full restart:
`systemctl restart xrootd`. All open connections are terminated. Clients must
reconnect and re-authenticate. For a busy site with thousands of concurrent
`xrdcp` transfers, this is disruptive.

---

## 12. Everything else nginx provides

Beyond what is covered above, nginx provides the following facilities that
the official XRootD daemon implements manually (or not at all):

| nginx feature | nginx directive / API | XRootD equivalent |
|---|---|---|
| Connection rate limiting | `limit_conn_zone` | Not built-in |
| Request rate limiting | `limit_req_zone` | Not built-in |
| IP allowlist/blocklist | `allow` / `deny` | Partial (`sec.protocol host allow/deny`) |
| Virtual hosting (SNI) | `server_name` | Not in XrdHttp |
| Upstream load balancing | `upstream {}` block | Not in XrdHttp |
| Reverse proxy | `proxy_pass` | Not in XrdHttp |
| Static file serving | `root` + content handler | N/A |
| Request body size limit | `client_max_body_size` | Manual in `XrdHttpReq` |
| Send/receive timeouts | `send_timeout` / `proxy_read_timeout` | `XrdScheduler` timers |
| OCSP stapling | `ssl_stapling on` | Not in XrdTls |
| TLS session tickets | Automatic (OpenSSL) | Not in XrdTls |
| TLS certificate hot-reload | `ssl_certificate` + SIGHUP | Requires daemon restart |
| System access log | `access_log` | Separate `xrootd.monitor` plugin |
| Error log levels | `error_log … debug` | XRootD trace flags |
| Log rotation signalling | SIGUSR1 support | Manual |
| gzip response compression | `gzip on` | Not available |
| HTTP/2 | `http2 on` (nginx ≥ 1.25) | Not in XrdHttp |
| Client certificate auth | `ssl_verify_client on` | Reimplemented in `XrdTls` |
| CORS | Module code (`src/protocols/webdav/*.c`) | Reimplemented in `XrdHttp` |
| Proxy protocol (PROXY header) | `proxy_protocol on` | Not supported |
| OS privilege separation | master/worker split | Custom in `XrdSupervisor` |

---

## 13. Source layout: what the module writes vs what nginx provides

Looking at the full source tree, the breakdown is:

```
src/protocols/root/stream/module.c  ← module registration only (~200 lines)
src/core/config/                    ← directive handlers, config merge, postconfiguration
src/protocols/root/connection/      ← XRootD state machine, send/recv loop, TLS start
src/protocols/root/handshake/       ← initial handshake, opcode dispatch, policy
src/protocols/root/session/         ← login, auth, bind, ping, per-session opcodes
src/auth/gsi/                       ← GSI/x509 proxy handshake (protocol-specific)
src/auth/token/                     ← JWT/WLCG validation
src/auth/sss/                       ← SSS shared-secret auth
src/auth/voms/                      ← VOMS VO extraction (via libvomsapi)
src/auth/crypto/                    ← PKI/CRL load and consistency checks
src/auth/authz/                     ← path ACLs, authdb, VO/group policy
src/protocols/root/read/            ← kXR_open, kXR_read, kXR_readv, kXR_pgread, kXR_stat
src/protocols/root/write/           ← kXR_write, kXR_pgwrite, kXR_truncate, kXR_mkdir, etc.
src/core/aio/                       ← ngx_thread_task_t wrappers for all blocking I/O
src/fs/path/                        ← path confinement, canonical resolution
src/protocols/root/query/           ← kXR_query subtypes (cksum, space, config, stats)
src/protocols/root/fattr/           ← kXR_fattr (xattr get/set/del via Linux xattrs)
src/fs/cache/                       ← read-through cache (origin fill, eviction)
src/net/cms/                        ← CMS manager heartbeat (send/receive)
src/tpc/                            ← native root:// TPC (pull path on destination)
src/protocols/root/response/        ← XRootD response framing helpers
src/observability/metrics/          ← Prometheus counters and HTTP export endpoint
src/net/upstream/                   ← outbound XRootD redirect client
src/protocols/webdav/               ← HTTP/WebDAV module (all methods, auth, TPC, S3)
src/net/manager/                    ← dynamic server registry for manager mode
src/core/types/                     ← shared type headers (brix_ctx_t, config.h, etc.)
src/protocols/root/protocol/        ← wire format constants (kXR_* opcodes, flags)
```

Everything in that list is **protocol logic, storage logic, or domain-specific
auth logic** — the work that genuinely needs to be written because it is specific
to XRootD and WLCG workflows.

The following subsystems are **not** in the source tree because nginx provides
them:

```
(absent) TCP accept loop              → nginx event loop
(absent) TLS state machine            → ngx_ssl_handshake()
(absent) HTTP/1.1 framing (WebDAV)    → ngx_http_request_t
(absent) Process lifecycle            → nginx master
(absent) Config file parsing          → ngx_command_t + ngx_conf_t
(absent) Config inheritance           → ngx_conf_merge_*()
(absent) Access logging               → access_log directive
(absent) Pool memory allocator        → ngx_pool_t / ngx_palloc()
(absent) Timer management             → ngx_add_timer() / ngx_del_timer()
(absent) File send (sendfile)         → ngx_chain_t + in_file buffers
(absent) Cross-worker shared memory   → ngx_shared_memory_add()
(absent) Thread pool dispatch         → ngx_thread_task_post()
(absent) Hot reload                   → nginx master SIGHUP
(absent) Signal handling              → nginx master
```

This is the core economic argument in the [comparison doc](design-rationale.md):
BriX-Cache took ~5,000 developer-hours to build because it did not need to
implement any of those absent subsystems. The official XRootD daemon took
~200,000 developer-hours in part because it did.
