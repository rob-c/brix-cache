# nginx internals used by this module

[← nginx concepts overview](index.md)

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
/* src/aio/read.c — kXR_read AIO path */

/* Thread function: runs in thread pool, must not call nginx APIs */
void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;

    /* Only the blocking syscall is here */
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

/* Done callback: runs on the event loop thread after pread completes */
void
xrootd_read_aio_done(ngx_event_t *ev)
{
    xrootd_read_aio_t *t = ev->data;
    xrootd_ctx_t      *ctx = t->ctx;

    if (!xrootd_aio_restore_stream(ctx, t->streamid)) {
        return;   /* connection was closed while we were in the thread */
    }

    /* Build the response chain and send it — nginx APIs are safe here */
    rsp_chain = xrootd_build_chunked_chain(ctx, c, t->databuf, t->nread);
    c->send_chain(c, rsp_chain, 0);
    xrootd_aio_resume(c);
}
```

nginx's thread pool posts the task and immediately returns the event loop to
serve other connections. When `pread` completes, the thread posts an event
back to the event loop, which calls `xrootd_read_aio_done`.

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
/* src/aio/buffers.c — build a file-backed chain for kXR_read */
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

## 7. TLS: one function call vs thousands of lines

Starting a TLS handshake in the stream module (for the `kXR_haveTLS` in-protocol
upgrade path) is one nginx API call:

```c
/* src/connection/tls.c */
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
for x509 proxy chain validation, in `src/crypto/pki_check.c`).

Compare: the XRootD daemon's `XrdTls` subsystem is ~3,000 lines of C++ that
wires OpenSSL, manages session caches, implements non-blocking handshake
retries, and handles certificate reload. nginx-xrootd has zero equivalent code.

---

## 8. Shared memory for cross-worker metrics

nginx workers are separate processes — they share no address space by default.
When 8 workers each serve connections, Prometheus metrics need to sum across
all 8. nginx provides a named shared-memory zone for this:

```c
/* src/metrics/config.c */
ngx_xrootd_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                              sizeof(ngx_xrootd_metrics_t),
                                              &ngx_stream_xrootd_module);
ngx_xrootd_shm_zone->init = ngx_xrootd_metrics_shm_init;
```

The shared memory is an `mmap(MAP_SHARED)` region that all worker processes
can read and write. The module declares all counters as `ngx_atomic_t`:

```c
/* src/metrics/metrics.h */
typedef struct {
    ngx_atomic_t  connections_total;   /* connections accepted (lifetime) */
    ngx_atomic_t  connections_active;  /* currently open connections      */
    ngx_atomic_t  bytes_rx_total;      /* bytes received from clients     */
    ngx_atomic_t  bytes_tx_total;      /* bytes sent to clients           */
    ngx_atomic_t  op_ok[XROOTD_OP_COUNT];
    ngx_atomic_t  op_err[XROOTD_OP_COUNT];
    …
} ngx_xrootd_metrics_t;
```

`ngx_atomic_t` uses processor-native compare-and-swap or locked increments
depending on the platform. Workers update counters with `ngx_atomic_fetch_add()`
without any mutex. The Prometheus scrape endpoint (an HTTP location handler
in the HTTP module) reads the same shared memory and serializes it.

The official XRootD daemon implements its own stats system (`XrdStats`,
`XrdXrootdMonitor`), with its own shared-memory layout, its own inter-process
communication for the monitor stream, and its own Prometheus exporter plugin.

---

## 9. Configuration: parsing, inheritance, and validation

nginx's config system provides:

- **Directive table**: each module declares a `ngx_command_t[]` array listing
  every directive it accepts, its argument count and types, and its handler
  function. nginx core validates arguments before calling the handler.

- **Config structs per scope**: nginx allocates a fresh config struct for every
  `server {}` block. The module declares `create_srv_conf` and `merge_srv_conf`
  callbacks. `merge_srv_conf` applies `http {}` or `stream {}` defaults to
  `server {}` settings:

```c
/* src/config/server_conf.c */
static char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;

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
  authdb rule path resolution happen (`src/config/postconfiguration.c`).

- **Type-checked directive setters**: `ngx_conf_set_flag_slot` (for `on`/`off`),
  `ngx_conf_set_str_slot` (for strings), `ngx_conf_set_num_slot` (for integers)
  — each validates the argument type and sets the field. The module only writes
  custom handlers for semantically complex directives (like `xrootd_manager_map`
  or `xrootd_authdb`).

The XRootD daemon's config is a single large file (`xrootd.cfg`) parsed by
`XrdConfig::Configure()` — a ~2,000 line function that manually tokenises each
line and dispatches to per-subsystem handlers. Inheritance between config
contexts requires manual passing of parent-scope pointers. There is no
type-checking layer — a wrong argument silently uses a default.

---

## 10. Hot reload without dropping connections

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

## 11. Everything else nginx provides

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
| CORS | Module code (`src/webdav/*.c`) | Reimplemented in `XrdHttp` |
| Proxy protocol (PROXY header) | `proxy_protocol on` | Not supported |
| OS privilege separation | master/worker split | Custom in `XrdSupervisor` |

---

## 12. Source layout: what the module writes vs what nginx provides

Looking at the full source tree, the breakdown is:

```
src/stream/module.c      ← module registration only (~200 lines)
src/config/              ← directive handlers, config merge, postconfiguration
src/connection/          ← XRootD state machine, send/recv loop, TLS start
src/handshake/           ← initial handshake, opcode dispatch, policy
src/session/             ← login, auth, bind, ping, per-session opcodes
src/gsi/                 ← GSI/x509 proxy handshake (protocol-specific)
src/token/               ← JWT/WLCG validation
src/sss/                 ← SSS shared-secret auth
src/voms/                ← VOMS VO extraction (via libvomsapi)
src/crypto/              ← PKI/CRL load and consistency checks
src/read/                ← kXR_open, kXR_read, kXR_readv, kXR_pgread, kXR_stat
src/write/               ← kXR_write, kXR_pgwrite, kXR_truncate, kXR_mkdir, etc.
src/aio/                 ← ngx_thread_task_t wrappers for all blocking I/O
src/path/                ← path confinement, canonical resolution, VO ACL
src/query/               ← kXR_query subtypes (cksum, space, config, stats)
src/fattr/               ← kXR_fattr (xattr get/set/del via Linux xattrs)
src/cache/               ← read-through cache (origin fill, eviction)
src/cms/                 ← CMS manager heartbeat (send/receive)
src/tpc/                 ← native root:// TPC (pull path on destination)
src/response/            ← XRootD response framing helpers
src/metrics/             ← Prometheus counters and HTTP export endpoint
src/upstream/            ← outbound XRootD redirect client
src/webdav/              ← HTTP/WebDAV module (all methods, auth, TPC, S3)
src/manager/             ← dynamic server registry for manager mode
src/types/               ← shared type headers (xrootd_ctx_t, config.h, etc.)
src/protocol/            ← wire format constants (kXR_* opcodes, flags)
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

This is the core economic argument in the [comparison doc](../comparison-with-xrootd.md):
nginx-xrootd took ~5,000 developer-hours to build because it did not need to
implement any of those absent subsystems. The official XRootD daemon took
~200,000 developer-hours in part because it did.
