# nginx stream module: why root:// lives here

The stream module handles raw TCP — it's what makes nginx able to speak the XRootD wire protocol without an HTTP translation layer in between.

[← nginx concepts overview](nginx-overview.md)

## 3. Why `root://` uses the stream module

XRootD's `root://` protocol is a **stateful binary protocol** — it has nothing
to do with HTTP. A typical connection looks like this on the wire:

```
client                                  server
  │                                        │
  │──  20-byte client handshake ────────>  │   fixed header: 0x00 0x00 0x00 0x00 …
  │<─   8-byte server handshake ─────────  │   protocol version, flags
  │                                        │
  │──  kXR_protocol  (binary) ──────────>  │   client version, options
  │<─  kXR_ok + SecurityInfo  ───────────  │   security protocol list
  │                                        │
  │──  kXR_login  (binary) ─────────────>  │   username, capabilities, token
  │<─  kXR_ok / kXR_attn  ───────────────  │   session ID, auth challenge
  │                                        │
  │──  kXR_auth (GSI cert chain) ───────>  │   DH exchange, proxy cert, VOMS ACs
  │<─  kXR_ok ───────────────────────────  │   auth complete
  │                                        │
  │──  kXR_open("/store/…", O_RDONLY) ──>  │   binary: 2-byte opcode + 16-byte header + payload
  │<─  kXR_ok (fhandle=3) ───────────────  │   binary: 4-byte handle
  │                                        │
  │──  kXR_read(fh=3, off=0, len=4MiB) ─>  │
  │<─  kXR_ok(4MiB data) ────────────────  │   raw bytes, no HTTP framing
  │                                        │
  │──  kXR_close(fh=3) ─────────────────>  │
  │<─  kXR_ok ───────────────────────────  │
  │                                        │
  │   … many more request/response pairs   │   all on the same TCP connection
  │   … same TCP connection stays open     │
```

The protocol is session-oriented:
- One TCP connection = one authenticated session
- File handles are scoped to the session — `fh=3` on connection A is
  completely different from `fh=3` on connection B
- The server accumulates per-connection state (auth DN, open file table,
  session bytes, TPC rendezvous keys) across every request on that connection

nginx's HTTP module parses HTTP framing and exposes `ngx_http_request_t`.
For `root://` that is completely wrong — there is no HTTP here. Using the HTTP
module for XRootD would mean ignoring everything it provides while fighting
against its assumptions about what a "request" looks like.

The stream module is the right fit because it exposes:

- A raw `ngx_connection_t` — read and write callbacks directly on the TCP socket
- Optional TLS (`ngx_ssl_handshake`, `ngx_ssl_create_connection`) layered on
  top transparently — see `src/connection/tls.c`
- Per-connection context (`ngx_stream_get_module_ctx`) that lives as long as the
  TCP connection
- Write-ready and read-ready events so the module can implement its own
  request/response state machine

In `src/stream/module.c`, the module registers two event handlers:

```c
static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    …
    ngx_stream_xrootd_preread_handler,   /* preread — fires first, reads initial bytes */
    ngx_stream_xrootd_handler,           /* content — main loop after preread */
    …
};
```

The preread handler grabs the initial handshake bytes. The content handler
(`handler.c`) drives the state machine for the rest of the session.

### What XRootD implements manually that we get for free

| Feature | XRootD daemon | nginx-xrootd stream module |
|---|---|---|
| Process lifecycle | `XrdSupervisor`, `XrdFork` | nginx master process |
| Signal handling (`SIGHUP` reload) | Custom in `XrdConfig` | nginx master |
| Privilege dropping | Manual `setuid()` after bind | nginx framework (`user` directive) |
| Port binding | `XrdInet::Bind()` | nginx `listen` directive |
| TLS/SSL | Layered OpenSSL manually (`XrdTls`) | `ngx_ssl_handshake()` — 1 call |
| TCP accept loop | `XrdScheduler`, thread pool | nginx event loop |
| Connection timeout | `XrdScheduler` timers | `ngx_event_add_timer()` |
| Graceful shutdown | Custom drain logic | `ngx_quit` flag + worker lifecycle |
| Hot config reload | Restart required | nginx `SIGHUP` — no connection drops |

---

## 13. The nginx module type system in practice

Every nginx module declares its type constant, which determines which API
families are available at compile time:

```c
/* Stream module — src/stream/module.c */
ngx_module_t ngx_stream_xrootd_module = {
    NGX_MODULE_V1,
    &ngx_stream_xrootd_module_ctx,
    ngx_stream_xrootd_commands,
    NGX_STREAM_MODULE,        /* ← must match the ctx type */
    NGX_MODULE_V1_PADDING
};

/* HTTP module — src/webdav/module.c */
ngx_module_t ngx_http_xrootd_webdav_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_webdav_module_ctx,
    ngx_http_xrootd_webdav_commands,
    NGX_HTTP_MODULE,          /* ← must match the ctx type */
    NGX_MODULE_V1_PADDING
};
```

The type determines which get-module-ctx macros are valid:

| Operation | Stream module | HTTP module |
|---|---|---|
| Get per-server config | `ngx_stream_conf_get_module_srv_conf(s, mod)` | `ngx_http_get_module_srv_conf(r, mod)` |
| Get per-connection/request ctx | `ngx_stream_get_module_ctx(s, mod)` | `ngx_http_get_module_ctx(r, mod)` |
| Set ctx | `ngx_stream_set_ctx(s, ctx, mod)` | `ngx_http_set_ctx(r, ctx, mod)` |
| Log handle | `s->connection->log` | `r->connection->log` |
| Allocate from pool | `s->connection->pool` | `r->pool` |
| Finalize | `ngx_stream_finalize_session(s, code)` | `ngx_http_finalize_request(r, code)` |

Calling `ngx_http_get_module_ctx` from stream code is a compile-time error —
the types are incompatible. This prevents the most common class of
module-porting mistakes.

---

## 14. Memory pools: allocation without free

nginx pool memory is allocated in slabs; the entire pool is freed at once when
its owner (connection or request) is destroyed. There is no per-object `free()`:

```c
/* Allocate zeroed memory on the connection pool — persists until TCP close */
xrootd_ctx_t *ctx = ngx_pcalloc(s->connection->pool, sizeof(xrootd_ctx_t));

/* Allocate on the request pool — freed when HTTP response is sent */
ngx_str_t *tmp = ngx_palloc(r->pool, 256);

/* Allocate outside any pool — must be freed manually */
u_char *databuf = ngx_alloc(READ_BUFFER_SIZE, c->log);  /* → ngx_free() later */
```

The three pools in this module and when to use each:

| Pool | Pointer | Lives until | Use for |
|---|---|---|---|
| Config pool | `cf->pool` | Process exit | Parsed rules, cert stores, compiled directives |
| Connection pool | `s->connection->pool` or `c->pool` | TCP close | `xrootd_ctx_t`, auth state, session buffers |
| Request pool | `r->pool` (HTTP only) | Response sent | Per-request strings, response chain links |
| Manual (heap) | `ngx_alloc()` | Explicit `ngx_free()` | AIO read/write data buffers that outlive events |

The AIO read path uses `ngx_alloc` (not `ngx_palloc`) for the data buffer
because the buffer lifetime crosses event boundaries and cannot be tied to a
pool that might be freed before `pread()` completes.

**Common mistake:** allocating a large buffer on `r->pool` for an async
operation, then returning `NGX_DONE` from the handler. If nginx recycles the
request pool before the async operation finishes, the buffer is freed while
still in use. Use `ngx_alloc` + `ngx_free` in the done callback instead.
