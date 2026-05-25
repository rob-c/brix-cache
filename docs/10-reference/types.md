# Core type reference

The three types every handler touches. Read alongside `src/ngx_xrootd_module.h`, which has the authoritative definitions
and field-level comments.

---

## `xrootd_ctx_t` — per-connection context

One `xrootd_ctx_t` is allocated per TCP connection in
`connection/handler.c:ngx_stream_xrootd_handler()`.  It is freed when the
connection closes.  The state machine in `connection/recv.c` drives all
transitions.

### State machine group

```c
xrootd_state_t  state;
```

Controls which branch `recv.c` takes on each read event.  Valid values:

| State | Meaning |
|---|---|
| `XRD_ST_HANDSHAKE` | Accumulating the 20-byte client hello |
| `XRD_ST_REQ_HEADER` | Accumulating a 24-byte request header |
| `XRD_ST_REQ_PAYLOAD` | Accumulating `cur_dlen` payload bytes |
| `XRD_ST_SENDING` | Draining a pending write; read event is idle |
| `XRD_ST_AIO` | File I/O posted to thread pool; both events idle |
| `XRD_ST_TLS_HANDSHAKE` | SSL accept in progress |
| `XRD_ST_UPSTREAM` | Waiting for upstream redirector reply |

Handlers must not set `state` directly.  Use the helpers in
`connection/event_sched.c` and `connection/write_helpers.c`.

### Input accumulation group

```c
u_char    hdr_buf[24];   /* raw header bytes */
size_t    hdr_pos;       /* bytes received so far */
u_char    cur_streamid[2];
uint16_t  cur_reqid;     /* host byte order */
u_char    cur_body[16];
uint32_t  cur_dlen;
u_char   *payload;       /* NULL if dlen == 0 */
size_t    payload_pos;
u_char   *payload_buf;   /* reusable receive allocation (see pool patterns below) */
size_t    payload_buf_size;
```

A handler reads `hdr_buf` by casting it to the matching `ClientXxxRequest*`
from `protocol/wire.h`.  After dispatch, `payload` points at `payload_buf`
with exactly `cur_dlen` bytes.

**Handlers must not modify `hdr_buf`, `payload`, or `payload_buf`.**  These
fields are owned by `recv.c` and are overwritten on the next request.

For AIO write handlers that need the payload after returning to the event
loop, detach the buffer from the context (`ctx->payload_buf = NULL`) and free
it explicitly in the `_done` callback.

### Session auth group

```c
u_char      sessid[16];
ngx_flag_t  logged_in;    /* set after kXR_login */
ngx_flag_t  auth_done;    /* set after kXR_auth or when auth = none */
char        dn[512];       /* GSI subject DN */
char        primary_vo[128];
char        vo_list[512];
int         token_auth;
xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];
int         token_scope_count;
```

Handlers never write these fields; they are set by `session/login.c` and
`session/auth.c`.  Use `xrootd_dispatch_require_auth()` in
`handshake/policy.c` to gate access — do not check `logged_in` / `auth_done`
directly.

### File table group

```c
xrootd_file_t  files[XROOTD_MAX_FILES];
```

The array index is the XRootD file handle.  Handlers call
`xrootd_get_fhandle()` in `connection/fd_table.c` to validate a handle and
get a pointer to the slot.  They must not index `files[]` directly.

### Send buffers group

```c
/* Flat response path (small responses: error, ok, status) */
u_char   *wbuf;
size_t    wbuf_len, wbuf_pos;
u_char   *wbuf_base;

/* Chain response path (large responses: read data, dirlist) */
ngx_chain_t *wchain;
u_char      *wchain_base;

/* Reusable scratch for kXR_read / kXR_readv responses */
u_char   *read_scratch;
size_t    read_scratch_size;
u_char   *read_hdr_scratch;
size_t    read_hdr_scratch_size;
```

Handlers use `xrootd_send_ok()` and `xrootd_send_error()` from
`response/basic.c` for short responses, and
`xrootd_queue_response_chain()` from `connection/write_helpers.c` for
large responses.  They must not write to `wbuf*` or `wchain*` directly.

### AIO group

```c
ngx_uint_t  destroyed;
```

Set to 1 in `connection/disconnect.c:xrootd_on_disconnect()`.  Any AIO
`_done` callback (which fires on the main event loop after a thread-pool
task) must check this before touching `ctx` or `c`:

```c
void
xrootd_read_aio_done(ngx_event_t *wev)
{
    xrootd_aio_ctx_t *aio = wev->data;
    if (aio->ctx->destroyed) { ngx_free(aio); return; }
    /* safe to proceed */
}
```

### TLS group

```c
ngx_uint_t  tls_pending;
```

Set to 1 when `kXR_protocol` replies with `kXR_haveTLS`.  `recv.c` calls
`xrootd_start_tls()` on the next pass when this flag is set.

### Signing group

```c
u_char    signing_key[32];
int       signing_active;
uint64_t  last_seqno;
int       sigver_pending;
uint16_t  sigver_expectrid;
uint64_t  sigver_seqno;
int       sigver_nodata;
u_char    sigver_hmac[32];
```

These are owned entirely by `handshake/dispatch.c` and `handshake/sigver.c`.
No handler reads or writes them.

### Bind group

```c
int    is_bound;
int    pathid;
u_char bound_sessid[16];
```

Secondary data-channel state for `kXR_bind` parallel-stream connections.
Set by `session/bind.c`; not modified by any other handler.

---

## `xrootd_file_t` — per-open-file bookkeeping

One `xrootd_file_t` slot per entry in `ctx->files[]`.  A slot is free when
`fd == -1`.

```c
typedef struct {
    int        fd;            /* OS file descriptor; -1 = free */
    char      *path;          /* resolved absolute path */
    size_t     bytes_read;
    size_t     bytes_written;
    ngx_msec_t open_time;
    int        writable;
    int        readable;
    int        from_cache;    /* 1 = fd points into cache_root */
    char      *ckp_path;      /* heap-allocated; non-NULL when checkpoint active */
    int64_t    ckp_size;      /* file size saved at kXR_ckpBegin */
} xrootd_file_t;
```

### `fd` lifecycle

`fd` is opened in `read/open.c` via `open(2)` and closed in `read/close.c`
via `close(2)` or in `connection/fd_table.c:xrootd_close_all_files()` on
disconnect.  Handlers must not `close(f->fd)` themselves; use
`xrootd_free_fhandle()`.

### `path` ownership

`path` is allocated on the connection pool (`ngx_palloc(c->pool, len)`) at
`kXR_open` time.  It is freed implicitly when the connection pool is
destroyed at disconnect.  Do not `ngx_free(f->path)`.

### `ckp_path` ownership

`ckp_path` is heap-allocated via `ngx_alloc()` (raw `malloc`) in
`write/chkpoint.c:ckp_begin()` and freed explicitly by `ckp_clear_path(f)`.

This is different from `path` because the checkpoint file must be able to
be committed or rolled back while the main file remains open — it must
outlive (and can be freed before) the connection pool.

```c
/* correct: explicit free when done */
ngx_free(f->ckp_path);
f->ckp_path = NULL;

/* wrong: do not let it fall off the end of the connection lifetime */
```

---

## `ngx_stream_xrootd_srv_conf_t` — server configuration

One instance per `server {}` block.  Allocated by
`config/server_conf.c:ngx_stream_xrootd_create_srv_conf()`, merged with
parent defaults by `merge_srv_conf()`.

### Read-only fields (set at config parse time)

All fields except `cms_suspended` are written once at config-parse time
(before workers fork) and then read-only for the lifetime of the process.
Handlers read these fields freely; they must never write them.

Key fields:

| Field | Directive | What it controls |
|---|---|---|
| `root` | `xrootd_root` | Filesystem root; all client paths are restricted to this tree |
| `auth` | `xrootd_auth` | Authentication mode (`XROOTD_AUTH_NONE/GSI/TOKEN/BOTH/SSS`) |
| `allow_write` | `xrootd_allow_write` | Gates all mutation opcodes |
| `upstream_host` / `upstream_port` | `xrootd_upstream` | Redirector for kXR_locate |
| `cache`, `cache_root`, `cache_origin*` | `xrootd_cache*` | Read-through cache |
| `tls`, `tls_ctx` | `xrootd_tls` | In-protocol TLS upgrade |
| `thread_pool` | `xrootd_thread_pool` | AIO thread pool handle |
| `ckscan_max_depth`, `ckscan_max_files` | `xrootd_ckscan_depth`, `xrootd_ckscan_max_files` | Bounds for recursive checksum scans |

OpenSSL objects (`gsi_cert`, `gsi_key`, `gsi_store`) and the cached
`gsi_cert_pem` response material are populated after the config is fully
parsed. They are not available during directive parsing.

### Mutable runtime field

```c
ngx_uint_t  cms_suspended;
```

The only field written at runtime (set by `kYR_status suspend` from the CMS
manager; cleared by `kYR_status resume`).  Access is safe because nginx uses
a single-threaded event loop per worker process.

### `metrics_slot`

```c
ngx_int_t  metrics_slot;
```

Index into the shared-memory `ngx_xrootd_srv_metrics_t` array.  Assigned
during `postconfiguration`.  `-1` means the server has no metrics zone.
Handlers do not use this field directly; they go through `ctx->metrics`.

---

## nginx pool patterns

### `ngx_palloc(c->pool, size)` — connection-lifetime allocation

Use for any memory that should live until the connection closes.  The pool is
freed atomically in `ngx_stream_finalize_session()`.  Examples: `path`
strings, per-request temporary buffers.

Never call this from inside an AIO `_thread` function.

### `ngx_alloc(size, log)` — manually managed allocation

Use when the lifetime does not match the connection pool:

- **Longer than one request, freed explicitly** — `payload_buf` (reused
  across requests; freed in `xrootd_on_disconnect`).
- **May be freed before disconnect** — `ckp_path` (freed at checkpoint
  commit/rollback).
- **Owned by a thread-pool task** — AIO context structs that must remain
  valid after the connection's event loop returns.

### AIO callback safety rule

In any AIO `_done` callback:

```c
if (aio->ctx->destroyed) {
    ngx_free(aio);   /* free only what you allocated */
    return;
}
/* safe to use ctx and c below */
```

`ctx->destroyed` is set before the pool is freed.  Never assume `c` or
`ctx` is still valid without checking.
