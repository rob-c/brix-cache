# Development

## Source layout

| File | Responsibility |
|---|---|
| `src/stream/module.c` | Module entry point, directive table, nginx module context |
| `src/core/config/*.c` | Configuration parsing, inheritance, and startup validation |
| `src/connection/*.c` | Session state machine, send/recv flow, buffering helpers |
| `src/handshake/*.c` | Client hello, opcode dispatch, auth/write routing policy |
| `src/session/*.c` | Protocol negotiation, login, bind, ping/end-session, request signing |
| `src/gsi/*.c` | GSI/x509 proxy certificate authentication exchange (DH key exchange, cert chain validation) |
| `src/token/*.c` | JWT/JWKS validation, WLCG scope and group parsing, bearer-token (`ztn`) auth |
| `src/crypto/pki_*.c` / `src/pki/*.c` | PKI/CRL startup consistency checks |
| `src/voms/*.c` | Runtime VOMS support via `dlopen("libvomsapi.so.1")` — VO extraction from proxy certs |
| `src/read/*.c` | Read-side operations: open, read, readv, pgread, stat, statx, dirlist, locate, close |
| `src/cache/*.c` | Read-through cache origin fetch, locking, and fill callbacks |
| `src/query/*.c` | kXR_query subtypes (cksum, space, config, stats, xattr, finfo, fsinfo) and kXR_prepare, kXR_set |
| `src/fattr/*.c` | kXR_fattr extended attributes (get / set / del / list via Linux xattrs) |
| `src/upstream/*.c` | Outbound XRootD redirector client for manager/upstream misses |
| `src/write/*.c` | Write-side and namespace-mutating operations: write, pgwrite, writev, sync, truncate, mkdir, rm, rmdir, mv, chmod |
| `src/core/aio/*.c` | Async I/O response builders and nginx thread-pool callbacks |
| `src/response/*.c` | Response framing, control responses, status responses, CRC32C |
| `src/path/*.c` | Path extraction, root confinement, policy matching, and log sanitization |
| `src/cms/*.c` | CMS manager heartbeat: registration, ping/pong, space and load reporting |
| `src/metrics/` | Prometheus metrics: shared-memory counters and HTTP export endpoint |
| `src/webdav/*.c` | WebDAV over HTTPS module, auth, path safety, method handlers, HTTP-TPC, and upstream proxy (`proxy.c`) |

The `tests/` directory covers client interoperability, throughput, bridge transfers, GSI, token (JWT/WLCG), WebDAV, metrics, and security regressions.

The `utils/` directory contains standalone helper scripts used during development and testing. See [`utils/README.md`](../../utils/README.md) for full usage details.

| Script | Purpose |
|---|---|
| `utils/make_proxy.py` | Generate RFC 3820 GSI proxy certificates — called by the test suite when proxies expire |
| `utils/make_token.py` | Generate WLCG JWT tokens and signing authority (RSA keypair + JWKS) for token auth testing |
| `utils/make_crl.py` | Generate PEM CRLs for local certificate revocation tests |
| `utils/inspect_token.py` | Decode JWT header/payload data and list JWKS key IDs for token debugging |
| `utils/token_examples.py` | Runnable examples for generating custom tokens with `TokenIssuer` |
| `utils/xrd_python_smoke.py` | Smoke-test an endpoint with the XRootD Python client |
| `utils/xrd_proxy.py` | TCP relay that hex-dumps XRootD protocol traffic for wire-level debugging |
| `utils/xrd_ref_server.py` | Minimal reference XRootD data server for calibrating client behaviour |
| `utils/xrd_sec_probe.py` | Adversarial security probe (44 tests): lockups, auth bypass, path traversal, resource exhaustion |

---

## Development workflow

Build and run nginx entirely from the source tree — no system install needed:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)

# A reload only reloads config, not a rebuilt binary — always do a full restart
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf -s stop || true
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

cd /path/to/nginx-xrootd
pytest -q
```

Helper launcher for local test services:

```bash
cd /path/to/nginx-xrootd
tests/manage_test_servers.sh start      # nginx + reference xrootd
tests/manage_test_servers.sh status
tests/manage_test_servers.sh restart nginx
tests/manage_test_servers.sh stop
tests/manage_test_servers.sh force-stop ref   # kill unmanaged fixed-port ref listeners
```

The main test harness in `tests/` expects nginx already running on the base anonymous/GSI/WebDAV ports. Some focused suites start their own sidecar nginx or reference services: conformance and bridge tests use a reference `xrootd`, VO ACL tests use a dedicated VOMS listener, privilege tests use a read-only listener, CRL tests use a revoked-cert listener, and token tests use the token-auth listener described in [building.md](../03-configuration/build-guide.md).

---

## Control-flow style

Module source under `src/` must not use `goto`. Prefer small helper functions,
early returns, and explicit loop status flags for cleanup and error exits. This
keeps ownership and teardown paths readable without hidden jumps.

## Readability and optimization style

Readable code is part of the module's safety model. Most contributors arrive
through nginx, XRootD, grid security, or storage operations, not all four at
once, so code should make ownership, protocol state, units, and error handling
obvious at the call site.

Prefer simple algorithms and explicit control flow when they are within roughly
90 percent of the performance of a clever implementation. If a faster version
is needed, keep the optimized part small, name the helper after the behavior it
provides, and add a short comment describing the invariant or measurement that
justifies the complexity.

Common patterns to avoid:

- dense one-line conditionals with returns or state changes
- generic parser variables that obscure which pointer is the cursor, token
  start, token end, or value length
- macros that hide allocation, parsing, or caller returns
- unclear buffer ownership across queued sends, AIO callbacks, or HTTP body
  callbacks
- hand-rolled parsing without bounds variables named close to the pointer math

Good names should reduce mental bookkeeping: use names such as
`request_length`, `segment_end`, `response_cursor`, `body_mode`, and
`owned_base` when those values cross more than a few lines.

---

## Known client and runtime quirks

These came from interoperability debugging and are easy to forget:

For the longer-form version, see [quirks.md](../10-reference/quirks.md) and
[protocol-notes.md](../10-reference/protocol-notes.md).

- **Trailing NUL in path `dlen`:** Some XRootD clients include a single trailing NUL inside the path length field. The server must tolerate this terminator but still reject embedded NULs before it.
- **`xrdfs ping` support:** `kXR_ping` is implemented in the server. If your version of `xrdfs` (e.g. 5.9.2) does not support a dedicated ping command, use `xrdfs ... ls /` as a readiness probe instead.
- **Repeated upload tests:** Use `xrdcp -f` or remove the destination first; otherwise reruns fail because the file already exists rather than testing the server.
- **Log injection:** All client-controlled strings that reach log output must go through `xrootd_sanitize_log_string()` so control bytes are escaped as `\xNN`.
- **Token auth split:** Native XRootD enforces token scopes on path-resolving operations and still applies the server-wide `xrootd_allow_write` gate. WebDAV enforces token write scopes per mutating HTTP request.
- **Protocol edge cases:** Many things that look obvious from the XRootD spec differ from what real clients actually send. Check [protocol-notes.md](../10-reference/protocol-notes.md) before simplifying any wire-level behavior.
- **nginx `O_EXCL` trap:** `ngx_open_file(path, mode, create, access)` ORs `create` into the flags argument. `NGX_FILE_DEFAULT_ACCESS` is `0644` (octal), and `0644` octal contains the bit for `O_EXCL` (`0200` octal). Always pass `NGX_FILE_DEFAULT_ACCESS` as the `access` (fourth) argument, never as `create`.

---

## Comment style

The code carries heavy inline comments in protocol-dense areas. The convention:

- explain wire-format quirks and client expectations
- explain ownership and lifetime of pool-allocated buffers
- explain why a loop or state transition is structured a particular way
- explain why a non-obvious optimization is safe and worth the complexity
- do not comment single-line syntax that is already self-evident

Protocol knowledge lives next to the code that depends on it so nothing is lost when reading or patching a single file.

---

## Build system: configure vs make

This is the single most common source of "my code change didn't take effect" confusion:

| Change | Required steps |
|---|---|
| Edit an existing `.c` or `.h` file | `make -j$(nproc)` only |
| Add a new `.c` file to `config` | **`./configure ...` first, then `make`** |
| Edit the `config` file itself | **`./configure ...` first, then `make`** |
| Change nginx version | **`./configure ...` first, then `make`** |

After `./configure`, the build system regenerates `objs/Makefile` from `config`. Running only `make` after adding a source file silently ignores it — the new file is not compiled and not linked. There is no warning.

The full configure command for this repository:

```bash
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd
make -j$(nproc)
```

After rebuilding, always do a full stop + start of nginx — do NOT use `nginx -s reload`. A reload only reparses config for the running executable; it does not load a newly compiled binary.

```bash
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf -s stop || true
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf
```

---

## Test infrastructure — which tests need which services

Not all tests use the same set of nginx listeners. Running a focused subset without the right servers will cause immediate failures.

| Test file | Servers needed | How to start |
|---|---|---|
| `test_file_api.py`, `test_xrootd.py`, `test_readv.py` | `NGINX_ANON_PORT=11094` | `tests/manage_test_servers.sh start` |
| `test_aio.py`, `test_write.py`, `test_pgwrite_checksum.py` | `NGINX_ANON_PORT=11094` | same |
| `test_gsi_tls.py`, `test_gsi_security.py` | `NGINX_GSI_PORT=11095`, PKI fixtures | same |
| `test_token_auth.py`, `test_token_security.py` | `NGINX_TOKEN_PORT=11097`, JWKS key | same |
| `test_webdav.py`, `test_http_webdav*.py` | `NGINX_HTTP_WEBDAV_PORT=8080` | same |
| `test_https_webdav_status_codes.py` | `NGINX_WEBDAV_PORT=8443`, TLS cert | same |
| `test_webdav_tpc.py`, `test_tpc_token_mode.py` | `NGINX_WEBDAV_PORT=8443`, remote fixture | same |
| `test_s3.py`, `test_s3_multipart.py`, `test_s3_status_codes.py` | `NGINX_S3_PORT=9001` | same |
| `test_metrics.py` | `NGINX_METRICS_PORT=9100` | same |
| `test_conformance.py`, `test_xrdcp_root_anon_compare.py` | nginx + reference xrootd `11098/11099` | same |
| `test_vo_acl.py` | GSI listener + VOMS fixture | same |
| `test_manager_mode.py`, `test_cms.py` | manager port (separate config) | same |

The `manage_test_servers.sh start` script handles all of these in one command. Use focused test runs (`pytest tests/test_file_api.py -v`) to avoid waiting for the full suite when working on one subsystem.

---

## AIO pattern — template

Every operation that may block on disk I/O uses the same `_thread` / `_done` pair pattern. Copy this template when adding a new blocking operation:

```c
/* ── Task context (allocated on connection pool before posting) ──────── */
typedef struct {
    xrootd_ctx_t       *ctx;
    ngx_connection_t   *c;
    int                 fd;
    off_t               offset;
    size_t              length;
    u_char             *buf;
    ssize_t             result;   /* output: bytes read/written, or -1 */
    int                 io_errno; /* output: errno on failure */
    ngx_uint_t          streamid; /* for xrootd_aio_restore_stream() */
} myop_aio_ctx_t;

/* ── Thread function (runs on nginx thread pool) ─────────────────────── */
static void
myop_aio_thread(void *data, ngx_log_t *log)
{
    myop_aio_ctx_t *t = data;
    /* Only touch fields in t — no ctx, c, c->pool, or nginx internals */
    t->result = pread(t->fd, t->buf, t->length, t->offset);
    if (t->result < 0) {
        t->io_errno = errno;
    }
}

/* ── Completion callback (runs on main event loop) ───────────────────── */
static void
myop_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    myop_aio_ctx_t     *t = task->ctx;

    /* ALWAYS check destroyed first */
    if (!xrootd_aio_restore_stream(t->ctx, t->streamid)) {
        ngx_free(t->buf);  /* free any separately-allocated memory */
        return;
    }

    /* Now safe to use t->ctx and t->c */
    if (t->result < 0) {
        XROOTD_RETURN_ERR(t->ctx, t->c, XROOTD_OP_MYOP, "MYOP",
                          "-", "aio-read", kXR_IOError, strerror(t->io_errno));
        return;
    }

    /* Build and send response */
    /* ... */
}

/* ── Dispatch (runs on main event loop, posts the task) ─────────────── */
ngx_int_t
xrootd_try_post_myop_aio(xrootd_ctx_t *ctx, ngx_connection_t *c, ...)
{
    ngx_thread_task_t  *task;
    myop_aio_ctx_t     *t;

    task = ngx_thread_task_alloc(c->pool, sizeof(myop_aio_ctx_t));
    if (task == NULL) { return NGX_ERROR; }

    t = task->ctx;
    t->ctx = ctx;
    t->c = c;
    t->fd = ...; t->offset = ...; t->length = ...;
    t->streamid = ctx->cur_streamid;
    t->buf = ngx_alloc(t->length, c->log);  /* not ngx_palloc — thread-safe */

    task->handler = myop_aio_thread;
    task->event.handler = myop_aio_done;
    task->event.data = task;

    ctx->state = XRD_ST_AIO;
    if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
        ngx_free(t->buf);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }
    return NGX_OK;
}
```

Key rules:
- Allocate `t->buf` with `ngx_alloc` (not `ngx_palloc`) — `ngx_palloc` is not thread-safe
- Never call `ngx_palloc`, `ngx_log_error`, or any nginx API from inside `_thread`
- Always check `xrootd_aio_restore_stream` at the top of `_done`
- Set `ctx->state = XRD_ST_AIO` before posting, restore in `_done` or on error
