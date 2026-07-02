# Phase 19 — HTTP/3 & QUIC Support

**Scope**: Add HTTP/3 (RFC 9114) over QUIC (RFC 9000) to the WebDAV and S3 endpoints,
enabling TLS 1.3-secured, UDP-multiplexed data transfer for WLCG and HEP clients.

**Net LoC change**: +~220 LoC (new helper + config directive + metrics)  
**Risk**: Medium — the core change touches `compat/http_file_response.c` which is shared
by WebDAV GET, S3 GET, and multipart-range; regression testing is broad.  
**Build impact**: Requires `--with-http_v3_module` and an OpenSSL with QUIC API support
(see Build Prerequisites). No new source files need to be registered in `config.h`.

---

## Why HTTP/3 for HEP / WLCG

XRootD's native protocol runs over TCP with optional TLS (roots://). WebDAV davs:// is TCP
TLS/1.2–1.3. HTTP/3 (QUIC) adds:

- **Head-of-line blocking elimination**: QUIC multiplexes streams independently over UDP;
  one stalled GET does not block concurrent transfers.
- **Connection migration**: client IP change (roaming Wi-Fi, multi-homed nodes) survives
  without re-handshake; critical for long-running grid jobs.
- **0-RTT reconnect**: QUIC resumes sessions without a full TLS handshake round-trip —
  reduces latency for frequent small stat/open requests typical in WLCG pilots.
- **Standard adoption**: dCache and EOS now advertise h3 via Alt-Svc. Rucio and FTS clients
  are beginning to use curl 8.x with QUIC for transfers. Being able to respond on the same
  port with HTTP/1.1, HTTP/2, and HTTP/3 negotiated via ALPN/Alt-Svc keeps the gateway
  transparent to all client generations.

---

## Architecture constraints

### nginx HTTP/3 model

nginx 1.28.3 ships `ngx_http_v3_module` (enabled via `--with-http_v3_module`). Key points:

- HTTP/3 connections are accepted on a `listen <port> quic` UDP socket.
- nginx presents an `ngx_http_request_t` to content handlers identically to HTTP/1.1 and
  HTTP/2 — the handler code path is **identical**. `r->http_version == NGX_HTTP_VERSION_30`
  (3000) distinguishes the protocol version.
- **Critical**: QUIC cannot use sendfile. `ngx_buf_t` with `b->in_file = 1` is a file
  descriptor reference to be passed to `sendfile(2)` — that syscall requires a TCP socket.
  Over QUIC (UDP), nginx's output filter stack reads the data into memory. nginx will
  silently fall back to `pread(2)` for in-file buffers on QUIC connections, which means
  the data is still served correctly — but it defeats zero-copy optimization. For large
  file transfers (typical in HEP) the cost is significant: every byte is copied into nginx
  worker address space before being handed to the QUIC stack. The better path is to detect
  QUIC at response build time and use memory-backed buffers built from pre-read chunks,
  letting nginx's QUIC output filter manage stream framing directly.
- `r->connection->quic` is non-NULL for QUIC connections in nginx ≥ 1.25.

### OpenSSL QUIC requirement

nginx's QUIC implementation requires `SSL_set_quic_method()` from the OpenSSL TLS provider.
This API is **not** in OpenSSL 3.0.x (the system version: 3.0.18). It is available in:

| Library | Min version | Notes |
|---|---|---|
| **quictls** | any recent | OpenSSL 1.1.1 fork with QUIC patches; standard in CMS/ATLAS grids |
| **OpenSSL** | 3.3.0 | Native QUIC API landed in 3.3; 3.4+ is preferred |
| **BoringSSL** | any | Google fork; used by Chromium; not in standard Linux repos |
| **LibreSSL** | 3.9+ | Not yet standard on EL9/Debian 12 |

The build section below covers how to compile against quictls or OpenSSL 3.4+.  
OpenSSL 3.0.18 (current system): **configure will fail** with the `--with-http_v3_module`
flag until one of the above is in use.

---

## Implementation: step-by-step

### Step A — Build system

**Files**: `AGENTS.md`, `docs/03-configuration/build-guide.md`

1. Add `--with-http_v3_module` to the standard configure invocation:

```bash
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v3_module \        # <-- new
    --with-http_dav_module \
    --with-threads \
    --with-openssl=/opt/quictls \  # <-- path to QUIC-capable OpenSSL (see below)
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

make -j$(nproc)
```

2. Install quictls (the easiest QUIC-capable OpenSSL on EL9/Debian 12):

```bash
# EL9 / Rocky / Alma
git clone https://github.com/quictls/openssl /opt/quictls-src
cd /opt/quictls-src
./Configure enable-tls1_3 --prefix=/opt/quictls linux-x86_64
make -j$(nproc)
sudo make install_sw
```

Pass `--with-openssl=/opt/quictls-src` to nginx's configure (not `--prefix`; nginx
configure builds OpenSSL inline from source when given a source path).

3. Alternatively on systems with OpenSSL ≥ 3.3:

```bash
# Debian 13 / Ubuntu 24.04+ ship OpenSSL 3.3+ by default
# On those distros, drop --with-openssl entirely; the system library suffices
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v3_module \
    --with-http_dav_module \
    --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd
```

---

### Step B — QUIC buffer detection helper

**File**: `src/core/compat/http_file_response.h` / `src/core/compat/http_file_response.c`

Add one inline helper to centralize the QUIC connection check:

```c
/* http_file_response.h — add after existing includes */

/* Returns 1 if the request arrived over QUIC (HTTP/3), 0 otherwise.
 * Used to choose memory-backed vs file-backed ngx_buf_t at send time. */
static ngx_inline int
xrootd_http_is_quic(ngx_http_request_t *r)
{
#if (NGX_HTTP_V3)
    return r->connection->quic != NULL;
#else
    return 0;
#endif
}
```

The `NGX_HTTP_V3` guard ensures the compile-time symbol (set by nginx when
`--with-http_v3_module` is given) protects the `connection->quic` field reference which
doesn't exist in non-QUIC builds.

---

### Step C — Memory-backed file range send (core change)

**File**: `src/core/compat/http_file_response.c`

`xrootd_http_send_file_range()` (line 212) and `xrootd_http_chain_append_file_range()`
(line 26) both set `b->in_file = 1`. This works correctly for TCP (sendfile) but misses
the zero-copy path for QUIC.

Add a new function `xrootd_http_chain_append_mem_range()` and modify
`xrootd_http_send_file_range()` to dispatch based on QUIC detection:

```c
/*
 * xrootd_http_chain_append_mem_range - append a memory-backed buf for QUIC.
 *
 * Reads [start, start+len) from fd into an ngx_palloc'd buffer, appends to
 * the chain.  Used when r->connection->quic is set — sendfile is not available
 * over UDP so we read into worker memory and let the QUIC output filter handle
 * stream framing.
 *
 * Maximum single-call len: WEBDAV_PUT_COPY_CHUNK (16 MiB).  For larger bodies,
 * callers must chunk into multiple calls.
 */
static ngx_int_t
xrootd_http_chain_append_mem_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, off_t start, off_t len)
{
    u_char         *buf;
    ngx_buf_t      *b;
    ngx_chain_t    *link;
    ssize_t         n;

    if (len == 0) {
        return NGX_OK;
    }

    buf = ngx_palloc(r->pool, (size_t) len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    n = pread(fd, buf, (size_t) len, (off_t) start);
    if (n != (ssize_t) len) {
        return NGX_ERROR;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos        = buf;
    b->last       = buf + len;
    b->start      = buf;
    b->end        = buf + len;
    b->memory     = 1;
    b->last_buf   = 1;
    b->last_in_chain = 1;

    link = ngx_alloc_chain_link(r->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }
    link->buf  = b;
    link->next = NULL;

    if (*tail != NULL) {
        (*tail)->next = link;
    }
    *tail = link;

    return NGX_OK;
}
```

Modify `xrootd_http_send_file_range()` to branch on QUIC:

```c
ngx_int_t
xrootd_http_send_file_range(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len, ngx_flag_t close_fd)
{
    ngx_chain_t  out;
    ngx_chain_t *tail = NULL;
    ngx_int_t    rc;

    ngx_memzero(&out, sizeof(out));

    if (len > 0) {
        if (xrootd_http_is_quic(r)) {
            /* QUIC: read into memory — no sendfile over UDP */
            if (xrootd_http_chain_append_mem_range(r, &tail, fd, start, len)
                != NGX_OK)
            {
                if (close_fd) { ngx_close_file(fd); }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (close_fd) { ngx_close_file(fd); }
        } else {
            /* TCP: file-backed buffer — sendfile zero-copy */
            if (xrootd_http_chain_append_file_range(r, &tail, fd, path,
                                                    start, start + len - 1,
                                                    close_fd)
                != NGX_OK)
            {
                if (close_fd) { ngx_close_file(fd); }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        out.buf  = tail->buf;
        out.next = NULL;
    }

    /* ... existing header send + filter dispatch ... */
}
```

Similarly, update `xrootd_http_chain_append_file_range()` to accept a QUIC flag and
delegate to `xrootd_http_chain_append_mem_range()` when set. This covers the multipart
range caller in `webdav/xrdhttp_multipart.c` (line 191).

**Constraint on chunk size**: `pread()` is a blocking syscall. For large ranges the worker
blocks. The existing AGENTS.md invariant "Async I/O? Event-loop only" normally forbids
this. However:
- nginx already falls back to `pread()` for in-file buffers on QUIC silently (it has no
  sendfile-over-QUIC path); so the blocking is happening today, just hidden.
- For this phase, the 16 MiB WEBDAV_PUT_COPY_CHUNK cap keeps individual blocking windows
  reasonable.
- Phase 20 (future) would use `ngx_thread_pool_run` to offload the `pread()` to a thread
  pool for truly async QUIC GET — document this as a known limitation.

---

### Step D — nginx.conf: HTTP/3 listener and QUIC config

**File**: `tests/configs/nginx_shared.conf` + deployment template

The QUIC listener coexists with the existing TLS listener on the same port using a UDP
socket:

```nginx
server {
    listen 8443 ssl;          # existing — HTTP/1.1 + HTTP/2 over TCP
    listen 8443 quic reuseport; # new — HTTP/3 over UDP

    ssl_protocols TLSv1.2 TLSv1.3;  # QUIC requires TLS 1.3 but keep 1.2 for TCP
    ssl_certificate      /tmp/xrd-test/certs/server.crt;
    ssl_certificate_key  /tmp/xrd-test/certs/server.key;

    # HTTP/3 settings
    http3 on;
    quic_retry on;                    # anti-amplification DoS protection
    http3_max_concurrent_streams 256; # concurrent GET streams

    # Advertise HTTP/3 availability to HTTP/1.1 and HTTP/2 clients
    add_header Alt-Svc 'h3=":8443"; ma=86400' always;

    location / {
        xrootd_webdav on;
        # ... existing directives ...
    }
}
```

Key points:
- `reuseport` on the `quic` listen line: required when nginx has multiple worker processes;
  each worker gets its own UDP socket for QUIC — prevents a single-accept-process bottleneck.
- `quic_retry on`: requires address validation token before allocating per-connection state;
  protects against UDP amplification attacks (important for public-facing endpoints).
- `http3_max_concurrent_streams 256`: matches typical WLCG pilot concurrency.
- `ssl_protocols TLSv1.2 TLSv1.3`: keep TLSv1.2 for HTTP/1.1 TCP connections; QUIC
  internally enforces TLS 1.3 regardless of this directive.

For the S3 endpoint (port 9001):

```nginx
server {
    listen 9001 ssl;
    listen 9001 quic reuseport;

    http3 on;
    quic_retry on;
    add_header Alt-Svc 'h3=":9001"; ma=86400' always;

    location / {
        xrootd_s3 on;
        # ... existing directives ...
    }
}
```

---

### Step E — Alt-Svc header injection (optional module-level control)

The `add_header` nginx directive in Step D is sufficient for most deployments. If per-location
control is needed (some WebDAV paths don't expose HTTP/3, e.g., internal proxy locations),
add a new directive:

**New directive**: `xrootd_webdav_http3_alt_svc <port> <max_age_seconds>`

Example: `xrootd_webdav_http3_alt_svc 8443 86400;`

**Implementation** (3 files, ~30 LoC):

1. `src/webdav/webdav.h` — add to `ngx_http_xrootd_webdav_loc_conf_t`:
   ```c
   ngx_int_t  http3_alt_svc_port;  /* NGX_CONF_UNSET_UINT — 0 = disabled */
   ngx_uint_t http3_alt_svc_max_age; /* seconds, default 86400 */
   ```

2. `src/webdav/module.c` — register directive in `ngx_command_t` array:
   ```c
   { ngx_string("xrootd_webdav_http3_alt_svc"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
     ngx_http_xrootd_webdav_conf_http3_alt_svc,
     NGX_HTTP_LOC_CONF_OFFSET,
     0, NULL },
   ```

3. `src/webdav/access.c` — inject header in access handler after CORS:
   ```c
   if (conf->http3_alt_svc_port != NGX_CONF_UNSET_UINT
       && r->http_version != NGX_HTTP_VERSION_30)
   {
       char alt_svc[64];
       ngx_snprintf((u_char *) alt_svc, sizeof(alt_svc),
                    "h3=\":%d\"; ma=%d",
                    (int) conf->http3_alt_svc_port,
                    (int) conf->http3_alt_svc_max_age);
       xrootd_http_set_header(r, "Alt-Svc", alt_svc);
   }
   ```

**Default**: disabled (no Alt-Svc injected by module code unless directive is present).
The `add_header` nginx directive in `nginx.conf` is the simpler, zero-code-change path
and is preferred unless per-location granularity is required.

---

### Step F — Protocol metrics for HTTP/3

**Files**: `src/observability/metrics/unified.h`, `src/observability/metrics/webdav.c`, `src/observability/metrics/s3.c`,
`src/observability/metrics/writer.c` (Prometheus export), `src/webdav/access.c`, `src/s3/metrics.c`

1. **`src/observability/metrics/unified.h`** — add H3 to the protocol enum:
   ```c
   typedef enum {
       XROOTD_PROTO_STREAM = 0,
       XROOTD_PROTO_WEBDAV = 1,
       XROOTD_PROTO_S3     = 2,
       XROOTD_PROTO_H3     = 3,   /* <-- new: HTTP/3 over QUIC */
       XROOTD_PROTO_COUNT  = 4
   } xrootd_proto_t;
   ```
   Update `xrootd_metric_proto_name()` in `src/observability/metrics/unified.c` to return `"h3"` for
   the new slot.

2. **`src/webdav/access.c`** — detect HTTP/3 and route to H3 protocol counter:
   ```c
   xrootd_proto_t proto = (r->http_version == NGX_HTTP_VERSION_30)
                          ? XROOTD_PROTO_H3
                          : XROOTD_PROTO_WEBDAV;
   webdav_metrics_request_proto(r, proto);
   ```

3. **`src/observability/metrics/webdav.c`** — add byte counters:
   ```c
   /* Existing: bytes_rx_ipv4_total, bytes_rx_ipv6_total, bytes_tx_ipv4_total, bytes_tx_ipv6_total */
   /* New: */
   ngx_atomic_t  bytes_rx_h3_total;
   ngx_atomic_t  bytes_tx_h3_total;
   ngx_atomic_t  requests_h3_total;
   ```
   Increment in `access.c` on request entry and in `metrics_return()` on completion.

4. **`src/observability/metrics/writer.c`** — export new labels in Prometheus format:
   ```
   xrootd_webdav_bytes_received_total{proto="h3"} <N>
   xrootd_webdav_bytes_sent_total{proto="h3"} <N>
   xrootd_webdav_requests_total{proto="h3",method="GET"} <N>
   ```

   INVARIANT from AGENTS.md: metric labels must be low-cardinality. `proto` already has
   only 4 values (stream, webdav, s3, h3) — safe.

---

### Step G — xrdhttp multipart range (QUIC fix)

**File**: `src/webdav/xrdhttp_multipart.c` (line 191)

The multipart range handler calls `xrootd_http_chain_append_file_range()` in a loop
to build a chain of file-backed buffers for multi-range responses. On QUIC this hits the
same issue. After Step C modifies `xrootd_http_chain_append_file_range()` to accept a
QUIC dispatch flag, update the call site:

```c
/* Before: */
if (xrootd_http_chain_append_file_range(r, &tail, fd, path,
                                        rng.start, rng.end, 0) != NGX_OK) {

/* After: */
if (xrootd_http_chain_append_file_range(r, &tail, fd, path,
                                        rng.start, rng.end, 0,
                                        xrootd_http_is_quic(r)) != NGX_OK) {
```

The function signature change:
```c
/* Old */
ngx_int_t xrootd_http_chain_append_file_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, const char *path,
    off_t start, off_t end, ngx_flag_t close_fd);

/* New */
ngx_int_t xrootd_http_chain_append_file_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, const char *path,
    off_t start, off_t end, ngx_flag_t close_fd, ngx_flag_t use_mem);
```

All callers (currently: `xrdhttp_multipart.c:191` only) must be updated. No other callers
exist — confirmed by grep.

---

### Step H — TPC (Third-Party Copy) behavior under HTTP/3

HTTP-TPC (`src/webdav/tpc.c`) uses libcurl for both push and pull transfers. curl 8.x
supports HTTP/3 when built with `--with-ngtcp2` or `--with-quiche`, but this is not
guaranteed to be present in system curl packages on EL9 or Debian 12.

**Decision for this phase**: TPC operates over HTTP/1.1 or HTTP/2 regardless of whether
the incoming COPY request arrived over HTTP/3. No curl changes needed.

Document this in `docs/04-protocols/webdav-overview.md`:
> HTTP-TPC COPY pull and push use libcurl for transport. Libcurl will negotiate HTTP/2
> if the remote server supports it. HTTP/3 TPC is not yet supported; libcurl must be
> built with ngtcp2 or quiche QUIC support, which is not available in standard EL9/Debian
> packages. Use `xrootd_webdav_tpc_http_version 1.1` to pin TPC to HTTP/1.1 if HTTP/2
> causes issues with non-standard endpoints.

---

### Step I — GSI proxy certificate under QUIC

GSI proxy certificate extraction happens in `src/webdav/auth_cert.c`, which reads the
peer certificate from the SSL connection context. QUIC also uses TLS 1.3 for the
handshake, and the peer certificate is available identically via `SSL_get_peer_certificate()`
regardless of whether the underlying transport is TCP or UDP.

No changes needed in `auth_cert.c`. The existing `webdav_verify_proxy_cert()` call in
`access.c` works transparently under HTTP/3.

Confirm with:
```bash
curl --http3 --cert /tmp/xrd-test/certs/user.crt --key /tmp/xrd-test/certs/user.key \
     https://localhost:8443/test/file.txt
```

---

## Build prerequisites install sequence

### Option A: quictls (recommended for EL9)

```bash
# 1. Build quictls from source
git clone --depth=1 https://github.com/quictls/openssl /opt/quictls-src
cd /opt/quictls-src
./Configure enable-tls1_3 --prefix=/opt/quictls --shared linux-x86_64
make -j$(nproc)
sudo make install_sw

# 2. Configure nginx with HTTP/3
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v3_module \
    --with-http_dav_module \
    --with-threads \
    --with-openssl=/opt/quictls-src \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

make -j$(nproc)
```

### Option B: OpenSSL 3.3+ (future Debian 13 / Ubuntu 24.04)

```bash
# No --with-openssl needed; system library suffices
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v3_module \
    --with-http_dav_module \
    --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

make -j$(nproc)
```

Detect at configure time: if configure reports `checking for OpenSSL QUIC support... not
found`, the system OpenSSL is too old — use Option A.

---

## Implementation order

| Step | File(s) | Purpose | Blocker |
|------|---------|---------|---------|
| A | `AGENTS.md`, build-guide | Add `--with-http_v3_module` to docs | None |
| B | `compat/http_file_response.h` | `xrootd_http_is_quic()` helper | None |
| C | `compat/http_file_response.c` | Memory-backed range send for QUIC | Step B |
| G | `webdav/xrdhttp_multipart.c` | Update chain_append_file_range call | Step C |
| D | test nginx configs | QUIC listener + Alt-Svc header | None |
| E | `webdav/webdav.h`, `webdav/module.c`, `webdav/access.c` | Optional per-location Alt-Svc directive | None |
| F | `metrics/unified.h`, `metrics/webdav.c`, `metrics/writer.c` | HTTP/3 protocol counters | None |

Steps B, D, E, F are independent and can proceed in parallel. Step C depends on B. Step G
depends on C.

---

## Tests (minimum 3 per area)

### Buffer compatibility

```bash
# Confirm HTTP/3 GET works end-to-end
curl --http3 -v https://localhost:8443/test/file.txt

# Confirm byte-range GET works over HTTP/3
curl --http3 -r 0-1023 https://localhost:8443/test/file.txt | wc -c
# Expected: 1024

# Confirm HTTP/1.1 GET still uses sendfile (regression)
curl -v https://localhost:8443/test/file.txt
# Check nginx access log for protocol version
```

### Alt-Svc header

```bash
# HTTP/1.1 response includes Alt-Svc
curl -I https://localhost:8443/test/file.txt | grep Alt-Svc
# Expected: Alt-Svc: h3=":8443"; ma=86400

# HTTP/3 response does NOT include Alt-Svc (already on H3)
curl --http3 -I https://localhost:8443/test/file.txt | grep Alt-Svc
# Expected: (no Alt-Svc header — already on HTTP/3)
```

### Protocol metrics

```bash
# Generate some HTTP/3 traffic then check Prometheus
curl --http3 https://localhost:8443/test/file.txt
curl http://localhost:9100/metrics | grep 'proto="h3"'
# Expected: xrootd_webdav_bytes_sent_total{proto="h3"} > 0
```

### Test suite integration

```bash
# Run full WebDAV suite — should pass unchanged (HTTP/1.1 path)
PYTHONPATH=tests pytest tests/test_a_webdav_clients.py -v

# Run S3 suite
PYTHONPATH=tests pytest tests/test_s3.py -v --tb=short

# GSI auth over HTTP/3 (requires curl with HTTP/3 support)
curl --http3 --cert /tmp/xrd-test/certs/user.crt --key /tmp/xrd-test/certs/user.key \
     https://localhost:8443/test/file.txt
```

---

## Known limitations and future work

| Limitation | Reason | Future fix |
|---|---|---|
| `pread()` blocks worker for QUIC GET | Large range reads are synchronous | Phase 20: `ngx_thread_pool_run` for QUIC GET ranges |
| TPC COPY stays on HTTP/1.1/2 | libcurl QUIC not in standard packages | Phase 21: detect curl QUIC support, allow `tpc_http_version 3` |
| 0-RTT (early data) not exploited | nginx HTTP/3 doesn't expose early-data API to modules | Low priority — requires server-side anti-replay state |
| QUIC connection migration metrics | `bytes_rx/tx_h3_total` doesn't track migrated connections distinctly | QUIC migration metrics not exposed by nginx API today |
| No WebDAV LOCK/PROPFIND over HTTP/3 specific tests | curl HTTP/3 doesn't support COPY/MOVE/PROPFIND in current tool | Need aioquic or httpx-based test client |

---

## Relationship to the refactor series

| Phase | Target area | Net ΔLoC |
|-------|-------------|----------|
| Phase 12 | Shared HTTP file-serve | −80–110 |
| Phase 13 | AIO task dispatch macro | −10 |
| Phase 14 | Table-driven Prometheus export | −83 |
| Phase 15 | Unified namespace layer | −16 |
| Phase 16 | Unified prop store | −277 |
| Phase 17 | Error-response macro collapse | −414 |
| Phase 18 | Auth gate completion | −47 |
| **Phase 19** | HTTP/3 & QUIC support | **+~220** |
| **Subtotal** | | **−707–737 LoC net** |

Phase 19 is additive (+LoC) because it adds a new capability rather than removing
duplication. The refactor series overall remains net-negative even with this phase.
