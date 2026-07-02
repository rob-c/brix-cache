# Phase 24 — Traffic Mirroring

**Status:** ✅ Implemented (as-built diverges from this plan — see status section)  
**Depends on:** Phase 22 (stream health check bootstrap) for stream surface  
**Touches:** `src/net/mirror/` (new), `src/protocols/root/handshake/dispatch.c`, `src/protocols/webdav/postconfig.c`  
**Net LoC:** +~780 new, ~25 modified

---

## Implementation status (as-built — reconciled 2026-06-14)

Audited against the code under `src/`. **The mirror surfaces shipped and are off
by default**: the HTTP/WebDAV mirror (PRECONTENT-phase background subrequest),
the XRootD stream stateless mirror (request replay to a shadow server after the
primary responds), and opt-in write/data-write mirroring gated by
`xrootd_mirror_writes`. The main divergences from the original plan are the
stream bootstrap state names, the Prometheus metric naming, and the later write
mirroring expansion.

| Step | Capability | Status | Evidence / divergence |
|------|-----------|--------|-----------------------|
| **A** | Common mirror config | ✅ **Done** | `xrootd_mirror_conf_t` (`src/net/mirror/mirror.h`) with `method_mask`/`opcode_mask`, `XROOTD_MIRROR_MAX_TARGETS=4`, and the `xrootd_mirror_should_sample()` PRNG helper. Embedded in both the WebDAV loc conf and the stream srv conf. |
| **B** | HTTP/WebDAV mirror | ✅ **Done** | `src/net/mirror/http_mirror.c` — PRECONTENT-phase handler registered in `src/protocols/webdav/postconfig.c:70`; main-request-only with a `mirror_fired` idempotency guard; fires a `NGX_HTTP_SUBREQUEST_BACKGROUND` subrequest per target to internal `/_xrootd_mirror...` locations; auth-strip + divergence tracking. |
| **C** | XRootD stream mirror | ✅ **Done — granular bootstrap states** | `src/net/mirror/stream_mirror.c`; `xrootd_stream_mirror_maybe()` is called from **`src/protocols/root/handshake/dispatch.c:73`** after the read-opcode dispatch (as planned). Bootstrap states are `XRD_MIR_HANDSHAKE → XRD_MIR_PROTOCOL → XRD_MIR_LOGIN → XRD_MIR_REQUEST` (mirroring the real bootstrap phases), **not** the doc's `CONNECTING/BOOTSTRAP/REQUEST/DONE`. Replays the saved primary request frame, discards the response, compares status. |
| **D** | Memory-safety invariant | ✅ **Done** | Stream mirror ctx is allocated off a process-lifetime pool (not the client connection pool) so it outlives the client; matches the Step-D requirement. |
| **E** | Multi-target | ✅ **Done** | Up to `XROOTD_MIRROR_MAX_TARGETS` (4); HTTP fans out one background subrequest per target, stream loops over targets. |
| **F** | Metrics | ✅ **Done — different metric names** | The 8 counter fields exist (`metrics.h:496-503`: `mirror_http_*` + `mirror_stream_*`). **Exported with a shared name + `surface="http"\|"stream"` label** (`xrootd_mirror_requests_total{surface=...}`, `xrootd_mirror_dropped_total{...}`, `xrootd_mirror_divergence_total{...}`, from `src/observability/metrics/stream.c:416+`), **not** the plan's separate `xrootd_webdav_mirror_*` / `xrootd_stream_mirror_*` metric names. (`surface` is a 2-value label — low cardinality, honoring Invariant 8.) |
| **G** | Opt-in write/data-write mirroring | ✅ **Done — added after original scope** | HTTP/WebDAV write methods are gated by `mirror_writes`; stream metadata mutations are replayed by `stream_mirror.c`; sequential `open(write) -> write -> close` data writes are buffered and replayed by `src/net/mirror/stream_wmirror.c`. `kXR_pgwrite`, non-sequential offsets, and over-cap payloads abort the data-write mirror safely. |

### As-built divergences (not defects)

1. **Stream bootstrap states are granular** (`HANDSHAKE/PROTOCOL/LOGIN/REQUEST`) and
   share the structure of the Phase-22 health-check / upstream bootstrap rather than
   the plan's single `BOOTSTRAP` state.
2. **Mirror metrics use a `surface` label** on shared counter names instead of
   per-surface metric names — fewer distinct metric strings, same data.
3. **Write mirroring exists even though the original plan scoped it out.** It is
   deliberately double-gated by method/opcode selection and `xrootd_mirror_writes`
   because the shadow namespace must be isolated from the primary.

### Pending / not done

- **Response-body / checksum diffing:** out of scope; only status-class divergence is
  compared, as designed.
- The shared `xrootd_bootstrap_ctx_t` base type (suggested under *Interaction with
  Other Phases*) was **not** extracted — the stream mirror, health check, and
  upstream each carry their own bootstrap state machine.

---

## Motivation

Validating a new storage backend (new cache layer, replacement TPC handler, CEPH
upgrade) against real production traffic patterns is the gold standard for correctness
testing — synthetic benchmarks miss edge cases that appear only in the wild.

The problem with bringing a shadow backend into production: clients must never see
the shadow response, shadow writes must never corrupt shared namespace, and latency
jitter on the shadow path must not bleed into the primary response. Traffic mirroring
solves all three: the primary request completes normally, then an independent
fire-and-forget copy of the request is sent to the shadow backend.

Use cases:
- **Cache backend validation**: does the new cache return the same files, with the
  same checksums, as the production cache?
- **Protocol upgrade testing**: does the new TPC handler produce the same kXR_status
  response codes as the old one under real load?
- **Read amplification measurement**: what fraction of production kXR_read/kXR_stat
  requests miss the shadow cache vs. the production cache?
- **Zero-risk regression detection**: any divergence in shadow response codes is
  reported as a metric counter and optional log line, without affecting clients.

---

## Scope and Constraints

**In scope for this phase:**

- Read operations on both surfaces: GET/HEAD/PROPFIND/STAT/LOCATE (HTTP/WebDAV)
  and kXR_stat, kXR_locate, kXR_open-read, kXR_read, kXR_readv, kXR_dirlist (stream)
- Configurable sampling rate (1–100%)
- Per-method/opcode filter list
- Divergence counter: shadow status code differs from primary status code
- Optional divergence log line at `NGX_LOG_NOTICE`

**Originally out of scope in this plan:**

- **Write mirroring** (PUT, kXR_write, kXR_pgwrite): the original plan excluded it
  because buffering write payloads risks namespace corruption on shared
  filesystems. Current source has a later implementation behind
  `xrootd_mirror_writes`; it must only target isolated shadow storage.
- **Response body comparison** (checksum diffing): comparing GET response bodies
  requires streaming the entire file from both endpoints, doubling egress. Out of scope.
- **XrdHttp stats query mirroring**: internal stats requests are not user traffic.
- **Auth/session opcode mirroring**: kXR_login, kXR_auth, kXR_bind carry live
  credentials that cannot be replayed against a second server.

---

## Architecture

Two separate mirror implementations share a common config layer but diverge at the
protocol boundary:

```
┌─────────────────────────────────────────────────────────┐
│  Production request                                     │
│                                                         │
│  WebDAV (HTTP)          XRootD stream                   │
│  ┌──────────────────┐   ┌──────────────────────────┐   │
│  │ PRECONTENT phase │   │ xrootd_dispatch()         │   │
│  │ handler fires    │   │ → primary handler returns  │   │
│  │ background       │   │ → xrootd_stream_mirror()  │   │
│  │ subrequest to    │   │   allocates mirror ctx,   │   │
│  │ /_xrootd_mirror  │   │   async connect to shadow │   │
│  └──────┬───────────┘   └──────────┬────────────────┘   │
│         │ NGX_DECLINED             │ primary rc returned │
│         ▼                         ▼                     │
│  Primary WebDAV        Primary stream response           │
│  handler serves        sent to client immediately        │
│  client normally                                         │
└─────────────────────────────────────────────────────────┘
         │ background                │ async (non-blocking)
         ▼                           ▼
   Shadow WebDAV backend      Shadow XRootD server
   (HTTP/HTTPS upstream)      (full bootstrap + request)
   Response discarded          Response read + discarded
   Status compared             Status compared
```

Both paths are fully non-blocking and complete entirely within the nginx event loop.
The primary client response is never delayed by the mirror path.

---

## Step A — Common Mirror Config

**Files:** `src/net/mirror/mirror.h` (new), `src/core/config/directives.c` (extend),
`src/core/types/config.h` (stream), `src/protocols/webdav/webdav.h` (HTTP)

### A1 — Shared config types

```c
/* src/net/mirror/mirror.h */

#define XROOTD_MIRROR_MAX_TARGETS  4   /* up to 4 shadow backends */

/* Bitmask of HTTP methods to mirror */
#define XROOTD_MIRROR_M_GET       (1u << 0)
#define XROOTD_MIRROR_M_HEAD      (1u << 1)
#define XROOTD_MIRROR_M_PROPFIND  (1u << 2)
#define XROOTD_MIRROR_M_DELETE    (1u << 3)   /* only if mirror_writes on */
#define XROOTD_MIRROR_M_MKCOL     (1u << 4)
#define XROOTD_MIRROR_M_DEFAULT   (XROOTD_MIRROR_M_GET     \
                                  | XROOTD_MIRROR_M_HEAD    \
                                  | XROOTD_MIRROR_M_PROPFIND)

/* Bitmask of XRootD opcodes to mirror */
#define XROOTD_MIRROR_OP_STAT     (1u << 0)
#define XROOTD_MIRROR_OP_LOCATE   (1u << 1)
#define XROOTD_MIRROR_OP_OPEN     (1u << 2)   /* read opens only */
#define XROOTD_MIRROR_OP_READ     (1u << 3)
#define XROOTD_MIRROR_OP_READV    (1u << 4)
#define XROOTD_MIRROR_OP_DIRLIST  (1u << 5)
#define XROOTD_MIRROR_OP_QUERY    (1u << 6)
#define XROOTD_MIRROR_OP_DEFAULT  (XROOTD_MIRROR_OP_STAT    \
                                  | XROOTD_MIRROR_OP_LOCATE  \
                                  | XROOTD_MIRROR_OP_OPEN    \
                                  | XROOTD_MIRROR_OP_DIRLIST)

typedef struct {
    ngx_str_t   url;          /* http[s]://host:port (WebDAV) or host:port (stream) */
    ngx_str_t   host;         /* parsed hostname */
    uint16_t    port;
    ngx_uint_t  ssl;          /* 1 = use TLS */
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
} xrootd_mirror_target_t;

typedef struct {
    ngx_uint_t              enabled;
    ngx_array_t            *targets;      /* array of xrootd_mirror_target_t */
    ngx_uint_t              sample_pct;   /* 1–100; 100 = mirror everything */
    ngx_uint_t              method_mask;  /* XROOTD_MIRROR_M_* bitmask */
    ngx_uint_t              opcode_mask;  /* XROOTD_MIRROR_OP_* bitmask */
    ngx_uint_t              strip_auth;   /* 1 = remove Authorization before forwarding */
    ngx_uint_t              log_diverge;  /* 1 = log when shadow status != primary */
    ngx_msec_t              timeout_ms;   /* shadow connection timeout (default 5s) */
} xrootd_mirror_conf_t;
```

### A2 — Directives

```nginx
# WebDAV location context
xrootd_mirror_url        https://shadow1.example.org:8443;
xrootd_mirror_url        https://shadow2.example.org:8443;  # multiple targets

# Stream server context
xrootd_stream_mirror_url shadow-xrd.example.org:1094;

# Shared options (both contexts)
xrootd_mirror_sample     10;        # mirror 10% of qualifying requests
xrootd_mirror_methods    GET HEAD PROPFIND;
xrootd_mirror_opcodes    stat locate open dirlist;
xrootd_mirror_strip_auth on;        # default: on (shadow never sees prod credentials)
xrootd_mirror_log_diverge on;       # log shadow vs primary status divergence
xrootd_mirror_timeout    5s;
```

`xrootd_mirror_url` may appear multiple times (up to `XROOTD_MIRROR_MAX_TARGETS`).
When multiple targets are configured, each qualifying request is mirrored to all of
them simultaneously (separate subrequests / connections).

### A3 — Sampling

```c
static ngx_uint_t
xrootd_mirror_should_sample(ngx_uint_t sample_pct)
{
    if (sample_pct >= 100) return 1;
    if (sample_pct == 0)   return 0;
    /* ngx_random() returns [0, RAND_MAX]; scale to [0, 99] */
    return (ngx_uint_t)(ngx_random() % 100) < sample_pct;
}
```

Per-request PRNG is sufficient — no need for a Bloom filter or reservoir sampler for
HEP traffic volumes. Sampling is per-request, not per-session.

---

## Step B — HTTP/WebDAV Mirror

**Files:** `src/net/mirror/http_mirror.h` (new), `src/net/mirror/http_mirror.c` (new),
`src/protocols/webdav/postconfig.c` (extend)

### B1 — PRECONTENT phase handler

nginx's `NGX_HTTP_PRECONTENT_PHASE` runs after access but before the content handler.
Registering here means the mirror fires regardless of which WebDAV method handler
runs. This is the same phase used by `ngx_http_mirror_module` and the
`ngx_http_auth_request_module`.

```c
static ngx_int_t
xrootd_http_mirror_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    xrootd_http_mirror_ctx_t          *ctx;
    xrootd_mirror_target_t            *targets;
    ngx_http_request_t                *sr;
    ngx_str_t                          mirror_uri;
    ngx_uint_t                         i;

    /* Only fire on main requests — subrequests (including the mirror itself)
     * must be skipped to avoid infinite recursion. */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    if (!conf->mirror.enabled) {
        return NGX_DECLINED;
    }

    /* Idempotency: only run once per request */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx != NULL && ctx->mirror_fired) {
        return NGX_DECLINED;
    }

    if (!xrootd_mirror_method_allowed(&conf->mirror, r->method,
                                      r->method_name))
    {
        return NGX_DECLINED;
    }

    if (!xrootd_mirror_should_sample(conf->mirror.sample_pct)) {
        XROOTD_WEBDAV_METRIC_INC(mirror_dropped_total);
        return NGX_DECLINED;
    }

    /* Mark as fired before issuing subrequests to prevent re-entry */
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) return NGX_DECLINED;
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);
    }
    ctx->mirror_fired = 1;
    ctx->primary_status = 0;  /* filled in by the content handler via ctx */

    /* Keep the request body alive for body-forwarding subrequests */
    r->preserve_body = 1;

    targets = conf->mirror.targets->elts;
    for (i = 0; i < conf->mirror.targets->nelts; i++) {
        /* Each target gets its own subrequest to a distinct internal location.
         * The target index is encoded into the URI:
         *   /_xrootd_mirror_internal/0
         *   /_xrootd_mirror_internal/1  etc. */
        u_char  *uri_data = ngx_palloc(r->pool, 32);
        if (uri_data == NULL) continue;
        mirror_uri.len  = ngx_snprintf(uri_data, 32,
                                       "/_xrootd_mirror_internal/%uz", i)
                          - uri_data;
        mirror_uri.data = uri_data;

        if (ngx_http_subrequest(r, &mirror_uri, &r->args, &sr, NULL,
                                NGX_HTTP_SUBREQUEST_BACKGROUND) != NGX_OK)
        {
            continue;
        }

        sr->method      = r->method;
        sr->method_name = r->method_name;
        sr->header_only = 1;   /* discard shadow response body */
    }

    return NGX_DECLINED;  /* main request continues to content handler */
}
```

Registration in `src/protocols/webdav/postconfig.c`:

```c
h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
if (h == NULL) return NGX_ERROR;
*h = xrootd_http_mirror_handler;
```

### B2 — Internal mirror proxy handler

Each `/_xrootd_mirror_internal/{idx}` location is a programmatically created
internal location that delegates to `xrootd_http_mirror_proxy_handler()`. This
handler is identical in structure to `webdav_proxy_handler()` (Phase 23's proxy
infrastructure) but with three key differences:

1. **Auth stripping / replacement**: When `strip_auth = 1`, the `create_request`
   callback omits the `Authorization` header. When a `mirror_token` is configured,
   it substitutes a static Bearer token.

2. **Silent failure**: `finalize_request` logs only at `NGX_LOG_DEBUG` on error.
   A failed mirror never returns an error to the client.

3. **Divergence tracking**: `process_header` extracts the shadow HTTP status code
   and compares to `ctx->primary_status` (set by the content handler after
   completing). If they differ, increment `mirror_divergence_total` and optionally
   log.

```c
static void
xrootd_mirror_proxy_finalize(ngx_http_request_t *r, ngx_int_t rc)
{
    xrootd_mirror_proxy_ctx_t *mctx;
    ngx_http_request_t        *parent;
    ngx_uint_t                 shadow_status;

    mctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (mctx == NULL) return;

    shadow_status = (r->upstream != NULL)
                    ? r->upstream->headers_in.status_n : 0;

    parent = r->parent;
    if (parent != NULL && shadow_status != 0) {
        xrootd_http_mirror_ctx_t *pctx =
            ngx_http_get_module_ctx(parent, ngx_http_xrootd_webdav_module);

        if (pctx != NULL && pctx->primary_status != 0
            && xrootd_mirror_status_class(shadow_status)
               != xrootd_mirror_status_class(pctx->primary_status))
        {
            XROOTD_WEBDAV_METRIC_INC(mirror_divergence_total);

            if (mctx->log_diverge) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "xrootd mirror divergence: primary=%uz shadow=%uz uri=%V",
                    pctx->primary_status, shadow_status, &parent->uri);
            }
        }
    }

    if (rc != NGX_OK) {
        XROOTD_WEBDAV_METRIC_INC(mirror_http_errors_total);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd mirror: shadow request failed (rc=%d) uri=%V",
                       (int) rc, &r->uri);
    } else {
        XROOTD_WEBDAV_METRIC_INC(mirror_http_total);
    }
}
```

`xrootd_mirror_status_class()` maps HTTP status to `{1,2,3,4,5}`:
```c
static ngx_uint_t
xrootd_mirror_status_class(ngx_uint_t status) { return status / 100; }
```

### B3 — Internal location creation

In `src/protocols/webdav/postconfig.c`, after registering the content handler:

```c
/* Create /_xrootd_mirror_internal/{0..N-1} internal locations programmatically.
 * Each location's handler is xrootd_http_mirror_proxy_handler with a baked-in
 * target index. Uses the same technique as ngx_http_auth_request_module for
 * adding internal-only locations from postconfiguration. */
```

The location conf clones the parent location's `ngx_http_xrootd_webdav_loc_conf_t`
and overrides the content handler with `xrootd_http_mirror_proxy_handler`. A
`target_idx` field in the cloned conf selects which `mirror.targets[]` element is
used.

### B4 — Auth stripping in create_request

```c
static ngx_int_t
mirror_proxy_create_request(ngx_http_request_t *r)
{
    /* Reconstruct upstream request line and headers.
     * If strip_auth: skip Authorization and Proxy-Authorization headers.
     * If mirror_token configured: inject Authorization: Bearer <token>. */
    ngx_table_elt_t *h;
    /* ... build request headers, skipping auth ... */
}
```

The implementation mirrors `webdav_proxy_create_request()` in `proxy_request.c` with
auth-stripping added in the header copy loop.

---

## Step C — XRootD Stream Mirror

**Files:** `src/net/mirror/stream_mirror.h` (new), `src/net/mirror/stream_mirror.c` (new),
`src/protocols/root/handshake/dispatch.c` (extend)

The stream mirror reuses the bootstrap machinery from Phase 22 (health checks):
the same connect→handshake→protocol→TLS→login sequence. After bootstrap completes,
instead of sending kXR_ping, it sends the saved primary request frame.

### C1 — Mirror context

```c
/* stream_mirror.h */

typedef enum {
    XRD_MIR_CONNECTING = 0,
    XRD_MIR_BOOTSTRAP,     /* same phases as xrootd_hc_ctx_t */
    XRD_MIR_REQUEST,       /* sent the replayed request, awaiting response */
    XRD_MIR_DONE,
} xrootd_mir_state_t;

typedef struct xrootd_stream_mirror_s {
    ngx_connection_t        *conn;
    xrootd_mir_state_t       state;

    /* Bootstrap read accumulator (same layout as upstream/health check) */
    u_char   rhdr[XRD_RESPONSE_HDR_LEN];
    size_t   rhdr_pos;
    uint16_t resp_status;
    uint32_t resp_dlen;
    u_char   resp_discard[256];  /* small discard buffer for response body */
    size_t   resp_discard_pos;

    u_char  *wbuf;
    size_t   wbuf_len;
    size_t   wbuf_pos;

    ngx_event_t  timeout_ev;

    /* Saved primary request — copied at mirror-launch time */
    u_char   saved_hdr[XRD_REQUEST_HDR_LEN];   /* 16-byte wire header */
    u_char  *saved_payload;
    uint32_t saved_dlen;

    uint16_t saved_opcode;
    ngx_int_t primary_rc;  /* primary dispatch return code for divergence check */

    char     host[256];
    uint16_t port;

    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_cycle_t                  *cycle;
    ngx_log_t                    *log;

    ngx_uint_t  log_diverge;
} xrootd_stream_mirror_t;
```

### C2 — Launch function (called from dispatch.c)

```c
/*
 * xrootd_stream_mirror_maybe — fire a mirror request to the shadow XRootD
 * server if mirroring is enabled and this opcode/request passes the filter.
 *
 * Called from xrootd_dispatch() after the primary handler returns. The primary
 * response is already queued to the client; this function runs entirely in the
 * background.
 *
 * `primary_rc` is the return code from the primary dispatch — saved for
 * divergence comparison.
 */
void
xrootd_stream_mirror_maybe(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_int_t primary_rc)
{
    xrootd_stream_mirror_t *mir;
    ngx_cycle_t            *cycle;

    if (!conf->mirror.enabled) return;
    if (!xrootd_mirror_opcode_allowed(&conf->mirror, ctx->cur_reqid)) return;
    if (!xrootd_mirror_should_sample(conf->mirror.sample_pct)) {
        XROOTD_STREAM_METRIC_INC(mirror_dropped_total);
        return;
    }

    /* Allocate from the cycle pool — the client's per-connection pool may be
     * freed before the mirror connection closes. */
    cycle = c->log->data;   /* or pass cycle explicitly */
    mir = ngx_pcalloc(cycle->pool, sizeof(*mir));
    if (mir == NULL) return;

    mir->conf        = conf;
    mir->cycle       = cycle;
    mir->log         = c->log;
    mir->primary_rc  = primary_rc;
    mir->log_diverge = conf->mirror.log_diverge;

    /* Copy primary request header (16 bytes) */
    ngx_memcpy(mir->saved_hdr, ctx->hdr_buf, XRD_REQUEST_HDR_LEN);
    mir->saved_opcode = ctx->cur_reqid;

    /* Copy payload (path + options) — bounded by XROOTD_MAX_PAYLOAD_MIRROR */
    if (ctx->payload != NULL && ctx->cur_dlen > 0
        && ctx->cur_dlen <= XROOTD_MAX_PAYLOAD_MIRROR)
    {
        mir->saved_payload = ngx_palloc(cycle->pool, ctx->cur_dlen);
        if (mir->saved_payload != NULL) {
            ngx_memcpy(mir->saved_payload, ctx->payload, ctx->cur_dlen);
            mir->saved_dlen = ctx->cur_dlen;
        }
    }

    /* Pick target (round-robin when multiple configured) */
    ngx_str_set_from_cstr(&mir->host, conf->mirror.targets[0].host);
    mir->port = conf->mirror.targets[0].port;

    xrootd_stream_mirror_start(mir);
}
```

`XROOTD_MAX_PAYLOAD_MIRROR` is set to `4096` bytes — sufficient for path + options
(stat/locate/dirlist payloads), but write bodies exceed this and are skipped. Write
opcodes are excluded by the opcode mask anyway.

### C3 — Bootstrap completion → send request

The mirror bootstrap state machine is identical to Phase 22's health check
(`xrootd_hc_handle_bootstrap`). When `XRD_MIR_BOOTSTRAP` completes:

```c
static void
xrootd_stream_mirror_send_request(xrootd_stream_mirror_t *mir)
{
    size_t  total;
    u_char *buf;

    total = XRD_REQUEST_HDR_LEN + mir->saved_dlen;
    buf   = ngx_palloc(mir->conn->pool, total);
    if (buf == NULL) {
        xrootd_stream_mirror_finish(mir, 0);
        return;
    }

    /* Rewrite streamid to 0x0002 to distinguish mirror from client reqs on
     * the shadow server's logs. The saved opcode and dlen are left as-is. */
    ngx_memcpy(buf, mir->saved_hdr, XRD_REQUEST_HDR_LEN);
    buf[0] = 0; buf[1] = 2;   /* streamid bytes */

    if (mir->saved_dlen > 0 && mir->saved_payload != NULL) {
        ngx_memcpy(buf + XRD_REQUEST_HDR_LEN, mir->saved_payload,
                   mir->saved_dlen);
    }

    mir->wbuf     = buf;
    mir->wbuf_len = total;
    mir->wbuf_pos = 0;
    mir->state    = XRD_MIR_REQUEST;

    xrootd_stream_mirror_flush(mir);
}
```

### C4 — Response read and divergence check

After the mirror request is sent, the read handler accumulates the 16-byte response
header and discards the body. On completion:

```c
static void
xrootd_stream_mirror_on_response(xrootd_stream_mirror_t *mir)
{
    uint16_t shadow_status = mir->resp_status;
    ngx_int_t shadow_rc;

    /* Map kXR status to the same NGX_HTTP_* category used by primary */
    shadow_rc = xrootd_kxr_to_ngx_rc(shadow_status);

    if (shadow_rc != mir->primary_rc) {
        XROOTD_STREAM_METRIC_INC(mirror_divergence_total);

        if (mir->log_diverge) {
            ngx_log_error(NGX_LOG_NOTICE, mir->log, 0,
                "xrootd stream mirror divergence: op=%d "
                "primary_rc=%d shadow_kxr=%d",
                (int) mir->saved_opcode, (int) mir->primary_rc,
                (int) shadow_status);
        }
    } else {
        XROOTD_STREAM_METRIC_INC(mirror_stream_total);
    }

    xrootd_stream_mirror_finish(mir, 1);
}
```

### C5 — Integration point in dispatch.c

```c
ngx_int_t
xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_int_t rc;

    /* ... existing dispatch logic unchanged ... */

    rc = xrootd_dispatch_read_opcode(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        xrootd_stream_mirror_maybe(ctx, c, conf, rc);   /* ← new */
        return rc;
    }

    /* Current source also observes/replays selected write paths behind
     * xrootd_mirror_writes; this original sketch predates that expansion. */
    rc = xrootd_dispatch_write_opcode(ctx, c, conf);
    if (rc != XROOTD_DISPATCH_CONTINUE) {
        return rc;
    }

    /* ... rest unchanged ... */
}
```

Note: `xrootd_stream_mirror_maybe()` is a no-op when mirroring is disabled
(`conf->mirror.enabled == 0`) — zero overhead on the hot path.

---

## Step D — Memory Safety Invariant

The stream mirror context is allocated from `cycle->pool`, not from the client
connection pool. This is mandatory because:

1. The primary client connection may close before the mirror connection finishes.
2. The client pool is destroyed on `ngx_close_connection()`.
3. The mirror must outlive the client.

`cycle->pool` is only freed on nginx reload/shutdown. Mirror contexts are small
(~2 KiB each) and short-lived (seconds), so pool fragmentation is not a concern at
production traffic volumes. The `ngx_pfree(cycle->pool, mir)` call in
`xrootd_stream_mirror_finish()` returns the memory promptly.

The `mir->log` pointer is also snapshotted from `c->log` at launch time. If the
connection closes, the log object itself (owned by `c->pool`) becomes invalid.
To avoid use-after-free, use `cycle->log` instead:

```c
mir->log = cycle->log;   /* safe: lives for the duration of the process */
```

---

## Step E — Multi-Target Support

When `xrootd_mirror_url` appears multiple times:

**HTTP surface**: Each target gets its own internal location index and its own
background subrequest. All subrequests fire in the same event-loop cycle. Each is
independent — a failure on target 0 does not prevent target 1 from being attempted.

**Stream surface**: For each target in `conf->mirror.targets[]`, `xrootd_stream_mirror_maybe()`
loops and calls `xrootd_stream_mirror_start()` for each. Each gets its own
`xrootd_stream_mirror_t` context. The targets connect concurrently within the event
loop.

---

## Step F — Metrics

> **Status: ✅ done — exported names differ.** The 8 counter fields exist
> (`metrics.h:496-503`), but they are exposed as **shared metric names with a
> `surface="http"|"stream"` label** (`xrootd_mirror_requests_total`,
> `xrootd_mirror_dropped_total`, `xrootd_mirror_divergence_total`, …) from
> `src/observability/metrics/stream.c`, **not** the per-surface `xrootd_webdav_mirror_*` /
> `xrootd_stream_mirror_*` names listed below. Update Prometheus queries/alerts to
> use `{surface="…"}` selectors accordingly.

**File:** `src/observability/metrics/metrics.h` (extend), `src/observability/metrics/stream.c` and
`src/observability/metrics/webdav.c` (add counter increments)

```c
/* WebDAV mirror counters (add to ngx_xrootd_webdav_metrics_t) */
ngx_atomic_t  mirror_http_total;           /* shadow responded (any status) */
ngx_atomic_t  mirror_http_errors_total;    /* shadow connect/protocol failed */
ngx_atomic_t  mirror_dropped_total;        /* sampling filter skip */
ngx_atomic_t  mirror_divergence_total;     /* shadow status class != primary */

/* Stream mirror counters (add to ngx_xrootd_srv_metrics_t) */
ngx_atomic_t  mirror_stream_total;
ngx_atomic_t  mirror_stream_errors_total;
ngx_atomic_t  mirror_stream_dropped_total;
ngx_atomic_t  mirror_stream_divergence_total;
```

Prometheus exposition:

```
xrootd_webdav_mirror_requests_total         N
xrootd_webdav_mirror_errors_total           N
xrootd_webdav_mirror_dropped_total          N
xrootd_webdav_mirror_divergence_total       N
xrootd_stream_mirror_requests_total         N
xrootd_stream_mirror_errors_total           N
xrootd_stream_mirror_dropped_total          N
xrootd_stream_mirror_divergence_total       N
```

`mirror_divergence_total` is the primary operational signal. Set up a Prometheus
alert: `rate(xrootd_webdav_mirror_divergence_total[5m]) > 0` triggers when the
shadow backend starts behaving differently from production.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/net/mirror/mirror.h` | **New** | Shared config types, sampling helper, method/opcode masks |
| `src/net/mirror/http_mirror.h` | **New** | HTTP mirror context type; `xrootd_http_mirror_handler` declaration |
| `src/net/mirror/http_mirror.c` | **New** | PRECONTENT handler; subrequest launcher; mirror proxy handler; divergence tracking |
| `src/net/mirror/stream_mirror.h` | **New** | `xrootd_stream_mirror_t`; `xrootd_stream_mirror_maybe()` |
| `src/net/mirror/stream_mirror.c` | **New** | Bootstrap state machine; request replay; response discard; divergence check |
| `src/protocols/root/handshake/dispatch.c` | Modify | Call `xrootd_stream_mirror_maybe()` after read opcode dispatch |
| `src/protocols/webdav/postconfig.c` | Modify | Register `xrootd_http_mirror_handler` in PRECONTENT phase; create internal locations |
| `src/protocols/webdav/webdav.h` | Modify | Add `xrootd_mirror_conf_t mirror` to `ngx_http_xrootd_webdav_loc_conf_t`; add `mirror_fired`, `primary_status` to req ctx |
| `src/core/config/directives.c` | Modify | Register `xrootd_mirror_url`, `xrootd_mirror_sample`, `xrootd_mirror_methods`, etc. |
| `src/core/types/config.h` | Modify | Add `xrootd_mirror_conf_t mirror` to `ngx_stream_xrootd_srv_conf_t` |
| `src/observability/metrics/metrics.h` | Modify | Add 8 mirror counter fields |
| `src/observability/metrics/webdav.c` | Modify | Expose 4 HTTP mirror counters in Prometheus output |
| `src/observability/metrics/stream.c` | Modify | Expose 4 stream mirror counters |
| `src/core/config/config.h` | Modify | Add `http_mirror.c`, `stream_mirror.c` to `NGX_ADDON_SRCS` |

---

## Build Registration

Add to `NGX_ADDON_SRCS` in `src/core/config/config.h`:
- `$ngx_addon_dir/src/net/mirror/http_mirror.c`
- `$ngx_addon_dir/src/net/mirror/stream_mirror.c`

Run `./configure` once to pick up new source files, then `make -j$(nproc)` for all
subsequent changes.

---

## Testing Requirements

3 tests per area (success + error + security-neg per CLAUDE.md):

### Step B (HTTP WebDAV mirror)
- `test_a_webdav_clients.py::TestMirror::test_get_fires_shadow_request` — GET to primary also reaches shadow backend (verified via shadow access log or dedicated shadow counter endpoint)
- `test_a_webdav_clients.py::TestMirror::test_shadow_failure_transparent` — shadow backend down → primary GET still returns 200 (shadow error not visible to client)
- `test_a_webdav_clients.py::TestMirror::test_auth_stripped_from_shadow` — shadow request does not carry `Authorization` header from primary when `mirror_strip_auth on`

### Step C (XRootD stream mirror)
- `test_a_robustness.py::TestStreamMirror::test_stat_mirrored_to_shadow` — kXR_stat on primary also issues kXR_stat to shadow XRootD server
- `test_a_robustness.py::TestStreamMirror::test_mirror_does_not_delay_client` — response time for primary stat is not affected by shadow connection timeout
- `test_a_robustness.py::TestStreamMirror::test_shadow_kxr_notfound_increments_divergence` — shadow returns kXR_NotFound where primary returns kXR_ok → `mirror_stream_divergence_total` increments

### Sampling
- `test_conformance.py::TestMirrorSampling::test_sample_100pct_mirrors_all` — `mirror_sample 100` → every request mirrored
- `test_conformance.py::TestMirrorSampling::test_sample_0pct_mirrors_none` — `mirror_sample 0` → no mirror traffic
- `test_conformance.py::TestMirrorSampling::test_write_not_mirrored_by_default` — PUT never reaches shadow unless `mirror_methods` explicitly includes `PUT`

---

## Interaction with Other Phases

| Phase | Interaction |
|---|---|
| Phase 21 (Subrequests) | HTTP mirror uses the same `ngx_http_subrequest()` + `NGX_HTTP_SUBREQUEST_BACKGROUND` pattern. The `r->preserve_body = 1` flag is also used in Phase 21's introspect subrequest — both can coexist since `preserve_body` is a boolean. |
| Phase 22 (Health checks) | Stream mirror bootstrap state machine is structurally identical to `xrootd_hc_ctx_t`. Both allocate from `cycle->pool` and use `ngx_event_t timeout_ev`. Consider extracting `xrootd_bootstrap_ctx_t` as a shared base type. |
| Phase 23 (Dynamic upstreams) | Mirror targets can be backed by the Phase 23 dynamic backend pool. The `xrootd_mirror_conf_t` target list can reference `xrootd_proxy_be_entry_t` entries from the pool — runtime-switchable shadow backends without reload. |
| Phase 24 (this phase) | The `primary_status` comparison requires that the content handler sets `ctx->primary_status` before returning. This is a clean hook: each WebDAV handler sets the wctx field, and the mirror's `finalize_request` reads it from the parent request. |

---

## Operational Configuration Example

```nginx
# Production WebDAV location
location /data {
    xrootd_webdav on;
    xrootd_root /srv/xrootd;

    # Mirror 5% of reads to shadow cluster for cache validation
    xrootd_mirror_url     https://shadow-cache.example.org:8443;
    xrootd_mirror_sample  5;
    xrootd_mirror_methods GET HEAD PROPFIND;
    xrootd_mirror_strip_auth  on;    # shadow uses anon or its own token
    xrootd_mirror_log_diverge on;
    xrootd_mirror_timeout 3s;        # give up on shadow quickly
}

stream {
    server {
        listen 1094;
        xrootd_enable on;

        # Mirror all stat/locate to shadow XRootD for protocol upgrade test
        xrootd_stream_mirror_url  shadow-xrd.example.org:21094;
        xrootd_mirror_sample      10;
        xrootd_mirror_opcodes     stat locate dirlist;
        xrootd_mirror_log_diverge on;
        xrootd_mirror_timeout     3s;
    }
}
```

```nginx
# Prometheus alert for divergence detection
- alert: XrootdMirrorDivergence
  expr: rate(xrootd_webdav_mirror_divergence_total[5m]) > 0.01
  annotations:
    summary: "Shadow backend returning different status class than production"
```
