# Phase 21 — Nginx Subrequests & Upstream Filters

**Status:** ✅ Implemented (as-built diverges from this plan — see status section)  
**Depends on:** Phase 18 (auth-gate), Phase 20 (SHM/KV cache)  
**Touches:** `src/protocols/webdav/`, `src/core/compat/`, `src/auth/token/`  
**Net LoC:** +~720 new, -~140 scattered call-site injections = +~580 net

---

## Implementation status (as-built — reconciled 2026-06-13)

Audited against the code under `src/`. **All four capabilities shipped** — the
XrdHttp header/body filters, the OIDC introspection subrequest, and the
multi-backend WebDAV proxy are implemented and wired. The implementation diverges
from this plan in several places; in two of them (the filter module, the directive
namespace) the as-built choice is **better** than the original design.

| Step | Capability | Status | Evidence / divergence |
|------|-----------|--------|-----------------------|
| **A** | Fix XrdHttp header filter | ✅ **Done — different mechanism** | Implemented as a **separate `HTTP_AUX_FILTER` module** `ngx_http_xrootd_xrdhttp_filter_module` (`src/protocols/webdav/xrdhttp_filter.c`; registered in `config` as `ngx_module_type=HTTP_AUX_FILTER`, lines ~601-608), **not** via the webdav module's `preconfiguration` as this plan proposed. The aux-filter module is placed by `auto/modules` *after* the core header/write filters, so it chains correctly — the file's header comment explains why the preconfiguration approach in Step A would still have been clobbered. The old `xrdhttp_register_header_filter()` no-op stub was **removed** (no references remain). |
| **B** | Body filter for `Digest: adler32` | ✅ **Done** | `xrdhttp_body_filter` in `xrdhttp_filter.c` → `xrdhttp_digest_body_filter()` in `src/protocols/webdav/xrdhttp.c`; accumulates adler32 over output bufs and queues a `Digest: adler32=<hex>` trailer. Req-ctx flags `compute_digest`/`digest_emitted`/`adler` in `xrdhttp.h`. No separate `src/core/compat/digest_trailer.h` — logic lives in `xrdhttp.c`. |
| **C** | OIDC introspection subrequest | ✅ **Done — different location & directive names** | Implemented in **`src/protocols/webdav/introspect.c`** (registered at `config:592`), **not** `src/auth/token/introspect.c`. Real `ngx_http_subrequest()` is used; runs as a *second* `NGX_HTTP_ACCESS_PHASE` handler (`src/protocols/webdav/postconfig.c`) so suspend/resume re-entry replays only the introspection check. Directives are **`xrootd_webdav_token_introspect_{url,loc,ttl,fail_open}`** (webdav-prefixed; the plan wrote `xrootd_token_introspect_*`). Revoked-token negative results cached in a Phase-20 KV zone via `conf->revoke_kv`; fail-open configurable. |
| **D** | Multi-backend WebDAV proxy | ✅ **Done — simple RR, not weighted** | `upstream_backends` (`ngx_array_t` of `xrootd_webdav_backend_t`, `src/protocols/webdav/proxy_internal.h`) replaces the single resolved address; `webdav_proxy_pick_backend()` (`src/protocols/webdav/proxy.c`) does round-robin with passive health skip; `webdav_proxy_build_backends()` (`proxy_config.c`) parses multiple space/comma-separated URLs. Directives `xrootd_webdav_proxy_max_fails` (default 3) and `xrootd_webdav_proxy_fail_timeout` (default 30s) exist. **No `weight=` field** — selection is plain round-robin, not weighted as the plan sketched. Per-backend TLS (`ssl`/`ssl_ctx`) was added beyond the plan. |
| **E** | Phase-20 KV for proxy state | ⚠️ **Diverged — per-worker, not KV** | The round-robin cursor (`upstream_rr`, an `ngx_atomic_t` in the loc conf) and per-backend `fail_count`/`fail_time` live **per-worker in the config pool**, not in a Phase-20 KV/SHM zone as Step E proposed. Adequate for best-effort load distribution (the plan itself allows approximate cross-worker counts). The introspection revocation cache *does* use a Phase-20 KV zone (Step C). |

### As-built divergences (none are defects)

1. **Filters are a standalone `HTTP_AUX_FILTER` module, not webdav-preconfiguration.**
   This is the *correct* nginx idiom and is what actually survives core-module
   filter registration; treat Step A's preconfiguration recipe as superseded.
2. **Introspection lives in `src/protocols/webdav/`, not `src/auth/token/`,** with
   `xrootd_webdav_*`-namespaced directives, and runs as a dedicated access-phase
   handler rather than being inlined into `dispatch.c`.
3. **Multi-backend RR is unweighted** and **state is per-worker**, not the
   Phase-20 KV zone of Step E.
4. **Phase-23 dynamic upstream pool is a separate feature** (`proxy_pool.c`,
   runtime add/remove via REST + SHM). It is *not* this phase's static
   multi-backend list — `proxy.c` branches between them. See
   `phase-23-dynamic-upstreams.md`.

### Pending / not done

- **Step E (KV-backed proxy state):** not implemented — superseded by the simpler
  per-worker model. Recommend marking **won't-do** unless cross-worker health
  consensus is later required.
- **Weighted round-robin** (`weight=` token): not implemented; plain RR ships.
- **`src/core/compat/digest_trailer.h`:** never created; the Digest logic is in
  `xrdhttp.c` instead (no separate header needed).

---

## Motivation

Three independent problems share a common root: the module reaches outside nginx's
standard processing pipeline at individual call sites rather than integrating cleanly
with the filter chain and subrequest machinery.

1. **Header injection is scattered.** `xrdhttp_add_response_headers()` and
   `xrdhttp_add_checksum_header()` are called manually at ~12 call sites across
   `get.c`, `put.c`, `multipart.c`, and others. If a new handler forgets the call,
   the response silently lacks XrdHttp headers. A registered body filter would make
   this automatic.

2. **Header filter registration is broken.** `xrdhttp_register_header_filter()` in
   `src/protocols/webdav/xrdhttp.c:638` is a no-op stub because `ngx_http_header_filter_module`
   overwrites `ngx_http_top_header_filter` during its own `postconfiguration`, which
   runs after the webdav module's `postconfiguration`. The fix is to register in
   `preconfiguration`, which runs before any module's `postconfiguration`.

3. **Token revocation has no real-time path.** The JWT validation path in
   `src/auth/token/validate.c` relies on expiry time only. Revoked tokens remain valid
   until expiry. An OIDC `/introspect` subrequest would allow real-time revocation
   checking against the IdP without blocking the event loop.

4. **WebDAV proxy supports only a single upstream.** `src/protocols/webdav/proxy.c` copies
   `conf->upstream_resolved` (a single `ngx_http_upstream_resolved_t`) into each
   request. Adding a backend array with round-robin selection and passive health
   tracking would allow high-availability proxy deployments.

---

## Current State

> **Historical (pre-Phase-21).** Every row below has since been addressed — the
> header/body filters fire via the `HTTP_AUX_FILTER` module, `ngx_http_subrequest()`
> is used by the introspection path, and the proxy supports a backend array. See
> the *Implementation status* section above for the as-built picture.

| Mechanism | Current status |
|---|---|
| `ngx_http_top_header_filter` | No-op stub — hook overwrites itself because postconfiguration ordering conflict |
| `ngx_http_top_body_filter` | Not used — no body filter registered anywhere in module |
| `ngx_http_subrequest()` | Not used — zero calls anywhere in module |
| XrdHttp header injection | Manual at ~12 call sites in webdav handlers |
| Token revocation | Not checked — JWT expiry only |
| WebDAV proxy backends | Single pre-resolved address in `conf->upstream_resolved` |

### Why the header filter broke

`ngx_http_header_filter_module` is a core nginx module. Its `postconfiguration` hook
executes after all add-on module `postconfiguration` hooks because core modules are
sorted first. Inside that hook, the core module assigns:

```c
ngx_http_top_header_filter = ngx_http_header_filter;
```

This overwrites whatever the webdav module placed in `ngx_http_top_header_filter`
during its own `postconfiguration`. The fix: register the filter in the webdav
module's `preconfiguration` hook instead. At `preconfiguration` time, the chain
pointer is `NULL`; after `postconfiguration` completes, it starts with the last
registered module (LIFO). Because `preconfiguration` runs before any
`postconfiguration`, our filter node will be at the **end** of the chain —
meaning it fires last, after the core module has already written headers. This is
exactly what we want: inject XrdHttp headers just before the final send.

---

## Step A — Fix Header Filter Registration

> **Status: ✅ done, but via a different (better) mechanism — the recipe below is
> superseded.** Instead of registering in the webdav module's `preconfiguration`,
> the filters live in a standalone `HTTP_AUX_FILTER` module
> (`src/protocols/webdav/xrdhttp_filter.c`, `ngx_http_xrootd_xrdhttp_filter_module`). The
> aux-filter module is ordered after the core header/write filters by
> `auto/modules`, so it chains correctly without the preconfiguration trick. The
> `xrdhttp_register_header_filter()` stub was removed. The A1–A4 details below are
> retained for design context only.

**Files:** `src/protocols/webdav/xrdhttp.c`, `src/protocols/webdav/xrdhttp.h`, `src/protocols/webdav/module.c`

### A1 — Module-level filter pointers

In `src/protocols/webdav/xrdhttp.c`, declare two static pointers below the include block:

```c
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
```

### A2 — Header filter function

```c
static ngx_int_t
xrdhttp_header_filter(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf == NULL || !conf->xrdhttp_headers) {
        return ngx_http_next_header_filter(r);
    }

    /* Inject X-XRootD-Status, X-XRootD-TProtocol, OpaqueDest headers if the
     * per-request context marks this as an XrdHttp response. The ctx flag is set
     * by dispatch.c when the incoming request carried an XrdHttp marker. */
    ngx_http_xrootd_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (wctx != NULL && wctx->is_xrdhttp) {
        xrdhttp_add_response_headers(r, r->headers_out.status);
    }

    return ngx_http_next_header_filter(r);
}
```

### A3 — Register in preconfiguration (not postconfiguration)

In `src/protocols/webdav/module.c`, the `ngx_http_module_t` struct currently has
`xrdhttp_register_header_filter` wired to `postconfiguration`. Move it to
`preconfiguration`:

```c
static ngx_int_t
webdav_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = xrdhttp_header_filter;
    return NGX_OK;
}
```

```c
static ngx_http_module_t webdav_module_ctx = {
    webdav_preconfiguration,   /* preconfiguration  ← changed */
    webdav_postconfiguration,  /* postconfiguration */
    ...
};
```

Because `preconfiguration` fires before any `postconfiguration`, the core module's
`ngx_http_header_filter_module` will register its own filter *after* ours. In LIFO
order this means the core filter fires first, then ours fires last — at the point
where the socket write is about to happen. XrdHttp headers will be present in every
response routed through the webdav location.

### A4 — Call-site cleanup

Remove the manual `xrdhttp_add_response_headers(r, r->headers_out.status)` calls
from the following files; the filter now handles injection automatically:

- `src/protocols/webdav/get.c` — `webdav_get_add_xrdhttp_headers()` callback (keep
  `xrdhttp_add_checksum_header`; move status header to filter)
- `src/protocols/webdav/put.c`
- `src/protocols/webdav/namespace.c`
- `src/protocols/webdav/methods_basic.c`

The `xrdhttp_add_checksum_header()` call requires an open `fd` and `struct stat`,
so it cannot be moved into the filter (no `fd` access at filter time). Leave it at
call sites. Only the `xrdhttp_add_response_headers()` status/protocol header calls
are automatable.

**Test:** `tests/test_a_webdav_clients.py::TestXrdHttpHeaders` — existing suite
verifies header presence; the filter change should be transparent.

---

## Step B — Body Filter for Digest Header Injection

**Files:** `src/protocols/webdav/xrdhttp.c`, `src/core/compat/digest_trailer.h` (new)

XrdHttp clients expect a `Digest: adler32=<hex>` trailing header on GET responses.
Currently the adler32 is computed per-chunk in `xrdhttp_multipart.c` but the final
response Digest header is only added in the multipart path. Single-range GET omits
it.

### B1 — Body filter

```c
static ngx_int_t
xrdhttp_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_xrootd_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (wctx == NULL || !wctx->is_xrdhttp || !wctx->compute_digest) {
        return ngx_http_next_body_filter(r, in);
    }

    /* Accumulate adler32 over each output buf in the chain */
    ngx_chain_t *cl;
    for (cl = in; cl != NULL; cl = cl->next) {
        if (cl->buf->pos < cl->buf->last) {
            wctx->adler = xrootd_adler32_update(wctx->adler,
                cl->buf->pos, cl->buf->last - cl->buf->pos);
        }
    }

    return ngx_http_next_body_filter(r, in);
}
```

Register in the same `webdav_preconfiguration`:

```c
ngx_http_next_body_filter = ngx_http_top_body_filter;
ngx_http_top_body_filter  = xrdhttp_body_filter;
```

The `wctx->compute_digest` flag is set by `get.c` when the `XrdHttp-Want-Digest`
request header is present. `wctx->adler` starts at `1` (adler32 identity). After
the last buf is sent (checked via `last_buf`), a separate trailer subrequest or
chunked trailer mechanism delivers the final value. For HTTP/1.1 connections without
trailer support, the Digest is instead injected into the response headers before
the first output filter call (setting `r->headers_out.content_length_n = -1` to
force chunked, then appending a trailer).

**Note:** HTTP trailers require `Transfer-Encoding: chunked`. For TLS+HTTP/1.1,
set `r->chunked = 1` and use `ngx_http_trailer_add()`. For HTTP/2 and HTTP/3, use
the headers frame on the EOS DATA frame — nginx handles this automatically when
`r->headers_out.trailers` is populated before the final output filter call.

---

## Step C — OIDC Token Introspection Subrequest

> **Status: ✅ done — implemented under `src/protocols/webdav/`, not `src/auth/token/`.** The code
> is in **`src/protocols/webdav/introspect.c`** (registered at `config:592`) and runs as a
> dedicated second `NGX_HTTP_ACCESS_PHASE` handler (`src/protocols/webdav/postconfig.c`),
> not inlined into `dispatch.c`. Directives are namespaced
> **`xrootd_webdav_token_introspect_{url,loc,ttl,fail_open}`** (the names below
> omit the `webdav` prefix). Real `ngx_http_subrequest()` is used and the revoked
> result is cached in a Phase-20 KV zone (`conf->revoke_kv`). The C1–C5 design
> below is accurate in approach; only the file paths and directive names differ.

**Files (as-built):** `src/protocols/webdav/introspect.c`, `src/protocols/webdav/postconfig.c`,
`src/protocols/webdav/module.c` (directives), `src/protocols/webdav/webdav.h` (ctx flags)  
**Files (as planned):** `src/auth/token/introspect.c` (new), `src/auth/token/introspect.h` (new),
`src/auth/token/validate.c`, `src/protocols/webdav/dispatch.c`

### C1 — Concept

`ngx_http_subrequest()` creates a child request to an internal nginx location that
proxies to an OIDC `/introspect` endpoint. The parent request suspends until the
subrequest completes, then the parent's handler resumes via a `post_subrequest`
callback. This is fully non-blocking — the event loop continues serving other
requests while waiting for the IdP response.

### C2 — Configuration

New nginx directives (registered in `src/protocols/webdav/module.c`):

```nginx
xrootd_token_introspect_url  https://iam.example.org/introspect;
xrootd_token_introspect_loc  /internal/oidc_introspect;  # internal location name
xrootd_token_introspect_ttl  30s;   # negative-result cache TTL
```

Add a synthetic internal location in `postconfig` that proxies to the IdP:

```nginx
location = /internal/oidc_introspect {
    internal;
    proxy_pass  https://iam.example.org/introspect;
    proxy_method POST;
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_pass_request_body on;
}
```

This location is created programmatically via `ngx_http_conf_ctx_t` cloning during
`postconfiguration` — the same technique nginx's `auth_request` module uses.

### C3 — Subrequest call

In `src/auth/token/introspect.c`:

```c
ngx_int_t
xrootd_token_introspect(ngx_http_request_t *r,
    const ngx_str_t *raw_token,
    ngx_http_post_subrequest_t *cb)
{
    ngx_http_request_t  *sr;
    ngx_str_t            uri;
    ngx_str_t            args;
    ngx_uint_t           flags;

    /* Body: "token=<raw_token>" — written into a temp buf attached to the
     * subrequest pool so it doesn't outlive the child request lifetime. */
    ngx_http_request_body_t *rb = /* allocate + fill body buf */;

    ngx_str_set(&uri, "/internal/oidc_introspect");
    ngx_str_null(&args);
    flags = NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY;

    if (ngx_http_subrequest(r, &uri, &args, &sr, cb, flags) != NGX_OK) {
        return NGX_ERROR;
    }

    sr->request_body = rb;
    sr->method       = NGX_HTTP_POST;
    sr->method_name  = ngx_string("POST");

    return NGX_AGAIN;  /* caller must return NGX_DONE to suspend parent */
}
```

### C4 — Post-subrequest callback

```c
static ngx_int_t
xrootd_introspect_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc)
{
    xrootd_introspect_ctx_t *ctx = data;
    ngx_http_request_t      *sr  = r->parent ? r : r;   /* child request */

    if (rc != NGX_OK || sr->upstream == NULL) {
        ctx->active = 0;  /* treat introspect failure as allowed (fail-open) */
        return NGX_OK;
    }

    /* Parse JSON response: {"active": true/false} */
    ngx_buf_t *b = &sr->upstream->buffer;
    ctx->active = xrootd_introspect_parse_active(b->pos, b->last - b->pos);

    /* Cache negative result in Phase-20 KV zone keyed by SHA-256(token)[0:32] */
    if (!ctx->active) {
        xrootd_kv_set(&g_revoke_zone, ctx->token_hash, 32,
                      (uint8_t *)"0", 1, ngx_time() + ctx->ttl);
    }

    return NGX_OK;
}
```

### C5 — Integration point in dispatch.c

```c
/* After JWT signature verification passes and before routing to handler: */
if (conf->introspect_url.len > 0) {
    /* Fast path: revocation cache hit */
    uint8_t  rkey[32];
    uint8_t  rval[4];
    size_t   rval_len;
    xrootd_token_sha256(raw_token, rkey);
    if (xrootd_kv_get(&g_revoke_zone, rkey, 32, rval, &rval_len) == NGX_OK
        && rval[0] == '0')
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* Slow path: fire introspect subrequest */
    ngx_http_post_subrequest_t *cb = ngx_palloc(r->pool, sizeof(*cb));
    cb->handler = xrootd_introspect_done;
    cb->data    = ctx;
    rc = xrootd_token_introspect(r, &raw_token, cb);
    if (rc == NGX_AGAIN) return NGX_DONE;  /* suspend parent */
}
```

**Failure mode:** If the IdP is unreachable (`rc != NGX_OK`), the callback sets
`ctx->active = 0` which falls through to `active` (fail-open). This is configurable
via `xrootd_token_introspect_fail_open on|off` directive. Most HEP deployments
prefer fail-open to avoid outage propagation from a central IdP; WLCG policy requires
this for bearer tokens.

**Interaction with Phase 20 KV cache:** The revocation cache lives in a named KV zone
(`xrootd_kv_zone revoke 1m key=32 val=1;`) defined in Phase 20. Positive results
(active=true) are not cached — only negative results (revoked tokens) are cached for
`introspect_ttl` seconds. This ensures revocation propagates quickly while avoiding
per-request IdP round-trips for valid tokens (Phase 20's token validation cache
handles those).

---

## Step D — Multi-Backend WebDAV Proxy

**Files:** `src/protocols/webdav/proxy_config.c`, `src/protocols/webdav/proxy.c`,
`src/protocols/webdav/proxy_internal.h`, `src/protocols/webdav/webdav.h`

### D1 — Configuration change

Replace the single `upstream_resolved` pointer in `ngx_http_xrootd_webdav_loc_conf_t`
with an array:

```c
/* webdav.h — existing field */
- ngx_http_upstream_resolved_t   *upstream_resolved;
+ ngx_array_t                    *upstream_backends;  /* array of backend_entry_t */
+ ngx_atomic_t                   *upstream_rr_index;  /* shared RR counter in SHM */
```

New type in `proxy_internal.h`:

```c
typedef struct {
    ngx_http_upstream_resolved_t  resolved;
    ngx_str_t                     host;        /* for Host: header */
    ngx_str_t                     url_base;    /* for request line */
    ngx_uint_t                    weight;
    ngx_uint_t                    fail_count;  /* passive health: consecutive failures */
    ngx_msec_t                    fail_time;   /* time of last failure */
    ngx_uint_t                    max_fails;
    ngx_msec_t                    fail_timeout;
} xrootd_webdav_backend_t;
```

### D2 — Directive syntax change

```nginx
# Before (single backend):
xrootd_webdav_proxy_url  https://backend.example.org:8080;

# After (multiple backends — comma-separated, same directive):
xrootd_webdav_proxy_url  https://be1.example.org:8080
                         https://be2.example.org:8080 weight=2
                         https://be3.example.org:8080;
```

The directive handler parses each URL token into a `xrootd_webdav_backend_t` and
appends to `conf->upstream_backends` (allocated via `ngx_array_create`). Single-URL
form remains backward-compatible.

### D3 — Round-robin selection in proxy.c

```c
static xrootd_webdav_backend_t *
webdav_proxy_pick_backend(ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_log_t *log)
{
    ngx_uint_t              i, n, idx;
    xrootd_webdav_backend_t *be;
    ngx_msec_t               now;

    n   = conf->upstream_backends->nelts;
    be  = conf->upstream_backends->elts;
    now = ngx_current_msec;

    /* Weighted round-robin: try up to n backends starting from rr_index */
    for (i = 0; i < n; i++) {
        idx = ngx_atomic_fetch_add(conf->upstream_rr_index, 1) % n;
        xrootd_webdav_backend_t *b = &be[idx];

        /* Skip if in fail_timeout window and fail_count >= max_fails */
        if (b->max_fails > 0
            && b->fail_count >= b->max_fails
            && (now - b->fail_time) < b->fail_timeout)
        {
            continue;
        }

        return b;
    }

    /* All backends marked failed — return first anyway (circuit-breaker open) */
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "webdav proxy: all backends failed, using backend[0]");
    return &be[0];
}
```

`conf->upstream_rr_index` points into a `ngx_atomic_t` allocated in a small
dedicated SHM zone (`ngx_shared_memory_add`) so the counter is shared across nginx
workers. Size: one `ngx_atomic_t` per proxy location — negligible.

### D4 — Passive health tracking

In `webdav_proxy_finalize_request()` (already exists in `proxy.c`):

```c
static void
webdav_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    webdav_proxy_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    xrootd_webdav_backend_t *be = ctx->selected_backend;

    if (be == NULL) return;

    if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT
        || rc == NGX_HTTP_SERVICE_UNAVAILABLE)
    {
        ngx_atomic_fetch_add(&be->fail_count, 1);
        be->fail_time = ngx_current_msec;
    } else {
        /* Reset on success */
        if (be->fail_count > 0) {
            ngx_atomic_t prev = ngx_atomic_fetch_add(&be->fail_count, -1);
            if (prev == 0) be->fail_count = 0;  /* guard underflow */
        }
    }
}
```

`fail_count` and `fail_time` live in the `xrootd_webdav_backend_t` structs which are
in the per-process config pool. For shared passive health state across workers,
allocate the counter array in the same SHM zone as `upstream_rr_index`.

### D5 — Directive defaults

```nginx
xrootd_webdav_proxy_max_fails   3;    # mark backend down after 3 consecutive errors
xrootd_webdav_proxy_fail_timeout 30s; # retry down backend after 30 seconds
```

---

## Step E — Integration with Phase 20 Upstream Resolution Cache

> **Status: ⚠️ NOT implemented (won't-do as written).** The round-robin cursor and
> per-backend `fail_count`/`fail_time` are kept **per-worker** in the WebDAV loc
> conf (`upstream_rr` is an `ngx_atomic_t`; counters live in the backend structs),
> not in a Phase-20 KV/SHM zone. This is adequate for best-effort distribution and
> avoids a shared-memory dependency on the proxy hot path. Only the introspection
> revocation cache (Step C) uses a Phase-20 KV zone. The KV-backed proxy-state
> design below was not adopted.

Phase 20 introduces `src/core/shm/kv.h`. The multi-backend round-robin counter
(`upstream_rr_index`) and passive health counters (`fail_count`) can live in a
dedicated Phase-20 KV zone rather than a raw `ngx_shared_memory_add()` call:

```nginx
xrootd_kv_zone  proxy_state  64k  key=8  val=16;
```

Key: 8-byte index (location ID). Value: `{rr_counter: u32, fail_counts: u32[3]}` —
fits in 16 bytes for up to 3 backends. For more than 3 backends, increase `val=`.

This replaces the dedicated SHM zone and keeps all shared state under the Phase-20
KV framework.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/protocols/webdav/xrdhttp.c` | Modify | Fix filter registration; add header + body filter functions |
| `src/protocols/webdav/xrdhttp.h` | Modify | Export new filter registration; add `compute_digest`, `adler` to req ctx |
| `src/protocols/webdav/module.c` | Modify | Wire preconfiguration hook; add `ngx_http_top_body_filter` registration |
| `src/protocols/webdav/get.c` | Modify | Remove manual `xrdhttp_add_response_headers` call; set `compute_digest` flag |
| `src/protocols/webdav/put.c` | Modify | Remove manual header injection call |
| `src/protocols/webdav/namespace.c` | Modify | Remove manual header injection calls |
| `src/protocols/webdav/methods_basic.c` | Modify | Remove manual header injection calls |
| `src/protocols/webdav/dispatch.c` | Modify | Add introspect subrequest call after JWT verify |
| `src/auth/token/introspect.c` | **New** | `xrootd_token_introspect()` subrequest setup; done callback |
| `src/auth/token/introspect.h` | **New** | Public API; `xrootd_introspect_ctx_t` type |
| `src/protocols/webdav/proxy.c` | Modify | Multi-backend selection; store `selected_backend` in ctx |
| `src/protocols/webdav/proxy_config.c` | Modify | Parse multiple URLs into `upstream_backends` array |
| `src/protocols/webdav/proxy_internal.h` | Modify | Add `xrootd_webdav_backend_t`; `selected_backend` in ctx |
| `src/protocols/webdav/webdav.h` | Modify | Replace `upstream_resolved` with `upstream_backends` + `upstream_rr_index` |

---

## Build Registration

`src/auth/token/introspect.c` must be added to `NGX_ADDON_SRCS` in `src/core/config/config.h`
before `./configure` is re-run. No new top-level config blocks are introduced, so
`./configure` only needs rerunning once to pick up the new source file.

---

## Testing Requirements

Per CLAUDE.md: 3 tests per change (success + error + security-neg).

### Step A (header filter fix)
- `test_a_webdav_clients.py::TestXrdHttpHeaders::test_get_has_xrdhttp_status` — 200 response carries `X-XRootD-Status`
- `test_a_webdav_clients.py::TestXrdHttpHeaders::test_non_xrdhttp_no_inject` — plain curl GET without XrdHttp marker gets no injected headers
- `test_a_webdav_clients.py::TestXrdHttpHeaders::test_put_has_xrdhttp_status` — PUT response also carries header

### Step B (body filter / Digest)
- `test_conformance.py::TestDigestHeader::test_get_digest_present` — `Digest: adler32=<hex>` present in GET response
- `test_conformance.py::TestDigestHeader::test_digest_value_correct` — computed adler32 matches file content
- `test_conformance.py::TestDigestHeader::test_no_digest_without_want_header` — Digest absent when `XrdHttp-Want-Digest` not sent

### Step C (introspect subrequest)
- `test_credential_translation.py::TestIntrospect::test_revoked_token_rejected` — revoked token returns 403
- `test_credential_translation.py::TestIntrospect::test_valid_token_allowed` — valid token passes through
- `test_credential_translation.py::TestIntrospect::test_idp_unreachable_failopen` — IdP down → request proceeds (fail-open)

### Step D (multi-backend proxy)
- `test_a_upstream_redirect.py::TestMultiBackend::test_round_robin_distributes` — requests spread across backends
- `test_a_upstream_redirect.py::TestMultiBackend::test_failed_backend_skipped` — down backend bypassed
- `test_a_upstream_redirect.py::TestMultiBackend::test_all_down_falls_back` — all down → returns 502 (not crash)

---

## Implementation Order

1. **Step A** first — fixes the broken header filter, unblocks cleanup in Steps A4
2. **Step B** — depends on Step A's `ngx_http_next_body_filter` pointer
3. **Step D** — independent of A/B/C; can be done in parallel with B
4. **Step C** last — depends on Phase 20 KV zone being available; can be stubbed
   with a simple HTTP proxy location and real subrequest machinery for Phase 22
   if Phase 20 is not yet merged

---

## Risk Notes

- **Filter registration ordering** is the most subtle part. The preconfiguration
  trick is documented in nginx's `auth_request` module source and is the standard
  pattern. Do not revert to postconfiguration registration.
- **Subrequest body allocation** must use the subrequest's pool, not the parent's.
  The child pool is destroyed when `post_subrequest` returns.
- **`NGX_HTTP_SUBREQUEST_IN_MEMORY`** is essential — without it, nginx will try to
  send the subrequest response to the client connection.
- **`fail_count` races:** Two workers can increment simultaneously. Using
  `ngx_atomic_fetch_add` prevents torn reads but doesn't prevent double-counting.
  This is acceptable for passive health (approximate counts are fine; exact counting
  requires a mutex that would hurt throughput).
