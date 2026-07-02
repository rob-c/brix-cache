# Phase 23 — Dynamic Upstreams

**Status:** ✅ Implemented (one security item pending — see status section)  
**Depends on:** Phase 22 (health checks) recommended but not required  
**Touches:** `src/observability/dashboard/`, `src/net/manager/`, `src/protocols/webdav/`  
**Net LoC:** +~920 new, ~60 modified

---

## Implementation status (as-built — reconciled 2026-06-13)

Audited against the code under `src/`. **Both surfaces shipped**: the REST admin
write API (`/xrootd/api/v1/admin/...`) for the stream cluster registry and a
dynamic SHM-backed WebDAV proxy backend pool with drain support. The two new
source files exist and are registered. The main gap vs. the plan is the admin-API
**rate limiting** (Security Design), which is not implemented.

| Step | Capability | Status | Evidence / divergence |
|------|-----------|--------|-----------------------|
| **A** | Admin auth layer | ✅ **Done** | `xrootd_admin_check_auth()` (`api_admin.c:167`) — CIDR allowlist and/or bearer secret, with `xrootd_admin_require_both`. Directives `xrootd_admin_allow` / `xrootd_admin_secret` / `xrootd_admin_require_both` registered in `src/observability/dashboard/module.c`. The `XROOTD_ADMIN_AUTH_METHOD_NOT_ALLOWED` enum value was dropped — only `OK`/`DENIED`. |
| **B** | Async body reader | ✅ **Done** | `xrootd_admin_read_body()` (`api_admin.c:293`) coalesces the body, parses JSON (jansson), dispatches to a handler. |
| **C** | Cluster registry endpoints | ✅ **Done** | `admin_cluster_register` (POST/PUT upsert), `admin_cluster_drain`, DELETE, and `xrootd_srv_undrain()` (`registry.c:591`, declared `registry.h:89`). Host/path whitelist validation present. |
| **D** | WebDAV proxy backend pool | ✅ **Done** | `src/protocols/webdav/proxy_pool.{c,h}` — SHM table of `xrootd_proxy_be_entry_t`, `xrootd_proxy_pool_add/remove/drain/undrain/select/snapshot` + atomic `in_flight`. `proxy.c:50-87` selects from the pool when `proxy_pool_enabled` and reserves `in_flight`; `proxy_response.c:192` releases it in finalize. `select()` signature differs (`xrootd_proxy_pool_select(xrootd_proxy_be_pick_t *out)` returning `ngx_int_t`, not returning an entry pointer). |
| **E** | Proxy backend endpoints | ✅ **Done** | `admin_proxy_add` + `/admin/proxy/backends[/{id}[/drain\|/undrain]]` routing (`api_admin.c:842-853`). Drain workflow backed by the `in_flight` counter (`xrootd_proxy_pool_in_flight()`). |
| **F** | Dispatch routing | ✅ **Done** | `xrootd_admin_dispatch()` (`api_admin.c:798`) auth-checks then routes by method + URI; reached from the dashboard handler for `/xrootd/api/v1/admin/` URIs. Structured audit log line emitted per write (`api_admin.c:213`: `xrootd: admin: %V %s target=%s client=%V result=%s`). |
| **G** | Dashboard GET extension | ✅ **Done (partial)** | The cluster snapshot gained the `"draining"` field (`api.c:715`). Proxy-pool state is exposed via the snapshot/admin path rather than a separate no-auth `/xrootd/api/v1/proxy/backends` read endpoint. |

### As-built divergences (not defects)

1. **`xrootd_proxy_pool_select()` returns a status + fills a `pick` out-param**
   (`xrootd_proxy_be_pick_t`) instead of returning an entry pointer, and takes the
   `in_flight` reservation atomically inside the select.
2. **Admin auth enum** is `OK`/`DENIED` only (the `METHOD_NOT_ALLOWED` value was
   dropped; method errors are handled in the dispatcher).
3. **Step G** exposes proxy-pool state through the admin/snapshot path, not a
   distinct unauthenticated read endpoint.

### Pending / not done

- **Admin-API rate limiting (Security Design):** ⛔ **not implemented.** There is no
  per-source-IP throttle on `POST`/`DELETE`/`PUT` admin requests (`api_admin.c`
  contains no rate-limit logic). The endpoints rely on the CIDR allowlist + bearer
  secret for protection. If a throttle is wanted, wire the Phase-20/25 rate limiter
  into `xrootd_admin_dispatch()`.
- **Force-remove semantics:** the drain → poll-`in_flight` → DELETE workflow is
  supported, but verify whether `DELETE` of a backend with `in_flight > 0` hard-fails
  (409) or removes regardless — the `xrootd_proxy_pool_in_flight()` helper exists for
  the handler to enforce this.

---

## Motivation

Every upstream endpoint in the module is currently static: resolved at `postconfiguration`
time, burned into the nginx config pool, and immutable until `nginx -s reload`. Two
distinct surfaces suffer from this:

**Surface A — XRootD stream cluster (manager_mode):** The CMS management protocol
auto-registers and unregisters data servers at runtime, but it cannot be driven from
outside (e.g., a site automation script that wants to drain a storage node for
maintenance before rebooting it). The only manual option is `nginx -s reload`, which
tears down every active XRootD session — unacceptable for a 100-node storage cluster
mid-transfer.

**Surface B — WebDAV proxy backends:** `src/protocols/webdav/proxy.c` currently holds a single
pre-resolved `ngx_http_upstream_resolved_t` pointer from `conf->upstream_resolved`.
Adding or removing a WebDAV backend means editing nginx.conf and reloading. A dynamic
pool in shared memory would allow zero-downtime backend rotation.

This phase adds:
1. A REST admin API (`/xrootd/api/v1/admin/...`) with POST/DELETE/PUT write endpoints
2. A dynamic backend pool in SHM for the WebDAV HTTP proxy
3. Drain support for both surfaces (stop routing new requests while in-flight ones finish)

---

## Current State

| Component | How upstreams are managed | Mutability |
|---|---|---|
| Stream cluster registry | CMS protocol auto-registers/unregisters | Runtime via CMS; no REST write API |
| `xrootd_srv_blacklist()` | Sets `blacklisted_until` in SHM | Runtime via CMS disconnect |
| WebDAV proxy backend | Single `conf->upstream_resolved` in config pool | Config-time only |
| Dashboard API | All GET-only (`NGX_HTTP_NOT_ALLOWED` on POST/DELETE) | Read-only |

The stream cluster registry (`src/net/manager/registry.c`) is already in SHM and has a
complete public API (`xrootd_srv_register`, `xrootd_srv_unregister`,
`xrootd_srv_blacklist`). Surface A only needs REST API endpoints that call these
existing functions — no registry changes required.

Surface B requires a new SHM backend pool and changes to `proxy.c`'s selection logic.

---

## Step A — Admin API Auth Layer

**Files:** `src/observability/dashboard/api_admin.c` (new), `src/observability/dashboard/api_admin.h` (new)

The existing dashboard auth (`ngx_http_xrootd_dashboard_check_auth`) uses IP allowlist
or bearer token for read endpoints. Write endpoints need a stronger guard:

```c
typedef enum {
    XROOTD_ADMIN_AUTH_OK = 0,
    XROOTD_ADMIN_AUTH_DENIED,
    XROOTD_ADMIN_AUTH_METHOD_NOT_ALLOWED,
} xrootd_admin_auth_result_t;

xrootd_admin_auth_result_t
xrootd_admin_check_auth(ngx_http_request_t *r,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf);
```

Logic:
1. Check `r->connection->addr_text` against `conf->admin_allow_cidr` list (new config
   field — list of CIDR strings, e.g. `127.0.0.1/32 10.0.0.0/8`)
2. If `conf->admin_secret.len > 0`, require `Authorization: Bearer <secret>` header
   to match
3. Either condition alone is sufficient; both can be required via
   `xrootd_admin_require_both on` directive

New directives (registered in `src/core/config/directives.c`):

```nginx
xrootd_admin_allow       127.0.0.1  10.0.0.0/8;  # CIDR list
xrootd_admin_secret      /run/secrets/xrootd_admin_token;  # file path
xrootd_admin_require_both off;
```

The secret is read from a file at config time (not embedded in nginx.conf) and stored
as an `ngx_str_t` in the location conf. The file path approach avoids leaking the
secret into `nginx -T` output.

---

## Step B — Request Body Reader Helper

**File:** `src/observability/dashboard/api_admin.c`

All write endpoints need to read and parse a JSON request body. nginx body reading is
async: `ngx_http_read_client_request_body()` fires a callback when the body is
buffered. To avoid a large per-endpoint callback chain, use a shared body-reader
helper:

```c
typedef ngx_int_t (*xrootd_admin_body_handler_t)(ngx_http_request_t *r,
    json_t *body, void *data);

typedef struct {
    xrootd_admin_body_handler_t  handler;
    void                        *data;
} xrootd_admin_body_ctx_t;

/*
 * xrootd_admin_read_body — read the full request body, parse as JSON,
 * call handler(r, parsed_json, data). Returns NGX_DONE on async completion
 * or an HTTP status code on error. The handler is called from the body
 * callback and must call ngx_http_finalize_request() when done.
 */
ngx_int_t xrootd_admin_read_body(ngx_http_request_t *r,
    xrootd_admin_body_handler_t handler, void *data);
```

Implementation:

```c
static void
xrootd_admin_body_callback(ngx_http_request_t *r)
{
    xrootd_admin_body_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_dashboard_module);
    ngx_chain_t             *chain;
    u_char                  *buf;
    size_t                   total = 0, off = 0;
    json_t                  *parsed;
    json_error_t             jerr;
    ngx_int_t                rc;

    /* Coalesce body chain into a single linear buffer */
    for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
        total += chain->buf->last - chain->buf->pos;
    }

    if (total == 0 || total > 65536) {  /* max 64 KiB body */
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return;
    }

    buf = ngx_palloc(r->pool, total + 1);
    if (buf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
        size_t n = chain->buf->last - chain->buf->pos;
        ngx_memcpy(buf + off, chain->buf->pos, n);
        off += n;
    }
    buf[total] = '\0';

    parsed = json_loadb((char *) buf, total, 0, &jerr);
    if (parsed == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    rc = ctx->handler(r, parsed, ctx->data);
    json_decref(parsed);

    if (rc != NGX_DONE) {
        ngx_http_finalize_request(r, rc);
    }
}
```

---

## Step C — Stream Registry Admin Endpoints

**Files:** `src/observability/dashboard/api_admin.c`, `src/observability/dashboard/module.c`

These endpoints call the existing `src/net/manager/registry.c` public API. No registry
changes are required.

### Endpoint table

| Method | URI | Action | Registry call |
|---|---|---|---|
| `POST` | `/xrootd/api/v1/admin/cluster/servers` | Register a server manually | `xrootd_srv_register()` |
| `DELETE` | `/xrootd/api/v1/admin/cluster/servers/{host}/{port}` | Remove immediately | `xrootd_srv_unregister()` |
| `POST` | `/xrootd/api/v1/admin/cluster/servers/{host}/{port}/drain` | Blacklist for `duration` seconds | `xrootd_srv_blacklist()` |
| `POST` | `/xrootd/api/v1/admin/cluster/servers/{host}/{port}/undrain` | Clear blacklist | New `xrootd_srv_undrain()` |
| `PUT` | `/xrootd/api/v1/admin/cluster/servers/{host}/{port}` | Update paths/weight | `xrootd_srv_register()` (upsert) |

### C1 — Register / PUT (upsert)

Request body:
```json
{
    "host":     "se01.example.org",
    "port":     1094,
    "paths":    "/data/cms:/data/atlas",
    "free_mb":  500000,
    "util_pct": 42
}
```

Handler:
```c
static ngx_int_t
admin_cluster_server_register(ngx_http_request_t *r,
    json_t *body, void *data)
{
    const char *host;
    json_int_t  port, free_mb, util_pct;
    const char *paths;

    host     = json_string_value(json_object_get(body, "host"));
    port     = json_integer_value(json_object_get(body, "port"));
    paths    = json_string_value(json_object_get(body, "paths"));
    free_mb  = json_integer_value(json_object_get(body, "free_mb"));
    util_pct = json_integer_value(json_object_get(body, "util_pct"));

    if (host == NULL || port <= 0 || port > 65535 || paths == NULL) {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_field");
    }

    /* Input sanitisation: host must be printable ASCII, no shell metacharacters.
     * xrootd_sanitize_log_string is not appropriate here — use a whitelist check. */
    if (!admin_validate_hostname(host) || !admin_validate_paths(paths)) {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_field");
    }

    xrootd_srv_register(host, (uint16_t) port, paths,
                        (uint32_t) free_mb, (uint32_t) util_pct);

    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server registered", host);
    return admin_send_ok(r, "registered");
}
```

**Input validation functions** (`admin_validate_hostname`, `admin_validate_paths`)
are mandatory — the host and paths strings are written into the SHM registry and
later logged and returned in kXR_redirect responses. Reject anything containing
`\0`, `\n`, `\r`, `;`, `|`, `$`, `&`, `>`, `<`, backtick, or non-ASCII.

### C2 — DELETE

URI parsing: extract `{host}` and `{port}` from the last two path segments.

```c
static ngx_int_t
admin_cluster_server_delete(ngx_http_request_t *r)
{
    char     host[256];
    uint16_t port;

    if (admin_parse_host_port_uri(r, host, sizeof(host), &port) != NGX_OK) {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
    }

    xrootd_srv_unregister(host, port);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server unregistered", host);
    return admin_send_ok(r, "removed");
}
```

### C3 — Drain

Request body: `{"duration_s": 300}` (default 300 seconds if omitted).

```c
    xrootd_srv_blacklist(host, port, (ngx_msec_t) duration_s * 1000);
```

A drain is not destructive to in-flight sessions — `xrootd_srv_select()` skips the
entry for new clients while existing sessions continue to their open connections. This
is the same mechanism used when a CMS connection drops.

### C4 — Undrain (new registry function)

`xrootd_srv_undrain()` clears `blacklisted_until` and resets `error_count`:

```c
void
xrootd_srv_undrain(const char *host, uint16_t port)
{
    xrootd_srv_table_t *tbl = srv_table();
    ngx_uint_t          i;

    if (tbl == NULL) return;

    ngx_shmtx_lock(&xrootd_srv_mutex);
    for (i = 0; i < tbl->capacity; i++) {
        xrootd_srv_entry_t *e = &tbl->slots[i];
        if (e->in_use && e->port == port
            && ngx_strcmp(e->host, host) == 0)
        {
            e->blacklisted_until = 0;
            e->error_count       = 0;
            break;
        }
    }
    ngx_shmtx_unlock(&xrootd_srv_mutex);
}
```

---

## Step D — WebDAV Proxy Backend Pool

**Files:** `src/protocols/webdav/proxy_pool.h` (new), `src/protocols/webdav/proxy_pool.c` (new),
`src/protocols/webdav/proxy.c` (modify), `src/protocols/webdav/proxy_config.c` (modify),
`src/protocols/webdav/webdav.h` (modify)

### D1 — SHM pool structure

The pool mirrors the stream cluster registry pattern: a fixed-capacity SHM table,
spinlock at front, entries with host/port/state.

```c
/* proxy_pool.h */
#define XROOTD_PROXY_POOL_SLOTS  32

typedef enum {
    XROOTD_PROXY_BE_ACTIVE  = 0,
    XROOTD_PROXY_BE_DRAINING,   /* stop new selects; in-flight finish */
    XROOTD_PROXY_BE_DEAD,       /* Phase 22 HC failure; no new selects */
} xrootd_proxy_be_state_e;

typedef struct {
    char                     host[256];
    uint16_t                 port;
    ngx_uint_t               ssl;
    ngx_uint_t               weight;          /* relative selection weight */
    xrootd_proxy_be_state_e  state;
    ngx_msec_t               added_at;
    ngx_msec_t               drained_at;
    uint32_t                 in_flight;       /* atomic: active upstream conns */
    uint32_t                 id;             /* monotonic ID for REST API */
    ngx_uint_t               in_use;
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    char                     url_base[512];   /* "https://host:port" for Host: header */
} xrootd_proxy_be_entry_t;

typedef struct {
    ngx_shmtx_sh_t          lock;
    uint32_t                 next_id;
    ngx_atomic_t             rr_index;
    ngx_uint_t               capacity;
    xrootd_proxy_be_entry_t  slots[];
} xrootd_proxy_be_table_t;
```

`in_flight` is updated atomically (`ngx_atomic_fetch_add`) when `proxy.c` starts and
finishes an upstream connection — no spinlock needed for the counter itself.

### D2 — Pool API (proxy_pool.c)

```c
/* Initialise SHM zone — call from webdav postconfiguration */
ngx_int_t xrootd_proxy_pool_configure(ngx_conf_t *cf);
ngx_int_t xrootd_proxy_pool_shm_init(ngx_shm_zone_t *zone, void *data);

/* Add/remove/drain backends — thread-safe via spinlock */
ngx_int_t xrootd_proxy_pool_add(const char *url, ngx_uint_t weight,
    ngx_pool_t *pool, ngx_log_t *log, uint32_t *id_out);
ngx_int_t xrootd_proxy_pool_remove(uint32_t id);
ngx_int_t xrootd_proxy_pool_drain(uint32_t id);
ngx_int_t xrootd_proxy_pool_undrain(uint32_t id);

/* Select next backend — weighted round-robin, skip DRAINING/DEAD */
xrootd_proxy_be_entry_t *xrootd_proxy_pool_select(ngx_log_t *log);

/* Snapshot for dashboard/admin GET */
ngx_uint_t xrootd_proxy_pool_snapshot(xrootd_proxy_be_snapshot_t *out,
    ngx_uint_t max);
```

`xrootd_proxy_pool_add()` parses the URL string (same logic as
`proxy_config.c:webdav_upstream_configure_url()` — extract scheme, call
`ngx_parse_url()`, fill sockaddr), then writes the resolved entry into the SHM table.
This means `ngx_parse_url()` must be called while a pool is available — the admin
endpoint handler allocates a short-lived `ngx_pool_t` for this purpose.

### D3 — Config migration

**Before (static):**
```c
/* webdav.h */
ngx_http_upstream_resolved_t *upstream_resolved;  /* single pre-resolved address */
```

**After (dynamic pool):**
```c
ngx_shm_zone_t               *proxy_pool_zone;    /* SHM pool for dynamic backends */
ngx_uint_t                    proxy_pool_enabled;
/* upstream_resolved kept as fallback when pool is empty */
ngx_http_upstream_resolved_t *upstream_resolved;
```

During `proxy_config.c:webdav_upstream_configure_url()` at config time: if
`proxy_pool_enabled`, add the static URL to the SHM pool as the initial backend
(so the config-file URL is the seed; additional backends are added at runtime).
If pool is disabled, fall through to the old single-backend path — fully backward
compatible.

### D4 — proxy.c selection change

```c
/* Before: copies conf->upstream_resolved into per-request resolved struct */
*u->resolved = *conf->upstream_resolved;

/* After: pick from pool when enabled */
if (conf->proxy_pool_enabled) {
    xrootd_proxy_be_entry_t *be = xrootd_proxy_pool_select(c->log);
    if (be == NULL) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    /* Fill resolved from pool entry */
    u->resolved = ngx_palloc(r->pool, sizeof(*u->resolved));
    ngx_memzero(u->resolved, sizeof(*u->resolved));
    u->resolved->sockaddr  = (struct sockaddr *) &be->sockaddr;
    u->resolved->socklen   = be->socklen;
    ngx_str_set(&u->resolved->host, be->host);
    u->resolved->port      = be->port;
    /* Track in-flight for drain support */
    ctx->proxy_be_id = be->id;
    ngx_atomic_fetch_add(&be->in_flight, 1);
} else {
    u->resolved = ngx_palloc(r->pool, sizeof(*u->resolved));
    *u->resolved = *conf->upstream_resolved;
}
```

In `webdav_proxy_finalize_request()`, decrement `in_flight`:

```c
if (conf->proxy_pool_enabled && ctx->proxy_be_id != 0) {
    xrootd_proxy_pool_dec_inflight(ctx->proxy_be_id);
}
```

`in_flight` enables a true graceful drain: the drain endpoint sets `state =
DRAINING`; `xrootd_proxy_pool_select()` skips DRAINING entries; operators can poll
`GET /xrootd/api/v1/admin/proxy/backends/{id}` until `in_flight` reaches 0 before
removing the backend.

---

## Step E — Proxy Backend Admin Endpoints

**Files:** `src/observability/dashboard/api_admin.c`, `src/observability/dashboard/module.c`

| Method | URI | Action |
|---|---|---|
| `GET` | `/xrootd/api/v1/admin/proxy/backends` | List all backends + state + in_flight |
| `POST` | `/xrootd/api/v1/admin/proxy/backends` | Add backend |
| `GET` | `/xrootd/api/v1/admin/proxy/backends/{id}` | Single backend detail |
| `DELETE` | `/xrootd/api/v1/admin/proxy/backends/{id}` | Remove (immediate) |
| `POST` | `/xrootd/api/v1/admin/proxy/backends/{id}/drain` | Start draining |
| `POST` | `/xrootd/api/v1/admin/proxy/backends/{id}/undrain` | Resume active |

### E1 — Add backend

Request body:
```json
{
    "url":    "https://be02.example.org:8443",
    "weight": 2
}
```

Response (201 Created):
```json
{
    "schema": "xrootd-dashboard.v1",
    "backend": {
        "id": 3,
        "host": "be02.example.org",
        "port": 8443,
        "ssl": true,
        "weight": 2,
        "state": "active",
        "in_flight": 0,
        "added_at": 1749600000000
    }
}
```

```c
static ngx_int_t
admin_proxy_backend_add(ngx_http_request_t *r, json_t *body, void *data)
{
    const char *url;
    json_int_t  weight;
    uint32_t    id;
    ngx_int_t   rc;

    url    = json_string_value(json_object_get(body, "url"));
    weight = json_integer_value(json_object_get(body, "weight"));
    if (weight <= 0) weight = 1;

    if (url == NULL) {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_url");
    }

    if (!admin_validate_url(url)) {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_url");
    }

    rc = xrootd_proxy_pool_add(url, (ngx_uint_t) weight, r->pool, r->connection->log, &id);
    if (rc == NGX_ERROR) {
        return admin_send_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "pool_full");
    }

    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: proxy backend added", url);
    return admin_send_backend(r, NGX_HTTP_CREATED, id);
}
```

### E2 — Drain + polling workflow

Site automation for zero-downtime backend removal:

```bash
# 1. Start drain (stops new requests from routing to this backend)
curl -X POST -H "Authorization: Bearer $TOKEN" \
     https://gateway/xrootd/api/v1/admin/proxy/backends/3/drain

# 2. Poll until in_flight == 0
until [ "$(curl -s https://gateway/xrootd/api/v1/admin/proxy/backends/3 \
           | jq .backend.in_flight)" == "0" ]; do sleep 5; done

# 3. Remove safely
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
     https://gateway/xrootd/api/v1/admin/proxy/backends/3
```

---

## Step F — Routing in module.c

**File:** `src/observability/dashboard/module.c`

The dashboard's `ngx_http_xrootd_dashboard_handler()` already routes GET requests by
URI prefix. Extend it to dispatch write methods:

```c
/* Existing GET routing stays as-is */
if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
    /* ... existing endpoint dispatch ... */
    return ngx_http_xrootd_dashboard_api_handler(r, endpoint);
}

/* New: admin write routing */
if (ngx_str_has_prefix(r->uri, "/xrootd/api/v1/admin/")) {
    return xrootd_admin_dispatch(r);
}

return NGX_HTTP_NOT_ALLOWED;
```

`xrootd_admin_dispatch()` in `api_admin.c` handles auth check first, then routes
by method + URI prefix to the appropriate handler.

---

## Step G — Dashboard GET Extension

Add cluster-registry and proxy-pool state to the existing read endpoints (no auth
required — same as existing dashboard):

- `/xrootd/api/v1/cluster` — already shows server list; add `"draining": true|false`
  field to each entry (derived from `blacklisted_until != 0`)
- `/xrootd/api/v1/proxy/backends` — new read-only endpoint listing proxy pool state
  (without auth; informational only)

`dashboard_fill_cluster()` in `api.c` gets a one-line addition:
```c
json_object_set_new(srv, "draining",
    entries[i].blacklisted_until != 0 ? json_true() : json_false());
```

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/observability/dashboard/api_admin.h` | **New** | Admin API types; `xrootd_admin_dispatch()` declaration |
| `src/observability/dashboard/api_admin.c` | **New** | Auth check; body reader; all write endpoint handlers |
| `src/observability/dashboard/api.c` | Modify | Add `draining` field to cluster snapshot; add proxy pool GET |
| `src/observability/dashboard/module.c` | Modify | Route non-GET methods to `xrootd_admin_dispatch()`; add new endpoint enum values |
| `src/observability/dashboard/dashboard_http.h` | Modify | Add admin endpoint enum values |
| `src/protocols/webdav/proxy_pool.h` | **New** | `xrootd_proxy_be_entry_t`, `xrootd_proxy_be_table_t`, pool API |
| `src/protocols/webdav/proxy_pool.c` | **New** | SHM init, add/remove/drain/select/snapshot |
| `src/protocols/webdav/proxy.c` | Modify | Pick from pool when `proxy_pool_enabled`; decrement `in_flight` in finalize |
| `src/protocols/webdav/proxy_config.c` | Modify | Seed pool with static URL at config time; allocate SHM zone |
| `src/protocols/webdav/webdav.h` | Modify | Add `proxy_pool_zone`, `proxy_pool_enabled`, `proxy_be_id` to ctx |
| `src/net/manager/registry.c` | Modify | Add `xrootd_srv_undrain()`; declare in `registry.h` |
| `src/net/manager/registry.h` | Modify | Declare `xrootd_srv_undrain()` |
| `src/core/config/directives.c` | Modify | Register 3 admin auth directives |
| `src/core/types/config.h` | Modify | Add `admin_allow_cidr`, `admin_secret` fields |
| `src/core/config/config.h` | Modify | Add `proxy_pool.c` + `api_admin.c` to `NGX_ADDON_SRCS` |

---

## Build Registration

Two new source files (`src/protocols/webdav/proxy_pool.c`, `src/observability/dashboard/api_admin.c`) must
be added to `NGX_ADDON_SRCS` in `src/core/config/config.h` before running `./configure`
once. All subsequent changes build with `make -j$(nproc)`.

---

## Security Design

### Input validation invariants

All string inputs from admin API bodies that flow into SHM or wire responses must
pass whitelist validation before being written:

- **Hostnames**: `[A-Za-z0-9.\-]`, max 253 chars; no IP literal brackets (handled
  separately)
- **Paths field**: `[A-Za-z0-9/.\-_:]`, max `XROOTD_SRV_MAX_PATHS` bytes; colons
  only as path delimiters
- **URLs**: must begin with `http://` or `https://`; remainder checked by
  `ngx_parse_url()` — if it fails, return 400
- **Port numbers**: integer 1–65535

Reject any input that fails whitelist — do not sanitize and continue. The host and
paths strings are written into SHM and later emitted in `kXR_redirect` XRootD
responses to clients; injection into those responses could redirect clients to
attacker-controlled servers.

### Rate limiting

> **Status: ⛔ NOT implemented.** No per-IP throttle exists on the admin write
> endpoints (`api_admin.c` has no rate-limit logic); protection currently relies on
> the CIDR allowlist + bearer secret (Step A). The design below is the path to add
> it — wiring the Phase-20/25 rate limiter into `xrootd_admin_dispatch()`.

The admin API must not be a DoS vector for SHM exhaustion. Apply a simple rate
limit: max 60 POST/DELETE/PUT requests per minute per source IP, enforced by a small
per-IP counter array in a dedicated SHM zone (reuse Phase 20 KV rate-limit
mechanism, or a simpler fixed-size array keyed by IPv4/6 address hash).

### Audit logging

Every successful write operation logs a structured `ngx_log_error(NGX_LOG_NOTICE)`:

```
xrootd: admin: POST /cluster/servers host=se01.example.org port=1094
        client=127.0.0.1 result=registered
```

This is separate from `xrootd_dashboard_event_add()` (dashboard ring buffer) — the
nginx error log is append-only and forensically reliable.

---

## Testing Requirements

3 tests per area (success + error + security-neg per CLAUDE.md):

### Step C (cluster registry write API)
- `test_a_upstream_redirect.py::TestAdminClusterAPI::test_register_server_routes_traffic` — POST registers server; subsequent locate returns it
- `test_a_upstream_redirect.py::TestAdminClusterAPI::test_delete_server_stops_routing` — DELETE removes; locate no longer returns it
- `test_a_upstream_redirect.py::TestAdminClusterAPI::test_register_invalid_host_rejected` — shell metachar in host → 400, no registry write

### Step D + E (proxy pool)
- `test_a_webdav_clients.py::TestDynamicProxy::test_add_backend_serves_requests` — POST adds backend; subsequent WebDAV GET routes to it
- `test_a_webdav_clients.py::TestDynamicProxy::test_drain_stops_new_selects` — drain → new requests go to other backends; `in_flight` counts existing
- `test_a_webdav_clients.py::TestDynamicProxy::test_remove_active_backend_rejected` — DELETE while `in_flight > 0` returns 409 Conflict (or warn + force flag)

### Step A (auth)
- `test_credential_translation.py::TestAdminAuth::test_missing_token_returns_403` — POST without auth → 403
- `test_credential_translation.py::TestAdminAuth::test_wrong_token_returns_403` — wrong secret → 403
- `test_credential_translation.py::TestAdminAuth::test_cidr_allowlist_enforced` — request from disallowed IP → 403 even with correct token

---

## Interaction with Other Phases

| Phase | Interaction |
|---|---|
| Phase 22 (Health Checks) | HC sets `state = XROOTD_PROXY_BE_DEAD` on probe failure; this phase provides the API to undrain/re-enable manually. HC also clears `blacklisted_until` on recovery for stream registry. |
| Phase 20 (SHM/KV) | Rate limiting for admin API can reuse KV zone rather than a custom SHM zone. |
| Phase 21 (Subrequests) | Multi-backend proxy (Phase 21 Step D) adds round-robin selection; this phase adds the runtime add/remove API on top of that pool. |

---

## Operational Notes

### Zero-downtime backend swap

```bash
# Add new backend
NEW_ID=$(curl -sX POST -H "Authorization: Bearer $TOKEN" \
    -d '{"url":"https://new-be.example.org:8443","weight":1}' \
    https://gw/xrootd/api/v1/admin/proxy/backends | jq .backend.id)

# Drain old backend
curl -X POST ... https://gw/xrootd/api/v1/admin/proxy/backends/1/drain

# Wait for in_flight to drop
until [ "$(curl -s .../backends/1 | jq .backend.in_flight)" == "0" ]; do sleep 5; done

# Remove old backend
curl -X DELETE ... https://gw/xrootd/api/v1/admin/proxy/backends/1
```

### Maintenance drain for stream cluster

```bash
# Drain storage node se07 for 10 minutes during disk replacement
curl -X POST -H "Authorization: Bearer $TOKEN" \
    -d '{"duration_s": 600}' \
    https://gw/xrootd/api/v1/admin/cluster/servers/se07.example.org/1094/drain

# After maintenance, re-enable (CMS reconnect also auto-clears it)
curl -X POST ... https://gw/xrootd/api/v1/admin/cluster/servers/se07.example.org/1094/undrain
```
