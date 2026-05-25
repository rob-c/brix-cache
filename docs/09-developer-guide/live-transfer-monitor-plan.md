# Live Transfer Monitor — Implementation Plan

A self-contained admin dashboard served by the module itself. A site operator opens a browser, logs in with a configured password, and sees every active transfer in real time: who, what file, which protocol, how fast, and totals across the whole server's lifetime.

---

## What the admin sees

```
┌─ nginx-xrootd Transfer Monitor ──────────────────────── last update: 0.3s ago ─┐
│                                                                                  │
│  7 active sessions    ↓ 1.23 TB ingress    ↑ 847 GB egress    12,305 lifetime   │
│                                                                                  │
│ Client          Identity                  Path                   Proto  Dir      │
│                 Transferred  Rate     Elapsed                                    │
│ ──────────────────────────────────────────────────────────────────────────────── │
│ 131.154.200.10  /CN=ATLAS T2 /store/data/reco_2024_001.root  [root]  ↑ write    │
│                 4.1 GB       823 MB/s   5s                                       │
│ 192.168.1.42    anonymous    /public/mc_samples/pythia8.root  [davs]  ↓ read    │
│                 12.3 GB      210 MB/s   59s                                      │
│ …                                                                                │
└──────────────────────────────────────────────────────────────────────────────────┘
```

The page polls a JSON API every two seconds. Rate is computed client-side from consecutive snapshots — no server-side rate tracking needed. The admin page is served by the module itself; no external proxy, Grafana, or Node.js required.

---

## Architecture

```
┌─ nginx worker (stream) ─────────────────────────────────┐
│  kXR_open  → xrootd_transfer_slot_alloc()               │
│  kXR_read  → xrootd_transfer_slot_update(bytes)         │  ╔═ shared memory ═════════╗
│  kXR_write → xrootd_transfer_slot_update(bytes)         │  ║ xrootd_transfer_table_t ║
│  kXR_close → xrootd_transfer_slot_free()                │  ║  [512 slots]            ║
│  disconnect → xrootd_transfer_slot_free_all(sessid)     │  ║  each: IP, identity,    ║
│                                                         │  ║  path, proto, dir,      ║
│  WebDAV GET/PUT → same alloc/update/free hooks          │  ║  bytes, timestamps      ║
│  S3 GET/PUT     → same alloc/update/free hooks          │  ╚═════════════════════════╝
└─────────────────────────────────────────────────────────┘             │
                                                                         │ read-only
┌─ nginx worker (HTTP) ───────────────────────────────────┐             │
│  GET /xrootd/transfers → JSON snapshot of live slots    │─────────────┘
│  GET /xrootd/          → embedded HTML+JS dashboard     │
│  GET /xrootd/login     → login form                     │
│  POST /xrootd/login    → verify password → set cookie   │
└─────────────────────────────────────────────────────────┘
                      ↑
               browser polls every 2s
```

The transfer table is a **separate** shared memory zone from the metrics zone. It has different lifecycle requirements: slots are allocated and freed at high frequency while metric counters only ever increment. Keeping them separate also means the dashboard can be disabled without touching metrics.

---

## New shared memory structure

**`src/dashboard/dashboard.h`** — the complete public header for the feature.

```c
#ifndef XROOTD_DASHBOARD_H
#define XROOTD_DASHBOARD_H

#include <stdint.h>
#include <ngx_core.h>

/* Hard limits — chosen to keep the SHM zone under 512 KB. */
#define XROOTD_DASHBOARD_MAX_TRANSFERS   512
#define XROOTD_DASHBOARD_PATH_LEN        512
#define XROOTD_DASHBOARD_IDENTITY_LEN    128
#define XROOTD_DASHBOARD_IP_LEN           64

/* Protocol tag values stored in xrootd_transfer_slot_t.proto */
#define XROOTD_XFER_PROTO_ROOT    1   /* native XRootD stream (root://)   */
#define XROOTD_XFER_PROTO_WEBDAV  2   /* WebDAV over HTTPS (davs://)      */
#define XROOTD_XFER_PROTO_S3      3   /* S3-compatible REST API           */

/* Direction tag values */
#define XROOTD_XFER_DIR_READ   1   /* client downloading                 */
#define XROOTD_XFER_DIR_WRITE  2   /* client uploading                   */
#define XROOTD_XFER_DIR_TPC    3   /* third-party copy (no client data)  */

/*
 * One active-transfer record.  Lives in shared memory; all fields updated
 * from stream workers via atomics.  The lock in xrootd_transfer_table_t is
 * held only for slot allocation — per-slot byte/timestamp updates are
 * lock-free using ngx_atomic_t.
 */
typedef struct {
    ngx_atomic_t  in_use;       /* 0=free, 1=active; written under table lock */
    uint32_t      serial;       /* monotonic ID — lets the JS detect row churn */
    u_char        sessid[16];   /* session ID for cleanup-by-sessid on disconnect */
    char          client_ip[XROOTD_DASHBOARD_IP_LEN];
    char          identity[XROOTD_DASHBOARD_IDENTITY_LEN]; /* DN, "anonymous", etc. */
    char          path[XROOTD_DASHBOARD_PATH_LEN];
    uint8_t       direction;    /* XROOTD_XFER_DIR_*  */
    uint8_t       proto;        /* XROOTD_XFER_PROTO_* */
    ngx_atomic_t  bytes;        /* bytes transferred so far (atomic increment) */
    int64_t       start_ms;     /* epoch ms at transfer start (written once)   */
    ngx_atomic_t  last_ms;      /* epoch ms of last I/O (atomic write)         */
} xrootd_transfer_slot_t;

typedef struct {
    ngx_shmtx_sh_t           lock;         /* held only during alloc/free      */
    uint32_t                 next_serial;   /* monotonic counter for slot IDs   */
    xrootd_transfer_slot_t  slots[XROOTD_DASHBOARD_MAX_TRANSFERS];
} xrootd_transfer_table_t;

/* Global pointer set during stream postconfiguration, read by HTTP handler. */
extern ngx_shm_zone_t *ngx_xrootd_dashboard_shm_zone;

/* transfer_table.c — the four public operations */
int  xrootd_transfer_slot_alloc(
    xrootd_transfer_table_t *t,
    const u_char sessid[16],
    const char *client_ip,
    const char *identity,
    const char *path,
    uint8_t direction,
    uint8_t proto,
    int64_t now_ms);

void xrootd_transfer_slot_update(
    xrootd_transfer_table_t *t,
    int slot_idx,
    ngx_atomic_int_t nbytes,
    int64_t now_ms);

void xrootd_transfer_slot_free(
    xrootd_transfer_table_t *t,
    int slot_idx);

void xrootd_transfer_slot_free_all_for_session(
    xrootd_transfer_table_t *t,
    const u_char sessid[16]);

#endif /* XROOTD_DASHBOARD_H */
```

**Memory layout:** `sizeof(xrootd_transfer_slot_t)` ≈ 800 bytes × 512 slots = ~400 KB. SHM zone sized at `sizeof(xrootd_transfer_table_t) + ngx_pagesize` ≈ 408 KB, rounded up to the nearest OS page.

---

## Hook points in `xrootd_file_t`

Each open file handle needs to remember which dashboard slot belongs to it so that read/write handlers can call `slot_update()` by index without scanning the table.

Add one field to `src/types/file.h`:

```c
int32_t  dashboard_slot;  /* index into transfer table; -1 = not tracked */
```

Initialise to `-1` in the open handler. Set after `xrootd_transfer_slot_alloc()` succeeds. The close handler calls `xrootd_transfer_slot_free(table, fh->dashboard_slot)` and resets to `-1`.

---

## New files

### `src/dashboard/transfer_table.c`

Implements the four public functions declared in `dashboard.h`.

**`xrootd_transfer_slot_alloc()`:**
- Acquire `t->lock` (ngx_shmtx_lock)
- Scan `slots[0..MAX]` for first `in_use == 0`
- If none found: release lock, return `-1` (silently, transfer is untracked — not an error)
- Copy all fields into the slot; set `in_use = 1`, assign `t->next_serial++` as serial
- Release lock
- Return slot index

Scan is O(N) under lock. With 512 slots and typical concurrency (tens of connections), this is a handful of cache-line reads. No need for a free-list optimisation yet.

**`xrootd_transfer_slot_update()`:**
- Bounds-check slot_idx; if `< 0` or slot `in_use == 0`, return silently
- `ngx_atomic_fetch_add(&slot->bytes, nbytes)`
- Atomic write to `slot->last_ms` (via `ngx_atomic_cmp_set` loop or direct word write — 64-bit platforms have atomic word stores)

No lock needed for updates — only the `bytes` and `last_ms` fields change, and both are atomic.

**`xrootd_transfer_slot_free()`:**
- Bounds-check slot_idx
- `ngx_atomic_cmp_set(&slot->in_use, 1, 0)` — atomic, no lock needed

**`xrootd_transfer_slot_free_all_for_session()`:**
- Acquire lock
- Scan all in-use slots comparing `sessid` via `ngx_memcmp`
- Zero each matching slot (`ngx_memzero`), set `in_use = 0`
- Release lock

Called from `xrootd_on_disconnect()` as the final cleanup step. This catches dropped connections that never sent `kXR_close`.

**Stale slot GC in the JSON exporter:** When the JSON handler iterates slots to build output, it checks: `if (in_use && now_ms - last_ms > 60000)` → free the slot. This provides a second safety net against slot leaks.

---

### `src/dashboard/api.c`

HTTP handler for `GET /xrootd/transfers`. Returns JSON.

```c
ngx_int_t ngx_http_xrootd_dashboard_api_handler(ngx_http_request_t *r);
```

Steps:
1. Auth cookie check — if not valid, return `401 Unauthorized` (not a redirect; the JS fetch() handles this and redirects to login).
2. Read-only scan of `xrootd_transfer_table_t` slots (no lock — eventually consistent is fine for display).
3. Read aggregate totals from `ngx_xrootd_shm_zone->data` (the existing metrics SHM).
4. Build JSON into a `metrics_writer_t` chain (reuse the same writer from `src/metrics/writer.c`).
5. Respond with `Content-Type: application/json`.

**JSON shape:**

```json
{
  "server_ms": 1716556800000,
  "active_transfers": [
    {
      "id": 42,
      "client": "131.154.200.10",
      "identity": "/DC=ch/DC=cern/CN=Test User",
      "path": "/store/data/2024/reco_001.root",
      "direction": "read",
      "protocol": "root",
      "bytes": 1048576000,
      "start_ms": 1716556750000,
      "last_ms":  1716556799800
    }
  ],
  "totals": {
    "connections_active": 7,
    "connections_total":  12305,
    "bytes_rx_total":     1234567890123,
    "bytes_tx_total":     847123456789,
    "webdav_bytes_rx":    111111111,
    "webdav_bytes_tx":    222222222,
    "s3_bytes_rx":        333333333,
    "s3_bytes_tx":        444444444
  }
}
```

Totals for the aggregate bytes are summed across all `servers[]` slots from the existing metrics SHM — no duplication of counters, just a different view over the same data.

---

### `src/dashboard/page.c`

HTTP handler for `GET /xrootd/`. Serves the dashboard HTML page as a static string constant embedded in the C source.

```c
static const char ngx_xrootd_dashboard_html[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    /* ... */
    ;
```

The page:
- Dark-themed CSS inline in `<style>` — no external stylesheets.
- Totals bar at the top: active sessions, total ingress, total egress, lifetime connections.
- A `<table>` with columns: **Client IP · Identity · Path · Protocol · Direction · Transferred · Rate · Elapsed**.
- JavaScript polls `fetch('/xrootd/transfers')` every 2 000 ms.
- Rate = `(new_bytes − prev_bytes) / (new_server_ms − prev_server_ms) * 1000` bytes/s, rendered as MB/s or GB/s.
- Rows sorted descending by instantaneous rate (most active first).
- Rows where `now - last_ms > 5 000` are greyed (stall detection).
- Human-readable byte formatting (`fmtBytes(n)` in JS: "1.2 GB", "847 MB", etc.).
- `server_ms` from the JSON response is used as the clock reference so server/browser clock skew does not affect elapsed-time display.
- A `<div id="status">` shows "LIVE · updated 0.3s ago" or "DISCONNECTED — retrying…" if a fetch fails.
- If a fetch returns HTTP 401, the browser is redirected to `/xrootd/login`.

The entire page — including inline CSS and JS — fits comfortably under 8 KB, which is small enough to embed as a single C string literal.

---

### `src/dashboard/auth.c`

Handles the login flow and cookie verification.

**Config:**
```c
typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   password;       /* plaintext from xrootd_dashboard_password directive */
    ngx_str_t   cookie_secret;  /* HMAC key; defaults to password if not set          */
    ngx_uint_t  session_ttl;    /* cookie lifetime in seconds; default 28800 (8 h)    */
} ngx_http_xrootd_dashboard_loc_conf_t;
```

**Cookie format:** `<hex(HMAC-SHA256(secret, timestamp_s))>.<timestamp_s>`

The HMAC covers only the timestamp, not a per-user identity — the dashboard is single-user. Verification:
1. Split cookie on `.`; parse `timestamp_s`.
2. Reject if `now - timestamp_s > session_ttl`.
3. Recompute HMAC; constant-time compare via `CRYPTO_memcmp()` (OpenSSL, already linked).

OpenSSL is already a module dependency — no new library needed.

**`ngx_http_xrootd_dashboard_check_auth(r, conf)`:**
Returns `NGX_OK` if the request carries a valid `xrd_dashboard` cookie, `NGX_HTTP_UNAUTHORIZED` otherwise.

**`GET /xrootd/login`:**
Serves the login form as an inline HTML string in `auth.c`. Minimal: one password `<input>`, POST to `/xrootd/login`.

**`POST /xrootd/login`:**
1. Read the request body.
2. Parse `password=` from the URL-encoded body.
3. Compare `ngx_str_t password` from config using `CRYPTO_memcmp()`.
4. On match: generate cookie (`time(NULL)`, HMAC, format as above), set `Set-Cookie: xrd_dashboard=<value>; Path=/xrootd; HttpOnly; SameSite=Strict`, redirect `302 → /xrootd/`.
5. On mismatch: re-serve the login form with an `?error=1` query parameter that triggers a "wrong password" message.

No rate-limiting on login attempts is planned for v1; this dashboard should be firewalled to trusted networks. A note in the config reference warns operators accordingly.

---

### `src/dashboard/module.c`

Defines `ngx_http_xrootd_dashboard_module`. Mirrors the structure of `src/metrics/module.c`:

- `create_loc_conf` / `merge_loc_conf` for `ngx_http_xrootd_dashboard_loc_conf_t`
- Two directives: `xrootd_dashboard on|off` and `xrootd_dashboard_password "<string>"`
- `ngx_conf_set_flag_slot` for the boolean; a custom setter for the password that also installs the content handler:

```c
static char *
ngx_http_xrootd_dashboard_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char *rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_dashboard_main_handler;
    return NGX_CONF_OK;
}
```

`ngx_http_xrootd_dashboard_main_handler` dispatches on `r->uri` suffix:
- ends with `/transfers` → `api_handler`
- ends with `/login`     → `auth_login_handler`
- everything else        → `page_handler` (after auth check)

---

## Modifications to existing files

### `src/metrics/metrics.h`

Add the declaration:

```c
extern ngx_shm_zone_t *ngx_xrootd_dashboard_shm_zone;
```

And include `src/dashboard/dashboard.h` from the umbrella header so that `xrootd_file_t` can reference `dashboard_slot` without extra includes.

### `src/types/file.h`

Add one field to `xrootd_file_t`:

```c
int32_t  dashboard_slot;   /* transfer table slot index; -1 = not tracked */
```

Initialise to `-1` alongside the other fields at the top of `open_resolved_file.c`.

### `src/config/config.c` (or wherever `xrootd_configure_metrics()` is called)

Add `xrootd_configure_dashboard(cf, cmcf)` — registers the transfer table SHM zone exactly as metrics registers its zone. The zone name is `"xrootd_dashboard"`. The init callback zeros the table on first startup and preserves it across reloads (same pattern as metrics).

### `src/read/open_resolved_file.c`

After a successful `open()` returns a valid file descriptor, call:

```c
if (ngx_xrootd_dashboard_shm_zone != NULL) {
    xrootd_transfer_table_t *tbl = ngx_xrootd_dashboard_shm_zone->data;
    const char *identity = ctx->dn[0] ? ctx->dn : "anonymous";
    uint8_t dir = writable ? XROOTD_XFER_DIR_WRITE : XROOTD_XFER_DIR_READ;
    fh->dashboard_slot = xrootd_transfer_slot_alloc(
        tbl, ctx->sessid, ctx->peer_ip, identity, canon_path, dir,
        XROOTD_XFER_PROTO_ROOT, (int64_t) ngx_current_msec);
}
```

Failure to allocate a slot (`-1` returned) is silently ignored — the transfer proceeds untracked.

### `src/read/read.c`, `readv.c`, `pgread.c`

After a successful data response is queued, add:

```c
if (fh->dashboard_slot >= 0 && ngx_xrootd_dashboard_shm_zone) {
    xrootd_transfer_slot_update(
        ngx_xrootd_dashboard_shm_zone->data,
        fh->dashboard_slot, (ngx_atomic_int_t) nbytes_sent,
        (int64_t) ngx_current_msec);
}
```

For AIO reads (`src/aio/`), the update goes in the AIO completion callback, after `ctx->destroyed` is checked (same guard as the metrics update there).

### `src/write/write.c`, `writev.c`, `pgwrite.c`

Same pattern: update slot with bytes written after a successful commit to disk.

### `src/read/close.c`

Before zeroing `fh`:

```c
if (fh->dashboard_slot >= 0 && ngx_xrootd_dashboard_shm_zone) {
    xrootd_transfer_slot_free(ngx_xrootd_dashboard_shm_zone->data,
                              fh->dashboard_slot);
    fh->dashboard_slot = -1;
}
```

### `src/connection/disconnect.c` — `xrootd_on_disconnect()`

After the per-connection cleanup, add:

```c
if (ngx_xrootd_dashboard_shm_zone != NULL) {
    xrootd_transfer_slot_free_all_for_session(
        ngx_xrootd_dashboard_shm_zone->data, ctx->sessid);
}
```

This handles clients that drop TCP without sending `kXR_close`.

### `src/webdav/get.c`

Allocate a slot when the WebDAV GET handler resolves the target path and is about to start streaming a response body. Store the slot index in the WebDAV request context (`ngx_http_xrootd_webdav_ctx_t`, adding `int32_t dashboard_slot`). Update in the sendfile/AIO completion chain. Free in the request finaliser.

Identity for WebDAV: use the client DN extracted during `webdav_verify_proxy_cert()` / `webdav_verify_bearer_token()`, or `"anonymous"` if unauthenticated. This is already stored in the request context.

### `src/webdav/put.c`

Same pattern as GET but with `XROOTD_XFER_DIR_WRITE`. Update on each `write()` completion, free in the PUT finaliser.

### `src/webdav/tpc.c`

Allocate a slot with `XROOTD_XFER_DIR_TPC`. The `tpc_curl.c` byte-progress callback updates the slot. Free on TPC completion (success or failure).

### `src/s3/get.c`, `src/s3/put.c`

Same treatment as WebDAV. S3 identity from SigV4 key ID or `"anonymous"`.

---

## Config directives

```nginx
http {
    server {
        listen 9101;

        # Dashboard endpoint — put this behind a firewall, not on a public port
        location /xrootd/ {
            xrootd_dashboard on;
            xrootd_dashboard_password "changeme_use_a_real_password";
            # xrootd_dashboard_session_ttl 28800;   # cookie lifetime, seconds (default 8h)
        }

        # Existing metrics endpoint — separate location, separate module
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

The two directives:

| Directive | Context | Type | Default | Description |
|---|---|---|---|---|
| `xrootd_dashboard` | `location` | `flag` | `off` | Enables the dashboard on this location |
| `xrootd_dashboard_password` | `location` | `string` | (required) | Plaintext password for the login form |
| `xrootd_dashboard_session_ttl` | `location` | `number` | `28800` | Cookie lifetime in seconds |

The password is stored in `ngx_http_xrootd_dashboard_loc_conf_t.password` as an `ngx_str_t`. It is **never** written to the dashboard page or any response. The operator is responsible for ensuring the nginx config file is not world-readable.

---

## Build system changes

**`config`** — add new sources to `NGX_ADDON_SRCS`:

```sh
ngx_addon_srcs="$ngx_addon_srcs \
    $ngx_addon_dir/src/dashboard/transfer_table.c \
    $ngx_addon_dir/src/dashboard/api.c \
    $ngx_addon_dir/src/dashboard/page.c \
    $ngx_addon_dir/src/dashboard/auth.c \
    $ngx_addon_dir/src/dashboard/module.c \
    "
```

No new `--with-*` flags needed — the dashboard compiles in alongside the metrics module. If needed it can be made conditional on a `--with-dashboard` flag in the same style as `--with-stream`.

---

## Test plan

Three tests per change, following the project rule.

### `tests/test_dashboard.py`

**`TestDashboardAuth`**
- `test_no_cookie_redirects_to_login` — GET `/xrootd/` without cookie → 302 to `/xrootd/login`
- `test_api_no_cookie_returns_401` — GET `/xrootd/transfers` without cookie → 401
- `test_login_wrong_password_stays_on_form` — POST wrong password → 200 with error indicator, no cookie set
- `test_login_correct_password_sets_cookie` — POST correct password → 302 to `/xrootd/`, `Set-Cookie` present
- `test_cookie_allows_dashboard_access` — GET with valid cookie → 200
- `test_expired_cookie_redirects_to_login` — GET with cookie whose timestamp is beyond `session_ttl` → 302
- `test_tampered_cookie_redirects_to_login` — GET with HMAC flipped → 302

**`TestDashboardApi`**
- `test_api_returns_json` — valid cookie, GET `/xrootd/transfers` → `Content-Type: application/json`, parseable
- `test_api_has_totals` — response contains `totals.connections_active`, `totals.bytes_rx_total`, `totals.bytes_tx_total`
- `test_api_reflects_active_transfer` — start an xrdcp read transfer; GET `/xrootd/transfers` while it's running → `active_transfers` array is non-empty, entry has expected `protocol`, `direction`, `path`, `bytes > 0`
- `test_api_clears_slot_after_close` — wait for xrdcp to finish; GET again → `active_transfers` is empty
- `test_api_webdav_transfer_appears` — start a WebDAV GET; check API → entry with `protocol: "webdav"`
- `test_api_s3_transfer_appears` — start an S3 PUT; check API → entry with `protocol: "s3"`

**`TestDashboardSecurityNeg`**
- `test_path_not_in_api_payload_header` — response does not expose path info in HTTP headers
- `test_csrf_post_without_referer_rejected` — POST to `/xrootd/login` with mismatched `Origin` header → rejected (basic CSRF mitigation: verify `Origin` matches server host when present)
- `test_slot_freed_on_disconnect` — open a transfer, kill the TCP connection without `kXR_close`, wait 2s, check API → slot gone

### `tests/test_dashboard_rate.py`

- `test_rate_nonzero_during_large_transfer` — stream a 512 MB file; poll the API twice 1s apart; verify `(bytes_t2 - bytes_t1) / 1.0 > 0` (smoke test that bytes increment)
- `test_bytes_match_actual_transfer` — compare total bytes from API to actual file size after transfer completes

---

## Stale slot safety net

The GC check in `api.c` during JSON export:

```c
int64_t now_ms = (int64_t) ngx_current_msec;
for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
    xrootd_transfer_slot_t *s = &tbl->slots[i];
    if (!ngx_atomic_fetch_add(&s->in_use, 0)) { continue; }

    /* Stale: no I/O for > 60 s means the close event was missed. */
    int64_t last = (int64_t) ngx_atomic_fetch_add(&s->last_ms, 0);
    if (now_ms - last > 60000) {
        xrootd_transfer_slot_free(tbl, (int) i);
        continue;
    }

    /* emit JSON for this slot */
}
```

This runs at most every 2 seconds (the polling interval), touches only in-use slots, and requires no additional locking.

---

## Security notes

- The dashboard password is transmitted over HTTP unless the admin server block uses TLS. **Recommend serving on a localhost-only port or behind a TLS terminator.** Document this prominently in the config reference.
- Cookie is `HttpOnly` and `SameSite=Strict` to mitigate XSS/CSRF.
- The HMAC key is the plaintext password. Rotating it requires a config reload (which invalidates all active sessions — acceptable for an internal admin tool).
- File paths visible in the dashboard are the same paths already logged in `xrootd_access*.log`. There is no new information exposure compared to what an operator can already read from logs.
- The `identity` field shown in the dashboard is the client's GSI DN or token sub claim — the same values emitted to the access log. No credential material (token bytes, private keys) is ever written to a slot.
- Slot scanning under the table lock in `slot_alloc` and `slot_free_all_for_session` is O(512). At worst this is a few microseconds. The lock is not held during I/O — only during slot lifecycle transitions.

---

## Open questions before implementation

1. **Should the dashboard page be configurable or always embedded?** Embedded keeps the module self-contained. An `xrootd_dashboard_html_file` directive could let operators customise it without recompiling, at the cost of an extra dependency.

2. **Multiple simultaneous admin users?** The current design is single-password / single-session. For multi-user access a separate `xrootd_dashboard_users` file directive would be more appropriate.

3. **WebDAV identity depth:** The WebDAV path uses `webdav_verify_proxy_cert()` to extract the DN. For token-auth WebDAV, the `sub` claim would be the right identity string. Both code paths need to surface a string into the transfer slot.

4. **TPC identity:** During WebDAV TPC the "identity" is the service certificate performing the copy, not the end user who triggered it. Should the slot show the service DN or omit identity for TPC slots?
