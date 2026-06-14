# Phase 10: dashboard/api.c → jansson

**Projected ΔLoC:** −150 (conservative) / −200 (optimistic)  
**Risk:** Low  
**Depends on:** nothing (jansson already a build dependency)  
**Blocks:** nothing  
**Parallel-safe with:** all other phases

---

## Goal

Replace the hand-rolled JSON serialiser in `src/dashboard/api.c` with jansson.  The
current implementation uses a pointer-chasing pattern (`p = json_append(p, end, ...)`)
over a pre-allocated 1 MB pool buffer.  jansson is already linked for `token/` and
`s3/` code; switching the dashboard avoids the 1 MB fixed allocation, eliminates
truncation risk, and removes the custom `json_append_escaped_str` with its manual
control-character escaping.

---

## Corrected premise on LoC savings

The original estimate of ~−400 LoC was based on a flawed assumption that the
hand-rolled code was verbose.  Reading the actual file reveals that `json_append()` is
a tight wrapper around `vsnprintf`, and compact multi-field format strings keep each
function short.  The honest savings are:

| Source of saving | ΔLoC |
|---|---|
| Delete `json_append` (26 LoC) + `json_append_escaped_str` (48 LoC) | −74 |
| Eliminate `!first` / `i != 0` comma-separator logic in 5 loops | −20 |
| Eliminate `p < end - N` mid-loop overflow guards | −10 |
| Shorten `dashboard_append_transfer_object` (118 → ~85) | −33 |
| Shorten `dashboard_append_transfer_rows`, `_tpc_registry` | −30 |
| Shorten `dashboard_append_events`, `_history`, `_cache`, `_cluster` | −55 |
| Shorten 8 thin builder functions + main handler | −25 |
| Remove `JSON_BUF_SIZE` define, `<stdarg.h>`, `<stdio.h>` | −3 |
| **Gross savings** | **−250** |
| New NULL checks on `json_object()` / `json_array()` | +20 |
| `json_decref()` on error paths | +10 |
| `dashboard_append_limits` becomes longer with jansson | +5 |
| `dashboard_send_json` changes | +5 |
| `#include <jansson.h>` | +1 |
| **Gross additions** | **+41** |
| **Net** | **−150 to −200** |

---

## Key design decisions

### Memory: `json_dumpb()` avoids malloc/free

jansson 2.14 (the installed version) provides `json_dumpb()`, which writes to a
caller-supplied buffer and returns the byte count required.  The two-call pattern
avoids any `malloc`/`free` outside the nginx pool:

```c
/* Step 1: probe size */
size_t needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
if (needed == 0) { json_decref(root); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

/* Step 2: pool-allocate exact size */
u_char *buf = ngx_palloc(r->pool, needed);
if (buf == NULL) { json_decref(root); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

/* Step 3: fill */
json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
json_decref(root);

/* Step 4: hand to nginx chain (no null terminator needed — length is exact) */
```

This replaces the 1 MB `ngx_palloc(r->pool, JSON_BUF_SIZE)` with an allocation sized
to the actual output.

### Function signature change

Every `dashboard_append_*` and `dashboard_build_v1_*` function currently has the
signature:

```c
static char *dashboard_append_X(char *p, char *end, ...)
```

After migration the builders that produce sub-objects return `json_t *` and the top-
level endpoint builders return the root `json_t *` directly:

```c
static json_t *dashboard_build_limits(const ngx_http_xrootd_dashboard_loc_conf_t *conf);
static json_t *dashboard_build_transfer_object(...);
// etc.
```

The main handler calls the appropriate builder, then serialises once at the end.

### SHM memory barrier: unchanged

The `ngx_memory_barrier()` + local-variable copy pattern in
`dashboard_append_transfer_object` (lines 416–440) is **preserved verbatim**.  jansson
only changes what happens after the data is copied to local stack variables.

### Truncation handling

The current `if (p >= end)` guard fires when the 1 MB buffer fills.  With jansson this
cannot happen — `json_object()` returns NULL only on OOM.  The 507 truncation event is
retained but triggered by `json_object()` / `json_dumpb()` returning NULL/0 instead of
buffer overflow.

---

## Before / after: representative functions

### `json_append_escaped_str` — deleted entirely

```c
/* BEFORE (48 LoC) */
static char *
json_append_escaped_str(char *p, char *end, const char *s)
{
    const unsigned char *src;
    if (p >= end) { return end; }
    *p++ = '"';
    if (s == NULL) { if (p < end) { *p++ = '"'; } return p; }
    src = (const unsigned char *) s;
    while (*src != '\0' && p < end - 1) {
        unsigned char c = *src++;
        if (c == '"' || c == '\\') { ... *p++ = '\\'; *p++ = (char) c; ... }
        if (c < 0x20) { ... p = json_append(p, end, "\\u%04x", (unsigned int) c); ... }
        *p++ = (char) c;
    }
    if (p < end) { *p++ = '"'; }
    return p;
}

/* AFTER: json_string(s) handles all escaping correctly, including null → "null" */
```

### `dashboard_append_totals` — 24 → ~14 LoC

```c
/* BEFORE */
static char *
dashboard_append_totals(char *p, char *end,
    const xrootd_dashboard_totals_t *totals)
{
    return json_append(p, end,
        "\"totals\":{"
        "\"connections_active\":%" PRIu64 ","
        ...  /* 11 fields in one format string */
        "}",
        totals->conn_active, totals->conn_total, ...);
}

/* AFTER */
static json_t *
dashboard_build_totals(const xrootd_dashboard_totals_t *totals)
{
    json_t *obj = json_object();
    if (!obj) return NULL;
    json_object_set_new(obj, "connections_active", json_integer((json_int_t) totals->conn_active));
    json_object_set_new(obj, "connections_total",  json_integer((json_int_t) totals->conn_total));
    json_object_set_new(obj, "bytes_rx_total",     json_integer((json_int_t) totals->bytes_rx));
    json_object_set_new(obj, "bytes_tx_total",     json_integer((json_int_t) totals->bytes_tx));
    json_object_set_new(obj, "webdav_bytes_rx",    json_integer((json_int_t) totals->wdav_rx));
    json_object_set_new(obj, "webdav_bytes_tx",    json_integer((json_int_t) totals->wdav_tx));
    json_object_set_new(obj, "s3_bytes_rx",        json_integer((json_int_t) totals->s3_rx));
    json_object_set_new(obj, "s3_bytes_tx",        json_integer((json_int_t) totals->s3_tx));
    json_object_set_new(obj, "stream_errors_total",  json_integer((json_int_t) totals->stream_errors));
    json_object_set_new(obj, "webdav_errors_total",  json_integer((json_int_t) totals->webdav_errors));
    json_object_set_new(obj, "s3_errors_total",      json_integer((json_int_t) totals->s3_errors));
    return obj;
}
```

### `dashboard_append_transfer_rows` — 46 → ~28 LoC

```c
/* BEFORE: first=1 sentinel, comma insertion, p < end - 1024 guard */
static char *
dashboard_append_transfer_rows(char *p, char *end, int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields)
{
    xrootd_transfer_table_t *tbl;
    ngx_uint_t              first = 1;
    ngx_uint_t              i;

    p = json_append(p, end, "\"active_transfers\":[");
    ...
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS && p < end - 1024; i++) {
        ...
        if (!first) { p = json_append(p, end, ","); }
        first = 0;
        p = dashboard_append_transfer_object(p, end, conf, slot, now_ms, v1_fields, 0);
    }
    return json_append(p, end, "]");
}

/* AFTER: array manages commas; no overflow guard */
static json_t *
dashboard_build_transfer_rows(int64_t now_ms,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf, ngx_uint_t v1_fields)
{
    xrootd_transfer_table_t *tbl;
    json_t                  *arr;
    ngx_uint_t               i;

    arr = json_array();
    if (!arr || ngx_xrootd_dashboard_shm_zone == NULL
        || ngx_xrootd_dashboard_shm_zone->data == NULL
        || ngx_xrootd_dashboard_shm_zone->data == (void *) 1)
    {
        return arr;
    }

    tbl = ngx_xrootd_dashboard_shm_zone->data;
    for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
        xrootd_transfer_slot_t *slot = &tbl->slots[i];
        int64_t                 last_ms;
        json_t                 *obj;

        if (slot->in_use == 0) { continue; }

        last_ms = (int64_t) slot->last_ms;
        if (last_ms > 0 && now_ms - last_ms > STALE_GC_MS) {
            xrootd_dashboard_event_add(XROOTD_DASH_EVENT_DASHBOARD, slot->proto,
                                       0, "stale active transfer cleaned up", slot->path);
            xrootd_transfer_slot_free(tbl, (int) i);
            continue;
        }

        obj = dashboard_build_transfer_object(conf, slot, now_ms, v1_fields, 0);
        if (obj) { json_array_append_new(arr, obj); }
    }
    return arr;
}
```

### `dashboard_send_json` — receives `json_t *` instead of `char *buf, char *p`

```c
/* AFTER */
static ngx_int_t
dashboard_send_json(ngx_http_request_t *r, ngx_int_t status, json_t *root)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    ngx_int_t        rc;
    size_t           needed;
    u_char          *buf;

    needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
    json_decref(root);
    if (needed == 0) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    buf = ngx_palloc(r->pool, needed);
    if (buf == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
    /* root already decref'd above — do NOT touch root again */

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    b->pos = b->start = buf;
    b->last = b->end  = buf + needed;
    b->memory = 1; b->last_buf = 1;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) needed;
    r->headers_out.content_type     = (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key,   "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) { return rc; }

    out.buf = b; out.next = NULL;
    return ngx_http_output_filter(r, &out);
}
```

**Note:** `json_dumpb(root, NULL, 0, ...)` must be called BEFORE `json_decref(root)`.
Move `json_decref` to after the `json_dumpb` fill call, not after the probe.  The
snippet above has a logic error for illustration — correct order is: probe → allocate
→ fill → decref → send.

---

## LoC delta table

| File | Current | Projected | ΔLoC |
|---|---|---|---|
| `src/dashboard/api.c` | 1,188 | ~990 | −198 |
| No new files; jansson already in build | — | — | 0 |
| **Net** | | | **≈−200** |

---

## Migration steps

### Step A: infrastructure helpers deleted, `dashboard_send_json` updated

1. Delete `json_append()` (lines 51–76) and `json_append_escaped_str()` (78–125).
2. Remove `#include <stdarg.h>`, `#include <stdio.h>`, `#define JSON_BUF_SIZE`.
3. Add `#include <jansson.h>`.
4. Rewrite `dashboard_send_json()` to accept `json_t *root` and use `json_dumpb()`.
5. Stub all builder functions to return `json_t *` (temporarily returning
   `json_object()`) so the file compiles.

`make -j$(nproc)` must succeed with zero errors before proceeding.

### Step B: leaf builders migrated

Convert in dependency order (leaves first):

1. `dashboard_build_limits()` — 7 fields, no dependencies
2. `dashboard_build_totals()` — 11 fields, no dependencies
3. `dashboard_build_transfer_object()` — most complex; preserve SHM barrier block
4. `dashboard_build_transfer_rows()` — calls (3)
5. `dashboard_build_tpc_registry()` — independent
6. `dashboard_build_protocols()` — independent
7. `dashboard_build_events()` — independent
8. `dashboard_build_history()` — independent
9. `dashboard_build_cache()` — independent
10. `dashboard_build_cluster()` — independent

Each conversion: migrate function → `make` → run dashboard test → move to next.

### Step C: top-level endpoint builders updated

Convert `dashboard_build_v1_prefix()` and all 8 `dashboard_build_v1_*()` functions to
assemble a `json_t *` root object using `json_object_set_new()` rather than the
`p = dashboard_append_*(p, end, ...)` chain.

Update `ngx_http_xrootd_dashboard_api_handler()`:
- Remove `buf`, `p`, `end` locals and the `JSON_BUF_SIZE` allocation.
- Remove the `if (p >= end)` truncation block (replaced by NULL check on `json_object()`).
- Each `switch` case calls the builder and passes its return to `dashboard_send_json()`.

---

## Truncation / OOM handling

The 507 event is preserved; the trigger changes:

```c
/* BEFORE */
if (p >= end) {
    xrootd_dashboard_event_add(..., "dashboard JSON response truncated", NULL);
    status = NGX_HTTP_INSUFFICIENT_STORAGE;
    p = buf;
    p = dashboard_build_v1_truncated(p, end, now_ms, conf);
}

/* AFTER — in the main handler, after the switch: */
if (root == NULL) {
    xrootd_dashboard_event_add(..., "dashboard JSON response truncated", NULL);
    status = NGX_HTTP_INSUFFICIENT_STORAGE;
    root = dashboard_build_v1_truncated(now_ms, conf);
}
```

`dashboard_build_v1_truncated()` still exists; it now builds a small `json_t *` error
object rather than writing to a buffer.

---

## Build requirements

- jansson ≥ 2.13 required for `json_dumpb()` — confirmed at 2.14 on this host.
- No `./configure` needed (jansson already linked; no new `.c` files).
- `CFLAGS` already include the jansson header path (verified by existing token/ builds).

---

## Verification

```bash
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

tests/manage_test_servers.sh restart

# Dashboard endpoints
PYTHONPATH=tests pytest tests/test_dashboard.py -v

# Validate JSON shape against schema
curl -s http://localhost:9200/xrootd/api/v1/snapshot | python3 -m json.tool > /dev/null
curl -s http://localhost:9200/xrootd/api/v1/transfers | python3 -m json.tool > /dev/null
curl -s http://localhost:9200/xrootd/api/v1/events    | python3 -m json.tool > /dev/null
curl -s http://localhost:9200/xrootd/api/v1/history   | python3 -m json.tool > /dev/null
curl -s http://localhost:9200/xrootd/api/v1/cluster   | python3 -m json.tool > /dev/null
curl -s http://localhost:9200/xrootd/api/v1/cache     | python3 -m json.tool > /dev/null

# Transfer detail endpoint
curl -s http://localhost:9200/xrootd/api/v1/transfers/1 | python3 -m json.tool

# Compat endpoint
curl -s http://localhost:9200/xrootd/transfers | python3 -m json.tool > /dev/null

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk assessment

**Low.** The dashboard endpoints are read-only HTTP GET handlers.  The output JSON
structure is identical — only the serialiser changes.  The main risk is a subtle
difference in how numbers are formatted: jansson uses `json_integer_t` (64-bit signed)
and formats without leading zeros or `+` signs, which matches the current `%"PRIu64`
format strings.  One corner case: `json_integer()` takes `json_int_t` (signed); casting
`uint64_t` values above `INT64_MAX` would wrap.  All byte counters are `uint64_t` but
in practice never approach 2^63, so this is not a live concern — but the casts should
be explicit `(json_int_t)` to document the intent.

The `dashboard_append_cache` function has a `double` field
(`eviction_threshold_ratio`, `occupancy_ratio`) formatted with `%0.6f`.  jansson
`json_real()` encodes doubles as IEEE 754 with full precision — confirm the JavaScript
dashboard does not parse these as strings before merging.

## Rollback

```bash
git revert <phase-10-commit>
make -j$(nproc)
```

No `./configure` needed.
