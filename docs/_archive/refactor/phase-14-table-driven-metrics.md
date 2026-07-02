# Phase 14 — Table-Driven Prometheus Export

**Target**: eliminate the per-block `# HELP / # TYPE / for-loop` duplication
in `src/observability/metrics/webdav.c` and `src/observability/metrics/s3.c` by introducing two helper
functions and moving two identical name tables to the existing shared header.

**Net LoC reduction**: ~65–75 LoC  
**Risk**: very low — mechanical replacement of identical patterns, zero logic
change  
**Requires**: `make -j$(nproc)` only — no new source files, no `./configure`

---

## Correction to original proposal

The original "Phase 14 — Table-driven Prometheus export (~200 LoC)" estimate
was wrong.  Reading the files reveals:

1. `stream.c` is structurally different: it iterates per-server slots with
   `{port="...",auth="..."}` label pairs and already has its own
   `XROOTD_EXPORT_SRV_COUNTER` macro (lines 235–276).  The helpers described
   here do not apply there.

2. The 2D `responses_total[method][status]` loop appears once in each file and
   requires two label keys.  A `mw_emit_2d_labeled()` helper would add ~15 LoC
   and save ~10 LoC across both files — net negative.  Leave these loops
   unchanged.

3. The DEPRECATED scalar blocks (`bytes_rx_total`, `bytes_tx_total` in both
   files) carry unique embedded comment text in the `mw_printf` call.  They
   are not identical to the plain scalar pattern and must remain unchanged.

What is genuinely duplicated:

| Pattern | Occurrences | LoC each | Total |
|---------|-------------|----------|-------|
| Single-label `for` loop (`auth`, `range`, `put`, `tpc`, …) | 13 × | 11 | 143 |
| Plain scalar (no DEPRECATED comment) | 10 × | 7 | 70 |
| Identical `status_names[]` table (webdav + s3) | 2 × | 8 | 16 |
| Identical `range_names[]` table (webdav + s3) | 2 × | 5 | 10 |

After replacement:

| Pattern | Per-call LoC | Total |
|---------|--------------|-------|
| `mw_emit_labeled(…)` call | 7 | 91 |
| `mw_emit_scalar(…)` call | 4 | 40 |
| Shared tables in `http_common.h` | — | 13 |
| New functions in `writer.c` + decls | +25 | — |

**Net: ~70 LoC** (original proposal assumed stream.c was also a target and
double-counted the 2D loop).

---

## Change A — two shared helper functions in `metrics/writer.c`

### `mw_emit_labeled()`

Replaces every single-label `# HELP / # TYPE / for` block.

**Add to `src/observability/metrics/writer.c`** (at the end of the file, before any
`#ifdef`-guarded epilogue if present):

```c
void
mw_emit_labeled(metrics_writer_t *mw, const char *name, const char *help,
    const char *label_key, const char * const *names, ngx_uint_t n,
    ngx_atomic_t *counters)
{
    ngx_uint_t  i;

    mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n", name, help, name);
    for (i = 0; i < n; i++) {
        mw_printf(mw, "%s{%s=\"%s\"} %lu\n", name, label_key, names[i],
                  (unsigned long) ngx_atomic_fetch_add(&counters[i], 0));
    }
}
```

**Constraint**: `counters` must be a contiguous `ngx_atomic_t[]` array so
pointer arithmetic `&counters[i]` is valid.  All current target arrays
(`auth_total[]`, `range_total[]`, etc.) satisfy this.  The 2D
`responses_total[method][status]` is NOT a target — see above.

### `mw_emit_scalar()`

Replaces every plain three-line scalar block.

**Add to `src/observability/metrics/writer.c`**:

```c
void
mw_emit_scalar(metrics_writer_t *mw, const char *name, const char *help,
    ngx_atomic_t *counter)
{
    mw_printf(mw, "# HELP %s %s\n# TYPE %s counter\n%s %lu\n",
              name, help, name,
              name, (unsigned long) ngx_atomic_fetch_add(counter, 0));
}
```

### Declarations

**Add to `src/observability/metrics/metrics_internal.h`** (after the existing `mw_printf`
declaration):

```c
void mw_emit_labeled(metrics_writer_t *mw, const char *name, const char *help,
    const char *label_key, const char * const *names, ngx_uint_t n,
    ngx_atomic_t *counters);
void mw_emit_scalar(metrics_writer_t *mw, const char *name, const char *help,
    ngx_atomic_t *counter);
```

**LoC accounting for Change A**:
```
mw_emit_labeled() function body:    +12 LoC
mw_emit_scalar() function body:     + 8 LoC
Two declarations:                   + 5 LoC
Total new code:                     +25 LoC
```

---

## Change B — shared name tables in `metrics/http_common.h`

`xrootd_http_status_names[]` is declared `static` in both `webdav.c` (lines
27–34) and `s3.c` (lines 32–39) with identical content.
`xrootd_webdav_range_names[]` and its s3 counterpart are also identical.

Move both to `src/observability/metrics/http_common.h`, which already exists as the shared
cross-protocol HTTP metrics header (it currently contains only
`xrootd_http_status_class()`).

**Add to `src/observability/metrics/http_common.h`** (after the `xrootd_http_status_class`
function):

```c
/*
 * Shared low-cardinality label strings used by both WebDAV and S3 metrics.
 * Both modules include this header, so the tables are defined once.
 */
static const char *xrootd_http_status_names[XROOTD_HTTP_NSTATUS] = {
    "1xx", "2xx", "3xx", "4xx", "5xx", "other",
};

static const char *xrootd_http_range_result_names[3] = {
    "full", "partial", "unsatisfied",
};
```

**Remove from `src/observability/metrics/webdav.c`**:
- Lines 27–34: `static const char *xrootd_http_status_names[...]` (8 LoC)
- Lines 44–48: `static const char *xrootd_webdav_range_names[...]` (5 LoC)
  — callers updated to use the shared name `xrootd_http_range_result_names`

**Remove from `src/observability/metrics/s3.c`**:
- Lines 32–39: `static const char *xrootd_s3_status_names[...]` (8 LoC)
  — callers updated to use `xrootd_http_status_names`
- The s3 range names table (5 LoC)
  — callers updated to use `xrootd_http_range_result_names`

**LoC accounting for Change B**:
```
http_common.h addition:          +13 LoC (8 + 5, single-line values)
webdav.c removal:                -13 LoC
s3.c removal:                    -13 LoC
Net:                             -13 LoC
```

---

## Change C — update `webdav.c` call sites

The 8 single-label loops and 5 non-deprecated scalars in `webdav.c`:

| Block | Pattern | Current LoC | Call LoC | Saved |
|-------|---------|-------------|----------|-------|
| `requests_total[method]` | labeled | 11 | 7 | 4 |
| `auth_total[i]` | labeled | 11 | 7 | 4 |
| `range_total[i]` | labeled | 11 | 7 | 4 |
| `put_body_total[i]` | labeled | 11 | 7 | 4 |
| `propfind_depth_total[i]` | labeled | 11 | 7 | 4 |
| `tpc_total[i]` | labeled | 11 | 7 | 4 |
| `cors_total[i]` | labeled | 11 | 7 | 4 |
| `tpc_cred_total[i]` | labeled | 11 | 7 | 4 |
| `bytes_rx_ipv4_total` | scalar | 7 | 4 | 3 |
| `bytes_tx_ipv4_total` | scalar | 7 | 4 | 3 |
| `bytes_rx_ipv6_total` | scalar | 7 | 4 | 3 |
| `bytes_tx_ipv6_total` | scalar | 7 | 4 | 3 |
| `propfind_entries_total` | scalar | 7 | 4 | 3 |

**webdav.c net savings: ~47 LoC**

Before/after example for `auth_total`:

```c
/* BEFORE (11 LoC) */
    mw_printf(mw,
        "# HELP xrootd_webdav_auth_total "
            "WebDAV authentication outcomes.\n"
        "# TYPE xrootd_webdav_auth_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NAUTH_RESULTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_auth_total{result=\"%s\"} %lu\n",
            xrootd_webdav_auth_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.auth_total[i], 0));
    }

/* AFTER (7 LoC) */
    mw_emit_labeled(mw,
        "xrootd_webdav_auth_total",
        "WebDAV authentication outcomes.",
        "result",
        xrootd_webdav_auth_names, XROOTD_WEBDAV_NAUTH_RESULTS,
        shm->webdav.auth_total);
```

**Leave unchanged in `webdav.c`**:
- `responses_total[method][status]` — 2D loop, two label keys, no suitable helper
- `bytes_rx_total` — DEPRECATED comment embedded in `mw_printf` call
- `bytes_tx_total` — same

---

## Change D — update `s3.c` call sites

The 5 single-label loops and 5 non-deprecated scalars in `s3.c`:

| Block | Pattern | Saved |
|-------|---------|-------|
| `requests_total[method]` | labeled | 4 |
| `auth_total[i]` | labeled | 4 |
| `range_total[i]` | labeled | 4 |
| `put_body_total[i]` | labeled | 4 |
| `events_total[i]` | labeled | 4 |
| `bytes_rx_ipv4_total` | scalar | 3 |
| `bytes_tx_ipv4_total` | scalar | 3 |
| `list_contents_total` | scalar | 3 |
| `list_common_prefixes_total` | scalar | 3 |
| `list_truncated_total` | scalar | 3 |

**s3.c net savings: ~35 LoC** (plus 13 LoC from removed duplicate tables in
Change B)

**Leave unchanged in `s3.c`**:
- `responses_total[method][status]` — 2D loop
- `bytes_rx_total` — DEPRECATED
- `bytes_tx_total` — DEPRECATED

---

## What NOT to change

| Target | Reason |
|--------|--------|
| `stream.c` | Per-server-slot iteration with two-label (`port`,`auth`) pattern; structurally different; already has `XROOTD_EXPORT_SRV_COUNTER` |
| 2D `responses_total` loops | A 2D helper would cost more LoC than it saves |
| DEPRECATED scalar blocks | Embedded comment text inside `mw_printf` makes them non-identical to the plain scalar pattern |
| `metrics_macros.h` | Call-site increment macros; orthogonal to export formatting |

---

## Honest LoC accounting

```
Change A (mw_emit_labeled + mw_emit_scalar + decls):  +25 LoC
Change B (shared tables moved to http_common.h):      −13 LoC
Change C (webdav.c labeled + scalar sites):           −47 LoC
Change D (s3.c labeled + scalar + table removal):     −48 LoC
────────────────────────────────────────────────────────────
Net code reduction:                                   −83 LoC
```

Uncertainty ±15 LoC depending on actual blank-line and comment counts
around each block in the current files.

---

## Implementation steps

1. **Verify shared table content** — confirm byte-for-byte that
   `xrootd_http_status_names[]` in `webdav.c` and `xrootd_s3_status_names[]`
   in `s3.c` are identical; same for range names.

2. **Add shared tables to `http_common.h`** (Change B, additions only).

3. **Add helpers to `writer.c`** and declarations to `metrics_internal.h`
   (Change A).

4. **Build** — `make -j$(nproc)`.  The new symbols must compile before
   updating callers.

5. **Update `webdav.c`** (Change C):
   - Replace 8 labeled loops + 5 scalars with helper calls.
   - Remove the now-duplicate `xrootd_http_status_names[]` and
     `xrootd_webdav_range_names[]` definitions; update references to use
     `xrootd_http_range_result_names`.

6. **Update `s3.c`** (Change D):
   - Replace 5 labeled loops + 5 scalars with helper calls.
   - Remove `xrootd_s3_status_names[]` and the s3 range names table; update
     references to use `xrootd_http_status_names` and
     `xrootd_http_range_result_names`.

7. **Build and test**:
   ```bash
   make -j$(nproc)
   /tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
   PYTHONPATH=tests pytest tests/test_dashboard.py -v
   PYTHONPATH=tests pytest tests/ -k "metric" -v
   ```

---

## Tests (minimum 3)

No new tests are needed — no logic changes.  After the changes, run:

```bash
# Prometheus scrape roundtrip — verifies all metric names/labels are intact
PYTHONPATH=tests pytest tests/test_dashboard.py -v

# WebDAV operations to generate counter values, then scrape
PYTHONPATH=tests pytest tests/ -k "webdav" -v

# S3 operations to generate counter values, then scrape
PYTHONPATH=tests pytest tests/ -k "s3" -v
```

A manual sanity check is also recommended: after starting the test servers,
`curl http://localhost:9100/metrics | grep -E "^# (HELP|TYPE)"` and confirm
all expected metric families are still present with correct names.

---

## Relationship to overall 10% target

This phase contributes **~83 LoC net** to the 10% reduction goal — the
largest single contributor among phases 12–14.  Its primary value is:

- Establishing `mw_emit_labeled()` and `mw_emit_scalar()` as canonical helpers
  so future metrics additions (new auth types, new event names) require one
  call instead of an 11-line block
- Eliminating two duplicate static name tables that diverged silently
  (`xrootd_s3_status_names` could have been updated independently of
  `xrootd_http_status_names` since they had different identifiers)
- Reducing `webdav.c` from ~270 LoC to ~220 LoC and `s3.c` from ~235 LoC to
  ~190 LoC — both files fit more comfortably in a single read
