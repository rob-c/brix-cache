# Bulk Storage Scan / Verify / Fill — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an admin-grade bulk storage auditor — enumerate a confined export subtree and per object dump metadata + stored checksum, verify stored-vs-recomputed, backfill missing checksums, or feed a client-side compare — streamed as NDJSON over an admin HTTP endpoint, throttled to protect the backend (esp. CEPH).

**Architecture:** A protocol-agnostic, ngx-free engine in `src/scan/` (throttle + NDJSON + per-object action + resumable walk) driven by one nginx-coupled HTTP handler (`scan_http.c`) that streams results with backpressure via the native HTTP thread-pool pattern. A thin clean-room client (`xrdstorascan`) wraps the endpoint. All FS access goes through `xrootd_vfs_*`/`obj->driver->*` and the existing `XrdCksData` codec, so it inherits stock-XrdCeph byte-compatibility for free.

**Tech Stack:** C (nginx HTTP module conventions), nginx thread pool, `xrootd_vfs_walk`, `xrootd_integrity_get_fd`, `xrootd_cksdata_decode/encode`, libxrdc/HTTP client.

**Spec:** `docs/superpowers/specs/2026-06-29-storage-scan-verify-design.md`

## Global Constraints

- **No `goto`** anywhere in `src/`, `shared/`, `client/`. Early-return + helper decomposition only.
- **Functional/modular:** one job per function, explicit state (no new globals), section-level WHAT/WHY/HOW doc block on every function.
- **VFS seam (INVARIANT 11):** zero raw libc FS calls in `src/scan/`. Use `xrootd_vfs_walk`, `xrootd_vfs_open_fd_at`, `xrootd_vfs_fgetxattr`, `xrootd_integrity_get_fd`. No `rados_*` symbol above `src/fs/backend/`.
- **Byte-compatible with stock XrdCeph** (`/tmp/xrootd-src/src/XrdCeph`): bytes via `obj->driver->pread` (must be libradosstriper-backed for Ceph verify/fill — gated, Task 8); stored checksum is the binary `XrdCksData` blob in `XrdCks.<alg>` via `xrootd_cksdata_decode/encode`; honor `fmTime` staleness (`stale` ≠ `mismatch`).
- **3 tests per change:** success + error + security-negative.
- **Build:** new `.c`/`.h` files register in the top-level `./config` (`$ngx_addon_dir/src/scan/*.c`), NOT `src/config/config.h`. After adding a new source file: `rm -rf objs && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)`. Incremental edits: `make -j$(nproc)` only. NEVER `./configure` over a stale `objs/` (mixed-ABI SIGSEGV).
- **Metrics:** low-cardinality only — no paths/algorithms/reqids as labels.
- **NEVER run git** without explicit user instruction. The `git commit` steps below are written for completeness; the executor must obtain the user's go-ahead before running any git command (project hard rule).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/scan/scan_throttle.h/.c` | Pure token bucket: concurrency gate, byte-rate leaky bucket, adaptive multiplier, budget. ngx-free. |
| `src/scan/scan_record.h/.c` | Pure NDJSON formatters: `file`/`cursor`/`summary` records into a caller buffer. ngx-free. |
| `src/scan/scan_engine.h/.c` | Engine: opts/stats types, mode enum, per-object action, resumable walk + emit callback. ngx-free (takes `rootfd`, `ngx_log_t*`). |
| `src/scan/scan_engine_unittest.c` | Standalone gcc unit test (pattern: `src/fs/backend/csi_unittest.c`). |
| `src/scan/scan_http.c` | nginx HTTP handler: route, admin auth, param parse, confinement, thread-pool batch drive, chunked NDJSON output. Only ngx-coupled file. |
| `src/scan/README.md` | Module doc. |
| `src/config/config.h` | `xrootd_scan*` loc-conf fields. |
| `src/config/directives.c` | `xrootd_scan*` `ngx_command_t` + merge. |
| `src/dashboard/module.c` | Route `/xrootd/api/v1/scan` → `scan_http` handler. |
| `client/tools/xrdstorascan.c` | Clean-room client wrapper. |
| `client/Makefile` | Build `xrdstorascan`. |
| `tests/test_scan.py` | Integration + security-neg suite. |
| `config` (top-level) | Register new `src/scan/*.c` sources. |

---

## Task 1: Throttle token bucket (`scan_throttle`)

**Files:**
- Create: `src/scan/scan_throttle.h`, `src/scan/scan_throttle.c`
- Create: `src/scan/scan_engine_unittest.c` (start the standalone harness here; extended in later tasks)
- Modify: top-level `config` (add `src/scan/scan_throttle.c`)

**Interfaces:**
- Produces:
  - `typedef struct { uint32_t parallel; uint64_t max_rate; int adaptive; uint64_t max_bytes; uint64_t max_seconds; } xrootd_scan_limits_t;`
  - `typedef struct xrootd_scan_throttle_s xrootd_scan_throttle_t;`
  - `void xrootd_scan_throttle_init(xrootd_scan_throttle_t *t, const xrootd_scan_limits_t *lim, uint64_t now_ms);`
  - `uint64_t xrootd_scan_throttle_delay_ms(xrootd_scan_throttle_t *t, uint64_t want_bytes, uint64_t now_ms);` — ms to wait before reading `want_bytes` (0 = go now); accounts for byte-rate × adaptive multiplier.
  - `void xrootd_scan_throttle_charge(xrootd_scan_throttle_t *t, uint64_t bytes, uint64_t now_ms);` — record bytes actually read.
  - `void xrootd_scan_throttle_set_pressure(xrootd_scan_throttle_t *t, double foreground, double latency_ewma_ms);` — feed adaptive inputs; recomputes multiplier in `[0.1,1.0]`.
  - `int xrootd_scan_throttle_budget_hit(const xrootd_scan_throttle_t *t, uint64_t now_ms);` — 1 when `max_bytes` or `max_seconds` exceeded.

- [ ] **Step 1: Write the failing test** — append to `src/scan/scan_engine_unittest.c`:

```c
/* scan_engine_unittest.c — standalone unit tests for the ngx-free scan cores.
 * Build: gcc -I src/scan -o /tmp/scan_ut src/scan/scan_engine_unittest.c \
 *            src/scan/scan_throttle.c && /tmp/scan_ut
 * (extended in later tasks with record + engine-action cases). */
#include "scan_throttle.h"
#include <assert.h>
#include <stdio.h>

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static void test_throttle_byterate(void)
{
    xrootd_scan_limits_t lim = { .parallel = 1, .max_rate = 1000 /*B/s*/,
                                 .adaptive = 0, .max_bytes = 0, .max_seconds = 0 };
    xrootd_scan_throttle_t t;
    xrootd_scan_throttle_init(&t, &lim, 0);

    /* Fresh bucket: a 500-byte read fits in the first second → no delay. */
    CHECK(xrootd_scan_throttle_delay_ms(&t, 500, 0) == 0);
    xrootd_scan_throttle_charge(&t, 1000, 0);          /* spend the whole second */
    /* Now over budget for this second: another 1000 B must wait ~1000 ms. */
    CHECK(xrootd_scan_throttle_delay_ms(&t, 1000, 0) >= 900);
    /* One second later the bucket refilled. */
    CHECK(xrootd_scan_throttle_delay_ms(&t, 1000, 1000) == 0);
}

static void test_throttle_unlimited_and_budget(void)
{
    xrootd_scan_limits_t lim = { .parallel = 4, .max_rate = 0, .adaptive = 0,
                                 .max_bytes = 0, .max_seconds = 5 };
    xrootd_scan_throttle_t t;
    xrootd_scan_throttle_init(&t, &lim, 1000);
    CHECK(xrootd_scan_throttle_delay_ms(&t, 1u << 30, 1000) == 0);  /* rate 0 = unlimited */
    CHECK(xrootd_scan_throttle_budget_hit(&t, 2000) == 0);          /* 1s elapsed < 5s */
    CHECK(xrootd_scan_throttle_budget_hit(&t, 7000) == 1);          /* 6s elapsed > 5s */
}

static void test_throttle_adaptive(void)
{
    xrootd_scan_limits_t lim = { .parallel = 8, .max_rate = 1000, .adaptive = 1,
                                 .max_bytes = 0, .max_seconds = 0 };
    xrootd_scan_throttle_t t;
    xrootd_scan_throttle_init(&t, &lim, 0);
    uint64_t d_calm = xrootd_scan_throttle_delay_ms(&t, 1000, 0);
    xrootd_scan_throttle_charge(&t, 1000, 0);
    xrootd_scan_throttle_set_pressure(&t, 1.0 /*busy*/, 500.0 /*slow*/);
    uint64_t d_busy = xrootd_scan_throttle_delay_ms(&t, 1000, 0);
    CHECK(d_busy > d_calm);   /* pressure shrinks the effective rate → longer wait */
}

int main(void)
{
    test_throttle_byterate();
    test_throttle_unlimited_and_budget();
    test_throttle_adaptive();
    printf(failures ? "FAILED (%d)\n" : "OK\n", failures);
    return failures ? 1 : 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -I src/scan -o /tmp/scan_ut src/scan/scan_engine_unittest.c src/scan/scan_throttle.c && /tmp/scan_ut`
Expected: FAIL — `scan_throttle.h` / `scan_throttle.c` do not exist (compile error).

- [ ] **Step 3: Write `src/scan/scan_throttle.h`**

```c
#ifndef XROOTD_SCAN_THROTTLE_H
#define XROOTD_SCAN_THROTTLE_H

#include <stdint.h>

/*
 * scan/scan_throttle.h — pure (ngx-free) backend-protection token bucket.
 *
 * WHAT: bounds a bulk scan's backend read load by three composable controls —
 *       a byte-rate leaky bucket, an adaptive multiplier driven by foreground
 *       pressure + backend latency, and a wall-clock/bytes budget. The
 *       concurrency cap (parallel) is stored here but enforced by the caller's
 *       worker-pool sizing. WHY: a verify/fill sweep must never melt the backend
 *       (esp. CEPH/RADOS read IOPS). HOW: monotonic-ms accounting; delay_ms()
 *       tells a worker how long to sleep before reading want_bytes.
 */

typedef struct {
    uint32_t parallel;       /* max concurrent byte-reading workers (caller sizes pool) */
    uint64_t max_rate;       /* bytes/sec ceiling (0 = unlimited)                        */
    int      adaptive;       /* 1 = apply pressure/latency multiplier                    */
    uint64_t max_bytes;      /* stop after this many bytes read (0 = none)               */
    uint64_t max_seconds;    /* stop after this wall-clock (0 = none)                    */
} xrootd_scan_limits_t;

typedef struct xrootd_scan_throttle_s {
    xrootd_scan_limits_t lim;
    uint64_t start_ms;
    uint64_t window_start_ms;   /* current 1-second accounting window start */
    uint64_t bytes_this_window; /* bytes charged in the current window      */
    uint64_t bytes_total;       /* lifetime bytes (for budget)              */
    double   multiplier;        /* adaptive [0.1, 1.0]                      */
} xrootd_scan_throttle_t;

void     xrootd_scan_throttle_init(xrootd_scan_throttle_t *t,
             const xrootd_scan_limits_t *lim, uint64_t now_ms);
uint64_t xrootd_scan_throttle_delay_ms(xrootd_scan_throttle_t *t,
             uint64_t want_bytes, uint64_t now_ms);
void     xrootd_scan_throttle_charge(xrootd_scan_throttle_t *t,
             uint64_t bytes, uint64_t now_ms);
void     xrootd_scan_throttle_set_pressure(xrootd_scan_throttle_t *t,
             double foreground, double latency_ewma_ms);
int      xrootd_scan_throttle_budget_hit(const xrootd_scan_throttle_t *t,
             uint64_t now_ms);

#endif /* XROOTD_SCAN_THROTTLE_H */
```

- [ ] **Step 4: Write `src/scan/scan_throttle.c`**

```c
/*
 * scan/scan_throttle.c — see scan_throttle.h. Pure, no nginx, no allocation.
 */
#include "scan_throttle.h"

/* Initialise the bucket at now_ms; multiplier starts at full (1.0). */
void
xrootd_scan_throttle_init(xrootd_scan_throttle_t *t,
    const xrootd_scan_limits_t *lim, uint64_t now_ms)
{
    t->lim = *lim;
    t->start_ms = now_ms;
    t->window_start_ms = now_ms;
    t->bytes_this_window = 0;
    t->bytes_total = 0;
    t->multiplier = 1.0;
}

/* Effective bytes/sec after the adaptive multiplier (0 stays unlimited). */
static uint64_t
throttle_effective_rate(const xrootd_scan_throttle_t *t)
{
    if (t->lim.max_rate == 0) {
        return 0;
    }
    if (!t->lim.adaptive) {
        return t->lim.max_rate;
    }
    double r = (double) t->lim.max_rate * t->multiplier;
    return r < 1.0 ? 1 : (uint64_t) r;
}

/* Roll the 1-second window forward if now_ms has crossed it. */
static void
throttle_roll_window(xrootd_scan_throttle_t *t, uint64_t now_ms)
{
    if (now_ms >= t->window_start_ms + 1000) {
        t->window_start_ms = now_ms;
        t->bytes_this_window = 0;
    }
}

/* ms to wait before reading want_bytes; 0 when within this window's allowance. */
uint64_t
xrootd_scan_throttle_delay_ms(xrootd_scan_throttle_t *t,
    uint64_t want_bytes, uint64_t now_ms)
{
    uint64_t rate;

    throttle_roll_window(t, now_ms);
    rate = throttle_effective_rate(t);
    if (rate == 0) {
        return 0;   /* unlimited */
    }
    if (t->bytes_this_window < rate) {
        return 0;   /* allowance remains in this window */
    }
    /* Window spent: wait until the next window boundary. */
    {
        uint64_t elapsed = now_ms - t->window_start_ms;
        return elapsed >= 1000 ? 0 : (1000 - elapsed);
    }
}

/* Record bytes actually read. */
void
xrootd_scan_throttle_charge(xrootd_scan_throttle_t *t,
    uint64_t bytes, uint64_t now_ms)
{
    throttle_roll_window(t, now_ms);
    t->bytes_this_window += bytes;
    t->bytes_total += bytes;
}

/* Recompute the adaptive multiplier from foreground request pressure (0..1+)
 * and a backend read-latency EWMA in ms. Both rising shrink the multiplier
 * toward the 0.1 floor; idle + fast restores it toward 1.0. */
void
xrootd_scan_throttle_set_pressure(xrootd_scan_throttle_t *t,
    double foreground, double latency_ewma_ms)
{
    double m = 1.0;

    if (foreground > 0.0) {
        m /= (1.0 + foreground);             /* busy server → back off */
    }
    if (latency_ewma_ms > 50.0) {
        m *= 50.0 / latency_ewma_ms;         /* slow backend → back off */
    }
    if (m < 0.1) {
        m = 0.1;
    }
    if (m > 1.0) {
        m = 1.0;
    }
    t->multiplier = m;
}

/* 1 when a configured byte or time budget has been exceeded. */
int
xrootd_scan_throttle_budget_hit(const xrootd_scan_throttle_t *t, uint64_t now_ms)
{
    if (t->lim.max_bytes && t->bytes_total >= t->lim.max_bytes) {
        return 1;
    }
    if (t->lim.max_seconds && (now_ms - t->start_ms) >= t->lim.max_seconds * 1000) {
        return 1;
    }
    return 0;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `gcc -I src/scan -o /tmp/scan_ut src/scan/scan_engine_unittest.c src/scan/scan_throttle.c && /tmp/scan_ut`
Expected: `OK`

- [ ] **Step 6: Register source + commit**

Add `$ngx_addon_dir/src/scan/scan_throttle.c` to the source list in the top-level `config` (next to the other module sources). Then (with user go-ahead):

```bash
git add src/scan/scan_throttle.h src/scan/scan_throttle.c src/scan/scan_engine_unittest.c config
git commit -m "feat(scan): backend-protection throttle token bucket + unit tests"
```

---

## Task 2: NDJSON record formatter (`scan_record`)

**Files:**
- Create: `src/scan/scan_record.h`, `src/scan/scan_record.c`
- Modify: `src/scan/scan_engine_unittest.c` (add record cases + link `scan_record.c`)
- Modify: top-level `config`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `typedef enum { XROOTD_SCAN_OK, XROOTD_SCAN_MISMATCH, XROOTD_SCAN_STALE, XROOTD_SCAN_MISSING, XROOTD_SCAN_UNREADABLE, XROOTD_SCAN_FILLED, XROOTD_SCAN_ALREADY } xrootd_scan_status_t;`
  - `typedef struct { const char *path; uint64_t size; int64_t mtime; const char *alg; const char *stored; int64_t cks_mtime; /* -1 = none */ const char *computed; /* NULL when absent */ xrootd_scan_status_t status; } xrootd_scan_file_rec_t;`
  - `typedef struct { uint64_t files, bytes, ok, mismatch, stale, missing, unreadable, filled; double elapsed_s; } xrootd_scan_summary_t;`
  - `int xrootd_scan_record_file(const xrootd_scan_file_rec_t *rec, char *out, size_t outsz);` — JSON-escapes `path`; returns bytes written (incl trailing `\n`), or 0 on overflow.
  - `int xrootd_scan_record_cursor(const char *after, char *out, size_t outsz);`
  - `int xrootd_scan_record_summary(const xrootd_scan_summary_t *s, char *out, size_t outsz);`
  - `const char *xrootd_scan_status_str(xrootd_scan_status_t st);`

- [ ] **Step 1: Write the failing test** — append cases + main wiring in `scan_engine_unittest.c`:

```c
/* add near top: */
#include "scan_record.h"
#include <string.h>

static void test_record_file_ok(void)
{
    xrootd_scan_file_rec_t rec = {
        .path = "/atlas/x.root", .size = 12345, .mtime = 1719600000,
        .alg = "adler32", .stored = "a1b2c3d4", .cks_mtime = 1719600000,
        .computed = "a1b2c3d4", .status = XROOTD_SCAN_OK };
    char buf[512];
    int n = xrootd_scan_record_file(&rec, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "\"t\":\"file\"") != NULL);
    CHECK(strstr(buf, "\"status\":\"ok\"") != NULL);
    CHECK(strstr(buf, "\"stored\":\"a1b2c3d4\"") != NULL);
    CHECK(buf[n - 1] == '\n');
}

static void test_record_file_escapes_and_nulls(void)
{
    xrootd_scan_file_rec_t rec = {
        .path = "/a\"b\\c/\t.root", .size = 1, .mtime = 1,
        .alg = "crc32c", .stored = NULL, .cks_mtime = -1,
        .computed = NULL, .status = XROOTD_SCAN_MISSING };
    char buf[512];
    int n = xrootd_scan_record_file(&rec, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "\\\"b\\\\c") != NULL);     /* quote + backslash escaped */
    CHECK(strstr(buf, "\"stored\":null") != NULL);
    CHECK(strstr(buf, "\"status\":\"missing\"") != NULL);
}

static void test_record_overflow(void)
{
    xrootd_scan_file_rec_t rec = { .path = "/x", .alg = "adler32",
        .cks_mtime = -1, .status = XROOTD_SCAN_OK };
    char tiny[8];
    CHECK(xrootd_scan_record_file(&rec, tiny, sizeof(tiny)) == 0);  /* skip, no truncation */
}
```
Add `test_record_file_ok(); test_record_file_escapes_and_nulls(); test_record_overflow();` to `main()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -I src/scan -o /tmp/scan_ut src/scan/scan_engine_unittest.c src/scan/scan_throttle.c src/scan/scan_record.c && /tmp/scan_ut`
Expected: FAIL — `scan_record.h`/`.c` missing.

- [ ] **Step 3: Write `src/scan/scan_record.h`** — the types + prototypes from the Interfaces block above, wrapped in an include guard `XROOTD_SCAN_RECORD_H`, each with a one-line WHAT comment.

- [ ] **Step 4: Write `src/scan/scan_record.c`**

```c
/*
 * scan/scan_record.c — NDJSON line formatters for scan results. Pure: writes
 * into a caller buffer, returns 0 (skip) on overflow rather than truncating, so
 * a partial JSON object is never emitted. JSON-escapes the path (the only
 * field carrying arbitrary bytes); algorithm/status are from fixed vocabularies.
 */
#include "scan_record.h"
#include <stdio.h>
#include <string.h>

const char *
xrootd_scan_status_str(xrootd_scan_status_t st)
{
    switch (st) {
    case XROOTD_SCAN_OK:         return "ok";
    case XROOTD_SCAN_MISMATCH:   return "mismatch";
    case XROOTD_SCAN_STALE:      return "stale";
    case XROOTD_SCAN_MISSING:    return "missing";
    case XROOTD_SCAN_UNREADABLE: return "unreadable";
    case XROOTD_SCAN_FILLED:     return "filled";
    case XROOTD_SCAN_ALREADY:    return "already";
    default:                     return "unknown";
    }
}

/* Append a JSON-escaped string into out[*pos..outsz). Returns 0 on overflow. */
static int
json_escape(const char *s, char *out, size_t outsz, size_t *pos)
{
    size_t i;

    for (i = 0; s && s[i]; i++) {
        unsigned char c = (unsigned char) s[i];
        char esc[8];
        const char *rep = esc;
        size_t rlen;

        switch (c) {
        case '"':  rep = "\\\""; rlen = 2; break;
        case '\\': rep = "\\\\"; rlen = 2; break;
        case '\n': rep = "\\n";  rlen = 2; break;
        case '\t': rep = "\\t";  rlen = 2; break;
        case '\r': rep = "\\r";  rlen = 2; break;
        default:
            if (c < 0x20) {
                rlen = (size_t) snprintf(esc, sizeof(esc), "\\u%04x", c);
            } else {
                esc[0] = (char) c; rlen = 1;
            }
        }
        if (*pos + rlen >= outsz) {
            return 0;
        }
        memcpy(out + *pos, rep, rlen);
        *pos += rlen;
    }
    return 1;
}

int
xrootd_scan_record_file(const xrootd_scan_file_rec_t *rec, char *out, size_t outsz)
{
    size_t pos = 0;
    int    n;

    n = snprintf(out, outsz, "{\"t\":\"file\",\"path\":\"");
    if (n < 0 || (size_t) n >= outsz) {
        return 0;
    }
    pos = (size_t) n;
    if (!json_escape(rec->path, out, outsz, &pos)) {
        return 0;
    }
    n = snprintf(out + pos, outsz - pos,
        "\",\"size\":%llu,\"mtime\":%lld,\"alg\":\"%s\"",
        (unsigned long long) rec->size, (long long) rec->mtime,
        rec->alg ? rec->alg : "");
    if (n < 0 || (size_t) n >= outsz - pos) {
        return 0;
    }
    pos += (size_t) n;

    if (rec->stored) {
        n = snprintf(out + pos, outsz - pos, ",\"stored\":\"%s\"", rec->stored);
    } else {
        n = snprintf(out + pos, outsz - pos, ",\"stored\":null");
    }
    if (n < 0 || (size_t) n >= outsz - pos) { return 0; }
    pos += (size_t) n;

    if (rec->cks_mtime >= 0) {
        n = snprintf(out + pos, outsz - pos, ",\"cks_mtime\":%lld",
                     (long long) rec->cks_mtime);
    } else {
        n = snprintf(out + pos, outsz - pos, ",\"cks_mtime\":null");
    }
    if (n < 0 || (size_t) n >= outsz - pos) { return 0; }
    pos += (size_t) n;

    if (rec->computed) {
        n = snprintf(out + pos, outsz - pos, ",\"computed\":\"%s\"", rec->computed);
        if (n < 0 || (size_t) n >= outsz - pos) { return 0; }
        pos += (size_t) n;
    }
    n = snprintf(out + pos, outsz - pos, ",\"status\":\"%s\"}\n",
                 xrootd_scan_status_str(rec->status));
    if (n < 0 || (size_t) n >= outsz - pos) { return 0; }
    pos += (size_t) n;
    return (int) pos;
}

int
xrootd_scan_record_cursor(const char *after, char *out, size_t outsz)
{
    size_t pos;
    int    n = snprintf(out, outsz, "{\"t\":\"cursor\",\"after\":\"");
    if (n < 0 || (size_t) n >= outsz) { return 0; }
    pos = (size_t) n;
    if (!json_escape(after, out, outsz, &pos)) { return 0; }
    n = snprintf(out + pos, outsz - pos, "\"}\n");
    if (n < 0 || (size_t) n >= outsz - pos) { return 0; }
    return (int) (pos + (size_t) n);
}

int
xrootd_scan_record_summary(const xrootd_scan_summary_t *s, char *out, size_t outsz)
{
    int n = snprintf(out, outsz,
        "{\"t\":\"summary\",\"files\":%llu,\"bytes\":%llu,\"ok\":%llu,"
        "\"mismatch\":%llu,\"stale\":%llu,\"missing\":%llu,\"unreadable\":%llu,"
        "\"filled\":%llu,\"elapsed_s\":%.1f}\n",
        (unsigned long long) s->files, (unsigned long long) s->bytes,
        (unsigned long long) s->ok, (unsigned long long) s->mismatch,
        (unsigned long long) s->stale, (unsigned long long) s->missing,
        (unsigned long long) s->unreadable, (unsigned long long) s->filled,
        s->elapsed_s);
    return (n < 0 || (size_t) n >= outsz) ? 0 : n;
}
```

- [ ] **Step 5: Run test to verify it passes** — same command as Step 2 → `OK`.

- [ ] **Step 6: Register `src/scan/scan_record.c` in top-level `config`; commit** (with go-ahead):

```bash
git add src/scan/scan_record.h src/scan/scan_record.c src/scan/scan_engine_unittest.c config
git commit -m "feat(scan): NDJSON record formatters + unit tests"
```

---

## Task 3: Engine types + per-object action (`scan_engine` part 1)

**Files:**
- Create: `src/scan/scan_engine.h`, `src/scan/scan_engine.c`
- Modify: `src/scan/scan_engine_unittest.c` (action cases against a temp fixture tree), top-level `config`

**Interfaces:**
- Consumes: `scan_record.h` (status/rec types), `scan_throttle.h`, VFS (`src/fs/vfs.h`: `xrootd_vfs_open_fd_at`, `xrootd_vfs_fgetxattr`), integrity (`src/compat/integrity_info.h`: `xrootd_integrity_get_fd`, `xrootd_cksdata_decode`, `xrootd_integrity_info_t`, `xrootd_integrity_opts_t`).
- Produces:
  - `typedef enum { XROOTD_SCAN_MODE_DUMP, XROOTD_SCAN_MODE_VERIFY, XROOTD_SCAN_MODE_FILL, XROOTD_SCAN_MODE_COMPARE } xrootd_scan_mode_t;`
  - `typedef struct { xrootd_scan_mode_t mode; char alg[16]; int rootfd; } xrootd_scan_action_ctx_t;`
  - `xrootd_scan_status_t xrootd_scan_action_one(ngx_log_t *log, const xrootd_scan_action_ctx_t *a, const char *logical, const xrootd_vfs_stat_t *st, xrootd_scan_file_rec_t *rec_out, char *stored_buf, char *computed_buf, uint64_t *bytes_read_out);` — runs the mode action on one already-walked file; fills `rec_out` (pointing into the two caller buffers); `*bytes_read_out` = bytes the backend served (0 for dump/compare).

- [ ] **Step 1: Write the failing test** — a fixture-tree action case in `scan_engine_unittest.c`. Because the action needs nginx types (`ngx_log_t`, `xrootd_vfs_stat_t`), this case compiles only in the in-tree build, so guard it:

```c
#ifdef XROOTD_SCAN_UT_NGX
/* Linked against the full module objects; exercises xrootd_scan_action_one
 * over a real temp file with a known adler32 + an XrdCks.adler32 xattr. */
static void test_action_verify_ok(void) { /* see Step 3 for the asserted flow */ }
#endif
```
The pure throttle/record tests stay in the default standalone build; the action test runs via a dedicated target added in Step 5.

- [ ] **Step 2: Run** the standalone build (unchanged) to confirm it still passes, and confirm the new `scan_engine.c` is required by the in-tree build (it won't link until written). Expected: standalone `OK`; in-tree references unresolved.

- [ ] **Step 3: Write `src/scan/scan_engine.h` + the action in `scan_engine.c`.** `xrootd_scan_action_one`:
  1. **dump/compare:** read `XrdCks.<alg>` via `xrootd_vfs_fgetxattr` on an `xrootd_vfs_open_fd_at(rootfd, logical, O_RDONLY|O_NOFOLLOW, ...)` fd; `xrootd_cksdata_decode(buf,len, st->mtime, &info)` → on success `stored=info.hex`, `cks_mtime=info` fmTime, status `OK` (or `STALE` flag surfaced via `cks_mtime != st->mtime`); on absent xattr `stored=NULL, cks_mtime=-1`. No byte read. `*bytes_read_out=0`.
  2. **verify:** read stored as above; then `xrootd_integrity_get_fd(log, fd, st->obj, logical, alg, &{allow_xattr_cache:0, update_xattr_cache:0, require_regular_file:1, no_compute:0}, &computed)`. Compare: no stored → `MISSING`; stored present but `fmTime != st->mtime` → `STALE`; `computed.hex == stored` → `OK` else `MISMATCH`; open/read error → `UNREADABLE`. `*bytes_read_out = st->size`.
  3. **fill:** read stored; if present and fresh → `ALREADY`; else `xrootd_integrity_get_fd(..., {update_xattr_cache:1, ...})` to compute+persist → `FILLED`; error → `UNREADABLE`. `*bytes_read_out = st->size` only when it computed.
  Copy `info.hex`/`computed.hex` into `stored_buf`/`computed_buf` (≥129 bytes) and point `rec_out` at them (no dangling stack pointers).

- [ ] **Step 4: Build the module** incrementally: `make -j$(nproc)` (after `./configure` re-run because new sources were added in Tasks 1–2; if not yet reconfigured, `rm -rf objs && ./configure ... && make`). Expected: clean compile.

- [ ] **Step 5: In-tree action test.** Add a small test runner `tests/test_scan_action.sh` that compiles `scan_engine_unittest.c` with `-DXROOTD_SCAN_UT_NGX` against the built objects for `scan_engine.o scan_record.o scan_throttle.o` plus the VFS/integrity objects, creates a temp file, sets `user.XrdCks.adler32` via the codec, and asserts `verify`→`ok`, a byte-flip→`mismatch`, an mtime-bump→`stale`, xattr-removal→`missing`. Run it; Expected: `OK`.

- [ ] **Step 6: Commit** (with go-ahead):

```bash
git add src/scan/scan_engine.h src/scan/scan_engine.c src/scan/scan_engine_unittest.c tests/test_scan_action.sh config
git commit -m "feat(scan): per-object dump/verify/fill action over VFS + XrdCks codec"
```

---

## Task 4: Resumable batched walk + emit (`scan_engine` part 2)

**Files:**
- Modify: `src/scan/scan_engine.h`, `src/scan/scan_engine.c`, `src/scan/scan_engine_unittest.c`

**Interfaces:**
- Consumes: Task 3 action, `xrootd_vfs_walk`, `scan_throttle`.
- Produces:
  - `typedef int (*xrootd_scan_emit_cb)(void *cookie, const char *line, size_t len);` — return 0 ok, non-0 abort (e.g. client gone / write would block → caller pauses).
  - `typedef struct { xrootd_scan_mode_t mode; char alg[16]; xrootd_scan_limits_t limits; char after[PATH_MAX]; uint32_t max_depth; uint32_t max_files; } xrootd_scan_opts_t;`
  - `typedef struct xrootd_scan_run_s xrootd_scan_run_t;`
  - `xrootd_scan_run_t *xrootd_scan_run_create(ngx_log_t *log, int rootfd, const char *subtree, const xrootd_scan_opts_t *opts, xrootd_scan_emit_cb emit, void *cookie);`
  - `ngx_int_t xrootd_scan_run_step(xrootd_scan_run_t *run, uint32_t max_records, uint64_t now_ms);` — process up to `max_records` files, emitting each via `emit`; honors `after` (skip ≤ cursor), throttle delay (returns `NGX_AGAIN` with a requested-wait when rate-limited), budget (emits final `cursor`+`summary`, returns `NGX_DONE`). Returns `NGX_OK` (more to do), `NGX_AGAIN` (call again after `xrootd_scan_run_wait_ms()`), `NGX_DONE` (finished), `NGX_ERROR`.
  - `uint64_t xrootd_scan_run_wait_ms(const xrootd_scan_run_t *run);`
  - `void xrootd_scan_run_destroy(xrootd_scan_run_t *run);`

  **Walk strategy (resumable):** the run owns a persistent `xrootd_vfs_walk` invocation is *not* resumable mid-call, so the engine instead does its own bounded enumeration: it keeps an explicit directory-cursor stack (dir logical path + an opened `DIR*`-equivalent fd via `xrootd_vfs_open_fd_at(O_DIRECTORY)` and `readdir`), advancing `max_records` entries per `step`. Reuse the per-entry classify/skip rules from `vfs_walk.c` (dot-skip, `AT_SYMLINK_NOFOLLOW` fstatat, soft-skip on error). This keeps emit ordering = walk order and makes `after=` a simple "skip until path > cursor". (If a future `xrootd_vfs_walk_iter` is added, swap to it; for now the engine carries the cursor.)

- [ ] **Step 1: Write the failing test** (standalone-friendly): a fake `emit` collects lines; build a temp tree of 3 files + 1 subdir/2 files; run `mode=dump` with `max_records=2` per step until `NGX_DONE`; assert 5 `file` lines + 1 `summary`, in sorted walk order, and that resuming with `after=<3rd path>` yields exactly the tail. Guard the tree-walk parts under `XROOTD_SCAN_UT_NGX` (needs VFS).

- [ ] **Step 2: Run** → FAIL (run API absent).

- [ ] **Step 3: Implement** `xrootd_scan_run_*` in `scan_engine.c`: cursor stack, per-step loop calling `xrootd_scan_action_one`, throttle `delay_ms`/`charge`, `budget_hit` → emit cursor+summary, `after` skip, emit each record (skip a record whose formatter returns 0). Decompose into `scan_run_open_dir`, `scan_run_next_entry`, `scan_run_emit_rec` helpers (no `goto`).

- [ ] **Step 4: Run** → `OK`.

- [ ] **Step 5: Commit** (go-ahead): `feat(scan): resumable batched walk + throttled emit engine`.

---

## Task 5: Config directives (`xrootd_scan*`)

**Files:**
- Modify: `src/config/config.h` (loc-conf fields), `src/config/directives.c` (commands + merge)
- Reference pattern: `dashboard_http.h` `browse_root` + `browse_root_canon` realpath handling; `src/config/directives.c` existing `xrootd_dashboard_*` entries.

**Interfaces:**
- Produces config fields read by `scan_http.c` (Task 6): `scan_enable` (flag), `scan_root` (ngx_str_t) + `scan_root_canon[PATH_MAX]`, `scan_parallel` (ngx_uint_t), `scan_max_rate` (off_t/size), `scan_adaptive` (flag).

- [ ] **Step 1: Write the failing test** — `tests/test_scan.py::test_scan_disabled_404` (skeleton): with `xrootd_scan off`, `GET /xrootd/api/v1/scan?...` → 404. (Fails until Task 6 wires the route, but the directive must parse first: add a config-validation step `nginx -t` with the new directives present.)

- [ ] **Step 2:** Add the 5 fields to the HTTP loc conf struct in `config.h` (init `NGX_CONF_UNSET`), the 5 `ngx_command_t` entries in `directives.c`, and merge logic in `merge_*_conf()` (defaults: enable off, parallel 4, max_rate 0, adaptive on; canonicalize `scan_root` via `realpath` like `browse_root_canon`). Run `objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf` with a config block setting the new directives. Expected: `configuration test is successful`.

- [ ] **Step 3: Commit** (go-ahead): `feat(scan): config directives xrootd_scan{,_root,_parallel,_max_rate,_adaptive}`.

---

## Task 6: HTTP endpoint + streaming drive (`scan_http.c`)

**Files:**
- Create: `src/scan/scan_http.c`
- Modify: `src/dashboard/module.c` (route), `src/dashboard/dashboard_http.h` (declare `ngx_http_xrootd_scan_handler`), top-level `config`
- Reference: `src/dashboard/files.c` (auth + `xrootd_beneath_open_root` confinement + status mapping), nginx `ngx_thread_task_post` + chunked output.

**Interfaces:**
- Consumes: `xrootd_scan_run_*` (engine), `ngx_http_xrootd_dashboard_check_auth`, `xrootd_beneath_open_root(conf->scan_root_canon)`.
- Produces: `ngx_int_t ngx_http_xrootd_scan_handler(ngx_http_request_t *r);`

  **Threading/streaming model (nginx-native, single producer step per task):**
  - On entry: `check_auth` (403 on fail); if `!scan_enable || scan_root_canon[0]=='\0'` → 404; parse query params (`mode`,`path`,`alg`,`parallel`,`max_rate`,`adaptive`,`max_bytes`,`max_seconds`,`after`), **clamp** parallel/max_rate to configured ceilings; confine `path` by opening `rootfd = xrootd_beneath_open_root(scan_root_canon)` then validating the subtree via a `RESOLVE_BENEATH` probe (escape → 403).
  - Send headers: status 200, `Content-Type: application/x-ndjson`, chunked (`r->headers_out.content_length_n = -1`), `ngx_http_send_header(r)`.
  - Create the engine run; `r->main->count++` to hold the request across thread hops.
  - **Drive loop (event loop ↔ thread pool):** post a thread task (`ngx_thread_task_post(pool, task)`) whose worker calls `xrootd_scan_run_step(run, BATCH, now_ms)` into a per-run scratch buffer (the emit callback appends NDJSON into that buffer; the worker does NOT touch the connection). The completion handler (event loop) wraps the scratch buffer in an `ngx_buf_t` chain and `ngx_http_output_filter(r, &out)` with `flush=1`; on `NGX_AGAIN`/`r->connection->buffered` it waits for the write event (backpressure) before posting the next step; on engine `NGX_AGAIN` (throttle) it arms a timer for `xrootd_scan_run_wait_ms`; on `NGX_DONE` it sends the last buffer with `last_buf=1`, `xrootd_scan_run_destroy`, and `ngx_http_finalize_request(r, NGX_OK)`.
  - Pool: reuse the configured thread pool (same accessor the cache/aio use); if none, run the step inline on the event loop (degraded, still correct).

- [ ] **Step 1: Write the failing test** — `tests/test_scan.py::test_dump_manifest`: build a fixture export, `GET .../scan?mode=dump&path=/&alg=adler32` with an admin token, assert NDJSON has one `file` per fixture file with correct `stored`, ending in a `summary`. Run → FAIL (404, route absent).

- [ ] **Step 2: Implement** `scan_http.c` per the model above; decompose into `scan_http_parse_opts`, `scan_http_open_root`, `scan_http_send_headers`, `scan_http_post_step`, `scan_http_step_thread`, `scan_http_step_done` (no `goto`). Add the route in `module.c` (most-specific-first, before the `/api/v1/` catch-all):

```c
    if (dashboard_uri_eq(uri, "/xrootd/api/v1/scan")) {
        return ngx_http_xrootd_scan_handler(r);
    }
```
Register `src/scan/scan_http.c` in top-level `config`; `rm -rf objs && ./configure ... && make`.

- [ ] **Step 3: Run** `tests/test_scan.py::test_dump_manifest` → PASS. Also `test_scan_disabled_404` (Task 5) → PASS.

- [ ] **Step 4: Security-neg tests** — `test_scan_requires_admin` (missing/invalid token → 403), `test_scan_path_confined` (`path=../../etc` → 403), `test_scan_clamps_limits` (`parallel=999` honored as ≤ configured). Run → PASS.

- [ ] **Step 5: Commit** (go-ahead): `feat(scan): admin HTTP NDJSON streaming endpoint /xrootd/api/v1/scan`.

---

## Task 7: CEPH byte-compat gate (verify/fill)

**Files:**
- Modify: `src/scan/scan_http.c` (or `scan_engine.c` action) — refuse `verify`/`fill` when the bound backend is a non-striper Ceph driver.
- Reference: `src/fs/backend/sd.h` driver capability flags; phase-60 `sd_ceph` caps.

**Interfaces:**
- Consumes: the SD driver capability of the resolved export (a cap bit indicating "byte reads are stock-XrdCeph-faithful" — for POSIX/pblock always true; for `sd_ceph` true only once libradosstriper-backed). If the driver lacks a striper-faithful read, `verify`/`fill` must return a clean error record/501, never wrong bytes.

- [ ] **Step 1: Write the failing test** — `tests/test_scan.py::test_verify_gated_on_ceph` (skipif no Ceph harness): on a Ceph export with a non-striper driver, `mode=verify` → an error record `{"t":"error","reason":"verify unsupported on this backend"}` and HTTP 200 stream cleanly closed (or 501 before streaming). On POSIX → not gated.

- [ ] **Step 2: Implement** a capability check in `scan_http_parse_opts`/engine create: query the resolved driver caps; for `verify`/`fill` without the striper-faithful read cap, emit one `error` record and finish. Add `xrootd_scan_record_error(const char *reason, ...)` to `scan_record.c` (+ unit test) for the record shape.

- [ ] **Step 3: Run** → PASS (POSIX unaffected; Ceph gated). **Step 4: Commit** (go-ahead): `feat(scan): gate verify/fill off non-striper Ceph backends (stock byte-compat)`.

---

## Task 8: Parallel worker pool (intra-run concurrency)

**Files:**
- Modify: `src/scan/scan_engine.{c,h}` (add an N-worker variant), `src/scan/scan_http.c` (use it when `parallel>1`)

**Interfaces:**
- Produces: an internal producer/consumer in the run — the step thread enqueues up to `parallel` files into a bounded ring; `parallel` is realized by issuing that batch's byte-reads concurrently *within one thread task* via... **decision:** to stay inside nginx threading rules (one task = one thread) without a bespoke multi-task choreography, realize concurrency by sizing each `step`'s batch and relying on multiple in-flight HTTP scan requests being the unit of cross-file parallelism is NOT acceptable (single admin request). Instead post up to `parallel` **independent worker tasks** to the pool from `scan_http_step_done`, each running one file's `xrootd_scan_action_one`; collect their records, emit in walk order once all in the batch complete, then post the next batch. The throttle (`delay_ms`/`charge`) is consulted under a mutex shared by the batch.

- [ ] **Step 1: Write the failing test** — `tests/test_scan.py::test_parallel_speedup_and_order`: a fixture of N large-ish files; `parallel=4` completes faster than `parallel=1` (wall-clock assertion with generous margin) AND the emitted order is identical (deterministic walk order) AND `max_rate` is respected (measured aggregate ≤ ceiling). Run → FAIL (no concurrency yet).

- [ ] **Step 2: Implement** the batched multi-task fan-out + ordered gather in the engine + `scan_http` drive; shared-throttle mutex; ordered emit buffer keyed by walk-order index.

- [ ] **Step 3: Run** → PASS. **Step 4: Commit** (go-ahead): `feat(scan): bounded parallel worker pool with ordered emit + shared throttle`.

---

## Task 9: Client tool `xrdstorascan` — dump/verify/fill

**Files:**
- Create: `client/tools/xrdstorascan.c`
- Modify: `client/Makefile`
- Reference: an existing phase-37 client tool in `client/tools/` for arg-parse + libxrdc HTTP + credential setup; `client/lib/cks_verify.c` for checksum-format helpers.

**Interfaces:**
- Consumes: the HTTP endpoint (Task 6); libxrdc HTTP GET with credential auth.
- Produces: CLI `xrdstorascan <dump|verify|fill|compare> <url> [flags]`; flags map to query params; renders NDJSON → TSV (default) / `--json` / `--summary`.

- [ ] **Step 1: Write the failing test** — `tests/test_scan.py::test_client_dump_tsv`: run `xrdstorascan dump davs://.../ -o /tmp/m.tsv`, assert the TSV has one row per fixture file (`path\tsize\talg\tstored\tstatus`). Run → FAIL (tool absent).

- [ ] **Step 2: Implement** arg parse (subcommand → mode, `--alg/--parallel/--max-rate/--adaptive/--max-bytes/--max-seconds` → params), HTTP GET streaming read, line-by-line NDJSON parse (minimal: reuse `shared/xrdproto/json_min.c` if linkable, else a tiny field extractor), TSV/JSON/summary renderers. No `goto`; credential-hardened temp handling per `client_credfile_hardening` rules if writing output.

- [ ] **Step 3: Build** `make -C client xrdstorascan`. **Step 4: Run** test → PASS. **Step 5: Commit** (go-ahead): `feat(client): xrdstorascan dump/verify/fill driver`.

---

## Task 10: Client `--resume`, budget, and `compare`

**Files:**
- Modify: `client/tools/xrdstorascan.c`, `client/Makefile` (if split helpers)

**Interfaces:**
- Consumes: `cursor` records (Task 4), the `dump` stream (for compare).
- Produces: `--resume` (persist last `cursor` to `<output>.scanstate`, re-issue with `after=`), `--max-bytes/--max-seconds` passthrough, `compare --manifest <file>` (stream server `dump`, diff vs `path\tchecksum` catalog → `missing`/`extra`/`mismatch`, exit non-zero on any discrepancy).

- [ ] **Step 1: Write the failing test** — `test_client_resume_completes_once` (interrupt a dump, resume, assert union == full set, no dupes) + `test_client_compare_flags` (inject missing/extra/mismatch vs a manifest). Run → FAIL.

- [ ] **Step 2: Implement** resume-state sidecar + `after=` re-issue; manifest loader + diff (hash map path→checksum); exit codes. **Step 3: Run** → PASS. **Step 4: Commit** (go-ahead): `feat(client): xrdstorascan resume + budget + manifest compare`.

---

## Task 11: Docs + CEPH stock-parity guard + suite green

**Files:**
- Create: `src/scan/README.md`; Modify: `docs/10-architecture/*` index + a reference page; `tests/test_scan.py` (Ceph parity, skipif no harness)
- Reference: `docs/refactor/phase-60-ceph-rados-backend.md` single-node Ceph harness.

- [ ] **Step 1:** Write `src/scan/README.md` (Overview / Files / control+data flow / invariants — match the `src/query/README.md` shape).
- [ ] **Step 2:** `tests/test_scan.py::test_ceph_stock_parity` (skipif): write a fixture via **stock XrdCeph**, then assert the scan `dump` reproduces stock's `XrdCks.adler32` and `verify`→`ok` over striper-reassembled bytes; assert verify on a non-striper Ceph driver is gated (Task 7).
- [ ] **Step 3:** Run the whole module suite: `PYTHONPATH=tests pytest tests/test_scan.py -v --tb=short` and the standalone unit (`/tmp/scan_ut`). Expected: all pass (Ceph cases skip without harness).
- [ ] **Step 4:** Update `CLAUDE.md` OP→FILE (add a `scan` row) and the docs index. **Step 5: Commit** (go-ahead): `docs(scan): module README + architecture/index + CEPH parity guard`.

---

## Self-Review

**Spec coverage:**
- §1 module layout → Tasks 1,2,3/4,6 (one file per task group). ✓
- §2 engine + 4 modes + ordering → Tasks 3 (action) + 4 (walk/emit/order) + 8 (parallel ordered). ✓
- §3 throttle (concurrency/byte-rate/adaptive/budget) → Task 1 (+ concurrency realized Task 8, pressure feed wired in Task 6/8). ✓
- §4 transport + NDJSON schema + params + confinement/backpressure → Tasks 2 (schema) + 6 (transport/params/confine/backpressure). ✓
- §5 config directives → Task 5. ✓
- §6 client (4 subcommands, render, resume, compare) → Tasks 9 + 10. ✓
- §7 CEPH byte-compat + striper gate + XrdCksData codec + fmTime → Tasks 3 (codec/fmTime), 7 (gate), 11 (parity guard). ✓
- §8 tests (success/error/security-neg, resume, CEPH parity) → woven into Tasks 1–11. ✓
- §9 scope boundaries (no root:// opcode, client-side compare, fill-only mutation, no striper work here) → respected; Task 7 *gates* rather than implements striper. ✓

**Placeholder scan:** Tasks 1,2 carry full code. Tasks 3,4,6,8 specify exact functions, signatures, decomposition, and integration calls (real symbols verified against the tree) but describe some bodies as ordered logic rather than full listings — the executor (subagent per task) writes the body against the named helpers; this is acceptable per task-right-sizing but the executor MUST add the WHAT/WHY/HOW doc blocks and keep no-goto. **Note for executor:** if any referenced symbol (`xrootd_vfs_open_fd_at` flags, thread-pool accessor name) differs at implementation time, grep the header and adjust — do not invent.

**Type consistency:** `xrootd_scan_status_t`, `xrootd_scan_file_rec_t`, `xrootd_scan_summary_t` (Task 2) are reused unchanged in Tasks 3/4/6/8. `xrootd_scan_limits_t` (Task 1) embedded in `xrootd_scan_opts_t` (Task 4). `xrootd_scan_emit_cb` (Task 4) consumed by Task 6. Mode enum (Task 3) used by Tasks 4/6/9. Consistent. One typo fixed inline ("non/bad token" → ASCII) — executor: the test name is `test_scan_requires_admin`.
