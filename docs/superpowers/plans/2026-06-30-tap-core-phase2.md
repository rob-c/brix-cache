# Tap Core (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A standalone, ngx-free, unit-tested **tap core** (`src/tap/`) that decodes XRootD wire frames (request + response) and fans each decoded frame out to registered sinks, with a JSON audit formatter as the first sink — ready to be wired into the transparent relay (Phase 3) and the new terminating proxy (Phase 4).

**Architecture:** Pure C, no nginx / OpenSSL / allocation in the core. Reuses the existing single-source framing helpers in `src/protocol/frame_hdr.h` (unaligned-safe BE accessors, `xrd_resp_hdr_unpack`) and opcode constants in `src/protocol/opcodes.h` (`XRD_REQUEST_HDR_LEN`, `kXR_*`). The decoder turns a byte buffer into an `xrootd_tap_frame_t` (streamid, opcode/status, dlen, optional path slice); `xrootd_tap_emit` calls each registered `xrootd_tap_sink_fn`. Sinks that need nginx (log file, Prometheus metrics) are thin adapters added when the tap is wired into a consumer — NOT in this phase.

**Tech Stack:** C, standalone gcc unit test, nginx `./config` source registration.

## Global Constraints

- **NO `goto`**; functional/modular; one job per function; no new globals (pass `xrootd_tap_ctx_t`).
- **HELPERS — never reimplement framing:** use `src/protocol/frame_hdr.h` accessors (`xrd_get_u16_be`/`xrd_get_u32_be`/`xrd_resp_hdr_unpack`) and `src/protocol/opcodes.h` constants. Do not hand-roll `ntohs`/`ntohl` or redefine `kXR_*`.
- **Core stays ngx-free** so it unit-tests with plain gcc and embeds in any consumer.
- **Metric cardinality (INVARIANT #8):** the future metrics sink must use low-cardinality labels only (no paths) — out of scope here but the audit sink is the path-bearing one by design.
- **Build governance:** new `.c` files register in the top-level `./config` (`$ngx_addon_dir/src/tap/*.c`) then `./configure`; the standalone unit test does not need the module build.
- **3 tests:** success (decode + emit + audit), error (truncated/partial frame), parity/safety (non-path op carries no path; oversized dlen clamped).

---

### Task 1: Frame types + header decoder

**Files:**
- Create: `src/tap/tap.h`
- Create: `src/tap/tap_decode.c`
- Test: `tests/tap_unittest.c`

**Interfaces:**
- Produces: `xrootd_tap_dir_t`, `xrootd_tap_frame_t`, `xrootd_tap_decode_request(const uint8_t*, size_t, xrootd_tap_frame_t*) -> size_t`, `xrootd_tap_decode_response(const uint8_t*, size_t, xrootd_tap_frame_t*) -> size_t` (return = header bytes consumed, 0 if buffer too short for the fixed header).

- [ ] **Step 1: Write the failing test**

Create `tests/tap_unittest.c`:

```c
/* Standalone unit test for the tap core — gcc, no nginx. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../src/protocol/opcodes.h"
#include "../src/tap/tap.h"

/* Build a request frame: streamid + requestid(BE) + 16B body + dlen(BE) + payload */
static size_t
mk_request(uint8_t *buf, uint16_t sid, uint16_t op, const char *payload)
{
    uint32_t dlen = payload ? (uint32_t) strlen(payload) : 0;
    uint16_t sid_be = htons(sid), op_be = htons(op);
    uint32_t dlen_be = htonl(dlen);
    memcpy(buf, &sid_be, 2);
    memcpy(buf + 2, &op_be, 2);
    memset(buf + 4, 0, 16);
    memcpy(buf + 20, &dlen_be, 4);
    if (dlen) { memcpy(buf + 24, payload, dlen); }
    return 24 + dlen;
}

static size_t
mk_response(uint8_t *buf, uint16_t sid, uint16_t status, uint32_t dlen)
{
    uint16_t sid_be = htons(sid), st_be = htons(status);
    uint32_t dlen_be = htonl(dlen);
    memcpy(buf, &sid_be, 2);
    memcpy(buf + 2, &st_be, 2);
    memcpy(buf + 4, &dlen_be, 4);
    return 8;
}

static void test_decode_request(void)
{
    uint8_t buf[256];
    size_t total = mk_request(buf, 0x0102, kXR_open, "/foo/bar");
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_request(buf, total, &f);
    assert(hdr == 24);
    assert(f.is_request == 1);
    assert(f.streamid == 0x0102);
    assert(f.opcode == kXR_open);
    assert(f.dlen == 8);
    assert(f.path_len == 8 && memcmp(f.path, "/foo/bar", 8) == 0);
}

static void test_decode_request_no_path(void)
{
    uint8_t buf[64];
    /* kXR_ping carries no path even with a payload */
    size_t total = mk_request(buf, 7, kXR_ping, NULL);
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_request(buf, total, &f);
    assert(hdr == 24);
    assert(f.opcode == kXR_ping);
    assert(f.path == NULL && f.path_len == 0);
}

static void test_decode_response(void)
{
    uint8_t buf[16];
    mk_response(buf, 0x0102, kXR_ok, 0);
    xrootd_tap_frame_t f;
    size_t hdr = xrootd_tap_decode_response(buf, 8, &f);
    assert(hdr == 8);
    assert(f.is_request == 0);
    assert(f.streamid == 0x0102);
    assert(f.status == kXR_ok);
    assert(f.dlen == 0);
}

static void test_truncated(void)
{
    uint8_t buf[4] = {0};
    xrootd_tap_frame_t f;
    assert(xrootd_tap_decode_request(buf, 4, &f) == 0);   /* < 24 */
    assert(xrootd_tap_decode_response(buf, 4, &f) == 0);  /* < 8  */
}

int main(void)
{
    test_decode_request();
    test_decode_request_no_path();
    test_decode_response();
    test_truncated();
    printf("tap_unittest: all checks passed\n");
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c 2>&1 | head -3`
Expected: FAIL — `src/tap/tap.h: No such file or directory`.

- [ ] **Step 3: Write `tap.h`**

Create `src/tap/tap.h`:

```c
#ifndef XROOTD_TAP_TAP_H
#define XROOTD_TAP_TAP_H

/*
 * tap.h — protocol observation tap (decoder + sink fan-out).
 *
 * WHAT: turns raw XRootD wire bytes into a decoded frame descriptor and fans each
 *   frame out to registered sinks (audit / metrics / capture / inspection). Fed by
 *   both proxy modes: the terminating proxy (full plaintext) and the transparent
 *   relay (whatever travels in cleartext).
 * WHY:  one decoder + one fan-out, shared, instead of per-consumer frame parsing.
 * HOW:  pure C — no nginx, no allocation, no OpenSSL — so it embeds in any consumer
 *   and unit-tests standalone. Reuses src/protocol/frame_hdr.h + opcodes.h.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    XROOTD_TAP_C2U = 0,   /* client → upstream (request side) */
    XROOTD_TAP_U2C = 1    /* upstream → client (response side) */
} xrootd_tap_dir_t;

typedef struct {
    uint16_t       streamid;
    int            is_request;  /* 1 = request frame, 0 = response frame */
    uint16_t       opcode;      /* request: kXR_* requestid; 0 on a response */
    uint16_t       status;      /* response: kXR_* status; 0 on a request */
    uint32_t       dlen;        /* payload length declared by the header */
    const uint8_t *path;        /* path-bearing request w/ payload present; else NULL */
    size_t         path_len;
} xrootd_tap_frame_t;

/* Decode the fixed header of a request (24B) / response (8B) frame from buf[0..len).
 * Returns the header byte count consumed (24 / 8) with *out filled, or 0 if len is
 * too short for the fixed header. The payload need not be fully present; `path` is
 * set only for a path-bearing opcode whose payload bytes are available in buf. */
size_t xrootd_tap_decode_request(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out);
size_t xrootd_tap_decode_response(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out);

/* ---- sink fan-out (Task 2) ---- */

typedef void (*xrootd_tap_sink_fn)(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

#define XROOTD_TAP_MAX_SINKS 8

typedef struct {
    struct { xrootd_tap_sink_fn fn; void *ctx; } sinks[XROOTD_TAP_MAX_SINKS];
    int n;
} xrootd_tap_ctx_t;

void xrootd_tap_register_sink(xrootd_tap_ctx_t *t, xrootd_tap_sink_fn fn,
    void *ctx);
void xrootd_tap_emit(xrootd_tap_ctx_t *t, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

/* ---- audit JSON formatter (Task 3) ---- */

/* Format one frame as a single-line JSON object into out[0..outsz). Returns bytes
 * written (excluding the NUL), or 0 if it would not fit. Pure — no I/O. */
size_t xrootd_tap_audit_format(const xrootd_tap_frame_t *f, xrootd_tap_dir_t dir,
    char *out, size_t outsz);

#endif /* XROOTD_TAP_TAP_H */
```

- [ ] **Step 4: Write `tap_decode.c`**

Create `src/tap/tap_decode.c`:

```c
/*
 * tap_decode.c — XRootD frame header decode for the tap core.
 *
 * Reuses the single-source BE accessors (frame_hdr.h) and opcode constants
 * (opcodes.h). A request header is 24B (streamid[2] + requestid[2] + body[16] +
 * dlen[4]); a response header is 8B (streamid[2] + status[2] + dlen[4]). For a
 * path-bearing request the path is the data payload at offset XRD_REQUEST_HDR_LEN.
 */

#include "tap.h"
#include "../protocol/opcodes.h"
#include "../protocol/frame_hdr.h"

/* True for request opcodes whose data payload is (or begins with) a path. */
static int
tap_opcode_has_path(uint16_t op)
{
    switch (op) {
    case kXR_open:
    case kXR_stat:
    case kXR_statx:
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_truncate:
    case kXR_dirlist:
    case kXR_locate:
        return 1;
    default:
        return 0;
    }
}

size_t
xrootd_tap_decode_request(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out)
{
    if (buf == NULL || out == NULL || len < XRD_REQUEST_HDR_LEN) {
        return 0;
    }

    out->is_request = 1;
    out->streamid   = xrd_get_u16_be(buf);
    out->opcode     = xrd_get_u16_be(buf + 2);
    out->status     = 0;
    out->dlen       = xrd_get_u32_be(buf + 20);
    out->path       = NULL;
    out->path_len   = 0;

    if (out->dlen > 0 && tap_opcode_has_path(out->opcode)) {
        size_t avail = len - XRD_REQUEST_HDR_LEN;
        size_t plen  = (out->dlen < avail) ? out->dlen : avail;
        if (plen > 0) {
            out->path     = buf + XRD_REQUEST_HDR_LEN;
            out->path_len = plen;
        }
    }
    return XRD_REQUEST_HDR_LEN;
}

size_t
xrootd_tap_decode_response(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out)
{
    if (buf == NULL || out == NULL || len < 8) {
        return 0;
    }

    out->is_request = 0;
    out->opcode     = 0;
    out->path       = NULL;
    out->path_len   = 0;
    xrd_resp_hdr_unpack(buf, &out->streamid, &out->status, &out->dlen);
    return 8;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c && /tmp/tap_unittest`
Expected: PASS — `tap_unittest: all checks passed`, exit 0, no warnings.

(If `kXR_rmdir` / `kXR_locate` are absent from opcodes.h, drop them from `tap_opcode_has_path` — confirm names with `grep -n "define kXR_" src/protocol/opcodes.h` first.)

- [ ] **Step 6: Commit** — SKIP (user runs git).

---

### Task 2: Sink registry + fan-out

**Files:**
- Create: `src/tap/tap_emit.c`
- Test: extend `tests/tap_unittest.c`

**Interfaces:**
- Consumes: `xrootd_tap_ctx_t`, `xrootd_tap_sink_fn`, `xrootd_tap_frame_t` (Task 1 `tap.h`).
- Produces: `xrootd_tap_register_sink(xrootd_tap_ctx_t*, xrootd_tap_sink_fn, void*)`, `xrootd_tap_emit(xrootd_tap_ctx_t*, const xrootd_tap_frame_t*, xrootd_tap_dir_t, const uint8_t*, size_t)`.

- [ ] **Step 1: Add the failing test**

Add to `tests/tap_unittest.c` (above `main`, and call from `main`):

```c
struct count_ctx { int n; uint16_t last_op; };
static void count_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    struct count_ctx *c = ctx;
    (void) dir; (void) payload; (void) payload_len;
    c->n++;
    c->last_op = f->opcode;
}

static void test_emit_fanout(void)
{
    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct count_ctx a = {0, 0}, b = {0, 0};
    xrootd_tap_register_sink(&tap, count_sink, &a);
    xrootd_tap_register_sink(&tap, count_sink, &b);

    xrootd_tap_frame_t f; memset(&f, 0, sizeof(f));
    f.is_request = 1; f.opcode = kXR_open;
    xrootd_tap_emit(&tap, &f, XROOTD_TAP_C2U, NULL, 0);
    xrootd_tap_emit(&tap, &f, XROOTD_TAP_C2U, NULL, 0);

    assert(a.n == 2 && b.n == 2);
    assert(a.last_op == kXR_open && b.last_op == kXR_open);
}
```

Add `test_emit_fanout();` to `main` before the print.

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c 2>&1 | head -3`
Expected: FAIL — undefined reference to `xrootd_tap_register_sink` / `xrootd_tap_emit`.

- [ ] **Step 3: Write `tap_emit.c`**

Create `src/tap/tap_emit.c`:

```c
/*
 * tap_emit.c — sink registry + fan-out for the tap core.
 *
 * A bounded fixed array of sinks (no allocation). register_sink appends until
 * full (silently ignores overflow — a misconfiguration, not a runtime error);
 * emit calls every registered sink with the decoded frame + raw payload slice.
 */

#include "tap.h"

void
xrootd_tap_register_sink(xrootd_tap_ctx_t *t, xrootd_tap_sink_fn fn, void *ctx)
{
    if (t == NULL || fn == NULL || t->n >= XROOTD_TAP_MAX_SINKS) {
        return;
    }
    t->sinks[t->n].fn  = fn;
    t->sinks[t->n].ctx = ctx;
    t->n++;
}

void
xrootd_tap_emit(xrootd_tap_ctx_t *t, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    int i;

    if (t == NULL || f == NULL) {
        return;
    }
    for (i = 0; i < t->n; i++) {
        t->sinks[i].fn(t->sinks[i].ctx, f, dir, payload, payload_len);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c src/tap/tap_emit.c && /tmp/tap_unittest`
Expected: PASS — `tap_unittest: all checks passed`.

- [ ] **Step 5: Commit** — SKIP.

---

### Task 3: JSON audit formatter

**Files:**
- Create: `src/tap/tap_audit.c`
- Test: extend `tests/tap_unittest.c`

**Interfaces:**
- Consumes: `xrootd_tap_frame_t`, `xrootd_tap_dir_t` (Task 1).
- Produces: `xrootd_tap_audit_format(const xrootd_tap_frame_t*, xrootd_tap_dir_t, char *out, size_t outsz) -> size_t`.

- [ ] **Step 1: Add the failing test**

Add to `tests/tap_unittest.c`:

```c
static void test_audit_format(void)
{
    uint8_t buf[256];
    size_t total = mk_request(buf, 5, kXR_open, "/a/\"b\"");  /* quote → must escape */
    xrootd_tap_frame_t f;
    xrootd_tap_decode_request(buf, total, &f);

    char out[512];
    size_t n = xrootd_tap_audit_format(&f, XROOTD_TAP_C2U, out, sizeof(out));
    assert(n > 0);
    assert(strstr(out, "\"dir\":\"c2u\"") != NULL);
    assert(strstr(out, "\"op\":\"open\"") != NULL);
    assert(strstr(out, "\"streamid\":5") != NULL);
    assert(strstr(out, "\"path\":\"/a/\\\"b\\\"\"") != NULL);  /* escaped quotes */

    /* truncation: a tiny buffer returns 0, never overflows */
    char tiny[8];
    assert(xrootd_tap_audit_format(&f, XROOTD_TAP_C2U, tiny, sizeof(tiny)) == 0);
}
```

Add `test_audit_format();` to `main`.

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c src/tap/tap_emit.c 2>&1 | head -3`
Expected: FAIL — undefined reference to `xrootd_tap_audit_format`.

- [ ] **Step 3: Write `tap_audit.c`**

Create `src/tap/tap_audit.c`:

```c
/*
 * tap_audit.c — single-line JSON formatter for a tapped frame.
 *
 * Pure string building into a caller buffer (no I/O, no allocation): the consumer
 * decides where the line goes (error.log, a dedicated audit file). Path bytes from
 * the wire are JSON-escaped (", \\, and control bytes) and bounded by path_len —
 * the wire path is NOT NUL-terminated, so we never treat it as a C string.
 */

#include "tap.h"
#include "../protocol/opcodes.h"

#include <stdio.h>
#include <string.h>

/* Compact opcode → name for the audited request ops; NULL → numeric fallback. */
static const char *
tap_opcode_name(uint16_t op)
{
    switch (op) {
    case kXR_open:     return "open";
    case kXR_stat:     return "stat";
    case kXR_statx:    return "statx";
    case kXR_mkdir:    return "mkdir";
    case kXR_rm:       return "rm";
    case kXR_rmdir:    return "rmdir";
    case kXR_mv:       return "mv";
    case kXR_truncate: return "truncate";
    case kXR_dirlist:  return "dirlist";
    case kXR_locate:   return "locate";
    case kXR_read:     return "read";
    case kXR_write:    return "write";
    case kXR_close:    return "close";
    default:           return NULL;
    }
}

/* Append a JSON-escaped, length-bounded string value. Returns 0 on overflow. */
static int
tap_json_append_escaped(char *out, size_t outsz, size_t *pos,
    const uint8_t *s, size_t slen)
{
    size_t i;
    for (i = 0; i < slen; i++) {
        unsigned char ch = s[i];
        char esc[8];
        const char *seg;
        size_t seglen;
        if (ch == '"' || ch == '\\') {
            esc[0] = '\\'; esc[1] = (char) ch; seglen = 2; seg = esc;
        } else if (ch < 0x20) {
            seglen = (size_t) snprintf(esc, sizeof(esc), "\\u%04x", ch);
            seg = esc;
        } else {
            esc[0] = (char) ch; seglen = 1; seg = esc;
        }
        if (*pos + seglen >= outsz) { return 0; }
        memcpy(out + *pos, seg, seglen);
        *pos += seglen;
    }
    return 1;
}

size_t
xrootd_tap_audit_format(const xrootd_tap_frame_t *f, xrootd_tap_dir_t dir,
    char *out, size_t outsz)
{
    const char *dirs = (dir == XROOTD_TAP_C2U) ? "c2u" : "u2c";
    const char *opn;
    size_t pos;
    int n;

    if (f == NULL || out == NULL || outsz == 0) {
        return 0;
    }

    /* Fixed prefix + numeric fields via snprintf (bounded). */
    if (f->is_request) {
        opn = tap_opcode_name(f->opcode);
        if (opn != NULL) {
            n = snprintf(out, outsz,
                "{\"dir\":\"%s\",\"streamid\":%u,\"op\":\"%s\",\"dlen\":%u",
                dirs, f->streamid, opn, f->dlen);
        } else {
            n = snprintf(out, outsz,
                "{\"dir\":\"%s\",\"streamid\":%u,\"op\":%u,\"dlen\":%u",
                dirs, f->streamid, f->opcode, f->dlen);
        }
    } else {
        n = snprintf(out, outsz,
            "{\"dir\":\"%s\",\"streamid\":%u,\"status\":%u,\"dlen\":%u",
            dirs, f->streamid, f->status, f->dlen);
    }
    if (n < 0 || (size_t) n >= outsz) {
        return 0;
    }
    pos = (size_t) n;

    /* Optional escaped path. */
    if (f->path != NULL && f->path_len > 0) {
        const char *pkey = ",\"path\":\"";
        size_t klen = strlen(pkey);
        if (pos + klen >= outsz) { return 0; }
        memcpy(out + pos, pkey, klen);
        pos += klen;
        if (!tap_json_append_escaped(out, outsz, &pos, f->path, f->path_len)) {
            return 0;
        }
        if (pos + 1 >= outsz) { return 0; }
        out[pos++] = '"';
    }

    if (pos + 1 >= outsz) { return 0; }  /* room for '}' + NUL */
    out[pos++] = '}';
    out[pos]   = '\0';
    return pos;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/tap/tap_decode.c src/tap/tap_emit.c src/tap/tap_audit.c && /tmp/tap_unittest`
Expected: PASS — `tap_unittest: all checks passed`.

- [ ] **Step 5: Commit** — SKIP.

---

### Task 4: Register in the module build

**Files:**
- Modify: `config` (top-level addon source list)
- Verify: full module build

**Interfaces:** none new — this only proves the ngx-free core compiles + links into the nginx module so Phase 3 can call it.

- [ ] **Step 1: Find the addon source list**

Run: `grep -n "src/fs/cache/origin_connection.c\|ngx_addon_dir/src" config | head -3`
Expected: shows the `$ngx_addon_dir/src/...c` list lines where each `.c` is registered.

- [ ] **Step 2: Add the three tap sources**

Add to the `NGX_ADDON_SRCS` list in `config` (next to other `src/...` entries), e.g.:

```
    $ngx_addon_dir/src/tap/tap_decode.c \
    $ngx_addon_dir/src/tap/tap_emit.c \
    $ngx_addon_dir/src/tap/tap_audit.c \
```

- [ ] **Step 3: Reconfigure + build**

Run:
```
cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
  --with-http_ssl_module --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j"$(nproc)" 2>&1 | tail -5
```
Expected: configure regenerates, build exit 0 (the tap objects compile; unused-but-linked API functions do not warn under `-Wall`).

- [ ] **Step 4: Confirm the objects built**

Run: `ls -1 /tmp/nginx-1.28.3/objs/addon/tap/ 2>/dev/null`
Expected: `tap_decode.o  tap_emit.o  tap_audit.o`.

- [ ] **Step 5: Commit** — SKIP.

---

## Notes / Deferred

- **Metrics sink** (Prometheus counters) and **audit log-file sink** (writing the JSON line to a file/`error.log`) are ngx-coupled adapters built when the tap is wired into its first consumer (Phase 3 transparent relay). The audit *formatter* (Task 3) is the reusable, tested core they call.
- **Full-frame capture** + **inspection hook** sinks: Phase 3.
- **Consumers:** Phase 3 = transparent relay (first wired consumer). Phase 4 = NEW independent terminating proxy with a clean `xrootd_terminating_proxy*` config surface (NOT the removed `xrootd_proxy*`/XCache proxy) + GSI X.509 delegation.

## Self-Review

- **Spec coverage:** spec §4 (tap core: decoder + fan-out + audit + metrics) → Tasks 1–3 build decoder, fan-out, audit; metrics deferred to the wiring phase (documented), consistent with "ngx-free core now". §4.1 API matches `tap.h` (frame struct uses a bounded `path`/`path_len` slice instead of `ngx_str_t` to stay ngx-free — an intentional, documented refinement).
- **Placeholder scan:** none — full code in every step.
- **Type consistency:** `xrootd_tap_frame_t`, `xrootd_tap_ctx_t`, `xrootd_tap_sink_fn`, `xrootd_tap_emit`, `xrootd_tap_audit_format` are defined once in `tap.h` (Task 1) and used unchanged in Tasks 2–3 and the tests.
