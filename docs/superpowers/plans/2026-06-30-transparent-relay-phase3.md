# Transparent Relay + First Tap Wiring (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** A transparent pass-through relay (`xrootd_transparent_proxy host:port`) that relays a `root://` client's bytes verbatim to an upstream **official XRootD** server (auth handshake travels end-to-end, so x509/GSI just work), while a non-consuming tap decodes the cleartext frames in flight and emits them to a JSON audit log — the first live consumer of the Phase-2 tap core.

**Architecture:** Two parts. (3a) `xrootd_tap_stream` — an ngx-free streaming state machine that accepts arbitrary byte chunks per direction, reassembles frame headers (24B request / 8B response), captures the path for path-bearing requests, and calls `xrootd_tap_emit` per frame; standalone-unit-tested. (3b) `src/protocols/root/relay/` — a bidirectional buffered TCP relay modeled directly on the proven `src/protocols/root/handoff/handoff.c` pump, that connects to the configured upstream, relays both directions verbatim, and feeds each direction's freshly-`recv`'d bytes into a `xrootd_tap_stream`. The relay engages at the top of the stream handler (before any XRootD frame is parsed). An audit sink writes each tap frame's JSON line to `error.log`.

**Tech Stack:** C nginx stream module, ngx event loop, standalone gcc unit test, bash+xrdfs integration test.

## Global Constraints

- **NO `goto`**; functional/modular; explicit ctx; no new globals.
- **HELPERS — reuse:** `xrootd_tap_decode_request`/`_response`/`xrootd_tap_emit`/`xrootd_tap_audit_format` (Phase 2); the `handoff_pump` relay pattern from `src/protocols/root/handoff/handoff.c`; `ngx_event_connect_peer`. Do not reimplement framing or a new event-loop relay from scratch — mirror handoff.
- **Transparent = verbatim:** the relay MUST NOT alter, reorder, or drop client/upstream bytes; the tap is read-only (fed a copy of bytes already committed to forwarding).
- **Tap each byte once:** feed the stream decoder only on a fresh `recv` (never on a re-send after `NGX_AGAIN`).
- **Build governance:** new `.c` (tap_stream.c, relay/*.c) → register in top-level `./config`, then `./configure`.
- **3 tests:** success (byte-exact passthrough + tap logs the opcodes), error (partial/chunked frame still decodes; upstream-down fails cleanly), parity (a non-transparent server is unaffected).

---

### Task 1 (3a): Streaming frame decoder `xrootd_tap_stream`

**Files:**
- Modify: `src/net/tap/tap.h` (add the stream type + API)
- Create: `src/net/tap/tap_stream.c`
- Test: extend `tests/tap_unittest.c`

**Interfaces:**
- Consumes: `xrootd_tap_ctx_t`, `xrootd_tap_frame_t`, `xrootd_tap_decode_request`/`_response`, `xrootd_tap_emit` (Phase 2).
- Produces: `xrootd_tap_stream_t`, `xrootd_tap_stream_init(xrootd_tap_stream_t*, xrootd_tap_ctx_t*, xrootd_tap_dir_t)`, `xrootd_tap_stream_feed(xrootd_tap_stream_t*, const uint8_t*, size_t)`.

- [ ] **Step 1: Add the failing test** to `tests/tap_unittest.c`:

```c
/* records every frame the stream decoder emits */
struct rec_ctx { int n; uint16_t op[16]; char path[16][64]; };
static void rec_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const uint8_t *payload, size_t payload_len)
{
    struct rec_ctx *r = ctx;
    (void) dir; (void) payload; (void) payload_len;
    if (r->n >= 16) { return; }
    r->op[r->n] = f->is_request ? f->opcode : f->status;
    r->path[r->n][0] = '\0';
    if (f->path && f->path_len < 64) {
        memcpy(r->path[r->n], f->path, f->path_len);
        r->path[r->n][f->path_len] = '\0';
    }
    r->n++;
}

static void test_stream_chunked(void)
{
    /* two requests back-to-back, fed one byte at a time */
    uint8_t a[256], b[256];
    size_t na = mk_request(a, 1, kXR_open, "/x");
    size_t nb = mk_request(b, 2, kXR_stat, "/y/z");
    uint8_t wire[512];
    memcpy(wire, a, na); memcpy(wire + na, b, nb);
    size_t total = na + nb;

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx r; memset(&r, 0, sizeof(r));
    xrootd_tap_register_sink(&tap, rec_sink, &r);

    xrootd_tap_stream_t st;
    xrootd_tap_stream_init(&st, &tap, XROOTD_TAP_C2U);
    for (size_t i = 0; i < total; i++) {
        xrootd_tap_stream_feed(&st, wire + i, 1);   /* 1-byte chunks */
    }
    assert(r.n == 2);
    assert(r.op[0] == kXR_open && strcmp(r.path[0], "/x") == 0);
    assert(r.op[1] == kXR_stat && strcmp(r.path[1], "/y/z") == 0);
}

static void test_stream_response_and_skip(void)
{
    /* a write request (no path, big-ish payload to skip) then a response */
    uint8_t buf[600]; memset(buf, 0, sizeof(buf));
    uint16_t sid = htons(9), op = htons(kXR_write);
    uint32_t dlen = htonl(500);
    memcpy(buf, &sid, 2); memcpy(buf + 2, &op, 2);
    memcpy(buf + 20, &dlen, 4);           /* 24B hdr + 500B payload */
    size_t reqlen = 24 + 500;
    uint8_t resp[8];
    mk_response(resp, 9, kXR_ok, 0);

    xrootd_tap_ctx_t tap; memset(&tap, 0, sizeof(tap));
    struct rec_ctx rq; memset(&rq, 0, sizeof(rq));
    struct rec_ctx rs; memset(&rs, 0, sizeof(rs));
    xrootd_tap_register_sink(&tap, rec_sink, &rq);
    xrootd_tap_stream_t cu; xrootd_tap_stream_init(&cu, &tap, XROOTD_TAP_C2U);
    xrootd_tap_stream_feed(&cu, buf, reqlen);
    assert(rq.n == 1 && rq.op[0] == kXR_write);   /* emitted on header, payload skipped */

    memset(&tap, 0, sizeof(tap));
    xrootd_tap_register_sink(&tap, rec_sink, &rs);
    xrootd_tap_stream_t uc; xrootd_tap_stream_init(&uc, &tap, XROOTD_TAP_U2C);
    xrootd_tap_stream_feed(&uc, resp, 8);
    assert(rs.n == 1 && rs.op[0] == kXR_ok);
}
```

Add `test_stream_chunked(); test_stream_response_and_skip();` to `main`.

- [ ] **Step 2: Run to verify it fails**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/net/tap/tap_decode.c src/net/tap/tap_emit.c src/net/tap/tap_audit.c 2>&1 | head -3`
Expected: FAIL — undefined `xrootd_tap_stream_init` / `_feed`.

- [ ] **Step 3: Add the stream API to `tap.h`** (after the audit formatter decl):

```c
/* ---- streaming decoder (tap_stream.c) ----
 * Feeds the byte-relay: one per direction. Reassembles frame headers across
 * arbitrary chunk boundaries, captures the path for path-bearing requests (up to
 * XROOTD_TAP_PATH_CAP bytes), and emits each frame to `tap`. Non-path frames
 * (and all responses) emit as soon as the header is complete; the payload is
 * skipped, never buffered whole. */
#define XROOTD_TAP_PATH_CAP 1024

typedef struct {
    xrootd_tap_ctx_t *tap;
    xrootd_tap_dir_t  dir;
    size_t            hdr_need;                  /* 24 (C2U) or 8 (U2C) */
    uint8_t           hdr[24];
    size_t            hdr_got;
    int               in_payload;                /* 0 = filling header */
    uint64_t          payload_left;
    xrootd_tap_frame_t cur;                      /* decoded-from-header frame */
    uint8_t           pathbuf[XROOTD_TAP_PATH_CAP];
    size_t            path_cap;                  /* bytes still to capture */
    size_t            path_got;
    int               emitted;                   /* cur already emitted? */
} xrootd_tap_stream_t;

void xrootd_tap_stream_init(xrootd_tap_stream_t *st, xrootd_tap_ctx_t *tap,
    xrootd_tap_dir_t dir);
void xrootd_tap_stream_feed(xrootd_tap_stream_t *st, const uint8_t *buf,
    size_t len);
```

- [ ] **Step 4: Write `src/net/tap/tap_stream.c`**:

```c
/*
 * tap_stream.c — chunk-wise streaming frame decoder for the byte relay.
 *
 * The relay hands us bytes as they arrive off the wire (arbitrary chunk sizes).
 * A two-phase state machine reassembles each frame: collect the fixed header
 * (24B request / 8B response), decode it, then consume `dlen` payload bytes —
 * capturing the first XROOTD_TAP_PATH_CAP of them as the path for a path-bearing
 * request. A path frame emits once its path bytes are in; every other frame emits
 * the moment its header completes, so a large write/read payload is skipped, never
 * buffered.
 */

#include "tap.h"

#include <string.h>

void
xrootd_tap_stream_init(xrootd_tap_stream_t *st, xrootd_tap_ctx_t *tap,
    xrootd_tap_dir_t dir)
{
    memset(st, 0, sizeof(*st));
    st->tap      = tap;
    st->dir      = dir;
    st->hdr_need = (dir == XROOTD_TAP_C2U) ? 24 : 8;
}

/* Header complete: decode it, set up payload accounting + path capture. */
static void
tap_stream_on_header(xrootd_tap_stream_t *st)
{
    if (st->dir == XROOTD_TAP_C2U) {
        xrootd_tap_decode_request(st->hdr, st->hdr_need, &st->cur);
    } else {
        xrootd_tap_decode_response(st->hdr, st->hdr_need, &st->cur);
    }
    st->in_payload  = 1;
    st->payload_left = st->cur.dlen;
    st->emitted     = 0;
    st->path_got    = 0;
    st->path_cap    = 0;

    /* decode_* set cur.path into the (short) hdr buffer; the real path lives in
     * the payload that follows, so capture it ourselves and re-point cur.path. */
    if (st->cur.path != NULL && st->cur.dlen > 0) {
        st->path_cap = (st->cur.dlen < XROOTD_TAP_PATH_CAP)
                     ? st->cur.dlen : XROOTD_TAP_PATH_CAP;
        st->cur.path = NULL;
        st->cur.path_len = 0;
    }

    if (st->path_cap == 0) {                 /* nothing to wait for → emit now */
        xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
        st->emitted = 1;
        if (st->payload_left == 0) {         /* whole frame done */
            st->in_payload = 0;
            st->hdr_got = 0;
        }
    }
}

void
xrootd_tap_stream_feed(xrootd_tap_stream_t *st, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        if (!st->in_payload) {
            size_t need = st->hdr_need - st->hdr_got;
            size_t take = (len < need) ? len : need;
            memcpy(st->hdr + st->hdr_got, buf, take);
            st->hdr_got += take;
            buf += take; len -= take;
            if (st->hdr_got == st->hdr_need) {
                tap_stream_on_header(st);
            }
            continue;
        }

        /* in payload: capture path bytes (if any left), then skip the rest */
        size_t take = (len < st->payload_left) ? len : (size_t) st->payload_left;
        if (st->path_cap > st->path_got) {
            size_t cap = st->path_cap - st->path_got;
            if (cap > take) { cap = take; }
            memcpy(st->pathbuf + st->path_got, buf, cap);
            st->path_got += cap;
        }
        buf += take; len -= take;
        st->payload_left -= take;

        if (!st->emitted && st->path_got >= st->path_cap) {
            st->cur.path     = st->pathbuf;
            st->cur.path_len = st->path_got;
            xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
            st->emitted = 1;
        }
        if (st->payload_left == 0) {
            if (!st->emitted) {              /* defensive: emit even if capped at 0 */
                xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
            }
            st->in_payload = 0;
            st->hdr_got = 0;
        }
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `gcc -Wall -Wextra -o /tmp/tap_unittest tests/tap_unittest.c src/net/tap/tap_decode.c src/net/tap/tap_emit.c src/net/tap/tap_audit.c src/net/tap/tap_stream.c && /tmp/tap_unittest`
Expected: PASS — `tap_unittest: all checks passed`.

- [ ] **Step 6: Register `tap_stream.c`** in `config` next to the other tap sources; **commit SKIP**.

---

### Task 2 (3b): Transparent relay subsystem + config + audit sink

**Files:**
- Create: `src/protocols/root/relay/relay.h`, `src/protocols/root/relay/relay.c`
- Modify: `src/core/types/config.h` (relay addr/name fields), `src/core/config/server_conf.c` (init+merge), `src/protocols/root/stream/module.c` (directive), `src/protocols/root/connection/handler.c` (engage seam)
- Modify: `config` (register `src/protocols/root/relay/relay.c`)

**Interfaces:**
- Consumes: `xrootd_tap_stream` (Task 1), `xrootd_tap_audit_format` (Phase 2), the handoff relay pattern.
- Produces: directive `xrootd_transparent_proxy host:port` → `conf->relay_addr` (`ngx_addr_t*`) + `conf->relay_name`; `char *xrootd_conf_set_transparent_proxy(ngx_conf_t*, ngx_command_t*, void*)`; `ngx_int_t xrootd_relay_start(ngx_stream_session_t*, ngx_connection_t*, void *srv_conf)`.

- [ ] **Step 1: Write the failing integration test** `tests/run_transparent_relay.sh`:

```bash
#!/usr/bin/env bash
# Transparent relay: a root:// client through the relay reaches a real origin
# byte-exact, and the relay's tap logs the opcodes (open/stat) to error.log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11950; RP=11951
PFX="$(mktemp -d /tmp/relay.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/relay_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; brix_root on; xrootd_root $PFX/o/root; xrootd_auth none; } }
EOF
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${RP}; brix_root on;
    xrootd_transparent_proxy 127.0.0.1:${OP};
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo relay-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 300000 /dev/urandom > "$PFX/o/root/f.bin"

# byte-exact passthrough via the relay
"$XRDFS" root://127.0.0.1:${RP} cat /f.bin > /tmp/relay_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/relay_a.got && ok "relay passthrough byte-exact" || bad "relay passthrough mismatch"

# stat through the relay (a metadata op for the tap to log)
"$XRDFS" root://127.0.0.1:${RP} stat /f.bin >/dev/null 2>&1 && ok "stat via relay" || bad "stat via relay failed"

sleep 0.5
grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" || bad "tap did not log open"
grep -q '"op":"stat"' "$PFX/n/logs/e.log" && ok "tap logged stat" || bad "tap did not log stat"
exit $fail
```

`chmod +x`. Run: `tests/run_transparent_relay.sh` → FAIL (`unknown directive "xrootd_transparent_proxy"`).

- [ ] **Step 2: Config field + directive + merge.**
  - `src/core/types/config.h`: near `http_handoff_addr`, add `ngx_addr_t *relay_addr; ngx_str_t relay_name;`.
  - `src/core/config/server_conf.c`: init `conf->relay_addr = NULL;`; merge-inherit like `http_handoff_addr` (copy from prev if unset).
  - `src/protocols/root/stream/module.c`: register `{ ngx_string("xrootd_transparent_proxy"), NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1, xrootd_conf_set_transparent_proxy, NGX_STREAM_SRV_CONF_OFFSET, 0, NULL }`.
  - Directive handler `xrootd_conf_set_transparent_proxy` (in `relay.c`): `ngx_parse_url` the arg (host:port), store `ngx_addr_t*` in `conf->relay_addr`, name in `conf->relay_name` (mirror `xrootd_conf_set_http_handoff` in handoff.c exactly). Declare its prototype in `relay.h`.

- [ ] **Step 3: Write `src/protocols/root/relay/relay.{h,c}`** — copy `src/protocols/root/handoff/handoff.c`'s struct + `*_pump`/`*_cu`/`*_uc`/4 handlers/`*_begin_relay`/`*_connect_done`/peer-connect, renaming `handoff`→`relay`, with these changes:
  1. The struct gains `xrootd_tap_ctx_t tap; xrootd_tap_stream_t cu_dec; xrootd_tap_stream_t uc_dec;` and registers the audit sink in `xrootd_relay_start`.
  2. In the pump, immediately after a successful `recv` (`n > 0`), call `xrootd_tap_stream_feed(dec, buf, (size_t) n);` where `dec` is the direction's decoder (pass it into `relay_pump`). This taps each byte exactly once.
  3. `xrootd_relay_start` takes no `prefix` (engages before any read): `cu_off = cu_end = 0`. Connect to `conf->relay_addr` (not http_handoff_addr).
  4. Store the relay hub on `ctx` (add `void *relay;` to `xrootd_ctx_t` next to `handoff`, or reuse a generic slot) so the client-side handlers can resolve it; upstream-side uses `u->data`.
  5. Audit sink: `static void relay_audit_sink(void *ctx, const xrootd_tap_frame_t *f, xrootd_tap_dir_t dir, const uint8_t *p, size_t pl)` → `char line[1200]; if (xrootd_tap_audit_format(f, dir, line, sizeof(line))) ngx_log_error(NGX_LOG_INFO, ((ngx_log_t*)ctx), 0, "xrootd tap: %s", line);` with `ctx = c->log`.

- [ ] **Step 4: Engage seam** in `src/protocols/root/connection/handler.c` — after ctx init, before the normal handshake path:

```c
    if (mconf->relay_addr != NULL) {
        if (xrootd_relay_start(s, c, mconf) != NGX_OK) {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }
```

(Include `src/protocols/root/relay/relay.h`.) Confirm the exact local names (`mconf`/`s`/`c`) match handler.c.

- [ ] **Step 5: Register + build.** Add `$ngx_addon_dir/src/protocols/root/relay/relay.c` to `config`; then:
```
cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
  --with-http_ssl_module --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j"$(nproc)" 2>&1 | tail -5
```
Expected: build exit 0.

- [ ] **Step 6: Run the integration test.**

Run: `tests/run_transparent_relay.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — passthrough byte-exact, stat works, tap logged `open` + `stat`.

- [ ] **Step 7: Parity check** — `tests/run_cache_xroot_origin.sh` still PASS (a server without `xrootd_transparent_proxy` is unaffected). **Commit SKIP.**

---

## Notes / Deferred

- **Family policy on the relay upstream:** Phase 3 resolves the upstream at config time via `ngx_parse_url` (single address). Forcing the relay's upstream family (`XROOTD_AF_*`) is a small follow-up — wire `xrootd_resolve_connect_socket(..., af_policy, ...)` into the connect path.
- **Metrics / full-capture / inspection-hook sinks:** the audit sink lands here; the others are additional `xrootd_tap_register_sink` adapters, added when needed.
- **Phase 4:** the NEW independent terminating proxy (clean `xrootd_terminating_proxy*` config, NOT the removed `xrootd_proxy*`) + GSI X.509 delegation; it reuses the same tap core.

## Self-Review

- **Spec coverage:** spec §5 (transparent relay: verbatim byte relay + non-consuming cleartext decode + capture/hook) → Task 2 relay + Task 1 streaming decode; audit sink wires the tap; capture/hook sinks deferred (documented). §5.1 "reuse splice/relay" → mirrors handoff. The cleartext-only-visibility property holds: the relay taps the plaintext bytes it forwards; a full-TLS client↔origin session yields only ciphertext to the decoder (no frames emitted), as designed.
- **Placeholder scan:** Task 1 is fully coded; Task 2 specifies the mirror-of-handoff edits precisely (struct additions, pump tap point, connect target, engage seam, audit sink) rather than re-pasting ~250 lines of handoff verbatim — the source to copy is named exactly (`src/protocols/root/handoff/handoff.c`).
- **Type consistency:** `xrootd_tap_stream_t`/`_init`/`_feed` defined in `tap.h` (Task 1), used in `relay.c` (Task 2); audit sink uses `xrootd_tap_audit_format` (Phase 2) unchanged.
