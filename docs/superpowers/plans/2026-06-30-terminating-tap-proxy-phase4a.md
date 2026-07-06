# Terminating Tap Proxy (Phase 4a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Revive the existing (directive-disabled) terminating reverse proxy under a clean `xrootd_tap_proxy*` config surface and wire the Phase-2 tap into it, so a `root://` client is authenticated locally, re-authenticated upstream as the user (anonymous / token / SSS / username — already built), forwarded verbatim opcode-by-opcode, and every request/response is decoded and emitted to a JSON audit log. GSI X.509 delegation is deferred to Phase 4b.

**Architecture:** `src/net/proxy/` is a complete, cache-independent terminating proxy (connect → bootstrap with ztn/SSS/file-token/anonymous login → forward with file-handle translation → relay with `kXR_wait`/`kXR_redirect`/splice). It is still compiled in; only its `xrootd_proxy*` directives were removed. This phase re-adds the directive table entries under `xrootd_tap_proxy*` names mapped to the *existing* handlers/fields, then feeds the Phase-2 tap from the two points where the proxy already has fully-assembled frames: `xrootd_proxy_forward_request()` (client→upstream request buffer) and `xrootd_proxy_relay_to_client()` (upstream→client status/dlen). The tap uses the stable-log-copy pattern proven in Phase 3.

**Tech Stack:** C nginx stream module, the existing proxy runtime, the Phase-2 tap core, bash+xrdfs integration test.

## Global Constraints

- **NO `goto`**; functional/modular; no new globals; reuse existing handlers/fields.
- **HELPERS — reuse:** the existing `xrootd_conf_set_proxy_*` handlers, the proxy runtime, `xrootd_tap_decode_request`/`xrootd_tap_emit`/`xrootd_tap_audit_format` (Phase 2). Do NOT re-implement the proxy or re-parse frames the proxy already parsed.
- **Stable log:** the tap sink must use a log copy with `.handler/.data/.action = NULL` (Phase-3 lesson — a captured session log goes stale and SIGSEGVs).
- **Build governance:** no new `.c` files (edits to existing proxy + module + config) → `make` only, no `./configure`.
- **3 tests:** success (terminating proxy passthrough byte-exact + tap logs opcodes), error (upstream down → clean client error), parity (a server without `xrootd_tap_proxy` is unaffected).

---

### Task 1: Revive the directive surface as `xrootd_tap_proxy*`

**Files:**
- Modify: `src/protocols/root/stream/module.c` (add directive table entries)

**Interfaces:**
- Consumes: existing handlers `xrootd_conf_set_proxy_upstream`/`_auth`/`_login_user` (from `proxy/proxy.h`, already declared) and the config field offsets (`proxy_enable`, `proxy_audit_log`, `proxy_upstream_tls`).
- Produces: working directives `xrootd_tap_proxy on|off`, `xrootd_tap_proxy_upstream host:port`, `xrootd_tap_proxy_auth ...`, `xrootd_tap_proxy_login_user ...`, `xrootd_tap_proxy_audit_log <path>`, `xrootd_tap_proxy_upstream_tls on|off`.

- [ ] **Step 1: Write the failing config test** `tests/run_tap_proxy.sh` (full version in Task 3 Step 1 — for now it asserts the directive is accepted). Quick check:

Run: build a minimal conf with `xrootd_tap_proxy on; xrootd_tap_proxy_upstream 127.0.0.1:1094;` and `nginx -t`.
Expected (before edit): FAIL `unknown directive "xrootd_tap_proxy"`.

- [ ] **Step 2: Ensure module.c includes the proxy directive prototypes**

Confirm `#include "../proxy/proxy.h"` is present in `src/protocols/root/stream/module.c` (the handlers are declared there). If absent, add it.

- [ ] **Step 3: Add the directive entries** in `src/protocols/root/stream/module.c` (next to the `xrootd_transparent_proxy` block from Phase 3):

```c
    { ngx_string("xrootd_tap_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_enable),
      NULL },

    { ngx_string("xrootd_tap_proxy_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      xrootd_conf_set_proxy_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_auth,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_login_user"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_login_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_tap_proxy_audit_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_audit_log),
      NULL },

    { ngx_string("xrootd_tap_proxy_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls),
      NULL },
```

(Confirm the `NGX_CONF_TAKE12` arg-count for `xrootd_conf_set_proxy_upstream` matches the old registration; check `git log`/the handler body for how many args it reads. If it reads exactly one `host:port`, use `NGX_CONF_TAKE1`.)

- [ ] **Step 4: Build + verify the directive is accepted**

Run: `make -j$(nproc)` then `nginx -t` on the minimal conf.
Expected: build exit 0; `nginx -t` succeeds.

- [ ] **Step 5: Commit** — SKIP.

---

### Task 2: Wire the Phase-2 tap into the proxy

**Files:**
- Modify: `src/net/proxy/proxy_internal.h` (add tap fields to `xrootd_proxy_ctx_t`)
- Modify: `src/net/proxy/forward_relay_dispatch.c` (init the tap at ctx alloc)
- Modify: `src/net/proxy/forward_request.c` (emit C2U request frame)
- Modify: `src/net/proxy/forward_relay_response.c` (emit U2C response frame)

**Interfaces:**
- Consumes: `xrootd_tap_ctx_t`, `xrootd_tap_decode_request`, `xrootd_tap_emit`, `xrootd_tap_audit_format` (Phase 2).
- Produces: `proxy->tap` populated; a JSON `xrootd tap:` line per forwarded request and relayed response.

- [ ] **Step 1: Add tap fields + a shared sink declaration**

In `src/net/proxy/proxy_internal.h`, add `#include "../tap/tap.h"` and, inside `xrootd_proxy_ctx_t`:

```c
    /* Phase-4a observation tap: a stable log copy (no session appender) + the
     * fan-out ctx with the audit sink registered, fed from forward/relay. */
    xrootd_tap_ctx_t  tap;
    ngx_log_t         tap_log;
    int               tap_inited;
```

Declare the sink (so both dispatch + relay TUs share one definition — define it in forward_relay_dispatch.c, declare here):

```c
void xrootd_proxy_tap_audit_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const u_char *payload, size_t payload_len);
void xrootd_proxy_tap_init(xrootd_proxy_ctx_t *proxy, ngx_connection_t *c);
```

- [ ] **Step 2: Define the sink + init in `forward_relay_dispatch.c`**

Add near the top (after includes):

```c
void
xrootd_proxy_tap_audit_sink(void *ctx, const xrootd_tap_frame_t *f,
    xrootd_tap_dir_t dir, const u_char *payload, size_t payload_len)
{
    ngx_log_t *log = ctx;
    char       line[1280];

    (void) payload;
    (void) payload_len;

    if (xrootd_tap_audit_format(f, dir, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0, "xrootd tap: %s", line);
    }
}

void
xrootd_proxy_tap_init(xrootd_proxy_ctx_t *proxy, ngx_connection_t *c)
{
    if (proxy->tap_inited) {
        return;
    }
    proxy->tap_log         = *c->log;
    proxy->tap_log.handler = NULL;
    proxy->tap_log.data    = NULL;
    proxy->tap_log.action  = NULL;
    ngx_memzero(&proxy->tap, sizeof(proxy->tap));
    xrootd_tap_register_sink(&proxy->tap, xrootd_proxy_tap_audit_sink,
                             &proxy->tap_log);
    proxy->tap_inited = 1;
}
```

Then call `xrootd_proxy_tap_init(proxy, c);` immediately after the `proxy = ngx_pcalloc(c->pool, sizeof(xrootd_proxy_ctx_t));` success check at `forward_relay_dispatch.c:117`.

- [ ] **Step 3: Emit the request frame in `forward_request.c`**

After the request buffer `req` is fully assembled (and any path rewrite applied — emit what is actually sent upstream), before the queue/flush, add:

```c
    {
        xrootd_tap_frame_t tf;
        if (xrootd_tap_decode_request(req, total, &tf) > 0) {
            xrootd_tap_emit(&proxy->tap, &tf, XROOTD_TAP_C2U, NULL, 0);
        }
    }
```

Place it once on the common path (e.g. just before the request is queued to the upstream `wbuf`). Ensure `req`/`total` reflect the final post-rewrite frame at that point.

- [ ] **Step 4: Emit the response frame in `forward_relay_response.c`**

In `xrootd_proxy_relay_to_client()`, after `status`/`dlen` are read (~line 40-42), add:

```c
    {
        xrootd_tap_frame_t tf;
        ngx_memzero(&tf, sizeof(tf));
        tf.is_request = 0;
        tf.streamid   = (uint16_t) ((proxy->fwd_streamid[0] << 8)
                                     | proxy->fwd_streamid[1]);
        tf.status     = status;
        tf.dlen       = dlen;
        xrootd_tap_emit(&proxy->tap, &tf, XROOTD_TAP_U2C, NULL, 0);
    }
```

- [ ] **Step 5: Build**

Run: `make -j$(nproc)`
Expected: exit 0, no warnings (`-Werror`).

- [ ] **Step 6: Commit** — SKIP.

---

### Task 3: Integration test

**Files:**
- Create: `tests/run_tap_proxy.sh`

- [ ] **Step 1: Write the test** `tests/run_tap_proxy.sh`:

```bash
#!/usr/bin/env bash
# Terminating tap proxy: client authenticates to the proxy (anon), the proxy
# re-logs-in to the origin and forwards opcodes; passthrough is byte-exact and
# the tap logs the forwarded opcodes (open/read) to error.log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11960; PP=11961
PFX="$(mktemp -d /tmp/tapproxy.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/tapproxy_*.got; }
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
    listen 127.0.0.1:${PP}; brix_root on; xrootd_auth none;
    xrootd_tap_proxy on;
    xrootd_tap_proxy_upstream 127.0.0.1:${OP};
    xrootd_tap_proxy_auth anonymous;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo proxy-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 400000 /dev/urandom > "$PFX/o/root/f.bin"

"$XRDFS" root://127.0.0.1:${PP} cat /f.bin > /tmp/tapproxy_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/tapproxy_a.got && ok "terminating proxy passthrough byte-exact" || bad "passthrough mismatch"
"$XRDFS" root://127.0.0.1:${PP} stat /f.bin >/dev/null 2>&1 && ok "stat via tap proxy" || bad "stat failed"

sleep 0.5
grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" || bad "tap did not log open"
grep -q '"dir":"u2c"' "$PFX/n/logs/e.log" && ok "tap logged a response" || bad "tap did not log response"
exit $fail
```

`chmod +x`.

- [ ] **Step 2: Run**

Run: `tests/run_tap_proxy.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — byte-exact, stat works, tap logged `open` + a `u2c` response.

- [ ] **Step 3: Parity**

Run: `tests/run_transparent_relay.sh` and `tests/run_cache_xroot_origin.sh`
Expected: both still PASS (Phase-3 relay + non-proxy servers unaffected).

- [ ] **Step 4: Commit** — SKIP.

---

## Notes / Deferred (Phase 4b)

- **GSI X.509 proxy delegation upstream** — the high-risk piece (native TPC GSI already broken). Own spec/plan. Until then the tap proxy forwards anonymous/token(ztn)/SSS/username, which `src/net/proxy/` already supports.
- **Tap richness:** request path + opcode + response status/dlen now; per-handle path correlation, capture/metrics sinks are follow-ups.
- The old `xrootd_proxy*` directives stay removed; `xrootd_tap_proxy*` is the supported surface.

## Self-Review

- **Spec coverage:** spec §2 terminating MITM (re-auth upstream as the user) + §4 tap-into-terminating-proxy → Task 1 (config) + Task 2 (tap wiring on the existing forwarder). Credential forwarding (token/SSS/username) is the existing proxy's; GSI deferred to 4b per the approved phasing.
- **Placeholder scan:** none — every step has concrete code; the one verification note (TAKE12 vs TAKE1) is a check-then-pick, not a placeholder.
- **Type consistency:** `proxy->tap` is `xrootd_tap_ctx_t`; `xrootd_proxy_tap_init`/`_audit_sink` signatures match between the `proxy_internal.h` declaration and the `forward_relay_dispatch.c` definition; the emit calls use `xrootd_tap_frame_t`/`xrootd_tap_emit` exactly as defined in Phase 2.
