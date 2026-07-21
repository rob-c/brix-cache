# Phase 22 — Advanced Stream Health Checks

**Status:** ✅ Implemented (as-built diverges from this plan — see status section)  
**Depends on:** None (standalone; Phase 20 KV can be adopted later for rate data)  
**Touches:** `src/net/manager/`, `src/net/upstream/`, `src/observability/metrics/`  
**Net LoC:** +~680 new, ~0 removed

---

## Implementation status (as-built — reconciled 2026-06-13)

Audited against the code under `src/`. **Active stream health checking is
implemented and wired**: the registry carries the HC fields and claim/pass/fail
API, `src/net/manager/health_check.{c,h}` runs the probe state machine + timer,
six directives configure it (off by default), and cluster metrics export the
results. Several details diverge from this plan; the one genuinely *reduced*
piece was TLS probing (Step F) — **closed 2026-07-21**, see row F.

| Step | Capability | Status | Evidence / divergence |
|------|-----------|--------|-----------------------|
| **A** | Registry extensions | ✅ **Done** | `xrootd_srv_entry_t` has `hc_next_check`/`hc_last_ok`/`hc_fail_count`/`hc_in_progress` (`registry.h:39-42`); snapshot entry has `hc_last_ok`/`hc_fail_count` (`:60-61`). `xrootd_srv_hc_claim` (`registry.c:626`), `xrootd_srv_hc_pass` (`:666`), `xrootd_srv_hc_fail` (`:701`). Note: `hc_fail` returns `int` (1 if it newly blacklisted), not `void` as sketched. |
| **B** | Probe state machine | ✅ **Done — more granular states** | `src/net/manager/health_check.c`. States are `XRD_HC_HANDSHAKE → XRD_HC_PROTOCOL → XRD_HC_LOGIN → XRD_HC_PROBE` (mirroring the real upstream bootstrap phases), **not** the doc's `CONNECTING/BOOTSTRAP/PROBE/DONE`. Probe sends `kXR_ping` or `kXR_stat "/"` (`xrootd_hc_send_probe`, `:111`). The ctx is `xrootd_hc_ctx_t` (`:61`) — defined in the `.c`, not exported in the header as the doc proposed. |
| **C** | Health-check timer | ✅ **Done — different start hook** | `xrootd_hc_mgr_t`, `xrootd_hc_timer_handler` (`:487`), `xrootd_hc_manager_start` (`:504`), `xrootd_hc_start` (`:368`). Started from **`src/core/config/process.c:163`** (the module's `init_process`), **not** `src/protocols/root/stream/module.c` as the file map said. Scan interval = `interval / slots`, min 100 ms. |
| **D** | Config directives | ✅ **Done** | All six `xrootd_health_check[_interval/_timeout/_threshold/_blacklist/_type]` directives are registered in **`src/protocols/root/stream/module.c`** (not `src/core/config/directives.c`); conf fields `hc_enabled/hc_interval_ms/hc_timeout_ms/hc_threshold/hc_blacklist_ms/hc_type` in `src/core/types/config.h:357-362`. Off by default. |
| **E** | Metrics | ✅ **Done — different counter set** | `src/observability/metrics/cluster.c` exports `xrootd_cluster_hc_{probes,pass,fail,blacklist}_total` (fields in `metrics.h:490-493`). Diverges from the plan: there is an **extra `hc_probes_total`** (probes started) and **no `hc_probe_active` gauge**. Per-server `hc_last_ok`/`hc_fail_count` are in the snapshot for the dashboard. |
| **F** | TLS support for probes | ✅ **Done (2026-07-21, via a shared-function seam rather than the planned ctx struct)** | `brix_outbound_start_tls()` extracted from `src/net/upstream/tls.c` (declared in `upstream_internal.h`), `brix_upstream_start_tls()` is now a thin wrapper over it. With `brix_upstream_tls on` + `brix_upstream_tls_ca` on the manager block, a probe advertises `kXR_ableTLS`, **defers login past the protocol verdict** (see below), and on `kXR_gotoTLS` upgrades the connection, re-sends a fresh login over TLS, and completes the full login+ping/stat probe (`brix_hc_tls_handshake_done`). Handshake or peer-verify failure = probe **failure**. Without an outbound TLS ctx, the old shallow protocol-OK-alive behavior is preserved byte-identically. Tests: `test_phase22_health_check.py` §4 (deep pass / untrusted-CA fail / shallow fallback). |

### As-built divergences (none are correctness defects)

1. **Bootstrap states are granular** (`HANDSHAKE/PROTOCOL/LOGIN/PROBE`) to match the
   upstream bootstrap, and the probe can **finish early as a pass** at the protocol
   or login stage (e.g. server wants TLS, or login isn't required) — it confirms
   liveness without always reaching `kXR_ping`.
2. **Directives live in `src/protocols/root/stream/module.c`**, the start hook in
   `src/core/config/process.c`, and the ctx struct stays private to `health_check.c` —
   different files than the plan's File Map.
3. **Metrics: `hc_probes_total` replaces the planned `hc_probe_active` gauge.**

### Pending / not done

- ~~**Step F (TLS-upgraded probes):** not implemented.~~ **DONE 2026-07-21** —
  see row F above and § Step F below. Two wire facts discovered while landing it:
  1. a brix server only answers `kXR_gotoTLS` to clients that advertised
     `kXR_ableTLS`/`kXR_wantTLS` (`session/protocol.c`) — a flagless probe is
     simply allowed to finish in cleartext, silently skipping the deep path —
     so TLS-capable probes send the flag (`brix_upstream_build_bootstrap_flags`);
  2. a TLS-capable probe must **not pipeline the plaintext login** behind the
     protocol request: on `kXR_gotoTLS` the server hands all pending cleartext
     bytes to `SSL_do_handshake` ("packet length too long"). The probe now sends
     handshake+protocol only and sends login after the verdict (cleartext or TLS).
- The shared `xrootd_do_bootstrap()` extraction (Risk Notes) was **not** done — the
  HC bootstrap is a parallel implementation of the upstream bootstrap phases.

---

## Motivation

The current health model is purely passive and reactive:

| Signal | How detected | Latency |
|---|---|---|
| Data server TCP disconnect | CMS `server_recv.c` → `xrootd_srv_blacklist(30s)` | Immediate |
| Disk/IO failure (process alive) | First client locate fails; upstream query times out | Per-request |
| Kernel-socket half-open (TCP keepalive) | Only if SO_KEEPALIVE fires (~minutes) | Minutes |

A storage node whose XRootD process is up but hung (e.g., deadlocked I/O subsystem,
journaling freeze, slow CEPH OSD) keeps its CMS connection alive and passes TCP checks.
`xrootd_srv_select()` continues routing real client traffic to it until the upstream
locate query times out — which blocks the client for the full `XROOTD_UP_WAIT_MAX` (60s).

Active health checks solve this by probing each registered server on a fixed schedule
and blacklisting before clients are redirected there.

---

## Current State

**Registry:** `src/net/manager/registry.c` — 128-slot SHM table with `blacklisted_until`
and `error_count` fields. `xrootd_srv_select()` skips blacklisted entries. No timing
field for health check scheduling.

**CMS liveness probe:** `src/net/cms/server_send.c:xrootd_cms_srv_send_ping()` sends a
CMS-layer `kYR_ping` to data servers. This is a *CMS protocol* heartbeat, not an
XRootD-protocol health probe — it confirms the CMS management socket is alive, not
that the data server can serve XRootD file operations.

**Upstream connect:** `src/net/upstream/` opens a per-request XRootD connection with full
bootstrap (handshake → protocol → TLS → login) before sending a locate/open query.
This bootstrap machinery is exactly what a health probe needs — reusing it avoids
duplicating wire-protocol logic.

**No active probing exists.** There are no timers in the module that initiate
outbound XRootD connections for health-check purposes.

> **Historical (pre-Phase-22).** Active probing now exists — see the
> *Implementation status* section above. `src/net/manager/health_check.c` runs a timer
> that opens outbound probe connections and feeds verdicts back into the registry.

---

## Design Overview

```
nginx worker 0..N                         data server
    │                                         │
    │  [every hc_interval / N_slots ms]       │
    │──── TCP connect ──────────────────────► │
    │──── handshake + protocol + login ──────►│
    │──── kXR_ping (or kXR_stat "/") ────────►│
    │◄─── kXR_ok ─────────────────────────── │
    │  success: clear blacklist + reset       │
    │  fail/timeout: increment hc_fail_count  │
    │    if >= threshold: blacklist(duration) │
    │  close probe connection                 │
```

Worker coordination uses the SHM registry spinlock and a new `hc_next_check` field:
workers race to claim a slot (CAS via `ngx_shmtx_trylock`) and the winner probes.
This means exactly one worker probes each server per interval, regardless of worker
count.

---

## Step A — Registry Extensions

**File:** `src/net/manager/registry.h`

Add four fields to `xrootd_srv_entry_t`:

```c
typedef struct {
    char        host[256];
    uint16_t    port;
    char        paths[XROOTD_SRV_MAX_PATHS];
    uint32_t    free_mb;
    uint32_t    util_pct;
    ngx_msec_t  last_seen;
    ngx_uint_t  in_use;
    ngx_msec_t  blacklisted_until;
    uint32_t    error_count;

    /* Health check additions */
    ngx_msec_t  hc_next_check;   /* absolute ms: when next probe is due */
    ngx_msec_t  hc_last_ok;      /* absolute ms: time of last passing probe */
    uint32_t    hc_fail_count;   /* consecutive probe failures */
    ngx_uint_t  hc_in_progress;  /* 1 = a worker has claimed this slot */
} xrootd_srv_entry_t;
```

Also add to `xrootd_srv_snapshot_entry_t` (for the dashboard API):

```c
    ngx_msec_t  hc_last_ok;
    uint32_t    hc_fail_count;
```

New registry API functions (declared in `registry.h`, implemented in `registry.c`):

```c
/*
 * Try to claim a registry slot for health checking.
 * Returns 1 and fills host_out/port_out if a slot is due for probing
 * and no other worker has claimed it yet. Sets hc_in_progress=1 and
 * advances hc_next_check by interval_ms inside the spinlock.
 * Returns 0 if no slot is due.
 */
int xrootd_srv_hc_claim(char *host_out, size_t host_size,
    uint16_t *port_out, ngx_msec_t interval_ms);

/* Called by health check on probe success: clears hc_fail_count,
 * updates hc_last_ok, clears hc_in_progress. If server was
 * blacklisted solely due to health check failures, clears blacklist. */
void xrootd_srv_hc_pass(const char *host, uint16_t port);

/* Called on probe failure: increments hc_fail_count, clears
 * hc_in_progress. If fail_count >= threshold, calls xrootd_srv_blacklist. */
void xrootd_srv_hc_fail(const char *host, uint16_t port,
    uint32_t threshold, ngx_msec_t blacklist_duration_ms);
```

Implementation of `xrootd_srv_hc_claim`:

```c
int
xrootd_srv_hc_claim(char *host_out, size_t host_size, uint16_t *port_out,
    ngx_msec_t interval_ms)
{
    xrootd_srv_table_t *tbl = srv_table();
    ngx_msec_t          now = ngx_current_msec;

    if (tbl == NULL) return 0;

    ngx_shmtx_lock(&xrootd_srv_mutex);

    for (ngx_uint_t i = 0; i < tbl->capacity; i++) {
        xrootd_srv_entry_t *e = &tbl->slots[i];

        if (!e->in_use || e->hc_in_progress) continue;
        if (e->hc_next_check > now)           continue;

        /* Claim this slot */
        e->hc_in_progress = 1;
        e->hc_next_check  = now + interval_ms;

        ngx_strlcpy(host_out, e->host, host_size);
        *port_out = e->port;

        ngx_shmtx_unlock(&xrootd_srv_mutex);
        return 1;
    }

    ngx_shmtx_unlock(&xrootd_srv_mutex);
    return 0;
}
```

---

## Step B — Health Check Context and State Machine

**Files:** `src/net/manager/health_check.c` (new), `src/net/manager/health_check.h` (new)

The health check probe reuses the XRootD wire bootstrap protocol already implemented
in `src/net/upstream/bootstrap.c`. The difference: instead of forwarding a saved client
request after bootstrap, the probe sends `kXR_ping` and closes the connection.

### B1 — Context struct

```c
/* health_check.h */
typedef enum {
    XRD_HC_CONNECTING = 0,
    XRD_HC_BOOTSTRAP,         /* handshake + protocol + login in progress */
    XRD_HC_PROBE,             /* waiting for kXR_ping response */
    XRD_HC_DONE,
} xrootd_hc_state_t;

typedef struct xrootd_hc_ctx_s {
    ngx_connection_t   *conn;
    xrootd_hc_state_t   state;

    /* Bootstrap accumulator (same layout as xrootd_upstream_t) */
    u_char   rhdr[XRD_RESPONSE_HDR_LEN];
    size_t   rhdr_pos;
    uint16_t resp_status;
    uint32_t resp_dlen;
    u_char   resp_body_buf[32];  /* ping response body is empty; 32 bytes is safe */
    size_t   resp_body_pos;

    u_char  *wbuf;
    size_t   wbuf_len;
    size_t   wbuf_pos;

    ngx_event_t  timeout_ev;   /* probe timeout: kills connection if fired */

    char         host[256];
    uint16_t     port;

    /* Config back-references */
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_cycle_t                  *cycle;
    uint32_t    hc_threshold;          /* failures before blacklist */
    ngx_msec_t  hc_blacklist_ms;       /* blacklist duration on failure */
    ngx_msec_t  hc_timeout_ms;         /* probe timeout */
} xrootd_hc_ctx_t;
```

### B2 — State machine

```c
/* health_check.c */

static void
xrootd_hc_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    xrootd_hc_ctx_t *hc = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: health check: %s:%d timed out", hc->host, hc->port);
        xrootd_hc_finish(hc, 0 /* fail */);
        return;
    }

    /* Read response header into rhdr, then body */
    if (xrootd_hc_recv_response(hc) != NGX_OK) {
        xrootd_hc_finish(hc, 0);
        return;
    }

    if (hc->state == XRD_HC_BOOTSTRAP) {
        xrootd_hc_handle_bootstrap(hc);
    } else if (hc->state == XRD_HC_PROBE) {
        /* kXR_ping response received */
        if (hc->resp_status == kXR_ok) {
            xrootd_hc_finish(hc, 1 /* pass */);
        } else {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: health check: %s:%d ping failed (status %d)",
                          hc->host, hc->port, (int) hc->resp_status);
            xrootd_hc_finish(hc, 0);
        }
    }
}

static void
xrootd_hc_handle_bootstrap(xrootd_hc_ctx_t *hc)
{
    /* Mirrors xrootd_upstream_handle_bootstrap_response() but without
     * client_ctx. On BS_DONE → send kXR_ping instead of forwarding
     * a saved client request. */

    /* ... same phase transitions as upstream/bootstrap.c ... */

    if (/* bootstrap done */) {
        hc->state = XRD_HC_PROBE;
        xrootd_hc_send_ping(hc);
    }
}

static void
xrootd_hc_send_ping(xrootd_hc_ctx_t *hc)
{
    ClientPingRequest req;
    ngx_memzero(&req, sizeof(req));
    req.streamid[0] = 0;
    req.streamid[1] = 2;            /* streamid 2 distinguishes health from client reqs */
    req.requestid   = htons(kXR_ping);
    req.dlen        = 0;

    /* Copy into wbuf; xrootd_hc_flush() sends it. */
    hc->wbuf = ngx_palloc(hc->conn->pool, sizeof(req));
    ngx_memcpy(hc->wbuf, &req, sizeof(req));
    hc->wbuf_len = sizeof(req);
    hc->wbuf_pos = 0;

    xrootd_hc_flush(hc);
}

static void
xrootd_hc_finish(xrootd_hc_ctx_t *hc, int passed)
{
    if (hc->timeout_ev.timer_set) {
        ngx_del_timer(&hc->timeout_ev);
    }

    if (hc->conn) {
        ngx_close_connection(hc->conn);
        hc->conn = NULL;
    }

    if (passed) {
        xrootd_srv_hc_pass(hc->host, hc->port);
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->cycle->log, 0,
                       "xrootd: health check: %s:%d passed", hc->host, hc->port);
        XROOTD_HC_METRIC_INC(hc_pass_total);
    } else {
        xrootd_srv_hc_fail(hc->host, hc->port,
                           hc->hc_threshold, hc->hc_blacklist_ms);
        XROOTD_HC_METRIC_INC(hc_fail_total);
    }

    ngx_pfree(hc->cycle->pool, hc);
}
```

### B3 — Probe type: kXR_stat vs kXR_ping

`kXR_ping` is sufficient for confirming the server process responds at the XRootD
protocol level. `kXR_stat "/"` is deeper — it exercises the path resolution and POSIX
`stat()` call chain, catching disk subsystem hangs.

Default: `kXR_ping` (lower overhead, avoids path ACL checks on health connections).  
Optional: `kXR_stat` via `xrootd_health_check_type stat;` directive.

```c
static void
xrootd_hc_send_stat_root(xrootd_hc_ctx_t *hc)
{
    size_t path_len = 1;  /* "/" */
    size_t total = sizeof(ClientStatRequest) + path_len;
    ClientStatRequest *req = ngx_palloc(hc->conn->pool, total);
    ngx_memzero(req, sizeof(*req));
    req->streamid[0] = 0;
    req->streamid[1] = 2;
    req->requestid   = htons(kXR_stat);
    req->options     = 0;
    req->dlen        = htonl((kXR_int32) path_len);
    ((u_char *) req)[sizeof(*req)] = '/';

    hc->wbuf     = (u_char *) req;
    hc->wbuf_len = total;
    hc->wbuf_pos = 0;
    xrootd_hc_flush(hc);
}
```

For `kXR_stat`, the response body is a 4-field space-separated string
(`id flags modtime devid`) — parse only that `resp_status == kXR_ok`.

---

## Step C — Health Check Timer

**File:** `src/net/manager/health_check.c`

```c
/*
 * xrootd_hc_timer_handler — periodic scanner for due health checks.
 *
 * Fires every `hc_scan_interval` ms (= hc_interval / max_slots, minimum 100ms).
 * Each firing calls xrootd_srv_hc_claim() once; if a slot is claimed, starts
 * a probe. Re-arms itself.
 */
static void
xrootd_hc_timer_handler(ngx_event_t *ev)
{
    xrootd_hc_mgr_t             *mgr = ev->data;
    ngx_stream_xrootd_srv_conf_t *conf = mgr->conf;
    char     host[256];
    uint16_t port;

    ngx_add_timer(ev, mgr->scan_interval_ms);

    if (!xrootd_srv_hc_claim(host, sizeof(host), &port,
                              (ngx_msec_t) conf->hc_interval_ms))
    {
        return;  /* nothing due — wait for next tick */
    }

    xrootd_hc_start(mgr->cycle, conf, host, port);
}
```

`xrootd_hc_start()` resolves the target address, allocates `xrootd_hc_ctx_t`,
creates a non-blocking socket, arms the write handler, and sends the bootstrap
buffer — nearly identical to `xrootd_upstream_start()` but without the client
context references.

**Manager struct:**

```c
typedef struct {
    ngx_event_t                   timer;
    ngx_cycle_t                  *cycle;
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_msec_t                    scan_interval_ms;
} xrootd_hc_mgr_t;
```

**Start hook** (called from stream module's `init_process`):

```c
void
xrootd_hc_manager_start(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_hc_mgr_t *mgr;

    if (!conf->hc_enabled || conf->hc_interval_ms == 0) return;

    mgr = ngx_pcalloc(cycle->pool, sizeof(*mgr));
    mgr->cycle = cycle;
    mgr->conf  = conf;
    /* Spread checks evenly: fire every interval/128 ms (min 100ms) */
    mgr->scan_interval_ms = ngx_max(100,
        conf->hc_interval_ms / XROOTD_SRV_REGISTRY_SLOTS);

    mgr->timer.handler = xrootd_hc_timer_handler;
    mgr->timer.data    = mgr;
    mgr->timer.log     = cycle->log;

    ngx_add_timer(&mgr->timer, 2000);  /* initial delay: let CMS connections settle */

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: health check manager started (interval=%Ms scan=%Ms)",
                  conf->hc_interval_ms, mgr->scan_interval_ms);
}
```

---

## Step D — New Config Directives

**File:** `src/core/config/directives.c` (register), `src/protocols/root/stream/module.c` (merge)

| Directive | Default | Notes |
|---|---|---|
| `xrootd_health_check on\|off` | `off` | Enable/disable (off = behaves as today) |
| `xrootd_health_check_interval 30s` | 30s | Per-server probe interval |
| `xrootd_health_check_timeout 5s` | 5s | Per-probe response timeout |
| `xrootd_health_check_threshold 3` | 3 | Consecutive failures before blacklist |
| `xrootd_health_check_blacklist 60s` | 60s | Blacklist duration on failure |
| `xrootd_health_check_type ping\|stat` | `ping` | kXR_ping or kXR_stat "/" probe |

Fields added to `ngx_stream_xrootd_srv_conf_t`:

```c
    ngx_uint_t  hc_enabled;
    ngx_msec_t  hc_interval_ms;
    ngx_msec_t  hc_timeout_ms;
    ngx_uint_t  hc_threshold;
    ngx_msec_t  hc_blacklist_ms;
    ngx_uint_t  hc_type;    /* XROOTD_HC_TYPE_PING or XROOTD_HC_TYPE_STAT */
```

`merge_srv_conf()` defaults:
- `hc_enabled = 0` (off by default — non-breaking)
- `hc_interval_ms = 30000`
- `hc_timeout_ms = 5000`
- `hc_threshold = 3`
- `hc_blacklist_ms = 60000`

---

## Step E — Metrics

**File:** `src/observability/metrics/cluster.c` (extend existing)

Four new counters in the cluster metrics group:

```c
/* In metrics/metrics.h — cluster group extension */
uint64_t   hc_pass_total;        /* successful probes */
uint64_t   hc_fail_total;        /* failed probes */
uint64_t   hc_blacklist_total;   /* times a server was blacklisted via HC */
uint64_t   hc_probe_active;      /* current in-flight probes (gauge) */
```

Prometheus exposition:

```
xrootd_cluster_hc_pass_total              N
xrootd_cluster_hc_fail_total              N
xrootd_cluster_hc_blacklist_total         N
xrootd_cluster_hc_probe_active            N
```

Additionally, expose per-server health state via the existing dashboard snapshot API
(adds `hc_last_ok` and `hc_fail_count` to `xrootd_srv_snapshot_entry_t` — Step A).

---

## Step F — TLS Support for Health Probes

> **Status: ✅ IMPLEMENTED 2026-07-21** — via a shared *function* seam instead of the
> wrapper-struct below: `brix_outbound_start_tls(ssl_ctx, conn, sni, handler)` was
> extracted from `src/net/upstream/tls.c` (declared in `upstream_internal.h`);
> `brix_upstream_start_tls()` wraps it and `health_check.c` calls it directly with
> its own handshake-done callback (`brix_hc_tls_handshake_done`), which verifies the
> peer, restores the probe handlers, and re-sends a fresh login over TLS — then the
> probe continues LOGIN → PROBE at full depth. Gated on the manager block's
> `brix_upstream_tls on` + `brix_upstream_tls_ca`; without a ctx the pre-Step-F
> shallow protocol-OK-alive behavior is preserved. Two wire preconditions (found
> the hard way, see "Pending / not done" above): the probe must advertise
> `kXR_ableTLS` or a brix server never answers `kXR_gotoTLS`, and it must NOT
> pipeline the plaintext login (the server feeds pending cleartext bytes to the
> TLS handshake). Tests: `test_phase22_health_check.py` §4 + template
> `tests/configs/nginx_hc_tls_cluster.conf`. The original design sketch below is
> kept for the record.

If `xrootd_upstream_tls on` is configured, data servers advertise `kXR_gotoTLS` in
the protocol response. The health check bootstrap must handle TLS upgrade the same way
`src/net/upstream/tls.c` does.

**Approach:** Share `xrootd_upstream_start_tls()` by refactoring its signature to accept
a generic conn+log pair rather than a `xrootd_upstream_t *`. A thin wrapper type can
provide both:

```c
typedef struct {
    ngx_connection_t             *conn;
    ngx_log_t                    *log;
    ngx_stream_xrootd_srv_conf_t *conf;
} xrootd_tls_upgrade_ctx_t;
```

Both `xrootd_upstream_t` and `xrootd_hc_ctx_t` embed this as `tls_ctx` or expose
compatible fields. The TLS callback for health checks calls `xrootd_hc_send_probe()`
instead of `xrootd_upstream_send_request()`.

This keeps TLS upgrade code in one place and prevents divergence between upstream
proxy and health check TLS behaviour.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/net/manager/registry.h` | Modify | Add HC fields to entry; declare `hc_claim/pass/fail` |
| `src/net/manager/registry.c` | Modify | Implement `xrootd_srv_hc_claim`, `hc_pass`, `hc_fail` |
| `src/net/manager/health_check.h` | **New** | `xrootd_hc_ctx_t`, `xrootd_hc_mgr_t`, public API |
| `src/net/manager/health_check.c` | **New** | Timer, state machine, connect/send/recv/finish |
| `src/net/upstream/tls.c` | Modify | Refactor TLS upgrade to `xrootd_tls_upgrade_ctx_t` for sharing |
| `src/net/upstream/upstream_internal.h` | Modify | Use `xrootd_tls_upgrade_ctx_t` alias |
| `src/core/config/directives.c` | Modify | Register 6 new `xrootd_health_check*` directives |
| `src/core/types/config.h` | Modify | Add HC fields to `ngx_stream_xrootd_srv_conf_t` |
| `src/protocols/root/stream/module.c` | Modify | Call `xrootd_hc_manager_start()` in `init_process` hook |
| `src/observability/metrics/cluster.c` | Modify | Add 4 HC counters; wire `XROOTD_HC_METRIC_INC` macro |
| `src/observability/metrics/metrics.h` | Modify | Declare new HC counter fields |
| `src/core/config/config.h` | Modify | Add `health_check.c` to `NGX_ADDON_SRCS` |

---

## Build Registration

Add `$ngx_addon_dir/src/net/manager/health_check.c` to `NGX_ADDON_SRCS` in
`src/core/config/config.h` before running `./configure`. All other changes are in existing
files; incremental `make -j$(nproc)` suffices after the initial `./configure`.

---

## Testing Requirements

3 tests per area (success + error + security-neg per CLAUDE.md):

### Step A + B (probe machinery)
- `test_a_robustness.py::TestHealthCheck::test_ping_probe_passes_live_server` — HC marks live server as healthy after kXR_ping `kXR_ok`
- `test_a_robustness.py::TestHealthCheck::test_probe_fails_on_port_closed` — HC marks server failed when TCP refused
- `test_a_robustness.py::TestHealthCheck::test_probe_timeout_triggers_blacklist` — HC fires timeout, after `threshold` failures server enters blacklist

### Step C (timer / worker coordination)
- `test_a_robustness.py::TestHealthCheck::test_only_one_worker_probes_per_slot` — under 4-worker config, server receives exactly 1 probe per interval (not 4)
- `test_a_robustness.py::TestHealthCheck::test_staggered_probes_spread_evenly` — scan timer distributes probes across interval window
- `test_a_robustness.py::TestHealthCheck::test_disabled_by_default` — without `xrootd_health_check on`, no probe connections opened

### Step D (directives)
- `test_conformance.py::TestHealthCheckConfig::test_threshold_respected` — blacklist only after N consecutive failures (not on first)
- `test_conformance.py::TestHealthCheckConfig::test_blacklist_clears_on_recovery` — after recovery server is re-selected for client locate
- `test_conformance.py::TestHealthCheckConfig::test_stat_type_probe` — `hc_type stat` sends kXR_stat and accepts `kXR_ok`

---

## Interaction with Existing Mechanisms

| Existing mechanism | Interaction |
|---|---|
| CMS `server_recv.c` → `xrootd_srv_blacklist(30s)` on disconnect | Unchanged; HC does not interfere. CMS disconnect blacklist is independent of HC fail_count. `xrootd_srv_hc_pass()` does not clear a CMS-triggered blacklist (detected by checking that blacklist was set *by HC* via a new `blacklist_source` flag, or simply by not clearing CMS blacklists at all — HC pass only clears when `hc_fail_count > 0`). |
| `xrootd_upstream_start()` per-request locate queries | Unchanged. If HC has already blacklisted a server, `xrootd_srv_select()` skips it — the upstream query is never attempted. |
| CMS `xrootd_cms_srv_send_ping()` liveness probe | Complements HC — CMS ping detects disconnected sockets; HC detects hung-but-connected processes. Both feed into `blacklisted_until` via the same registry spinlock. |
| Dashboard API (`src/observability/dashboard/api.c`) | `hc_last_ok` and `hc_fail_count` are included in the server snapshot used by the dashboard endpoint, providing operator visibility into health check state per node. |

---

## Risk Notes

- **Bootstrap duplication:** The HC bootstrap state machine is near-identical to
  `src/net/upstream/bootstrap.c`. Consider extracting `xrootd_do_bootstrap(conn, conf, done_cb)`
  as a shared function in `src/net/upstream/` to prevent the two implementations from
  drifting. This is not required for Phase 22 but should be done if the bootstrap
  protocol changes in the future.
- **Connection exhaustion:** With 128 registry slots and 4 workers, worst-case
  128 concurrent probe connections per worker during startup bursts. The `hc_in_progress`
  flag and `scan_interval_ms` staggering prevent this — at most 1 probe per
  `scan_interval` fires.
- **Metric label cardinality:** Do NOT label HC metrics with host/port — that
  violates INVARIANT 8 (low-cardinality labels only). Use the dashboard snapshot
  API for per-server state; the Prometheus counters are aggregates only.
- **`hc_fail_count` races:** Two workers could simultaneously decrement past 0 in
  `xrootd_srv_hc_pass()`. Guard with spinlock (same pattern as `error_count`
  in `xrootd_srv_blacklist()`). The existing `ngx_shmtx_t` spinlock already
  serializes all registry mutations.
