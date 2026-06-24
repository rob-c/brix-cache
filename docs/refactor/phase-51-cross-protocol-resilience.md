# Phase 51 — Cross-protocol connectivity resilience (complete the hardening, deepen CMS)

**Status:** IMPLEMENTED 2026-06-23 — all workstreams (A1–A4, B1–B3, C1, E1–E6)
landed, build-clean (`-Werror`, zero warnings), regression-green. Only the
dedicated new test files (D) remain optional (existing suites cover the changes).
**Scope:** all protocols — `root://` stream, `cms://`, WebDAV/S3 HTTP, proxy,
native TPC, cluster/manager — and the shared auth stacks (GSI/x509 + OCSP/CRL/VOMS,
token/JWT/macaroon, SSS, krb5, S3 SigV4, XrdAcc), with `cms://` and auth-under-
pressure as the deepening focuses.
**Hard requirement:** **zero wire change**, byte-for-byte interop with official
XRootD `cmsd` and clients.

### Implementation status

| WS | Item | Status |
|----|------|--------|
| B1 | proxy upstream write-stall default ON (~60s) | ✅ DONE (`server_conf.c`) |
| B2 | native-TPC absolute cap 24h + curl low-speed 1KB/s·60s default ON | ✅ DONE (`server_conf.c`, `webdav/tpc_config.c`) |
| E1 | OCSP fetch socket timeout (connect/handshake/read, ~5s) | ✅ DONE (`crypto/ocsp.c`); per-request status cache + circuit-breaker → TODO |
| E2 | auth-gate per-worker L1 cache (lockless, in front of SHM L2) | ✅ DONE (`path/auth_gate_l1.{c,h}`, `auth_gate.c`) |
| A2 | bounded CMS frames-per-wakeup (anti-flood fairness) | ✅ DONE (`cms/recv.c`, `cms/server_recv.c`) |
| C1 | fsync-before-rename (data + dir) in staged commit; fail-closed | ✅ DONE (`compat/staged_file.c` — covers WebDAV PUT + S3) |
| E5 | CRL reload mtime-skip (regular-file CRL) | ✅ DONE (`config/process.c`) |
| A1 | CMS observability metrics (read/login/idle/cap/yield counters) | ✅ DONE (`metrics.h`, `stream.c`, CMS call sites) |
| A3 | CMS per-source-IP connection cap | ✅ DONE (`cms/server_handler.c`, `server_module.c`) |
| A4 | pending-locate active reaper (worker-0 timer) | ✅ DONE (`manager/pending.c`, `config/process.c`) |
| E3 | XrdAcc NSS / reverse-DNS negative-cache + circuit-breaker | ✅ DONE (`acc/groups.c`, `acc/resolve.c`) |
| E4 | cold-auth concurrency limiter: in-flight GSI-handshake cap, sheds `kXR_wait` | ✅ DONE (`gsi/auth.c`, leak-proof release in `connection/disconnect.c`) |
| E6 / B3 | auth + resilience metrics on `/metrics` | ✅ DONE (`xrootd_export_resilience_metrics`) |
| D | dedicated `test_http_resilience.py` / `test_auth_resilience.py` | ⏳ OPTIONAL (existing suites cover the changes; smoke test added) |

Validated batch: `test_webdav_auth_cache` (E2), `test_webdav_spooled_put` + `test_s3`
(C1), `test_cms_resilience` (A2), `test_gsi_concurrency`, `test_token_cache_l1` — all
green on the rebuilt binary.

---

## 1. Context & motivation

The objective: keep every protocol serving under high load and poor network
conditions, with `cms://` in particular extremely hardened against timeouts,
packet loss, slow/half-open peers, floods, and hostile actors.

A full audit (2026-06-23) found the **foundation is already implemented** — this
phase does **not** redo it; it closes the residual gaps and adds the
observability/anti-abuse depth that "extremely hardened" implies.

### 1.1 Already implemented (the foundation — do not redo)

| Area | State | Evidence |
|---|---|---|
| `root://` stream deadlines (phase-39) | **FULL** | `src/connection/deadline.h` armed/disarmed at PDU boundaries in `recv.c`/`send.c`; pre-auth handshake deadline; response-drain write deadline; metrics `handshake_timeouts_total`/`read_pdu_timeouts_total`/`send_drain_timeouts_total` |
| TCP dead-peer reaping | **FULL** | `src/connection/netopt.h` `xrootd_apply_tcp_deadpeer_opts()` at root:// accept (`handler.c`) + CMS sockets |
| Stream admission cap | **FULL** | pre-identity `xrootd_max_connections` in `handler.c` (atomic `connections_active`, `connections_rejected_total`) |
| `cms://` hardening (phase-50) | **FULL** | client read-liveness + send-stall deadlines, server login + idle deadlines, per-worker conn cap, redirect-host validation, log-flood fix; 72 CMS tests green |
| HTTP token auth | **FULL** | always-on per-worker L1 validation cache `src/token/worker_cache.c` |
| Proxy upstream | bounded | connect 10s, read 60s, reconnect budget + teardown guard (`events_read.c` `if (ctx->proxy != proxy) return;`) |
| Native TPC | thread-pooled | `curl` on thread pool, 30s connect timeout, registry reaper + cancel-on-disconnect |
| Health check | bounded | 5s probe deadline + 10s blacklist |
| GSI DH keygen | **FULL** | thread-pool keypool warms 64 ffdhe2048 keys off-loop (`src/gsi/keypool.c`); pop is O(1), inline keygen only on pool-empty (phase-33 wedge fixed) |
| S3 SigV4 signing key | **FULL** | per-worker one-slot date+region cache (`src/s3/auth_sigv4_verify.c`) → ~99% hit, 4-round HMAC only on date roll |
| SSS / krb5 keytab | bounded | keytabs loaded once at startup, in-memory; SSS Blowfish+CRC32 is µs-scale CPU only |
| XrdAcc group lookups | partial | per-worker 256-slot username cache (12h TTL) in `src/acc/groups.c` — but a cold/diverse miss blocks on NSS/NIS/LDAP |
| GSI auth-result cache | partial | DN+VO-keyed SHM verdict cache (`src/path/auth_gate.c`) skips full chain re-verify for repeat clients — but SHM-spinlock only, **no per-worker L1** |

> The `phase39_network_resilience_plan` memory note says "PLAN ONLY" — that note is
> **stale**; the audit confirmed phase-39 WS1–WS9 are all implemented in code.

### 1.2 Residual gaps (what this phase fixes)

1. **Two data-plane timeouts default to UNLIMITED (high-load risk).**
   `proxy_write_timeout = 0` → a slow/backpressured upstream stalls the client
   connection indefinitely (`src/config/server_conf.c:588`). Native-TPC
   `tpc_max_transfer_secs = 0` + low-speed knobs off → a stalled remote pins a
   thread-pool worker forever (thread-pool exhaustion = HTTP unresponsiveness
   under load).
2. **CMS has no observability** for its new timeouts/closes/cap-rejections — the
   hardening (and attacks against it) are invisible under load.
3. **No fairness bound on CMS work-per-wakeup** — a single connection flooding
   frames can monopolize the worker event loop (only TCP backpressure + the idle
   watchdog bound it today).
4. **CMS cap is global-per-worker only** — one source IP can consume every slot.
5. **Pending-locate slots are lazily reaped** — abandoned manager-side locate
   entries linger until the next insert if traffic ceases (`src/manager/pending.c`).
6. **No fault-injection resilience tests for the HTTP family** (WebDAV, S3,
   HTTP-TPC, HTTP-proxy) — `tests/c/fault_proxy.c` covers only root:///cms.
7. *(durability)* WebDAV/S3 staged-commit does not `fsync` before `rename` — a
   crash / ENOSPC mid-write can publish a torn object.

### 1.2a Auth-stack gaps under load / system pressure (the auth focus)

The auth stacks share the single-threaded event loop with everything else, so any
inline blocking I/O or unbounded CPU there freezes *all* protocols at once. The
caches above blunt the common (repeat-client) case; these are the remaining
hot-path hazards when a backend is slow/down or under CPU/memory pressure:

8. **OCSP per-request fetch has NO timeout (highest event-loop-freeze risk).**
   When `xrootd_ocsp on`, `do_ocsp_request()` (`src/crypto/ocsp.c:190`,
   `BIO_do_connect`/`BIO_do_handshake`/`OCSP_sendreq_bio`) is a synchronous
   network call with no socket timeout — a slow/down responder blocks the whole
   worker for the kernel TCP timeout (~60–120 s). There is no per-request OCSP
   response cache (only the stapling cache, a different path). Default is
   `ocsp off` + `ocsp_soft_fail on`, so stock deployments are unaffected, but any
   site enabling OCSP is exposed.
9. **No per-worker L1 on the auth-result (auth-gate) cache.** Every GSI/authz
   decision takes the SHM spinlock (`xrootd_kv_get/_set` in `src/shm/kv.c`) —
   cross-worker contention under load. The token cache got an L1 this session; the
   auth-gate cache did not (`src/path/auth_gate.c`).
10. **XrdAcc NSS / reverse-DNS lookups block on miss.** `getpwnam`/`getgrouplist`
    (`src/acc/groups.c`) and `getnameinfo` (`src/acc/resolve.c`) block the event
    loop when the directory service (NIS/LDAP) or DNS is slow and the per-worker
    cache misses — a classic "system pressure" cascade.
11. **No bound on cold-auth concurrency.** Cache-*miss* crypto — `X509_verify_cert`
    (`src/crypto/gsi_verify.c:75`) and RSA/EC token verify (`src/token/validate.c`)
    — runs inline; a burst of *distinct* (uncached) clients serializes on the loop
    with no admission limit, so CPU saturation becomes a worker-wide stall.
12. **krb5 `krb5_rd_req()` may touch the KDC** (`src/krb5/auth.c:255`) inline
    (compile-gated) — blocks under a slow/unreachable KDC.
13. **CRL reload runs on the event thread** (`src/crypto/pki_load.c` via the
    `crl_timer`) without an mtime-skip — a large CRL on slow storage stalls the
    loop, even if briefly and infrequently.
14. **No auth-pressure observability** — no metrics for per-method cache hit/miss,
    OCSP/NSS latency or timeouts, cold-verify counts, or backend circuit trips.

### 1.3 Decision (confirmed)

The two unlimited data-plane timeouts get **generous-bounded defaults ON** — stall
detectors enabled plus a *large* total cap, with `0` retained as the explicit
"unlimited" escape. Stall detectors measure lack of progress, not duration, so a
conformant slow-but-progressing transfer is never clipped.

---

## 2. Hard constraints

- **Zero wire change**; interop with official `cmsd`/clients. New deadlines are
  generous multiples of the relevant interval so a conformant peer is never
  tripped.
- Repo rules: **no `goto`**, functional/modular helpers, reuse existing helpers,
  3 tests per change (success + error + security-negative). Low-cardinality metric
  labels only (no paths/hosts/UUIDs).

---

## 3. Reusable building blocks

- Metrics: `ngx_atomic_t` counters in `src/metrics/metrics.h` + export in
  `src/metrics/stream.c` + `XROOTD_*_METRIC_INC` at the call site (the
  `*_timeouts_total` family is the template).
- `xrootd_apply_tcp_deadpeer_opts()` (`netopt.h`), CMS deadlines (`src/cms/*`),
  `xrootd_net_host_chars_valid()` / `xrootd_sanitize_log_string()`.
- TPC stall plumbing present: `tpc_curl_apply_stall_bounds()`
  (`src/webdav/tpc_curl.c`), `tpc_max_transfer_secs`, `tpc_low_speed_bytes/secs`,
  registry reaper (`src/tpc/common/registry.c`).
- `proxy_write_timeout` arming present (`src/proxy/events_write.c`) — only the
  default changes.
- Config pattern: `NGX_CONF_UNSET*` → `ngx_conf_merge_*` → `ngx_command_t`.
- Fault-injection: `tests/c/fault_proxy.c`; dedicated-instance pattern in
  `tests/resilience/`.

---

## 4. Workstreams

### A — CMS deepening (the "in particular" focus)

- **A1. CMS observability metrics.** Low-cardinality counters exported on
  `/metrics`: client `cms_read_timeouts_total`, `cms_reconnects_total`; server
  `cms_login_timeouts_total`, `cms_idle_closes_total`, `cms_cap_rejections_total`,
  `cms_redirect_host_rejections_total`, `cms_oversized_frame_drops_total`.
  Increment at the existing phase-50 sites. Reuse the `*_timeouts_total` pattern.
- **A2. Bounded CMS work-per-wakeup (anti-flood fairness).** Cap complete frames
  processed per read event (e.g. 64) in `src/cms/recv.c` and `server_recv.c`; if
  more remain, re-post the read event so the worker services other connections
  first. Stops a single flooding peer monopolizing the event loop. Wire-invariant.
- **A3. Per-source-IP CMS connection cap (server).** Complement the global
  per-worker cap (phase-50 WS4) with a small per-source-IP counter (default
  generous, `0`=off) checked in `xrootd_cms_srv_handler`; decrement in
  `xrootd_cms_srv_close` (gate with a `counted`-style flag).
- **A4. Pending-locate active reaper (manager).** Low-frequency worker-0-gated,
  deadline-rearmed timer (health-check pattern) GCs expired `pending.c` slots so
  abandoned locates are reclaimed even when traffic ceases; keep opportunistic
  reap as the fast path.

### B — Cross-protocol data-plane defaults

- **B1. proxy write-stall ON by default.** `proxy_write_timeout` merge default
  `0` → ~60s in `src/config/server_conf.c`; `0` still disables. Arming exists.
- **B2. Native-TPC stall bounds ON by default.** Default low-speed detector
  (~1KB/s over ~60s) + large absolute `tpc_max_transfer_secs` (~24h); `0` =
  unlimited. Applied via `tpc_curl_apply_stall_bounds()`.
- **B3. HTTP overload visibility.** HTTP already has per-principal
  `xrootd_concurrency_limit` (→503) and TPC-registry-full→503; add a 503-shed
  metric counter and document recommended `client_header_timeout`/
  `client_body_timeout`/`send_timeout`/`keepalive_timeout` in
  `contrib/xrootd.conf.example`. No new global HTTP cap unless review finds a gap.

### C — Durability under poor conditions

- **C1. fsync-before-rename** in the WebDAV/S3 staged-commit path so a crash /
  ENOSPC mid-write cannot publish a torn object.

### D — Resilience tests for the HTTP family

- **D1.** New `fault_proxy`-based tests (dedicated high ports): WebDAV + S3
  GET/PUT through lossy/drip/latency (integrity + bounded failure, no hang);
  HTTP-TPC pull from a stalled source (bounded by B2); proxy-mode root:// through
  a backpressured upstream (bounded by B1). Plus a CMS frame-flood test (A2 — the
  worker stays responsive) and `/metrics` assertions for A1. Existing
  root:///cms/webdav/s3 interop suites must stay green.

### E — Auth-stack resilience under load & system pressure (cross-protocol)

**Guiding principle:** the auth stacks (GSI/x509+OCSP+CRL+VOMS, token/JWT/macaroon,
SSS, krb5, S3 SigV4, XrdAcc) all run on the shared single-threaded event loop, so a
slow/down auth backend or a CPU/memory spike there freezes *every* protocol at once.
The rule for every auth dependency is therefore: **(1) bound it with a timeout,
(2) cache it (per-worker lockless L1 in front of any SHM L2), (3) circuit-break a
degraded backend to its configured fail policy** for a cooldown window rather than
re-blocking each request, and **(4) keep the cold (cache-miss) crypto path
concurrency-bounded** so CPU saturation sheds gracefully instead of stalling. The
GSI DH keypool (`src/gsi/keypool.c`) is the model for moving cost off the loop.

- **E1. OCSP: timeout + per-request cache + circuit-breaker (highest priority).**
  Add connect/read/write socket timeouts to `do_ocsp_request()`
  (`src/crypto/ocsp.c`) — generous default (~3–5 s), so a dead responder can never
  hold the worker for the kernel TCP timeout. Add a per-worker OCSP-status cache
  keyed by issuer+serial (GOOD/REVOKED honouring `nextUpdate`), so a re-presented
  cert never re-fetches. Add a circuit-breaker: after N consecutive responder
  timeouts, short-circuit to the `ocsp_soft_fail` policy for a cooldown window
  instead of re-blocking every handshake. Optionally offload the cold fetch to the
  thread pool. Document `ocsp_soft_fail` (default on = fail-open) prominently.

- **E2. Per-worker L1 in front of the auth-result (auth-gate) cache.** Mirror
  `src/token/worker_cache.c`: a lockless per-worker direct-mapped L1 keyed by the
  existing 32-byte auth-cache SHA-256 key, in front of the SHM L2
  (`src/path/auth_gate.c`). An L1 hit skips both the SHM spinlock and the full
  authdb/VO-ACL/scope/chain decision; bounded by the same TTL; promote L2 hits into
  L1. Removes the cross-worker contention point that GSI-heavy load hits hardest.

- **E3. Bound the blocking NSS / reverse-DNS lookups (XrdAcc).** Wrap
  `getpwnam`/`getgrouplist` (`src/acc/groups.c`) and `getnameinfo`
  (`src/acc/resolve.c`) with a **negative cache + circuit-breaker**: cache misses
  and timeouts so a degraded NIS/LDAP/DNS service trips to a bounded fail decision
  for a cooldown rather than re-blocking the loop on every cold/diverse user; keep
  the existing 12 h positive cache. *(Stretch: thread-pool offload of the cold
  lookup with a bounded wait, following the keypool pattern.)* Document
  `acc_gidlifetime` / `xrootd_acc_resolve_hosts` tuning.

- **E4. Bound cold-auth concurrency (overload shedding under CPU pressure).** Add a
  per-worker limiter on simultaneous in-flight **cache-miss** auth verifications
  (`X509_verify_cert`, RSA/EC token verify). Over the limit, shed with the existing
  backpressure — stream `kXR_wait`, HTTP `503` — reusing the phase-25 / W7
  concurrency-limit machinery. Cached (repeat) clients are never throttled; only
  the cold crypto that would otherwise bury the loop is. Generous default; `0`=off.

- **E5. CRL refresh hardening (low).** Add an mtime-skip to the CRL reload
  (`src/crypto/pki_load.c`, like JWKS `refresh.c`) and parse large CRLs on the
  thread pool, so a big/slow CRL on remote storage never stalls the loop.

- **E6. Auth-pressure observability.** Counters per auth method: cache hit/miss
  (token L1 already; add auth-gate L1 + OCSP cache), OCSP fetch latency / timeout /
  circuit-open, NSS lookup timeout / circuit-open, cold-verify count + shed count,
  krb5 KDC latency. Exported on `/metrics` so operators see auth pressure and the
  breakers tripping. Reuse the `XROOTD_*_METRIC_INC` pattern.

> **Interop note:** all of E is internal performance/resilience plumbing — no wire
> change, and the *semantics* of every fail policy (`ocsp_soft_fail`, VOMS
> fail-open-if-missing, fail-closed-on-parse-error) are preserved exactly. A
> conformant client/CA is never rejected; only the *timing* of how a degraded
> backend is handled changes (fast-fail to the same verdict instead of blocking).

---

## 5. Default posture summary

| Knob | Old default | New default | Escape |
|---|---|---|---|
| `proxy_write_timeout` | 0 (off) | ~60s | `0` = unlimited |
| `tpc_low_speed_bytes`/`_secs` | 0/0 (off) | ~1KB/s over ~60s | `0` = off |
| `tpc_max_transfer_secs` | 0 (unlimited) | ~24h | `0` = unlimited |
| CMS per-IP cap (A3) | — | generous (on) | `0` = off |
| A1 metrics / A2 fairness | — | always on (no wire/behavior change) | — |
| OCSP fetch timeout (E1) | none (∞) | ~3–5 s + circuit-breaker | only when `ocsp on` |
| OCSP per-request cache (E1) | — | on (when `ocsp on`) | — |
| Auth-gate L1 cache (E2) | — | always on | — |
| NSS/DNS negative-cache + breaker (E3) | none | on | tunable TTL |
| Cold-auth concurrency limit (E4) | — | generous (on) | `0` = off |
| E6 auth metrics | — | always on | — |

---

## 6. Files to modify (representative)

- CMS: `src/cms/recv.c`, `server_recv.c`, `server_handler.c`, `connect.c`,
  `server.h`, `server_module.c` (A1 INCs, A2 work-cap, A3 per-IP cap).
- Manager: `src/manager/pending.c`/`.h` (A4 reaper).
- Metrics: `src/metrics/metrics.h` + `src/metrics/stream.c` (A1 counters/export).
- Defaults: `src/config/server_conf.c` (B1, B2).
- TPC/durability: `src/webdav/tpc_curl.c` (confirm B2), WebDAV/S3 staged-commit
  site (C1 fsync).
- Docs/config: `contrib/xrootd.conf.example` (B3), `docs/04-protocols/cms-protocol.md`
  (metrics table).
- Tests: `tests/test_http_resilience.py` (new), extend `tests/test_cms_resilience.py`.
- Auth (Part E): `src/crypto/ocsp.c` (E1 timeout + cache + breaker),
  `src/path/auth_gate.c` + a new `src/path/auth_gate_l1.{c,h}` mirroring
  `src/token/worker_cache.c` (E2), `src/acc/groups.c` + `src/acc/resolve.c` (E3
  negative cache + breaker), the GSI/token cold-verify call sites
  `src/gsi/auth.c` / `src/token/validate.c` + the W7 concurrency limiter (E4),
  `src/crypto/pki_load.c` (E5), `src/metrics/metrics.h` + `src/metrics/stream.c` +
  `src/metrics/http.c` (E6). New auth directives via the usual
  `NGX_CONF_UNSET`→merge→`ngx_command_t` pattern (`src/config/server_conf.c`,
  `src/stream/module.c`, `src/webdav/module.c`).
- Auth tests: `tests/test_auth_resilience.py` (new) — OCSP responder that
  black-holes (handshake fails fast within the timeout, not after 60 s; soft-fail
  allows, hard-fail denies, both bounded); a slow-NSS shim (LD_PRELOAD) proving the
  circuit-breaker sheds instead of stalling; auth-gate L1 hit/miss correctness;
  cold-auth burst sheds with `kXR_wait`/503 while cached clients stay fast.
- Any new `.c` → register in `config` `NGX_ADDON_SRCS` and run `./configure` once.

---

## 7. Verification

```bash
# Build (configure once if a new .c is added; lz4 env-hint required):
XROOTD_LZ4_CFLAGS=-I$HOME/miniconda3/include XROOTD_LZ4_LIBS=-l:liblz4.so.1 \
  ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf

PYTHONPATH=tests pytest tests/test_http_resilience.py tests/test_cms_resilience.py \
                       tests/test_auth_resilience.py -v
PYTHONPATH=tests pytest tests/ -k "cms or manager or cluster or netfault or resilience" -v
# Auth interop guardrail (conformant CAs/tokens/clients still authenticate):
PYTHONPATH=tests pytest tests/ -k "gsi or token or ocsp or voms or sss or krb5 or acc or s3" -q
curl http://127.0.0.1:9100/metrics | grep -E 'cms_|shed|auth_|ocsp_'  # observe under load
```

Manual:
- TPC pull from a `fault_proxy` source that goes silent → transfer aborts within
  the low-speed window, thread-pool worker released; flood a CMS connection →
  worker keeps serving other clients and `cms_*` counters advance.
- Point `xrootd_ocsp on` at a black-holed responder and drive concurrent GSI
  handshakes → the worker must keep serving (handshakes fast-fail to the soft/hard
  policy within the OCSP timeout, the breaker opens, `ocsp_*` counters advance);
  it must NOT freeze for the kernel TCP timeout.
