# Phase 39 — Network-Fault Resilience (packet loss, slow/badly-behaved peers, stalls, drops)

**Status:** ✅ All 9 workstreams implemented + build-clean (2026-06-15). All new directives default OFF
(perf-neutral by construction; a default config parses unchanged); the stream timer suite is **test-verified
(`tests/test_netfault_stream.py` 5/5)** and the WebDAV staged PUT is **roundtrip-verified (byte-exact create
201 / overwrite 204 / empty / no temp leak)**; no regression; nothing committed.
DONE: Phase 0 (foundation); Phase 1/WS1-3 (stream read/handshake/send deadlines + TCP_USER_TIMEOUT/
keepalive); Phase 2/WS4 (TPC curl connect/low-speed + native wall-clock deadline) + WS5 (TPC registry
abandoned-slot reaper — unique id as the generation, inline-on-full self-heal); Phase 3/WS6 (PXY-3 wbuf
leak, PXY-6 splice, PXY-2 write timeout); Phase 4/WS7 (cluster `last_seen` staleness in srv_select,
prefer-fresh-with-all-stale-fallback); Phase 5/WS8 (WebDAV staged-commit PUT via the shared
xrootd_staged_open/commit/abort; S3 incomplete-MPU reaper, bounded per-directory, on InitiateMultipart;
HTTP planes already inherit nginx core client/send timeouts); Phase 6/WS9 (max_connections cap + rl_rules
merge inheritance).
FOLLOW-UPS (non-blocking, lower value): WS5 curl-cancel-on-disconnect; WS7 CMS read-timer/backoff/jitter;
WS8/HTTP-5 MPU-complete thread-pool offload + fsync-before-rename; and the **Phase-9** ASAN/LSan proxy-leak
proof (PXY-3, needs a proxy+upstream pair) + full-fleet regression.
**Author:** multi-agent source audit (8 parallel readers + architect synthesis + adversarial critique), 2026-06-15
**Scope:** make nginx-xrootd highly resilient to packet loss, slow/badly-behaved clients, badly-behaved
network equipment, mid-transfer stalls, and dropped/half-open connections — **going further than official
XRootD**, which is widely criticized for its behaviour under packet loss — *without regressing the
data-plane hot paths* (read pipelining, sendfile, kTLS, CRC offload, memory-budget windowing). Includes a
two-tier test design that verifies correct behaviour under up to 20% packet loss across all protocols plus
hundreds of concurrent metadata queries.
**Reference implementation studied:** official XRootD under `/tmp/xrootd-src` (`src/Xrd/XrdLink*`,
`src/XrdSys/XrdSysIOEvents*`, `src/XrdCl/*`, `src/XProtocol/*`).

> **Hard rule for every workstream below:** all new behaviour is gated behind a new directive defaulted to
> **OFF** (`NGX_CONF_UNSET_MSEC` → `NGX_CONF_NO_TIMER`, or `0`). Existing deployments and benchmarks are
> **byte-for-byte unchanged** until an operator opts in. Fixes live on the error/slow paths, never in the
> inner byte loop, the Phase-29 pipelining keep-reading conjuncts, or the sendfile/kTLS zero-copy chain.

---

## 1. The physics — what "packet loss" actually means at this layer

root://, roots://, WebDAV/davs://, S3 and /metrics are **all TCP**. The kernel TCP stack transparently
retransmits lost packets and reassembles reordered ones, so the application **never literally sees** an
out-of-order or lost packet. What 20% loss / bad middleboxes / badly-behaved clients do to the
*application* is:

- **Partial reads** — a request PDU's header or body arrives split across many `recv()` calls.
- **Short writes / `EAGAIN`** — the socket won't accept a full response in one `send()`.
- **Stalls** — long quiet gaps mid-operation (slow client, lossy link, stuck middlebox). *This is where
  XRootD is most criticized.*
- **Resets / half-open** — connection dies mid-read or mid-write; RST; FIN with pending data.
- **Slow-drip** — slowloris-style byte-at-a-time senders holding resources.
- **Timeouts** firing (or, the actual bug here, **never** firing when they should).

So "resilience to packet loss" for this codebase concretely means: robust partial-I/O handling, sane
per-operation deadlines, backpressure, clean cancellation of in-flight async I/O (no use-after-free when a
connection dies), idempotent recovery on reconnect, and **no resource leak / state corruption** when a peer
misbehaves.

---

## 2. Where we already beat official XRootD (build on this)

The audit confirmed nginx-xrootd is **architecturally superior** for exactly the failure mode XRootD is
criticized for:

- **Non-blocking, event-driven recv/send state machine** (`src/connection/recv.c`, `send.c`) that
  **correctly accumulates split PDUs** and **parks partial sends** in an `out_ring` — it never blocks a
  worker thread on a stalled peer.
- Official XRootD blocks in `MSG_WAITALL` recv and writes under `wrMutex`
  (`/tmp/xrootd-src/src/Xrd/XrdLink.cc`), so a handful of slow/lossy clients **exhaust its bounded worker
  pool** — the canonical "XRootD falls over under packet loss" symptom. We have structurally avoided this.
- Official XRootD disables TCP keepalive by default and uses coarse fixed timeouts; its single-TCP-stream
  design head-of-line-blocks under loss; slow consumers can hit `SendQ` silent-discard or block a worker in
  `write()`.

**Conclusion:** we are not rebuilding the I/O model. We are closing the *time* gaps on top of a sound model.

---

## 3. The dominant gap — time, not bytes

**No client-facing read/write/idle/handshake timer is ever armed on the steady-state path.** The
`rev->timedout` / `wev->timedout` branches *exist* and disconnect cleanly (`recv.c:135-140`, `send.c:42`)
but are **dead code** — nothing calls `ngx_add_timer` to target them. Consequences:

- A slowloris, a silent mid-PDU stall, or a half-open peer pins **ctx + scratch heap + open fd handles +
  charged memory budget + concurrency slot** indefinitely.
- Official only has a 3s `readWait` *reschedule* (a 1-byte-every-2.9s trickle never times out) and a
  handshake-only `hailWait`. We can do strictly better with per-PDU and per-drain deadlines.

### 3.1 Two confirmed real bugs (fix regardless of theme)

- **PXY-3 (leak):** the stream proxy never frees `proxy->wbuf` after a deferred flush completes
  (`src/net/proxy/events_write.c:106-124`), while `src/net/proxy/forward_request.c:345` reassigns it on the next
  request — **leaks up to ~128KB per request** under exactly the slow/lossy-consumer case.
- **PXY-6 (wire corruption):** the splice path sends the 8-byte response header, then on a short send falls
  back to the buffered path which **re-sends the full header** (`src/net/proxy/events_splice.c:272-279`),
  duplicating bytes on the wire and corrupting the client's frame stream.

---

## 4. Workstreams

All effort/risk and "exceeds official" flags are from the synthesis; **the correctness rules in §4.10 are
mandatory** (the critic verified the underlying UAF/double-free/corruption hazards against source).

| WS | Title | Protocols | Effort / Risk | Beats official? |
|---|---|---|---|---|
| WS1 | Per-PDU read deadline + handshake deadline (slowloris/silent-stall defense) | root:// | M / med | ✅ |
| WS2 | Response-drain (slow-consumer) write deadline | root:// | M / med | ✅ |
| WS3 | Payload-receive deadline reuse + `TCP_USER_TIMEOUT` / keepalive kernel dead-peer reaping | root:// (+HTTP accept) | S / low | ✅ |
| WS4 | TPC stall bounding: connect timeout + low-speed detect + native wall-clock deadline | WebDAV + native TPC | M / low | ✅ |
| WS5 | TPC registry reaper + curl cancel-on-client-disconnect | WebDAV + native TPC | M / med | ✅ |
| WS6 | Proxy: free wbuf (**PXY-3**) + splice header fix (**PXY-6**) + upstream write timeout | stream proxy | M / med | — (bugfix) |
| WS7 | Cluster/CMS dead-peer: `last_seen` staleness in selection + CMS read deadlines + backoff/jitter | cluster + CMS | L / med | ✅ |
| WS8 | HTTP/WebDAV/S3: client-timeout defaults + S3 MPU reaper + WebDAV staged-commit + MPU-complete offload | WebDAV + S3 | L / med | ✅ |
| WS9 | Overload shedding: pre-identity connection cap + fix rate-limit/auth-cache merge inheritance | all | S / low | — |

### 4.1 WS1 — Per-PDU read deadline + handshake deadline
**Closes:** the single highest-impact gap (no client read timer). Prevents pre-auth and mid-PDU
resource-holding DoS.
**Files:** `src/connection/recv.c`, `handler.c`, `disconnect.c`; `src/core/types/config.h`;
`src/stream/module.c` (directive registration); `src/core/config/server_conf.c` (merge).
**Changes:**
- Add `ngx_msec_t read_timeout` (steady-state per-PDU receive deadline) and `handshake_timeout`
  (pre-login deadline) to `ngx_stream_xrootd_srv_conf_t`. `NGX_CONF_UNSET_MSEC` in create;
  `ngx_conf_merge_msec_value(..., NGX_CONF_NO_TIMER)` in merge → default disabled.
- Arm `handshake_timeout` at accept in `handler.c` before the first `recv` (one arm; no hot-path cost).
- Two pure helpers `xrootd_arm_read_deadline` / `xrootd_disarm_read_deadline`. See **§4.10** for the
  mandatory arm/disarm discipline (NOT per-PDU).
- The `recv.c:135-140` `rev->timedout` disconnect branch becomes live; distinguish pre-login vs post-login
  only for the log/metric label.
- Add metrics `handshake_timeouts_total` / `read_pdu_timeouts_total` (low-cardinality).
**Perf:** negligible — off by default; timer touched only at genuine incompletion/quiescence, never in the
byte loop or pipelining conjuncts.
**Tests:** (success) normal pyXRootD read/stat completes under a small `read_timeout`, byte-exact,
connection survives many serial ops (proves disarm-on-complete). (error) `fault_proxy` slow-drip → server
closes within `read_timeout`+slack, gauges return to baseline, no fd/budget leak. (security) pre-auth
handshake stall (`test_a_robustness.py::_partial_handshake_10_bytes` then silence) → dropped within
`handshake_timeout`.

### 4.2 WS2 — Response-drain (slow-consumer) write deadline
**Closes:** parked `out_ring` slots + pinned `read_scratch`/`rd_pool` windows held forever by a frozen
reader; `send.c:42 wev->timedout` can never fire today.
**Files:** `src/connection/write_helpers.c`, `send.c`, `event_sched.c`; `config.h`; `server_conf.c`;
`module.c`.
**Changes:**
- Add `ngx_msec_t send_timeout` (UNSET → `NGX_CONF_NO_TIMER`).
- Arm `c->write` timer **only on the genuine stall** (`send_chain` returns `NGX_AGAIN` after the
  `XROOTD_SEND_CHAIN_SPIN_MAX` spin budget is exhausted — the real park). Disarm only when the **last** slot
  retires and no further `AGAIN` this drain. Use `timer_set` to make re-arm a no-op; never `del+add` on a
  slot that merely advanced (see §4.10).
- Cache the merged `send_timeout` on `ctx` at accept to avoid a srv_conf lookup on the park path.
- `send.c:42` branch becomes live; add metric `send_drain_timeouts_total`.
**Perf:** negligible — only arms when the kernel send buffer is already full (the slow-consumer error path);
zero effect on the sendfile/kTLS chain.
**Tests:** (success) fast reader drains 200MiB, byte-exact, timer cleanly disarmed, connection reusable.
(error) `fault_proxy` `block` mid-large-read → teardown within `send_timeout`, budget + slots released.
(security) half-open reader (forward up, black-hole down after header) → `wev->timedout` reaps it; a
concurrent healthy connection is unaffected (no worker-wide stall).

### 4.3 WS3 — Payload-receive deadline + kernel dead-peer reaping
**Closes:** a dripped write/auth/prepare payload tying up budget; OS-level dead-peer detection during parked
AIO/SENDING windows where the app timer intentionally yields ownership.
**Files:** `src/connection/recv.c` (payload state falls out of WS1), `handler.c` (setsockopt at accept);
`config.h`; `server_conf.c`; `module.c`.
**Changes:**
- WS1's arm helper already covers `REQ_PAYLOAD` (keyed on "any incomplete PDU").
- Add `tcp_user_timeout` (ms; UNSET → 0 = leave kernel default): at accept, `setsockopt(IPPROTO_TCP,
  TCP_USER_TIMEOUT)` guarded `#ifdef TCP_USER_TIMEOUT`.
- Add `tcp_keepalive` flag → `SO_KEEPALIVE` + tight `TCP_KEEPIDLE/INTVL/CNT` (e.g. 30/10/3) when enabled;
  default off. **setsockopt failures are non-fatal** and must not abort accept (see §4.10).
**Perf:** none — setsockopt once at accept on the control path; defaults leave the kernel untouched.
**Tests:** (success) long idle-then-active session not killed, byte-exact. (error) `fault_proxy` `drop`
(RST) mid-AIO → dead peer detected via the single disconnect funnel, no UAF, slot freed within the
keepalive window. (security) half-open black-hole during a parked SENDING window with app `send_timeout`
DISABLED but `tcp_user_timeout` enabled → kernel backstop still tears it down.

### 4.4 WS4 — TPC stall bounding
**Closes:** curl TPC has no connect/idle/low-speed bound (only optional `CURLOPT_TIMEOUT` at
`tpc_curl.c:257/516`); native TPC has only a per-recv `SO_RCVTIMEO` that resets every byte. A stalled
remote pins a finite thread-pool worker forever; enough stalls wedge all TPC.
**Files:** `src/webdav/tpc_curl.c`; `src/tpc/source.c` (native pull loop ~182+);
`src/tpc/tpc_internal.h`; `src/webdav/webdav.h`, `tpc_config.c`; `config.h` + `module.c` (native knob).
**Changes:**
- On **every** curl easy handle (single + multi paths) set `CURLOPT_CONNECTTIMEOUT` (e.g. 30s),
  `CURLOPT_LOW_SPEED_LIMIT` (new `xrootd_webdav_tpc_low_speed_bytes`, e.g. 1024) + `CURLOPT_LOW_SPEED_TIME`
  (new `xrootd_webdav_tpc_low_speed_secs`, e.g. 30) + `CURLOPT_TCP_KEEPALIVE 1`. Idle/stall abort that does
  **not** kill slow-but-progressing transfers.
- Native `source.c` loop: wall-clock deadline sampled every N frames via `ngx_cached_time` (**no syscall
  per frame**, outside the per-frame `pwrite` hot path). New `xrootd_tpc_max_transfer_secs` (default 0 = no
  cap). Keep `SO_RCVTIMEO/SO_SNDTIMEO` as the idle bound.
- TPC-8: in `tpc_marker_poll` track last-progress bytes + timestamp; if no progress for `low_speed_secs`,
  finalize the marker stream as failure so FTS/RUCIO learns promptly.
- **Corrected premise:** the "curl_multi busy-spins at 100% CPU" claim is **stale** —
  `tpc_curl.c:796` already passes a 1000ms timeout to `curl_multi_wait`. Do **not** "fix" the working multi
  loop; at most prefer `curl_multi_poll` for old-libcurl correctness.
**Perf:** negligible — pure additive setopts; native check sampled, off the per-frame path; permissive
defaults never fire on healthy transfers.
**Tests:** (success) healthy WebDAV COPY + native TPC both byte-exact with bounds enabled. (error)
`fault_proxy` in front of the TPC **source** slow-drip below floor → curl aborts within `low_speed_secs`,
worker released; native aborts within `max_transfer_secs` and unlinks the partial dst. (security) stall N =
pool-size TPCs against a black-hole source → throughput recovers after the bound; a fresh TPC succeeds.

### 4.5 WS5 — TPC registry reaper + curl cancel-on-disconnect
**Closes:** the cross-process TPC registry slot is freed only on explicit completion; abandoned transfers
accumulate as permanent `in_use` slots until `XROOTD_TPC_REGISTRY_SLOTS` fill and every new TPC 503s. The
transfer struct already carries `started_at`/`updated_at` (`src/tpc/common/transfer.h:59-60`).
**Files:** `src/tpc/common/registry.c/.h`; `src/webdav/tpc_curl.c`, `tpc_marker.c`, `tpc_thread.c`;
`config.h` + `module.c`.
**Changes:**
- `xrootd_tpc_registry_reap(max_age, log)` driven by a coarse per-worker timer (~60s). New
  `xrootd_tpc_transfer_max_age` (default 0 = disabled; recommended 3600s). **Must mark-then-reclaim with a
  generation counter — never `free()` outright** (see §4.10).
- Cancel-flag read inside the **existing** `webdav_tpc_curl_progress` (`tpc_curl.c:374-399`, currently
  always returns 0) → return `CURLE_ABORTED_BY_CALLBACK` when set. **Corrected premise:** the progress
  callback is already wired; only the cancel-read is new. Cancellation latency = curl's progress interval
  (sub-second), **not** per-write-callback granularity.
- `tpc_marker_cleanup` (client-disconnect pool cleanup) sets the cancel flag; add an equivalent pool
  cleanup to the non-marker `tpc_thread.c` path (currently none). **The cancel flag must live in the
  refcounted registry entry, not the request pool** (see §4.10).
**Perf:** negligible — reaper on a coarse timer under the existing registry mutex, off the data path,
disabled by default; cancel read is a single relaxed atomic.
**Tests:** (success) many completed TPCs leave zero `in_use` slots; a healthy in-flight TPC is never reaped
(progress refreshes `updated_at`). (error) abandoned transfers with a short test max-age → slots reclaimed,
subsequent TPC succeeds instead of 503. (security) client disconnect mid-COPY → curl thread aborts, temp
file unlinked, worker freed, no cross-tenant effect.

### 4.6 WS6 — Stream proxy correctness + leak + upstream write timeout
**Closes:** PXY-3 (leak), PXY-6 (corruption), PXY-2 (no upstream write-stall timeout).
**Files:** `src/net/proxy/events_write.c`, `forward_request.c`, `connect_lifecycle.c`, `events_splice.c`;
`config.h` + `module.c`; `server_conf.c`.
**Changes:**
- **PXY-3:** after the deferred `xrootd_proxy_flush` completes in `events_write.c`, free `proxy->wbuf` and
  clear the pointer (mirroring the immediate-completion branch in `forward_request.c`). Ensure
  `ngx_handle_write_event` is armed after a partial flush so ET epoll re-delivers.
- **PXY-6:** branch on `sent<0` (`NGX_AGAIN`, nothing on the wire — safe to resend whole) vs `0<sent<8`
  (partial — resume from offset) vs `sent==8`. Safest: do not put header bytes on the wire until splice is
  confirmed viable. Preserve the 1MiB-pipe splice fast path; fix only the short-header fallback.
- **PXY-2:** add `proxy_write_timeout` (UNSET → no write timer). When set, arm `uconn->write` at the
  deferred-flush park and del on full drain; `events_write.c wev->timedout` already aborts cleanly.
**Perf:** none — wbuf free + write-event arm are on the partial-write error path; splice fix only touches
the rare short-header fallback.
**Tests:** (success) normal proxied read/write byte-exact, reused across many requests, no wbuf growth
(malloc-count probe / ASAN loop). (error) slow client reader forcing repeated partial header sends →
relayed frame stream byte-exact (no duplicated header), no leak over N iters (LSan clean). (security)
stalled upstream with `proxy_write_timeout` → session torn down within timeout, wbuf freed, concurrent
healthy session unaffected.

### 4.7 WS7 — Cluster/CMS dead-peer detection
**Closes:** PXY-4 (`xrootd_srv_select` filters only `blacklisted_until`, never `last_seen` age, so a
silently-dead DS stays selectable), CMS-1/CMS-2 (manager/client never correlate PONG; `ev->timedout` is
dead code), PXY-8 (redir cache vs `?tried=` reconciliation).
**Files:** `src/net/manager/registry.c`; `src/net/cms/server_recv.c`, `recv.c`, `connect.c`;
`src/net/manager/redir_cache.c` + `src/read/open_request.c`; `config.h` + `module.c`.
**Changes:**
- `last_seen` staleness check inside the existing `xrootd_srv_select` / `xrootd_srv_count_matching`
  slot-scan (two integer comparisons, same lock, no second pass). New `xrootd_manager_stale_after`
  (default 0; recommended ~3× `cms_interval`).
- CMS read-inactivity timer on **a separate `c->read` timer object** (NOT the heartbeat ping timer — see
  §4.10) for each registered DS and the CMS client; refresh `last_seen` on inbound PING/PONG.
- Reconcile collapse-redir cache lookup with the client's `?tried=` list in `open_request.c` (skip a cached
  host that's in `tried`), within the bounded probe window.
- Exponential backoff + jitter on module-driven retry/redirect re-convergence to avoid retry storms.
- CMS-3: gate the unconditional `NGX_LOG_WARN` spam behind `NGX_LOG_DEBUG_STREAM` (reduces heartbeat
  overhead).
**Perf:** negligible — additive comparisons under the existing spinlock; CMS timers reuse existing events;
log gating *reduces* per-frame overhead; all default off.
**Tests:** (success) healthy cluster open/locate/stat selects a live DS; a heartbeating DS is never marked
stale. (error) stop a DS's heartbeat with `stale_after` enabled → manager stops selecting it within the
window, clients redirected to a live peer. (security) redirect with `?tried=deadhost` → redir cache does
not re-return the dead host; converges to `kXR_NotFound` or a live host, no loop. **Plus** the
all-replicas-transiently-stale degenerate case (see §7).

### 4.8 WS8 — HTTP/WebDAV/S3 durability + reapers
**Closes:** HTTP-1 (no module-set `client_body/header/send_timeout` → nginx 60s defaults: too generous for
slowloris, too tight for slow WAN), HTTP-2 (S3 MPU staging dirs orphan forever → ENOSPC DoS), HTTP-4
(WebDAV PUT writes final path `O_TRUNC` in place — concurrent reader sees partial, crash leaves truncated
file), HTTP-5 (`CompleteMultipartUpload` assembles parts with blocking read/write on the event thread,
head-of-line-stalling the worker).
**Files:** `src/webdav/config.c`, `webdav.h`, `put.c`; `src/s3/multipart_*.c`, `module.c`;
`docs/03-configuration/production-deployment.md`.
**Changes:**
- HTTP-1: module-recommended timeout defaults via docs + a tuned sample config, and optionally sane
  defaults in the WebDAV/S3 location merge where the module owns the loc conf (explicit operator value
  always wins). Do **not** silently change nginx core defaults globally.
- HTTP-2: S3 incomplete-MPU reaper — coarse timer rmdir-recursives staging dirs older than
  `xrootd_s3_mpu_max_age` (default 0 = disabled; recommended 7 days, AWS-parity).
- HTTP-4: WebDAV PUT staged temp + atomic rename (reuse `s3/put.c` pattern). **Add fsync-before-rename**
  ordering and an ENOSPC test (see §7).
- HTTP-5: offload `CompleteMultipartUpload` part-assembly to the thread pool (as PUT already does),
  preserving 64KiB chunking + atomic rename.
**Perf:** negligible — GET zero-copy sendfile/kTLS path untouched; PUT in-memory thread-pool fast path
untouched (staged-commit changes the destination fd, not the copy mechanism); MPU-complete offload *moves
blocking work off the event thread* (a perf improvement under load); reaper on a coarse timer, default off.
**Tests:** (success) WebDAV PUT via staged temp+rename byte-exact; concurrent GET during the write window
never sees a partial/zero-length object (atomic). (error) S3 MPU parts then disconnect without
Complete/Abort, reaper at short test max-age → staging reclaimed, disk back to baseline. (security) large
offloaded Complete → other clients on the same worker served with bounded latency (no HoL freeze), object
byte-exact with atomic rename.

### 4.9 WS9 — Overload shedding
**Closes:** STR-6 / KNOB-5 (no raw concurrent-connection cap before identity is known), KNOB-4 (Phase-20
rate-limit/auth-cache configs not inherited across server scopes — a child block silently gets the feature
OFF).
**Files:** `src/core/config/server_conf.c` (merge inheritance); `src/connection/handler.c` (cap at accept);
`config.h` + `module.c`; `docs/05-operations/*`.
**Changes:**
- KNOB-4: add parent→child inheritance for `token_cache_kv` / `auth_cache` / `rate_limit` in
  `merge_srv_conf` (currently set in create, never merged).
- KNOB-5: optional pre-identity admission cap `xrootd_max_connections` (default 0 = unlimited) checked at
  accept against the existing `connections_active` atomic. **Pre-identity it must be a plain TCP close, not
  a framed `kXR_wait`** (no streamid before login — see §4.10), and the `connections_active` decrement must
  go through the single disconnect funnel.
- Document recommended `memory_budget` + keepalive + read/send timeout combos for lossy/WAN fleets.
**Perf:** negligible — single atomic compare at accept (default 0 = skip); merge fix is config-time only.
**Tests:** (success) cap above load → all admitted, byte-exact; child block inherits parent rate-limit.
(error) exceed the cap → clean refusal (not a crash), existing connections unaffected. (security)
half-open flood + WS1 `handshake_timeout` together bound resource use; server stays responsive to a
legitimate client during the flood.

### 4.10 MANDATORY correctness rules (verified hazards — not optional)

1. **Timer ownership is a UAF hazard.** `recv.c` hands off to AIO/SENDING and *returns* without
   re-entering the loop (`recv.c:165-205`). If the read timer is left armed across that handoff,
   `rev->timedout` fires mid-AIO and finalizes the session while an AIO task still references
   `ctx`/`read_scratch` → use-after-free. **Disarm the read timer before every return-to-subsystem
   (AIO/SENDING/UPSTREAM/PROXY); the send timer is the sole owner during SENDING.**
2. **Do not arm/disarm per-PDU.** There are 5+ `state=REQ_HEADER` reset sites
   (`recv.c:176,326,442,452,470,501`) plus Phase-29 pipelining keep-reading branches
   (`recv.c:436-444, 495-504`). Arm **once on genuine incompletion** (first `avail<need` on an idle
   connection), disarm **on quiescence** (`out_count==0` AND no partial header/payload), with an idempotent
   `armed` bool so the pipelining conjuncts never touch the timer. Use `timer_set` so re-arm is a no-op;
   never `del+add` a timer on a slot that merely advanced.
3. **WS5 reaper must mark-then-reclaim with a generation counter** — `updated_at` older than max-age does
   **not** prove the worker is dead; a wedged-but-alive worker can wake and write into a reaped slot →
   double-free / slot-reuse corruption. Set a tombstone/generation under the mutex; the worker checks the
   generation before writing back. Re-check `state==RUNNING/PENDING && in_use` under the lock before
   reclaiming.
4. **WS5 cancel-flag lifetime:** set from the event thread on client disconnect, read by the curl worker
   (thread pool). It **must live in the refcounted registry entry** (or a refcounted heap struct), not the
   request pool — freed only after the worker has acknowledged. Otherwise classic cancel-race UAF.
5. **WS6 splice fix** must branch on `sent<0` (`NGX_AGAIN`) vs `0<sent<8` vs `sent==8` — treating the
   negative `NGX_AGAIN` as a byte count computes a garbage resume offset.
6. **WS7 CMS timer** must be a **separate `c->read` timer object** — reusing the heartbeat ping timer
   overwrites `timer.key`, silently breaking one or the other.
7. **WS3 `TCP_USER_TIMEOUT` must be `>> send_timeout`** and `>>` the slowest legitimate window drain (it is
   an active per-connection kernel deadline that RSTs unacked-data connections, not a passive backstop).
   Keep idle-probe `SO_KEEPALIVE` as the primary OS backstop; make `TCP_USER_TIMEOUT` opt-in with a loud
   doc warning. setsockopt failures are non-fatal.
8. **WS9 pre-identity cap** = plain TCP close; `connections_active` decrement via the single disconnect
   funnel (else the gauge drifts).

---

## 5. New config directives (all default to current behaviour)

| Directive | Purpose | Default |
|---|---|---|
| `xrootd_read_timeout` | Steady-state per-PDU receive deadline on root:// (slowloris / silent stall; also bounds slow write/auth/prepare payload). | off (`NGX_CONF_NO_TIMER`) |
| `xrootd_handshake_timeout` | Tighter pre-login deadline so an unauthenticated stall cannot squat a slot. | off |
| `xrootd_send_timeout` | Response-drain deadline: sheds a slow/half-open consumer holding parked `out_ring` slots. | off |
| `xrootd_tcp_user_timeout` | `setsockopt(TCP_USER_TIMEOUT)` at accept — kernel reaps a silently-dropped peer with unacked in-flight data. | 0 (kernel default) |
| `xrootd_tcp_keepalive` | `SO_KEEPALIVE` + tight `KEEPIDLE/INTVL/CNT` for seconds-scale dead-peer detection. | off |
| `xrootd_max_connections` | Pre-identity concurrent-connection admission cap (vs `connections_active`). | 0 (unlimited) |
| `xrootd_proxy_write_timeout` | Stream-proxy upstream write-stall deadline. | off |
| `xrootd_manager_stale_after` | `last_seen` age beyond which a DS is excluded from cluster selection; drives CMS read-deadline staleness. | 0 (recommended ~3× `cms_interval`) |
| `xrootd_webdav_tpc_low_speed_bytes` | `CURLOPT_LOW_SPEED_LIMIT` floor (B/s) for WebDAV HTTP-TPC. | 0 |
| `xrootd_webdav_tpc_low_speed_secs` | `CURLOPT_LOW_SPEED_TIME` window (s below floor before abort). | 0 |
| `xrootd_tpc_max_transfer_secs` | Wall-clock deadline for a native root:// TPC pull (sampled, no per-frame syscall). | 0 (no cap) |
| `xrootd_tpc_transfer_max_age` | Max age (since `updated_at`) before the TPC registry reaper reclaims a stuck slot. | 0 (recommended 3600s) |
| `xrootd_s3_mpu_max_age` | Max staging-dir mtime age before the S3 incomplete-MPU reaper rmdirs it. | 0 (recommended 7 days) |

---

## 6. Test design — two tiers (honest framing)

At the application layer these are TCP protocols, so only the optional tier injects *literal* loss. **The
`fault_proxy` tier must not be labeled "packet-loss testing" — it is a stall/partial/disconnect harness**
(its own code comment notes that dropping bytes from an ACKed stream corrupts rather than emulates loss).

| Tier | Mechanism | Privilege | Tests | Coverage |
|---|---|---|---|---|
| **Primary** (always runs) | Extend `tests/c/fault_proxy.c` into a byte-level fault shim the test dials *through* | **None** (`cc`) | Stall / partial-read / slow-drip / mid-op RST / outage (symptoms of loss) | All protocols, TLS only at the record level |
| **Optional** (skips cleanly) | `unshare --net --user --map-root-user` + `tc qdisc … netem delay … loss 20% reorder …` on `lo` | **None** — unprivileged userns, **verified working on this host, no sudo** | Literal 20% IP-layer loss/delay/reorder with real TCP retransmit dynamics | Cleartext root:// frame reassembly |

### 6.1 `fault_proxy` extensions (new control-port levers)
Beyond the existing `latency/drop/block/unblock/clear/status`:
- `chunk <bytes>` — split every forwarded write into ≤N-byte segments.
- `drip <bytes> <ms>` — forward `<bytes>`, sleep `<ms>`, repeat (slow-drip / low-speed).
- `lossy <pct>` — per-chunk probabilistic drop-connection / inject-stall.

> **Validity requirement:** `chunk` alone does **not** force partial reads — the kernel re-coalesces. The
> harness must set **`TCP_NODELAY` on the proxy egress AND insert a real time gap (`drip`)** so bytes are
> delivered separately and the `recv.c:316 avail<need` reassembly branch actually executes. Without the
> gap, WS1's reassembly defense is untested while the test passes green.

### 6.2 Per protocol
- **root:// / roots://** — pyXRootD `client.File/FileSystem` (`timeout=`) + raw-socket framing
  (`test_metadata_stress` `_xrd_login/_op_stat/_op_dirlist/_op_locate`, `test_a_robustness` partial-frame
  helpers), dialing the proxy port. TLS passes through opaquely. **Frame-level reassembly (WS1/WS2) is only
  truly exercised on the cleartext :11094 plane** — over TLS the proxy only splits ciphertext records.
- **WebDAV davs:///http** — `requests.Session(verify=False)` + raw-socket PROPFIND keep-alive.
- **S3 REST** — `requests` + hand-rolled SigV4 (no boto3).
- **/metrics** — urllib/requests for leak/gauge assertions. *(Also harden the :9100 handler against a
  slowloris scraper — see §7.)*
- **TPC** — `fault_proxy` in front of the TPC **source** so the curl/native puller sees the slow/dropping
  remote.

### 6.3 True-loss tier (optional)
Inside `unshare --net --user --map-root-user`: `ip link set lo up` then
`tc qdisc add dev lo root netem delay <D>ms loss 20% reorder <R>% <corr>%`. The netns loopback is
**namespace-local**, so the pre-started 127.0.0.1 fleet is unreachable — **this tier must spawn its own
nginx inside the ns from the *identical* rendered config** (`TEST_SKIP_SERVER_SETUP=1`, fixed high ports)
or the 20% result won't generalize to the deployed config.

### 6.4 Metadata load
Reuse `tests/test_metadata_stress.py::_paced_hammer` (lock-free, per-thread sessions, per-thread counters)
at **`NETFAULT_WORKERS=200-400`** firing interleaved `kXR_stat`/`dirlist`/`locate` (raw) + PROPFIND.
Data-plane integrity covered separately by the `test_concurrent` `ProcessPoolExecutor` pattern (n=1/2/4/8
each transferring the 200MiB file, md5-checked) through the same fault path.

### 6.5 Success criteria (assertions)
- **Data integrity:** every *completed* read/GET/TPC is byte-exact (md5 == origin) — no silent truncation
  or corruption.
- **Completion rate is measured separately** and **expected to crater under 20% loss** — do **not** assert
  `<1% errored`. A pass means "everything that completed was correct + nothing hung + nothing leaked," not
  "most ops succeeded."
- **No hang:** under slow-drip/black-hole/stall the server CLOSES within the configured deadline (+slack);
  measure teardown latency with an **independent in-test wall-clock bound strictly below the pytest
  timeout** (else a real hang is indistinguishable from pytest's own kill).
- **Clean errors not crashes:** classify via `_classify_stream/_classify_http`; `_assert_no_fallover`
  (something always answers; graceful `kXR_wait`/`429`/`Retry-After`; no worker crash / 5xx storm).
- **No leak:** prove with an **ASAN/LSan build run** (the sound proof for PXY-3 + the TPC cancel paths) —
  gauge-polling races the 60s reaper and gives false results. If gauges are used, drain-to-quiescence with a
  bounded poll tied to the reaper interval, then assert exactly baseline.
- **Bounded latency:** served-op p95/p99 stay finite under loss (validates the event-model + per-op
  deadline claims).
- **Self-heal:** after a stall storm, a fresh request SUCCEEDS (reaper/cap/timeout reclaim, not permanent
  wedge).

### 6.6 Harness integration
New `netfault` marker registered in `pytest.ini` AND `conftest.py::pytest_configure`; suite also
`@pytest.mark.serial + slow + timeout(180)`, run in a dedicated lane (`pytest -m netfault -p no:xdist`),
excluded from the fast lane (`-m 'not netfault'`). A `requires_netfault` session fixture probes
`unshare --net --user --map-root-user true` + `sch_netem` and `pytest.skip()`s **only** the true-loss tier;
the primary `fault_proxy` tier always runs (needs only `cc` + a reachable server). If even `cc` is missing,
fall back to a pure-Python asyncio fault relay implementing the same levers.

---

## 7. Open questions & gaps to resolve before/while implementing

**Decisions for Rob:**
1. **Default posture:** ship the new timeouts OFF (chosen here — zero behaviour change, but a fresh
   deployment stays vulnerable until tuned) **or** with a conservative hardened-by-default value
   (e.g. `read_timeout 300s` — protects out of the box but is a behaviour change for existing configs)?
2. **Subsystem-handoff timer semantics:** disarm-on-handoff + kernel backstop (simpler, chosen) vs a
   whole-operation (per-request) deadline (exceeds official even further, more complex)?
3. **True-netem tier in CI:** is the CI runner an unprivileged-userns + `sch_netem` environment (as this
   dev host is), or should the true-loss tier be dev-only with CI relying on the `fault_proxy` tier?

**Gaps the plan must cover (critic-identified):**
- **kXR_bind secondary connections:** a bound secondary shares file handles with the primary via the
  session registry; a per-conn read timer must respect the multi-connection session lifetime and not
  conflict with the Phase-27 LRU session reaper.
- **/metrics :9100 self-resilience:** harden the metrics stream handler (`src/observability/metrics/stream.c`) against a
  slowloris scraper — HTTP-1 guidance covers WebDAV/S3 loc confs, not this separate handler.
- **IPv6 / dual-stack:** `TCP_USER_TIMEOUT`, `SO_KEEPALIVE`, and the cap/accept logic must work on
  `AF_INET6` (the codebase has a documented unbracketed-IPv6 history — phase-36). Add an IPv6 netfault case.
- **All-replicas-transiently-stale (WS7):** a 20% loss storm can mark every replica stale → `srv_select`
  returns zero candidates → false `kXR_NotFound` for a file that exists. Test this degenerate case;
  backoff/jitter alone doesn't cover it.
- **TPC PUSH direction + delegation expiry:** WS4/WS5 focus on PULL; a stalled PUSH and a delegated proxy
  expiring mid-transfer are distinct stall modes.
- **ENOSPC during staged-commit/reaper (WS8):** the staged temp write and recursive rmdir can fail under
  the very ENOSPC the MPU-orphan DoS causes; needs fsync-before-rename ordering + an ENOSPC test.
- **MPU concurrency:** two clients completing the same upload-id, or the reaper deleting a staging dir while
  a Complete assembles from it (same class as the WS5 reaper race).
- **Protocol-correct error mapping:** a stall must surface as the right wire error per the
  errno→kXR→HTTP table (clean close / kXR error for stream; 408/504 for WebDAV; the right S3 code) — FTS/
  RUCIO distinguish timeout from reset. "Connection dropped" is not always the protocol-correct shed.
- **SHM consistency on worker SIGKILL mid-reap:** a worker killed while holding the registry/manager reaper
  mutex wedges reaping fleet-wide (the documented FRM/SHM mutex-clobber class — see
  `frm_fork_shm_crash`). Reaper mutexes need the robust-mutex / slab-header discipline already established.

---

## 8. Sequencing

- **Phase 0 — foundation (low risk):** directive + merge scaffolding, the two pure timer helpers, metrics
  enums — all defaulted OFF. Everything builds on this.
- **Phase 1 — stream slow-client defense (highest value):** WS1 → WS2 → WS3, shipped with the `fault_proxy`
  tier from day one.
- **Phase 2 — TPC stall bounding:** WS4 → WS5.
- **Phase 3 — proxy correctness:** WS6 (the two real bugs).
- **Phase 4 — cluster/CMS dead-peer:** WS7.
- **Phase 5 — HTTP/S3 durability:** WS8 (parallel with Phase 4).
- **Phase 6 — overload hardening:** WS9.
- **Throughout:** 3 tests per change (success + error + security/edge); netfault suite grows in its own
  serial lane. **Final gate:** perf regression run with all directives OFF (prove hot-path neutrality),
  then a second run with them ON (characterize cost on the error/slow paths only).

---

## 9. Verdict (from the adversarial critique)

> *Sound in diagnosis, and the load-bearing claims were verified against source:* the steady-state
> read/send/handshake timers genuinely are never armed (`recv.c:135-140` is a live-but-unreached
> `timedout` branch); **PXY-3 is a confirmed real leak** (`events_write.c:106-124` never frees
> `proxy->wbuf` after a deferred flush while `forward_request.c:345` reassigns it per request); **PXY-6 is a
> confirmed real corruption bug** (`events_splice.c:272-279` re-sends the whole header on any `sent!=8`).
> The off-by-default gating discipline is correct and the architectural-superiority claim over official
> XRootD is defensible. **The three things this doc fixes vs the first draft:** (1) the test is re-scoped
> and re-labeled — `fault_proxy` is a stall/partial/disconnect harness, the only real-loss tier runs a
> self-spawned server and at 20% loss mostly times out, so completed-op integrity is separated from
> completion rate, partial-PDU is forced with `TCP_NODELAY`+`drip`, and leaks are proven with ASAN/LSan;
> (2) timer ownership across the AIO/SENDING handoff is treated as a mandatory UAF fix, not an open
> question, and timers are never churned in the pipelining branches; (3) the TPC reaper is mark-then-reclaim
> with a generation counter and the cancel flag is pinned to the refcounted registry entry. Stale premises
> trimmed: WS4's curl busy-spin (already has a 1000ms wait) and WS5's progress callback (already wired).
