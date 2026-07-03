# CVMFS proxy: absorb upstream flakiness (upstream retry + RTT geo-answer)

**Date:** 2026-07-03
**Status:** approved → implementation
**Area:** `src/protocols/cvmfs/`, `src/fs/cache/`, `src/fs/cache/origin/`, `src/fs/backend/http/`

---

## 1. Problem

A UK worker node mounts CVMFS through this nginx-xrootd node acting as its
**site proxy** (`CVMFS_HTTP_PROXY`). Fills from the node to the RAL Stratum-1
periodically **get stuck before returning any data** — a connection opens (or
half-opens) and then delivers no bytes. The cause is outside our control:
deep-packet-inspection on the intervening network, and/or RAL rate-limiting a
single client node (which it should not do). When this happens:

1. A single stuck fill burns the **entire client-hold budget** (default 25 s,
   which must stay under the worker node's `CVMFS_TIMEOUT`).
2. The client times out and begins **geo flailing** — probing distant servers
   (China, Australia) before dropping back to CERN rather than the nearer RAL.
3. A storm builds as more requests pile onto stuck upstream connections
   (visible in the dashboard transfer table as connections stuck pre-first-byte).

### Verified root cause

CVMFS CAS/manifest fills go `sd_http.c` → the shared curl transport
(`origin/s3_transport.c`), which sets **only** `CURLOPT_TIMEOUT_MS` (60 s
total) and `CURLOPT_NOSIGNAL`. There is:

- **no `CURLOPT_CONNECTTIMEOUT`** — a DPI-blackholed connect hangs up to 60 s;
- **no `CURLOPT_LOW_SPEED_LIMIT`/`_TIME`** — a socket that opens but returns no
  bytes hangs the full 60 s.

`sd_http_request_fo` already implements read-failover (2 attempts) and health
scoring, and `fill_retry.c` already implements a waiters-aware
backoff/jitter budget — **but they are starved of time**: the first attempt's
60 s timeout exceeds the 25 s client hold, so the client gives up before the
retry machinery ever runs. The fix is therefore **detect the stall in seconds,
then force the preferred origin through with fresh connections inside the
client-hold budget**, not "add retry" (retry already exists).

---

## 2. Goals / non-goals

**Goals**
- Detect a stuck connect or a no-first-byte stall in seconds, not 60 s.
- Keep retrying the **preferred origin** (RAL) with fresh connections until the
  data lands or the client-hold budget is (nearly) exhausted — "force through".
- When the budget is exhausted with zero bytes, **serve a stale cached copy if
  one exists** (meaningful for the mutable manifest/whitelist class) rather than
  surfacing an error.
- As belt-and-braces, **answer the geo API ourselves** with an RTT-ranked order
  so that even a fill that does fail leaves the client pointed at sane servers.
- Everything defaults to today's behavior; new behavior is opt-in per location.

**Non-goals**
- No global circuit-breaker. Force-through is deliberately aggressive per
  operator intent; an optional per-origin in-flight cap is the only throttle.
- No change to the CAS verify-on-fill contract, the coalescing/hold layer's
  external contract, or the client protocol.
- GeoIP databases: the geo-answer ranks by measured RTT from our vantage, not
  by geolocation of arbitrary hostnames.

---

## 3. Design — Part A: upstream fill resilience

### A1. Fast stall detection (the enabler)

Extend the origin transport seam so the fill can bound connect and throughput,
plumbed from config with safe defaults. In `origin/s3_transport.c`'s
`curl_easy_setopt` block add:

- `CURLOPT_CONNECTTIMEOUT_MS` — connect ceiling.
- `CURLOPT_LOW_SPEED_LIMIT` + `CURLOPT_LOW_SPEED_TIME` — if throughput stays
  below the floor for the window, libcurl aborts with `CURLE_OPERATION_TIMEDOUT`.
- Keep `CURLOPT_TIMEOUT_MS` as the outer ceiling.

The transport `request()` signature carries the extra bounds (a small
`xrootd_origin_timeouts_t { connect_ms; stall_ms; stall_bytes_per_s; total_ms; }`
passed through instead of the single `timeout_ms`, defaulted so existing callers
are unchanged). `sd_http` fills these from its instance config.

New directives (cvmfs loc-conf):
- `xrootd_cvmfs_origin_connect_timeout` — seconds, default 2.
- `xrootd_cvmfs_origin_stall_timeout` — seconds, default 4.
- `xrootd_cvmfs_origin_stall_bytes` — bytes/s floor, default 1.

### A2. Budget-bounded force-through retry (policy = force-primary)

New directive `xrootd_cvmfs_fill_retry_policy failover|force-primary`, default
`failover` (preserves today's alternate-endpoint behavior for existing
multi-origin deployments). In `force-primary`:

- `sd_http_request_fo`'s **alternate-endpoint switch is suppressed** — a
  transport failure/stall re-attempts the *same* preferred endpoint with a
  **fresh connection** (a new connection dodges a single DPI-poisoned /
  half-open / rate-limited socket).
- The number of attempts and the per-attempt timeout are sized so
  `attempts × total_ms ≤ client_hold`. `fill_retry.c` already gates the loop on
  the waiters-aware window (`client_hold` while a client waits, `max_life`
  after); the per-attempt curl total timeout is derived from the same budget so
  a farm of fills cannot each overrun the hold.

The retry loop reuses `fill_retry.c` backoff+jitter between attempts; no new
retry engine.

### A3. Serve-stale-if-error on exhaustion — ALREADY PRESENT (no new code)

Verified during implementation: this is already implemented at the tier layer.
`sd_cache_fill()` (`src/fs/backend/cache/sd_cache.c`) calls
`sd_cache_stale_serve_ok()` on both an origin-open failure and a mid-read
failure: if an expired-but-COMPLETE cached copy exists within the bounded
10×-`manifest_ttl` window, the fill returns `NGX_OK` serving the re-armed stale
copy (expiry pushed one TTL forward so the next request retries the origin).

Consequence with A1/A2: for a **manifest/whitelist** whose refill stalls, the
FIRST failed attempt serves the stale copy immediately — the client gets a valid
recent manifest fast instead of blocking the whole hold. Force-through (A2) only
governs objects with nothing to serve stale (cold CAS miss, or a manifest past
the 10× window), which is the intended split. No change required here; adding a
second stale path would duplicate the existing helper.

### A4. Storm safety

Relies on existing machinery: `http_cache_fill.c` coalesces a client storm into
one fill per object; `fill_retry.c` half-jitter decorrelates the fill farm;
`sd_http` health scoring benches a genuinely dead origin (and the half-open
probe recovers it). One new optional throttle:

- `xrootd_cvmfs_origin_max_inflight` — per-origin concurrent fill cap, default 0
  (unlimited). A safety valve if RAL's rate-limiting ever needs taming; not
  engaged by default because force-through is the intent.

---

## 4. Design — Part B: server-side RTT geo-answer (belt-and-braces)

New directive `xrootd_cvmfs_geo_answer off|rtt`, default `off` (today's verbatim
passthrough). When `rtt`, `gate.c`'s `CVMFS_URL_GEO` case calls a new
`xrootd_cvmfs_geo_answer()` (new file `geo_answer.c`) instead of
`xrootd_cvmfs_geo_passthrough`:

1. **Parse** (event loop, pure, no alloc): the geo request is
   `/cvmfs/<repo>/api/v1.0/geo/<proxy-ref>/<server-list>`. Split the last
   `/`-segment on `,` into ≤ `max_servers` entries; extract host + port
   (default 80, `:port` honored). Every index is kept — a server is never
   dropped from the response permutation.
2. **Probe** (thread task, reusing the `geo.c` async idiom): for each server use
   a fresh EWMA-cached RTT; probe only stale entries. Reuse
   `cvmfs_connect_rtt_us()` (promoted from `static` in `origin_probe.c` to a
   shared helper — no reimplementation) and the `xrootd_cvmfs_rank_by_metric`
   ranker in `origin_geo.c`.
3. **Rank + respond** (event-loop done handler): fold samples into a per-worker
   direct-mapped EWMA cache keyed by `host:port` (short TTL, default 60 s; the
   `gate.c` negative-memo idiom), rank, emit the 1-based permutation as
   `text/plain`.

**Ranking buckets** preserve original relative order within each:
probed-reachable (by RTT) → probed-unreachable → unprobed. "Unprobed" =
guard-skipped or over-cap.

**Security guard (port + count caps):** only TCP-connect to CVMFS server ports
`{80, 443, 8000}`; a server on any other port (e.g. `:22`) is never probed and
lands in the unprobed bucket. `xrootd_cvmfs_geo_max_servers` (default 16) caps
the probed list; entries beyond it are unprobed. The node cannot be turned into
a general port scanner, and the client always receives a complete, well-formed
permutation. Replace-not-repair: when answering locally we never contact the
upstream GeoAPI. Any parse failure / empty result / missing thread pool falls
back to `xrootd_cvmfs_geo_passthrough`.

New directives: `xrootd_cvmfs_geo_answer off|rtt` (default off),
`xrootd_cvmfs_geo_cache_ttl` (default 60), `xrootd_cvmfs_geo_max_servers`
(default 16).

---

## 5. Files

**New**
- `src/protocols/cvmfs/geo_answer.c` — parse/probe/rank/respond geo answer.

**Edit**
- `src/fs/cache/origin/transport.h`, `origin/s3_transport.c` — carry connect +
  low-speed bounds through `request()`; set the curl options.
- `src/fs/backend/http/sd_http.c` / `.h` — process-global force-primary toggle
  (`sd_http_force_primary_set`) suppressing the alternate-endpoint switch in
  `sd_http_request_fo`; each retry re-hits the preferred origin on a fresh handle.
- `src/protocols/cvmfs/gate.c` — geo fork.
- A3 (serve-stale-on-exhaustion): NO change — already implemented by
  `sd_cache_stale_serve_ok()` in `src/fs/backend/cache/sd_cache.c` (see §A3).
- `src/protocols/cvmfs/geo.c` — unchanged passthrough kept as fallback.
- `src/protocols/cvmfs/origin_probe.c` / cvmfs.h — export `cvmfs_connect_rtt_us`.
- `src/protocols/cvmfs/cvmfs.h`, `module.c` — new directives + conf fields.
- `./config` — add `geo_answer.c`.
- `docs/04-protocols/cvmfs.md` — §3.3 (geo answer), §5 (origin resilience).

---

## 6. Testing (3 per change: success + error + security/limit)

**Part A**
- *Success:* mock origin accepts the connection then withholds bytes → fill
  declares a stall in ~stall_timeout and forces through on a fresh connection
  that serves the object, all within a 25 s hold; client sees 200, never 504.
- *Stale:* manifest refill against a stalled origin with a prior cached manifest
  → served stale, no error.
- *Limit/security:* per-attempt timeout × attempts never exceeds `client_hold`;
  `force-primary` never opens an alternate endpoint (assert single endpoint hit).

**Part B**
- *Success:* geo request listing two local mock servers (fast loopback + slow /
  blackholed) → response ranks the fast one first even when sent worst-first.
- *Fallback:* `geo_answer=off`, and a malformed/empty list with `rtt` on →
  verbatim passthrough, no crash.
- *Security-neg:* a `:22` entry is never connected to and lands last; over
  `max_servers` entries are appended unprobed in original order.

---

## 7. Defaults summary

| Directive | Default | Effect at default |
|---|---|---|
| `xrootd_cvmfs_origin_connect_timeout` | 2 s | connect fails fast |
| `xrootd_cvmfs_origin_stall_timeout` | 4 s | no-first-byte fails fast |
| `xrootd_cvmfs_origin_stall_bytes` | 1 B/s | low-speed floor |
| `xrootd_cvmfs_fill_retry_policy` | `failover` | today's behavior; set `force-primary` to force RAL |
| `xrootd_cvmfs_origin_max_inflight` | 0 | unlimited (force-through intent) |
| `xrootd_cvmfs_geo_answer` | `off` | verbatim geo passthrough |
| `xrootd_cvmfs_geo_cache_ttl` | 60 s | per-host RTT cache TTL |
| `xrootd_cvmfs_geo_max_servers` | 16 | probed-list cap |

Note: even with fast detection + force-through, a cold CAS miss against a
totally-dead RAL for the whole budget can still 504 (nothing to serve stale).
This is accepted; force-through makes it rare.
