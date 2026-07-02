# Reliability under load: observed XRootD failure modes and the nginx module's mitigations

## Scope and honesty up front

This document records **specific failure modes observed in the official XRootD
stack under sustained, concurrent, and adversarial load**, and the **concrete
architectural choices the nginx-xrootd module makes** that address those classes
of problem. Every "official-server problem" below is something that was *directly
observed* while validating this module — most of it during a single
~4,000-test conformance/stress marathon on a constrained host — not a claim
copied from elsewhere.

A fair framing matters: the official XRootD server and `XrdCl` client are mature,
widely deployed, production-grade software. Several observations below are
sharpened by a deliberately hostile environment (a constrained WSL2 host, a
26-minute serial marathon that accumulates kernel and memory pressure, and tests
that *intentionally* race teardowns and forge requests). The point is not "nginx
beats XRootD"; it is that the module's design removes or contains several classes
of load-induced fragility, and where it cannot, it fails *predictably* rather
than *silently* or *fatally*.

```text
  THREAD-PER-CONNECTION (official)          EVENT LOOP (nginx-xrootd worker)
  ──────────────────────────────           ────────────────────────────────
  conn1 ─▶ [thread] ─blocks on disk─╮      conn1 ─┐
  conn2 ─▶ [thread] ─blocks on cv ──┤      conn2 ─┤   ┌─ epoll loop ─┐  never
  conn3 ─▶ [thread] ─stalled ───────┤      conn3 ─┼──▶│ non-blocking │  blocks
  …                                 │      …       │   │ slow work ▶ │
  connN ─▶ [thread] ────────────────┤      connN ─┘   │ thread pool │
                                    ▼                  └──────┬──────┘
   under load: threads SATURATE,           one slow op CANNOT freeze the loop;
   a wedged op ties up a thread,           a bad request is contained to its
   the daemon stalls or dies               own ngx_connection_t
                                           ⚠ the rule: a handler that blocks
                                             freezes EVERY conn on the worker
```

The two servers also differ in concurrency model in a way that explains most of
what follows:

| | Official `xrootd` / `cmsd` | nginx-xrootd module |
|---|---|---|
| Concurrency | Thread-per-connection / thread pools, blocking I/O | Single-threaded **epoll event loop** per worker, non-blocking I/O |
| A slow/blocked op | Ties up a thread; under load threads saturate | Must never block the loop — slow work is cached, offloaded, or deferred with backpressure |
| Failure of one request | Can stall or crash a shared thread/daemon | Contained to one `ngx_connection_t` |

---

## Problems observed with the official stack under load

### 1. `XrdCl` synchronous-call deadlock (client-side, fatal to the caller)

A synchronous `XrdCl` call blocks the calling thread inside a C++ condition
variable — `XrdCl::Stream::OnReadTimeout → XrdSysCondVar::Wait` — **with the GIL
released** (in the Python binding) and no externally observable timeout. When
XrdCl's internal read-timeout path wedges (seen under concurrent load), the
caller is stuck *forever*: the wait never returns to the interpreter, so even a
SIGALRM-based watchdog cannot fire.

**Evidence:** a GDB backtrace of a frozen test process showed exactly this stack;
a single hung op froze an entire 4,000-test session and had to be killed.

**Consequence:** an application embedding `XrdCl` inherits an un-interruptible
hang. This is why this project's test harness now runs *all* official bindings in
an out-of-process worker — so a deadlock kills a subprocess, not the host process.

### 2. `XrdCl` response-framing corruption under concurrent dirlist load

Under concurrent `kXR_dirlist` traffic the official client/server pair
intermittently returns `[ERROR] Invalid response`. It is a known framing quirk on
the pooled client connection: a second large response on a reused connection can
desync the parser. The condition is real enough that the conformance suite ships
a dedicated retry helper whose comment names it *"an xrootd-client quirk, not an
nginx behaviour."*

**Evidence:** in the same dirlist comparison, **the nginx module returned
`[SUCCESS]` while the reference official xrootd returned `[ERROR] Invalid
response`** — repeatedly, across multiple marathon runs, only under load.

### 3. Reference `xrootd`/`cmsd` daemons becoming unhealthy under a long marathon

After a sustained multi-process marathon, the reference data-node daemons were
found dead (process count had dropped to zero) — i.e. they did not survive the
accumulated resource pressure of the run, whereas the nginx instances did. This
is the practical face of the thread-per-connection model meeting fd/memory
pressure.

### 4. CMS heartbeat drop → **false `kXR_NotFound` for a file that exists**

In a redirector/cluster (`cmsd` ↔ manager), a data server's management
connection can transiently drop under load (CPU starvation, a momentary stall)
**even though its data plane is still serving bytes**. The stock reaction is to
treat the server as gone. A client asking for a file that lives *only* on that
server then gets "not found" — a correctness failure caused purely by load on the
*control* plane, not the data plane.

**Evidence:** reproduced deterministically — killing a data node's `cmsd` (while
its `xrootd` data server kept running) made the manager answer
`[3011] file not found` for a file that was demonstrably on disk and being served.

### 5. Per-request cryptographic validation stalling the request path

WLCG/JWT bearer-token validation (RSA signature verification + JSON parsing)
performed *per request* is expensive enough that, under token-auth load, it
stalls the request path — surfacing to clients as HTTP read timeouts.

**Evidence:** token-auth tests intermittently failed with
`requests.exceptions.ReadTimeout` only under the full concurrent load.

### 6. Adversarial teardown / handle-reuse races

Tests that *intentionally* tear a primary session down while a bound secondary
holds a large read, or that reuse a freed connection slot for a different file
under a new session (ABA), probe whether the server can be made to serve stale or
corrupt bytes, or to crash, under teardown races.

---

## What the nginx module does differently

### A. The event loop is never allowed to block (addresses #1, #3, #5)

Each worker is a single-threaded `epoll` loop. The architectural rule — enforced
throughout `src/` — is that **no handler may block the loop**: there is no
per-connection thread to absorb a stall, so a stall would freeze *every* client
on that worker. In practice that means:

- All client I/O is non-blocking, driven by read/write events.
- Genuinely blocking work (large disk reads, `copy_file_range`, S3 spooled PUT
  decode/multipart) is **offloaded to a thread pool** (`src/core/aio/`), proven via
  `strace` to run on thread-pool TIDs, never on the loop.
- A single misbehaving request is contained to its own `ngx_connection_t`; it
  cannot wedge a shared thread or the daemon.

This structurally removes the failure class behind #1 and #3: there is no
synchronous condvar wait on the request path to deadlock, and there is no
thread-per-connection pool to exhaust.

### B. Always-on per-worker token validation cache (addresses #5)

`src/auth/token/worker_cache.c` is a **lock-free, per-worker L1 cache** of
already-validated bearer-token claims, sitting in front of an optional
shared-memory L2. Because the loop is single-threaded, the L1 needs no locking
(O(1) probe, bounded memory, no LRU bookkeeping). A repeated token is served from
cache instead of re-running RSA verification + JSON parsing on the event loop, so
token-auth load no longer stalls the request path. A hard re-validation bound
caps how long a cached token may be served regardless of its `exp`.

### C. Availability-biased cluster selection — never a false NotFound (addresses #4)

The manager's server registry (`src/manager/registry.c`) is designed so that a
**control-plane hiccup never produces a false `NotFound` for a file that
exists**, on two axes:

- **Staleness fallback (Phase 39):** a data server that has missed its heartbeat
  window is *de-preferred*, not dropped — `xrootd_srv_select()` prefers the
  freshest live server but falls back to the least-stale one rather than
  answering NotFound when every replica is stale.
- **Blacklist fallback (this work):** a CMS-disconnect blacklists a server for
  30 s; `kXR_open`/`kXR_stat` now fall back to a *blacklisted-but-present* server
  as a last resort (`xrootd_srv_select_or_blacklisted`), because the data plane
  is almost always still alive after a transient heartbeat drop. `kXR_locate`
  stays strict (it reports only live servers), so a genuinely dead node is still
  honestly "not found" there, and the `tried`/`triedrc` retry protocol converges
  cleanly if a fallback target really is gone.

```text
  data node: cmsd (control plane) DROPS, but xrootd (data plane) STILL SERVING
  ───────────────────────────────────────────────────────────────────────────
   client ── open /file (only on node A) ──▶ manager
                                              │
                STOCK                         │            nginx-xrootd
          node A heartbeat missed             │      node A heartbeat missed
                │                             │            │
          "A is gone" ──▶ drop A              │      de-prefer / blacklist A (30s)
                │                             │            │ but data plane likely alive
          no other replica                    │      open/stat FALL BACK to A
                ▼                             │            ▼  (last resort)
          [3011] file NOT FOUND ✗             │      serve bytes ✓  5/5 + checksums
          (false: file is on disk!)           │
                                              │   locate STAYS strict → a truly
                                              │   dead node is still honestly absent
```

**Verified:** with a data node's `cmsd` killed (data server still up, node
blacklisted for 30 s), `xrdcp` through the nginx manager now succeeds 5/5 with
correct checksums, where the stock behaviour returned `file not found`.

### D. Graceful overload backpressure instead of rejection (addresses #3, #6)

Rather than rejecting or stalling under pressure, the module uses the protocol's
own backpressure primitives:

- `xrootd_send_wait()` / `xrootd_send_waitresp()` (`src/response/control.c`) emit
  `kXR_wait`/`kXR_waitresp` — telling a client to pause and retry after a bounded
  interval **without losing session context** — instead of an immediate
  `kXR_Overloaded` or a dropped connection.
- A leaky-bucket rate limiter (`src/ratelimit/`) sheds excess metadata traffic as
  `kXR_wait`/HTTP 429 and recovers, rather than falling over. Stress testing
  (paced ~100 req/s of `stat`/`dirlist`/`locate`/PROPFIND) showed it sheds
  cleanly with a stat-exempt / dirlist-limited policy and no fall-over.

### E. Hardened against load-induced crashes and leaks (addresses #3, #6)

Several load-only fragilities were found and fixed in the module itself, which is
why its instances survive marathons that the reference daemons did not:

- **Proxy upstream-bootstrap leak:** a permanently-rejecting upstream caused a
  95% CPU spin re-processing a torn-down proxy → >20 GB OOM. Fixed with a
  teardown guard at the top of the relay loop (`if (ctx->proxy != proxy) return;`).
- **FRM fork/SHM crash:** forking any reaped child SIGSEGV'd the master because
  custom SHM zones clobbered the slab header. Fixed by slab-allocating the table
  with the lock as its first member.
- **`kXR_endsess` session scope:** endsess used to de-authenticate the *current*
  connection regardless of which session id it named, breaking official-client
  reconnect recovery on lossy links. Now session-scoped, restoring clean
  reconnect for `XrdCl`/`xrdcp`/`xrootdfs`.
- The adversarial teardown/ABA races (#6) are part of the standing
  `evil_actor` suite; the server's worker stays flat on CPU/RSS/fds throughout
  them, and post-teardown reads return correct bytes or a clean error — never
  stale-inode or corrupt data.

### F. Lower per-request cost on the hot path

`kXR_pgread` uses a zero-copy gapped `preadv` with in-place 3-way CRC32c, cutting
module CRC+copy cost from ~27.6% to ~10% of the read path and eliminating a
14.8% memcpy. Less CPU per request means more headroom before load translates
into latency.

---

## Where the module deliberately fails *predictably* instead of silently

Reliability is not only about not failing; it is about failing legibly:

- **Containment over hang:** the harness runs official bindings out-of-process so
  an `XrdCl` deadlock (#1) becomes a bounded, killable subprocess timeout — a
  test failure, never a frozen host. This is a model for any application
  embedding `XrdCl`.
- **`kXR_wait`, not silent drop:** overload yields an explicit, bounded retry
  signal that preserves session context.
- **Honest NotFound boundaries:** the availability-biased selection (C) is
  carefully scoped so `locate` stays strict and the `tried`/`triedrc` protocol
  still converges — the module does not paper over a genuinely-absent file.

---

## Honest caveats

- **Not everything observed is the server's fault.** Some marathon failures are
  the *test client's* connection churn slowing ~10× under accumulated WSL2
  TIME_WAIT/scheduler pressure while the **nginx worker sits idle** (verified:
  flat CPU/RSS/fds). Those are host-capacity limits, not module defects, and no
  amount of server hardening fixes them — the right response there is to scale
  the client-side load, not the server.
- **The official server is mature.** These are specific, load-induced edges, not
  a verdict on XRootD's overall robustness; many were only reproducible under a
  deliberately hostile environment.
- **The module's advantages are model-driven.** The single-threaded event loop
  removes whole classes of thread/lock fragility but imposes its own discipline
  (never block the loop); the wins above are the payoff for honouring it.

---

## Summary table

| Observed failure mode (official stack, under load) | nginx-xrootd mitigation |
|---|---|
| 1. `XrdCl` sync-call deadlock (un-interruptible) | No blocking call on the request path; offload to thread pool; out-of-process containment for embedded `XrdCl` |
| 2. `XrdCl` "Invalid response" framing under concurrent dirlist | Module-side dirlist returns `[SUCCESS]` under the same load |
| 3. Reference daemons dying under marathon pressure | Event-loop model + leak/crash hardening; instances survive the marathon |
| 4. CMS heartbeat drop → false `NotFound` | Availability-biased selection: stale + blacklist fallback; `locate` stays strict |
| 5. Per-request token crypto stalling the path | Lock-free per-worker L1 token-claims cache |
| 6. Teardown/ABA races | Per-connection containment; flat worker profile; correct-bytes-or-clean-error guarantee |
| Overload | `kXR_wait`/`kXR_waitresp` backpressure + leaky-bucket shedding, not rejection |
