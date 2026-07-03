# Postmortem: Proxy Upstream-Bootstrap Memory Leak (event-loop spin on a torn-down proxy)

**Status:** Resolved. Primary fix in `src/net/proxy/events_read.c` (a teardown guard);
defense-in-depth in the rest of `src/net/proxy/` (see [The fix](#5-the-fix)).
**Severity:** Critical — a single client connection could drive a worker to
**>20 GB RSS at ~95% CPU**, rendering the host unresponsive (OOM risk).
**Component:** `src/net/proxy/` (transparent root:// proxy / upstream forwarding).
**Trigger surfaced by:** `tests/test_chaos_mixed_auth.py` (the `proxy-sss-bad`
instance — a proxy configured with a deliberately-wrong SSS keytab so the
upstream permanently rejects the forwarded credential).

> **Note on this writeup.** The first investigation mis-identified the loop as a
> per-request re-allocation in the *dispatch* path and added a failure cap there.
> The spin **persisted** — because the loop never reaches dispatch. A GDB
> backtrace of the live worker then revealed the true root cause (below). The
> dispatch cap was kept as defense-in-depth but is **not** what fixed this bug.
> The debugging arc is itself a lesson (§7).

---

## 1. Summary

A transparent proxy whose upstream **permanently** rejects the forwarded
credential spun forever inside the **upstream read handler's `for(;;)` loop**,
re-processing the same buffered rejection frame on a proxy context that had
already been torn down (a use-after-free busy-loop). Each iteration logged,
attempted a client send, and corrupted memory; RSS climbed ~34 MB/s.

> `nginx: worker process` — **95.7% CPU**, RSS **2.6 GB and climbing**, error log:
> `upstream #0 marked DOWN after 76,594,600 failures` (~500K aborts/sec).

The authoritative evidence was a GDB backtrace of the live worker:

```
#3  brix_proxy_up_mark_failed        at src/net/proxy/pool.c:80
#4  brix_proxy_abort                 at src/net/proxy/connect_lifecycle.c:135
#5  brix_proxy_handle_bootstrap      at src/net/proxy/events_bootstrap.c:225
#6  brix_proxy_read_handler          at src/net/proxy/events_read.c:239   <-- for(;;)
#7  ngx_epoll_process_events
```

— the same proxy ctx (`0x1e5a38c0`) re-aborting every iteration, never
re-allocated and never returning to dispatch.

---

## 2. Impact / symptom

- One spinning worker per affected connection: ~100% CPU + linear RSS growth that
  is **monotonic and never freed** — distinct from the legitimate, transient
  memory of heavy cluster/mesh test fixtures (which spike then return).
- Self-sustaining: it kept spinning **after the client disconnected**
  (`send() failed (Broken pipe)` in the log), proving the loop was driven
  entirely server-side, not by client traffic.
- Under the full suite the worker ballooned past 20 GB and made the host
  unresponsive.

---

## 3. Root cause

### The loop

`brix_proxy_read_handler` drives upstream I/O in a `for(;;)` loop that
dispatches on the **upstream-side** state field `proxy->state`:

```c
/* src/net/proxy/events_read.c */
for (;;) {
    /* ... recv upstream header into proxy->rhdr (skipped while rhdr_pos >= 8) ... */

    if (proxy->state == XRD_PX_BOOTSTRAP) {
        brix_proxy_handle_bootstrap(proxy);          /* aborts on auth reject */
        if (proxy->state != XRD_PX_BOOTSTRAP) {
            return;                                     /* bootstrap done (IDLE) */
        }
        continue;                                       /* else: read next frame */
    }
    ...
}
```

For the bad-credential case, `handle_bootstrap` reaches the `XRD_PX_BS_AUTH`
phase, sees the upstream rejected the token, and calls `brix_proxy_abort`.

### The invariant violation

`brix_proxy_abort` tears the proxy down — closes the upstream connection, runs
`brix_proxy_cleanup`, sets **the client ctx** state (`ctx->state =
XRD_ST_REQ_HEADER`), sets `ctx->proxy = NULL`, sends a client error, and resumes
the client read loop. **It never changes `proxy->state`.**

So after `abort` returns into the loop:

- `proxy->state` is *still* `XRD_PX_BOOTSTRAP` → the guard
  `if (proxy->state != XRD_PX_BOOTSTRAP) return;` is **false**;
- the upstream's buffered rejection header is *still* in `proxy->rhdr`
  (`rhdr_pos >= 8`), so the top-of-loop `recv` is skipped;
- `continue` re-enters `handle_bootstrap` on the **torn-down (freed-cleanup)**
  proxy → re-aborts → `continue` → … forever.

~500K iterations/sec. Each one logs `marked DOWN`, attempts `brix_send_error`
(SIGPIPE once the client is gone), and reads/writes through the cleaned-up proxy
— the `brix_queue_response(buffer_len=509001148)` seen in the backtrace is a
**509 MB** length computed from use-after-free garbage. That corruption + the
per-iteration churn is the ~34 MB/s growth.

The deep cause: **two representations of "is this proxy alive" drifted apart on
the error path.** The loop's liveness signal was `proxy->state`; `abort`'s
liveness signal was `ctx->proxy = NULL`. Nothing kept them consistent.

```text
  TWO LIVENESS SIGNALS, DRIFTED ON THE ERROR PATH
  ───────────────────────────────────────────────
   for(;;) {                          abort() signals death via:
     recv ──skip (rhdr already full)      ctx->proxy = NULL   ◀─┐
        │                                 proxy->state UNCHANGED │ (still BOOTSTRAP)
        ▼                                                        │
     state == BOOTSTRAP? ── yes                                  │
        │                                                        │
        ▼                                                        │
     handle_bootstrap() ── auth rejected ── abort() ─────────────┘
        │                                      │ frees/cleanups proxy
        ▼                                      ▼
     state != BOOTSTRAP? ── NO (abort left it stale) ── continue ─┐
        │                                                          │
        └──────────────── re-process SAME frame on DEAD proxy ◀────┘
                          ~500K iters/sec · use-after-free · +34 MB/s · 95% CPU

  THE FIX: the loop checks the SAME signal abort sets
   if (ctx->proxy != proxy) return;   ← proxy is dead, stop. one source of truth.
```

---

## 4. How it came about (likely origin)

1. **The `for(;;)` loop assumed every handler it calls leaves `proxy->state`
   well-defined.** On the *success* path that holds — `handle_bootstrap`
   transitions to `XRD_PX_IDLE`, and the guard `state != BOOTSTRAP` correctly
   ends the loop. The *failure* path (`abort`) was the unconsidered case: it
   signals teardown a different way (`ctx->proxy = NULL`), so the guard never
   sees it.
2. **`abort` legitimately can't set a normal `proxy->state`** — the proxy is
   being destroyed, not transitioned. The loop simply needed to check the same
   teardown signal `abort` actually sets.
3. **The first responder chased memory, not control flow.** RSS-attribution
   heuristics (which test was active when memory crossed a threshold) repeatedly
   mis-blamed `cms_mesh`, compression, and a partial-handshake test — all of
   which reproduced as *bounded* in isolation. The loop was only obvious from a
   stack trace.
4. **The negative test only asserted the per-request outcome.** `proxy-sss-bad`
   checked that the proxy *returns an error* with a wrong keytab — not that the
   worker's CPU/RSS stayed bounded. In a 30-second single-test run the instance
   was torn down before the spin ballooned; only the long, parallel full suite
   turned ~34 MB/s into an OOM.

---

## 5. The fix

### Primary — stop the loop touching a torn-down proxy

`abort` clears `ctx->proxy`, and the read handler already holds `ctx`, so one
guard at the top of the loop catches teardown from **any** aborting handler
(bootstrap, relay, splice, …):

```c
/* src/net/proxy/events_read.c — top of the for(;;) loop */
if (ctx->proxy != proxy) {
    return;     /* a handler called abort(): proxy is dead, do not re-process */
}
```

This is robust because it keys off the *same* signal `abort` sets, rather than
the `proxy->state` field `abort` leaves stale.

### Defense-in-depth (kept; guards a different, theoretical re-dispatch loop)

| File | Change |
|---|---|
| `src/core/types/context.h` | New `ngx_uint_t proxy_fail_count` on `brix_ctx_t`. |
| `src/net/proxy/proxy_internal.h` | `#define BRIX_PROXY_MAX_CONN_FAILS 8`. |
| `src/net/proxy/forward_relay_dispatch.c` | Stop spawning a new proxy once the per-connection budget is exhausted; count sync connect/selection failures. |
| `src/net/proxy/connect_lifecycle.c` | Hard abort increments `proxy_fail_count`. |
| `src/net/proxy/events_bootstrap.c` | A successful bootstrap resets `proxy_fail_count = 0`. |
| `src/net/proxy/connect_upstream.c` | Selection fails fast when **all** upstreams are down instead of falling through to a dead one. |

These bound the *dispatch-level* re-creation path (and avoid hammering a
known-down upstream), but the spinning worker never reached dispatch — the
`events_read.c` guard is the operative fix.

### Verification

| | Before | After |
|---|---|---|
| `test_chaos_mixed_auth.py` | 95.7% CPU, 76.6M failures, **>20 GB**; GDB catches a 195 MB+ spinner instantly | **5/5 pass; no spinner caught; bounded RSS** |
| Proxy regression (`test_proxy_mode`, `test_proxy_protocol_edges`, `test_chaos_mesh`, `test_integrity_matrix`) | — | **129 passed, 16 pre-existing env skips** |

---

## 6. Lessons learned

1. **One authoritative liveness signal.** When an object can be destroyed inside
   a callback, the loop driving callbacks must re-check the *same* signal the
   teardown path sets. Here `abort` set `ctx->proxy = NULL` while the loop
   checked `proxy->state` — two signals, drifted apart, on the error path only.
2. **Get the stack trace first for a CPU spin.** `gdb -p <pid> -batch -ex 'bt 25'`
   on the live worker (binary built with `-g`) named the exact loop in seconds,
   after RSS-attribution heuristics had burned a long time mis-blaming unrelated
   suites. A pegged worker is a control-flow bug; debug it with control-flow
   tools.
3. **A leak fix is not verified by "the test passes."** The same test passed
   `5/5` *before* the fix while a worker burned 500K aborts/sec; the instance was
   just torn down before it ballooned. Verify with the actual signal (no spinner;
   bounded RSS; the failure counter stays small).
4. **Negative/chaos tests should assert resource bounds**, not just error
   returns. Follow-up: have `proxy-sss-bad` assert the worker RSS stays bounded
   and the upstream is marked DOWN only a small number of times.
5. **Beware code paths that "can't change state."** `abort` couldn't set a normal
   `proxy->state`, which is exactly why the state-based loop guard failed — that
   asymmetry is the smell.

---

## 7. Detection methodology (reusable)

Finding this was much harder than fixing it. What worked, for the next "something
balloons during the suite" report:

- **GDB the live spinner — this is the highest-value step.** A memory-capped
  repro that lets the worker spin (without killing the host) plus
  `gdb -p PID -batch -ex 'bt 25'` gives the exact loop. Everything below is for
  *getting* a live spinner safely; once you have one, trace it.
- **Reproduce under a memory cap, never bare.**
  `systemd-run --user --scope -p MemoryMax=20G -p MemorySwapMax=0 <cmd>` so a
  balloon kills only the offender (cgroup v2 + user manager required).
- **Per-process forensics, not aggregate RSS.** Snapshot the single nginx process
  over a threshold and dump its `-c` config, CPU%, and error-log tail — that
  named `proxy-sss-bad` immediately. Aggregate nginx RSS is confounded by tests
  that spin up their own instances.
- **Trailing-minimum vs instantaneous RSS.** Heavy fixtures step RSS up then back
  down; a leak ratchets the floor. Watching instantaneous RSS produced repeated
  false attributions.
- **Idle-fleet baseline + zero leftovers.** A freshly started fleet with no tests
  was flat (~1.2 GB), proving the leak was traffic-triggered; earlier "monotonic
  climb from the start" was contamination from orphaned spinners left by prior
  killed runs. Always confirm zero leftover `nginx` and no orphaned
  `systemd --user run-*.scope` units before a clean measurement.

## 8. Operational gotchas hit along the way

- **Do not `rm -rf objs/addon` to force a rebuild.** nginx's generated Makefile
  does not recreate output subdirectories (only `./configure` does); the next
  build fails with `can't create …/x.o: No such file or directory`. For a full
  addon rebuild after a struct-layout change, `touch` the sources or recreate the
  dirs: `grep -oE 'objs/addon/[^:]*\.o' objs/Makefile | xargs -n1 dirname |
  sort -u | xargs mkdir -p`. (Struct-layout changes require a full rebuild — see
  the mixed-ABI stale-object hazard in the dev-workflow notes.)
- **`systemd-run --scope` as a backgrounded task is unreliable for long runs** —
  the scope can die and the child reparents to the root cgroup (uncapped), or
  orphaned scopes keep sampler loops and daemonized `nginx` alive and resist
  `pkill`. Stop them with `systemctl --user stop run-*.scope`.

---

*Related:* `tests/test_chaos_mixed_auth.py` (the negative-auth chaos suite that
exposed this) and the SSS proxy-upstream auth work it accompanies.
