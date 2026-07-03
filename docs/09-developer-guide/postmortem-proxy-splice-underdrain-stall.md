# Postmortem: proxy splice under-drain stall (flaky mesh topologies)

**Date:** 2026-06-27 · **Area:** `brix_proxy` data forwarding (`src/net/proxy/events_splice.c`)
**Symptom:** `test_conformance_topologies` flaky — `proxy`/`mesh` intermittently FAIL,
`cluster`/`mirror` PASS · **Status:** fixed (self-healing splice→buffered fallback)
**Related:** [postmortem-proxy-retry-leak.md](postmortem-proxy-retry-leak.md),
[postmortem-shmtx-semaphore-stall.md](postmortem-shmtx-semaphore-stall.md),
[lifecycle-startup-shutdown-performance.md](lifecycle-startup-shutdown-performance.md)

A large read forwarded through `brix_proxy` could hang for 60 s and time the client
out. It was intermittent, so it surfaced as flaky topology tests rather than an
obvious bug. This is the debugging story and what it teaches.

---

## 1. Symptom and the first wrong turn

`test_conformance_topologies` runs the full conformance suite through four storage
fronts: `proxy`, `mesh`, `cluster`, `mirror`. It failed non-deterministically — a
different subset each run, and re-running a single case in isolation often passed.

The first-glance error was `XrdClWorkerError: XrdCl worker died during op file_new` —
the **client-side** out-of-process pyxrootd worker dying. That is a known-flaky test
harness component, and it was tempting to write the whole thing off as
"infrastructure." Two things stopped that:

1. **The failing set changed between runs** — non-determinism is evidence, not noise.
2. **An orphan-process red herring.** Clearing ~8 stale `nginx` workers left by a
   previous session's `evil3` adversarial test (masters dead, workers reparented to
   `init`, still holding ports) made an isolated case pass. That *looked* like "it
   was just resource pressure" — but it only masked the real bug by changing timing.

The lesson that mattered here: **`XrdCl worker died` is a client symptom; go look at
the server.** Capturing the full pytest output (not a `tail` that the teardown
warnings flooded) revealed the actual failure underneath: a specific test,
`test_read_5mb_random_file_md5`, **timing out** in `f.read(size=5MiB)`.

---

## 2. Narrowing to the component

Reading the topology definitions was the decisive step:

- `proxy` = one `brix_proxy` hop; `mesh` = **two stacked `brix_proxy` hops**.
- `cluster` = CMS redirector + a direct read from the data server; `mirror` = direct.

The failing topologies were exactly the ones that **forward data through
`brix_proxy`**. The passing ones read directly. So the bug was in the proxy data
path, not CMS, not the redirect logic — and a 5 MiB read was the trigger.

---

## 3. A deterministic repro beats an intermittent one

The topology suite is heavy (boots a fleet) and flaky. The investigation only moved
once there was a **minimal, deterministic repro**:

```
backend nginx (data server, 5 MiB file)  ←  proxy nginx (brix_proxy)  ←  client
```

- `xrdcp` looped 40× through the proxy: **0/40 hangs**. Dead end — until noticing
  `xrdcp` chunks its reads.
- The official XrdCl client issues **one** `kXR_read` for the whole 5 MiB. Driving
  that via the test's own `_xrdcl_proxy` worker in a loop reproduced it **every
  time**: a read would take **60.1 s** (the client timeout) instead of 0.05 s.

That `xrdcp`-works-but-XrdCl-hangs split was itself the clue: the difference is one
large read vs. many small ones.

---

## 4. Root cause: socket-splice under-drains, and edge-triggered epoll waits forever

Three pieces of evidence pinned it:

1. **`ss` during the stall:** the proxy→backend socket had **`Recv-Q` = 300 KB+
   unread** — the backend had sent the data, the proxy wasn't reading it.
2. **`gdb` on the proxy worker:** parked in `epoll_wait` — *idle*, not spinning, not
   blocked on a lock. So it was waiting for an event that would never come.
3. **Temporary `ngx_log_error` instrumentation** (because `ngx_log_debug` is compiled
   out without `--with-debug`) showed the read handler re-entering with
   `splice=1 dlen=5MiB` and the splice counters **crawling**:
   `splice u->pipe r=130966 ... r=-1 errno=EAGAIN`, moving ~64–128 KB per call.

The proxy has a zero-copy fast path for plaintext reads: `splice(upstream_socket →
pipe → client_socket)`. On this kernel (**WSL2**), `splice()` from a TCP socket
**under-drains** — it moves a small chunk (the pipe stayed at ~64 KB because
`F_SETPIPE_SZ(1MB)` silently doesn't take) and returns `EAGAIN` with data still
queued. The pump assumed `EAGAIN` ⇒ "socket empty, wait for the next read edge." But
the data had *already arrived* — under edge-triggered epoll there is **no new edge**
for data that's already in the buffer. So the transfer crawled along, paced only by
TCP flow-control trickle, and blew past the 60 s client timeout.

The buffered `recv` path doesn't have this problem: `recv()` drains the whole socket
buffer per call, so it finishes a 5 MiB read in a handful of edges. That's why
`xrdcp` (which stayed on the buffered path) and the direct-read topologies were fine.

---

## 5. The fix — and the fix that didn't work

**First attempt (wrong):** on `splice` `EAGAIN`, `recv(..., MSG_PEEK)` to check if data
is really queued; if so, fall back. It failed: during the TCP-paced crawl, each
`EAGAIN` hit a *momentarily* empty socket (between segments), so the peek saw nothing
and it kept waiting — still a 60 s stall, now with a fallback that fired too late.

**Correct fix:** the pump always drains everything currently in the socket *before*
`splice(upstream→pipe)` reports `EAGAIN`. So **`EAGAIN` with body bytes still
outstanding** means either the remainder hasn't fully arrived or the kernel
under-drains — and in both cases the reliable, edge-efficient choice is to relay the
rest via the buffered `recv` path. The remainder is relayed **raw** (the 8-byte
response header is already on the wire) using `brix_queue_response_base`'s
owned-buffer mode. The zero-copy path is still used in full when the whole body was
already buffered (the pump completes via `splice_done` and never reaches the
fallback).

```
splice(upstream → pipe) == EAGAIN
        │
        ├─ splice_downstream  < splice_total  → switch the REMAINDER to buffered recv
        │      (brix_proxy_splice_to_buffered → …_fallback_finish, relay RAW)
        │
        └─ splice_downstream == splice_total  → done (normal splice_done)
```

**Result:** 20/20 and 15/15 ×2 single-5 MiB XrdCl reads complete at 0.04–0.06 s (was
60 s), md5 exact; `test_conformance_topologies` passed 4× back-to-back (6/6 each);
`test_proxy_mode` + `…_protocol_edges` + `…_e2e_proxy_matrix` = 54 passed; new guard
`tests/test_proxy_large_read.py` added.

---

## 6. Lessons

1. **A client-side symptom is not a root cause.** "XrdCl worker died" / a client
   timeout points *somewhere*; the server was the thing actually misbehaving. When a
   multi-process test fails, get evidence from every component, especially the one
   you didn't write.
2. **Non-determinism is a signal.** "It passes when I re-run it" is data about timing
   and shared state, not permission to ignore it. Here it meant a race/throughput
   bug, not a logic bug.
3. **Beware the red herring that "fixes" the symptom.** Clearing orphan processes
   made a run pass — by changing timing, not by fixing anything. Verify you changed
   the cause, not the weather.
4. **Build a deterministic repro before theorizing.** The intermittent fleet test was
   unworkable; a 30-line `proxy → backend` loop that hung *every time* turned a
   multi-hour guessing game into a measurement.
5. **The tool difference is the clue.** `xrdcp` worked, XrdCl didn't — the delta
   (one big read vs. chunked) pointed straight at the large-read path.
6. **`gdb` + `ss` answer "stuck where?" precisely.** `wchan`/backtrace = idle in
   `epoll_wait` (waiting on an event that won't come) vs. a futex (blocked on a lock);
   `Recv-Q > 0` = the read side isn't draining. Those two facts located the bug
   before any code was read. See the debug table in
   [CLAUDE.md](../../CLAUDE.md).
7. **`ngx_log_debug` is compiled out without `--with-debug`.** For one-off event
   tracing in a release build, temporary `ngx_log_error(NGX_LOG_NOTICE, …)` is the
   fastest path — just remove it after.
8. **Edge-triggered epoll + `splice()` is a sharp edge.** Any handler that returns
   while readable data remains, assuming a fresh edge will wake it, can stall
   forever. The same class of bug recurs in this codebase (bootstrap path, oksofar
   re-post); when in doubt, drain to `EAGAIN` or post the event explicitly.
9. **A zero-copy optimization must degrade, not stall.** `splice()` from a socket is
   not uniformly supported (WSL2 under-drains). The right design keeps the
   optimization for the case it serves and falls back to the always-correct path the
   moment it can't keep up — reliability over cleverness.

---

## 7. File map

| File | Change |
|---|---|
| `src/net/proxy/events_splice.c` | `splice(upstream→pipe)` `EAGAIN`-with-remainder → fall back; `brix_proxy_splice_to_buffered()` + `brix_proxy_splice_fallback_finish()` |
| `src/net/proxy/events_read.c` | read handler dispatches to the fallback finish when `splice_fallback` is set |
| `src/net/proxy/proxy_internal.h` | `splice_fallback` ctx field + fallback-finish declaration |
| `src/net/proxy/README.md` | documents the self-healing fallback |
| `tests/test_proxy_large_read.py` | self-contained regression: 20 large XrdCl reads through a proxy must each finish fast |
