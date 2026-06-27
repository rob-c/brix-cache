# Postmortem: Multi-Worker Connection Stall (ngx_shmtx POSIX-semaphore lost-wakeup)

**Status:** Resolved. Single fix in `src/compat/shm_slots.c` — create every module
SHM-table mutex in **spin+yield-only** mode (POSIX semaphore disabled).
**Severity:** High — under concurrent `root://` load on a multi-worker server, a
random subset of connections stalled **60–450 s** (until the client gave up),
collapsing aggregate read throughput (n=8 read ≈ 5700 → ≈ 26 MiB/s).
**Component:** `src/session/handles.c` / `src/compat/shm_slots.c` (cross-worker
shared-memory handle table, locked on every `kXR_open`).
**Trigger surfaced by:** a read/write load benchmark — 8 concurrent `xrdcp` of a
1 GiB file against a `worker_processes auto` (or any ≥ 2) nginx.

> **Note on this writeup.** The first several hypotheses were wrong, and the
> reverted attempts are documented in §6 on purpose. The bug masqueraded as a
> lost edge-triggered-epoll *read* event for hours; the authoritative evidence
> was a GDB backtrace of the stalled worker plus a read of the lock's shared
> state. The debugging arc is the real lesson (§7).

---

## 1. Summary

Under concurrent `kXR_open` load across multiple nginx workers, a worker would
**block forever inside `ngx_shmtx_lock(&xrootd_handle_mutex)`** while publishing a
file handle to the cross-worker shared-handle table — *even though the lock was
free*. The blocked worker stops running its event loop entirely, so **every**
connection pinned to it (via `reuseport`) stalls: their buffered requests sit
unread in the socket (`Recv-Q > 0`), their read events never fire, and their
timers never expire. The client eventually times out (~60 s) and retries on a
fresh connection, which is why transfers eventually completed with a huge tail
latency rather than failing outright.

The authoritative evidence was a GDB backtrace of the stalled worker:

```
#0  __futex_abstimed_wait_common
#2  ngx_shmtx_lock (mtx=&xrootd_handle_mutex)        src/core/ngx_shmtx.c:111
#3  xrootd_session_handle_publish                    src/session/handles.c:106
#4  xrootd_open_resolved_file                        src/read/open_resolved_file.c:459
#5  xrootd_handle_open                               src/read/open_request.c:641
#6  xrootd_dispatch_read_opcode  ←  kXR_open
```

…combined with a read of the lock's shared state, which was the smoking gun:

```
(gdb) print *(int*)xrootd_handle_mutex.lock   →  0     # lock is FREE (no holder)
(gdb) print *(int*)xrootd_handle_mutex.wait   →  0     # no waiters counted
        # …yet the main thread is parked in sem_wait() forever.
```

A lock that is **free**, a wait-count of **zero**, and a thread nonetheless
blocked in `sem_wait()` is the signature of a **lost semaphore wakeup**.

The blast radius — why one stuck worker freezes *many* unrelated transfers:

```text
   reuseport pins each connection to one worker for its whole life
   ───────────────────────────────────────────────────────────────
                     ┌──────────── worker 3 (FROZEN in sem_wait) ──┐
   conn A ──pinned──▶│  event loop NOT running                    │
   conn B ──pinned──▶│  · read events never fire (Recv-Q > 0)     │  ✗ all stall
   conn C ──pinned──▶│  · armed timers never expire               │   60–450 s
   conn D ──pinned──▶│  · ~0% CPU, futex_do_wait, not crashed     │
                     └────────────────────────────────────────────┘
   conn E ──pinned──▶  worker 4 (healthy) ── fine ────────────────▶ ✓ ok

   recovery ONLY when the client times out (~60s) and reconnects → new worker
```



---

## 2. Impact / symptom

- **Probabilistic** (≈ 50–75 % of connections under 8-way concurrency on this
  host), and **multi-worker only** — a single-worker nginx was 100 % immune,
  even though it handled *more* connections per worker. That asymmetry is the
  fingerprint of cross-worker shared-state contention, not per-connection logic.
- A stalled connection's server socket showed **`Recv-Q = 44–45`, `Send-Q = 0`**:
  the client's next request was buffered but never read — a read-side stall, not
  a slow/blocked *write*.
- The owning worker was at near-zero CPU in `futex_do_wait` — **idle-blocked**,
  not spinning and not crashed (no `SIGSEGV`/`SIGABRT`, no respawns in the log).
- Recovery only ever came from the **client** giving up and reconnecting, leaving
  the original socket in `CLOSE-WAIT`.

Net effect on the benchmark: single-stream throughput was fine, but n=8
concurrent reads collapsed from ~5.7 GiB/s aggregate to a few MiB/s because most
streams were parked behind a frozen worker.

---

## 3. Root cause

### The mechanism

`xrootd_handle_mutex` is an `ngx_shmtx` created (via `xrootd_shm_table_alloc()`)
with `ngx_shmtx_create()`, which — whenever `NGX_HAVE_POSIX_SEM` is defined —
unconditionally initialises and enables a **POSIX semaphore** for the blocking
path (`mtx->semaphore = 1`, `spin = 2048`). On contention, `ngx_shmtx_lock()`
spins `spin` times and then, instead of yielding, does:

```c
ngx_atomic_fetch_add(mtx->wait, 1);   /* announce intent to block      */
if (lock just became free) { fetch_add(mtx->wait, -1); return; }  /* fast path */
sem_wait(&mtx->sem);                   /* BLOCK                          */
ngx_atomic_fetch_add(mtx->wait, -1);
```

and `ngx_shmtx_unlock()` wakes a waiter only when `*wait > 0`:

```c
ngx_shmtx_wakeup: if (*wait <= 0) return; CAS(wait, wait-1); sem_post(&sem);
```

Under heavy, bursty contention (8 workers all doing `kXR_open` at once) the
`wait` counter, the semaphore count, and the lock atomic can desynchronise across
the increment → fast-path-acquire → `sem_post` → `sem_wait` interleavings. The
result we observed: a worker ends up parked in `sem_wait()` with the lock already
released (`lock == 0`) and `wait == 0`, so **no subsequent `unlock` will ever
post the semaphore** (wakeup only posts when `wait > 0`). The worker is stuck
until — by luck — another waiter arrives, bumps `wait`, and a later unlock posts.
Once the open-burst subsides, no new waiter comes, and the worker stays frozen.

This is a known fragility of `ngx_shmtx`'s optional semaphore mode; it is also
aggravated by the host kernel's futex/semaphore behaviour (it reproduced readily
on WSL2). It does not depend on anything XRootD-specific beyond the fact that we
take this SHM lock **on the hot `kXR_open` path from every worker**.

### Why single-worker was immune

With one worker there is never contention on the process-shared mutex: the fast
path (`CAS(lock, 0, pid)`) always succeeds and the semaphore path is never
entered, so the lost-wakeup race cannot occur.

---

## 4. How it came about (likely origin)

The shared-handle table exists for `kXR_bind` parallel streams: a primary
connection *publishes* a file handle's metadata so a secondary stream on another
worker can re-open and validate the same file. Publishing happens on **every**
`kXR_open`, even when the client never uses bind (the common `xrdcp` case). The
mutex was created with the stock `ngx_shmtx_create(…, NULL)`, which silently opts
into the semaphore blocking path. Nothing about the call site signals that the
critical section is a microsecond fixed-slot table scan for which blocking on a
semaphore is both unnecessary and hazardous.

---

## 5. The fix

`src/compat/shm_slots.c` — wrap mutex creation so the semaphore is disabled,
leaving `ngx_shmtx` in **spin-then-`ngx_sched_yield`** mode:

```c
static ngx_int_t
xrootd_shm_table_mutex_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr)
{
    if (ngx_shmtx_create(mtx, addr, NULL) != NGX_OK) {
        return NGX_ERROR;
    }
#if (NGX_HAVE_POSIX_SEM)
    mtx->semaphore = 0;   /* spin+yield only — immune to the lost wakeup */
#endif
    return NGX_OK;
}
```

All three `ngx_shmtx_create()` call sites inside `xrootd_shm_table_alloc()` now
route through this helper, so the change covers **every** module SHM-table mutex
created by that allocator (the bind handle table, the session registry, and the
FRM-converted zones — see `src/compat/shm_slots.c` / `shm_slots.h`, whose
slab-safe allocation also exists to survive `ngx_unlock_mutexes()` on child death).

Why spin+yield is the right call here: these critical sections are tiny,
fixed-slot table scans held for microseconds. Spinning a bounded number of times
and then calling `sched_yield()` to let the holder run is correct, cheaper than a
`sem_wait`/`sem_post` syscall pair, and — crucially — has **no wakeup to lose**.

### Verification

- **104+ transfers** across 2-worker and 20-worker configurations: **0 stalls**
  (previously 50–75 % of connections stalled 60–450 s). Worst-case per-transfer
  latency for 8 concurrent 1 GiB reads dropped to **1–2 s**.
- Benchmark (`tests/run_load_test.sh`, isolated under `/tmp/xrd-load`), all runs
  100 % OK:

  | Workload          | n=1 nginx / xrootd | n=8 nginx / xrootd |
  |-------------------|--------------------|--------------------|
  | anon read         | 2030 / 2051        | **5683 / 4803**    |
  | anon write        | 1142 / 1050        | 1395 / 1478        |
  | GSI read          | 1866 / 1678        | **4737 / 4490**    |
  | GSI write         | 957 / 1002         | 1751 / 2016        |

  (MiB/s aggregate.) The n=8 read column is the one that used to collapse; it now
  leads the official server.

---

## 6. False alarms (what did NOT fix it, and why)

Each of these was implemented, tested, and **reverted** when it failed. They are
recorded so the next investigator does not repeat them.

1. **"nginx writes are ~30 % slower — find the write bug."** The original
   suspicion. Writes were actually within ~6–13 % either direction; the real
   defect was entirely in the *read-concurrency* path. Chasing the framing of the
   question wasted the first pass.

2. **`ngx_shmtx`-free L1 / "stale-`available`" recv fix.** Early theory: the recv
   loop's `c->recv()` short-circuited on a stale `rev->available == 0`. Ruled out
   — the loop already forces `rev->available = -1` before every `recv()`.

3. **Stale `rev->posted` skipping the read-resume post.** Instrumented
   `xrootd_schedule_read_resume`; `SKIP-POST` count was **0**. The post was never
   skipped.

4. **Lost edge-triggered-epoll read edge (the big one).** For hours this looked
   like a dropped `EPOLLIN` edge: data buffered (`Recv-Q > 0`), the read event
   armed (`active = 1`, `EPOLLIN|EPOLLET` confirmed in `ngx_epoll_*`), worker idle
   in `epoll_wait`. We even verified the combined read/write epoll registration
   preserves `EPOLLIN`. **Reverted fix:** a bounded "recovery poll" via
   `ngx_posted_next_events`, then a timer-based recovery (re-purposing the Phase-39
   read-deadline timer to re-check for buffered data). It **did not work** — and
   the reason it didn't work was the clue that cracked the case: a correctly-armed
   50 ms timer **never fired** (`arm-timer` logged, `tmo-fire` = 0). An nginx timer
   that doesn't fire while the worker is alive means **the worker is not running
   its event loop at all** — i.e. blocked in a syscall, not idle. That redirected
   us from "lost wakeup in epoll" to "the worker is stuck", and the GDB backtrace
   immediately showed the futex/`sem_wait`.

5. **WSL2 kernel epoll bug.** A tempting conclusion given the lost edge *and* the
   non-firing timer, and the multi-worker-only reproduction. It was wrong: the
   module follows nginx's event contract correctly. The kernel's semaphore
   behaviour *aggravates* the `ngx_shmtx` race but is not the root cause — the
   spin-only fix resolves it regardless of kernel.

6. **Mixed-ABI / build-staleness self-inflicted noise.** Adding a field to
   `xrootd_ctx_t` and rebuilding without touching the dependent `.c` files left a
   stale object whose missing log string briefly "proved" a function wasn't
   running. The addon Makefile does not track header dependencies — see §8.

---

## 7. Detection methodology (reusable)

The decision tree that finally worked, in order:

```text
  connection stalls under concurrency
            │
   ① ss -tn 'sport = :PORT'
            │
     Recv-Q > 0 ?  ──no(Send-Q>0)──▶ write-side stall (different bug)
            │ yes → read-side
            ▼
   ② /proc/PID/wchan + %cpu
            │
     do_epoll_wait,low cpu ──▶ genuinely idle → suspect lost notification
     futex_do_wait         ──▶ BLOCKED on a lock/condvar  ┐
            │                                             │
            ▼                                             │
   ③ arm a 50ms nginx timer — does it fire? ──no──────────┤ worker not looping
            │ (never fires while alive)                   │
            ▼                                             ▼
   ④ gdb -p PID -batch -ex "thread apply all bt"   ──▶ names lock + call path
            │                                            (ngx_shmtx_lock ← kXR_open)
            ▼
   ⑤ print *(int*)MUTEX.lock  /  *(int*)MUTEX.wait
            │
     lock==0 && wait==0 && thread in sem_wait  ──▶ LOST SEMAPHORE WAKEUP ∎
```

1. **Confirm the side.** `ss -tn 'sport = :<port>'` during a stall. `Recv-Q > 0,
   Send-Q = 0` ⇒ the server is not *reading* (read-side); `Send-Q > 0` ⇒ not
   *writing*. Ours was unambiguously read-side.
2. **Confirm liveness vs. blockage.** Per-worker `%cpu` + `/proc/<pid>/wchan`.
   `do_epoll_wait` at low CPU = genuinely idle (suspect lost notification);
   `futex_do_wait` = **blocked on a lock/condvar** (suspect a stuck mutex). This
   single distinction is what separates "lost epoll edge" from "stuck worker".
3. **The timer test.** If a correctly-armed nginx timer never fires while the
   process is alive, the event loop is not running — the worker is blocked. Don't
   keep theorising about epoll; go to GDB.
4. **GDB the blocked worker.** `gdb -p <worker> -batch -ex "thread apply all bt"`.
   The main-thread frame named the lock and the call path
   (`ngx_shmtx_lock` ← `kXR_open`).
5. **Read the lock's shared state.** `print *(int*)<mutex>.lock` (holder PID) and
   `print *(int*)<mutex>.wait`. `lock == 0` + `wait == 0` + a thread in
   `sem_wait` = lost semaphore wakeup, full stop.
6. **Map worker → connection** (when needed): match the stalled socket's inode
   (`ss -tne`, `ino:NNN`) against `/proc/<pid>/fd` to find which worker owns it.

Reproduction notes: the bug is probabilistic, so loop the 8-concurrent test until
a stall is caught, and capture state **while frozen** (the window is the client
timeout, ~60 s — ample for `ss`/GDB).

---

## 8. Operational gotchas hit along the way

- **The addon Makefile does not track header dependencies.** Editing a header
  (`deadline.h`, `tunables.h`, or an `ngx_inline` in any `.h`) and running `make`
  will **not** recompile the `.c` files that include it. Always
  `find src -name '*.c' -exec touch {} +` before `make` after a header edit. A
  stale object once produced a misleading "this code path isn't running".
- **Struct-field appends are ABI-safe but still need a touch-all rebuild.** Adding
  a field at the **end** of `xrootd_ctx_t` does not shift existing offsets, but an
  incremental build still risks mixing old/new `sizeof`; rebuild everything.
- **`pkill` is sandbox-blocked** in the agent harness; killing test servers needs
  the dangerous-bash escape. Worse, a `pkill -9` of a worker *while it holds an
  SHM mutex* can itself strand that lock for the lifetime of the SHM segment —
  don't `-9` workers mid-test and then puzzle over a stuck lock.
- **Orphaned workers re-parent to init and keep the listen socket.** After a hard
  kill, verify with `pgrep -x nginx` (exact name) — `pgrep -f nginx` matches your
  own shell commands and lies.

---

## 9. Conclusion

A high-severity, intermittent, multi-worker-only stall that *looked* like a lost
edge-triggered epoll notification (and even like a kernel bug) was, in fact, a
**lost POSIX-semaphore wakeup inside `ngx_shmtx`** on a hot-path cross-worker
mutex (`xrootd_handle_mutex`, taken on every `kXR_open`). The fix is one line of
intent — disable the semaphore and use spin+yield — applied uniformly to all
module SHM-table mutexes via their shared allocator. The decisive tools were
`ss` (read-side vs. write-side), `/proc/<pid>/wchan` (idle vs. blocked), the
"non-firing timer ⇒ worker not looping" inference, and a GDB read of the mutex's
shared `lock`/`wait` words.

**Rule of thumb going forward:** prefer spin+yield `ngx_shmtx` for any
short, hot-path module SHM critical section; reserve the semaphore mode for locks
that are genuinely held long enough that blocking is worth a syscall — and even
then, treat its wakeup path as suspect under high contention.
