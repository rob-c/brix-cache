# Adversarial Hardening Tests (evil-actor suite)

> **Audience:** Maintainers and security reviewers of the nginx-xrootd stream/HTTP data planes.
> **Prerequisites:** Familiarity with the XRootD `root://` wire protocol (24-byte request header, `kXR_*` opcodes, `kXR_status` framing), the nginx stream event loop + thread pool model, and the project's confinement/AIO invariants in [`CLAUDE.md`](../../CLAUDE.md).
> **Time:** ~20 min read; full ASAN run ~10-15 min wall.

## Overview

The `evil-actor` suite is a worker-crash and data-race hunt against the live server, not a functional or input-fuzz conformance suite. It exists to catch a single failure mode that ordinary tests structurally cannot see: **a worker process that takes a fatal signal (SIGSEGV/SIGABRT) on a hostile request and is silently respawned by the nginx master.** A naive health check — "does a fresh login+ping still succeed?" — passes immediately after such a crash, because the master has already forked a replacement worker. The bug is invisible to liveness probes and to the existing fuzz fleet, which only assert that the session keeps answering.

Two suites implement the hunt:

| Suite | File(s) | Plane | Race model |
|---|---|---|---|
| v1 | `tests/test_evil_actor.py` | `root://` stream | Probabilistic (timing jitter + hard RST) |
| v2 | `tests/test_evil_actor_v2.py` + `tests/race_shim.c` | `root://` stream + WebDAV/S3/metrics HTTP | **Deterministic** (worker-gated syscall slowing via `LD_PRELOAD` shim) |

Both stand up their own nginx with a real `master_process on` + multiple workers + a multi-thread `aiopool`, plant deterministic test files (a large cold file seeded `chunk[i] = (i*31+7) & 0xFF`, plus a small writable scratch), and fire byte-accurate hostile wire frames and concurrency races. The shared raw-wire attack library is a hand-rolled XRootD client (`_connect`/`_login` → 20-byte handshake then `kXR_login`; `_frame(opcode, body16, payload, dlen)` that can deliberately lie about `dlen`; `_open*` to mint real 4-byte file handles; `_read_response` that understands `kXR_status` 24-byte framing; `_rst_close` with `SO_LINGER 0` to force a hard TCP RST).

### Why a four-pronged crash detector

After every phase the harness (`_Srv.assert_healthy`) runs all four checks. Any one failing fails the phase:

| Check | What it catches | Mechanism |
|---|---|---|
| Error-log delta scan | A worker that crashed and was respawned | Diffs `error.log` since a per-phase mark for `CRASH_PATTERNS`: `signal 11/6/4/7/8`, `SIGSEGV`/`SIGABRT`, `core dumped`, `segfault`, and the full sanitizer vocabulary (`AddressSanitizer`, `heap-use-after-free`, `heap/stack-buffer-overflow`, `attempting double-free`, `runtime error:`, `LeakSanitizer`) |
| `os.kill(master, 0)` | Master death | Master must still be alive |
| `pgrep -P master` | Silent worker respawn / pgrep-churn | At least one worker must still exist; combined with the log scan, a faulted-then-respawned worker is caught even though the live worker count looks healthy |
| `_ping_ok` | A wedged but un-crashed server | A fresh login+ping must round-trip |

The v2 harness adds a fifth prong: it scans the TSan log directory but fails **only** on data races whose stack frames name module/AIO code (`src/aio|read|write|cache|session|connection`, `_aio_thread`, `read_scratch`, `payload_to_free`, `ctx->destroyed`, `xrootd_*`), so suppressed benign atomic races in nginx core do not fail the run.

The suites are strongest under an ASAN nginx (`TEST_NGINX_BIN`): a sometimes-faulting use-after-free becomes a deterministic abort with a heap-use-after-free report, converting a flaky 1-in-10000 race into a reproducible failure.

## Threat model and methodology

The attacker speaks raw XRootD bytes to an open port. They can:

- Send arbitrary frames with attacker-chosen opcodes, handle bytes, offsets, lengths, segment counts, CRCs, and a `dlen` that lies about the real payload size.
- Open real handles on one session and replay them on another session that does not own them.
- Open a second TCP connection and `kXR_bind` it to a captured 16-byte session id (the parallel-data-channel feature).
- Disconnect at any instant — including mid-transfer — with a hard TCP RST.
- Drive multiple protocols (`root://`, WebDAV, S3) at the same shared file, and swap that file's inode underneath all of them.

The attacker's goal is to reach memory corruption: an out-of-bounds read/write off the file-handle table, an integer-overflow under-allocation, a use-after-free where a thread-pool worker writes into buffers the event loop already freed, an inode-swap TOCTOU, or a session-hijack via a forged session id. The defender's contract is that **every one of these terminates in a clean wire error or a clean connection close — never a worker fault.**

The methodology is byte-accurate raw framing (no client library to sanitize input), replayed across many fresh sessions and many connections to widen race windows, with the four-pronged detector after each phase. v2 additionally makes the worker-thread-vs-event-loop window deterministic with `race_shim.c`.

## The race_shim mechanism (deterministic worker-gated syscall slowing)

`tests/race_shim.c` is an `LD_PRELOAD` shim that interposes the blocking file-I/O syscalls the nginx-xrootd thread pool runs on its **worker** threads — `pread`, `pwrite`, `preadv`, `pwritev`, `read`, `write` — and injects a tunable `nanosleep` (`XRD_RACE_DELAY_US`, default 15000us) around the real syscall (before by default; after if `XRD_RACE_AFTER=1`). The delay turns a microsecond-wide race into a per-iteration hit.

### Why it only delays workers, never the event loop

A `__attribute__((constructor))` (`race_shim.c:47-56`, `race_init`) runs at load time and captures `pthread_self()` into `g_main`. Because nginx forks its workers **without `exec`**, that main-thread id is inherited verbatim into every worker process — so inside any worker, `pthread_self() == g_main` identifies the event-loop thread. The thread-pool threads are spawned later (during `ngx_thread_pool` `init_process`) and therefore are **not** `g_main`. `race_on_worker()` (`race_shim.c:60-63`) returns true only on those pool threads and only when a delay is set, so the event loop is never slowed. This is the proof that the shim cannot mask the bug it hunts: if it delayed the event loop, it would serialize the very thing whose concurrency it is trying to expose.

Each wrapper chains to the real function via `dlsym(RTLD_NEXT, ...)` — under a sanitizer build this reaches the sanitizer's own interceptor first. The delay itself is taken via `nanosleep` directly (`race_delay`, `race_shim.c:67-74`), so an intercepted `usleep` cannot recurse and worker signal masking is irrelevant.

### What the shim makes deterministic

```text
  WIDENING THE USE-AFTER-FREE WINDOW (race_shim makes µs deterministic)
  ────────────────────────────────────────────────────────────────────
  EVENT LOOP thread        │  POOL WORKER thread (g_main? NO → delayed)
  ─────────────────        │  ─────────────────────────────────────────
  dispatch kXR_read        │
   post task to pool ─────▶│  pread(fd, scratch, …)
                           │   └─ shim injects nanosleep(15ms) ──┐
  ◀── loop races ahead ────┤                                     │  worker
   client RST / close      │                                     │  HELD here
   FREE scratch buffer ✗   │                                     │  (window
   unlink+recreate file    │                                     │   forced
   reuse scratch (pipeline) │                                    │   open)
                           │   real pread writes into scratch ◀──┘
                           │   ✗ HEAP-USE-AFTER-FREE (ASan aborts)
  ────────────────────────────────────────────────────────────────────
  shim NEVER delays the event loop (pthread_self()==g_main) → can't mask the bug
```

With a worker held inside `pread`/`pwrite` on a connection's scratch/payload/published-handle buffer, the event loop races ahead and can: (a) RST-disconnect and free those buffers; (b) on a peer connection, `close` + `unlink` + recreate a shared file; (c) pipeline a follow-up op that reuses the same scratch. The shim turns each into a per-iteration hit that ASan (heap-use-after-free) and TSan (missing happens-before) catch reliably.

## v1 phases (test_evil_actor.py) — stream plane

### Phase A — Hostile-frame barrage

`FUZZ_REPEAT` passes over a ~40-frame library, each frame sent on a fresh session that does **not** own the embedded handles (handles are minted on a throwaway session, then replayed elsewhere so even "valid" handles are not-open there). A clean rejection or a clean close both count as a valid defense; only a worker crash fails the phase.

| Attack (concrete bytes/sequence) | Exploit hypothesis | Defense | Location |
|---|---|---|---|
| `fhandle[0]` ∈ {15,16,17,64,200,255} on read/pgread/close/stat/truncate/write/pgwrite | OOB index past the 16-slot `files[]` table | `idx = (int)(unsigned char)fhandle[0]` cast blocks sign-extension; validators reject `idx<0 || idx>=XROOTD_MAX_FILES(16)` and `fd<0` → `kXR_FileNotOpen` | `src/read/read.c:101`; `src/connection/fd_table.c:347-352`, `:361-389` |
| read `off=-1`, `off=0x7FFFFFFFFFFFFFFF`, `rlen=0x7FFFFFFF` | Negative/overflow offset into `pread`/`sendfile` | `if (offset < 0)` → `kXR_IOError "negative read offset"`; `rlen` capped at `XROOTD_READ_REQUEST_MAX` | `src/read/read.c:121-125` |
| pgread unaligned `off=1 rlen=4097`, `off=-7` | Page-math overflow / negative offset | Handle validated, negative offset → `kXR_IOError`; page boundaries re-derived from file offset | `src/read/pgread.c:115-140` |
| readv `dlen=17` (not mult 16), zero-length, 1025 segs, OOB-handle seg, per-seg `rlen=0x7FFFFFFF`, neg offset | OOB read of payload buffer; segment-count overflow | `dlen%16==0` and `1..MAXSEGS(1024)`; overflow-checked `xrootd_size_mul`; per-seg negative-offset and `offset+len` overflow rejected | `src/read/readv.c:211-228`, `:86-93`, `:107-121` |
| pgwrite CRC `0xDEADBEEF`, `dlen=4`, unaligned `off=4095` + 10-byte body | Bad-CRC write; short-payload over-read | Reject `payload_len <= CKSZ`; per-page CRC32c verify → `NGX_DECLINED`; `INT64_MAX` offset-overflow guard | `src/write/pgwrite.c:115-117`, `:148-156` |
| writev declared `wlen 0x7FFFFFFF` but short payload | OOB read when declared wlen ≠ real payload | Recover N by scanning until `n*16+Σwlen==dlen`; reject overshoot/undershoot before reading data → `kXR_ArgInvalid` | `src/write/writev.c:79-104` |
| clone neg / 2^63 offsets | OOB / overflow in copy | Validate dst+payload-presence+length-divisibility+item-count; bad offsets fail `copy_file_range`/`pread` as `EINVAL` | `src/read/clone.c:50-74` |
| fattr `numattr=255`, `subcode=99`, truncated nvec | CPU/memory blowup; over-read into fixed `attrs[16]` | `subcode<=kXR_fattrMaxSC`; `numattr` ∈ `1..kXR_faMaxVars(16)` (list must be 0); `fattr_parse_nvec` stops at buffer end → `-1` → `kXR_ArgInvalid` | `src/fattr/dispatch.c:48-62`; `src/fattr/helpers.c:73-103` |
| query bad subcode 999 + `/../`×64 path | Mis-dispatch on unknown infotype | Unknown infotype → `kXR_Unsupported` | `src/query/dispatch.c:80-84` |
| open `/../`×80`etc/passwd`, `/big\x00.bin`, 9000-char path | Path traversal; embedded-NUL truncation | `xrootd_extract_path` rejects `>MAX_PATH`, embedded-NUL-not-at-end; `openat2(RESOLVE_BENEATH\|RESOLVE_NO_MAGICLINKS)` makes `..`/symlink escape a kernel `EXDEV` → `kXR_NotAuthorized` | `src/path/extract.c:19-55`; `src/path/beneath.c:73-93` |
| lying `dlen` — read `0x40000000`, write `0x7FFFFFFF`, stat `0x10000000` | Huge-allocation DoS / integer overflow | Per-opcode cap via `xrootd_max_payload_for_request` checked **before** any allocation; over-cap closes the connection; `dlen+1` overflow guard | `src/connection/recv.c:21-46`, `:360-368`, `:62-65` |
| login NUL/non-printable username | NUL-truncation impersonation (`a\x00evil` → user `a`) | Reject any byte `< 0x20 \|\| > 0x7e` → `kXR_ArgInvalid` | `src/session/login.c:85-92` |
| reserved/unknown opcodes 2999/3005/3099/4099/65535/0 | Unknown-opcode mis-dispatch | Unknown opcode → `kXR_Unsupported` | `src/path/beneath.c` funnel + dispatcher |

### Phase B — Disconnect-mid-AIO use-after-free torture (headline finding)

`AIO_THREADS(8)` Python threads, up to `AIO_ROUNDS(600)` rounds over 90s. Each round opens `/big.bin`, issues one large thread-pool-offloaded op (random `kXR_pgread`/`kXR_read`/16-segment `kXR_readv`/1MiB `kXR_write`) at a random offset with `rlen ∈ {8,24,48}MiB`, waits a jittered delay in `{0,0,0.0005,0.002,0.008}s` chosen to land inside the post-dispatch → worker-thread `pread`/`pwrite`/CRC window, then slams the socket with a hard RST.

**Exploit hypothesis:** the RST drives the disconnect path to free `read_scratch`/`write_scratch`/`payload_buf` while a pool worker is still `pread`/`pwrite`-ing into exactly those buffers; or the done-callback fires on a torn-down ctx and writes a response into freed memory.

**Why this is NOT a use-after-free.** The defense is structural, not best-effort:

1. **Worker halves touch only the task struct.** `xrootd_read_aio_thread` (and the pgread/readv/write worker halves) snapshot `fd`/`offset`/`len`/`databuf` into the task and never dereference `ctx`/`c`/`pool`. The contract is documented at `src/aio/reads.c:228-241` and the write worker at `src/aio/write.c:11-25`.
2. **Completion is serialized onto the event loop.** The done callback is posted via `ngx_post_event` and runs on the same single worker thread that runs disconnect, so the two never overlap in time.
3. **The `ctx->destroyed` guard defers teardown.** `xrootd_on_disconnect` sets `ctx->destroyed = 1` first (`src/connection/disconnect.c:281`), then frees the raw-heap scratch/payload buffers (`:22-81`). Every AIO done callback first calls `xrootd_aio_restore_stream`/`_request` (`src/aio/resume.c:23-31`, `:41-52`), which returns 0 when `destroyed` and aborts before touching `ctx`/`c`. The pgread completion guard is `src/aio/reads.c:407`; the read completion guard is `:266-268`; `xrootd_aio_resume` re-checks `ctx == NULL || ctx->destroyed` at `:100-117`.
4. **The detached write payload is freed exactly once.** `xrootd_write_aio_done` frees the detached heap copy **unconditionally before** the guard (`src/aio/write.c:40-61`; writev at `:228-244`), and `xrootd_handle_write` nulls `ctx->payload`/`payload_buf` after posting so disconnect's free cannot race it (`src/write/write.c:116-122`).
5. **The recv loop never reads/dispatches/disconnects while an AIO is in flight.** The disconnect-detection branch routes `n==0`/`NGX_ERROR` through `xrootd_on_disconnect` before finalize (`src/connection/recv.c:286-293`), but the `XRD_ST_AIO` recv guard (below) ensures that branch is not reached while a worker is running.

The decisive harness check is the error-log scan for `heap-use-after-free`/`heap-buffer-overflow`/`attempting double-free`/`SIGSEGV` plus the pgrep worker-still-alive check.

### Phase C — endsess-then-pipelined-read + RST

200 iterations: open `/big.bin`, then in **one** `sendall` write two back-to-back frames in a single TCP segment — `kXR_endsess` (16 zero bytes) immediately followed by a pipelined `kXR_pgread` for 16MiB on the just-opened handle — then immediately hard-RST.

**Exploit hypothesis:** the pipelined pgread executes against a handle/buffers already freed by endsess teardown; or `xrootd_on_disconnect` runs twice (once from endsess, once from the RST) and double-frees.

**Defense.** `xrootd_handle_endsess` does full teardown synchronously: it calls `xrootd_on_disconnect` (sets `destroyed=1`, frees buffers, releases budget, unregisters the session), then `xrootd_close_all_files` (each `xrootd_free_fhandle` `close()`s the fd and resets the slot to `fd=-1`), then clears `ctx->logged_in=0` and `ctx->auth_done=0` (`src/session/lifecycle.c:132-145`). The pipelined pgread then hits two independent gates: `xrootd_dispatch_require_auth` rejects it with `kXR_NotAuthorized` because the auth flags are now 0 (`src/handshake/policy.c:54-62`), and even if reached, `xrootd_validate_read_handle` finds `fd<0` → `kXR_FileNotOpen` (`src/connection/fd_table.c:361-376`). The disconnect path is idempotent (buffer frees null their pointers; `xrootd_free_fhandle` is bounds-guarded and resets state — `src/connection/fd_table.c:233-323`). The Phase-29 drain barrier defers any non-read opcode while the output queue is non-empty (`src/connection/recv.c:391-396`), and the deferred path is itself re-dispatched only when quiescent (`:150-180`).

### Phase D — Resource exhaustion (shed, don't crash)

Three sub-attacks: (1) one session issues 64 `kXR_open /big.bin` calls (far past the 16-slot table); (2) 24 concurrent threads each fire 20 `kXR_pgread` of 48MiB against the 8m `xrootd_memory_budget`, then RST; (3) 300 rapid connect+RST cycles to churn the session registry.

| Sub-attack | Hypothesis | Defense | Location |
|---|---|---|---|
| 64-open flood | OOB write past `files[16]` | `xrootd_alloc_fhandle` scans the fixed 16-slot table and returns `-1` when full; open handler maps `-1` to an error reply (no 17th slot written) | `src/connection/fd_table.c:12-28` |
| 24×20× 48MiB pgread | Unbounded heap growth → OOM | `xrootd_budget_admit` returns 0 when others' in-use heap + request would exceed the budget → `kXR_wait` + `budget_waits_total`, no allocation; `rlen` capped at `XROOTD_READ_REQUEST_MAX(64MiB)`; readv total capped at 256MiB | `src/connection/budget.h:100-120`; `src/read/pgread.c:153-184`; `src/read/readv.c:263-290`; `src/read/read.c:301-303` |
| connect/RST storm | Registry slot leak / churn corruption | `xrootd_on_disconnect` releases budget, concurrency slot, dashboard slots, and (for authed non-bound sessions) the registry slot exactly once; scratch/payload freed and nulled | `src/connection/disconnect.c:295-338`, `:43-57` |

### Phase E — Final integrity proof

On a fresh session, `kXR_read` the first 65536 bytes and assert the body equals `bytes((i*31+7)&0xFF for i in range(65536))`; then `kXR_pgread` the same range and assert `kXR_ok`/`kXR_status` (page framing intact). This is the positive control: after thousands of hostile frames and AIO/RST races, the data path must still return byte-correct content with intact CRC framing.

**Defense.** Scratch buffers are per-session and reset/trimmed between requests (`out_count==0` trim gate at `src/connection/recv.c` top-of-request); the windowed/sendfile builders clamp to the cached file size (`src/read/read.c:148-233`, `:457-470`); the AIO thread/done split keeps protocol-state mutation on the event loop (`src/aio/reads.c:228-241`, `:266`); pgread re-derives page boundaries and recomputes CRC32c per page via `xrootd_pgread_encode_pages` (`src/read/pgread.c:51-94`, `:96-152`). Because earlier phases were all rejected/serialized without corrupting `ctx`, this read sees a clean session.

## v2 phases (test_evil_actor_v2.py + race_shim) — cross-connection and cross-protocol

v2 deliberately targets the surfaces the per-connection `XRD_ST_AIO` recv guard does **not** cover — cross-connection bind handles and cross-protocol shared files — and uses `race_shim` to make every worker-vs-event-loop window deterministic.

### P1 — Cross-connection kXR_bind handle inode-swap race

Per round: open a primary, `kXR_open /shared.bin` → `fh` + sessid; on a second connection `kXR_bind` to that sessid; the bound secondary fires a large `kXR_pgread(fh, 0, 8MiB)` (worker held mid-`pread` by the shim); during that held read the **primary** sends `kXR_close(fh)` and the test `unlink`s `/shared.bin` and rewrites it with new content (fresh inode). The single-connection `XRD_ST_AIO` guard suspends only the secondary, so the primary's close is a genuine cross-thread/cross-connection window.

**Hypothesis:** the secondary keeps reading from a primary-published handle after close+unlink, or reads the swapped-in attacker inode (data confusion), or a worker dereferences a freed handle.

**Defense.** A bound secondary owns no independent handle: on every read it re-derives the handle from the primary's SHM-published table. `xrootd_ensure_read_handle` re-checks the published slot under the handle mutex on each request via `xrootd_session_handle_lookup_hint` (`src/connection/fd_table.c:184`, `:203`, `:198-226`). If the primary closed/reused the slot, the lookup misses and the secondary's local fd is freed and the read is `NGX_DECLINED` (revocation). If still published but stale, the handle is reopened through the same confined opener and the fresh `fstat` `st_dev`/`st_ino` is compared against the published device/inode — `xrootd_local_file_matches_shared_handle` (`src/connection/fd_table.c:66`, `:76`) and the reopen guard `if (st.st_dev != shared->device || st.st_ino != shared->inode) { close(fd); return NGX_DECLINED; }` (`:144`). An inode swap fails this check and never serves swapped content. Read buffers are per-connection scratch owned by that connection's `ctx` (freed only at its own disconnect/AIO-done), so the primary's close cannot free the secondary worker's in-flight buffer; the secondary's pgread done callback re-validates via the `ctx->destroyed`/streamid guard (`src/aio/reads.c:407`).

### P1b — Many-secondaries simultaneous close revocation race

Per round: one primary opens `/big.bin`; five secondaries `kXR_bind` and all fire a large `kXR_pgread(fh, random off, 8MiB)` at once (all held mid-`pread`); then the primary `kXR_close(fh)`; then RST all.

**Hypothesis:** multiple worker threads reading one published handle while the primary's close clears the SHM slot under them frees a handle still in use, or violates the shared-table mutex.

**Defense.** Each secondary is a separate connection with its own `ctx`, slot hint, and AIO task; all five independently re-validate the published slot under the single handle mutex on their next read. The unpublish on primary close (`xrootd_session_handle_unpublish`, `src/session/handles.c:284`) takes the same mutex, so the clear is atomic w.r.t. each lookup; the full key (`in_use` + sessid + `handle_index`) is re-checked every read via `xrootd_shared_handle_same_key` (`src/session/handles.c:71`). A secondary that already passed lookup reads from its own confined fd/buffer (no shared mutable state) and its done callback is gated by streamid/`ctx->destroyed`. There is no shared per-handle refcount to corrupt — revocation is purely SHM-slot visibility under a mutex, so N concurrent revocations serialize correctly. The local-fd revocation logic is `src/connection/fd_table.c:198-226`.

### P2 — Cross-session bind security contract

(a) On a fresh connection, `kXR_bind` with the **captured** primary sessid and confirm it succeeds and can read the primary's `fh`. (b) 64 times, `kXR_bind` with a fully **random** 16-byte sessid; assert `forged_ok == 0`.

**Finding (honest statement of the trust model).** The 16-byte sessid is a **bearer token**, not a capability secret. It is built at connection setup from `{time, pid, (uintptr_t)c, ngx_random()}` (`src/connection/handler.c:82`) and is explicitly **not** a CSPRNG value — its purpose is uniqueness within a process, not unguessability. Consequences:

- **A captured sessid grants identity + handle access.** Anyone who observes a valid sessid (e.g. on the wire, in a log) can `kXR_bind` and inherit the primary's authenticated identity (DN, VO list, `token_auth`), skipping login/auth entirely. This is by design for parallel data channels, and the test documents it.
- **Blind online forgery is infeasible.** `kXR_bind` is hard-gated on an exact-match registry lookup: `xrootd_handle_bind` calls `xrootd_session_lookup(req->sessid)` and on miss returns `kXR_NotAuthorized "bind sessid not recognised"` **before** inheriting any state (`src/session/bind.c:78`, `:86`). The lookup is a 16-byte `ngx_memcmp` against in-use registry slots (`src/session/registry.c:293`, `:315`). A sessid is only inserted into the registry at the point a real session is permitted file I/O (anonymous login or successful `kXR_auth`), so an attacker must possess a sessid that a real session published. The asserted `0/64` random-sessid acceptances confirm the gate; the test treats this as the documented trust boundary, not as a cryptographic guarantee.

**Hardening recommendation:** mint the sessid from a CSPRNG. Uniqueness is unchanged, but the bearer token becomes computationally infeasible to forge offline as well as online, removing the residual "if you can guess it you are in" weakness and hardening against low-entropy collisions across a fleet.

### P3 — Disconnect-mid-AIO, shim-widened

Six threads loop until a 70s deadline: connect, login, open `/big.bin`, issue a large offloaded op (`kXR_pgread 8/16MiB`, `kXR_readv` 8×1MiB, or `kXR_write` 1MiB to `/w.bin`) so a worker is held mid-syscall by the shim, then after a randomized `0/0.5ms/3ms` delay hard-RST.

This is the deterministic version of v1 Phase B. Same defenses, now exercised with the worker reliably parked inside the syscall: the two-phase task split (`src/aio/readv.c:93`, `src/aio/write.c:47`, `:59`), the `ctx->destroyed` guard at completion (`src/aio/resume.c:23`, `:42`, `:115`), the unconditional detached-payload free before the guard, and the recv loop's `XRD_ST_AIO` branch that re-arms the read event and returns without reading/dispatching (`src/connection/recv.c:186`). `ctx->destroyed` is set under the event loop before the scratch/payload buffers are freed (`src/connection/disconnect.c:281`, `:43`), so the in-flight task's done callback no-ops via the guard, making the buffers safe to release.

### P4 — Pipelined read → readv → pgread scratch reuse then RST

≥40 iterations: open `/big.bin`, send in a **single** TCP segment three pipelined ops on the same handle — `kXR_read(fh,0,4MiB)`, `kXR_readv` 4×1MiB, `kXR_pgread(fh,0,4MiB)` — then immediately RST. The three contend for the shared read scratch while the shim widens each worker `pread`.

**Hypothesis:** a later pipelined op overwrites or frees the shared `read_scratch` while an earlier op's response chain still references it (the historical pool-churn UAF: large read then large readv).

**Defense.** Pipelining is restricted to `kXR_read` only, and only when the response is a single self-contained file-backed sendfile span (`resp_pipelinable && !rd_win_active && out_count < PIPELINE_MAX` — `src/connection/recv.c:436`). Any non-read opcode arriving while reads still drain sets `recv_deferred` and parks in `XRD_ST_SENDING` until the output queue fully drains (`src/connection/recv.c:233`, `:391`), so it never runs while a prior chain references the scratch. The scratch slots are **raw `ngx_alloc` heap** owned by `ctx` (not pool allocations) precisely so the earlier pool-churn UAF cannot recur (`src/aio/buffers.c:33-59`, alloc/grow at `:48`); `xrootd_release_read_buffer` is a no-op for the reusable scratch slots (`:82`); trim happens only at top-of-request with `out_count==0` (`src/connection/recv.c:252`). Each completion is still `ctx->destroyed`/streamid-gated, so the RST is handled like P3.

### P5 — Stateful / less-tested opcode fuzz

≥60 seeded-RNG iterations on `/w.bin`: one of `kXR_truncate` (hostile size −1/0/1<<62), `kXR_chkpoint` (random subcode, 50% an embedded sub-`kXR_write` whose fhandle `0x07000000` mismatches the open handle), `kXR_fattr` (random subcode/count + 0/2/40 junk bytes), `kXR_sync`, or `kXR_endsess` carrying a random cross-session sessid immediately followed by a pipelined `kXR_read`. Then read one response and RST.

**Hypothesis:** an out-of-range truncate or mismatched chkpoint fhandle indexes off the table; a fattr count/payload mismatch over-reads; or a forged-sessid `kXR_endsess` leaves the session usable so the pipelined read still operates (auth bypass).

**Defense.** `dlen` is bounded per-opcode before any allocation (`src/connection/recv.c:360`) and the payload buffer always carries a NUL terminator (`:55`). Handles are 0-255 table slots validated in `fd_table` helpers, so a mismatched/embedded chkpoint fhandle resolves to an empty slot (`fd<0` → declined) — bounds check at `src/connection/fd_table.c:190`. `kXR_endsess` **ignores the wire sessid entirely** — it tears down via `xrootd_on_disconnect` + `xrootd_close_all_files` then clears `ctx->logged_in=0`/`auth_done=0` (`src/session/lifecycle.c:132`, `:142`), so the pipelined `kXR_read` is rejected by the auth gate; a client cannot keep operating after endsess, even with a forged id. The drain barrier defers the pipelined non-read after a parked response. Username validation remains in force at `src/session/login.c:85`.

### P6 — Cross-protocol simultaneous assault + unlink/recreate

For 25s, 11 threads hammer the **same** files: 4 do `root://` open+read of `/xp.bin`; 3 do WebDAV `GET` + `PROPFIND(allprop)`; 2 do S3 `GET` + `HEAD` on `/s3b/xp.bin`; and 2 swapper threads continuously rewrite, `unlink`, and recreate `/xp.bin` (inode churn).

**Hypothesis:** a shared fd-cache or SHM entry reused across `root`/WebDAV/S3 serves a stale or swapped inode; the unlink/recreate lets one protocol read another's freed buffer; or a concurrent open escapes the export root.

**Defense.** Every wire path resolves through the same confinement helper before open: `xrootd_open_beneath` uses a per-worker `O_PATH` rootfd + `openat2(RESOLVE_BENEATH)` (`src/fs/vfs_open.c:290`, dispatch cascade at `:275`), so no protocol can traverse outside root regardless of inode churn (Invariant 4). Each open captures `st_dev`/`st_ino` into its **own** per-connection handle (`src/read/open_resolved_file.c:220-221`), so an unlink+recreate leaves earlier opens reading the now-unlinked original inode and later opens getting the new one — no shared mutable buffer is crossed between protocols (S3 SigV4, WebDAV, and `root` each have isolated auth/handle state — Invariant 6). The three protocols are independent nginx modules sharing only read-only confined-open primitives and mutex-guarded SHM.

### P7 — Survival + integrity

After all prior phases, open a clean session, `kXR_open /big.bin`, `kXR_read` the first 65536 bytes, and compare byte-for-byte against the seed pattern.

**Defense.** Because each phase's defenses keep buffers connection-owned, handles inode-validated, and completions `ctx->destroyed`-gated, no cross-request or cross-connection state survives to corrupt a later clean read; the read path returns the file's true bytes (`src/aio/reads.c:317` data delivery + `:266` survival guard; framing decode at `src/connection/recv.c:343`; open/stat at `src/read/open_resolved_file.c:220`). The crash harness confirms liveness; this phase confirms correctness end-to-end.

## Supporting core mechanisms (cross-cutting)

These are the load-bearing invariants the phases above repeatedly lean on:

| Mechanism | Role | Key locations |
|---|---|---|
| `XRD_ST_AIO` recv-loop teardown deferral | While an AIO task is in flight, recv re-arms the read event and returns without reading/dispatching/disconnecting — the connection is frozen until the done callback transitions state back | `src/connection/recv.c:165-170`, `:186-191`, `:413-418`, `:483-488` |
| `read_scratch`/`write_scratch` lifetime + `ctx->destroyed` guard | Scratch is raw `ngx_alloc` (not pool-backed), reused across requests, freed exactly once on disconnect after `destroyed=1`; resume helpers abort when destroyed | `src/aio/buffers.c:23-60`, `:75-89`; `src/connection/disconnect.c:43-75`, `:281`; `src/aio/resume.c:23-31`, `:115-117` |
| AIO offload policy | write/readv/pgread offload unconditionally; `kXR_read` probes the cache with `preadv2(RWF_NOWAIT)` and completes inline only on an exact warm hit, else falls through to the pool | `src/read/read.c:50`, `:344-423`; `src/aio/reads.c:365-387`; `src/write/write.c:105-123`; `src/aio/resume.c:67-87` |
| Kernel-enforced path confinement | `openat2(RESOLVE_BENEATH\|RESOLVE_NO_MAGICLINKS)` per-worker rootfd is the security boundary; `#error` guards require kernel ≥ 5.6; mutating `*at()` ops pre-resolve the parent | `src/path/beneath.c:43-49`, `:73-93`, `:129-220`; `src/path/resolve_confined_helpers.c:221-233`, `:286-288`; `src/path/resolve_confined_ops.c:56-115` |
| Bounded file-handle table | Fixed `files[XROOTD_MAX_FILES(16)]`; wire fhandle is one untrusted byte; three validators bound-check range + open + capability | `src/connection/fd_table.c:12-28`, `:343-355`, `:361-389`, `:395-409`, `:184-227` |
| `kXR_bind` sessid contract | Bearer-token sessid, registry-validated, identity inherited only from a registered entry; secondaries confined to read-only of published handles | `src/connection/handler.c:77-87`; `src/session/login.c:116-133`; `src/session/bind.c:78-88`, `:89-122`; `src/session/registry.c:203-290` |
| Wire-framing caps + overflow guards | Per-opcode `dlen` cap before allocation; readv segment caps (`SEGSIZE 16`, `MAXSEGS 1024`, total 256MiB); overflow-checked multiplies; pgwrite `INT64` offset guard | `src/connection/recv.c:21-46`, `:62-65`, `:360-368`; `src/read/readv.c:56-57`, `:84-95`, `:106-129`, `:211-272`; `src/write/pgwrite.c:153-154` |
| SHM-global memory budget + windowed reads | Cross-worker atomic caps aggregate scratch; over-budget reads defer with `kXR_wait`; large memory-backed reads stream in ~2MiB windows | `src/connection/budget.h:25-120`; `src/read/read.c:301-312`; `src/read/readv.c:288-299`; `src/aio/reads.c:52-103`, `:112-215`; `src/aio/buffers.c:111-142`; `src/connection/recv.c:252-258`; `src/types/tunables.h:55-57` |

## Running the tests

### Release build (probabilistic, fast)

```bash
# Build the module + nginx (only when config/source list changes; else `make -j$(nproc)`)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)

# v1 stream-plane suite
PYTHONPATH=tests pytest tests/test_evil_actor.py -v --tb=short

# v2 cross-connection / cross-protocol suite
PYTHONPATH=tests pytest tests/test_evil_actor_v2.py -v --tb=short
```

In release mode the harness still catches a hard crash (signal in the log + pgrep churn), but a use-after-free may only sometimes fault. Use ASAN for determinism.

### ASAN build (deterministic UAF/overflow detection)

Point `TEST_NGINX_BIN` at an ASAN-instrumented nginx, and for v2 build the shim with matching sanitizer flags and select it:

```bash
# ASAN nginx in a separate build tree (XROOTD_OPTIMIZE=none keeps the module's
# own -O3/LTO profile from fighting the sanitizer flags)
cp -a /path/to/nginx-src /path/to/nginx-asan && cd /path/to/nginx-asan
XROOTD_OPTIMIZE=none ./configure --with-stream --with-stream_ssl_module \
  --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO \
  --with-cc-opt="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  --with-ld-opt="-fsanitize=address" && make -j$(nproc)

export TEST_NGINX_BIN=/path/to/nginx-asan/objs/nginx
export TEST_EVIL_SHIM_SAN=address      # v2: harness rebuilds race_shim.c with -fsanitize=address

PYTHONPATH=tests pytest tests/test_evil_actor_v2.py -v --tb=short
```

### The ASAN + LD_PRELOAD link-order gotcha

`race_shim.c` is preloaded so it can interpose the worker syscalls. Under ASAN, the ASan runtime **must** appear before the shim in `LD_PRELOAD`, or the loader rejects the shim with an "ASan runtime does not come first" ordering error. The harness handles this automatically: it derives the real versioned runtime from `ldd $TEST_NGINX_BIN | grep libasan` (the resolved `/lib64/libasan.so.6`, **not** the non-loadable linker-script `libasan.so`) and prepends it ahead of the freshly built `librace.so`. The equivalent manual invocation is:

```bash
# space-separated LD_PRELOAD: real ASan runtime first, then the shim
export LD_PRELOAD="/lib64/libasan.so.6 /path/to/librace.so"
export ASAN_OPTIONS="verify_asan_link_order=0:abort_on_error=1:halt_on_error=1:detect_leaks=0"
```

`detect_leaks=0` is required because nginx intentionally leaves pool memory unfreed at exit; with LSan on, those benign leaks would trip the `LeakSanitizer` crash pattern. The harness rebuilds `librace.so` with the sanitizer flags from `TEST_EVIL_SHIM_SAN` so the shim's `dlsym(RTLD_NEXT, ...)` chain reaches the sanitizer's interceptor first; the syscall delay is taken via a direct `nanosleep` so it never recurses through an intercepted `usleep`.

### TSan

TSan is wired (`TEST_EVIL_SHIM_SAN=thread`, plus the TSan log-dir scan in `assert_healthy` that fails only on module/AIO-framed races). It is **env-blocked on the current host**: the system `libtsan` runtime is missing, so a TSan nginx will not load. When a host with `libtsan` is available, build the shim and nginx with `-fsanitize=thread`, set `TSAN_OPTIONS` to a writable `log_path`, and the same phases will additionally catch missing happens-before edges (e.g. a worker write to `read_scratch` racing the event-loop free) that ASan alone cannot.

## What this proves / residual recommendations

**Proven.**

- A worker that takes a fatal signal on any of the hostile inputs above is caught — the four-pronged detector (error-log delta + master alive + pgrep worker-still-alive + fresh ping) sees through the master's silent respawn that a liveness probe alone would miss.
- Disconnect-mid-AIO is **not** a use-after-free: the worker halves touch only the task struct, completions are serialized onto the event loop, the `ctx->destroyed` guard defers buffer teardown until the done callback runs and no-ops, and the detached write payload is freed exactly once. The `race_shim` makes this deterministic by holding the worker inside the syscall while the RST runs — and the proof that the shim is sound is that it only ever delays non-`g_main` (pool) threads, never the event loop.
- Cross-connection bind handles are revoked under a mutex on every read, and an inode swap (unlink+recreate) is rejected by a fresh `st_dev`/`st_ino` comparison rather than serving attacker content.
- `kXR_bind` cannot be used for blind online session hijack: 0/64 random sessids are accepted because the registry lookup is an exact 16-byte match against sessids published only by authenticated/anonymous-login sessions.
- After the full siege the data path is byte-exact and pgread CRC framing is intact (v1 Phase E, v2 P7).

**Residual recommendations.**

1. **Mint the sessid from a CSPRNG** (`src/connection/handler.c:82`). The bind contract is currently a bearer-token model whose only forgery defense is the registry exact-match; a CSPRNG sessid additionally defeats offline guessing and low-entropy collisions across a fleet without changing the inheritance semantics.
2. **Unblock TSan on a host with `libtsan`.** ASan proves spatial/temporal memory safety on the paths that fault; TSan is the only tool that proves the *happens-before* edges (event-loop free vs. worker write) the suite is built to stress. Until it runs, the "no data race" claim rests on serialization reasoning plus ASan, not on a race detector.
3. **Treat the captured-sessid trust boundary as documentation, not a control.** The bearer-token property means sessid exposure (logs, mirrored traffic, debug captures) is an identity-disclosure risk; ensure sessids are not logged in cleartext and consider binding the secondary's source identity where feasible.

---

See also: [`coding-standards.md`](coding-standards.md) for the no-`goto` / functional-modular rules the AIO and confinement helpers follow, and the per-module READMEs under `src/aio/`, `src/connection/`, and `src/path/` for the WHAT/WHY/HOW contracts referenced above.
