# Phase 29 BLOCKER: ~~readv `read_scratch` memory corruption~~ → BUILD ARTIFACT

**Date:** 2026-06-12 (truly resolved 2026-06-13)
**Status:** ✅ RESOLVED — and the real root cause was a **stale-object mixed-ABI
build**, NOT a memory-corruption bug in the readv path.

## The actual root cause (2026-06-13)

Every "crash" attributed to this blocker was an **incremental build against a
changed struct layout**. The Phase-1 output-queue refactor enlarges/reorders
`xrootd_ctx_t` (`src/types/context.h`). nginx's `--add-module` build does **not**
track header dependencies, so `make` recompiled only the `.c` files that were
edited (`buffers.c`, `write_helpers.c`) and left every other object
(`recv.o`, `readv.o`, `aio/*.o`, …) compiled against the **old** struct layout.
Translation units then disagreed on field offsets → reads/writes landed at the
wrong addresses → SIGSEGV, surfacing in the readv memory path (the one path that
exercises `build_single_memory_chain`). Reverting Phase-1 incrementally *also*
crashed (reverted header vs stale objects), which is exactly why it looked
"pre-existing on `main`".

**Fix / rule:** after any change to `context.h` / `tunables.h` (or any header that
affects struct layout), force a full recompile before testing:
```
cd /home/rcurrie/HEP-x/nginx-xrootd && find src -name '*.c' -exec touch {} +
cd /tmp/nginx-1.28.3 && make -j$(nproc)     # confirm objs/nginx mtime+size change
```

**Proof:** with a forced full recompile, the read→readv repro and readv-alone and
read-alone all survive **8/8 byte-exact** at pipeline depth **1 and 4**, and
`test_readv` (10/10), `test_conformance`+`test_interop_io` (55/55) pass. No code
fix to the readv path was required.

The "Phase-31 raw-heap scratch" change is still a fine improvement on its own
merits (bounds per-connection resident heap), and it likely *appeared* to fix this
only because it happened to perturb which objects got recompiled. The
pool-large-list / dangling-`read_scratch` / per-segment-bounds-guard theories below
are **superseded** — they were post-hoc rationalisations of a build mirage.

---

## (historical) ROOT-CAUSE INVESTIGATION

## ✅ ROOT CAUSE CONFIRMED + FIX (2026-06-12)

**Decisive experiment.** With the Phase-31 scratch-trim removed, the exact repro
(large `kXR_read` → large `kXR_readv` on one client-pooled connection) **survives
8/8 iterations, byte-exact, 9/9 readv integrity tests pass**. With the trim
present, the worker SIGSEGVs in the readv build loop (`read_scratch` is a
freed/undersized buffer). So `xrootd_trim_scratch()` (added by the concurrent
"Phase 31 — Memory-budget streaming" work) is the cause.

`xrootd_trim_one()` (`src/aio/buffers.c`) does `ngx_pfree(read_scratch)` then
`ngx_palloc(XROOTD_READ_WINDOW)` at the top of each new request (`recv.c`,
`REQ_HEADER`, `hdr_pos==0`). Its in-function bookkeeping is self-consistent
(pointer + size updated together), so the corruption is a **pool/lifecycle
interaction** — the `ngx_pfree`/realloc of `read_scratch` leaves the subsequent
readv's `read_scratch` pointing at freed/reused memory. (The precise pool
interaction was not isolated by inspection; the empirical bisect is conclusive.)

**Fix applied:** the `xrootd_trim_scratch()` call in `recv.c` is commented out
with a SECURITY note. The trim is **incomplete external Phase-31 work** (only the
trim landed; the `XROOTD_READ_WINDOW` windowed-read path and
`XROOTD_CONN_XFER_HEAP_MAX` backstop are not yet implemented), so disabling the
buggy trim is the correct interim state. **Coordinate with the Phase-31 owner** to
re-implement the trim safely (e.g. only drop the buffer when provably unreferenced,
or fold trimming into the windowed-read rework) before re-enabling.

---

## (superseded) CORRECTION — bounds guard was insufficient

## ⚠ CORRECTION (2026-06-12, later): the guard is NOT a complete fix

Re-applying the Phase-1 output-queue refactor (which changes the `xrootd_ctx_t`
layout) **re-triggered the crash even with the guard in place** — and the gdb
backtrace lands at the readv header `ngx_memcpy` *after* the guard, meaning **the
guard's bounds check passed and the write still segfaulted**. Therefore:

- `ctx->read_scratch_size` is *accurate for the size at allocation time*, but
  `ctx->read_scratch` is a **dangling pointer** — the buffer it references has
  been freed while the size field still says it is valid. The next readv's
  `XROOTD_GET_SCRATCH` sees `read_scratch_size >= need`, returns the **stale
  freed pointer**, and the per-segment write lands in unmapped/reused memory.
- This is a **use-after-free of `read_scratch`**, *not* the readv loop
  over-advancing. The earlier "valgrind clean ⇒ sound fix" conclusion was
  **wrong**: valgrind's (and ASAN's) layout simply doesn't hit the free/reuse
  timing window, so they don't reproduce it. The bug is real and layout-fragile.
- The guard checks the size field, which is not the thing that's wrong, so it
  **cannot catch the dangling-pointer case**. It is kept only as cheap
  defense-in-depth for the (separate) size-over-advance subset.

**Open root-cause question:** *what frees the `read_scratch` buffer while
`ctx->read_scratch`/`read_scratch_size` still reference it?* The connection is
reused across the large read and the readv (the XRootD client pools the TCP
conn), so the read leaves `read_scratch` dangling for the readv. Suspects:
`xrootd_get_pool_scratch`'s grow path (`ngx_pfree(old)` — must verify nothing
else still holds `old`), the large-read response lifecycle, or a pool
interaction.

**IMPORTANT — concurrent work:** an external dev stream is actively reworking
exactly this buffer (`tunables.h` now has "Phase 31 — Memory-budget streaming":
`XROOTD_READ_WINDOW`, `XROOTD_SCRATCH_TRIM_THRESHOLD`, `XROOTD_CONN_XFER_HEAP_MAX`,
which window/trim `read_scratch`). That rework likely intersects this UAF —
**coordinate with it** rather than patching `read_scratch` in parallel. The
Phase-1 pipelining refactor must wait until this UAF is genuinely fixed (it
re-exposes the crash).

---

## (superseded) Earlier "Fix applied" notes

## Fix applied (2026-06-12)

A fail-safe bounds guard was added to the readv response-build loop
(`src/read/readv.c`, just before the per-segment header `ngx_memcpy`): before
writing each segment it checks
`(response_cursor - response_buffer) + XROOTD_READV_SEGSIZE + read_length >
ctx->read_scratch_size` and, if so, frees the descriptor array, releases the
buffer, and returns `kXR_ArgInvalid` instead of overflowing `read_scratch`.
`read_scratch_size` is the **real** allocation size (kept in lock-step with the
buffer by `xrootd_get_pool_scratch`), so this can never itself write OOB.

**Result:** the exact crash repro below now survives 8+ iterations, all readv
responses are byte-exact, and `test_readv.py::TestReadvCorrectness` +
`TestReadvEdgeCases` (9 tests) pass. The crash is gone.

**Diagnostics run (and what they rule out):**
- **valgrind memcheck** (real glibc allocator, byte-precise, flags any overrun
  even without a crash) on the guard build running the exact read→readv repro:
  **ZERO invalid reads/writes**, read and readv both succeed. Crucially, valgrind
  saw **no overrun during the large read** — so there is **no read-path heap
  corruption** writing past any allocation. The bug is therefore *not* "the read
  corrupts the pool and the readv is the victim"; it is the **readv loop's own
  cursor over-advancing past `read_scratch`** in the specific production `-O`
  binary layout.
- **ASAN** (`-O0` and `-O2`) does not reproduce the crash either — its redzones
  shift the layout the over-advance depends on.

**Conclusion on the guard.** Because (a) valgrind confirms no upstream heap
corruption and (b) the guard bounds the readv write against the *real* allocation
size (`read_scratch_size`, kept in lock-step with the buffer), the guard makes
the readv write path provably OOB-safe — it is a **sound fix**, not merely a
layout mask. The guard "not firing" in the guard build is expected: that build's
(different) layout simply doesn't hit the over-advance, and any layout that *did*
would be caught and rejected.

**Residual / nice-to-have.** *Why* the readv loop over-advances only in the exact
no-guard production layout is unexplained (the size math is textually
self-consistent), which smells like **undefined behavior / a codegen artifact**.
A **UBSan build** (`-fsanitize=undefined`, which instruments operations rather
than allocations and so perturbs layout less than ASAN/valgrind) is the right
tool to chase the UB if a definitive root cause is wanted. Not blocking — the
guard is correct and the crash is gone.

## Summary

A `kXR_readv` whose response is large (~MiB scale), issued on a connection that
**already served a large `kXR_read`**, overflows / writes through the per-connection
`read_scratch` buffer. The stream worker crashes:

- **SIGSEGV at `src/read/readv.c:303`** (sync path) — `ngx_memcpy(response_cursor, …)`
  with `response_cursor` past the end of `read_scratch`, or
- **`free(): invalid pointer` → SIGABRT** (thread-pool path) — the AIO `preadv`
  worker writes past `read_scratch`, corrupting heap metadata, detected at the
  next `free`/pool-teardown.

This is **pre-existing** (NOT introduced by the Phase-1 output-queue refactor):
reproduced on the original `main`-branch code after fully reverting Phase 1.

## Reproduction (minimal, no harness)

```nginx
# stream server: anon, cleartext
server { listen 12950; xrootd on; xrootd_root /tmp/rv; xrootd_auth none; xrootd_allow_write on; }
```
```python
from XRootD import client
from XRootD.client.flags import OpenFlags
# a 20 MB file at /tmp/rv/rvtest.bin
f = client.File();  f.open("root://localhost:12950//rvtest.bin", OpenFlags.READ)
f.read(0, 20_000_000); f.close()                       # large read first
f2 = client.File(); f2.open("root://localhost:12950//rvtest.bin", OpenFlags.READ)
f2.vector_read([(i*65536, 65536) for i in range(200)]) # ~13 MB readv -> CRASH
```

Isolation results:
- readv-alone (200×64 KiB) on a fresh connection: **no crash**.
- read-alone (20 MB): **no crash**.
- **read → readv on the same client session: crash every time.**

(The XRootD client pools the TCP connection, so the read and readv land on the
same server-side `xrootd_ctx_t`, sharing `read_scratch`.)

## What is and isn't ruled out

- The readv size math is self-consistent: `max_response_bytes = Σ(XROOTD_READV_SEGSIZE
  + read_length)` (`readv.c:253`), the header loop writes `XROOTD_READV_SEGSIZE`(=16)
  bytes/segment and advances `response_cursor` by `SEGSIZE + read_length`
  (`readv.c:321`). On a **fresh** connection this fits `read_scratch` exactly — hence
  readv-alone is fine.
- `xrootd_get_pool_scratch` (`aio/buffers.c:23`) grows correctly and updates
  `read_scratch`/`read_scratch_size` together.
- Therefore the corruption comes from **cross-request state**: after the large
  read, `read_scratch`/`read_scratch_size` are left in a state where the readv's
  `XROOTD_GET_SCRATCH(read_scratch, …, max_response_bytes)` returns a buffer that
  is smaller than the size field claims (a dangling or under-sized pointer), and
  the per-segment write runs off the end.
- The cleartext read uses the **sendfile** path (`read.c:93`,
  `build_sendfile_chain`) which is documented to use `read_hdr_scratch`, *not*
  `read_scratch` — so the precise mechanism by which the read perturbs
  `read_scratch`/`read_scratch_size` (or corrupts the pool's large-alloc list) is
  **not yet pinned down** and needs ASAN to localize the first out-of-bounds write.

## Recommended fix path

1. **Build the module with ASAN** (Phase-27 W6 sanitizer build) and run the
   repro — ASAN will report the *first* out-of-bounds write with the exact
   allocation, immediately localizing the corruption (read path vs readv path).
2. Likely candidates to inspect once ASAN points the way:
   - whether the large-read path (`src/read/read.c`, `src/aio/buffers.c`
     `build_sendfile_chain`/`build_chunked_chain`) ever writes `read_scratch` /
     mutates `read_scratch_size`;
   - whether a stalled large-read response leaves a chain referencing
     `read_scratch` that a later `xrootd_get_pool_scratch` grow then `ngx_pfree`s
     (use-after-free), with `read_scratch_size` left stale;
   - `readv.c` bounds: add a hard guard `response_cursor + XROOTD_READV_SEGSIZE +
     read_length <= response_buffer + read_scratch_size` per segment as
     defense-in-depth regardless of root cause.
3. Add a regression test: `read(large) → readv(large)` on one client session,
   byte-exact, must not crash (success + the security-negative case).

## Why this matters for Phase 29

The read/readv/pgread **integrity test suite cannot be used to validate the
pipelining refactor** while this pre-existing crash stands — the harness
(`test_conformance` large reads → `test_readv`) trips it. **Fix this first**, then
re-apply Phase 1 (the slot-FIFO output-queue refactor, which was reverted only
because this pre-existing crash masked its validation) and continue.
