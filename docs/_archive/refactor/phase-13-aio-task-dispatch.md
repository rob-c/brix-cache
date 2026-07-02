# Phase 13 — aio/ Task Dispatch Consolidation

**Target**: eliminate remaining task-dispatch boilerplate in the `aio/` module
and its callers, and consolidate the trivially-small `read.c` + `pgread.c` into
a single file.

**Net LoC reduction**: ~25–40 LoC  
**Risk**: very low — mechanical changes, zero logic change  
**Requires**: `make -j$(nproc)` only (no new source files, no `./configure`)

---

## Correction to original proposal

The original "Phase 13 — aio/ macro collapse (~180 LoC)" estimate was wrong.
Reading the files reveals that most of the imagined boilerplate was already
extracted into three shared helpers:

| Helper | File | What it covers |
|--------|------|----------------|
| `xrootd_aio_post_task()` | `aio/resume.c:68` | `ngx_thread_task_post` + null-pool guard + fallback log + `state=XRD_ST_AIO` |
| `xrootd_aio_restore_request()` | `aio/resume.c:42` | `ctx->destroyed` check + `state=XRD_ST_REQ_HEADER` reset |
| `xrootd_aio_restore_stream()` | `aio/resume.c:21` | `ctx->destroyed` check + stream-id restore |

These three already absorb the bulk of the "dispatch boilerplate" mentioned in
the original proposal.

What remains genuinely duplicated:

1. **3-line handler assignment** — appears at every dispatch site:
   ```c
   task->handler       = xrootd_read_aio_thread;
   task->event.handler = xrootd_read_aio_done;
   task->event.data    = task;
   ```
   Nine sites across the codebase; 3 LoC each = 27 LoC total.

2. **Trivially-small separate files** — `aio/read.c` (128 LoC) and
   `aio/pgread.c` (181 LoC) are each a single `_thread` + `_done` function
   pair. Both operations are kXR page-read variants and naturally belong
   together.

3. **NOT a target** — `_done` preamble macros:
   The 4-line `task = ev->data; t = task->ctx; ctx = t->ctx; c = t->c;` block
   appears in every done callback. A macro would save 3 LoC per callback × 6 =
   18 LoC but at the cost of hiding local variable declarations from GDB/LLDB.
   This is not worth it.

---

## Change A — `xrootd_task_bind()` inline helper

**What**: add a 5-line inline to `aio/aio.h` that replaces the 3-line
handler-assignment block at every dispatch site.

**Before** (at each of 9 dispatch sites):
```c
task->handler       = xrootd_read_aio_thread;
task->event.handler = xrootd_read_aio_done;
task->event.data    = task;
```

**After**:
```c
xrootd_task_bind(task, xrootd_read_aio_thread, xrootd_read_aio_done);
```

**Definition** — add to `aio/aio.h` before the function declarations:
```c
/*
 * xrootd_task_bind — wire a thread function and done callback into an
 * ngx_thread_task_t.  task->event.data must always point back to task so
 * the done callback can recover it from ev->data.
 */
static ngx_inline void
xrootd_task_bind(ngx_thread_task_t *task,
    ngx_thread_pt       thread_fn,
    ngx_event_handler_pt done_fn)
{
    task->handler       = thread_fn;
    task->event.handler = done_fn;
    task->event.data    = task;
}
```

**Dispatch sites to update** (9 total):

| File | Approx line | Handler pair |
|------|-------------|--------------|
| `src/read/read.c` | ~226 | `xrootd_read_aio_thread` / `xrootd_read_aio_done` |
| `src/read/pgread.c` | ~157 | `xrootd_pgread_aio_thread` / `xrootd_pgread_aio_done` |
| `src/read/readv.c` | ~307 | `xrootd_readv_aio_thread` / `xrootd_readv_aio_done` |
| `src/write/common.c` | ~151 | `xrootd_write_aio_thread` / `xrootd_write_aio_done` |
| `src/write/common.c` | ~? | `xrootd_writev_write_aio_thread` / `xrootd_writev_write_aio_done` |
| `src/dirlist/handler.c` | ~176 | `xrootd_dirlist_aio_thread` / `xrootd_dirlist_aio_done` |
| `src/query/checksum_ckscan_dispatch.c` | ~272 | ckscan pair |
| `src/tpc/launch.c` | ~350 | `xrootd_tpc_pull_thread` / `xrootd_tpc_pull_done` |
| `src/cache/open_or_fill.c` | ~54 | cache fill pair |

*webdav/tpc_thread.c, webdav/put.c, webdav/copy.c, webdav/move.c, and
webdav/tpc_marker.c* each use their own private task patterns with HTTP
pool + different state management — leave these unchanged.

**LoC accounting**:
```
New inline definition in aio.h:         +8 LoC
Each site: 3 LoC → 1 LoC (save 2):     9 × −2 = −18 LoC
Net:                                    −10 LoC
```

---

## Change B — merge `aio/read.c` + `aio/pgread.c` → `aio/reads.c`

**What**: concatenate the two files. Both serve kXR_read variants; both are
too small to warrant separate compilation units.

**Current layout**:
```
aio/read.c    — xrootd_read_aio_thread (7 LoC)  + xrootd_read_aio_done  (45 LoC)
aio/pgread.c  — xrootd_pgread_aio_thread (13 LoC) + xrootd_pgread_aio_done (107 LoC)
```

**After layout** — `aio/reads.c`:
```
/* Section: kXR_read  */
xrootd_read_aio_thread   + xrootd_read_aio_done   (moved verbatim)
/* Section: kXR_pgread */
xrootd_pgread_aio_thread + xrootd_pgread_aio_done  (moved verbatim)
```

**LoC accounting**: 0 — same code, one fewer file.  
**Build accounting**: update `config` (the nginx module shell script) to replace
the two entries with one:

```sh
# Remove:
    $ngx_addon_dir/src/core/aio/read.c \
    $ngx_addon_dir/src/core/aio/pgread.c \
# Replace with:
    $ngx_addon_dir/src/core/aio/reads.c \
```

Because a source file is renamed (deleted + added), `./configure` must be
re-run once, then `make -j$(nproc)`.

---

## Change C — task caching for writev (optional, performance not LoC)

While reading the dispatch sites, `src/read/read.c` caches its task struct
in `ctx->read_aio_task` to avoid a pool alloc on every read request.
`src/write/common.c` always calls `ngx_thread_task_alloc` fresh.

If task caching is extended to writes (add `ctx->write_aio_task` to
`xrootd_ctx_t`), the allocation savings per write request are measurable on
high-IOPS workloads. This is a **performance** improvement, not LoC reduction.
Record it here as a known gap; implement only if benchmarks show allocation
overhead in write-heavy profiles.

---

## Honest LoC accounting

```
Change A (xrootd_task_bind):      −10 LoC
Change B (merge read+pgread):       0 LoC (file consolidation only)
────────────────────────────────────────────
Net code reduction:               −10 LoC
Files deleted:                    −1 (aio/pgread.c merged into reads.c)
```

**Why so little?** The three existing helpers (`xrootd_aio_post_task`,
`xrootd_aio_restore_request`, `xrootd_aio_restore_stream`) already cover the
bulk of the dispatch/restore boilerplate. The remaining 3-line pattern is the
only genuine duplication; the `_done` preamble is inherent to the nginx
thread-pool API and cannot be compressed without harming debuggability.

The original estimate of ~180 LoC assumed these helpers did not exist. This
phase is worth doing for consistency (every dispatch site reads identically)
but contributes negligibly to the 10% LoC reduction target.

---

## Why NOT to macro the _done preamble

Every `*_aio_done` callback starts with:
```c
ngx_thread_task_t  *task = ev->data;
xrootd_read_aio_t  *t = task->ctx;      /* type varies per operation */
xrootd_ctx_t       *ctx = t->ctx;
ngx_connection_t   *c = t->c;
```

A `XROOTD_AIO_DONE_PREAMBLE(type)` macro would save 3 LoC × 6 callbacks =
18 LoC. It is explicitly rejected here because:

1. **Debuggers cannot see macro-defined locals.** GDB's `info locals`, LLDB's
   `frame variable`, and clangd's hover all fail to show `ctx`, `c`, `t` when
   they are declared inside a macro expansion. This makes debugging AIO
   completion callbacks significantly harder for the exact code paths most
   likely to be inspected under a debugger.

2. **18 LoC is not a meaningful reduction** relative to the effort and the
   ongoing maintenance cost of a macro that defines scope-polluting variables.

3. **The existing pattern is already clear.** A new contributor reading a
   `_done` callback understands the setup immediately from the 4 explicit
   variable declarations.

---

## Implementation steps

1. **Add `xrootd_task_bind` inline** to `aio/aio.h` (after the existing
   `#include` block, before the `typedef struct` declarations).
2. **Update 9 dispatch sites**: replace the 3-line handler assignment with
   `xrootd_task_bind(task, thread_fn, done_fn)`. Verify each call compiles
   (`make -j$(nproc)` after each file or after all 9).
3. **Merge `aio/read.c` + `aio/pgread.c`**:
   - Create `aio/reads.c` by concatenating the two files with a comment
     separator between the kXR_read and kXR_pgread sections.
   - Delete `aio/read.c` and `aio/pgread.c`.
   - Update `config` (the nginx module shell script) as described in Change B.
   - Run `./configure` (one time only for the renamed files), then
     `make -j$(nproc)`.
4. **Test**: run the full suite; specifically verify that kXR_read, kXR_pgread,
   and kXR_readv all pass since those _done callbacks are in the renamed file.

---

## Tests (minimum 3)

The existing test suite covers the paths affected. After the changes, run:

```bash
PYTHONPATH=tests pytest tests/test_aio.py -v           # AIO read/write paths
PYTHONPATH=tests pytest tests/ -k "pgread or read or dirlist" -v
PYTHONPATH=tests pytest tests/test_conformance.py -v   # full protocol suite
```

No new tests are needed — this phase changes no logic.

---

## Relationship to overall 10% target

This phase contributes **~10 LoC net** to the 10% reduction goal.  It is
worth doing for code consistency but should not be counted as a significant
contributor to the LoC target. Its primary value is:
- Establishing a single canonical idiom for wiring up an nginx thread task
- Reducing the file count in `aio/` from 8 to 7
- Serving as documentation that the dispatch infrastructure is already well
  factored, so future operations should reuse `xrootd_aio_post_task` rather
  than rolling their own
