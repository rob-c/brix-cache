# VFS Auxiliary-Storage Consolidation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route the last non-export ("auxiliary") storage I/O through the SD-driver seam instead of raw libc, starting with the one live `check_vfs_seam.sh` break (`http_serve_offload.c`) and the DRY primitive the later domain migrations all reuse.

**Architecture:** The export data/namespace plane already funnels through `xrootd_vfs_*` → `obj->driver->*` (seam fully closed, guard green except one site). The *auxiliary* domains (serve-scratch, read-cache store, S3-multipart staging, TPC temp, checkpoint journal, FRM control) still do their own raw `open`/`pread`/`pwrite`. This plan introduces **one shared "drain an SD object into a worker-owned scratch fd through the driver" primitive** (`xrootd_vfs_scratch_drain_obj`), proves it on the serve-offload path, and lays out the per-domain migrations as follow-on plans. No new infrastructure is invented — it composes the existing `xrootd_sd_posix_wrap()` + driver vtable.

**Tech Stack:** C (nginx module + ngx-free worker-safe helpers), the `xrootd_sd_driver_t` capability vtable (`src/fs/backend/sd.h`), standalone `gcc` unit tests (the repo's existing `*_unittest.c` convention), `tools/ci/check_vfs_seam.sh` as the acceptance gate, pytest for runtime byte-equality.

## Global Constraints

- **NO `goto`** anywhere in `src/` (`docs/09-developer-guide/coding-standards.md` §4) — early-return + helper decomposition only.
- **All file byte I/O stays in / routes through the SD driver** (CLAUDE.md INVARIANT #11). Any raw libc FS call that survives MUST carry a same-line `/* vfs-seam-allow: <reason> */` marker; the goal is to eliminate the marker, not add one.
- **Functional + modular** — one responsibility per function, explicit data flow, no new globals (§8).
- **Section-level WHAT/WHY/HOW doc block on every new function** (coding-standards).
- **Worker-safe helpers are ngx-free** — the raw byte ops (`pread`/`pwrite`/`fstat`/`ftruncate`/`fsync`) touch no nginx runtime, so they can run off the event loop (`sd.h` line ~226).
- **3 tests per change:** success + error + (where applicable) a guard/security check.
- Build: incremental `make -j$(nproc)`; only `./configure` when a **new** `.c` is added to the top-level `config` source list.

---

### Task 1: Migrate the serve-offload materialize write onto the driver seam

Closes the single live `check_vfs_seam.sh` break: `src/protocols/shared/http_serve_offload.c:149` writes the materialized object to its scratch tmp fd with a raw `pwrite`, while the read side already goes through `obj->driver->pread`. Wrap the tmp fd in a stack POSIX SD object and write through the driver — symmetric with the read side and with `vfs_scratch.c`'s `scratch_copy_in`.

**Files:**
- Modify: `src/protocols/shared/http_serve_offload.c:99-171` (the `serve_offload_thread` materialize loop)
- Test: `tools/ci/check_vfs_seam.sh` (acceptance gate) + `tests/test_serve_offload_remote.py` (runtime byte-equality, may already exist — see Step 4)

**Interfaces:**
- Consumes: `xrootd_sd_posix_wrap(xrootd_sd_obj_t *obj, ngx_fd_t fd)` (`src/fs/backend/sd.h:426`) — binds a bare fd to a stack POSIX SD object; `obj->driver->pwrite(obj, buf, len, off)` returns `ssize_t` (`sd.h:244`).
- Produces: no new public symbol; behavior unchanged, raw `pwrite` removed.

- [ ] **Step 1: Run the guard to confirm the break exists**

Run: `bash tools/ci/check_vfs_seam.sh`
Expected: FAIL, naming `src/protocols/shared/http_serve_offload.c:149 ... pwrite(t->tmp_fd, ...)`.

- [ ] **Step 2: Wrap the tmp fd and write through the driver**

In `serve_offload_thread` (`src/protocols/shared/http_serve_offload.c`), after `buf` is allocated and before the copy loop, add the stack wrap; then replace the inner raw `pwrite` with the driver slot. The loop becomes:

```c
    xrootd_sd_obj_t dst;                  /* worker-owned scratch, driver-routed */

    xrootd_sd_posix_wrap(&dst, t->tmp_fd);

    for ( ;; ) {
        ssize_t r = obj->driver->pread(obj, buf, XROOTD_SERVE_OFFLOAD_CHUNK, off);
        off_t   w = 0;

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            t->mret = errno ? errno : EIO;
            break;
        }
        if (r == 0) {
            t->mret = 0;
            break;                       /* EOF - the whole object is materialised */
        }
        while (w < r) {
            ssize_t n = dst.driver->pwrite(&dst, buf + w, (size_t) (r - w), off + w);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                t->mret = errno ? errno : EIO;
                break;
            }
            w += n;
        }
        if (w < r) {
            break;                       /* a write error broke the inner loop      */
        }
        off += r;
    }
```

(`<errno.h>`, `<fcntl.h>`, `<unistd.h>` and `"../fs/backend/sd.h"` are already reachable: `http_serve_offload.c` includes `../fs/vfs.h`, which includes `backend/sd.h`. Confirm `xrootd_sd_posix_wrap` resolves at compile; if not, add `#include "../fs/backend/posix/sd_posix.h"` — but `sd.h` already declares it at line 426.)

- [ ] **Step 3: Build**

Run: `make -j$(nproc)`
Expected: clean compile (the module is `-Werror`); no new warnings in `http_serve_offload.c`.

- [ ] **Step 4: Run the guard — expect green**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: prints `GUARD_GREEN`; no `http_serve_offload.c` line reported.

- [ ] **Step 5: Runtime byte-equality of a remote (offloaded) serve**

The offload path triggers when serving a `root://`-backed (socket-wire) object over WebDAV/S3. Use the existing remote-serve fixture if present, else a minimal check:

Run: `PYTHONPATH=tests pytest tests/ -k "serve and remote" -v --tb=short`
Expected: PASS — the served bytes equal the origin object (the materialize copy is unchanged, only the syscall path moved). If no such test exists, fall back to the hybrid-mesh remote-WebDAV fixture: `PYTHONPATH=tests pytest tests/test_hybrid_mesh.py -k webdav -v`.

- [ ] **Step 6: Commit**

```bash
git add src/protocols/shared/http_serve_offload.c
git commit -m "fix(vfs-seam): route serve-offload scratch write through the SD driver

The materialize loop read via obj->driver->pread but wrote the scratch
copy with a raw pwrite, tripping check_vfs_seam.sh. Wrap the tmp fd in a
stack POSIX SD object and write through the driver, symmetric with the
read side and vfs_scratch.c. Closes the one live seam break.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Extract the shared obj→scratch-fd drain primitive (DRY)

`vfs_scratch.c` has a private `scratch_copy_in(src_fd, dst_fd)` that wraps both fds and copies through the driver; `http_serve_offload.c` (post-Task 1) hand-rolls the same obj→fd drain. Promote one public worker-safe primitive both call, so every future auxiliary-domain migration (cache fill, multipart assembly, TPC temp) reuses it instead of re-deriving the loop.

**Files:**
- Modify: `src/fs/vfs_scratch.h` (declare the primitive) and `src/fs/vfs_scratch.c` (define it; reimplement `scratch_copy_in` on top of it)
- Modify: `src/protocols/shared/http_serve_offload.c` (call the primitive)
- Test: `src/fs/vfs_scratch_unittest.c` (new standalone gcc test)
- Modify: top-level `config` only if a new `.c` is compiled into the module — the unittest is **not** added to the build (standalone, like `vfs_core_unittest.c`); `vfs_scratch.c` is already compiled.

**Interfaces:**
- Produces:
  ```c
  /* Drain an open SD object `src` into the worker-owned scratch fd `dst_fd`,
   * copying `chunk`-sized blocks positionally through the driver (bytes never
   * leave the backend). On success returns NGX_OK and, if `out_total` != NULL,
   * sets *out_total to the byte count copied. On failure returns NGX_ERROR with
   * errno set. EINTR is retried. Worker-safe: no nginx pool, no event loop. */
  ngx_int_t xrootd_vfs_scratch_drain_obj(xrootd_sd_obj_t *src, ngx_fd_t dst_fd,
      size_t chunk, off_t *out_total);
  ```
- Consumes: `xrootd_sd_posix_wrap` (`sd.h:426`), `obj->driver->pread/pwrite` (`sd.h:244`).

- [ ] **Step 1: Write the failing standalone unit test**

Create `src/fs/vfs_scratch_unittest.c`:

```c
/*
 * vfs_scratch_unittest.c — standalone unit test for xrootd_vfs_scratch_drain_obj.
 *
 * Built OUTSIDE the nginx tree (plain gcc). Wraps two real temp fds in the POSIX
 * SD driver and verifies a full drain copies byte-exact and reports the total.
 *
 * Usage:
 *   cd src/fs
 *   gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
 *       -I../compat -I../protocol -Ibackend \
 *       -o /tmp/vfs_scratch_unittest \
 *       vfs_scratch.c backend/posix/sd_posix.c vfs_scratch_unittest.c \
 *       ../compat/staged_file.c
 *   /tmp/vfs_scratch_unittest
 */
#include "vfs_scratch.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;
#define CHECK(c, m) do { if (c) printf("ok: %s\n", m); \
                         else { printf("FAIL: %s\n", m); g_fail = 1; } } while (0)

int main(void)
{
    char            stmpl[] = "/tmp/vfs_scr_src.XXXXXX";
    char            dtmpl[] = "/tmp/vfs_scr_dst.XXXXXX";
    int             sfd = mkstemp(stmpl);
    int             dfd = mkstemp(dtmpl);
    unsigned char   src[8192];
    unsigned char   dst[8192];
    xrootd_sd_obj_t sobj;
    off_t           total = 0;
    size_t          i;
    ngx_int_t       rc;

    for (i = 0; i < sizeof(src); i++) { src[i] = (unsigned char) (i * 31 + 7); }
    CHECK(sfd >= 0 && dfd >= 0, "temp fds open");
    CHECK(pwrite(sfd, src, sizeof(src), 0) == (ssize_t) sizeof(src), "seed source");

    xrootd_sd_posix_wrap(&sobj, sfd);
    rc = xrootd_vfs_scratch_drain_obj(&sobj, dfd, 1024, &total);

    CHECK(rc == NGX_OK, "drain returns NGX_OK");
    CHECK(total == (off_t) sizeof(src), "drain reports full byte count");
    CHECK(pread(dfd, dst, sizeof(dst), 0) == (ssize_t) sizeof(dst), "read dst");
    CHECK(memcmp(src, dst, sizeof(src)) == 0, "dst byte-identical to src");

    close(sfd); close(dfd); unlink(stmpl); unlink(dtmpl);
    printf(g_fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_fail;
}
```

- [ ] **Step 2: Run it to verify it fails (undefined symbol)**

Run:
```bash
cd src/fs && gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
  -I../compat -I../protocol -Ibackend \
  -o /tmp/vfs_scratch_unittest \
  vfs_scratch.c backend/posix/sd_posix.c vfs_scratch_unittest.c ../compat/staged_file.c
```
Expected: link error — `undefined reference to 'xrootd_vfs_scratch_drain_obj'`.

- [ ] **Step 3: Declare the primitive**

In `src/fs/vfs_scratch.h`, add the declaration shown in **Interfaces → Produces** above (with its WHAT/WHY/HOW comment), beside the existing `xrootd_vfs_scratch_*` declarations.

- [ ] **Step 4: Define the primitive and re-base `scratch_copy_in` on it**

In `src/fs/vfs_scratch.c`, add the definition and rewrite the existing `scratch_copy_in` to delegate (DRY — one copy loop, not two):

```c
ngx_int_t
xrootd_vfs_scratch_drain_obj(xrootd_sd_obj_t *src, ngx_fd_t dst_fd,
    size_t chunk, off_t *out_total)
{
    xrootd_sd_obj_t d;
    char           *buf;
    off_t           off = 0;

    if (src == NULL || dst_fd == NGX_INVALID_FILE || chunk == 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    buf = malloc(chunk);
    if (buf == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    xrootd_sd_posix_wrap(&d, dst_fd);
    for ( ;; ) {
        ssize_t r = src->driver->pread(src, buf, chunk, off);
        ssize_t w_done = 0;

        if (r < 0) { if (errno == EINTR) { continue; } free(buf); return NGX_ERROR; }
        if (r == 0) { break; }
        while (w_done < r) {
            ssize_t w = d.driver->pwrite(&d, buf + w_done, (size_t) (r - w_done),
                                         off + w_done);
            if (w < 0) { if (errno == EINTR) { continue; } free(buf); return NGX_ERROR; }
            w_done += w;
        }
        off += r;
    }
    free(buf);
    if (out_total != NULL) {
        *out_total = off;
    }
    return NGX_OK;
}
```

Then replace the body of the existing `scratch_copy_in(int src_fd, int dst_fd)` with:

```c
static ngx_int_t
scratch_copy_in(int src_fd, int dst_fd)
{
    xrootd_sd_obj_t s;

    xrootd_sd_posix_wrap(&s, src_fd);
    return xrootd_vfs_scratch_drain_obj(&s, dst_fd, 256 * 1024, NULL);
}
```

- [ ] **Step 5: Rebuild the unit test and verify it passes**

Run:
```bash
cd src/fs && gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
  -I../compat -I../protocol -Ibackend \
  -o /tmp/vfs_scratch_unittest \
  vfs_scratch.c backend/posix/sd_posix.c vfs_scratch_unittest.c ../compat/staged_file.c \
  && /tmp/vfs_scratch_unittest
```
Expected: all `ok:` lines, final `RESULT: PASS`.

- [ ] **Step 6: Use the primitive in serve-offload**

In `src/protocols/shared/http_serve_offload.c` `serve_offload_thread`, replace the entire hand-rolled copy loop (the block added in Task 1) with one call, after the `obj` is open and `snap`/`mtime` captured:

```c
    {
        off_t total = 0;

        if (xrootd_vfs_scratch_drain_obj(obj, t->tmp_fd,
                                         XROOTD_SERVE_OFFLOAD_CHUNK, &total) != NGX_OK) {
            t->mret = errno ? errno : EIO;
        } else {
            t->mret = 0;
            off = total;
        }
    }
```

Add `#include "../fs/vfs_scratch.h"` near the existing `../fs/vfs.h` include. Drop the now-unused `buf`/`off` copy-loop locals (keep `off` only if still used for `t->size = off`; the snippet sets it from `total`). Remove the `malloc(XROOTD_SERVE_OFFLOAD_CHUNK)` / `free(buf)` pair.

- [ ] **Step 7: Build, guard, runtime**

Run:
```bash
make -j$(nproc) && bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN
PYTHONPATH=tests pytest tests/ -k "serve and remote" -v --tb=short
```
Expected: clean build, `GUARD_GREEN`, serve test PASS (byte-equality preserved).

- [ ] **Step 8: Commit**

```bash
git add src/fs/vfs_scratch.h src/fs/vfs_scratch.c src/fs/vfs_scratch_unittest.c src/protocols/shared/http_serve_offload.c
git commit -m "refactor(vfs): one shared obj->scratch-fd drain primitive

Promote vfs_scratch's private copy loop to xrootd_vfs_scratch_drain_obj
(worker-safe, driver-routed) and call it from both vfs_scratch.c and the
serve-offload materialize path. One copy loop, reused by the upcoming
per-domain auxiliary-storage migrations. Adds a standalone unit test.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Follow-on plans (per-subsystem — each needs its own writing-plans pass)

These are the auxiliary storage domains that INVARIANT #11 currently carves *out* of the VFS. Each is an independent subsystem and a separate plan: the worker-identity "scratch/secondary VFS context" they share (a `xrootd_vfs_ctx_t` bound to the domain's own root + a worker — not impersonated — identity) needs a brainstorming/design pass before it can be written as no-placeholder tasks. Listed here as the roadmap, **not** as executable tasks.

| # | Domain | Files (raw today) | Driver that exists | What the plan must design |
|---|--------|-------------------|--------------------|---------------------------|
| 3 | **Read-through cache store** | `src/fs/cache/` — ~19 of 34 files still raw (`io.c`, `cache_storage.c`, `cstore.c`, `fetch.c`, `open_or_fill.c`, `evict_*`) | `sd_cache` + `tier`/`xfer` | Finish the phase-64 migration: cache-store byte/namespace I/O via the cstore/`sd_cache` instance, not raw cache-root POSIX. Highest leverage (biggest domain, infra already exists). |
| 4 | **S3 multipart staging** | `src/protocols/s3/` — 5 `vfs-seam-allow` markers | — (none) | A staging instance (worker-identity scratch ctx) so part upload/assemble/commit route through the driver; commit stays a VFS↔VFS move. |
| 5 | **TPC temp / assembly** | `src/tpc/`, `src/protocols/webdav/tpc*` — 8 markers | — (none) | In-progress transfer temps + multi-stream assembly onto the scratch ctx; final publish via `xrootd_commit_staged`. |
| 6 | **Checkpoint journal** | `src/write/` (chkpoint) — handle-owned raw | — (none) | Journal file as a handle-owned scratch object; teardown path currently has "no export root" — the scratch ctx supplies one. |
| 7 | **FRM control/journal** | `src/frm/` — partial | `sd_frm` | Route FRM control/journal through `sd_frm`; reconcile with the `xfer` ledger. |

**Sequencing rationale:** #3 first (infra exists, biggest win, de-risks the pattern). #4–#6 depend on the shared worker-identity scratch context, so that design (a brainstorming output) gates them. #7 last (smallest, and FRM/tape recall is itself a later phase-64 step, SP5).

**Acceptance for each follow-on:** the domain's `vfs-seam-allow` markers drop to zero (or to a genuinely irreducible IPC/`/proc`/config-file residue), `check_vfs_seam.sh` stays green, and the domain's existing pytest suite passes byte-for-byte unchanged.

---

## Self-Review

- **Spec coverage:** The user's intent ("focus all file management/access on the VFS, not raw POSIX") splits into (a) the export plane — already done, confirmed by the guard — and (b) the auxiliary domains. Tasks 1–2 deliver the one live break + the shared primitive; the table covers every remaining domain. ✔
- **Placeholder scan:** Tasks 1–2 contain complete code and exact commands. The follow-on section is explicitly a roadmap, not tasks (no checkboxes), per the writing-plans guidance to split multi-subsystem work into separate plans. ✔
- **Type consistency:** `xrootd_vfs_scratch_drain_obj(xrootd_sd_obj_t *, ngx_fd_t, size_t, off_t *)` is used identically in its declaration (Task 2 Interfaces), definition (Step 4), the unit test (Step 1), and both call sites (Step 4 `scratch_copy_in`, Step 6 serve-offload). `xrootd_sd_posix_wrap` and `obj->driver->pwrite` match `sd.h:426`/`sd.h:244`. ✔
