# Phase 56 — VFS ↔ Storage-Driver ↔ POSIX data-plane optimization audit

**Date:** 2026-06-25
**Author:** performance audit (`src/fs/` + `src/fs/backend/` whole-layer sweep)
**Status:** AUDIT / roadmap — **first phases landed (F0 + A-1, 2026-06-25)**; the
rest is sequenced below. This is the perf + expansion catalogue for the data-plane
stack introduced by Phase 54 (thread-safe VFS I/O core) and Phase 55 (pluggable
Storage Driver seam). Treat `src/` as authoritative; re-check an item's
reachability before quoting it as open.

> **Implementation status (this revision).**
> - **F0 — CI seam guard: DONE + verified, now dual-class.** `tools/ci/check_vfs_seam.sh`
>   + `tools/ci/vfs_seam_backlog.txt` (**48** grandfathered files). Rejects a new
>   bypass of **either** class — tier-2 (confined-helper) **and** tier-1.5 (SD-direct
>   byte loop, the A-3 backlog) — verified on synthetic probes of both; passes clean
>   on the current tree; `--regen`-able as files migrate. Wire it into CI next to
>   the no-`goto` check.
> - **A-1 — strip the no-op SD-vtable indirection from the VFS byte primitives:
>   DONE + builds clean** (`-Werror`). `xrootd_vfs_pread_full` (`vfs_read.c`),
>   `pwrite_full` (`vfs_write.c`), `xrootd_vfs_io_write_counted` (`vfs_io_core.c`),
>   and the two FRM journal loops (`frm/reqfile.c`, sweep per §9.3) now call
>   `pread`/`pwrite` directly. Byte-identical (the POSIX driver slot was the bare
>   syscall). *Not yet benchmarked* — the perf win (§11.1) needs a non-WSL2 host;
>   *integration suite not run here* — the test env (`/tmp/xrd-test`) was not
>   provisioned, so build-clean + byte-identical is the evidence, and the full
>   pytest suite remains the final gate.
> - **A-3 — DISCOVERED while implementing A-1 (§4.3, §9.3): 18 more byte loops**
>   bypass the VFS primitives via direct SD-vtable calls (incl. the stream-read hot
>   paths). Documented + enumerated; backlog **frozen** by the (now dual-class) F0
>   guard. The doc's earlier "byte plane is clean" (§9.3) is corrected accordingly.
> - **D-1 — monotonic latency clock: DONE + builds clean** (`-Werror`). Added
>   `xrootd_vfs_now_ns()` (`CLOCK_MONOTONIC`) to `vfs_internal.h`; the VFS observers
>   (`vfs_stat/copy/rename/unlink/mkdir/dir/staged/xattr/read/write`, 10 files) now
>   capture a real ns timestamp instead of the cached `ngx_current_msec`, so
>   inline-op latency is no longer reported as 0 µs and the sub-ms band is real
>   (§7.1). Metrics-only (no client-visible behaviour); the static marker suite held
>   at its baseline. **D-2** (data-plane op-latency in the AIO COMPLETE callbacks)
>   is the remaining half — still planned.
> - **§3 (delete the dead `xrootd_vfs_read`/`write`) — BLOCKED, finding corrected.**
>   The "dead" code is **pinned by a conformance marker test**
>   (`tests/test_cross_protocol_shared_helpers.py::test_phase3_vfs_preserves_io_invariants`,
>   which asserts `b->memory=1`/`b->in_file=1`/`xrootd_crc32c_value(` live in
>   `vfs_read.c`). So Option B (delete) is **not** a pure build-verified change — it
>   would break the stock suite and remove that invariant guard. §3 / Appendix A
>   corrected; deletion now requires migrating the markers to a live path first.
> - Everything else (B-1, D-2, B-2, C-1…C-5, the Pillar-F migration F1–F7) remains
>   planned and sequenced (§12); each is gated on its §11 measurement.
**Scope:** the unified data-plane stack only — `src/fs/vfs*.{c,h}` (the
protocol-agnostic VFS), `src/fs/vfs_io_core.{c,h}` (the worker-safe job core),
and `src/fs/backend/{sd.h,sd_posix.c,sd_registry.c}` (the Storage Driver seam +
POSIX driver). Protocol handlers, the cache, and path/auth middleware are
referenced where they cross the seam but are not re-audited (Phases 3/8/26/30).
**Codifies:** `CLAUDE.md` invariant #11 — *"Data plane = `proto → VFS → POSIX`."*
This document is the optimization backlog for exactly that contract.

> **Non-negotiable (carried from Phase 30 / `CLAUDE.md`):** none of the work below
> may weaken protocol correctness or the security invariants — pgread/pgwrite
> per-page CRC32c, the TLS-buffer/sendfile discipline (`b->memory=1` only under
> TLS; cleartext = file-backed + sendfile; never mix), `RESOLVE_BENEATH`
> confinement before every `open()`, the `allow_write` gate before token scope,
> and low-cardinality metric labels. Every item carries an invariant-preservation
> note. Optimizations that trade correctness or confinement for speed are out of
> scope.

---

## 0. How this audit was produced (and how to trust it)

A read-only sweep of all 16 files under `src/fs/` plus the two backend files,
each finding cross-referenced against (a) every external call site (`grep` for
each public `xrootd_vfs_*` entry point across `src/**/*.c`), (b) the helper it
bottoms out in (`xrootd_open_beneath`, `xrootd_lstat_confined_canon`,
`xrootd_ns_*`, `xrootd_metric_op_done`), and (c) the impersonation path. Each
finding carries a **confidence tag**:

- **`[VERIFIED]`** — the exact lines were read, the behaviour confirmed, **and the
  reachability checked** (is this code on a live path, and which one?).
- **`[AUDIT]`** — surfaced by the sweep and plausible from surrounding code, but
  the claimed win must be **confirmed at implementation time and measured** on a
  representative HEP workload before it is trusted.

**Golden rule (from Phase 30):** *measure before and after every item.* Several
wins below are micro-optimizations whose real-world magnitude is unknown until
benchmarked. The harness in **§11** is a prerequisite, not an afterthought.

### 0.1 The caveat that reshaped this audit — two marquee entry points are dead

The single most important fact for reading everything below: **`xrootd_vfs_read()`
and `xrootd_vfs_write()` have zero callers in the tree.**

```
$ grep -rn '\bxrootd_vfs_read\b'  src/ --include=*.c   # → only its own definition
$ grep -rn '\bxrootd_vfs_write\b' src/ --include=*.c   # → only its own definition
```

`vfs.h` documents `xrootd_vfs_read()` as *"the only place every protocol gets
identical framing, CRC, and cache behaviour"* and `xrootd_vfs_write()` as the
unified chain-writer. **Neither is wired.** The live data plane goes around them
(§1.1). This matters because three findings that *look* like hot-path wins
(`make_file_chain` path alloc, the `write_file_buf` 64 KB bounce, the writethrough
pre-scan) are all inside the dead `xrootd_vfs_read`/`xrootd_vfs_write` bodies, and
optimizing them today changes nothing in production. They are quarantined in **§8
(latent / wire-or-delete)** and **Appendix A (corrected findings)**, not in the
hot-path pillars. The split is itself the top architectural finding (**§3**).

### 0.2 Reachability of the public VFS surface (measured this sweep)

| Entry point | Ext. call sites | Live? | Real callers / route |
|---|---:|:--:|---|
| `xrootd_vfs_open` | 3 | ✅ | `webdav/get.c:125`, `s3/object.c:69`, `s3/conditional.c` |
| `xrootd_vfs_stat` | 3 | ✅ | `webdav/resource.c:81`, `s3/object.c:212`, `s3/conditional.c:261` |
| `xrootd_vfs_opendir`/`readdir`/`closedir` | — | ✅ | PROPFIND-collection / S3 LIST streaming enumerators |
| `xrootd_vfs_copy` | 4 | ✅ | `webdav/copy.c:424`, `s3/copy.c:129` |
| `xrootd_vfs_staged_open`/`commit`/`abort` | 4 | ✅ | `webdav/put.c:390`, `s3/post_object.c:1138` |
| `xrootd_vfs_io_execute` | 20+ | ✅ | all `src/aio/*.c`, `src/read/*.c`, `src/write/*.c` |
| `xrootd_vfs_file_sendfile_fd` | 2 | ✅ | `shared/file_serve.c:184`, `webdav/get.c:170` |
| `xrootd_vfs_stat`/`sync`/`truncate` (handle) | — | ✅ | via `xrootd_vfs_io_execute` SYNC/TRUNCATE jobs |
| **`xrootd_vfs_read`** | **0** | ❌ | — (dead chain-builder; `make_file_chain`/`make_memory_chain`) |
| **`xrootd_vfs_write`** | **0** | ❌ | — (dead chain-writer; `write_file_buf`/`write_memory_buf`) |

### 0.3 The cross-cutting axis the sweep kept hitting — **impersonation**

Three findings (C-1, C-2, D-1) change shape depending on whether Phase-40 UNIX
impersonation is active, so it is called out once here. The confined metadata
helpers branch on `xrootd_imp_client_active()`:

```c
/* src/path/resolve_confined_ops.c:804 — xrootd_lstat_confined_canon */
if (xrootd_imp_client_active()) {
    char rel[PATH_MAX];
    xrootd_resolved_relative_to_root(log, root_canon, resolved, rel, sizeof rel);
    return xrootd_imp_stat(rel, st, nofollow);    /* ← BROKER IPC ROUND-TRIP */
}
return nofollow ? lstat(resolved, st) : stat(resolved, st);   /* ← one syscall */
```

- **Off impersonation** a confined per-child stat is one `lstat(2)` on the
  full resolved path (cheap, but a full-path walk — see C-5).
- **Under impersonation** it is a **round-trip to the root broker process**
  (`xrootd_imp_stat` → IPC) — *orders of magnitude* costlier than a syscall.

So any optimization that *eliminates* a per-child stat (C-1 `d_type`) or
*memoizes* a repeated stat (C-2 negative cache) is **dramatically more valuable
under impersonation**, where each avoided stat saves a broker IPC rather than a
syscall. Conversely, any cache that stores a stat *result* must be **identity-
scoped** under impersonation, because traversal permission (and therefore
`ENOENT`-vs-`EACCES`) is per-mapped-user. Each affected finding states its
impersonation behaviour explicitly.

---

## 1. The stack under audit (self-contained recap)

```
 Protocol handler fills xrootd_vfs_ctx_t, calls an xrootd_vfs_* entry point
   │
   ├── LIVE read funnels:  vfs_open + vfs_file_sendfile_fd      (HTTP, file_serve.c)
   │                       vfs_io_execute READ/READV/PGREAD     (stream, aio/*.c)
   ├── LIVE write funnels: vfs_staged_open + staged_write       (HTTP PUT/POST)
   │                       vfs_io_execute WRITE/WRITEV          (stream, aio/*.c)
   ├── LIVE metadata:      vfs_stat / vfs_copy / vfs_opendir+readdir / vfs_io_execute OPENDIR
   │
   ▼
 VFS public API (src/fs/vfs_*.c)
   │  confinement re-check · write gate · cache integration · metrics · access log
   ▼
 VFS I/O core (src/fs/vfs_io_core.c) — POD jobs, NO pool/metrics/log/cache (thread-safe)
   │  xrootd_vfs_pread_full / pwrite_full / pgread_encode / readv_segments
   ▼
 Storage Driver seam (src/fs/backend/sd.h) — capability-typed vtable
   ▼
 POSIX driver (sd_posix.c) → xrootd_open_beneath / pread(2) / pwrite(2) / xrootd_ns_*
```

### 1.1 The four live funnels, traced (this is the real contract)

The header's promised single read/write funnel does not exist; these four do.
Each trace is the exact call chain with `file:line`, so the rest of the document
can reference a precise step.

**Funnel 1 — HTTP read (WebDAV GET, S3 GetObject), zero-copy sendfile:**
```
webdav/get.c:125   xrootd_vfs_open(&vctx, O_READ)            → fh (rootfd=-1 ⇒ confined_canon open)
shared/file_serve.c:184  xrootd_vfs_file_sendfile_fd(fh)     → sd vtable read_sendfile_fd(obj,0,size,1)
shared/file_serve.c:188  send_fd = dup(fd)
shared/file_serve.c:195  xrootd_vfs_close(fh)                 ← handle released; dup'd fd survives
shared/file_serve.c:197  xrootd_http_send_file_range(send_fd) → nginx builds its OWN in_file buf + sendfile
                          (xrootd_vfs_read / make_file_chain NEVER called)
```

**Funnel 2 — stream `root://` read (kXR_read), AIO offload or inline:**
```
aio/reads.c:247 (worker)  xrootd_vfs_job_read_init(&job,fd,off,len,buf,…)
aio/reads.c:249           xrootd_vfs_io_execute(&job)
  → vfs_io_core.c:162     xrootd_vfs_io_execute_read(job)
  → vfs_read.c:32         xrootd_vfs_pread_full(fd, buf, len, off, &n)
  → vfs_read.c:43         xrootd_sd_posix_driver.pread(&obj, …)   ← SD VTABLE INDIRECTION (A.1)
  → sd_posix.c:255        pread(obj->fd, …)
aio/reads.c:210 (inline fallback) — identical job → io_execute path, on the event-loop thread
```

**Funnel 3 — HTTP write (WebDAV PUT, S3 PutObject/POST), atomic staged:**
```
webdav/put.c:390   xrootd_vfs_staged_open(&vctx, mode, 16, &err)  → O_EXCL temp in export root
                   (loop) write body → staged fd via xrootd_vfs_staged_fd(st)
                          [body chunk → xrootd_vfs_pwrite_full OR sd_posix_staged_write → pwrite]
vfs_staged.c:102   xrootd_vfs_staged_commit(st, excl)             → atomic rename onto final path
vfs_staged.c:130   xrootd_lstat_confined_canon(final)             ← post-commit re-stat FOR METRIC BYTES (B.5)
vfs_staged.c:137   xrootd_vfs_observe_ctx_op(OP_WRITE, bytes, start=ngx_current_msec)  ← (D.1)
                   (xrootd_vfs_write / write_file_buf NEVER called)
```

**Funnel 4 — stream `root://` write (kXR_write/pgwrite/writev), AIO offload:**
```
aio/write.c:25/284  xrootd_vfs_io_execute(&job)   [WRITE or WRITEV]
  → vfs_io_core.c:205 xrootd_vfs_io_execute_write(job)
  → vfs_io_core.c:100 xrootd_vfs_io_write_counted(fd, buf, len, off, …)
  → vfs_io_core.c:123 xrootd_sd_posix_driver.pwrite(&obj, …)  ← SD VTABLE INDIRECTION (A.1)
  → sd_posix.c:268    pwrite(obj->fd, …)
```

**Observation that falls straight out of these traces:** the only layer common to
*all four* live funnels is the **raw byte core** (`pread_full`/`pwrite_full`/
`write_counted`) — which is why **§4 (Pillar A)** is the headline. Funnels 1 and 3
additionally touch the open/handle path (**§5**) and the metric observer (**§7**);
Funnels for metadata (stat/dir/copy) touch the confined-stat helper (**§6**).

### 1.2 The seam's contract (Phase 55), restated precisely

The *raw byte primitives* (`pread`/`pwrite`/`preadv`/`preadv2`/`copy_range`/
`ftruncate`/`fsync`/`fstat`) are declared in `sd.h:141` as **WORKER-SAFE**: no
nginx pool, metrics, log, or cache; runnable from an AIO worker thread. The
*policy* — confinement re-check, metrics, access log, cache, buffer shaping —
stays above the seam in the VFS. The POSIX driver is **behaviour-preserving**:
every slot delegates to the same confined helper the VFS called before the seam
was cut, so the ~5180-test suite is the behaviour oracle. **Crucially**, the three
worker-safe byte loops *hard-code* `xrootd_sd_posix_driver` (they do **not**
dispatch through `obj->driver`) — see A.1, the basis of the headline finding.

---

## 2. Executive summary — the levers, ranked

| # | Lever | Funnel(s) | Effort | Expected gain | Confidence |
|---|---|---|---|---|---|
| **A-1** | Drop the SD-vtable indirection from the raw byte loops (`pread_full`/`pwrite_full`/`write_counted`) | **2, 4** + staged write | trivial | Inlines `pread`/`pwrite` on every stream R/W chunk + HTTP `staged_write`; kills an indirect call + 64 B memzero per 64 KB chunk | **VERIFIED (hot)** |
| **B-1** | Stack-allocate the borrowed POSIX instance (no `pcalloc`) on the hot `root://` open | open path | small | Removes ~3 `pcalloc`/open on the stream open path | **VERIFIED (hot)** |
| **D-1** | Latency metrics use cached `ngx_current_msec` → inline metadata ops report **0 µs** | metadata observers | small | Makes the VFS latency histogram measure inline-op latency (use `CLOCK_MONOTONIC`) | **VERIFIED** |
| **D-2** | The bulk data plane (stream R/W, HTTP sendfile) emits **no** op-latency metric at all | 1, 2, 3, 4 | medium | Closes a histogram blind spot on the busiest ops | **VERIFIED (gap)** |
| **B-2** | Push the existing `POSIX_FADV_*` read-ahead down into the SD `open` slot | 1, 2 | small | Sequential read-ahead for **all** protocols (root://+S3), not just WebDAV GET | **VERIFIED (gap)** |
| **C-1** | Expose `d_type` through `xrootd_sd_dirent_t`; skip per-child stat in `fs_walk` tree walks + LIST | metadata | medium | 1 stat→0 per entry on recursive DELETE/COPY + S3 LIST common-prefix; **saves a broker IPC/entry under impersonation** | **AUDIT** |
| **C-5** | `xrootd_vfs_readdir` stats children by **full path** (`lstat`) not dirfd-relative `fstatat` | metadata | small | O(depth) path-walk → O(1) per child, off-impersonation | **VERIFIED** |
| **C-2** | Per-worker bounded **negative-stat** cache in front of `vfs_stat` (identity-scoped under impersonation) | metadata | medium | Collapses repeat `ENOENT` probes (xcache fill races, namespace browsing) to 1 syscall/IPC | **AUDIT** |
| **C-3** | `CAP_IOURING`-gated **batched `statx`** for `want_stat` dirlist | metadata | large | O(n) sequential `fstatat` → O(1) submit+wait on big stat'd listings (Phase 44) | **AUDIT** |
| **B-5** | `staged_commit`/`vfs_copy` re-stat by path for the metric byte count instead of `fstat`-ing the open fd | 3 + COPY | trivial | Removes 1 path-stat (or broker IPC) per upload/copy | **VERIFIED** |
| **C-4** | dirlist `fstatat` error branch collapses ENOENT and EIO/EACCES identically (silent drop) | metadata | trivial | Surface child I/O/permission errors instead of hiding them | **VERIFIED** |
| **B-3** | Open-time `fstat` snapshot reused for stat-after-open (`stat_current`) | 1, 3 | — | already optimal — **guard against regression** | **VERIFIED** |
| **E-1/2/3** | Wire-or-delete the dead `xrootd_vfs_read`/`write` bodies (path alloc, 64 KB bounce→`copy_file_range`, writethrough pre-scan) | — | medium | unify funnel or delete; sub-opts only matter once wired | **VERIFIED (dead)** |
| **F-1** | **Seam closure** — migrate ~105 confined-helper bypass sites onto `xrootd_vfs_*` so the VFS is the *sole* data/namespace funnel (§9) | all metadata + open + staged | large (phased) | metrics/log/cache for every op; **all** ops follow a non-POSIX backend (Phase 55) instead of being POSIX-pinned | **VERIFIED (backlog)** |
| **F-2** | Close the §9.6 S3-multipart **asymmetry** — confine the part-file *write* side (raw `open` today; the *read* side already is) + replace its userspace `read`/`write` copy loop with `copy_range` | S3 multipart | medium | defence-in-depth (write side gains the read side's `RESOLVE_BENEATH`) + a `copy_file_range` perf win | **VERIFIED (corrected)** |
| **F-3** | Add a **CI seam guard** (`check_vfs_seam.sh` + shrinking allowlist) so no new bypass regresses (§9.9) | build | small | freezes the backlog; makes "VFS = sole source of truth" enforceable | **VERIFIED (absent today)** |

**Shape of the win:** A-1, B-1, B-2, D-1 are near-free, genuinely-hot wins; land
them first. C-1/C-5/C-2/C-3 are the metadata-plane syscall/IPC-amplification
reductions that dominate at high directory/namespace concurrency and under
impersonation. D-2 closes an observability gap. E-1/2/3 are an **architectural
decision** (§3) that must be resolved *before* its sub-optimizations are worth
doing. **F-1/2/3 (§9) are the strategic core**: §3 and §9 together are the two
halves of making the VFS the *sole source of data-plane truth* — delete the dead
funnel, then migrate the ~105 live bypassers onto the real one. F-2 (unconfined S3
multipart) is the one item here with a security edge and should lead.

---

## 3. The architectural finding — the data-plane funnel is bypassed

**`[VERIFIED]`**  `vfs.h` promises one read path (`xrootd_vfs_read`) and one write
path (`xrootd_vfs_write`) so that *"confinement, metrics, access logging,
page-CRC, and cache integration are implemented once and inherited for free."* In
reality (§1.1) the live data plane uses four different funnels and neither marquee
entry point is called.

**Why it happened (benign, traceable):** Phase 54 split every op into
PREPARE/EXECUTE/COMPLETE and routed the *stream* plane through the POD
`xrootd_vfs_io_execute()` job core (so it can run on an AIO worker). The *HTTP*
plane independently grew the zero-copy `vfs_open` + `sendfile_fd` + `file_serve.c`
path (Phase 32/45) and the `staged_open` upload lifecycle (Phase 46). The
chain-shaped `xrootd_vfs_read`/`write` were the *original* unified design and were
left in place as the seam moved underneath them.

**Consequences worth stating plainly:**

1. The CRC32c / cache-access / metrics logic inside `xrootd_vfs_read`/`write` is
   **not** the logic that runs in production — the real per-read CRC lives in
   `xrootd_vfs_io_execute_read` (pgcrc), the real HTTP read metrics in
   `file_serve.c`/dashboard, the real write metrics in the io-core COMPLETE
   callbacks and `staged_commit`. Two implementations of "the same" concern can
   drift, and a future editor may "fix" a bug in the dead copy.
2. Several plausible optimizations target the dead bodies (§8). They are not wins
   until the funnel is unified.

**The decision this phase forces (do this first):**

- **Option A — Unify.** Make `file_serve.c` + the stream read path call
  `xrootd_vfs_read()`, and the HTTP/stream write paths call `xrootd_vfs_write()`.
  Delivers the original design's payoff (one CRC/cache/metrics implementation) and
  makes E-1/E-2 real. **Cost:** non-trivial — HTTP zero-copy sendfile and the
  stream pre-allocated wire buffers must be expressible as `ngx_chain_t` outputs
  without regressing Phase 32/45 zero-copy or Phase 54 thread-safety. The
  `make_file_chain` builder already emits an `in_file` buf for sendfile, so the
  HTTP-read half is the tractable one.
- **Option B — Delete.** Remove `xrootd_vfs_read`/`write` + their private builders
  (~250 lines) and correct `vfs.h` to document the *actual* funnels (§1.1).
  Smallest, most honest move; preserves the seam without pretending an unused path
  is the contract.

**Recommendation (corrected — Option B is NOT free; verified at implementation).**
A first pass said "just delete it". **False:** the dead code is **pinned by a
conformance marker test** — `tests/test_cross_protocol_shared_helpers.py::
test_phase3_vfs_preserves_io_invariants` asserts `vfs_read.c` contains
`b->memory = 1` / `b->in_file = 1` / `xrootd_crc32c_value(` and `vfs_write.c`
contains `xrootd_crc32c_extend(` / `b->in_file` / `ngx_buf_in_memory(`. The marker
suite uses the "dead" `make_*_chain` / `write_*_buf` builders as the **reference
implementation of the TLS-memory-vs-sendfile + per-read-CRC invariants**. Deleting
them breaks the stock suite *and* removes that invariant guard. So Option B first
requires migrating those markers onto a live path (≈ Option A, unify) or relocating
the assertions. **Net: leave the dead code in place** until the funnel is unified or
an object backend makes `make_memory_chain` load-bearing (§10.2), then reintroduce
it *wired*, not revived from a stale copy. (Separately, `make_file_chain`'s
`dup(fh->fd)` marker is itself **stale** post-Phase-55 — `fh->fd` is now
`fh->obj.fd`/`src_fd` — one of three pre-existing red markers unrelated to this
work; the invariant it guards, a dup for sendfile, is intact.)

*Invariant note:* deleting unreferenced code changes no wire behaviour; the oracle
suite is unaffected. Unifying (Option A) is behaviour-sensitive and must hold
every TLS-buffer / sendfile / pgcrc invariant — gate behind the full conformance
suite.

**This finding is only half the story.** §3 is "the documented funnel is dead";
its complement is **§9 (Pillar F)** — "~105 handlers reach *past* the VFS into the
confined-helper layer." Making the VFS the *sole source of data-plane truth*
(`CLAUDE.md` #11) needs both: delete/re-document the dead funnel here, **and**
migrate the live bypassers in §9.

---

## 4. Pillar A — the raw byte I/O core (genuinely hot, all four funnels)

This is the only layer on every live data path (§1.1). The stream plane's
`xrootd_vfs_io_execute()` and the HTTP upload's `staged_write` both bottom out
here.

### 4.1 `[VERIFIED]` A-1 — strip the SD-vtable indirection from the raw byte loops — **the headline**

`xrootd_vfs_pread_full` (`vfs_read.c:31`), `xrootd_vfs_pwrite_full`
(`vfs_write.c:32`), and `xrootd_vfs_io_write_counted` (`vfs_io_core.c:100`) each
do, per iteration:

```c
xrootd_sd_obj_t obj;
xrootd_sd_posix_wrap(&obj, fd);                    /* ngx_memzero(&obj, 64 B) + set 2 fields */
while (done < len) {
    ssize_t n = xrootd_sd_posix_driver.pread(&obj, buf+done, len-done, off+done);
    /* xrootd_sd_posix_driver.pread = function pointer load → call sd_posix_pread
     *   → which is literally `return pread(obj->fd, buf, len, off);`            */
    ...
}
```

**Two facts make this pure overhead today:**

1. The three helpers **hard-code the `xrootd_sd_posix_driver` symbol** — they do
   *not* dispatch through `obj->driver`. So they are POSIX-only by construction;
   the indirection exercises **no** backend pluggability. (Verified: `grep -n
   'driver\.\|driver->' src/fs/vfs_read.c src/fs/vfs_write.c
   src/fs/vfs_io_core.c` shows only the literal `xrootd_sd_posix_driver.` form.)
2. They are the per-chunk inner loop on every funnel. `write_file_buf` and the
   stream offloads iterate in 64 KB chunks (`XROOTD_VFS_COPY_CHUNK = 65536`,
   `vfs_internal.h:45`). A 1 GB transfer ⇒ ~16 384 iterations, each paying: a
   non-inlinable indirect call through a vtable slot, wrapping a one-line syscall
   the compiler could otherwise inline and the branch predictor could otherwise
   see straight through.

**Per-iteration cost removed (qualitative, to be confirmed by `perf` — §11.1):**
one indirect-call dispatch (defeats inlining of `pread`/`pwrite`; one extra I-cache
line for `sd_posix_pread`'s prologue/epilogue; one indirect-branch-predictor slot)
plus, for the `write_counted` path, a 64-byte `ngx_memzero` of the throwaway
`xrootd_sd_obj_t`. None of it is large per call; the point is it is *per chunk on
the busiest loops in the module* and buys nothing.

**Fix:** call the syscall directly in these three worker-safe primitives; keep the
seam where the contract actually lives — the *object* ops (`open`/`close`/`fstat`/
namespace), which *do* dispatch through `obj->driver` and *are* where a non-POSIX
backend differs:

```c
/* xrootd_vfs_pread_full — the raw primitive is POSIX by definition; the seam value
 * is above this loop (driver->open/fstat/stat), not in pread(2). */
ngx_int_t
xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len, off_t offset, size_t *nread)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, buf + done, len - done, offset + (off_t) done);
        if (n < 0) { if (errno == EINTR) continue;
                     if (nread) *nread = done; return NGX_ERROR; }
        if (n == 0) break;
        done += (size_t) n;
    }
    if (nread) *nread = done;
    return NGX_OK;
}
```

(`pwrite_full` and `write_counted` symmetrically.)

**Why this does not break the Phase-55 seam.** `sd.h:141` already documents the
raw byte ops as worker-safe and the POSIX slots as `pread(obj->fd, …)` *verbatim*.
A non-POSIX backend never reaches these loops — it owns its EXECUTE phase (its own
`pread`/`pwrite` slot, dispatched at the *object* level where `obj->driver` is
consulted). If a future backend genuinely needs to intercept the byte loop, the
correct move is to resolve `obj->driver->pread` into a local function pointer
*once* before the loop (so the inner call is direct), not to re-pay the dispatch
per iteration. For POSIX the honest form is a direct `pread`.

*Invariant note:* byte-identical I/O — same EINTR retry, same short-read/short-
write accounting, same `errno`, same 0-byte-pwrite⇒EIO rule. No confinement change
(the fd is the already-confined `RESOLVE_BENEATH` descriptor). **Measure** (§11.1):
large-transfer throughput + `perf stat -e instructions,branch-misses` delta. The
win is real but workload-dependent — benchmark, do not assert a number.

### 4.2 `[VERIFIED]` A-2 — `xrootd_sd_posix_wrap` memzeroes a 64-byte struct; keep it out of the loop

Rolls into A-1. `xrootd_sd_posix_wrap` (`sd.h:250`) does
`ngx_memzero(obj, sizeof(*obj))` over the full `xrootd_sd_obj_t` (driver + inst +
fd + `xrootd_sd_stat_t snap` + state ≈ 64 B). In `pread_full`/`pwrite_full` it is
already correctly hoisted *above* the loop (good — the fd does not change across
iterations); in `write_counted` it is likewise once per call. With A-1 the wrap
disappears entirely. If A-1 is rejected, the reviewed invariant must be *"wrap once
per call, never per iteration"* — and the `snap`/`state` fields it zeroes are never
read on this path, so even the once-per-call memzero is only defensive.

---

### 4.3 `[VERIFIED]` A-3 — 18 byte loops bypass the VFS primitives (SD-vtable-direct)

Discovered while implementing A-1 (§9.3). Beyond the three VFS byte *primitives*
A-1 fixed, **18 other byte loops in 11 files** call `xrootd_sd_posix_driver.
(pread|pwrite|preadv|copy_range)(&obj, …)` directly — each re-deriving the
EINTR/short-I/O loop instead of calling `xrootd_vfs_pread_full`/`pwrite_full`. They
carry **both** problems: A-1's no-op POSIX indirection **and** a Pillar-F-class VFS
bypass (unmetered, POSIX-pinned, Phase-54-violating). Full list:

| File | Op(s) | Plane | Migrate to |
|---|---|---|---|
| `read/read.c:373`, `read/readv.c:175`, `read/pgread.c:137` | `preadv` | stream read **hot** | a VFS vectored-read primitive (`xrootd_vfs_preadv_full`, new) or the io-core |
| `compat/checksum_core.c` (×3) | `pread` | checksum compute | `xrootd_vfs_pread_full` |
| `compat/http_body.c` (×3) | `pwrite`/`pread` | HTTP body spool + file read | `xrootd_vfs_pread_full`/`pwrite_full` |
| `compat/copy_range.c` (×3) | `pread`/`pwrite`/`copy_range` | copy fallback | `pread_full`/`pwrite_full` + a VFS `copy_range` primitive |
| `compat/http_compress.c` | `pread` | compressed GET | `xrootd_vfs_pread_full` |
| `s3/aws_chunked.c` (×2), `s3/post_object.c` | `pread`/`pwrite` | S3 upload decode/spool | `pread_full`/`pwrite_full` |
| `webdav/tpc_curl.c` | `pwrite` | TPC relay | `xrootd_vfs_pwrite_full` |
| `cache/writethrough_flush.c` | `pread` | cache plane | cache-internal (like `read/stat.c`, §9.7) |

**Why it matters:** once these route through `xrootd_vfs_pread_full`/`pwrite_full`,
they inherit A-1's direct-syscall path *and* the single EINTR/short-I/O policy, and
the byte plane finally funnels through the VFS (Phase 54's goal) — closing the gap
§9.3 now documents. **Fix:** the simple `pread`/`pwrite` cases are a 1-line swap to
the VFS primitive; the three `preadv` hot-read sites and the `copy_range` fallback
need a small new VFS primitive each (`xrootd_vfs_preadv_full`,
`xrootd_vfs_copy_range`) — so A-3 is a **medium** effort, sequenced after A-1.
*Invariant note:* byte-identical (the VFS primitives perform the same syscalls);
the win is funnel-uniformity + the A-1 inlining. **Status:** the data-plane
migration is *not yet implemented* — A-1 (the 5 primitives) shipped this revision;
A-3a (strip the indirection from these 18) and A-3b (route them through the VFS
primitives + add `xrootd_vfs_preadv_full`/`xrootd_vfs_copy_range`) are the
follow-up. **However, the §9.9 CI guard was extended this revision to also reject
new `xrootd_sd_posix_driver.<byteop>` calls** outside the VFS/driver layer — so this
backlog is **frozen** (it can only shrink) even before the migration lands. Since
A-1 made `src/fs/` clean of driver byte-ops, the guard's tier-1.5 allowlist is
exactly these 11 files.

## 5. Pillar B — open / handle lifecycle

### 5.1 `[VERIFIED]` B-1 — the hot `root://` open allocates a throwaway POSIX instance

`xrootd_vfs_open` (`vfs_open.c:350-381`), `rootfd >= 0` branch — the stream
`root://` data-server hot open path (HTTP uses `rootfd=-1`, see B-4):

```c
if (ctx->sd == NULL) {
    ctx->sd = xrootd_sd_posix_borrow_instance(ctx->pool, ctx->log,
                                              ctx->rootfd, ctx->root_canon);  /* 2× pcalloc */
}
o = ctx->sd->driver->open(ctx->sd, path, xrootd_vfs_to_sd_flags(flags), 0644, &sderr);  /* 1× pcalloc */
fd = o->fd;   /* o->snap is never read — adopt_fd re-fstats below (vfs_open.c:396) */
```

`xrootd_sd_posix_borrow_instance` (`sd_posix.c:159`) does **two `ngx_pcalloc`s**
(instance + `sd_posix_state_t`) to wrap three already-available values (`rootfd`,
`root_canon`, the static POSIX driver), and `sd_posix_open` `pcalloc`s a **third**
object whose captured metadata is immediately discarded (the comment at
`vfs_open.c:357` acknowledges this). `ctx->sd` caches within one ctx, but the ctx
is per-operation, so this is ~3 `pcalloc`s per stream open — and stream opens
(`kXR_open`) are the highest-frequency control op on a busy data server.

The fallback branch one line down already shows the zero-alloc form:
`fd = xrootd_open_beneath(ctx->rootfd, path, oflags, 0644);` — which is *exactly*
the syscall `sd_posix_open` performs.

**Fix (preserves the seam, zero heap).** Two acceptable shapes:

- **Stack borrow:** add an in-place init that writes a caller-provided **stack**
  `xrootd_sd_instance_t` + `sd_posix_state_t` (no `pcalloc`), and have
  `sd_posix_open` accept a caller-provided stack `xrootd_sd_obj_t` for the hot
  path (it only needs `driver`+`inst`+`fd`).
- **Direct call (simplest, equivalent for POSIX):** in the `rootfd >= 0` branch
  call `xrootd_open_beneath(ctx->rootfd, path, oflags, 0644)` directly, and reserve
  the `driver->open` dispatch for `ctx->sd != NULL && driver != posix` (a configured
  non-POSIX backend). The discarded-obj `pcalloc` in `sd_posix_open` vanishes with it.

```c
if (ctx->rootfd >= 0) {
    if (ctx->sd != NULL && ctx->sd->driver != &xrootd_sd_posix_driver
        && ctx->sd->driver->open != NULL) {
        /* configured non-POSIX backend: route through the seam */
        xrootd_sd_obj_t *o = ctx->sd->driver->open(ctx->sd, path, sdflags, 0644, &sderr);
        if (o == NULL) { *err_out = sderr; errno = sderr; return NULL; }
        fd = o->fd;
    } else {
        /* default POSIX: the seam's open == this exact confined syscall */
        fd = xrootd_open_beneath(ctx->rootfd, path, oflags, 0644);
    }
}
```

*Invariant note:* identical confinement (`xrootd_open_beneath` =
`openat2(RESOLVE_BENEATH)` either way) and identical fd. No behaviour change; the
suite is the oracle. *Lifetime risk (see §13):* if the stack-borrow shape is
chosen, assert no path stores `ctx->sd` past the synchronous open call.

### 5.2 `[VERIFIED gap]` B-2 — push the read-ahead hint down into the SD `open` slot

The tree already has mature `POSIX_FADV_WILLNEED` machinery — but only at two
layers, applied *after* open by each protocol:

- **WebDAV:** `webdav_fadvise_willneed` (`src/webdav/io.c:76`), called from
  `webdav/get.c:55` for the whole file.
- **Stream read:** `src/read/prefetch.{c,h}` — windowed, sequential-pattern-aware
  (`read_last_end`/`read_ahead_end`), HEP-tuned 1 MiB/32 MiB/8 MiB constants.

The **S3 GetObject** path and any future backend get **no** hint, and
`sd_posix_open` (`sd_posix.c:198`) returns a bare `open(2)` fd with default kernel
read-ahead.

**Fix — a capability-typed `read_advise` slot on the seam** so every protocol
inherits one implementation and a non-POSIX backend can map it (object-store
range-prefetch, io_uring `IORING_OP_FADVISE`, or no-op):

```c
/* sd.h — new optional slot (NULL ⇒ backend has no advice primitive) */
ngx_int_t (*read_advise)(xrootd_sd_obj_t *obj, off_t off, size_t len, int advice);
/* advice ∈ { XROOTD_SD_ADV_SEQUENTIAL, XROOTD_SD_ADV_WILLNEED, XROOTD_SD_ADV_RANDOM } */

/* sd_posix.c */
static ngx_int_t
sd_posix_read_advise(xrootd_sd_obj_t *obj, off_t off, size_t len, int advice)
{
#if defined(POSIX_FADV_SEQUENTIAL)
    int a = advice == XROOTD_SD_ADV_WILLNEED ? POSIX_FADV_WILLNEED
          : advice == XROOTD_SD_ADV_RANDOM   ? POSIX_FADV_RANDOM
          :                                    POSIX_FADV_SEQUENTIAL;
    return posix_fadvise(obj->fd, off, (off_t) len, a) == 0 ? NGX_OK : NGX_ERROR;
#else
    (void)obj;(void)off;(void)len;(void)advice; return NGX_OK;
#endif
}
```

The VFS read PREPARE calls `read_advise` once at open (`SEQUENTIAL` for a streaming
GET) and the existing `src/read/prefetch.c` windowed `WILLNEED` logic is expressed
*through* the slot. The ad-hoc `webdav/io.c` hint is then retired in favour of one
seam-level implementation.

*Caveat (honest):* `SEQUENTIAL` and `WILLNEED` are different tools — `SEQUENTIAL`
grows the read-ahead window for the whole fd (right for streaming GET); `WILLNEED`
forces immediate range read-ahead (right for the prefetch subsystem's windowed
pattern). The slot passes the hint through; do not collapse them. *Invariant note:*
fadvise is advisory — zero correctness impact, ignored hints log-and-continue (as
`webdav/io.c:88` already does). **Measure** (§11.3) on cold-cache large sequential
reads; on a warm page cache it is a no-op.

### 5.3 `[VERIFIED — already optimal, guard against regression]` B-3 — open-time `fstat` snapshot

`adopt_fd` (`vfs_open.c:141`) captures size/mtime/ctime/mode/ino via one
`driver->fstat` at open and sets `fh->stat_current = 1`; `xrootd_vfs_file_stat`
(`vfs_open.c:499`) answers from that snapshot when current, and `xrootd_vfs_write`
clears the bit (`vfs_write.c:243`) so a write-then-stat still does a live `fstat`.
This is the Phase-45 W2/R1 optimization, **correct and complete** — the S3/WebDAV
GET pattern (open then immediately stat for `Content-Length`/`ETag`) pays exactly
one `fstat`. No action; listed so a future editor does not "simplify" the
`stat_current` bit away. *Invariant note:* the write-clears-bit logic is the
correctness guard — keep it.

### 5.4 `[AUDIT]` B-4 — HTTP front ends pay a per-request root-anchor open

Adjacent to the seam: HTTP callers build their ctx with `xrootd_vfs_ctx_init`,
which sets `rootfd = -1` (`vfs_open.c:49`). So `xrootd_vfs_open` takes the
`root_canon`-only branch → `xrootd_open_confined_canon` (`vfs_open.c:382`), which
*opens the rootfd per call* (comment at `:341`) — i.e. an extra `open(O_PATH)` of
the export root per HTTP request, on top of the file open. The stream plane avoids
this via the persistent per-worker rootfd. Giving the HTTP front ends a per-worker
persistent O_PATH export anchor (opened once) removes one `openat` per HTTP
GET/PUT/stat. *Confidence AUDIT:* needs confirmation the HTTP location conf can
hold a persistent per-worker fd across config reload — Phase-55 already plans
per-export instances, the natural home. *Invariant note:* `xrootd_open_confined_canon`
and `xrootd_open_beneath` are the same `RESOLVE_BENEATH` semantics; only the anchor
lifetime changes.

### 5.5 `[VERIFIED]` B-5 — `staged_commit`/`vfs_copy` re-stat by path for the metric byte count

`xrootd_vfs_staged_commit` (`vfs_staged.c:130`) and `xrootd_vfs_copy`
(`vfs_copy.c:76`) both do, purely to fill the `bytes` argument of the metric:

```c
if (xrootd_lstat_confined_canon(st->log, root_canon, final_path, &sb, 1) == 0
    && S_ISREG(sb.st_mode))
    bytes = (size_t) sb.st_size;
```

For **`staged_commit`** the staged fd is still open at commit (`staged_commit`
renames; only `abort` closes — `staged_file.c`), so the size is available via a
cheap `fstat(staged.fd)` taken *before* the rename, avoiding a fresh path stat.
**Under impersonation** this matters more: the path `xrootd_lstat_confined_canon`
becomes a broker IPC round-trip per upload, whereas `fstat` on the already-open fd
is a local syscall.

*Fix:* capture the committed size with `fstat(xrootd_vfs_staged_fd(st), &sb)`
before the rename (or have the staged primitive return the final size from its own
pre-rename `fstat`). For `vfs_copy`, `xrootd_ns_local_copy` already opens/writes
the destination internally and could return `bytes_out` (the SD `server_copy` slot
already has an `off_t *bytes_out` parameter — `sd.h:170` — it is simply not plumbed
back to `vfs_copy`); plumb it through instead of a post-copy path stat.

*Invariant note:* metric byte-count only; a wrong/zero count never affects the
return value or wire response (both call sites already treat the stat as
best-effort). **Measure** (§11.5): upload/copy op count under impersonation (broker
IPC/op should drop by one).

---

## 6. Pillar C — metadata & directory plane (syscall/IPC amplification)

### 6.1 `[AUDIT]` C-1 — expose `d_type` through `xrootd_sd_dirent_t` for tree-walk + LIST consumers

`xrootd_sd_dirent_t` (`sd.h:89`) carries only `char name[256]`; `sd_posix_readdir`
(`sd_posix.c:500`) and `xrootd_vfs_readdir` (`vfs_dir.c:115`) both drop
`de->d_type`. Linux `readdir(3)` returns `d_type` (DT_REG/DT_DIR/DT_LNK/
DT_UNKNOWN) for free on ext4/xfs/btrfs/tmpfs.

**Where it does *not* help (be precise).** The `kXR_dirlist` wire builder
(`xrootd_vfs_io_execute_opendir`) `fstatat`s only when `want_stat` is set
(`vfs_io_core.c:592`), and when it does it needs the *full* stat body (size, mtime,
mode bits) for the dstat wire format — `d_type` cannot replace that. Plain
(no-stat) dirlist already does zero per-entry `fstatat`. So `d_type` buys the
dirlist wire path nothing.

**Where it *does* help — the central tree walker `fs_walk.c`.** Its own header
states: *"opendir/readdir/lstat with dot-filtering … used by DEL/MOVE/COPY on
collections … XRootD dirlist, WebDAV PROPFIND, S3 ListObjects."* Every consumer
that only needs **file-vs-dir classification** pays a full stat per child today:

- recursive `DELETE`/`rmdir` and `COPY` tree walks (`xrootd_fs_remove_tree_confined`
  and the `fs_walk` callback, reached from `xrootd_ns_delete` recursive at
  `namespace_ops.c:219`);
- S3 `ListObjects` common-prefix (directory) vs object detection;
- any `xrootd_vfs_readdir` caller that branches on `stat_out->is_directory`.

For these, `d_type` turns 1 stat → 0 per entry, with a `DT_UNKNOWN` fallback to the
stat for filesystems that do not fill it. **Under impersonation each avoided stat
is an avoided broker IPC** (§0.3) — so on a 10 000-entry collection delete this is
10 000 fewer broker round-trips. This is the seam-level enabler for Phase 30 §B.3
("Listing syscall amplification — PROPFIND / S3 LIST / COPY tree").

**Fix:**
```c
/* sd.h */
typedef struct { char name[256]; unsigned char d_type; } xrootd_sd_dirent_t;
/* sd_posix_readdir: out->d_type = de->d_type; */
/* xrootd_vfs_readdir: expose d_type on the public dir API so consumers can
 * classify; fall back to stat only when d_type == DT_UNKNOWN or full metadata
 * (size/mtime) is genuinely needed. */
```
plus a `readdir`-time `is_dir`/`is_reg` fast path in the `fs_walk` callback and the
LIST consumers, gated on `d_type != DT_UNKNOWN`.

*Invariant note:* `d_type` is metadata-only and **never** a confinement or
authorization decision — the actual open/delete still goes through
`RESOLVE_BENEATH` / the confined unlink. A spoofed `d_type` on a hostile FS can
only cause a fallback stat, never an escape. *Confidence AUDIT:* the per-consumer
wins need tracing + measurement on real large directories (§11.4).

### 6.2 `[VERIFIED]` C-5 — `xrootd_vfs_readdir` stats children by full path, not dirfd-relative

`xrootd_vfs_readdir` with `stat_out != NULL` (`vfs_dir.c:139-158`) builds the full
child path and stats it by that path:

```c
n = snprintf(child, sizeof(child), "%s/%s", dh->path, de->d_name);   /* full path   */
xrootd_lstat_confined_canon(dh->log, dh->root_canon, child, &st, 1); /* re-walks it */
```

Off impersonation, `xrootd_lstat_confined_canon` is `lstat(child)` (§0.3) — the
kernel re-walks **every** path component from the mount root for each child. The
io-core dirlist path does the fast thing — `fstatat(dfd, name, &st,
AT_SYMLINK_NOFOLLOW)` (`vfs_io_core.c:596`) — resolving in O(1) from the already-open
directory fd. So the streaming and batch dirlist halves are inconsistent: one is
O(depth) per child, the other O(1).

**Why the slow form exists:** the broker-routed per-child lstat (impersonation)
needs the logical *rel* path, which `xrootd_lstat_confined_canon` derives. So the
fast `fstatat(dirfd(dh->dir), name, …)` is correct **only off impersonation**.

*Fix:* when `!xrootd_imp_client_active()`, stat children with `fstatat(dirfd(
dh->dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW)`; keep the confined-canon path only
under impersonation (where the broker route is mandatory). Combined with C-1, the
common off-impersonation listing pays zero or one *O(1)* stat per child instead of
one *O(depth)* lstat. *Invariant note:* `fstatat` on the confined directory fd
cannot escape the directory (the fd is already `RESOLVE_BENEATH`-anchored;
`AT_SYMLINK_NOFOLLOW` preserves the no-follow semantics). **Measure** (§11.4):
PROPFIND/LIST syscall count on a deep, wide tree.

### 6.3 `[AUDIT]` C-2 — per-worker bounded negative-stat cache in front of `vfs_stat`

`xrootd_vfs_stat` (`vfs_stat.c:50`) → `xrootd_lstat_confined_canon` issues a
syscall (or broker IPC under impersonation) on every call. Two live patterns
hammer the same negative result:

1. **xcache fill races** — concurrent readers probing a path not yet in the cache
   root (`open_cache.c` two-step resolution) each stat the same absent cache path
   during a fill window.
2. **Namespace browsing** — `kXR_stat`/PROPFIND/S3 HEAD on not-yet-existent paths
   (client "does this exist?" probes) repeat.

**Design (per-worker, lockless, no SHM):**
```c
#define NEG_STAT_SLOTS 256          /* power of two */
typedef struct { uint64_t hash; ngx_msec_t expire; } neg_stat_ent_t;
static neg_stat_ent_t neg_stat[NEG_STAT_SLOTS];   /* per-worker (no cross-worker share) */

/* key = FNV1a(root_canon) ⊕ FNV1a(resolved_path)  [⊕ FNV1a(mapped_uid) under imp] */
/* lookup: slot = hash & (NEG_STAT_SLOTS-1); hit iff ent.hash==hash && now<ent.expire
 *         ⇒ return ENOENT without the syscall. TTL ≈ 1 s. */
/* insert: only on a genuine ENOENT result (never EACCES/EIO; never a positive). */
/* invalidate: every successful create/mkdir/rename/staged_commit through THIS worker
 *             clears the target's slot (the VFS already sees every mutator). */
```

Sits in `vfs_stat.c` immediately before `xrootd_lstat_confined_canon`. Positive
stats are **not** cached (they carry size/mtime that must be live).

*Impersonation:* key MUST include the mapped UID (a path that is `ENOENT` for the
worker may be `EACCES`-masked vs genuinely absent per mapped user), or the cache
must be disabled under impersonation. Default-off either way.

*Invariant note (this is the dangerous one — see §13):* a negative-stat cache can
turn a real file into a **false `ENOENT`** if a cross-worker create is not seen.
Mitigations are mandatory: per-worker only (never cross-worker), short TTL, cleared
by every same-worker mutator, identity-scoped under impersonation, **default off**,
and a 3-tests rule including a create-after-negative-probe race test. *Confidence
AUDIT:* hit-rate is entirely workload-shaped — measure on `test_metadata_stress`
(§11.4) before trusting it.

### 6.4 `[AUDIT]` C-3 — `CAP_IOURING`-gated batched `statx` for `want_stat` dirlist

`XROOTD_SD_CAP_IOURING` is declared (`sd.h:56`) but **no driver slot consumes it**.
The `want_stat` dirlist (`vfs_io_core.c:727` loop) does one **sequential**
`fstatat` per entry — a 10 000-entry stat'd listing is 10 000 serialized syscall
round-trips inside one worker task.

Because the OPENDIR job already runs the *entire* scan in one worker thread
(Phase 54), an io_uring-capable POSIX backend can, within that same task: (1)
`readdir` names into a local array; (2) submit one batch of `IORING_OP_STATX` for
all entries; (3) `io_uring_submit_and_wait` once. O(n) round-trips → O(1) submit +
O(1) wait, with no event-loop interaction (the worker blocks on the ring exactly as
it blocks on `fstatat` today). This is the natural first `CAP_IOURING` consumer and
dovetails with the Phase-44 io_uring backend and Phase-55.D's `CAP_IOURING`-gated
orthogonality.

**Fix:** a second registered driver (`"posix_uring"`, or a runtime-probed
capability on the POSIX driver) adding a batch-statx hook the dirlist EXECUTE phase
calls when `want_stat && (caps & CAP_IOURING)`; fall back to the sequential loop
otherwise (and for small directories below a crossover threshold). *Invariant
note:* identical wire output (same dstat body, ordering, filtering); only *how* the
stats are gathered changes; the statx targets are `dirfd`-relative names under the
already-confined directory fd. *Confidence AUDIT:* crossover point + liburing/kernel
availability gating must be measured (§11.6). Large effort — sequence behind
Phase 44.

### 6.5 `[VERIFIED]` C-4 — dirlist `fstatat` error branch hides child I/O/permission errors

`xrootd_vfs_io_dirlist_stat_entry` (`vfs_io_core.c:596`):
```c
if (fstatat(dfd, name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0) {
    return errno == ENOENT ? NGX_DECLINED : NGX_DECLINED;   /* both arms identical */
}
```
The ternary returns `NGX_DECLINED` for *both* ENOENT and every other errno, so any
stat failure silently drops the entry. A real `EIO`/`EACCES` on a child is
indistinguishable from the benign "entry vanished mid-scan" (`ENOENT`) race.
*Fix:* keep silently skipping the benign ENOENT race (correct), but **log** the
non-ENOENT case at `NGX_LOG_ERR` (a permission/IO error on a child is
operationally interesting and currently invisible) before declining. *Invariant
note:* listing output unchanged; this only adds a diagnostic.

---

## 7. Pillar D — observability resolution

### 7.1 `[VERIFIED]` D-1 — VFS latency metrics are blind to inline-op latency

`xrootd_vfs_elapsed_usec` (`vfs_internal.h:231`):
```c
now = ngx_current_msec;
if (now < start_msec) return 0;
return (now - start_msec) * 1000;     /* ms delta, scaled to "µs" */
```
`ngx_current_msec` is nginx's **cached** clock — it advances on event-loop ticks /
timer processing, **not** per call. Two consequences:

1. A **synchronous** VFS metadata op that completes without returning to the event
   loop (a warm `stat`, `mkdir`, `rename`, fast `staged_commit`) sees `now ==
   start` ⇒ reports **0 µs**. The histogram structurally cannot see inline-op
   latency — only ops that crossed a thread-pool round-trip (during which the loop
   ticked) register a non-zero value.
2. Even then, resolution is milliseconds dressed as microseconds (`* 1000`), so the
   entire sub-millisecond band quantizes to 0 or 1000 µs.

The metric API itself is fine — `xrootd_metric_op_done(proto, op, bytes,
latency_usec, err)` (`unified.h:121`) *"files latency_usec (microseconds) into the
single matching histogram bucket plus count and sum."* It is being **fed** a fake
value.

**Fix:** capture a real monotonic timestamp at op start and plumb it through
`xrootd_vfs_observe_*`:
```c
/* vfs_internal.h */
static ngx_inline uint64_t xrootd_vfs_now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);    /* vDSO, ~20 ns */
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}
/* elapsed_usec = (now_ns - start_ns) / 1000  → real sub-ms resolution */
```
Note `CLOCK_MONOTONIC_COARSE` does **not** fix this — it is also ~1–4 ms
granularity; it would only fix the "frozen during an inline op" half, not the
resolution. Since these are latency histograms where sub-ms is the interesting
band, use full `CLOCK_MONOTONIC`.

*Invariant note:* metrics-only change, zero data-plane effect. *Scope:* the LIVE
ctx-op observers — `vfs_stat`, `vfs_copy`, `vfs_rename`, `vfs_unlink`, `vfs_mkdir`,
`vfs_opendir`, `staged_commit`. **Measure** (§11.2): confirm the ~20 ns/op overhead
is lost in the syscall noise and that buckets are configured for the now-visible
sub-ms range. Low-cardinality labels unchanged.

### 7.2 `[VERIFIED gap]` D-2 — the bulk data plane emits no op-latency metric at all

Verified this sweep: there are only **10** references to `xrootd_metric_op_done`
tree-wide (including its definition), and **none** in `src/aio/*.c`,
`src/read/read.c`, or `src/write/write.c`. So the high-volume **stream read/write**
and **HTTP sendfile** ops emit **no** per-op latency at all — their accounting is
byte counters on the handle/session, not the op-latency histogram. The VFS latency
series therefore covers only the metadata/namespace ops (stat/copy/rename/unlink/
mkdir/dirlist/staged_commit), which are precisely the *low*-volume ops.

The result: the latency histogram has a blind spot exactly over the busiest ops.
An operator watching `xrootd_*_op_latency` cannot see read/write tail latency — the
thing most likely to matter for a HEP data server.

**Fix:** emit `xrootd_metric_op_done(READ/WRITE, bytes, latency_usec, err)` from the
io-core COMPLETE callbacks (`aio/reads.c` / `aio/write.c` done handlers) and from
the HTTP `file_serve.c` post-send accounting, timed with the D-1 monotonic clock
(captured in PREPARE, consumed in COMPLETE — both run on the event-loop thread, so
no thread-safety issue; the timestamp travels in the job/task struct). *Invariant
note:* additive metric only; low-cardinality labels (proto, op, err-class) — **no**
per-handle/per-path labels. *Confidence:* the gap is VERIFIED; the *cost* of adding
a histogram increment per data op must be measured (§11.2) — it is one atomic
bucket bump (`xrootd_metric_op_done` is "lock-free via atomics"), but on the hot
read/write path even that should be confirmed negligible. Pairs naturally with D-1.

---

## 8. Pillar E — latent wins inside the dead funnel (wire-or-delete first)

**Read §3 before touching anything here.** Every item is real code with a real
inefficiency, but it sits inside `xrootd_vfs_read` / `xrootd_vfs_write`, which have
**no callers**. Optimizing them now changes nothing in production. They become
genuine wins *only if* §3 Option A (unify) is chosen; if Option B (delete) is
chosen they vanish with the dead code. Catalogued so the decision is informed and
nobody mistakes them for hot-path work.

### 8.1 `[VERIFIED, dead]` E-1 — `make_file_chain` allocates+copies the path per read

`xrootd_vfs_make_file_chain` (`vfs_read.c:163-171`) `ngx_pnalloc`s and `ngx_memcpy`s
`fh->path` into `b->file->name.data` — but `fh->path` already lives on the same
`fh->pool` with the same lifetime, used only for nginx's log line. If the funnel
were wired this would be one needless alloc+copy per cleartext read; the fix is
`b->file->name.data = (u_char *) fh->path; b->file->name.len = strlen(fh->path);`.
**Today: dead.**

### 8.2 `[VERIFIED, dead]` E-2 — `write_file_buf` bounces `in_file` payloads through a 64 KB stack buffer

`xrootd_vfs_write_file_buf` (`vfs_write.c:68-114`) streams an `in_file` buffer
through `u_char tmp[65536]` via `pread_full` + `pwrite_full`. The seam already
exposes `copy_range` (`sd_posix_copy_range` = `copy_file_range(2)`, `sd_posix.c:305`)
for exactly this kernel-side zero-copy move (with an EXDEV fallback). If the funnel
were wired and an `in_file` payload reached it, routing same-filesystem moves
through `driver->copy_range` would eliminate the 64 KB stack bounce and the
userspace copy. **Today: dead** — and the live PUT path (`staged_write`) takes a
*memory* buffer, not an `in_file` chain, so the opportunity does not exist on a
live path. (The live COPY path `xrootd_vfs_copy` → `xrootd_ns_local_copy` already
uses `copy_file_range`.)

### 8.3 `[VERIFIED, dead]` E-3 — writethrough pre-scan runs unconditionally for a debug log

`xrootd_vfs_write` (`vfs_write.c:204-211`) calls `xrootd_vfs_write_chain_length(in)`
(a full chain walk) and `xrootd_cache_should_writethrough(...)` on every write, and
uses the result **only** to emit `ngx_log_debug2`. `xrootd_cache_should_writethrough`
(`writethrough_decision.c:214`) early-returns `DENY` when `!ctx->cache_writethrough`,
so when writethrough is off the chain walk is pure waste. If wired, gate the block
on `fh->ctx->cache_writethrough`. **Today: dead.** (Writethrough itself is a live
feature — flush at `kXR_sync`/`kXR_close` via `cache/writethrough_flush.c` — and
does not depend on this dead pre-scan.)

---

## 9. Pillar F — closing the seam: the VFS as the sole source of data-plane truth

This pillar is the **complement of §3** and the headline of this revision. §3
found that the VFS's *documented* funnel is dead (nothing calls
`xrootd_vfs_read`/`write`). This pillar finds the other half: a large backlog of
handlers that reach **past** the VFS, straight into the confined-helper layer the
POSIX driver is supposed to own. Making the VFS the *sole source of data
management and truth* (`CLAUDE.md` invariant #11) requires **both** halves: (a)
wire-or-delete the dead funnel (§3), and (b) migrate every bypasser onto the VFS
surface (this pillar). Until both land, "the VFS is the data plane" is an
aspiration, not a fact.

**Why it matters (what bypass actually costs).** Every bypass below is *confined*
(it goes through `xrootd_*_confined_canon` / `xrootd_*_beneath` / `xrootd_ns_*`,
which enforce `RESOLVE_BENEATH`) — except the §9.6 subset, which is **not**. So
this is mostly not a *security* hole; it is a **truth** hole. A bypassing op:

1. emits **no** VFS metric and **no** access-log line (it skips
   `xrootd_vfs_observe_*`) — so dashboards and audit logs undercount it;
2. is invisible to the read-through **cache** and write-through logic;
3. cannot be served by a **non-POSIX backend** — when the Phase-55 object/block
   driver lands, only ops that went through `xrootd_vfs_*` follow the configured
   backend; a direct `xrootd_open_beneath` is hard-wired to POSIX forever;
4. re-implements confinement-string juggling (`strip root_canon → rel`) inline at
   ~20 sites, each a place a future bug can de-confine one path.

So seam-closure is the precondition for the entire Phase-55 promise (swap the
backend, inherit it everywhere) **and** for honest observability.

### 9.1 The layering, and what "bypass" means precisely

```
 handler  ──►  xrootd_vfs_*            (src/fs/)            ◄── the ONLY layer a handler may call
                 └─► SD vtable          (src/fs/backend/sd.h)
                       └─► sd_posix      (src/fs/backend/sd_posix.c)
                             └─► xrootd_open_beneath / xrootd_ns_* /          ◄── the "POSIX / confined-helper
                                 xrootd_*_confined_canon / xrootd_staged_* /      layer": src/path/, src/compat/
                                 fs_walk                                          {namespace_ops,staged_file,fs_walk}
                                   └─► openat2(RESOLVE_BENEATH) / pread / …    (libc)
```

- **Tier-1 bypass** = a handler calls **libc** directly on export data/namespace
  (`open`/`pread`/`stat`/`openat`/…). The most serious kind; the rawest.
- **Tier-2 bypass** = a handler calls the **confined-helper layer** directly
  (`xrootd_*_confined_canon`, `xrootd_*_beneath`, `xrootd_ns_*`,
  `xrootd_staged_*`) instead of the `xrootd_vfs_*` entry point that wraps it.
  Confined, but bypasses metrics/log/cache/backend-selection.

### 9.2 Audit methodology (reproducible)

```bash
EXC='^src/fs/|^src/path/|^src/compat/(namespace_ops|staged_file|fs_walk|resolve)|^src/impersonate/|^src/dashboard/'
# Tier-1: raw data-plane syscalls outside the VFS/helper layer
grep -rnE '\b(pread|pwrite|preadv2?|pwritev2?|copy_file_range|sendfile)\s*\(' src/ --include=*.c | grep -vE "$EXC|xrootd_vfs_|xrootd_sd_"
# Tier-2: confined-helper calls outside the VFS/helper layer
grep -rnE '\bxrootd_(open_beneath|open_confined_canon|lstat_(beneath|confined_canon)|opendir_confined_canon|unlink_beneath|ns_(delete|mkdir|rename|local_copy)|staged_(open|commit|abort))\s*\(' src/ --include=*.c | grep -vE "$EXC"
# Unconfined raw on possibly-export paths (the dangerous subset)
grep -rnE '\b(open|stat|lstat)\s*\(' src/{read,write,webdav,s3,dirlist}/ --include=*.c | grep -vE 'xrootd_|webdav_|s3_|fstat|statx'
```

### 9.3 Tier-1 finding — **essentially clean** (Phase 54 already funneled the byte plane)

The raw read/write/copy/sendfile sweep over export data outside `src/fs/` returns
**nothing** but a log string (`frm/reqfile.c:224` mentions the word "pread"). The
hot byte plane is genuinely funneled through `xrootd_vfs_io_execute` /
`xrootd_vfs_pread_full`/`pwrite_full` already (Phase 54's achievement). The only
raw-syscall exceptions are (i) the asymmetric S3-multipart scratch in §9.6 (which
*does* include one userspace `read`/`write` copy loop) and (ii) the gateway-private
sidecars in §9.7 — overwhelmingly metadata, not bulk bytes. **Conclusion:** the
client data-byte plane is done; the work left is the *namespace + open + staged*
plane (plus the §9.6 copy loop).

**Two subsystems invariant #11 names explicitly, audited:**

- **CMS / manager data-server (`src/cms`, `src/manager`) — VERIFIED CLEAN.** No
  `xrootd_vfs_*`, `xrootd_ns_*`, `xrootd_*_beneath`, or raw file-data syscall on the
  export; CMS is a network/metadata control plane (cluster registry, redirect,
  `cms.space` reporting) and never touches export bytes directly. It is named in #11
  for completeness, but has no bypass to migrate.
- **Tier-1.5 — SD-vtable-direct byte loops (corrected + expanded this revision).**
  An earlier draft noted only FRM here. A full sweep for
  `xrootd_sd_posix_driver.(pread|pwrite|preadv|copy_range)` found that **Phase 55
  wrapped *every* raw byte loop in the tree** with that hard-coded driver
  indirection — **23 sites in 13 files**, not 5. They split two ways:
  - **The 5 the A-1 implementation fixed** (this revision): the three VFS byte
    primitives (`vfs_read.c` `pread_full`, `vfs_write.c` `pwrite_full`,
    `vfs_io_core.c` `write_counted`) + the two FRM journal loops (`frm/reqfile.c`).
    These now call `pread`/`pwrite` directly (byte-identical; the FRM journal is a
    §9.7 gateway-private sidecar swept along for consistency).
  - **18 that remain — a new tier-1.5 backlog (A-3, §4.3).** These byte
    loops **bypass the VFS primitives entirely**, re-implementing the EINTR/short-IO
    policy against the driver vtable: `read/read.c:373`, `read/readv.c:175`,
    `read/pgread.c:137` (`preadv`, **stream read hot paths**); `compat/checksum_core.c`
    (×3), `compat/http_body.c` (×3), `compat/copy_range.c` (×3 incl. the
    `copy_file_range` fallback), `compat/http_compress.c`, `s3/aws_chunked.c` (×2),
    `s3/post_object.c`, `webdav/tpc_curl.c`, `cache/writethrough_flush.c`. So the
    §9.3 "byte plane is essentially clean" claim holds for **raw libc** but **not**
    for SD-direct loops: 18 loops should route through `xrootd_vfs_pread_full`/
    `pwrite_full` (now direct after A-1) — or gain a VFS vectored/`copy_range`
    primitive for the `preadv`/`copy_range` cases — so the byte plane funnels
    through the VFS the way Phase 54 intended. See **A-3 (§4.3)** for the plan.

### 9.4 Tier-2 backlog — the inventory (105 call sites in 39 files; full list in App C)

Counts — **comment-filtered call sites** (the raw `grep` returns ~121, but ~16 of
those are function names mentioned in file-header WHAT/WHY/HOW doc-blocks, not
calls; `src/write/mv.c`'s header alone names `xrootd_ns_rename` eight times). The
authoritative count, with doc-block lines stripped and `src/cache/` excluded (it is
reached *from* `xrootd_vfs_open` at `vfs_open.c:316`, so it is VFS-internal, not a
handler bypass), is **105 sites across 39 files**:

| Op family | Helper(s) bypassed | Sites | VFS entry point to use |
|---|---|---:|---|
| open (read/write/dir fd) | `xrootd_open_beneath`, `xrootd_open_confined_canon` | **28** | `xrootd_vfs_open` (+ `xrootd_vfs_file_fd` accessor for fd-table adopters) |
| stat / lstat | `xrootd_lstat_beneath`, `xrootd_lstat_confined_canon` | **30** | `xrootd_vfs_stat` |
| opendir / scan | `xrootd_opendir_confined_canon` (+ `fstatat` per child) | **9** | `xrootd_vfs_opendir` / `xrootd_vfs_readdir` |
| namespace mutate | `xrootd_ns_mkdir` / `_rename` / `_delete` | **8** | `xrootd_vfs_mkdir` / `_rename` / `_unlink` / `_rmdir` |
| staged write | `xrootd_staged_open` / `_commit` / `_abort` | **30** | `xrootd_vfs_staged_open` / `_commit` / `_abort` |
| | | **= 105** | |

The two biggest single-file clusters are **`s3/put.c` (20 sites:** the un-migrated
S3 simple-PUT staged-write + abort ladder — see the scorecard, §9.4.1) and
**`webdav/tpc.c` (11 sites:** the TPC staged-abort ladder + two stats). The 30
"staged" sites are mostly **abort ladders** (one `xrootd_staged_abort` per error arm
in `s3/put.c` and `webdav/tpc.c`), so they migrate as two units, not 30
independent edits. Every target VFS entry point **already exists** and **already calls the same
confined helper underneath** (the POSIX driver delegates to exactly these
functions — `sd_posix.c`), so each migration is **byte-identical behaviour** plus
the metric/log/cache/backend-routing the bypass currently skips. Notable sites by
subsystem:

- **Stream `root://` (`src/read`,`write`,`dirlist`,`connection`,`query`):**
  `read/open_resolved_file.c:220` + `connection/fd_table.c:127` (the **hot** open —
  §9.5); `dirlist/handler.c:403,474` (dir open) + `:565` (`fstatat`/child) +
  `dirlist/dcksm.c:131` (`openat`); `write/mv.c:149,198`, `write/mkdir.c:93`,
  `write/op_table.c:50,70` (mv/mkdir/delete via `xrootd_ns_*`/`_beneath`);
  `query/checksum_ckscan_common.c:132,209,172` + `checksum_ckscan_dispatch.c:142`
  (checksum-scan opens + `fstatat`); `path/op_path.c:82` (`lstat_beneath`).
- **WebDAV (`src/webdav`):** `propfind.c:811,845,985,1011` (collection
  opendir+lstat); `lock.c:272,316,351,414,419` (lock-DB scan + open);
  `copy.c:323,336` + `fs/copy_engine.c:52,56,62,99,131` (COPY tree
  lstat/open/opendir); `search.c:225,249`; `methods_basic.c:146`;
  `namespace.c:137` (mkdir), `move.c:44` (rename); `tpc.c:582,755` (lstat) and the
  `staged_open`/`staged_abort` ladder `tpc.c:604,639,653,672,685,704,719,735,736`;
  `tpc_curl.c:609,632` (src/dst opens).
- **S3 (`src/s3`):** `object.c:261` (open), `:412` (`ns_delete`);
  `checksum.c:268,317` (read-open); `delete_objects.c:412` (`ns_delete`);
  `multipart_complete_list_parts.c:107,127` + `multipart_complete_list_uploads.c:106`
  (lstat+opendir of the upload staging dir).

### 9.4.1 Seam-closure scorecard — what is already migrated vs still bypassing

The backlog is the *remainder* of an in-progress transition (§9.13). Per-handler
status, verified this audit (✓ = routes through `xrootd_vfs_*`; ✗ = bypasses;
◐ = partially migrated):

| Protocol | ✓ Migrated (on the VFS) | ✗ / ◐ Still bypassing | Phase |
|---|---|---|---|
| **WebDAV** | GET (`vfs_open`+`sendfile_fd`), DELETE (`vfs_rmdir`/`unlink`), COPY (`vfs_copy`), PROPFIND-on-file (`vfs_stat`), PUT ◐ (`vfs_staged_open` main path) | MKCOL (`ns_mkdir`), MOVE (`ns_rename`+2 stat), PROPFIND-collection (opendir+lstat), LOCK (5), SEARCH (2), TPC (11: stat+staged ladder), PUT residual (4) | F2/F3/F4/F5 |
| **S3** | GET/HEAD (`vfs_open`/`vfs_stat`), POST-object (`vfs_staged_*`, 8), CopyObject (`vfs_copy`) | simple PUT (20: raw `staged`×16+stat+open), DELETE (`ns_delete`×2), multipart-complete (open+stat+§9.6 copy), list-walk (3) | F1/F2/F4 |
| **Stream `root://`** | all data-plane R/W/readv/pgread (`vfs_io_execute`), sync/truncate-by-handle | open (`open_beneath` — **hot**, F6), dirlist (open+`fstatat`), mv/mkdir (`ns_*`), checkpoint (5), checksum-scan (5), truncate-by-path, fattr-open | F2/F5/F6 |

Two same-file proofs that this is a *transition*, not a design split:
`webdav/namespace.c` — **DELETE ✓** (`vfs_rmdir`/`unlink`, `:91`) vs **MKCOL ✗**
(`ns_mkdir`, `:137`); and S3 — **POST-object ✓** (`post_object.c`, 8×
`vfs_staged_*`) vs **simple PUT ✗** (`put.c`, 16× raw `staged`). In both cases the
migrated sibling is the literal copy-paste template for the un-migrated one.

### 9.5 The hot/risky case — the stream handle table wants the raw fd

`read/open_resolved_file.c:220` and `connection/fd_table.c:127` open with
`xrootd_open_beneath(conf->rootfd, rel, …)` and store the **bare `int` fd** in the
0–255 `xrootd_file_t` handle table (`src/connection/fd_table.c`). There is even a
deliberate raw `open(open_path, oflags | O_CLOEXEC, …)` branch
(`open_resolved_file.c:~206`) whose comment cites *FD-leak avoidance into a forked
`tpc_curl` child*. These bypass the VFS because the stream plane manages descriptor
lifetime itself (fixed-slot table, bound-handle reopen, AIO offload by fd), whereas
`xrootd_vfs_open` returns an `xrootd_vfs_file_t` wrapper.

**This is the highest-volume open path in the module** (`kXR_open` on every file a
`root://` client touches), so it is migrated **last** and most carefully. The
bridge already exists: `xrootd_vfs_open` → `xrootd_vfs_file_fd(fh)` yields exactly
the `int` the table needs, and `xrootd_vfs_close` releases it; the table would hold
the `xrootd_vfs_file_t*` (or adopt its fd with an explicit ownership transfer). The
`O_CLOEXEC`-for-fork concern is satisfiable at the SD `open` slot (it already opens
with `O_CLOEXEC` semantics via `RESOLVE_BENEATH`). *Risk:* a regression here hits
every stream open — gate behind the full conformance suite + an open-storm
benchmark (§11.5), and pair with **B-1** (the borrow-instance fix) since both touch
this exact branch.

### 9.6 The asymmetric-hardening subset — S3 multipart scratch (corrected; see App A)

> **Correction.** An earlier revision called this *"unconfined raw syscalls on
> attacker paths"*. Reading the code (`s3/multipart_complete_upload_part_copy.c:107-
> 188`) shows that is **overstated** — the paths here are **server-constructed**,
> not client strings, and the *read* side is already confined. The accurate finding
> is an **asymmetry**, recorded honestly below and in Appendix A.

The S3 multipart `UploadPartCopy` assembler hardens its two sides **unequally**:

- **Source (read) side — confined.** `:145` opens the copy source via
  `xrootd_open_confined_canon` (`openat2(RESOLVE_BENEATH)`), with a code comment
  documenting a *real prior fix*: *"A raw open() here followed a planted in-bucket
  symlink straight to a host file (e.g. /etc/passwd)."* Good — this side is correct.
- **Destination (write) side — raw.** `:153` opens the part file with a bare
  `open(part_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)` — **no** `O_NOFOLLOW`, **no**
  `RESOLVE_BENEATH` — then copies bytes with a **userspace `read`/`write` loop**
  (`:160-179`) and `stat`s the result raw (`:129,:183`). `part_path` is
  *server-constructed*: `s3_get_mpu_dir(confined fs_path, validated upload_id) +
  "/part.<int>"`, and the file's comment asserts *"Bare stat is safe"* because the
  components are pre-validated.

So this is **not** a client-controlled-path escape (severity is **low** — the path
has no un-validated client segment). It is two real, narrower problems:

1. **Asymmetric confinement.** The write side has none of the `RESOLVE_BENEATH`
   hardening the read side was explicitly given. If the staging directory ever
   becomes plantable (a future bug, or a second code path that creates names there),
   the `O_CREAT|O_TRUNC` open would **follow a symlink** and truncate/overwrite the
   target — exactly the class of bug the read side already fixed. Defence-in-depth
   says both sides should be confined identically.
2. **A userspace copy loop** (`read`→`write`, `:160-179`) where the rest of the
   module uses `copy_file_range` (the SD `copy_range` slot) — a perf miss on every
   `UploadPartCopy`, and a second place the byte plane escapes the VFS.

**Fix:** route both sides through the VFS **staging** surface (Phase-55's
`xrootd_storage_staging` store): the destination open inherits `RESOLVE_BENEATH`
(closing the asymmetry), the copy uses `copy_range`, and the scratch becomes
metered + backend-swappable. Priority is **F1 (early)** — not because it is
exploitable today, but because closing a confinement asymmetry is cheap insurance
and it removes a userspace copy loop. The sibling raw stats
(`multipart_complete_list_parts.c:156`, `multipart_helpers.c:214`) ride along.
(`s3/object.c:310`, `list_objects_v1.c:99` `stat()` the **configured export root
itself**, not a client path — benign, not in this subset.)

### 9.7 The scope ruling — what the VFS owns vs gateway-private sidecars

To make "sole source of truth" actionable, the boundary must be explicit.
**Proposed ruling:**

> The VFS owns every operation on **(1) client-visible export file data** and
> **(2) the export namespace** (the bytes and metadata a protocol client can read,
> write, stat, list, or mutate). Gateway-**private** bookkeeping that no client
> ever names is **not** export data and may use direct I/O — **but** must remain
> kernel-confined whenever it lives under the export root.

Classify each borderline case found this sweep:

| Artifact | Files | Ruling |
|---|---|---|
| Checkpoint `.ckp` + lock files | `write/chkpoint.c:94,197,232,521` | **Gateway-private.** Internal kXR_chkpoint journal/lock; client never names it. May stay direct **if confined**; ideal target = VFS staging store. |
| TPC markers / temp / curl scratch | `webdav/tpc_marker.c:146,173,487`, `tpc_curl.c:793`, `tpc_thread.c:151,204` | **Gateway-private** transfer scratch. Same ruling. |
| Cache metadata stat | `read/stat.c:203,338` | **Cache-internal** (the cache root, not the export). Belongs to the cache subsystem's own surface, not the export VFS. Out of Pillar F scope. |
| Multipart part files | §9.6 | **Export staging — IN scope**, and unconfined ⇒ priority (§9.6). |
| Stat of the export root itself | `s3/object.c:310`, `list_objects_v1.c:99` | **Benign** (configured root, not client path). No action. |

The principled long-term answer for the "gateway-private" rows is **not** to bless
them forever but to route them through the VFS **staging/scratch store** (Phase
55.F): then even scratch is confined, metered, and swappable to a different backend
— and the ruling collapses to *"everything file-shaped goes through the VFS; the
VFS has two stores, a durable backend store and a staging store."*

### 9.8 Legitimate non-targets (do **not** migrate — these are the layer or below it)

| Location | Why it is correct as-is |
|---|---|
| `src/path/beneath.c`, `resolve_confined_ops.c`, `resolve_confined_helpers.c` | These **define** the confined helpers — the POSIX layer the SD driver wraps. Their raw `openat2`/`unlinkat`/`mkdirat`/`renameat` belong here. |
| `src/compat/namespace_ops.c`, `staged_file.c`, `fs_walk.c` | The namespace/staged/walk implementation `sd_posix.c` delegates to. Below the seam. |
| `src/impersonate/broker.c` | The **privileged broker process** that performs the syscall as the mapped user — the impersonation execution backend, reached via `xrootd_imp_*` *below* the confined helpers. |
| `src/dashboard/files.c` | The admin file viewer over a **separate** `xrootd_dashboard_browse_root` with its own `openat2(RESOLVE_BENEATH)` confinement — not the protocol export data plane. |

### 9.9 Enforcement — a CI seam guard (there is none today)

The sweep found **no** existing guard preventing a new bypass (Phase 54's
`VFS-THREAD-SAFE` annotation contract guards *thread-safety*, not *seam-routing*).
Without one, this backlog regrows. Propose `tools/ci/check_vfs_seam.sh`:

```bash
#!/usr/bin/env bash
# Fail if a confined-helper symbol is called outside the allowed layer.
set -euo pipefail
ALLOW='^src/fs/|^src/path/|^src/compat/(namespace_ops|staged_file|fs_walk|resolve)|^src/impersonate/'
SYMS='xrootd_open_beneath|xrootd_open_confined_canon|xrootd_lstat_beneath|xrootd_lstat_confined_canon|xrootd_opendir_confined_canon|xrootd_unlink_beneath|xrootd_ns_(delete|mkdir|rename|local_copy)|xrootd_staged_(open|commit|abort)'
viol=$(grep -rnE "\\b($SYMS)\\s*\\(" src/ --include=*.c | grep -vE "$ALLOW" \
        | grep -vFf tools/ci/vfs_seam_backlog.txt || true)
[ -z "$viol" ] || { echo "NEW VFS-seam bypass (route through xrootd_vfs_*):"; echo "$viol"; exit 1; }
```

`tools/ci/vfs_seam_backlog.txt` is the **shrinking allowlist** of the 105 known
sites — its **seed content is enumerated in full in Appendix C** (same pattern as
the `client/` `goto` refactor-on-touch backlog in `CLAUDE.md`): every migration
phase deletes its lines, and the guard rejects any *new* bypass. When the file is
empty, the seam is closed and the guard becomes absolute. Wire it into the
build-governance check alongside the no-`goto` rule.

> **As shipped (this revision)** the guard is **dual-class**: the snippet above is
> the tier-2 (confined-helper) check; the implemented `check_vfs_seam.sh` adds a
> second grep for `xrootd_sd_posix_driver.<byteop>` (tier-1.5 SD-direct byte loops,
> the A-3 backlog — §4.3) and unions the two before subtracting the allowlist. The
> seeded backlog is **48 files** (40 tier-2 + the tier-1.5 byte-loop files;
> `src/fs/` is excluded — A-1 made it clean of driver byte-ops).

### 9.10 Migration plan (each phase shippable, byte-identical, 3-tests rule)

Every step swaps a confined-helper call for the `xrootd_vfs_*` wrapper that already
calls it underneath — so the wire behaviour is identical and the win is
metrics+log+cache+backend-routing+one-source-of-truth. Ordered lowest-risk and
highest-danger first; the hot path last.

| Phase | Scope | Sites | Risk |
|---|---|---:|---|
| **F0** | Land the §9.9 CI guard + backlog allowlist (freeze the backlog) | — | none |
| **F1** | §9.6 S3-multipart **write-side asymmetry** → VFS staging surface (confine the part open + `copy_range`) | ~6 | medium (defence-in-depth + perf) |
| **F2** | Namespace mutations (`ns_mkdir`/`_rename`/`_delete`) → `xrootd_vfs_mkdir`/`_rename`/`_unlink`/`_rmdir` | 17 | low (1:1 wrappers) |
| **F3** | stat/lstat → `xrootd_vfs_stat`; opendir+child-scan → `xrootd_vfs_opendir`/`readdir` (composes with C-1/C-5) | 40 | low–medium |
| **F4** | Staged writes (WebDAV TPC ladder, chkpoint) → `xrootd_vfs_staged_*` | 30 | medium (abort-ladder error paths) |
| **F5** | Cold opens (checksum scans, S3 checksum, WebDAV copy_engine/methods_basic/lock, tpc_curl) → `xrootd_vfs_open` | ~28 | medium |
| **F6** | **Hot** stream open (`open_resolved_file.c`, `fd_table.c`) → `xrootd_vfs_open` + `xrootd_vfs_file_fd`; pairs with **B-1** | ~6 | **high** (every `kXR_open`) |
| **F7** | Scope-ruling cleanup (§9.7): route gateway-private sidecars to the VFS staging store, or bless-and-confine | ~12 | low |

*Invariant note (whole pillar):* each migrated call resolves to the *same*
`openat2(RESOLVE_BENEATH)` / `xrootd_ns_*` / `xrootd_staged_*` underneath, so
confinement and wire semantics are preserved exactly; the oracle suite is the
proof. F1 additionally **closes the §9.6 confinement asymmetry** (the write side
gains the hardening the read side already has). The net effect: when the Phase-55
object/block backend lands, **all** of these ops follow the configured backend
instead of being silently pinned to POSIX — which is the entire point of the seam.

### 9.11 Worked migration — a same-file before/after (`webdav/namespace.c`)

The migration is not hypothetical: `webdav/namespace.c` already contains **both** a
migrated handler and an un-migrated one, side by side, so the diff is exact.

**Already migrated — `webdav_handle_delete` (`:88`)** is the template:
```c
/* "Route the delete through the metered VFS surface." */
webdav_ns_vfs_ctx_init(r, path, &vctx);                 /* established per-area ctx builder */
rc = S_ISDIR(sb.st_mode) ? xrootd_vfs_rmdir(&vctx, 0)   /* meters OP_DELETE, access-logs,  */
                         : xrootd_vfs_unlink(&vctx);     /* write-gated, cache-aware        */
/* errno → HTTP map unchanged (ENOTEMPTY→409, ENOENT→404, else 500) */
```

**Not yet migrated — `webdav_handle_mkcol` (`:137`)**, the adjacent handler:
```c
/* BEFORE (bypass): no VFS metric, no access-log, POSIX-pinned */
res = xrootd_ns_mkdir(r->connection->log, conf->common.root_canon, path, 0755, 0);
if (res.status == XROOTD_NS_OK)     return webdav_send_no_body(r, NGX_HTTP_CREATED);
if (res.status == XROOTD_NS_EXISTS) return NGX_HTTP_NOT_ALLOWED;
...
```
```c
/* AFTER (F2): three-line change, copied from the DELETE handler above */
webdav_ns_vfs_ctx_init(r, path, &vctx);                 /* same builder the DELETE uses    */
rc = xrootd_vfs_mkdir(&vctx, 0755, 0);                  /* now emits OP_MKDIR + access-log */
if (rc == NGX_OK)        return webdav_send_no_body(r, NGX_HTTP_CREATED);
if (errno == EEXIST)     return NGX_HTTP_NOT_ALLOWED;   /* xrootd_vfs_mkdir sets errno      */
...                                                     /* same errno → HTTP map as before */
```

What changed: the wire response is **byte-identical** (`xrootd_vfs_mkdir` calls the
same `xrootd_ns_mkdir` underneath), but MKCOL now appears in the `OP_MKDIR` metric
series and the access log for the first time, is routed to whatever backend the
export selects, and shares the DELETE handler's confinement path. What did **not**
change: the errno→HTTP mapping, the lock check, the path resolution. This is the
shape of **every** F2/F3/F5 migration — swap the raw helper for the `xrootd_vfs_*`
wrapper, keep the surrounding protocol logic.

### 9.12 The one real friction — loop-only ctx-ops vs thread-offloaded handlers

Not every migration is three lines. The VFS **ctx-ops** (`xrootd_vfs_stat`/`rename`/
`mkdir`/`unlink`/`copy`/`staged_commit`) are **loop-only**: each ends in
`xrootd_vfs_observe_ctx_op`, which emits a metric **and an access-log line** on the
event-loop thread. But a few handlers **offload the namespace op to a thread pool**
— `webdav/move.c` (`webdav_move_collection_thread` runs `xrootd_ns_rename` on a
worker) and `webdav/copy.c` similarly. Naively calling `xrootd_vfs_rename` from the
worker would emit metrics/access-log **off the loop**, which the VFS observer is not
built for.

Two further wrinkles, both already visible in `move.c`:

1. **`xrootd_vfs_rename` takes a resolved `xrootd_path_result_t*` destination**
   (`vfs.h`), not a `char*` — so the migration must construct the dst path-result,
   not just pass `dst_path`. (Source comes from the ctx.)
2. **Impersonation already forces these handlers synchronous** —
   `webdav_move_collection_post_task` returns `NGX_DECLINED` when
   `xrootd_imp_enabled()` because *"the per-worker broker socket is a single fd used
   by the event-loop thread; a thread-pool task issuing confined ops would race it."*
   So under impersonation the offload is already off and the op runs on the loop.

**Resolution (pick per-op, document in the phase):**
- **Preferred for `rename`/`mkdir`/`unlink`:** run them on the loop and **drop the
  offload**. `rename(2)`/`mkdir(2)` are O(1) metadata ops; `move.c`'s own comment
  says the offload *"mainly isolates the worker from rare slow-fs stalls."* The
  collection-MOVE recursive case (a tree rename) is the only one with real work, and
  it is already a single `renameat` (atomic within the fs) — not a per-child walk. So
  the offload buys little and seam-uniformity buys a lot.
- **If an offload must be kept** (e.g. a genuinely slow recursive `copy`): add a
  thread-safe ctx-op variant that runs the syscall on the worker (via the existing
  io-core pattern) and defers the single `observe` to the COMPLETE callback on the
  loop — exactly the PREPARE/EXECUTE/COMPLETE split Phase 54 built for I/O, extended
  to namespace ops. This is more work and is only justified where the offload is
  load-bearing; most sites take the "drop the offload" path.

*This friction is confined to the ~4 thread-offloaded namespace sites* (move/copy
collection paths); the other ~117 sites are already synchronous and migrate like
§9.11.

### 9.13 This is *finishing* a started migration, not a greenfield one

The scaffolding already exists and is proven in-tree, which de-risks the whole
pillar:

- `xrootd_vfs_ctx_init` (the generic builder) **plus** established per-area wrappers
  — `webdav_ns_vfs_ctx_init` (`namespace.c:20`), `webdav_lock_vfs_ctx_init`
  (`prop_xattr.c:37`), `webdav_put_vfs_ctx_init` (`put.c`) — so a migrating handler
  rarely writes ctx boilerplate from scratch.
- Whole handlers are **already migrated**: WebDAV DELETE (`xrootd_vfs_rmdir`/
  `unlink`), GET (`xrootd_vfs_open`+`sendfile_fd`), PUT (`xrootd_vfs_staged_*`), COPY
  (`xrootd_vfs_copy`); S3 GET/HEAD (`xrootd_vfs_open`/`stat`). The bypass backlog is
  the **remainder** of a transition that began with Phases 45/46/54/55, not an
  untouched legacy.

So Pillar F is "**finish the funnel migration the codebase is already half-way
through, then lock it with the §9.9 guard**" — and the in-tree migrated handlers are
copy-paste templates for their un-migrated siblings (literally adjacent, as §9.11
shows). That is a materially lower-risk framing than "rewrite 105 call sites."

---

## 10. Expansion roadmap (capability growth, not just trimming)

Three expansions the Phase-55 architecture was built to host:

1. **`CAP_IOURING` data path (C-3 generalized).** Wire io_uring through the seam
   for the disk-I/O EXECUTE phase — read/write/readv batches and the dirlist statx
   batch — gated on the capability + runtime probe (Phase 44). The job core is
   already a superset of the SQE inputs, so this is additive: a `posix_uring`
   driver registers alongside `posix` and the VFS selects it when configured and
   available.

2. **Object/block backend read shaping (Phase 55.E).** When a non-POSIX backend
   cannot sendfile (`!CAP_SENDFILE`), the VFS *must* serve memory-backed — exactly
   what the (currently dead) `make_memory_chain` builder does. This is the one
   scenario that argues for §3 **Option A** over deletion: if the object driver
   lands, reintroduce a *wired* `xrootd_vfs_read` whose file-vs-memory branch is
   driven by `read_sendfile_fd` returning `NGX_INVALID_FILE`. Decide §3 with this
   on the table.

3. **`read_advise` seam slot (B-2 generalized).** A first-class advise slot lets
   POSIX map to `posix_fadvise`, io_uring to `IORING_OP_FADVISE`, and an object
   backend to range-prefetch or a no-op — unifying the three current ad-hoc
   prefetch implementations (`webdav/io.c`, `read/prefetch.c`, the absent S3 one)
   behind one capability-typed call.

---

## 11. Measurement & benchmark harness (prerequisite, per Phase 30 §8)

Every item must show a before/after on the path it claims to improve. Capture a
baseline first; all numbers are **relative** (WSL2 loopback >1 GB/s figures are
memory-bandwidth artefacts — see Phase 53 §5).

```bash
# Baseline — full suite must stay green throughout (behaviour oracle)
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

### 11.1 A-1 / A-2 — raw byte loop (throughput + branch behaviour)
```bash
# Large sequential read + write, root:// stream, 4 GB, repeated:
tests/profile_load.sh --proto root --op read  --size 4G --reps 8
tests/profile_load.sh --proto root --op write --size 4G --reps 8
# Instruction + indirect-branch delta on a single big transfer:
perf stat -e instructions,branches,branch-misses,L1-icache-load-misses \
    -- xrdcp root://localhost:11094//big.4g /dev/null
# Expectation: fewer instructions + branch-misses post-A-1; throughput ≥ baseline.
```

### 11.2 D-1 / D-2 — latency metric fidelity + overhead
```bash
# Before: confirm inline metadata ops report 0 in the histogram:
curl -s localhost:9100/metrics | grep -E 'op_latency.*op="stat"'
# After D-1: sub-ms buckets populate. After D-2: read/write op latency series exist.
# Overhead: clock_gettime(MONOTONIC) micro-bench (~20 ns) vs a pread (µs-scale):
perf bench -- ... ; confirm op-latency add is < 0.1% on a 4 GB read.
```

### 11.3 B-2 — read-ahead pushdown (cold cache only)
```bash
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches      # cold page cache
tests/profile_load.sh --proto s3 --op get --size 4G --reps 5   # S3 had NO hint before
# Expectation: cold-cache sequential GET throughput up on root://+S3; WebDAV unchanged.
```

### 11.4 C-1 / C-5 / C-2 — metadata syscall/IPC amplification
```bash
# Wide+deep tree; count syscalls per listing/delete:
strace -f -e trace=newfstatat,lstat,statx -c -- \
    <PROPFIND-depth-1 | S3 ListObjects | recursive DELETE on a 10k-entry collection>
# Repeat under impersonation (xrootd_impersonate on) and count broker round-trips.
PYTHONPATH=tests pytest tests/test_metadata_stress.py -v     # C-2 hit-rate + race
# Expectation: C-5 → fewer path-walk lstats; C-1 → ~0 stats for type-only walks;
#              C-2 → repeat ENOENT probes collapse to 1 syscall (default-off flag on).
```

### 11.5 B-1 / B-5 — open + commit allocation/stat count
```bash
# Open storm (kXR_open) alloc count via massif/heaptrack on a worker:
heaptrack /tmp/nginx-1.28.3/objs/nginx -g 'daemon off;' & ; tests/open_storm.py
# B-5: upload/copy op under impersonation — broker IPC/op drops by one (strace -f count).
```

### 11.6 C-3 — io_uring batch statx (behind Phase 44)
```bash
# Crossover sweep: sequential fstatat vs uring batch over N ∈ {16,128,1k,10k} entries.
tests/dirlist_statx_bench.py --backend posix      --sizes 16,128,1024,10240
tests/dirlist_statx_bench.py --backend posix_uring --sizes 16,128,1024,10240
# Expectation: uring wins above a crossover (~hundreds of entries); small dirs stay seq.
```

### 11.7 F-1/F-2/F-3 — seam closure (audit, behaviour-equivalence, confinement)
```bash
# (a) The bypass audit itself, as a regression metric — count must only ever fall:
tools/ci/check_vfs_seam.sh ; wc -l tools/ci/vfs_seam_backlog.txt   # backlog shrinks per phase

# (b) Behaviour-equivalence of a migrated op (byte-identical wire response):
#     run the op's conformance tests before+after; the op's /metrics counter, which
#     was previously ZERO (unmetered bypass), should now appear and increment.
PYTHONPATH=tests pytest tests/ -k "propfind or s3_multipart or webdav_copy or kxr_open" -v
curl -s localhost:9100/metrics | grep -E 'op_total.*op="(stat|mkdir|rename|delete|write)"'

# (c) F-2 confinement proof — a crafted multipart part name must NOT escape:
PYTHONPATH=tests pytest tests/test_attack_vectors.py -k "multipart and traversal" -v
strace -f -e trace=openat,openat2,statx -- <S3 CompleteMultipartUpload> \
   | grep -E 'openat2'    # part-file opens now go through the RESOLVE_BENEATH path

# (d) Hot-path (F6) — open storm must not regress (pair with §11.5 / B-1):
tests/open_storm.py --proto root --opens 1e6   # ops/s >= baseline; alloc count <= baseline
```
Expectation: the backlog file monotonically shrinks; every migrated op's wire
output stays byte-identical (conformance green) while its metric/access-log
coverage appears for the first time; F-2 part-file opens now show
`openat2(RESOLVE_BENEATH)`; F6 open throughput is at or above baseline.

---

## 12. Phased rollout

Each step is independently shippable and carries the 3-tests rule (success + error
+ security-negative) and the relevant §11 before/after.

| Step | Items | Gate |
|---|---|---|
| **56.0** | **Resolve §3** — delete (Option B) or schedule unify (Option A). Land the deletion + `vfs.h` re-doc if B. | full suite green; doc matches `src/` (§1.1 funnels documented) |
| **56.1** | A-1 (direct byte loops) + A-2 (wrap discipline) + B-1 (stack/direct borrow) | §11.1 throughput + branch-miss delta; suite green |
| **56.2** | D-1 (monotonic latency) + D-2 (data-plane op-latency) in lockstep | §11.2 sub-ms buckets populate; read/write series exist; overhead < 0.1% |
| **56.3** | B-2 (`read_advise` seam + fadvise pushdown; retire `webdav/io.c` hint) | §11.3 cold-cache S3/root:// up; WebDAV parity unchanged |
| **56.4** | C-5 (dirfd `fstatat`) + C-1 (`d_type`) + C-4 (fstatat error log) + B-5 (fstat-for-bytes) | §11.4/§11.5 syscall + broker-IPC count drops; listings byte-identical |
| **56.5** | C-2 (negative-stat cache, **default off**, identity-scoped) | §11.4 hit-rate + create-after-probe race test green |
| **56.6** | C-3 / §10.1 (io_uring batch statx) — **behind Phase 44** | §11.6 crossover measured; availability gating; wire-identical dirlist |

56.0 → 56.1 → 56.2 are the near-free core (land together-ish). 56.3–56.5 are the
metadata-plane trims that dominate under directory concurrency + impersonation.
56.6 is the io_uring expansion, sequenced behind its enabling phase.

**The seam-closure track (Pillar F) runs in parallel as its own phased sequence
F0–F7 (§9.10)** — it is orthogonal to the perf steps (it touches handler call
sites, not the VFS internals 56.1–56.6 touch) and can be executed by a separate
engineer. Land **F0 (the CI guard, §9.9) first of everything** so no new bypass is
added while the rest is in flight, and **F1 (the S3 multipart
write-side asymmetry, §9.6) early** because closing a confinement asymmetry is cheap
defence-in-depth (and removes a userspace copy loop). F3 (stat/opendir migration)
should land *after* 56.4 (C-1/C-5) so the migrated call sites inherit the
`d_type`/dirfd-`fstatat` fast paths rather than being rewritten twice.

---

## 13. Risk register & invariant-preservation checklist

| Item | Risk | Mitigation |
|---|---|---|
| A-1 | A future non-POSIX backend wants to intercept the byte loop | The intercept point is the *object* ops (open/fstat/namespace), not the worker-safe byte primitive — document explicitly. A backend needing a different byte loop owns its EXECUTE phase, or resolves `obj->driver->pread` into a local fn-ptr *once* before the loop. |
| B-1 | Lifetime bug if a stack-borrowed instance outlives the open call | The instance is used only synchronously inside `xrootd_vfs_open`; the returned *fd* (not the instance) is what `adopt_fd` keeps. Assert no path stores `ctx->sd` past the call when stack-borrowed; prefer the direct-`xrootd_open_beneath` shape which has no instance at all. |
| C-2 | **False `ENOENT`** on a path created by another worker → correctness bug | Default off; per-worker only (never cross-worker); short TTL; cleared by every same-worker mutator; identity-scoped under impersonation; mandatory create-after-negative-probe race test. |
| C-1 / C-5 | Hostile/legacy FS returns DT_UNKNOWN or spoofs type; `fstatat` follows a symlink | DT_UNKNOWN falls back to stat; `d_type` is never a confinement/authz input; `fstatat` uses `AT_SYMLINK_NOFOLLOW` on the already-`RESOLVE_BENEATH`-anchored dir fd; impersonation keeps the broker route. |
| D-1 / D-2 | `clock_gettime`/atomic bump overhead on the hot path | `CLOCK_MONOTONIC` is vDSO (~20 ns); the metric bump is one lock-free atomic. Measure (§11.2) and confirm < 0.1% on a 4 GB read; it is one op per *operation*, never per byte. |
| B-2 | A backend ignores/​mishandles advice | Advisory only; ignored hints log-and-continue; `read_advise == NULL` ⇒ no-op. |
| §3 Option A (unify) | Regressing Phase 32/45 zero-copy or Phase 54 thread-safety while merging funnels | Gate behind full conformance + integrity-matrix + readv/pg security suites; do the HTTP-read half first (sendfile builder exists), stream + write halves separately. |
| F-1 (seam closure) hot path | F6 migrates the highest-volume `kXR_open` path; a regression hits every stream open | Sequence F6 **last**; pair with B-1 (same branch); gate behind full conformance + an open-storm benchmark (§11.5); the migration is byte-identical (same `xrootd_open_beneath` underneath) so divergence = a wiring bug, caught by the oracle. |
| F-1 staged-abort ladder (F4) | The WebDAV TPC `staged_abort` error ladder (`tpc.c`, ~9 sites) is delicate; a missed abort leaks a temp | Migrate the ladder as one unit; assert every error arm calls `xrootd_vfs_staged_abort`; reuse the existing leak/partial-object tests as the gate. |
| F-2 (multipart asymmetry) | The §9.6 part paths are server-constructed and assumed valid; routing the *write* side through the VFS staging surface must not change the multipart assembly result | Behaviour-preserve the assembly; add `RESOLVE_BENEATH` to the write side (a strict tightening matching the read side, never a loosening); swap the `read`/`write` loop for `copy_range`; 3-tests incl. a planted-symlink-in-staging negative. |
| F (thread-offload sites) | Migrating `move.c`/`copy.c` collection ops to loop-only VFS ctx-ops drops a thread offload | §9.12: drop the offload for O(1) `rename`/`mkdir` (the offload only guards rare slow-fs stalls; impersonation already forces sync); add a PREPARE/EXECUTE/COMPLETE namespace variant only where an offload is load-bearing. ~4 sites. |
| F (regression of the backlog) | Without enforcement the bypass set regrows as new handlers are written | F0 lands the `check_vfs_seam.sh` CI guard + shrinking allowlist **first**; the guard is absolute once the allowlist empties. |
| All | Weakening a `CLAUDE.md` invariant | Every step preserves: pgread/pgwrite per-page CRC; TLS-memory vs cleartext-sendfile buffer discipline; `RESOLVE_BENEATH` before open; `allow_write` before token scope; low-cardinality labels. A-1/B-1/B-5/D-1/D-2/E-*/F-* are byte- or metrics-identical by construction (F-2 additionally *adds* confinement). |

**Invariants that must remain true after every step:** raw byte primitives stay
worker-safe (no pool/metrics/log/cache); confinement re-check happens above the
seam on every op; the POSIX driver stays behaviour-preserving against the
~5180-test oracle; metric labels stay low-cardinality (no paths/inodes/UUIDs);
impersonation metadata ops stay broker-routed where the worker lacks DAC.

---

## 14. Interface / ABI contracts for the new SD slots (implementation reference)

Precise pre/post-conditions for the seam additions C-1/B-2/C-3 propose, so an
implementer (or a future object/io_uring backend) has an exact contract.

### 14.1 `read_advise` (B-2)
```c
ngx_int_t (*read_advise)(xrootd_sd_obj_t *obj, off_t off, size_t len, int advice);
```
- **Pre:** `obj` is an open handle from `driver->open`; `advice ∈
  {SEQUENTIAL,WILLNEED,RANDOM}`; `off ≥ 0`; `len == 0` means "whole object".
- **Post:** advisory only — returns `NGX_OK` whether or not the kernel honoured it;
  `NGX_ERROR` (errno set) only on a hard failure the caller may log and ignore.
  **Must not** change file position, size, or contents. Worker-safe (no
  pool/metrics/log). `NULL` slot ⇒ backend has no advice primitive (VFS treats as
  no-op).
- **Thread context:** callable from the event loop or an AIO worker.

### 14.2 `xrootd_sd_dirent_t.d_type` (C-1)
```c
typedef struct { char name[256]; unsigned char d_type; } xrootd_sd_dirent_t;
```
- **Post:** `d_type` is one of `DT_REG/DT_DIR/DT_LNK/DT_FIFO/DT_SOCK/DT_BLK/DT_CHR`
  or `DT_UNKNOWN`. A backend that cannot classify cheaply **must** set
  `DT_UNKNOWN` (never guess) — consumers fall back to a stat. **Never** an
  authorization input.
- **Compat:** additive field; existing readers ignore it. No ABI break for the
  in-tree static driver table (no external driver ABI is published yet).

### 14.3 batched statx hook (C-3)
```c
/* gathers stat for up to n dirfd-relative names in one submission; out[i] valid
 * iff rc[i]==0. dfd is the confined directory fd. */
ngx_int_t (*statx_batch)(xrootd_sd_dir_t *d, int dfd, const char *const *names,
                         size_t n, struct statx *out, int *rc);
```
- **Pre:** `dfd` is the `RESOLVE_BENEATH`-anchored directory fd; `names[i]` are
  single components (no `/`).
- **Post:** semantically identical to `n` sequential `fstatat(dfd, names[i], …,
  AT_SYMLINK_NOFOLLOW)` calls — same per-entry results and errnos, only batched.
  Worker-safe; blocks on the ring within the worker task. `NULL` slot ⇒ VFS uses
  the sequential `fstatat` loop.

---

## 15. Exact edit hunks (per file, for the near-free core 56.1–56.2)

A concrete starting point for the lowest-risk steps. Each is behaviour- or
metrics-identical; full text lives in the cited functions.

- **`src/fs/vfs_read.c` — `xrootd_vfs_pread_full` (A-1):** delete the
  `xrootd_sd_obj_t obj; xrootd_sd_posix_wrap(&obj, fd);` lines and replace
  `xrootd_sd_posix_driver.pread(&obj, buf+done, len-done, off+done)` with
  `pread(fd, buf+done, len-done, offset+(off_t)done)`. Drop the now-unused
  `#include "backend/sd.h"` if nothing else needs it.
- **`src/fs/vfs_write.c` — `xrootd_vfs_pwrite_full` (A-1):** symmetric, `pwrite`.
- **`src/fs/vfs_io_core.c` — `xrootd_vfs_io_write_counted` (A-1):** drop the
  `obj`/`wrap`; replace the `xrootd_sd_posix_driver.pwrite(&obj, …)` call with
  `pwrite(fd, …)`. Leave `_execute_sync`/`_execute_truncate` routing through the
  seam as-is (those are single ops, not inner loops — the indirection cost is
  irrelevant and the seam reads cleaner; or convert them too for consistency).
- **`src/fs/vfs_open.c` — `xrootd_vfs_open` rootfd≥0 branch (B-1):** gate the
  `driver->open` dispatch on `ctx->sd != NULL && ctx->sd->driver !=
  &xrootd_sd_posix_driver`; else `fd = xrootd_open_beneath(ctx->rootfd, path,
  oflags, 0644);`. Remove the unconditional `xrootd_sd_posix_borrow_instance`
  call.
- **`src/fs/vfs_internal.h` — add `xrootd_vfs_now_ns()` (D-1)** and change
  `xrootd_vfs_observe_*` to take `uint64_t start_ns`; `xrootd_vfs_elapsed_usec`
  becomes `(now_ns - start_ns)/1000`. Update the ~7 ctx-op call sites
  (`vfs_stat/copy/rename/unlink/mkdir/dir/staged`) to capture `start_ns` instead
  of `start = ngx_current_msec`.
- **`src/aio/reads.c` / `src/aio/write.c` (D-2):** in the done callbacks, after the
  byte counters, call `xrootd_metric_op_done(proto, OP_READ|OP_WRITE, bytes,
  usec_from(task->start_ns), err_class)`; add a `uint64_t start_ns` to the task
  struct set in PREPARE.

*Build governance:* none of these add a `.c` file, a top-level config block, or a
`--with-*` option, so **no `./configure`** — incremental `make -j$(nproc)` only.
(C-1/C-3/B-2 add seam slots in existing files = still no new source file; a
`posix_uring` driver in a new `sd_posix_uring.c` *would* require a `config.h`
`NGX_ADDON_SRCS` edit + `./configure`.)

---

## 16. Files in scope (reference index)

**VFS public + internal:** `src/fs/vfs.h`, `src/fs/vfs_internal.h`,
`src/fs/vfs_open.c` (B-1, B-3, B-4), `src/fs/vfs_read.c` (A-1; E-1 **dead body**),
`src/fs/vfs_write.c` (A-1; E-2, E-3 **dead body**), `src/fs/vfs_stat.c` (C-2),
`src/fs/vfs_dir.c` (C-1, C-5), `src/fs/vfs_copy.c` (B-5), `src/fs/vfs_staged.c`
(B-5, D-1), `src/fs/vfs_rename.c` / `vfs_unlink.c` / `vfs_mkdir.c` / `vfs_xattr.c`
(D-1 observers).

**I/O core:** `src/fs/vfs_io_core.c` (A-1 `write_counted`; C-3/C-4 dirlist; D-2
COMPLETE), `src/fs/vfs_io_core.h`.

**Storage Driver seam:** `src/fs/backend/sd.h` (C-1 dirent, B-2/C-3 new slots),
`src/fs/backend/sd_posix.c` (A-1 raw slots, B-1 borrow, B-2 fadvise, C-1 d_type),
`src/fs/backend/sd_registry.c` (§10 new driver registration).

**Crosses the seam (referenced, not re-audited):** `src/shared/file_serve.c`
(Funnel 1), `src/aio/reads.c` / `aio/write.c` (Funnels 2/4, D-2), `src/webdav/get.c`
/ `put.c`, `src/s3/object.c` / `post_object.c` / `copy.c`, `src/compat/fs_walk.c`
(C-1 central tree walker), `src/compat/namespace_ops.c` (recursive delete),
`src/path/resolve_confined_ops.c` (impersonation stat — §0.3), `src/read/prefetch.c`
+ `src/webdav/io.c` (B-2 existing fadvise), `src/metrics/unified.{h,c}` (D-1/D-2),
`src/cache/writethrough_decision.c` (E-3).

**Pillar F seam-closure backlog (the ~105 bypass sites to migrate — §9.4):**
*stream* `src/read/open_resolved_file.c` (F6 hot), `src/connection/fd_table.c` (F6
hot), `src/dirlist/handler.c` + `dirlist/dcksm.c`, `src/write/mv.c` / `mkdir.c` /
`op_table.c` / `chkpoint.c`, `src/query/checksum_ckscan_common.c` /
`checksum_ckscan_dispatch.c`, `src/path/op_path.c`; *WebDAV*
`src/webdav/propfind.c` / `lock.c` / `copy.c` / `fs/copy_engine.c` / `search.c` /
`methods_basic.c` / `namespace.c` / `move.c` / `tpc.c` / `tpc_curl.c`; *S3*
`src/s3/object.c` / `checksum.c` / `delete_objects.c` /
`multipart_complete_list_parts.c` / `multipart_complete_list_uploads.c`, and the
**unconfined** (F2-priority) `src/s3/multipart_complete_upload_part_copy.c` /
`multipart_helpers.c` (§9.6). **New files:** `tools/ci/check_vfs_seam.sh` +
`tools/ci/vfs_seam_backlog.txt` (§9.9). **Legitimate non-targets (§9.8):**
`src/path/beneath.c` / `resolve_confined_ops.c`, `src/compat/{namespace_ops,
staged_file,fs_walk}.c`, `src/impersonate/broker.c`, `src/dashboard/files.c`.

---

## Appendix A — corrected findings (do not re-introduce as "hot-path wins")

The §0.2 reachability check demoted three items that an initial read of
`vfs_read.c`/`vfs_write.c` makes look like obvious hot-path optimizations:

- **"`make_file_chain` does a needless path alloc on every cleartext read."** FALSE
  as a hot-path claim: `xrootd_vfs_read` has **zero callers** (§0.1). Real but dead.
  → §8.1 E-1.
- **"`write_file_buf` should use `copy_file_range` instead of a 64 KB bounce on
  every PUT."** FALSE: `xrootd_vfs_write` has **zero callers**, and the live PUT
  path (`staged_write`) takes a *memory* buffer, not an `in_file` chain — so no
  `copy_file_range` opportunity exists on a live path. → §8.2 E-2.
- **"S3 multipart uses unconfined raw syscalls on attacker paths" (§9.6).**
  OVERSTATED — corrected this revision. Reading `multipart_complete_upload_part_copy.c`
  shows the part paths are **server-constructed** (`confined fs_path` + validated
  `upload_id` + `/part.<int>`), and the *read* side is already
  `RESOLVE_BENEATH`-confined (with a documented prior planted-symlink fix). The real
  finding is **asymmetric hardening** (raw `open`+userspace copy loop on the *write*
  side only), low severity, fixed by routing the write side through the VFS staging
  surface. The lesson repeats: **read the code, including its security comments,
  before assigning severity.**
- **"The writethrough decision is dead code."** PARTLY FALSE: writethrough is a
  *live* feature (flush at sync/close via `writethrough_flush.c`); only the
  *pre-scan in `xrootd_vfs_write`* is dead (its caller is). Don't delete the
  feature; delete-or-gate the pre-scan with the §3 funnel decision. → §8.3 E-3.
- **"§3 Option B — just delete the dead `xrootd_vfs_read`/`write` (build-verified,
  zero risk)."** FALSE — found at implementation. The "dead" code is **pinned by a
  conformance marker test** (`test_phase3_vfs_preserves_io_invariants`) as the
  reference TLS-buffer/sendfile/CRC invariant implementation; deleting it breaks the
  stock suite and removes that guard. → §3 (recommendation corrected). The lesson
  repeats with a twist: **check the *tests*, not just the call sites — "no runtime
  callers" ≠ "safe to delete" when a marker/conformance test pins the code.**

**Lesson for the next auditor:** in this stack, **read the call sites before
ranking a finding.** The VFS public surface contains designed-but-unwired paths,
and the live data plane is split across the io-core jobs, the sendfile serve path,
and the staged-upload path — not the chain-shaped entry points the header
advertises (§1.1).

---

## Appendix B — glossary & symbol reference

| Symbol / term | Meaning |
|---|---|
| **VFS** | `src/fs/` — the protocol-agnostic data-plane API (`xrootd_vfs_*`); the layer every handler must call instead of raw syscalls (`CLAUDE.md` #11). |
| **SD / Storage Driver** | `src/fs/backend/` — the capability-typed pluggable backend below the VFS (`xrootd_sd_driver_t`); POSIX is the default + behaviour oracle. |
| **the seam** | the `sd.h` vtable boundary: policy above (VFS), mechanism below (driver). |
| **funnel** | one of the four live read/write code paths (§1.1); *not* the header's promised single funnel (which is dead — §3). |
| **io-core / job** | `vfs_io_core.c` + `xrootd_vfs_job_t` — the POD, worker-safe EXECUTE surface (no pool/metrics/log/cache); the stream plane's data path. |
| **PREPARE / EXECUTE / COMPLETE** | Phase-54 op split: loop-side setup / worker-safe syscall / loop-side meter+log+cache. |
| **borrow instance** | `xrootd_sd_posix_borrow_instance` — wraps an existing persistent rootfd as a POSIX SD instance without owning the fd (B-1). |
| **rootfd** | persistent per-worker `O_PATH` fd on the export root; the `RESOLVE_BENEATH` anchor for `xrootd_open_beneath`. `-1` ⇒ HTTP transient path (B-4). |
| **confined-canon** | `xrootd_*_confined_canon` helpers — confined op on an already-resolved canonical path; impersonation-aware (broker-routed) (§0.3). |
| **`stat_current`** | handle bit: open-time `fstat` snapshot still authoritative ⇒ stat-without-syscall; cleared by write (B-3). |
| **impersonation** | Phase-40 per-request UNIX identity mapping; confined metadata ops route through the root **broker** (IPC), not a local syscall (§0.3). |
| **`d_type`** | `readdir(3)` entry type (DT_REG/DT_DIR/DT_LNK/DT_UNKNOWN); free classification, dropped today (C-1). |
| **`CAP_*`** | SD capability bits (`sd.h:41`): FD/SENDFILE/RANDOM_WRITE/RANGE_READ/TRUNCATE/SERVER_COPY/XATTR/HARD_RENAME/DIRS/APPEND/IOURING. |
| **dead body** | a function with zero callers (`xrootd_vfs_read`/`write` and their private builders) — §3, §8, Appendix A. |
| **seam closure** | Pillar F (§9): migrating every export data/namespace op onto `xrootd_vfs_*` so the VFS is the *sole* data-plane funnel; the complement of §3. |
| **tier-1 / tier-2 bypass** | tier-1 = a handler calls **libc** directly on export data; tier-2 = a handler calls the **confined-helper layer** directly, skipping `xrootd_vfs_*` (§9.1). Tier-1 is ~clean; tier-2 is the ~105-site backlog. |
| **confined-helper layer** | `xrootd_*_confined_canon` / `xrootd_*_beneath` / `xrootd_ns_*` / `xrootd_staged_*` (in `src/path/`, `src/compat/`) — the POSIX primitives the SD driver delegates to; handlers must reach them *through* the VFS, not directly (§9.1). |
| **backend store / staging store** | Phase-55's two independently-selectable SD instances per export — a durable backend (`xrootd_storage_backend`) and an in-progress staging store (`xrootd_storage_staging`); §9.6/§9.7 route multipart + scratch through the latter. |
| **CI seam guard** | `tools/ci/check_vfs_seam.sh` + shrinking `vfs_seam_backlog.txt` (§9.9) — fails the build on a *new* bypass; the enforcement that keeps the VFS the sole source of truth once §9 lands. |
| **tier-1.5 bypass** | calls the **SD driver vtable** directly (`xrootd_sd_posix_driver.pread`) — below the VFS but above libc; FRM's journal reader (`frm/reqfile.c`) does this. Shares A-1's no-benefit indirection (§9.3). |
| **loop-only ctx-op** | a VFS namespace/metadata op (`xrootd_vfs_stat`/`rename`/`mkdir`/`unlink`/`copy`/`staged_commit`) that emits its metric+access-log inline on the event-loop thread — so it cannot be called from a thread-pool worker without the §9.12 reconciliation. |
| **thread-offload friction** | §9.12: ~4 handlers (`move.c`/`copy.c` collection paths) offload a namespace op to a worker; migrating them to loop-only ctx-ops means dropping the offload (preferred for O(1) ops) or adding a PREPARE/EXECUTE/COMPLETE namespace variant. |

---

## Appendix C — the complete enumerated seam-closure backlog (`vfs_seam_backlog.txt`)

The full, comment-filtered inventory behind the §9.4 counts: **105 call sites in 39
files** (`src/cache/` excluded — VFS-internal; the §9.6 raw-syscall sites are listed
separately at the end). This is the seed content for the §9.9 CI-guard allowlist —
each migration phase deletes its rows; when the table is empty the seam is closed.
Families: **O**=open→`vfs_open`, **S**=stat→`vfs_stat`, **D**=opendir→`vfs_opendir`,
**N**=ns-mutate→`vfs_mkdir`/`rename`/`unlink`/`rmdir`, **G**=staged→`vfs_staged_*`.
(Line numbers drift; the file path + family is the stable key the CI guard matches.)

### C.1 Stream `root://` (`src/read`, `write`, `dirlist`, `connection`, `query`, `fattr`, `tpc`, `path`) — 24 sites

| File | Fam (n) | Phase | Note |
|---|---|---|---|
| `read/open_resolved_file.c` | O(1) | **F6** | **hot** `kXR_open`; handle table wants raw fd (§9.5) |
| `connection/fd_table.c` | O(1) | **F6** | **hot** bound-handle reopen (§9.5) |
| `read/stat.c` | S(1) | F3/F7 | cache-path stat (borderline §9.7) |
| `dirlist/handler.c` | O(2) | F5 | stream `kXR_dirlist` dir open (+ a raw `fstatat`/child, `:565`) |
| `query/checksum_ckscan_common.c` | O(2) | F5 | checksum scan (+ raw `fstatat`, `:172`) |
| `query/checksum_ckscan_dispatch.c` | O(1) | F5 | checksum scan dispatch |
| `query/checksum_ckscan_async.c` | O(1) | F5 | async checksum scan |
| `query/checksum_qcksum.c` | O(1) | F5 | `Qcksum` open |
| `fattr/dispatch.c` | O(1) | F5 | extended-attr op open |
| `tpc/launch.c` | O(1) | F5 | native-TPC destination open |
| `path/op_path.c` | S(1) | F3 | path-op stat helper |
| `write/mv.c` | S(1) N(1) | F2/F3 | `kXR_mv` (`:149` lstat, `:198` rename) |
| `write/mkdir.c` | N(1) | F2 | `kXR_mkdir` |
| `write/op_table.c` | N(2) | F2 | `kXR_rm`/`rmdir` descriptors |
| `write/truncate.c` | O(1) | F5 | `kXR_truncate`-by-path open |
| `write/chkpoint.c` | O(2) G(3) | F4/F7 | checkpoint journal (gateway-private, §9.7) |

### C.2 WebDAV (`src/webdav`) — 40 sites

| File | Fam (n) | Phase | Note |
|---|---|---|---|
| `namespace.c` | N(1) | **F2** | **MKCOL** (`:137`) — DELETE sibling already migrated (§9.11 template) |
| `move.c` | N(1) S(2) | F2/F3 | MOVE rename + 2 stat; thread-offloaded (§9.12) |
| `copy.c` | S(2) | F3 | COPY pre-checks (COPY body already on `vfs_copy`) |
| `fs/copy_engine.c` | S(2) O(2) D(1) | F3/F5 | recursive COPY tree walk |
| `lock.c` | O(1) S(3) D(1) | F3/F5 | WebDAV lock database |
| `propfind.c` | O? S(2) D(2) | F3 | PROPFIND collection enumerate+lstat |
| `search.c` | O(1) S(1) | F3 | SEARCH (DASL) |
| `methods_basic.c` | O(1) | F5 | misc method open |
| `put.c` | S(1) G(3) | F4 | residual (main path on `vfs_staged_open`) |
| `tpc.c` | S(2) G(9) | **F4** | TPC stat + staged-abort **ladder** (migrates as 1 unit) |
| `tpc_curl.c` | O(2) | F5 | TPC curl src/dst opens |

### C.3 S3 (`src/s3`) — 41 sites

| File | Fam (n) | Phase | Note |
|---|---|---|---|
| `put.c` | O? S? G(16) | **F4** | **un-migrated simple PUT** — 16× raw `staged` abort ladder (20 total); POST-object sibling migrated |
| `object.c` | O(1) N(1) | F2/F5 | GetObject open + DeleteObject `ns_delete` |
| `delete_objects.c` | N(1) | F2 | bulk DeleteObjects |
| `copy.c` | S(1) | F3 | CopyObject pre-stat (body on `vfs_copy`) |
| `post_object.c` | S(1) | F3 | residual (POST-object on `vfs_staged_*`) |
| `checksum.c` | O(2) | F5 | checksum read-open |
| `list_walk.c` | S(2) O(1) | F3 | ListObjects walk |
| `multipart_complete_body.c` | O? S? (4) | F4 | multipart assembly |
| `multipart_complete_list_parts.c` | S(1) O(1) D(1) | F3 | list parts |
| `multipart_complete_list_uploads.c` | O(1) S(1) D(2) | F3 | list uploads |
| `multipart_complete_upload_part_copy.c` | S(1) O(1) | **F1** | §9.6 asymmetry + raw dst `open`/copy-loop |
| `multipart_helpers.c` | O(1) D(1) | F3 | shared multipart helpers |

### C.4 The §9.6 raw / unconfined subset (tier-1, separate from the 105) — fix in F1

```
src/s3/multipart_complete_upload_part_copy.c:153  open(part_path, O_CREAT|O_TRUNC)   ← raw, no O_NOFOLLOW (write-side asymmetry)
src/s3/multipart_complete_upload_part_copy.c:160  read()/write() copy loop           ← userspace copy (use copy_range)
src/s3/multipart_complete_upload_part_copy.c:129  stat(mpu_dir) / :183 stat(part_path)
src/s3/multipart_complete_list_parts.c:156        lstat(part_path)
src/s3/multipart_helpers.c:214                    lstat(full)
```

### C.5 Legitimate non-targets (allowlisted permanently, never migrate — §9.8)

```
src/path/beneath.c  src/path/resolve_confined_ops.c  src/path/resolve_confined_helpers.c   # helper DEFINITIONS
src/compat/namespace_ops.c  src/compat/staged_file.c  src/compat/fs_walk.c                 # the layer sd_posix delegates to
src/impersonate/broker.c                                                                    # privileged execution backend (below seam)
src/dashboard/files.c                                                                       # separate admin browse-root, own confinement
src/cache/open.c                                                                            # VFS-internal (called from xrootd_vfs_open)
src/frm/reqfile.c                                                                           # tier-1.5: SD-vtable-direct on FRM-private journal (§9.3)
```
