# VFS Seam Residue Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **STATUS — 2026-07-01: Task 1 ✅ done, Task 3 ✅ done, Task 2 ⏸ deferred.** Build clean, `check_vfs_seam.sh` green, S3 multipart tests 17 passed, checkpoint/POSC/resume 29 passed. Two learnings reshaped the tasks:
> - **The guard requires the full `xrootd_vfs_*` seam, not the `*_confined_canon` bypass layer** the plan first reached for (`*_confined_canon` is a per-file grandfathered tier-2 bypass; adding it to a new file is rejected). So **Task 1** was reworked onto `xrootd_vfs_probe` (existence, via `s3_build_vfs_ctx`) + `xrootd_vfs_open_fd` + `xrootd_vfs_unlink_path` + an `fstat` on the VFS-opened part fd (it also folded in a *fourth* raw stat found at `upload_part_copy.c:133`, and the ETag stat at :206). **Task 3** used `xrootd_vfs_unlink_path` (not `xrootd_unlink_confined_canon`) and, better than planned, needs **no new handle field** — teardown derives `root_canon` from `ctx->session` (via `ngx_stream_get_module_srv_conf`), with a marked raw fallback only for a path genuinely not under the export root.
> - **Task 2 (TPC size-probes) deferred:** they are size-only progress/byte-count probes on server-controlled temps, already accepted carve-outs (marked, guard-green). The proper `xrootd_vfs_*` migration is blocked/disproportionate: two sites run **off-thread** (`tpc_thread`, no thread-safe request pool for `xrootd_vfs_ctx_init`), and the temps' under-export status is unconfirmed (if they live outside the export they are irreducible). Low value, non-trivial cost — left as documented carve-outs.

**Goal:** Migrate the last cluster of *under-export* raw-POSIX sites onto the **existing** confined VFS primitives, and give the file handle a `root_canon` so checkpoint/POSC teardown can confined-unlink — removing ~9 `vfs-seam-allow` carve-outs without inventing any new mechanism.

**Architecture:** A scope correction drives this plan. The auxiliary domains I earlier flagged as needing a new "worker-scratch VFS context" turned out to be **already under the export root and already ~80–90% on the VFS** (S3 multipart uses `xrootd_mkdir_confined_canon`/`xrootd_vfs_open_fd`/`xrootd_vfs_ctx_t`; TPC uses `xrootd_link/unlink/rename_confined_canon`; `mpu_rmdir_recursive`/`s3_mpu_reap_stale` are fully on the VFS seam). What remains is a small **residue** of under-migrated calls (a `lstat`, one dst-part `open`+`unlink`, three `stat` size-probes) that map directly onto existing primitives, plus two checkpoint/POSC `unlink`s at `fd_table` teardown that lack a `root_canon`. **No new VFS context is built.** The genuinely-outside-export worker scratch (none remain after this) is not needed.

**Tech Stack:** C (nginx http + stream module), the existing confined VFS surface — `xrootd_vfs_open_fd` / `xrootd_vfs_unlink_path` / `xrootd_vfs_unlink_at` (`src/fs/vfs.h`), `xrootd_lstat_confined_canon` / `xrootd_unlink_confined_canon` (`src/path/path.h`) — the existing S3/TPC/checkpoint test harnesses as the gate, and `tools/ci/check_vfs_seam.sh`.

## Global Constraints

- **NO `goto`** anywhere in `src/` (`docs/09-developer-guide/coding-standards.md` §4) — early-return + helper decomposition.
- **`*_confined_canon` primitives take the ABSOLUTE path** (they strip `root_canon` themselves — never pre-strip), per CLAUDE.md INVARIANT #11.
- **`xrootd_vfs_open_fd` / `xrootd_vfs_unlink_path` take the LOGICAL (export-relative) path**; `xrootd_vfs_*_at` take the persistent `rootfd` + logical path. Match the existing callers in the same file when choosing which.
- **Impersonation correctness:** the staging dirs are mapped-user-owned (0700); the confined ops perform as the mapped user under impersonation, which is exactly why a raw worker call EACCESes. Do **not** "fix" an EACCES by reverting to raw — route through the confined op.
- **Behavior-preserving:** identical HTTP/kXR status codes and side effects; the existing S3/TPC/checkpoint suites must pass unchanged.
- **Section-level WHAT/WHY/HOW doc block on every changed function**; functional/modular, no new globals.
- Build: incremental `make -j$(nproc)`; no `./configure` (no new `.c`, no new directive). Task 3 adds one struct field (no build-system change).
- Each task ends with `tools/ci/check_vfs_seam.sh` green and its domain's tests passing.

---

### Task 1: S3 multipart staging residue → confined VFS ops

Three raw sites remain in S3 multipart; all are under the export with `root_canon` in scope and direct existing-primitive equivalents.

**Files:**
- Modify: `src/s3/multipart_abort.c:40` (the `lstat(mpu_dir)` existence probe)
- Modify: `src/s3/multipart_complete_upload_part_copy.c:156,186` (dst-part `open` + error `unlink`)
- Test: `tests/` S3 multipart suite (see Step 4)

**Interfaces:**
- Consumes: `int xrootd_lstat_confined_canon(ngx_log_t *log, const char *root_canon, const char *resolved, struct stat *st, int nofollow)` → 0/-1 (`path.h`); `int xrootd_vfs_open_fd(ngx_log_t *log, const char *root_canon, const char *logical, int flags, mode_t mode)` → raw fd/-1 (`vfs.h:398`); `int xrootd_vfs_unlink_path(ngx_log_t *log, const char *root_canon, const char *logical)` → 0/-1 (`vfs.h:411`). `root_canon` is `cf->common.root_canon` (already used at `multipart_complete_body.c:93` and `multipart_initiate.c:79`).
- Produces: identical 404/500/204 semantics; three markers removed.

- [ ] **Step 1: Migrate the abort existence probe**

In `src/s3/multipart_abort.c`, the staging-dir probe currently is:

```c
    if (lstat(mpu_dir, &sb) != 0) {  /* vfs-seam-allow: S3 multipart staging-dir domain */
```

Replace with the confined stat (the `cf` loc-conf is already resolved in this handler — grep `cf` / `loc_conf` at the top of the function for the exact local; it mirrors the other multipart handlers):

```c
    if (xrootd_lstat_confined_canon(r->connection->log, cf->common.root_canon,
                                    mpu_dir, &sb, 1 /* nofollow */) != 0) {
```

(Drop the `vfs-seam-allow` comment. `mpu_dir` is the absolute path; `*_confined_canon` strips `root_canon` itself.)

- [ ] **Step 2: Migrate the dst-part open + error unlink**

In `src/s3/multipart_complete_upload_part_copy.c`, the destination part file open (line ~156):

```c
    dst_fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);  /* vfs-seam-allow: S3 multipart staging-dir domain */
```

becomes (mirroring `multipart_complete_body.c:93`'s `xrootd_vfs_open_fd`):

```c
    dst_fd = xrootd_vfs_open_fd(r->connection->log, cf->common.root_canon,
                               part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                               0600);
```

and the error-path cleanup (line ~186):

```c
            unlink(part_path);  /* vfs-seam-allow: S3 multipart staging-dir domain */
```

becomes:

```c
            (void) xrootd_vfs_unlink_path(r->connection->log,
                                          cf->common.root_canon, part_path);
```

Confirm `cf` (the S3 loc-conf with `common.root_canon`) is in scope at both sites; the file already builds an `xrootd_vfs_ctx_t sctx` (line 69) so the loc-conf is available — reuse the same local. The data copy below (the `src_obj.driver->pread` → `dst_obj.driver->pwrite` loop) is already driver-routed and unchanged.

- [ ] **Step 3: Build**

Run: `make -j$(nproc)`
Expected: clean compile (`-Werror`).

- [ ] **Step 4: S3 multipart behavior unchanged**

Run: `PYTHONPATH=tests pytest tests/ -k "multipart or mpu or upload_part" -q -p no:cacheprovider`
Expected: PASS — initiate/upload-part/upload-part-copy/complete/abort all green, same status codes (NoSuchUpload 404, success 200/204). If the suite name differs, locate it: `grep -rl "AbortMultipartUpload\|upload_part\|CompleteMultipart" tests/`.

- [ ] **Step 5: Guard**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN`; the three S3 multipart markers are gone and no new raw site appears.

- [ ] **Step 6: Commit** — _skipped per standing instruction (no git); leave changes in the working tree._

---

### Task 2: TPC in-progress size probes → confined stat

Three raw `stat()` size-probes remain in the WebDAV TPC path (progress/byte accounting). They are under the export with `root_canon` available and map onto `xrootd_lstat_confined_canon`.

**Files:**
- Modify: `src/webdav/tpc_thread.c:152,205` (`stat(t->local_path)` after push/pull)
- Modify: `src/webdav/tpc_marker.c:469` (`stat(ctx->tmp_path)` single-stream progress)
- Test: the TPC test suite (see Step 3)

**Interfaces:**
- Consumes: `xrootd_lstat_confined_canon(log, root_canon, resolved, &st, nofollow)`. `root_canon` is `t->conf->common.root_canon` in `tpc_thread.c` and `ctx->root_canon` in `tpc_marker.c` (already used at `tpc_marker.c:178-211`).
- Produces: identical `bytes_transferred` / progress values; three markers removed.

- [ ] **Step 1: Migrate the tpc_thread size probes**

In `src/webdav/tpc_thread.c`, both occurrences (push at ~152, pull at ~205) of:

```c
            if (stat(t->local_path, &st) == 0) {  /* vfs-seam-allow: TPC local transfer temp */
                t->bytes_transferred = st.st_size;
            }
```

become:

```c
            if (xrootd_lstat_confined_canon(t->log, t->conf->common.root_canon,
                                            t->local_path, &st, 0) == 0) {
                t->bytes_transferred = st.st_size;
            }
```

(`nofollow=0` keeps the current `stat` follow semantics. Confirm `t->conf->common.root_canon` is the WebDAV export root for this transfer — it is the same conf used by `webdav_tpc_run_curl_push` on the line above.)

- [ ] **Step 2: Migrate the tpc_marker single-stream probe**

In `src/webdav/tpc_marker.c` (~469), inside the single-stream branch:

```c
            if (stat(ctx->tmp_path, &sb) == 0) {  /* vfs-seam-allow: TPC in-progress transfer temp (committed via rename) */
                bytes = sb.st_size;
            }
```

becomes:

```c
            if (xrootd_lstat_confined_canon(r->connection->log, ctx->root_canon,
                                            ctx->tmp_path, &sb, 0) == 0) {
                bytes = sb.st_size;
            }
```

(`ctx->root_canon` is already populated at `tpc_marker.c:455`. Use the request log already in scope in this function.)

- [ ] **Step 3: Build + TPC behavior**

Run:
```bash
make -j$(nproc)
PYTHONPATH=tests pytest tests/ -k "tpc and (webdav or push or pull or marker)" -q -p no:cacheprovider
```
Expected: clean build; WebDAV TPC push/pull + the performance-marker progress stream report the same byte counts. (If a dedicated harness exists — `grep -rl "tpc" tests/run_*.sh` — run it too.)

- [ ] **Step 4: Guard**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN`; the three TPC stat markers gone.

- [ ] **Step 5: Commit** — _skipped per standing instruction._

---

### Task 3: Checkpoint / POSC teardown → confined unlink via a handle-carried `root_canon`

The two `fd_table` teardown unlinks (`file->ckp_path`, the POSC `file->path`) are raw because, as their markers say, "teardown context has no export root." Give the handle a borrowed `root_canon` at open time so teardown can `xrootd_unlink_confined_canon` the handle-owned staging temp.

**Files:**
- Modify: `src/types/file.h` (add `root_canon` to `xrootd_file_t`)
- Modify: the handle-open site that sets `ckp_path`/`posc_final_path`/`path` (grep below) to also set `file->root_canon`
- Modify: `src/connection/fd_table.c:288,305` (the teardown unlinks)
- Test: checkpoint + POSC abandon tests (see Step 5)

**Interfaces:**
- Consumes: `int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon, const char *resolved)` (`path.h:130`, absolute-path input). The open-time `root_canon` is `conf->common.root_canon` (a stable per-worker borrowed pointer, already used in `fd_table.c` at the open path, e.g. line 125/128).
- Produces: a new `const char *root_canon` field on `xrootd_file_t`; identical teardown removal behavior, now confined; two markers removed.

- [ ] **Step 1: Add the field**

In `src/types/file.h`, in `xrootd_file_t`, add next to `path`:

```c
    /* Borrowed export root_canon (stable for the worker's life) so handle-owned
     * staging temps (ckp_path / POSC path) can be confined-unlinked at teardown,
     * where no request/conf context is in scope. NULL ⇒ fall back to raw. */
    const char  *root_canon;
```

- [ ] **Step 2: Populate it at handle open**

Find where the handle's `path` (and `ckp_path`/`posc_final_path`) are set at open — grep for the assignment:

```bash
grep -rn "file->path =\|->ckp_path =\|->posc_final_path =" src/read src/write src/connection
```

At that open site (which has the stream `conf` in scope), set:

```c
    file->root_canon = conf->common.root_canon;
```

(Borrowed, not copied — `root_canon` lives in the conf for the worker's lifetime. Set it wherever the handle is first populated for a writable/checkpoint/POSC open; setting it unconditionally on every open is fine and simplest.)

- [ ] **Step 3: Confined-unlink at teardown — checkpoint**

In `src/connection/fd_table.c` (~288):

```c
    if (file->ckp_path != NULL) {
        (void) unlink(file->ckp_path);  /* vfs-seam-allow: ... */
        ngx_free(file->ckp_path);
    }
```

becomes:

```c
    if (file->ckp_path != NULL) {
        if (file->root_canon != NULL) {
            (void) xrootd_unlink_confined_canon(NULL, file->root_canon,
                                                file->ckp_path);
        } else {
            (void) unlink(file->ckp_path);  /* vfs-seam-allow: no export root on this handle */
        }
        ngx_free(file->ckp_path);
    }
```

(Pass the teardown log if one is in scope in this function; `NULL` is acceptable for the confined op. Keep a marked raw fallback for the `root_canon == NULL` case so a handle opened without it never leaks.)

- [ ] **Step 4: Confined-unlink at teardown — POSC**

In `src/connection/fd_table.c` (~305):

```c
    if (file->posc_final_path != NULL) {
        if (file->path != NULL && !file->is_resume) {
            (void) unlink(file->path);  /* vfs-seam-allow: ... */
        }
        ngx_free(file->posc_final_path);
    }
```

becomes:

```c
    if (file->posc_final_path != NULL) {
        if (file->path != NULL && !file->is_resume) {
            if (file->root_canon != NULL) {
                (void) xrootd_unlink_confined_canon(NULL, file->root_canon,
                                                    file->path);
            } else {
                (void) unlink(file->path);  /* vfs-seam-allow: no export root on this handle */
            }
        }
        ngx_free(file->posc_final_path);
    }
```

Add `#include` for the confined-unlink declaration if `fd_table.c` does not already see `path.h` (grep its includes; it likely reaches it via `vfs.h` / the module header).

- [ ] **Step 5: Build + checkpoint/POSC behavior**

Run:
```bash
make -j$(nproc)
PYTHONPATH=tests pytest tests/ -k "chkpoint or checkpoint or posc or resume" -q -p no:cacheprovider
```
Expected: clean build; checkpoint rollback temp removed on abandon, POSC abandon unlinks the staging temp, **upload-resume partial is still preserved** (`is_resume` path untouched). If a raw-wire harness exists (`grep -rl "ckpBegin\|posc" tests/`), run it.

- [ ] **Step 6: Guard**

Run: `bash tools/ci/check_vfs_seam.sh && echo GUARD_GREEN`
Expected: `GUARD_GREEN`; the two teardown markers replaced by confined ops (the `root_canon == NULL` fallback retains a justified marker, which is correct — that path genuinely has no root).

- [ ] **Step 7: Commit** — _skipped per standing instruction._

---

## Out of scope (unchanged)

- **Cache fill/flush** (`fetch.c`, `writethrough_flush.c`) — active phase-64 SP2; tracked in `2026-07-01-cache-policy-cstore-consolidation.md`.
- **Genuinely non-storage raw I/O that must stay raw:** `/tmp` + GSI/bearer credential temps, `/proc` fd hygiene, HeadBucket/list-cache stat of the export root itself, metadata on an already-VFS-opened fd. These are not export storage and correctly keep their `vfs-seam-allow` markers.
- **`read/open_resolved_file.c` upload stage-dir** (2 markers) — a separate-domain staging open; deferrable, lower value, and entangled with the upload-resume staging path. Add a follow-up task only if a marker-zero goal demands it.

## Self-Review

**Spec coverage:** The "consolidatable" residue from the seam re-scan — S3 multipart (Task 1), TPC size-probes (Task 2), checkpoint/POSC teardown (Task 3) — is fully covered. The deferred/irreducible sets are listed explicitly. ✔

**Placeholder scan:** Every step shows the exact before/after with real signatures (`xrootd_lstat_confined_canon`, `xrootd_vfs_open_fd`, `xrootd_vfs_unlink_path`, `xrootd_unlink_confined_canon`). Three "grep the exact local/open-site" instructions are verification of existing in-file names (the `cf` loc-conf local, the handle-open assignment site, the `fd_table` include set), not logic placeholders. ✔

**Type consistency:** `root_canon` is `const char *` everywhere (conf field, the new `xrootd_file_t` field, every confined-op argument). `xrootd_lstat_confined_canon` is used with the same `(log, root_canon, abs_path, &st, nofollow)` shape in Tasks 1 and 2. The confined ops receive **absolute** paths (per the Global Constraint), matching how `mpu_dir`/`part_path`/`local_path`/`ckp_path` are already built. ✔

**Risk:** lowest of the consolidation plans — no new primitive, no new context, no signature changes to shared APIs; each site swaps a raw call for the confined equivalent already proven in the same file/family. The one behavioral subtlety (impersonation EACCES if a confined op is mis-pointed) is covered by the Global Constraint and the existing-caller mirroring.
