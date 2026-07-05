# brixMount cvmfs-rw Writable Overlay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `brixMount cvmfs-rw` mount type that unions a local writable upper layer (`<mnt>/.brixwrites/upper`, sibling of `.brixcache`) over the read-only CVMFS lower layer, with full POSIX semantics (copy-up, whiteout deletes, opaque dirs) plus `--overlay-list`/`--overlay-reset` CLI subcommands.

**Architecture:** A standalone FUSE-free/CVMFS-free union core (`client/lib/fs/overlay.{c,h}`) owns every upper-tree primitive behind a per-component `O_NOFOLLOW` walk; a new FUSE ops file (`client/apps/fs/brixcvmfs_rw.c`) composes overlay-first / `cvmfs_client_*`-fallback and exposes `/.brixwrites` as a read-write passthrough subtree; `brixmount.c` gains the `cvmfs-rw` table row and overlay subcommand routing. The read-only `cvmfs` driver is behavior-unchanged.

**Tech Stack:** C11, libfuse3 (high-level API, single-threaded `-s`), plain POSIX `*at()` syscalls, existing mock-repo harness (`tests/cvmfs/brix_mkrepo.c`).

**Spec:** `docs/superpowers/specs/2026-07-05-brixmount-cvmfs-writable-overlay-design.md`

## Global Constraints

- **NO `goto`** anywhere; early-return + helper decomposition (CLAUDE.md HARD BLOCK).
- Functional/modular: one job per function, explicit data flow, WHAT/WHY/HOW doc block on every file and section-level function.
- Overlay core returns `0`/`-errno` (FUSE convention); fd-returning functions return `fd >= 0` or `-errno`.
- Reserved names: prefix `.brix.wh.`, exact `.brix.opq`, prefix `.brix.tmp.` — rejected with `-EPERM` through the mount; `.brixwrites`/`.brixcache` reserved at mount root.
- Upper paths are repo-relative WITHOUT leading slash (`""` = root), matching `cat_path()`.
- All upper-tree access via per-component `O_NOFOLLOW` walk rooted at the `upper/` dirfd — never absolute paths, never following symlinks (symlink-escape defense).
- Every unit test compile line: `gcc -Wall -Wextra -Werror` (repo standard).
- Commits go directly to `main` (no branches — user rule). Stage ONLY the files each task names (the worktree carries unrelated uncommitted WIP).
- Build check for client tree: `make -C client -j$(nproc)` must stay green.

---

### Task 1: Overlay core — walk, classify, whiteout/opaque primitives

**Files:**
- Create: `client/lib/fs/overlay.h`
- Create: `client/lib/fs/overlay.c`
- Create: `client/lib/fs/overlay_unittest.c`
- Create: `tests/run_overlay_unit.sh`
- Modify: `client/Makefile:110` (add `lib/fs/overlay.c` to `LIB_SRCS`)

**Interfaces:**
- Produces (used by all later tasks):
  - `typedef struct { int writes_fd; int upper_fd; } brix_overlay;`
  - `typedef enum { BRIX_OV_NONE=0, BRIX_OV_UPPER, BRIX_OV_MASKED } brix_ov_state;`
  - `int brix_overlay_init(brix_overlay *ov, int writes_fd);` — opens/creates `upper/`, fills `upper_fd`
  - `void brix_overlay_close(brix_overlay *ov);`
  - `int brix_ov_name_reserved(const char *name);` — 1 for `.brix.wh.*` / `.brix.opq` / `.brix.tmp.*`
  - `int brix_overlay_classify(const brix_overlay *ov, const char *rel, struct stat *st, brix_ov_state *state);`
  - `int brix_overlay_whiteout(const brix_overlay *ov, const char *rel);` — query 1/0/-errno
  - `int brix_overlay_whiteout_set(const brix_overlay *ov, const char *rel);` (creates parent chain)
  - `int brix_overlay_whiteout_clear(const brix_overlay *ov, const char *rel);`
  - internal (static in overlay.c, reused by every later primitive): `ov_walk_parent(const brix_overlay *ov, const char *rel, char *name_out, size_t name_cap)` → parent dirfd or -errno, O_NOFOLLOW per component; with `mkparents` variant.

Header constants: `BRIX_OV_WH_PREFIX ".brix.wh."`, `BRIX_OV_OPQ_NAME ".brix.opq"`, `BRIX_OV_TMP_PREFIX ".brix.tmp."`, `BRIX_OV_DIRNAME ".brixwrites"`, `BRIX_OV_UPPER_DIRNAME "upper"`.

Classify semantics (the load-bearing logic):
- Walk `rel` component by component from `upper_fd`.
- At each level, `.brix.wh.<comp>` present in current dir → `BRIX_OV_MASKED`.
- Component opens as dir (O_NOFOLLOW|O_DIRECTORY) → descend; remember whether it contains `.brix.opq`.
- Component exists but is NOT a dir mid-path → `BRIX_OV_MASKED` (an upper file shadows the whole lower subtree).
- Component missing mid-path or at leaf → `BRIX_OV_MASKED` if any traversed dir was opaque, else `BRIX_OV_NONE`.
- Leaf exists → `BRIX_OV_UPPER`, `fstatat(..., AT_SYMLINK_NOFOLLOW)` into `st`.

- [ ] **Step 1: Write the failing unit test** (`client/lib/fs/overlay_unittest.c`) with a `CHECK` macro like `brixmount_unittest.c`, a `mkdtemp`-based fixture, and cases:
  - init creates `upper/` under the writes dir
  - `brix_ov_name_reserved`: `.brix.wh.x`=1, `.brix.opq`=1, `.brix.tmp.a`=1, `hello`=0, `.brixcacheX`=0
  - classify absent path → `BRIX_OV_NONE`
  - create `upper/a/b` via raw mkdir/creat in the fixture → classify `a/b` → `BRIX_OV_UPPER` with `S_ISREG`, classify `a` → UPPER dir
  - raw-create `upper/.brix.wh.gone` → classify `gone` → MASKED; `whiteout("gone")` → 1
  - `whiteout_set("sub/dead")` then classify `sub/dead` → MASKED (parent chain auto-created)
  - `whiteout_clear("sub/dead")` → classify → NONE
  - opaque: mkdir `upper/od` + creat `upper/od/.brix.opq` → classify `od/missing` → MASKED, but classify `od` → UPPER
  - upper file shadows subtree: creat `upper/f` → classify `f/child` → MASKED
  - **security-neg:** `symlink("/etc", upper/esc)` → classify `esc/passwd` must NOT follow: expect MASKED or -ELOOP-derived error, and specifically never `BRIX_OV_UPPER`/NONE-with-follow (assert classify of `esc` itself is UPPER symlink via `S_ISLNK`)
- [ ] **Step 2: Write `tests/run_overlay_unit.sh`** (pattern `run_brixmount_unit.sh`):

```bash
#!/usr/bin/env bash
# run_overlay_unit.sh — unit tests for the brixMount writable-overlay core.
set -euo pipefail
cd "$(dirname "$0")/.."
gcc -Wall -Wextra -Werror -I client/lib -o /tmp/overlay_ut \
    client/lib/fs/overlay_unittest.c client/lib/fs/overlay.c
/tmp/overlay_ut
```

- [ ] **Step 3: Run it — expect compile failure** (overlay.h missing): `bash tests/run_overlay_unit.sh` → FAIL
- [ ] **Step 4: Write `overlay.h`** (full WHAT/WHY/HOW header per spec §1, guard `XRDC_OVERLAY_H`) declaring everything in **Interfaces**, and **`overlay.c`** implementing init/close, reserved-name check, the `ov_walk_parent` + `ov_walk_parent_mk` walkers, classify, whiteout query/set/clear. No goto — each helper single-purpose.
- [ ] **Step 5: Run test → PASS**: `bash tests/run_overlay_unit.sh` → `N checks, 0 failed`
- [ ] **Step 6: Add `lib/fs/overlay.c` to `LIB_SRCS`** in `client/Makefile` (line ~110, alphabetical beside `lib/fs/path.c`), then `make -C client -j$(nproc)` → green.
- [ ] **Step 7: Commit** `client/lib/fs/overlay.{h,c}`, `client/lib/fs/overlay_unittest.c`, `tests/run_overlay_unit.sh`, `client/Makefile` — `feat(client): overlay core — classify/whiteout/opaque primitives`

### Task 2: Overlay core — mutation primitives

**Files:**
- Modify: `client/lib/fs/overlay.h`, `client/lib/fs/overlay.c`, `client/lib/fs/overlay_unittest.c`

**Interfaces (produces):**
- `int brix_overlay_mkdirs(const brix_overlay *ov, const char *rel_dir, mode_t (*mode_fn)(void *ud, const char *rel), void *ud);` — ensure upper dir chain; `mode_fn==NULL` → 0755
- `int brix_overlay_open(const brix_overlay *ov, const char *rel, int oflags, mode_t mode);` → fd/-errno (O_NOFOLLOW forced; parents NOT auto-created)
- `int brix_overlay_mkdir(const brix_overlay *ov, const char *rel, mode_t mode);`
- `int brix_overlay_set_opaque(const brix_overlay *ov, const char *rel_dir);`
- `int brix_overlay_unlink_upper(const brix_overlay *ov, const char *rel);`
- `int brix_overlay_rmdir_upper(const brix_overlay *ov, const char *rel);` — unlinks ONLY marker files inside, then AT_REMOVEDIR; real entries → -ENOTEMPTY
- `int brix_overlay_rename_upper(const brix_overlay *ov, const char *from, const char *to);`
- `int brix_overlay_symlink(const brix_overlay *ov, const char *target, const char *rel);`
- `int brix_overlay_readlink(const brix_overlay *ov, const char *rel, char *buf, size_t n);`
- `int brix_overlay_chmod(const brix_overlay *ov, const char *rel, mode_t mode);` — S_ISLNK leaf → -EOPNOTSUPP
- `int brix_overlay_utimens(const brix_overlay *ov, const char *rel, const struct timespec tv[2]);` (AT_SYMLINK_NOFOLLOW)
- `int brix_overlay_truncate(const brix_overlay *ov, const char *rel, off_t len);`

- [ ] **Step 1: Extend unit test** — failing cases: mkdirs deep chain (+ mode_fn honored), open O_CREAT|O_EXCL then classify UPPER, mkdir/EEXIST, unlink_upper, rmdir_upper on dir holding only `.brix.wh.x` marker succeeds, rmdir_upper with a real file → -ENOTEMPTY, rename_upper across dirs, symlink+readlink round-trip, chmod 0640 visible in classify st_mode, truncate to 3 bytes, utimens sets mtime 12345; **error-neg:** open of missing parent → -ENOENT; **security-neg:** truncate through `upper/esc → /etc` symlink → -ELOOP (walk refuses).
- [ ] **Step 2: Run → FAIL** (undefined symbols)
- [ ] **Step 3: Implement** in overlay.c on top of `ov_walk_parent`/`ov_walk_parent_mk` (chmod: `fstatat` first, S_ISLNK → -EOPNOTSUPP, else `fchmodat(parent, name, mode, 0)`; truncate: `openat(parent, name, O_WRONLY|O_NOFOLLOW)` + `ftruncate`)
- [ ] **Step 4: Run → PASS**; `make -C client -j$(nproc)` green
- [ ] **Step 5: Commit** — `feat(client): overlay core — upper-tree mutation primitives`

### Task 3: Overlay core — atomic copy-up

**Files:**
- Modify: `client/lib/fs/overlay.h`, `client/lib/fs/overlay.c`, `client/lib/fs/overlay_unittest.c`

**Interfaces (produces):**
- `typedef int (*brix_ov_read_fn)(void *ud, const char *rel, uint64_t off, size_t len, unsigned char *buf, size_t *outlen);` — 0/-errno; `*outlen==0` = EOF
- `int brix_overlay_copyup(const brix_overlay *ov, const char *rel, const struct stat *lower_st, brix_ov_read_fn read_lower, void *ud);` — parents via mkdirs(NULL); writes `.brix.tmp.<name>` beside the target; streams in 1 MiB chunks; `futimens` to lower mtime; `renameat` into place; `whiteout_clear(rel)`; on ANY failure unlinks the tmp and returns -errno

- [ ] **Step 1: Extend unit test** — mock `read_lower` serving a 3 MiB patterned buffer (checks multi-chunk loop): copyup → classify UPPER, size==3 MiB, byte-spot-checks, mtime==lower_st mtime, mode==lower_st mode&07777, no `.brix.tmp.*` residue; copyup over an existing whiteout clears it; **error-neg:** read_lower returning -EIO at offset 1 MiB → copyup returns -EIO AND no target file AND no tmp residue.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement** (single helper `ov_copyup_stream(int tmpfd, const char*rel, uint64_t size, read_fn, ud)`; malloc'd 1 MiB buffer, freed on all paths — early-return via small helpers, no goto)
- [ ] **Step 4: Run → PASS**; commit — `feat(client): overlay core — atomic tmp+rename copy-up`

### Task 4: Overlay core — readdir nameset

**Files:**
- Modify: `client/lib/fs/overlay.h`, `client/lib/fs/overlay.c`, `client/lib/fs/overlay_unittest.c`

**Interfaces (produces):**
- `typedef struct { char *buf; size_t used, cap, count; } brix_ov_nameset;`
- `int brix_overlay_read_upper(const brix_overlay *ov, const char *rel, brix_ov_nameset *set, int *opaque);` — packs entries `<flag><name>\0` (flag `'u'` real upper entry, `'w'` whiteout base-name); strips `.brix.opq`/`.brix.tmp.*`; `*opaque=1` when `.brix.opq` present; missing upper dir → 0 with empty set
- `char brix_ov_nameset_flag(const brix_ov_nameset *s, const char *name);` — 0 absent / `'u'` / `'w'`
- `const char *brix_ov_nameset_at(const brix_ov_nameset *s, size_t i, char *flag);`
- `void brix_ov_nameset_free(brix_ov_nameset *s);`

- [ ] **Step 1: Extend unit test** — dir with `a`, `sub/`, `.brix.wh.gone`, `.brix.opq`, `.brix.tmp.x`: read_upper → count==3 (`a`,`sub` flagged 'u'; `gone` flagged 'w'), opaque==1, `.brix.tmp.x` absent; flag lookups; iteration order stable; empty/missing dir → count 0 opaque 0.
- [ ] **Step 2–4:** FAIL → implement (grow-doubling buf) → PASS; commit — `feat(client): overlay core — merged-readdir nameset`

### Task 5: Overlay CLI cores (--overlay-list / --overlay-reset)

**Files:**
- Modify: `client/lib/fs/overlay.h`, `client/lib/fs/overlay.c`, `client/lib/fs/overlay_unittest.c`

**Interfaces (produces, consumed by Task 8):**
- `int brix_overlay_cli_list(const char *mountdir, FILE *out);` — exit code 0/2; guard: `<mountdir>/.brixwrites/upper` must exist else prints error → 2. Recursive lstat walk; per entry prints `deleted <rel>` (whiteout marker), `dir <rel>`, else `lgetxattr(<mountdir>/<rel>, "user.overlay")` → `new`/`modified`; xattr unavailable (unmounted) → `upper <rel>`. Skips `.brix.opq`/`.brix.tmp.*`.
- `int brix_overlay_cli_reset(const char *mountdir);` — same guard; recursively empties `upper/` contents (keeps `upper/` itself), never follows symlinks.

- [ ] **Step 1: Extend unit test** (raw dirs, no mount): fixture `<d>/.brixwrites/upper/{n.txt, sub/m.txt, .brix.wh.del, sub/.brix.opq}`; list into `open_memstream` → lines `upper n.txt`, `dir sub`, `upper sub/m.txt`, `deleted del`, no `.brix.opq` line; reset → `upper/` empty but present; **error-neg:** list/reset on a dir without `.brixwrites` → 2 and untouched.
- [ ] **Step 2–4:** FAIL → implement (path-string recursion with `lstat`, `unlinkat` via opened parent fds) → PASS; commit — `feat(client): overlay CLI list/reset cores`

### Task 6: brixcvmfs read-only op exposure (mechanical refactor, no behavior change)

**Files:**
- Create: `client/apps/fs/brixcvmfs_internal.h`
- Modify: `client/apps/fs/brixcvmfs.c`

**Interfaces (produces, consumed by Task 7):**
- `brixcvmfs_internal.h` declares: `cvmfs_client_t *brixcvmfs_cl(void);` `const char *brixcvmfs_cat_path(const char *p);` `long brixcvmfs_mono_now(void);` and the renamed non-static ro ops `int brixcvmfs_op_getattr(...)`, `_op_readdir`, `_op_open`, `_op_read`, `_op_readlink`, `_op_statfs`, `_op_getxattr`, `_op_listxattr` (exact fuse3 signatures as today) + `int brixcvmfs_setup_rw(const char *mnt, const char *writes_override);` (declared now, defined Task 7) + `extern int brixcvmfs_rw;` flag + `brix_overlay *brixcvmfs_ov(void);`
- brixcvmfs.c: rename the 8 ro ops `op_X` → `brixcvmfs_op_X` (drop `static`), keep the ops table pointing at them; keep `g_cl` static but add the accessor.

- [ ] **Step 1:** Apply the mechanical rename + accessor additions; header has full WHAT/WHY/HOW block.
- [ ] **Step 2: Verify no behavior change:** `bash tests/run_brixcvmfs_check.sh` → `BRIXCVMFS --check OK`; `bash tests/run_brixcvmfs_clever_live.sh` → `CLEVER OVERLAY + DPI-HARDENING LIVE OK`; `bash tests/run_brixmount_unit.sh` → 0 failed. (These scripts compile brixcvmfs.c standalone — they are the test.)
- [ ] **Step 3: Commit** — `refactor(client): expose brixcvmfs ro ops via internal header`

### Task 7: FUSE rw driver (brixcvmfs_rw.c) + e2e test

**Files:**
- Create: `client/apps/fs/brixcvmfs_rw.c`
- Create: `tests/run_brixcvmfs_overlay.sh`
- Modify: `client/apps/fs/brixcvmfs.c` (rw setup hook, `-o writes=`, standalone `--rw` arg, ops-table select)
- Modify: `client/apps/fs/brixcvmfs_internal.h` (rw ops table extern)
- Modify: `client/Makefile` (compile rule for `brixcvmfs_rw.o` mirroring `brixcvmfs.o`; add to `BRIXMOUNT_OBJS`)

**Interfaces:**
- Consumes: everything from Tasks 1–4 + 6.
- Produces: `int brixcvmfs_rw_main(int argc, char **argv);` (wrapper: sets `brixcvmfs_rw=1`, delegates to `brixcvmfs_main`); `extern const struct fuse_operations brixcvmfs_rw_ops;`

**rw op semantics (spec §3 — implement exactly):**
- helper `ov_rel(path)` = `path+1`; helper `pt_rel(path)` → non-NULL iff path is `/.brixwrites` or below (maps to `writes_fd`-relative)
- passthrough subtree: getattr/readdir/open/create/read/write/truncate/unlink/mkdir/rmdir/rename(within subtree, else -EXDEV) straight on `writes_fd` via `*at` calls; root readdir additionally emits `.brixwrites`
- `getattr`: pt → fstatat; classify UPPER → overlay st; MASKED → -ENOENT; NONE → `brixcvmfs_op_getattr`
- `open`/`create`: reserved name → -EPERM; UPPER → `brix_overlay_open` → `fi->fh = fd+1`; MASKED+O_CREAT → mkdirs+create+whiteout_clear; NONE+write-mode+lower file → `brix_overlay_copyup` (read_lower callback = `cvmfs_client_read` on `brixcvmfs_cl()`) then open upper; NONE+O_RDONLY+lower → `fi->fh=0` (lower via `brixcvmfs_op_read`); O_CREAT+no lower → mkdirs+create
- `read`: `fi->fh` → `pread(fh-1)`; else ro read. `write`/`fsync`/`flush`: on `fh-1`. `release`: close.
- `truncate`: fh → ftruncate; UPPER → overlay truncate; lower file → copyup+truncate; MASKED → -ENOENT
- `mkdir`: reserved → -EPERM; merged-exists → -EEXIST; MASKED (deleted lower dir) → mkdirs+mkdir+whiteout_clear+`set_opaque`; else mkdirs+mkdir
- `unlink`: UPPER file → unlink_upper, + whiteout_set iff lower exists; NONE+lower file → whiteout_set; lower dir → -EISDIR; MASKED → -ENOENT
- `rmdir`: merged-empty check (upper nameset 'u'-count==0 AND every lower entry whiteouted); UPPER → rmdir_upper; + whiteout_set iff lower dir exists; MASKED → -ENOENT
- `rename` (flags!=0 → RENAME_NOREPLACE honored via merged-exists check, others -EINVAL): dir-with-lower-involvement → -EXDEV; file: ensure-upper (copyup if lower-only), mkdirs(to-parent), whiteout_clear(to), rename_upper, whiteout_set(from) iff from-lower exists
- `symlink`: reserved → -EPERM; merged-exists → -EEXIST; mkdirs+overlay symlink+whiteout_clear. `readlink`: UPPER → overlay; MASKED → -ENOENT; else ro.
- `chmod`/`utimens`: UPPER → overlay; lower file → copyup then overlay; lower dir → mkdirs(rel) then overlay; MASKED → -ENOENT. `chown`: same shape via `fchownat` (returns real errno — usually -EPERM unprivileged).
- `getxattr("user.overlay")`: UPPER → `"modified"` iff lower resolves else `"new"`; lower-only → `"lower"`; then fall through to ro getxattr for other names
- rw setup (`brixcvmfs_setup_rw` in brixcvmfs_rw.c, called from `brixcvmfs_main` pre-`fuse_main` when `brixcvmfs_rw`): mkdir `<mnt>/.brixwrites` (or `-o writes=DIR`), open dirfd, `brix_overlay_init`
- standalone binary: `brixcvmfs --rw <repo> <mnt>` routes to `brixcvmfs_rw_main`

- [ ] **Step 1: Write the failing e2e test** `tests/run_brixcvmfs_overlay.sh` (pattern `run_brixcvmfs_clever_live.sh`; compile adds `client/apps/fs/brixcvmfs_rw.c client/lib/fs/overlay.c` and `-I client/lib`; mount with `--rw`). Assertions:
  - write a NEW file (`echo local > $MNT/newfile`) → readable back; visible in `ls`
  - MODIFY lower `hello` (`echo changed > $MNT/hello`) → reads back `changed`
  - DELETE a lower file (`rm $MNT/hello2` — mkrepo must provide ≥2 files; if it only makes one, write via overlay first is NOT ok — instead delete `hello` after the modify-check and confirm `ENOENT`)
  - mkdir + nested write; `mv` a lower file (EXDEV fallback via `mv` works)
  - `.brixwrites` visible in root `ls`; `getfattr -n user.overlay $MNT/newfile` → `new`
  - unmount → remount → all local changes persist (upper wins), deleted stays deleted
  - unmount → `.brixwrites/upper` on disk contains `newfile`, `hello`, whiteout marker
  - **regression:** plain (no `--rw`) mount still returns `EROFS` on write
  - **security-neg:** `touch $MNT/.brix.wh.x` → fails EPERM
- [ ] **Step 2: Run → FAIL** (no `--rw`, no rw file)
- [ ] **Step 3: Implement** `brixcvmfs_rw.c` (ops table + helpers above, WHAT/WHY/HOW blocks, small functions), hook into brixcvmfs.c (`--rw` routing in standalone main, `writes=` in `opts_o_list`, setup call + `&brixcvmfs_rw_ops` select before `fuse_main`), Makefile rule + `BRIXMOUNT_OBJS`.
- [ ] **Step 4: Run e2e → PASS**; also re-run `run_brixcvmfs_clever_live.sh` + `run_overlay_unit.sh` (still green); `make -C client -j$(nproc)` green.
- [ ] **Step 5: Commit** — `feat(client): brixcvmfs rw union driver + overlay e2e`

### Task 8: brixMount wiring (cvmfs-rw row + overlay subcommand routing)

**Files:**
- Modify: `client/apps/fs/brixmount.c`, `client/apps/fs/brixmount_unittest.c`, `tests/run_brixcvmfs_overlay.sh` (extend with CLI checks)

**Interfaces:**
- Produces: table row `{ "cvmfs-rw", "CVMFS-brix-rw", brixcvmfs_rw_main }`; pure router `int brixmount_overlay_route(int argc, char **argv, int (*list_fn)(const char *, FILE *), int (*reset_fn)(const char *));` → -1 when argv[1] isn't `--overlay-list`/`--overlay-reset`, else the subcommand's exit code (2 on missing mountdir arg); `main()` calls the router first with `brix_overlay_cli_list`/`_reset`, then dispatch.

- [ ] **Step 1: Extend `brixmount_unittest.c` (failing):** cvmfs-rw dispatch reaches a mock with brand `CVMFS-brix-rw`; router: `--overlay-list <d>` calls list mock with `<d>` → its rc returned; `--overlay-reset` likewise; `--overlay-list` with no arg → 2; `cvmfs …` → -1 (falls through). Update usage expectation.
- [ ] **Step 2:** `bash tests/run_brixmount_unit.sh` → FAIL
- [ ] **Step 3: Implement** in brixmount.c (row, router fn, main hookup, usage lines for the new type + subcommands). NOTE: `run_brixmount_unit.sh` compiles brixmount.c standalone with `BRIXMOUNT_NO_MAIN` — router must live OUTSIDE the `#ifndef BRIXMOUNT_NO_MAIN` block and take the fn pointers (no link dep on overlay.c).
- [ ] **Step 4:** unit PASS; extend e2e: while mounted `brixMount --overlay-list $MNT` shows `new newfile`/`modified hello`/`deleted …`; `--overlay-reset` → mount view returns to pristine lower (hello original content back); after unmount `--overlay-list` prints `upper …` lines (raw mode). Run e2e → PASS. (e2e builds the real `brixMount` via `make -C client bin/brixMount` or links brixmount.c into the test binary — mirror whichever the script already does for brixcvmfs.)
- [ ] **Step 5:** `make -C client -j$(nproc)` green; commit — `feat(client): brixMount cvmfs-rw type + --overlay-list/--overlay-reset`

### Task 9: Docs + spec close-out

**Files:**
- Modify: `client/lib/README.md` (one bullet: fs/overlay.c — writable-overlay union core for cvmfs-rw)
- Modify: `docs/superpowers/specs/2026-07-05-brixmount-cvmfs-writable-overlay-design.md` (Status: implemented)
- Modify: `client/apps/README.md` if it catalogs fs/ apps (add cvmfs-rw + subcommands)

- [ ] **Step 1:** Write the doc updates (usage examples: `brixMount cvmfs-rw atlas.cern.ch ~/mnt`, `brixMount --overlay-list ~/mnt`).
- [ ] **Step 2:** Full verification sweep: `run_overlay_unit.sh`, `run_brixmount_unit.sh`, `run_brixcvmfs_check.sh`, `run_brixcvmfs_clever_live.sh`, `run_brixcvmfs_overlay.sh`, `make -C client -j$(nproc)` — all green.
- [ ] **Step 3:** Commit — `docs(client): brixMount cvmfs-rw overlay docs; spec implemented`

---

## Self-review notes

- Spec §2 reserved-name enforcement at mount root (`.brixwrites`/`.brixcache` creation) is covered by Task 7 `create`/`mkdir` reserved check plus the passthrough carve-out.
- Spec §5 wrong-mountpoint guard → Task 5 error-neg. Tmp-rename atomicity → Task 3. Symlink escape → Tasks 1/2 security-negs (per-component O_NOFOLLOW walk chosen over openat2 for portability; revisit openat2(RESOLVE_BENEATH) only if a perf need appears — the walk is equivalent security-wise).
- Type consistency: `brix_overlay`, `brix_ov_state`, `brix_ov_read_fn`, `brix_ov_nameset` names used identically across Tasks 1–8.
