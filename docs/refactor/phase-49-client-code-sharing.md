# Phase 49 — Client + FUSE code-sharing consolidation

**Status:** IN PROGRESS (authored 2026-06-21, verified against the current `client/` tree).
- **W0 DONE + tested** — `lib/cli_cksum.c` (xrdcrc32c/xrdcrc64/xrdadler32 now ~6-line
  shims); `xrootd_crypto_init` folded into `xrdc_connect`/`xrdc_connect_no_login` via
  `pthread_once`; `XRDC_EXIT_{USAGE,IO,AUTH}` constants in `xrdc.h`; dead
  `libxrdclient.a` removed + Makefile comment fixed. Local-digest oracle match +
  root:// parity + `test_native_tools.py`/`test_crc64.py` (22) green; clean-room intact.
- **W1 opts sweep DONE + tested** — `lib/cli_opts.c` (`xrdc_opts_init` +
  `xrdc_opts_parse_arg`), `lib/cli_conn.c` (`xrdc_cli_connect` + `xrdc_report_err`)
  built into libxrdc.a. Adopted: `xrdmapc`, **`xrdcp`, `xrddiag`, `xrdgsitest`**
  (each tool's copy-pasted --tls/--notlsok/--noverifyhost/--auth/--wire-trace[=N]/
  --timing/--redirect-trace/--capture ladder → one `xrdc_opts_parse_arg` call;
  xrdcp bridges its `size_t i` via an int temp), plus `xrdqstats`/`xrdprep`
  (connect scaffold). Behaviour-preserving — adopted ONLY the parser, NOT the init,
  so each tool keeps its existing `verify_host` default (xrdcp/xrdfs default 0 via
  memset; xrdmapc uses `xrdc_opts_init`=1) — flipping it would break localhost-cert
  TLS tests. 48 pytest (xrdcp_client_options + native_tools + xrd_frontend + xrddiag
  + xrddiag_capture). `strv` not extracted (single consumer = xrdcp, no cross-app dup).
  Remaining (deferred, low value): the `xrdfs` per-handler `xrdc_report_err` sweep
  (~35 sites; `mv`/`cp` two-path formats don't fit the single-path helper; error-
  string churn against asserting tests). `wait41` keeps its own retry-loop connect.
- **W4 (FUSE) — biggest shared engines DONE + tested.** `lib/posix_map.c`
  (`xrdc_statinfo_to_stat` with an allow_symlink flag, `xrdc_parse_qspace`,
  `xrdc_fattr_listxattr_xlate`) and `lib/iobuf.c` (read-ahead/write-back engine
  driven by a `pread`/`pwrite` vtable over an opaque backend) now back BOTH drivers:
  `xrootdfs.c` (async — afh_io_pread dispatches mfile/webfile) and
  `xrootdfs_legacy.c` (pool — xrdc_file_read/_write). ~485 LoC of duplicated
  stat/statfs/listxattr + buffering removed; each driver's read/write/flush is now a
  one-line iobuf call. Verified: 33 FUSE pytest (test_xrootdfs{,_ext,_resilience,_http})
  + a manual `--legacy` mount (3 MiB write/read/random-read byte-exact) + clean-room.
- **W4 (FUSE) — meta-runner DONE + tested.** `lib/fuse_ops.{c,h}` (no fuse3 dep):
  `xrdc_fuse_run(pool, max_retries, op, ctx, st)` + `xrdc_fuse_errno` +
  `xrdc_fuse_conn_healthy` + 12 typed op thunks (stat/lstat/dirlist/mkdir/rm/rmdir/
  mv/chmod/trunc/setattr/symlink/link). The async retry loop with `max_retries==0`
  is byte-identical to the legacy single checkout→op→checkin→errno-map, so ONE
  runner backs both drivers. `xrootdfs.c`: `xfs_err`/`xfs_conn_healthy`/`xfs_meta`
  are now thin wrappers (no call-site churn); local standard thunks deleted, call
  sites use `xrdc_fuse_*` (async-only `op_qspace`/`op_cks`/`op_fa*` stay local).
  `xrootdfs_legacy.c`: 8 inline meta ops collapsed to one `xrdc_fuse_run` call each.
  Verified: async 36 pytest (xrootdfs{,_ext,_resilience,_http} +
  compression_fuse_resilience) + legacy hand-mount (all ops byte-exact) + clean-room.
- **W4 NOT pursued (by design):** the full single `fuse_core.c` + one
  `fuse_operations` table + web backend behind a vtable. The two drivers are
  intentionally distinct (simple vs resilient + http/WebDAV + srv_path export base);
  the shared runner+thunks (`fuse_ops`) + `iobuf` + `posix_map` already capture the
  genuinely-shared logic without erasing that distinction. statfs/xattr stay per-driver.
- **W2 — path + units DONE + tested.** `lib/path.c` (`xrdc_path_resolve` = the
  xrdfs `build_path` ".."/dup-slash canonicaliser) and `lib/units.c`
  (`xrdc_fmt_size`/`xrdc_parse_bytes`/`xrdc_rate_pace`). xrdfs's statics are now
  thin wrappers (zero call-site churn). Verified: `..`-path put + `ls -h` (human
  size) + `dd bs=256k` against the harness, native-tools/frontend 23 green,
  clean-room intact.
- **Remaining (lower value / higher churn):** export the `copy.c` pump
  (`xrdc_file_pump`/`drain_to_fd`/`slurp`) — xrdfs hand-rolls the remote read loop
  ~9× (cat/head/tail/wc/grep/dd); `lib/walk.c` (one remote-tree walker). **W3
  PENDING** (move xrdcp recursive WebDAV/S3 + web→web relay into copy.c — reorg, not
  dup). `xrdfs` `report_err` sweep DEFERRED (error-string churn, single-app).
  `strv` SKIPPED (single consumer, no dup).

> SIDE FIX (pre-existing bug, found + fixed during this work): `xrdcp` to a refused
> endpoint looped `connect→ECONNREFUSED→sleep 50ms→retry` for the full 60s
> `max_stall` window (×`--retry` → effectively a hang;
> `test_client_xrdcp_bulk.py::test_retry_then_fail_no_hang`). Root cause: the
> non-blocking `connect_one` (lib/sock.c) read `SO_ERROR` but never propagated it
> into `errno`, so the connect status carried `sys_errno=0` instead of
> `ECONNREFUSED`. Fix: (1) `connect_one` now sets `errno` to the real cause
> (`SO_ERROR`, or `ETIMEDOUT` on poll-timeout); (2) `connect_resolved` captures it
> before `freeaddrinfo`; (3) `copy.c resilient_setup` fast-fails a *never-established*
> `ECONNREFUSED` (definitive — re-attempts are the OUTER `--retry`'s job; a TIMEOUT
> or a fault after the session was up still retries within the window). Result:
> dead-port `xrdcp --retry 1` fails in ~0.5s (the one jittered backoff), 0.003s
> with no retry; `xrdfs` unchanged. Verified: bulk 12 + native-tools 15 + crc64 7 +
> frontend 8 + resilience 14 green. Bonus: connect errors now show the real errno.

**Goal:** make the native CLI tools (`xrdcp`, `xrdfs`, `xrddiag`, the single-shot
tools) and the two FUSE drivers (`xrootdfs.c` = async, `xrootdfs_legacy.c` = pool)
share as much code as possible by lifting app-level plumbing into `client/lib/`
(libxrdc.a). No wire-protocol change; no behaviour change for any tool.

---

## 0. Current state (what is already shared — do NOT touch)

`client/lib/` (libxrdc.a) already shares the hard parts and every binary links it
through one Makefile rule (plus FUSE/preload variants with the same libs + fuse3):

- wire/framing (`frame.c`), connect + redirect (`conn.c`, `aio.c`, `aio_mgr.c`),
  sockets/TLS (`sock.c`, `tls.c`), auth + all Sec*-equivalents (`auth.c`, `sec/`),
  URL/endpoint parse (`url.c`), status/exit-code/cred-hints (`status.c`,
  `credinfo.c`), the copy engine (`copy.c`), glob (`glob.c`), parallel streams
  (`streams.c`), file/fs/meta/ext ops (`ops_*.c`), WebDAV/S3/webfile transports
  (`http.c`, `s3.c`, `weblist.c`, `webfile.c`), checksums (`checksum.c`), zip
  (`zip.c`), fattr (`fattr.c`), the connection pool (`pool.c`).

No app re-rolls protocol/auth/TLS/copy. **The remaining duplication is purely
app-level plumbing plus the two near-identical FUSE drivers.**

**Dead artifact:** `client/libxrdclient.a` is superseded by `libxrdc.a` — no
Makefile rule builds it; only a stale comment references it. Delete it.

### Verified duplication (current files)

| Area | Where | ~LoC dup | Risk |
|---|---|---|---|
| FUSE: the two drivers implement the same ~26 `xfs_*` ops with near-identical bodies | `apps/xrootdfs.c` vs `apps/xrootdfs_legacy.c` | ~760 | med |
| FUSE: read-ahead/write-back buffered I/O engine | both drivers (`afh_*`/`xfs_*` read/write/flush) | ~220 | low |
| FUSE: `statinfo→struct stat`, `Qspace→statvfs`, xattr name/cks/list translation | both drivers (3rd copy in `preload/`) | ~190 | low |
| CLI: 3 checksum tools byte-identical bar one algo enum | `apps/xrdcrc32c.c`, `xrdcrc64.c`, `xrdadler32.c` | ~105 | low |
| CLI: common connect-flag ladder (`--tls/--notlsok/--noverifyhost/--auth/...`) | ~8 apps incl. both FUSE drivers | ~140 | low |
| CLI: `endpoint_parse → connect → error/exit` scaffold | `xrddiag` (~12 sites) + single-shot tools | ~110 | low |
| CLI: per-op `fprintf(...st.msg); cred_hint; return shellcode` idiom | `xrdfs` (~35 sites) | ~90 | low |
| CLI: remote read-pump hand-rolled (cat/head/tail/wc/grep/dd) | `xrdfs` ~9 sites | ~320 | med |
| CLI: path normalise / basename / join | `xrdfs`, `xrdcp` | ~70 | low |
| CLI: rate-pace / parse-bytes / fmt-size, strv, manifest reader, tree-walker | `xrdfs`, `xrdcp` | ~190 | low |
| CLI: recursive WebDAV/S3 download + web→web relay engine | `xrdcp` only (belongs in `copy.c`) | ~520 | med |

Total ≈ **3,200 LoC** consolidatable, most low-risk.

---

## 1. Keystone — one FUSE core behind a backend vtable

The two drivers differ ONLY in their connection model, and the async driver
*already* multiplexes two backends inline (`if (g_web)` web/http vs root:// mfile in
every op). So there are really **three** backends today — legacy pool, aio root://
mfile, aio webfile http(s) — open-coded across two files. Replace all of it with one
core + a backend vtable:

```c
/* lib/fuse_backend.h */
typedef struct {
    /* metadata ops — return 0 / -errno; fill xrdc_statinfo etc. */
    int (*stat)   (void *be, const char *path, xrdc_statinfo *si, xrdc_status *st);
    int (*readdir)(void *be, const char *path, xrdc_dirent_cb cb, void *cbctx, xrdc_status *st);
    int (*mkdir)  (void *be, const char *path, mode_t m, xrdc_status *st);
    int (*unlink) (void *be, const char *path, xrdc_status *st);
    int (*rmdir)  (void *be, const char *path, xrdc_status *st);
    int (*rename) (void *be, const char *from, const char *to, xrdc_status *st);
    int (*chmod)  (void *be, const char *path, mode_t m, xrdc_status *st);
    int (*truncate)(void *be, const char *path, off_t sz, xrdc_status *st);
    int (*statfs) (void *be, const char *path, xrdc_spaceinfo *sp, xrdc_status *st);
    int (*fattr_get/set/del/list)(...);          /* xattr surface */
    /* per-handle data I/O (NULL pwrite ⇒ read-only backend, e.g. webfile) */
    void *(*open) (void *be, const char *path, int writable, int force, xrdc_status *st);
    ssize_t (*pread) (void *h, int64_t off, void *buf, size_t n, xrdc_status *st);
    ssize_t (*pwrite)(void *h, int64_t off, const void *buf, size_t n, xrdc_status *st);
    int (*fsync) (void *h, xrdc_status *st);
    int (*close) (void *h, xrdc_status *st);
    unsigned caps;     /* WRITABLE | SYMLINK | XATTR | STATFS ... */
} xrdc_fuse_backend;
```

`lib/fuse_core.c` owns the single `struct fuse_operations`, ALL `xfs_*` handlers
(getattr/readdir/mkdir/.../statfs/access + the full xattr block incl. the virtual
`user.XrdCks.<algo>` and the `U.`→`user.` listxattr rewrite), `xfs_init`, error
mapping, and the read-ahead/write-back engine — calling the backend through the
vtable. Each driver becomes a thin `main()` that builds a backend and calls
`xrdc_fuse_run(argc, argv, &backend, &cfg)`.

Three backends ship:
- `lib/fuse_be_pool.c` — `pool_checkout → op → pool_checkin` (the legacy driver).
- `lib/fuse_be_mfile.c` — `aio_mgr` mfile (the async root:// driver).
- `lib/fuse_be_web.c` — `webfile`/WebDAV (read-only; `pwrite`/`mkdir`/... = `-EROFS`).

Result: `xrootdfs.c` and `xrootdfs_legacy.c` each shrink to ~80–150 LoC (pick
backend + register + run); the webfile/root branching inside the async driver
disappears (it becomes "which backend was selected"). The legacy/no-async path is
preserved at near-zero marginal cost.

---

## 2. Workstreams (independently shippable, low-risk first)

### W0 — Quick wins (~250 LoC, low risk)
- `lib/cli_cksum.c` → `xrdc_cksum_tool_main(prog, algo_name, algo, arg)`. The 3
  checksum CLIs collapse to a ~6-line `main()` each.
- Fold `xrootd_crypto_init()` into `xrdc_connect()` via `pthread_once`; drop the
  per-app call (removes the "forgot to init → GSI silently breaks" footgun).
- Named exit codes in `xrdc.h` (`XRDC_EXIT_USAGE=50`, `_IO=51`, `_AUTH=53`).
- Delete `libxrdclient.a` + fix the stale Makefile comment.

### W1 — CLI scaffold (~340 LoC, low risk)
- `lib/cli_opts.c` → `xrdc_opts_init(o)` + `xrdc_opts_parse_arg(o, argc, argv, &i)`
  (returns 1=consumed a common connect flag, 0=app's own, -1=error). Adopt in
  `xrdcp`, `xrdfs`, `xrddiag`, `xrdmapc`, `xrdgsitest`, and BOTH FUSE drivers'
  option loops.
- `lib/cli_conn.c` → `xrdc_cli_connect(endpoint, o, &c, prog, &st)`
  (alias-resolve + endpoint-parse + connect + standard `prog: connect host: msg`).
  Replaces ~12 inline ladders in `xrddiag` and the single-shot tools.
- `xrdc_report_err(out, tool, op, path, st, want_write)` — the ~35× `xrdfs` idiom.

### W2 — Transfer/path primitives (~700 LoC, low–med risk)
- `lib/path.c` → `xrdc_path_resolve/basename/join/mkdirs_for/is_dot`.
- Export the `copy.c` pump publicly: `xrdc_file_pump(c,&f,off,limit,sink,ctx,opts,st)`
  + `xrdc_file_drain_to_fd` + `xrdc_file_slurp`. Re-point `xrdfs` cat/head/tail/
  wc/grep/dd at it.
- `lib/units.c` (`xrdc_rate_pace`, `xrdc_parse_bytes`, `xrdc_fmt_size`),
  `lib/strv.c` (`xrdc_strv_append`, `xrdc_read_lines_file`; pairs with existing
  `xrdc_strv_free`), `lib/walk.c` (`xrdc_walk_remote(visitor)` — one walker for
  `xrdfs` du/find/tree).

### W3 — Recursive copy into the engine (~520 LoC, med risk)
- Move `xrdcp`'s recursive WebDAV/S3 download + local→web upload + web→web relay
  into `lib/copy.c` behind `xrdc_copy` (make `copy_web` honour `o->recursive` via
  `xrdc_webdav_list`/`xrdc_s3_list`; add `xrdc_copy_web_to_web`). `xrdcp` keeps only
  arg-parsing.

### W4 — FUSE unification (~760 LoC, med risk — the headline, §1)
- `lib/fuse_core.c` + `fuse_backend.h`, `lib/iobuf.c` (read-ahead/write-back driven
  by the vtable), `lib/posix_map.c` (`statinfo→stat`, `Qspace→statvfs`, fattr-list
  xlate — also de-dupes the `preload/` copy), `lib/fuse_main.c` (option parser via
  W1 `cli_opts` + `fuse_main` lifecycle), and the three `fuse_be_*.c` backends.
- Re-back `xrootdfs.c` (mfile + web backends) and `xrootdfs_legacy.c` (pool backend)
  on the core.

---

## 3. Sequencing, risk, verification

Order: **W0 → W1 → W2 → W3 → W4** (W1's `cli_opts` is reused by W4's `fuse_main`).
After each workstream: `make -C client` clean, run the client + FUSE pytest suites
(`tests/test_xrootdfs*.py`, `test_compression_*` client paths, `test_native_*`),
and the clean-room/no-goto lint (`tests/test_compression_cleanroom_lint.py`, which
already checks `client/bin/{xrdcp,xrdfs,xrootdfs}` link no `libXrd*`). Invariants:
no wire change, no new `goto`, clean-room preserved, every tool's user-visible
behaviour byte-identical (diff outputs before/after on the harness).

**Net effect:** ~3,200 LoC of duplication removed; each FUSE driver ~80–150 LoC;
new tools get connect/auth/transfer/FUSE for free from `lib/`.
