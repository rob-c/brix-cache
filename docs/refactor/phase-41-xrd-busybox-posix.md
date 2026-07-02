# Phase 41 — `xrd` as a BusyBox-style POSIX multi-tool

**Status:** IMPLEMENTED 2026-06-15. **Batch 1** (read & mutate): `head`, `tail -n/-f`,
`df`, `mount` listing, `touch`, `ln`/`ln -s`, `readlink`, `chmod -R`, `ls -h`.
**Batch 2** (inspect & verify, tiers 1–3): `cksum`, `wc`, `cmp`, `xattr`
(`ls`/`get`/`set`/`rm`), `grep`, `hexdump`, `stage`/`evict`, `ping`, `replicas`
(→`xrdmapc`), `sync` (→`xrdcp -r --sync`). **Batch 3** (rate-limited block I/O):
`dd` (`bs=`/`skip=`/`count=`/`rate=`, windowed read→stdout), `upload` and `download`
(`rate=`/`bs=`/`-f`, the throttled native counterparts to `put`/`get`); rate caps are
client-side token-bucket pacing. (`tree` was already present from batch 1.)
**Batch 4** (endpoint diagnostics): `certinfo` (server host-cert validity/expiry via a
new no-login `insecure_tls` TLS probe + `xrdc_tls_peer_cert_info`), `clockskew`
(client↔server offset via HTTP `Date` / root:// touch+stat — diagnoses token/GSI time
failures), `whoami` (negotiated auth + presented identity), `caps` (kXR_Qconfig matrix),
all folded into `doctor`, plus `xrd doctor [endpoint] --json` for a machine-readable
endpoint report. **Batch 5** (doctor functional battery): `doctor` now runs a method
battery per endpoint — read-only by default (stat/dirlist/statvfs/query/path-confinement),
`--rw` adds a full write/read/verify/checksum/metadata cycle, and `--also <url>` adds
WebDAV (OPTIONS/PROPFIND + rw MKCOL/PUT/GET-verify/MOVE/DELETE) and S3 (list + rw signed
PUT/GET-verify/DELETE) faces — all emitted in the `--json` `tests[]` array. The battery
surfaced (and we then FIXED) a real module bug: `rm`/delete followed a symlink's final
component — the existence gate + delete probe now use lstat (POSIX unlink semantics), so
`rm <symlink>` removes the link, not its target (`src/path/op_path.c`,
`src/core/compat/namespace_ops.c`). pytest in `tests/test_xrd_busybox.py`,
man page `client/man/xrd.1`, quirks in `docs/10-reference/quirks.md`. Two scope
corrections: symbolic `chmod` (`u+x`) was dropped — the XRootD wire stat does not
expose the current POSIX mode, so there is no base for relative changes (octal + `-R`
ship); and `cmp` compares same-endpoint pairs with a server-checksum fast path rather
than always streaming bytes.
**Scope:** `client/` only — no nginx-module (`src/`) changes
**Depends on:** phase-37 native clients (`xrd`, `xrdfs`, `xrdcp`, `libxrdc`), phase-38 file-size/UNIX ops
**Author target:** the unified `xrd` front-end + the `xrdfs` subcommand table

---

## 0. TL;DR

`xrd` is **already** a git-style multi-call dispatcher (`client/apps/xrd.c`) and the
verbs the user asked for *mostly already exist*. This phase is a **small, additive
gap-fill plus a UX polish**, not a new tool:

| Asked for         | Today                                                            | This phase                                         |
|-------------------|-----------------------------------------------------------------|----------------------------------------------------|
| `xrd cp A B`      | ✅ `cp`/`copy` → `xrdcp`                                          | keep                                               |
| `xrd rm f`        | ✅ `rm` → `xrdfs rm`                                              | keep                                               |
| `xrd mv B C/D/e`  | ✅ `mv` → `xrdfs mv` (multi-path endpoint mapping already works) | keep                                               |
| `xrd ls /p`       | ✅ `ls` → `xrdfs ls [-l] [-R]`                                    | keep; minor `-h` polish                            |
| `xrd cat f`       | ✅ `cat` → `xrdfs cat`                                            | keep                                               |
| `xrd tail f`      | ✅ `tail [-c N]` → `xrdfs tail`                                   | extend with `-n LINES` + `-f` follow               |
| `xrd chmod f m`   | ✅ `chmod` → `xrdfs chmod` (octal only)                           | extend with symbolic (`u+x`) + `-R`                |
| **`xrd head f`**  | ❌ missing                                                        | **NEW** `do_head` in `xrdfs` + verb in `xrd`       |
| **`xrd df` / `-h`** | ⚠️ only raw `statvfs`/`query space` (machine reply string)     | **NEW** friendly `do_df` (columnar, `-h`, cluster) |
| **`xrd mount`** (list) | ⚠️ `mount` means *action* (FUSE mount), no listing form    | **NEW** bare `xrd mount` / `xrd mounts` lists FUSE  |
| **`xrd touch f`** | ❌ missing                                                        | **NEW** `do_touch` (create-if-absent + set times)  |
| **`xrd ln [-s]`** | ❌ missing                                                        | **NEW** `do_ln` (hard/symlink)                     |
| **`xrd readlink`**| ❌ missing                                                        | **NEW** `do_readlink`                              |
| `xrd chown`       | n/a                                                              | **EXCLUDED** — no ownership mutation (see §3)      |

Net new code: `do_head`, `do_df`, `do_touch`, `do_ln`, `do_readlink`, a `tail`
extension, a `chmod` extension, and a no-arg branch in `xrd_mount`. Everything reuses
existing `libxrdc` ops and the existing dispatch plumbing — including the
already-implemented, server-side, capability-negotiated POSIX wire extensions
(`kXR_setattr`/`symlink`/`readlink`/`link`). No new ownership/`chown` surface
(see §3). No `goto`, functional/modular, 3 tests per new verb.

---

## 1. Current architecture (what we build on)

### 1.1 The dispatcher — `client/apps/xrd.c`
Three dispatch strategies already coexist; we extend them, we don't replace them:

1. **Exec-passthrough** — `cp`/`get`/`put` → `xrdcp`, `diag` → `xrddiag`
   (`exec_tool()` finds the sibling binary next to `argv[0]`, else `$PATH`).
2. **FS-verb rewrite** — a verb in `FS_VERBS[]` (`xrd.c:31`) is rewritten to
   `xrdfs <endpoint> <verb> [paths…]`, splitting a `root://h//p` URL into the
   connect endpoint and the path, and mapping *every* further path arg onto the
   same endpoint (`map_fs_arg()`, `xrd.c:99`) so multi-path verbs like `mv` work.
3. **Inline composition** — `doctor`/`login`/`mount`/`unmount` are implemented
   inline in `xrd.c` by composing `libxrdc` calls (no exec).

Adding a verb = (a) append it to `FS_VERBS[]` if it lives in `xrdfs`, or (b) add an
inline branch in `main()` for cross-cutting verbs (`df` aggregation, `mount` listing).

### 1.2 The subcommand library — `client/apps/xrdfs.c`
`xrdfs` owns a clean dispatch table (`COMMANDS[]`, `xrdfs.c:1007`) of
`{name, fn, help}` where `fn` is `int (*)(xrdc_conn*, const char *cwd, int argc, char **argv)`.
Relevant existing handlers we reuse/extend:

- `stream_file(c, path, start, st)` (`xrdfs.c:356`) — open-read-print loop; `cat`/`tail`
  both call it. **`head` reuses it verbatim** with a byte cap.
- `fmt_size(n, out, sz, human)` (`xrdfs.c:724`) — renders `1.2K/3.4M/…`. **`df -h`/`ls -h`
  reuse it** — no new humanizer.
- `do_statvfs` (`xrdfs.c:458`) → `xrdc_statvfs()` returns the *raw* server reply string
  (the `oss.space`/`kXR_Qspace` token line). `df` parses that into columns.
- `do_du` (`xrdfs.c:811`) — already has the `-h` flag idiom and recursive walk we mirror.

### 1.3 The op library — `client/lib/`
All wire ops already exist as library calls (no new protocol work):

| Need                | Function                                  | File          |
|---------------------|-------------------------------------------|---------------|
| space/quota         | `xrdc_statvfs()`, `xrdc_query(kXR_Qspace)`| `ops_ext.c`   |
| stat                | `xrdc_stat()` / `xrdc_lstat()`            | `ops_meta.c`  |
| read stream         | `xrdc_file_open_read/read/close`          | `ops_file.c`  |
| cluster holders     | `xrdc_locate()`                           | `ops_ext.c`   |
| URL/endpoint parse  | `xrdc_url_parse()`, `xrdc_endpoint_parse()`| `url.c`      |
| alias expand        | `xrdc_alias_resolve()`                    | `xrdrc.c`     |
| errno→exit          | `xrdc_shellcode()`, `xrdc_status_*`       | `status.c`    |
| create empty file   | `xrdc_file_open_write(…, force=0, …)`+close| `ops_file.c` |
| set times           | `xrdc_setattr()` (set_times, set_owner=0) | `ops_ext.c`   |
| chmod               | `xrdc_chmod()` (octal mode)               | `ops_fs.c`    |
| symlink / hardlink  | `xrdc_symlink()` / `xrdc_link()`          | `ops_ext.c`   |
| readlink            | `xrdc_readlink()`                         | `ops_ext.c`   |

The link/setattr/readlink ops are **capability-negotiated**: the client only emits
them when the server advertises `kXR_Qconfig "xrdfs.ext"`, and they are fully
implemented server-side (`src/write/ext_ops.c` — `kXR_setattr` 3500 / `symlink` 3501 /
`readlink` 3502 / `link` 3503), so the new verbs work end-to-end against the standard
test servers, not only against real xrootd.

### 1.4 Build registration
The client builds **independently of the nginx module** — `config.h`/`./configure`
are NOT involved. `client/Makefile` already lists `xrd`, `xrdfs` in `BINS` and the
per-binary rule (`Makefile:114`) links `apps/<name>.o + libxrdc.a + libxrdproto.a`.

**Therefore:** new code added *inside existing `apps/xrd.c` / `apps/xrdfs.c`* needs
**zero Makefile changes**. (Only a brand-new top-level binary would need a `BINS`
entry — we are deliberately avoiding that.)

---

## 2. New / changed verbs — detailed spec

### 2.1 `xrd head` — print the first N bytes/lines  *(NEW)*

**xrdfs side** — add `do_head` next to `do_tail` (`xrdfs.c:~408`):

```
head [-c BYTES] [-n LINES] <path>
```
- `-c BYTES` → stream `[0, BYTES)` via a **byte-capped** `stream_file`. The current
  `stream_file(c, path, start, st)` streams *to EOF*; add an optional `int64_t limit`
  (`-1` = unbounded) and stop once `limit` bytes are emitted. `cat`/`tail` pass `-1`,
  preserving behavior.
- `-n LINES` (default 10) → read forward in chunks, count `\n`, stop after the Nth
  (emit the partial final line if EOF first). Keep the read loop in a small helper
  `head_lines(c, path, nlines, st)` — single responsibility, early-return on error.
- No path / both `-c` and `-n` → usage error (exit 50). `-c` wins if both given
  (matches GNU `head` precedence is the opposite — document: we prefer `-c` because
  byte mode is exact and cheap; note this quirk in the man page + `docs/10-reference/quirks.md`).

**xrd side:** add `"head"` to `FS_VERBS[]` (`xrd.c:31`) — that is the *entire* wiring;
the rewrite path handles `xrd head root://h//big.log -n 20`.

**Register:** `{ "head", do_head, "head [-c BYTES] [-n LINES] <path>" }` in `COMMANDS[]`.

### 2.2 `xrd tail` — add `-n LINES` and `-f` follow  *(EXTEND)*

`do_tail` already does `-c BYTES`. Extend:
- `-n LINES` (default 10): stat the file, then read backward in capped windows
  (e.g. 64 KiB) counting newlines until N are found or offset 0 is reached, then
  `stream_file` from that offset. Helper `tail_start_for_lines(c, path, nlines, &start, st)`.
- `-f` follow: after the initial dump, poll `xrdc_stat` on an interval (default 1 s,
  `--interval`); when `size` grows, `stream_file` the delta. Bounded, interruptible
  by SIGINT (install a tiny handler that flips a `volatile sig_atomic_t stop`). This
  is the one verb that loops — keep the loop in `tail_follow()`, isolated.
  **Polling only** (no inotify on a remote FS); document the interval in the man page.

### 2.3 `xrd df` / `xrd df -h` — friendly space report  *(NEW)*

Real `df` shows mounted-filesystem capacity. For XRootD the analogue is the server's
space report (`kXR_Qspace` / `xrdc_statvfs`). Today users only get the raw reply
string. Add a **`df` inline verb in `xrd.c`** (not a thin `xrdfs` passthrough) because
it does two `xrd`-level things: (a) human formatting, (b) optional cluster
aggregation across `locate` holders.

```
xrd df [-h] [-c|--cluster] [-P] <endpoint>[/path] [more endpoints…]
```
- Parse the server space reply (`oss.space=`/`oss.free=`/`oss.maxf=`/`oss.usage=` or the
  `kXR_Qspace` `total free largest` token form — handle both; the parser lives in a
  pure helper `df_parse_space(reply, &cap, &free, &largest)` returning -1 on an
  unrecognized shape so we fall back to printing the raw line).
- Columns: `Filesystem  Size  Used  Avail  Use%  Largest  Mounted on`.
  `-h` → `fmt_size(…, human=1)` for Size/Used/Avail/Largest; default = bytes.
- `-c/--cluster`: run `xrdc_locate(path)`, then query each holder's space and print
  one row per data server + a `total` row. Reuse the `xrdmapc` holder-parse pattern
  (`S<r|w>host:port`) — factor it into `lib/ops_ext.c` as `xrdc_locate_holders()` if
  not already shared, so `xrdmapc` and `xrd df` use one parser (DRY; note in plan if
  refactor-on-touch applies).
- `-P` → POSIX/portable one-line-per-fs output (no wrapping), for scripts.
- Multiple endpoints → one block each.
- Exit: `xrdc_shellcode()` of the first failure; partial success in `-c` prints
  reachable holders and a stderr note for unreachable ones (fail-soft like `xrdmapc --verify`).

`statvfs` stays as the raw/debug verb; `df` is the friendly face. Cross-link in help.

### 2.4 `xrd mount` — list mounts when given no mount args  *(EXTEND, resolves a name clash)*

Today `xrd mount <endpoint> <mp>` performs a FUSE mount. The user also wants
`xrd mount` (bare) to *list* XRootD mounts — exactly the dual behavior of the real
`mount(8)` (no args = list, args = mount). Implement that overload:

- **`xrd mount` with no positional args**, OR **`xrd mounts`** (new explicit alias),
  OR `xrd mount -l/--list` → **list** current XRootD FUSE mounts.
- **`xrd mount <endpoint> <mountpoint> [opts]`** → unchanged (existing `xrd_mount`).

**Listing implementation** (`xrd_list_mounts()`):
- Read `/proc/self/mountinfo` (preferred — has the fs subtype) or `/proc/mounts`.
- Select rows whose type is `fuse.xrootdfs`, `fuse.xrootdfs_aio`, or `fuse` with a
  source matching `root://`/`roots://` (the drivers set the FUSE `subtype`/`fsname` to
  the endpoint — confirm/realize that in the driver if missing; if the driver doesn't
  yet stamp `fsname=root://…`, add `-o fsname=` in `xrd_mount`'s exec so listing is
  reliable — small, self-contained driver-arg change).
- Print: `ENDPOINT  MOUNTPOINT  DRIVER  OPTIONS` (e.g. `root://store//data  /mnt/xrd  aio  ro`).
- `-h` here is irrelevant (no sizes); reserve `-h`/`--help` for usage. Combine with
  `df`: `xrd mount` then `xrd df /mnt/...` is the natural pairing — document it.
- Pure parse of a procfs file → no network, no creds. Honest empty output (and exit 0)
  when nothing is mounted.

**macOS/non-Linux note:** `/proc` is Linux-only. Gate the procfs path on Linux; on
other platforms fall back to parsing `mount(8)` output or print "unsupported on this
platform" — but since the whole toolkit currently targets Linux, a `#ifdef __linux__`
with a clear stderr message elsewhere is acceptable for v1.

### 2.5 `ls -h` polish *(MINOR, optional)*
`do_ls` already supports `-l`/`-R`. Add `-h` to humanize the size column via the
existing `fmt_size`. One-line idiom mirroring `do_du`. Low priority.

### 2.6 File-metadata verbs — `touch`, `ln`, `readlink`, `chmod`+  *(NEW)*

Round out the POSIX file-tool category. All are `xrdfs` subcommands surfaced through
`xrd` exactly like the existing ones: add the name to `FS_VERBS[]` (`xrd.c:31`) and a
`COMMANDS[]` row (`xrdfs.c:1006`); each handler has the standard signature
`int do_X(xrdc_conn *c, const char *cwd, int argc, char **argv)` (`xrdfs.c:998`), uses
`build_path()` (`xrdfs.c:49`) for relative-path resolution, clears an `xrdc_status`,
and returns `xrdc_shellcode(&st)` on failure — the same shape as `do_chmod`
(`xrdfs.c:316`). **None of these mutate ownership** — see §3.

**`touch [-c] [-a] [-m] [-t TS] <path>`** — POSIX touch.
- Create-if-absent: `xrdc_file_open_write(c, path, /*force=*/0, /*posc=*/0, &f, st)`
  (`ops_file.c:36`; `force=0` ⇒ `kXR_new`, fails only if it already exists — treat
  `kXR_InvalidRequest`/exists as "already there, fine"), then immediate
  `xrdc_file_close`.
- Update timestamps: `xrdc_setattr(c, path, /*set_times=*/1, times, /*set_owner=*/0,
  /*uid=*/(uint32_t)-1, /*gid=*/(uint32_t)-1, st)` (`ops_ext.c:42`). `times[]` is two
  `struct timespec`; default both to `UTIME_NOW`. `-a`/`-m` restrict to atime/mtime
  (the other gets `UTIME_OMIT`); `-t TS` parses an explicit time (`[[CC]YY]MMDDhhmm[.ss]`,
  pure helper `touch_parse_time(spec, &ts)`); `-c` = no-create (skip the open step).
- **`set_owner` is hard-wired to 0** — touch never changes uid/gid.

**`ln [-s] [-f] <target> <linkpath>`** — hard or symbolic link (GNU arg order:
target first, then the link name).
- `-s` ⇒ `xrdc_symlink(c, target, linkpath, st)` (`ops_ext.c:87`, kXR_symlink 3501).
  `target` is stored verbatim (link *content*, not resolved/confined); only `linkpath`
  is confined under the export root. Allows dangling/relative targets, like real `ln -s`.
- default (hard link) ⇒ `xrdc_link(c, oldpath, newpath, st)` (`ops_ext.c:119`,
  kXR_link 3503); both paths confined; source must exist.
- `-f` = remove an existing `linkpath` first (`xrdc_rm`) — optional, document the
  non-atomicity.

**`readlink <path>`** — print a symlink's target.
- `xrdc_readlink(c, path, out, sizeof(out), st)` (`ops_ext.c:151`, kXR_readlink 3502)
  returns the *true* target length (may exceed `outsz-1`). Bounds-check: if
  `ret >= (ssize_t)sizeof(out)`, the value was truncated — either re-call with a
  heap buffer sized to `ret+1` or print a clear "target too long" diagnostic. Never
  print past `out`. On a non-symlink the server errors (`EINVAL`→`kXR_ArgInvalid`).

**`chmod` extension** — keep the existing octal absolute mode (`do_chmod` +
`xrdc_chmod`, `ops_fs.c:126`) and add `-R`, without any wire change:
- **`-R` recursive** (IMPLEMENTED): reuse the directory-walk idiom from `do_du`/`do_find`
  (`xrdfs.c`), one `xrdc_chmod` per entry (`chmod_recursive`/`chmod_visit`); report
  per-path failures and continue, exit nonzero if any failed.
- **symbolic modes** (`u+x`) — **DROPPED, not feasible**: applying `+`/`-`/`=` needs the
  file's current permission bits, but the XRootD wire stat returns only
  `kXR_readable`/`kXR_writable`/`kXR_isDir` flags (`xrdc_statinfo`), never the octal mode.
  With no correct base, `chmod` accepts only absolute octal (`chmod [-R] <path> <octal>`).

**Capability + fail-soft:** symlink/link/readlink/setattr are gated on the server
advertising `xrdfs.ext`. Against a server without the extension the client surfaces the
server's `kXR_Unsupported` message mapped through `xrdc_shellcode` (nonzero exit) —
the verb fails cleanly, it does not crash or silently no-op. `chmod`/`touch`-create use
the always-present `kXR_chmod`/`kXR_open` opcodes and work everywhere.

---

## 3. Non-goals / explicitly deferred

- **No new top-level binary.** Everything lands in `xrd.c`/`xrdfs.c`. Keeps the
  Makefile and packaging untouched.
- **No `inotify`/push for `tail -f`** — remote FS, polling only.
- **NO `chown`/`chgrp` — no ownership mutation, ever.** This is a hard constraint of
  this phase. The backend `xrdc_setattr` *can* set uid/gid (`set_owner`), but every new
  verb here passes `set_owner=0` / `uid=gid=-1`. Ownership changes are a DAC and
  UNIX-impersonation surface (see `phase40_impersonation`) and are out of scope: a
  future `xrd chown` would need its own design + authz review.
- File-metadata verbs in scope are exactly: `touch`, `ln`/`ln -s`, `readlink`, and the
  `chmod` symbolic/`-R` extension (§2.6) — all permission/link/timestamp only.
- **No S3/WebDAV `df`** in v1 — `df` is `root://` (Qspace) first; HTTP `df` via the
  WLCG SRR/`RFC 4331` quota-used props is a clean follow-up (cross-link
  `srr_wlcg_endpoint`).

---

## 4. Coding-standards compliance (mandatory)

Per `docs/09-developer-guide/coding-standards.md` and CLAUDE.md HARD BLOCKS:
- **No `goto`.** New helpers use early-return; the `client/` goto backlog rule is
  refactor-on-touch — if a `do_*` we edit contains legacy `goto`, remove it.
- **Functional/modular.** Each new verb is one `do_*` entry point that delegates to
  small pure helpers (`head_lines`, `tail_start_for_lines`, `tail_follow`,
  `df_parse_space`, `xrd_list_mounts`, `touch_parse_time`, `chmod_apply_symbolic`).
  No new globals (the `tail -f` SIGINT flag is the one justified
  `volatile sig_atomic_t`, file-scoped, documented).
- **Reuse helpers** — `stream_file`, `fmt_size`, `xrdc_*` ops, `xrdc_shellcode`,
  `xrdc_alias_resolve`, `build_path`. Never reimplement path/space/format logic.
- **Section WHAT/WHY/HOW docblock** on every new function.
- Allocation: client uses libc `malloc`/`free` (not nginx pools) — match `xrd.c`'s
  existing `malloc(...)+free` pattern; check every alloc, free on every path.

---

## 5. Tests (3 per new verb: success + error + security/edge)

Harness: client tests run against the standard test servers
(`tests/manage_test_servers.sh`, `root://localhost:11094`). Add to a new
`tests/test_xrd_busybox.py` (or extend `test_xrdfs*`).

**`head`:** (1) first-N bytes of a known file == local `head -c`; (2) `-n LINES`
count matches; (3) error: nonexistent path → nonzero exit + 404-mapped message;
edge: `-c` larger than file = whole file, no error.

**`tail` (extension):** (1) `-n LINES` matches local `tail -n`; (2) `-f` sees an
append within the interval then exits on SIGINT; (3) error path + zero-length file edge.

**`df`:** (1) parses Qspace into 4 numeric columns; `-h` renders K/M/G; (2) `-c`
against the cluster/manager test topology lists ≥1 holder + a total; (3) error:
bad endpoint → nonzero; unrecognized reply → raw passthrough (no crash).

**`mount` listing:** (1) with a live `xrootdfs_aio` mount present, `xrd mount` lists
its endpoint+mountpoint+driver; (2) no mounts → empty + exit 0; (3) parse robustness
against a synthetic `/proc/mounts` fixture with spaces/escapes in paths (octal
`\040` un-escaping) — feed via a `XRD_MOUNTINFO_PATH` test override env so the parser
is unit-testable without root/FUSE.

**`touch`:** (1) create-new appears in `ls` with size 0; (2) re-touch an existing file
updates mtime (stat the delta); (3) `-c` on an absent path is a no-op + exit 0; edge:
existing file is not truncated; error: unwritable path → nonzero. (Gated on
`xrdfs.ext` for the time-set step.)

**`ln` / `ln -s`:** (1) `ln -s` target reads back via `readlink`; (2) hard link shares
size/inode-stat with the source; (3) error: hard-link source missing, or `ln -s` with a
target containing a space (stored verbatim); cross-export `linkpath` rejected.

**`readlink`:** (1) matches the `ln -s` target exactly; (2) non-symlink → nonzero +
`EINVAL`-mapped message; (3) target near/over the buffer bound exercises the
truncation contract (no overrun, clear diagnostic).

**`chmod` extension:** (1) symbolic `u+x` flips exactly one bit (stat before/after);
(2) `-R` walks a tree and chmods every entry; (3) octal absolute mode still works
(regression). 

**Capability fail-soft (all link/setattr verbs):** add a skip/xfail asserting that
against a server *without* `xrdfs.ext` the verb exits nonzero with the
`kXR_Unsupported` message — proving it fails cleanly rather than crashing or no-opping.

Security/edge themes: path traversal is the server's job (already enforced), but the
**procfs parser must not trust field counts** (bounds-check splits), `df`'s reply
parser must reject malformed/oversized token lines without overrunning the fixed
`reply[]` buffer, and `readlink` must never print past its output buffer.

---

## 6. Docs (same-PR requirement)

- **Man pages:** `client/man/` currently has only the FUSE drivers. Add `xrd.1`
  (umbrella) documenting all verbs incl. the new `head`/`df`/`mount`-list/`touch`/
  `ln`/`readlink`, and refresh `xrdfs.1` if/when added. At minimum, extend the
  `usage()` text in `xrd.c` and the `COMMANDS[]` help strings (these are the de-facto
  docs today).
- **Quirks:** record the `head -c` vs `-n` precedence, `tail -f` polling semantics, and
  the `xrdfs.ext` capability requirement (+ fail-soft) for `touch`-times/`ln`/`readlink`
  in `docs/10-reference/quirks.md`.
- **Reference:** add an `xrd` cheat-sheet table to the user-facing client docs and
  cross-link `df`↔`statvfs`, `mount`(list)↔`mount`(action)↔`unmount`, and note that
  `chown`/`chgrp` are intentionally absent (§3).

---

## 7. Implementation order (small, independently shippable steps)

1. **`head`** — `stream_file` byte-cap param + `do_head` + `head_lines` + `FS_VERBS`
   entry + `COMMANDS` entry + 3 tests + help. (Smallest, pure additive.)
2. **`tail -n`/`-f`** — extend `do_tail` + helpers + tests. (Reuses step 1's loop idioms.)
3. **`df`** — `df_parse_space` + `xrdc_locate_holders` factor-out + inline `xrd df`
   branch + tests + help. (Largest; touches `lib/ops_ext.c` for the shared holder parse.)
4. **`mount` listing** — `xrd_list_mounts` + no-arg/`mounts`/`-l` branch in `xrd_mount`
   + optional driver `fsname=` stamping + `XRD_MOUNTINFO_PATH` test seam + tests.
5. **`touch`** — `do_touch` + `touch_parse_time` + `FS_VERBS`/`COMMANDS` entries +
   3 tests + help. (Pure additive; `xrdc_setattr`/`open_write` already exist.)
6. **`ln`/`ln -s`** — `do_ln` over `xrdc_link`/`xrdc_symlink` + entries + 3 tests + help.
7. **`readlink`** — `do_readlink` over `xrdc_readlink` (truncation-safe) + entries +
   3 tests + help.
8. **`chmod` symbolic/`-R`** *(optional)* — `chmod_apply_symbolic` + dir-walk reuse +
   regression test.
9. **`ls -h`** polish (optional).
10. Man page `xrd.1` + quirks + cheat-sheet.

Each step builds with `make -C client -j$(nproc)` (no `./configure`), passes its 3
tests, and leaves `xrd help` accurate. Stop-on-failure rules apply.

---

## 8. Risk / review notes

- **`mount` overload ambiguity:** bare `xrd mount` changing from "error: needs args"
  to "list mounts" is a behavior change. It mirrors `mount(8)` and is additive (no
  existing valid invocation breaks), but call it out in the PR. The explicit
  `xrd mounts` alias gives an unambiguous spelling for scripts.
- **Driver `fsname` stamping:** if the FUSE drivers don't already set a recognizable
  `fsname`/`subtype`, mount-listing must heuristically match `fuse.xrootdfs*`; verify
  against a live mount before relying on the endpoint column. Adding `-o fsname=<endpoint>`
  in `xrd_mount` is the robust fix and is a one-line, self-contained change.
- **`df` reply heterogeneity:** managers vs data servers vs cache origins format
  Qspace differently (see `integrity_matrix`/cluster work). Parser must fail-soft to
  raw passthrough, never crash, on an unknown shape.
- **`tail -f` resource use:** bounded poll interval, single connection, SIGINT-clean.
  No detached threads.
- **`touch` create semantics:** `force=0`/`kXR_new` fails when the file already exists;
  treat that specific error as success (the file is there) rather than surfacing it —
  otherwise `touch` of an existing file would error before the time-update step. Verify
  the exact status code returned (`kXR_InvalidRequest` vs a dedicated exists code) on
  the test server and key the "benign" branch off it precisely, not a blanket catch.
- **`ln -s` target is unconfined by design:** the symlink *target* is stored verbatim
  and not path-resolved (only `linkpath` is confined) — matching real `ln -s` and the
  server's `xrootd_handle_symlink` contract. Document this so it isn't mistaken for a
  path-confinement gap; the server still confines all *resolution* through the link.
- **No-chown enforcement is a code invariant, not just a missing verb:** every
  `xrdc_setattr` call this phase adds must pass `set_owner=0`; a reviewer should grep
  the diff to confirm no `set_owner=1` / real uid/gid slips in.
