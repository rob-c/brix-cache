# brixMount CVMFS writable overlay — design

**Date:** 2026-07-05
**Status:** approved

## Goal

Add a local writable overlay to brixMount CVMFS mounts: writes into the
(normally read-only) CVMFS mount are captured and stored under an additional
local path alongside the `.brixcache` cache directory underneath the
mountpoint, overlaying the upstream repo content. Full POSIX overlay semantics
(including deletes via whiteouts), enabled by a **separate mount type** so the
read-only driver is untouched, plus CLI subcommands to list/reset local
changes.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| Write scope | Full POSIX overlay: create/write/truncate/mkdir/rename/chmod AND delete of upstream files via whiteout markers |
| Enablement | Separate mount type `cvmfs-rw` — the read-only `cvmfs` path is byte-for-byte unchanged |
| Change management | Full CLI subcommands: `--overlay-list` / `--overlay-reset`, working mounted or unmounted |
| Approach | In-driver union layer with a standalone overlay core (Approach A); kernel overlayfs stacking rejected (privileges, FUSE-lowerdir caveats, WSL2); overlay logic inside `shared/cvmfs/` client core rejected (server builds against it — wrong boundary) |

## 1. Architecture & naming

A new brixMount type **`cvmfs-rw`** (brand: `CVMFS-brix-rw`) is added to the
driver table in `client/apps/fs/brixmount.c`, dispatching to a thin wrapper
entry `brixcvmfs_rw_main()` that sets an overlay-enable flag and calls the
existing `brixcvmfs_main()` machinery.

All union logic lives in a **new standalone, FUSE-free, ngx-free module
`client/lib/fs/overlay.{c,h}`** (phase-69 client bucket layout), linked into
`libbrix` and the brixMount binary. It operates purely on an overlay dirfd +
repo-relative paths — no CVMFS types leak in, no overlay types leak into
`shared/cvmfs/`. The FUSE ops in `brixcvmfs.c` become: *consult overlay → fall
back to `cvmfs_client_*`*. The shared CVMFS core (which the nginx server also
builds) is untouched.

FUSE stays single-threaded (`-s`, already forced), so the overlay module needs
no locking.

## 2. Overlay store format

```
<mnt>/.brixwrites/            ← sibling of <mnt>/.brixcache, hidden by the mount,
  upper/                        reached via a dirfd opened BEFORE fuse_main (same
    sw/lhcb/myfile.py           trick .brixcache already uses)
    sw/.brix.wh.badfile        ← whiteout marker: "badfile" deleted from lower
    scratch/.brix.opq          ← opaque marker: dir shadows lower dir entirely
```

- **Upper files/dirs/symlinks** mirror repo paths 1:1 — human-inspectable,
  diffable, `rm -rf`-resettable, trivially exportable later.
- **Whiteouts** are empty marker files `.brix.wh.<name>` (no root needed,
  unlike overlayfs char-devs).
- **Opaque dirs** (`.brix.opq` inside an upper dir) mark "don't merge lower" —
  created when a lower dir is deleted and later re-created.
- Names beginning with `.brix.wh.` / equal to `.brix.opq` are **reserved**:
  attempts to create them through the mount get `-EPERM`. Same for
  `.brixwrites`/`.brixcache` at the root.
- Works identically in clever and explicit-cache modes; `-o writes=<DIR>`
  overrides the location (parity with `-o cache=`).

## 3. FUSE op semantics (upper always wins)

| Op | Behavior |
|---|---|
| `getattr`/`readlink`/`getxattr` | upper if present → `fstatat`/`readlinkat`; whiteout → `-ENOENT`; else lower (current code path) |
| `readdir` | merge: upper entries (markers stripped) ∪ lower entries not whiteouted/shadowed; opaque dir → upper only |
| `open(O_RDONLY)`/`read` | upper file → `pread` on upper fd; else `cvmfs_client_read` |
| `open(O_WRONLY/O_RDWR)`, `truncate` | **copy-up at open**: create upper parent chain (modes copied from lower dirs), stream lower→upper via the existing 8 MiB scratch read loop (chunked files handled by `cvmfs_client_read`), then operate on upper |
| `create`/`write`/`mkdir`/`symlink`/`chmod`/`chown`/`utimens` | on upper (metadata changes on a lower file trigger copy-up); remove any whiteout marker being shadowed |
| `unlink` | upper-only file → unlink; lower exists → unlink upper (if any) + create whiteout |
| `rmdir` | merged-view-empty check → remove upper dir + whiteout if lower dir exists |
| `rename` | pure-upper → `renameat`; file with lower involvement → copy-up + rename + whiteout source; **dir rename involving lower → `-EXDEV`** (mv/coreutils transparently fall back to copy+delete — same trade kernel overlayfs makes without `redirect_dir`) |

Upstream revision refresh (`cvmfs_client_refresh`) keeps working untouched;
locally-modified paths simply keep winning over the new revision.

## 4. CLI subcommands + passthrough subtree

The FUSE driver exposes **`<mnt>/.brixwrites` as a visible read-write
passthrough subtree** mapped directly onto the overlay dirfd
(openat/unlinkat/mkdirat & co). That single mechanism powers the tooling with
no control channel:

- `brixMount --overlay-list <mnt>` — walks `…/.brixwrites/upper`, prints one
  line per change: `new` / `modified` (lower exists) / `deleted` (whiteout) /
  `dir`. Works mounted (through the passthrough) or unmounted (raw dir), same
  code.
- `brixMount --overlay-reset <mnt>` — recursively empties `upper/`. With
  single-threaded FUSE this is race-free; subsequent ops just fall back to
  lower.

`--overlay-list` classifies `modified` vs `new` by whether the same path also
resolves in the lower layer; when unmounted (no lower view available) it
prints `upper` for regular files instead of guessing.

## 5. Error handling & security

- Copy-up failures (`ENOSPC`, fetch-exhausted on lower read) abort the op
  cleanly with the errno; a partial copy-up is written to
  `upper/…/.brix.tmp.<name>` and renamed into place only when complete — no
  torn upper files.
- Upper-tree path resolution uses `openat2(RESOLVE_BENEATH)` (fallback
  `O_NOFOLLOW` per-component walk) so a symlink planted in the user-writable
  upper tree can't make the driver read/write outside `.brixwrites` —
  defense-in-depth mirroring the server-side VFS symlink-escape fix.
- Reserved marker names rejected with `-EPERM`; path components `..` never
  reach the dirfd ops.
- `--overlay-list/reset` refuse to run on a directory that has no
  `.brixwrites` (wrong-mountpoint guard).

## 6. Testing (3-per-change rule)

1. **Unit** — `client/lib/fs/overlay_unittest.c` + `tests/run_overlay_unit.sh`
   (pattern: `run_cvmfs_core_unit.sh`): lookup states, copy-up,
   whiteout/opaque, readdir merge, rename/EXDEV, reserved-name rejection,
   tmp-rename atomicity, symlink-escape attempt (security-neg).
2. **E2E** — `tests/run_brixcvmfs_overlay.sh` against the existing mock-repo
   harness: mount `cvmfs-rw`, write/modify/delete/remount-persist cycle,
   `--overlay-list/--overlay-reset` both mounted and unmounted, and read-only
   `cvmfs` type still returns `EROFS` (regression).
3. **Dispatch unit** — extend `client/apps/fs/brixmount_unittest.c` for the
   new table row + subcommand arg parsing.
