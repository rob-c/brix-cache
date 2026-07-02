# `xrootd_csi_trust_fs` — trust the backing filesystem on reads

**Date:** 2026-07-02
**Status:** approved

## Problem

The CSI per-page CRC32C tagstore (`xrootd_csi on`) verifies every byte served
against stored tags on every read: a tag-file read plus a CRC32c pass over the
data. On storage that already provides end-to-end integrity (ZFS, CephFS,
RADOS, Btrfs) this verification is redundant work on the hot read path.

Operators need an explicit way to say "I trust this filesystem's own
checksumming" and skip read-path verification — while keeping the write side
fully intact so tags stay fresh for scrubbing, `xrdstorascan`, and a later
switch back to verification.

## Directive

`xrootd_csi_trust_fs on|off` — default **off**.

- New `ngx_flag_t csi_trust_fs` beside the other `csi_*` fields in
  `src/core/types/config.h`.
- Init/merge in `src/core/config/server_conf.c` (default 0).
- `ngx_command_t` entry next to `xrootd_csi_require` in
  `src/protocols/root/stream/module.c`.
- Per-server. Generic across SD drivers automatically: verification sits in
  `vfs_io_core` above the driver seam. No `./configure` needed (no new source
  file, no new top-level block).

## Behavior when on

1. **Pure read opens skip the tagstore entirely.** In
   `src/protocols/root/read/open_resolved_file.c` the CSI attach block is
   bypassed when `conf->csi_trust_fs && !is_write`: no tag-file open, no
   per-read verify. Documented consequence: `csi_require` is **not** enforced
   on read opens in this mode — trusting the filesystem supersedes requiring
   tags to read.
2. **Write handles attach as today**, with a new `trust_fs:1` bit set on
   `xrootd_csi_t` (`src/fs/backend/csi_tagstore.h`).
   `xrootd_csi_verify_read()` (`src/fs/backend/csi_verify.c`) early-returns
   `XROOTD_CSI_OK` when the bit is set. This single choke point covers reads
   issued through a read-write handle on every path: the VFS job read
   (`src/fs/vfs/vfs_io_core.c`), the warm page-cache fast path
   (`src/protocols/root/read/read.c`), and readv.
3. **Write side unchanged** — "still verify on write":
   `xrootd_csi_update_aligned` retags on write, `xrootd_csi_store_pgcrc` on
   pgwrite, strict RMW verify-before-merge on partial pages, and pgwrite
   wire-CRC validation all keep running. Trust applies to disk reads only,
   never to bytes arriving off the wire.

## Tests

- **Success:** with `trust_fs on`, flip a byte in the data file (tags now
  stale) → read succeeds (verify skipped); and a write through a trusted
  handle retags correctly, proven by reading back with `trust_fs off` and
  passing.
- **Error/parity:** identical corruption with `trust_fs off` (default) → read
  fails `kXR_ChkSumErr`; default behavior untouched.
- **Security-negative:** with `trust_fs on`, a pgwrite carrying a bad wire CRC
  is still rejected.
- **Unit:** `csi_unittest.c` case — `trust_fs=1` makes `verify_read` return
  OK on a known-mismatching page.

## Docs

Directive documented alongside the other `xrootd_csi_*` entries, with an
explicit warning that it must only be enabled on storage with its own
end-to-end checksumming, and the `csi_require`-on-reads interaction noted.
