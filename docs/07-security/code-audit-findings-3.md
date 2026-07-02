# nginx-xrootd Code-Level Security Audit — Round 3

**Scope:** Temp-file handling audit covering TOCTOU races and missing `O_NOFOLLOW`
defenses across all subsystems that create files atomically (cache fill, checkpoint
snapshot, WebDAV COPY/TPC, S3 PUT/CopyObject, XRootD POSC writes).

**Audit method:** Static analysis of every `open(2)` call that uses `O_CREAT`, every
`unlink(2)` call adjacent to `open(2)`, and every `rename(2)` call across `src/`.
Cross-referenced against the path through which each temp path is constructed to
evaluate symlink-swap risk.

**Status:** All actionable findings fixed (2026-05-21).

---

## Summary Table

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| [T-01](#t-01-toctou-race-in-cachefetchc) | **High** | Cache fetch | `unlink` + `open(O_CREAT\|O_TRUNC)` TOCTOU in cache part-file creation | ✅ Fixed |
| [T-02](#t-02-missing-o_nofollow-in-writechkpointc) | **Medium** | Checkpoint | `open(O_CREAT\|O_TRUNC)` without `O_NOFOLLOW` on `.ckp` snapshot file | ✅ Fixed |

**Confirmed not vulnerable (no action needed):**

- `src/webdav/copy.c`, `src/webdav/tpc.c`, `src/s3/put.c`, `src/s3/copy.c` — all
  use `xrootd_staged_open` which enforces `O_CREAT|O_EXCL|O_NOFOLLOW`, random names
  via `xrootd_make_tmp_path()`, and confined operations. ✅
- `src/read/open_resolved_file.c` (POSC) — uses `xrootd_make_tmp_path()` (random name),
  `O_EXCL` on first open attempt, `xrootd_open_confined()` (path escape prevention). ✅
- `src/cache/lock.c`, `src/cache/evict_candidates.c` — lock files use `O_CREAT|O_EXCL`;
  correct for lock semantics, not temp-file semantics. ✅
- `src/webdav/lock.c` — WebDAV lock token file uses `O_CREAT|O_EXCL`; zero-byte resource
  creation, not a staging temp file. ✅

---

## T-01: TOCTOU Race in `cache/fetch.c`

**Severity:** High
**File:** `src/cache/fetch.c` — `xrootd_cache_fetch_origin()`

### Vulnerability

The cache-fill thread-pool worker opened its per-entry part file with a two-step
unlink-then-open pattern:

```c
/* VULNERABLE — before fix */
unlink(t->part_path);                                     /* step 1 */
outfd = open(t->part_path,                               /* step 2 */
             O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC,
             0644);
```

Between step 1 (`unlink`) and step 2 (`open`), a local attacker with write access to
the cache directory can race in and place a symbolic link at `t->part_path` pointing to
an arbitrary file.  The subsequent `open(O_CREAT|O_TRUNC)` follows the symlink and
truncates or overwrites the link target with the content of the fetched file.

`t->part_path` is constructed as `<cache_path>.part` — a predictable, fixed suffix.
An attacker who can observe which cache paths are being populated (e.g., via directory
listing of the cache root) can reliably hit the window, which is bounded only by the
scheduler's time slice between the two syscalls.

**Why High rather than Critical:**
- Exploiting this requires local filesystem write access to the cache directory
  (`conf->cache_root`), which is typically owned by the nginx worker user.
- The write is constrained to the content of the fetched file (attacker does not control
  the bytes written, only the destination).
- The cache directory is normally not world-writable in a correctly deployed system.

### Attack Scenario

1. Attacker observes (or predicts) that path `/atlas/reco/file.root` is about to be
   fetched into the cache as `/var/cache/xrd/atlas/reco/file.root.part`.
2. Attacker races: `rm /var/cache/xrd/atlas/reco/file.root.part &&
   ln -s /etc/cron.d/xrootd-job /var/cache/xrd/atlas/reco/file.root.part`
3. The worker's `open(O_CREAT|O_TRUNC)` follows the symlink.
4. The worker writes the fetched file body to `/etc/cron.d/xrootd-job`.

### Fix

Remove the `unlink()` and fold the create-or-truncate into a single `open()` call with
`O_NOFOLLOW`.  `O_CREAT|O_TRUNC|O_NOFOLLOW` atomically creates-or-truncates without
following a symlink (returns `ELOOP` if the final path component is a symlink):

```c
/* After fix — no preceding unlink; single atomic open */
outfd = open(t->part_path,
             O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
             0644);
```

`O_TRUNC` already ensures a fresh file; the `unlink()` was redundant and harmful.
Removing it collapses the two-step race into a single atomic operation.

**Implementation:** `src/cache/fetch.c` — removed `unlink(t->part_path)` call
preceding the `open()`; added `O_NOFOLLOW` to the `open()` flags.

**Note on naming:** `t->part_path` intentionally keeps the predictable `.part` suffix
rather than switching to `xrootd_make_tmp_path()`.  `src/cache/lock.c` uses the fixed
path for fill-lock coordination — exactly one worker holds the fill lock for a given
cache entry at a time, preventing concurrent fetches.  Switching to a random name would
break the lock protocol.  The security property that matters here is the atomic single
`open()` plus `O_NOFOLLOW`, not randomness.

---

## T-02: Missing `O_NOFOLLOW` in `write/chkpoint.c`

**Severity:** Medium
**File:** `src/write/chkpoint.c` — `xrootd_handle_chkpoint_begin()`

### Vulnerability

The checkpoint-begin handler created the `.ckp` snapshot file without `O_NOFOLLOW`:

```c
/* VULNERABLE — before fix */
ckp_fd = open(f->ckp_path,
              O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
              0600);
```

`f->ckp_path` is constructed as `f->path + ".ckp"`, where `f->path` is the confined,
resolved file path.  Although `f->path` itself is validated against the export root
through the XRootD path resolution machinery, the `.ckp` sibling does not go through
that machinery — it is constructed by simple string concatenation:

```c
ngx_memcpy(f->ckp_path, f->path, plen);
ngx_memcpy(f->ckp_path + plen, ".ckp", 5);  /* includes NUL */
```

An attacker with write access to the directory containing `f->path` could race in a
symbolic link at `<f->path>.ckp` between the `kXR_open` (when `f->path` is resolved)
and the `kXR_chkpoint begin` (when `f->ckp_path` is opened).  The `open(O_CREAT|O_TRUNC)`
without `O_NOFOLLOW` follows the symlink and truncates the link target, then overwrites
it with the original file's content.

**Why Medium rather than High:**
- Requires write access to the parent directory of the file being checkpointed, which
  is typically within the export root controlled by the server.
- The attacker controls the destination but not the bytes written (the checkpoint
  content is the original file's content).
- The confined path machinery already prevents the checkpoint path from escaping the
  export root via `..` traversal; symlink swap is a narrower residual risk.

### Fix

Add `O_NOFOLLOW`:

```c
/* After fix */
ckp_fd = open(f->ckp_path,
              O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
```

If the final path component is a symbolic link, `open()` returns `ELOOP`.  The existing
error handler in `chkpoint.c` converts this to `kXR_IOError` and a log entry — the
client receives an appropriate error response and the checkpoint is not created.

**Implementation:** `src/write/chkpoint.c` — added `O_NOFOLLOW` to `ckp_fd = open(...)`.

**Note on naming:** `f->ckp_path` uses a fixed `.ckp` suffix (rather than a random temp
path) because the XRootD checkpoint protocol requires a client to locate its checkpoint
on reconnect.  `O_TRUNC` without `O_EXCL` is also intentional: starting a new checkpoint
replaces a previous one from an earlier `kXR_chkpoint begin` on the same file handle.
Only `O_NOFOLLOW` was missing.

---

## Consolidated temp-file security model

Following these two fixes, all temp-file creation paths in the module satisfy one of
two security patterns:

**Pattern A — Staged atomic write** (four callers; `src/core/compat/staged_file.c`):
`O_CREAT|O_EXCL|O_NOFOLLOW` + random name + confined ops + confined rename/unlink.
Used by WebDAV COPY, WebDAV TPC pull, S3 PUT, S3 CopyObject.

**Pattern B — Fixed-name controlled create** (three callers; can't use staged API):
`O_CREAT|O_TRUNC|O_NOFOLLOW` (no preceding `unlink`) + confined create where applicable.
Used by POSC writes (also has `O_EXCL` on first attempt), cache part files, checkpoint
snapshots.  Each has a structural reason why a random name or the staged API cannot be
used; those reasons are documented in
[cross-protocol-unification.md](../10-architecture/cross-protocol-unification.md#temp-file-staging-srccompatstaged_filec).

The common invariant across both patterns: **no `open()` with `O_CREAT` is issued
without either `O_EXCL` or `O_NOFOLLOW`**.
