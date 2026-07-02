# Enabling CephFS over a Glasgow/RAL (XrdCeph/libradosstriper) pool — runbook

Operator runbook for `xrdceph_striper_migrate`
(`tests/ceph/xrdceph_striper_migrate.cpp`). It has two modes:

- **`--mode redirect` (default, ZERO-MOVE)** — no data is copied. The MDS builds
  the namespace and each CephFS data-object name is pointed at the existing striper
  object via a RADOS **redirect**. **Reversible** with `--rollback`. This is the
  right choice when draining/refilling the data is impractical (e.g. a slow
  external uplink) and the dataset is read-mostly/archive.
- **`--mode copy`** — server-side `copy_from` (OSD→OSD) duplicates the bytes into
  native, fully-owned CephFS objects; `--delete-source` reclaims the originals
  afterwards. Use this when you want a clean CephFS that no longer depends on the
  old pool and can tolerate a one-time in-cluster copy.

Why there is no "just build metadata, leave the objects as-is" without redirects:
CephFS addresses data at `<inode>.<objno>` (name computed from the MDS-allocated
inode), while striper data is at `<LFN>.<stripe>`, and RADOS has no rename. So the
only ways are (a) copy the bytes to the new names, or (b) leave them and add a
**redirect** at the new name — there is no third option. See
`docs/superpowers/specs/2026-06-30-cephfs-rados-program-design.md`.

## Choosing a mode

| | `--mode redirect` (zero-move) | `--mode copy` |
|---|---|---|
| Data movement | **none** | one in-cluster server-side copy |
| Extra space | none | transient ~2× (reclaim with `--delete-source`) |
| Source pool | **must be kept** (it *is* the data) | can be decommissioned after |
| Writability | **READ-ONLY ONLY** — a write goes *through* to the source object | full read/write |
| Rollback | `--rollback` (detaches stubs first → data-safe) | only if `--delete-source` not yet used |
| End state | **staging only** → must `--finalize` to become read-write/owned | already owned read-write |
| Maturity | experimental/unsupported under CephFS (validate first) | supported-shaped |

## How redirect mode works (and what was validated)

Per file: the MDS creates an empty file with a layout matching the striper geometry
(it allocates the inode, dentry and backtrace), then a RADOS redirect stub is
created at each `<ino>.<objno>` pointing at `<soid>.<stripe>` in the striper pool
(set_redirect — metadata only, **no bytes copied, source untouched**), xattrs incl.
`user.XrdCks.*` are carried onto the file, and the size is set via the MDS.

Validated on reef 18.2.4 (`tests/ceph/run_striper_migrate.sh` + the spike tools):
- CephFS reads **follow the redirects** and return data byte-exact (incl. the
  stripe interleave for `stripe_count` 1/2/4 with `object_size ≥ stripe_unit`).
- **Durable**: the redirect survives an MDS **journal flush + cache drop**, and the
  MDS's `parent` backtrace write to the first object **coexists** with the redirect
  (it does not clobber the data path).
- **Reversible**: rollback removes the overlay and leaves the source intact; a
  re-migrate round-trips cleanly.
- **Scrub-safe**: deep-scrub of the redirect stubs' PG and the source targets' PG
  produced **no inconsistent PGs and no scrub errors**, and the file re-read
  byte-exact afterward (`tests/ceph/spike_redirect_write.cpp` covers writes;
  scrub was driven via `ceph pg deep-scrub`).

### CRITICAL: redirect mode is a STAGING state — both writes and deletes go through

While files are still redirects, operations on them act on the **source** object:
- **Writes** are written *through* to the source striper object (verified: a marker
  written via CephFS appeared in the source object's bytes). Not copy-on-write.
- **Deletes** *delete-through*: deleting a redirect stub deletes its source object
  (verified — happens with or without `--with-reference`, and even with the source
  pool's `nodelete` flag set). So an `unlink` of a redirect-migrated file, once the
  MDS purge runs, **destroys the original data**.

Therefore, **while in redirect mode you must serve the CephFS read-only** (read-only
export/mount/caps) AND must not delete files normally — use `--rollback` (below),
which detaches first. **Do not treat redirect mode as the finished migration.** It
is a fast, zero-move, reversible *staging* layer; to reach a real read-write CephFS
you **finalize** (next section).

### Completion: finalize → a real read-write CephFS, then decommission XrdCeph

`--finalize` materializes each redirect into a CephFS-**owned** in-cluster copy
(`tier_promote`, OSD-side — again **no external uplink**), then strips the striper
xattrs. After finalize (verified end-to-end):
- writes stay **local** (the source is no longer touched),
- deletes reclaim the file's **own** objects (normal CephFS purge),
- the **source striper objects can be deleted** and the file still reads — i.e. the
  data is now fully owned by CephFS and **XrdCeph / the striper pool can be
  decommissioned and forgotten**.

```bash
# after the data is validated through CephFS:
xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
    --finalize --list files.txt --threads 8
# then make the export read-write, and once finalize is complete for everything,
# drop the old striper pool.
```

This gives the two-phase model you want: **(1)** redirect-migrate for an instant,
zero-move, read-only cutover (no waiting on a copy); **(2)** finalize in the
background to convert to an owned read-write CephFS and retire XrdCeph. The only
cost is in-cluster space/bandwidth + time during phase 2 — never the external link.

### Still to validate before wide production use

- **Recovery/balancer** behaviour across the two pools under OSD failure (needs a
  multi-OSD cluster; the demo is single-OSD), and cross-version **upgrade** of
  redirect/manifest objects.
- On the demo (degraded, single-OSD) cluster, RADOS reclamation of deleted objects
  was slow (the namespace delete + purge-enqueue worked — `strays_enqueued`
  advanced — but object removal lagged); confirm prompt reclamation on a healthy
  cluster.

## Prerequisites

- Target **CephFS up with an active MDS** + its metadata/data pools.
- Source striper pool readable from the same cluster (the tool reads raw RADOS
  objects; it does **not** need libradosstriper).
- Run on an **in-cluster node**. Build deps: `librados` C++ + `libcephfs`
  (`gcc-c++`).
- Geometry representable as a CephFS layout (`object_size` a multiple of
  `stripe_unit`, `stripe_unit` a multiple of 64 KiB — true for stock XrdCeph).

## Build

```bash
g++ -std=c++17 -D_FILE_OFFSET_BITS=64 tests/ceph/xrdceph_striper_migrate.cpp \
    -lrados -lcephfs -lpthread -o xrdceph_striper_migrate
```

## Procedure (zero-move)

1. **Dry-run** to preview (no writes) **and forecast the wall clock**:
   ```bash
   xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
       --list files.txt --dry-run --threads 8
   ```
   `files.txt` = one **soid** (LFN) per line; omit `--list` to enumerate the pool.
   `--strip <pfx>` trims a leading prefix before joining `/<dest>`.

   Besides listing every action, the dry-run **forecasts the wall clock** for
   both modes. It does this the only way that is reliably accurate: it **really
   migrates a small representative sample** of the work list (a handful of files
   picked by an even stride across sizes) at the configured `--threads`, times
   it, **rolls it back**, and scales the timing up to the full inventory —
   redirect by file count, copy by bytes. Because the sample runs the exact
   migration code path, every real cost is captured (MDS create + layout +
   xattr carry + truncate, the per-file pool enumeration, per-object stub /
   `copy_from`, and MDS/OSD contention at your thread count) — nothing is
   modeled or guessed:

   ```
   == DRY-RUN ESTIMATE (pool 'xrdtest' -> '/dest', 8 thread(s)) ==
   inventory: 1,204,331 file(s), 812.4 GiB, ~208,117 data object(s); pool holds 1,412,448 object(s)
   calibration @ 8 thr: redirect sample 16 file(s) in 0.4 s (38 file/s), copy sample 8 file(s) in 6.1 s @ 105 MiB/s; enum 41220 obj/s; client read 480 MiB/s
   mode redirect (zero-move):   ~8.8 h
   mode copy (in-cluster):      ~2.2 h
     + --verify:                +29 min
   ```

   **Safety:** the calibration's redirect sample is zero-move and rolled back
   (stubs detached first, source intact); its copy sample creates owned objects
   that are unlinked afterward. The **source pool is never written**, exactly as
   in a real dry-run.

   **Accuracy** improves the longer the real run is (a multi-hour migration is
   dominated by the measured body, not by one-time connect/mount overhead), and
   it depends on the sample being representative. For a **skewed file-size
   distribution**, forecast per shard: split `files.txt` and dry-run each shard.
   Note the tool scans the whole pool once per file to find its stripes, so for
   very large pools the enumeration term (reported as `enum obj/s`) can dominate
   — sharding with `--list` bounds it.

2. **Migrate (zero-move) with verify**:
   ```bash
   xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
       --list files.txt --verify --threads 8
   ```
   `--verify` reads each migrated file through the redirects and compares adler32 to
   the carried `user.XrdCks.adler32` — i.e. it confirms the redirect chain serves
   correct data end-to-end. Re-runnable: completed files are skipped.

3. **Validate** a representative subset (reads, checksums, and — critically for
   redirect mode — confirm your workload is read-only; test a write if any clients
   might write).

4. **Cut over** clients/endpoints to read from CephFS.

### Rollback (any time before finalize)

```bash
xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
    --rollback --list files.txt
```
Because a redirect stub delete-throughs to its source, `--rollback` **detaches each
stub (`unset_manifest`) BEFORE unlinking**, so the MDS purge only removes empty,
detached stubs and the source striper pool is left **fully intact** (verified:
source objects + XrdCeph readback survive the async purge). You are back to serving
the original pool via XrdCeph. (Note: a plain `rm`/`unlink` of a redirect-migrated
file *without* this detach would destroy the source — always roll back with this
command, not by hand.) The simplest rollback of all is to just **stop using CephFS
and resume XrdCeph** — the source is intact and XrdCeph-readable throughout; only
clean up the overlay with `--rollback` when you're sure.

## Procedure (copy mode, when you want a fully-owned CephFS)

```bash
# migrate + verify
xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
    --mode copy --list files.txt --verify --threads 8
# reclaim source in batches after verifying
xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> /<dest> \
    --mode copy --list batch_N.txt --verify --delete-source
```
`--delete-source` is **refused in redirect mode** (it would destroy the data the
redirects point at).

## Options

| Option | Effect |
|---|---|
| `--mode redirect\|copy` | zero-move (default) vs server-side copy |
| `--rollback` | remove the CephFS overlay (detaches stubs first; source intact) |
| `--finalize` | materialize redirects → owned in-cluster copies (read-write end state) |
| `--list FILE` | only the listed soids (else enumerate) |
| `--strip PFX` | strip a leading prefix before joining dest |
| `--threads N` | parallel workers (default 4) |
| `--verify` | read + compare `user.XrdCks.adler32` |
| `--delete-source` | (copy mode only) drop striper objects after verify |
| `--force` | re-migrate even if the target exists |
| `--dry-run` | report actions, write nothing; probe the pool (read-only) and print a per-mode wall-clock estimate |
| `--sample-mb N` | dry-run read-bandwidth probe budget in MiB (default 64) |
| `--conf PATH` | ceph.conf (default `/etc/ceph/ceph.conf` / `$CEPH_CONF`) |

## Safety summary

- **Redirect mode never moves or deletes source data during migration**, and
  rollback is data-safe **as long as nothing has written to the migrated files**.
  The decisive constraint is that **writes go through to the source** — so you must
  **serve the migrated CephFS read-only**. With read-only serving, redirect mode is
  data-safe and fully reversible; without it, a client write silently mutates the
  original data.
- **Copy mode** is data-safe until `--delete-source`; after that, rollback can no
  longer restore from CephFS.
- Both modes are **idempotent/resumable** (a file already present at the right size
  is skipped).

## Validation harness

`tests/ceph/run_striper_migrate.sh` (host-side) builds the tool and exercises:
zero-move migrate + verify (asserting source intact), MDS flush+cache-drop
durability, idempotent re-run, rollback (asserting source intact) + re-migrate
round-trip, copy-mode regression with `--delete-source`, and the redirect
`--delete-source` guard. Source simulator: `tests/ceph/striper_seed.c` (real
libradosstriper data + an `XrdCks.adler32` xattr).
