# XrdCeph ⇄ CephFS migration tools — test record (Ceph Reef)

This is the validation record for the two migration tools and their shared
decoder, documenting **exactly how they were exercised on a Ceph Reef deployment**,
what passed, and the limitations of the test environment. It is the evidence behind
the `[VERIFIED]` claims in
[`xrdceph-cephfs-bidirectional-migration.md`](xrdceph-cephfs-bidirectional-migration.md).

> Scope note: all testing was on a **single-node demo cluster** (one OSD, hence
> permanently `HEALTH_WARN`/degraded). That is sufficient to prove *correctness* of
> the object/metadata mechanics, but **not** multi-OSD failure/recovery, balancer,
> or scrub-under-failure behaviour. See §7 (Limitations).

---

## 1. Test environment

| Item | Value |
|---|---|
| Ceph version | **reef 18.2.4** (`e7ad5345525c7aa95470c26863873b581076945d`, stable) |
| Cluster | `quay.io/ceph/demo:latest-reef`, single node, all daemons in one container (`xrd-ceph-demo`) |
| Host | Docker Desktop on WSL2 — `--network host` binds the Docker-Desktop VM (MON at `192.168.65.x`), reachable only from other `--network host` containers |
| Health | `HEALTH_WARN` (1 OSD < `osd_pool_default_size 2`; ~50% degraded) — **normal for the demo**, unrelated to the tools |
| Pools | `xrdtest` (XrdCeph/striper, size 1), `cephfs_data`, `cephfs_metadata` |
| File system | `cephfs` (`cephfs_metadata`/`cephfs_data`), MDS `demo` = `up:active` |
| Build/run container | `xrd-ceph-work` (CentOS-Stream base) with: `librados-devel`, `libradosstriper-devel`, `libcephfs-devel`, `gcc-c++`, `xrootd-client`, and the cluster's `ceph.conf` + admin keyring wired into `/etc/ceph` |

[FACT] CephFS + XrdCeph(striper) + the target striper pool all live in the **same
cluster**, so every migration op is intra-cluster (`set_redirect` / `copy_from` /
`tier_promote`) — the property that makes "no PB over the wire" true.

Harness scripts: `tests/ceph/ceph_harness.sh` (cluster), `tests/ceph/Dockerfile.build`
+ `build_in_container.sh` (build env), runners listed in §6.

---

## 2. Test data generators

| Generator | Produces | Notes |
|---|---|---|
| `striper_seed.c` | a real **libradosstriper** object set in a pool | params: size, object_size, stripe_unit, stripe_count; writes a **position-dependent pattern** + stamps `user.XrdCks.adler32` |
| `cephfs_seed.c` / `cephfs_seed2.c` | a known **CephFS** tree (libcephfs) | files/dirs, a symlink, user xattrs |
| inline `lseed`/`cwrite` | single CephFS file, word==offset + adler32 | used for the reverse-direction tests |

[FACT] **The verification pattern is position-dependent: each 8-byte word holds its
own byte offset.** A plain fill would compare equal even under a scrambled stripe
interleave; the offset pattern makes any mis-ordering detectable. This is what gives
the byte-exact claims teeth for `stripe_count > 1`.

---

## 3. Verification methods used

```
 method                      what it proves
 ─────────────────────────   ───────────────────────────────────────────────
 word==offset full scan      byte-exact incl. stripe interleave / object order
 user.XrdCks.adler32 carry   end-to-end checksum survives migration + verify
 libradosstriper read-back   XrdCeph can actually serve the result
 libcephfs fresh-mount read  CephFS can serve it; fresh client = no stale cache
 rados get / stat / listxattr object-level truth (redirect vs owned, xattrs, size)
 MDS flush + cache drop      durability: result survives metadata flush + reread
 raw set-redirect probes     redirect read/write/delete semantics in isolation
```

---

## 4. Decoder unit tests (no cluster)

Built standalone with `gcc`; run anywhere.

| Test | Coverage | Result |
|---|---|---|
| `cephfs_denc_unittest.c` | LE ints, length-prefixed strings, `ENCODE_START` framing + forward-skip, overrun/bad-length safety | **ALL PASS** |
| `cephfs_layout_unittest.c` | synthetic `inode_t` at struct_v **2,3,4,5,11,14,19**; fragtree leaf math; xattr map; **real reef-18.2.4 fixtures** (file/dir/symlink + xattr) | **ALL PASS** |

Fixtures: `tests/ceph/fixtures/reef-18.2.4/*.bin`, captured with `rados getomapval`
from the seeded CephFS; ground truth from the known seed values and cross-checked
with `ceph-dencoder`.

---

## 5. Cluster test matrix and results

All on reef 18.2.4. "byte-exact" = full word==offset scan unless noted.

### 5.1 Read-only CephFS-via-RADOS backend (`cephfsro`) — prerequisite work

| Check | Result |
|---|---|
| Standalone driver vtable (open/pread 5 MiB/stat/ls/getxattr/symlink/`EROFS`), quiesced + **live** mode | **ALL PASS** |
| In-nginx export, root:// + WebDAV, `?assume_quiesced=1` and `?live=1` | **ALL PASS** (reads byte-exact, writes refused) |

### 5.2 Forward: XrdCeph → CephFS (`xrdceph_striper_migrate`)

| Check | Result |
|---|---|
| Redirect (zero-move), `stripe_count` 1 / 2 / 4 (incl. `object_size>stripe_unit`) | byte-exact incl. interleave |
| Redirect durability: `mds flush journal` + `cache drop`, re-read | **PASS** (and the MDS `parent` backtrace coexists on the stub) |
| Copy mode (`copy_from`, OSD↔OSD) + `--verify` | byte-exact, verified |
| Finalize (`tier_promote`+`unset_manifest`): writes go local; source deletable; still reads | **PASS** |
| Rollback (detach-first): source survives the async purge; XrdCeph still reads | **PASS** |
| Idempotent re-run (all SKIP); dry-run (no writes); `--delete-source` (source dropped) | **PASS** |
| Guard: `--delete-source` refused in redirect mode | **PASS** |

### 5.3 Reverse: CephFS → XrdCeph (`xrdceph_cephfs_to_striper`)

| Check | Result |
|---|---|
| Namespace walk from RADOS (unmounted), redirect (zero-move) + `--verify` | `OK redirect lanc/a.dat ... verified` |
| `libradosstriper` reads the file **through the redirects** at its path | byte-exact (6 MiB) |
| Finalize, then **delete the CephFS data objects**, then read | byte-exact (decoupled / owned) |
| Copy-based core mechanism (`spike_cephfs_to_striper.cpp`) | byte-exact |

### 5.4 RADOS redirect/promote semantics (isolated probes)

| Check | Result |
|---|---|
| Plain `rados get` of a redirect stub returns target bytes | **PASS** (4 MiB) |
| Read-through for **librados**, **CephFS client**, **libradosstriper** | all byte-exact |
| **Write-through** [HAZARD]: write via CephFS lands in the *source* object | **CONFIRMED** (marker found in source @offset) |
| **Delete-through** [HAZARD]: deleting a stub deletes the target — no-reference, with-reference, AND pool `nodelete` | **CONFIRMED** (target GONE in all three) |
| **Safe rollback**: `unset_manifest` (detach) *then* delete stub → target survives | **CONFIRMED** (target PRESENT, content intact) |

### 5.5 Unhandled-component identification

| Check | Result |
|---|---|
| Symlink detected + skipped | **PASS** (`/dir1/link`) |
| Hardlink: `nlink=2` primary flagged **UNVERIFIED** + alias dentry skipped | **PASS** (after `ceph_link`) |
| CephFS snapshot detected via `mds_snaptable` `last_snap` | **PASS** (`last_snap=2` after `mkdir /dir1/.snap/s1`; matches mon `last_created:2`) |
| `--report-only` inventory (counts + per-item warnings, migrates nothing) | **PASS** |
| Forward: RADOS pool-snapshot warning (`snap_list`) | wired (no pool snaps present to trigger in this run) |

### 5.6 Deletion / space reclamation

| Check | Result |
|---|---|
| CephFS unlink removes the file from the namespace | **PASS** (`statx` → ENOENT) |
| Purge pipeline active | **PASS** (`strays_enqueued` advanced) |
| RADOS object physically reclaimed | **NOT OBSERVED within 120 s** — demo purge lag (see §7) |

---

## 6. How to reproduce

Prereqs: `tests/ceph/ceph_harness.sh start`; build env per
`tests/ceph/build_in_container.sh`; a CephFS with an MDS.

```bash
# decoder unit tests (no cluster)
cc -I src/fs/backend/rados tests/ceph/cephfs_denc_unittest.c \
   src/fs/backend/rados/cephfs_denc.c -o /tmp/t && /tmp/t
cc -I src/fs/backend/rados tests/ceph/cephfs_layout_unittest.c \
   src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c \
   -o /tmp/t && /tmp/t tests/ceph/fixtures/reef-18.2.4

# cephfsro driver + nginx export (in xrd-ceph-work)
tests/ceph/run_cephfs_ro_live.sh
docker exec xrd-ceph-work bash /work/cephfs_ro_smoke.sh           # both modes

# forward migrator full matrix (host-side runner)
tests/ceph/run_striper_migrate.sh

# reverse migrator: seed a CephFS file, then (in xrd-ceph-work)
#   gcc -c cephfs_layout.c / cephfs_denc.c ; g++ xrdceph_cephfs_to_striper.cpp ...
#   ./rev <meta> <cephfs_data> <striper> --assume-quiesced --report-only
#   ./rev ... --verify ; ./rev ... --finalize

# redirect/promote semantics + hazards (spikes)
#   tests/ceph/striper_redirect_cephfs.cpp   (forward redirect read-through)
#   tests/ceph/spike_redirect_write.cpp      (write-through)
#   tests/ceph/spike_finalize.cpp            (tier_promote materialize)
#   tests/ceph/spike_cephfs_to_striper.cpp   (reverse copy core)
```

[GOTCHA] In `xrd-ceph-work`, build a new module/source set with
`rm -rf objs && ./configure && make` (configure over stale objs ⇒ mixed-ABI
garbage). Clean up nginx with `pkill -9 nginx` (workers rename their cmdline, so
`pkill -f objs/nginx` misses them).

---

## 7. Limitations of this test environment

[REQUIREMENT] Re-validate the following on a **production-representative (multi-OSD,
healthy)** cluster before operational use — they could not be exercised here:

- **RADOS object reclamation timing.** On the degraded single-OSD demo, namespace
  deletes + purge-enqueue worked but physical object removal lagged (>120 s, purge
  queue idle). Almost certainly a degraded/single-OSD throttle, not a defect —
  confirm prompt reclamation when healthy.
- **OSD failure / recovery / balancer** of redirect (manifest) objects over time
  (single-OSD cluster cannot be failed without stopping all I/O).
- **Deep-scrub** of redirect objects under load and across recovery.
- **Cross-Ceph-version upgrade** of redirect/manifest objects.
- **Scale**: correctness was shown on small files/trees; throughput, the
  per-file pool enumeration cost, and parallelism want testing at realistic counts.
- **Hardlinks** are detected and flagged **UNVERIFIED** — the multi-name semantics
  has no XrdCeph equivalent and was not validated end-to-end.
- **Snapshots** (`.snap`) and RADOS **pool snapshots** are detected and reported
  but **not migrated** by design.

---

## 8. Summary

On Ceph reef 18.2.4 the **correctness mechanics** of both migration directions were
validated end-to-end and byte-exact (including stripe interleave and checksum), as
were the redirect read/write/delete semantics, the finalize (materialise → owned)
step, the detach-first rollback, and the unhandled-component identification. The
**operational hardening** items in §7 remain to be validated on a healthy multi-OSD
cluster. Treat the zero-move redirect phase as a fast, reversible *staging* tool and
**finalise** to a fully-owned end state before decommissioning the other side.
