# Python XrdCeph ⇄ CephFS migration tools — reference & operator guide

**Date:** 2026-07-02 · **Status:** landed on main, e2e-verified against the
Docker demo cluster (reef/18.2)
**Companion docs:**
[`xrdceph-cephfs-bidirectional-migration.md`](xrdceph-cephfs-bidirectional-migration.md)
(byte-level theory of the redirect migration),
[`cephfs-migration-glasgow-ral.md`](cephfs-migration-glasgow-ral.md) /
[`cephfs-to-xrdceph-migration.md`](cephfs-to-xrdceph-migration.md)
(per-direction runbooks), `tests/ceph/README.md` (harness quick-start).

This document is the single reference for the 2026-07-02 wave of migration-tool
work: the **pure-Python re-implementation** of both migration tools, the
**`--config` site profile** added to all four tools (Python *and* C++), the
**delete-through data-loss fix**, and a complete **operator usage guide** for
the Python tools.

---

## 1. What landed (summary of recent changes)

| Change | Where | Commits |
|---|---|---|
| Pure-Python decoders + namespace walker (port of `cephfs_denc`/`cephfs_layout`) | `client/apps/ceph/pymigrate/cephfs_meta.py` | `11afa81` |
| Shared CLI plumbing: worklist filters, state manifest, JSON, progress, thread runner | `client/apps/ceph/pymigrate/common.py` | `e683ac6` |
| ctypes bridge to librados's C++-only manifest ops + libradosstriper reader | `client/apps/ceph/pymigrate/radosbridge.py` | `00263dc` |
| Compiled C-ABI shim fallback for the manifest ops | `client/apps/ceph/pymigrate/shim/rados_manifest_shim.cpp` | `9b05eee` |
| **Tool 1 (Python):** striper → CephFS | `client/apps/ceph/xrdceph_striper_migrate.py` | `c97c4c1` |
| **Tool 2 (Python):** CephFS → striper | `client/apps/ceph/xrdceph_cephfs_to_striper.py` | `da9cfef` |
| Docker e2e runner (both directions, all modes) + **delete-through fix** | `tests/ceph/run_py_migrate.sh` | `0bcc290` |
| C++ tool: `--dry-run` wall-clock estimator (real sample migrate, scaled) | `xrdceph_striper_migrate.cpp` | `d210a2c` |
| C++ tool: O(N) source index + progress line + **delete-through fix** (detach before every unlink) | `xrdceph_striper_migrate.cpp` | `01c1583` |
| **`--config` site profile** in all four tools (parser, wiring, e2e legs, docs) | `pymigrate/common.py`, `xrdceph_migrate_config.h`, both `.py` + both `.cpp` | `14474ae`…`be5a6b7` |

Design specs: `docs/superpowers/specs/2026-07-02-python-xrdceph-cephfs-migration-design.md`
and `…-migration-tools-pool-config-design.md`.

The C++ originals remain fully supported; the Python tools are semantic
twins (same modes, same guards, same exit codes) with extra operator
conveniences. Either can be used on a given estate — they produce identical
on-cluster state.

---

## 2. The tools at a glance

| | Forward | Reverse |
|---|---|---|
| Script | `client/apps/ceph/xrdceph_striper_migrate.py` | `client/apps/ceph/xrdceph_cephfs_to_striper.py` |
| Direction | libradosstriper (stock XrdCeph) pool → CephFS | quiesced CephFS → libradosstriper |
| Namespace side | created by the **MDS** via libcephfs (mount) | walked from **pure RADOS** (no mount, no MDS) |
| Default mode | zero-move **redirect** (no bytes copied) | zero-move **redirect** |
| Data mapping | stub `<ino_hex>.<objno %08x>` → `<soid>.<stripe %016x>` | stub `<soid>.<stripe %016x>` → `<ino_hex>.<objno %08x>` |
| Verify | libcephfs read + adler32 vs `user.XrdCks.adler32` | libradosstriper read + adler32 |
| Hard gate | `--delete-source` refused in redirect/rollback | `--assume-quiesced` mandatory; `--delete-source` finalize-only |
| Exit codes | 0 all ok/skip · 1 any per-file failure · 2 usage/guard | same |

**Dependencies:** distro `python3-rados` + `python3-cephfs` and Python 3.9+
stdlib. No pip. No compile step (the shim fallback is optional, §4).

---

## 3. Package layout

```
client/apps/ceph/                   (official client tools since 2026-07-07;
                                     build: make -C client ceph-tools)
  xrdceph_striper_migrate.py        forward tool (executable)
  xrdceph_cephfs_to_striper.py      reverse tool (executable)
  xrdceph_migrate_config.h          --config parser for the C++ tools (header-only)
  pymigrate/
    cephfs_meta.py                  CephFS on-RADOS metadata decoders + walker
    common.py                       shared CLI plumbing + --config parser
    radosbridge.py                  ctypes manifest-op bridge + striper reader
    shim/rados_manifest_shim.cpp    C-ABI fallback shim
tests/ceph/
  run_py_migrate.sh                 Docker e2e runner (host side)
  test_cephfs_meta.py               unit tests (no cluster required)
```

- **`cephfs_meta.py`** — a faithful Python port of the C decode core
  (`src/fs/backend/rados/cephfs_denc.{c,h}` + `cephfs_layout.{c,h}`): bounded
  `Denc` cursor with `ENCODE_START` framing (raises `DecodeError`, never a
  wild parse), dentry (primary `'I'/'i'` / remote `'L'/'l'`), `inode_t`
  struct_v 2→19, fragtree leaves, xattr map, plus the omap-paging namespace
  walker and the `mds_snaptable` snapshot probe. Validated against the same
  reef-18.2.4 byte fixtures as the C decoders.
- **`common.py`** — `adler32_hex` (seed 1, XRootD convention),
  `filter_worklist` (`--list` verbatim / `--prefix` / `--match`),
  `StateManifest` (append-only JSONL, keyed on soid+action+mode),
  `Reporter` (human/JSONL output, thread-safe counters, 400-warning budget,
  progress, exit code), `run_parallel`, and the `--config` parser (§6).
- **`radosbridge.py`** — see §4.

---

## 4. The redirect bridge (how pure Python reaches C++-only RADOS ops)

The zero-move migration rests on four RADOS operations — `set_redirect`,
`copy_from`, `tier_promote`, `unset_manifest` — that exist **only in
librados's C++ API**: `librados.h` has no C entry points for them and the
python-rados `WriteOp` doesn't expose them. `librados.so.2` does export the
mangled C++ symbols under the ABI-versioned inline namespace
`librados::v14_2_0::…` (unchanged since Nautilus).

`ManifestBridge` therefore:

1. Opens its **own** cluster connection through the C API via ctypes (so it
   holds raw `rados_ioctx_t` pointers, and so `rados_get_last_version()`
   version affinity is correct for `set_redirect`'s target version).
2. For the four ops, calls the mangled symbols directly:
   `librados::IoCtx` is a single-pointer pimpl over the same impl the C API
   hands out; `ObjectWriteOperation` is `{vptr, impl}` whose **base-class**
   (`ObjectOperation`) constructor/destructor are exported (the derived ctor
   is inline — the base ctor sets a real vptr, so nothing is fabricated);
   `std::string` arguments are built per the CXX11 ABI.
3. **Self-tests before any real write** (redirect/copy/finalize runs): write
   a 4 KiB scratch object → stub → `set_redirect` → read-through
   byte-compare → detach → delete. If this fails, no migration write happens.
4. **Falls back to a compiled shim** when symbol probing or the self-test
   fails: `pymigrate/shim/rados_manifest_shim.cpp` (~80 lines, plain C ABI)
   is loaded from `$PYMIGRATE_SHIM`, from a prebuilt `.so` next to the
   module, or compiled on the spot (`g++` + `<rados/librados.hpp>` — on el9
   the header is in **`libradospp-devel`**, *not* `librados-devel`).

Environment knobs: `PYMIGRATE_FORCE_SHIM=1` forces the shim path (the e2e
runner exercises it); `PYMIGRATE_SHIM=/path/to.so` names a prebuilt shim.
The tool banner reports which backend engaged: `bridge=ctypes` or
`bridge=shim`.

Verification via a libradosstriper read (reverse tool `--verify`) uses that
library's **C API** (which does exist) through ctypes — no binding needed.

---

## 5. Operator guide

### 5.1 Forward: striper pool → CephFS (`xrdceph_striper_migrate.py`)

```
xrdceph_striper_migrate.py <striper_pool> <cephfs_data_pool> <dest_prefix>
    [--mode redirect|copy] [--rollback] [--finalize] [--list FILE]
    [--strip PFX] [--threads N] [--verify] [--delete-source] [--force]
    [--dry-run] [--conf PATH] [--config PATH]
    [--json] [--state FILE] [--prefix PFX] [--match GLOB] [--progress]
```

A typical zero-move campaign:

```bash
# 0) inventory only — nothing is written
xrdceph_striper_migrate.py xrdtest cephfs.cephfs.data /migrated --dry-run

# 1) migrate (zero-move redirects) with checksum verification and a resume file
xrdceph_striper_migrate.py xrdtest cephfs.cephfs.data /migrated \
    --verify --threads 8 --state /var/tmp/mig.state --progress

# 2) serve the CephFS **read-only** and soak-test it            <-- REQUIRED
# 3) when satisfied, materialize into owned CephFS objects (in-cluster copy):
xrdceph_striper_migrate.py xrdtest cephfs.cephfs.data /migrated --finalize
# 4) the striper pool is now droppable

# ...or abort instead: remove the overlay, source untouched:
xrdceph_striper_migrate.py xrdtest cephfs.cephfs.data /migrated --rollback
```

Per file, migrate does: read the striper geometry
(`striper.layout.*`/`striper.size` xattrs on stripe 0) → create the CephFS
file empty with a **matching layout** (so the MDS allocates the inode and the
striping math lines up) → redirect-stub every data object → carry `user.*`
xattrs (checksums included) → truncate to size → optional adler32 verify
through the full redirect chain. Already-migrated files (right size) are
`SKIP`ped; `--force` re-does them safely (see §7).

`--mode copy` uses OSD-side `copy_from` instead of redirects (real owned
copies, transient ~2× space, still no host/WAN data movement); only then is
`--delete-source` legal, and only after verify.

### 5.2 Reverse: quiesced CephFS → striper (`xrdceph_cephfs_to_striper.py`)

```
xrdceph_cephfs_to_striper.py <meta_pool> <cephfs_data_pool> <striper_pool>
    --assume-quiesced [--finalize] [--rollback] [--strip PFX] [--threads N]
    [--verify] [--delete-source] [--dry-run] [--report-only] [--conf PATH]
    [--config PATH] [--json] [--state FILE] [--list FILE] [--prefix PFX]
    [--match GLOB] [--progress]
```

The CephFS **must be quiesced** (unmounted / `ceph fs fail`, MDS journal
flushed — e.g. `ceph tell mds.<id> flush journal`); the namespace is walked
straight from the metadata-pool omaps and a live MDS would mutate them
underneath the walk. `--assume-quiesced` is your assertion of that state and
is mandatory.

```bash
# 0) ALWAYS start with the classification report — it names everything that
#    will NOT migrate (hardlink aliases, symlinks, specials, other-pool files,
#    snapshot dentries, SnapServer state, truncated fragtrees/xattr sets):
xrdceph_cephfs_to_striper.py cephfs.cephfs.meta cephfs.cephfs.data xrdtest \
    --assume-quiesced --report-only

# 1) redirect-migrate + verify via a REAL libradosstriper read:
xrdceph_cephfs_to_striper.py cephfs.cephfs.meta cephfs.cephfs.data xrdtest \
    --assume-quiesced --verify --threads 8 --state /var/tmp/rev.state

# 2) serve via stock XrdCeph **read-only**, soak
# 3) materialize into owned striper objects and (optionally) drop CephFS data:
xrdceph_cephfs_to_striper.py cephfs.cephfs.meta cephfs.cephfs.data xrdtest \
    --assume-quiesced --finalize --verify --delete-source

# ...or abort: remove the striper overlay, CephFS untouched:
xrdceph_cephfs_to_striper.py cephfs.cephfs.meta cephfs.cephfs.data xrdtest \
    --assume-quiesced --rollback
```

### 5.3 The Python-only conveniences (both tools)

| Flag | What it does |
|---|---|
| `--json` | JSONL to stdout: one record per file (`soid/action/result/bytes/objects/dest/error`) + a final `{"summary": …}`; human log moves to stderr |
| `--state FILE` | Append-only JSONL outcome manifest keyed on (soid, action, mode). Reruns skip `ok` entries **without touching the cluster**; failures are retried; `--force` overrides. A migrate record never suppresses a rollback run |
| `--prefix P` / `--match GLOB` | Worklist filters over the enumeration (composable). `--list FILE` names soids **verbatim** — deliberately not intersected with enumeration, so rollback can name files whose sources are already gone |
| `--progress` | done/total, MiB, MiB/s, ETA on stderr every ~5 s (auto-on when stderr is a TTY) |
| O(N) indexing | one pass over the source pool builds `soid → stripe indices` (the original C++ tool rescanned the pool per file — O(N²); it has since gained the same index, `01c1583`) |

---

## 6. The `--config` site profile (all four tools)

Pools and connection identity can live in a flat profile instead of
positionals — same file format for Python and C++:

```ini
# site.conf — '#' comments (inline too); unknown keys are a HARD error
striper_pool = xrdtest
meta_pool    = cephfs.cephfs.meta     # reverse tools
data_pool    = cephfs.cephfs.data
conf         = /etc/ceph/ceph.conf    # optional
client       = admin                  # optional (was hardcoded 'admin' before)
fs_name      = cephfs                 # optional, forward tools (multi-fs clusters)
dest_prefix  = /migrated              # forward tools
strip        =                        # optional (empty = unset)
```

```bash
xrdceph_striper_migrate.py --config site.conf --verify          # Python
./xrdceph_striper_migrate  --config site.conf --verify          # C++
export XRDCEPH_MIGRATE_CONF=site.conf                           # flag-free default
```

Rules (identical everywhere):

- **Precedence: explicit CLI > config file > built-in default**
  (`conf`: `$CEPH_CONF` → `/etc/ceph/ceph.conf`; `client`: `admin`;
  `fs_name`: the cluster's default fs).
- **Arity:** give the tool its full legacy positional set *or none* — a
  partial mix is ambiguous and refused (exit 2). Legacy invocations are
  unchanged.
- Unknown keys and malformed lines abort before anything connects — typo
  protection for tools that can delete data.
- `client` also flows into the reverse tool's separate verify connection and
  the Python bridge; `fs_name` selects the filesystem via
  `ceph_select_filesystem` / `LibCephFS.mount(filesystem_name=…)`.

Parsers: `pymigrate.common.load_tool_config()` (Python),
`client/apps/ceph/xrdceph_migrate_config.h` (C++, header-only — compile with
`-I client/apps/ceph`).

---

## 7. Safety model (read this before a production run)

1. **READ-ONLY until finalize.** A write to a redirect-migrated file writes
   **through** to the source object. Serve the migrated estate read-only
   (export/mount/caps) until `--finalize` completes, or the original data is
   silently modified and rollback can no longer restore it.
2. **Redirect stubs carry no reference**, so deleting a *detached* stub never
   garbage-collects the source — rollback is data-safe by construction.
3. **Delete-through (the fixed hazard).** Deleting an **attached** stub
   deletes through to its target. The MDS purge behind `unlink` is
   *asynchronous*, so any path that unlinks a migrated CephFS file must
   **detach (`unset_manifest`) every stub first** — otherwise the purge
   destroys the source objects (even freshly re-created same-named ones)
   minutes later. Both rollback *and* `--force` re-migrate do this in both
   implementations now (Python from day one via a **data-pool ino index** —
   robust even when the source objects are already gone; C++ fixed in
   `01c1583`). The e2e runners assert source survival after both paths.
4. **Guards:** `--delete-source` is refused in redirect mode and during
   rollback (forward) and outside `--finalize` (reverse); the reverse tool
   refuses to run at all without `--assume-quiesced`.
5. **Failures are contained:** a per-file error logs `FAIL` and the run
   continues; exit 1 reports that something failed. Decoder refusals
   (unknown `struct_v`, truncation) are classified and skipped, never
   guessed at. The bridge fails **closed** before any write if its ABI
   self-test cannot pass.
6. **Out of scope (flagged, not migrated):** RADOS pool snapshots, CephFS
   `.snap` data, hardlink alias names, symlinks, special files, files whose
   data lives in a different pool. The reverse tool's report enumerates all
   of them per estate.

---

## 8. Testing

```bash
# unit tests (decoders vs reef byte-fixtures, plumbing, --config) — no cluster:
python3 -m pytest tests/ceph/test_cephfs_meta.py --noconftest -v     # 34 tests

# Python tools, full e2e (needs tests/ceph_harness.sh demo cluster + xrd-ceph-work):
tests/ceph/run_py_migrate.sh          # "run_py_migrate: ALL CHECKS PASSED"

# C++ forward tool e2e (incl. its --config leg + delete-through regression):
tests/ceph/run_striper_migrate.sh
```

`run_py_migrate.sh` covers, in one rerunnable script: forward redirect +
verify with source intact, MDS flush + cache-drop durability, idempotent
SKIP, rollback → re-migrate round-trip, copy + `--delete-source`, both
guards, `--json` validity, `--state` resume, `--prefix` subsetting, the
forced-shim bridge leg, and the full reverse lifecycle (report-only
classification → redirect → striper-read verify → rollback → finalize +
delete-source).

Gotchas worth knowing when extending the harness: the demo cluster's fs
pools are named `cephfs.cephfs.meta`/`cephfs.cephfs.data` (discover with
`ceph fs ls --format json` rather than hardcoding); `docker exec` needs `-i`
for heredoc-driven scripts; and the reverse C++ tool's `cephfs_denc`/
`cephfs_layout` dependencies must be compiled with `gcc` before linking
(`g++` compiles `.c` as C++ and breaks the `extern "C"` contract).
