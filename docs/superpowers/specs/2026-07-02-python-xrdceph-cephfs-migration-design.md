# Python3 XrdCeph ↔ CephFS migration tools — design

**Status:** design, 2026-07-02
**Owner:** Rob Currie
**Predecessors:**
[`2026-06-30-cephfs-rados-program-design.md`](2026-06-30-cephfs-rados-program-design.md)
(umbrella program), the C++ originals
`tests/ceph/xrdceph_striper_migrate.cpp` (striper → CephFS) and
`tests/ceph/xrdceph_cephfs_to_striper.cpp` (CephFS → striper), and
`docs/10-reference/xrdceph-cephfs-bidirectional-migration.md`.

Re-implement both bidirectional XrdCeph (libradosstriper) ↔ CephFS migration
tools in **pure Python 3**, with full feature parity plus operator
quality-of-life improvements, keeping the zero-move in-place migration via
RADOS redirects, tested against the Docker Ceph demo cluster.

---

## 1. Goals

1. **Two separate Python tools**, mirroring the C++ pair one-to-one:
   - `xrdceph_striper_migrate.py` — Glasgow/RAL-style migration: expose an
     existing libradosstriper (stock XrdCeph) pool as a CephFS.
   - `xrdceph_cephfs_to_striper.py` — Lancaster/Manchester-style reverse
     migration: expose a quiesced CephFS as stock-XrdCeph striper storage.
2. **In-place (zero-move) migration via RADOS redirects** stays the default
   mode in both directions; copy/finalize/rollback/verify parity throughout.
3. **Pure Python**: distro `python3-rados` / `python3-cephfs` modules +
   stdlib only. No pip. No mandatory compile step (a compiled shim exists
   only as an automatic fallback).
4. **Improvements over the C++ tools**: `--json` machine output, progress
   reporting, a resumable state manifest, `--prefix`/`--match` worklist
   filters, and an O(N) single-pass source-pool index (the C++ forward tool
   rescans the pool per file — O(N²)).
5. **Tested in Docker Ceph**: decoder unit tests run anywhere; end-to-end
   tests run against the existing `ceph_harness.sh` demo cluster via a
   host-side runner in the `xrd-ceph-work` container.

### Non-goals

- The C++ tools are **kept unchanged** (proven reference); nothing is
  deleted or deprecated.
- No new nginx module code; these are standalone operator tools.
- Out-of-scope Ceph components stay out of scope exactly as in C++:
  RADOS pool snapshots, CephFS `.snap` data, RBD/RGW pools, additional
  filesystems; hardlink aliases and symlinks in the reverse direction are
  classified and reported, not migrated.
- No support for Ceph releases whose librados drops the
  `LIBRADOS_14.2.0`-versioned C++ ABI (see §3 risk handling — the tool
  fails closed, it does not guess).

---

## 2. Layout

All new files live in `tests/ceph/`, alongside the C++ originals:

```
tests/ceph/
  xrdceph_striper_migrate.py        # tool 1 entry point (executable)
  xrdceph_cephfs_to_striper.py      # tool 2 entry point (executable)
  pymigrate/
    __init__.py
    radosbridge.py                  # ctypes manifest-op bridge + striper read
    shim/rados_manifest_shim.cpp    # C-ABI fallback shim (compiled on demand)
    cephfs_meta.py                  # pure-Python CephFS metadata decoders + walker
    common.py                       # shared CLI plumbing (log/json/progress/state/worklist/threads)
  test_cephfs_meta.py               # decoder unit tests (no cluster)
  run_py_migrate.sh                 # host runner: e2e in xrd-ceph-work
```

Tools are invoked as scripts (`./xrdceph_striper_migrate.py …`); `pymigrate`
is imported relative to the script location (no install step).

---

## 3. The redirect bridge (`pymigrate/radosbridge.py`)

**Problem:** the manifest/redirect ops the zero-move mode depends on —
`set_redirect`, `tier_promote`, `unset_manifest`, `copy_from` — exist only
in librados's **C++** API. Verified on the reef 18.2 container: `librados.h`
has none of them, `rados.WriteOp` (python3-rados) has none of them, but
`librados.so.2` exports the mangled symbols under the ABI-versioned inline
namespace `librados::v14_2_0::` (stable since Nautilus, e.g.
`_ZN8librados7v14_2_020ObjectWriteOperation12set_redirectE…@@LIBRADOS_14.2.0`).

**Approach (hybrid, chosen):** a ctypes bridge as the default path, with a
compiled C-ABI shim as automatic fallback.

### 3.1 ctypes path (default)

- The bridge owns its **own** cluster connection through librados's C API
  via ctypes (`rados_create2`, `rados_conf_read_file`, `rados_connect`,
  `rados_ioctx_create`, `rados_ioctx_destroy`, `rados_shutdown`), so it
  holds raw `rados_ioctx_t` pointers independent of python-rados.
- For the four C++-only ops it calls the mangled symbols directly:
  - `ObjectWriteOperation` is polymorphic (virtual dtor), so the bridge
    never fabricates a vptr: it mallocs the object and calls the
    **exported C++ constructor** symbol to initialize it (and the exported
    destructor to tear it down).
  - `librados::IoCtx` is a single-pointer pimpl; the bridge fabricates one
    as `struct { void *io_ctx_impl; }` around its raw `rados_ioctx_t`.
  - `std::string` arguments are built per the CXX11 ABI
    (`{char *ptr; size_t len; union {char sso[16]; size_t cap;};}`).
  - Ops are submitted via the C++ `IoCtx::operate(const std::string&,
    ObjectWriteOperation*)` symbol.
- Symbol lookup tries a short list of known inline-namespace versions
  (currently `v14_2_0`; the list is the single place to extend). A miss
  raises a clear error naming every symbol tried.

### 3.2 Self-test gate

Before any real write in redirect/finalize/copy modes, the bridge
round-trips a throwaway object in the target pool: write a source blob →
create stub → `set_redirect` → read-through and byte-compare →
`unset_manifest` → delete both. Migration only starts if the self-test
passes; `--dry-run` skips it.

### 3.3 Shim fallback

If symbol probing or the self-test fails, the bridge falls back to
`shim/rados_manifest_shim.cpp`: ~80 lines exposing the four ops (plus a
version probe) with a plain C ABI, loaded via ctypes. Resolution order:

1. a prebuilt `rados_manifest_shim.so` next to the module (or at
   `$PYMIGRATE_SHIM`);
2. compile it on the spot with `g++` if a toolchain + librados-devel
   (`librados.hpp`) are present;
3. otherwise abort with a message explaining both remedies.

`PYMIGRATE_FORCE_SHIM=1` skips the ctypes path entirely so tests exercise
the fallback deliberately.

### 3.4 Striper read (for tool 2 `--verify`)

There is no distro Python binding for libradosstriper, but it has a full
**C API**; the bridge wraps `rados_striper_create` /
`rados_striper_read` / `rados_striper_getxattr` / `rados_striper_destroy`
from `libradosstriper.so.1` via ctypes (plain C — no ABI tricks needed).

### 3.5 Bridge API (consumed by both tools)

```python
class ManifestBridge:                       # context manager
    def __init__(conf_path, client="admin") ...
    def ioctx(pool) -> BridgeIoctx          # cached per pool
    def create_stub(pool, oid)              # create(exclusive=False)
    def set_redirect(dst_pool, dst_oid, src_pool, src_oid, src_version)
    def copy_from(dst_pool, dst_oid, src_pool, src_oid, src_version)
    def tier_promote(pool, oid)
    def unset_manifest(pool, oid)           # best-effort (no-op on owned objects)
    def self_test(scratch_pool) -> None     # raises BridgeError on failure
    def striper_read(pool, soid, size) -> bytes
```

`stat` (for `src_version`) and everything else standard goes through
python-rados in the tools; the bridge is deliberately minimal.

---

## 4. CephFS metadata decoders (`pymigrate/cephfs_meta.py`)

A pure-Python port of the existing C decode core
(`src/fs/backend/rados/cephfs_denc.{c,h}` + `cephfs_layout.{c,h}`), used by
tool 2 to walk an **unmounted** CephFS namespace straight from the metadata
pool:

- **denc layer:** bounded little-endian cursor; `ENCODE_START(v, compat,
  len)` framing with `DECODE_FINISH` length-skip; strings, bufferlists,
  maps/sets with element counts. Any overrun/underrun marks the cursor bad
  — no wild parses.
- **layout layer** (version-dispatched on the frame's `struct_v`, refusing
  cleanly on unknown/too-new versions):
  - `decode_dentry` — primary (`'I'/'i'` → embedded `InodeStore`) and
    remote (`'L'/'l'` → `(ino, d_type)`) dentries;
  - `decode_inode` (`inode_t` struct_v 2→19) — mode, size, nlink,
    mtime/ctime, `file_layout_t`, symlink target, xattr map, fragtree;
  - `decode_fragtree`, `decode_file_layout`;
  - the `mds_snaptable` `last_snap` probe (snapshots-exist detection).
- **walker:** iterates dir fragment objects `<ino_hex>.<frag_hex8>` in the
  metadata pool, paging omap keys via python-rados `omap_get_vals`;
  `_head` keys are current names; non-`_head` hex-suffixed keys are counted
  as snapshot dentries. Yields typed entries (file/dir/symlink/remote/
  special) so the tool's classification report is a pure consumer.

Truncation caps from the C decoders (fragtree entries, xattr count) are
kept, surfaced as per-entry flags and counted in the report.

---

## 5. Tool 1 — `xrdceph_striper_migrate.py` (striper → CephFS)

Feature parity with the C++ tool, same CLI grammar:

```
xrdceph_striper_migrate.py <striper_pool> <cephfs_data_pool> <dest_prefix>
    [--mode redirect|copy] [--rollback] [--finalize] [--list FILE]
    [--strip PFX] [--threads N] [--verify] [--delete-source] [--force]
    [--dry-run] [--conf PATH]
    [--json] [--state FILE] [--prefix PFX] [--match GLOB]   # new
```

Semantics preserved exactly:

- **Namespace creation via the MDS** (python3-cephfs `LibCephFS`): mkdirs,
  `open(O_CREAT|O_WRONLY|O_TRUNC)`, `fsetxattr` the three
  `ceph.file.layout.*` values to match the striper geometry (from
  `striper.layout.*` xattrs on `<soid>.0000000000000000`), close, `statx`
  for the inode, carry `user.*` xattrs, `truncate` to `striper.size`.
- **Redirect mode (default, zero-move):** for each stripe object
  `<soid>.<%016x>`, create stub `<ino_hex>.<%08lx>` in the CephFS data pool
  and `set_redirect` it at the striper object **without a reference** (so
  rollback can never GC the source). Read-only serving caveat documented
  as in C++ (writes write **through** to the source).
- **Copy mode:** `copy_from` (OSD-side), then strip the `striper.*` +
  `lock.striper.lock` xattrs from stripe 0. `--delete-source` valid only
  here, after verify.
- **Rollback:** `unset_manifest` every stub **first** (a stub
  delete-throughs to its source), then `ceph_unlink` — source pool intact.
- **Finalize:** `tier_promote` + `unset_manifest` per object + strip
  striper xattrs → normal read-write CephFS file, source droppable.
- **Verify:** read the CephFS file via libcephfs, `zlib.adler32` (seed 1 —
  identical algorithm), compare to carried `user.XrdCks.adler32`; fall back
  to size check when no checksum was carried.
- **Guards:** `--delete-source` refused in redirect mode and with
  `--rollback`; RADOS pool snapshots on the source flagged as not migrated.
- **Idempotency:** target present at the right size → `SKIP` (unless
  `--force`), plus the new state-manifest fast path (§7).

**Perf fix over C++:** one `nobjects` pass over the source pool up front
builds `soid → sorted [stripe indices]` (the C++ forward tool rescans the
whole pool for every file). Worklist enumeration (`*.0000000000000000`
suffix) falls out of the same pass.

---

## 6. Tool 2 — `xrdceph_cephfs_to_striper.py` (CephFS → striper)

Feature parity with the C++ tool, same CLI grammar:

```
xrdceph_cephfs_to_striper.py <meta_pool> <cephfs_data_pool> <striper_pool>
    --assume-quiesced [--finalize] [--rollback] [--strip PFX] [--threads N]
    [--verify] [--delete-source] [--dry-run] [--report-only] [--conf PATH]
    [--json] [--state FILE] [--prefix PFX] [--match GLOB] [--list FILE]  # --list is new here
```

- **Hard gate:** refuses to run without `--assume-quiesced` (fs unmounted /
  failed, MDS journal flushed) — the walk reads RADOS directly.
- **Pass 1:** index the CephFS data pool (`<ino_hex>.<objno_hex8>` →
  `ino → sorted [objno]`).
- **Pass 2:** walk the namespace from root ino `0x1` via `cephfs_meta`,
  emitting the same classification report as C++ (`--report-only` stops
  after it): regular files to migrate; dirs; hardlinked primaries
  (UNVERIFIED warning) and remote aliases (not migrated); symlinks;
  specials; other-pool files; snapshot dentries; SnapServer `last_snap`;
  truncated fragtrees/xattr sets; RADOS pool-snapshot warning. Per-item
  warning budget (400) then summary-only, as in C++.
- **Redirect (default):** per data object `<ino>.<%08x>`, create striper
  stub `<soid>.<%016x>` in the target pool, `set_redirect` at the CephFS
  object, then stamp `striper.layout.*` + `striper.size` (+ carried
  `user.XrdCks.adler32`) on stripe 0 so libradosstriper serves `<soid>`.
- **Verify:** whole-object `striper_read` via the bridge + adler32 against
  the carried checksum (also proves the redirect chain end-to-end).
- **Rollback:** `unset_manifest` then remove each striper stub — CephFS
  untouched. **Finalize:** `tier_promote` + `unset_manifest` per stub;
  `--delete-source` (finalize only) then removes the CephFS data objects.
- **Idempotency:** striper stripe 0 already stamped with matching
  `striper.size` → `SKIP` (finalize intentionally re-touches, as in C++).

---

## 7. Shared plumbing & improvements (`pymigrate/common.py`)

Both tools get, identically:

- **`--json`** — machine output as JSON Lines on stdout: one record per
  file `{"soid", "action", "result": "ok|skip|fail", "bytes", "objects",
  "dest", "error"?}` and a final `{"summary": …}` record; human log moves
  to stderr in this mode.
- **Progress** — a stderr line every ~5 s (and at end): files done/total,
  bytes, MB/s, ETA. Suppressed when stderr is not a TTY unless
  `--progress` forces it.
- **`--state FILE`** — append-only JSONL manifest of per-soid outcomes.
  On rerun with the same state file, soids recorded `ok` are skipped
  without touching the cluster; `fail`/absent entries are (re)processed.
  `--force` ignores the state file. Entries record action+mode so a state
  file from a migrate run does not suppress a rollback run.
- **Worklist filters** — `--list FILE` (both tools now), `--prefix PFX`,
  `--match GLOB` (fnmatch), composable (intersection).
- **Threading** — `ThreadPoolExecutor(--threads)`, per-file task, thread-
  safe counters; both python-rados and ctypes calls release the GIL.
  libcephfs mount and bridge connection are shared (thread-safe as in the
  C++ tools).
- **Exit codes** — 0 all ok/skip; 1 any per-file failure (run continues
  past failures); 2 usage/guard violations, matching the C++ tools.

---

## 8. Error handling

- Per-file errors: log `FAIL <soid>: <reason>` (+ JSON record), count,
  continue; never abort the estate for one file.
- Decoder refusal (unknown `struct_v`, truncation, short buffer):
  classified + skipped with a warning — never a guess.
- Bridge failure (symbols missing, self-test mismatch, shim unavailable):
  **fail closed before any write**, with a message that names the tried
  symbols and the shim remedies.
- Guard violations (`--delete-source` in redirect/rollback, missing
  `--assume-quiesced`): usage error, exit 2, nothing touched.
- Interrupted runs: safe by construction (idempotent SKIP + state
  manifest); a partially-migrated file is re-done from scratch on rerun
  (target cleared first, as in C++).

---

## 9. Testing

### 9.1 Decoder unit tests — `tests/ceph/test_cephfs_meta.py` (no cluster)

pytest, runnable anywhere: decode the byte fixtures in
`tests/ceph/fixtures/reef-18.2.4/` and assert equality with the
`ceph-dencoder` JSON ground truth (same fixtures the C decoders use);
negative cases: short/corrupt buffers, too-new `struct_v`, truncated
fragtree/xattr caps. Also unit-covers `common.py` (worklist filters, state
manifest, JSON records) with no Ceph imports needed.

### 9.2 End-to-end — `tests/ceph/run_py_migrate.sh` (Docker demo cluster)

Host-side runner in the `run_striper_migrate.sh` mould: copies the Python
files into `xrd-ceph-work`, seeds with the existing `striper_seed` /
`cephfs_seed` binaries, then asserts:

**Forward (striper → CephFS):** redirect migrate + verify with source
objects still present; durability across `flush journal` + `cache drop`;
idempotent rerun → SKIP; rollback (overlay gone, source intact) →
re-migrate round-trip; copy mode + `--delete-source` (source gone); guard:
redirect + `--delete-source` refused.

**Reverse (CephFS → striper):** seeded fs quiesced (`flush journal`);
`--report-only` classification matches the seeded tree (incl. symlink /
hardlink counts); redirect migrate + striper-read verify; rollback (CephFS
intact); finalize + `--delete-source`; guard: missing `--assume-quiesced`
refused.

**New features:** `--json` output parses and totals match; `--state` resume
(kill mid-run, rerun completes only the remainder); `--prefix` migrates
only the matching subset.

**Bridge paths:** the forward redirect leg is repeated with
`PYMIGRATE_FORCE_SHIM=1` to prove the fallback (skipped with a notice if
the container lacks g++/librados-devel).

Runner exits non-zero on any failed assertion; it does not touch the C++
tools' tests.

---

## 10. Documentation

- `tests/ceph/README.md`: a "Python migration tools" subsection under the
  existing recovery/migration section (usage, bridge/shim notes, runner).
- `docs/10-reference/xrdceph-cephfs-bidirectional-migration.md`: short
  note that Python implementations exist with identical semantics + the
  extra flags.

---

## 11. Risks

1. **C++ ABI coupling (ctypes path)** — mitigated by: versioned inline
   namespace (unchanged since Nautilus), the pre-write self-test gate, the
   compiled-shim fallback, and Docker e2e coverage of both paths.
2. **Decoder drift across Ceph releases** — same exposure as the C core;
   mitigated by version-dispatch + clean refusal + shared fixtures
   (reef seeded today; new releases = new fixture dirs).
3. **python3-cephfs/rados API variance across distro versions** — the
   tools pin to long-stable binding surfaces (mount/open/setxattr/statx,
   ioctx/omap/xattr); the e2e runner is the compatibility oracle.
4. **Redirect write-through hazard (inherent, both languages):** a
   redirect-migrated estate MUST be served read-only until finalized —
   documented prominently in both tools' `--help` and the README, exactly
   as the C++ headers do.
