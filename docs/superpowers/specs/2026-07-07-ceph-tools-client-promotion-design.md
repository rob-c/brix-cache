# Ceph operator tools — promotion into the official client suite (2026-07-07)

## Goal

Promote the CephFS↔RADOS (XrdCeph) migration and rescue tool family from
`tests/ceph/` into the official `client/` suite: first-class build, install,
man pages, completions, packaging, and docs — with the known C++ rollback
hazard fixed before the C++ tools become the primary face.

## Decisions (from brainstorming)

- **Both implementations promoted**: the Python tools (maintained, richer
  flags) AND the C++ tools, side by side.
- **C++ primary**: compiled binaries take the bare installed names
  (`xrdceph_striper_migrate`, `xrdceph_cephfs_to_striper`) — matching the
  names the RPM `brix-tools` subpackage already ships. Python tools install
  with a `.py` suffix.
- **Whole family**: the migration pair (py+cpp) plus the three C operator
  utilities `xrdrados_rescue`, `xrdcephfs_rescue`, `xrdceph_migrate`.
- **Approach A**: new `client/apps/ceph/` bucket (phase-69 style), reusing
  the client suite's existing install/man/completion plumbing. Precedent:
  `xrdstorascan` in `client/apps/scan/`.

## 1. Layout & naming

`git mv` from `tests/ceph/` to `client/apps/ceph/`:

| File | Role |
|---|---|
| `xrdceph_striper_migrate.cpp` | C++ forward migration (striper→CephFS), primary |
| `xrdceph_cephfs_to_striper.cpp` | C++ reverse migration (CephFS→striper), primary |
| `xrdceph_striper_migrate.py` | Python forward migration (`--json/--state/--prefix/--match/--progress`) |
| `xrdceph_cephfs_to_striper.py` | Python reverse migration |
| `pymigrate/` (incl. `shim/rados_manifest_shim.cpp`) | shared Python package + compiled C-ABI shim fallback |
| `xrdrados_rescue.c` | flat-pool recovery utility |
| `xrdcephfs_rescue.c` | CephFS-from-RADOS recovery utility (drives the `cephfsro` driver) |
| `xrdceph_migrate.c` | flat-pool → filesystem copy-through-mount |
| `ngx_shim.h` | ngx-type shim the C tools compile against (tools own it now) |

Stays in `tests/ceph/`: spikes (`spike_*.cpp`, `striper_redirect_cephfs.cpp`,
`striper_to_cephfs*.{c,cpp}`), seeds, denc/layout unit tests, the Docker
harness (`build_in_container.sh`, `Dockerfile.build`, fixtures), all
`run_*.sh` e2e runners, and `test_cephfs_meta.py`. Anything in `tests/ceph/`
that referenced a moved file (notably `ngx_shim.h` and the tool sources in the
runners) repoints to `client/apps/ceph/`.

Installed names keep the established underscore forms. No renames — the RPM
already ships `%{_bindir}/xrdceph_striper_migrate` and
`%{_bindir}/xrdceph_cephfs_to_striper`; that interface is preserved.

## 2. Build integration (`client/Makefile`)

A dep-gated optional section modeled on the existing FUSE3 gating (§14.4
pattern): probe each dependency via `pkg-config --exists` with a header
existence fallback (`/usr/include/rados/librados.h`, etc.), plus a working
`$(CXX)` (`CXX ?= g++`, verified with a one-line probe like the pkg-config
checks).

Per-tool gates (each joins `OPT_EXES` only when its own deps are present;
missing deps skip silently, exactly like `xrootdfs`):

| Tool | Needs |
|---|---|
| `xrdceph_striper_migrate` (C++) | CXX, librados, libcephfs |
| `xrdceph_cephfs_to_striper` (C++) | CXX, librados, libradosstriper |
| `xrdrados_rescue` (C) | librados |
| `xrdcephfs_rescue` (C) | librados |
| `xrdceph_migrate` (C) | librados |

Build recipes mirror what the RPM spec / `run_rescue_tools.sh` prove today:

- C tools: `$(CC) -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -include apps/ceph/ngx_shim.h`
  against the needed `src/fs/backend/rados/` sources (`sd_ceph.c`,
  `sd_ceph_compat.c`, and for `xrdcephfs_rescue` also `sd_cephfs_ro.c`,
  `cephfs_denc.c`, `cephfs_layout.c`), `-lrados`.
- Reverse C++ tool: `cephfs_denc.c`/`cephfs_layout.c` compiled **as C
  objects** first (g++ would treat `.c` as C++ and break the documented
  `extern "C"` boundary), then linked with `-lrados -lradosstriper`.
- Forward C++ tool: single TU, `-lrados -lcephfs -pthread`.

A `ceph-tools` phony target builds exactly this group so packaging can invoke
it directly. `make -C client` stays green with zero Ceph dev packages
installed (all five simply skipped).

## 3. Install & packaging

- `install-bin` installs the compiled tools through the existing `OPT_EXES`
  loop (already `[ -f ] &&`-guarded).
- Python: `pymigrate/` and both `.py` tools install to
  `$(PREFIX)/libexec/brix/`, with symlinks
  `$(PREFIX)/bin/xrdceph_striper_migrate.py` and
  `$(PREFIX)/bin/xrdceph_cephfs_to_striper.py` → libexec. The tools' existing
  `sys.path.insert(0, dirname(realpath(__file__)))` resolves the symlink, so
  `pymigrate` is found with **no source change**. The shim source ships
  alongside the package (it can compile on the spot; `PYMIGRATE_FORCE_SHIM=1`
  behavior unchanged).
- RPM (`packaging/rpm/nginx-mod-brix-cache.spec`): the hand-rolled `%build`
  g++ lines collapse to `make -C client ceph-tools` (with distro
  optflags/ldflags as for the main client build), `%install` copies from
  `client/bin/`, and `brix-tools` gains the three rescue utilities plus the
  suffixed Python tools + libexec `pymigrate/`. The spec and
  `client/Makefile` currently carry uncommitted WIP — edits are additive and
  must not disturb in-flight hunks.

## 4. C++ rollback hazard fix (promotion gate)

**Audit outcome (2026-07-07): the fix is already present in both C++ tools —
no code change was required.** The hazard (async MDS purge delete-throughs a
still-attached redirect stub to its source) was fixed after the memory note
that motivated this section was written. Re-verified at promotion time:

- Forward tool (`xrdceph_striper_migrate.cpp`): `detach_stubs()` runs before
  `ceph_unlink` in BOTH `rollback_one()` and the `--force` re-migrate path;
  `--finalize` detaches only after `tier_promote` makes the object owned;
  stubs are created with `set_redirect(..., 0)` (no reference), so deleting a
  detached stub never GCs the source.
- Reverse tool (`xrdceph_cephfs_to_striper.cpp`): rollback issues
  `unset_manifest` on each stub before `remove`; finalize promotes then
  detaches; `--delete-source` removes CephFS data objects only on the
  finalize path, after any `--verify`.

The stale "C++ tool unfixed" memory note has been corrected.

## 5. Docs, man pages, completions

- Five new section-1 man pages in `client/man/`, each passing
  `check_man.sh` (every `--flag` in `--help` present in the page; no `/home/`
  paths). The `xrdceph_striper_migrate.1` page documents the Python variant's
  extra flags (`--json/--state/--prefix/--match/--progress`) as belonging to
  the `.py` tool — an explicit, documented divergence.
- `completions/brix-tools.bash` gains the five tools.
- `client/README.md` and `client/apps/README.md` gain the `apps/ceph/` rows.
- The five `docs/10-reference/` migration/rescue docs update paths and build
  lines to the new locations / `make -C client ceph-tools`.
- `k8s-tests/remote-suite/tests/ceph/` mirrors the old layout; refresh it to
  match (confirm its sync mechanism during implementation — if it is
  script-generated, fix the generator, not the copy).

## 6. Testing

No new cluster tests. Verification matrix:

1. `make -C client` on this box **without** Ceph dev packages → all five
   skipped, suite builds green (gating proof).
2. `tests/ceph/build_in_container.sh` + repointed runners in the librados
   container → all five build; `run_rescue_tools.sh` smoke passes.
3. `run_striper_migrate.sh` (container e2e) → migrate + **rollback** legs
   green with the C++ detach fix; source objects verified intact after
   rollback.
4. `run_py_migrate.sh` + `test_cephfs_meta.py` → Python tools unchanged
   behavior from their new home.
5. `man/check_man.sh` green (new pages, binaries present or skipped).
6. RPM build (`packaging/rpm/` container) → `brix-tools` packages the new
   paths.

## Out of scope

- Feature-parity work between the C++ and Python implementations (the
  divergence is documented, not closed).
- Renaming tools to the suite's no-underscore convention.
- The Ceph Docker harness and spike/seed material — stays test-only.
