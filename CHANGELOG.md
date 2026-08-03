# Changelog

Notable changes per release. The version in `src/core/ident.h`
(`BRIX_SERVER_VERSION_BARE`) is the single source of truth; the RPM version,
the spec's literal fallback, this file's top entry and the git tag all derive
from it, and `tools/ci/check_version_sync.py` fails CI if they drift apart.
Cutting a release is documented in
[docs/09-developer-guide/release-process.md](docs/09-developer-guide/release-process.md).

Versions that were never cut: **1.0.6**, **1.1.0**, **1.2.x**. The version line
skipped them; they are not missing entries. Releases before 1.3.0 were shipped
as RPM revisions (`1.1.1-3` … `1.1.1-25`) whose per-revision packaging detail
lives in the `%changelog` of
[`packaging/rpm/nginx-mod-brix-cache.spec`](packaging/rpm/nginx-mod-brix-cache.spec)
— that file remains authoritative for packaging changes; this one summarises
what changed for a user of the server.

---

## v1.4.0 — 2026-08-03

Storage, auth and cache feature wave, a diagnostic advisor, and a repository
hygiene pass that closed several guards which had stopped enforcing anything.

### Added

- **Client io_uring `O_DIRECT` tier** (`--io-uring-direct`): aligned slab
  allocation with a buffered short-tail fallback for the unaligned remainder.
- **HTTP cache-fill remote passthrough** (`brix_cache_passthrough`,
  `brix_cache_passthrough_max`): store-then-evict for objects that should not
  occupy the cache permanently. HTTP plane only — the `root://` stream plane
  does not passthrough.
- **CVMFS proxy authorization** (`brix_scvmfs_authz x509|voms`): end-entity DN
  authorization with an allow-glob (`brix_scvmfs_x509_dn`), plus a VOMS mode
  (`brix_scvmfs_voms`, `brix_scvmfs_vomsdir`, `brix_scvmfs_voms_cert_dir`).
- **`block:<device>` server plane**: exports a block device as a fixed-extent
  namespace `/0`…`/N-1`.
- **Full S3 namespace mutation** for the remote storage driver, via `path/`
  marker objects, with capability parity for directory writes.
- **WebDAV origin mutation** for the HTTP storage driver: `MKCOL` (`.mkdir`)
  and `MOVE` (`.rename`), advertising `CAP_DIRS_WRITE | CAP_HARD_RENAME`.
- **GridFTP VO ACL gate** (`brix_gridftp_require_vo`): fail-closed VO check on
  every verb at path resolution.
- **Bandwidth reservation** wired into `root://` read-open
  (`brix_throttle_bandwidth_zone`, `brix_throttle_bandwidth_budget`).
- **`xrddiag` remote advisor**: `--config-audit` scrapes `Qconfig`/`Qspace` and
  applies value rules; `--all-servers` fans out across the fleet and diffs;
  `--cap-threshold` tunes the capacity findings.
- **`xrddiag` mesh map**: `--map` with `--map-format ascii|dot|mermaid`,
  classifying nodes from the CMS plane (`kXR_locate`) so redirectors, data
  servers and read-only holders are distinguished — including endpoints that
  cannot be connected to directly.
- **`xrddiag` latency**: `--latency` / `--latency-count` measure bi-directional
  RTT over both the xrootd (`kXR_stat`) and CMS (`kXR_locate`) planes.

### Changed

- **brix-fault-proxy** unified onto the upstream v1.3.0 core and decomposed
  from a 2814-line monolith into seven translation units behind a shared state
  header; below-TCP and MITM fault levers retained.
- **Python dependencies** split into required / optional / dev / cluster-lab
  files, each entry bounded on both sides. `requirements.txt` previously named
  three packages against a suite that imports fifteen.
- **Repository governance**: added `SECURITY.md`, `CODEOWNERS`, Dependabot
  configuration, and issue/PR templates.

### Fixed

- **`urlencode` NUL passthrough** in the percent-codec (a `strchr(set, 0)`
  footgun) — found by a 2946-case non-UTF-8 byte-input suite over the real
  codec, opaque-validation and reserved-name kernels.
- **41 orphaned client sources** were never built: `make -C client` was red on
  `main`. Now wired into `client/Makefile` and enforced by a new guard.
- **The pre-push hook enforced no guards at all** — it globbed for shell
  guards long after the fleet became Python, so it both skipped every check and
  blocked every push on the unmatched pattern.
- **`check_gridftp_interop_image.py`** was committed without its executable
  bit, so CI could not run it.
- **A VFS seam bypass** in the io_uring `O_DIRECT` unaligned tail, and 13 files
  over the 600-line cap, both of which had reddened the tree's own guards.
- An optional test dependency (`zstandard`) was imported at module scope,
  making it mandatory for anyone collecting the test suite.

### Security

- New coordinated disclosure policy in
  [`SECURITY.md`](SECURITY.md): private reporting routes, response targets, and
  an explicit scope.
- Dependency bounds are now two-sided, so a new major of a crypto or HTTP
  dependency cannot enter CI unreviewed.

---

## v1.3.0 — 2026-07-24

### Added

- **CMS auto-role clustering**: a node derives its cluster role (manager /
  sub-manager / leaf) from its configuration and can act as a sub-manager of a
  stock upstream `cmsd` rather than only ever being a leaf. Includes
  control-plane action logging and a four-tier topology test.
- **brix-fault-proxy below-TCP and MITM fault levers.**

### Fixed

- **Per-worker SID collision** that made a stock `cmsd` reject workers 2..N as
  "already logged in" (with a 30s blacklist), so only `worker_processes 1`
  registered cleanly.

---

## v1.1.1 — 2026-07-07

Packaging-focused release; shipped as RPM revisions `-1` through `-25`.

### Added

- **Source-derived versioning**: the RPM version is `sed`ed out of
  `src/core/ident.h` by the build scripts, making the header the single source
  of truth.
- **SELinux support** for enforcing hosts: a targeted-policy subpackage
  (`brix_port_t` on 1094/1095/9001/9100, data-plane labels, impersonation-broker
  rules), plus a verification suite (`tests/test_selinux_rpm.py`).
- **CVMFS packaging**: `brix-cvmfs-automount` (native `brixMount autofs`
  umbrella, `/sbin/mount.cvmfs`, autofs program map) and `brix-cvmfs-config`
  (vendored upstream domain configs and master keys).
- **Co-installable compat subpackages** (`brix-cache-client-compat`,
  `brix-tools-compat`): the same binaries under a `brix-` prefix so a host can
  carry both stock `xrootd-client` and the BriX tools. One name-agnostic
  compile serves both — every tool derives its identity from `argv[0]`.
- **Standalone FUSE subpackages** (`brix-xrootdfs-fuse`, `brix-cvmfs-fuse`) so
  a mount tier can deploy without the full CLI suite.

### Changed

- `io_uring`, `zstd` and `lz4` default ON; Ceph became a stated contract.
- `packaging/` rebranded `nginx-xrootd` → `brix-cache` for everything that is
  not an upgrade-path compatibility name.
- Client binaries colliding with stock XRootD packages renamed
  (`mpxstats` → `mpxstats-brix`, `wait41` → `wait41-brix`, …).

### Fixed

- **CVMFS whitelist/manifest body-binding**: the signed hash line covers the
  body up to but *excluding* the `--\n` separator (verified against live
  stratum-1 artifacts). The verifier previously included it and rejected every
  genuine repository with trust/catalog error -5.
- Container builds.

---

## v1.0.8 — 2026-07-03 — BriX namespace rebrand

Renamed the project's own code namespace to BriX; upstream XRootD / `root://`
protocol references are preserved throughout.

- **Code:** server `xrootd_`→`brix_`, `XROOTD_`→`BRIX_`, `ngx_xrootd*`→`ngx_brix*`
  (incl. `ngx_xrootd_{module,fattr}.h`→`ngx_brix_*`); client `xrdc_`→`brix_`.
- **Breaking:** nginx config directives (`xrootd_*`→`brix_*`), Prometheus metric
  names (`xrootd_*`→`brix_*`), dashboard routes (`/xrootd`→`/brix`), env vars
  (`XROOTD_*`→`BRIX_*`), access-log filenames (`xrootd_access*.log`→
  `brix_access*.log`), and operator log-line prefixes (`xrootd:`→`brix:`).
- **Client:** `libxrdc.{a,so,pc}`→`libbrix.*` (SONAME `libbrix.so.0`),
  `libxrdposix_preload.so`→`libbrixposix_preload.so`, pkg-config `-lbrix`.
- **Preserved:** upstream XRootD/`root://` protocol refs (`kXR_*`, `XrdCl`,
  `XrdHttp`), tool binaries (`xrdcp`/`xrdfs`/`xrdcinfo`/`xrdckverify`/`xrdcrc32c`/
  `xrdcrc64`/`xrootdfs`), the nginx module identity `nginx-xrootd`, and the
  on-disk cache sentinels (`.ngx-xrootd-*`).
- Operator migration map: [docs/refactor/brix-rename-migration.md](docs/refactor/brix-rename-migration.md).

See the plan and rationale in
[docs/refactor/2026-07-03-brix-symbol-rebrand.md](docs/refactor/2026-07-03-brix-symbol-rebrand.md).

---

## v1.0.7 — 2026-07-03

Rebrand to BriX-Cache; CVMFS proxy resilience to upstream flakiness, plus
traffic visibility for it.

## v1.0.5 — 2026-07-02

Phase-67 source layout, gnuBall identity, `writev`/`ckpXeq` stock framing, and
an audit-hardening sweep.

> The 1.0.x line existed in the source only. Packaging went straight from
> `0.1.0-9` to `1.1.1-1`, so no RPM was ever labelled 1.0.x.

---

## v0.1.0 — 2026-04-21 → 2026-06-15

The pre-1.0 line, shipped as nine RPM revisions (`0.1.0-1` … `0.1.0-9`) under
the original `nginx-xrootd` package name. Per-revision detail is in the spec's
`%changelog`; the arc was:

- `-1` initial nginx dynamic module package;
- `-2` SRR, XrdHttp filter and dashboard modules;
- `-3` the native client tools (`xrdcp`/`xrdfs`/… plus the `xrootdfs` FUSE
  driver and the `LD_PRELOAD` shim) and the pytest suite, both as subpackages;
  RPM optflags threaded through the client build (PIE/RELRO/BIND_NOW);
- `-4` … `-9` module load ordering, external library linkage, and packaging
  fixes.
