# Changelog

## v1.0.8 — BriX namespace rebrand

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
