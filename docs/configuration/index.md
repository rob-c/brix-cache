# Configuration reference

Native XRootD stream directives go inside a `server {}` block in the `stream {}` section of `nginx.conf`. Each `server {}` block is a separate XRootD endpoint and can have its own settings. HTTP/WebDAV, S3, and metrics directives are summarized at the end of this page.

## Fail-fast path validation

During `nginx -t` and startup, the module validates configured file/directory
paths and permissions up front and fails fast with `emerg` log messages if
required inputs are missing or unreadable.

Examples of checks performed:
- stream: `xrootd_root`, `xrootd_cache_root`, `xrootd_certificate`, `xrootd_certificate_key`, `xrootd_trusted_ca`, `xrootd_crl`, `xrootd_token_jwks`, `xrootd_vomsdir`, `xrootd_voms_cert_dir`
- webdav: `xrootd_webdav_root`, `xrootd_webdav_cadir`, `xrootd_webdav_cafile`, `xrootd_webdav_crl`, `xrootd_webdav_token_jwks`, and HTTP-TPC paths (`xrootd_webdav_tpc_*`) when enabled
- s3: `xrootd_s3_root`

This avoids silent runtime failures deep in auth or request handling and gives
operators a precise startup error tied to the directive/path that is invalid.

---

## Configuration sub-pages

- [Directive reference](directives.md) — all `xrootd_*` directives with descriptions, defaults, and examples
- [Complete examples](examples.md) — annotated full nginx.conf configs for common deployments
- [Quick reference tables](quick-reference.md) — stream, metrics, WebDAV, and S3 directive summary tables

---
