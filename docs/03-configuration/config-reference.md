# Configuration reference

Every directive that BriX-Cache recognizes, with types, defaults, and examples. Native XRootD stream directives live inside a `server {}` block in the `stream {}` section; WebDAV, S3, and metrics directives are collected at the end.

## Fail-fast path validation

During `nginx -t` and startup, the module validates configured file/directory
paths and permissions up front and fails fast with `emerg` log messages if
required inputs are missing or unreadable.

Examples of checks performed:
- stream: `brix_root`, `brix_cache_root`, `brix_certificate`, `brix_certificate_key`, `brix_trusted_ca`, `brix_crl`, `brix_token_jwks`, `brix_vomsdir`, `brix_voms_cert_dir`
- webdav: `brix_webdav_root`, `brix_webdav_cadir`, `brix_webdav_cafile`, `brix_webdav_crl`, `brix_webdav_token_jwks`, and HTTP-TPC paths (`brix_webdav_tpc_*`) when enabled
- s3: `brix_s3_root`

This avoids silent runtime failures deep in auth or request handling and gives
operators a precise startup error tied to the directive/path that is invalid.

---

## Configuration sub-pages

- [Directive reference](directives.md) — all `brix_*` directives with descriptions, defaults, and examples
- [Complete examples](examples.md) — annotated full nginx.conf configs for common deployments
- [Quick reference tables](quick-reference.md) — stream, metrics, WebDAV, and S3 directive summary tables

---
