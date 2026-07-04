# Unified kTLS across root://, WebDAV, and S3 — Design

**Date:** 2026-07-04
**Status:** approved (brainstorming)
**Author:** brix

## Goal

Provide one `brix_ktls` kTLS model spanning every brix TLS surface — the
`root://` stream and the HTTP plane (WebDAV `https://`/`davs://` and S3
`https://`). When the kernel TLS ULP can offload the negotiated cipher, TLS
downloads take the zero-copy `sendfile(2)` path (kernel encrypts in place) and
uploads decrypt in-kernel, eliminating the userspace `SSL_write`/`memmove`
crypto that a flame graph of the `https://+TLS+token` path showed dominating
(OpenSSL `libcrypto` + `__memmove_avx` ≈ 95% of on-CPU work; the module code and
token auth were negligible).

### Non-goals

- No new crypto, no cipher policy changes — kTLS uses the cipher nginx/OpenSSL
  already negotiated.
- No rewrite of the GET/PUT/read/write handlers — the HTTP plane relies on
  nginx's native output/recv path, which already uses `sendfile`/kTLS once the
  `SSL_CTX` is opted in.

## Background

- `root://` already has `brix_ktls` (`ngx_stream_brix_srv_conf_t.tls_ktls`),
  wired in `src/protocols/root/session/tls_config.c` via `SSL_OP_ENABLE_KTLS`,
  with a per-connection `brix_ktls_send_active()` (`BIO_get_ktls_send`) gate on
  the sendfile branch (`src/protocols/root/read/read.c`). It currently defaults
  **off**.
- The HTTP plane uses nginx's native `http_ssl` module (`listen … ssl`,
  `ssl_certificate`, …). The brix WebDAV `postconfig.c` already iterates
  `cmcf->servers` and reaches each server's `sslcf = ctx->srv_conf[
  ngx_http_ssl_module.ctx_index]` and calls `SSL_CTX_*` on `sslcf->ssl.ctx`
  (today for `X509_V_FLAG_ALLOW_PROXY_CERTS`). The same loop is the hook for
  `SSL_OP_ENABLE_KTLS`.
- WebDAV GET already serves via `brix_vfs_file_sendfile_fd()` → nginx output
  chain; S3 GET is likewise sendfile-eligible. Once the `SSL_CTX` carries
  `SSL_OP_ENABLE_KTLS`, nginx's `ngx_output_chain`/`ngx_linux_sendfile` and its
  recv path use kTLS automatically for both directions.

## Design

### Config model

- **Default ON where offloadable.** `SSL_OP_ENABLE_KTLS` is set by default on
  every brix TLS context. It is a transparent no-op when the negotiated cipher
  or running kernel cannot offload — OpenSSL falls back to userspace TLS with no
  behavior change. Escape hatch: `brix_ktls off`.
- **Stream (`root://`):** reuse `brix_ktls` → `tls_ktls`; flip the merge default
  `0 → 1` (`src/core/config/server_conf.c`). This changes the existing
  conservative default — intentional, per the unified "on where offloadable"
  decision.
- **HTTP (WebDAV + S3):** add a `ktls` flag to the shared
  `ngx_http_brix_shared_conf_t common` (embedded first in both the WebDAV and S3
  loc confs). Register a `brix_ktls` directive (`NGX_HTTP_*_CONF | NGX_CONF_FLAG`)
  in the WebDAV and S3 command tables, both writing `common.ktls`. Merge default
  **1** in each protocol's `common` merge.

### Enable point (HTTP)

A single focused helper — `brix_http_ktls_enable(ngx_conf_t *cf)` in
`src/core/http/` (shared HTTP semantics) — iterates `cmcf->servers`. For each
server that (a) has an `http_ssl` context (`sslcf->ssl.ctx != NULL`) and (b) is
a brix HTTP server with kTLS on — i.e. its WebDAV `common.enable && common.ktls`
**or** its S3 `common.enable && common.ktls` — it calls
`SSL_CTX_set_options(sslcf->ssl.ctx, SSL_OP_ENABLE_KTLS)` under
`#ifdef SSL_OP_ENABLE_KTLS`, and logs one NOTICE per server. `common` is the
first member of both loc confs, so the helper reads `enable`/`ktls` generically
from each module's loc conf without a cross-module struct dependency. Called once
from WebDAV `postconfig.c` (which already runs the server loop), so a server that
is S3-only, WebDAV-only, or both is covered.

### Data path

No handler changes. Downloads: nginx's file-backed output chain sendfiles over
the kTLS socket (kernel encrypt). Uploads: nginx recv uses kTLS RX (kernel
decrypt) — OpenSSL 3.0 `SSL_OP_ENABLE_KTLS` enables both TX and RX.

### Safety / fallback

Fully transparent: a non-offloadable cipher (TLS1.2 CBC, or ChaCha on a kernel
without chacha-kTLS) → userspace TLS, byte-identical. One startup NOTICE per
plane records that kTLS was requested; runtime engagement is decided by
OpenSSL/kernel per connection.

## Testing

- **Functional (engages):** HTTPS GET and PUT of a file with an AES-GCM cipher →
  byte-identical, **and** assert kTLS actually engaged by reading
  `/proc/net/tls_stat` `TlsTxSw`/`TlsRxSw` deltas across the transfer (software
  kTLS; the test box has the `tls` module loaded).
- **Escape hatch:** `brix_ktls off` → `TlsTxSw` delta 0, transfer still correct.
- **Safety (fallback):** force a non-offloadable cipher → transparent fallback,
  transfer byte-identical, no error.
- **`root://` regression:** existing `root://` TLS read/write still correct with
  the new default-on kTLS.

Three tests per the project rule: success (engages + correct), error/edge
(disabled + fallback), security-negative (cleartext and non-brix vhosts are not
kTLS-forced beyond their own SSL_CTX; no bytes served without the normal auth).

## Docs

`docs/` note: when kTLS helps (HW-offload NIC, copy-bound bulk transfer) vs hurts
(software-only kTLS on AES-NI CPUs), the default-on rationale, `brix_ktls off`
escape hatch, and the `/proc/net/tls_stat` verification recipe.

## Files touched

- `src/core/config/server_conf.c` — stream `tls_ktls` merge default `0→1`.
- `src/protocols/root/session/tls_config.c`, `src/protocols/root/stream/module.c`
  — log wording for default-on.
- `src/core/types/config.h` / shared conf — `ktls` flag on
  `ngx_http_brix_shared_conf_t`.
- `src/protocols/webdav/module.c`, `src/protocols/s3/…` — `brix_ktls` directive +
  `common.ktls` merge default 1.
- `src/core/http/ktls.c` (new) + header — `brix_http_ktls_enable()`; add to
  `./config`; call from `src/protocols/webdav/postconfig.c`.
- `docs/…` note; tests under `tests/`.
