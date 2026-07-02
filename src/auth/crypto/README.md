# crypto — shared OpenSSL X.509 / PKI core for GSI and WebDAV certificate auth

## Overview

This subsystem is the single home for the OpenSSL primitives that the gateway's
two independent certificate-authentication paths both need: the XRootD stream
**GSI** path (`root://`/`roots://`, `kXR_auth` with an RFC 3820 proxy chain) and
the HTTP **WebDAV/DAVS** path (`davs://` client certificate). Before this code
existed, each protocol carried its own ~25-line `X509_STORE_CTX` verification
block and its own ~80-line CRL file/directory scanner — verbatim duplicates that
could (and did) drift apart, so a flag fix or depth change would silently land in
only one protocol. Centralising here means one fix covers both, and the security
behaviour of GSI and DAVS stays provably identical.

It does four things: (1) build an `X509_STORE` from CA directories/bundles plus
grid-style CRLs (`pki_build.c`); (2) load PEM certs and CRLs off disk for a
startup consistency audit and verify each CRL is signed by a CA actually in the
trust store (`pki_load.c` + `pki_check.c`); (3) run the actual leaf-chain
verification with proxy-cert support and extract the subject DN
(`gsi_verify.c`); and (4) provide online OCSP revocation checking for client
certs plus OCSP-staple fetching for the server cert (`ocsp.c`). A header-only
helper (`scoped.h`) supplies the NULL-safe `goto cleanup` destroyer vocabulary
used across the wider crypto/TPC code to make attacker-driven error paths
leak-free.

Where it sits in the request lifecycle: everything here runs on the
authentication path, never the hot data path. `pki_build.c`/`pki_check.c` run at
**nginx config / reload time** (store construction + consistency audit).
`gsi_verify.c` and `ocsp.c` run **once per connection during login/handshake**,
before any file is opened. OCSP staple fetch is a periodic/reload-time server
operation consumed later by the TLS ClientHello callback. None of this code is
on the per-read/per-write path, which is why its synchronous (blocking) OpenSSL
BIO usage is acceptable.

These functions are **shared services** — this directory exports the
verification primitives; the per-protocol wiring (loading config paths into a
store, deciding soft-fail policy, mapping results to `kXR_NotAuthorized` vs HTTP
403) lives in the callers: `../gsi/` (`config.c`, `auth.c`, `pki.c`) and
`../webdav/` (`auth_store.c`, `auth_cert.c`, `pki.c`), plus `../session/`
(`tls_config.c`) for staple delivery.

## Files

| File | Responsibility |
|------|---------------|
| `gsi_verify.c` | `xrootd_gsi_verify_chain()` — the unified X509_STORE_CTX lifecycle: init with leaf + untrusted chain + CA store, set `X509_V_FLAG_ALLOW_PROXY_CERTS`, optional depth, `X509_verify_cert()`, then extract the leaf subject DN via `X509_NAME_oneline` into `res->dn_buf`. Owns nothing it is passed. |
| `gsi_verify.h` | Declares `xrootd_gsi_verify_chain()` and the `xrootd_gsi_verify_result_t` output struct (`char dn_buf[1024]`). |
| `pki_build.c` | `xrootd_build_ca_store()` — construct an `X509_STORE` from a CA dir and/or CA bundle file (falls back to system default paths if both NULL), apply caller `extra_flags`, then scan a CRL file or directory and, if any CRL loaded, enable `CRL_CHECK | CRL_CHECK_ALL | USE_DELTAS`. Internal `pki_load_crls*` scan `*.pem` and grid `*.r[0-9]` CRL files. |
| `pki_build.h` | Declares `xrootd_build_ca_store()`; documents NULL-path semantics and that CRL-path failure is fatal (returns NULL, store already freed). |
| `pki_load.c` | PEM loaders used by the startup audit: `xrootd_pki_load_certs_from_path()` / `xrootd_pki_load_crls_from_path()` accept a file or directory, allocate a `STACK_OF`, set `FD_CLOEXEC` on every opened file, filter CRL filenames, and free the stack if empty. Returns caller-owned stacks. |
| `pki_check.c` | Startup **consistency audit** (not online revocation): `xrootd_pki_check_paths()` loads CAs+CRLs, then `xrootd_pki_verify_crls()` matches each CRL's issuer DN to a CA subject DN **and** verifies the CRL signature with that CA's public key. Errors are logged but **non-fatal** (always returns NGX_OK). `xrootd_check_pki_and_crl()` is the thin module-facing wrapper. |
| `pki_check.h` | Declares the audit API; defines `UNIT_TEST` typedefs (`XROOTD_LOG_T`, `XROOTD_PKI_STATUS_T`) so `pki_check.c`/`pki_load.c` compile standalone for `tests/unit/` without nginx. |
| `ocsp.c` | OCSP client: `xrootd_ocsp_check_cert()` (online revocation of a client leaf via its AIA OCSP URL, with nonce + soft-fail policy) and `xrootd_ocsp_staple_fetch()` (fetch the server cert's OCSP response, DER-encode, cache in `xcf->ocsp_staple_data`). Synchronous HTTP/1.0 over OpenSSL BIO; HTTPS responders get a verifying TLS client with SNI. |
| `ocsp.h` | Declares the two OCSP entry points and documents the soft-fail contract (REVOKED always fails regardless of `soft_fail`). |
| `scoped.h` | Header-only `goto cleanup` idiom: NULL-safe destroyers (`xrootd_evp_pkey_free`, `xrootd_bio_free`, `xrootd_x509_store_ctx_free`, `xrootd_bn_clear_free` for secrets, etc.) plus an in-comment jansson borrowed/owned/stealing ownership cheatsheet. Used by the broader EVP/GSI/TPC code to free every handle on every exit path. |
| `README.md` | This document. |

## Key types & data structures

- **`xrootd_gsi_verify_result_t`** (`gsi_verify.h`) — output of chain
  verification; `char dn_buf[1024]` holds the NUL-terminated subject DN of the
  verified leaf, set only on `NGX_OK`, zeroed on failure.
- **`X509_STORE`** — the trust anchor set returned by `xrootd_build_ca_store()`
  and held per server block by the callers (`conf->gsi_store` for stream,
  `conf->ca_store` for WebDAV). The verify functions take it but never own it.
- **`STACK_OF(X509)` / `STACK_OF(X509_CRL)`** — caller-owned collections
  produced by `pki_load.c` and consumed by the `pki_check.c` audit; freed with
  `sk_X509_pop_free` / `sk_X509_CRL_pop_free`.
- **`OCSP_REQUEST` / `OCSP_RESPONSE` / `OCSP_CERTID` / `OCSP_BASICRESP`**
  (`ocsp.c`) — the request carries a replay-protection nonce; `OCSP_CERTID` is
  the SHA-1 hash of issuer fields (`OCSP_cert_to_id`); the basic response is
  signature-verified before its `V_OCSP_CERTSTATUS_*` is mapped to GOOD(0) /
  REVOKED(-1) / UNKNOWN(1).
- **`ngx_stream_xrootd_srv_conf_t`** (defined in `../types/config.h`) —
  `ocsp.c` reads `gsi_cert` / `gsi_store` and writes the cached staple into
  `ocsp_staple_data` / `ocsp_staple_len` (allocated with `ngx_alloc`, freed on
  reload).
- **The `scoped.h` destroyer set** — not a type but the project's standard
  cleanup vocabulary; treat every handle as `… *h = NULL;` then free
  unconditionally at one `cleanup:` label.

## Control & data flow

**Entry is always from a caller subsystem; this directory has no nginx hooks of
its own.**

- **Config / reload time.** `../gsi/config.c` and `../webdav/auth_store.c` call
  `xrootd_build_ca_store()` to build their per-server `X509_STORE`. `../gsi/pki.c`
  and `../webdav/pki.c` call `xrootd_check_pki_and_crl()` /
  `xrootd_pki_check_paths()` to run the startup CA↔CRL audit and warn (not fail)
  on misconfigured `ca_dir`/`crl_dir`.
- **Per-connection handshake.** `../gsi/auth.c` (stream GSI, `gsi/auth.c:217`)
  and `../webdav/auth_cert.c` (DAVS, `webdav/auth_cert.c:483`) call
  `xrootd_gsi_verify_chain()` against their store. On success GSI then optionally
  calls `xrootd_ocsp_check_cert()` (`gsi/auth.c:244`) for live revocation.
- **TLS staple.** `xrootd_ocsp_staple_fetch()` is driven at reload; the cached
  DER is later attached to the ServerHello by the status-request callback in
  `../session/tls_config.c` (`#include "../crypto/ocsp.h"`).

**Calls outward:** purely into OpenSSL (`libssl`/`libcrypto`) and libc
(`fopen`/`stat`/`opendir`); nginx core only for `ngx_log_*` and `ngx_alloc`.
It does **not** touch the data plane (`../aio/`, `../read/`, `../write/`),
path confinement (`../path/`), or metrics — it returns a verdict and a DN, and
the calling auth layer decides what to do with it.

**Build registration:** the five `.c` files are listed in the top-level `config`
script (`config:408-412`); a new file here must be added there or `./configure`
won't compile it.

## Invariants, security & gotchas

1. **Proxy certs are required, and enabled in two places.**
   `gsi_verify.c:69` sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the verify ctx, and
   callers pass the same flag as `extra_flags` to `xrootd_build_ca_store()` so
   the store honours RFC 3820 proxy chains (WLCG credentials). Drop either and
   valid grid proxies fail.
2. **DN match alone never authorises a CRL.** `pki_check.c` deliberately does
   issuer-DN matching only to *select a candidate CA*, then proves ownership with
   `X509_CRL_verify()` against that CA's public key
   (`xrootd_pki_crl_signature_valid`). Two CAs can share a subject DN in a
   misconfigured store; the signature step is what closes that hole.
3. **The startup audit is fail-open by design.** `xrootd_pki_verify_crls` /
   `xrootd_pki_check_paths` **always return NGX_OK** and only log — a broken or
   stale CRL must not take the whole gateway down at reload (grid CA bundles are
   updated out-of-band). This is intentional; do not "harden" it into a fatal
   error. Online enforcement is `ocsp.c`'s job, not the audit's.
4. **OCSP soft-fail contract.** `xrootd_ocsp_check_cert` returns 0 (pass) or -1
   (fail). A **REVOKED** status is always -1 and is never overridden by
   `soft_fail`; only network errors / missing AIA URL / UNKNOWN status are
   subject to `soft_fail` (`ocsp.c:336`+, `ocsp.h:35`). Choose the policy in the
   caller, not here.
5. **OCSP responses are nonce-checked.** Requests add a nonce
   (`OCSP_request_add1_nonce`); a nonce *mismatch* fails the check, a *missing*
   response nonce only warns (`check_ocsp_response`). Note: a
   `OCSP_MAX_RESPONSE_BYTES` constant (64 KiB) is *defined* at `ocsp.c:34` but is
   **not currently wired into the read path** — the response is read via
   `OCSP_sendreq_bio()` (`ocsp.c:223`) with no explicit byte cap. Treat the
   constant as a TODO/placeholder for a future bound, not an active guard. (This
   is low-risk in practice because the responder URL comes from the AIA of an
   already-chain-verified cert, but the constant does not enforce it.)
6. **Blocking I/O is allowed here only.** Both OCSP functions and all PEM loaders
   use synchronous BIO/`fopen`. This is safe *because* it runs on the
   auth/config path, never inside an event-loop data handler — do not copy this
   pattern into `../read/`, `../write/`, or any per-request hot path; use
   `../aio/` there instead.
7. **HTTPS OCSP responders are verified, not trusted blindly.** `do_ocsp_request`
   sets `SSL_VERIFY_PEER`, loads default trust paths, sets SNI **and**
   `SSL_set1_host()` for hostname verification, and rechecks
   `SSL_get_verify_result()` after handshake (`ocsp.c:144`-221).
8. **Known limitation, documented in code.** `xrootd_ocsp_check_cert` passes
   `NULL` as the store to `check_ocsp_response`, so the *client-cert* OCSP
   response signature uses OpenSSL defaults rather than `gsi_store`
   (`ocsp.c:390` note). It's acceptable only because the chain is already
   verified before the OCSP call; the *staple* path correctly passes
   `xcf->gsi_store`.
9. **Ownership discipline.** `xrootd_gsi_verify_chain` and `xrootd_build_ca_store`
   take ownership of nothing they receive; loaders return caller-owned stacks;
   `X509_NAME_oneline` results must be `OPENSSL_free`d (see
   `xrootd_pki_name_to_str` callers). Every file opened sets `FD_CLOEXEC` so a
   worker fork can't leak PKI fds. Prefer the `scoped.h` destroyers + a single
   `cleanup:` label for any new branchy crypto code.
10. **Unit-testability is a contract.** `pki_check.h`'s `UNIT_TEST` typedefs let
    `pki_check.c`/`pki_load.c` build without nginx for `tests/unit/`. New code in
    these two files must keep that ifdef path compiling (no hard nginx-only deps).

## Entry points / extending

- **Add a new CA/CRL source format:** extend the filename filter in
  `pki_load.c` (`xrootd_pki_crl_filename_matches`) and/or the directory scan in
  `pki_build.c` (`pki_load_crls`). Keep `FD_CLOEXEC` and the regular-file check.
- **Add a verification flag (e.g. policy constraints):** set it in
  `xrootd_gsi_verify_chain` (`gsi_verify.c:69`) so *both* protocols inherit it,
  and/or thread it through `extra_flags` of `xrootd_build_ca_store`. Never patch
  one caller only.
- **Add a revocation source (e.g. CRLDP fetch):** model it on `ocsp.c` — keep it
  synchronous-but-bounded, nonce/signature-checked, with an explicit soft-fail
  parameter, and update the `ocsp.h` contract comment.
- **New crypto `.c` file:** register it in the top-level `config` script
  alongside `config:408-412`, then `./configure` + `make`.
- **New cleanup helper:** add a NULL-safe `static ngx_inline` destroyer to
  `scoped.h` (use `*_clear_free` for secret material) and use the `goto cleanup`
  idiom documented at the top of that header.

## See also

- [`../gsi/README.md`](../gsi/README.md) — stream GSI auth; primary consumer of
  `gsi_verify` + `ocsp` + the CA store.
- [`../webdav/README.md`](../webdav/README.md) — DAVS client-cert auth
  (`auth_store.c` builds the store, `auth_cert.c` verifies the chain).
- [`../session/README.md`](../session/README.md) — TLS config and the OCSP
  status-request callback that delivers the cached staple.
- [`../token/README.md`](../token/README.md) / [`../sss/README.md`](../sss/README.md)
  / [`../krb5/README.md`](../krb5/README.md) — sibling auth domains (distinct
  trust models; they do **not** share this X.509 logic).
- [`../README.md`](../README.md) — master subsystem index.
