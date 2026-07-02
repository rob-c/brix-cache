# gsi — XRootD `kXR_auth` dispatcher and GSI/x509 proxy-certificate authentication

## Overview

This subsystem implements the server side of the XRootD `kXR_auth` exchange for
the **stream** (`root://`/`roots://`) protocol. It is the single dispatch point
for every client credential type the gateway accepts: GSI/x509 grid proxy
certificates (`gsi`), WLCG/SciToken bearer JWTs (`ztn`), Simple Shared Secret
(`sss`), Kerberos 5 (`krb5`), and `unix`. Only `gsi` and `ztn` are *implemented
in this directory*; `sss`/`krb5`/`unix` are routed out to sibling subsystems.
Despite the directory name, `gsi/` therefore owns the credential-routing
"front door," not just GSI.

GSI is the heavyweight path and the reason this code is self-contained: rather
than linking the Globus GSSAPI stack, the module speaks the XRootD GSI wire
protocol directly against OpenSSL 3. The protocol is a two-round Diffie-Hellman
key exchange layered over `kXR_auth`. Round 1 (`kXGC_certreq`): the client asks
for the server's certificate; the server replies (`kXGS_cert`) with its X.509
cert, a fresh ephemeral `ffdhe2048` DH public key, and a cipher/digest
negotiation list. Round 2 (`kXGC_cert`): the client returns its DH public value
plus its X.509 proxy chain *AES-encrypted under the derived shared secret*. The
server derives the same secret, decrypts the chain, verifies it against the
configured CA store (allowing proxy certs), extracts the Subject DN, and
optionally resolves VOMS VO membership. The SHA-256 of the DH secret becomes the
session signing key used downstream for `kXR_sigver` request integrity.

In the request lifecycle this code runs *after* `kXR_login` and *before* any data
operation: `connection/handler.c` → `handshake/dispatch.c` →
`handshake/dispatch_session.c` calls `xrootd_handle_auth()` here. On success it
sets `ctx->auth_done = 1`, populates the unified `ctx->identity`, and registers
the session so that bind operations and CMS/manager cross-node coordination can
proceed. Configuration-time setup (loading the cert/key/CA store, caching the PEM
the server hands out, warming the DH key pool) also lives here and is driven from
`config/postconfiguration.c` and `config/process.c`.

GSI authentication is the most CPU-expensive credential path in the gateway, so
two performance concerns shaped this code: (1) a per-worker pool of
pre-generated ephemeral DH keys keeps OpenSSL keygen off the single nginx event
thread, and (2) a brute-force counter plus a verified-JWT cache bound the cost an
attacker or a handshake burst can impose.

## Files

| File | Responsibility |
|------|----------------|
| `auth.c` | `xrootd_handle_auth()` — the public, rate-limited `kXR_auth` entry point and its inner dispatcher. Reads the 4-byte credtype, routes to the right handler, runs the full GSI round-2 path (parse → `xrootd_gsi_verify_chain` → optional OCSP → DN/VOMS extraction → identity + session registration → metrics), and enforces the `XROOTD_MAX_AUTH_ATTEMPTS` brute-force limit. |
| `cert_response.c` | `xrootd_gsi_send_cert()` — GSI round 1. Pops/generates an ephemeral DH key, hex-encodes the public value as a `---BPUB---…---EPUB--` blob, optionally RSA-signs the client `rtag`, and assembles the `kXGS_cert` (`kXR_authmore`) wire response with `kXRS_puk`/`kXRS_cipher_alg`/`kXRS_md_alg`/`kXRS_x509`/`kXRS_main` buckets. |
| `parse_x509.c` | `xrootd_gsi_parse_x509()` — GSI round 2 top-level. Extracts client DH public + encrypted `kXRS_main`, derives the DH shared secret, sets `ctx->signing_key`/`ctx->signing_active`, AES-CBC-decrypts the chain, and returns the parsed `STACK_OF(X509)` (caller frees). |
| `parse_crypto_helpers.c` | OpenSSL building blocks for round 2: `xrootd_gsi_parse_client_dh_public_key()` (decode the BPUB/EPUB hex blob → `BIGNUM`), `xrootd_gsi_select_cipher_name()` (pick the cipher from `kXRS_cipher_alg`), `xrootd_gsi_build_peer_dh_key()` (build the client peer `EVP_PKEY` from merged server params + client pub). |
| `buffer.c` | `gsi_find_bucket()` — the XrdSutBuffer binary parser. Safely scans an untrusted `[type:BE][len:BE][data]` bucket list (terminated by `kXRS_none`) for one bucket type. Used by every GSI handler to locate buckets. |
| `keypool.c` / `keypool.h` | Per-worker warm pool of ephemeral `ffdhe2048` DH keys: `xrootd_gsi_dh_keygen()` (one key), `xrootd_gsi_keypool_init()` (lazy seed at worker start — generates only `xrootd_gsi_keypool_seed` keys synchronously, then fills to `xrootd_gsi_keypool_size` **off the event thread** via the GSI server's thread pool; full synchronous warm-up only when no thread pool exists), `xrootd_gsi_keypool_pop()` (lock-free pop + off-thread refill at half-target low-water). Keeps keygen off the event thread — including at boot, which was the dominant per-worker startup cost. |
| `token.c` | `xrootd_handle_token_auth()` — the `ztn` (WLCG/SciToken JWT) path. Extracts the bearer token, checks the cross-worker token cache, validates signature/issuer/audience via `xrootd_token_validate()` (with macaroon grace-period key rotation), then sets identity/DN/VO/scopes and registers the session. |
| `config.c` | `xrootd_configure_gsi()` (load cert/key/CA, cache server PEM, compute CA issuer hash) and `xrootd_rebuild_gsi_store()` (atomic, hot-reloadable `X509_STORE` rebuild from CA + CRLs with `X509_V_FLAG_ALLOW_PROXY_CERTS`). |
| `pki.c` | `xrootd_check_pki_consistency_stream()` — stream-config wrapper that validates the CA↔CRL pairing at config time via `crypto/pki_check.c`; non-fatal so the server still starts with a broken CRL. |
| `gsi_internal.h` | Shared internal declarations for the three in-directory handlers (`xrootd_gsi_send_cert`, `xrootd_handle_token_auth`, `xrootd_handle_sss_auth`); pulls in `ngx_xrootd_module.h` for ngx + OpenSSL EVP types. |
| `gsi_core.c` | **Shared, ngx-free** GSI crypto kernels (compiled into both the module *and* `libxrdproto`). After the Phase-38 split, keeps the cert-request/response assembly (`xrootd_gsi_build_cert_response`) + `kXR_sigver` HMAC helpers + the fixed DH-params PEM. |
| `gsi_buf.c` | XrdSutBuffer bucket scan (`xrootd_gsi_find_bucket`) + builder (`xrootd_gbuf_*`). *(Phase 38 split of `gsi_core.c`.)* |
| `gsi_dh.c` | Diffie-Hellman keygen/encode/decode/derive (`xrootd_gsi_dh_*`). *(Phase 38 split of `gsi_core.c`.)* |
| `gsi_cipher.c` | Session-cipher negotiation + AES encrypt/decrypt (`xrootd_gsi_cipher_*`). *(Phase 38 split of `gsi_core.c`.)* |
| `gsi_rsa.c` | RSA sign / encrypt-private / decrypt-public + `xrootd_gsi_rand`. *(Phase 38 split of `gsi_core.c`.)* |
| `gsi_core_internal.h` | Private (ngx-free) split contract shared by the `gsi_core`/`gsi_buf`/`gsi_dh`/`gsi_cipher`/`gsi_rsa` family. |

## Key types & data structures

- **`xrootd_ctx_t`** (`../types/context.h`) — the per-connection state this code
  reads and mutates: `cur_body`/`payload`/`cur_dlen` (current `kXR_auth` frame),
  `gsi_dh_key` (server ephemeral `EVP_PKEY`, lives only between round 1 and 2),
  `signing_key[32]` + `signing_active` (HMAC key for `kXR_sigver`), `dn`,
  `primary_vo`, `vo_list`, `bearer_token`, `token_scopes[]`/`token_scope_count`,
  `identity` (unified identity object), `auth_done`, `auth_fail_count`,
  `logged_in`, `sessid`.
- **`ngx_stream_xrootd_srv_conf_t`** (`../types/config.h`) — server config
  holding the GSI trust material: `auth` (`XROOTD_AUTH_GSI/TOKEN/SSS/UNIX/KRB5/BOTH/NONE`),
  `gsi_cert`/`gsi_key`/`gsi_store`/`gsi_cert_pem`(+`_len`)/`gsi_ca_hash`,
  `trusted_ca`/`crl`/`certificate`/`certificate_key`, `vomsdir`/`voms_cert_dir`,
  `ocsp_enable`/`ocsp_soft_fail`, JWKS/issuer/audience and macaroon-secret fields,
  `token_cache_kv`, and `rate_limit`.
- **GSI wire buckets** — `kXGC_certreq`/`kXGC_cert` (client steps),
  `kXGS_cert` (server reply), and the `XrdSut` bucket types
  (`kXRS_puk`, `kXRS_main`, `kXRS_x509`, `kXRS_cipher_alg`, `kXRS_md_alg`,
  `kXRS_rtag`, `kXRS_signed_rtag`, `kXRS_none`) defined in the XProtocol headers.
- **`xrootd_gsi_verify_result_t`** (`../crypto/gsi_verify.h`) — carries the
  verified leaf's DN (`dn_buf`) back from chain verification.
- **`xrootd_token_claims_t`** (`../token/`) — JWT claims (`sub`, `groups`,
  `scopes[]`, `scope_count`) extracted on the `ztn` path.
- **`xrootd_gsi_refill_t`** (`keypool.c`) — task-local batch of freshly generated
  keys handed from the thread-pool worker back to the event thread on refill.

## Control & data flow

Execution **enters** at `xrootd_handle_auth()`, called from
`../handshake/dispatch_session.c` (the `kXR_auth` opcode case) once
`ctx->logged_in` is set. From there:

- **GSI round 1** → `xrootd_gsi_send_cert()` (`cert_response.c`), which pulls a
  key from `keypool.c` (refilling via `../aio/` thread-pool tasks) and uses
  `gsi_find_bucket()` (`buffer.c`) to locate the client `rtag`. The server cert
  PEM it ships was cached at config time by `xrootd_configure_gsi()` (`config.c`).
- **GSI round 2** → `xrootd_gsi_parse_x509()` (`parse_x509.c`) + the helpers in
  `parse_crypto_helpers.c`, then chain verification in `../crypto/` (`gsi_verify.h`),
  optional revocation via `../crypto/ocsp.h`, and VOMS attribute extraction in
  `../voms/` (`xrootd_extract_voms_info`, runtime-dlopen, gated by
  `xrootd_voms_available()`).
- **Token (`ztn`)** → `token.c` → `../token/` (`xrootd_token_validate`,
  `token_cache.h`, `macaroon.h`).
- **`sss` / `krb5` / `unix`** → routed by `auth.c` to `../sss/`, `../krb5/`,
  and the unix handler respectively — not implemented here.

On success every path calls `../session/registry.h`
(`xrootd_session_register`), populates `ctx->identity`
(`xrootd_identity_set_*`), records per-VO/per-user counters via `../metrics/`
(`xrootd_metrics_shared`, `xrootd_track_vo_activity`, `xrootd_track_unique_user`),
and emits an access-log line via `xrootd_log_access`. The GSI/token-derived
`ctx->signing_key` is later consumed by `../handshake/sigver.c` and
`../session/signing.c` to verify `kXR_sigver`-signed requests. Config-time
entry is from `../config/postconfiguration.c` (calls `xrootd_configure_gsi`) and
`../config/process.c` (calls `xrootd_gsi_keypool_init` per worker and re-runs
`xrootd_rebuild_gsi_store` on the CRL-refresh timer).

## Invariants, security & gotchas

- **Phase ordering is enforced.** `xrootd_handle_auth_inner()` rejects
  `kXR_auth` unless `ctx->logged_in` (`kXR_login` must precede it). With
  `XROOTD_AUTH_NONE` it short-circuits to `auth_done = 1`.
- **Each credtype is gated against `conf->auth`** before its handler runs — a
  `gsi` credtype is refused unless `auth` is `GSI` or `BOTH`, `ztn` unless
  `TOKEN`/`BOTH`, etc. Fail-closed: unknown credtypes → `kXR_NotAuthorized`.
- **Two-round GSI is mandatory for confidentiality.** The proxy chain is only
  ever read after AES-CBC decryption with the DH-derived secret; a missing
  `ctx->gsi_dh_key` in round 2 means round 1 was skipped and parsing aborts
  (`parse_x509.c:52`). The DH key is freed immediately after round 2 in `auth.c`.
- **Untrusted binary parsing.** `gsi_find_bucket()` (`buffer.c`) bounds-checks
  every bucket length against the frame end and uses `ngx_strnlen()` so a missing
  protocol-name NUL cannot cause an out-of-frame read. The wire frame is never
  mutated in place — the DH hex blob is copied to a pool buffer before
  NUL-termination (`parse_crypto_helpers.c`).
- **Secret hygiene.** The DH shared secret is `OPENSSL_cleanse()`d after cipher
  key/IV setup (`parse_x509.c`). The AES-CBC IV is the all-zero GSI-standard IV.
- **Brute-force + amplification guard.** `xrootd_handle_auth()` stops after
  `XROOTD_MAX_AUTH_ATTEMPTS` and explicitly does **not** count the `kXGC_certreq`
  round (a protocol challenge, not a credential failure) toward the limit.
- **OpenSSL error-queue hygiene (Phase 33).** Each auth round starts with
  `ERR_clear_error()`; GSI parsing provokes benign OpenSSL errors that, left in
  the queue, corrupt nginx's TLS clean-close detection on the shared worker.
- **Keygen must stay off the event thread.** Inline `ffdhe2048` keygen
  head-of-line-blocks the whole worker under a handshake burst, so keys come from
  the warm pool; the pool is only mutated by the event thread (pop + refill
  done-callback), making it lock-free. Inline keygen is a correctness fallback
  only (`cert_response.c`, `keypool.c`/`keypool.h`).
- **DN truncation is logged, not silent.** A DN longer than `sizeof(ctx->dn)` is
  truncated with a warning that VO-ACL matching may break (`auth.c`).
- **Hot CRL reload is non-disruptive.** `xrootd_rebuild_gsi_store()` builds the
  new `X509_STORE` first and atomically swaps it in, leaving the old store intact
  on failure so live connections are never broken.
- **Per-identity rate limiting** (`auth.c`) is applied *after* the DN/identity is
  known (keyed by DN or peer IP per config), distinct from the early
  brute-force counter.
- **Token vs GSI are separate auth domains.** The `ztn` path shares no signature
  logic with GSI; it sets `ctx->token_auth`, stashes the raw token in
  `ctx->bearer_token` for proxy auth-bridging, and only caches *verified* claims.
- **Metric labels stay low-cardinality** — VO names are tracked, DNs/tokens are
  not used as label values.

## Entry points / extending

- **Add a new credential type:** add the 4-byte credtype check in
  `xrootd_handle_auth_inner()` (`auth.c`), gate it against a new
  `XROOTD_AUTH_*` value in `conf->auth`, and either implement the handler here or
  route to a sibling subsystem (mirror the `sss`/`krb5` pattern). Declare the
  handler in `gsi_internal.h`.
- **Add a GSI config directive:** add the field to
  `ngx_stream_xrootd_srv_conf_t` (`../types/config.h`), wire the command in the
  config subsystem, then load/validate it in `xrootd_configure_gsi()`
  (`config.c`). Register any new `.c` file in the top-level `config` script
  (`$ngx_addon_dir/src/auth/gsi/…`) and re-run `./configure`.
- **Change the cipher/digest negotiation:** edit the advertised lists in
  `cert_response.c` (`cipher_alg`/`md_alg`) and the accepted set in
  `xrootd_gsi_select_cipher_name()` (`parse_crypto_helpers.c`).
- **Tune the DH key pool:** the `XROOTD_GSI_KEYPOOL_*` knobs live in
  `../types/tunables.h`.

## See also

- `../handshake/README.md` — opcode dispatch and `kXR_sigver` verification
  (consumes `ctx->signing_key`).
- `../session/README.md` — login, the session registry, and request signing.
- `../crypto/README.md` — `xrootd_gsi_verify_chain`, OCSP, CA-store building,
  PKI/CRL consistency checks.
- `../voms/README.md` — VOMS VO-membership extraction.
- `../token/README.md` — JWT validation, the token cache, and macaroon secrets.
- `../sss/README.md`, `../krb5/` — the other credential handlers this dispatcher
  routes to.
- `../config/README.md` — directive registration and the CRL-refresh / key-pool
  worker init hooks.
- `../README.md` — master subsystem index.
