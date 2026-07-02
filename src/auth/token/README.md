# token — WLCG/SciToken JWT and macaroon bearer-token validation

## Overview

This subsystem is the bearer-token authentication core for nginx-xrootd. It turns an
opaque `Authorization: Bearer <...>` value — a WLCG/SciToken **JWT** or a WLCG
**macaroon** (optionally with discharges) — into a trusted, structured
`xrootd_token_claims_t` describing the subject, issuer, audience, validity window,
VO groups, and a list of `permission:path` storage scopes. Every protocol that
accepts tokens funnels through one entry point, `xrootd_token_validate()` in
`validate.c`, so JWT and macaroon auth behave identically across `root://`, WebDAV,
and S3-with-OIDC paths. It is the WLCG-token half of the module's two distinct,
never-shared auth domains (the other being S3 SigV4 — see invariant #5 in the
master primer).

The subsystem owns the full token lifecycle: loading and **hot-refreshing** RSA/EC
public keys from a JWKS file (`jwks.c`, `keys.c`, `refresh.c`), verifying RS256 and
ES256 signatures on OpenSSL EVP (`signature.c`), parsing claims and scopes
(`validate.c`, `scopes.c`), validating HMAC-chained macaroons including third-party
discharge bundles (`macaroon.c`), and even *minting* macaroons for the
`POST /.oauth2/token` delegation endpoint (`macaroon_issue.c`). Cross-cutting
primitives — base64url (`b64url.c`), JSON-over-jansson (`json.c`), OAuth2 response
parsing (`oauth2.c`), bounded token-file reads (`file.c`) — live here too so callers
need only include the subsystem's small public headers.

In the request lifecycle this subsystem runs in the **auth/access phase**, before
any path is opened. The stream (`root://`) login path reaches it via
`../handshake/policy.c` and `../gsi/token.c`; WebDAV reaches it via
`../webdav/auth_token.c` (access-phase handler); S3-with-OIDC and TPC credential
flows use `oauth2.c`/`file.c`. Validation only *authenticates* the token and parses
its scopes — the caller must still call `xrootd_token_check_read()` /
`xrootd_token_check_write()` for the specific path before granting access, and that
path check is what enforces the scope-confined namespace.

Validation results are cached in two tiers so token auth never re-runs crypto +
JSON parsing on the event loop for a repeated token — the cause of "HTTP
ReadTimeout under load":

- **L1 — `worker_cache.c` (always on, per-worker, lockless).** A direct-mapped
  table keyed on SHA-256(token) → validated `xrootd_token_claims_t`, created
  lazily on first token auth. An L1 hit skips both `EVP_DigestVerify` AND the L2
  spinlock. This is the dominant win: the common "one client reuses its token for
  many requests" pattern collapses to an O(1) probe with no lock.
- **L2 — `token_cache.c` (optional, cross-worker SHM).** The pre-existing
  `xrootd_kv_t`-backed cache; consulted on an L1 miss and promoted into L1.

Both tiers store *only* successfully validated claims and cap each entry at
`min(exp-now, 5 min)`, so a token is re-validated at least every 5 minutes (the
standard stateless-JWT revocation/rotation tradeoff). L1 is per-conf, so the
issuer/audience/key-set/secret that governed a validation is implicitly part of
the cache identity — claims are never served across server/location blocks.

## Files

| File | Responsibility |
|---|---|
| `validate.c` | **Primary entry point.** `xrootd_token_validate()`: routes macaroon-vs-JWT, then for JWT does structure check (3 dot-segments) → alg check (RS256/ES256 only, rejects `alg:none`) → key selection by `kid` → signature verify → claim extraction (iss/sub/aud/exp/nbf/iat/scope/groups) → issuer/audience/time-window checks. Also `token_sanitize_for_log()` (anti log-injection) and `xrootd_token_extract_groups()`. |
| `scopes.c` | WLCG scope engine. `xrootd_token_parse_scopes()` splits the space-separated `permission:path` claim into `xrootd_token_scope_t[]`; `xrootd_token_check_read/_write()` test access with prefix matching guarded against the `/data` vs `/database` boundary attack. Maps `storage.read/write/create/modify/stage`. |
| `macaroon.c` | WLCG macaroon validator. `xrootd_macaroon_validate[_bundle]()` reconstructs the HMAC-SHA256 signature chain over binary packets, extracts `activity:`/`path:`/`before:` caveats, and verifies third-party discharge macaroons (AES-256-CBC vid decryption, caveat intersection). `xrootd_token_is_macaroon()` and `xrootd_macaroon_secret_parse()`. |
| `macaroon_issue.c` | Macaroon **minting** for the delegation endpoint. `xrootd_macaroon_issue()` builds the packet sequence (location/identifier/caveats/signature), computes the HMAC chain, base64url-encodes the result. |
| `jwks.c` | Loads a JWKS JSON file from disk (size-capped, `FD_CLOEXEC`), parses the `keys` array into `EVP_PKEY` handles via jansson. `xrootd_jwks_load/_free/_register_cleanup()`. |
| `keys.c` | JWK→OpenSSL bridge. `xrootd_token_rsa_pubkey_from_ne()` (n/e → RSA `EVP_PKEY`) and `xrootd_token_ec_pubkey_from_xy()` (x/y → EC P-256 `EVP_PKEY`) via `OSSL_PARAM_BLD` + `EVP_PKEY_fromdata`. |
| `signature.c` | JWT signature verification. `xrootd_token_verify_rs256()` (RSA+SHA-256 EVP chain) and `xrootd_token_verify_es256()` (converts IEEE P1363 raw `r||s` → DER ASN.1 before EVP). |
| `refresh.c` | JWKS hot-reload. Per-worker mtime-polling timer (`xrootd_token_jwks_schedule_refresh()` + handler) that reloads keys in-place only after a successful parse, preserving old keys on failure. |
| `config.c` | `xrootd_configure_token_auth()`: `nginx -t`-time validation that `token_jwks`/`token_issuer`/`token_audience` are set when auth is token/both, loads JWKS, records mtime, registers cleanup. |
| `token_cache.c` | L2: cross-worker validated-claims cache keyed on SHA-256(token), TTL = `min(exp-now, 5min)`. `xrootd_token_cache_lookup/_store()` and the `xrootd_token_cache` zone directive setter. |
| `worker_cache.c` | L1: always-on, per-worker, lockless direct-mapped validated-claims cache (`xrootd_token_l1_create/_lookup/_store()`). Front of the optional L2; created lazily per conf. Stops repeated token validation from stalling the event loop under load. |
| `oauth2.c` | `xrootd_oauth2_parse_access_token()`: extracts `access_token` from an OIDC/OAuth2 token-endpoint JSON response (jansson, duplicate-rejecting). |
| `file.c` | `xrootd_token_read_file()`: shared bounded reader for tokens/credentials stored on disk (size cap, whitespace strip, `FD_CLOEXEC`). |
| `b64url.c` | base64url codec (RFC 4648 URL-safe). `b64url_decode()` (OpenSSL EVP, 8 KiB cap) and `b64url_encode()` (minimal table-driven). |
| `json.c` | jansson-backed JSON accessors used by all token parsing: `json_get_string/_string_array/_int64()`, `json_backend_name()`. |
| `token.h` | Public interface + core types (`xrootd_jwks_key_t`, `xrootd_token_scope_t`, `xrootd_token_claims_t`) and tunables (`XROOTD_MAX_JWKS_KEYS`, `XROOTD_MAX_TOKEN_SCOPES`, `XROOTD_SCOPE_PATH_MAX`). |
| `token_internal.h` | Internal RSA/EC key-construction and RS256/ES256 verify prototypes (shared by `keys.c`/`signature.c`/`validate.c`/`macaroon.c`). |
| `macaroon.h` / `macaroon_issue.h` | Macaroon validate/issue prototypes and `XROOTD_MACAROON_ISSUE_OUT_MAX`. |
| `scopes.h` | Scope struct + parse/check prototypes (mirrors `token.h` for callers that need only scopes). |
| `oauth2.h` / `file.h` / `b64url.h` / `json.h` / `token_cache.h` | Public headers for the corresponding helpers. |

## Key types & data structures

- **`xrootd_token_claims_t`** (`token.h`) — the output of all validation. Fixed-size,
  caller-owned, no heap: `sub/iss/aud` (256B each), `exp/nbf/iat` (int64 epoch),
  `scope_raw` (1024B), `groups` (512B comma-joined from `wlcg.groups`), and a parsed
  `scopes[XROOTD_MAX_TOKEN_SCOPES]` array with `scope_count`. This whole struct is
  what `token_cache.c` stores verbatim.
- **`xrootd_token_scope_t`** (`token.h`/`scopes.h`) — one `permission:path` grant:
  `path[XROOTD_SCOPE_PATH_MAX]` plus `read/write/create/modify` bitfields. Empty path
  defaults to `/` (full-prefix) per WLCG convention; `storage.stage` maps to read.
- **`xrootd_jwks_key_t`** (`token.h`) — a loaded key: `kid[128]` + `EVP_PKEY *pkey`
  (RSA or EC). Held in the server-conf `jwks_keys[]` array (`config.c`/`refresh.c`).
- **`xrootd_macaroon_tp_t`** (`macaroon.c`, file-private) — a captured third-party
  caveat: `cid`, raw `vid`, and `sig_before` (the HMAC value before the cid update,
  which is the AES-256 key that decrypts the discharge key out of the vid).

## Control & data flow

**Entry** is almost always `xrootd_token_validate()` (`validate.c`). It first calls
`xrootd_token_is_macaroon()`; if the token has no `.` it is treated as a macaroon and
handed to `macaroon.c` (requires a configured secret). Otherwise it runs the JWT
pipeline using `b64url.c` (segment decode), `json.c` (claim extraction), the
`token_internal.h` key/verify helpers (`signature.c`), and finally `scopes.c` to
parse the scope claim. Success populates a caller-supplied `xrootd_token_claims_t`.

Callers into this subsystem:

- `../handshake/policy.c` and `../gsi/token.c` — stream `root://` login auth.
- `../webdav/auth_token.c` — WebDAV access-phase Bearer auth, including macaroon
  old-secret grace-period fallback during key rotation.
- `../webdav/macaroon_endpoint.c` — calls `xrootd_macaroon_issue()` for delegation.
- `../webdav/tpc_cred_parse.c`, `../tpc/tpc_token.c`, `../tpc/gsi_outbound_common.c`,
  `../upstream/auth.c` — TPC/redirector credential handling (`oauth2.c`/`file.c`).
- `../types/identity.c` — folds token claims into the unified identity model.

Key material is loaded at config time by `config.c` (calling `jwks.c`) into the
server-conf `jwks_keys[]`, then kept fresh per-worker by `refresh.c`. Scope decisions
made *after* validation feed `../path/` ACL/confinement: a granted scope is necessary
but the actual filesystem access still goes through `../path/beneath.c` confinement.
The validated-claims cache (`token_cache.c`) sits on top of `../shm/` (`xrootd_kv_t`)
and uses `../compat/crypto.h` for the SHA-256 fingerprint.

## Invariants, security & gotchas

- **`alg:none` is rejected before signature handling.** `validate.c:231` accepts only
  `RS256`/`ES256`; an unsigned token never reaches the verify step. The signature
  MUST be verified before any claim is trusted.
- **Issuer- and audience-confusion prevention.** When `expected_issuer`/
  `expected_audience` are configured, `iss`/`aud` must match exactly
  (`validate.c:314`, `:325`) — otherwise a valid token from a *different* trusted
  issuer would be accepted.
- **Path-prefix attack guard.** `scope_path_matches()` (`scopes.c:202`) requires the
  byte after the prefix to be `/` or NUL so `storage.read:/data` does **not** grant
  `/database`. Permission strings are matched by exact length (`token_scope_set_permission`).
- **Validation only authenticates; it does not authorize a path.** Callers must run
  `xrootd_token_check_read/_write()` per path, and real access is still gated by
  `../path/beneath.c` (RESOLVE_BENEATH). Token scope ≠ filesystem permission.
- **Log-injection defense.** Every untrusted claim is run through
  `token_sanitize_for_log()` (escapes control/non-ASCII to `\xHH`) before hitting the
  error log — a wire string must never be logged raw.
- **Clock skew is bounded, not zero.** `exp`/`nbf` are checked against the server
  clock with a `XROOTD_TOKEN_CLOCK_SKEW_SECS` (30s, `../types/tunables.h`) grace
  window; deployments still need NTP.
- **Macaroon HMAC chain is order-sensitive.** Any tampered/reordered caveat yields a
  mismatched final signature (`macaroon_parse_core`). Caveats *narrow* authority:
  `path:` caveats intersect with scope paths (disjoint ⇒ all permissions revoked,
  `macaroon.c:295`); `before:` only ever lowers `exp`.
- **Discharge depth is capped at 1.** Discharge macaroons may not themselves carry
  third-party caveats (`validate_bundle` passes `NULL` tp_arr); bundle limits are
  `XROOTD_MACAROON_MAX_DISCHARGES`/`_TP_CAVEATS` (8 each). Recovered discharge keys
  are wiped with `OPENSSL_cleanse`.
- **Cache is fail-open within its short TTL.** `token_cache.c` stores *only*
  successfully verified claims, never failures, and never beyond `min(exp, 5min)`;
  revocation cannot be detected once cached — the standard stateless-JWT tradeoff.
  Cached claims are re-checked against `exp` on lookup.
- **JWKS hot-refresh is leak-safe and crash-safe.** `refresh.c` frees old `EVP_PKEY`
  handles only after a successful reload; a failed parse keeps the old key set.
  `config.c` registers a pool cleanup that reads the live count at destroy time so
  refresh-mutated arrays are freed correctly on reload/shutdown.
- **Single-threaded assumptions.** Key-array swap is a `memcpy` + count update with no
  locking — correct only because each worker owns its config copy and runs the swap on
  its own event loop. No blocking I/O is performed during request-time validation.
- **Buffer caps.** Token ≤ 8192 bytes (`validate.c:191`); base64url decode capped at
  8 KiB; JWKS file ≤ 64 KiB; scope path ≤ 256B; ≤ 8 keys, ≤ 8 scopes. Oversized input
  is rejected, not truncated-into-overflow.

## Entry points / extending

- **Add a new scope permission:** extend `token_scope_set_permission()` (`scopes.c`)
  with the exact permission string + length, set the right `xrootd_token_scope_t` bit,
  and (if write-like) honor it in `xrootd_token_check_write()`. Add a bit to
  `xrootd_token_scope_t` in both `token.h` and `scopes.h` if a new capability is needed.
- **Add a new signature algorithm:** add a `verify_*` to `signature.c` (declared in
  `token_internal.h`), construct the key in `keys.c` if a new curve/type is involved,
  load it in `jwks.c`, and add the `strcmp(alg, ...)` branch in `validate.c`.
- **Add a new macaroon caveat:** parse it in `macaroon_parse_core()` (`macaroon.c`)
  and, for issuance, emit it via `write_packet()` in `macaroon_issue.c`. Keep both
  sides byte-for-byte consistent or the HMAC chain breaks.
- **Add a new JWT claim:** extract it in `xrootd_token_validate()` with
  `json_get_string/_int64()` into a new `xrootd_token_claims_t` field (remember the
  field is also what `token_cache.c` stores verbatim — size it fixed).
- **Register a new file:** any new `.c`/`.h` must be added to the project `config`
  source/header lists (see master primer build governance) before `./configure`.

## See also

- `../path/README.md` — RESOLVE_BENEATH confinement and ACLs that consume token scopes.
- `../gsi/README.md` — the x509-proxy auth domain (token claims fold into the same identity).
- `../webdav/README.md` — WebDAV Bearer/macaroon auth and the macaroon issuance endpoint.
- `../handshake/README.md` / `../session/README.md` — stream `root://` login that invokes validation.
- `../shm/README.md` — the KV zone backing `token_cache.c`.
- `../types/README.md` — `tunables.h` (clock skew) and the unified `identity` model.
- `../compat/README.md` — `crypto.h` (SHA-256) and `hex.h` used here.
- `../README.md` — master subsystem index.
