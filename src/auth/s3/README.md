# S3 STS Credential Exchange

AWS STS client for backend credential EXCHANGE (phase-70 §5.5). An inbound S3
request proves knowledge of a secret via SigV4 but never transmits it, so the
caller's key cannot be forwarded to the origin — pure passthrough is impossible
by design. Instead the node holds a long-lived backend S3 *service* credential
and calls `AssumeRole` (or `GetSessionToken` when no role ARN is configured),
tagging the call with the inbound principal via `RoleSessionName`, and forwards
the resulting short-lived (AccessKeyId, SecretAccessKey, SessionToken) triple to
the origin. The one public entry point is `brix_s3_sts_assume()` in `sts.h`.

File split (phase-79 — formerly one 815-line file, split by concern):

- `sts.h` — public API: `brix_s3_sts_conf_t` (endpoint/region/role/service
  keys/TTL), `brix_s3_sts_out_t`, `brix_s3_sts_assume()`.
- `sts.c` — orchestrator: validates config, derives identity/timestamps,
  clamps the TTL to the STS-permitted [900, 43200] window, sanitises the
  RoleSessionName to the AWS-permitted alphabet, and drives prepare → perform
  → finish, pool-copying the returned credentials.
- `sts_sign.c` — pure request builder: canonical (sorted, percent-encoded)
  query string plus SigV4 signing over the "sts" service, reusing
  `brix_sigv4_signing_key()` and `brix_hmac_sha256`/`brix_sha256` from
  `core/compat/`. No I/O, no allocation.
- `sts_http.c` — the side-effecting edge: libcurl GET (TLS verified, protocols
  pinned to http/https, mirroring `webdav/tpc_curl.c`) and libxml2 parsing of
  the XML reply. A no-libxml2 build fails closed.
- `sts_internal.h` — the cross-file contract: `sts_req_t` / `sts_resp_t` /
  `sts_creds_buf_t`, the `BRIX_STS_RESP_MAX` (64 KiB) response bound, and the
  four seam functions. Nothing here is public — callers use only `sts.h`.

Invariants: the service secret and the returned secret/session token are never
logged. Response bodies are capped at `BRIX_STS_RESP_MAX` so a hostile reply
cannot exhaust memory. On `NGX_ERROR` the out params are untouched.
