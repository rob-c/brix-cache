# Token Sources

JWT/WLCG token handling is split by concept:

| File | Responsibility |
|---|---|
| `config.c` | nginx directive parsers: `xrootd_token_jwks`, `xrootd_token_issuer`, `xrootd_token_audience` |
| `jwks.c` | Load RSA/EC public keys from a JWKS file; uses Jansson when available and the built-in scanner for minimal builds |
| `keys.c` | Build OpenSSL RSA public keys from JWK `n`/`e` values |
| `signature.c` | Verify JWT RS256 signatures |
| `validate.c` | Public JWT validation and claim extraction |
| `scopes.c` | Parse and authorize WLCG storage scopes |
| `json.c` | Token JSON adapter; uses Jansson when available and falls back to minimal in-tree helpers |
| `b64url.c` | Base64url encode/decode helpers |
| `b64url.h` | Base64url helper types and prototypes |
| `file.c` | Token file operations: load/save token store |
| `file.h` | Token file operation types and prototypes |
| `json.h` | JSON adapter types and prototypes |
| `macaroon.c` | WLCG macaroon parser — activity/path caveat mapping, discharge VID handling |
| `macaroon.h` | Macaroon parser types and prototypes |
| `oauth2.c` | OAuth 2.0 token exchange helpers |
| `oauth2.h` | OAuth 2.0 helper types and prototypes |
| `refresh.c` | JWT refresh token management |
| `scopes.h` | Scope parsing types and prototypes |
| `token.h` | Public token validation interface |
| `token_internal.h` | Internal token types and cross-file prototypes |

## Commodity Library Notes

Phase 1 wires `jansson` behind the existing token JSON/JWKS API when
`pkg-config --exists jansson` succeeds.  The public token validation interface
does not change: callers still use `xrootd_jwks_load()` and
`xrootd_token_validate()`.

`libjwt`/`jose` are not assumed by the build.  JWT signature verification stays
on OpenSSL EVP so minimal deployments do not gain another hard dependency.

The WLCG macaroon parser remains local by design.  It implements project-specific
activity/path caveat mapping, discharge VID handling, and secret rotation
semantics that are not a drop-in fit for `libmacaroons`.
