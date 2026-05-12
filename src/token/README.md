# Token Sources

JWT/WLCG token handling is split by concept:

| File | Responsibility |
|---|---|
| `config.c` | nginx directive parsers: `xrootd_token_jwks`, `xrootd_token_issuer`, `xrootd_token_audience` |
| `jwks.c` | Load RSA public keys from a JWKS file |
| `keys.c` | Build OpenSSL RSA public keys from JWK `n`/`e` values |
| `signature.c` | Verify JWT RS256 signatures |
| `validate.c` | Public JWT validation and claim extraction |
| `scopes.c` | Parse and authorize WLCG storage scopes |
| `json.c` | Minimal JSON helpers used by token parsing |
| `b64url.c` | Base64url encode/decode helpers |
