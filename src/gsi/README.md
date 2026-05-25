# gsi — GSI/x509 proxy-certificate and bearer-token authentication

Implements the kXR_auth exchange for two credential types:

**GSI (Grid Security Infrastructure)** — multi-round DH key exchange over
x509 proxy certificates, following the XRootD GSI wire protocol.

| File | Responsibility |
|------|----------------|
| `config.c` | nginx directive parsers: `xrootd_certificate`, `xrootd_certificate_key`, `xrootd_trusted_ca`, `xrootd_vomsdir`, `xrootd_crl*` |
| `pki.c` | `xrootd_check_pki_consistency_stream` — validate CA/CRL paths at postconfiguration time |
| `auth.c` | `xrootd_handle_auth` — top-level kXR_auth dispatcher; routes by credential type and round number |
| `parse.c` | Decrypt and parse the x509 proxy chain from the client's kXGC_cert message |
| `parse_crypto_helpers.c` | OpenSSL crypto helpers for GSI signature parsing |
| `parse_x509.c` | X.509 certificate parsing for GSI auth |
| `cert_response.c` | `xrootd_gsi_send_cert` — build and send the server's kXGS_cert reply |
| `buffer.c` | XrdSutBuffer binary parser — scan a serialised bucket list for a specific bucket type |
| `gsi_internal.h` | Internal types: per-connection GSI context, bucket definitions, DH state |
| `token.c` | `xrootd_handle_token_auth` — validate a WLCG JWT against the configured JWKS and issuer |

**Bearer token (ztn/WLCG JWT)** — single-round token submission.

| File | Responsibility |
|------|----------------|
| `token.c` | `xrootd_handle_token_auth` — validate a WLCG JWT against the configured JWKS and issuer |

Both paths are dispatched from `auth.c`.  The token path is also used when
`xrootd_auth both` is configured (GSI preferred, token as fallback).
