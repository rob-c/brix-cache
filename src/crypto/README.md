# crypto — OpenSSL PKI utilities: cert/CRL loading and verification

Low-level OpenSSL helpers shared by the stream module (GSI auth, CRL
enforcement) and the WebDAV module (x509 proxy cert verification).

| File | Exports |
|------|---------|
| `pki_load.c` | `xrootd_pki_load_certs_from_path` — load all PEM certs from a directory into a `STACK_OF(X509)` |
| `pki_load.c` | `xrootd_pki_load_crls_from_path` — load all PEM CRLs from a directory into a `STACK_OF(X509_CRL)` |
| `pki_check.c` | `xrootd_pki_verify_crls` — verify that every CA cert in a stack has a corresponding non-expired CRL |
| `pki_check.c` | `xrootd_pki_check_paths` — load configured CA/CRL paths and run the shared consistency check |
| `pki_check.h` | Public header; uses `UNIT_TEST` guards so the functions can be exercised without nginx types |

`pki_check.c` is designed to be independently unit-tested: when `UNIT_TEST`
is defined the nginx log/return types are replaced with plain C equivalents.
See `tests/unit/` for the test harness.

The `pki/` sibling directory contains module-specific wrappers that call
these functions at configuration time for each server block.
