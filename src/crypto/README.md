# crypto — OpenSSL PKI utilities: cert/CRL loading and verification

Low-level OpenSSL helpers shared by the stream module (GSI auth, CRL
enforcement) and the WebDAV module (x509 proxy cert verification).

| File | Exports |
|------|---------|
| `pki_load.c` | `xrootd_pki_load_certs_from_path`, `xrootd_pki_load_crls_from_path` — load all PEM certs/CRLs from a directory into STACK_OF(X509) / STACK_OF(X509_CRL) |
| `pki_build.c` | PKI certificate chain building and host-cert preparation |
| `pki_check.c` | CA/CRL path consistency check: verify every CA cert has a corresponding non-expired CRL |
| `gsi_verify.c` | GSI proxy certificate verification: chain validation, expiry, identity extraction |
| `ocsp.c` | OCSP stapling and online certificate status checking |
| `pki_build.h` | PKI build types and prototypes |
| `pki_check.h` | PKI check types and prototypes |
| `gsi_verify.h` | GSI verify types and prototypes |
| `ocsp.h` | OCSP helper types and prototypes

`pki_check.c` is designed to be independently unit-tested: when `UNIT_TEST`
is defined the nginx log/return types are replaced with plain C equivalents.
See `tests/unit/` for the test harness.

The `pki/` sibling directory contains module-specific wrappers that call
these functions at configuration time for each server block.
