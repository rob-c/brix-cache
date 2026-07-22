/*
 * ucred_internal.h — internal parser prototypes shared between ucred.c and
 * ucred_parse.c.
 *
 * WHAT: Declares the four credential-file readers (PEM/token/S3/keyring) that
 *       live in ucred_parse.c and are called from brix_sd_ucred_resolve() in
 *       ucred.c.  These are implementation details of the ucred helper — NOT
 *       part of the public ucred.h surface — so they live in a private header
 *       that only the two ucred translation units include.
 *
 * WHY:  Splitting the file-format parsers out of ucred.c keeps each
 *       translation unit under the file-size guard while preserving the
 *       verbatim parser logic.  Only the four reader entry points cross the
 *       split; the per-format line-scanning helpers remain static in
 *       ucred_parse.c.
 *
 * HOW:  Prototypes only; include ucred.h for the ngx_int_t type and the
 *       BRIX_UCRED_* size bounds referenced by the callers.
 */
#ifndef BRIX_FS_BACKEND_UCRED_INTERNAL_H
#define BRIX_FS_BACKEND_UCRED_INTERNAL_H

#include "ucred.h"

/* Classify one candidate credential PEM file (x509 proxy). NGX_OK valid;
 * NGX_DECLINED absent/unreadable/unparseable, with *expired=1 when parseable
 * but past notAfter. */
ngx_int_t ucred_check_pem(const char *path, int *expired);

/* Read a bearer token from a .token file into out_bearer (cap bytes).
 * NGX_OK on a non-empty trimmed value, NGX_DECLINED otherwise. */
ngx_int_t ucred_read_token(const char *path, char *out_bearer, size_t cap);

/* Read an S3 access-key/secret-key/region triple from a .s3 file.
 * NGX_OK on a well-formed file, NGX_DECLINED otherwise. */
ngx_int_t ucred_read_s3(const char *path, char *out_ak, size_t ak_cap,
    char *out_sk, size_t sk_cap, char *out_region, size_t region_cap);

/* Read a CephX user id + keyring path from a `[client.NAME]` keyring file.
 * NGX_OK on a well-formed keyring, NGX_DECLINED otherwise. */
ngx_int_t ucred_read_keyring(const char *path, char *out_path, size_t path_cap,
    char *out_user, size_t user_cap);

#endif /* BRIX_FS_BACKEND_UCRED_INTERNAL_H */
