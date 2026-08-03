/*
 * cvmfs/secure_internal.h — shared seam between secure.c and secure_x509.c.
 *
 * The CVMFS authz modes are split across two TUs (bearer + dispatch in
 * secure.c, X.509/VOMS in secure_x509.c).  This header carries the two
 * declarations and the one policy constant they both need, so neither TU has to
 * export them through the module-wide header.
 */
#ifndef BRIX_CVMFS_SECURE_INTERNAL_H
#define BRIX_CVMFS_SECURE_INTERNAL_H

#include "cvmfs.h"

/* Max rendered subject-DN length (matches BRIX_UCRED_PRINC_MAX = 512, kept
 * local so this policy glue need not pull the ucred backend header). */
#define SCVMFS_DN_MAX  512

/* secure_x509.c — authz back-ends dispatched from brix_scvmfs_preamble().
 * Return NGX_DECLINED to proceed, else the HTTP status to fail with. */
ngx_int_t scvmfs_check_x509(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);
ngx_int_t scvmfs_check_voms(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

#endif /* BRIX_CVMFS_SECURE_INTERNAL_H */
