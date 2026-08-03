/* vfs_deleg_internal.h — seam between the delegation gate TUs.
 *
 * WHAT: Declarations shared by vfs_deleg.c (strategy dispatch, SSS/krb5/STS
 *       arms) and vfs_deleg_x509.c (RFC-3820 proxy-chain trust gate).
 *
 * WHY:  The two TUs are one logical unit split for the 600-line cap
 *       (coding-standards §1); these symbols are internal to that unit and
 *       deliberately NOT in vfs_internal.h, which is the module-wide seam.
 *
 * HOW:  Include after vfs_internal.h. Every symbol here is defined in one of
 *       the two deleg TUs and referenced only by the other. */

#ifndef BRIX_VFS_DELEG_INTERNAL_H_INCLUDED
#define BRIX_VFS_DELEG_INTERNAL_H_INCLUDED

/* Cleanup payload: the pool-allocated 0600 temp path materialised for a
 * PASSTHROUGH proxy. On pool destruction the file is removed and the path
 * string is zeroed so it cannot linger in freed-but-reused pool memory. */
typedef struct {
    char *path;   /* NUL-terminated temp path, owned by the request pool */
} brix_deleg_temp_t;

/* vfs_deleg.c — pool-cleanup handler for a staged proxy-PEM temp file: unlinks
 * the path (ENOENT tolerated) and scrubs the path bytes. */
void brix_vfs_deleg_temp_cleanup(void *data);

/* vfs_deleg.c — true when the bytes parse as at least one PEM certificate. */
int brix_vfs_deleg_pem_is_valid(const u_char *pem, size_t len);

/* vfs_deleg_x509.c — PASSTHROUGH arm: chain-trust re-verify of the captured
 * proxy PEM, then stage it to a request-scoped temp file for the driver. */
ngx_int_t brix_vfs_deleg_proxy(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out);

#endif /* BRIX_VFS_DELEG_INTERNAL_H_INCLUDED */
