#ifndef XROOTD_DIRLIST_DCKSM_H
#define XROOTD_DIRLIST_DCKSM_H

#include "core/ngx_xrootd_module.h"
#include <sys/stat.h>

/* Parse the cks.type= CGI parameter from the kXR_dirlist payload.
 * Returns NGX_OK (algo set), NGX_DECLINED (unsupported algo, bad_algo set),
 * or NGX_ERROR on parse failure. */
ngx_int_t xrootd_dirlist_checksum_algorithm(const u_char *payload,
    size_t payload_len, char *algo, size_t algo_sz,
    char *bad_algo, size_t bad_algo_sz);

/* Compute the checksum of a single directory entry and write the
 * "algo:hexdigest" token into out[].
 * Takes ngx_log_t* instead of ngx_connection_t* so it is safe to call
 * from a thread-pool worker (no access to connection state). */
void xrootd_dirlist_checksum_token(ngx_log_t *log, int dfd,
    const char *name, const char *path, const struct stat *st,
    const char *algo, char *out, size_t outsz);

/* Format the extended 9-field dcksm stat body for a single entry into out[]. */
void xrootd_dirlist_make_dcksm_stat_body(const struct stat *st,
    char *out, size_t outsz);

#endif /* XROOTD_DIRLIST_DCKSM_H */
