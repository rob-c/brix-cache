#ifndef BRIX_DIRLIST_DCKSM_H
#define BRIX_DIRLIST_DCKSM_H

#include "fs/vfs/vfs_policy.h"

#include "core/ngx_brix_module.h"
#include <sys/stat.h>

/* Parse the cks.type= CGI parameter from the kXR_dirlist payload.
 * Returns NGX_OK (algo set), NGX_DECLINED (unsupported algo, bad_algo set),
 * or NGX_ERROR on parse failure. */
ngx_int_t brix_dirlist_checksum_algorithm(const u_char *payload,
    size_t payload_len, char *algo, size_t algo_sz,
    char *bad_algo, size_t bad_algo_sz);

/*
 * WHAT: one entry's checksum request — where the entry lives (dirfd + name),
 *       how to name it in a log line, its already-taken stat, the algorithm,
 *       and the endpoint's phase-105 write posture.
 * WHY:  the digest cache writes an xattr ON THE EXPORT OBJECT (Appendix H.1),
 *       so the listing has to carry the caller's mutation policy down to the
 *       integrity layer rather than persisting unconditionally; bundling it
 *       also keeps the call at three parameters instead of nine.
 * HOW:  the caller fills one on the stack per entry; the token builder only
 *       reads it. `policy` zero-initialises to READ_ONLY, so a caller that
 *       forgets it recomputes the digest rather than writing to the export.
 */
typedef struct {
    ngx_log_t                  *log;    /* worker-safe log (never c->log)     */
    int                         dfd;    /* confined parent directory fd       */
    const char                 *name;   /* entry name within dfd              */
    const char                 *path;   /* display path for the integrity log */
    const struct stat          *st;     /* stat already taken by the caller   */
    const char                 *algo;   /* requested digest algorithm         */
    brix_vfs_mutation_policy_t  policy; /* phase-105 endpoint write posture   */
} brix_dirlist_cksum_req_t;

/* Compute the checksum of a single directory entry and write the
 * "algo:hexdigest" token into out[].
 * Takes ngx_log_t* instead of ngx_connection_t* so it is safe to call
 * from a thread-pool worker (no access to connection state). */
void brix_dirlist_checksum_token(const brix_dirlist_cksum_req_t *req,
    char *out, size_t outsz);

/* Format the extended 9-field dcksm stat body for a single entry into out[]. */
void brix_dirlist_make_dcksm_stat_body(const struct stat *st,
    char *out, size_t outsz);

#endif /* BRIX_DIRLIST_DCKSM_H */
