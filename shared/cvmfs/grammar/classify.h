/* classify.h — CVMFS URL classifier (pure C, no ngx deps).
 *
 * WHAT: types + entry point mapping a request path onto the four CVMFS
 *       traffic classes (immutable CAS object / mutable signed metadata /
 *       geo API / reject).
 * WHY:  the whole cache policy — TTL, verification, pass-through, guard —
 *       keys off the class; one pure classifier keeps policy testable
 *       without nginx and reusable from dispatch AND the fill verifier AND
 *       the standalone FUSE client.
 * HOW:  no allocation, no failure mode — unrecognized shapes come back
 *       CVMFS_URL_REJECT; pointers in the result alias the input buffer.
 */
#ifndef BRIX_CVMFS_CLASSIFY_H
#define BRIX_CVMFS_CLASSIFY_H

#include <stddef.h>

typedef enum {
    CVMFS_URL_CAS = 0,      /* /cvmfs/<repo>/data/<2hex>/<hex36+>[suffix]     */
    CVMFS_URL_MANIFEST,     /* .cvmfspublished / .cvmfswhitelist / .cvmfsreflog */
    CVMFS_URL_GEO,          /* /cvmfs/<repo>/api/v1.0/geo/...                  */
    CVMFS_URL_REJECT        /* anything else                                   */
} cvmfs_url_class_e;

typedef struct {
    cvmfs_url_class_e  cls;
    const char        *repo;      size_t repo_len;   /* points into input     */
    const char        *rel;       size_t rel_len;    /* path under the repo   */
    char               cas_hex[129];                 /* CAS only, NUL-term    */
    size_t             cas_hex_len;
    char               cas_suffix;                   /* 0 or C/H/X/M/L/P      */
} cvmfs_url_info_t;

/* Classify `path` (len bytes, no query string). Returns 0 and fills *out;
 * never fails — unrecognized shapes come back CVMFS_URL_REJECT. Pure C,
 * no allocation, no ngx types (standalone-testable). */
int cvmfs_classify_url(const char *path, size_t len, cvmfs_url_info_t *out);

#endif /* BRIX_CVMFS_CLASSIFY_H */
