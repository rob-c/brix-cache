#ifndef BRIX_CHECKSUM_QCKSUM_INTERNAL_H
#define BRIX_CHECKSUM_QCKSUM_INTERNAL_H

/*
 * WHAT: Shared internal seam for the kXR_Qcksum decomposition — the per-request
 *      scope struct, the default-algorithm macros, and the prototypes for the
 *      helpers that cross the checksum_qcksum.c / checksum_qcksum_path.c split.
 * WHY:  The dispatcher + handle variant (checksum_qcksum.c) and the path variant
 *      (checksum_qcksum_path.c) both build a brix_qcksum_req_t, seed it from the
 *      default algorithm, and share the algorithm parser + checksum builder; the
 *      dispatcher also calls into the path variant. These few symbols are the
 *      only cross-file contract — everything else stays file-local static.
 * HOW:  Pulls query_internal.h for the brix core types (brix_ctx_t,
 *      ngx_stream_brix_srv_conf_t, brix_sd_obj_t) plus PATH_MAX/BRIX_MAX_PATH,
 *      then declares the shared macros, struct, and prototypes.
 */

#include "query_internal.h"

/* Default kXR_Qcksum algorithm — xrdcp's historical default; a leading "algo:"
 * prefix or a "?cks.type=" CGI on the request overrides it downstream. */
#define BRIX_QCKSUM_DEFAULT_ALGO "adler32"
#define BRIX_QCKSUM_ALGO_SZ      32

/*
 * WHAT: Per-request scope shared by every kXR_Qcksum decomposition helper — the connection/config
 *      trio plus the selected algorithm buffer and the resolved paths.
 * WHY:  Threading (ctx, c, conf, algo) through each stage as discrete parameters pushed several
 *      helpers past the 5-argument budget; a single scope struct keeps the data flow explicit
 *      while every helper stays within the argument gate. It is a plain value bundle — no hidden
 *      global state — constructed fresh per request in the two variant entry points.
 * HOW:  `algo` is seeded to BRIX_QCKSUM_DEFAULT_ALGO and may be overridden by algo selection;
 *      `full_path`/`pathbuf` are populated by the resolver (path variant) or the fhandle lookup
 *      (handle variant). Buffers are inline so the struct owns their storage for the request.
 */
typedef struct {
    brix_ctx_t                 *ctx;
    ngx_connection_t           *c;
    ngx_stream_brix_srv_conf_t *conf;
    char                        algo[BRIX_QCKSUM_ALGO_SZ];
    char                        full_path[PATH_MAX];
    char                        pathbuf[BRIX_MAX_PATH + 1];
} brix_qcksum_req_t;

/* Shared across the qcksum split (checksum_qcksum.c ↔ checksum_qcksum_path.c). */
ngx_flag_t brix_query_parse_algorithm(const u_char *src, size_t len, char *algo,
    size_t algo_sz);

ngx_int_t brix_query_build_checksum(brix_ctx_t *ctx, ngx_connection_t *c,
    int fd, brix_sd_obj_t *obj, const char *resolved, const char *algo,
    char *resp, size_t resp_sz);

ngx_int_t brix_query_cksum_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

#endif /* BRIX_CHECKSUM_QCKSUM_INTERNAL_H */
