#ifndef XROOTD_QUERY_INTERNAL_H
#define XROOTD_QUERY_INTERNAL_H

#include "../ngx_xrootd_module.h"
#include "../compat/checksum.h"

#define XROOTD_CKSCAN_INIT_CAP  (256 * 1024)

/* Maximum number of file paths collected per kXR_prepare staging request and
 * forwarded to xrootd_prepare_command.  Caps pool allocation in
 * xrootd_handle_prepare() and argv length in xrootd_prepare_invoke_command(). */
#define XROOTD_PREPARE_CMD_MAX_PATHS  512

uint32_t xrootd_query_adler32_fd(int fd, const char *path, ngx_log_t *log);
uint32_t xrootd_query_crc32_fd(int fd, const char *path, ngx_log_t *log);
uint32_t xrootd_query_crc32_file(const ngx_str_t *root, const char *path,
    ngx_log_t *log);

typedef struct {
    xrootd_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_xrootd_srv_conf_t  *conf;
    char                           root_resolved[PATH_MAX];
    char                           scan_resolved[PATH_MAX];
    char                           scan_logical[XROOTD_MAX_PATH + 1];
    char                           algo[32];
    ngx_uint_t                     max_depth;
    ngx_uint_t                     max_files;
    u_char                         streamid[2];

    u_char                        *resp;
    size_t                         resp_len;
    int                            error_code;
    char                           error_msg[128];
} xrootd_ckscan_aio_t;

/*
 * xrootd_cksum_aio_t — async kXR_Qcksum context.
 *
 * For path-based requests, fd is opened on the main thread after all auth
 * checks pass and close_fd=1 so the done callback closes it.
 * For handle-based requests, fd is the session-owned descriptor and
 * close_fd=0 (the session keeps ownership).
 */
typedef struct {
    xrootd_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_xrootd_srv_conf_t  *conf;
    u_char  streamid[2];
    int     fd;
    int     close_fd;        /* 1 = we opened fd (path-based); must close in done */
    char    algo[32];
    char    resolved[PATH_MAX];  /* for logging */
    char    resp[256];           /* filled by thread on success */
    int     error_code;          /* 0 = success, else kXR_* error code */
    char    error_msg[128];
} xrootd_cksum_aio_t;

/* kXR_Qcksum async functions — defined in checksum_qcksum_async.c */
void xrootd_cksum_aio_thread(void *data, ngx_log_t *log);
void xrootd_cksum_aio_done(ngx_event_t *ev);

/* Checksum scan helpers shared across checksum_ckscan_*.c fragments. */
int xrootd_ckscan_append(u_char **buf, size_t *cap, size_t *used,
    const char *algo, uint32_t cksum, const char *logical);
int xrootd_ckscan_walk(ngx_log_t *log, const char *root_resolved,
    const char *resolved_dir, const char *logical_dir, const char *algo,
    u_char **buf, size_t *cap, size_t *used, ngx_uint_t depth,
    ngx_uint_t max_depth, ngx_uint_t max_files, ngx_uint_t *nfiles,
    char *errmsg, size_t errsz);
uint32_t xrootd_query_adler32_file(const ngx_str_t *root,
    const char *path, ngx_log_t *log);
ngx_flag_t xrootd_query_digest_fd(int fd, const char *path,
    xrootd_checksum_alg_t alg,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);
ngx_flag_t xrootd_query_digest_file(const ngx_str_t *root,
    const char *path, xrootd_checksum_alg_t alg,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);

ngx_int_t xrootd_query_cksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ClientQueryRequest *req);
ngx_int_t xrootd_query_ckscan(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_space(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_fsinfo(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_config(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_stats(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_xattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_finfo(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_visa(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req);
ngx_int_t xrootd_query_opaque(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_opaquf(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_opaqug(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req);
ngx_int_t xrootd_query_prep_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_QUERY_INTERNAL_H */

/*
 * query_internal.h — Internal prototypes and shared types for the XRootD
 * kXR_query sub-protocol.
 *
 * WHAT: Central header for all query opcode handlers (Qcksum, Qckscan,
 *       Qspace, Qconfig, QPrep/Qprep_status, metadata ops). Declares the
 *       shared context structs and dispatch-level entry points used by
 *       dispatch.c. Keeps 15+ sub-type prototypes in one place.
 *
 * WHY: query.opcodes span many sub-types; a single internal header avoids
 *       each .c file including multiple separate headers.
 *
 * HOW: Constants defined here (XROOTD_CKSCAN_INIT_CAP,
 *       XROOTD_PREPARE_CMD_MAX_PATHS). AIO structs carry ctx, c, conf,
 *       streamid, and per-op result/error fields. All prototypes match
 *       dispatch.c routing signatures.
 */
