#ifndef XROOTD_QUERY_INTERNAL_H
#define XROOTD_QUERY_INTERNAL_H

#include "../ngx_xrootd_module.h"
#include "../compat/checksum.h"

#define XROOTD_CKSCAN_INIT_CAP  (256 * 1024)

/* Maximum number of file paths collected per kXR_prepare staging request and
 * forwarded to xrootd_prepare_command.  Caps pool allocation in
 * xrootd_handle_prepare() and argv length in xrootd_prepare_invoke_command(). */
#define XROOTD_PREPARE_CMD_MAX_PATHS  512

/* Adler-32 of an already-open O_RDONLY fd. `path` is for log context only.
 * Returns the checksum, or the sentinel 0xFFFFFFFF on I/O error. */
uint32_t xrootd_query_adler32_fd(int fd, const char *path, ngx_log_t *log);
/* ISO-3309/IEEE-802.3 CRC-32 (not CRC32c) of an open fd. `path` for logs only.
 * Returns the checksum, or 0xFFFFFFFF on I/O error. */
uint32_t xrootd_query_crc32_fd(int fd, const char *path, ngx_log_t *log);
/* CRC-32 by path: confined-open under `root`, compute, close. Borrows root/path.
 * Returns the checksum, or 0xFFFFFFFF on open or I/O failure. */
uint32_t xrootd_query_crc32_file(const ngx_str_t *root, const char *path,
    ngx_log_t *log);

typedef struct {
    xrootd_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_xrootd_srv_conf_t  *conf;
    int                            rootfd;             /* persistent O_PATH rootfd */
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
/* Thread-pool worker: computes the checksum of t->fd into t->resp, or sets
 * t->error_code (kXR_*) + t->error_msg on failure. `data` is xrootd_cksum_aio_t.
 * Runs off the event loop — must NOT touch ctx/c/ngx_pool. */
void xrootd_cksum_aio_thread(void *data, ngx_log_t *log);
/* Main-thread completion callback for the above task. Closes the fd if
 * t->close_fd (path-based), restores the request streamid, sends the response
 * (or error) and resumes the connection. No-op if the client already gone. */
void xrootd_cksum_aio_done(ngx_event_t *ev);

/* Checksum scan helpers shared across checksum_ckscan_*.c fragments. */
/* Append one "algo hex  logical\n" line to the heap buffer *buf, growing it
 * (ngx_alloc, exponential) and updating *cap and *used in place. Runs on a worker
 * thread, so the buffer is raw heap not pool-backed. `hex` is the already-computed
 * lowercase checksum (8 chars for adler32/crc32c, 16 for crc64/crc64nvme) — width
 * is carried in the string so the line format stays algorithm-agnostic. Returns 1
 * on success, 0 if the line is too long to format (skipped), -1 on OOM (caller
 * still owns and must free *buf). */
int xrootd_ckscan_append(u_char **buf, size_t *cap, size_t *used,
    const char *algo, const char *hex, const char *logical);
/* Recursively scan logical_dir under rootfd (export-jailed via open_beneath),
 * appending a checksum line per regular file via xrootd_ckscan_append. depth
 * counts from 0; max_depth==0 means this dir only. *nfiles is the running count,
 * capped at max_files. On hard error writes errmsg (errsz bytes) and returns -1;
 * depth/file caps are non-error stops that return 0. */
int xrootd_ckscan_walk(ngx_log_t *log, int rootfd,
    const char *logical_dir, const char *algo,
    u_char **buf, size_t *cap, size_t *used, ngx_uint_t depth,
    ngx_uint_t max_depth, ngx_uint_t max_files, ngx_uint_t *nfiles,
    char *errmsg, size_t errsz);
/* Adler-32 by path: confined-open under `root`, compute, close. Borrows args.
 * Returns the checksum, or 0xFFFFFFFF on open or I/O failure. */
uint32_t xrootd_query_adler32_file(const ngx_str_t *root,
    const char *path, ngx_log_t *log);
/* OpenSSL EVP digest (md5/sha1/sha256 via `alg`) of an open fd; writes bytes to
 * out[] (>= EVP_MAX_MD_SIZE) and length to *outlen. Returns 1 on success, 0 on
 * error. `path` is for logs only. */
ngx_flag_t xrootd_query_digest_fd(int fd, const char *path,
    xrootd_checksum_alg_t alg,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);
/* EVP digest by path: confined-open under `root`, compute, close. Same out[]/
 * outlen contract as xrootd_query_digest_fd. Returns 1 on success, 0 on error
 * (open or compute). */
ngx_flag_t xrootd_query_digest_file(const ngx_str_t *root,
    const char *path, xrootd_checksum_alg_t alg,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);

/* kXR_Qcksum: single-file checksum by path (full auth chain + confined open) or
 * by open fhandle, chosen on the payload's first byte; default algo adler32, a
 * leading "algo:" overrides. May run async (thread pool) or sync. Sends the wire
 * response itself; returns NGX_OK/NGX_DONE on completion or NGX_ERROR. */
ngx_int_t xrootd_query_cksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrdw_query_req_t *req);
/* kXR_Qckscan: recursive directory checksum scan after auth (READ) on the path.
 * Posts a thread-pool task when configured (returns NGX_OK), else runs sync.
 * Sends the wire response itself. */
ngx_int_t xrootd_query_ckscan(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_Qspace (3015): filesystem capacity as "oss.*" key-value text from statvfs
 * on conf root. Sends response (kXR_IOError on statvfs failure); returns NGX_OK. */
ngx_int_t xrootd_query_space(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_QFSinfo (3017): capacity in the compact "wVal freeMB util sVal freeMB util"
 * locate/redirect format (always writable=1, staging=1). Sends response; NGX_OK. */
ngx_int_t xrootd_query_fsinfo(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_Qconfig: best-effort capability report; answers only the whitespace-
 * separated keys present in the payload (chksum/readv/tpc/tpcdlg, else "key=0").
 * Empty query sends an empty OK. Sends response; returns NGX_OK/NGX_ERROR. */
ngx_int_t xrootd_query_config(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_QStats: XML server statistics (connections, bytes, uptime, port) from the
 * metrics struct. Sends response; returns NGX_OK. */
ngx_int_t xrootd_query_stats(xrootd_ctx_t *ctx, ngx_connection_t *c);
/* kXR_Qxattr: extended attributes of a path after auth (READ); returns oss.*
 * stat fields plus user.U.* xattrs. Sends response (kXR_* on stat/arg error). */
ngx_int_t xrootd_query_xattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_QFinfo: placeholder — always sends "0" (XrdOfs plugin not embedded);
 * returns NGX_OK. */
ngx_int_t xrootd_query_finfo(xrootd_ctx_t *ctx, ngx_connection_t *c);
/* kXR_Qvisa: validates req->fhandle index then replies kXR_Unsupported (fctl not
 * supported). Sends response; returns NGX_OK or the validation error code. */
ngx_int_t xrootd_query_visa(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req);
/* kXR_Qopaque: requires payload, then replies kXR_Unsupported (FSctl). Sends
 * response; returns NGX_OK (kXR_ArgMissing if payload absent). */
ngx_int_t xrootd_query_opaque(xrootd_ctx_t *ctx, ngx_connection_t *c);
/* kXR_Qopaquf: extracts+auths (READ) a path then replies kXR_Unsupported (FSctl).
 * Sends response; returns NGX_OK or the auth/arg error. */
ngx_int_t xrootd_query_opaquf(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_Qopaqug: validates req->fhandle; payload "ofs.tpc cancel" yields kXR_FSError
 * (no such TPC), otherwise kXR_Unsupported (fctl). Sends response; returns NGX_OK
 * or the validation error code. */
ngx_int_t xrootd_query_opaqug(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req);
/* kXR_QPrep status: per-path staging status ("A <path>" available / "M <path>"
 * missing) from inline paths or the ctx-stored prepare list. Empty input sends
 * an empty OK. Sends response; returns NGX_OK (kXR_NoMemory on alloc failure). */
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
