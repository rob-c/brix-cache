/* ---- File: tpc_internal.h — Native TPC source-side pull API and shared types ----
 *
 * WHAT: Defines all shared types, constants, and function declarations for native XRootD third-party-copy (TPC) destination-side pull. Wire constants → TPC_IO_TIMEOUT_SEC(60s), TPC_CONNECT_TIMEOUT_SEC(5s), TPC_CHUNK_SIZE(1MB per kXR_read), TPC_RESP_MAX_BODY(1MB+256 malloc cap); typedef xrootd_tpc_params_t — parsed tpc.* opaque fields (key/src/src_host/src_path/dst/lfn/org/stage/token_mode + has_* flags + src_port); typedef xrootd_tpc_pull_t — per-pull heap-allocated task context containing connection/ctx/conf refs, streamid/options/mode_bits, src info, key/org/delegated_token/token_scope, dst_path/dst_fd/fhandle_idx/reply_kind/result/xrd_error/bytes_written/err_msg; API declarations → xrootd_tpc_parse_opaque(opaque,out) parses opaque into params struct (parse.c); tpc_send_all(fd,buf,len)/tpc_recv_response(fd,status,body,dlen) low-level socket helpers (io.c); tpc_connect(t) DNS+TCP connect with timeout (connect.c); xrootd_tpc_check_src_policy(src_host,port,allow_local,allow_private,err_msg,sz) SSRF preflight; tpc_bootstrap(t,fd) anonymous session setup kXR_protocol+kXR_login (bootstrap.c); tpc_outbound_finish_login/tpc_outbound_gsi/tpc_outbound_ztn/GSI DH helpers for source auth; tpc_pull_from_source(t,fd) remote open+read loop+fsync+close (source.c); xrootd_tpc_pull_thread(data,log) thread-pool orchestrator connect→bootstrap→pull (thread.c); tpc_fetch_delegated_token(t) OAuth2/OIDC token fetch (tpc_token.c); xrootd_tpc_pull_done(ev) main-thread completion callback sends kXR_open response/error (done.c); xrootd_tpc_prepare_pull/launch_pull/start_pull event-thread entry points validate+allocate+post to thread pool (launch.c).
 *
 * WHY: TPC destination-side pull requires a coordinated sequence across multiple files — parsing opaque params, connecting to remote origin, bootstrapping session, streaming reads, completion callback. This header centralizes all shared types so launch.c/thread.c/source.c/connect.c/bootstrap.c/io.c/done.c/tpc_token.c can reference the same structs and function signatures without duplication. Heap-allocated pull_t struct enables ngx_thread_task_post() lifecycle (allocate in event thread → post to pool → free in done callback). Wire constants ensure consistent timeout/chunk sizes across all TPC files.
 *
 * HOW: Constants at top → typedef xrootd_tpc_params_t with opaque field comments → API declaration for parse_opaque → typedef xrootd_tpc_pull_t with heap/lifecycle comments → grouped function declarations by file (io.c helpers, connect.c, bootstrap.c auth helpers, source.c pull, thread.c worker, tpc_token.c fetch, done.c callback, launch.c entry points). Each declaration includes brief WHAT describing behavior and return value. */

#pragma once

#include "../ngx_xrootd_module.h"
#include "key_registry.h"

/* ------------------------------------------------------------------ */
/* Wire-level constants shared by all TPC source files                  */
/* ------------------------------------------------------------------ */

#define TPC_IO_TIMEOUT_SEC      60  /* SO_RCVTIMEO / SO_SNDTIMEO for read/write */
#define TPC_CONNECT_TIMEOUT_SEC  5  /* poll() timeout for non-blocking connect */
#define TPC_CHUNK_SIZE      (1024 * 1024)   /* bytes per kXR_read request */
#define TPC_RESP_MAX_BODY   (TPC_CHUNK_SIZE + 256)  /* malloc cap for recv */

#define XROOTD_TPC_REPLY_OPEN  1
#define XROOTD_TPC_REPLY_SYNC  2

/* ------------------------------------------------------------------ */
/* TPC opaque parameter extraction                                       */
/* ------------------------------------------------------------------ */

/*
 * Parsed tpc.* parameters from an XRootD kXR_open opaque query string.
 *
 * XRootD TPC opaque parameters are appended to the path after '?':
 *   /path/to/file?tpc.src=root://src//path&tpc.key=<token>&tpc.dst=root://dst//path
 *
 * src_host, src_port, src_path are parsed from the tpc.src URL.
 * has_* flags indicate which fields were actually present in the opaque string.
 */
typedef struct {
    char     key[128];          /* tpc.key — authorization token */
    char     src[512];          /* tpc.src raw URL */
    char     src_host[256];     /* hostname parsed from tpc.src */
    char     src_path[PATH_MAX];/* path parsed from tpc.src */
    char     dst[512];          /* tpc.dst raw URL */
    char     lfn[PATH_MAX];     /* tpc.lfn source logical path */
    char     org[256];          /* tpc.org origin identity */
    char     stage[64];         /* tpc.stage, usually "copy" */
    char     token_mode[32];    /* tpc.token_mode: "none", "oidc-agent",
                                    "token-exchange" */
    int      has_src;           /* 1 = tpc.src was present */
    int      has_dst;           /* 1 = tpc.dst was present */
    int      has_key;           /* 1 = tpc.key was present */
    int      has_lfn;           /* 1 = tpc.lfn was present */
    int      has_org;           /* 1 = tpc.org was present */
    int      has_stage;         /* 1 = tpc.stage was present */
    int      has_token_mode;    /* 1 = tpc.token_mode was present */
    uint16_t src_port;          /* TCP port from tpc.src (0 → use 1094) */
} xrootd_tpc_params_t;

/*
 * Parse tpc.* parameters from a raw opaque string (everything after '?' in
 * the open path payload).
 * Returns 0 if at least one tpc.* parameter was found and parsed; -1 if the
 * opaque string is empty or contains no tpc.* parameters.
 */
int xrootd_tpc_parse_opaque(const char *opaque, xrootd_tpc_params_t *out);


/* ------------------------------------------------------------------ */
/* TPC destination-side pull task                                        */
/* ------------------------------------------------------------------ */

/*
 * Per-TPC-pull task context, heap-allocated before ngx_thread_task_post()
 * and freed in xrootd_tpc_pull_done() after the result is consumed.
 *
 * The thread function (xrootd_tpc_pull_thread) connects to the XRootD source
 * server, bootstraps a session (handshake+protocol+login), opens src_path,
 * streams the file content into dst_fd, and closes the source connection.
 */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    u_char    streamid[2];
    uint16_t  options;      /* kXR_retstat etc., from the client's kXR_open */
    uint16_t  mode_bits;    /* permission bits, from the client's kXR_open */
    char      src_host[256];
    uint16_t  src_port;     /* 0 = use default 1094 */
    char      src_path[PATH_MAX];
    char      tpc_key[128]; /* presented to source in ?tpc.key= opaque */
    char      tpc_org[256]; /* presented to source in ?tpc.org= opaque */
    char      token_mode[32]; /* OAuth2/OIDC delegation mode for source auth */
    char      delegated_token[65536]; /* fetched delegated access token */
    char      token_scope[256]; /* scope string for token exchange request */
    char      dst_path[PATH_MAX]; /* local path being written */
    int       dst_fd;       /* open O_RDWR fd on dst_path; caller must close */
    int       fhandle_idx;  /* ctx->files[] slot pre-allocated by launcher */
    int       reply_kind;   /* XROOTD_TPC_REPLY_* controls done callback */
    int       result;       /* NGX_OK on success, NGX_ERROR on failure */
    int       xrd_error;    /* kXR_* error code when result == NGX_ERROR */
    size_t    bytes_written;/* source bytes copied into dst_fd */
    char      err_msg[512]; /* human-readable error detail for logging */
} xrootd_tpc_pull_t;

/*
 * io.c — low-level socket helpers.
 * All three are called by bootstrap.c and source.c; not directly by callers
 * outside the tpc/ directory.
 */
int tpc_send_all(int fd, const void *buf, size_t len);
int tpc_recv_response(int fd, uint16_t *status, u_char **body, uint32_t *dlen);

/*
 * connect.c — DNS resolution and TCP connect.
 * Returns an open, timeout-configured fd on success, or -1 with
 * t->err_msg and t->xrd_error set on failure.
 */
int tpc_connect(xrootd_tpc_pull_t *t);

/*
 * connect.c — optional SSRF preflight before opening the local TPC destination.
 */
int xrootd_tpc_check_src_policy(const char *src_host, uint16_t src_port,
    ngx_flag_t allow_local, ngx_flag_t allow_private,
    char *err_msg, size_t err_msg_sz);

/*
 * bootstrap.c — anonymous XRootD session setup.
 * Sends client hello → kXR_protocol → kXR_login on fd.
 * Returns 0 on success, -1 with t->err_msg set on failure.
 */
int tpc_bootstrap(xrootd_tpc_pull_t *t, int fd);

void tpc_put_u32(u_char *p, uint32_t v);
int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq,
    const u_char *cred, uint32_t len);

/*
 * Complete kXR_login kXR_authmore using ztn and/or GSI credentials from
 * ngx_stream_xrootd_srv_conf_t (bearer file, certificate paths).
 */
int tpc_outbound_finish_login(xrootd_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen);

int tpc_outbound_gsi(xrootd_tpc_pull_t *t, int fd);
int tpc_outbound_gsi_exchange(xrootd_tpc_pull_t *t, int fd,
    u_char *body, uint32_t dlen,
    X509 *x, STACK_OF(X509) *chain, EVP_PKEY *pkey,
    u_char *certreq, BIO *cbio, BIO *kbio);

/*
 * gsi_outbound_common.c — anonymous (ZTN) token outbound auth.
 * Sends a bearer-token kXR_authmore response to the source server.
 */
int tpc_outbound_ztn(xrootd_tpc_pull_t *t, int fd);

/*
 * gsi_outbound_dh_helpers.c — DH key-exchange helpers for GSI outbound auth.
 * tpc_gsi_select_cipher   — pick a cipher from a server-advertised list.
 * tpc_parse_hex_pub       — decode a hex-encoded DH public key blob.
 * tpc_dh_peer_from        — build an EVP_PKEY peer key from local key + BIGNUM.
 */
void tpc_gsi_select_cipher(const u_char *payload, size_t payload_len,
    char *out, size_t outsz);
BIGNUM *tpc_parse_hex_pub(const u_char *puk_data, size_t puk_len);
EVP_PKEY *tpc_dh_peer_from(EVP_PKEY *local_key, BIGNUM *peer_pub_bn);

/*
 * source.c — remote file open, streaming read loop, and close.
 * Opens t->src_path on fd (appending ?tpc.key= if set), reads all data
 * into t->dst_fd in TPC_CHUNK_SIZE chunks, fsyncs, then closes the
 * remote handle.  Sets t->result and t->xrd_error.
 * Returns 0 on success, -1 on failure.
 */
int tpc_pull_from_source(xrootd_tpc_pull_t *t, int fd);

/* thread.c — thread-pool worker: orchestrates connect/bootstrap/pull. */
void xrootd_tpc_pull_thread(void *data, ngx_log_t *log);

/* tpc_token.c — OAuth2/OIDC token fetching for TPC source auth. */
int tpc_fetch_delegated_token(xrootd_tpc_pull_t *t);

/* done.c — main-thread completion callback: sends kXR_open response or error. */
void xrootd_tpc_pull_done(ngx_event_t *ev);

/*
 * launch.c — nginx event-thread entry points.
 */
ngx_int_t xrootd_tpc_prepare_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

ngx_int_t xrootd_tpc_start_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int fhandle_idx);

ngx_int_t xrootd_tpc_launch_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

