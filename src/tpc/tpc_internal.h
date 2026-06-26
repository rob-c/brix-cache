/* ---- File: tpc_internal.h — Native TPC source-side pull API and shared types ----
 *
 * WHAT: Defines all shared types, constants, and function declarations for native XRootD third-party-copy (TPC) destination-side pull. Wire constants → TPC_IO_TIMEOUT_SEC(60s), TPC_CONNECT_TIMEOUT_SEC(5s), TPC_CHUNK_SIZE(1MB per kXR_read), TPC_RESP_MAX_BODY(1MB+256 malloc cap); typedef xrootd_tpc_params_t — parsed tpc.* opaque fields (key/src/src_host/src_path/dst/lfn/org/stage/token_mode + has_* flags + src_port); typedef xrootd_tpc_pull_t — per-pull heap-allocated task context containing connection/ctx/conf refs, streamid/options/mode_bits, src info, key/org/delegated_token/token_scope, dst_path/dst_fd/fhandle_idx/reply_kind/result/xrd_error/bytes_written/err_msg; API declarations → xrootd_tpc_parse_opaque(opaque,out) parses opaque into params struct (parse.c); tpc_send_all(fd,buf,len)/tpc_recv_response(fd,status,body,dlen) low-level socket helpers (io.c); tpc_connect(t) DNS+TCP connect with timeout (connect.c); xrootd_tpc_check_src_policy(src_host,port,allow_local,allow_private,err_msg,sz) SSRF preflight; tpc_bootstrap(t,fd) anonymous session setup kXR_protocol+kXR_login (bootstrap.c); tpc_outbound_finish_login/tpc_outbound_gsi/tpc_outbound_ztn/GSI DH helpers for source auth; tpc_pull_from_source(t,fd) remote open+read loop+fsync+close (source.c); xrootd_tpc_pull_thread(data,log) thread-pool orchestrator connect→bootstrap→pull (thread.c); tpc_fetch_delegated_token(t) OAuth2/OIDC token fetch (tpc_token.c); xrootd_tpc_pull_done(ev) main-thread completion callback sends kXR_open response/error (done.c); xrootd_tpc_prepare_pull/launch_pull/start_pull event-thread entry points validate+allocate+post to thread pool (launch.c).
 *
 * WHY: TPC destination-side pull requires a coordinated sequence across multiple files — parsing opaque params, connecting to remote origin, bootstrapping session, streaming reads, completion callback. This header centralizes all shared types so launch.c/thread.c/source.c/connect.c/bootstrap.c/io.c/done.c/tpc_token.c can reference the same structs and function signatures without duplication. Heap-allocated pull_t struct enables ngx_thread_task_post() lifecycle (allocate in event thread → post to pool → free in done callback). Wire constants ensure consistent timeout/chunk sizes across all TPC files.
 *
 * HOW: Constants at top → typedef xrootd_tpc_params_t with opaque field comments → API declaration for parse_opaque → typedef xrootd_tpc_pull_t with heap/lifecycle comments → grouped function declarations by file (io.c helpers, connect.c, bootstrap.c auth helpers, source.c pull, thread.c worker, tpc_token.c fetch, done.c callback, launch.c entry points). Each declaration includes brief WHAT describing behavior and return value. */

#ifndef XROOTD_TPC_TPC_INTERNAL_H
#define XROOTD_TPC_TPC_INTERNAL_H

#include "../ngx_xrootd_module.h"
#include "key_registry.h"
#include "common/auth.h"
#include "common/credential.h"
#include "common/registry.h"
#include "common/metrics.h"

/* ------------------------------------------------------------------ */
/* Wire-level constants shared by all TPC source files                  */
/* ------------------------------------------------------------------ */

#define TPC_IO_TIMEOUT_SEC      60  /* SO_RCVTIMEO / SO_SNDTIMEO for read/write */
#define TPC_CONNECT_TIMEOUT_SEC  5  /* poll() timeout for non-blocking connect */
#define TPC_CHUNK_SIZE      (1024 * 1024)   /* bytes per kXR_read request */
#define TPC_RESP_MAX_BODY   (TPC_CHUNK_SIZE + 256)  /* malloc cap for recv */

/* Async kXR_open resolution (phase-57 §F8): a real source (EOS/dCache, or any
 * server still completing the TPC rendezvous) may answer the open with kXR_wait
 * (retry-after) or kXR_waitresp (a deferred kXR_attn asynresp will follow) before
 * it settles. tpc_open_resolve() honours that flow, bounded on every axis so a
 * source that never resolves fails cleanly instead of hanging the pull thread. */
#define TPC_OPEN_RESOLVE_MAX_SEC   120  /* total wall-clock cap for the negotiation */
#define TPC_OPEN_WAIT_CAP_SEC       15  /* clamp a single wait sleep AND the per-recv
                                         * idle timeout during open resolution, so a
                                         * silent (no-attn) source fails fast enough
                                         * for the client's --tpc fallback to run */
#define TPC_OPEN_RESOLVE_MAX_ITERS  16  /* max wait/waitresp/attn rounds */

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
    uint8_t   gsi_rtag[8];  /* GSI round-1 random tag (sent in certreq) */
    char      dst_path[PATH_MAX]; /* local path being written */
    int       dst_fd;       /* open O_RDWR fd on dst_path; caller must close */
    int       fhandle_idx;  /* ctx->files[] slot pre-allocated by launcher */
    int       reply_kind;   /* XROOTD_TPC_REPLY_* controls done callback */
    int       result;       /* NGX_OK on success, NGX_ERROR on failure */
    int       xrd_error;    /* kXR_* error code when result == NGX_ERROR */
    uint64_t  transfer_id;  /* shared TPC registry entry, 0 if unavailable */
    size_t    bytes_written;/* source bytes copied into dst_fd */
    char      err_msg[512]; /* human-readable error detail for logging */
    ngx_uint_t pmark_exp;   /* SciTags experiment id for the outbound flow,    */
    ngx_uint_t pmark_act;   /* and activity id; 0 = not marked (resolved on the */
                            /* event loop in start_pull, applied in connect.c)  */
    void      *tls;         /* SSL* once the pull upgraded to TLS (kXR_gotoTLS), */
                            /* NULL = plaintext. The I/O helpers route through   */
                            /* it transparently. Owned with tls_ctx; freed in    */
                            /* thread.c via tpc_tls_teardown(). (phase-57 §F5)    */
    void      *tls_ctx;     /* SSL_CTX* backing tls (per-pull client ctx), or NULL */
    u_char    *deleg_cred_pem; /* §F6: captured delegated proxy credential (proxy
                               * cert + key + issuer chain, PEM) to authenticate the
                               * pull AS THE USER instead of conf->certificate;
                               * NULL = use the gateway cert. malloc'd; freed in
                               * thread.c. */
    size_t     deleg_cred_len;
} xrootd_tpc_pull_t;

/*
 * io.c — low-level socket helpers.
 * All three are called by bootstrap.c and source.c; not directly by callers
 * outside the tpc/ directory.
 */
/*
 * Send the whole buffer over a blocking fd, looping on partial writes (retries
 * on EINTR). buf is borrowed. Returns 0 once all len bytes are sent, -1 on any
 * other send() error; a -1 leaves the socket mid-message (caller must abort).
 */
int tpc_send_all(xrootd_tpc_pull_t *t, int fd, const void *buf, size_t len);
/*
 * Read one XRootD ServerResponseHdr frame plus its payload from fd.
 * On success returns 0 and sets *status (host order kXR_* code) and *dlen; *body
 * is a malloc'd, NUL-terminated copy of the payload that the caller must free()
 * (NULL when *dlen == 0). dlen is rejected if it exceeds TPC_RESP_MAX_BODY.
 * Returns -1 on I/O, framing, oversize, or allocation failure (nothing to free).
 */
int tpc_recv_response(xrootd_tpc_pull_t *t, int fd, uint16_t *status,
                      u_char **body, uint32_t *dlen);

/*
 * tls.c — TPC pull in-protocol TLS upgrade (kXR_gotoTLS). tpc_start_tls performs a
 * blocking client SSL handshake over the connected pull fd (thread-pool context),
 * storing the SSL on t->tls so the I/O helpers route through it; tpc_tls_teardown
 * frees the SSL + per-pull SSL_CTX. (phase-57 §F5)
 */
int  tpc_start_tls(xrootd_tpc_pull_t *t, int fd);
void tpc_tls_teardown(xrootd_tpc_pull_t *t);

/*
 * connect.c — DNS resolution and TCP connect.
 * Returns an open, timeout-configured fd on success, or -1 with
 * t->err_msg and t->xrd_error set on failure.
 */
int tpc_connect(xrootd_tpc_pull_t *t);

/*
 * connect.c — optional SSRF preflight before opening the local TPC destination.
 * Thin host+port wrapper over xrootd_net_target_check_dns(); port 0 defaults to
 * 1094. allow_local/allow_private widen the policy to loopback/RFC1918 targets.
 * Returns 0 if the source is permitted, -1 (with err_msg filled, up to
 * err_msg_sz) if the host is missing or the resolved address is blocked.
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

/* Store v as a big-endian uint32 at p; ngx_memcpy-based, so p may be unaligned
 * (used to fill packed XRootD security-bucket length/tag fields). */
void tpc_put_u32(u_char *p, uint32_t v);
/*
 * Build and send a kXR_auth request frame on fd. seq becomes streamid[1] (echoed
 * by the server's reply); cred is the borrowed payload whose first 4 bytes are
 * the NUL-padded protocol tag ("gsi\0"/"ztn\0", must be >= 4 bytes) copied into
 * the header credtype slot. Returns 0, or -1 with t->err_msg and t->xrd_error
 * set; a -1 leaves the socket mid-message (callers treat it as fatal).
 */
int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq,
    const u_char *cred, uint32_t len);

/*
 * Complete a kXR_login kXR_authmore using ztn and/or GSI credentials from
 * ngx_stream_xrootd_srv_conf_t (bearer file, certificate paths). login_body is
 * the borrowed authmore payload (login_dlen bytes); the auth-method list is read
 * from it after the session id. When the server offers both, ZTN is tried first
 * and falls through to GSI only if the server also lists gsi and a cert is
 * configured (so an expired token recovers instead of failing silently).
 * Returns 0 once authenticated, -1 with t->err_msg/t->xrd_error set on failure.
 */
int tpc_outbound_finish_login(xrootd_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen);

/*
 * GSI handshake round 1: load the local cert chain + key, send a kXGC_certreq
 * kXR_auth frame on fd, and require a kXR_authmore reply (>= 16 bytes). All
 * locally allocated OpenSSL objects are freed before return. Returns 0 when the
 * server is mid-handshake (caller proceeds to tpc_outbound_gsi_exchange), or -1
 * with t->err_msg and t->xrd_error set (kXR_AuthFailed on a wrong/short reply).
 */
int tpc_outbound_gsi(xrootd_tpc_pull_t *t, int fd,
    const u_char *login_body, uint32_t login_dlen);
/*
 * GSI handshake round 2: perform the DH key exchange, optionally verify the
 * server leaf cert against conf->gsi_store (proxy certs allowed; absent cert is
 * not fatal), send the encrypted client cert, and require a kXR_ok reply. body
 * is the borrowed kXR_authmore payload from round 1 (dlen bytes); x/chain/pkey/
 * certreq/cbio/kbio are the round-1 cert material it reuses. Returns 0 on
 * success, -1 with t->err_msg and t->xrd_error set on failure.
 */
int tpc_outbound_gsi_exchange(xrootd_tpc_pull_t *t, int fd,
    u_char *body, uint32_t dlen,
    X509 *x, STACK_OF(X509) *chain, EVP_PKEY *pkey,
    u_char *certreq, BIO *cbio, BIO *kbio);

/*
 * gsi_outbound_common.c — WLCG/ZTN bearer-token outbound auth (kXR_auth, seq 3).
 * Uses t->delegated_token when set, else reads conf->tpc_outbound_bearer_file and
 * caches it back into t->delegated_token. Sends a "ztn"-tagged credential and
 * requires a kXR_ok reply. Returns 0 on success, -1 with t->err_msg/t->xrd_error
 * set (e.g. no token available, send/recv failure, non-ok server status).
 */
int tpc_outbound_ztn(xrootd_tpc_pull_t *t, int fd);

/* (The former gsi_outbound_dh_helpers.c — raw-OpenSSL DH/cipher helpers
 * tpc_gsi_select_cipher / tpc_parse_hex_pub / tpc_dh_peer_from — was removed when
 * tpc_outbound_gsi_exchange migrated onto the shared gsi_core kernel.) */

/*
 * source.c — remote file open, streaming read loop, and close.
 * Opens t->src_path on fd (appending ?tpc.key= if set), reads all data
 * into t->dst_fd in TPC_CHUNK_SIZE chunks, fsyncs, then closes the
 * remote handle.  Sets t->result and t->xrd_error.
 * Returns 0 on success, -1 on failure.
 */
int tpc_pull_from_source(xrootd_tpc_pull_t *t, int fd);

/* thread.c — thread-pool worker (ngx_thread_task) orchestrating connect →
 * bootstrap → pull → close. data is the xrootd_tpc_pull_t (borrowed; not freed
 * here). Runs off the event loop and may block. Communicates only via the task
 * struct: sets t->result/t->xrd_error/t->bytes_written and advances the shared
 * TPC registry state (ACTIVE→DONE/ERROR); always closes its own source fd. */
void xrootd_tpc_pull_thread(void *data, ngx_log_t *log);

/* tpc_token.c — fetch an OAuth2/OIDC delegated token per t->token_mode and store
 * it in t->delegated_token. "none"/empty is a no-op. Returns 0 on success (or
 * no-op), -1 with t->err_msg/t->xrd_error set (unknown mode, token_endpoint
 * unconfigured for token-exchange, or backend fetch/validation failure). */
int tpc_fetch_delegated_token(xrootd_tpc_pull_t *t);

/* done.c — main-thread completion callback posted by the thread pool (ev->data
 * is the ngx_thread_task_t; pull state is task->ctx). Restores the deferred
 * kXR_open/kXR_sync request and sends the kXR_open/kXR_sync response or error,
 * then resumes the connection. If the client vanished mid-pull it instead
 * releases everything (source fd, dst fd, partial file via unlink, fhandle slot,
 * registry entry). The pull task itself is c->pool-allocated, so it is reclaimed
 * with the connection rather than freed here; runs no blocking I/O. */
void xrootd_tpc_pull_done(ngx_event_t *ev);

/*
 * launch.c — nginx event-thread entry points.
 */
/*
 * Handle the kXR_open leg of a TPC pull: require a configured thread pool,
 * validate the source, apply the SSRF source-policy gate, allocate an fhandle,
 * open the confined destination (dst_path is the root_canon-prefixed absolute
 * path used for authz/logging; it is stripped to the logical path before the
 * confined open), populate ctx->files[idx] metadata, and send the kXR_open
 * response. options/mode_bits come from the client's kXR_open. Returns NGX_OK,
 * or the result of the error response it sends (open is deferred until kXR_sync).
 */
ngx_int_t xrootd_tpc_prepare_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

/*
 * Handle the kXR_sync leg: snapshot the prepared fhandle into a heap task and
 * post xrootd_tpc_pull_thread to the thread pool, parking the connection in
 * XRD_ST_AIO until xrootd_tpc_pull_done resumes it. Idempotent — a sync arriving
 * while the worker runs returns a kXR_wait instead of posting again. Returns
 * NGX_OK on a committed hand-off, NGX_ERROR, or a sent error (bad handle, full
 * transfer registry, or thread-post failure).
 */
ngx_int_t xrootd_tpc_start_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int fhandle_idx);

/* Thin wrapper that forwards to xrootd_tpc_prepare_pull unchanged. */
ngx_int_t xrootd_tpc_launch_pull(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const xrootd_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

#endif /* XROOTD_TPC_TPC_INTERNAL_H */
