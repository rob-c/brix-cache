/* ---- File: tpc_internal.h — Native TPC source-side pull API and shared types ----
 *
 * PURPOSE:
 *   Centralizes all shared types, constants, and function declarations for
 *   native XRootD third-party-copy (TPC) destination-side pull.
 *
 * KEY DESIGN DECISIONS:
 * 1. Heap-allocated brix_tpc_pull_t enables ngx_thread_task_post() lifecycle:
 *    - Allocate in event thread
 *    - Post to thread pool for blocking I/O
 *    - Free in done callback
 * 2. Wire constants ensure consistent timeout/chunk sizes across all TPC files
 * 3. Cached-only SSRF preflight (brix_tpc_check_src_policy) prevents blocking
 *    DNS during open — async resolve parks pull if cache miss
 * 4. Open resolution honors kXR_wait/kXR_waitresp with bounded retries:
 *    - TPC_OPEN_RESOLVE_MAX_SEC: 120s total wall-clock cap
 *    - TPC_OPEN_WAIT_CAP_SEC: 15s per-recv idle timeout
 *    - TPC_OPEN_WAIT_RETRY_SEC: 1s sleep before RESEND (sub-second to catch grant window)
 *    - TPC_OPEN_RESOLVE_MAX_ITERS: 16 max wait/waitresp/attn rounds
 *
 * CONSTANTS (wire-level, shared by all TPC source files):
 *   - BRIX_TPC_IO_TIMEOUT_SEC: 60s (SO_RCVTIMEO/SO_SNDTIMEO)
 *   - BRIX_TPC_CONNECT_TIMEOUT_SEC: 5s (poll timeout for non-blocking connect)
 *   - TPC_CHUNK_SIZE: 1MB (bytes per kXR_read request)
 *   - TPC_RESP_MAX_BODY: 1MB+256 (malloc cap for recv)
 *   - TPC_HOPS_DEFAULT: 4 (brix_tpc_max_hops default)
 *   - TPC_REDIR_OPAQUE_LEN: 1024 (replayed cap.sym/cap.msg budget)
 *
 * TYPES:
 *   brix_tpc_params_t — Parsed tpc.* opaque fields:
 *     - key, src, src_host, src_path, src_port
 *     - dst, dst_host, dst_path (F16 push)
 *     - lfn, dlfn (F16 push), org, stage, token_mode
 *     - has_* flags for presence detection
 *     - str (parallel read streams, F7)
 *
 *   brix_tpc_pull_t — Per-pull heap-allocated task context:
 *     - connection/ctx/conf refs
 *     - streamid, options, mode_bits
 *     - src info, key, org, delegated_token, token_scope
 *     - dst_path, dst_fd, fhandle_idx, reply_kind
 *     - result, xrd_error, bytes_written, err_msg
 *
 * API (grouped by implementation file):
 *   parse.c:      brix_tpc_parse_opaque(opaque, out)
 *   io.c:         tpc_send_all(), tpc_recv_response()
 *   connect.c:    tpc_connect(t) — DNS+TCP with timeout
 *   policy:       brix_tpc_check_src_policy() — cached SSRF preflight
 *   bootstrap.c:  tpc_bootstrap(t, fd) — kXR_protocol+kXR_login
 *   auth:         tpc_outbound_finish_login/gsi/ztn, GSI DH helpers
 *   source.c:     tpc_pull_from_source(t, fd) — open+read+fsync+close
 *   thread.c:     brix_tpc_pull_thread(data, log) — pool orchestrator
 *   tpc_token.c:  tpc_fetch_delegated_token(t) — OAuth2/OIDC fetch
 *   done.c:       brix_tpc_pull_done(ev) — main-thread completion callback
 *   launch.c:     brix_tpc_prepare_pull/launch_pull/start_pull — entry points
 */

#ifndef BRIX_TPC_TPC_INTERNAL_H
#define BRIX_TPC_TPC_INTERNAL_H

#include "core/ngx_brix_module.h"
#include "key_registry.h"
#include "tpc/common/auth.h"
#include "tpc/common/credential.h"
#include "tpc/common/registry.h"
#include "tpc/common/metrics.h"
#include "fs/vfs/vfs.h"
#include "tpc/outbound/stream_plan.h"   /* TPC_STREAMS_MAX, read_args (F7) */

/* ------------------------------------------------------------------ */
/* Wire-level constants shared by all TPC source files                  */
/* ------------------------------------------------------------------ */

/* Timeout constants now in src/core/types/tunables.h:
 *   - BRIX_BRIX_TPC_IO_TIMEOUT_SEC: 60s (SO_RCVTIMEO/SO_SNDTIMEO)
 *   - BRIX_BRIX_TPC_CONNECT_TIMEOUT_SEC: 5s (poll timeout for connect)
 */
#define TPC_CHUNK_SIZE      (1024 * 1024)   /* bytes per kXR_read request */
#define TPC_RESP_MAX_BODY   (TPC_CHUNK_SIZE + 256)  /* malloc cap for recv */

/* TPC port and buffer constants */
#define TPC_DEFAULT_PORT         1094   /* Default XRootD port */
#define TPC_TIMESTAMP_BUF_SIZE   64     /* ISO-8601 timestamp buffer */

/* Async kXR_open resolution (phase-57 §F8): a real source (EOS/dCache, or any
 * server still completing the TPC rendezvous) may answer the open with kXR_wait
 * (retry-after) or kXR_waitresp (a deferred kXR_attn asynresp will follow) before
 * it settles. tpc_open_resolve() honours that flow, bounded on every axis so a
 * source that never resolves fails cleanly instead of hanging the pull thread. */
#define TPC_OPEN_RESOLVE_MAX_SEC   120  /* total wall-clock cap for the negotiation */
#define TPC_OPEN_WAIT_CAP_SEC       15  /* clamp the per-recv idle timeout during open
                                         * resolution, so a silent (no-attn) source
                                         * fails fast enough for the client's --tpc
                                         * fallback to run */
#define TPC_OPEN_WAIT_RETRY_SEC      1  /* how long to sleep before RESENDing an open
                                         * after a kXR_wait. A real xrootd source can
                                         * request a multi-second wait while the TPC
                                         * grant is only briefly visible to our racing
                                         * dest-open; sleeping the server's full hint
                                         * (up to CAP_SEC) misses the window and the
                                         * grant lapses ("tpc authorization expired").
                                         * Stock XrdCl re-polls sub-second, so cap our
                                         * retry sleep here (MAX_ITERS/MAX_SEC still
                                         * bound the total) and re-poll while valid. */
#define TPC_OPEN_RESOLVE_MAX_ITERS  16  /* max wait/waitresp/attn rounds */

#define BRIX_TPC_REPLY_OPEN  1
#define BRIX_TPC_REPLY_SYNC  2

/* F7 multihop / multi-stream: defaults and the redirect-follow return code. */
#define TPC_HOPS_DEFAULT      4     /* brix_tpc_max_hops default */
#define TPC_REDIR_OPAQUE_LEN  1024  /* replayed cap.sym/cap.msg budget */
#define TPC_PULL_REDIRECT     1     /* tpc_pull_from_source(): the source
                                     * answered kXR_redirect; t->redir_* is
                                     * filled, the leg must be re-run */

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
    char     dst_host[256];     /* hostname parsed from tpc.dst (F16 push) */
    char     dst_path[PATH_MAX];/* path parsed from tpc.dst, or tpc.dlfn */
    char     lfn[PATH_MAX];     /* tpc.lfn source logical path */
    char     dlfn[PATH_MAX];    /* tpc.dlfn destination logical path (F16 push) */
    char     org[256];          /* tpc.org origin identity */
    char     stage[64];         /* tpc.stage, usually "copy" */
    char     token_mode[32];    /* tpc.token_mode: "none", "passthrough",
                                    "oidc-agent", "token-exchange" */
    int      has_src;           /* 1 = tpc.src was present */
    int      has_dst;           /* 1 = tpc.dst was present */
    int      has_key;           /* 1 = tpc.key was present */
    int      has_lfn;           /* 1 = tpc.lfn was present */
    int      has_dlfn;          /* 1 = tpc.dlfn was present (F16 push) */
    int      has_org;           /* 1 = tpc.org was present */
    int      has_stage;         /* 1 = tpc.stage was present */
    int      has_token_mode;    /* 1 = tpc.token_mode was present */
    char     str[8];            /* tpc.str: parallel read streams the client
                                   wishes for (F7); clamped by brix_tpc_streams */
    int      has_str;           /* 1 = tpc.str was present */
    uint16_t src_port;          /* TCP port from tpc.src (0 → use 1094) */
    uint16_t dst_port;          /* TCP port from tpc.dst (0 → use 1094), F16 */
} brix_tpc_params_t;

/*
 * F16: 1 when the opaque carries tpc.stage=push — the BriX push dialect, in
 * which the SOURCE dials the destination and writes, instead of the
 * destination dialing the source and reading. Both legs of a push carry it,
 * which is what separates them from the pull rendezvous over the same keys.
 */
int brix_tpc_stage_is_push(const brix_tpc_params_t *tpc);

/*
 * Parse tpc.* parameters from a raw opaque string (everything after '?' in
 * the open path payload).
 * Returns 0 if at least one tpc.* parameter was found and parsed; -1 if the
 * opaque string is empty or contains no tpc.* parameters.
 */
int brix_tpc_parse_opaque(const char *opaque, brix_tpc_params_t *out);


/* ------------------------------------------------------------------ */
/* TPC destination-side pull task                                        */
/* ------------------------------------------------------------------ */

/*
 * Per-TPC-pull task context, heap-allocated before ngx_thread_task_post()
 * and freed in brix_tpc_pull_done() after the result is consumed.
 *
 * The thread function (brix_tpc_pull_thread) connects to the XRootD source
 * server, bootstraps a session (handshake+protocol+login), opens src_path,
 * streams the file content into dst_fd, and closes the source connection.
 */
/* F7: one bound secondary socket toward the source (kXR_bind pathid). */
typedef struct {
    int     fd;
    void   *tls;        /* SSL*      — set when the sub-stream upgraded */
    void   *tls_ctx;    /* SSL_CTX*  — owned per sub-stream */
    u_char  pathid;     /* the source's path id for this socket (1..253) */
} tpc_substream_t;

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    ngx_stream_brix_srv_conf_t  *conf;
    u_char    streamid[2];
    uint16_t  options;      /* kXR_retstat etc., from the client's kXR_open */
    uint16_t  mode_bits;    /* permission bits, from the client's kXR_open */
    char      src_host[256];
    uint16_t  src_port;     /* 0 = use default 1094 */
    char      src_path[PATH_MAX];
    char      tpc_key[128]; /* presented to source in ?tpc.key= opaque */
    char      tpc_org[256]; /* presented to source in ?tpc.org= opaque */
    char      token_mode[32]; /* source-auth token mode: none/passthrough (strict)/
                               * passthrough-opt (default, opportunistic)/
                               * oidc-agent/token-exchange */
    char      delegated_token[BRIX_TPC_TOKEN_MAX]; /* delegated/forwarded access token: fetched
                                       * (oidc-agent/token-exchange), read from the
                                       * bearer file, or — for "passthrough" — the
                                       * client's own inbound bearer JWT captured on
                                       * the event loop (launch.c) */
    char      token_scope[256]; /* scope string for token exchange request */
    uint8_t   gsi_rtag[8];  /* GSI round-1 random tag (sent in certreq) */
    char      dst_path[PATH_MAX]; /* local path being written */
    int       dst_fd;       /* open O_RDWR fd on dst_path; caller must close */
    brix_sd_obj_t dst_obj;  /* copied backend object for worker I/O */
    brix_vfs_writer_t *dst_writer; /* backend-neutral whole-object destination */
    int       fhandle_idx;  /* ctx->files[] slot pre-allocated by launcher */
    int       reply_kind;   /* BRIX_TPC_REPLY_* controls done callback */
    int       result;       /* NGX_OK on success, NGX_ERROR on failure */
    int       xrd_error;    /* kXR_* error code when result == NGX_ERROR */
    uint64_t  transfer_id;  /* shared TPC registry entry, 0 if unavailable */
    brix_sess_t *sess;      /* outbound lifecycle audit session */
    brix_sess_xfer_t sess_xfer; /* source-side transfer audit record */
    size_t    bytes_written;/* source bytes copied into dst_fd */
    struct stat dst_stat;   /* final destination metadata for completion reply */
    unsigned   dst_stat_valid:1;
    uint64_t  src_size;     /* authoritative source size from kXR_stat, when known;
                             * the pull's completion signal (bytes_written must
                             * match it) instead of the forgeable zero-byte-read EOF */
    int       src_size_known; /* 1 = src_size was obtained from the source's stat */
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
    struct sockaddr_storage peer_ss; /* the client's peer address (origin_id.c) */
    socklen_t  peer_len;        /* 0 = unknown: no tpc.org rebuild on the thread */
    char       org_user[9];     /* kXR_login user, "xrd" when empty */
    uint32_t   org_pid;         /* kXR_login pid, ngx_pid when 0 */
    unsigned   tpc_org_unresolved:1; /* tpc_org holds the numeric fallback: the
                                      * pull thread finishes the PTR first */
    time_t     cred_expires_at;   /* `exp` of the delegated credential this
                                   * pull presented, 0 = unknown (W8.2) */
    time_t     cred_renew_next_try; /* no mint attempt before this instant  */
    ngx_uint_t cred_renewals;     /* successful mid-transfer renewals       */
    unsigned   cred_presented:1;  /* the source accepted a ztn credential   */
    unsigned   cred_renew_off:1;  /* renewing cannot help this transfer     */

    /* F7 multihop: the kXR_redirect target the last leg handed us. Only
     * tpc_redirect_follow() promotes it into src_host/src_port, after the
     * hop budget, self-loop and egress-policy gates. */
    char       redir_host[256];
    uint16_t   redir_port;
    char       redir_opaque[TPC_REDIR_OPAQUE_LEN]; /* cap.sym/cap.msg replay */
    ngx_uint_t hops;               /* redirects followed so far            */
    unsigned   redirect_pending:1; /* redir_* filled, not yet followed     */
    unsigned   redirect_refused:1; /* a hop failed the egress guard        */

    /*
     * F16 push. When is_push is set this task moves bytes the other way: the
     * local file (dst_path / dst_fd / dst_obj, opened READ-ONLY here) is
     * written to the remote peer at src_host:src_port under push_lfn. The
     * remote-peer fields keep their names so connect.c's egress guard and
     * per-address SSRF recheck cover a push exactly as they cover a pull —
     * there is one dial path, and it is guarded once.
     */
    unsigned   is_push:1;
    char       push_lfn[PATH_MAX];  /* remote destination path to write */
    uint64_t   push_size;           /* local file size: the completion signal */

    /* F7 multi-stream: the login session id (needed by kXR_bind) and the
     * secondary sockets bound to it. nsub <= streams_requested - 1. */
    u_char     sessid[BRIX_SESSION_ID_LEN];
    unsigned   sessid_known:1;
    int        streams_requested;  /* clamped tpc.str wish, >= 1          */
    tpc_substream_t sub[TPC_SUBSTREAMS_MAX];
    int        nsub;               /* sub-streams actually bound           */
} brix_tpc_pull_t;

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
int tpc_send_all(brix_tpc_pull_t *t, int fd, const void *buf, size_t len);
/*
 * Read one XRootD ServerResponseHdr frame plus its payload from fd.
 * On success returns 0 and sets *status (host order kXR_* code) and *dlen; *body
 * is a malloc'd, NUL-terminated copy of the payload that the caller must free()
 * (NULL when *dlen == 0). dlen is rejected if it exceeds TPC_RESP_MAX_BODY.
 * Returns -1 on I/O, framing, oversize, or allocation failure (nothing to free).
 */
int tpc_recv_response(brix_tpc_pull_t *t, int fd, uint16_t *status,
                      u_char **body, uint32_t *dlen);
/*
 * As tpc_recv_response, additionally copying the frame's streamid out when
 * `streamid` is non-NULL — the multi-stream loop demultiplexes replies by it
 * (F7). fd may be the primary or any bound sub-stream socket.
 */
int tpc_recv_response_sid(brix_tpc_pull_t *t, int fd, u_char streamid[2],
                          uint16_t *status, u_char **body, uint32_t *dlen);
/*
 * Bytes already decrypted and buffered inside fd's TLS session (0 on a
 * cleartext socket). poll() cannot see them, so the multi-stream drain asks
 * here before it blocks (F7).
 */
int tpc_io_pending(brix_tpc_pull_t *t, int fd);

/*
 * tls.c — TPC pull in-protocol TLS upgrade (kXR_gotoTLS). tpc_start_tls performs a
 * blocking client SSL handshake over the connected pull fd (thread-pool context),
 * storing the SSL on t->tls so the I/O helpers route through it; tpc_tls_teardown
 * frees the SSL + per-pull SSL_CTX. (phase-57 §F5)
 */
int  tpc_start_tls(brix_tpc_pull_t *t, int fd);
void tpc_tls_teardown(brix_tpc_pull_t *t);
/* Release the TLS objects of one bound sub-stream socket (or the primary when
 * fd is not a sub-stream); NULL-safe, used by substreams.c (F7). */
void tpc_tls_teardown_fd(brix_tpc_pull_t *t, int fd);

/*
 * connect.c — DNS resolution and TCP connect.
 * Returns an open, timeout-configured fd on success, or -1 with
 * t->err_msg and t->xrd_error set on failure.
 */
int tpc_connect(brix_tpc_pull_t *t);

/*
 * connect.c — event-loop SSRF preflight before opening the local TPC
 * destination.  Host+port wrapper over brix_net_target_check_cached() under
 * conf's tpc_allow_local/tpc_allow_private and brix_resolver policy; port 0
 * defaults to 1094.  Never resolves.  Returns 0 if every cached address is
 * permitted, -1 (err_msg filled, up to err_msg_sz) if the host is missing,
 * definitively unknown or blocked, and 1 when no answer is cached yet.
 */
int brix_tpc_check_src_policy(const ngx_stream_brix_srv_conf_t *conf,
    const char *src_host, uint16_t src_port, char *err_msg, size_t err_msg_sz);

/*
 * bootstrap.c — anonymous XRootD session setup.
 * Sends client hello → kXR_protocol → kXR_login on fd.
 * Returns 0 on success, -1 with t->err_msg set on failure.
 */
int tpc_bootstrap(brix_tpc_pull_t *t, int fd);
/* Transport half of tpc_bootstrap (handshake + kXR_protocol + optional TLS
 * upgrade), no login: a kXR_bind sub-stream joins the primary's session by
 * session id and must not log in again (F7). */
int tpc_bootstrap_transport(brix_tpc_pull_t *t, int fd);

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
int tpc_send_kxr_auth(brix_tpc_pull_t *t, int fd, u_char seq,
    const u_char *cred, uint32_t len);

/*
 * Complete a kXR_login kXR_authmore using ztn and/or GSI credentials from
 * ngx_stream_brix_srv_conf_t (bearer file, certificate paths). login_body is
 * the borrowed authmore payload (login_dlen bytes); the auth-method list is read
 * from it after the session id. When the server offers both, ZTN is tried first
 * and falls through to GSI only if the server also lists gsi and a cert is
 * configured (so an expired token recovers instead of failing silently).
 * Returns 0 once authenticated, -1 with t->err_msg/t->xrd_error set on failure.
 */
int tpc_outbound_finish_login(brix_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen);

/*
 * GSI handshake round 1: load the local cert chain + key, send a kXGC_certreq
 * kXR_auth frame on fd, and require a kXR_authmore reply (>= 16 bytes). All
 * locally allocated OpenSSL objects are freed before return. Returns 0 when the
 * server is mid-handshake (caller proceeds to tpc_outbound_gsi_exchange), or -1
 * with t->err_msg and t->xrd_error set (kXR_AuthFailed on a wrong/short reply).
 */
int tpc_outbound_gsi(brix_tpc_pull_t *t, int fd,
    const u_char *login_body, uint32_t login_dlen);
/*
 * GSI handshake round 2: perform the DH key exchange, optionally verify the
 * server leaf cert against conf->gsi_store (proxy certs allowed; absent cert is
 * not fatal), send the encrypted client cert, and require a kXR_ok reply. body
 * is the borrowed kXR_authmore payload from round 1 (dlen bytes); x/chain/pkey/
 * certreq/cbio/kbio are the round-1 cert material it reuses. Returns 0 on
 * success, -1 with t->err_msg and t->xrd_error set on failure.
 */
int tpc_outbound_gsi_exchange(brix_tpc_pull_t *t, int fd,
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
int tpc_outbound_ztn(brix_tpc_pull_t *t, int fd);
/* The same ztn kXR_auth at an explicit handshake sequence. tpc_outbound_ztn()
 * is the seq-3 wrapper (first auth after bootstrap); mid-transfer renewal
 * passes 4 so a packet capture can tell the two apart. */
int tpc_outbound_ztn_seq(brix_tpc_pull_t *t, int fd, int seq);

/* tpc_token_renew.c — mid-transfer delegated-credential renewal (W8.2).
 * tpc_cred_note_expiry() records the lifetime of the credential the session
 * presented; tpc_cred_renew_if_due() is sampled once per streamed chunk and
 * returns 0 to continue, -1 to fail the pull with err_msg/xrd_error set. */
void tpc_cred_note_expiry(brix_tpc_pull_t *t);
int tpc_cred_renew_if_due(brix_tpc_pull_t *t, int fd);

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
int tpc_pull_from_source(brix_tpc_pull_t *t, int fd);

/*
 * push.c — F16 native push. Opens t->push_lfn on the remote destination for
 * write (opaque ?tpc.key=&tpc.org=&tpc.stage=push), streams the local file out
 * over the primary plus every bound sub-stream, then syncs and closes the
 * remote handle. Sets t->result/t->xrd_error/t->bytes_written exactly as the
 * pull does. Returns 0 on success, -1 on failure.
 */
int tpc_push_to_dest(brix_tpc_pull_t *t, int fd);

/*
 * push_stream.c — the write loop behind tpc_push_to_dest: one round of
 * `nstreams` windowed kXR_write frames per pass (the primary carries slot 0,
 * each bound sub-stream carries its own whole write), advancing until the
 * local file is exhausted. `fhandle` is the remote handle from the push open.
 * Returns 0 with t->bytes_written set, -1 with t->err_msg/t->xrd_error set.
 */
int tpc_push_stream(brix_tpc_pull_t *t, int fd, const u_char *fhandle);

/*
 * redirect.c — F7 multihop. tpc_redirect_note() decodes a kXR_redirect reply
 * body into t->redir_* (0, or -1 with err_msg/xrd_error set; a malformed body
 * or invalid port is a hard failure). tpc_redirect_follow() promotes the
 * pending target into src_host/src_port once it passes the hop budget
 * (brix_tpc_max_hops), the self-loop check and the egress guard
 * (brix_tpc_source_guard/allow) — a refused hop sets t->redirect_refused so
 * done.c can count it against tpc_egress_refused_total. Returns 0 to re-run
 * the leg, -1 to fail the pull.
 */
int tpc_redirect_note(brix_tpc_pull_t *t, const u_char *body, uint32_t dlen);
int tpc_redirect_follow(brix_tpc_pull_t *t, ngx_log_t *log);

/*
 * substreams.c — F7 multi-stream. tpc_substreams_open() connects, transports
 * and kXR_binds up to streams_requested-1 secondary sockets to the primary's
 * session; every failure degrades to fewer streams (never fails the pull) and
 * is logged once. tpc_substreams_close() releases them all (idempotent).
 */
int  tpc_substreams_open(brix_tpc_pull_t *t, ngx_log_t *log);
void tpc_substreams_close(brix_tpc_pull_t *t);

/* thread.c — thread-pool worker (ngx_thread_task) orchestrating connect →
 * bootstrap → pull → close. data is the brix_tpc_pull_t (borrowed; not freed
 * here). Runs off the event loop and may block. Communicates only via the task
 * struct: sets t->result/t->xrd_error/t->bytes_written and advances the shared
 * TPC registry state (ACTIVE→DONE/ERROR); always closes its own source fd. */
void brix_tpc_pull_thread(void *data, ngx_log_t *log);

/* tpc_token.c — resolve the outbound source-auth token per t->token_mode and
 * store it in t->delegated_token. "none"/empty is a no-op; "passthrough"
 * validates the client's inbound bearer JWT already captured into
 * t->delegated_token (launch.c) and denies cleanly when absent; "oidc-agent"/
 * "token-exchange" fetch a delegated token. Returns 0 on success (or no-op), -1
 * with t->err_msg/t->xrd_error set (unknown mode, missing passthrough token,
 * token_endpoint unconfigured for token-exchange, or backend fetch/validation
 * failure). */
int tpc_fetch_delegated_token(brix_tpc_pull_t *t);

/* done.c — main-thread completion callback posted by the thread pool (ev->data
 * is the ngx_thread_task_t; pull state is task->ctx). Restores the deferred
 * kXR_open/kXR_sync request and sends the kXR_open/kXR_sync response or error,
 * then resumes the connection. If the client vanished mid-pull it instead
 * releases everything (source fd, dst fd, partial file via unlink, fhandle slot,
 * registry entry). The pull task itself is c->pool-allocated, so it is reclaimed
 * with the connection rather than freed here; runs no blocking I/O. */
void brix_tpc_pull_done(ngx_event_t *ev);

/*
 * launch.c — nginx event-thread entry points.
 */
/*
 * A queued response is not a return value. brix_send_error() returns NGX_OK once
 * the kXR_error is on the wire, so a function that ends `return
 * brix_send_error(...)` reports SUCCESS to whoever called it. At a protocol entry
 * point that is exactly right: NGX_OK there means "request handled" and nothing
 * runs afterwards. One call deep it is a gate bypass — the caller reads NGX_OK as
 * "the check passed, carry on" and carries on past a refusal it has already
 * answered, allocating the handle and queueing a second, contradictory response.
 * The TPC prepare path therefore says TPC_ANSWERED — "refused, and the client has
 * been told" — and only brix_tpc_prepare_pull, the entry point where the
 * distinction stops mattering, folds it back into the wire contract's NGX_OK.
 */
#define TPC_ANSWERED  NGX_DONE

/* Log, count and answer one refusal on the TPC prepare path. Returns
 * TPC_ANSWERED once the kXR_error is queued, NGX_ERROR if it could not be. */
ngx_int_t brix_tpc_refuse(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *dst_path, uint16_t code, const char *msg);

/*
 * Open the destination of a pull through the identity-bound VFS and classify it:
 * a random-write handle when the selected storage leaf supports pwrite, a staged
 * whole-object writer otherwise. Fills file->fd/writer/sd_obj and *st. Returns
 * NGX_OK, TPC_ANSWERED when the failure was answered on the wire (the fhandle at
 * idx is freed by then), or NGX_ERROR. Defined in launch_dest.c.
 */
ngx_int_t brix_tpc_open_destination(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *dst_path,
    uint16_t options, uint16_t mode_bits, int idx,
    brix_file_t *file, struct stat *st);

/*
 * Handle the kXR_open leg of a TPC pull: require a configured thread pool,
 * validate the source, apply the SSRF source-policy gate, allocate an fhandle,
 * open the confined destination (dst_path is the root_canon-prefixed absolute
 * path used for authz/logging; it is stripped to the logical path before the
 * confined open), populate ctx->files[idx] metadata, and send the kXR_open
 * response. options/mode_bits come from the client's kXR_open. Returns NGX_OK,
 * or the result of the error response it sends (open is deferred until kXR_sync).
 */
ngx_int_t brix_tpc_prepare_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

/*
 * The prepare pipeline after the source verdict is in (launch_prepare.c):
 * fhandle → confined destination open → ctx->files[idx] metadata → kXR_open
 * response.  Entered by brix_tpc_prepare_pull when the verdict was cached, or
 * by launch_dns.c when it arrived asynchronously.  NGX_OK (answered) / NGX_ERROR.
 */
ngx_int_t brix_tpc_prepare_pull_resolved(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

/*
 * launch_dns.c — park the kXR_open on an async resolve of the source host when
 * no answer is cached; the completion applies the source policy and either
 * refuses or runs brix_tpc_prepare_pull_resolved.  Returns TPC_ANSWERED
 * (parked in XRD_ST_AIO, or answered inline) or NGX_ERROR.
 */
ngx_int_t brix_tpc_prepare_park_dns(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

/*
 * origin_id.c — the tpc.org identity "user.pid@host" of this connection's
 * client.  brix_tpc_origin_build: event loop; cached PTR or the numeric
 * fallback XrdNetAddr prints; returns 1 when the PTR is still pending (a fill
 * was started).  brix_tpc_origin_snapshot_peer: copy what the thread needs.
 * brix_tpc_origin_thread_fill: pull thread; finish a pending PTR through the
 * DNS driver (blocking, off-loop) and rebuild t->tpc_org.
 */
struct brix_dns_policy_s;
unsigned brix_tpc_origin_build(brix_ctx_t *ctx, ngx_connection_t *c,
    const struct brix_dns_policy_s *policy, char *dst, size_t dst_size);
void brix_tpc_origin_snapshot_peer(brix_tpc_pull_t *t, const brix_ctx_t *ctx,
    const ngx_connection_t *c);
void brix_tpc_origin_thread_fill(brix_tpc_pull_t *t);

/*
 * Handle the kXR_sync leg: snapshot the prepared fhandle into a heap task and
 * post brix_tpc_pull_thread to the thread pool, parking the connection in
 * XRD_ST_AIO until brix_tpc_pull_done resumes it. Idempotent — a sync arriving
 * while the worker runs returns a kXR_wait instead of posting again. Returns
 * NGX_OK on a committed hand-off, NGX_ERROR, or a sent error (bad handle, full
 * transfer registry, or thread-post failure).
 */
ngx_int_t brix_tpc_start_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int fhandle_idx);

/* Thin wrapper that forwards to brix_tpc_prepare_pull unchanged. */
ngx_int_t brix_tpc_launch_pull(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits);

#include "tpc_push.h"   /* F16: the native push dialect declarations */

#endif /* BRIX_TPC_TPC_INTERNAL_H */
