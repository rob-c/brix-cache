#pragma once

/* ---- File: context.h — Per-connection session context (xrootd_ctx_t) ----
 *
 * WHAT: Defines xrootd_ctx_t — per-TCP-connection session context holding all state for the XRootD protocol lifecycle. Struct sections: input accumulation (hdr_buf[24] + hdr_pos for fixed header read, cur_streamid/cur_reqid/cur_body/cur_dlen for parsed header fields), payload accumulation (payload pointer + pos into reusable payload_buf with size guard, async handlers detach buf on completion), session auth state (sessid from kXR_login, logged_in/auth_done flags, login_user[9]/login_pid from client, auth_fail_count capped at XROOTD_MAX_AUTH_ATTEMPTS, pool_bytes_used capped at XROOTD_MAX_CONN_POOL_BYTES), authenticated identity (dn[512] GSI subject DN, primary_vo[128], vo_list[512] space-separated VOs, peer_ip[64]), open file table (xrootd_file_t[XROOTD_MAX_FILES] — array index = XRootD file handle), pending flat-buffer send path (wbuf/wbuf_len/wbuf_pos/wbuf_base for EAGAIN tail storage + write event arm), pending chain send path (wchain remaining links + wchain_pending unsent bytes + wchain_base backing buffer, only one of wbuf or wchain active at a time), reusable response scratch buffers (read_scratch/read_hdr_scratch/write_scratch with size fields — malloc/realloc single buffer per session lifetime avoids pool growth), reusable thread-pool task (read_aio_task for memory-backed kXR_read TLS reads), reusable chain objects (read_fast_hdr/body_chain + hdr/body_buf + read_fast_file for common one-chunk response avoiding per-read allocation), GSI Diffie-Hellman key (gsi_dh_key generated at kXGS_cert freed after DH secret derivation at kXGC_cert), bearer-token auth state (token_auth flag + token_scope_count + token_scopes[XROOTD_MAX_TOKEN_SCOPES]), per-request latency start time, prepare polling state (prepare_reqid/prepare_paths heap-allocated newline-separated path list), session-level transfer totals (session_bytes/session_bytes_written/session_bytes_tx_ipv4/ipv6/session_bytes_rx_ipv4/ipv6/session_start for access log at disconnect), metrics pointer to shared-memory segment, AIO destruction guard (destroyed=1 in on_disconnect prevents stale callback writes), TLS upgrade state (tls_pending=1 when kXR_haveTLS sent awaiting ClientHello), upstream redirector query pointer, proxy forwarding context pointer, raw bearer token [4096] for proxy forward, kXR_sigver request-signing lifecycle (signing_key HMAC-SHA256 from DH secret + signing_active/last_seqno replay guard + sigver_pending envelope fields + sigver_hmac verification + cached EVP_MAC/EVP_MAC_CTX handles), kXR_bind parallel-stream state (is_bound/pathid/bound_sessid for secondary data channel inheriting primary auth, lazy reopen of canonical path in own worker with device/inode validation), CMS locate suspension (cms_wait_streamid pending-table key), protocol label/IP version (read-only set at connection time).
 *
 * WHY: One instance per TCP connection allocated from nginx connection pool. State machine runs on single worker thread — XRootD multiplexing handled via streamid matching on client side, server serialises responses. Reusable scratch buffers and chain objects prevent pool growth in long-lived xrdcp sessions (malloc/realloc instead of ngx_palloc per-request). AIO destruction guard prevents post-disconnect callback writes to freed memory. TLS upgrade path intercepts next recv as ClientHello when kXR_haveTLS advertised. Bind connections lazily reopen primary's canonical path in own worker (nginx workers cannot share post-fork fd integers safely) and validate device/inode before serving data. Sigver lifecycle: kXGC_cert → signing_key=SHA-256(DH-secret)/active=1, sigver arrives → pending=1/envelope saved, next dispatch → HMAC verified/pending=0, replay guard → seqno > last_seqno.
 *
 * HOW: Struct layout — session pointer/state (lines 16-17) → input accumulation hdr_buf/hdr_pos (lines 24-26) → parsed header cur_streamid/cur_reqid/cur_body/cur_dlen (lines 28-31) → payload accumulation payload/payload_pos/payload_buf/payload_buf_size (lines 43-46) → session auth sessid/logged_in/auth_done/login_user/login_pid/auth_fail_count/pool_bytes_used (lines 59-65) → authenticated identity dn/primary_vo/vo_list/peer_ip (lines 68-71) → file table files[XROOTD_MAX_FILES] (line 74) → flat-buffer send wbuf/wbuf_len/wbuf_pos/wbuf_base (lines 84-87) → chain send wchain/wchain_pending/wchain_base (lines 97-99) → scratch buffers read_scratch/read_hdr_scratch/write_scratch + sizes (lines 112-117) → aio task read_aio_task (line 124) → fast-chain objects read_fast_* (lines 131-135) → gsi_dh_key (line 142) → token auth token_auth/token_scope_count/token_scopes (lines 153-155) → req_start (line 158) → prepare polling prepare_reqid/prepare_paths/prepare_paths_len (lines 164-166) → session totals bytes/session_bytes_tx_ipv4/ipv6/session_bytes_rx_ipv4/ipv6/session_start (lines 169-175) → metrics pointer (line 179) → destroyed guard (line 187) → tls_pending (line 195) → upstream pointer (line 198) → proxy pointer (line 201) → bearer_token[4096] (line 208) → sigver signing_key/signing_active/last_seqno/sigver_* fields/EVP_MAC/EVP_MAC_CTX (lines 225-235) → bind is_bound/pathid/bound_sessid (lines 253-255) → cms_wait_streamid (line 258) → protocol_label/ip_version (lines 261-262). */

/*
 * Per-connection context (xrootd_ctx_t).
 *
 * One instance per TCP connection, allocated from the nginx connection pool.
 * The state machine runs on a single nginx worker thread; only one request
 * is "in flight" at a time — XRootD multiplexing is handled via streamid
 * matching on the client side, but the server serialises responses.
 *
 * Requires: state.h, file.h, tunables.h, protocol/protocol.h,
 *           token/token.h, metrics/metrics.h, and nginx/OpenSSL headers
 *           before inclusion.
 */
typedef struct {
    ngx_stream_session_t  *session;  /* nginx session; gives us c, pool, log */
    xrootd_state_t         state;    /* drives the read/write event callbacks */

    /*
     * Input accumulation.
     * We read in two stages: first the fixed 24-byte request header into
     * hdr_buf, then (if hdr->dlen > 0) the payload into *payload.
     */
    u_char     hdr_buf[24];   /* raw bytes of the current request header */
    size_t     hdr_pos;       /* how many header bytes we have so far */

    /* Parsed fields from the most recent 24-byte request header */
    u_char     cur_streamid[2]; /* echoed back unchanged in every response */
    uint16_t   cur_reqid;       /* opcode, host byte order (e.g. kXR_open=3010) */
    u_char     cur_body[16];    /* request-specific parameter bytes (see wire.h) */
    uint32_t   cur_dlen;        /* payload length that follows the header */

    /*
     * Payload accumulation.
     *
     * payload points at payload_buf while a request is being read/dispatched.
     * payload_buf is an explicitly owned reusable allocation so long-lived
     * xrdcp sessions do not retain every request payload in the nginx pool.
     * Async write handlers may detach the current payload_buf and free it from
     * their completion callback, leaving these fields NULL until the next
     * payload-bearing request.
     */
    u_char    *payload;          /* current request payload, NULL if none */
    size_t     payload_pos;      /* bytes accumulated so far */
    u_char    *payload_buf;      /* reusable receive buffer */
    size_t     payload_buf_size; /* allocated size of payload_buf */

    /*
     * Session auth state.
     *
     * XRootD uses a two-step login model:
     *   1. kXR_login  → server issues session ID; logged_in = 1
     *   2. kXR_auth   → client presents credentials; auth_done = 1
     *
     * When xrootd_auth = none, auth_done is set immediately after login.
     * Most file opcodes require both flags.  kXR_ping and kXR_protocol
     * are allowed before login.
     */
    u_char     sessid[XROOTD_SESSION_ID_LEN]; /* opaque ID we issued at login */
    ngx_flag_t logged_in;  /* set when kXR_login is accepted */
    ngx_flag_t auth_done;  /* set when authentication is complete */
    char       login_user[9]; /* fixed-width kXR_login username, NUL-terminated */
    uint32_t   login_pid;     /* client pid from kXR_login, host byte order */
    uint8_t    auth_fail_count; /* failed kXR_auth attempts; capped at XROOTD_MAX_AUTH_ATTEMPTS */
    size_t     pool_bytes_used; /* cumulative ngx_palloc bytes; capped at XROOTD_MAX_CONN_POOL_BYTES */

    /* Authenticated identity (filled during kXR_auth / token validation) */
    char  dn[512];          /* GSI subject DN, e.g. "/DC=org/DC=cilogon/CN=Rob" */
    char  primary_vo[128];  /* first VO from the VOMS attribute cert, e.g. "cms" */
    char  vo_list[512];     /* space-separated list of all VOs, e.g. "cms atlas" */
    char  peer_ip[64];      /* remote peer address for authdb HOST ('p') rules */
    xrootd_identity_t *identity; /* canonical Phase 2 identity object */

    /* Open file table — array index IS the XRootD file handle (0-based) */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /*
     * Pending flat-buffer send path (small responses: error, ok, status).
     *
     * When c->send() returns EAGAIN, the unsent tail is stored here and the
     * write event is armed.  wbuf points into the allocation; wbuf_base is
     * the start of the allocation (freed on disconnect or after full drain).
     * wbuf_len is the total size; wbuf_pos is how many bytes have been sent.
     */
    u_char    *wbuf;        /* pointer to the next byte to send */
    size_t     wbuf_len;    /* total bytes in the buffer */
    size_t     wbuf_pos;    /* bytes successfully sent so far */
    u_char    *wbuf_base;   /* allocation base (freed when send completes) */

    /*
     * Pending chain send path (large responses: read data, dirlist chunks).
     *
     * xrootd_queue_response_chain() stores the chain here when c->sendfile_chain()
     * or c->send_chain() returns EAGAIN.  wchain_base (if set) is a heap buffer
     * that backs some chain link and is freed after the chain is fully drained.
     * Only one of wbuf or wchain is active at a time.
     */
    ngx_chain_t *wchain;       /* remaining chain links to send */
    off_t        wchain_pending; /* unsent bytes in wchain, for cheap resume */
    u_char      *wchain_base;  /* optional backing buffer, freed after drain */

    /*
     * Reusable response scratch buffers for read-heavy sessions.
     *
     * Building a kXR_read response header + data, or a kXR_readv interleaved
     * response, requires a temporary buffer.  Instead of allocating from the
     * connection pool on every request (which grows the pool permanently),
     * we malloc/realloc a single buffer and keep it for the session lifetime.
     *
     *   read_scratch      — holds the flat data block (for read/pgread)
     *   read_hdr_scratch  — holds the per-chunk response headers (for readv)
     */
    u_char   *read_scratch;          /* reusable data buffer */
    size_t    read_scratch_size;      /* current allocated size */
    u_char   *read_hdr_scratch;       /* reusable header buffer */
    size_t    read_hdr_scratch_size;  /* current allocated size */
    u_char   *write_scratch;          /* reusable pgwrite decode buffer */
    size_t    write_scratch_size;     /* current allocated size */

    /*
     * Reusable thread-pool task for memory-backed kXR_read.  TLS/native GSI
     * reads cannot use sendfile, so avoiding per-request task allocation keeps
     * single-stream encrypted reads from growing the connection pool.
     */
    ngx_thread_task_t *read_aio_task;

    /*
     * Reusable chain objects for the common one-chunk read response.
     * xrdcp's default request size fits this path, so keeping the structs in
     * the connection context avoids per-read pool allocation and pool growth.
     */
    ngx_chain_t  read_fast_hdr_chain;
    ngx_chain_t  read_fast_body_chain;
    ngx_buf_t    read_fast_hdr_buf;
    ngx_buf_t    read_fast_body_buf;
    ngx_file_t   read_fast_file;

    /*
     * GSI Diffie-Hellman key — generated during kXGS_cert and freed
     * immediately after the DH shared secret is derived at kXGC_cert.
     * NULL at all other times.
     */
    EVP_PKEY  *gsi_dh_key;

    /*
     * Bearer-token auth state.
     *
     * token_auth=1 means this session was authenticated via a WLCG/SciToken
     * (not GSI).  The scopes extracted from the token are stored in token_scopes
     * and checked per-operation in open/write handlers.
     *
     * token_auth=0 with auth_done=1 means GSI was used; scopes are not relevant.
     */
    int                   token_auth;         /* 1 = token session */
    int                   token_scope_count;  /* valid entries in token_scopes[] */
    xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];

    /* Per-request start time for latency logging */
    ngx_msec_t  req_start;

    /* State saved from a kXR_prepare + kXR_stage request for kXR_QPrep polling.
     * The reqid we issued is stored so we can recognize it in QPrep.
     * The path list (newline-separated, heap-allocated) lets us check disk
     * status when the client queries without re-supplying the paths. */
    char    prepare_reqid[32];
    u_char *prepare_paths;
    size_t  prepare_paths_len;

    /* Session-level transfer totals written to the access log at disconnect */
    size_t      session_bytes;          /* total bytes read by client           */
    size_t      session_bytes_written;  /* total bytes written by client        */
    size_t      session_bytes_tx_ipv4;  /* bytes sent to IPv4 clients (session) */
    size_t      session_bytes_rx_ipv4;  /* bytes received from IPv4 clients     */
    size_t      session_bytes_tx_ipv6;  /* bytes sent to IPv6 clients (session) */
    size_t      session_bytes_rx_ipv6;  /* bytes received from IPv6 clients     */
    ngx_msec_t  session_start;          /* ngx_current_msec at login            */

    /* Points into the shared-memory metrics segment for this server slot.
     * NULL if metrics are not configured (xrootd_metrics_zone not set). */
    ngx_xrootd_srv_metrics_t  *metrics;

    /*
     * AIO destruction guard.
     * Set to 1 in xrootd_on_disconnect() so that a thread-pool callback
     * that fires after the connection closes can detect the stale pointer
     * and abort instead of writing to freed memory.
     */
    ngx_uint_t  destroyed;

    /*
     * TLS upgrade state (kXR_ableTLS).
     * Set to 1 when we send kXR_haveTLS in a kXR_protocol response.
     * The next recv is the ClientHello; cleared when the TLS handshake
     * succeeds and we resume normal request parsing.
     */
    ngx_uint_t  tls_pending;

    /* Active upstream redirector query (NULL when not in UPSTREAM state) */
    xrootd_upstream_t  *upstream;

    /* Proxy forwarding context (NULL when proxy not active for this session) */
    xrootd_proxy_ctx_t *proxy;

    /*
     * Raw bearer token saved during kXR_auth token validation so the proxy can
     * forward it to the upstream when xrootd_proxy_auth forward is set.
     * Empty string when the client authenticated via GSI or anonymously.
     */
    char  bearer_token[4096];

    /*
     * kXR_sigver request-signing state (GSI sessions only).
     *
     * When the server advertises kXR_secreqs in kXR_protocol, the GSI
     * client wraps each subsequent request in a kXR_sigver envelope
     * carrying an HMAC-SHA256 over the next request's header (and
     * optionally its payload).
     *
     * Lifecycle:
     *   kXGC_cert completes → signing_key = SHA-256(DH-shared-secret),
     *                          signing_active = 1
     *   kXR_sigver arrives  → sigver_pending = 1, envelope fields saved
     *   next dispatch       → HMAC verified; sigver_pending = 0
     *   replay guard        → seqno must be > last_seqno
     */
    u_char    signing_key[32];    /* HMAC-SHA256 key (SHA-256 of DH secret) */
    int       signing_active;     /* 1 = signing_key is valid and in use */
    uint64_t  last_seqno;         /* highest seqno accepted so far */

    int       sigver_pending;     /* 1 = next dispatch must verify the HMAC */
    int       verified_signing;   /* 1 = current request passed sigver verification */
    uint16_t  sigver_expectrid;   /* the opcode the sigver envelope covers */
    uint64_t  sigver_seqno;       /* seqno from the kXR_sigver frame */
    int       sigver_nodata;      /* 1 = payload was excluded from the HMAC */
    u_char    sigver_hmac[32];    /* expected HMAC bytes to check against */
    EVP_MAC      *sigver_mac;     /* cached OpenSSL HMAC provider handle */
    EVP_MAC_CTX  *sigver_mac_ctx; /* reusable HMAC context for signed reqs */

    /*
     * kXR_bind parallel-stream state.
     *
     * A secondary ("bound") connection is created by an xrdcp parallel-stream
     * client.  It skips kXR_login and sends kXR_bind with the primary session's
     * sessid instead.  The server assigns a pathid (1–253); the client then
     * tags read/write requests with that pathid so the server knows which
     * data channel they arrived on.
     *
     * Bound connections inherit auth from the primary registry entry but are
     * not independent file sessions.  They may only issue read/readv/pgread
     * against handles currently published by the primary.  Because nginx
     * workers cannot share post-fork fd integers safely, the secondary lazily
     * reopens the primary's canonical path in its own worker and validates the
     * stored device/inode before serving data.
     */
    int     is_bound;                            /* 1 = secondary data channel */
    int     pathid;                              /* assigned path ID (1–253)  */
    u_char  bound_sessid[XROOTD_SESSION_ID_LEN]; /* primary session we bound to */

    /* CMS locate suspension (state == XRD_ST_WAITING_CMS) */
    uint32_t    cms_wait_streamid;  /* pending-table key for removal on timeout */

    /* Protocol label and IP version — set at connection time, read-only thereafter. */
    char        protocol_label[8];  /* "root", "dav", or "s3"               */
    u_char      ip_version;         /* AF_INET (2) or AF_INET6 (10)     */

} xrootd_ctx_t;
