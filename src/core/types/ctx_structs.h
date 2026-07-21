/*
 * core/types/ctx_structs.h
 *
 * Per-connection context sub-struct helper types, grouped out of the main
 * brix_ctx_t definition (context.h) so the connection state reads as a set of
 * named concern groups rather than a flat wall of ~100 fields.  Every field is
 * reached as ctx-><group>.<field> (e.g. ctx->gsi.sess_key, ctx->recv.payload,
 * ctx->out.pipeline_depth).
 *
 * NOT self-contained: included by context.h at the point right before the
 * brix_ctx_t definition, AFTER the helper slot structs (brix_resp_slot_t,
 * brix_read_slot_t) and after the translation unit has pulled in state.h,
 * file.h, tunables.h, token/token.h, metrics/metrics.h, and nginx/OpenSSL
 * headers — exactly where these fields previously lived inline.  Do not include
 * it directly — include context.h.
 */

#ifndef BRIX_TYPES_CTX_STRUCTS_H
#define BRIX_TYPES_CTX_STRUCTS_H

/* Sub-structs are appended here one concern-group at a time (see
 * docs/superpowers/plans/2026-07-04-context-h-substruct-migration.md). */

/* XrdSecpwd (Phase 52 WS-B) multi-round handshake state.  Round 1 derives the
 * DH session key from the client's kXRS_puk; round 2 decrypts the credential
 * with it, so the ephemeral DH keypair need not survive between rounds. */
typedef struct {
    uint8_t   session_key[16]; /* aes-128 DH session key (round 1) */
    unsigned  round;           /* rounds seen (1 = puk-exchange done, awaiting creds) */
    char      user[64];        /* username asserted in round 1, verified in round 2 */
} brix_ctx_pwd_t;

/* Bearer-token (WLCG/SciToken) auth state.  auth=1 means this session was
 * authenticated via a token (not GSI); the extracted scopes are checked
 * per-operation in the open/write handlers. */
typedef struct {
    int                 auth;         /* 1 = token session */
    int                 scope_count;  /* valid entries in scopes[] */
    brix_token_scope_t  scopes[BRIX_MAX_TOKEN_SCOPES];
} brix_ctx_token_t;

/* XrdThrottle (Phase-59 W3a) per-user accounting for this connection.
 * open_held = open-file increments this conn holds (disconnect decrements
 * exactly that many); conn_counted = counted toward the per-user active total. */
typedef struct {
    ngx_uint_t  open_held;
    unsigned    conn_counted:1;
} brix_ctx_throttle_t;

/* Phase 39 steady-state network-fault deadlines.  *_armed track whether THIS
 * module armed c->read / c->write's timer (so arm/disarm are idempotent);
 * *_ms are the merged timeouts cached at accept so the hot recv/park paths
 * avoid a srv_conf lookup.  0 = the corresponding deadline is disabled. */
typedef struct {
    unsigned    read_armed:1;   /* 1 = we armed c->read's timer  */
    unsigned    send_armed:1;   /* 1 = we armed c->write's timer */
    ngx_msec_t  read_ms;        /* cached brix_read_timeout (0 = off)      */
    ngx_msec_t  handshake_ms;   /* cached brix_handshake_timeout (0 = off) */
    ngx_msec_t  send_ms;        /* cached brix_send_timeout (0 = off)      */
} brix_ctx_deadline_t;

/* Session-level transfer totals written to the access log at disconnect. */
typedef struct {
    size_t      bytes;          /* total bytes read by client           */
    size_t      bytes_written;  /* total bytes written by client        */
    size_t      bytes_tx_ipv4;  /* bytes sent to IPv4 clients (session) */
    size_t      bytes_rx_ipv4;  /* bytes received from IPv4 clients     */
    size_t      bytes_tx_ipv6;  /* bytes sent to IPv6 clients (session) */
    size_t      bytes_rx_ipv6;  /* bytes received from IPv6 clients     */
    ngx_msec_t  start;          /* ngx_current_msec at login            */
} brix_ctx_totals_t;

/* kXR_prepare + kXR_stage state for kXR_QPrep polling, plus async tape recall
 * (kXR_waitresp -> kXR_attn asynresp).  When stage_async_active, a replayed open
 * of a just-staged file emits its open-OK wrapped in kXR_attn(asynresp) on the
 * saved stage_async_streamid. */
typedef struct {
    char      reqid[40];             /* stage "<seq>.<pid>@<host>" reqid */
    u_char   *paths;                 /* newline-separated path list (heap) */
    size_t    paths_len;
    unsigned  stage_async_active:1;
    u_char    stage_async_streamid[2];
} brix_ctx_prepare_t;

/* SciTags packet-marking flow (src/pmark/): begun on the first file open, ended
 * on disconnect. */
typedef struct {
    struct brix_pmark_flow_s *flow;    /* flow handle (NULL = not marked) */
    ngx_event_t               echo_ev; /* periodic "ongoing" firefly timer (if echo>0) */
    ngx_msec_t                echo_ms; /* echo interval, for the timer to re-arm itself */
} brix_ctx_pmark_t;

/* kXR_sigver request-signing state (GSI sessions).  The client wraps each
 * request in a kXR_sigver envelope carrying an HMAC-SHA256 over the next
 * request's header (and optionally payload); the replay guard requires seqno >
 * last_seqno.  signing_key = SHA-256(DH-shared-secret) set at kXGC_cert. */
typedef struct {
    u_char       signing_key[32];  /* HMAC-SHA256 key (SHA-256 of DH secret) */
    int          signing_active;   /* 1 = signing_key is valid and in use */
    uint64_t     last_seqno;       /* highest seqno accepted so far */
    int          pending;          /* 1 = next dispatch must verify the HMAC */
    int          verified;         /* 1 = current request passed sigver verification */
    uint16_t     expectrid;        /* the opcode the sigver envelope covers */
    uint64_t     seqno;            /* seqno from the kXR_sigver frame */
    int          nodata;           /* 1 = payload was excluded from the HMAC */
    u_char       hmac[32];         /* expected HMAC bytes to check against */
    EVP_MAC      *mac;             /* cached OpenSSL HMAC provider handle */
    EVP_MAC_CTX  *mac_ctx;         /* reusable HMAC context for signed reqs */
} brix_ctx_sigver_t;

/* GSI handshake + X.509 proxy delegation state.  dh_key is the ephemeral DH key
 * (kXGS_cert), freed after the shared secret is derived.  signed_dh selects the
 * signed vs unsigned DH wire form (phase-48).  The deleg_* fields capture the
 * client's proxy during login for a later TPC pull (phase-57 §F6). */
typedef struct {
    EVP_PKEY  *dh_key;          /* DH key (kXGS_cert), freed after secret derived */
    int        signed_dh;       /* 0 = unsigned DH (default), 1 = signed DH (>=10400) */
    char       sess_cipher[24]; /* negotiated session cipher name */
    u_char     sess_key[32];    /* session AES key (DH-secret derived) */
    int        sess_keylen;     /* valid bytes in sess_key (0 = unset) */
    int        sess_use_iv;     /* 1 = IV-prepended main (signed-DH path) */
    EVP_PKEY  *deleg_reqkey;    /* fresh proxy key (build_pxyreq), or NULL */
    uint32_t   clnt_opts;       /* client's kXRS_clnt_opts (kOpts*) delegation mode */
    int        deleg_await;     /* 1 = sent kXGS_pxyreq, awaiting kXGC_sigpxy */
    u_char    *deleg_chain_pem; /* client chain PEM (for assemble), heap */
    size_t     deleg_chain_len;
    u_char    *deleg_proxy_pem; /* captured delegated proxy credential (PEM) */
    size_t     deleg_proxy_len;
    u_char     deleg_client_rtag[64]; /* client's kXGC_cert random tag */
    int        deleg_client_rtag_len;
    /* phase-70 §5.1: raw client-pushed FULL proxy PEM (kXRS_x509_fullproxy)
     * captured from the decrypted kXGC_cert inner buffer, BEFORE DN validation.
     * auth.c validates (chain+key parse, leaf DN == authenticated DN) then
     * promotes the bytes to ctx->deleg_proxy_pem; heap-owned, freed at cleanup. */
    u_char    *client_fullproxy_pem;
    size_t     client_fullproxy_len;
} brix_ctx_gsi_t;

/* Per-connection rate-limit state (Phase 25/33).  bw_* = the current request's
 * bandwidth charge target; conc_* = a per-principal concurrency slot held for the
 * connection's lifetime; key_cache = cached identity-stable rule keys.  The
 * *_rule pointers are brix_rl_rule_t* (void to keep ratelimit.h out of this
 * widely-included header). */
typedef struct {
    void       *bw_rule;
    char        bw_key[128];
    void       *conc_rule;   /* NULL = no concurrency slot held */
    char        conc_key[128];
    char        key_cache[BRIX_RL_RULE_CACHE_MAX][128];
    uint32_t    key_cache_valid; /* bitmask: bit i ⇒ key_cache[i] holds rule i's key */
} brix_ctx_rl_t;

/* Session login + authenticated-identity state.  Two-step XRootD login: kXR_login
 * sets logged_in and issues sessid; kXR_auth sets auth_done and fills the identity
 * strings (dn/primary_vo/vo_list/peer_ip).  acc_host is the opt-in XrdAcc
 * reverse-DNS cache; gsi_counted tracks an in-flight GSI handshake slot. */
typedef struct {
    u_char     sessid[BRIX_SESSION_ID_LEN]; /* opaque ID we issued at login */
    ngx_flag_t logged_in;       /* set when kXR_login is accepted */
    ngx_flag_t auth_done;       /* set when authentication is complete */
    char       user[9];         /* fixed-width kXR_login username, NUL-terminated */
    uint32_t   pid;             /* client pid from kXR_login, host byte order */
    uint8_t    auth_fail_count; /* failed kXR_auth attempts; capped */
    size_t     pool_bytes_used; /* cumulative ngx_palloc bytes; capped */
    char       dn[512];         /* GSI subject DN */
    char       primary_vo[128]; /* first VO from the VOMS attribute cert */
    char       vo_list[512];    /* space-separated list of all VOs */
    char       peer_ip[64];     /* remote peer address for authdb HOST ('p') rules */
    const char *acc_host;       /* XrdAcc reverse-DNS host cache (points into c->pool) */
    unsigned    acc_host_done:1;
    unsigned    gsi_counted:1;  /* holds a GSI in-flight handshake slot (Phase 51 E4) */
} brix_ctx_login_t;

/* Request receive/framing state.  Read in two stages: the fixed 24-byte header
 * into hdr_buf, then (if dlen>0) the payload into the reusable payload_buf.
 * cur_* are the parsed header fields; cur_body_extra/extended cover the trailing
 * body streamed after the dlen-framed payload (kXR_writev / kXR_chkpoint). */
typedef struct {
    u_char     hdr_buf[24];        /* raw bytes of the current request header */
    size_t     hdr_pos;            /* header bytes received so far */
    u_char     cur_streamid[2];    /* echoed back unchanged in every response */
    uint16_t   cur_reqid;          /* opcode, host byte order */
    u_char     cur_body[16];       /* request-specific parameter bytes (wire.h) */
    uint32_t   cur_dlen;           /* payload length that follows the header */
    uint32_t   cur_body_extra;     /* streamed data bytes beyond cur_dlen */
    unsigned   cur_body_extended:2;/* completed extension stages (2 = done) */
    u_char    *payload;            /* current request payload, NULL if none */
    size_t     payload_pos;        /* bytes accumulated so far */
    u_char    *payload_buf;        /* reusable receive buffer */
    size_t     payload_buf_size;   /* allocated size of payload_buf */
} brix_ctx_recv_t;

/* Output response ring + write-pipelining state (Phase 29/32).  A response is
 * built into ring[tail] and drained from ring[head]; count = slots in use; the
 * ring holds pipeline_depth slots (all arithmetic modulo pipeline_depth).
 * wr_inflight bounds in-flight plain-write pwrites; the recv loop keeps reading
 * while count + wr_inflight < pipeline_depth. */
typedef struct {
    ngx_uint_t         pipeline_depth; /* ring capacity = configured in-flight bound */
    brix_resp_slot_t *ring;            /* [pipeline_depth] response slots */
    ngx_uint_t         head;           /* slot being drained to the socket */
    ngx_uint_t         tail;           /* slot currently being built */
    ngx_uint_t         count;          /* number of slots in use (responses queued) */
    unsigned           recv_deferred:1;    /* drain barrier: parked non-pipelinable req awaits count==0 */
    u_char             deferred_streamid[2]; /* parked request's sid: a pipelined AIO ack completing
                                              * during the park clobbers recv.cur_streamid, so the
                                              * deferred dispatch must reinstall its own sid */
    unsigned           resp_pipelinable:1; /* current response is a single-chunk sendfile read */
    ngx_uint_t         wr_inflight;        /* plain-write pwrites posted, not yet acked */
    unsigned           resp_async:1;       /* ack drains without disturbing recv */
    unsigned           finalize_pending:1; /* deferred teardown while wr_inflight > 0 */
    ngx_int_t          finalize_status;    /* ngx_stream status to finalize with */
} brix_ctx_out_t;

/* Read pipeline + reusable read/write scratch buffers.  The *_scratch buffers
 * are raw ngx_alloc kept for the session lifetime (grown on demand).  The
 * *_aio_task are reused per-opcode thread tasks for serial memory-backed reads.
 * pool[pipeline_depth] backs concurrent single-shot memory reads (Phase 32 WS3);
 * win_* is the windowed-read continuation for large TLS/non-regular reads. */
typedef struct {
    u_char   *read_scratch;          /* flat data block (read/pgread) */
    size_t    read_scratch_size;
    u_char   *read_hdr_scratch;      /* per-chunk response headers (readv) */
    size_t    read_hdr_scratch_size;
    u_char   *write_scratch;         /* pgwrite decode buffer */
    size_t    write_scratch_size;
    u_char   *cmp_scratch;           /* inline read-compression codec output (Phase-42 W4) */
    size_t    cmp_scratch_size;
    ngx_thread_task_t *read_aio_task;
    ngx_thread_task_t *pgread_aio_task;
    ngx_thread_task_t *readv_aio_task;
    brix_read_slot_t *pool;          /* [pipeline_depth] in-flight read buffers */
    ngx_uint_t         inflight;     /* pool entries currently in use */
    unsigned           backpressured:1; /* recv stopped admitting reads (pool full) */
    unsigned   win_active:1;         /* windowed memory-read in flight */
    int        win_idx;
    int        win_fd;
    off_t      win_offset;           /* next file offset to read */
    size_t     win_remaining;        /* bytes still to send */
    u_char     win_streamid[2];
} brix_ctx_rd_t;

#endif /* BRIX_TYPES_CTX_STRUCTS_H */
