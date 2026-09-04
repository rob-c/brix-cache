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

/* XrdSeckrb5 forwarded-TGT delegation-capture state (phase-70 §5.7, inbound
 * two-round exchange).  Round 1 verifies the AP_REQ and — when brix_krb5_delegate
 * is on — replies kXR_authmore "fwdtgt" instead of finalizing, parking the
 * round-1 auth context (holds the session subkey the forwarded KRB_CRED is
 * encrypted under) and the mapped client principal so round 2 can decrypt the
 * client's krb5_fwd_tgt_creds() blob.  Handles are opaque (void*) so krb5.h never
 * leaks into this widely-included header; deleg_capture.c owns the casts and the
 * pool-cleanup that frees them.  On capture the forwarded TGT is serialised to a
 * 0600 FILE ccache whose path is stashed in `ccache` for the request-time VFS
 * delegation bind (brix_root_vfs_bind_session → brix_vfs_deleg_set_krb5). */
typedef struct {
    unsigned  round;          /* 0 = fresh; 1 = fwdtgt challenge sent, awaiting KRB_CRED */
    void     *auth_ctx;       /* round-1 krb5_auth_context (session subkey), freed at round 2/cleanup */
    void     *client;         /* copied krb5_principal of the verified client */
    char      cname[512];     /* mapped local name, promoted to login.dn at finalize */
    char      ccache[1024];   /* captured forwarded-TGT 0600 FILE ccache path (no "FILE:" prefix) */
} brix_ctx_krb5_t;

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
 * request in a kXR_sigver envelope carrying the stock XrdSecProtect secver-0
 * signature: the GSI session cipher's encryption of SHA-256(seqno_be(8) ||
 * header(24) || payload-unless-nodata), IV-prepended on the signed-DH path.
 * The replay guard requires seqno > last_seqno.  The cipher material is a COPY
 * (armed at kXGC_cert) so delegation's ctx->gsi.sess_key cleanse cannot disarm
 * signing mid-session. */
typedef struct {
    char         sig_cipher[24];   /* session cipher name (kXRS_cipher_alg) */
    u_char       sig_key[32];      /* session key (first key_len of DH secret) */
    int          sig_keylen;       /* valid bytes in sig_key (0 = unset) */
    int          sig_use_iv;       /* 1 = IV-prepended blobs (signed-DH peer) */
    int          signing_active;   /* 1 = cipher/key are valid and in use */
    uint64_t     last_seqno;       /* highest seqno accepted so far */
    int          pending;          /* 1 = next dispatch must verify the signature */
    int          verified;         /* 1 = current request passed sigver verification */
    uint16_t     expectrid;        /* the opcode the sigver envelope covers */
    u_char       sid[2];           /* streamid of the sigver frame (must match) */
    uint64_t     seqno;            /* seqno from the kXR_sigver frame */
    int          nodata;           /* 1 = payload was excluded from the hash */
    u_char       sig[64];          /* signature blob (BRIX_GSI_SIGVER_SIG_MAX) */
    int          sig_len;          /* valid bytes in sig */
    int          unsignable_logged; /* 1 = this session already logged that it
                                     * cannot sign while a signing level is
                                     * configured (audit §5.2). One line per
                                     * session, not per request: the condition is
                                     * a property of the session's auth protocol,
                                     * so repeating it per opcode would be a log
                                     * flood with no added information. */
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
    uint8_t    ability;         /* §1.3 XLoginAbility bitmask the client
                                 * advertised (kXR_fullurl=1 honored in
                                 * brix_send_redirect; other bits stored) */
    uint8_t    ability2;        /* §1.3 XLoginAbility2 bitmask (stored) */
    uint8_t    auth_fail_count; /* failed kXR_auth attempts; capped */
    size_t     pool_bytes_used; /* cumulative ngx_palloc bytes; capped */
    char       dn[512];         /* GSI subject DN (literal proxy-leaf DN) */
    char       eec_dn[512];     /* P80.11: stable End-Entity Cert DN (proxy
                                 * serial stripped); "" for non-proxy/non-GSI
                                 * auth. The authorization identity — see
                                 * brix_gsi_complete_auth. */
    char       primary_vo[128]; /* first VO from the VOMS attribute cert */
    char       vo_list[512];    /* space-separated list of all VOs */
    char       peer_ip[64];     /* remote peer address for authdb HOST ('p') rules */
    const char *acc_host;       /* XrdAcc reverse-DNS host cache (points into c->pool) */
    unsigned    acc_host_done:1;
    unsigned    gsi_counted:1;  /* holds a GSI in-flight handshake slot (Phase 51 E4) */
    int         session_slot_hint; /* Round 15: SHM registry slot this session was
                                    * registered into, or -1 if it never was.  Lets
                                    * the disconnect clear that slot directly instead
                                    * of scanning the live prefix under the global
                                    * session mutex — see
                                    * brix_session_unregister_hinted(). */
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

    /* Post-auth read-ahead stash (see BRIX_RECV_STASH_SIZE): one big recv
     * feeds many exact-size frame reads with zero further syscalls.  Only
     * engaged once no other subsystem can ever read this socket raw
     * (auth done; no upstream/relay conf), so buffered bytes are always
     * consumed by the framing loop.  stash_len > stash_head means pipelined
     * request bytes are buffered — a kXR_bind must then refuse migration
     * (the bytes would not travel with the fd). */
    u_char    *stash;              /* lazily allocated from c->pool */
    uint32_t   stash_head;         /* next unconsumed byte */
    uint32_t   stash_len;          /* bytes buffered (0 = empty) */

    /* Streaming large plain kXR_write.  When sw_active is set the payload is a
     * SINGLE bounded chunk (payload_buf holds BRIX_WRITE_STREAM_CHUNK bytes) and
     * cur_dlen is repurposed as the CURRENT chunk length rather than the whole
     * write; each filled chunk is applied to the fd / staged writer at
     * sw_base_off+sw_done and one ack is sent after the last chunk.  See
     * write_stream.c. */
    unsigned    sw_active:1;       /* a chunked streaming write is in progress */
    unsigned    sw_staged:1;       /* route: staged append (else direct pwrite) */
    unsigned    sw_drain:1;        /* handle unusable: discard bytes, err at end */
    int         sw_idx;            /* file-handle slot being written */
    int64_t     sw_base_off;       /* wire offset of the logical write */
    uint32_t    sw_total;          /* total logical write length (original dlen) */
    uint32_t    sw_done;           /* bytes already applied */
    int         sw_err;            /* latched kXR_* error code (0 = none yet) */
    const char *sw_errmsg;         /* latched error detail string */
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

    /* §1.2 pool-send (offload-AIO): a worker thread that finished a large
     * pgread may send the frame on this connection's cleartext socket itself,
     * so the socket has two potential writers.  send_token is the ownership
     * CAS (0 free / 1 held) every socket-touching path takes once
     * pool_send_active is set; send_busy mirrors "the out-ring holds parked
     * frames" for the worker thread (the head one may be mid-frame, so it
     * must decline and preserve wire order).  Whole frames may reorder freely
     * — responses correlate by streamid — but bytes within a frame may not. */
    ngx_atomic_t       send_token;         /* socket ownership: 0 free, 1 held */
    ngx_atomic_t       send_busy;          /* 1 while ring holds parked frames */
    unsigned           pool_send_active:1; /* pool-send discipline engaged */
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

    /* used-since-last-trim marks, one per BRIX_GET_SCRATCH slot (the macro
     * sets <slot>_hot on every fetch).  brix_trim_scratch only shrinks a slot
     * whose mark is CLEAR — i.e. one idle for a whole trim cycle — and clears
     * the marks as it passes.  This keeps a streaming transfer's buffer warm
     * across back-to-back large requests (no per-request free/mmap churn)
     * while an idle connection still returns to window-scale heap one request
     * later than before.  hdr/cmp slots carry the mark for macro uniformity
     * even though the trim never targets them. */
    unsigned  read_scratch_hot:1;
    unsigned  read_hdr_scratch_hot:1;
    unsigned  write_scratch_hot:1;
    unsigned  cmp_scratch_hot:1;
    u_char   *dirlist_chunk;         /* kXR_dirlist header + chunk accumulator,
                                      * fixed XRD_RESPONSE_HDR_LEN + 64KB
                                      * (handler.c chunk_cap); alloc'd on first
                                      * dirlist, reused across requests while no
                                      * parked response references it */
    ngx_thread_task_t *read_aio_task;
    ngx_thread_task_t *readv_aio_task;
    brix_read_slot_t *pool;          /* [pipeline_depth] in-flight read buffers */
    ngx_uint_t         inflight;     /* pool entries currently in use */
    ngx_uint_t         aio_inflight; /* phase-32 WS3: single-shot read AIO tasks
                                      * posted but not yet completed — a worker
                                      * thread is preading into a pool buffer, so
                                      * teardown must defer until this hits 0
                                      * (mirrors out.wr_inflight for writes) */
    unsigned           backpressured:1; /* recv stopped admitting reads (pool full) */
    unsigned   win_active:1;         /* windowed memory-read in flight */
    unsigned   win_pgread:1;         /* windowed stream is a kXR_pgread: the
                                      * pump cuts windows on the 4 KiB page
                                      * grid, the worker runs the in-place
                                      * encode+CRC, and emit frames kXR_status
                                      * partial/final (pgread_window.c) */
    unsigned   win_readv:1;          /* windowed kXR_readv body stream */
    unsigned   win_readv_started:1;  /* outer response header was sent */
    unsigned   win_readv_seg_started:1; /* current segment header was sent */
    int        win_idx;
    int        win_fd;
    off_t      win_offset;           /* next file offset to read */
    size_t     win_remaining;        /* bytes still to send */
    u_char     win_streamid[2];

    /* kXR_readv continuation cursor.  win_readv_wire borrows recv.payload;
     * recv remains suspended while win_active is set, so the request buffer
     * outlives the train.  No backend locator or payload buffer is retained. */
    void      *win_readv_wire;
    size_t     win_readv_count;
    size_t     win_readv_index;
    size_t     win_readv_total;
    size_t     win_readv_body_size;  /* complete wire body advertised in dlen */

    /* Round 12 — double-buffered windows: while window N drains from
     * read_scratch, window N+1 is read ahead into win_scratch_b by a counted
     * thread-pool task; after each emit the two (ptr,size,hot) field triples
     * swap, so the just-filled back buffer becomes the next emit source and
     * the just-drained front buffer becomes the next read-ahead target.
     * win_prefetch = a read-ahead task is on a worker; win_ready = its result
     * is stashed in win_pf_* awaiting the previous frame's drain. */
    u_char    *win_scratch_b;        /* back window buffer (read-ahead target) */
    size_t     win_scratch_b_size;
    unsigned   win_scratch_b_hot:1;  /* used-since-last-trim (BRIX_GET_SCRATCH) */
    unsigned   win_prefetch:1;       /* read-ahead task in flight */
    unsigned   win_ready:1;          /* read-ahead result stashed in win_pf_* */
    ssize_t    win_pf_nread;         /* stashed read-ahead completion */
    size_t     win_pf_osz;
    int        win_pf_errno;
} brix_ctx_rd_t;

#endif /* BRIX_TYPES_CTX_STRUCTS_H */
