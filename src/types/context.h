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
/*
 * Output-queue slot (Phase 29 pipelining).
 *
 * Each slot owns the full send state for ONE in-flight response: the
 * flat-buffer tail (small error/ok/status frames) OR the chain tail (read data,
 * dirlist chunks), plus the reusable header/data/file chain structs that back a
 * single-chunk read response.  Bundling these per-slot (instead of one set of
 * singletons on the connection) is what lets more than one response be in flight
 * without the builders aliasing each other's chain memory.
 *
 * Only one of wbuf / wchain is active in a given slot at a time.  wbuf points at
 * the next unsent byte; wbuf_base is the owned allocation freed once the slot
 * drains.  wchain holds the remaining chain links; wchain_base (if set) backs a
 * chain link and is freed after the chain fully drains.  The read_fast_* structs
 * are the pre-zeroed chain/buf/file objects reused for the common one-chunk read
 * response so that path allocates nothing from the pool per request.
 */
typedef struct {
    u_char      *wbuf;            /* pointer to the next byte to send */
    size_t       wbuf_len;        /* total bytes in the buffer */
    size_t       wbuf_pos;        /* bytes successfully sent so far */
    u_char      *wbuf_base;       /* allocation base (freed when send completes) */

    ngx_chain_t *wchain;          /* remaining chain links to send */
    off_t        wchain_pending;  /* unsent bytes in wchain, for cheap resume */
    u_char      *wchain_base;     /* optional backing buffer, freed after drain */

    ngx_chain_t  read_fast_hdr_chain;
    ngx_chain_t  read_fast_body_chain;
    ngx_buf_t    read_fast_hdr_buf;
    ngx_buf_t    read_fast_body_buf;
    ngx_file_t   read_fast_file;

    /*
     * Per-slot response header storage (Phase 29 single-chunk; Phase 32 WS2
     * widened to XROOTD_SLOT_HDR_MAX so a MULTI-chunk sendfile read also keeps
     * all its per-chunk ServerResponseHdrs here instead of the shared
     * read_hdr_scratch).  Owning the headers per-slot is what lets multiple
     * (single- or multi-chunk) reads pipeline without their headers clobbering
     * each other while a prior response is still draining.
     */
    u_char       hdr_bytes[XROOTD_SLOT_HDR_MAX];
} xrootd_resp_slot_t;

/*
 * Phase 32 WS3 — concurrent-AIO read pipeline.
 *
 * A pool of per-in-flight-read buffers + thread tasks lets multiple
 * memory-backed kXR_reads be outstanding at once (pipelined) instead of the
 * single read_scratch / read_aio_task serial pair.  Each entry is owned by one
 * in-flight read from dispatch until the response it backs has fully drained
 * from its out_ring slot, at which point xrootd_release_read_buffer() returns it
 * to the pool.  Buffers are raw ngx_alloc'd (Phase-31 discipline) and freed on
 * disconnect.  rd_inflight counts entries currently in use.
 */
typedef struct {
    u_char            *buf;       /* raw-alloc'd data buffer (ngx_alloc/ngx_free) */
    size_t             size;      /* allocated size of buf */
    ngx_thread_task_t *task;      /* per-entry thread task (kXR_read AIO) */
    unsigned           in_use:1;  /* 1 while an in-flight read owns this entry */
} xrootd_read_slot_t;

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
    /* XrdAcc reverse-DNS host cache: resolved once per connection (opt-in via
     * xrootd_acc_resolve_hosts).  acc_host points into c->pool; NULL once
     * acc_host_done is set means resolution failed → fall back to peer_ip. */
    const char *acc_host;
    unsigned    acc_host_done:1;
    xrootd_identity_t *identity; /* canonical Phase 2 identity object */

    /* SciTags packet-marking flow handle (NULL = not marked); begun on the
     * first file open, ended on disconnect.  See src/pmark/. */
    struct xrootd_pmark_flow_s *pmark_flow;
    ngx_event_t  pmark_echo_ev;  /* periodic "ongoing" firefly timer (if echo>0) */
    ngx_msec_t   pmark_echo_ms;  /* echo interval, for the timer to re-arm itself */

    /* Open file table — array index IS the XRootD file handle (0-based) */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /*
     * Output queue (Phase 29 pipelining).
     *
     * out_ring is a FIFO of response slots.  A response is built into the tail
     * slot (out_ring[out_tail]) and drained from the head slot
     * (out_ring[out_head]); out_count is the number of slots currently in use.
     * Each slot owns its own flat-buffer / chain send state and the reusable
     * one-chunk read-response chain structs (see xrootd_resp_slot_t), so
     * multiple responses can be in flight without aliasing each other's memory.
     *
     * Phase 1 lands the ring with effective depth 1: the recv loop stays serial
     * (it suspends on XRD_ST_SENDING), so out_head == out_tail == 0 throughout
     * and behaviour is identical to the previous single wbuf/wchain singletons.
     * Phase 2 raises the in-flight bound to XROOTD_PIPELINE_MAX.
     */
    xrootd_resp_slot_t out_ring[XROOTD_PIPELINE_MAX];
    ngx_uint_t         out_head;   /* slot being drained to the socket */
    ngx_uint_t         out_tail;   /* slot currently being built */
    ngx_uint_t         out_count;  /* number of slots in use (responses queued) */

    /*
     * Phase 29 drain barrier: set when a non-pipelinable request was fully read
     * while pipelined reads were still in flight.  The request stays parked in
     * the cur_ header fields and payload buffer and is dispatched by the recv
     * loop once the output queue has fully drained (out_count==0), preserving
     * the serial invariant for every
     * opcode except kXR_read.
     */
    unsigned           recv_deferred:1;

    /*
     * Phase 29: set by the single-chunk sendfile read builder, cleared by every
     * other response builder.  The recv loop only pipelines a kXR_read when this
     * is set — i.e. the response is a single sendfile span whose 8-byte header
     * lives in its own slot (slot->hdr_bytes), so queueing the next read cannot
     * clobber it.  Multi-chunk (>16 MiB) reads and all other opcodes stay serial.
     */
    unsigned           resp_pipelinable:1;

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
     * Phase 31 W4 — bytes this connection currently has charged to the global
     * transfer-heap budget (metrics->xfer_heap_in_use).  Reconciled idempotently
     * by xrootd_budget_sync(); released to 0 on disconnect.
     */
    size_t    budget_charged;

    /*
     * Reusable thread-pool task for memory-backed kXR_read.  TLS/native GSI
     * reads cannot use sendfile, so avoiding per-request task allocation keeps
     * single-stream encrypted reads from growing the connection pool.
     */
    ngx_thread_task_t *read_aio_task;

    /*
     * Reusable thread-pool tasks for kXR_pgread and kXR_readv, mirroring
     * read_aio_task above.  The connection is a strictly serial state machine
     * (one in-flight request at a time), so a single cached task per opcode is
     * reused across requests instead of allocating a fresh one each time.
     * Reset task->next and event.complete before each reuse.
     */
    ngx_thread_task_t *pgread_aio_task;
    ngx_thread_task_t *readv_aio_task;

    /*
     * Phase 32 WS3 — concurrent-AIO read pipeline state.  rd_pool holds up to
     * XROOTD_PIPELINE_MAX in-flight memory-read buffers/tasks; rd_inflight is the
     * count currently in use.  rd_backpressured is set when the recv loop stops
     * admitting reads because the pool + out_ring are full, and cleared when a
     * pool entry frees (driving a read-resume).  Single-shot memory reads draw
     * from this pool so several can be outstanding at once; the legacy
     * read_scratch/read_aio_task pair still backs windowed reads (serial).
     */
    xrootd_read_slot_t rd_pool[XROOTD_PIPELINE_MAX];
    ngx_uint_t         rd_inflight;
    unsigned           rd_backpressured:1;

    /*
     * Phase 31 W2.1 — windowed memory read continuation.  A large memory-backed
     * kXR_read (TLS / non-regular file) that exceeds XROOTD_READ_WINDOW is served
     * as a sequence of kXR_oksofar wire chunks ending in kXR_ok, each sourced
     * from one window-sized disk read into read_scratch.  The next window is
     * read only after the previous chunk has fully drained from read_scratch
     * (so the single buffer is never overwritten while still being sent).
     * rd_win_active marks a windowed read in flight; rd_win_offset is the next
     * file offset to read; rd_win_remaining is the bytes still to send.
     */
    unsigned   rd_win_active:1;
    int        rd_win_idx;
    int        rd_win_fd;
    off_t      rd_win_offset;
    size_t     rd_win_remaining;
    u_char     rd_win_streamid[2];

    /*
     * Reusable chain objects for the common one-chunk read response now live
     * per-slot in out_ring[] (xrootd_resp_slot_t.read_fast_*), so that a read
     * response being built does not clobber the chain structs of one still
     * draining on the wire.
     */

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
    char    prepare_reqid[40];   /* FRM "<seq>.<pid>@<host>" (FRM_REQID_LEN) */
    u_char *prepare_paths;
    size_t  prepare_paths_len;

    /* Phase 35 / Phase 3 — async tape recall (kXR_waitresp → kXR_attn asynresp).
     * When frm_async_active is set during a replayed open of a just-staged file,
     * the open-OK emit goes out wrapped in kXR_attn(asynresp) on the saved
     * frm_async_streamid instead of a normal kXR_ok header. */
    unsigned  frm_async_active:1;
    u_char    frm_async_streamid[2];

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

    /* Phase 24 W3: data-write mirror accumulation (xrootd_wmirror_conn_t *).
     * NULL until a write-open occurs; freed by xrootd_stream_wmirror_cleanup()
     * on disconnect.  void* keeps the mirror type out of this header. */
    void       *wmirror;

    /* Protocol label and IP version — set at connection time, read-only thereafter. */
    char        protocol_label[8];  /* "root", "dav", or "s3"               */
    u_char      ip_version;         /* AF_INET (2) or AF_INET6 (10)     */

    /* Written by xrootd_auth_gate() on NGX_DONE; the calling handler must
     * return this value immediately.  Zero-initialised; only meaningful
     * immediately after an xrootd_auth_gate() call that returned NGX_DONE. */
    ngx_int_t   write_rc;

    /* Phase 25 — bandwidth charge target set by the rate-limit dispatch gate
     * for the current request; consumed by read/write completion via
     * xrootd_rl_charge_ctx().  rl_bw_rule is an xrootd_rl_rule_t* (void to keep
     * ratelimit.h out of this widely-included header). */
    void       *rl_bw_rule;
    char        rl_bw_key[128];

    /* Phase 25 W7 (stream) — per-principal concurrency slot held by THIS
     * connection.  Acquired once by the rate-limit dispatch gate on the first
     * matching xrootd_concurrency_limit rule and released exactly once in
     * xrootd_on_disconnect (the stream plane has no LOG phase), so it caps the
     * number of concurrent connections per principal.  Non-NULL rl_conc_rule
     * means a slot is held.  void* to keep ratelimit.h out of this header. */
    void       *rl_conc_rule;
    char        rl_conc_key[128];

    /* Phase 33 C4 — per-connection rate-limit key cache.  Identity-stable rules
     * (VO/ISSUER/IP/DN) yield a connection-constant key, so the stream dispatch
     * gate caches the first XROOTD_RL_RULE_CACHE_MAX such keys here and reuses
     * them instead of re-hashing per read.  rl_key_cache_valid is a bitmask:
     * bit i set ⇒ rl_key_cache[i] holds rule i's key.  VOLUME (path-dependent)
     * rules are never cached.  Zero-initialised ⇒ cold (recompute on first use). */
    char        rl_key_cache[XROOTD_RL_RULE_CACHE_MAX][128];
    uint32_t    rl_key_cache_valid;

    /*
     * Phase 39 — network-fault resilience (steady-state deadlines).
     *
     * read_deadline_armed / send_deadline_armed track whether THIS module armed
     * c->read / c->write's timer, so arm/disarm are idempotent no-ops: under
     * healthy back-to-back pipelined reads (avail >= need every time) the timer
     * is never armed, so the Phase-29 keep-reading branches never touch the
     * worker's timer rbtree.  A deadline is only ever armed on a *genuine*
     * incompletion / send park, and MUST be disarmed before recv hands off to
     * AIO/SENDING/UPSTREAM/PROXY/WAITING_* (else rev->timedout could fire and
     * finalize the session while an in-flight AIO task still references ctx).
     *
     * The merged timeouts are cached here at accept so the hot recv/park paths
     * avoid a srv_conf lookup.  0 = the corresponding deadline is disabled.
     */
    unsigned    read_deadline_armed:1;  /* 1 = we armed c->read's timer  */
    unsigned    send_deadline_armed:1;  /* 1 = we armed c->write's timer */
    ngx_msec_t  read_timeout_ms;        /* cached xrootd_read_timeout (0 = off)      */
    ngx_msec_t  handshake_timeout_ms;   /* cached xrootd_handshake_timeout (0 = off) */
    ngx_msec_t  send_timeout_ms;        /* cached xrootd_send_timeout (0 = off)      */

} xrootd_ctx_t;
