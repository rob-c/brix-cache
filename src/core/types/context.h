#ifndef BRIX_TYPES_CONTEXT_H
#define BRIX_TYPES_CONTEXT_H

/* ---- File: context.h — Per-connection session context (brix_ctx_t) ----
 *
 * WHAT: Defines brix_ctx_t — per-TCP-connection session context holding all state for the XRootD protocol lifecycle. Struct sections: input accumulation (hdr_buf[24] + hdr_pos for fixed header read, cur_streamid/cur_reqid/cur_body/cur_dlen for parsed header fields), payload accumulation (payload pointer + pos into reusable payload_buf with size guard, async handlers detach buf on completion), session auth state (sessid from kXR_login, logged_in/auth_done flags, login_user[9]/login_pid from client, auth_fail_count capped at BRIX_MAX_AUTH_ATTEMPTS, pool_bytes_used capped at BRIX_MAX_CONN_POOL_BYTES), authenticated identity (dn[512] GSI subject DN, primary_vo[128], vo_list[512] space-separated VOs, peer_ip[64]), open file table (brix_file_t[BRIX_MAX_FILES] — array index = XRootD file handle), pending flat-buffer send path (wbuf/wbuf_len/wbuf_pos/wbuf_base for EAGAIN tail storage + write event arm), pending chain send path (wchain remaining links + wchain_pending unsent bytes + wchain_base backing buffer, only one of wbuf or wchain active at a time), reusable response scratch buffers (read_scratch/read_hdr_scratch/write_scratch with size fields — malloc/realloc single buffer per session lifetime avoids pool growth), reusable thread-pool task (read_aio_task for memory-backed kXR_read TLS reads), reusable chain objects (read_fast_hdr/body_chain + hdr/body_buf + read_fast_file for common one-chunk response avoiding per-read allocation), GSI Diffie-Hellman key (gsi_dh_key generated at kXGS_cert freed after DH secret derivation at kXGC_cert), bearer-token auth state (token_auth flag + token_scope_count + token_scopes[BRIX_MAX_TOKEN_SCOPES]), per-request latency start time, prepare polling state (prepare_reqid/prepare_paths heap-allocated newline-separated path list), session-level transfer totals (session_bytes/session_bytes_written/session_bytes_tx_ipv4/ipv6/session_bytes_rx_ipv4/ipv6/session_start for access log at disconnect), metrics pointer to shared-memory segment, AIO destruction guard (destroyed=1 in on_disconnect prevents stale callback writes), TLS upgrade state (tls_pending=1 when kXR_haveTLS sent awaiting ClientHello), upstream redirector query pointer, proxy forwarding context pointer, raw bearer token [4096] for proxy forward, kXR_sigver request-signing lifecycle (signing_key HMAC-SHA256 from DH secret + signing_active/last_seqno replay guard + sigver_pending envelope fields + sigver_hmac verification + cached EVP_MAC/EVP_MAC_CTX handles), kXR_bind parallel-stream state (is_bound/pathid/bound_sessid for secondary data channel inheriting primary auth, lazy reopen of canonical path in own worker with device/inode validation), CMS locate suspension (cms_wait_streamid pending-table key), protocol label/IP version (read-only set at connection time).
 *
 * WHY: One instance per TCP connection allocated from nginx connection pool. State machine runs on single worker thread — XRootD multiplexing handled via streamid matching on client side, server serialises responses. Reusable scratch buffers and chain objects prevent pool growth in long-lived xrdcp sessions (malloc/realloc instead of ngx_palloc per-request). AIO destruction guard prevents post-disconnect callback writes to freed memory. TLS upgrade path intercepts next recv as ClientHello when kXR_haveTLS advertised. Bind connections lazily reopen primary's canonical path in own worker (nginx workers cannot share post-fork fd integers safely) and validate device/inode before serving data. Sigver lifecycle: kXGC_cert → signing_key=SHA-256(DH-secret)/active=1, sigver arrives → pending=1/envelope saved, next dispatch → HMAC verified/pending=0, replay guard → seqno > last_seqno.
 *
 * HOW: Struct layout — session pointer/state (lines 16-17) → input accumulation hdr_buf/hdr_pos (lines 24-26) → parsed header cur_streamid/cur_reqid/cur_body/cur_dlen (lines 28-31) → payload accumulation payload/payload_pos/payload_buf/payload_buf_size (lines 43-46) → session auth sessid/logged_in/auth_done/login_user/login_pid/auth_fail_count/pool_bytes_used (lines 59-65) → authenticated identity dn/primary_vo/vo_list/peer_ip (lines 68-71) → file table files[BRIX_MAX_FILES] (line 74) → flat-buffer send wbuf/wbuf_len/wbuf_pos/wbuf_base (lines 84-87) → chain send wchain/wchain_pending/wchain_base (lines 97-99) → scratch buffers read_scratch/read_hdr_scratch/write_scratch + sizes (lines 112-117) → aio task read_aio_task (line 124) → fast-chain objects read_fast_* (lines 131-135) → gsi_dh_key (line 142) → token auth token_auth/token_scope_count/token_scopes (lines 153-155) → req_start (line 158) → prepare polling prepare_reqid/prepare_paths/prepare_paths_len (lines 164-166) → session totals bytes/session_bytes_tx_ipv4/ipv6/session_bytes_rx_ipv4/ipv6/session_start (lines 169-175) → metrics pointer (line 179) → destroyed guard (line 187) → tls_pending (line 195) → upstream pointer (line 198) → proxy pointer (line 201) → bearer_token[4096] (line 208) → sigver signing_key/signing_active/last_seqno/sigver_* fields/EVP_MAC/EVP_MAC_CTX (lines 225-235) → bind is_bound/pathid/bound_sessid (lines 253-255) → cms_wait_streamid (line 258) → protocol_label/ip_version (lines 261-262). */

/*
 * Per-connection context (brix_ctx_t).
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
     * widened to BRIX_SLOT_HDR_MAX so a MULTI-chunk sendfile read also keeps
     * all its per-chunk ServerResponseHdrs here instead of the shared
     * read_hdr_scratch).  Owning the headers per-slot is what lets multiple
     * (single- or multi-chunk) reads pipeline without their headers clobbering
     * each other while a prior response is still draining.
     */
    u_char       hdr_bytes[BRIX_SLOT_HDR_MAX];
} brix_resp_slot_t;

/*
 * Phase 32 WS3 — concurrent-AIO read pipeline.
 *
 * A pool of per-in-flight-read buffers + thread tasks lets multiple
 * memory-backed kXR_reads be outstanding at once (pipelined) instead of the
 * single read_scratch / read_aio_task serial pair.  Each entry is owned by one
 * in-flight read from dispatch until the response it backs has fully drained
 * from its out_ring slot, at which point brix_release_read_buffer() returns it
 * to the pool.  Buffers are raw ngx_alloc'd (Phase-31 discipline) and freed on
 * disconnect.  rd_inflight counts entries currently in use.
 */
typedef struct {
    u_char            *buf;       /* raw-alloc'd data buffer (ngx_alloc/ngx_free) */
    size_t             size;      /* allocated size of buf */
    ngx_thread_task_t *task;      /* per-entry thread task (kXR_read AIO) */
    unsigned           in_use:1;  /* 1 while an in-flight read owns this entry */
} brix_read_slot_t;

/* Per-connection concern sub-structs (ctx->recv, ctx->gsi, ctx->out, ...).
 * Split into ctx_structs.h so brix_ctx_t reads as named groups; included after
 * the slot structs above and after this TU's prerequisite includes. */
#include "ctx_structs.h"

typedef struct brix_ctx_s {
    ngx_stream_session_t  *session;  /* nginx session; gives us c, pool, log */
    brix_state_t         state;    /* drives the read/write event callbacks */

    /* Request receive/framing state (header + payload accumulation) — see
     * brix_ctx_recv_t. */
    brix_ctx_recv_t  recv;

    /* Session login + authenticated-identity state — see brix_ctx_login_t. */
    brix_ctx_login_t  login;
    brix_sess_t      *sess;     /* lifecycle audit session; NULL when disabled */
    brix_sess_end_t   sess_end_hint;     /* explicit END reason from close sites */
    ngx_uint_t        sess_end_hint_set; /* 1 when sess_end_hint is meaningful */
    brix_identity_t *identity; /* canonical Phase 2 identity object */

    /* SciTags packet-marking flow handle (NULL = not marked); begun on the
     * first file open, ended on disconnect.  See src/pmark/. */
    brix_ctx_pmark_t  pmark;  /* SciTags packet-marking flow — see brix_ctx_pmark_t. */

    /* Open file table — array index IS the XRootD file handle (0-based) */
    brix_file_t  files[BRIX_MAX_FILES];

    /*
     * Output queue (Phase 29 pipelining).
     *
     * out_ring is a FIFO of response slots.  A response is built into the tail
     * slot (out_ring[out_tail]) and drained from the head slot
     * (out_ring[out_head]); out_count is the number of slots currently in use.
     * Each slot owns its own flat-buffer / chain send state and the reusable
     * one-chunk read-response chain structs (see brix_resp_slot_t), so
     * multiple responses can be in flight without aliasing each other's memory.
     *
     * Phase 1 lands the ring with effective depth 1: the recv loop stays serial
     * (it suspends on XRD_ST_SENDING), so out_head == out_tail == 0 throughout
     * and behaviour is identical to the previous single wbuf/wchain singletons.
     * Phase 2 raises the in-flight bound to ctx->out.pipeline_depth.
     *
     * out_ring/rd_pool are heap-allocated (c->pool) to pipeline_depth slots at
     * connection setup (handler.c); all ring arithmetic is modulo pipeline_depth.
     */
    /* Response ring + write-pipelining + deferred-teardown state — see brix_ctx_out_t. */
    brix_ctx_out_t  out;

    /* Read pipeline + reusable read/write/compression scratch buffers,
     * per-opcode AIO tasks, concurrent-read pool, and windowed-read
     * continuation — see brix_ctx_rd_t. */
    brix_ctx_rd_t  rd;

    /*
     * Phase 31 W4 — bytes this connection currently has charged to the global
     * transfer-heap budget (metrics->xfer_heap_in_use).  Reconciled idempotently
     * by brix_budget_sync(); released to 0 on disconnect.
     */
    size_t    budget_charged;


    /*
     * Reusable chain objects for the common one-chunk read response now live
     * per-slot in out_ring[] (brix_resp_slot_t.read_fast_*), so that a read
     * response being built does not clobber the chain structs of one still
     * draining on the wire.
     */

    /* GSI DH key + signed-DH selector + session cipher + X.509 proxy delegation
     * state (phase-48/57 §F6) — see brix_ctx_gsi_t. */
    brix_ctx_gsi_t  gsi;

    /*
     * Phase 52 (WS-B): XrdSecpwd multi-round handshake state.  Round 1 derives the
     * DH session key from the client's kXRS_puk and stores it here (16 bytes,
     * aes-128); round 2 decrypts the credential with it, so the ephemeral DH
     * keypair need not survive between rounds.  pwd_round counts rounds seen
     * (1 = puk-exchange done, awaiting creds).  pwd_user is the username asserted
     * in round 1, verified against the creds in round 2.
     */
    brix_ctx_pwd_t  pwd;  /* XrdSecpwd handshake state — see brix_ctx_pwd_t. */

    /*
     * Bearer-token auth state.
     *
     * token_auth=1 means this session was authenticated via a WLCG/SciToken
     * (not GSI).  The scopes extracted from the token are stored in token_scopes
     * and checked per-operation in open/write handlers.
     *
     * token_auth=0 with auth_done=1 means GSI was used; scopes are not relevant.
     */
    brix_ctx_token_t  token;  /* bearer-token auth state — see brix_ctx_token_t. */

    /* phase-59 W3a: XrdThrottle per-user accounting state for this connection.
     * throttle_open_held = open-file increments this conn holds (so disconnect
     * decrements exactly that many); throttle_conn_counted = this conn has been
     * counted toward the per-user active-connection total. */
    brix_ctx_throttle_t   throttle;  /* per-user throttle accounting — see brix_ctx_throttle_t. */

    /* Per-request start time for latency logging */
    ngx_msec_t  req_start;

    /* kXR_prepare/kXR_stage polling + async tape recall — see brix_ctx_prepare_t. */
    brix_ctx_prepare_t  prepare;

    /* Session-level transfer totals written to the access log at disconnect */
    brix_ctx_totals_t  totals;  /* session transfer totals — see brix_ctx_totals_t. */

    /* Points into the shared-memory metrics segment for this server slot.
     * NULL if metrics are not configured (brix_metrics_zone not set). */
    ngx_brix_srv_metrics_t  *metrics;

    /*
     * AIO destruction guard.
     * Set to 1 in brix_on_disconnect() so that a thread-pool callback
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
    brix_upstream_t  *upstream;

    /* Proxy forwarding context (NULL when proxy not active for this session) */
    brix_proxy_ctx_t *proxy;

    /*
     * Consecutive upstream-bootstrap failures on THIS client connection.
     * Each lazy proxy (re)connect that aborts before the upstream accepted the
     * forwarded credential increments this; a successful bootstrap resets it to
     * 0.  When it reaches BRIX_PROXY_MAX_CONN_FAILS the dispatch path stops
     * spawning fresh proxy contexts and fails the request instead — without this
     * bound a permanently-rejecting upstream (e.g. a bad SSS keytab) drives an
     * unbounded reconnect loop that re-allocates a proxy ctx on c->pool every
     * event-loop tick (CPU spin + multi-GB pool growth that never frees until
     * the connection closes).
     */
    ngx_uint_t proxy_fail_count;

    /*
     * Raw bearer token saved during kXR_auth token validation so the proxy can
     * forward it to the upstream when brix_proxy_auth forward is set.
     * Empty string when the client authenticated via GSI or anonymously.
     */
    char  bearer_token[4096];

    /*
     * Optional client-supplied FULL x509 proxy (cert chain + private key, PEM),
     * captured during the GSI kXGC_cert exchange when the client opts in
     * (phase-70 §5.1, kXRS_x509_fullproxy). Empty len when absent. Populated
     * ONLY after (a) the transport is TLS, (b) the PEM parses to a chain + key,
     * and (c) the leaf/EEC DN equals the GSI-authenticated ctx->login.dn — so a
     * session can never present a proxy for a different identity. The root://
     * VFS binder forwards these bytes to brix_vfs_deleg_bind for backend
     * PASSTHROUGH. Bytes live in c->pool. NEVER logged.
     */
    ngx_str_t  deleg_proxy_pem;

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
    brix_ctx_sigver_t  sigver;  /* kXR_sigver request-signing state — see brix_ctx_sigver_t. */

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
    u_char  bound_sessid[BRIX_SESSION_ID_LEN]; /* primary session we bound to */

    /* CMS locate suspension (state == XRD_ST_WAITING_CMS) */
    uint32_t    cms_wait_streamid;  /* pending-table key for removal on timeout */

    /* Phase 24 W3: data-write mirror accumulation (brix_wmirror_conn_t *).
     * NULL until a write-open occurs; freed by brix_stream_wmirror_cleanup()
     * on disconnect.  void* keeps the mirror type out of this header. */
    void       *wmirror;

    /* Protocol label and IP version — set at connection time, read-only thereafter. */
    char        protocol_label[8];  /* "root", "dav", or "s3"               */
    u_char      ip_version;         /* AF_INET (2) or AF_INET6 (10)     */

    /* Written by brix_auth_gate() on NGX_DONE; the calling handler must
     * return this value immediately.  Zero-initialised; only meaningful
     * immediately after an brix_auth_gate() call that returned NGX_DONE. */
    ngx_int_t   write_rc;

    /* Per-connection rate-limit state (Phase 25/33) — see brix_ctx_rl_t. */
    brix_ctx_rl_t  rl;

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
    brix_ctx_deadline_t  deadline;  /* network-fault deadlines — see brix_ctx_deadline_t. */

    /*
     * Single-port protocol handoff (src/handoff/handoff.c): when a non-XRootD
     * (HTTP/TLS) client arrives on this stream port and brix_http_handoff is
     * configured, the connection is spliced to a local HTTP/WebDAV listener.
     * Opaque brix_handoff_t* — the hub the client-side relay handlers reach
     * via s -> ctx -> handoff (the upstream side reaches it via uconn->data).
     */
    void       *handoff;

    /*
     * Transparent relay (src/relay/relay.c): when brix_transparent_proxy is
     * configured, the connection is relayed verbatim to an upstream XRootD server
     * while a tap decodes the cleartext frames. Opaque brix_relay_t* — reached
     * by the client-side relay handlers via s -> ctx -> relay (upstream side via
     * uconn->data), mirroring the handoff hub above.
     */
    void       *relay;

} brix_ctx_t;

#endif /* BRIX_TYPES_CONTEXT_H */
