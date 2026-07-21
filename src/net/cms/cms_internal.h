#ifndef NGX_BRIX_CMS_INTERNAL_H
#define NGX_BRIX_CMS_INTERNAL_H

#include "core/ngx_brix_module.h"
#include "meter.h"

/*
 * Timing and sizing constants for the CMS heartbeat client.
 *
 *   INITIAL_DELAY   — ms to wait before the first connection attempt after
 *                     the worker starts (lets nginx finish binding ports first).
 *   BACKOFF_INITIAL — ms for the first reconnect delay after a disconnect.
 *   BACKOFF_MAX     — maximum reconnect delay (60 s).
 *   CONNECT_TIMEOUT — ms before TCP connect is considered failed.
 *   HDR_LEN         — fixed-size CMS frame header (8 bytes).
 *   MAX_FRAME       — maximum CMS payload size (4096 bytes).
 *   MIN_FREE_MB     — if free space is below this threshold, report 0 (suspend).
 */
#define NGX_BRIX_CMS_INITIAL_DELAY   1000
#define NGX_BRIX_CMS_BACKOFF_INITIAL 6000
#define NGX_BRIX_CMS_BACKOFF_MAX     60000
#define NGX_BRIX_CMS_CONNECT_TIMEOUT 5000

/*
 * Fast cold-start mesh settling (src/cms/connect.c).  When a whole cluster boots
 * together — most acutely on one host — a node's first connect often races ahead of
 * its manager's listen socket and is refused.  Instead of jumping straight to the
 * multi-second reconnect backoff, a node that has NEVER yet logged in retries the
 * TCP connect on a short fixed interval for a bounded window, then falls back to the
 * normal exponential backoff.  Two locality profiles; an explicit
 * brix_cms_initial_delay / brix_cms_connect_retry directive overrides the
 * matching default.  The interval floor and the bounded window are what keep this
 * from ever becoming a busy-spin (cf. the self-rearming-0ms-timer footgun).
 */
/* When a logged-in data server drops its CMS link, blacklist host:port for this
 * long (ms) so in-flight locate replies skip the departed node; cleared early on
 * a successful re-register (src/cms/server_recv.c). */
#define NGX_BRIX_CMS_SRV_DROP_BLACKLIST_MS  30000

#define NGX_BRIX_CMS_INITDELAY_LOOPBACK   0      /* loopback: connect immediately */
#define NGX_BRIX_CMS_INITDELAY_REMOTE     10     /* remote: tiny settle margin     */
#define NGX_BRIX_CMS_FASTRETRY_LOOPBACK   10     /* loopback retry interval (ms)   */
#define NGX_BRIX_CMS_FASTRETRY_REMOTE     75     /* remote retry interval (ms)     */
#define NGX_BRIX_CMS_FASTRETRY_FLOOR      10     /* never retry faster than this   */
#define NGX_BRIX_CMS_FASTWIN_LOOPBACK     2000   /* loopback fast-retry window (ms)*/
#define NGX_BRIX_CMS_FASTWIN_REMOTE       3000   /* remote fast-retry window (ms)  */
#define NGX_BRIX_CMS_HDR_LEN         8
#define NGX_BRIX_CMS_MAX_FRAME       4096
/*
 * Phase 51 (A2): max complete frames processed per read-event wakeup before the
 * handler yields (re-posts its read event) so one peer flooding frames on a
 * single connection cannot monopolise the worker event loop.  Generous — a
 * conformant manager/node never sends this many frames back-to-back.
 */
#define NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP  64
#define NGX_BRIX_CMS_MIN_FREE_MB     100

/*
 * CMS request/reply opcodes (kYR_* from the CMS protocol).
 * Numeric values are wire constants; do not renumber.
 */
#define CMS_RR_LOGIN   0    /* kYR_login: announce server identity to manager */
#define CMS_RR_CHMOD   1    /* kYR_chmod: forwarded mode change */
#define CMS_RR_LOCATE  2    /* kYR_locate: ask manager which server has a path */
#define CMS_RR_MKDIR   3    /* kYR_mkdir: forwarded directory create */
#define CMS_RR_MKPATH  4    /* kYR_mkpath: forwarded recursive directory create */
#define CMS_RR_MV      5    /* kYR_mv: forwarded rename */
#define CMS_RR_PREPADD 6    /* kYR_prepadd: forwarded stage-in request */
#define CMS_RR_PREPDEL 7    /* kYR_prepdel: forwarded stage cancel */
#define CMS_RR_RM      8    /* kYR_rm: forwarded file unlink */
#define CMS_RR_RMDIR   9    /* kYR_rmdir: forwarded directory remove */
#define CMS_RR_STATS   11   /* kYR_stats: cluster stats query */
#define CMS_RR_DISC    13   /* kYR_disc: graceful disconnect notification */
#define CMS_RR_STATFS  21   /* kYR_statfs: space query for a path */
#define CMS_RR_TRUNC   23   /* kYR_trunc: forwarded truncate */
#define CMS_RR_UPDATE  25   /* kYR_update: request peer resend its state */
#define CMS_RR_USAGE   26   /* kYR_usage: load/usage query */

/*
 * CMS response codes (CmsRspCode) — carried in CmsRRHdr.rrCode on a REPLY frame.
 * Distinct numeric space from the request codes above (disambiguated by
 * direction); do not renumber.  Used by forwarded-op replies (Plane B).
 */
#define CMS_RSP_DATA   0    /* kYR_data: reply carries data */
#define CMS_RSP_ERROR  1    /* kYR_error: reply carries [4B ecode][text] */
#define CMS_RSP_WAIT   3    /* kYR_wait: reply carries [4B delay-seconds] */

/*
 * CMS error codes (CmsErrorCode) — the 4-byte big-endian value at the head of a
 * kYR_error payload.  Stock cmsd's XrdCmsProtocol::Execute always replies to a
 * failed forwarded op with kYR_EINVAL and the strerror() text, so that is the
 * only code a forwarded-op reply needs.
 */
#define CMS_ERR_EINVAL 4    /* kYR_EINVAL */
#define CMS_RR_AVAIL   12   /* kYR_avail: report available files for a path */
#define CMS_RR_GONE    14   /* kYR_gone: data server path-level deregister */
#define CMS_RR_HAVE    15   /* kYR_have: server tells manager it holds a path */
#define CMS_RR_LOAD    16   /* kYR_load: periodic load/space heartbeat */
#define CMS_RR_SELECT  10   /* kYR_select: manager redirect reply (single host) */
#define CMS_RR_PING    17   /* kYR_ping: manager liveness probe */
#define CMS_RR_PONG    18   /* kYR_pong: reply to kYR_ping */
#define CMS_RR_SPACE   19   /* kYR_space: request available disk space stats */
#define CMS_RR_STATE   20   /* kYR_state: manager asks "do you have <path>?" */
#define CMS_RR_STATUS  22   /* kYR_status: suspend/resume traffic control */
#define CMS_RR_TRY     24   /* kYR_try: manager redirect reply (ordered list) */
#define CMS_RR_XAUTH   27   /* kYR_xauth: security handshake (sss credential) */

/*
 * kYR_status modifier bits (real XrdCms CmsStatusRequest values — do not renumber).
 * The data node sends kYR_status(Resume|noStage) after login so the manager marks
 * it active and eligible for selection.
 */
#define CMS_ST_STAGE    0x01   /* staging available */
#define CMS_ST_NOSTAGE  0x02   /* staging unavailable (disk-only node) */
#define CMS_ST_RESUME   0x04   /* resume accepting requests */
#define CMS_ST_SUSPEND  0x08   /* stop accepting new requests */
#define CMS_ST_RESET    0x10   /* reset state */

/*
 * Request modifier bits (CmsReqModifier). kYR_raw marks an unmarshalled
 * (non-Pup) payload — used for the raw path in kYR_state / kYR_have, and the
 * Online flag a server sets in kYR_have to signal the file is resident.
 */
#define CMS_MOD_RAW     0x20   /* payload is raw (not Pup-encoded) */
#define CMS_HAVE_ONLINE 0x01   /* kYR_have modifier: file is online/resident */

/*
 * CMS variable-length encoding type tags.
 * Fields in CMS frames are packed with a leading type byte followed by the
 * big-endian value.  These tags identify short (2-byte) vs int (4-byte) values.
 */
#define CMS_PT_SHORT   0x80   /* 2-byte big-endian value follows */
#define CMS_PT_INT     0xa0   /* 4-byte big-endian value follows */

/*
 * kYR_try sub-reason codes (Phase-89 W5 vocabulary; YProtocol CmsSelectRequest
 * opts bits, 32-bit — NOT the 1-byte frame modifier).  A stock cmsd encodes
 * WHY it bounced a select into these bits of the try/redirect response.  In
 * this topology clients speak XRootD to the manager (registry select →
 * kXR_redirect on the root plane; the CMS server plane has no select
 * dispatch), so nothing here EMITS them yet — they are the conformance
 * vocabulary for decoding a stock parent's replies and for a future select
 * plane, kept beside the other wire constants so any emitter shares one truth.
 */
#define CMS_TRY_MISS   0x00000000   /* kYR_tryMISS: file not found            */
#define CMS_TRY_IOER   0x00010000   /* kYR_tryIOER: I/O error on the server   */
#define CMS_TRY_FSER   0x00020000   /* kYR_tryFSER: filesystem error          */
#define CMS_TRY_SVER   0x00030000   /* kYR_trySVER: server error              */
#define CMS_TRY_MASK   0x00030000   /* mask over the reason bits              */
#define CMS_TRY_SHFT   16           /* shift to extract the reason value      */
#define CMS_TRY_RSEL   0x00040000   /* kYR_tryRSEL: retry the selection       */
#define CMS_TRY_RSEG   0x00080000   /* kYR_tryRSEG: retry within the segment  */

/*
 * Login packet constants.
 *   VERSION       — CMS protocol version sent in kYR_login.
 *   MODE          — kYR_DataServer flag: this node exports data files.
 *   MODE_MANAGER  — kYR_Manager flag: this node also manages data servers.
 */
#define CMS_LOGIN_VERSION       3
#define CMS_LOGIN_MODE          0x00000008  /* kYR_server: this node exports data */
#define CMS_LOGIN_MODE_MANAGER  0x00000002  /* kYR_manager: also manages servers
                                             * (real LoginMode bit; 0x10 is proxy) */

/*
 * Per-manager CMS heartbeat context (one instance per CMS manager address).
 *
 * Lifetime: heap-allocated in each worker's init_process hook (each nginx
 * worker maintains its own independent CMS connection to the parent manager)
 * and freed when the worker exits.
 */
struct ngx_brix_cms_ctx_s {
    ngx_cycle_t                    *cycle;       /* nginx cycle (for pool, log) */
    ngx_stream_brix_srv_conf_t   *conf;        /* server block configuration */
    ngx_peer_connection_t           peer;        /* nginx upstream peer state */
    ngx_connection_t               *connection;  /* active TCP connection (NULL = disconnected) */
    brix_sess_t                    *sess;        /* lifecycle audit session */
    brix_sess_end_t                 sess_end_hint;
    ngx_uint_t                      sess_end_hint_set;
    ngx_uint_t                      sess_attempt_logged;
    ngx_event_t                     timer;       /* reconnect / heartbeat timer */
    ngx_msec_t                      backoff;     /* current reconnect wait (ms) */
    ngx_uint_t                      logged_in;   /* 1 after kYR_login exchange */

    /* Fast cold-start settling state (resolved once at ngx_brix_cms_start). */
    ngx_msec_t                      fast_retry;     /* resolved retry interval (ms) */
    ngx_msec_t                      fast_window;    /* resolved fast-retry window   */
    ngx_msec_t                      fast_deadline;  /* ngx_current_msec end of the
                                                       fast-retry window; 0 = unstarted */
    ngx_uint_t                      ever_logged_in; /* sticky: 1 after first login  */
    ngx_uint_t                      connect_attempts; /* TCP connect tries this boot */
    uint64_t                        start_ns;       /* ctx creation (settle timing) */
    unsigned                        is_loopback:1;  /* manager addr is loopback     */
    uint32_t                        next_streamid; /* per-worker monotone counter;
                                                      wraps at UINT32_MAX; used as
                                                      CMS locate correlation key */
    brix_cms_meter_t                meter;       /* Phase-89 W4 heartbeat load
                                                    meter (all-zeroes valid) */
    u_char                          inbuf[NGX_BRIX_CMS_MAX_FRAME]; /* receive accumulation buffer */
    size_t                          in_pos;      /* bytes received so far */
    size_t                          in_need;     /* bytes needed to complete the frame */
};

/* wire.c — big-endian encode/decode */

/* Read a big-endian uint16 from the 2 bytes at p (read-only, no bounds check —
 * caller guarantees >=2 readable bytes). */
uint16_t  ngx_brix_cms_get16(const u_char *p);
/* Read a big-endian uint32 from the 4 bytes at p (read-only, no bounds check —
 * caller guarantees >=4 readable bytes). */
uint32_t  ngx_brix_cms_get32(const u_char *p);
/* Write value big-endian into the 2 bytes at p (caller owns >=2 writable bytes). */
void      ngx_brix_cms_put16(u_char *p, uint16_t value);
/* Write value big-endian into the 4 bytes at p (caller owns >=4 writable bytes). */
void      ngx_brix_cms_put32(u_char *p, uint32_t value);
/* Emit a Pup-tagged short (CMS_PT_SHORT byte + 2B big-endian value); writes 3
 * bytes at p and returns the cursor advanced past them so writes can be chained. */
u_char   *ngx_brix_cms_put_short(u_char *p, uint16_t value);
/* Emit a Pup-tagged int (CMS_PT_INT byte + 4B big-endian value); writes 5 bytes
 * at p and returns the cursor advanced past them. */
u_char   *ngx_brix_cms_put_int(u_char *p, uint32_t value);
/* Emit an XrdOucPup packed string [2B BE len][data][NUL] (len counts the NUL);
 * NULL/zero-length data writes a bare 2-byte zero length. No type tag — the wire
 * parser tells string from scalar by the absence of the 0x80 bit. Copies data
 * (borrows, does not retain). Returns the advanced cursor. */
u_char   *ngx_brix_cms_put_string(u_char *p, const u_char *data, size_t len);

/* space.c — filesystem space measurement */

/* Return the path(s) this node exports to the manager: conf->cms.paths if set,
 * else conf->common.root. Returns the ngx_str_t by value but its .data still
 * borrows conf-owned memory (do not free; valid for the config lifetime). */
ngx_str_t  ngx_brix_cms_export_paths(ngx_stream_brix_srv_conf_t *conf);
/* statvfs the export root and fill any non-NULL out params: total_gb (GiB),
 * free_mb (MiB available), util_pct (0-100 used). Returns NGX_OK, or NGX_ERROR
 * if statvfs fails or the fs reports zero blocks (out params left untouched). */
ngx_int_t  ngx_brix_cms_stat_space(ngx_stream_brix_srv_conf_t *conf,
               uint32_t *total_gb, uint32_t *free_mb, uint32_t *util_pct);

/* send.c — outgoing CMS frames.
 * All send_* build a frame and write it on ctx->connection; they return NGX_OK
 * on a full send, else NGX_ERROR (e.g. partial/failed write or payload overflow).
 * Each requires ctx->connection to be a live, logged-in socket. */

/* Send the kYR_login frame (streamid 0): version, mode, PID, space stats, listen
 * port, exported paths. Calls stat_space (and aggregates space in manager mode). */
ngx_int_t  ngx_brix_cms_send_login(ngx_brix_cms_ctx_t *ctx);
/* Send a kYR_load heartbeat (streamid 0) reporting free space; zero CPU/net/etc
 * load bytes. Aggregates space across servers in manager mode. */
ngx_int_t  ngx_brix_cms_send_load(ngx_brix_cms_ctx_t *ctx);
/* Reply to a kYR_space query with free_mb + util_pct, echoing the request's
 * streamid. */
ngx_int_t  ngx_brix_cms_send_avail(ngx_brix_cms_ctx_t *ctx,
               uint32_t streamid);
/* Reply to a kYR_ping with an empty kYR_pong, echoing the request's streamid. */
ngx_int_t  ngx_brix_cms_send_pong(ngx_brix_cms_ctx_t *ctx,
               uint32_t streamid);
/* Send a header-only kYR_status(Resume|noStage) (streamid 0) so the manager
 * marks this disk-only node active and eligible for selection. */
ngx_int_t  ngx_brix_cms_send_status(ngx_brix_cms_ctx_t *ctx);
/* Reply to a kYR_state query with kYR_have(RAW|Online): the raw NUL-terminated
 * path (borrowed, copied into a stack buffer) echoing streamid. Returns NGX_ERROR
 * if path_len+1 exceeds the internal path buffer. */
ngx_int_t  ngx_brix_cms_send_have(ngx_brix_cms_ctx_t *ctx,
               uint32_t streamid, const char *path, size_t path_len);
/* Send a kYR_locate asking the manager which node owns path (NUL-terminated C
 * string, borrowed). streamid correlates the later reply. Returns NGX_ERROR if
 * the path (incl. NUL) overflows the internal buffer. */
ngx_int_t  ngx_brix_cms_send_locate(ngx_brix_cms_ctx_t *ctx,
               uint32_t streamid, const char *path);
/* Return the next outgoing streamid, incrementing ctx->next_streamid and wrapping
 * UINT32_MAX -> 1 (never returns 0, which is reserved for unsolicited frames). */
uint32_t   ngx_brix_cms_next_streamid(ngx_brix_cms_ctx_t *ctx);

/* Reply kYR_error to a failed forwarded op (Plane B): [4B BE ecode][text+NUL],
 * echoing streamid.  Byte-exact with cmsd Reply_Error. NGX_OK / NGX_ERROR. */
ngx_int_t  ngx_brix_cms_send_error(ngx_brix_cms_ctx_t *ctx,
               uint32_t streamid, uint32_t ecode, const char *text);

/* recv.c — incoming frame read loop and dispatch */

/* nginx read-event handler for the CMS socket (ev->data is the connection, whose
 * ->data is the ctx). Drains the socket, reassembles header+payload frames into
 * ctx->inbuf, and dispatches each opcode (ping->pong, space->avail, status,
 * select/try redirect). On timeout/EOF/error it disconnects and schedules a retry.
 * Self-guards if the event no longer matches the active connection. */
void  ngx_brix_cms_read_handler(ngx_event_t *ev);

/* connect.c — TCP connection lifecycle, timer, entry point */

/* Close the active connection (if any), drop its read/write timers, and reset
 * ctx state (connection=NULL, logged_in=0, inbuf cursors). Safe to call when
 * already disconnected (no-op). Does NOT schedule a reconnect — caller must. */
void  ngx_brix_cms_set_end_hint(ngx_brix_cms_ctx_t *ctx,
          brix_sess_end_t why);
void  ngx_brix_cms_disconnect(ngx_brix_cms_ctx_t *ctx);
/* Arm (replacing any pending) the ctx heartbeat/reconnect timer to fire in delay
 * milliseconds. */
void  ngx_brix_cms_schedule(ngx_brix_cms_ctx_t *ctx, ngx_msec_t delay);
/* Schedule a reconnect using the current backoff, then double the backoff toward
 * the cap (min of 10x cms_interval and BACKOFF_MAX=60s). Call after a failure. */
void  ngx_brix_cms_schedule_retry(ngx_brix_cms_ctx_t *ctx);

/* Phase 50 (WS1): (re)arm the manager-inactivity read deadline on the live CMS
 * socket.  Measures bounded silence since the last manager activity / our last
 * heartbeat; on expiry recv.c's ev->timedout path disconnects and reconnects with
 * backoff, so a black-holed/half-open manager is detected and failed over.  No-op
 * when disconnected or when conf->cms.read_timeout is 0 (disabled). */
void  ngx_brix_cms_arm_read_deadline(ngx_brix_cms_ctx_t *ctx);

#endif /* NGX_BRIX_CMS_INTERNAL_H */
