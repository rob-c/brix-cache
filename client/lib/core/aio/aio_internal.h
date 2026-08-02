/*
 * aio_internal.h - private split contract for aio.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_AIO_INTERNAL_H
#define BRIX_AIO_INTERNAL_H

#include "aio.h"
#include "uring.h"                 
#include "protocols/root/protocol/frame_hdr.h"   
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if (BRIX_HAVE_LIBURING)
#include <liburing.h>
#endif
#define AIO_MAXEV      64
#define AIO_URING_SLOTS 128
#define AIO_READ_CHUNK 65536u
#define AIO_TICK_MS    1000

/* Phase-44 ii-b (P44-C): cleartext RECV/SEND multishot tier. */
#define AIO_URING_BGID_RX   1        /* provided-buffer group id (receive)     */
#define AIO_URING_RXBUFS    32u      /* provided buffers (power of two)        */
#define AIO_URING_RXBUF_SZ  32768u   /* bytes per provided buffer              */
#define AIO_URING_STAGE_SZ  65536u   /* per-conn send staging slice            */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   start;
    size_t   len;
} xbuf;

typedef struct brix_areq {
    uint16_t    sid;
    uint8_t     hdr[XRD_REQUEST_HDR_LEN];
    uint8_t    *payload;     /* owned copy, or NULL */
    uint32_t    plen;

    uint8_t    *acc;         /* accumulated reply body (owned until delivered) */
    uint32_t    acc_len;
    uint32_t    acc_cap;

    brix_aio_cb cb;
    void       *ctx;
    uint64_t    deadline_ns; /* 0 = none */

    /* resilience (M2) */
    int         retry_safe;  /* may be re-issued verbatim after a reconnect */
    int         retries_left;/* transport re-issues remaining */
    int         is_ping;     /* internal keepalive heartbeat (no user cb) */
    int         deferred;    /* server sent kXR_waitresp; reply arrives as an
                              * unsolicited kXR_attn(asynresp) — completion is
                              * NOT an RTT sample (it measures the deferral) */
    uint64_t    submit_ns;   /* when the current attempt was written (RTT sample) */
    struct brix_areq *pend_next;  /* link in the aconn pending (re-issue) list */
} brix_areq;

#define REQMAP_TOMB ((brix_areq *) -1)
typedef struct {
    brix_areq **slots;
    uint32_t    cap;        /* power of two */
    uint32_t    count;      /* live entries */
    uint32_t    tomb;       /* tombstones */
} reqmap;

typedef enum {
    ACONN_ALIVE = 0,    /* normal: doing I/O on a healthy socket */
    ACONN_RECONNECTING, /* socket dropped; a worker thread is re-establishing it */
    ACONN_DEAD          /* reconnect budget exhausted; no recovery */
} aconn_state;

struct brix_aconn {
    brix_loop     *loop;
    brix_conn     *conn;     /* borrowed brought-up session */
    int            fd;
    struct ssl_st *ssl;      /* mirrors conn->io.ssl (NULL = cleartext) */
    uint16_t       next_sid;

    xbuf           wbuf;     /* outgoing serialized frames */
    xbuf           rbuf;     /* incoming bytes being parsed */
    reqmap         inflight;

    int            epoll_events;          /* currently registered interest */
    int            uring_slot;            /* phase-44: io_uring poll-slot idx, or -1 */
    uint32_t       fd_gen;                /* phase-44: bumped per (re)arm; guards CQEs */
    int            dead;                  /* socket not usable right now */
    int            tls_want_write_on_read;/* SSL_read returned WANT_WRITE */
    int            tls_want_read_on_write;/* SSL_write returned WANT_READ */

    /* resilience (M2) */
    aconn_state    state;
    int            max_stall_ms;          /* reconnect patience budget */
    int            keepalive_ms;          /* idle-before-heartbeat (0=off) */
    int            def_retries;           /* default per-request retry budget */
    uint64_t       last_activity_ns;      /* last frame heard from the server */
    uint64_t       srtt_ns, rttvar_ns;    /* RTT EWMA (TCP-style) */
    int            have_rtt;              /* srtt seeded */
    int            ping_inflight;         /* heartbeat ping outstanding */
    uint64_t       reconnect_deadline_ns; /* give up reconnecting past this */
    brix_areq     *pending;               /* parked requests awaiting re-issue */

    /* reconnect worker handoff (worker writes rc_*, loop polls rc_finished) */
    pthread_t      rc_thread;
    int            rc_thread_live;
    volatile int   rc_finished;           /* set by worker just before it returns */
    int            rc_result;             /* 0 = reconnected, -1 = gave up */
    brix_status    rc_st;                 /* failure detail when rc_result < 0 */

    struct brix_aconn *next; /* loop->aconns singly-linked list */
};

typedef enum {
    CMD_ADD_ACONN,
    CMD_SUBMIT,
    CMD_CLOSE_ACONN,
    CMD_STOP
} cmd_type;

typedef struct cmd {
    cmd_type     type;
    brix_aconn  *ac;

    /* SUBMIT payload (header copied inline; payload owned, moved into the areq) */
    uint8_t      hdr[XRD_REQUEST_HDR_LEN];
    uint8_t     *payload;
    uint32_t     plen;
    brix_aio_cb  cb;
    void        *ctx;
    int          deadline_ms;
    int          max_retries;   /* < 0 ⇒ aconn default */
    int          retry_safe;    /* idempotent + not handle-bound */

    /* synchronous control ops signal the caller through these (NULL for SUBMIT) */
    pthread_mutex_t *dmx;
    pthread_cond_t  *dcv;
    int             *done;

    struct cmd  *next;
} cmd;

struct brix_poll_slot {
    brix_aconn *ac;
    uint32_t    gen;
    int         in_use;

    /* Phase-44 ii-b (P44-C): engine-owned cleartext RECV/SEND state.  Lives in
     * the slot (not the aconn) so brix_aconn keeps fd_gen as its single
     * phase-44 addition (§13.6). */
    int         rxtx;          /* 1 = this conn runs multishot RECV/SEND     */
    int         recv_armed;    /* multishot RECV outstanding for current gen */
    int         send_inflight; /* one-shot SEND outstanding                  */
    uint8_t    *stage;         /* lazily-malloc'd send staging slice         */
    uint32_t    stage_len;     /* bytes handed to the in-flight SEND         */
};

struct brix_loop {
    int             epfd;
    int             evfd;
    pthread_t       thread;
    int             thread_ok;

    pthread_mutex_t cq_lock;
    cmd            *cq_head;
    cmd            *cq_tail;

    brix_aconn     *aconns;   /* loop-thread-owned list */
    int             stop;

    int             use_uring; /* phase-44: loop engine is io_uring (default 0) */
    int             use_rxtx;  /* phase-44 ii-b: cleartext RECV/SEND multishot  */
#if (BRIX_HAVE_LIBURING)
    struct io_uring uring;
    int             uring_ok;  /* ring initialized (teardown guard)             */
    struct brix_poll_slot uslots[AIO_URING_SLOTS];
    struct io_uring_buf_ring *brx;      /* provided-buffer ring (BGID_RX)       */
    uint8_t                  *brx_pool; /* its backing memory (RXBUFS * SZ)     */
#endif
};

#if (BRIX_HAVE_LIBURING)
#define AIO_URING_EVFD_UD    0xffffffffffffffffULL  /* evfd readiness poll       */
#define AIO_URING_IGNORE_UD  0xfffffffffffffffeULL  /* cancel-ack CQE (drop)     */

/* Slot-CQE user_data packing: (gen << 32) | (kind << 30) | slot.  Slots are
 * < AIO_URING_SLOTS (128) so bits 30-31 are free for the op kind; the legacy
 * poll encoding is unchanged (kind 0).  P44-C adds RECV/SEND kinds. */
#define AIO_UD_POLL  0u
#define AIO_UD_RECV  1u
#define AIO_UD_SEND  2u
#define AIO_URING_UD(kind, gen, slot) \
    (((uint64_t) (gen) << 32) | ((uint64_t) (kind) << 30) | (uint64_t) (slot))
#define AIO_UD_SLOT(ud)  ((uint32_t) ((ud) & 0x3fffffffULL))
#define AIO_UD_KIND(ud)  ((uint32_t) (((ud) >> 30) & 3u))
#define AIO_UD_GEN(ud)   ((uint32_t) ((ud) >> 32))
#endif /* BRIX_HAVE_LIBURING */
typedef struct {
    pthread_mutex_t mx;
    pthread_cond_t  cv;
    int             done;
    int             rc;
    uint16_t        kxr;
    uint8_t        *body;
    uint32_t        blen;
    brix_status     st;
} call_wait;


/* aio_buffers.c */
int xbuf_reserve(xbuf *b, size_t need);
int xbuf_append(xbuf *b, const void *data, size_t n);
void xbuf_compact(xbuf *b);
void xbuf_free(xbuf *b);
void areq_free(brix_areq *r);
int areq_accumulate(brix_areq *r, const uint8_t *body, uint32_t n);
void areq_complete(brix_areq *r, int rc, uint16_t kxr, const brix_status *st);
int reqmap_rehash(reqmap *m, uint32_t newcap);
int reqmap_put(reqmap *m, brix_areq *r);
brix_areq * reqmap_get(reqmap *m, uint16_t sid);
void reqmap_del(reqmap *m, uint16_t sid);

/* aio_io.c */
void aconn_do_write(brix_aconn *ac);
void aconn_note_rtt(brix_aconn *ac, const brix_areq *r);
uint64_t aconn_rto_ns(const brix_aconn *ac);
void aconn_dispatch_frame(brix_aconn *ac, uint16_t sid, uint16_t stat, const uint8_t *body, uint32_t dlen);
void aconn_parse(brix_aconn *ac);
void aconn_do_read(brix_aconn *ac);
void aconn_handle_io(brix_aconn *ac, uint32_t events);

/* aio_engine.c */
#if (BRIX_HAVE_LIBURING)
unsigned uring_pollmask(int want);
int uring_slot_alloc(brix_loop *l, brix_aconn *ac);
int uring_poll_submit(brix_loop *l, brix_aconn *ac, int want);
void uring_poll_cancel(brix_loop *l, brix_aconn *ac, int freeing);
int uring_rxtx_send_submit(brix_loop *l, brix_aconn *ac);
/* submit-side helpers shared with the Phase-38 CQE split sibling
 * (aio_engine_cqe.c): re-arm recv + recycle an exhausted rxtx recv buffer. */
int uring_recv_submit(brix_loop *l, brix_aconn *ac);
void uring_rxtx_recycle(brix_loop *l, struct io_uring_cqe *cqe);
/* aconn_is_rxtx — true when this conn's bytes move via the cleartext
 * RECV/SEND multishot tier (P44-C): loop engine is io_uring with the rxtx
 * tier enabled and the conn is not TLS. */
static inline int
aconn_is_rxtx(const brix_aconn *ac)
{
    return ac->loop != NULL && ac->loop->use_uring && ac->loop->use_rxtx
           && ac->ssl == NULL;
}
#else
static inline int aconn_is_rxtx(const brix_aconn *ac) { (void) ac; return 0; }
static inline int uring_rxtx_send_submit(brix_loop *l, brix_aconn *ac)
{ (void) l; (void) ac; return -1; }
#endif /* BRIX_HAVE_LIBURING */
int io_engine_setup(brix_loop *l, brix_status *st);
void io_engine_teardown(brix_loop *l);
int io_engine_arm(brix_loop *l, brix_aconn *ac, int want);
void io_engine_del(brix_loop *l, brix_aconn *ac);
int io_engine_wait(brix_loop *l, struct epoll_event *evs, int max, int timeout_ms);

/* aio_conn.c */
void aconn_update_epoll(brix_aconn *ac);
void aconn_drain_inflight(brix_aconn *ac, const brix_status *st);
void aconn_pending_fail_all(brix_aconn *ac, const brix_status *st);

/* aio.c */
void * rc_worker_main(void *arg);

/* aio_conn.c */
void aconn_on_transport_error(brix_aconn *ac, const brix_status *st);
void aconn_reconnect_succeeded(brix_aconn *ac);
void aconn_poll_reconnect(brix_aconn *ac);
void aconn_ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen, const brix_status *st);
void aconn_maybe_ping(brix_aconn *ac);
void aconn_destroy(brix_aconn *ac);
uint16_t aconn_alloc_sid(brix_aconn *ac);
void aconn_issue_areq(brix_aconn *ac, brix_areq *r);
uint64_t aconn_deadline_ns(brix_aconn *ac, int deadline_ms);
void aconn_submit_cmd(brix_aconn *ac, cmd *c);

/* aio.c */
void loop_push_cmd(brix_loop *l, cmd *c);
void loop_run_control(brix_loop *l, cmd_type type, brix_aconn *ac);
void loop_drain_commands(brix_loop *l);
int loop_process_timeouts(brix_loop *l);
void * loop_thread(void *arg);
brix_loop * brix_loop_create_fail(brix_loop *l);
int brix_loop_want_uring(void);
int brix_loop_want_rxtx(void);
void call_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen, const brix_status *st);

#endif /* BRIX_AIO_INTERNAL_H */
