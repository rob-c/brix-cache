/*
 * aio_internal.h - private split contract for aio.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_AIO_INTERNAL_H
#define XROOTD_AIO_INTERNAL_H

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
#if (XROOTD_HAVE_LIBURING)
#include <liburing.h>
#endif
#define AIO_MAXEV      64        
#define AIO_URING_SLOTS 128      
#define AIO_READ_CHUNK 65536u    
#define AIO_TICK_MS    1000      
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   start;
    size_t   len;
} xbuf;

typedef struct xrdc_areq {
    uint16_t    sid;
    uint8_t     hdr[XRD_REQUEST_HDR_LEN];
    uint8_t    *payload;     /* owned copy, or NULL */
    uint32_t    plen;

    uint8_t    *acc;         /* accumulated reply body (owned until delivered) */
    uint32_t    acc_len;
    uint32_t    acc_cap;

    xrdc_aio_cb cb;
    void       *ctx;
    uint64_t    deadline_ns; /* 0 = none */

    /* resilience (M2) */
    int         retry_safe;  /* may be re-issued verbatim after a reconnect */
    int         retries_left;/* transport re-issues remaining */
    int         is_ping;     /* internal keepalive heartbeat (no user cb) */
    uint64_t    submit_ns;   /* when the current attempt was written (RTT sample) */
    struct xrdc_areq *pend_next;  /* link in the aconn pending (re-issue) list */
} xrdc_areq;

#define REQMAP_TOMB ((xrdc_areq *) -1)
typedef struct {
    xrdc_areq **slots;
    uint32_t    cap;        /* power of two */
    uint32_t    count;      /* live entries */
    uint32_t    tomb;       /* tombstones */
} reqmap;

typedef enum {
    ACONN_ALIVE = 0,    /* normal: doing I/O on a healthy socket */
    ACONN_RECONNECTING, /* socket dropped; a worker thread is re-establishing it */
    ACONN_DEAD          /* reconnect budget exhausted; no recovery */
} aconn_state;

struct xrdc_aconn {
    xrdc_loop     *loop;
    xrdc_conn     *conn;     /* borrowed brought-up session */
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
    xrdc_areq     *pending;               /* parked requests awaiting re-issue */

    /* reconnect worker handoff (worker writes rc_*, loop polls rc_finished) */
    pthread_t      rc_thread;
    int            rc_thread_live;
    volatile int   rc_finished;           /* set by worker just before it returns */
    int            rc_result;             /* 0 = reconnected, -1 = gave up */
    xrdc_status    rc_st;                 /* failure detail when rc_result < 0 */

    struct xrdc_aconn *next; /* loop->aconns singly-linked list */
};

typedef enum {
    CMD_ADD_ACONN,
    CMD_SUBMIT,
    CMD_CLOSE_ACONN,
    CMD_STOP
} cmd_type;

typedef struct cmd {
    cmd_type     type;
    xrdc_aconn  *ac;

    /* SUBMIT payload (header copied inline; payload owned, moved into the areq) */
    uint8_t      hdr[XRD_REQUEST_HDR_LEN];
    uint8_t     *payload;
    uint32_t     plen;
    xrdc_aio_cb  cb;
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

struct xrdc_poll_slot {
    xrdc_aconn *ac;
    uint32_t    gen;
    int         in_use;
};

struct xrdc_loop {
    int             epfd;
    int             evfd;
    pthread_t       thread;
    int             thread_ok;

    pthread_mutex_t cq_lock;
    cmd            *cq_head;
    cmd            *cq_tail;

    xrdc_aconn     *aconns;   /* loop-thread-owned list */
    int             stop;

    int             use_uring; /* phase-44: loop engine is io_uring (default 0) */
#if (XROOTD_HAVE_LIBURING)
    struct io_uring uring;
    int             uring_ok;  /* ring initialized (teardown guard)             */
    struct xrdc_poll_slot uslots[AIO_URING_SLOTS];
#endif
};

#if (XROOTD_HAVE_LIBURING)
#define AIO_URING_EVFD_UD    0xffffffffffffffffULL  /* evfd readiness poll       */
#define AIO_URING_IGNORE_UD  0xfffffffffffffffeULL  /* cancel-ack CQE (drop)     */
#endif /* XROOTD_HAVE_LIBURING */
typedef struct {
    pthread_mutex_t mx;
    pthread_cond_t  cv;
    int             done;
    int             rc;
    uint16_t        kxr;
    uint8_t        *body;
    uint32_t        blen;
    xrdc_status     st;
} call_wait;


/* aio_buffers.c */
int xbuf_reserve(xbuf *b, size_t need);
int xbuf_append(xbuf *b, const void *data, size_t n);
void xbuf_compact(xbuf *b);
void xbuf_free(xbuf *b);
void areq_free(xrdc_areq *r);
int areq_accumulate(xrdc_areq *r, const uint8_t *body, uint32_t n);
void areq_complete(xrdc_areq *r, int rc, uint16_t kxr, const xrdc_status *st);
int reqmap_rehash(reqmap *m, uint32_t newcap);
int reqmap_put(reqmap *m, xrdc_areq *r);
xrdc_areq * reqmap_get(reqmap *m, uint16_t sid);
void reqmap_del(reqmap *m, uint16_t sid);

/* aio_io.c */
void aconn_do_write(xrdc_aconn *ac);
void aconn_note_rtt(xrdc_aconn *ac, const xrdc_areq *r);
uint64_t aconn_rto_ns(const xrdc_aconn *ac);
void aconn_dispatch_frame(xrdc_aconn *ac, uint16_t sid, uint16_t stat, const uint8_t *body, uint32_t dlen);
void aconn_parse(xrdc_aconn *ac);
void aconn_do_read(xrdc_aconn *ac);
void aconn_handle_io(xrdc_aconn *ac, uint32_t events);

/* aio_engine.c */
unsigned uring_pollmask(int want);
int uring_slot_alloc(xrdc_loop *l, xrdc_aconn *ac);
int uring_poll_submit(xrdc_loop *l, xrdc_aconn *ac, int want);
void uring_poll_cancel(xrdc_loop *l, xrdc_aconn *ac, int freeing);
int io_engine_setup(xrdc_loop *l, xrdc_status *st);
void io_engine_teardown(xrdc_loop *l);
int io_engine_arm(xrdc_loop *l, xrdc_aconn *ac, int want);
void io_engine_del(xrdc_loop *l, xrdc_aconn *ac);
int io_engine_wait(xrdc_loop *l, struct epoll_event *evs, int max, int timeout_ms);

/* aio_conn.c */
void aconn_update_epoll(xrdc_aconn *ac);
void aconn_drain_inflight(xrdc_aconn *ac, const xrdc_status *st);
void aconn_pending_fail_all(xrdc_aconn *ac, const xrdc_status *st);

/* aio.c */
void * rc_worker_main(void *arg);

/* aio_conn.c */
void aconn_on_transport_error(xrdc_aconn *ac, const xrdc_status *st);
void aconn_reconnect_succeeded(xrdc_aconn *ac);
void aconn_poll_reconnect(xrdc_aconn *ac);
void aconn_ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen, const xrdc_status *st);
void aconn_maybe_ping(xrdc_aconn *ac);
void aconn_destroy(xrdc_aconn *ac);
uint16_t aconn_alloc_sid(xrdc_aconn *ac);
void aconn_issue_areq(xrdc_aconn *ac, xrdc_areq *r);
uint64_t aconn_deadline_ns(xrdc_aconn *ac, int deadline_ms);
void aconn_submit_cmd(xrdc_aconn *ac, cmd *c);

/* aio.c */
void loop_push_cmd(xrdc_loop *l, cmd *c);
void loop_run_control(xrdc_loop *l, cmd_type type, xrdc_aconn *ac);
void loop_drain_commands(xrdc_loop *l);
int loop_process_timeouts(xrdc_loop *l);
void * loop_thread(void *arg);
xrdc_loop * xrdc_loop_create_fail(xrdc_loop *l);
int xrdc_loop_want_uring(void);
void call_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen, const xrdc_status *st);

#endif /* XROOTD_AIO_INTERNAL_H */
