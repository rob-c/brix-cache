/*
 * stream_wmirror_internal.h — declarations shared across the XRootD stream
 * data-write mirror files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the handful of symbols and the two state structs that
 *       straddle the boundaries between the three data-write-mirror files, plus
 *       the shared BRIX_WMIR_METRIC_INC counter macro.
 * WHY:  stream_wmirror.c (824 lines) split into three focused files under the
 *       500-line cap:
 *         stream_wmirror.c        — per-connection accumulation + the public
 *                                   on_open / observe / cleanup hooks
 *         stream_wmirror_replay.c — detached-replay lifecycle: socket setup,
 *                                   event handlers, flush, teardown, launch
 *         stream_wmirror_state.c  — replay protocol state machine: per-phase
 *                                   frame build/send + step decisions + dispatch
 *       The accumulation side launches a replay (wmir_launch); the replay's read
 *       handler hands each parsed frame to the state machine (wmir_dispatch); the
 *       state machine drains/queues frames (wmir_flush) and tears down on any
 *       error (wmir_finish).  Exactly those cross-file symbols become non-static
 *       and are declared here; everything else stays file-local.
 * HOW:  All three .c files include this header; none of these symbols is part of
 *       the mirror's public surface (stream_wmirror.h).
 *
 * Requires: core/ngx_brix_module.h (ngx + wire types, XRD_RESPONSE_HDR_LEN) and
 *           observability/metrics/metrics_macros.h (brix_metrics_shared) — both
 *           pulled in below so this header stands alone.
 */
#ifndef BRIX_MIRROR_STREAM_WMIRROR_INTERNAL_H
#define BRIX_MIRROR_STREAM_WMIRROR_INTERNAL_H

#include "core/ngx_brix_module.h"   /* umbrella: nginx + protocol + ctx/conf types */
#include "observability/metrics/metrics_macros.h"

#include <sys/socket.h>             /* struct sockaddr_storage, socklen_t */

/* Data-write mirror counters live in the shared root metrics struct (low
 * cardinality, no per-file labels per metrics INVARIANT 8).  Shared by the
 * teardown path (stream_wmirror_replay.c) and the accumulation cap-drop path
 * (stream_wmirror.c). */
#define BRIX_WMIR_METRIC_INC(field)                                        \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


/*
 * A single per-file accumulator slot.  The accumulation side (stream_wmirror.c)
 * owns and fills it keyed by the primary's file-handle index; wmir_launch
 * (stream_wmirror_replay.c) reads it to seed a detached replay, stealing f->data.
 */
typedef struct {
    unsigned   active:1;        /* a write-open is accumulating          */
    unsigned   aborted:1;       /* cap exceeded / non-seq / pgwrite      */
    u_char     open_hdr[24];    /* client's open request header (24 B)   */
    u_char    *open_payload;    /* malloc: open path (+cgi)              */
    uint32_t   open_dlen;
    u_char    *data;            /* malloc/realloc: accumulated bytes     */
    size_t     data_len;
    off_t      next_off;        /* expected next contiguous write offset */
} brix_wmirror_file_t;


/*
 * Replay state machine.  The first three are the shared bootstrap (identical to
 * the read mirror); the last three are this mirror's stateful create sequence.
 * Each phase names the frame we have SENT and are now awaiting a response for.
 * Linear progression only — any non-ok response aborts via wmir_finish(r, 0).
 */
typedef enum {
    WMIR_HANDSHAKE = 0,
    WMIR_PROTOCOL,
    WMIR_LOGIN,
    WMIR_OPEN,     /* sent open, awaiting open response (shadow fhandle) */
    WMIR_WRITE,    /* sent write, awaiting response                      */
    WMIR_CLOSE,    /* sent close, awaiting response                      */
} wmir_phase_t;

typedef struct {
    ngx_pool_t       *pool;
    ngx_connection_t *conn;
    ngx_log_t        *log;
    wmir_phase_t      phase;
    unsigned          connecting:1;
    unsigned          log_diverge:1;

    u_char    rhdr[XRD_RESPONSE_HDR_LEN];
    size_t    rhdr_pos;
    uint16_t  resp_status;
    uint32_t  resp_dlen;
    u_char   *resp_body;
    size_t    resp_body_pos;

    u_char   *wbuf;
    size_t    wbuf_len;
    size_t    wbuf_pos;

    ngx_event_t  tev;

    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    char                     host[256];
    uint16_t                 port;

    u_char   *open_frame;       /* malloc: open header(24) + path, to send */
    size_t    open_frame_len;
    u_char   *data;             /* malloc: file bytes                      */
    size_t    data_len;
    u_char    shadow_fhandle[4];
} brix_wmirror_replay_t;


/* ---- cross-file entry points ---------------------------------------------
 * Defined in stream_wmirror_replay.c, called from the other two files. */

/* Launch a detached replay for a fully-buffered file.  Ownership of f->data
 * transfers to the replay (nulled by the caller's reset afterwards). Called from
 * the accumulation side (stream_wmirror.c). */
void wmir_launch(ngx_stream_brix_srv_conf_t *conf, brix_wmirror_file_t *f);

/* Drain the pending write buffer to the shadow socket; NGX_OK / NGX_AGAIN (a
 * normal yield) / NGX_ERROR (terminal).  Called by the state machine's send
 * paths in stream_wmirror_state.c. */
ngx_int_t wmir_flush(brix_wmirror_replay_t *r);

/* Single teardown path for the replay (success and every failure route here).
 * Called by the state machine in stream_wmirror_state.c. */
void wmir_finish(brix_wmirror_replay_t *r, int ok);

/* ---- cross-file entry point ----------------------------------------------
 * Defined in stream_wmirror_state.c, called from the replay's read handler. */

/* Advance one replay phase for the frame just parsed into r; sends the next
 * frame, re-posts the read, or tears down.  Called by wmir_read_handler in
 * stream_wmirror_replay.c. */
void wmir_dispatch(brix_wmirror_replay_t *r);

#endif /* BRIX_MIRROR_STREAM_WMIRROR_INTERNAL_H */
