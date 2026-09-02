/*
 * io_monitor.h — the per-request / per-session I/O monitor record.
 *
 * WHAT: One small protocol-neutral record that accumulates, across every brix
 *       VFS operation of ONE HTTP request or ONE root:// session, the facts the
 *       uniform $brix_* monitoring surface reports at log time:
 *
 *         bytes served / received     $brix_bytes_served / $brix_bytes_received
 *         summed backend I/O time     $brix_backend_time
 *         cache disposition           $brix_cache_status
 *         primary operation + path    $brix_op / $brix_path
 *         outcome class               $brix_status
 *         operation count             $brix_ops
 *         reported file checksum      $brix_checksum
 *
 * WHY:  Every value above already existed somewhere in brix (the JSON access
 *       log proves it) but nothing retained them per request/session, so the
 *       variables could not exist as pure handlers (phase-106 Appendix G, the
 *       "data-plane" rows). This record is that retention layer, kept
 *       deliberately small and free of protocol or HTTP knowledge so the VFS
 *       layer can fold into it through a bare pointer without depending on the
 *       plane that owns its lifetime. phase-110 W1-W4 extend it from the three
 *       phase-106 counters to the full uniform vocabulary.
 *
 * HOW:  The owning plane allocates it ON THE EVENT LOOP — an HTTP plane on the
 *       request pool (stored in ngx_http_brix_common_module's ctx slot), the
 *       root plane embedded in its per-connection brix_ctx_t — and points every
 *       data-plane brix_vfs_ctx_t->io_monitor at it. The VFS layer folds:
 *         * the post-op observer (vfs_internal.h): latency, op/path/err by the
 *           weight rule below, op count;
 *         * brix_vfs_adopt_fd: the open as a read/write op (the client-facing
 *           serve is zero-copy and never reaches the observer, so the OPEN is
 *           what identifies a GET as "read");
 *         * brix_vfs_observe_cache: HIT/MISS/BYPASS beside the unified metric;
 *         * the mutation gate: FORBIDDEN on a read-only refusal;
 *       and the planes fold the two facts only they know: served bytes
 *       (result->bytes_sent) and the checksum they reported to the client.
 *
 * THREADING: single-writer. Exactly one op runs at a time for a request or
 *       session; the GET/PUT offload thread only WRITES scalar fields / memcpys
 *       into the pre-allocated fixed buffers below (never allocates), and the
 *       task done-handler orders those writes before the event-loop log phase
 *       reads them. Do not add a reader on any other thread, and never give
 *       this struct a pointer into a pool the thread could free.
 *
 * VALUE RULES (the "-" discipline): a field is "-" when the event did not
 *       happen, never a measured zero. `any` = at least one op observed;
 *       `have_op` = an op was recorded; `have_checksum` = one was reported.
 */
#ifndef BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H
#define BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>
#include <string.h>

#include "observability/metrics/unified.h"   /* the shared vocabularies */

/* Bounded copy of the primary op's export-relative path. Matches the JSON
 * access log's own bound (access_log.c path_json[1024]); a longer path is
 * truncated, never dropped — the log shows a prefix rather than "-". */
#define BRIX_IO_MONITOR_PATH_MAX   1024
/* "alg:hex": brix_integrity_info_t alg_name[16] + ':' + hex[129]. */
#define BRIX_IO_MONITOR_CKSUM_MAX  (16 + 1 + 129)

/* The tag is what brix_vfs_ctx_t forward-declares; keep it stable. */
typedef struct brix_io_monitor_s {
    uint64_t            bytes;          /* bytes SERVED to the client            */
    uint64_t            bytes_received; /* bytes RECEIVED from the client (writes)*/
    ngx_msec_t          backend_usec;   /* summed VFS op latency, microseconds   */
    uint32_t            ops;            /* observed VFS ops                      */
    brix_metric_op_t    op;             /* primary op (valid iff have_op)        */
    brix_err_class_t    err;            /* outcome class of the primary op       */
    brix_cache_status_e cache;          /* disposition; NONE = no decision       */
    unsigned            op_weight;      /* weight of the recorded primary op     */
    size_t              path_len;       /* 0 = none */
    size_t              checksum_len;   /* 0 = none */
    unsigned            any:1;          /* at least one brix I/O op was observed */
    unsigned            have_op:1;
    unsigned            have_checksum:1;
    char                path[BRIX_IO_MONITOR_PATH_MAX];
    char                checksum[BRIX_IO_MONITOR_CKSUM_MAX];
} brix_io_monitor_t;


/*
 * brix_io_monitor_op_weight — which op describes the request.
 *
 * A GET is stat + open-for-read; a PROPFIND is stat + dirlist + stats; a COPY
 * is copy + the reads and writes that implement it. The op the operator wants
 * to see is the one with the highest weight; on equal weight the LATER op wins
 * (a PROPPATCH is stat then xattr → xattr). Metadata probes weigh nothing so
 * they never displace a data op, and the composite ops (copy/tpc) outweigh the
 * primitive reads/writes they are made of.
 */
static ngx_inline unsigned
brix_io_monitor_op_weight(brix_metric_op_t op)
{
    switch (op) {
    case BRIX_METRIC_OP_COPY:
    case BRIX_METRIC_OP_TPC:
        return 3;
    case BRIX_METRIC_OP_READ:
    case BRIX_METRIC_OP_WRITE:
    case BRIX_METRIC_OP_DELETE:
    case BRIX_METRIC_OP_MKDIR:
    case BRIX_METRIC_OP_RENAME:
        return 2;
    case BRIX_METRIC_OP_DIRLIST:
        return 1;
    case BRIX_METRIC_OP_STAT:
    case BRIX_METRIC_OP_XATTR:
    case BRIX_METRIC_OP_COUNT:
    default:
        return 0;
    }
}


/* Fold one observed op's timing. NULL monitor = unmonitored path (silent). */
static ngx_inline void
brix_io_monitor_add_latency(brix_io_monitor_t *m, ngx_msec_t latency_usec)
{
    if (m == NULL) {
        return;
    }
    m->any = 1;
    m->backend_usec += latency_usec;
}


/* Fold bytes the plane SERVED to the client (the plane's authoritative count,
 * e.g. brix_http_serve_result_t.bytes_sent — the serve is zero-copy and never
 * reaches the per-op observer). */
static ngx_inline void
brix_io_monitor_add_served(brix_io_monitor_t *m, size_t bytes)
{
    if (m == NULL || bytes == 0) {
        return;
    }
    m->any = 1;
    m->bytes += (uint64_t) bytes;
}


/* Fold bytes RECEIVED from the client (the observer's WRITE op count). */
static ngx_inline void
brix_io_monitor_add_received(brix_io_monitor_t *m, size_t bytes)
{
    if (m == NULL || bytes == 0) {
        return;
    }
    m->any = 1;
    m->bytes_received += (uint64_t) bytes;
}


/*
 * brix_io_monitor_record_op — candidate primary op (weight rule above).
 *
 * Copies `path` into the monitor's own buffer: the observer's path argument may
 * be a caller STACK buffer (lock_check.c hands it a char[PATH_MAX]), so a stored
 * pointer would dangle by log time. memcpy into a preallocated buffer is safe
 * from the offload thread. The err class rides with the op so $brix_status is
 * the outcome of the op $brix_op names, not of an incidental probe.
 */
static ngx_inline void
brix_io_monitor_record_op(brix_io_monitor_t *m, brix_metric_op_t op,
    const char *path, brix_err_class_t err)
{
    unsigned  w;
    size_t    n;

    if (m == NULL) {
        return;
    }
    m->any = 1;
    m->ops++;
    w = brix_io_monitor_op_weight(op);
    if (m->have_op && w < m->op_weight) {
        return;
    }
    m->have_op = 1;
    m->op = op;
    m->op_weight = w;
    m->err = err;
    if (path == NULL || path[0] == '\0') {
        m->path_len = 0;
        return;
    }
    n = strlen(path);
    if (n > sizeof(m->path) - 1) {
        n = sizeof(m->path) - 1;
    }
    memcpy(m->path, path, n);
    m->path[n] = '\0';
    m->path_len = n;
}


/* Record an outcome class WITHOUT an op — the mutation gate's read-only
 * refusal happens before any VFS op runs, and an HTTP plane's own refusal
 * (401/403/404) may never reach the VFS at all. A recorded op's own class is
 * not overwritten: the primary op's outcome stays authoritative. */
static ngx_inline void
brix_io_monitor_record_err(brix_io_monitor_t *m, brix_err_class_t err)
{
    if (m == NULL) {
        return;
    }
    m->any = 1;
    if (!m->have_op || m->err == BRIX_ERR_NONE) {
        m->err = err;
    }
}


/*
 * brix_io_monitor_record_cache — fold a cache decision.
 *
 * MISS dominates HIT: a request that had to reach the origin for any part of
 * its data was, for hit-rate purposes, a miss. BYPASS/NEGHIT only fill an
 * undecided slot (a deliberate skip beside a real hit is still a hit).
 */
static ngx_inline void
brix_io_monitor_record_cache(brix_io_monitor_t *m, brix_cache_status_e status)
{
    if (m == NULL || status == BRIX_CACHE_STATUS_NONE) {
        return;
    }
    m->any = 1;
    if (m->cache == BRIX_CACHE_STATUS_NONE || status == BRIX_CACHE_STATUS_MISS) {
        m->cache = status;
    }
}


/* Record the file checksum the plane REPORTED to the client, rendered
 * "alg:hex" (INVARIANT #9: the algorithm travels with the digits so the value
 * is never misread). Last one wins — a request reports at most one. */
static ngx_inline void
brix_io_monitor_record_checksum(brix_io_monitor_t *m, const char *alg,
    const char *hex)
{
    size_t  la, lh;

    if (m == NULL || alg == NULL || hex == NULL || alg[0] == '\0'
        || hex[0] == '\0')
    {
        return;
    }
    la = strlen(alg);
    lh = strlen(hex);
    if (la + 1 + lh > sizeof(m->checksum) - 1) {
        return;                         /* not representable: leave "-" */
    }
    memcpy(m->checksum, alg, la);
    m->checksum[la] = ':';
    memcpy(m->checksum + la + 1, hex, lh);
    m->checksum[la + 1 + lh] = '\0';
    m->checksum_len = la + 1 + lh;
    m->have_checksum = 1;
    m->any = 1;
}

#endif /* BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H */
