/* origin_probe.c — per-worker RTT probe for brix_cvmfs_origin_select rtt.
 *
 * WHAT: a repeating per-worker timer posts a thread-pool task that measures
 *       TCP connect RTT to every configured origin endpoint; the event-loop
 *       completion folds samples into an EWMA, ranks endpoints, and pushes
 *       ranks into the sd_http driver.
 * WHY:  on a Tier-2 with erratic routing, configured order and geography
 *       both lie; measured connect RTT is what the fills will actually feel.
 * HOW:  measurement is blocking (getaddrinfo + nonblocking connect + poll)
 *       and therefore lives on a thread-pool worker, mirroring the cache
 *       fill I/O pattern; the event loop only re-arms the timer and writes
 *       ranks (relaxed atomics — see sd_http.h). Exports register at config
 *       time (merge runs in the master; the list survives the fork), and
 *       every worker arms its own timers at init_process — the same
 *       lifecycle the cache reaper uses.
 */
#include "cvmfs.h"
#include "origin_geo.h"
#include "core/aio/aio.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/http/sd_http.h"
#include "fs/vfs/vfs_backend_registry.h"

#include <netdb.h>
#include <poll.h>
#include <time.h>

#define CVMFS_PROBE_TIMEOUT_MS 2000
#define CVMFS_PROBE_FAIL_US    (CVMFS_PROBE_TIMEOUT_MS * 1000L * 4)
#define CVMFS_PROBE_MAX_EXPORTS 8

/* Config-time registration (per-process statics; written by the master's
 * config parse, read by every worker at init). */
typedef struct {
    char    root[256];
    char    pool[64];
    time_t  interval;
} cvmfs_rtt_reg_t;

static cvmfs_rtt_reg_t  cvmfs_rtt_regs[CVMFS_PROBE_MAX_EXPORTS];
static ngx_uint_t       cvmfs_rtt_regs_n;

void
brix_cvmfs_rtt_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name)
{
    ngx_uint_t       i;
    cvmfs_rtt_reg_t *reg = NULL;

    for (i = 0; i < cvmfs_rtt_regs_n; i++) {
        if (ngx_strcmp(cvmfs_rtt_regs[i].root, root_canon) == 0) {
            reg = &cvmfs_rtt_regs[i];          /* reload: update in place */
            break;
        }
    }
    if (reg == NULL) {
        if (cvmfs_rtt_regs_n >= CVMFS_PROBE_MAX_EXPORTS
            || ngx_strlen(root_canon) >= sizeof(reg->root))
        {
            return;
        }
        reg = &cvmfs_rtt_regs[cvmfs_rtt_regs_n++];
    }
    ngx_cpystrn((u_char *) reg->root, (u_char *) root_canon,
                sizeof(reg->root));
    reg->interval = (interval > 0) ? interval : 60;
    reg->pool[0] = '\0';
    if (pool_name != NULL && pool_name->len > 0
        && pool_name->len < sizeof(reg->pool))
    {
        ngx_memcpy(reg->pool, pool_name->data, pool_name->len);
        reg->pool[pool_name->len] = '\0';
    }
}

/* Per-worker probe context (one per rtt export; the ngx_thread_task_t is
 * allocated once and re-posted — timer → post → done → re-arm is strictly
 * sequential, so reuse is safe). */
typedef struct {
    ngx_event_t         timer;
    ngx_thread_task_t  *task;
    const cvmfs_rtt_reg_t *reg;
    int                 n;
    char                hosts[SD_HTTP_EP_MAX][256];
    int                 ports[SD_HTTP_EP_MAX];
    double              ewma_us[SD_HTTP_EP_MAX];   /* 0 = no sample yet */
    long                sample_us[SD_HTTP_EP_MAX]; /* thread → done     */
    int                 prev_ranks[SD_HTTP_EP_MAX]; /* last pushed ranks;
                                                       -1 = none yet     */
    int                 probe_down[SD_HTTP_EP_MAX]; /* 1 = last sample
                                                       failed (transition
                                                       logging)          */
} cvmfs_probe_ctx_t;

/* One nonblocking connect, timed. Returns RTT µs, or -1 on any failure
 * (refused, unreachable, timeout, resolution failure). Shared with the
 * on-demand geo-answer probe (geo_answer.c) — ONE connect-RTT implementation. */
long
brix_cvmfs_connect_rtt_us(const char *host, int port, int timeout_ms)
{
    struct addrinfo  hints, *ai = NULL;
    struct pollfd    pfd;
    struct timespec  t0, t1;
    char             svc[8];
    int              fd, soerr = 0;
    socklen_t        slen = sizeof(soerr);
    long             us = -1;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
    snprintf(svc, sizeof(svc), "%d", port);
    if (getaddrinfo(host, svc, &hints, &ai) != 0 || ai == NULL) {
        return -1;
    }
    fd = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0); /* vfs-seam-allow: probe socket, non-export resource */
    if (fd < 0) {
        freeaddrinfo(ai);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        us = (t1.tv_sec - t0.tv_sec) * 1000000L
           + (t1.tv_nsec - t0.tv_nsec) / 1000L;
    } else if (errno == EINPROGRESS) {
        pfd.fd = fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, timeout_ms) == 1
            && getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0
            && soerr == 0)
        {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            us = (t1.tv_sec - t0.tv_sec) * 1000000L
               + (t1.tv_nsec - t0.tv_nsec) / 1000L;
        }
    }
    close(fd); /* vfs-seam-allow: probe socket, non-export resource */
    freeaddrinfo(ai);
    return us;
}

/* thread-pool side: probe every endpoint sequentially */
static void
cvmfs_probe_thread(void *data, ngx_log_t *log)
{
    cvmfs_probe_ctx_t *pc = data;
    int                i;

    (void) log;
    for (i = 0; i < pc->n; i++) {
        pc->sample_us[i] = brix_cvmfs_connect_rtt_us(pc->hosts[i],
                                                pc->ports[i],
                                                CVMFS_PROBE_TIMEOUT_MS);
    }
}

static int
cvmfs_rank_zero_index(const int *ranks, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (ranks[i] == 0) {
            return i;
        }
    }
    return 0;
}

/* Render the per-endpoint probe outcome as one bounded "; "-joined line:
 * "host:port rank=N ewma=Xus rtt=Y" — the full evidence trail behind a
 * ranking decision, so an operator can see WHY endpoint order changed. */
static void
cvmfs_probe_table(const cvmfs_probe_ctx_t *pc, const double *metric,
    const int *ranks, char *buf, size_t cap)
{
    size_t off = 0;
    char   samp[32];
    int    i, w;

    buf[0] = '\0';
    for (i = 0; i < pc->n && off + 1 < cap; i++) {
        if (pc->sample_us[i] < 0) {
            snprintf(samp, sizeof(samp), "UNREACHABLE");
        } else {
            snprintf(samp, sizeof(samp), "%ldus", pc->sample_us[i]);
        }
        w = snprintf(buf + off, cap - off, "%s%s:%d rank=%d ewma=%.0fus rtt=%s",
                     (i > 0) ? "; " : "", pc->hosts[i], pc->ports[i],
                     ranks[i], metric[i], samp);
        if (w < 0 || (size_t) w >= cap - off) {
            break;
        }
        off += (size_t) w;
    }
}

/* Log per-endpoint reachability TRANSITIONS (probe ok → fail and back) at
 * WARN/NOTICE — steady state stays quiet, the flap is what matters. */
static void
cvmfs_probe_log_reachability(cvmfs_probe_ctx_t *pc, ngx_log_t *log)
{
    int i, failed;

    for (i = 0; i < pc->n; i++) {
        failed = (pc->sample_us[i] < 0);
        if (failed == pc->probe_down[i]) {
            continue;
        }
        pc->probe_down[i] = failed;
        if (failed) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "cvmfs rtt probe: origin %s:%d UNREACHABLE (connect probe "
                "failed/timed out within %dms) - penalised in ranking at "
                "%.0fus ewma until it answers again",
                pc->hosts[i], pc->ports[i], CVMFS_PROBE_TIMEOUT_MS,
                pc->ewma_us[i]);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "cvmfs rtt probe: origin %s:%d reachable again "
                "(rtt %ldus, ewma %.0fus - preference recovers as the "
                "ewma decays)",
                pc->hosts[i], pc->ports[i], pc->sample_us[i],
                pc->ewma_us[i]);
        }
    }
}

/* Unwrap the composed stack (cache → stage → backend) to the http source. */
static brix_sd_instance_t *
cvmfs_unwrap_http(brix_sd_instance_t *inst)
{
    while (inst != NULL && ngx_strcmp(inst->driver->name, "http") != 0) {
        inst = brix_sd_cache_source_instance(inst);
    }
    return inst;
}

/* event-loop side: fold EWMA, rank, push, re-arm. Every rank ORDER change is
 * logged with the full evidence table (NOTICE — this is the moment the next
 * fill starts going somewhere else); steady-state ticks stay at INFO. */
static void
cvmfs_probe_done(ngx_event_t *ev)
{
    ngx_thread_task_t     *task = ev->data;
    cvmfs_probe_ctx_t     *pc = task->ctx;
    brix_sd_instance_t  *inst;
    double                 metric[SD_HTTP_EP_MAX];
    char                   tbl[1024];
    int                    ranks[SD_HTTP_EP_MAX], i, best;
    int                    first_tick, changed, prev_best;

    for (i = 0; i < pc->n; i++) {
        double s = (pc->sample_us[i] < 0) ? (double) CVMFS_PROBE_FAIL_US
                                          : (double) pc->sample_us[i];
        pc->ewma_us[i] = (pc->ewma_us[i] == 0.0)
                       ? s : pc->ewma_us[i] * 0.75 + s * 0.25;
        metric[i] = pc->ewma_us[i];
    }
    brix_cvmfs_rank_by_metric(metric, pc->n, ranks);

    cvmfs_probe_log_reachability(pc, ev->log);

    inst = cvmfs_unwrap_http(
        brix_vfs_backend_resolve(pc->reg->root, ev->log));
    if (inst != NULL) {
        sd_http_set_ranks(inst, ranks, pc->n);
    }

    first_tick = (pc->prev_ranks[0] < 0);
    changed = 0;
    for (i = 0; i < pc->n && !first_tick; i++) {
        if (ranks[i] != pc->prev_ranks[i]) {
            changed = 1;
        }
    }
    best = cvmfs_rank_zero_index(ranks, pc->n);
    cvmfs_probe_table(pc, metric, ranks, tbl, sizeof(tbl));

    if (first_tick) {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
            "cvmfs rtt initial ranking (export %s): preferred %s:%d - %s",
            pc->reg->root, pc->hosts[best], pc->ports[best], tbl);
    } else if (changed) {
        prev_best = cvmfs_rank_zero_index(pc->prev_ranks, pc->n);
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
            "cvmfs rtt ranking CHANGED (export %s): preferred %s:%d -> %s:%d "
            "- %s",
            pc->reg->root, pc->hosts[prev_best], pc->ports[prev_best],
            pc->hosts[best], pc->ports[best], tbl);
    } else {
        ngx_log_error(NGX_LOG_INFO, ev->log, 0,
            "cvmfs rtt ranks (export %s): preferred %s:%d - %s",
            pc->reg->root, pc->hosts[best], pc->ports[best], tbl);
    }
    for (i = 0; i < pc->n; i++) {
        pc->prev_ranks[i] = ranks[i];
    }

    if (!ngx_exiting) {
        ngx_add_timer(&pc->timer, (ngx_msec_t) pc->reg->interval * 1000
                                  + (ngx_msec_t) (ngx_random() % 1000));
    }
}

/* timer side: post the probe task (skip the tick if no pool resolves) */
static void
cvmfs_probe_fire(ngx_event_t *ev)
{
    cvmfs_probe_ctx_t *pc = ev->data;
    ngx_thread_pool_t *pool;
    ngx_str_t          pname;

    if (pc->reg->pool[0] != '\0') {
        pname.data = (u_char *) pc->reg->pool;
        pname.len  = ngx_strlen(pc->reg->pool);
    } else {
        ngx_str_set(&pname, "default");
    }
    pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname);
    if (pool == NULL || ngx_thread_task_post(pool, pc->task) != NGX_OK) {
        if (!ngx_exiting) {
            ngx_add_timer(ev, (ngx_msec_t) pc->reg->interval * 1000);
        }
    }
    /* re-armed by cvmfs_probe_done after the samples land */
}

ngx_int_t
brix_cvmfs_rtt_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t i;

    for (i = 0; i < cvmfs_rtt_regs_n; i++) {
        const cvmfs_rtt_reg_t *reg = &cvmfs_rtt_regs[i];
        ngx_thread_task_t     *task;
        cvmfs_probe_ctx_t     *pc;
        const char            *host;
        int                    port, idx;

        task = ngx_thread_task_alloc(cycle->pool, sizeof(cvmfs_probe_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }
        pc = task->ctx;
        pc->task = task;
        pc->reg  = reg;
        for (idx = 0; idx < SD_HTTP_EP_MAX; idx++) {
            if (brix_vfs_backend_http_endpoint_at(reg->root, idx, &host,
                                                    &port) != 0)
            {
                break;
            }
            ngx_cpystrn((u_char *) pc->hosts[idx], (u_char *) host,
                        sizeof(pc->hosts[idx]));
            pc->ports[idx] = port;
        }
        pc->n = idx;
        if (pc->n == 0) {
            continue;                    /* not an http backend (misconfig) */
        }
        for (idx = 0; idx < SD_HTTP_EP_MAX; idx++) {
            pc->prev_ranks[idx] = -1;    /* -1 = no ranking pushed yet */
        }

        brix_task_bind(task, cvmfs_probe_thread, cvmfs_probe_done);
        task->event.log = cycle->log;

        pc->timer.handler = cvmfs_probe_fire;
        pc->timer.data    = pc;
        pc->timer.log     = cycle->log;
        /* first probe within 500 ms so ranks exist before the first fill */
        ngx_add_timer(&pc->timer, (ngx_msec_t) (ngx_random() % 500) + 1);
    }
    return NGX_OK;
}
