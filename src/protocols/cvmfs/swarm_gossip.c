/* swarm_gossip.c — the G12 swarm's probe/gossip engine (thread + event loop).
 *
 * WHAT: the bounded plain-socket roster probe (thread pool), the live-ring
 *       rebuild + publish, the gossip lifecycle timers, and the per-worker
 *       init that arms them.
 * WHY:  swarm.c grew past the file-size gate; the engine — everything that
 *       runs OFF the request path — moved here whole. The membership core,
 *       roster wire format, and the request-path roster endpoint stay in
 *       swarm.c; the shared seam is swarm_internal.h.
 * HOW:  the probe is a SWIM-style push-pull: the GET's query string
 *       introduces the prober (pull-only gossip can never propagate a new
 *       member upstream), the reply body is merged by swarm.c's roster
 *       merge, and the ALIVE view republishes into the cache fill spine
 *       through brix_sd_cache_ring_swap. Published rings are immutable and
 *       never freed (churn leaks ~4.5 KiB per swap by design).
 */
#include "cvmfs.h"
#include "swarm_internal.h"
#include "core/aio/aio.h"                  /* brix_task_bind */
#include "fs/tier/tier.h"                  /* brix_tier_build */
#include "fs/vfs/vfs_backend_registry.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- probe task (thread pool): bounded plain-socket HTTP GET ------------ */

static void
cvmfs_swarm_thread(void *data, ngx_log_t *log)
{
    cvmfs_swarm_ctx_t *sw = data;
    struct addrinfo    hints, *res = NULL, *ai;
    struct timeval     tv = { CVMFS_SWARM_IO_TIMEOUT_S, 0 };
    char               portstr[8], req[512];
    int                fd = -1, n;
    ssize_t            got;
    size_t             off = 0;
    char              *body;

    (void) log;
    sw->probe_ok = 0;
    sw->resp_len = 0;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf(portstr, sizeof(portstr), "%d", sw->probe_port);
    if (getaddrinfo(sw->probe_host, portstr, &hints, &res) != 0) {
        return;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        return;
    }

    /* Push-pull: the query string INTRODUCES the prober (pull-only gossip
     * can never propagate a new member upstream — the probed node must
     * learn who called it). */
    n = snprintf(req, sizeof(req),
                 "GET " CVMFS_SWARM_ROSTER_PATH "?from=%s&gen=%llu"
                 " HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                 sw->probe_from, (unsigned long long) sw->probe_gen,
                 sw->probe_host);
    if (n < 0 || (size_t) n >= sizeof(req)
        || write(fd, req, (size_t) n) != (ssize_t) n)
    {
        close(fd);
        return;
    }
    while (off < sizeof(sw->resp) - 1) {
        got = read(fd, sw->resp + off, sizeof(sw->resp) - 1 - off);
        if (got < 0) {
            close(fd);
            return;                        /* timeout / reset: probe miss */
        }
        if (got == 0) {
            break;
        }
        off += (size_t) got;
    }
    close(fd);
    sw->resp[off] = '\0';

    if (strncmp(sw->resp, "HTTP/1.", 7) != 0
        || strncmp(sw->resp + 8, " 200", 4) != 0)
    {
        return;
    }
    body = strstr(sw->resp, "\r\n\r\n");
    if (body == NULL) {
        return;
    }
    body += 4;
    sw->resp_len = off - (size_t) (body - sw->resp);
    memmove(sw->resp, body, sw->resp_len);
    sw->resp[sw->resp_len] = '\0';
    sw->probe_ok = 1;
}

/* ---- ring rebuild (event loop) ------------------------------------------ */

static brix_sd_instance_t *
cvmfs_swarm_member_inst(cvmfs_swarm_member_t *m, ngx_log_t *log)
{
    brix_tier_cfg_t pcfg;

    if (m->inst != NULL) {
        return m->inst;
    }
    ngx_memzero(&pcfg, sizeof(pcfg));
    pcfg.role = BRIX_TIER_CACHE;
    ngx_cpystrn((u_char *) pcfg.driver, (u_char *) "http",
                sizeof(pcfg.driver));
    ngx_cpystrn((u_char *) pcfg.host, (u_char *) m->host,
                sizeof(pcfg.host));
    pcfg.port       = m->port;
    pcfg.configured = 1;
    m->inst = brix_tier_build(&pcfg, log);  /* cached forever; NULL = degrade */
    if (m->inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "cvmfs-swarm: fill source build failed for member %s - "
            "its keys fall through to the origin", m->label);
    }
    return m->inst;
}

/* Build the label-sorted ALIVE index set (self always included). Labels are
 * sorted so every converged node computes the identical ring — the HRW owner
 * then agrees swarm-wide with no coordination. Caps at the published-ring
 * limit with a WARN (no silent caps). */
static ngx_uint_t
cvmfs_swarm_ring_alive(cvmfs_swarm_ctx_t *sw, ngx_uint_t *alive,
    ngx_log_t *log)
{
    ngx_uint_t i, j, n = 0;

    for (i = 0; i < sw->n_members; i++) {
        if ((int) i != sw->self && sw->members[i].dead) {
            continue;
        }
        /* insertion sort by label — deterministic across nodes */
        for (j = n; j > 0
             && strcmp(sw->members[alive[j - 1]].label,
                       sw->members[i].label) > 0; j--)
        {
            alive[j] = alive[j - 1];
        }
        alive[j] = i;
        n++;
    }
    if (n > BRIX_SD_CACHE_MAX_PEERS) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "cvmfs-swarm (export %s): %ui live members exceed the ring "
            "cap %d - the lexicographic tail falls through to the origin",
            sw->reg->root, n, BRIX_SD_CACHE_MAX_PEERS);
        n = BRIX_SD_CACHE_MAX_PEERS;
    }
    return n;
}

/* Is the candidate alive set identical to the currently published ring? */
static int
cvmfs_swarm_ring_unchanged(cvmfs_swarm_ctx_t *sw, const ngx_uint_t *alive,
    ngx_uint_t n, int self_slot)
{
    ngx_uint_t i;

    if (sw->pub_ring == NULL || sw->pub_ring->n != (int) n
        || sw->pub_ring->self != self_slot)
    {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (strcmp(sw->pub_ring->peers[i].label,
                   sw->members[alive[i]].label) != 0)
        {
            return 0;
        }
    }
    return 1;
}

/* Publish the ALIVE membership as the live rendezvous ring iff it changed. */
void
cvmfs_swarm_ring_publish(cvmfs_swarm_ctx_t *sw, ngx_log_t *log)
{
    ngx_uint_t             alive[CVMFS_SWARM_MAX_MEMBERS];
    ngx_uint_t             i, n;
    int                    self_slot = -1;
    brix_sd_cache_ring_t  *ring;
    brix_sd_instance_t    *cache;

    n = cvmfs_swarm_ring_alive(sw, alive, log);
    for (i = 0; i < n; i++) {
        if ((int) alive[i] == sw->self) {
            self_slot = (int) i;
        }
    }
    if (n < 2 || self_slot < 0) {
        return;                            /* no usable ring — keep current */
    }
    if (cvmfs_swarm_ring_unchanged(sw, alive, n, self_slot)) {
        return;
    }

    cache = brix_vfs_backend_resolve(sw->reg->root, log);
    if (cache == NULL) {
        return;
    }
    ring = malloc(sizeof(*ring));          /* published forever, never freed */
    if (ring == NULL) {
        return;
    }
    ngx_memzero(ring, sizeof(*ring));
    ring->n    = (int) n;
    ring->self = self_slot;
    for (i = 0; i < n; i++) {
        cvmfs_swarm_member_t *m = &sw->members[alive[i]];

        ngx_cpystrn((u_char *) ring->peers[i].label, (u_char *) m->label,
                    sizeof(ring->peers[i].label));
        ring->peers[i].inst = ((int) i == self_slot)
                               ? NULL : cvmfs_swarm_member_inst(m, log);
    }
    brix_sd_cache_ring_swap(cache, ring);
    sw->pub_ring = ring;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "cvmfs-swarm (export %s): published live ring of %ui member(s) "
        "(self=%s)", sw->reg->root, n, ring->peers[self_slot].label);
}

/* ---- gossip lifecycle (event loop) -------------------------------------- */

static void
cvmfs_swarm_done(ngx_event_t *ev)
{
    ngx_thread_task_t    *task = ev->data;
    cvmfs_swarm_ctx_t    *sw = task->ctx;
    cvmfs_swarm_member_t *m = &sw->members[sw->probe_idx];

    sw->busy = 0;
    if (sw->probe_ok) {
        m->miss = 0;
        if (m->dead) {
            m->dead = 0;                   /* direct proof beats gossip */
            ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                "cvmfs-swarm (export %s): member %s answered a probe - "
                "back alive", sw->reg->root, m->label);
        }
        (void) cvmfs_swarm_roster_merge(sw, sw->resp, sw->resp_len,
                                          ev->log);
    } else if (!m->dead && ++m->miss >= CVMFS_SWARM_MISS_DEAD) {
        m->dead = 1;
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
            "cvmfs-swarm (export %s): member %s missed %d probe(s) - "
            "marked dead, its keys route around it", sw->reg->root,
            m->label, CVMFS_SWARM_MISS_DEAD);
    }
    cvmfs_swarm_ring_publish(sw, ev->log);

    if (!ngx_exiting) {
        ngx_add_timer(&sw->timer,
                      (ngx_msec_t) sw->reg->interval * 1000
                      + (ngx_msec_t) (ngx_random() % 500));
    }
}

static void
cvmfs_swarm_fire(ngx_event_t *ev)
{
    cvmfs_swarm_ctx_t  *sw = ev->data;
    ngx_thread_pool_t  *pool;
    ngx_str_t           pname;
    ngx_uint_t          i, idx;

    cvmfs_swarm_seed(sw, ev->log);
    if (sw->seeded && !sw->busy) {
        cvmfs_swarm_ring_publish(sw, ev->log);  /* seed ring before gossip */

        /* round-robin over probe candidates (everyone but self — dead
         * members stay probed so a restart is noticed and re-merged). */
        for (i = 0; i < sw->n_members; i++) {
            idx = (sw->rr + 1 + i) % sw->n_members;
            if ((int) idx == sw->self) {
                continue;
            }
            sw->rr = idx;
            sw->probe_idx  = idx;
            sw->probe_port = sw->members[idx].port;
            sw->probe_gen  = sw->self_gen;
            ngx_cpystrn((u_char *) sw->probe_host,
                        (u_char *) sw->members[idx].host,
                        sizeof(sw->probe_host));
            ngx_cpystrn((u_char *) sw->probe_from,
                        (u_char *) sw->members[sw->self].label,
                        sizeof(sw->probe_from));

            if (sw->reg->pool[0] != '\0') {
                pname.data = (u_char *) sw->reg->pool;
                pname.len  = ngx_strlen(sw->reg->pool);
            } else {
                ngx_str_set(&pname, "default");
            }
            pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname);
            if (pool != NULL) {
                sw->busy = 1;
                if (ngx_thread_task_post(pool, sw->task) == NGX_OK) {
                    return;                /* re-armed by cvmfs_swarm_done */
                }
                sw->busy = 0;
            }
            break;
        }
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) sw->reg->interval * 1000);
    }
}

ngx_int_t
brix_cvmfs_swarm_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t i;

    /* EVERY worker gossips: backend instances (and so the published ring)
     * are per-worker. N workers probing is N× a tiny roster GET. */
    for (i = 0; i < cvmfs_swarm_regs_n; i++) {
        ngx_thread_task_t *task;
        cvmfs_swarm_ctx_t *sw;

        task = ngx_thread_task_alloc(cycle->pool, sizeof(cvmfs_swarm_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }
        sw = task->ctx;
        sw->task = task;
        sw->reg  = &cvmfs_swarm_regs[i];
        sw->self = -1;

        brix_task_bind(task, cvmfs_swarm_thread, cvmfs_swarm_done);
        task->event.log = cycle->log;

        sw->timer.handler = cvmfs_swarm_fire;
        sw->timer.data    = sw;
        sw->timer.log     = cycle->log;
        ngx_add_timer(&sw->timer, (ngx_msec_t) sw->reg->interval * 1000
                                  + (ngx_msec_t) (ngx_random() % 500));

        cvmfs_swarm_ctxs[i] = sw;
    }
    return NGX_OK;
}
