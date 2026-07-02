/* fill_retry.c — see header. The classification table is convention #7 of
 * the phase-68 plan; keep the two in sync. */
#include "fill_retry.h"

#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define FILL_BACKOFF_START_MS 250
#define FILL_BACKOFF_CAP_MS   8000

void
xrootd_fill_retry_init(xrootd_fill_retry_t *rs, time_t client_hold,
    time_t max_life, _Atomic int *waiters, unsigned n_endpoints)
{
    rs->backoff_ms = FILL_BACKOFF_START_MS;
    rs->start = time(NULL);
    rs->client_hold = client_hold;
    rs->max_life = max_life;
    rs->waiters = waiters;
    rs->verify_budget = (n_endpoints > 0) ? n_endpoints : 1;
}

xrootd_fill_class_e
xrootd_fill_classify(ngx_int_t fill_rc, int err, xrootd_fill_retry_t *rs)
{
    if (fill_rc == NGX_OK || fill_rc == NGX_DECLINED) {
        return XROOTD_FILL_OK;
    }
    if (err == ENOENT || err == ENOTDIR || err == EACCES || err == EPERM) {
        return XROOTD_FILL_DEFINITIVE;     /* 404/403: the origin's answer  */
    }
    if (err == EBADMSG) {
        /* digest MISMATCH: corruption is often path-local — try each
         * remaining endpoint once, then give up definitively (502 — the
         * data is proven bad, not "come back later"). */
        if (rs->verify_budget > 0) {
            rs->verify_budget--;
            return XROOTD_FILL_RETRY;
        }
        return XROOTD_FILL_DEFINITIVE;
    }
    return XROOTD_FILL_RETRY;              /* refused/unreach/timeout/5xx   */
}

int
xrootd_fill_retry_wait(xrootd_fill_retry_t *rs)
{
    time_t      now = time(NULL);
    time_t      window;
    ngx_msec_t  d;

    window = (atomic_load_explicit(rs->waiters, memory_order_relaxed) > 0)
           ? rs->client_hold : rs->max_life;
    if (window <= 0 || now >= rs->start + window) {
        return 0;
    }
    /* half-jitter: [backoff/2, backoff) — decorrelates a farm of fills */
    d = rs->backoff_ms / 2
      + (ngx_msec_t) (random() % (rs->backoff_ms / 2 + 1));
    if (rs->backoff_ms < FILL_BACKOFF_CAP_MS) {
        rs->backoff_ms *= 2;
    }
    usleep((useconds_t) d * 1000);         /* fill worker thread: sleeping OK */
    return 1;
}
