/*
 * http_cache_fill_worker.c - the off-event-loop fill worker and its completion
 * finalize. Split verbatim from http_cache_fill.c (zero behaviour change); see
 * http_cache_fill.h / http_cache_fill_internal.h for the WHAT/WHY.
 *
 * This unit runs the blocking source->store fill on the thread pool (with the
 * T20 retry schedule) and, back on the event loop, resolves every coalesced
 * waiter with the single outcome and releases the heap-owned fill block.
 */
#include "http_cache_fill.h"
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_* */
#include "fs/backend/http/sd_http.h"    /* sd_http_n_endpoints (verify budget) */
#include "fs/cache/fill_retry.h"        /* T20 classification + backoff */
#include "core/aio/aio.h"                      /* brix_task_bind */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */
#include "observability/sesslog/sesslog_ngx.h"

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>
#include <stdlib.h>                          /* calloc/free (worker heap) */
#include <sys/socket.h>                     /* recv(MSG_PEEK): client-abort probe */

#include "http_cache_fill_internal.h"

#if (NGX_THREADS)

/* Worker thread: run the blocking source->store fill off the event loop,
 * retrying transient origin failures to the T20 deadlines (single-pass when
 * no hold is configured — the pre-phase-68 semantics for other protocols). */
void
brix_http_cache_fill_thread(void *data, ngx_log_t *log)
{
    brix_http_cache_fill_ctx_t *t = data;
    brix_fill_retry_t           rs;
    unsigned                      n_eps;
    char                          kbuf[256];

    n_eps = (unsigned) sd_http_n_endpoints(
                brix_sd_cache_source_instance(t->inst));
    brix_fill_retry_init(&rs, t->client_hold, t->max_life, &t->waiters_n,
                           n_eps);
    for ( ;; ) {
        errno = 0;
        t->attempts++;
        t->result = brix_sd_cache_fill_key(t->inst, t->key);
        t->err = errno;
        switch (brix_fill_classify(t->result, t->err, &rs)) {
        case BRIX_FILL_OK:
            if (t->attempts > 1) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd-fill: event=recovered key=\"%s\" attempts=%ud "
                    "elapsed_ms=%M — origin answered after transient failures",
                    brix_http_fill_log_key(t->key, kbuf, sizeof(kbuf)),
                    t->attempts,
                    (ngx_msec_t) (ngx_current_msec - t->started_ms));
            }
            return;
        case BRIX_FILL_DEFINITIVE:
            return;
        case BRIX_FILL_RETRY:
            break;
        }
        /* One line per failed attempt: WHICH object, WHICH attempt, WHY —
         * the trail that locates a flapping origin or a lossy WAN window.
         * Bounded by the backoff schedule (a handful per fill, worst case). */
        ngx_log_error(NGX_LOG_WARN, log, t->err,
            "xrootd-fill: event=retry key=\"%s\" attempt=%ud rc=%i "
            "elapsed_ms=%M endpoints=%ud waiters=%d next_backoff_ms=%M",
            brix_http_fill_log_key(t->key, kbuf, sizeof(kbuf)),
            t->attempts, t->result,
            (ngx_msec_t) (ngx_current_msec - t->started_ms), n_eps,
            atomic_load_explicit(&t->waiters_n, memory_order_relaxed),
            rs.backoff_ms);
        if (!brix_fill_retry_wait(&rs)) {
            if (t->err == EBADMSG) {
                return;              /* proven-bad data: 502, not "later" */
            }
            t->err = ETIMEDOUT;      /* deadline exhausted: 504 to waiters */
            return;
        }
    }
}

/* Resolve one waiter with the fill outcome (event loop). */
static void
brix_http_fill_resolve_waiter(brix_http_cache_fill_ctx_t *t,
    brix_http_fill_waiter_t *w)
{
    ngx_http_request_t *r = w->r;
    ngx_connection_t   *c = r->connection;
    ngx_int_t           rc;

    if (t->result == NGX_OK) {
        rc = w->reenter(r, w->reenter_data);    /* hit -> serve (zero-copy) */
    } else if (t->result == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "brix: cache fill declined for \"%s\" (object not cacheable and "
            "remote-source streaming is not yet supported) - returning 502",
            t->key);
        rc = NGX_HTTP_BAD_GATEWAY;
    } else if (t->err == ENOENT || t->err == ENOTDIR) {
        /* The origin's definitive answer: the object does not exist. */
        rc = NGX_HTTP_NOT_FOUND;
    } else if (t->err == EACCES || t->err == EPERM) {
        rc = NGX_HTTP_FORBIDDEN;
    } else if (t->err == ETIMEDOUT) {
        /* T20: deadline exhausted while this waiter was still attached —
         * same keep-alive 504 the hold timer sends. */
        brix_http_fill_send_retry_later(r);
        ngx_http_run_posted_requests(c);
        return;
    } else {
        /* per-waiter detail at debug; the fill-level ERR line in done()
         * carries the full story once, not once per parked client */
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "xrootd-fill: resolving waiter with 502 (key \"%s\", err %d)",
            t->key, t->err);
        rc = NGX_HTTP_BAD_GATEWAY;
    }

    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* Event loop: resolve EVERY still-attached waiter with the one fill outcome
 * (the stampede coalescing contract), then release the fill. Waiter memory
 * stays with its request's pool cleanup. */
void
brix_http_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    brix_http_cache_fill_ctx_t  *t = task->ctx;
    brix_http_cache_fill_ctx_t **pp;
    brix_http_fill_waiter_t     *w;
    char                         errscratch[BRIX_SESSLOG_ERR_MAX];
    const char                  *err;
    int                          ok;

    /* Unlink from the in-flight list FIRST so a re-entered handler that
     * misses again starts a fresh fill rather than attaching to this one. */
    for (pp = &brix_http_fills; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }

    /* ONE outcome line per fill — the anchor every other event (retry /
     * hold-expired / client-gone) correlates with via the key. */
    {
        int   waiters = atomic_load_explicit(&t->waiters_n,
                                             memory_order_relaxed);
        char  kbuf[256];
        const char *k = brix_http_fill_log_key(t->key, kbuf, sizeof(kbuf));
        ngx_msec_t elapsed = ngx_current_msec - t->started_ms;

        if (t->result == NGX_OK) {
            ngx_uint_t lvl = (waiters > 0) ? NGX_LOG_INFO : NGX_LOG_NOTICE;

            ngx_log_error(lvl, ev->log, 0,
                "xrootd-fill: event=%s key=\"%s\" attempts=%ud "
                "elapsed_ms=%M waiters=%d",
                (waiters > 0) ? "done" : "done-detached", k,
                t->attempts, elapsed, waiters);
        } else if (t->err == ENOENT || t->err == ENOTDIR) {
            ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                "xrootd-fill: event=not-found key=\"%s\" attempts=%ud "
                "elapsed_ms=%M waiters=%d — the origin's definitive 404",
                k, t->attempts, elapsed, waiters);
        } else if (t->err == ETIMEDOUT) {
            ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                "xrootd-fill: event=exhausted key=\"%s\" attempts=%ud "
                "elapsed_ms=%M waiters=%d verdict=\"504 retry-later to every "
                "waiter; no origin answered within the deadline\"",
                k, t->attempts, elapsed, waiters);
        } else {
            ngx_log_error(NGX_LOG_ERR, ev->log, t->err,
                "xrootd-fill: event=failed key=\"%s\" attempts=%ud "
                "elapsed_ms=%M waiters=%d verdict=%s",
                k, t->attempts, elapsed, waiters,
                (t->err == EBADMSG)
                    ? "\"502; every endpoint served corrupt data "
                      "(verify quarantined the evidence)\""
                    : "\"502 to every waiter\"");
        }
    }

    ok = (t->result == NGX_OK);
    err = ok ? NULL : brix_sesslog_err_from_errno(t->err, errscratch,
                                                  sizeof(errscratch));
    brix_sess_result(t->sess, ok, t->key, BRIX_SESS_MODE_READ, err);
    brix_sess_xfer_end(t->sess, &t->sess_xfer,
                       ok ? BRIX_SESS_XFER_COMPLETE
                          : BRIX_SESS_XFER_ABORTED);
    brix_sess_end(t->sess, ok ? BRIX_SESS_END_SERVER
                               : BRIX_SESS_END_ERROR);

    while ((w = t->waiters) != NULL) {
        brix_http_fill_detach(w);              /* unlink + stop the hold */
        brix_http_fill_resolve_waiter(t, w);
    }
    free(t->task);           /* the calloc'd task+ctx block (task is first) */
}

#endif /* NGX_THREADS */
