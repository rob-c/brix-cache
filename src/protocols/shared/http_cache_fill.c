/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 *
 * Phase-68 additions:
 *   - COALESCING: every concurrent request for one (inst,key) parks on a
 *     single heap-owned fill — a 40-request stampede is exactly ONE origin
 *     fetch. The waiter list is event-loop-only (no locks).
 *   - NEVER-DROP (T20): with a client-hold configured, the fill worker
 *     retries transient origin failures with jittered backoff until the
 *     hold deadline; a waiter whose hold expires detaches and receives
 *     504 + Retry-After on a KEPT-ALIVE connection (a TCP close is never
 *     an error signal — convention #6). A client abort detaches its waiter
 *     but never cancels the fill: the fill keeps retrying (max-life
 *     deadline) and publishes so the client's retry is a hit.
 *
 * Ownership: the fill ctx (+ its ngx_thread_task_t) is one calloc block,
 * freed in the done handler. Each waiter is freed by ITS REQUEST's pool
 * cleanup (which always fires exactly once), so a late cleanup can never
 * use-after-free a waiter the done handler already resolved.
 */
#include "http_cache_fill.h"
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_* */
#include "fs/backend/http/sd_http.h"    /* sd_http_n_endpoints (verify budget) */
#include "fs/cache/fill_retry.h"        /* T20 classification + backoff */
#include "core/aio/aio.h"                      /* brix_task_bind */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>
#include <stdlib.h>                          /* calloc/free (worker heap) */
#include <sys/socket.h>                     /* recv(MSG_PEEK): client-abort probe */

#if (NGX_THREADS)

struct brix_http_cache_fill_ctx_s;

/* One request parked on an in-flight fill (event-loop-only). */
typedef struct brix_http_fill_waiter_s {
    ngx_http_request_t                   *r;
    brix_http_cache_reenter_pt          reenter;
    void                                 *reenter_data;
    struct brix_http_fill_waiter_s     *next;
    struct brix_http_cache_fill_ctx_s  *owner;   /* valid while !resolved */
    ngx_event_t                           hold;    /* T20 client-hold timer */
    ngx_msec_t                            parked_ms;  /* attach timestamp   */
    unsigned                              resolved:1;
} brix_http_fill_waiter_t;

/* Per-fill task context — ONE per (inst,key) in flight, shared by every
 * concurrent request for that object. */
typedef struct brix_http_cache_fill_ctx_s {
    brix_sd_instance_t                *inst;
    brix_http_fill_waiter_t           *waiters;
    _Atomic int                          waiters_n;  /* read by the worker */
    struct brix_http_cache_fill_ctx_s *next;       /* in-flight list     */
    ngx_thread_task_t                   *task;       /* the calloc block   */
    time_t                               client_hold; /* T20 deadlines     */
    time_t                               max_life;
    ngx_int_t                            result;    /* NGX_OK/DECLINED/ERROR */
    int                                  err;       /* errno from the fill  */
    ngx_msec_t                           started_ms; /* fill post timestamp */
    unsigned                             attempts;   /* origin attempts run */
    char                                 key[PATH_MAX];
} brix_http_cache_fill_ctx_t;

/* Sanitize the (wire-derived) object key for a log line. */
static const char *
brix_http_fill_log_key(const char *key, char *buf, size_t cap)
{
    brix_sanitize_log_string(key, buf, cap);
    return buf;
}

/* Per-worker in-flight fills (event-loop-only; a handful at a time). */
static brix_http_cache_fill_ctx_t  *brix_http_fills;

static brix_http_cache_fill_ctx_t *
brix_http_fill_find(brix_sd_instance_t *inst, const char *key)
{
    brix_http_cache_fill_ctx_t *t;

    for (t = brix_http_fills; t != NULL; t = t->next) {
        if (t->inst == inst && ngx_strcmp(t->key, key) == 0) {
            return t;
        }
    }
    return NULL;
}

/* Unlink `w` from its fill (idempotent; both the hold timer and the request
 * cleanup may race to it on the event loop). */
static void
brix_http_fill_detach(brix_http_fill_waiter_t *w)
{
    brix_http_fill_waiter_t **pp;

    if (w->resolved) {
        return;
    }
    w->resolved = 1;
    /* Un-arm the parked-window client-abort handler: past this point the
     * request is either served (reenter), sent a 504, or being finalized —
     * downstream read handling reverts to nginx's default, exactly as before
     * the request parked. */
    if (w->r != NULL) {
        w->r->read_event_handler = ngx_http_block_reading;
    }
    if (w->hold.timer_set) {
        ngx_del_timer(&w->hold);
    }
    for (pp = &w->owner->waiters; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == w) {
            *pp = w->next;
            break;
        }
    }
    atomic_fetch_sub_explicit(&w->owner->waiters_n, 1, memory_order_relaxed);
}

/* 504 + Retry-After on a KEPT-ALIVE connection (convention #6: origin
 * trouble is a well-formed HTTP answer, never a broken socket). */
static void
brix_http_fill_send_retry_later(ngx_http_request_t *r)
{
    static u_char     body[] = "origin temporarily unreachable; retrying - "
                               "please retry\n";
    ngx_table_elt_t  *h;
    ngx_buf_t        *b;
    ngx_chain_t       out;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Retry-After");
    ngx_str_set(&h->value, "2");

    r->headers_out.status = NGX_HTTP_GATEWAY_TIME_OUT;
    r->headers_out.content_length_n = sizeof(body) - 1;
    r->keepalive = 1;                       /* NEVER close on origin trouble */
    if (ngx_http_send_header(r) != NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, NGX_OK);
        return;
    }
    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    b->pos = b->start = body;
    b->last = b->end = body + sizeof(body) - 1;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}

/* T20 hold timer: the client has waited long enough — answer 504 on the
 * kept-alive connection and leave the fill running (its own retry, arriving
 * on the same warm socket, coalesces onto this still-running fill). */
static void
brix_http_fill_hold_expire(ngx_event_t *ev)
{
    brix_http_fill_waiter_t *w = ev->data;
    ngx_http_request_t        *r = w->r;
    ngx_connection_t          *c = r->connection;

    /* Diagnosis line for hold/CVMFS_TIMEOUT misalignment: WHO waited HOW
     * LONG on WHAT while the origin still hadn't answered. */
    if (w->owner != NULL) {
        char kbuf[256];

        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "xrootd-fill: event=hold-expired key=\"%s\" client=%V "
            "held_ms=%M fill_elapsed_ms=%M waiters_left=%d "
            "action=\"504+Retry-After sent on the kept-alive connection; "
            "the fill keeps running\"",
            brix_http_fill_log_key(w->owner->key, kbuf, sizeof(kbuf)),
            &c->addr_text,
            (ngx_msec_t) (ngx_current_msec - w->parked_ms),
            (ngx_msec_t) (ngx_current_msec - w->owner->started_ms),
            atomic_load_explicit(&w->owner->waiters_n,
                                 memory_order_relaxed) - 1);
    }

    brix_http_fill_detach(w);
    brix_http_fill_send_retry_later(r);
    ngx_http_run_posted_requests(c);
}

/* Request-pool cleanup: the waiter's single owner for freeing. Fires exactly
 * once per parked request — after the done handler resolved it (resolved=1,
 * just free) or on a client abort mid-fill (detach, then free; the fill
 * itself is NEVER cancelled). */
static void
brix_http_fill_waiter_cleanup(void *data)
{
    brix_http_fill_waiter_t *w = data;

    /* Still attached at teardown = an ABNORMAL finalize the read-abort
     * handler and the hold timer both missed (worker shutdown mid-fill, or
     * nginx forcibly closing the request). The routine client-abort case is
     * logged promptly by brix_http_fill_client_read; this is the safety
     * net so a parked request never disappears without a trace. */
    if (!w->resolved && w->owner != NULL) {
        ngx_connection_t *c = w->r->connection;
        char              kbuf[256];

        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "xrootd-fill: event=parked-teardown key=\"%s\" client=%V "
            "parked_ms=%M fill_elapsed_ms=%M "
            "cause=\"request finalized while parked (worker shutdown or "
            "forced close); the fill continues detached\"",
            brix_http_fill_log_key(w->owner->key, kbuf, sizeof(kbuf)),
            &c->addr_text,
            (ngx_msec_t) (ngx_current_msec - w->parked_ms),
            (ngx_msec_t) (ngx_current_msec - w->owner->started_ms));
    }

    brix_http_fill_detach(w);
    free(w);
}

/* Find the waiter parked for request `r` (a handful in flight; linear is
 * fine). NULL if `r` is not currently parked on any fill. */
static brix_http_fill_waiter_t *
brix_http_fill_waiter_for(ngx_http_request_t *r)
{
    brix_http_cache_fill_ctx_t *t;
    brix_http_fill_waiter_t    *w;

    for (t = brix_http_fills; t != NULL; t = t->next) {
        for (w = t->waiters; w != NULL; w = w->next) {
            if (w->r == r) {
                return w;
            }
        }
    }
    return NULL;
}

/* Read-event handler for a PARKED request: nginx normally ignores downstream
 * reads while a request is suspended (r->main->count raised), so a client
 * that breaks its connection mid-fill would go unnoticed until its hold timer
 * fires. Detecting it here lets us log the broken client, reclaim its parked
 * slot immediately, and finalize — while the fill keeps running detached
 * (never-drop: one client hanging up must not cancel the origin fetch that
 * other clients, or the client's own retry, still need). */
static void
brix_http_fill_client_read(ngx_http_request_t *r)
{
    ngx_connection_t          *c = r->connection;
    ngx_event_t               *rev = c->read;
    brix_http_fill_waiter_t *w;
    u_char                     probe;
    ssize_t                    n;

    if (!rev->ready && !rev->eof) {
        return;                                  /* spurious wakeup */
    }
    /* Peek: EOF (0) or a hard error means the client is gone; EAGAIN means it
     * merely sent data we don't want (ignore — never-drop keeps waiting). */
    n = recv(c->fd, &probe, 1, MSG_PEEK);
    if (n > 0) {
        return;
    }
    if (n < 0 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
        return;
    }

    w = brix_http_fill_waiter_for(r);
    if (w != NULL && w->owner != NULL) {
        char kbuf[256];

        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "xrootd-fill: event=client-gone key=\"%s\" client=%V "
            "parked_ms=%M fill_elapsed_ms=%M waiters_left=%d "
            "hint=\"client broke the connection before the origin answered; "
            "the fill continues detached. If this recurs the client timeout "
            "is shorter than the fill latency (CVMFS_TIMEOUT vs client_hold)\"",
            brix_http_fill_log_key(w->owner->key, kbuf, sizeof(kbuf)),
            &c->addr_text,
            (ngx_msec_t) (ngx_current_msec - w->parked_ms),
            (ngx_msec_t) (ngx_current_msec - w->owner->started_ms),
            atomic_load_explicit(&w->owner->waiters_n,
                                 memory_order_relaxed) - 1);
        brix_http_fill_detach(w);              /* resolved=1: no dup log */
        r->main->count--;                        /* release the parked ref */
    }
    c->error = 1;
    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}

/* Park `r` on fill `t` (r->main->count++ balanced by the finalize in done /
 * hold-expiry / abort teardown). */
static ngx_int_t
brix_http_fill_attach(brix_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, brix_http_cache_reenter_pt reenter,
    void *reenter_data)
{
    brix_http_fill_waiter_t *w = calloc(1, sizeof(*w));
    ngx_pool_cleanup_t        *cln;

    if (w == NULL) {
        return NGX_ERROR;
    }
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        free(w);
        return NGX_ERROR;
    }
    w->r            = r;
    w->reenter      = reenter;
    w->reenter_data = reenter_data;
    w->parked_ms    = ngx_current_msec;
    w->owner        = t;
    w->next         = t->waiters;
    t->waiters      = w;
    atomic_fetch_add_explicit(&t->waiters_n, 1, memory_order_relaxed);

    cln->handler = brix_http_fill_waiter_cleanup;
    cln->data    = w;

    if (t->client_hold > 0) {
        w->hold.handler = brix_http_fill_hold_expire;
        w->hold.data    = w;
        w->hold.log     = r->connection->log;
        ngx_add_timer(&w->hold, (ngx_msec_t) t->client_hold * 1000);
    }

    /* Notice a client that breaks its connection while parked (above): the
     * read handler logs it, reclaims this slot, and finalizes — the fill
     * runs on. Arm the read event so the abort actually wakes us. */
    r->read_event_handler = brix_http_fill_client_read;
    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        /* non-fatal: we simply fall back to the hold timer for teardown */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "xrootd-fill: could not arm client-abort read event");
    }

    r->main->count++;
    return NGX_DONE;
}

/* Worker thread: run the blocking source->store fill off the event loop,
 * retrying transient origin failures to the T20 deadlines (single-pass when
 * no hold is configured — the pre-phase-68 semantics for other protocols). */
static void
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
            "xrootd: cache fill declined for \"%s\" (object not cacheable and "
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
static void
brix_http_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    brix_http_cache_fill_ctx_t  *t = task->ctx;
    brix_http_cache_fill_ctx_t **pp;
    brix_http_fill_waiter_t     *w;

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

    while ((w = t->waiters) != NULL) {
        brix_http_fill_detach(w);              /* unlink + stop the hold */
        brix_http_fill_resolve_waiter(t, w);
    }
    free(t->task);           /* the calloc'd task+ctx block (task is first) */
}

/* Lazily resolve the export's async thread pool: server postconfig fills only the
 * server-level loc_conf, so a nested location block resolves on first use (the
 * webdav/copy.c idiom). NULL when no pool is configured. */
static ngx_thread_pool_t *
brix_http_cache_fill_pool(ngx_http_brix_shared_conf_t *common)
{
    ngx_thread_pool_t *pool = common->thread_pool;

    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = common->thread_pool_name.len > 0
                                  ? &common->thread_pool_name : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            common->thread_pool = pool;
        }
    }
    return pool;
}

ngx_int_t
brix_http_cache_fill_if_needed(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key,
    ngx_http_brix_shared_conf_t *common,
    brix_http_cache_reenter_pt reenter, void *reenter_data)
{
    ngx_thread_task_t            *task;
    brix_http_cache_fill_ctx_t *t;
    ngx_thread_pool_t            *pool;
    u_char                       *block;

    if (inst == NULL || key == NULL || reenter == NULL || common == NULL
        || !brix_sd_cache_fill_needs_offload(inst, key))
    {
        return NGX_DECLINED;                 /* serve inline (hit / local / none) */
    }

    /* Coalesce onto an in-flight fill of the same object: the stampede case
     * (N concurrent cold reads) is exactly ONE origin fetch. */
    t = brix_http_fill_find(inst, key);
    if (t != NULL) {
        return brix_http_fill_attach(t, r, reenter, reenter_data);
    }

    pool = brix_http_cache_fill_pool(common);
    if (pool == NULL) {
        /* No pool: nothing can run off-loop, so fall through to the inline path
         * (preserves the pre-SP2 behaviour - a remote miss may stall/fail). */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "xrootd: cache miss on \"%s\" needs an async thread pool to fill a "
            "remote tier; none configured - serving inline (may stall)", key);
        return NGX_DECLINED;
    }

    /* Heap-owned task + ctx: the fill is shared by every parked request and
     * must not live in any one request's pool (an aborted first requester
     * would otherwise free the memory under the running task). */
    block = calloc(1, sizeof(ngx_thread_task_t)
                      + sizeof(brix_http_cache_fill_ctx_t));
    if (block == NULL) {
        return NGX_ERROR;
    }
    task = (ngx_thread_task_t *) block;
    task->ctx = block + sizeof(ngx_thread_task_t);
    t = task->ctx;
    t->inst        = inst;
    t->task        = task;
    t->result      = NGX_ERROR;
    t->client_hold = common->cache_client_hold;   /* 0 = single-pass fill */
    t->max_life    = common->cache_fill_max_life;
    t->started_ms  = ngx_current_msec;
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));

    brix_task_bind(task, brix_http_cache_fill_thread,
                     brix_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (brix_http_fill_attach(t, r, reenter, reenter_data) != NGX_DONE) {
        free(block);
        return NGX_ERROR;
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        brix_http_fill_detach(t->waiters);     /* undo the attach        */
        r->main->count--;
        free(block);
        return NGX_ERROR;
    }

    t->next = brix_http_fills;                 /* publish for coalescing */
    brix_http_fills = t;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "xrootd: offloaded cache fill of \"%s\" to the thread pool", key);
    return NGX_DONE;
}

#else  /* !NGX_THREADS */

/* Built without --with-threads: no pool to offload onto, so the caller keeps its
 * inline open/fill path (correct for a local tier; a remote tier is unsupported
 * without threads, exactly as before SP2). */
ngx_int_t
brix_http_cache_fill_if_needed(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key,
    ngx_http_brix_shared_conf_t *common,
    brix_http_cache_reenter_pt reenter, void *reenter_data)
{
    (void) r;
    (void) inst;
    (void) key;
    (void) common;
    (void) reenter;
    (void) reenter_data;
    return NGX_DECLINED;
}

#endif /* NGX_THREADS */
