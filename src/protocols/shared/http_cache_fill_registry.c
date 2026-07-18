/*
 * http_cache_fill_registry.c - coalescing waiter registry for the HTTP
 * cache-miss fill path. Split verbatim from http_cache_fill.c (zero behaviour
 * change); see http_cache_fill.h / http_cache_fill_internal.h for the WHAT/WHY.
 *
 * This unit owns the per-worker in-flight-fill list and the per-request waiters
 * that park on a fill: attach/detach, the T20 client-hold timer, the parked
 * client-abort probe, and the keep-alive 504 answer. It is event-loop-only.
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

/* Sanitize the (wire-derived) object key for a log line. */
const char *
brix_http_fill_log_key(const char *key, char *buf, size_t cap)
{
    brix_sanitize_log_string(key, buf, cap);
    return buf;
}

/* Per-worker in-flight fills (event-loop-only; a handful at a time). */
brix_http_cache_fill_ctx_t  *brix_http_fills;

brix_http_cache_fill_ctx_t *
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
void
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
void
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
ngx_int_t
brix_http_fill_attach(brix_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, brix_http_cache_reenter_pt reenter,
    void *reenter_data)
{
    /* padded to ngx_connection_t: with --with-debug, ngx_add_timer's debug
     * line casts ev->data (== w, via w->hold) to a connection to read ->fd;
     * keep that read in-bounds (zeroed) instead of past the allocation. */
    size_t wsz = sizeof(brix_http_fill_waiter_t) > sizeof(ngx_connection_t)
                     ? sizeof(brix_http_fill_waiter_t)
                     : sizeof(ngx_connection_t);
    brix_http_fill_waiter_t *w = calloc(1, wsz);
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

#endif /* NGX_THREADS */
