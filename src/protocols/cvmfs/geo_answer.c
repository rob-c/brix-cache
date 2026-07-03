/* geo_answer.c — server-side RTT-ranked answer to the CVMFS geo API.
 *
 * WHAT: when xrootd_cvmfs_geo_answer is `rtt`, this replaces the blind upstream
 *       passthrough (geo.c): it parses the client-supplied server list, measures
 *       TCP-connect RTT from THIS proxy to each server, and replies with the
 *       nearest-first 1-based permutation the CVMFS client expects. Because the
 *       proxy sits next to the client, its RTT is the client's effective
 *       proximity — so a buggy/mis-ordered upstream GeoAPI (probing distant
 *       Stratum-1s) is bypassed entirely (replace, not repair).
 * WHY:  a client that receives a bad geo order flails to far servers before
 *       falling back; answering authoritatively from here keeps it on the near
 *       ones without trusting the upstream answer.
 * HOW:  the geo.c async idiom — parse + cache-read on the event loop, blocking
 *       connect probes on a thread-pool task, fold/rank/respond in the done
 *       handler. Ranking uses three order-preserving buckets:
 *         reachable (by RTT) → unreachable → unprobed (guard-skipped / over-cap),
 *       so a server is never dropped and the client always gets a complete,
 *       well-formed permutation. The list is client-supplied, so probing is
 *       guarded: only CVMFS server ports {80,443,8000}, capped at
 *       xrootd_cvmfs_geo_max_servers — the node cannot be turned into a general
 *       port scanner. A short per-worker EWMA cache (keyed host:port) answers
 *       repeat/remount requests without re-probing. Any parse/setup failure
 *       falls back to xrootd_cvmfs_geo_passthrough.
 */
#include "cvmfs.h"
#include "origin_geo.h"
#include "core/aio/aio.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CVMFS_GEO_MAX_ENTRIES     64      /* hard cap on the parsed list      */
#define CVMFS_GEO_PROBE_TIMEOUT_MS 1000   /* per-server connect probe budget  */
#define CVMFS_GEO_CACHE_SLOTS     256u    /* per-worker EWMA cache (pow2 mask) */

/* Metric bucket bases: reachable RTTs (µs, small) sort first; unreachable and
 * unprobed sort after, each preserving the client's original relative order via
 * the +index tiebreak. The gaps dwarf any real RTT so buckets never overlap. */
#define CVMFS_GEO_M_UNREACHABLE   1.0e12
#define CVMFS_GEO_M_UNPROBED      2.0e12

/* One parsed server-list entry. */
typedef struct {
    char    host[256];
    int     port;
    int     valid;        /* parseable + allowed port + within cap → probe   */
    int     need_probe;   /* valid && cache miss/stale                       */
    double  cached_ewma;  /* valid && !need_probe: the fresh cached RTT       */
    long    sample_us;    /* thread result when need_probe (−1 = unreachable) */
} cvmfs_geo_entry_t;

typedef struct {
    ngx_http_request_t *r;
    int                 n;
    time_t              ttl;
    u_char             *body;          /* pool-allocated response buffer      */
    size_t              body_len;
    cvmfs_geo_entry_t   e[CVMFS_GEO_MAX_ENTRIES];
} cvmfs_geo_task_t;

/* Per-worker RTT cache: event-loop-only (read at entry, folded in done), so no
 * lock — the same worker-local discipline as the gate.c negative memo. */
typedef struct {
    uint64_t  key;         /* FNV-1a of "host:port"; 0 = empty slot           */
    double    ewma_us;     /* 0 = no sample                                   */
    time_t    updated;
} cvmfs_geo_slot_t;

static cvmfs_geo_slot_t  cvmfs_geo_cache[CVMFS_GEO_CACHE_SLOTS];

static uint64_t
cvmfs_geo_key(const char *host, int port)
{
    uint64_t h = 0xcbf29ce484222325ull;
    const char *p;
    char portbuf[8];
    int  i, n;

    for (p = host; *p != '\0'; p++) {
        h = (h ^ (unsigned char) *p) * 0x100000001b3ull;
    }
    n = snprintf(portbuf, sizeof(portbuf), ":%d", port);
    for (i = 0; i < n; i++) {
        h = (h ^ (unsigned char) portbuf[i]) * 0x100000001b3ull;
    }
    return (h != 0) ? h : 1;
}

static int
cvmfs_geo_port_allowed(int port)
{
    return port == 80 || port == 443 || port == 8000;
}

/* Parse one "host" or "host:port" token into `e`. A token with a non-host
 * character (a coordinate literal, IPv6, garbage) or a disallowed port is left
 * !valid — it keeps its response slot but lands in the unprobed bucket. */
static void
cvmfs_geo_parse_entry(const u_char *tok, size_t len, cvmfs_geo_entry_t *e)
{
    size_t i, hlen = 0;
    int    port = 80;

    e->valid = 0;
    e->need_probe = 0;
    e->cached_ewma = 0.0;
    e->sample_us = -1;
    e->host[0] = '\0';
    e->port = 0;

    if (len == 0) {
        return;
    }
    /* host run: [a-zA-Z0-9.-] */
    for (i = 0; i < len; i++) {
        u_char c = tok[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '.' || c == '-')
        {
            if (hlen + 1 >= sizeof(e->host)) {
                return;                        /* host too long → unprobed    */
            }
            e->host[hlen++] = (char) c;
            continue;
        }
        break;
    }
    if (hlen == 0) {
        return;                                /* no host → unprobed          */
    }
    e->host[hlen] = '\0';

    if (i < len) {
        /* the only accepted separator is ":<digits>" to end-of-token */
        if (tok[i] != ':') {
            return;
        }
        port = 0;
        for (i++; i < len; i++) {
            if (tok[i] < '0' || tok[i] > '9') {
                return;                        /* junk after host → unprobed  */
            }
            port = port * 10 + (tok[i] - '0');
            if (port > 65535) {
                return;
            }
        }
        if (port == 0) {
            return;
        }
    }
    e->port = port;
    e->valid = cvmfs_geo_port_allowed(port);   /* guard: CVMFS server ports   */
}

/* Split the server list (last '/'-segment of the geo URI) into entries. Returns
 * the count, or −1 to signal the caller to fall back to passthrough (no list,
 * or more servers than we can index). */
static int
cvmfs_geo_parse(ngx_http_request_t *r, cvmfs_geo_task_t *t, ngx_uint_t max_probe)
{
    const u_char *uri = r->uri.data;
    const u_char *end = uri + r->uri.len;
    const u_char *slash = NULL, *p, *tok;
    int           n = 0;

    for (p = uri; p < end; p++) {
        if (*p == '/') {
            slash = p;
        }
    }
    if (slash == NULL || slash + 1 >= end) {
        return -1;
    }
    tok = slash + 1;
    for (p = tok; p <= end; p++) {
        if (p == end || *p == ',') {
            if (n >= CVMFS_GEO_MAX_ENTRIES) {
                return -1;                     /* absurd list → passthrough   */
            }
            cvmfs_geo_parse_entry(tok, (size_t) (p - tok), &t->e[n]);
            if ((ngx_uint_t) n >= max_probe) {
                t->e[n].valid = 0;             /* over cap → unprobed          */
            }
            n++;
            tok = p + 1;
        }
    }
    t->n = n;
    return (n > 0) ? 0 : -1;
}

/* Event-loop pre-pass: mark each valid entry probe-needed unless a fresh cache
 * entry answers it. */
static void
cvmfs_geo_cache_read(cvmfs_geo_task_t *t, time_t now)
{
    int i;

    for (i = 0; i < t->n; i++) {
        cvmfs_geo_entry_t *e = &t->e[i];
        cvmfs_geo_slot_t  *s;
        uint64_t           k;

        if (!e->valid) {
            continue;
        }
        k = cvmfs_geo_key(e->host, e->port);
        s = &cvmfs_geo_cache[k & (CVMFS_GEO_CACHE_SLOTS - 1)];
        if (s->key == k && s->ewma_us > 0.0 && (now - s->updated) < t->ttl) {
            e->need_probe  = 0;
            e->cached_ewma = s->ewma_us;
        } else {
            e->need_probe = 1;
        }
    }
}

/* Done-side: fold one fresh (reachable) sample into the cache and return the
 * effective EWMA. Folds onto an existing same-key sample, else seeds it. */
static double
cvmfs_geo_cache_fold(const cvmfs_geo_entry_t *e, time_t now)
{
    uint64_t          k = cvmfs_geo_key(e->host, e->port);
    cvmfs_geo_slot_t *s = &cvmfs_geo_cache[k & (CVMFS_GEO_CACHE_SLOTS - 1)];
    double            sample = (double) e->sample_us;
    double            ewma;

    ewma = (s->key == k && s->ewma_us > 0.0)
         ? s->ewma_us * 0.75 + sample * 0.25
         : sample;
    s->key = k;
    s->ewma_us = ewma;
    s->updated = now;
    return ewma;
}

/* thread-pool side: probe every entry that needs it (blocking connects). */
static void
cvmfs_geo_thread(void *data, ngx_log_t *log)
{
    cvmfs_geo_task_t *t = data;
    int               i;

    (void) log;
    for (i = 0; i < t->n; i++) {
        cvmfs_geo_entry_t *e = &t->e[i];

        if (e->valid && e->need_probe) {
            e->sample_us = xrootd_cvmfs_connect_rtt_us(e->host, e->port,
                                                       CVMFS_GEO_PROBE_TIMEOUT_MS);
        }
    }
}

/* Build the nearest-first 1-based permutation string into t->body. */
static void
cvmfs_geo_render(cvmfs_geo_task_t *t, time_t now)
{
    double metric[CVMFS_GEO_MAX_ENTRIES];
    int    ranks[CVMFS_GEO_MAX_ENTRIES];
    int    order[CVMFS_GEO_MAX_ENTRIES];
    int    i;
    size_t off = 0;
    size_t cap = (size_t) t->n * 8 + 2;

    for (i = 0; i < t->n; i++) {
        cvmfs_geo_entry_t *e = &t->e[i];

        if (!e->valid) {
            metric[i] = CVMFS_GEO_M_UNPROBED + i;
        } else if (!e->need_probe) {
            metric[i] = e->cached_ewma;                 /* reachable bucket  */
        } else if (e->sample_us >= 0) {
            metric[i] = cvmfs_geo_cache_fold(e, now);   /* reachable bucket  */
        } else {
            metric[i] = CVMFS_GEO_M_UNREACHABLE + i;    /* unreachable       */
        }
    }

    xrootd_cvmfs_rank_by_metric(metric, t->n, ranks);
    for (i = 0; i < t->n; i++) {
        order[ranks[i]] = i + 1;                        /* 1-based index     */
    }
    for (i = 0; i < t->n && off < cap; i++) {
        int w = snprintf((char *) t->body + off, cap - off, "%s%d",
                         (i > 0) ? "," : "", order[i]);
        if (w < 0 || (size_t) w >= cap - off) {
            break;
        }
        off += (size_t) w;
    }
    if (off + 1 < cap) {
        t->body[off++] = '\n';
    }
    t->body_len = off;
}

/* event-loop side: fold + rank + respond. */
static void
cvmfs_geo_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    cvmfs_geo_task_t   *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_connection_t   *c = r->connection;
    ngx_buf_t          *b;
    ngx_chain_t         out;

    cvmfs_geo_render(t, ngx_time());

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) t->body_len;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    if (ngx_http_send_header(r) != NGX_OK || r->header_only || t->body_len == 0) {
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
        ngx_http_run_posted_requests(c);
        return;
    }
    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }
    b->pos = b->start = t->body;
    b->last = b->end = t->body + t->body_len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
    ngx_http_run_posted_requests(c);
}

ngx_int_t
xrootd_cvmfs_geo_answer(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    ngx_thread_task_t *task;
    cvmfs_geo_task_t  *t;
    ngx_thread_pool_t *pool;
    ngx_uint_t         max_probe;

    pool = lcf->common.thread_pool;
    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = lcf->common.thread_pool_name.len > 0
                                  ? &lcf->common.thread_pool_name
                                  : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            lcf->common.thread_pool = pool;
        }
    }
    if (pool == NULL) {
        return xrootd_cvmfs_geo_passthrough(r, lcf);   /* no pool → relay     */
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(cvmfs_geo_task_t));
    if (task == NULL) {
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    }
    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->r = r;
    t->ttl = (lcf->cvmfs.geo_cache_ttl > 0) ? lcf->cvmfs.geo_cache_ttl : 60;

    max_probe = (lcf->cvmfs.geo_max_servers > 0) ? lcf->cvmfs.geo_max_servers
                                                 : 16;
    if (cvmfs_geo_parse(r, t, max_probe) != 0) {
        return xrootd_cvmfs_geo_passthrough(r, lcf);   /* unparseable → relay */
    }

    t->body = ngx_palloc(r->pool, (size_t) t->n * 8 + 2);
    if (t->body == NULL) {
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    }

    cvmfs_geo_cache_read(t, ngx_time());

    xrootd_task_bind(task, cvmfs_geo_thread, cvmfs_geo_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    }
    r->main->count++;
    return NGX_DONE;
}
