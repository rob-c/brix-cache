/*
 * sd_http_select.c — endpoint selection, health scoring, and read failover for
 * the HTTP-origin storage driver.
 *
 * WHAT: Owns the ranked, health-scored endpoint set's decision logic — pick the
 *       best endpoint, run one request with one-alternate transport failover
 *       (phase-68 T11), record the outcome against the endpoint's EWMA health
 *       score, and emit the operator's origin-flap / origin-switch audit trail.
 *       sd_http_request_fo() is the single request primitive the read path
 *       (HEAD/GET) drives; sd_http_write_path() composes the endpoint-0 write
 *       URL for the write path (writes never fail over — that would split-brain
 *       the store).
 *
 * WHY:  Split out of sd_http.c (phase-79 file-size split): selection + failover
 *       is one cohesive concept, distinct from the read path (sd_http_read.c),
 *       the write path (sd_http_write.c), and the driver vtable/lifecycle
 *       (sd_http.c). The shared instance/endpoint layout comes from
 *       sd_http_internal.h; the per-request state (sd_http_req_t) is declared
 *       there because the read path constructs it too.
 *
 * HOW:  Pure health-scoring helpers (score/pick/preferred) feed the failover
 *       orchestrator sd_http_request_fo, which is a flat early-return loop of
 *       named steps (select → perform → note-success / note-fail → next). All
 *       logging is at the edges; the scoring math is side-effect-honest.
 */

#include "sd_http_internal.h"    /* endpoint + inst_state + req_t layout */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>

/* Force-primary read policy (process-global operator toggle; set pre-fork from
 * the cvmfs merge when brix_cvmfs_fill_retry_policy is force-primary, so all
 * workers inherit it — the trace/timeouts idiom). When set, a read always
 * targets the RANK-PREFERRED endpoint and NEVER fails over to an alternate on a
 * transport failure: the fill loop retries the SAME preferred origin (RAL) with
 * a fresh connection until it forces through or the client-hold budget expires.
 * Off (default) keeps the phase-68 T11 alternate-endpoint failover. */
int  g_sd_http_force_primary;

void
sd_http_force_primary_set(int on)
{
    g_sd_http_force_primary = on ? 1 : 0;
}

/* Compose the WRITE-target URL path: writes (staged PUT, DELETE) always go
 * to endpoint 0 — failing a write over to another origin would split-brain
 * the store; read failover (sd_http_request_fo) never applies here. */
void
sd_http_write_path(const sd_http_inst_state *is, const char *key, char *dst,
    size_t cap)
{
    snprintf(dst, cap, "%s%s", is->eps[0].base_path,
             (key != NULL && key[0]) ? key : "/");
}

/* Effective pick score: policy rank first, health inside a rank. */
static int
sd_http_ep_score(const sd_http_endpoint *ep)
{
    return atomic_load_explicit((_Atomic int *) &ep->rank,
                                memory_order_relaxed)
         * SD_HTTP_RANK_WEIGHT + ep->fail_score;
}

/* Pick the best endpoint (lowest effective score, order-stable ties). */
static sd_http_endpoint *
sd_http_pick(sd_http_inst_state *is)
{
    sd_http_endpoint *best = &is->eps[0];
    int               i;

    for (i = 1; i < is->n_eps; i++) {
        if (sd_http_ep_score(&is->eps[i]) < sd_http_ep_score(best)) {
            best = &is->eps[i];
        }
    }
    return best;
}

/* Rank-preferred endpoint ignoring health — the half-open probe target. */
static sd_http_endpoint *
sd_http_preferred(sd_http_inst_state *is)
{
    sd_http_endpoint *best = &is->eps[0];
    int               i;

    for (i = 1; i < is->n_eps; i++) {
        if (atomic_load_explicit(&is->eps[i].rank, memory_order_relaxed)
            < atomic_load_explicit(&best->rank, memory_order_relaxed))
        {
            best = &is->eps[i];
        }
    }
    return best;
}

/* Record one transport outcome: score = score*7/8 + (ok ? 0 : 256). */
static void
sd_http_score(sd_http_endpoint *ep, int ok)
{
    ep->fail_score = ep->fail_score * 7 / 8 + (ok ? 0 : 256);
}

/* Score + health-transition note in one step: crossing the 128 hysteresis
 * band emits ONE degraded/recovered event (not one per failure) through the
 * owner-injected hook — the operator's origin-flap trail. */
static void
sd_http_score_noted(sd_http_inst_state *is, sd_http_endpoint *ep, int ok)
{
    int was = ep->fail_score;

    sd_http_score(ep, ok);
    if (is->health_note == NULL) {
        return;
    }
    if (!ok && was < 128 && ep->fail_score >= 128) {
        is->health_note(ep->host, ep->port, 0);
    } else if (ok && was >= 128 && ep->fail_score < 128) {
        is->health_note(ep->host, ep->port, 1);
    }
}

/* Endpoint's rank as currently published by the selection policy. */
static int
sd_http_ep_rank(const sd_http_endpoint *ep)
{
    return atomic_load_explicit((_Atomic int *) &ep->rank,
                                memory_order_relaxed);
}

/* Sanitised copy of a wire-derived request key for log lines (control bytes
 * hex-escaped so a crafted path cannot forge log records). */
static const char *
sd_http_log_key(const char *key, char *buf, size_t cap)
{
    (void) brix_sanitize_log_string((key != NULL && key[0]) ? key : "/",
                                      buf, cap);
    return buf;
}

/* Selection audit: log (NOTICE) every change of the endpoint that answers —
 * the "why is RAL being skipped for CERN" record. States why the policy-
 * preferred endpoint was overridden when it was (health benching). Called
 * from fill threads; cur_ep is racy-by-design (see the field comment). */
static void
sd_http_log_switch(sd_http_inst_state *is, sd_http_endpoint *ep)
{
    int               idx = (int) (ep - is->eps);
    sd_http_endpoint *pref;
    char              prev[300];

    if (idx == is->cur_ep) {
        return;
    }
    if (is->cur_ep >= 0 && is->cur_ep < is->n_eps) {
        snprintf(prev, sizeof(prev), "%s:%d",
                 is->eps[is->cur_ep].host, is->eps[is->cur_ep].port);
    } else {
        snprintf(prev, sizeof(prev), "(none)");
    }
    is->cur_ep = idx;
    if (is->log == NULL) {
        return;
    }
    pref = sd_http_preferred(is);
    if (ep == pref) {
        ngx_log_error(NGX_LOG_NOTICE, is->log, 0,
            "brix: http origin switched to %s:%d (endpoint %d, rank %d, "
            "fail_score %d; the policy-preferred endpoint), was %s",
            ep->host, ep->port, idx, sd_http_ep_rank(ep), ep->fail_score,
            prev);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, is->log, 0,
            "brix: http origin switched to %s:%d (endpoint %d, rank %d, "
            "fail_score %d), was %s; policy-preferred %s:%d SKIPPED "
            "(rank %d, fail_score %d - benched by recent transport failures, "
            "recovers via half-open probing as its score decays)",
            ep->host, ep->port, idx, sd_http_ep_rank(ep), ep->fail_score,
            prev, pref->host, pref->port, sd_http_ep_rank(pref),
            pref->fail_score);
    }
}

/* sd_http_fo_select — choose the endpoint the FIRST attempt targets.
 *
 * WHAT: Returns the starting endpoint: rank-preferred under force-primary,
 *       else best-by-score, with a periodic half-open probe of a benched
 *       preferred origin folded in.
 * WHY:  Force-primary pins the preferred endpoint (nowhere to fail over by
 *       policy); otherwise a benched origin would stay benched forever unless
 *       scores could move, so every 4th request re-tries the preferred one.
 * HOW:  Pick base endpoint by policy; when not force-primary and multiple
 *       endpoints exist, on each 4th tick swap in the rank-preferred endpoint
 *       if it carries any fail_score (a recovered origin earns its score back;
 *       the in-loop failover still answers if it is still down). */
static sd_http_endpoint *
sd_http_fo_select(const sd_http_req_t *rq)
{
    sd_http_inst_state *is = rq->is;
    sd_http_endpoint   *ep = rq->force_primary ? sd_http_preferred(is)
                                               : sd_http_pick(is);
    char                klog[160];

    if (rq->force_primary || is->n_eps <= 1 || (++is->probe_tick & 3u) != 0) {
        return ep;
    }
    sd_http_endpoint *pref = sd_http_preferred(is);

    if (pref->fail_score <= 0) {
        return ep;
    }
    if (pref != ep && is->log != NULL) {
        ngx_log_error(NGX_LOG_INFO, is->log, 0,
            "brix: http origin half-open probe: re-trying benched "
            "preferred %s:%d (rank %d, fail_score %d) instead of "
            "%s:%d for %s \"%s\"",
            pref->host, pref->port, sd_http_ep_rank(pref),
            pref->fail_score, ep->host, ep->port, rq->method,
            sd_http_log_key(rq->key, klog, sizeof(klog)));
    }
    return pref;
}

/* sd_http_fo_perform — issue ONE request to `ep`, score the outcome.
 *
 * WHAT: Composes the URL, dispatches through the cred or plain transport slot,
 *       records the transport outcome against the endpoint's health score, and
 *       returns the transport rc (0 = ok). *errbuf carries the curl detail.
 * WHY:  GSI-over-https routes a per-open proxy PEM through request_cred as the
 *       mutual-TLS client cert; the common anonymous/bearer path uses the plain
 *       slot. A cert with no request_cred slot means allow-mode (open already
 *       refused deny-mode) — degrade to the plain request.
 * HOW:  snprintf the endpoint base_path + key, then request_cred vs request by
 *       cert presence and slot availability, then sd_http_score_noted. */
static int
sd_http_fo_perform(const sd_http_req_t *rq, sd_http_endpoint *ep,
    char *errbuf, size_t errcap)
{
    sd_http_inst_state *is = rq->is;
    char                full[SD_HTTP_PATH_MAX];
    int                 rc;

    snprintf(full, sizeof(full), "%s%s", ep->base_path,
             (rq->key != NULL && rq->key[0]) ? rq->key : "/");
    errbuf[0] = '\0';
    if (rq->cert_pem != NULL && rq->cert_pem[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        rc = is->transport->request_cred(is->tctx, ep->host, ep->port,
                                ep->tls, rq->method, full, rq->extra_hdrs,
                                NULL, 0, is->timeout_ms, rq->cert_pem,
                                rq->resp, errbuf, errcap);
    } else {
        rc = is->transport->request(is->tctx, ep->host, ep->port, ep->tls,
                                rq->method, full, rq->extra_hdrs, NULL, 0,
                                is->timeout_ms, rq->resp, errbuf, errcap);
    }
    sd_http_score_noted(is, ep, rc == 0);
    return rc;
}

/* sd_http_fo_note_success — record the answering endpoint on a served request.
 *
 * WHAT: Stashes last_origin, the per-upstream failover flag, and emits the
 *       selection-change audit line. *used (when non-NULL) names the endpoint.
 * WHY:  The metric "failover" = served by a NON-PRIMARY endpoint; keyed on
 *       eps[0] (not `first`) so it holds however scoring reordered the picks
 *       and across the HEAD-then-GET sub-requests of one fill. */
static void
sd_http_fo_note_success(const sd_http_req_t *rq, sd_http_endpoint *ep,
    sd_http_endpoint **used)
{
    sd_http_inst_state *is = rq->is;

    if (used != NULL) {
        *used = ep;
    }
    snprintf(is->last_origin, sizeof(is->last_origin), "%s:%d",
             ep->host, ep->port);
    is->last_failover = (ep != &is->eps[0]);
    sd_http_log_switch(is, ep);
}

/* sd_http_fo_next — pick the alternate endpoint for a failover attempt.
 *
 * WHAT: Returns the best-by-score endpoint distinct from `first`, or NULL when
 *       there is none. On a hit, fires the failover-accounting hook and the
 *       NOTICE audit line.
 * WHY:  A transport failure on the first pick earns ONE alternate attempt
 *       (phase-68 T11); the alternate must not be the endpoint that just failed.
 * HOW:  Linear best-score scan skipping `first`; failover_note + log on success. */
static sd_http_endpoint *
sd_http_fo_next(const sd_http_req_t *rq, sd_http_endpoint *first)
{
    sd_http_inst_state *is = rq->is;
    sd_http_endpoint   *ep = NULL;
    char                klog[160];
    int                 i;

    for (i = 0; i < is->n_eps; i++) {
        if (&is->eps[i] == first) {
            continue;
        }
        if (ep == NULL
            || sd_http_ep_score(&is->eps[i]) < sd_http_ep_score(ep))
        {
            ep = &is->eps[i];
        }
    }
    if (ep == NULL) {
        return NULL;
    }
    if (is->failover_note != NULL) {
        is->failover_note();                   /* T16: failover accounting */
    }
    if (is->log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, is->log, 0,
            "brix: http origin failover for %s \"%s\": %s:%d -> %s:%d "
            "(alternate rank %d, fail_score %d)",
            rq->method, sd_http_log_key(rq->key, klog, sizeof(klog)),
            first->host, first->port, ep->host, ep->port,
            sd_http_ep_rank(ep), ep->fail_score);
    }
    return ep;
}

/* sd_http_fo_note_fail — WARN the per-endpoint transport failure with detail. */
static void
sd_http_fo_note_fail(const sd_http_req_t *rq, sd_http_endpoint *ep,
    const char *errbuf, int attempt, int score_before)
{
    if (rq->is->log == NULL) {
        return;
    }
    char klog[160];

    ngx_log_error(NGX_LOG_WARN, rq->is->log, 0,
        "brix: http origin %s:%d failed %s \"%s\": %s "
        "(attempt %d/2, rank %d, fail_score %d -> %d)",
        ep->host, ep->port, rq->method,
        sd_http_log_key(rq->key, klog, sizeof(klog)),
        errbuf[0] ? errbuf : "transport error",
        attempt + 1, sd_http_ep_rank(ep), score_before, ep->fail_score);
}

/* One request with read-failover (phase-68 T11): try the best endpoint, then
 * ONE alternate on a TRANSPORT failure (an HTTP 4xx is NOT a transport
 * failure — the object genuinely isn't there; do not mask it by failing
 * over). The request identity (method/key/extra_hdrs/cert_pem/resp) rides in
 * the caller-populated `rq`; `rq->extra_hdrs` is the pre-joined header block
 * (Range and/or auth); `rq->cert_pem`, when non-NULL/non-empty, is a per-open
 * TLS client-cert PATH (a user proxy PEM) presented via mutual-TLS through the
 * transport's request_cred slot — the GSI-over-https backend leg (phase-70
 * §5.1); NULL keeps the plain request slot (anonymous / header-borne auth).
 * On success *used (when non-NULL) names the endpoint that answered. */
int
sd_http_request_fo(const sd_http_req_t *rq, sd_http_endpoint **used)
{
    sd_http_inst_state *is = rq->is;
    sd_http_endpoint   *ep = sd_http_fo_select(rq);
    sd_http_endpoint   *first = ep;
    char                errbuf[256], klog[160];
    int                 attempt, rc, score_before;

    for (attempt = 0; attempt < 2; attempt++) {
        score_before = ep->fail_score;
        rc = sd_http_fo_perform(rq, ep, errbuf, sizeof(errbuf));
        if (rc == 0) {
            sd_http_fo_note_success(rq, ep, used);
            return 0;
        }
        /* The transport failure is the evidence an operator needs to explain
         * a later "origin switched" line — record it with the curl detail. */
        sd_http_fo_note_fail(rq, ep, errbuf, attempt, score_before);
        if (is->n_eps < 2 || rq->force_primary) {
            break;                    /* force-primary: never fail over */
        }
        ep = sd_http_fo_next(rq, first);
        if (ep == NULL) {
            break;
        }
    }
    if (is->log != NULL) {
        ngx_log_error(NGX_LOG_ERR, is->log, 0,
            "brix: http origin request exhausted all endpoints (%d tried) "
            "for %s \"%s\" - reporting EIO to the fill layer",
            (is->n_eps < 2) ? 1 : 2, rq->method,
            sd_http_log_key(rq->key, klog, sizeof(klog)));
    }
    errno = EIO;
    return -1;
}
