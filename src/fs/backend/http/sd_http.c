/*
 * sd_http.c — read-only HTTP(S) source storage driver (phase-63 C-4). See header.
 *
 * A thin driver over the injected brix_s3_transport_t (the same vtable the S3
 * driver uses): `open`/`stat` HEAD the URL for the size, `pread` issues a byte
 * Range GET. No SigV4, no auth — plain anonymous HTTP. No kernel fd ⇒ memory-served.
 */

#include "sd_http.h"
#include "sd_http_internal.h"    /* endpoint + inst_state layout (split out) */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SD_HTTP_PREAD_MAX  (8LL * 1024 * 1024)

/* Force-primary read policy (process-global operator toggle; set pre-fork from
 * the cvmfs merge when brix_cvmfs_fill_retry_policy is force-primary, so all
 * workers inherit it — the trace/timeouts idiom). When set, a read always
 * targets the RANK-PREFERRED endpoint and NEVER fails over to an alternate on a
 * transport failure: the fill loop retries the SAME preferred origin (RAL) with
 * a fresh connection until it forces through or the client-hold budget expires.
 * Off (default) keeps the phase-68 T11 alternate-endpoint failover. */
static int  g_sd_http_force_primary;

void
sd_http_force_primary_set(int on)
{
    g_sd_http_force_primary = on ? 1 : 0;
}


typedef struct {
    char key[SD_HTTP_PATH_MAX];    /* export-relative key (leading '/'); the
                                      full URL path is composed per endpoint */
    char auth_hdr[SD_HTTP_AUTH_MAX]; /* per-open "Authorization: Bearer <tok>\r\n"
                                      (Phase 2 T7); "" when the object should
                                      fall back to the instance's static
                                      is->auth_hdr (plain open, or a cred with
                                      no usable bearer). A COPY of the bearer
                                      bytes — cred->bearer is only borrowed for
                                      the duration of the open() call. */
    char cert_pem[SD_HTTP_PATH_MAX]; /* per-open TLS client-cert PATH (phase-70
                                      §5.1 GSI-over-https): the user's proxy PEM
                                      (chain+key) presented via mutual-TLS on
                                      each read. "" when the open carries no
                                      x509 cred. A COPY of cred->x509_proxy,
                                      which is only borrowed for the open call. */
} sd_http_obj_state;

/* Per-staged-write state: HTTP has no streaming PUT through this transport, so the
 * object is buffered and PUT whole at commit (a remote stage/cache store of typical
 * file sizes; very large objects are a multipart follow-up).
 *
 * auth_hdr / cert_pem carry the per-open (per-user) credential captured at
 * staged_open_cred so the commit PUT authenticates to the origin AS the requesting
 * user rather than the static service credential (phase-70 §5.1, write leg). Both
 * are COPIES — the cred fields are borrowed only for the staged_open() call. "" in
 * either falls back to the instance static (is->auth_hdr) / no client cert. Exactly
 * one kind is ever set (the VFS gate populates one of bearer / x509_proxy). */
typedef struct {
    char     path[SD_HTTP_PATH_MAX];
    u_char  *buf;
    size_t   len;
    size_t   cap;
    char     auth_hdr[SD_HTTP_AUTH_MAX];
    char     cert_pem[SD_HTTP_PATH_MAX];
} sd_http_staged_state;

/* Compose the WRITE-target URL path: writes (staged PUT, DELETE) always go
 * to endpoint 0 — failing a write over to another origin would split-brain
 * the store; read failover (sd_http_request_fo) never applies here. */
static void
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

/* Per-request state threaded through the failover helpers so each stays under
 * the parameter cap and reads as one nameable step. Carries the immutable
 * request identity (method/key/headers/cert) plus the resp out-slot; the
 * mutable selection state (current/first endpoint) rides in locals. */
typedef struct {
    sd_http_inst_state *is;
    const char         *method;
    const char         *key;
    const char         *extra_hdrs;
    const char         *cert_pem;
    brix_s3_resp_t     *resp;
    int                 force_primary;
} sd_http_req_t;

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
static int
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

/* HEAD `key` → *size_out (−1 if no Content-Length). 0, or −1 with errno.
 * `auth_hdr`/`cert_pem` carry the per-open credential (bearer header and/or
 * GSI proxy client-cert path) so the size probe authenticates as the same
 * identity the following reads use; NULL/"" fall back to the instance static. */
static int
sd_http_head_size(sd_http_inst_state *is, const char *key,
    const char *auth_hdr, const char *cert_pem, int64_t *size_out)
{
    brix_s3_resp_t resp;
    char             cl[32];
    sd_http_req_t    rq = { is, "HEAD", key, auth_hdr, cert_pem, &resp,
                            g_sd_http_force_primary };

    if (sd_http_request_fo(&rq, NULL) != 0)
    {
        return -1;                              /* errno = EIO */
    }
    if (resp.status == 404) {
        is->transport->resp_free(&resp);
        errno = ENOENT;
        return -1;
    }
    if (resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        return -1;
    }
    if (is->transport->resp_header(&resp, "Content-Length", cl, sizeof(cl)) == 0) {
        *size_out = (int64_t) strtoll(cl, NULL, 10);
    } else {
        *size_out = -1;
    }
    is->transport->resp_free(&resp);
    return 0;
}

/* sd_http_cred_gate — decide whether a proxy-only x509 credential is presentable
 * to this HTTP origin, and refuse in deny mode when it is not.
 *
 * WHAT: An x509-proxy cred over an https backend leg is presented as a mutual-TLS
 *       client cert (phase-70 §5.1) — but ONLY if the injected transport can do
 *       so (it implements request_cred). Returns 0 when the open may proceed,
 *       -1 (errno=EACCES) when a deny-mode proxy cred cannot be presented.
 * WHY:  fallback_deny forbids silently serving a per-user request on the
 *       anonymous/service credential. If the user presented ONLY an x509 proxy
 *       (no bearer) and the transport cannot mutual-TLS, presenting it is
 *       impossible; deny rather than leak onto anonymous access.
 * HOW:  Only fires for a cred whose sole credential is x509_proxy (no bearer).
 *       When the transport lacks request_cred and deny is set → EACCES. A usable
 *       transport, a bearer-carrying cred, or allow-mode all return 0 (proceed;
 *       the open then wires whatever it can). */
static int
sd_http_cred_gate(sd_http_inst_state *is, const brix_sd_cred_t *cred)
{
    int has_bearer;
    int has_proxy;

    if (cred == NULL) {
        return 0;
    }
    has_bearer = (cred->bearer != NULL && cred->bearer[0] != '\0');
    has_proxy  = (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0');
    if (has_bearer || !has_proxy) {
        return 0;                       /* bearer path, or no per-user cred    */
    }
    if (is->transport->request_cred == NULL && cred->fallback_deny) {
        errno = EACCES;                 /* proxy-only + can't mutual-TLS + deny */
        return -1;
    }
    return 0;
}

/* sd_http_resolve_open_cred — resolve a `cred` into the per-open bearer header
 * and x509 client-cert path used for both the HEAD probe and later reads.
 *
 * WHAT: Writes the "Authorization: Bearer <tok>\r\n" line into `open_auth`
 *       (empty when no usable bearer) and returns the x509 proxy PATH (NULL
 *       when none / the transport cannot present a client cert).
 * WHY:  The size probe and the object's reads must present the SAME identity;
 *       resolving once here keeps them consistent for an origin that authorizes
 *       per-object. cred==NULL leaves auth empty → fall back to the static.
 * HOW:  Bearer → snprintf into open_auth; x509 proxy → return cred->x509_proxy
 *       only when request_cred is available (both are borrowed, copied later). */
static const char *
sd_http_resolve_open_cred(sd_http_inst_state *is, const brix_sd_cred_t *cred,
    char *open_auth, size_t auth_cap)
{
    open_auth[0] = '\0';
    if (cred == NULL) {
        return NULL;
    }
    if (cred->bearer != NULL && cred->bearer[0] != '\0') {
        snprintf(open_auth, auth_cap, "Authorization: Bearer %s\r\n",
                 cred->bearer);
    }
    if (cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        return cred->x509_proxy;
    }
    return NULL;
}

/* Resolved per-open result threaded into sd_http_build_obj: the credential the
 * object copies into its own buffers plus the size the HEAD probe returned. */
typedef struct {
    const char *open_auth;   /* bearer header line ("" = none) */
    const char *open_cert;   /* x509 client-cert PATH (NULL = none) */
    int64_t     size;        /* HEAD Content-Length (−1 if unknown) */
} sd_http_open_result_t;

/* sd_http_build_obj — allocate + populate the memory-served object shell.
 *
 * WHAT: Allocates the per-open object state and shell, copies the key and the
 *       resolved per-open credential (bearer header / cert path) into the
 *       object's own buffers, and fills the stat snapshot. NULL + *err_out on
 *       allocation failure.
 * HOW:  calloc both, COPY key/open_auth/open_cert into st (cred fields were only
 *       borrowed), wire the read-only regular-file snapshot. No kernel fd. */
static brix_sd_obj_t *
sd_http_build_obj(brix_sd_instance_t *inst, const char *path,
    const sd_http_open_result_t *res, int *err_out)
{
    sd_http_obj_state *st  = calloc(1, sizeof(*st));
    brix_sd_obj_t     *obj = calloc(1, sizeof(*obj));

    if (st == NULL || obj == NULL) {
        free(st);
        free(obj);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    snprintf(st->key, sizeof(st->key), "%s",
             (path != NULL && path[0]) ? path : "/");
    if (res->open_auth[0] != '\0') {
        snprintf(st->auth_hdr, sizeof(st->auth_hdr), "%s", res->open_auth);
    }
    if (res->open_cert != NULL) {
        snprintf(st->cert_pem, sizeof(st->cert_pem), "%s", res->open_cert);
    }

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state      = st;
    obj->heap_shell = 1;
    obj->snap.size  = (off_t) res->size;
    obj->snap.mode  = S_IFREG | 0444;
    obj->snap.is_reg = 1;
    return obj;
}

/* The open-request quartet the vtable slots hand to the shared open path,
 * bundled so the common helper stays under the parameter cap. `cred` is NULL
 * for the plain (service/anonymous) slot, non-NULL for the per-user slot. */
typedef struct {
    const char             *path;
    int                     sd_flags;
    mode_t                  mode;
    const brix_sd_cred_t   *cred;
} sd_http_open_req_t;

/* sd_http_open_common — shared open path for the plain and credential-scoped
 * open slots.
 *
 * WHAT: HEADs `req->path` for its size and builds the per-open object. A `cred`
 *       with a usable bearer token sets the object's auth_hdr; a `cred` with an
 *       x509 proxy (a PEM chain+key path) sets the object's cert_pem so
 *       subsequent reads present that identity — the bearer via an Authorization
 *       header, the proxy via a mutual-TLS client cert on the origin handshake.
 * WHY:  Phase 2 T7 (bearer) + phase-70 §5.1 (x509) per-user backend credentials
 *       — an HTTP-origin driver has no kernel fd / session to re-scope per user,
 *       so the per-user identity travels as per-object state copied at open time.
 * HOW:  Refuse write intent; gate the cred; resolve it once (helper); HEAD the
 *       size with the SAME identity; then build the object (helper). Exactly one
 *       cred kind is ever set (the VFS gate populates one of bearer/x509_proxy). */
static brix_sd_obj_t *
sd_http_open_common(brix_sd_instance_t *inst, const sd_http_open_req_t *req,
    int *err_out)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert;

    (void) req->mode;

    /* Read-only source: refuse any write/create/trunc intent. */
    if (req->sd_flags & (BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC
                    | BRIX_SD_O_APPEND))
    {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    if (sd_http_cred_gate(is, req->cred) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    open_cert = sd_http_resolve_open_cred(is, req->cred, open_auth,
                                          sizeof(open_auth));

    if (sd_http_head_size(is, req->path,
                          open_auth[0] ? open_auth
                                       : (is->auth_hdr[0] ? is->auth_hdr : NULL),
                          open_cert, &size) != 0)
    {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    sd_http_open_result_t res = { open_auth, open_cert, size };
    return sd_http_build_obj(inst, req->path, &res, err_out);
}

/* sd_http_open — vtable open slot: service credential / anonymous.
 *
 * WHAT: Plain open for callers that do not carry a per-user credential.
 * WHY:  Preserves the existing public vtable signature; passes cred=NULL so
 *       the object falls back to the instance's static bearer_token header.
 * HOW:  Delegates to sd_http_open_common with cred=NULL. */
static brix_sd_obj_t *
sd_http_open(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_http_open_req_t req = { path, sd_flags, mode, NULL };

    return sd_http_open_common(inst, &req, err_out);
}

/* sd_http_open_cred — vtable open_cred slot: per-user bearer-token credential.
 *
 * WHAT: Credential-scoped open that presents the requesting user's WLCG
 *       bearer token to the origin instead of the static service token.
 * WHY:  Phase 2 T7 — an HTTP/WebDAV/cvmfs origin authenticates purely on the
 *       Authorization header, so per-user auth is a per-open header swap.
 * HOW:  Delegates to sd_http_open_common with the supplied cred; the common
 *       path copies cred->bearer into the object's own auth_hdr buffer. */
static brix_sd_obj_t *
sd_http_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_open_req_t req = { path, sd_flags, mode, cred };

    return sd_http_open_common(inst, &req, err_out);
}

static ngx_int_t
sd_http_close(brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        free(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

static ssize_t
sd_http_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_http_inst_state *is = obj->inst->state;
    sd_http_obj_state  *st = obj->state;
    brix_s3_resp_t    resp;
    char                hdrs[SD_HTTP_AUTH_MAX + 80];
    const void         *body;
    const char         *auth_hdr;
    size_t              blen = 0, n;
    int64_t             end;

    if (len == 0) {
        return 0;
    }
    if (len > (size_t) SD_HTTP_PREAD_MAX) {
        len = (size_t) SD_HTTP_PREAD_MAX;
    }
    end = (int64_t) off + (int64_t) len - 1;
    /* Phase 2 T7: a per-open bearer (open_cred) wins over the instance's
     * static bearer_token; "" (plain open, or no usable cred) falls back.
     * Phase-70 §5.1: a per-open x509 proxy path (st->cert_pem) is presented as
     * the mutual-TLS client cert on the read — orthogonal to the bearer header
     * (the VFS gate sets exactly one of the two). */
    auth_hdr = st->auth_hdr[0] ? st->auth_hdr : is->auth_hdr;
    snprintf(hdrs, sizeof(hdrs), "Range: bytes=%lld-%lld\r\n%s",
             (long long) off, (long long) end, auth_hdr);

    sd_http_req_t rq = { is, "GET", st->key, hdrs,
                         st->cert_pem[0] ? st->cert_pem : NULL, &resp,
                         g_sd_http_force_primary };
    if (sd_http_request_fo(&rq, NULL) != 0) {
        return -1;                              /* errno = EIO */
    }
    if (resp.status == 416) {
        is->transport->resp_free(&resp);
        return 0;                              /* range past EOF → EOF (0) */
    }
    if (resp.status != 206 && resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 404) ? ENOENT : EIO;
        return -1;
    }
    body = is->transport->resp_body(&resp, &blen);
    if (body == NULL || blen == 0) {
        is->transport->resp_free(&resp);
        return 0;                              /* EOF / empty range */
    }

    /* 206 → body is exactly the requested range, starting at `off`. 200 → the
     * origin ignored the Range header and returned the WHOLE object from byte 0
     * (stock python http.server, some proxies), so the bytes we want begin at
     * `off` within `body`; past EOF that is a short read of 0. Slicing here keeps
     * a correct, terminating fill loop against either kind of origin. */
    if (resp.status == 200) {
        if ((size_t) off >= blen) {
            is->transport->resp_free(&resp);
            return 0;                          /* requested range past EOF */
        }
        body  = (const char *) body + off;
        blen -= (size_t) off;
    }
    n = (blen < len) ? blen : len;
    memcpy(buf, body, n);
    is->transport->resp_free(&resp);
    return (ssize_t) n;
}

static ngx_int_t
sd_http_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

/* sd_http_stat_fill — fill a brix_sd_stat_t from a HEAD-probed size.
 *
 * WHAT: Zero `out` then stamp the regular-file snapshot the size probe produced.
 * WHY:  The plain and credential-scoped stat slots derive an identical stat
 *       snapshot from the HEAD Content-Length; factoring it keeps the two slots
 *       from drifting on the mode/is_reg fields.
 * HOW:  ngx_memzero + size/mode/is_reg — the http origin exposes only read-only
 *       regular files (0444), same shape the object snapshot uses. */
static void
sd_http_stat_fill(brix_sd_stat_t *out, int64_t size)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
}

static ngx_int_t
sd_http_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;

    /* Plain namespace stat runs on the instance's static credential — the
     * anonymous/service path used when no per-user credential is threaded. */
    if (sd_http_head_size(is, path, is->auth_hdr[0] ? is->auth_hdr : NULL,
                          NULL, &size) != 0) {
        return NGX_ERROR;                       /* errno set by head_size */
    }
    sd_http_stat_fill(out, size);
    return NGX_OK;
}

/* sd_http_stat_cred — vtable stat_cred slot: per-user credential-scoped stat.
 *
 * WHAT: Namespace stat (a HEAD size probe) that presents the requesting user's
 *       credential — a WLCG bearer as the Authorization header, or an x509 proxy
 *       as the mutual-TLS client cert — to the origin instead of the static
 *       service credential.
 * WHY:  Phase-70 §5.1 — an https backend leg authorizes EVERY request on the
 *       presented credential, so a namespace stat issued under a per-user policy
 *       (e.g. the root:// write pre-flight existence check, or a WebDAV lock-state
 *       probe on a remote origin) must carry the same forwarded identity the
 *       open/staged-open legs use. Without this slot the stat dispatched through
 *       the plain .stat and hit the auth-required origin ANONYMOUSLY, which the
 *       backend rejected — aborting the whole two-hop PUT even though the user's
 *       credential was fully resolved. sd_http has no kernel fd / session to
 *       re-scope, so — exactly like sd_http_open_cred — the credential is applied
 *       per request via the HEAD headers + client cert.
 * HOW:  Runs sd_http_cred_gate (deny a proxy-only cred the transport cannot
 *       mutual-TLS present), resolves the cred into a bearer header line + x509
 *       cert path with sd_http_resolve_open_cred (the SAME resolver the read open
 *       uses, so stat and open present one identity), then HEAD-probes with those
 *       — falling back to the instance static header only when the cred yields no
 *       bearer. cred==NULL degrades to the plain-stat behaviour. */
static ngx_int_t
sd_http_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;
    char                open_auth[SD_HTTP_AUTH_MAX];
    const char         *open_cert;

    if (sd_http_cred_gate(is, cred) != 0) {
        return NGX_ERROR;                       /* errno = EACCES (set by gate) */
    }

    open_cert = sd_http_resolve_open_cred(is, cred, open_auth,
                                          sizeof(open_auth));

    if (sd_http_head_size(is, path,
                          open_auth[0] ? open_auth
                                       : (is->auth_hdr[0] ? is->auth_hdr : NULL),
                          open_cert, &size) != 0) {
        return NGX_ERROR;                       /* errno set by head_size */
    }
    sd_http_stat_fill(out, size);
    return NGX_OK;
}

/* ---- write path (SP3): the HTTP origin as a writable cache / stage store. A
 * staged write buffers the object and PUTs it whole at commit (atomic from the
 * reader's view); unlink is a DELETE (eviction + post-flush stage cleanup). */

/* sd_http_staged_open_common — shared staged-open path for the plain and
 * credential-scoped staged-open slots.
 *
 * WHAT: Allocates the staged buffer state, composes the write-target URL path
 *       and, when a `cred` is present, captures the per-user credential (bearer →
 *       Authorization header; x509 proxy → mutual-TLS client-cert PATH) into the
 *       staged state so the commit PUT presents THAT identity, not the static
 *       service credential.
 * WHY:  Phase-70 §5.1 write leg — an HTTP/WebDAV origin authenticates a PUT purely
 *       on the request credential, and this driver has no kernel fd / session to
 *       re-scope per user, so the per-user identity travels as staged state copied
 *       at open time (mirroring the read-leg sd_http_open_common exactly).
 * HOW:  cred==NULL (plain .staged_open) leaves auth_hdr AND cert_pem empty, so the
 *       commit falls back to the instance static header and no client cert. The
 *       same cred_gate the read path uses refuses a proxy-only cred in deny mode
 *       when the transport cannot mutual-TLS (request_cred==NULL) → EACCES. A
 *       bearer is snprintf'd into the staged auth_hdr; an x509 proxy path is copied
 *       into cert_pem only when the transport can present it (request_cred!=NULL).
 *       Both are COPIES — cred fields are borrowed only for this call. */
static brix_sd_staged_t *
sd_http_staged_open_common(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_http_inst_state   *is = inst->state;
    sd_http_staged_state *ss;
    brix_sd_staged_t   *h;

    (void) mode;

    /* Same credential gate the read leg applies: a proxy-only cred that cannot be
     * presented as a client cert must be refused in deny mode rather than served
     * on the anonymous/service credential. */
    if (sd_http_cred_gate(is, cred) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    sd_http_write_path(is, final_path, ss->path, sizeof(ss->path));

    /* Capture the per-open credential for the commit PUT: bearer → header;
     * x509 proxy → cert path (only when the transport can present it). Empty
     * leaves the commit on the instance static / anonymous credential. */
    if (cred != NULL && cred->bearer != NULL && cred->bearer[0] != '\0') {
        snprintf(ss->auth_hdr, sizeof(ss->auth_hdr),
                 "Authorization: Bearer %s\r\n", cred->bearer);
    }
    if (cred != NULL && cred->x509_proxy != NULL && cred->x509_proxy[0] != '\0'
        && is->transport->request_cred != NULL)
    {
        snprintf(ss->cert_pem, sizeof(ss->cert_pem), "%s", cred->x509_proxy);
    }

    h->inst  = inst;
    h->state = ss;
    return h;
}

/* sd_http_staged_open — vtable staged_open slot: service credential / anonymous. */
static brix_sd_staged_t *
sd_http_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, NULL, err_out);
}

/* sd_http_staged_open_cred — vtable staged_open_cred slot: per-user credential.
 *
 * WHAT: Credential-scoped staged open that binds the requesting user's bearer
 *       token or x509 proxy to the staged object so the commit PUT authenticates
 *       to the origin AS that user (phase-70 §5.1 write leg — the two-hop PUT over
 *       an https backend leg).
 * WHY:  Without this slot the write/commit leg always PUT with the static service
 *       credential, so per-user forwarding failed for two-hop PUT over an https
 *       backend leg (the "C HH/RH gsi/token" cells in run_fwd_brix_brix.sh).
 * HOW:  Delegates to sd_http_staged_open_common with the supplied cred. */
static brix_sd_staged_t *
sd_http_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    return sd_http_staged_open_common(inst, final_path, mode, cred, err_out);
}

static ssize_t
sd_http_staged_write(brix_sd_staged_t *h, const void *buf, size_t len,
    off_t off)
{
    sd_http_staged_state *ss = h->state;

    /* Sequential append only (whole-object PUT has no random write). */
    if ((size_t) off != ss->len) {
        errno = ESPIPE;
        return -1;
    }
    if (ss->len + len > ss->cap) {
        size_t  ncap = ss->cap ? ss->cap * 2 : (1u << 20);
        u_char *nbuf;

        while (ncap < ss->len + len) {
            ncap *= 2;
        }
        nbuf = realloc(ss->buf, ncap);
        if (nbuf == NULL) {
            errno = ENOMEM;
            return -1;
        }
        ss->buf = nbuf;
        ss->cap = ncap;
    }
    ngx_memcpy(ss->buf + ss->len, buf, len);
    ss->len += len;
    return (ssize_t) len;
}

static ngx_int_t
sd_http_staged_commit(brix_sd_staged_t *h, int noreplace)
{
    sd_http_staged_state *ss = h->state;
    sd_http_inst_state   *is = h->inst->state;
    brix_s3_resp_t      resp;
    char                  errbuf[256];
    const char           *auth_hdr;
    int                   rq;
    ngx_int_t             rc = NGX_OK;

    (void) noreplace;                          /* HTTP PUT always replaces */

    /* Per-user commit: a per-open bearer (staged_open_cred) wins over the
     * instance's static bearer_token; "" (plain staged_open, or no usable cred)
     * falls back. A per-open x509 proxy path (ss->cert_pem) is presented as the
     * mutual-TLS client cert on the PUT via the transport's request_cred slot —
     * exactly mirroring the read leg (sd_http_request_fo / sd_http_pread). The
     * cred gate at staged_open already refused a proxy-only cred that cannot be
     * presented in deny mode, so reaching here with a cert path guarantees a
     * request_cred-capable transport. */
    auth_hdr = ss->auth_hdr[0] ? ss->auth_hdr
                               : (is->auth_hdr[0] ? is->auth_hdr : NULL);
    if (ss->cert_pem[0] != '\0' && is->transport->request_cred != NULL) {
        rq = is->transport->request_cred(is->tctx, is->eps[0].host,
                               is->eps[0].port, is->eps[0].tls, "PUT",
                               ss->path, auth_hdr, ss->buf, ss->len,
                               is->timeout_ms, ss->cert_pem, &resp,
                               errbuf, sizeof(errbuf));
    } else {
        rq = is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "PUT",
                               ss->path, auth_hdr,
                               ss->buf, ss->len, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf));
    }
    if (rq != 0) {
        free(ss->buf);
        free(ss);
        free(h);
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 200 && resp.status != 201 && resp.status != 204) {
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        rc = NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    free(ss->buf);
    free(ss);
    free(h);
    return rc;
}

static void
sd_http_staged_abort(brix_sd_staged_t *h)
{
    sd_http_staged_state *ss = h->state;

    free(ss->buf);
    free(ss);
    free(h);
}

static ngx_int_t
sd_http_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_http_inst_state *is = inst->state;
    brix_s3_resp_t    resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];

    (void) is_dir;
    sd_http_write_path(is, path, full, sizeof(full));
    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "DELETE",
                               full, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               NULL, 0, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    /* Idempotent: 204/200 ok, 404 already gone. */
    if (resp.status != 204 && resp.status != 200 && resp.status != 404) {
        is->transport->resp_free(&resp);
        errno = EIO;
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}

/* Read + write: an HTTP/WebDAV origin as a read source and a writable cache_store /
 * stage_store (buffered whole-object PUT + DELETE). */
static const brix_sd_driver_t brix_sd_http_driver = {
    .name  = "http",
    /* phase-71: read-only primary — no .pwrite slot (writes are staged whole-object
     * PUTs via .staged_*), so CAP_RANDOM_WRITE is NOT advertised (honest caps). */
    .caps  = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE,
    .cred_accept = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM,
    .open  = sd_http_open,
    .open_cred = sd_http_open_cred,
    .close = sd_http_close,
    .pread = sd_http_pread,
    .fstat = sd_http_fstat,
    .stat  = sd_http_stat,
    .stat_cred     = sd_http_stat_cred,
    .unlink        = sd_http_unlink,
    .staged_open   = sd_http_staged_open,
    .staged_open_cred = sd_http_staged_open_cred,
    .staged_write  = sd_http_staged_write,
    .staged_commit = sd_http_staged_commit,
    .staged_abort  = sd_http_staged_abort,
};

/* 1 iff `inst` is an sd_http instance.  Kept beside the (file-private) driver
 * struct it checks; the introspection accessors (sd_http_introspect.c) reach it
 * via sd_http_internal.h. */
int
sd_http_instance_is(const brix_sd_instance_t *inst)
{
    return inst != NULL && inst->driver == &brix_sd_http_driver;
}


/* sd_http_init_endpoints — fill the endpoint table from the primary host plus
 * any extra failover origins.
 *
 * WHAT: Writes eps[0] from cfg->{host,port,tls,base_path}, then appends up to
 *       SD_HTTP_EP_MAX-1 valid extras, setting is->n_eps.
 * HOW:  Primary is always present (create() validated it); each extra is
 *       skipped when its host/port is missing or out of range. */
static void
sd_http_init_endpoints(sd_http_inst_state *is, const brix_sd_http_cfg_t *cfg)
{
    snprintf(is->eps[0].host, sizeof(is->eps[0].host), "%s", cfg->host);
    is->eps[0].port = cfg->port;
    is->eps[0].tls  = cfg->tls;
    snprintf(is->eps[0].base_path, sizeof(is->eps[0].base_path), "%s",
             (cfg->base_path != NULL) ? cfg->base_path : "");
    is->n_eps = 1;

    if (cfg->extra == NULL || cfg->n_extra <= 0) {
        return;
    }
    int i, n = cfg->n_extra;

    if (n > SD_HTTP_EP_MAX - 1) {
        n = SD_HTTP_EP_MAX - 1;
    }
    for (i = 0; i < n; i++) {
        const brix_sd_http_ep_cfg_t *ec = &cfg->extra[i];

        if (ec->host == NULL || ec->host[0] == '\0' || ec->port <= 0
            || ec->port > 65535)
        {
            continue;
        }
        snprintf(is->eps[is->n_eps].host, sizeof(is->eps[0].host), "%s",
                 ec->host);
        is->eps[is->n_eps].port = ec->port;
        is->eps[is->n_eps].tls  = ec->tls;
        snprintf(is->eps[is->n_eps].base_path,
                 sizeof(is->eps[0].base_path), "%s",
                 (ec->base_path != NULL) ? ec->base_path : "");
        is->n_eps++;
    }
}

/* sd_http_init_tctx — resolve the transport TLS context (trust anchor).
 *
 * WHAT: An explicit cfg->tctx wins (a caller injecting a custom transport owns
 *       its own context). Otherwise, when an operator CA path is configured,
 *       store a persistent copy and hand it to the curl transport as tctx so
 *       origin TLS verifies against that trust anchor (phase-70 https backend
 *       leg). No CA and no tctx ⇒ NULL ⇒ the transport's system bundle. */
static void
sd_http_init_tctx(sd_http_inst_state *is, const brix_sd_http_cfg_t *cfg)
{
    if (cfg->tctx != NULL) {
        is->tctx = cfg->tctx;
    } else if (cfg->ca_path != NULL && cfg->ca_path[0] != '\0') {
        snprintf(is->ca_path, sizeof(is->ca_path), "%s", cfg->ca_path);
        is->tctx = is->ca_path;
    } else {
        is->tctx = NULL;
    }
}

brix_sd_instance_t *
brix_sd_http_create(const brix_sd_http_cfg_t *cfg, ngx_log_t *log)
{
    brix_sd_instance_t *inst;
    sd_http_inst_state   *is;

    if (cfg == NULL || cfg->host == NULL || cfg->host[0] == '\0'
        || cfg->port <= 0 || cfg->port > 65535 || cfg->transport == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    sd_http_init_endpoints(is, cfg);
    is->transport  = cfg->transport;
    is->failover_note = cfg->failover_note;
    is->health_note   = cfg->health_note;
    sd_http_init_tctx(is, cfg);
    is->timeout_ms = (cfg->timeout_ms > 0) ? cfg->timeout_ms
                                            : BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS;
    is->log        = log;
    is->cur_ep     = -1;
    if (cfg->bearer_token != NULL && cfg->bearer_token[0] != '\0') {
        snprintf(is->auth_hdr, sizeof(is->auth_hdr),
                 "Authorization: Bearer %s\r\n", cfg->bearer_token);
    }

    inst->driver = &brix_sd_http_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
brix_sd_http_destroy(brix_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}
