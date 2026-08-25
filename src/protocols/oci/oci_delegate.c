/*
 * oci_delegate.c — downstream Basic delegation and the authorize-on-hit gate
 * (phase-104 D16).
 *
 * WHAT: the mirror's delegated-pull mode: read the client's own registry
 *       credential from a downstream Basic header, prove it against the
 *       upstream once per (credential, repository), and refuse to serve any
 *       object route — cache hit or miss alike — without a fresh proof.
 * WHY:  one shared content-addressed cache is the whole point of a mirror,
 *       and it is exactly what turns a private image into a leak: after the
 *       first authorized pull the bytes are local, and a plain cache would
 *       hand them to anyone who can spell the digest. The fix is not to
 *       shard the cache but to keep the UPSTREAM the authorization oracle:
 *       every request on a delegate-mode mirror must first mint (or hold) a
 *       per-principal authorization proof, so revocation upstream propagates
 *       within the proof TTL and no user's credential or token can satisfy
 *       another user's request. The credential itself is replayed ONLY to
 *       the allowlisted token endpoint — never stored, never sent to the
 *       data plane; its sha256 is the one form that outlives the request,
 *       and only ever as an SHM key.
 * HOW:  ident (event loop): decode Basic, refuse cleartext, hash. Gate
 *       (event loop): SHM proof probe; on a miss, one bounded thread-pool
 *       task runs the proof: challenge memo → credential-scoped token mint
 *       (oci_upstream_auth.c) → a HEAD against the object with that bearer,
 *       because a DockerHub-style endpoint answers a denied scope with a
 *       200 and an empty grant, so "the mint worked" is NOT "authorized".
 *       Denials are answered with one uniform 401 that reveals nothing —
 *       not even whether the repository exists.
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/aio/aio.h"
#include "fs/cache/origin/s3_transport.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

#include <stdio.h>
#include <string.h>

#define OCI_DELEG_TIMEOUT_MS   10000

/* How long a discovered upstream auth challenge is memoized. The challenge
 * names the realm and service, which change on upstream reconfiguration and
 * nothing else — but a bound keeps a stale realm from outliving the day. */
#define OCI_DELEG_CHAL_TTL_MS  (3600 * 1000)

/* The memo value that records "this upstream challenges nobody": a marker no
 * real WWW-Authenticate can begin with, so the two readings cannot collide. */
#define OCI_DELEG_OPEN_MARK    "\x01open"

typedef enum {
    OCI_DELEG_ERROR = 0,               /* upstream unreachable → 502        */
    OCI_DELEG_GRANTED,
    OCI_DELEG_DENIED
} oci_deleg_verdict_e;

typedef struct {
    ngx_http_request_t   *r;
    brix_oci_upstream_t  *up;
    char                  path[BRIX_OCI_KEY_MAX];   /* canonical /v2/ route */
    char                  scope[512];               /* repository:<n>:pull  */
    char                  basic[BRIX_OCI_BASIC_MAX];/* "" = anonymous       */
    u_char                cred[32];
    time_t                proof_ttl;
    int                   verdict;                  /* oci_deleg_verdict_e  */
    unsigned              probe_get:1;              /* GET probe (listings) */
} oci_deleg_task_t;

/* ---- keys ---------------------------------------------------------------- */

/* The proof record's key: sha256("proof" ‖ 0x00 ‖ base_url ‖ 0x00 ‖ scope ‖
 * 0x00 ‖ cred). Same NUL discipline as the token key, same reason — and the
 * ASCII prefix is what keeps a proof from ever aliasing a token entry in the
 * shared zone. 0 = key written. */
static int
oci_deleg_proof_key(const brix_oci_upstream_t *up, const char *scope,
    const u_char cred[32], u_char key[32])
{
    char    buf[1600];
    size_t  n = 0, b = strlen(up->base_url), s = strlen(scope);

    if (6 + b + 1 + s + 1 + 32 >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, "proof", 6);                 n  = 6;
    memcpy(buf + n, up->base_url, b);        n += b;
    buf[n++] = '\0';
    memcpy(buf + n, scope, s);               n += s;
    buf[n++] = '\0';
    memcpy(buf + n, cred, 32);               n += 32;

    return brix_oci_sha256_key(buf, n, key);
}

/* The challenge memo's key: sha256("chal" ‖ 0x00 ‖ base_url). Per upstream,
 * not per scope — the realm and service are properties of the registry. */
static int
oci_deleg_chal_key(const brix_oci_upstream_t *up, u_char key[32])
{
    char    buf[600];
    size_t  b = strlen(up->base_url);

    if (5 + b >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, "chal", 5);
    memcpy(buf + 5, up->base_url, b);

    return brix_oci_sha256_key(buf, 5 + b, key);
}

/* ---- the downstream identity (event loop) -------------------------------- */

/* The one downstream challenge this surface issues, on every refusal that a
 * (different) credential could cure. Basic, not Bearer: the client's own
 * registry credential is the thing being delegated, and docker/podman login
 * already speaks it with no ceremony. */
static ngx_int_t
oci_deleg_challenge_hdr(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    u_char          *v;
    size_t           n;

    if (h == NULL) {
        return NGX_ERROR;
    }
    n = sizeof("Basic realm=\"\"") + lcf->delegate_realm.len;
    v = ngx_pnalloc(r->pool, n);
    if (v == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "WWW-Authenticate");
    h->value.data = v;
    h->value.len  = (size_t) (ngx_snprintf(v, n, "Basic realm=\"%V\"",
                                           &lcf->delegate_realm) - v);

    return NGX_OK;
}

/* The uniform refusal (D16): 401 + Basic challenge + the DENIED envelope with
 * no detail. One spelling for "bad password", "no such repository" and "not
 * yours to read", because any difference between them is an enumeration
 * oracle over somebody else's private namespace. */
static ngx_int_t
oci_deleg_refuse(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx)
{
    ctx->disp = BRIX_OCI_OUT_REFUSED;
    brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_READ,
                        NGX_HTTP_UNAUTHORIZED);
    if (oci_deleg_challenge_hdr(r, lcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_error(r, NGX_HTTP_UNAUTHORIZED, BRIX_OCI_ERR_DENIED,
                          NULL);
}

/* Decode the Basic payload into "user:pass" in the request pool and hash it.
 * NGX_DECLINED = identity established; anything else already answered. */
static ngx_int_t
oci_deleg_decode(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, ngx_str_t *b64)
{
    ngx_str_t          dst;
    u_char            *colon;
    char              *user;

    dst.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(b64->len) + 1);
    if (dst.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_decode_base64(&dst, b64) != NGX_OK
        || dst.len == 0 || dst.len >= BRIX_OCI_BASIC_MAX
        || memchr(dst.data, '\0', dst.len) != NULL)
    {
        return oci_deleg_refuse(r, lcf, ctx);
    }
    dst.data[dst.len] = '\0';

    colon = (u_char *) strchr((char *) dst.data, ':');
    if (colon == NULL || colon == dst.data) {
        return oci_deleg_refuse(r, lcf, ctx);
    }

    if (brix_oci_sha256_key(dst.data, dst.len, ctx->deleg_cred) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->deleg_basic = (const char *) dst.data;

    /* The username half, for the dashboard/log identity. Never the pair. */
    user = ngx_pnalloc(r->pool, (size_t) (colon - dst.data) + 1);
    if (user == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(user, dst.data, (size_t) (colon - dst.data));
    user[colon - dst.data] = '\0';
    ctx->deleg_user = user;

    return NGX_DECLINED;
}

ngx_int_t
brix_oci_delegate_ident(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx)
{
    ngx_table_elt_t *auth = r->headers_in.authorization;
    ngx_str_t        b64;
    int              is_tls = 0;

    if (!lcf->delegate || auth == NULL) {
        return NGX_DECLINED;               /* off, or anonymous: cred = 0s */
    }

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL);
#endif
    /* A credential on a cleartext connection is already burned; the ONE
     * thing still in our power is to refuse to act on it — before decoding,
     * so the secret never even enters this process's data flow. */
    if (!is_tls && !lcf->deleg_insecure) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        brix_oci_guard_emit(r, GUARD_R_AUTHFAIL, GUARD_OP_READ,
                            NGX_HTTP_BAD_REQUEST);
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST, BRIX_OCI_ERR_DENIED,
                              "credentials require TLS on this mirror");
    }

    if (auth->value.len < sizeof("Basic ") - 1
        || ngx_strncasecmp(auth->value.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1) != 0)
    {
        /* Bearer, Negotiate, junk: not a credential this surface can
         * delegate, and guessing is how a secret goes somewhere wrong. */
        return oci_deleg_refuse(r, lcf, ctx);
    }
    b64.data = auth->value.data + sizeof("Basic ") - 1;
    b64.len  = auth->value.len - (sizeof("Basic ") - 1);

    return oci_deleg_decode(r, lcf, ctx, &b64);
}

/* ---- the proof (thread pool) --------------------------------------------- */

/* One upstream leg on the worker thread: `method` against `path` (relative
 * to the upstream base), with an optional extra header block. The HTTP
 * status, or -1 on transport failure; `challenge` (may be NULL) receives the
 * WWW-Authenticate of a 401. */
static int
oci_deleg_leg(brix_oci_upstream_t *up, const char *method, const char *path,
    const char *hdrs, char *challenge, size_t challenge_len)
{
    const brix_s3_transport_t  *tr = &brix_s3_origin_curl_transport;
    brix_s3_resp_t              resp;
    char                        full[BRIX_OCI_KEY_MAX + 256];
    char                        errbuf[256];
    int                         status;

    if (challenge != NULL) {
        challenge[0] = '\0';
    }
    if ((size_t) snprintf(full, sizeof(full), "%s%s", up->base_path, path)
        >= sizeof(full))
    {
        return -1;
    }
    if (tr->request(NULL, up->host, up->port, up->tls, method, full, hdrs,
                    NULL, 0, OCI_DELEG_TIMEOUT_MS, &resp,
                    errbuf, sizeof(errbuf)) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "oci: delegate proof leg unreachable host=%s: %s",
            up->host, errbuf);
        return -1;
    }
    status = resp.status;
    if (status == NGX_HTTP_UNAUTHORIZED && challenge != NULL) {
        (void) tr->resp_header(&resp, "www-authenticate",
                               challenge, challenge_len);
    }
    tr->resp_free(&resp);

    return status;
}

/* Establish the upstream's auth challenge, through the SHM memo: probe
 * GET /v2/ once per upstream per memo-TTL, remember either the challenge or
 * the fact that the upstream challenges nobody. 0 = `chal` holds the
 * challenge or the open marker; -1 = the upstream could not be asked. */
static int
oci_deleg_challenge(brix_oci_upstream_t *up, char *chal, size_t chalsz)
{
    u_char  key[32];
    size_t  out_len = chalsz - 1;
    int     status;

    if (up->tokens != NULL && oci_deleg_chal_key(up, key) == 0
        && brix_kv_get(up->tokens, key, sizeof(key), chal, &out_len))
    {
        chal[out_len] = '\0';
        return 0;
    }

    status = oci_deleg_leg(up, "GET", "/v2/", NULL, chal, chalsz);
    if (status == NGX_HTTP_UNAUTHORIZED && chal[0] != '\0') {
        /* keep chal as-is */
    } else if (status >= 200 && status < 400) {
        (void) snprintf(chal, chalsz, "%s", OCI_DELEG_OPEN_MARK);
    } else {
        return -1;
    }

    if (up->tokens != NULL && oci_deleg_chal_key(up, key) == 0) {
        (void) brix_kv_set(up->tokens, key, sizeof(key), chal, strlen(chal),
                           OCI_DELEG_CHAL_TTL_MS);
    }
    return 0;
}

/* The verify HEAD: does THIS bearer actually read THIS object? 401/403 is
 * the denial; 404 is "authorized, absent" (the fill will surface it); any
 * other answer proves the grant. Required because a DockerHub-style token
 * endpoint mints a 200 with an empty access list for a denied scope. */
static int
oci_deleg_verify(oci_deleg_task_t *t, const char *tok)
{
    char  hdrs[BRIX_OCI_TOKEN_MAX + 64];
    int   status;

    hdrs[0] = '\0';
    if (tok != NULL
        && snprintf(hdrs, sizeof(hdrs), "Authorization: Bearer %s\r\n", tok)
           >= (int) sizeof(hdrs))
    {
        return OCI_DELEG_ERROR;
    }
    status = oci_deleg_leg(t->up, t->probe_get ? "GET" : "HEAD", t->path,
                           hdrs[0] ? hdrs : NULL, NULL, 0);
    if (status < 0) {
        return OCI_DELEG_ERROR;
    }
    if (status == NGX_HTTP_UNAUTHORIZED || status == NGX_HTTP_FORBIDDEN) {
        return OCI_DELEG_DENIED;
    }
    return OCI_DELEG_GRANTED;
}

/* thread side: challenge → credential-scoped mint → verify → record. */
static void
oci_deleg_thread(void *data, ngx_log_t *log)
{
    oci_deleg_task_t  *t = data;
    char               chal[1024];
    char               tok[BRIX_OCI_TOKEN_MAX];
    u_char             key[32];
    long               expires = 0;
    int                denied = 0;

    (void) log;
    t->verdict = OCI_DELEG_ERROR;

    if (oci_deleg_challenge(t->up, chal, sizeof(chal)) != 0) {
        return;
    }

    if (strcmp(chal, OCI_DELEG_OPEN_MARK) == 0) {
        /* An upstream with no auth has no private repositories: the HEAD
         * still runs, so a broken upstream is an error, not a grant. */
        t->verdict = oci_deleg_verify(t, NULL);

    } else {
        if (brix_oci_token_get_cred(t->up, t->path, chal,
                                    t->basic[0] ? t->basic : NULL, t->cred,
                                    tok, sizeof(tok), &expires,
                                    &denied) != 0)
        {
            t->verdict = denied ? OCI_DELEG_DENIED : OCI_DELEG_ERROR;
            return;
        }
        t->verdict = oci_deleg_verify(t, tok);
    }

    if (t->verdict != OCI_DELEG_GRANTED) {
        return;
    }

    /* Record the proof, then lend the bearer to the credential-blind entry
     * the coalesced fill's provider probes — bounded by the proof TTL and by
     * the token's own life, whichever ends first. */
    if (t->up->tokens != NULL
        && oci_deleg_proof_key(t->up, t->scope, t->cred, key) == 0)
    {
        (void) brix_kv_set(t->up->tokens, key, sizeof(key), "1", 1,
                           (ngx_msec_t) t->proof_ttl * 1000);
    }
    if (strcmp(chal, OCI_DELEG_OPEN_MARK) != 0) {
        long share = (long) t->proof_ttl;

        if (expires > 0 && expires < share) {
            share = expires;
        }
        brix_oci_token_share(t->up, t->path, tok, share);
    }
}

/* event-loop side: turn the verdict into the response or the re-entry. */
static void
oci_deleg_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    oci_deleg_task_t              *t = task->ctx;
    ngx_http_request_t            *r = t->r;
    ngx_connection_t              *c = r->connection;
    ngx_http_brix_oci_loc_conf_t  *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_oci_module);
    ngx_http_brix_oci_ctx_t       *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);

    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }

    if (t->verdict == OCI_DELEG_GRANTED) {
        BRIX_OCI_METRIC_INC(delegate_total[BRIX_OCI_DELEG_GRANTED]);
        ctx->deleg_proved = 1;
        ngx_http_finalize_request(r, ngx_http_brix_oci_handler(r));

    } else if (t->verdict == OCI_DELEG_DENIED) {
        BRIX_OCI_METRIC_INC(delegate_total[BRIX_OCI_DELEG_DENIED]);
        ngx_http_finalize_request(r, oci_deleg_refuse(r, lcf, ctx));

    } else {
        BRIX_OCI_METRIC_INC(delegate_total[BRIX_OCI_DELEG_ERROR]);
        BRIX_OCI_METRIC_INC(upstream_errors_total[BRIX_OCI_UPERR_OTHER]);
        ctx->disp = BRIX_OCI_OUT_ERROR;
        ngx_http_finalize_request(r,
            brix_oci_error(r, NGX_HTTP_BAD_GATEWAY, BRIX_OCI_ERR_UNAVAILABLE,
                           NULL));
    }
    ngx_http_run_posted_requests(c);
}

/* ---- the gate (event loop) ----------------------------------------------- */

/* Derive the upstream path the proof leg will probe. The object routes carry
 * the canonical key and are probed with a HEAD of the object itself. The
 * listing routes are gated BEFORE any key is built, so the classifier's
 * validated name is the source and a GET of the (paginated) tags listing is
 * the probe — same repository:pull scope either way, and the scope string is
 * derived ONCE, by pull_scope, from whichever probe path is in play.
 * NGX_OK = probe written (*probe_get set for the listing shape); anything
 * else is the finalized status the gate must return as-is. */
static ngx_int_t
oci_deleg_probe(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    char *probe, size_t probesz, int *probe_get)
{
    if (ctx->keyed) {
        if ((size_t) snprintf(probe, probesz, "%s", ctx->key) >= probesz) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return NGX_OK;
    }

    if (ctx->classified && ctx->req.name != NULL && ctx->req.name_len > 0) {
        if ((size_t) snprintf(probe, probesz, "/v2/%.*s/tags/list?n=1",
                              (int) ctx->req.name_len, ctx->req.name)
            >= probesz)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        *probe_get = 1;
        return NGX_OK;
    }

    return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                          BRIX_OCI_ERR_NAME_INVALID, NULL);
}

/* Copy everything the worker leg needs OUT of the request into the task —
 * after the post, only oci_deleg_done may touch `r` again. NGX_OK, or 500
 * when a component that already fit its source buffer somehow does not fit
 * the task's (a size-contract violation, not a runtime condition). */
static ngx_int_t
oci_deleg_task_fill(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, const char *probe, int probe_get,
    const char *scope, oci_deleg_task_t *t)
{
    t->r         = r;
    t->up        = lcf->up;
    t->proof_ttl = lcf->deleg_proof_ttl;
    ngx_memcpy(t->cred, ctx->deleg_cred, sizeof(t->cred));
    t->probe_get = probe_get ? 1 : 0;
    (void) snprintf(t->scope, sizeof(t->scope), "%s", scope);
    if ((size_t) snprintf(t->path, sizeof(t->path), "%s", probe)
        >= sizeof(t->path))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    t->basic[0] = '\0';
    if (ctx->deleg_basic != NULL
        && (size_t) snprintf(t->basic, sizeof(t->basic), "%s",
                             ctx->deleg_basic) >= sizeof(t->basic))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_oci_delegate_gate(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx)
{
    ngx_thread_task_t  *task;
    ngx_thread_pool_t  *pool;
    ngx_int_t           rc;
    char                scope[512];
    u_char              key[32];
    size_t              out_len;
    char                one[2];

    char                probe[BRIX_OCI_KEY_MAX + 32];
    int                 probe_get = 0;

    if (!lcf->delegate || ctx->deleg_proved) {
        return NGX_DECLINED;
    }

    rc = oci_deleg_probe(r, ctx, probe, sizeof(probe), &probe_get);
    if (rc != NGX_OK) {
        return rc;
    }

    if (brix_oci_pull_scope(probe, scope, sizeof(scope)) != 0) {
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_NAME_INVALID, NULL);
    }

    out_len = sizeof(one) - 1;
    if (lcf->up->tokens != NULL
        && oci_deleg_proof_key(lcf->up, scope, ctx->deleg_cred, key) == 0
        && brix_kv_get(lcf->up->tokens, key, sizeof(key), one, &out_len))
    {
        BRIX_OCI_METRIC_INC(delegate_total[BRIX_OCI_DELEG_CACHED]);
        return NGX_DECLINED;
    }

    brix_oci_up_log_ensure(lcf);

    pool = brix_oci_thread_pool(lcf);
    if (pool == NULL) {
        return brix_oci_error(r, NGX_HTTP_SERVICE_UNAVAILABLE,
                              BRIX_OCI_ERR_UNAVAILABLE,
                              "no thread pool configured for delegation");
    }
    task = ngx_thread_task_alloc(r->pool, sizeof(oci_deleg_task_t));
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = oci_deleg_task_fill(r, lcf, ctx, probe, probe_get, scope, task->ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    brix_task_bind(task, oci_deleg_thread, oci_deleg_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->main->count++;              /* request survives until oci_deleg_done */

    return NGX_DONE;
}
