/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 *
 * This unit is the public entry point + async-pool resolver. The concurrency
 * machinery it drives was split out mechanically (zero behaviour change) for
 * auditability — see http_cache_fill_internal.h:
 *   http_cache_fill_registry.c  coalescing waiter registry (attach/detach/hold/abort)
 *   http_cache_fill_worker.c    worker thread + resolve + done finalize
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
#include "fs/vfs/vfs_internal.h"       /* backend credential gate */
#include "core/aio/aio.h"                      /* brix_task_bind */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */
#include "observability/sesslog/sesslog_ngx.h"

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>
#include <stdlib.h>                          /* calloc/free (worker heap) */
#include <sys/socket.h>                     /* recv(MSG_PEEK): client-abort probe */
#include <openssl/crypto.h>                  /* constant-time compare + secret wipe */

#include "http_cache_fill_internal.h"

typedef struct {
    char       *dst;
    size_t      cap;
    const char *src;
} fill_cred_copy_t;

static ngx_int_t
fill_cred_copy_fields(brix_http_fill_cred_t *out,
    const brix_sd_cred_t *cred)
{
    fill_cred_copy_t fields[] = {
        { out->x509_proxy, sizeof(out->x509_proxy), cred->x509_proxy },
        { out->bearer, sizeof(out->bearer), cred->bearer },
        { out->s3_ak, sizeof(out->s3_ak), cred->s3_ak },
        { out->s3_sk, sizeof(out->s3_sk), cred->s3_sk },
        { out->s3_region, sizeof(out->s3_region), cred->s3_region },
        { out->s3_session, sizeof(out->s3_session), cred->s3_session },
        { out->ceph_keyring, sizeof(out->ceph_keyring), cred->ceph_keyring },
        { out->ceph_user, sizeof(out->ceph_user), cred->ceph_user },
        { out->sss_keytab, sizeof(out->sss_keytab), cred->sss_keytab },
        { out->krb5_ccache, sizeof(out->krb5_ccache), cred->krb5_ccache },
        { out->krb5_princ, sizeof(out->krb5_princ), cred->krb5_princ },
        { out->key, sizeof(out->key), cred->key },
        { out->principal, sizeof(out->principal), cred->principal },
        { out->vos, sizeof(out->vos), cred->vos },
        { out->cred_dir, sizeof(out->cred_dir), cred->cred_dir },
    };
    size_t i;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        size_t len = fields[i].src == NULL ? 0 : ngx_strlen(fields[i].src);

        if (len >= fields[i].cap) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }
        if (len > 0) {
            ngx_memcpy(fields[i].dst, fields[i].src, len);
        }
        fields[i].dst[len] = '\0';
    }
    return NGX_OK;
}

ngx_int_t
brix_http_fill_cred_resolve(brix_vfs_ctx_t *vctx,
    brix_http_fill_cred_t *out)
{
    brix_sd_ucred_t store;
    brix_sd_cred_t  cred;
    int             use_cred = 0;
    int             gate_err = 0;
    ngx_int_t       rc;

    ngx_memzero(out, sizeof(*out));
    if (vctx == NULL) {
        return NGX_OK;
    }
    ngx_memzero(&store, sizeof(store));
    ngx_memzero(&cred, sizeof(cred));
    rc = brix_vfs_backend_cred(vctx, &store, &cred, &use_cred, &gate_err);
    if (rc == NGX_OK && use_cred) {
        rc = fill_cred_copy_fields(out, &cred);
        out->mode = cred.mode;
        out->fallback_deny = cred.fallback_deny ? 1 : 0;
        out->use_cred = (rc == NGX_OK) ? 1 : 0;
    }
    brix_sd_ucred_wipe(&store);
    if (rc != NGX_OK && gate_err != 0) {
        errno = gate_err;
    }
    return rc;
}

static const char *
fill_cred_field(const char *field)
{
    return field[0] == '\0' ? NULL : field;
}

void
brix_http_fill_cred_view(const brix_http_fill_cred_t *owned,
    brix_sd_cred_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->x509_proxy = fill_cred_field(owned->x509_proxy);
    out->bearer = fill_cred_field(owned->bearer);
    out->s3_ak = fill_cred_field(owned->s3_ak);
    out->s3_sk = fill_cred_field(owned->s3_sk);
    out->s3_region = fill_cred_field(owned->s3_region);
    out->s3_session = fill_cred_field(owned->s3_session);
    out->ceph_keyring = fill_cred_field(owned->ceph_keyring);
    out->ceph_user = fill_cred_field(owned->ceph_user);
    out->sss_keytab = fill_cred_field(owned->sss_keytab);
    out->krb5_ccache = fill_cred_field(owned->krb5_ccache);
    out->krb5_princ = fill_cred_field(owned->krb5_princ);
    out->key = fill_cred_field(owned->key);
    out->principal = fill_cred_field(owned->principal);
    out->vos = fill_cred_field(owned->vos);
    out->cred_dir = fill_cred_field(owned->cred_dir);
    out->mode = owned->mode;
    out->fallback_deny = owned->fallback_deny;
}

int
brix_http_fill_cred_equal(const brix_http_fill_cred_t *a,
    const brix_http_fill_cred_t *b)
{
    return CRYPTO_memcmp(a, b, sizeof(*a)) == 0;
}

void
brix_http_fill_cred_wipe(brix_http_fill_cred_t *cred)
{
    OPENSSL_cleanse(cred, sizeof(*cred));
}

#if (NGX_THREADS)

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
    brix_vfs_ctx_t *vctx,
    brix_http_cache_reenter_pt reenter, void *reenter_data,
    brix_http_fill_fail_pt on_fail)
{
    ngx_thread_task_t            *task;
    brix_http_cache_fill_ctx_t *t;
    ngx_thread_pool_t            *pool;
    u_char                       *block;
    brix_http_fill_cred_t         cred;

    if (inst == NULL || key == NULL || reenter == NULL || common == NULL
        || !brix_sd_cache_fill_needs_offload(inst, key))
    {
        return NGX_DECLINED;                 /* serve inline (hit / local / none) */
    }

    if (brix_http_fill_cred_resolve(vctx, &cred) != NGX_OK) {
        return NGX_ERROR;                    /* deny before coalescing/origin I/O */
    }

    /* Coalesce onto an in-flight fill of the same object: the stampede case
     * (N concurrent cold reads) is exactly ONE origin fetch, but only within
     * one credential scope. */
    t = brix_http_fill_find(inst, key, &cred);
    if (t != NULL) {
        ngx_int_t arc = brix_http_fill_attach(t, r, reenter, reenter_data,
                                              on_fail);
        brix_http_fill_cred_wipe(&cred);
        return arc;
    }

    pool = brix_http_cache_fill_pool(common);
    if (pool == NULL) {
        /* No pool: nothing can run off-loop, so fall through to the inline path
         * (preserves the pre-SP2 behaviour - a remote miss may stall/fail). */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: cache miss on \"%s\" needs an async thread pool to fill a "
            "remote tier; none configured - serving inline (may stall)", key);
        brix_http_fill_cred_wipe(&cred);
        return NGX_DECLINED;
    }

    /* Heap-owned task + ctx: the fill is shared by every parked request and
     * must not live in any one request's pool (an aborted first requester
     * would otherwise free the memory under the running task). */
    block = calloc(1, sizeof(ngx_thread_task_t)
                      + sizeof(brix_http_cache_fill_ctx_t));
    if (block == NULL) {
        brix_http_fill_cred_wipe(&cred);
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
    ngx_memcpy(&t->cred, &cred, sizeof(cred));
    brix_http_fill_cred_wipe(&cred);
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));
    t->sess = brix_sess_begin(common->session_log,
        brix_http_shared_access_log_fd(common), BRIX_SESS_PROTO_FILL,
        BRIX_SESS_DIR_OUT, "cache-origin", sizeof("cache-origin") - 1,
        BRIX_SESS_AM_ANON, NULL);
    brix_sess_auth_once(t->sess, BRIX_SESS_AM_ANON, "-", "-");
    brix_sess_attempt(t->sess, t->key, BRIX_SESS_MODE_READ);
    brix_sess_xfer_start(t->sess, &t->sess_xfer, t->key,
                         BRIX_SESS_MODE_READ, -1);

    brix_task_bind(task, brix_http_cache_fill_thread,
                     brix_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (brix_http_fill_attach(t, r, reenter, reenter_data, on_fail)
        != NGX_DONE)
    {
        brix_sess_end(t->sess, BRIX_SESS_END_ERROR);
        brix_http_fill_cred_wipe(&t->cred);
        free(block);
        return NGX_ERROR;
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        brix_http_fill_detach(t->waiters);     /* undo the attach        */
        r->main->count--;
        brix_sess_end(t->sess, BRIX_SESS_END_ERROR);
        brix_http_fill_cred_wipe(&t->cred);
        free(block);
        return NGX_ERROR;
    }

    t->next = brix_http_fills;                 /* publish for coalescing */
    brix_http_fills = t;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix: offloaded cache fill of \"%s\" to the thread pool", key);
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
    struct brix_vfs_ctx_s *vctx,
    brix_http_cache_reenter_pt reenter, void *reenter_data,
    brix_http_fill_fail_pt on_fail)
{
    (void) r;
    (void) inst;
    (void) key;
    (void) common;
    (void) vctx;
    (void) reenter;
    (void) reenter_data;
    (void) on_fail;
    return NGX_DECLINED;
}

#endif /* NGX_THREADS */
