#ifndef BRIX_HTTP_CACHE_FILL_INTERNAL_H
#define BRIX_HTTP_CACHE_FILL_INTERNAL_H

/*
 * http_cache_fill_internal.h - private glue shared by the three
 * http_cache_fill translation units (split mechanically from a single file
 * for auditability; zero behaviour change):
 *
 *   http_cache_fill.c           public entry + pool resolver (+ !NGX_THREADS stub)
 *   http_cache_fill_registry.c  coalescing waiter registry (attach/detach/hold/abort)
 *   http_cache_fill_worker.c    worker thread + resolve + done finalize
 *
 * It declares the fill ctx / waiter structs, the per-worker in-flight list, and
 * the handful of symbols DEFINED in one unit but REFERENCED from another. All of
 * this machinery is thread-pool-only; the unit bodies stay guarded by NGX_THREADS.
 */

#include "http_cache_fill.h"
#include "fs/backend/ucred.h"
#include "observability/sesslog/sesslog_ngx.h"   /* brix_sess_t, brix_sess_xfer_t */

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>

struct brix_http_cache_fill_ctx_s;

/* Detached credential carried from the request event loop into the fill
 * worker. Every pointer-bearing brix_sd_cred_t field has owned storage here;
 * the whole zero-initialised value is also the coalescing scope, so two users
 * never share an origin authorization decision merely because their object
 * keys match. */
typedef struct {
    enum brix_cred_mode mode;
    unsigned            use_cred:1;
    unsigned            fallback_deny:1;
    char x509_proxy[BRIX_UCRED_PATH_MAX];
    char bearer[BRIX_UCRED_BEARER_MAX];
    char s3_ak[BRIX_UCRED_S3_AK_MAX];
    char s3_sk[BRIX_UCRED_S3_SK_MAX];
    char s3_region[BRIX_UCRED_S3_REGION_MAX];
    char s3_session[BRIX_UCRED_BEARER_MAX];
    char ceph_keyring[BRIX_UCRED_CEPH_KEYRING_MAX];
    char ceph_user[BRIX_UCRED_CEPH_USER_MAX];
    char sss_keytab[BRIX_UCRED_PATH_MAX];
    char krb5_ccache[BRIX_UCRED_PATH_MAX];
    char krb5_princ[BRIX_UCRED_PRINC_MAX];
    char key[BRIX_UCRED_KEY_MAX];
    char principal[BRIX_UCRED_PRINC_MAX];
    char vos[BRIX_UCRED_PRINC_MAX];
    char cred_dir[BRIX_UCRED_PATH_MAX];
} brix_http_fill_cred_t;

/* One request parked on an in-flight fill (event-loop-only). */
typedef struct brix_http_fill_waiter_s {
    ngx_http_request_t                   *r;
    brix_http_cache_reenter_pt          reenter;
    void                                 *reenter_data;
    brix_http_fill_fail_pt              on_fail;   /* NULL = no intercept */
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
    int                                  passthrough; /* phase-92: filled ONLY
                                                    * under brix_cache_passthrough
                                                    * — evict the key after every
                                                    * waiter has been served     */
    ngx_msec_t                           started_ms; /* fill post timestamp */
    unsigned                             attempts;   /* origin attempts run */
    brix_http_fill_cred_t                cred;       /* origin auth + scope */
    char                                 key[PATH_MAX];
    brix_sess_t                         *sess;
    brix_sess_xfer_t                     sess_xfer;
} brix_http_cache_fill_ctx_t;

/* Per-worker in-flight fills (event-loop-only; a handful at a time). Owned by
 * the registry unit; the worker unit unlinks a completed fill and the entry
 * unit both scans (coalesce) and publishes new fills. */
extern brix_http_cache_fill_ctx_t  *brix_http_fills;

/* Registry unit (http_cache_fill_registry.c). */
const char *brix_http_fill_log_key(const char *key, char *buf, size_t cap);
brix_http_cache_fill_ctx_t *brix_http_fill_find(brix_sd_instance_t *inst,
    const char *key, const brix_http_fill_cred_t *cred);
void brix_http_fill_detach(brix_http_fill_waiter_t *w);
void brix_http_fill_send_retry_later(ngx_http_request_t *r);
ngx_int_t brix_http_fill_attach(brix_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, brix_http_cache_reenter_pt reenter,
    void *reenter_data, brix_http_fill_fail_pt on_fail);

/* Worker unit (http_cache_fill_worker.c). */
void brix_http_cache_fill_thread(void *data, ngx_log_t *log);
void brix_http_cache_fill_done(ngx_event_t *ev);

/* Entry/worker credential carry helpers (http_cache_fill.c). */
ngx_int_t brix_http_fill_cred_resolve(struct brix_vfs_ctx_s *vctx,
    brix_http_fill_cred_t *out);
void brix_http_fill_cred_view(const brix_http_fill_cred_t *owned,
    brix_sd_cred_t *out);
int brix_http_fill_cred_equal(const brix_http_fill_cred_t *a,
    const brix_http_fill_cred_t *b);
void brix_http_fill_cred_wipe(brix_http_fill_cred_t *cred);

#endif /* BRIX_HTTP_CACHE_FILL_INTERNAL_H */
