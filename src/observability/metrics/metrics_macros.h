/*
 * metrics_macros.h — lock-free SHM counter-increment macros and accessor.
 *
 * WHAT: Provides the one inline accessor brix_metrics_shared() that resolves
 *       the shared-memory metrics block from ngx_brix_shm_zone, plus the family
 *       of BRIX_*_METRIC_INC / _ADD macros that bump counters for each counter
 *       group: per-server (SRV), WebDAV, S3, and proxy (aggregate + per-upstream).
 *       The low-level BRIX_ATOMIC_INC/DEC/ADD primitives wrap ngx_atomic_fetch_add.
 * WHY:  Metric updates run on the hot request/IO path and across multiple worker
 *       processes, so every counter touch must be lock-free and NULL-safe. Funnelling
 *       all increments through these macros guarantees consistent atomic semantics,
 *       skips work when the SHM zone is not yet initialised (data == NULL or the
 *       nginx "==(void*)1" reuse sentinel) or when a ctx/metrics pointer is NULL,
 *       and keeps call sites terse so handlers never hand-roll atomics.
 * HOW:  brix_metrics_shared() guards the SHM sentinels and returns the typed
 *       block (or NULL). The webdav/s3 macros dereference that singleton; the SRV
 *       and PROXY macros instead take a ctx whose ->metrics field may be NULL. ADD
 *       skips zero/negative amounts. The per-upstream UP_ macros bound-check
 *       proxy_ptr->upstream_idx against BRIX_PROXY_MAX_UPSTREAMS before indexing
 *       the upstreams[] slice, and are meant to be called after the matching
 *       aggregate BRIX_PROXY_METRIC_INC/_ADD. Header-only (static inline + macros);
 *       requires ngx_brix_metrics_t / ngx_brix_shm_zone to be already in scope.
 */
#ifndef NGX_BRIX_METRICS_MACROS_H
#define NGX_BRIX_METRICS_MACROS_H

static ngx_inline ngx_brix_metrics_t *
brix_metrics_shared(void)
{
    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (ngx_brix_metrics_t *) ngx_brix_shm_zone->data;
}

#define BRIX_ATOMIC_INC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), 1);                                  \
    } while (0)

#define BRIX_ATOMIC_DEC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), (ngx_atomic_int_t) -1);              \
    } while (0)

#define BRIX_ATOMIC_ADD(counter, amount)                                   \
    do {                                                                     \
        size_t _brix_metric_amount = (size_t) (amount);                    \
        if (_brix_metric_amount > 0) {                                     \
            ngx_atomic_fetch_add((counter), _brix_metric_amount);          \
        }                                                                    \
    } while (0)

#define BRIX_SRV_METRIC_INC(ctx, field)                                    \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            BRIX_ATOMIC_INC(&(ctx)->metrics->field);                       \
        }                                                                    \
    } while (0)

#define BRIX_SRV_METRIC_ADD(ctx, field, amount)                            \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            BRIX_ATOMIC_ADD(&(ctx)->metrics->field, (amount));             \
        }                                                                    \
    } while (0)

#define BRIX_WEBDAV_METRIC_INC(field)                                      \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->webdav.field);               \
        }                                                                    \
    } while (0)

#define BRIX_WEBDAV_METRIC_ADD(field, amount)                              \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_ADD(&_brix_metrics->webdav.field, (amount));     \
        }                                                                    \
    } while (0)

#define BRIX_S3_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->s3.field);                   \
        }                                                                    \
    } while (0)

#define BRIX_CVMFS_METRIC_INC(field)                                       \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->cvmfs.field);                \
        }                                                                    \
    } while (0)

#define BRIX_CVMFS_METRIC_ADD(field, amount)                               \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_ADD(&_brix_metrics->cvmfs.field, (amount));      \
        }                                                                    \
    } while (0)

/* SciTags packet-marking counters (phase-34) — global, low-cardinality.  Safe
 * from any context (firefly/flowlabel emit; open/dispatch call sites); no-op when
 * the metrics SHM is not yet mapped. */
#define BRIX_PMARK_METRIC_INC(field)                                        \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->field);                      \
        }                                                                    \
    } while (0)

#define BRIX_S3_METRIC_ADD(field, amount)                                  \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_ADD(&_brix_metrics->s3.field, (amount));         \
        }                                                                    \
    } while (0)

/* Phase 51 cross-protocol resilience counters — global, low-cardinality.  Safe
 * from any context (CMS recv/accept, auth gate, OCSP, XrdAcc breakers); a no-op
 * until the metrics SHM is mapped. */
#define BRIX_RESIL_METRIC_INC(field)                                        \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->field);                      \
        }                                                                    \
    } while (0)

/* FRM tape-stage counters (phase-35) — global, low-cardinality.  Safe from the
 * stage scheduler/agent-reply path and the open/prepare/Tape-REST call sites;
 * no-op until the metrics SHM is mapped.  INC/DEC drive the in_flight gauge. */
#define BRIX_FRM_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_INC(&_brix_metrics->frm.field);                  \
        }                                                                    \
    } while (0)

#define BRIX_FRM_METRIC_DEC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_DEC(&_brix_metrics->frm.field);                  \
        }                                                                    \
    } while (0)

#define BRIX_FRM_METRIC_ADD(field, amount)                                  \
    do {                                                                     \
        ngx_brix_metrics_t *_brix_metrics = brix_metrics_shared();     \
        if (_brix_metrics != NULL) {                                       \
            BRIX_ATOMIC_ADD(&_brix_metrics->frm.field, (amount));        \
        }                                                                    \
    } while (0)

/* Proxy metrics — use these from proxy/ sources.  ctx->metrics may be NULL. */
#define BRIX_PROXY_METRIC_INC(ctx, field)                                  \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            BRIX_ATOMIC_INC(&(ctx)->metrics->proxy.field);                 \
        }                                                                    \
    } while (0)

#define BRIX_PROXY_METRIC_ADD(ctx, field, amount)                          \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            BRIX_ATOMIC_ADD(&(ctx)->metrics->proxy.field, (amount));       \
        }                                                                    \
    } while (0)

/*
 * Per-upstream breakdown macros.  proxy_ptr must be brix_proxy_ctx_t *.
 * These increment the per-upstream slice at proxy_ptr->upstream_idx alongside
 * the aggregate; call BRIX_PROXY_METRIC_INC first, then one of these.
 */
#define BRIX_PROXY_UP_INC(proxy_ptr, field)                                \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < BRIX_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            BRIX_ATOMIC_INC(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field); \
        }                                                                    \
    } while (0)

#define BRIX_PROXY_UP_ADD(proxy_ptr, field, amount)                        \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < BRIX_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            BRIX_ATOMIC_ADD(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field, \
                (amount));                                                   \
        }                                                                    \
    } while (0)

#endif /* NGX_BRIX_METRICS_MACROS_H */
