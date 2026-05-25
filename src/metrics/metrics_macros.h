#ifndef NGX_XROOTD_METRICS_MACROS_H
#define NGX_XROOTD_METRICS_MACROS_H

static ngx_inline ngx_xrootd_metrics_t *
xrootd_metrics_shared(void)
{
    if (ngx_xrootd_shm_zone == NULL
        || ngx_xrootd_shm_zone->data == NULL
        || ngx_xrootd_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (ngx_xrootd_metrics_t *) ngx_xrootd_shm_zone->data;
}

#define XROOTD_ATOMIC_INC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), 1);                                  \
    } while (0)

#define XROOTD_ATOMIC_DEC(counter)                                           \
    do {                                                                     \
        ngx_atomic_fetch_add((counter), (ngx_atomic_int_t) -1);              \
    } while (0)

#define XROOTD_ATOMIC_ADD(counter, amount)                                   \
    do {                                                                     \
        size_t _xrootd_metric_amount = (size_t) (amount);                    \
        if (_xrootd_metric_amount > 0) {                                     \
            ngx_atomic_fetch_add((counter), _xrootd_metric_amount);          \
        }                                                                    \
    } while (0)

#define XROOTD_SRV_METRIC_INC(ctx, field)                                    \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_INC(&(ctx)->metrics->field);                       \
        }                                                                    \
    } while (0)

#define XROOTD_SRV_METRIC_ADD(ctx, field, amount)                            \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_ADD(&(ctx)->metrics->field, (amount));             \
        }                                                                    \
    } while (0)

#define XROOTD_WEBDAV_METRIC_INC(field)                                      \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_INC(&_xrootd_metrics->webdav.field);               \
        }                                                                    \
    } while (0)

#define XROOTD_WEBDAV_METRIC_ADD(field, amount)                              \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_ADD(&_xrootd_metrics->webdav.field, (amount));     \
        }                                                                    \
    } while (0)

#define XROOTD_S3_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_INC(&_xrootd_metrics->s3.field);                   \
        }                                                                    \
    } while (0)

#define XROOTD_S3_METRIC_ADD(field, amount)                                  \
    do {                                                                     \
        ngx_xrootd_metrics_t *_xrootd_metrics = xrootd_metrics_shared();     \
        if (_xrootd_metrics != NULL) {                                       \
            XROOTD_ATOMIC_ADD(&_xrootd_metrics->s3.field, (amount));         \
        }                                                                    \
    } while (0)

/* Proxy metrics — use these from proxy/ sources.  ctx->metrics may be NULL. */
#define XROOTD_PROXY_METRIC_INC(ctx, field)                                  \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_INC(&(ctx)->metrics->proxy.field);                 \
        }                                                                    \
    } while (0)

#define XROOTD_PROXY_METRIC_ADD(ctx, field, amount)                          \
    do {                                                                     \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                       \
            XROOTD_ATOMIC_ADD(&(ctx)->metrics->proxy.field, (amount));       \
        }                                                                    \
    } while (0)

/*
 * Per-upstream breakdown macros.  proxy_ptr must be xrootd_proxy_ctx_t *.
 * These increment the per-upstream slice at proxy_ptr->upstream_idx alongside
 * the aggregate; call XROOTD_PROXY_METRIC_INC first, then one of these.
 */
#define XROOTD_PROXY_UP_INC(proxy_ptr, field)                                \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < XROOTD_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            XROOTD_ATOMIC_INC(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field); \
        }                                                                    \
    } while (0)

#define XROOTD_PROXY_UP_ADD(proxy_ptr, field, amount)                        \
    do {                                                                     \
        int _ui = (proxy_ptr)->upstream_idx;                                 \
        if (_ui >= 0 && _ui < XROOTD_PROXY_MAX_UPSTREAMS                    \
            && (proxy_ptr)->client_ctx != NULL                               \
            && (proxy_ptr)->client_ctx->metrics != NULL)                     \
        {                                                                    \
            XROOTD_ATOMIC_ADD(                                               \
                &(proxy_ptr)->client_ctx->metrics->proxy.upstreams[_ui].field, \
                (amount));                                                   \
        }                                                                    \
    } while (0)

#endif /* NGX_XROOTD_METRICS_MACROS_H */
