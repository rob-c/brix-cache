#include "metrics_internal.h"


static ngx_int_t
mw_alloc_chain_buffer(ngx_pool_t *pool, ngx_chain_t **chain_out)
{
    ngx_buf_t   *buffer;
    ngx_chain_t *chain;

    buffer = ngx_create_temp_buf(pool, METRICS_BUF_SIZE);
    if (buffer == NULL) {
        return NGX_ERROR;
    }

    chain = ngx_alloc_chain_link(pool);
    if (chain == NULL) {
        return NGX_ERROR;
    }

    chain->buf = buffer;
    chain->next = NULL;

    *chain_out = chain;
    return NGX_OK;
}


static void
mw_select_tail_buffer(metrics_writer_t *mw)
{
    ngx_buf_t *buffer;

    buffer = mw->tail->buf;
    mw->pos = buffer->pos;
    mw->last = buffer->last + METRICS_BUF_SIZE;
}


static ngx_int_t
mw_append_buffer(metrics_writer_t *mw)
{
    ngx_chain_t *chain;

    mw->tail->buf->last = mw->pos;

    if (mw_alloc_chain_buffer(mw->pool, &chain) != NGX_OK) {
        return NGX_ERROR;
    }

    mw->tail->next = chain;
    mw->tail = chain;
    mw_select_tail_buffer(mw);

    return NGX_OK;
}


ngx_int_t
mw_init(metrics_writer_t *mw, ngx_pool_t *pool)
{
    ngx_chain_t *chain;

    if (mw_alloc_chain_buffer(pool, &chain) != NGX_OK) {
        return NGX_ERROR;
    }

    mw->pool  = pool;
    mw->head  = chain;
    mw->tail  = chain;
    mw->total = 0;

    mw_select_tail_buffer(mw);

    return NGX_OK;
}


ngx_int_t
mw_printf(metrics_writer_t *mw, const char *fmt, ...)
{
    va_list     args;
    int         formatted_len;
    size_t      available;

    available = (size_t) (mw->last - mw->pos);

    va_start(args, fmt);
    formatted_len = vsnprintf((char *) mw->pos, available, fmt, args);
    va_end(args);

    if (formatted_len < 0) {
        return NGX_ERROR;
    }

    if ((size_t) formatted_len >= available) {
        if (mw_append_buffer(mw) != NGX_OK) {
            return NGX_ERROR;
        }

        available = METRICS_BUF_SIZE;
        va_start(args, fmt);
        formatted_len = vsnprintf((char *) mw->pos, available, fmt, args);
        va_end(args);

        if (formatted_len < 0 || (size_t) formatted_len >= available) {
            return NGX_ERROR;
        }
    }

    mw->pos += formatted_len;
    mw->total += formatted_len;

    return NGX_OK;
}


void
mw_finish(metrics_writer_t *mw)
{
    mw->tail->buf->last    = mw->pos;
    mw->tail->buf->last_buf = 1;
}
