#include "metrics_internal.h"

/*
 * WHAT: metrics_writer_t buffer-chain writer — alloc, append, printf, and finish for Prometheus exposition output.
 * WHY: The /metrics endpoint must emit HELP/TYPE/value lines in the Prometheus text format (0.0.4). A
 *      linked chain of ngx_buf_t buffers provides a growing write surface that can expand when vsnprintf
 *      output exceeds the current buffer capacity — nginx-chain-compatible for direct filter delivery.
 * HOW: mw_init allocates the first buffer and sets position markers. mw_printf uses vsnprintf with available-space
 *      check; on overflow, mw_append_buffer creates a new chain link and resets positions. mw_select_tail_buffer()
 *      establishes write boundaries (mw->pos / mw->last) within the selected tail buffer. mw_finish marks the last
 *      buffer's last_buf flag so nginx knows this is the complete response chain.
 */

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

/* ---- Function: mw_select_tail_buffer() — metrics writer tail buffer selection ---- */
/* WHAT: Selects the metrics_writer_t's tail ngx_buf_t for appending by initializing mw->pos to buffer's current position (buffer->pos) and setting mw->last = buffer->last + METRICS_BUF_SIZE. This establishes the write boundaries within the tail buffer before subsequent mw_append_buffer calls fill content.
 * WHY: The metrics writer uses a linked chain of buffers where each new buffer is appended via mw_append_buffer(). Before appending to any buffer, mw_select_tail_buffer() must establish position markers so mw->pos (write start) and mw->last (write end) are correctly set relative to the selected tail buffer. METRICS_BUF_SIZE defines how much beyond buffer->last we consider writable — this accounts for pre-allocated extra space in nginx_buf_t allocation.
 * HOW: Single three-step assignment → read mw->tail->buf pointer, copy buffer->pos into mw->pos (write start), set mw->last = buffer->last + METRICS_BUF_SIZE (write end boundary). No validation or error handling — assumes tail buffer is valid and pre-allocated with sufficient capacity. */

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
