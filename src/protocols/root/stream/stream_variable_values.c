/* Value publication helpers for the root:// nginx stream variables. */
#include "core/ngx_brix_module.h"
#include "protocols/root/stream/stream_variables_internal.h"

/* The sentinel for "brix has nothing to say about this session". Distinct from
 * an empty value so a log line never silently reads as a zero-byte session. */
static const char  brix_stream_var_none[] = "-";


brix_ctx_t *
brix_stream_var_ctx(ngx_stream_session_t *s)
{
    return ngx_stream_get_module_ctx(s, ngx_stream_brix_module);
}


ngx_int_t
brix_stream_var_none_value(ngx_stream_variable_value_t *v,
    ngx_uint_t no_cacheable)
{
    v->len = sizeof(brix_stream_var_none) - 1;
    v->valid = 1;
    v->no_cacheable = no_cacheable ? 1 : 0;
    v->not_found = 0;
    v->data = (u_char *) brix_stream_var_none;
    return NGX_OK;
}


/*
 * brix_stream_var_cstr — publish a NUL-terminated session string.
 *
 * Copies into the CONNECTION pool: the session's own buffers are reused across
 * ops, so handing nginx a pointer into ctx would risk the value changing (or
 * the buffer being recycled) between the handler running and the log line
 * being written. An empty source string reports the sentinel, not "".
 */
ngx_int_t
brix_stream_var_cstr(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    const char *src, ngx_uint_t no_cacheable)
{
    size_t   len;
    u_char  *copy;

    if (src == NULL || *src == '\0') {
        return brix_stream_var_none_value(v, no_cacheable);
    }

    len = ngx_strlen(src);
    copy = ngx_pnalloc(s->connection->pool, len);
    if (copy == NULL) {
        return brix_stream_var_none_value(v, no_cacheable);
    }
    ngx_memcpy(copy, src, len);

    v->len = (unsigned) len;
    v->valid = 1;
    v->no_cacheable = no_cacheable ? 1 : 0;
    v->not_found = 0;
    v->data = copy;
    return NGX_OK;
}


ngx_int_t
brix_stream_var_size(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    size_t value)
{
    u_char  *buf;

    buf = ngx_pnalloc(s->connection->pool, NGX_SIZE_T_LEN);
    if (buf == NULL) {
        return brix_stream_var_none_value(v, 1);
    }

    v->len = (unsigned) (ngx_sprintf(buf, "%uz", value) - buf);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = buf;
    return NGX_OK;
}

