/* Internal value-rendering helpers shared by the stream variable units. */
#ifndef BRIX_STREAM_VARIABLES_INTERNAL_H
#define BRIX_STREAM_VARIABLES_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

typedef struct brix_ctx_s brix_ctx_t;

brix_ctx_t *brix_stream_var_ctx(ngx_stream_session_t *s);
ngx_int_t brix_stream_var_none_value(ngx_stream_variable_value_t *v,
    ngx_uint_t no_cacheable);
ngx_int_t brix_stream_var_cstr(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, const char *src, ngx_uint_t no_cacheable);
ngx_int_t brix_stream_var_size(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, size_t value);

#endif /* BRIX_STREAM_VARIABLES_INTERNAL_H */
