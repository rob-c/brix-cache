#ifndef BRIX_COMPAT_HTTP_XML_H
#define BRIX_COMPAT_HTTP_XML_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdarg.h>

/*
 * Shared HTTP XML chain construction and response helpers.
 *
 * WHAT: Builds ngx_chain_t of ngx_buf_t from formatted strings (printf-style), appends
 *       segments to a chain head/tail, and sends the completed chain as an HTTP response
 *       with status + content-type set on headers_out.
 *
 * WHY: S3 ListObjectsV2, CompleteMultipartUpload responses, and WebDAV PROPFIND all need
 *      XML bodies built from formatted strings. Centralising chain-append and send logic
 *      prevents duplicated pool-alloc patterns, va_list handling, and header-setup across
 *      protocol handlers.
 */

ngx_buf_t *brix_http_chain_vappendf(ngx_pool_t *pool,
    ngx_chain_t **head, ngx_chain_t **tail, const char *fmt, va_list ap)
    __attribute__((format(printf, 4, 0)));

/*
 * brix_http_chain_appendf - convenience wrapper: append formatted string via variadic args.
 *
 * WHAT: Wraps vappendf() with va_start/va_end so callers pass a printf-style fmt+args
 *       directly without constructing a va_list manually. Returns buf pointer.
 *
 * WHY: Eliminates va_start/va_end boilerplate at each callsite.
 *
 * HOW: va_start(ap,fmt) → vappendf(pool,head,tail,fmt,ap) → va_end(ap). Return buf.
 */

ngx_buf_t *brix_http_chain_appendf(ngx_pool_t *pool,
    ngx_chain_t **head, ngx_chain_t **tail, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/*
 * brix_http_send_xml_buffer - send a single ngx_buf_t as an HTTP XML response.
 *
 * WHAT: Sets r->headers_out.status, content_type, and content_length_n from the buffer size,
 *       then sends headers via ngx_http_send_header() followed by the buffer as a last_buf
 *       chain through ngx_http_output_filter(). Returns NGX_HTTP_INTERNAL_SERVER_ERROR if b is NULL.
 *
 * WHY: S3 and WebDAV XML responses follow the same pattern: set status + content-type,
 *      compute length from buffer, send header, output single-buffer chain with last_buf=1.
 *
 * HOW: b->last_buf=1; out.buf=b; out.next=NULL. Set headers_out fields. ngx_http_send_header;
 *       return ngx_http_output_filter(r,&out).
 */

ngx_int_t brix_http_send_xml_buffer(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t content_type, ngx_buf_t *b);

/*
 * brix_http_send_xml_error - send a protocol-agnostic <Error> XML response.
 *
 * WHAT: Builds <?xml …?><Error><Code>code</Code><Message>message</Message></Error>
 *       with XML escaping on both fields, then sends via brix_http_send_xml_buffer.
 *
 * WHY: S3 uses this exact structure for all API errors; WebDAV REST endpoints can use
 *      it for machine-readable errors without duplicating the buffer/escaping/header
 *      boilerplate in each protocol module.
 *
 * HOW: brix_xml_text_element_len → pre-size buffer → ngx_create_temp_buf →
 *      write prefix + Code element + Message element + suffix →
 *      brix_http_send_xml_buffer(status, "application/xml", b).
 */
ngx_int_t brix_http_send_xml_error(ngx_http_request_t *r,
    ngx_uint_t status, const char *code, const char *message);

#endif /* BRIX_COMPAT_HTTP_XML_H */
