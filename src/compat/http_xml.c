/*
 * http_xml.c - shared HTTP XML chain construction and response helpers.
 *
 * WHAT: Builds ngx_chain_t of ngx_buf_t from formatted strings (printf-style),
 *       appends segments to a chain head/tail, and sends the completed chain
 *       as an HTTP response with status + content-type set on headers_out.
 *
 * WHY: S3 ListObjectsV2, CompleteMultipartUpload responses, and WebDAV PROPFIND all need
 *      XML bodies built from formatted strings. Centralising chain-append and send logic
 *      prevents duplicated pool-alloc patterns, va_list handling, and header-setup across
 *      protocol handlers.
 *
 * HOW: vappendf uses vsnprintf into stack tmp[2048] or palloc'd heap on overflow;
 *       creates ngx_buf_t + ngx_chain_t link;
 appends to head/tail pointers. appendf wraps
 *       vappendf with va_start/va_end. send_xml_buffer sets status/content_type/
 *       content_length_n, calls ngx_http_send_header then ngx_http_output_filter.
 */

#include "http_xml.h"
#include "xml.h"

#include <stdio.h>
#include <string.h>

/*
 * xrootd_http_chain_vappendf - append formatted string to an existing chain via va_list.
 *
 * WHAT: Formats args into a buffer (stack tmp[2048] or pool-allocated heap on overflow),
 *       creates an ngx_buf_t + ngx_chain_t link, and appends it to the chain pointed
 *       to by head/tail. Returns pointer to the new buf for callers that need to inspect it.
 *
 * WHY: S3 XML responses build incrementally — each element (BucketName, Contents,
 *      NextContinuationToken) is appended one at a time. This helper handles va_list
 *      formatting with safe overflow into pool-allocated memory so the chain grows without
 *      stack exhaustion.
 *
 * HOW: va_copy → vsnprintf(tmp,2048). If n>=sizeof(tmp): ngx_palloc(n+1) + retry vsnprintf.
 *       Else use tmp. ngx_create_temp_buf(pool,n) + ngx_memcpy data. ngx_alloc_chain_link
 *       (pool) → cl->buf=b; cl->next=NULL. Append to tail, update head/tail pointers.
 *       Return b pointer.
 */

ngx_buf_t *
xrootd_http_chain_vappendf(ngx_pool_t *pool, ngx_chain_t **head,
    ngx_chain_t **tail, const char *fmt, va_list ap)
{
    va_list      ap_copy;
    char         tmp[2048];
    char        *src;
    int          n;
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    va_copy(ap_copy, ap);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    if (n < 0) {
        va_end(ap_copy);
        return NULL;
    }

    if ((size_t) n >= sizeof(tmp)) {
        src = ngx_pnalloc(pool, (size_t) n + 1);
        if (src == NULL) {
            va_end(ap_copy);
            return NULL;
        }
        (void) vsnprintf(src, (size_t) n + 1, fmt, ap_copy);
    } else {
        src = tmp;
    }
    va_end(ap_copy);

    if (n == 0) {
        return (*tail != NULL) ? (*tail)->buf : NULL;
    }

    b = ngx_create_temp_buf(pool, (size_t) n);
    if (b == NULL) {
        return NULL;
    }
    ngx_memcpy(b->pos, src, (size_t) n);
    b->last = b->pos + n;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }
    cl->buf = b;
    cl->next = NULL;

    if (*tail == NULL) {
        *head = cl;
        *tail = cl;
    } else {
        (*tail)->next = cl;
        *tail = cl;
    }

    return b;
}

/*
 * xrootd_http_chain_appendf - convenience wrapper: append formatted string via variadic args.
 *
 * WHAT: Wraps xrootd_http_chain_vappendf() with va_start/va_end so callers pass a
 *       printf-style fmt+args directly without constructing a va_list manually. Appends the
 *       resulting buffer to head/tail chain pointers. Returns buf pointer.
 *
 * WHY: Most callers have a simple printf-style format string and don't want to manage
 *      va_list lifecycle. This wrapper eliminates va_start/va_end boilerplate at each callsite.
 *
 * HOW: va_start(ap,fmt) → vappendf(pool,head,tail,fmt,ap) → va_end(ap). Return buf.
 */

ngx_buf_t *
xrootd_http_chain_appendf(ngx_pool_t *pool, ngx_chain_t **head,
    ngx_chain_t **tail, const char *fmt, ...)
{
    va_list    ap;
    ngx_buf_t *b;

    va_start(ap, fmt);
    b = xrootd_http_chain_vappendf(pool, head, tail, fmt, ap);
    va_end(ap);

    return b;
}

/*
 * xrootd_http_send_xml_buffer - send a single ngx_buf_t as an HTTP XML response.
 *
 * WHAT: Sets r->headers_out.status, content_type, and content_length_n from the buffer size,
 *       then sends headers via ngx_http_send_header() followed by the buffer as a last_buf
 *       chain through ngx_http_output_filter(). Returns NGX_HTTP_INTERNAL_SERVER_ERROR if b is NULL.
 *
 * WHY: S3 and WebDAV XML responses follow the same pattern: set status + content-type,
 *      compute length from buffer, send header, output single-buffer chain with last_buf=1.
 *      Centralising this prevents inconsistent header setup across protocol handlers.
 *
 * HOW: b->last_buf=1; out.buf=b; out.next=NULL. Set headers_out fields. ngx_http_send_header;
 *       return ngx_http_output_filter(r,&out).
 */

ngx_int_t
xrootd_http_send_xml_buffer(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t content_type, ngx_buf_t *b)
{
    ngx_chain_t out;

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_type = content_type;
    r->headers_out.content_length_n = (off_t) (b->last - b->pos);

    ngx_http_send_header(r);
    return ngx_http_output_filter(r, &out);
}

/*
 * xrootd_http_send_xml_error - build and send a protocol-agnostic XML error response.
 *
 * WHAT: Formats an <Error><Code>...</Code><Message>...</Message></Error> body with
 *       XML-escaped Code and Message, then sends it with application/xml content-type.
 *
 * WHY: S3 uses this structure for all error responses; WebDAV REST endpoints can use it
 *      for machine-readable errors. Centralising the builder prevents each protocol from
 *      duplicating the XML escaping + buffer assembly + header setup pattern.
 *
 * HOW: Pre-sizes buffer with xrootd_xml_text_element_len(), allocates from r->pool,
 *      writes prefix + Code element + Message element + suffix, sends via
 *      xrootd_http_send_xml_buffer(). Returns NGX_HTTP_INTERNAL_SERVER_ERROR on OOM.
 */

ngx_int_t
xrootd_http_send_xml_error(ngx_http_request_t *r, ngx_uint_t status,
    const char *code, const char *message)
{
    static const char  prefix[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>";
    static const char  suffix[] = "</Error>";

    size_t      codelen = strlen(code);
    size_t      msglen  = strlen(message);
    size_t      total;
    ngx_buf_t  *b;

    total = sizeof(prefix) - 1
          + xrootd_xml_text_element_len("Code",
                (const u_char *) code, codelen,
                XROOTD_XML_ESCAPE_APOS_ENTITY)
          + xrootd_xml_text_element_len("Message",
                (const u_char *) message, msglen,
                XROOTD_XML_ESCAPE_APOS_ENTITY)
          + sizeof(suffix) - 1;

    b = ngx_create_temp_buf(r->pool, total + 4);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, prefix, sizeof(prefix) - 1);

    if (xrootd_xml_write_text_element("Code", (const u_char *) code, codelen,
                                      XROOTD_XML_ESCAPE_APOS_ENTITY,
                                      b->last, (size_t) (b->end - b->last),
                                      &codelen) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last += codelen;

    if (xrootd_xml_write_text_element("Message", (const u_char *) message, msglen,
                                      XROOTD_XML_ESCAPE_APOS_ENTITY,
                                      b->last, (size_t) (b->end - b->last),
                                      &msglen) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last += msglen;
    b->last  = ngx_cpymem(b->last, suffix, sizeof(suffix) - 1);

    return xrootd_http_send_xml_buffer(r, status,
        (ngx_str_t) ngx_string("application/xml"), b);
}
