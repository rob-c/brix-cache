/*
 * xrdhttp_multipart.c — multipart/byteranges GET for XrdHttp vector reads.
 *
 * WHAT: Implements HTTP multipart/byteranges response (RFC 7233 §4.1) for GET requests
 * that carry multiple comma-separated byte ranges.  This maps to XRootD's kXR_readv
 * (vector read) operation when accessed via the XrdHttp protocol dialect: clients such
 * as ROOT TFile and xrdcp --prefer-xrdhttp submit a single GET with a multi-range
 * Range header to retrieve non-contiguous data blocks in one round-trip.
 *
 * WHY: Without multipart range support, XrdHttp clients that need N data blocks must
 * issue N sequential GETs, negating the latency benefit of XRootD's readv.  A single
 * multipart GET reduces round-trips to one regardless of how many blocks are needed.
 *
 * HOW: After the file is already open (fd) and stat'd (sb):
 *   1. Parse all "bytes=a-b, c-d, ..." ranges from the Range header into a fixed-size
 *      array (up to XRDHTTP_MAX_RANGES entries; excess ranges are silently ignored).
 *   2. Validate each range: clamp end to file size; drop zero-length ranges.
 *   3. Compute total Content-Length (sum of per-part headers + data + boundaries).
 *   4. Build an ngx_chain_t: per-range part = boundary+headers (memory buf) +
 *      file data (file buf).  Append final boundary marker.
 *   5. Send headers and chain through ngx_http_output_filter().
 *
 * TLS/cleartext buffer rule (from AGENTS.md §INVARIANTS):
 *   - TLS connections: use memory-backed ngx_buf_t (b->memory=1).
 *   - Cleartext: use file-backed ngx_buf_t (b->in_file=1) for sendfile.
 *   Here we use file-backed buffers for data sections (sendfile-eligible) and
 *   memory buffers for part headers and boundary markers in both cases.
 *   This is safe: nginx's sendfile filter correctly handles mixed chains.
 *
 * FD ownership: if fd_from_table==1 the fd is owned by the fd-cache; we set
 *   clnf->fd = NGX_INVALID_FILE for each part's cleanup so the cache retains it.
 */

#include "xrdhttp.h"
#include "webdav.h"
#include "core/compat/http_file_response.h"
#include "core/compat/range_vector.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "core/compat/alloc_guard.h"

#define XRDHTTP_BOUNDARY  "xrdhttp_boundary_42"

/*
 * Append a memory buffer containing <text> (NUL-terminated) to the chain.
 * Allocates the text copy from r->pool.  Returns NGX_OK or NGX_ERROR.
 */
static ngx_int_t
chain_append_text(ngx_http_request_t *r,
                  ngx_chain_t **tail, const char *text,
                  ngx_chain_t **new_link_out)
{
    ngx_buf_t   *b;
    ngx_chain_t *link;
    size_t       len = ngx_strlen(text);

    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(ngx_buf_t), NGX_ERROR);
    b->pos  = b->start = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(b->pos, text, len);
    b->last = b->end = b->pos + len;
    b->memory = 1;

    link = ngx_alloc_chain_link(r->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }
    link->buf  = b;
    link->next = NULL;

    if (*tail != NULL) {
        (*tail)->next = link;
    }
    *tail = link;

    if (new_link_out) {
        *new_link_out = link;
    }
    return NGX_OK;
}


ngx_int_t
xrdhttp_handle_multipart_get(ngx_http_request_t *r,
                              ngx_fd_t fd,
                              const struct stat *sb,
                              int fd_from_table)
{
    xrootd_byte_range_t       ranges[XRDHTTP_MAX_RANGES];
    xrootd_range_vector_opts_t opts;
    ngx_uint_t                nranges;
    off_t                     total_len = 0;
    ngx_chain_t              *head = NULL;
    ngx_chain_t              *tail = NULL;
    ngx_chain_t              *link;
    ngx_table_elt_t          *h;
    char                      path[WEBDAV_MAX_PATH];
    char                      part_hdr[256];
    char                      len_str[32];
    ngx_uint_t                i;

    /* Get the resolved path for file bufs (used in cleanup). */
    path[0] = '\0';
    if (r->uri.len > 0 && r->uri.len < sizeof(path) - 1) {
        ngx_cpystrn((u_char *) path, r->uri.data,
                    ngx_min(r->uri.len + 1, sizeof(path)));
    }

    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncmp(r->headers_in.range->value.data, "bytes=", 6) != 0)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.max_ranges         = XRDHTTP_MAX_RANGES;
    opts.allow_suffix       = 1;
    opts.allow_open_ended   = 1;
    opts.drop_unsatisfiable = 1;

    if (xrootd_http_parse_range_vector(r->headers_in.range->value.data + 6,
                                       r->headers_in.range->value.len - 6,
                                       sb->st_size, &opts,
                                       ranges, &nranges) != NGX_OK
        || nranges == 0)
    {
        /* All ranges unsatisfiable. */
        r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    /* Compute Content-Length */    for (i = 0; i < nranges; i++) {
        off_t part_data_len = ranges[i].end - ranges[i].start + 1;

        /* Per-part header:
         *   --BOUNDARY\r\n
         *   Content-Type: application/octet-stream\r\n
         *   Content-Range: bytes START-END/SIZE\r\n
         *   \r\n
         */
        int hdr_len = snprintf(part_hdr, sizeof(part_hdr),
                               "--" XRDHTTP_BOUNDARY "\r\n"
                               "Content-Type: application/octet-stream\r\n"
                               "Content-Range: bytes %lld-%lld/%lld\r\n"
                               "\r\n",
                               (long long) ranges[i].start,
                               (long long) ranges[i].end,
                               (long long) sb->st_size);
        if (hdr_len < 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        total_len += hdr_len + part_data_len + 2 /* \r\n after data */;
    }
    /* Final boundary: --BOUNDARY--\r\n */
    total_len += sizeof("--" XRDHTTP_BOUNDARY "--\r\n") - 1;

    /* Build response chain */    for (i = 0; i < nranges; i++) {
        off_t part_data_len = ranges[i].end - ranges[i].start + 1;

        /* Part header. */
        snprintf(part_hdr, sizeof(part_hdr),
                 "--" XRDHTTP_BOUNDARY "\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Content-Range: bytes %lld-%lld/%lld\r\n"
                 "\r\n",
                 (long long) ranges[i].start,
                 (long long) ranges[i].end,
                 (long long) sb->st_size);

        if (chain_append_text(r, &tail, part_hdr, &link) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (head == NULL) {
            head = link;
        }

        /* File data for this range. */
        if (part_data_len > 0) {
            if (xrootd_http_chain_append_file_range(r, &tail, fd, path,
                                                    ranges[i].start,
                                                    ranges[i].end,
                                                    !fd_from_table) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (head == NULL) {
                head = tail;
            }
        }

        /* CRLF between data and next boundary. */
        if (chain_append_text(r, &tail, "\r\n", &link) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (head == NULL) {
            head = link;
        }
    }

    /* Final boundary. */
    if (chain_append_text(r, &tail,
                          "--" XRDHTTP_BOUNDARY "--\r\n",
                          &link) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (head == NULL) {
        head = link;
    }

    /* Mark last buffer. */
    if (tail != NULL) {
        tail->buf->last_buf        = 1;
        tail->buf->last_in_chain   = 1;
    }

    /* Set response headers */    r->headers_out.status           = NGX_HTTP_PARTIAL_CONTENT;
    r->headers_out.content_length_n = total_len;
    r->allow_ranges = 0;  /* we're emitting the ranges ourselves */

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){
        sizeof("multipart/byteranges; boundary=" XRDHTTP_BOUNDARY) - 1,
        (u_char *) "multipart/byteranges; boundary=" XRDHTTP_BOUNDARY
    });
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->value.len = sizeof("multipart/byteranges; boundary=" XRDHTTP_BOUNDARY) - 1;

    /* Add bytes-transferred metric for the total data payload only. */
    off_t data_bytes = 0;
    for (i = 0; i < nranges; i++) {
        data_bytes += ranges[i].end - ranges[i].start + 1;
    }
    snprintf(len_str, sizeof(len_str), "%lld", (long long) data_bytes);
    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) data_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) data_bytes);
    } else {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) data_bytes);
    }

    /* Inject XrdHttp response headers before send. */
    (void) xrdhttp_add_response_headers(r, NGX_HTTP_PARTIAL_CONTENT);

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, head);
}
