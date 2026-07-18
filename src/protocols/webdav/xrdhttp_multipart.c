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
#include "core/http/http_file_response.h"
#include "core/compat/range_vector.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "core/compat/alloc_guard.h"

#define XRDHTTP_BOUNDARY  "xrdhttp_boundary_42"


/*
 * WHAT: Per-request assembly context for the multipart body build.
 * WHY: The content-length pass and the chain-build pass share the same
 *   invariant inputs (request, source fd + its path/ownership, file size, and a
 *   caller-owned formatting scratch buffer).  Bundling them keeps each helper's
 *   signature small and its data flow explicit rather than threading 6+ params.
 * HOW: Populated once in the orchestrator and passed by const pointer to the
 *   length/chain helpers; nothing here is mutated by those helpers.
 */
typedef struct {
    ngx_http_request_t *r;
    ngx_fd_t            fd;
    const char         *path;
    int                 fd_from_table;
    off_t               file_size;
    char               *scratch;
    size_t              scratch_size;
} mp_ctx_t;

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

    BRIX_PCALLOC_OR_RETURN(b, r->pool, sizeof(ngx_buf_t), NGX_ERROR);
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


/*
 * WHAT: Format one part's MIME header block into <buf> and return its length.
 * WHY: The Content-Length pre-pass and the chain-build pass need byte-identical
 *   part headers; a single formatter guarantees the emitted bytes match the
 *   pre-computed length (RFC 7233 §4.1 boundary/Content-Range framing frozen).
 * HOW: snprintf the fixed 4-line block (boundary, Content-Type, Content-Range,
 *   blank) with this range's start/end and the file size.  Returns the snprintf
 *   result (>=0 on success, <0 on encoding error) so callers can fail-closed.
 */
static int
mp_format_part_header(char *buf, size_t buf_size,
                      const brix_byte_range_t *range, off_t file_size)
{
    return snprintf(buf, buf_size,
                    "--" XRDHTTP_BOUNDARY "\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Range: bytes %lld-%lld/%lld\r\n"
                    "\r\n",
                    (long long) range->start,
                    (long long) range->end,
                    (long long) file_size);
}


/*
 * WHAT: Compute the total multipart/byteranges body length into *total_out.
 * WHY: The response Content-Length must be known before any buffer is sent;
 *   it is the exact sum of per-part header bytes + data bytes + the "\r\n"
 *   after each part + the closing boundary marker.
 * HOW: For each range, format its header (via the shared formatter) to learn
 *   the header byte count, then add header + data + 2 (trailing CRLF).  Finally
 *   add the closing "--BOUNDARY--\r\n".  Returns NGX_OK, or NGX_ERROR if any
 *   header fails to format.  <ctx> carries the file size and scratch buffer.
 */
static ngx_int_t
mp_compute_content_length(const mp_ctx_t *ctx, const brix_byte_range_t *ranges,
                          ngx_uint_t nranges, off_t *total_out)
{
    off_t      total = 0;
    ngx_uint_t i;

    for (i = 0; i < nranges; i++) {
        off_t part_data_len = ranges[i].end - ranges[i].start + 1;
        int   hdr_len = mp_format_part_header(ctx->scratch, ctx->scratch_size,
                                              &ranges[i], ctx->file_size);
        if (hdr_len < 0) {
            return NGX_ERROR;
        }
        total += hdr_len + part_data_len + 2 /* \r\n after data */;
    }
    /* Final boundary: --BOUNDARY--\r\n */
    total += sizeof("--" XRDHTTP_BOUNDARY "--\r\n") - 1;

    *total_out = total;
    return NGX_OK;
}


/*
 * WHAT: Append one multipart part (header + optional file data + trailing CRLF)
 *   to the response chain, tracking the chain head.
 * WHY: The per-range emission is the load-bearing byte sequence; isolating it
 *   keeps the orchestrator flat and each append's error path a single return.
 * HOW: Format the part header into <scratch>, append it as a memory buf, then
 *   for non-empty ranges append the file-backed data buf (sendfile-eligible;
 *   own_fd = !fd_from_table so the fd-cache retains a shared fd), then append
 *   the "\r\n" separator.  *head is set to the first link produced if still
 *   NULL.  Returns NGX_OK or NGX_ERROR.
 */
static ngx_int_t
mp_append_part(const mp_ctx_t *ctx, ngx_chain_t **head, ngx_chain_t **tail,
               const brix_byte_range_t *range)
{
    off_t        part_data_len = range->end - range->start + 1;
    ngx_chain_t *link = NULL;

    mp_format_part_header(ctx->scratch, ctx->scratch_size, range,
                          ctx->file_size);

    if (chain_append_text(ctx->r, tail, ctx->scratch, &link) != NGX_OK) {
        return NGX_ERROR;
    }
    if (*head == NULL) {
        *head = link;
    }

    if (part_data_len > 0) {
        if (brix_http_chain_append_file_range(ctx->r, tail, ctx->fd, ctx->path,
                                                range->start, range->end,
                                                !ctx->fd_from_table) != NGX_OK)
        {
            return NGX_ERROR;
        }
        if (*head == NULL) {
            *head = *tail;
        }
    }

    if (chain_append_text(ctx->r, tail, "\r\n", &link) != NGX_OK) {
        return NGX_ERROR;
    }
    if (*head == NULL) {
        *head = link;
    }
    return NGX_OK;
}


/*
 * WHAT: Build the complete multipart body chain for all ranges and mark its
 *   last buffer.  Returns the chain head via *head_out.
 * WHY: Separating chain assembly from header/metric emission keeps the
 *   orchestrator a linear sequence of named phases.
 * HOW: Append each part (mp_append_part), then the closing boundary marker,
 *   then flag the tail buf as last_buf/last_in_chain.  Returns NGX_OK or
 *   NGX_ERROR.
 */
static ngx_int_t
mp_build_chain(const mp_ctx_t *ctx, const brix_byte_range_t *ranges,
               ngx_uint_t nranges, ngx_chain_t **head_out)
{
    ngx_chain_t *head = NULL;
    ngx_chain_t *tail = NULL;
    ngx_chain_t *link = NULL;
    ngx_uint_t   i;

    for (i = 0; i < nranges; i++) {
        if (mp_append_part(ctx, &head, &tail, &ranges[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Final boundary. */
    if (chain_append_text(ctx->r, &tail, "--" XRDHTTP_BOUNDARY "--\r\n",
                          &link) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (head == NULL) {
        head = link;
    }

    /* Mark last buffer. */
    if (tail != NULL) {
        tail->buf->last_buf      = 1;
        tail->buf->last_in_chain = 1;
    }

    *head_out = head;
    return NGX_OK;
}


/*
 * WHAT: Set the 206 status, Content-Length, and multipart Content-Type header.
 * WHY: Header emission is a distinct concern from body assembly; the
 *   multipart/byteranges Content-Type + boundary bytes are wire-frozen.
 * HOW: Assign status/content_length_n, disable nginx's own range emission,
 *   then push a Content-Type header carrying the boundary.  Returns NGX_OK or
 *   NGX_ERROR.
 */
static ngx_int_t
mp_set_response_headers(ngx_http_request_t *r, off_t total_len)
{
    ngx_table_elt_t *h;

    r->headers_out.status           = NGX_HTTP_PARTIAL_CONTENT;
    r->headers_out.content_length_n = total_len;
    r->allow_ranges = 0;  /* we're emitting the ranges ourselves */

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){
        sizeof("multipart/byteranges; boundary=" XRDHTTP_BOUNDARY) - 1,
        (u_char *) "multipart/byteranges; boundary=" XRDHTTP_BOUNDARY
    });
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }
    h->value.len = sizeof("multipart/byteranges; boundary=" XRDHTTP_BOUNDARY) - 1;
    return NGX_OK;
}


/*
 * WHAT: Account the transferred data-payload bytes (data only, no framing) to
 *   the WebDAV byte-transfer metrics, split by address family.
 * WHY: Metric labels must stay low-cardinality; only total + per-family byte
 *   counters are bumped, using the summed data length (not the framed length).
 * HOW: Sum each range's data length, add to the total counter and to the IPv6
 *   or IPv4 counter based on the connection's socket family.
 */
static void
mp_account_metrics(ngx_http_request_t *r,
                   const brix_byte_range_t *ranges, ngx_uint_t nranges)
{
    off_t      data_bytes = 0;
    ngx_uint_t i;

    for (i = 0; i < nranges; i++) {
        data_bytes += ranges[i].end - ranges[i].start + 1;
    }

    BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) data_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) data_bytes);
    } else {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) data_bytes);
    }
}


/*
 * WHAT: Copy the request URI into <path> (used as the file-buf path for
 *   sendfile cleanup), NUL-terminating and bounding to the buffer.
 * WHY: The file-range bufs record a path for their cleanup handler; it must be
 *   a bounded C string derived from the (non-NUL-terminated) ngx_str_t URI.
 * HOW: Start empty, and if the URI fits, cpystrn it (which NUL-terminates).
 */
static void
mp_resolve_path(ngx_http_request_t *r, char *path, size_t path_size)
{
    path[0] = '\0';
    if (r->uri.len > 0 && r->uri.len < path_size - 1) {
        ngx_cpystrn((u_char *) path, r->uri.data,
                    ngx_min(r->uri.len + 1, path_size));
    }
}


ngx_int_t
xrdhttp_handle_multipart_get(ngx_http_request_t *r,
                              ngx_fd_t fd,
                              const struct stat *sb,
                              int fd_from_table)
{
    brix_byte_range_t        ranges[XRDHTTP_MAX_RANGES];
    brix_range_vector_opts_t opts;
    ngx_uint_t               nranges = 0;
    off_t                    total_len = 0;
    ngx_chain_t             *head = NULL;
    char                     path[WEBDAV_MAX_PATH];
    char                     part_hdr[256];
    ngx_int_t                rc;

    /* Get the resolved path for file bufs (used in cleanup). */
    mp_resolve_path(r, path, sizeof(path));

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

    if (brix_http_parse_range_vector(r->headers_in.range->value.data + 6,
                                       r->headers_in.range->value.len - 6,
                                       sb->st_size, &opts,
                                       ranges, &nranges, NULL) != NGX_OK
        || nranges == 0)
    {
        /* All ranges unsatisfiable. */
        r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    mp_ctx_t ctx = {
        .r             = r,
        .fd            = fd,
        .path          = path,
        .fd_from_table = fd_from_table,
        .file_size     = sb->st_size,
        .scratch       = part_hdr,
        .scratch_size  = sizeof(part_hdr),
    };

    if (mp_compute_content_length(&ctx, ranges, nranges, &total_len) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (mp_build_chain(&ctx, ranges, nranges, &head) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (mp_set_response_headers(r, total_len) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    mp_account_metrics(r, ranges, nranges);

    /* Inject XrdHttp response headers before send. */
    (void) xrdhttp_add_response_headers(r, NGX_HTTP_PARTIAL_CONTENT);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, head);
}
