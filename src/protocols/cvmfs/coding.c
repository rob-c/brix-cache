/* Bounded request-owned input and memory-backed coded responses. Delta and
 * dictionary selection/compression stay in their protocol-specific owners.
 */
#include "coding.h"
#include "core/compat/log_event.h"
#include "core/http/http_file_response.h"

/* WHAT: Read one bounded VFS object into request-owned coding buffers.
 * WHY: Both codings require exact input, handle-bound metadata, and an output
 * capacity no larger than input (a coded response must win over identity).
 * HOW: Validate metadata, allocate bounded buffers, read until complete; refuse
 * short/error reads so the caller retains its normal identity fallback.
 */
int
brix_cvmfs_coding_load(ngx_http_request_t *r, brix_vfs_file_t *file,
    brix_vfs_stat_t *metadata, size_t maximum, size_t *length,
    unsigned char **input, unsigned char **output)
{
    size_t offset = 0, size;

    if (brix_vfs_file_stat(file, metadata) != NGX_OK || metadata->is_directory
        || metadata->size <= 0 || (size_t) metadata->size > maximum)
    {
        return -1;
    }
    size = (size_t) metadata->size;
    *input = ngx_pnalloc(r->pool, size);
    *output = ngx_pnalloc(r->pool, size);
    if (*input == NULL || *output == NULL) {
        return -1;
    }
    while (offset < size) {
        ssize_t count = brix_vfs_file_pread(file, *input + offset,
                                           size - offset, (off_t) offset);
        if (count <= 0 || (size_t) count > size - offset) {
            return -1;
        }
        offset += (size_t) count;
    }
    *length = size;
    return 0;
}

/* WHAT: Emit the committed coded response with its exact negotiated identity.
 * WHY: Delta/dictionary metadata differ; ownership, memory/TLS flags, framing
 * and header-only handling must not diverge between the two encodings.
 * HOW: Set typed metadata, publish the declared encoding/identity/Vary headers,
 * wrap the pool-owned output, then use the existing single-buffer sender.
 */
ngx_int_t
brix_cvmfs_coding_emit(ngx_http_request_t *r, const brix_cvmfs_coding_t *coding,
    time_t mtime, const char *id, unsigned char *output,
    size_t source_length, size_t output_length)
{
    ngx_table_elt_t *encoding = NULL;
    ngx_buf_t *buffer;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) output_length;
    r->headers_out.last_modified_time = mtime;
    ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    if (brix_http_set_header(r, "Content-Encoding", coding->encoding, &encoding) != NGX_OK
        || brix_http_set_header(r, coding->id_header, id, NULL) != NGX_OK
        || brix_http_set_header(r, "Vary", coding->vary, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_encoding = encoding;
    buffer = ngx_calloc_buf(r->pool);
    if (buffer == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buffer->memory = 1;
    buffer->start = output;
    buffer->pos = output;
    buffer->last = output + output_length;
    buffer->end = buffer->last;
    buffer->last_buf = 1;
    buffer->last_in_chain = 1;
    BRIX_LOG(NGX_LOG_DEBUG, r->connection->log, 0,
        "%s: coded serve %uz -> %uz %s=%s", coding->log_label,
        source_length, output_length, coding->id_label, id);
    return brix_http_send_single_buf(r, buffer);
}
