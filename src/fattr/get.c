#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

/* ---- Function: fattr_read_value_size() — query POSIX xattr value length ----
 *
 * WHAT: Calls getxattr(path, key, NULL, 0) for path-based operations or
 *       fgetxattr(fd, key, NULL, 0) for open-file-handle operations to
 *       query the size of an extended attribute's stored value without
 *       allocating a buffer. Returns ssize_t: positive = value length in bytes,
 *       -1 = syscall error (errno set). Used as the first step before
 *       fattr_read_value() which allocates and reads the actual data.
 *
 * WHY: Two-phase read pattern — query size first then allocate buffer
 *       second avoids over-allocation and handles zero-length attributes
 *       correctly. Path-based vs fd-based dispatch via path != NULL check
 *       allows callers to use either operation mode without duplication. */
static ssize_t
fattr_read_value_size(const char *path, int fd, const char *xkey)
{
    return path != NULL ? getxattr(path, xkey, NULL, 0)
                        : fgetxattr(fd, xkey, NULL, 0);
}

/* ---- Function: fattr_read_value() — read POSIX xattr value bytes ----
 *
 * WHAT: Calls getxattr(path, key, buffer, len) for path-based operations or
 *       fgetxattr(fd, key, buffer, len) for open-file-handle operations to
 *       read the actual bytes stored in an extended attribute into caller-
 *       provided buffer. Returns ssize_t: positive = bytes read, -1 = syscall
 *       error (errno set). Caller must ensure value_len >= queried size from
 *       fattr_read_value_size().
 *
 * WHY: Same path/fd dispatch pattern as fattr_read_value_size() — single
 *       helper serves both operation modes. Buffer filled with raw attribute
 *       bytes; caller responsible for null-termination if needed (fattr_get
 *       adds +1 byte padding at allocation). */
static ssize_t
fattr_read_value(const char *path, int fd, const char *xkey, u_char *value,
    size_t value_len)
{
    return path != NULL ? getxattr(path, xkey, value, value_len)
                        : fgetxattr(fd, xkey, value, value_len);
}

/* ---- Function: fattr_value_len_for_response() — compute response payload length ----
 *
 * WHAT: Returns the number of bytes an attribute's value contributes to the
 *       vvec (value vector) portion of the kXR_fattrGet response body. If
 *       attr->vlen > 0 returns that value as size_t; if vlen == 0 (error or
 *       zero-length attribute) returns 0. Used during response-size estimation
 *       phase to calculate total buffer allocation before building wire format. */
static size_t
fattr_value_len_for_response(const xrootd_fattr_entry_t *attr)
{
    return attr->vlen > 0 ? (size_t) attr->vlen : 0;
}

/* ---- Function: fattr_get() — handle kXR_fattrGet: read extended attributes ----
 *
 * WHAT: Iterates over requested attribute names from the nvec (name vector),
 *       queries each value size via getxattr/fgetxattr, allocates buffers for
 *       successful reads, then builds a vector status response containing
 *       error count, total attr count, name vector copy, and per-attribute
 *       value lengths + raw bytes. Sends the response as kXR_ok with the
 *       complete vvec payload. Supports both path-based and open-file-handle
 *       operations — dispatches to getxattr or fgetxattr based on whether
 *       path parameter is non-null. Thread safety: operates only on provided
 *       ctx, c, pool and local stack variables (attrs array).
 *
 * WHY: XRootD kXR_fattrGet returns a structured vector response where each
 *       attribute gets its own value_len field followed by raw bytes in the
 *       vvec. Per-attribute error recording allows partial success — clients
 *       can read some attributes even if others fail (e.g., permission denied
 *       on specific xkeys). Two-phase read (size query then buffer alloc +
 *       read) prevents over-allocation and handles zero-length attributes
 *       correctly. Value length capped at kXR_faMaxVlen to prevent oversized
 *       responses from a single attribute. */
ngx_int_t
fattr_get(xrootd_ctx_t *ctx, ngx_connection_t *c, const char *path, int fd,
    u_char *nvec_copy, size_t nvec_len, int numattr,
    xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool;
    u_char     *response;
    u_char     *cursor;
    size_t      response_size;
    int         error_count;

    pool = c->pool;
    response_size = 2 + nvec_len;

    for (int attr_index = 0; attr_index < numattr; attr_index++) {
        xrootd_fattr_entry_t *attr;
        ssize_t              value_size;
        ssize_t              bytes_read;

        attr = &attrs[attr_index];
        value_size = fattr_read_value_size(path, fd, attr->xkey);
        if (value_size < 0) {
            fattr_set_rc(attr, fattr_errno_to_xrd(errno));
            response_size += 4;
            continue;
        }

        if (value_size > kXR_faMaxVlen) {
            value_size = kXR_faMaxVlen;
        }

        attr->value = ngx_palloc(pool, (size_t) value_size + 1);
        if (attr->value == NULL) {
            fattr_set_rc(attr, kXR_NoMemory);
            response_size += 4;
            continue;
        }

        bytes_read = fattr_read_value(path, fd, attr->xkey, attr->value,
                                      (size_t) value_size);
        if (bytes_read < 0) {
            fattr_set_rc(attr, fattr_errno_to_xrd(errno));
            attr->vlen = 0;
        } else {
            attr->vlen = bytes_read;
        }

        response_size += 4 + fattr_value_len_for_response(attr);
    }

    response = ngx_palloc(pool, response_size);
    if (response == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    error_count = 0;
    for (int attr_index = 0; attr_index < numattr; attr_index++) {
        if (attrs[attr_index].errcode != 0) {
            error_count++;
        }
    }

    cursor = response;
    *cursor++ = (u_char) error_count;
    *cursor++ = (u_char) numattr;

    ngx_memcpy(cursor, nvec_copy, nvec_len);
    cursor += nvec_len;

    for (int attr_index = 0; attr_index < numattr; attr_index++) {
        uint32_t value_len;
        uint32_t value_len_be;

        value_len = (uint32_t) fattr_value_len_for_response(&attrs[attr_index]);
        value_len_be = htonl(value_len);

        ngx_memcpy(cursor, &value_len_be, sizeof(value_len_be));
        cursor += sizeof(value_len_be);

        if (value_len > 0 && attrs[attr_index].value != NULL) {
            ngx_memcpy(cursor, attrs[attr_index].value, value_len);
            cursor += value_len;
        }
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, response, (uint32_t) response_size);
}
