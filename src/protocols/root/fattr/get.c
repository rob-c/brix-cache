#include "ngx_brix_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "core/compat/alloc_guard.h"

/*
 *
 * WHAT: Queries the size of an extended attribute's stored value (NULL buffer)
 *       through the VFS xattr seam — path mode (brix_vfs_getxattr on the vctx's
 *       resolved path) or open-handle mode (brix_vfs_fgetxattr on fd) selected
 *       by `path != NULL`. Returns ssize_t: positive = value length in bytes,
 *       -1 = error (errno set). First step before fattr_read_value() reads data.
 *
 * WHY: Two-phase read pattern — query size first then allocate buffer
 *       second avoids over-allocation and handles zero-length attributes
 *       correctly. Routing through the VFS keeps every xattr touch confined and
 *       observed (OP_XATTR metric) rather than hitting getxattr(2) directly. */
static ssize_t
fattr_read_value_size(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *xkey)
{
    return path != NULL ? brix_vfs_getxattr(vctx, xkey, NULL, 0)
                        : brix_vfs_fgetxattr(vctx, fd, xkey, NULL, 0);
}

/*
 *
 * WHAT: Reads the actual bytes stored in an extended attribute into the caller's
 *       buffer through the VFS xattr seam — path or open-handle mode as above.
 *       Returns ssize_t: positive = bytes read, -1 = error (errno set). Caller
 *       must ensure value_len >= queried size from fattr_read_value_size().
 *
 * WHY: Same path/fd dispatch pattern as fattr_read_value_size() — single
 *       helper serves both operation modes. Buffer filled with raw attribute
 *       bytes; caller responsible for null-termination if needed (fattr_get
 *       adds +1 byte padding at allocation). */
static ssize_t
fattr_read_value(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *xkey, u_char *value, size_t value_len)
{
    return path != NULL ? brix_vfs_getxattr(vctx, xkey, value, value_len)
                        : brix_vfs_fgetxattr(vctx, fd, xkey, value,
                                               value_len);
}

/*
 *
 * WHAT: Returns the number of bytes an attribute's value contributes to the
 *       vvec (value vector) portion of the kXR_fattrGet response body. If
 *       attr->vlen > 0 returns that value as size_t; if vlen == 0 (error or
 *       zero-length attribute) returns 0. Used during response-size estimation
 *       phase to calculate total buffer allocation before building wire format. */
static size_t
fattr_value_len_for_response(const brix_fattr_entry_t *attr)
{
    return attr->vlen > 0 ? (size_t) attr->vlen : 0;
}

/*
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
fattr_get(brix_ctx_t *ctx, ngx_connection_t *c, brix_vfs_ctx_t *vctx,
    const char *path, int fd, u_char *nvec_copy, size_t nvec_len, int numattr,
    brix_fattr_entry_t *attrs)
{
    ngx_pool_t *pool;
    u_char     *response;
    u_char     *cursor;
    size_t      response_size;
    int         error_count;

    pool = c->pool;
    response_size = 2 + nvec_len;

    for (int attr_index = 0; attr_index < numattr; attr_index++) {
        brix_fattr_entry_t *attr;
        ssize_t              value_size;
        ssize_t              bytes_read;

        attr = &attrs[attr_index];
        value_size = fattr_read_value_size(vctx, path, fd, attr->xkey);
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

        bytes_read = fattr_read_value(vctx, path, fd, attr->xkey, attr->value,
                                      (size_t) value_size);
        if (bytes_read < 0) {
            fattr_set_rc(attr, fattr_errno_to_xrd(errno));
            attr->vlen = 0;
        } else {
            attr->vlen = bytes_read;
        }

        response_size += 4 + fattr_value_len_for_response(attr);
    }

    BRIX_PALLOC_OR_RETURN(response, pool, response_size, brix_send_error(ctx, c, kXR_NoMemory, "out of memory"));

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

    BRIX_OP_OK(ctx, BRIX_OP_FATTR);
    return brix_send_ok(ctx, c, response, (uint32_t) response_size);
}
