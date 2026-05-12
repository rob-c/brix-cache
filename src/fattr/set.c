#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

ngx_int_t
fattr_set(xrootd_ctx_t *ctx, ngx_connection_t *c, const char *path, int fd,
    int options, u_char *nvec_copy, size_t nvec_len, u_char *vvec_buf,
    size_t vvec_len, int numattr, xrootd_fattr_entry_t *attrs)
{
    u_char *value_cursor;
    u_char *value_end;
    int     attr_index;
    int     xattr_flags;

    /*
     * vvec has one value per parsed name-vector entry, in the same order:
     *   [4-byte big-endian value length][value bytes]...
     *
     * Convert the signed wire length before doing pointer arithmetic.  That
     * avoids the easy-to-miss "negative length becomes huge size_t" trap.
     */
    value_cursor = vvec_buf;
    value_end = vvec_buf + vvec_len;
    xattr_flags = (options & kXR_fa_isNew) ? XATTR_CREATE : 0;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        uint32_t value_len_wire;
        int32_t  value_len_signed;
        size_t   value_len;
        int      rc;

        if ((size_t) (value_end - value_cursor) < 4) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr set: vvec truncated");
        }

        ngx_memcpy(&value_len_wire, value_cursor, 4);
        value_len_signed = (int32_t) ntohl(value_len_wire);
        value_cursor += 4;

        if (value_len_signed < 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr set: value invalid");
        }

        value_len = (size_t) value_len_signed;
        if (value_len > kXR_faMaxVlen) {
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "fattr set: value invalid");
        }
        if ((size_t) (value_end - value_cursor) < value_len) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr set: value invalid");
        }

        if (path != NULL) {
            rc = setxattr(path, attrs[attr_index].xkey, value_cursor,
                          value_len, xattr_flags);
        } else {
            rc = fsetxattr(fd, attrs[attr_index].xkey, value_cursor,
                           value_len, xattr_flags);
        }

        if (rc != 0) {
            fattr_set_rc(&attrs[attr_index], fattr_errno_to_xrd(errno));
        }

        value_cursor += value_len;
    }

    return fattr_send_vector_status(ctx, c, nvec_copy, nvec_len,
                                    numattr, attrs);
}
