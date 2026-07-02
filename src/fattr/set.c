#include "ngx_xrootd_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>   /* XATTR_CREATE flag only — syscalls go via the VFS */
#include <arpa/inet.h>

/*
 *
 * WHAT: Sets XRootD file extended attributes via POSIX setxattr/fsetxattr syscalls. Parses wire-format vvec buffer (4-byte big-endian length + value bytes per attribute) and applies each attribute to either path or fd based on options. Returns vector status response with per-attribute error codes.
 * WHY: Extended attribute management is critical for HEP data file metadata (checksums, provenance, access permissions). The wire protocol uses signed lengths which must be converted to unsigned before pointer arithmetic — this prevents the "negative length becomes huge size_t" trap that would cause buffer overruns. XATTR_CREATE flag enables kXR_fa_isNew option semantics (fail if attribute exists rather than overwrite).
 * HOW: Four-phase execution: (1) parse vvec with bounds checking and signed-to-unsigned conversion for safety, (2) apply each attribute via path-based or handle-based syscall depending on options, (3) collect per-attribute errors into attrs[] array, (4) send fattr_send_vector_status response with kXR_status(4007) framing containing per-attribute success/failure codes. INVARIANT #1 referenced: vector status responses use kXR_status framing + per-page CRC for integrity verification in pgwrite context; here applied to attribute error reporting consistency. */

ngx_int_t
fattr_set(xrootd_ctx_t *ctx, ngx_connection_t *c, xrootd_vfs_ctx_t *vctx,
    const char *path, int fd, int options, u_char *nvec_copy, size_t nvec_len,
    u_char *vvec_buf, size_t vvec_len, int numattr,
    xrootd_fattr_entry_t *attrs)
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
            rc = xrootd_vfs_setxattr(vctx, attrs[attr_index].xkey, value_cursor,
                                     value_len, xattr_flags);
        } else {
            rc = xrootd_vfs_fsetxattr(vctx, fd, attrs[attr_index].xkey,
                                      value_cursor, value_len, xattr_flags);
        }

        if (rc != 0) {
            fattr_set_rc(&attrs[attr_index], fattr_errno_to_xrd(errno));
        }

        value_cursor += value_len;
    }

    return fattr_send_vector_status(ctx, c, nvec_copy, nvec_len,
                                    numattr, attrs);
}
