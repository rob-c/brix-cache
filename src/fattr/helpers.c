#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

uint16_t
fattr_errno_to_xrd(int err)
{
    switch (err) {
    case ENODATA:   return kXR_AttrNotFound;
    case ENOENT:
    case ENOTDIR:   return kXR_NotFound;
    case EPERM:
    case EACCES:    return kXR_NotAuthorized;
    case EEXIST:    return kXR_ItExists;
    case ERANGE:    return kXR_ArgTooLong;
    case ENOMEM:    return kXR_NoMemory;
    case ENOSPC:    return kXR_NoSpace;
    default:        return kXR_FSError;
    }
}

void
fattr_set_rc(xrootd_fattr_entry_t *attr, uint16_t rc)
{
    uint16_t rc_be;

    attr->errcode = rc;

    rc_be = htons(rc);
    ngx_memcpy(attr->rc_ptr, &rc_be, 2);
}

ssize_t
fattr_parse_nvec(ngx_log_t *log, u_char *nvec_copy, size_t buflen,
    int numattr, xrootd_fattr_entry_t *attrs)
{
    u_char *cursor;
    u_char *end;
    int     attr_index;

    /*
     * nvec is repeated as:
     *   [2-byte per-attribute result slot][NUL-terminated attribute name]
     *
     * The request payload is copied before parsing, so rc_ptr can safely point
     * back into nvec_copy.  Later operations overwrite only the result slot.
     */
    cursor = nvec_copy;
    end = nvec_copy + buflen;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        u_char *name_start;
        size_t  name_len;

        if (cursor + 2 > end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr nvec truncated at entry %d",
                          attr_index);
            return -1;
        }

        attrs[attr_index].rc_ptr = cursor;
        attrs[attr_index].errcode = 0;
        attrs[attr_index].value = NULL;
        attrs[attr_index].vlen = 0;
        cursor += 2;

        name_start = cursor;
        while (cursor < end && *cursor) {
            cursor++;
        }

        if (cursor >= end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr name not null-terminated");
            return -1;
        }

        name_len = (size_t) (cursor - name_start);
        if (name_len == 0 || name_len > kXR_faMaxNlen) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr name length %uz invalid",
                          name_len);
            return -1;
        }

        attrs[attr_index].name = (char *) name_start;
        attrs[attr_index].nlen = name_len;
        snprintf(attrs[attr_index].xkey, sizeof(attrs[attr_index].xkey),
                 XROOTD_FATTR_XKEY_PFX "%.*s", (int) name_len, name_start);

        cursor++;
    }

    return (ssize_t) (cursor - nvec_copy);
}

ngx_int_t
fattr_send_vector_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *nvec_copy, size_t nvec_len, int numattr,
    xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool;
    u_char     *response;
    size_t      response_size;
    int         error_count;
    int         attr_index;

    pool = c->pool;
    error_count = 0;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        if (attrs[attr_index].errcode) {
            error_count++;
        }
    }

    response_size = 2 + nvec_len;
    response = ngx_palloc(pool, response_size);
    if (response == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    response[0] = (u_char) error_count;
    response[1] = (u_char) numattr;
    ngx_memcpy(response + 2, nvec_copy, nvec_len);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, response, (uint32_t) response_size);
}
