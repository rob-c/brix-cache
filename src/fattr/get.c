#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

static ssize_t
fattr_read_value_size(const char *path, int fd, const char *xkey)
{
    return path != NULL ? getxattr(path, xkey, NULL, 0)
                        : fgetxattr(fd, xkey, NULL, 0);
}


static ssize_t
fattr_read_value(const char *path, int fd, const char *xkey, u_char *value,
    size_t value_len)
{
    return path != NULL ? getxattr(path, xkey, value, value_len)
                        : fgetxattr(fd, xkey, value, value_len);
}


static size_t
fattr_value_len_for_response(const xrootd_fattr_entry_t *attr)
{
    return attr->vlen > 0 ? (size_t) attr->vlen : 0;
}


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
