#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

ngx_int_t
fattr_del(xrootd_ctx_t *ctx, ngx_connection_t *c, const char *path, int fd,
    u_char *nvec_copy, size_t nvec_len, int numattr,
    xrootd_fattr_entry_t *attrs)
{
    int attr_index;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        int rc;

        if (path != NULL) {
            rc = removexattr(path, attrs[attr_index].xkey);
        } else {
            rc = fremovexattr(fd, attrs[attr_index].xkey);
        }

        if (rc != 0) {
            fattr_set_rc(&attrs[attr_index], fattr_errno_to_xrd(errno));
        }
    }

    return fattr_send_vector_status(ctx, c, nvec_copy, nvec_len,
                                    numattr, attrs);
}
