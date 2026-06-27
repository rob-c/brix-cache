#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

/* Resolve `root` to its canonical absolute path (realpath) into the caller's
 * buffer.  Returns NGX_OK, or NGX_ERROR (emerg-logged) on failure. */
int
xrootd_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
                          char *root_canon, size_t root_canon_sz)
{
    char root_buf[PATH_MAX];

    if (root == NULL || root->len == 0 || root->len >= sizeof(root_buf)) {
        return 0;
    }

    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    if (realpath(root_buf, root_canon) == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cannot canonicalize root \"%s\"", root_buf);
        return 0;
    }

    if (ngx_strnlen((u_char *) root_canon, root_canon_sz) >= root_canon_sz) {
        return 0;
    }

    return 1;
}
