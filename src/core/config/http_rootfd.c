#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <fcntl.h>
#include <unistd.h>

#include "shared_conf.h"
#include "http_rootfd.h"

/*
 * Pool cleanup: close the rootfd when the cycle pool is destroyed. On reload the
 * old cycle's pool is freed in the master, closing the master's copy of the fd;
 * worker copies (inherited via fork) are closed by the kernel when each worker
 * exits. This keeps reloads from leaking one fd per export root.
 */
static void
brix_http_rootfd_cleanup(void *data)
{
    ngx_http_brix_shared_conf_t *common = data;

    if (common->rootfd >= 0) {
        (void) close(common->rootfd);
        common->rootfd = -1;
    }
}

char *
brix_http_open_rootfd(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *common)
{
    ngx_pool_cleanup_t *cln;

    /* Nothing to confine: protocol disabled or no local export root (e.g. an
     * S3 location with no brix_s3_root). rootfd stays -1. */
    if (!common->enable || common->root_canon[0] == '\0') {
        return NGX_CONF_OK;
    }

    /* Idempotent: merge_loc_conf runs once per location, but guard anyway so a
     * second call never leaks the first fd. */
    if (common->rootfd >= 0) {
        return NGX_CONF_OK;
    }

    common->rootfd = open(common->root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (common->rootfd < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix: cannot open export root \"%s\" for "
                           "kernel-confined path operations",
                           common->root_canon);
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        (void) close(common->rootfd);
        common->rootfd = -1;
        return NGX_CONF_ERROR;
    }
    cln->handler = brix_http_rootfd_cleanup;
    cln->data    = common;

    return NGX_CONF_OK;
}
