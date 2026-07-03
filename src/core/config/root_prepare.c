/*
 * root_prepare.c — shared export-root validation and canonicalization.
 *
 * All three protocol surfaces (native root://, WebDAV, S3) need the same
 * startup check on their configured export root: verify it exists, is a
 * readable directory with the right permissions, and resolve it through
 * realpath(3) to eliminate symlinks from the confinement boundary.
 *
 * This helper centralises that logic so the behaviour is identical across
 * all surfaces.  It must be called during merge_loc_conf / postconfiguration
 * so that nginx -t catches misconfigured roots before traffic is accepted.
 */

#include "config.h"
#include "root_prepare.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

char *
brix_prepare_export_root(ngx_conf_t *cf,
    const ngx_str_t *root, const brix_export_root_opts_t *opts,
    char *root_canon)
{
    char       root_buf[PATH_MAX];
    int        access_mode;
    ngx_str_t  root_str;

    /* Empty root — either silently skip or hard fail depending on opts. */
    if (root == NULL || root->len == 0) {
        if (opts->required) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s is required but not set",
                               opts->directive_name);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    /* Guard against paths that would overflow the canonical buffer. */
    if (root->len >= opts->canon_size || root->len >= sizeof(root_buf)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s path is too long", opts->directive_name);
        return NGX_CONF_ERROR;
    }

    /* Build a NUL-terminated copy for stat/access/realpath. */
    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    /* Validate existence, kind (directory), and access permissions. */
    root_str.data = (u_char *) root_buf;
    root_str.len  = root->len;
    access_mode   = opts->allow_write ? (R_OK | W_OK | X_OK) : (R_OK | X_OK);

    if (brix_validate_path(cf, opts->directive_name, &root_str,
                             BRIX_PATH_DIRECTORY, access_mode) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* Resolve symlinks and normalise the path for the confinement boundary. */
    if (realpath(root_buf, root_canon) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                           "%s: cannot resolve canonical path for \"%s\"",
                           opts->directive_name, root_buf);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
