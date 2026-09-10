/*
 * vfs_backend_config_fwd.c — the forward://<protocols> backend grammar (2.0 F5)
 *
 * WHAT  `brix_storage_backend forward://root[,roots] permit=<host|.suffix> …`
 *       claims the export for the xroot_fwd driver: an export that names NO
 *       origin of its own, and instead relays each client-named
 *       `/root://host:port//path` key to that origin — the XCache forwarding
 *       proxy shape (upstream `pss.origin =`).
 * WHY   Every other backend line names one fixed origin, and the whole
 *       registry entry describes that one link (host/port/tls/credential).  A
 *       forwarding export has none of that: the protocol set and the origin
 *       permit list ARE its configuration, so it needs its own parser that
 *       fills the entry with an empty origin and the two forwarding fields.
 * HOW   Runs before the fixed-origin scheme table in
 *       vfs_parse_xroot_or_driver_origin() and answers NGX_DECLINED unless the
 *       spec starts with "forward://".  The permit list arrives later through
 *       the store-line params (`permit=`, vfs_backend_store_params.c), which
 *       refuses a forwarding export that ends up with none.
 */

#include "vfs_backend_config_internal.h"

#define VFS_FWD_PREFIX "forward://"

/* "root", "roots" or "root,roots" (any order): the schemes a client may name.
 * Anything else — an empty list, an unknown scheme, a dangling comma — is a
 * grammar error, never a silently narrowed set. */
static ngx_int_t
vfs_fwd_parse_protocols(const u_char *list, size_t list_len, int *root,
    int *roots)
{
    const u_char *end = list + list_len;
    const u_char *tok = list;
    const u_char *cut;
    size_t        len;

    *root = 0;
    *roots = 0;
    if (list_len == 0) {
        return NGX_ERROR;
    }
    while (tok <= end) {
        cut = ngx_strlchr((u_char *) tok, (u_char *) end, ',');
        if (cut == NULL) {
            cut = end;
        }
        len = (size_t) (cut - tok);
        if (len == sizeof("root") - 1 && ngx_strncmp(tok, "root", len) == 0) {
            *root = 1;
        } else if (len == sizeof("roots") - 1
                   && ngx_strncmp(tok, "roots", len) == 0)
        {
            *roots = 1;
        } else {
            return NGX_ERROR;           /* empty token or unknown scheme */
        }
        if (cut == end) {
            return NGX_OK;
        }
        tok = cut + 1;                  /* a trailing ',' yields an empty tok */
    }
    return NGX_ERROR;
}

ngx_int_t
vfs_parse_forward_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, int family)
{
    static const size_t        pfxn = sizeof(VFS_FWD_PREFIX) - 1;
    brix_vfs_backend_entry_t  *e;
    int                        root, roots;

    if (sb->len < pfxn || ngx_strncmp(sb->data, VFS_FWD_PREFIX, pfxn) != 0) {
        return NGX_DECLINED;
    }
    if (vfs_fwd_parse_protocols(sb->data + pfxn, sb->len - pfxn,
                                &root, &roots) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend \"%V\": forward:// takes a protocol list of "
            "root and/or roots (e.g. forward://root,roots)", sb);
        return NGX_ERROR;
    }

    e = brix_vfs_backend_entry_claim(root_canon, "xroot_fwd");
    if (e == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend \"%V\": backend registry is full", sb);
        return NGX_ERROR;
    }
    /* No origin of its own: the host is empty, the path root is "/", and the
     * permit list stays empty until the store-line params stamp it (an export
     * that never gets one is refused there). */
    brix_vfs_backend_set_origin(e, "", 0, 0, "/", 0);
    e->origin_family = family;
    e->origin_fwd_allow_root = root ? 1 : 0;
    e->origin_fwd_allow_roots = roots ? 1 : 0;
    e->origin_fwd_permit[0] = '\0';
    return NGX_OK;
}
