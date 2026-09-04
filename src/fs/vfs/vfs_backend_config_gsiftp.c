/* Config-time ftp:// and gsiftp:// origin parser. */

#include "vfs_backend_config_internal.h"
#include "core/compat/host_split.h"

#include <string.h>

void
brix_vfs_backend_config_gsiftp(const char *root_canon,
    const brix_vfs_gsiftp_origin_t *origin)
{
    brix_vfs_backend_entry_t *entry;

    if (root_canon == NULL || root_canon[0] == '\0' || origin == NULL
        || origin->host == NULL || origin->host[0] == '\0'
        || origin->port < 1 || origin->port > 65535
        || origin->base_path == NULL || origin->base_path[0] != '/') {
        return;
    }
    entry = brix_vfs_backend_entry_claim(root_canon, "gsiftp");
    if (entry != NULL) {
        brix_vfs_backend_set_origin(entry, origin->host, origin->port,
            origin->require_gsi != 0, origin->base_path, 0);
    }
}

static int
vfs_gsiftp_scheme(const ngx_str_t *value, size_t *prefix_len,
    int *require_gsi)
{
    if (value->len > sizeof("gsiftp://") - 1
        && ngx_strncmp(value->data, "gsiftp://",
                       sizeof("gsiftp://") - 1) == 0) {
        *prefix_len = sizeof("gsiftp://") - 1;
        *require_gsi = 1;
        return 1;
    }
    if (value->len > sizeof("ftp://") - 1
        && ngx_strncmp(value->data, "ftp://", sizeof("ftp://") - 1) == 0) {
        *prefix_len = sizeof("ftp://") - 1;
        *require_gsi = 0;
        return 1;
    }
    return 0;
}

static int
vfs_gsiftp_char_safe(unsigned char ch)
{
    return ch != '\\' && ch != '?' && ch != '#' && ch != 0x7f
           && (ch == '\0' || ch >= 0x20);
}

static int
vfs_gsiftp_component_safe(const char *part, const char *end)
{
    size_t len = (size_t) (end - part);

    return !((len == 1 && part[0] == '.')
             || (len == 2 && part[0] == '.' && part[1] == '.'));
}

static int
vfs_gsiftp_path_valid(const char *path)
{
    const char *part = path + 1;
    const char *cursor;

    if (path[0] != '/') {
        return 0;
    }
    for (cursor = part;; cursor++) {
        unsigned char ch = (unsigned char) *cursor;

        if (!vfs_gsiftp_char_safe(ch)) {
            return 0;
        }
        if (ch != '/' && ch != '\0') {
            continue;
        }
        if (!vfs_gsiftp_component_safe(part, cursor)) {
            return 0;
        }
        if (ch == '\0') {
            return 1;
        }
        part = cursor + 1;
    }
}

ngx_int_t
vfs_parse_gsiftp_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *value)
{
    brix_vfs_gsiftp_origin_t origin;
    char                     authority[512];
    char                     host[256];
    char                     base[1024];
    size_t                   prefix_len;
    size_t                   authority_len;
    size_t                   path_len;
    size_t                   i;
    int                      require_gsi;
    int                      port;

    if (!vfs_gsiftp_scheme(value, &prefix_len, &require_gsi)) {
        return NGX_DECLINED;
    }
    authority_len = value->len - prefix_len;
    for (i = 0; i < authority_len; i++) {
        if (value->data[prefix_len + i] == '/') {
            authority_len = i;
            break;
        }
    }
    path_len = value->len - prefix_len - authority_len;
    if (authority_len == 0 || authority_len >= sizeof(authority)
        || path_len >= sizeof(base)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: ftp origin needs host[:port][/base]");
        return NGX_ERROR;
    }
    ngx_memcpy(authority, value->data + prefix_len, authority_len);
    authority[authority_len] = '\0';
    if (brix_split_host_port(authority, host, sizeof(host), &port,
                             require_gsi ? 2811 : 21) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: invalid ftp origin authority");
        return NGX_ERROR;
    }
    if (path_len == 0) {
        ngx_memcpy(base, "/", sizeof("/"));
    } else {
        ngx_memcpy(base, value->data + prefix_len + authority_len, path_len);
        base[path_len] = '\0';
    }
    if (!vfs_gsiftp_path_valid(base)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: unsafe ftp origin base path");
        return NGX_ERROR;
    }
    origin.host = host;
    origin.port = port;
    origin.base_path = base;
    origin.require_gsi = require_gsi;
    brix_vfs_backend_config_gsiftp(root_canon, &origin);
    return NGX_OK;
}
