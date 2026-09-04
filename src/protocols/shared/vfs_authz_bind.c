/* HTTP-plane adapter for the protocol-neutral VFS authorization bundle. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "vfs_authz_bind.h"
#include "auth/authz/acc/acc.h"

static brix_authz_backstop_mode_t
http_authz_mode(const ngx_http_brix_shared_conf_t *common)
{
    ngx_uint_t mode = common->authz_backstop;

    if (mode == NGX_CONF_UNSET_UINT) {
        mode = BRIX_AUTHZ_BACKSTOP_OBSERVE;
    }
    return (brix_authz_backstop_mode_t) mode;
}

void
brix_http_vfs_bind_authz(ngx_http_request_t *r,
    const ngx_http_brix_shared_conf_t *common,
    ngx_array_t *authdb_rules, ngx_array_t *vo_rules,
    brix_vfs_ctx_t *vctx)
{
    char        peer[256];
    const char *resolved;
    size_t      len;

    if (r == NULL || common == NULL || vctx == NULL) {
        return;
    }

    len = ngx_min(r->connection->addr_text.len, sizeof(peer) - 1);
    ngx_memcpy(peer, r->connection->addr_text.data, len);
    peer[len] = '\0';
    if (common->acc.resolve_hosts) {
        resolved = brix_acc_resolve_peer(r->connection->sockaddr,
                                         r->connection->socklen,
                                         peer, sizeof(peer));
        if (resolved == NULL) {
            len = ngx_min(r->connection->addr_text.len, sizeof(peer) - 1);
            ngx_memcpy(peer, r->connection->addr_text.data, len);
            peer[len] = '\0';
        }
    }

    brix_vfs_ctx_bind_authz(vctx, authdb_rules, vo_rules,
        common->acc.tables, common->acc.format, peer,
        http_authz_mode(common));
}

void
brix_http_vfs_bind_no_rules(const ngx_http_brix_shared_conf_t *common,
    brix_vfs_ctx_t *vctx)
{
    if (common == NULL || vctx == NULL) {
        return;
    }
    brix_vfs_ctx_bind_no_authz_rules(vctx, http_authz_mode(common));
}
