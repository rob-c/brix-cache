/*
 * propfind_props_acl.c - RFC 3744 ACL-related DAV: properties.
 * Phase-38 split of propfind_props.c; behavior-identical.
 */
#include "propfind_internal.h"

/*
 * WHAT: Emit owner property (authenticated DN or "anonymous"). Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  RFC 3744 D:owner identifies the resource owner. We use the authenticated
 *       client DN from the request context, or "anonymous" if unavailable.
 *
 * HOW:  Check ctx for non-empty DN, XML-escape it, emit as <D:owner><D:href>.
 */
static ngx_int_t
propfind_emit_owner(ngx_http_request_t *r, ngx_chain_t **head,
                     ngx_chain_t **tail, ngx_http_brix_webdav_req_ctx_t *ctx)
{
    ngx_pool_t *pool = r->pool;
    const char *owner = (ctx != NULL && ctx->dn[0] != '\0')
                        ? ctx->dn : "anonymous";
    char *safe_owner = webdav_escape_xml_text(pool, owner);

    if (safe_owner == NULL
        || brix_http_chain_appendf(pool, head, tail,
            "<D:owner><D:href>%s</D:href></D:owner>",
            safe_owner) == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Emit current-user-privilege-set ACL property. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  RFC 3744 requires reporting the effective privileges for the current user.
 *       We synthesize read-only or read-write privileges based on allow_write.
 *
 * HOW:  Emit <D:current-user-privilege-set> with <D:read/>. If allow_write is
 *       enabled, add write/write-content/write-properties/bind/unbind.
 */
static ngx_int_t
propfind_emit_current_privilege(ngx_http_request_t *r, ngx_chain_t **head,
                                  ngx_chain_t **tail,
                                  ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_pool_t *pool = r->pool;

    if (brix_http_chain_appendf(pool, head, tail,
            "<D:current-user-privilege-set>"
            "<D:privilege><D:read/></D:privilege>") == NULL)
    {
        return NGX_ERROR;
    }

    if (conf->common.allow_write
        && brix_http_chain_appendf(pool, head, tail,
            "<D:privilege><D:write/></D:privilege>"
            "<D:privilege><D:write-content/></D:privilege>"
            "<D:privilege><D:write-properties/></D:privilege>"
            "<D:privilege><D:bind/></D:privilege>"
            "<D:privilege><D:unbind/></D:privilege>") == NULL)
    {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(pool, head, tail,
            "</D:current-user-privilege-set>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Emit supported-privilege-set property. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  RFC 3744 D:supported-privilege-set describes the privilege tree.
 *       We advertise a static hierarchy: all > read, all > write > (write-content,
 *       write-properties, bind, unbind).
 *
 * HOW:  Emit the nested <D:supported-privilege> hierarchy as a single XML block.
 */
static ngx_int_t
propfind_emit_supported_privilege(ngx_http_request_t *r, ngx_chain_t **head,
                                    ngx_chain_t **tail)
{
    ngx_pool_t *pool = r->pool;

    if (brix_http_chain_appendf(pool, head, tail,
            "<D:supported-privilege-set>"
            "<D:supported-privilege>"
            "<D:privilege><D:all/></D:privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:read/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write/></D:privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write-content/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write-properties/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:bind/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:unbind/></D:privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege-set>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Emit ACL element with all/read/write privileges. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  RFC 3744 D:acl property describes the ACL entries for the resource.
 *       We advertise a simple all-principal grant with read and (optionally) write.
 *
 * HOW:  Emit <D:acl><D:ace> with all principal, read privilege, and (if allow_write)
 *       write privilege.
 */
static ngx_int_t
propfind_emit_acl(ngx_http_request_t *r, ngx_chain_t **head,
                   ngx_chain_t **tail, ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_pool_t *pool = r->pool;

    if (brix_http_chain_appendf(pool, head, tail,
            "<D:acl><D:ace><D:principal><D:all/></D:principal>"
            "<D:grant><D:privilege><D:read/></D:privilege>") == NULL)
    {
        return NGX_ERROR;
    }

    if (conf->common.allow_write
        && brix_http_chain_appendf(pool, head, tail,
            "<D:privilege><D:write/></D:privilege>") == NULL)
    {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(pool, head, tail,
            "</D:grant><D:protected/></D:ace></D:acl>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Append the RFC 3744 ACL-related DAV: properties selected by `mask`.
 * These are synthesized from the request's authenticated identity and the
 * location's allow_write flag rather than from a real ACL store: owner is the
 * client DN (or "anonymous"), and the privilege/ACL sets advertise read plus
 * (only when writes are enabled) the write family.  Each clause is gated on its
 * own mask bit so PROP requests get exactly the properties they asked for.
 */
ngx_int_t
propfind_append_acl_properties(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, unsigned mask)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_http_brix_webdav_req_ctx_t  *ctx;
    ngx_pool_t                        *pool = r->pool;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    if (mask & PF_OWNER) {
        if (propfind_emit_owner(r, head, tail, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if ((mask & PF_GROUP)
        && brix_http_chain_appendf(pool, head, tail, "<D:group/>") == NULL)
    {
        return NGX_ERROR;
    }

    if (mask & PF_CURRENT_PRIVILEGE) {
        if (propfind_emit_current_privilege(r, head, tail, conf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (mask & PF_SUPPORTED_PRIVILEGE) {
        if (propfind_emit_supported_privilege(r, head, tail) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (mask & PF_ACL) {
        if (propfind_emit_acl(r, head, tail, conf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if ((mask & PF_ACL_RESTRICTIONS)
        && brix_http_chain_appendf(pool, head, tail,
            "<D:acl-restrictions><D:grant-only/><D:no-invert/>"
            "</D:acl-restrictions>") == NULL)
    {
        return NGX_ERROR;
    }

    if ((mask & PF_PRINCIPAL_SET)
        && brix_http_chain_appendf(pool, head, tail,
            "<D:principal-collection-set/>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
