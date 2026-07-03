/*
 * propfind_props.c - extracted concern
 * Phase-38 split of propfind.c; behavior-identical.
 */
#include "propfind_internal.h"


/*
 * Per-resource D:response generation
 * */

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
    }

    if ((mask & PF_GROUP)
        && brix_http_chain_appendf(pool, head, tail, "<D:group/>") == NULL)
    {
        return NGX_ERROR;
    }

    if (mask & PF_CURRENT_PRIVILEGE) {
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
    }

    if ((mask & PF_SUPPORTED_PRIVILEGE)
        && brix_http_chain_appendf(pool, head, tail,
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

    if (mask & PF_ACL) {
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


/*
 * Emit a D:response XML element for one resource.
 *
 * Behaviour depends on req->type:
 *   ALLPROP   — all known properties with values
 *   PROPNAME  — all property names as empty elements, no values, no
 *               expensive calls (skips statvfs and lock scan)
 *   PROP      — only req->prop_mask properties in 200 propstat; any
 *               unrecognised property in req->unknown[] in 404 propstat
 */
ngx_int_t
propfind_entry(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail,
               const char *href, const char *path, struct stat *sb,
               const propfind_req_t *req)
{
    char        date_buf[30];
    char       *safe_href;
    ngx_pool_t *pool  = r->pool;
    /* For an explicit PROP request only the requested bits are emitted; ALLPROP
     * (and PROPNAME, handled separately below) emits the full PF_ALL set. */
    unsigned    mask  = (req->type == PROPFIND_PROP) ? req->prop_mask : PF_ALL;
    /* Tracks which of the request's unknown props were actually resolved as
     * dead properties, so the rest can be reported in the 404 propstat. */
    ngx_flag_t  unknown_found[PF_UNKNOWN_MAX];
    ngx_uint_t  i;

    /* ngx_http_time writes an RFC 1123 date with no NUL; terminate it here. */
    *ngx_http_time((u_char *) date_buf, sb->st_mtime) = '\0';
    ngx_memzero(unknown_found, sizeof(unknown_found));

    safe_href = webdav_escape_xml_text(pool, href);
    if (safe_href == NULL) {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(pool, head, tail,
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop>", safe_href) == NULL)
    {
        return NGX_ERROR;
    }

    /* PROPNAME: emit all names as empty elements, then close. */    if (req->type == PROPFIND_PROPNAME) {
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:resourcetype/>"
                "<D:getcontentlength/>"
                "<D:getlastmodified/>"
                "<D:getetag/>"
                "<D:creationdate/>"
                "<D:displayname/>"
                "<D:quota-available-bytes/>"
                "<D:quota-used-bytes/>"
                "<D:supported-report-set/>"
                "<D:supportedlock/>"
                "<D:lockdiscovery/>"
                "<D:getcontenttype/>"
                "<D:owner/>"
                "<D:group/>"
                "<D:current-user-privilege-set/>"
                "<D:supported-privilege-set/>"
                "<D:acl/>"
                "<D:acl-restrictions/>"
                "<D:principal-collection-set/>"
                "<xrd:locality/>") == NULL
            || webdav_dead_props_append_all(r, path, head, tail, 1)
               != NGX_OK
            || brix_http_chain_appendf(pool, head, tail,
                "</D:prop>"
                "<D:status>HTTP/1.1 200 OK</D:status>"
                "</D:propstat>"
                "</D:response>") == NULL)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    /* ALLPROP / PROP: emit property values filtered by mask. */
    if (mask & PF_RESOURCETYPE) {
        if (S_ISDIR(sb->st_mode)) {
            if (brix_http_chain_appendf(pool, head, tail,
                    "<D:resourcetype>"
                    "<D:collection/>"
                    "</D:resourcetype>") == NULL)
                return NGX_ERROR;
        } else if (brix_http_chain_appendf(pool, head, tail,
                       "<D:resourcetype/>") == NULL) {
            return NGX_ERROR;
        }
    }

    if (mask & PF_CONTENTLENGTH) {
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:getcontentlength>%lld</D:getcontentlength>",
                S_ISDIR(sb->st_mode) ? 0LL : (long long) sb->st_size) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_LASTMODIFIED) {
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:getlastmodified>%s</D:getlastmodified>",
                date_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_ETAG) {
        char etag_buf[64];
        brix_http_etag_str(etag_buf, sizeof(etag_buf), sb->st_mtime,
                             sb->st_size, BRIX_ETAG_WEAK);
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:getetag>%s</D:getetag>", etag_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_CREATIONDATE) {
        char cdate_buf[32];

        brix_format_iso8601(sb->st_ctime, cdate_buf, sizeof(cdate_buf));
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:creationdate>%s</D:creationdate>", cdate_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_DISPLAYNAME) {
        const char *name = href + strlen(href);
        char       *safe_name;

        /* Display name is the last path segment: scan back from end of href to
         * the byte after the final '/'. */
        while (name > href && *(name - 1) != '/') {
            name--;
        }
        safe_name = webdav_escape_xml_text(pool, name);
        if (safe_name != NULL
            && brix_http_chain_appendf(pool, head, tail,
                   "<D:displayname>%s</D:displayname>", safe_name) == NULL)
        {
            return NGX_ERROR;
        }
    }

    /*
     * RFC 4331 quota properties describe a COLLECTION's storage quota, not a
     * file's.  Emitting them on a regular file is non-conformant and actively
     * breaks clients: gfal2/davix maps <D:quota-used-bytes> onto st_size, so a
     * file's reported size becomes the filesystem's used bytes (~TB) instead of
     * getcontentlength.  Stock XrdHttp never emits quota per-file.  Gate to
     * directories so files carry only getcontentlength as their size.
     */
    if ((mask & (PF_QUOTA_AVAILABLE | PF_QUOTA_USED)) && S_ISDIR(sb->st_mode)) {
        brix_fs_usage_t fsu;
        if (brix_fs_usage_stat(path, &fsu) == NGX_OK) {
            if ((mask & PF_QUOTA_AVAILABLE)
                && brix_http_chain_appendf(pool, head, tail,
                       "<D:quota-available-bytes>"
                       "%llu"
                       "</D:quota-available-bytes>",
                       (unsigned long long) fsu.available_bytes) == NULL)
                return NGX_ERROR;
            if ((mask & PF_QUOTA_USED)
                && brix_http_chain_appendf(pool, head, tail,
                       "<D:quota-used-bytes>"
                       "%llu"
                       "</D:quota-used-bytes>",
                       (unsigned long long) fsu.used_bytes) == NULL)
                return NGX_ERROR;
        }
    }

    if (mask & PF_SUPPORTED_REPORT) {
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:supported-report-set/>") == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_SUPPORTEDLOCK) {
        /* Lock helpers are best-effort here: a failure to emit the optional
         * supportedlock/lockdiscovery block must not abort the whole response. */
        (void) webdav_lock_append_supported(r, head, tail);
    }

    if (mask & PF_LOCKDISCOVERY) {
        (void) webdav_lock_append_discovery(r, path, head, tail);
    }

    if (mask & PF_CONTENTTYPE) {
        const char *ct = S_ISDIR(sb->st_mode)
                         ? "httpd/unix-directory"
                         : "application/octet-stream";
        if (brix_http_chain_appendf(pool, head, tail,
                "<D:getcontenttype>%s</D:getcontenttype>", ct) == NULL)
            return NGX_ERROR;
    }

    /*
     * xrd:locality — tape residency (phase-64 VFS seam). Emitted only when the
     * client explicitly names the prop (PF_LOCALITY is not in PF_ALL) and only for
     * regular files. Residency comes from the storage backend's model via
     * brix_vfs_residency (no FRM xattr): a plain disk/object export classifies
     * ONLINE, so it needs no nearline tier; on a nearline (tape) export an online
     * object is ONLINE_AND_NEARLINE (resident AND on the backend) and a
     * nearline/offline object is NEARLINE. Values follow the WLCG locality vocab.
     */
    if ((mask & PF_LOCALITY) && !S_ISDIR(sb->st_mode)) {
        ngx_http_brix_webdav_loc_conf_t *conf =
            ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
        brix_vfs_ctx_t      vctx;
        brix_sd_residency_t res;
        int                   nearline = 0;
        const char           *loc = "ONLINE";

        brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
            BRIX_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
            conf->common.allow_write, 0 /* is_tls */, NULL, path);
        if (brix_vfs_residency(&vctx, &res, &nearline) == NGX_OK && nearline) {
            switch (res) {
            case BRIX_SD_RES_ONLINE:
                loc = "ONLINE_AND_NEARLINE";
                break;
            case BRIX_SD_RES_NEARLINE:
            case BRIX_SD_RES_OFFLINE:
                loc = "NEARLINE";
                break;
            case BRIX_SD_RES_LOST:
                loc = "LOST";
                break;
            }
        }
        if (brix_http_chain_appendf(pool, head, tail,
                "<xrd:locality>%s</xrd:locality>", loc) == NULL)
            return NGX_ERROR;
    }

    if (propfind_append_acl_properties(r, head, tail, mask) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Dead (client-defined) properties: ALLPROP dumps them all; an explicit
     * PROP request instead tries to resolve each unrecognised name against the
     * dead-property store, recording hits in unknown_found[] so the misses can
     * go into a 404 propstat afterwards.  DAV:-namespace unknowns are never
     * looked up here — a DAV: name we don't know is genuinely unsupported. */
    if (req->type == PROPFIND_ALLPROP) {
        if (webdav_dead_props_append_all(r, path, head, tail, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (req->type == PROPFIND_PROP) {
        for (i = 0; i < req->unknown_count; i++) {
            if (strcmp(req->unknown[i].ns, "DAV:") != 0) {
                if (webdav_dead_prop_append_value(r, path,
                        req->unknown[i].ns, req->unknown[i].local,
                        head, tail, &unknown_found[i]) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (brix_http_chain_appendf(pool, head, tail,
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>") == NULL)
        return NGX_ERROR;

    /* For explicit PROP requests: emit 404 propstat for unknown properties.
     * Skip the whole block if every named unknown turned out to exist as a dead
     * property (all resolved above) — emitting an empty 404 propstat is invalid. */
    if (req->type == PROPFIND_PROP && req->unknown_count > 0) {
        ngx_flag_t any_missing = 0;

        for (i = 0; i < req->unknown_count; i++) {
            if (!unknown_found[i]) {
                any_missing = 1;
                break;
            }
        }

        /* Emit the 404 propstat only when at least one named property is
         * genuinely missing — an empty 404 propstat would be invalid, so when
         * nothing is missing we skip straight to closing the response. */
        if (any_missing) {
            if (brix_http_chain_appendf(pool, head, tail,
                    "<D:propstat><D:prop>") == NULL)
                return NGX_ERROR;

            for (i = 0; i < req->unknown_count; i++) {
                if (unknown_found[i]) {
                    continue;
                }
                if (brix_http_chain_appendf(pool, head, tail,
                        "%s", req->unknown[i].xml) == NULL)
                    return NGX_ERROR;
            }

            if (brix_http_chain_appendf(pool, head, tail,
                    "</D:prop>"
                    "<D:status>HTTP/1.1 404 Not Found</D:status>"
                    "</D:propstat>") == NULL)
                return NGX_ERROR;
        }
    }

    if (brix_http_chain_appendf(pool, head, tail, "</D:response>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
