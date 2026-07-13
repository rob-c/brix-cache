/*
 * propfind_props.c - extracted concern
 * Phase-38 split of propfind.c; behavior-identical.
 */
#include "propfind_internal.h"


/*
 * Per-resource D:response generation
 * */

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


/*
 * WHAT: Emit RFC 4331 quota properties for directories. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  Quota properties describe a COLLECTION's storage quota. Emitting them on
 *       regular files breaks clients (gfal2/davix maps quota-used-bytes onto file
 *       size, so a file appears ~TB instead of its actual size).
 *
 * HOW:  Gate on S_ISDIR, query filesystem usage via brix_fs_usage_stat(), emit
 *       quota-available-bytes and/or quota-used-bytes based on mask bits.
 */
static ngx_int_t
propfind_emit_quota(ngx_http_request_t *r, ngx_chain_t **head,
                     ngx_chain_t **tail, unsigned mask, const char *path,
                     struct stat *sb)
{
    ngx_pool_t *pool = r->pool;

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

    return NGX_OK;
}

/*
 * WHAT: Emit displayname property (last path segment of href). Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  DAV:displayname is a human-readable resource name, typically the last
 *       segment of the URL path.
 *
 * HOW:  Scan backwards from end of href to find the byte after the final '/'.
 *       XML-escape the name and emit as <D:displayname>.
 */
static ngx_int_t
propfind_emit_displayname(ngx_http_request_t *r, ngx_chain_t **head,
                           ngx_chain_t **tail, const char *href)
{
    ngx_pool_t *pool = r->pool;
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

    return NGX_OK;
}

/*
 * WHAT: Emit xrd:locality (tape residency) for regular files. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  xrd:locality reports WLCG tape residency status (ONLINE, NEARLINE, etc.).
 *       Only emitted when explicitly requested (not in PF_ALL) and only for files.
 *
 * HOW:  Query VFS residency via brix_vfs_residency(), map backend residency state
 *       (ONLINE/NEARLINE/OFFLINE/LOST) to WLCG locality vocab, emit as <xrd:locality>.
 */
static ngx_int_t
propfind_emit_locality(ngx_http_request_t *r, ngx_chain_t **head,
                        ngx_chain_t **tail, const char *path, struct stat *sb)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_pool_t                        *pool = r->pool;
    brix_vfs_ctx_t                     vctx;
    brix_sd_residency_t                res;
    int                                nearline = 0;
    const char                        *loc = "ONLINE";

    /*
     * xrd:locality — tape residency (phase-64 VFS seam). Emitted only when the
     * client explicitly names the prop (PF_LOCALITY is not in PF_ALL) and only for
     * regular files. Residency comes from the storage backend's model via
     * brix_vfs_residency (no FRM xattr): a plain disk/object export classifies
     * ONLINE, so it needs no nearline tier; on a nearline (tape) export an online
     * object is ONLINE_AND_NEARLINE (resident AND on the backend) and a
     * nearline/offline object is NEARLINE. Values follow the WLCG locality vocab.
     */
    if (S_ISDIR(sb->st_mode)) {
        return NGX_OK; /* Only emit for regular files. */
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
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

    return NGX_OK;
}


/*
 * WHAT: Emit basic metadata properties (resourcetype, contentlength, lastmodified,
 *       etag, creationdate). Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  These five properties are the core DAV metadata set, each derived directly
 *       from stat(2) buffer fields.
 *
 * HOW:  Check each mask bit, emit the corresponding property from sb fields.
 *       resourcetype is <D:collection/> for dirs, empty for files. contentlength
 *       is 0 for dirs, st_size for files. etag/creationdate use helper formatters.
 */
static ngx_int_t
propfind_emit_basic_metadata(ngx_http_request_t *r, ngx_chain_t **head,
                               ngx_chain_t **tail, unsigned mask,
                               struct stat *sb, char *date_buf)
{
    ngx_pool_t *pool = r->pool;

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

    return NGX_OK;
}


/*
 * WHAT: Emit standard DAV properties filtered by mask. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  PROPFIND responses carry different sets of properties depending on the
 *       request type (ALLPROP vs explicit PROP) and the requested prop_mask.
 *       Each standard property (resourcetype, contentlength, etag, etc.) has
 *       its own emission logic and FS dependency.
 *
 * HOW:  Iterate through the 11 standard property types (resourcetype through
 *       locality), checking the mask bit for each. Emit the property's XML
 *       element with its value derived from sb (stat buffer), fs usage, or VFS
 *       residency. The mask ladder is kept inline (not table-driven) because
 *       each property has unique FS logic and different data sources.
 */
static ngx_int_t
propfind_emit_standard_props(ngx_http_request_t *r, ngx_chain_t **head,
                              ngx_chain_t **tail, unsigned mask,
                              const char *href, const char *path,
                              struct stat *sb, char *date_buf)
{
    ngx_pool_t *pool = r->pool;

    /* Emit basic metadata properties (resourcetype, contentlength, etag, etc.). */
    if (propfind_emit_basic_metadata(r, head, tail, mask, sb, date_buf)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (mask & PF_DISPLAYNAME) {
        if (propfind_emit_displayname(r, head, tail, href) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (mask & (PF_QUOTA_AVAILABLE | PF_QUOTA_USED)) {
        if (propfind_emit_quota(r, head, tail, mask, path, sb) != NGX_OK) {
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

    if (mask & PF_LOCALITY) {
        if (propfind_emit_locality(r, head, tail, path, sb) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Resolve and emit dead (client-defined) properties. Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  ALLPROP dumps all stored dead properties; explicit PROP requests resolve
 *       only the unknown (non-DAV:) properties against the xattr store, tracking
 *       hits in unknown_found[] so misses can be reported in a 404 propstat.
 *
 * HOW:  For ALLPROP, call webdav_dead_props_append_all() to dump everything.
 *       For PROP, iterate req->unknown[], skip DAV: namespace unknowns (they're
 *       genuinely unsupported), and call webdav_dead_prop_append_value() for
 *       each non-DAV unknown, recording resolution success in unknown_found[].
 */
static ngx_int_t
propfind_dead_props_resolve_and_emit(ngx_http_request_t *r, ngx_chain_t **head,
                                      ngx_chain_t **tail, const char *path,
                                      const propfind_req_t *req,
                                      ngx_flag_t unknown_found[PF_UNKNOWN_MAX])
{
    ngx_uint_t i;

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

    return NGX_OK;
}

/*
 * WHAT: Emit 404 propstat for missing properties in explicit PROP requests.
 *       Returns NGX_OK or NGX_ERROR.
 *
 * WHY:  RFC 4918 requires PROPFIND to report which explicitly-requested
 *       properties were not found via a 404 propstat. Emitting an empty
 *       404 propstat is invalid; we only emit it when at least one requested
 *       property is genuinely missing.
 *
 * HOW:  Iterate unknown_found[] to detect if any requested properties were
 *       not resolved. If any are missing, emit <D:propstat><D:prop>, iterate
 *       again to emit each missing property's pre-built XML element, then
 *       close with 404 status.
 */
static ngx_int_t
propfind_emit_404_propstat(ngx_http_request_t *r, ngx_chain_t **head,
                            ngx_chain_t **tail, const propfind_req_t *req,
                            const ngx_flag_t unknown_found[PF_UNKNOWN_MAX])
{
    ngx_pool_t *pool = r->pool;
    ngx_uint_t  i;
    ngx_flag_t  any_missing = 0;

    /* For explicit PROP requests: emit 404 propstat for unknown properties.
     * Skip the whole block if every named unknown turned out to exist as a dead
     * property (all resolved above) — emitting an empty 404 propstat is invalid. */
    if (req->type != PROPFIND_PROP || req->unknown_count == 0) {
        return NGX_OK;
    }

    for (i = 0; i < req->unknown_count; i++) {
        if (!unknown_found[i]) {
            any_missing = 1;
            break;
        }
    }

    /* Emit the 404 propstat only when at least one named property is
     * genuinely missing — an empty 404 propstat would be invalid, so when
     * nothing is missing we skip straight to closing the response. */
    if (!any_missing) {
        return NGX_OK;
    }

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

    /* PROPNAME: emit all names as empty elements, then close. */
    if (req->type == PROPFIND_PROPNAME) {
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

    /* Emit standard DAV properties. */
    if (propfind_emit_standard_props(r, head, tail, mask, href, path, sb,
                                      date_buf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Emit ACL-related properties. */
    if (propfind_append_acl_properties(r, head, tail, mask) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Resolve and emit dead (client-defined) properties. */
    if (propfind_dead_props_resolve_and_emit(r, head, tail, path, req,
                                               unknown_found) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(pool, head, tail,
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>") == NULL)
    {
        return NGX_ERROR;
    }

    /* Emit 404 propstat for missing properties in explicit PROP requests. */
    if (propfind_emit_404_propstat(r, head, tail, req, unknown_found)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(pool, head, tail, "</D:response>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
