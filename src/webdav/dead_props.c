/*
 * dead_props.c - WebDAV dead property persistence.
 *
 * Dead properties are opaque client-owned XML properties.  Store them as
 * user xattrs on the already-resolved resource so they move with the file on
 * local renames and avoid hidden sidecar files in the namespace.
 */

#include "webdav.h"
#include "path/path.h"
#include "fs/vfs.h"
#include "compat/http_xml.h"
#include "compat/namespace_ops.h"

#include <errno.h>
#include <string.h>
#include <sys/xattr.h>
#include "compat/alloc_guard.h"

/*
 * Phase 40: dead-property xattrs (user.nginx_xrootd.webdav.*) must be set / read /
 * listed AS THE MAPPED USER under impersonation — else PROPPATCH setxattr on the
 * user-owned resource fails EACCES from the worker.  Derive the export root from
 * the request and route every xattr op through the VFS xattr surface, which
 * delegates to xrootd_*xattr_confined_canon (broker under map mode; raw
 * path-based syscall otherwise) while adding OP_XATTR metering — confinement and
 * errno behaviour are unchanged.
 */

/*
 * Build a transient VFS ctx for a confined dead-property xattr op on `path`
 * (mirrors the canonical construction in get.c).  The xattr family is not
 * allow_write-gated, so the allow_write flag does not affect set/remove.
 */
static void
webdav_dead_prop_vfs_ctx_init(ngx_http_request_t *r, const char *path,
    xrootd_vfs_ctx_t *vctx)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ngx_http_xrootd_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log,
        XROOTD_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
}

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

/*
 * xattr naming scheme: an xattr key is
 *   "user.nginx_xrootd.webdav." <hex(namespace-URI)> "." <hex(local-name)>
 * Both the XML namespace URI and the local element name are lowercase-hex
 * encoded so that arbitrary URI bytes (':', '/', '.', etc.) survive the
 * "user." flat keyspace, and the single literal '.' separator is unambiguous
 * (real dots inside the URI/name become "2e", never a bare '.').
 * NAME_MAX 255 is the Linux xattr-key limit; VALUE_MAX/LIST_MAX cap how much
 * we will read back so a hostile filesystem cannot force unbounded allocs.
 */
#define WEBDAV_DEAD_PROP_PREFIX      "user.nginx_xrootd.webdav."
#define WEBDAV_DEAD_PROP_PREFIX_LEN  (sizeof(WEBDAV_DEAD_PROP_PREFIX) - 1)
#define WEBDAV_DEAD_PROP_NAME_MAX    255
#define WEBDAV_DEAD_PROP_VALUE_MAX   16384
#define WEBDAV_DEAD_PROP_LIST_MAX    65536

/* Single hex digit -> nibble, or -1 if not a hex character. */
static int
webdav_dead_prop_hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/*
 * Validate that a decoded local name is a safe XML element name before it is
 * spliced back into a PROPFIND response.  This is the injection guard: a name
 * read from an xattr is attacker-influenced, so we restrict it to the XML
 * NameStartChar/NameChar subset (ASCII letters, '_', then also digits, '-',
 * '.') and reject anything else (notably '<', '>', '&', '/', whitespace).
 */
static ngx_flag_t
webdav_dead_prop_xml_name_ok(const char *name)
{
    const unsigned char *p = (const unsigned char *) name;

    if (p == NULL || *p == '\0') {
        return 0;
    }

    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')
          || *p == '_'))
    {
        return 0;
    }

    for (p++; *p != '\0'; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')
            || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'
            || *p == '.')
        {
            continue;
        }
        return 0;
    }

    return 1;
}

/*
 * Encode (namespace URI, local name) into the flat xattr key documented above:
 * PREFIX + hex(ns) + '.' + hex(local).  Writes a NUL-terminated string into
 * out[0..outsz).  Every append is bounds-checked against `left` and returns
 * NGX_ERROR (caller maps to ENAMETOOLONG) rather than truncating, since a
 * truncated key would silently collide with a different property.
 */
static ngx_int_t
webdav_dead_prop_attr_name(const char *ns, const char *local,
    char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p;
    char                *d = out;
    size_t               left = outsz;
    size_t               n;

    /* Prefix is fixed-length and always written first. */
    n = WEBDAV_DEAD_PROP_PREFIX_LEN;
    if (left <= n) {
        return NGX_ERROR;
    }
    ngx_memcpy(d, WEBDAV_DEAD_PROP_PREFIX, n);
    d += n;
    left -= n;

    /* hex(namespace): two output bytes per source byte; need >2 left so a
     * trailing '.' and NUL still fit. */
    for (p = (const unsigned char *) ns; p != NULL && *p != '\0'; p++) {
        if (left <= 2) {
            return NGX_ERROR;
        }
        *d++ = hex[*p >> 4];
        *d++ = hex[*p & 0x0f];
        left -= 2;
    }

    if (left <= 1) {
        return NGX_ERROR;
    }
    *d++ = '.';   /* the one literal separator; source dots are hex "2e" */
    left--;

    /* hex(local name) */
    for (p = (const unsigned char *) local; p != NULL && *p != '\0'; p++) {
        if (left <= 2) {
            return NGX_ERROR;
        }
        *d++ = hex[*p >> 4];
        *d++ = hex[*p & 0x0f];
        left -= 2;
    }

    if (left == 0) {
        return NGX_ERROR;
    }
    *d = '\0';
    return NGX_OK;
}

/*
 * Inverse of the hex encoder: decode `len` hex chars into len/2 raw bytes plus
 * a NUL.  Returns NULL on odd length or any non-hex digit (a corrupted/foreign
 * xattr key), which the caller treats as "not one of ours" rather than fatal.
 */
static char *
webdav_dead_prop_decode_hex(ngx_pool_t *pool, const char *hex, size_t len)
{
    char   *out;
    size_t  i;

    if ((len & 1) != 0) {     /* hex always comes in pairs */
        return NULL;
    }

    XROOTD_PNALLOC_OR_RETURN(out, pool, len / 2 + 1, NULL);

    for (i = 0; i < len; i += 2) {
        int hi = webdav_dead_prop_hexval(hex[i]);
        int lo = webdav_dead_prop_hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return NULL;
        }
        out[i / 2] = (char) ((hi << 4) | lo);
    }
    out[len / 2] = '\0';
    return out;
}

/*
 * Parse one listxattr entry back into (namespace, local name).
 * Returns NGX_DECLINED for any key that is not a well-formed dead-property key
 * (wrong prefix, no '.' separator, bad hex, or a local name that fails the XML
 * safety check) so the caller can skip foreign xattrs silently.
 */
static ngx_int_t
webdav_dead_prop_decode_attr(ngx_pool_t *pool, const char *attr,
    char **ns_out, char **local_out)
{
    const char *payload;
    const char *dot;

    if (ngx_strncmp(attr, WEBDAV_DEAD_PROP_PREFIX,
                   WEBDAV_DEAD_PROP_PREFIX_LEN) != 0)
    {
        return NGX_DECLINED;
    }

    payload = attr + WEBDAV_DEAD_PROP_PREFIX_LEN;
    dot = strchr(payload, '.');
    if (dot == NULL) {
        return NGX_DECLINED;
    }

    *ns_out = webdav_dead_prop_decode_hex(pool, payload,
                                          (size_t) (dot - payload));
    *local_out = webdav_dead_prop_decode_hex(pool, dot + 1, strlen(dot + 1));
    if (*ns_out == NULL || *local_out == NULL
        || !webdav_dead_prop_xml_name_ok(*local_out))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/*
 * WHAT: Report whether a DAV:-namespace property is server-managed (protected).
 * WHY:  PROPPATCH must reject attempts to set/remove live DAV: properties
 *       (getetag, getcontentlength, ...).  Any property in the DAV: namespace
 *       is treated as protected here, so the predicate is "is this a DAV: prop"
 *       and `local != NULL` is just a defensive non-NULL guard — the caller
 *       only invokes this once it has already matched the DAV: namespace.
 */
ngx_flag_t
webdav_dead_prop_is_protected_dav(const char *local)
{
    return local != NULL ? 1 : 0;
}

/*
 * Emit an empty self-closing element for one property name (used by PROPFIND
 * propname, which lists names without values).  The serialized form depends on
 * the namespace: DAV: -> <D:name/>; no namespace -> <name/>; any other URI ->
 * <X:name xmlns:X="..."/> with the (escaped) URI bound to a local "X" prefix.
 * The local name is re-validated here so a stored-but-now-suspect key cannot
 * inject markup; the namespace URI is XML-escaped before interpolation.
 */
ngx_int_t
webdav_dead_prop_append_empty(ngx_http_request_t *r, const char *ns,
    const char *local, ngx_chain_t **head, ngx_chain_t **tail)
{
    char *safe_ns;

    if (!webdav_dead_prop_xml_name_ok(local)) {
        return NGX_ERROR;
    }

    if (ns != NULL && strcmp(ns, "DAV:") == 0) {
        return xrootd_http_chain_appendf(r->pool, head, tail,
                                         "<D:%s/>", local) == NULL
               ? NGX_ERROR : NGX_OK;
    }

    if (ns == NULL || ns[0] == '\0') {
        return xrootd_http_chain_appendf(r->pool, head, tail,
                                         "<%s/>", local) == NULL
               ? NGX_ERROR : NGX_OK;
    }

    safe_ns = webdav_escape_xml_text(r->pool, ns);
    if (safe_ns == NULL) {
        return NGX_ERROR;
    }

    return xrootd_http_chain_appendf(r->pool, head, tail,
                                     "<X:%s xmlns:X=\"%s\"/>",
                                     local, safe_ns) == NULL
           ? NGX_ERROR : NGX_OK;
}

/*
 * PROPPATCH set: store the property's raw XML value as the xattr value.
 * The stored bytes are echoed verbatim on read, so the caller is responsible
 * for having serialized well-formed, already-escaped XML.  Oversized values
 * are rejected up front (ENAMETOOLONG) to keep read-back bounded.
 */
ngx_int_t
webdav_dead_prop_set(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, const char *xml, size_t xml_len)
{
    char             attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];
    xrootd_vfs_ctx_t vctx;

    if (xml_len > WEBDAV_DEAD_PROP_VALUE_MAX
        || webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK)
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    webdav_dead_prop_vfs_ctx_init(r, path, &vctx);

    if (xrootd_vfs_setxattr(&vctx, attr, xml, xml_len, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                      "xrootd_webdav: setxattr dead property failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * PROPPATCH remove: delete the property's xattr.  Removing a property that does
 * not exist is success (idempotent) — ENODATA/ENOATTR are swallowed; any other
 * errno is a real failure.
 */
ngx_int_t
webdav_dead_prop_remove(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local)
{
    char             attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];
    xrootd_vfs_ctx_t vctx;

    if (webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    webdav_dead_prop_vfs_ctx_init(r, path, &vctx);

    /* "not present" == already removed, so treat ENODATA/ENOATTR as success. */
    if (xrootd_vfs_removexattr(&vctx, attr) != NGX_OK
        && errno != ENODATA && errno != ENOATTR)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                      "xrootd_webdav: removexattr dead property failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * PROPFIND (with values): if the named dead property exists, append its stored
 * XML fragment to the response chain and set *found.  A missing property is not
 * an error: *found stays 0 and NGX_OK is returned so the caller can report it as
 * 404 inside the multistatus.  Returns NGX_ERROR only on a real fault.
 *
 * Two getxattr calls are intentional (size probe, then read).  The first gets
 * the length so we can size the alloc; the value is capped at VALUE_MAX so the
 * probe cannot drive an unbounded allocation.
 */
ngx_int_t
webdav_dead_prop_append_value(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, ngx_chain_t **head,
    ngx_chain_t **tail, ngx_flag_t *found)
{
    char             attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];
    xrootd_vfs_ctx_t vctx;
    char            *value;
    ssize_t          len;

    *found = 0;

    if (webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK) {
        return NGX_OK;
    }

    webdav_dead_prop_vfs_ctx_init(r, path, &vctx);

    /* Probe length first (buf=NULL, size=0). */
    len = xrootd_vfs_getxattr(&vctx, attr, NULL, 0);
    if (len < 0) {
        if (errno == ENODATA || errno == ENOATTR) {
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    if (len > WEBDAV_DEAD_PROP_VALUE_MAX) {
        return NGX_ERROR;
    }

    XROOTD_PNALLOC_OR_RETURN(value, r->pool, (size_t) len + 1, NGX_ERROR);

    /* Second read fetches the actual bytes; a concurrent shrink is fine since
     * we re-read the returned length, a concurrent grow is bounded by the buf. */
    len = xrootd_vfs_getxattr(&vctx, attr, value, (size_t) len);
    if (len < 0) {
        return NGX_ERROR;
    }
    value[len] = '\0';

    if (xrootd_http_chain_appendf(r->pool, head, tail, "%s", value) == NULL) {
        return NGX_ERROR;
    }

    *found = 1;
    return NGX_OK;
}

/*
 * PROPFIND allprop / propname: enumerate every dead property on `path` and
 * append each one to the response chain.  listxattr returns all xattr keys as a
 * single NUL-separated blob; we walk it, decode the dead-property keys (skipping
 * any foreign xattr), and emit either just the name (names_only, for propname)
 * or the name+value (for allprop).  A node with no xattrs (len<=0) is normal.
 */
ngx_int_t
webdav_dead_props_append_all(ngx_http_request_t *r, const char *path,
    ngx_chain_t **head, ngx_chain_t **tail, ngx_flag_t names_only)
{
    xrootd_vfs_ctx_t vctx;
    char            *list;
    ssize_t          len;
    char            *p;

    webdav_dead_prop_vfs_ctx_init(r, path, &vctx);

    /* Probe the size of the NUL-separated key list. */
    len = xrootd_vfs_listxattr(&vctx, NULL, 0);
    if (len <= 0) {
        return NGX_OK;
    }

    if (len > WEBDAV_DEAD_PROP_LIST_MAX) {
        return NGX_OK;
    }

    XROOTD_PNALLOC_OR_RETURN(list, r->pool, (size_t) len, NGX_ERROR);

    len = xrootd_vfs_listxattr(&vctx, list, (size_t) len);
    if (len <= 0) {
        return NGX_OK;
    }

    /* Each key is NUL-terminated; advance past the terminator to the next. */
    for (p = list; p < list + len; p += strlen(p) + 1) {
        char *ns = NULL;
        char *local = NULL;

        /* Skip xattrs that are not our dead properties (other "user.*", etc.). */
        if (webdav_dead_prop_decode_attr(r->pool, p, &ns, &local) != NGX_OK) {
            continue;
        }

        if (names_only) {
            if (webdav_dead_prop_append_empty(r, ns, local, head, tail)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        } else {
            ngx_flag_t found;
            if (webdav_dead_prop_append_value(r, path, ns, local, head, tail,
                                              &found) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

/*
 * Copy all dead properties from src to dst (used by COPY/MOVE so client
 * properties travel with the resource).  Delegates to the shared xattr copier,
 * which only transfers keys under our prefix and skips values over VALUE_MAX.
 */
void
webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst)
{
    xrootd_xattr_copy_by_prefix(log, src, dst,
        WEBDAV_DEAD_PROP_PREFIX, WEBDAV_DEAD_PROP_PREFIX_LEN,
        WEBDAV_DEAD_PROP_VALUE_MAX);
}
