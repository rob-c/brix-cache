/*
 * dead_props.c - WebDAV dead property persistence.
 *
 * Dead properties are opaque client-owned XML properties.  Store them as
 * user xattrs on the already-resolved resource so they move with the file on
 * local renames and avoid hidden sidecar files in the namespace.
 */

#include "webdav.h"
#include "../compat/http_xml.h"

#include <errno.h>
#include <string.h>
#include <sys/xattr.h>

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#define WEBDAV_DEAD_PROP_PREFIX      "user.nginx_xrootd.webdav."
#define WEBDAV_DEAD_PROP_PREFIX_LEN  (sizeof(WEBDAV_DEAD_PROP_PREFIX) - 1)
#define WEBDAV_DEAD_PROP_NAME_MAX    255
#define WEBDAV_DEAD_PROP_VALUE_MAX   16384
#define WEBDAV_DEAD_PROP_LIST_MAX    65536

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

static ngx_int_t
webdav_dead_prop_attr_name(const char *ns, const char *local,
    char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p;
    char                *d = out;
    size_t               left = outsz;
    size_t               n;

    n = WEBDAV_DEAD_PROP_PREFIX_LEN;
    if (left <= n) {
        return NGX_ERROR;
    }
    ngx_memcpy(d, WEBDAV_DEAD_PROP_PREFIX, n);
    d += n;
    left -= n;

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
    *d++ = '.';
    left--;

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

static char *
webdav_dead_prop_decode_hex(ngx_pool_t *pool, const char *hex, size_t len)
{
    char   *out;
    size_t  i;

    if ((len & 1) != 0) {
        return NULL;
    }

    out = ngx_pnalloc(pool, len / 2 + 1);
    if (out == NULL) {
        return NULL;
    }

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

ngx_flag_t
webdav_dead_prop_is_protected_dav(const char *local)
{
    return local != NULL ? 1 : 0;
}

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

ngx_int_t
webdav_dead_prop_set(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, const char *xml, size_t xml_len)
{
    char attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];

    if (xml_len > WEBDAV_DEAD_PROP_VALUE_MAX
        || webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK)
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (setxattr(path, attr, xml, xml_len, 0) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                      "xrootd_webdav: setxattr dead property failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
webdav_dead_prop_remove(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local)
{
    char attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];

    if (webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (removexattr(path, attr) != 0 && errno != ENODATA && errno != ENOATTR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                      "xrootd_webdav: removexattr dead property failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
webdav_dead_prop_append_value(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, ngx_chain_t **head,
    ngx_chain_t **tail, ngx_flag_t *found)
{
    char    attr[WEBDAV_DEAD_PROP_NAME_MAX + 1];
    char   *value;
    ssize_t len;

    *found = 0;

    if (webdav_dead_prop_attr_name(ns, local, attr, sizeof(attr)) != NGX_OK) {
        return NGX_OK;
    }

    len = getxattr(path, attr, NULL, 0);
    if (len < 0) {
        if (errno == ENODATA || errno == ENOATTR) {
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    if (len > WEBDAV_DEAD_PROP_VALUE_MAX) {
        return NGX_ERROR;
    }

    value = ngx_pnalloc(r->pool, (size_t) len + 1);
    if (value == NULL) {
        return NGX_ERROR;
    }

    len = getxattr(path, attr, value, (size_t) len);
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

ngx_int_t
webdav_dead_props_append_all(ngx_http_request_t *r, const char *path,
    ngx_chain_t **head, ngx_chain_t **tail, ngx_flag_t names_only)
{
    char    *list;
    ssize_t  len;
    char    *p;

    len = listxattr(path, NULL, 0);
    if (len <= 0) {
        return NGX_OK;
    }

    if (len > WEBDAV_DEAD_PROP_LIST_MAX) {
        return NGX_OK;
    }

    list = ngx_pnalloc(r->pool, (size_t) len);
    if (list == NULL) {
        return NGX_ERROR;
    }

    len = listxattr(path, list, (size_t) len);
    if (len <= 0) {
        return NGX_OK;
    }

    for (p = list; p < list + len; p += strlen(p) + 1) {
        char *ns = NULL;
        char *local = NULL;

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

void
webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst)
{
    char    *list;
    char    *p;
    ssize_t  len, vlen;
    u_char   value[WEBDAV_DEAD_PROP_VALUE_MAX];

    len = listxattr(src, NULL, 0);
    if (len <= 0 || len > WEBDAV_DEAD_PROP_LIST_MAX) {
        return;
    }

    list = ngx_alloc((size_t) len, log);
    if (list == NULL) {
        return;
    }

    len = listxattr(src, list, (size_t) len);
    if (len <= 0) {
        ngx_free(list);
        return;
    }

    for (p = list; p < list + len; p += strlen(p) + 1) {
        if (ngx_strncmp(p, WEBDAV_DEAD_PROP_PREFIX,
                        WEBDAV_DEAD_PROP_PREFIX_LEN) != 0)
        {
            continue;
        }

        vlen = getxattr(src, p, value, sizeof(value));
        if (vlen > 0) {
            (void) setxattr(dst, p, value, (size_t) vlen, 0);
        }
    }

    ngx_free(list);
}
