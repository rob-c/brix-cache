/*
 * path.c - URI decoding, path confinement, safe logging, and XML escaping.
 */

#include "webdav.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * webdav_resolve_destination_path — resolve a decoded Destination header path
 * within the export root.
 *
 * Called by COPY and MOVE handlers after stripping the scheme://authority
 * prefix from the Destination URL and URL-decoding the path component.
 *
 * Because realpath(3) requires the target to exist, a non-existent
 * destination is handled by resolving its parent directory and appending the
 * final filename — the same strategy used for PUT/MKCOL targets.
 *
 * op_label is used in log messages to identify the calling operation
 * ("COPY" or "MOVE").
 *
 * Returns: NGX_OK on success; an NGX_HTTP_* error code otherwise.
 */
ngx_int_t
webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    char   candidate[PATH_MAX];
    char   resolved[PATH_MAX];
    size_t dlen;
    size_t root_len;

    /* Strip trailing slashes from destination */
    dlen = strlen(decoded_path);
    while (dlen > 1 && decoded_path[dlen - 1] == '/') {
        dlen--;
    }

    if ((size_t) snprintf(candidate, sizeof(candidate), "%.*s%.*s",
                          (int) strlen(root_canon), root_canon,
                          (int) dlen, decoded_path)
        >= sizeof(candidate))
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    if (realpath(candidate, resolved) == NULL) {
        if (errno == ENOENT) {
            char   parent[PATH_MAX];
            char   parent_canon[PATH_MAX];
            char   filename[NAME_MAX + 1];
            char  *slash;
            size_t parent_len;
            size_t fname_len;

            slash = strrchr(candidate, '/');
            if (slash == NULL) {
                return NGX_HTTP_BAD_REQUEST;
            }

            parent_len = (size_t) (slash - candidate);
            if (parent_len >= sizeof(parent)) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
            memcpy(parent, candidate, parent_len);
            parent[parent_len] = '\0';

            fname_len = strlen(slash + 1);
            if (fname_len == 0 || fname_len >= sizeof(filename)) {
                return NGX_HTTP_BAD_REQUEST;
            }
            memcpy(filename, slash + 1, fname_len + 1);

            if (realpath(parent, parent_canon) == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, errno,
                              "xrootd_webdav %s: cannot resolve destination parent",
                              op_label);
                return NGX_HTTP_CONFLICT;
            }

            root_len = strlen(root_canon);
            if (strncmp(parent_canon, root_canon, root_len) != 0
                || (parent_canon[root_len] != '\0'
                    && parent_canon[root_len] != '/'))
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_webdav %s: destination parent outside root",
                              op_label);
                return NGX_HTTP_FORBIDDEN;
            }

            if ((size_t) snprintf(resolved, sizeof(resolved), "%s/%s",
                                  parent_canon, filename)
                >= sizeof(resolved))
            {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "xrootd_webdav %s: cannot resolve destination",
                          op_label);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    root_len = strlen(root_canon);
    if (strncmp(resolved, root_canon, root_len) != 0
        || (resolved[root_len] != '\0' && resolved[root_len] != '/'))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav %s: destination traversal blocked",
                      op_label);
        return NGX_HTTP_FORBIDDEN;
    }

    {
        size_t rlen = strlen(resolved);
        if (rlen >= outsz) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        memcpy(out, resolved, rlen + 1);
    }

    return NGX_OK;
}

static ngx_int_t
webdav_hex_value(u_char ch, u_char *value)
{
    if (ch >= '0' && ch <= '9') {
        *value = (u_char) (ch - '0');
        return NGX_OK;
    }

    if (ch >= 'a' && ch <= 'f') {
        *value = (u_char) (ch - 'a' + 10);
        return NGX_OK;
    }

    if (ch >= 'A' && ch <= 'F') {
        *value = (u_char) (ch - 'A' + 10);
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_inline u_char
webdav_hex_digit(u_char value)
{
    return (value < 10) ? (u_char) ('0' + value)
                        : (u_char) ('A' + (value - 10));
}

void
ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
                                     ngx_err_t err, const char *prefix,
                                     const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(level, log, err, "%s: \"%s\"", prefix, safe_path);
}

static int
webdav_path_within_root(const char *root_canon, const char *path_canon)
{
    size_t root_len = strlen(root_canon);

    if (strncmp(path_canon, root_canon, root_len) != 0) {
        return 0;
    }

    return path_canon[root_len] == '\0' || path_canon[root_len] == '/';
}

static int
webdav_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}

static int
webdav_path_has_forbidden_components(const char *path)
{
    const char *scan = path;

    while (*scan == '/') {
        scan++;
    }

    while (*scan != '\0') {
        const char *seg_end;
        size_t      seg_len;

        while (*scan == '/') {
            scan++;
        }
        if (*scan == '\0') {
            break;
        }

        seg_end = strchr(scan, '/');
        seg_len = seg_end ? (size_t) (seg_end - scan) : strlen(scan);

        if (webdav_path_component_forbidden(scan, seg_len)) {
            return 1;
        }

        if (seg_end == NULL) {
            break;
        }

        scan = seg_end + 1;
    }

    return 0;
}

/*
 * webdav_urldecode — decode a percent-encoded URI into a plain C string.
 *
 * Only well-formed percent-escapes (%HH where HH are valid hex digits) are
 * decoded.  A literal '%' with malformed or absent hex digits is preserved
 * verbatim (lenient decoding, matching nginx's own URI handling).
 *
 * Decoded NUL bytes (%00) are rejected because all downstream path APIs
 * (realpath, open, stat) are C-string based and would interpret a NUL as
 * the path terminator, potentially hiding suffix components.
 *
 * Preconditions: dst_sz >= 2 (at minimum, one decoded byte + NUL).
 * Postconditions on NGX_OK: dst is NUL-terminated; strlen(dst) < dst_sz.
 * Returns: NGX_OK, NGX_HTTP_REQUEST_URI_TOO_LARGE, or NGX_HTTP_BAD_REQUEST.
 */
ngx_int_t
webdav_urldecode(const u_char *src, size_t src_len, char *dst, size_t dst_sz)
{
    size_t src_index = 0;
    size_t dst_index = 0;
    u_char hi;
    u_char lo;
    u_char decoded;

    if (dst == NULL || dst_sz < 2) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Decode only well-formed percent escapes.  A literal '%' with missing or
     * invalid hex digits is preserved so nginx's URI handling remains lenient,
     * but decoded NUL is rejected because downstream path APIs are C strings.
     */
    while (src_index < src_len) {
        if (dst_index + 1 >= dst_sz) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }

        if (src[src_index] == '%' && src_index + 2 < src_len
            && webdav_hex_value(src[src_index + 1], &hi) == NGX_OK
            && webdav_hex_value(src[src_index + 2], &lo) == NGX_OK)
        {
            decoded = (u_char) ((hi << 4) | lo);
            if (decoded == '\0') {
                return NGX_HTTP_BAD_REQUEST;
            }

            dst[dst_index++] = (char) decoded;
            src_index += 3;
            continue;
        }

        dst[dst_index++] = (char) src[src_index++];
    }

    dst[dst_index] = '\0';
    return NGX_OK;
}

/*
 * webdav_escape_xml_text — escape a string for safe inclusion in XML text.
 *
 * Escapes &, <, >, ", and '.  Control characters (< 0x20 or 0x7f) are
 * percent-encoded as %XX to prevent XML parser confusion.
 *
 * Pool allocation: the result is ngx_pnalloc(pool, src_len * 6 + 1) —
 *   worst case is every byte needing a 6-char escape like "&quot;".
 *   Lifetime matches pool (r->pool → request lifetime).
 *
 * Returns: escaped NUL-terminated string, or NULL on OOM.
 */
char *
webdav_escape_xml_text(ngx_pool_t *pool, const char *src)
{
    const u_char *in;
    u_char       *out;
    u_char       *escaped;
    size_t        src_len;

    if (pool == NULL || src == NULL) {
        return NULL;
    }

    src_len = strlen(src);
    escaped = ngx_pnalloc(pool, src_len * 6 + 1);
    if (escaped == NULL) {
        return NULL;
    }

    in = (const u_char *) src;
    out = escaped;

    while (*in != '\0') {
        switch (*in) {
        case '&':
            out = ngx_cpymem(out, "&amp;", sizeof("&amp;") - 1);
            break;
        case '<':
            out = ngx_cpymem(out, "&lt;", sizeof("&lt;") - 1);
            break;
        case '>':
            out = ngx_cpymem(out, "&gt;", sizeof("&gt;") - 1);
            break;
        case '"':
            out = ngx_cpymem(out, "&quot;", sizeof("&quot;") - 1);
            break;
        case '\'':
            out = ngx_cpymem(out, "&#39;", sizeof("&#39;") - 1);
            break;
        default:
            if (*in < 0x20 || *in == 0x7f) {
                *out++ = '%';
                *out++ = webdav_hex_digit((u_char) (*in >> 4));
                *out++ = webdav_hex_digit((u_char) (*in & 0x0f));
            } else {
                *out++ = *in;
            }
            break;
        }

        in++;
    }

    *out = '\0';
    return (char *) escaped;
}

/*
 * ngx_http_xrootd_webdav_resolve_path — URL-decode r->uri and canonicalise
 * it to a filesystem path within root_canon.
 *
 * Security invariants enforced:
 *   1. Decoded NUL (%00) is rejected.
 *   2. "." and ".." path components are rejected before realpath.
 *   3. realpath(3) requires existence: if the final component does not exist
 *      (ENOENT), the parent is canonicalised and the filename appended only
 *      after confirming the parent is within root_canon.
 *      This handles PUT/MKCOL targets that do not yet exist.
 *   4. The resolved path is re-checked against root_canon after realpath to
 *      catch any symlink escape that was not caught by step 2.
 *
 * Pool allocation: uses no pool allocation — out[] is caller-supplied storage.
 *
 * Returns: NGX_OK on success; an NGX_HTTP_* code on failure.
 */
ngx_int_t
ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
                                    const char *root_canon,
                                    char *out, size_t outsz)
{
    char      uri_decoded[WEBDAV_MAX_PATH];
    char      candidate_path[PATH_MAX];
    char      resolved[PATH_MAX];
    ngx_int_t rc;

    rc = webdav_urldecode(r->uri.data, r->uri.len,
                          uri_decoded, sizeof(uri_decoded));
    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_BAD_REQUEST) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: rejecting URI with decoded NUL");
        }
        return rc;
    }

    {
        size_t uri_dlen = strlen(uri_decoded);

        while (uri_dlen > 1 && uri_decoded[uri_dlen - 1] == '/') {
            uri_decoded[--uri_dlen] = '\0';
        }
    }

    if (webdav_path_has_forbidden_components(uri_decoded)) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_WARN, 0,
                                             "xrootd_webdav: path traversal attempt",
                                             uri_decoded);
        return NGX_HTTP_FORBIDDEN;
    }

    /*
     * Resolve existing paths through realpath().  For PUT/MKCOL destinations
     * that do not exist yet, resolve the parent and append the final filename
     * only after proving that the parent stayed under root_canon.
     */
    if ((size_t) snprintf(candidate_path, sizeof(candidate_path), "%s%s",
                          root_canon, uri_decoded)
        >= sizeof(candidate_path))
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    if (realpath(candidate_path, resolved) == NULL) {
        if (errno == ENOENT) {
            char  parent[PATH_MAX];
            char  parent_canon[PATH_MAX];
            char  filename[NAME_MAX + 1];
            char *slash;
            size_t parent_len;
            size_t fname_len;

            slash = strrchr(candidate_path, '/');
            if (slash == NULL) {
                return NGX_HTTP_BAD_REQUEST;
            }

            parent_len = (size_t) (slash - candidate_path);
            if (parent_len >= sizeof(parent)) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
            ngx_memcpy(parent, candidate_path, parent_len);
            parent[parent_len] = '\0';

            fname_len = strlen(slash + 1);
            if (fname_len == 0 || fname_len >= sizeof(filename)) {
                return NGX_HTTP_BAD_REQUEST;
            }
            ngx_memcpy(filename, slash + 1, fname_len + 1);

            if (realpath(parent, parent_canon) == NULL) {
                ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                     NGX_LOG_WARN, errno,
                                                     "xrootd_webdav: cannot resolve parent of",
                                                     candidate_path);
                return NGX_HTTP_NOT_FOUND;
            }

            if (!webdav_path_within_root(root_canon, parent_canon)) {
                ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                     NGX_LOG_WARN, 0,
                                                     "xrootd_webdav: path traversal blocked",
                                                     parent_canon);
                return NGX_HTTP_FORBIDDEN;
            }

            if ((size_t) snprintf(resolved, sizeof(resolved), "%s/%s",
                                  parent_canon, filename)
                >= sizeof(resolved))
            {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
        } else {
            ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                 NGX_LOG_WARN, errno,
                                                 "xrootd_webdav: cannot resolve",
                                                 candidate_path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (!webdav_path_within_root(root_canon, resolved)) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_WARN, 0,
                                             "xrootd_webdav: path traversal blocked",
                                             resolved);
        return NGX_HTTP_FORBIDDEN;
    }

    {
        size_t rlen = strlen(resolved);

        if (rlen >= outsz) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        ngx_memcpy(out, resolved, rlen + 1);
    }

    return NGX_OK;
}
