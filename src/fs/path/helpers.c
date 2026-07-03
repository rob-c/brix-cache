#include "core/ngx_brix_module.h"

#include "core/compat/hex.h"
#include "path_internal.h"

// Check if a path component name is forbidden by filesystem security rules.
// Returns true for "." and ".." components that enable directory traversal attacks.
/* Return 1 if a path component is "." or ".." (forbidden in a resolved path). */
int
brix_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}
/* Return 1 if `path` contains a ".." component (traversal attempt). */
int
brix_path_has_dotdot(const char *path)
{
    const char *p = path;

    if (path == NULL) {
        return 0;
    }
    while (*p != '\0') {
        const char *seg;
        size_t      seg_len;

        while (*p == '/') {
            p++;
        }
        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        seg_len = (size_t) (p - seg);
        if (seg_len == 2 && seg[0] == '.' && seg[1] == '.') {
            return 1;
        }
    }
    return 0;
}

/* Copy in -> out, escaping control bytes, quotes, backslashes and non-ASCII to
 * \xNN, so a wire string is safe to write to the access log. */
size_t
brix_sanitize_log_string(const char *in, char *out, size_t outsz)
{
    const u_char *src;
    size_t        written;
    u_char        ch;

    if (out == NULL || outsz == 0) {
        return 0;
    }

    src = (const u_char *) ((in != NULL) ? in : "-");
    written = 0;

    while (*src != '\0' && written + 1 < outsz) {
        ch = *src++;

        if (ch >= 0x21 && ch <= 0x7e && ch != '"' && ch != '\\') {
            out[written++] = (char) ch;
            continue;
        }

        if (written + 4 >= outsz) {
            break;
        }

        out[written++] = '\\';
        out[written++] = 'x';
        out[written++] = (char) brix_hex_nibble((u_char) (ch >> 4));
        out[written++] = (char) brix_hex_nibble((u_char) (ch & 0x0f));
    }

    out[written] = '\0';

    return written;
}

// Count path components by iterating through '/' separators — O(n) string scan.
// Returns NGX_ERROR if component count exceeds BRIX_MAX_WALK_DEPTH (32);
// returns NGX_OK otherwise. Leading slashes skipped; trailing empty
// components do not increment depth.
/* Return the number of (non-empty, slash-separated) components in `path`. */
ngx_int_t
brix_count_path_depth(const char *path)
{
    const char  *p = path;
    ngx_uint_t   count;

    while (*p == '/') {
        p++;
    }

    if (*p == '\0') {
        return NGX_OK;
    }

    count = 1;
    while (*p) {
        if (*p == '/') {
            p++;
            if (*p != '\0') {
                count++;
            }
        } else {
            p++;
        }
    }

    return (count > BRIX_MAX_WALK_DEPTH) ? NGX_ERROR : NGX_OK;
}
/* Generic postconfig finalizer: resolve the path field (at path_offset, with
 * element_size stride) of each rule-array entry against the export root. */
ngx_int_t
brix_finalize_path_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules, size_t element_size, size_t path_offset,
    size_t resolved_offset, size_t resolved_size)
{
    char        root_canon[PATH_MAX];
    u_char     *elts;
    ngx_uint_t  i;

    if (rules == NULL) {
        return NGX_OK;
    }

    if (!brix_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return NGX_ERROR;
    }

    elts = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        ngx_str_t  *path;
        char       *resolved;

        path = (ngx_str_t *) (elts + i * element_size + path_offset);
        resolved = (char *) (elts + i * element_size + resolved_offset);

        if (path->len == 1 && path->data[0] == '/') {
            ngx_cpystrn((u_char *) resolved, (u_char *) root_canon,
                        resolved_size);
            continue;
        }

        /*
         * Config-time only, and deliberately NOT migrated to the beneath API.
         * This canonicalises a TRUSTED, admin-configured VO/group policy rule
         * path once at startup (not a client request path), so realpath(3) is
         * the right tool: it resolves the rule to its absolute form for later
         * prefix matching against resolved request paths.  There is no rootfd at
         * config-parse time and no untrusted input here, so openat2
         * RESOLVE_BENEATH would add nothing.
         */
        if (!brix_resolve_path_noexist(log, root,
                                         (const char *) path->data,
                                         resolved, resolved_size))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
