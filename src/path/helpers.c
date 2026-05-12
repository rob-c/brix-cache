#include "../ngx_xrootd_module.h"

#include "path_internal.h"

static ngx_inline u_char
xrootd_hex_digit(u_char value)
{
    return (value < 10) ? (u_char) ('0' + value)
                        : (u_char) ('A' + (value - 10));
}

int
xrootd_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}

size_t
xrootd_sanitize_log_string(const char *in, char *out, size_t outsz)
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
        out[written++] = (char) xrootd_hex_digit((u_char) (ch >> 4));
        out[written++] = (char) xrootd_hex_digit((u_char) (ch & 0x0f));
    }

    out[written] = '\0';

    return written;
}

ngx_int_t
xrootd_finalize_path_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules, size_t element_size, size_t path_offset,
    size_t resolved_offset, size_t resolved_size)
{
    char        root_canon[PATH_MAX];
    u_char     *elts;
    ngx_uint_t  i;

    if (rules == NULL) {
        return NGX_OK;
    }

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
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

        if (!xrootd_resolve_path_noexist(log, root,
                                         (const char *) path->data,
                                         resolved, resolved_size))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
