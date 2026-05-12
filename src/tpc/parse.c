#include "tpc_internal.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

static int
tpc_copy_component(char *dst, size_t dst_size, const char *start,
    const char *end)
{
    size_t length;

    length = (size_t) (end - start);
    if (length == 0 || length >= dst_size) {
        return -1;
    }

    memcpy(dst, start, length);
    dst[length] = '\0';

    return 0;
}


static int
tpc_parse_port_range(const char *port_start, const char *port_end,
    uint16_t *port)
{
    char   port_text[16];
    char  *parse_end;
    long   parsed_port;
    size_t port_len;

    port_len = (size_t) (port_end - port_start);
    if (port_len == 0 || port_len >= sizeof(port_text)) {
        return -1;
    }

    memcpy(port_text, port_start, port_len);
    port_text[port_len] = '\0';

    errno = 0;
    parsed_port = strtol(port_text, &parse_end, 10);
    if (errno != 0 || parse_end == port_text
        || parsed_port < 1 || parsed_port > 65535)
    {
        return -1;
    }

    *port = (uint16_t) parsed_port;
    return 0;
}


static int
tpc_copy_src_path(char *path, size_t path_size, const char *path_start)
{
    size_t path_len;

    if (path_start == NULL || *path_start == '\0') {
        path[0] = '\0';
        return 0;
    }

    while (path_start[0] == '/' && path_start[1] == '/') {
        path_start++;
    }

    path_len = strlen(path_start);
    if (path_len + (path_start[0] == '/' ? 0 : 1) >= path_size) {
        return -1;
    }

    if (path_start[0] == '/') {
        memcpy(path, path_start, path_len + 1);
    } else {
        path[0] = '/';
        memcpy(path + 1, path_start, path_len + 1);
    }

    return 0;
}


/*
 * Parse a TPC source endpoint.
 *
 * XrdCl may send a full URL (root://host//path or xroot://host/path) or the
 * native TPC CGI form where tpc.src is only host[:port] and tpc.lfn carries
 * the logical source file name.
 */
static int
tpc_parse_src_spec(const char *src, char *host, size_t host_size,
    uint16_t *port, char *path, size_t path_size)
{
    const char *authority_start;
    const char *authority_end;
    const char *port_separator;
    const char *path_start;
    const char *scheme_separator;
    const char *src_end;

    if (src == NULL || *src == '\0') {
        return -1;
    }

    src_end = src + strlen(src);
    scheme_separator = strstr(src, "://");
    if (scheme_separator != NULL) {
        authority_start = scheme_separator + 3;
        authority_end = memchr(authority_start, '/',
                               (size_t) (src_end - authority_start));
        path_start = authority_end;
        if (authority_end == NULL) {
            authority_end = src_end;
            path_start = NULL;
        }
    } else {
        authority_start = src;
        authority_end = src_end;
        path_start = NULL;
    }

    if (authority_start == authority_end) {
        return -1;
    }

    if (*authority_start == '[') {
        const char *bracket_end;

        bracket_end = memchr(authority_start, ']',
                             (size_t) (authority_end - authority_start));
        if (bracket_end == NULL) {
            return -1;
        }

        if (tpc_copy_component(host, host_size, authority_start + 1,
                               bracket_end) != 0) {
            return -1;
        }

        if (bracket_end + 1 < authority_end) {
            if (bracket_end[1] != ':'
                || tpc_parse_port_range(bracket_end + 2, authority_end,
                                        port) != 0) {
                return -1;
            }
        } else {
            *port = 0;
        }

    } else {
        port_separator = memchr(authority_start, ':',
                                (size_t) (authority_end - authority_start));
        if (port_separator != NULL) {
            if (tpc_copy_component(host, host_size, authority_start,
                                   port_separator) != 0) {
                return -1;
            }
            if (tpc_parse_port_range(port_separator + 1, authority_end,
                                     port) != 0) {
                return -1;
            }
        } else {
            if (tpc_copy_component(host, host_size, authority_start,
                                   authority_end) != 0) {
                return -1;
            }
            *port = 0;
        }
    }

    return tpc_copy_src_path(path, path_size, path_start);
}


static int
tpc_copy_value(char *dst, size_t dst_size, const char *value_start,
    size_t value_len)
{
    if (value_len >= dst_size) {
        return -1;
    }

    memcpy(dst, value_start, value_len);
    dst[value_len] = '\0';

    return 0;
}


static void
tpc_fill_src_path_from_lfn(xrootd_tpc_params_t *out)
{
    if (out->src_path[0] != '\0' || !out->has_lfn) {
        return;
    }

    if (out->lfn[0] == '/') {
        ngx_cpystrn((u_char *) out->src_path, (u_char *) out->lfn,
                    sizeof(out->src_path));
        return;
    }

    if (strlen(out->lfn) + 1 < sizeof(out->src_path)) {
        out->src_path[0] = '/';
        ngx_cpystrn((u_char *) out->src_path + 1, (u_char *) out->lfn,
                    sizeof(out->src_path) - 1);
    }
}


static void
tpc_parse_src_fields(xrootd_tpc_params_t *out)
{
    if (!out->has_src) {
        return;
    }

    if (tpc_parse_src_spec(out->src, out->src_host, sizeof(out->src_host),
                           &out->src_port, out->src_path,
                           sizeof(out->src_path)) != 0) {
        out->src_host[0] = '\0';
        out->src_path[0] = '\0';
        out->src_port = 0;
        return;
    }

    tpc_fill_src_path_from_lfn(out);
}

/*
 * Process one "key=value" token from the opaque query string.
 * p   → start of current token
 * end → one past the last byte of the full opaque string
 * Returns a pointer to the next token (character after '&'), or NULL when done.
 */
static const char *
tpc_parse_token(const char *token_start, const char *opaque_end,
    xrootd_tpc_params_t *out)
{
    const char *token_end;
    const char *equals;
    const char *key_start;
    const char *value_start;
    size_t      key_len;
    size_t      value_len;

    /* Find end of this token. */
    token_end = memchr(token_start, '&', (size_t) (opaque_end - token_start));
    if (token_end == NULL) {
        token_end = opaque_end;
    }

    equals = memchr(token_start, '=', (size_t) (token_end - token_start));
    if (equals == NULL) {
        return (token_end < opaque_end) ? token_end + 1 : NULL;
    }

    key_start = token_start;
    value_start = equals + 1;
    key_len = (size_t) (equals - key_start);
    value_len = (size_t) (token_end - value_start);

    /* Only handle "tpc." keys. */
    if (key_len < 5 || memcmp(key_start, "tpc.", 4) != 0) {
        return (token_end < opaque_end) ? token_end + 1 : NULL;
    }

    key_start += 4;
    key_len -= 4;

    if (key_len == 3 && memcmp(key_start, "src", 3) == 0) {
        if (tpc_copy_value(out->src, sizeof(out->src), value_start,
                           value_len) == 0) {
            out->has_src   = 1;
        }
    } else if (key_len == 3 && memcmp(key_start, "dst", 3) == 0) {
        if (tpc_copy_value(out->dst, sizeof(out->dst), value_start,
                           value_len) == 0) {
            out->has_dst   = 1;
        }
    } else if (key_len == 3 && memcmp(key_start, "key", 3) == 0) {
        if (tpc_copy_value(out->key, sizeof(out->key), value_start,
                           value_len) == 0) {
            out->has_key   = 1;
        }
    } else if (key_len == 3 && memcmp(key_start, "lfn", 3) == 0) {
        if (tpc_copy_value(out->lfn, sizeof(out->lfn), value_start,
                           value_len) == 0) {
            out->has_lfn = 1;
        }
    } else if (key_len == 3 && memcmp(key_start, "org", 3) == 0) {
        if (tpc_copy_value(out->org, sizeof(out->org), value_start,
                           value_len) == 0) {
            out->has_org = 1;
        }
    } else if (key_len == 5 && memcmp(key_start, "stage", 5) == 0) {
        if (tpc_copy_value(out->stage, sizeof(out->stage), value_start,
                           value_len) == 0) {
            out->has_stage = 1;
        }
    } else if (key_len == 10 && memcmp(key_start, "token_mode", 10) == 0) {
        if (tpc_copy_value(out->token_mode, sizeof(out->token_mode),
                           value_start, value_len) == 0) {
            out->has_token_mode = 1;
        }
    }

    return (token_end < opaque_end) ? token_end + 1 : NULL;
}

int
xrootd_tpc_parse_opaque(const char *opaque, xrootd_tpc_params_t *out)
{
    const char *token;
    const char *end;
    int         found = 0;

    memset(out, 0, sizeof(*out));

    if (opaque == NULL || *opaque == '\0') {
        return -1;
    }

    token = opaque;
    end = opaque + strlen(opaque);

    while (token != NULL && token < end) {
        token = tpc_parse_token(token, end, out);
    }

    found = (out->has_src || out->has_dst || out->has_key
             || out->has_lfn || out->has_org || out->has_stage
             || out->has_token_mode);
    if (!found) {
        return -1;
    }

    tpc_parse_src_fields(out);

    return 0;
}
