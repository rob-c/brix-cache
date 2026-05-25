/* ---- File: parse.c — TPC opaque parameter parsing and source URL decomposition ----
 *
 * WHAT: Six functions parse the TPC opaque query string from a kXR_open request into structured xrootd_tpc_params_t fields. tpc_parse_opaque (public entry) zero-initializes out → iterates key=value tokens via tpc_parse_token → validates at least one recognized key present → delegates src parsing to tpc_parse_src_fields; tpc_parse_token extracts key/value pairs from '&' delimited opaque string, matching only "tpc." prefixed keys (src/dst/key/lfn/org/stage/token_mode) and setting has_* flags; tpc_parse_src_fields calls tpc_parse_src_spec() for URL/host/port/path decomposition, clears all fields on failure to prevent partial-parse security bypass, then normalizes src_path via LFN if applicable; tpc_fill_src_path_from_lfn converts lfn into src_path with leading '/' normalization when src_path is empty and has_lfn=true; tpc_parse_src_spec decomposes root://host//path or xroot://host/path URLs (or bare host[:port]) into host/port/path, supports IPv6 bracket notation; tpc_copy_component copies substring with size guard; tpc_parse_port_range strtol-validates port 1-65535; tpc_copy_src_path strips leading double-slashes and ensures single '/' prefix.
 *
 * WHY: TPC (Third-Party Copy) requests carry source endpoint information in opaque query parameters appended to the kXR_open path field. Clients may send full URLs (root://host//path), bare host[:port] with lfn carrying the file name, or IPv6 addresses in bracket notation. Parsing must be robust against malformed inputs — partial parse failures must clear all fields to prevent security bypass where a partially-parsed source could reach downstream validation. LFN normalization ensures consistent path format regardless of client convention.
 *
 * HOW: Parse_opaque → memset(out,0) → iterate tokens via tpc_parse_token(&-delimited) → check at least one has_* flag set → call tpc_parse_src_fields if has_src=true; parse_token → find '&' or end-of-string as token boundary → locate '=' separator → verify "tpc." prefix (4 bytes) → match remaining key length against known keys (src=3, dst=3, key=3, lfn=3, org=3, stage=5, token_mode=10) → copy value into corresponding buffer with size guard; parse_src_fields → call tpc_parse_src_spec() for URL decomposition → on error clear src_host/\\0, src_path/\\0, src_port=0 → delegate to tpc_fill_src_path_from_lfn for LFN normalization; parse_src_spec → find "://" scheme separator → extract authority (host[:port]) between scheme and '/' → handle IPv6 brackets [...] → strtol validate port range 1-65535 → copy path component after '/'; fill_src_path_from_lfn → if src_path already set or has_lfn=false, return; if lfn starts with '/', copy directly; else prepend '/' then copy remaining chars.
 * ------------------------------------------------------------------ */
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

/* ---- Function: tpc_parse_src_spec() — Decompose TPC source URL into host/port/path ---- */
/* WHAT: Decomposes a TPC source endpoint string (root://host//path, xroot://host/path, or bare host[:port]) into host, port, and path components. Finds "://" scheme separator → extracts authority between scheme and '/' → handles IPv6 bracket notation [...] → strtol validates port range 1-65535 → copies path component after '/' via tpc_copy_src_path (strips leading double-slashes, ensures single '/' prefix). Returns 0 on success, -1 on failure.
 * WHY: TPC clients send source endpoints in varying formats — full URLs with scheme and path, bare host[:port] with lfn carrying the file name separately, or IPv6 addresses in bracket notation. This function normalizes all variants into a consistent host/port/path triplet for downstream security validation and file resolution. Port validation (1-65535) prevents overflow; full-field-clearing on failure prevents partial-parse bypass.
 * HOW: strstr("://") scheme separator → authority_start = after "://" → memchr('/') path boundary → handle IPv6 brackets [...] → strtol port range 1-65535 → tpc_copy_src_path for path component with double-slash stripping and single '/' prefix enforcement. */
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

/* ---- Function: tpc_fill_src_path_from_lfn() — LFN-to-src_path conversion with leading slash ---- */
/* WHAT: Converts a Logical File Name (lfn) into src_path, adding a leading '/' if the lfn lacks one. Only executes when out->src_path is empty AND out->has_lfn is true. Handles both absolute paths (starting with '/') and relative paths by prepending '/'. Enforces sizeof(out->src_path) boundary to prevent overflow.
 * WHY: TPC source specifications may arrive as LFNs without leading slashes; this helper normalizes path format before src_host/src_port parsing ensures consistent path representation for downstream security validation and file resolution. Prevents cross-filesystem transfer attempts with malformed paths.
 * HOW: Three cases → if src_path already populated or has_lfn=false, return immediately; if lfn starts with '/', copy directly via ngx_cpystrn; if relative (no leading '/'), prepend '/' then copy remaining characters into buffer with size guard. */

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

/* ---- Function: tpc_parse_src_fields() — TPC source host/port/path parsing ---- */
/* WHAT: Parses the Source field from a TPC request into src_host, src_port, and src_path components via tpc_parse_src_spec(). On failure, clears all three fields to prevent partial-parse security bypass. Then delegates path normalization to tpc_fill_src_path_from_lfn() for LFN-to-src_path conversion.
 * WHY: TPC (Transfer Protocol Client) requires parsing source specification into host/port/path components before initiating cross-server transfer. Complete-field-clearing on failure prevents security bypass where a partially-parsed source could be used with incomplete authentication. Path normalization ensures consistent source path format for downstream validation.
 * HOW: Two-phase → if has_src is false, return immediately; call tpc_parse_src_spec() to extract host/port/path; on non-zero error result, clear all fields (src_host='\0', src_path='\0', src_port=0); then call tpc_fill_src_path_from_lfn() for LFN normalization. */

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

/* ---- Function: tpc_parse_token() — Extract one key=value pair from TPC opaque string ---- */
/* WHAT: Iterates through one "key=value" token in the '&' delimited opaque query string. Finds token boundary (next '&' or end-of-string) → locates '=' separator → verifies "tpc." prefix (4 bytes) → matches remaining key length against known keys (src=3, dst=3, key=3, lfn=3, org=3, stage=5, token_mode=10) → copies value into corresponding buffer with size guard → sets has_* flag on success → returns pointer to next token or NULL when done.
 * WHY: TPC opaque parameters are '&' delimited key=value pairs prefixed with "tpc.". This function extracts each recognized parameter into the typed xrootd_tpc_params_t struct while silently ignoring unknown keys (forward compatibility). Size-guarded copies prevent buffer overflow from oversized values. Returns next-token pointer enables iterative loop in tpc_parse_opaque.
 * HOW: memchr(&) for token boundary → memchr(=) for key/value split → memcmp("tpc.") prefix check → switch on remaining key length against known keys → tpc_copy_value with size guard → set has_* flag → return next-token pointer or NULL. */
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

/* ---- Function: xrootd_tpc_parse_opaque() — TPC opaque query string parser (public API) ---- */
/* WHAT: Public entry point that parses the TPC opaque parameter string from a kXR_open request into structured xrootd_tpc_params_t fields. Zero-initializes out → iterates '&' delimited key=value tokens via tpc_parse_token → validates at least one recognized "tpc." key present (src/dst/key/lfn/org/stage/token_mode) → delegates src URL/host/port/path decomposition to tpc_parse_src_fields → returns 0 on success, -1 on failure.
 * WHY: TPC requests encode source endpoint information in opaque query parameters appended to the kXR_open path field. This function extracts those parameters into a typed struct for downstream security validation and file resolution. Zero-initialization prevents stale data from previous parses; full-field-clearing on src-parse failure prevents partial-parse security bypass.
 * HOW: memset(out,0) → iterate tokens via tpc_parse_token(&-delimited loop) → check at least one has_* flag set → call tpc_parse_src_fields if has_src=true → return 0/−1 based on found flags count. */

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
