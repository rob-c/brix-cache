/* File: parse.c — TPC opaque parameter parsing and source URL decomposition
 * WHAT: Six functions parse the TPC opaque query string from a kXR_open request into structured xrootd_tpc_params_t fields. tpc_parse_opaque (public entry) zero-initializes out → iterates key=value tokens via tpc_parse_token → validates at least one recognized key present → delegates src parsing to tpc_parse_src_fields; tpc_parse_token extracts key/value pairs from '&' delimited opaque string, matching only "tpc." prefixed keys (src/dst/key/lfn/org/stage/token_mode) and setting has_* flags; tpc_parse_src_fields calls tpc_parse_src_spec() for URL/host/port/path decomposition, clears all fields on failure to prevent partial-parse security bypass, then normalizes src_path via LFN if applicable; tpc_fill_src_path_from_lfn converts lfn into src_path with leading '/' normalization when src_path is empty and has_lfn=true; tpc_parse_src_spec decomposes root://host//path or xroot://host/path URLs (or bare host[:port]) into host/port/path, delegating the authority host:port split (IPv6 brackets + 1-65535 port validation) to the shared xrootd_split_host_port() that the native client (url.c) also uses; tpc_copy_src_path strips leading double-slashes and ensures single '/' prefix.
 *
 * WHY: TPC (Third-Party Copy) requests carry source endpoint information in opaque query parameters appended to the kXR_open path field. Clients may send full URLs (root://host//path), bare host[:port] with lfn carrying the file name, or IPv6 addresses in bracket notation. Parsing must be robust against malformed inputs — partial parse failures must clear all fields to prevent security bypass where a partially-parsed source could reach downstream validation. LFN normalization ensures consistent path format regardless of client convention.
 *
 * HOW: Parse_opaque → memset(out,0) → iterate tokens via tpc_parse_token(&-delimited) → check at least one has_* flag set → call tpc_parse_src_fields if has_src=true; parse_token → find '&' or end-of-string as token boundary → locate '=' separator → verify "tpc." prefix (4 bytes) → match remaining key length against known keys (src=3, dst=3, key=3, lfn=3, org=3, stage=5, token_mode=10) → copy value into corresponding buffer with size guard; parse_src_fields → call tpc_parse_src_spec() for URL decomposition → on error clear src_host/\\0, src_path/\\0, src_port=0 → delegate to tpc_fill_src_path_from_lfn for LFN normalization; parse_src_spec → find "://" scheme separator → extract authority (host[:port]) between scheme and '/' → handle IPv6 brackets [...] → strtol validate port range 1-65535 → copy path component after '/'; fill_src_path_from_lfn → if src_path already set or has_lfn=false, return; if lfn starts with '/', copy directly; else prepend '/' then copy remaining chars.
 * */
#include "tpc_internal.h"
#include "../compat/host_split.h"   /* shared bracketed-IPv6 host:port split (libxrdproto) */

#include <string.h>
#include <stdlib.h>

/* WHAT: Normalise the source path into `path`: collapse a leading run of '/'
 * down to a single '/', and guarantee the result starts with exactly one '/'.
 * WHY: xrootd URLs use "root://host//path" (double slash separates authority
 * from an absolute path), and clients are inconsistent about leading slashes.
 * Collapsing leading slashes prevents "//" path-traversal ambiguity downstream;
 * forcing a single leading '/' yields a canonical absolute path for authz.
 * HOW: empty/NULL -> "" ; skip leading "//" pairs; size-check accounting for a
 * possibly-prepended '/'; copy verbatim if already rooted, else prepend '/'. */
static int
tpc_copy_src_path(char *path, size_t path_size, const char *path_start)
{
    size_t path_len;

    if (path_start == NULL || *path_start == '\0') {
        path[0] = '\0';
        return 0;
    }

    /* Collapse a leading run of slashes ("///x" -> "/x") to defeat the
     * "root://host//path" double-slash and any "//" traversal ambiguity. */
    while (path_start[0] == '/' && path_start[1] == '/') {
        path_start++;
    }

    /* Reserve one extra byte for a '/' we will prepend when not already rooted. */
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

/* WHAT: Decomposes a TPC source endpoint string (root://host//path, xroot://host/path, or bare host[:port]) into host, port, and path components. Finds "://" scheme separator → extracts authority between scheme and '/' → handles IPv6 bracket notation [...] → strtol validates port range 1-65535 → copies path component after '/' via tpc_copy_src_path (strips leading double-slashes, ensures single '/' prefix). Returns 0 on success, -1 on failure.
 * WHY: TPC clients send source endpoints in varying formats — full URLs with scheme and path, bare host[:port] with lfn carrying the file name separately, or IPv6 addresses in bracket notation. This function normalizes all variants into a consistent host/port/path triplet for downstream security validation and file resolution. Port validation (1-65535) prevents overflow; full-field-clearing on failure prevents partial-parse bypass.
 * HOW: strstr("://") scheme separator → authority_start = after "://" → memchr('/') path boundary → handle IPv6 brackets [...] → strtol port range 1-65535 → tpc_copy_src_path for path component with double-slash stripping and single '/' prefix enforcement. */
static int
tpc_parse_src_spec(const char *src, char *host, size_t host_size,
    uint16_t *port, char *path, size_t path_size)
{
    const char *authority_start;
    const char *authority_end;
    const char *path_start;
    const char *scheme_separator;
    const char *src_end;
    char        authority[320];
    size_t      authority_len;
    int         parsed_port = 0;

    if (src == NULL || *src == '\0') {
        return -1;
    }

    src_end = src + strlen(src);
    scheme_separator = strstr(src, "://");
    if (scheme_separator != NULL) {
        /* URL form: authority begins after "://" and runs up to the first '/'
         * (which also marks where the path begins). No '/' => authority spans
         * to end and there is no path component. */
        authority_start = scheme_separator + 3;
        authority_end = memchr(authority_start, '/',
                               (size_t) (src_end - authority_start));
        path_start = authority_end;
        if (authority_end == NULL) {
            authority_end = src_end;
            path_start = NULL;
        }
    } else {
        /* Bare "host[:port]" form: the whole string is the authority; the file
         * name will be supplied separately via the lfn parameter. */
        authority_start = src;
        authority_end = src_end;
        path_start = NULL;
    }

    if (authority_start == authority_end) {
        return -1;
    }

    /* Lift the authority slice into a NUL-terminated scratch buffer and split it
     * with the shared bracketed-IPv6-aware host:port parser — the same leaf the
     * native client (url.c) uses, so both validate the authority identically.
     * default_port 0 keeps this caller's "no explicit port -> 0 sentinel"
     * contract (the launch path applies the real default later); an explicit
     * port is validated to 1..65535. */
    authority_len = (size_t) (authority_end - authority_start);
    if (authority_len >= sizeof(authority)) {
        return -1;
    }
    memcpy(authority, authority_start, authority_len);
    authority[authority_len] = '\0';

    if (xrootd_split_host_port(authority, host, host_size, &parsed_port, 0)
        != 0) {
        return -1;
    }
    *port = (uint16_t) parsed_port;

    return tpc_copy_src_path(path, path_size, path_start);
}

/* WHAT: Copy a value_len-byte opaque value into dst as a NUL-terminated string,
 * rejecting any value that does not fit (with its NUL) — the core overflow
 * guard for every tpc.* parameter parsed by tpc_parse_token().
 * WHY: Opaque values come straight off the wire; a fixed-size destination must
 * never be overrun by an attacker-controlled length.
 * HOW: bounds-check value_len < dst_size, memcpy, terminate. */
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

    /* Only handle "tpc." keys. key_len < 5 means there is no name after the
     * 4-char prefix, so it cannot be a recognised tpc.* parameter. Unknown
     * keys are skipped (return next token), giving forward compatibility. */
    if (key_len < 5 || memcmp(key_start, "tpc.", 4) != 0) {
        return (token_end < opaque_end) ? token_end + 1 : NULL;
    }

    /* Advance past "tpc." so the comparisons below match the bare name. */
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
