/* ------------------------------------------------------------------ */
/* Path Helpers — Hex Encoding, Sanitization, Component Validation       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements path helper functions used throughout the codebase for filesystem operations. xrootd_path_component_forbidden() checks if path component is "." or ".." enabling directory traversal attacks — returns true when forbidden, false otherwise; xrootd_sanitize_log_string() escapes control bytes, quotes, backslashes, and non-ASCII characters to \xNN escape sequences ensuring log output contains only printable ASCII without breaking log parsers or revealing sensitive data; xrootd_finalize_path_rules() canonicalizes all policy rule paths using realpath(2) against the configured root directory preparing them for runtime enforcement.
 *
 * WHY: These helpers are used throughout path resolution, ACL enforcement, and access logging — security-critical operations that must handle edge cases consistently across the entire codebase. Hex encoding enables safe escape representation of non-printable characters; component validation blocks traversal attacks before filesystem operations begin; sanitization prevents log corruption from binary data in wire protocol payloads; rule finalization ensures all policy paths use canonical representations matching realpath(2) output for consistent runtime comparison. */

/* ------------------------------------------------------------------ */
/* Section: Path Component Validation                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_path_component_forbidden() checks if a path component name is "." (single dot) or ".." (double dot) — these are forbidden by filesystem security rules because they enable directory traversal attacks allowing access to paths outside configured root boundaries. Returns true (1) when component is forbidden; returns false (0) otherwise for valid component names.
 *
 * WHY: Directory traversal prevention is critical security invariant — without this check, clients could construct paths like /foo/../bar to escape configured root boundary and access unrestricted filesystem locations. Every path resolution function must call this helper before processing any component to ensure traversal attacks are blocked at the earliest possible point in request handling. */

/* ------------------------------------------------------------------ */
/* Section: Log String Sanitization                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_sanitize_log_string() escapes control bytes, quotes, backslashes, and non-ASCII characters to \xNN escape sequences ensuring log output contains only printable ASCII (0x21-0x7e excluding '"' and '\\'). Characters outside this range are converted to four-character \\xHH escape where HH is hex representation of original byte value. Returns number of bytes written; returns 0 if out buffer is NULL or zero-size.
 *
 * WHY: Wire protocol payloads may contain arbitrary binary data — logging raw wire strings without sanitization would corrupt log files, break parser expectations, and potentially reveal sensitive content. Sanitization ensures all logged strings are safe for standard log processing tools while preserving information about non-printable characters through hex escape representation. NULL input is treated as "-" providing consistent fallback for missing string values. */

/* ------------------------------------------------------------------ */
/* Section: Path Rule Finalization                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_finalize_path_rules() canonicalizes all policy rule paths using realpath(2) against the configured root directory — resolves "/" prefix rules to the canonicalized root path directly, calls xrootd_resolve_path_noexist() for relative rule paths transforming them into absolute canonical filesystem representations. Returns NGX_OK when all rule paths resolved successfully; returns NGX_ERROR on any resolution failure preventing policy enforcement with inconsistent paths.
 *
 * WHY: Policy rule finalization ensures runtime ACL and VO ACL enforcement uses consistent canonical path representations — without this step, rules referencing different path forms (relative vs absolute, symbolic links vs real filesystem) could fail comparison during access control checks causing either over-permissive or under-permissive behavior depending on mismatch direction. Canonicalization prevents policy bypass attempts through different path representations of the same filesystem location. */

/* ---- Function: xrootd_path_component_forbidden() ----
 *
 * WHAT: Checks if a path component name is "." (single dot) or ".." (double dot) — these are forbidden by filesystem security rules because they enable directory traversal attacks allowing access to paths outside configured root boundaries. Returns true (1) when component is forbidden; returns false (0) otherwise for valid component names.
 *
 * WHY: Directory traversal prevention is critical security invariant — without this check, clients could construct paths like /foo/../bar to escape configured root boundary and access unrestricted filesystem locations. Every path resolution function must call this helper before processing any component to ensure traversal attacks are blocked at the earliest possible point in request handling. */

/* ---- Function: xrootd_sanitize_log_string() ----
 *
 * WHAT: Escapes control bytes, quotes, backslashes, and non-ASCII characters to \\xNN escape sequences ensuring log output contains only printable ASCII (0x21-0x7e excluding '"' and '\\'). Characters outside this range are converted to four-character \\xHH escape where HH is hex representation of original byte value. Returns number of bytes written; returns 0 if out buffer is NULL or zero-size. NULL input treated as "-" providing consistent fallback for missing string values.
 *
 * WHY: Wire protocol payloads may contain arbitrary binary data — logging raw wire strings without sanitization would corrupt log files, break parser expectations, and potentially reveal sensitive content. Sanitization ensures all logged strings are safe for standard log processing tools while preserving information about non-printable characters through hex escape representation. NULL input is treated as "-" providing consistent fallback for missing string values. */

/* ---- Function: xrootd_count_path_depth() ----
 *
 * WHAT: Counts path components by iterating through '/' separators — O(n) string scan with no filesystem calls. Returns NGX_ERROR if component count exceeds XROOTD_MAX_WALK_DEPTH (32); returns NGX_OK otherwise. Leading slashes are skipped; trailing empty components (consecutive slashes, trailing slash) do not increment depth.
 *
 * WHY: This guard prevents CPU exhaustion before expensive realpath(3) / lstat() operations begin — malicious paths with 100+ symlink components or deep directory nesting can exhaust worker resources causing denial-of-service conditions. By rejecting oversized paths early (at string-scan cost only), we eliminate the attack vector without impacting normal operation performance where typical paths are 5–8 components deep. */

#include "../ngx_xrootd_module.h"

#include "../compat/hex.h"
#include "path_internal.h"

// Check if a path component name is forbidden by filesystem security rules.
// Returns true for "." and ".." components that enable directory traversal attacks.
int
xrootd_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}
/* ---- HOW: comp_len==1&&comp[0]=='.' || comp_len==2&&comp[0]=='.'&&comp[1]=='.'. Single comparison — O(1) constant-time check. */

/* ---- Function: xrootd_path_has_dotdot() ----
 *
 * WHAT: Returns 1 iff some '/'-delimited component of the NUL-terminated path is
 *       exactly "..". A filename that merely contains the two characters
 *       (e.g. "a..b", "..foo") is NOT a match — only a whole ".." component.
 * WHY:  The extract-based ops (stat/open/dirlist/locate) resolve through the
 *       kernel RESOLVE_BENEATH, which silently collapses an in-tree ".." instead
 *       of rejecting it. The reference XRootD server (rpCheck) rejects any ".."
 *       path outright rather than normalizing; op-table ops already reject it in
 *       xrootd_path_resolve_beneath(). This shared detector lets the extract-
 *       based ops match that contract. (Escaping ".." is independently confined
 *       by RESOLVE_BENEATH; this is a protocol-conformance guard, not a new
 *       security boundary.) */
int
xrootd_path_has_dotdot(const char *path)
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
        out[written++] = (char) xrootd_hex_nibble((u_char) (ch >> 4));
        out[written++] = (char) xrootd_hex_nibble((u_char) (ch & 0x0f));
    }

    out[written] = '\0';

    return written;
}

// Count path components by iterating through '/' separators — O(n) string scan.
// Returns NGX_ERROR if component count exceeds XROOTD_MAX_WALK_DEPTH (32);
// returns NGX_OK otherwise. Leading slashes skipped; trailing empty
// components do not increment depth.
ngx_int_t
xrootd_count_path_depth(const char *path)
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

    return (count > XROOTD_MAX_WALK_DEPTH) ? NGX_ERROR : NGX_OK;
}
/* ---- HOW: while(*p=='/') p++ skip leading slashes. *p=='\0' → return NGX_OK (empty). count=1. While *p: if '/'→p++; else *p!='\0'→count++. Returns (count>XROOTD_MAX_WALK_DEPTH)?NGX_ERROR:NGX_OK. */

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

        /*
         * Config-time only, and deliberately NOT migrated to the beneath API.
         * This canonicalises a TRUSTED, admin-configured VO/group policy rule
         * path once at startup (not a client request path), so realpath(3) is
         * the right tool: it resolves the rule to its absolute form for later
         * prefix matching against resolved request paths.  There is no rootfd at
         * config-parse time and no untrusted input here, so openat2
         * RESOLVE_BENEATH would add nothing.
         */
        if (!xrootd_resolve_path_noexist(log, root,
                                         (const char *) path->data,
                                         resolved, resolved_size))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
/* ---- HOW: rules==NULL → NGX_OK. xrootd_get_canonical_root() for root_canon — if fail NGX_ERROR. elts=rules->elts. Loop i=0..nelts-1: path=(ngx_str_t*)(elts+i*element_size+path_offset); resolved=(char*)(elts+i*element_size+resolved_offset). If path->len==1&&data[0]=='/': ngx_cpystrn(resolved,root_canon,resolved_size) (root-only → resolved=root). Else: xrootd_resolve_path_noexist() — if fail NGX_ERROR. After all rules: return NGX_OK. */
/* ---- HOW: out==NULL||outsz==0 → return 0. src=(in!=NULL)?in:"-"". written=0. Loop over bytes: printable ASCII pass-through; else write hex escape (4 chars). After loop: null-term. Return written count. */
