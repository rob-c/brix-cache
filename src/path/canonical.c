/* ------------------------------------------------------------------ */
/* Canonical Path Resolution — realpath() Wrapper                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements xrootd_get_canonical_root() which converts an nginx ngx_str_t root path into a canonical filesystem path using realpath(2). The function validates input length constraints (ngx_str_t must fit within PATH_MAX buffer), performs null-termination conversion from non-null-terminated ngx_str_t, calls realpath() to resolve symbolic links and normalize directory components, and returns 1 on success with canonicalized path written to output buffer; returns 0 on failure with warn-level log describing the specific error.
 *
 * WHY: Canonical root path resolution is critical for security — without canonicalization, different representations of the same filesystem path (e.g., /foo/../bar vs /bar) could be treated as distinct locations allowing path traversal attacks to escape configured root boundaries. realpath(2) resolves all symbolic links and removes redundant directory components ensuring every operation uses a single authoritative path representation preventing spoofing or boundary bypass attempts. */

/* ------------------------------------------------------------------ */
/* Section: Input Validation                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Pre-realpath validation checks two constraints: ngx_str_t length must not exceed PATH_MAX (1024 bytes on Linux) to prevent buffer overflow in root_buf allocation; output buffer capacity must accommodate canonicalized result. Both checks return 0 immediately without calling realpath(2) preventing unnecessary filesystem operations when inputs are invalid.
 *
 * WHY: Buffer validation prevents crashes where oversized paths would overflow PATH_MAX-sized stack buffers, causing undefined behavior and potential security issues. Output size check ensures the caller has provided sufficient capacity to receive canonicalized result — realpath may produce longer paths than original input due to symbolic link resolution. */

/* ------------------------------------------------------------------ */
/* Section: Canonicalization                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_get_canonical_root() performs three-step canonicalization: null-terminate ngx_str_t into PATH_MAX buffer using ngx_memcpy + NUL append — call realpath(2) resolving symbolic links and normalizing directory components (e.g., /a/b/../c → /a/c) — validate output fits within caller-provided capacity. Returns 1 on success with canonicalized path written to root_canon output; returns 0 on failure logging warn-level error describing specific cause (ENOENT, EACCES, or buffer overflow).
 *
 * WHY: Canonicalization ensures all subsequent file operations use a single authoritative filesystem path representation — preventing security issues where different path representations could bypass configured root boundaries. Symbolic link resolution eliminates potential spoofing attempts through symlink chains; directory normalization removes redundant components ensuring consistent path comparison across all ACL rules and access control checks. */

/* ---- Function: xrootd_get_canonical_root() ----
 *
 * WHAT: Converts an nginx ngx_str_t root path into canonical filesystem path using realpath(2) performing three steps: validate input fits PATH_MAX buffer, null-terminate from non-null-terminated ngx_str_t via ngx_memcpy + NUL append, call realpath(2) resolving symbolic links and normalizing directory components, verify output fits caller-provided capacity. Returns 1 on success with canonicalized path written to root_canon output; returns 0 on failure logging warn-level error describing specific cause (ENOENT, EACCES, or buffer overflow).
 *
 * WHY: Canonicalization ensures all subsequent file operations use a single authoritative filesystem path representation — preventing security issues where different path representations could bypass configured root boundaries. Symbolic link resolution eliminates potential spoofing attempts through symlink chains; directory normalization removes redundant components ensuring consistent path comparison across all ACL rules and access control checks.
 *
 * HOW: Three-step canonicalization → validate ngx_str_t length fits PATH_MAX buffer (return 0 if oversized) — null-terminate into stack buffer using ngx_memcpy + '\0' append — call realpath(root_buf, root_canon) resolving symbolic links and normalizing components — verify output fits caller-provided capacity via ngx_strnlen (return 0 if overflow) — return 1 on success with canonicalized path in root_canon; return 0 logging warn-level error for realpath failure. */

#include "../ngx_xrootd_module.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

int
xrootd_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
                          char *root_canon, size_t root_canon_sz)
{
    char root_buf[PATH_MAX];

    if (root == NULL || root->len == 0 || root->len >= sizeof(root_buf)) {
        return 0;
    }

    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    if (realpath(root_buf, root_canon) == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cannot canonicalize root \"%s\"", root_buf);
        return 0;
    }

    if (ngx_strnlen((u_char *) root_canon, root_canon_sz) >= root_canon_sz) {
        return 0;
    }

    return 1;
}
