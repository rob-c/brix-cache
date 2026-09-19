#ifndef BRIX_PATH_PATH_INTERNAL_H
#define BRIX_PATH_PATH_INTERNAL_H

#include "core/ngx_brix_module.h"

/* Traversal guard: returns 1 (true) iff comp[0..comp_len) is exactly "." or
 * "..", else 0. Borrows comp (need not be NUL-terminated); O(1), no alloc. */
int brix_path_component_forbidden(const char *comp, size_t comp_len);

/* Boundary-aware path prefix test: 1 iff `path` is AT or BENEATH the first
 * `prefix_len` bytes of `prefix` — the match must land on a component boundary,
 * so "/foo" covers "/foo" and "/foo/bar" but not "/foobar".  A prefix that
 * itself ends in '/' is already at a separator and therefore covers everything
 * below it; the root prefix "/" is the case that matters, because it cannot be
 * stripped to a non-separator form.  Borrows both strings; NULL → 0.
 *
 * ONE implementation on purpose.  There were two — one here in find_rule.c's
 * shape (with the carve-out) and a private copy in auth/authz/authdb.c (without
 * it) — and the divergence was invisible for as long as the request path
 * happened to arrive with a doubled slash, whose second '/' satisfied the
 * boundary test by accident.  The moment the join was fixed to emit a single
 * slash, an authdb rule on "/" (the natural grant for a remote-backed export,
 * whose root_canon IS "/") matched the literal "/" and nothing beneath it:
 * every authorized principal was refused. */
int brix_path_prefix_match(const char *prefix, size_t prefix_len,
    const char *path);

/* Traversal guard for extract-based ops: returns 1 iff some '/'-delimited
 * component of the NUL-terminated path is exactly ".." (a lone "." is not a
 * match). Borrows path (may be NULL → 0). See brix_reject_dotdot_path. */
int brix_path_has_dotdot(const char *path);

/* Emits an NGX_LOG_WARN "<prefix>: <path>" line with path run through
 * brix_sanitize_log_string() (control/non-ASCII bytes hex-escaped) to block
 * log injection from wire-supplied paths. path may be NULL (logged as "-").
 * Borrows both strings; truncates path to 511 chars via a stack buffer. */
void brix_log_path_warning(ngx_log_t *log, const char *prefix,
    const char *path);

/* Confinement helpers used across resolve_confined_*.c fragments. */

/* Open an export-root anchor; returns an owned fd or -1 (logs on failure).
 * The caller closes the fd after its confined operations finish. */
int brix_open_root_fd(ngx_log_t *log, const char *root_canon);

/* Split a root-relative path into parent and final component. Returns 1 on
 * success, 0 with EINVAL for NULL/empty/"." or ENAMETOOLONG when either output
 * does not fit. Outputs are valid only on success; borrows the input string. */
int brix_split_relative_parent(const char *rel, char *parent, size_t parentsz,
    char *base, size_t basesz);

/* Walk parent below a borrowed rootfd without following symlinks. Returns an
 * owned parent fd (a dup for empty/"." parent), or -1 with errno set. */
int brix_open_confined_parent_fallback(int rootfd, const char *parent);

/* openat2-first confined open (RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS); an
 * ENOSYS/EINVAL/EOPNOTSUPP answer tells the caller to take the segment-walk
 * fallback. Shared by resolve_confined_helpers.c and resolve_confined_ops.c. */
int brix_openat2_confined(int rootfd, const char *rel, int flags, mode_t mode);

/* Open the confined parent of canonical resolved and write its leaf to base.
 * Returns an owned parent fd, or -1. Borrows both canonical path strings. */
int brix_open_confined_parent_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *base, size_t basesz);

/* Export-boundary check: returns 1 iff path_canon equals root_canon or is a
 * descendant of it, else 0. Both must be canonical absolute paths (no trailing
 * slash unless root is "/"). The next-byte ('/' or NUL) test defeats prefix
 * spoofing ("/export" never matches "/exportdata"). Borrows both strings. */
int brix_path_within_root(const char *root_canon, const char *path_canon);

/* Strips root_canon from absolute resolved, writing the root-relative form
 * (or "." when resolved IS the root) into rel[0..relsz). Returns 1 on success,
 * 0 on failure (sets errno: EXDEV if resolved escapes root and logs a warning;
 * ENAMETOOLONG if the relative form does not fit relsz). Note: failure is 0,
 * not -1. Borrows root_canon/resolved; writes only on success. */
int brix_resolved_relative_to_root(ngx_log_t *log, const char *root_canon,
    const char *resolved, char *rel, size_t relsz);

/* Canonicalizes config root (ngx_str_t, not NUL-terminated) into root_canon via
 * realpath(3); the root must exist. Returns 1 on success, 0 on failure (root
 * NULL/empty/>=PATH_MAX, realpath error logged at WARN, or result >= root_canon_sz).
 * Borrows root; writes root_canon only on success. */
int brix_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
    char *root_canon, size_t root_canon_sz);

/* Startup-only: canonicalizes each policy rule's path field in-place into its
 * resolved field, for a generic array described by element_size and the byte
 * offsets/size of the path/resolved members. A rule whose path is "/" resolves
 * to the canonical root; others go through brix_resolve_path_noexist (rule
 * path need not exist). rules==NULL is a no-op. Returns NGX_OK, or NGX_ERROR if
 * the root or any rule path fails to resolve. Uses realpath on trusted admin
 * config (no rootfd/openat2 confinement). */
ngx_int_t brix_finalize_path_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules, size_t element_size, size_t path_offset,
    size_t resolved_offset, size_t resolved_size);

#endif /* BRIX_PATH_PATH_INTERNAL_H */
