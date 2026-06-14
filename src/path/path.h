#ifndef XROOTD_PATH_H
#define XROOTD_PATH_H

#include "../ngx_xrootd_module.h"

/* Sanitize a path string for safe logging (replaces control chars). */
size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);

/* Normalize a policy-style path (collapse "..", trailing slashes). */
ngx_int_t xrootd_normalize_policy_path(ngx_pool_t *pool,
    const ngx_str_t *src, ngx_str_t *dst);

/* Merge two ngx_array_t rule arrays; child entries shadow parent. */
ngx_array_t *xrootd_merge_arrays(ngx_conf_t *cf, ngx_array_t *parent,
    ngx_array_t *child, size_t element_size);

/* Resolve configured vo_rules and group_rules to absolute paths. */

/* Config-time: realpath()-canonicalise each VO rule's .path into .resolved,
 * relative to <root>. Mutates the rules array in place. NGX_OK / NGX_ERROR. */
ngx_int_t xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
/* As above for authdb rules (canonicalise each rule path into .resolved). */
ngx_int_t xrootd_finalize_authdb_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
/* As above for group-policy rules (canonicalise each rule path into .resolved). */
ngx_int_t xrootd_finalize_group_rules(ngx_log_t *log,
    const ngx_str_t *root, ngx_array_t *rules);

/* Longest-prefix rule lookups (VO ACL and group policy). */

/* Longest-prefix VO rule covering <resolved_path> (boundary-aware: matches at a
 * '/' or end-of-string only). Borrows into <rules>; NULL if none / bad input. */
const xrootd_vo_rule_t *xrootd_find_vo_rule(const char *resolved_path,
    ngx_array_t *rules);
/* Longest-prefix authdb rule that BOTH matches <ctx>'s identity and grants all
 * <needed_privs> bits. Reads identity from ctx->identity, else synthesises one
 * from ctx->dn / ctx->vo_list. Borrows into <rules>; NULL if no sufficient rule. */
const xrootd_authdb_rule_t *xrootd_find_authdb_rule(const char *resolved_path,
    ngx_array_t *rules, xrootd_ctx_t *ctx, uint32_t needed_privs);
/* As above but takes an explicit identity and peer IP (for host rules). Only
 * rules granting all <needed_privs> compete; longest prefix wins (ties: last). */
const xrootd_authdb_rule_t *xrootd_find_authdb_rule_identity(
    const char *resolved_path, ngx_array_t *rules,
    const xrootd_identity_t *identity, const char *peer_ip,
    uint32_t needed_privs);
/* Longest-prefix group-policy rule for <resolved_path>; borrows; NULL if none. */
const xrootd_group_rule_t *xrootd_find_group_rule(
    const char *resolved_path, ngx_array_t *rules);

/* Test whether <required_vo> is one of the comma-separated tokens in <vo_list>
 * (whole-token match). Returns 1 (allow) if <required_vo> is NULL/empty; 0 if
 * <vo_list> is NULL/empty or has no matching token. */
ngx_flag_t xrootd_vo_list_contains(const char *vo_list,
    const char *required_vo);

/* Check the VO ACL for a resolved path. */

/* Allow iff no rule covers <resolved_path>, or the covering rule's VO appears in
 * the comma-separated <vo_list>. NGX_OK to allow; NGX_ERROR on deny (logs a
 * sanitised WARN line). Empty/NULL vo_rules => allow-all. */
ngx_int_t xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
    ngx_array_t *vo_rules, const char *vo_list);
/* As above, deriving the VO list from <identity>'s VO CSV. NGX_OK / NGX_ERROR. */
ngx_int_t xrootd_check_vo_acl_identity(ngx_log_t *log,
    const char *resolved_path, ngx_array_t *vo_rules,
    const xrootd_identity_t *identity);

/* Check the Authdb for a resolved path; returns NGX_OK or NGX_ERROR. */

/* Allow iff some authdb rule grants <ctx>'s identity all <needed_privs> bits on
 * <resolved_path>. Pulls rules from the session's srv conf. NGX_OK to allow;
 * NGX_ERROR on deny (logs sanitised WARN). Empty rule set => allow-all. */
ngx_int_t xrootd_check_authdb(xrootd_ctx_t *ctx, const char *resolved_path,
    uint32_t needed_privs);
/* As above with explicit <rules>, <identity> and <peer_ip>; <log> is the sink
 * for the deny WARN. NGX_OK / NGX_ERROR; empty/NULL rules => allow-all. */
ngx_int_t xrootd_check_authdb_identity(ngx_log_t *log, ngx_array_t *rules,
    const xrootd_identity_t *identity, const char *peer_ip,
    const char *resolved_path, uint32_t needed_privs);

/* Parse an XRootD authdb file into rules. */
ngx_int_t xrootd_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename,
    ngx_array_t *rules);

/* Apply parent-directory group ownership policy (chown GID). */

/* If a group rule covers <path>, chown its GID to the parent dir's GID and
 * propagate setgid (chmod). Operates on <fd> (fchown/fchmod) to avoid TOCTOU.
 * NGX_OK applied; NGX_DECLINED no rule / path is root; NGX_ERROR on syscall fail. */
ngx_int_t xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd,
    const char *path, ngx_array_t *rules);
/* As above but operates by path (chown/chmod via the resolved <path>, no fd). */
ngx_int_t xrootd_apply_parent_group_policy_path(ngx_log_t *log,
    const char *path, ngx_array_t *rules);

/*
 * Resolve a client-supplied path to an absolute path under <root>.
 * _noexist: allows non-existent final component (for creates).
 * _write:   additionally checks that the path is writable.
 * Returns 0 on success, -1 on error (errno set or log message emitted).
 */
/* Config-time only: canonicalises trusted VO/group policy rule paths at startup
 * (xrootd_finalize_path_rules).  The runtime EXISTING/WRITE resolvers were
 * removed in Phase 8 — see xrootd_path_resolve_beneath() in path/op_path.h. */
int xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);

/*
 * Root-confined namespace syscalls.
 *
 * The caller still resolves and authorises the logical path first.  These
 * helpers make the final syscall relative to the export root so a symlink or
 * parent-directory swap after realpath() cannot redirect the operation outside
 * the configured root.  On Linux they use openat2(RESOLVE_BENEATH); the
 * portable fallback walks parent directories with O_NOFOLLOW and is therefore
 * more conservative about symlinks.
 */
/* Open <resolved> confined under <root> (ngx_str_t); canonicalises root first
 * (errno=EACCES if that fails). <mode> applies only with O_CREAT in <flags>.
 * Returns an fd (caller MUST close it; not pool-managed) or -1 with errno set. */
int xrootd_open_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int flags, mode_t mode);
/* As above but <root_canon> is already canonical (skips the realpath). */
int xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
/* Confined unlinkat of <resolved>; <is_dir> != 0 sets AT_REMOVEDIR (rmdir).
 * Returns 0 or -1 with errno set. */
int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
/* Confined mkdirat of <resolved> with <mode>. Returns 0 or -1 (errno set). */
int xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
/* Confined renameat; both src and dst parents are opened under <root_canon>
 * (no cross-root moves). Returns 0 or -1 with errno set. */
int xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
/* Confined linkat (hard link); both parents confined as above. 0 / -1 (errno). */
int xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/*
 * xrootd_openat2_runtime_available — returns 1 if openat2(2) works on the
 * running kernel, 0 if it is compiled out or the syscall returns ENOSYS.
 * Call once from init_process to log a warning on degraded systems.
 */
int xrootd_openat2_runtime_available(void);

/* Extract a NUL-terminated path from a raw XRootD request payload. */
int xrootd_extract_path(ngx_log_t *log, const u_char *payload,
    size_t payload_len, char *out, size_t outsz, ngx_flag_t strip_cgi);

/* Recursively create directory <path> with mode <mode>. Treats EEXIST on any
 * level as success. Returns 0, or -1 with errno set (ENAMETOOLONG if too long).
 * No confinement — for trusted paths only. */
int xrootd_mkdir_recursive(const char *path, mode_t mode);
/* As above, but on each level it actually creates (not EEXIST) applies the
 * parent-group policy via <rules>/<log>; a policy error aborts with -1.
 * Pass log=rules=NULL to skip the policy step (then identical to the above). */
int xrootd_mkdir_recursive_policy(const char *path, mode_t mode,
    ngx_log_t *log, ngx_array_t *rules);
/*
 * xrootd_mkdir_recursive_confined_canon — like xrootd_mkdir_recursive_confined
 * but takes an already-resolved root_canon string (char *) instead of an
 * ngx_str_t, skipping the internal xrootd_get_canonical_root() call.
 * Used by callers (e.g. S3 PUT) that have already resolved the canonical root.
 * <resolved> must lie under <root_canon> (else errno=EXDEV; EEXIST if equal).
 * Each level is created via the confined mkdirat; EEXIST is success. Optional
 * <rules> applies parent-group policy per level (best-effort). 0 / -1 (errno).
 */
int xrootd_mkdir_recursive_confined_canon(ngx_log_t *log,
    const char *root_canon, const char *resolved, mode_t mode,
    ngx_array_t *rules);
/* As _confined_canon but creates each level via openat2(RESOLVE_BENEATH) under
 * an already-open <rootfd> (O_PATH dirfd of the export root) instead of
 * re-opening parents per call. <root_canon> is still used to derive the relative
 * path and bounds-check <resolved>. EEXIST is success; 0 / -1 with errno set. */
int xrootd_mkdir_recursive_beneath(ngx_log_t *log, int rootfd,
    const char *root_canon, const char *resolved, mode_t mode,
    ngx_array_t *rules);

/* Strip CGI query string from a path (modifies out in-place). */
void xrootd_strip_cgi(const char *in, char *out, size_t outsz);

/*
 * Count path components before filesystem operations begin.
 * Returns NGX_OK if depth ≤ XROOTD_MAX_WALK_DEPTH; NGX_ERROR otherwise.
 * Prevents CPU exhaustion from excessive symlink traversal or deep nesting.
 */
ngx_int_t xrootd_count_path_depth(const char *path);

/* Format the ASCII stat body: "<id> <size> <flags> <mtime>".
 * extra_flags is OR-ed into the computed flags field — pass kXR_cachersp
 * when the file is known to live in the local read-through cache. */
void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    int extra_flags, char *out, size_t outsz);

/* Write one line to the module access log file. */
void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);

/* Phase 33 C1: flush the per-worker batched access-log buffer to disk.  Called
 * on connection close (xrootd_on_disconnect) so a session's lines are durable
 * once it ends; also invoked internally on buffer-full, fd-switch, and a 1s
 * timer.  Safe to call when nothing is buffered (no-op). */
void xrootd_access_log_flush(void);

#endif /* XROOTD_PATH_H */
