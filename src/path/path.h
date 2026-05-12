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
ngx_int_t xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
ngx_int_t xrootd_finalize_authdb_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
ngx_int_t xrootd_finalize_group_rules(ngx_log_t *log,
    const ngx_str_t *root, ngx_array_t *rules);

/* Longest-prefix rule lookups (VO ACL and group policy). */
const xrootd_vo_rule_t *xrootd_find_vo_rule(const char *resolved_path,
    ngx_array_t *rules);
const xrootd_authdb_rule_t *xrootd_find_authdb_rule(const char *resolved_path,
    ngx_array_t *rules, xrootd_ctx_t *ctx, uint32_t needed_privs);
const xrootd_group_rule_t *xrootd_find_group_rule(
    const char *resolved_path, ngx_array_t *rules);

/* Test whether <required_vo> appears in a space-separated <vo_list>. */
ngx_flag_t xrootd_vo_list_contains(const char *vo_list,
    const char *required_vo);

/* Check the VO ACL for a resolved path; returns NGX_OK or NGX_DECLINED. */
ngx_int_t xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
    ngx_array_t *vo_rules, const char *vo_list);

/* Check the Authdb for a resolved path; returns NGX_OK or NGX_ERROR. */
ngx_int_t xrootd_check_authdb(xrootd_ctx_t *ctx, const char *resolved_path,
    uint32_t needed_privs);

/* Parse an XRootD authdb file into rules. */
ngx_int_t xrootd_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename,
    ngx_array_t *rules);

/* Apply parent-directory group ownership policy (chown GID). */
ngx_int_t xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd,
    const char *path, ngx_array_t *rules);
ngx_int_t xrootd_apply_parent_group_policy_path(ngx_log_t *log,
    const char *path, ngx_array_t *rules);

/*
 * Resolve a client-supplied path to an absolute path under <root>.
 * _noexist: allows non-existent final component (for creates).
 * _write:   additionally checks that the path is writable.
 * Returns 0 on success, -1 on error (errno set or log message emitted).
 */
int xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
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
int xrootd_open_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int flags, mode_t mode);
int xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
int xrootd_unlink_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, int is_dir);
int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
int xrootd_mkdir_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, mode_t mode);
int xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
int xrootd_rename_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *src_resolved, const char *dst_resolved);
int xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
int xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/* Extract a NUL-terminated path from a raw XRootD request payload. */
int xrootd_extract_path(ngx_log_t *log, const u_char *payload,
    size_t payload_len, char *out, size_t outsz, ngx_flag_t strip_cgi);

/* Recursively create directory <path> with mode <mode>. */
int xrootd_mkdir_recursive(const char *path, mode_t mode);
int xrootd_mkdir_recursive_policy(const char *path, mode_t mode,
    ngx_log_t *log, ngx_array_t *rules);
int xrootd_mkdir_recursive_confined(ngx_log_t *log, const ngx_str_t *root,
    const char *resolved, mode_t mode, ngx_array_t *rules);

/* Strip CGI query string from a path (modifies out in-place). */
void xrootd_strip_cgi(const char *in, char *out, size_t outsz);

/* Format the ASCII stat body: "<id> <size> <flags> <mtime>".
 * extra_flags is OR-ed into the computed flags field — pass kXR_cachersp
 * when the file is known to live in the local read-through cache. */
void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    int extra_flags, char *out, size_t outsz);

/* Write one line to the module access log file. */
void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);

#endif /* XROOTD_PATH_H */
