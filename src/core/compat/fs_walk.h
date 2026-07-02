#ifndef XROOTD_COMPAT_FS_WALK_H
#define XROOTD_COMPAT_FS_WALK_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * xrootd_fs_walk_entry_t — directory walk entry passed to callback.
 *
 * WHAT: Struct containing path, name, stat info, and recursion depth for each file/directory
 *      encountered during traversal. WHY: Callback functions need all metadata about the entry
 *      without requiring separate syscalls. */

typedef struct {
    const char        *path;
    const char        *name;
    const struct stat *st;
    ngx_uint_t         depth;
} xrootd_fs_walk_entry_t;

/*
 * xrootd_fs_walk_pt — callback function type for recursive directory walk.
 *
 * WHAT: Function pointer invoked for each entry during xrootd_fs_walk(). WHY: Callers supply
 *      custom logic (dirlist emission, PROPFIND property collection, tree removal) via callback. */

typedef ngx_int_t (*xrootd_fs_walk_pt)(const xrootd_fs_walk_entry_t *entry,
    void *data);

/*
 * xrootd_fs_walk_options_t — configuration for recursive directory walk.
 *
 * WHAT: Struct controlling max_depth (0=unlimited), include_files/dirs filters, hidden entry
 *      skip, cross-device traversal restriction via root_dev. WHY: dirlist/PROPFIND/remove-tree
 *      have different filtering needs; this struct unifies options across callers. */

typedef struct {
    ngx_uint_t max_depth;
    ngx_flag_t include_files;
    ngx_flag_t include_dirs;
    ngx_flag_t skip_hidden;
    ngx_flag_t stay_on_device;
    dev_t      root_dev;
} xrootd_fs_walk_options_t;

/*
 * xrootd_fs_is_dot_entry — check if name is "." or "..".
 *
 * WHAT: Returns NGX_TRUE for dot entries, NGX_FALSE otherwise. WHY: All traversal loops skip dots.
 * HOW: name[0]=='.' && (name[1]=='\0' || name[1]=='.' && name[2]=='\0'). */

ngx_flag_t xrootd_fs_is_dot_entry(const char *name);

/*
 * xrootd_fs_join_path — concatenate dir + '/' + name into out buffer.
 *
 * WHAT: Writes "dir/name" via snprintf, returns NGX_OK/NGX_ERROR on truncation. WHY: Traversal
 *      builds child paths from parent directory and entry name. */

ngx_int_t xrootd_fs_join_path(const char *dir, const char *name,
    char *out, size_t outsz);

/*
 * xrootd_fs_dir_is_empty — check if directory contains non-dot entries.
 *
 * WHAT: Sets *is_empty=1 for empty dir or no non-dot entries, 0 otherwise. WHY: XRootD stat on
 *      collection returns emptiness; WebDAV MKCOL checks target emptiness. */

ngx_int_t xrootd_fs_dir_is_empty(const char *path, ngx_flag_t *is_empty);

/*
 * xrootd_fs_walk — recursive directory walk with callback and options.
 *
 * WHAT: Validates start_path then delegates to internal walk_dir() at depth 1, calling cb(entry)
 *      for each matching entry in the tree. WHY: Convenience entry point for callers needing full
 *      directory traversal without managing recursion themselves. */

ngx_int_t xrootd_fs_walk(ngx_log_t *log, const char *start_path,
    const xrootd_fs_walk_options_t *opts, xrootd_fs_walk_pt cb, void *data);

/*
 * xrootd_fs_remove_tree_confined — recursively delete tree confined to root_canon.
 *
 * WHAT: Opens path, iterates entries (skip dots), recurses into subdirs, unlinks files via
 *      xrootd_unlink_confined_canon(), then rmdir the directory itself. WHY: DEL/MOVE/COPY on
 *      collections requires recursive child deletion with confined boundary check. */

ngx_int_t xrootd_fs_remove_tree_confined(ngx_log_t *log,
    const char *root_canon, const char *path);

#endif /* XROOTD_COMPAT_FS_WALK_H */
