#ifndef BRIX_COMPAT_FS_WALK_H
#define BRIX_COMPAT_FS_WALK_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * BRIX_FS_TREE_MAX_DEPTH — hard recursion-depth ceiling for the confined tree
 * ops that recurse on the C stack independently of the max_depth-capped
 * vfs_walk_dir(): brix_fs_remove_tree_confined(), brix_vfs_copytree(), and the
 * driver-level brix_vfs_driver_rmtree().  Without it, an attacker-nested
 * directory tree (deep MKCOL/PUT nesting) drives unbounded recursion into a
 * worker stack overflow — a crash-class DoS (D-6/T2).  A hostile tree past this
 * depth must abort with an error, not fault.  Each frame carries a few KiB of
 * on-stack path buffers, so 512 levels stays well inside an 8 MiB worker stack
 * while dwarfing any legitimate collection depth (the ingress path already caps
 * a single request at 32 components).
 */
#define BRIX_FS_TREE_MAX_DEPTH  512

/*
 * brix_fs_walk_entry_t — directory walk entry passed to callback.
 *
 * WHAT: Struct containing path, name, stat info, and recursion depth for each file/directory
 *      encountered during traversal. WHY: Callback functions need all metadata about the entry
 *      without requiring separate syscalls. */

typedef struct {
    const char        *path;
    const char        *name;
    const struct stat *st;
    ngx_uint_t         depth;
} brix_fs_walk_entry_t;

/*
 * brix_fs_walk_pt — callback function type for recursive directory walk.
 *
 * WHAT: Function pointer invoked for each entry during brix_fs_walk(). WHY: Callers supply
 *      custom logic (dirlist emission, PROPFIND property collection, tree removal) via callback. */

typedef ngx_int_t (*brix_fs_walk_pt)(const brix_fs_walk_entry_t *entry,
    void *data);

/*
 * brix_fs_walk_options_t — configuration for recursive directory walk.
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
} brix_fs_walk_options_t;

/*
 * brix_fs_is_dot_entry — check if name is "." or "..".
 *
 * WHAT: Returns NGX_TRUE for dot entries, NGX_FALSE otherwise. WHY: All traversal loops skip dots.
 * HOW: name[0]=='.' && (name[1]=='\0' || name[1]=='.' && name[2]=='\0'). */

ngx_flag_t brix_fs_is_dot_entry(const char *name);

/*
 * brix_fs_join_path — concatenate dir + '/' + name into out buffer.
 *
 * WHAT: Writes "dir/name" via snprintf, returns NGX_OK/NGX_ERROR on truncation. WHY: Traversal
 *      builds child paths from parent directory and entry name. */

ngx_int_t brix_fs_join_path(const char *dir, const char *name,
    char *out, size_t outsz);

/*
 * brix_fs_dir_is_empty — check if directory contains non-dot entries.
 *
 * WHAT: Sets *is_empty=1 for empty dir or no non-dot entries, 0 otherwise. WHY: XRootD stat on
 *      collection returns emptiness; WebDAV MKCOL checks target emptiness. */

ngx_int_t brix_fs_dir_is_empty(const char *path, ngx_flag_t *is_empty);

/*
 * brix_fs_walk — recursive directory walk with callback and options.
 *
 * WHAT: Validates start_path then delegates to internal walk_dir() at depth 1, calling cb(entry)
 *      for each matching entry in the tree. WHY: Convenience entry point for callers needing full
 *      directory traversal without managing recursion themselves. */

ngx_int_t brix_fs_walk(ngx_log_t *log, const char *start_path,
    const brix_fs_walk_options_t *opts, brix_fs_walk_pt cb, void *data);

/*
 * brix_fs_remove_tree_confined — recursively delete tree confined to root_canon.
 *
 * WHAT: Opens path, iterates entries (skip dots), recurses into subdirs, unlinks files via
 *      brix_unlink_confined_canon(), then rmdir the directory itself. WHY: DEL/MOVE/COPY on
 *      collections requires recursive child deletion with confined boundary check. */

ngx_int_t brix_fs_remove_tree_confined(ngx_log_t *log,
    const char *root_canon, const char *path);

#endif /* BRIX_COMPAT_FS_WALK_H */
