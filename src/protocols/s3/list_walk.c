/*
 * list_walk.c — S3 ListObjects filesystem walker, comparator, and lazy stat.
 *
 * WHAT: Three functions used by the V1/V2 list emitters
 *   (list_objects_v2.c / list_objects_v1.c):
 *   - s3_walk(): recursive directory walker that appends object (is_prefix=0)
 *     and CommonPrefix (is_prefix=1) entries into a growable array, respecting
 *     prefix, delimiter, and sentinel filters.
 *   - entry_cmp(): qsort comparator for lexicographic key ordering.
 *   - s3_entry_fill_stat(): lazily fill size/mtime/ETag for ONE emitted object.
 *
 * WHY (phase-45 W1): the previous walker `lstat`'d EVERY entry in the whole
 *   prefix subtree and stored them in a fixed `s3_entry_t[65536]` (~273 MB per
 *   request, key[4096] inline) — both costs grew with the bucket, not the page.
 *   ListObjects requires a globally-sorted key set to paginate, so the *names*
 *   must still be walked; but `size`/`mtime`/`ETag` are only needed for the
 *   ≤max-keys objects actually emitted. So this walker:
 *     1. classifies dir/file/symlink from readdir's `d_type` with NO stat
 *        (an `lstat` fallback only on `DT_UNKNOWN`, e.g. some NFS mounts), and
 *     2. collects only a pooled, right-sized key + the is_prefix flag,
 *   and the caller `lstat`s just the emitted page slice via s3_entry_fill_stat().
 *   → `lstat` count drops from O(objects in subtree) to O(page); the entry
 *   store drops from a fixed 273 MB to O(actual key bytes).
 *
 * The symlink-skip security property is preserved: a `DT_LNK` entry is skipped
 * outright, and a `DT_UNKNOWN` entry is `lstat`'d and skipped if `S_ISLNK` — a
 * symlink is never listed as an object nor recursed into (it could otherwise
 * leak another tenant's tree or the host filesystem).
 */


#include "s3.h"
#include "core/compat/fs_walk.h"
#include "fs/vfs/vfs.h"   /* confined walk via vfs_opendir_quiet/readdir_kind/probe */
#include "fs/path/path.h"   /* brix_dirlist_access_ok (impersonation list gate) */
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include <errno.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>
#include "core/compat/alloc_guard.h"

/*
 * qsort comparator — lexicographic key order
 * */

int
entry_cmp(const void *a, const void *b)
{
    return strcmp(((const s3_entry_t *) a)->key,
                  ((const s3_entry_t *) b)->key);
}

/*
 * Push a (pooled, right-sized) key into the growable entry array
 * */

static int
s3_walk_push(ngx_array_t *entries, const char *key, unsigned is_prefix)
{
    size_t       len = strlen(key);
    char        *kdup;
    s3_entry_t  *e;

    BRIX_PNALLOC_OR_RETURN(kdup, entries->pool, len + 1, -1);
    ngx_memcpy(kdup, key, len + 1);

    e = ngx_array_push(entries);
    if (e == NULL) {
        return -1;
    }
    e->key       = kdup;
    e->is_prefix = is_prefix;
    e->size      = 0;
    e->mtime     = 0;
    e->etag[0]   = '\0';
    return 0;
}

/*
 * Classify a directory entry: 1 = dir, 2 = regular file, 0 = skip.
 * Uses readdir d_type (no syscall); falls back to a confined lstat only on
 * DT_UNKNOWN.  Symlinks (and FIFO/SOCK/CHR/BLK) are skipped.
 * */

static int
s3_walk_classify(ngx_pool_t *pool, ngx_log_t *log, const char *root,
    const char *child_path, brix_vfs_dirent_kind_t dkind)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;

    switch (dkind) {
    case BRIX_VFS_DT_DIR:
        return 1;
    case BRIX_VFS_DT_REG:
        return 2;
    case BRIX_VFS_DT_OTHER:
        return 0;   /* symlink / special: never list or traverse */
    case BRIX_VFS_DT_UNKNOWN:
    default:
        /* The filesystem did not populate d_type (e.g. some NFS mounts): classify
         * via a confined no-follow probe (non-metered — the ListObjects op already
         * accounts for the walk). A symlink/special stats as neither dir nor
         * regular and is skipped, preserving the symlink-skip security property. */
        brix_vfs_ctx_init(&vctx, pool, log, BRIX_PROTO_S3, root, NULL,
            0 /* allow_write */, 0 /* is_tls */, NULL, child_path);
        if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK) {
            return 0;
        }
        if (vst.is_directory) {
            return 1;
        }
        if (vst.is_regular) {
            return 2;
        }
        return 0;
    }
}

/*
 * s3_walk_ctx_t — the invariant parameters of one recursive ListObjects walk.
 *
 * WHAT: bundles the eight fixed inputs of s3_walk() (log, root, the two prefix
 *   filters + their cached lengths, the delimiter, the output array, and the
 *   entry cap) so the recursion and the per-entry helpers pass ONE pointer
 *   instead of an eight-argument list.
 * WHY: s3_walk()'s public signature is frozen (recursive + an out-of-file
 *   caller in list_common.c), but its internal fan-out — path build, classify,
 *   directory emit, file emit — repeated the same eight values on every call
 *   and inflated cyclomatic complexity. A file-local context lets those helpers
 *   take (ctx, per-entry args) and keeps the walk loop flat.
 * HOW: s3_walk() populates it once (caching filter_prefix / delimiter lengths,
 *   which are constant across the whole recursion) and hands &ctx to
 *   s3_walk_run(); dir_path / key_prefix stay per-call arguments because they
 *   change at each recursion level.
 */
typedef struct {
    ngx_log_t   *log;            /* request log (for the access gate)  */
    const char  *root;           /* filesystem root (== root_canon)    */
    const char  *filter_prefix;  /* ListObjects prefix param (or NULL) */
    const char  *delimiter;      /* hierarchy delimiter (or NULL)      */
    size_t       fp_len;         /* strlen(filter_prefix), cached      */
    size_t       del_len;        /* strlen(delimiter), cached          */
    ngx_array_t *entries;        /* growable output array              */
    int          max_entries;    /* hard cap on entries                */
} s3_walk_ctx_t;


static int s3_walk_run(s3_walk_ctx_t *ctx, const char *dir_path,
    const char *key_prefix);


/*
 * s3_child_paths_t — the two fixed-size buffers built per directory entry.
 *
 * WHAT: pairs the filesystem child path (PATH_MAX) with the root-relative S3
 *   key (S3_MAX_KEY) that s3_walk_build_paths() fills for one readdir entry.
 * WHY: bundling the two output buffers into one out-param keeps
 *   s3_walk_build_paths() within the 5-parameter budget while preserving the
 *   caller-owned, stack-allocated storage (no extra allocation).
 * HOW: the caller declares one on the stack and passes its address; the buffer
 *   sizes are the struct's array bounds, so no size arguments are needed.
 */
typedef struct {
    char  path[PATH_MAX];    /* "<dir_path>/<dname>"           */
    char  key[S3_MAX_KEY];   /* root-relative object/prefix key */
} s3_child_paths_t;


/*
 * Build the child filesystem path and S3 key for one directory entry.
 *
 * WHAT: writes "<dir_path>/<dname>" into out->path and the root-relative key
 *   into out->key.  Returns 0 on success, -1 if either buffer would overflow
 *   (the caller then skips this entry, matching the original inline behaviour).
 * WHY: hoists two bounds-checked snprintf/memcpy blocks out of the walk loop so
 *   the loop reads as classify → emit without truncation noise.
 * HOW: out->path is always "<dir_path>/<dname>"; out->key is
 *   "<key_prefix>/<dname>" at depth, or the bare name at the bucket root
 *   (key_prefix == "").  name carries the pre-measured length for the root case.
 */
static int
s3_walk_build_paths(const char *dir_path, const char *key_prefix,
    const ngx_str_t *name, s3_child_paths_t *out)
{
    const char *dname = (const char *) name->data;

    if ((size_t) snprintf(out->path, sizeof(out->path), "%s/%s",
                          dir_path, dname) >= sizeof(out->path)) {
        return -1;
    }

    if (key_prefix[0] != '\0') {
        if ((size_t) snprintf(out->key, sizeof(out->key), "%s/%s",
                              key_prefix, dname) >= sizeof(out->key)) {
            return -1;
        }
    } else {
        if (name->len >= sizeof(out->key)) {
            return -1;
        }
        memcpy(out->key, dname, name->len + 1);
    }
    return 0;
}


/*
 * Handle a directory entry: recurse into it or emit it as a CommonPrefix.
 *
 * WHAT: for kind==1 (directory) entries.  With no delimiter, recurses
 *   unconditionally.  With a delimiter, either recurses (when the user prefix
 *   descends into this dir) or emits "<key>/" as a CommonPrefix if it matches
 *   the filter.  Returns 0 to continue the loop, -1 on a push failure (which
 *   stops the walk, as before).
 * WHY: isolates the directory branch (the deepest nesting in the old loop) into
 *   one named step with early-return over the nested-if pyramid.
 * HOW: CommonPrefix carries no size/mtime/etag (S3 spec) so no stat is done;
 *   recursion re-uses the shared ctx and only advances dir_path/child_key.
 */
static int
s3_walk_emit_dir(s3_walk_ctx_t *ctx, const char *child_path,
    const char *child_key)
{
    char    prefix_entry[S3_MAX_KEY];
    size_t  pe_len;

    if (ctx->del_len == 0) {
        /* No delimiter: recurse unconditionally. */
        s3_walk_run(ctx, child_path, child_key);
        return 0;
    }

    /* Build "dir_key/" to check against filter_prefix. */
    if ((size_t) snprintf(prefix_entry, sizeof(prefix_entry), "%s/", child_key)
        >= sizeof(prefix_entry)) {
        return 0;   /* truncated → skip this entry */
    }
    pe_len = strlen(prefix_entry);

    /*
     * Recurse if filter_prefix starts with this dir (i.e. the user-supplied
     * prefix descends into this directory).
     */
    if (ctx->fp_len > 0 && ctx->fp_len >= pe_len
        && strncmp(ctx->filter_prefix, prefix_entry, pe_len) == 0) {
        s3_walk_run(ctx, child_path, child_key);
        return 0;
    }

    /* Emit as CommonPrefix if it matches or starts with filter. */
    if (ctx->fp_len > 0
        && strncmp(prefix_entry, ctx->filter_prefix, ctx->fp_len) != 0) {
        return 0;
    }
    /* CommonPrefix carries no size/mtime/etag (S3 spec) — no stat. */
    if (s3_walk_push(ctx->entries, prefix_entry, 1) != 0) {
        return -1;
    }
    return 0;
}


/*
 * Handle a regular-file entry: apply the object filters and push the key.
 *
 * WHAT: for kind==2 (regular file) entries.  Skips the directory sentinel and
 *   internal sidecar/staging names, applies the prefix filter, and (with a
 *   delimiter) skips keys that carry a delimiter after the prefix (they belong
 *   under a CommonPrefix subtree).  Returns 0 to continue, -1 on push failure.
 * WHY: isolates the file branch so the walk loop stays flat; keeps the sentinel
 *   / internal-name / prefix / delimiter filter order byte-identical to the
 *   original so the emitted key set is unchanged.
 * HOW: collects the key only (phase-45 W1); size/mtime/etag are filled lazily
 *   for the emitted page via s3_entry_fill_stat().
 */
static int
s3_walk_emit_file(s3_walk_ctx_t *ctx, const char *child_key,
    const char *dname)
{
    /* Skip directory sentinel. */
    if (strcmp(dname, S3_DIR_SENTINEL) == 0) {
        return 0;
    }
    /* Hide internal metadata/staging artifacts (sidecars, upload temps) —
     * never listable as an S3 object key. */
    if (brix_is_internal_name(dname)) {
        return 0;
    }
    /* Filter by prefix. */
    if (ctx->fp_len > 0
        && strncmp(child_key, ctx->filter_prefix, ctx->fp_len) != 0) {
        return 0;
    }
    /* With delimiter, skip entries that have a delimiter after prefix
     * (they belong under a CommonPrefix subtree, not at this level). */
    if (ctx->del_len > 0) {
        const char *after_prefix = child_key + ctx->fp_len;
        if (strstr(after_prefix, ctx->delimiter) != NULL) {
            return 0;
        }
    }

    /* phase-45 W1: collect the key only; size/mtime/etag are filled lazily for
     * the emitted page via s3_entry_fill_stat(). */
    if (s3_walk_push(ctx->entries, child_key, 0) != 0) {
        return -1;
    }
    return 0;
}


/*
 * Process one readdir entry: build paths, classify, dispatch to dir/file emit.
 *
 * WHAT: given a readdir name+kind, computes the child path/key, classifies it
 *   (dir / regular file / skip), and routes to s3_walk_emit_dir or
 *   s3_walk_emit_file.  Returns 0 to continue the loop, -1 to stop it.
 * WHY: one nameable step per entry keeps s3_walk_run's loop to open → read →
 *   process, removing the branch nesting that drove the CCN warning.
 * HOW: symlinks/specials classify as kind==0 and are skipped, preserving the
 *   symlink-skip security property.
 */
static int
s3_walk_entry(s3_walk_ctx_t *ctx, const char *dir_path, const char *key_prefix,
    const ngx_str_t *name, brix_vfs_dirent_kind_t dkind)
{
    s3_child_paths_t  cp;
    const char       *dname = (const char *) name->data;
    int               kind;

    if (s3_walk_build_paths(dir_path, key_prefix, name, &cp) != 0) {
        return 0;   /* path/key truncation → skip this entry */
    }

    /*
     * Classify from the readdir d_type (no stat); a confined no-follow probe is
     * used only on DT_UNKNOWN.  Symlinks/specials are skipped (kind==0).
     */
    kind = s3_walk_classify(ctx->entries->pool, ctx->log, ctx->root,
                            cp.path, dkind);
    if (kind == 0) {
        return 0;
    }
    if (kind == 1) {
        return s3_walk_emit_dir(ctx, cp.path, cp.key);
    }
    return s3_walk_emit_file(ctx, cp.key, dname);
}


/*
 * Recursive walk core — open one directory and process its entries.
 *
 * WHAT: enforces the impersonation list gate, opens dir_path through the VFS,
 *   and loops readdir → s3_walk_entry until end-of-dir, the entry cap, or a
 *   push failure.  Returns the running entry count.
 * WHY: carries the recursion (s3_walk_emit_dir calls back into it) while
 *   s3_walk() stays a thin public wrapper with the frozen 8-arg signature.
 * HOW: uses the NON-METERED opendir so a recursive ListObjects does not emit an
 *   OP_DIRLIST per visited subdirectory (the enclosing S3 list op accounts for
 *   the whole walk).
 */
static int
s3_walk_run(s3_walk_ctx_t *ctx, const char *dir_path, const char *key_prefix)
{
    brix_vfs_ctx_t   wctx;
    brix_vfs_dir_t  *dh;

    /*
     * Phase 40 confidentiality gate: under impersonation the worker uid may be
     * able to readdir() a directory the MAPPED user cannot.  Ask the broker to
     * open it as the mapped user first; on denial skip the whole subtree rather
     * than enumerate it with the worker's credentials.  No-op when off.
     */
    if (brix_dirlist_access_ok(ctx->log, ctx->root, dir_path) != NGX_OK) {
        return (int) ctx->entries->nelts;
    }

    /* Enumerate through the VFS (broker fdopendir under impersonation), using
     * the NON-METERED opendir. */
    brix_vfs_ctx_init(&wctx, ctx->entries->pool, ctx->log, BRIX_PROTO_S3,
        ctx->root, NULL, 0 /* allow_write */, 0 /* is_tls */, NULL, dir_path);
    dh = brix_vfs_opendir_quiet(&wctx, NULL);
    if (dh == NULL) {
        return (int) ctx->entries->nelts;
    }

    for ( ;; ) {
        ngx_str_t                name;
        brix_vfs_dirent_kind_t   dkind;
        ngx_int_t                rrc;

        if ((int) ctx->entries->nelts >= ctx->max_entries) {
            break;
        }
        /* "." / ".." are filtered by brix_vfs_readdir_kind; the entry kind
         * comes from d_type so the fast path needs no per-entry stat. */
        rrc = brix_vfs_readdir_kind(dh, &name, &dkind);
        if (rrc != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop with what we have */
        }

        if (s3_walk_entry(ctx, dir_path, key_prefix, &name, dkind) != 0) {
            break;   /* push failure → stop with what we have */
        }
    }

    brix_vfs_closedir(dh, ctx->log);
    return (int) ctx->entries->nelts;
}


/*
 * Recursive directory walker — appends entries, returns the running total
 * */

int
s3_walk(ngx_log_t  *log,           /* request log (for the access gate)   */
        const char *root,          /* filesystem root (== root_canon)     */
        const char *dir_path,      /* filesystem path to scan    */
        const char *key_prefix,    /* key prefix so far          */
        const char *filter_prefix, /* ListObjects prefix param   */
        const char *delimiter,     /* hierarchy delimiter        */
        ngx_array_t *entries,      /* growable output array      */
        int         max_entries)   /* hard cap on entries        */
{
    s3_walk_ctx_t  ctx;

    ngx_memzero(&ctx, sizeof(ctx));
    ctx.log           = log;
    ctx.root          = root;
    ctx.filter_prefix = filter_prefix;
    ctx.delimiter     = delimiter;
    /* Cache lengths once — avoids repeated strlen() in the readdir loop. */
    ctx.fp_len        = filter_prefix ? strlen(filter_prefix) : 0;
    ctx.del_len       = delimiter     ? strlen(delimiter)      : 0;
    ctx.entries       = entries;
    ctx.max_entries   = max_entries;

    return s3_walk_run(&ctx, dir_path, key_prefix);
}

/*
 * Lazy per-object stat — called only for the entries actually emitted
 * */

ngx_int_t
s3_entry_fill_stat(ngx_pool_t *pool, ngx_log_t *log, const char *root,
    s3_entry_t *e)
{
    char              fs_path[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    struct stat       sb;

    if (e->is_prefix) {
        return NGX_OK;   /* CommonPrefix: no size/mtime/etag */
    }

    /* The walk built keys relative to root, so the filesystem path of an object
     * is always root + "/" + key (see s3_walk's child_path/child_key). */
    if ((size_t) snprintf(fs_path, sizeof(fs_path), "%s/%s", root, e->key)
        >= sizeof(fs_path)) {
        return NGX_DECLINED;
    }

    /* Confined no-follow probe (non-metered — the ListObjects op accounts for
     * the page): if the entry vanished or is no longer a regular file (e.g.
     * swapped for a symlink after the walk), skip it — matching the eager
     * walker's stat-failure / symlink skip. */
    brix_vfs_ctx_init(&vctx, pool, log, BRIX_PROTO_S3, root, NULL,
        0 /* allow_write */, 0 /* is_tls */, NULL, fs_path);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK
        || !vst.is_regular) {
        return NGX_DECLINED;
    }

    e->size  = vst.size;
    e->mtime = vst.mtime;
    ngx_memzero(&sb, sizeof(sb));
    sb.st_size  = vst.size;
    sb.st_mtime = vst.mtime;
    s3_etag(&sb, e->etag, sizeof(e->etag));
    return NGX_OK;
}
