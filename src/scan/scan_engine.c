/*
 * scan_engine.c — VFS-driven walk + per-object action (see scan_engine.h).
 *
 * Mirrors the proven xrootd_ckscan_run() shape: a confined xrootd_vfs_walk fires
 * a per-file callback that runs the mode action and appends one NDJSON record to
 * a growing heap buffer. Runs on a thread-pool worker (heap, not pool).
 */
#include "scan_engine.h"

#include "../compat/integrity_info.h"
#include "../fs/vfs.h"
#include "../protocol/opcodes.h"

#include <limits.h>
#include <string.h>
#include <strings.h>

/* One NDJSON line = JSON record (≤ SCAN record sizing) + '\n'. */
#define SCAN_LINE_MAX 3072

/* Render the walk's internal logical path (anchored at "." or a relative
 * subdir) as a clean, root-relative display path: "." → "/", "./a/b" → "/a/b",
 * "sub/x" → "/sub/x". The integrity layer keys on the fd, not this string. */
static void
scan_display_path(const char *logical, char *out, size_t outsz)
{
    const char *p = logical;

    if (p[0] == '.' && p[1] == '/') {
        p += 2;
    } else if (p[0] == '.' && p[1] == '\0') {
        p += 1;
    }
    snprintf(out, outsz, "/%s", p);
}

ngx_int_t
xrootd_scan_mode_parse(const char *name, xrootd_scan_mode_t *out)
{
    if (strcmp(name, "dump") == 0)    { *out = XROOTD_SCAN_DUMP;    return NGX_OK; }
    if (strcmp(name, "verify") == 0)  { *out = XROOTD_SCAN_VERIFY;  return NGX_OK; }
    if (strcmp(name, "fill") == 0)    { *out = XROOTD_SCAN_FILL;    return NGX_OK; }
    if (strcmp(name, "compare") == 0) { *out = XROOTD_SCAN_COMPARE; return NGX_OK; }
    if (strcmp(name, "inspect") == 0) { *out = XROOTD_SCAN_INSPECT; return NGX_OK; }
    return NGX_ERROR;
}

/* Append a ready NDJSON line (llen bytes) plus a newline to the growing heap
 * buffer. Returns 1 ok, -1 OOM (caller owns *buf on failure). Mirrors
 * xrootd_ckscan_append's exponential growth. */
static int
scan_append(u_char **buf, size_t *cap, size_t *used, const char *line, size_t llen)
{
    if (*used + llen + 2 > *cap) {
        size_t  new_cap = *cap * 2 + llen + 2;
        u_char *nb = ngx_alloc(new_cap, ngx_cycle->log);

        if (nb == NULL) {
            return -1;
        }
        if (*buf != NULL) {
            ngx_memcpy(nb, *buf, *used);
            ngx_free(*buf);
        }
        *buf = nb;
        *cap = new_cap;
    }
    ngx_memcpy(*buf + *used, line, llen);
    *used += llen;
    (*buf)[(*used)++] = '\n';
    return 0;
}

typedef struct {
    ngx_log_t                  *log;
    const xrootd_scan_opts_t   *opts;
    u_char                    **buf;
    size_t                     *cap;
    size_t                     *used;
    xrootd_scan_summary_t      *sum;
    int                         oom;
} scan_walk_ctx_t;

/* Look up the stored (cached) checksum without computing. Returns the hex on a
 * cache hit (into `info`), or NULL on miss. */
static const char *
scan_stored(scan_walk_ctx_t *cc, int fd, const char *logical,
            xrootd_integrity_info_t *info)
{
    xrootd_integrity_opts_t io;

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 1;
    io.no_compute = 1;
    if (xrootd_integrity_get_fd(cc->log, fd, NULL, logical, cc->opts->alg,
                                &io, info) == NGX_OK)
    {
        return info->hex;
    }
    return NULL;
}

/* dump / compare: emit stored checksum (or null), never read bytes. */
static int
scan_action_dump(scan_walk_ctx_t *cc, const char *logical, off_t size,
                 time_t mtime, int fd, char *line, size_t linesz)
{
    xrootd_integrity_info_t info;
    const char             *stored = scan_stored(cc, fd, logical, &info);
    int                     n;

    n = xrootd_scan_record_file(line, linesz, logical, (int64_t) size,
                                (int64_t) mtime, cc->opts->alg, stored, NULL, "ok");
    cc->sum->ok++;
    return n;
}

/* verify: recompute and compare to stored. */
static int
scan_action_verify(scan_walk_ctx_t *cc, const char *logical, off_t size,
                   time_t mtime, int fd, char *line, size_t linesz)
{
    xrootd_integrity_info_t stored_info, comp_info;
    const char             *stored;
    xrootd_integrity_opts_t io;
    const char             *status;
    const char             *computed = NULL;
    char                    stored_copy[129];

    stored = scan_stored(cc, fd, logical, &stored_info);
    if (stored != NULL) {
        ngx_memcpy(stored_copy, stored, ngx_strlen(stored) + 1);
        stored = stored_copy;   /* survive the second get_fd's info reuse */
    }

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 0;   /* force a fresh compute over the bytes */
    io.no_compute = 0;
    if (xrootd_integrity_get_fd(cc->log, fd, NULL, logical, cc->opts->alg,
                                &io, &comp_info) != NGX_OK)
    {
        status = "unreadable";
        cc->sum->unreadable++;
    } else {
        computed = comp_info.hex;
        cc->sum->bytes += (uint64_t) size;
        if (stored == NULL) {
            status = "missing";
            cc->sum->missing++;
        } else if (strcasecmp(stored, computed) == 0) {
            status = "ok";
            cc->sum->ok++;
        } else {
            status = "mismatch";
            cc->sum->mismatch++;
        }
    }
    return xrootd_scan_record_file(line, linesz, logical, (int64_t) size,
                                   (int64_t) mtime, cc->opts->alg, stored,
                                   computed, status);
}

/* fill: persist a checksum only when none is stored. */
static int
scan_action_fill(scan_walk_ctx_t *cc, const char *logical, off_t size,
                 time_t mtime, int fd, char *line, size_t linesz)
{
    xrootd_integrity_info_t info;
    xrootd_integrity_opts_t io;
    const char             *status;
    const char             *stored;

    stored = scan_stored(cc, fd, logical, &info);
    if (stored != NULL) {
        status = "already";
        cc->sum->already++;
        return xrootd_scan_record_file(line, linesz, logical, (int64_t) size,
                                       (int64_t) mtime, cc->opts->alg, stored,
                                       NULL, status);
    }

    ngx_memzero(&io, sizeof(io));
    io.allow_xattr_cache = 1;   /* required alongside update for the persist path */
    io.update_xattr_cache = 1;
    io.no_compute = 0;
    if (xrootd_integrity_get_fd(cc->log, fd, NULL, logical, cc->opts->alg,
                                &io, &info) != NGX_OK)
    {
        status = "unreadable";
        stored = NULL;
        cc->sum->unreadable++;
    } else {
        status = "filled";
        stored = info.hex;
        cc->sum->filled++;
        cc->sum->bytes += (uint64_t) size;
    }
    return xrootd_scan_record_file(line, linesz, logical, (int64_t) size,
                                   (int64_t) mtime, cc->opts->alg, stored,
                                   NULL, status);
}

/* inspect (A2): per-file backend introspection. The scan endpoint walks the
 * export root via POSIX openat2 (not the SD-driver seam), so the backend is
 * "posix" and namespace==backend by construction; the driver-bound view
 * (Ceph object key, cluster facts) is a Phase-4 prerequisite. */
static int
scan_action_inspect(scan_walk_ctx_t *cc, const char *logical, off_t size,
                    time_t mtime, int fd, char *line, size_t linesz)
{
    xrootd_integrity_info_t info;
    const char             *stored = scan_stored(cc, fd, logical, &info);

    cc->sum->ok++;
    return xrootd_scan_record_inspect(line, linesz, logical, "posix",
                                      (int64_t) size, (int64_t) mtime,
                                      stored != NULL ? "xattr" : "none",
                                      1 /* posix: namespace == backend */);
}

static ngx_int_t
scan_walk_file(void *cookie, const char *logical, const xrootd_vfs_stat_t *st,
               int fd)
{
    scan_walk_ctx_t *cc = cookie;
    char             line[SCAN_LINE_MAX];
    char             disp[PATH_MAX];
    int              n;

    scan_display_path(logical, disp, sizeof(disp));

    switch (cc->opts->mode) {
    case XROOTD_SCAN_VERIFY:
        n = scan_action_verify(cc, disp, st->size, st->mtime, fd, line,
                               sizeof(line));
        break;
    case XROOTD_SCAN_FILL:
        n = scan_action_fill(cc, disp, st->size, st->mtime, fd, line,
                             sizeof(line));
        break;
    case XROOTD_SCAN_INSPECT:
        n = scan_action_inspect(cc, disp, st->size, st->mtime, fd, line,
                                sizeof(line));
        break;
    case XROOTD_SCAN_DUMP:
    case XROOTD_SCAN_COMPARE:
    default:
        n = scan_action_dump(cc, disp, st->size, st->mtime, fd, line,
                             sizeof(line));
        break;
    }

    if (n < 0) {
        return NGX_OK;   /* path too long to format — soft skip */
    }
    cc->sum->files++;
    if (scan_append(cc->buf, cc->cap, cc->used, line, (size_t) n) < 0) {
        cc->oom = 1;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_scan_run(ngx_log_t *log, int rootfd, const char *logical,
    const xrootd_scan_opts_t *opts, u_char **buf, size_t *cap, size_t *used,
    xrootd_scan_summary_t *summary, uint16_t *err_code, char *err_msg,
    size_t err_sz)
{
    scan_walk_ctx_t          cc;
    xrootd_vfs_walk_opts_t   wopts;
    xrootd_vfs_walk_target_t target = XROOTD_VFS_WALK_NONE;
    char                     walkmsg[128] = "";
    ngx_int_t                rc;

    ngx_memzero(&cc, sizeof(cc));
    cc.log = log;
    cc.opts = opts;
    cc.buf = buf;
    cc.cap = cap;
    cc.used = used;
    cc.sum = summary;

    ngx_memzero(&wopts, sizeof(wopts));
    wopts.max_depth = opts->max_depth;
    wopts.max_files = opts->max_files;
    wopts.open_files = 1;   /* the walk hands each regular file a read-only fd */

    rc = xrootd_vfs_walk(log, rootfd, logical, &wopts, scan_walk_file, &cc,
                         &target, walkmsg, sizeof(walkmsg));

    if (rc == NGX_DECLINED) {
        *err_code = kXR_NotFound;
        snprintf(err_msg, err_sz, "target not found");
        return NGX_ERROR;
    }
    if (rc != NGX_OK) {
        if (cc.oom) {
            *err_code = kXR_NoMemory;
            snprintf(err_msg, err_sz, "out of memory");
        } else {
            *err_code = kXR_IOError;
            snprintf(err_msg, err_sz, "%s", walkmsg[0] ? walkmsg : "I/O error");
        }
        return NGX_ERROR;
    }
    if (target == XROOTD_VFS_WALK_OTHER) {
        *err_code = kXR_ArgInvalid;
        snprintf(err_msg, err_sz, "not a file or directory");
        return NGX_ERROR;
    }
    return NGX_OK;
}
