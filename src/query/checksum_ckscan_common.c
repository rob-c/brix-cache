/*
 * checksum_ckscan_common.c — shared helpers for kXR_Qckscan directory/file checksum scans.
 *
 * WHAT: Provides three functions used by checksum_ckscan_async.c and checksum_ckscan_dispatch.c to walk filesystem trees and compute per-file checksums. ckscan_append() grows a response buffer with "algo hex logical_path" lines; xrootd_ckscan_join_logical() constructs canonical logical paths from parent+child components; xrootd_ckscan_walk() recursively scans directories up to max_depth/max_files limits, computing checksums for regular files.
 *
 * WHY: kXR_Qckscan walks a directory tree off the event loop (async via thread pool) and returns one checksum line per file. These shared helpers eliminate code duplication between async and dispatch implementations while providing consistent path construction, buffer growth logic, and recursive walk semantics with depth/capacity limits.
 */

#include "query_internal.h"
#include "response/response.h"
#include "core/aio/aio.h"
#include "core/compat/checksum.h"
#include "fs/vfs.h"   /* xrootd_vfs_walk — confined recursive scan */

#include <dirent.h>
#include <sys/stat.h>

/* kXR_Qckscan — directory / file checksum scan */
/* Append one "algo hex  logical_path\n" line, growing the buffer if needed. */
int
xrootd_ckscan_append(u_char **buf, size_t *cap, size_t *used,
    const char *algo, const char *hex, const char *logical)
{
    char    line[XROOTD_MAX_PATH + 64];
    size_t  llen;
    u_char *nb;

    /*
     * snprintf returns the length it WOULD have written, so llen can exceed
     * sizeof(line) on truncation. The >= test below catches that (and the
     * mandatory NUL means equality is already overflow), so `line` is never
     * read past a valid terminator. `hex` is the already-formatted lowercase
     * checksum — its width is algorithm-dependent (8 chars for adler32/crc32c,
     * 16 for crc64/crc64nvme), carried in the string so this formatter stays
     * width-agnostic; the two spaces between hex and path are literal, part of
     * the on-wire line format the client parses.
     */
    llen = (size_t) snprintf(line, sizeof(line), "%s %s  %s\n",
                             algo, hex, logical);
    if (llen >= sizeof(line)) {
        return 0;  /* path too long: skip */
    }

    /*
     * Grow trigger reserves llen + 2 (line bytes + a trailing NUL slot + 1
     * slack) so the caller's final buf[used]='\0' always lands in-bounds.
     * Growth is exponential (*cap*2) plus the line size, so a single oversized
     * line still fits even when doubling alone would not.
     */
    if (*used + llen + 2 > *cap) {
        size_t new_cap = *cap * 2 + llen + 2;
        /*
         * Manual realloc: this runs on a thread-pool worker, so the buffer is
         * heap-backed (ngx_alloc, not pool). On OOM we return -1 WITHOUT freeing
         * *buf — ownership stays with the caller, which frees it on its error
         * path. Only *used bytes are copied (the live prefix); the old block is
         * freed only after a successful copy. *buf==NULL on the very first call
         * is tolerated (skip the copy/free).
         */
        nb = ngx_alloc(new_cap, ngx_cycle->log);
        if (nb == NULL) {
            return -1;
        }
        if (*buf) {
            ngx_memcpy(nb, *buf, *used);
            ngx_free(*buf);
        }
        *buf = nb;
        *cap = new_cap;
    }

    ngx_memcpy(*buf + *used, line, llen);
    *used += llen;
    return 1;
}
/* WHY: Qckscan responses are newline-delimited "algo hex logical_path" lines growing into a dynamically-sized buffer. The client expects all checksum results in one response, so the buffer must handle arbitrary tree sizes via exponential growth. Returns 1 on success (line appended), 0 if output line would overflow local snprintf buffer (path too long → skip silently), -1 if OOM during buffer reallocation. */
/* HOW: snprintf(line) formats "%s %08x  %s\n" with algo, cksum as hex, logical path — returns llen. If llen >= sizeof(line) returns 0 (skip). Checks *used+llen+2 <= *cap — if insufficient allocates new_cap=*cap*2+llen+2 via ngx_alloc(), copies existing *buf content, frees old buffer, updates *buf and *cap. memcpy line into *buf at offset *used; increments *used by llen. Returns 1. */

/*
 * ckscan_walk_ctx_t + ckscan_walk_file — the per-file callback driven by
 * xrootd_vfs_walk: compute the file's checksum (algorithm-appropriate hex width)
 * and append one "algo hex logical" line. An unreadable file or unknown algorithm
 * is a soft skip (return NGX_OK so the scan continues); only an append OOM aborts
 * the walk (records cc->oom so the caller maps it to kXR_NoMemory). The confined
 * open + traversal happen INSIDE the VFS walk — this layer never touches a fd
 * except the read-only one the walk hands it.
 */
typedef struct {
    ngx_log_t  *log;
    const char *algo;
    u_char    **buf;
    size_t     *cap;
    size_t     *used;
    int         oom;
} ckscan_walk_ctx_t;

static ngx_int_t
ckscan_walk_file(void *cookie, const char *logical,
    const xrootd_vfs_stat_t *st, int fd)
{
    ckscan_walk_ctx_t *cc = cookie;
    char               hex[129];   /* 8 (adler32/crc32c) … EVP_MAX_MD_SIZE*2 */

    (void) st;

    if (xrootd_checksum_hex_name_fd(cc->algo, fd, logical, cc->log,
                                    hex, sizeof(hex), NULL, 0) != NGX_OK)
    {
        return NGX_OK;   /* skip unreadable / bad-algorithm file (continue scan) */
    }

    /* append returns 1=ok, 0=line too long (soft skip), <0=OOM (abort). */
    if (xrootd_ckscan_append(cc->buf, cc->cap, cc->used, cc->algo, hex,
                             logical) < 0)
    {
        cc->oom = 1;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Run a kXR_Qckscan over a file/dir target through the confined VFS walk and map
 * the outcome to a kXR error code. See query_internal.h for the full contract. */
ngx_int_t
xrootd_ckscan_run(ngx_log_t *log, int rootfd, const char *logical,
    const char *algo, u_char **buf, size_t *cap, size_t *used,
    ngx_uint_t max_depth, ngx_uint_t max_files,
    uint16_t *err_code, char *err_msg, size_t err_sz)
{
    ckscan_walk_ctx_t        cc;
    xrootd_vfs_walk_opts_t   opts;
    xrootd_vfs_walk_target_t target = XROOTD_VFS_WALK_NONE;
    char                     walkmsg[128] = "";
    ngx_int_t                rc;

    ngx_memzero(&cc, sizeof(cc));
    cc.log = log;
    cc.algo = algo;
    cc.buf = buf;
    cc.cap = cap;
    cc.used = used;

    ngx_memzero(&opts, sizeof(opts));
    opts.max_depth  = max_depth;
    opts.max_files  = max_files;
    opts.open_files = 1;   /* the walk hands each regular file a read-only fd */

    rc = xrootd_vfs_walk(log, rootfd, logical, &opts, ckscan_walk_file, &cc,
                         &target, walkmsg, sizeof(walkmsg));

    if (rc == NGX_DECLINED) {
        *err_code = kXR_NotFound;
        snprintf(err_msg, err_sz, "stat failed: %s", strerror(errno));
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
    /* A regular-file target that produced no line means its open succeeded but
     * the checksum failed (the callback skipped it) — a hard error for a single
     * file, unlike an (acceptably) empty directory listing. */
    if (target == XROOTD_VFS_WALK_FILE && *used == 0) {
        *err_code = kXR_IOError;
        snprintf(err_msg, err_sz, "checksum computation failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}
