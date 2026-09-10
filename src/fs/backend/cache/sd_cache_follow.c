/*
 * sd_cache_follow.c — serve-while-filling for the whole-file fill (audit §4.5).
 *
 * WHAT: A cache miss whose whole-file fill is ALREADY in flight no longer waits
 *       for that fill to commit. The arriving reader opens a "follower" object
 *       over the filler's staged temp file and reads the bytes already pumped;
 *       a read at the fill frontier is answered EAGAIN, which the root read
 *       path turns into kXR_wait, so the client streams at the origin's pace.
 *
 * WHY:  Before this, whole-file mode was strictly foreground: every concurrent
 *       reader of a cold object serialised behind one fill and paid the FULL
 *       object's transfer time before its first byte. Slice mode already served
 *       partial content (sd_cache_partial.c); whole-file mode is the gap the
 *       parity audit records as §4.5 (upstream XrdPfc serve-while-filling).
 *
 * HOW:  The coordination channel is the filesystem, so it works across workers
 *       and across processes with no SHM and no IPC — the same doctrine as the
 *       cache fill lock (fs/cache/lock.c). The filler publishes
 *       `<local_root><key>.brixfill` naming its staged temp path; a follower
 *       reads the marker, opens that temp file O_RDONLY once, and uses its own
 *       fd's SIZE as the frontier (the pump writes strictly sequentially, so
 *       size == bytes readable). Termination is decided from the follower's own
 *       fd, not from the marker, because only the fd is race-free:
 *
 *         st_nlink == 0  the staged file was unlinked  → the fill ABORTED → EIO
 *         marker gone    the staged file was renamed   → COMMITTED → real EOF
 *         otherwise      still pumping                 → EAGAIN (kXR_wait)
 *
 *       so the fill spine must commit (rename) BEFORE withdrawing the marker,
 *       and unlink the staged file BEFORE withdrawing it on an abort — both
 *       enforced in sd_cache_follow_withdraw. A filler that dies without
 *       withdrawing leaves the marker behind; the follower bounds that with its
 *       own no-progress deadline (policy.serve_while_filling seconds since the
 *       frontier last moved) and fails ETIMEDOUT rather than hanging.
 *
 *       The follower deliberately advertises NO capabilities: caps == 0 means
 *       brix_sd_fd() returns NGX_INVALID_FILE, so no sendfile span is ever
 *       built over a file that is still growing.
 */
#include "sd_cache_follow.h"
#include "fs/cache/cstore.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SD_CACHE_FOLLOW_SUFFIX  ".brixfill"


/* Per-follower state: the staged fd plus the no-progress ratchet. */
typedef struct {
    sd_cache_inst_state *st;
    int                   fd;          /* the staged temp file, O_RDONLY      */
    off_t                 declared;    /* the source's final size (0 = unknown)*/
    off_t                 frontier;    /* last size we observed               */
    ngx_msec_t            moved_at;    /* when frontier last advanced         */
    char                  marker[PATH_MAX];
} sd_cache_follow_t;


/* `<local_root><key>.brixfill` into `dst`. Returns 0, or -1 when the store has
 * no local root (a remote cache store has no marker plane) or the name would
 * overflow. */
static int
follow_marker_path(sd_cache_inst_state *st, const char *key, char *dst,
    size_t dstsz)
{
    const char *root = brix_cstore_local_root(&st->cstore);

    if (root == NULL || key == NULL || key[0] != '/') {
        return -1;
    }
    if ((size_t) snprintf(dst, dstsz, "%s%s%s", root, key,
                          SD_CACHE_FOLLOW_SUFFIX) >= dstsz)
    {
        return -1;
    }
    return 0;
}


/* 1 iff `path` lies under the cache store's local root, at a path-component
 * boundary. The staged temp is always created beside its final object, so this
 * is exactly the set of paths a well-formed marker can name. */
static int
follow_path_under_root(sd_cache_inst_state *st, const char *path)
{
    const char *root = brix_cstore_local_root(&st->cstore);
    size_t      n;

    if (root == NULL) {
        return 0;
    }
    n = strlen(root);
    while (n > 1 && root[n - 1] == '/') {      /* ignore a trailing slash */
        n--;
    }
    return strncmp(path, root, n) == 0 && path[n] == '/';
}


/* Read the staged path (and the declared size, when `size_out` is non-NULL) out
 * of the marker at `marker`. Returns 0 on a well-formed marker, -1 otherwise
 * (missing, truncated, or a path that is not absolute — a marker is only ever
 * written by this file, so a malformed one is treated as absent rather than
 * trusted). */
static int
follow_read_marker(const char *marker, char *dst, size_t dstsz, off_t *size_out)
{
    char       buf[PATH_MAX + 64];
    ssize_t    n;
    char      *sp, *end;
    long long  declared;
    int        fd;

    fd = open(marker, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    (void) close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
    sp = strchr(buf, ' ');               /* "<pid> <declared size> <path>" */
    if (sp == NULL) {
        return -1;
    }
    declared = strtoll(sp + 1, &end, 10);
    if (end == sp + 1 || *end != ' ' || end[1] != '/' || declared < 0) {
        return -1;
    }
    sp = end + 1;
    if (strlen(sp) >= dstsz) {
        return -1;
    }
    memcpy(dst, sp, strlen(sp) + 1);
    if (size_out != NULL) {
        *size_out = (off_t) declared;
    }
    return 0;
}


void
sd_cache_follow_publish(sd_cache_inst_state *st, const char *key,
    const char *staged_path, off_t declared_size)
{
    char   marker[PATH_MAX];
    char   line[PATH_MAX + 64];
    int    fd, len;

    if (st == NULL || staged_path == NULL || staged_path[0] != '/'
        || st->policy.serve_while_filling <= 0
        || follow_marker_path(st, key, marker, sizeof(marker)) != 0)
    {
        return;
    }
    len = snprintf(line, sizeof(line), "%ld %lld %s\n", (long) getpid(),
                   (long long) (declared_size > 0 ? declared_size : 0),
                   staged_path);
    if (len <= 0 || (size_t) len >= sizeof(line)) {
        return;
    }
    fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, line, (size_t) len) != len) {
        (void) close(fd);
        (void) unlink(marker);
        return;
    }
    (void) close(fd);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                   "sd_cache: serve-while-filling armed for \"%s\"", key);
}


void
sd_cache_follow_arm(sd_cache_inst_state *st, const char *key,
    brix_sd_staged_t *staged, off_t declared_size)
{
    const brix_sd_driver_t *drv;
    const char             *path;

    if (st == NULL || staged == NULL || staged->inst == NULL
        || st->policy.serve_while_filling <= 0)
    {
        return;
    }
    /* SECURITY: a verifying fill's staged bytes are provisional — see the
     * header. Only an unverified fill may be followed. */
    if (st->policy.verify != BRIX_CACHE_VERIFY_OFF) {
        return;
    }
    drv = staged->inst->driver;
    if (drv == NULL || drv->staged_path == NULL) {
        return;                    /* remote staged plane: no file to follow */
    }
    path = drv->staged_path(staged);
    if (path == NULL) {
        return;
    }
    sd_cache_follow_publish(st, key, path, declared_size);
}


void
sd_cache_follow_withdraw(sd_cache_inst_state *st, const char *key, int aborted)
{
    char  marker[PATH_MAX];
    char  staged[PATH_MAX];

    if (st == NULL || st->policy.serve_while_filling <= 0
        || follow_marker_path(st, key, marker, sizeof(marker)) != 0)
    {
        return;
    }
    /* Fail closed: a follower decides "aborted" from st_nlink == 0 on its own
     * fd, so the staged file must be gone BEFORE the marker is. A driver whose
     * staged_abort already unlinked it makes this a harmless ENOENT. */
    if (aborted
        && follow_read_marker(marker, staged, sizeof(staged), NULL) == 0)
    {
        (void) unlink(staged);
    }
    (void) unlink(marker);
}


/* The frontier, refreshed from the follower's own fd. Sets *nlink so the caller
 * can tell an aborted fill (0) from a committed one. Returns -1 on fstat
 * failure. */
static off_t
follow_frontier(sd_cache_follow_t *f, nlink_t *nlink)
{
    struct stat sb;

    if (fstat(f->fd, &sb) != 0) {
        return -1;
    }
    *nlink = sb.st_nlink;
    if (sb.st_size > f->frontier) {
        f->frontier = sb.st_size;
        f->moved_at = ngx_current_msec;
    }
    return f->frontier;
}


/* The read verdict once the reader has caught up with the frontier: 0 = clean
 * EOF (the fill committed), -1 with errno set otherwise. */
static ssize_t
follow_at_frontier(sd_cache_follow_t *f, nlink_t nlink)
{
    ngx_msec_int_t idle;

    if (nlink == 0) {
        errno = EIO;                     /* the fill aborted under us */
        return -1;
    }
    if (f->declared > 0 && f->frontier >= f->declared) {
        return 0;      /* every declared byte is pumped: EOF without waiting
                        * for the commit to withdraw the marker */
    }
    if (access(f->marker, F_OK) != 0) {
        return 0;                        /* committed: the frontier is final */
    }
    idle = (ngx_msec_int_t) (ngx_current_msec - f->moved_at);
    if (idle > (ngx_msec_int_t) (f->st->policy.serve_while_filling * 1000)) {
        errno = ETIMEDOUT;               /* the filler died without withdrawing */
        return -1;
    }
    errno = EAGAIN;                      /* still pumping: retry (kXR_wait) */
    return -1;
}


static ssize_t
sd_cache_follow_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_cache_follow_t *f = obj->state;
    nlink_t             nlink = 1;
    off_t               frontier;

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    frontier = follow_frontier(f, &nlink);
    if (frontier < 0) {
        return -1;
    }
    if (off >= frontier) {
        return follow_at_frontier(f, nlink);
    }
    if ((off_t) len > frontier - off) {
        len = (size_t) (frontier - off);   /* short read at the frontier */
    }
    return pread(f->fd, buf, len, off);
}


static ngx_int_t
sd_cache_follow_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    sd_cache_follow_t *f = obj->state;
    struct stat         sb;

    if (fstat(f->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    memset(out, 0, sizeof(*out));
    /* The DECLARED size off the marker, NOT st_size. The phase-107 C5 reserve
     * uses fallocate(FALLOC_FL_KEEP_SIZE), which claims blocks without moving
     * st_size, so the staged file's st_size IS the frontier — reporting it
     * would tell the client the object is short and it would stop reading at
     * the frontier. Only a source that declared no size falls back to it. */
    out->size   = (f->declared > 0) ? f->declared : sb.st_size;
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->mode   = sb.st_mode;
    out->ino    = sb.st_ino;
    out->uid    = sb.st_uid;
    out->gid    = sb.st_gid;
    out->is_reg = 1;
    return NGX_OK;
}


static ngx_int_t
sd_cache_follow_close(brix_sd_obj_t *obj)
{
    sd_cache_follow_t *f = obj->state;

    if (f != NULL) {
        if (f->fd >= 0) {
            (void) close(f->fd);
        }
        free(f);
        obj->state = NULL;
    }
    return NGX_OK;
}


/* caps == 0 on purpose: no CAP_FD, so brix_sd_fd() declines and no sendfile
 * span is ever built over a file that is still growing. */
static const brix_sd_driver_t  sd_cache_follow_driver = {
    .name  = "cache-follow",
    .caps  = 0,
    .close = sd_cache_follow_close,
    .pread = sd_cache_follow_pread,
    .fstat = sd_cache_follow_fstat,
};


/* The per-export instance the follower objects hang off. One static instance is
 * enough: it carries no per-export state (the follower's own struct holds the
 * fd and the policy comes off obj->state->st), and caps == 0 makes every
 * capability query decline regardless of which export asked. */
static brix_sd_instance_t  sd_cache_follow_inst = {
    .driver = &sd_cache_follow_driver,
    .caps   = 0,
};


brix_sd_obj_t *
sd_cache_follow_open(sd_cache_inst_state *st, const char *key, int *err_out)
{
    sd_cache_follow_t *f;
    brix_sd_obj_t     *obj;
    char                marker[PATH_MAX];
    char                staged[PATH_MAX];
    off_t               declared = 0;
    int                 fd;

    if (err_out != NULL) { *err_out = ENOENT; }

    if (st == NULL || st->policy.serve_while_filling <= 0
        /* SECURITY, defence in depth: sd_cache_follow_arm already refuses to
         * publish under a verify policy, so a marker seen here is stale or
         * planted. Following it would stream bytes no digest ever checked to a
         * client whose export demands verification, so the read side refuses
         * independently rather than trusting the publisher. */
        || st->policy.verify != BRIX_CACHE_VERIFY_OFF
        || follow_marker_path(st, key, marker, sizeof(marker)) != 0
        || follow_read_marker(marker, staged, sizeof(staged), &declared) != 0)
    {
        return NULL;                     /* no fill in flight for this key */
    }
    /* SECURITY: the marker names a path this process will open and stream to a
     * client, so it is confined to the cache store's own root — the staged temp
     * always sits beside its final object (brix_staged_open), so a marker that
     * points anywhere else is malformed and is refused rather than followed. */
    if (!follow_path_under_root(st, staged)) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: serve-while-filling marker for \"%s\" names a staged "
            "path outside the cache store - ignored", key);
        return NULL;
    }
    fd = open(staged, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;                     /* raced the commit/abort: refill */
    }
    f = calloc(1, sizeof(*f));
    obj = calloc(1, sizeof(*obj));
    if (f == NULL || obj == NULL) {
        free(f);
        free(obj);
        (void) close(fd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    f->st       = st;
    f->fd       = fd;
    f->declared = declared;
    f->moved_at = ngx_current_msec;
    memcpy(f->marker, marker, strlen(marker) + 1);

    obj->driver     = &sd_cache_follow_driver;
    obj->inst       = &sd_cache_follow_inst;
    obj->fd         = NGX_INVALID_FILE;
    obj->state      = f;
    obj->heap_shell = 1;
    (void) sd_cache_follow_fstat(obj, &obj->snap);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, st->log, 0,
                   "sd_cache: following in-flight fill of \"%s\"", key);
    if (err_out != NULL) { *err_out = 0; }
    return obj;
}
