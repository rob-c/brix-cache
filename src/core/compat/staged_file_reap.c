/*
 * staged_file_reap.c — Durable stage-out markers + crash-safe commit reaper.
 *
 * WHAT: The pending-commit marker family (register stage dirs, write/remove a
 *       "<stage_partial>.commit" marker) and the reaper that finishes any
 *       interrupted stage-out on the next worker startup / periodic sweep.
 *
 * WHY:  Split from staged_file.c (phase-79 file-size split). With a synchronous
 *       commit the client waits for the stage→storage move, but if the worker
 *       dies mid-move the COMPLETE file is left in the cache with nothing
 *       recording where it belongs. A durable marker (content = the final
 *       absolute path) written+fsync'd before the move and removed after lets the
 *       reaper always drive complete-but-uncommitted files to storage across
 *       restarts. Keeping this recovery machinery in its own file leaves the
 *       hot-path open/commit lifecycle uncluttered.
 *
 * HOW:  brix_stage_dir_register/_count track the dirs to sweep. mark/unmark write
 *       and drop the marker around a move. brix_stage_reap_dir snapshots every
 *       marker basename FIRST (reap_collect_markers — it unlinks while iterating,
 *       which would otherwise make readdir skip entries), then reap_one_marker
 *       reads each target (reap_read_marker_target) and republishes via
 *       brix_commit_staged (declared in staged_file.h). Idempotent: a marker whose
 *       partial is already gone is simply dropped. Zero behavior change from the
 *       pre-split code.
 */

#include "staged_file.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * When an upload completes, the (complete) staged file must be moved from the
 * stage device to the final storage.  With a synchronous commit the client waits
 * for that move, but if the worker dies mid-move the COMPLETE file is left in the
 * cache with nothing recording where it should go.  A marker file
 * "<stage_partial>.commit" (content = the final absolute path) is written +
 * fsync'd just before the move and removed after it; if the move is interrupted
 * the marker survives, and brix_stage_reap_dir() finishes the move on the next
 * worker startup / periodic sweep — so complete-but-uncommitted files are tracked
 * across restarts and always reach storage.
 */
#define BRIX_STAGE_COMMIT_SUFFIX ".commit"
#define BRIX_STAGE_MAX_DIRS 32

static char       s_stage_dirs[BRIX_STAGE_MAX_DIRS][PATH_MAX];
static ngx_uint_t s_stage_dir_count;

void
brix_stage_dir_register(const char *canon)
{
    ngx_uint_t i;

    if (canon == NULL || canon[0] == '\0' || strlen(canon) >= PATH_MAX) {
        return;
    }
    for (i = 0; i < s_stage_dir_count; i++) {
        if (strcmp(s_stage_dirs[i], canon) == 0) {
            return;   /* already registered (dedup across server blocks) */
        }
    }
    if (s_stage_dir_count >= BRIX_STAGE_MAX_DIRS) {
        return;
    }
    ngx_memcpy(s_stage_dirs[s_stage_dir_count], canon, strlen(canon) + 1);
    s_stage_dir_count++;
}

ngx_uint_t
brix_stage_dir_count(void)
{
    return s_stage_dir_count;
}

ngx_int_t
brix_stage_mark_pending(const char *stage_partial, const char *final_path,
                          ngx_log_t *log)
{
    char    marker[PATH_MAX];
    int     fd, n;
    size_t  flen;

    (void) log;
    n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                 BRIX_STAGE_COMMIT_SUFFIX);
    if (n < 0 || (size_t) n >= sizeof(marker)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return NGX_ERROR;
    }
    flen = strlen(final_path);
    if ((size_t) write(fd, final_path, flen) != flen || fsync(fd) != 0) {
        int e = errno; close(fd); (void) unlink(marker); errno = e;
        return NGX_ERROR;
    }
    close(fd);
    return NGX_OK;
}

void
brix_stage_unmark_pending(const char *stage_partial)
{
    char marker[PATH_MAX];
    int  n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                      BRIX_STAGE_COMMIT_SUFFIX);
    if (n > 0 && (size_t) n < sizeof(marker)) {
        (void) unlink(marker);
    }
}

/* Maximum stage-out markers snapshotted per reap pass, and the per-basename cap. */
#define BRIX_STAGE_REAP_MAX_MARKERS  256
#define BRIX_STAGE_REAP_NAME_MAX     256

/*
 * WHAT: Snapshot the basenames of every ".commit" marker in stage_dir into names[]
 *       (returns the count captured, capped at max).
 *
 * WHY:  The reap loop unlinks markers while it works, which would make a live
 *       readdir skip entries — so the directory is scanned into a snapshot FIRST,
 *       then the snapshot is processed.
 *
 * HOW:  opendir + readdir, keeping only names that end in BRIX_STAGE_COMMIT_SUFFIX
 *       and fit the basename buffer; copy each (with its NUL) into names[]. A
 *       missing / unopenable dir yields 0.
 *
 * Parameters:
 *   stage_dir — directory to scan
 *   names — output array of NUL-terminated basenames
 *   max — capacity of names[] (entries beyond it are ignored)
 */
static ngx_uint_t
reap_collect_markers(const char *stage_dir,
    char names[][BRIX_STAGE_REAP_NAME_MAX], ngx_uint_t max)
{
    DIR           *d;
    struct dirent *de;
    size_t         slen = sizeof(BRIX_STAGE_COMMIT_SUFFIX) - 1;
    ngx_uint_t     ncount = 0;

    d = opendir(stage_dir);
    if (d == NULL) {
        return 0;
    }
    while ((de = readdir(d)) != NULL && ncount < max) {
        size_t nlen = strlen(de->d_name);
        if (nlen > slen && nlen < BRIX_STAGE_REAP_NAME_MAX
            && strcmp(de->d_name + nlen - slen, BRIX_STAGE_COMMIT_SUFFIX) == 0)
        {
            ngx_memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);
    return ncount;
}

/*
 * WHAT: Read a marker's recorded final path into *final (NUL-terminated, trailing
 *       whitespace trimmed), validating it is a sane absolute path.
 *
 * WHY:  A marker's content is the final absolute path to publish the partial to;
 *       an unreadable, empty, or non-absolute marker is corrupt and must not drive
 *       a commit.
 *
 * HOW:  open O_RDONLY|O_NOFOLLOW, read up to cap-1 bytes, trim trailing CR/LF/space,
 *       and require a leading '/'. Returns NGX_OK with *final populated, or
 *       NGX_ERROR (the caller drops the marker).
 *
 * Parameters:
 *   marker — absolute path to the ".commit" marker file
 *   final — output buffer for the recorded path
 *   cap — size of final
 */
static ngx_int_t
reap_read_marker_target(const char *marker, char *final, size_t cap)
{
    int      mfd;
    ssize_t  r;

    mfd = open(marker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (mfd < 0) {
        return NGX_ERROR;
    }
    r = read(mfd, final, cap - 1);
    close(mfd);
    if (r <= 0) {
        return NGX_ERROR;
    }
    final[r] = '\0';
    while (r > 0 && (final[r - 1] == '\n' || final[r - 1] == '\r'
                     || final[r - 1] == ' ')) {
        final[--r] = '\0';
    }
    if (final[0] != '/') {                 /* sanity: must be absolute */
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Reap one snapshotted marker basename — finish its pending stage-out and
 *       remove the marker. Returns 1 if a commit completed this call, else 0.
 *
 * WHY:  Isolating the per-marker decision (build paths, read target, check the
 *       partial still exists, commit) keeps brix_stage_reap_dir a flat scan+loop.
 *       Idempotent: a marker whose partial is gone (committed by a racing pass or
 *       a client retry) is just dropped.
 *
 * HOW:  Build the marker + partial paths under stage_dir; read the target; if the
 *       partial is missing drop the marker; else brix_commit_staged (no fd →
 *       final_mode unused, fchmod is fd-guarded, partial keeps its on-disk mode).
 *       On success unlink the marker + NOTICE-log; on failure WARN and keep it for
 *       retry.
 *
 * Parameters:
 *   stage_dir — directory holding the marker + partial
 *   name — ".commit" marker basename to reap
 *   log — nginx log for the NOTICE / WARN result line
 */
static ngx_uint_t
reap_one_marker(const char *stage_dir, const char *name, ngx_log_t *log)
{
    char         marker[PATH_MAX], partial[PATH_MAX], final[PATH_MAX];
    size_t       slen = sizeof(BRIX_STAGE_COMMIT_SUFFIX) - 1;
    size_t       nlen = strlen(name);
    int          n;
    struct stat  sb;

    n = snprintf(marker, sizeof(marker), "%s/%s", stage_dir, name);
    if (n < 0 || (size_t) n >= sizeof(marker)) { return 0; }
    n = snprintf(partial, sizeof(partial), "%s/%.*s", stage_dir,
                 (int) (nlen - slen), name);
    if (n < 0 || (size_t) n >= sizeof(partial)) { return 0; }

    if (reap_read_marker_target(marker, final, sizeof(final)) != NGX_OK) {
        (void) unlink(marker);
        return 0;
    }

    if (stat(partial, &sb) != 0) {
        /* Partial already gone (committed elsewhere) — drop the marker. */
        (void) unlink(marker);
        return 0;
    }
    /* Crash-recovery: no open fd, so final_mode is unused (fchmod is fd-guarded);
     * the recovered partial keeps its on-disk mode. */
    if (brix_commit_staged(NGX_INVALID_FILE, partial, final, 0, log) == NGX_OK) {
        (void) unlink(marker);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: completed pending stage-out \"%s\" -> \"%s\"",
            partial, final);
        return 1;
    }
    ngx_log_error(NGX_LOG_WARN, log, errno,
        "brix: pending stage-out \"%s\" -> \"%s\" failed; will retry",
        partial, final);
    return 0;
}

/* Finish every pending stage-out recorded in stage_dir.  Returns the count of
 * commits completed this pass.  Idempotent and crash-safe: a marker whose partial
 * is already gone (committed by a racing pass / a client retry) is just dropped. */
ngx_uint_t
brix_stage_reap_dir(const char *stage_dir, ngx_log_t *log)
{
    /* Snapshot marker basenames first — we unlink while iterating, which would
     * otherwise make readdir skip entries. */
    char        names[BRIX_STAGE_REAP_MAX_MARKERS][BRIX_STAGE_REAP_NAME_MAX];
    ngx_uint_t  done = 0, ncount, i;

    if (stage_dir == NULL || stage_dir[0] == '\0') {
        return 0;
    }
    ncount = reap_collect_markers(stage_dir, names,
                                  BRIX_STAGE_REAP_MAX_MARKERS);

    for (i = 0; i < ncount; i++) {
        done += reap_one_marker(stage_dir, names[i], log);
    }
    return done;
}

ngx_uint_t
brix_stage_reap_all(ngx_log_t *log)
{
    ngx_uint_t total = 0, i;
    for (i = 0; i < s_stage_dir_count; i++) {
        total += brix_stage_reap_dir(s_stage_dirs[i], log);
    }
    return total;
}
