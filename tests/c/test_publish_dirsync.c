/*
 * test_publish_dirsync.c — the phase-107 C3 durable-publish barrier, against
 * the REAL staged_file.o + beneath.o (the confined-fd machinery is the point:
 * the security case only means something with RESOLVE_IN_ROOT actually live).
 *
 * The barrier's whole reason to exist is the defect this file pins first:
 * the old code ran (void) fsync(rootfd) where rootfd is O_PATH — every such
 * fsync failed EBADF and the cast threw the evidence away (case 1).
 *
 * fsync is interposed with -Wl,--wrap=fsync: DIRECTORY fsyncs are counted and
 * their inodes recorded (and optionally forced to fail), then forwarded to
 * __real_fsync — so "the dirsync happened exactly once, on the PARENT of the
 * published path, not the export root" is asserted by inode, not inferred.
 *
 * Cross-TU spies (the hermetic seam): brix_vfs_backend_durable (switchable —
 * the off case), brix_make_tmp_path/brix_make_resume_path (fixed names), the
 * impersonation broker (inactive), brix_chmod_confined_canon (never reached).
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/staged_file.h"
#include "fs/path/beneath.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- fsync interposition ------------------------------------------------ */

int __real_fsync(int fd);

static int    g_dir_fail_errno;      /* force DIRECTORY fsyncs to fail with this */
static int    g_dir_count;
static ino_t  g_dir_ino[16];

int
__wrap_fsync(int fd)
{
    struct stat sb;

    if (fstat(fd, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        if (g_dir_count < 16) {
            g_dir_ino[g_dir_count] = sb.st_ino;
        }
        g_dir_count++;
        if (g_dir_fail_errno != 0) {
            errno = g_dir_fail_errno;
            return -1;
        }
    }
    return __real_fsync(fd);
}

/* ---- cross-TU spies ----------------------------------------------------- */

static ngx_int_t g_durable = 1;

ngx_int_t
brix_vfs_backend_durable(const char *root_canon)
{
    (void) root_canon;
    return g_durable;
}

ngx_int_t
brix_make_tmp_path(const char *base_path, char *out, size_t out_sz)
{
    int n = snprintf(out, out_sz, "%s.xrd-tmp.%d.t", base_path, (int) getpid());

    return (n > 0 && (size_t) n < out_sz) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_make_resume_path(const char *base_path, const char *principal,
    const char *stage_dir, char *out, size_t out_sz)
{
    (void) principal; (void) stage_dir;
    return brix_make_tmp_path(base_path, out, out_sz);
}

int brix_imp_client_active(void) { return 0; }
int brix_imp_open(const char *p, int f, mode_t m) { (void) p; (void) f; (void) m; abort(); }
int brix_imp_stat(const char *p, struct stat *st, int nf) { (void) p; (void) st; (void) nf; abort(); }
int brix_imp_mkdir(const char *p, mode_t m) { (void) p; (void) m; abort(); }
int brix_imp_unlink(const char *p, int d) { (void) p; (void) d; abort(); }
int brix_imp_rename(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_rename_noreplace(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_link(const char *s, const char *d) { (void) s; (void) d; abort(); }

int
brix_chmod_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode)
{
    (void) log; (void) root_canon; (void) resolved; (void) mode;
    abort();   /* broker inactive: this path must never be taken */
}

/* ---- helpers ------------------------------------------------------------ */

static char       g_root[128];      /* short so "%s/%s" composes into
                                     * PATH_MAX warning-free */
static ngx_log_t  g_log;      /* ngx_log_error derefs log->log_level; the
                               * core is the shared no-op link stub */

static ino_t
ino_of(const char *path)
{
    struct stat sb;

    assert(stat(path, &sb) == 0);
    return sb.st_ino;
}

static void
reset_counters(void)
{
    g_dir_count = 0;
    g_dir_fail_errno = 0;
    memset(g_dir_ino, 0, sizeof(g_dir_ino));
}

/* Stage one temp under g_root and commit it onto `final_rel`. */
static ngx_int_t
publish(const char *final_rel, brix_staged_file_t *staged)
{
    char                    final_path[PATH_MAX];
    brix_staged_open_req_t  req;

    snprintf(final_path, sizeof(final_path), "%s/%s", g_root, final_rel);
    memset(&req, 0, sizeof(req));
    req.root_canon = g_root;
    req.final_path = final_path;
    req.mode       = 0644;
    req.open_flags = O_WRONLY;
    assert(brix_staged_open(&g_log, &req, staged) == NGX_OK);
    assert(write(staged->fd, "x", 1) == 1);
    return brix_staged_commit(&g_log, g_root, staged, final_path);
}

int
main(void)
{
    char                buf[PATH_MAX];
    brix_staged_file_t  staged;
    int                 rootfd, rc;

    g_log.log_level = NGX_LOG_DEBUG;
    snprintf(g_root, sizeof(g_root), "/tmp/pubsync-%d", (int) getpid());
    assert(mkdir(g_root, 0755) == 0);
    snprintf(buf, sizeof(buf), "%s/a", g_root);       assert(mkdir(buf, 0755) == 0);
    snprintf(buf, sizeof(buf), "%s/a/b", g_root);     assert(mkdir(buf, 0755) == 0);

    /* 1. THE DEFECT PIN: the pre-C3 barrier fsynced the O_PATH root fd and
     * discarded the result. Prove that call was inert: EBADF, every time. */
    rootfd = brix_beneath_open_root(g_root);
    assert(rootfd >= 0);
    errno = 0;
    assert(__real_fsync(rootfd) == -1);
    assert(errno == EBADF);
    close(rootfd);

    /* 2. SUCCESS: one publish → exactly one directory fsync, on the PARENT of
     * the published path (a/b), not the export root. */
    reset_counters();
    assert(publish("a/b/f1", &staged) == NGX_OK);
    assert(g_dir_count == 1);
    snprintf(buf, sizeof(buf), "%s/a/b", g_root);
    assert(g_dir_ino[0] == ino_of(buf));
    snprintf(buf, sizeof(buf), "%s/a/b/f1", g_root);
    assert(access(buf, F_OK) == 0);

    /* 3. SUCCESS: a publish directly under the root flushes the root itself
     * (parent derivation's "." arm). */
    reset_counters();
    assert(publish("f2", &staged) == NGX_OK);
    assert(g_dir_count == 1);
    assert(g_dir_ino[0] == ino_of(g_root));

    /* 4. OFF: brix_durable_publish off (spy = 0) skips the barrier entirely —
     * the publish still lands, with zero directory fsyncs. */
    reset_counters();
    g_durable = 0;
    assert(publish("a/b/f3", &staged) == NGX_OK);
    assert(g_dir_count == 0);
    g_durable = 1;

    /* 5. ERROR: a failing dirsync FAILS the publish (EIO to the caller, not
     * swallowed) — and the name IS already visible, which is exactly why the
     * failure must be reported rather than success claimed. */
    reset_counters();
    g_dir_fail_errno = EIO;
    errno = 0;
    rc = publish("a/b/f4", &staged);
    assert(rc == NGX_ERROR);
    assert(errno == EIO);
    snprintf(buf, sizeof(buf), "%s/a/b/f4", g_root);
    assert(access(buf, F_OK) == 0);          /* visible, not durable — reported */
    g_dir_fail_errno = 0;

    /* 6. SECURITY-NEGATIVE: swap the parent for an absolute symlink pointing
     * OUTSIDE the export between rename and barrier. RESOLVE_IN_ROOT re-roots
     * the link inside the export, so the outside directory is never opened,
     * never flushed — the barrier errors instead of following the swap. */
    reset_counters();
    snprintf(buf, sizeof(buf), "/tmp/pubsync-evil-%d", (int) getpid());
    assert(mkdir(buf, 0755) == 0);
    {
        char parent[PATH_MAX], evil[PATH_MAX];
        ino_t evil_ino = ino_of(buf);
        int   i;

        strcpy(evil, buf);
        snprintf(parent, sizeof(parent), "%s/a/swapped", g_root);
        assert(symlink(evil, parent) == 0);
        errno = 0;
        rc = brix_publish_dirsync(&g_log, -1, g_root, "a/swapped/f5");
        assert(rc != NGX_OK);
        for (i = 0; i < g_dir_count && i < 16; i++) {
            assert(g_dir_ino[i] != evil_ino);
        }
        assert(rmdir(evil) == 0);
    }

    printf("publish_dirsync: 6 cases ok\n");
    return 0;
}
