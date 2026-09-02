/*
 * test_ns_fastpath.c — the metadata-hot-path syscall reductions, against the
 * REAL namespace_ops.o + beneath.o + canonical.o (kernel confinement live).
 *
 * Three changes under test:
 *   1. ns_delete_fast: every non-recursive delete now classifies from the
 *      unlinkat errno instead of an lstat pre-probe (EISDIR retries with
 *      AT_REMOVEDIR; AT_REMOVEDIR's own ENOTEMPTY replaces the getdents
 *      emptiness scan — the brix_fs_dir_is_empty abort stub below IS the
 *      proof no pre-probe runs).
 *   2. brix_ns_delete_at / brix_ns_mkdir_at: the borrowed persistent-rootfd
 *      entry points — identical semantics, and the fd they were handed must
 *      SURVIVE every call (beneath_open_parent hands the root back borrowed
 *      for single-component names; beneath_close_parent must not close it).
 *   3. brix_realpath_existing: realpath(3) semantics via one open(O_PATH) +
 *      /proc/self/fd readback — identical canonical results, including for
 *      an ESCAPING symlink (the stat fallback's prefix check depends on the
 *      true outside target coming back, not an in-root lexical path).
 *
 * Cross-TU stubs: the impersonation broker (inactive), and the recursive
 * delete/mkdir externs this unit never drives — abort bodies prove the fast
 * path stays off the probe/tree planes. ngx_link_stubs.c supplies the ngx
 * error core; ngx_strnlen (canonical.o) is a local wrapper.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/namespace_ops.h"
#include "fs/path/beneath.h"

/* fs/path/path.h drags the whole module header (ngx_stream.h) into a
 * hermetic unit; the one symbol under test is declared directly. */
char *brix_realpath_existing(const char *path, char *resolved);

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- cross-TU stubs ----------------------------------------------------- */

int brix_imp_client_active(void) { return 0; }
int brix_imp_open(const char *p, int f, mode_t m) { (void) p; (void) f; (void) m; abort(); }
int brix_imp_stat(const char *p, struct stat *st, int nf) { (void) p; (void) st; (void) nf; abort(); }
int brix_imp_mkdir(const char *p, mode_t m) { (void) p; (void) m; abort(); }
int brix_imp_unlink(const char *p, int d) { (void) p; (void) d; abort(); }
int brix_imp_rename(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_rename_noreplace(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_link(const char *s, const char *d) { (void) s; (void) d; abort(); }

size_t
ngx_strnlen(u_char *p, size_t n)
{
    return strnlen((const char *) p, n);
}

/* namespace_ops.o externs from planes this unit never drives. The
 * brix_fs_dir_is_empty abort body is load-bearing: a non-recursive
 * require_empty_dir delete reaching the old getdents pre-probe would abort
 * the run — its survival proves ns_delete_fast handles that arm. */
int
brix_mkdir_recursive_beneath(ngx_log_t *log, int rootfd,
    const char *root_canon, const char *resolved, mode_t mode,
    ngx_array_t *rules)
{
    (void) log; (void) rootfd; (void) root_canon; (void) resolved;
    (void) mode; (void) rules;
    abort();
}

ngx_int_t
brix_fs_dir_is_empty(const char *path, ngx_flag_t *is_empty)
{
    (void) path; (void) is_empty;
    abort();
}

ngx_int_t
brix_fs_remove_tree_confined(ngx_log_t *log, const char *root_canon,
    const char *path)
{
    (void) log; (void) root_canon; (void) path;
    abort();
}

/* ---- helpers ------------------------------------------------------------ */

static char       g_root[128];
static ngx_log_t  g_log;

static void
put_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");

    assert(f != NULL);
    assert(fputs(content, f) >= 0);
    assert(fclose(f) == 0);
}

/* The borrowed-fd survival witness: F_GETFD succeeds only on a live fd. */
static void
expect_fd_alive(int fd)
{
    assert(fcntl(fd, F_GETFD) >= 0);
}

int
main(void)
{
    char                    a[PATH_MAX], b[PATH_MAX], real[PATH_MAX],
                            expect[PATH_MAX];
    int                     rootfd;
    brix_ns_result_t        res;
    brix_ns_delete_opts_t   del;

    g_log.log_level = NGX_LOG_DEBUG;
    snprintf(g_root, sizeof(g_root), "/tmp/nsfast-%d", (int) getpid());
    assert(mkdir(g_root, 0755) == 0);

    /* ============ 1. ns_delete_fast (owned-rootfd entry point) ========== */

    /* 1a. SUCCESS: plain file delete — the hot kXR_rm path. */
    snprintf(a, sizeof(a), "%s/f1", g_root);
    put_file(a, "x");
    memset(&del, 0, sizeof(del));
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_OK && res.sys_errno == 0);
    assert(res.existed == 1 && res.was_dir == 0);
    assert(access(a, F_OK) == -1);

    /* 1b. SUCCESS: kXR_rm pointed at a real directory — the EISDIR retry
     * arm removes it with AT_REMOVEDIR and reports was_dir like the old
     * probe did. */
    snprintf(a, sizeof(a), "%s/d1", g_root);
    assert(mkdir(a, 0755) == 0);
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_OK);
    assert(res.existed == 1 && res.was_dir == 1);
    assert(access(a, F_OK) == -1);

    /* 1c. SUCCESS: kXR_rmdir semantics (require_directory +
     * require_empty_dir) on an empty dir — and brix_fs_dir_is_empty is an
     * abort stub, so reaching here proves no getdents pre-probe ran. */
    snprintf(a, sizeof(a), "%s/d2", g_root);
    assert(mkdir(a, 0755) == 0);
    memset(&del, 0, sizeof(del));
    del.require_directory = 1;
    del.require_empty_dir = 1;
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_OK && res.was_dir == 1);

    /* 1d. ERROR: rmdir of a populated dir — AT_REMOVEDIR's own ENOTEMPTY
     * answers what the emptiness scan used to, race-free; the child
     * survives. */
    snprintf(a, sizeof(a), "%s/d3", g_root);
    assert(mkdir(a, 0755) == 0);
    snprintf(b, sizeof(b), "%s/d3/child", g_root);
    put_file(b, "kept");
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_NOT_EMPTY && res.sys_errno == ENOTEMPTY);
    assert(access(b, F_OK) == 0);

    /* 1e. ERROR: rmdir of a regular file → ENOTDIR, exactly as the
     * lstat-classified rejection answered. */
    snprintf(a, sizeof(a), "%s/f2", g_root);
    put_file(a, "not-a-dir");
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.sys_errno == ENOTDIR);
    assert(access(a, F_OK) == 0);

    /* 1f. SECURITY-NEGATIVE: rmdir of a SYMLINK to a directory must refuse
     * ENOTDIR (unlinkat(AT_REMOVEDIR) does not follow), never remove the
     * target through the link — parity with the lstat classification,
     * which called a symlink not-a-dir. */
    snprintf(a, sizeof(a), "%s/d4", g_root);
    assert(mkdir(a, 0755) == 0);
    snprintf(b, sizeof(b), "%s/link-to-d4", g_root);
    assert(symlink(a, b) == 0);
    res = brix_ns_delete(&g_log, g_root, b, &del);
    assert(res.sys_errno == ENOTDIR);
    assert(access(a, F_OK) == 0);          /* target dir untouched */
    assert(unlink(b) == 0);

    /* 1g. SUCCESS + SECURITY: plain delete of a symlink removes the LINK,
     * not the file behind it. */
    snprintf(a, sizeof(a), "%s/f3", g_root);
    put_file(a, "survives");
    snprintf(b, sizeof(b), "%s/link-to-f3", g_root);
    assert(symlink(a, b) == 0);
    memset(&del, 0, sizeof(del));
    res = brix_ns_delete(&g_log, g_root, b, &del);
    assert(res.status == BRIX_NS_OK);
    {
        struct stat sb;
        assert(lstat(b, &sb) == -1 && errno == ENOENT);   /* link gone... */
    }
    assert(access(a, F_OK) == 0);          /* ...target intact */

    /* 1h. ERROR: missing target → NOT_FOUND, unless idempotent_missing
     * turns it into OK with existed=0 (the DELETE-idempotency contract). */
    snprintf(a, sizeof(a), "%s/ghost", g_root);
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_NOT_FOUND && res.sys_errno == ENOENT);
    del.idempotent_missing = 1;
    res = brix_ns_delete(&g_log, g_root, a, &del);
    assert(res.status == BRIX_NS_OK && res.existed == 0);

    /* ============ 2. the borrowed-rootfd entry points =================== */

    rootfd = open(g_root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    assert(rootfd >= 0);

    /* 2a. SUCCESS: single-component delete on the borrowed fd — the
     * beneath_open_parent root-borrow arm — and the fd survives the call. */
    snprintf(a, sizeof(a), "%s/f4", g_root);
    put_file(a, "x");
    memset(&del, 0, sizeof(del));
    res = brix_ns_delete_at(&g_log, rootfd, g_root, a, &del);
    assert(res.status == BRIX_NS_OK);
    assert(access(a, F_OK) == -1);
    expect_fd_alive(rootfd);

    /* 2b. SUCCESS: multi-component name through the same fd (the parent
     * openat2 arm) — fd still survives. */
    snprintf(a, sizeof(a), "%s/sub", g_root);
    assert(mkdir(a, 0755) == 0);
    snprintf(a, sizeof(a), "%s/sub/deep", g_root);
    put_file(a, "x");
    res = brix_ns_delete_at(&g_log, rootfd, g_root, a, &del);
    assert(res.status == BRIX_NS_OK);
    expect_fd_alive(rootfd);

    /* 2c. SECURITY-NEGATIVE: a path outside root_canon refuses EXDEV /
     * DENIED before any syscall — including on the borrowed-fd entry. */
    res = brix_ns_delete_at(&g_log, rootfd, g_root, "/etc/hostname", &del);
    assert(res.status == BRIX_NS_DENIED && res.sys_errno == EXDEV);
    expect_fd_alive(rootfd);

    /* 2d. SUCCESS: mkdir_at single component (root-borrow arm), fd
     * survives; the directory is real. */
    snprintf(a, sizeof(a), "%s/mk1", g_root);
    res = brix_ns_mkdir_at(&g_log, rootfd, g_root, a, 0755, 0);
    assert(res.status == BRIX_NS_OK && res.created == 1);
    {
        struct stat sb;
        assert(lstat(a, &sb) == 0 && S_ISDIR(sb.st_mode));
    }
    expect_fd_alive(rootfd);

    /* 2e. ERROR: mkdir_at on an existing name → EXISTS/EEXIST. */
    res = brix_ns_mkdir_at(&g_log, rootfd, g_root, a, 0755, 0);
    assert(res.status == BRIX_NS_EXISTS && res.sys_errno == EEXIST);

    /* 2f. SECURITY-NEGATIVE: mkdir_at outside the root refuses EXDEV; no
     * directory appears. */
    snprintf(a, sizeof(a), "/tmp/nsfast-escape-%d", (int) getpid());
    res = brix_ns_mkdir_at(&g_log, rootfd, g_root, a, 0755, 0);
    assert(res.status == BRIX_NS_DENIED && res.sys_errno == EXDEV);
    assert(access(a, F_OK) == -1);
    expect_fd_alive(rootfd);

    assert(close(rootfd) == 0);

    /* ============ 3. brix_realpath_existing ============================= */

    /* 3a. SUCCESS: a symlink chain canonicalises to exactly what
     * realpath(3) says. */
    snprintf(a, sizeof(a), "%s/mk1/target", g_root);
    put_file(a, "t");
    snprintf(b, sizeof(b), "%s/hop", g_root);
    assert(symlink(a, b) == 0);
    assert(realpath(b, expect) != NULL);
    assert(brix_realpath_existing(b, real) == real);
    assert(strcmp(real, expect) == 0);

    /* 3b. ERROR: a missing path answers NULL + ENOENT (one failing open —
     * the hot stat-miss leg this helper exists for). */
    snprintf(a, sizeof(a), "%s/no-such", g_root);
    errno = 0;
    assert(brix_realpath_existing(a, real) == NULL);
    assert(errno == ENOENT);

    /* 3c. SECURITY-NEGATIVE: an ESCAPING symlink must canonicalise to the
     * TRUE outside target — identical to realpath(3) — so the caller's
     * root-prefix check catches the escape. An in-root lexical answer here
     * would be a confinement hole. */
    snprintf(b, sizeof(b), "%s/escape", g_root);
    assert(symlink("/etc/hostname", b) == 0);
    assert(realpath(b, expect) != NULL);
    assert(brix_realpath_existing(b, real) == real);
    assert(strcmp(real, expect) == 0);
    assert(strncmp(real, g_root, strlen(g_root)) != 0);

    printf("test_ns_fastpath: all assertions passed\n");
    return 0;
}
