/*
 * test_vfs_exchange.c — the phase-107 C6 atomic two-name exchange, against the
 * REAL namespace_ops.o + beneath.o (renameat2(RENAME_EXCHANGE) through the
 * confined rootfd is the point: the security cases only mean something with
 * the kernel confinement actually live).
 *
 * No protocol verb reaches brix_vfs_exchange yet (the OCI tag flip is
 * phase-108 C10), so this unit is the ONLY behavior coverage for the verb.
 * The contract it pins (namespace_ops.c, §3.5 of the phase doc):
 *   - both names swap in ONE kernel op — witnessed by inode identity, not
 *     content copy (a two-rename emulation would mint new inodes / windows);
 *   - ENOENT unless BOTH names exist (matching renameat2), survivor untouched;
 *   - either name outside the export root refuses EXDEV → BRIX_NS_DENIED,
 *     never a confinement escape — including the "/root"-vs-"/rootevil"
 *     prefix-boundary trap in brix_beneath_strip_root;
 *   - the primitive is type-agnostic (file <-> directory swaps work);
 *   - where the kernel/filesystem cannot exchange names, ENOTSUP leaves both
 *     names, inodes and contents unchanged; confinement still takes precedence.
 *
 * Cross-TU stubs: the impersonation broker (inactive), and namespace_ops.o's
 * delete/mkdir-path externs (unreachable from exchange — abort bodies prove
 * it). ngx_cycle/ngx_log_error_core come from the shared ngx_link_stubs.c.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/namespace_ops.h"
#include "fs/path/beneath.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if (NGX_DARWIN)
#include <sys/stdio.h>
#elif (NGX_LINUX)
#include <sys/syscall.h>
#endif

/* ---- cross-TU stubs ----------------------------------------------------- */

int brix_imp_client_active(void) { return 0; }
int brix_imp_open(const char *p, int f, mode_t m) { (void) p; (void) f; (void) m; abort(); }
int brix_imp_stat(const char *p, struct stat *st, int nf) { (void) p; (void) st; (void) nf; abort(); }
int brix_imp_mkdir(const char *p, mode_t m) { (void) p; (void) m; abort(); }
int brix_imp_unlink(const char *p, int d) { (void) p; (void) d; abort(); }
int brix_imp_rename(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_rename_noreplace(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_rename_exchange(const char *s, const char *d) { (void) s; (void) d; abort(); }
int brix_imp_link(const char *s, const char *d) { (void) s; (void) d; abort(); }

/* namespace_ops.o externs from verbs this unit never drives — abort bodies
 * double as the proof that exchange stays off the delete/mkdir planes. */
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

static char       g_root[128];   /* short so "%s/%s" composes warning-free */
static ngx_log_t  g_log;

static void
put_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");

    assert(f != NULL);
    assert(fputs(content, f) >= 0);
    assert(fclose(f) == 0);
}

static void
expect_file(const char *path, const char *content)
{
    char  buf[64];
    FILE *f = fopen(path, "r");
    size_t n;

    assert(f != NULL);
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    assert(strcmp(buf, content) == 0);
    assert(fclose(f) == 0);
}

static ino_t
ino_of(const char *path)
{
    struct stat sb;

    assert(lstat(path, &sb) == 0);
    return sb.st_ino;
}

/* Probe the OS independently: a broken PAL must not turn successful-swap
 * coverage into an unsupported-capability pass. Never emulate an exchange. */
static int
native_exchange(const char *a, const char *b)
{
#if (NGX_DARWIN)
    return renameatx_np(AT_FDCWD, a, AT_FDCWD, b, RENAME_SWAP);
#elif (NGX_LINUX) && defined(SYS_renameat2)
    return syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 2 /* RENAME_EXCHANGE */);
#elif (NGX_FREEBSD) && defined(RENAME_EXCHANGE)
    return renameat2(AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE);
#else
    (void) a; (void) b;
    errno = ENOTSUP;
    return -1;
#endif
}

static int
exchange_supported(const char *a, const char *b)
{
    ino_t original_a = ino_of(a), original_b = ino_of(b);

    if (native_exchange(a, b) == 0) {
        assert(ino_of(a) == original_b && ino_of(b) == original_a);
        assert(native_exchange(a, b) == 0);
        assert(ino_of(a) == original_a && ino_of(b) == original_b);
        return 1;
    }
    assert(errno == ENOTSUP || errno == EOPNOTSUPP
           || errno == ENOSYS || errno == EINVAL);
    assert(ino_of(a) == original_a && ino_of(b) == original_b);
    return 0;
}

static void
expect_exchange_status(brix_ns_result_t res, int supported)
{
    if (supported) {
        assert(res.status == BRIX_NS_OK && res.sys_errno == 0);
        return;
    }
    assert(res.status == BRIX_NS_IO_ERROR && res.sys_errno == ENOTSUP);
}

static void
expect_missing_status(brix_ns_result_t res, int supported)
{
    if (supported) {
        assert(res.status == BRIX_NS_NOT_FOUND && res.sys_errno == ENOENT);
        return;
    }
    expect_exchange_status(res, 0);
}

int
main(void)
{
    char              a[PATH_MAX], b[PATH_MAX], buf[PATH_MAX];
    ino_t             ino_a, ino_b;
    brix_ns_result_t  res;
    int               supported;

    g_log.log_level = NGX_LOG_DEBUG;
    snprintf(g_root, sizeof(g_root), "/tmp/xchg-%d", (int) getpid());
    assert(mkdir(g_root, 0755) == 0);
    snprintf(buf, sizeof(buf), "%s/d", g_root);
    assert(mkdir(buf, 0755) == 0);

    /* 1. SUCCESS: file <-> file across directories, one kernel op. The inode
     * swap is the atomicity witness: a two-rename emulation (banned by §3.5)
     * would expose an ENOENT window and could not preserve both inodes. */
    snprintf(a, sizeof(a), "%s/a.txt", g_root);
    snprintf(b, sizeof(b), "%s/d/b.txt", g_root);
    put_file(a, "alpha");
    put_file(b, "bravo!");
    ino_a = ino_of(a);
    ino_b = ino_of(b);
    supported = exchange_supported(a, b);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    expect_exchange_status(res, supported);
    expect_file(a, supported ? "bravo!" : "alpha");
    expect_file(b, supported ? "alpha" : "bravo!");
    assert(ino_of(a) == (supported ? ino_b : ino_a));
    assert(ino_of(b) == (supported ? ino_a : ino_b));

    /* 2. SUCCESS: the primitive is type-agnostic — a regular file and a
     * populated directory swap names; the directory's child rides along. */
    snprintf(a, sizeof(a), "%s/plain", g_root);
    snprintf(b, sizeof(b), "%s/subdir", g_root);
    put_file(a, "plain-bytes");
    assert(mkdir(b, 0755) == 0);
    snprintf(buf, sizeof(buf), "%s/subdir/child", g_root);
    put_file(buf, "child-bytes");
    ino_a = ino_of(a);
    ino_b = ino_of(b);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    expect_exchange_status(res, supported);
    assert(ino_of(a) == (supported ? ino_b : ino_a));
    assert(ino_of(b) == (supported ? ino_a : ino_b));
    snprintf(buf, sizeof(buf), "%s/%s/child", g_root,
             supported ? "plain" : "subdir");
    expect_file(buf, "child-bytes");        /* dir now answers to "plain" */
    expect_file(supported ? b : a, "plain-bytes");

    /* 3. ERROR: one name missing → ENOENT/NOT_FOUND (renameat2 semantics:
     * BOTH must exist), and the survivor is untouched — same inode, same
     * bytes. Exchange must never half-create the missing side. */
    snprintf(a, sizeof(a), "%s/a.txt", g_root);
    snprintf(b, sizeof(b), "%s/never-made", g_root);
    ino_a = ino_of(a);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    expect_missing_status(res, supported);
    assert(ino_of(a) == ino_a);
    expect_file(a, supported ? "bravo!" : "alpha");
    assert(access(b, F_OK) == -1);
    assert(errno == ENOENT);

    /* 4. ERROR: both names missing is still plain ENOENT, not a crash or a
     * spurious create. */
    snprintf(a, sizeof(a), "%s/ghost1", g_root);
    snprintf(b, sizeof(b), "%s/ghost2", g_root);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    expect_missing_status(res, supported);
    assert(access(a, F_OK) == -1 && errno == ENOENT);
    assert(access(b, F_OK) == -1 && errno == ENOENT);

    /* 5. SECURITY-NEGATIVE: first name outside the export root → EXDEV /
     * DENIED before any syscall touches it; the outside file survives byte
     * for byte. (Cross-EXPORT exchange is refused at the VFS layer the same
     * way — one rootfd confines both ends here.) */
    snprintf(buf, sizeof(buf), "/tmp/xchg-outside-%d", (int) getpid());
    assert(mkdir(buf, 0755) == 0);
    snprintf(a, sizeof(a), "%s/loot", buf);
    put_file(a, "outside");
    snprintf(b, sizeof(b), "%s/a.txt", g_root);
    ino_b = ino_of(b);
    ino_a = ino_of(a);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    assert(res.status == BRIX_NS_DENIED);
    assert(res.sys_errno == EXDEV);
    expect_file(a, "outside");
    assert(ino_of(a) == ino_a);
    assert(ino_of(b) == ino_b);
    expect_file(b, supported ? "bravo!" : "alpha");

    /* 6. SECURITY-NEGATIVE: second name outside the root refuses identically
     * (the ns_rel arm rather than the strip_root arm). */
    res = brix_ns_exchange(&g_log, g_root, b, a);
    assert(res.status == BRIX_NS_DENIED);
    assert(res.sys_errno == EXDEV);
    expect_file(a, "outside");
    assert(ino_of(a) == ino_a && ino_of(b) == ino_b);
    expect_file(b, supported ? "bravo!" : "alpha");

    /* 7. SECURITY-NEGATIVE: the prefix-boundary trap — "/tmp/xchg-N-evil"
     * shares the root's string prefix but is NOT under it; strip_root must
     * reject at the '/' boundary, not on strncmp alone. */
    snprintf(buf, sizeof(buf), "%s-evil", g_root);
    assert(mkdir(buf, 0755) == 0);
    snprintf(a, sizeof(a), "%s-evil/f", g_root);
    put_file(a, "evil");
    ino_a = ino_of(a);
    res = brix_ns_exchange(&g_log, g_root, a, b);
    assert(res.status == BRIX_NS_DENIED);
    assert(res.sys_errno == EXDEV);
    expect_file(a, "evil");
    assert(ino_of(a) == ino_a && ino_of(b) == ino_b);
    expect_file(b, supported ? "bravo!" : "alpha");

    printf("vfs_exchange: 7 cases ok (native exchange %s)\n",
           supported ? "supported" : "unsupported; ENOTSUP verified");
    return 0;
}
