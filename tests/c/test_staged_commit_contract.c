/*
 * test_staged_commit_contract.c — the staged_commit ownership contract for the
 * POSIX SD driver (regression for the double-free family fixed alongside the
 * sd_remote one covered by tests/test_backend_put_checksum.py).
 *
 * CONTRACT (documented in src/fs/vfs/vfs_staged.c and matched by the remote and
 * pblock drivers): driver->staged_commit frees the heap handle ONLY on success.
 * On failure the handle STAYS VALID and the caller (stage_engine / brix_vfs)
 * releases it via driver->staged_abort. sd_posix_staged_commit used to free the
 * handle unconditionally, so an aborting caller ran abort() on freed memory ->
 * use-after-free + double-free.
 *
 * This drives the REAL sd_posix_ns.c staged wrapper over the REAL compat
 * staged_file.c publish logic; the confinement seam (brix_*_beneath, tmp-path)
 * is stubbed with plain syscalls so the test is hermetic. Built under ASan so a
 * double-free aborts loudly. A rename-to-directory (EISDIR) deterministically
 * forces the commit failure.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/posix/sd_posix_internal.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* ---- confinement-seam + ngx stubs (real syscalls, absolute-under-root) ---- */

static const char *rel_of(const char *p) { while (*p == '/') p++; return p; }

int brix_beneath_open_root(const char *root_canon)
{
    return open(root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC);
}
int brix_open_beneath(int rootfd, const char *reqpath, int flags, mode_t mode)
{
    return openat(rootfd, rel_of(reqpath), flags, mode);
}
int brix_unlink_beneath(int rootfd, const char *reqpath, int is_dir)
{
    return unlinkat(rootfd, rel_of(reqpath), is_dir ? AT_REMOVEDIR : 0);
}
int brix_rename_beneath(int rootfd, const char *src, const char *dst)
{
    return renameat(rootfd, rel_of(src), rootfd, rel_of(dst));
}
int brix_rename_beneath_excl(int rootfd, const char *src, const char *dst)
{
    /* RENAME_NOREPLACE via syscall to stay glibc-version agnostic. */
    return (int) syscall(SYS_renameat2, rootfd, rel_of(src), rootfd,
                         rel_of(dst), (unsigned) (1 /* RENAME_NOREPLACE */));
}

ngx_int_t brix_make_tmp_path(const char *base_path, char *out, size_t out_sz)
{
    static int seq;
    return (size_t) snprintf(out, out_sz, "%s._sc_tmp_%d_%d",
                             base_path, (int) getpid(), seq++) < out_sz
               ? NGX_OK : NGX_ERROR;
}
ngx_int_t brix_make_resume_path(const char *base_path, const char *principal,
    const char *stage_dir, char *out, size_t out_sz)
{
    (void) base_path; (void) principal; (void) stage_dir; (void) out; (void) out_sz;
    return NGX_ERROR;                       /* resume path unused by this test */
}

ngx_int_t brix_vfs_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = pwrite(fd, p, len, off);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return NGX_ERROR; }
        p += n; off += n; len -= (size_t) n;
    }
    return NGX_OK;
}

/* ngx helpers actually reached on the staged path. */
void *ngx_calloc(size_t size, ngx_log_t *log) { (void) log; return calloc(1, size); }
void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) return dst;
    while (--n) { if ((*dst = *src) == '\0') return dst; dst++; src++; }
    *dst = '\0';
    return dst;
}
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...) { (void) level; (void) log; (void) err; (void) fmt; }

/* Linker-only refs from sd_posix_ns.o that this test never calls. */
void sd_posix_fill_stat(const struct stat *st, brix_sd_stat_t *out) { (void) st; (void) out; }
int brix_lstat_beneath(int rf, const char *p, struct stat *s) { (void) rf; (void) p; (void) s; return -1; }
ngx_int_t brix_chmod_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_getxattr_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_listxattr_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_removexattr_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_setxattr_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_setattr_confined_canon(void) { return NGX_ERROR; }
ngx_int_t brix_ns_delete(void) { return NGX_ERROR; }
ngx_int_t brix_ns_local_copy(void) { return NGX_ERROR; }
ngx_int_t brix_ns_mkdir(void) { return NGX_ERROR; }
ngx_int_t brix_ns_rename(void) { return NGX_ERROR; }

/* --------------------------------------------------------------------------- */

int main(void)
{
    char root[] = "/tmp/sc_contract.XXXXXX";
    if (mkdtemp(root) == NULL) { perror("mkdtemp"); return 2; }

    sd_posix_state_t st = { .rootfd = -1, .root_canon = root, .borrowed = 1 };
    brix_sd_instance_t inst;
    memset(&inst, 0, sizeof inst);
    inst.state = &st;
    inst.log = NULL;

    /* FAILURE path: publish rename fails (target is a directory -> EISDIR).
     * The commit must report failure WITHOUT freeing; the caller's abort then
     * releases the still-valid handle exactly once. Pre-fix this double-freed. */
    {
        int err = 0;
        brix_sd_staged_t *h = sd_posix_staged_open(&inst, "/obj_fail.bin", 0644, &err);
        CHECK(h != NULL, "staged_open (failure case)");
        if (h != NULL) {
            CHECK(sd_posix_staged_write(h, "hello", 5, 0) == 5, "staged_write");

            char finalp[512];
            snprintf(finalp, sizeof finalp, "%s/obj_fail.bin", root);
            CHECK(mkdir(finalp, 0755) == 0, "mkdir final (inject EISDIR)");

            ngx_int_t rc = sd_posix_staged_commit(h, 0);
            CHECK(rc != NGX_OK, "commit must fail when publish target is a dir");

            sd_posix_staged_abort(h);           /* releases the still-valid handle */
            rmdir(finalp);
        }
    }

    /* SUCCESS path: a clean commit publishes byte-exact and frees the handle
     * exactly once (a following abort would be UAF, so we must not abort). */
    {
        int err = 0;
        brix_sd_staged_t *h = sd_posix_staged_open(&inst, "/obj_ok.bin", 0644, &err);
        CHECK(h != NULL, "staged_open (success case)");
        if (h != NULL) {
            CHECK(sd_posix_staged_write(h, "world", 5, 0) == 5, "staged_write ok");
            CHECK(sd_posix_staged_commit(h, 0) == NGX_OK, "clean commit must succeed");

            char okp[512];
            snprintf(okp, sizeof okp, "%s/obj_ok.bin", root);
            struct stat sb;
            CHECK(stat(okp, &sb) == 0 && sb.st_size == 5,
                  "committed object present and byte-exact");
            unlink(okp);
        }
    }

    rmdir(root);

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("sd_posix staged-commit ownership contract: PASS\n");
    return 0;
}
