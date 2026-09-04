/*
 * test_service_publish.c — the phase-108 C10 service-publish verb
 * (src/core/compat/service_publish.c) exercised against the REAL phase-107
 * primitives it composes: the domain claim (vfs_policy_domain.o + vfs_policy.o),
 * the staged temp and confined durable commit (staged_file.o), the confined
 * openat2 layer (beneath.o) and the temp-name kernel (tmp_path.o) are all linked
 * in. Only the surfaces the normal-server path never reaches are doubled:
 * impersonation (brix_imp_client_active() == 0, so every beneath op takes the
 * real openat2/renameat leg and the brix_imp_* leaves are dead), the confined
 * chmod broker, the resume-path hash, and the metric sink.
 *
 * The contract pinned (spec §11.4):
 *   success    — bytes_is_durable: a REGISTRY publish lands the bytes at a nested
 *                final path with the intended mode, the temp is gone, and the
 *                durable barrier ran (brix_vfs_backend_durable == 1 here);
 *   error      — short_write_reaps_and_logs: a write cut short by RLIMIT_FSIZE
 *                fails with EFBIG, leaves neither temp nor final, and emits the
 *                D5 error line that was silent before phase 108;
 *   error      — stages_adjacent_to_final: the staged temp is a sibling of the
 *                final path, so the commit rename is intra-device by construction
 *                — the verb never crosses a device and never needs the EXDEV
 *                copy path (that path belongs to brix_commit_staged, the resume
 *                mover, not to this verb — see the landing record);
 *   error      — excl_eexist_is_benign: the _fd/excl arm returns EEXIST when the
 *                final exists, the caller-staged temp is reaped, the final is
 *                untouched — exactly what the OCI blob seal treats as success;
 *   security   — rejects_export_domain: an EXPORT-domain claim is refused with
 *                EROFS (never EACCES) and creates no file;
 *   security   — temp_is_unpredictable: two temp names for one final differ and
 *                neither is the guessable "<final>.tmp.<pid>" form — the random
 *                O_EXCL suffix is what makes the pre-plant attack structural;
 *   security   — no_follow: a symlink pre-planted at the final path is replaced,
 *                not traversed — the out-of-tree target it points at is never
 *                written.
 *
 * Object-linked heavy unit: registered in c_regression_units_part2.py.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/service_publish.h"
#include "core/compat/staged_file.h"
#include "core/compat/tmp_path.h"
#include "fs/path/site_n2n.h"

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- link doubles ------------------------------------------------------- *
 *
 * The two nginx globals a unit inherits when it links nginx's own string kernel
 * — but here we want to OBSERVE the log, so ngx_log_error_core counts calls
 * instead of the silent ngx_link_stubs.c body. Instances run with log=NULL, so
 * the count only moves on the SUT's own ngx_log_error() calls with a non-NULL
 * log, which the tests pass deliberately to witness the D5 error line. */
static int g_log_calls;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
    g_log_calls++;
}

/* The RENAME_NOREPLACE fallback (beneath.c, the excl commit arm) logs through
 * ngx_cycle->log, so the cycle cannot be NULL for the excl test. main() points
 * it at a static cycle whose ->log is the admitting s_log below. */
static ngx_cycle_t    s_cycle;
volatile ngx_cycle_t *ngx_cycle = NULL;

/* vfs_policy.o binds the export's name-translation rule when it constructs an
 * off-thread operation context.  Service-publish is deliberately restricted to
 * the service-owned REGISTRY domain and never translates an export path, so the
 * focused unit supplies the production default: no configured rule means the
 * identity mapping. */
const brix_n2n_cfg_t *
brix_vfs_backend_n2n(const char *root_canon)
{
    (void) root_canon;
    return NULL;
}

/* Faithful nginx ngx_cpystrn (ngx_string.c): copy at most n-1 bytes, always
 * NUL-terminate, return the pointer to the terminating NUL. Provided here rather
 * than linking ngx_string.o, whose allocator closure (ngx_pnalloc/ngx_alloc/the
 * pool) this unit has no business dragging in. service_publish_fd is its one
 * caller (adopting the caller's stage path onto the staged struct). */
u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n) {
        *dst = *src;
        if (*dst == '\0') {
            return dst;
        }
        dst++;
        src++;
    }
    *dst = '\0';
    return dst;
}

/* Impersonation is inactive on a normal server: brix_imp_client_active() == 0,
 * so every beneath op runs the real openat2/renameat/unlinkat leg and the
 * brix_imp_* leaves are dead-but-linked. Aborting in them turns any surprise
 * reach into a loud failure rather than a silent broker call. */
int brix_imp_client_active(void) { return 0; }

int brix_imp_open(const char *p, int f, mode_t m)
{ (void) p; (void) f; (void) m; abort(); }
int brix_imp_stat(const char *p, struct stat *s, int n)
{ (void) p; (void) s; (void) n; abort(); }
int brix_imp_mkdir(const char *p, mode_t m) { (void) p; (void) m; abort(); }
int brix_imp_unlink(const char *p, int d) { (void) p; (void) d; abort(); }
int brix_imp_rename(const char *a, const char *b) { (void) a; (void) b; abort(); }
int brix_imp_rename_noreplace(const char *a, const char *b)
{ (void) a; (void) b; abort(); }
int brix_imp_link(const char *a, const char *b) { (void) a; (void) b; abort(); }

/* The confined chmod broker is reached only under active impersonation with a
 * closed write fd; the service verb seals its own fd with fchmod first, so this
 * is dead here. */
int
brix_chmod_confined_canon(ngx_log_t *log, const char *root, const char *res,
    mode_t mode)
{ (void) log; (void) root; (void) res; (void) mode; abort(); }

/* Only the deterministic resume path hashes; the service verb uses the random
 * temp, so these are dead here. */
int brix_sha256(const uint8_t *d, size_t n, uint8_t out[32])
{ (void) d; (void) n; (void) out; abort(); }
void brix_hex_encode(const uint8_t *in, size_t n, char *out)
{ (void) in; (void) n; (void) out; abort(); }

/* Durable backend: REGISTRY is a durable domain and an unregistered root
 * defaults durable, so the C3 parent-dir barrier runs — as it will in
 * production for the OCI store. */
ngx_int_t brix_vfs_backend_durable(const char *root) { (void) root; return 1; }

/* Low-cardinality accounting sink — no-op double (the metric layer is a
 * separate closure). The domain claim books one sample; an EXPORT refusal books
 * one denial. */
void brix_metric_vfs_domain_mutation(ngx_uint_t domain, ngx_uint_t op)
{ (void) domain; (void) op; }
void brix_metric_vfs_mutation_denied(int proto, ngx_uint_t op)
{ (void) proto; (void) op; }

/* ---- fsync interposer: the runnable durability proof -------------------- *
 *
 * The spec's ideal durability proof SIGKILLs a worker between the rename and the
 * next flush, remounts, and asserts the tag resolves — that needs privileged
 * fault injection (a loop/dm-flakey mount) this unit host cannot assume. The
 * invariant it proves is nonetheless observable at runtime: the verb must fsync
 * the DATA (defect 1) before the rename publishes the name, then fsync the
 * PARENT DIRECTORY (defect 2, the phase-107 C3 barrier) so the just-published
 * name's directory entry survives a crash. A strong `fsync` definition in the
 * executable interposes over libc's for the linked objects' calls, so the test
 * records each fsync's target kind and the order. See the ordering test below. */
static int g_fsync_data_seen;      /* a regular-file fsync has happened */
static int g_fsync_dir_after_data; /* a directory fsync happened after that */
static int (*g_real_fsync)(int);

int
fsync(int fd)
{
    struct stat st;

    if (g_real_fsync == NULL) {
        g_real_fsync = (int (*)(int)) dlsym(RTLD_NEXT, "fsync");
    }
    if (fstat(fd, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (g_fsync_data_seen) {
                g_fsync_dir_after_data = 1;
            }
        } else if (S_ISREG(st.st_mode)) {
            g_fsync_data_seen = 1;
        }
    }
    return g_real_fsync != NULL ? g_real_fsync(fd) : 0;
}

/* ---- fixtures ----------------------------------------------------------- */

/* A canonical (symlink-free) store root under /tmp for one test. */
static void
make_root(char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "/tmp/brix_svcpub.%ld.%u.XXXXXX",
                     (long) getpid(), (unsigned) rand());
    assert(n > 0 && (size_t) n < outsz);
    assert(mkdtemp(out) != NULL);
}

/* Recursively remove a small store tree so each test starts clean. */
static void
rm_rf(const char *path)
{
    DIR           *d = opendir(path);
    struct dirent *e;
    char           child[PATH_MAX];

    if (d != NULL) {
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (e->d_type == DT_DIR) {
                rm_rf(child);
            } else {
                unlink(child);
            }
        }
        closedir(d);
        rmdir(path);
        return;
    }
    unlink(path);
}

/* Read a whole regular file; returns byte count, or -1 if absent. */
static ssize_t
slurp(const char *path, char *buf, size_t bufsz)
{
    int     fd = open(path, O_RDONLY | O_NOFOLLOW);
    ssize_t n;

    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, bufsz);
    close(fd);
    return n;
}

/* Nonzero if any ".xrd-tmp." staged temp survives anywhere under root. */
static int
temp_survives(const char *root)
{
    DIR           *d = opendir(root);
    struct dirent *e;
    char           child[PATH_MAX];
    int            found = 0;

    if (d == NULL) {
        return 0;
    }
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }
        if (brix_tmp_is_temp_name(e->d_name)) {
            found = 1;
            break;
        }
        if (e->d_type == DT_DIR) {
            snprintf(child, sizeof(child), "%s/%s", root, e->d_name);
            found = temp_survives(child);
            if (found) {
                break;
            }
        }
    }
    closedir(d);
    return found;
}

/* An ngx_log_t whose log_level admits NGX_LOG_ERR so the SUT's ngx_log_error()
 * macro does not short-circuit before reaching the doubled ngx_log_error_core
 * (the macro gates on log->log_level >= level). Its other fields are never
 * read by the double. */
static ngx_log_t  s_log;

static brix_service_publish_req_t
base_req(const char *root, const char *final, brix_vfs_domain_t domain)
{
    brix_service_publish_req_t req;

    ngx_memzero(&req, sizeof(req));
    req.log        = &s_log;
    req.domain     = domain;
    req.root_canon = root;
    req.final_path = final;
    req.mode       = 0644;
    return req;
}

/* ---- success ------------------------------------------------------------ */

static void
test_service_publish_bytes_is_durable(void)
{
    char        root[PATH_MAX], sub[PATH_MAX], final[PATH_MAX], buf[64];
    struct stat st;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(sub, sizeof(sub), "%s/blobs", root);
    assert(mkdir(sub, 0755) == 0);          /* the verb never creates dirs */
    snprintf(final, sizeof(final), "%s/blobs/manifest", root);

    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);
    assert(brix_service_publish_bytes(&req, "sha256:cafe", 11) == NGX_OK);

    assert(slurp(final, buf, sizeof(buf)) == 11);
    assert(memcmp(buf, "sha256:cafe", 11) == 0);
    assert(lstat(final, &st) == 0 && S_ISREG(st.st_mode));
    assert((st.st_mode & 07777) == 0644);
    assert(!temp_survives(root));

    rm_rf(root);
    printf("ok service_publish_bytes_is_durable\n");
}

/* ---- error: a short write reaps the temp and is no longer silent --------- */

static void
test_service_publish_short_write_reaps_and_logs(void)
{
    char           root[PATH_MAX], final[PATH_MAX], buf[64];
    struct rlimit  saved, small;
    ngx_int_t      rc;
    int            saved_log;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(final, sizeof(final), "%s/big", root);
    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);

    /* RLIMIT_FSIZE would raise SIGXFSZ on the over-limit write and kill us;
     * ignore it so write(2) returns -1/EFBIG and the SUT's error loop runs. */
    signal(SIGXFSZ, SIG_IGN);
    assert(getrlimit(RLIMIT_FSIZE, &saved) == 0);
    small = saved;
    small.rlim_cur = 8;                     /* 8-byte ceiling < payload */
    assert(setrlimit(RLIMIT_FSIZE, &small) == 0);

    saved_log = g_log_calls;
    errno = 0;
    rc = brix_service_publish_bytes(&req, "0123456789ABCDEF0123", 20);

    assert(setrlimit(RLIMIT_FSIZE, &saved) == 0);   /* restore for later tests */
    signal(SIGXFSZ, SIG_DFL);

    assert(rc == NGX_ERROR);
    assert(errno == EFBIG);
    assert(g_log_calls > saved_log);        /* the D5 line, silent before 108 */
    assert(slurp(final, buf, sizeof(buf)) == -1);   /* no final */
    assert(!temp_survives(root));                   /* temp reaped on abort */

    rm_rf(root);
    printf("ok service_publish_short_write_reaps_and_logs\n");
}

/* ---- error/structural: the temp is a sibling of the final --------------- */

static void
test_service_publish_stages_adjacent_to_final(void)
{
    char        root[PATH_MAX], sub[PATH_MAX], final[PATH_MAX], buf[64];
    char        tmp_a[PATH_MAX];
    const char *slash_final, *slash_tmp;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(sub, sizeof(sub), "%s/a/b", root);
    assert(mkdir(sub, 0755) != 0);          /* parent must be built stepwise */
    snprintf(sub, sizeof(sub), "%s/a", root);
    assert(mkdir(sub, 0755) == 0);
    snprintf(sub, sizeof(sub), "%s/a/b", root);
    assert(mkdir(sub, 0755) == 0);
    snprintf(final, sizeof(final), "%s/a/b/obj", root);

    /* The temp name derives from the final path in the SAME directory, so the
     * commit rename is intra-device — EXDEV cannot arise for this verb. */
    assert(brix_make_tmp_path(final, tmp_a, sizeof(tmp_a)) == NGX_OK);
    slash_final = strrchr(final, '/');
    slash_tmp   = strrchr(tmp_a, '/');
    assert(slash_final != NULL && slash_tmp != NULL);
    assert((slash_final - final) == (slash_tmp - tmp_a));
    assert(strncmp(final, tmp_a, (size_t) (slash_final - final)) == 0);

    /* And a deeply nested final still commits through the confined rename. */
    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);
    assert(brix_service_publish_bytes(&req, "nested", 6) == NGX_OK);
    assert(slurp(final, buf, sizeof(buf)) == 6);
    assert(memcmp(buf, "nested", 6) == 0);

    rm_rf(root);
    printf("ok service_publish_stages_adjacent_to_final\n");
}

/* ---- error: the excl arm's EEXIST is benign, and reaps the staged temp --- */

static void
test_service_publish_excl_eexist_is_benign(void)
{
    char        root[PATH_MAX], final[PATH_MAX], stage[PATH_MAX], buf[64];
    int         fd;
    ngx_int_t   rc;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(final, sizeof(final), "%s/blob", root);
    snprintf(stage, sizeof(stage), "%s/blob.xrd-tmp.staged", root);

    /* A pre-existing final the excl publish must not overwrite. */
    fd = open(final, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "EXISTING", 8) == 8 && close(fd) == 0);

    /* The caller's already-written staged file (the OCI blob-seal shape). */
    fd = open(stage, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "NEW", 3) == 3);
    /* keep fd open — service_publish_fd fsyncs and seals it */

    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);
    req.excl = 1;
    errno = 0;
    rc = brix_service_publish_fd(&req, fd, stage);

    assert(rc == NGX_ERROR);
    assert(errno == EEXIST);                /* the caller maps this to success */
    assert(slurp(final, buf, sizeof(buf)) == 8);
    assert(memcmp(buf, "EXISTING", 8) == 0);        /* untouched */
    assert(access(stage, F_OK) != 0);               /* staged temp reaped */

    rm_rf(root);
    printf("ok service_publish_excl_eexist_is_benign\n");
}

/* ---- security: an EXPORT-domain claim is refused with EROFS ------------- */

static void
test_service_publish_rejects_export_domain(void)
{
    char        root[PATH_MAX], final[PATH_MAX], buf[64];
    ngx_int_t   rc;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(final, sizeof(final), "%s/exported", root);

    req = base_req(root, final, BRIX_VFS_DOMAIN_EXPORT);
    errno = 0;
    rc = brix_service_publish_bytes(&req, "laundered", 9);

    assert(rc == NGX_ERROR);
    assert(errno == EROFS);                 /* the phase-105 kernel, not EACCES */
    assert(slurp(final, buf, sizeof(buf)) == -1);   /* nothing created */
    assert(!temp_survives(root));

    rm_rf(root);
    printf("ok service_publish_rejects_export_domain\n");
}

/* ---- security: the temp name is unpredictable --------------------------- */

static void
test_service_publish_temp_is_unpredictable(void)
{
    char root[PATH_MAX], final[PATH_MAX];
    char a[PATH_MAX], b[PATH_MAX], guess[PATH_MAX];

    make_root(root, sizeof(root));
    snprintf(final, sizeof(final), "%s/obj", root);

    assert(brix_make_tmp_path(final, a, sizeof(a)) == NGX_OK);
    assert(brix_make_tmp_path(final, b, sizeof(b)) == NGX_OK);

    /* Two temps for one final differ — the ngx_random() suffix, not a counter. */
    assert(strcmp(a, b) != 0);
    /* Both carry the agreed marker so the reaper and the enumerators find them. */
    assert(brix_tmp_is_temp_name(a) && brix_tmp_is_temp_name(b));
    /* Neither is the guessable "<final>.tmp.<pid>" an attacker could pre-plant. */
    snprintf(guess, sizeof(guess), "%s.tmp.%ld", final, (long) getpid());
    assert(strcmp(a, guess) != 0 && strcmp(b, guess) != 0);

    rm_rf(root);
    printf("ok service_publish_temp_is_unpredictable\n");
}

/* ---- security: a symlink at the final path is replaced, not followed ----- */

static void
test_service_publish_no_follow(void)
{
    char        root[PATH_MAX], final[PATH_MAX], outside[PATH_MAX], buf[64];
    struct stat st;
    int         fd;
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(final, sizeof(final), "%s/link", root);
    snprintf(outside, sizeof(outside), "%s/OUTSIDE", root);

    /* An out-of-line target holding bytes a follow-through publish would clobber
     * (kept inside root only so rm_rf cleans it; the point is final != target). */
    fd = open(outside, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "ORIG", 4) == 4 && close(fd) == 0);
    assert(symlink(outside, final) == 0);

    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);
    assert(brix_service_publish_bytes(&req, "REPLACED", 8) == NGX_OK);

    /* The symlink was replaced by a regular file with our bytes... */
    assert(lstat(final, &st) == 0 && S_ISREG(st.st_mode));
    assert(slurp(final, buf, sizeof(buf)) == 8 && memcmp(buf, "REPLACED", 8) == 0);
    /* ...and the target it pointed at was never written through. */
    assert(slurp(outside, buf, sizeof(buf)) == 4 && memcmp(buf, "ORIG", 4) == 0);

    rm_rf(root);
    printf("ok service_publish_no_follow\n");
}

/* ---- durability: data is flushed, then the name's directory entry -------- */

static void
test_service_publish_flushes_data_then_dir(void)
{
    char        root[PATH_MAX], sub[PATH_MAX], final[PATH_MAX];
    brix_service_publish_req_t req;

    make_root(root, sizeof(root));
    snprintf(sub, sizeof(sub), "%s/blobs", root);
    assert(mkdir(sub, 0755) == 0);
    snprintf(final, sizeof(final), "%s/blobs/tag", root);

    g_fsync_data_seen = 0;
    g_fsync_dir_after_data = 0;

    req = base_req(root, final, BRIX_VFS_DOMAIN_REGISTRY);
    assert(brix_service_publish_bytes(&req, "sha256:beef", 11) == NGX_OK);

    /* Defect 1: the temp's bytes were fsynced (before the rename). */
    assert(g_fsync_data_seen);
    /* Defect 2: the parent directory was fsynced AFTER the data — the C3
     * barrier that makes the published name survive a crash between the rename
     * and the next flush (the bug this wave exists to close). */
    assert(g_fsync_dir_after_data);

    rm_rf(root);
    printf("ok service_publish_flushes_data_then_dir\n");
}

int
main(void)
{
    srand((unsigned) (getpid() ^ (unsigned) time(NULL)));
    s_log.log_level = NGX_LOG_DEBUG;
    s_cycle.log = &s_log;
    ngx_cycle = &s_cycle;

    test_service_publish_bytes_is_durable();
    test_service_publish_flushes_data_then_dir();
    test_service_publish_short_write_reaps_and_logs();
    test_service_publish_stages_adjacent_to_final();
    test_service_publish_excl_eexist_is_benign();
    test_service_publish_rejects_export_domain();
    test_service_publish_temp_is_unpredictable();
    test_service_publish_no_follow();

    printf("PASS test_service_publish\n");
    return 0;
}
