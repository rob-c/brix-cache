/*
 * test_cred_stage.c — standalone unit test for the harmonized credential
 * staging facility (src/core/compat/cred_stage.c) that backs A-5.
 *
 * The facility is the single place every credential stager (native TPC token
 * exchange, WebDAV TPC, GSI proxy delegation) routes through instead of
 * open-coding mkstemp("/tmp/..."). This test pins the security-relevant
 * contract:
 *
 *   success  — brix_cred_stage_write() creates a 0600 file under the per-uid
 *              /dev/shm/brix-creds.<euid> tmpfs dir, round-trips the bytes, and
 *              hands back distinct paths on repeated calls;
 *   dir      — brix_cred_stage_dir() creates the parent 0700, owned by euid;
 *   security — a pre-existing staging dir with loosened (group/other) mode is
 *              rejected (fail closed, EPERM) rather than trusted;
 *   never-/tmp — the returned path always lives under /dev/shm, never /tmp;
 *   error    — NULL arguments are rejected with EINVAL.
 *
 * ngx-free: links against libc only, mirroring the kernel it exercises.
 */
#include "core/compat/cred_stage.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Reconstruct the per-uid staging dir path the way cred_stage.c does, so the
 * test can inspect and manipulate it directly. Kept in lockstep with the
 * BRIX_CRED_STAGE_BASE ".<euid>" convention. */
static void
staging_dir(char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "/dev/shm/brix-creds.%u",
                     (unsigned) geteuid());
    assert(n > 0 && (size_t) n < outsz);
}

/* Remove the staging dir and everything in it so each test starts from a known
 * state (a prior aborted run may have left a loosened dir or stray files). */
static void
reset_dir(void)
{
    char           dir[64];
    DIR           *d;
    struct dirent *ent;

    staging_dir(dir, sizeof(dir));

    /* Make sure we can traverse/unlink even if a negative test loosened it. */
    (void) chmod(dir, 0700);

    d = opendir(dir);
    if (d != NULL) {
        while ((ent = readdir(d)) != NULL) {
            char path[512];
            if (strcmp(ent->d_name, ".") == 0
                || strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
            unlink(path);
        }
        closedir(d);
    }
    (void) rmdir(dir);
}

/* success: a staged file exists, is 0600, round-trips its bytes, and a second
 * call returns a DIFFERENT path (mkstemp uniqueness). */
static void
test_write_success(void)
{
    const char   secret[] = "grant_type=token-exchange&subject_token=DEADBEEF";
    char         path1[512];
    char         path2[512];
    struct stat  st;
    char         readback[128];
    int          fd;
    ssize_t      n;

    reset_dir();

    assert(brix_cred_stage_write("ut_body_", secret, sizeof(secret) - 1,
                                 path1, sizeof(path1)) == 0);

    /* File exists with owner-only 0600 permissions. */
    assert(lstat(path1, &st) == 0);
    assert(S_ISREG(st.st_mode));
    assert((st.st_mode & 07777) == 0600);
    assert(st.st_uid == geteuid());

    /* Round-trip: the file holds exactly the bytes we staged. */
    fd = open(path1, O_RDONLY);
    assert(fd >= 0);
    n = read(fd, readback, sizeof(readback));
    close(fd);
    assert(n == (ssize_t) (sizeof(secret) - 1));
    assert(memcmp(readback, secret, sizeof(secret) - 1) == 0);

    /* A second stage yields a distinct path (no name reuse / clobber). */
    assert(brix_cred_stage_write("ut_body_", secret, sizeof(secret) - 1,
                                 path2, sizeof(path2)) == 0);
    assert(strcmp(path1, path2) != 0);

    unlink(path1);
    unlink(path2);
    printf("ok write_success\n");
}

/* dir: the staging parent is created 0700 and owned by the effective uid. */
static void
test_dir_is_private(void)
{
    char        dir[64];
    struct stat st;

    reset_dir();

    assert(brix_cred_stage_dir(dir, sizeof(dir)) == 0);
    assert(lstat(dir, &st) == 0);
    assert(S_ISDIR(st.st_mode));
    assert((st.st_mode & 0077) == 0);       /* no group/other access */
    assert(st.st_uid == geteuid());
    printf("ok dir_is_private\n");
}

/* never-/tmp: the resolved path lives on tmpfs under /dev/shm, never /tmp. */
static void
test_never_tmp(void)
{
    char path[512];

    reset_dir();

    assert(brix_cred_stage_write("ut_", "x", 1, path, sizeof(path)) == 0);
    assert(strncmp(path, "/dev/shm/brix-creds.", 20) == 0);
    assert(strncmp(path, "/tmp/", 5) != 0);
    unlink(path);
    printf("ok never_tmp\n");
}

/* security: a pre-existing staging dir with a loosened mode (group/other bits
 * set) must be refused, not reused — otherwise a co-tenant that pre-created a
 * world-accessible dir could read staged secrets. */
static void
test_loose_mode_rejected(void)
{
    char dir[64];
    char path[512];

    reset_dir();
    staging_dir(dir, sizeof(dir));

    /* Pre-create the exact staging dir world-accessible (chmod defeats umask). */
    assert(mkdir(dir, 0700) == 0);
    assert(chmod(dir, 0777) == 0);

    errno = 0;
    assert(brix_cred_stage_dir(dir, sizeof(dir)) == -1);
    assert(errno == EPERM);

    /* And the higher-level write refuses too — fail closed, no file created. */
    staging_dir(dir, sizeof(dir));
    (void) chmod(dir, 0777);
    errno = 0;
    assert(brix_cred_stage_write("ut_", "x", 1, path, sizeof(path)) == -1);

    reset_dir();
    printf("ok loose_mode_rejected\n");
}

/* error: NULL arguments are rejected with EINVAL, no file created. */
static void
test_invalid_args(void)
{
    char path[512];

    reset_dir();

    errno = 0;
    assert(brix_cred_stage_write(NULL, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(brix_cred_stage_write("ut_", NULL, 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(brix_cred_stage_write("ut_", "x", 1, NULL, sizeof(path)) == -1);
    assert(errno == EINVAL);

    printf("ok invalid_args\n");
}

/* ---- phase-108 C11: the shared credential-write engine ---- */

#include <signal.h>
#include <sys/resource.h>
#include <dlfcn.h>              /* dlsym(RTLD_NEXT) for the fsync interposer */

/* fsync interposer — the runtime witness for the C11 durability contract.
 * A strong definition here overrides libc's fsync for the linked cred_stage.o,
 * so the test observes exactly which fds the engine flushes and in what order.
 * Classified by fstat: a regular file is the staged data, a directory is the
 * parent-dir barrier. Mirrors test_service_publish.c's interposer. */
static int (*g_real_fsync)(int) = NULL;
static int g_fsync_data_seen = 0;        /* a regular-file fsync happened */
static int g_fsync_dir_after_data = 0;   /* a dir fsync happened, AFTER data */
static int g_fsync_any = 0;              /* any fsync at all (for the absence proof) */

int
fsync(int fd)
{
    struct stat st;

    if (g_real_fsync == NULL) {
        g_real_fsync = (int (*)(int)) dlsym(RTLD_NEXT, "fsync");
    }
    g_fsync_any = 1;
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

/* close interposer — the runtime witness for "close() IS a write error". When
 * armed, it fails the NEXT regular-file close with EIO (one-shot), so the test
 * drives the engine's checked-close branch through the shipped code instead of
 * only source-pinning the `if (close(fd) != 0)` string. The fd is ALWAYS really
 * closed first (no leak); only the reported result is forced. Disarmed, it is a
 * transparent pass-through — a directory close (opendir/closedir) never trips it
 * because it is not S_ISREG. */
static int (*g_real_close)(int) = NULL;
static int g_fail_next_reg_close = 0;    /* arm: fail the next regular-file close */

int
close(int fd)
{
    struct stat st;
    int         want_fail = 0, r;

    if (g_real_close == NULL) {
        g_real_close = (int (*)(int)) dlsym(RTLD_NEXT, "close");
    }
    if (g_fail_next_reg_close && fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        want_fail = 1;
        g_fail_next_reg_close = 0;        /* one-shot */
    }
    r = g_real_close != NULL ? g_real_close(fd) : 0;
    if (want_fail) {
        errno = EIO;
        return -1;
    }
    return r;
}

/* Build a fresh private scratch directory for the PERSISTENT arm's
 * destination; mkdtemp gives 0700 under the test's own uid. */
static void
persist_dir(char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "/dev/shm/brix-cred-ut-XXXXXX");
    assert(n > 0 && (size_t) n < outsz);
    assert(mkdtemp(out) != NULL);
}

/* Count non-dot entries; -1 when the dir cannot be opened. Used to prove the
 * reap invariant: no failure branch may leave a temp file behind. */
static int
dir_entry_count(const char *dir)
{
    DIR           *d = opendir(dir);
    struct dirent *ent;
    int            count = 0;

    if (d == NULL) {
        return -1;
    }
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
            count++;
        }
    }
    closedir(d);
    return count;
}

static void
rm_tree(const char *dir)
{
    DIR           *d = opendir(dir);
    struct dirent *ent;

    if (d != NULL) {
        while ((ent = readdir(d)) != NULL) {
            char path[512];
            if (strcmp(ent->d_name, ".") == 0
                || strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
            (void) unlink(path);
            (void) rmdir(path);
        }
        closedir(d);
    }
    (void) rmdir(dir);
}

/* success: the engine's VOLATILE arm holds brix_cred_stage_write's contract —
 * 0600 file under the per-uid tmpfs dir, byte round-trip, distinct paths. */
static void
test_cred_write_volatile_matches_stage_write(void)
{
    brix_cred_write_req_t req;
    const char            secret[] = "volatile-arm-secret";
    char                  path1[512], path2[512];
    struct stat           st;
    char                  readback[64];
    int                   fd;
    ssize_t               n;

    reset_dir();

    memset(&req, 0, sizeof(req));
    req.arm    = BRIX_CRED_ARM_VOLATILE;
    req.kind   = BRIX_CRED_KIND_BEARER;
    req.prefix = "ut_engine_";

    assert(brix_cred_write_engine(&req, secret, sizeof(secret) - 1,
                                  path1, sizeof(path1)) == 0);
    assert(strncmp(path1, "/dev/shm/brix-creds.", 20) == 0);
    assert(strstr(path1, "/ut_engine_") != NULL);
    assert(lstat(path1, &st) == 0);
    assert(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0600);

    fd = open(path1, O_RDONLY);
    assert(fd >= 0);
    n = read(fd, readback, sizeof(readback));
    close(fd);
    assert(n == (ssize_t) (sizeof(secret) - 1));
    assert(memcmp(readback, secret, sizeof(secret) - 1) == 0);

    assert(brix_cred_write_engine(&req, secret, sizeof(secret) - 1,
                                  path2, sizeof(path2)) == 0);
    assert(strcmp(path1, path2) != 0);

    unlink(path1);
    unlink(path2);
    printf("ok cred_write_volatile_matches_stage_write\n");
}

/* success: the PERSISTENT arm publishes <dir>/<name> atomically — final file
 * 0600 with the exact bytes, path_out is the final path, and NO temp remains
 * (the dot-temp existed only between create and rename). The fsync calls
 * themselves are pinned at source level by test_cred_write_parity. */
static void
test_cred_write_persistent_publishes_final(void)
{
    brix_cred_write_req_t req;
    const char            pem[] = "-----BEGIN UT-----\nx\n-----END UT-----\n";
    char                  dir[64], path[512], expect[600];
    struct stat           st;

    persist_dir(dir, sizeof(dir));

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "subject.pem";

    assert(brix_cred_write_engine(&req, pem, sizeof(pem) - 1,
                                  path, sizeof(path)) == 0);
    snprintf(expect, sizeof(expect), "%s/subject.pem", dir);
    assert(strcmp(path, expect) == 0);
    assert(lstat(path, &st) == 0);
    assert(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0600);
    assert(st.st_size == (off_t) (sizeof(pem) - 1));
    assert(dir_entry_count(dir) == 1);      /* the final file, no temp */

    /* Re-publish over an existing name: rename replaces atomically. */
    assert(brix_cred_write_engine(&req, "v2", 2, path, sizeof(path)) == 0);
    assert(lstat(path, &st) == 0 && st.st_size == 2);
    assert(dir_entry_count(dir) == 1);

    rm_tree(dir);
    printf("ok cred_write_persistent_publishes_final\n");
}

/* error: a write that cannot complete (RLIMIT_FSIZE forces the kernel to
 * refuse the bytes past the cap) is an ERROR, never a silently truncated
 * secret — and the failed temp is reaped on the way out. */
static void
test_cred_write_short_write_is_an_error(void)
{
    brix_cred_write_req_t req;
    struct rlimit         old, tiny;
    char                  dir[64], path[512];
    unsigned char         big[64];

    persist_dir(dir, sizeof(dir));
    memset(big, 0x42, sizeof(big));

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "cap.pem";

    assert(getrlimit(RLIMIT_FSIZE, &old) == 0);
    signal(SIGXFSZ, SIG_IGN);               /* take EFBIG, not the signal */
    tiny = old;
    tiny.rlim_cur = 8;                      /* first write is short, next EFBIG */
    assert(setrlimit(RLIMIT_FSIZE, &tiny) == 0);

    errno = 0;
    assert(brix_cred_write_engine(&req, big, sizeof(big),
                                  path, sizeof(path)) == -1);
    assert(errno == EFBIG);

    assert(setrlimit(RLIMIT_FSIZE, &old) == 0);
    signal(SIGXFSZ, SIG_DFL);

    assert(dir_entry_count(dir) == 0);      /* reaped: no temp, no final */
    rm_tree(dir);
    printf("ok cred_write_short_write_is_an_error\n");
}

/* error+reap: every forceable failure branch leaves the destination dir
 * empty — request-shape refusals before any fd, and the late rename branch
 * (a directory squatting on the final name) after the temp existed. */
static void
test_cred_write_reaps_on_every_branch(void)
{
    brix_cred_write_req_t req;
    char                  dir[64], path[512], squat[600];

    persist_dir(dir, sizeof(dir));

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;

    /* Shape refusals: '/' in the name, dot-dirs, missing name — EINVAL,
     * nothing created (the '/' rule is what keeps a name from walking the
     * write out of the claimed directory). */
    static const char *bad_names[] = { "../escape.pem", "a/b.pem", ".", "..",
                                       "", NULL };
    for (int i = 0; i < 6; i++) {
        req.name = bad_names[i];
        errno = 0;
        assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
        assert(errno == EINVAL);
    }
    assert(dir_entry_count(dir) == 0);

    /* A too-small caller buffer is refused before any file exists. */
    req.name = "fits.pem";
    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, 4) == -1);
    assert(errno == ENAMETOOLONG);
    assert(dir_entry_count(dir) == 0);

    /* Late branch: a DIRECTORY on the final name makes rename fail after the
     * temp was created, written, and fsynced — the temp must still be reaped. */
    snprintf(squat, sizeof(squat), "%s/taken.pem", dir);
    assert(mkdir(squat, 0700) == 0);
    req.name = "taken.pem";
    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
    assert(dir_entry_count(dir) == 1);      /* only the squatting dir */
    assert(rmdir(squat) == 0);

    rm_tree(dir);
    printf("ok cred_write_reaps_on_every_branch\n");
}

/* security: the PERSISTENT destination gets the SAME owner/mode scrutiny as
 * the volatile staging dir — group or other bits refuse with EPERM before
 * any fd is opened, and nothing is created inside. */
static void
test_cred_write_rejects_group_or_other_bits(void)
{
    brix_cred_write_req_t req;
    char                  dir[64], path[512];

    persist_dir(dir, sizeof(dir));
    assert(chmod(dir, 0770) == 0);          /* group bit set — unsafe */

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "subject.pem";

    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EPERM);

    assert(chmod(dir, 0700) == 0);
    assert(dir_entry_count(dir) == 0);
    rm_tree(dir);
    printf("ok cred_write_rejects_group_or_other_bits\n");
}

/* security: TMPDIR has NO influence on either arm — the volatile product
 * lands under /dev/shm/brix-creds.<euid> regardless, and when the staging
 * dir is unsafe the engine fails closed instead of falling back (the
 * pre-C11 krb5 ccache honored TMPDIR||/tmp; this pins the inversion). */
static void
test_cred_write_no_tmpdir_fallback(void)
{
    brix_cred_write_req_t req;
    char                  trap[64], sdir[64], path[512];

    persist_dir(trap, sizeof(trap));        /* a valid, writable decoy */
    assert(setenv("TMPDIR", trap, 1) == 0);

    reset_dir();
    memset(&req, 0, sizeof(req));
    req.arm    = BRIX_CRED_ARM_VOLATILE;
    req.kind   = BRIX_CRED_KIND_CCACHE;
    req.prefix = "brix-krb5-fwd-";

    /* The krb5 ccache shape: len == 0 pre-creates an empty 0600 file. */
    assert(brix_cred_write_engine(&req, NULL, 0, path, sizeof(path)) == 0);
    assert(strncmp(path, "/dev/shm/brix-creds.", 20) == 0);
    assert(strncmp(path, trap, strlen(trap)) != 0);
    unlink(path);

    /* Staging dir unsafe → fail closed; the TMPDIR decoy must stay empty. */
    staging_dir(sdir, sizeof(sdir));
    assert(mkdir(sdir, 0700) == 0 || errno == EEXIST);
    assert(chmod(sdir, 0777) == 0);
    errno = 0;
    assert(brix_cred_write_engine(&req, NULL, 0, path, sizeof(path)) == -1);
    assert(errno == EPERM);
    assert(dir_entry_count(trap) == 0);

    assert(unsetenv("TMPDIR") == 0);
    reset_dir();
    rm_tree(trap);
    printf("ok cred_write_no_tmpdir_fallback\n");
}

/* error: out-of-range arm/kind and a NULL-bytes-with-length request are
 * request-shape defects — EINVAL, nothing touched. */
static void
test_cred_write_rejects_bad_shape(void)
{
    brix_cred_write_req_t req;
    char                  path[512];

    reset_dir();
    memset(&req, 0, sizeof(req));
    req.arm    = BRIX_CRED_ARM_VOLATILE;
    req.kind   = BRIX_CRED_KIND_BEARER;
    req.prefix = "ut_";

    req.arm = (brix_cred_arm_t) 99;
    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    req.arm  = BRIX_CRED_ARM_VOLATILE;
    req.kind = (brix_cred_kind_t) 99;
    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    req.kind = BRIX_CRED_KIND_BEARER;
    errno = 0;
    assert(brix_cred_write_engine(&req, NULL, 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(brix_cred_write_engine(NULL, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EINVAL);

    printf("ok cred_write_rejects_bad_shape\n");
}

/* durability (runtime): the PERSISTENT arm fsyncs the staged DATA file and then
 * the PARENT DIRECTORY, in that order — a rename is not durable until its parent
 * is. The VOLATILE arm fsyncs NEITHER (the §3.3 tmpfs carve-out: durability for
 * a secret that must not survive reboot is an anti-goal). test_cred_write_parity
 * pins these at source level; this pins them at RUNTIME through the shipped code
 * via the fsync interposer, the runtime substitute for the infeasible crash
 * test. */
static void
test_cred_write_persistent_fsyncs_data_and_parent(void)
{
    brix_cred_write_req_t req;
    const char            pem[] = "-----BEGIN UT-----\ndurable\n-----END UT-----\n";
    char                  dir[64], path[512], vpath[512];

    /* PERSISTENT: data fsync, then parent-dir fsync after it. */
    persist_dir(dir, sizeof(dir));
    g_fsync_data_seen = g_fsync_dir_after_data = g_fsync_any = 0;

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "subject.pem";

    assert(brix_cred_write_engine(&req, pem, sizeof(pem) - 1,
                                  path, sizeof(path)) == 0);
    assert(g_fsync_data_seen);              /* the staged data file was fsynced */
    assert(g_fsync_dir_after_data);         /* the parent dir was fsynced AFTER */
    rm_tree(dir);

    /* VOLATILE: same interposer, cleared — proves NO fsync of any kind. */
    reset_dir();
    g_fsync_data_seen = g_fsync_dir_after_data = g_fsync_any = 0;

    memset(&req, 0, sizeof(req));
    req.arm    = BRIX_CRED_ARM_VOLATILE;
    req.kind   = BRIX_CRED_KIND_BEARER;
    req.prefix = "ut_nofsync_";

    assert(brix_cred_write_engine(&req, pem, sizeof(pem) - 1,
                                  vpath, sizeof(vpath)) == 0);
    assert(!g_fsync_any);                   /* volatile arm fsyncs nothing */
    unlink(vpath);
    reset_dir();
    printf("ok cred_write_persistent_fsyncs_data_then_parent\n");
}

/* security (runtime): the distinct OWNER half of cred_dir_check — a destination
 * dir owned by ANOTHER uid is refused with EPERM even when its mode is a clean
 * 0700 (so the (mode & 0077) half passes and only the st_uid != geteuid() half
 * can fire). Fail-closed before any fd is opened. Privilege-conditional: needs
 * CAP_CHOWN to plant a foreign owner, so it skips cleanly when unprivileged. */
static void
test_cred_write_rejects_foreign_dir_owner(void)
{
    brix_cred_write_req_t req;
    char                  dir[64], path[512];
    uid_t                 foreign;

    if (geteuid() != 0) {
        printf("ok cred_write_rejects_foreign_dir_owner "
               "(skipped: need CAP_CHOWN)\n");
        return;
    }

    persist_dir(dir, sizeof(dir));          /* mkdtemp: 0700, owned by euid (0) */

    /* Plant a foreign owner. In a full-privilege lane 65534 (nobody) works; in
     * a range-mapped user namespace only a few low uids are valid, so try a
     * handful and skip only if NONE can be assigned (constrained privilege). */
    {
        static const uid_t candidates[] = { 65534u, 1u, 2u, 3u, 100000u };
        size_t             ci;

        foreign = (uid_t) -1;
        for (ci = 0; ci < sizeof(candidates) / sizeof(candidates[0]); ci++) {
            if (candidates[ci] != geteuid()
                && chown(dir, candidates[ci], (gid_t) -1) == 0)
            {
                foreign = candidates[ci];
                break;
            }
        }
    }
    if (foreign == (uid_t) -1) {
        rm_tree(dir);
        printf("ok cred_write_rejects_foreign_dir_owner "
               "(skipped: chown failed)\n");
        return;
    }
    /* mode is still 0700 — the (mode & 0077) half PASSES; only owner fires. */

    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "subject.pem";

    errno = 0;
    assert(brix_cred_write_engine(&req, "x", 1, path, sizeof(path)) == -1);
    assert(errno == EPERM);
    assert(dir_entry_count(dir) == 0);      /* fail closed, before any fd */

    /* restore so rm_tree can clean.  The same privilege planted the foreign
     * owner a moment ago, so this must succeed; a `(void)` cast does NOT
     * silence chown's warn_unused_result, so consume the result for real. */
    assert(chown(dir, geteuid(), (gid_t) -1) == 0);
    rm_tree(dir);
    printf("ok cred_write_rejects_foreign_dir_owner\n");
}

/* error (runtime): a failing close() on the credential fd is REPORTED as an
 * error and the staged file is reaped — never a half-written secret left on
 * disk. This is the property cred_stage.c has and cred_mint.c:203 / delegation.c
 * did not (D.2); test_cred_write_parity source-pins the `if (close(fd) != 0)`
 * strings, this drives the branch at runtime through the shipped engine via the
 * close interposer, on BOTH arms. */
static void
test_cred_write_close_failure_is_reported(void)
{
    brix_cred_write_req_t req;
    char                  dir[64], sdir[64], path[512];

    /* PERSISTENT: the data-file close fails → -1/EIO, the temp is unlinked and
     * nothing is published (the rename never runs). */
    persist_dir(dir, sizeof(dir));
    memset(&req, 0, sizeof(req));
    req.arm  = BRIX_CRED_ARM_PERSISTENT;
    req.kind = BRIX_CRED_KIND_PROXY;
    req.dir  = dir;
    req.name = "subject.pem";

    g_fail_next_reg_close = 1;
    errno = 0;
    assert(brix_cred_write_engine(&req, "payload", 7, path, sizeof(path)) == -1);
    assert(errno == EIO);
    assert(g_fail_next_reg_close == 0);     /* the one-shot actually fired */
    assert(dir_entry_count(dir) == 0);      /* temp reaped, nothing published */
    rm_tree(dir);

    /* VOLATILE: the staged product IS the file, so a close failure must unlink
     * it — a co-tenant must never find a half-written secret under the tmpfs. */
    reset_dir();
    memset(&req, 0, sizeof(req));
    req.arm    = BRIX_CRED_ARM_VOLATILE;
    req.kind   = BRIX_CRED_KIND_BEARER;
    req.prefix = "ut_closefail_";

    g_fail_next_reg_close = 1;
    errno = 0;
    assert(brix_cred_write_engine(&req, "payload", 7, path, sizeof(path)) == -1);
    assert(errno == EIO);
    assert(g_fail_next_reg_close == 0);
    staging_dir(sdir, sizeof(sdir));
    assert(dir_entry_count(sdir) == 0);     /* volatile product unlinked */

    reset_dir();
    printf("ok cred_write_close_failure_is_reported\n");
}

int
main(void)
{
    test_write_success();
    test_dir_is_private();
    test_never_tmp();
    test_loose_mode_rejected();
    test_invalid_args();

    /* phase-108 C11: the shared engine, both arms */
    test_cred_write_volatile_matches_stage_write();
    test_cred_write_persistent_publishes_final();
    test_cred_write_short_write_is_an_error();
    test_cred_write_close_failure_is_reported();
    test_cred_write_reaps_on_every_branch();
    test_cred_write_rejects_group_or_other_bits();
    test_cred_write_rejects_foreign_dir_owner();
    test_cred_write_no_tmpdir_fallback();
    test_cred_write_rejects_bad_shape();
    test_cred_write_persistent_fsyncs_data_and_parent();

    reset_dir();
    printf("PASS test_cred_stage\n");
    return 0;
}
