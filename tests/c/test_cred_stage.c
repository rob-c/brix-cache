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

int
main(void)
{
    test_write_success();
    test_dir_is_private();
    test_never_tmp();
    test_loose_mode_rejected();
    test_invalid_args();
    reset_dir();
    printf("PASS test_cred_stage\n");
    return 0;
}
