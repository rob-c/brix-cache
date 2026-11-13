/* Finite broker/client driver. Production identity mapping, DAC, confinement
 * and SCM_RIGHTS remain in use; the server exits via its documented stop flag
 * so resource cleanup and instrumented execution can be observed. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "auth/impersonate/impersonate.h"

/* WHAT: Supply an unused log sink for the standalone object executable.
 * WHY: Tests pass NULL logs. HOW: Consume incidental nginx link arguments. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    (void) level; (void) log; (void) error; (void) format;
}

/* WHAT: Run the real broker until its shared stop flag is set.
 * WHY: Normal shutdown must be testable without killing an active request.
 * HOW: Map the parent-owned flag, initialize identity policy, enter the loop. */
static int
run_server(char **argv)
{
    brix_idmap_conf_t config;
    volatile sig_atomic_t *stop = mmap(NULL, sizeof(*stop), PROT_READ,
        MAP_SHARED, atoi(argv[4]), 0);

    assert(stop != MAP_FAILED);
    memset(&config, 0, sizeof(config));
    config.min_uid = 1000;
    config.worker_uid = (uid_t) -1;
    assert(brix_idmap_init(&config, NULL) == NGX_OK);
    int result = brix_imp_broker_run(atoi(argv[2]), atoi(argv[3]), stop, NULL);
    assert(munmap((void *) stop, sizeof(*stop)) == 0);
    return result == 0 ? 0 : 1;
}

/* WHAT: Create and verify a file owned by the mapped account.
 * WHY: A successful open alone cannot prove impersonation or fd passing.
 * HOW: Write through SCM_RIGHTS, then check broker-reported uid and content size. */
static void
create_file(const char *path)
{
    struct stat info;
    struct passwd *account = getpwnam(getenv("BRIX_FINITE_ACCOUNT"));
    int fd = brix_imp_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);

    assert(account != NULL && fd >= 0);
    assert(write(fd, "hello", 5) == 5);
    assert(close(fd) == 0);
    assert(brix_imp_stat(path, &info, 0) == 0);
    assert(info.st_uid == account->pw_uid && info.st_size == 5);
}

/* WHAT: Exercise namespace changes and atomic refusal over the real transport.
 * WHY: Test mutations must retain mapped ownership and no-replace semantics.
 * HOW: Create, link, exchange, rename, remove, and verify the resulting names. */
static void
namespace_case(void)
{
    struct stat info;

    assert(brix_imp_mkdir("/dir", 0700) == 0);
    create_file("/dir/first");
    assert(brix_imp_link("/dir/first", "/dir/hard") == 0);
    assert(brix_imp_rename_noreplace("/dir/first", "/dir/hard") == -1);
    assert(errno == EEXIST);
    assert(brix_imp_rename_noreplace("/dir/first", "/dir/second") == 0);
    assert(brix_imp_rename_exchange("/dir/second", "/dir/hard") == 0);
    assert(brix_imp_rename("/dir/second", "/dir/final") == 0);
    assert(brix_imp_unlink("/dir/final", 0) == 0);
    assert(brix_imp_unlink("/dir/hard", 0) == 0);
    assert(brix_imp_rmdir("/dir") == 0);
    assert(brix_imp_stat("/dir", &info, 0) == -1 && errno == ENOENT);
}

/* WHAT: Verify metadata and symbolic-link round trips under the mapped user.
 * WHY: Permissions and symlinks must traverse the same broker confinement.
 * HOW: Truncate, chmod, set times/group, inspect, and read an actual link. */
static void
metadata_case(void)
{
    struct stat info;
    char target[64];
    struct timespec times[2] = {{123456780, 0}, {123456789, 0}};
    struct passwd *account = getpwnam(getenv("BRIX_FINITE_ACCOUNT"));

    assert(account != NULL);
    create_file("/file");
    assert(brix_imp_truncate("/file", 2) == 0);
    assert(brix_imp_chmod("/file", 0640) == 0);
    assert(brix_imp_chown_gid("/file", account->pw_gid) == 0);
    assert(brix_imp_setattr("/file", 1, times, 1, (uid_t)-1, account->pw_gid) == 0);
    assert(brix_imp_stat("/file", &info, 0) == 0);
    assert(info.st_size == 2 && (info.st_mode & 0777) == 0640);
    assert(info.st_mtime == times[1].tv_sec);
    assert(brix_imp_symlink("file", "/link") == 0);
    assert(brix_imp_readlink("/link", target, sizeof(target)) == 4);
    assert(memcmp(target, "file", 4) == 0);
    assert(brix_imp_stat("/link", &info, 1) == 0 && S_ISLNK(info.st_mode));
}

/* WHAT: Verify extended-attribute data and size/error contracts.
 * WHY: Payload framing must survive refusals without desynchronizing requests.
 * HOW: Set/probe/read/list/remove and reject a privileged namespace. */
static void
xattr_case(void)
{
    char value[128];

    create_file("/file");
    assert(brix_imp_setxattr("/file", "user.finite", "value", 5, 0) == 0);
    assert(brix_imp_getxattr("/file", "user.finite", NULL, 0) == 5);
    assert(brix_imp_getxattr("/file", "user.finite", value, 2) == -1);
    assert(errno == ERANGE);
    assert(brix_imp_getxattr("/file", "user.finite", value, sizeof(value)) == 5);
    assert(memcmp(value, "value", 5) == 0);
    assert(brix_imp_listxattr("/file", NULL, 0) > 0);
    assert(brix_imp_listxattr("/file", value, sizeof(value)) > 0);
    assert(strcmp(value, "user.finite") == 0);
    assert(brix_imp_setxattr("/file", "security.finite", "bad", 3, 0) == -1);
    assert(brix_imp_removexattr("/file", "user.finite") == 0);
    assert(brix_imp_getxattr("/file", "user.finite", value, sizeof(value)) == -1);
}

/* WHAT: Reject root/unmapped identities, DAC violations and export escapes.
 * WHY: A denial must not poison the next legitimate request's credentials.
 * HOW: Interleave refusals with a valid mapped creation and metadata request. */
static void
refusal_case(void)
{
    struct stat info;

    brix_imp_set_principal("root");
    assert(brix_imp_open("/root-owned", O_CREAT | O_RDWR, 0600) == -1);
    assert(errno == EACCES);
    brix_imp_set_principal("brix-no-such-finite-account");
    assert(brix_imp_stat("/", &info, 0) == -1 && errno == EACCES);
    brix_imp_set_principal(getenv("BRIX_FINITE_ACCOUNT"));
    assert(brix_imp_open("/private/no", O_CREAT | O_RDWR, 0600) == -1);
    assert(errno == EACCES);
    assert(brix_imp_open("/../outside", O_RDONLY, 0) == -1);
    assert(brix_imp_open("/escape", O_RDONLY, 0) == -1);
    create_file("/allowed");
    brix_imp_clear_principal();
    assert(brix_imp_stat("/allowed", &info, 0) == -1 && errno == EACCES);
    brix_imp_set_principal(getenv("BRIX_FINITE_ACCOUNT"));
    assert(brix_imp_stat("/allowed", &info, 0) == 0);
}

/* WHAT: Dispatch one finite server/client scenario.
 * WHY: Every run owns its process credentials and exits normally.
 * HOW: Select a server or connect the real client and execute one case. */
int
main(int argc, char **argv)
{
    assert(argc >= 3);
    if (strcmp(argv[1], "server") == 0) {
        assert(argc == 5);
        return run_server(argv);
    }
    assert(brix_imp_client_connect(argv[2], NULL) == NGX_OK);
    brix_imp_set_principal(getenv("BRIX_FINITE_ACCOUNT"));
    if (strcmp(argv[1], "namespace") == 0) { namespace_case(); }
    else if (strcmp(argv[1], "metadata") == 0) { metadata_case(); }
    else if (strcmp(argv[1], "xattr") == 0) { xattr_case(); }
    else { assert(strcmp(argv[1], "refusal") == 0); refusal_case(); }
    return 0;
}
