/* Native FreeBSD PAL contracts, with deterministic native-list race injection. */
#include "platform/platform_api.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static int list_mode;
static unsigned list_calls;
ssize_t __real_extattr_list_file(const char *, int, void *, size_t);

ssize_t
__wrap_extattr_list_file(const char *path, int space, void *data, size_t capacity)
{
    if (list_mode == 0) { return __real_extattr_list_file(path, space, data, capacity); }
    list_calls++;
    if (list_mode == 1) { return list_calls == 1 ? 0 : 8192; }
    if (list_mode == 2) { return data == NULL && list_calls == 1 ? 2 : 8192; }
    if (data != NULL) {
        assert(capacity == 2);
        ((unsigned char *) data)[0] = 0;
        ((unsigned char *) data)[1] = 'x';
    }
    return 2;
}

static void
check_list_race(int mode)
{
    char output[32];
    ssize_t result;

    list_mode = mode;
    result = brix_plat_listxattr("injected-native-list", output, sizeof(output));
    if (mode == 1) {
        assert(result == 0 && list_calls == 1);
    } else {
        assert(result == -1);
        assert(errno == (mode == 2 ? ERANGE : EIO));
    }
}

static int
fixture_file(const char *directory, char *path, size_t capacity)
{
    int length = snprintf(path, capacity, "%s/data", directory);
    assert(length > 0 && (size_t) length < capacity);
    int descriptor = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    assert(descriptor >= 0);
    assert(write(descriptor, "test", 4) == 4);
    return descriptor;
}

static void
check_xattrs(const char *directory)
{
    char path[1024], value[8], names[128];
    int descriptor = fixture_file(directory, path, sizeof(path));

    assert(brix_plat_setxattr(path, "user.brix", "a\0b", 3, 0) == 0);
    assert(brix_plat_fgetxattr(descriptor, "user.brix", value, sizeof(value)) == 3);
    assert(memcmp(value, "a\0b", 3) == 0);
    assert(brix_plat_getxattr(path, "user.brix", value, 2) == -1 && errno == ERANGE);
    assert(brix_plat_listxattr(path, names, sizeof(names)) == 10);
    assert(strcmp(names, "user.brix") == 0);
    assert(brix_plat_listxattr(path, names, 2) == -1 && errno == ERANGE);
    assert(brix_plat_setxattr(path, "security.brix", "x", 1, 0) == -1);
    assert(errno == EOPNOTSUPP);
    assert(brix_plat_setxattr(path, "user.brix", "x", 1, XATTR_CREATE) == -1);
    assert(errno == ENOTSUP);
    assert(brix_plat_getxattr(path, "user.brix", value, sizeof(value)) == 3);
    assert(memcmp(value, "a\0b", 3) == 0);
    assert(brix_plat_removexattr(path, "user.brix") == 0);
    assert(brix_plat_getxattr(path, "user.brix", value, sizeof(value)) == -1);
    assert(errno == ENODATA);
    close(descriptor);
    assert(unlink(path) == 0);
}

static void
check_descriptors(const char *directory)
{
    char path[1024], value[4];
    int descriptor = fixture_file(directory, path, sizeof(path));
    int write_only = open(path, O_WRONLY | O_CLOEXEC);
    int reader = brix_plat_fd_reopen_readonly(write_only);

    assert(reader >= 0 && (fcntl(reader, F_GETFL) & O_ACCMODE) == O_RDONLY);
    assert((fcntl(reader, F_GETFD) & FD_CLOEXEC) != 0);
    assert(pread(reader, value, sizeof(value), 0) == 4);
    assert(memcmp(value, "test", 4) == 0);
    assert(write(reader, "bad", 3) == -1 && errno == EBADF);
    close(reader);
    assert(unlink(path) == 0);
    reader = brix_plat_fd_reopen_readonly(descriptor);
    assert(reader >= 0 && pread(reader, value, sizeof(value), 0) == 4);
    close(reader);
    assert(brix_plat_fd_reopen_readonly(write_only) == -1 && errno == EACCES);
    assert(brix_plat_fd_reopen_readonly(-1) == -1 && errno == EBADF);
    close(write_only);
    close(descriptor);
}

static void
check_paths(const char *directory)
{
    char path[1024], link[1024];
    struct stat metadata;
    int descriptor = fixture_file(directory, path, sizeof(path));
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int confined = brix_plat_openat2(root, "data", O_RDONLY, 0, RESOLVE_BENEATH);

    assert(root >= 0 && confined >= 0);
    close(confined);
    assert(brix_plat_stat_resolve(root, "data", 0, RESOLVE_BENEATH, &metadata) == 0);
    assert(metadata.st_size == 4);
    assert(brix_plat_openat2(root, "../", O_RDONLY, 0, RESOLVE_BENEATH) == -1);
    assert(errno == EXDEV);
    assert(snprintf(link, sizeof(link), "%s/escape", directory) > 0);
    assert(symlink("/etc/passwd", link) == 0);
    assert(brix_plat_openat2(root, "escape", O_RDONLY, 0, RESOLVE_BENEATH) == -1);
    assert(errno == EXDEV);
    assert(brix_plat_openat2(root, "escape", O_RDONLY, 0, RESOLVE_NO_SYMLINKS) == -1);
    assert(errno == ELOOP);
    assert(unlink(link) == 0 && unlink(path) == 0);
    close(root);
    close(descriptor);
}

static void
check_no_new_privileges(void)
{
    int status;
    pid_t child = fork();

    assert(child >= 0);
    if (child == 0) {
        assert(brix_plat_prctl(PR_SET_NO_NEW_PRIVS, 1) == 0);
        assert(brix_plat_prctl(PR_GET_NO_NEW_PRIVS, 0) == 1);
        assert(brix_plat_prctl(PR_SET_NO_NEW_PRIVS, 0) == -1 && errno == ENOTSUP);
        assert(brix_plat_prctl(PR_GET_NO_NEW_PRIVS, 0) == 1);
        assert(brix_plat_prctl(PR_SET_KEEPCAPS, 1) == -1 && errno == ENOTSUP);
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
check_events_and_peer(void)
{
    int reader, writer, pair[2];
    uid_t uid;
    gid_t gid;
    pid_t pid;

    assert(brix_plat_wakefd_open(&reader, &writer, BRIX_EVENTFD_CLOEXEC | BRIX_EVENTFD_NONBLOCK) == 0);
    assert(brix_plat_wakefd_signal(writer) == 0);
    assert(brix_plat_wakefd_drain(reader) == 0);
    assert(brix_plat_wakefd_drain(reader) == 0);
    brix_plat_wakefd_close(reader, writer);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(brix_plat_peer_cred(pair[0], &uid, &gid, &pid) == 0);
    assert(uid == geteuid() && gid == getegid() && pid == getpid());
    assert(brix_plat_peer_cred(-1, &uid, &gid, &pid) == -1);
    close(pair[0]);
    close(pair[1]);
}

int
main(int argc, char **argv)
{
    if (argc != 3) { return 2; }
    if (strcmp(argv[1], "xattrs") == 0) { check_xattrs(argv[2]); }
    else if (strcmp(argv[1], "descriptors") == 0) { check_descriptors(argv[2]); }
    else if (strcmp(argv[1], "paths") == 0) { check_paths(argv[2]); }
    else if (strcmp(argv[1], "no-new-privileges") == 0) { check_no_new_privileges(); }
    else if (strcmp(argv[1], "events-peer") == 0) { check_events_and_peer(); }
    else if (strcmp(argv[1], "list-empty-growth") == 0) { check_list_race(1); }
    else if (strcmp(argv[1], "list-oversize") == 0) { check_list_race(2); }
    else if (strcmp(argv[1], "list-malformed") == 0) { check_list_race(3); }
    else { return 2; }
    return 0;
}
