/* Finite POD worker contract: real VFS, checksum, framing and storage code. */
#include "fs/vfs/vfs_io_core.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct dirent *__real_readdir64(DIR *directory);
int __real_fstatat64(int fd, const char *path, struct stat *st, int flags);

static int
fault_is(const char *name)
{
    const char *fault = getenv("BRIX_DIRLIST_FAULT");
    return fault != NULL && strcmp(fault, name) == 0;
}

struct dirent *
__wrap_readdir64(DIR *directory)
{
    if (fault_is("readdir")) {
        errno = EIO;
        return NULL;
    }
    return __real_readdir64(directory);
}

int
__wrap_fstatat64(int fd, const char *path, struct stat *st, int flags)
{
    if (fault_is("stat-vanished") || fault_is("stat-denied")) {
        errno = fault_is("stat-vanished") ? ENOENT : EACCES;
        return -1;
    }
    return __real_fstatat64(fd, path, st, flags);
}

static void
assert_canaries(const unsigned char *allocation, size_t capacity)
{
    size_t index;
    for (index = 0; index < 16; index++) {
        assert(allocation[index] == 0xa5);
        assert(allocation[16 + capacity + index] == 0xa5);
    }
}

int
main(int argc, char **argv)
{
    brix_vfs_job_t job;
    unsigned char *allocation;
    char error[32];
    char long_path[8192];
    size_t capacity;
    int fd;

    assert(argc == 4);
    capacity = (size_t) strtoul(argv[2], NULL, 10);
    assert(capacity <= 1048576);
    allocation = malloc(capacity + 32);
    assert(allocation != NULL);
    memset(allocation, 0xa5, capacity + 32);
    memset(&job, 0, sizeof(job));
    memset(error, 0, sizeof(error));
    memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    job.op = BRIX_VFS_IO_OPENDIR;
    job.rootfd = fd;
    job.buf = allocation + 16;
    job.buf_cap = capacity;
    job.path = fault_is("long-path") ? long_path : argv[1];
    job.want_stat = strcmp(argv[3], "names") != 0;
    job.want_cksum = strcmp(argv[3], "stat") != 0 && job.want_stat;
    job.cksum_algo = argv[3];
    job.streamid[0] = 0x17;
    job.streamid[1] = 0x39;
    job.err_msg = error;
    job.err_msg_cap = sizeof(error);
    if (fault_is("invalid-fd")) {
        job.rootfd = -1;
    }
    if (fault_is("null-buffer")) {
        job.buf = NULL;
    }
    if (fault_is("closed-fd")) {
        assert(close(fd) == 0);
    }
    brix_vfs_io_execute(&job);
    assert_canaries(allocation, capacity);
    assert(job.out_size <= capacity);
    assert(error[sizeof(error) - 1] == '\0');
    printf("%ld %d %zu\n", (long) job.nio, job.io_errno, job.out_size);
    assert(fwrite(job.buf, 1, job.out_size, stdout) == job.out_size);
    if (!fault_is("closed-fd")) {
        assert(fcntl(fd, F_GETFD) >= 0);
        assert(close(fd) == 0);
    }
    free(allocation);
    return 0;
}
