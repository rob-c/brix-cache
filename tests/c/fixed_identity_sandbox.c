/* Native fixed-identity helper primitives, independent of broker dispatch.
 * Requires: PAL host selection, ordinary libc and the host privilege wrapper.
 * No real account database or host policy is modified by this probe.
 */
#include "platform/platform_api.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>

/* WHAT: Report a failed native contract. WHY: Preserve the syscall errno.
 * HOW: Print the exact stage to stderr and exit this disposable probe. */
static void
require(int condition, const char *stage)
{
    if (!condition) {
        perror(stage);
        _exit(1);
    }
}

/* WHAT: Exercise real descriptor-only file access and refusal boundaries.
 * WHY: A sandbox flag alone does not prove usable or confined storage access.
 * HOW: Create/read one relative file, then try ambient paths, root and exec. */
static void
confined_child(int channel, int rootfd)
{
    int fd;
    char bytes[4];
    char *const arguments[] = {"true", NULL};

    require(brix_plat_broker_confine(channel, rootfd, -1) == 0, "confine");
    fd = openat(rootfd, "probe", O_CREAT | O_EXCL | O_RDWR, 0600);
    require(fd >= 0, "relative create");
    require(write(fd, "brix", 4) == 4, "relative write");
    require(pread(fd, bytes, 4, 0) == 4 && memcmp(bytes, "brix", 4) == 0,
            "relative read");
    int flags = fcntl(fd, F_GETFL);
    require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
            "bounded file status controls");
    require(flock(fd, LOCK_EX | LOCK_NB) == 0 && flock(fd, LOCK_UN) == 0,
            "inode transaction lock");
    close(fd);
    require(open("/etc/passwd", O_RDONLY) == -1, "ambient path escaped");
    require(openat(rootfd, "../outside", O_CREAT | O_WRONLY, 0600) == -1,
            "parent path escaped");
    require(setuid(0) == -1 && geteuid() != 0, "root regained");
    require(execv("/usr/bin/true", arguments) == -1, "ambient exec escaped");
    require(write(channel, "Y", 1) == 1, "confinement result");
    _exit(0);
}

/* WHAT: Execute the native probe or explicit unsupported-host controls.
 * WHY: Neither an unsupported primitive nor an unsafe root helper may pass.
 * HOW: Fork only an owned child, communicate over a private socket and inspect
 * its real exit/EOF; the caller supplies a fresh directory owned by its uid. */
int
main(int argc, char **argv)
{
    int process_fd = -1, pair[2], rootfd, status;
    pid_t child;
    char result;

    if (argc != 3) { return 2; }
    if (strcmp(argv[1], "unsupported") == 0) {
        require(brix_plat_broker_fork(&process_fd) == -1 && errno == ENOTSUP,
                "unsupported fork");
        require(brix_plat_broker_confine(-1, -1, -1) == -1 && errno == ENOTSUP,
                "unsupported confinement");
        return 0;
    }
    alarm(10);
    rootfd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(rootfd >= 0, "private root");
    require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0,
            "private channel");
    child = brix_plat_broker_fork(&process_fd);
    require(child >= 0, "owned fork");
    if (child == 0) {
        close(pair[0]);
        if (strcmp(argv[1], "lifetime") == 0) {
            require(write(pair[1], "Y", 1) == 1, "child ready");
            for (;;) { pause(); }
        }
        confined_child(pair[1], rootfd);
    }
    close(pair[1]);
    require(read(pair[0], &result, 1) == 1 && result == 'Y', "child result");
    if (strcmp(argv[1], "lifetime") == 0) {
        close(process_fd);
        require(read(pair[0], &result, 1) == 0, "owned child survived close");
    } else {
        require(waitpid(child, &status, 0) == child
                && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exit");
        close(process_fd);
    }
    close(rootfd);
    close(pair[0]);
    return 0;
}
