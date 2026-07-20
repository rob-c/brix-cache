/*
 * fd_kind_test.c — unit for brix_fd_kind (src/core/aio/fd_kind.c).
 *
 * The classifier backs the failed-read forensic log line for the fast-lane
 * ESPIPE/EBADF watch item; the labels here are load-bearing (a triager greps
 * for fd_kind=stale / fd_kind=socket). Pins:
 *   1. success — a regular file classifies as "regular";
 *   2. error — a closed (recycled-away) fd classifies as "stale";
 *   3. security-neg — non-file descriptors (socket, pipe) are named as such,
 *      never mistaken for a readable regular file.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char *brix_fd_kind(int fd);

static int failures;

static void
expect(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s: got \"%s\" want \"%s\"\n", what, got, want);
        failures++;
    }
}

int
main(void)
{
    char path[] = "/tmp/fd_kind_test.XXXXXX";
    int  file_fd = mkstemp(path);
    int  pair[2];
    int  pipes[2];

    if (file_fd < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0
        || pipe(pipes) != 0)
    {
        fprintf(stderr, "FAIL setup\n");
        return 1;
    }
    unlink(path);

    expect("regular file", brix_fd_kind(file_fd), "regular");
    expect("socket", brix_fd_kind(pair[0]), "socket");
    expect("pipe", brix_fd_kind(pipes[0]), "fifo");
    expect("directory", brix_fd_kind(open("/tmp", O_RDONLY)), "dir");

    close(file_fd);
    expect("closed fd", brix_fd_kind(file_fd), "stale");

    if (failures == 0) {
        printf("fd_kind: all checks passed\n");
    }
    return failures ? 1 : 0;
}
