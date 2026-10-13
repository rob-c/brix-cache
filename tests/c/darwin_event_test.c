/* Native Darwin success, error and security-negative event PAL checks. */
#include "platform/platform_api.h"

#include <assert.h>
#include <errno.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(void)
{
    struct kevent ready[2];
    int           pair[2];
    int           kq;
    int           seen_read = 0;
    int           seen_write = 0;
    int           n;
    int           i;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    kq = brix_platform_event_init();
    assert(kq >= 0);
    assert(brix_platform_event_watch(kq, pair[0],
        BRIX_EVENT_READ | BRIX_EVENT_WRITE) == 0);
    assert(write(pair[1], "x", 1) == 1);
    n = brix_platform_event_wait(kq, ready, 2, 1000);
    assert(n == 2);
    for (i = 0; i < n; i++) {
        seen_read |= ready[i].filter == EVFILT_READ;
        seen_write |= ready[i].filter == EVFILT_WRITE;
    }
    assert(seen_read && seen_write);

    close(pair[0]);
    errno = 0;
    assert(brix_platform_event_watch(kq, pair[0], BRIX_EVENT_READ) == -1);
    assert(errno == EBADF || errno == ENOENT);

    errno = 0;
    assert(brix_platform_event_watch(kq, pair[1],
        BRIX_EVENT_READ | BRIX_EVENT_DELETE) == -1);
    assert(errno == EINVAL);

    close(pair[1]);
    brix_platform_event_close(kq);
    return 0;
}
