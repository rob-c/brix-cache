/*
 * src/platform/linux/event_wrapper.c - Linux epoll event monitoring
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX

#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>

/* ==========================================================================
 * EVENT MONITORING - Linux implementations (epoll)
 * ========================================================================== */

int
brix_plat_event_init(void)
{
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    
    if (epfd < 0) {
        return -1;  /* errno set by epoll_create1() */
    }
    
    return epfd;
}

void
brix_plat_event_close(int event_fd)
{
    if (event_fd >= 0) {
        close(event_fd);
    }
}

int
brix_platform_event_watch(int event_fd, int fd, uint32_t events)
{
    struct epoll_event ev;
    int op = EPOLL_CTL_ADD;
    
    /* Translate event mask to epoll events */
    ev.events = 0;
    if (events & BRIX_EVENT_READ) {
        ev.events |= EPOLLIN;
    }
    if (events & BRIX_EVENT_WRITE) {
        ev.events |= EPOLLOUT;
    }
    if (events & BRIX_EVENT_ERROR) {
        ev.events |= EPOLLERR;
    }
    
    /* Filesystem events not supported by epoll - use inotify instead */
    if (events & (BRIX_EVENT_DELETE | BRIX_EVENT_MODIFY | BRIX_EVENT_CREATE)) {
        errno = EINVAL;
        return -1;
    }
    
    ev.data.fd = fd;
    
    if (epoll_ctl(event_fd, op, fd, &ev) < 0) {
        return -1;  /* errno set by epoll_ctl() */
    }
    
    return 0;
}

int
brix_plat_event_wait(int event_fd, void *events, int max_events, int timeout_ms)
{
    struct epoll_event *ev = (struct epoll_event *)events;
    int timeout;
    
    if (timeout_ms < 0) {
        timeout = -1;  /* Infinite */
    } else {
        timeout = timeout_ms;
    }
    
    int nready = epoll_wait(event_fd, ev, max_events, timeout);
    
    if (nready < 0) {
        if (errno == EINTR) {
            return 0;  /* Interrupted by signal - not an error */
        }
        return -1;  /* errno set by epoll_wait() */
    }
    
    return nready;
}

#endif /* BRIX_PLATFORM_LINUX */
