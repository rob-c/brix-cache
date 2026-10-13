/*
 * src/platform/darwin/event_wrapper.c - macOS kqueue event monitoring
 */

#include "../platform.h"
#include "../platform_api.h"

#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

/* ==========================================================================
 * EVENT MONITORING - macOS implementations (kqueue)
 * ========================================================================== */

int
brix_platform_event_init(void)
{
    int kq = kqueue();
    
    if (kq < 0) {
        return -1;  /* errno set by kqueue() */
    }
    
    /* Set CLOEXEC to avoid fd leak on exec() */
    int flags = fcntl(kq, F_GETFD);
    if (flags != -1) {
        fcntl(kq, F_SETFD, flags | FD_CLOEXEC);
    }
    
    return kq;
}

void
brix_platform_event_close(int event_fd)
{
    if (event_fd >= 0) {
        close(event_fd);
    }
}

int
brix_platform_event_watch(int event_fd, int fd, uint32_t events)
{
    struct kevent changes[2];
    int            nchanges = 0;
    int            filter_flags = EV_ADD | EV_ENABLE | EV_CLEAR;
    uint32_t       vnode = events
        & (BRIX_EVENT_DELETE | BRIX_EVENT_MODIFY | BRIX_EVENT_CREATE
            | BRIX_EVENT_ATTRIB);
    
    /* Translate event mask to kqueue filter */
    if (vnode != 0 && (events & (BRIX_EVENT_READ | BRIX_EVENT_WRITE)) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (events & BRIX_EVENT_READ) {
        EV_SET(&changes[nchanges++], (uintptr_t) fd, EVFILT_READ,
            filter_flags, 0, 0, NULL);
    }
    if (events & BRIX_EVENT_WRITE) {
        EV_SET(&changes[nchanges++], (uintptr_t) fd, EVFILT_WRITE,
            filter_flags, 0, 0, NULL);
    }
    if (vnode != 0) {
        int vnode_flags = filter_flags;

        /* Filesystem events use EVFILT_VNODE */
        if (events & BRIX_EVENT_DELETE) {
            vnode_flags |= NOTE_DELETE;
        }
        if (events & BRIX_EVENT_MODIFY) {
            vnode_flags |= NOTE_WRITE;
        }
        if (events & BRIX_EVENT_CREATE) {
            vnode_flags |= NOTE_WRITE;
        }
        if (events & BRIX_EVENT_ATTRIB) {
            vnode_flags |= NOTE_ATTRIB;
        }
        EV_SET(&changes[nchanges++], (uintptr_t) fd, EVFILT_VNODE,
            vnode_flags, 0, 0, NULL);
    }
    if (nchanges == 0) {
        errno = EINVAL;
        return -1;
    }
    if (kevent(event_fd, changes, nchanges, NULL, 0, NULL) < 0) {
        return -1;  /* errno set by kevent() */
    }
    
    return 0;
}

int
brix_platform_event_wait(int event_fd, void *events, int max_events,
    int timeout_ms)
{
    struct kevent *kev = (struct kevent *)events;
    struct timespec ts;
    struct timespec *tsp;
    int nready;
    
    if (timeout_ms < 0) {
        tsp = NULL;  /* Infinite timeout */
    } else {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        tsp = &ts;
    }
    
    nready = kevent(event_fd, NULL, 0, kev, (intptr_t)max_events, tsp);
    
    if (nready < 0) {
        if (errno == EINTR) {
            return 0;  /* Interrupted by signal - not an error */
        }
        return -1;  /* errno set by kevent() */
    }
    
    return nready;
}
