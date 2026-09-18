/*
 * client/lib/platform/darwin/epoll.c - epoll(7) over kqueue for the client loop
 *
 * WHAT: epoll_create1 / epoll_ctl / epoll_wait with the subset of semantics
 *       the client's readiness loop uses (level-triggered IN/OUT, per-fd
 *       user data, ERR/HUP reporting).
 * WHY:  The loop is written against epoll; keeping one loop and emulating the
 *       three calls is smaller and safer than a second loop implementation.
 * HOW:  One kqueue per epoll set; EPOLLIN -> EVFILT_READ, EPOLLOUT ->
 *       EVFILT_WRITE, udata carries the epoll_data pointer; EV_EOF/EV_ERROR
 *       map to EPOLLHUP/EPOLLERR.
 */

#include "platform/platform.h"

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int
epoll_create1(int flags)
{
    int kq = kqueue();
    if (kq < 0) {
        return -1;
    }
    if (flags & EPOLL_CLOEXEC) {
        (void) fcntl(kq, F_SETFD, FD_CLOEXEC);   /* kqueue fds are CLOEXEC anyway */
    }
    return kq;
}

/* Apply one filter change; a delete of an absent filter is not an error. */
static int
kq_change(int kq, int fd, int16_t filter, uint16_t flags, void *udata)
{
    struct kevent kev;
    EV_SET(&kev, (uintptr_t) fd, filter, flags, 0, 0, udata);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
        if ((flags & EV_DELETE) && errno == ENOENT) {
            return 0;
        }
        return -1;
    }
    return 0;
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev)
{
    uint32_t want;
    void    *udata;

    if (op == EPOLL_CTL_DEL) {
        (void) kq_change(epfd, fd, EVFILT_READ,  EV_DELETE, NULL);
        (void) kq_change(epfd, fd, EVFILT_WRITE, EV_DELETE, NULL);
        return 0;
    }
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD) {
        errno = EINVAL;
        return -1;
    }
    if (ev == NULL) {
        errno = EFAULT;
        return -1;
    }
    want  = ev->events;
    udata = ev->data.ptr;

    if (want & EPOLLIN) {
        if (kq_change(epfd, fd, EVFILT_READ, EV_ADD | EV_ENABLE, udata) != 0) {
            return -1;
        }
    } else if (op == EPOLL_CTL_MOD) {
        (void) kq_change(epfd, fd, EVFILT_READ, EV_DELETE, NULL);
    }
    if (want & EPOLLOUT) {
        if (kq_change(epfd, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, udata) != 0) {
            return -1;
        }
    } else if (op == EPOLL_CTL_MOD) {
        (void) kq_change(epfd, fd, EVFILT_WRITE, EV_DELETE, NULL);
    }
    return 0;
}

static uint32_t
kev_to_epoll(const struct kevent *kev)
{
    uint32_t e = 0;
    if (kev->flags & EV_ERROR) {
        return EPOLLERR;
    }
    if (kev->filter == EVFILT_READ) {
        e |= EPOLLIN;
        if (kev->flags & EV_EOF) {
            e |= EPOLLHUP;
        }
    } else if (kev->filter == EVFILT_WRITE) {
        e |= EPOLLOUT;
        if (kev->flags & EV_EOF) {
            e |= EPOLLHUP;
        }
    }
    return e;
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms)
{
    struct kevent    stackbuf[64];
    struct kevent   *kevs = stackbuf;
    struct timespec  ts, *tsp = NULL;
    int              n, i, out = 0;

    if (maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }
    /* kqueue may return two kevents (read + write) per fd; fetch up to twice
     * the caller's capacity so coalescing cannot starve an fd of its pair. */
    if (maxevents * 2 > (int) (sizeof(stackbuf) / sizeof(stackbuf[0]))) {
        kevs = (struct kevent *) calloc((size_t) maxevents * 2, sizeof(*kevs));
        if (kevs == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }
    if (timeout_ms >= 0) {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long) (timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }

    n = kevent(epfd, NULL, 0, kevs, maxevents * 2, tsp);
    if (n < 0) {
        if (kevs != stackbuf) {
            free(kevs);
        }
        return -1;
    }

    for (i = 0; i < n; i++) {
        uint32_t e = kev_to_epoll(&kevs[i]);
        int      j;
        for (j = 0; j < out; j++) {            /* coalesce by identity (udata) */
            if (events[j].data.ptr == kevs[i].udata) {
                events[j].events |= e;
                break;
            }
        }
        if (j == out && out < maxevents) {
            events[out].events   = e;
            events[out].data.ptr = kevs[i].udata;
            out++;
        }
    }
    if (kevs != stackbuf) {
        free(kevs);
    }
    return out;
}

#endif /* BRIX_PLATFORM_DARWIN */
