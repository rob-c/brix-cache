/*
 * client/lib/platform/darwin/host.h - epoll(7) for the client loop, over kqueue
 *
 * WHAT: The subset of the epoll API the client's readiness loop uses, with
 *       the Linux ABI values; bodies in darwin/epoll.c.
 */
#ifndef BRIX_CLIENT_PLATFORM_DARWIN_HOST_H
#define BRIX_CLIENT_PLATFORM_DARWIN_HOST_H

#include <stdint.h>

#define EPOLLIN   0x001u
#define EPOLLOUT  0x004u
#define EPOLLERR  0x008u
#define EPOLLHUP  0x010u

#define EPOLL_CLOEXEC 02000000

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
    void     *ptr;
    int       fd;
    uint32_t  u32;
    uint64_t  u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout_ms);

#endif /* BRIX_CLIENT_PLATFORM_DARWIN_HOST_H */
