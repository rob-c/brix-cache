/*
 * src/platform/linux/fs_watcher.c - Linux inotify filesystem monitoring
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_HAS_INOTIFY

#include <sys/inotify.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * Filesystem watcher context for Linux (inotify-based)
 */
struct brix_plat_fs_watcher {
    int inotify_fd;           /* inotify file descriptor */
    int event_fd;             /* for non-blocking reads */
    uint32_t watch_count;     /* number of active watches */
};

/* ==========================================================================
 * FILESYSTEM MONITORING - Linux implementations (inotify)
 * ========================================================================== */

int
brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher)
{
    int flags;
    
    if (watcher == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    memset(watcher, 0, sizeof(brix_plat_fs_watcher_t));
    
    /* Initialize inotify with non-blocking and CLOEXEC flags */
    watcher->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (watcher->inotify_fd < 0) {
        return -1;
    }
    
    /* Set FD_CLOEXEC explicitly (in case IN_CLOEXEC isn't supported) */
    flags = fcntl(watcher->inotify_fd, F_GETFD);
    if (flags != -1) {
        fcntl(watcher->inotify_fd, F_SETFD, flags | FD_CLOEXEC);
    }
    
    watcher->event_fd = watcher->inotify_fd;
    watcher->watch_count = 0;
    
    return 0;
}

void
brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher)
{
    if (watcher != NULL) {
        if (watcher->inotify_fd >= 0) {
            close(watcher->inotify_fd);
        }
        /* Note: Caller allocated watcher, so we don't free it here */
    }
}

int
brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher, const char *path, uint32_t events)
{
    uint32_t mask;
    int wd;
    
    if (watcher == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* inotify doesn't support recursive watches natively.
     * For recursive watches, caller must add each directory separately.
     *
     * DESIGN NOTE: Recursive directory watching requires:
     * 1. Directory tree walker (ftw/nftw or custom implementation)
     * 2. Watch descriptor tracking (wd → path mapping)
     * 3. Dynamic watch management (add/remove as dirs change)
     *
     * Current scope: Single-path watches only (Phase 2).
     * Future enhancement: Add brix_plat_fs_watcher_add_recursive() if needed.
     */
    
    /* Set up event mask - translate from platform-independent mask */
    mask = IN_MODIFY | IN_ATTRIB | IN_CREATE | IN_DELETE |
           IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO;
    
    wd = inotify_add_watch(watcher->inotify_fd, path, mask);
    if (wd < 0) {
        return -1;  /* errno set by inotify_add_watch() */
    }
    
    watcher->watch_count++;
    return wd;  /* Return watch descriptor */
}

int
brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd)
{
    int ret;
    
    if (watcher == NULL || wd < 0) {
        errno = EINVAL;
        return -1;
    }
    
    /* Remove the watch using inotify_rm_watch() */
    ret = inotify_rm_watch(watcher->inotify_fd, wd);
    if (ret < 0) {
        return -1;  /* errno set by inotify_rm_watch() */
    }
    
    if (watcher->watch_count > 0) {
        watcher->watch_count--;
    }
    
    return 0;
}

int
brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher, brix_plat_fs_event_t *event, int timeout_ms)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    struct inotify_event *iev;
    ssize_t n;
    int ret;
    
    if (watcher == NULL || event == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* For non-blocking mode, we'd use select/poll/epoll on the inotify fd.
     * For Phase 2, we just do a non-blocking read.
     */
    n = read(watcher->inotify_fd, buf, sizeof(buf));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  /* No events available */
        }
        if (errno == EINTR) {
            return 0;  /* Interrupted by signal */
        }
        return -1;  /* Real error */
    }
    
    if (n == 0) {
        return 0;  /* EOF (shouldn't happen) */
    }
    
    /* Parse the first event in the buffer */
    iev = (struct inotify_event *)buf;
    
    /* Copy path - inotify events include the name for directory watches */
    if (iev->len > 0) {
        /* Event includes filename (directory watch)
         *
         * DESIGN NOTE: Full path reconstruction requires wd → path mapping
         * table to prepend parent directory path. Current implementation
         * returns relative name only (sufficient for most use cases).
         *
         * Future enhancement: Add path reconstruction if absolute paths needed.
         */
        strncpy(event->path, iev->name, sizeof(event->path) - 1);
        event->path[sizeof(event->path) - 1] = '\0';
    } else {
        event->path[0] = '\0';
    }
    
    /* Translate event mask */
    event->events = 0;
    if (iev->mask & IN_MODIFY) {
        event->events |= BRIX_FS_EVENT_WRITE;
    }
    if (iev->mask & IN_ATTRIB) {
        event->events |= BRIX_FS_EVENT_ATTRIB;
    }
    if (iev->mask & IN_CREATE) {
        event->events |= BRIX_FS_EVENT_CREATE;
    }
    if (iev->mask & IN_DELETE) {
        event->events |= BRIX_FS_EVENT_DELETE;
    }
    if (iev->mask & IN_DELETE_SELF) {
        event->events |= BRIX_FS_EVENT_DELETE_SELF;
    }
    if (iev->mask & IN_MOVED_FROM) {
        event->events |= BRIX_FS_EVENT_RENAME;
    }
    if (iev->mask & IN_MOVED_TO) {
        event->events |= BRIX_FS_EVENT_MOVE_TO;
    }
    
    event->cookie = iev->cookie;
    /* Timestamp: inotify doesn't provide event timestamps.
     * Could use inotify_event_sync() or clock_gettime() for approximate time.
     * Current: 0 (not available in Phase 2 implementation)
     */
    event->timestamp = 0;
    
    return 1;  /* Event returned */
}

#else /* !BRIX_HAS_INOTIFY */

/* Stub implementation when inotify is not available */

int
brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher)
{
    (void)watcher;
    errno = ENOSYS;
    return -1;
}

void
brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher)
{
    (void)watcher;
}

int
brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher, const char *path, uint32_t events)
{
    (void)watcher;
    (void)path;
    (void)events;
    errno = ENOSYS;
    return -1;
}

int
brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd)
{
    (void)watcher;
    (void)wd;
    errno = ENOSYS;
    return -1;
}

int
brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher, brix_plat_fs_event_t *event, int timeout_ms)
{
    (void)watcher;
    (void)event;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

#endif /* BRIX_HAS_INOTIFY */
