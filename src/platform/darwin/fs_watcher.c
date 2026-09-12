/*
 * src/platform/darwin/fs_watcher.c - macOS filesystem monitoring
 * 
 * Phase 2: Uses kqueue EVFILT_VNODE for file monitoring.
 * Phase 4: Can be extended to use FSEvents for directory-wide monitoring.
 * 
 * kqueue EVFILT_VNODE advantages:
 * - Simple API, already using kqueue for events
 * - Per-file watching (like inotify)
 * - No additional frameworks needed
 * 
 * kqueue EVFILT_VNODE limitations:
 * - Must have file open to watch it
 * - Doesn't work well for directories
 * - No recursive watching
 * 
 * FSEvents (Phase 4) advantages:
 * - Directory-wide monitoring
 * - Recursive watching support
 * - Efficient for large directory trees
 */

#include "../platform.h"
#include "../platform_api.h"

#include <sys/event.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

/*
 * Watch descriptor for tracking individual file watches
 */
typedef struct brix_watch_desc {
    int fd;                      /* File descriptor (needed for kqueue watch) */
    int wd;                      /* Watch descriptor ID */
    uint32_t events;            /* Event mask being watched */
    char path[PATH_MAX];        /* Path being watched */
    struct brix_watch_desc *next;
} brix_watch_desc_t;

/*
 * Filesystem watcher context for macOS (kqueue-based)
 */
struct brix_plat_fs_watcher {
    int kqueue_fd;              /* kqueue file descriptor */
    brix_watch_desc_t *watches; /* Linked list of watch descriptors */
    uint32_t watch_count;       /* Number of active watches */
};

/* ==========================================================================
 * FILESYSTEM MONITORING - macOS implementations (kqueue EVFILT_VNODE)
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
    
    /* Create kqueue with CLOEXEC */
    watcher->kqueue_fd = kqueue();
    if (watcher->kqueue_fd < 0) {
        return -1;
    }
    
    /* Set CLOEXEC */
    flags = fcntl(watcher->kqueue_fd, F_GETFD);
    if (flags != -1) {
        fcntl(watcher->kqueue_fd, F_SETFD, flags | FD_CLOEXEC);
    }
    
    watcher->watches = NULL;
    watcher->watch_count = 0;
    
    return 0;
}

void
brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher)
{
    brix_watch_desc_t *w, *next;
    
    if (watcher != NULL) {
        /* Close all watched files and free watch descriptors */
        w = watcher->watches;
        while (w != NULL) {
            next = w->next;
            if (w->fd >= 0) {
                close(w->fd);
            }
            free(w);
            w = next;
        }
        
        if (watcher->kqueue_fd >= 0) {
            close(watcher->kqueue_fd);
        }
        
        /* Note: Caller allocated watcher, so we don't free it here */
    }
}

/*
 * Helper: Create a new watch descriptor
 */
static brix_watch_desc_t *
brix_watch_desc_create(brix_plat_fs_watcher_t *watcher, int fd, const char *path, uint32_t events)
{
    brix_watch_desc_t *wd;
    
    wd = calloc(1, sizeof(brix_watch_desc_t));
    if (wd == NULL) {
        return NULL;
    }
    
    wd->fd = fd;
    wd->wd = watcher->watch_count + 1;  /* Assign unique ID */
    wd->events = events;
    strncpy(wd->path, path, sizeof(wd->path) - 1);
    wd->path[sizeof(wd->path) - 1] = '\0';
    wd->next = NULL;
    
    return wd;
}

/*
 * Helper: Add watch descriptor to list
 */
static void
brix_watch_desc_add(brix_plat_fs_watcher_t *watcher, brix_watch_desc_t *wd)
{
    wd->next = watcher->watches;
    watcher->watches = wd;
    watcher->watch_count++;
}

/*
 * Helper: Remove and free watch descriptor
 */
static void
brix_watch_desc_remove(brix_plat_fs_watcher_t *watcher, brix_watch_desc_t *wd, brix_watch_desc_t *prev)
{
    if (prev == NULL) {
        watcher->watches = wd->next;
    } else {
        prev->next = wd->next;
    }
    
    if (wd->fd >= 0) {
        /* Remove from kqueue before closing */
        struct kevent ev;
        EV_SET(&ev, (uintptr_t)wd->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
        kevent(watcher->kqueue_fd, &ev, 1, NULL, 0, NULL);
        
        close(wd->fd);
    }
    
    free(wd);
    watcher->watch_count--;
}

int
brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher, const char *path, uint32_t events)
{
    brix_watch_desc_t *wd;
    struct kevent ev;
    int fd;
    int filter_flags;
    uint32_t vnode_flags = 0;
    
    if (watcher == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* kqueue EVFILT_VNODE requires the file to be open */
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;  /* errno set by open() */
    }
    
    /* Check if it's a directory - kqueue vnode filters work differently for dirs */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    if (S_ISDIR(st.st_mode) && !recursive) {
        /* kqueue EVFILT_VNODE doesn't work well for directories.
         * For Phase 2, we'll skip directory watches.
         * Phase 4 can use FSEvents for directory monitoring.
         */
        close(fd);
        errno = EISDIR;
        return -1;
    }
    
    /* Translate event mask to kqueue vnode flags */
    filter_flags = EV_ADD | EV_ENABLE | EV_CLEAR;
    
    /* Note: We watch for all common events and filter in brix_plat_fs_watcher_next() */
    vnode_flags = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND |
#if defined(NOTE_TRUNCATE)
                  NOTE_TRUNCATE |
#endif
                  NOTE_ATTRIB | NOTE_RENAME;
    
    /* Register with kqueue */
    EV_SET(&ev, (uintptr_t)fd, EVFILT_VNODE, filter_flags, vnode_flags, 0, NULL);
    
    if (kevent(watcher->kqueue_fd, &ev, 1, NULL, 0, NULL) < 0) {
        close(fd);
        return -1;  /* errno set by kevent() */
    }
    
    /* Create and add watch descriptor */
    wd = brix_watch_desc_create(watcher, fd, path, 0);
    if (wd == NULL) {
        /* Remove from kqueue */
        EV_SET(&ev, (uintptr_t)fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
        kevent(watcher->kqueue_fd, &ev, 1, NULL, 0, NULL);
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    
    brix_watch_desc_add(watcher, wd);
    return wd->wd;  /* Return watch descriptor ID */
}

int
brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd)
{
    brix_watch_desc_t *current, *prev;
    
    if (watcher == NULL || wd < 0) {
        errno = EINVAL;
        return -1;
    }
    
    /* Find the watch descriptor by ID */
    prev = NULL;
    current = watcher->watches;
    
    while (current != NULL) {
        if (current->wd == wd) {
            brix_watch_desc_remove(watcher, current, prev);
            return 0;
        }
        prev = current;
        current = current->next;
    }
    
    /* Watch descriptor not found */
    errno = ENOENT;
    return -1;
}

int
brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher, brix_plat_fs_event_t *event, int timeout_ms)
{
    struct kevent ev;
    struct timespec ts;
    struct timespec *tsp;
    brix_watch_desc_t *wd;
    int nready;
    
    if (watcher == NULL || event == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Set up timeout */
    if (timeout_ms < 0) {
        tsp = NULL;  /* Infinite */
    } else {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        tsp = &ts;
    }
    
    /* Wait for kqueue events */
    nready = kevent(watcher->kqueue_fd, NULL, 0, &ev, 1, tsp);
    
    if (nready < 0) {
        if (errno == EINTR) {
            return 0;  /* Interrupted by signal */
        }
        return -1;  /* Real error */
    }
    
    if (nready == 0) {
        return 0;  /* Timeout */
    }
    
    /* Check that it's a vnode event */
    if (ev.filter != EVFILT_VNODE) {
        errno = EINVAL;
        return -1;
    }
    
    /* Find the watch descriptor for this fd */
    wd = watcher->watches;
    while (wd != NULL) {
        if ((uintptr_t)wd->fd == (uintptr_t)ev.ident) {
            break;
        }
        wd = wd->next;
    }
    
    if (wd == NULL) {
        /* Orphaned event - shouldn't happen */
        errno = ENOENT;
        return -1;
    }
    
    /* Copy path from watch descriptor */
    strncpy(event->path, wd->path, sizeof(event->path) - 1);
    event->path[sizeof(event->path) - 1] = '\0';
    
    /* Translate kqueue vnode flags to platform-independent mask */
    event->events = 0;
    if (ev.fflags & NOTE_DELETE) {
        event->events |= BRIX_FS_EVENT_DELETE;
    }
    if (ev.fflags & NOTE_WRITE) {
        event->events |= BRIX_FS_EVENT_WRITE;
    }
    if (ev.fflags & NOTE_EXTEND) {
        event->events |= BRIX_FS_EVENT_CREATE;  /* File extended/created */
    }
    if (ev.fflags & NOTE_ATTRIB) {
        event->events |= BRIX_FS_EVENT_ATTRIB;
    }
    if (ev.fflags & NOTE_RENAME) {
        event->events |= BRIX_FS_EVENT_RENAME;
    }
    
    event->cookie = 0;  /* kqueue doesn't provide cookies like inotify */
    event->timestamp = 0;  /* TODO: Get timestamp if needed */
    
    return 1;  /* Event returned */
}

/* ==========================================================================
 * API COMPATIBILITY WRAPPERS
 * These wrappers ensure macOS implementation matches the PAL API
 * ========================================================================== */

/*
 * Compatibility wrapper: API expects init(), macOS has create()
 * This wrapper allows code to use the standard init() interface
 */

/* Note: brix_plat_fs_watcher_init() and brix_plat_fs_watcher_rm() are implemented
 * directly above - no wrapper needed */
