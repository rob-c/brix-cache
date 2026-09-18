/* Event notification and filesystem watching.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * EVENT & NOTIFICATION
 *
 * Event notification and file system monitoring.
 * ========================================================================== */

/* ==========================================================================
 * EVENT & NOTIFICATION
 *
 * Event notification and file system monitoring.
 * Note: Two event systems exist:
 *   1. Generic events (brix_platform_event_*): epoll/kqueue-based
 *   2. Eventfd (brix_plat_eventfd): eventfd emulation
 * ========================================================================== */

/* Event constants for brix_platform_event_watch() */
#define BRIX_EVENT_READ         0x001  /**< Readable event */
#define BRIX_EVENT_WRITE        0x002  /**< Writable event */
#define BRIX_EVENT_ERROR        0x004  /**< Error condition */
#define BRIX_EVENT_DELETE       0x008  /**< File deleted */
#define BRIX_EVENT_MODIFY       0x010  /**< File modified */
#define BRIX_EVENT_CREATE       0x020  /**< File created */
#define BRIX_EVENT_ATTRIB       0x040  /**< Metadata changed */

/**
 * Create an event notification fd
 *
 * Linux: eventfd(initial_value, flags)
 * macOS: pipe-based implementation
 * Windows: pipe-based emulation
 *
 * Windows Implementation:
 * - Uses anonymous pipe (CreatePipe)
 * - Initial value written as uint64_t if non-zero
 * - Flags applied via SetHandleInformation()
 * - Returns read end of pipe
 *
 * @param initial_value Initial counter value
 * @param flags Flags (BRIX_EVENTFD_*)
 * @return Event fd, or -1 on error
 */
int brix_plat_eventfd(unsigned int initial_value, int flags);

/** Eventfd flags */
#define BRIX_EVENTFD_CLOEXEC    02000  /**< Set FD_CLOEXEC */
#define BRIX_EVENTFD_NONBLOCK   04000  /**< Set O_NONBLOCK */

/**
 * Write to eventfd (Windows-specific helper)
 *
 * Linux: write(efd, &value, sizeof(value))
 * macOS: write to pipe
 * Windows: Protected write to emulated eventfd counter
 *
 * Windows Implementation:
 * - Acquires CRITICAL_SECTION lock
 * - Adds value to 64-bit counter
 * - Writes to pipe for signaling
 * - Checks for overflow (EINVAL)
 *
 * @param efd Event fd from brix_plat_eventfd()
 * @param value Value to add (typically 1)
 * @return 0 on success, -1 on error (errno: EBADF, EINVAL, EAGAIN)
 */
int brix_plat_eventfd_write(int efd, uint64_t value);

/**
 * Read from eventfd (Windows-specific helper)
 *
 * Linux: read(efd, &value, sizeof(value))
 * macOS: read from pipe
 * Windows: Protected read from emulated eventfd counter
 *
 * Windows Implementation:
 * - Reads all available data from pipe
 * - Accumulates counter value
 * - Resets counter to 0
 * - Returns total in *value
 *
 * @param efd Event fd from brix_plat_eventfd()
 * @param value Output: accumulated counter value
 * @return 0 on success, -1 on error (errno: EBADF, EINVAL, EAGAIN)
 */
int brix_plat_eventfd_read(int efd, uint64_t *value);

/**
 * Close eventfd (Windows-specific helper)
 *
 * Linux: close(efd)
 * macOS: close(pipe_fd)
 * Windows: Full cleanup of eventfd emulation structure
 *
 * Windows Implementation:
 * - Unregisters from fd table
 * - Closes both pipe ends
 * - Deletes CRITICAL_SECTION
 * - Frees brix_win_eventfd_t structure
 *
 * @param efd Event fd from brix_plat_eventfd()
 * @return 0 on success, -1 on error (errno: EBADF)
 */
int brix_plat_eventfd_close(int efd);

/* ==========================================================================
 * GENERIC EVENT MONITORING (Linux/macOS epoll/kqueue)
 *
 * Cross-platform event monitoring using epoll (Linux) or kqueue (macOS).
 * Windows uses IOCP or select-based emulation (Windows-specific functions below).
 * ========================================================================== */

/**
 * Initialize event monitoring subsystem
 *
 * Linux: epoll_create1(EPOLL_CLOEXEC)
 * macOS: kqueue()
 * Windows: Returns 0 (no-op, uses IOCP internally)
 *
 * @return Event fd (Linux/macOS) or 0 (Windows), or -1 on error
 */
int brix_platform_event_init(void);

/**
 * Close event monitoring fd
 *
 * @param event_fd Event fd from brix_platform_event_init()
 */
void brix_platform_event_close(int event_fd);

/**
 * Add fd to event monitoring
 *
 * Linux: epoll_ctl(EPOLL_CTL_ADD)
 * macOS: kevent(EV_ADD)
 * Windows: Returns -EINVAL (use brix_plat_socket_event_create instead)
 *
 * @param event_fd Event fd from brix_platform_event_init()
 * @param fd File descriptor to monitor
 * @param events Event mask (BRIX_EVENT_*)
 * @return 0 on success, -1 on error
 */
int brix_platform_event_watch(int event_fd, int fd, uint32_t events);

/**
 * Wait for events (blocking)
 *
 * Linux: epoll_wait()
 * macOS: kevent()
 * Windows: Returns 0 (no-op, use brix_plat_event_wait instead)
 *
 * @param event_fd Event fd from brix_platform_event_init()
 * @param events Output event array (struct epoll_event or struct kevent[])
 * @param max_events Maximum events to return
 * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 * @return Number of events ready, 0 on timeout, -1 on error
 */
int brix_platform_event_wait(int event_fd, void *events, int max_events, int timeout_ms);

/* ==========================================================================
 * WINDOWS-SPECIFIC EVENT FUNCTIONS (IOCP-based)
 *
 * Windows uses IOCP (I/O Completion Port) for scalable event handling.
 * These functions are only available on Windows (BRIX_PLATFORM_WINDOWS).
 * ========================================================================== */


/**
 * Create a pipe with flags
 *
 * Linux: pipe2(flags)
 * macOS: pipe() + fcntl() for flags
 * Windows: CreatePipe() + SetHandleInformation()
 *
 * Windows Implementation:
 * - Uses CreatePipe() for anonymous pipe
 * - CLOEXEC via bInheritHandle=FALSE
 * - NONBLOCK via SetNamedPipeHandleState()
 * - Converts HANDLEs to fds via _open_osfhandle()
 *
 * @param pipefd Pipe file descriptors [2]
 * @param flags Flags (BRIX_PIPE_*)
 * @return 0 on success, -1 on error
 */
int brix_plat_pipe2(int pipefd[2], int flags);

/** Pipe flags */
#define BRIX_PIPE_CLOEXEC       02000  /**< Set FD_CLOEXEC on both ends */
#define BRIX_PIPE_NONBLOCK      04000  /**< Set O_NONBLOCK on both ends */

/**
 * File system watcher context (opaque)
 *
 * Linux: inotify-based
 * macOS: kqueue EVFILT_VNODE-based
 * Windows: ReadDirectoryChangesW-based
 *
 * Windows Implementation:
 * - Linked list of watch descriptors
 * - Each watch: directory HANDLE + overlapped I/O
 * - Events via WaitForMultipleObjects()
 * - Buffer-based event queuing (4KB default)
 */
typedef struct brix_plat_fs_watcher brix_plat_fs_watcher_t;

/**
 * File system event structure
 */
typedef struct {
    uint32_t cookie;      /**< Event cookie for related events (e.g., rename) */
    uint64_t timestamp;   /**< Event timestamp (platform-specific epoch) */
    char path[4096];      /**< Path where event occurred */
    uint32_t events;      /**< Event mask (BRIX_FS_EVENT_*) */
} brix_plat_fs_event_t;

/** File system event types */
#define BRIX_FS_EVENT_DELETE    0x001  /**< File/directory deleted */
#define BRIX_FS_EVENT_WRITE     0x002  /**< File modified */
#define BRIX_FS_EVENT_CREATE    0x004  /**< File/directory created */
#define BRIX_FS_EVENT_RENAME    0x008  /**< File/directory renamed */
#define BRIX_FS_EVENT_ATTRIB    0x010  /**< Metadata changed */

/**
 * Initialize a file system watcher
 *
 * @param watcher Watcher context (allocated by caller)
 * @return 0 on success, -1 on error
 */
int brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher);

/**
 * Add a path to watch
 *
 * @param watcher Watcher context
 * @param path Path to watch
 * @param events Events to monitor (BRIX_FS_EVENT_*)
 * @return Watch descriptor (>=0), or -1 on error
 */
int brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher,
                             const char *path, uint32_t events);

/**
 * Remove a watch
 *
 * @param watcher Watcher context
 * @param wd Watch descriptor (from brix_plat_fs_watcher_add)
 * @return 0 on success, -1 on error
 */
int brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd);

/**
 * Get next file system event (blocking)
 *
 * @param watcher Watcher context
 * @param event Event output buffer (allocated by caller)
 * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 * @return 0 on event, -1 on error/timeout
 */
int brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher,
                              brix_plat_fs_event_t *event, int timeout_ms);

/**
 * Destroy a file system watcher
 *
 * @param watcher Watcher context
 */
void brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher);
