/*
 * src/platform/platform_api.h - Platform Abstraction Layer Public API
 *
 * This header defines the complete PAL API. Source code should ONLY include
 * this header - NEVER platform-specific headers or preprocessor blocks.
 *
 * All platform detection and implementation logic lives in platform-specific subdirectories.
 *
 * Supported Platforms:
 *   - Linux (x86_64, arm64)
 *   - macOS/Darwin (x86_64, arm64/Apple Silicon)
 *   - Windows (x86_64, arm64) [planned]
 *
 * Usage Example:
 *   #include "platform/platform_api.h"
 *
 *   int fd = brix_plat_anon_fd("temp-file", NULL);
 *   ssize_t n = brix_plat_getxattr(path, "user.key", buf, sizeof(buf));
 *   uint64_t be_val = brix_plat_htobe64(host_val);
 */

#ifndef BRIX_PLATFORM_API_H
#define BRIX_PLATFORM_API_H

#include "platform.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

/* Platform-specific headers for byte-order operations */
#if BRIX_PLATFORM_LINUX
#include <endian.h>
#elif BRIX_PLATFORM_DARWIN
#include <libkern/OSByteOrder.h>
#elif BRIX_PLATFORM_WINDOWS
/* Windows byte order handled via intrinsics in inline functions below */
#include <windows.h>
#include <stdlib.h>
#endif

/* ==========================================================================
 * PLATFORM DETECTION & INFORMATION
 *
 * Query platform properties at runtime. All functions are thread-safe.
 * ========================================================================== */

/**
 * Get platform name
 * @return "linux", "darwin", or "windows"
 *
 * Windows: Returns "windows" for all Windows versions
 */
const char *brix_plat_name(void);

/**
 * Get platform version (kernel/OS version)
 * @return Version string (e.g., "5.15.0", "21.6.0", "10.0.20348")
 *
 * Windows: Returns NT version string (e.g., "10.0.20348" for Server 2022)
 * Retrieved via GetVersionEx() or RtlGetVersion()
 */
const char *brix_plat_version(void);

/**
 * Get CPU architecture name
 * @return "x86_64", "arm64", "aarch64", etc.
 *
 * Windows: Returns "x86_64" for AMD64, "arm64" for ARM64
 * Detected via GetNativeSystemInfo()
 */
const char *brix_plat_arch(void);

/**
 * Check if running as root/administrator
 * @return 1 if privileged, 0 otherwise
 *
 * Windows: Checks if process has Administrator privileges
 * Uses IsUserAnAdmin() or token-based check
 */
int brix_plat_is_root(void);

/**
 * Get number of online CPUs
 * @return CPU count, or -1 on error
 *
 * Windows: Uses GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
 * Supports processor groups on systems with >64 logical processors
 */
int brix_plat_cpu_count(void);

/**
 * Get total system memory in bytes
 * @return Memory size, or 0 on error
 *
 * Windows: Uses GlobalMemoryStatusEx()
 * Returns total physical RAM
 */
uint64_t brix_plat_total_memory(void);

/**
 * Get available memory in bytes
 * @return Available memory, or 0 on error
 *
 * Windows: Uses GlobalMemoryStatusEx()
 * Returns available physical RAM (not including page file)
 */
uint64_t brix_plat_available_memory(void);

/* ==========================================================================
 * FILE DESCRIPTOR OPERATIONS
 *
 * Cross-platform file descriptor management.
 * ========================================================================== */

/**
 * Create an anonymous file descriptor
 *
 * Linux: memfd_create(name, MFD_CLOEXEC)
 * macOS: mkstemp() with immediate unlink
 * Windows: CreateFile() with FILE_FLAG_DELETE_ON_CLOSE
 *
 * Windows Implementation:
 * - Creates temporary file in %TEMP% directory
 * - FILE_FLAG_DELETE_ON_CLOSE ensures automatic cleanup
 * - Returns _open_osfhandle() wrapped fd
 * - Name parameter used as filename prefix
 *
 * @param name Optional name hint (may be NULL)
 * @param dir Optional directory for tempfile (may be NULL, uses /tmp or %TEMP%)
 * @return File descriptor, or -1 on error (errno set)
 */
int brix_plat_anon_fd(const char *name, const char *dir);

/**
 * Provide file access hints (advisory)
 *
 * Linux: posix_fadvise()
 * macOS: no-op (returns 0)
 * Windows: no-op (returns 0)
 *
 * Windows Implementation:
 * - Stub implementation (returns 0)
 * - Windows lacks direct equivalent to posix_fadvise
 * - Could use SetFileValidData or FILE_ATTRIBUTE_TEMPORARY in future
 *
 * @param fd File descriptor
 * @param offset Start offset
 * @param len Length of region (0 = to EOF)
 * @param advice Hint type (BRIX_FADV_*)
 * @return 0 on success, -1 on error
 */
int brix_plat_fadvise(int fd, off_t offset, off_t len, int advice);

/** Advice constants for brix_plat_fadvise() */
#define BRIX_FADV_NORMAL      0  /**< No special treatment */
#define BRIX_FADV_RANDOM      1  /**< Expect random access */
#define BRIX_FADV_SEQUENTIAL  2  /**< Expect sequential access */
#define BRIX_FADV_WILLNEED    3  /**< Will access soon */
#define BRIX_FADV_DONTNEED    4  /**< Don't need access */
#define BRIX_FADV_NOREUSE     5  /**< Access once only */

/**
 * Flush file data to stable storage (metadata may be flushed too)
 *
 * Linux: fdatasync()
 * macOS: fcntl(F_FULLFSYNC) with fsync() fallback
 * Windows: FlushFileBuffers()
 *
 * Windows Implementation:
 * - Uses FlushFileBuffers() on HANDLE
 * - Flushes both data and metadata
 * - Converts fd to HANDLE via _get_osfhandle()
 *
 * @param fd File descriptor
 * @return 0 on success, -1 on error
 */
int brix_plat_fsync_data(int fd);

/**
 * Sync all filesystems (global barrier)
 *
 * Linux/macOS/Windows: sync() or equivalent
 *
 * Windows Implementation:
 * - Stub implementation (no-op)
 * - Windows lacks direct sync() equivalent
 * - Could iterate volumes and call FlushFileBuffers in future
 *
 * Note: This is a blocking operation that may take significant time.
 */
void brix_plat_sync(void);

/**
 * Sync a specific filesystem tree
 *
 * Linux: syncfs()
 * macOS: sync() (coarser but same guarantee)
 * Windows: FlushFileBuffers() on volume
 *
 * Windows Implementation:
 * - Uses FlushFileBuffers() on directory HANDLE
 * - Converts dirfd to HANDLE via _get_osfhandle()
 *
 * @param dirfd Directory file descriptor
 * @return 0 on success, -1 on error
 */
int brix_plat_sync_tree(int dirfd);

/* ==========================================================================
 * ZERO-COPY TRANSFERS
 *
 * High-performance data transfer between file descriptors.
 * ========================================================================== */

/**
 * Zero-copy file transfer to socket/file
 *
 * Linux: sendfile(out_fd, in_fd, offset, count)
 * macOS: sendfile(in_fd, out_fd, offset, &count, NULL, 0)
 * Windows: TransmitFile()
 *
 * Windows Implementation:
 * - Uses TransmitFile() from mswsock.dll
 * - Requires socket as output fd
 * - TF_USE_KERNEL_APC | TF_WRITE_BEHIND flags for performance
 * - Offset tracked via LARGE_INTEGER parameter
 *
 * @param out_fd Output fd (socket or file)
 * @param in_fd Input fd (file)
 * @param offset File offset (updated on success)
 * @param count Bytes to transfer
 * @return Bytes transferred, or -1 on error (errno set)
 */
ssize_t brix_plat_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

/**
 * Zero-copy pipe splice (Linux only)
 *
 * Linux: splice() syscall
 * macOS: Returns -ENOSYS (use buffered copy)
 * Windows: Returns -ENOSYS (not implemented)
 *
 * Windows Implementation:
 * - Stub returns -1 with errno=ENOSYS
 * - Windows lacks direct splice() equivalent
 * - Use buffered copy or TransmitFile() for sockets
 *
 * @param in_fd Input fd
 * @param out_fd Output fd (must be pipe on Linux)
 * @param nbytes Bytes to splice
 * @param flags Splice flags (BRIX_SPLICE_*)
 * @return Bytes spliced, or -1 on error
 */
ssize_t brix_plat_splice(int in_fd, int out_fd, size_t nbytes, unsigned int flags);

/** Splice flags for brix_plat_splice() */
#define BRIX_SPLICE_F_MOVE      1  /**< Move pages (not copy) */
#define BRIX_SPLICE_F_NONBLOCK  2  /**< Don't block */
#define BRIX_SPLICE_F_MORE      4  /**< More data coming */
#define BRIX_SPLICE_F_GIFT      8  /**< Pages are a gift */

/**
 * Copy a range of data between file descriptors
 *
 * Linux: copy_file_range()
 * macOS: clonefile() or copyfile() for full files
 * Windows: CopyFile2() or FSCTL_COPY_FILE
 *
 * Windows Implementation:
 * - Stub returns -1 with errno=ENOSYS
 * - Windows CopyFile2() works on paths, not fds
 * - FSCTL_COPY_FILE requires volume handles
 * - Future: Implement via temporary file mapping
 *
 * @param in_fd Input fd
 * @param in_off Input offset (updated on success, or NULL)
 * @param out_fd Output fd
 * @param out_off Output offset (updated on success, or NULL)
 * @param len Bytes to copy
 * @param flags Copy flags (BRIX_COPY_*)
 * @return Bytes copied, or -1 on error
 */
ssize_t brix_plat_copy_range(int in_fd, off_t *in_off,
                             int out_fd, off_t *out_off,
                             size_t len, unsigned int flags);

/** Copy range flags for brix_plat_copy_range() */
#define BRIX_COPY_F_MOVE        1  /**< Move data (not copy) */
#define BRIX_COPY_F_SPLICE      2  /**< Use splice semantics */
#define BRIX_COPY_F_REFLINK     4  /**< Use reflink if possible */
#define BRIX_COPY_F_SAME_MOUNT  8  /**< Require same mount point */

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

#if BRIX_PLATFORM_WINDOWS

/**
 * Initialize Windows event subsystem (IOCP)
 *
 * Phase 1: No-op (uses WaitForMultipleObjects)
 * Phase 2: Create IOCP for scalable event handling
 *
 * @return 0 on success, -1 on error
 */
int brix_plat_event_init(void);

/**
 * Wait for Windows event
 *
 * Phase 1: WaitForMultipleObjects (limited to 64 handles)
 * Phase 2: GetQueuedCompletionStatus (IOCP, scalable)
 *
 * @param efd Event fd/handle
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return 0 on event, -1 on timeout/error
 */
int brix_plat_event_wait(int efd, int timeout_ms);

/**
 * Create Windows socket event monitor
 *
 * Uses WSAEventSelect to associate socket with event object.
 * Maps PAL events to WSA network events:
 * - BRIX_EVENT_READ → FD_READ | FD_ACCEPT | FD_CLOSE
 * - BRIX_EVENT_WRITE → FD_WRITE | FD_CONNECT
 *
 * @param sock Socket to monitor (SOCKET type)
 * @param events Event mask (BRIX_EVENT_*)
 * @return Event handle, or -1 on error
 */
int brix_plat_socket_event_create(SOCKET sock, uint32_t events);

/**
 * Wait for Windows socket event
 *
 * @param event_handle Event handle from brix_plat_socket_event_create()
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return 0 on event, -1 on timeout/error
 */
int brix_plat_socket_event_wait(int event_handle, int timeout_ms);

/**
 * Destroy Windows socket event
 *
 * @param event_handle Event handle to destroy
 */
void brix_plat_socket_event_destroy(int event_handle);

#endif /* BRIX_PLATFORM_WINDOWS */

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

/* ==========================================================================
 * SECURITY & CONFINEMENT
 *
 * Security context and credential manipulation.
 * Note: Windows support is limited (stubbed) due to different security model.
 * ========================================================================== */

/**
 * Initialize security context
 *
 * Linux: seccomp_init() + profile loading
 * macOS: sandbox_init() (stub - relies on system security)
 * Windows: Job Objects (stub)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows security model differs fundamentally (ACLs, tokens, SIDs)
 * - Future: Implement via Job Objects or AppContainer
 * - Profile parameter ignored
 *
 * @param profile Security profile name (or NULL for default)
 * @return 0 on success, -1 on error
 */
int brix_plat_security_init(const char *profile);

/**
 * Enter security confinement
 *
 * Linux: seccomp_load()
 * macOS: sandbox_exec() (stub)
 * Windows: Job Object assignment (stub)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - No-op until Job Objects implementation
 * - Profile parameter ignored
 *
 * @param profile Security profile name
 * @return 0 on success, -1 on error
 */
int brix_plat_security_enter(const char *profile);

/**
 * Set filesystem user ID (Linux only, stubbed on macOS/Windows)
 *
 * Linux: setfsuid()
 * macOS: seteuid() (affects both real and effective)
 * Windows: stub (returns 0)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows uses impersonation, not UID switching
 * - Future: Implement via ImpersonateLoggedOnUser()
 *
 * @param uid User ID
 * @return 0 on success, -1 on error
 */
int brix_plat_setfsuid(uid_t uid);

/**
 * Set filesystem group ID (Linux only, stubbed on macOS/Windows)
 *
 * Linux: setfsgid()
 * macOS: setegid()
 * Windows: stub (returns 0)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows uses security groups, not GID switching
 * - Future: Implement via token manipulation
 *
 * @param gid Group ID
 * @return 0 on success, -1 on error
 */
int brix_plat_setfsgid(gid_t gid);

/* ==========================================================================
 * RANDOM NUMBER GENERATION
 *
 * Cryptographically secure random number generation.
 * ========================================================================== */

/**
 * Generate cryptographically secure random bytes
 *
 * Linux: getrandom() or /dev/urandom
 * macOS: SecRandomCopyBytes() or /dev/urandom
 * Windows: BCryptGenRandom()
 *
 * Windows Implementation:
 * - Uses BCryptGenRandom() from bcrypt.dll
 * - BCRYPT_USE_SYSTEM_PREFERRED_RNG flag
 * - Algorithm handle cached for performance
 * - Fallback to CryptGenRandom() if BCrypt unavailable
 *
 * @param buf Output buffer
 * @param len Number of bytes
 * @return 0 on success, -1 on error
 */
int brix_plat_random(void *buf, size_t len);

/* ==========================================================================
 * EXTENDED ATTRIBUTES
 *
 * Cross-platform xattr operations.
 * Note: Windows uses NTFS Alternate Data Streams (ADS).
 * ========================================================================== */

/**
 * Get extended attribute
 *
 * Linux: getxattr(path, name, value, size)
 * macOS: getxattr(path, name, value, size, 0, 0)
 * Windows: NTFS Alternate Data Streams (ADS)
 *
 * Windows Implementation:
 * - Maps xattr names to ADS streams ("user.key" → "file:key")
 * - Uses CreateFileW() with stream name syntax
 * - Reads stream content into value buffer
 * - Returns ENODATA if stream doesn't exist
 *
 * @param path File path
 * @param name Attribute name (e.g., "user.key")
 * @param value Output buffer
 * @param size Buffer size
 * @return Bytes read, or -1 on error
 */
ssize_t brix_plat_getxattr(const char *path, const char *name,
                           void *value, size_t size);

/**
 * Get extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_getxattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @param value Output buffer
 * @param size Buffer size
 * @return Bytes read, or -1 on error
 */
ssize_t brix_plat_fgetxattr(int fd, const char *name,
                            void *value, size_t size);

/**
 * Set extended attribute
 *
 * Windows Implementation:
 * - Maps xattr names to ADS streams
 * - Uses CreateFileW() with stream name syntax
 * - Writes value to stream
 * - Supports XATTR_CREATE (FAIL_IF_EXISTS)
 * - Supports XATTR_REPLACE (TRUNCATE_EXISTING)
 *
 * @param path File path
 * @param name Attribute name
 * @param value Attribute value
 * @param size Value size
 * @param flags Flags (0, BRIX_XATTR_CREATE, BRIX_XATTR_REPLACE)
 * @return 0 on success, -1 on error
 */
int brix_plat_setxattr(const char *path, const char *name,
                       const void *value, size_t size, int flags);

/**
 * Set extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_setxattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @param value Attribute value
 * @param size Value size
 * @param flags Flags
 * @return 0 on success, -1 on error
 */
int brix_plat_fsetxattr(int fd, const char *name,
                        const void *value, size_t size, int flags);

/**
 * Remove extended attribute
 *
 * Windows Implementation:
 * - Maps xattr name to ADS stream
 * - Uses DeleteFileW() with stream name syntax
 * - Returns ENODATA if stream doesn't exist
 *
 * @param path File path
 * @param name Attribute name
 * @return 0 on success, -1 on error
 */
int brix_plat_removexattr(const char *path, const char *name);

/**
 * Remove extended attribute (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandle() to get path
 * - Delegates to brix_plat_removexattr()
 *
 * @param fd File descriptor
 * @param name Attribute name
 * @return 0 on success, -1 on error
 */
int brix_plat_fremovexattr(int fd, const char *name);

/**
 * List extended attributes
 *
 * Windows Implementation:
 * - Uses FindFirstStreamW()/FindNextStreamW() to enumerate NTFS ADS streams
 * - Fully implemented for Windows 8+ / Server 2012+
 * - Returns null-separated attribute names
 * - NTFS filesystem required (FAT32/exFAT do not support ADS)
 *
 * Linux Implementation:
 * - Uses lgetxattr() with XATTR_NAME_ALL
 * - Fully implemented
 *
 * macOS Implementation:
 * - Uses getxattr() with XATTR_NOFOLLOW
 * - Fully implemented
 *
 * @param path File path
 * @param list Output buffer (null-separated names)
 * @param size Buffer size
 * @return Bytes written, or -1 on error
 */
ssize_t brix_plat_listxattr(const char *path, char *list, size_t size);

/**
 * List extended attributes (file descriptor version)
 *
 * Windows Implementation:
 * - Converts fd to HANDLE via _get_osfhandle()
 * - Uses GetFinalPathNameByHandleW() to get file path
 * - Delegates to brix_plat_listxattr()
 * - Fully implemented
 *
 * Linux Implementation:
 * - Uses flistxattr()
 * - Fully implemented
 *
 * macOS Implementation:
 * - Uses flistxattr()
 * - Fully implemented
 *
 * @param fd File descriptor
 * @param list Output buffer
 * @param size Buffer size
 * @return Bytes written, or -1 on error
 */
ssize_t brix_plat_flistxattr(int fd, char *list, size_t size);

/** Extended attribute flags */
#define BRIX_XATTR_CREATE       0x0002  /**< Fail if attr exists */
#define BRIX_XATTR_REPLACE      0x0004  /**< Fail if attr doesn't exist */
#define BRIX_XATTR_NOFOLLOW     0x0001  /**< Don't follow symlinks */

/**
 * BRIX_XATTR_NOFOLLOW Platform Support Matrix
 * 
 * This flag requests that symlink targets not be followed when setting/getting
 * extended attributes. Support varies by platform:
 * 
 * | Platform | Status | Notes |
 * |----------|--------|-------|
 * | Linux | ✅ Supported | Uses AT_SYMLINK_NOFOLLOW with *xattrat() |
 * | macOS | ✅ Supported | Native lgetxattr/lsetxattr APIs |
 * | Windows | ⚠️ NOT IMPLEMENTED | Returns EINVAL if flag set |
 * 
 * Windows Limitation:
 * - NTFS ADS operations always follow symlinks by default
 * - Would require FILE_FLAG_OPEN_REPARSE_POINT + CreateFileW()
 * - Complex implementation due to ADS path construction with reparse points
 * - Security implication: Attributes may be set on symlink target, not link
 * 
 * Workaround on Windows:
 * - Use GetFileAttributesW() to detect FILE_ATTRIBUTE_REPARSE_POINT
 * - Manually check for symlinks before calling setxattr/getxattr
 * - Or accept that attributes follow symlinks (matches most use cases)
 * 
 * Future Enhancement:
 * - Implement symlink detection in Windows xattr wrapper
 * - Return ENOTSUP or EINVAL when flag is set on symlink
 * - See: src/platform/windows/xattr.c for implementation notes
 */

/* ==========================================================================
 * PROCESS EXECUTION
 *
 * Process creation and management.
 * ========================================================================== */

/**
 * Execute a program with PATH search and environment
 *
 * Linux: execvpe()
 * macOS: posix_spawn() emulation
 * Windows: CreateProcessW() + SearchPathW()
 *
 * Windows Implementation:
 * - Uses SearchPathW() to locate executable in PATH
 * - Converts UTF-8 arguments to UTF-16 via MultiByteToWideChar()
 * - Builds command line with proper escaping (Microsoft rules)
 * - Creates process via CreateProcessW()
 * - Waits for child process, propagates exit code
 * - Calls _exit() with child's exit code
 * - Does not return on success (mimics execvpe behavior)
 *
 * Note: Does not return on success (replaces current process).
 *
 * @param file Program name (searched in PATH if not absolute)
 * @param argv Argument array (NULL-terminated)
 * @param envp Environment array (NULL-terminated, or NULL for current)
 * @return Does not return on success, -1 on error
 */
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[]);

/* ==========================================================================
 * BYTE ORDER OPERATIONS (inline for performance)
 *
 * Host <-> Big-Endian conversion for 16/32/64-bit integers.
 * These are inline functions for zero overhead.
 * ========================================================================== */

#if BRIX_PLATFORM_LINUX

/* Linux: use endian.h */
static inline uint64_t brix_plat_htobe64(uint64_t x) { return htobe64(x); }
static inline uint64_t brix_plat_be64toh(uint64_t x) { return be64toh(x); }
static inline uint32_t brix_plat_htobe32(uint32_t x) { return htobe32(x); }
static inline uint32_t brix_plat_be32toh(uint32_t x) { return be32toh(x); }
static inline uint16_t brix_plat_htobe16(uint16_t x) { return htobe16(x); }
static inline uint16_t brix_plat_be16toh(uint16_t x) { return be16toh(x); }

#elif BRIX_PLATFORM_DARWIN

/* macOS: use libkern/OSByteOrder.h */
static inline uint64_t brix_plat_htobe64(uint64_t x) { return OSSwapHostToBigInt64(x); }
static inline uint64_t brix_plat_be64toh(uint64_t x) { return OSSwapBigToHostInt64(x); }
static inline uint32_t brix_plat_htobe32(uint32_t x) { return OSSwapHostToBigInt32(x); }
static inline uint32_t brix_plat_be32toh(uint32_t x) { return OSSwapBigToHostInt32(x); }
static inline uint16_t brix_plat_htobe16(uint16_t x) { return OSSwapHostToBigInt16(x); }
static inline uint16_t brix_plat_be16toh(uint16_t x) { return OSSwapBigToHostInt16(x); }

#elif BRIX_PLATFORM_WINDOWS

/* Windows: use intrinsics or manual byte swap */
#include <stdlib.h>

static inline uint64_t brix_plat_htobe64(uint64_t x) { return _byteswap_uint64(x); }
static inline uint64_t brix_plat_be64toh(uint64_t x) { return _byteswap_uint64(x); }
static inline uint32_t brix_plat_htobe32(uint32_t x) { return _byteswap_ulong(x); }
static inline uint32_t brix_plat_be32toh(uint32_t x) { return _byteswap_ulong(x); }
static inline uint16_t brix_plat_htobe16(uint16_t x) { return _byteswap_ushort(x); }
static inline uint16_t brix_plat_be16toh(uint16_t x) { return _byteswap_ushort(x); }

#else

/* Portable fallback for unknown platforms */
static inline uint64_t brix_plat_htobe64(uint64_t x) {
    return ((uint64_t)htonl((uint32_t)(x >> 32)) |
            ((uint64_t)htonl((uint32_t)x) << 32));
}
static inline uint64_t brix_plat_be64toh(uint64_t x) {
    return ((uint64_t)ntohl((uint32_t)(x >> 32)) |
            ((uint64_t)ntohl((uint32_t)x) << 32));
}
static inline uint32_t brix_plat_htobe32(uint32_t x) { return htonl(x); }
static inline uint32_t brix_plat_be32toh(uint32_t x) { return ntohl(x); }
static inline uint16_t brix_plat_htobe16(uint16_t x) { return htons(x); }
static inline uint16_t brix_plat_be16toh(uint16_t x) { return ntohs(x); }

#endif

/* ==========================================================================
 * INITIALIZATION
 *
 * PAL lifecycle management. Call brix_plat_init() once at startup.
 * ========================================================================== */

/**
 * Initialize the Platform Abstraction Layer
 *
 * Called once at module initialization.
 *
 * CURRENT IMPLEMENTATION: Minimal stub returning 0.
 *
 * FUTURE ENHANCEMENT: May perform platform-specific initialization such as:
 *   - Linux: io_uring capability detection, seccomp availability
 *   - macOS: Accelerate framework init, kqueue setup
 *   - Windows: Handle registry init, BCrypt algorithm setup
 *
 * @return 0 on success (currently always succeeds), -1 on error
 */
int brix_plat_init(void);

/**
 * Clean up the Platform Abstraction Layer
 *
 * Called once at module shutdown.
 *
 * CURRENT IMPLEMENTATION: Empty stub (no-op).
 *
 * FUTURE ENHANCEMENT: May release PAL resources such as:
 *   - Linux: io_uring ring cleanup, seccomp context
 *   - macOS: kqueue fd cleanup
 *   - Windows: Handle registry cleanup, BCrypt handle closure
 *
 * @return void
 */
void brix_plat_cleanup(void);

#endif /* BRIX_PLATFORM_API_H */

/* ==========================================================================
 * DARWIN / APPLE SILICON APIs (macOS ARM64 only)
 * ========================================================================== */

#if BRIX_PLATFORM_DARWIN && BRIX_ARCH_ARM64

/* ==========================================================================
 * APPLE SILICON CHIP DETECTION
 * ========================================================================== */

/**
 * Detect Apple Silicon chip type
 *
 * Populates internal state with chip model (M1/M2/M3 series) and core counts.
 * Called automatically by brix_apple_init().
 *
 * @return void
 *
 * Usage: Called once at initialization for chip detection
 */
void brix_apple_detect_chip(void);

/**
 * Get Apple Silicon chip name
 * @return Chip name string (e.g., "M1", "M2 Pro", "M3 Max")
 *         Static buffer, do not free
 *
 * Usage: Logging, diagnostics, optimization selection
 */
const char *brix_apple_get_chip_name(void);

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or 0 if unavailable
 *
 * Usage: Pin high-priority workers to performance cores
 */
int brix_apple_get_perf_cores(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if unavailable
 *
 * Usage: Pin background workers to efficiency cores
 */
int brix_apple_get_eff_cores(void);

/* ==========================================================================
 * CPU TOPOLOGY APIs
 * ========================================================================== */

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or fallback to total cores
 *
 * Usage: Pin high-priority workers (SSL, cache fill) to performance cores
 */
int brix_plat_cpu_count_performance(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if none (Intel or Apple Silicon without eff cores)
 *
 * Usage: Pin background workers (log flush, metrics, cache eviction) to efficiency cores
 */
int brix_plat_cpu_count_efficiency(void);

/**
 * Get detailed CPU information including chip model
 *
 * Note: brix_apple_cpu_info_t is defined in cpu_topology.c
 * For public API, use brix_apple_get_chip_name() and core count functions.
 *
 * @param info Output structure (must be allocated by caller)
 * @return 0 on success, -1 on error
 *
 * Usage: Determine chip capabilities for optimization selection
 */
int brix_plat_cpu_info(void *info);

/**
 * Get chip model string
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return 0 on success, -1 on error
 *
 * Usage: Logging, diagnostics, optimization selection
 */
int brix_plat_chip_model(char *buf, size_t buf_size);

/**
 * Check if running on Apple Silicon
 * @return 1 if Apple Silicon (ARM64), 0 if Intel (x86_64)
 *
 * Usage: Conditional code paths for Apple Silicon optimizations
 */
int brix_plat_is_apple_silicon(void);

/**
 * Get recommended worker placement strategy
 * @return Strategy code:
 *   1 = All performance cores (no efficiency cores)
 *   2 = Mixed: perf for workers, eff for background
 *   0 = Unknown/error
 *
 * Usage: Determine optimal worker thread placement
 */
int brix_plat_worker_placement_strategy(void);

/**
 * Print CPU topology information (for debugging/logging)
 *
 * Usage: Call at startup to log detected hardware
 */
void brix_plat_cpu_topology_print(void);

/* ==========================================================================
 * APFS CLONEFILE OPTIMIZATION
 * ========================================================================== */

/**
 * Get Apple Silicon chip name
 * @return Chip name string (e.g., "M1", "M2 Pro", "M3 Max")
 *         Static buffer, do not free
 *
 * Usage: Logging, diagnostics, optimization selection
 */
const char *brix_apple_get_chip_name(void);

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or 0 if unavailable
 *
 * Usage: Pin high-priority workers to performance cores
 */
int brix_apple_get_perf_cores(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if unavailable
 *
 * Usage: Pin background workers to efficiency cores
 */
int brix_apple_get_eff_cores(void);

/**
 * APFS clonefile - Copy-on-write file clone
 *
 * Creates an instantaneous metadata-only clone of a file on APFS.
 * Extremely fast (~100x faster than copy for large files).
 *
 * @param src Source file path
 * @param dst Destination file path
 * @param flags Clone flags (currently unused, pass 0)
 * @return 0 on success, -1 on error (errno set)
 *
 * Availability: macOS 10.12+ (Sierra)
 * Performance: ~100x faster than copy for large files
 *
 * Usage: Fast file copies, snapshots, backup operations
 */
int brix_apple_clonefile(const char *src, const char *dst, int flags);

/**
 * APFS clonefileat - Relative path version
 *
 * @param src_dirfd Source directory file descriptor
 * @param src Source file path (relative to src_dirfd)
 * @param dst_dirfd Destination directory file descriptor
 * @param dst Destination file path (relative to dst_dirfd)
 * @param flags Clone flags (currently unused, pass 0)
 * @return 0 on success, -1 on error (errno set)
 *
 * Usage: Clone files within directory trees
 */
int brix_apple_clonefileat(int src_dirfd, const char *src,
                           int dst_dirfd, const char *dst, int flags);

/**
 * Allocate aligned memory for cache efficiency
 *
 * Allocates memory aligned to 128-byte cache line boundary
 * for optimal L1 cache performance on Apple Silicon.
 *
 * @param size Size in bytes
 * @return Aligned pointer, or NULL on failure
 *
 * Usage: Allocate buffers for SIMD operations, cache structures
 */
void *brix_apple_aligned_alloc(size_t size);

/**
 * Apple Silicon performance statistics
 */
typedef struct {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t cache_misses;
    uint64_t branch_misses;
} brix_apple_perf_stats_t;

/**
 * Start performance monitoring
 * @return 0 on success, -1 on error
 *
 * Note: Requires entitlements on macOS, currently no-op
 */
int brix_apple_perf_start(void);

/**
 * Read performance counters
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 *
 * Note: Limited implementation due to macOS restrictions
 */
int brix_apple_perf_read(brix_apple_perf_stats_t *stats);

/**
 * Stop performance monitoring
 * @return 0 on success, -1 on error
 */
int brix_apple_perf_stop(void);

/**
 * Initialize Apple Silicon optimizations
 *
 * Called once at module initialization.
 * Detects chip type and core counts.
 *
 * @return void
 */
void brix_apple_init(void);

/**
 * Get optimization information
 * @return Info string (static buffer, do not free)
 *
 * Format: "Apple Silicon: M1 (4 perf + 4 eff cores), Accelerate=yes, clonefile=yes"
 */
const char *brix_apple_get_optimization_info(void);

#endif /* BRIX_PLATFORM_DARWIN && BRIX_ARCH_ARM64 */

/* ==========================================================================
 * WINDOWS PLATFORM DETECTION (Windows only)
 * ========================================================================== */

#if BRIX_PLATFORM_WINDOWS

/**
 * Check if running on Windows
 * @return 1 if Windows, 0 otherwise
 */
int brix_plat_is_windows(void);

/**
 * Get Windows version string
 * @return Version string (e.g., "Windows 11 (22H2) (Build 22621)")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_version(void);

/**
 * Get Windows build number
 * @return Build number (e.g., 22621)
 */
unsigned long brix_plat_windows_build(void);

/**
 * Get Windows version components
 * @param major Output: Major version
 * @param minor Output: Minor version
 * @param build Output: Build number
 * @return 0 on success, -1 on failure
 */
int brix_plat_windows_version_info(unsigned long *major,
                                   unsigned long *minor,
                                   unsigned long *build);

/**
 * Check if running on Windows Server
 * @return 1 if Server, 0 if client
 */
int brix_plat_is_windows_server(void);

/**
 * Get Windows service pack string
 * @return Service pack string (e.g., "Service Pack 1", "None")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_service_pack(void);

/**
 * Get Windows edition from registry
 * @return Edition string (e.g., "Professional", "Datacenter")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_edition(void);

/**
 * Check if Windows version meets minimum requirements
 * @param min_major Minimum major version
 * @param min_minor Minimum minor version
 * @param min_build Minimum build number
 * @return 1 if meets requirements, 0 otherwise
 */
int brix_plat_windows_version_at_least(unsigned long min_major,
                                       unsigned long min_minor,
                                       unsigned long min_build);

#endif /* BRIX_PLATFORM_WINDOWS */
