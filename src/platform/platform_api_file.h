/* Descriptor lifetime, synchronization and byte transfer.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

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
