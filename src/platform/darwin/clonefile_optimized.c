/*
 * src/platform/darwin/clonefile_optimized.c - APFS clonefile optimization
 * 
 * This file provides optimized file copy operations using APFS clonefile.
 * clonefile creates a copy-on-write clone instantly, with zero data copying.
 * 
 * Performance Benefits:
 * - clonefile: ~1 microsecond (instant, metadata-only)
 * - sendfile: ~100 microseconds + memory bandwidth
 * - read/write: ~1-10 milliseconds (full data copy)
 * - Speedup: 1000-10000x for large files
 * 
 * Requirements:
 * - APFS filesystem (default on macOS 10.13+)
 * - macOS 10.12+ (clonefile syscall)
 * - Source and destination on same filesystem
 * 
 * Fallback:
 * If clonefile fails (non-APFS, cross-filesystem), falls back to sendfile.
 */

#include "../platform.h"

#if BRIX_PLATFORM_DARWIN

#include <sys/syscall.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/param.h>   /* struct statfs (with <sys/mount.h>) */
#include <sys/mount.h>
#include <sys/socket.h>  /* sendfile on macOS */
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/*
 * APFS clonefile Implementation
 * 
 * Creates a copy-on-write clone of a file. The clone shares data blocks
 * with the original until either file is modified.
 * 
 * Implementation:
 * - Uses clonefile() syscall (macOS 10.12+)
 * - Falls back to sendfile() if clonefile fails
 * - Falls back to buffered copy if sendfile fails
 * 
 * @param src_path Source file path
 * @param dst_path Destination file path
 * @param flags Clone flags (CLONE_NOFOLLOW, etc.)
 * @return 0 on success, -1 on error (errno set)
 */
int
brix_plat_clonefile(const char *src_path, const char *dst_path, int flags)
{
    struct stat st;
    
    /* Check if source exists and is a regular file */
    if (stat(src_path, &st) < 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        return -1;
    }
    
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    
    /* Try clonefile first (fastest) */
    if (clonefile(src_path, dst_path, flags) == 0) {
        return 0;
    }
    
    /*
     * clonefile failed. Common reasons:
     * - ENOTSUP: Not APFS filesystem
     * - EXDEV: Cross-filesystem copy
     * - EEXIST: Destination exists
     * 
     * Fall back to sendfile
     */
    int src_fd = open(src_path, O_RDONLY); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
    if (src_fd < 0) {
        return -1;
    }
    
    int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
    if (dst_fd < 0) {
        close(src_fd);
        return -1;
    }
    
    off_t offset = 0;
    off_t count = st.st_size;
    struct sf_hdtr hdtr;
    memset(&hdtr, 0, sizeof(hdtr));
    
    if (sendfile(src_fd, dst_fd, offset, &count, &hdtr, 0) < 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        /* sendfile failed, fall back to buffered copy */
        close(src_fd);
        close(dst_fd);
        
        /* Buffered copy fallback */
        char buf[65536];
        ssize_t n;
        
        src_fd = open(src_path, O_RDONLY); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode); /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        
        if (src_fd < 0 || dst_fd < 0) {
            if (src_fd >= 0) close(src_fd);
            if (dst_fd >= 0) close(dst_fd);
            return -1;
        }
        
        while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
            if (write(dst_fd, buf, n) != n) {
                close(src_fd);
                close(dst_fd);
                return -1;
            }
        }
        
        close(src_fd);
        close(dst_fd);
        return (n < 0) ? -1 : 0;
    }
    
    close(src_fd);
    close(dst_fd);
    return 0;
}

/*
 * brix_plat_copy_range() for Darwin lives in posix_wrapper.c (ENOSYS stub:
 * macOS has no copy_file_range(2); callers fall back to buffered copy).
 * clonefile(2) needs paths, not descriptors, so it cannot back that API —
 * use brix_plat_clonefile()/brix_plat_supports_clonefile() below instead.
 */

/*
 * Check if filesystem supports clonefile
 * 
 * @param path Path to check
 * @return 1 if clonefile supported, 0 otherwise
 */
int
brix_plat_supports_clonefile(const char *path)
{
    struct statfs fs;
    
    if (statfs(path, &fs) < 0) {
        return 0;
    }
    
    /* Check if filesystem is APFS */
    /* APFS type: 0x424a5342 ("BJBB" in little-endian) */
    return (strcmp(fs.f_fstypename, "apfs") == 0);
}

/*
 * Get clonefile statistics
 * Phase 3 stub - returns 0 clones
 * 
 * @param path File path
 * @param clone_count Output: number of clones
 * @param shared_bytes Output: bytes shared with clones
 * @return 0 on success, -1 on error
 */
int
brix_plat_get_clone_stats(const char *path, uint32_t *clone_count, uint64_t *shared_bytes)
{
    struct stat st;
    
    if (stat(path, &st) < 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation beneath VFS */
        return -1;
    }
    
    /* Phase 3 stub - no clone statistics available */
    if (clone_count) {
        *clone_count = 0;
    }
    
    if (shared_bytes) {
        *shared_bytes = 0;
    }
    
    return 0;
}

#endif /* BRIX_PLATFORM_DARWIN */
