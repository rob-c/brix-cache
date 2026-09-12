/*
 * src/platform/linux/copy_range.c - Linux copy_file_range wrapper
 */

#include "../platform.h"
#include "../platform_api.h"

#if defined(__NR_copy_file_range)

#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>

ssize_t
brix_platform_copy_range(int src_fd, off_t *src_off, int dst_fd, 
                          off_t *dst_off, size_t len, unsigned int flags)
{
    ssize_t copied;
    size_t total_copied = 0;
    
    /* Loop to handle partial copies and EINTR */
    while (total_copied < len) {
        size_t remaining = len - total_copied;
        
        copied = syscall(__NR_copy_file_range, src_fd, src_off, 
                        dst_fd, dst_off, remaining, flags);
        
        if (copied < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on signal */
            }
            /* Error - return what we've copied so far, or -1 if nothing */
            return (total_copied > 0) ? (ssize_t)total_copied : -1;
        }
        
        if (copied == 0) {
            /* EOF reached */
            break;
        }
        
        total_copied += (size_t)copied;
    }
    
    return (ssize_t)total_copied;
}

#else /* !__NR_copy_file_range */

/* Fallback when copy_file_range syscall is not available */

#include <errno.h>
#include <unistd.h>

ssize_t
brix_platform_copy_range(int src_fd, off_t *src_off, int dst_fd, 
                          off_t *dst_off, size_t len, unsigned int flags)
{
    /* No copy_file_range - caller should use pread/pwrite fallback */
    (void)src_fd;
    (void)src_off;
    (void)dst_fd;
    (void)dst_off;
    (void)len;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

#endif /* __NR_copy_file_range */
