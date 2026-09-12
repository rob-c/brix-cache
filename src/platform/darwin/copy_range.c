/*
 * src/platform/darwin/copy_range.c - macOS copy_file_range fallback
 * 
 * macOS lacks copy_file_range(2), so we use a pread/pwrite loop.
 * This is the same fallback that Linux uses when copy_file_range fails.
 */

#include "../platform.h"
#include "../platform_api.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

/* 256 KB buffer for pread/pwrite fallback - matches Linux implementation */
#define BRIX_COPY_RANGE_BUFSZ  (256 * 1024)

ssize_t
brix_platform_copy_range(int src_fd, off_t *src_off, int dst_fd, 
                          off_t *dst_off, size_t len, unsigned int flags)
{
    u_char *buf;
    size_t total_copied = 0;
    
    (void)flags;  /* No flags on macOS */
    
    /* Allocate buffer for pread/pwrite loop */
    buf = malloc(BRIX_COPY_RANGE_BUFSZ);
    if (buf == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    while (total_copied < len) {
        size_t to_read = (len - total_copied < BRIX_COPY_RANGE_BUFSZ) ? 
                         (len - total_copied) : BRIX_COPY_RANGE_BUFSZ;
        ssize_t nread;
        ssize_t nwritten;
        
        /* Read from source */
        nread = pread(src_fd, buf, to_read, *src_off);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on signal */
            }
            /* Real error */
            free(buf);
            return (total_copied > 0) ? (ssize_t)total_copied : -1;
        }
        
        if (nread == 0) {
            /* EOF reached */
            break;
        }
        
        /* Write to destination */
        nwritten = pwrite(dst_fd, buf, (size_t)nread, *dst_off);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on signal */
            }
            /* Real error */
            free(buf);
            return (total_copied > 0) ? (ssize_t)total_copied : -1;
        }
        
        if (nwritten != nread) {
            /* Short write - treat as error */
            errno = EIO;
            free(buf);
            return (total_copied > 0) ? (ssize_t)total_copied : -1;
        }
        
        /* Update offsets and counters */
        *src_off += (off_t)nread;
        *dst_off += (off_t)nwritten;
        total_copied += (size_t)nwritten;
    }
    
    free(buf);
    return (ssize_t)total_copied;
}
