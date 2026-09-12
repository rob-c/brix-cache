/*
 * test_platform.c - Simple platform detection test
 * 
 * Compile: gcc -Isrc -Iobjs test_platform.c -o test_platform
 * Run: ./test_platform
 */

#include <stdio.h>
#include <stdlib.h>

/* Mock ngx_core.h for standalone test */
typedef void *ngx_log_t;
typedef struct { ngx_log_t *log; } ngx_cycle_t;
ngx_cycle_t *ngx_cycle;

/* Include platform headers */
#include "src/platform/platform.h"
#include "src/platform/platform_api.h"

int main(int argc, char *argv[])
{
    printf("===========================================\n");
    printf("BriX-Cache Platform Detection Test\n");
    printf("===========================================\n\n");
    
    /* Platform detection */
    printf("Platform: %s\n", brix_platform_name());
    printf("Version: %s\n", brix_platform_version());
    printf("Is root: %s\n", brix_platform_is_root() ? "yes" : "no");
    printf("CPU count: %d\n", brix_platform_cpu_count());
    printf("Total memory: %llu bytes\n", (unsigned long long)brix_platform_total_memory());
    printf("Available memory: %llu bytes\n", (unsigned long long)brix_platform_available_memory());
    printf("\n");
    
    /* Feature gating */
    printf("Feature Support:\n");
    printf("  io_uring: %s\n", BRIX_HAS_IO_URING ? "yes" : "no");
    printf("  seccomp: %s\n", BRIX_HAS_SECCOMP ? "yes" : "no");
    printf("  CephFS: %s\n", BRIX_HAS_CEPH ? "yes" : "no");
    printf("  inotify: %s\n", BRIX_HAS_INOTIFY ? "yes" : "no");
    printf("  splice: %s\n", BRIX_HAS_SPLICE ? "yes" : "no");
    printf("  posix_fadvise: %s\n", BRIX_HAS_POSIX_FADVISE ? "yes" : "no");
    printf("  FUSE: %s\n", BRIX_HAS_FUSE ? "yes" : "no");
    printf("\n");
    
    /* Test event initialization */
    printf("Testing event initialization...\n");
    int event_fd = brix_platform_event_init();
    if (event_fd >= 0) {
        printf("  ✓ Event fd: %d\n", event_fd);
        brix_platform_event_close(event_fd);
        printf("  ✓ Event fd closed\n");
    } else {
        printf("  ✗ Event initialization failed (errno=%d)\n", errno);
    }
    printf("\n");
    
    /* Test filesystem watcher creation */
    printf("Testing filesystem watcher...\n");
    brix_fs_watcher_t *watcher = brix_fs_watcher_create();
    if (watcher != NULL) {
        printf("  ✓ Watcher created\n");
        brix_fs_watcher_destroy(watcher);
        printf("  ✓ Watcher destroyed\n");
    } else {
        printf("  ✗ Watcher creation failed (errno=%d)\n", errno);
    }
    printf("\n");
    
    printf("===========================================\n");
    printf("Test Complete\n");
    printf("===========================================\n");
    
    return 0;
}
