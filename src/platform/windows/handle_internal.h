/* Windows handle registry storage and allocation helpers.
 * Requires: no prior headers; the PAL handle type is included here.
 */
#pragma once
#include "handle_abstraction.h"
#if BRIX_PLATFORM_WINDOWS
/* ==========================================================================
 * CONFIGURATION
 * ========================================================================== */

/* Maximum number of concurrent file descriptors */
#define BRIX_WIN32_MAX_FDS  4096

/* Initial registry size (grows dynamically if needed) */
#define BRIX_WIN32_INITIAL_SIZE  256

/* Sentinel value for unused entries */
#define BRIX_WIN32_FD_UNUSED  -1

/**
 * Handle registry entry
 *
 * Each entry tracks a single file descriptor and its associated HANDLE.
 * The fd field serves as both the index and validity marker:
 * - fd == BRIX_WIN32_FD_UNUSED: Entry is free
 * - fd >= 0: Entry is in use, fd matches array index
 */
typedef struct {
    int fd;                      /* File descriptor (index in registry) */
    union {
        HANDLE handle;           /* Generic handle */
        SOCKET socket;           /* Socket handle (Winsock) */
    };
    brix_win32_fd_type_t type;   /* Handle type for proper cleanup */
    int refcount;                /* Reference count for shared handles */
    const char *name;            /* Optional debug name (NULL if not tracked) */
} brix_win32_handle_entry_t;

/**
 * Handle registry
 *
 * Thread-safe registry using SRW lock (Slim Reader-Writer lock).
 * SRW locks are more efficient than critical sections for read-heavy workloads.
 *
 * The registry grows dynamically:
 * - Starts at BRIX_WIN32_INITIAL_SIZE entries
 * - Doubles in size when capacity is reached
 * - Maximum size: BRIX_WIN32_MAX_FDS
 */
typedef struct {
    brix_win32_handle_entry_t *entries;  /* Array of handle entries */
    size_t capacity;                     /* Total capacity (entries array size) */
    size_t next_fd;                      /* Next available fd (monotonic counter) */
    size_t used_count;                   /* Number of active handles */
    SRWLOCK lock;                        /* Thread-safe access lock */
    int initialized;                     /* Initialization flag */
} brix_win32_handle_registry_t;

int brix_win32_registry_init(brix_win32_handle_registry_t *registry);
int brix_win32_registry_grow(brix_win32_handle_registry_t *registry);
int brix_win32_find_free_entry(brix_win32_handle_registry_t *registry);
#endif
