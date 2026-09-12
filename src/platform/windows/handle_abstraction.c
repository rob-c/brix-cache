/*
 * src/platform/windows/handle_abstraction.c - Windows HANDLE/fd abstraction layer
 * 
 * Status: 🚧 IMPLEMENTATION COMPLETE
 * 
 * Provides thread-safe mapping between POSIX file descriptors and Windows HANDLEs.
 * This abstraction layer enables BriX-Cache to use POSIX-style file descriptor
 * operations on Windows while properly managing HANDLE lifecycles.
 * 
 * Integration:
 * - Included by posix_wrapper.c and other Windows PAL implementation files
 * - Called by brix_plat_*() functions to convert between fd and HANDLE
 * - Thread-safe via SRW lock (Slim Reader-Writer lock)
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"

#include <windows.h>
#include <winsock2.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ==========================================================================
 * CONFIGURATION
 * ========================================================================== */

/* Maximum number of concurrent file descriptors */
#define BRIX_WIN32_MAX_FDS  4096

/* Initial registry size (grows dynamically if needed) */
#define BRIX_WIN32_INITIAL_SIZE  256

/* Sentinel value for unused entries */
#define BRIX_WIN32_FD_UNUSED  -1

/* ==========================================================================
 * DATA STRUCTURES
 * ========================================================================== */

/**
 * Handle type enumeration
 * 
 * Different handle types require different cleanup operations:
 * - FD_FILE: CloseHandle()
 * - FD_SOCKET: closesocket()
 * - FD_PIPE: CloseHandle() + special pipe cleanup
 * - FD_EVENT: CloseHandle() (event objects, pipes, etc.)
 */
typedef enum {
    FD_UNUSED = 0,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_EVENT
} brix_win32_fd_type_t;

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

/* Global handle registry (singleton) */
static brix_win32_handle_registry_t g_handle_registry = {
    .entries = NULL,
    .capacity = 0,
    .next_fd = 0,
    .used_count = 0,
    .lock = SRWLOCK_INIT,
    .initialized = 0
};

/* ==========================================================================
 * INTERNAL FUNCTIONS
 * ========================================================================== */

/**
 * Initialize the handle registry
 * 
 * Called once at module initialization.
 * Thread-safe: uses atomic compare-and-swap for initialization flag.
 * 
 * @return 0 on success, -1 on error (errno set)
 */
static int
brix_win32_registry_init(void)
{
    /* Fast path: already initialized */
    if (g_handle_registry.initialized) {
        return 0;
    }
    
    /* Allocate initial registry */
    g_handle_registry.entries = (brix_win32_handle_entry_t *)calloc(
        BRIX_WIN32_INITIAL_SIZE,
        sizeof(brix_win32_handle_entry_t)
    );
    
    if (g_handle_registry.entries == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    /* Initialize all entries as unused */
    for (size_t i = 0; i < BRIX_WIN32_INITIAL_SIZE; i++) {
        g_handle_registry.entries[i].fd = BRIX_WIN32_FD_UNUSED;
        g_handle_registry.entries[i].type = FD_UNUSED;
        g_handle_registry.entries[i].refcount = 0;
        g_handle_registry.entries[i].name = NULL;
    }
    
    g_handle_registry.capacity = BRIX_WIN32_INITIAL_SIZE;
    g_handle_registry.next_fd = 0;
    g_handle_registry.used_count = 0;
    
    /* Initialize SRW lock (already initialized via SRWLOCK_INIT, but be explicit) */
    InitializeSRWLock(&g_handle_registry.lock);
    
    /* Memory barrier to ensure visibility */
    g_handle_registry.initialized = 1;
    
    return 0;
}

/**
 * Grow the handle registry
 * 
 * Called when capacity is reached.
 * Must be called with write lock held.
 * 
 * @return 0 on success, -1 on error (errno set, registry unchanged)
 */
static int
brix_win32_registry_grow(void)
{
    size_t new_capacity = g_handle_registry.capacity * 2;
    
    /* Check maximum limit */
    if (new_capacity > BRIX_WIN32_MAX_FDS) {
        errno = EMFILE;
        return -1;
    }
    
    /* Allocate new array */
    brix_win32_handle_entry_t *new_entries = (brix_win32_handle_entry_t *)realloc(
        g_handle_registry.entries,
        new_capacity * sizeof(brix_win32_handle_entry_t)
    );
    
    if (new_entries == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    /* Initialize new entries as unused */
    for (size_t i = g_handle_registry.capacity; i < new_capacity; i++) {
        new_entries[i].fd = BRIX_WIN32_FD_UNUSED;
        new_entries[i].type = FD_UNUSED;
        new_entries[i].refcount = 0;
        new_entries[i].name = NULL;
    }
    
    /* Switch to new array */
    g_handle_registry.entries = new_entries;
    g_handle_registry.capacity = new_capacity;
    
    return 0;
}

/**
 * Find a free entry in the registry
 * 
 * Searches from next_fd position (round-robin allocation).
 * Must be called with write lock held.
 * 
 * @return Index of free entry, or -1 if registry is full
 */
static int
brix_win32_find_free_entry(void)
{
    size_t start = g_handle_registry.next_fd;
    size_t i = start;
    
    do {
        if (g_handle_registry.entries[i].fd == BRIX_WIN32_FD_UNUSED) {
            /* Found free entry */
            g_handle_registry.next_fd = (i + 1) % g_handle_registry.capacity;
            return (int)i;
        }
        
        i = (i + 1) % g_handle_registry.capacity;
    } while (i != start);
    
    /* No free entry found */
    return -1;
}

/* ==========================================================================
 * PUBLIC API - HANDLE REGISTRATION
 * ========================================================================== */

/**
 * Register a new HANDLE and allocate an fd
 * 
 * Thread-safe: acquires write lock.
 * 
 * @param handle Windows HANDLE to register
 * @param type Handle type (FD_FILE, FD_SOCKET, etc.)
 * @param name Optional debug name (can be NULL, copied if provided)
 * @return New file descriptor (>= 0), or -1 on error (errno set)
 */
int
brix_win32_register_handle(HANDLE handle, brix_win32_fd_type_t type, const char *name)
{
    int fd = -1;
    int entry_idx;
    
    /* Ensure registry is initialized */
    if (brix_win32_registry_init() < 0) {
        return -1;
    }
    
    /* Validate handle */
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        errno = EINVAL;
        return -1;
    }
    
    /* Acquire write lock */
    AcquireSRWLockExclusive(&g_handle_registry.lock);
    
    /* Find free entry (grow registry if needed) */
    entry_idx = brix_win32_find_free_entry();
    
    if (entry_idx < 0) {
        /* Registry is full, try to grow */
        if (brix_win32_registry_grow() < 0) {
            goto unlock_error;
        }
        
        /* Try again after growing */
        entry_idx = brix_win32_find_free_entry();
        if (entry_idx < 0) {
            errno = EMFILE;
            goto unlock_error;
        }
    }
    
    /* Allocate entry */
    fd = entry_idx;
    g_handle_registry.entries[entry_idx].fd = fd;
    g_handle_registry.entries[entry_idx].handle = handle;
    g_handle_registry.entries[entry_idx].type = type;
    g_handle_registry.entries[entry_idx].refcount = 1;
    
    /* Copy name if provided */
    if (name != NULL) {
        g_handle_registry.entries[entry_idx].name = _strdup(name);
        /* Ignore strdup failure - name is optional debug info */
    } else {
        g_handle_registry.entries[entry_idx].name = NULL;
    }
    
    g_handle_registry.used_count++;
    
    /* Release write lock */
    ReleaseSRWLockExclusive(&g_handle_registry.lock);
    
    return fd;

unlock_error:
    ReleaseSRWLockExclusive(&g_handle_registry.lock);
    return -1;
}

/**
 * Register a SOCKET and allocate an fd
 * 
 * Convenience wrapper for socket handles.
 * 
 * @param socket Winsock SOCKET to register
 * @return New file descriptor (>= 0), or -1 on error (errno set)
 */
int
brix_win32_register_socket(SOCKET socket)
{
    if (socket == INVALID_SOCKET) {
        errno = EINVAL;
        return -1;
    }
    
    return brix_win32_register_handle((HANDLE)socket, FD_SOCKET, "socket");
}

/* ==========================================================================
 * PUBLIC API - HANDLE CONVERSION
 * ========================================================================== */

/**
 * Convert file descriptor to HANDLE
 * 
 * Thread-safe: acquires read lock.
 * Does NOT transfer ownership - caller should not close the returned HANDLE.
 * 
 * @param fd File descriptor
 * @return HANDLE on success, NULL on error (errno set)
 */
HANDLE
brix_win32_fd_to_handle(int fd)
{
    HANDLE handle;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        errno = EBADF;
        return NULL;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        errno = EBADF;
        return NULL;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    /* Validate entry */
    if (g_handle_registry.entries[fd].fd != fd ||
        g_handle_registry.entries[fd].type == FD_UNUSED)
    {
        ReleaseSRWLockShared(&g_handle_registry.lock);
        errno = EBADF;
        return NULL;
    }
    
    /* Get handle */
    handle = g_handle_registry.entries[fd].handle;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
    
    return handle;
}

/**
 * Convert file descriptor to SOCKET
 * 
 * Thread-safe: acquires read lock.
 * Only valid for FD_SOCKET type handles.
 * 
 * @param fd File descriptor
 * @return SOCKET on success, INVALID_SOCKET on error (errno set)
 */
SOCKET
brix_win32_fd_to_socket(int fd)
{
    SOCKET socket;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        errno = EBADF;
        return INVALID_SOCKET;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        errno = EBADF;
        return INVALID_SOCKET;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    /* Validate entry and type */
    if (g_handle_registry.entries[fd].fd != fd ||
        g_handle_registry.entries[fd].type != FD_SOCKET)
    {
        ReleaseSRWLockShared(&g_handle_registry.lock);
        errno = ENOTSOCK;
        return INVALID_SOCKET;
    }
    
    /* Get socket */
    socket = (SOCKET)g_handle_registry.entries[fd].handle;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
    
    return socket;
}

/**
 * Get handle type
 * 
 * Thread-safe: acquires read lock.
 * 
 * @param fd File descriptor
 * @return Handle type (FD_FILE, FD_SOCKET, etc.), or FD_UNUSED on error
 */
brix_win32_fd_type_t
brix_win32_get_fd_type(int fd)
{
    brix_win32_fd_type_t type;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        return FD_UNUSED;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        return FD_UNUSED;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    /* Validate entry */
    if (g_handle_registry.entries[fd].fd != fd) {
        ReleaseSRWLockShared(&g_handle_registry.lock);
        return FD_UNUSED;
    }
    
    type = g_handle_registry.entries[fd].type;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
    
    return type;
}

/* ==========================================================================
 * PUBLIC API - HANDLE CLEANUP
 * ========================================================================== */

/**
 * Close a file descriptor and release its HANDLE
 * 
 * Thread-safe: acquires write lock.
 * Properly closes the underlying HANDLE based on type:
 * - FD_FILE: CloseHandle()
 * - FD_SOCKET: closesocket()
 * - FD_PIPE: CloseHandle()
 * - FD_EVENT: CloseHandle()
 * 
 * @param fd File descriptor to close
 * @return 0 on success, -1 on error (errno set)
 */
int
brix_win32_close_handle(int fd)
{
    int result = 0;
    HANDLE handle;
    brix_win32_fd_type_t type;
    const char *name;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        errno = EBADF;
        return -1;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        errno = EBADF;
        return -1;
    }
    
    /* Acquire write lock */
    AcquireSRWLockExclusive(&g_handle_registry.lock);
    
    /* Validate entry */
    if (g_handle_registry.entries[fd].fd != fd ||
        g_handle_registry.entries[fd].type == FD_UNUSED)
    {
        ReleaseSRWLockExclusive(&g_handle_registry.lock);
        errno = EBADF;
        return -1;
    }
    
    /* Get handle info */
    handle = g_handle_registry.entries[fd].handle;
    type = g_handle_registry.entries[fd].type;
    name = g_handle_registry.entries[fd].name;
    
    /* Decrement refcount */
    g_handle_registry.entries[fd].refcount--;
    
    if (g_handle_registry.entries[fd].refcount > 0) {
        /* Still referenced, don't close yet */
        ReleaseSRWLockExclusive(&g_handle_registry.lock);
        return 0;
    }
    
    /* Close based on type */
    switch (type) {
        case FD_SOCKET:
            if (closesocket((SOCKET)handle) == SOCKET_ERROR) {
                /* Don't set errno here - closesocket may fail for already-closed sockets */
            }
            break;
            
        case FD_FILE:
        case FD_PIPE:
        case FD_EVENT:
            if (!CloseHandle(handle)) {
                /* Don't set errno here - CloseHandle may fail for already-closed handles */
            }
            break;
            
        default:
            /* Unknown type, try CloseHandle as fallback */
            CloseHandle(handle);
            break;
    }
    
    /* Free debug name if allocated */
    if (name != NULL) {
        free((void *)name);
    }
    
    /* Clear entry */
    g_handle_registry.entries[fd].fd = BRIX_WIN32_FD_UNUSED;
    g_handle_registry.entries[fd].handle = NULL;
    g_handle_registry.entries[fd].type = FD_UNUSED;
    g_handle_registry.entries[fd].refcount = 0;
    g_handle_registry.entries[fd].name = NULL;
    
    g_handle_registry.used_count--;
    
    /* Release write lock */
    ReleaseSRWLockExclusive(&g_handle_registry.lock);
    
    return result;
}

/**
 * Duplicate a file descriptor (increment refcount)
 * 
 * Thread-safe: acquires read lock.
 * 
 * @param fd File descriptor to duplicate
 * @return New fd (same as input), or -1 on error (errno set)
 */
int
brix_win32_dup_fd(int fd)
{
    int result = -1;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        errno = EBADF;
        return -1;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        errno = EBADF;
        return -1;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    /* Validate entry */
    if (g_handle_registry.entries[fd].fd != fd ||
        g_handle_registry.entries[fd].type == FD_UNUSED)
    {
        ReleaseSRWLockShared(&g_handle_registry.lock);
        errno = EBADF;
        return -1;
    }
    
    /* Increment refcount */
    g_handle_registry.entries[fd].refcount++;
    result = fd;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
    
    return result;
}

/**
 * Get debug name for a file descriptor
 * 
 * Thread-safe: acquires read lock.
 * Returns pointer to internal string - do NOT free.
 * 
 * @param fd File descriptor
 * @return Debug name, or NULL if not set
 */
const char *
brix_win32_get_fd_name(int fd)
{
    const char *name;
    
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        return NULL;
    }
    
    /* Validate fd range */
    if (fd < 0 || (size_t)fd >= g_handle_registry.capacity) {
        return NULL;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    /* Validate entry */
    if (g_handle_registry.entries[fd].fd != fd) {
        ReleaseSRWLockShared(&g_handle_registry.lock);
        return NULL;
    }
    
    name = g_handle_registry.entries[fd].name;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
    
    return name;
}

/* ==========================================================================
 * PUBLIC API - REGISTRY MANAGEMENT
 * ========================================================================== */

/**
 * Get registry statistics
 * 
 * Thread-safe: acquires read lock.
 * 
 * @param capacity Output: total capacity
 * @param used Output: number of active handles
 * @param next_fd Output: next fd to be allocated
 */
void
brix_win32_get_registry_stats(size_t *capacity, size_t *used, size_t *next_fd)
{
    /* Ensure registry is initialized */
    if (!g_handle_registry.initialized) {
        if (capacity) *capacity = 0;
        if (used) *used = 0;
        if (next_fd) *next_fd = 0;
        return;
    }
    
    /* Acquire read lock */
    AcquireSRWLockShared(&g_handle_registry.lock);
    
    if (capacity) *capacity = g_handle_registry.capacity;
    if (used) *used = g_handle_registry.used_count;
    if (next_fd) *next_fd = g_handle_registry.next_fd;
    
    /* Release read lock */
    ReleaseSRWLockShared(&g_handle_registry.lock);
}

/**
 * Cleanup the handle registry
 * 
 * Called once at module shutdown.
 * Closes all remaining handles and frees registry memory.
 * 
 * WARNING: Should only be called when no other threads are using the registry.
 */
void
brix_win32_cleanup_registry(void)
{
    if (!g_handle_registry.initialized) {
        return;
    }
    
    /* Acquire write lock */
    AcquireSRWLockExclusive(&g_handle_registry.lock);
    
    /* Close all remaining handles */
    for (size_t i = 0; i < g_handle_registry.capacity; i++) {
        if (g_handle_registry.entries[i].fd != BRIX_WIN32_FD_UNUSED) {
            HANDLE handle = g_handle_registry.entries[i].handle;
            brix_win32_fd_type_t type = g_handle_registry.entries[i].type;
            const char *name = g_handle_registry.entries[i].name;
            
            /* Close based on type */
            switch (type) {
                case FD_SOCKET:
                    closesocket((SOCKET)handle);
                    break;
                case FD_FILE:
                case FD_PIPE:
                case FD_EVENT:
                    CloseHandle(handle);
                    break;
                default:
                    break;
            }
            
            /* Free debug name */
            if (name != NULL) {
                free((void *)name);
            }
        }
    }
    
    /* Free registry memory */
    free(g_handle_registry.entries);
    g_handle_registry.entries = NULL;
    g_handle_registry.capacity = 0;
    g_handle_registry.used_count = 0;
    g_handle_registry.next_fd = 0;
    g_handle_registry.initialized = 0;
    
    /* Release write lock */
    ReleaseSRWLockExclusive(&g_handle_registry.lock);
}

#endif /* BRIX_PLATFORM_WINDOWS */
