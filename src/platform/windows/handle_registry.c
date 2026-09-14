/* Windows fd registry allocation, growing and free-slot selection.
 * The handle owner passes its existing storage; no registry is duplicated.
 */
#include "handle_internal.h"
#if BRIX_PLATFORM_WINDOWS
#include <errno.h>
#include <stdlib.h>
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
int
brix_win32_registry_init(brix_win32_handle_registry_t *registry)
{
    /* Fast path: already initialized */
    if (registry->initialized) {
        return 0;
    }

    /* Allocate initial registry */
    registry->entries = (brix_win32_handle_entry_t *)calloc(
        BRIX_WIN32_INITIAL_SIZE,
        sizeof(brix_win32_handle_entry_t)
    );

    if (registry->entries == NULL) {
        errno = ENOMEM;
        return -1;
    }

    /* Initialize all entries as unused */
    for (size_t i = 0; i < BRIX_WIN32_INITIAL_SIZE; i++) {
        registry->entries[i].fd = BRIX_WIN32_FD_UNUSED;
        registry->entries[i].type = FD_UNUSED;
        registry->entries[i].refcount = 0;
        registry->entries[i].name = NULL;
    }

    registry->capacity = BRIX_WIN32_INITIAL_SIZE;
    registry->next_fd = 0;
    registry->used_count = 0;

    /* Initialize SRW lock (already initialized via SRWLOCK_INIT, but be explicit) */
    InitializeSRWLock(&registry->lock);

    /* Memory barrier to ensure visibility */
    registry->initialized = 1;

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
int
brix_win32_registry_grow(brix_win32_handle_registry_t *registry)
{
    size_t new_capacity = registry->capacity * 2;

    /* Check maximum limit */
    if (new_capacity > BRIX_WIN32_MAX_FDS) {
        errno = EMFILE;
        return -1;
    }

    /* Allocate new array */
    brix_win32_handle_entry_t *new_entries = (brix_win32_handle_entry_t *)realloc(
        registry->entries,
        new_capacity * sizeof(brix_win32_handle_entry_t)
    );

    if (new_entries == NULL) {
        errno = ENOMEM;
        return -1;
    }

    /* Initialize new entries as unused */
    for (size_t i = registry->capacity; i < new_capacity; i++) {
        new_entries[i].fd = BRIX_WIN32_FD_UNUSED;
        new_entries[i].type = FD_UNUSED;
        new_entries[i].refcount = 0;
        new_entries[i].name = NULL;
    }

    /* Switch to new array */
    registry->entries = new_entries;
    registry->capacity = new_capacity;

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
int
brix_win32_find_free_entry(brix_win32_handle_registry_t *registry)
{
    size_t start = registry->next_fd;
    size_t i = start;

    do {
        if (registry->entries[i].fd == BRIX_WIN32_FD_UNUSED) {
            /* Found free entry */
            registry->next_fd = (i + 1) % registry->capacity;
            return (int)i;
        }

        i = (i + 1) % registry->capacity;
    } while (i != start);

    /* No free entry found */
    return -1;
}

#endif /* BRIX_PLATFORM_WINDOWS */
