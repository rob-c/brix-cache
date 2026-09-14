/*
 * src/platform/windows/fs_watcher.c - Windows filesystem monitoring
 * 
 * Uses ReadDirectoryChangesW with overlapped I/O for async file monitoring.
 * Phase 2: Can be extended to use completion ports for better scalability.
 * 
 * ReadDirectoryChangesW advantages:
 * - Native Windows API for directory monitoring
 * - Supports recursive watching
 * - Provides detailed change information
 * 
 * ReadDirectoryChangesW limitations vs inotify/kqueue:
 * - Requires directory handles, not file handles
 * - Buffer overflows can lose events
 * - No fd-based interface (uses HANDLE)
 * - More complex async handling
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fs_watcher_internal.h"

/* ==========================================================================
 * EVENT MAPPING: Windows FILE_ACTION_* to BRIX_FS_EVENT_*
 * ========================================================================== */

/*
 * Map PAL BRIX_FS_EVENT_* to Windows FILE_NOTIFY_FILTER_*
 * 
 * Note: Windows uses filters for what to watch, not events that occurred
 */
DWORD
brix_win_map_pal_to_notify_filter(uint32_t events)
{
    DWORD filter = 0;
    
    if (events & (BRIX_FS_EVENT_CREATE | BRIX_FS_EVENT_DELETE)) {
        filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
    }
    
    if (events & (BRIX_FS_EVENT_WRITE | BRIX_FS_EVENT_ATTRIB)) {
        filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
        filter |= FILE_NOTIFY_CHANGE_SIZE;
        filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
    }
    
    if (events & BRIX_FS_EVENT_RENAME) {
        filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
        filter |= FILE_NOTIFY_CHANGE_DIR_NAME;
    }
    
    /* Additional filters for completeness */
    filter |= FILE_NOTIFY_CHANGE_CREATION;
    filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
    filter |= FILE_NOTIFY_CHANGE_SECURITY;
    
    return filter;
}

/* ==========================================================================
 * WATCH MANAGEMENT
 * ========================================================================== */

/*
 * Find watch descriptor by ID
 */
static brix_win_watch_desc_t *
brix_win_find_watch(brix_plat_fs_watcher_t *watcher, int wd)
{
    brix_win_watch_desc_t *current = watcher->watches;
    
    while (current != NULL) {
        if (current->wd == wd) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

/*
 * Add watch to linked list
 */
static void
brix_win_add_watch_to_list(brix_plat_fs_watcher_t *watcher, brix_win_watch_desc_t *wdesc)
{
    wdesc->next = watcher->watches;
    watcher->watches = wdesc;
    watcher->event_count++;
}

/*
 * Remove watch from linked list
 */
static brix_win_watch_desc_t *
brix_win_remove_watch_from_list(brix_plat_fs_watcher_t *watcher, int wd)
{
    brix_win_watch_desc_t **prev = &watcher->watches;
    brix_win_watch_desc_t *current = watcher->watches;
    
    while (current != NULL) {
        if (current->wd == wd) {
            *prev = current->next;
            watcher->event_count--;
            return current;
        }
        prev = &current->next;
        current = current->next;
    }
    
    return NULL;
}

/* ==========================================================================
 * FILESYSTEM WATCHER LIFECYCLE
 * ========================================================================== */

int
brix_plat_fs_watcher_init(brix_plat_fs_watcher_t *watcher)
{
    /*
     * Initialize filesystem watcher
     * 
     * Phase 1: Simple linked list implementation
     * Phase 2: IOCP-based for better scalability
     */
    if (watcher == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    memset(watcher, 0, sizeof(brix_plat_fs_watcher_t));
    
    watcher->watches = NULL;
    watcher->next_wd = 1;  /* Start from 1 (0 is invalid) */
    watcher->event_count = 0;
    watcher->completion_port = NULL;
    
    /*
     * Phase 2: Create IOCP for scalable event handling
     * For now, use simple polling on overlapped I/O
     */
    
    return 0;
}

int
brix_plat_fs_watcher_add(brix_plat_fs_watcher_t *watcher,
                         const char *path, uint32_t events)
{
    /*
     * Add a directory watch
     * 
     * Windows ReadDirectoryChangesW requirements:
     * - Must open directory with FILE_LIST_DIRECTORY permission
     * - Must use FILE_FLAG_BACKUP_SEMANTICS for directory handles
     * - Supports recursive watching (optional)
     */
    brix_win_watch_desc_t *wdesc;
    HANDLE dir_handle;
    DWORD notify_filter;
    char normalized_path[MAX_PATH];
    
    if (watcher == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Normalize path (forward slashes to backslashes) */
    strncpy(normalized_path, path, sizeof(normalized_path) - 1);
    normalized_path[sizeof(normalized_path) - 1] = '\0';
    brix_win32_normalize_path(normalized_path);
    
    /* Open directory handle */
    dir_handle = CreateFileA(
        normalized_path,
        FILE_LIST_DIRECTORY,           /* Permission: list directory contents */
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |   /* Required for directory handles */
        FILE_FLAG_OVERLAPPED,          /* Async I/O */
        NULL
    );
    
    if (dir_handle == INVALID_HANDLE_VALUE) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Allocate watch descriptor */
    wdesc = (brix_win_watch_desc_t *)calloc(1, sizeof(brix_win_watch_desc_t));
    if (wdesc == NULL) {
        CloseHandle(dir_handle);
        errno = ENOMEM;
        return -1;
    }
    
    /* Initialize watch descriptor */
    wdesc->dir_handle = dir_handle;
    wdesc->events = events;
    wdesc->wd = watcher->next_wd++;
    strncpy(wdesc->path, normalized_path, sizeof(wdesc->path) - 1);
    
    /* Initialize overlapped structure */
    memset(&wdesc->overlapped, 0, sizeof(OVERLAPPED));
    wdesc->overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    
    if (wdesc->overlapped.hEvent == NULL) {
        free(wdesc);
        CloseHandle(dir_handle);
        errno = ENOMEM;
        return -1;
    }
    
    /* Map PAL events to Windows notify filter */
    notify_filter = brix_win_map_pal_to_notify_filter(events);
    
    /* Start monitoring with ReadDirectoryChangesW */
    /* Note: This will complete asynchronously */
    BOOL result = ReadDirectoryChangesW(
        dir_handle,
        wdesc->overlapped.Pointer,  /* Buffer in overlapped structure */
        BRIX_WIN_EVENT_BUFFER_SIZE,
        FALSE,                       /* Not recursive (Phase 2: make configurable) */
        notify_filter,
        NULL,                        /* bytes_returned - NULL for async */
        &wdesc->overlapped,
        NULL                         /* completion routine - NULL for event-based */
    );
    
    if (!result) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            /* Real error (not just pending) */
            brix_win32_set_errno(error);
            CloseHandle(wdesc->overlapped.hEvent);
            free(wdesc);
            CloseHandle(dir_handle);
            return -1;
        }
        /* ERROR_IO_PENDING is expected for async operation */
    }
    
    /* Add to watch list */
    brix_win_add_watch_to_list(watcher, wdesc);
    
    return wdesc->wd;
}

int
brix_plat_fs_watcher_rm(brix_plat_fs_watcher_t *watcher, int wd)
{
    /*
     * Remove a watch
     * 
     * Cleanup steps:
     * 1. Cancel pending I/O
     * 2. Close event handle
     * 3. Close directory handle
     * 4. Free watch descriptor
     */
    brix_win_watch_desc_t *wdesc;
    
    if (watcher == NULL || wd < 0) {
        errno = EINVAL;
        return -1;
    }
    
    /* Find and remove from list */
    wdesc = brix_win_remove_watch_from_list(watcher, wd);
    if (wdesc == NULL) {
        errno = ENOENT;
        return -1;
    }
    
    /* Cancel pending I/O */
    CancelIo(wdesc->dir_handle);
    
    /* Wait for cancellation to complete */
    Sleep(10);  /* Brief delay for cancellation */
    
    /* Close handles */
    if (wdesc->overlapped.hEvent != NULL) {
        CloseHandle(wdesc->overlapped.hEvent);
    }
    
    CloseHandle(wdesc->dir_handle);
    
    /* Free watch descriptor */
    free(wdesc);
    
    return 0;
}

void
brix_plat_fs_watcher_destroy(brix_plat_fs_watcher_t *watcher)
{
    /*
     * Destroy filesystem watcher
     * 
     * Cleanup all remaining watches
     */
    brix_win_watch_desc_t *wdesc;
    brix_win_watch_desc_t *next;
    
    if (watcher == NULL) {
        return;
    }
    
    /* Remove all watches */
    wdesc = watcher->watches;
    while (wdesc != NULL) {
        next = wdesc->next;
        
        /* Cancel I/O */
        CancelIo(wdesc->dir_handle);
        
        /* Close handles */
        if (wdesc->overlapped.hEvent != NULL) {
            CloseHandle(wdesc->overlapped.hEvent);
        }
        CloseHandle(wdesc->dir_handle);
        
        /* Free descriptor */
        free(wdesc);
        
        wdesc = next;
    }
    
    watcher->watches = NULL;
    watcher->event_count = 0;
    
    /* Close completion port if created (Phase 2) */
    if (watcher->completion_port != NULL) {
        CloseHandle(watcher->completion_port);
        watcher->completion_port = NULL;
    }
}

/* ==========================================================================
 * LIMITATIONS SUMMARY (vs inotify/kqueue)
 * ========================================================================== */

/*
 * ReadDirectoryChangesW Limitations vs inotify (Linux) and kqueue (macOS):
 * 
 * 1. Event Granularity:
 *    - inotify: Per-file watches with fine-grained events
 *    - kqueue: Per-file descriptor watches with vnode events
 *    - Windows: Directory-based watches, less granular
 * 
 * 2. Event Types:
 *    - inotify: IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_*, IN_OPEN, etc.
 *    - kqueue: NOTE_DELETE, NOTE_WRITE, NOTE_EXTEND, NOTE_ATTRIB, etc.
 *    - Windows: FILE_ACTION_* (ADDED, REMOVED, MODIFIED, RENAMED)
 *    - Missing: Access tracking, close events, open events
 * 
 * 3. Event Reliability:
 *    - inotify: Queue-based, no event loss (unless queue overflows)
 *    - kqueue: Kernel queue, reliable delivery
 *    - Windows: Buffer-based, can overflow and lose events
 * 
 * 4. Rename Handling:
 *    - inotify: IN_MOVED_FROM/IN_MOVED_TO with cookie for pairing
 *    - kqueue: NOTE_RENAME (single event)
 *    - Windows: FILE_ACTION_RENAMED_OLD_NAME/NEW_NAME (no cookie)
 * 
 * 5. Interface:
 *    - inotify: File descriptor interface (select/poll/epoll compatible)
 *    - kqueue: File descriptor interface (select/poll/kqueue compatible)
 *    - Windows: HANDLE interface (requires WaitForMultipleObjects/IOCP)
 * 
 * 6. Recursive Watching:
 *    - inotify: Manual (watch each subdirectory)
 *    - kqueue: Manual (watch each subdirectory)
 *    - Windows: Built-in support (hParameter to ReadDirectoryChangesW)
 * 
 * 7. Performance:
 *    - inotify: Very efficient, kernel-side filtering
 *    - kqueue: Very efficient, kernel-side filtering
 *    - Windows: Good, but buffer copies and async complexity
 * 
 * Phase 2 Improvements:
 * - IOCP integration for scalable event handling
 * - Better buffer management to prevent overflow
 * - Recursive watching support
 * - Proper UTF-16 to UTF-8 filename conversion
 * - Timestamp extraction via GetFileTime
 */

#endif /* BRIX_PLATFORM_WINDOWS */
