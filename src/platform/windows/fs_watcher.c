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

/* ==========================================================================
 * INTERNAL STRUCTURES
 * ========================================================================== */

/*
 * Watch descriptor for tracking individual directory watches
 */
typedef struct brix_win_watch_desc {
    HANDLE dir_handle;              /* Directory handle */
    OVERLAPPED overlapped;          /* Overlapped I/O structure */
    uint32_t events;                /* Event mask being watched */
    char path[MAX_PATH];            /* Path being watched */
    int wd;                         /* Watch descriptor ID */
    struct brix_win_watch_desc *next;
} brix_win_watch_desc_t;

/*
 * Buffer for ReadDirectoryChangesW notifications
 */
#define BRIX_WIN_EVENT_BUFFER_SIZE (4096)

typedef struct {
    BYTE buffer[BRIX_WIN_EVENT_BUFFER_SIZE];
    DWORD bytes_returned;
} brix_win_event_buffer_t;

/*
 * Filesystem watcher context for Windows (ReadDirectoryChangesW-based)
 */
struct brix_plat_fs_watcher {
    brix_win_watch_desc_t *watches; /* Linked list of watch descriptors */
    int next_wd;                     /* Next watch descriptor ID */
    int event_count;                 /* Number of active watches */
    HANDLE completion_port;          /* IOCP handle (future optimization) */
};

/* ==========================================================================
 * EVENT MAPPING: Windows FILE_ACTION_* to BRIX_FS_EVENT_*
 * ========================================================================== */

/*
 * Map Windows FILE_ACTION_* constants to PAL BRIX_FS_EVENT_* constants
 * 
 * Windows → PAL mapping:
 *   FILE_ACTION_ADDED             → BRIX_FS_EVENT_CREATE
 *   FILE_ACTION_REMOVED           → BRIX_FS_EVENT_DELETE
 *   FILE_ACTION_MODIFIED          → BRIX_FS_EVENT_WRITE
 *   FILE_ACTION_RENAMED_OLD_NAME  → BRIX_FS_EVENT_RENAME (from)
 *   FILE_ACTION_RENAMED_NEW_NAME  → BRIX_FS_EVENT_RENAME (to)
 * 
 * Limitations vs inotify/kqueue:
 *   - No direct equivalent to IN_ATTRIB (attribute changes)
 *   - No IN_MOVED_FROM/IN_MOVED_TO pairing (just rename events)
 *   - No IN_CLOSE_WRITE/IN_CLOSE_NOWRITE
 *   - No IN_ACCESS (read access tracking)
 *   - No IN_DELETE_SELF/IN_MOVE_SELF (self-deletion/movement)
 *   - Buffer overflow can lose events (inotify has cookie for pairing)
 */

static uint32_t
brix_win_map_file_action_to_pal(DWORD action)
{
    switch (action) {
        case FILE_ACTION_ADDED:
            return BRIX_FS_EVENT_CREATE;
        
        case FILE_ACTION_REMOVED:
            return BRIX_FS_EVENT_DELETE;
        
        case FILE_ACTION_MODIFIED:
            return BRIX_FS_EVENT_WRITE;
        
        case FILE_ACTION_RENAMED_OLD_NAME:
        case FILE_ACTION_RENAMED_NEW_NAME:
            return BRIX_FS_EVENT_RENAME;
        
        default:
            /* Unknown action - treat as attribute change */
            return BRIX_FS_EVENT_ATTRIB;
    }
}

/*
 * Map PAL BRIX_FS_EVENT_* to Windows FILE_NOTIFY_FILTER_*
 * 
 * Note: Windows uses filters for what to watch, not events that occurred
 */
static DWORD
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
    brix_win_normalize_path(normalized_path);
    
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

int
brix_plat_fs_watcher_next(brix_plat_fs_watcher_t *watcher,
                          brix_plat_fs_event_t *event, int timeout_ms)
{
    /*
     * Get next filesystem event
     * 
     * Implementation:
     * 1. Poll all watches for completed I/O
     * 2. Parse FILE_NOTIFY_INFORMATION structures
     * 3. Map to PAL event format
     * 4. Re-arm watches for continued monitoring
     * 
     * Limitations vs inotify/kqueue:
     * - Polling required (no single event fd)
     * - Buffer overflow can lose events
     * - No cookie for rename pairing
     * - More complex path handling
     */
    brix_win_watch_desc_t *wdesc;
    DWORD wait_result;
    DWORD timeout_win;
    HANDLE *handles;
    int num_handles;
    int i;
    
    if (watcher == NULL || event == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    if (watcher->watches == NULL) {
        errno = EBADF;
        return -1;
    }
    
    /* Convert timeout to Windows format */
    if (timeout_ms < 0) {
        timeout_win = INFINITE;
    } else {
        timeout_win = (DWORD)timeout_ms;
    }
    
    /* Build array of event handles to wait on */
    num_handles = watcher->event_count;
    if (num_handles == 0) {
        errno = EBADF;
        return -1;
    }
    
    handles = (HANDLE *)malloc(num_handles * sizeof(HANDLE));
    if (handles == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    /* Collect all event handles from watches */
    wdesc = watcher->watches;
    for (i = 0; i < num_handles && wdesc != NULL; i++, wdesc = wdesc->next) {
        handles[i] = wdesc->overlapped.hEvent;
    }
    
    /* Wait for any event to complete */
    wait_result = WaitForMultipleObjects(num_handles, handles, FALSE, timeout_win);
    free(handles);
    
    if (wait_result == WAIT_TIMEOUT) {
        errno = EAGAIN;
        return -1;
    }
    
    if (wait_result == WAIT_FAILED) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Find which watch completed */
    int watch_index = wait_result - WAIT_OBJECT_0;
    wdesc = watcher->watches;
    for (i = 0; i < watch_index && wdesc != NULL; i++, wdesc = wdesc->next) {
        /* skip */
    }
    
    if (wdesc == NULL) {
        errno = EBADF;
        return -1;
    }
    
    /* Get result of ReadDirectoryChangesW */
    if (!GetOverlappedResult(wdesc->dir_handle, &wdesc->overlapped, 
                             &wdesc->overlapped.Internal, FALSE)) {
        DWORD error = GetLastError();
        if (error == ERROR_OPERATION_ABORTED) {
            /* Watch was removed */
            errno = EBADF;
            return -1;
        }
        /* Other error */
        brix_win32_set_errno(error);
        return -1;
    }
    
    /* Parse FILE_NOTIFY_INFORMATION structures */
    /* Note: Buffer is in overlapped.Pointer */
    BYTE *buffer = (BYTE *)wdesc->overlapped.Pointer;
    FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buffer;
    
    /* Extract event information */
    event->cookie = 0;  /* Windows doesn't provide cookies like inotify */
    event->timestamp = 0;  /* Would need GetFileTime for timestamp */
    
    /* Map filename (UTF-16 to UTF-8) */
    if (fni->FileNameLength > 0 && fni->FileNameLength < sizeof(event->path)) {
        /* Simple conversion (assumes ASCII - proper implementation needs WideCharToMultiByte) */
        for (DWORD j = 0; j < fni->FileNameLength / sizeof(WCHAR) && j < sizeof(event->path) - 1; j++) {
            event->path[j] = (char)fni->FileName[j];
        }
        event->path[fni->FileNameLength / sizeof(WCHAR)] = '\0';
    } else {
        event->path[0] = '\0';
    }
    
    /* Prepend watched directory path */
    /* Note: Full path construction would require combining wdesc->path + event->path */
    
    /* Map Windows action to PAL event type */
    event->events = brix_win_map_file_action_to_pal(fni->Action);
    
    /* Re-arm the watch for continued monitoring */
    ResetEvent(wdesc->overlapped.hEvent);
    memset(&wdesc->overlapped, 0, sizeof(OVERLAPPED));
    wdesc->overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    
    DWORD notify_filter = brix_win_map_pal_to_notify_filter(wdesc->events);
    ReadDirectoryChangesW(
        wdesc->dir_handle,
        wdesc->overlapped.Pointer,
        BRIX_WIN_EVENT_BUFFER_SIZE,
        FALSE,
        notify_filter,
        NULL,
        &wdesc->overlapped,
        NULL
    );
    
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
