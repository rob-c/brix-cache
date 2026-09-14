/* Windows watch completion polling and PAL event decoding.
 * Watch lifetime and list mutation remain in fs_watcher.c.
 */
#include "fs_watcher_internal.h"
#if BRIX_PLATFORM_WINDOWS
#include <errno.h>
#include <stdlib.h>
#include <string.h>
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

/* ---- Decode the current Windows notification filename ----
 * WHAT: Fill the PAL path using the existing notification name conversion.
 * WHY: Keep buffer decoding separate from wait and watch rearming.
 * HOW: 1. Validate the recorded length. 2. Copy name bytes and terminate.
 */
static void
brix_win_watch_event_name(brix_plat_fs_event_t *event,
                         const FILE_NOTIFY_INFORMATION *fni)
{
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

}

/* ---- Find the watch selected by WaitForMultipleObjects ----
 * WHAT: Return the indexed descriptor or NULL if the list ended early.
 * WHY: Completion indexing is separate from waiting and event decoding.
 * HOW: 1. Start at the watch-list head. 2. Advance by the reported index.
 */
static brix_win_watch_desc_t *
brix_win_completed_watch(brix_win_watch_desc_t *head, int watch_index)
{
    brix_win_watch_desc_t *descriptor = head;
    for (int index = 0; index < watch_index && descriptor != NULL; index++) {
        descriptor = descriptor->next;
    }
    return descriptor;
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
    DWORD bytes_returned;

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
    wdesc = brix_win_completed_watch(watcher->watches, watch_index);

    if (wdesc == NULL) {
        errno = EBADF;
        return -1;
    }

    /* Get result of ReadDirectoryChangesW */
    if (!GetOverlappedResult(wdesc->dir_handle, &wdesc->overlapped,
                             &bytes_returned, FALSE)) {
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

    brix_win_watch_event_name(event, fni);

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

#endif /* BRIX_PLATFORM_WINDOWS */
