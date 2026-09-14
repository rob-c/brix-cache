/* Windows watch descriptors shared by lifecycle and event decoding.
 * Requires: no prior headers; native types and the PAL API are included.
 */
#pragma once
#include "../platform.h"
#if BRIX_PLATFORM_WINDOWS
#include "win32_compat.h"
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

DWORD brix_win_map_pal_to_notify_filter(uint32_t events);
#endif
