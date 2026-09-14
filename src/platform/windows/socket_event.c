/* Windows socket readiness monitoring, separate from eventfd/IOCP dispatch. */
#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
 * SOCKET EVENT HANDLING
 * ========================================================================== */

/*
 * Windows socket events use WSAEventSelect or WSAAsyncSelect
 *
 * WSAEventSelect approach:
 * 1. Create event object with WSACreateEvent
 * 2. Associate with socket using WSAEventSelect
 * 3. Wait on event with WaitForSingleObject
 * 4. Check network events with WSAEnumNetworkEvents
 *
 * This is used for socket-based event monitoring
 */

typedef struct {
    SOCKET socket;
    HANDLE event;
    long network_events;
} brix_win_socket_event_t;

int
brix_plat_socket_event_create(SOCKET sock, uint32_t events)
{
    /*
     * Create socket event monitor
     *
     * Maps PAL events to WSA network events:
     * - BRIX_EVENT_READ → FD_READ | FD_ACCEPT | FD_CLOSE
     * - BRIX_EVENT_WRITE → FD_WRITE | FD_CONNECT
     * - BRIX_EVENT_ATTRIB → N/A (sockets don't have attributes)
     */
    brix_win_socket_event_t *sev;
    long wsa_events = 0;

    if (sock == INVALID_SOCKET) {
        errno = EINVAL;
        return -1;
    }

    sev = (brix_win_socket_event_t *)calloc(1, sizeof(brix_win_socket_event_t));
    if (sev == NULL) {
        errno = ENOMEM;
        return -1;
    }

    sev->socket = sock;

    /* Create event object */
    sev->event = WSACreateEvent();
    if (sev->event == WSA_INVALID_EVENT) {
        free(sev);
        errno = ENOMEM;
        return -1;
    }

    /* Map PAL events to WSA events */
    if (events & BRIX_EVENT_READ) {
        wsa_events |= FD_READ | FD_ACCEPT | FD_CLOSE;
    }
    if (events & BRIX_EVENT_WRITE) {
        wsa_events |= FD_WRITE | FD_CONNECT;
    }

    sev->network_events = wsa_events;

    /* Associate event with socket */
    if (WSAEventSelect(sock, sev->event, wsa_events) == SOCKET_ERROR) {
        WSACloseEvent(sev->event);
        free(sev);
        errno = EINVAL;
        return -1;
    }

    return 0;  /* Return handle to caller */
}

int
brix_plat_socket_event_wait(int event_handle, int timeout_ms)
{
    /*
     * Wait for socket event
     */
    brix_win_socket_event_t *sev = (brix_win_socket_event_t *)event_handle;
    DWORD wait_result;
    DWORD timeout_win;

    if (sev == NULL || sev->event == WSA_INVALID_EVENT) {
        errno = EINVAL;
        return -1;
    }

    /* Convert timeout */
    timeout_win = (timeout_ms < 0) ? INFINITE : (DWORD)timeout_ms;

    /* Wait for event */
    wait_result = WaitForSingleObject(sev->event, timeout_win);

    if (wait_result == WAIT_OBJECT_0) {
        /* Event signaled - reset for next wait */
        WSAResetEvent(sev->event);
        return 0;
    }

    if (wait_result == WAIT_TIMEOUT) {
        errno = EAGAIN;
        return -1;
    }

    brix_win32_set_errno(GetLastError());
    return -1;
}

void
brix_plat_socket_event_destroy(int event_handle)
{
    /*
     * Destroy socket event monitor
     */
    brix_win_socket_event_t *sev = (brix_win_socket_event_t *)event_handle;

    if (sev == NULL) {
        return;
    }

    /* Dissociate event from socket */
    if (sev->socket != INVALID_SOCKET) {
        WSAEventSelect(sev->socket, NULL, 0);
    }

    /* Close event */
    if (sev->event != WSA_INVALID_EVENT) {
        WSACloseEvent(sev->event);
    }

    free(sev);
}

#endif /* BRIX_PLATFORM_WINDOWS */
