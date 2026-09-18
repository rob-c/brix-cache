/* Windows version information.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#ifndef BRIX_PLATFORM_WINDOWS_HOST_API_H
#define BRIX_PLATFORM_WINDOWS_HOST_API_H

#include "win32_compat.h"

/* ==========================================================================
 * WINDOWS PLATFORM DETECTION (Windows only)
 * ========================================================================== */


/**
 * Check if running on Windows
 * @return 1 if Windows, 0 otherwise
 */
int brix_plat_is_windows(void);

/**
 * Get Windows version string
 * @return Version string (e.g., "Windows 11 (22H2) (Build 22621)")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_version(void);

/**
 * Get Windows build number
 * @return Build number (e.g., 22621)
 */
unsigned long brix_plat_windows_build(void);

/**
 * Get Windows version components
 * @param major Output: Major version
 * @param minor Output: Minor version
 * @param build Output: Build number
 * @return 0 on success, -1 on failure
 */
int brix_plat_windows_version_info(unsigned long *major,
                                   unsigned long *minor,
                                   unsigned long *build);

/**
 * Check if running on Windows Server
 * @return 1 if Server, 0 if client
 */
int brix_plat_is_windows_server(void);

/**
 * Get Windows service pack string
 * @return Service pack string (e.g., "Service Pack 1", "None")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_service_pack(void);

/**
 * Get Windows edition from registry
 * @return Edition string (e.g., "Professional", "Datacenter")
 *         Static buffer, do not free
 */
const char *brix_plat_windows_edition(void);

/**
 * Check if Windows version meets minimum requirements
 * @param min_major Minimum major version
 * @param min_minor Minimum minor version
 * @param min_build Minimum build number
 * @return 1 if meets requirements, 0 otherwise
 */
int brix_plat_windows_version_at_least(unsigned long min_major,
                                       unsigned long min_minor,
                                       unsigned long min_build);

/* --- event and Winsock readiness entry points (event_wrapper.c, socket_event.c) --- */

/**
 * Initialize Windows event subsystem (IOCP)
 *
 * Phase 1: No-op (uses WaitForMultipleObjects)
 * Phase 2: Create IOCP for scalable event handling
 *
 * @return 0 on success, -1 on error
 */
int brix_plat_event_init(void);

/**
 * Wait for Windows event
 *
 * Phase 1: WaitForMultipleObjects (limited to 64 handles)
 * Phase 2: GetQueuedCompletionStatus (IOCP, scalable)
 *
 * @param efd Event fd/handle
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return 0 on event, -1 on timeout/error
 */
int brix_plat_event_wait(int efd, int timeout_ms);

/**
 * Create Windows socket event monitor
 *
 * Uses WSAEventSelect to associate socket with event object.
 * Maps PAL events to WSA network events:
 * - BRIX_EVENT_READ → FD_READ | FD_ACCEPT | FD_CLOSE
 * - BRIX_EVENT_WRITE → FD_WRITE | FD_CONNECT
 *
 * @param sock Socket to monitor (SOCKET type)
 * @param events Event mask (BRIX_EVENT_*)
 * @return Event handle, or -1 on error
 */
int brix_plat_socket_event_create(SOCKET sock, uint32_t events);

/**
 * Wait for Windows socket event
 *
 * @param event_handle Event handle from brix_plat_socket_event_create()
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return 0 on event, -1 on timeout/error
 */
int brix_plat_socket_event_wait(int event_handle, int timeout_ms);

/**
 * Destroy Windows socket event
 *
 * @param event_handle Event handle to destroy
 */
void brix_plat_socket_event_destroy(int event_handle);


#endif /* BRIX_PLATFORM_WINDOWS_HOST_API_H */
