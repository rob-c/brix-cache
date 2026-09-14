/* Windows version information.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * WINDOWS PLATFORM DETECTION (Windows only)
 * ========================================================================== */

#if BRIX_PLATFORM_WINDOWS

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

#endif /* BRIX_PLATFORM_WINDOWS */
