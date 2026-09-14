/* Runtime host and resource information.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * PLATFORM DETECTION & INFORMATION
 *
 * Query platform properties at runtime. All functions are thread-safe.
 * ========================================================================== */

/**
 * Get platform name
 * @return "linux", "darwin", or "windows"
 *
 * Windows: Returns "windows" for all Windows versions
 */
const char *brix_plat_name(void);

/**
 * Get platform version (kernel/OS version)
 * @return Version string (e.g., "5.15.0", "21.6.0", "10.0.20348")
 *
 * Windows: Returns NT version string (e.g., "10.0.20348" for Server 2022)
 * Retrieved via GetVersionEx() or RtlGetVersion()
 */
const char *brix_plat_version(void);

/**
 * Get CPU architecture name
 * @return "x86_64", "arm64", "aarch64", etc.
 *
 * Windows: Returns "x86_64" for AMD64, "arm64" for ARM64
 * Detected via GetNativeSystemInfo()
 */
const char *brix_plat_arch(void);

/**
 * Check if running as root/administrator
 * @return 1 if privileged, 0 otherwise
 *
 * Windows: Checks if process has Administrator privileges
 * Uses IsUserAnAdmin() or token-based check
 */
int brix_plat_is_root(void);

/**
 * Get number of online CPUs
 * @return CPU count, or -1 on error
 *
 * Windows: Uses GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
 * Supports processor groups on systems with >64 logical processors
 */
int brix_plat_cpu_count(void);

/**
 * Get total system memory in bytes
 * @return Memory size, or 0 on error
 *
 * Windows: Uses GlobalMemoryStatusEx()
 * Returns total physical RAM
 */
uint64_t brix_plat_total_memory(void);

/**
 * Get available memory in bytes
 * @return Available memory, or 0 on error
 *
 * Windows: Uses GlobalMemoryStatusEx()
 * Returns available physical RAM (not including page file)
 */
uint64_t brix_plat_available_memory(void);
