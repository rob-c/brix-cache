/* src/platform/darwin/host_api.h - Apple Silicon extensions (macOS ARM64 only).
 * Reached through platform/platform_api.h; never included directly. */
#ifndef BRIX_PLATFORM_DARWIN_HOST_API_H
#define BRIX_PLATFORM_DARWIN_HOST_API_H

/* ==========================================================================
 * DARWIN / APPLE SILICON APIs (macOS ARM64 only)
 * ========================================================================== */

#if BRIX_ARCH_ARM64

/* ==========================================================================
 * APPLE SILICON CHIP DETECTION
 * ========================================================================== */

/**
 * Detect Apple Silicon chip type
 *
 * Populates internal state with chip model (M1/M2/M3 series) and core counts.
 * Called automatically by brix_apple_init().
 *
 * @return void
 *
 * Usage: Called once at initialization for chip detection
 */
void brix_apple_detect_chip(void);

/**
 * Get Apple Silicon chip name
 * @return Chip name string (e.g., "M1", "M2 Pro", "M3 Max")
 *         Static buffer, do not free
 *
 * Usage: Logging, diagnostics, optimization selection
 */
const char *brix_apple_get_chip_name(void);

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or 0 if unavailable
 *
 * Usage: Pin high-priority workers to performance cores
 */
int brix_apple_get_perf_cores(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if unavailable
 *
 * Usage: Pin background workers to efficiency cores
 */
int brix_apple_get_eff_cores(void);

/* ==========================================================================
 * CPU TOPOLOGY APIs
 * ========================================================================== */

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or fallback to total cores
 *
 * Usage: Pin high-priority workers (SSL, cache fill) to performance cores
 */
int brix_plat_cpu_count_performance(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if none (Intel or Apple Silicon without eff cores)
 *
 * Usage: Pin background workers (log flush, metrics, cache eviction) to efficiency cores
 */
int brix_plat_cpu_count_efficiency(void);

/**
 * Get detailed CPU information including chip model
 *
 * Note: brix_apple_cpu_info_t is defined in cpu_topology.c
 * For public API, use brix_apple_get_chip_name() and core count functions.
 *
 * @param info Output structure (must be allocated by caller)
 * @return 0 on success, -1 on error
 *
 * Usage: Determine chip capabilities for optimization selection
 */
int brix_plat_cpu_info(void *info);

/**
 * Get chip model string
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return 0 on success, -1 on error
 *
 * Usage: Logging, diagnostics, optimization selection
 */
int brix_plat_chip_model(char *buf, size_t buf_size);

/**
 * Check if running on Apple Silicon
 * @return 1 if Apple Silicon (ARM64), 0 if Intel (x86_64)
 *
 * Usage: Conditional code paths for Apple Silicon optimizations
 */
int brix_plat_is_apple_silicon(void);

/**
 * Get recommended worker placement strategy
 * @return Strategy code:
 *   1 = All performance cores (no efficiency cores)
 *   2 = Mixed: perf for workers, eff for background
 *   0 = Unknown/error
 *
 * Usage: Determine optimal worker thread placement
 */
int brix_plat_worker_placement_strategy(void);

/**
 * Print CPU topology information (for debugging/logging)
 *
 * Usage: Call at startup to log detected hardware
 */
void brix_plat_cpu_topology_print(void);

/* ==========================================================================
 * APFS CLONEFILE OPTIMIZATION
 * ========================================================================== */

/**
 * Get Apple Silicon chip name
 * @return Chip name string (e.g., "M1", "M2 Pro", "M3 Max")
 *         Static buffer, do not free
 *
 * Usage: Logging, diagnostics, optimization selection
 */
const char *brix_apple_get_chip_name(void);

/**
 * Get number of performance cores (firestorm)
 * @return Number of performance cores, or 0 if unavailable
 *
 * Usage: Pin high-priority workers to performance cores
 */
int brix_apple_get_perf_cores(void);

/**
 * Get number of efficiency cores (icestorm)
 * @return Number of efficiency cores, or 0 if unavailable
 *
 * Usage: Pin background workers to efficiency cores
 */
int brix_apple_get_eff_cores(void);

/**
 * APFS clonefile - Copy-on-write file clone
 *
 * Creates an instantaneous metadata-only clone of a file on APFS.
 * Extremely fast (~100x faster than copy for large files).
 *
 * @param src Source file path
 * @param dst Destination file path
 * @param flags Clone flags (currently unused, pass 0)
 * @return 0 on success, -1 on error (errno set)
 *
 * Availability: macOS 10.12+ (Sierra)
 * Performance: ~100x faster than copy for large files
 *
 * Usage: Fast file copies, snapshots, backup operations
 */
int brix_apple_clonefile(const char *src, const char *dst, int flags);

/**
 * APFS clonefileat - Relative path version
 *
 * @param src_dirfd Source directory file descriptor
 * @param src Source file path (relative to src_dirfd)
 * @param dst_dirfd Destination directory file descriptor
 * @param dst Destination file path (relative to dst_dirfd)
 * @param flags Clone flags (currently unused, pass 0)
 * @return 0 on success, -1 on error (errno set)
 *
 * Usage: Clone files within directory trees
 */
int brix_apple_clonefileat(int src_dirfd, const char *src,
                           int dst_dirfd, const char *dst, int flags);

/**
 * Allocate aligned memory for cache efficiency
 *
 * Allocates memory aligned to 128-byte cache line boundary
 * for optimal L1 cache performance on Apple Silicon.
 *
 * @param size Size in bytes
 * @return Aligned pointer, or NULL on failure
 *
 * Usage: Allocate buffers for SIMD operations, cache structures
 */
void *brix_apple_aligned_alloc(size_t size);

/**
 * Apple Silicon performance statistics
 */
typedef struct {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t cache_misses;
    uint64_t branch_misses;
} brix_apple_perf_stats_t;

/**
 * Start performance monitoring
 * @return 0 on success, -1 on error
 *
 * Note: Requires entitlements on macOS, currently no-op
 */
int brix_apple_perf_start(void);

/**
 * Read performance counters
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 *
 * Note: Limited implementation due to macOS restrictions
 */
int brix_apple_perf_read(brix_apple_perf_stats_t *stats);

/**
 * Stop performance monitoring
 * @return 0 on success, -1 on error
 */
int brix_apple_perf_stop(void);

/**
 * Initialize Apple Silicon optimizations
 *
 * Called once at module initialization.
 * Detects chip type and core counts.
 *
 * @return void
 */
void brix_apple_init(void);

/**
 * Get optimization information
 * @return Info string (static buffer, do not free)
 *
 * Format: "Apple Silicon: M1 (4 perf + 4 eff cores), Accelerate=yes, clonefile=yes"
 */
const char *brix_apple_get_optimization_info(void);

#endif /* BRIX_ARCH_ARM64 */

#endif /* BRIX_PLATFORM_DARWIN_HOST_API_H */
