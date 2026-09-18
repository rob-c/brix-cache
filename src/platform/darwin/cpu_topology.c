/*
 * src/platform/darwin/cpu_topology.c - Apple Silicon CPU topology detection
 * 
 * Detects performance (firestorm) and efficiency (icestorm) cores on Apple Silicon.
 * Provides CPU model identification for M1/M2/M3 series chips.
 * 
 * Usage:
 *   - Worker placement: Pin high-priority workers to performance cores
 *   - Cache sizing: Adjust based on chip capabilities
 *   - Optimization selection: Enable chip-specific code paths
 * 
 * References:
 *   - Apple Silicon Technical Overview
 *   - sysctlbyname() documentation
 *   - machdep.cpu brand string format
 */

#include "../platform.h"

#if BRIX_PLATFORM_DARWIN

#include "../platform_api.h"
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>   /* atoi */
#include <string.h>
#include <ctype.h>
#include "cpu_cache.h"
#include "sysctl_value.h"

/* ==========================================================================
 * INTERNAL TYPES
 * ========================================================================== */

typedef struct {
    int perf_cores;           /* Number of performance cores (firestorm) */
    int eff_cores;            /* Number of efficiency cores (icestorm) */
    int total_cores;          /* Total CPU cores */
    int l1d_cache_size;       /* L1 data cache size in KB */
    int l2_cache_size;        /* L2 cache size in KB */
    char chip_model[64];      /* M1, M1 Pro, M2, M3, etc. */
    int generation;           /* 1=M1, 2=M2, 3=M3, etc. */
    int has_neon;             /* NEON SIMD support (always yes on ARM64) */
    int has_crypto;           /* ARM crypto extensions */
    int has_crc32;            /* CRC32 instructions */
} brix_apple_cpu_info_t;

/* ==========================================================================
 * CHIP MODEL DETECTION
 * ========================================================================== */

/*
 * Parse the machdep.cpu.brand_string to extract chip model
 * 
 * Examples:
 *   "Apple M1"
 *   "Apple M1 Pro"
 *   "Apple M1 Max"
 *   "Apple M1 Ultra"
 *   "Apple M2"
 *   "Apple M2 Pro"
 *   "Apple M2 Max"
 *   "Apple M3"
 *   "Apple M3 Pro"
 *   "Apple M3 Max"
 */
static int
parse_chip_model(const char *brand_string, char *chip_model, size_t model_size)
{
    const char *m_pos;
    const char *space_pos;
    size_t len;
    
    if (brand_string == NULL || chip_model == NULL) {
        return -1;
    }
    
    /* Look for "Apple M" prefix */
    m_pos = strstr(brand_string, "Apple M");
    if (m_pos == NULL) {
        /* Fallback: just use the brand string */
        strncpy(chip_model, brand_string, model_size - 1);
        chip_model[model_size - 1] = '\0';
        return 0;
    }
    
    /* Skip "Apple " prefix */
    m_pos += 6;
    
    /* Find end of model string (space or end of string) */
    space_pos = strchr(m_pos, ' ');
    if (space_pos != NULL) {
        len = space_pos - m_pos;
    } else {
        len = strlen(m_pos);
    }
    
    /* Copy model string (e.g., "M1", "M2 Pro", "M3 Max") */
    if (len >= model_size) {
        len = model_size - 1;
    }
    
    strncpy(chip_model, m_pos, len);
    chip_model[len] = '\0';
    
    return 0;
}

/*
 * Extract generation number from chip model
 * M1 -> 1, M2 -> 2, M3 -> 3, etc.
 */
static int
extract_generation(const char *chip_model)
{
    const char *m_pos;
    int gen;
    
    if (chip_model == NULL) {
        return 0;
    }
    
    m_pos = strchr(chip_model, 'M');
    if (m_pos == NULL) {
        return 0;
    }
    
    /* Parse digit after 'M' */
    gen = atoi(m_pos + 1);
    
    return gen;
}

/*
 * Determine cache sizes based on chip model
 * Apple Silicon cache configurations (approximate)
 */
static void
determine_cache_sizes(brix_apple_cpu_info_t *info)
{
    /*
     * Apple Silicon cache configurations (per core unless noted):
     * 
     * M1:
     *   - Firestorm: 192KB L1I, 128KB L1D, 12MB shared L2
     *   - Icestorm:  128KB L1I, 64KB L1D, 4MB shared L2
     * 
     * M1 Pro/Max:
     *   - Firestorm: 192KB L1I, 128KB L1D, 24MB/48MB shared L2
     *   - Icestorm:  128KB L1I, 64KB L1D
     * 
     * M2:
     *   - Firestorm: 192KB L1I, 128KB L1D, 16MB shared L2
     *   - Icestorm:  128KB L1I, 64KB L1D
     * 
     * M2 Pro/Max:
     *   - Firestorm: 192KB L1I, 128KB L1D, 36MB/96MB shared L2
     * 
     * M3:
     *   - Firestorm: 192KB L1I, 128KB L1D, 16MB shared L2
     *   - Icestorm:  128KB L1I, 64KB L1D
     * 
     * M3 Pro/Max:
     *   - Firestorm: 192KB L1I, 128KB L1D, 36MB/144MB shared L2
     */
    
    info->l1d_cache_size = 128;
    info->l2_cache_size = brix_apple_l2_cache_mb(info->generation,
                                               info->chip_model) * 1024;
}

/* ==========================================================================
 * PUBLIC API IMPLEMENTATIONS
 * ========================================================================== */

/**
 * Get number of performance cores (firestorm)
 * 
 * @return Number of performance cores, or -1 on error
 * 
 * Usage: Pin high-priority workers (SSL, cache fill) to performance cores
 */
int
brix_plat_cpu_count_performance(void)
{
    int count = 0;
    
    if (brix_darwin_sysctl_read_int("hw.perflevel0.physicalcpu", &count) == 0) {
        return count;
    }
    
    /* Fallback: assume all cores are performance cores (Intel Macs) */
    return brix_plat_cpu_count();
}

/**
 * Get number of efficiency cores (icestorm)
 * 
 * @return Number of efficiency cores, or 0 if none (Intel or Apple Silicon without eff cores)
 * 
 * Usage: Pin background workers (log flush, metrics, cache eviction) to efficiency cores
 */
int
brix_plat_cpu_count_efficiency(void)
{
    return brix_darwin_sysctl_int("hw.perflevel1.physicalcpu", 0);
}

/**
 * Get detailed CPU information including chip model
 * 
 * @param info Output structure (must be allocated by caller)
 * @return 0 on success, -1 on error
 * 
 * Usage: Determine chip capabilities for optimization selection
 */
int
brix_plat_cpu_info(brix_apple_cpu_info_t *info)
{
    size_t len;
    char brand_string[256];
    
    if (info == NULL) {
        return -1;
    }
    
    memset(info, 0, sizeof(*info));
    
    /* Get total CPU count */
    info->total_cores = brix_plat_cpu_count();
    if (info->total_cores < 0) {
        return -1;
    }
    
    /* Get performance cores */
    info->perf_cores = brix_plat_cpu_count_performance();
    if (info->perf_cores < 0) {
        info->perf_cores = info->total_cores;
    }
    
    /* Get efficiency cores */
    info->eff_cores = brix_plat_cpu_count_efficiency();
    if (info->eff_cores < 0) {
        info->eff_cores = 0;
    }
    
    /* Get brand string */
    len = sizeof(brand_string);
    if (sysctlbyname("machdep.cpu.brand_string", brand_string, &len, NULL, 0) != 0) {
        strncpy(brand_string, "Unknown", sizeof(brand_string));
    }
    brand_string[sizeof(brand_string) - 1] = '\0';
    
    /* Parse chip model */
    if (parse_chip_model(brand_string, info->chip_model, sizeof(info->chip_model)) < 0) {
        strncpy(info->chip_model, "Unknown", sizeof(info->chip_model));
    }
    
    /* Extract generation */
    info->generation = extract_generation(info->chip_model);
    
    /* Determine cache sizes */
    determine_cache_sizes(info);
    
    /* Feature detection (ARM64 always has NEON) */
    info->has_neon = 1;
    
    /* Check for crypto extensions (ARMv8.0+) */
    info->has_crypto = (info->generation >= 1) ? 1 : 0;
    
    /* Check for CRC32 extensions (ARMv8.1+) */
    info->has_crc32 = (info->generation >= 1) ? 1 : 0;
    
    return 0;
}

/**
 * Get chip model string
 * 
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return 0 on success, -1 on error
 * 
 * Usage: Logging, diagnostics, optimization selection
 */
int
brix_plat_chip_model(char *buf, size_t buf_size)
{
    brix_apple_cpu_info_t info;
    
    if (buf == NULL || buf_size == 0) {
        return -1;
    }
    
    if (brix_plat_cpu_info(&info) < 0) {
        strncpy(buf, "Unknown", buf_size);
        return -1;
    }
    
    strncpy(buf, info.chip_model, buf_size - 1);
    buf[buf_size - 1] = '\0';
    
    return 0;
}

/**
 * Check if running on Apple Silicon
 * 
 * @return 1 if Apple Silicon (ARM64), 0 if Intel (x86_64)
 * 
 * Usage: Conditional code paths for Apple Silicon optimizations
 */
int
brix_plat_is_apple_silicon(void)
{
#if defined(__arm64__) || defined(__aarch64__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Get recommended worker placement strategy
 * 
 * @return Strategy code:
 *   1 = All performance cores (no efficiency cores)
 *   2 = Mixed: perf for workers, eff for background
 *   0 = Unknown/error
 * 
 * Usage: Determine optimal worker thread placement
 */
int
brix_plat_worker_placement_strategy(void)
{
    int perf_cores, eff_cores;
    
    perf_cores = brix_plat_cpu_count_performance();
    eff_cores = brix_plat_cpu_count_efficiency();
    
    if (perf_cores < 0) {
        return 0;
    }
    
    if (eff_cores <= 0) {
        /* No efficiency cores: use all cores equally */
        return 1;
    }
    
    /* Mixed topology: perf for workers, eff for background */
    return 2;
}

/**
 * Print CPU topology information (for debugging/logging)
 * 
 * Usage: Call at startup to log detected hardware
 */
void
brix_plat_cpu_topology_print(void)
{
    brix_apple_cpu_info_t info;
    const char *placement_str;
    int strategy;
    
    if (brix_plat_cpu_info(&info) < 0) {
        fprintf(stderr, "[BRIX PAL] Failed to get CPU info\n");
        return;
    }
    
    strategy = brix_plat_worker_placement_strategy();
    
    switch (strategy) {
        case 1:
            placement_str = "All cores equal (no big.LITTLE)";
            break;
        case 2:
            placement_str = "Mixed: perf cores for workers, eff cores for background";
            break;
        default:
            placement_str = "Unknown";
            break;
    }
    
    fprintf(stderr, "[BRIX PAL] CPU Topology:\n");
    fprintf(stderr, "  Chip: Apple %s (Gen %d)\n", info.chip_model, info.generation);
    fprintf(stderr, "  Total cores: %d\n", info.total_cores);
    fprintf(stderr, "  Performance cores (firestorm): %d\n", info.perf_cores);
    fprintf(stderr, "  Efficiency cores (icestorm): %d\n", info.eff_cores);
    fprintf(stderr, "  L1D cache (per perf core): %d KB\n", info.l1d_cache_size);
    fprintf(stderr, "  L2 cache (shared): %d MB\n", info.l2_cache_size / 1024);
    fprintf(stderr, "  Features: NEON=%d, Crypto=%d, CRC32=%d\n",
            info.has_neon, info.has_crypto, info.has_crc32);
    fprintf(stderr, "  Worker placement: %s\n", placement_str);
}

#endif /* BRIX_PLATFORM_DARWIN */
