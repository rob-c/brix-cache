/*
 * cpu_topology_test.c - Standalone test for Apple Silicon CPU detection
 * 
 * Compile and run independently to verify CPU detection:
 *   clang -o cpu_topology_test cpu_topology_test.c
 *   ./cpu_topology_test
 * 
 * This is a standalone test - not part of the nginx build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

/* ==========================================================================
 * STANDALONE IMPLEMENTATION (no nginx dependencies)
 * ========================================================================== */

static int
get_perf_cores(void)
{
    int count = 0;
    size_t len = sizeof(count);
    
    if (sysctlbyname("hw.perflevel0.physicalcpu", &count, &len, NULL, 0) == 0) {
        return count;
    }
    
    /* Fallback: Intel Mac or error */
    len = sizeof(count);
    if (sysctlbyname("hw.ncpu", &count, &len, NULL, 0) == 0) {
        return count;
    }
    
    return -1;
}

static int
get_eff_cores(void)
{
    int count = 0;
    size_t len = sizeof(count);
    
    if (sysctlbyname("hw.perflevel1.physicalcpu", &count, &len, NULL, 0) == 0) {
        return count;
    }
    
    /* No efficiency cores */
    return 0;
}

static int
get_total_cores(void)
{
    int count = 0;
    size_t len = sizeof(count);
    
    if (sysctlbyname("hw.ncpu", &count, &len, NULL, 0) == 0) {
        return count;
    }
    
    return -1;
}

static int
get_brand_string(char *buf, size_t size)
{
    size_t len = size;
    
    if (sysctlbyname("machdep.cpu.brand_string", buf, &len, NULL, 0) == 0) {
        buf[len] = '\0';
        return 0;
    }
    
    strncpy(buf, "Unknown", size);
    return -1;
}

static int
is_apple_silicon(void)
{
#if defined(__arm64__) || defined(__aarch64__)
    return 1;
#else
    return 0;
#endif
}

static void
parse_chip_model(const char *brand, char *model, size_t size)
{
    const char *m_pos = strstr(brand, "Apple M");
    
    if (m_pos == NULL) {
        strncpy(model, brand, size - 1);
        model[size - 1] = '\0';
        return;
    }
    
    /* Skip "Apple " */
    m_pos += 6;
    
    /* Copy until space or end */
    size_t i = 0;
    while (i < size - 1 && m_pos[i] != '\0' && m_pos[i] != ' ') {
        model[i] = m_pos[i];
        i++;
    }
    model[i] = '\0';
}

static int
get_generation(const char *model)
{
    const char *m = strchr(model, 'M');
    if (m == NULL) return 0;
    return atoi(m + 1);
}

/* ==========================================================================
 * MAIN TEST PROGRAM
 * ========================================================================== */

int main(void)
{
    int perf_cores, eff_cores, total_cores;
    char brand[256], chip_model[64];
    int generation, is_as;
    const char *placement;
    
    printf("=== Apple Silicon CPU Topology Detection ===\n\n");
    
    /* Get basic info */
    is_as = is_apple_silicon();
    total_cores = get_total_cores();
    perf_cores = get_perf_cores();
    eff_cores = get_eff_cores();
    
    printf("Platform: %s\n", is_as ? "Apple Silicon (ARM64)" : "Intel (x86_64)");
    printf("Brand String: ");
    if (get_brand_string(brand, sizeof(brand)) == 0) {
        printf("%s\n", brand);
    } else {
        printf("Unknown\n");
    }
    
    /* Parse chip model */
    parse_chip_model(brand, chip_model, sizeof(chip_model));
    generation = get_generation(chip_model);
    
    printf("\n=== Chip Identification ===\n");
    printf("Chip Model: %s\n", chip_model[0] != '\0' ? chip_model : "Intel/Unknown");
    printf("Generation: M%d\n", generation > 0 ? generation : 0);
    
    printf("\n=== CPU Topology ===\n");
    printf("Total Cores: %d\n", total_cores);
    printf("Performance Cores (Firestorm): %d\n", perf_cores);
    printf("Efficiency Cores (Icestorm): %d\n", eff_cores);
    
    if (eff_cores > 0 && perf_cores > 0) {
        printf("Topology: big.LITTLE (mixed)\n");
    } else {
        printf("Topology: Uniform (all cores equal)\n");
    }
    
    printf("\n=== Worker Placement Strategy ===\n");
    
    if (eff_cores <= 0 || perf_cores <= 0) {
        placement = "Strategy 1: Use all cores equally";
        printf("%s\n", placement);
        printf("  - All workers can run on any core\n");
        printf("  - No special placement needed\n");
    } else {
        placement = "Strategy 2: Mixed placement (recommended)";
        printf("%s\n", placement);
        printf("  - HIGH-PRIORITY workers → Performance cores:\n");
        printf("    * SSL/TLS handshake workers\n");
        printf("    * Cache fill operations\n");
        printf("    * Origin fetch workers\n");
        printf("    * Client response writers\n");
        printf("  \n");
        printf("  - BACKGROUND workers → Efficiency cores:\n");
        printf("    * Log file flush\n");
        printf("    * Metrics collection\n");
        printf("    * Cache eviction candidates\n");
        printf("    * Periodic cleanup tasks\n");
    }
    
    printf("\n=== Cache Configuration Recommendations ===\n");
    
    if (generation >= 3) {
        printf("M3 Series detected:\n");
        if (strstr(chip_model, "Max")) {
            printf("  - L2 Cache: 144MB (large)\n");
            printf("  - Recommendation: Increase cache block size to 256KB\n");
        } else if (strstr(chip_model, "Pro")) {
            printf("  - L2 Cache: 36MB (medium)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        } else {
            printf("  - L2 Cache: 16MB (base)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        }
    } else if (generation == 2) {
        printf("M2 Series detected:\n");
        if (strstr(chip_model, "Max")) {
            printf("  - L2 Cache: 96MB (large)\n");
            printf("  - Recommendation: Increase cache block size to 128KB\n");
        } else if (strstr(chip_model, "Pro")) {
            printf("  - L2 Cache: 36MB (medium)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        } else {
            printf("  - L2 Cache: 16MB (base)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        }
    } else if (generation == 1) {
        printf("M1 Series detected:\n");
        if (strstr(chip_model, "Ultra") || strstr(chip_model, "Max")) {
            printf("  - L2 Cache: 48MB (large)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        } else if (strstr(chip_model, "Pro")) {
            printf("  - L2 Cache: 24MB (medium)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        } else {
            printf("  - L2 Cache: 12MB (base)\n");
            printf("  - Recommendation: Standard cache block size (64KB)\n");
        }
    } else {
        printf("Intel Mac or unknown chip\n");
        printf("  - Recommendation: Use default cache configuration\n");
    }
    
    printf("\n=== Feature Detection ===\n");
    printf("NEON SIMD: %s (always available on ARM64)\n", is_as ? "Yes" : "N/A");
    printf("ARM Crypto Extensions: %s\n", (is_as && generation >= 1) ? "Yes" : "N/A");
    printf("CRC32 Instructions: %s\n", (is_as && generation >= 1) ? "Yes" : "N/A");
    
    printf("\n=== Example Code Usage ===\n");
    printf("/* In nginx worker initialization: */\n");
    printf("int strategy = brix_plat_worker_placement_strategy();\n");
    printf("if (strategy == 2) {\n");
    printf("    // Mixed topology - use affinity APIs\n");
    printf("    if (is_high_priority_worker) {\n");
    printf("        thread_bind_to_perf_cores();\n");
    printf("    } else {\n");
    printf("        thread_bind_to_eff_cores();\n");
    printf("    }\n");
    printf("}\n");
    
    printf("\n=== Detection Complete ===\n");
    
    return 0;
}
