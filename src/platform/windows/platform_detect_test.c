/*
 * src/platform/windows/platform_detect_test.c - Windows platform detection tests
 * 
 * Tests for Windows version detection functions.
 * Note: These tests must be run on Windows to be meaningful.
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Forward declarations from platform_detect.c */
extern int brix_plat_is_windows(void);
extern const char *brix_plat_windows_version(void);
extern unsigned long brix_plat_windows_build(void);
extern int brix_plat_windows_version_info(unsigned long *major,
                                          unsigned long *minor,
                                          unsigned long *build);
extern int brix_plat_is_windows_server(void);
extern const char *brix_plat_windows_service_pack(void);
extern const char *brix_plat_windows_edition(void);
extern int brix_plat_windows_version_at_least(unsigned long min_major,
                                              unsigned long min_minor,
                                              unsigned long min_build);

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    tests_run++; \
    printf("Running %s... ", #name); \
    test_##name(); \
    tests_passed++; \
    printf("PASSED\n"); \
} while(0)

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAILED: %s\n", msg); \
        tests_failed++; \
        tests_passed--; \
        return; \
    } \
} while(0)

/* ==========================================================================
 * TEST CASES
 * ========================================================================== */

/**
 * Test: brix_plat_is_windows()
 * Expected: Always returns 1 on Windows
 */
TEST(is_windows)
{
    int result = brix_plat_is_windows();
    ASSERT(result == 1, "Should return 1 on Windows");
    printf("(is_windows=%d)", result);
}

/**
 * Test: brix_plat_windows_version()
 * Expected: Returns non-NULL string with version info
 */
TEST(windows_version)
{
    const char *version = brix_plat_windows_version();
    ASSERT(version != NULL, "Version string should not be NULL");
    ASSERT(strlen(version) > 0, "Version string should not be empty");
    ASSERT(strstr(version, "Windows") != NULL, "Should contain 'Windows'");
    printf("(version=%s)", version);
}

/**
 * Test: brix_plat_windows_build()
 * Expected: Returns non-zero build number
 */
TEST(windows_build)
{
    unsigned long build = brix_plat_windows_build();
    ASSERT(build > 0, "Build number should be > 0");
    printf("(build=%lu)", build);
}

/**
 * Test: brix_plat_windows_version_info()
 * Expected: Returns valid version components
 */
TEST(windows_version_info)
{
    unsigned long major = 0, minor = 0, build = 0;
    int result = brix_plat_windows_version_info(&major, &minor, &build);
    
    ASSERT(result == 0, "Should return 0 on success");
    ASSERT(major > 0, "Major version should be > 0");
    ASSERT(build > 0, "Build number should be > 0");
    printf("(major=%lu, minor=%lu, build=%lu)", major, minor, build);
}

/**
 * Test: brix_plat_is_windows_server()
 * Expected: Returns 0 or 1
 */
TEST(is_windows_server)
{
    int is_server = brix_plat_is_windows_server();
    ASSERT(is_server == 0 || is_server == 1, "Should return 0 or 1");
    printf("(is_server=%d)", is_server);
}

/**
 * Test: brix_plat_windows_service_pack()
 * Expected: Returns non-NULL string
 */
TEST(windows_service_pack)
{
    const char *sp = brix_plat_windows_service_pack();
    ASSERT(sp != NULL, "Service pack string should not be NULL");
    printf("(service_pack=%s)", sp);
}

/**
 * Test: brix_plat_windows_edition()
 * Expected: Returns non-NULL string with edition info
 */
TEST(windows_edition)
{
    const char *edition = brix_plat_windows_edition();
    ASSERT(edition != NULL, "Edition string should not be NULL");
    ASSERT(strlen(edition) > 0, "Edition string should not be empty");
    printf("(edition=%s)", edition);
}

/**
 * Test: brix_plat_windows_version_at_least()
 * Expected: Correct version comparison
 */
TEST(windows_version_at_least)
{
    unsigned long major, minor, build;
    int result;
    
    /* Get current version */
    result = brix_plat_windows_version_info(&major, &minor, &build);
    ASSERT(result == 0, "Should get version info");
    
    /* Test: Should meet minimum of Windows 8 (6.2) */
    result = brix_plat_windows_version_at_least(6, 2, 0);
    ASSERT(result == 1, "Should meet Windows 8 minimum");
    
    /* Test: Should meet minimum of current version */
    result = brix_plat_windows_version_at_least(major, minor, build);
    ASSERT(result == 1, "Should meet current version minimum");
    
    /* Test: Should NOT meet minimum of impossible future version */
    result = brix_plat_windows_version_at_least(99, 0, 0);
    ASSERT(result == 0, "Should not meet impossible future version");
    
    printf("(version_check=passed)");
}

/**
 * Test: Version string contains build number
 */
TEST(version_string_format)
{
    const char *version = brix_plat_windows_version();
    unsigned long build = brix_plat_windows_build();
    char expected[64];
    
    snprintf(expected, sizeof(expected), "(Build %lu)", build);
    ASSERT(strstr(version, expected) != NULL, 
           "Version string should contain build number");
    printf("(format=valid)");
}

/**
 * Test: Caching works (multiple calls return same result)
 */
TEST(version_caching)
{
    const char *v1 = brix_plat_windows_version();
    const char *v2 = brix_plat_windows_version();
    const char *sp1 = brix_plat_windows_service_pack();
    const char *sp2 = brix_plat_windows_service_pack();
    
    ASSERT(v1 == v2, "Version string should be cached");
    ASSERT(sp1 == sp2, "Service pack string should be cached");
    printf("(caching=working)");
}

/**
 * Test: Detect Windows 10/11 vs Server
 */
TEST(version_detection_accuracy)
{
    unsigned long major, minor, build;
    int is_server;
    
    brix_plat_windows_version_info(&major, &minor, &build);
    is_server = brix_plat_is_windows_server();
    
    /* Windows 10/11 have major version 10 */
    /* Windows Server 2019/2022 also have major version 10 */
    ASSERT(major >= 6, "Major version should be >= 6");
    
    /* Build numbers should be reasonable */
    ASSERT(build >= 10240, "Build should be >= Windows 10 RTM");
    
    printf("(accuracy=valid)");
}

/* ==========================================================================
 * MAIN TEST RUNNER
 * ========================================================================== */

int
main(int argc, char *argv[])
{
    printf("============================================================\n");
    printf("Windows Platform Detection Test Suite\n");
    printf("============================================================\n\n");
    
    printf("Running %d tests...\n\n", 11);
    
    RUN_TEST(is_windows);
    RUN_TEST(windows_version);
    RUN_TEST(windows_build);
    RUN_TEST(windows_version_info);
    RUN_TEST(is_windows_server);
    RUN_TEST(windows_service_pack);
    RUN_TEST(windows_edition);
    RUN_TEST(windows_version_at_least);
    RUN_TEST(version_string_format);
    RUN_TEST(version_caching);
    RUN_TEST(version_detection_accuracy);
    
    printf("\n============================================================\n");
    printf("Test Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(" (%d failed)", tests_failed);
    }
    printf("\n============================================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}

#else

/* Stub for non-Windows platforms */
#include <stdio.h>

int
main(int argc, char *argv[])
{
    printf("Windows platform detection tests - SKIPPED (not Windows)\n");
    printf("These tests must be run on Windows.\n");
    return 0;
}

#endif /* BRIX_PLATFORM_WINDOWS */
