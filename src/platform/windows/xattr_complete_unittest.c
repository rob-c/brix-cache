/*
 * xattr_complete_unittest.c - Complete test suite for Windows NTFS ADS xattr
 * 
 * Tests all 8 xattr functions:
 * - brix_plat_getxattr / brix_plat_fgetxattr
 * - brix_plat_setxattr / brix_plat_fsetxattr
 * - brix_plat_removexattr / brix_plat_fremovexattr
 * - brix_plat_listxattr / brix_plat_flistxattr
 * 
 * Compile: cl.exe xattr_complete_unittest.c /Fe:test_xattr.exe /I.. /I../../..
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>

/* Include PAL API */
#include "../platform_api.h"

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, test_name) \
    do { \
        if (condition) { \
            printf("✓ PASS: %s\n", test_name); \
            tests_passed++; \
        } else { \
            printf("✗ FAIL: %s\n", test_name); \
            tests_failed++; \
        } \
    } while(0)

/* ==========================================================================
 * TEST: Basic set/get/remove operations
 * ========================================================================== */

void test_basic_set_get_remove(void)
{
    const char *test_file = "test_xattr_basic.txt";
    const char *attr_name = "user.testattr";
    const char *test_value = "Hello, NTFS ADS!";
    char buffer[256];
    ssize_t result;
    int fd;
    
    printf("\n=== Test: Basic set/get/remove ===\n");
    
    /* Create test file */
    fd = _open(test_file, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    _close(fd);
    
    /* Set xattr */
    result = brix_plat_setxattr(test_file, attr_name, test_value, strlen(test_value) + 1, 0);
    TEST_ASSERT(result == 0, "Set xattr");
    
    /* Get xattr */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_getxattr(test_file, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(result > 0, "Get xattr returns size");
    TEST_ASSERT(strcmp(buffer, test_value) == 0, "Get xattr returns correct value");
    
    /* Remove xattr */
    result = brix_plat_removexattr(test_file, attr_name);
    TEST_ASSERT(result == 0, "Remove xattr");
    
    /* Verify removal - should fail with ENODATA */
    result = brix_plat_getxattr(test_file, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(result == -1 && errno == ENODATA, "Get after remove returns ENODATA");
    
    /* Cleanup */
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: File descriptor variants (fsetxattr, fgetxattr, fremovexattr)
 * ========================================================================== */

void test_fd_variants(void)
{
    const char *test_file = "test_xattr_fd.txt";
    const char *attr_name = "user.fdtest";
    const char *test_value = "FD-based xattr test";
    char buffer[256];
    ssize_t result;
    int fd;
    
    printf("\n=== Test: File descriptor variants ===\n");
    
    /* Create and open test file */
    fd = _open(test_file, _O_RDWR | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Open test file with fd");
    if (fd < 0) return;
    
    /* Set xattr using fd */
    result = brix_plat_fsetxattr(fd, attr_name, test_value, strlen(test_value) + 1, 0);
    TEST_ASSERT(result == 0, "fsetxattr");
    
    /* Get xattr using fd */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_fgetxattr(fd, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(result > 0, "fgetxattr returns size");
    TEST_ASSERT(strcmp(buffer, test_value) == 0, "fgetxattr returns correct value");
    
    /* Remove xattr using fd */
    result = brix_plat_fremovexattr(fd, attr_name);
    TEST_ASSERT(result == 0, "fremovexattr");
    
    /* Cleanup */
    _close(fd);
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: Flag handling (XATTR_CREATE, XATTR_REPLACE)
 * ========================================================================== */

void test_flag_handling(void)
{
    const char *test_file = "test_xattr_flags.txt";
    const char *attr_name = "user.flagtest";
    const char *value1 = "First value";
    const char *value2 = "Second value";
    char buffer[256];
    ssize_t result;
    int fd;
    
    printf("\n=== Test: Flag handling ===\n");
    
    /* Create test file */
    fd = _open(test_file, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    _close(fd);
    
    /* Test XATTR_CREATE: should succeed (attr doesn't exist) */
    result = brix_plat_setxattr(test_file, attr_name, value1, strlen(value1) + 1, BRIX_XATTR_CREATE);
    TEST_ASSERT(result == 0, "XATTR_CREATE on non-existent attr succeeds");
    
    /* Test XATTR_CREATE: should fail with EEXIST (attr exists) */
    result = brix_plat_setxattr(test_file, attr_name, value2, strlen(value2) + 1, BRIX_XATTR_CREATE);
    TEST_ASSERT(result == -1 && errno == EEXIST, "XATTR_CREATE on existing attr fails with EEXIST");
    
    /* Test XATTR_REPLACE: should succeed (attr exists) */
    result = brix_plat_setxattr(test_file, attr_name, value2, strlen(value2) + 1, BRIX_XATTR_REPLACE);
    TEST_ASSERT(result == 0, "XATTR_REPLACE on existing attr succeeds");
    
    /* Verify value was replaced */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_getxattr(test_file, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(strcmp(buffer, value2) == 0, "Value was replaced");
    
    /* Test XATTR_REPLACE: should fail with ENODATA (attr doesn't exist) */
    brix_plat_removexattr(test_file, attr_name);
    result = brix_plat_setxattr(test_file, attr_name, value1, strlen(value1) + 1, BRIX_XATTR_REPLACE);
    TEST_ASSERT(result == -1 && errno == ENODATA, "XATTR_REPLACE on non-existent attr fails with ENODATA");
    
    /* Cleanup */
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: Error handling (ENODATA, ERANGE, EINVAL)
 * ========================================================================== */

void test_error_handling(void)
{
    const char *test_file = "test_xattr_errors.txt";
    const char *attr_name = "user.errtest";
    const char *test_value = "Error test value";
    char small_buffer[4];
    ssize_t result;
    int fd;
    
    printf("\n=== Test: Error handling ===\n");
    
    /* Create test file */
    fd = _open(test_file, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    _close(fd);
    
    /* Test ENODATA: get non-existent attr */
    result = brix_plat_getxattr(test_file, attr_name, NULL, 0);
    TEST_ASSERT(result == -1 && errno == ENODATA, "Get non-existent attr returns ENODATA");
    
    /* Set attr for ERANGE test */
    brix_plat_setxattr(test_file, attr_name, test_value, strlen(test_value) + 1, 0);
    
    /* Test ERANGE: buffer too small */
    result = brix_plat_getxattr(test_file, attr_name, small_buffer, sizeof(small_buffer));
    TEST_ASSERT(result == -1 && errno == ERANGE, "Buffer too small returns ERANGE");
    
    /* Test EINVAL: invalid attr name (contains ':') */
    result = brix_plat_setxattr(test_file, "user:invalid:name", test_value, strlen(test_value) + 1, 0);
    TEST_ASSERT(result == -1 && errno == EINVAL, "Invalid attr name returns EINVAL");
    
    /* Test EINVAL: NULL name */
    result = brix_plat_setxattr(test_file, NULL, test_value, strlen(test_value) + 1, 0);
    TEST_ASSERT(result == -1 && errno == EINVAL, "NULL attr name returns EINVAL");
    
    /* Cleanup */
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: listxattr enumeration
 * ========================================================================== */

void test_listxattr(void)
{
    const char *test_file = "test_xattr_list.txt";
    char buffer[512];
    ssize_t result;
    int fd;
    
    printf("\n=== Test: listxattr enumeration ===\n");
    
    /* Create test file */
    fd = _open(test_file, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    _close(fd);
    
    /* Set multiple xattrs */
    brix_plat_setxattr(test_file, "user.attr1", "value1", 7, 0);
    brix_plat_setxattr(test_file, "user.attr2", "value2", 7, 0);
    brix_plat_setxattr(test_file, "user.attr3", "value3", 7, 0);
    
    /* List xattrs (get size first) */
    result = brix_plat_listxattr(test_file, NULL, 0);
    TEST_ASSERT(result > 0, "listxattr returns size");
    
    /* List xattrs (get names) */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_listxattr(test_file, buffer, sizeof(buffer));
    TEST_ASSERT(result > 0, "listxattr returns names");
    
    /* Verify all three attrs are present */
    TEST_ASSERT(strstr(buffer, "user.attr1") != NULL, "attr1 in list");
    TEST_ASSERT(strstr(buffer, "user.attr2") != NULL, "attr2 in list");
    TEST_ASSERT(strstr(buffer, "user.attr3") != NULL, "attr3 in list");
    
    /* Test fd variant */
    fd = _open(test_file, _O_RDONLY, 0);
    if (fd >= 0) {
        memset(buffer, 0, sizeof(buffer));
        result = brix_plat_flistxattr(fd, buffer, sizeof(buffer));
        TEST_ASSERT(result > 0, "flistxattr returns names");
        _close(fd);
    }
    
    /* Cleanup */
    brix_plat_removexattr(test_file, "user.attr1");
    brix_plat_removexattr(test_file, "user.attr2");
    brix_plat_removexattr(test_file, "user.attr3");
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: Binary data handling
 * ========================================================================== */

void test_binary_data(void)
{
    const char *test_file = "test_xattr_binary.bin";
    const char *attr_name = "user.binary";
    unsigned char test_data[256];
    unsigned char buffer[256];
    ssize_t result;
    int i;
    int fd;
    
    printf("\n=== Test: Binary data handling ===\n");
    
    /* Create test data (all byte values) */
    for (i = 0; i < 256; i++) {
        test_data[i] = (unsigned char)i;
    }
    
    /* Create test file */
    fd = _open(test_file, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create binary test file");
    if (fd < 0) return;
    _close(fd);
    
    /* Set binary xattr */
    result = brix_plat_setxattr(test_file, attr_name, test_data, sizeof(test_data), 0);
    TEST_ASSERT(result == 0, "Set binary xattr");
    
    /* Get binary xattr */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_getxattr(test_file, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(result == sizeof(test_data), "Get binary xattr returns correct size");
    TEST_ASSERT(memcmp(buffer, test_data, sizeof(test_data)) == 0, "Binary data matches");
    
    /* Cleanup */
    brix_plat_removexattr(test_file, attr_name);
    DeleteFileA(test_file);
}

/* ==========================================================================
 * TEST: NTFS detection utility
 * ========================================================================== */

void test_ntfs_detection(void)
{
    const char *ntfs_path = "C:\\test_ntfs_check.txt";
    int is_ntfs;
    
    printf("\n=== Test: NTFS detection ===\n");
    
    is_ntfs = brix_win32_is_ntfs_path(ntfs_path);
    printf("  C: drive is NTFS: %s\n", is_ntfs ? "yes" : "no");
    TEST_ASSERT(is_ntfs == 1, "C: drive is NTFS");
    
    /* Test with NULL path */
    is_ntfs = brix_win32_is_ntfs_path(NULL);
    TEST_ASSERT(is_ntfs == 0, "NULL path returns 0");
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */

int main(void)
{
    printf("============================================================\n");
    printf("Windows NTFS ADS Xattr Test Suite\n");
    printf("============================================================\n");
    
    test_basic_set_get_remove();
    test_fd_variants();
    test_flag_handling();
    test_error_handling();
    test_listxattr();
    test_binary_data();
    test_ntfs_detection();
    
    printf("\n============================================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("============================================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}
