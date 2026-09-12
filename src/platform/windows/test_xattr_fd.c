/*
 * test_xattr_fd.c - Test fd-based xattr operations on Windows
 * 
 * Tests brix_plat_fgetxattr, brix_plat_fsetxattr, brix_plat_fremovexattr,
 * and brix_plat_flistxattr using file descriptors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>

/* Include PAL API */
#include "../platform_api.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        tests_run++; \
        if (condition) { \
            tests_passed++; \
            printf("  ✓ %s\n", message); \
        } else { \
            tests_failed++; \
            printf("  ✗ FAILED: %s (line %d)\n", message, __LINE__); \
            printf("    errno=%d (%s)\n", errno, strerror(errno)); \
        } \
    } while(0)

/*
 * Test 1: Basic fsetxattr/fgetxattr roundtrip
 */
static void
test_fd_xattr_basic(void)
{
    const char *test_file = "test_xattr_fd.tmp";
    const char *attr_name = "user.testattr";
    const char *attr_value = "test_value_123";
    char buffer[256];
    int fd;
    ssize_t ret;
    
    printf("\n[Test 1: Basic fsetxattr/fgetxattr roundtrip]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set xattr using fd */
    ret = brix_plat_fsetxattr(fd, attr_name, attr_value, strlen(attr_value), 0);
    TEST_ASSERT(ret == 0, "fsetxattr via fd");
    
    /* Get xattr using fd */
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(ret > 0, "fgetxattr via fd returns size");
    TEST_ASSERT(strcmp(buffer, attr_value) == 0, "fgetxattr returns correct value");
    
    /* Cleanup */
    close(fd);
    brix_plat_fremovexattr(fd, attr_name);
    unlink(test_file);
}

/*
 * Test 2: Invalid file descriptor handling
 */
static void
test_fd_xattr_invalid_fd(void)
{
    const char *attr_name = "user.testattr";
    char buffer[256];
    ssize_t ret;
    
    printf("\n[Test 2: Invalid file descriptor handling]\n");
    
    /* Test with invalid fd (-1) */
    ret = brix_plat_fgetxattr(-1, attr_name, buffer, sizeof(buffer));
    TEST_ASSERT(ret == -1, "fgetxattr with invalid fd returns -1");
    TEST_ASSERT(errno == EBADF, "fgetxattr sets errno to EBADF");
    
    ret = brix_plat_fsetxattr(-1, attr_name, "value", 5, 0);
    TEST_ASSERT(ret == -1, "fsetxattr with invalid fd returns -1");
    TEST_ASSERT(errno == EBADF, "fsetxattr sets errno to EBADF");
    
    ret = brix_plat_fremovexattr(-1, attr_name);
    TEST_ASSERT(ret == -1, "fremovexattr with invalid fd returns -1");
    TEST_ASSERT(errno == EBADF, "fremovexattr sets errno to EBADF");
    
    ret = brix_plat_flistxattr(-1, buffer, sizeof(buffer));
    TEST_ASSERT(ret == -1, "flistxattr with invalid fd returns -1");
    TEST_ASSERT(errno == EBADF, "flistxattr sets errno to EBADF");
}

/*
 * Test 3: Multiple attributes on same fd
 */
static void
test_fd_xattr_multiple_attrs(void)
{
    const char *test_file = "test_xattr_fd_multi.tmp";
    int fd;
    ssize_t ret;
    char buffer[256];
    
    printf("\n[Test 3: Multiple attributes on same fd]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set multiple attributes */
    ret = brix_plat_fsetxattr(fd, "user.attr1", "value1", 6, 0);
    TEST_ASSERT(ret == 0, "Set first attribute");
    
    ret = brix_plat_fsetxattr(fd, "user.attr2", "value2", 6, 0);
    TEST_ASSERT(ret == 0, "Set second attribute");
    
    ret = brix_plat_fsetxattr(fd, "user.attr3", "value3", 6, 0);
    TEST_ASSERT(ret == 0, "Set third attribute");
    
    /* Read back each attribute */
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.attr1", buffer, sizeof(buffer));
    TEST_ASSERT(ret == 6 && strcmp(buffer, "value1") == 0, "Read first attribute");
    
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.attr2", buffer, sizeof(buffer));
    TEST_ASSERT(ret == 6 && strcmp(buffer, "value2") == 0, "Read second attribute");
    
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.attr3", buffer, sizeof(buffer));
    TEST_ASSERT(ret == 6 && strcmp(buffer, "value3") == 0, "Read third attribute");
    
    /* Remove one attribute */
    ret = brix_plat_fremovexattr(fd, "user.attr2");
    TEST_ASSERT(ret == 0, "Remove second attribute");
    
    /* Verify removal */
    ret = brix_plat_fgetxattr(fd, "user.attr2", buffer, sizeof(buffer));
    TEST_ASSERT(ret == -1 && errno == ENODATA, "Removed attribute returns ENODATA");
    
    /* Verify others still exist */
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.attr1", buffer, sizeof(buffer));
    TEST_ASSERT(ret == 6, "First attribute still exists");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 4: flistxattr via fd
 */
static void
test_fd_xattr_list(void)
{
    const char *test_file = "test_xattr_fd_list.tmp";
    int fd;
    ssize_t ret;
    char list[512];
    
    printf("\n[Test 4: flistxattr via fd]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set some attributes */
    brix_plat_fsetxattr(fd, "user.attr_a", "a", 1, 0);
    brix_plat_fsetxattr(fd, "user.attr_b", "b", 1, 0);
    brix_plat_fsetxattr(fd, "user.attr_c", "c", 1, 0);
    
    /* List attributes (get size first) */
    ret = brix_plat_flistxattr(fd, NULL, 0);
    TEST_ASSERT(ret > 0, "flistxattr returns size");
    
    /* List attributes (get names) */
    memset(list, 0, sizeof(list));
    ret = brix_plat_flistxattr(fd, list, sizeof(list));
    TEST_ASSERT(ret > 0, "flistxattr returns attribute names");
    
    /* Check if attributes are in the list */
    TEST_ASSERT(memmem(list, ret, "user.attr_a", 11) != NULL, "attr_a in list");
    TEST_ASSERT(memmem(list, ret, "user.attr_b", 11) != NULL, "attr_b in list");
    TEST_ASSERT(memmem(list, ret, "user.attr_c", 11) != NULL, "attr_c in list");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 5: XATTR_CREATE and XATTR_REPLACE flags
 */
static void
test_fd_xattr_flags(void)
{
    const char *test_file = "test_xattr_fd_flags.tmp";
    int fd;
    ssize_t ret;
    
    printf("\n[Test 5: XATTR_CREATE and XATTR_REPLACE flags]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set initial attribute */
    ret = brix_plat_fsetxattr(fd, "user.flagtest", "initial", 7, 0);
    TEST_ASSERT(ret == 0, "Set initial attribute");
    
    /* Try to create existing attribute (should fail) */
    ret = brix_plat_fsetxattr(fd, "user.flagtest", "new", 3, BRIX_XATTR_CREATE);
    TEST_ASSERT(ret == -1 && errno == EEXIST, "XATTR_CREATE on existing fails with EEXIST");
    
    /* Replace existing attribute (should succeed) */
    ret = brix_plat_fsetxattr(fd, "user.flagtest", "replaced", 8, BRIX_XATTR_REPLACE);
    TEST_ASSERT(ret == 0, "XATTR_REPLACE on existing succeeds");
    
    /* Verify replacement */
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.flagtest", buffer, sizeof(buffer));
    TEST_ASSERT(ret == 8 && strcmp(buffer, "replaced") == 0, "Value was replaced");
    
    /* Try to replace non-existing attribute (should fail) */
    ret = brix_plat_fsetxattr(fd, "user.nonexistent", "value", 5, BRIX_XATTR_REPLACE);
    TEST_ASSERT(ret == -1 && errno == ENODATA, "XATTR_REPLACE on non-existing fails with ENODATA");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 6: Large attribute values
 */
static void
test_fd_xattr_large_value(void)
{
    const char *test_file = "test_xattr_fd_large.tmp";
    int fd;
    ssize_t ret;
    char large_value[4096];
    char buffer[4096];
    
    printf("\n[Test 6: Large attribute values]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Fill with pattern */
    memset(large_value, 'A', sizeof(large_value));
    
    /* Set large attribute */
    ret = brix_plat_fsetxattr(fd, "user.large", large_value, sizeof(large_value), 0);
    TEST_ASSERT(ret == 0, "Set large attribute (4KB)");
    
    /* Read back */
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.large", buffer, sizeof(buffer));
    TEST_ASSERT(ret == sizeof(large_value), "Read large attribute");
    TEST_ASSERT(memcmp(buffer, large_value, sizeof(large_value)) == 0, "Large value matches");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 7: Binary data (non-text)
 */
static void
test_fd_xattr_binary_data(void)
{
    const char *test_file = "test_xattr_fd_binary.tmp";
    int fd;
    ssize_t ret;
    unsigned char binary_data[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
    };
    unsigned char buffer[32];
    
    printf("\n[Test 7: Binary data (non-text)]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set binary attribute */
    ret = brix_plat_fsetxattr(fd, "user.binary", binary_data, sizeof(binary_data), 0);
    TEST_ASSERT(ret == 0, "Set binary attribute");
    
    /* Read back */
    memset(buffer, 0, sizeof(buffer));
    ret = brix_plat_fgetxattr(fd, "user.binary", buffer, sizeof(buffer));
    TEST_ASSERT(ret == sizeof(binary_data), "Read binary attribute");
    TEST_ASSERT(memcmp(buffer, binary_data, sizeof(binary_data)) == 0, "Binary data matches");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 8: fd from different sources (socket, pipe, file)
 */
static void
test_fd_xattr_different_sources(void)
{
    const char *test_file = "test_xattr_fd_sources.tmp";
    int fd_file, fd_pipe[2];
    ssize_t ret;
    char buffer[256];
    
    printf("\n[Test 8: fd from different sources]\n");
    
    /* Test with regular file */
    fd_file = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd_file >= 0, "Create test file");
    if (fd_file >= 0) {
        ret = brix_plat_fsetxattr(fd_file, "user.file", "file_value", 10, 0);
        TEST_ASSERT(ret == 0, "fsetxattr on file fd");
        close(fd_file);
    }
    
    /* Test with pipe (should fail - pipes don't support ADS) */
    if (pipe(fd_pipe) == 0) {
        ret = brix_plat_fsetxattr(fd_pipe[1], "user.pipe", "pipe_value", 10, 0);
        /* This may fail on pipes, which is expected */
        if (ret == -1) {
            TEST_ASSERT(errno != 0, "fsetxattr on pipe fd fails (expected)");
        } else {
            printf("  ℹ Pipe xattr succeeded (unexpected)\n");
        }
        close(fd_pipe[0]);
        close(fd_pipe[1]);
    }
    
    /* Cleanup */
    unlink(test_file);
}

/*
 * Test 9: Error handling - buffer too small
 */
static void
test_fd_xattr_buffer_too_small(void)
{
    const char *test_file = "test_xattr_fd_buffer.tmp";
    int fd;
    ssize_t ret;
    const char *value = "this_is_a_test_value_that_is_longer_than_buffer";
    char small_buffer[10];
    
    printf("\n[Test 9: Error handling - buffer too small]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Set attribute */
    ret = brix_plat_fsetxattr(fd, "user.test", value, strlen(value), 0);
    TEST_ASSERT(ret == 0, "Set attribute");
    
    /* Try to read with small buffer */
    ret = brix_plat_fgetxattr(fd, "user.test", small_buffer, sizeof(small_buffer));
    TEST_ASSERT(ret == -1 && errno == ERANGE, "fgetxattr with small buffer returns ERANGE");
    
    /* Get required size */
    ret = brix_plat_fgetxattr(fd, "user.test", NULL, 0);
    TEST_ASSERT(ret == strlen(value), "fgetxattr with NULL returns required size");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

/*
 * Test 10: Attribute name validation
 */
static void
test_fd_xattr_name_validation(void)
{
    const char *test_file = "test_xattr_fd_names.tmp";
    int fd;
    ssize_t ret;
    
    printf("\n[Test 10: Attribute name validation]\n");
    
    /* Create test file */
    fd = open(test_file, O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
    TEST_ASSERT(fd >= 0, "Create test file");
    if (fd < 0) return;
    
    /* Test invalid names */
    ret = brix_plat_fsetxattr(fd, "", "value", 5, 0);
    TEST_ASSERT(ret == -1 && errno == EINVAL, "Empty name rejected");
    
    ret = brix_plat_fsetxattr(fd, "user:invalid", "value", 5, 0);
    TEST_ASSERT(ret == -1 && errno == EINVAL, "Name with colon rejected");
    
    ret = brix_plat_fsetxattr(fd, "user\\invalid", "value", 5, 0);
    TEST_ASSERT(ret == -1 && errno == EINVAL, "Name with backslash rejected");
    
    /* Test valid names */
    ret = brix_plat_fsetxattr(fd, "user.valid_name", "value", 5, 0);
    TEST_ASSERT(ret == 0, "Valid name accepted");
    
    ret = brix_plat_fsetxattr(fd, "user.dash-name", "value", 5, 0);
    TEST_ASSERT(ret == 0, "Name with dash accepted");
    
    /* Cleanup */
    close(fd);
    unlink(test_file);
}

int
main(int argc, char *argv[])
{
    printf("============================================================\n");
    printf("Windows fd-based xattr Test Suite\n");
    printf("============================================================\n");
    printf("Testing: brix_plat_fgetxattr, brix_plat_fsetxattr,\n");
    printf("         brix_plat_fremovexattr, brix_plat_flistxattr\n");
    printf("============================================================\n\n");
    
    /* Run all tests */
    test_fd_xattr_basic();
    test_fd_xattr_invalid_fd();
    test_fd_xattr_multiple_attrs();
    test_fd_xattr_list();
    test_fd_xattr_flags();
    test_fd_xattr_large_value();
    test_fd_xattr_binary_data();
    test_fd_xattr_different_sources();
    test_fd_xattr_buffer_too_small();
    test_fd_xattr_name_validation();
    
    /* Print summary */
    printf("\n============================================================\n");
    printf("Test Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("============================================================\n");
    
    if (tests_failed > 0) {
        printf("\n⚠️  %d test(s) FAILED\n", tests_failed);
        return 1;
    } else {
        printf("\n✅ All %d tests PASSED\n", tests_run);
        return 0;
    }
}
