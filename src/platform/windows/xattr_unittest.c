/*
 * src/platform/windows/xattr_unittest.c - Test suite for Windows xattr implementation
 * 
 * Compile and run on Windows to verify NTFS ADS xattr functionality.
 * 
 * Usage:
 *   cl xattr_unittest.c xattr.c win32_compat.c /Fe:test_xattr.exe
 *   .\test_xattr.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>

#include "../platform_api.h"
#include "win32_compat.h"

/* Test file path - use temp directory */
static char test_file_path[MAX_PATH];

/* ==========================================================================
 * TEST UTILITIES
 * ========================================================================== */

static int
setup_test_file(void)
{
    char temp_dir[MAX_PATH];
    HANDLE handle;
    
    /* Get temp directory */
    if (GetTempPathA(sizeof(temp_dir), temp_dir) == 0) {
        fprintf(stderr, "Failed to get temp directory\n");
        return -1;
    }
    
    /* Build test file path */
    snprintf(test_file_path, sizeof(test_file_path), 
             "%s\\brix_xattr_test_%d.txt", temp_dir, GetCurrentProcessId());
    
    /* Create test file */
    handle = CreateFileA(
        test_file_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create test file: %s\n", test_file_path);
        return -1;
    }
    
    CloseHandle(handle);
    return 0;
}

static void
cleanup_test_file(void)
{
    DeleteFileA(test_file_path);
}

static int
is_ntfs_test_path(void)
{
    return brix_win32_is_ntfs_path(test_file_path);
}

/* ==========================================================================
 * TEST CASES
 * ========================================================================== */

static void
test_set_get_simple(void)
{
    const char *attr_name = "user.test_simple";
    const char *value = "Hello, World!";
    char buffer[64];
    ssize_t size;
    int ret;
    
    printf("  Testing set/get simple attribute... ");
    
    ret = brix_plat_setxattr(test_file_path, attr_name, value, strlen(value), 0);
    assert(ret == 0);
    
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(value));
    assert(memcmp(buffer, value, size) == 0);
    buffer[size] = '\0';
    
    printf("OK (value: '%s')\n", buffer);
}

static void
test_set_get_binary(void)
{
    const char *attr_name = "user.test_binary";
    unsigned char value[256];
    unsigned char buffer[256];
    ssize_t size;
    int ret;
    int i;
    
    printf("  Testing set/get binary attribute... ");
    
    /* Fill with pattern */
    for (i = 0; i < 256; i++) {
        value[i] = (unsigned char)i;
    }
    
    ret = brix_plat_setxattr(test_file_path, attr_name, value, sizeof(value), 0);
    assert(ret == 0);
    
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size == sizeof(value));
    assert(memcmp(buffer, value, size) == 0);
    
    printf("OK (%zd bytes)\n", size);
}

static void
test_get_nonexistent(void)
{
    const char *attr_name = "user.does_not_exist";
    char buffer[64];
    ssize_t size;
    
    printf("  Testing get nonexistent attribute... ");
    
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size < 0);
    assert(errno == ENODATA);
    
    printf("OK (errno=ENODATA)\n");
}

static void
test_set_multiple(void)
{
    const char *attr1 = "user.attr1";
    const char *attr2 = "user.attr2";
    const char *attr3 = "user.attr3";
    const char *val1 = "value1";
    const char *val2 = "value2";
    const char *val3 = "value3";
    char buffer[64];
    ssize_t size;
    int ret;
    
    printf("  Testing set multiple attributes... ");
    
    ret = brix_plat_setxattr(test_file_path, attr1, val1, strlen(val1), 0);
    assert(ret == 0);
    
    ret = brix_plat_setxattr(test_file_path, attr2, val2, strlen(val2), 0);
    assert(ret == 0);
    
    ret = brix_plat_setxattr(test_file_path, attr3, val3, strlen(val3), 0);
    assert(ret == 0);
    
    /* Verify all three */
    size = brix_plat_getxattr(test_file_path, attr1, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(val1) && memcmp(buffer, val1, size) == 0);
    
    size = brix_plat_getxattr(test_file_path, attr2, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(val2) && memcmp(buffer, val2, size) == 0);
    
    size = brix_plat_getxattr(test_file_path, attr3, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(val3) && memcmp(buffer, val3, size) == 0);
    
    printf("OK\n");
}

static void
test_list_attributes(void)
{
    char list[256];
    ssize_t size;
    int count;
    char *p;
    
    printf("  Testing list attributes... ");
    
    size = brix_plat_listxattr(test_file_path, list, sizeof(list));
    assert(size > 0);
    
    /* Count attributes */
    count = 0;
    for (p = list; p < list + size; p += strlen(p) + 1) {
        count++;
        printf("\n    - %s", p);
    }
    
    assert(count >= 3);  /* At least the 3 we set */
    
    printf("\n  OK (%d attributes)\n", count);
}

static void
test_remove_attribute(void)
{
    const char *attr_name = "user.to_remove";
    const char *value = "temporary";
    char buffer[64];
    int ret;
    ssize_t size;
    
    printf("  Testing remove attribute... ");
    
    /* Set attribute */
    ret = brix_plat_setxattr(test_file_path, attr_name, value, strlen(value), 0);
    assert(ret == 0);
    
    /* Verify it exists */
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size > 0);
    
    /* Remove it */
    ret = brix_plat_removexattr(test_file_path, attr_name);
    assert(ret == 0);
    
    /* Verify it's gone */
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size < 0);
    assert(errno == ENODATA);
    
    printf("OK\n");
}

static void
test_set_flags_create(void)
{
    const char *attr_name = "user.create_test";
    const char *value = "create me";
    int ret;
    
    printf("  Testing XATTR_CREATE flag... ");
    
    /* Create new attribute */
    ret = brix_plat_setxattr(test_file_path, attr_name, value, strlen(value), 
                             BRIX_XATTR_CREATE);
    assert(ret == 0);
    
    /* Try to create again (should fail) */
    ret = brix_plat_setxattr(test_file_path, attr_name, value, strlen(value), 
                             BRIX_XATTR_CREATE);
    assert(ret < 0);
    assert(errno == EEXIST);
    
    printf("OK (EEXIST on duplicate)\n");
}

static void
test_set_flags_replace(void)
{
    const char *attr_name = "user.replace_test";
    const char *value1 = "original";
    const char *value2 = "replaced";
    char buffer[64];
    ssize_t size;
    int ret;
    
    printf("  Testing XATTR_REPLACE flag... ");
    
    /* Create initial attribute */
    ret = brix_plat_setxattr(test_file_path, attr_name, value1, strlen(value1), 0);
    assert(ret == 0);
    
    /* Replace it */
    ret = brix_plat_setxattr(test_file_path, attr_name, value2, strlen(value2), 
                             BRIX_XATTR_REPLACE);
    assert(ret == 0);
    
    /* Verify replaced */
    size = brix_plat_getxattr(test_file_path, attr_name, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(value2) && memcmp(buffer, value2, size) == 0);
    
    /* Try to replace nonexistent */
    ret = brix_plat_setxattr(test_file_path, "user.nonexistent", value1, 
                             strlen(value1), BRIX_XATTR_REPLACE);
    assert(ret < 0);
    assert(errno == ENODATA);
    
    printf("OK\n");
}

static void
test_buffer_too_small(void)
{
    const char *attr_name = "user.large_attr";
    const char *value = "This is a moderately large value that should not fit in a tiny buffer";
    char tiny_buffer[8];
    ssize_t size;
    int ret;
    
    printf("  Testing buffer too small... ");
    
    /* Set large attribute */
    ret = brix_plat_setxattr(test_file_path, attr_name, value, strlen(value), 0);
    assert(ret == 0);
    
    /* Try to read with tiny buffer */
    size = brix_plat_getxattr(test_file_path, attr_name, tiny_buffer, sizeof(tiny_buffer));
    assert(size < 0);
    assert(errno == ERANGE);
    
    /* Get required size */
    size = brix_plat_getxattr(test_file_path, attr_name, NULL, 0);
    assert(size == (ssize_t)strlen(value));
    
    printf("OK (required size: %zd)\n", size);
}

static void
test_invalid_name(void)
{
    const char *invalid_names[] = {
        "user:invalid",   /* Colon not allowed */
        "user\\invalid",  /* Backslash not allowed */
        "user/invalid",   /* Forward slash not allowed */
        "",               /* Empty name */
        NULL
    };
    int i;
    
    printf("  Testing invalid attribute names... ");
    
    for (i = 0; invalid_names[i] != NULL; i++) {
        int ret = brix_plat_setxattr(test_file_path, invalid_names[i], "value", 5, 0);
        assert(ret < 0);
        assert(errno == EINVAL);
    }
    
    printf("OK\n");
}

static void
test_fd_variants(void)
{
    const char *attr_name = "user.fd_test";
    const char *value = "via file descriptor";
    char buffer[64];
    ssize_t size;
    int ret;
    int fd;
    
    printf("  Testing fd-based variants... ");
    
    /* Open file */
    fd = _open(test_file_path, _O_RDWR);
    assert(fd >= 0);
    
    /* Set via fd */
    ret = brix_plat_fsetxattr(fd, attr_name, value, strlen(value), 0);
    assert(ret == 0);
    
    /* Get via fd */
    size = brix_plat_fgetxattr(fd, attr_name, buffer, sizeof(buffer));
    assert(size == (ssize_t)strlen(value));
    assert(memcmp(buffer, value, size) == 0);
    
    _close(fd);
    
    printf("OK\n");
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("Windows NTFS ADS Xattr Test Suite\n");
    printf("==================================\n\n");
    
    /* Setup */
    printf("Setting up test file... ");
    if (setup_test_file() < 0) {
        printf("FAILED\n");
        return 1;
    }
    printf("OK (%s)\n", test_file_path);
    
    /* Check NTFS */
    printf("Checking filesystem type... ");
    if (!is_ntfs_test_path()) {
        printf("SKIPPED (not NTFS)\n");
        printf("\nWarning: ADS requires NTFS filesystem.\n");
        printf("Current path is on FAT32, exFAT, or another filesystem.\n");
        cleanup_test_file();
        return 0;
    }
    printf("OK (NTFS)\n\n");
    
    /* Run tests */
    printf("Running tests:\n");
    
    test_set_get_simple();
    test_set_get_binary();
    test_get_nonexistent();
    test_set_multiple();
    test_list_attributes();
    test_remove_attribute();
    test_set_flags_create();
    test_set_flags_replace();
    test_buffer_too_small();
    test_invalid_name();
    test_fd_variants();
    
    /* Cleanup */
    printf("\nCleaning up... ");
    cleanup_test_file();
    printf("OK\n\n");
    
    printf("All tests PASSED!\n");
    return 0;
}
