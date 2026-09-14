/*
 * xattr_list_unittest.c - Test NTFS ADS stream enumeration
 * 
 * Tests brix_plat_listxattr and brix_plat_flistxattr functions
 * which enumerate alternate data streams using FindFirstStreamW/FindNextStreamW.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <io.h>

/* Mock PAL API for testing */
#define BRIX_PLATFORM_WINDOWS 1

#include "../platform.h"
#include "../platform_api.h"
#include "win32_compat.h"

/* Forward declarations from xattr.c */
extern ssize_t brix_plat_listxattr(const char *path, char *list, size_t size);
extern ssize_t brix_plat_flistxattr(int fd, char *list, size_t size);
extern int brix_plat_setxattr(const char *path, const char *name,
                              const void *value, size_t size, int flags);
extern int brix_plat_removexattr(const char *path, const char *name);
extern int brix_win32_is_ntfs_path(const char *path);

/* Test helper: Print stream names from list buffer */
static void
print_stream_list(const char *list, size_t size)
{
    size_t i = 0;
    int count = 0;
    
    printf("  Streams found (%zu bytes):\n", size);
    while (i < size) {
        if (list[i] == '\0') {
            break;
        }
        printf("    [%d] %s\n", count++, &list[i]);
        i += strlen(&list[i]) + 1;
    }
}

/* Test 1: List streams on file with no attributes */
static int
test_list_empty_file(void)
{
    const char *test_file = "test_empty.txt";
    char buffer[1024];
    ssize_t result;
    FILE *f;
    
    printf("Test 1: List streams on empty file\n");
    
    /* Create test file */
    f = fopen(test_file, "w");
    if (f == NULL) {
        printf("  ✗ Failed to create test file\n");
        return -1;
    }
    fprintf(f, "test content\n");
    fclose(f);
    
    /* Check if NTFS */
    if (!brix_win32_is_ntfs_path(test_file)) {
        printf("  ⊘ Skipped: Not an NTFS volume\n");
        remove(test_file);
        return 0;
    }
    
    /* List streams (should only have ::DATA which is filtered) */
    result = brix_plat_listxattr(test_file, buffer, sizeof(buffer));
    
    if (result < 0 && errno == ENODATA) {
        printf("  ✓ Correctly returned ENODATA (no user streams)\n");
        remove(test_file);
        return 0;
    } else if (result == 0) {
        printf("  ✓ Correctly returned 0 bytes (no user streams)\n");
        remove(test_file);
        return 0;
    } else {
        printf("  ✗ Unexpected result: %zd (errno=%d)\n", result, errno);
        remove(test_file);
        return -1;
    }
}

/* Test 2: List streams on file with multiple attributes */
static int
test_list_multiple_streams(void)
{
    const char *test_file = "test_multi.txt";
    char buffer[1024];
    ssize_t result;
    const char *attr1_name = "user.test1";
    const char *attr2_name = "user.test2";
    const char *attr3_name = "user.metadata";
    const char *attr1_value = "value1";
    const char *attr2_value = "value2";
    const char *attr3_value = "metadata_value";
    
    printf("Test 2: List streams with multiple attributes\n");
    
    /* Create test file */
    FILE *f = fopen(test_file, "w");
    if (f == NULL) {
        printf("  ✗ Failed to create test file\n");
        return -1;
    }
    fprintf(f, "test content\n");
    fclose(f);
    
    /* Check if NTFS */
    if (!brix_win32_is_ntfs_path(test_file)) {
        printf("  ⊘ Skipped: Not an NTFS volume\n");
        remove(test_file);
        return 0;
    }
    
    /* Set multiple attributes */
    if (brix_plat_setxattr(test_file, attr1_name, attr1_value, strlen(attr1_value), 0) < 0) {
        printf("  ✗ Failed to set attr1: %d\n", errno);
        remove(test_file);
        return -1;
    }
    
    if (brix_plat_setxattr(test_file, attr2_name, attr2_value, strlen(attr2_value), 0) < 0) {
        printf("  ✗ Failed to set attr2: %d\n", errno);
        brix_plat_removexattr(test_file, attr1_name);
        remove(test_file);
        return -1;
    }
    
    if (brix_plat_setxattr(test_file, attr3_name, attr3_value, strlen(attr3_value), 0) < 0) {
        printf("  ✗ Failed to set attr3: %d\n", errno);
        brix_plat_removexattr(test_file, attr1_name);
        brix_plat_removexattr(test_file, attr2_name);
        remove(test_file);
        return -1;
    }
    
    printf("  ✓ Set 3 attributes\n");
    
    /* List streams */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_listxattr(test_file, buffer, sizeof(buffer));
    
    if (result < 0) {
        printf("  ✗ listxattr failed: %d\n", errno);
        brix_plat_removexattr(test_file, attr1_name);
        brix_plat_removexattr(test_file, attr2_name);
        brix_plat_removexattr(test_file, attr3_name);
        remove(test_file);
        return -1;
    }
    
    printf("  ✓ listxattr returned %zd bytes\n", result);
    print_stream_list(buffer, result);
    
    /* Verify all three streams are listed */
    int found1 = 0, found2 = 0, found3 = 0;
    size_t i = 0;
    while (i < (size_t)result) {
        if (strcmp(&buffer[i], attr1_name) == 0) found1 = 1;
        if (strcmp(&buffer[i], attr2_name) == 0) found2 = 1;
        if (strcmp(&buffer[i], attr3_name) == 0) found3 = 1;
        i += strlen(&buffer[i]) + 1;
    }
    
    /* Cleanup */
    brix_plat_removexattr(test_file, attr1_name);
    brix_plat_removexattr(test_file, attr2_name);
    brix_plat_removexattr(test_file, attr3_name);
    remove(test_file);
    
    if (found1 && found2 && found3) {
        printf("  ✓ All 3 streams found\n");
        return 0;
    } else {
        printf("  ✗ Missing streams: %s %s %s\n", 
               found1 ? "" : "test1",
               found2 ? "" : "test2",
               found3 ? "" : "metadata");
        return -1;
    }
}

/* Test 3: List with NULL buffer (size query) */
static int
test_list_size_query(void)
{
    const char *test_file = "test_size.txt";
    ssize_t result;
    const char *attr_name = "user.sizetest";
    const char *attr_value = "size_test_value";
    
    printf("Test 3: List with NULL buffer (size query)\n");
    
    /* Create test file */
    FILE *f = fopen(test_file, "w");
    if (f == NULL) {
        printf("  ✗ Failed to create test file\n");
        return -1;
    }
    fprintf(f, "test content\n");
    fclose(f);
    
    /* Check if NTFS */
    if (!brix_win32_is_ntfs_path(test_file)) {
        printf("  ⊘ Skipped: Not an NTFS volume\n");
        remove(test_file);
        return 0;
    }
    
    /* Set attribute */
    if (brix_plat_setxattr(test_file, attr_name, attr_value, strlen(attr_value), 0) < 0) {
        printf("  ✗ Failed to set attribute: %d\n", errno);
        remove(test_file);
        return -1;
    }
    
    /* Query size with NULL buffer */
    result = brix_plat_listxattr(test_file, NULL, 0);
    
    if (result > 0) {
        printf("  ✓ Size query returned %zd bytes\n", result);
        
        /* Now allocate exact size and verify */
        char *buffer = malloc(result);
        if (buffer == NULL) {
            printf("  ✗ Failed to allocate buffer\n");
            brix_plat_removexattr(test_file, attr_name);
            remove(test_file);
            return -1;
        }
        
        ssize_t result2 = brix_plat_listxattr(test_file, buffer, result);
        if (result2 == result) {
            printf("  ✓ Exact size buffer worked\n");
            print_stream_list(buffer, result2);
        } else {
            printf("  ✗ Exact size failed: %zd vs %zd\n", result2, result);
        }
        
        free(buffer);
    } else {
        printf("  ✗ Size query failed: %zd\n", result);
    }
    
    /* Cleanup */
    brix_plat_removexattr(test_file, attr_name);
    remove(test_file);
    
    return (result > 0) ? 0 : -1;
}

/* Test 4: List with insufficient buffer */
static int
test_list_buffer_too_small(void)
{
    const char *test_file = "test_small.txt";
    char buffer[10];  /* Very small buffer */
    ssize_t result;
    const char *attr_name = "user.largetest";
    const char *attr_value = "large_value_that_exceeds_buffer";
    
    printf("Test 4: List with buffer too small\n");
    
    /* Create test file */
    FILE *f = fopen(test_file, "w");
    if (f == NULL) {
        printf("  ✗ Failed to create test file\n");
        return -1;
    }
    fprintf(f, "test content\n");
    fclose(f);
    
    /* Check if NTFS */
    if (!brix_win32_is_ntfs_path(test_file)) {
        printf("  ⊘ Skipped: Not an NTFS volume\n");
        remove(test_file);
        return 0;
    }
    
    /* Set attribute */
    if (brix_plat_setxattr(test_file, attr_name, attr_value, strlen(attr_value), 0) < 0) {
        printf("  ✗ Failed to set attribute: %d\n", errno);
        remove(test_file);
        return -1;
    }
    
    /* Try with small buffer */
    result = brix_plat_listxattr(test_file, buffer, sizeof(buffer));
    
    if (result < 0 && errno == ERANGE) {
        printf("  ✓ Correctly returned ERANGE\n");
        brix_plat_removexattr(test_file, attr_name);
        remove(test_file);
        return 0;
    } else {
        printf("  ✗ Expected ERANGE, got %zd (errno=%d)\n", result, errno);
        brix_plat_removexattr(test_file, attr_name);
        remove(test_file);
        return -1;
    }
}

/* Test 5: List using file descriptor */
static int
test_flistxattr(void)
{
    const char *test_file = "test_fd.txt";
    char buffer[1024];
    ssize_t result;
    int fd;
    const char *attr_name = "user.fdtest";
    const char *attr_value = "fd_test_value";
    
    printf("Test 5: List using file descriptor (flistxattr)\n");
    
    /* Create test file */
    FILE *f = fopen(test_file, "w");
    if (f == NULL) {
        printf("  ✗ Failed to create test file\n");
        return -1;
    }
    fprintf(f, "test content\n");
    fclose(f);
    
    /* Check if NTFS */
    if (!brix_win32_is_ntfs_path(test_file)) {
        printf("  ⊘ Skipped: Not an NTFS volume\n");
        remove(test_file);
        return 0;
    }
    
    /* Set attribute */
    if (brix_plat_setxattr(test_file, attr_name, attr_value, strlen(attr_value), 0) < 0) {
        printf("  ✗ Failed to set attribute: %d\n", errno);
        remove(test_file);
        return -1;
    }
    
    /* Open file descriptor */
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        printf("  ✗ Failed to open file: %d\n", errno);
        brix_plat_removexattr(test_file, attr_name);
        remove(test_file);
        return -1;
    }
    
    /* List using fd */
    memset(buffer, 0, sizeof(buffer));
    result = brix_plat_flistxattr(fd, buffer, sizeof(buffer));
    
    close(fd);
    
    if (result > 0) {
        printf("  ✓ flistxattr returned %zd bytes\n", result);
        print_stream_list(buffer, result);
        
        /* Verify stream name */
        if (strstr(buffer, attr_name) != NULL) {
            printf("  ✓ Stream name found\n");
            brix_plat_removexattr(test_file, attr_name);
            remove(test_file);
            return 0;
        } else {
            printf("  ✗ Stream name not found\n");
        }
    } else {
        printf("  ✗ flistxattr failed: %zd\n", result);
    }
    
    /* Cleanup */
    brix_plat_removexattr(test_file, attr_name);
    remove(test_file);
    
    return (result > 0) ? 0 : -1;
}

/* Test 6: List on non-existent file */
static int
test_list_nonexistent(void)
{
    const char *test_file = "test_nonexistent.txt";
    char buffer[1024];
    ssize_t result;
    
    printf("Test 6: List on non-existent file\n");
    
    result = brix_plat_listxattr(test_file, buffer, sizeof(buffer));
    
    if (result < 0) {
        printf("  ✓ Correctly failed (errno=%d)\n", errno);
        return 0;
    } else {
        printf("  ✗ Should have failed, got %zd\n", result);
        return -1;
    }
}

int
main(int argc, char *argv[])
{
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    int result;
    
    printf("============================================================\n");
    printf("NTFS ADS Stream Enumeration Tests\n");
    printf("============================================================\n\n");
    
    /* Test 1: Empty file */
    result = test_list_empty_file();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    /* Test 2: Multiple streams */
    result = test_list_multiple_streams();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    /* Test 3: Size query */
    result = test_list_size_query();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    /* Test 4: Buffer too small */
    result = test_list_buffer_too_small();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    /* Test 5: File descriptor */
    result = test_flistxattr();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    /* Test 6: Non-existent file */
    result = test_list_nonexistent();
    if (result == 0) passed++;
    else if (result == 0) skipped++;
    else failed++;
    
    printf("\n============================================================\n");
    printf("Results: %d passed, %d failed, %d skipped\n", passed, failed, skipped);
    printf("============================================================\n");
    
    return (failed > 0) ? 1 : 0;
}
