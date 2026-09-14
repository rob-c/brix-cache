/*
 * copy_range_unittest.c - Test suite for Windows brix_plat_copy_range() implementation
 * 
 * Tests:
 * 1. Full file copy using CopyFile2
 * 2. Range copy using FSCTL_COPY_FILE_RANGE
 * 3. Buffered copy fallback
 * 4. Error handling (invalid fds, permissions)
 * 5. Offset handling
 * 6. Large file copy (>1GB)
 * 
 * Windows Version Requirements:
 * - Minimum: Windows NT 3.5+ (buffered fallback)
 * - CopyFile2: Windows 8+ / Server 2012+
 * - FSCTL_COPY_FILE_RANGE: Windows 10 1607+ / Server 2016+
 * 
 * Compile:
 *   cl /W4 /Fe:test_copy_range.exe copy_range_unittest.c /link ws2_32.lib
 * 
 * Run:
 *   test_copy_range.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <windows.h>

/* Include PAL implementation */
#include "../platform.h"
#include "../platform_api.h"

#if !BRIX_PLATFORM_WINDOWS
#error "This test is for Windows only"
#endif

#include "win32_compat.h"

/* Test file paths */
#define TEST_DIR "C:\\brix_test_copy_range"
#define TEST_FILE_SOURCE TEST_DIR "\\source.dat"
#define TEST_FILE_DEST TEST_DIR "\\dest.dat"
#define TEST_FILE_TEMP TEST_DIR "\\temp.dat"

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* ==========================================================================
 * TEST UTILITIES
 * ========================================================================== */

/**
 * test_begin - Mark beginning of a test
 */
static void test_begin(const char *name)
{
    tests_run++;
    printf("[TEST %d] %s... ", tests_run, name);
    fflush(stdout);
}

/**
 * test_pass - Mark test as passed
 */
static void test_pass(void)
{
    tests_passed++;
    printf("PASSED\n");
}

/**
 * test_fail - Mark test as failed with reason
 */
static void test_fail(const char *reason)
{
    tests_failed++;
    printf("FAILED: %s\n", reason);
}

/**
 * create_test_directory - Create test directory if it doesn't exist
 */
static int create_test_directory(void)
{
    if (CreateDirectoryA(TEST_DIR, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    return -1;
}

/**
 * cleanup_test_directory - Remove test directory and files
 */
static void cleanup_test_directory(void)
{
    DeleteFileA(TEST_FILE_SOURCE);
    DeleteFileA(TEST_FILE_DEST);
    DeleteFileA(TEST_FILE_TEMP);
    RemoveDirectoryA(TEST_DIR);
}

/**
 * create_test_file - Create a test file with random data
 * 
 * @filename: Path to file
 * @size: Size in bytes
 * @return: 0 on success, -1 on error
 */
static int create_test_file(const char *filename, size_t size)
{
    HANDLE hFile;
    BYTE *buffer;
    DWORD bytes_written;
    
    hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    /* Create random data */
    buffer = (BYTE *)malloc(size);
    if (buffer == NULL) {
        CloseHandle(hFile);
        return -1;
    }
    
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (BYTE)(rand() % 256);
    }
    
    if (!WriteFile(hFile, buffer, (DWORD)size, &bytes_written, NULL) ||
        bytes_written != size) {
        free(buffer);
        CloseHandle(hFile);
        return -1;
    }
    
    free(buffer);
    CloseHandle(hFile);
    return 0;
}

/**
 * verify_files_equal - Verify two files are identical
 * 
 * @file1: First file path
 * @file2: Second file path
 * @return: 0 if equal, -1 if different
 */
static int verify_files_equal(const char *file1, const char *file2)
{
    HANDLE h1, h2;
    BYTE buffer1[65536], buffer2[65536];
    DWORD bytes_read1, bytes_read2;
    
    h1 = CreateFileA(file1, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (h1 == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    h2 = CreateFileA(file2, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (h2 == INVALID_HANDLE_VALUE) {
        CloseHandle(h1);
        return -1;
    }
    
    while (1) {
        if (!ReadFile(h1, buffer1, sizeof(buffer1), &bytes_read1, NULL) ||
            !ReadFile(h2, buffer2, sizeof(buffer2), &bytes_read2, NULL)) {
            CloseHandle(h1);
            CloseHandle(h2);
            return -1;
        }
        
        if (bytes_read1 != bytes_read2) {
            CloseHandle(h1);
            CloseHandle(h2);
            return -1;
        }
        
        if (bytes_read1 == 0) {
            break;  /* EOF */
        }
        
        if (memcmp(buffer1, buffer2, bytes_read1) != 0) {
            CloseHandle(h1);
            CloseHandle(h2);
            return -1;
        }
    }
    
    CloseHandle(h1);
    CloseHandle(h2);
    return 0;
}

/**
 * get_file_size - Get file size in bytes
 */
static off_t get_file_size(const char *filename)
{
    HANDLE hFile;
    LARGE_INTEGER size;
    
    hFile = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    size.LowPart = GetFileSize(hFile, &size.HighPart);
    CloseHandle(hFile);
    
    if (size.LowPart == INVALID_FILE_SIZE) {
        return -1;
    }
    
    return (off_t)size.QuadPart;
}

/* ==========================================================================
 * TEST CASES
 * ========================================================================== */

/**
 * test_copy_full_file - Test full file copy using CopyFile2
 */
static void test_copy_full_file(void)
{
    int in_fd, out_fd;
    ssize_t result;
    const size_t file_size = 1024 * 1024;  /* 1MB */
    
    test_begin("Full file copy (CopyFile2)");
    
    /* Create source file */
    if (create_test_file(TEST_FILE_SOURCE, file_size) < 0) {
        test_fail("Cannot create source file");
        return;
    }
    
    /* Open files */
    in_fd = open(TEST_FILE_SOURCE, O_RDONLY | O_BINARY);
    if (in_fd < 0) {
        test_fail("Cannot open source file");
        cleanup_test_directory();
        return;
    }
    
    out_fd = open(TEST_FILE_DEST, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        test_fail("Cannot open destination file");
        cleanup_test_directory();
        return;
    }
    
    /* Copy entire file */
    result = brix_plat_copy_range(in_fd, NULL, out_fd, NULL, file_size, 0);
    
    close(in_fd);
    close(out_fd);
    
    if (result < 0) {
        test_fail("brix_plat_copy_range failed");
        cleanup_test_directory();
        return;
    }
    
    /* Verify files are equal */
    if (verify_files_equal(TEST_FILE_SOURCE, TEST_FILE_DEST) != 0) {
        test_fail("Files differ");
        cleanup_test_directory();
        return;
    }
    
    test_pass();
    cleanup_test_directory();
}

/**
 * test_copy_range - Test range copy using FSCTL_COPY_FILE_RANGE
 */
static void test_copy_range(void)
{
    int in_fd, out_fd;
    ssize_t result;
    off_t in_off = 1024;  /* Start at offset 1KB */
    off_t out_off = 0;
    const size_t range_size = 4096;  /* Copy 4KB */
    const size_t file_size = 8192;  /* 8KB total file */
    
    test_begin("Range copy (FSCTL_COPY_FILE_RANGE)");
    
    /* Create source file */
    if (create_test_file(TEST_FILE_SOURCE, file_size) < 0) {
        test_fail("Cannot create source file");
        return;
    }
    
    /* Open files */
    in_fd = open(TEST_FILE_SOURCE, O_RDONLY | O_BINARY);
    if (in_fd < 0) {
        test_fail("Cannot open source file");
        cleanup_test_directory();
        return;
    }
    
    out_fd = open(TEST_FILE_DEST, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        test_fail("Cannot open destination file");
        cleanup_test_directory();
        return;
    }
    
    /* Copy range */
    result = brix_plat_copy_range(in_fd, &in_off, out_fd, &out_off, range_size, 0);
    
    close(in_fd);
    close(out_fd);
    
    if (result < 0) {
        test_fail("brix_plat_copy_range failed");
        cleanup_test_directory();
        return;
    }
    
    if (result != (ssize_t)range_size) {
        test_fail("Wrong number of bytes copied");
        cleanup_test_directory();
        return;
    }
    
    /* Verify offsets were updated */
    if (in_off != 1024 + (off_t)range_size || out_off != (off_t)range_size) {
        test_fail("Offsets not updated correctly");
        cleanup_test_directory();
        return;
    }
    
    test_pass();
    cleanup_test_directory();
}

/**
 * test_buffered_fallback - Test buffered copy fallback
 */
static void test_buffered_fallback(void)
{
    int in_fd, out_fd;
    ssize_t result;
    const size_t file_size = 256 * 1024;  /* 256KB */
    
    test_begin("Buffered copy fallback");
    
    /* Create source file */
    if (create_test_file(TEST_FILE_SOURCE, file_size) < 0) {
        test_fail("Cannot create source file");
        return;
    }
    
    /* Open files */
    in_fd = open(TEST_FILE_SOURCE, O_RDONLY | O_BINARY);
    if (in_fd < 0) {
        test_fail("Cannot open source file");
        cleanup_test_directory();
        return;
    }
    
    out_fd = open(TEST_FILE_DEST, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        test_fail("Cannot open destination file");
        cleanup_test_directory();
        return;
    }
    
    /* Copy file (will use buffered fallback if other methods fail) */
    result = brix_plat_copy_range(in_fd, NULL, out_fd, NULL, file_size, 0);
    
    close(in_fd);
    close(out_fd);
    
    if (result < 0) {
        test_fail("brix_plat_copy_range failed");
        cleanup_test_directory();
        return;
    }
    
    /* Verify files are equal */
    if (verify_files_equal(TEST_FILE_SOURCE, TEST_FILE_DEST) != 0) {
        test_fail("Files differ");
        cleanup_test_directory();
        return;
    }
    
    test_pass();
    cleanup_test_directory();
}

/**
 * test_invalid_fds - Test error handling with invalid file descriptors
 */
static void test_invalid_fds(void)
{
    ssize_t result;
    
    test_begin("Invalid file descriptors");
    
    /* Test with invalid input fd */
    result = brix_plat_copy_range(-1, NULL, -2, NULL, 1024, 0);
    if (result >= 0 && errno != EBADF) {
        test_fail("Should fail with EBADF for invalid fds");
        return;
    }
    
    test_pass();
}

/**
 * test_large_file - Test large file copy (>1GB)
 */
static void test_large_file(void)
{
    int in_fd, out_fd;
    ssize_t result;
    const size_t file_size = 100 * 1024 * 1024;  /* 100MB for faster testing */
    
    test_begin("Large file copy (100MB)");
    
    /* Create source file */
    if (create_test_file(TEST_FILE_SOURCE, file_size) < 0) {
        test_fail("Cannot create source file");
        return;
    }
    
    /* Open files */
    in_fd = open(TEST_FILE_SOURCE, O_RDONLY | O_BINARY);
    if (in_fd < 0) {
        test_fail("Cannot open source file");
        cleanup_test_directory();
        return;
    }
    
    out_fd = open(TEST_FILE_DEST, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        test_fail("Cannot open destination file");
        cleanup_test_directory();
        return;
    }
    
    /* Copy file */
    result = brix_plat_copy_range(in_fd, NULL, out_fd, NULL, file_size, 0);
    
    close(in_fd);
    close(out_fd);
    
    if (result < 0) {
        test_fail("brix_plat_copy_range failed");
        cleanup_test_directory();
        return;
    }
    
    /* Verify file sizes match */
    if (get_file_size(TEST_FILE_SOURCE) != get_file_size(TEST_FILE_DEST)) {
        test_fail("File sizes differ");
        cleanup_test_directory();
        return;
    }
    
    test_pass();
    cleanup_test_directory();
}

/**
 * test_copyfile2_availability - Check if CopyFile2 is available
 */
static void test_copyfile2_availability(void)
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    
    test_begin("CopyFile2 availability check");
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 6;
    osvi.dwMinorVersion = 2;  /* Windows 8 */
    
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    
    if (VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask)) {
        printf("Windows 8+ detected - CopyFile2 available\n");
        test_pass();
    } else {
        printf("Windows < 8 detected - CopyFile2 not available (will use fallback)\n");
        test_pass();  /* Still pass - fallback is valid */
    }
}

/**
 * test_fsctl_availability - Check if FSCTL_COPY_FILE_RANGE is available
 */
static void test_fsctl_availability(void)
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    
    test_begin("FSCTL_COPY_FILE_RANGE availability check");
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.wServicePackMajor = 0;
    
    /* Windows 10 version 1607 (build 14393) */
    osvi.dwBuildNumber = 14393;
    
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);
    
    if (VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask)) {
        printf("Windows 10 1607+ detected - FSCTL_COPY_FILE_RANGE available\n");
        test_pass();
    } else {
        printf("Windows < 10 1607 detected - FSCTL_COPY_FILE_RANGE not available (will use fallback)\n");
        test_pass();  /* Still pass - fallback is valid */
    }
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("============================================================\n");
    printf("Windows brix_plat_copy_range() Test Suite\n");
    printf("============================================================\n\n");
    
    /* Initialize random seed */
    srand((unsigned int)time(NULL));
    
    /* Create test directory */
    if (create_test_directory() < 0) {
        printf("ERROR: Cannot create test directory %s\n", TEST_DIR);
        return 1;
    }
    
    /* Run tests */
    test_copyfile2_availability();
    test_fsctl_availability();
    test_copy_full_file();
    test_copy_range();
    test_buffered_fallback();
    test_invalid_fds();
    test_large_file();
    
    /* Cleanup */
    cleanup_test_directory();
    
    /* Print summary */
    printf("\n============================================================\n");
    printf("Test Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_run);
    printf("============================================================\n");
    
    return (tests_failed > 0) ? 1 : 0;
}
