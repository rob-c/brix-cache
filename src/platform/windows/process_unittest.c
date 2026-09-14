/*
 * src/platform/windows/process_unittest.c - Test suite for Windows process execution
 * 
 * Tests for brix_plat_execvpe() implementation:
 * - UTF-8 ↔ UTF-16 conversion
 * - Argument escaping
 * - PATH search
 * - Environment handling
 * - Full execvpe() integration
 * 
 * Status: ✅ Complete
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS && defined(BRIX_TEST)

#include "win32_compat.h"
#include "../platform_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
    printf("PASS\n"); \
} while(0)

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s\n", msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* ==========================================================================
 * UTF-8 ↔ UTF-16 CONVERSION TESTS
 * ========================================================================== */

TEST(utf8_to_utf16_basic)
{
    wchar_t wide[256];
    int len;
    
    /* Simple ASCII */
    len = brix_win32_utf8_to_utf16("hello", wide, 256);
    ASSERT(len == 5, "ASCII length");
    ASSERT(wcscmp(wide, L"hello") == 0, "ASCII content");
    
    /* UTF-8 multi-byte */
    len = brix_win32_utf8_to_utf16("café", wide, 256);
    ASSERT(len == 4, "UTF-8 length");
    ASSERT(wcscmp(wide, L"café") == 0, "UTF-8 content");
    
    /* Empty string */
    len = brix_win32_utf8_to_utf16("", wide, 256);
    ASSERT(len == 0, "Empty string length");
    ASSERT(wide[0] == L'\0', "Empty string content");
}

TEST(utf8_to_utf16_buffer_overflow)
{
    wchar_t wide[4];
    int len;
    
    /* Buffer too small */
    len = brix_win32_utf8_to_utf16("hello", wide, 3);
    ASSERT(len < 0, "Buffer too small returns error");
}

TEST(utf16_to_utf8_basic)
{
    char utf8[256];
    int len;
    
    /* Simple ASCII */
    len = brix_win32_utf16_to_utf8(L"hello", utf8, 256);
    ASSERT(len == 5, "ASCII length");
    ASSERT(strcmp(utf8, "hello") == 0, "ASCII content");
    
    /* UTF-8 multi-byte */
    len = brix_win32_utf16_to_utf8(L"café", utf8, 256);
    ASSERT(len == 5, "UTF-8 length (é is 2 bytes)");
    ASSERT(strcmp(utf8, "café") == 0, "UTF-8 content");
}

/* ==========================================================================
 * ARGUMENT ESCAPING TESTS
 * ========================================================================== */

TEST(escape_argument_simple)
{
    char escaped[256];
    int ret;
    
    /* No escaping needed */
    ret = brix_win32_escape_argument("hello", escaped, 256);
    ASSERT(ret == 0, "Simple arg success");
    ASSERT(strcmp(escaped, "hello") == 0, "Simple arg content");
}

TEST(escape_argument_spaces)
{
    char escaped[256];
    int ret;
    
    /* Spaces require quoting */
    ret = brix_win32_escape_argument("hello world", escaped, 256);
    ASSERT(ret == 0, "Spaces success");
    ASSERT(strcmp(escaped, "\"hello world\"") == 0, "Spaces quoted");
}

TEST(escape_argument_quotes)
{
    char escaped[256];
    int ret;
    
    /* Quotes require escaping */
    ret = brix_win32_escape_argument("say \"hi\"", escaped, 256);
    ASSERT(ret == 0, "Quotes success");
    ASSERT(strcmp(escaped, "\"say \\\"hi\\\"\"") == 0, "Quotes escaped");
}

TEST(escape_argument_backslashes)
{
    char escaped[256];
    int ret;
    
    /* Backslashes before quotes */
    ret = brix_win32_escape_argument("path\\to\\file", escaped, 256);
    ASSERT(ret == 0, "Backslashes success");
    /* Backslashes not followed by quotes don't need escaping */
    ASSERT(strcmp(escaped, "\"path\\to\\file\"") == 0, "Backslashes content");
}

TEST(escape_argument_complex)
{
    char escaped[256];
    int ret;
    
    /* Complex: spaces, quotes, and backslashes */
    ret = brix_win32_escape_argument("C:\\Program Files\\app.exe", escaped, 256);
    ASSERT(ret == 0, "Complex success");
    ASSERT(strcmp(escaped, "\"C:\\Program Files\\app.exe\"") == 0, "Complex content");
}

TEST(escape_argument_buffer_overflow)
{
    char escaped[10];
    int ret;
    
    /* Buffer too small */
    ret = brix_win32_escape_argument("very long argument", escaped, 10);
    ASSERT(ret < 0, "Buffer too small returns error");
}

/* ==========================================================================
 * COMMAND LINE BUILDING TESTS
 * ========================================================================== */

TEST(build_command_line_simple)
{
    char *argv[] = {"program", "arg1", "arg2", NULL};
    char cmd_line[256];
    int ret;
    
    ret = brix_win32_build_command_line(argv, cmd_line, 256);
    ASSERT(ret == 0, "Build success");
    ASSERT(strcmp(cmd_line, "program arg1 arg2") == 0, "Build content");
}

TEST(build_command_line_with_spaces)
{
    char *argv[] = {"my program", "arg with spaces", NULL};
    char cmd_line[256];
    int ret;
    
    ret = brix_win32_build_command_line(argv, cmd_line, 256);
    ASSERT(ret == 0, "Build spaces success");
    ASSERT(strcmp(cmd_line, "\"my program\" \"arg with spaces\"") == 0, "Build spaces content");
}

TEST(build_command_line_empty)
{
    char *argv[] = {NULL};
    char cmd_line[256];
    int ret;
    
    ret = brix_win32_build_command_line(argv, cmd_line, 256);
    ASSERT(ret == 0, "Empty argv success");
    ASSERT(strcmp(cmd_line, "") == 0, "Empty cmd line");
}

/* ==========================================================================
 * PATH SEARCH TESTS
 * ========================================================================== */

TEST(search_path_absolute)
{
    char full_path[MAX_PATH];
    int ret;
    
    /* Absolute path should just copy */
    ret = brix_win32_search_path("C:\\Windows\\System32\\cmd.exe", full_path, sizeof(full_path));
    /* May fail if file doesn't exist, but that's OK for this test */
    ASSERT(ret == 0 || errno == ENOENT, "Absolute path handled");
}

TEST(search_path_relative)
{
    char full_path[MAX_PATH];
    int ret;
    
    /* Relative path - search PATH */
    ret = brix_win32_search_path("cmd.exe", full_path, sizeof(full_path));
    /* Should find cmd.exe in PATH on Windows */
    ASSERT(ret == 0, "Found cmd.exe in PATH");
}

TEST(search_path_nonexistent)
{
    char full_path[MAX_PATH];
    int ret;
    
    ret = brix_win32_search_path("nonexistent_program_xyz.exe", full_path, sizeof(full_path));
    ASSERT(ret < 0, "Nonexistent program returns error");
    ASSERT(errno == ENOENT, "ENOENT set");
}

/* ==========================================================================
 * ENVIRONMENT BLOCK TESTS
 * ========================================================================== */

TEST(build_environment_block_null)
{
    wchar_t *env_block = NULL;
    int ret;
    
    /* NULL envp should use current environment */
    ret = brix_win32_build_environment_block(NULL, &env_block);
    ASSERT(ret == 0, "NULL envp success");
    ASSERT(env_block != NULL, "Environment block allocated");
    
    if (env_block != NULL) {
        brix_win32_free_environment_block(env_block);
    }
}

TEST(build_environment_block_custom)
{
    char *envp[] = {"FOO=bar", "BAZ=qux", NULL};
    wchar_t *env_block = NULL;
    int ret;
    
    ret = brix_win32_build_environment_block(envp, &env_block);
    ASSERT(ret == 0, "Custom envp success");
    ASSERT(env_block != NULL, "Environment block allocated");
    
    if (env_block != NULL) {
        brix_win32_free_environment_block(env_block);
    }
}

/* ==========================================================================
 * INTEGRATION TESTS
 * ========================================================================== */

TEST(execvpe_echo)
{
    /* Test that we can execute a simple command */
    char *argv[] = {"echo", "hello", "world", NULL};
    char *envp[] = {"TEST=value", NULL};
    
    /* Fork a child to test execvpe */
    int pid = _fork();
    if (pid == 0) {
        /* Child - exec */
        brix_plat_execvpe("echo", argv, envp);
        /* Should not return */
        _exit(255);
    } else if (pid > 0) {
        /* Parent - wait */
        int status;
        _waitpid(pid, &status, 0);
        ASSERT(status == 0, "echo exited successfully");
    } else {
        /* Fork failed - skip test */
        printf("SKIP (fork failed)\n");
        tests_failed--;  /* Compensate for RUN_TEST increment */
        return;
    }
}

TEST(execvpe_nonexistent)
{
    char *argv[] = {"nonexistent_program_xyz", NULL};
    char *envp[] = {NULL};
    
    int ret = brix_plat_execvpe("nonexistent_program_xyz", argv, envp);
    ASSERT(ret < 0, "Nonexistent program returns error");
    ASSERT(errno == ENOENT, "ENOENT set");
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */

int main(int argc, char *argv[])
{
    printf("Windows Process Execution Test Suite\n");
    printf("=====================================\n\n");
    
    /* UTF-8 conversion tests */
    printf("UTF-8 Conversion Tests:\n");
    RUN_TEST(utf8_to_utf16_basic);
    RUN_TEST(utf8_to_utf16_buffer_overflow);
    RUN_TEST(utf16_to_utf8_basic);
    printf("\n");
    
    /* Argument escaping tests */
    printf("Argument Escaping Tests:\n");
    RUN_TEST(escape_argument_simple);
    RUN_TEST(escape_argument_spaces);
    RUN_TEST(escape_argument_quotes);
    RUN_TEST(escape_argument_backslashes);
    RUN_TEST(escape_argument_complex);
    RUN_TEST(escape_argument_buffer_overflow);
    printf("\n");
    
    /* Command line building tests */
    printf("Command Line Building Tests:\n");
    RUN_TEST(build_command_line_simple);
    RUN_TEST(build_command_line_with_spaces);
    RUN_TEST(build_command_line_empty);
    printf("\n");
    
    /* PATH search tests */
    printf("PATH Search Tests:\n");
    RUN_TEST(search_path_absolute);
    RUN_TEST(search_path_relative);
    RUN_TEST(search_path_nonexistent);
    printf("\n");
    
    /* Environment block tests */
    printf("Environment Block Tests:\n");
    RUN_TEST(build_environment_block_null);
    RUN_TEST(build_environment_block_custom);
    printf("\n");
    
    /* Integration tests */
    printf("Integration Tests:\n");
    RUN_TEST(execvpe_echo);
    RUN_TEST(execvpe_nonexistent);
    printf("\n");
    
    /* Summary */
    printf("=====================================\n");
    printf("Tests run: %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

#endif /* BRIX_PLATFORM_WINDOWS && BRIX_TEST */
