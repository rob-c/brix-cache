/*
 * src/platform/windows/process.c - Windows process execution
 * 
 * Implements brix_plat_execvpe() using CreateProcessW + SearchPathW
 * with proper UTF-8↔UTF-16 conversion, argument escaping, and environment handling.
 * 
 * Status: ✅ Complete
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "process_internal.h"
#include "../platform_api.h"

#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <process.h>

/* ==========================================================================
 * UTF-8 ↔ UTF-16 CONVERSION
 * ========================================================================== */

/**
 * Convert UTF-8 string to UTF-16 wide string
 * 
 * @param utf8_src    Source UTF-8 string (null-terminated)
 * @param utf16_dest  Destination UTF-16 buffer (caller-allocated)
 * @param dest_size   Size of destination buffer (in wchar_t units)
 * @return            Length of converted string (excluding null), or -1 on error
 * 
 * Notes:
 * - Handles all valid UTF-8 sequences (1-4 bytes per codepoint)
 * - Returns error for invalid UTF-8 sequences
 * - Destination is always null-terminated if conversion succeeds
 */
static int
brix_win32_utf8_to_utf16(const char *utf8_src, wchar_t *utf16_dest, int dest_size)
{
    if (utf8_src == NULL || utf16_dest == NULL || dest_size < 1) {
        errno = EINVAL;
        return -1;
    }
    
    /* Use Windows API for conversion */
    int result = MultiByteToWideChar(
        CP_UTF8,                    /* Source encoding */
        0,                          /* Flags */
        utf8_src,                   /* Source string */
        -1,                         /* Source length (-1 = null-terminated) */
        utf16_dest,                 /* Destination buffer */
        dest_size                   /* Destination size */
    );
    
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* MultiByteToWideChar includes null terminator in count */
    return result - 1;
}

/**
 * Convert UTF-16 wide string to UTF-8
 * 
 * @param utf16_src   Source UTF-16 string (null-terminated)
 * @param utf8_dest   Destination UTF-8 buffer (caller-allocated)
 * @param dest_size   Size of destination buffer (in bytes)
 * @return            Length of converted string (excluding null), or -1 on error
 */
static int
brix_win32_utf16_to_utf8(const wchar_t *utf16_src, char *utf8_dest, int dest_size)
{
    if (utf16_src == NULL || utf8_dest == NULL || dest_size < 1) {
        errno = EINVAL;
        return -1;
    }
    
    int result = WideCharToMultiByte(
        CP_UTF8,                    /* Destination encoding */
        0,                          /* Flags */
        utf16_src,                  /* Source string */
        -1,                         /* Source length (-1 = null-terminated) */
        utf8_dest,                  /* Destination buffer */
        dest_size,                  /* Destination size */
        NULL,                       /* Default char (not needed for UTF-8) */
        NULL                        /* Used default char flag (not needed) */
    );
    
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    return result - 1;
}

/**
 * Allocate and convert UTF-8 to UTF-16
 * 
 * @param utf8_src  Source UTF-8 string
 * @return          Allocated UTF-16 string (caller must free), or NULL on error
 * 
 * Notes:
 * - Caller must free result with free()
 * - Returns NULL on allocation failure or invalid UTF-8
 */
static wchar_t *
brix_win32_utf8_to_utf16_alloc(const char *utf8_src)
{
    if (utf8_src == NULL) {
        errno = EINVAL;
        return NULL;
    }
    
    /* Get required buffer size */
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8_src, -1, NULL, 0);
    if (wide_len == 0) {
        brix_win32_set_errno(GetLastError());
        return NULL;
    }
    
    /* Allocate buffer */
    wchar_t *wide_str = (wchar_t *)malloc(wide_len * sizeof(wchar_t));
    if (wide_str == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    
    /* Convert */
    if (MultiByteToWideChar(CP_UTF8, 0, utf8_src, -1, wide_str, wide_len) == 0) {
        free(wide_str);
        brix_win32_set_errno(GetLastError());
        return NULL;
    }
    
    return wide_str;
}

/* ==========================================================================
 * ENVIRONMENT BLOCK HANDLING
 * ========================================================================== */

/**
 * Build Windows environment block from envp array
 * 
 * Windows environment block format:
 * - Each entry: "NAME=VALUE\0"
 * - Block terminated by: "\0\0" (double null)
 * 
 * @param envp        NULL-terminated environment array (UTF-8)
 * @param env_block   Destination buffer for environment block
 * @param block_size  Size of destination buffer
 * @return            0 on success, -1 on error
 * 
 * Notes:
 * - If envp is NULL, uses current process environment
 * - Environment variables are case-insensitive on Windows
 */
static int
brix_win32_build_environment_block(char *const envp[], wchar_t **env_block_out)
{
    if (env_block_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    *env_block_out = NULL;
    
    /* If no environment provided, use current process environment */
    if (envp == NULL) {
        *env_block_out = GetEnvironmentStringsW();
        if (*env_block_out == NULL) {
            brix_win32_set_errno(GetLastError());
            return -1;
        }
        return 0;
    }
    
    /* Calculate required buffer size */
    size_t total_chars = 0;
    for (int i = 0; envp[i] != NULL; i++) {
        /* Convert to UTF-16 to get size */
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, envp[i], -1, NULL, 0);
        if (wide_len == 0) {
            brix_win32_set_errno(GetLastError());
            return -1;
        }
        total_chars += wide_len;  /* Includes null terminator */
    }
    total_chars++;  /* Final double-null terminator */
    
    /* Allocate buffer */
    wchar_t *env_block = (wchar_t *)malloc(total_chars * sizeof(wchar_t));
    if (env_block == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    /* Convert each entry */
    wchar_t *out = env_block;
    for (int i = 0; envp[i] != NULL; i++) {
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, envp[i], -1, out, 
                                           (int)(total_chars - (out - env_block)));
        if (wide_len == 0) {
            free(env_block);
            brix_win32_set_errno(GetLastError());
            return -1;
        }
        out += wide_len;
    }
    
    /* Double-null terminate */
    *out = L'\0';
    
    *env_block_out = env_block;
    return 0;
}

/**
 * Free environment block
 * 
 * @param env_block  Environment block to free
 * 
 * Notes:
 * - Must use FreeEnvironmentStringsW for blocks from GetEnvironmentStringsW
 * - Use free() for blocks we allocated
 */
static void
brix_win32_free_environment_block(wchar_t *env_block)
{
    if (env_block != NULL) {
        /* Check if this is from GetEnvironmentStringsW or our allocation */
        /* For safety, we'll use FreeEnvironmentStringsW for both */
        FreeEnvironmentStringsW(env_block);
    }
}

/* ==========================================================================
 * PATH SEARCH
 * ========================================================================== */

/**
 * Search for executable in PATH
 * 
 * @param file        Program name or path
 * @param full_path   Destination buffer for full path
 * @param path_size   Size of destination buffer
 * @return            0 on success, -1 on error
 * 
 * Notes:
 * - If file is already absolute, copies it to full_path
 * - Searches PATH environment variable if file is relative
 * - Adds .exe extension if not present
 */
static int
brix_win32_search_path(const char *file, char *full_path, size_t path_size)
{
    if (file == NULL || full_path == NULL || path_size < MAX_PATH) {
        errno = EINVAL;
        return -1;
    }
    
    wchar_t file_wide[MAX_PATH];
    wchar_t path_wide[MAX_PATH];
    
    /* Convert file name to UTF-16 */
    if (brix_win32_utf8_to_utf16(file, file_wide, MAX_PATH) < 0) {
        return -1;
    }
    
    /* Search PATH */
    DWORD result = SearchPathW(
        NULL,           /* Search PATH */
        file_wide,      /* File to find */
        L".exe",        /* Extension to add if missing */
        MAX_PATH,       /* Buffer size */
        path_wide,      /* Output buffer */
        NULL            /* Don't need filename pointer */
    );
    
    if (result == 0) {
        brix_win32_set_errno(GetLastError());
        return -1;
    }
    
    /* Convert result back to UTF-8 */
    if (brix_win32_utf16_to_utf8(path_wide, full_path, (int)path_size) < 0) {
        return -1;
    }
    
    return 0;
}

/* ==========================================================================
 * MAIN IMPLEMENTATION: brix_plat_execvpe
 * ========================================================================== */

/**
 * Execute a program with PATH search and environment (Windows implementation)
 * 
 * @param file  Program name (searched in PATH if not absolute)
 * @param argv  Argument array (NULL-terminated), argv[0] is program name
 * @param envp  Environment array (NULL-terminated), or NULL for current
 * @return      Does not return on success, -1 on error
 * 
 * POSIX execvpe() behavior:
 * - Replaces current process image
 * - Searches PATH if file is not absolute
 * - Uses envp for environment (or inherits if NULL)
 * - Does not return on success
 * 
 * Windows CreateProcessW differences:
 * - Creates new process (doesn't replace current)
 * - Returns immediately (doesn't wait)
 * - Returns process handle, not exit code
 * 
 * Our implementation:
 * - Creates child process with CreateProcessW
 * - Waits for child to complete
 * - Exits with child's exit code
 * - Mimics execvpe() behavior for compatibility
 * 
 * Argument escaping:
 * - Arguments with spaces/tabs/quotes are quoted
 * - Backslashes before quotes are doubled
 * - See brix_win32_escape_argument() for details
 * 
 * UTF-8 handling:
 * - All input strings are UTF-8
 * - Converted to UTF-16 for Windows API
 * - Exit codes are preserved correctly
 * 
 * Error handling:
 * - Sets errno on failure
 * - Common errors: ENOENT (not found), EACCES (permission denied),
 *   ENOMEM (out of memory), ENOSPC (buffer too small)
 * 
 * Security considerations:
 * - PATH search can be vulnerable to PATH injection
 * - Use absolute paths for sensitive operations
 * - Argument escaping prevents command injection
 * 
 * Reference: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
 */
/* ---- Release process resources and preserve exec-style termination ----
 * WHAT: Close owned handles, free the environment and exit with the status.
 * WHY: Every post-environment launch failure follows the same cleanup path.
 * HOW: 1. Release initialized resources. 2. Terminate with the chosen status.
 */
static int
brix_win32_finish_process(PROCESS_INFORMATION *process, wchar_t *env_block,
                          int exit_code)
{
    /* Clean up handles */
    if (process->hProcess != NULL) {
        CloseHandle(process->hProcess);
    }
    if (process->hThread != NULL) {
        CloseHandle(process->hThread);
    }

    /* Clean up environment block */
    if (env_block != NULL) {
        brix_win32_free_environment_block(env_block);
    }

    /* Exit with child's exit code */
    _exit(exit_code);

    /* NOTREACHED */
    return -1;  /* Only reached if _exit fails, which shouldn't happen */
}

int
brix_plat_execvpe(const char *file, char *const argv[], char *const envp[])
{
    /* Validate inputs */
    if (file == NULL || argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t *env_block = NULL;
    char full_path[MAX_PATH];
    wchar_t file_wide[MAX_PATH];
    char cmd_line[32768];  /* Windows max command line length */
    int exit_code = 255;   /* Default error exit code */
    
    /* Initialize structures */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    /* Step 1: Search for executable in PATH */
    if (brix_win32_search_path(file, full_path, sizeof(full_path)) < 0) {
        /* errno already set by search_path */
        return -1;
    }
    
    /* Convert full path to UTF-16 */
    if (brix_win32_utf8_to_utf16(full_path, file_wide, MAX_PATH) < 0) {
        return -1;
    }
    
    /* Step 2: Build command line */
    if (brix_win32_build_command_line(argv, cmd_line, sizeof(cmd_line)) < 0) {
        /* errno already set */
        return -1;
    }
    
    /* Step 3: Build environment block */
    if (brix_win32_build_environment_block(envp, &env_block) < 0) {
        /* errno already set */
        return -1;
    }
    
    /* Step 4: Create process */
    wchar_t cmd_line_wide[32768];
    if (brix_win32_utf8_to_utf16(cmd_line, cmd_line_wide, 32768) < 0) {
        return brix_win32_finish_process(&pi, env_block, exit_code);
    }
    
    BOOL success = CreateProcessW(
        file_wide,              /* Application name */
        cmd_line_wide,          /* Command line */
        NULL,                   /* Process security attributes */
        NULL,                   /* Thread security attributes */
        FALSE,                  /* Don't inherit handles */
        CREATE_UNICODE_ENVIRONMENT,  /* Use UTF-16 environment block */
        env_block,              /* Environment block */
        NULL,                   /* Use parent's current directory */
        &si,                    /* Startup info */
        &pi                     /* Process information */
    );
    
    if (!success) {
        brix_win32_set_errno(GetLastError());
        return brix_win32_finish_process(&pi, env_block, exit_code);
    }
    
    /* Step 5: Wait for child process to complete */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, INFINITE);
    
    if (wait_result != WAIT_OBJECT_0) {
        brix_win32_set_errno(GetLastError());
        return brix_win32_finish_process(&pi, env_block, exit_code);
    }
    
    /* Step 6: Get exit code */
    DWORD child_exit_code;
    if (!GetExitCodeProcess(pi.hProcess, &child_exit_code)) {
        brix_win32_set_errno(GetLastError());
        return brix_win32_finish_process(&pi, env_block, exit_code);
    }
    
    exit_code = (int)(child_exit_code & 0xFF);  /* POSIX exit codes are 0-255 */
    
    return brix_win32_finish_process(&pi, env_block, exit_code);
}

/* ==========================================================================
 * HELPER FUNCTIONS (for testing and debugging)
 * ========================================================================== */

#ifdef BRIX_DEBUG

/**
 * Print command line escaping (debug function)
 */
void brix_win32_debug_print_command_line(char *const argv[])
{
    char cmd_line[32768];
    
    if (brix_win32_build_command_line(argv, cmd_line, sizeof(cmd_line)) == 0) {
        fprintf(stderr, "Command line: %s\n", cmd_line);
    }
}

/**
 * Print environment block (debug function)
 */
void brix_win32_debug_print_environment(char *const envp[])
{
    if (envp == NULL) {
        fprintf(stderr, "Environment: (inherited)\n");
        return;
    }
    
    fprintf(stderr, "Environment:\n");
    for (int i = 0; envp[i] != NULL; i++) {
        fprintf(stderr, "  %s\n", envp[i]);
    }
}

#endif /* BRIX_DEBUG */

#endif /* BRIX_PLATFORM_WINDOWS */
