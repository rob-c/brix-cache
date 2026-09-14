/* Process execution.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * PROCESS EXECUTION
 *
 * Process creation and management.
 * ========================================================================== */

/**
 * Execute a program with PATH search and environment
 *
 * Linux: execvpe()
 * macOS: posix_spawn() emulation
 * Windows: CreateProcessW() + SearchPathW()
 *
 * Windows Implementation:
 * - Uses SearchPathW() to locate executable in PATH
 * - Converts UTF-8 arguments to UTF-16 via MultiByteToWideChar()
 * - Builds command line with proper escaping (Microsoft rules)
 * - Creates process via CreateProcessW()
 * - Waits for child process, propagates exit code
 * - Calls _exit() with child's exit code
 * - Does not return on success (mimics execvpe behavior)
 *
 * Note: Does not return on success (replaces current process).
 *
 * @param file Program name (searched in PATH if not absolute)
 * @param argv Argument array (NULL-terminated)
 * @param envp Environment array (NULL-terminated, or NULL for current)
 * @return Does not return on success, -1 on error
 */
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[]);
