/* Windows command-line byte serialization, independent of process launch.
 * Keeping the pure quoting logic separate allows native unit validation.
 */
#include "process_internal.h"
#include <errno.h>
#include <string.h>

/* ==========================================================================
 * ARGUMENT ESCAPING
 * ========================================================================== */

/**
 * Escape a single argument for Windows command line
 *
 * Windows command line parsing rules (from Microsoft documentation):
 *
 * 1. Arguments are separated by spaces
 * 2. Arguments containing spaces, tabs, or quotes must be quoted
 * 3. Backslashes are interpreted literally, UNLESS followed by a quote:
 *    - N backslashes + quote → N/2 backslashes + quote (if N even)
 *    - N backslashes + quote → (N-1)/2 backslashes + escaped quote (if N odd)
 * 4. A quote preceded by an odd number of backslashes becomes literal
 * 5. Double quotes within quoted arguments must be escaped with backslash
 *
 * This function implements the correct escaping for CreateProcessW.
 *
 * @param arg         Source argument (no escaping)
 * @param escaped     Destination buffer for escaped argument
 * @param dest_size   Size of destination buffer
 * @return            0 on success, -1 on error (buffer too small)
 *
 * Reference: https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
 */
/* ---- Append repeated bytes without consuming the terminator slot ----
 * WHAT: Return zero after appending, or -1/ENOSPC when it will not fit.
 * WHY: Quoting and backslash runs use the same exact capacity rule.
 * HOW: 1. Check the remaining capacity. 2. Append and advance the cursor.
 */
static int
brix_win32_append_escaped(char *output, size_t capacity, size_t *used,
                         char value, size_t count)
{
    if (count >= capacity - *used) {
        errno = ENOSPC;
        return -1;
    }
    memset(output + *used, value, count);
    *used += count;
    return 0;
}

int
brix_win32_escape_argument(const char *arg, char *escaped, size_t dest_size)
{
    if (arg == NULL || escaped == NULL || dest_size == 0) {
        errno = EINVAL;
        return -1;
    }

    if (strpbrk(arg, " \t\"\\") == NULL) {
        if (strlen(arg) >= dest_size) {
            errno = ENOSPC;
            return -1;
        }
        strcpy(escaped, arg);
        return 0;
    }

    size_t out_idx = 0;
    if (brix_win32_append_escaped(escaped, dest_size, &out_idx, '"', 1) < 0) {
        return -1;
    }
    for (const char *cursor = arg; *cursor != '\0'; cursor++) {
        size_t backslashes = 0;
        while (*cursor == '\\') {
            backslashes++;
            cursor++;
        }
        if (*cursor == '"') {
            backslashes = backslashes * 2 + 1;
        } else if (*cursor == '\0') {
            backslashes *= 2;
        }
        if (brix_win32_append_escaped(escaped, dest_size, &out_idx,
                                     '\\', backslashes) < 0) {
            return -1;
        }
        if (*cursor == '\0') {
            break;
        }
        if (brix_win32_append_escaped(escaped, dest_size, &out_idx,
                                     *cursor, 1) < 0) {
            return -1;
        }
    }
    if (brix_win32_append_escaped(escaped, dest_size, &out_idx, '"', 1) < 0) {
        return -1;
    }
    escaped[out_idx] = '\0';
    return 0;
}

/**
 * Build Windows command line from argv array
 *
 * @param argv        NULL-terminated argument array (UTF-8)
 * @param cmd_line    Destination buffer for command line
 * @param cmd_size    Size of destination buffer
 * @return            0 on success, -1 on error
 *
 * Notes:
 * - argv[0] is the program name (not included in command line)
 * - Arguments are space-separated
 * - Each argument is properly escaped
 */
int
brix_win32_build_command_line(char *const argv[], char *cmd_line, size_t cmd_size)
{
    if (argv == NULL || cmd_line == NULL || cmd_size == 0) {
        errno = EINVAL;
        return -1;
    }

    cmd_line[0] = '\0';
    size_t remaining = cmd_size - 1;
    char *out = cmd_line;
    int first_arg = 1;

    for (int i = 0; argv[i] != NULL; i++) {
        /* Add space between arguments */
        if (!first_arg) {
            if (remaining < 1) {
                errno = ENOSPC;
                return -1;
            }
            *out++ = ' ';
            remaining--;
        }
        first_arg = 0;

        /* Escape and append argument */
        char escaped_arg[4096];  /* Max argument length */
        if (brix_win32_escape_argument(argv[i], escaped_arg, sizeof(escaped_arg)) < 0) {
            return -1;
        }

        size_t arg_len = strlen(escaped_arg);
        if (arg_len >= remaining) {
            errno = ENOSPC;
            return -1;
        }

        memcpy(out, escaped_arg, arg_len);
        out += arg_len;
        remaining -= arg_len;
    }

    *out = '\0';
    return 0;
}
