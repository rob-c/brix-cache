/* Windows command-line serialization. Requires: no prior headers.
 * These pure byte-string operations do not call the Windows API.
 */
#pragma once
#include <stddef.h>
int brix_win32_escape_argument(const char *arg, char *escaped, size_t dest_size);
int brix_win32_build_command_line(char *const argv[], char *cmd_line,
                                 size_t cmd_size);
