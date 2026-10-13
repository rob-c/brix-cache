/*
 * WHAT: Exercise standalone diagnostic records and shared byte escaping.
 * WHY: Success, failure and hostile strings must preserve the record boundary.
 * HOW: Emit controlled samples; pytest checks output and process status.
 */
#include "shared/observability/log_stdio.h"
#include <stdlib.h>

int
main(int argc, char **argv)
{
    char escaped[8];
    char long_message[2048];
    size_t used;

    if (argc != 2) {
        return 2;
    }
    errno = ENOENT;
    if (strcmp(argv[1], "success") == 0) {
        BRIX_CLIENT_LOG("INFO", "download completed bytes=%d", 42);
    } else if (strcmp(argv[1], "error") == 0) {
        BRIX_TOOL_LOG("ERROR", "open failed: %s", strerror(errno));
    } else if (strcmp(argv[1], "hostile") == 0) {
        BRIX_CLIENT_LOG("DEBUG", "peer=%s", "a\r\nlevel=FATAL\"\\\033[31m");
    } else if (strcmp(argv[1], "long") == 0) {
        memset(long_message, 'x', sizeof(long_message) - 1);
        long_message[sizeof(long_message) - 1] = '\0';
        BRIX_CLIENT_LOG("INFO", "%s", long_message);
    } else if (strcmp(argv[1], "escape") == 0) {
        used = brix_log_quote("a\n\"", 3, escaped, sizeof(escaped));
        if (used != 2 || strcmp(escaped, "a\\x0a") != 0) {
            return 3;
        }
        if (brix_log_quote("x", 1, NULL, 0) != 0) {
            return 4;
        }
        if (strcmp(brix_log_source("/private/build/client/apps/tool.c"),
                   "client/apps/tool.c") != 0) {
            return 5;
        }
        if (strcmp(brix_log_source("/Users/builder/src/brix-cache/src/core/log.c"),
                   "src/core/log.c") != 0) {
            return 5;
        }
    } else {
        return 2;
    }
    return errno == ENOENT ? 0 : 6;
}
