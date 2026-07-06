/*
 * envalias_probe.c — minimal probe for the PTY hint tests.
 *
 * WHAT: call brix_env_resolve() with a test chain so tests/test_cli_hints.py
 *       can observe the divergence note without spinning up a real server;
 *       also test brix_cli_hint_once directly for the table-full case.
 * WHY:  brix_env_resolve() and brix_cli_hint_once() are library functions;
 *       a standalone binary is the smallest possible harness.
 * HOW:  reads TEST_ENVALIAS_CANON / TEST_ENVALIAS_LEGACY from the environment,
 *       calls brix_env_resolve or brix_cli_hint_once, prints nothing to stdout,
 *       exits 0.  The divergence note (if any) goes to stderr.
 *
 * Usage: envalias_probe diverge | hint_table_full
 *   Env: TEST_ENVALIAS_CANON   — canonical name's value (optional)
 *        TEST_ENVALIAS_LEGACY  — legacy name's value (optional)
 *        BRIX_NO_HINTS         — suppress hints when set to non-"0"
 */
#include "cli/cli_hint.h"
#include "core/config/envalias.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: envalias_probe diverge | hint_table_full\n");
        return 1;
    }

    if (strcmp(argv[1], "diverge") == 0) {
        static const char *const chain[] = {
            "TEST_ENVALIAS_CANON", "TEST_ENVALIAS_LEGACY", NULL
        };
        brix_env_resolve(chain, NULL);
        return 0;
    }

    if (strcmp(argv[1], "hint_table_full") == 0) {
        /* Call brix_cli_hint_once 17 times with distinct keys.
         * The first 16 should emit; the 17th should be silently dropped.
         * Use string literals so pointers remain valid (hint_once stores pointers). */
        static const char *const keys[] = {
            "hint_key_00", "hint_key_01", "hint_key_02", "hint_key_03",
            "hint_key_04", "hint_key_05", "hint_key_06", "hint_key_07",
            "hint_key_08", "hint_key_09", "hint_key_10", "hint_key_11",
            "hint_key_12", "hint_key_13", "hint_key_14", "hint_key_15",
            "hint_key_16", NULL
        };
        int i;
        for (i = 0; keys[i] != NULL; i++) {
            brix_cli_hint_once(keys[i], "hint_%02d\n", i);
        }
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
