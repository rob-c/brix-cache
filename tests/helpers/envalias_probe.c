/*
 * envalias_probe.c — minimal probe for the PTY hint tests.
 *
 * WHAT: call brix_env_resolve() with a test chain so tests/test_cli_hints.py
 *       can observe the divergence note without spinning up a real server.
 * WHY:  brix_env_resolve() is a library function; a standalone binary is the
 *       smallest possible harness.
 * HOW:  reads TEST_ENVALIAS_CANON / TEST_ENVALIAS_LEGACY from the environment,
 *       calls brix_env_resolve, prints nothing to stdout, exits 0.  The
 *       divergence note (if any) goes to stderr via brix_cli_hint_once.
 *
 * Usage: envalias_probe diverge
 *   Env: TEST_ENVALIAS_CANON  — canonical name's value (optional)
 *        TEST_ENVALIAS_LEGACY — legacy name's value (optional)
 *        BRIX_NO_HINTS        — suppress hints when set to non-"0"
 */
#include "core/config/envalias.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    static const char *const chain[] = {
        "TEST_ENVALIAS_CANON", "TEST_ENVALIAS_LEGACY", NULL
    };

    if (argc < 2 || strcmp(argv[1], "diverge") != 0) {
        fprintf(stderr, "usage: envalias_probe diverge\n");
        return 1;
    }

    brix_env_resolve(chain, NULL);
    return 0;
}
