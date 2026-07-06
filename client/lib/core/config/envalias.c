/*
 * envalias.c — shared env-var alias resolver (spec WS-1 change 1.1).
 *
 * WHAT: brix_env_resolve() walks a NULL-terminated alias chain, returns the
 *       first-set value, and fires a TTY-gated note when two names in the
 *       chain are set to DIFFERENT values.
 * WHY:  legacy env names (XrdSec*) remain accepted forever (C2 compat); this
 *       module is the single place that implements precedence so callers never
 *       hand-roll duplicate chains.
 * HOW:  Linear scan; remember first-set name+value; on each subsequent set
 *       entry compare values — on divergence call brix_cli_hint_once with the
 *       canonical key (chain[0]) and the two names.  Values are NEVER printed
 *       (secrets protection).  Return the winner (first-set).
 */
#include "core/config/envalias.h"
#include "cli/cli_hint.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

const char *
brix_env_resolve(const char *const *chain, const char **which)
{
    /*
     * WHAT: first-set-wins resolver with divergence detection.
     * WHY:  canonical name (chain[0]) takes precedence; any set legacy name is
     *       still accepted; a mismatch is flagged once per process per chain so
     *       users can correct their environment.
     * HOW:  two passes in one loop — winner_val/winner_name track the first set
     *       entry; differ_name tracks the first DIFFERING second entry so we can
     *       emit the note with both names.
     */
    const char *winner_val  = NULL;
    const char *winner_name = NULL;
    const char *differ_name = NULL;
    int         i;

    for (i = 0; chain[i] != NULL; i++) {
        const char *val = getenv(chain[i]);

        if (val == NULL) {
            continue;
        }

        if (winner_val == NULL) {
            /* First set entry — record as the winner. */
            winner_val  = val;
            winner_name = chain[i];
            continue;
        }

        /* A second set entry: check for divergence. */
        if (differ_name == NULL && strcmp(winner_val, val) != 0) {
            differ_name = chain[i];
        }
    }

    /* Emit a TTY-gated note if two variables carry different values. */
    if (differ_name != NULL) {
        brix_cli_hint_once(chain[0],
            "note: both %s and %s are set and differ; using %s (see brix-env(7))\n",
            winner_name, differ_name, winner_name);
    }

    if (which != NULL) {
        *which = winner_name;
    }
    return winner_val;
}
