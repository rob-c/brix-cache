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


/* Stock XRD_* names brix honors (nettmo.c aliases) or owns outright — the
 * unsupported-variable note must not fire for these. */
static const char *const brix_env_xrd_known[] = {
    "XRD_CONNECTIONWINDOW",   /* → connect timeout (nettmo.c)            */
    "XRD_REQUESTTIMEOUT",     /* → io timeout (nettmo.c)                 */
    "XRD_STREAMTIMEOUT",      /* → stall deadline (nettmo.c)             */
    "XRD_MOUNTINFO_PATH",     /* brix-owned (xrd mount test override)    */
    NULL,
};

void
brix_env_warn_stock_unsupported(void)
{
    /*
     * WHAT: one-shot scan of environ for set-but-unsupported stock XRD_*
     *       variables; emits a single TTY-gated note listing up to six names.
     * WHY:  the stock client honors ~40 XRD_* keys; a drop-in user whose
     *       XRD_LOGLEVEL / XRD_CPRETRY / … silently does nothing gets exactly
     *       the surprise the parity audit (§7.10) flags. Making the ignore
     *       LOUD (on a TTY; scripts keep byte-identical output per the C3
     *       gate) turns a silent hazard into an actionable one.
     * HOW:  static once-guard, then a linear environ walk: names starting
     *       "XRD_" and not in brix_env_xrd_known are collected into one
     *       comma-separated note (names only, never values). Bounded copy per
     *       name; the note fires through brix_cli_hint_once under one key.
     */
    extern char **environ;
    static int    warned = 0;
    char          names[256];
    size_t        used = 0;
    int           listed = 0, extra = 0, i, j;

    if (warned) {
        return;
    }
    warned = 1;

    names[0] = '\0';
    for (i = 0; environ[i] != NULL; i++) {
        const char *entry = environ[i];
        const char *eq    = strchr(entry, '=');
        size_t      nlen  = (eq != NULL) ? (size_t) (eq - entry) : strlen(entry);
        int         known = 0;

        if (nlen < 4 || strncmp(entry, "XRD_", 4) != 0) {
            continue;
        }
        for (j = 0; brix_env_xrd_known[j] != NULL; j++) {
            if (nlen == strlen(brix_env_xrd_known[j])
                && strncmp(entry, brix_env_xrd_known[j], nlen) == 0)
            {
                known = 1;
                break;
            }
        }
        if (known) {
            continue;
        }
        if (listed >= 6 || used + nlen + 3 >= sizeof(names)) {
            extra++;
            continue;
        }
        if (listed > 0) {
            names[used++] = ',';
            names[used++] = ' ';
        }
        memcpy(names + used, entry, nlen);
        used += nlen;
        names[used] = '\0';
        listed++;
    }

    if (listed == 0) {
        return;
    }
    if (extra > 0) {
        brix_cli_hint_once("xrd-env",
            "note: stock XRootD variable(s) %s (+%d more) are set but not "
            "supported by brix-client (see brix-env(7))\n", names, extra);
    } else {
        brix_cli_hint_once("xrd-env",
            "note: stock XRootD variable(s) %s are set but not supported by "
            "brix-client (see brix-env(7))\n", names);
    }
}
