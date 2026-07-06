#ifndef BRIX_ENVALIAS_H
#define BRIX_ENVALIAS_H
/*
 * envalias.h — shared env-var alias resolver (spec WS-1 change 1.1).
 *
 * WHAT: walk a NULL-terminated chain of env-var names in precedence order,
 *       return the first set value, and emit a TTY-gated note when two or
 *       more names in the chain are set to DIFFERENT values.
 * WHY:  centralises all alias resolution so the single-point-of-truth rule
 *       holds: legacy names (XrdSec*) remain accepted forever (C2) while
 *       canonical XRDC_* names take higher precedence.
 * HOW:  see brix_env_resolve() below.
 */

/*
 * Walk chain[] (NULL-terminated, highest-precedence first) and return the
 * value of the first set variable.  On return *which (if non-NULL) is the
 * name of the winning variable.
 *
 * Divergence rule: if two or more members of the chain are set to DIFFERENT
 * values, brix_cli_hint_once(chain[0], ...) emits a TTY-gated note naming
 * both variables and the winner.  Only variable NAMES are printed — never
 * values (no secret leakage).  If all set members agree (same value) no note
 * is emitted.
 *
 * Returns NULL when no chain member is set.
 */
const char *brix_env_resolve(const char *const *chain, const char **which);

#endif /* BRIX_ENVALIAS_H */
