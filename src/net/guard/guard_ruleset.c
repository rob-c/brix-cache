/*
 * guard_ruleset.c — guard ruleset construction.
 *
 * WHAT: builders that populate a guard_ruleset_t: zero-init, the built-in
 *   junk-scanner signature set, operator-supplied signatures/prefixes, and
 *   per-profile grammar defaults ("arc" | "xrdhttp" | "root").
 * WHY:  adapters (nginx http module, stream relay) assemble rulesets at config
 *   time from directives; the assembly logic itself is protocol-agnostic and
 *   lives here, next to the classifier that consumes it.
 * HOW:  pure C, no allocation — patterns are borrowed pointers that must
 *   outlive the ruleset (string literals or nginx conf-pool strings).
 */
#include "guard.h"
#include <string.h>

/* ---- Zero a ruleset ----
 *
 * WHAT: resets every field of *rs to zero (no signatures, no prefixes, no ops
 *   allowed, grammar not enforced, outcome flags off).
 *
 * WHY: gives adapters one canonical empty state to build on, so a
 *   half-initialized ruleset can never classify.
 *
 * HOW: 1. memset the whole struct.
 */
void
guard_ruleset_init(guard_ruleset_t *rs)
{
    memset(rs, 0, sizeof(*rs));
}
