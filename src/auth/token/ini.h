#ifndef BRIX_TOKEN_INI_H
#define BRIX_TOKEN_INI_H

#include <stddef.h>

/*
 * token/ini.h — minimal INI parser shared by the SciTokens issuer registry
 * (issuer_registry.c) and the throttle per-user config (Phase-59 W3a).
 *
 * Grammar: `[section]` headers, `key = value` lines, `#`/`;` comments, blank
 * lines ignored. Pure C — no nginx runtime dependency, so it is unit-testable
 * standalone (see tests + the §EE design in the phase-59 plan).
 */

/*
 * Per key/value callback. Invoked once per `key = value` line with the current
 * section name (empty string before the first [section]). Return 0 to continue
 * parsing, non-zero to abort the parse early with that return code.
 */
typedef int (*brix_ini_cb)(void *user, const char *section,
    const char *key, const char *value);

/*
 * Parse the INI file at `path`, invoking `cb(user, section, key, value)` per
 * key line. On a parse/IO error returns -1 and fills errbuf (which must be at
 * least errlen bytes); on success returns 0. A non-zero return from `cb`
 * aborts and is propagated as the return value.
 */
int brix_ini_parse_file(const char *path, brix_ini_cb cb, void *user,
    char *errbuf, size_t errlen);

#endif /* BRIX_TOKEN_INI_H */
