/*
 * token/ini.c — minimal INI parser (see ini.h).
 *
 * WHAT: Reads an INI file and dispatches every `key = value` line to a caller
 *       callback, tracking the current `[section]`. Used to parse the upstream
 *       SciTokens `scitokens.cfg` grammar (issuer_registry.c) and the throttle
 *       userconfig file (Phase-59 W3a), so both share one auditable reader.
 * WHY:  XRootD ships these as INI files; parsing the grammar verbatim lets an
 *       operator point us at their existing config unchanged (phase-59 ADR-1).
 * HOW:  Line-buffered fgets; strip comments + surrounding whitespace; `[name]`
 *       updates the section; `key = value` splits on the first `=` and invokes
 *       the callback. Pure C, no nginx runtime — unit-testable standalone.
 */

#include "ini.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

/* ini_lstrip — advance past leading ASCII whitespace */static char *
ini_lstrip(char *s)
{
    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }
    return s;
}

/* ini_rstrip — trim trailing ASCII whitespace in place */static void
ini_rstrip(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && isspace((unsigned char) s[n - 1])) {
        s[--n] = '\0';
    }
}

/* ini_trim — strip both ends, returning a pointer into the buffer */static char *
ini_trim(char *s)
{
    s = ini_lstrip(s);
    ini_rstrip(s);
    return s;
}

/* ini_drop_comment — terminate the line at the first # or ; comment */static void
ini_drop_comment(char *s)
{
    char *p;

    for (p = s; *p != '\0'; p++) {
        if (*p == '#' || *p == ';') {
            *p = '\0';
            return;
        }
    }
}

/* ini_section — parse "[name]" into out; returns 0 on success */static int
ini_section(char *s, char *out, size_t outsz)
{
    char *end;
    char *name;

    end = strchr(s, ']');
    if (end == NULL) {
        return -1;
    }
    *end = '\0';
    name = ini_trim(s + 1);
    if (*name == '\0') {
        return -1;
    }
    snprintf(out, outsz, "%s", name);
    return 0;
}

/* xrootd_ini_parse_file — parse path, dispatch each key line */int
xrootd_ini_parse_file(const char *path, xrootd_ini_cb cb, void *user,
    char *errbuf, size_t errlen)
{
    FILE *f;
    char  line[1024];
    char  section[64] = "";
    int   rc = 0;
    int   lineno = 0;

    f = fopen(path, "re");                  /* 'e' = O_CLOEXEC */
    if (f == NULL) {
        snprintf(errbuf, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *s;
        char *eq;

        lineno++;
        ini_drop_comment(line);
        s = ini_trim(line);
        if (*s == '\0') {
            continue;
        }
        if (*s == '[') {
            if (ini_section(s, section, sizeof(section)) != 0) {
                snprintf(errbuf, errlen, "%s:%d: bad section header",
                    path, lineno);
                rc = -1;
                break;
            }
            continue;
        }
        eq = strchr(s, '=');
        if (eq == NULL) {
            snprintf(errbuf, errlen, "%s:%d: missing '='", path, lineno);
            rc = -1;
            break;
        }
        *eq = '\0';
        rc = cb(user, section, ini_trim(s), ini_trim(eq + 1));
        if (rc != 0) {
            snprintf(errbuf, errlen, "%s:%d: rejected key", path, lineno);
            break;
        }
    }

    fclose(f);
    return rc;
}
