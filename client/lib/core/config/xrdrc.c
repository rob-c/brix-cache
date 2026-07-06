/*
 * xrdrc.c — ~/.xrdrc endpoint aliases (the start of the "just works" UX engine).
 *
 * WHAT: brix_alias_resolve() turns "name:suffix" into the full URL configured for
 *       that alias, so users can write `xrdcp lab:/data/f.root .` instead of the
 *       long root://host:port//data/... form.
 * WHY:  A swiss-army-knife toolkit should let staff/students name their endpoints
 *       once and never retype host/port/scheme. This is additive: anything that is
 *       not a known alias passes through verbatim, so existing usage is unchanged.
 * HOW:  An optional ini-style file at $XRDRC (else ~/.xrdrc), parsed once and cached:
 *         [alias NAME]
 *         url = root://se.lab.example:1094//data
 *       Resolution: split the arg at the first ':'; if the prefix names an alias and
 *       the suffix is not "//..." (which would be a scheme), the result is the alias
 *       URL joined to the suffix with exactly one '/'.
 *
 * Clean-room; no external config library.
 */
#include "brix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDRC_MAX_ALIASES 256
#define XRDRC_NAME_MAX     64

typedef struct {
    char name[XRDRC_NAME_MAX];
    char url[XRDC_PATH_MAX];
    /* optional per-endpoint credentials */
    char token[8192];                 /* inline bearer token */
    char token_file[XRDC_PATH_MAX];   /* …or a file to read the token from */
    char s3_access[256];
    char s3_secret[256];
    char s3_region[64];
    char proxy[XRDC_PATH_MAX];
} xrdrc_alias;

static xrdrc_alias g_aliases[XRDRC_MAX_ALIASES];
static int         g_nalias = 0;
static int         g_loaded = 0;

/* Parsed [defaults] keys — 0 means "not set". Only positive integers are stored;
 * negative/garbage values are intentionally ignored so they cannot silently become
 * giant unsigned timeouts in the callers. */
static int g_def_connect_ms = 0;
static int g_def_io_ms      = 0;
static int g_def_stall_ms   = 0;
static int g_def_backoff_ms = 0;

/* Trim trailing whitespace/newline in place. */
static void
rstrip(char *s)
{
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) {
        *--e = '\0';
    }
}

/* Load $XRDRC (else ~/.xrdrc) once into g_aliases. Missing file → no aliases. */
static void
xrdrc_load(void)
{
    char        path[XRDC_PATH_MAX];
    const char *p = getenv("XRDRC");
    FILE       *f;
    /* Big enough to hold an inline `token = <jwt>` line whole — WLCG SciTokens
     * routinely exceed 2 KB, and the token field is 8 KB; a smaller line buffer
     * would silently truncate the credential. */
    char        line[8192 + 256];
    int         cur = -1;       /* current [alias N] index, or -1 */
    int         in_defaults = 0; /* 1 while parsing the [defaults] section */

    g_loaded = 1;
    if (p != NULL && p[0] != '\0') {
        snprintf(path, sizeof(path), "%s", p);
    } else {
        const char *home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            return;
        }
        snprintf(path, sizeof(path), "%s/.xrdrc", home);
    }
    f = fopen(path, "r");
    if (f == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *s = line;
        while (*s == ' ' || *s == '\t') { s++; }
        rstrip(s);
        if (*s == '\0' || *s == '#') {
            continue;
        }
        if (*s == '[') {
            cur = -1;
            in_defaults = 0;
            if (strcmp(s, "[defaults]") == 0) {
                in_defaults = 1;
            } else if (strncmp(s, "[alias ", 7) == 0) {
                char *nm = s + 7;
                char *rb = strchr(nm, ']');
                if (rb != NULL) { *rb = '\0'; }
                while (*nm == ' ') { nm++; }
                if (*nm != '\0' && g_nalias < XRDRC_MAX_ALIASES) {
                    cur = g_nalias++;
                    snprintf(g_aliases[cur].name, sizeof(g_aliases[cur].name), "%s", nm);
                    g_aliases[cur].url[0] = '\0';
                }
            }
            continue;
        }
        /* key = value lines */
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            continue;
        }
        char *k = s, *v = eq + 1, *ke = eq;
        *eq = '\0';
        while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t')) { *--ke = '\0'; }
        while (*v == ' ' || *v == '\t') { v++; }

        if (in_defaults) {
            /* Parse positive integers only — negative/non-numeric are silently
             * ignored so they cannot become giant unsigned timeouts. */
            char  *end;
            long   n = strtol(v, &end, 10);
            int    valid = (*v != '\0' && *end == '\0' && n > 0);
            if (strcmp(k, "connect_timeout_ms") == 0) {
                if (valid) { g_def_connect_ms = (int) n; }
            } else if (strcmp(k, "io_timeout_ms") == 0) {
                if (valid) { g_def_io_ms = (int) n; }
            } else if (strcmp(k, "max_stall_ms") == 0) {
                if (valid) { g_def_stall_ms = (int) n; }
            } else if (strcmp(k, "backoff_base_ms") == 0) {
                if (valid) { g_def_backoff_ms = (int) n; }
            }
        } else if (cur >= 0) {
            if (strcmp(k, "url") == 0) {
                snprintf(g_aliases[cur].url, sizeof(g_aliases[cur].url), "%s", v);
            } else if (strcmp(k, "token") == 0) {
                snprintf(g_aliases[cur].token, sizeof(g_aliases[cur].token), "%s", v);
            } else if (strcmp(k, "token_file") == 0 || strcmp(k, "bearer_token_file") == 0) {
                snprintf(g_aliases[cur].token_file, sizeof(g_aliases[cur].token_file), "%s", v);
            } else if (strcmp(k, "s3_access") == 0) {
                snprintf(g_aliases[cur].s3_access, sizeof(g_aliases[cur].s3_access), "%s", v);
            } else if (strcmp(k, "s3_secret") == 0) {
                snprintf(g_aliases[cur].s3_secret, sizeof(g_aliases[cur].s3_secret), "%s", v);
            } else if (strcmp(k, "s3_region") == 0) {
                snprintf(g_aliases[cur].s3_region, sizeof(g_aliases[cur].s3_region), "%s", v);
            } else if (strcmp(k, "proxy") == 0) {
                snprintf(g_aliases[cur].proxy, sizeof(g_aliases[cur].proxy), "%s", v);
            }
        }
    }
    fclose(f);
}

int
brix_alias_resolve(const char *arg, char *out, size_t outsz)
{
    const char *colon;
    size_t      nlen;
    char        name[XRDRC_NAME_MAX];
    int         i;

    if (!g_loaded) {
        xrdrc_load();
    }
    snprintf(out, outsz, "%s", arg);   /* default: pass through verbatim */

    colon = strchr(arg, ':');
    if (colon == NULL) {
        return 0;
    }
    nlen = (size_t) (colon - arg);
    if (nlen == 0 || nlen >= sizeof(name)) {
        return 0;
    }
    if (colon[1] == '/' && colon[2] == '/') {
        return 0;   /* "scheme://…" — a URL, not an alias */
    }
    memcpy(name, arg, nlen);
    name[nlen] = '\0';

    for (i = 0; i < g_nalias; i++) {
        if (strcmp(g_aliases[i].name, name) == 0 && g_aliases[i].url[0] != '\0') {
            const char *base = g_aliases[i].url;
            const char *suffix = colon + 1;
            size_t      bl = strlen(base);
            int         base_slash = (bl > 0 && base[bl - 1] == '/');
            int         suf_slash = (suffix[0] == '/');
            if (base_slash && suf_slash) {
                snprintf(out, outsz, "%s%s", base, suffix + 1);   /* drop one '/' */
            } else if (!base_slash && !suf_slash) {
                snprintf(out, outsz, "%s/%s", base, suffix);       /* add the '/' */
            } else {
                snprintf(out, outsz, "%s%s", base, suffix);        /* exactly one */
            }
            return 1;
        }
    }
    return 0;
}

/* Read the first non-empty line of `path` into out[outsz] (trimmed). 0 / -1. */
static int
read_first_line(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "r");
    char  line[8192];
    out[0] = '\0';
    if (f == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *s = line;
        while (*s == ' ' || *s == '\t') { s++; }
        rstrip(s);
        if (*s != '\0') {
            snprintf(out, outsz, "%s", s);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

int
brix_alias_lookup(const char *name, brix_alias_info *info)
{
    int i;
    if (info == NULL) {
        return 0;
    }
    memset(info, 0, sizeof(*info));
    if (!g_loaded) {
        xrdrc_load();
    }
    for (i = 0; i < g_nalias; i++) {
        if (strcmp(g_aliases[i].name, name) == 0) {
            const xrdrc_alias *a = &g_aliases[i];
            info->found = 1;
            snprintf(info->s3_access, sizeof(info->s3_access), "%s", a->s3_access);
            snprintf(info->s3_secret, sizeof(info->s3_secret), "%s", a->s3_secret);
            snprintf(info->s3_region, sizeof(info->s3_region), "%s", a->s3_region);
            snprintf(info->proxy, sizeof(info->proxy), "%s", a->proxy);
            if (a->token[0] != '\0') {
                snprintf(info->bearer, sizeof(info->bearer), "%s", a->token);
            } else if (a->token_file[0] != '\0') {
                snprintf(info->token_file, sizeof(info->token_file), "%s", a->token_file);
                if (read_first_line(a->token_file, info->bearer, sizeof(info->bearer)) != 0
                    || info->bearer[0] == '\0') {
                    info->token_file_failed = 1;   /* unreadable or empty — caller warns */
                }
            }
            return 1;
        }
    }
    return 0;
}

/*
 * brix_xrdrc_default_ms — look up a [defaults] timeout key from ~/.xrdrc.
 *
 * WHAT: Returns 1 and sets *out_ms when the [defaults] section of the user's
 *       .xrdrc file carries `key` with a valid positive integer; returns 0
 *       otherwise (key absent, value non-numeric, or value <= 0).
 * WHY:  Allows users and operators to tune network timeouts once in ~/.xrdrc
 *       rather than through environment variables in every shell profile.
 *       Sits below the env-var layer so $XRDC_* and CLI flags always win.
 * HOW:  Ensures the file is loaded via the same lazy-load gate the alias
 *       lookups use, then maps `key` to one of the four parsed static ints.
 *       Negative and non-numeric values are intentionally rejected at parse
 *       time so they are never stored and can never be returned here.
 */
int
brix_xrdrc_default_ms(const char *key, int *out_ms)
{
    if (!g_loaded) {
        xrdrc_load();
    }
    if (strcmp(key, "connect_timeout_ms") == 0 && g_def_connect_ms > 0) {
        *out_ms = g_def_connect_ms;
        return 1;
    }
    if (strcmp(key, "io_timeout_ms") == 0 && g_def_io_ms > 0) {
        *out_ms = g_def_io_ms;
        return 1;
    }
    if (strcmp(key, "max_stall_ms") == 0 && g_def_stall_ms > 0) {
        *out_ms = g_def_stall_ms;
        return 1;
    }
    if (strcmp(key, "backoff_base_ms") == 0 && g_def_backoff_ms > 0) {
        *out_ms = g_def_backoff_ms;
        return 1;
    }
    return 0;
}
