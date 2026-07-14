/*
 * idmap_gridmap.c — grid-mapfile (DN -> local username) parse/load/lookup.
 *
 * WHAT: Parses the classic grid-mapfile (each line: "<quoted DN>" <username>)
 *   once at init into a small array of (quoted-DN, username) pairs, and answers
 *   exact-DN lookups against it.  Split out of idmap.c (file-size cap).
 *
 * WHY: This is a pure, self-contained text-parsing concern with no dependency on
 *   the numeric mapping policy or the deny-lists — it only feeds a candidate
 *   username to the resolver.
 *
 * HOW: The mapfile table (idmap_gridmap[]) is private to this translation unit;
 *   only idmap_gridmap_load()/idmap_gridmap_lookup() cross the boundary (declared
 *   in idmap_internal.h).  No goto; pure helpers, side effects at the edges.
 */

#include "impersonate.h"
#include "core/compat/cstr.h"
#include "idmap_internal.h"

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


typedef struct {
    char *dn;                           /* malloc'd quoted-DN key */
    char *user;                         /* malloc'd local username */
} idmap_gridmap_entry_t;

static idmap_gridmap_entry_t  *idmap_gridmap;       /* NULL = no mapfile */
static size_t                  idmap_gridmap_n;


/* Free any previously-loaded grid-mapfile table. */
static void
idmap_gridmap_free(void)
{
    size_t i;

    if (idmap_gridmap == NULL) {
        return;
    }
    for (i = 0; i < idmap_gridmap_n; i++) {
        free(idmap_gridmap[i].dn);
        free(idmap_gridmap[i].user);
    }
    free(idmap_gridmap);
    idmap_gridmap   = NULL;
    idmap_gridmap_n = 0;
}

/* Skip leading spaces/tabs; returns the first non-blank position. */
static const char *
idmap_skip_blanks(const char *p)
{
    while (*p == ' ' || *p == '\t') { p++; }
    return p;
}

/*
 * Scan the leading "<quoted DN>" field of a grid-mapfile line.  Comments (#),
 * blank lines, unquoted and unterminated DNs are all "no field here".  Pure
 * scan: on success sets [*start, *end) to the DN bytes (quotes excluded),
 * advances *pp past the closing quote, and returns 1; returns 0 to skip.
 */
static int
idmap_scan_quoted_dn(const char **pp, const char **start, const char **end)
{
    const char *p = idmap_skip_blanks(*pp);

    if (*p != '"') {
        return 0;                       /* comment, blank, or unquoted -> skip */
    }
    *start = ++p;                       /* after the opening quote */
    while (*p != '"' && *p != '\0' && *p != '\n') { p++; }
    if (*p != '"') {
        return 0;                       /* unterminated quote -> skip */
    }
    *end = p;                           /* at closing quote */
    *pp  = p + 1;
    return 1;
}

/*
 * Scan the local-username field that follows the DN.  Pure scan: sets
 * [*start, *end) to the token and advances *pp; returns 1 on a non-empty
 * username, 0 when the field is missing.
 */
static int
idmap_scan_username(const char **pp, const char **start, const char **end)
{
    const char *p = idmap_skip_blanks(*pp);

    *start = p;
    while (*p != '\0' && *p != '\n' && *p != ' ' && *p != '\t') { p++; }
    *end = p;
    *pp  = p;
    return *end != *start;
}

/*
 * Parse one grid-mapfile line of the classic form:
 *     "<quoted DN>" <local-username>
 * Comments (#) and blank lines are skipped.  Returns 1 and fills the two out
 * params (malloc'd) on a usable mapping, 0 to skip the line, -1 on OOM.
 */
static int
idmap_gridmap_parse_line(const char *line, char **dn_out, char **user_out)
{
    const char *p = line;
    const char *dn_start, *dn_end, *u_start, *u_end;

    if (!idmap_scan_quoted_dn(&p, &dn_start, &dn_end)
        || !idmap_scan_username(&p, &u_start, &u_end)
        || (size_t) (dn_end - dn_start) >= IDMAP_PRINC_MAX)
    {
        return 0;                       /* unusable line -> skip */
    }

    *dn_out   = strndup(dn_start, (size_t) (dn_end - dn_start));
    *user_out = strndup(u_start, (size_t) (u_end - u_start));
    if (*dn_out == NULL || *user_out == NULL) {
        free(*dn_out);
        free(*user_out);
        return -1;
    }
    return 1;
}

/* Load the grid-mapfile at `path` into idmap_gridmap[].  Returns NGX_OK (incl.
 * the "no path" case) or NGX_ERROR on IO/OOM. */
ngx_int_t
idmap_gridmap_load(const char *path, ngx_log_t *log)
{
    FILE   *fp;
    char    line[1024];
    size_t  cap = 0;

    idmap_gridmap_free();
    if (path == NULL || path[0] == '\0') {
        return NGX_OK;                  /* no mapfile configured */
    }

    fp = fopen(path, "re");
    if (fp == NULL) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "impersonate: cannot open grid-mapfile \"%s\"", path);
        }
        return NGX_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *dn = NULL, *user = NULL;
        int   r = idmap_gridmap_parse_line(line, &dn, &user);

        if (r < 0) {
            /* phase72-fp: read-only stream — fclose result carries no data loss */
            (void) fclose(fp);
            idmap_gridmap_free();
            return NGX_ERROR;
        }
        if (r == 0) {
            continue;
        }
        if (idmap_gridmap_n == cap) {
            size_t                 ncap = cap ? cap * 2 : 16;
            idmap_gridmap_entry_t *ne =
                realloc(idmap_gridmap, ncap * sizeof(*ne));
            if (ne == NULL) {
                free(dn); free(user);
                /* phase72-fp: read-only stream — fclose result carries no data loss */
                (void) fclose(fp);
                idmap_gridmap_free();
                return NGX_ERROR;
            }
            idmap_gridmap = ne;
            cap = ncap;
        }
        idmap_gridmap[idmap_gridmap_n].dn   = dn;
        idmap_gridmap[idmap_gridmap_n].user = user;
        idmap_gridmap_n++;
    }
    /* phase72-fp: read-only stream — fclose result carries no data loss */
    (void) fclose(fp);

    if (log != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "impersonate: loaded %uz grid-mapfile entries from \"%s\"",
                      idmap_gridmap_n, path);
    }
    return NGX_OK;
}

/* Look up a DN in the grid-mapfile; returns the local username or NULL. */
const char *
idmap_gridmap_lookup(const char *dn)
{
    size_t i;

    for (i = 0; i < idmap_gridmap_n; i++) {
        if (strcmp(idmap_gridmap[i].dn, dn) == 0) {
            return idmap_gridmap[i].user;
        }
    }
    return NULL;
}
