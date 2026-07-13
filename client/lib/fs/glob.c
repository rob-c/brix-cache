/*
 * glob.c — client-side wildcard expansion for root:// URLs.
 *
 * WHAT: brix_glob() expands a root:// URL whose final path component contains glob
 *       metacharacters (* ? [) into the list of matching full URLs.
 * WHY:  The XRootD wire protocol has no server-side globbing for transfer/metadata
 *       ops, so a "swiss-army-knife" client must expand patterns itself and hide
 *       that from the user — a quoted wildcard source just works.
 * HOW:  Parse the URL, split the path into <dir>/<pattern>, open one connection,
 *       dirlist <dir>, fnmatch each entry against <pattern> (FNM_PERIOD so '*' does
 *       not match dotfiles, mirroring the shell), and rebuild a full URL per match.
 *
 * Scope: single-level (the wildcard must be in the LAST path component); multi-level
 * patterns (a wildcard in a non-final component) are not expanded. Clean-room.
 */
#include "brix.h"

#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>

/* 1 if `s` contains a glob metacharacter. */
int
brix_has_glob(const char *s)
{
    return s != NULL && strpbrk(s, "*?[") != NULL;
}

/*
 * Parsed <dir>/<pattern> split of a glob URL's path, plus the pre-computed URL
 * rebuild pieces (scheme name, IPv6 host brackets, directory separator).
 */
typedef struct {
    char        dir[XRDC_PATH_MAX];
    char        pattern[XRDC_NAME_MAX];
    const char *scheme;   /* "root" / "roots" */
    const char *hb, *he;  /* IPv6 host bracket prefix/suffix ("" when not v6) */
    const char *dsep;     /* "" if dir already ends in '/', else "/" */
} glob_spec;

/*
 * WHAT: Validate a parsed glob URL and split its path into dir + last-component
 *       pattern, filling `sp` with everything the collect loop needs.
 * WHY:  Isolates all the pure parse/validate/reject logic (scheme check, path
 *       split, length limits, wildcard presence) from the I/O + match loop so the
 *       orchestrator stays flat and each rejection keeps its exact status string.
 * HOW:  Reject non-root schemes, find the last '/', copy the trailing component as
 *       the pattern (rejecting over-length or wildcard-free), copy the leading part
 *       as dir (defaulting to "/"), then precompute the URL-rebuild pieces. Returns
 *       0 on success, -1 with `st` set on any rejection. No behavior change.
 */
static int
glob_parse_spec(const brix_url *u, glob_spec *sp, brix_status *st)
{
    const char *slash;
    size_t      dlen;

    if (u->scheme != XRDC_SCHEME_ROOT && u->scheme != XRDC_SCHEME_ROOTS) {
        brix_status_set(st, XRDC_EUSAGE, 0, "glob: only root:// URLs are expanded");
        return -1;
    }
    slash = strrchr(u->path, '/');
    if (slash == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "glob: malformed path");
        return -1;
    }
    if (strlen(slash + 1) >= sizeof(sp->pattern)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "glob: pattern too long");
        return -1;   /* reject — never truncate (a clipped wildcard mis-matches) */
    }
    memcpy(sp->pattern, slash + 1, strlen(slash + 1) + 1);
    if (!brix_has_glob(sp->pattern)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "glob: no wildcard in last path component");
        return -1;
    }
    dlen = (size_t) (slash - u->path);
    if (dlen == 0) {
        sp->dir[0] = '/';
        sp->dir[1] = '\0';
    } else {
        if (dlen >= sizeof(sp->dir)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "glob: directory path too long");
            return -1;
        }
        memcpy(sp->dir, u->path, dlen);
        sp->dir[dlen] = '\0';
    }

    sp->scheme = (u->scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    {
        int v6 = (strchr(u->host, ':') != NULL);   /* IPv6 literal */
        sp->hb = v6 ? "[" : "";
        sp->he = v6 ? "]" : "";
    }
    sp->dsep = (sp->dir[0] != '\0' && sp->dir[strlen(sp->dir) - 1] == '/') ? "" : "/";
    return 0;
}

/*
 * WHAT: Test one dirlist entry against the pattern and, on a match, rebuild its
 *       full URL into `full`.
 * WHY:  Keeps the per-entry match + traversal-safety + URL-format logic in one
 *       pure predicate so the collect loop is a flat "match? then append".
 * HOW:  Skip names containing '/', "." or ".." (a hostile/odd name must not yield
 *       a traversal-shaped URL); skip fnmatch misses; skip a rebuilt URL that would
 *       truncate. Returns 1 with `full` filled when the entry is a keeper, else 0.
 *       No behavior change.
 */
static int
glob_match_entry(const brix_url *u, const glob_spec *sp, const char *name,
                 char *full, size_t fullsz)
{
    int wn;

    /* dirlist entries are single path components; reject anything else so a
     * hostile / odd name can't yield a traversal-shaped URL. */
    if (strchr(name, '/') != NULL
        || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return 0;
    }
    if (fnmatch(sp->pattern, name, FNM_PERIOD | FNM_PATHNAME) != 0) {
        return 0;
    }
    /* Re-bracket an IPv6 host so the rebuilt URL round-trips. */
    wn = snprintf(full, fullsz, "%s://%s%s%s:%d/%s%s%s",
                  sp->scheme, sp->hb, u->host, sp->he, u->port,
                  sp->dir, sp->dsep, name);
    if (wn < 0 || (size_t) wn >= fullsz) {
        return 0;   /* skip a match whose rebuilt URL would truncate */
    }
    return 1;
}

/* Growable string-array accumulator owned by the collect loop. */
typedef struct {
    char **arr;
    size_t n;
    size_t cap;
} glob_acc;

/*
 * WHAT: Append `s` (duplicated) to a growable string-array accumulator.
 * WHY:  Confines the realloc-doubling + strdup ownership to one place so the
 *       collect loop just reports success/failure.
 * HOW:  Double the capacity (seed 16) when full; strdup the string into the next
 *       slot. Returns 0 on success, -1 on OOM (accumulator left intact for the
 *       caller to free). No behavior change.
 */
static int
glob_acc_append(glob_acc *ac, const char *s)
{
    if (ac->n == ac->cap) {
        size_t nc = ac->cap ? ac->cap * 2 : 16;
        char **na = (char **) realloc(ac->arr, nc * sizeof(char *));
        if (na == NULL) {
            return -1;
        }
        ac->arr = na;
        ac->cap = nc;
    }
    ac->arr[ac->n] = strdup(s);
    if (ac->arr[ac->n] == NULL) {
        return -1;
    }
    ac->n++;
    return 0;
}

/*
 * WHAT: Walk the dirlist entries, matching each against the pattern and collecting
 *       the rebuilt URLs of the keepers into `ac`.
 * WHY:  The collect loop is the one side-effecting step (allocation) worth
 *       isolating from parse and connection setup; keeping it here lets the
 *       orchestrator read as a flat sequence.
 * HOW:  For each entry, ask glob_match_entry; on a keeper, append via
 *       glob_acc_append. Returns 0 on success (with `ac` filled), -1 on OOM
 *       (partial array left in `ac` for the caller to free). No behavior change.
 */
static int
glob_collect(const brix_url *u, const glob_spec *sp, const brix_dirent *ents,
             size_t ne, glob_acc *ac)
{
    size_t i;

    for (i = 0; i < ne; i++) {
        char full[XRDC_PATH_MAX + 320];
        if (!glob_match_entry(u, sp, ents[i].name, full, sizeof(full))) {
            continue;
        }
        if (glob_acc_append(ac, full) != 0) {
            return -1;
        }
    }
    return 0;
}

int
brix_glob(const char *url, const brix_opts *co, char ***out, size_t *n_out,
          brix_status *st)
{
    brix_url     u;
    brix_conn    c;
    brix_dirent *ents = NULL;
    glob_spec    sp = {0};
    glob_acc     ac = {0};
    size_t       ne = 0;

    *out = NULL;
    *n_out = 0;
    if (brix_url_parse(url, &u, st) != 0) {
        return -1;
    }
    if (glob_parse_spec(&u, &sp, st) != 0) {
        return -1;
    }
    if (brix_connect(&c, &u, co, st) != 0) {
        return -1;
    }
    if (brix_dirlist(&c, sp.dir, 0 /*no stat*/, &ents, &ne, st) != 0) {
        brix_close(&c);
        return -1;
    }
    if (glob_collect(&u, &sp, ents, ne, &ac) != 0) {
        free(ents);
        brix_close(&c);
        brix_glob_free(ac.arr, ac.n);
        brix_status_set(st, XRDC_EPROTO, 0, "glob: out of memory");
        return -1;
    }
    free(ents);
    brix_close(&c);

    *out = ac.arr;
    *n_out = ac.n;
    return (int) ac.n;
}

void
brix_glob_free(char **arr, size_t n)
{
    size_t i;
    if (arr == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {
        free(arr[i]);
    }
    free(arr);
}
