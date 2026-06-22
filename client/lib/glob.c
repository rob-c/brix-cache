/*
 * glob.c — client-side wildcard expansion for root:// URLs.
 *
 * WHAT: xrdc_glob() expands a root:// URL whose final path component contains glob
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
#include "xrdc.h"

#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>

/* 1 if `s` contains a glob metacharacter. */
int
xrdc_has_glob(const char *s)
{
    return s != NULL && strpbrk(s, "*?[") != NULL;
}

int
xrdc_glob(const char *url, const xrdc_opts *co, char ***out, size_t *n_out,
          xrdc_status *st)
{
    xrdc_url     u;
    xrdc_conn    c;
    xrdc_dirent *ents = NULL;
    char       **arr = NULL;
    char         dir[XRDC_PATH_MAX];
    char         pattern[XRDC_NAME_MAX];
    const char  *scheme, *slash, *dsep;
    size_t       ne = 0, cap = 0, n = 0, i, dlen;

    *out = NULL;
    *n_out = 0;
    if (xrdc_url_parse(url, &u, st) != 0) {
        return -1;
    }
    if (u.scheme != XRDC_SCHEME_ROOT && u.scheme != XRDC_SCHEME_ROOTS) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "glob: only root:// URLs are expanded");
        return -1;
    }
    slash = strrchr(u.path, '/');
    if (slash == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "glob: malformed path");
        return -1;
    }
    if (strlen(slash + 1) >= sizeof(pattern)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "glob: pattern too long");
        return -1;   /* reject — never truncate (a clipped wildcard mis-matches) */
    }
    memcpy(pattern, slash + 1, strlen(slash + 1) + 1);
    if (!xrdc_has_glob(pattern)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "glob: no wildcard in last path component");
        return -1;
    }
    dlen = (size_t) (slash - u.path);
    if (dlen == 0) {
        dir[0] = '/';
        dir[1] = '\0';
    } else {
        if (dlen >= sizeof(dir)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "glob: directory path too long");
            return -1;
        }
        memcpy(dir, u.path, dlen);
        dir[dlen] = '\0';
    }

    if (xrdc_connect(&c, &u, co, st) != 0) {
        return -1;
    }
    if (xrdc_dirlist(&c, dir, 0 /*no stat*/, &ents, &ne, st) != 0) {
        xrdc_close(&c);
        return -1;
    }
    scheme = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    dsep = (dir[0] != '\0' && dir[strlen(dir) - 1] == '/') ? "" : "/";
    {
        int         v6 = (strchr(u.host, ':') != NULL);   /* IPv6 literal */
        const char *hb = v6 ? "[" : "";
        const char *he = v6 ? "]" : "";
        int         err = 0;
        for (i = 0; i < ne && !err; i++) {
            char full[XRDC_PATH_MAX + 320];
            int  wn;
            /* dirlist entries are single path components; reject anything else so a
             * hostile/odd name can't yield a traversal-shaped URL. */
            if (strchr(ents[i].name, '/') != NULL
                || strcmp(ents[i].name, ".") == 0 || strcmp(ents[i].name, "..") == 0) {
                continue;
            }
            if (fnmatch(pattern, ents[i].name, FNM_PERIOD | FNM_PATHNAME) != 0) {
                continue;
            }
            /* Re-bracket an IPv6 host so the rebuilt URL round-trips. */
            wn = snprintf(full, sizeof(full), "%s://%s%s%s:%d/%s%s%s",
                          scheme, hb, u.host, he, u.port, dir, dsep, ents[i].name);
            if (wn < 0 || (size_t) wn >= sizeof(full)) {
                continue;   /* skip a match whose rebuilt URL would truncate */
            }
            if (n == cap) {
                size_t  nc = cap ? cap * 2 : 16;
                char  **na = (char **) realloc(arr, nc * sizeof(char *));
                if (na == NULL) { err = 1; break; }
                arr = na;
                cap = nc;
            }
            arr[n] = strdup(full);
            if (arr[n] == NULL) { err = 1; break; }
            n++;
        }
        free(ents);
        xrdc_close(&c);
        if (err) {
            xrdc_glob_free(arr, n);
            xrdc_status_set(st, XRDC_EPROTO, 0, "glob: out of memory");
            return -1;
        }
    }
    *out = arr;
    *n_out = n;
    return (int) n;
}

void
xrdc_glob_free(char **arr, size_t n)
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
