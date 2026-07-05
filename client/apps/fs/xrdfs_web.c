/*
 * xrdfs_web.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


/* http(s)/WebDAV endpoints — read-only namespace ops (ls, stat).       */
/* WHAT: When the endpoint is an http/https/dav/davs URL, xrdfs speaks  */
/*       WebDAV PROPFIND for metadata (the webfile.c transport, shared  */
/*       with the FUSE driver) instead of the binary root:// protocol — */
/*       so `xrdfs https://host/path ls` works like the official client.*/
/* WHY:  A WebDAV endpoint has no root:// session; only the read-only    */
/*       metadata ops map cleanly. Mutating/file ops report clearly that */
/*       they need a root:// endpoint.                                   */


/* Map a cwd-relative arg onto the absolute server path under the URL base. */
void
web_build_path(const char *base, const char *cwd, const char *arg,
               char *out, size_t outsz)
{
    char rel[XRDC_PATH_MAX];
    build_path(cwd, (arg != NULL && arg[0] != '\0') ? arg : ".", rel, sizeof(rel));
    if (rel[0] == '/' && rel[1] == '\0') {
        snprintf(out, outsz, "%s", (base != NULL && base[0] != '\0') ? base : "/");
    } else {
        snprintf(out, outsz, "%s%s", base, rel);
    }
}


/* WebDAV equivalent of ls_print_dir() — same output format, PROPFIND source. */
int
web_ls_print_dir(const web_ctx *w, const char *path, int want_long,
                 int recursive, int human, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, k, plen;
    char         prefix[XRDC_PATH_MAX + 2];
    const char  *sep;

    if (brix_web_readdir(w->u, path, w->bearer, w->verify, w->ca_dir,
                         &ents, &n, st) != 0) {
        return -1;
    }
    plen = strlen(path);
    sep = (plen > 0 && path[plen - 1] == '/') ? "" : "/";
    snprintf(prefix, sizeof(prefix), "%s%s", path, sep);

    for (k = 0; k < n; k++) {
        if (want_long && ents[k].have_stat) {
            int  f  = ents[k].st.flags;
            char td = (f & kXR_isDir)    ? 'd' : '-';
            char r  = (f & kXR_readable) ? 'r' : '-';
            char wc = (f & kXR_writable) ? 'w' : '-';
            char szs[32];
            fmt_size(ents[k].st.size, szs, sizeof(szs), human);
            printf("%c%c%c %12s %s%s\n", td, r, wc, szs, prefix, ents[k].name);
        } else {
            printf("%s%s\n", prefix, ents[k].name);
        }
    }
    if (recursive) {
        for (k = 0; k < n; k++) {
            char full[XRDC_PATH_MAX];
            if (is_dot(ents[k].name)
                || !(ents[k].have_stat && (ents[k].st.flags & kXR_isDir))) {
                continue;
            }
            if (join_path(path, ents[k].name, full, sizeof(full)) != 0) {
                continue;
            }
            printf("\n%s:\n", full);
            if (web_ls_print_dir(w, full, want_long, 1, human, st) != 0) {
                free(ents);
                return -1;
            }
        }
    }
    free(ents);
    return 0;
}


int
web_ls(const web_ctx *w, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *arg = NULL;
    int         want_long = 0, recursive = 0, human = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)      { want_long = 1; }
        else if (strcmp(argv[i], "-R") == 0) { recursive = 1; }
        else if (strcmp(argv[i], "-h") == 0) { human = 1; }
        else if (strcmp(argv[i], "-lR") == 0 || strcmp(argv[i], "-Rl") == 0) {
            want_long = 1; recursive = 1;
        } else { arg = argv[i]; }
    }
    web_build_path(w->base, cwd, arg, path, sizeof(path));
    brix_status_clear(&st);
    if (web_ls_print_dir(w, path, want_long, recursive, human, &st) != 0) {
        fprintf(stderr, "xrdfs: ls %s: %s\n", path, st.msg);
        brix_cred_hint_for_status(&st, 0, stderr);
        return brix_shellcode(&st);
    }
    return 0;
}


int
web_stat(const web_ctx *w, const char *cwd, int argc, char **argv)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: stat <path>\n"); return 50; }
    web_build_path(w->base, cwd, argv[1], path, sizeof(path));
    brix_status_clear(&st);
    if (brix_web_stat(w->u, path, w->bearer, w->verify, w->ca_dir, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: stat %s: %s\n", path, st.msg);
        brix_cred_hint_for_status(&st, 0, stderr);
        return brix_shellcode(&st);
    }
    print_statinfo(path, &si);
    return 0;
}


/* Dispatch one command against a WebDAV endpoint. Read-only metadata ops only. */
int
web_dispatch(const web_ctx *w, int argc, char **argv)
{
    const char *cmd = argv[0];
    if (strcmp(cmd, "ls") == 0)   { return web_ls(w, "/", argc, argv); }
    if (strcmp(cmd, "stat") == 0) { return web_stat(w, "/", argc, argv); }
    fprintf(stderr, "xrdfs: '%s' is not supported over an http(s)/WebDAV endpoint "
                    "(read-only metadata only: ls, stat). Use a root:// endpoint for "
                    "the full command set.\n", cmd);
    return 50;
}
