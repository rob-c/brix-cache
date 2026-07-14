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


/* ---- Print one directory entry in xrdfs ls format ----
 *
 * WHAT: Emits a single line for one PROPFIND-derived dirent to stdout. In long
 *       mode (want_long) with stat data present, prints the drwx-style flag
 *       triplet, a right-justified size (human-readable when human is set), and
 *       the full "prefix + name" path; otherwise prints just "prefix + name".
 *       No return value; output-only.
 *
 * WHY:  Factored out of web_ls_print_dir so the per-entry formatting (with its
 *       flag/size ternaries) is a single-purpose helper, keeping the directory
 *       walker's cyclomatic complexity within the project cap and matching the
 *       exact one-line-per-entry format of the root:// ls_print_dir().
 *
 * HOW:  1. If long output is requested and the entry carries stat data, derive
 *          the dir/readable/writable flag characters and format the size.
 *       2. Print the long-form line with flags, size, prefix, and name.
 *       3. Otherwise print the short form: prefix followed by name.
 */
static void
web_print_one_entry(const brix_dirent *ent, const char *prefix,
                    int want_long, int human)
{
    if (want_long && ent->have_stat) {
        int  f  = ent->st.flags;
        char td = (f & kXR_isDir)    ? 'd' : '-';
        char r  = (f & kXR_readable) ? 'r' : '-';
        char wc = (f & kXR_writable) ? 'w' : '-';
        char szs[32];
        fmt_size(ent->st.size, szs, sizeof(szs), human);
        printf("%c%c%c %12s %s%s\n", td, r, wc, szs, prefix, ent->name);
    } else {
        printf("%s%s\n", prefix, ent->name);
    }
}


/* ---- Recurse into subdirectories for xrdfs ls -R over WebDAV ----
 *
 * WHAT: For each subdirectory in a directory listing, prints the "full:" header
 *       and recursively lists its contents via web_ls_print_dir(). Returns 0 on
 *       success, -1 if any recursive listing fails (with st describing the
 *       failure). Skips "." / ".." entries, non-directories, and any child whose
 *       joined path would overflow.
 *
 * WHY:  Separated from web_ls_print_dir so the recursion loop is an independent,
 *       single-purpose step. This keeps the walker's complexity within the cap
 *       while preserving the exact skip rules and recursive descent order.
 *
 * HOW:  1. Iterate the entries; skip dot entries and anything that is not a
 *          stat-bearing directory.
 *       2. Build the child's full path; skip entries that do not fit.
 *       3. Print the "\nfull:\n" section header, then recurse; on the first
 *          recursion failure return -1, otherwise return 0.
 */
static int
web_ls_recurse_children(const web_ctx *w, const char *path,
                        const brix_dirent *ents, size_t n,
                        int want_long, int human, brix_status *st)
{
    size_t k;

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
            return -1;
        }
    }
    return 0;
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
        web_print_one_entry(&ents[k], prefix, want_long, human);
    }
    if (recursive
        && web_ls_recurse_children(w, path, ents, n, want_long, human, st) != 0) {
        free(ents);
        return -1;
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
        xrdfs_web_hints(&st, 0, w);   /* WS-7 doctor referral */
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
        xrdfs_web_hints(&st, 0, w);   /* WS-7 doctor referral */
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
