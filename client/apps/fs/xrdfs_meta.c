/*
 * xrdfs_meta.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


/* WHAT: stat [-j] <path> — print file metadata in human or JSON format.
 * WHY:  -j enables machine-readable output for scripting and pipeline use.
 * HOW:  flags are parsed first; the path argument is whatever is left.
 *       On error no output goes to stdout so partial JSON is never emitted. */
int
do_stat(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];
    const char   *arg = NULL;
    int           json = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else {
            arg = argv[i];
        }
    }
    if (arg == NULL) { fprintf(stderr, "usage: stat [-j] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_stat(c, path, &si, &st) != 0) {
        return xrdfs_report_err("stat", path, &st, 0, c);
    }
    if (json) { json_statinfo(path, &si); } else { print_statinfo(path, &si); }
    return 0;
}


/* ---- Print one ls directory entry line ----
 *
 * WHAT: Emits a single directory entry to stdout — the long "drw SIZE
 *       prefixNAME" form when want_long is set and the entry carries stat data,
 *       otherwise the plain "prefixNAME" form. Returns nothing.
 *
 * WHY:  The per-entry formatting is the branchiest part of listing a directory;
 *       pulling it out keeps ls_print_dir's control flow (dirlist, loop,
 *       recurse) flat and under the complexity cap.
 *
 * HOW:  1. When want_long and the entry has stat data, derive the type and rwx
 *          glyphs from the flags and format the size through fmt_size.
 *       2. Otherwise print just the prefixed name.
 */
static void
ls_print_entry(const brix_dirent *ent, const char *prefix, int want_long,
               int human)
{
    if (want_long && ent->have_stat) {
        int  f  = ent->st.flags;
        char td = (f & kXR_isDir)    ? 'd' : '-';
        char r  = (f & kXR_readable) ? 'r' : '-';
        char w  = (f & kXR_writable) ? 'w' : '-';
        char szs[32];
        fmt_size(ent->st.size, szs, sizeof(szs), human);
        printf("%c%c%c %12s %s%s\n", td, r, w, szs, prefix, ent->name);
    } else {
        printf("%s%s\n", prefix, ent->name);
    }
}


/* ---- Recurse into each subdirectory (ls -R) ----
 *
 * WHAT: For every child of an already-listed directory that is a real
 *       subdirectory, prints a "fullpath:" section header and lists it
 *       recursively. Returns 0 on success, -1 if any recursive listing fails.
 *
 * WHY:  Isolating the descent loop from the entry-printing loop keeps each loop
 *       single-purpose and holds ls_print_dir under the complexity cap.
 *
 * HOW:  1. Skip "." / ".." and any entry not flagged kXR_isDir with stat data
 *          (directory symlinks report kXR_other and are listed, not descended).
 *       2. Join the parent path and child name; skip entries that overflow.
 *       3. Print the section header and recurse, propagating a failure as -1.
 */
static int
ls_recurse_subdirs(brix_conn *c, const char *path, const brix_dirent *ents,
                   size_t n, int want_long, int human, brix_status *st)
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
        if (ls_print_dir(c, full, want_long, 1, human, st) != 0) {
            return -1;
        }
    }
    return 0;
}


/* Print one directory's entries; if recursive, descend into each subdir under a
 * "fullpath:" section header (classic ls -R). 0 / -1. */

int
ls_print_dir(brix_conn *c, const char *path, int want_long, int recursive,
             int human, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, k;
    char         prefix[XRDC_PATH_MAX + 2];
    size_t       plen;
    const char  *sep;

    if (brix_dirlist(c, path, (want_long || recursive), &ents, &n, st) != 0) {
        return -1;
    }
    plen = strlen(path);
    sep = (plen > 0 && path[plen - 1] == '/') ? "" : "/";
    snprintf(prefix, sizeof(prefix), "%s%s", path, sep);

    for (k = 0; k < n; k++) {
        ls_print_entry(&ents[k], prefix, want_long, human);
    }
    if (recursive
        && ls_recurse_subdirs(c, path, ents, n, want_long, human, st) != 0) {
        free(ents);
        return -1;
    }
    free(ents);
    return 0;
}


/* WHAT: flat JSON array of one directory's entries for ls -j.
 * WHY:  brix_dirlist returns all entries at once, so no partial output can
 *       reach stdout on error — the array is complete or nothing is emitted.
 * HOW:  forces want_stat=1; entries with no stat data emit -1 sentinel values.
 *       Name strings go through brix_json_kv_str so embedded quotes and control
 *       bytes are safely escaped (security requirement). */
static int
ls_json_dir(brix_conn *c, const char *path, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, k;
    char         prefix[XRDC_PATH_MAX + 2];
    size_t       plen;
    const char  *sep;
    int          first = 1;

    if (brix_dirlist(c, path, 1 /*want_stat*/, &ents, &n, st) != 0) {
        return -1;
    }
    plen = strlen(path);
    sep  = (plen > 0 && path[plen - 1] == '/') ? "" : "/";
    snprintf(prefix, sizeof(prefix), "%s%s", path, sep);

    fputc('[', stdout);
    for (k = 0; k < n; k++) {
        char fullname[XRDC_PATH_MAX];
        int  is_dir = ents[k].have_stat && (ents[k].st.flags & kXR_isDir);

        if ((size_t) snprintf(fullname, sizeof(fullname), "%s%s",
                              prefix, ents[k].name) >= sizeof(fullname)) {
            continue;   /* skip overlong paths rather than truncating silently */
        }
        if (!first) { fputc(',', stdout); }
        first = 0;

        fputc('{', stdout);
        brix_json_kv_str(stdout, "name",   fullname,                                  1);
        brix_json_kv_ll(stdout,  "size",
                        ents[k].have_stat ? (long long) ents[k].st.size  : -1LL,      1);
        brix_json_kv_ll(stdout,  "mtime",
                        ents[k].have_stat ? (long long) ents[k].st.mtime : -1LL,      1);
        brix_json_kv_bool(stdout, "is_dir", is_dir,                                   0);
        fputc('}', stdout);
    }
    fputs("]\n", stdout);
    free(ents);
    return 0;
}


/* WHAT: ls [-l] [-R] [-h] [-j] [path] — list directory entries.
 * WHY:  -j enables machine-readable JSON output for scripting.
 * HOW:  -j dispatches to ls_json_dir (flat array, safe escaping);
 *       all other flag combinations go through the existing ls_print_dir path. */
int
do_ls(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *arg = NULL;
    int         want_long = 0, recursive = 0, human = 0, json = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)      { want_long = 1; }
        else if (strcmp(argv[i], "-R") == 0) { recursive = 1; }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0) { human = 1; }
        else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[i], "-lR") == 0 || strcmp(argv[i], "-Rl") == 0) {
            want_long = 1; recursive = 1;
        } else { arg = argv[i]; }
    }
    build_path(cwd, arg != NULL ? arg : ".", path, sizeof(path));

    brix_status_clear(&st);
    if (json) {
        if (ls_json_dir(c, path, &st) != 0) {
            return xrdfs_report_err("ls", path, &st, 0, c);
        }
        return 0;
    }
    if (ls_print_dir(c, path, want_long, recursive, human, &st) != 0) {
        return xrdfs_report_err("ls", path, &st, 0, c);
    }
    return 0;
}


int
do_mkdir(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    int         parents = 0, mode = 0755, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) { parents = 1; }
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode = (int) strtol(argv[++i], NULL, 8);
        } else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: mkdir [-p] [-m mode] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_mkdir(c, path, mode, parents, &st) != 0) {
        return xrdfs_report_err("mkdir", path, &st, 1, c);
    }
    return 0;
}


/* rm_report — per-entry printer for rm -r -v. Never aborts the delete. */
static int
rm_report(const char *path, int is_dir, void *u)
{
    (void) u;
    printf("removed %s%s\n", is_dir ? "dir  " : "file ", path);
    return 0;
}

/* WHAT: rm [-r] [-v] <path> — delete a file, or a whole tree with -r.
 * WHY:  rmdir only takes empty dirs; users cleaning a tree need one command.
 * HOW:  -r stats the target; directories go through brix_rmtree (post-order,
 *       depth-capped). The resolved export root "/" is always refused.
 *       brix_rmtree probes each kXR_isDir entry with brix_lstat before
 *       descending: directory symlinks (kXR_other) are unlinked, not descended,
 *       matching POSIX `rm -r` semantics. */
int
do_rm(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    int         recursive = 0, verbose = 0, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0) {
            recursive = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: rm [-r] [-v, --verbose] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    brix_status_clear(&st);
    if (recursive) {
        brix_statinfo si;
        if (strcmp(path, "/") == 0) {
            fprintf(stderr, "xrdfs: rm -r: refusing to delete the export root\n");
            return 50;
        }
        if (brix_stat(c, path, &si, &st) != 0) {
            return xrdfs_report_err("rm", path, &st, 1, c);
        }
        if (si.flags & kXR_isDir) {
            if (brix_rmtree(c, path, 0, verbose ? rm_report : NULL, NULL,
                            &st) != 0) {
                return xrdfs_report_err("rm -r", path, &st, 1, c);
            }
            return 0;
        }
        /* -r on a plain file falls through to the single unlink */
    }
    if (brix_rm(c, path, &st) != 0) {
        return xrdfs_report_err("rm", path, &st, 1, c);
    }
    return 0;
}


int
do_rmdir(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: rmdir <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    brix_status_clear(&st);
    if (brix_rmdir(c, path, &st) != 0) {
        return xrdfs_report_err("rmdir", path, &st, 1, c);
    }
    return 0;
}


int
do_mv(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        src[XRDC_PATH_MAX], dst[XRDC_PATH_MAX];

    if (argc < 3) { fprintf(stderr, "usage: mv <src> <dst>\n"); return 50; }
    build_path(cwd, argv[1], src, sizeof(src));
    build_path(cwd, argv[2], dst, sizeof(dst));
    brix_status_clear(&st);
    if (brix_mv(c, src, dst, &st) != 0) {
        fprintf(stderr, "xrdfs: mv: %s\n", st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
    }
    return 0;
}


/* chmod [-R] <path> <mode> — keeps the historical xrdfs arg order (path first).
 * <mode> is the stock 9-char symbolic form ("rwxr-xr-x") or an octal absolute
 * mode ("755"). -R recurses into directories, applying the same mode to every
 * entry. */
int
do_chmod(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *patharg = NULL, *modearg = NULL;
    int         recursive = 0, mode, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-R") == 0)   { recursive = 1; }
        else if (patharg == NULL)         { patharg = argv[i]; }
        else if (modearg == NULL)         { modearg = argv[i]; }
    }
    if (patharg == NULL || modearg == NULL) {
        fprintf(stderr, "usage: chmod [-R] <path> <rwxr-xr-x | octal-mode>\n");
        return 50;
    }
    build_path(cwd, patharg, path, sizeof(path));
    mode = parse_chmod_mode(modearg);
    if (mode < 0) {
        fprintf(stderr, "xrdfs: chmod: invalid mode '%s' "
                "(expected rwxr-xr-x or octal)\n", modearg);
        return 50;
    }

    brix_status_clear(&st);
    if (brix_chmod(c, path, mode, &st) != 0) {
        return xrdfs_report_err("chmod", path, &st, 1, c);
    }
    if (recursive) {
        int         failures = 0;
        brix_status wst;
        brix_status_clear(&wst);
        if (chmod_recursive(c, path, mode, &failures, &wst) != 0) {
            return xrdfs_report_err("chmod -R", path, &wst, 1, c);
        }
        if (failures > 0) { return 1; }   /* per-entry errors already reported */
    }
    return 0;
}


int
do_truncate(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    long long   size;

    if (argc < 3) { fprintf(stderr, "usage: truncate <path> <size>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    size = strtoll(argv[2], NULL, 10);
    brix_status_clear(&st);
    if (brix_truncate(c, path, (int64_t) size, &st) != 0) {
        return xrdfs_report_err("truncate", path, &st, 1, c);
    }
    return 0;
}


int
do_locate(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];

    if (argc < 2) { fprintf(stderr, "usage: locate <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    brix_status_clear(&st);
    if (brix_locate(c, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("locate", path, &st, 0, c);
    }
    printf("%s\n", reply);
    return 0;
}


int
do_statvfs(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];

    build_path(cwd, argc >= 2 ? argv[1] : "/", path, sizeof(path));
    brix_status_clear(&st);
    if (brix_statvfs(c, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("statvfs", path, &st, 0, c);
    }
    printf("%s\n", reply);
    return 0;
}


/* df [-h] [path] — friendly disk-space report over kXR_Qspace (the server's oss.*
 * capacity record). Default path "/". -h humanizes the byte columns. Falls back to
 * printing the raw reply verbatim when the shape is unrecognized (never crashes).
 * Cluster-wide aggregation (per-holder rows) is out of scope here — use `xrdmapc`. */
int
do_df(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[4096];
    int64_t     total, avail, used, largest;
    int         human = 0, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0) { human = 1; }
        else { arg = argv[i]; }
    }
    build_path(cwd, arg != NULL ? arg : "/", path, sizeof(path));

    brix_status_clear(&st);
    if (brix_query(c, kXR_Qspace, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("df", path, &st, 0, c);
    }
    if (df_parse_space(reply, &total, &avail, &used, &largest) != 0) {
        printf("%s\n", reply);   /* unknown shape: honest raw passthrough */
        return 0;
    }
    {
        char ts[32], us[32], as[32], ls[32], pctbuf[8];
        fmt_size(total   >= 0 ? total   : 0, ts, sizeof(ts), human);
        fmt_size(used    >= 0 ? used    : 0, us, sizeof(us), human);
        fmt_size(avail   >= 0 ? avail   : 0, as, sizeof(as), human);
        fmt_size(largest >= 0 ? largest : 0, ls, sizeof(ls), human);
        if (total > 0 && used >= 0) {
            snprintf(pctbuf, sizeof(pctbuf), "%d%%", (int) ((used * 100) / total));
        } else {
            snprintf(pctbuf, sizeof(pctbuf), "-");
        }
        printf("%-12s %-12s %-12s %-6s %-12s %s\n",
               "Size", "Used", "Avail", "Use%", "Largest", "Path");
        printf("%-12s %-12s %-12s %-6s %-12s %s\n", ts, us, as, pctbuf, ls, path);
    }
    return 0;
}

