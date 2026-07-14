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
        fprintf(stderr, "xrdfs: stat %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 0, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
            fprintf(stderr, "xrdfs: ls %s: %s\n", path, st.msg);
            xrdfs_op_hints(&st, 0, c);   /* WS-3/WS-7 */
            return brix_shellcode(&st);
        }
        return 0;
    }
    if (ls_print_dir(c, path, want_long, recursive, human, &st) != 0) {
        fprintf(stderr, "xrdfs: ls %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 0, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: mkdir %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
            fprintf(stderr, "xrdfs: rm %s: %s\n", path, st.msg);
            brix_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
            return brix_shellcode(&st);
        }
        if (si.flags & kXR_isDir) {
            if (brix_rmtree(c, path, 0, verbose ? rm_report : NULL, NULL,
                            &st) != 0) {
                fprintf(stderr, "xrdfs: rm -r %s: %s\n", path, st.msg);
                xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
                return brix_shellcode(&st);
            }
            return 0;
        }
        /* -r on a plain file falls through to the single unlink */
    }
    if (brix_rm(c, path, &st) != 0) {
        fprintf(stderr, "xrdfs: rm %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: rmdir %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: chmod %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
    }
    if (recursive) {
        int         failures = 0;
        brix_status wst;
        brix_status_clear(&wst);
        if (chmod_recursive(c, path, mode, &failures, &wst) != 0) {
            fprintf(stderr, "xrdfs: chmod -R %s: %s\n", path, wst.msg);
            return brix_shellcode(&wst);
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
        fprintf(stderr, "xrdfs: truncate %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: locate %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: statvfs %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: df %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
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


/* ---- Parse touch's argument vector ----
 *
 * WHAT: Scans argv for -c/-a/-m/-t|--timestamp flags and the single path
 *       operand, writing each into the caller's out-params. Returns 0 on
 *       success, or 50 (after printing a diagnostic) on a malformed
 *       -t/--timestamp value.
 *
 * WHY:  The flag scan — especially the -t branch that consumes the next argv
 *       slot and parses a timestamp — is what pushes do_touch over the
 *       complexity cap; isolating it keeps the command body linear.
 *
 * HOW:  1. Walk argv setting the boolean out-param for each recognised option.
 *       2. For -t/--timestamp with a following argument, parse it into *tspec
 *          via touch_parse_time; on failure print the usage hint and return 50.
 *       3. Treat any other token (including a bare -t with no following value,
 *          matching the original loop) as the path operand, last one winning.
 */
static int
touch_parse_argv(int argc, char **argv, int *no_create, int *do_atime,
                 int *do_mtime, int *have_t, struct timespec *tspec,
                 const char **arg)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)      { *no_create = 1; }
        else if (strcmp(argv[i], "-a") == 0) { *do_atime = 1; }
        else if (strcmp(argv[i], "-m") == 0) { *do_mtime = 1; }
        else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timestamp") == 0)
                 && i + 1 < argc) {
            if (touch_parse_time(argv[++i], tspec) != 0) {
                fprintf(stderr, "xrdfs: touch: bad -t/--timestamp value '%s' "
                                "(want [[CC]YY]MMDDhhmm[.ss])\n", argv[i]);
                return 50;
            }
            *have_t = 1;
        } else { *arg = argv[i]; }
    }
    return 0;
}


/* ---- Populate the utimensat times[2] pair for touch ----
 *
 * WHAT: Fills times[0] (atime) and times[1] (mtime) with UTIME_NOW, an explicit
 *       parsed timestamp, or UTIME_OMIT according to which fields touch selected.
 *
 * WHY:  Encapsulates the per-field UTIME_NOW / OMIT / explicit decision so
 *       do_touch reads as a flat sequence and stays under the complexity cap.
 *
 * HOW:  1. Zero tv_sec for both slots; set tv_nsec to UTIME_NOW when the field
 *          is selected without an explicit -t, UTIME_OMIT when unselected, and 0
 *          (a real seconds value follows) when an explicit -t was given.
 *       2. When have_t is set, copy tspec into each selected slot.
 */
static void
touch_fill_times(struct timespec times[2], int do_atime, int do_mtime,
                 int have_t, const struct timespec *tspec)
{
    times[0].tv_sec = times[1].tv_sec = 0;
    times[0].tv_nsec = do_atime ? (have_t ? 0 : UTIME_NOW) : UTIME_OMIT;
    times[1].tv_nsec = do_mtime ? (have_t ? 0 : UTIME_NOW) : UTIME_OMIT;
    if (have_t) {
        if (do_atime) { times[0] = *tspec; }
        if (do_mtime) { times[1] = *tspec; }
    }
}


/* ---- Ensure the touch target exists before stamping ----
 *
 * WHAT: With no_create set, reports whether the file is absent; otherwise
 *       creates the file if it does not exist. Returns 1 when do_touch should
 *       stop early with success (-c on an absent file), 0 to proceed to setattr.
 *
 * WHY:  POSIX touch treats -c on a missing file as a silent no-op and otherwise
 *       creates the file before stamping; isolating that keeps do_touch's error
 *       handling focused on the setattr call that actually reports failures.
 *
 * HOW:  1. Under -c, stat the path; an absent file returns 1 (no-op), an
 *          existing file returns 0 to continue to the stamp.
 *       2. Otherwise open write with force=0 (kXR_new); on success close it. An
 *          already-existing file makes the open fail, which is ignored — the
 *          file is present and the caller's setattr still runs. Returns 0.
 */
static int
touch_ensure_file(brix_conn *c, const char *path, int no_create)
{
    brix_status cs;

    if (no_create) {
        brix_statinfo si;
        brix_status_clear(&cs);
        if (brix_stat(c, path, &si, &cs) != 0) { return 1; }
        return 0;
    }
    /* Create-if-absent: force=0 ⇒ kXR_new (fails if it already exists, which we
     * ignore — the file is there and the setattr below still runs). */
    {
        brix_file f;
        brix_status_clear(&cs);
        if (brix_file_open_write(c, path, 0 /*force=new*/, 0 /*posc*/, &f, &cs) == 0) {
            brix_file_close(c, &f, &cs);
        }
    }
    return 0;
}


/* touch [-c] [-a] [-m] [-t STAMP] <path> — create the file if absent (unless -c) and
 * set its access/modification times (default: both to now). -a/-m restrict to
 * atime/mtime; -t sets an explicit [[CC]YY]MMDDhhmm[.ss] time. NEVER changes
 * ownership: brix_setattr is always called with set_owner = 0. */
int
do_touch(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status     st;
    char            path[XRDC_PATH_MAX];
    struct timespec times[2], tspec;
    const char     *arg = NULL;
    int             no_create = 0, do_atime = 0, do_mtime = 0, have_t = 0, prc;

    tspec.tv_sec  = 0;   /* unused unless have_t; init to silence -Wmaybe-uninit */
    tspec.tv_nsec = 0;
    prc = touch_parse_argv(argc, argv, &no_create, &do_atime, &do_mtime,
                           &have_t, &tspec, &arg);
    if (prc != 0) {
        return prc;
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: touch [-c] [-a] [-m] [-t/--timestamp STAMP] <path>\n");
        return 50;
    }
    if (!do_atime && !do_mtime) { do_atime = do_mtime = 1; }   /* default: both */
    build_path(cwd, arg, path, sizeof(path));

    /* atime = slot 0, mtime = slot 1; per-field UTIME_OMIT when not selected. */
    touch_fill_times(times, do_atime, do_mtime, have_t, &tspec);

    if (touch_ensure_file(c, path, no_create)) {
        return 0;
    }

    brix_status_clear(&st);
    if (brix_setattr(c, path, 1 /*set_times*/, times, 0 /*set_owner*/,
                     (uint32_t) -1, (uint32_t) -1, &st) != 0) {
        fprintf(stderr, "xrdfs: touch %s: %s\n", path, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
    }
    return 0;
}


/* ln [-s] [-f] <target> <linkpath> — create a hard link (default) or a symbolic link
 * (-s), GNU arg order (target first). -f removes an existing linkpath first
 * (best-effort, non-atomic). For -s the target is stored verbatim (link content, not
 * path-resolved); only linkpath is confined. Hard links confine both paths. */
int
do_ln(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        linkpath[XRDC_PATH_MAX], oldpath[XRDC_PATH_MAX];
    const char *target = NULL, *link = NULL;
    int         symbolic = 0, force = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0)      { symbolic = 1; }
        else if (strcmp(argv[i], "-f") == 0) { force = 1; }
        else if (target == NULL)             { target = argv[i]; }
        else if (link == NULL)               { link = argv[i]; }
    }
    if (target == NULL || link == NULL) {
        fprintf(stderr, "usage: ln [-s] [-f] <target> <linkpath>\n");
        return 50;
    }
    build_path(cwd, link, linkpath, sizeof(linkpath));

    brix_status_clear(&st);
    if (force) {
        brix_status rmst;
        brix_status_clear(&rmst);
        (void) brix_rm(c, linkpath, &rmst);   /* best-effort; ignore "not found" */
    }
    if (symbolic) {
        if (brix_symlink(c, target, linkpath, &st) != 0) {   /* target verbatim */
            fprintf(stderr, "xrdfs: ln -s %s %s: %s\n", target, linkpath, st.msg);
            xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
            return brix_shellcode(&st);
        }
        return 0;
    }
    build_path(cwd, target, oldpath, sizeof(oldpath));   /* hard link: both confined */
    if (brix_link(c, oldpath, linkpath, &st) != 0) {
        fprintf(stderr, "xrdfs: ln %s %s: %s\n", oldpath, linkpath, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        return brix_shellcode(&st);
    }
    return 0;
}


/* readlink <path> — print a symlink's target. brix_readlink returns the TRUE target
 * length (which may exceed the buffer); guard against printing a truncated value. */
int
do_readlink(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], target[XRDC_PATH_MAX];
    ssize_t     n;

    if (argc < 2) { fprintf(stderr, "usage: readlink <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    brix_status_clear(&st);
    n = brix_readlink(c, path, target, sizeof(target), &st);
    if (n < 0) {
        fprintf(stderr, "xrdfs: readlink %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if ((size_t) n >= sizeof(target)) {
        fprintf(stderr, "xrdfs: readlink %s: target too long (%lld bytes)\n",
                path, (long long) n);
        return 1;
    }
    printf("%s\n", target);
    return 0;
}


/* cksum [-a algo] <path> — print the server-side checksum (kXR_query/Qcksum). algo
 * defaults to adler32; also crc32c/crc64/crc64nvme/md5. Output: "<algo> <hex> <path>". */
int
do_cksum(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], hex[160];
    const char *algo = "adler32", *arg = NULL;
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) { algo = argv[++i]; }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: cksum [-a algo] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));
    brix_status_clear(&st);
    if (brix_query_cksum(c, path, algo, hex, sizeof(hex), &st) != 0) {
        fprintf(stderr, "xrdfs: cksum %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    printf("%s %s %s\n", algo, hex, path);
    return 0;
}


/* xattr ls|get|set|rm — extended attributes via kXR_fattr (client/lib/fattr.c).
 *   xattr ls  <path>                  list attribute names
 *   xattr get <path> <name>           print one value
 *   xattr set <path> <name> <value>   set/replace a value
 *   xattr rm  <path> <name>           delete an attribute
 * `xattr <path>` with no subcommand is treated as `ls`. */
int
xattr_ls(brix_conn *c, const char *path)
{
    brix_status st;
    char        names[8192];
    size_t      total = 0, off;

    brix_status_clear(&st);
    if (brix_fattr_list(c, path, names, sizeof(names), &total, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr ls %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    /* The server returns a NUL-separated list of managed names tagged with a
     * one-letter namespace prefix ("U.<name>" for the user namespace). Strip the
     * "<X>." tag so the printed names round-trip directly through xattr get/set. */
    for (off = 0; off < total && names[off] != '\0'; ) {
        const char *name = names + off;
        if (name[0] >= 'A' && name[0] <= 'Z' && name[1] == '.') { name += 2; }
        printf("%s\n", name);
        off += strlen(names + off) + 1;
    }
    return 0;
}


/* ---- Is argv[1] a recognised xattr subcommand keyword? ----
 *
 * WHAT: Returns 1 when the token is one of ls/get/set/rm, 0 otherwise.
 *
 * WHY:  `xattr <path>` with no subcommand is shorthand for `xattr ls <path>`;
 *       factoring the four-way keyword test out keeps do_xattr's dispatch under
 *       the complexity cap.
 *
 * HOW:  Compare the token against each of the four recognised subcommand names.
 */
static int
xattr_is_subcommand(const char *s)
{
    return strcmp(s, "ls") == 0 || strcmp(s, "get") == 0
        || strcmp(s, "set") == 0 || strcmp(s, "rm") == 0;
}


/* ---- xattr get <path> <name> ----
 *
 * WHAT: Fetches one attribute value and writes it to stdout followed by a
 *       newline. Returns 0 on success, 50 on a usage error, or the mapped shell
 *       code on a protocol failure.
 *
 * WHY:  Splits the get branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> argument.
 *       2. Call brix_fattr_get; on error report the message and map the status.
 *       3. Write the raw value bytes (clamped to the buffer) and a newline.
 */
static int
xattr_get(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;
    char        val[8192];
    size_t      vlen = 0;

    if (argc < 4) { fprintf(stderr, "usage: xattr get <path> <name>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_get(c, path, argv[3], val, sizeof(val), &vlen, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr get %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    fwrite(val, 1, vlen < sizeof(val) ? vlen : sizeof(val), stdout);
    printf("\n");
    return 0;
}


/* ---- xattr set <path> <name> <value> ----
 *
 * WHAT: Sets or replaces one attribute value. Returns 0 on success, 50 on a
 *       usage error, or the mapped shell code on a protocol failure.
 *
 * WHY:  Splits the set branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> and <value> arguments.
 *       2. Call brix_fattr_set with the value's byte length; on error report
 *          the message and map the status.
 */
static int
xattr_set(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;

    if (argc < 5) { fprintf(stderr, "usage: xattr set <path> <name> <value>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_set(c, path, argv[3], argv[4], strlen(argv[4]), 0, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr set %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* ---- xattr rm <path> <name> ----
 *
 * WHAT: Deletes one attribute. Returns 0 on success, 50 on a usage error, or the
 *       mapped shell code on a protocol failure.
 *
 * WHY:  Splits the rm branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> argument.
 *       2. Call brix_fattr_del; on error report the message and map the status.
 */
static int
xattr_rm(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;

    if (argc < 4) { fprintf(stderr, "usage: xattr rm <path> <name>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_del(c, path, argv[3], &st) != 0) {
        fprintf(stderr, "xrdfs: xattr rm %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


int
do_xattr(brix_conn *c, const char *cwd, int argc, char **argv)
{
    char path[XRDC_PATH_MAX];

    if (argc < 2) {
        fprintf(stderr, "usage: xattr ls|get|set|rm <path> [name] [value]\n");
        return 50;
    }
    /* `xattr <path>` (no subcommand) → list. */
    if (!xattr_is_subcommand(argv[1])) {
        build_path(cwd, argv[1], path, sizeof(path));
        return xattr_ls(c, path);
    }
    if (argc < 3) {
        fprintf(stderr, "usage: xattr %s <path> ...\n", argv[1]);
        return 50;
    }
    build_path(cwd, argv[2], path, sizeof(path));

    if (strcmp(argv[1], "ls") == 0)  { return xattr_ls(c, path); }
    if (strcmp(argv[1], "get") == 0) { return xattr_get(c, path, argc, argv); }
    if (strcmp(argv[1], "set") == 0) { return xattr_set(c, path, argc, argv); }
    return xattr_rm(c, path, argc, argv);   /* the only remaining subcommand */
}


int
do_query(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        reply[4096], pathbuf[XRDC_PATH_MAX];
    int         infotype;
    const char *args;

    if (argc < 2) {
        fprintf(stderr, "usage: query <config|space|checksum|stats> [args]\n");
        return 50;
    }
    if      (strcmp(argv[1], "config")   == 0) { infotype = kXR_Qconfig; }
    else if (strcmp(argv[1], "space")    == 0) { infotype = kXR_Qspace; }
    else if (strcmp(argv[1], "checksum") == 0) { infotype = kXR_Qcksum; }
    else if (strcmp(argv[1], "stats")    == 0) { infotype = kXR_QStats; }
    else {
        fprintf(stderr, "xrdfs: unknown query subtype '%s'\n", argv[1]);
        return 50;
    }

    /* space/checksum take a path (resolved); config/stats take a literal key. */
    if (argc >= 3
        && (infotype == kXR_Qspace || infotype == kXR_Qcksum)) {
        build_path(cwd, argv[2], pathbuf, sizeof(pathbuf));
        args = pathbuf;
    } else {
        args = (argc >= 3) ? argv[2] : "";
    }

    brix_status_clear(&st);
    if (brix_query(c, infotype, args, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: query %s: %s\n", argv[1], st.msg);
        return brix_shellcode(&st);
    }
    printf("%s\n", reply);
    return 0;
}


int
do_prepare(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        reply[1024];
    char        resolved[16][XRDC_PATH_MAX];
    const char *paths[16];
    int         options = 0, optionX = 0, np = 0, i;

    for (i = 1; i < argc && np < 16; i++) {
        if (strcmp(argv[i], "-s") == 0)      { options |= kXR_stage; }
        else if (strcmp(argv[i], "-w") == 0) { options |= kXR_wmode; }
        else if (strcmp(argv[i], "-c") == 0) { options |= kXR_cancel; }
        else if (strcmp(argv[i], "-f") == 0) { options |= kXR_fresh; }
        else if (strcmp(argv[i], "-e") == 0) { optionX |= kXR_evict; }
        else {
            build_path(cwd, argv[i], resolved[np], sizeof(resolved[np]));
            paths[np] = resolved[np];
            np++;
        }
    }
    if (np == 0) { fprintf(stderr, "usage: prepare [-s|-w|-c|-f|-e] <path>...\n"); return 50; }

    brix_status_clear(&st);
    if (brix_prepare(c, paths, np, options, optionX, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: prepare: %s\n", st.msg);
        return brix_shellcode(&st);
    }
    if (reply[0] != '\0') {
        printf("%s\n", reply);   /* request id, when the server returns one */
    }
    return 0;
}


/* stage [--wait[=SECS]] <path>... — request tape/disk staging (kXR_prepare + kXR_stage);
 * with --wait, poll each path's residency until online or the timeout (default 300 s). */
int
do_stage(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        reply[1024];
    char        resolved[16][XRDC_PATH_MAX];
    const char *paths[16];
    int         np = 0, i, wait = 0, timeout = 300, rc = 0;

    for (i = 1; i < argc && np < 16; i++) {
        if (strcmp(argv[i], "--wait") == 0) { wait = 1; }
        else if (strncmp(argv[i], "--wait=", 7) == 0) { wait = 1; timeout = atoi(argv[i] + 7); }
        else {
            build_path(cwd, argv[i], resolved[np], sizeof(resolved[np]));
            paths[np] = resolved[np];
            np++;
        }
    }
    if (np == 0) { fprintf(stderr, "usage: stage [--wait[=SECS]] <path>...\n"); return 50; }

    brix_status_clear(&st);
    if (brix_prepare(c, paths, np, kXR_stage, 0, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: stage: %s\n", st.msg);
        return brix_shellcode(&st);
    }
    if (reply[0] != '\0') { printf("%s\n", reply); }
    if (wait) {
        for (i = 0; i < np; i++) {
            int w = wait_online(c, paths[i], timeout, &st);
            if (w < 0) {
                fprintf(stderr, "xrdfs: stage --wait %s: %s\n", paths[i], st.msg);
                rc = brix_shellcode(&st);
            } else if (w == 1) {
                fprintf(stderr, "xrdfs: stage --wait %s: still offline after %ds\n",
                        paths[i], timeout);
                rc = 1;
            } else {
                printf("online: %s\n", paths[i]);
            }
        }
    }
    return rc;
}


/* evict <path>... — request eviction from disk cache (kXR_prepare + kXR_evict). */
int
do_evict(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        reply[1024];
    char        resolved[16][XRDC_PATH_MAX];
    const char *paths[16];
    int         np = 0, i;

    for (i = 1; i < argc && np < 16; i++) {
        build_path(cwd, argv[i], resolved[np], sizeof(resolved[np]));
        paths[np] = resolved[np];
        np++;
    }
    if (np == 0) { fprintf(stderr, "usage: evict <path>...\n"); return 50; }

    brix_status_clear(&st);
    if (brix_prepare(c, paths, np, 0, kXR_evict, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: evict: %s\n", st.msg);
        return brix_shellcode(&st);
    }
    if (reply[0] != '\0') { printf("%s\n", reply); }
    return 0;
}
