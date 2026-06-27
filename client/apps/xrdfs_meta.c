/*
 * xrdfs_meta.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


int
do_stat(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: stat <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: stat %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 0, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    print_statinfo(path, &si);
    return 0;
}


/* Print one directory's entries; if recursive, descend into each subdir under a
 * "fullpath:" section header (classic ls -R). 0 / -1. */

int
ls_print_dir(xrdc_conn *c, const char *path, int want_long, int recursive,
             int human, xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, k;
    char         prefix[XRDC_PATH_MAX + 2];
    size_t       plen;
    const char  *sep;

    if (xrdc_dirlist(c, path, (want_long || recursive), &ents, &n, st) != 0) {
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
            char w  = (f & kXR_writable) ? 'w' : '-';
            char szs[32];
            fmt_size(ents[k].st.size, szs, sizeof(szs), human);
            printf("%c%c%c %12s %s%s\n", td, r, w, szs, prefix, ents[k].name);
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
            if (ls_print_dir(c, full, want_long, 1, human, st) != 0) {
                free(ents);
                return -1;
            }
        }
    }
    free(ents);
    return 0;
}


int
do_ls(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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
    build_path(cwd, arg != NULL ? arg : ".", path, sizeof(path));

    xrdc_status_clear(&st);
    if (ls_print_dir(c, path, want_long, recursive, human, &st) != 0) {
        fprintf(stderr, "xrdfs: ls %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 0, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_mkdir(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_mkdir(c, path, mode, parents, &st) != 0) {
        fprintf(stderr, "xrdfs: mkdir %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_rm(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: rm <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_rm(c, path, &st) != 0) {
        fprintf(stderr, "xrdfs: rm %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_rmdir(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: rmdir <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_rmdir(c, path, &st) != 0) {
        fprintf(stderr, "xrdfs: rmdir %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_mv(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        src[XRDC_PATH_MAX], dst[XRDC_PATH_MAX];

    if (argc < 3) { fprintf(stderr, "usage: mv <src> <dst>\n"); return 50; }
    build_path(cwd, argv[1], src, sizeof(src));
    build_path(cwd, argv[2], dst, sizeof(dst));
    xrdc_status_clear(&st);
    if (xrdc_mv(c, src, dst, &st) != 0) {
        fprintf(stderr, "xrdfs: mv: %s\n", st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


/* chmod [-R] <path> <mode> — keeps the historical xrdfs arg order (path first).
 * <mode> is the stock 9-char symbolic form ("rwxr-xr-x") or an octal absolute
 * mode ("755"). -R recurses into directories, applying the same mode to every
 * entry. */
int
do_chmod(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_chmod(c, path, mode, &st) != 0) {
        fprintf(stderr, "xrdfs: chmod %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    if (recursive) {
        int         failures = 0;
        xrdc_status wst;
        xrdc_status_clear(&wst);
        if (chmod_recursive(c, path, mode, &failures, &wst) != 0) {
            fprintf(stderr, "xrdfs: chmod -R %s: %s\n", path, wst.msg);
            return xrdc_shellcode(&wst);
        }
        if (failures > 0) { return 1; }   /* per-entry errors already reported */
    }
    return 0;
}


int
do_truncate(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    long long   size;

    if (argc < 3) { fprintf(stderr, "usage: truncate <path> <size>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    size = strtoll(argv[2], NULL, 10);
    xrdc_status_clear(&st);
    if (xrdc_truncate(c, path, (int64_t) size, &st) != 0) {
        fprintf(stderr, "xrdfs: truncate %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);   /* Phase 40 (c) */
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_locate(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX], reply[1024];

    if (argc < 2) { fprintf(stderr, "usage: locate <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_locate(c, path, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: locate %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("%s\n", reply);
    return 0;
}


int
do_statvfs(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX], reply[1024];

    build_path(cwd, argc >= 2 ? argv[1] : "/", path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_statvfs(c, path, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: statvfs %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("%s\n", reply);
    return 0;
}


/* df [-h] [path] — friendly disk-space report over kXR_Qspace (the server's oss.*
 * capacity record). Default path "/". -h humanizes the byte columns. Falls back to
 * printing the raw reply verbatim when the shape is unrecognized (never crashes).
 * Cluster-wide aggregation (per-holder rows) is out of scope here — use `xrdmapc`. */
int
do_df(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX], reply[4096];
    int64_t     total, avail, used, largest;
    int         human = 0, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { human = 1; }
        else { arg = argv[i]; }
    }
    build_path(cwd, arg != NULL ? arg : "/", path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_query(c, kXR_Qspace, path, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: df %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
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


/* touch [-c] [-a] [-m] [-t STAMP] <path> — create the file if absent (unless -c) and
 * set its access/modification times (default: both to now). -a/-m restrict to
 * atime/mtime; -t sets an explicit [[CC]YY]MMDDhhmm[.ss] time. NEVER changes
 * ownership: xrdc_setattr is always called with set_owner = 0. */
int
do_touch(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            path[XRDC_PATH_MAX];
    struct timespec times[2], tspec;
    const char     *arg = NULL;
    int             no_create = 0, do_atime = 0, do_mtime = 0, have_t = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)      { no_create = 1; }
        else if (strcmp(argv[i], "-a") == 0) { do_atime = 1; }
        else if (strcmp(argv[i], "-m") == 0) { do_mtime = 1; }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (touch_parse_time(argv[++i], &tspec) != 0) {
                fprintf(stderr, "xrdfs: touch: bad -t timestamp '%s' "
                                "(want [[CC]YY]MMDDhhmm[.ss])\n", argv[i]);
                return 50;
            }
            have_t = 1;
        } else { arg = argv[i]; }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: touch [-c] [-a] [-m] [-t STAMP] <path>\n");
        return 50;
    }
    if (!do_atime && !do_mtime) { do_atime = do_mtime = 1; }   /* default: both */
    build_path(cwd, arg, path, sizeof(path));

    /* atime = slot 0, mtime = slot 1; per-field UTIME_OMIT when not selected. */
    times[0].tv_sec = times[1].tv_sec = 0;
    times[0].tv_nsec = do_atime ? (have_t ? 0 : UTIME_NOW) : UTIME_OMIT;
    times[1].tv_nsec = do_mtime ? (have_t ? 0 : UTIME_NOW) : UTIME_OMIT;
    if (have_t) {
        if (do_atime) { times[0] = tspec; }
        if (do_mtime) { times[1] = tspec; }
    }

    if (no_create) {
        /* -c: an absent file is a silent no-op (POSIX). */
        xrdc_statinfo si;
        xrdc_status   pst;
        xrdc_status_clear(&pst);
        if (xrdc_stat(c, path, &si, &pst) != 0) { return 0; }
    } else {
        /* Create-if-absent: force=0 ⇒ kXR_new (fails if it already exists, which we
         * ignore — the file is there and the setattr below still runs). */
        xrdc_file   f;
        xrdc_status cs;
        xrdc_status_clear(&cs);
        if (xrdc_file_open_write(c, path, 0 /*force=new*/, 0 /*posc*/, &f, &cs) == 0) {
            xrdc_file_close(c, &f, &cs);
        }
    }

    xrdc_status_clear(&st);
    if (xrdc_setattr(c, path, 1 /*set_times*/, times, 0 /*set_owner*/,
                     (uint32_t) -1, (uint32_t) -1, &st) != 0) {
        fprintf(stderr, "xrdfs: touch %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);
        return xrdc_shellcode(&st);
    }
    return 0;
}


/* ln [-s] [-f] <target> <linkpath> — create a hard link (default) or a symbolic link
 * (-s), GNU arg order (target first). -f removes an existing linkpath first
 * (best-effort, non-atomic). For -s the target is stored verbatim (link content, not
 * path-resolved); only linkpath is confined. Hard links confine both paths. */
int
do_ln(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (force) {
        xrdc_status rmst;
        xrdc_status_clear(&rmst);
        (void) xrdc_rm(c, linkpath, &rmst);   /* best-effort; ignore "not found" */
    }
    if (symbolic) {
        if (xrdc_symlink(c, target, linkpath, &st) != 0) {   /* target verbatim */
            fprintf(stderr, "xrdfs: ln -s %s %s: %s\n", target, linkpath, st.msg);
            xrdc_cred_hint_for_status(&st, 1, stderr);
            return xrdc_shellcode(&st);
        }
        return 0;
    }
    build_path(cwd, target, oldpath, sizeof(oldpath));   /* hard link: both confined */
    if (xrdc_link(c, oldpath, linkpath, &st) != 0) {
        fprintf(stderr, "xrdfs: ln %s %s: %s\n", oldpath, linkpath, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);
        return xrdc_shellcode(&st);
    }
    return 0;
}


/* readlink <path> — print a symlink's target. xrdc_readlink returns the TRUE target
 * length (which may exceed the buffer); guard against printing a truncated value. */
int
do_readlink(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX], target[XRDC_PATH_MAX];
    ssize_t     n;

    if (argc < 2) { fprintf(stderr, "usage: readlink <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    n = xrdc_readlink(c, path, target, sizeof(target), &st);
    if (n < 0) {
        fprintf(stderr, "xrdfs: readlink %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
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
do_cksum(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX], hex[160];
    const char *algo = "adler32", *arg = NULL;
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) { algo = argv[++i]; }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: cksum [-a algo] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_query_cksum(c, path, algo, hex, sizeof(hex), &st) != 0) {
        fprintf(stderr, "xrdfs: cksum %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
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
xattr_ls(xrdc_conn *c, const char *path)
{
    xrdc_status st;
    char        names[8192];
    size_t      total = 0, off;

    xrdc_status_clear(&st);
    if (xrdc_fattr_list(c, path, names, sizeof(names), &total, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr ls %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
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


int
do_xattr(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) {
        fprintf(stderr, "usage: xattr ls|get|set|rm <path> [name] [value]\n");
        return 50;
    }
    /* `xattr <path>` (no subcommand) → list. */
    if (strcmp(argv[1], "ls") != 0 && strcmp(argv[1], "get") != 0
        && strcmp(argv[1], "set") != 0 && strcmp(argv[1], "rm") != 0) {
        build_path(cwd, argv[1], path, sizeof(path));
        return xattr_ls(c, path);
    }
    if (argc < 3) {
        fprintf(stderr, "usage: xattr %s <path> ...\n", argv[1]);
        return 50;
    }
    build_path(cwd, argv[2], path, sizeof(path));
    xrdc_status_clear(&st);

    if (strcmp(argv[1], "ls") == 0) {
        return xattr_ls(c, path);
    }
    if (strcmp(argv[1], "get") == 0) {
        char   val[8192];
        size_t vlen = 0;
        if (argc < 4) { fprintf(stderr, "usage: xattr get <path> <name>\n"); return 50; }
        if (xrdc_fattr_get(c, path, argv[3], val, sizeof(val), &vlen, &st) != 0) {
            fprintf(stderr, "xrdfs: xattr get %s [%s]: %s\n", path, argv[3], st.msg);
            return xrdc_shellcode(&st);
        }
        fwrite(val, 1, vlen < sizeof(val) ? vlen : sizeof(val), stdout);
        printf("\n");
        return 0;
    }
    if (strcmp(argv[1], "set") == 0) {
        if (argc < 5) { fprintf(stderr, "usage: xattr set <path> <name> <value>\n"); return 50; }
        if (xrdc_fattr_set(c, path, argv[3], argv[4], strlen(argv[4]), 0, &st) != 0) {
            fprintf(stderr, "xrdfs: xattr set %s [%s]: %s\n", path, argv[3], st.msg);
            return xrdc_shellcode(&st);
        }
        return 0;
    }
    /* rm */
    if (argc < 4) { fprintf(stderr, "usage: xattr rm <path> <name>\n"); return 50; }
    if (xrdc_fattr_del(c, path, argv[3], &st) != 0) {
        fprintf(stderr, "xrdfs: xattr rm %s [%s]: %s\n", path, argv[3], st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}


int
do_query(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_query(c, infotype, args, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: query %s: %s\n", argv[1], st.msg);
        return xrdc_shellcode(&st);
    }
    printf("%s\n", reply);
    return 0;
}


int
do_prepare(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_prepare(c, paths, np, options, optionX, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: prepare: %s\n", st.msg);
        return xrdc_shellcode(&st);
    }
    if (reply[0] != '\0') {
        printf("%s\n", reply);   /* request id, when the server returns one */
    }
    return 0;
}


/* stage [--wait[=SECS]] <path>... — request tape/disk staging (kXR_prepare + kXR_stage);
 * with --wait, poll each path's residency until online or the timeout (default 300 s). */
int
do_stage(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_prepare(c, paths, np, kXR_stage, 0, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: stage: %s\n", st.msg);
        return xrdc_shellcode(&st);
    }
    if (reply[0] != '\0') { printf("%s\n", reply); }
    if (wait) {
        for (i = 0; i < np; i++) {
            int w = wait_online(c, paths[i], timeout, &st);
            if (w < 0) {
                fprintf(stderr, "xrdfs: stage --wait %s: %s\n", paths[i], st.msg);
                rc = xrdc_shellcode(&st);
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
do_evict(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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

    xrdc_status_clear(&st);
    if (xrdc_prepare(c, paths, np, 0, kXR_evict, 0, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "xrdfs: evict: %s\n", st.msg);
        return xrdc_shellcode(&st);
    }
    if (reply[0] != '\0') { printf("%s\n", reply); }
    return 0;
}
