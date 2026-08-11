/*
 * xrdfs_meta_ns.c - namespace mutations (mkdir / rm / rmdir / mv / chmod /
 * truncate), split from xrdfs_meta.c at phase-103; behavior-identical.
 */
#include "xrdfs_internal.h"

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

/* WHAT: rm_one_path — delete one already-built absolute path (file, or whole
 *       tree with recursive). Returns 0 on success, else the exit code.
 * WHY:  the single-path delete pipeline extracted so do_rm can loop over
 *       every operand — each path owns its refusal/stat/delete sequence.
 * HOW:  recursive stats the target; directories go through brix_rmtree
 *       (post-order, depth-capped). The resolved export root "/" is always
 *       refused. brix_rmtree probes each kXR_isDir entry with brix_lstat
 *       before descending: directory symlinks (kXR_other) are unlinked, not
 *       descended, matching POSIX `rm -r` semantics. */
static int
rm_one_path(brix_conn *c, const char *path, int recursive, int verbose)
{
    brix_status st;

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

/* WHAT: rm [-r] [-v] <path> [path ...] — delete every named file, or whole
 *       trees with -r. Returns 0 when all deletes succeed, else the first
 *       failure's exit code.
 * WHY:  rmdir only takes empty dirs; users cleaning a tree need one command.
 *       Multiple operands used to silently act on the LAST path only
 *       (feature-parity audit §9.2); each operand is now deleted
 *       independently, POSIX rm-style: a failing path is reported and the
 *       remaining operands still processed.
 * HOW:  flags parsed in a first pass; a second pass loops every non-flag
 *       operand through rm_one_path, remembering the first failing code. */
int
do_rm(brix_conn *c, const char *cwd, int argc, char **argv)
{
    char path[XRDC_PATH_MAX];
    int  recursive = 0, verbose = 0, worst = 0, npaths = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0) {
            recursive = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        }
    }
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0
            || strcmp(argv[i], "-v") == 0
            || strcmp(argv[i], "--verbose") == 0) {
            continue;
        }
        npaths++;
        build_path(cwd, argv[i], path, sizeof(path));
        {
            int path_rc = rm_one_path(c, path, recursive, verbose);

            if (worst == 0) { worst = path_rc; }
        }
    }
    if (npaths == 0) {
        fprintf(stderr, "usage: rm [-r] [-v, --verbose] <path> [path ...]\n");
        return 50;
    }
    return worst;
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

