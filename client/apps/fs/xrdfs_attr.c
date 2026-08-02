/*
 * xrdfs_attr.c - xrdfs attribute, timestamp, link, checksum & staging subcommands.
 *
 * WHAT: touch/ln/readlink/cksum/xattr/query/prepare/stage/evict command handlers.
 * WHY:  Phase-38 split of xrdfs_meta.c to keep each file under the 600-line cap,
 *       one concept per file (coding-standards.md §1).
 * HOW:  behavior-identical extraction; the do_* handlers are declared in
 *       xrdfs_internal.h and dispatched from xrdfs.c exactly as before.
 */
#include "xrdfs_internal.h"

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
        return xrdfs_report_err("touch", path, &st, 1, c);
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
        return xrdfs_report_err("readlink", path, &st, 0, c);
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
        return xrdfs_report_err("cksum", path, &st, 0, c);
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
        return xrdfs_report_err("xattr ls", path, &st, 0, c);
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
        return xrdfs_report_err("query", argv[1], &st, 0, c);
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
                rc = xrdfs_report_err("stage --wait", paths[i], &st, 1, c);
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
