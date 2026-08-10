/*
 * xrdfs_meta.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"
#include "protocols/shared/zip.h"   /* ls -Z: shared central-directory parser */


/* WHAT: Evaluates one stock `stat -q` query string ("IsDir|Offline",
 *       "IsReadable&IsDir", …) against a stat flags word. Returns 1 (holds),
 *       0 (does not hold), or -1 (unknown flag name — usage error).
 * WHY:  stock xrdfs contract, pinned live against xrdfs 5.6.9: '&' requires
 *       every named flag, '|' is satisfied by any; evaluation is a linear
 *       left-to-right fold with no precedence. Exit codes at the caller:
 *       0 holds, 55 fails, 50 unknown flag.
 * HOW:  walk '&'/'|'-separated tokens; map each name through the stock
 *       vocabulary table to its kXR bit; fold presence with the separator
 *       that PRECEDED the token. */
static int
stat_query_eval(const char *query, int flags)
{
    static const struct { const char *name; int bit; } vocab[] = {
        { "XBitSet",     kXR_xset     },
        { "IsDir",       kXR_isDir    },
        { "Other",       kXR_other    },
        { "Offline",     kXR_offline  },
        { "POSCPending", kXR_poscpend },
        { "IsReadable",  kXR_readable },
        { "IsWriteable", kXR_writable },
        { NULL,          0            },
    };
    const char *cursor = query;
    int         holds = -1;               /* -1 = first token pending */
    char        sep = 0;

    while (*cursor != '\0') {
        char   token[24];
        size_t token_len = 0;
        int    bit = -1, present, k;

        while (*cursor != '\0' && *cursor != '&' && *cursor != '|') {
            if (token_len + 1 < sizeof(token)) {
                token[token_len++] = *cursor;
            }
            cursor++;
        }
        token[token_len] = '\0';

        for (k = 0; vocab[k].name != NULL; k++) {
            if (strcmp(token, vocab[k].name) == 0) {
                bit = vocab[k].bit;
                break;
            }
        }
        if (bit < 0) {
            return -1;
        }

        present = (flags & bit) != 0;
        if (holds < 0) {
            holds = present;
        } else if (sep == '&') {
            holds = holds && present;
        } else {
            holds = holds || present;
        }

        if (*cursor != '\0') {
            sep = *cursor;
            cursor++;
        }
    }

    return holds < 0 ? -1 : holds;
}

/* WHAT: stat [-j] [-q query] <path> [path ...] — print metadata for every
 *       named path in human or JSON format (one JSON object per path).
 *       Returns 0 when all paths stat cleanly (and, with -q, every path
 *       satisfies the flag query), 55 when a path fails the query, else the
 *       first failure's exit code.
 * WHY:  -j enables machine-readable output for scripting and pipeline use.
 *       -q is the stock flag-query contract (parity audit §7.12): shell
 *       scripts branch on "is this a directory / offline / writable" without
 *       parsing output. Multiple operands used to silently act on the LAST
 *       path only (feature-parity audit §9.2); every operand now gets its own
 *       stat, and a failure is reported without hiding the remaining paths'
 *       output.
 * HOW:  flags are parsed in a first pass (-q consumes its value); a second
 *       pass treats every other argument as an operand: build_path →
 *       brix_stat → print → evaluate -q, remembering the first failing exit
 *       code. On a per-path error nothing goes to stdout for that path so
 *       partial JSON is never emitted. */
int
do_stat(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];
    const char   *query = NULL;
    int           json = 0, worst = 0, npaths = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query = argv[++i];
        }
    }
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            continue;
        }
        if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            i++;                          /* skip the query value operand */
            continue;
        }
        npaths++;
        build_path(cwd, argv[i], path, sizeof(path));

        brix_status_clear(&st);
        if (brix_stat(c, path, &si, &st) != 0) {
            int path_rc = xrdfs_report_err("stat", path, &st, 0, c);

            if (worst == 0) { worst = path_rc; }
            continue;
        }
        if (json) { json_statinfo(path, &si); } else { print_statinfo(path, &si); }

        if (query != NULL) {
            int q = stat_query_eval(query, si.flags);

            if (q < 0) {
                fprintf(stderr, "xrdfs: stat: unknown -q flag in '%s' "
                        "(XBitSet, IsDir, Other, Offline, POSCPending, "
                        "IsReadable, IsWriteable)\n", query);
                return 50;
            }
            if (q == 0 && worst == 0) {
                worst = 55;               /* stock: query not satisfied */
            }
        }
    }
    if (npaths == 0) {
        fprintf(stderr, "usage: stat [-j] [-q query] <path> [path ...]\n");
        return 50;
    }
    return worst;
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
/* ls option bundle — the stock flag surface threaded through the printers as
 * ONE pointer instead of a widening parameter fan-out. url_base ("root://h:p",
 * or "" = off) implements -u; want_cksum implements -C (a kXR_Qcksum per
 * non-directory entry, appended as "algo:hex"). */
typedef struct {
    int   want_long;
    int   recursive;
    int   human;
    int   want_cksum;
    char  url_base[300];
} ls_opts;

static void
ls_print_entry(brix_conn *c, const brix_dirent *ent, const char *prefix,
               const ls_opts *o)
{
    char cksum_col[XRDC_CKV_HEX_MAX + 24];

    /* -C: checksum every non-directory entry. A per-entry query failure is
     * reported inline ("adler32:err") and never aborts the listing. */
    cksum_col[0] = '\0';
    if (o->want_cksum
        && !(ent->have_stat && (ent->st.flags & kXR_isDir))) {
        char full[XRDC_PATH_MAX];
        char hex[XRDC_CKV_HEX_MAX];
        brix_status qst;

        brix_status_clear(&qst);
        if ((size_t) snprintf(full, sizeof(full), "%s%s", prefix, ent->name)
                < sizeof(full)
            && brix_query_cksum(c, full, "adler32", hex, sizeof(hex),
                                &qst) == 0) {
            snprintf(cksum_col, sizeof(cksum_col), "  adler32:%s", hex);
        } else {
            snprintf(cksum_col, sizeof(cksum_col), "  adler32:err");
        }
    }

    if (o->want_long && ent->have_stat) {
        int  f  = ent->st.flags;
        char td = (f & kXR_isDir)    ? 'd' : '-';
        char r  = (f & kXR_readable) ? 'r' : '-';
        char w  = (f & kXR_writable) ? 'w' : '-';
        char szs[32];
        fmt_size(ent->st.size, szs, sizeof(szs), o->human);
        printf("%c%c%c %12s %s%s%s%s\n", td, r, w, szs, o->url_base,
               prefix, ent->name, cksum_col);
    } else {
        printf("%s%s%s%s\n", o->url_base, prefix, ent->name, cksum_col);
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
static int ls_print_dir_opts(brix_conn *c, const char *path,
                             const ls_opts *o, brix_status *st);

static int
ls_recurse_subdirs(brix_conn *c, const char *path, const brix_dirent *ents,
                   size_t n, const ls_opts *o, brix_status *st)
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
        if (ls_print_dir_opts(c, full, o, st) != 0) {
            return -1;
        }
    }
    return 0;
}


/* Print one directory's entries per the option bundle; if recursive, descend
 * into each subdir under a "fullpath:" section header (classic ls -R). 0/-1. */
static int
ls_print_dir_opts(brix_conn *c, const char *path, const ls_opts *o,
                  brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, k;
    char         prefix[XRDC_PATH_MAX + 2];
    size_t       plen;
    const char  *sep;

    if (brix_dirlist(c, path, (o->want_long || o->recursive || o->want_cksum),
                     &ents, &n, st) != 0) {
        return -1;
    }
    plen = strlen(path);
    sep = (plen > 0 && path[plen - 1] == '/') ? "" : "/";
    snprintf(prefix, sizeof(prefix), "%s%s", path, sep);

    for (k = 0; k < n; k++) {
        ls_print_entry(c, &ents[k], prefix, o);
    }
    if (o->recursive
        && ls_recurse_subdirs(c, path, ents, n, o, st) != 0) {
        free(ents);
        return -1;
    }
    free(ents);
    return 0;
}


/* pread adapter: brix_zip_pread_fn over an open resilient remote file. */
typedef struct {
    brix_rfile  *rf;
    brix_status *st;
} ls_zip_pread_ctx;

static ssize_t
ls_zip_pread(void *vctx, uint64_t off, void *buf, size_t len)
{
    ls_zip_pread_ctx *zc = (ls_zip_pread_ctx *) vctx;

    return brix_rfile_pread(zc->rf, (int64_t) off, buf, len, zc->st);
}

/* WHAT: ls -Z — list a remote ZIP archive's members: one line per member,
 *       "<uncomp_size> <name>" (long mode adds the method and CRC-32).
 *       Returns 0 on success, -1 with *st set (not-a-zip included).
 * WHY:  stock xrdfs ls -Z lists archive content in place of a directory
 *       listing (parity audit §7.12); the shared bounds-checked central-
 *       directory parser (protocols/shared/zip.h) already serves xrdcp's
 *       unzip path, so this is a read-only reuse — random reads through a
 *       resilient rfile, no extraction.
 * HOW:  stat for the archive size, open a read rfile, parse the central
 *       directory via the pread adapter, print entries, free everything on
 *       every exit path. */
static int
ls_zip_archive(brix_conn *c, const char *path, const ls_opts *o,
               brix_status *st)
{
    brix_statinfo    si;
    brix_rfile       rf;
    ls_zip_pread_ctx zc;
    brix_zip_dir     dir;
    int              zr;
    size_t           k;

    if (brix_stat(c, path, &si, st) != 0) {
        return -1;
    }
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &rf, st) != 0) {
        return -1;
    }
    zc.rf = &rf;
    zc.st = st;

    zr = brix_zip_open(ls_zip_pread, &zc, (uint64_t) si.size, &dir);
    if (zr != XRDC_ZIP_OK) {
        brix_status_clear(st);
        brix_rfile_close(&rf, st);
        if (zr == XRDC_ZIP_ENOTZIP) {
            brix_status_set(st, XRDC_EUSAGE, 0, "not a ZIP archive: %s", path);
        } else {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "ZIP directory parse failed (%d): %s", zr, path);
        }
        return -1;
    }

    for (k = 0; k < dir.n; k++) {
        const brix_zip_entry *e = &dir.entries[k];
        char szs[32];

        fmt_size((int64_t) e->uncomp_size, szs, sizeof(szs), o->human);
        if (o->want_long) {
            printf("%12s %7s %08x %s\n", szs,
                   e->method == 0 ? "store" : "deflate", e->crc32, e->name);
        } else {
            printf("%12s %s\n", szs, e->name);
        }
    }

    brix_zip_dir_free(&dir);
    brix_status_clear(st);
    brix_rfile_close(&rf, st);
    return 0;
}

/* Historical fixed-flag entry point (kept for the header surface). */
int
ls_print_dir(brix_conn *c, const char *path, int want_long, int recursive,
             int human, brix_status *st)
{
    ls_opts o;

    memset(&o, 0, sizeof(o));
    o.want_long = want_long;
    o.recursive = recursive;
    o.human     = human;
    return ls_print_dir_opts(c, path, &o, st);
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
    ls_opts     o;
    int         json = 0, zip = 0, i;

    /* Stock flag surface (parity audit §7.12): -u prints entries as URLs,
     * -C checksums every entry, -Z lists a ZIP archive's members, -D shows
     * duplicate entries — accepted as a no-op here because a single-server
     * listing is never merged, so there are no duplicates to re-show. */
    memset(&o, 0, sizeof(o));
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)      { o.want_long = 1; }
        else if (strcmp(argv[i], "-R") == 0) { o.recursive = 1; }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0) { o.human = 1; }
        else if (strcmp(argv[i], "-u") == 0) {
            brix_url snap;
            xrdfs_url_snap(c, &snap);
            snprintf(o.url_base, sizeof(o.url_base), "root://%s:%d",
                     snap.host, snap.port);
        }
        else if (strcmp(argv[i], "-C") == 0) { o.want_cksum = 1; }
        else if (strcmp(argv[i], "-Z") == 0) { zip = 1; }
        else if (strcmp(argv[i], "-D") == 0) { /* no merged listings: no-op */ }
        else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[i], "-lR") == 0 || strcmp(argv[i], "-Rl") == 0) {
            o.want_long = 1; o.recursive = 1;
        } else { arg = argv[i]; }
    }
    build_path(cwd, arg != NULL ? arg : ".", path, sizeof(path));

    brix_status_clear(&st);
    if (zip) {
        if (ls_zip_archive(c, path, &o, &st) != 0) {
            return xrdfs_report_err("ls -Z", path, &st, 0, c);
        }
        return 0;
    }
    if (json) {
        if (ls_json_dir(c, path, &st) != 0) {
            return xrdfs_report_err("ls", path, &st, 0, c);
        }
        return 0;
    }
    if (ls_print_dir_opts(c, path, &o, &st) != 0) {
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


/* deep-locate walk state: connection + wire options + failure latch. */
typedef struct {
    brix_conn *conn;
    unsigned   options;
    int        failures;
} locate_deep_ctx;

/* WHAT: walk_dir visitor for locate -d — locates every non-directory entry
 *       and prints "<path>: <reply>"; failures are reported and counted, the
 *       walk continues. Always returns 0 (never aborts the walk).
 * WHY:  stock deep-locate reports the locations of every FILE under the tree;
 *       one dead entry must not hide the rest.
 * HOW:  skip directories (their children are visited anyway); locate with the
 *       caller's wire options; print or report per entry. */
static int
locate_deep_visit(const char *full, const brix_dirent *e, int depth, void *u)
{
    locate_deep_ctx *dc = (locate_deep_ctx *) u;
    brix_status      st;
    char             reply[1024];

    (void) depth;
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        return 0;
    }
    brix_status_clear(&st);
    if (brix_locate_opts(dc->conn, full, dc->options, reply, sizeof(reply),
                         &st) != 0) {
        (void) xrdfs_report_err("locate", full, &st, 0, dc->conn);
        dc->failures++;
        return 0;
    }
    printf("%s: %s\n", full, reply);
    return 0;
}

/* WHAT: locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path> — resolve a path to
 *       its serving endpoint(s); -d recurses, locating every file under a
 *       directory. Returns 0 on success, else the first failure's exit code.
 * WHY:  stock xrdfs flag surface (parity audit §7.12 — options were hardcoded
 *       to 0): -r sets kXR_refresh (BriX flushes + bypasses the loc/redirect
 *       caches, §2.7), -n sets kXR_nowait (immediate possibly-incomplete
 *       answer; stock servers honor it), -m/-h set kXR_prefname (DNS names
 *       over IPs — already this server's default). -i (no name resolution)
 *       and -p (no tried= opaque) are accepted for stock CLI compatibility:
 *       this client already never resolves names in locate replies and never
 *       sends tried= on a first attempt, so both are satisfied by default.
 * HOW:  parse flags into wire option bits; -d stats the target — a directory
 *       walks via walk_dir with locate_deep_visit, anything else falls
 *       through to the single-path locate. */
int
do_locate(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];
    const char *arg = NULL;
    unsigned    options = 0;
    int         deep = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            options |= kXR_refresh;
        } else if (strcmp(argv[i], "-n") == 0) {
            options |= kXR_nowait;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-h") == 0) {
            options |= kXR_prefname;
        } else if (strcmp(argv[i], "-d") == 0) {
            deep = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-p") == 0) {
            /* accepted for stock CLI compatibility; see WHY above */
        } else if (argv[i][0] == '-') {
            fprintf(stderr,
                    "usage: locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path>\n");
            return 50;
        } else {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr,
                "usage: locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));

    if (deep) {
        brix_statinfo si;

        brix_status_clear(&st);
        if (brix_stat(c, path, &si, &st) != 0) {
            return xrdfs_report_err("locate", path, &st, 0, c);
        }
        if (si.flags & kXR_isDir) {
            locate_deep_ctx dc = { c, options, 0 };

            brix_status_clear(&st);
            if (walk_dir(c, path, 0, locate_deep_visit, &dc, &st) < 0) {
                return xrdfs_report_err("locate -d", path, &st, 0, c);
            }
            return dc.failures ? 54 : 0;
        }
        /* -d on a plain file falls through to the single locate */
    }

    brix_status_clear(&st);
    if (brix_locate_opts(c, path, options, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("locate", path, &st, 0, c);
    }
    printf("%s\n", reply);
    return 0;
}


/* WHAT: cache {evict|fevict} <path> — the stock operator cache-eviction
 *       command (parity audit §4.11/§7.12): asks the server to drop the
 *       path's cached copy. Returns 0 on success, else the failure's code.
 * WHY:  drop-in with stock xrdfs: the command travels as kXR_set
 *       "cache <verb> <path>" (pinned live against 5.6.9). On BriX both
 *       spellings evict; the in-use refusal that distinguishes stock's evict
 *       from fevict is a documented divergence.
 * HOW:  validate the sub-verb, build the confined path, send the kXR_set
 *       command via brix_set_cmd, print any reply text. */
int
do_cache(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], payload[XRDC_PATH_MAX + 32];
    char        reply[256];

    if (argc < 3
        || (strcmp(argv[1], "evict") != 0 && strcmp(argv[1], "fevict") != 0)) {
        fprintf(stderr, "usage: cache {evict | fevict} <path>\n");
        return 50;
    }
    build_path(cwd, argv[2], path, sizeof(path));
    snprintf(payload, sizeof(payload), "cache %s %s", argv[1], path);

    brix_status_clear(&st);
    if (brix_set_cmd(c, payload, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("cache", path, &st, 1, c);
    }
    if (reply[0] != '\0') {
        printf("%s\n", reply);
    }
    return 0;
}

/* WHAT: spaceinfo [path] — the stock xrdfs report: Path/Total/Free/Used/
 *       Largest free chunk, one per line, labels padded to column 21 (byte
 *       shape captured live from stock 5.6.9). Returns 0 / mapped code.
 * WHY:  §7.12 — BriX had no spaceinfo verb at all; stock scripts parse this
 *       exact layout. The numbers come from kXR_Qspace's oss.* keys
 *       (space/free/used/maxf), the same source stock reads.
 * HOW:  query Qspace on the (cwd-resolved) path, pull the four keys out of
 *       the &-separated reply, print stock's five lines. */
int
do_spaceinfo(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];
    const char *keys[4] = { "oss.space=", "oss.free=", "oss.used=",
                            "oss.maxf=" };
    const char *labels[4] = { "Total:", "Free:", "Used:",
                              "Largest free chunk:" };
    long long   vals[4];
    int         k;

    build_path(cwd, argc >= 2 ? argv[1] : "/", path, sizeof(path));
    brix_status_clear(&st);
    if (brix_query(c, kXR_Qspace, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("spaceinfo", path, &st, 0, c);
    }
    for (k = 0; k < 4; k++) {
        const char *hit = strstr(reply, keys[k]);

        if (hit == NULL) {
            fprintf(stderr, "xrdfs: spaceinfo: server reply lacks %s\n",
                    keys[k]);
            return 54;
        }
        vals[k] = atoll(hit + strlen(keys[k]));
    }
    printf("%-20s%s\n", "Path:", path);
    for (k = 0; k < 4; k++) {
        printf("%-20s%lld\n", labels[k], vals[k]);
    }
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

