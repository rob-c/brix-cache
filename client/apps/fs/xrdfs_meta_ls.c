/*
 * xrdfs_meta_ls.c - the ls family (plain / long / recursive / JSON / ZIP),
 * split from xrdfs_meta.c at phase-103; behavior-identical, with do_ls's
 * flag parsing extracted (CCN 20 -> ls_parse_opts + a flat dispatcher).
 */
#include "xrdfs_internal.h"
#include "protocols/shared/zip.h"   /* ls -Z: shared central-directory parser */

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



/* Fold the stock ls flag surface into the option bundle.  -D is accepted as a
 * no-op (a single-server listing is never merged, so there are no duplicates
 * to re-show); the last non-flag argument is the operand. */
static void
ls_parse_opts(brix_conn *c, int argc, char **argv, ls_opts *o, int *json,
              int *zip, const char **arg)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)      { o->want_long = 1; }
        else if (strcmp(argv[i], "-R") == 0) { o->recursive = 1; }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0) { o->human = 1; }
        else if (strcmp(argv[i], "-u") == 0) {
            brix_url snap;
            xrdfs_url_snap(c, &snap);
            snprintf(o->url_base, sizeof(o->url_base), "root://%s:%d",
                     snap.host, snap.port);
        }
        else if (strcmp(argv[i], "-C") == 0) { o->want_cksum = 1; }
        else if (strcmp(argv[i], "-Z") == 0) { *zip = 1; }
        else if (strcmp(argv[i], "-D") == 0) { /* no merged listings: no-op */ }
        else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            *json = 1;
        } else if (strcmp(argv[i], "-lR") == 0 || strcmp(argv[i], "-Rl") == 0) {
            o->want_long = 1; o->recursive = 1;
        } else { *arg = argv[i]; }
    }
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
    int         json = 0, zip = 0;

    /* Stock flag surface (parity audit §7.12): -u prints entries as URLs,
     * -C checksums every entry, -Z lists a ZIP archive's members, -D shows
     * duplicate entries — accepted as a no-op here because a single-server
     * listing is never merged, so there are no duplicates to re-show. */
    memset(&o, 0, sizeof(o));
    ls_parse_opts(c, argc, argv, &o, &json, &zip, &arg);
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
