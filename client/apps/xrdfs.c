/*
 * xrdfs.c — native XRootD filesystem CLI (full subcommand set + REPL).
 *
 * WHAT: `xrdfs [opts] host[:port] [command [args]]` — connects over root:// and
 *       either runs one command or, when no command is given, drops into an
 *       interactive shell with a working directory. Commands: stat, ls, mkdir,
 *       rm, rmdir, mv, chmod, truncate, cat, tail, locate, query, statvfs,
 *       prepare (+ cd/pwd/help/exit in the REPL).
 * WHY:  A libXrdCl-free `xrdfs` (phase-37) the harness drives via TEST_XRDFS_BIN,
 *       feature-matching the system xrdfs so a conformance diff is meaningful.
 * HOW:  Hand-rolled arg parse → xrdc_connect → table-driven dispatch into the
 *       lib/ops_*.c calls → formatted output → exit with the op's shell code.
 *       Relative paths resolve against the (REPL) working directory via BuildPath.
 *
 * Clean-room: command set/output mirror the documented xrdfs (xrdfs.1), not
 * XrdClFS source.
 */
#include "xrdc.h"
#include "compat/crypto.h"   /* xrootd_crypto_init (libxrdproto SHA/HMAC kernels) */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>     /* upload: open() the local source */
#include <fnmatch.h>   /* find -name glob matching */
#include <regex.h>     /* grep PATTERN matching */
#include <signal.h>    /* tail -f: SIGINT-clean follow loop */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>  /* UTIME_NOW / UTIME_OMIT for touch */
#include <time.h>
#include <unistd.h>    /* dd/upload rate pacing + local read()/close() */

#define XRDFS_MAXTOK 64

/* ------------------------------------------------------------------ */
/* endpoint + path helpers                                             */
/* ------------------------------------------------------------------ */

/* Turn "host[:port]", a root:// URL, or a ~/.xrdrc "alias:suffix" into a connectable
 * xrdc_url. Thin wrapper over the shared xrdc_endpoint_parse (grammar lives in url.c),
 * with alias resolution applied first so `xrdfs lab:/ ls` works. */
static int
endpoint_to_url(const char *ep, xrdc_url *u, xrdc_status *st)
{
    char resolved[XRDC_PATH_MAX];
    xrdc_alias_resolve(ep, resolved, sizeof(resolved));
    return xrdc_endpoint_parse(resolved, u, st);
}

/* Resolve `arg` (absolute or relative to `cwd`) into a clean absolute path in
 * out[outsz], collapsing "." / ".." / duplicate slashes. */
static void
build_path(const char *cwd, const char *arg, char *out, size_t outsz)
{
    xrdc_path_resolve(cwd, arg, out, outsz);   /* shared (lib/path.c) */
}

static void
flags_to_str(int f, char *out, size_t sz)
{
    int first = 1;
    out[0] = '\0';

#define XRDFS_ADD(bit, name)                                      \
    do {                                                          \
        if (f & (bit)) {                                          \
            if (!first) { strncat(out, "|", sz - strlen(out) - 1); } \
            strncat(out, (name), sz - strlen(out) - 1);           \
            first = 0;                                             \
        }                                                         \
    } while (0)

    XRDFS_ADD(kXR_xset,     "XBitSet");
    XRDFS_ADD(kXR_isDir,    "IsDir");
    XRDFS_ADD(kXR_other,    "Other");
    XRDFS_ADD(kXR_offline,  "Offline");
    XRDFS_ADD(kXR_readable, "IsReadable");
    XRDFS_ADD(kXR_writable, "IsWritable");
    XRDFS_ADD(kXR_poscpend, "POSCPending");
    XRDFS_ADD(kXR_bkpexist, "BackUpExists");
#undef XRDFS_ADD

    if (first) {
        snprintf(out, sz, "none");
    }
}

/* Forward decls for the recursive-walk helpers (defined with the power tools). */
static int is_dot(const char *name);
static int join_path(const char *dir, const char *name, char *out, size_t sz);
static int chmod_recursive(xrdc_conn *c, const char *path, int mode, int *failures,
                           xrdc_status *st);

/* ------------------------------------------------------------------ */
/* command handlers — argv[0] is the command name; argv[1..argc-1] args */
/* ------------------------------------------------------------------ */

/* Print one labelled "%Y-%m-%d %H:%M:%S" time line in UTC (matching official
 * xrdfs, which formats stat times with gmtime); falls back to the raw epoch. */
static void
print_stat_time(const char *label, long epoch)
{
    time_t    t = (time_t) epoch;
    struct tm tmv;
    char      tb[32];

    if (gmtime_r(&t, &tmv) != NULL
        && strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S", &tmv) > 0) {
        printf("%s%s\n", label, tb);
    } else {
        printf("%s%ld\n", label, epoch);
    }
}

/* Print a stat report in the official xrdfs field order. CTime/ATime/Mode/
 * Owner/Group are emitted only when the server supplied them (have_ext). */
static void
print_statinfo(const char *path, const xrdc_statinfo *si)
{
    char fbuf[256];

    flags_to_str(si->flags, fbuf, sizeof(fbuf));
    printf("Path:   %s\n", path);
    printf("Id:     %llu\n", (unsigned long long) si->id);
    printf("Size:   %lld\n", (long long) si->size);
    print_stat_time("MTime:  ", si->mtime);
    if (si->have_ext) {
        print_stat_time("CTime:  ", si->ctime);
        print_stat_time("ATime:  ", si->atime);
    }
    printf("Flags:  %d (%s)\n", si->flags, fbuf);
    if (si->have_ext) {
        printf("Mode:   0%03o\n", si->mode & 07777);
        printf("Owner:  %s\n", si->owner);
        printf("Group:  %s\n", si->group);
    }
}

static int
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
static void fmt_size(int64_t n, char *out, size_t sz, int human);

static int
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

static int
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

/* ------------------------------------------------------------------ */
/* http(s)/WebDAV endpoints — read-only namespace ops (ls, stat).       */
/*                                                                      */
/* WHAT: When the endpoint is an http/https/dav/davs URL, xrdfs speaks  */
/*       WebDAV PROPFIND for metadata (the webfile.c transport, shared  */
/*       with the FUSE driver) instead of the binary root:// protocol — */
/*       so `xrdfs https://host/path ls` works like the official client.*/
/* WHY:  A WebDAV endpoint has no root:// session; only the read-only    */
/*       metadata ops map cleanly. Mutating/file ops report clearly that */
/*       they need a root:// endpoint.                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    const xrdc_weburl *u;
    const char        *base;     /* URL path component, trailing '/' trimmed */
    const char        *bearer;   /* WebDAV bearer token (or NULL = anonymous) */
    int                verify;   /* verify the TLS server chain (https/davs) */
    const char        *ca_dir;   /* CA hash dir for verification (or NULL) */
} web_ctx;

/* Map a cwd-relative arg onto the absolute server path under the URL base. */
static void
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
static int
web_ls_print_dir(const web_ctx *w, const char *path, int want_long,
                 int recursive, int human, xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, k, plen;
    char         prefix[XRDC_PATH_MAX + 2];
    const char  *sep;

    if (xrdc_web_readdir(w->u, path, w->bearer, w->verify, w->ca_dir,
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

static int
web_ls(const web_ctx *w, const char *cwd, int argc, char **argv)
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
    web_build_path(w->base, cwd, arg, path, sizeof(path));
    xrdc_status_clear(&st);
    if (web_ls_print_dir(w, path, want_long, recursive, human, &st) != 0) {
        fprintf(stderr, "xrdfs: ls %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 0, stderr);
        return xrdc_shellcode(&st);
    }
    return 0;
}

static int
web_stat(const web_ctx *w, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: stat <path>\n"); return 50; }
    web_build_path(w->base, cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (xrdc_web_stat(w->u, path, w->bearer, w->verify, w->ca_dir, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: stat %s: %s\n", path, st.msg);
        xrdc_cred_hint_for_status(&st, 0, stderr);
        return xrdc_shellcode(&st);
    }
    print_statinfo(path, &si);
    return 0;
}

/* Dispatch one command against a WebDAV endpoint. Read-only metadata ops only. */
static int
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

static int
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

static int
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

static int
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

static int
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

/* parse_chmod_mode — accept the stock xrdfs 9-char symbolic form ("rwxr-xr-x",
 * XrdClFS.cc ConvertMode) AND an octal absolute mode ("755") as a local
 * extension. Returns the permission bits, or -1 on a malformed mode. The stock
 * client takes ONLY the symbolic 9-char form, so users/tools that pass it (and
 * our own conformance suite) must get the right bits — previously strtol(…,8)
 * turned "rwxr-xr-x" into 0, silently setting mode 000. */
static int
parse_chmod_mode(const char *s)
{
    size_t n = strlen(s);

    if (n == 9) {
        int i, m = 0, ok = 1;
        for (i = 0; i < 9; i++) {
            char want = "rwx"[i % 3];
            if (s[i] == want) {
                m |= (1 << (8 - i));    /* pos 0 -> 0400 … pos 8 -> 0001 */
            } else if (s[i] != '-') {
                ok = 0;
                break;
            }
        }
        if (ok) {
            return m;
        }
    }

    {
        char *endp = NULL;
        long  v    = strtol(s, &endp, 8);
        if (endp != s && *endp == '\0' && v >= 0) {
            return (int) (v & 07777);
        }
    }
    return -1;
}

/* chmod [-R] <path> <mode> — keeps the historical xrdfs arg order (path first).
 * <mode> is the stock 9-char symbolic form ("rwxr-xr-x") or an octal absolute
 * mode ("755"). -R recurses into directories, applying the same mode to every
 * entry. */
static int
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

static int
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

/* cat / tail / head share an open-read + stream-to-stdout core. tail seeks the tail
 * window via stat size. `limit` caps the number of bytes streamed from `start`
 * (< 0 = stream to EOF); head passes a positive cap, cat/tail pass -1. */
static int
stream_file(xrdc_conn *c, const char *path, int64_t start, int64_t limit,
            xrdc_status *st)
{
    xrdc_rfile rf;
    uint8_t  *buf;
    int64_t   off = start;
    int64_t   remaining = limit;   /* meaningful only when limit >= 0 */
    int       rc = 0;

    /* Resilient read: rides out a mid-stream sever (reconnect + reopen + resume
     * at offset) within the connection's stall window — xrootdfs parity. */
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &rf, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&rf, st);
        return -1;
    }
    for (;;) {
        size_t  want = 1 << 20;
        ssize_t n;
        if (limit >= 0) {
            if (remaining <= 0) { break; }
            if ((int64_t) want > remaining) { want = (size_t) remaining; }
        }
        n = xrdc_rfile_pread(&rf, off, buf, want, st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            xrdc_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
        if (limit >= 0) { remaining -= n; }
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&rf, rc == 0 ? st : &tw);
    }
    return rc;
}

static int
do_cat(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: cat <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (stream_file(c, path, 0, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: cat %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}

/* Stream the first `nlines` newline-delimited lines of `path` to stdout, reading
 * forward in 1 MiB chunks and stopping at the Nth newline (emitting any trailing
 * partial line if EOF arrives first). 0 / -1. */
static int
head_lines(xrdc_conn *c, const char *path, long nlines, xrdc_status *st)
{
    xrdc_rfile f;
    uint8_t  *buf;
    int64_t   off = 0;
    long      seen = 0;
    int       rc = 0;

    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (seen < nlines) {
        ssize_t n = xrdc_rfile_pread(&f, off, buf, 1 << 20, st);
        size_t  emit;
        ssize_t i;
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        emit = (size_t) n;
        for (i = 0; i < n; i++) {
            if (buf[i] == '\n' && ++seen == nlines) {
                emit = (size_t) (i + 1);
                break;
            }
        }
        if (fwrite(buf, 1, emit, stdout) != emit) {
            xrdc_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}

/* head [-c BYTES] [-n LINES] <path> — print the start of a file. -c (byte count) wins
 * over -n (line count, default 10); both modes stream forward only. */
static int
do_head(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    long long   nbytes = -1;   /* -c; < 0 = not set */
    long        nlines = 10;   /* -n default */
    const char *arg = NULL;
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            nbytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = strtol(argv[++i], NULL, 10);
        } else { arg = argv[i]; }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: head [-c BYTES] [-n LINES] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    xrdc_status_clear(&st);

    if (nbytes >= 0) {
        if (stream_file(c, path, 0, (int64_t) nbytes, &st) != 0) {
            fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
        return 0;
    }
    if (nlines <= 0) { return 0; }   /* head -n 0 → nothing */
    if (head_lines(c, path, nlines, &st) != 0) {
        fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}

/* tail -f sets this from a SIGINT handler so the follow loop exits cleanly. */
static volatile sig_atomic_t tail_stop = 0;

static void
tail_sigint(int sig)
{
    (void) sig;
    tail_stop = 1;
}

/* Compute the byte offset at which the last `nlines` lines of a `size`-byte file
 * begin, scanning backward in 64 KiB windows. A single trailing newline at EOF is
 * not counted (it terminates the last line; it does not start an extra one). Sets
 * *start (0 if the whole file is within the window). 0 / -1. */
static int
tail_start_for_lines(xrdc_conn *c, const char *path, int64_t size, long nlines,
                     int64_t *start, xrdc_status *st)
{
    xrdc_rfile    f;
    uint8_t      *buf;
    const int64_t WIN = 1 << 16;
    int64_t       pos = size;
    long          newlines = 0;
    int           rc = 0, found = 0;

    *start = 0;
    if (size <= 0 || nlines <= 0) { return 0; }
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc((size_t) WIN);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (pos > 0 && !found) {
        int64_t chunk = (pos > WIN) ? WIN : pos;
        int64_t base  = pos - chunk;
        ssize_t n = xrdc_rfile_pread(&f, base, buf, (size_t) chunk, st);
        ssize_t i;
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        for (i = n - 1; i >= 0; i--) {
            int64_t abs_off = base + i;
            if (buf[i] == '\n' && abs_off != size - 1) {
                if (++newlines == nlines) {
                    *start = abs_off + 1;
                    found = 1;
                    break;
                }
            }
        }
        pos = base;
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}

/* tail -f follow loop: after the initial dump, poll the file size every `interval`
 * seconds and stream any growth, until SIGINT. On truncation, resync to the new EOF.
 * 0 (clean / interrupted) / -1 (stat or read error, st set). */
static int
tail_follow(xrdc_conn *c, const char *path, int64_t from, double interval,
            xrdc_status *st)
{
    int64_t          off = from;
    struct sigaction sa, old;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tail_sigint;
    sigaction(SIGINT, &sa, &old);

    while (!tail_stop) {
        xrdc_statinfo   si;
        struct timespec ts;
        xrdc_status_clear(st);
        if (xrdc_stat(c, path, &si, st) != 0) {
            sigaction(SIGINT, &old, NULL);
            return -1;
        }
        if (si.size > off) {
            if (stream_file(c, path, off, si.size - off, st) != 0) {
                sigaction(SIGINT, &old, NULL);
                return -1;
            }
            fflush(stdout);
            off = si.size;
        } else if (si.size < off) {
            off = si.size;   /* truncated → resync */
        }
        if (tail_stop) { break; }
        ts.tv_sec  = (time_t) interval;
        ts.tv_nsec = (long) ((interval - (double) ts.tv_sec) * 1e9);
        nanosleep(&ts, NULL);
    }
    sigaction(SIGINT, &old, NULL);
    return 0;
}

static int
do_tail(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];
    long long     nbytes = -1;     /* -c; < 0 = not set */
    long          nlines = 10;     /* -n default */
    int           follow = 0, i;
    double        interval = 1.0;  /* --interval seconds */
    int64_t       start;
    const char   *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            nbytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-f") == 0) {
            follow = 1;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            interval = atof(argv[++i]);
            if (interval <= 0.0) { interval = 1.0; }
        } else { arg = argv[i]; }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: tail [-c BYTES] [-n LINES] [-f] [--interval S] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (nbytes >= 0) {
        start = (si.size > nbytes) ? si.size - nbytes : 0;
    } else if (tail_start_for_lines(c, path, si.size, nlines, &start, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (stream_file(c, path, start, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (follow) {
        fflush(stdout);
        if (tail_follow(c, path, si.size, interval, &st) != 0) {
            fprintf(stderr, "xrdfs: tail -f %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
    }
    return 0;
}

static int
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

static int
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

/* Pull one "oss.<key>=<u64>" field out of a Qspace reply. Returns the value, or -1
 * if the key is absent. */
static int64_t
df_field(const char *reply, const char *key)
{
    const char *p = strstr(reply, key);
    return (p != NULL) ? (int64_t) strtoll(p + strlen(key), NULL, 10) : -1;
}

/* Parse a kXR_Qspace "oss.*" reply into byte counts. Returns 0 if any field was
 * recognized (absent fields stay -1), or -1 for an unrecognized shape. */
static int
df_parse_space(const char *reply, int64_t *total, int64_t *avail, int64_t *used,
               int64_t *largest)
{
    *total   = df_field(reply, "oss.space=");
    *avail   = df_field(reply, "oss.free=");
    *used    = df_field(reply, "oss.used=");
    *largest = df_field(reply, "oss.maxf=");
    return (*total < 0 && *avail < 0 && *used < 0 && *largest < 0) ? -1 : 0;
}

/* df [-h] [path] — friendly disk-space report over kXR_Qspace (the server's oss.*
 * capacity record). Default path "/". -h humanizes the byte columns. Falls back to
 * printing the raw reply verbatim when the shape is unrecognized (never crashes).
 * Cluster-wide aggregation (per-holder rows) is out of scope here — use `xrdmapc`. */
static int
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

/* Two-octal-digit reader for touch_parse_time. Caller guarantees p[0..1] are digits. */
static int
two_digits(const char *p)
{
    return (p[0] - '0') * 10 + (p[1] - '0');
}

/* Parse a POSIX touch -t stamp: [[CC]YY]MMDDhhmm[.ss] (local time) into *out
 * (tv_nsec = 0). Returns 0 / -1 on a malformed stamp. */
static int
touch_parse_time(const char *s, struct timespec *out)
{
    char        d[16];
    size_t      dn = 0, i;
    int         sec = 0, year, mon, day, hour, min;
    const char *dot = strchr(s, '.');
    const char *p;
    struct tm   tmv;
    time_t      now = time(NULL), t;

    for (i = 0; s[i] != '\0' && s[i] != '.'; i++) {
        if (!isdigit((unsigned char) s[i]) || dn >= sizeof(d) - 1) { return -1; }
        d[dn++] = s[i];
    }
    d[dn] = '\0';
    if (dot != NULL) {
        if (strlen(dot + 1) != 2 || !isdigit((unsigned char) dot[1])
            || !isdigit((unsigned char) dot[2])) {
            return -1;
        }
        sec = two_digits(dot + 1);
    }
    if (dn != 8 && dn != 10 && dn != 12) { return -1; }

    localtime_r(&now, &tmv);              /* default year from "now" */
    year = tmv.tm_year + 1900;
    p = d;
    if (dn == 12) {                       /* CCYYMMDDhhmm */
        year = two_digits(p) * 100 + two_digits(p + 2);
        p += 4;
    } else if (dn == 10) {                /* YYMMDDhhmm (POSIX pivot at 69) */
        int yy = two_digits(p);
        year = (yy >= 69) ? 1900 + yy : 2000 + yy;
        p += 2;
    }
    mon = two_digits(p); day = two_digits(p + 2);
    hour = two_digits(p + 4); min = two_digits(p + 6);

    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year  = year - 1900;
    tmv.tm_mon   = mon - 1;
    tmv.tm_mday  = day;
    tmv.tm_hour  = hour;
    tmv.tm_min   = min;
    tmv.tm_sec   = sec;
    tmv.tm_isdst = -1;
    t = mktime(&tmv);
    if (t == (time_t) -1) { return -1; }
    out->tv_sec  = t;
    out->tv_nsec = 0;
    return 0;
}

/* touch [-c] [-a] [-m] [-t STAMP] <path> — create the file if absent (unless -c) and
 * set its access/modification times (default: both to now). -a/-m restrict to
 * atime/mtime; -t sets an explicit [[CC]YY]MMDDhhmm[.ss] time. NEVER changes
 * ownership: xrdc_setattr is always called with set_owner = 0. */
static int
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
static int
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
static int
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
static int
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

/* wc [-c] [-l] [-w] <path> — count bytes/lines/words. With no flag, prints all three
 * (lines words bytes), like wc(1). -c alone is answered from stat (no read); -l/-w
 * stream the file once. Output columns match the selected counters, then the path. */
static int
do_wc(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];
    const char   *arg = NULL;
    int           want_c = 0, want_l = 0, want_w = 0, i;
    long long     lines = 0, words = 0, bytes = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)      { want_c = 1; }
        else if (strcmp(argv[i], "-l") == 0) { want_l = 1; }
        else if (strcmp(argv[i], "-w") == 0) { want_w = 1; }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: wc [-c] [-l] [-w] <path>\n"); return 50; }
    if (!want_c && !want_l && !want_w) { want_l = want_w = want_c = 1; }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    bytes = (long long) si.size;

    if (want_l || want_w) {   /* a single streaming pass counts lines + words */
        xrdc_rfile f;
        uint8_t  *buf;
        int64_t   off = 0;
        int       in_word = 0, rc = 0;

        if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
            fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
        buf = (uint8_t *) malloc(1 << 20);
        if (buf == NULL) {
            xrdc_rfile_close(&f, &st);
            fprintf(stderr, "xrdfs: wc: out of memory\n");
            return 51;
        }
        for (;;) {
            ssize_t got = xrdc_rfile_pread(&f, off, buf, 1 << 20, &st);
            ssize_t k;
            if (got < 0) { rc = -1; break; }
            if (got == 0) { break; }
            for (k = 0; k < got; k++) {
                if (buf[k] == '\n') { lines++; }
                if (isspace(buf[k])) { in_word = 0; }
                else if (!in_word) { in_word = 1; words++; }
            }
            off += got;
        }
        free(buf);
        xrdc_rfile_close(&f, &st);
        if (rc != 0) {
            fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
    }

    if (want_l) { printf(" %lld", lines); }
    if (want_w) { printf(" %lld", words); }
    if (want_c) { printf(" %lld", bytes); }
    printf(" %s\n", path);
    return 0;
}

/* Read a whole remote file into a malloc'd buffer (*out, *len). Caller frees. 0/-1. */
static int
slurp_file(xrdc_conn *c, const char *path, uint8_t **out, int64_t *len, xrdc_status *st)
{
    xrdc_rfile    f;
    xrdc_statinfo si;
    uint8_t      *buf;
    int64_t       off = 0;

    if (xrdc_stat(c, path, &si, st) != 0) { return -1; }
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc(si.size > 0 ? (size_t) si.size : 1);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (off < si.size) {
        ssize_t got = xrdc_rfile_pread(&f, off, buf + off, (size_t) (si.size - off), st);
        if (got < 0) { free(buf); xrdc_rfile_close(&f, st); return -1; }
        if (got == 0) { break; }
        off += got;
    }
    xrdc_rfile_close(&f, st);
    *out = buf;
    *len = off;
    return 0;
}

/* cmp <path1> <path2> — compare two files on this endpoint. Fast path: same-algo
 * server checksums (adler32); if they match the files are identical (exit 0), if they
 * differ exit 1. Falls back to a byte-exact compare when checksums are unavailable.
 * Quiet on a match (cmp(1) convention); reports the first differing offset otherwise. */
static int
do_cmp(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        p1[XRDC_PATH_MAX], p2[XRDC_PATH_MAX];
    char        h1[160], h2[160];

    if (argc < 3) { fprintf(stderr, "usage: cmp <path1> <path2>\n"); return 50; }
    build_path(cwd, argv[1], p1, sizeof(p1));
    build_path(cwd, argv[2], p2, sizeof(p2));

    /* Fast path: compare server checksums (cheap, no bulk transfer). */
    xrdc_status_clear(&st);
    if (xrdc_query_cksum(c, p1, "adler32", h1, sizeof(h1), &st) == 0) {
        xrdc_status s2;
        xrdc_status_clear(&s2);
        if (xrdc_query_cksum(c, p2, "adler32", h2, sizeof(h2), &s2) == 0) {
            if (strcmp(h1, h2) == 0) { return 0; }
            printf("%s %s differ: checksum adler32 (%s vs %s)\n", p1, p2, h1, h2);
            return 1;
        }
    }

    /* Fallback: byte-exact compare. */
    {
        uint8_t *b1 = NULL, *b2 = NULL;
        int64_t  l1 = 0, l2 = 0, i, rc;
        xrdc_status_clear(&st);
        if (slurp_file(c, p1, &b1, &l1, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p1, st.msg);
            return xrdc_shellcode(&st);
        }
        if (slurp_file(c, p2, &b2, &l2, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p2, st.msg);
            free(b1);
            return xrdc_shellcode(&st);
        }
        rc = 0;
        for (i = 0; i < l1 && i < l2; i++) {
            if (b1[i] != b2[i]) {
                printf("%s %s differ: byte %lld\n", p1, p2, (long long) (i + 1));
                rc = 1;
                break;
            }
        }
        if (rc == 0 && l1 != l2) {
            printf("%s %s differ: EOF (sizes %lld vs %lld)\n", p1, p2,
                   (long long) l1, (long long) l2);
            rc = 1;
        }
        free(b1);
        free(b2);
        return (int) rc;
    }
}

/* xattr ls|get|set|rm — extended attributes via kXR_fattr (client/lib/fattr.c).
 *   xattr ls  <path>                  list attribute names
 *   xattr get <path> <name>           print one value
 *   xattr set <path> <name> <value>   set/replace a value
 *   xattr rm  <path> <name>           delete an attribute
 * `xattr <path>` with no subcommand is treated as `ls`. */
static int
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

static int
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

/* grep [-i] [-n] PATTERN <path> — POSIX-regex line match over a streamed file. Lines
 * are reassembled across read chunks. -i case-insensitive, -n prefix line numbers.
 * Exit 0 if any line matched, 1 if none, >1 on error (grep(1) convention). */
static int
do_grep(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    const char *pattern = NULL, *arg = NULL;
    int         icase = 0, numbered = 0, i, cflags = REG_NEWLINE;
    regex_t     re;
    xrdc_rfile  f;
    uint8_t    *buf;
    char       *line = NULL;
    size_t      lcap = 0, llen = 0;
    int64_t     off = 0;
    long        lineno = 0;
    int         matched = 0, rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0)      { icase = 1; }
        else if (strcmp(argv[i], "-n") == 0) { numbered = 1; }
        else if (pattern == NULL)            { pattern = argv[i]; }
        else                                 { arg = argv[i]; }
    }
    if (pattern == NULL || arg == NULL) {
        fprintf(stderr, "usage: grep [-i] [-n] PATTERN <path>\n");
        return 2;
    }
    if (icase) { cflags |= REG_ICASE; }
    if (regcomp(&re, pattern, cflags) != 0) {
        fprintf(stderr, "xrdfs: grep: bad pattern '%s'\n", pattern);
        return 2;
    }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        regfree(&re);
        return xrdc_shellcode(&st) > 1 ? xrdc_shellcode(&st) : 2;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) { xrdc_rfile_close(&f, &st); regfree(&re); return 2; }

    for (;;) {
        ssize_t got = xrdc_rfile_pread(&f, off, buf, 1 << 20, &st);
        ssize_t k;
        if (got < 0) { rc = 2; break; }
        if (got == 0) { break; }
        for (k = 0; k < got; k++) {
            if (buf[k] == '\n') {
                if (llen + 1 > lcap) {
                    char *nl = (char *) realloc(line, llen + 1);
                    if (nl == NULL) { rc = 2; break; }
                    line = nl; lcap = llen + 1;
                }
                line[llen] = '\0';
                lineno++;
                if (regexec(&re, line, 0, NULL, 0) == 0) {
                    matched = 1;
                    if (numbered) { printf("%ld:", lineno); }
                    printf("%s\n", line);
                }
                llen = 0;
            } else {
                if (llen + 1 > lcap) {
                    size_t ncap = lcap ? lcap * 2 : 256;
                    char  *nl = (char *) realloc(line, ncap);
                    if (nl == NULL) { rc = 2; break; }
                    line = nl; lcap = ncap;
                }
                line[llen++] = (char) buf[k];
            }
        }
        if (rc != 0) { break; }
        off += got;
    }
    free(buf);
    free(line);
    xrdc_rfile_close(&f, &st);
    regfree(&re);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        return rc;
    }
    return matched ? 0 : 1;
}

/* hexdump [-n BYTES] <path> — xxd-style dump: 8-hex-digit offset, 16 hex bytes, then
 * the printable-ASCII gutter. -n caps the number of bytes shown. */
static int
do_hexdump(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    const char *arg = NULL;
    long long   limit = -1;        /* -n; < 0 = whole file */
    int         i;
    xrdc_rfile  f;
    uint8_t    *buf;
    int64_t     off = 0;
    int         rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) { limit = strtoll(argv[++i], NULL, 10); }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: hexdump [-n BYTES] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc(1 << 16);
    if (buf == NULL) { xrdc_rfile_close(&f, &st); return 51; }

    for (;;) {
        size_t  want = 1 << 16;
        ssize_t got, base;
        if (limit >= 0) {
            int64_t rem = limit - off;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        got = xrdc_rfile_pread(&f, off, buf, want, &st);
        if (got < 0) { rc = -1; break; }
        if (got == 0) { break; }
        for (base = 0; base < got; base += 16) {
            ssize_t j, row = (got - base < 16) ? got - base : 16;
            printf("%08llx ", (unsigned long long) (off + base));
            for (j = 0; j < 16; j++) {
                if (j < row) { printf("%02x ", buf[base + j]); }
                else         { printf("   "); }
            }
            printf(" |");
            for (j = 0; j < row; j++) {
                int ch = buf[base + j];
                putchar((ch >= 32 && ch < 127) ? ch : '.');
            }
            printf("|\n");
        }
        off += got;
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}

/* ---- dd / upload — windowed, rate-limited block I/O ---------------------- */

#define XRDFS_DD_MAXBS (256LL << 20)   /* cap a single block buffer at 256 MiB */

/* Parse a byte count with an optional 1024-based K/M/G/T suffix (e.g. "10M",
 * "1.5G", "4096"). Returns the byte count, or -1 on a malformed value. */
static int64_t
parse_bytes(const char *s)
{
    return xrdc_parse_bytes(s);   /* shared (lib/units.c) */
}

static void
rate_pace(const struct timespec *start, int64_t sent, double rate)
{
    xrdc_rate_pace(start, sent, rate);   /* shared (lib/units.c) */
}

/* dd [if=]<path> [bs=BYTES] [skip=BLOCKS] [count=BLOCKS] [rate=BYTES/s] — read a
 * windowed, optionally rate-limited slice of a remote file to stdout. bs defaults to
 * 1 MiB; the window starts at skip*bs and is count*bs bytes (count omitted = to EOF).
 * rate accepts a K/M/G suffix; 0 = unlimited. A one-line byte summary goes to stderr. */
static int
do_dd(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            path[XRDC_PATH_MAX];
    const char     *arg = NULL;
    int64_t         bs = 1 << 20, skip = 0, count = -1, want_total, off, produced = 0;
    double          rate = 0.0;
    int             i, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: dd: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "skip=", 5) == 0) {
            skip = strtoll(argv[i] + 5, NULL, 10);
            if (skip < 0) { fprintf(stderr, "xrdfs: dd: bad skip\n"); return 50; }
        } else if (strncmp(argv[i], "count=", 6) == 0) {
            count = strtoll(argv[i] + 6, NULL, 10);
            if (count < 0) { fprintf(stderr, "xrdfs: dd: bad count\n"); return 50; }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: dd: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strncmp(argv[i], "if=", 3) == 0) {
            arg = argv[i] + 3;
        } else if (argv[i][0] != '-') {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    off        = skip * bs;
    want_total = (count >= 0) ? count * bs : -1;

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        fprintf(stderr, "xrdfs: dd: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        size_t  want = (size_t) bs;
        ssize_t n;
        if (want_total >= 0) {
            int64_t rem = want_total - produced;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        n = xrdc_rfile_pread(&f, off, buf, want, &st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            xrdc_status_set(&st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1; break;
        }
        off += n; produced += n;
        rate_pace(&start, produced, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    fprintf(stderr, "%lld bytes copied\n", (long long) produced);
    return 0;
}

/* upload [bs=BYTES] [rate=BYTES/s] [-f] <localfile|-> <remote-path> — write a local
 * file (or stdin "-") to a remote path, optionally rate-limited. Without -f the remote
 * must not already exist (kXR_new); -f truncates/overwrites. bs defaults to 1 MiB. */
static int
do_upload(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            rpath[XRDC_PATH_MAX];
    const char     *local = NULL, *remote = NULL;
    int64_t         bs = 1 << 20, off = 0;
    double          rate = 0.0;
    int             force = 0, i, fd, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: upload: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: upload: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strcmp(argv[i], "-f") == 0) {
            force = 1;
        } else if (local == NULL)  { local = argv[i]; }
        else if (remote == NULL)   { remote = argv[i]; }
    }
    if (local == NULL || remote == NULL) {
        fprintf(stderr, "usage: upload [bs=N] [rate=R] [-f] <localfile|-> <remote>\n");
        return 50;
    }

    fd = (strcmp(local, "-") == 0) ? 0 : open(local, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "xrdfs: upload: %s: %s\n", local, strerror(errno));
        return 50;
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    xrdc_status_clear(&st);
    if (xrdc_rfile_open_write(c, rpath, force ? 1 : 0, 0, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: upload %s: %s\n", rpath, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);
        if (fd > 0) { close(fd); }
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        if (fd > 0) { close(fd); }
        fprintf(stderr, "xrdfs: upload: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t r = read(fd, buf, (size_t) bs);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            fprintf(stderr, "xrdfs: upload: read %s: %s\n", local, strerror(errno));
            rc = -1; break;
        }
        if (r == 0) { break; }
        if (xrdc_rfile_pwrite(&f, off, buf, (size_t) r, &st) != 0) {
            fprintf(stderr, "xrdfs: upload %s: %s\n", rpath, st.msg);
            rc = xrdc_shellcode(&st); break;
        }
        off += r;
        rate_pace(&start, off, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);   /* commit */
    if (fd > 0) { close(fd); }
    if (rc != 0) { return rc < 0 ? 1 : rc; }
    fprintf(stderr, "%lld bytes uploaded to %s\n", (long long) off, rpath);
    return 0;
}

/* download [bs=BYTES] [rate=BYTES/s] [-f] <remote> [localfile|-] — read a remote file
 * to a local file (or stdout "-"), optionally rate-limited. The local destination
 * defaults to the remote basename in the current directory (like `get`). Without -f an
 * existing local file is not overwritten (O_EXCL). The rate-limit counterpart to
 * `upload`; for windowed/stdout reads use `dd`. */
static int
do_download(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            rpath[XRDC_PATH_MAX], namebuf[XRDC_PATH_MAX];
    const char     *remote = NULL, *local = NULL;
    int64_t         bs = 1 << 20, off = 0;
    double          rate = 0.0;
    int             force = 0, i, fd, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: download: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: download: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strcmp(argv[i], "-f") == 0) {
            force = 1;
        } else if (remote == NULL) { remote = argv[i]; }
        else if (local == NULL)    { local = argv[i]; }
    }
    if (remote == NULL) {
        fprintf(stderr, "usage: download [bs=N] [rate=R] [-f] <remote> [localfile|-]\n");
        return 50;
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    if (local == NULL) {   /* default: remote basename in the cwd (like get) */
        const char *base = strrchr(rpath, '/');
        base = (base != NULL) ? base + 1 : rpath;
        if (base[0] == '\0') {
            fprintf(stderr, "xrdfs: download: no local dest and remote has no basename\n");
            return 50;
        }
        snprintf(namebuf, sizeof(namebuf), "%s", base);
        local = namebuf;
    }

    if (strcmp(local, "-") == 0) {
        fd = 1;   /* stdout */
    } else {
        int flags = O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL);
        fd = open(local, flags, 0644);
        if (fd < 0) {
            fprintf(stderr, "xrdfs: download: %s: %s\n", local, strerror(errno));
            return 50;
        }
    }
    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, rpath, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: download %s: %s\n", rpath, st.msg);
        if (fd > 1) { close(fd); }
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        if (fd > 1) { close(fd); }
        fprintf(stderr, "xrdfs: download: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t n = xrdc_rfile_pread(&f, off, buf, (size_t) bs, &st);
        ssize_t w = 0;
        if (n < 0) {
            fprintf(stderr, "xrdfs: download %s: %s\n", rpath, st.msg);
            rc = xrdc_shellcode(&st); break;
        }
        if (n == 0) { break; }
        while (w < n) {
            ssize_t k = write(fd, buf + w, (size_t) (n - w));
            if (k < 0) {
                if (errno == EINTR) { continue; }
                fprintf(stderr, "xrdfs: download: write %s: %s\n", local, strerror(errno));
                rc = 1; break;
            }
            if (k == 0) { rc = 1; break; }
            w += k;
        }
        if (rc != 0) { break; }
        off += n;
        rate_pace(&start, off, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (fd > 1) { close(fd); }
    if (rc != 0) { return rc; }
    if (fd != 1) {   /* don't pollute a piped stdout with the summary */
        fprintf(stderr, "%lld bytes downloaded to %s\n", (long long) off, local);
    }
    return 0;
}

static int
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

static int
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

/* Poll a path's residency until it is online (kXR_offline clears) or `timeout_s`
 * elapses. Returns 0 online, 1 still offline at timeout, -1 on a stat error. */
static int
wait_online(xrdc_conn *c, const char *path, int timeout_s, xrdc_status *st)
{
    int waited = 0;
    for (;;) {
        xrdc_statinfo si;
        struct timespec ts;
        xrdc_status_clear(st);
        if (xrdc_stat(c, path, &si, st) != 0) { return -1; }
        if (!(si.flags & kXR_offline)) { return 0; }
        if (waited >= timeout_s) { return 1; }
        ts.tv_sec = 1; ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        waited++;
    }
}

/* stage [--wait[=SECS]] <path>... — request tape/disk staging (kXR_prepare + kXR_stage);
 * with --wait, poll each path's residency until online or the timeout (default 300 s). */
static int
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
static int
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

/* §15: narrate the connection — protocol caps, signing, auth choice, TLS. The
 * session is already established (main connected before dispatch); this is a
 * read-only report over the conn fields conn.c/auth.c populated. */
static int
do_explain(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    (void) cwd; (void) argc; (void) argv;
    xrdc_explain_conn(c, &c->opts, stdout);
    return 0;
}

/* Strict non-negative decimal parse: rejects empty, trailing garbage, sign, and
 * overflow. Fills *out and returns 0; on any error returns -1. */
static int
parse_u64_strict(const char *s, unsigned long long *out)
{
    char              *end;
    unsigned long long v;
    if (s == NULL || *s == '\0' || *s == '-') {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

/* readv <path> <off1> <len1> [<off2> <len2> ...] — scatter-gather read (kXR_readv);
 * the requested segments are read in one round-trip and written, concatenated, to
 * stdout (so the bytes can be verified against the file). */
static int
do_readv(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status    st;
    char           path[XRDC_PATH_MAX];
    xrdc_file      f;
    xrdc_readv_seg segs[XRDC_VEC_MAXSEGS];
    size_t         nseg = 0, i;
    int            a;
    ssize_t        got;
    int            rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: readv <path> <off len>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
    for (a = 2; a + 1 < argc && nseg < XRDC_VEC_MAXSEGS; a += 2) {
        unsigned long long off, len;
        if (parse_u64_strict(argv[a], &off) != 0
            || parse_u64_strict(argv[a + 1], &len) != 0) {
            for (i = 0; i < nseg; i++) { free(segs[i].buf); }
            fprintf(stderr, "xrdfs: readv: bad offset/length '%s %s'\n",
                    argv[a], argv[a + 1]);
            return 50;
        }
        segs[nseg].offset = (int64_t) off;
        segs[nseg].len    = (size_t) len;
        segs[nseg].got    = 0;
        segs[nseg].buf    = malloc(segs[nseg].len ? segs[nseg].len : 1);
        if (segs[nseg].buf == NULL) {
            for (i = 0; i < nseg; i++) { free(segs[i].buf); }
            fprintf(stderr, "xrdfs: readv: out of memory\n");
            return 51;
        }
        nseg++;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_open_read(c, path, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free(segs[i].buf); }
        fprintf(stderr, "xrdfs: readv open %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    got = xrdc_file_readv(c, &f, segs, nseg, &st);
    if (got < 0) {
        fprintf(stderr, "xrdfs: readv %s: %s\n", path, st.msg);
        rc = xrdc_shellcode(&st);
    } else {
        for (i = 0; i < nseg; i++) {
            fwrite(segs[i].buf, 1, segs[i].got, stdout);   /* actual bytes read */
        }
    }
    xrdc_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free(segs[i].buf); }
    return rc;
}

/* writev <path> <off1> <hexdata1> [<off2> <hexdata2> ...] — scatter-gather write
 * (kXR_writev): each segment's hex-encoded bytes are written at its offset in one
 * round-trip (the file is created/truncated first). */
static int
do_writev(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            path[XRDC_PATH_MAX];
    xrdc_file       f;
    xrdc_writev_seg segs[XRDC_VEC_MAXSEGS];
    size_t          nseg = 0, i;
    int             a, rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: writev <path> <off hexdata>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
    for (a = 2; a + 1 < argc && nseg < XRDC_VEC_MAXSEGS; a += 2) {
        const char *hex = argv[a + 1];
        size_t      hl = strlen(hex), n = hl / 2, j;
        uint8_t    *d;
        if (hl == 0 || (hl % 2) != 0) {
            for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
            fprintf(stderr, "xrdfs: writev: bad hex data\n");
            return 50;
        }
        d = malloc(n);
        if (d == NULL) {
            for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
            fprintf(stderr, "xrdfs: writev: out of memory\n");
            return 51;
        }
        for (j = 0; j < n; j++) {
            unsigned v;
            if (sscanf(hex + 2 * j, "%2x", &v) != 1) {
                free(d);
                for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
                fprintf(stderr, "xrdfs: writev: bad hex data\n");
                return 50;
            }
            d[j] = (uint8_t) v;
        }
        {
            unsigned long long off;
            if (parse_u64_strict(argv[a], &off) != 0) {
                free(d);
                for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
                fprintf(stderr, "xrdfs: writev: bad offset '%s'\n", argv[a]);
                return 50;
            }
            segs[nseg].offset = (int64_t) off;
        }
        segs[nseg].len    = n;
        segs[nseg].data   = d;
        nseg++;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_open_write(c, path, 1 /*force*/, 0 /*posc*/, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
        fprintf(stderr, "xrdfs: writev open %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (xrdc_file_writev(c, &f, segs, nseg, 1 /*sync*/, &st) != 0) {
        fprintf(stderr, "xrdfs: writev %s: %s\n", path, st.msg);
        rc = xrdc_shellcode(&st);
    }
    xrdc_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
    return rc;
}

/* ------------------------------------------------------------------ */
/* power tools — recursive walk: du / tree / find / ls -R              */
/* ------------------------------------------------------------------ */

#define XRDFS_MAXDEPTH 64   /* recursion bound (defensive; trees aren't cyclic) */

/* "." / ".." dirent test. */
static int
is_dot(const char *name)
{
    return name[0] == '.'
        && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/* Render a byte count: raw decimal, or a human 1.2K/3.4M/… when human != 0. */
static void
fmt_size(int64_t n, char *out, size_t sz, int human)
{
    xrdc_fmt_size(n, out, sz, human);   /* shared (lib/units.c) */
}

/* Join dir + name into out (path separator aware). Returns 0, or -1 if too long. */
static int
join_path(const char *dir, const char *name, char *out, size_t sz)
{
    size_t dl = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, sz, "%s%s%s", dir, sep, name) >= sz) ? -1 : 0;
}

/* Per-entry callback for walk_dir; return nonzero to abort the whole walk. */
typedef int (*xrdfs_visit)(const char *full, const xrdc_dirent *e, int depth, void *u);

/* Recursively walk the remote tree under `path` (depth-first, pre-order), invoking
 * `visit` for every entry. Directories are descended up to XRDFS_MAXDEPTH. 0 / -1. */
static int
walk_dir(xrdc_conn *c, const char *path, int depth, xrdfs_visit visit, void *u,
         xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, i;

    if (xrdc_dirlist(c, path, 1 /*want_stat*/, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char full[XRDC_PATH_MAX];
        if (is_dot(ents[i].name) || join_path(path, ents[i].name, full, sizeof(full)) != 0) {
            continue;
        }
        if (visit(full, &ents[i], depth, u) != 0) {
            free(ents);
            return 1;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)
            && depth + 1 < XRDFS_MAXDEPTH) {
            int rc = walk_dir(c, full, depth + 1, visit, u, st);
            if (rc != 0) {
                free(ents);
                return rc;
            }
        }
    }
    free(ents);
    return 0;
}

/* ---- chmod -R ---- */

typedef struct {
    xrdc_conn *c;
    int        mode;
    int        failures;
} chmod_walk;

/* walk_dir visitor: chmod each entry, counting (and reporting) per-entry failures
 * without aborting the walk. */
static int
chmod_visit(const char *full, const xrdc_dirent *e, int depth, void *u)
{
    chmod_walk *w = (chmod_walk *) u;
    xrdc_status st;
    (void) e; (void) depth;
    xrdc_status_clear(&st);
    if (xrdc_chmod(w->c, full, w->mode, &st) != 0) {
        fprintf(stderr, "xrdfs: chmod %s: %s\n", full, st.msg);
        w->failures++;
    }
    return 0;   /* keep walking */
}

/* Recursively chmod every entry under `path` (the top path is chmod'd by the caller).
 * *failures accumulates per-entry errors; returns 0 / -1 (walk-level error, st set). */
static int
chmod_recursive(xrdc_conn *c, const char *path, int mode, int *failures,
                xrdc_status *st)
{
    chmod_walk w;
    int        rc;
    w.c = c; w.mode = mode; w.failures = 0;
    rc = walk_dir(c, path, 0, chmod_visit, &w, st);
    *failures = w.failures;
    return (rc < 0) ? -1 : 0;
}

/* ---- du ---- */

typedef struct {
    int64_t bytes;
    long    files;
    long    dirs;
} du_acc;

static int
du_visit(const char *full, const xrdc_dirent *e, int depth, void *u)
{
    du_acc *a = (du_acc *) u;
    (void) full;
    (void) depth;
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        a->dirs++;
    } else if (e->have_stat) {
        a->bytes += e->st.size;
        a->files++;
    }
    return 0;
}

/* du [-h] <path>... — recursive total size + file/dir counts per argument. */
static int
do_du(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    int human = 0, i, rc = 0, any = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { human = 1; }
    }
    for (i = 1; i < argc; i++) {
        char        path[XRDC_PATH_MAX], sz[32];
        xrdc_status st;
        du_acc      a = { 0, 0, 0 };
        if (argv[i][0] == '-') { continue; }
        any = 1;
        build_path(cwd, argv[i], path, sizeof(path));
        xrdc_status_clear(&st);
        if (walk_dir(c, path, 0, du_visit, &a, &st) != 0) {
            fprintf(stderr, "xrdfs: du %s: %s\n", path, st.msg);
            rc = xrdc_shellcode(&st);
            continue;
        }
        fmt_size(a.bytes, sz, sizeof(sz), human);
        printf("%-10s %s  (%ld files, %ld dirs)\n", sz, path, a.files, a.dirs);
    }
    if (!any) {
        char        path[XRDC_PATH_MAX], sz[32];
        xrdc_status st;
        du_acc      a = { 0, 0, 0 };
        build_path(cwd, ".", path, sizeof(path));
        xrdc_status_clear(&st);
        if (walk_dir(c, path, 0, du_visit, &a, &st) != 0) {
            fprintf(stderr, "xrdfs: du %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
        fmt_size(a.bytes, sz, sizeof(sz), human);
        printf("%-10s %s  (%ld files, %ld dirs)\n", sz, path, a.files, a.dirs);
    }
    return rc;
}

/* ---- find ---- */

typedef struct {
    const char *name_glob;   /* -name PATTERN (fnmatch on basename), or NULL */
    int         type;        /* -type: 0=any, 1=file, 2=dir */
    int         size_sign;   /* -size: -1 (<), 0 (none/exact), +1 (>) */
    int64_t     size_val;    /* -size threshold in bytes */
} find_pred;

static int
find_visit(const char *full, const xrdc_dirent *e, int depth, void *u)
{
    const find_pred *p = (const find_pred *) u;
    int  is_dir = e->have_stat && (e->st.flags & kXR_isDir);
    (void) depth;

    if (p->type == 1 && is_dir) { return 0; }
    if (p->type == 2 && !is_dir) { return 0; }
    if (p->name_glob != NULL && fnmatch(p->name_glob, e->name, 0) != 0) { return 0; }
    if (p->size_sign != 0 && e->have_stat) {
        if (p->size_sign < 0 && !(e->st.size < p->size_val)) { return 0; }
        if (p->size_sign > 0 && !(e->st.size > p->size_val)) { return 0; }
    }
    printf("%s\n", full);
    return 0;
}

/* find <path> [-name GLOB] [-type f|d] [-size +N|-N] — recursive predicate search. */
static int
do_find(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    find_pred   p = { NULL, 0, 0, 0 };
    const char *start = ".";
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            p.name_glob = argv[++i];
        } else if (strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            p.type = (t[0] == 'd') ? 2 : (t[0] == 'f') ? 1 : 0;
        } else if (strcmp(argv[i], "-size") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            p.size_sign = (s[0] == '+') ? 1 : (s[0] == '-') ? -1 : 1;
            p.size_val  = (int64_t) strtoll((s[0] == '+' || s[0] == '-') ? s + 1 : s,
                                            NULL, 10);
        } else if (argv[i][0] != '-') {
            start = argv[i];
        }
    }
    build_path(cwd, start, path, sizeof(path));
    xrdc_status_clear(&st);
    if (walk_dir(c, path, 0, find_visit, &p, &st) != 0) {
        fprintf(stderr, "xrdfs: find %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}

/* ---- tree ---- */

typedef struct {
    long ndirs;
    long nfiles;
    int  maxdepth;   /* -L; <0 = unlimited */
    int  dirs_only;  /* -d */
} tree_opts;

static int
tree_recurse(xrdc_conn *c, const char *path, const char *prefix, int depth,
             tree_opts *o, xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, i;
    int         *keep, nk = 0, j;

    if (o->maxdepth >= 0 && depth > o->maxdepth) { return 0; }
    if (xrdc_dirlist(c, path, 1, &ents, &n, st) != 0) { return -1; }

    keep = (int *) malloc((n ? n : 1) * sizeof(int));
    if (keep == NULL) {
        free(ents);
        xrdc_status_set(st, XRDC_EPROTO, 0, "tree: out of memory");
        return -1;
    }
    for (i = 0; i < n; i++) {
        int is_dir = ents[i].have_stat && (ents[i].st.flags & kXR_isDir);
        if (is_dot(ents[i].name)) { continue; }
        if (o->dirs_only && !is_dir) { continue; }
        keep[nk++] = (int) i;
    }
    for (j = 0; j < nk; j++) {
        xrdc_dirent *e = &ents[keep[j]];
        int   last   = (j == nk - 1);
        int   is_dir = e->have_stat && (e->st.flags & kXR_isDir);
        char  full[XRDC_PATH_MAX];
        char  child_prefix[512];

        printf("%s%s%s\n", prefix, last ? "\\-- " : "|-- ", e->name);
        if (is_dir) { o->ndirs++; } else { o->nfiles++; }
        if (is_dir && join_path(path, e->name, full, sizeof(full)) == 0
            && depth + 1 < XRDFS_MAXDEPTH) {
            snprintf(child_prefix, sizeof(child_prefix), "%s%s",
                     prefix, last ? "    " : "|   ");
            if (tree_recurse(c, full, child_prefix, depth + 1, o, st) != 0) {
                free(keep);
                free(ents);
                return -1;
            }
        }
    }
    free(keep);
    free(ents);
    return 0;
}

/* tree [-d] [-L N] [path] — visual directory tree. */
static int
do_tree(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    tree_opts   o = { 0, 0, -1, 0 };
    const char *start = ".";
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) { o.dirs_only = 1; }
        else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) { o.maxdepth = atoi(argv[++i]); }
        else if (argv[i][0] != '-') { start = argv[i]; }
    }
    build_path(cwd, start, path, sizeof(path));
    printf("%s\n", path);
    xrdc_status_clear(&st);
    if (tree_recurse(c, path, "", 0, &o, &st) != 0) {
        fprintf(stderr, "xrdfs: tree %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    printf("\n%ld directories, %ld files\n", o.ndirs, o.nfiles);
    return 0;
}

/* ------------------------------------------------------------------ */
/* dispatch table                                                      */
/* ------------------------------------------------------------------ */

typedef int (*xrdfs_fn)(xrdc_conn *, const char *, int, char **);

typedef struct {
    const char *name;
    xrdfs_fn    fn;
    const char *help;
} xrdfs_cmd;

static const xrdfs_cmd COMMANDS[] = {
    { "stat",     do_stat,     "stat <path>" },
    { "ls",       do_ls,       "ls [-l] [-R] [-h] [path]" },
    { "du",       do_du,       "du [-h] <path>...  (recursive size)" },
    { "df",       do_df,       "df [-h] [path]  (disk space, oss.* Qspace)" },
    { "tree",     do_tree,     "tree [-d] [-L N] [path]" },
    { "find",     do_find,     "find <path> [-name GLOB] [-type f|d] [-size +N|-N]" },
    { "mkdir",    do_mkdir,    "mkdir [-p] [-m mode] <path>" },
    { "rm",       do_rm,       "rm <path>" },
    { "rmdir",    do_rmdir,    "rmdir <path>" },
    { "mv",       do_mv,       "mv <src> <dst>" },
    { "chmod",    do_chmod,    "chmod [-R] <path> <octal-mode>" },
    { "touch",    do_touch,    "touch [-c] [-a] [-m] [-t STAMP] <path>" },
    { "ln",       do_ln,       "ln [-s] [-f] <target> <linkpath>" },
    { "readlink", do_readlink, "readlink <path>" },
    { "truncate", do_truncate, "truncate <path> <size>" },
    { "cat",      do_cat,      "cat <path>" },
    { "head",     do_head,     "head [-c BYTES] [-n LINES] <path>" },
    { "tail",     do_tail,     "tail [-c BYTES] [-n LINES] [-f] <path>" },
    { "wc",       do_wc,       "wc [-c] [-l] [-w] <path>" },
    { "grep",     do_grep,     "grep [-i] [-n] PATTERN <path>" },
    { "hexdump",  do_hexdump,  "hexdump [-n BYTES] <path>" },
    { "dd",       do_dd,       "dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]" },
    { "upload",   do_upload,   "upload [bs=N] [rate=R] [-f] <localfile|-> <remote>" },
    { "download", do_download, "download [bs=N] [rate=R] [-f] <remote> [localfile|-]" },
    { "cmp",      do_cmp,      "cmp <path1> <path2>" },
    { "cksum",    do_cksum,    "cksum [-a algo] <path>" },
    { "xattr",    do_xattr,    "xattr ls|get|set|rm <path> [name] [value]" },
    { "readv",    do_readv,    "readv <path> <off len>...  (scatter-gather read)" },
    { "writev",   do_writev,   "writev <path> <off hexdata>...  (scatter-gather write)" },
    { "locate",   do_locate,   "locate <path>" },
    { "query",    do_query,    "query <config|space|checksum|stats> [args]" },
    { "statvfs",  do_statvfs,  "statvfs [path]" },
    { "prepare",  do_prepare,  "prepare [-s|-w|-c|-f|-e] <path>..." },
    { "stage",    do_stage,    "stage [--wait[=SECS]] <path>..." },
    { "evict",    do_evict,    "evict <path>..." },
    { "explain",  do_explain,  "explain (connection/auth/TLS facts)" },
    { NULL, NULL, NULL }
};

static const xrdfs_cmd *
find_command(const char *name)
{
    for (const xrdfs_cmd *cmd = COMMANDS; cmd->name != NULL; cmd++) {
        if (strcmp(cmd->name, name) == 0) {
            return cmd;
        }
    }
    return NULL;
}

/* Run one tokenized command. cwd/cwdsz hold the mutable working directory (for
 * the REPL's cd/pwd). Returns a shell code; sets *quit when asked to leave. */
static int
dispatch(xrdc_conn *c, char *cwd, size_t cwdsz, int ntok, char **tok, int *quit)
{
    const xrdfs_cmd *cmd;

    if (ntok == 0) {
        return 0;
    }
    if (strcmp(tok[0], "exit") == 0 || strcmp(tok[0], "quit") == 0) {
        if (quit != NULL) { *quit = 1; }
        return 0;
    }
    if (strcmp(tok[0], "pwd") == 0) {
        printf("%s\n", cwd);
        return 0;
    }
    if (strcmp(tok[0], "cd") == 0) {
        char next[XRDC_PATH_MAX];
        build_path(cwd, ntok >= 2 ? tok[1] : "/", next, sizeof(next));
        snprintf(cwd, cwdsz, "%s", next);
        return 0;
    }
    if (strcmp(tok[0], "help") == 0) {
        for (const xrdfs_cmd *h = COMMANDS; h->name != NULL; h++) {
            printf("  %s\n", h->help);
        }
        printf("  cd <path> | pwd | help | exit\n");
        return 0;
    }

    cmd = find_command(tok[0]);
    if (cmd == NULL) {
        fprintf(stderr, "xrdfs: unknown command '%s'\n", tok[0]);
        return 50;
    }
    return cmd->fn(c, cwd, ntok, tok);
}

/* ------------------------------------------------------------------ */
/* interactive shell                                                   */
/* ------------------------------------------------------------------ */

static int
tokenize(char *line, char **tok, int maxtok)
{
    int   n = 0;
    char *p = line;

    while (*p != '\0' && n < maxtok) {
        while (*p != '\0' && isspace((unsigned char) *p)) { p++; }
        if (*p == '\0') { break; }
        tok[n++] = p;
        while (*p != '\0' && !isspace((unsigned char) *p)) { p++; }
        if (*p != '\0') { *p++ = '\0'; }
    }
    return n;
}

static int
repl(xrdc_conn *c, const char *host, int port)
{
    char    cwd[XRDC_PATH_MAX] = "/";
    char   *line = NULL;
    size_t  cap = 0;
    int     last = 0;

    for (;;) {
        char   *tok[XRDFS_MAXTOK];
        int     ntok, quit = 0;
        ssize_t r;

        printf("[%s:%d] %s > ", host, port, cwd);
        fflush(stdout);

        r = getline(&line, &cap, stdin);
        if (r < 0) {
            printf("\n");
            break;   /* EOF */
        }
        ntok = tokenize(line, tok, XRDFS_MAXTOK);
        last = dispatch(c, cwd, sizeof(cwd), ntok, tok, &quit);
        if (quit) {
            break;
        }
    }
    free(line);
    return last;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrdfs [opts] host[:port]|root[s]://host[:port]|http[s]|dav[s]://host/path [command [args]]\n"
        "  with no command, drops into an interactive shell (root:// only).\n"
        "  opts:\n"
        "    --tls --notlsok --noverifyhost   in-protocol TLS controls\n"
        "    --auth <gsi|ztn|krb5|sss|unix>   force an auth protocol (root://)\n"
        "    --token TOK | -T TOK             bearer token for http(s)/WebDAV ($BEARER_TOKEN)\n"
        "  http(s)/WebDAV endpoints support read-only metadata: ls, stat\n"
        "  commands (root://):\n"
        "    stat ls du df tree find mkdir rm rmdir mv chmod touch ln readlink\n"
        "    truncate cat head tail wc grep hexdump dd upload download cmp cksum\n"
        "    xattr readv writev locate query statvfs prepare stage evict explain\n"
        "      (cd/pwd/help/exit in the shell)\n");
}

int
main(int argc, char **argv)
{
    xrdc_url    u;
    xrdc_conn   c;
    xrdc_status st;
    xrdc_opts   opts;
    const char *endpoint;
    const char *web_token = NULL;   /* --token / $BEARER_TOKEN for http(s)/WebDAV */
    char        cwd[XRDC_PATH_MAX] = "/";
    int         argi = 1, rc;

    memset(&opts, 0, sizeof(opts));
    opts.verify_host = 1;
    xrootd_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    while (argi < argc && argv[argi][0] == '-' && strcmp(argv[argi], "-") != 0) {
        if (strcmp(argv[argi], "--no-cwd") == 0)        { argi++; continue; }
        if (strcmp(argv[argi], "--tls") == 0)           { opts.want_tls = 1; argi++; continue; }
        if (strcmp(argv[argi], "--notlsok") == 0)       { opts.notlsok = 1; argi++; continue; }
        if (strcmp(argv[argi], "--noverifyhost") == 0)  { opts.verify_host = 0; argi++; continue; }
        if (strcmp(argv[argi], "--auth") == 0 && argi + 1 < argc) {
            opts.auth_force = argv[argi + 1]; argi += 2; continue;
        }
        if ((strcmp(argv[argi], "--token") == 0 || strcmp(argv[argi], "-T") == 0)
            && argi + 1 < argc) {
            web_token = argv[argi + 1]; argi += 2; continue;   /* http(s)/WebDAV bearer */
        }
        if (strcmp(argv[argi], "--wire-trace") == 0)      { opts.wire_trace = 1; argi++; continue; }
        if (strncmp(argv[argi], "--wire-trace=", 13) == 0) { opts.wire_trace = atoi(argv[argi] + 13); argi++; continue; }
        if (strcmp(argv[argi], "--timing") == 0)          { opts.timing = 1; argi++; continue; }
        if (strcmp(argv[argi], "--redirect-trace") == 0)  { opts.redir_trace = 1; argi++; continue; }
        if (strcmp(argv[argi], "--capture") == 0 && argi + 1 < argc) { opts.capture = argv[argi + 1]; argi += 2; continue; }
        if (strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0) {
            usage();
            return 0;
        }
        break;
    }

    if (argi >= argc) { usage(); return 50; }
    endpoint = argv[argi++];

    /* http(s)/WebDAV endpoint: no root:// session — serve read-only metadata
     * (ls, stat) over WebDAV PROPFIND, mirroring the official xrdfs. */
    if (xrdc_is_web_url(endpoint)) {
        xrdc_weburl wu;
        char        base[XRDC_PATH_MAX];
        size_t      bl;
        web_ctx     w;
        if (xrdc_weburl_parse(endpoint, &wu) != 0) {
            fprintf(stderr, "xrdfs: bad web URL: %s\n", endpoint);
            return 50;
        }
        if (wu.is_s3) {
            fprintf(stderr, "xrdfs: s3:// endpoints are not supported "
                            "(use http/https/dav/davs)\n");
            return 50;
        }
        snprintf(base, sizeof(base), "%s", wu.path);   /* URL path = export base */
        bl = strlen(base);
        while (bl > 0 && base[bl - 1] == '/') {
            base[--bl] = '\0';
        }
        w.u      = &wu;
        w.base   = base;
        w.bearer = web_token != NULL ? web_token : getenv("BEARER_TOKEN");
        w.verify = opts.verify_host;
        w.ca_dir = xrdc_resolve_ca_dir(NULL);
        if (argi >= argc) {
            fprintf(stderr, "xrdfs: an http(s)/WebDAV endpoint needs a command "
                            "(e.g. ls); the interactive shell is root:// only\n");
            return 50;
        }
        return web_dispatch(&w, argc - argi, &argv[argi]);
    }

    xrdc_status_clear(&st);
    if (endpoint_to_url(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrdfs: %s\n", st.msg);
        return 50;
    }
    if (xrdc_connect_resilient(&c, &u, &opts, &st) != 0) {
        fprintf(stderr, "xrdfs: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return xrdc_shellcode(&st);
    }

    if (argi >= argc) {
        rc = repl(&c, u.host, u.port);   /* no command → interactive shell */
    } else {
        rc = dispatch(&c, cwd, sizeof(cwd), argc - argi, &argv[argi], NULL);
    }

    xrdc_close(&c);
    return rc;
}
